#pragma once

// Candidate rows (docs/parity/00-plan.md §3.4). Every SQL heuristic and most stage queries select
// SELECT_FIELDS (H:51-84); the consumer (check_match -> add_matches_internal, D:1786-1948) reads the
// aliases ea, name1, ea2, name2, description, nodes1, nodes2, md1, md2 and, through the row indices,
// the per-function columns check_ratio reads. A RowSource yields those rows in exactly the order
// Python's cursor would (Path A: the verbatim SQL through the SQLite C API).

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "dsigmatcher/diff/Database.h"
#include "dsigmatcher/diff/Interner.h"
#include "dsigmatcher/diff/Table.h"

namespace DSig::Diff {

class DiffSession;

struct HeuristicRow {
  AddrId Ea1 = kNoneAddr;        // `ea`  : exact f.address TEXT
  AddrId Ea2 = kNoneAddr;        // `ea2` : exact df.address TEXT
  uint32_t Row1 = kNoRow;        // row of Ea1 in the Side1 table (RowByAddr)
  uint32_t Row2 = kNoRow;        // row of Ea2 in the Side2 table
  Side Side1 = Side::Main;       // which export Row1 indexes (always Main for SQL rows)
  Side Side2 = Side::Diff;       // which export Row2 indexes (always Diff for SQL rows)
  NameId Name1 = kNoneName;      // `name1`
  NameId Name2 = kNoneName;      // `name2`
  DescId Desc{};                 // `description`
  std::optional<int64_t> Nodes1; // `nodes1`; nullopt for NULL (int(None) raises at the consuming site)
  std::optional<int64_t> Nodes2;
  std::optional<double> Md1;     // `md1` = cast(f.md_index as real); nullopt for NULL (float(None) raises)
  std::optional<double> Md2;
};

class RowSource {
public:
  virtual ~RowSource() = default;
  // Fetches the next row into `Out`. Returns false when exhausted. May throw DiaphoraWouldRaise
  // (SQL error, invalid UTF-8 at fetch) or UnsupportedInput (see SqlRowSource).
  virtual bool Next(HeuristicRow& Out) = 0;
  // Rows returned by Next() so far.
  virtual uint64_t Fetched() const = 0;
};

// Path A. The statement is prepared, bound and first stepped on the first Next() call, which is where
// Python's cur.execute would run relative to the consumer's checks (for example the
// all_functions_matched early return at D:1956 happens before execute). For every row, Next():
//   1. steps the statement;
//   2. raises DiaphoraWouldRaise("fetch", "invalid UTF-8 ...") when a TEXT column of the row is not
//      valid UTF-8 (SELECT_FIELDS columns through FunctionTable::SelectFieldsUtf8Bad, any other
//      column, such as description or f_names, by direct validation);
//   3. maps ea / ea2 to rows through RowByAddr;
//   4. interns name1, name2 and description;
//   5. reads nodes1/2 and md1/2 as optional values.
// A NULL or non-TEXT ea/ea2, name or description, or a non-INTEGER nodes value, is an input quirk
// the exporter never produces; it throws UnsupportedInput instead of guessing where Python would fail.
class SqlRowSource final : public RowSource {
public:
  SqlRowSource(DiffSession& S, std::string Sql, std::vector<BindValue> Binds = {});
  ~SqlRowSource() override;
  SqlRowSource(const SqlRowSource&) = delete;
  SqlRowSource& operator=(const SqlRowSource&) = delete;

  bool Next(HeuristicRow& Out) override;
  uint64_t Fetched() const override;

  // The underlying statement, positioned on the row Next() returned last (for extra aliases such as
  // f_names / df_names of search_small_differences). Valid only after the first Next().
  const Statement& Current() const;
  std::string_view Sql() const;

private:
  struct Impl;
  std::unique_ptr<Impl> Impl_;
};

// Rows from memory (unit tests, replays of recorded row streams).
class VectorRowSource final : public RowSource {
public:
  explicit VectorRowSource(std::vector<HeuristicRow> Rows) : Rows_(std::move(Rows)) {}
  bool Next(HeuristicRow& Out) override {
    if (Next_ >= Rows_.size()) {
      return false;
    }
    Out = Rows_[Next_++];
    return true;
  }
  uint64_t Fetched() const override { return Next_; }

private:
  std::vector<HeuristicRow> Rows_;
  size_t Next_ = 0;
};

// Maps the rows of a `select *`-shaped Path A statement (functions columns, optionally prefixed by
// `db_name` as in functions_exists, D:2976-2988) to (side, row) pairs by their `address` column.
// Side comes from `db_name` when present ('main' / 'diff'), else from `Default`. At most `Limit`
// rows are fetched: 1 reproduces cur.fetchone() (get_function_row, D:2445-2460), the default
// reproduces fetchall(). A fetched row with invalid UTF-8 in any column raises like Python's fetch.
struct FunctionRowRef {
  Side Which = Side::Main;
  uint32_t Row = kNoRow;
};
std::vector<FunctionRowRef> FetchFunctionRows(DiffSession& S, std::string_view Sql,
                                              std::span<const BindValue> Binds, Side Default,
                                              size_t Limit = SIZE_MAX);

}
