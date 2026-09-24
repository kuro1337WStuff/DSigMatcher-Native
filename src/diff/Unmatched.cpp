// find_unmatched: D:2323-2356. Spec: 01 §10.1-§10.3, 02 §16, 07 §10.13.
// D: = diaphora.py at 3.4.2-4-g621ec26.
//
// The labels are swapped in Diaphora: the main-database functions go into the chooser titled
// "Unmatched in primary", which is stored in self.unmatched_second and written with type 'secondary';
// the diff-database functions go into self.unmatched_primary and are written as 'primary'
// (D:2334-2354, D:2414-2415). FinalResults keeps Diaphora's attribute names: UnmatchedPrimary is
// self.unmatched_primary (diff functions), UnmatchedSecondary is self.unmatched_second (main).
//
// The queries run through Path A (kSqlUnmatchedMain / kSqlUnmatchedDiff, `select name, address from
// [diff.]functions`, D:2330 / D:2343): no ORDER BY, so the row order is SQLite's (SCAN, rowid order on
// the real exports, 01 §10.3 V7) and only affects the `line` column.

#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "StateDetail.h"
#include "dsigmatcher/diff/Errors.h"
#include "dsigmatcher/diff/Pipeline.h"
#include "dsigmatcher/diff/StageSql.h"
#include "dsigmatcher/diff/Stages.h"

namespace DSig::Diff {

namespace {

struct NameAddressRow {
  NameId Name = kNoneName;  // row["name"]; None for NULL
  AddrId Ea = kNoneAddr;    // row[1] / row["address"]; None for NULL
};

// Reads one TEXT-affinity cell the way Python's sqlite3 (text_factory = str, D:346) returns it: NULL
// is None, TEXT is str (decoding raises OperationalError at fetch time for invalid UTF-8). Other
// storage classes cannot occur in these TEXT-affinity columns of a real export (name varchar(255),
// address text; db_support/schema.py:70-72) and are refused instead of guessed (BLOB would be Python
// bytes, which the writer would store as a BLOB).
std::optional<std::string_view> TextCell(const Statement& Q, int Column, std::string_view Query) {
  switch (Q.Type(Column)) {
    case SqlType::Null:
      return std::nullopt;
    case SqlType::Text: {
      const std::string_view Bytes = Q.Text(Column);
      if (!IsValidUtf8(Bytes)) {
        throw DiaphoraWouldRaise("fetch", "OperationalError: Could not decode to UTF-8 column '" +
                                              std::string(Q.ColumnName(Column)) + "' (" + std::string(Query) + ")");
      }
      return Bytes;
    }
    default:
      throw UnsupportedInput("find_unmatched: non-TEXT value in column '" + std::string(Q.ColumnName(Column)) +
                             "' of `" + std::string(Query) + "`");
  }
}

// cur.execute(sql); rows = cur.fetchall() (D:2330-2332, D:2343-2345): every row is fetched (and
// decoded) before any is used.
std::vector<NameAddressRow> FetchAll(DiffSession& S, std::string_view Sql) {
  Statement Q = S.Db().Prepare(Sql);
  std::vector<NameAddressRow> Rows;
  while (Q.Step()) {
    NameAddressRow Row;
    Row.Name = S.Ids().NameOpt(TextCell(Q, 0, Sql));
    Row.Ea = S.Ids().AddrOpt(TextCell(Q, 1, Sql));
    Rows.push_back(Row);
  }
  return Rows;
}

// The loop over the fetched rows of one side (D:2335-2340 / D:2348-2353):
//   name = row["name"]; if name not in <dict>: choose.add_item(CChooser.Item(row address, name))
// add_item of an "Unmatched in ..." chooser formats "%08x" % int(item.ea) (D:280), which raises for a
// None or non-integer address.
std::vector<UnmatchedRow> Unmatched(DiffSession& S, const std::vector<NameAddressRow>& Rows, bool MainSide,
                                    const char* AddItemSite) {
  std::vector<UnmatchedRow> Choose;
  for (const NameAddressRow& Row : Rows) {
    const bool Matched = MainSide ? S.State().Primary(Row.Name).has_value()     // D:2338
                                  : S.State().Secondary(Row.Name).has_value();  // D:2351
    if (!Matched) {
      Detail::RequirePyInt(S.Ids(), Row.Ea, AddItemSite);
      Choose.push_back(UnmatchedRow{Row.Ea, Row.Name});
    }
  }
  return Choose;
}

}

void StageFindUnmatched(DiffSession& S) {
  // D:2327 cur = self.db_cursor() (the main connection, diff attached).
  {
    const std::vector<NameAddressRow> Rows = FetchAll(S, kSqlUnmatchedMain);  // D:2330-2332
    if (!Rows.empty()) {                                                      // D:2333
      // D:2334 choose = self.chooser("Unmatched in primary", ...); D:2341 self.unmatched_second = choose
      S.Final().UnmatchedSecondary = Unmatched(S, Rows, true, "D:280 (main)");
    }
    // An empty table leaves the attribute as it was: None since __init__ (D:438-439).
  }
  {
    const std::vector<NameAddressRow> Rows = FetchAll(S, kSqlUnmatchedDiff);  // D:2343-2345
    if (!Rows.empty()) {                                                      // D:2346
      // D:2347 choose = self.chooser("Unmatched in secondary", ...); D:2354 self.unmatched_primary = choose
      S.Final().UnmatchedPrimary = Unmatched(S, Rows, false, "D:280 (diff)");
    }
  }
}

}
