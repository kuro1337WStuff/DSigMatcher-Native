// Lane L6: search_small_differences("partial") (D:2085-2150), the last step of find_partial_matches
// (D:2218-2221). Spec: 05 §11, 01 §5.11, 02 §5.1 and §5.5, 07 §10.10. D: = diaphora.py (Diaphora
// 3.4.2-4-g621ec26), C: = diaphora_config.py.
//
// It runs on the main thread: every exception propagates out of diff() (no `except`, D:2108-2150),
// so the run aborts with no output (plan §3.11).

#include <algorithm>
#include <cstdint>
#include <exception>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "TiersDetail.h"
#include "dsigmatcher/diff/Config.h"
#include "dsigmatcher/diff/Consumer.h"
#include "dsigmatcher/diff/Errors.h"
#include "dsigmatcher/diff/Pipeline.h"
#include "dsigmatcher/diff/PyValue.h"
#include "dsigmatcher/diff/StageSql.h"
#include "dsigmatcher/diff/Stages.h"

namespace DSig::Diff {

namespace {

// One fetched row: SELECT_FIELDS plus the two extra aliases (D:2097-2098 `f.names f_names,
// df.names df_names`), captured while the statement is on the row.
struct SmallRow {
  HeuristicRow Row;
  std::optional<std::string> FNames;   // nullopt: SQL NULL (Python None)
  std::optional<std::string> DfNames;
};

// result_iter(cur) (D:139-146, called at D:2110): `cursor.fetchmany(1000)` in a loop. Python 3.13's
// sqlite3 converts a row (decoding every TEXT column, db.text_factory = str at D:346) when it fetches
// that row, and steps to the NEXT row before returning it; fetchmany collects up to 1000 rows and
// returns nothing when any of those calls raises. (CPython's Modules/_sqlite/cursor.c was not read
// for this port: the behaviour below is what was measured.) Measured on the oracle's Python 3.13.12 /
// SQLite 3.51.1 (lane L6 probe on a 2100-row cursor, scratch only; diff_tiers pins the same counts):
//   * invalid UTF-8 in row 5, 1000, 1001, 2001 or 2100: 0, 0, 1000, 2000 and 2000 rows reach the loop;
//   * a step error (integer overflow) positioning row 5, 1000, 1001, 1002, 2001 or 2100: 0, 0, 0, 1000,
//     1000 and 2000 rows reach the loop.
// So a batch is filled completely before any of its rows is consumed, and after the 1000th row the
// step to the 1001st already belongs to the batch: its failure discards the batch, while the
// 1001st row's own conversion error surfaces only when the next batch is fetched.
// SqlRowSource::Next() steps (DiaphoraWouldRaise site "sqlite3_step") and then converts (site
// "fetch"), so the look-ahead below separates the two.
class ResultIter {
public:
  static constexpr size_t kArraySize = 1000;  // D:139 arraysize=1000

  ResultIter(DiffSession& S, std::string_view Sql) : Source_(S, std::string(Sql)) {}

  // The next row, or nullptr when the cursor is exhausted. Throws where Python's fetchmany raises.
  const SmallRow* Next() {
    if (Pos_ >= Batch_.size()) {
      if (Exhausted_ && !Deferred_ && !Ahead_) {
        return nullptr;
      }
      Fill();
      if (Batch_.empty()) {
        return nullptr;  // D:142-143 `if not results: break`
      }
    }
    return &Batch_[Pos_++];
  }

private:
  SqlRowSource Source_;
  int ColFNames_ = -1;
  int ColDfNames_ = -1;
  std::vector<SmallRow> Batch_;
  size_t Pos_ = 0;
  std::optional<SmallRow> Ahead_;
  std::exception_ptr Deferred_;
  bool Exhausted_ = false;

  std::optional<std::string> Names(int Column, const char* Alias) {
    const Statement& Stmt = Source_.Current();
    switch (Stmt.Type(Column)) {
      case SqlType::Null:
        return std::nullopt;
      case SqlType::Text:
        return std::string(Stmt.Text(Column));  // UTF-8 already validated by SqlRowSource (fetch)
      case SqlType::Blob:
        // Python gets bytes; json.loads(bytes) auto-detects UTF-8/16/32. The column has TEXT
        // affinity (db_support/schema.py) and the exporter writes str, so this is not ported.
        throw UnsupportedInput(std::string("search_small_differences: ") + Alias +
                               " is a BLOB (json.loads(bytes) not ported)");
      default:
        // An INTEGER / REAL value cannot be stored in a TEXT-affinity column; json.loads(int) would
        // raise TypeError.
        throw DiaphoraWouldRaise(std::string("D:2119-2120 TypeError"),
                                 std::string("the JSON object must be str, bytes or bytearray (") + Alias + ")");
    }
  }

  // One row through SqlRowSource (step, then conversion), with its names columns. False at the end.
  bool Fetch(SmallRow& Out) {
    if (!Source_.Next(Out.Row)) {
      return false;
    }
    if (ColFNames_ < 0) {
      ColFNames_ = Source_.Current().FindColumn("f_names");    // row["f_names"] (D:2119)
      ColDfNames_ = Source_.Current().FindColumn("df_names");  // row["df_names"] (D:2120)
      if (ColFNames_ < 0 || ColDfNames_ < 0) {
        throw UnsupportedInput("search_small_differences: the query lacks f_names / df_names");
      }
    }
    Out.FNames = Names(ColFNames_, "f_names");
    Out.DfNames = Names(ColDfNames_, "df_names");
    return true;
  }

  void Fill() {
    Batch_.clear();
    Pos_ = 0;
    if (Deferred_) {
      // the look-ahead row's own conversion failed: Python raises it at this fetchmany
      std::exception_ptr Error = Deferred_;
      Deferred_ = nullptr;
      Exhausted_ = true;
      std::rethrow_exception(Error);
    }
    if (Ahead_) {
      Batch_.push_back(std::move(*Ahead_));
      Ahead_.reset();
    }
    while (!Exhausted_ && Batch_.size() < kArraySize) {
      SmallRow Row;
      if (!Fetch(Row)) {  // an exception here discards the whole batch, as fetchmany does
        Exhausted_ = true;
        break;
      }
      Batch_.push_back(std::move(Row));
    }
    if (!Exhausted_ && Batch_.size() == kArraySize) {
      // Python steps to row 1001 while fetching row 1000 (inside this batch).
      SmallRow Row;
      try {
        if (Fetch(Row)) {
          Ahead_ = std::move(Row);
        } else {
          Exhausted_ = true;
        }
      } catch (const DiaphoraWouldRaise& Error) {
        if (Error.Site == "sqlite3_step") {
          Batch_.clear();
          throw;  // the step failed during this fetchmany: the batch is lost
        }
        Deferred_ = std::current_exception();  // the conversion of row 1001 belongs to the next batch
      } catch (...) {
        Deferred_ = std::current_exception();
      }
    }
  }
};

// set(json.loads(text)) (D:2119-2120). json.loads(None) raises TypeError; PyJsonLoadsList /
// PySetFromList raise where Python raises (invalid JSON, a non-iterable value, an unhashable element).
PySet NamesSet(const std::optional<std::string>& Text, const char* Site) {
  if (!Text) {
    throw DiaphoraWouldRaise(std::string(Site) + " TypeError",
                             "the JSON object must be str, bytes or bytearray, not NoneType");
  }
  return PySetFromList(PyJsonLoadsList(*Text));
}

// int(row["nodesN"]) (D:2116-2117): int(None) raises TypeError.
int64_t IntOfNodes(const std::optional<int64_t>& Nodes, const char* Site) {
  if (!Nodes) {
    throw DiaphoraWouldRaise(std::string(Site) + " TypeError",
                             "int() argument must be a string, a bytes-like object or a real number, not 'NoneType'");
  }
  return *Nodes;
}

}  // namespace

void StageSearchSmallDifferences(DiffSession& S) {
  // D:2089-2106: the query is kSqlSmallDifferences (verbatim in StageSql.inc, rendered from
  // get_query_fields(name) plus the f_names / df_names aliases).
  Tiers::SearchSmallDifferencesWith(S, kSqlSmallDifferences);
}

void Tiers::SearchSmallDifferencesWith(DiffSession& S, std::string_view Sql) {
  // D:2085 search_small_differences(self, choose) is called with choose = "partial" (D:2221).
  const Chooser Choose = Chooser::Partial;
  // D:2109-2110: cur.execute(sql) and rows = result_iter(cur). No all_functions_matched() check, no
  // row cap, no timeout (05 §11).
  ResultIter Rows(S, Sql);
  while (const SmallRow* Current = Rows.Next()) {  // D:2111
    const HeuristicRow& Row = Current->Row;
    // D:2112-2114: ea = str(row["ea"]) (cannot raise), name1 / name2 read as they are.
    const int64_t Nodes1 = IntOfNodes(Row.Nodes1, "D:2116");  // D:2116
    const int64_t Nodes2 = IntOfNodes(Row.Nodes2, "D:2117");  // D:2117
    const PySet S1 = NamesSet(Current->FNames, "D:2119");     // D:2119
    const PySet S2 = NamesSet(Current->DfNames, "D:2120");    // D:2120
    const size_t Total = std::max(S1.Size(), S2.Size());      // D:2121
    const size_t Commons = PySetIntersectionSize(S1, S2);     // D:2122
    if (Total == 0) {
      // D:2123 (commons * 1.0) / total with total == 0: ZeroDivisionError, e.g. f.names '[ ]'
      // (passes `f.names != '[]'`) against an empty diff list (05 §11).
      throw DiaphoraWouldRaise("D:2123 ZeroDivisionError", "float division by zero");
    }
    // D:2123: commons * 1.0 is exact (a set size), then a correctly rounded IEEE division.
    const double NamesRatio = (static_cast<double>(Commons) * 1.0) / static_cast<double>(Total);
    // D:2124-2125: has_better_match with the NAMES ratio, before check_match (05 §11).
    if (S.State().HasBetterMatch(Row.Name1, Row.Name2, NamesRatio)) {
      continue;
    }
    if (!(NamesRatio >= kDefaultPartialRatio)) {  // D:2127 (C:137 DEFAULT_PARTIAL_RATIO = 0.5)
      continue;
    }
    // D:2129-2131: check_match (nullsub, has_best_match, check_ratio, has_better_match, hook); it
    // writes the row trace event itself (Consumer.cpp).
    const std::optional<double> Checked = CheckMatch(S, Row);
    if (!Checked) {
      continue;
    }
    const double Ratio = *Checked;  // D:2133 ratio = ratio2: no lower bound (05 §11 scenario E)
    // D:2134-2140 re-read the row: str(ea) ("None" for a NULL address, which SqlRowSource refuses),
    // ea2, names, description, int(nodes) (already converted above, so they cannot raise now).
    const AddrId Ea = Row.Ea1 == kNoneAddr ? S.Ids().Addr("None") : Row.Ea1;
    // D:2142 item = [ea, name1, ea2, name2, desc, ratio, nodes1, nodes2]; no int(ea) here (unlike
    // add_matches_internal's "0x%x" % int(ea), D:1935).
    const Item It{Ea, Row.Name1, Row.Ea2, Row.Name2, Row.Desc, Ratio, Nodes1, Nodes2};
    const Chooser Target = Ratio == 1.0 ? Chooser::Best : Choose;  // D:2143-2146
    S.State().AddMatch(Row.Name1, Row.Name2, Ratio, It, Target);    // D:2148
  }
  // D:2149-2150 finally: cur.close()
}

}  // namespace DSig::Diff
