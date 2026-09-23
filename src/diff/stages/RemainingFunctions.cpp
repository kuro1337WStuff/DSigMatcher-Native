// Lane L5: find_remaining_functions (D:2702-2716) with get_unmatched_functions (D:2639-2669) and
// search_remaining_functions (D:2671-2700). Spec: 01 §5.9, 05 §16-§18, 07 §10.8.
// D: = diaphora.py at 3.4.2-4-g621ec26, C: = diaphora_config.py.
//
// Both queries run through Path A: kSqlUnmatchedUnion (its row order is SQLite's UNION USING TEMP
// B-TREE order, (db_name, name, address) in BINARY collation, 05 §16), and kSqlRemainingPair once per
// (main, diff) pair, with the three text binds of D:2695 (the nodes >= 3 suffix of D:2684-2685 is part
// of the constant because `small` is False).

#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "EarlyPasses.h"
#include "dsigmatcher/diff/Config.h"
#include "dsigmatcher/diff/Consumer.h"
#include "dsigmatcher/diff/Errors.h"
#include "dsigmatcher/diff/Pipeline.h"
#include "dsigmatcher/diff/StageSql.h"
#include "dsigmatcher/diff/Stages.h"
#include "dsigmatcher/diff/Table.h"

namespace DSig::Diff {

namespace {

struct UnmatchedKey {
  AddrId Ea = kNoneAddr;    // row["address"] (None for NULL)
  NameId Name = kNoneName;  // row["name"] (None for NULL)
};

// One TEXT-affinity cell (name varchar(255), address text: schema.py:70-72) as Python's sqlite3
// returns it: NULL is None, TEXT is str (decoded at fetch: invalid UTF-8 raises). Another storage
// class would be a Python int / float / bytes used as a dict key and a bind value; no export stores
// one, and it is refused instead of guessed.
std::optional<std::string_view> TextCell(const Statement& Q, int Column) {
  switch (Q.Type(Column)) {
    case SqlType::Null:
      return std::nullopt;
    case SqlType::Text: {
      const std::string_view Bytes = Q.Text(Column);
      if (!IsValidUtf8(Bytes)) {
        throw DiaphoraWouldRaise("fetch", "OperationalError: Could not decode to UTF-8 column '" +
                                              std::string(Q.ColumnName(Column)) + "'");
      }
      return Bytes;
    }
    default:
      throw UnsupportedInput("get_unmatched_functions: a non-TEXT value in column '" +
                             std::string(Q.ColumnName(Column)) + "' is not ported");
  }
}

// get_unmatched_functions (D:2639-2669).
std::pair<std::vector<UnmatchedKey>, std::vector<UnmatchedKey>> GetUnmatchedFunctions(DiffSession& S) {
  // D:2647-2652: rows = cur.fetchall() (every row decoded before any is used).
  Statement Q = S.Db().Prepare(kSqlUnmatchedUnion);
  const int ColDb = Q.FindColumn("db_name");
  const int ColName = Q.FindColumn("name");
  const int ColAddress = Q.FindColumn("address");
  struct Fetched {
    bool Diff = false;
    UnmatchedKey Key;
  };
  std::vector<Fetched> Rows;
  while (Q.Step()) {
    Fetched Row;
    const std::optional<std::string_view> Db = TextCell(Q, ColDb);  // the literal 'main' / 'diff'
    Row.Diff = Db && *Db == "diff";                                 // D:2658 row["db_name"] == "diff"
    Row.Key.Name = S.Ids().NameOpt(TextCell(Q, ColName));
    Row.Key.Ea = S.Ids().AddrOpt(TextCell(Q, ColAddress));
    Rows.push_back(Row);
  }
  std::vector<UnmatchedKey> Main;
  std::vector<UnmatchedKey> Diff;
  std::set<std::pair<AddrId, NameId>> SeenMain;
  std::set<std::pair<AddrId, NameId>> SeenDiff;
  for (const Fetched& Row : Rows) {  // D:2653-2666
    // D:2655-2660: name = row["name"]; d = matched_primary (main) or matched_secondary (diff).
    // D:2662 `if name not in d`: the live dicts, with no cleanup since find_same_name (05 §16).
    const bool Matched = Row.Diff ? S.State().Secondary(Row.Key.Name).has_value()
                                  : S.State().Primary(Row.Key.Name).has_value();
    if (Matched) {
      continue;
    }
    // D:2663-2666: key = [ea, name]; `if key not in l: l.append(key)` (redundant after UNION, 05 §16).
    std::set<std::pair<AddrId, NameId>>& Seen = Row.Diff ? SeenDiff : SeenMain;
    if (Seen.insert({Row.Key.Ea, Row.Key.Name}).second) {
      (Row.Diff ? Diff : Main).push_back(Row.Key);
    }
  }
  return {std::move(Main), std::move(Diff)};
}

BindValue BindOfAddress(const Interners& Ids, AddrId Ea) {
  // cur.execute(sql, (heur, ea1, ea2)) (D:2695): a str binds as TEXT, None as NULL (`address = NULL`
  // then matches no row).
  return Ea == kNoneAddr ? BindValue::Null() : BindValue::Str(Ids.AddrText(Ea));
}

// search_remaining_functions (D:2671-2700) with the values of find_remaining_functions (D:2710-2715):
// only_sub True, small False, val = SPEEDUP_PATCH_DIFF_RENAMED_FUNCTION_MIN_RATIO (C:172, 0.6).
void SearchRemainingFunctions(DiffSession& S, const std::vector<UnmatchedKey>& MainUnmatched,
                              const std::vector<UnmatchedKey>& DiffUnmatched, std::string_view Heur) {
  Early::EarlyFacts& Facts = S.Ext<Early::EarlyFacts>();
  // The lists are snapshots (05 §17): matches made in this loop do not remove pairs from them; only
  // check_match / add_match consult the live state.
  for (const UnmatchedKey& Main : MainUnmatched) {  // D:2689
    // D:2690-2692: `if not name1.startswith("sub_"): continue` (case-sensitive; None raises).
    if (Main.Name == kNoneName) {
      throw DiaphoraWouldRaise("D:2691 AttributeError", "'NoneType' object has no attribute 'startswith'");
    }
    if (!S.Ids().NameText(Main.Name).starts_with("sub_")) {
      continue;
    }
    for (const UnmatchedKey& Diff : DiffUnmatched) {  // D:2694 every diff leftover, named or not
      // D:2695 cur.execute(sql, (values["heur"], ea1, ea2)); the statement runs on the first fetch,
      // at the top of add_matches_internal's loop, with nothing in between.
      std::vector<BindValue> Binds{BindValue::Str(Heur), BindOfAddress(S.Ids(), Main.Ea),
                                   BindOfAddress(S.Ids(), Diff.Ea)};
      SqlRowSource Rows(S, std::string(kSqlRemainingPair), std::move(Binds));
      ++Facts.RemainingQueries;
      // D:2696-2698 add_matches_internal(cur, best="best", partial="partial", val=0.6): 1.0 -> best,
      // >= 0.6 -> partial, else dropped; unreliable=None.
      AddMatchesInternal(S, Rows, Chooser::Best, Chooser::Partial, kSpeedupPatchDiffRenamedFunctionMinRatio);
    }
  }
}

}

void StageFindRemainingFunctions(DiffSession& S) {
  // D:2707: the leftover lists are always computed (also in stripped mode, where nothing uses them,
  // but where the query and its decoding still run).
  const auto [MainUnmatched, DiffUnmatched] = GetUnmatchedFunctions(S);
  Early::EarlyFacts& Facts = S.Ext<Early::EarlyFacts>();
  Facts.RemainingMainUnmatched = MainUnmatched.size();
  Facts.RemainingDiffUnmatched = DiffUnmatched.size();
  if (!S.Flags().IsPatchDiff) {  // D:2708
    return;
  }
  // D:2709-2716
  SearchRemainingFunctions(S, MainUnmatched, DiffUnmatched,
                           "Renamed or anonymous function match in patch diffing session");
}

}
