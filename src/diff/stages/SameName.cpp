// Lane L5: find_same_name("partial") (D:2152-2210). Spec: 01 §5.8, 05 §9, 07 §10.9.
// D: = diaphora.py at 3.4.2-4-g621ec26, C: = diaphora_config.py.
//
// The query is kSqlSameName through Path A (select distinct SELECT_FIELDS 'Perfect match, same name'
// ... where (df.mangled_function = f.mangled_function or df.name = f.name) and f.name not like
// 'nullsub_%'). The `not like` is SQLite's: ASCII case-insensitive, '_' matches one character.

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "EarlyPasses.h"
#include "dsigmatcher/diff/Config.h"
#include "dsigmatcher/diff/Consumer.h"
#include "dsigmatcher/diff/Errors.h"
#include "dsigmatcher/diff/Pipeline.h"
#include "dsigmatcher/diff/StageSql.h"
#include "dsigmatcher/diff/Stages.h"

namespace DSig::Diff {

namespace {

// row["mangled1"] as Python sees it for `name.startswith("sub_")` (D:2176, D:2179).
enum class MangledKind : uint8_t { Text, None, Bytes, Number };

struct SameNameRow {
  HeuristicRow Row;
  MangledKind Kind = MangledKind::Text;
  bool SubPrefix = false;  // str.startswith("sub_"): case-sensitive, a byte prefix for this ASCII prefix
};

}

void StageFindSameName(DiffSession& S) {
  Early::EarlyFacts& Facts = S.Ext<Early::EarlyFacts>();
  // D:2170-2172: cur.execute(sql); rows = cur.fetchall(). Every row is fetched, and every TEXT cell
  // decoded (SqlRowSource raises for invalid UTF-8 like Python's fetch), before the first row is used.
  std::vector<SameNameRow> Rows;
  {
    SqlRowSource Source(S, std::string(kSqlSameName));
    int ColMangled1 = -1;
    HeuristicRow Row;
    while (Source.Next(Row)) {
      const Statement& Q = Source.Current();
      if (ColMangled1 < 0) {
        ColMangled1 = Q.FindColumn("mangled1");
        if (ColMangled1 < 0) {
          throw UnsupportedInput("find_same_name: the query does not select mangled1");
        }
      }
      SameNameRow Entry;
      Entry.Row = Row;
      switch (Q.Type(ColMangled1)) {
        case SqlType::Text:
          Entry.Kind = MangledKind::Text;
          Entry.SubPrefix = Q.Text(ColMangled1).starts_with("sub_");
          break;
        case SqlType::Null:
          Entry.Kind = MangledKind::None;
          break;
        case SqlType::Blob:
          Entry.Kind = MangledKind::Bytes;
          break;
        default:
          Entry.Kind = MangledKind::Number;
          break;
      }
      Rows.push_back(Entry);
    }
  }
  Facts.SameNameRows = static_cast<int64_t>(Rows.size());

  // D:2174: all_functions_matched() is evaluated once, before the loop (01 §5.8).
  if (Rows.empty() || S.State().AllFunctionsMatched()) {
    return;
  }
  Facts.SameNameLoopRan = true;
  const bool IgnoreSubNames = S.Config().IgnoreSubNames;  // C:50 DIFFING_IGNORE_SUB_FUNCTION_NAMES (True)
  for (const SameNameRow& Entry : Rows) {
    const HeuristicRow& Row = Entry.Row;
    // D:2176-2180: name = row["mangled1"] (the MAIN side's mangled name, not name1);
    // `if self.ignore_sub_names and name.startswith("sub_"): continue`.
    if (IgnoreSubNames) {
      switch (Entry.Kind) {
        case MangledKind::None:
          throw DiaphoraWouldRaise("D:2179 AttributeError", "'NoneType' object has no attribute 'startswith'");
        case MangledKind::Bytes:
          // bytes.startswith("sub_"): a str argument raises TypeError
          throw DiaphoraWouldRaise("D:2179 TypeError", "startswith first arg must be bytes or a tuple of bytes, not str");
        case MangledKind::Number:
          throw DiaphoraWouldRaise("D:2179 AttributeError", "the mangled1 value has no attribute 'startswith'");
        case MangledKind::Text:
          break;
      }
      if (Entry.SubPrefix) {
        ++Facts.SameNameSkippedSub;
        continue;
      }
    }
    // D:2183-2185: check_match (nullsub_ names, has_best_match, check_ratio, has_better_match, the
    // patch-diff hook when loaded).
    const std::optional<double> Checked = CheckMatch(S, Row);
    if (!Checked) {
      continue;
    }
    double Ratio = *Checked;
    // D:2187-2195. ea = str(row["ea"]): SqlRowSource only yields TEXT addresses, so str() is the text.
    // nodes1 = int(row["nodes1"]), nodes2 = int(row["nodes2"]): int(None) raises TypeError.
    if (!Row.Nodes1) {
      throw DiaphoraWouldRaise("D:2192 TypeError",
                               "int() argument must be a string, a bytes-like object or a real number, not 'NoneType'");
    }
    if (!Row.Nodes2) {
      throw DiaphoraWouldRaise("D:2193 TypeError",
                               "int() argument must be a string, a bytes-like object or a real number, not 'NoneType'");
    }
    const int64_t Nodes1 = *Row.Nodes1;
    const int64_t Nodes2 = *Row.Nodes2;
    // D:2196-2206. `float(ratio) == 1.0 or (self.relaxed_ratio and ...)`: relaxed_ratio is False
    // (C:47, plan §1.1), so md1/md2 (D:2194-2195) are never compared.
    Chooser Target = Chooser::Best;
    Item It{Row.Ea1, Row.Name1, Row.Ea2, Row.Name2, Row.Desc, 1.0, Nodes1, Nodes2};  // D:2200: ratio int 1
    if (!(Ratio == 1.0)) {
      Target = Chooser::Partial;  // D:2202 the_chooser = choose ("partial", D:3624)
      // D:2203-2204: the bonus only when the IEEE sum stays below 1.0 (0.99 + 0.01 == 1.0, so 0.99
      // keeps 0.99); there is no lower bound (05 H5).
      if (Ratio + kMatchesBonusRatio < 1.0) {
        Ratio += kMatchesBonusRatio;
      }
      It.Ratio = Ratio;  // D:2206
    }
    S.State().AddMatch(Row.Name1, Row.Name2, Ratio, It, Target);  // D:2208
  }
}

}
