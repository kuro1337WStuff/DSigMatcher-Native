// Lane L5: apply_dirty_heuristics (D:2629-2637) = search_just_stripped_binaries (D:2540-2585), then
// search_patchdiff_with_symbols (D:2587-2627). Spec: 01 §5.7, 05 §6-§8, 07 §10.8, 03b §4.4.
// D: = diaphora.py at 3.4.2-4-g621ec26, C: = diaphora_config.py.
//
// Every query runs through Path A (kSqlStrippedCount, kSqlStrippedRows, kSqlPatchCount). The stripped
// rows go through AddMatchesFromQueryRatio on the main thread, so a raise inside it aborts the run
// (D:1967-1973 re-raise; the SystemExit timeout of D:1965-1966 is not emulated, plan §0.8).

#include <cstdint>
#include <string>

#include "EarlyPasses.h"
#include "dsigmatcher/diff/Config.h"
#include "dsigmatcher/diff/Consumer.h"
#include "dsigmatcher/diff/Errors.h"
#include "dsigmatcher/diff/Pipeline.h"
#include "dsigmatcher/diff/PyValue.h"
#include "dsigmatcher/diff/StageSql.h"
#include "dsigmatcher/diff/Stages.h"

namespace DSig::Diff {

namespace {

// `row = cur.fetchone(); matches = row[0]` of a `select count(0) ...` (D:2555-2557, D:2603-2605).
int64_t CountOf(DiffSession& S, std::string_view Sql) {
  Statement Q = S.Db().Prepare(Sql);
  if (!Q.Step() || Q.Type(0) != SqlType::Integer) {
    throw UnsupportedInput("apply_dirty_heuristics: the count query returned no INTEGER");
  }
  const int64_t Value = Q.Int(0);
  Q.Step();  // fetchone() steps once more after building the row (a count has no second row)
  return Value;
}

// `(matches * 100) / total` (D:2562, D:2609): Python int * int is exact and int / int is the
// correctly rounded quotient. When both operands are at most 2**53 in magnitude they are exact
// doubles, and IEEE division of exact operands is correctly rounded, so the double quotient is
// Python's. Larger operands are refused rather than approximated (no corpus pair comes near).
double PercentOf(int64_t Matches, int64_t Total, const char* Site) {
  constexpr int64_t Exact = int64_t{1} << 53;
  if (Matches < 0 || Matches > Exact / 100) {
    throw UnsupportedInput(std::string(Site) + ": a match count above 2**53 / 100 is not ported");
  }
  const int64_t Scaled = Matches * 100;
  if (Total == 0) {
    // total_functions1 == 0 (an empty main database): ZeroDivisionError on the main thread, no output
    // file (01 §13, 05 §7).
    throw DiaphoraWouldRaise(std::string(Site) + " ZeroDivisionError", "division by zero (total_functions1 == 0)");
  }
  if (Total > Exact || Total < -Exact) {
    throw UnsupportedInput(std::string(Site) + ": a function count above 2**53 is not ported");
  }
  return static_cast<double>(Scaled) / static_cast<double>(Total);
}

bool SearchJustStrippedBinaries(DiffSession& S) {
  Early::DirtyHeuristicFacts& Facts = S.Ext<Early::EarlyFacts>().Stripped;
  const int64_t Total = S.State().Total1();                 // D:2547 total = self.total_functions1
  const int64_t Matches = CountOf(S, kSqlStrippedCount);    // D:2551-2557 (f.address = df.address, TEXT)
  const double Percent = PercentOf(Matches, Total, "D:2562");  // D:2562
  Facts.Evaluated = true;
  Facts.Matches = Matches;
  Facts.Total = Total;
  Facts.Percent = Percent;
  if (!(Percent >= kSpeedupStrippedBinariesMinPercent)) {   // D:2563, C:160 (99.0, inclusive)
    return false;                                           // D:2585 ret = False
  }
  Facts.Fired = true;
  S.Flags().IsSymbolsStripped = true;                       // D:2564
  // D:2565-2566 (f-string: {percent} is repr(float))
  S.Log().Info("Symbols stripped detected: A total of " + std::to_string(Matches) + " matches out of " +
               std::to_string(Total) + ", " + PyReprFloat(Percent) + "% percent have the same address");
  // D:2568-2577 select distinct <SELECT_FIELDS 'Same binary with symbols stripped'> ... where
  // f.address = df.address; D:2580 add_matches_from_query_ratio(sql, "best", "partial"): the
  // all_functions_matched early return (D:1956), then add_matches_internal with val None -> 0.5.
  SqlRowSource Rows(S, std::string(kSqlStrippedRows));
  AddMatchesFromQueryRatio(S, Rows, Chooser::Best, Chooser::Partial);
  return true;                                              // D:2581
}

bool SearchPatchdiffWithSymbols(DiffSession& S) {
  Early::DirtyHeuristicFacts& Facts = S.Ext<Early::EarlyFacts>().Patch;
  const int64_t Total = S.State().Total1();                 // D:2595
  // D:2599-2605: a PAIR count over f.mangled_function = df.mangled_function (NULL never equal;
  // duplicated names multiply, so the percent can exceed 100).
  const int64_t Matches = CountOf(S, kSqlPatchCount);
  const double Percent = PercentOf(Matches, Total, "D:2609");  // D:2609
  Facts.Evaluated = true;
  Facts.Matches = Matches;
  Facts.Total = Total;
  Facts.Percent = Percent;
  if (!(Percent > kSpeedupPatchDiffSymbolsMinPercent)) {    // D:2610, C:166 (90.0, strict)
    return false;
  }
  Facts.Fired = true;
  S.Flags().IsPatchDiff = true;                             // D:2614
  // D:2615-2619: project_script is None in the parity configuration (plan §1.1: DIAPHORA_PROJECT_SCRIPT
  // unset, D:421) and RUN_DEFAULT_SCRIPTS is True (C:186), so config.DEFAULT_SCRIPT_PATCH_DIFF
  // (scripts/patch_diff_vulns.py) is loaded as the hooks: a new CVulnerabilityPatches object, whose
  // `dones` set starts empty (:67). load_hooks' return value is ignored (D:2619).
  S.Flags().HooksLoaded = true;
  S.Ext<Early::PatchDiffHookState>().Dones.clear();
  S.Log().Info("Patch diffing detected: A total of " + std::to_string(Matches) + " matches out of " +
               std::to_string(Total) + ", " + PyReprFloat(Percent) + "% percent have the same name");  // D:2621-2622
  return true;                                              // D:2623
}

}

bool StageApplyDirtyHeuristics(DiffSession& S) {
  // D:2633-2637: short-circuit; the patch-diff check is not evaluated when the stripped one fired.
  if (SearchJustStrippedBinaries(S)) {
    return true;
  }
  if (SearchPatchdiffWithSymbols(S)) {
    return true;
  }
  return false;
}

}
