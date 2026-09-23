#pragma once

// Private to lane L5 (src/diff/stages/Preflight.cpp, EqualMatches.cpp, DirtyHeuristics.cpp,
// SameName.cpp, RemainingFunctions.cpp, PatchDiffHook.cpp); not part of the frozen API.
//
// Session state of the pre-loop passes, kept in DiffSession::Ext<T>() (Pipeline.h) so that no frozen
// header changes:
//   * PatchDiffHookState: the `dones` set of the loaded patch-diff hook object
//     (scripts/patch_diff_vulns.py:67, :211-214);
//   * EarlyFacts: what the passes computed on the way (counts and the dirty-heuristic percentages).
//     Nothing reads it back for matching; it exists for tests and reports (the dirty percentages of
//     05 §19.1 are not logged by Diaphora when a speed-up does not fire).

#include <cstddef>
#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <utility>

#include "dsigmatcher/diff/Interner.h"

namespace DSig::Diff::Early {

// CVulnerabilityPatches.dones (scripts/patch_diff_vulns.py:67). The key is str([name1, name2])
// (:211): repr() of a str is injective and repr(None) = "None" differs from repr("None") = "'None'",
// so two keys are equal exactly when both names are equal, None only matching None. A pair of
// NameIds (kNoneName for None) is therefore the same key.
struct PatchDiffHookState {
  std::set<std::pair<NameId, NameId>> Dones;
};

struct DirtyHeuristicFacts {
  bool Evaluated = false;  // the count query ran and the percent was computed
  int64_t Matches = 0;     // row[0] of the count query
  int64_t Total = 0;       // total_functions1
  double Percent = 0.0;    // (matches * 100) / total
  bool Fired = false;
};

struct EarlyFacts {
  std::optional<bool> EqualDb;                 // equal_db()'s return value (D:661-687)
  std::optional<std::string> CallgraphLog;     // the check_callgraph log line (D:1330-1336), when known
  int64_t EqualRows = 0;                       // find_equal_matches INTERSECT rows (D:1432)
  DirtyHeuristicFacts Stripped;                // search_just_stripped_binaries (D:2540-2585)
  DirtyHeuristicFacts Patch;                   // search_patchdiff_with_symbols (D:2587-2627)
  int64_t SameNameRows = 0;                    // find_same_name fetchall() rows (D:2172)
  int64_t SameNameSkippedSub = 0;              // rows skipped by ignore_sub_names (D:2179-2180)
  bool SameNameLoopRan = false;                // the D:2174 condition held
  size_t RemainingMainUnmatched = 0;           // get_unmatched_functions list sizes (D:2639-2669)
  size_t RemainingDiffUnmatched = 0;
  int64_t RemainingQueries = 0;                // search_remaining_functions executes (D:2695)
  int64_t HookAnalysed = 0;                    // on_match calls that ran the two searches (:216-218)
  int64_t HookFound = 0;                       // ... of which found something (:222)
};

}
