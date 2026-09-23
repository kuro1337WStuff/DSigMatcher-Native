#pragma once

// One function per Diaphora pass, owned by the lanes of docs/parity/00-plan.md §4. All of them run
// on the single diff thread, in Diaphora's order, called by RunPipeline / RunReplay (Pipeline.h).
//
// Points and cleanups. RunPipeline emits the before/after points of the top-level stages it calls
// (Appendix B). A stage function itself must:
//   * call S.Cleanup(CleanupSite::Lxxxx) for every cleanup_matches() it contains (that call emits
//     "before:cleanup:<site>:<n>", runs MatchState::Cleanup and emits "after:...");
//   * emit the points of the Diaphora methods it calls that Appendix B wraps, with S.Point(...):
//     StageRunHeuristicsForCategory emits "before:heuristic:<id>" / "after:heuristic:<id>" around
//     each heuristic it runs and "after:run_heuristics_for_category:<Best|Partial>" as its last act;
//     StageFindPartialMatches emits "before:/after:search_small_differences" around that call.
// Errors: throw DiaphoraWouldRaise at the Python raise site (§3.11). Heuristic workers truncate that
// heuristic and continue (inside StageRunHeuristicsForCategory); main-thread passes let it propagate.
// UnsupportedInput (a quirk the port refuses) and IoFailure / SqliteEnvironmentFailure (the disk, the
// temporary directory, a damaged file) are never caught by a stage: they end the run (Errors.h).

#include <cstdint>
#include <memory>
#include <string_view>

#include "dsigmatcher/diff/Candidates.h"
#include "dsigmatcher/diff/Registry.h"

namespace DSig::Diff {

class DiffSession;

// ---- L5 stages/Preflight.cpp -----------------------------------------------------------------
// D:3577-3591: `select value from diff.version`; false when it raises or returns no row (diff()
// returns False and save_results writes empty tables); a different value only logs the warning.
bool StageCheckVersion(DiffSession& S);
// D:661-687 equal_db. Log only; may raise (SQL failure).
bool StageEqualDb(DiffSession& S);
// D:1288-1338 check_callgraph / get_callgraph_difference: validation of the program rows (exactly 2
// in the union, Decimal callgraph_primes, JSON callgraph_all_primes); log only otherwise.
void StageCheckCallgraph(DiffSession& S);
// D:2950-2967 same_processor_both_databases.
bool StageSameProcessor(DiffSession& S);

// ---- L5 stages/EqualMatches.cpp -------------------------------------------------------------
// D:1404-1442 find_equal_matches; also MatchState::SetTotals (D:1411-1419).
void StageFindEqualMatches(DiffSession& S);

// ---- L5 stages/DirtyHeuristics.cpp ----------------------------------------------------------
// D:2629-2637 apply_dirty_heuristics = search_just_stripped_binaries (D:2540-2585) then
// search_patchdiff_with_symbols (D:2587-2627). Sets IsSymbolsStripped / IsPatchDiff / HooksLoaded.
bool StageApplyDirtyHeuristics(DiffSession& S);

// ---- L5 stages/SameName.cpp -----------------------------------------------------------------
// D:2152-2210 find_same_name("partial").
void StageFindSameName(DiffSession& S);

// ---- L5 stages/RemainingFunctions.cpp -------------------------------------------------------
// D:2702-2716 find_remaining_functions (get_unmatched_functions D:2639-2669, search_remaining_functions
// D:2671-2700 with val 0.6).
void StageFindRemainingFunctions(DiffSession& S);

// ---- L5 stages/PatchDiffHook.cpp ------------------------------------------------------------
// scripts/patch_diff_vulns.py on_match (:204-236): returns (True, ratio) on every path, so only its
// raising conditions are reproduced (find_vulns_using_assembly / _pseudocode, e.g. IndexError at :162).
// Called by CheckMatch when S.Flags().HooksLoaded. Throws DiaphoraWouldRaise when Python would raise.
void PatchDiffHookOnMatch(DiffSession& S, const HeuristicRow& Row, double Ratio);

// ---- L6 stages/HeuristicTiers.cpp -----------------------------------------------------------
// D:1461-1552 run_heuristics_for_category: list build in HEURISTICS order with the build-time
// all_functions_matched break and the UNRELIABLE / SLOW / SAME_CPU filters, then execution in reverse
// order (jkutils/threads.py:40), per-heuristic DiaphoraWouldRaise truncation, Cleanup(L1551) and
// show_summary. Emits "before:/after:heuristic:<id>" around each heuristic and finally
// "after:run_heuristics_for_category:<CategoryName>".
void StageRunHeuristicsForCategory(DiffSession& S, HeurCategory Category);
// Runs heuristic `Id` exactly as its worker thread would (dispatch by RatioType, %POSTFIX% applied,
// the add_matches_* wrapper's all_functions_matched early return). Used by the category runner and
// by replays of "heuristic:<id>". No points, no cleanup.
void StageRunSingleHeuristic(DiffSession& S, int Id);
// D:2212-2221 find_partial_matches: the Partial category, then (slow heuristics) search_small_differences.
void StageFindPartialMatches(DiffSession& S);

// ---- L6 stages/SmallDifferences.cpp ---------------------------------------------------------
// D:2085-2150 search_small_differences("partial").
void StageSearchSmallDifferences(DiffSession& S);

// ---- L7 stages/CalleeDiffing.cpp ------------------------------------------------------------
// D:3211-3229 find_matches_diffing (find_matches_diffing_internal D:3150-3193,
// find_one_match_diffing D:3033-3148).
void StageFindMatchesDiffing(DiffSession& S, int Iteration);

// ---- L8 stages/RelatedConstants.cpp ---------------------------------------------------------
// D:3462-3494 find_related_matches.
void StageFindRelatedMatches(DiffSession& S, int Iteration);
// D:3362-3394 find_related_constants for one (main row, diff row) seed.
void FindRelatedConstants(DiffSession& S, uint32_t MainRow, uint32_t DiffRow);

// ---- L8 stages/RelatedCompilationUnit.cpp ---------------------------------------------------
// D:3395-3460 find_related_compilation_unit.
void StageFindRelatedCompilationUnit(DiffSession& S, int Iteration);

// Native replay of kSqlCuCartesian (06 §9.2): (f.id, df.id) ascending with
// Lo <= AddressSqlReal <= Hi on each side. Must equal SqlRowSource over kSqlCuCartesian row for row.
class CuReplaySource final : public RowSource {
public:
  CuReplaySource(DiffSession& S, double Lo1, double Hi1, double Lo2, double Hi2);
  ~CuReplaySource() override;
  CuReplaySource(const CuReplaySource&) = delete;
  CuReplaySource& operator=(const CuReplaySource&) = delete;

  bool Next(HeuristicRow& Out) override;
  uint64_t Fetched() const override;

private:
  struct Impl;
  std::unique_ptr<Impl> Impl_;
};
// The EXPLAIN QUERY PLAN guard: true when kSqlCuCartesian plans as exactly `SCAN f` / `SCAN df`.
bool CuReplayPlanOk(DiffSession& S);

// ---- L8 stages/LocalAffinity.cpp ------------------------------------------------------------
// D:3315-3360 find_locally_affine_functions (find_functions_between D:3231-3313).
void StageFindLocallyAffineFunctions(DiffSession& S, int Iteration);

// ---- L1 FinalPass.cpp / Unmatched.cpp -------------------------------------------------------
// D:2937-2948 final_pass (cleanup at 2945, find_multimatches D:2839-2914, add_final_chooser_items
// D:2916-2935). Fills S.Final() Best / Partial / Unreliable / Multimatch.
void StageFinalPass(DiffSession& S);
// D:2323-2356 find_unmatched (labels swapped). Fills S.Final().UnmatchedPrimary / UnmatchedSecondary.
void StageFindUnmatched(DiffSession& S);

}
