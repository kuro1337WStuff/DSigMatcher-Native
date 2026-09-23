// L0 STUB of lane L6 (SQL heuristic tiers; spec: 01 §5.10-§5.12, 02 §4-§5, 04a §1-§5, 07 §10.3-§10.4).
//
// What is already here is the literal skeleton: the run_heuristics_for_category list build and
// reverse execution order with its points, the category cleanup and show_summary, and
// find_partial_matches. The per-heuristic dispatch (StageRunSingleHeuristic) and the worker-thread
// error truncation are L6's; the stub dispatch throws StageNotImplemented, which InvokeStage logs as
// SKIPPED per heuristic.

#include <string>
#include <vector>

#include "dsigmatcher/diff/Errors.h"
#include "dsigmatcher/diff/Pipeline.h"
#include "dsigmatcher/diff/Stages.h"

namespace DSig::Diff {

void StageRunHeuristicsForCategory(DiffSession& S, HeurCategory Category) {
  // D:1479-1517 build the list in HEURISTICS order.
  std::vector<int> Runnable;
  for (const HeuristicSpec& Spec : Heuristics()) {
    if (S.State().AllFunctionsMatched()) {  // D:1481-1484, evaluated while building the list
      S.Log().Info("All functions matched in at least one database, finishing.");
      break;
    }
    if (Spec.Category != Category) {  // D:1486-1488
      continue;
    }
    if (Spec.FlagUnreliable && !S.Config().Unreliable) {  // D:1498-1500
      continue;
    }
    if (Spec.FlagSlow && !S.Config().SlowHeuristics) {  // D:1502-1504
      continue;
    }
    if (Spec.FlagSameCpu && !S.Flags().IsSameProcessor) {  // D:1506-1508
      continue;
    }
    Runnable.push_back(Spec.Id);
  }
  // D:1543-1549 threads_apply with one thread: targets.pop() runs the list in reverse
  // (jkutils/threads.py:40), one heuristic at a time.
  for (auto It = Runnable.rbegin(); It != Runnable.rend(); ++It) {
    const std::string Label = "heuristic:" + std::to_string(*It);
    S.Point("before:" + Label);
    {
      ContextScope Scope(S, Label);
      InvokeStage(S, Label, [&] { StageRunSingleHeuristic(S, *It); });
    }
    S.Point("after:" + Label);
  }
  S.Cleanup(CleanupSite::L1551);  // D:1551
  LogShowSummary(S);              // D:1552
  S.Point("after:run_heuristics_for_category:" + std::string(CategoryName(Category)));
}

void StageRunSingleHeuristic(DiffSession&, int Id) {
  throw StageNotImplemented("heuristic " + std::to_string(Id) + " dispatch (L6)");
}

void StageFindPartialMatches(DiffSession& S) {
  // D:2212-2221
  InvokeStage(S, "run_heuristics_for_category:Partial",
              [&] { StageRunHeuristicsForCategory(S, HeurCategory::Partial); });  // D:2216
  if (S.Config().SlowHeuristics) {                                              // D:2218
    S.Point("before:search_small_differences");
    {
      ContextScope Scope(S, "search_small_differences");
      InvokeStage(S, "search_small_differences", [&] { StageSearchSmallDifferences(S); });  // D:2221
    }
    S.Point("after:search_small_differences");
  }
}

}
