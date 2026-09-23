// L0 STUB of lane L5 (the raising conditions of scripts/patch_diff_vulns.py on_match, :204-236;
// spec: 01 §5.4, 03b §4.4, 05 §8.3).

#include "dsigmatcher/diff/Errors.h"
#include "dsigmatcher/diff/Pipeline.h"
#include "dsigmatcher/diff/Stages.h"

namespace DSig::Diff {

void PatchDiffHookOnMatch(DiffSession&, const HeuristicRow&, double) {
  throw StageNotImplemented("patch_diff_vulns on_match (L5)");
}

}
