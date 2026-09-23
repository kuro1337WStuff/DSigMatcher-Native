// L0 STUB of lane L5 (apply_dirty_heuristics, D:2629-2637, with search_just_stripped_binaries
// D:2540-2585 and search_patchdiff_with_symbols D:2587-2627; spec: 01 §5.7, 05 §6-§8, 07 §10.8).
// While this is a stub the pipeline takes mode N (skip_others stays False).

#include "dsigmatcher/diff/Errors.h"
#include "dsigmatcher/diff/Pipeline.h"
#include "dsigmatcher/diff/Stages.h"

namespace DSig::Diff {

bool StageApplyDirtyHeuristics(DiffSession&) { throw StageNotImplemented("apply_dirty_heuristics (L5)"); }

}
