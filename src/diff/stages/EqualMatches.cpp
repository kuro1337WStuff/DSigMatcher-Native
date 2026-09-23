// L0 STUB of lane L5 (find_equal_matches, D:1404-1442; spec: 01 §5.5, 05 §5, 07 §10.7).
// While this is a stub, RunPipeline sets the totals from the ingested row counts instead.

#include "dsigmatcher/diff/Errors.h"
#include "dsigmatcher/diff/Pipeline.h"
#include "dsigmatcher/diff/Stages.h"

namespace DSig::Diff {

void StageFindEqualMatches(DiffSession&) { throw StageNotImplemented("find_equal_matches (L5)"); }

}
