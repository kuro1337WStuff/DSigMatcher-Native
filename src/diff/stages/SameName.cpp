// L0 STUB of lane L5 (find_same_name("partial"), D:2152-2210; spec: 01 §5.8, 05 §9, 07 §10.9).

#include "dsigmatcher/diff/Errors.h"
#include "dsigmatcher/diff/Pipeline.h"
#include "dsigmatcher/diff/Stages.h"

namespace DSig::Diff {

void StageFindSameName(DiffSession&) { throw StageNotImplemented("find_same_name (L5)"); }

}
