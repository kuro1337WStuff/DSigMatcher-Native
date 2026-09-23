// L0 STUB of lane L5 (preflight). L5 replaces this file with the ports of the version check
// (D:3577-3591), equal_db (D:661-687), check_callgraph (D:1288-1338) and
// same_processor_both_databases (D:2950-2967); spec: 01 §5.1-§5.3, §5.6; 05 §3.

#include "dsigmatcher/diff/Errors.h"
#include "dsigmatcher/diff/Pipeline.h"
#include "dsigmatcher/diff/Stages.h"

namespace DSig::Diff {

bool StageCheckVersion(DiffSession&) { throw StageNotImplemented("check_version (L5)"); }

bool StageEqualDb(DiffSession&) { throw StageNotImplemented("equal_db (L5)"); }

void StageCheckCallgraph(DiffSession&) { throw StageNotImplemented("check_callgraph (L5)"); }

bool StageSameProcessor(DiffSession&) { throw StageNotImplemented("same_processor_both_databases (L5)"); }

}
