// L0 STUB of lane L8 (find_locally_affine_functions D:3315-3360 and find_functions_between
// D:3231-3313; spec: 06 §11, 07 §10.11.4).

#include "dsigmatcher/diff/Errors.h"
#include "dsigmatcher/diff/Pipeline.h"
#include "dsigmatcher/diff/Stages.h"

namespace DSig::Diff {

void StageFindLocallyAffineFunctions(DiffSession& S, int) {
  // D:3336 on_special_heuristic defaults to True without hooks; D:3340 cleanup_matches()
  S.Cleanup(CleanupSite::L3340);
  throw StageNotImplemented("find_locally_affine_functions (L8)");
}

}
