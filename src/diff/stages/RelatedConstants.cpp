// L0 STUB of lane L8 (find_related_matches D:3462-3494 and find_related_constants D:3362-3394;
// spec: 06 §7-§8, 07 §10.11.2).

#include "dsigmatcher/diff/Errors.h"
#include "dsigmatcher/diff/Pipeline.h"
#include "dsigmatcher/diff/Stages.h"

namespace DSig::Diff {

void StageFindRelatedMatches(DiffSession& S, int) {
  // D:3467 on_special_heuristic defaults to True without hooks; D:3471 cleanup_matches()
  S.Cleanup(CleanupSite::L3471);
  throw StageNotImplemented("find_related_matches (L8)");
}

void FindRelatedConstants(DiffSession&, uint32_t, uint32_t) { throw StageNotImplemented("find_related_constants (L8)"); }

}
