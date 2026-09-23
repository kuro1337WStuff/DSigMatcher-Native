// L0 STUB of lane L7 (callee diffing: find_matches_diffing D:3211-3229,
// find_matches_diffing_internal D:3150-3193, find_one_match_diffing D:3033-3148;
// spec: 03b §4.3, 06 §4-§6, 07 §10.11.1).

#include "dsigmatcher/diff/Errors.h"
#include "dsigmatcher/diff/Pipeline.h"
#include "dsigmatcher/diff/Stages.h"

namespace DSig::Diff {

void StageFindMatchesDiffing(DiffSession& S, int) {
  S.Cleanup(CleanupSite::L3217);  // D:3217: find_matches_diffing starts with cleanup_matches()
  throw StageNotImplemented("find_matches_diffing (L7)");
}

}
