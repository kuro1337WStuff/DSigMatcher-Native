// L0 STUB of lane L1 (final pass). L1 replaces this file with the literal port of D:2937-2948,
// D:2839-2935 and D:2718-2747 (spec: 01 §9, 06 §12-§15, 07 §10.12).

#include "dsigmatcher/diff/Errors.h"
#include "dsigmatcher/diff/Pipeline.h"
#include "dsigmatcher/diff/Stages.h"

namespace DSig::Diff {

void StageFinalPass(DiffSession& S) {
  // D:2945: final_pass starts with cleanup_matches(); the rest is L1's.
  S.Cleanup(CleanupSite::L2945);
  throw StageNotImplemented("final_pass (L1)");
}

}
