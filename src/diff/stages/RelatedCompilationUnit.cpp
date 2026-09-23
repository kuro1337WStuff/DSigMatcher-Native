// L0 STUB of lane L8 (find_related_compilation_unit D:3395-3460 and the native cartesian replay;
// spec: 06 §9-§10, 07 §10.11.3, plan §0.3).

#include "dsigmatcher/diff/Errors.h"
#include "dsigmatcher/diff/Pipeline.h"
#include "dsigmatcher/diff/Stages.h"

namespace DSig::Diff {

void StageFindRelatedCompilationUnit(DiffSession& S, int) {
  // D:3409 on_special_heuristic defaults to True without hooks; D:3413 cleanup_matches()
  S.Cleanup(CleanupSite::L3413);
  throw StageNotImplemented("find_related_compilation_unit (L8)");
}

struct CuReplaySource::Impl {};

CuReplaySource::CuReplaySource(DiffSession&, double, double, double, double) {
  throw StageNotImplemented("CuReplaySource (L8)");
}

CuReplaySource::~CuReplaySource() = default;

bool CuReplaySource::Next(HeuristicRow&) { throw StageNotImplemented("CuReplaySource::Next (L8)"); }

uint64_t CuReplaySource::Fetched() const { return 0; }

bool CuReplayPlanOk(DiffSession&) { throw StageNotImplemented("CuReplayPlanOk (L8)"); }

}
