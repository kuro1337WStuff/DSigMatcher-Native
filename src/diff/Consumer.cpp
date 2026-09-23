// L0 STUB of lane L1 (row consumers). L1 replaces this file with the literal port of D:1786-2083
// (spec: 02 §6-§12, 07 §10.5.1-10.5.2, 05 §2.2-§2.3).

#include "dsigmatcher/diff/Consumer.h"

#include "dsigmatcher/diff/Errors.h"

namespace DSig::Diff {

std::optional<double> CheckMatch(DiffSession&, const HeuristicRow&) { throw StageNotImplemented("CheckMatch (L1)"); }

void AddMatchesInternal(DiffSession&, RowSource&, Chooser, std::optional<Chooser>, std::optional<double>) {
  throw StageNotImplemented("AddMatchesInternal (L1)");
}

void AddMatchesFromQuery(DiffSession&, RowSource&, Chooser) { throw StageNotImplemented("AddMatchesFromQuery (L1)"); }

void AddMatchesFromQueryRatio(DiffSession&, RowSource&, Chooser, Chooser) {
  throw StageNotImplemented("AddMatchesFromQueryRatio (L1)");
}

void AddMatchesFromQueryRatioMax(DiffSession&, RowSource&, Chooser, Chooser, double) {
  throw StageNotImplemented("AddMatchesFromQueryRatioMax (L1)");
}

void AddMatchesFromQueryRatioMaxTrusted(DiffSession&, RowSource&, double) {
  throw StageNotImplemented("AddMatchesFromQueryRatioMaxTrusted (L1)");
}

}
