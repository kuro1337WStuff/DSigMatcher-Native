#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "dsigmatcher/Types.h"

namespace DSig {

struct DiffOptions {
  bool IgnoreSmallFunctions = false;
  bool SameProcessor = false;
  unsigned ThreadCount = 0;
};

struct HeuristicStats {
  std::string Name;
  MatchCategory Category = MatchCategory::Best;
  bool Ran = false;
  std::string SkipReason;
  size_t RawMatches = 0;
};

struct DiffResult {
  std::vector<Match> Resolved;
  std::vector<HeuristicStats> Stats;
  size_t RawMatches = 0;
};

DiffResult RunExactHeuristics(const FunctionTable& OldTable, const FunctionTable& NewTable,
                              const DiffOptions& Options);

const char* CategoryName(MatchCategory Category);

}
