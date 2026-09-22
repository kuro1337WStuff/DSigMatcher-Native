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
  double ElapsedMs = 0.0;
};

struct DiffResult {
  std::vector<Match> Resolved;
  std::vector<HeuristicStats> Stats;
  size_t RawMatches = 0;
  double WallMs = 0.0;
};

size_t HeuristicCount();
const char* HeuristicName(size_t Index);
bool HeuristicRequiresSameProcessor(size_t Index);

void RunHeuristic(size_t Index, const FunctionTable& Reference, const FunctionTable& Target,
                  const DiffOptions& Options, std::vector<Match>& Sink);

DiffResult RunExactHeuristics(const FunctionTable& OldTable, const FunctionTable& NewTable,
                              const DiffOptions& Options);

const char* CategoryName(MatchCategory Category);

}
