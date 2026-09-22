#include "dsigmatcher/MatchStore.h"

#include <algorithm>
#include <unordered_map>

namespace DSig {

void MatchStore::Add(const Match& Candidate) {
  Raw_.push_back(Candidate);
}

void MatchStore::AddAll(const std::vector<Match>& Candidates) {
  Raw_.insert(Raw_.end(), Candidates.begin(), Candidates.end());
}

std::vector<Match> MatchStore::Resolve() const {
  std::vector<Match> Ordered = Raw_;

  std::stable_sort(Ordered.begin(), Ordered.end(), [](const Match& Left, const Match& Right) {
    if (Left.Ratio != Right.Ratio) {
      return Left.Ratio > Right.Ratio;
    }
    if (Left.HeuristicId != Right.HeuristicId) {
      return Left.HeuristicId < Right.HeuristicId;
    }
    if (Left.Index1 != Right.Index1) {
      return Left.Index1 < Right.Index1;
    }
    return Left.Index2 < Right.Index2;
  });

  std::vector<Match> Resolved;
  Resolved.reserve(Ordered.size());

  std::unordered_map<uint64_t, size_t> SeenPairs;
  SeenPairs.reserve(Ordered.size() * 2);
  std::vector<char> UsedLeft;
  std::vector<char> UsedRight;

  size_t MaxLeft = 0;
  size_t MaxRight = 0;
  for (const Match& Candidate : Ordered) {
    MaxLeft = std::max(MaxLeft, static_cast<size_t>(Candidate.Index1));
    MaxRight = std::max(MaxRight, static_cast<size_t>(Candidate.Index2));
  }
  UsedLeft.assign(MaxLeft + 1, 0);
  UsedRight.assign(MaxRight + 1, 0);

  for (const Match& Candidate : Ordered) {
    const uint64_t PairKey = (static_cast<uint64_t>(Candidate.Index1) << 32) | Candidate.Index2;
    if (SeenPairs.find(PairKey) != SeenPairs.end()) {
      continue;
    }
    SeenPairs.emplace(PairKey, Resolved.size());

    if (UsedLeft[Candidate.Index1] != 0 || UsedRight[Candidate.Index2] != 0) {
      continue;
    }

    UsedLeft[Candidate.Index1] = 1;
    UsedRight[Candidate.Index2] = 1;
    Resolved.push_back(Candidate);
  }

  return Resolved;
}

}
