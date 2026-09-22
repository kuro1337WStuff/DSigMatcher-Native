#pragma once

#include <cstddef>
#include <vector>

#include "dsigmatcher/Types.h"

namespace DSig {

class MatchStore {
public:
  void Add(const Match& Candidate);
  void AddAll(const std::vector<Match>& Candidates);

  size_t RawCount() const { return Raw_.size(); }
  const std::vector<Match>& Raw() const { return Raw_; }

  std::vector<Match> Resolve() const;

private:
  std::vector<Match> Raw_;
};

}
