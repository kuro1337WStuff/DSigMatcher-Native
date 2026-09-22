#pragma once

#include <cstddef>
#include <vector>

#include "dsigmatcher/Types.h"

namespace DSig {

class ThreadPool;

class MatchStore {
public:
  void Add(const Match& Candidate);
  void AddAll(const std::vector<Match>& Candidates);

  size_t RawCount() const { return Raw_.size(); }
  const std::vector<Match>& Raw() const { return Raw_; }

  void SetPool(ThreadPool* Pool) { Pool_ = Pool; }

  std::vector<Match> Resolve(unsigned ThreadCount = 0) const;

private:
  std::vector<Match> Raw_;
  ThreadPool* Pool_ = nullptr;
};

}
