#include "dsigmatcher/PrimeTable.h"

namespace DSig {

PrimeTable::PrimeTable(uint32_t Limit) : Limit_(Limit) {
  if (Limit <= 2) {
    return;
  }

  std::vector<char> Composite(static_cast<size_t>(Limit), 0);
  Composite[0] = 1;
  Composite[1] = 1;

  for (uint64_t Candidate = 2; Candidate * Candidate < static_cast<uint64_t>(Limit); ++Candidate) {
    if (Composite[static_cast<size_t>(Candidate)] != 0) {
      continue;
    }
    for (uint64_t Multiple = Candidate * Candidate; Multiple < static_cast<uint64_t>(Limit);
         Multiple += Candidate) {
      Composite[static_cast<size_t>(Multiple)] = 1;
    }
  }

  Primes_.reserve(static_cast<size_t>(Limit) / 10 + 16);
  for (uint32_t Value = 2; Value < Limit; ++Value) {
    if (Composite[Value] == 0) {
      Primes_.push_back(Value);
    }
  }
}

const PrimeTable& PrimeTable::Main() {
  static const PrimeTable Instance(2048u * 2048u);
  return Instance;
}

const PrimeTable& PrimeTable::Pseudocode() {
  static const PrimeTable Instance(4096u);
  return Instance;
}

}
