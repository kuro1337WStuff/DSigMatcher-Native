#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace DSig {

class PrimeTable {
public:
  static const PrimeTable& Main();
  static const PrimeTable& Pseudocode();

  size_t Count() const { return Primes_.size(); }
  uint32_t Limit() const { return Limit_; }
  bool InRange(size_t Index) const { return Index < Primes_.size(); }
  uint32_t At(size_t Index) const { return InRange(Index) ? Primes_[Index] : 0u; }

private:
  explicit PrimeTable(uint32_t Limit);

  uint32_t Limit_;
  std::vector<uint32_t> Primes_;
};

}
