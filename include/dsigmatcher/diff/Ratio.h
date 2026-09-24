#pragma once

// The similarity ratio (L2): check_ratio (D:1645-1775), deep_ratio (D:2749-2837), quick_ratio
// (D:150-165), the 7-decimal rounding and ratios_cache (first writer wins, keyed f"{ea1}-{ea2}",
// D:1653). Spec: 03a in full. MdSource is declared in Consumer.h (with IRatioProvider).

#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>
#include <vector>

#include "dsigmatcher/diff/Candidates.h"
#include "dsigmatcher/diff/Consumer.h"
#include "dsigmatcher/diff/Interner.h"

namespace DSig::Diff {

class DiffSession;

class RatioEngine final : public IRatioProvider {
public:
  explicit RatioEngine(DiffSession& S);
  ~RatioEngine() override;
  RatioEngine(const RatioEngine&) = delete;
  RatioEngine& operator=(const RatioEngine&) = delete;

  // After ingest and once IsSameProcessor is known (D:3617): per-function precomputation.
  void Prepare();

  double CheckRatio(const HeuristicRow& Row, MdSource Src) override;              // D:1645-1775
  double CompareFunctionRows(uint32_t MainRow, uint32_t DiffRow) override;        // D:2479-2538

  // ratios_cache: D:3572 resets it at diff() start; first writer wins (03a §8).
  void ClearCache();
  void SeedCache(AddrId Ea1, AddrId Ea2, double R);
  std::optional<double> Cached(AddrId Ea1, AddrId Ea2) const;
  struct CacheEntry {
    AddrId Ea1 = kNoneAddr;
    AddrId Ea2 = kNoneAddr;
    double Ratio = 0.0;
  };
  std::vector<CacheEntry> CacheSnapshot() const;  // insertion order (Python dict order)
  const std::vector<CacheEntry>& CacheEntries() const;  // the same, without a copy

  static double QuickRatio(std::optional<std::string_view> A, std::optional<std::string_view> B);  // D:150-165
  static double Round7(double V);                                                // float("{0:.7f}".format(v))
  double DeepRatio(uint32_t MainRow, uint32_t DiffRow) const;                    // D:2749-2837

private:
  struct Impl;
  std::unique_ptr<Impl> Impl_;
};

}
