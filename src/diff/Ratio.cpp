// L0 STUB of lane L2 (ratio engine). L2 replaces this file with the port of check_ratio
// (D:1645-1775), deep_ratio (D:2749-2837), quick_ratio (D:150-165) and the 7-decimal rounding
// (spec: 03a in full). The stub keeps ratios_cache as plain storage (first writer wins, D:1653).

#include "dsigmatcher/diff/Ratio.h"

#include <unordered_map>

#include "dsigmatcher/diff/Errors.h"

namespace DSig::Diff {

namespace {

uint64_t CacheKey(AddrId Ea1, AddrId Ea2) {
  return (static_cast<uint64_t>(static_cast<uint32_t>(Ea1)) << 32) | static_cast<uint32_t>(Ea2);
}

}

struct RatioEngine::Impl {
  std::unordered_map<uint64_t, size_t> Index;
  std::vector<CacheEntry> Entries;  // insertion order
};

RatioEngine::RatioEngine(DiffSession&) : Impl_(std::make_unique<Impl>()) {}
RatioEngine::~RatioEngine() = default;

void RatioEngine::Prepare() {}

double RatioEngine::CheckRatio(const HeuristicRow&, MdSource) {
  throw StageNotImplemented("RatioEngine::CheckRatio (L2)");
}

double RatioEngine::CompareFunctionRows(uint32_t, uint32_t) {
  throw StageNotImplemented("RatioEngine::CompareFunctionRows (L2)");
}

void RatioEngine::ClearCache() {
  Impl_->Index.clear();
  Impl_->Entries.clear();
}

void RatioEngine::SeedCache(AddrId Ea1, AddrId Ea2, double R) {
  const uint64_t Key = CacheKey(Ea1, Ea2);
  if (Impl_->Index.find(Key) != Impl_->Index.end()) {
    return;  // first writer wins (03a §8)
  }
  Impl_->Index.emplace(Key, Impl_->Entries.size());
  Impl_->Entries.push_back(CacheEntry{Ea1, Ea2, R});
}

std::optional<double> RatioEngine::Cached(AddrId Ea1, AddrId Ea2) const {
  const auto Found = Impl_->Index.find(CacheKey(Ea1, Ea2));
  if (Found == Impl_->Index.end()) {
    return std::nullopt;
  }
  return Impl_->Entries[Found->second].Ratio;
}

std::vector<RatioEngine::CacheEntry> RatioEngine::CacheSnapshot() const { return Impl_->Entries; }

double RatioEngine::QuickRatio(std::optional<std::string_view>, std::optional<std::string_view>) {
  throw StageNotImplemented("RatioEngine::QuickRatio (L2)");
}

double RatioEngine::Round7(double) { throw StageNotImplemented("RatioEngine::Round7 (L2)"); }

double RatioEngine::DeepRatio(uint32_t, uint32_t) const { throw StageNotImplemented("RatioEngine::DeepRatio (L2)"); }

}
