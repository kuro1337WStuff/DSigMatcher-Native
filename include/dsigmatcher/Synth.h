#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "dsigmatcher/Types.h"

namespace DSig {

struct SynthOptions {
  size_t FunctionCount = 10000;
  size_t IdenticalPercent = 55;
  size_t RecompiledPercent = 25;
  size_t AmbiguousPercent = 10;
  size_t OrphanPercent = 10;
  size_t StableAddressPercent = 25;
  size_t AmbiguousGroupSize = 6;
  size_t MinInstructions = 6;
  size_t MaxInstructions = 80;
  size_t TextBytesPerInstruction = 29;
  size_t PseudoBytesPerLine = 41;
  uint64_t Seed = 0x9E3779B97F4A7C15ull;
};

struct SynthPair {
  FunctionTable Reference;
  FunctionTable Target;

  std::vector<uint32_t> ReferenceToTarget;
  std::vector<uint32_t> TargetToReference;

  size_t IdenticalCount = 0;
  size_t RecompiledCount = 0;
  size_t AmbiguousCount = 0;
  size_t OrphanReferenceCount = 0;
  size_t OrphanTargetCount = 0;

  size_t PairedCount() const { return IdenticalCount + RecompiledCount + AmbiguousCount; }
};

SynthPair MakeSyntheticPair(const SynthOptions& Options);

}
