#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace DSig {

enum KghPrimeIndex : int {
  KghNodeEntry = 0,
  KghNodeExit = 1,
  KghNodeNormal = 2,
  KghEdgeInConditional = 3,
  KghEdgeOutConditional = 4,
  KghFeatureLoop = 5,
  KghFeatureCall = 6,
  KghFeatureDataRefs = 7,
  KghFeatureCallRef = 8,
  KghFeatureStronglyConnected = 9,
  KghFeatureFuncNoRet = 10,
  KghFeatureFuncLib = 11,
  KghFeatureFuncThunk = 12,
  KghPrimeCount = 13
};

class BigUInt {
public:
  BigUInt();
  explicit BigUInt(uint32_t Value);

  void MultiplySmall(uint32_t Value);
  void MultiplyBig(const BigUInt& Other);
  std::string ToDecimalString() const;
  size_t LimbCount() const { return Limbs_.size(); }

  static BigUInt Power(uint32_t Base, uint64_t Exponent);

private:
  void TrimLeadingZeros();

  std::vector<uint32_t> Limbs_;
};

class KghAccumulator {
public:
  KghAccumulator();

  void Multiply(KghPrimeIndex Prime);
  void MultiplyPower(KghPrimeIndex Prime, uint64_t Exponent);

  void AddBlock(uint64_t SuccessorCount, uint64_t PredecessorCount);
  void AddLoopComponents(uint64_t LoopComponents);
  void AddStronglyConnectedCount(uint64_t ComponentCount);
  void AddFunctionFlags(bool NoReturn, bool Library, bool Thunk);

  std::string ToDecimalString() const;

  const uint64_t* Exponents() const { return Exponents_; }
  uint64_t Exponent(KghPrimeIndex Prime) const { return Exponents_[Prime]; }

private:
  uint64_t Exponents_[KghPrimeCount];
};

}
