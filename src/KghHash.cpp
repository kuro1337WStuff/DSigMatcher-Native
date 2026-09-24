// Diaphora's KOKA graph hash (jkutils/graph_hashes.py, Copyright (c) 2018-2019 Joxean Koret, AGPL),
// reimplemented in C++; see NOTICE.
#include "dsigmatcher/KghHash.h"

#include <cstdio>

namespace DSig {

namespace {

constexpr uint32_t LimbBase = 1000000000u;

const uint32_t KghPrimes[KghPrimeCount] = {2, 3, 5, 7, 11, 19, 23, 29, 31, 37, 41, 43, 47};

}

BigUInt::BigUInt() : Limbs_{0} {}

BigUInt::BigUInt(uint32_t Value) {
  if (Value == 0) {
    Limbs_.push_back(0);
    return;
  }
  while (Value > 0) {
    Limbs_.push_back(Value % LimbBase);
    Value /= LimbBase;
  }
}

void BigUInt::TrimLeadingZeros() {
  while (Limbs_.size() > 1 && Limbs_.back() == 0) {
    Limbs_.pop_back();
  }
}

void BigUInt::MultiplySmall(uint32_t Value) {
  if (Value == 0) {
    Limbs_.assign(1, 0);
    return;
  }
  if (Value == 1) {
    return;
  }

  uint64_t Carry = 0;
  for (size_t Index = 0; Index < Limbs_.size(); ++Index) {
    const uint64_t Product = static_cast<uint64_t>(Limbs_[Index]) * Value + Carry;
    Limbs_[Index] = static_cast<uint32_t>(Product % LimbBase);
    Carry = Product / LimbBase;
  }

  while (Carry > 0) {
    Limbs_.push_back(static_cast<uint32_t>(Carry % LimbBase));
    Carry /= LimbBase;
  }
}

void BigUInt::MultiplyBig(const BigUInt& Other) {
  if (Limbs_.size() == 1 && Limbs_[0] == 0) {
    return;
  }
  if (Other.Limbs_.size() == 1 && Other.Limbs_[0] == 0) {
    Limbs_.assign(1, 0);
    return;
  }
  if (Other.Limbs_.size() == 1) {
    MultiplySmall(Other.Limbs_[0]);
    return;
  }

  std::vector<uint32_t> Result(Limbs_.size() + Other.Limbs_.size() + 1, 0);

  for (size_t Outer = 0; Outer < Limbs_.size(); ++Outer) {
    if (Limbs_[Outer] == 0) {
      continue;
    }

    uint64_t Carry = 0;
    for (size_t Inner = 0; Inner < Other.Limbs_.size(); ++Inner) {
      const uint64_t Product = static_cast<uint64_t>(Limbs_[Outer]) * Other.Limbs_[Inner] +
                               Result[Outer + Inner] + Carry;
      Result[Outer + Inner] = static_cast<uint32_t>(Product % LimbBase);
      Carry = Product / LimbBase;
    }

    size_t Position = Outer + Other.Limbs_.size();
    while (Carry > 0) {
      const uint64_t Sum = static_cast<uint64_t>(Result[Position]) + Carry;
      Result[Position] = static_cast<uint32_t>(Sum % LimbBase);
      Carry = Sum / LimbBase;
      ++Position;
    }
  }

  Limbs_.swap(Result);
  TrimLeadingZeros();
}

BigUInt BigUInt::Power(uint32_t Base, uint64_t Exponent) {
  BigUInt Result(1);
  if (Exponent == 0) {
    return Result;
  }

  BigUInt Accumulator(Base);
  uint64_t Remaining = Exponent;
  while (Remaining > 0) {
    if ((Remaining & 1ull) != 0) {
      Result.MultiplyBig(Accumulator);
    }
    Remaining >>= 1;
    if (Remaining > 0) {
      Accumulator.MultiplyBig(Accumulator);
    }
  }

  return Result;
}

std::string BigUInt::ToDecimalString() const {
  std::string Result = std::to_string(Limbs_.back());
  Result.reserve(Limbs_.size() * 9);

  char Buffer[16];
  for (size_t Index = Limbs_.size() - 1; Index-- > 0;) {
    std::snprintf(Buffer, sizeof(Buffer), "%09u", Limbs_[Index]);
    Result.append(Buffer, 9);
  }

  return Result;
}

KghAccumulator::KghAccumulator() : Exponents_{} {}

void KghAccumulator::Multiply(KghPrimeIndex Prime) {
  ++Exponents_[Prime];
}

void KghAccumulator::MultiplyPower(KghPrimeIndex Prime, uint64_t Exponent) {
  Exponents_[Prime] += Exponent;
}

void KghAccumulator::AddBlock(uint64_t SuccessorCount, uint64_t PredecessorCount) {
  if (PredecessorCount == 0) {
    ++Exponents_[KghNodeEntry];
  }
  if (SuccessorCount == 0) {
    ++Exponents_[KghNodeExit];
  }
  ++Exponents_[KghNodeNormal];
  Exponents_[KghEdgeOutConditional] += SuccessorCount;
  Exponents_[KghEdgeInConditional] += PredecessorCount;
}

void KghAccumulator::AddLoopComponents(uint64_t LoopComponents) {
  Exponents_[KghFeatureLoop] += LoopComponents;
}

void KghAccumulator::AddStronglyConnectedCount(uint64_t ComponentCount) {
  Exponents_[KghFeatureStronglyConnected] += ComponentCount;
}

void KghAccumulator::AddFunctionFlags(bool NoReturn, bool Library, bool Thunk) {
  if (NoReturn) {
    ++Exponents_[KghFeatureFuncNoRet];
  }
  if (Library) {
    ++Exponents_[KghFeatureFuncLib];
  }
  if (Thunk) {
    ++Exponents_[KghFeatureFuncThunk];
  }
}

std::string KghAccumulator::ToDecimalString() const {
  BigUInt Result(1);

  for (int Index = 0; Index < KghPrimeCount; ++Index) {
    if (Exponents_[Index] == 0) {
      continue;
    }
    Result.MultiplyBig(BigUInt::Power(KghPrimes[Index], Exponents_[Index]));
  }

  return Result.ToDecimalString();
}

}
