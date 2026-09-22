#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

namespace {

using Clock = std::chrono::steady_clock;

double MsSince(const Clock::time_point& Start) {
  return std::chrono::duration<double, std::milli>(Clock::now() - Start).count();
}

uint64_t HashBytes(const char* Data, size_t Length) {
  uint64_t Hash = 0xCBF29CE484222325ull;
  for (size_t Index = 0; Index < Length; ++Index) {
    Hash ^= static_cast<uint8_t>(Data[Index]);
    Hash *= 0x1000000001B3ull;
  }
  return Hash;
}

class Rng {
public:
  explicit Rng(uint64_t Seed) : State_(Seed) {}
  uint64_t Next() {
    State_ += 0x9E3779B97F4A7C15ull;
    uint64_t Value = State_;
    Value = (Value ^ (Value >> 30)) * 0xBF58476D1CE4E5B9ull;
    Value = (Value ^ (Value >> 27)) * 0x94D049BB133111EBull;
    return Value ^ (Value >> 31);
  }
  size_t Below(size_t Bound) { return Bound == 0 ? 0 : static_cast<size_t>(Next() % Bound); }

private:
  uint64_t State_;
};

struct Corpus {
  std::vector<std::string> Reference;
  std::vector<std::string> Target;
};

Corpus MakeCorpus(size_t Rows, size_t KeyLength, size_t SharedPercent, uint64_t Seed) {
  Rng Random(Seed);
  Corpus Result;
  Result.Reference.resize(Rows);
  Result.Target.resize(Rows);

  for (size_t Index = 0; Index < Rows; ++Index) {
    std::string Key(KeyLength, 'a');
    for (size_t Position = 0; Position < KeyLength; Position += 8) {
      const uint64_t Value = Random.Next();
      const size_t Count = KeyLength - Position < 8 ? KeyLength - Position : 8;
      std::memcpy(Key.data() + Position, &Value, Count);
    }
    Result.Reference[Index] = Key;

    if (Random.Below(100) < SharedPercent) {
      Result.Target[Index] = Key;
    } else {
      std::string Other(KeyLength, 'b');
      for (size_t Position = 0; Position < KeyLength; Position += 8) {
        const uint64_t Value = Random.Next();
        const size_t Count = KeyLength - Position < 8 ? KeyLength - Position : 8;
        std::memcpy(Other.data() + Position, &Value, Count);
      }
      Result.Target[Index] = Other;
    }
  }

  return Result;
}

size_t JoinByString(const Corpus& Data, size_t& OutMatches) {
  std::unordered_multimap<std::string, uint32_t> Index;
  Index.reserve(Data.Target.size() * 2);
  for (uint32_t Index_ = 0; Index_ < Data.Target.size(); ++Index_) {
    Index.emplace(Data.Target[Index_], Index_);
  }

  size_t Matches = 0;
  for (size_t Index_ = 0; Index_ < Data.Reference.size(); ++Index_) {
    const auto Range = Index.equal_range(Data.Reference[Index_]);
    for (auto Iterator = Range.first; Iterator != Range.second; ++Iterator) {
      ++Matches;
    }
  }
  OutMatches = Matches;
  return Matches;
}

size_t JoinByPrecomputedHash(const Corpus& Data, const std::vector<uint64_t>& ReferenceHashes,
                             const std::vector<uint64_t>& TargetHashes, size_t& OutMatches) {
  std::unordered_multimap<uint64_t, uint32_t> Index;
  Index.reserve(Data.Target.size() * 2);
  for (uint32_t Index_ = 0; Index_ < TargetHashes.size(); ++Index_) {
    Index.emplace(TargetHashes[Index_], Index_);
  }

  size_t Matches = 0;
  for (size_t Index_ = 0; Index_ < ReferenceHashes.size(); ++Index_) {
    const auto Range = Index.equal_range(ReferenceHashes[Index_]);
    for (auto Iterator = Range.first; Iterator != Range.second; ++Iterator) {
      if (Data.Reference[Index_] == Data.Target[Iterator->second]) {
        ++Matches;
      }
    }
  }
  OutMatches = Matches;
  return Matches;
}

}

int main(int Argc, char** Argv) {
  const size_t Rows = Argc > 1 ? static_cast<size_t>(std::strtoul(Argv[1], nullptr, 10)) : 50000;
  const size_t SharedPercent = 60;

  const size_t KeyLengths[] = {36, 256, 1024, 4096};
  const int Repetitions = 3;

  std::printf("rows=%zu shared=%zu%% repeats=%d\n\n", Rows, SharedPercent, Repetitions);
  std::printf("%-10s %14s %14s %14s %14s %12s\n", "keylen", "string join", "precompute",
              "int join", "int total", "speedup");
  std::printf("%-10s %14s %14s %14s %14s %12s\n", "----------", "--------------",
              "--------------", "--------------", "--------------", "------------");

  for (const size_t KeyLength : KeyLengths) {
    const Corpus Data = MakeCorpus(Rows, KeyLength, SharedPercent, 0x12345678ull ^ KeyLength);

    double StringBest = 1e18;
    double PrecomputeBest = 1e18;
    double IntBest = 1e18;
    size_t StringMatches = 0;
    size_t IntMatches = 0;
    std::vector<uint64_t> ReferenceHashes;
    std::vector<uint64_t> TargetHashes;

    for (int Attempt = 0; Attempt < Repetitions; ++Attempt) {
      const auto StringStart = Clock::now();
      JoinByString(Data, StringMatches);
      StringBest = std::min(StringBest, MsSince(StringStart));
    }

    for (int Attempt = 0; Attempt < Repetitions; ++Attempt) {
      const auto Start = Clock::now();
      ReferenceHashes.assign(Data.Reference.size(), 0);
      TargetHashes.assign(Data.Target.size(), 0);
      for (size_t Index = 0; Index < Data.Reference.size(); ++Index) {
        ReferenceHashes[Index] = HashBytes(Data.Reference[Index].data(), Data.Reference[Index].size());
      }
      for (size_t Index = 0; Index < Data.Target.size(); ++Index) {
        TargetHashes[Index] = HashBytes(Data.Target[Index].data(), Data.Target[Index].size());
      }
      PrecomputeBest = std::min(PrecomputeBest, MsSince(Start));
    }

    for (int Attempt = 0; Attempt < Repetitions; ++Attempt) {
      const auto Start = Clock::now();
      JoinByPrecomputedHash(Data, ReferenceHashes, TargetHashes, IntMatches);
      IntBest = std::min(IntBest, MsSince(Start));
    }

    const double IntTotal = PrecomputeBest + IntBest;
    std::printf("%-10zu %11.2f ms %11.2f ms %11.2f ms %11.2f ms %10.2fx\n", KeyLength, StringBest,
                PrecomputeBest, IntBest, IntTotal, StringBest / IntTotal);

    if (StringMatches != IntMatches) {
      std::printf("  MISMATCH: string join found %zu, int join found %zu\n", StringMatches,
                  IntMatches);
    }
  }

  std::printf("\nfusion: three heuristics sharing one join key\n");
  std::printf("%-10s %14s %14s %12s\n", "keylen", "3x separate", "1x fused", "speedup");
  std::printf("%-10s %14s %14s %12s\n", "----------", "--------------", "--------------",
              "------------");

  for (const size_t KeyLength : KeyLengths) {
    const Corpus Data = MakeCorpus(Rows, KeyLength, SharedPercent, 0x12345678ull ^ KeyLength);

    double SeparateBest = 1e18;
    for (int Attempt = 0; Attempt < Repetitions; ++Attempt) {
      const auto Start = Clock::now();
      size_t Ignored = 0;
      JoinByString(Data, Ignored);
      JoinByString(Data, Ignored);
      JoinByString(Data, Ignored);
      SeparateBest = std::min(SeparateBest, MsSince(Start));
    }

    double FusedBest = 1e18;
    for (int Attempt = 0; Attempt < Repetitions; ++Attempt) {
      const auto Start = Clock::now();
      std::unordered_multimap<std::string, uint32_t> Index;
      Index.reserve(Data.Target.size() * 2);
      for (uint32_t Index_ = 0; Index_ < Data.Target.size(); ++Index_) {
        Index.emplace(Data.Target[Index_], Index_);
      }
      size_t Total = 0;
      for (size_t Index_ = 0; Index_ < Data.Reference.size(); ++Index_) {
        const auto Range = Index.equal_range(Data.Reference[Index_]);
        for (auto Iterator = Range.first; Iterator != Range.second; ++Iterator) {
          const uint32_t Other = Iterator->second;
          if (Data.Reference[Index_].size() == Data.Target[Other].size()) {
            ++Total;
          }
          if (Other % 2 == 0) {
            ++Total;
          }
          if (Index_ != Other) {
            ++Total;
          }
        }
      }
      FusedBest = std::min(FusedBest, MsSince(Start));
      if (Total == 0) {
        std::printf("");
      }
    }

    std::printf("%-10zu %11.2f ms %11.2f ms %10.2fx\n", KeyLength, SeparateBest, FusedBest,
                SeparateBest / FusedBest);
  }

  return 0;
}
