#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <numeric>
#include <random>
#include <thread>
#include <unordered_map>
#include <vector>

#include "dsigmatcher/MatchStore.h"
#include "dsigmatcher/ThreadPool.h"
#include "dsigmatcher/Types.h"

namespace {

using namespace DSig;
using Clock = std::chrono::steady_clock;

int ChecksRun = 0;
int ChecksFailed = 0;

void Report(bool Ok, const char* Expression, const char* File, int Line) {
  ++ChecksRun;
  if (!Ok) {
    ++ChecksFailed;
    std::printf("  FAIL %s:%d  %s\n", File, Line, Expression);
  }
}

void Suite(const char* Name) {
  std::printf("[%s]\n", Name);
}

#define CHECK(Expr) Report(static_cast<bool>(Expr), #Expr, __FILE__, __LINE__)
#define CHECK_EQ(A, B) Report((A) == (B), #A " == " #B, __FILE__, __LINE__)

double MillisecondsSince(const Clock::time_point& Start) {
  return std::chrono::duration<double, std::milli>(Clock::now() - Start).count();
}

uint64_t OraclePairKey(const Match& Candidate) {
  return (static_cast<uint64_t>(Candidate.Index1) << 32) | static_cast<uint64_t>(Candidate.Index2);
}

std::vector<Match> OracleResolve(const std::vector<Match>& Raw) {
  std::vector<Match> Ordered = Raw;

  std::stable_sort(Ordered.begin(), Ordered.end(), [](const Match& Left, const Match& Right) {
    if (Left.Ratio != Right.Ratio) {
      return Left.Ratio > Right.Ratio;
    }
    if (Left.HeuristicId != Right.HeuristicId) {
      return Left.HeuristicId < Right.HeuristicId;
    }
    if (Left.Index1 != Right.Index1) {
      return Left.Index1 < Right.Index1;
    }
    return Left.Index2 < Right.Index2;
  });

  std::vector<Match> Resolved;
  Resolved.reserve(Ordered.size());

  std::unordered_map<uint64_t, size_t> SeenPairs;
  SeenPairs.reserve(Ordered.size() * 2);
  std::vector<char> UsedLeft;
  std::vector<char> UsedRight;

  size_t MaxLeft = 0;
  size_t MaxRight = 0;
  for (const Match& Candidate : Ordered) {
    MaxLeft = std::max(MaxLeft, static_cast<size_t>(Candidate.Index1));
    MaxRight = std::max(MaxRight, static_cast<size_t>(Candidate.Index2));
  }
  UsedLeft.assign(MaxLeft + 1, 0);
  UsedRight.assign(MaxRight + 1, 0);

  for (const Match& Candidate : Ordered) {
    const uint64_t PairKey = OraclePairKey(Candidate);
    if (SeenPairs.find(PairKey) != SeenPairs.end()) {
      continue;
    }
    SeenPairs.emplace(PairKey, Resolved.size());

    if (UsedLeft[Candidate.Index1] != 0 || UsedRight[Candidate.Index2] != 0) {
      continue;
    }

    UsedLeft[Candidate.Index1] = 1;
    UsedRight[Candidate.Index2] = 1;
    Resolved.push_back(Candidate);
  }

  return Resolved;
}

bool SameMatches(const std::vector<Match>& Left, const std::vector<Match>& Right) {
  if (Left.size() != Right.size()) {
    return false;
  }
  if (Left.empty()) {
    return true;
  }
  return std::memcmp(Left.data(), Right.data(), Left.size() * sizeof(Match)) == 0;
}

std::vector<Match> ResolveAt(const std::vector<Match>& Raw, unsigned ThreadCount) {
  MatchStore Store;
  Store.AddAll(Raw);
  return Store.Resolve(ThreadCount);
}

bool OneToOne(const std::vector<Match>& Resolved) {
  std::vector<uint32_t> LeftSeen;
  std::vector<uint32_t> RightSeen;
  for (const Match& Candidate : Resolved) {
    LeftSeen.push_back(Candidate.Index1);
    RightSeen.push_back(Candidate.Index2);
  }
  std::sort(LeftSeen.begin(), LeftSeen.end());
  std::sort(RightSeen.begin(), RightSeen.end());
  const bool LeftUnique =
      std::adjacent_find(LeftSeen.begin(), LeftSeen.end()) == LeftSeen.end();
  const bool RightUnique =
      std::adjacent_find(RightSeen.begin(), RightSeen.end()) == RightSeen.end();
  return LeftUnique && RightUnique;
}

bool NoDuplicatePairs(const std::vector<Match>& Resolved) {
  std::vector<uint64_t> Keys;
  Keys.reserve(Resolved.size());
  for (const Match& Candidate : Resolved) {
    Keys.push_back(OraclePairKey(Candidate));
  }
  std::sort(Keys.begin(), Keys.end());
  return std::adjacent_find(Keys.begin(), Keys.end()) == Keys.end();
}

std::vector<Match> MakeCascadeCandidates(size_t FunctionCount, uint64_t Seed) {
  std::mt19937_64 Rng(Seed);

  std::vector<uint32_t> Partner(FunctionCount);
  std::iota(Partner.begin(), Partner.end(), 0u);
  std::shuffle(Partner.begin(), Partner.end(), Rng);

  std::vector<Match> Raw;
  Raw.reserve(FunctionCount * 8);

  for (uint16_t Heuristic = 0; Heuristic < 8; ++Heuristic) {
    const float Ratio = (Heuristic % 3 == 2) ? 0.5f : 1.0f;
    const uint64_t Cover = 66 + Heuristic * 2;
    const uint64_t DecoyLimit = 6 + Heuristic;
    for (size_t Index = 0; Index < FunctionCount; ++Index) {
      const uint64_t Roll = Rng() % 100;
      if (Roll >= Cover) {
        continue;
      }
      Match Item;
      Item.Index1 = static_cast<uint32_t>(Index);
      Item.Index2 = Partner[Index];
      Item.HeuristicId = Heuristic;
      Item.Ratio = Ratio;
      Item.Category = MatchCategory::Best;
      Raw.push_back(Item);

      if (Roll < DecoyLimit) {
        Match Decoy = Item;
        Decoy.Index2 = static_cast<uint32_t>(Rng() % FunctionCount);
        Decoy.Ratio = 0.5f;
        Decoy.Category = MatchCategory::Partial;
        Raw.push_back(Decoy);
      }
    }
  }

  return Raw;
}

std::vector<Match> MakeRandomCandidates(size_t Count, size_t LeftSpan, size_t RightSpan,
                                        uint64_t Seed, bool ContinuousRatios) {
  std::mt19937_64 Rng(Seed);
  std::vector<Match> Raw;
  Raw.reserve(Count);
  for (size_t Index = 0; Index < Count; ++Index) {
    Match Item;
    Item.Index1 = static_cast<uint32_t>(Rng() % (LeftSpan != 0 ? LeftSpan : 1));
    Item.Index2 = static_cast<uint32_t>(Rng() % (RightSpan != 0 ? RightSpan : 1));
    Item.HeuristicId = static_cast<uint16_t>(Rng() % 12);
    if (ContinuousRatios) {
      Item.Ratio = static_cast<float>(static_cast<double>(Rng() % 100000) / 100000.0);
    } else {
      Item.Ratio = static_cast<float>(Rng() % 5) / 4.0f;
    }
    Item.Category = static_cast<MatchCategory>(Rng() % 3);
    Raw.push_back(Item);
  }
  return Raw;
}

std::vector<Match> MakeTiedCandidates(size_t Count, uint64_t Seed) {
  std::mt19937_64 Rng(Seed);
  std::vector<Match> Raw;
  Raw.reserve(Count * 3);
  for (size_t Index = 0; Index < Count; ++Index) {
    Match Base;
    Base.Index1 = static_cast<uint32_t>(Index % 4000);
    Base.Index2 = static_cast<uint32_t>((Index * 31) % 4000);
    Base.HeuristicId = static_cast<uint16_t>(Index % 5);
    Base.Ratio = static_cast<float>(Index % 7) / 6.0f;
    Base.Category = MatchCategory::Best;
    Raw.push_back(Base);

    Match Clone = Base;
    Clone.Category = MatchCategory::Unreliable;
    Raw.push_back(Clone);

    Match CloneAgain = Base;
    CloneAgain.Category = MatchCategory::Partial;
    Raw.push_back(CloneAgain);
  }
  return Raw;
}

const unsigned ThreadCounts[] = {1, 2, 3, 8, 32};

void TestThreadPoolBasics() {
  Suite("ThreadPool basics");

  ThreadPool Single(1);
  CHECK_EQ(Single.WorkerCount(), 1u);

  ThreadPool Auto(0);
  CHECK(Auto.WorkerCount() >= 1u);

  ThreadPool Wide(64);
  CHECK_EQ(Wide.WorkerCount(), 64u);

  std::vector<size_t> Empty;
  Single.ParallelFor(0, [&Empty](size_t Index) { Empty.push_back(Index); });
  CHECK(Empty.empty());

  std::vector<uint64_t> WideOut(3, 0);
  Wide.ParallelFor(WideOut.size(), [&WideOut](size_t Index) { WideOut[Index] = Index + 100; });
  CHECK_EQ(WideOut[0], static_cast<uint64_t>(100));
  CHECK_EQ(WideOut[1], static_cast<uint64_t>(101));
  CHECK_EQ(WideOut[2], static_cast<uint64_t>(102));

  std::vector<uint64_t> SingleOut(1, 0);
  Single.ParallelFor(SingleOut.size(), [&SingleOut](size_t Index) { SingleOut[Index] = Index + 7; });
  CHECK_EQ(SingleOut[0], static_cast<uint64_t>(7));

  ThreadPool Pool(8);
  std::vector<uint64_t> Sums(4096, 0);
  Pool.ParallelFor(Sums.size(), [&Sums](size_t Index) { Sums[Index] = Index * Index; });
  bool SquaresOk = true;
  for (size_t Index = 0; Index < Sums.size(); ++Index) {
    if (Sums[Index] != Index * Index) {
      SquaresOk = false;
    }
  }
  CHECK(SquaresOk);
}

void TestThreadPoolReuse() {
  Suite("ThreadPool reuse across many batches");

  ThreadPool Pool(16);
  bool AllOk = true;
  std::vector<uint64_t> Buffer(2048, 0);

  for (int Round = 0; Round < 300; ++Round) {
    std::fill(Buffer.begin(), Buffer.end(), 0);
    const size_t Items = static_cast<size_t>(1 + (Round * 37) % 2048);
    Pool.ParallelFor(Items, [&Buffer, Round](size_t Index) {
      Buffer[Index] = static_cast<uint64_t>(Round) * 100000ull + Index;
    });
    for (size_t Index = 0; Index < Items; ++Index) {
      if (Buffer[Index] != static_cast<uint64_t>(Round) * 100000ull + Index) {
        AllOk = false;
      }
    }
    for (size_t Index = Items; Index < Buffer.size(); ++Index) {
      if (Buffer[Index] != 0) {
        AllOk = false;
      }
    }
  }
  CHECK(AllOk);

  std::atomic<uint64_t> Counter{0};
  for (int Round = 0; Round < 50; ++Round) {
    Pool.ParallelFor(1000, [&Counter](size_t) { Counter.fetch_add(1); });
  }
  CHECK_EQ(Counter.load(), static_cast<uint64_t>(50000));
}

void TestThreadPoolWakeAfterIdle() {
  Suite("ThreadPool wakes correctly after idle");

  ThreadPool Pool(8);
  std::vector<uint64_t> Buffer(512, 0);
  bool AllOk = true;

  for (int Round = 0; Round < 4; ++Round) {
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    std::fill(Buffer.begin(), Buffer.end(), 0);
    Pool.ParallelFor(Buffer.size(), [&Buffer](size_t Index) { Buffer[Index] = Index + 1; });
    for (size_t Index = 0; Index < Buffer.size(); ++Index) {
      if (Buffer[Index] != Index + 1) {
        AllOk = false;
      }
    }
  }
  CHECK(AllOk);
}

void TestThreadPoolLifetime() {
  Suite("ThreadPool construction and destruction churn");

  for (int Round = 0; Round < 40; ++Round) {
    ThreadPool Transient(static_cast<unsigned>(1 + (Round % 32)));
    std::vector<uint64_t> Buffer(256, 0);
    Transient.ParallelFor(Buffer.size(),
                          [&Buffer](size_t Index) { Buffer[Index] = Index * 2; });
    bool Ok = true;
    for (size_t Index = 0; Index < Buffer.size(); ++Index) {
      if (Buffer[Index] != Index * 2) {
        Ok = false;
      }
    }
    CHECK(Ok);
  }

  for (int Round = 0; Round < 20; ++Round) {
    ThreadPool Doomed(16);
    std::atomic<uint64_t> Touched{0};
    Doomed.ParallelFor(4000, [&Touched](size_t) { Touched.fetch_add(1); });
    CHECK_EQ(Touched.load(), static_cast<uint64_t>(4000));
  }
}

void TestThreadPoolNested() {
  Suite("ThreadPool nested submission runs inline without deadlock");

  ThreadPool Pool(8);
  std::vector<uint64_t> Outer(64, 0);
  std::vector<uint64_t> Inner(64 * 32, 0);

  Pool.ParallelFor(Outer.size(), [&](size_t Index) {
    Outer[Index] = Index;
    Pool.ParallelFor(32, [&Inner, Index](size_t Slot) { Inner[Index * 32 + Slot] = Index + Slot; });
  });

  bool OuterOk = true;
  for (size_t Index = 0; Index < Outer.size(); ++Index) {
    if (Outer[Index] != Index) {
      OuterOk = false;
    }
  }
  CHECK(OuterOk);

  bool InnerOk = true;
  for (size_t Index = 0; Index < 64; ++Index) {
    for (size_t Slot = 0; Slot < 32; ++Slot) {
      if (Inner[Index * 32 + Slot] != Index + Slot) {
        InnerOk = false;
      }
    }
  }
  CHECK(InnerOk);

  ThreadPool Other(4);
  std::vector<uint64_t> Cross(128, 0);
  Pool.ParallelFor(8, [&](size_t Index) {
    Other.ParallelFor(16, [&Cross, Index](size_t Slot) { Cross[Index * 16 + Slot] = Index * Slot; });
  });
  bool CrossOk = true;
  for (size_t Index = 0; Index < 8; ++Index) {
    for (size_t Slot = 0; Slot < 16; ++Slot) {
      if (Cross[Index * 16 + Slot] != Index * Slot) {
        CrossOk = false;
      }
    }
  }
  CHECK(CrossOk);
}

void TestThreadPoolConcurrentSubmission() {
  Suite("ThreadPool concurrent submission from several callers");

  ThreadPool Pool(8);
  constexpr size_t Callers = 4;
  constexpr size_t Items = 4096;
  std::vector<std::vector<uint64_t>> Buffers(Callers, std::vector<uint64_t>(Items, 0));

  std::vector<std::thread> CallerThreads;
  for (size_t Caller = 0; Caller < Callers; ++Caller) {
    CallerThreads.emplace_back([&Pool, &Buffers, Caller]() {
      Pool.ParallelFor(Items, [&Buffers, Caller](size_t Index) {
        Buffers[Caller][Index] = static_cast<uint64_t>(Caller) * Items + Index;
      });
    });
  }
  for (std::thread& Worker : CallerThreads) {
    Worker.join();
  }

  bool Ok = true;
  for (size_t Caller = 0; Caller < Callers; ++Caller) {
    for (size_t Index = 0; Index < Items; ++Index) {
      if (Buffers[Caller][Index] != static_cast<uint64_t>(Caller) * Items + Index) {
        Ok = false;
      }
    }
  }
  CHECK(Ok);
}

void TestDedupAndPreference() {
  Suite("Duplicate pair dedup and ratio preference");

  MatchStore Dedup;
  for (uint16_t Heuristic = 0; Heuristic < 6; ++Heuristic) {
    Match Item;
    Item.Index1 = 11;
    Item.Index2 = 22;
    Item.HeuristicId = Heuristic;
    Item.Ratio = 1.0f;
    Dedup.Add(Item);
  }
  CHECK_EQ(Dedup.RawCount(), static_cast<size_t>(6));
  const std::vector<Match> Deduped = Dedup.Resolve();
  CHECK_EQ(Deduped.size(), static_cast<size_t>(1));
  CHECK(NoDuplicatePairs(Deduped));
  CHECK(OneToOne(Deduped));

  MatchStore Conflict;
  Match High;
  High.Index1 = 1;
  High.Index2 = 2;
  High.HeuristicId = 5;
  High.Ratio = 0.9f;
  Match Low;
  Low.Index1 = 1;
  Low.Index2 = 7;
  Low.HeuristicId = 0;
  Low.Ratio = 0.4f;
  Conflict.Add(Low);
  Conflict.Add(High);
  const std::vector<Match> Preferred = Conflict.Resolve();
  CHECK_EQ(Preferred.size(), static_cast<size_t>(1));
  CHECK_EQ(Preferred[0].Index2, static_cast<uint32_t>(2));
  CHECK_EQ(Preferred[0].Ratio, 0.9f);

  MatchStore EmptyStore;
  CHECK(EmptyStore.Resolve().empty());
  CHECK(EmptyStore.Resolve(32).empty());

  MatchStore Single;
  Match Only;
  Only.Index1 = 0;
  Only.Index2 = 0;
  Only.Ratio = 1.0f;
  Single.Add(Only);
  CHECK_EQ(Single.Resolve().size(), static_cast<size_t>(1));
  CHECK_EQ(Single.Resolve(32).size(), static_cast<size_t>(1));

  std::vector<Match> Contested;
  const size_t ContestedCount = 40000;
  for (size_t Index = 0; Index < ContestedCount; ++Index) {
    Match Weak;
    Weak.Index1 = static_cast<uint32_t>(Index % 20000);
    Weak.Index2 = static_cast<uint32_t>(20000 + (Index % 20000));
    Weak.HeuristicId = 9;
    Weak.Ratio = 0.25f;
    Contested.push_back(Weak);

    Match Strong = Weak;
    Strong.Index2 = static_cast<uint32_t>(40000 + (Index % 20000));
    Strong.HeuristicId = 1;
    Strong.Ratio = 0.95f;
    Contested.push_back(Strong);
  }
  const std::vector<Match> ContestedResolved = ResolveAt(Contested, 32);
  const std::vector<Match> ContestedOracle = OracleResolve(Contested);
  CHECK(SameMatches(ContestedResolved, ContestedOracle));
  bool StrongWon = !ContestedResolved.empty();
  for (const Match& Candidate : ContestedResolved) {
    if (Candidate.Ratio != 0.95f) {
      StrongWon = false;
    }
  }
  CHECK(StrongWon);
  CHECK(OneToOne(ContestedResolved));
}

void TestStabilityTieBreak() {
  Suite("Full comparator ties fall back to input order");

  MatchStore Small;
  Match First;
  First.Index1 = 4;
  First.Index2 = 9;
  First.HeuristicId = 2;
  First.Ratio = 0.75f;
  First.Category = MatchCategory::Partial;
  Match Second = First;
  Second.Category = MatchCategory::Unreliable;
  Small.Add(First);
  Small.Add(Second);
  const std::vector<Match> SmallResolved = Small.Resolve();
  CHECK_EQ(SmallResolved.size(), static_cast<size_t>(1));
  CHECK(SmallResolved[0].Category == MatchCategory::Partial);

  MatchStore Reversed;
  Reversed.Add(Second);
  Reversed.Add(First);
  const std::vector<Match> ReversedResolved = Reversed.Resolve();
  CHECK_EQ(ReversedResolved.size(), static_cast<size_t>(1));
  CHECK(ReversedResolved[0].Category == MatchCategory::Unreliable);

  const std::vector<Match> Tied = MakeTiedCandidates(6000, 0xABCDEF01ull);
  const std::vector<Match> TiedOracle = OracleResolve(Tied);
  CHECK(Tied.size() > 8192);
  for (const unsigned Threads : ThreadCounts) {
    const std::vector<Match> Got = ResolveAt(Tied, Threads);
    CHECK(SameMatches(Got, TiedOracle));
  }

  std::vector<Match> TiedShuffled = Tied;
  std::mt19937_64 Rng(555);
  std::shuffle(TiedShuffled.begin(), TiedShuffled.end(), Rng);
  const std::vector<Match> ShuffledOracle = OracleResolve(TiedShuffled);
  for (const unsigned Threads : ThreadCounts) {
    CHECK(SameMatches(ResolveAt(TiedShuffled, Threads), ShuffledOracle));
  }
}

void TestDeterminismAcrossThreadCounts() {
  Suite("Parallel resolve identical to serial at every thread count");

  const uint64_t Seeds[] = {0x9E3779B97F4A7C15ull, 0xDEADBEEFull, 20260922ull};

  for (const uint64_t Seed : Seeds) {
    const std::vector<Match> Raw = MakeCascadeCandidates(6000, Seed);
    CHECK(Raw.size() > 8192);
    const std::vector<Match> Expected = OracleResolve(Raw);

    MatchStore Store;
    Store.AddAll(Raw);
    const std::vector<Match> DefaultResult = Store.Resolve();
    CHECK(SameMatches(DefaultResult, Expected));

    for (const unsigned Threads : ThreadCounts) {
      const std::vector<Match> Got = ResolveAt(Raw, Threads);
      CHECK(SameMatches(Got, Expected));
      CHECK(OneToOne(Got));
      CHECK(NoDuplicatePairs(Got));
    }

    std::vector<Match> Wide = Raw;
    for (int Repeat = 0; Repeat < 4; ++Repeat) {
      const std::vector<Match> Extra = MakeCascadeCandidates(1500, Seed + Repeat + 1);
      Wide.insert(Wide.end(), Extra.begin(), Extra.end());
    }
    const std::vector<Match> WideExpected = OracleResolve(Wide);
    for (const unsigned Threads : ThreadCounts) {
      CHECK(SameMatches(ResolveAt(Wide, Threads), WideExpected));
    }
  }

  const std::vector<Match> UniquePairs = MakeRandomCandidates(60000, 60000, 60000, 77, true);
  const std::vector<Match> UniqueExpected = OracleResolve(UniquePairs);
  for (const unsigned Threads : ThreadCounts) {
    CHECK(SameMatches(ResolveAt(UniquePairs, Threads), UniqueExpected));
  }

  const std::vector<Match> Continuous = MakeRandomCandidates(60000, 8000, 8000, 88, true);
  const std::vector<Match> ContinuousExpected = OracleResolve(Continuous);
  for (const unsigned Threads : ThreadCounts) {
    CHECK(SameMatches(ResolveAt(Continuous, Threads), ContinuousExpected));
  }

  const std::vector<Match> Collapsed = MakeRandomCandidates(60000, 64, 64, 99, false);
  const std::vector<Match> CollapsedExpected = OracleResolve(Collapsed);
  for (const unsigned Threads : ThreadCounts) {
    CHECK(SameMatches(ResolveAt(Collapsed, Threads), CollapsedExpected));
  }
}

void TestPermutedInput() {
  Suite("Determinism under permuted input order");

  const std::vector<Match> Raw = MakeCascadeCandidates(8000, 0x1234567ull);
  const std::vector<Match> Expected = OracleResolve(Raw);

  std::mt19937_64 Rng(31337);
  for (int Permutation = 0; Permutation < 5; ++Permutation) {
    std::vector<Match> Shuffled = Raw;
    std::shuffle(Shuffled.begin(), Shuffled.end(), Rng);
    const std::vector<Match> ShuffledExpected = OracleResolve(Shuffled);
    for (const unsigned Threads : ThreadCounts) {
      CHECK(SameMatches(ResolveAt(Shuffled, Threads), ShuffledExpected));
    }

    std::vector<Match> Reversed = Raw;
    std::reverse(Reversed.begin(), Reversed.end());
    const std::vector<Match> ReversedExpected = OracleResolve(Reversed);
    for (const unsigned Threads : ThreadCounts) {
      CHECK(SameMatches(ResolveAt(Reversed, Threads), ReversedExpected));
    }
    CHECK(SameMatches(ReversedExpected, Expected));
  }
}

void TestThresholdBoundary() {
  Suite("Serial and partitioned paths agree around the size threshold");

  const size_t Sizes[] = {1,    2,     3,     17,    64,    127,   255,   256,   257,
                          511,  512,   513,   1024,  2047,  2048,  2049,  4096,  8191,
                          8192, 8193,  16384, 32768, 65536, 131072};

  for (const size_t Size : Sizes) {
    const std::vector<Match> Raw =
        MakeRandomCandidates(Size, std::max<size_t>(Size / 3, 1), std::max<size_t>(Size / 3, 1),
                             1000 + Size, Size % 2 == 0);
    const std::vector<Match> Expected = OracleResolve(Raw);
    for (const unsigned Threads : ThreadCounts) {
      const std::vector<Match> Got = ResolveAt(Raw, Threads);
      if (!SameMatches(Got, Expected)) {
        std::printf("  mismatch at size %zu threads %u\n", Size, Threads);
      }
      CHECK(SameMatches(Got, Expected));
      CHECK(OneToOne(Got));
    }
  }
}

void TestPersistentPoolReuse() {
  Suite("One persistent pool reused for many resolves");

  const std::vector<Match> Raw = MakeCascadeCandidates(8000, 0xF00Dull);
  const std::vector<Match> Expected = OracleResolve(Raw);

  ThreadPool Pool(8);
  MatchStore Store;
  Store.AddAll(Raw);
  Store.SetPool(&Pool);

  bool AllOk = true;
  for (int Round = 0; Round < 50; ++Round) {
    if (!SameMatches(Store.Resolve(), Expected)) {
      AllOk = false;
    }
  }
  CHECK(AllOk);

  MatchStore Other;
  Other.AddAll(Raw);
  Other.SetPool(&Pool);
  CHECK(SameMatches(Other.Resolve(), Expected));
  CHECK(SameMatches(Other.Resolve(1), Expected));

  Other.SetPool(nullptr);
  CHECK(SameMatches(Other.Resolve(4), Expected));

  std::vector<Match> Small;
  Small.push_back(Raw.front());
  MatchStore Tiny;
  Tiny.AddAll(Small);
  Tiny.SetPool(&Pool);
  CHECK(SameMatches(Tiny.Resolve(), OracleResolve(Small)));
}

void TestStress() {
  Suite("Stress: random matches resolved at every thread count");

  for (const uint64_t Seed : {1ull, 2ull, 3ull, 5ull, 8ull, 13ull}) {
    const std::vector<Match> Raw = MakeRandomCandidates(4000, 3000, 3000, Seed, Seed % 2 == 0);
    const std::vector<Match> Expected = OracleResolve(Raw);

    for (const unsigned Threads : ThreadCounts) {
      for (int Repeat = 0; Repeat < 3; ++Repeat) {
        const std::vector<Match> Got = ResolveAt(Raw, Threads);
        CHECK(SameMatches(Got, Expected));
        CHECK(OneToOne(Got));
        CHECK(NoDuplicatePairs(Got));
      }
    }

    std::vector<Match> Duplicated = Raw;
    Duplicated.insert(Duplicated.end(), Raw.begin(), Raw.end());
    Duplicated.insert(Duplicated.end(), Raw.begin(), Raw.end());
    const std::vector<Match> DuplicatedExpected = OracleResolve(Duplicated);
    for (const unsigned Threads : ThreadCounts) {
      CHECK(SameMatches(ResolveAt(Duplicated, Threads), DuplicatedExpected));
    }
  }
}

void TestTimingHarness() {
  Suite("Timing: ~316k candidates, original serial vs partitioned");

  const std::vector<Match> Raw = MakeCascadeCandidates(50000, 0x9E3779B97F4A7C15ull);
  std::printf("  candidates            : %zu\n", Raw.size());

  const std::vector<Match> Expected = OracleResolve(Raw);
  std::printf("  resolved              : %zu\n", Expected.size());
  CHECK(OneToOne(Expected));

  double Baseline = 1e18;
  for (int Attempt = 0; Attempt < 5; ++Attempt) {
    const auto Start = Clock::now();
    const std::vector<Match> Got = OracleResolve(Raw);
    Baseline = std::min(Baseline, MillisecondsSince(Start));
    CHECK(SameMatches(Got, Expected));
  }
  std::printf("  original serial       : %8.3f ms  (1.00x)\n", Baseline);

  const unsigned Sweep[] = {1, 2, 4, 8, 16, 32};
  std::printf("  %-18s %10s %10s %12s\n", "threads", "ms", "speedup", "identity");
  for (const unsigned Threads : Sweep) {
    ThreadPool Pool(Threads);
    MatchStore Store;
    Store.AddAll(Raw);
    Store.SetPool(&Pool);

    double Best = 1e18;
    bool Identical = true;
    for (int Attempt = 0; Attempt < 7; ++Attempt) {
      const auto Start = Clock::now();
      const std::vector<Match> Got = Store.Resolve();
      Best = std::min(Best, MillisecondsSince(Start));
      if (!SameMatches(Got, Expected)) {
        Identical = false;
      }
    }

    double Interleaved = 1e18;
    for (int Attempt = 0; Attempt < 3; ++Attempt) {
      const auto Start = Clock::now();
      const std::vector<Match> Got = OracleResolve(Raw);
      Interleaved = std::min(Interleaved, MillisecondsSince(Start));
      CHECK(SameMatches(Got, Expected));
    }
    Baseline = std::min(Baseline, Interleaved);

    std::printf("  %-18u %10.3f %9.2fx %12s\n", Threads, Best, Baseline / Best,
                Identical ? "identical" : "MISMATCH");
    CHECK(Identical);
  }

  std::printf("  serial baseline (best interleaved) : %.3f ms\n", Baseline);

  std::vector<Match> Shuffled = Raw;
  std::mt19937_64 Rng(2026);
  std::shuffle(Shuffled.begin(), Shuffled.end(), Rng);
  const std::vector<Match> ShuffledExpected = OracleResolve(Shuffled);
  double ShuffledBaseline = 1e18;
  for (int Attempt = 0; Attempt < 3; ++Attempt) {
    const auto Start = Clock::now();
    const std::vector<Match> Got = OracleResolve(Shuffled);
    ShuffledBaseline = std::min(ShuffledBaseline, MillisecondsSince(Start));
    CHECK(SameMatches(Got, ShuffledExpected));
  }
  std::printf("  shuffled input, original serial    : %.3f ms\n", ShuffledBaseline);
  for (const unsigned Threads : Sweep) {
    ThreadPool Pool(Threads);
    MatchStore Store;
    Store.AddAll(Shuffled);
    Store.SetPool(&Pool);
    double Best = 1e18;
    bool Identical = true;
    for (int Attempt = 0; Attempt < 5; ++Attempt) {
      const auto Start = Clock::now();
      const std::vector<Match> Got = Store.Resolve();
      Best = std::min(Best, MillisecondsSince(Start));
      if (!SameMatches(Got, ShuffledExpected)) {
        Identical = false;
      }
    }
    std::printf("  shuffled %-9u %10.3f %9.2fx %12s\n", Threads, Best, ShuffledBaseline / Best,
                Identical ? "identical" : "MISMATCH");
    CHECK(Identical);
  }
}

}

int main() {
  TestThreadPoolBasics();
  TestThreadPoolReuse();
  TestThreadPoolWakeAfterIdle();
  TestThreadPoolLifetime();
  TestThreadPoolNested();
  TestThreadPoolConcurrentSubmission();
  TestDedupAndPreference();
  TestStabilityTieBreak();
  TestDeterminismAcrossThreadCounts();
  TestPermutedInput();
  TestThresholdBoundary();
  TestPersistentPoolReuse();
  TestStress();
  TestTimingHarness();

  std::printf("\n%d checks, %d failed\n", ChecksRun, ChecksFailed);
  return ChecksFailed == 0 ? 0 : 1;
}
