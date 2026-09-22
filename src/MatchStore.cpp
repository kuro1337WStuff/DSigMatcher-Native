#include "dsigmatcher/MatchStore.h"

#include <algorithm>
#include <cstdint>
#include <memory>
#include <thread>
#include <unordered_map>
#include <vector>

#include "dsigmatcher/ThreadPool.h"

namespace DSig {

namespace {

constexpr uint32_t EmptySlot = 0xFFFFFFFFu;
constexpr size_t PartitionGrain = 256;
constexpr size_t MaxPartitionedTotal = static_cast<size_t>(0xFFFFFFFFull);

uint64_t PairKeyOf(const Match& Candidate) {
  return (static_cast<uint64_t>(Candidate.Index1) << 32) | static_cast<uint64_t>(Candidate.Index2);
}

uint64_t MixKey(uint64_t Value) {
  Value ^= Value >> 33;
  Value *= 0xFF51AFD7ED558CCDull;
  Value ^= Value >> 33;
  Value *= 0xC4CEB9FE1A85EC53ull;
  Value ^= Value >> 33;
  return Value;
}

size_t NextPowerOfTwo(size_t Value) {
  size_t Result = 1;
  while (Result < Value) {
    Result <<= 1;
  }
  return Result;
}

bool OrdersBefore(const Match& Left, const Match& Right) {
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
}

bool Outranks(const Match& Candidate, size_t CandidateOrigin, const Match& Held, size_t HeldOrigin) {
  if (Candidate.Ratio != Held.Ratio) {
    return Candidate.Ratio > Held.Ratio;
  }
  if (Candidate.HeuristicId != Held.HeuristicId) {
    return Candidate.HeuristicId < Held.HeuristicId;
  }
  return CandidateOrigin < HeldOrigin;
}

unsigned DetectedWorkerCount(unsigned ThreadCount) {
  if (ThreadCount != 0) {
    return ThreadCount;
  }
  const unsigned Detected = std::thread::hardware_concurrency();
  return Detected != 0 ? Detected : 1u;
}

std::vector<Match> ResolveSerial(const std::vector<Match>& Raw) {
  std::vector<Match> Ordered = Raw;

  std::stable_sort(Ordered.begin(), Ordered.end(), OrdersBefore);

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
    const uint64_t PairKey = PairKeyOf(Candidate);
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

std::vector<Match> GreedySelect(const std::vector<Match>& Ordered) {
  size_t MaxLeft = 0;
  size_t MaxRight = 0;
  for (const Match& Candidate : Ordered) {
    MaxLeft = std::max(MaxLeft, static_cast<size_t>(Candidate.Index1));
    MaxRight = std::max(MaxRight, static_cast<size_t>(Candidate.Index2));
  }

  std::vector<char> UsedLeft(MaxLeft + 1, 0);
  std::vector<char> UsedRight(MaxRight + 1, 0);

  std::vector<Match> Resolved;
  Resolved.reserve(Ordered.size());

  for (const Match& Candidate : Ordered) {
    if (UsedLeft[Candidate.Index1] != 0 || UsedRight[Candidate.Index2] != 0) {
      continue;
    }
    UsedLeft[Candidate.Index1] = 1;
    UsedRight[Candidate.Index2] = 1;
    Resolved.push_back(Candidate);
  }

  return Resolved;
}

std::vector<Match> ResolvePartitioned(const std::vector<Match>& Raw, ThreadPool& Pool) {
  const size_t Total = Raw.size();
  const size_t ChunkCount = Pool.WorkerCount();
  const size_t ChunkSize = (Total + ChunkCount - 1) / ChunkCount;
  const size_t BucketCount = NextPowerOfTwo(ChunkCount * 4);
  const size_t BucketMask = BucketCount - 1;

  std::vector<uint32_t> Counts(BucketCount * ChunkCount, 0);
  Pool.ParallelFor(ChunkCount, [&](size_t Chunk) {
    const size_t Begin = Chunk * ChunkSize;
    const size_t End = std::min(Total, Begin + ChunkSize);
    uint32_t* Row = &Counts[Chunk * BucketCount];
    for (size_t Index = Begin; Index < End; ++Index) {
      ++Row[MixKey(PairKeyOf(Raw[Index])) & BucketMask];
    }
  });

  std::vector<uint32_t> BucketStart(BucketCount + 1, 0);
  std::vector<uint32_t> Cursor(BucketCount * ChunkCount, 0);
  uint32_t Running = 0;
  for (size_t Bucket = 0; Bucket < BucketCount; ++Bucket) {
    BucketStart[Bucket] = Running;
    for (size_t Chunk = 0; Chunk < ChunkCount; ++Chunk) {
      Cursor[Chunk * BucketCount + Bucket] = Running;
      Running += Counts[Chunk * BucketCount + Bucket];
    }
  }
  BucketStart[BucketCount] = Running;

  std::unique_ptr<uint32_t[]> Items(new uint32_t[Total]);
  Pool.ParallelFor(ChunkCount, [&](size_t Chunk) {
    const size_t Begin = Chunk * ChunkSize;
    const size_t End = std::min(Total, Begin + ChunkSize);
    uint32_t* Row = &Cursor[Chunk * BucketCount];
    for (size_t Index = Begin; Index < End; ++Index) {
      const size_t Bucket = MixKey(PairKeyOf(Raw[Index])) & BucketMask;
      Items[Row[Bucket]++] = static_cast<uint32_t>(Index);
    }
  });

  size_t Widest = 0;
  for (size_t Bucket = 0; Bucket < BucketCount; ++Bucket) {
    const size_t Span = static_cast<size_t>(BucketStart[Bucket + 1] - BucketStart[Bucket]);
    Widest = std::max(Widest, Span);
  }
  const size_t TableStride = NextPowerOfTwo(std::max(Widest * 2, static_cast<size_t>(16)));
  const size_t TableMask = TableStride - 1;

  std::unique_ptr<uint32_t[]> Tables(new uint32_t[TableStride * BucketCount]);
  std::vector<uint8_t> Selected(Total, 0);

  Pool.ParallelFor(BucketCount, [&](size_t Bucket) {
    uint32_t* Table = Tables.get() + Bucket * TableStride;
    std::fill(Table, Table + TableStride, EmptySlot);
    for (size_t Slot = BucketStart[Bucket]; Slot < BucketStart[Bucket + 1]; ++Slot) {
      const size_t Index = Items[Slot];
      const Match& Candidate = Raw[Index];
      const uint64_t Key = PairKeyOf(Candidate);
      size_t Probe = static_cast<size_t>(MixKey(Key) & TableMask);
      for (;;) {
        const uint32_t Held = Table[Probe];
        if (Held == EmptySlot) {
          Table[Probe] = static_cast<uint32_t>(Index);
          Selected[Index] = 1;
          break;
        }
        if (PairKeyOf(Raw[Held]) == Key) {
          if (Outranks(Candidate, Index, Raw[Held], Held)) {
            Selected[Held] = 0;
            Table[Probe] = static_cast<uint32_t>(Index);
            Selected[Index] = 1;
          }
          break;
        }
        Probe = (Probe + 1) & TableMask;
      }
    }
  });

  std::vector<uint32_t> ChunkHits(ChunkCount, 0);
  Pool.ParallelFor(ChunkCount, [&](size_t Chunk) {
    const size_t Begin = Chunk * ChunkSize;
    const size_t End = std::min(Total, Begin + ChunkSize);
    uint32_t Hits = 0;
    for (size_t Index = Begin; Index < End; ++Index) {
      Hits += static_cast<uint32_t>(Selected[Index]);
    }
    ChunkHits[Chunk] = Hits;
  });

  std::vector<uint32_t> ChunkBase(ChunkCount + 1, 0);
  for (size_t Chunk = 0; Chunk < ChunkCount; ++Chunk) {
    ChunkBase[Chunk + 1] = ChunkBase[Chunk] + ChunkHits[Chunk];
  }

  std::vector<Match> Ordered(ChunkBase[ChunkCount]);
  Pool.ParallelFor(ChunkCount, [&](size_t Chunk) {
    const size_t Begin = Chunk * ChunkSize;
    const size_t End = std::min(Total, Begin + ChunkSize);
    size_t Out = ChunkBase[Chunk];
    for (size_t Index = Begin; Index < End; ++Index) {
      if (Selected[Index] != 0) {
        Ordered[Out++] = Raw[Index];
      }
    }
  });

  std::stable_sort(Ordered.begin(), Ordered.end(), OrdersBefore);

  return GreedySelect(Ordered);
}

}

void MatchStore::Add(const Match& Candidate) {
  Raw_.push_back(Candidate);
}

void MatchStore::AddAll(const std::vector<Match>& Candidates) {
  Raw_.insert(Raw_.end(), Candidates.begin(), Candidates.end());
}

std::vector<Match> MatchStore::Resolve(unsigned ThreadCount) const {
  const size_t Total = Raw_.size();

  if (Total > MaxPartitionedTotal) {
    return ResolveSerial(Raw_);
  }

  if (Pool_ != nullptr) {
    if (Total < PartitionGrain * Pool_->WorkerCount()) {
      return ResolveSerial(Raw_);
    }
    return ResolvePartitioned(Raw_, *Pool_);
  }

  const unsigned Workers = DetectedWorkerCount(ThreadCount);
  if (Total < PartitionGrain * Workers) {
    return ResolveSerial(Raw_);
  }

  ThreadPool LocalPool(Workers);
  return ResolvePartitioned(Raw_, LocalPool);
}

}
