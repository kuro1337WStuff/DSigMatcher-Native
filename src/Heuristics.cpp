#include "dsigmatcher/Heuristics.h"

#include <algorithm>
#include <chrono>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

#include "dsigmatcher/MatchStore.h"
#include "dsigmatcher/Naming.h"
#include "dsigmatcher/ThreadPool.h"

namespace DSig {

namespace {

constexpr float AmbiguousRatio = 0.5f;

bool NameCompatible(const FunctionTable& A, uint32_t I, const FunctionTable& B, uint32_t J) {
  return DSig::NameCompatible(A.Text(A.Name[I]), B.Text(B.Name[J]));
}

bool PassesSizeGate(const FunctionTable& A, uint32_t I, const FunctionTable& B, uint32_t J,
                    const DiffOptions& Options) {
  if (!Options.IgnoreSmallFunctions) {
    return true;
  }
  return A.Instructions[I] > 5 && B.Instructions[J] > 5;
}

template <typename KeyFn, typename PredFn>
void JoinByKey(const FunctionTable& A, const FunctionTable& B, KeyFn Key, PredFn Accept,
               bool PenalizeAmbiguity, uint16_t HeuristicId, MatchCategory Category,
               std::vector<Match>& Sink) {
  std::unordered_multimap<std::string_view, uint32_t> Index;
  Index.reserve(B.Count() * 2 + 1);
  for (uint32_t J = 0; J < static_cast<uint32_t>(B.Count()); ++J) {
    const std::string_view KeyValue = Key(B, J);
    if (KeyValue.empty()) {
      continue;
    }
    Index.emplace(KeyValue, J);
  }

  std::vector<uint32_t> Candidates;
  for (uint32_t I = 0; I < static_cast<uint32_t>(A.Count()); ++I) {
    const std::string_view KeyValue = Key(A, I);
    if (KeyValue.empty()) {
      continue;
    }

    Candidates.clear();
    const auto Range = Index.equal_range(KeyValue);
    for (auto Iterator = Range.first; Iterator != Range.second; ++Iterator) {
      if (Accept(I, Iterator->second)) {
        Candidates.push_back(Iterator->second);
      }
    }

    if (Candidates.empty()) {
      continue;
    }

    const float Ratio = (PenalizeAmbiguity && Candidates.size() > 1) ? AmbiguousRatio : 1.0f;
    for (const uint32_t J : Candidates) {
      Match Candidate;
      Candidate.Index1 = I;
      Candidate.Index2 = J;
      Candidate.HeuristicId = HeuristicId;
      Candidate.Ratio = Ratio;
      Candidate.Category = Category;
      Sink.push_back(Candidate);
    }
  }
}

void RunSameRvaAndHash(const FunctionTable& A, const FunctionTable& B, const DiffOptions& Options,
                       std::vector<Match>& Sink, uint16_t Id) {
  JoinByKey(
      A, B, [](const FunctionTable& T, uint32_t I) { return T.Text(T.BytesHash[I]); },
      [&](uint32_t I, uint32_t J) {
        if (!PassesSizeGate(A, I, B, J, Options)) {
          return false;
        }
        const std::string_view LeftRva = A.Text(A.Rva[I]);
        const std::string_view RightRva = B.Text(B.Rva[J]);
        const std::string_view LeftSegment = A.Text(A.SegmentRva[I]);
        const std::string_view RightSegment = B.Text(B.SegmentRva[J]);
        const bool RvaEqual = (!LeftRva.empty() && LeftRva == RightRva) ||
                              (!LeftSegment.empty() && LeftSegment == RightSegment);
        return RvaEqual && A.Instructions[I] == B.Instructions[J] && NameCompatible(A, I, B, J) &&
               A.Nodes[I] >= 3 && B.Nodes[J] >= 3;
      },
      false, Id, MatchCategory::Best, Sink);
}

void RunSameOrderAndHash(const FunctionTable& A, const FunctionTable& B, const DiffOptions& Options,
                         std::vector<Match>& Sink, uint16_t Id) {
  JoinByKey(
      A, B, [](const FunctionTable& T, uint32_t I) { return T.Text(T.BytesHash[I]); },
      [&](uint32_t I, uint32_t J) {
        if (!PassesSizeGate(A, I, B, J, Options)) {
          return false;
        }
        if (A.Id[I] != B.Id[J] || A.Instructions[I] != B.Instructions[J]) {
          return false;
        }
        if (!NameCompatible(A, I, B, J)) {
          return false;
        }
        const bool SmallButStructured = A.Nodes[I] > 1 && B.Nodes[J] > 1 && A.Instructions[I] > 5 &&
                                        B.Instructions[J] > 5;
        const bool Large = A.Instructions[I] > 10 && B.Instructions[J] > 10;
        return SmallButStructured || Large;
      },
      false, Id, MatchCategory::Best, Sink);
}

void RunFunctionHash(const FunctionTable& A, const FunctionTable& B, const DiffOptions& Options,
                     std::vector<Match>& Sink, uint16_t Id) {
  JoinByKey(
      A, B, [](const FunctionTable& T, uint32_t I) { return T.Text(T.FunctionHash[I]); },
      [&](uint32_t I, uint32_t J) {
        if (!PassesSizeGate(A, I, B, J, Options)) {
          return false;
        }
        const bool SmallButStructured = A.Nodes[I] > 1 && B.Nodes[J] > 1 && A.Instructions[I] > 5 &&
                                        B.Instructions[J] > 5;
        const bool Large = A.Instructions[I] > 10 && B.Instructions[J] > 10;
        return SmallButStructured || Large;
      },
      false, Id, MatchCategory::Best, Sink);
}

void RunBytesHash(const FunctionTable& A, const FunctionTable& B, const DiffOptions& Options,
                  std::vector<Match>& Sink, uint16_t Id) {
  JoinByKey(
      A, B, [](const FunctionTable& T, uint32_t I) { return T.Text(T.BytesHash[I]); },
      [&](uint32_t I, uint32_t J) {
        return PassesSizeGate(A, I, B, J, Options) && A.Instructions[I] > 5 && B.Instructions[J] > 5;
      },
      false, Id, MatchCategory::Best, Sink);
}

void RunSameAddressAndMnemonics(const FunctionTable& A, const FunctionTable& B,
                                const DiffOptions& Options, std::vector<Match>& Sink, uint16_t Id) {
  JoinByKey(
      A, B, [](const FunctionTable& T, uint32_t I) { return T.Text(T.Address[I]); },
      [&](uint32_t I, uint32_t J) {
        if (!PassesSizeGate(A, I, B, J, Options)) {
          return false;
        }
        return A.Text(A.Mnemonics[I]) == B.Text(B.Mnemonics[J]) &&
               A.Instructions[I] == B.Instructions[J] && A.Instructions[I] > 5 &&
               NameCompatible(A, I, B, J);
      },
      true, Id, MatchCategory::Best, Sink);
}

void RunSameCleanedAssembly(const FunctionTable& A, const FunctionTable& B, const DiffOptions& Options,
                            std::vector<Match>& Sink, uint16_t Id) {
  JoinByKey(
      A, B, [](const FunctionTable& T, uint32_t I) { return T.Text(T.CleanAssembly[I]); },
      [&](uint32_t I, uint32_t J) {
        if (!PassesSizeGate(A, I, B, J, Options)) {
          return false;
        }
        return A.Nodes[I] >= 3 && B.Nodes[J] >= 3 && !IsNullSub(A.Text(A.Name[I])) &&
               !IsNullSub(B.Text(B.Name[J]));
      },
      true, Id, MatchCategory::Best, Sink);
}

void RunSameCleanedMicrocode(const FunctionTable& A, const FunctionTable& B,
                             const DiffOptions& Options, std::vector<Match>& Sink, uint16_t Id) {
  JoinByKey(
      A, B, [](const FunctionTable& T, uint32_t I) { return T.Text(T.CleanMicrocode[I]); },
      [&](uint32_t I, uint32_t J) {
        if (!PassesSizeGate(A, I, B, J, Options)) {
          return false;
        }
        return A.Instructions[I] > 3 && B.Instructions[J] > 3 && !IsNullSub(A.Text(A.Name[I])) &&
               !IsNullSub(B.Text(B.Name[J]));
      },
      true, Id, MatchCategory::Best, Sink);
}

void RunSameCleanedPseudoCode(const FunctionTable& A, const FunctionTable& B,
                              const DiffOptions& Options, std::vector<Match>& Sink, uint16_t Id) {
  JoinByKey(
      A, B, [](const FunctionTable& T, uint32_t I) { return T.Text(T.CleanPseudo[I]); },
      [&](uint32_t I, uint32_t J) {
        if (!PassesSizeGate(A, I, B, J, Options)) {
          return false;
        }
        return A.PseudocodeLines[I] > 5 && B.PseudocodeLines[J] > 5 &&
               !IsNullSub(A.Text(A.Name[I])) && !IsNullSub(B.Text(B.Name[J]));
      },
      true, Id, MatchCategory::Best, Sink);
}

using RarityMap = std::unordered_map<std::string_view, uint32_t>;

RarityMap BuildRarity(const FunctionTable& Table,
                      const std::vector<PackedString> FunctionTable::*Column) {
  RarityMap Counts;
  Counts.reserve(Table.Count() * 2 + 1);

  for (uint32_t Index = 0; Index < static_cast<uint32_t>(Table.Count()); ++Index) {
    const std::string_view Key = Table.Text((Table.*Column)[Index]);
    if (Key.empty() || Key == "0") {
      continue;
    }
    Counts[Key] += 1;
  }

  return Counts;
}

bool IsRare(const RarityMap& ReferenceCounts, const RarityMap& TargetCounts,
            std::string_view Key) {
  const auto ReferenceIterator = ReferenceCounts.find(Key);
  const auto TargetIterator = TargetCounts.find(Key);
  const bool RareInReference =
      ReferenceIterator != ReferenceCounts.end() && ReferenceIterator->second <= 2;
  const bool RareInTarget = TargetIterator != TargetCounts.end() && TargetIterator->second <= 2;
  return RareInReference || RareInTarget;
}

void RunSameKokaHashAndMdIndex(const FunctionTable& A, const FunctionTable& B,
                               const DiffOptions& Options, std::vector<Match>& Sink,
                               uint16_t Id) {
  JoinByKey(
      A, B, [](const FunctionTable& T, uint32_t I) { return T.Text(T.KghHash[I]); },
      [&](uint32_t I, uint32_t J) {
        if (!PassesSizeGate(A, I, B, J, Options)) {
          return false;
        }
        return A.Text(A.MdIndex[I]) == B.Text(B.MdIndex[J]) && A.Nodes[I] == B.Nodes[J] &&
               A.Nodes[I] >= 4 && A.Outdegree[I] == B.Outdegree[J] &&
               A.Indegree[I] == B.Indegree[J] &&
               (IsAutoNamed(A.Text(A.Name[I])) || IsAutoNamed(B.Text(B.Name[J])));
      },
      true, Id, MatchCategory::Partial, Sink);
}

void RunSameConstants(const FunctionTable& A, const FunctionTable& B, const DiffOptions& Options,
                      std::vector<Match>& Sink, uint16_t Id) {
  JoinByKey(
      A, B, [](const FunctionTable& T, uint32_t I) { return T.Text(T.Constants[I]); },
      [&](uint32_t I, uint32_t J) {
        return PassesSizeGate(A, I, B, J, Options) &&
               A.ConstantsCount[I] == B.ConstantsCount[J] && A.ConstantsCount[I] > 1;
      },
      true, Id, MatchCategory::Partial, Sink);
}

void RunSameRareKokaHash(const FunctionTable& A, const FunctionTable& B,
                         const DiffOptions& Options, std::vector<Match>& Sink, uint16_t Id) {
  const RarityMap ReferenceCounts = BuildRarity(A, &FunctionTable::KghHash);
  const RarityMap TargetCounts = BuildRarity(B, &FunctionTable::KghHash);

  JoinByKey(
      A, B, [](const FunctionTable& T, uint32_t I) { return T.Text(T.KghHash[I]); },
      [&](uint32_t I, uint32_t J) {
        if (!PassesSizeGate(A, I, B, J, Options)) {
          return false;
        }
        return IsRare(ReferenceCounts, TargetCounts, A.Text(A.KghHash[I])) && A.Nodes[I] > 5 &&
               (IsAutoNamed(A.Text(A.Name[I])) || IsAutoNamed(B.Text(B.Name[J])));
      },
      true, Id, MatchCategory::Partial, Sink);
}

void RunSameRareMdIndex(const FunctionTable& A, const FunctionTable& B,
                        const DiffOptions& Options, std::vector<Match>& Sink, uint16_t Id) {
  const RarityMap ReferenceCounts = BuildRarity(A, &FunctionTable::MdIndex);
  const RarityMap TargetCounts = BuildRarity(B, &FunctionTable::MdIndex);

  JoinByKey(
      A, B, [](const FunctionTable& T, uint32_t I) { return T.Text(T.MdIndex[I]); },
      [&](uint32_t I, uint32_t J) {
        return PassesSizeGate(A, I, B, J, Options) &&
               IsRare(ReferenceCounts, TargetCounts, A.Text(A.MdIndex[I])) && A.Nodes[I] > 10;
      },
      true, Id, MatchCategory::Partial, Sink);
}

struct Definition {
  const char* Name;
  MatchCategory Category;
  bool RequiresSameProcessor;
  void (*Runner)(const FunctionTable&, const FunctionTable&, const DiffOptions&, std::vector<Match>&,
                 uint16_t);
};

const Definition Definitions[] = {
  {"Same RVA and hash", MatchCategory::Best, true, RunSameRvaAndHash},
  {"Same order and hash", MatchCategory::Best, true, RunSameOrderAndHash},
  {"Function Hash", MatchCategory::Best, true, RunFunctionHash},
  {"Bytes hash", MatchCategory::Best, true, RunBytesHash},
  {"Same address and mnemonics", MatchCategory::Best, false, RunSameAddressAndMnemonics},
  {"Same cleaned assembly", MatchCategory::Best, true, RunSameCleanedAssembly},
  {"Same cleaned microcode", MatchCategory::Best, true, RunSameCleanedMicrocode},
  {"Same cleaned pseudo-code", MatchCategory::Best, false, RunSameCleanedPseudoCode},
  {"Same KOKA hash and MD-Index", MatchCategory::Partial, false, RunSameKokaHashAndMdIndex},
  {"Same constants", MatchCategory::Partial, false, RunSameConstants},
  {"Same rare KOKA hash", MatchCategory::Partial, false, RunSameRareKokaHash},
  {"Same rare MD Index", MatchCategory::Partial, false, RunSameRareMdIndex},
};

constexpr size_t DefinitionCount = sizeof(Definitions) / sizeof(Definitions[0]);

}

size_t HeuristicCount() { return DefinitionCount; }

const char* HeuristicName(size_t Index) {
  return Index < DefinitionCount ? Definitions[Index].Name : "";
}

bool HeuristicRequiresSameProcessor(size_t Index) {
  return Index < DefinitionCount && Definitions[Index].RequiresSameProcessor;
}

void RunHeuristic(size_t Index, const FunctionTable& Reference, const FunctionTable& Target,
                  const DiffOptions& Options, std::vector<Match>& Sink) {
  if (Index >= DefinitionCount) {
    return;
  }
  Definitions[Index].Runner(Reference, Target, Options, Sink, static_cast<uint16_t>(Index));
}

const char* CategoryName(MatchCategory Category) {
  switch (Category) {
  case MatchCategory::Best:
    return "best";
  case MatchCategory::Partial:
    return "partial";
  case MatchCategory::Unreliable:
    return "unreliable";
  }
  return "unknown";
}

DiffResult RunExactHeuristics(const FunctionTable& OldTable, const FunctionTable& NewTable,
                              const DiffOptions& Options) {
  const auto WallStart = std::chrono::steady_clock::now();

  DiffResult Result;
  Result.Stats.resize(DefinitionCount);

  unsigned Requested = Options.ThreadCount;
  if (Requested == 0) {
    const unsigned Detected = std::thread::hardware_concurrency();
    Requested = Detected > 0 ? Detected : 1u;
  }

  std::vector<size_t> Runnable;
  Runnable.reserve(DefinitionCount);
  for (size_t Slot = 0; Slot < DefinitionCount; ++Slot) {
    HeuristicStats& Stats = Result.Stats[Slot];
    Stats.Name = Definitions[Slot].Name;
    Stats.Category = Definitions[Slot].Category;

    if (Definitions[Slot].RequiresSameProcessor && !Options.SameProcessor) {
      Stats.Ran = false;
      Stats.SkipReason = "processor specific";
      continue;
    }

    Stats.Ran = true;
    Runnable.push_back(Slot);
  }

  std::vector<std::vector<Match>> Sinks(DefinitionCount);
  std::vector<double> Timings(DefinitionCount, 0.0);

  ThreadPool Pool(Requested);
  Pool.ParallelFor(Runnable.size(), [&](size_t Item) {
    const size_t Slot = Runnable[Item];
    const auto Start = std::chrono::steady_clock::now();
    Definitions[Slot].Runner(OldTable, NewTable, Options, Sinks[Slot],
                             static_cast<uint16_t>(Slot));
    Timings[Slot] =
        std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - Start).count();
  });

  MatchStore Store;
  if (Requested > 1) {
    Store.SetPool(&Pool);
  }
  for (size_t Slot = 0; Slot < DefinitionCount; ++Slot) {
    Result.Stats[Slot].RawMatches = Sinks[Slot].size();
    Result.Stats[Slot].ElapsedMs = Timings[Slot];
    Result.RawMatches += Sinks[Slot].size();
    Store.AddAll(Sinks[Slot]);
  }

  Result.Resolved = Store.Resolve(Requested);
  Result.WallMs =
      std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - WallStart).count();
  return Result;
}

}
