#include "dsigmatcher/Heuristics.h"

#include <algorithm>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

#include "dsigmatcher/MatchStore.h"

namespace DSig {

namespace {

constexpr float AmbiguousRatio = 0.5f;

bool HasPrefix(std::string_view Text, std::string_view Prefix) {
  return Text.size() >= Prefix.size() && Text.compare(0, Prefix.size(), Prefix) == 0;
}

bool IsAutoNamed(std::string_view Name) {
  return HasPrefix(Name, "sub_");
}

bool IsNullSub(std::string_view Name) {
  return HasPrefix(Name, "nullsub");
}

bool NameCompatible(const FunctionTable& A, uint32_t I, const FunctionTable& B, uint32_t J) {
  const std::string_view Left = A.Text(A.Name[I]);
  const std::string_view Right = B.Text(B.Name[J]);
  const bool LeftAuto = IsAutoNamed(Left);
  const bool RightAuto = IsAutoNamed(Right);
  return (Left == Right && !LeftAuto) || LeftAuto || RightAuto;
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

struct Definition {
  const char* Name;
  bool RequiresSameProcessor;
  void (*Runner)(const FunctionTable&, const FunctionTable&, const DiffOptions&, std::vector<Match>&,
                 uint16_t);
};

const Definition Definitions[] = {
  {"Same RVA and hash", true, RunSameRvaAndHash},
  {"Same order and hash", true, RunSameOrderAndHash},
  {"Function Hash", true, RunFunctionHash},
  {"Bytes hash", true, RunBytesHash},
  {"Same address and mnemonics", false, RunSameAddressAndMnemonics},
  {"Same cleaned assembly", true, RunSameCleanedAssembly},
  {"Same cleaned microcode", true, RunSameCleanedMicrocode},
  {"Same cleaned pseudo-code", false, RunSameCleanedPseudoCode},
};

constexpr size_t DefinitionCount = sizeof(Definitions) / sizeof(Definitions[0]);

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
  DiffResult Result;
  Result.Stats.resize(DefinitionCount);

  unsigned Requested = Options.ThreadCount;
  if (Requested == 0) {
    const unsigned Detected = std::thread::hardware_concurrency();
    Requested = Detected > 0 ? Detected : 1u;
  }
  const unsigned WorkerCount =
      std::max(1u, std::min(Requested, static_cast<unsigned>(DefinitionCount)));

  std::vector<std::vector<Match>> Sinks(DefinitionCount);
  std::vector<std::thread> Workers;
  Workers.reserve(DefinitionCount);

  size_t NextLaunch = 0;
  size_t InFlight = 0;

  while (NextLaunch < DefinitionCount || InFlight > 0) {
    while (InFlight < WorkerCount && NextLaunch < DefinitionCount) {
      const size_t Slot = NextLaunch++;
      HeuristicStats& Stats = Result.Stats[Slot];
      Stats.Name = Definitions[Slot].Name;
      Stats.Category = MatchCategory::Best;

      if (Definitions[Slot].RequiresSameProcessor && !Options.SameProcessor) {
        Stats.Ran = false;
        Stats.SkipReason = "processor specific";
        continue;
      }

      Stats.Ran = true;
      ++InFlight;
      Workers.emplace_back([&, Slot]() {
        Definitions[Slot].Runner(OldTable, NewTable, Options, Sinks[Slot],
                                 static_cast<uint16_t>(Slot));
      });
    }

    if (InFlight == 0) {
      continue;
    }

    for (auto& Worker : Workers) {
      if (Worker.joinable()) {
        Worker.join();
      }
    }
    Workers.clear();
    InFlight = 0;
  }

  MatchStore Store;
  for (size_t Slot = 0; Slot < DefinitionCount; ++Slot) {
    Result.Stats[Slot].RawMatches = Sinks[Slot].size();
    Result.RawMatches += Sinks[Slot].size();
    Store.AddAll(Sinks[Slot]);
  }

  Result.Resolved = Store.Resolve();
  return Result;
}

}
