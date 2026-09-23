// L0 STUB of lane L1 (MatchState). L1 replaces this file with the literal port of D:1340-1402,
// D:1554-1605, D:1777-1784 and D:3133-3148 (spec: 01 §8, 02 §6-§16, 07 §10.5).
//
// The stub stores the lists and dicts so that the pipeline, snapshots and replays work on empty
// state; every operation whose semantics L1 ports throws StageNotImplemented, except Cleanup on an
// empty state (a no-op in Python too).

#include "dsigmatcher/diff/MatchState.h"

#include <algorithm>
#include <unordered_map>

#include "dsigmatcher/diff/Errors.h"
#include "dsigmatcher/diff/Pipeline.h"

namespace DSig::Diff {

std::string_view ChooserName(Chooser C) {
  switch (C) {
    case Chooser::Best:
      return "best";
    case Chooser::Partial:
      return "partial";
    case Chooser::Unreliable:
      return "unreliable";
  }
  return "";
}

struct MatchState::Impl {
  DiffSession& S;
  int64_t Total1 = 0;
  int64_t Total2 = 0;
  std::vector<Item> Lists[3];
  // dict insertion order is kept by the key vectors
  std::vector<NameId> PrimaryOrder;
  std::vector<NameId> SecondaryOrder;
  std::unordered_map<NameId, MatchedEntry> PrimaryMap;
  std::unordered_map<NameId, MatchedEntry> SecondaryMap;

  explicit Impl(DiffSession& Session) : S(Session) {}

  static void Put(std::vector<NameId>& Order, std::unordered_map<NameId, MatchedEntry>& Map, NameId Key,
                  MatchedEntry Entry) {
    if (Map.find(Key) == Map.end()) {
      Order.push_back(Key);
    }
    Map[Key] = Entry;
  }
};

MatchState::MatchState(DiffSession& S) : Impl_(std::make_unique<Impl>(S)) {}
MatchState::~MatchState() = default;

void MatchState::SetTotals(int64_t Total1, int64_t Total2) {
  Impl_->Total1 = Total1;
  Impl_->Total2 = Total2;
}

int64_t MatchState::Total1() const { return Impl_->Total1; }
int64_t MatchState::Total2() const { return Impl_->Total2; }

void MatchState::AddMatch(NameId, NameId, double, const Item&, std::optional<Chooser>) {
  throw StageNotImplemented("MatchState::AddMatch (L1)");
}

bool MatchState::HasBestMatch(NameId, NameId) const { throw StageNotImplemented("MatchState::HasBestMatch (L1)"); }

bool MatchState::HasBetterMatch(NameId, NameId, double) const {
  throw StageNotImplemented("MatchState::HasBetterMatch (L1)");
}

void MatchState::Cleanup(CleanupSite) {
  if (Impl_->Lists[0].empty() && Impl_->Lists[1].empty() && Impl_->Lists[2].empty()) {
    // D:1554-1605 on empty lists leaves empty lists and empty dicts.
    Impl_->PrimaryOrder.clear();
    Impl_->SecondaryOrder.clear();
    Impl_->PrimaryMap.clear();
    Impl_->SecondaryMap.clear();
    return;
  }
  throw StageNotImplemented("MatchState::Cleanup (L1)");
}

bool MatchState::AllFunctionsMatched() const {
  // D:1777-1784
  return static_cast<int64_t>(Impl_->PrimaryMap.size()) == Impl_->Total1 ||
         static_cast<int64_t>(Impl_->SecondaryMap.size()) == Impl_->Total2;
}

size_t MatchState::TotalMatchedFunctions() const {
  // D:3142-3148
  return Impl_->Lists[0].size() + Impl_->Lists[1].size();
}

std::vector<Item> MatchState::SortedResults(Chooser C) const {
  // D:3133-3140: sorted(..., key=float(x[5]), reverse=True) is stable
  std::vector<Item> Copy = Impl_->Lists[static_cast<size_t>(C)];
  std::stable_sort(Copy.begin(), Copy.end(), [](const Item& A, const Item& B) { return A.Ratio > B.Ratio; });
  return Copy;
}

const std::vector<Item>& MatchState::Items(Chooser C) const { return Impl_->Lists[static_cast<size_t>(C)]; }

std::optional<MatchedEntry> MatchState::Primary(NameId Name) const {
  const auto Found = Impl_->PrimaryMap.find(Name);
  if (Found == Impl_->PrimaryMap.end()) {
    return std::nullopt;
  }
  return Found->second;
}

std::optional<MatchedEntry> MatchState::Secondary(NameId Name) const {
  const auto Found = Impl_->SecondaryMap.find(Name);
  if (Found == Impl_->SecondaryMap.end()) {
    return std::nullopt;
  }
  return Found->second;
}

size_t MatchState::PrimarySize() const { return Impl_->PrimaryMap.size(); }
size_t MatchState::SecondarySize() const { return Impl_->SecondaryMap.size(); }

namespace {

SnapItem Export(const Interners& Ids, const Item& It) {
  SnapItem Out;
  Out.Ea1 = std::string(Ids.AddrKeyText(It.Ea1));
  if (auto Name = Ids.NameOrNone(It.Name1)) {
    Out.Name1 = std::string(*Name);
  }
  Out.Ea2 = std::string(Ids.AddrKeyText(It.Ea2));
  if (auto Name = Ids.NameOrNone(It.Name2)) {
    Out.Name2 = std::string(*Name);
  }
  Out.Desc = std::string(Ids.DescText(It.Desc));
  Out.RatioBits = RatioBits(It.Ratio);
  Out.Nodes1 = It.Nodes1;
  Out.Nodes2 = It.Nodes2;
  return Out;
}

Item Import(Interners& Ids, const SnapItem& In) {
  Item Out;
  Out.Ea1 = Ids.Addr(In.Ea1);
  Out.Name1 = In.Name1 ? Ids.Name(*In.Name1) : kNoneName;
  Out.Ea2 = Ids.Addr(In.Ea2);
  Out.Name2 = In.Name2 ? Ids.Name(*In.Name2) : kNoneName;
  Out.Desc = Ids.Desc(In.Desc);
  Out.Ratio = RatioFromBits(In.RatioBits);
  Out.Nodes1 = In.Nodes1;
  Out.Nodes2 = In.Nodes2;
  return Out;
}

}

StateSnapshot MatchState::Export() const {
  StateSnapshot Snap;
  const Interners& Ids = Impl_->S.Ids();
  std::vector<SnapItem>* Targets[3] = {&Snap.Best, &Snap.Partial, &Snap.Unreliable};
  for (size_t Index = 0; Index < 3; ++Index) {
    for (const Item& It : Impl_->Lists[Index]) {
      Targets[Index]->push_back(Diff::Export(Ids, It));
    }
  }
  const auto Dump = [&](const std::vector<NameId>& Order, const std::unordered_map<NameId, MatchedEntry>& Map,
                        std::vector<SnapMatched>& Out) {
    for (const NameId Key : Order) {
      const MatchedEntry& Entry = Map.at(Key);
      SnapMatched Row;
      if (auto Name = Ids.NameOrNone(Key)) {
        Row.Key = std::string(*Name);
      }
      if (auto Name = Ids.NameOrNone(Entry.Other)) {
        Row.Other = std::string(*Name);
      }
      Row.RatioBits = RatioBits(Entry.Ratio);
      Out.push_back(std::move(Row));
    }
  };
  Dump(Impl_->PrimaryOrder, Impl_->PrimaryMap, Snap.MatchedPrimary);
  Dump(Impl_->SecondaryOrder, Impl_->SecondaryMap, Snap.MatchedSecondary);
  Snap.Flags.TotalFunctions1 = Impl_->Total1;
  Snap.Flags.TotalFunctions2 = Impl_->Total2;
  return Snap;
}

void MatchState::Import(const StateSnapshot& Snapshot) {
  Interners& Ids = Impl_->S.Ids();
  const std::vector<SnapItem>* Sources[3] = {&Snapshot.Best, &Snapshot.Partial, &Snapshot.Unreliable};
  for (size_t Index = 0; Index < 3; ++Index) {
    Impl_->Lists[Index].clear();
    for (const SnapItem& It : *Sources[Index]) {
      Impl_->Lists[Index].push_back(Diff::Import(Ids, It));
    }
  }
  Impl_->PrimaryOrder.clear();
  Impl_->SecondaryOrder.clear();
  Impl_->PrimaryMap.clear();
  Impl_->SecondaryMap.clear();
  for (const SnapMatched& Row : Snapshot.MatchedPrimary) {
    Impl::Put(Impl_->PrimaryOrder, Impl_->PrimaryMap, Row.Key ? Ids.Name(*Row.Key) : kNoneName,
              MatchedEntry{Row.Other ? Ids.Name(*Row.Other) : kNoneName, RatioFromBits(Row.RatioBits)});
  }
  for (const SnapMatched& Row : Snapshot.MatchedSecondary) {
    Impl::Put(Impl_->SecondaryOrder, Impl_->SecondaryMap, Row.Key ? Ids.Name(*Row.Key) : kNoneName,
              MatchedEntry{Row.Other ? Ids.Name(*Row.Other) : kNoneName, RatioFromBits(Row.RatioBits)});
  }
  Impl_->Total1 = Snapshot.Flags.TotalFunctions1;
  Impl_->Total2 = Snapshot.Flags.TotalFunctions2;
}

}
