// Diaphora's match bookkeeping (lane L1): all_matches, matched_primary / matched_secondary and the
// operations on them. Literal port of D:1340-1374 (add_match), D:1376-1402 (has_best_match,
// has_better_match), D:1554-1605 (cleanup_matches), D:1777-1784 (all_functions_matched) and
// D:3133-3148 (get_sorted_results, get_total_matched_functions). Spec: 01 §6 and §8, 02 §2 and
// §7-§9, §13-§15, 06 §2.1-§2.6, 07 §10.5.3-§10.5.5. D: = diaphora.py at 3.4.2-4-g621ec26.
//
// State model (02 §2):
//   * all_matches = {"best": [], "partial": [], "unreliable": []} (D:382): three ordered lists of
//     8-field items, iterated in that key order everywhere (cleanup rebuilds the dict in the same
//     order, D:1560-1563, D:1605).
//   * matched_primary[name1] = {"name": name2, "ratio": r}, matched_secondary[name2] = {"name": name1,
//     "ratio": r} (D:1373-1374): dicts keyed by NAME (NameId; Python None is kNoneName, a key of its
//     own). Only membership, lookup and len() are used for matching; the insertion order is kept for
//     the snapshots (Python dict order: re-assigning a key keeps its position).
//   * `item not in self.all_matches[chooser]` (D:1370) is a linear scan with Python == on all 8
//     fields; here it is a per-chooser hash map of the item tuple with ratios compared as doubles
//     (1 == 1.0, and -0.0 == 0.0 hash alike). It is rebuilt whenever a list is replaced (cleanup,
//     import), because a removed item may be appended again later (02 §9 "Port spec").
//
// Ratios are Python floats or the ints 1/0 (02 §2); all comparisons below are exact double
// comparisons, as in Python (1 == 1.0). No ratio can be NaN: every ratio producer divides by a
// non-zero value or raises (ZeroDivisionError), so Python's list-identity shortcut for NaN never
// matters and the descending sorts are strict weak orderings.

#include "dsigmatcher/diff/MatchState.h"

#include <algorithm>
#include <bit>
#include <cstring>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "dsigmatcher/diff/Errors.h"
#include "dsigmatcher/diff/Pipeline.h"
#include "dsigmatcher/diff/Trace.h"

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

namespace {

// Hash of the 8-field item tuple, consistent with Item::operator== (ratio by value: -0.0 == 0.0).
struct ItemHash {
  size_t operator()(const Item& It) const noexcept {
    uint64_t RatioKey = 0;
    if (It.Ratio != 0.0) {
      RatioKey = std::bit_cast<uint64_t>(It.Ratio);
    }
    uint64_t H = 1469598103934665603ull;
    const auto Mix = [&H](uint64_t Value) {
      H ^= Value + 0x9e3779b97f4a7c15ull + (H << 6) + (H >> 2);
    };
    Mix(static_cast<uint64_t>(It.Ea1));
    Mix(static_cast<uint64_t>(It.Name1));
    Mix(static_cast<uint64_t>(It.Ea2));
    Mix(static_cast<uint64_t>(It.Name2));
    Mix(static_cast<uint64_t>(It.Desc));
    Mix(RatioKey);
    Mix(static_cast<uint64_t>(It.Nodes1));
    Mix(static_cast<uint64_t>(It.Nodes2));
    return static_cast<size_t>(H);
  }
};

// A Python dict {name: {"name": other, "ratio": r}} with its insertion order.
struct NameDict {
  std::vector<NameId> Order;
  std::unordered_map<NameId, MatchedEntry> Map;

  void Put(NameId Key, MatchedEntry Entry) {
    auto [It, Inserted] = Map.try_emplace(Key, Entry);
    if (Inserted) {
      Order.push_back(Key);  // a new key goes to the end of a Python dict
    } else {
      It->second = Entry;  // re-assignment keeps the key's position
    }
  }
  const MatchedEntry* Find(NameId Key) const {
    const auto It = Map.find(Key);
    return It == Map.end() ? nullptr : &It->second;
  }
  void Clear() {
    Order.clear();
    Map.clear();
  }
};

// sorted(items, key=lambda x: float(x[5]), reverse=True) (D:1565, D:3137-3139, D:2846, D:2926): Python's
// sort is stable and reverse=True keeps equal keys in their original order, which is exactly
// std::stable_sort with a strict `>` on the double (06 §2.6; not an ascending sort then a reverse).
void SortDescending(std::vector<Item>& Items) {
  std::stable_sort(Items.begin(), Items.end(), [](const Item& A, const Item& B) { return A.Ratio > B.Ratio; });
}

[[noreturn]] void RaiseStartsWithNone(const char* Site) {
  throw DiaphoraWouldRaise(Site, "AttributeError: 'NoneType' object has no attribute 'startswith'");
}

}

struct MatchState::Impl {
  DiffSession& S;
  int64_t Total1 = 0;
  int64_t Total2 = 0;
  std::vector<Item> Lists[3];
  std::unordered_map<Item, uint32_t, ItemHash> Members[3];  // item -> occurrences in Lists[c]
  NameDict Primary;
  NameDict Secondary;

  explicit Impl(DiffSession& Session) : S(Session) {}

  void RebuildMembers(size_t Index) {
    Members[Index].clear();
    Members[Index].reserve(Lists[Index].size());
    for (const Item& It : Lists[Index]) {
      ++Members[Index][It];
    }
  }

  bool StartsWith(NameId Name, std::string_view Prefix, const char* Site) const {
    if (Name == kNoneName) {
      RaiseStartsWithNone(Site);
    }
    return S.Ids().NameText(Name).starts_with(Prefix);
  }

  // D:1386-1402, with the evaluation order of the Python expression (short-circuit `and`).
  bool HasBetterMatch(NameId N1, NameId N2, double Ratio) const {
    // D:1392: `if not name1.startswith("sub_") and not name2.startswith("sub_"):` -- name2 is only
    // evaluated when name1 is not a sub_ name; a None name raises AttributeError there.
    bool Named = !StartsWith(N1, "sub_", "D:1392");
    if (Named) {
      Named = !StartsWith(N2, "sub_", "D:1392");
    }
    if (Named) {
      if (const MatchedEntry* Entry = Primary.Find(N1)) {  // D:1393
        return Entry->Other == N1;                          // D:1394: ratios are not looked at
      }
    }
    // D:1396 `ratio = float(ratio)`: the ratio is already a double.
    if (const MatchedEntry* Entry = Primary.Find(N1); Entry != nullptr && Entry->Ratio > Ratio) {  // D:1397
      return true;
    }
    if (const MatchedEntry* Entry = Secondary.Find(N2); Entry != nullptr && Entry->Ratio > Ratio) {  // D:1399
      return true;
    }
    return false;  // D:1402
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

void MatchState::AddMatch(NameId N1, NameId N2, double Ratio, const Item& It, std::optional<Chooser> C) {
  // D:1347 `with self.items_lock:` has no effect with one thread (02 §2).
  const double RatioArg = Ratio;  // the trace records add_match's ratio ARGUMENT (Trace.h)
  // D:1350-1351: same names -> the ratio stored in the dicts is a fake 1.0; the item keeps its own.
  if (N1 == N2) {
    Ratio = 1.0;
  }
  // D:1353-1355: below 1.0 the better-match test runs again (it can raise on a None name, before
  // anything changes, and then no trace event is written, as the oracle's wrapper writes none).
  if (Ratio != 1.0) {
    if (Impl_->HasBetterMatch(N1, N2, Ratio)) {
      TraceAddMatch(Impl_->S, N1, N2, RatioArg, It, C, AddMatchResult::RejectedBetter);
      return;
    }
    // D:1357-1367: debug messages only.
  }
  // D:1369-1371: `if chooser is not None: if item not in self.all_matches[chooser]: append`.
  bool Appended = false;
  if (C) {
    const size_t Index = static_cast<size_t>(*C);
    uint32_t& Count = Impl_->Members[Index][It];
    if (Count == 0) {
      Impl_->Lists[Index].push_back(It);
      Count = 1;
      Appended = true;
    }
  }
  // D:1373-1374: both dicts are overwritten unconditionally (also for a duplicate item), last writer
  // wins, with the (possibly faked) ratio.
  Impl_->Primary.Put(N1, MatchedEntry{N2, Ratio});
  Impl_->Secondary.Put(N2, MatchedEntry{N1, Ratio});
  // The oracle infers the result from the effect (tools/parity/README.md "add_match event"): the list
  // grew -> appended; otherwise the dicts were rewritten -> duplicate (also for chooser None).
  TraceAddMatch(Impl_->S, N1, N2, RatioArg, It, C, Appended ? AddMatchResult::Appended : AddMatchResult::Duplicate);
}

bool MatchState::HasBestMatch(NameId N1, NameId N2) const {
  // D:1380-1381: exact double equality with 1.0 (the stored ratio may be the same-name fake 1.0).
  if (const MatchedEntry* Entry = Impl_->Primary.Find(N1); Entry != nullptr && Entry->Ratio == 1.0) {
    return true;
  }
  // D:1382-1383
  if (const MatchedEntry* Entry = Impl_->Secondary.Find(N2); Entry != nullptr && Entry->Ratio == 1.0) {
    return true;
  }
  return false;  // D:1384
}

bool MatchState::HasBetterMatch(NameId N1, NameId N2, double Ratio) const {
  return Impl_->HasBetterMatch(N1, N2, Ratio);
}

void MatchState::Cleanup(CleanupSite) {
  // D:1554-1605. The site only names the caller (snapshot points); the body is the same for all.
  const Interners& Ids = Impl_->S.Ids();
  std::unordered_set<std::string> Dones;           // D:1559 dones = {} (one set for all categories)
  std::unordered_map<AddrId, double> EaRatios;     // D:1561 ea_ratios = {} keyed by item[0] only
  std::vector<Item> Out[3];                        // D:1560 d = {}
  for (size_t Index = 0; Index < 3; ++Index) {     // D:1562 best, partial, unreliable (D:382 order)
    std::vector<Item> Sorted = Impl_->Lists[Index];
    SortDescending(Sorted);                        // D:1565
    for (const Item& It : Sorted) {                // D:1566
      // D:1575 match = f"{name1}-{name2}": a plain concatenation (None renders as "None"), so names
      // containing '-' can collide, as in Python (01 §6).
      std::string Key;
      const std::string_view Name1 = Ids.NameKeyText(It.Name1);
      const std::string_view Name2 = Ids.NameKeyText(It.Name2);
      Key.reserve(Name1.size() + 1 + Name2.size());
      Key.append(Name1).append("-").append(Name2);
      if (Dones.count(Key) != 0) {                 // D:1576-1577
        continue;
      }
      double Ratio = It.Ratio;                     // D:1572
      if (It.Name1 == It.Name2) {                  // D:1579-1581: fake 1.0 for the two tests below only
        Ratio = 1.0;
      }
      Dones.insert(std::move(Key));                // D:1583: marked BEFORE the ea1 test (02 §14 item 3)
      const auto Found = EaRatios.find(It.Ea1);    // D:1587-1590: strict >, ties survive
      if (Found != EaRatios.end() && Found->second > Ratio) {
        continue;
      }
      EaRatios[It.Ea1] = Ratio;
      Out[Index].push_back(It);                    // D:1592
    }
  }
  // D:1595-1603: rebuild both dicts from the kept items in (category, sorted) order; last writer wins
  // and the stored ratio is item[5], not the fake 1.0 (02 §14 item 7).
  Impl_->Primary.Clear();
  Impl_->Secondary.Clear();
  for (size_t Index = 0; Index < 3; ++Index) {
    for (const Item& It : Out[Index]) {
      Impl_->Primary.Put(It.Name1, MatchedEntry{It.Name2, It.Ratio});
      Impl_->Secondary.Put(It.Name2, MatchedEntry{It.Name1, It.Ratio});
    }
  }
  // D:1605 self.all_matches = d: every list is replaced by its sorted, pruned copy.
  for (size_t Index = 0; Index < 3; ++Index) {
    Impl_->Lists[Index] = std::move(Out[Index]);
    Impl_->RebuildMembers(Index);
  }
}

bool MatchState::AllFunctionsMatched() const {
  // D:1777-1784: distinct dict keys compared with the row counts by `==` (not >=; 02 §13).
  return static_cast<int64_t>(Impl_->Primary.Map.size()) == Impl_->Total1 ||
         static_cast<int64_t>(Impl_->Secondary.Map.size()) == Impl_->Total2;
}

size_t MatchState::TotalMatchedFunctions() const {
  // D:3142-3148: raw item counts of best + partial (unreliable excluded, duplicates counted).
  return Impl_->Lists[0].size() + Impl_->Lists[1].size();
}

std::vector<Item> MatchState::SortedResults(Chooser C) const {
  // D:3133-3140: a new, stably sorted list; the stored list is not modified.
  std::vector<Item> Copy = Impl_->Lists[static_cast<size_t>(C)];
  SortDescending(Copy);
  return Copy;
}

const std::vector<Item>& MatchState::Items(Chooser C) const { return Impl_->Lists[static_cast<size_t>(C)]; }

std::optional<MatchedEntry> MatchState::Primary(NameId Name) const {
  if (const MatchedEntry* Entry = Impl_->Primary.Find(Name)) {
    return *Entry;
  }
  return std::nullopt;
}

std::optional<MatchedEntry> MatchState::Secondary(NameId Name) const {
  if (const MatchedEntry* Entry = Impl_->Secondary.Find(Name)) {
    return *Entry;
  }
  return std::nullopt;
}

size_t MatchState::PrimarySize() const { return Impl_->Primary.Map.size(); }
size_t MatchState::SecondarySize() const { return Impl_->Secondary.Map.size(); }

namespace {

SnapItem ExportItem(const Interners& Ids, const Item& It) {
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

Item ImportItem(Interners& Ids, const SnapItem& In) {
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

void ExportDict(const Interners& Ids, const NameDict& Dict, std::vector<SnapMatched>& Out) {
  for (const NameId Key : Dict.Order) {
    const MatchedEntry& Entry = Dict.Map.at(Key);
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
}

void ImportDict(Interners& Ids, const std::vector<SnapMatched>& Rows, NameDict& Dict) {
  Dict.Clear();
  for (const SnapMatched& Row : Rows) {
    Dict.Put(Row.Key ? Ids.Name(*Row.Key) : kNoneName,
             MatchedEntry{Row.Other ? Ids.Name(*Row.Other) : kNoneName, RatioFromBits(Row.RatioBits)});
  }
}

}

StateSnapshot MatchState::Export() const {
  StateSnapshot Snap;
  const Interners& Ids = Impl_->S.Ids();
  std::vector<SnapItem>* Targets[3] = {&Snap.Best, &Snap.Partial, &Snap.Unreliable};
  for (size_t Index = 0; Index < 3; ++Index) {
    Targets[Index]->reserve(Impl_->Lists[Index].size());
    for (const Item& It : Impl_->Lists[Index]) {
      Targets[Index]->push_back(ExportItem(Ids, It));
    }
  }
  ExportDict(Ids, Impl_->Primary, Snap.MatchedPrimary);
  ExportDict(Ids, Impl_->Secondary, Snap.MatchedSecondary);
  Snap.Flags.TotalFunctions1 = Impl_->Total1;
  Snap.Flags.TotalFunctions2 = Impl_->Total2;
  return Snap;
}

void MatchState::Import(const StateSnapshot& Snapshot) {
  Interners& Ids = Impl_->S.Ids();
  const std::vector<SnapItem>* Sources[3] = {&Snapshot.Best, &Snapshot.Partial, &Snapshot.Unreliable};
  for (size_t Index = 0; Index < 3; ++Index) {
    Impl_->Lists[Index].clear();
    Impl_->Lists[Index].reserve(Sources[Index]->size());
    for (const SnapItem& It : *Sources[Index]) {
      Impl_->Lists[Index].push_back(ImportItem(Ids, It));
    }
    Impl_->RebuildMembers(Index);
  }
  ImportDict(Ids, Snapshot.MatchedPrimary, Impl_->Primary);
  ImportDict(Ids, Snapshot.MatchedSecondary, Impl_->Secondary);
  Impl_->Total1 = Snapshot.Flags.TotalFunctions1;
  Impl_->Total2 = Snapshot.Flags.TotalFunctions2;
}

}
