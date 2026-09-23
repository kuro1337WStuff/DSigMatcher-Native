#pragma once

// Diaphora's match bookkeeping (L1): all_matches (three lists), matched_primary / matched_secondary
// (dicts keyed by NAME strings), and the cleanup / counters around them. Literal port of
// D:1340-1402 (add_match, has_best_match, has_better_match), D:1554-1605 (cleanup_matches),
// D:1777-1784 (all_functions_matched), D:3133-3148 (get_sorted_results, get_total_matched_functions).
// Spec: 01 §8, 02 §6-§16, 07 §10.5. State is keyed by NameId, never by row.

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>
#include <vector>

#include "dsigmatcher/diff/Interner.h"
#include "dsigmatcher/diff/Snapshot.h"

namespace DSig::Diff {

class DiffSession;

// all_matches keys (D:382). The multimatch chooser only exists in FinalResults (ResultsWriter.h).
enum class Chooser : uint8_t { Best = 0, Partial = 1, Unreliable = 2 };

std::string_view ChooserName(Chooser C);  // "best", "partial", "unreliable"

// A Diaphora match item [ea, name1, ea2, name2, desc, ratio, nodes1, nodes2] (D:1927, 01 §6).
// `item not in list` (D:1370) compares all 8 fields; the int 1 and the float 1.0 are the same double.
struct Item {
  AddrId Ea1 = kNoneAddr;
  NameId Name1 = kNoneName;
  AddrId Ea2 = kNoneAddr;
  NameId Name2 = kNoneName;
  DescId Desc{};
  double Ratio = 0.0;
  int64_t Nodes1 = 0;
  int64_t Nodes2 = 0;
  bool operator==(const Item&) const = default;
};

// matched_primary[name1] = {"name": name2, "ratio": ratio} (and the mirror for secondary).
struct MatchedEntry {
  NameId Other = kNoneName;
  double Ratio = 0.0;
};

// The caller line of every cleanup_matches() call in the default diff (Appendix B); the value is the
// D: line number, used in the snapshot point names "before:cleanup:<site>:<n>".
enum class CleanupSite : uint16_t {
  L1551 = 1551,  // run_heuristics_for_category, after each category
  L2945 = 2945,  // final_pass
  L3185 = 3185,  // find_matches_diffing_internal, after each inner iteration
  L3217 = 3217,  // find_matches_diffing, at entry
  L3340 = 3340,  // find_locally_affine_functions, at entry
  L3413 = 3413,  // find_related_compilation_unit, at entry
  L3471 = 3471,  // find_related_matches, at entry
  L3655 = 3655,  // diff() loop, top
  L3671 = 3671,  // diff() loop, bottom
};

class MatchState {
public:
  explicit MatchState(DiffSession& S);
  ~MatchState();
  MatchState(const MatchState&) = delete;
  MatchState& operator=(const MatchState&) = delete;

  void SetTotals(int64_t Total1, int64_t Total2);                     // D:1418-1419
  int64_t Total1() const;
  int64_t Total2() const;

  // D:1340-1374. `C` is nullopt only where Python passes chooser=None. Emits the add_match trace
  // event (TraceAddMatch in Trace.h) with its outcome.
  void AddMatch(NameId N1, NameId N2, double Ratio, const Item& It, std::optional<Chooser> C);
  bool HasBestMatch(NameId N1, NameId N2) const;                      // D:1376-1384
  bool HasBetterMatch(NameId N1, NameId N2, double Ratio) const;      // D:1386-1402
  // D:1554-1605. Stage code calls DiffSession::Cleanup(Site), which emits the before/after points and
  // the cleanup trace event around this; call this directly only from replays and unit tests.
  void Cleanup(CleanupSite Site);
  bool AllFunctionsMatched() const;                                   // D:1777-1784
  size_t TotalMatchedFunctions() const;                               // D:3142-3148 (items in best+partial)
  std::vector<Item> SortedResults(Chooser C) const;                   // D:3133-3140 (stable, desc, copy)
  const std::vector<Item>& Items(Chooser C) const;
  std::optional<MatchedEntry> Primary(NameId Name) const;
  std::optional<MatchedEntry> Secondary(NameId Name) const;
  size_t PrimarySize() const;
  size_t SecondarySize() const;

  // Snapshot I/O (Appendix B). Export fills all_matches, matched_* (dict insertion order) and the
  // totals; the session adds point, flags, cache, choosers and unmatched. Import restores the same
  // fields (interning through the session's Interners) and rebuilds any derived index.
  StateSnapshot Export() const;
  void Import(const StateSnapshot& Snapshot);

private:
  struct Impl;
  std::unique_ptr<Impl> Impl_;
};

}
