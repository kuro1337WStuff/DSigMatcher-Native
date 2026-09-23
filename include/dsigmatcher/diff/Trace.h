#pragma once

// The JSONL trace (docs/parity/00-plan.md §2.2, Appendix B) and the stderr summary-line logger.
//
// Trace events, one JSON object per line, every event carrying "seq" (event ordinal from 0):
//   {"ev":"add_match","seq":..,"ctx":"heuristic:41","name1":..,"name2":..,"ea1":..,"ea2":..,
//    "desc":..,"ratio_bits":..,"chooser":"partial","result":"appended|duplicate|rejected_better"}
//   {"ev":"cleanup","seq":..,"site":3185,"n":4,"best":..,"partial":..,"unreliable":..}   (sizes after)
//   {"ev":"point","seq":..,"name":"before:final_pass","best":..,"partial":..,"unreliable":..}
//   {"ev":"row","seq":..,"ctx":..,"ea1":..,"ea2":..,"decision":"accepted_partial","ratio_bits":..|null}
// "ctx" is the innermost stage or heuristic label (DiffSession::Context()): the point base names
// "find_equal_matches", "apply_dirty_heuristics", "find_same_name", "find_remaining_functions",
// "heuristic:<id>", "search_small_differences", "find_matches_diffing:<k>", "find_related_matches:<k>",
// "find_related_compilation_unit:<k>", "find_locally_affine_functions:<k>", "final_pass",
// "find_unmatched", or "diff" outside any of them. "ratio_bits" in add_match is the `ratio` argument
// of add_match (before the name1 == name2 forcing at D:1349-1350).
//
// Summary lines are Diaphora's own log texts without timestamps, one per line on stderr:
//   "Current results: ..." / "Matched ..." (D:1622-1635), "Symbols stripped detected: ...",
//   "Patch diffing detected: ..." (D:2566, D:2611-2613), "Final results: ..." (D:3690-3695).

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "dsigmatcher/diff/Candidates.h"
#include "dsigmatcher/diff/Interner.h"
#include "dsigmatcher/diff/MatchState.h"

namespace DSig::Diff {

class DiffSession;

enum class AddMatchResult : uint8_t { Appended, Duplicate, RejectedBetter };
enum class RowDecision : uint8_t { Nullsub, HasBest, HasBetter, AcceptedBest, AcceptedPartial, BelowMin };

std::string_view AddMatchResultName(AddMatchResult Result);  // "appended", "duplicate", "rejected_better"
std::string_view RowDecisionName(RowDecision Decision);      // "nullsub", "has_best", "has_better",
                                                             // "accepted_best", "accepted_partial", "below_min"

class TraceSink {
public:
  TraceSink();
  ~TraceSink();
  TraceSink(const TraceSink&) = delete;
  TraceSink& operator=(const TraceSink&) = delete;

  void Open(const std::string& Path, bool Rows);  // truncates; throws IoFailure
  void Close();
  bool Enabled() const;
  bool RowsEnabled() const;
  uint64_t Events() const;

  void AddMatch(std::string_view Ctx, std::optional<std::string_view> Name1,
                std::optional<std::string_view> Name2, std::string_view Ea1, std::string_view Ea2,
                std::string_view Desc, double Ratio, std::optional<std::string_view> ChooserText,
                AddMatchResult Result);
  void Cleanup(int Site, int64_t N, size_t Best, size_t Partial, size_t Unreliable);
  void Point(std::string_view Name, size_t Best, size_t Partial, size_t Unreliable);
  void Row(std::string_view Ctx, std::string_view Ea1, std::string_view Ea2, RowDecision Decision,
           std::optional<double> Ratio);

private:
  struct Impl;
  std::unique_ptr<Impl> Impl_;
};

// Diaphora's summary lines on stderr. Every line is also kept for tests.
class SummaryLog {
public:
  void Info(std::string_view Line);
  void SetQuiet(bool Quiet) { Quiet_ = Quiet; }
  const std::vector<std::string>& Lines() const { return Lines_; }

private:
  bool Quiet_ = false;
  std::vector<std::string> Lines_;
};

// Session helpers the lanes call. They are no-ops when the trace is disabled.
void TraceAddMatch(DiffSession& S, NameId N1, NameId N2, double Ratio, const Item& It,
                   std::optional<Chooser> C, AddMatchResult Result);
void TraceRow(DiffSession& S, const HeuristicRow& Row, RowDecision Decision, std::optional<double> Ratio);

// show_summary (D:1622-1635): count_different_matches (distinct item[0]) per category and the percent
// over total_functions1. Throws DiaphoraWouldRaise("D:1631 ZeroDivisionError") when total_functions1 is 0.
void LogShowSummary(DiffSession& S);

// Python "%1.2f" % value (correctly rounded, half-even on the exact double).
std::string FormatPercent2(double Value);

}
