#pragma once

// The JSONL trace (docs/parity/00-plan.md §2.2, Appendix B) and the stderr summary-line logger.
//
// The reference for every convention is the oracle instrumentation, tools/parity/oracle_trace.py and
// tools/parity/README.md (lane L0b): the native writer emits byte-identical lines (compact JSON, keys
// in this order, one event per line):
//   {"ev":"add_match","seq":..,"ctx":"heuristic:41","name1":..,"name2":..,"ea1":..,"ea2":..,
//    "desc":..,"ratio_bits":..,"chooser":"partial","result":"appended|duplicate|rejected_better"}
//   {"ev":"cleanup","site":3185,"n":4,"best":..,"partial":..,"unreliable":..}   (list sizes after)
//   {"ev":"point","name":"before:final_pass","best":..,"partial":..,"unreliable":..}
//   {"ev":"row","ctx":..,"ea1":..,"ea2":..,"decision":"accepted_partial","ratio_bits":..|null}
// Only add_match events carry "seq": the 0-based ordinal of add_match calls (not of events).
// "ctx" is the innermost stage or heuristic label (DiffSession::Context()): "find_equal_matches",
// "apply_dirty_heuristics", "find_same_name", "find_remaining_functions", "heuristic:<id>",
// "run_heuristics_for_category:<Best|Partial>", "search_small_differences",
// "find_matches_diffing:<k>", "find_related_matches:<k>", "find_related_compilation_unit:<k>",
// "find_locally_affine_functions:<k>", "final_pass", "find_unmatched"; outside every one of them
// (Context() == "diff") it is written as null, as the oracle writes Python None. "ratio_bits" in
// add_match is the `ratio` ARGUMENT of add_match, i.e. before its name1 == name2 forcing to 1.0
// (D:1349-1350); the stored item keeps its own ratio.
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
// Row decisions of tools/parity/README.md ("row event"). AcceptedUnreliable (D:1940-1946, dead under
// the defaults) and Raised (check_match raised) never occur on the corpus; they were appended by lane
// R0 so the native writer can emit every value the oracle can.
enum class RowDecision : uint8_t {
  Nullsub,
  HasBest,
  HasBetter,
  AcceptedBest,
  AcceptedPartial,
  BelowMin,
  AcceptedUnreliable,
  Raised
};

std::string_view AddMatchResultName(AddMatchResult Result);  // "appended", "duplicate", "rejected_better"
std::string_view RowDecisionName(RowDecision Decision);      // "nullsub", "has_best", "has_better",
                                                             // "accepted_best", "accepted_partial", "below_min",
                                                             // "accepted_unreliable", "raised"

class TraceSink {
public:
  TraceSink();
  ~TraceSink();
  TraceSink(const TraceSink&) = delete;
  TraceSink& operator=(const TraceSink&) = delete;

  void Open(const std::string& Path, bool Rows);  // UTF-8 path; truncates; throws IoFailure
  void Close();
  bool Enabled() const;
  bool RowsEnabled() const;
  uint64_t Events() const;  // lines written (every event type)

  // An empty Ctx is written as null (the oracle's None: outside every wrapped stage). Point() also
  // flushes the file, as the oracle does at every point.
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

// The end of diff() (D:3684-3695): the chooser item counts of S.Final(), then percent (D:3689), then
// the "Final results: ..." (D:3690-3692) and "Matched ..." (D:3694-3695) lines. The percent comes
// first, as in Python, so when total_functions1 is 0 it throws DiaphoraWouldRaise("D:3689
// ZeroDivisionError") before any line is logged. Stub-only fallback (removed at L9 with the other
// RunPipeline fallbacks): when stages were skipped (DiffSession::SkippedStages) and total_functions1 is
// 0, it logs both lines with "Matched: not computed ..." instead of raising. Added by lane R0 so the
// ordering is testable; RunPipeline calls it.
void LogFinalResults(DiffSession& S);

// Python "%1.2f" % value (correctly rounded, half-even on the exact double).
std::string FormatPercent2(double Value);

}
