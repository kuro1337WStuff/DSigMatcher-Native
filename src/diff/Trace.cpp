// JSONL trace sink and Diaphora's summary lines (docs/parity/00-plan.md §2.2, Appendix B).

#include "dsigmatcher/diff/Trace.h"

#include <charconv>
#include <cstdio>
#include <fstream>
#include <unordered_set>

#include "dsigmatcher/diff/Errors.h"
#include "dsigmatcher/diff/Json.h"
#include "dsigmatcher/diff/Pipeline.h"
#include "dsigmatcher/diff/Snapshot.h"

namespace DSig::Diff {

std::string_view AddMatchResultName(AddMatchResult Result) {
  switch (Result) {
    case AddMatchResult::Appended:
      return "appended";
    case AddMatchResult::Duplicate:
      return "duplicate";
    case AddMatchResult::RejectedBetter:
      return "rejected_better";
  }
  return "";
}

std::string_view RowDecisionName(RowDecision Decision) {
  switch (Decision) {
    case RowDecision::Nullsub:
      return "nullsub";
    case RowDecision::HasBest:
      return "has_best";
    case RowDecision::HasBetter:
      return "has_better";
    case RowDecision::AcceptedBest:
      return "accepted_best";
    case RowDecision::AcceptedPartial:
      return "accepted_partial";
    case RowDecision::BelowMin:
      return "below_min";
  }
  return "";
}

// ---------------------------------------------------------------------------------------------
// TraceSink

struct TraceSink::Impl {
  std::ofstream File;
  bool Open = false;
  bool Rows = false;
  uint64_t Seq = 0;

  void Line(const std::string& Text) {
    File << Text << '\n';
    ++Seq;
  }
};

TraceSink::TraceSink() : Impl_(std::make_unique<Impl>()) {}

TraceSink::~TraceSink() { Close(); }

void TraceSink::Open(const std::string& Path, bool Rows) {
  Close();
  Impl_->File.open(Path, std::ios::binary | std::ios::trunc);
  if (!Impl_->File) {
    throw IoFailure("cannot write trace '" + Path + "'");
  }
  Impl_->Open = true;
  Impl_->Rows = Rows;
  Impl_->Seq = 0;
}

void TraceSink::Close() {
  if (Impl_ && Impl_->Open) {
    Impl_->File.close();
    Impl_->Open = false;
  }
}

bool TraceSink::Enabled() const { return Impl_->Open; }

bool TraceSink::RowsEnabled() const { return Impl_->Open && Impl_->Rows; }

uint64_t TraceSink::Events() const { return Impl_->Seq; }

namespace {

std::string OptionalQuoted(std::optional<std::string_view> Text) {
  return Text ? JsonQuote(*Text) : std::string("null");
}

}

void TraceSink::AddMatch(std::string_view Ctx, std::optional<std::string_view> Name1,
                         std::optional<std::string_view> Name2, std::string_view Ea1, std::string_view Ea2,
                         std::string_view Desc, double Ratio, std::optional<std::string_view> ChooserText,
                         AddMatchResult Result) {
  if (!Enabled()) {
    return;
  }
  std::string Line = "{\"ev\": \"add_match\", \"seq\": " + std::to_string(Impl_->Seq);
  Line += ", \"ctx\": " + JsonQuote(Ctx);
  Line += ", \"name1\": " + OptionalQuoted(Name1);
  Line += ", \"name2\": " + OptionalQuoted(Name2);
  Line += ", \"ea1\": " + JsonQuote(Ea1);
  Line += ", \"ea2\": " + JsonQuote(Ea2);
  Line += ", \"desc\": " + JsonQuote(Desc);
  Line += ", \"ratio_bits\": " + JsonQuote(RatioBitsHex(Ratio));
  Line += ", \"chooser\": " + OptionalQuoted(ChooserText);
  Line += ", \"result\": " + JsonQuote(AddMatchResultName(Result)) + "}";
  Impl_->Line(Line);
}

void TraceSink::Cleanup(int Site, int64_t N, size_t Best, size_t Partial, size_t Unreliable) {
  if (!Enabled()) {
    return;
  }
  Impl_->Line("{\"ev\": \"cleanup\", \"seq\": " + std::to_string(Impl_->Seq) + ", \"site\": " +
              std::to_string(Site) + ", \"n\": " + std::to_string(N) + ", \"best\": " + std::to_string(Best) +
              ", \"partial\": " + std::to_string(Partial) + ", \"unreliable\": " + std::to_string(Unreliable) + "}");
}

void TraceSink::Point(std::string_view Name, size_t Best, size_t Partial, size_t Unreliable) {
  if (!Enabled()) {
    return;
  }
  Impl_->Line("{\"ev\": \"point\", \"seq\": " + std::to_string(Impl_->Seq) + ", \"name\": " + JsonQuote(Name) +
              ", \"best\": " + std::to_string(Best) + ", \"partial\": " + std::to_string(Partial) +
              ", \"unreliable\": " + std::to_string(Unreliable) + "}");
}

void TraceSink::Row(std::string_view Ctx, std::string_view Ea1, std::string_view Ea2, RowDecision Decision,
                    std::optional<double> Ratio) {
  if (!RowsEnabled()) {
    return;
  }
  Impl_->Line("{\"ev\": \"row\", \"seq\": " + std::to_string(Impl_->Seq) + ", \"ctx\": " + JsonQuote(Ctx) +
              ", \"ea1\": " + JsonQuote(Ea1) + ", \"ea2\": " + JsonQuote(Ea2) + ", \"decision\": " +
              JsonQuote(RowDecisionName(Decision)) + ", \"ratio_bits\": " +
              (Ratio ? JsonQuote(RatioBitsHex(*Ratio)) : std::string("null")) + "}");
}

// ---------------------------------------------------------------------------------------------
// SummaryLog

void SummaryLog::Info(std::string_view Line) {
  Lines_.emplace_back(Line);
  if (!Quiet_) {
    std::fwrite(Line.data(), 1, Line.size(), stderr);
    std::fputc('\n', stderr);
    std::fflush(stderr);
  }
}

// ---------------------------------------------------------------------------------------------
// session helpers

void TraceAddMatch(DiffSession& S, NameId N1, NameId N2, double Ratio, const Item& It, std::optional<Chooser> C,
                   AddMatchResult Result) {
  TraceSink& Sink = S.Tracer();
  if (!Sink.Enabled()) {
    return;
  }
  const Interners& Ids = S.Ids();
  std::optional<std::string_view> ChooserText;
  if (C) {
    ChooserText = ChooserName(*C);
  }
  Sink.AddMatch(S.Context(), Ids.NameOrNone(N1), Ids.NameOrNone(N2), Ids.AddrKeyText(It.Ea1),
                Ids.AddrKeyText(It.Ea2), Ids.DescText(It.Desc), Ratio, ChooserText, Result);
}

void TraceRow(DiffSession& S, const HeuristicRow& Row, RowDecision Decision, std::optional<double> Ratio) {
  TraceSink& Sink = S.Tracer();
  if (!Sink.RowsEnabled()) {
    return;
  }
  Sink.Row(S.Context(), S.Ids().AddrKeyText(Row.Ea1), S.Ids().AddrKeyText(Row.Ea2), Decision, Ratio);
}

std::string FormatPercent2(double Value) {
  // Python "%1.2f" formats the exact double with round-half-even, as std::to_chars fixed does.
  char Buffer[512];
  const auto Result = std::to_chars(Buffer, Buffer + sizeof(Buffer), Value, std::chars_format::fixed, 2);
  return std::string(Buffer, Result.ptr);
}

void LogShowSummary(DiffSession& S) {
  // D:1607-1620 count_different_matches / get_total_matches_for: distinct item[0] per category.
  const auto Distinct = [&](Chooser C) {
    std::unordered_set<AddrId> Seen;
    for (const Item& It : S.State().Items(C)) {
      Seen.insert(It.Ea1);
    }
    return Seen.size();
  };
  const size_t Best = Distinct(Chooser::Best);                 // D:1627
  const size_t Partial = Distinct(Chooser::Partial);           // D:1628
  const size_t Unreliable = Distinct(Chooser::Unreliable);     // D:1629
  const size_t Total = Best + Partial + Unreliable;            // D:1630
  const int64_t Total1 = S.State().Total1();
  if (Total1 == 0) {
    throw DiaphoraWouldRaise("D:1631 ZeroDivisionError", "show_summary with total_functions1 == 0");
  }
  // D:1631 (total * 100) / total_functions1: Python true division of ints (exact in double here)
  const double Percent = static_cast<double>(Total * 100) / static_cast<double>(Total1);
  S.Log().Info("Current results: Best " + std::to_string(Best) + ", Partial " + std::to_string(Partial) +
               ", Unreliable " + std::to_string(Unreliable));  // D:1632
  S.Log().Info("Matched " + FormatPercent2(Percent) + "% of main binary functions (" + std::to_string(Total) +
               " out of " + std::to_string(Total1) + ")");  // D:1634-1635
}

}
