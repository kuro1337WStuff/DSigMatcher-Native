// JSONL trace sink and Diaphora's summary lines (docs/parity/00-plan.md §2.2, Appendix B).
//
// The line format is the oracle's, byte for byte (tools/parity/oracle_trace.py, lane L0b, whose hours-
// long captures already exist): Snap.DumpJson(event) = json.dumps(event, ensure_ascii=False,
// separators=(",", ":")) followed by "\n", with the keys in the order the oracle builds each event:
//   add_match  Instrument.WrapAddMatch: ev, seq, ctx, name1, name2, ea1, ea2, desc, ratio_bits, chooser,
//              result (seq = Instrument.AddMatchSeq, the 0-based ordinal of add_match calls)
//   cleanup    Instrument.WrapCleanup: ev, site, n, best, partial, unreliable
//   point      Instrument.Point: ev, name, best, partial, unreliable
//   row        Instrument.EmitRow: ev, ctx, ea1, ea2, decision, ratio_bits
// diff_foundation re-emits every event of a real oracle trace through this sink and compares the bytes.

#include "dsigmatcher/diff/Trace.h"

#include <charconv>
#include <cstdio>
#include <fstream>
#include <unordered_set>

#include "FileIo.h"
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
  // tools/parity/README.md "row event" and oracle_trace.py Instrument.WrapRows / EmitRow.
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
    case RowDecision::AcceptedUnreliable:
      return "accepted_unreliable";
    case RowDecision::Raised:
      return "raised";
  }
  return "";
}

// ---------------------------------------------------------------------------------------------
// TraceSink

struct TraceSink::Impl {
  std::ofstream File;
  std::string Path;
  bool Open = false;
  bool Rows = false;
  uint64_t Lines = 0;        // every event written
  uint64_t AddMatchSeq = 0;  // oracle Instrument.AddMatchSeq

  // A failed write, flush or close (a full disk, audit F27) ends the trace: the sink stops writing, so
  // nothing more is attempted while the IoFailure unwinds, and the run ends with exit 6 instead of
  // exiting 0 with a trace cut off mid-line.
  void Check(const char* What) {
    if (!File) {
      Open = false;
      File.close();
      throw IoFailure("cannot write trace '" + Path + "' (" + What + " failed; is the disk full?)");
    }
  }

  void Line(std::string& Text) {
    Text += '\n';
    File.write(Text.data(), static_cast<std::streamsize>(Text.size()));
    Check("write");
    ++Lines;
  }
};

TraceSink::TraceSink() : Impl_(std::make_unique<Impl>()) {}

TraceSink::~TraceSink() { Close(); }

void TraceSink::Open(const std::string& Path, bool Rows) {
  Close();
  Impl_->File.clear();
  Impl_->File.open(Detail::PathFromUtf8(Path), std::ios::binary | std::ios::trunc);
  if (!Impl_->File) {
    throw IoFailure("cannot write trace '" + Path + "'");
  }
  Impl_->Path = Path;
  Impl_->Open = true;
  Impl_->Rows = Rows;
  Impl_->Lines = 0;
  Impl_->AddMatchSeq = 0;
}

void TraceSink::Close() {
  if (Impl_ && Impl_->Open) {
    Impl_->File.close();
    Impl_->Open = false;
  }
}

void TraceSink::Finish() {
  if (!Impl_->Open) {
    return;
  }
  Impl_->File.flush();
  Impl_->Check("flush");
  Impl_->File.close();
  Impl_->Open = false;
  if (Impl_->File.fail()) {
    throw IoFailure("cannot write trace '" + Impl_->Path + "' (close failed; is the disk full?)");
  }
}

void TraceSink::InjectWriteFailureForTest() {
  if (Impl_->Open) {
    Impl_->File.setstate(std::ios::badbit);
  }
}

bool TraceSink::Enabled() const { return Impl_->Open; }

bool TraceSink::RowsEnabled() const { return Impl_->Open && Impl_->Rows; }

uint64_t TraceSink::Events() const { return Impl_->Lines; }

namespace {

std::string OptionalQuoted(std::optional<std::string_view> Text) {
  return Text ? JsonQuote(*Text) : std::string("null");
}

// The oracle's ctx is None (null) outside every wrapped stage.
std::string CtxJson(std::string_view Ctx) { return Ctx.empty() ? std::string("null") : JsonQuote(Ctx); }

void AppendSizes(std::string& Line, size_t Best, size_t Partial, size_t Unreliable) {
  Line += ",\"best\":" + std::to_string(Best);
  Line += ",\"partial\":" + std::to_string(Partial);
  Line += ",\"unreliable\":" + std::to_string(Unreliable);
  Line += '}';
}

}

void TraceSink::AddMatch(std::string_view Ctx, std::optional<std::string_view> Name1,
                         std::optional<std::string_view> Name2, std::string_view Ea1, std::string_view Ea2,
                         std::string_view Desc, double Ratio, std::optional<std::string_view> ChooserText,
                         AddMatchResult Result) {
  if (!Enabled()) {
    return;
  }
  std::string Line = "{\"ev\":\"add_match\",\"seq\":" + std::to_string(Impl_->AddMatchSeq++);
  Line += ",\"ctx\":" + CtxJson(Ctx);
  Line += ",\"name1\":" + OptionalQuoted(Name1);
  Line += ",\"name2\":" + OptionalQuoted(Name2);
  Line += ",\"ea1\":" + JsonQuote(Ea1);
  Line += ",\"ea2\":" + JsonQuote(Ea2);
  Line += ",\"desc\":" + JsonQuote(Desc);
  Line += ",\"ratio_bits\":" + JsonQuote(RatioBitsHex(Ratio));
  Line += ",\"chooser\":" + OptionalQuoted(ChooserText);
  Line += ",\"result\":" + JsonQuote(AddMatchResultName(Result)) + "}";
  Impl_->Line(Line);
}

void TraceSink::Cleanup(int Site, int64_t N, size_t Best, size_t Partial, size_t Unreliable) {
  if (!Enabled()) {
    return;
  }
  std::string Line = "{\"ev\":\"cleanup\",\"site\":" + std::to_string(Site) + ",\"n\":" + std::to_string(N);
  AppendSizes(Line, Best, Partial, Unreliable);
  Impl_->Line(Line);
}

void TraceSink::Point(std::string_view Name, size_t Best, size_t Partial, size_t Unreliable) {
  if (!Enabled()) {
    return;
  }
  std::string Line = "{\"ev\":\"point\",\"name\":" + JsonQuote(Name);
  AppendSizes(Line, Best, Partial, Unreliable);
  Impl_->Line(Line);
  Impl_->File.flush();  // oracle Instrument.Point: TraceHandle.flush() at every point
  Impl_->Check("flush");
}

void TraceSink::Row(std::string_view Ctx, std::string_view Ea1, std::string_view Ea2, RowDecision Decision,
                    std::optional<double> Ratio) {
  if (!RowsEnabled()) {
    return;
  }
  std::string Line = "{\"ev\":\"row\",\"ctx\":" + CtxJson(Ctx);
  Line += ",\"ea1\":" + JsonQuote(Ea1);
  Line += ",\"ea2\":" + JsonQuote(Ea2);
  Line += ",\"decision\":" + JsonQuote(RowDecisionName(Decision));
  Line += ",\"ratio_bits\":" + (Ratio ? JsonQuote(RatioBitsHex(*Ratio)) : std::string("null")) + "}";
  Impl_->Line(Line);
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

namespace {

// DiffSession::Context() is "diff" at the top level (Pipeline.h); the oracle writes None there.
std::string_view TraceCtx(DiffSession& S) {
  const std::string_view Ctx = S.Context();
  return Ctx == "diff" ? std::string_view() : Ctx;
}

}

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
  // `Ratio` must be add_match's ratio argument (the oracle's ratio_bits), not the forced 1.0 of
  // D:1350-1351. ea1/ea2 are item[0]/item[2], the address TEXT from SQLite; a None address cannot
  // reach an item (SqlRowSource refuses NULL addresses), so AddrKeyText's "None" is never written.
  Sink.AddMatch(TraceCtx(S), Ids.NameOrNone(N1), Ids.NameOrNone(N2), Ids.AddrKeyText(It.Ea1),
                Ids.AddrKeyText(It.Ea2), Ids.DescText(It.Desc), Ratio, ChooserText, Result);
}

void TraceRow(DiffSession& S, const HeuristicRow& Row, RowDecision Decision, std::optional<double> Ratio) {
  TraceSink& Sink = S.Tracer();
  if (!Sink.RowsEnabled()) {
    return;
  }
  Sink.Row(TraceCtx(S), S.Ids().AddrKeyText(Row.Ea1), S.Ids().AddrKeyText(Row.Ea2), Decision, Ratio);
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

void LogFinalResults(DiffSession& S) {
  // D:3684-3695 (the "Done, time taken" line at D:3698 is wall-clock only and is not reproduced).
  const FinalResults& R = S.Final();
  const size_t Best = R.Best.size();                 // D:3684 len(self.best_chooser.items)
  const size_t Partial = R.Partial.size();           // D:3685
  const size_t Unreliable = R.Unreliable.size();     // D:3686
  const size_t Multi = R.Multimatch.size();          // D:3687
  const size_t Total = Best + Partial + Unreliable;  // D:3688
  const std::string FinalLine = "Final results: Best " + std::to_string(Best) + ", Partial " +
                                std::to_string(Partial) + ", Unreliable " + std::to_string(Unreliable) +
                                ", Multimatches " + std::to_string(Multi);  // D:3690-3692
  const int64_t Total1 = S.State().Total1();
  if (Total1 == 0) {
    // D:3689 raises ZeroDivisionError before the D:3690 log call: no "Final results" line.
    throw DiaphoraWouldRaise("D:3689 ZeroDivisionError", "total_functions1 == 0");
  }
  const double Percent = static_cast<double>(Total * 100) / static_cast<double>(Total1);  // D:3689
  S.Log().Info(FinalLine);
  S.Log().Info("Matched " + FormatPercent2(Percent) + "% of main binary functions (" + std::to_string(Total) +
               " out of " + std::to_string(Total1) + ")");  // D:3694-3695
}

}
