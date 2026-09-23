// The diff driver (docs/parity/00-plan.md §2.1, §2.4, §3.6): DiffSession, the literal port of
// CBinDiff.diff() (D:3568-3701), stage replay and RunDiff, the exception boundary.

#include "dsigmatcher/diff/Pipeline.h"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <map>
#include <tuple>
#include <unordered_map>

#include "dsigmatcher/diff/Errors.h"
#include "dsigmatcher/diff/Stages.h"

#ifndef DSIG_VERSION
#define DSIG_VERSION "0.0.0"
#endif

namespace DSig::Diff {

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------------------------
// DiffSession

struct DiffSession::Impl {
  DiffConfig Config;
  Interners Ids;
  DiffDatabase Db;
  ExportData Main;
  ExportData Diff;
  std::unique_ptr<MatchState> State;
  std::unique_ptr<RatioEngine> Engine;
  IRatioProvider* Provider = nullptr;
  DiffFlags Flags;
  FinalResults Final;
  TraceSink Trace;
  SummaryLog Log;
  RelatedCuSource Cu = RelatedCuSource::Native;
  bool Open = false;

  std::string Pair;
  bool Snapshots = false;
  std::string SnapshotDir;
  std::string PointGlobs = "*";
  std::string CacheGlobs;
  int64_t PointSeq = 0;
  std::vector<std::tuple<int64_t, std::string, std::string>> Index;
  std::map<int, int64_t> CleanupCounters;
  std::optional<int> Iteration;
  std::vector<std::string> Contexts;
  std::vector<std::string> Skipped;
  std::unordered_map<std::type_index, std::shared_ptr<void>> Ext;
};

DiffSession::DiffSession(DiffConfig Config) : Impl_(std::make_unique<Impl>()) {
  Impl_->Config = Config;
  Impl_->Main.Which = Side::Main;
  Impl_->Diff.Which = Side::Diff;
  Impl_->State = std::make_unique<MatchState>(*this);
  Impl_->Engine = std::make_unique<RatioEngine>(*this);
}

DiffSession::~DiffSession() {
  // The lane objects may refer to the session while they are destroyed; drop them first.
  Impl_->Engine.reset();
  Impl_->State.reset();
}

void DiffSession::Open(const std::string& Db1, const std::string& Db2) {
  Impl_->Db.Open(Db1, Db2);
  Impl_->Main.Path = Db1;
  Impl_->Diff.Path = Db2;
  // Ingest is lenient (ExportData::Problems): Diaphora checks diff.version before touching any
  // table (D:3577-3591), so problems are only refused by RequireIngest after that check.
  IngestExport(Impl_->Db, Side::Main, Impl_->Ids, Impl_->Main);
  IngestExport(Impl_->Db, Side::Diff, Impl_->Ids, Impl_->Diff);
  Impl_->Open = true;
}

bool DiffSession::IsOpen() const { return Impl_->Open; }

void DiffSession::RequireIngest() const {
  std::string Problems;
  for (const ExportData* Side : {&Impl_->Main, &Impl_->Diff}) {
    for (const std::string& Problem : Side->Problems) {
      Problems += Problems.empty() ? "" : "; ";
      Problems += Problem;
    }
  }
  if (!Problems.empty()) {
    throw UnsupportedInput("export not supported: " + Problems);
  }
}

const DiffConfig& DiffSession::Config() const { return Impl_->Config; }
DiffConfig& DiffSession::MutableConfig() { return Impl_->Config; }
Interners& DiffSession::Ids() { return Impl_->Ids; }
const Interners& DiffSession::Ids() const { return Impl_->Ids; }
DiffDatabase& DiffSession::Db() { return Impl_->Db; }
const DiffDatabase& DiffSession::Db() const { return Impl_->Db; }
ExportData& DiffSession::Main() { return Impl_->Main; }
const ExportData& DiffSession::Main() const { return Impl_->Main; }
ExportData& DiffSession::Diff() { return Impl_->Diff; }
const ExportData& DiffSession::Diff() const { return Impl_->Diff; }
ExportData& DiffSession::Export(Side Which) { return Which == Side::Main ? Impl_->Main : Impl_->Diff; }
const ExportData& DiffSession::Export(Side Which) const { return Which == Side::Main ? Impl_->Main : Impl_->Diff; }
MatchState& DiffSession::State() { return *Impl_->State; }
const MatchState& DiffSession::State() const { return *Impl_->State; }
RatioEngine& DiffSession::Engine() { return *Impl_->Engine; }
IRatioProvider& DiffSession::Ratio() {
  return Impl_->Provider != nullptr ? *Impl_->Provider : static_cast<IRatioProvider&>(*Impl_->Engine);
}
void DiffSession::SetRatioProvider(IRatioProvider* Provider) { Impl_->Provider = Provider; }
DiffFlags& DiffSession::Flags() { return Impl_->Flags; }
const DiffFlags& DiffSession::Flags() const { return Impl_->Flags; }
FinalResults& DiffSession::Final() { return Impl_->Final; }
const FinalResults& DiffSession::Final() const { return Impl_->Final; }
TraceSink& DiffSession::Tracer() { return Impl_->Trace; }
SummaryLog& DiffSession::Log() { return Impl_->Log; }
RelatedCuSource DiffSession::CuSource() const { return Impl_->Cu; }
void DiffSession::SetCuSource(RelatedCuSource Source) { Impl_->Cu = Source; }

void DiffSession::SetPairLabel(std::string Pair) { Impl_->Pair = std::move(Pair); }
const std::string& DiffSession::PairLabel() const { return Impl_->Pair; }

void DiffSession::EnableSnapshots(const std::string& Dir, std::string PointGlobs, std::string CacheGlobs) {
  std::error_code Error;
  fs::create_directories(fs::path(Dir), Error);
  if (Error && !fs::is_directory(fs::path(Dir))) {
    throw IoFailure("cannot create snapshot directory '" + Dir + "': " + Error.message());
  }
  Impl_->Snapshots = true;
  Impl_->SnapshotDir = Dir;
  Impl_->PointGlobs = std::move(PointGlobs);
  Impl_->CacheGlobs = std::move(CacheGlobs);
}

void DiffSession::EnableTrace(const std::string& Path, bool Rows) { Impl_->Trace.Open(Path, Rows); }

void DiffSession::Point(std::string_view Name) {
  const int64_t Seq = Impl_->PointSeq++;
  const MatchState& S = *Impl_->State;
  Impl_->Trace.Point(Name, S.Items(Chooser::Best).size(), S.Items(Chooser::Partial).size(),
                     S.Items(Chooser::Unreliable).size());
  if (Impl_->Snapshots && PointMatchesAnyGlob(Name, Impl_->PointGlobs)) {
    StateSnapshot Snap = Snapshot(Name, PointMatchesAnyGlob(Name, Impl_->CacheGlobs));
    Snap.Seq = Seq;
    const std::string File = SnapshotFileName(Seq, Name);
    WriteSnapshot((fs::path(Impl_->SnapshotDir) / File).string(), Snap);
    Impl_->Index.emplace_back(Seq, std::string(Name), File);
  }
}

void DiffSession::Cleanup(CleanupSite Site) {
  const int Line = static_cast<int>(Site);
  const int64_t N = ++Impl_->CleanupCounters[Line];
  const std::string Suffix = "cleanup:" + std::to_string(Line) + ":" + std::to_string(N);
  Point("before:" + Suffix);
  InvokeStage(*this, Suffix, [&] { Impl_->State->Cleanup(Site); });
  const MatchState& S = *Impl_->State;
  Impl_->Trace.Cleanup(Line, N, S.Items(Chooser::Best).size(), S.Items(Chooser::Partial).size(),
                       S.Items(Chooser::Unreliable).size());
  Point("after:" + Suffix);
}

std::optional<int> DiffSession::Iteration() const { return Impl_->Iteration; }
void DiffSession::SetIteration(std::optional<int> Iteration) { Impl_->Iteration = Iteration; }

std::string_view DiffSession::Context() const {
  return Impl_->Contexts.empty() ? std::string_view("diff") : std::string_view(Impl_->Contexts.back());
}
void DiffSession::PushContext(std::string Label) { Impl_->Contexts.push_back(std::move(Label)); }
void DiffSession::PopContext() {
  if (!Impl_->Contexts.empty()) {
    Impl_->Contexts.pop_back();
  }
}

namespace {

SnapItem ToSnapItem(const Interners& Ids, const Item& It) {
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

Item FromSnapItem(Interners& Ids, const SnapItem& In) {
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

std::vector<SnapItem> ToSnapItems(const Interners& Ids, const std::vector<Item>& Items) {
  std::vector<SnapItem> Out;
  Out.reserve(Items.size());
  for (const Item& It : Items) {
    Out.push_back(ToSnapItem(Ids, It));
  }
  return Out;
}

std::vector<Item> FromSnapItems(Interners& Ids, const std::vector<SnapItem>& Items) {
  std::vector<Item> Out;
  Out.reserve(Items.size());
  for (const SnapItem& It : Items) {
    Out.push_back(FromSnapItem(Ids, It));
  }
  return Out;
}

std::optional<std::vector<SnapUnmatched>> ToSnapUnmatched(const Interners& Ids,
                                                          const std::optional<std::vector<UnmatchedRow>>& Rows) {
  if (!Rows) {
    return std::nullopt;
  }
  std::vector<SnapUnmatched> Out;
  for (const UnmatchedRow& Row : *Rows) {
    SnapUnmatched Entry;
    Entry.Ea = std::string(Ids.AddrKeyText(Row.Ea));
    if (auto Name = Ids.NameOrNone(Row.Name)) {
      Entry.Name = std::string(*Name);
    }
    Out.push_back(std::move(Entry));
  }
  return Out;
}

std::optional<std::vector<UnmatchedRow>> FromSnapUnmatched(Interners& Ids,
                                                           const std::optional<std::vector<SnapUnmatched>>& Rows) {
  if (!Rows) {
    return std::nullopt;
  }
  std::vector<UnmatchedRow> Out;
  for (const SnapUnmatched& Row : *Rows) {
    Out.push_back(UnmatchedRow{Ids.Addr(Row.Ea), Row.Name ? Ids.Name(*Row.Name) : kNoneName});
  }
  return Out;
}

}

StateSnapshot DiffSession::Snapshot(std::string_view PointName, bool WithCache) const {
  StateSnapshot Snap = Impl_->State->Export();
  Snap.Schema = std::string(kSnapshotSchema);
  Snap.Producer = std::string("dsigmatcher-") + DSIG_VERSION;
  Snap.Pair = Impl_->Pair;
  Snap.Seq = Impl_->PointSeq;
  Snap.Point = std::string(PointName);
  if (Impl_->Iteration) {
    Snap.Iteration = *Impl_->Iteration;
  }
  Snap.Flags.IsSameProcessor = Impl_->Flags.IsSameProcessor;
  Snap.Flags.IsPatchDiff = Impl_->Flags.IsPatchDiff;
  Snap.Flags.IsSymbolsStripped = Impl_->Flags.IsSymbolsStripped;
  Snap.Flags.HooksLoaded = Impl_->Flags.HooksLoaded;
  Snap.Flags.TotalFunctions1 = Impl_->State->Total1();
  Snap.Flags.TotalFunctions2 = Impl_->State->Total2();
  const Interners& Ids = Impl_->Ids;
  if (WithCache) {
    std::vector<SnapCacheEntry> Cache;
    for (const RatioEngine::CacheEntry& Entry : Impl_->Engine->CacheSnapshot()) {
      // ratios_cache key f"{ea1}-{ea2}" (D:1653)
      Cache.push_back(SnapCacheEntry{std::string(Ids.AddrKeyText(Entry.Ea1)) + "-" +
                                         std::string(Ids.AddrKeyText(Entry.Ea2)),
                                     RatioBits(Entry.Ratio)});
    }
    Snap.RatiosCache = std::move(Cache);
  }
  if (PointName == "after:final_pass") {
    SnapChoosers Choosers;
    Choosers.Best = ToSnapItems(Ids, Impl_->Final.Best);
    Choosers.Partial = ToSnapItems(Ids, Impl_->Final.Partial);
    Choosers.Unreliable = ToSnapItems(Ids, Impl_->Final.Unreliable);
    Choosers.Multimatch = ToSnapItems(Ids, Impl_->Final.Multimatch);
    Snap.Choosers = std::move(Choosers);
  }
  if (PointName == "after:find_unmatched") {
    SnapUnmatchedDump Dump;
    Dump.Primary = ToSnapUnmatched(Ids, Impl_->Final.UnmatchedPrimary);
    Dump.Secondary = ToSnapUnmatched(Ids, Impl_->Final.UnmatchedSecondary);
    Snap.Unmatched = std::move(Dump);
  }
  return Snap;
}

void DiffSession::Restore(const StateSnapshot& Before) {
  Impl_->Flags.IsSameProcessor = Before.Flags.IsSameProcessor;
  Impl_->Flags.IsPatchDiff = Before.Flags.IsPatchDiff;
  Impl_->Flags.IsSymbolsStripped = Before.Flags.IsSymbolsStripped;
  Impl_->Flags.HooksLoaded = Before.Flags.HooksLoaded;
  if (Before.Iteration) {
    Impl_->Iteration = static_cast<int>(*Before.Iteration);
  } else {
    Impl_->Iteration.reset();
  }
  Impl_->State->Import(Before);  // also restores total_functions1/2
  if (Before.RatiosCache) {
    Impl_->Engine->ClearCache();
    for (const SnapCacheEntry& Entry : *Before.RatiosCache) {
      // Split "ea1-ea2" at the dash where both halves are known addresses of their sides.
      AddrId Ea1 = kNoneAddr;
      AddrId Ea2 = kNoneAddr;
      bool Found = false;
      for (size_t Dash = Entry.Key.find('-'); Dash != std::string::npos; Dash = Entry.Key.find('-', Dash + 1)) {
        const auto Left = Impl_->Ids.FindAddr(std::string_view(Entry.Key).substr(0, Dash));
        const auto Right = Impl_->Ids.FindAddr(std::string_view(Entry.Key).substr(Dash + 1));
        if (Left && Right && Impl_->Main.Functions.FindRow(*Left) && Impl_->Diff.Functions.FindRow(*Right)) {
          Ea1 = *Left;
          Ea2 = *Right;
          Found = true;
          break;
        }
      }
      if (!Found) {
        const size_t Dash = Entry.Key.find('-');
        if (Dash == std::string::npos) {
          throw UnsupportedInput("ratios_cache key without '-': " + Entry.Key);
        }
        Ea1 = Impl_->Ids.Addr(std::string_view(Entry.Key).substr(0, Dash));
        Ea2 = Impl_->Ids.Addr(std::string_view(Entry.Key).substr(Dash + 1));
      }
      Impl_->Engine->SeedCache(Ea1, Ea2, RatioFromBits(Entry.RatioBits));
    }
  }
  if (Before.Choosers) {
    Impl_->Final.Best = FromSnapItems(Impl_->Ids, Before.Choosers->Best);
    Impl_->Final.Partial = FromSnapItems(Impl_->Ids, Before.Choosers->Partial);
    Impl_->Final.Unreliable = FromSnapItems(Impl_->Ids, Before.Choosers->Unreliable);
    Impl_->Final.Multimatch = FromSnapItems(Impl_->Ids, Before.Choosers->Multimatch);
  }
  if (Before.Unmatched) {
    Impl_->Final.UnmatchedPrimary = FromSnapUnmatched(Impl_->Ids, Before.Unmatched->Primary);
    Impl_->Final.UnmatchedSecondary = FromSnapUnmatched(Impl_->Ids, Before.Unmatched->Secondary);
  }
}

void DiffSession::FinishHarness() {
  if (Impl_->Snapshots) {
    JsonValue Index = JsonValue::Array();
    for (const auto& [Seq, Point, File] : Impl_->Index) {
      JsonValue Row = JsonValue::Array();
      Row.Push(JsonValue::Int(Seq));
      Row.Push(JsonValue::String(Point));
      Row.Push(JsonValue::String(File));
      Index.Push(std::move(Row));
    }
    const std::string Path = (fs::path(Impl_->SnapshotDir) / "index.json").string();
    std::ofstream Out(Path, std::ios::binary | std::ios::trunc);
    if (!Out) {
      throw IoFailure("cannot write '" + Path + "'");
    }
    JsonWriteOptions Options;
    Options.Pretty = true;
    Out << JsonWrite(Index, Options) << '\n';
  }
  if (Impl_->Trace.Enabled()) {
    Impl_->Trace.Close();
  }
}

void DiffSession::NoteSkipped(std::string_view Stage, std::string_view Reason) {
  Impl_->Skipped.emplace_back(Stage);
  Impl_->Log.Info("SKIPPED " + std::string(Stage) + ": " + std::string(Reason));
}

const std::vector<std::string>& DiffSession::SkippedStages() const { return Impl_->Skipped; }

std::shared_ptr<void>& DiffSession::ExtSlot(std::type_index Type) { return Impl_->Ext[Type]; }

char DiffSession::Mode() const {
  if (Impl_->Flags.IsSymbolsStripped) {
    return 'S';
  }
  if (Impl_->Flags.IsPatchDiff) {
    return 'P';
  }
  return 'N';
}

bool InvokeStage(DiffSession& S, std::string_view Name, const std::function<void()>& F) {
  try {
    F();
    return true;
  } catch (const StageNotImplemented& Error) {
    S.NoteSkipped(Name, Error.What);
    return false;
  }
}

// ---------------------------------------------------------------------------------------------
// RunPipeline: diff() (D:3568-3701)

namespace {

// One stage of the convergence loop between its "before:"/"after:" points (Appendix B).
void LoopStage(DiffSession& S, const char* Name, int Iteration, void (*Fn)(DiffSession&, int)) {
  const std::string Base = std::string(Name) + ":" + std::to_string(Iteration);
  S.Point("before:" + Base);
  {
    ContextScope Scope(S, Base);
    InvokeStage(S, Base, [&] { Fn(S, Iteration); });
  }
  S.Point("after:" + Base);
}

// D:3684-3695 (the "Done, time taken" line at D:3698 is wall-clock only and is not reproduced).
void LogFinalResults(DiffSession& S) {
  const FinalResults& R = S.Final();
  const size_t Best = R.Best.size();              // D:3684 len(self.best_chooser.items)
  const size_t Partial = R.Partial.size();        // D:3685
  const size_t Unreliable = R.Unreliable.size();  // D:3686
  const size_t Multi = R.Multimatch.size();       // D:3687
  const size_t Total = Best + Partial + Unreliable;  // D:3688
  S.Log().Info("Final results: Best " + std::to_string(Best) + ", Partial " + std::to_string(Partial) +
               ", Unreliable " + std::to_string(Unreliable) + ", Multimatches " + std::to_string(Multi));
  const int64_t Total1 = S.State().Total1();
  if (Total1 == 0) {
    // D:3689 raises ZeroDivisionError. Unreachable in parity mode (D:2562 divides by the same value
    // first) unless find_equal_matches is still a stub and set no totals.
    if (!S.SkippedStages().empty()) {
      S.Log().Info("Matched: not computed (total_functions1 is 0 because stages were skipped)");
      return;
    }
    throw DiaphoraWouldRaise("D:3689 ZeroDivisionError", "total_functions1 == 0");
  }
  const double Percent = static_cast<double>(Total * 100) / static_cast<double>(Total1);  // D:3689
  S.Log().Info("Matched " + FormatPercent2(Percent) + "% of main binary functions (" + std::to_string(Total) +
               " out of " + std::to_string(Total1) + ")");  // D:3694-3695
}

}

bool RunPipeline(DiffSession& S) {
  ContextScope Root(S, "diff");
  S.Engine().ClearCache();  // D:3572 self.ratios_cache = {}
  S.SetIteration(std::nullopt);

  // D:3577-3591: `select value from diff.version`; failure or no row -> diff() returns False and
  // __main__ still calls save_results (D:3772-3773), which writes empty tables.
  bool VersionOk = true;
  InvokeStage(S, "check_version", [&] { VersionOk = StageCheckVersion(S); });
  if (!VersionOk) {
    return false;
  }
  S.RequireIngest();

  // D:3599-3601: do_continue is always True; equal_db only logs.
  InvokeStage(S, "equal_db", [&] {
    if (StageEqualDb(S)) {
      S.Log().Info("The databases seems to be 100% equal");
    }
  });
  // D:3603-3605 check_callgraph (validation; may raise)
  InvokeStage(S, "check_callgraph", [&] { StageCheckCallgraph(S); });
  // D:3607-3610: project_script is None in the parity configuration (§1.1), so no load_hooks.

  // D:3613-3614 find_equal_matches
  const bool EqualImplemented = InvokeStage(S, "find_equal_matches", [&] {
    ContextScope Scope(S, "find_equal_matches");
    StageFindEqualMatches(S);
  });
  if (!EqualImplemented) {
    // Stub fallback only: the totals find_equal_matches would set (D:1411-1419 `select count(*)`),
    // so that the stubbed pipeline still exercises all_functions_matched and the category lists.
    S.State().SetTotals(static_cast<int64_t>(S.Main().Functions.Count()),
                        static_cast<int64_t>(S.Diff().Functions.Count()));
  }
  S.Point("after:find_equal_matches");

  bool SkipOthers = false;  // D:3616
  InvokeStage(S, "same_processor", [&] { S.Flags().IsSameProcessor = StageSameProcessor(S); });  // D:3617
  InvokeStage(S, "ratio_prepare", [&] { S.Engine().Prepare(); });  // plan §3.6: after IsSameProcessor
  if (S.Config().Experimental) {  // D:3618-3621
    InvokeStage(S, "apply_dirty_heuristics", [&] {
      ContextScope Scope(S, "apply_dirty_heuristics");
      SkipOthers = StageApplyDirtyHeuristics(S);
    });
    S.Point("after:apply_dirty_heuristics");
  }

  if (!S.Config().IgnoreAllNames) {  // D:3623-3624
    S.Point("before:find_same_name");
    {
      ContextScope Scope(S, "find_same_name");
      InvokeStage(S, "find_same_name", [&] { StageFindSameName(S); });
    }
    S.Point("after:find_same_name");
  }

  if (SkipOthers) {  // D:3626-3627
    S.Point("before:find_remaining_functions");
    {
      ContextScope Scope(S, "find_remaining_functions");
      InvokeStage(S, "find_remaining_functions", [&] { StageFindRemainingFunctions(S); });
    }
    S.Point("after:find_remaining_functions");
  } else {
    // D:3629-3630 run_heuristics_for_category("Best") (emits its own heuristic and category points)
    InvokeStage(S, "run_heuristics_for_category:Best",
                [&] { StageRunHeuristicsForCategory(S, HeurCategory::Best); });
    // D:3633-3634 find_partial_matches
    InvokeStage(S, "find_partial_matches", [&] { StageFindPartialMatches(S); });
    // D:3636 apply_machine_learning: use_trained_model is False (§1.1), a no-op.
    // D:3638-3651: unreliable is False (§1.1), so neither unreliable nor experimental matches run.

    int Iteration = 0;  // D:3653
    while (true) {      // D:3654
      S.SetIteration(Iteration);
      S.Cleanup(CleanupSite::L3655);                                   // D:3655
      const size_t OldTotal = S.State().TotalMatchedFunctions();       // D:3656
      LoopStage(S, "find_matches_diffing", Iteration, &StageFindMatchesDiffing);  // D:3660
      if (S.Config().SlowHeuristics) {                                 // D:3662-3664
        LoopStage(S, "find_related_matches", Iteration, &StageFindRelatedMatches);
      }
      LoopStage(S, "find_related_compilation_unit", Iteration, &StageFindRelatedCompilationUnit);  // D:3666
      LoopStage(S, "find_locally_affine_functions", Iteration, &StageFindLocallyAffineFunctions);  // D:3669
      S.Cleanup(CleanupSite::L3671);                                   // D:3671
      const size_t NewTotal = S.State().TotalMatchedFunctions();       // D:3672
      if (NewTotal <= OldTotal) {                                      // D:3673-3674
        break;
      }
      ++Iteration;                                                     // D:3675
    }
  }

  S.Point("before:final_pass");  // D:3677
  {
    ContextScope Scope(S, "final_pass");
    InvokeStage(S, "final_pass", [&] { StageFinalPass(S); });
  }
  S.Point("after:final_pass");

  {
    ContextScope Scope(S, "find_unmatched");  // D:3680-3681
    InvokeStage(S, "find_unmatched", [&] { StageFindUnmatched(S); });
  }
  S.Point("after:find_unmatched");
  // D:3682 call_hook("on_finish"): patch_diff_vulns only shows a chooser, a no-op standalone.

  LogFinalResults(S);  // D:3684-3695
  return true;
}

// ---------------------------------------------------------------------------------------------
// RunReplay

namespace {

std::vector<std::string> SplitColons(std::string_view Text) {
  std::vector<std::string> Parts;
  size_t Start = 0;
  while (true) {
    const size_t Colon = Text.find(':', Start);
    Parts.emplace_back(Text.substr(Start, Colon == std::string_view::npos ? std::string_view::npos : Colon - Start));
    if (Colon == std::string_view::npos) {
      return Parts;
    }
    Start = Colon + 1;
  }
}

int ParseIntPart(const std::string& Text, const char* What) {
  try {
    size_t Used = 0;
    const int Value = std::stoi(Text, &Used);
    if (Used != Text.size()) {
      throw std::invalid_argument(Text);
    }
    return Value;
  } catch (const std::exception&) {
    throw UnsupportedInput(std::string("replay: bad ") + What + " '" + Text + "'");
  }
}

std::optional<CleanupSite> ToCleanupSite(int Line) {
  switch (Line) {
    case 1551:
    case 2945:
    case 3185:
    case 3217:
    case 3340:
    case 3413:
    case 3471:
    case 3655:
    case 3671:
      return static_cast<CleanupSite>(Line);
    default:
      return std::nullopt;
  }
}

}

StateSnapshot RunReplay(DiffSession& S, const StateSnapshot& Before, std::string_view Stage,
                        std::optional<int> Iteration, std::optional<int> HeuristicId) {
  const std::vector<std::string> Parts = SplitColons(Stage);
  const std::string& Base = Parts[0];
  S.Restore(Before);
  InvokeStage(S, "ratio_prepare", [&] { S.Engine().Prepare(); });

  const auto IterationArg = [&]() -> int {
    if (Parts.size() >= 2) {
      return ParseIntPart(Parts[1], "iteration");
    }
    if (Iteration) {
      return *Iteration;
    }
    if (Before.Iteration) {
      return static_cast<int>(*Before.Iteration);
    }
    throw UnsupportedInput("replay: stage '" + std::string(Stage) + "' needs an iteration");
  };

  std::string After;
  if (Base == "find_same_name" || Base == "find_remaining_functions" || Base == "search_small_differences" ||
      Base == "final_pass" || Base == "find_unmatched") {
    ContextScope Scope(S, Base);
    if (Base == "find_same_name") {
      StageFindSameName(S);
    } else if (Base == "find_remaining_functions") {
      StageFindRemainingFunctions(S);
    } else if (Base == "search_small_differences") {
      StageSearchSmallDifferences(S);
    } else if (Base == "final_pass") {
      StageFinalPass(S);
    } else {
      StageFindUnmatched(S);
    }
    After = "after:" + Base;
  } else if (Base == "heuristic") {
    int Id = 0;
    if (Parts.size() >= 2) {
      Id = ParseIntPart(Parts[1], "heuristic id");
    } else if (HeuristicId) {
      Id = *HeuristicId;
    } else {
      throw UnsupportedInput("replay: stage 'heuristic' needs a heuristic id");
    }
    const std::string Label = "heuristic:" + std::to_string(Id);
    ContextScope Scope(S, Label);
    StageRunSingleHeuristic(S, Id);
    After = "after:" + Label;
  } else if (Base == "run_heuristics_for_category") {
    if (Parts.size() < 2 || (Parts[1] != "Best" && Parts[1] != "Partial")) {
      throw UnsupportedInput("replay: run_heuristics_for_category needs :Best or :Partial");
    }
    StageRunHeuristicsForCategory(S, Parts[1] == "Best" ? HeurCategory::Best : HeurCategory::Partial);
    After = "after:run_heuristics_for_category:" + Parts[1];
  } else if (Base == "cleanup") {
    if (Parts.size() < 2) {
      throw UnsupportedInput("replay: cleanup needs a site, e.g. cleanup:3185:4");
    }
    const auto Site = ToCleanupSite(ParseIntPart(Parts[1], "cleanup site"));
    if (!Site) {
      throw UnsupportedInput("replay: unknown cleanup site '" + Parts[1] + "'");
    }
    ContextScope Scope(S, "cleanup");
    S.State().Cleanup(*Site);
    After = "after:cleanup:" + Parts[1] + (Parts.size() >= 3 ? ":" + Parts[2] : std::string());
  } else if (Base == "find_matches_diffing" || Base == "find_related_matches" ||
             Base == "find_related_compilation_unit" || Base == "find_locally_affine_functions") {
    const int K = IterationArg();
    S.SetIteration(K);
    const std::string Label = Base + ":" + std::to_string(K);
    ContextScope Scope(S, Label);
    if (Base == "find_matches_diffing") {
      StageFindMatchesDiffing(S, K);
    } else if (Base == "find_related_matches") {
      StageFindRelatedMatches(S, K);
    } else if (Base == "find_related_compilation_unit") {
      StageFindRelatedCompilationUnit(S, K);
    } else {
      StageFindLocallyAffineFunctions(S, K);
    }
    After = "after:" + Label;
  } else {
    throw UnsupportedInput("replay: stage '" + std::string(Stage) + "' is not replayable (Appendix B)");
  }
  StateSnapshot Result = S.Snapshot(After, Before.RatiosCache.has_value());
  Result.Seq = Before.Seq + 1;
  return Result;
}

// ---------------------------------------------------------------------------------------------
// RunDiff

std::string PathStem(std::string_view Path) {
  // basename(splitext(path)[0]) with genericpath._splitext and ntpath/posixpath basename semantics.
#ifdef _WIN32
  const auto IsSep = [](char Ch) { return Ch == '\\' || Ch == '/'; };
#else
  const auto IsSep = [](char Ch) { return Ch == '/'; };
#endif
  size_t SepIndex = std::string_view::npos;
  for (size_t Index = 0; Index < Path.size(); ++Index) {
    if (IsSep(Path[Index])) {
      SepIndex = Index;
    }
  }
  // splitext: the last '.' after the last separator, unless the name is only leading dots before it.
  std::string_view Root = Path;
  const size_t Dot = Path.rfind('.');
  if (Dot != std::string_view::npos && (SepIndex == std::string_view::npos || Dot > SepIndex)) {
    size_t Name = SepIndex == std::string_view::npos ? 0 : SepIndex + 1;
    while (Name < Dot) {
      if (Path[Name] != '.') {
        Root = Path.substr(0, Dot);
        break;
      }
      ++Name;
    }
  }
  // basename: everything after the last separator (ntpath also drops a drive such as "C:").
  size_t Start = 0;
  for (size_t Index = 0; Index < Root.size(); ++Index) {
    if (IsSep(Root[Index])) {
      Start = Index + 1;
    }
  }
#ifdef _WIN32
  if (Start == 0 && Root.size() >= 2 && Root[1] == ':') {
    Start = 2;
  }
#endif
  return std::string(Root.substr(Start));
}

std::string DefaultOutputName(std::string_view Db1, std::string_view Db2) {
  // D:3727-3731: f"{path1}_vs_{path2}.diaphora", relative to the current directory
  return PathStem(Db1) + "_vs_" + PathStem(Db2) + ".diaphora";
}

std::string SqliteMismatchWarning(std::string_view Version) {
  return "WARNING: SQLite " + std::string(Version) + " is not the oracle's " +
         std::string(DiffDatabase::kOracleSqliteVersion) +
         "; SQL row order may differ from Diaphora's, so results compare at level L1 only "
         "(use --strict-sqlite to refuse)";
}

namespace {

bool SamePath(const std::string& A, const std::string& B) {
  std::error_code Error;
  if (fs::exists(fs::path(A), Error) && fs::exists(fs::path(B), Error)) {
    return fs::equivalent(fs::path(A), fs::path(B), Error);
  }
  const fs::path CanonA = fs::weakly_canonical(fs::path(A), Error);
  const fs::path CanonB = fs::weakly_canonical(fs::path(B), Error);
  return CanonA == CanonB;
}

}

DiffOutcome RunDiff(const DiffArgs& Args) {
  DiffOutcome Outcome;
  Outcome.SqliteVersion = DiffDatabase::LibVersion();
  try {
    if (!Args.Config.Supported()) {
      Outcome.Status = DiffStatus::Unsupported;
      Outcome.Message = "configuration not supported by the parity engine (only the defaults of plan §1.1, "
                        "optionally with --ignore-small-functions)";
      return Outcome;
    }
    // Plan §7.1 D2: warn and continue on another SQLite; --strict-sqlite refuses with exit 5.
    if (!DiffDatabase::IsOracleSqlite()) {
      if (Args.StrictSqlite) {
        Outcome.Status = DiffStatus::SqliteMismatch;
        Outcome.Message = "SQLite " + Outcome.SqliteVersion + " is not the oracle's " +
                          std::string(DiffDatabase::kOracleSqliteVersion) + " (--strict-sqlite)";
        return Outcome;
      }
      if (!Args.AllowSqliteMismatch && !Args.Quiet) {
        std::fprintf(stderr, "%s\n", SqliteMismatchWarning(Outcome.SqliteVersion).c_str());
      }
    }

    const bool Replay = !Args.ReplayPath.empty();
    std::string Out;
    if (Replay) {
      if (Args.ReplayStage.empty() || Args.SnapshotOut.empty()) {
        Outcome.Status = DiffStatus::Usage;
        Outcome.Message = "--replay needs --stage and --snapshot-out";
        return Outcome;
      }
      Out = Args.SnapshotOut;
    } else {
      Out = Args.Out.empty() ? DefaultOutputName(Args.Db1, Args.Db2) : Args.Out;
    }
    Outcome.OutputPath = Out;
    // Plan §2.1: an output path that aliases an input is refused (the writer deletes it first).
    if (SamePath(Out, Args.Db1) || SamePath(Out, Args.Db2)) {
      Outcome.Status = DiffStatus::Usage;
      Outcome.Message = "output '" + Out + "' is one of the input databases";
      return Outcome;
    }

    DiffSession S(Args.Config);
    S.Log().SetQuiet(Args.Quiet);
    S.SetCuSource(Args.CuSource);
    S.Open(Args.Db1, Args.Db2);
    S.SetPairLabel(Args.PairLabel.empty() ? PathStem(Args.Db1) + "_vs_" + PathStem(Args.Db2) : Args.PairLabel);
    if (!Args.TracePath.empty()) {
      S.EnableTrace(Args.TracePath, Args.TraceRows);
    }
    if (!Args.SnapshotDir.empty()) {
      S.EnableSnapshots(Args.SnapshotDir, Args.SnapshotPoints, Args.SnapshotCache);
    }

    if (Replay) {
      const StateSnapshot Before = ReadSnapshot(Args.ReplayPath);
      if (Args.PairLabel.empty() && !Before.Pair.empty()) {
        S.SetPairLabel(Before.Pair);
      }
      StateSnapshot After;
      try {
        After = RunReplay(S, Before, Args.ReplayStage, Args.ReplayIteration, Args.ReplayHeuristic);
      } catch (...) {
        S.FinishHarness();
        throw;
      }
      S.FinishHarness();
      WriteSnapshot(Out, After, true);
      Outcome.OutputWritten = true;
      Outcome.Mode = S.Mode();
      Outcome.Skipped = S.SkippedStages();
      return Outcome;
    }

    try {
      Outcome.DiffReturned = RunPipeline(S);
    } catch (...) {
      S.FinishHarness();
      throw;
    }
    S.FinishHarness();

    // D:3773 bd.save_results(diff_out)
    WriteArgs Write;
    Write.OutPath = Out;
    Write.MainDb = Args.Db1;
    Write.DiffDb = Args.Db2;
    WriteDiaphoraResults(Write, S.Final(), S.Ids());
    Outcome.OutputWritten = true;
    Outcome.Mode = S.Mode();
    Outcome.Best = S.Final().Best.size();
    Outcome.Partial = S.Final().Partial.size();
    Outcome.Unreliable = S.Final().Unreliable.size();
    Outcome.Multimatch = S.Final().Multimatch.size();
    Outcome.Skipped = S.SkippedStages();
  } catch (const DiaphoraWouldRaise& Error) {
    Outcome.Status = DiffStatus::WouldRaise;
    Outcome.Message = Error.what();
  } catch (const UnsupportedInput& Error) {
    Outcome.Status = DiffStatus::Unsupported;
    Outcome.Message = Error.What;
  } catch (const IoFailure& Error) {
    Outcome.Status = DiffStatus::Io;
    Outcome.Message = Error.What;
  } catch (const JsonError& Error) {
    Outcome.Status = DiffStatus::Io;
    Outcome.Message = std::string("invalid snapshot JSON: ") + Error.what();
  } catch (const std::exception& Error) {
    Outcome.Status = DiffStatus::Io;
    Outcome.Message = std::string("internal error: ") + Error.what();
  }
  return Outcome;
}

}
