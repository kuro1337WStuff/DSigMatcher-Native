// The diff driver (docs/parity/00-plan.md §2.1, §2.4, §3.6): DiffSession, the literal port of
// CBinDiff.diff() (D:3568-3701), stage replay and RunDiff, the exception boundary.

#include "dsigmatcher/diff/Pipeline.h"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <map>
#include <new>
#include <set>
#include <tuple>
#include <unordered_map>

#include "FileIo.h"
#include "dsigmatcher/Version.h"
#include "dsigmatcher/diff/Errors.h"
#include "dsigmatcher/diff/Json.h"
#include "dsigmatcher/diff/StageSql.h"
#include "dsigmatcher/diff/Stages.h"
#include "stages/EarlyPasses.h"

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
  // index.json rows [seq, point, file]; file is "snapshots/<name>" or null (filtered out)
  std::vector<std::tuple<int64_t, std::string, std::optional<std::string>>> Index;
  std::map<int, int64_t> CleanupCounters;
  std::optional<int> Iteration;
  std::vector<std::string> Contexts;
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

namespace {

// tools/parity/oracle_trace.py writes run.json into every capture directory; the native engine never
// does. Writing native output there (or into a directory inside one, such as its snapshots/) would
// overwrite or mix into an oracle capture, so such a directory is refused.
// Throws UsageRefused (exit 2): RunDiff checks every write target this way before it opens anything.
void RefuseOracleCapture(const fs::path& Dir, const std::string& Shown) {
  std::error_code Error;
  const fs::path Absolute = fs::absolute(Dir.empty() ? fs::path(".") : Dir, Error);
  const fs::path& Checked = Error ? Dir : Absolute;
  for (const fs::path& Candidate : {Checked, Checked.parent_path()}) {
    if (!Candidate.empty() && fs::exists(Candidate / "run.json", Error)) {
      throw UsageRefused("refusing to write '" + Shown +
                         "': its directory is (or is inside) an oracle capture, which holds run.json "
                         "(tools/parity/oracle_trace.py)");
    }
  }
}

// snapshot.py SnapshotFileName: "%05d_%s.json" (five or more digits, '_', the sanitised point).
bool IsSnapshotFileName(const std::string& Name) {
  size_t Digits = 0;
  while (Digits < Name.size() && Name[Digits] >= '0' && Name[Digits] <= '9') {
    ++Digits;
  }
  return Digits >= 5 && Digits < Name.size() && Name[Digits] == '_' && Name.size() > 5 &&
         Name.compare(Name.size() - 5, 5, ".json") == 0;
}

// index.json of a snapshot capture: a JSON array of [seq, point, file] rows, seq an integer, point a
// string, file a string or null (the layout WriteIndexFile and oracle_trace.py write).
bool IsCaptureIndex(const std::string& Bytes) {
  try {
    const JsonValue Rows = JsonParse(Bytes);
    if (!Rows.IsArray()) {
      return false;
    }
    for (const JsonValue& Row : Rows.Items()) {
      if (!Row.IsArray() || Row.Items().size() != 3 || !Row.Items()[0].IsIntegerText() ||
          !Row.Items()[1].IsString() || !(Row.Items()[2].IsString() || Row.Items()[2].IsNull())) {
        return false;
      }
    }
    return true;
  } catch (const JsonError&) {
    return false;
  }
}

// Audit F29: EnableSnapshots deletes <dir>/index.json and the snapshot-named files under
// <dir>/snapshots. It may do that only to an earlier capture: an index.json that is not a capture
// index is somebody else's file, and the directory is refused (exit 2) with nothing deleted.
void RefuseForeignSnapshotDir(const std::string& Dir) {
  const fs::path Root = Detail::PathFromUtf8(Dir);
  RefuseOracleCapture(Root, Dir);
  std::error_code Error;
  const fs::path Index = Root / "index.json";
  if (fs::exists(Index, Error)) {
    if (!fs::is_regular_file(Index, Error)) {
      throw UsageRefused("refusing to use '" + Dir + "' as a snapshot directory: its index.json is not a file");
    }
    std::string Bytes;
    try {
      Bytes = Detail::ReadFileBytes(Detail::PathToUtf8(Index));
    } catch (const IoFailure& Failure) {
      throw UsageRefused("refusing to use '" + Dir + "' as a snapshot directory: " + Failure.What);
    }
    if (!IsCaptureIndex(Bytes)) {
      throw UsageRefused("refusing to use '" + Dir +
                         "' as a snapshot directory: its index.json is not a snapshot capture index, and "
                         "--snapshot-dir replaces index.json (use an empty or new directory; nothing was changed)");
    }
  }
}

}

void DiffSession::EnableSnapshots(const std::string& Dir, std::string PointGlobs, std::string CacheGlobs) {
  // The capture layout of tools/parity/oracle_trace.py (README "Output"), so compare_traces.py and
  // snapshot.py read native and oracle captures alike: <Dir>/index.json lists every point in order as
  // [seq, point, file]; the files are <Dir>/snapshots/NNNNN_<sanitised point>.json and `file` is that
  // path relative to <Dir> ("snapshots/..."), or null for a point --snapshot-points filtered out.
  const fs::path Root = Detail::PathFromUtf8(Dir);
  RefuseForeignSnapshotDir(Dir);  // also refuses an oracle capture (run.json)
  const fs::path Files = Root / "snapshots";
  std::error_code Error;
  fs::create_directories(Files, Error);
  if (!fs::is_directory(Files, Error)) {
    throw IoFailure("cannot create snapshot directory '" + Dir + "': " + Error.message());
  }
  // The oracle's PrepareOutDir removes an earlier capture's snapshots and index. Only files named like
  // a snapshot are removed here, so stale ones never sit next to this run's. A file that cannot be
  // removed is an error (audit F01): it is never overwritten in place later.
  std::vector<fs::path> Stale;
  for (const fs::directory_entry& Entry : fs::directory_iterator(Files, Error)) {
    if (Entry.is_regular_file(Error) && IsSnapshotFileName(Detail::PathToUtf8(Entry.path().filename()))) {
      Stale.push_back(Entry.path());
    }
  }
  if (Error) {
    throw IoFailure("cannot list snapshot directory '" + Detail::PathToUtf8(Files) + "': " + Error.message());
  }
  Stale.push_back(Root / "index.json");
  for (const fs::path& Path : Stale) {
    Error.clear();
    fs::remove(Path, Error);
    if (Error) {
      throw IoFailure("cannot remove '" + Detail::PathToUtf8(Path) + "': " + Error.message());
    }
  }
  Impl_->Snapshots = true;
  Impl_->SnapshotDir = Dir;
  Impl_->PointGlobs = std::move(PointGlobs);
  Impl_->CacheGlobs = std::move(CacheGlobs);
  Impl_->Index.clear();
}

void DiffSession::EnableTrace(const std::string& Path, bool Rows) {
  const fs::path Parent = Detail::PathFromUtf8(Path).parent_path();
  RefuseOracleCapture(Parent, Path);
  if (!Parent.empty()) {
    std::error_code Error;
    fs::create_directories(Parent, Error);  // like the oracle's capture directory; Open reports failures
  }
  Impl_->Trace.Open(Path, Rows);
}

namespace {

void WriteIndexFile(const std::string& Dir,
                    const std::vector<std::tuple<int64_t, std::string, std::optional<std::string>>>& Index) {
  // snapshot.py WriteJsonAtomic(index.json, [[seq, point, file], ...]): compact JSON, one newline,
  // replaced atomically (oracle_trace.py rewrites it at every point, so it is usable mid-run).
  JsonValue Rows = JsonValue::Array();
  for (const auto& [Seq, Point, File] : Index) {
    JsonValue Row = JsonValue::Array();
    Row.Push(JsonValue::Int(Seq));
    Row.Push(JsonValue::String(Point));
    Row.Push(File ? JsonValue::String(*File) : JsonValue::Null());
    Rows.Push(std::move(Row));
  }
  Detail::ReplaceFileBytes(Detail::PathToUtf8(Detail::PathFromUtf8(Dir) / "index.json"), JsonWrite(Rows) + "\n");
}

}

void DiffSession::Point(std::string_view Name) {
  // oracle_trace.py Instrument.Point: seq counts every point from 0, filtered ones included; the trace
  // gets a point event for every point; index.json lists every point, with a null file when the
  // snapshot was filtered out.
  const int64_t Seq = Impl_->PointSeq++;
  const MatchState& S = *Impl_->State;
  Impl_->Trace.Point(Name, S.Items(Chooser::Best).size(), S.Items(Chooser::Partial).size(),
                     S.Items(Chooser::Unreliable).size());
  if (Impl_->Snapshots) {
    std::optional<std::string> File;
    if (PointMatchesAnyGlob(Name, Impl_->PointGlobs)) {
      StateSnapshot Snap = Snapshot(Name, PointMatchesAnyGlob(Name, Impl_->CacheGlobs));
      Snap.Seq = Seq;
      File = "snapshots/" + SnapshotFileName(Seq, Name);
      WriteSnapshot(Detail::PathToUtf8(Detail::PathFromUtf8(Impl_->SnapshotDir) / "snapshots" /
                                       Detail::PathFromUtf8(SnapshotFileName(Seq, Name))),
                    Snap);
    }
    Impl_->Index.emplace_back(Seq, std::string(Name), std::move(File));
    WriteIndexFile(Impl_->SnapshotDir, Impl_->Index);
  }
}

void DiffSession::Cleanup(CleanupSite Site) {
  const int Line = static_cast<int>(Site);
  const int64_t N = ++Impl_->CleanupCounters[Line];
  const std::string Suffix = "cleanup:" + std::to_string(Line) + ":" + std::to_string(N);
  Point("before:" + Suffix);
  Impl_->State->Cleanup(Site);
  const MatchState& S = *Impl_->State;
  Impl_->Trace.Cleanup(Line, N, S.Items(Chooser::Best).size(), S.Items(Chooser::Partial).size(),
                       S.Items(Chooser::Unreliable).size());
  Point("after:" + Suffix);
}

std::optional<int> DiffSession::Iteration() const { return Impl_->Iteration; }
void DiffSession::SetIteration(std::optional<int> Iteration) { Impl_->Iteration = Iteration; }

int64_t DiffSession::PointSeq() const { return Impl_->PointSeq; }
void DiffSession::SetPointSeq(int64_t Seq) { Impl_->PointSeq = Seq; }

std::vector<std::pair<int, int64_t>> DiffSession::CleanupCounters() const {
  return std::vector<std::pair<int, int64_t>>(Impl_->CleanupCounters.begin(), Impl_->CleanupCounters.end());
}

void DiffSession::SetCleanupCounters(const std::vector<std::pair<int, int64_t>>& Counters) {
  Impl_->CleanupCounters.clear();
  for (const auto& [Site, Count] : Counters) {
    Impl_->CleanupCounters[Site] = Count;
  }
}

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
        // Real oracle caches hold keys that are not a (main function, diff function) pair of addresses
        // (for example "4203192-4202448" in ls_vs_ls-old's captures), so such a key is kept under the
        // first dash, as Python keeps it. A snapshot of another pair is refused by
        // CheckSnapshotMatchesInputs through its items and totals instead (audit F28).
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
    WriteIndexFile(Impl_->SnapshotDir, Impl_->Index);  // also when no point was reached: "[]"
  }
  Impl_->Trace.Finish();  // checked flush and close (audit F27); a no-op when the trace is off
}

void DiffSession::CheckSnapshotMatchesInputs(const StateSnapshot& Before) const {
  // Audit F28: every address the snapshot carries must be a function of the side it belongs to, and
  // the recorded function totals (0 before find_equal_matches sets them) must be the inputs' counts.
  const Interners& Ids = Impl_->Ids;
  const auto Require = [&](const std::string& Ea, const ExportData& Side, const char* Where) {
    const std::optional<AddrId> Id = Ids.FindAddr(Ea);
    if (!Id || !Side.Functions.FindRow(*Id)) {
      throw UnsupportedInput("replay: snapshot address " + Ea + " (" + Where + ") is not a function of '" +
                             Side.Path + "'; the snapshot (pair '" + Before.Pair +
                             "') does not belong to these databases");
    }
  };
  const auto RequireItems = [&](const std::vector<SnapItem>& Items, const char* Where) {
    for (const SnapItem& It : Items) {
      Require(It.Ea1, Impl_->Main, Where);
      Require(It.Ea2, Impl_->Diff, Where);
    }
  };
  RequireItems(Before.Best, "all_matches.best");
  RequireItems(Before.Partial, "all_matches.partial");
  RequireItems(Before.Unreliable, "all_matches.unreliable");
  if (Before.Choosers) {
    RequireItems(Before.Choosers->Best, "choosers.best");
    RequireItems(Before.Choosers->Partial, "choosers.partial");
    RequireItems(Before.Choosers->Unreliable, "choosers.unreliable");
    RequireItems(Before.Choosers->Multimatch, "choosers.multimatch");
  }
  if (Before.Unmatched) {
    // "primary" lists diff-database functions and "secondary" main-database ones (D:2330-2354).
    for (const auto& [Rows, Side, Where] :
         {std::tuple{&Before.Unmatched->Primary, &Impl_->Diff, "unmatched.primary"},
          std::tuple{&Before.Unmatched->Secondary, &Impl_->Main, "unmatched.secondary"}}) {
      if (!*Rows) {
        continue;
      }
      for (const SnapUnmatched& Row : **Rows) {
        if (Row.Ea != "None") {
          Require(Row.Ea, *Side, Where);
        }
      }
    }
  }
  const auto RequireTotal = [&](int64_t Recorded, const ExportData& Side, const char* Name) {
    const auto Count = static_cast<int64_t>(Side.Functions.Count());
    if (Recorded != 0 && Recorded != Count) {
      throw UnsupportedInput("replay: the snapshot records " + std::string(Name) + " = " + std::to_string(Recorded) +
                             " but '" + Side.Path + "' has " + std::to_string(Count) +
                             " functions; the snapshot (pair '" + Before.Pair + "') does not belong to these databases");
    }
  };
  RequireTotal(Before.Flags.TotalFunctions1, Impl_->Main, "total_functions1");
  RequireTotal(Before.Flags.TotalFunctions2, Impl_->Diff, "total_functions2");
}

std::shared_ptr<void>& DiffSession::ExtSlot(std::type_index Type) { return Impl_->Ext[Type]; }

// ---------------------------------------------------------------------------------------------
// Checkpoints (Checkpoint.h)

EngineCheckpoint CaptureCheckpoint(DiffSession& S, const PipelineCursor& Cursor) {
  EngineCheckpoint C;
  C.Cursor = Cursor;
  // A point name that is none of the dump points, so Snapshot adds neither choosers nor unmatched lists;
  // they are added below whenever their stage has run.
  C.State = S.Snapshot("checkpoint:" + std::string(PipelineStepName(Cursor.Done)), false);
  const Interners& Ids = S.Ids();
  if (Cursor.Done >= PipelineStep::FinalPass) {
    SnapChoosers Choosers;
    Choosers.Best = ToSnapItems(Ids, S.Final().Best);
    Choosers.Partial = ToSnapItems(Ids, S.Final().Partial);
    Choosers.Unreliable = ToSnapItems(Ids, S.Final().Unreliable);
    Choosers.Multimatch = ToSnapItems(Ids, S.Final().Multimatch);
    C.State.Choosers = std::move(Choosers);
  }
  if (Cursor.Done >= PipelineStep::FindUnmatched) {
    SnapUnmatchedDump Dump;
    Dump.Primary = ToSnapUnmatched(Ids, S.Final().UnmatchedPrimary);
    Dump.Secondary = ToSnapUnmatched(Ids, S.Final().UnmatchedSecondary);
    C.State.Unmatched = std::move(Dump);
  }
  const auto AddrText = [&](AddrId Id) -> std::optional<std::string> {
    if (Id == kNoneAddr) {
      return std::nullopt;
    }
    return std::string(Ids.AddrText(Id));
  };
  const std::vector<RatioEngine::CacheEntry>& Cache = S.Engine().CacheEntries();
  C.RatiosCache.reserve(Cache.size());
  for (const RatioEngine::CacheEntry& Entry : Cache) {
    C.RatiosCache.push_back(CheckpointCacheEntry{AddrText(Entry.Ea1), AddrText(Entry.Ea2), RatioBits(Entry.Ratio)});
  }
  const auto NameText = [&](NameId Id) -> std::optional<std::string> {
    if (const auto Name = Ids.NameOrNone(Id)) {
      return std::string(*Name);
    }
    return std::nullopt;
  };
  for (const auto& [Name1, Name2] : S.Ext<Early::PatchDiffHookState>().Dones) {
    C.HookDones.emplace_back(NameText(Name1), NameText(Name2));
  }
  C.PointSeq = S.PointSeq();
  C.CleanupCounters = S.CleanupCounters();
  return C;
}

void RestoreCheckpoint(DiffSession& S, const EngineCheckpoint& C) {
  S.CheckSnapshotMatchesInputs(C.State);
  S.Restore(C.State);  // flags, totals, iteration, all_matches, matched_*, choosers, unmatched
  Interners& Ids = S.Ids();
  const auto Addr = [&](const std::optional<std::string>& Text) { return Text ? Ids.Addr(*Text) : kNoneAddr; };
  S.Engine().ClearCache();
  for (const CheckpointCacheEntry& Entry : C.RatiosCache) {
    S.Engine().SeedCache(Addr(Entry.Ea1), Addr(Entry.Ea2), RatioFromBits(Entry.RatioBits));
  }
  const auto Name = [&](const std::optional<std::string>& Text) {
    return Text ? Ids.Name(*Text) : kNoneName;
  };
  std::set<std::pair<NameId, NameId>>& Dones = S.Ext<Early::PatchDiffHookState>().Dones;
  Dones.clear();
  for (const auto& [Name1, Name2] : C.HookDones) {
    Dones.insert({Name(Name1), Name(Name2)});
  }
  S.SetPointSeq(C.PointSeq);
  S.SetCleanupCounters(C.CleanupCounters);
}

char DiffSession::Mode() const {
  if (Impl_->Flags.IsSymbolsStripped) {
    return 'S';
  }
  if (Impl_->Flags.IsPatchDiff) {
    return 'P';
  }
  return 'N';
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
    Fn(S, Iteration);
  }
  S.Point("after:" + Base);
}

}

bool RunPipeline(DiffSession& S) { return RunPipeline(S, nullptr); }

// The pipeline is one code path for fresh and resumed runs: every top-level step runs unless the resumed
// checkpoint was written after it, and every completed step is offered to Checkpointing->Save. A
// resumed run starts from the state RestoreCheckpoint put into the session, which is everything a
// later step reads (matches, matched dicts, totals, flags, ratios cache, choosers, unmatched lists, the
// patch-diff hook's dones, the iteration and the harness counters), plus the two locals of diff() that
// outlive a step (skip_others, old_total), which the cursor carries.
bool RunPipeline(DiffSession& S, PipelineCheckpointing* Checkpointing) {
  ContextScope Root(S, "diff");
  const std::optional<PipelineCursor> Resume =
      Checkpointing != nullptr ? Checkpointing->ResumeFrom : std::optional<PipelineCursor>();
  PipelineCursor Cursor = Resume.value_or(PipelineCursor{});
  // A pre-loop or post-loop step is done when the checkpoint was written at it or at any later step
  // (the enumerators are in execution order; every loop step lies between the two groups).
  const auto Done = [&](PipelineStep Step) { return Resume && Resume->Done >= Step; };
  const auto Save = [&](PipelineStep Step) {
    Cursor.Done = Step;
    if (Checkpointing != nullptr && Checkpointing->Save) {
      Checkpointing->Save(Cursor);
    }
  };

  if (!Resume) {
    S.Engine().ClearCache();  // D:3572 self.ratios_cache = {}
    S.SetIteration(std::nullopt);

    // D:3577-3591: `select value from diff.version`; failure or no row -> diff() returns False and
    // __main__ still calls save_results (D:3772-3773), which writes empty tables.
    if (!StageCheckVersion(S)) {
      return false;
    }
    S.RequireIngest();

    // D:3599-3601: do_continue is always True; equal_db only logs.
    if (StageEqualDb(S)) {
      S.Log().Info("The databases seems to be 100% equal");
    }
    // D:3603-3605 check_callgraph (validation; may raise)
    StageCheckCallgraph(S);
    // D:3607-3610: project_script is None in the parity configuration (§1.1), so no load_hooks.

    // D:3613-3614 find_equal_matches (also sets total_functions1/2, D:1411-1422)
    {
      ContextScope Scope(S, "find_equal_matches");
      StageFindEqualMatches(S);
    }
    S.Point("after:find_equal_matches");
    Save(PipelineStep::EqualMatches);
  } else {
    // The checkpoint was written after the version check and the ingest checks passed on inputs with
    // the same sha256 (the manifest binding), so they pass again; the ingest check is cheap and repeated
    // as a guard.
    S.RequireIngest();
  }

  bool SkipOthers = Cursor.SkipOthers;  // D:3616
  if (!Done(PipelineStep::DirtyHeuristics)) {
    S.Flags().IsSameProcessor = StageSameProcessor(S);  // D:3617
    S.Engine().Prepare();                               // plan §3.6: after IsSameProcessor
    if (S.Config().Experimental) {                      // D:3618-3621
      {
        ContextScope Scope(S, "apply_dirty_heuristics");
        SkipOthers = StageApplyDirtyHeuristics(S);
      }
      S.Point("after:apply_dirty_heuristics");
    }
    Cursor.SkipOthers = SkipOthers;
    Save(PipelineStep::DirtyHeuristics);
  } else {
    S.Engine().Prepare();  // per-function data for the restored IsSameProcessor
  }

  if (!S.Config().IgnoreAllNames && !Done(PipelineStep::SameName)) {  // D:3623-3624
    S.Point("before:find_same_name");
    {
      ContextScope Scope(S, "find_same_name");
      StageFindSameName(S);
    }
    S.Point("after:find_same_name");
    Save(PipelineStep::SameName);
  }

  if (SkipOthers) {  // D:3626-3627
    if (!Done(PipelineStep::RemainingFunctions)) {
      S.Point("before:find_remaining_functions");
      {
        ContextScope Scope(S, "find_remaining_functions");
        StageFindRemainingFunctions(S);
      }
      S.Point("after:find_remaining_functions");
      Save(PipelineStep::RemainingFunctions);
    }
  } else {
    // D:3629-3630 run_heuristics_for_category("Best") (emits its own heuristic and category points).
    // oracle_trace.py WrapStage makes "run_heuristics_for_category:Best" the main-thread ctx.
    if (!Done(PipelineStep::BestCategory)) {
      {
        ContextScope Scope(S, "run_heuristics_for_category:Best");
        StageRunHeuristicsForCategory(S, HeurCategory::Best);
      }
      Save(PipelineStep::BestCategory);
    }
    // D:3633-3634 find_partial_matches (two steps: the Partial category, then search_small_differences)
    if (!Done(PipelineStep::PartialCategory)) {
      StageFindPartialMatchesCategory(S);
      Save(PipelineStep::PartialCategory);
    }
    if (!Done(PipelineStep::SmallDifferences)) {
      StageFindPartialMatchesSmallDifferences(S);
      Save(PipelineStep::SmallDifferences);
    }
    // D:3636 apply_machine_learning: use_trained_model is False (§1.1), a no-op.
    // D:3638-3651: unreliable is False (§1.1), so neither unreliable nor experimental matches run.

    if (!Done(PipelineStep::FinalPass)) {
      int Iteration = 0;                                   // D:3653
      PipelineStep LoopDone = PipelineStep::None;          // the step of iteration `Iteration` already done
      int64_t OldTotal = Cursor.OldTotal;
      if (Resume && IsLoopStep(Resume->Done)) {
        Iteration = Resume->Iteration;
        LoopDone = Resume->Done;
      }
      const auto Pending = [&](PipelineStep Step) { return LoopDone < Step; };
      while (true) {  // D:3654
        Cursor.Iteration = Iteration;
        // oracle_trace.py WrapCleanup: the n-th call at the loop head (D:3655) sets iteration n-1 before
        // its "before:cleanup:3655:<n>" point, so that point already carries k.
        S.SetIteration(Iteration);
        if (Pending(PipelineStep::LoopCleanupTop)) {
          S.Cleanup(CleanupSite::L3655);                                          // D:3655
          OldTotal = static_cast<int64_t>(S.State().TotalMatchedFunctions());     // D:3656
          Cursor.OldTotal = OldTotal;
          Save(PipelineStep::LoopCleanupTop);
        }
        if (Pending(PipelineStep::MatchesDiffing)) {
          LoopStage(S, "find_matches_diffing", Iteration, &StageFindMatchesDiffing);  // D:3660
          Save(PipelineStep::MatchesDiffing);
        }
        if (S.Config().SlowHeuristics && Pending(PipelineStep::RelatedMatches)) {  // D:3662-3664
          LoopStage(S, "find_related_matches", Iteration, &StageFindRelatedMatches);
          Save(PipelineStep::RelatedMatches);
        }
        if (Pending(PipelineStep::RelatedCompilationUnit)) {
          LoopStage(S, "find_related_compilation_unit", Iteration, &StageFindRelatedCompilationUnit);  // D:3666
          Save(PipelineStep::RelatedCompilationUnit);
        }
        if (Pending(PipelineStep::LocallyAffine)) {
          LoopStage(S, "find_locally_affine_functions", Iteration, &StageFindLocallyAffineFunctions);  // D:3669
          Save(PipelineStep::LocallyAffine);
        }
        if (Pending(PipelineStep::LoopCleanupBottom)) {
          S.Cleanup(CleanupSite::L3671);  // D:3671
          Save(PipelineStep::LoopCleanupBottom);
        }
        LoopDone = PipelineStep::None;
        const auto NewTotal = static_cast<int64_t>(S.State().TotalMatchedFunctions());  // D:3672
        if (NewTotal <= OldTotal) {                                                      // D:3673-3674
          break;
        }
        ++Iteration;  // D:3675
      }
    }
  }

  // The snapshot "iteration" is the outer-loop k only from the loop's first cleanup (D:3655) through
  // its last (D:3671); from before:final_pass on it is null again (tools/parity/README.md "iteration";
  // oracle_trace.py WrapStage sets Iteration = None when final_pass is entered).
  S.SetIteration(std::nullopt);
  Cursor.Iteration = 0;
  if (!Done(PipelineStep::FinalPass)) {
    S.Point("before:final_pass");  // D:3677
    {
      ContextScope Scope(S, "final_pass");
      StageFinalPass(S);
    }
    S.Point("after:final_pass");
    Save(PipelineStep::FinalPass);
  }

  if (!Done(PipelineStep::FindUnmatched)) {
    {
      ContextScope Scope(S, "find_unmatched");  // D:3680-3681
      StageFindUnmatched(S);
    }
    S.Point("after:find_unmatched");
    Save(PipelineStep::FindUnmatched);
  }
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
  S.Engine().Prepare();

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
    ContextScope Scope(S, "run_heuristics_for_category:" + Parts[1]);  // the oracle's main-thread ctx
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
    // No ctx label: cleanup_matches is not a ctx in the oracle (it emits only cleanup/point events).
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
  // D:3753-3755: f"{path1}_vs_{path2}.diaphora", relative to the current directory
  return PathStem(Db1) + "_vs_" + PathStem(Db2) + ".diaphora";
}

std::string SqliteMismatchWarning(std::string_view Version) {
  return "WARNING: SQLite " + std::string(Version) + " is not the oracle's " +
         std::string(DiffDatabase::kOracleSqliteVersion) +
         "; SQL row order may differ from Diaphora's, so results compare at level L1 only "
         "(use --strict-sqlite to refuse)";
}

namespace {

// One path RunDiff reads or writes, with the role its message names.
struct RolePath {
  std::string Role;
  std::string Path;
};

// A SQLite database and the sidecar files SQLite may create, read or delete beside it.
void AddDatabaseFiles(std::vector<RolePath>& Out, const std::string& Role, const std::string& Path) {
  if (Path.empty()) {
    return;
  }
  Out.push_back({Role, Path});
  for (const char* Suffix : {"-wal", "-shm", "-journal"}) {
    Out.push_back({Role + "'s " + Suffix + " file", Path + Suffix});
  }
}

std::string SnapshotIndexPath(const std::string& Dir) {
  return Detail::PathToUtf8(Detail::PathFromUtf8(Dir) / "index.json");
}

std::string SnapshotFilesDir(const std::string& Dir) {
  return Detail::PathToUtf8(Detail::PathFromUtf8(Dir) / "snapshots");
}

// Audit F01: every path diff writes or deletes, checked against every input BEFORE any file is opened,
// so an alias is refused with exit 2 and nothing is touched. Inputs are db1, db2 and their -wal / -shm
// / -journal files (SQLite reads a WAL and rolls back a hot journal), and the --replay snapshot. Written
// are the output (-o, or --snapshot-out when replaying) with its SQLite sidecars and the writer's
// temporary files, --trace, and <snapshot-dir>/index.json(.tmp); nothing may lie inside
// <snapshot-dir>/snapshots, where snapshot-named files are deleted. Paths are compared by identity
// (SameFilePath: hard links, 8.3 names, UNC shares, case), not by spelling. The write targets must not
// alias each other either (--trace onto -o would interleave a JSONL trace with the results database).
void RefusePathAliases(const DiffArgs& Args, const std::string& Out, bool Replay) {
  std::vector<RolePath> Inputs;
  AddDatabaseFiles(Inputs, "db1", Args.Db1);
  AddDatabaseFiles(Inputs, "db2", Args.Db2);
  if (Replay) {
    Inputs.push_back({"the --replay snapshot", Args.ReplayPath});
  }

  std::vector<RolePath> OutFiles;
  if (Replay) {
    OutFiles.push_back({"--snapshot-out", Out});
    OutFiles.push_back({"--snapshot-out's temporary file", Out + ".tmp"});
  } else {
    AddDatabaseFiles(OutFiles, "-o", Out);
    for (const std::string& Scratch : ResultsWriterScratchPaths(Out)) {
      OutFiles.push_back({"-o's temporary file", Scratch});
    }
  }
  std::vector<RolePath> HarnessFiles;
  if (!Args.TracePath.empty()) {
    HarnessFiles.push_back({"--trace", Args.TracePath});
  }
  if (!Args.SnapshotDir.empty()) {
    const std::string Index = SnapshotIndexPath(Args.SnapshotDir);
    HarnessFiles.push_back({"--snapshot-dir's index.json", Index});
    HarnessFiles.push_back({"--snapshot-dir's index.json.tmp", Index + ".tmp"});
  }

  const auto Refuse = [](const RolePath& Written, const RolePath& Other, const char* What) {
    throw UsageRefused(Written.Role + " '" + Written.Path + "' is " + Other.Role + " '" + Other.Path + "'; " + What +
                       " (nothing was changed)");
  };
  for (const std::vector<RolePath>* Group : {&OutFiles, &HarnessFiles}) {
    for (const RolePath& Written : *Group) {
      for (const RolePath& Input : Inputs) {
        if (Detail::SameFilePath(Written.Path, Input.Path)) {
          Refuse(Written, Input, "refusing to overwrite an input");
        }
      }
    }
  }
  for (const RolePath& Harness : HarnessFiles) {
    for (const RolePath& Output : OutFiles) {
      if (Detail::SameFilePath(Harness.Path, Output.Path)) {
        Refuse(Harness, Output, "the two outputs must be different files");
      }
    }
  }
  if (HarnessFiles.size() > 2 && !Args.TracePath.empty()) {
    for (size_t Index = 1; Index < HarnessFiles.size(); ++Index) {
      if (Detail::SameFilePath(HarnessFiles[0].Path, HarnessFiles[Index].Path)) {
        Refuse(HarnessFiles[0], HarnessFiles[Index], "the two outputs must be different files");
      }
    }
  }
  if (!Args.SnapshotDir.empty()) {
    const std::string Files = SnapshotFilesDir(Args.SnapshotDir);
    std::vector<RolePath> Checked = Inputs;
    Checked.insert(Checked.end(), OutFiles.begin(), OutFiles.end());
    if (!Args.TracePath.empty()) {
      Checked.push_back(HarnessFiles[0]);
    }
    for (const RolePath& Path : Checked) {
      if (Detail::PathIsInside(Path.Path, Files) || Detail::SameFilePath(Path.Path, Files)) {
        throw UsageRefused(Path.Role + " '" + Path.Path + "' lies inside the snapshot directory '" + Files +
                           "', whose snapshot files are replaced by every run (nothing was changed)");
      }
    }
  }
}

// Audit F25: the output's directory must exist and the output must not be a directory, checked before
// the inputs are opened (the writer would only find out after the whole diff). Neither the directory
// nor the output is created or deleted here, so Diaphora's replace-the-output behaviour is unchanged.
void RequireOutputLocation(const std::string& Out, const char* Role) {
  if (Out == ":memory:") {
    return;
  }
  const fs::path Path = Detail::PathFromUtf8(Out);
  std::error_code Error;
  if (fs::is_directory(Path, Error)) {
    throw IoFailure(std::string(Role) + " '" + Out + "' is a directory");
  }
  const fs::path Parent = Path.parent_path().empty() ? fs::path(".") : Path.parent_path();
  Error.clear();
  if (!fs::is_directory(Parent, Error)) {
    throw IoFailure(std::string(Role) + " directory '" + Detail::PathToUtf8(Parent) + "' does not exist");
  }
}

// A checkpoint directory's own files (manifest.json, state-NNNNNN.json and their .tmp files) are created,
// replaced and deleted by every checkpoint, so no input and no other output may be one of them. Other
// files in that directory are never touched (an -o beside the checkpoint is fine).
void RefuseCheckpointAliases(const DiffArgs& Args, const std::string& Out, const std::string& Dir) {
  std::vector<RolePath> Paths;
  AddDatabaseFiles(Paths, "db1", Args.Db1);
  AddDatabaseFiles(Paths, "db2", Args.Db2);
  AddDatabaseFiles(Paths, "-o", Out);
  for (const std::string& Scratch : ResultsWriterScratchPaths(Out)) {
    Paths.push_back({"-o's temporary file", Scratch});
  }
  if (!Args.TracePath.empty()) {
    Paths.push_back({"--trace", Args.TracePath});
  }
  if (!Args.SnapshotDir.empty()) {
    Paths.push_back({"--snapshot-dir's index.json", SnapshotIndexPath(Args.SnapshotDir)});
  }
  for (const RolePath& Path : Paths) {
    const fs::path Native = Detail::PathFromUtf8(Path.Path);
    const fs::path Parent = Native.parent_path().empty() ? fs::path(".") : Native.parent_path();
    if (CheckpointStore::IsStoreFileName(Detail::PathToUtf8(Native.filename())) &&
        Detail::SameFilePath(Detail::PathToUtf8(Parent), Dir)) {
      throw UsageRefused(Path.Role + " '" + Path.Path + "' is a file of the checkpoint directory '" + Dir +
                         "', which every checkpoint replaces (nothing was changed)");
    }
  }
}

// "find_related_compilation_unit:1" for a loop step, "final_pass" otherwise.
std::string CursorLabel(const PipelineCursor& Cursor) {
  std::string Label(PipelineStepName(Cursor.Done));
  if (IsLoopStep(Cursor.Done)) {
    Label += ":" + std::to_string(Cursor.Iteration);
  }
  return Label;
}

// FinishHarness on an error path: the error being handled is the one to report, so a second failure
// while writing index.json or closing the trace is dropped here.
void FinishHarnessQuietly(DiffSession& S) noexcept {
  try {
    S.FinishHarness();
  } catch (...) {
    // keep the original error
  }
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
      // Design decision (lane R0 (c)): --quiet silences only Diaphora's summary lines, never
      // this warning; --allow-sqlite-mismatch is the explicit way to acknowledge it.
      if (!Args.AllowSqliteMismatch) {
        std::fprintf(stderr, "%s\n", SqliteMismatchWarning(Outcome.SqliteVersion).c_str());
        std::fflush(stderr);
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

    // --checkpoint-dir / --resume (Checkpoint.h): the command-line combinations first.
    const bool Resuming = !Args.ResumeDir.empty();
    const std::string CheckpointDir = Resuming ? Args.ResumeDir : Args.CheckpointDir;
    if (!CheckpointDir.empty()) {
      std::string Refusal;
      if (Replay) {
        Refusal = "--checkpoint-dir and --resume do not apply to --replay";
      } else if (Resuming && !Args.CheckpointDir.empty() && Args.CheckpointDir != Args.ResumeDir &&
                 !Detail::SameFilePath(Args.CheckpointDir, Args.ResumeDir)) {
        Refusal = "--checkpoint-dir and --resume name different directories (--resume keeps checkpointing into "
                  "its own directory)";
      } else if (Resuming && (!Args.TracePath.empty() || !Args.SnapshotDir.empty())) {
        Refusal = "--resume cannot be combined with --trace or --snapshot-dir (a resumed run would record only "
                  "the stages after the checkpoint)";
      }
      if (!Refusal.empty()) {
        Outcome.Status = DiffStatus::Usage;
        Outcome.Message = Refusal;
        return Outcome;
      }
    }

    // Every check on the paths runs before any file is opened or written (audit F01, F25, F29).
    RefusePathAliases(Args, Out, Replay);  // plan §2.1: an output that aliases an input is refused
    if (!CheckpointDir.empty()) {
      RefuseCheckpointAliases(Args, Out, CheckpointDir);
      RefuseOracleCapture(Detail::PathFromUtf8(CheckpointDir), CheckpointDir);
    }
    RefuseOracleCapture(Detail::PathFromUtf8(Out).parent_path(), Out);
    if (!Args.TracePath.empty()) {
      RefuseOracleCapture(Detail::PathFromUtf8(Args.TracePath).parent_path(), Args.TracePath);
    }
    if (!Args.SnapshotDir.empty()) {
      RefuseForeignSnapshotDir(Args.SnapshotDir);
    }
    RequireOutputLocation(Out, Replay ? "--snapshot-out" : "output");

    // The checkpoint directory: --resume reads its checkpoint (exit 4 when there is none or it is
    // damaged); both check that it can be written (exit 6); a fresh run refuses a directory that already
    // holds a checkpoint (exit 2), so an earlier run's progress is never replaced by mistake.
    std::optional<CheckpointStore> Store;
    std::optional<EngineCheckpoint> Loaded;
    CheckpointBinding Binding;
    if (!CheckpointDir.empty()) {
      Store.emplace(CheckpointDir);
      if (Resuming) {
        Loaded = Store->Load();
        (void)Store->Prepare();
      } else {
        if (Store->HasManifest()) {
          bool Ours = false;
          try {
            (void)ParseCheckpointManifest(Detail::ReadFileBytes(Store->ManifestPath()));
            Ours = true;
          } catch (const std::exception&) {
            Ours = false;  // unreadable or not a checkpoint manifest: somebody else's file
          }
          if (Ours) {
            throw UsageRefused("the checkpoint directory '" + CheckpointDir +
                               "' already holds a checkpoint of an earlier run; continue it with --resume '" +
                               CheckpointDir + "', or remove its manifest.json and state-*.json files to start "
                               "again (nothing was changed)");
          }
          throw UsageRefused("the checkpoint directory '" + CheckpointDir +
                             "' holds a manifest.json that is not a dsigmatcher checkpoint, and --checkpoint-dir "
                             "replaces that file; use an empty or new directory (nothing was changed)");
        }
        (void)Store->Prepare();
      }
      Binding.ToolVersion = DSIG_VERSION;
      Binding.SqliteVersion = Outcome.SqliteVersion;
      BindInput(Args.Db1, Binding.Db1Sha256, Binding.Db1Size, Binding.Db1WalSha256);
      BindInput(Args.Db2, Binding.Db2Sha256, Binding.Db2Size, Binding.Db2WalSha256);
      Binding.IgnoreSmallFunctions = Args.Config.IgnoreSmallFunctions;
      Binding.RelatedCuSource = Args.CuSource == RelatedCuSource::Sql ? "sql" : "native";
      if (Loaded) {
        const std::string Mismatch = DescribeBindingMismatch(Loaded->Binding, Binding);
        if (!Mismatch.empty()) {
          throw UnsupportedInput("--resume: the checkpoint in '" + CheckpointDir +
                                 "' was made for other inputs or options: " + Mismatch +
                                 " (resume with the same inputs and options, or run again without --resume)");
        }
      }
      Outcome.CheckpointDir = CheckpointDir;  // only once the directory was accepted
    }

    DiffSession S(Args.Config);
    S.Log().SetQuiet(Args.Quiet);
    S.SetCuSource(Args.CuSource);
    S.Open(Args.Db1, Args.Db2);
    S.SetPairLabel(Args.PairLabel.empty() ? PathStem(Args.Db1) + "_vs_" + PathStem(Args.Db2) : Args.PairLabel);

    std::optional<StateSnapshot> Before;
    if (Replay) {
      Before = ReadSnapshot(Args.ReplayPath);
      // Audit F28: a snapshot of another pair is refused, not replayed against these inputs.
      if (!Args.PairLabel.empty() && !Before->Pair.empty() && Before->Pair != Args.PairLabel) {
        throw UnsupportedInput("replay: the snapshot is of pair '" + Before->Pair + "', not of --pair '" +
                               Args.PairLabel + "'");
      }
      S.CheckSnapshotMatchesInputs(*Before);
      if (Args.PairLabel.empty() && !Before->Pair.empty()) {
        S.SetPairLabel(Before->Pair);
      }
    }

    // Snapshots first: EnableSnapshots clears stale snapshot files, and the trace may live in the same
    // capture directory (the oracle writes <capture>/trace.jsonl next to index.json).
    if (!Args.SnapshotDir.empty()) {
      S.EnableSnapshots(Args.SnapshotDir, Args.SnapshotPoints, Args.SnapshotCache);
    }
    if (!Args.TracePath.empty()) {
      S.EnableTrace(Args.TracePath, Args.TraceRows);
    }

    if (Replay) {
      StateSnapshot After;
      try {
        After = RunReplay(S, *Before, Args.ReplayStage, Args.ReplayIteration, Args.ReplayHeuristic);
      } catch (...) {
        FinishHarnessQuietly(S);
        throw;
      }
      S.FinishHarness();
      WriteSnapshot(Out, After);  // compact, like every oracle snapshot
      Outcome.OutputWritten = true;
      Outcome.Mode = S.Mode();
      return Outcome;
    }

    PipelineCheckpointing Checkpointing;
    std::string LastCheckpoint;
    if (Store) {
      if (Loaded) {
        RestoreCheckpoint(S, *Loaded);
        Checkpointing.ResumeFrom = Loaded->Cursor;
        Outcome.ResumedAfter = CursorLabel(Loaded->Cursor);
        LastCheckpoint = Outcome.ResumedAfter;
        Loaded.reset();  // the restored state now lives in the session
      }
      Checkpointing.Save = [&](const PipelineCursor& Cursor) {
        // A checkpoint that cannot be written does not end the run: the previous checkpoint stays
        // usable (CheckpointStore::Write), and the run may well finish.
        try {
          EngineCheckpoint Checkpoint = CaptureCheckpoint(S, Cursor);
          Checkpoint.Binding = Binding;
          Store->Write(Checkpoint, Args.Db1, Args.Db2);
          ++Outcome.CheckpointsWritten;
          LastCheckpoint = CursorLabel(Cursor);
        } catch (const IoFailure& Failure) {
          const std::string Warning =
              "WARNING: no checkpoint after " + CursorLabel(Cursor) + ": " + Failure.What + "; the run goes on (" +
              (LastCheckpoint.empty() ? std::string("no checkpoint has been written yet")
                                      : "--resume would continue after " + LastCheckpoint) +
              ")";
          std::fprintf(stderr, "%s\n", Warning.c_str());
          std::fflush(stderr);
          Outcome.Warnings.push_back(Warning);
        }
      };
    }

    try {
      Outcome.DiffReturned = RunPipeline(S, Store ? &Checkpointing : nullptr);
    } catch (...) {
      FinishHarnessQuietly(S);
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
    if (Store) {
      // The results file is complete: the checkpoint is no longer needed.
      try {
        Store->Remove();
      } catch (const IoFailure& Failure) {
        const std::string Warning =
            "WARNING: the results were written, but the checkpoint could not be removed: " + Failure.What;
        std::fprintf(stderr, "%s\n", Warning.c_str());
        std::fflush(stderr);
        Outcome.Warnings.push_back(Warning);
      }
    }
    Outcome.Mode = S.Mode();
    Outcome.Best = S.Final().Best.size();
    Outcome.Partial = S.Final().Partial.size();
    Outcome.Unreliable = S.Final().Unreliable.size();
    Outcome.Multimatch = S.Final().Multimatch.size();
    if (!Outcome.DiffReturned) {
      // Audit F06 (a product decision over plan §2.1 / §3.10): the file is Diaphora's empty results
      // file, byte for byte, but the process says that db2 was not a usable export, so a caller that
      // goes by the exit code never takes an empty result for "nothing matched".
      Outcome.Status = DiffStatus::Unsupported;
      Outcome.Message = "db2 '" + Args.Db2 +
                        "' is not a usable Diaphora export (diff.version is missing or empty); Diaphora's "
                        "empty results file was written to '" + Out + "' and holds no matches";
    }
  } catch (const UsageRefused& Error) {
    Outcome.Status = DiffStatus::Usage;
    Outcome.Message = Error.What;
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
  } catch (const std::bad_alloc&) {
    Outcome.Status = DiffStatus::Io;
    Outcome.Message = "out of memory";
  } catch (const std::exception& Error) {
    Outcome.Status = DiffStatus::Internal;
    Outcome.Message = std::string("internal error: ") + Error.what();
  }
  return Outcome;
}

}
