// diff_tiers (lane L6): the SQL heuristic tiers and search_small_differences.
//
//   * unit tests: the run_heuristics_for_category list build (flags, categories, the build-time
//     all_functions_matched break), reverse execution order, dispatch by ratio type and chooser pair,
//     per-heuristic truncation, search_small_differences (names-ratio gate, has_better_match before
//     check_match, no lower bound, raises) and result_iter's fetchmany(1000) batching;
//   * the data-touched descriptor of all 50 heuristics, checked against SQLite's own authorizer;
//   * fixture tests (tests/diff/fixtures/tiers/**, recorded from real Diaphora by
//     fixtures/tiers/gen_tiers_fixtures.py): 02 probe 3 / 01 E1 (reverse order labels every pair
//     `Equal assembly`; forward order gives `Same order and hash`), 02 probe 5 (the UNION tie) and
//     the different-CPU list (5 Best / 26 Partial);
//   * corpus replays on the oracle captures (plan §4 L6 "Acceptance on the oracle"): every
//     before:heuristic:<id> -> StageRunSingleHeuristic -> after:heuristic:<id> (S-L2 and the trace
//     events), the category replays, before:search_small_differences -> S-L2, and one chained run
//     from after:find_same_name through after:search_small_differences compared event by event.
// Corpus tests skip without DSIG_CORPUS_ROOT; row-order checks need SQLite 3.51.1 (plan §2.6).

#include <sqlite3.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <optional>
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "../../src/diff/FileIo.h"
#include "../../src/diff/stages/TiersDetail.h"
#include "diff/CorpusPaths.h"
#include "diff/FixtureDb.h"
#include "diff/ResultsCompare.h"
#include "diff/TestHarness.h"
#include "dsigmatcher/diff/Config.h"
#include "dsigmatcher/diff/Consumer.h"
#include "dsigmatcher/diff/Errors.h"
#include "dsigmatcher/diff/Json.h"
#include "dsigmatcher/diff/Pipeline.h"
#include "dsigmatcher/diff/Registry.h"
#include "dsigmatcher/diff/Snapshot.h"
#include "dsigmatcher/diff/StageSql.h"
#include "dsigmatcher/diff/Stages.h"
#include "dsigmatcher/diff/Trace.h"

namespace {

namespace fs = std::filesystem;
using namespace DSig::Diff;

void Run(const char* Name, const std::function<void()>& F) {
  try {
    F();
  } catch (const std::exception& Error) {
    DSig::Test::Report(false, (std::string(Name) + " threw: " + Error.what()).c_str(), __FILE__, __LINE__);
  }
}

bool CheckReplay(const std::string& What, const StateSnapshot& Oracle, const StateSnapshot& Native) {
  const DSig::Test::CompareReport Report = DSig::Test::CompareSnapshots(Oracle, Native, 10);
  DSig::Test::Report(Report.L2Equal, What.c_str(), __FILE__, __LINE__);
  if (!Report.L2Equal) {
    for (const std::string& Line : Report.Differences) {
      DSig::Test::Note("    " + Line);
    }
  }
  return Report.L2Equal;
}

std::vector<JsonValue> ReadTraceFile(const std::string& Path) {
  std::vector<JsonValue> Events;
  std::ifstream In(DSig::Test::Utf8ToPath(Path), std::ios::binary);
  std::string Line;
  while (std::getline(In, Line)) {
    if (!Line.empty()) {
      Events.push_back(JsonParse(Line));
    }
  }
  return Events;
}

// A trace sink on a scratch file for the duration of one replay.
class TraceCapture {
public:
  TraceCapture(DiffSession& Session, std::string Path, bool Rows) : S_(Session), Path_(std::move(Path)) {
    S_.EnableTrace(Path_, Rows);
  }
  std::vector<JsonValue> Finish() {
    S_.Tracer().Close();
    return ReadTraceFile(Path_);
  }

private:
  DiffSession& S_;
  std::string Path_;
};

// add_match "seq" counts the whole run; comparisons use the ordinal relative to the segment's first.
std::string NormaliseEvents(const std::vector<JsonValue>& Events) {
  std::string Out;
  std::optional<int64_t> First;
  for (const JsonValue& Event : Events) {
    JsonValue Copy = Event;
    if (const JsonValue* Seq = Copy.Find("seq")) {
      const int64_t Value = Seq->AsInt64();
      if (!First) {
        First = Value;
      }
      Copy.Set("seq", JsonValue::Int(Value - *First));
    }
    Out += JsonWrite(Copy);
    Out += '\n';
  }
  return Out;
}

// First differing line of two event dumps, with a little context, for the failure note.
std::string FirstDifference(const std::string& A, const std::string& B) {
  std::istringstream InA(A);
  std::istringstream InB(B);
  std::string LineA;
  std::string LineB;
  size_t Index = 0;
  while (true) {
    const bool HasA = static_cast<bool>(std::getline(InA, LineA));
    const bool HasB = static_cast<bool>(std::getline(InB, LineB));
    if (!HasA && !HasB) {
      return "equal";
    }
    if (!HasA || !HasB || LineA != LineB) {
      return "event " + std::to_string(Index) + ":\n      oracle: " + (HasA ? LineA.substr(0, 400) : "<end>") +
             "\n      native: " + (HasB ? LineB.substr(0, 400) : "<end>");
    }
    ++Index;
  }
}

bool CheckEvents(const std::string& What, const std::vector<JsonValue>& Oracle, const std::vector<JsonValue>& Native) {
  const std::string A = NormaliseEvents(Oracle);
  const std::string B = NormaliseEvents(Native);
  const bool Equal = A == B;
  DSig::Test::Report(Equal, What.c_str(), __FILE__, __LINE__);
  if (!Equal) {
    DSig::Test::Note("    " + FirstDifference(A, B));
  }
  return Equal;
}

// ---------------------------------------------------------------------------------------------
// Corpus replays (plan §4 L6 "Acceptance on the oracle")

// The export ids of a pair name "<ref>_vs_<target>", where the target may omit the ref's library
// prefix ("userenv-9168-pdb_vs_9278-nopdb" -> userenv-9278-nopdb).
std::optional<std::pair<std::string, std::string>> ExportIdsOfPair(const std::string& Pair) {
  const size_t Vs = Pair.find("_vs_");
  if (Vs == std::string::npos) {
    return std::nullopt;
  }
  const std::string Ref = Pair.substr(0, Vs);
  const std::string Tail = Pair.substr(Vs + 4);
  if (!DSig::Test::ExportAvailable(Ref)) {
    return std::nullopt;
  }
  if (DSig::Test::ExportAvailable(Tail)) {
    return std::make_pair(Ref, Tail);
  }
  const size_t Dash = Ref.find('-');
  if (Dash != std::string::npos && DSig::Test::ExportAvailable(Ref.substr(0, Dash + 1) + Tail)) {
    return std::make_pair(Ref, Ref.substr(0, Dash + 1) + Tail);
  }
  return std::nullopt;
}

struct SnapshotFile {
  int64_t Seq = 0;
  std::string Path;
};

// snapshots/NNNNN_<sanitised point>.json by sanitised point. The oracle writes <name>.tmp and renames
// it (snapshot.py WriteJsonAtomic), so a listed .json file is complete and never rewritten.
std::map<std::string, SnapshotFile> ListSnapshots(const fs::path& Dir) {
  static const std::regex Pattern("^([0-9]{5,})_(.+)\\.json$");
  std::map<std::string, SnapshotFile> Out;
  std::error_code Error;
  for (const fs::directory_entry& Entry : fs::directory_iterator(Dir, Error)) {
    const std::string Name = DSig::Test::PathToUtf8(Entry.path().filename());
    std::smatch Match;
    if (std::regex_match(Name, Match, Pattern)) {
      Out.try_emplace(Match[2].str(), SnapshotFile{std::stoll(Match[1].str()), DSig::Test::PathToUtf8(Entry.path())});
    }
  }
  return Out;
}

// The oracle trace from the point `From` (exclusive) to the point `To` (inclusive), streamed so a
// long capture's trace (up to GBs) is only read that far. Empty when `From` never appears.
std::vector<JsonValue> ReadTraceBetween(const std::string& TracePath, const std::string& From, const std::string& To,
                                        bool& HasRows) {
  std::vector<JsonValue> Out;
  HasRows = false;
  std::ifstream In(DSig::Test::Utf8ToPath(TracePath), std::ios::binary);
  const std::string FromNeedle = "\"name\":" + JsonQuote(From) + ",";
  const std::string ToNeedle = "\"name\":" + JsonQuote(To) + ",";
  std::string Line;
  bool Open = false;
  while (std::getline(In, Line)) {
    const bool IsPoint = Line.find("\"ev\":\"point\"") != std::string::npos;
    if (!Open) {
      if (IsPoint && Line.find(FromNeedle) != std::string::npos) {
        Open = true;
      }
      continue;
    }
    JsonValue Event = JsonParse(Line);
    if (Event.At("ev").AsString() == "row") {
      HasRows = true;
    }
    Out.push_back(std::move(Event));
    if (IsPoint && Line.find(ToNeedle) != std::string::npos) {
      break;
    }
  }
  return Out;
}

// The row and add_match events of one ctx, in order (the per-heuristic segment of the oracle trace).
std::vector<JsonValue> EventsOfCtx(const std::vector<JsonValue>& Events, const std::string& Ctx) {
  std::vector<JsonValue> Out;
  for (const JsonValue& Event : Events) {
    const std::string& Kind = Event.At("ev").AsString();
    if ((Kind == "row" || Kind == "add_match") && Event.At("ctx").IsString() && Event.At("ctx").AsString() == Ctx) {
      Out.push_back(Event);
    }
  }
  return Out;
}

struct PairCounts {
  int HeuristicsRun = 0;
  int HeuristicsPassed = 0;
  int EventsRun = 0;
  int EventsPassed = 0;
  int CategoryRun = 0;
  int CategoryPassed = 0;
  int SmallRun = 0;
  int SmallPassed = 0;
  int ChainRun = 0;
  int ChainPassed = 0;
  std::vector<std::pair<int, bool>> PerHeuristic;  // (id, S-L2 and events passed), execution order
  std::vector<std::string> Slow;                   // heuristic replays over the Timings threshold
  double Seconds = 0.0;
};

// A replay from an oracle snapshot in a session that is reused for the pair: a snapshot without
// ratios_cache must start from an empty cache (Restore only replaces the cache when one is present).
StateSnapshot Replay(DiffSession& S, const StateSnapshot& Before, const std::string& Stage) {
  if (!Before.RatiosCache) {
    S.Engine().ClearCache();
  }
  return RunReplay(S, Before, Stage);
}

// Every L6 replay of one capture (an oracle capture of a corpus pair or a fixture capture):
//   (1) each before:heuristic:<id> -> RunReplay("heuristic:<id>") -> after:heuristic:<id> (S-L2) plus
//       the heuristic's row / add_match trace events against the oracle's (ctx "heuristic:<id>");
//   (2) after:find_same_name -> run_heuristics_for_category:Best and
//       after:run_heuristics_for_category:Best -> run_heuristics_for_category:Partial (S-L2);
//   (3) before:search_small_differences -> after:search_small_differences (S-L2 and trace events);
//   (4) a chained run from after:find_same_name through after:search_small_differences, driven the way
//       RunPipeline drives it, compared event by event and at every snapshot point on the way.
// `Timings` lists the heuristics whose replay took at least that many seconds.
PairCounts ReplayCapture(const std::string& Label, const std::string& Pair, const std::string& MainDb,
                         const std::string& DiffDb, const fs::path& Dir, const std::string& Scratch,
                         double Timings = -1.0) {
  PairCounts Counts;
  const auto Started = std::chrono::steady_clock::now();
  const std::map<std::string, SnapshotFile> Files = ListSnapshots(Dir / "snapshots");
  const auto Find = [&](const std::string& Point) -> const SnapshotFile* {
    const auto It = Files.find(SanitisePointName(Point));
    return It == Files.end() ? nullptr : &It->second;
  };
  if (Find("after:find_same_name") == nullptr || Find("after:run_heuristics_for_category:Best") == nullptr) {
    DSig::Test::Note(Label + ": no heuristic tiers in this capture (mode S or P)");
    return Counts;
  }
  const std::string TracePath = DSig::Test::PathToUtf8(Dir / "trace.jsonl");
  bool HasRows = false;
  const std::vector<JsonValue> OracleEvents =
      ReadTraceBetween(TracePath, "after:find_same_name", "after:search_small_differences", HasRows);
  const std::string NativeTrace = DSig::Test::PathToUtf8(DSig::Test::Utf8ToPath(Scratch) / (Label + ".trace.jsonl"));

  DiffSession S;
  S.Log().SetQuiet(true);
  S.Open(MainDb, DiffDb);
  S.SetPairLabel(Pair);

  // (1) every heuristic: before:heuristic:<id> -> StageRunSingleHeuristic -> after:heuristic:<id>
  std::vector<std::pair<int64_t, int>> Heuristics;
  static const std::regex HeurPattern("^before_heuristic_([0-9]+)$");
  for (const auto& [Name, File] : Files) {
    std::smatch Match;
    if (std::regex_match(Name, Match, HeurPattern)) {
      Heuristics.emplace_back(File.Seq, std::stoi(Match[1].str()));
    }
  }
  std::sort(Heuristics.begin(), Heuristics.end());
  for (const auto& [Seq, Id] : Heuristics) {
    const std::string Point = "heuristic:" + std::to_string(Id);
    const SnapshotFile* BeforeFile = Find("before:" + Point);
    const SnapshotFile* AfterFile = Find("after:" + Point);
    if (AfterFile == nullptr) {
      continue;
    }
    ++Counts.HeuristicsRun;
    const StateSnapshot Before = ReadSnapshot(BeforeFile->Path);
    CHECK_TEXT_EQ(Before.Point, "before:" + Point);
    StateSnapshot Native;
    std::vector<JsonValue> NativeEvents;
    const auto HeuristicStarted = std::chrono::steady_clock::now();
    {
      TraceCapture Capture(S, NativeTrace, HasRows);
      Native = Replay(S, Before, Point);
      NativeEvents = Capture.Finish();
    }
    const double HeuristicSeconds =
        std::chrono::duration<double>(std::chrono::steady_clock::now() - HeuristicStarted).count();
    if (Timings >= 0.0 && HeuristicSeconds >= Timings) {
      char Text[64];
      std::snprintf(Text, sizeof(Text), "%.1f s", HeuristicSeconds);
      Counts.Slow.push_back(Point + " " + Text);
    }
    const bool StateOk = CheckReplay(Label + " " + Point + " (S-L2)", ReadSnapshot(AfterFile->Path), Native);
    bool EventsOk = true;
    if (!OracleEvents.empty()) {
      ++Counts.EventsRun;
      EventsOk = CheckEvents(Label + " " + Point + " trace events", EventsOfCtx(OracleEvents, Point),
                             EventsOfCtx(NativeEvents, Point));
      Counts.EventsPassed += EventsOk ? 1 : 0;
    }
    Counts.HeuristicsPassed += StateOk ? 1 : 0;
    Counts.PerHeuristic.emplace_back(Id, StateOk && EventsOk);
  }

  // (2) the categories, each from the oracle's state before it
  const std::pair<const char*, const char*> Categories[] = {
      {"after:find_same_name", "run_heuristics_for_category:Best"},
      {"after:run_heuristics_for_category:Best", "run_heuristics_for_category:Partial"}};
  for (const auto& [From, Stage] : Categories) {
    const SnapshotFile* BeforeFile = Find(From);
    const SnapshotFile* AfterFile = Find(std::string("after:") + Stage);
    if (BeforeFile == nullptr || AfterFile == nullptr) {
      continue;
    }
    ++Counts.CategoryRun;
    const StateSnapshot Native = Replay(S, ReadSnapshot(BeforeFile->Path), Stage);
    Counts.CategoryPassed += CheckReplay(Label + " " + From + " -> " + Stage + " (S-L2)",
                                         ReadSnapshot(AfterFile->Path), Native)
                                 ? 1
                                 : 0;
  }

  // (3) before:search_small_differences -> after:search_small_differences
  if (const SnapshotFile* BeforeFile = Find("before:search_small_differences")) {
    if (const SnapshotFile* AfterFile = Find("after:search_small_differences")) {
      ++Counts.SmallRun;
      StateSnapshot Native;
      std::vector<JsonValue> NativeEvents;
      {
        TraceCapture Capture(S, NativeTrace, HasRows);
        Native = Replay(S, ReadSnapshot(BeforeFile->Path), "search_small_differences");
        NativeEvents = Capture.Finish();
      }
      bool Ok = CheckReplay(Label + " search_small_differences (S-L2)", ReadSnapshot(AfterFile->Path), Native);
      if (!OracleEvents.empty()) {
        Ok = CheckEvents(Label + " search_small_differences trace events",
                         EventsOfCtx(OracleEvents, "search_small_differences"),
                         EventsOfCtx(NativeEvents, "search_small_differences")) &&
             Ok;
      }
      Counts.SmallPassed += Ok ? 1 : 0;
    }
  }

  // (4) one chained run in a fresh session, the way RunPipeline drives it: after:find_same_name ->
  // Best category -> find_partial_matches (Partial category, then search_small_differences). Every
  // snapshot point on the way and the whole trace (points, cleanups, rows, add_match) must equal the
  // oracle's.
  if (const SnapshotFile* StartFile = Find("after:find_same_name"); StartFile != nullptr && !OracleEvents.empty()) {
    ++Counts.ChainRun;
    DiffSession Chain;
    Chain.Log().SetQuiet(true);
    Chain.Open(MainDb, DiffDb);
    Chain.SetPairLabel(Pair);
    const std::string ChainDir = DSig::Test::PathToUtf8(DSig::Test::Utf8ToPath(Scratch) / (Label + ".chain"));
    Chain.EnableSnapshots(ChainDir, "after:run_heuristics_for_category:*|after:search_small_differences|after:heuristic:*");
    Chain.Restore(ReadSnapshot(StartFile->Path));
    Chain.Engine().Prepare();
    std::vector<JsonValue> NativeEvents;
    {
      TraceCapture Capture(Chain, NativeTrace, HasRows);
      {
        ContextScope Root(Chain, "diff");
        {
          ContextScope Scope(Chain, "run_heuristics_for_category:Best");  // as RunPipeline does (D:3630)
          StageRunHeuristicsForCategory(Chain, HeurCategory::Best);
        }
        StageFindPartialMatches(Chain);  // D:3634
      }
      NativeEvents = Capture.Finish();
    }
    Chain.FinishHarness();
    bool Ok = CheckEvents(Label + " chained after:find_same_name -> after:search_small_differences trace", OracleEvents,
                          NativeEvents);
    int Points = 0;
    for (const auto& [Name, File] : ListSnapshots(DSig::Test::Utf8ToPath(ChainDir) / "snapshots")) {
      const auto Oracle = Files.find(Name);
      if (Oracle == Files.end()) {
        Ok = false;
        DSig::Test::Report(false, (Label + " chained: point " + Name + " not in the oracle capture").c_str(), __FILE__,
                           __LINE__);
        continue;
      }
      ++Points;
      Ok = CheckReplay(Label + " chained " + Name + " (S-L2)", ReadSnapshot(Oracle->second.Path),
                       ReadSnapshot(File.Path)) &&
           Ok;
    }
    CHECK(Points > 0);
    Counts.ChainPassed += Ok && Points > 0 ? 1 : 0;
  }
  Counts.Seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - Started).count();
  return Counts;
}

// The sechost captures take about 11 minutes (the constants joins of HEURISTICS 15, 20 and 21 run three
// times: alone, per category and chained), so they run only with DSIG_PARITY=long (the diff_parity
// convention, plan §2.6) or when DSIG_TIERS_PAIRS names them. userenv's take about 20 s.
bool LongCapture(const std::string& Pair) { return Pair.rfind("sechost-", 0) == 0; }

std::string Summary(const std::string& Name, const PairCounts& C) {
  char Seconds[32];
  std::snprintf(Seconds, sizeof(Seconds), "%.1f", C.Seconds);
  return Name + ": heuristics " + std::to_string(C.HeuristicsPassed) + "/" + std::to_string(C.HeuristicsRun) +
         " S-L2, trace events " + std::to_string(C.EventsPassed) + "/" + std::to_string(C.EventsRun) +
         ", categories " + std::to_string(C.CategoryPassed) + "/" + std::to_string(C.CategoryRun) +
         ", search_small_differences " + std::to_string(C.SmallPassed) + "/" + std::to_string(C.SmallRun) +
         ", chained " + std::to_string(C.ChainPassed) + "/" + std::to_string(C.ChainRun) + " (" + Seconds + " s)";
}

void NotePerHeuristic(const PairCounts& C) {
  std::string PerId;
  int IdPassed = 0;
  for (const auto& [Id, Ok] : C.PerHeuristic) {
    PerId += (PerId.empty() ? "" : " ") + std::to_string(Id) + (Ok ? "" : "!FAIL");
    IdPassed += Ok ? 1 : 0;
  }
  DSig::Test::Note("  per heuristic id, execution order (" + std::to_string(IdPassed) + "/" +
                   std::to_string(C.PerHeuristic.size()) + " passed): " + PerId);
  if (!C.Slow.empty()) {
    std::string Slow;
    for (const std::string& Item : C.Slow) {
      Slow += (Slow.empty() ? "" : ", ") + Item;
    }
    DSig::Test::Note("  slowest heuristic replays: " + Slow);
  }
}

void TestCorpusReplays(const std::string& Scratch) {
  DSig::Test::Suite("corpus replays (S-L2): heuristics, categories, search_small_differences, chained trace");
  if (!DSig::Test::CorpusRoot()) {
    DSig::Test::Skip("corpus replays", "DSIG_CORPUS_ROOT is not set");
    return;
  }
  if (!DSig::Test::OracleSqlite()) {
    // Path A row order is the oracle's only under SQLite 3.51.1 (plan §2.6, §5 R1).
    DSig::Test::Skip("corpus replays", "SQLite " + DiffDatabase::LibVersion() + " is not the oracle's 3.51.1");
    return;
  }
  const fs::path Traces = DSig::Test::Utf8ToPath(DSig::Test::OracleDir()) / "traces";
  std::error_code Error;
  if (!fs::is_directory(Traces, Error)) {
    DSig::Test::Skip("corpus replays", "no oracle captures under " + DSig::Test::PathToUtf8(Traces));
    return;
  }
  // DSIG_TIERS_PAIRS=a,b limits the captures (by directory name).
  std::set<std::string> Only;
  if (const auto Env = DSig::Test::GetEnv("DSIG_TIERS_PAIRS"); Env && !Env->empty()) {
    std::stringstream List(*Env);
    std::string Item;
    while (std::getline(List, Item, ',')) {
      Only.insert(Item);
    }
  }
  const auto Parity = DSig::Test::GetEnv("DSIG_PARITY");
  const bool Long = Parity && *Parity == "long";
  std::vector<std::string> Names;
  for (const fs::directory_entry& Entry : fs::directory_iterator(Traces, Error)) {
    const std::string Name = DSig::Test::PathToUtf8(Entry.path().filename());
    if (Entry.is_directory(Error) && !Name.empty() && Name[0] != '_' && (Only.empty() || Only.count(Name) != 0)) {
      Names.push_back(Name);
    }
  }
  std::sort(Names.begin(), Names.end());
  int Captures = 0;
  for (const std::string& Name : Names) {
    const fs::path Dir = Traces / DSig::Test::Utf8ToPath(Name);
    std::string Pair = Name;
    if (const size_t Dot = Name.find('.'); Dot != std::string::npos) {
      // A second capture of a pair (".full", ".prefix2"): used only once it has finished. While it
      // runs, its index.json / run.json are not read at all (a reader can break the writer's
      // os.replace); the finished marker is the removed work/ copy (tools/parity/README.md
      // "oracle_trace.py run" step 5), after which run.json is read through the shared-delete reader.
      Pair = Name.substr(0, Dot);
      bool Finished = !fs::exists(Dir / "work", Error);
      if (Finished) {
        try {
          const JsonValue RunInfo = JsonParse(Detail::ReadFileBytes(DSig::Test::PathToUtf8(Dir / "run.json")));
          const std::string& Status = RunInfo.At("status").AsString();
          Finished = Status == "complete" || Status == "stopped";
        } catch (const std::exception&) {
          Finished = false;
        }
      }
      if (!Finished) {
        DSig::Test::Note(Name + ": skipped (capture not finished; its run.json / index.json were not read)");
        continue;
      }
    }
    if (!fs::is_directory(Dir / "snapshots", Error)) {
      continue;
    }
    if (LongCapture(Pair) && !Long && Only.count(Name) == 0) {
      DSig::Test::Note(Name + ": skipped (long pair; set DSIG_PARITY=long or DSIG_TIERS_PAIRS=" + Name + ")");
      continue;
    }
    const auto Ids = ExportIdsOfPair(Pair);
    if (!Ids) {
      DSig::Test::Note(Name + ": skipped (exports not found)");
      continue;
    }
    ++Captures;
    const PairCounts C = ReplayCapture(Name, Pair, DSig::Test::ExportPath(Ids->first),
                                       DSig::Test::ExportPath(Ids->second), Dir, Scratch, 1.0);
    if (C.HeuristicsRun == 0 && C.CategoryRun == 0 && C.SmallRun == 0) {
      continue;
    }
    DSig::Test::Note(Summary(Name, C));
    NotePerHeuristic(C);
  }
  if (Captures == 0) {
    DSig::Test::Skip("corpus replays", "no capture has snapshots");
  }
}

// ---------------------------------------------------------------------------------------------
// Fixture databases (tests/diff/fixtures/tiers/<scenario>/main.sql, diff.sql; FixtureDb.h)

std::string TiersFixtureDir(const std::string& Scenario) {
  return DSig::Test::PathToUtf8(DSig::Test::Utf8ToPath(DSig::Test::TestDataDir()) / "fixtures" / "tiers" /
                                DSig::Test::Utf8ToPath(Scenario));
}

struct FixturePair {
  std::string Main;
  std::string Diff;
};

// Builds <Scratch>/<Tag>_{main,diff}.sqlite from a scenario's dumps, with extra SQL appended to each
// (after the dump's COMMIT). Reports and returns nullopt on failure.
std::optional<FixturePair> BuildFixture(const std::string& Scratch, const std::string& Scenario, const std::string& Tag,
                                        const std::string& ExtraMain = "", const std::string& ExtraDiff = "") {
  FixturePair Pair;
  const fs::path Work = DSig::Test::Utf8ToPath(Scratch);
  Pair.Main = DSig::Test::PathToUtf8(Work / (Tag + "_main.sqlite"));
  Pair.Diff = DSig::Test::PathToUtf8(Work / (Tag + "_diff.sqlite"));
  const std::tuple<const char*, std::string, std::string> Sides[] = {{"main", Pair.Main, ExtraMain},
                                                                     {"diff", Pair.Diff, ExtraDiff}};
  for (const auto& [Side, Out, Extra] : Sides) {
    std::string Text;
    try {
      Text = Detail::ReadFileBytes(DSig::Test::PathToUtf8(DSig::Test::Utf8ToPath(TiersFixtureDir(Scenario)) /
                                                          (std::string(Side) + ".sql")));
    } catch (const std::exception& Error) {
      DSig::Test::Report(false, (Scenario + ": " + Error.what()).c_str(), __FILE__, __LINE__);
      return std::nullopt;
    }
    const std::string Failure = DSig::Test::BuildFixtureDbFromText(Text + "\n" + Extra + "\n", Out);
    if (!Failure.empty()) {
      DSig::Test::Report(false, (Scenario + " " + Tag + ": " + Failure).c_str(), __FILE__, __LINE__);
      return std::nullopt;
    }
  }
  return Pair;
}

// check_ratio scripted per (ea, ea2) address text (Default for the rest), counting calls, recording
// them in call order and raising at chosen call numbers.
class ScriptedRatio final : public IRatioProvider {
public:
  explicit ScriptedRatio(DiffSession& Session) : S_(Session) {}
  std::map<std::pair<std::string, std::string>, double> Table;
  double Default = 0.1;
  std::set<int> RaiseOnCall;   // 1-based call numbers raising DiaphoraWouldRaise
  std::set<int> RefuseOnCall;  // 1-based call numbers raising UnsupportedInput
  int Calls = 0;
  std::vector<std::pair<std::string, std::string>> Seen;

  double CheckRatio(const HeuristicRow& Row, MdSource) override {
    ++Calls;
    auto Key = std::make_pair(std::string(S_.Ids().AddrKeyText(Row.Ea1)), std::string(S_.Ids().AddrKeyText(Row.Ea2)));
    Seen.push_back(Key);
    if (RaiseOnCall.count(Calls) != 0) {
      throw DiaphoraWouldRaise("scripted", "ValueError: scripted check_ratio failure");
    }
    if (RefuseOnCall.count(Calls) != 0) {
      throw UnsupportedInput("scripted refusal");
    }
    const auto Found = Table.find(Key);
    return Found == Table.end() ? Default : Found->second;
  }
  double CompareFunctionRows(uint32_t, uint32_t) override { throw std::logic_error("CompareFunctionRows is unused"); }
  bool Saw(const std::string& Ea1, const std::string& Ea2) const {
    return std::find(Seen.begin(), Seen.end(), std::make_pair(Ea1, Ea2)) != Seen.end();
  }

private:
  DiffSession& S_;
};

// (ea1, name1, ea2, name2, desc, ratio) of the items of a chooser, sorted (row order is SQLite's).
using ItemKey = std::tuple<std::string, std::string, std::string, std::string, std::string, double>;
std::vector<ItemKey> ItemsOf(const DiffSession& S, Chooser C) {
  std::vector<ItemKey> Out;
  for (const Item& It : S.State().Items(C)) {
    Out.emplace_back(std::string(S.Ids().AddrKeyText(It.Ea1)), std::string(S.Ids().NameKeyText(It.Name1)),
                     std::string(S.Ids().AddrKeyText(It.Ea2)), std::string(S.Ids().NameKeyText(It.Name2)),
                     std::string(S.Ids().DescText(It.Desc)), It.Ratio);
  }
  std::sort(Out.begin(), Out.end());
  return Out;
}

std::string Addr(int64_t Value) { return std::to_string(Value); }
// probe3: func_I at 0x401000 + I * 0x100, sub_XXXXXX at 0x501000 + I * 0x100 (I = 1..6).
std::string P3Main(int I) { return Addr(0x401000 + I * 0x100); }
std::string P3Diff(int I) { return Addr(0x501000 + I * 0x100); }
std::string P3MainName(int I) { return "func_" + std::to_string(I); }
std::string P3DiffName(int I) {
  char Text[32];
  std::snprintf(Text, sizeof(Text), "sub_%X", 0x501000 + I * 0x100);
  return Text;
}

bool ThrowsWouldRaise(const std::function<void()>& F, std::string* Site = nullptr) {
  try {
    F();
  } catch (const DiaphoraWouldRaise& Error) {
    if (Site != nullptr) {
      *Site = Error.Site;
    }
    return true;
  }
  return false;
}

std::vector<int> IdRange(int First, int Last) {
  std::vector<int> Out;
  for (int Id = First; Id <= Last; ++Id) {
    Out.push_back(Id);
  }
  return Out;
}

// ---------------------------------------------------------------------------------------------
// Unit tests: the list build (D:1479-1541)

void TestRunnableLists() {
  DSig::Test::Suite("run_heuristics_for_category list build (D:1479-1541, 01 §5.10, 02 §4.4)");
  const std::vector<int> BestSameCpu = IdRange(0, 11);
  std::vector<int> PartialSameCpu = IdRange(12, 35);
  PartialSameCpu.insert(PartialSameCpu.end(), {39, 40, 41});
  {
    DiffSession S;
    S.Log().SetQuiet(true);
    S.State().SetTotals(100, 100);
    S.Flags().IsSameProcessor = true;
    CHECK(Tiers::RunnableHeuristics(S, HeurCategory::Best) == BestSameCpu);        // 12 run, same CPU
    CHECK(Tiers::RunnableHeuristics(S, HeurCategory::Partial) == PartialSameCpu);  // 27 (36-38 UNRELIABLE)
    CHECK_NUM_EQ(Tiers::RunnableHeuristics(S, HeurCategory::Partial).size(), 27);
    CHECK(Tiers::RunnableHeuristics(S, HeurCategory::Unreliable) == IdRange(42, 49));  // the category filter only
    CHECK(Tiers::RunnableHeuristics(S, HeurCategory::Experimental).empty());         // no entry has it
    CHECK(S.Log().Lines().empty());
  }
  {
    // 02 §4.4 / 07 §10.14: different processors -> 5 Best (4, 7, 8, 10, 11) and 26 Partial (39 out)
    DiffSession S;
    S.State().SetTotals(100, 100);
    S.Flags().IsSameProcessor = false;
    CHECK((Tiers::RunnableHeuristics(S, HeurCategory::Best) == std::vector<int>{4, 7, 8, 10, 11}));
    std::vector<int> Partial = IdRange(12, 35);
    Partial.insert(Partial.end(), {40, 41});
    CHECK(Tiers::RunnableHeuristics(S, HeurCategory::Partial) == Partial);
    CHECK_NUM_EQ(Partial.size(), 26);
  }
  {
    // SLOW off (not a supported parity configuration, but the filter is literal): 14, 21, 41 and the
    // SLOW Unreliable entries 43-48 drop out.
    DiffSession S;
    S.State().SetTotals(100, 100);
    S.Flags().IsSameProcessor = true;
    S.MutableConfig().SlowHeuristics = false;
    std::vector<int> Partial = IdRange(12, 35);
    Partial.erase(std::remove_if(Partial.begin(), Partial.end(), [](int Id) { return Id == 14 || Id == 21; }),
                  Partial.end());
    Partial.insert(Partial.end(), {39, 40});
    CHECK(Tiers::RunnableHeuristics(S, HeurCategory::Partial) == Partial);
    CHECK((Tiers::RunnableHeuristics(S, HeurCategory::Unreliable) == std::vector<int>{42, 49}));
  }
  {
    // UNRELIABLE on: 36-38 join the Partial list (they are SLOW too, and slow is on)
    DiffSession S;
    S.State().SetTotals(100, 100);
    S.Flags().IsSameProcessor = true;
    S.MutableConfig().Unreliable = true;
    CHECK(Tiers::RunnableHeuristics(S, HeurCategory::Partial) == IdRange(12, 41));
  }
  {
    // D:1481-1484: len(matched_primary) == total_functions1 (0 == 0 here) fires at the first entry:
    // nothing runs, and the log line is written once.
    DiffSession S;
    S.Log().SetQuiet(true);
    S.State().SetTotals(0, 5);
    CHECK(Tiers::RunnableHeuristics(S, HeurCategory::Best).empty());
    CHECK_NUM_EQ(S.Log().Lines().size(), 1);
    if (!S.Log().Lines().empty()) {
      CHECK_TEXT_EQ(S.Log().Lines()[0], "All functions matched in at least one database, finishing.");
    }
  }
  {
    // StageRunSingleHeuristic refuses an id outside HEURISTICS
    DiffSession S;
    bool Refused = false;
    try {
      StageRunSingleHeuristic(S, 50);
    } catch (const UnsupportedInput&) {
      Refused = true;
    }
    CHECK(Refused);
  }
}

// ---------------------------------------------------------------------------------------------
// Unit tests: dispatch by ratio type and chooser pair (D:1510-1535) on the probe3 fixture pair,
// with a scripted check_ratio.

void TestDispatch(const std::string& Scratch) {
  DSig::Test::Suite("dispatch: NO_FPS / RATIO / RATIO_MAX / TRUSTED, the Unreliable demotion (D:1510-1535)");
  if (DSig::Test::TestDataDir().empty()) {
    DSig::Test::Skip("dispatch", "DSIG_TEST_DATA_DIR is not set");
    return;
  }
  const auto Db = BuildFixture(Scratch, "probe3", "dispatch");
  if (!Db) {
    return;
  }
  const auto Fresh = [&](DiffSession& S, ScriptedRatio& R) {
    S.Log().SetQuiet(true);
    S.Open(Db->Main, Db->Diff);
    S.State().SetTotals(6, 6);
    S.Flags().IsSameProcessor = true;
    S.SetRatioProvider(&R);
  };
  {
    // HEURISTICS[5] "Same cleaned assembly", RATIO (val 0.5): 1.0 -> best, [0.5, 1.0) -> partial.
    DiffSession S;
    ScriptedRatio R(S);
    Fresh(S, R);
    R.Table[{P3Main(1), P3Diff(1)}] = 0.49;
    R.Table[{P3Main(2), P3Diff(2)}] = 0.5;
    R.Table[{P3Main(3), P3Diff(3)}] = 1.0;
    StageRunSingleHeuristic(S, 5);
    CHECK_NUM_EQ(R.Calls, 6);  // the 6 rows of its SQL (equal clean_assembly)
    CHECK((ItemsOf(S, Chooser::Best) ==
           std::vector<ItemKey>{{P3Main(3), P3MainName(3), P3Diff(3), P3DiffName(3), "Same cleaned assembly", 1.0}}));
    CHECK((ItemsOf(S, Chooser::Partial) ==
           std::vector<ItemKey>{{P3Main(2), P3MainName(2), P3Diff(2), P3DiffName(2), "Same cleaned assembly", 0.5}}));
  }
  {
    // HEURISTICS[27] "Mnemonics small-primes-product", RATIO_MAX min 0.6: 0.59 dropped, 0.6 partial.
    DiffSession S;
    ScriptedRatio R(S);
    Fresh(S, R);
    R.Table[{P3Main(1), P3Diff(1)}] = 0.59;
    R.Table[{P3Main(2), P3Diff(2)}] = 0.6;
    R.Table[{P3Main(3), P3Diff(3)}] = 1.0;
    StageRunSingleHeuristic(S, 27);
    CHECK(R.Calls >= 6);  // 36 rows (6 x 6); has_best_match blocks some before check_ratio
    CHECK_NUM_EQ(ItemsOf(S, Chooser::Best).size(), 1);
    CHECK((ItemsOf(S, Chooser::Partial) == std::vector<ItemKey>{{P3Main(2), P3MainName(2), P3Diff(2), P3DiffName(2),
                                                                   "Mnemonics small-primes-product", 0.6}}));
  }
  {
    // HEURISTICS[10] "Equal assembly or pseudo-code", NO_FPS: any accepted ratio becomes an item ratio 1.
    DiffSession S;
    ScriptedRatio R(S);
    Fresh(S, R);
    R.Default = 0.3;
    StageRunSingleHeuristic(S, 10);
    std::vector<ItemKey> Expected;
    for (int I = 1; I <= 6; ++I) {
      Expected.emplace_back(P3Main(I), P3MainName(I), P3Diff(I), P3DiffName(I), "Equal assembly", 1.0);
    }
    CHECK(ItemsOf(S, Chooser::Best) == Expected);
    CHECK(ItemsOf(S, Chooser::Partial).empty());
    // matched_primary holds the dict ratio 1.0 too (D:2075 add_match(name1, name2, 1.0, ...))
    const auto Entry = S.State().Primary(*S.Ids().FindName(P3MainName(1)));
    CHECK(Entry.has_value() && Entry->Ratio == 1.0);
  }
  {
    // HEURISTICS[44] "Nodes, edges, complexity and mnemonics" (category Unreliable, RATIO): the
    // category demotes best -> partial and partial -> unreliable (D:1510-1512).
    DiffSession S;
    ScriptedRatio R(S);
    Fresh(S, R);
    R.Table[{P3Main(1), P3Diff(1)}] = 1.0;
    R.Table[{P3Main(2), P3Diff(2)}] = 0.55;
    StageRunSingleHeuristic(S, 44);
    CHECK(ItemsOf(S, Chooser::Best).empty());
    CHECK((ItemsOf(S, Chooser::Partial) == std::vector<ItemKey>{{P3Main(1), P3MainName(1), P3Diff(1), P3DiffName(1),
                                                                   "Nodes, edges, complexity and mnemonics", 1.0}}));
    CHECK((ItemsOf(S, Chooser::Unreliable) == std::vector<ItemKey>{{P3Main(2), P3MainName(2), P3Diff(2),
                                                                      P3DiffName(2),
                                                                      "Nodes, edges, complexity and mnemonics", 0.55}}));
  }
  {
    // HEURISTICS[12] "Same named compilation unit function match", RATIO_MAX_TRUSTED min 0.44: 0.45 goes
    // to partial (below 0.5), 0.43 is dropped; the wrapper's choosers are fixed "best" / "partial".
    const std::string Cu =
        "UPDATE functions SET nodes = 5;"
        "INSERT INTO compilation_units (id, name, functions, primes_value, pseudocode_primes, start_ea, end_ea) "
        "VALUES (1, 'unit.c', 6, '1', '1', '0', '1');"
        "INSERT INTO compilation_unit_functions (cu_id, func_id) SELECT 1, id FROM functions;";
    const auto CuDb = BuildFixture(Scratch, "probe3", "dispatch_cu", Cu, Cu);
    if (CuDb) {
      DiffSession S;
      ScriptedRatio R(S);
      S.Log().SetQuiet(true);
      S.Open(CuDb->Main, CuDb->Diff);
      S.State().SetTotals(6, 6);
      S.SetRatioProvider(&R);
      R.Table[{P3Main(1), P3Diff(1)}] = 0.45;
      R.Table[{P3Main(2), P3Diff(2)}] = 0.43;
      R.Table[{P3Main(3), P3Diff(3)}] = 1.0;
      StageRunSingleHeuristic(S, 12);
      CHECK(R.Calls >= 6);
      CHECK((ItemsOf(S, Chooser::Best) == std::vector<ItemKey>{{P3Main(3), P3MainName(3), P3Diff(3), P3DiffName(3),
                                                                 "Same named compilation unit function match", 1.0}}));
      CHECK((ItemsOf(S, Chooser::Partial) ==
             std::vector<ItemKey>{{P3Main(1), P3MainName(1), P3Diff(1), P3DiffName(1),
                                   "Same named compilation unit function match", 0.45}}));
    }
  }
  {
    // the wrappers' all_functions_matched() early return (D:1956, D:1981, D:2007, D:2045): no execute,
    // no row, even for a heuristic whose SQL would return rows
    DiffSession S;
    ScriptedRatio R(S);
    Fresh(S, R);
    S.State().SetTotals(0, 0);
    StageRunSingleHeuristic(S, 10);
    StageRunSingleHeuristic(S, 5);
    CHECK_NUM_EQ(R.Calls, 0);
  }
}

// ---------------------------------------------------------------------------------------------
// Unit tests: worker-thread truncation (plan §3.11, 02 §5.5, 07 §10.3) and the reverse order

void TestTruncation(const std::string& Scratch) {
  DSig::Test::Suite("per-heuristic truncation and reverse execution order (threads.py:40, D:1967-1973, D:2080)");
  if (DSig::Test::TestDataDir().empty()) {
    DSig::Test::Skip("truncation", "DSIG_TEST_DATA_DIR is not set");
    return;
  }
  const auto Db = BuildFixture(Scratch, "probe3", "truncation");
  if (!Db) {
    return;
  }
  // The row order of HEURISTICS[5]'s SQL, as SqlRowSource fetches it.
  std::vector<std::pair<std::string, std::string>> Order5;
  {
    DiffSession S;
    S.Open(Db->Main, Db->Diff);
    SqlRowSource Rows(S, ApplyPostfix(Heuristic(5).Sql, ""));
    HeuristicRow Row;
    while (Rows.Next(Row)) {
      Order5.emplace_back(std::string(S.Ids().AddrKeyText(Row.Ea1)), std::string(S.Ids().AddrKeyText(Row.Ea2)));
    }
  }
  CHECK_NUM_EQ(Order5.size(), 6);
  if (Order5.size() != 6) {
    return;
  }
  {
    // RATIO: the third row raises -> the first two stay, the heuristic ends there and is recorded.
    DiffSession S;
    ScriptedRatio R(S);
    S.Log().SetQuiet(true);
    S.Open(Db->Main, Db->Diff);
    S.State().SetTotals(6, 6);
    S.SetRatioProvider(&R);
    R.Default = 1.0;
    R.RaiseOnCall = {3};
    StageRunSingleHeuristic(S, 5);
    CHECK_NUM_EQ(R.Calls, 3);
    CHECK_NUM_EQ(S.State().Items(Chooser::Best).size(), 2);
    const auto& Truncations = Tiers::HeuristicTruncations(S);
    CHECK_NUM_EQ(Truncations.size(), 1);
    if (!Truncations.empty()) {
      CHECK_NUM_EQ(Truncations[0].Id, 5);
      CHECK_TEXT_EQ(Truncations[0].Site, "scripted");
    }
    CHECK(!S.Log().Lines().empty() && S.Log().Lines().back().rfind("Error: ", 0) == 0);
  }
  {
    // NO_FPS: add_matches_from_query swallows the error itself (D:2080-2081): no truncation record.
    DiffSession S;
    ScriptedRatio R(S);
    S.Open(Db->Main, Db->Diff);
    S.State().SetTotals(6, 6);
    S.SetRatioProvider(&R);
    R.Default = 1.0;
    R.RaiseOnCall = {3};
    StageRunSingleHeuristic(S, 10);
    CHECK_NUM_EQ(R.Calls, 3);
    CHECK_NUM_EQ(S.State().Items(Chooser::Best).size(), 2);
    CHECK(Tiers::HeuristicTruncations(S).empty());
  }
  {
    // A native refusal is not a Python exception: it propagates.
    DiffSession S;
    ScriptedRatio R(S);
    S.Open(Db->Main, Db->Diff);
    S.State().SetTotals(6, 6);
    S.SetRatioProvider(&R);
    R.RefuseOnCall = {1};
    bool Refused = false;
    try {
      StageRunSingleHeuristic(S, 5);
    } catch (const UnsupportedInput&) {
      Refused = true;
    }
    CHECK(Refused);
  }
  {
    // The Best category keeps going after a truncation. Calls: #1 is HEURISTICS[10]'s first row
    // (NO_FPS, swallowed: 10 ends with no add), #2 is 5's first row (1.0, kept), #3 is 5's second row
    // (RATIO: 5 is truncated); 3 ("Bytes hash") then takes the five pairs left. The points show the
    // reverse order 11, 10, ..., 0 (jkutils/threads.py:40).
    DiffSession S;
    ScriptedRatio R(S);
    S.Log().SetQuiet(true);
    S.Open(Db->Main, Db->Diff);
    S.State().SetTotals(6, 6);
    S.Flags().IsSameProcessor = true;
    S.SetRatioProvider(&R);
    R.Default = 1.0;
    R.RaiseOnCall = {1, 3};
    const std::string TracePath = DSig::Test::PathToUtf8(DSig::Test::Utf8ToPath(Scratch) / "truncation.trace.jsonl");
    std::vector<JsonValue> Events;
    {
      TraceCapture Capture(S, TracePath, false);
      {
        ContextScope Scope(S, "run_heuristics_for_category:Best");
        StageRunHeuristicsForCategory(S, HeurCategory::Best);
      }
      Events = Capture.Finish();
    }
    std::vector<std::string> Before;
    std::string LastPoint;
    for (const JsonValue& E : Events) {
      if (E.At("ev").AsString() == "point") {
        LastPoint = E.At("name").AsString();
        if (LastPoint.rfind("before:heuristic:", 0) == 0) {
          Before.push_back(LastPoint.substr(17));
        }
      }
    }
    CHECK((Before == std::vector<std::string>{"11", "10", "9", "8", "7", "6", "5", "4", "3", "2", "1", "0"}));
    CHECK_TEXT_EQ(LastPoint, "after:run_heuristics_for_category:Best");
    std::map<std::string, int> Descs;
    for (const auto& Key : ItemsOf(S, Chooser::Best)) {
      ++Descs[std::get<4>(Key)];
    }
    CHECK_NUM_EQ(Descs["Same cleaned assembly"], 1);
    CHECK_NUM_EQ(Descs["Bytes hash"], 5);
    CHECK_NUM_EQ(Descs.size(), 2);
    const std::vector<Item>& Best = S.State().Items(Chooser::Best);
    const auto First = std::find_if(Best.begin(), Best.end(), [&](const Item& It) {
      return S.Ids().DescText(It.Desc) == "Same cleaned assembly";
    });
    CHECK(First != Best.end() && S.Ids().AddrKeyText(First->Ea1) == Order5[0].first);
    CHECK_NUM_EQ(Tiers::HeuristicTruncations(S).size(), 1);
  }
}

// ---------------------------------------------------------------------------------------------
// Unit tests: search_small_differences (D:2085-2150, 05 §11)

// smalldiff: low_a / weak_a / half_a at 0x401000 / 0x401100 / 0x401200, sub_low_b / sub_weak_b /
// sub_half_b at 0x601000 / 0x601100 / 0x601200.
const std::string kLowA = Addr(0x401000), kWeakA = Addr(0x401100), kHalfA = Addr(0x401200);
const std::string kLowB = Addr(0x601000), kWeakB = Addr(0x601100), kHalfB = Addr(0x601200);
const std::string kSmallDesc = "Nodes, edges, complexity and mnemonics with small differences";

void TestSmallDifferences(const std::string& Scratch) {
  DSig::Test::Suite("search_small_differences: gate, has_better_match first, no lower bound, raises (05 §11)");
  if (DSig::Test::TestDataDir().empty()) {
    DSig::Test::Skip("small differences", "DSIG_TEST_DATA_DIR is not set");
    return;
  }
  const auto Db = BuildFixture(Scratch, "smalldiff", "small");
  if (!Db) {
    return;
  }
  const auto Fresh = [](DiffSession& S, ScriptedRatio& R, const FixturePair& P) {
    S.Log().SetQuiet(true);
    S.Open(P.Main, P.Diff);
    S.State().SetTotals(3, 3);
    S.SetRatioProvider(&R);
  };
  {
    // names ratios: low 2/3, weak 1/3 (gate: never reaches check_match), half 1/2 (>= 0.5 passes);
    // check_ratio 0.003 is recorded as is (no lower bound), 1.0 goes to best (D:2143-2146).
    DiffSession S;
    ScriptedRatio R(S);
    Fresh(S, R, *Db);
    R.Table[{kLowA, kLowB}] = 0.003;
    R.Table[{kHalfA, kHalfB}] = 1.0;
    StageSearchSmallDifferences(S);
    CHECK(R.Saw(kLowA, kLowB));
    CHECK(R.Saw(kHalfA, kHalfB));
    CHECK(!R.Saw(kWeakA, kWeakB));
    CHECK_NUM_EQ(R.Calls, 2);  // the cross pairs share no name: names ratio 0
    CHECK((ItemsOf(S, Chooser::Partial) == std::vector<ItemKey>{{kLowA, "low_a", kLowB, "sub_low_b", kSmallDesc, 0.003}}));
    CHECK((ItemsOf(S, Chooser::Best) == std::vector<ItemKey>{{kHalfA, "half_a", kHalfB, "sub_half_b", kSmallDesc, 1.0}}));
  }
  {
    // D:2124-2125: has_better_match runs on the NAMES ratio before check_match. matched_primary[low_a]
    // at 0.7 beats the names ratio 0.667 (sub_low_b is a sub_ name, so no named shortcut): the row
    // never reaches check_match. At 0.6 it does.
    for (const double Held : {0.7, 0.6}) {
      DiffSession S;
      ScriptedRatio R(S);
      Fresh(S, R, *Db);
      Item Prior;
      Prior.Ea1 = S.Ids().Addr(kLowA);
      Prior.Name1 = S.Ids().Name("low_a");
      Prior.Ea2 = S.Ids().Addr("1");
      Prior.Name2 = S.Ids().Name("sub_other");
      Prior.Desc = S.Ids().Desc("prior");
      Prior.Ratio = Held;
      S.State().AddMatch(Prior.Name1, Prior.Name2, Held, Prior, Chooser::Partial);
      StageSearchSmallDifferences(S);
      CHECK(R.Saw(kLowA, kLowB) == (Held < 2.0 / 3.0));
    }
  }
  {
    // no all_functions_matched() check (05 §11): the pass runs with every function matched
    DiffSession S;
    ScriptedRatio R(S);
    Fresh(S, R, *Db);
    S.State().SetTotals(0, 0);
    CHECK(S.State().AllFunctionsMatched());
    StageSearchSmallDifferences(S);
    CHECK_NUM_EQ(R.Calls, 2);
  }
  const auto Raises = [&](const std::string& Tag, const std::string& ExtraMain, const std::string& ExtraDiff,
                          const std::string& SitePrefix) {
    const auto Bad = BuildFixture(Scratch, "smalldiff", Tag, ExtraMain, ExtraDiff);
    if (!Bad) {
      return;
    }
    DiffSession S;
    ScriptedRatio R(S);
    Fresh(S, R, *Bad);
    std::string Site;
    const bool Raised = ThrowsWouldRaise([&] { StageSearchSmallDifferences(S); }, &Site);
    DSig::Test::Report(Raised, (Tag + " raises").c_str(), __FILE__, __LINE__);
    DSig::Test::ReportText(Site.rfind(SitePrefix, 0) == 0, (Tag + " site").c_str(), Site, SitePrefix, __FILE__,
                           __LINE__);
  };
  // D:2123: '[ ]' passes `f.names != '[]'`, both sets are empty: ZeroDivisionError
  Raises("zerodiv", "UPDATE functions SET names = '[ ]' WHERE name = 'low_a';",
         "UPDATE functions SET names = '[]' WHERE name = 'sub_low_b';", "D:2123 ZeroDivisionError");
  // D:2120: json.loads(None) for a NULL df.names (the SQL filters only f.names)
  Raises("nullnames", "", "UPDATE functions SET names = NULL WHERE name = 'sub_low_b';", "D:2120 TypeError");
  // json.loads raising on malformed JSON, and set() on an unhashable element
  Raises("badjson", "", "UPDATE functions SET names = '[\"CreateFileW\", ' WHERE name = 'sub_low_b';", "");
  Raises("unhashable", "", "UPDATE functions SET names = '[[\"x\"]]' WHERE name = 'sub_low_b';", "");
}

// result_iter: fetchmany(1000) (D:139-146). One main function against 2100 diff functions with equal
// nodes / edges / mnemonics / complexity and names, so every row reaches check_match (the scripted
// provider counts the rows consumed). A row that fails decides how many rows were consumed; the
// expected counts are the ones the lane's probe measured on the oracle's Python 3.13.12 / SQLite
// 3.51.1 (SmallDifferences.cpp ResultIter).
void TestResultIterBatches(const std::string& Scratch) {
  DSig::Test::Suite("result_iter fetchmany(1000) batching of search_small_differences (D:139-146, D:2110)");
  if (DSig::Test::TestDataDir().empty()) {
    DSig::Test::Skip("result_iter", "DSIG_TEST_DATA_DIR is not set");
    return;
  }
  const std::string Main =
      "DELETE FROM functions WHERE id <> 1;"
      "UPDATE functions SET names = '[\"a\", \"b\"]', mnemonics = '[\"m\"]', nodes = 4, edges = 3, "
      "cyclomatic_complexity = 1;";
  const std::string Diff =
      "DELETE FROM functions;"
      "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 2100) "
      "INSERT INTO functions (id, name, address, nodes, edges, mnemonics, names, cyclomatic_complexity, md_index, "
      "instructions, size) SELECT i, 'sub_' || (8000000 + i), CAST(8000000 + i AS TEXT), 4, 3, '[\"m\"]', "
      "'[\"a\", \"b\"]', 1, '0', 8, 32 FROM n;";
  // the same query with one more column that fails at a chosen row: abs() of -2^63 raises
  // "integer overflow" while SQLite steps to that row
  std::string StepSql(kSqlSmallDifferences);
  const size_t Select = StepSql.find("select ");
  if (Select == std::string::npos) {
    DSig::Test::Report(false, "kSqlSmallDifferences has no select", __FILE__, __LINE__);
    return;
  }
  StepSql.insert(Select + 7, "abs(df.size) probe_abs, ");
  const auto Consumed = [&](const std::string& Tag, const std::string& ExtraDiff, const std::string& Sql,
                            std::string* Site, std::vector<std::pair<std::string, std::string>>* Order) -> int {
    const auto Db = BuildFixture(Scratch, "probe3", Tag, Main, Diff + ExtraDiff);
    if (!Db) {
      return -1;
    }
    DiffSession S;
    ScriptedRatio R(S);
    S.Log().SetQuiet(true);
    S.Open(Db->Main, Db->Diff);
    S.State().SetTotals(1, 2100);
    S.SetRatioProvider(&R);
    R.Default = 0.6;
    std::string Raised;
    if (!ThrowsWouldRaise([&] { Tiers::SearchSmallDifferencesWith(S, Sql); }, &Raised)) {
      Raised.clear();
    }
    if (Site != nullptr) {
      *Site = Raised;
    }
    if (Order != nullptr) {
      *Order = R.Seen;
    }
    return R.Calls;
  };
  std::vector<std::pair<std::string, std::string>> Order;
  std::vector<std::pair<std::string, std::string>> StepOrder;
  std::string Site;
  CHECK_NUM_EQ(Consumed("batch_base", "", std::string(kSqlSmallDifferences), &Site, &Order), 2100);
  CHECK_TEXT_EQ(Site, "");
  CHECK_NUM_EQ(Consumed("batch_stepbase", "", StepSql, &Site, &StepOrder), 2100);
  if (Order.size() != 2100 || StepOrder.size() != 2100) {
    return;
  }
  // invalid UTF-8 in a SELECT_FIELDS column of the row at fetch position P (1-based): Python decodes a
  // row when it fetches it, so earlier batches are consumed and the failing batch is not. The expected
  // counts are Python 3.13.12's on a 2100-row cursor (the lane's probe): 5 -> 0, 1000 -> 0,
  // 1001 -> 1000, 2001 -> 2000, 2100 -> 2000.
  for (const auto& [P, Expected] : {std::pair<int, int>{5, 0}, {1000, 0}, {1001, 1000}, {2001, 2000}, {2100, 2000}}) {
    const std::string Tag = "batch_utf8_" + std::to_string(P);
    const std::string Bad = "UPDATE functions SET pseudocode = CAST(x'ff' AS TEXT) WHERE address = '" +
                            Order[static_cast<size_t>(P - 1)].second + "';";
    const int Got = Consumed(Tag, Bad, std::string(kSqlSmallDifferences), &Site, nullptr);
    DSig::Test::ReportNum(Got == Expected, (Tag + " rows consumed").c_str(), Got, Expected, __FILE__, __LINE__);
    CHECK_TEXT_EQ(Site, "fetch");
  }
  // a step error positioning row P: Python steps to row P while it fetches row P - 1, so the batch
  // holding row P - 1 is lost too. Python 3.13.12 (the lane's probe): 5 -> 0, 1000 -> 0, 1001 -> 0,
  // 1002 -> 1000, 2001 -> 1000, 2100 -> 2000.
  for (const auto& [P, Expected] :
       {std::pair<int, int>{5, 0}, {1000, 0}, {1001, 0}, {1002, 1000}, {2001, 1000}, {2100, 2000}}) {
    const std::string Tag = "batch_step_" + std::to_string(P);
    const std::string Bad = "UPDATE functions SET size = -9223372036854775808 WHERE address = '" +
                            StepOrder[static_cast<size_t>(P - 1)].second + "';";
    const int Got = Consumed(Tag, Bad, StepSql, &Site, nullptr);
    DSig::Test::ReportNum(Got == Expected, (Tag + " rows consumed").c_str(), Got, Expected, __FILE__, __LINE__);
    CHECK_TEXT_EQ(Site, "sqlite3_step");
  }
}

// ---------------------------------------------------------------------------------------------
// The data-touched descriptor (TiersDetail.h), checked against SQLite's own column resolution

// Every (schema.table, column) SQLite's authorizer reports as SQLITE_READ while preparing Sql on the
// fixture pair (main + ATTACHed diff). CTE / subquery columns are not table reads (auth.c
// sqlite3AuthRead returns for them), which matches DataTouched::Columns.
std::set<std::pair<std::string, std::string>> AuthorizerReads(const FixturePair& Db, const std::string& Sql,
                                                               std::string& Failure) {
  std::set<std::pair<std::string, std::string>> Reads;
  sqlite3* Handle = nullptr;
  const std::string Uri = DiffDatabase::UriForPath(Db.Main, true) + "&immutable=1";
  if (sqlite3_open_v2(Uri.c_str(), &Handle, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, nullptr) != SQLITE_OK) {
    Failure = "open";
    sqlite3_close(Handle);
    return Reads;
  }
  const std::string Attach = "ATTACH '" + DiffDatabase::UriForPath(Db.Diff, true) + "&immutable=1' AS diff";
  if (sqlite3_exec(Handle, Attach.c_str(), nullptr, nullptr, nullptr) != SQLITE_OK) {
    Failure = std::string("attach: ") + sqlite3_errmsg(Handle);
    sqlite3_close(Handle);
    return Reads;
  }
  const auto Callback = [](void* User, int Action, const char* Table, const char* Column, const char* Schema,
                           const char*) -> int {
    if (Action == SQLITE_READ && Table != nullptr && Column != nullptr && Schema != nullptr) {
      static_cast<std::set<std::pair<std::string, std::string>>*>(User)->emplace(std::string(Schema) + "." + Table,
                                                                                 Column);
    }
    return SQLITE_OK;
  };
  sqlite3_set_authorizer(Handle, Callback, &Reads);
  sqlite3_stmt* Stmt = nullptr;
  if (sqlite3_prepare_v2(Handle, Sql.c_str(), static_cast<int>(Sql.size()), &Stmt, nullptr) != SQLITE_OK) {
    Failure = std::string("prepare: ") + sqlite3_errmsg(Handle);
  }
  sqlite3_finalize(Stmt);
  sqlite3_set_authorizer(Handle, nullptr, nullptr);
  sqlite3_close(Handle);
  return Reads;
}

bool HasKey(const Tiers::DataTouched& D, const std::string& Left, const std::string& Right) {
  for (const auto& [L, R] : D.JoinKeys) {
    if (L.Text() == Left && R.Text() == Right) {
      return true;
    }
  }
  return false;
}

const Tiers::Predicate* FindPredicate(const Tiers::DataTouched& D, const std::string& Text) {
  for (const Tiers::Predicate& P : D.Predicates) {
    if (P.Text == Text) {
      return &P;
    }
  }
  return nullptr;
}

void TestDataTouched(const std::string& Scratch) {
  DSig::Test::Suite("data touched: tables, columns and join keys of the 50 heuristics (TiersDetail.h)");
  // every heuristic: no unresolved name; the raw SQL's %POSTFIX% count (H10 has two)
  for (const HeuristicSpec& Spec : Heuristics()) {
    const Tiers::DataTouched D = Tiers::HeuristicDataTouched(Spec.Id);
    DSig::Test::Report(D.Unresolved.empty(), ("H" + std::to_string(Spec.Id) + " resolves every name").c_str(),
                       __FILE__, __LINE__);
    DSig::Test::Report(!D.Columns.empty() && !D.Tables.empty(),
                       ("H" + std::to_string(Spec.Id) + " has columns").c_str(), __FILE__, __LINE__);
    const Tiers::DataTouched Raw = Tiers::DescribeSqlDataTouched(Spec.Sql);
    CHECK_NUM_EQ(Raw.PostfixTokens, Spec.Id == 10 ? 2 : 1);
    CHECK(Raw.Columns == D.Columns);
    CHECK_NUM_EQ(D.PostfixTokens, 0);
  }
  // spot checks against the SQL text (H: lines)
  {
    const auto D = Tiers::HeuristicDataTouched(3);  // H:145-157 f.bytes_hash = df.bytes_hash
    CHECK_TEXT_EQ(D.KeySignature, "main.functions.bytes_hash=diff.functions.bytes_hash");
    CHECK(D.Distinct);
    CHECK((D.Tables == std::vector<std::string>{"diff.functions", "main.functions"}));
  }
  {
    const auto D = Tiers::HeuristicDataTouched(0);  // H:89-107: (rva or segment_rva) and bytes_hash and ...
    CHECK_TEXT_EQ(D.KeySignature,
                  "main.functions.bytes_hash=diff.functions.bytes_hash & "
                  "main.functions.instructions=diff.functions.instructions");
    const Tiers::Predicate* Rva = FindPredicate(D, "df.rva = f.rva");
    CHECK(Rva != nullptr && Rva->Join && !Rva->Conjunctive && Rva->EquiKey.has_value() &&
          Rva->EquiKey->first.Text() == "main.functions.rva");
    const Tiers::Predicate* Nodes = FindPredicate(D, "f.nodes >= 3");
    CHECK(Nodes != nullptr && !Nodes->Join && Nodes->Conjunctive && Nodes->Op == ">=");
  }
  {
    const auto D = Tiers::HeuristicDataTouched(10);  // H:269-297 UNION of pseudocode and assembly arms
    CHECK(D.Union);
    CHECK_TEXT_EQ(D.KeySignature, "main.functions.pseudocode=diff.functions.pseudocode | "
                                  "main.functions.assembly=diff.functions.assembly");
    const Tiers::Predicate* Like = FindPredicate(D, "f.name not like 'nullsub%'");
    CHECK(Like != nullptr && Like->Op == "not like");
  }
  {
    const auto D = Tiers::HeuristicDataTouched(12);  // H:319-351 compilation-unit joins
    CHECK(HasKey(D, "main.compilation_units.name", "diff.compilation_units.name"));
    CHECK(HasKey(D, "main.compilation_unit_functions.func_id", "main.functions.id"));
    CHECK(HasKey(D, "main.functions.primes_value", "diff.functions.primes_value"));
    CHECK_NUM_EQ(D.Tables.size(), 6);
  }
  {
    const auto D = Tiers::HeuristicDataTouched(18);  // H:476-510 CTE shared_hashes
    CHECK((D.Ctes == std::vector<std::string>{"shared_hashes"}));
    CHECK(HasKey(D, "main.functions.kgh_hash", "diff.functions.kgh_hash"));
    CHECK(HasKey(D, "diff.functions.kgh_hash", "cte:shared_hashes.kgh_hash"));
    CHECK_NUM_EQ(D.GroupBy.size(), 2);  // kgh_hash of each CTE arm's table
  }
  {
    const auto D = Tiers::HeuristicDataTouched(39);  // H:888-934 three CTEs, f.name != df.name
    CHECK_NUM_EQ(D.Ctes.size(), 3);
    const Tiers::Predicate* Names = FindPredicate(D, "f.name != df.name");
    CHECK(Names != nullptr && Names->Join && Names->Op == "!=" && !Names->EquiKey);
    CHECK(HasKey(D, "main.functions.id", "cte:query1.main_func_id"));
  }
  {
    const auto D = Tiers::HeuristicDataTouched(40);  // H:936-979 bb CTEs, GROUP BY a result alias
    CHECK(HasKey(D, "cte:diff_bblocks.mnemonics_list", "cte:unique_main_bblocks.mnemonics_list"));
    CHECK(D.Unresolved.empty());
  }
  {
    const auto D = Tiers::DescribeSqlDataTouched(kSqlSmallDifferences);  // D:2093-2106
    CHECK_TEXT_EQ(D.KeySignature,
                  "main.functions.cyclomatic_complexity=diff.functions.cyclomatic_complexity & "
                  "main.functions.edges=diff.functions.edges & main.functions.mnemonics=diff.functions.mnemonics & "
                  "main.functions.nodes=diff.functions.nodes");
  }
  // the columns agree with SQLite's own name resolution (authorizer SQLITE_READ) on the fixture schema
  if (!DSig::Test::TestDataDir().empty()) {
    const auto Db = BuildFixture(Scratch, "probe3", "authorizer");
    if (Db) {
      int Agree = 0;
      std::vector<std::pair<std::string, std::string>> Queries;
      for (const HeuristicSpec& Spec : Heuristics()) {
        Queries.emplace_back("H" + std::to_string(Spec.Id), ApplyPostfix(Spec.Sql, ""));
      }
      Queries.emplace_back("small differences", std::string(kSqlSmallDifferences));
      for (const auto& [Name, Sql] : Queries) {
        std::string Failure;
        const auto Reads = AuthorizerReads(*Db, Sql, Failure);
        std::set<std::pair<std::string, std::string>> Mine;
        for (const Tiers::ColumnRef& Ref : Tiers::DescribeSqlDataTouched(Sql).Columns) {
          Mine.emplace(Ref.Source, Ref.Column);
        }
        const bool Same = Failure.empty() && Reads == Mine;
        DSig::Test::Report(Same, (Name + " columns == SQLite authorizer reads " + Failure).c_str(), __FILE__,
                           __LINE__);
        if (!Same) {
          for (const auto& R : Reads) {
            if (Mine.count(R) == 0) {
              DSig::Test::Note("    authorizer only: " + R.first + "." + R.second);
            }
          }
          for (const auto& R : Mine) {
            if (Reads.count(R) == 0) {
              DSig::Test::Note("    descriptor only: " + R.first + "." + R.second);
            }
          }
        }
        Agree += Same ? 1 : 0;
      }
      DSig::Test::Note(std::to_string(Agree) + "/" + std::to_string(Queries.size()) +
                       " queries: descriptor columns equal SQLite's authorizer reads");
    }
  }
  // the fusion view: each heuristic's key signature, then the conjunctive join keys shared by two or
  // more heuristics
  for (const HeuristicSpec& Spec : Heuristics()) {
    const Tiers::DataTouched D = Tiers::HeuristicDataTouched(Spec.Id);
    DSig::Test::Note("H" + std::to_string(Spec.Id) + " [" + std::to_string(D.Tables.size()) + " tables, " +
                     std::to_string(D.Columns.size()) + " columns" + (D.Ctes.empty() ? "" : ", CTEs") +
                     (D.Union ? ", UNION" : "") + (D.Distinct ? ", DISTINCT" : "") +
                     (D.OrderByPresent ? ", ORDER BY" : "") + "] " +
                     (D.KeySignature.empty() ? std::string("(no conjunctive equi-join key)") : D.KeySignature));
  }
  std::map<std::string, std::vector<int>> ByKey;
  for (const HeuristicSpec& Spec : Heuristics()) {
    for (const auto& [L, R] : Tiers::HeuristicDataTouched(Spec.Id).JoinKeys) {
      ByKey[L.Text() + "=" + R.Text()].push_back(Spec.Id);
    }
  }
  int Shared = 0;
  for (const auto& [Key, Ids] : ByKey) {
    if (Ids.size() < 2) {
      continue;
    }
    ++Shared;
    std::string List;
    for (const int Id : Ids) {
      List += (List.empty() ? "" : ",") + std::to_string(Id);
    }
    DSig::Test::Note("fusion key " + Key + ": H" + List);
  }
  CHECK(Shared > 0);
}

// ---------------------------------------------------------------------------------------------
// Fixture tests: real-Diaphora captures of the tiers fixtures (gen_tiers_fixtures.py)

std::optional<StateSnapshot> FixtureSnapshot(const std::string& Scenario, const std::string& Capture,
                                             const std::string& Point) {
  const auto Files = ListSnapshots(DSig::Test::Utf8ToPath(TiersFixtureDir(Scenario)) / DSig::Test::Utf8ToPath(Capture) /
                                   "snapshots");
  const auto It = Files.find(SanitisePointName(Point));
  if (It == Files.end()) {
    return std::nullopt;
  }
  return ReadSnapshot(It->second.Path);
}

// The ids of the before:heuristic:<id> points of a capture, in point order.
std::vector<int> CapturedHeuristics(const std::string& Scenario, const std::string& Capture) {
  std::vector<int> Out;
  const JsonValue Index = JsonParse(Detail::ReadFileBytes(DSig::Test::PathToUtf8(
      DSig::Test::Utf8ToPath(TiersFixtureDir(Scenario)) / DSig::Test::Utf8ToPath(Capture) / "index.json")));
  for (const JsonValue& Row : Index.Items()) {
    const std::string& Point = Row.Items()[1].AsString();
    if (Point.rfind("before:heuristic:", 0) == 0) {
      Out.push_back(std::stoi(Point.substr(17)));
    }
  }
  return Out;
}

// The native state after the Best category started from the capture's after:find_same_name, run in
// reverse (Diaphora) or forward (the negative control) order.
StateSnapshot NativeBest(const FixturePair& Db, const StateSnapshot& Start, bool Forward, DiffSession& S) {
  S.Log().SetQuiet(true);
  S.Open(Db.Main, Db.Diff);
  S.Restore(Start);
  S.Engine().Prepare();
  if (Forward) {
    for (const int Id : Tiers::RunnableHeuristics(S, HeurCategory::Best)) {
      ContextScope Scope(S, "heuristic:" + std::to_string(Id));
      StageRunSingleHeuristic(S, Id);
    }
    S.Cleanup(CleanupSite::L1551);
  } else {
    ContextScope Scope(S, "run_heuristics_for_category:Best");
    StageRunHeuristicsForCategory(S, HeurCategory::Best);
  }
  return S.Snapshot("after:run_heuristics_for_category:Best");
}

std::map<std::string, int> DescriptionCounts(const std::vector<SnapItem>& Items) {
  std::map<std::string, int> Out;
  for (const SnapItem& It : Items) {
    ++Out[It.Desc];
  }
  return Out;
}

void TestFixtures(const std::string& Scratch) {
  DSig::Test::Suite("fixtures recorded from real Diaphora: probe 3 / E1, probe 5, different CPU, small differences");
  if (DSig::Test::TestDataDir().empty()) {
    DSig::Test::Skip("fixtures", "DSIG_TEST_DATA_DIR is not set");
    return;
  }
  const bool Exact = DSig::Test::OracleSqlite();
  if (!Exact) {
    DSig::Test::Note("SQLite " + DiffDatabase::LibVersion() +
                     " is not the oracle's 3.51.1: order-sensitive replays skipped, properties checked");
  }
  // full replays of every fixture capture (S-L2, trace events, chained) under the oracle's SQLite
  for (const char* Scenario : {"probe3", "probe5", "diffcpu", "smalldiff"}) {
    const auto Db = BuildFixture(Scratch, Scenario, std::string("replay_") + Scenario);
    if (!Db || !Exact) {
      continue;
    }
    const PairCounts C = ReplayCapture(std::string("fixture ") + Scenario, Scenario, Db->Main, Db->Diff,
                                       DSig::Test::Utf8ToPath(TiersFixtureDir(Scenario)) / "capture", Scratch);
    DSig::Test::Note(Summary(std::string("fixture ") + Scenario, C));
    CHECK(C.HeuristicsRun > 0 && C.HeuristicsRun == C.HeuristicsPassed && C.EventsRun == C.EventsPassed &&
          C.ChainRun == 1 && C.ChainPassed == 1);
  }
  // 02 probe 3 / 01 E1: reverse order labels every pair `Equal assembly`; forward order (the negative
  // control, capture_forward/ recorded with threads_apply popping the first target) `Same order and hash`.
  {
    const auto Db = BuildFixture(Scratch, "probe3", "probe3_order");
    const auto Start = FixtureSnapshot("probe3", "capture", "after:find_same_name");
    const auto Oracle = FixtureSnapshot("probe3", "capture", "after:run_heuristics_for_category:Best");
    const auto OracleForward = FixtureSnapshot("probe3", "capture_forward", "after:run_heuristics_for_category:Best");
    CHECK(Db && Start && Oracle && OracleForward);
    if (Db && Start && Oracle && OracleForward) {
      CHECK((DescriptionCounts(Oracle->Best) == std::map<std::string, int>{{"Equal assembly", 6}}));
      CHECK((DescriptionCounts(OracleForward->Best) == std::map<std::string, int>{{"Same order and hash", 6}}));
      DiffSession Reverse;
      const StateSnapshot NativeReverse = NativeBest(*Db, *Start, false, Reverse);
      DiffSession Forward;
      const StateSnapshot NativeForward = NativeBest(*Db, *Start, true, Forward);
      CHECK((DescriptionCounts(NativeReverse.Best) == std::map<std::string, int>{{"Equal assembly", 6}}));
      CHECK((DescriptionCounts(NativeForward.Best) == std::map<std::string, int>{{"Same order and hash", 6}}));
      if (Exact) {
        CheckReplay("probe3 reverse order == Diaphora", *Oracle, NativeReverse);
        CheckReplay("probe3 forward order == Diaphora with targets.pop(0)", *OracleForward, NativeForward);
      }
      // the Partial category then runs nothing: all functions are matched when its list is built
      CHECK((CapturedHeuristics("probe3", "capture") == std::vector<int>{11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0}));
      CHECK(Tiers::RunnableHeuristics(Reverse, HeurCategory::Partial).empty());
    }
  }
  // 02 probe 5: the UNION output sorts '37120' (sub_9100) before '38656' (sub_9700); the first 1.0
  // row wins, so func_1 -> sub_9100 `Equal assembly` and sub_9700 stays unmatched.
  {
    const auto Db = BuildFixture(Scratch, "probe5", "probe5_tie");
    const auto Start = FixtureSnapshot("probe5", "capture", "after:find_same_name");
    CHECK(Db && Start);
    if (Db && Start) {
      DiffSession S;
      const StateSnapshot Native = NativeBest(*Db, *Start, false, S);
      bool Found = false;
      for (const SnapItem& It : Native.Best) {
        if (It.Name1 == std::optional<std::string>("func_1")) {
          Found = It.Name2 == std::optional<std::string>("sub_9100") && It.Ea2 == "37120" && It.Desc == "Equal assembly";
        }
        CHECK(It.Name2 != std::optional<std::string>("sub_9700"));
      }
      CHECK(Found);
      CHECK(!S.State().Secondary(*S.Ids().FindName("sub_9700")).has_value());
    }
  }
  // different processors: the lists Diaphora ran (its before:heuristic points) are the native lists
  {
    std::vector<int> Expected = {11, 10, 8, 7, 4};
    std::vector<int> Partial = IdRange(12, 35);
    Partial.insert(Partial.end(), {40, 41});
    std::reverse(Partial.begin(), Partial.end());
    Expected.insert(Expected.end(), Partial.begin(), Partial.end());
    CHECK(CapturedHeuristics("diffcpu", "capture") == Expected);
    CHECK_NUM_EQ(Expected.size(), 5 + 26);
    const auto Start = FixtureSnapshot("diffcpu", "capture", "after:find_same_name");
    CHECK(Start && !Start->Flags.IsSameProcessor);
    if (Start) {
      DiffSession S;
      S.Restore(*Start);
      std::vector<int> Native = Tiers::RunnableHeuristics(S, HeurCategory::Best);
      std::reverse(Native.begin(), Native.end());
      CHECK((Native == std::vector<int>{11, 10, 8, 7, 4}));
    }
  }
  // search_small_differences on the smalldiff fixture: Diaphora recorded low_a (names 2/3) and
  // half_a (1/2) as partial at check_ratio 0.003 (no lower bound) and skipped weak_a (1/3).
  {
    const auto Oracle = FixtureSnapshot("smalldiff", "capture", "after:search_small_differences");
    const auto Before = FixtureSnapshot("smalldiff", "capture", "before:search_small_differences");
    const auto Db = BuildFixture(Scratch, "smalldiff", "smalldiff_props");
    CHECK(Oracle && Before && Db);
    if (Oracle && Before && Db) {
      const auto Added = [](const StateSnapshot& Snap) {
        std::set<std::tuple<std::string, std::string, uint64_t>> Out;
        for (const SnapItem& It : Snap.Partial) {
          if (It.Desc == kSmallDesc) {
            Out.emplace(It.Name1.value_or("None"), It.Name2.value_or("None"), It.RatioBits);
          }
        }
        return Out;
      };
      const std::set<std::tuple<std::string, std::string, uint64_t>> Expected = {
          {"half_a", "sub_half_b", RatioBits(0.003)}, {"low_a", "sub_low_b", RatioBits(0.003)}};
      CHECK(Added(*Oracle) == Expected);
      DiffSession S;
      S.Log().SetQuiet(true);
      S.Open(Db->Main, Db->Diff);
      const StateSnapshot Native = RunReplay(S, *Before, "search_small_differences");
      CHECK(Added(Native) == Expected);
    }
  }
}

}  // namespace

int main() {
  const std::string Scratch = DSig::Test::ScratchDir("diff_tiers");
  Run("lists", TestRunnableLists);
  Run("dispatch", [&] { TestDispatch(Scratch); });
  Run("truncation", [&] { TestTruncation(Scratch); });
  Run("small differences", [&] { TestSmallDifferences(Scratch); });
  Run("result_iter", [&] { TestResultIterBatches(Scratch); });
  Run("data touched", [&] { TestDataTouched(Scratch); });
  Run("fixtures", [&] { TestFixtures(Scratch); });
  Run("corpus", [&] { TestCorpusReplays(Scratch); });
  DSig::Test::RemoveScratchDir(Scratch);
  return DSig::Test::Finish();
}
