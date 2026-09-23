// diff_early: lane L5, the pre-loop passes and patch-diff mode (docs/parity/00-plan.md §4 L5).
//
// Sections:
//  1. hook      the raising conditions of scripts/patch_diff_vulns.py on_match (P:204-236), on
//               in-memory function tables (no database), including the dedup key and the found paths;
//  2. fixtures  the five `early` scenarios (tests/diff/fixtures/early/<scenario>, built by
//               tools/parity/make_fixture.py from real Diaphora): the early-point snapshots and trace of
//               gen_early.py's instrumented capture at S-L2, RunReplay of find_same_name /
//               find_remaining_functions, and for modes S and P the whole output at L2 (L1 without the
//               oracle's SQLite) and the after:final_pass / after:find_unmatched dumps;
//  3. vectors   tests/diff/fixtures/early/vectors.json: a scenario plus SQL mutations, diffed by real
//               Diaphora: raise site and exception, empty-result path, mode, log lines, output rows and
//               (mode N) the early snapshots;
//  4. corpus    (skips without DSIG_CORPUS_ROOT) the oracle captures: S-L2 of the early points, trace
//               prefixes, replays, the dirty-heuristic percentages of 05 §19.1, the check_callgraph log
//               lines, and full-run L2 on the finished mode-P and mode-S pairs.
// Every comparison that depends on SQLite row order needs the oracle's SQLite (3.51.1, plan §2.6); on
// another SQLite those checks drop to the order-free level or are skipped with a note.

#include <sqlite3.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "../../src/diff/FileIo.h"
#include "../../src/diff/stages/EarlyPasses.h"
#include "diff/CorpusPaths.h"
#include "diff/FixtureDb.h"
#include "diff/ResultsCompare.h"
#include "diff/TestHarness.h"
#include "diff/fixtures/common/FixtureExpect.h"
#include "dsigmatcher/diff/Errors.h"
#include "dsigmatcher/diff/Json.h"
#include "dsigmatcher/diff/Pipeline.h"
#include "dsigmatcher/diff/Snapshot.h"
#include "dsigmatcher/diff/Stages.h"
#include "dsigmatcher/diff/Table.h"

namespace {

using namespace DSig::Diff;
namespace fs = std::filesystem;
using DSig::Test::PathToUtf8;
using DSig::Test::Utf8ToPath;

std::string Join(const std::string& Dir, const std::string& Name) { return PathToUtf8(Utf8ToPath(Dir) / Utf8ToPath(Name)); }

bool IsFile(const std::string& Path) {
  std::error_code Error;
  return fs::is_regular_file(Utf8ToPath(Path), Error);
}

std::vector<std::string> SplitLines(const std::string& Text) {
  std::vector<std::string> Out;
  std::istringstream In(Text);
  std::string Line;
  while (std::getline(In, Line)) {
    if (!Line.empty() && Line.back() == '\r') {
      Line.pop_back();
    }
    Out.push_back(Line);
  }
  return Out;
}

bool StartsWithAny(std::string_view Line, std::initializer_list<std::string_view> Prefixes) {
  for (const std::string_view Prefix : Prefixes) {
    if (Line.starts_with(Prefix)) {
      return true;
    }
  }
  return false;
}

// The log lines gen_early.py records (its LOG_PREFIXES) and the native summary log also writes.
bool IsComparedLogLine(std::string_view Line) {
  return StartsWithAny(Line, {"Error: ", "The selected file does not look like", "Invalid database!",
                              "WARNING: The database is from a different version", "Same MD5 in both databases",
                              "The databases seems to be 100% equal", "Call graph", "Symbols stripped detected:",
                              "Patch diffing detected:", "Final results:"});
}

std::string Joined(const std::vector<std::string>& Lines) {
  std::string Out;
  for (const std::string& Line : Lines) {
    Out += Line + "\n";
  }
  return Out;
}

bool ReportSnapshots(const std::string& What, const StateSnapshot& Oracle, const StateSnapshot& Native) {
  const DSig::Test::CompareReport Report = DSig::Test::CompareSnapshots(Oracle, Native, 8);
  DSig::Test::Report(Report.L2Equal, What.c_str(), __FILE__, __LINE__);
  if (!Report.L2Equal) {
    for (const std::string& Line : Report.Differences) {
      DSig::Test::Note("    " + Line);
    }
  }
  return Report.L2Equal;
}

// =============================================================================================
// 1. The patch-diff hook on in-memory tables

struct HookBench {
  DiffSession S;
  HookBench() { S.Flags().HooksLoaded = true; }

  static void Put(TextColumn& Column, const std::optional<std::string>& Value, bool Blob) {
    if (Value) {
      Column.Append(*Value, Blob);
    } else {
      Column.AppendNull();
    }
  }

  // One (main, diff) function pair and the row check_match would pass to the hook.
  HeuristicRow Row(const std::optional<std::string>& Asm1, const std::optional<std::string>& Asm2,
                   const std::optional<std::string>& Pseudo1 = std::nullopt,
                   const std::optional<std::string>& Pseudo2 = std::nullopt, const std::string& Name1 = "f",
                   const std::string& Name2 = "f", std::optional<int64_t> Nodes1 = 4, std::optional<int64_t> Nodes2 = 4,
                   const std::string& Ea1 = "4096", const std::string& Ea2 = "8192", bool BlobAsm = false) {
    HeuristicRow R;
    R.Row1 = static_cast<uint32_t>(S.Main().Functions.Assembly.Size());
    R.Row2 = static_cast<uint32_t>(S.Diff().Functions.Assembly.Size());
    Put(S.Main().Functions.Assembly, Asm1, BlobAsm);
    Put(S.Diff().Functions.Assembly, Asm2, false);
    Put(S.Main().Functions.Pseudocode, Pseudo1, false);
    Put(S.Diff().Functions.Pseudocode, Pseudo2, false);
    R.Side1 = Side::Main;
    R.Side2 = Side::Diff;
    R.Name1 = S.Ids().Name(Name1);
    R.Name2 = S.Ids().Name(Name2);
    R.Ea1 = S.Ids().Addr(Ea1);
    R.Ea2 = S.Ids().Addr(Ea2);
    R.Desc = S.Ids().Desc("Perfect match, same name");
    R.Nodes1 = Nodes1;
    R.Nodes2 = Nodes2;
    return R;
  }

  // "ok" or the DiaphoraWouldRaise site.
  std::string Call(const HeuristicRow& R, double Ratio = 0.9) {
    try {
      PatchDiffHookOnMatch(S, R, Ratio);
      return "ok";
    } catch (const DiaphoraWouldRaise& Error) {
      return Error.Site;
    }
  }

  const Early::EarlyFacts& Facts() { return S.Ext<Early::EarlyFacts>(); }
};

const char* const kIndexError = "scripts/patch_diff_vulns.py:162 IndexError";

void TestHook() {
  DSig::Test::Suite("patch-diff hook: raising conditions of scripts/patch_diff_vulns.py on_match");
  // 01 §5.4 item 3 / 05 §8.3 reproduction: an added empty line, or one starting with a space, gives an
  // empty mnemonic and mnem1[0] raises (P:162); the header rows already set `removed`.
  {
    HookBench B;
    CHECK_TEXT_EQ(B.Call(B.Row("mov eax, 1\nret", "mov eax, 1\n\nret")), kIndexError);
  }
  {
    HookBench B;
    CHECK_TEXT_EQ(B.Call(B.Row("mov eax, 1\nret", "mov eax, 1\n ret")), kIndexError);
  }
  {
    // the very first diff row is an added empty line: `removed` comes from the "--- " header
    HookBench B;
    CHECK_TEXT_EQ(B.Call(B.Row("a", "\na")), kIndexError);
  }
  {
    // a removed empty line raises only when the added mnemonic starts with "b" (mnem2[0] sits behind
    // the short-circuit `and`)
    HookBench B;
    CHECK_TEXT_EQ(B.Call(B.Row("x\n\ny", "x\nbswap eax\ny")), kIndexError);
    CHECK_TEXT_EQ(B.Call(B.Row("x\n\ny", "x\nxchg eax, eax\ny", std::nullopt, std::nullopt, "g", "g")), "ok");
    CHECK_TEXT_EQ(B.Call(B.Row("x\n\ny", "x\nBSWAP eax\ny", std::nullopt, std::nullopt, "h", "h")), kIndexError);
  }
  {
    // a removed line ending with ':' is skipped (P:150-151): `removed` stays the header's "-- \n", so the
    // empty mnemonic of " :" never reaches mnem2[0]
    HookBench B;
    CHECK_TEXT_EQ(B.Call(B.Row("x\n :\ny", "x\nbswap eax\ny")), "ok");
  }
  {
    // the signed/unsigned table (both directions) finds a pair and breaks before a bad line
    HookBench B;
    CHECK_TEXT_EQ(B.Call(B.Row("jle short a\nret", "jbe short a\n\nret")), "ok");
    CHECK_TEXT_EQ(B.Call(B.Row("JB x\nret", "jl x\n\nret", std::nullopt, std::nullopt, "g", "g")), "ok");
    CHECK_NUM_EQ(B.Facts().HookFound, 2);
    // a listed mnemonic whose partner does not match: no elif, no raise, and the walk goes on
    CHECK_TEXT_EQ(B.Call(B.Row("jle short a\nret", "jb short a\nret", std::nullopt, std::nullopt, "h", "h")), "ok");
    CHECK_TEXT_EQ(B.Call(B.Row("jle short a\nret", "jb short a\n\nret", std::nullopt, std::nullopt, "i", "i")), kIndexError);
  }
  {
    // branches where exactly one mnemonic ends with "s" are found (P:164-168); both "s" is not
    HookBench B;
    CHECK_TEXT_EQ(B.Call(B.Row("bgt x\nret", "bgts x\n\nret")), "ok");
    CHECK_TEXT_EQ(B.Call(B.Row("bgts x\nret", "blts x\n\nret", std::nullopt, std::nullopt, "g", "g")), kIndexError);
  }
  {
    // ratio 1.0 is never analysed (P:206); the dedup key is (name1, name2) (P:211-214)
    HookBench B;
    CHECK_TEXT_EQ(B.Call(B.Row("a\nb", "a\n\nb"), 1.0), "ok");
    CHECK_NUM_EQ(B.Facts().HookAnalysed, 0);
    CHECK_TEXT_EQ(B.Call(B.Row("a\nb", "a\nc", std::nullopt, std::nullopt, "k1", "k2")), "ok");
    CHECK_TEXT_EQ(B.Call(B.Row("a\nb", "a\n\nb", std::nullopt, std::nullopt, "k1", "k2")), "ok");  // same key: skipped
    CHECK_TEXT_EQ(B.Call(B.Row("a\nb", "a\n\nb", std::nullopt, std::nullopt, "k2", "k1")), kIndexError);
    CHECK_NUM_EQ(B.Facts().HookAnalysed, 2);
  }
  {
    // None on either side skips the assembly walk (P:134-135); bytes raise TypeError at the split (P:137)
    HookBench B;
    CHECK_TEXT_EQ(B.Call(B.Row(std::nullopt, "a\n\nb")), "ok");
    CHECK_TEXT_EQ(B.Call(B.Row("a", "a\nb", std::nullopt, std::nullopt, "g", "g", 4, 4, "4096", "8192", true)),
                  "scripts/patch_diff_vulns.py:137 TypeError");
  }
  {
    // the pseudo-code search (P:177-202) and the chooser item it leads to (D:237-245, D:275-296)
    HookBench B;
    const std::string P1 = "int f(int a1)\n{\n  return a1;\n}";
    const std::string P2 = "int f(int a1)\n{\n  memcpy(x, y, a1);\n  return a1;\n}";
    CHECK_TEXT_EQ(B.Call(B.Row("a", "a", P1, P2)), "ok");
    CHECK_NUM_EQ(B.Facts().HookFound, 1);
    CHECK_TEXT_EQ(B.Call(B.Row("a", "a", P1, P2, "g", "g", std::nullopt, 4)), "D:244 TypeError");
    CHECK_TEXT_EQ(B.Call(B.Row("a", "a", P1, P2, "h", "h", 4, std::nullopt)), "D:245 TypeError");
    CHECK_TEXT_EQ(B.Call(B.Row("a", "a", P1, P2, "i", "i", 4, 4, "0x1000")), "D:286 ValueError");
    CHECK_TEXT_EQ(B.Call(B.Row("a", "a", P1, P2, "j", "j", 4, 4, "4096", "")), "D:288 ValueError");
    // nothing found: the item is never built, so the same bad values do not raise
    CHECK_TEXT_EQ(B.Call(B.Row("a", "a", P1, P1 + "\n", "k", "k", std::nullopt, std::nullopt, "x", "y")), "ok");
    // an assembly finding also builds the item
    CHECK_TEXT_EQ(B.Call(B.Row("jg a", "ja a", std::nullopt, std::nullopt, "l", "l", std::nullopt, 4)), "D:244 TypeError");
  }
  {
    // the added-size-check rule (P:109-123): only '+' lines starting with "if ", a comparison, and no
    // "<comparison>0 " anywhere in the line
    HookBench B;
    const std::string Base = "int f(int a1)\n{\n  return a1;\n}";
    const auto With = [](const std::string& Line) { return "int f(int a1)\n{\n" + Line + "\n  return a1;\n}"; };
    const auto Found = [&](const std::string& P1, const std::string& P2, const std::string& Name) {
      const int64_t Before = B.Facts().HookFound;
      B.Call(B.Row("a", "a", P1, P2, Name, Name));
      return B.Facts().HookFound > Before;
    };
    CHECK(Found(Base, With("  if ( a1 > 16 )"), "s1"));
    CHECK(!Found(Base, With("  if ( a1 > 0 )"), "s2"));        // " > 0 " follows the comparison
    CHECK(Found(Base, With("  if ( a1 >= 5 && a1 > 0 )"), "s3"));   // " > 0 " skips " > ", then " >= " counts
    CHECK(!Found(Base, With("  if ( a1 > 0 && a1 < 0 )"), "s3b"));  // both comparisons followed by "0 "
    CHECK(Found(Base, With("  if ( a1 <= 5 )"), "s4"));
    CHECK(!Found(With("  if ( a1 > 16 )"), Base, "s5"));       // a removed line is not a new check
    CHECK(!Found(Base, With("  x = a1 > 16;"), "s6"));          // not an `if `
    CHECK(Found(With("  gets(b);"), Base, "s7"));              // PATTERNS apply to removed lines too
    CHECK(Found(Base, With("  \xC3\xA9if ( a1 > 16 )"), "s8") == false);  // line[2:] drops a whole character
    CHECK(Found(Base, With("\xC3\xA9 if ( a1 > 16 )"), "s9"));  // ... then strip(" ")
  }
}

// =============================================================================================
// Databases from the committed fixtures

std::string EarlyDir() { return Join(Join(DSig::Test::TestDataDir(), "fixtures"), "early"); }

struct DbPair {
  std::string Main;
  std::string Diff;
};

std::string ExecOnFile(const std::string& Path, const std::string& Sql) {
  sqlite3* Db = nullptr;
  if (sqlite3_open_v2(Path.c_str(), &Db, SQLITE_OPEN_READWRITE, nullptr) != SQLITE_OK) {
    const std::string Message = Db != nullptr ? sqlite3_errmsg(Db) : "out of memory";
    sqlite3_close(Db);
    return "open " + Path + ": " + Message;
  }
  char* Message = nullptr;
  std::string Failure;
  if (sqlite3_exec(Db, Sql.c_str(), nullptr, nullptr, &Message) != SQLITE_OK) {
    Failure = "exec: " + std::string(Message != nullptr ? Message : sqlite3_errmsg(Db));
  }
  sqlite3_free(Message);
  sqlite3_close(Db);
  return Failure;
}

// The scenario's two databases, rebuilt like make_fixture.py / gen_early.py rebuild them, then the
// mutation statements run on the finished files (gen_early.py BuildPair).
std::string BuildPair(const std::string& Scenario, const std::string& MainSql, const std::string& DiffSql,
                      const std::string& Work, DbPair& Out) {
  std::error_code Error;
  fs::create_directories(Utf8ToPath(Work), Error);
  Out.Main = Join(Work, "main.sqlite");
  Out.Diff = Join(Work, "diff.sqlite");
  const std::string Dir = Join(EarlyDir(), Scenario);
  for (const auto& [Db, Name, Extra] : {std::tuple{Out.Main, "main.sql", MainSql}, std::tuple{Out.Diff, "diff.sql", DiffSql}}) {
    std::string Failure = DSig::Test::BuildFixtureDb(Join(Dir, Name), Db);
    if (Failure.empty() && !Extra.empty()) {
      Failure = ExecOnFile(Db, Extra);
    }
    if (!Failure.empty()) {
      return Failure;
    }
  }
  return std::string();
}

struct NativeRun {
  bool Raised = false;
  bool Unsupported = false;
  std::string Site;
  std::string What;
  bool Returned = true;
  char Mode = 'N';
  std::vector<std::string> Log;
  Early::EarlyFacts Facts;
  bool Written = false;
  DSig::Test::ResultsFile Results;
};

// RunDiff, in process, keeping the session's log and facts: open, RunPipeline, save_results.
NativeRun RunNative(const DbPair& Pair, const std::string& Out, const std::string& SnapshotDir = std::string(),
                    const std::string& TracePath = std::string(), const std::string& Label = "fixture") {
  NativeRun R;
  DiffSession S;
  S.Log().SetQuiet(true);
  try {
    S.Open(Pair.Main, Pair.Diff);
    S.SetPairLabel(Label);
    if (!SnapshotDir.empty()) {
      S.EnableSnapshots(SnapshotDir, "*", "before:find_*");
    }
    if (!TracePath.empty()) {
      S.EnableTrace(TracePath, true);
    }
    try {
      R.Returned = RunPipeline(S);
    } catch (...) {
      S.FinishHarness();
      throw;
    }
    S.FinishHarness();
    WriteArgs Args;
    Args.OutPath = Out;
    Args.MainDb = Pair.Main;
    Args.DiffDb = Pair.Diff;
    Args.Date = "fixed";
    WriteDiaphoraResults(Args, S.Final(), S.Ids());  // D:3773 save_results runs whatever diff() returned
    R.Written = true;
    R.Results = DSig::Test::ReadResultsFile(Out);
  } catch (const DiaphoraWouldRaise& Error) {
    R.Raised = true;
    R.Site = Error.Site;
    R.What = Error.what();
  } catch (const UnsupportedInput& Error) {
    R.Unsupported = true;
    R.What = Error.What;
  } catch (const std::exception& Error) {
    R.Unsupported = true;
    R.What = std::string("unexpected: ") + Error.what();
  }
  R.Log = S.Log().Lines();
  R.Mode = S.Mode();
  R.Facts = S.Ext<Early::EarlyFacts>();
  return R;
}

// index.json of a capture directory: point -> snapshot file (null files left out).
std::vector<std::pair<std::string, std::string>> ReadIndex(const std::string& Dir) {
  std::vector<std::pair<std::string, std::string>> Out;
  const JsonValue Index = JsonParse(Detail::ReadFileBytes(Join(Dir, "index.json")));
  for (const JsonValue& Entry : Index.Items()) {
    if (!Entry.Items()[2].IsNull()) {
      Out.emplace_back(Entry.Items()[1].AsString(), Join(Dir, Entry.Items()[2].AsString()));
    }
  }
  return Out;
}

// The native capture's snapshot of `Point`.
std::optional<StateSnapshot> NativeSnapshot(const std::string& NativeDir, const std::string& Point) {
  for (const auto& [Name, File] : ReadIndex(NativeDir)) {
    if (Name == Point) {
      return ReadSnapshot(File);
    }
  }
  return std::nullopt;
}

// The first `Count` lines of a trace (the whole file when Count is SIZE_MAX).
std::vector<std::string> TraceLines(const std::string& Path, size_t Count = SIZE_MAX) {
  std::vector<std::string> Out;
  std::ifstream In(Utf8ToPath(Path), std::ios::binary);
  std::string Line;
  while (Out.size() < Count && std::getline(In, Line)) {
    Out.push_back(Line);
  }
  return Out;
}

// Trace lines up to and including the point event named `Point`.
std::vector<std::string> TraceUpTo(const std::string& Path, const std::string& Point) {
  std::vector<std::string> Out;
  std::ifstream In(Utf8ToPath(Path), std::ios::binary);
  std::string Line;
  const std::string Marker = "{\"ev\":\"point\",\"name\":" + JsonQuote(Point) + ",";
  while (std::getline(In, Line)) {
    Out.push_back(Line);
    if (Line.starts_with(Marker)) {
      break;
    }
  }
  return Out;
}

// Compares two traces event for event. As tools/parity/compare_traces.py does, `row` events are left
// out when only the native side has them (an oracle capture made without --rows).
bool CompareTraceLines(const std::string& What, const std::vector<std::string>& Oracle,
                       std::vector<std::string> Native) {
  const auto IsRow = [](const std::string& Line) { return Line.starts_with("{\"ev\":\"row\""); };
  if (std::none_of(Oracle.begin(), Oracle.end(), IsRow)) {
    Native.erase(std::remove_if(Native.begin(), Native.end(), IsRow), Native.end());
  }
  size_t First = 0;
  while (First < Oracle.size() && First < Native.size() && Oracle[First] == Native[First]) {
    ++First;
  }
  const bool Equal = Oracle.size() == Native.size() && First == Oracle.size();
  DSig::Test::Report(Equal, What.c_str(), __FILE__, __LINE__);
  if (!Equal) {
    DSig::Test::Note("    " + std::to_string(Oracle.size()) + " oracle events, " + std::to_string(Native.size()) +
                     " native events; first difference at event " + std::to_string(First));
    if (First < Oracle.size()) {
      DSig::Test::Note("    oracle: " + Oracle[First].substr(0, 300));
    }
    if (First < Native.size()) {
      DSig::Test::Note("    native: " + Native[First].substr(0, 300));
    }
  }
  return Equal;
}

// =============================================================================================
// 2. The early fixture scenarios

void TestFixtures(const std::string& Scratch) {
  DSig::Test::Suite("fixtures: the early scenarios (make_fixture.py + gen_early.py captures of real Diaphora)");
  if (DSig::Test::TestDataDir().empty()) {
    DSig::Test::Skip("fixtures", "DSIG_TEST_DATA_DIR is not set");
    return;
  }
  const bool Exact = DSig::Test::OracleSqlite();
  for (const char* Scenario : {"normal", "stripped", "patch", "equal_mangled", "quirks"}) {
    const std::string Dir = Join(EarlyDir(), Scenario);
    const JsonValue Oracle = JsonParse(Detail::ReadFileBytes(Join(Dir, "oracle.json")));
    const std::string Mode = Oracle.At("mode").AsString();
    const std::string Work = Join(Scratch, std::string("fixture-") + Scenario);
    DbPair Pair;
    const std::string Failure = BuildPair(Scenario, "", "", Join(Work, "db"), Pair);
    CHECK_TEXT_EQ(Failure, "");
    if (!Failure.empty()) {
      continue;
    }
    const std::string NativeDir = Join(Work, "native");
    const std::string TracePath = Join(NativeDir, "trace.jsonl");
    const NativeRun Run = RunNative(Pair, Join(Work, "out.diaphora"), NativeDir, TracePath);
    CHECK(!Run.Raised && !Run.Unsupported);
    if (Run.Raised || Run.Unsupported) {
      DSig::Test::Note(std::string(Scenario) + ": native run failed: " + Run.What);
      continue;
    }
    CHECK_TEXT_EQ(std::string(1, Run.Mode), Mode);

    // the capture's points, S-L2 (every point in modes S and P; up to after:find_same_name in mode N)
    const std::string CaptureDir = Join(Dir, "capture");
    int Points = 0;
    int PointsEqual = 0;
    std::string LastPoint;
    for (const auto& [Point, File] : ReadIndex(CaptureDir)) {
      const std::optional<StateSnapshot> Native = NativeSnapshot(NativeDir, Point);
      CHECK(Native.has_value());
      if (!Native) {
        continue;
      }
      ++Points;
      if (Exact) {
        PointsEqual += ReportSnapshots(std::string(Scenario) + " " + Point, ReadSnapshot(File), *Native) ? 1 : 0;
      }
      LastPoint = Point;
    }
    // the trace: the whole capture in modes S and P, its prefix in mode N (the capture stopped there)
    const std::vector<std::string> OracleTrace = TraceLines(Join(CaptureDir, "trace.jsonl"));
    const std::vector<std::string> NativeTrace = TraceLines(TracePath, Mode == "N" ? OracleTrace.size() : SIZE_MAX);
    const bool TraceEqual = Exact && CompareTraceLines(std::string(Scenario) + " trace", OracleTrace, NativeTrace);

    // replays from the capture's before: snapshots
    int Replays = 0;
    int ReplaysEqual = 0;
    for (const char* Stage : {"find_same_name", "find_remaining_functions"}) {
      std::optional<std::string> BeforeFile;
      std::optional<std::string> AfterFile;
      for (const auto& [Point, File] : ReadIndex(CaptureDir)) {
        if (Point == std::string("before:") + Stage) {
          BeforeFile = File;
        } else if (Point == std::string("after:") + Stage) {
          AfterFile = File;
        }
      }
      if (!BeforeFile || !AfterFile) {
        continue;
      }
      DiffSession S;
      S.Log().SetQuiet(true);
      S.Open(Pair.Main, Pair.Diff);
      ++Replays;
      const StateSnapshot Native = RunReplay(S, ReadSnapshot(*BeforeFile), Stage);
      if (Exact) {
        ReplaysEqual += ReportSnapshots(std::string(Scenario) + " replay " + Stage, ReadSnapshot(*AfterFile), Native) ? 1 : 0;
      }
    }

    // the whole output: modes S and P need only lane L5 and the final pass; mode N needs every lane
    std::string Output = "not compared";
    {
      const DSig::Test::ResultsFile Expected = DSig::Test::ReadExpectedFixture(Dir);
      const DSig::Test::CompareReport Report = DSig::Test::CompareResults(Expected, Run.Results);
      const bool Ok = Exact ? Report.L2Equal : Report.L1Equal;
      DSig::Test::Report(Ok, (std::string(Scenario) + " output").c_str(), __FILE__, __LINE__);
      for (const std::string& Line : Report.Differences) {
        DSig::Test::Note("    " + Line);
      }
      Output = std::string(Exact ? "L2 " : "L1 ") + (Ok ? "equal" : "DIFFERENT");
      // the raw chooser dumps and the unmatched dump
      for (const char* Point : {"after:final_pass", "after:find_unmatched"}) {
        const std::optional<StateSnapshot> Native = NativeSnapshot(NativeDir, Point);
        CHECK(Native.has_value());
        if (Native && Exact) {
          std::string File = Point;
          File = File.substr(6) + ".json";  // "after_final_pass.json"
          ReportSnapshots(std::string(Scenario) + " " + Point, ReadSnapshot(Join(Dir, "after_" + File)), *Native);
        }
      }
      const JsonValue& Counts = Oracle.At("final_results");
      const std::string Final = "Final results: Best " + Counts.At("best").NumberText() + ", Partial " +
                                Counts.At("partial").NumberText() + ", Unreliable " +
                                Counts.At("unreliable").NumberText() + ", Multimatches " +
                                Counts.At("multimatch").NumberText();
      CHECK(std::find(Run.Log.begin(), Run.Log.end(), Final) != Run.Log.end());
    }
    DSig::Test::Note(std::string(Scenario) + ": mode " + Mode + ", points " + std::to_string(PointsEqual) + "/" +
                     std::to_string(Points) + " S-L2 equal (last " + LastPoint + "), trace " +
                     std::to_string(OracleTrace.size()) + " events " + (TraceEqual ? "identical" : "not compared/DIFFERENT") +
                     ", replays " + std::to_string(ReplaysEqual) + "/" + std::to_string(Replays) + ", output " + Output);
  }
}

// =============================================================================================
// 3. The mutation vectors

// The DiaphoraWouldRaise site that corresponds to a Python frame: "D:<line>" in diaphora.py,
// "<relative file>:<line>" elsewhere in the checkout.
std::string SiteOfFrame(const JsonValue& Frame) {
  const std::string File = Frame.At("file").AsString();
  const std::string Line = Frame.At("line").NumberText();
  return File == "diaphora.py" ? "D:" + Line : File + ":" + Line;
}

std::vector<std::string> ComparedLog(const std::vector<std::string>& Lines, bool WithFinal) {
  std::vector<std::string> Out;
  for (const std::string& Line : Lines) {
    if (IsComparedLogLine(Line) && (WithFinal || !Line.starts_with("Final results:"))) {
      Out.push_back(Line);
    }
  }
  return Out;
}

void TestVectors(const std::string& Scratch) {
  DSig::Test::Suite("vectors: fixture mutations diffed by real Diaphora (tests/diff/fixtures/early/vectors.json)");
  if (DSig::Test::TestDataDir().empty()) {
    DSig::Test::Skip("vectors", "DSIG_TEST_DATA_DIR is not set");
    return;
  }
  const JsonValue File = JsonParse(Detail::ReadFileBytes(Join(EarlyDir(), "vectors.json")));
  const bool Exact = DSig::Test::OracleSqlite();
  int Run = 0;
  int Passed = 0;
  int Raising = 0;
  int Refused = 0;
  for (const JsonValue& V : File.At("vectors").Items()) {
    const std::string Name = V.At("name").AsString();
    const std::string Work = Join(Scratch, "vector-" + Name);
    DbPair Pair;
    const std::string Failure = BuildPair(V.At("base").AsString(), V.At("main_sql").AsString(),
                                          V.At("diff_sql").AsString(), Join(Work, "db"), Pair);
    CHECK_TEXT_EQ(Failure, "");
    if (!Failure.empty()) {
      continue;
    }
    ++Run;
    const int FailedBefore = DSig::Test::ChecksFailed;
    const std::string NativeDir = Join(Work, "native");
    const NativeRun R = RunNative(Pair, Join(Work, "out.diaphora"), NativeDir);
    const bool PythonRaised = V.At("exit_code").AsInt64() != 0;
    const std::string Label = "vector " + Name;
    if (V.At("native_unsupported").AsBool()) {
      // documented refusals (exit 4): the native engine does not guess what Python's float sum() decides
      ++Refused;
      DSig::Test::Report(R.Unsupported, (Label + " is refused (UnsupportedInput)").c_str(), __FILE__, __LINE__);
      if (!R.Unsupported) {
        DSig::Test::Note("    native: " + (R.Raised ? R.What : std::string("no refusal")));
      }
    } else if (PythonRaised) {
      ++Raising;
      // Diaphora raised: no output file; the native engine raises DIAPHORA_WOULD_RAISE at the same site.
      CHECK(!V.At("output_written").AsBool());
      const JsonValue& Exception = V.At("exception");
      const std::string Site = SiteOfFrame(Exception.At("frame"));
      const std::string Type = Exception.At("type").AsString();
      const bool Ok = R.Raised && R.Site.find(Site) != std::string::npos && R.What.find(Type) != std::string::npos;
      DSig::Test::Report(Ok, (Label + " raises " + Type + " at " + Site).c_str(), __FILE__, __LINE__);
      if (!Ok) {
        DSig::Test::Note("    native: " + (R.Raised ? R.What : R.Unsupported ? "unsupported: " + R.What : "no raise"));
      }
    } else {
      CHECK(!R.Raised && !R.Unsupported);
      if (R.Raised || R.Unsupported) {
        DSig::Test::Note("    " + Label + " native: " + R.What);
        continue;
      }
      CHECK_TEXT_EQ(std::string(1, R.Mode), V.At("mode").AsString());
      // the log lines (the "Final results" line only when every stage of the run is implemented)
      std::vector<std::string> Expected;
      for (const JsonValue& Line : V.At("log").Items()) {
        Expected.push_back(Line.AsString());
      }
      Expected = ComparedLog(Expected, true);
      if (V.At("native_log_omitted").AsBool()) {
        // a float took part in check_callgraph's sums: the value is not reproduced (Preflight.cpp)
        Expected.erase(std::remove_if(Expected.begin(), Expected.end(),
                                      [](const std::string& L) { return L.starts_with("Call graphs from both"); }),
                       Expected.end());
      }
      CHECK_TEXT_EQ(Joined(ComparedLog(R.Log, true)), Joined(Expected));
      // the output rows (modes S and P, or an early return): compared when every stage ran
      if (V.Find("results") != nullptr) {
        DSig::Test::ResultsFile Want;
        Want.Schema = DSig::Test::DiaphoraSchema();
        Want.Config.push_back({"", "", "3.4", ""});
        for (const JsonValue& Row : V.At("results").Items()) {
          const auto Text = [&](size_t I) { return Row.Items()[I].IsNull() ? std::string() : Row.Items()[I].AsString(); };
          DSig::Test::ResultsRow Out;
          Out.Type = Text(0);
          Out.Line = Text(1);
          Out.Address = Text(2);
          Out.Name = Text(3);
          Out.NameNull = Row.Items()[3].IsNull();
          Out.Address2 = Text(4);
          Out.Name2 = Text(5);
          Out.Name2Null = Row.Items()[5].IsNull();
          Out.Ratio = Text(6);
          Out.Nodes1 = Text(7);
          Out.Nodes2 = Text(8);
          Out.Description = Text(9);
          Want.Results.push_back(Out);
        }
        for (const JsonValue& Row : V.At("unmatched").Items()) {
          DSig::Test::UnmatchedRowText Out;
          Out.Type = Row.Items()[0].AsString();
          Out.Line = Row.Items()[1].AsString();
          Out.Address = Row.Items()[2].AsString();
          Out.NameNull = Row.Items()[3].IsNull();
          Out.Name = Out.NameNull ? std::string() : Row.Items()[3].AsString();
          Want.Unmatched.push_back(Out);
        }
        const DSig::Test::CompareReport Report = DSig::Test::CompareResults(Want, R.Results);
        DSig::Test::Report(Exact ? Report.L2Equal : Report.L1Equal, (Label + " output").c_str(), __FILE__, __LINE__);
        for (const std::string& Line : Report.Differences) {
          DSig::Test::Note("    " + Line);
        }
      }
      // the early points of a mode-N run
      if (const JsonValue* Early = V.Find("early_points"); Early != nullptr && Exact) {
        for (const auto& [Point, Snapshot] : Early->Members()) {
          const std::optional<StateSnapshot> Native = NativeSnapshot(NativeDir, Point);
          CHECK(Native.has_value());
          if (Native) {
            ReportSnapshots(Label + " " + Point, ParseSnapshot(JsonWrite(Snapshot)), *Native);
          }
        }
      }
    }
    if (DSig::Test::ChecksFailed == FailedBefore) {
      ++Passed;
    }
  }
  DSig::Test::Note(std::to_string(Passed) + "/" + std::to_string(Run) + " vectors passed (" + std::to_string(Raising) +
                   " where Diaphora raises, " + std::to_string(Refused) + " refused as not ported)");
  // The empty-result path through the CLI entry point (plan §3.10, 01 §5.1): no diff.version table ->
  // diff() returns False, save_results still writes the config row and empty tables. Audit F06 (v1.0.0
  // product decision): the file stays Diaphora's, byte for byte, but RunDiff reports Unsupported (exit 4)
  // with a message naming db2, so a caller never takes the empty file for "nothing matched".
  for (const JsonValue& V : File.At("vectors").Items()) {
    const std::string Name = V.At("name").AsString();
    if (Name != "version_missing" && Name != "version_empty") {
      continue;
    }
    const std::string Work = Join(Scratch, "rundiff-" + Name);
    DbPair Pair;
    if (!BuildPair(V.At("base").AsString(), V.At("main_sql").AsString(), V.At("diff_sql").AsString(),
                   Join(Work, "db"), Pair).empty()) {
      continue;
    }
    DiffArgs Args;
    Args.Db1 = Pair.Main;
    Args.Db2 = Pair.Diff;
    Args.Out = Join(Work, "out.diaphora");
    Args.Quiet = true;
    Args.AllowSqliteMismatch = true;
    const DiffOutcome Outcome = RunDiff(Args);
    CHECK_NUM_EQ(static_cast<int>(Outcome.Status), static_cast<int>(DiffStatus::Unsupported));
    CHECK(Outcome.Message.find("is not a usable Diaphora export") != std::string::npos);
    CHECK(Outcome.Message.find(Pair.Diff) != std::string::npos);
    CHECK(Outcome.OutputWritten && !Outcome.DiffReturned);
    const DSig::Test::ResultsFile Written = DSig::Test::ReadResultsFile(Args.Out);
    CHECK(Written.Error.empty() && Written.Results.empty() && Written.Unmatched.empty());
    CHECK(Written.Config.size() == 1 && Written.Config[0][2] == "3.4");
    CHECK(Written.Schema == DSig::Test::DiaphoraSchema());
  }
  // the threshold vectors recorded the exact percentages (C:160 inclusive, C:166 strict)
  {
    DbPair Pair;
    for (const auto& [Name, Stripped, Patch] :
         {std::tuple{"stripped_exactly_99", 99.0, -1.0}, std::tuple{"stripped_below_99", 98.0, -2.0},
          std::tuple{"patch_exactly_90", -3.0, 90.0}}) {
      for (const JsonValue& V : File.At("vectors").Items()) {
        if (V.At("name").AsString() != Name) {
          continue;
        }
        const std::string Work = Join(Scratch, std::string("threshold-") + Name);
        if (!BuildPair(V.At("base").AsString(), V.At("main_sql").AsString(), V.At("diff_sql").AsString(),
                       Join(Work, "db"), Pair).empty()) {
          continue;
        }
        const NativeRun R = RunNative(Pair, Join(Work, "out.diaphora"));
        if (Stripped >= 0) {
          CHECK(R.Facts.Stripped.Evaluated && R.Facts.Stripped.Percent == Stripped);
          CHECK_EQ(R.Facts.Stripped.Fired, Stripped >= 99.0);
        }
        if (Patch >= 0) {
          CHECK(R.Facts.Patch.Evaluated && R.Facts.Patch.Percent == Patch);
          CHECK(!R.Facts.Patch.Fired);
        }
      }
    }
  }
}

// =============================================================================================
// 4. The oracle corpus

// Export ids of a pair name ("<ref>_vs_<target>", the target optionally without the ref's family).
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

// RunPipeline's first stages (src/diff/Pipeline.cpp RunPipeline, D:3568-3627) with the same points
// and contexts, stopping after find_same_name (after find_remaining_functions in modes S and P): the
// later passes of a mode-N pair belong to other lanes (and take hours on the long pairs).
std::map<std::string, StateSnapshot> DriveEarlyStages(DiffSession& S) {
  std::map<std::string, StateSnapshot> Points;
  const auto Mark = [&](const std::string& Name) {
    S.Point(Name);
    Points[Name] = S.Snapshot(Name);
  };
  ContextScope Root(S, "diff");
  S.Engine().ClearCache();
  S.SetIteration(std::nullopt);
  if (!StageCheckVersion(S)) {
    return Points;
  }
  S.RequireIngest();
  if (StageEqualDb(S)) {
    S.Log().Info("The databases seems to be 100% equal");
  }
  StageCheckCallgraph(S);
  {
    ContextScope Scope(S, "find_equal_matches");
    StageFindEqualMatches(S);
  }
  Mark("after:find_equal_matches");
  S.Flags().IsSameProcessor = StageSameProcessor(S);
  S.Engine().Prepare();
  bool Skip = false;
  {
    ContextScope Scope(S, "apply_dirty_heuristics");
    Skip = StageApplyDirtyHeuristics(S);
  }
  Mark("after:apply_dirty_heuristics");
  Mark("before:find_same_name");
  {
    ContextScope Scope(S, "find_same_name");
    StageFindSameName(S);
  }
  Mark("after:find_same_name");
  if (Skip) {
    Mark("before:find_remaining_functions");
    {
      ContextScope Scope(S, "find_remaining_functions");
      StageFindRemainingFunctions(S);
    }
    Mark("after:find_remaining_functions");
  }
  return Points;
}

// snapshots/NNNNN_<sanitised point>.json of a capture, by point (never reads index.json: some
// captures are still being written by their oracle process).
std::optional<std::string> CaptureSnapshotFile(const std::string& Dir, const std::string& Point) {
  const std::string Suffix = "_" + SanitisePointName(Point) + ".json";
  std::error_code Error;
  for (const fs::directory_entry& Entry : fs::directory_iterator(Utf8ToPath(Join(Dir, "snapshots")), Error)) {
    const std::string Name = PathToUtf8(Entry.path().filename());
    if (Name.size() > Suffix.size() && Name.compare(Name.size() - Suffix.size(), Suffix.size(), Suffix) == 0 &&
        Name[0] >= '0' && Name[0] <= '9') {
      return PathToUtf8(Entry.path());
    }
  }
  return std::nullopt;
}

std::vector<std::string> DiaphoraLogLines(const std::string& Path, bool (*Keep)(std::string_view)) {
  std::vector<std::string> Out;
  if (!IsFile(Path)) {
    return Out;
  }
  for (const std::string& Raw : SplitLines(Detail::ReadFileBytes(Path))) {
    // "[Diaphora: <asctime>] INFO: <message>"
    if (!Raw.starts_with("[Diaphora: ")) {
      continue;
    }
    const size_t Close = Raw.find("] ");
    if (Close == std::string::npos) {
      continue;
    }
    const size_t Colon = Raw.find(": ", Close + 2);
    if (Colon == std::string::npos) {
      continue;
    }
    const std::string Message = Raw.substr(Colon + 2);
    if (Keep(Message)) {
      Out.push_back(Message);
    }
  }
  return Out;
}

bool IsEarlyLogLine(std::string_view Line) {
  return StartsWithAny(Line, {"The databases seems to be 100% equal", "Same MD5 in both databases", "Call graph",
                              "Symbols stripped detected:", "Patch diffing detected:"});
}

std::string Fixed3(double Value) {
  char Buffer[64];
  std::snprintf(Buffer, sizeof(Buffer), "%.3f", Value);
  return Buffer;
}

struct CorpusPair {
  const char* Name;
  const char* StrippedPercent;  // 05 §19.1 ("%.3f"); nullptr when the spec gives none
  const char* PatchPercent;     // nullptr: not in the spec; "-": not evaluated (stripped fired)
  int EqualRows;                // find_equal_matches rows (05 §19.1; the extension pairs from their traces)
};

void TestCorpus(const std::string& Scratch) {
  DSig::Test::Suite("corpus: early points (S-L2), traces, replays, dirty percentages, full runs of modes S and P");
  if (!DSig::Test::CorpusRoot()) {
    DSig::Test::Skip("corpus", "DSIG_CORPUS_ROOT is not set");
    return;
  }
  if (!DSig::Test::OracleSqlite()) {
    DSig::Test::Skip("corpus", "SQLite " + DiffDatabase::LibVersion() + " is not the oracle's 3.51.1 (row order)");
    return;
  }
  // The six finished captures, the userenv prefix capture and the part of the killed sechost capture
  // that was written (its snapshots up to after:cleanup:3413:1 are valid). The running re-captures
  // (".full", ".prefix2") are never read.
  static const CorpusPair Pairs[] = {
      {"ls-old_vs_ls", "2.961", "37.500", 0},
      {"ls_vs_ls-old", "2.830", "35.849", 0},
      {"userenv-9168-pdb_vs_9278-pdb", "4.821", "100.000", 0},
      {"userenv-9168-pdb_vs_9278-nopdb", "4.666", "9.331", 0},
      {"sechost-9168-pdb_vs_9444-nopdb", "61.234", "15.811", 4},
      {"cryptbase-1-pdb_vs_8875-nopdb", nullptr, nullptr, 1},
      {"win32u-9168-useri64_vs_9444-nopdb", nullptr, "-", 178},
      {"cryptbase-8875-pdb_vs_9444-nopdb", nullptr, "-", 14},
  };
  int Captures = 0;
  for (const CorpusPair& Entry : Pairs) {
    const std::string Pair = Entry.Name;
    const std::string Capture = DSig::Test::TracesDir(Pair);
    const auto Ids = ExportIdsOfPair(Pair);
    if (!Ids || !CaptureSnapshotFile(Capture, "after:find_same_name")) {
      DSig::Test::Note(Pair + ": skipped (exports or capture not found)");
      continue;
    }
    ++Captures;
    const DbPair Dbs{DSig::Test::ExportPath(Ids->first), DSig::Test::ExportPath(Ids->second)};
    const std::string Work = Join(Scratch, "corpus-" + Pair);
    std::error_code Error;
    fs::create_directories(Utf8ToPath(Work), Error);

    // (a) the early stages from the start, S-L2 at every early point, and the trace prefix
    int Points = 0;
    int PointsEqual = 0;
    std::string LastPoint;
    Early::EarlyFacts Facts;
    std::vector<std::string> NativeLog;
    char Mode = 'N';
    {
      DiffSession S;
      S.Log().SetQuiet(true);
      S.Open(Dbs.Main, Dbs.Diff);
      S.SetPairLabel(Pair);
      const std::string TracePath = Join(Work, "trace.jsonl");
      S.EnableTrace(TracePath, true);
      std::map<std::string, StateSnapshot> Native;
      try {
        Native = DriveEarlyStages(S);
      } catch (const std::exception& Failure) {
        DSig::Test::Report(false, (Pair + " early stages threw: " + Failure.what()).c_str(), __FILE__, __LINE__);
      }
      S.FinishHarness();
      for (const auto& [Point, Snapshot] : Native) {
        const std::optional<std::string> File = CaptureSnapshotFile(Capture, Point);
        CHECK(File.has_value());
        if (!File) {
          continue;
        }
        ++Points;
        PointsEqual += ReportSnapshots(Pair + " " + Point, ReadSnapshot(*File), Snapshot) ? 1 : 0;
      }
      LastPoint = Native.count("after:find_remaining_functions") != 0 ? "after:find_remaining_functions"
                                                                      : "after:find_same_name";
      CompareTraceLines(Pair + " trace up to " + LastPoint, TraceUpTo(Join(Capture, "trace.jsonl"), LastPoint),
                        TraceLines(TracePath));
      Facts = S.Ext<Early::EarlyFacts>();
      NativeLog = S.Log().Lines();
      Mode = S.Mode();
    }
    // (b) the log lines of the passes before any matching
    CHECK_TEXT_EQ(Joined(ComparedLog(NativeLog, false)),
                  Joined(DiaphoraLogLines(Join(Capture, "diaphora.log"), IsEarlyLogLine)));
    // (c) 05 §19.1: the dirty-heuristic percentages and the "100% equal" rows
    CHECK_NUM_EQ(Facts.EqualRows, Entry.EqualRows);
    if (Entry.StrippedPercent != nullptr) {
      CHECK_TEXT_EQ(Fixed3(Facts.Stripped.Percent), Entry.StrippedPercent);
    }
    if (Entry.PatchPercent != nullptr && std::string(Entry.PatchPercent) != "-") {
      CHECK(Facts.Patch.Evaluated);
      CHECK_TEXT_EQ(Fixed3(Facts.Patch.Percent), Entry.PatchPercent);
    }
    if (Entry.PatchPercent != nullptr && std::string(Entry.PatchPercent) == "-") {
      CHECK(!Facts.Patch.Evaluated);  // short-circuit (D:2633-2634)
    }
    // (d) replays from the capture's before: snapshots
    int Replays = 0;
    int ReplaysEqual = 0;
    for (const char* Stage : {"find_same_name", "find_remaining_functions"}) {
      const auto Before = CaptureSnapshotFile(Capture, std::string("before:") + Stage);
      const auto After = CaptureSnapshotFile(Capture, std::string("after:") + Stage);
      if (!Before || !After) {
        continue;
      }
      DiffSession S;
      S.Log().SetQuiet(true);
      S.Open(Dbs.Main, Dbs.Diff);
      ++Replays;
      try {
        ReplaysEqual += ReportSnapshots(Pair + " replay " + Stage, ReadSnapshot(*After),
                                        RunReplay(S, ReadSnapshot(*Before), Stage))
                            ? 1
                            : 0;
      } catch (const std::exception& Failure) {
        DSig::Test::Report(false, (Pair + " replay " + Stage + " threw: " + Failure.what()).c_str(), __FILE__, __LINE__);
      }
    }
    std::string Summary = Pair + ": mode " + std::string(1, Mode) + ", early points " + std::to_string(PointsEqual) +
                          "/" + std::to_string(Points) + " S-L2 equal (to " + LastPoint + "), replays " +
                          std::to_string(ReplaysEqual) + "/" + std::to_string(Replays) + ", equal rows " +
                          std::to_string(Facts.EqualRows) + ", stripped " + Fixed3(Facts.Stripped.Percent) + "%" +
                          (Facts.Patch.Evaluated ? ", patch " + Fixed3(Facts.Patch.Percent) + "%" : std::string()) +
                          ", same-name rows " + std::to_string(Facts.SameNameRows) + " (" +
                          std::to_string(Facts.SameNameSkippedSub) + " sub_ skipped)";

    // (e) modes S and P need only lane L5 and the final pass: the whole run at L2 and its trace
    if (Mode != 'N') {
      const std::string Oracle = DSig::Test::OracleResultsPath(Pair, 1);
      const std::string TracePath = Join(Work, "full-trace.jsonl");
      const NativeRun R = RunNative(Dbs, Join(Work, Pair + ".diaphora"), std::string(), TracePath, Pair);
      CHECK(!R.Raised && !R.Unsupported);
      const DSig::Test::CompareReport Report =
          DSig::Test::CompareResults(DSig::Test::ReadResultsFile(Oracle), R.Results);
      DSig::Test::Report(Report.DdlEqual && Report.L2Equal, (Pair + " full run L2").c_str(), __FILE__, __LINE__);
      for (const std::string& Line : Report.Differences) {
        DSig::Test::Note("    " + Line);
      }
      const bool TraceEqual = CompareTraceLines(Pair + " full trace", TraceLines(Join(Capture, "trace.jsonl")),
                                                TraceLines(TracePath));
      // the "Final results" line of the oracle's own run1 log
      const std::vector<std::string> OracleFinal = DiaphoraLogLines(
          Join(Join(Join(Join(DSig::Test::OracleDir(), "diffs"), Pair), "run1"), "diaphora.log"),
          [](std::string_view L) { return L.starts_with("Final results:"); });
      const std::vector<std::string> NativeFinal = ComparedLog(R.Log, true);
      CHECK(!OracleFinal.empty() && std::find(NativeFinal.begin(), NativeFinal.end(), OracleFinal.back()) != NativeFinal.end());
      Summary += ", full run: " + std::string(Report.L2Equal ? "L2 EQUAL" : "L2 DIFFERENT") + " (" +
                 std::to_string(R.Results.Results.size()) + " results, " + std::to_string(R.Results.Unmatched.size()) +
                 " unmatched rows), trace " + (TraceEqual ? "identical" : "DIFFERENT") + ", " +
                 (OracleFinal.empty() ? std::string("no oracle Final line") : OracleFinal.back());
    }
    DSig::Test::Note(Summary);
  }
  if (Captures == 0) {
    DSig::Test::Skip("corpus", "no oracle capture found under " + DSig::Test::OracleDir());
  }
}

void Run(const char* Name, const std::function<void()>& F) {
  try {
    F();
  } catch (const std::exception& Error) {
    DSig::Test::Report(false, (std::string(Name) + " threw: " + Error.what()).c_str(), __FILE__, __LINE__);
  }
}

}  // namespace

int main() {
  const std::string Scratch = DSig::Test::ScratchDir("diff_early");
  Run("hook", TestHook);
  Run("fixtures", [&] { TestFixtures(Scratch); });
  Run("vectors", [&] { TestVectors(Scratch); });
  Run("corpus", [&] { TestCorpus(Scratch); });
  DSig::Test::RemoveScratchDir(Scratch);
  return DSig::Test::Finish();
}
