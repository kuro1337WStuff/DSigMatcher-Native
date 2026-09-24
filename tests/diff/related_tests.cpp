// diff_related: related constants, related compilation unit and local affinity (spec 06 §7-§11,
// 07 §10.11.2-§10.11.4, 02 §18.2, 08 H-4).
//
//   * fixture vectors (tests/diff/fixtures/related/, recorded from REAL Diaphora by generate.py there):
//     every case restores a starting state, runs one stage and must reproduce Diaphora's state after
//     it, its add_match calls and the rows of every cursor it consumed, or raise where Diaphora raised;
//   * unit tests: the 06 §8.3 abs() table through the verbatim SQL, the 06 §11.1 lexicographic gap
//     probe, CuReplaySource vs SqlRowSource on fixture and edge-case databases (identical rows and
//     identical failures at the same row), the plan guard's fallback to SQL, the constant-order hook,
//     and the fetch-time failure sites (get_function_row swallows, the CU lookup and gap fetches raise);
//   * corpus replays (skip without DSIG_CORPUS_ROOT or the oracle captures): every before:<stage>:k ->
//     RunReplay -> after:<stage>:k of the three stages at S-L2, plus the stage's add_match (and, when
//     recorded, row) trace events against the oracle's. find_related_matches iterates a CPython set
//     (D:3389, 06 §8.3): its difference is classified as the tolerated class with exact counts, and replayed
//     again with the capture's own CPython order (<corpus>/oracle/vectors/related/<capture>.set_order.json,
//     generate.py set-order) when that file exists;
//   * CuReplaySource vs SqlRowSource row sequences on the long pairs' seeds and the native related-CU
//     timing (DSIG_RELATED_LONG=1: 50 seeds per pair and the long related-CU replays).
//
// Oracle files are only read, never from Python: snapshots and run.json through the shared-delete reader
// (a running capture replaces run.json / index.json with os.replace; index.json is never read), traces
// with std::ifstream (the oracle only appends to trace.jsonl), exports through immutable=1 connections
// (DiffDatabase opens inputs immutable).

#include <sqlite3.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <functional>
#include <limits>
#include <map>
#include <optional>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "../../src/diff/FileIo.h"
#include "../../src/diff/stages/RelatedDetail.h"
#include "diff/CorpusPaths.h"
#include "diff/FixtureDb.h"
#include "diff/ResultsCompare.h"
#include "diff/TestHarness.h"
#include "dsigmatcher/diff/Config.h"
#include "dsigmatcher/diff/Consumer.h"
#include "dsigmatcher/diff/Errors.h"
#include "dsigmatcher/diff/Json.h"
#include "dsigmatcher/diff/Pipeline.h"
#include "dsigmatcher/diff/PyValue.h"
#include "dsigmatcher/diff/Snapshot.h"
#include "dsigmatcher/diff/StageSql.h"
#include "dsigmatcher/diff/Stages.h"
#include "dsigmatcher/diff/Trace.h"

namespace fs = std::filesystem;
using namespace DSig::Diff;

namespace {

// ---------------------------------------------------------------------------------------------
// Helpers

bool LongEnabled() {
  const auto Value = DSig::Test::GetEnv("DSIG_RELATED_LONG");
  return Value && !Value->empty() && *Value != "0";
}

// DSIG_RELATED_ONLY=<substring>: run only the corpus cases whose label contains it (debugging aid).
bool Selected(const std::string& Label) {
  const auto Only = DSig::Test::GetEnv("DSIG_RELATED_ONLY");
  return !Only || Only->empty() || Label.find(*Only) != std::string::npos;
}

double Seconds(std::chrono::steady_clock::time_point Start) {
  return std::chrono::duration<double>(std::chrono::steady_clock::now() - Start).count();
}

std::string Fixed(double Value, int Digits = 1) {
  char Buffer[64];
  std::snprintf(Buffer, sizeof(Buffer), "%.*f", Digits, Value);
  return Buffer;
}

void Run(const char* Name, const std::function<void()>& F) {
  try {
    F();
  } catch (const std::exception& Error) {
    DSig::Test::Report(false, (std::string(Name) + " threw: " + Error.what()).c_str(), __FILE__, __LINE__);
  }
}

void Notes(const DSig::Test::CompareReport& Report) {
  for (const std::string& Line : Report.Differences) {
    DSig::Test::Note("    " + Line);
  }
}

// Runs F; returns "" when it returned, else "raise:<site>" (DiaphoraWouldRaise), "unsupported" or "other".
std::string Outcome(const std::function<void()>& F, std::string* Detail = nullptr) {
  try {
    F();
  } catch (const DiaphoraWouldRaise& Error) {
    if (Detail != nullptr) {
      *Detail = Error.what();
    }
    return "raise";
  } catch (const UnsupportedInput& Error) {
    if (Detail != nullptr) {
      *Detail = Error.What;
    }
    return "unsupported";
  } catch (const std::exception& Error) {
    if (Detail != nullptr) {
      *Detail = Error.what();
    }
    return "other";
  }
  return "";
}

std::vector<std::string> ReadLines(const std::string& Path) {
  std::vector<std::string> Lines;
  std::ifstream In(DSig::Test::Utf8ToPath(Path), std::ios::binary);
  std::string Line;
  while (std::getline(In, Line)) {
    if (!Line.empty()) {
      Lines.push_back(Line);
    }
  }
  return Lines;
}

// The native trace of a replay as the fixture vectors record it: add_match events as
// [name1, name2, ea1, ea2, desc, ratio_bits, chooser, result] and row events as [ea1, ea2].
struct NativeEvents {
  std::vector<std::string> AddMatch;
  std::vector<std::string> Rows;
};

NativeEvents ReadNativeEvents(const std::string& Path) {
  NativeEvents Out;
  for (const std::string& Line : ReadLines(Path)) {
    const JsonValue E = JsonParse(Line);
    const std::string& Ev = E.At("ev").AsString();
    if (Ev == "add_match") {
      JsonValue A = JsonValue::Array();
      for (const char* Key : {"name1", "name2", "ea1", "ea2", "desc", "ratio_bits", "chooser", "result"}) {
        A.Push(E.At(Key));
      }
      Out.AddMatch.push_back(JsonWrite(A));
    } else if (Ev == "row") {
      JsonValue A = JsonValue::Array();
      A.Push(E.At("ea1"));
      A.Push(E.At("ea2"));
      Out.Rows.push_back(JsonWrite(A));
    }
  }
  return Out;
}

std::vector<std::string> JsonLines(const JsonValue& Array) {
  std::vector<std::string> Out;
  for (const JsonValue& V : Array.Items()) {
    Out.push_back(JsonWrite(V));
  }
  return Out;
}

bool SameSequence(std::vector<std::string> A, std::vector<std::string> B, bool Ordered, std::string& First) {
  if (!Ordered) {
    std::sort(A.begin(), A.end());
    std::sort(B.begin(), B.end());
  }
  for (size_t I = 0; I < std::max(A.size(), B.size()); ++I) {
    const std::string X = I < A.size() ? A[I] : "<end>";
    const std::string Y = I < B.size() ? B[I] : "<end>";
    if (X != Y) {
      First = "[" + std::to_string(I) + "] expected " + X + " native " + Y;
      return false;
    }
  }
  return true;
}

// S-L2 (docs/parity/README.md, "Comparison levels"), or L1 (lists as multisets) when the runtime SQLite
// is not the oracle's.
DSig::Test::CompareReport CompareState(const StateSnapshot& Expected, const StateSnapshot& Native, bool Ordered) {
  if (Ordered) {
    return DSig::Test::CompareSnapshots(Expected, Native, 10);
  }
  StateSnapshot A = Expected;
  StateSnapshot B = Native;
  for (StateSnapshot* S : {&A, &B}) {
    for (std::vector<SnapItem>* L : {&S->Best, &S->Partial, &S->Unreliable}) {
      std::sort(L->begin(), L->end(), [](const SnapItem& X, const SnapItem& Y) {
        return std::tie(X.Ea1, X.Name1, X.Ea2, X.Name2, X.Desc, X.RatioBits, X.Nodes1, X.Nodes2) <
               std::tie(Y.Ea1, Y.Name1, Y.Ea2, Y.Name2, Y.Desc, Y.RatioBits, Y.Nodes1, Y.Nodes2);
      });
    }
  }
  return DSig::Test::CompareSnapshots(A, B, 10);
}

bool SameRow(const HeuristicRow& A, const HeuristicRow& B) {
  const auto Bits = [](const std::optional<double>& V) { return V ? RatioBits(*V) : ~uint64_t{0}; };
  return A.Ea1 == B.Ea1 && A.Ea2 == B.Ea2 && A.Row1 == B.Row1 && A.Row2 == B.Row2 && A.Side1 == B.Side1 &&
         A.Side2 == B.Side2 && A.Name1 == B.Name1 && A.Name2 == B.Name2 && A.Desc == B.Desc && A.Nodes1 == B.Nodes1 &&
         A.Nodes2 == B.Nodes2 && A.Md1.has_value() == B.Md1.has_value() && A.Md2.has_value() == B.Md2.has_value() &&
         Bits(A.Md1) == Bits(B.Md1) && Bits(A.Md2) == Bits(B.Md2);
}

struct SequenceResult {
  bool Same = true;
  uint64_t Rows = 0;
  std::string End;  // "" (both exhausted) or the failure both raised at the same row
  std::string Why;
};

// Walks CuReplaySource and SqlRowSource over the same bounds in lockstep: every row equal, and when one
// raises, the other raises the same way at the same row.
SequenceResult CompareCuSources(DiffSession& S, double Lo1, double Hi1, double Lo2, double Hi2) {
  SequenceResult R;
  std::optional<CuReplaySource> Native;
  std::optional<SqlRowSource> Sql;
  Native.emplace(S, Lo1, Hi1, Lo2, Hi2);
  Sql.emplace(S, std::string(kSqlCuCartesian),
              std::vector<BindValue>{BindValue::Double(Lo1), BindValue::Double(Hi1), BindValue::Double(Lo2),
                                     BindValue::Double(Hi2)});
  while (true) {
    HeuristicRow A;
    HeuristicRow B;
    bool HaveA = false;
    bool HaveB = false;
    const std::string EndA = Outcome([&] { HaveA = Native->Next(A); });
    const std::string EndB = Outcome([&] { HaveB = Sql->Next(B); });
    if (EndA != EndB) {
      R.Same = false;
      R.Why = "row " + std::to_string(R.Rows) + ": native '" + EndA + "' sql '" + EndB + "'";
      return R;
    }
    if (!EndA.empty()) {
      R.End = EndA;
      return R;
    }
    if (HaveA != HaveB) {
      R.Same = false;
      R.Why = "lengths differ after " + std::to_string(R.Rows) + " rows";
      return R;
    }
    if (!HaveA) {
      return R;
    }
    ++R.Rows;
    if (!SameRow(A, B)) {
      R.Same = false;
      R.Why = "row " + std::to_string(R.Rows) + " differs";
      return R;
    }
  }
}

// ---------------------------------------------------------------------------------------------
// Fixtures (tests/diff/fixtures/related)

std::string FixtureDir() {
  return DSig::Test::PathToUtf8(DSig::Test::Utf8ToPath(DSig::Test::TestDataDir()) / "fixtures" / "related");
}

// Builds <Scratch>/<Name>_<scenario>_{main,diff}.sqlite from the committed dumps. Returns "" or an error.
std::string BuildScenario(const std::string& Scratch, const std::string& Scenario, const std::string& Name,
                          std::string& Main, std::string& Diff) {
  const fs::path Dir = DSig::Test::Utf8ToPath(Scratch);
  Main = DSig::Test::PathToUtf8(Dir / (Name + "_main.sqlite"));
  Diff = DSig::Test::PathToUtf8(Dir / (Name + "_diff.sqlite"));
  const fs::path Src = DSig::Test::Utf8ToPath(FixtureDir());
  std::string Error = DSig::Test::BuildFixtureDb(DSig::Test::PathToUtf8(Src / (Scenario + "_main.sql")), Main);
  if (Error.empty()) {
    Error = DSig::Test::BuildFixtureDb(DSig::Test::PathToUtf8(Src / (Scenario + "_diff.sql")), Diff);
  }
  return Error;
}

// Runs SQL on a scratch fixture database (read-write; never an input of the oracle).
std::string Exec(const std::string& Db, const std::string& Sql) {
  sqlite3* Handle = nullptr;
  if (sqlite3_open_v2(Db.c_str(), &Handle, SQLITE_OPEN_READWRITE, nullptr) != SQLITE_OK) {
    sqlite3_close(Handle);
    return "cannot open " + Db;
  }
  char* Message = nullptr;
  std::string Error;
  if (sqlite3_exec(Handle, Sql.c_str(), nullptr, nullptr, &Message) != SQLITE_OK) {
    Error = Message != nullptr ? Message : "exec failed";
  }
  sqlite3_free(Message);
  sqlite3_close(Handle);
  return Error;
}

StateSnapshot SnapshotOf(const JsonValue& V) { return ParseSnapshot(JsonWrite(V)); }

// The fixture vectors: real Diaphora's outcome for every case of generate.py.
void TestFixtureVectors(const std::string& Scratch) {
  DSig::Test::Suite("fixture vectors from real Diaphora (tests/diff/fixtures/related/cases.json)");
  const std::string CasesPath = DSig::Test::PathToUtf8(DSig::Test::Utf8ToPath(FixtureDir()) / "cases.json");
  if (!Detail::PathExists(CasesPath)) {
    DSig::Test::Skip("fixture vectors", "cases.json not found under " + FixtureDir());
    return;
  }
  const bool Ordered = DSig::Test::OracleSqlite();
  if (!Ordered) {
    DSig::Test::Note("SQLite " + DiffDatabase::LibVersion() + " is not 3.51.1: rows and lists compared as multisets (L1)");
  }
  const JsonValue Doc = JsonParse(Detail::ReadFileBytes(CasesPath));
  int Passed = 0;
  int Total = 0;
  for (const JsonValue& Case : Doc.At("cases").Items()) {
    const std::string Name = Case.At("name").AsString();
    const std::string Stage = Case.At("stage").AsString();
    std::vector<RelatedCuSource> Sources = {RelatedCuSource::Native};
    if (Stage == "find_related_compilation_unit") {
      Sources.push_back(RelatedCuSource::Sql);  // both candidate sources must give Diaphora's result
    }
    for (const RelatedCuSource Source : Sources) {
      const std::string Label =
          Name + (Stage == "find_related_compilation_unit" ? (Source == RelatedCuSource::Native ? " [native CU]" : " [sql CU]")
                                                           : "");
      ++Total;
      std::string Main;
      std::string Diff;
      const std::string Built = BuildScenario(Scratch, Case.At("scenario").AsString(), "fx_" + Name, Main, Diff);
      CHECK_TEXT_EQ(Built, "");
      if (!Built.empty()) {
        continue;
      }
      const std::string TracePath = DSig::Test::PathToUtf8(DSig::Test::Utf8ToPath(Scratch) / ("fx_" + Name + ".jsonl"));
      std::string RaisedDetail;
      std::string Result;
      StateSnapshot Native;
      {
        DiffSession S;
        S.Log().SetQuiet(true);
        S.SetCuSource(Source);
        S.Open(Main, Diff);
        S.EnableTrace(TracePath, true);
        const StateSnapshot Before = SnapshotOf(Case.At("before"));
        Result = Outcome([&] { Native = RunReplay(S, Before, Stage + ":0"); }, &RaisedDetail);
        S.FinishHarness();
      }
      const NativeEvents Events = ReadNativeEvents(TracePath);
      bool Ok = true;
      const JsonValue& Raised = Case.At("raised");
      if (!Raised.IsNull()) {
        Ok = Result == "raise";
        DSig::Test::Report(Ok, (Label + ": raises like Python (" + Raised.At("type").AsString() + ")").c_str(), __FILE__,
                           __LINE__);
        if (!Ok) {
          DSig::Test::Note("    native outcome '" + Result + "' " + RaisedDetail);
        }
      } else {
        Ok = Result.empty();
        DSig::Test::Report(Ok, (Label + ": completes").c_str(), __FILE__, __LINE__);
        if (!Ok) {
          DSig::Test::Note("    native outcome '" + Result + "' " + RaisedDetail);
        } else {
          const DSig::Test::CompareReport Report = CompareState(SnapshotOf(Case.At("after")), Native, Ordered);
          DSig::Test::Report(Report.L2Equal, (Label + ": state after the stage").c_str(), __FILE__, __LINE__);
          Notes(Report);
          Ok = Report.L2Equal;
        }
      }
      std::string First;
      const bool AddsEqual = SameSequence(JsonLines(Case.At("add_match")), Events.AddMatch, Ordered, First);
      DSig::Test::Report(AddsEqual, (Label + ": add_match calls").c_str(), __FILE__, __LINE__);
      if (!AddsEqual) {
        DSig::Test::Note("    " + First);
      }
      const bool RowsEqual = SameSequence(JsonLines(Case.At("rows")), Events.Rows, Ordered, First);
      DSig::Test::Report(RowsEqual, (Label + ": consumed rows (check_match calls)").c_str(), __FILE__, __LINE__);
      if (!RowsEqual) {
        DSig::Test::Note("    " + First);
      }
      Ok = Ok && AddsEqual && RowsEqual;
      Passed += Ok ? 1 : 0;
      DSig::Test::Note(Label + " (" + Stage + "): " + (Ok ? "equal" : "DIFFERS") + ", " +
                       std::to_string(Events.AddMatch.size()) + " add_match, " + std::to_string(Events.Rows.size()) +
                       " rows" + (Raised.IsNull() ? std::string() : ", raised " + Raised.At("type").AsString()));
    }
  }
  DSig::Test::Note(std::to_string(Passed) + "/" + std::to_string(Total) + " fixture cases equal to real Diaphora");
}

// ---------------------------------------------------------------------------------------------
// Unit tests on the fixture databases

// 06 §8.3: which constants survive `abs(mc.constant) == 0` (SQLite 3.51.1 probe table). The verbatim
// related-constants SQL (D:3375-3387) runs once per value; abs_probe has a constants row for each value
// on both sides, so a value passes iff it returns the one (abs_probe, abs_probe) row.
void TestAbsTable(const std::string& Scratch) {
  DSig::Test::Suite("06 §8.3 abs() table through the related-constants SQL");
  if (!DSig::Test::OracleSqlite()) {
    DSig::Test::Skip("abs table", "the table was probed on SQLite 3.51.1; runtime is " + DiffDatabase::LibVersion());
    return;
  }
  std::string Main;
  std::string Diff;
  CHECK_TEXT_EQ(BuildScenario(Scratch, "related", "abs", Main, Diff), "");
  DiffSession S;
  S.Open(Main, Diff);
  const std::vector<std::pair<std::string, bool>> Table = {
      {"hello", true},     {"4096", false},   {"123abc", false}, {"  42 apples", false}, {"0x10", true},
      {"0 files", true},   {"1e5 x", false},  {".5x", false},    {"inf", true},          {"Infinity", true},
      {"NaN", true},       {"-12", false},    {"-0", true},      {"1e999", false},       {"\t7", false},
      {"\n5", false},      {"\x0b" "5", false}, {"+3a", false},  {"0000", true},         {"e5", true},
      {"1e", false},       {".e1", true},     {"-.5", false},    {"..5", true},          {"\xd9\xa3", true},
      {"\xc2\xa0" "5", true}, {"1e-400", true}, {"1e-320", false}};
  int Passing = 0;
  for (const auto& [Value, Passes] : Table) {
    SqlRowSource Rows(S, std::string(kSqlRelatedConstants), {BindValue::Str(Value)});
    HeuristicRow Row;
    uint64_t Count = 0;
    while (Rows.Next(Row)) {
      ++Count;
    }
    Passing += Count > 0 ? 1 : 0;
    DSig::Test::Report((Count > 0) == Passes, ("abs('" + Value + "') == 0 is " + (Passes ? "true" : "false")).c_str(),
                       __FILE__, __LINE__);
  }
  DSig::Test::Note(std::to_string(Passing) + " of " + std::to_string(Table.size()) + " table inputs produce rows");
}

// 06 §11.1: `address > ? and address < ?` with str binds compares TEXT bytewise, and the rows come in
// bytewise DESC order (`order by address desc`).
void TestLexicographicGap(const std::string& Scratch) {
  DSig::Test::Suite("06 §11.1 lexicographic gap query");
  std::string Main;
  std::string Diff;
  CHECK_TEXT_EQ(BuildScenario(Scratch, "related", "lex", Main, Diff), "");
  DiffSession S;
  S.Open(Main, Diff);
  const auto Gap = [&](std::string_view Low, std::string_view High) {
    const BindValue Binds[2] = {BindValue::Str(Low), BindValue::Str(High)};
    std::string Out;
    for (const FunctionRowRef& Ref : FetchFunctionRows(S, kSqlGapMain, std::span<const BindValue>(Binds, 2), Side::Main)) {
      Out += (Out.empty() ? "" : ",") + std::string(S.Main().Functions.Address.View(Ref.Row));
    }
    return Out;
  };
  // numerically 4096 < a < 8192 holds for 5000..8191 only; as TEXT '40970' is inside too
  CHECK_TEXT_EQ(Gap("4096", "8192"), "8191,7600,7500,7000,6000,5000,40970");
  CHECK_TEXT_EQ(Gap("999", "10000"), "");      // '999' > '10000' as TEXT: an empty range
  CHECK_TEXT_EQ(Gap("9990", "10010"), "");     // the fixture's la_anchor3 -> la_anchor4 gap
}

// 06 §9.2 first_cu: `SELECT distinct ... WHERE f.name = ?` + fetchone() (D:3419-3445) returns the CU of the
// function's compilation_unit_functions link with the lowest rowid. The fixture's gamma is in cu_b (link
// rowid 1) and cu_a (rowid 5), so its seed replays cu_b's range (the related_cu fixture case checks the
// resulting rows against real Diaphora).
void TestFirstCu(const std::string& Scratch) {
  DSig::Test::Suite("06 §9.2 first_cu: a function in two compilation units");
  std::string Main;
  std::string Diff;
  CHECK_TEXT_EQ(BuildScenario(Scratch, "related", "firstcu", Main, Diff), "");
  DiffSession S;
  S.Open(Main, Diff);
  const auto Lookup = [&](std::string_view Name) {
    const BindValue Bind = BindValue::Str(Name);
    Statement Q = S.Db().Prepare(kSqlCuLookupMain, std::span<const BindValue>(&Bind, 1));
    std::string Rows;
    while (Q.Step()) {
      Rows += (Rows.empty() ? "" : ";") + std::string(Q.Text(Q.FindColumn("cu_name"))) + ":" +
              std::string(Q.Text(Q.FindColumn("start_ea"))) + "-" + std::string(Q.Text(Q.FindColumn("end_ea")));
    }
    return Rows;
  };
  if (DSig::Test::OracleSqlite()) {
    CHECK_TEXT_EQ(Lookup("gamma"), "cu_b:20500-20900;cu_a:20100-20400");  // fetchone() takes cu_b
  } else {
    CHECK_TEXT_EQ(Lookup("gamma").substr(0, 4), "cu_b");
  }
  CHECK_TEXT_EQ(Lookup("alpha"), "cu_a:20100-20400");
  CHECK_TEXT_EQ(Lookup("no_such_function"), "");
}

// CuReplaySource == SqlRowSource on the fixture pair plus edge-case rows (06 §9.2): NULL / non-numeric /
// padded / negative / huge / fractional addresses, NULL md_index / nodes / name, and rows whose fetch
// raises (invalid UTF-8) or is refused (a BLOB name) -- at the same row on both sources.
void TestCuReplayEquivalence(const std::string& Scratch) {
  DSig::Test::Suite("CuReplaySource == SqlRowSource (fixtures, edge rows, failures)");
  std::string Main;
  std::string Diff;
  CHECK_TEXT_EQ(BuildScenario(Scratch, "related", "cueq", Main, Diff), "");
  const std::string Common =
      "insert into functions (id, name, address, nodes, md_index, mangled_function) values "
      "(100, 'edge_nulladdr', NULL, 3, '1.5', 'edge_nulladdr'), (101, 'edge_abc', 'abc', 3, '2.5', 'edge_abc'), "
      "(102, 'edge_lead0', '000123', 3, '3.050963036440351716676733804', 'edge_lead0'), "
      "(103, NULL, '124', 3, '0', NULL), (104, 'edge_mdnull', '125', NULL, NULL, 'edge_mdnull'), "
      "(105, 'edge_neg', '-5', 3, '0', 'edge_neg'), (106, 'edge_huge', '99999999999999999999', 3, '0', 'edge_huge'), "
      "(107, 'edge_frac', '126.5', 3, 'x', 'edge_frac'), (108, 'edge_exp', '1e2', 3, '7', 'edge_exp');";
  CHECK_TEXT_EQ(Exec(Main, Common), "");
  CHECK_TEXT_EQ(Exec(Diff, Common), "");
  {
    DiffSession S;
    S.Open(Main, Diff);
    const bool PlanOk = CuReplayPlanOk(S);
    if (!PlanOk) {
      DSig::Test::Skip("CU equivalence", "kSqlCuCartesian does not plan as SCAN f / SCAN df on SQLite " +
                                             DiffDatabase::LibVersion());
      return;
    }
    const double Inf = std::numeric_limits<double>::infinity();
    const double NaN = std::numeric_limits<double>::quiet_NaN();
    const std::vector<std::array<double, 4>> Bounds = {
        {20100, 20400, 30100, 30400}, {20500, 20900, 30100, 31000}, {-Inf, Inf, -Inf, Inf}, {0, 0, 0, 0},
        {100, 130, 100, 130},         {123, 123, 124, 126.5},      {NaN, 1e9, 0, 1e9},    {20400, 20100, 30100, 30400},
        {-10, 1e20, -10, 1e20},       {1e20, 1e20, 1e20, 1e20},    {-0.0, 0.0, 99.5, 100.5}};
    int Same = 0;
    uint64_t Rows = 0;
    for (const auto& B : Bounds) {
      const SequenceResult R = CompareCuSources(S, B[0], B[1], B[2], B[3]);
      Same += R.Same ? 1 : 0;
      Rows += R.Rows;
      DSig::Test::Report(R.Same, ("bounds " + Fixed(B[0], 1) + ".." + Fixed(B[1], 1) + " x " + Fixed(B[2], 1) + ".." +
                                  Fixed(B[3], 1) + " " + R.Why)
                                     .c_str(),
                         __FILE__, __LINE__);
      CHECK_TEXT_EQ(R.End, "");
    }
    DSig::Test::Note(std::to_string(Same) + "/" + std::to_string(Bounds.size()) + " bound sets identical, " +
                     std::to_string(Rows) + " rows");
    // the whole-range replay includes every non-NULL address (the NULL one is never selected)
    const SequenceResult All = CompareCuSources(S, -Inf, Inf, -Inf, Inf);
    CHECK_NUM_EQ(All.Rows, (S.Main().Functions.Count() - 1) * (S.Diff().Functions.Count() - 1));
  }
  // rows whose fetch raises (invalid UTF-8 in a SELECT_FIELDS column: 01 §13) or is refused (a BLOB
  // name): both sources stop at the same row, the same way
  CHECK_TEXT_EQ(Exec(Main, "insert into functions (id, name, address, nodes, md_index) values "
                           "(110, cast(x'41ff' as text), '140', 3, '0'), (111, x'4142', '141', 3, '0');"),
                "");
  {
    DiffSession S;
    S.Open(Main, Diff);
    const SequenceResult Bad = CompareCuSources(S, 139, 140, 100, 130);
    CHECK(Bad.Same);
    CHECK_TEXT_EQ(Bad.End, "raise");
    const SequenceResult Blob = CompareCuSources(S, 141, 141, 100, 130);
    CHECK(Blob.Same);
    CHECK_TEXT_EQ(Blob.End, "unsupported");
    // mid-sequence: the valid rows 'abc' (0.0), '000123', '124', '125', '126.5', '1e2' come first (ascending
    // id), the invalid UTF-8 row (id 110, '140') last
    const SequenceResult Both = CompareCuSources(S, 0, 141, 100, 130);
    CHECK(Both.Same);
    CHECK_TEXT_EQ(Both.End, "raise");
    CHECK(Both.Rows > 0);
    DSig::Test::Note("failure rows: invalid UTF-8 -> both raise after " + std::to_string(Bad.Rows) + " and after " +
                     std::to_string(Both.Rows) + " rows; BLOB name -> both refuse after " + std::to_string(Blob.Rows) +
                     " rows");
  }
}

// The EXPLAIN QUERY PLAN guard (06 §9.2): an expression index on cast(address as real) turns `SCAN f`
// into an index search, so the pass must use the verbatim SQL, and then the native and SQL settings
// give the same result.
void TestPlanGuardFallback(const std::string& Scratch) {
  DSig::Test::Suite("related CU: the plan guard falls back to SQL");
  std::string Main;
  std::string Diff;
  CHECK_TEXT_EQ(BuildScenario(Scratch, "related", "guard", Main, Diff), "");
  CHECK_TEXT_EQ(Exec(Main, "create index idx_castaddr on functions(cast(address as real))"), "");
  const std::string CasesPath = DSig::Test::PathToUtf8(DSig::Test::Utf8ToPath(FixtureDir()) / "cases.json");
  const JsonValue Doc = JsonParse(Detail::ReadFileBytes(CasesPath));
  std::optional<StateSnapshot> Before;
  for (const JsonValue& Case : Doc.At("cases").Items()) {
    if (Case.At("name").AsString() == "related_cu") {
      Before = SnapshotOf(Case.At("before"));
    }
  }
  CHECK(Before.has_value());
  if (!Before) {
    return;
  }
  std::string Plan;
  StateSnapshot Results[2];
  for (int Index = 0; Index < 2; ++Index) {
    DiffSession S;
    S.SetCuSource(Index == 0 ? RelatedCuSource::Native : RelatedCuSource::Sql);
    S.Open(Main, Diff);
    CHECK(!CuReplayPlanOk(S));
    for (const PlanRow& Row : S.Db().ExplainQueryPlan(kSqlCuCartesian)) {
      Plan += Index == 0 ? (Plan.empty() ? "" : " / ") + Row.Detail : "";
    }
    Results[Index] = RunReplay(S, *Before, "find_related_compilation_unit:0");
  }
  const DSig::Test::CompareReport Report = DSig::Test::CompareSnapshots(Results[1], Results[0], 5);
  CHECK(Report.L2Equal);
  Notes(Report);
  DSig::Test::Note("plan with the expression index: " + Plan);
}

// The constant-order hook (src/diff/stages/RelatedDetail.h): an installed order is executed as given;
// anything but a permutation of the intersection is refused.
void TestConstantOrderHook(const std::string& Scratch) {
  DSig::Test::Suite("find_related_constants: the constant-order hook");
  std::string Main;
  std::string Diff;
  CHECK_TEXT_EQ(BuildScenario(Scratch, "related", "order", Main, Diff), "");
  const auto RowNamed = [](const FunctionTable& T, std::string_view Name) {
    for (uint32_t Row = 0; Row < T.Count(); ++Row) {
      if (!T.Name.Null(Row) && T.Name.View(Row) == Name) {
        return Row;
      }
    }
    return kNoRow;
  };
  const std::string TracePath = DSig::Test::PathToUtf8(DSig::Test::Utf8ToPath(Scratch) / "order.jsonl");
  std::vector<std::string> Seen;
  std::vector<std::string> RowsFirst;
  std::vector<std::string> RowsReversed;
  for (int Pass = 0; Pass < 2; ++Pass) {
    DiffSession S;
    S.Open(Main, Diff);
    S.EnableTrace(TracePath, true);
    if (Pass == 1) {
      S.Ext<Detail::RelatedConstantOrder>().Reorder = [&](std::string_view M, std::string_view D,
                                                          const std::vector<std::string>& Native) {
        Seen.push_back(std::string(M) + "/" + std::string(D) + ":" + std::to_string(Native.size()));
        return std::vector<std::string>(Native.rbegin(), Native.rend());
      };
    }
    FindRelatedConstants(S, RowNamed(S.Main().Functions, "alpha"), RowNamed(S.Diff().Functions, "alpha"));
    S.FinishHarness();
    (Pass == 0 ? RowsFirst : RowsReversed) = ReadNativeEvents(TracePath).Rows;
  }
  CHECK_EQ(Seen.size(), 1u);
  CHECK_TEXT_EQ(Seen.empty() ? "" : Seen[0], "alpha/alpha:5");
  // first appearance in alpha's main list: "Hello related world" (9 rows), "0x1234 zero prefix" (1),
  // 8192 (0: abs != 0), "shared text A" (30), "second shared B" (4); reversed: the same blocks backwards
  CHECK_EQ(RowsFirst.size(), 44u);
  CHECK_EQ(RowsReversed.size(), 44u);
  if (RowsFirst.size() == 44 && RowsReversed.size() == 44) {
    CHECK(std::equal(RowsFirst.begin(), RowsFirst.begin() + 9, RowsReversed.end() - 9));
    CHECK(std::equal(RowsFirst.end() - 4, RowsFirst.end(), RowsReversed.begin()));
  }
  DiffSession S;
  S.Open(Main, Diff);
  S.Ext<Detail::RelatedConstantOrder>().Reorder = [](std::string_view, std::string_view, const std::vector<std::string>&) {
    return std::vector<std::string>{"not a constant"};
  };
  CHECK_TEXT_EQ(Outcome([&] {
                  FindRelatedConstants(S, RowNamed(S.Main().Functions, "alpha"), RowNamed(S.Diff().Functions, "alpha"));
                }),
                "unsupported");
}

// A ratio provider that only counts: every row check_match asks about gets 0.1 (below 0.5: no add).
class CountingRatio final : public IRatioProvider {
public:
  uint64_t Calls = 0;
  std::set<uint32_t> MainRows;
  double CheckRatio(const HeuristicRow& Row, MdSource) override {
    ++Calls;
    MainRows.insert(Row.Row1);
    return 0.1;
  }
  double CompareFunctionRows(uint32_t, uint32_t) override { return 0.1; }
};

SnapItem MakeSnapItem(std::string Ea1, std::string N1, std::string Ea2, std::string N2, double Ratio) {
  SnapItem I;
  I.Ea1 = std::move(Ea1);
  I.Name1 = std::move(N1);
  I.Ea2 = std::move(Ea2);
  I.Name2 = std::move(N2);
  I.Desc = "Synthetic";
  I.RatioBits = RatioBits(Ratio);
  I.Nodes1 = 3;
  I.Nodes2 = 3;
  return I;
}

// A snapshot of the given lists with the matched_* maps add_match would leave (last writer wins).
StateSnapshot StateWith(std::vector<SnapItem> Partial, std::vector<SnapItem> Best = {}) {
  StateSnapshot Snap;
  Snap.Best = std::move(Best);
  Snap.Partial = std::move(Partial);
  Snap.Flags.TotalFunctions1 = 100000;
  Snap.Flags.TotalFunctions2 = 100000;
  Snap.Iteration = 0;
  for (const auto* L : {&Snap.Best, &Snap.Partial}) {
    for (const SnapItem& I : *L) {
      Snap.MatchedPrimary.push_back(SnapMatched{I.Name1, I.Name2, I.RatioBits});
      Snap.MatchedSecondary.push_back(SnapMatched{I.Name2, I.Name1, I.RatioBits});
    }
  }
  return Snap;
}

// Fetch-time failures (01 §13, 06 Hard parts 6): get_function_row swallows every exception (D:2456-2457),
// the CU lookup's fetchone (D:3445) and the gap query's fetchall (D:3246) do not.
void TestFetchFailures(const std::string& Scratch) {
  DSig::Test::Suite("fetch-time failures: get_function_row swallows, CU lookup and gap fetch raise");
  std::string Main;
  std::string Diff;
  CHECK_TEXT_EQ(BuildScenario(Scratch, "related", "fetch", Main, Diff), "");
  CHECK_TEXT_EQ(Exec(Main, "insert into functions (id, name, address, nodes, md_index, pseudocode, constants, "
                           "constants_count, pseudocode_lines) values "
                           "(120, 'bad_row', '50500', 3, '0', cast(x'ff' as text), '[\"shared text A\"]', 1, 0), "
                           "(121, 'cu_bad_name', '50600', 3, '0', 'x', '[]', 0, 0), "
                           "(122, 'gap_lo', '50400', 3, '0', 'x', '[]', 0, 0), (123, 'gap_hi', '50550', 3, '0', 'x', '[]', 0, 0);"
                           "insert into compilation_units (id, name, functions, start_ea, end_ea) values "
                           "(9, cast(x'c3' as text), 1, '50600', '50600');"
                           "insert into compilation_unit_functions (cu_id, func_id) values (9, 121);"),
                "");
  {
    // bad_row's `select *` fetch fails and is swallowed: the seed is skipped, the pass completes
    DiffSession S;
    S.Open(Main, Diff);
    std::string Detail;
    const StateSnapshot Before = StateWith({MakeSnapItem("50500", "bad_row", "30100", "alpha", 0.9)});
    StateSnapshot After;
    CHECK_TEXT_EQ(Outcome([&] { After = RunReplay(S, Before, "find_related_matches:0"); }, &Detail), "");
    CHECK_EQ(After.Partial.size(), 1u);
  }
  {
    // cu_bad_name's CU row has an invalid UTF-8 name: fetchone raises (main thread, no try)
    DiffSession S;
    S.Open(Main, Diff);
    std::string Detail;
    const StateSnapshot Before = StateWith({MakeSnapItem("50600", "cu_bad_name", "30100", "alpha", 0.9)});
    CHECK_TEXT_EQ(Outcome([&] { RunReplay(S, Before, "find_related_compilation_unit:0"); }, &Detail), "raise");
    CHECK(Detail.find("D:3445") != std::string::npos);
  }
  {
    // the gap ('50400', '50550') holds bad_row ('50500'): fetchall raises
    DiffSession S;
    S.Open(Main, Diff);
    std::string Detail;
    const StateSnapshot Before = StateWith({}, {MakeSnapItem("50400", "gap_lo", "30100", "alpha", 1.0),
                                                MakeSnapItem("50550", "gap_hi", "30200", "sub_30200", 1.0)});
    CHECK_TEXT_EQ(Outcome([&] { RunReplay(S, Before, "find_locally_affine_functions:0"); }, &Detail), "raise");
    CHECK(Detail.find("fetch") != std::string::npos);
  }
}

// The 1,000,000-row cap of add_matches_internal (C:90 SQL_MAX_PROCESSED_ROWS, D:1874-1880, D:1893) applies
// to a related-CU cartesian product (06 §9.2): a 1001 x 1000 CU pair consumes exactly the first 1,000,000
// rows in (f.id, df.id) order, i.e. every main function but the last, on both candidate sources.
void TestCuRowCap(const std::string& Scratch) {
  DSig::Test::Suite("related CU: the 1,000,000-row cap on both candidate sources");
  std::string Main;
  std::string Diff;
  CHECK_TEXT_EQ(BuildScenario(Scratch, "related", "cap", Main, Diff), "");
  const auto Fill = [](const char* Prefix, int Count, int Base) {
    return std::string("delete from compilation_unit_functions; delete from compilation_units; delete from functions; "
                       "with recursive c(x) as (select 1 union all select x + 1 from c where x < ") +
           std::to_string(Count) +
           ") insert into functions (id, name, address, nodes, md_index) select x, '" + Prefix + "' || x, cast(" +
           std::to_string(Base) + " + x as text), 3, '0' from c; "
           "insert into compilation_units (id, name, functions, start_ea, end_ea) values (1, 'big', " +
           std::to_string(Count) + ", '" + std::to_string(Base + 1) + "', '" + std::to_string(Base + Count) +
           "'); insert into compilation_unit_functions (cu_id, func_id) values (1, 1);";
  };
  CHECK_TEXT_EQ(Exec(Main, Fill("sub_m", 1001, 100000)), "");
  CHECK_TEXT_EQ(Exec(Diff, Fill("sub_d", 1000, 200000)), "");
  for (const RelatedCuSource Source : {RelatedCuSource::Native, RelatedCuSource::Sql}) {
    DiffSession S;
    S.SetCuSource(Source);
    S.Open(Main, Diff);
    CountingRatio Fake;
    S.SetRatioProvider(&Fake);
    const auto Start = std::chrono::steady_clock::now();
    RunReplay(S, StateWith({MakeSnapItem("100001", "sub_m1", "200001", "sub_d1", 0.9)}), "find_related_compilation_unit:0");
    const char* Name = Source == RelatedCuSource::Native ? "native" : "sql";
    CHECK_NUM_EQ(Fake.Calls, 1000000);
    CHECK_EQ(Fake.MainRows.size(), 1000u);
    CHECK(Fake.MainRows.count(1000) == 0);  // the 1001st main function's rows are past the cap
    DSig::Test::Note(std::string(Name) + " source: " + std::to_string(Fake.Calls) + " rows consumed of 1,001,000, " +
                     Fixed(Seconds(Start), 2) + " s");
  }
}

// D:3345 sorted(..., key=lambda x: [int(x[0]), int(x[2])]): list.sort computes every key first, so a
// single item whose address int() rejects raises (ValueError) even though nothing is compared.
void TestAffinityIntKeys(const std::string& Scratch) {
  DSig::Test::Suite("local affinity: int() keys of the sort (D:3345)");
  std::string Main;
  std::string Diff;
  CHECK_TEXT_EQ(BuildScenario(Scratch, "related", "intkeys", Main, Diff), "");
  const auto Try = [&](const StateSnapshot& Before, std::string* Detail) {
    DiffSession S;
    S.Open(Main, Diff);
    return Outcome([&] { RunReplay(S, Before, "find_locally_affine_functions:0"); }, Detail);
  };
  std::string Detail;
  CHECK_TEXT_EQ(Try(StateWith({}, {MakeSnapItem("12x", "a", "5", "b", 1.0)}), &Detail), "raise");
  CHECK(Detail.find("D:3345") != std::string::npos);
  CHECK_TEXT_EQ(Try(StateWith({}, {MakeSnapItem("12", "a", "5 _5", "b", 1.0)}), &Detail), "raise");
  // int() accepts surrounding whitespace, a sign and single underscores between digits
  CHECK_TEXT_EQ(Try(StateWith({}, {MakeSnapItem(" 1_2 ", "a", "+5", "b", 1.0), MakeSnapItem("-0", "c", "0007", "d", 1.0)}),
                    &Detail),
                "");
}

// ---------------------------------------------------------------------------------------------
// Corpus: captures, exports, snapshots

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

// snapshots/NNNNN_<sanitised point>.json by sanitised point. The oracle writes <name>.tmp and renames it,
// so every .json file listed is complete and final, also while its capture is still running.
std::map<std::string, SnapshotFile> ListSnapshots(const fs::path& Dir) {
  static const std::regex Pattern("^([0-9]{5,})_(.+)\\.json$");
  std::map<std::string, SnapshotFile> Out;
  std::error_code Error;
  for (const fs::directory_entry& Entry : fs::directory_iterator(Dir, Error)) {
    const std::string Name = DSig::Test::PathToUtf8(Entry.path().filename());
    std::smatch Match;
    if (!std::regex_match(Name, Match, Pattern)) {
      continue;
    }
    Out.try_emplace(Match[2].str(), SnapshotFile{std::stoll(Match[1].str()), DSig::Test::PathToUtf8(Entry.path())});
  }
  return Out;
}

struct Capture {
  std::string Name;    // directory name
  std::string Pair;    // pair label (the directory name without a .full / .prefix2 suffix)
  fs::path Dir;
  std::string Status;  // run.json "status" ("complete", "stopped", "running", ...), "" if unreadable
  bool Rows = false;   // captured with --rows
  std::map<std::string, SnapshotFile> Files;
};

// run.json through the shared-delete reader (Detail::ReadFileBytes), never Python: a running capture
// replaces it with os.replace, which a reader without FILE_SHARE_DELETE could make fail.
void ReadRunJson(Capture& C) {
  try {
    const JsonValue Run = JsonParse(Detail::ReadFileBytes(DSig::Test::PathToUtf8(C.Dir / "run.json")));
    if (const JsonValue* Status = Run.Find("status"); Status != nullptr && Status->IsString()) {
      C.Status = Status->AsString();
    }
    if (const JsonValue* Options = Run.Find("options"); Options != nullptr && Options->IsObject()) {
      if (const JsonValue* Rows = Options->Find("rows"); Rows != nullptr && Rows->IsBool()) {
        C.Rows = Rows->AsBool();
      }
    }
  } catch (const std::exception&) {
    C.Status.clear();
  }
}

std::vector<Capture> ListCaptures() {
  std::vector<Capture> Out;
  const fs::path Traces = DSig::Test::Utf8ToPath(DSig::Test::OracleDir()) / "traces";
  std::error_code Error;
  if (!fs::is_directory(Traces, Error)) {
    return Out;
  }
  for (const fs::directory_entry& Entry : fs::directory_iterator(Traces, Error)) {
    const std::string Name = DSig::Test::PathToUtf8(Entry.path().filename());
    if (!Entry.is_directory(Error) || Name.empty() || Name[0] == '_') {
      continue;
    }
    Capture C;
    C.Name = Name;
    C.Pair = Name.substr(0, Name.find('.'));
    C.Dir = Entry.path();
    if (!fs::is_directory(C.Dir / "snapshots", Error)) {
      continue;
    }
    ReadRunJson(C);
    C.Files = ListSnapshots(C.Dir / "snapshots");
    Out.push_back(std::move(C));
  }
  std::sort(Out.begin(), Out.end(), [](const Capture& A, const Capture& B) { return A.Name < B.Name; });
  return Out;
}

// A capture's trace is complete (and no longer written) once the run completed or stopped.
bool TraceFinal(const Capture& C) { return C.Status == "complete" || C.Status == "stopped"; }

bool IsLongPair(const std::string& Pair) {
  return Pair.rfind("userenv-9168-pdb_vs_9278-nopdb", 0) == 0 || Pair.rfind("sechost-", 0) == 0;
}

// <corpus>/oracle/vectors/related/<capture>.set_order.json (generate.py set-order): the CPython order of
// the capture's constant sets, keyed "main name\0diff name".
std::optional<std::map<std::string, std::vector<std::string>>> ReadSetOrder(const std::string& CaptureName) {
  const std::string Path =
      DSig::Test::PathToUtf8(DSig::Test::Utf8ToPath(DSig::Test::VectorsDir("related")) / (CaptureName + ".set_order.json"));
  if (!Detail::PathExists(Path)) {
    return std::nullopt;
  }
  std::map<std::string, std::vector<std::string>> Out;
  const JsonValue Doc = JsonParse(Detail::ReadFileBytes(Path));
  for (const auto& [Key, List] : Doc.At("orders").Members()) {
    std::vector<std::string>& Order = Out[Key];
    for (const JsonValue& V : List.Items()) {
      Order.push_back(V.AsString());
    }
  }
  return Out;
}

// ---------------------------------------------------------------------------------------------
// Trace segments: the add_match / row lines between "before:<stage>" and "after:<stage>".

// "seq":<n> -> "seq":0 (the oracle's add_match seq counts the whole run; a replay's restarts at 0).
std::string NormaliseSeq(const std::string& Line) {
  const std::string Key = "\"seq\":";
  const size_t At = Line.find(Key);
  if (At == std::string::npos) {
    return Line;
  }
  size_t End = At + Key.size();
  while (End < Line.size() && Line[End] >= '0' && Line[End] <= '9') {
    ++End;
  }
  return Line.substr(0, At + Key.size()) + "0" + Line.substr(End);
}

bool IsStageEvent(const std::string& Line, bool Rows) {
  return Line.rfind("{\"ev\":\"add_match\"", 0) == 0 || (Rows && Line.rfind("{\"ev\":\"row\"", 0) == 0);
}

// Streams the stage events of a segment; Next returns false at the end.
class SegmentReader {
public:
  // Whole file (a native replay trace) when Point is empty; else the lines between the two points.
  SegmentReader(const std::string& Path, std::string Point, bool Rows)
      : In_(DSig::Test::Utf8ToPath(Path), std::ios::binary), Point_(std::move(Point)), Rows_(Rows) {
    if (!Point_.empty()) {
      const std::string Begin = "{\"ev\":\"point\",\"name\":\"before:" + Point_ + "\",";
      std::string Line;
      Started_ = false;
      while (std::getline(In_, Line)) {
        if (Line.rfind(Begin, 0) == 0) {
          Started_ = true;
          break;
        }
      }
    }
  }
  bool Started() const { return Started_; }
  bool Next(std::string& Out) {
    if (!Started_ || Done_) {
      return false;
    }
    const std::string End = "{\"ev\":\"point\",\"name\":\"after:" + Point_ + "\",";
    std::string Line;
    while (std::getline(In_, Line)) {
      if (!Point_.empty() && Line.rfind(End, 0) == 0) {
        Done_ = true;
        EndSeen_ = true;
        return false;
      }
      if (IsStageEvent(Line, Rows_)) {
        Out = NormaliseSeq(Line);
        return true;
      }
    }
    Done_ = true;
    return false;
  }
  bool EndSeen() const { return Point_.empty() || EndSeen_; }

private:
  std::ifstream In_;
  std::string Point_;
  bool Rows_ = false;
  bool Started_ = true;
  bool Done_ = false;
  bool EndSeen_ = false;
};

struct TraceVerdict {
  bool Compared = false;
  bool Equal = false;
  bool Incomplete = false;  // the oracle trace does not (yet) hold the segment's end point
  uint64_t AddMatches = 0;
  uint64_t RowsCount = 0;
  std::string FirstDifference;
};

TraceVerdict CompareSegments(const std::string& OraclePath, const std::string& Point, const std::string& NativePath,
                             bool Rows) {
  TraceVerdict V;
  SegmentReader Oracle(OraclePath, Point, Rows);
  if (!Oracle.Started()) {
    V.FirstDifference = "oracle trace has no point before:" + Point;
    return V;
  }
  SegmentReader Native(NativePath, "", Rows);
  V.Compared = true;
  V.Equal = true;
  std::string A;
  std::string B;
  uint64_t Index = 0;
  while (true) {
    const bool HaveA = Oracle.Next(A);
    const bool HaveB = Native.Next(B);
    if (!HaveA && !HaveB) {
      break;
    }
    if (HaveA) {
      V.AddMatches += A.rfind("{\"ev\":\"add_match\"", 0) == 0 ? 1 : 0;
      V.RowsCount += A.rfind("{\"ev\":\"row\"", 0) == 0 ? 1 : 0;
    }
    if (V.Equal && (HaveA != HaveB || A != B)) {
      V.Equal = false;
      V.FirstDifference = "event " + std::to_string(Index) + ": oracle [" +
                          (HaveA ? A.substr(0, 300) : std::string("<end>")) + "] native [" +
                          (HaveB ? B.substr(0, 300) : std::string("<end>")) + "]";
    }
    ++Index;
  }
  if (!Oracle.EndSeen()) {
    V.Equal = false;
    V.Incomplete = true;
    V.FirstDifference = "oracle trace ends before after:" + Point;
  }
  return V;
}

// ---------------------------------------------------------------------------------------------
// The set-order classification

bool IsRelatedConstantsItem(const SnapItem& I) { return I.Desc == "Same constants related matches"; }

std::string ItemKey(const SnapItem& I) {
  return I.Ea1 + "|" + I.Name1.value_or("\x01None") + "|" + I.Ea2 + "|" + I.Name2.value_or("\x01None") + "|" +
         I.Desc + "|" + RatioBitsHex(RatioFromBits(I.RatioBits)) + "|" + std::to_string(I.Nodes1) + "|" +
         std::to_string(I.Nodes2);
}

// The set-order tolerated class (D:3389, 06 §8.3): the two states differ only in "Same constants related
// matches" items (their presence or order) and in matched_* entries of names those items carry.
struct R3Class {
  bool Confined = true;
  size_t OnlyOracle = 0;
  size_t OnlyNative = 0;
  size_t Reordered = 0;    // positions whose item differs while the multiset is the same
  size_t MatchedKeys = 0;  // matched_primary / matched_secondary keys whose entry differs
  std::vector<std::string> Notes;
};

R3Class ClassifyR3(const StateSnapshot& Oracle, const StateSnapshot& Native) {
  R3Class R;
  std::set<std::string> Names;
  const auto List = [&](const char* What, const std::vector<SnapItem>& A, const std::vector<SnapItem>& B) {
    std::vector<SnapItem> OtherA;
    std::vector<SnapItem> OtherB;
    std::vector<std::string> SeqA;
    std::vector<std::string> SeqB;
    for (const auto& [Source, Other, Seq] : {std::tie(A, OtherA, SeqA), std::tie(B, OtherB, SeqB)}) {
      for (const SnapItem& I : Source) {
        if (IsRelatedConstantsItem(I)) {
          Seq.push_back(ItemKey(I));
          Names.insert(I.Name1.value_or("\x01None"));
          Names.insert(I.Name2.value_or("\x01None"));
        } else {
          Other.push_back(I);
        }
      }
    }
    if (OtherA != OtherB) {
      R.Confined = false;
      R.Notes.push_back(std::string(What) + ": items of other descriptions differ");
    }
    std::multiset<std::string> Left(SeqA.begin(), SeqA.end());
    for (const std::string& K : SeqB) {
      const auto Found = Left.find(K);
      if (Found != Left.end()) {
        Left.erase(Found);
      } else {
        ++R.OnlyNative;
      }
    }
    R.OnlyOracle += Left.size();
    if (std::multiset<std::string>(SeqA.begin(), SeqA.end()) == std::multiset<std::string>(SeqB.begin(), SeqB.end())) {
      for (size_t I = 0; I < SeqA.size(); ++I) {
        R.Reordered += SeqA[I] != SeqB[I] ? 1 : 0;
      }
    }
  };
  List("best", Oracle.Best, Native.Best);
  List("partial", Oracle.Partial, Native.Partial);
  List("unreliable", Oracle.Unreliable, Native.Unreliable);
  const auto Dict = [&](const char* What, const std::vector<SnapMatched>& A, const std::vector<SnapMatched>& B) {
    std::map<std::string, std::pair<std::string, uint64_t>> MA;
    std::map<std::string, std::pair<std::string, uint64_t>> MB;
    for (const SnapMatched& E : A) {
      MA[E.Key.value_or("\x01None")] = {E.Other.value_or("\x01None"), E.RatioBits};
    }
    for (const SnapMatched& E : B) {
      MB[E.Key.value_or("\x01None")] = {E.Other.value_or("\x01None"), E.RatioBits};
    }
    std::set<std::string> Keys;
    for (const auto& Entry : MA) {
      Keys.insert(Entry.first);
    }
    for (const auto& Entry : MB) {
      Keys.insert(Entry.first);
    }
    for (const std::string& K : Keys) {
      const auto FA = MA.find(K);
      const auto FB = MB.find(K);
      if (FA != MA.end() && FB != MB.end() && FA->second == FB->second) {
        continue;
      }
      ++R.MatchedKeys;
      const bool Related = Names.count(K) != 0 || (FA != MA.end() && Names.count(FA->second.first) != 0) ||
                           (FB != MB.end() && Names.count(FB->second.first) != 0);
      if (!Related) {
        R.Confined = false;
        R.Notes.push_back(std::string(What) + " key '" + K + "' differs outside the related-constants items");
      }
    }
  };
  Dict("matched_primary", Oracle.MatchedPrimary, Native.MatchedPrimary);
  Dict("matched_secondary", Oracle.MatchedSecondary, Native.MatchedSecondary);
  if (!(Oracle.Flags == Native.Flags)) {
    R.Confined = false;
    R.Notes.push_back("flags differ");
  }
  return R;
}

// ---------------------------------------------------------------------------------------------
// Corpus replays of the three stages

struct StageCounts {
  int Run = 0;
  int Exact = 0;           // S-L2 equal and (when compared) trace equal, documented order
  int Tolerated = 0;       // set-order class, documented order (find_related_matches)
  int ExactWithOrder = 0;  // S-L2 + trace equal with the capture's CPython order installed
  int OrderRuns = 0;
  int TraceCompared = 0;
  int TraceEqual = 0;
};

const char* const kStages[] = {"find_related_matches", "find_related_compilation_unit", "find_locally_affine_functions"};

std::map<std::string, StageCounts> g_Totals;  // by stage
std::set<std::string> g_Done;                   // pair + point already replayed (one capture per point)

struct ReplayResult {
  bool Ok = false;
  std::string Error;
  StateSnapshot Native;
  double Seconds = 0;
  std::optional<TraceVerdict> Trace;
};

ReplayResult ReplayOnce(const Capture& C, const std::pair<std::string, std::string>& Ids, const std::string& Base,
                        const StateSnapshot& Before, const std::string& Scratch, bool WithTrace,
                        const std::map<std::string, std::vector<std::string>>* Order) {
  ReplayResult R;
  DiffSession S;
  S.Log().SetQuiet(true);
  S.Open(DSig::Test::ExportPath(Ids.first), DSig::Test::ExportPath(Ids.second));
  S.SetPairLabel(C.Pair);
  if (Order != nullptr) {
    S.Ext<Detail::RelatedConstantOrder>().Reorder = [Order](std::string_view M, std::string_view D,
                                                            const std::vector<std::string>& Native) {
      const auto Found = Order->find(std::string(M) + std::string(1, '\0') + std::string(D));
      return Found == Order->end() ? Native : Found->second;
    };
  }
  const std::string NativeTrace =
      DSig::Test::PathToUtf8(DSig::Test::Utf8ToPath(Scratch) / (C.Name + "_" + SanitisePointName(Base) + ".jsonl"));
  if (WithTrace) {
    S.EnableTrace(NativeTrace, C.Rows);
  }
  const auto Start = std::chrono::steady_clock::now();
  try {
    R.Native = RunReplay(S, Before, Base);
    R.Ok = true;
  } catch (const std::exception& Error) {
    R.Error = Error.what();
  }
  R.Seconds = Seconds(Start);
  S.FinishHarness();
  if (WithTrace && R.Ok) {
    R.Trace = CompareSegments(DSig::Test::PathToUtf8(C.Dir / "trace.jsonl"), Base, NativeTrace, C.Rows);
    if (R.Trace->Incomplete && !TraceFinal(C)) {
      R.Trace.reset();  // a running capture has not flushed this segment yet: nothing to compare
    }
  }
  std::error_code Error;
  fs::remove(DSig::Test::Utf8ToPath(NativeTrace), Error);
  return R;
}

std::string TraceText(const std::optional<TraceVerdict>& T, bool Rows) {
  if (!T) {
    return "trace not compared (segment not in the running capture's trace yet)";
  }
  return std::string("trace ") + (T->Equal ? "equal" : "DIFFERS") + " (" + std::to_string(T->AddMatches) +
         " add_match" + (Rows ? ", " + std::to_string(T->RowsCount) + " row" : std::string()) + " events)";
}

void ReplayStage(const Capture& C, const std::pair<std::string, std::string>& Ids, const std::string& Stage, int K,
                 const std::string& Scratch) {
  const std::string Base = Stage + ":" + std::to_string(K);
  const std::string Label = C.Name + " " + Base;
  const auto Before = C.Files.find("before_" + SanitisePointName(Base));
  const auto After = C.Files.find("after_" + SanitisePointName(Base));
  if (Before == C.Files.end() || After == C.Files.end() || !Selected(Label)) {
    return;
  }
  if (!g_Done.insert(C.Pair + " " + Base).second) {
    return;  // the same point of another capture of this pair (e.g. a .full re-capture)
  }
  const bool Long = IsLongPair(C.Pair) && Stage == "find_related_compilation_unit";
  if (Long && !LongEnabled()) {
    DSig::Test::Note(Label + ": skipped (long related-CU replay; set DSIG_RELATED_LONG=1)");
    return;
  }
  StageCounts& Counts = g_Totals[Stage];
  ++Counts.Run;
  const StateSnapshot BeforeSnap = ReadSnapshot(Before->second.Path);
  const StateSnapshot AfterSnap = ReadSnapshot(After->second.Path);
  // Traces are append-only (the oracle never replaces trace.jsonl), so a running or killed capture's
  // trace is compared too, up to the segment's end point when it is already there.
  const bool WithTrace = true;
  std::string Timing;
  if (Long) {
    // a timing run: the stage alone, no trace written
    const ReplayResult Timed = ReplayOnce(C, Ids, Base, BeforeSnap, Scratch, false, nullptr);
    const DSig::Test::CompareReport Report = DSig::Test::CompareSnapshots(AfterSnap, Timed.Native, 5);
    DSig::Test::Report(Timed.Ok && Report.L2Equal, (Label + " (untraced timing run) S-L2").c_str(), __FILE__, __LINE__);
    Timing = ", untraced run " + Fixed(Timed.Seconds, 1) + " s";
  }
  const ReplayResult R = ReplayOnce(C, Ids, Base, BeforeSnap, Scratch, WithTrace, nullptr);
  if (!R.Ok) {
    DSig::Test::Report(false, (Label + " threw: " + R.Error).c_str(), __FILE__, __LINE__);
    return;
  }
  if (R.Trace) {
    ++Counts.TraceCompared;
    Counts.TraceEqual += R.Trace->Equal ? 1 : 0;
  }
  const DSig::Test::CompareReport Report = DSig::Test::CompareSnapshots(AfterSnap, R.Native, 10);
  const bool TraceOk = !R.Trace || R.Trace->Equal;
  std::string Summary = Label + ": " + std::to_string(AfterSnap.Best.size()) + " best / " +
                        std::to_string(AfterSnap.Partial.size()) + " partial after, " + Fixed(R.Seconds, 2) + " s" +
                        Timing + "; state S-L2 " + (Report.L2Equal ? "equal" : "DIFFERS") + ", " +
                        TraceText(R.Trace, C.Rows);
  if (Report.L2Equal && TraceOk) {
    ++Counts.Exact;
    DSig::Test::Report(true, Label.c_str(), __FILE__, __LINE__);
    DSig::Test::Note(Summary);
  } else if (Stage == "find_related_matches") {
    // `for constant in inter_consts` iterates a CPython set (D:3389, 06 §8.3). Report the class.
    const R3Class Class = ClassifyR3(AfterSnap, R.Native);
    std::string Text = Summary + "; set-order tolerated class " +
                       (Class.Confined ? "CONFINED" : "NOT confined") +
                       ": related-constants items only in the oracle " + std::to_string(Class.OnlyOracle) +
                       ", only native " + std::to_string(Class.OnlyNative) + ", reordered " +
                       std::to_string(Class.Reordered) + ", matched_* keys differing " +
                       std::to_string(Class.MatchedKeys);
    // Does the next cleanup (D:3413, the related-CU pass's first act) erase the difference?
    const auto AfterCleanup = C.Files.find("after_cleanup_3413_" + std::to_string(K + 1));
    if (!Report.L2Equal && AfterCleanup != C.Files.end()) {
      DiffSession T;
      T.Restore(R.Native);
      T.State().Cleanup(CleanupSite::L3413);
      const StateSnapshot Cleaned = T.Snapshot("after:cleanup:3413:" + std::to_string(K + 1));
      const DSig::Test::CompareReport Next =
          DSig::Test::CompareSnapshots(ReadSnapshot(AfterCleanup->second.Path), Cleaned, 5);
      Text += Next.L2Equal ? "; erased by the next cleanup (after:cleanup:3413 S-L2 equal)"
                           : "; NOT erased by the next cleanup";
    }
    DSig::Test::Note(Text);
    for (const std::string& Line : Class.Notes) {
      DSig::Test::Note("    " + Line);
    }
    if (R.Trace && !R.Trace->Equal) {
      DSig::Test::Note("    first trace difference: " + R.Trace->FirstDifference);
    }
    DSig::Test::Report(Class.Confined, (Label + " set-order class confined").c_str(), __FILE__, __LINE__);
    Counts.Tolerated += Class.Confined ? 1 : 0;
  } else {
    DSig::Test::Report(false, (Label + " S-L2" + (R.Trace ? " + trace" : "")).c_str(), __FILE__, __LINE__);
    DSig::Test::Note(Summary);
    Notes(Report);
    if (R.Trace && !R.Trace->Equal) {
      DSig::Test::Note("    first trace difference: " + R.Trace->FirstDifference);
    }
  }
  if (Stage == "find_related_matches") {
    // The same replay with the capture's own CPython constant order installed must be exact.
    const auto Order = ReadSetOrder(C.Name);
    if (!Order) {
      DSig::Test::Note(Label + ": no " + C.Name + ".set_order.json under vectors/related (generate.py set-order)");
      return;
    }
    ++Counts.OrderRuns;
    const ReplayResult O = ReplayOnce(C, Ids, Base, BeforeSnap, Scratch, WithTrace, &*Order);
    const DSig::Test::CompareReport OReport = DSig::Test::CompareSnapshots(AfterSnap, O.Native, 10);
    const bool Exact = O.Ok && OReport.L2Equal && (!O.Trace || O.Trace->Equal);
    Counts.ExactWithOrder += Exact ? 1 : 0;
    DSig::Test::Report(Exact, (Label + " with the capture's CPython set order: S-L2 + trace").c_str(), __FILE__,
                       __LINE__);
    DSig::Test::Note(Label + " with the capture's CPython set order (" + std::to_string(Order->size()) +
                     " seed pairs): state S-L2 " + (OReport.L2Equal ? "equal" : "DIFFERS") + ", " +
                     TraceText(O.Trace, C.Rows));
    if (!Exact) {
      Notes(OReport);
      if (O.Trace && !O.Trace->Equal) {
        DSig::Test::Note("    first trace difference: " + O.Trace->FirstDifference);
      }
    }
  }
}

void TestCorpusStageReplays(const std::string& Scratch) {
  DSig::Test::Suite("corpus replays (S-L2): find_related_matches, find_related_compilation_unit, "
                    "find_locally_affine_functions");
  if (!DSig::Test::CorpusRoot()) {
    DSig::Test::Skip("corpus replays", "DSIG_CORPUS_ROOT is not set");
    return;
  }
  const std::vector<Capture> Captures = ListCaptures();
  if (Captures.empty()) {
    DSig::Test::Skip("corpus replays", "no oracle captures");
    return;
  }
  for (const Capture& C : Captures) {
    const auto Ids = ExportIdsOfPair(C.Pair);
    if (!Ids) {
      continue;
    }
    for (int K = 0; K < 64; ++K) {
      bool Any = false;
      for (const char* Stage : kStages) {
        const std::string Base = std::string(Stage) + ":" + std::to_string(K);
        if (C.Files.count("before_" + SanitisePointName(Base)) != 0) {
          Any = true;
          ReplayStage(C, *Ids, Stage, K, Scratch);
        }
      }
      if (!Any) {
        break;
      }
    }
  }
  for (const auto& [Stage, Counts] : g_Totals) {
    DSig::Test::Note(Stage + ": " + std::to_string(Counts.Exact) + "/" + std::to_string(Counts.Run) +
                     " replays S-L2 + trace exact in the documented order, " + std::to_string(Counts.Tolerated) +
                     " set-order tolerated" +
                     (Counts.OrderRuns > 0 ? ", " + std::to_string(Counts.ExactWithOrder) + "/" +
                                                 std::to_string(Counts.OrderRuns) + " exact with the capture's CPython order"
                                           : std::string()) +
                     "; traces " + std::to_string(Counts.TraceEqual) + "/" + std::to_string(Counts.TraceCompared) +
                     " equal (documented order)");
  }
}

// ---------------------------------------------------------------------------------------------
// CuReplaySource == SqlRowSource on the long pairs' seeds

struct CuSeed {
  std::string Name1;
  std::string Name2;
  double Lo1 = 0;
  double Hi1 = 0;
  double Lo2 = 0;
  double Hi2 = 0;
};

// An independent re-derivation of the pass's seeds (D:3413-3456), for the sequence check only.
std::vector<CuSeed> CuSeeds(DiffSession& S, size_t Limit) {
  std::vector<Item> L = S.State().SortedResults(Chooser::Best);
  const std::vector<Item> P = S.State().SortedResults(Chooser::Partial);
  L.insert(L.end(), P.begin(), P.end());
  std::vector<CuSeed> Out;
  for (const Item& M : L) {
    if (M.Ratio < kRelatedMatchesMinRatio || Out.size() >= Limit) {
      break;
    }
    const auto Lookup = [&](std::string_view Sql, NameId Name) -> std::optional<std::pair<double, double>> {
      const BindValue Bind = BindValue::Str(S.Ids().NameText(Name));
      Statement Q = S.Db().Prepare(Sql, std::span<const BindValue>(&Bind, 1));
      if (!Q.Step()) {
        return std::nullopt;
      }
      const auto Lo = PyFloat(Q.Text(Q.FindColumn("start_ea")));
      const auto Hi = PyFloat(Q.Text(Q.FindColumn("end_ea")));
      if (!Lo || !Hi) {
        return std::nullopt;
      }
      return std::make_pair(*Lo, *Hi);
    };
    const auto Main = Lookup(kSqlCuLookupMain, M.Name1);
    const auto Diff = Lookup(kSqlCuLookupDiff, M.Name2);
    if (!Main || !Diff) {
      continue;
    }
    Out.push_back(CuSeed{std::string(S.Ids().NameText(M.Name1)), std::string(S.Ids().NameText(M.Name2)), Main->first,
                         Main->second, Diff->first, Diff->second});
  }
  return Out;
}

void TestCuSequences() {
  DSig::Test::Suite("CuReplaySource == SqlRowSource on the long pairs' first seeds (06 §9.2)");
  if (!DSig::Test::CorpusRoot()) {
    DSig::Test::Skip("CU sequences", "DSIG_CORPUS_ROOT is not set");
    return;
  }
  if (!DSig::Test::OracleSqlite()) {
    DSig::Test::Skip("CU sequences", "SQLite " + DiffDatabase::LibVersion() + " is not the oracle's 3.51.1");
    return;
  }
  const bool Long = LongEnabled();
  const size_t SeedLimit = Long ? 50 : 2;
  std::set<std::string> PairsDone;
  for (const Capture& C : ListCaptures()) {
    if (!IsLongPair(C.Pair) || PairsDone.count(C.Pair) != 0 || !Selected(C.Name + " cu-seq")) {
      continue;
    }
    const auto Before = C.Files.find("before_find_related_compilation_unit_0");
    const auto Ids = ExportIdsOfPair(C.Pair);
    if (Before == C.Files.end() || !Ids) {
      continue;
    }
    PairsDone.insert(C.Pair);
    DiffSession S;
    S.Open(DSig::Test::ExportPath(Ids->first), DSig::Test::ExportPath(Ids->second));
    S.Restore(ReadSnapshot(Before->second.Path));
    S.State().Cleanup(CleanupSite::L3413);  // D:3413, then the seed list of D:3416-3417
    CHECK(CuReplayPlanOk(S));
    const std::vector<CuSeed> Seeds = CuSeeds(S, SeedLimit);
    uint64_t Rows = 0;
    size_t Equal = 0;
    const auto Start = std::chrono::steady_clock::now();
    for (size_t I = 0; I < Seeds.size(); ++I) {
      const CuSeed& Seed = Seeds[I];
      const SequenceResult R = CompareCuSources(S, Seed.Lo1, Seed.Hi1, Seed.Lo2, Seed.Hi2);
      Rows += R.Rows;
      Equal += R.Same && R.End.empty() ? 1 : 0;
      DSig::Test::Report(R.Same && R.End.empty(), (C.Pair + " seed " + std::to_string(I) + " (" + Seed.Name1 + " / " +
                                                   Seed.Name2 + ") native == SQL row sequence " + R.Why)
                                                      .c_str(),
                         __FILE__, __LINE__);
    }
    DSig::Test::Note(C.Pair + ": " + std::to_string(Equal) + "/" + std::to_string(Seeds.size()) +
                     " seeds with identical CuReplaySource / SqlRowSource row sequences, " + std::to_string(Rows) +
                     " rows, " + Fixed(Seconds(Start), 1) + " s" +
                     (Long ? "" : " [first 2 seeds; DSIG_RELATED_LONG=1 runs 50]"));
    if (!Long) {
      continue;
    }
    // The size of the whole pass at iteration 0: every seed's cartesian product, capped at 1,000,000.
    {
      const std::vector<CuSeed> All = CuSeeds(S, SIZE_MAX);
      const auto InRange = [](const FunctionTable& T, double Lo, double Hi) {
        uint64_t N = 0;
        for (size_t Row = 0; Row < T.Count(); ++Row) {
          N += T.AddressSqlNull[Row] == 0 && T.AddressSqlReal[Row] >= Lo && T.AddressSqlReal[Row] <= Hi ? 1 : 0;
        }
        return N;
      };
      uint64_t Total = 0;
      for (const CuSeed& Seed : All) {
        Total += std::min<uint64_t>(1000000, InRange(S.Main().Functions, Seed.Lo1, Seed.Hi1) *
                                                 InRange(S.Diff().Functions, Seed.Lo2, Seed.Hi2));
      }
      DSig::Test::Note(C.Pair + " iteration 0: " + std::to_string(All.size()) +
                       " seeds reach the cartesian replay, " + std::to_string(Total) + " rows in total");
    }
    // A pair whose capture has no after:find_related_compilation_unit:0 yet (sechost): time the native
    // pass anyway (no comparison possible until the oracle capture reaches that point).
    if (C.Files.count("after_find_related_compilation_unit_0") == 0) {
      DiffSession T;
      T.Log().SetQuiet(true);
      T.Open(DSig::Test::ExportPath(Ids->first), DSig::Test::ExportPath(Ids->second));
      const auto T0 = std::chrono::steady_clock::now();
      const StateSnapshot After = RunReplay(T, ReadSnapshot(Before->second.Path), "find_related_compilation_unit:0");
      DSig::Test::Note(C.Pair + " find_related_compilation_unit:0 native pass (no oracle snapshot yet): " +
                       Fixed(Seconds(T0), 1) + " s, " + std::to_string(After.Best.size()) + " best / " +
                       std::to_string(After.Partial.size()) + " partial after");
    }
  }
  if (PairsDone.empty()) {
    DSig::Test::Skip("CU sequences", "no long-pair capture with before:find_related_compilation_unit:0");
  }
}

}  // namespace

int main() {
  const std::string Scratch = DSig::Test::ScratchDir("diff_related");
  Run("fixture vectors", [&] { TestFixtureVectors(Scratch); });
  Run("abs table", [&] { TestAbsTable(Scratch); });
  Run("lexicographic gap", [&] { TestLexicographicGap(Scratch); });
  Run("first cu", [&] { TestFirstCu(Scratch); });
  Run("CU equivalence", [&] { TestCuReplayEquivalence(Scratch); });
  Run("plan guard", [&] { TestPlanGuardFallback(Scratch); });
  Run("order hook", [&] { TestConstantOrderHook(Scratch); });
  Run("fetch failures", [&] { TestFetchFailures(Scratch); });
  Run("row cap", [&] { TestCuRowCap(Scratch); });
  Run("int keys", [&] { TestAffinityIntKeys(Scratch); });
  Run("corpus stages", [&] { TestCorpusStageReplays(Scratch); });
  Run("cu sequences", TestCuSequences);
  DSig::Test::RemoveScratchDir(Scratch);
  return DSig::Test::Finish();
}
