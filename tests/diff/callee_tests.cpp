// diff_callee: callee diffing, "Callee found diffing matches assembly / pseudo-code" (docs/parity/00-plan.md
// §4 L7; find_matches_diffing D:3211-3229, find_matches_diffing_internal D:3150-3193, find_one_match_diffing
// D:3033-3131; spec 03b §4.3, 06 §4-§6, 07 §10.11.1, 02 §3).
//
//   * unit tests: the documented diff-walk examples (03b §4.3.2 quirks 1-4, §4.3.3, 06 §6.3-§6.4 and V2)
//     on Detail::CalleeCandidatePairs; the chooser / bonus / gate rules of D:3084-3110 with a scripted
//     ratio provider; the raise and refusal sites (D:3084 TypeError, D:3089 ZeroDivisionError, fetch
//     errors, the functions_exists same-database quirk, BLOB text, show_summary's D:1631);
//   * vector tests: tests/diff/fixtures/callee/walk_vectors.json, the pairs, dones keys and
//     functions_exists calls the UNMODIFIED find_one_match_diffing produced on 425 synthetic text pairs;
//   * fixture replays: tests/diff/fixtures/callee/<scenario>/ (03b experiments A and Z, the walk quirks
//     through the whole stage, the gates and churn, a different processor), recorded from real Diaphora by
//     gen_callee_fixtures.py: before:find_matches_diffing:k -> StageFindMatchesDiffing -> S-L2 equal to
//     after:find_matches_diffing:k, the same trace events and the same find_one_match_diffing call counts;
//   * corpus replays (skip without DSIG_CORPUS_ROOT): every before:/after:find_matches_diffing:k pair of
//     every oracle capture under <corpus>/oracle/traces/, compared at S-L2, event for event against the
//     oracle trace, and with the run.json call counts (06 V3: assembly 716 / pseudocode 426 on
//     ls-old_vs_ls). Oracle files are only read: snapshots, traces and run.json through shared-delete
//     readers, exports through immutable=1 connections (DiffDatabase).
//
// The fixture databases are built from their committed dumps (tests/diff/FixtureDb.h). Every lookup in
// this stage is by a unique name, so the replays do not depend on the SQLite build's row order.

#include <sqlite3.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "../../src/diff/FileIo.h"
#include "../../src/diff/stages/CalleeDiffingDetail.h"
#include "diff/CorpusPaths.h"
#include "diff/FixtureDb.h"
#include "diff/ResultsCompare.h"
#include "diff/TestHarness.h"
#include "dsigmatcher/diff/Errors.h"
#include "dsigmatcher/diff/Json.h"
#include "dsigmatcher/diff/Pipeline.h"
#include "dsigmatcher/diff/ResultsWriter.h"
#include "dsigmatcher/diff/Snapshot.h"
#include "dsigmatcher/diff/Stages.h"
#include "dsigmatcher/diff/Trace.h"

namespace fs = std::filesystem;
using namespace DSig::Diff;

namespace {

using PairList = std::vector<std::pair<std::string, std::string>>;
using CallMap = std::map<std::string, int64_t>;  // find_one_match_diffing calls by "<field>:outer<k>:inner<i>"

// ---------------------------------------------------------------------------------------------
// Helpers

std::string JoinLines(std::initializer_list<std::string_view> Lines) {
  std::string Out;
  bool First = true;
  for (const std::string_view Line : Lines) {
    if (!First) {
      Out.push_back('\n');
    }
    First = false;
    Out.append(Line);
  }
  return Out;
}

std::string PairsText(const PairList& Pairs) {
  std::string Out = "[";
  for (const auto& [A, B] : Pairs) {
    Out += (Out.size() > 1 ? ", (" : "(") + A + ", " + B + ")";
  }
  return Out + "]";
}

void ExpectPairs(const std::string& What, const PairList& Actual, const PairList& Expected) {
  DSig::Test::ReportText(Actual == Expected, What.c_str(), PairsText(Actual), PairsText(Expected), __FILE__, __LINE__);
}

std::string ReadText(const std::string& Path) { return Detail::ReadFileBytes(Path); }

JsonValue ReadJsonFile(const std::string& Path) { return JsonParse(ReadText(Path)); }

std::string PathJoin(const std::string& A, const std::string& B) {
  return DSig::Test::PathToUtf8(DSig::Test::Utf8ToPath(A) / DSig::Test::Utf8ToPath(B));
}

bool FileExists(const std::string& Path) {
  std::error_code Error;
  return fs::is_regular_file(DSig::Test::Utf8ToPath(Path), Error);
}

std::string CalleeFixtureDir() { return PathJoin(PathJoin(DSig::Test::TestDataDir(), "fixtures"), "callee"); }

// A trace event with the fields that legitimately differ between a whole-run capture and a one-stage
// replay neutralised: the run-wide add_match ordinal `seq`, and the per-site cleanup counter (the "n" of a
// cleanup event and the ":<n>" suffix of its before/after point names), which a fresh replay session
// restarts at 1. Everything else is compared byte for byte (compact JSON, the oracle's key order).
std::string NormaliseEvent(JsonValue Event) {
  if (Event.Find("seq") != nullptr) {
    Event.Set("seq", JsonValue::Int(0));
  }
  const std::string Kind = Event.At("ev").AsString();
  if (Kind == "cleanup") {
    Event.Set("n", JsonValue::Int(0));
  } else if (Kind == "point") {
    std::string Name = Event.At("name").AsString();
    if (Name.starts_with("before:cleanup:") || Name.starts_with("after:cleanup:")) {
      Name = Name.substr(0, Name.rfind(':'));
      Event.Set("name", JsonValue::String(Name));
    }
  }
  return JsonWrite(Event);
}

std::vector<std::string> ReadNormalisedEvents(const std::string& Path) {
  std::vector<std::string> Out;
  std::istringstream Lines(FileExists(Path) ? ReadText(Path) : std::string());
  std::string Line;
  while (std::getline(Lines, Line)) {
    if (!Line.empty()) {
      Out.push_back(NormaliseEvent(JsonParse(Line)));
    }
  }
  return Out;
}

bool ExpectEvents(const std::string& What, const std::vector<std::string>& Actual,
                  const std::vector<std::string>& Expected) {
  const bool Same = Actual == Expected;
  DSig::Test::Report(Same, What.c_str(), __FILE__, __LINE__);
  if (!Same) {
    size_t First = 0;
    while (First < Actual.size() && First < Expected.size() && Actual[First] == Expected[First]) {
      ++First;
    }
    DSig::Test::Note("    " + std::to_string(Actual.size()) + " native events, " + std::to_string(Expected.size()) +
                     " expected; first difference at event " + std::to_string(First));
    for (size_t Index = First; Index < First + 3; ++Index) {
      if (Index < Expected.size()) {
        DSig::Test::Note("    expected: " + Expected[Index].substr(0, 400));
      }
      if (Index < Actual.size()) {
        DSig::Test::Note("    native:   " + Actual[Index].substr(0, 400));
      }
    }
  }
  return Same;
}

bool ExpectSnapshot(const std::string& What, const StateSnapshot& Oracle, const StateSnapshot& Native) {
  const DSig::Test::CompareReport Report = DSig::Test::CompareSnapshots(Oracle, Native, 10);
  DSig::Test::Report(Report.L2Equal, What.c_str(), __FILE__, __LINE__);
  if (!Report.L2Equal) {
    for (const std::string& Line : Report.Differences) {
      DSig::Test::Note("    " + Line);
    }
  }
  return Report.L2Equal;
}

std::string CallsText(const std::map<std::string, int64_t>& Calls) {
  std::string Out;
  for (const auto& [Key, Count] : Calls) {
    Out += (Out.empty() ? "" : ", ") + Key + "=" + std::to_string(Count);
  }
  return "{" + Out + "}";
}

// The find_one_match_diffing counts of one outer iteration from a run.json / expect.json object.
std::map<std::string, int64_t> CallsOfIteration(const JsonValue& Counts, int K) {
  std::map<std::string, int64_t> Out;
  const std::string Needle = ":outer" + std::to_string(K) + ":";
  for (const auto& [Key, Value] : Counts.Members()) {
    if (Key.find(Needle) != std::string::npos) {
      Out[Key] = Value.AsInt64();
    }
  }
  return Out;
}

// Runs one replay of find_matches_diffing:<K> in a fresh session on (MainDb, DiffDb): the RunReplay entry
// point (plan §2.4) with the trace written to TracePath.
struct Replay {
  std::optional<StateSnapshot> After;
  std::vector<std::string> Events;
  std::map<std::string, int64_t> Calls;
  std::optional<std::string> RaiseSite;
  std::string Error;
  std::vector<std::string> Log;
};

Replay RunCalleeReplay(const std::string& MainDb, const std::string& DiffDb, const StateSnapshot& Before, int K,
                       const std::string& TracePath) {
  Replay Out;
  DiffSession S;
  S.Log().SetQuiet(true);
  S.Open(MainDb, DiffDb);
  S.SetPairLabel(Before.Pair);
  S.EnableTrace(TracePath, false);
  try {
    Out.After = RunReplay(S, Before, "find_matches_diffing:" + std::to_string(K));
  } catch (const DiaphoraWouldRaise& Error) {
    Out.RaiseSite = Error.Site;
    Out.Error = Error.what();
  } catch (const std::exception& Error) {
    Out.Error = Error.what();
  }
  S.Tracer().Close();
  Out.Events = ReadNormalisedEvents(TracePath);
  Out.Calls = S.Ext<Detail::CalleeDiffingStats>().OneMatchDiffingCalls;
  Out.Log = S.Log().Lines();
  return Out;
}

bool IsCalleeDesc(const std::string& Desc) { return Desc.starts_with("Callee found diffing matches "); }

// (name1, name2, desc, ratio "%.7f", chooser) of every callee-diffing item of a snapshot, best then partial.
std::vector<std::string> CalleeItems(const StateSnapshot& Snap) {
  std::vector<std::string> Out;
  const auto Add = [&](const std::vector<SnapItem>& Items, const char* Chooser) {
    for (const SnapItem& It : Items) {
      if (IsCalleeDesc(It.Desc)) {
        Out.push_back(std::string(Chooser) + " " + It.Name1.value_or("None") + " -> " + It.Name2.value_or("None") +
                      " " + FormatRatio7(RatioFromBits(It.RatioBits)) + " " + std::to_string(It.Nodes1) + "/" +
                      std::to_string(It.Nodes2) + " " + It.Desc);
      }
    }
  };
  Add(Snap.Best, "best");
  Add(Snap.Partial, "partial");
  return Out;
}

bool MentionsName(const StateSnapshot& Snap, const std::string& Name) {
  for (const auto* List : {&Snap.Best, &Snap.Partial, &Snap.Unreliable}) {
    for (const SnapItem& It : *List) {
      if (It.Name1 == Name || It.Name2 == Name) {
        return true;
      }
    }
  }
  return false;
}

std::string Joined(const std::vector<std::string>& Items) {
  std::string Out;
  for (const std::string& Item : Items) {
    Out += (Out.empty() ? "" : " | ") + Item;
  }
  return Out;
}

// ---------------------------------------------------------------------------------------------
// Unit tests: the documented diff walk (03b §4.3.2-§4.3.3, 06 §6.3-§6.4, V2)

void TestDocumentedWalk() {
  DSig::Test::Suite("diff walk: documented examples (03b §4.3.2 quirks 1-4, §4.3.3, 06 §6.3 and V2)");
  using Detail::CalleeCandidatePairs;
  // quirk 1: rows ['--- ', '+++ ', '@@ -1,4 +1,4 @@', ' a', ' b', ' c', '-call foo_old', '+call foo_new'] and
  // no context row after the change, so the block is never flushed.
  ExpectPairs("quirk 1: trailing change never flushed", CalleeCandidatePairs("a\nb\nc\ncall foo_old", "a\nb\nc\ncall foo_new"),
              {});
  ExpectPairs("06 §6.3: trailing block", CalleeCandidatePairs("x1\nx2\nx3\ncall foo_a", "x1\nx2\nx3\ncall foo_b"), {});
  // quirk 2: a delete-only first hunk at line 0 is flushed together with "+++ " (no pairs).
  ExpectPairs("quirk 2: leading deletion",
              CalleeCandidatePairs(JoinLines({"call alpha_one", "x1", "x2", "x3", "x4"}), JoinLines({"x1", "x2", "x3", "x4"})),
              {});
  // 06 V2: a leading pure deletion followed later by a pure insertion gives [] (without the header rows it
  // would give [('call','call'), ('alpha_one','delta_two')]).
  ExpectPairs("V2: leading deletion then insertion",
              CalleeCandidatePairs(JoinLines({"call alpha_one", "ctx1", "ctx2", "ctx3", "ctx4", "ctx5", "ctx6", "ctx7",
                                              "ctx8", "ctx9", "ctx10", "call  beta_two", "ctxC"}),
                                   JoinLines({"ctx1", "ctx2", "ctx3", "ctx4", "ctx5", "ctx6", "ctx7", "ctx8", "ctx9",
                                              "ctx10", "call  delta_two", "call  beta_two", "ctxC"})),
              {});
  // 06 V2: a leading replace pairs normally.
  ExpectPairs("V2: leading replace",
              CalleeCandidatePairs(JoinLines({"call alpha_one", "ctx1", "ctx2", "ctx3", "ctx4", "ctx5", "ctx6"}),
                                   JoinLines({"call gamma_new", "ctx1", "ctx2", "ctx3", "ctx4", "ctx5", "ctx6"})),
              {{"call", "call"}, {"alpha_one", "gamma_new"}});
  // 06 §6.3 (hdr.py): the leading insertion is discarded with the header; alpha_one pairs with delta_two
  // across the hunks.
  ExpectPairs("06 §6.3: header discards leading insertion",
              CalleeCandidatePairs(JoinLines({"ctx1", "ctx2", "ctx3", "ctx4", "call alpha_one", "ctx5", "ctx6", "ctx7",
                                              "ctx8", "ctx9", "ctx10", "ctx11", "call  beta_two", "ctx12"}),
                                   JoinLines({"call gamma_new", "ctx1", "ctx2", "ctx3", "ctx4", "ctx5", "ctx6", "ctx7",
                                              "ctx8", "ctx9", "ctx10", "ctx11", "call  delta_two", "ctx12"})),
              {{"call", "call"}, {"alpha_one", "delta_two"}});
  // quirk 3: a middle delete-only hunk is carried into the next hunk (03b "14-line case").
  ExpectPairs("quirk 3: carried across hunks",
              CalleeCandidatePairs(JoinLines({"ctx1", "ctx2", "ctx3", "ctx4", "call alpha_one", "ctx5", "ctx6", "ctx7",
                                              "ctx8", "ctx9", "ctx10", "ctx11", "ctx12"}),
                                   JoinLines({"ctx1", "ctx2", "ctx3", "ctx4", "ctx5", "ctx6", "ctx7", "ctx8", "ctx9",
                                              "call gamma_new", "ctx10", "ctx11", "ctx12"})),
              {{"call", "call"}, {"alpha_one", "gamma_new"}});
  // quirk 4: positional pairing over every token; one extra token shifts the rest.
  ExpectPairs("quirk 4: positional pairing",
              CalleeCandidatePairs(JoinLines({"c0", "c1", "c2", "call pos_old_a", "c3", "c4", "c5"}),
                                   JoinLines({"c0", "c1", "c2", "call extra_tok pos_new_a", "c3", "c4", "c5"})),
              {{"call", "call"}, {"pos_old_a", "extra_tok"}});
  // 06 §6.3 / V2: findall over "jmp mov call push lea test" gives ['call', 'push', 'test'].
  ExpectPairs("V2: 3-character mnemonics are not names",
              CalleeCandidatePairs(JoinLines({"s0", "s1", "jmp mov call push lea test", "s2", "s3"}),
                                   JoinLines({"s0", "s1", "jmp mov call push lea test extra", "s2", "s3"})),
              {{"call", "call"}, {"push", "push"}, {"test", "test"}});
  // 03b §4.3.3: `call Foo::Barbaz::x` -> ['call', 'Barbaz::x'], `call abc::defg` -> ['call', 'defg'],
  // `push qword ptr [rax]` -> ['push', 'qword'], `mov eax, 0x401000` -> ['x401000'].
  ExpectPairs("03b §4.3.3 namespaces", CalleeCandidatePairs("q0\ncall Foo::Barbaz::x\nq1", "q0\ncall abc::defg\nq1"),
              {{"call", "call"}, {"Barbaz::x", "defg"}});
  ExpectPairs("03b §4.3.3 hex constant", CalleeCandidatePairs("q0\npush qword ptr [rax]\nq1", "q0\nmov eax, 0x401000\nq1"),
              {{"push", "x401000"}});
  ExpectPairs("06 §6.4 no word boundary",
              CalleeCandidatePairs("q0\n12abcd std::vector::push_back\nq1", "q0\nab_c sub_401000\nq1"),
              {{"abcd", "ab_c"}, {"vector::push_back", "sub_401000"}});
  // 06 §6.4: under re.IGNORECASE, U+017F, U+212A, U+0130 and U+0131 are letters (UTF-8 below).
  ExpectPairs("06 §6.4 IGNORECASE letters",
              CalleeCandidatePairs("u0\ncall \xC5\xBF" "ub_1234 \xE2\x84\xAA" "ernel\nu1",
                                   "u0\ncall \xC4\xB0" "dent_x \xC4\xB1" "dent_y\nu1"),
              {{"call", "call"}, {"\xC5\xBF" "ub_1234", "\xC4\xB0" "dent_x"}, {"\xE2\x84\xAA" "ernel", "\xC4\xB1" "dent_y"}});
  // 06 §6.1: splitlines separators (U+2028 / U+2029 / U+0085 as UTF-8, \v, \f, \x1c-\x1e, \r, \r\n).
  ExpectPairs("06 §6.1 separators",
              CalleeCandidatePairs("p0\x1e" "call sep_old_two\xC2\x85p1\xE2\x80\xA8p2\xE2\x80\xA9p3",
                                   "p0\x1e" "call sep_new_two\xC2\x85p1\xE2\x80\xA8p2\xE2\x80\xA9p3"),
              {{"call", "call"}, {"sep_old_two", "sep_new_two"}});
  ExpectPairs("identical texts yield no rows", CalleeCandidatePairs("same\ntext\nhere", "same\ntext\nhere"), {});
  ExpectPairs("empty main text", CalleeCandidatePairs("", "call only_new\nx"), {});
  ExpectPairs("empty texts", CalleeCandidatePairs("", ""), {});
}

// ---------------------------------------------------------------------------------------------
// Vector tests: walk_vectors.json (real find_one_match_diffing)

void TestWalkVectors() {
  DSig::Test::Suite("diff walk: vectors recorded from the unmodified find_one_match_diffing");
  const std::string Path = PathJoin(CalleeFixtureDir(), "walk_vectors.json");
  if (DSig::Test::TestDataDir().empty() || !FileExists(Path)) {
    DSig::Test::Skip("walk vectors", "walk_vectors.json not found (DSIG_TEST_DATA_DIR)");
    return;
  }
  const JsonValue Root = ReadJsonFile(Path);
  CHECK(!Root.At("has_cdifflib").AsBool());
  int Cases = 0;
  int Failed = 0;
  size_t Pairs = 0;
  for (const JsonValue& Case : Root.At("cases").Items()) {
    const std::string& Main = Case.At("main").AsString();
    const std::string& Diff = Case.At("diff").AsString();
    PairList Expected;
    for (const JsonValue& P : Case.At("pairs").Items()) {
      Expected.emplace_back(P.Items().at(0).AsString(), P.Items().at(1).AsString());
    }
    std::vector<std::string> ExpectedKeys;
    for (const JsonValue& K : Case.At("keys").Items()) {
      ExpectedKeys.push_back(K.AsString());
    }
    PairList ExpectedExists;
    for (const JsonValue& P : Case.At("exists").Items()) {
      ExpectedExists.emplace_back(P.Items().at(0).AsString(), P.Items().at(1).AsString());
    }
    const PairList Actual = Detail::CalleeCandidatePairs(Main, Diff);
    // D:3067-3074 over the pairs: the key is added to dones first, then the nullsub filter.
    std::set<std::string> Dones;
    std::vector<std::string> Keys;
    PairList Exists;
    for (const auto& [A, B] : Actual) {
      const std::string Key = A + "-" + B;
      if (!Dones.insert(Key).second) {
        continue;
      }
      Keys.push_back(Key);
      if (A.starts_with("nullsub") || B.starts_with("nullsub")) {
        continue;
      }
      Exists.emplace_back(A, B);
    }
    const bool Ok = Actual == Expected && Keys == ExpectedKeys && Exists == ExpectedExists;
    ++Cases;
    Pairs += Expected.size();
    CHECK(Actual == Expected);
    CHECK(Keys == ExpectedKeys);
    CHECK(Exists == ExpectedExists);
    if (!Ok && ++Failed <= 5) {
      DSig::Test::Note("case " + std::to_string(Cases - 1) + ": native " + PairsText(Actual) + " expected " +
                       PairsText(Expected));
    }
  }
  DSig::Test::Note(std::to_string(Cases) + " cases, " + std::to_string(Pairs) + " recorded pairs, " +
                   std::to_string(Failed) + " failed");
  CHECK(Cases == 425);
}

// ---------------------------------------------------------------------------------------------
// Fixture replays: tests/diff/fixtures/callee/<scenario>/ (real Diaphora, gen_callee_fixtures.py)

struct ScenarioDbs {
  std::string Main;
  std::string Diff;
};

std::optional<ScenarioDbs> BuildScenario(const std::string& Name, const std::string& Scratch) {
  const std::string Dir = PathJoin(CalleeFixtureDir(), Name);
  ScenarioDbs Dbs{PathJoin(Scratch, Name + "_main.sqlite"), PathJoin(Scratch, Name + "_diff.sqlite")};
  const std::string E1 = DSig::Test::BuildFixtureDb(PathJoin(Dir, "main.sql"), Dbs.Main);
  const std::string E2 = DSig::Test::BuildFixtureDb(PathJoin(Dir, "diff.sql"), Dbs.Diff);
  CHECK_TEXT_EQ(E1, "");
  CHECK_TEXT_EQ(E2, "");
  if (!E1.empty() || !E2.empty()) {
    return std::nullopt;
  }
  return Dbs;
}

struct ScenarioRun {
  std::map<int, Replay> Replays;
  JsonValue Expect;
};

std::optional<ScenarioRun> ReplayScenario(const std::string& Name, const std::string& Scratch) {
  const std::string Dir = PathJoin(CalleeFixtureDir(), Name);
  const auto Dbs = BuildScenario(Name, Scratch);
  if (!Dbs) {
    return std::nullopt;
  }
  ScenarioRun Run;
  Run.Expect = ReadJsonFile(PathJoin(Dir, "expect.json"));
  CHECK(!Run.Expect.At("has_cdifflib").AsBool());
  const std::vector<JsonValue>& Iterations = Run.Expect.At("iterations").Items();
  for (size_t Index = 0; Index < Iterations.size(); ++Index) {
    const int K = static_cast<int>(Iterations[Index].AsInt64());
    const std::string Label = Name + " find_matches_diffing:" + std::to_string(K);
    const StateSnapshot Before = ReadSnapshot(PathJoin(Dir, "before_" + std::to_string(K) + ".json"));
    CHECK_TEXT_EQ(Before.Point, "before:find_matches_diffing:" + std::to_string(K));
    Replay R = RunCalleeReplay(Dbs->Main, Dbs->Diff, Before, K, PathJoin(Scratch, Name + "_trace.jsonl"));
    const std::string AfterPath = PathJoin(Dir, "after_" + std::to_string(K) + ".json");
    const JsonValue& Exception = Run.Expect.At("exception");
    const bool LastIteration = Index + 1 == Iterations.size();
    if (FileExists(AfterPath)) {
      CHECK_TEXT_EQ(R.Error, "");
      if (R.After) {
        ExpectSnapshot(Label + " state (S-L2)", ReadSnapshot(AfterPath), *R.After);
      } else {
        DSig::Test::Report(false, (Label + ": no after snapshot").c_str(), __FILE__, __LINE__);
      }
    } else {
      // Diaphora raised inside this stage: the native engine raises at the same site (plan §3.11).
      CHECK(LastIteration && !Exception.IsNull());
      if (!Exception.IsNull()) {
        const std::string Site =
            "D:" + std::to_string(Exception.At("line").AsInt64()) + " " + Exception.At("type").AsString();
        CHECK_TEXT_EQ(R.RaiseSite.value_or("(no raise: " + R.Error + ")"), Site);
      }
    }
    std::vector<std::string> Expected = ReadNormalisedEvents(PathJoin(Dir, "events_" + std::to_string(K) + ".jsonl"));
    ExpectEvents(Label + " trace events", R.Events, Expected);
    const std::map<std::string, int64_t> ExpectedCalls = CallsOfIteration(Run.Expect.At("find_one_match_diffing"), K);
    DSig::Test::ReportText(R.Calls == ExpectedCalls, (Label + " find_one_match_diffing calls").c_str(),
                           CallsText(R.Calls), CallsText(ExpectedCalls), __FILE__, __LINE__);
    Run.Replays.emplace(K, std::move(R));
  }
  return Run;
}

void TestFixtureScenarios(const std::string& Scratch) {
  DSig::Test::Suite("fixture replays: before:find_matches_diffing:k -> stage -> after (real Diaphora)");
  if (DSig::Test::TestDataDir().empty() || !FileExists(PathJoin(PathJoin(CalleeFixtureDir(), "exp_a"), "expect.json"))) {
    DSig::Test::Skip("fixture replays", "tests/diff/fixtures/callee not found (DSIG_TEST_DATA_DIR)");
    return;
  }
  // 03b §4.3.2 quirk 5, experiment A: only caller_fn and alpha_old_callee -> beta_new_callee (partial
  // 0.9008889, "(iteration #1)"); gamma_old_leaf -> delta_new_leaf is never found.
  if (auto Run = ReplayScenario("exp_a", Scratch)) {
    const auto& R0 = Run->Replays.at(0);
    if (R0.After) {
      CHECK_TEXT_EQ(Joined(CalleeItems(*R0.After)),
                    "partial alpha_old_callee -> beta_new_callee 0.9008889 5/6 Callee found diffing matches pseudo-code "
                    "(iteration #1)");
    }
    for (const auto& [K, R] : Run->Replays) {
      CHECK(R.After && !MentionsName(*R.After, "gamma_old_leaf") && !MentionsName(*R.After, "delta_new_leaf"));
    }
    // outer iteration 1: caller_fn re-emits alpha_old_callee-beta_new_callee before that match is reached
    // as a seed, so the pseudo-code pass calls find_one_match_diffing once (caller_fn) and the assembly
    // pass (its own dones) twice.
    const auto& Calls1 = Run->Replays.at(1).Calls;
    CHECK(Calls1.count("pseudocode:outer1:inner1") == 1 && Calls1.at("pseudocode:outer1:inner1") == 1);
    CHECK(Calls1.count("assembly:outer1:inner1") == 1 && Calls1.at("assembly:outer1:inner1") == 2);
  }
  // 03b §4.3.4 experiment Z: nodes = 0 on both callees -> ZeroDivisionError at D:3089, no output.
  if (auto Run = ReplayScenario("exp_z", Scratch)) {
    CHECK_TEXT_EQ(Run->Replays.at(0).RaiseSite.value_or("(none)"), "D:3089 ZeroDivisionError");
    CHECK(!Run->Replays.at(0).After.has_value());
  }
  // The walk quirks through the whole stage: only the carried middle block pairs (mid_old_fn, mid_new_fn);
  // the leading deletion, the shifted pair and the trailing block produce nothing.
  if (auto Run = ReplayScenario("walk_quirks", Scratch)) {
    const auto& R0 = Run->Replays.at(0);
    if (R0.After) {
      CHECK_TEXT_EQ(Joined(CalleeItems(*R0.After)),
                    "partial mid_old_fn -> mid_new_fn 0.9008889 5/6 Callee found diffing matches pseudo-code "
                    "(iteration #1)");
      for (const char* Name : {"lead_old_fn", "pos_old_fn", "tail_old_fn", "pos_new_fn", "tail_new_fn"}) {
        CHECK(!MentionsName(*R0.After, Name));
      }
    }
  }
  // Gates and churn (06 §6.5, §6.7).
  if (auto Run = ReplayScenario("churn_gates", Scratch)) {
    const auto& R0 = Run->Replays.at(0);
    bool ExactAppended = false;
    for (const std::string& Event : R0.Events) {
      if (Event.find("\"ev\":\"add_match\"") != std::string::npos &&
          Event.find("\"name1\":\"same_exact\"") != std::string::npos &&
          Event.find("\"chooser\":\"best\"") != std::string::npos &&
          Event.find("\"result\":\"appended\"") != std::string::npos) {
        ExactAppended = true;
      }
    }
    CHECK(ExactAppended);  // add_match has no has_best_match check: the same-name 1.0 pair is appended again
    if (R0.After) {
      const std::string Items = Joined(CalleeItems(*R0.After));
      CHECK(Items.find("same_exact") == std::string::npos);  // ... and the next cleanup removes it (06 §6.7)
      CHECK(Items.find("gate_edge_a -> gate_edge_b") != std::string::npos);  // 4 / 16 nodes: exactly 25.0 passes
      for (const char* Name : {"gate_small_a", "gate_pct_a", "nullsub_1a", "nullsubx_a"}) {
        CHECK(!MentionsName(*R0.After, Name));
      }
    }
    // hub_fn and emptypseudo_fn ("" is processed); nopseudo_fn (NULL on the diff side) is skipped.
    CHECK(R0.Calls.count("pseudocode:outer0:inner1") == 1 && R0.Calls.at("pseudocode:outer0:inner1") == 2);
  }
  // Different processors: no assembly pass (D:3219-3224).
  if (auto Run = ReplayScenario("other_cpu", Scratch)) {
    for (const auto& [K, R] : Run->Replays) {
      bool Assembly = false;
      for (const auto& [Key, Count] : R.Calls) {
        Assembly = Assembly || Key.starts_with("assembly:");
      }
      CHECK(!Assembly);
    }
  }
}

// ---------------------------------------------------------------------------------------------
// Unit tests on the churn_gates databases: the D:3084-3129 rules with scripted ratios, and the raise /
// refusal sites.

class ScriptedRatio final : public IRatioProvider {
public:
  explicit ScriptedRatio(DiffSession& Session) : S(Session) {}
  double Value = 0.5;
  std::vector<std::string> Calls;  // "main name/diff name"

  double CheckRatio(const HeuristicRow&, MdSource) override { throw std::logic_error("CheckRatio is unused here"); }
  double CompareFunctionRows(uint32_t MainRow, uint32_t DiffRow) override {
    Calls.push_back(std::string(S.Ids().NameText(S.Main().Functions.NameIdOf.at(MainRow))) + "/" +
                    std::string(S.Ids().NameText(S.Diff().Functions.NameIdOf.at(DiffRow))));
    return Value;
  }

private:
  DiffSession& S;
};

uint32_t RowNamed(DiffSession& S, Side Which, std::string_view Name) {
  const auto Rows = S.Export(Which).Functions.RowsNamed(S.Ids().Name(Name));
  if (Rows.empty()) {
    throw std::logic_error("no row named " + std::string(Name));
  }
  return Rows.front();
}

// A seed match as a same-name pass would store it (ratio `Ratio`, chooser `C`).
void AddSeed(DiffSession& S, std::string_view Name1, std::string_view Name2, double Ratio, Chooser C,
             std::string_view Desc = "Perfect match, same name") {
  const uint32_t R1 = RowNamed(S, Side::Main, Name1);
  const uint32_t R2 = RowNamed(S, Side::Diff, Name2);
  const FunctionTable& M = S.Main().Functions;
  const FunctionTable& D = S.Diff().Functions;
  const NameId N1 = S.Ids().Name(Name1);
  const NameId N2 = S.Ids().Name(Name2);
  S.State().AddMatch(N1, N2, Ratio,
                     Item{M.AddrIdOf[R1], N1, D.AddrIdOf[R2], N2, S.Ids().Desc(Desc), Ratio, M.Nodes.Value[R1],
                          D.Nodes.Value[R2]},
                     C);
}

std::string ItemsText(DiffSession& S, Chooser C) {
  std::string Out;
  for (const Item& It : S.State().Items(C)) {
    Out += (Out.empty() ? "" : " | ") + std::string(S.Ids().NameKeyText(It.Name1)) + "->" +
           std::string(S.Ids().NameKeyText(It.Name2)) + " " + FormatRatio7(It.Ratio) + " " +
           std::string(S.Ids().DescText(It.Desc));
  }
  return Out;
}

// Applies SQL to a scratch fixture database (sqlite3_exec). Returns "" or the error.
std::string ExecOn(const std::string& Db, const std::string& Sql) {
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

struct RulesRun {
  std::string Best;
  std::string Partial;
  std::vector<std::string> Calls;
  std::map<std::string, int64_t> Stats;
  std::vector<std::string> Events;
  std::optional<std::string> RaiseSite;
  std::optional<std::string> Unsupported;
};

// hub_fn -> hub_fn as the only seed (best, 1.0), then StageFindMatchesDiffing(S, 0) with every
// compare_function_rows answered by `Value`. `Setup` may add seeds first.
RulesRun RunRules(const ScenarioDbs& Dbs, double Value, bool SameProcessor, const std::string& TracePath,
                  const std::function<void(DiffSession&)>& Setup = nullptr, int64_t Total1 = 10) {
  RulesRun Out;
  DiffSession S;
  S.Log().SetQuiet(true);
  S.Open(Dbs.Main, Dbs.Diff);
  ScriptedRatio Ratio(S);
  Ratio.Value = Value;
  S.SetRatioProvider(&Ratio);
  S.Flags().IsSameProcessor = SameProcessor;
  S.State().SetTotals(Total1, 10);
  if (Setup) {
    Setup(S);
  } else {
    AddSeed(S, "hub_fn", "hub_fn", 1.0, Chooser::Best);
  }
  S.EnableTrace(TracePath, false);
  try {
    ContextScope Scope(S, "find_matches_diffing:0");
    StageFindMatchesDiffing(S, 0);
  } catch (const DiaphoraWouldRaise& Error) {
    Out.RaiseSite = Error.Site;
  } catch (const UnsupportedInput& Error) {
    Out.Unsupported = Error.What;
  }
  S.Tracer().Close();
  Out.Best = ItemsText(S, Chooser::Best);
  Out.Partial = ItemsText(S, Chooser::Partial);
  Out.Calls = Ratio.Calls;
  Out.Stats = S.Ext<Detail::CalleeDiffingStats>().OneMatchDiffingCalls;
  Out.Events = ReadNormalisedEvents(TracePath);
  return Out;
}

int CountEvents(const std::vector<std::string>& Events, std::string_view Needle) {
  return static_cast<int>(std::count_if(Events.begin(), Events.end(), [&](const std::string& E) {
    return E.find(Needle) != std::string::npos;
  }));
}

void TestRules(const std::string& Scratch) {
  DSig::Test::Suite("rules: chooser, bonus, gates, dones, inner iterations (D:3084-3129, D:3150-3193)");
  if (DSig::Test::TestDataDir().empty() || !FileExists(PathJoin(PathJoin(CalleeFixtureDir(), "churn_gates"), "main.sql"))) {
    DSig::Test::Skip("rules", "tests/diff/fixtures/callee/churn_gates not found");
    return;
  }
  const auto Dbs = BuildScenario("churn_gates", Scratch);
  if (!Dbs) {
    return;
  }
  const std::string Trace = PathJoin(Scratch, "rules_trace.jsonl");
  const std::string Desc = "Callee found diffing matches pseudo-code (iteration #1)";

  // r == 1.0 -> best, no bonus (D:3102-3103, D:3109). The candidates that pass the gates are same_exact,
  // same_changed and gate_edge (gate_small: nodes 2 < 3; gate_pct: 300/13 < 25; the nullsub pairs are
  // filtered before functions_exists). The appends change the count, so a second inner iteration runs; it
  // walks nothing (every key is in dones) and ends with its own cleanup (06 §5).
  {
    const RulesRun R = RunRules(*Dbs, 1.0, false, Trace);
    CHECK(!R.RaiseSite && !R.Unsupported);
    CHECK_TEXT_EQ(R.Best, "hub_fn->hub_fn 1.0000000 Perfect match, same name | same_exact->same_exact 1.0000000 " + Desc +
                              " | same_changed->same_changed 1.0000000 " + Desc + " | gate_edge_a->gate_edge_b 1.0000000 " +
                              Desc);
    CHECK_TEXT_EQ(R.Partial, "");
    CHECK(R.Calls == std::vector<std::string>({"same_exact/same_exact", "same_changed/same_changed", "gate_edge_a/gate_edge_b"}));
    CHECK(R.Stats == CallMap({{"pseudocode:outer0:inner1", 1}}));
    CHECK_NUM_EQ(CountEvents(R.Events, "\"ev\":\"cleanup\",\"site\":3217"), 1);
    CHECK_NUM_EQ(CountEvents(R.Events, "\"ev\":\"cleanup\",\"site\":3185"), 2);
  }
  // DEFAULT_TRUSTED_PARTIAL_RATIO is strict: r == 0.3 is dropped (D:3104-3107); one inner iteration.
  {
    const RulesRun R = RunRules(*Dbs, 0.3, false, Trace);
    CHECK_TEXT_EQ(R.Best, "hub_fn->hub_fn 1.0000000 Perfect match, same name");
    CHECK_TEXT_EQ(R.Partial, "");
    CHECK_NUM_EQ(R.Calls.size(), 3);
    CHECK_NUM_EQ(CountEvents(R.Events, "\"ev\":\"cleanup\",\"site\":3185"), 1);
  }
  // the next double above 0.3 is a partial, and gets the bonus after the chooser was picked (D:3109-3110).
  {
    const double Above = std::nextafter(0.3, 1.0);
    const RulesRun R = RunRules(*Dbs, Above, false, Trace);
    const std::string Ratio = FormatRatio7(Above + 0.01);
    // same_exact / same_changed are equal-name pairs: add_match forces 1.0 into matched_* only, the item
    // keeps its ratio (D:1350-1351).
    CHECK_TEXT_EQ(R.Partial, "same_exact->same_exact " + Ratio + " " + Desc + " | same_changed->same_changed " + Ratio +
                                 " " + Desc + " | gate_edge_a->gate_edge_b " + Ratio + " " + Desc);
  }
  // 0.99 + 0.01 == 1.0 in double, so a 0.99 ratio gets no bonus (06 §6.5 item 7); 0.98 becomes 0.98 + 0.01.
  {
    const RulesRun R = RunRules(*Dbs, 0.99, false, Trace);
    CHECK(R.Partial.find("gate_edge_a->gate_edge_b 0.9900000 ") != std::string::npos);
    CHECK(0.99 + 0.01 == 1.0);
    const RulesRun R2 = RunRules(*Dbs, 0.98, false, Trace);
    CHECK(R2.Partial.find("gate_edge_a->gate_edge_b " + FormatRatio7(0.98 + 0.01) + " ") != std::string::npos);
  }
  // Same processor: the assembly pass runs first, with its own dones set (D:3219-3224, D:3159). hub_fn's
  // assembly is identical on both sides, so it yields no candidate; the pseudo-code pass is unchanged.
  {
    const RulesRun R = RunRules(*Dbs, 0.5, true, Trace);
    CHECK(R.Stats == CallMap({{"assembly:outer0:inner1", 1}, {"pseudocode:outer0:inner1", 1}}));
    CHECK_NUM_EQ(R.Calls.size(), 3);
    CHECK(R.Partial.find("(iteration #1)") != std::string::npos);
  }
  // The shared dones key space (03b §4.3.2 quirk 5, 06 §5): a seed walked BEFORE hub_fn puts its key into
  // dones, so hub_fn's identical candidate is skipped (no second compare); a seed walked AFTER hub_fn is
  // skipped as a seed because the candidate put its key there first.
  {
    const RulesRun First = RunRules(*Dbs, 0.5, false, Trace, [](DiffSession& S) {
      AddSeed(S, "gate_edge_a", "gate_edge_b", 1.0, Chooser::Best, "Some heuristic");
      AddSeed(S, "hub_fn", "hub_fn", 1.0, Chooser::Best);
    });
    CHECK(First.Calls == std::vector<std::string>({"same_exact/same_exact", "same_changed/same_changed"}));
    CHECK(First.Stats == CallMap({{"pseudocode:outer0:inner1", 2}}));
    const RulesRun Second = RunRules(*Dbs, 0.5, false, Trace, [](DiffSession& S) {
      AddSeed(S, "hub_fn", "hub_fn", 1.0, Chooser::Best);
      AddSeed(S, "gate_edge_a", "gate_edge_b", 0.9, Chooser::Partial, "Some heuristic");
    });
    CHECK(Second.Calls == std::vector<std::string>({"same_exact/same_exact", "same_changed/same_changed",
                                                     "gate_edge_a/gate_edge_b"}));
    CHECK(Second.Stats == CallMap({{"pseudocode:outer0:inner1", 1}}));
  }
  // A seed whose name is Python None: its key renders "None" (D:3168) and get_function_row(None) binds NULL,
  // which matches no row, so it is skipped (D:3175).
  {
    const RulesRun R = RunRules(*Dbs, 0.5, false, Trace, [](DiffSession& S) {
      const uint32_t R1 = RowNamed(S, Side::Main, "hub_fn");
      const uint32_t R2 = RowNamed(S, Side::Diff, "hub_fn");
      S.State().AddMatch(kNoneName, S.Ids().Name("hub_fn"), 1.0,
                         Item{S.Main().Functions.AddrIdOf[R1], kNoneName, S.Diff().Functions.AddrIdOf[R2],
                              S.Ids().Name("hub_fn"), S.Ids().Desc("x"), 1.0, 12, 12},
                         Chooser::Best);
      AddSeed(S, "hub_fn", "hub_fn", 1.0, Chooser::Best);
    });
    CHECK(!R.RaiseSite && !R.Unsupported);
    CHECK(R.Stats == CallMap({{"pseudocode:outer0:inner1", 1}}));
  }
  // show_summary after the D:3185 cleanup divides by total_functions1 (D:1631).
  {
    const RulesRun R = RunRules(*Dbs, 0.5, false, Trace, nullptr, 0);
    CHECK_TEXT_EQ(R.RaiseSite.value_or("(none)"), "D:1631 ZeroDivisionError");
  }
}

void TestRaiseAndRefuse(const std::string& Scratch) {
  DSig::Test::Suite("raise and refusal sites (D:3084, D:3089, fetch errors, 06 §2.10, BLOB text)");
  if (DSig::Test::TestDataDir().empty() || !FileExists(PathJoin(PathJoin(CalleeFixtureDir(), "churn_gates"), "main.sql"))) {
    DSig::Test::Skip("raise and refusal sites", "tests/diff/fixtures/callee/churn_gates not found");
    return;
  }
  const std::string Trace = PathJoin(Scratch, "raise_trace.jsonl");
  const auto Variant = [&](const std::string& MainSql, const std::string& DiffSql) -> std::optional<ScenarioDbs> {
    auto Dbs = BuildScenario("churn_gates", Scratch);
    if (!Dbs) {
      return std::nullopt;
    }
    if (!MainSql.empty()) {
      CHECK_TEXT_EQ(ExecOn(Dbs->Main, MainSql), "");
    }
    if (!DiffSql.empty()) {
      CHECK_TEXT_EQ(ExecOn(Dbs->Diff, DiffSql), "");
    }
    return Dbs;
  };
  // D:3084 min(None, x): TypeError.
  if (auto Dbs = Variant("", "update functions set nodes = NULL where name = 'gate_edge_b'")) {
    const RulesRun R = RunRules(*Dbs, 0.5, false, Trace);
    CHECK_TEXT_EQ(R.RaiseSite.value_or("(none)"), "D:3084 TypeError");
  }
  // D:3088-3089: max_nodes == 0 raises before the DIFFING_MATCHES_MIN_BBLOCKS checks.
  if (auto Dbs = Variant("update functions set nodes = 0 where name = 'gate_edge_a'",
                         "update functions set nodes = 0 where name = 'gate_edge_b'")) {
    const RulesRun R = RunRules(*Dbs, 0.5, false, Trace);
    CHECK_TEXT_EQ(R.RaiseSite.value_or("(none)"), "D:3089 ZeroDivisionError");
    CHECK(R.Calls == std::vector<std::string>({"same_exact/same_exact", "same_changed/same_changed"}));
  }
  // 06 §2.10: two main rows named gate_edge_a and none named gate_edge_b in diff also give exists == True;
  // the port refuses (UnsupportedInput) instead of comparing two main rows.
  if (auto Dbs = Variant("update functions set name = 'gate_edge_a' where name = 'gate_pct_a'",
                         "update functions set name = 'gate_edge_x' where name = 'gate_edge_b'")) {
    const RulesRun R = RunRules(*Dbs, 0.5, false, Trace);
    CHECK(R.Unsupported.has_value() && R.Unsupported->find("same database") != std::string::npos);
  }
  // The quirk only matters where Python would compare the two rows: when a node check rejects the pair
  // first (here main_row / diff_row are two main rows with 2 and 4 nodes, D:3096-3099), Python continues,
  // and so does the port.
  if (auto Dbs = Variant("update functions set name = 'gate_small_a' where name = 'gate_edge_a'",
                         "update functions set name = 'gone_b' where name = 'gate_small_b'")) {
    const RulesRun R = RunRules(*Dbs, 0.5, false, Trace);
    CHECK(!R.RaiseSite && !R.Unsupported);
    CHECK(R.Calls == std::vector<std::string>({"same_exact/same_exact", "same_changed/same_changed"}));
  }
  // ... and the mirrored case (no main row, two diff rows).
  if (auto Dbs = Variant("update functions set name = 'gate_edge_z' where name = 'gate_edge_a'",
                         "update functions set name = 'gate_edge_b' where name = 'gate_pct_b'")) {
    const RulesRun R = RunRules(*Dbs, 0.5, false, Trace);
    CHECK(R.Unsupported.has_value() && R.Unsupported->find("same database") != std::string::npos);
  }
  // get_function_row's bare except (D:2456-2457): a seed row Python cannot decode is None, so the seed is
  // skipped without an error.
  if (auto Dbs = Variant("update functions set comment = cast(x'ff' as text) where name = 'hub_fn'", "")) {
    const RulesRun R = RunRules(*Dbs, 0.5, false, Trace);
    CHECK(!R.RaiseSite && !R.Unsupported);
    CHECK(R.Stats.empty());
    CHECK(R.Calls.empty());
  }
  // functions_exists has no except clause (D:2974-2990): the fetch error propagates.
  if (auto Dbs = Variant("", "update functions set comment = cast(x'ff' as text) where name = 'gate_edge_b'")) {
    const RulesRun R = RunRules(*Dbs, 0.5, false, Trace);
    CHECK_TEXT_EQ(R.RaiseSite.value_or("(none)"), "fetch");
  }
  // A BLOB pseudocode would be Python bytes at D:3040: refused, not emulated.
  if (auto Dbs = Variant("update functions set pseudocode = cast(pseudocode as blob) where name = 'hub_fn'", "")) {
    const RulesRun R = RunRules(*Dbs, 0.5, false, Trace);
    CHECK(R.Unsupported.has_value() && R.Unsupported->find("BLOB") != std::string::npos);
  }
  // A non-INTEGER nodes value (REAL storage) is refused rather than given Python's float semantics.
  if (auto Dbs = Variant("", "update functions set nodes = 16.5 where name = 'gate_edge_b'")) {
    const RulesRun R = RunRules(*Dbs, 0.5, false, Trace);
    CHECK(R.Unsupported.has_value() && R.Unsupported->find("nodes") != std::string::npos);
  }
  // Hooks (patch-diff mode only, where the loop never runs): the candidate goes through
  // PatchDiffHookOnMatch (lane L5), which returns (True, ratio), so the state is unchanged by it.
  if (auto Dbs = BuildScenario("churn_gates", Scratch)) {
    const RulesRun Plain = RunRules(*Dbs, 0.5, false, Trace);
    const RulesRun Hooked = RunRules(*Dbs, 0.5, false, Trace, [](DiffSession& S) {
      S.Flags().HooksLoaded = true;
      AddSeed(S, "hub_fn", "hub_fn", 1.0, Chooser::Best);
    });
    CHECK(!Hooked.RaiseSite && !Hooked.Unsupported);
    CHECK_TEXT_EQ(Hooked.Partial, Plain.Partial);
    CHECK_TEXT_EQ(Hooked.Best, Plain.Best);
  }
}

// ---------------------------------------------------------------------------------------------
// Corpus replays (S-L2 and trace level)

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

// snapshots/NNNNN_<sanitised point>.json of a capture for the find_matches_diffing points. A listed .json
// file is final (the oracle writes <name>.tmp and renames it).
std::map<std::string, SnapshotFile> ListCalleeSnapshots(const fs::path& Dir) {
  std::map<std::string, SnapshotFile> Out;
  std::error_code Error;
  for (const fs::directory_entry& Entry : fs::directory_iterator(Dir, Error)) {
    const std::string Name = DSig::Test::PathToUtf8(Entry.path().filename());
    const size_t Underscore = Name.find('_');
    if (Underscore == std::string::npos || Underscore < 5 || !Name.ends_with(".json") ||
        Name.find("find_matches_diffing_") == std::string::npos) {
      continue;
    }
    const std::string Digits = Name.substr(0, Underscore);
    if (!std::all_of(Digits.begin(), Digits.end(), [](char C) { return C >= '0' && C <= '9'; })) {
      continue;
    }
    Out[Name.substr(Underscore + 1, Name.size() - Underscore - 6)] =
        SnapshotFile{std::stoll(Digits), DSig::Test::PathToUtf8(Entry.path())};
  }
  return Out;
}

// The oracle trace events strictly between before:find_matches_diffing:k and after:find_matches_diffing:k
// for every k in Ks, normalised. Streams the file and stops after the last needed after point, so only the
// head of a long capture's trace is read. Complete[k] is set when k's after point was seen.
std::map<int, std::vector<std::string>> ReadOracleSegments(const std::string& TracePath, const std::set<int>& Ks,
                                                           std::map<int, bool>& Complete, int& OtherEvents) {
  std::map<int, std::vector<std::string>> Out;
  std::ifstream In(DSig::Test::Utf8ToPath(TracePath), std::ios::binary);
  std::string Line;
  std::optional<int> Open;
  size_t Done = 0;
  OtherEvents = 0;
  static const std::string BeforeTag = "\"name\":\"before:find_matches_diffing:";
  static const std::string AfterTag = "\"name\":\"after:find_matches_diffing:";
  while (Done < Ks.size() && std::getline(In, Line)) {
    const bool IsPoint = Line.find("\"ev\":\"point\"") != std::string::npos;
    if (IsPoint) {
      if (const size_t At = Line.find(BeforeTag); At != std::string::npos) {
        const int K = std::stoi(Line.substr(At + BeforeTag.size()));
        if (Ks.count(K) != 0) {
          Open = K;
          Out[K].clear();
        }
        continue;
      }
      if (const size_t At = Line.find(AfterTag); At != std::string::npos) {
        const int K = std::stoi(Line.substr(At + AfterTag.size()));
        if (Open && *Open == K) {
          Complete[K] = true;
          ++Done;
          Open.reset();
        }
        continue;
      }
    }
    if (!Open) {
      continue;
    }
    const JsonValue Event = JsonParse(Line);
    const std::string Kind = Event.At("ev").AsString();
    if (Kind == "add_match" || Kind == "cleanup" || Kind == "point") {
      Out[*Open].push_back(NormaliseEvent(Event));
    } else {
      ++OtherEvents;  // callee diffing calls no check_match, so a --rows capture has no row event here
    }
  }
  return Out;
}

struct CorpusCounts {
  int Replays = 0;
  int StatePassed = 0;
  int EventsPassed = 0;
  int CallsPassed = 0;
  int CallsCompared = 0;
  int64_t AddMatches = 0;
};

CorpusCounts ReplayCapture(const std::string& Name, const std::string& Pair, const fs::path& Dir,
                           const std::string& Scratch, std::map<std::string, int64_t>& Totals) {
  CorpusCounts Counts;
  const auto Ids = ExportIdsOfPair(Pair);
  if (!Ids) {
    DSig::Test::Note(Name + ": skipped (exports not found)");
    return Counts;
  }
  const std::map<std::string, SnapshotFile> Files = ListCalleeSnapshots(Dir / "snapshots");
  std::set<int> Ks;
  for (const auto& [Point, File] : Files) {
    if (Point.starts_with("before_find_matches_diffing_")) {
      const int K = std::stoi(Point.substr(std::string("before_find_matches_diffing_").size()));
      if (Files.count("after_find_matches_diffing_" + std::to_string(K)) != 0) {
        Ks.insert(K);
      }
    }
  }
  if (Ks.empty()) {
    DSig::Test::Note(Name + ": no find_matches_diffing snapshot pair");
    return Counts;
  }
  std::map<int, bool> Complete;
  int OtherEvents = 0;
  const std::map<int, std::vector<std::string>> Segments =
      ReadOracleSegments(DSig::Test::PathToUtf8(Dir / "trace.jsonl"), Ks, Complete, OtherEvents);
  CHECK_NUM_EQ(OtherEvents, 0);
  // run.json stats (tools/parity/README.md), read through the shared-delete reader; a killed capture has
  // no stats.
  std::optional<JsonValue> Stats;
  try {
    const JsonValue Run = JsonParse(Detail::ReadFileBytes(DSig::Test::PathToUtf8(Dir / "run.json")));
    if (const JsonValue* S = Run.Find("stats"); S != nullptr && S->IsObject()) {
      if (const JsonValue* F = S->Find("find_one_match_diffing"); F != nullptr && F->IsObject()) {
        Stats = *F;
      }
    }
  } catch (const std::exception&) {
  }
  const std::string Main = DSig::Test::ExportPath(Ids->first);
  const std::string Diff = DSig::Test::ExportPath(Ids->second);
  for (const int K : Ks) {
    const std::string Label = Name + " find_matches_diffing:" + std::to_string(K);
    const StateSnapshot Before = ReadSnapshot(Files.at("before_find_matches_diffing_" + std::to_string(K)).Path);
    const StateSnapshot After = ReadSnapshot(Files.at("after_find_matches_diffing_" + std::to_string(K)).Path);
    CHECK(Before.RatiosCache.has_value());  // the captures cache at before:find_* (README "Long-pair ...")
    Replay R = RunCalleeReplay(Main, Diff, Before, K, PathJoin(Scratch, "corpus_trace.jsonl"));
    ++Counts.Replays;
    CHECK_TEXT_EQ(R.Error, "");
    if (R.After && ExpectSnapshot(Label + " state (S-L2)", After, *R.After)) {
      ++Counts.StatePassed;
    } else if (!R.After) {
      DSig::Test::Report(false, (Label + ": no native after snapshot").c_str(), __FILE__, __LINE__);
    }
    const auto Segment = Segments.find(K);
    CHECK(Segment != Segments.end() && Complete[K]);
    if (Segment != Segments.end() && ExpectEvents(Label + " trace events", R.Events, Segment->second)) {
      ++Counts.EventsPassed;
    }
    Counts.AddMatches += CountEvents(R.Events, "\"ev\":\"add_match\"");
    for (const auto& [Key, Count] : R.Calls) {
      Totals[Key.substr(0, Key.find(':'))] += Count;
    }
    if (Stats) {
      ++Counts.CallsCompared;
      const std::map<std::string, int64_t> Expected = CallsOfIteration(*Stats, K);
      DSig::Test::ReportText(R.Calls == Expected, (Label + " find_one_match_diffing calls").c_str(), CallsText(R.Calls),
                             CallsText(Expected), __FILE__, __LINE__);
      Counts.CallsPassed += R.Calls == Expected ? 1 : 0;
    }
    DSig::Test::Note(Label + ": " + CallsText(R.Calls) + ", " + std::to_string(R.Events.size()) + " events, " +
                     std::to_string(CountEvents(R.Events, "\"ev\":\"add_match\"")) + " add_match");
  }
  return Counts;
}

void TestCorpusReplays(const std::string& Scratch) {
  DSig::Test::Suite("corpus replays: before:find_matches_diffing:k -> stage -> after (S-L2, trace, call counts)");
  if (!DSig::Test::CorpusRoot()) {
    DSig::Test::Skip("corpus replays", "DSIG_CORPUS_ROOT is not set");
    return;
  }
  const fs::path Traces = DSig::Test::Utf8ToPath(DSig::Test::OracleDir()) / "traces";
  std::error_code Error;
  if (!fs::is_directory(Traces, Error)) {
    DSig::Test::Skip("corpus replays", "no oracle captures under " + DSig::Test::PathToUtf8(Traces));
    return;
  }
  std::vector<std::string> Names;
  for (const fs::directory_entry& Entry : fs::directory_iterator(Traces, Error)) {
    const std::string Name = DSig::Test::PathToUtf8(Entry.path().filename());
    if (Entry.is_directory(Error) && !Name.empty() && Name[0] != '_') {
      Names.push_back(Name);
    }
  }
  std::sort(Names.begin(), Names.end());
  int Captures = 0;
  for (const std::string& Name : Names) {
    const fs::path Dir = Traces / DSig::Test::Utf8ToPath(Name);
    std::string Pair = Name;
    const size_t Dot = Name.find('.');
    if (Dot != std::string::npos) {
      // A re-capture (".full", ".prefix2", ...): used only once finished. run.json is read through the
      // shared-delete reader, which never blocks the writer's replace.
      Pair = Name.substr(0, Dot);
      std::string Status;
      try {
        Status = JsonParse(Detail::ReadFileBytes(DSig::Test::PathToUtf8(Dir / "run.json"))).At("status").AsString();
      } catch (const std::exception&) {
      }
      if (Status != "complete" && Status != "stopped") {
        DSig::Test::Note(Name + ": skipped (capture status '" + Status + "')");
        continue;
      }
    }
    if (!fs::is_directory(Dir / "snapshots", Error) || !fs::is_regular_file(Dir / "trace.jsonl", Error)) {
      continue;
    }
    std::map<std::string, int64_t> Totals;
    const CorpusCounts C = ReplayCapture(Name, Pair, Dir, Scratch, Totals);
    if (C.Replays == 0) {
      continue;
    }
    ++Captures;
    std::string TotalText;
    for (const auto& [Field, Count] : Totals) {
      TotalText += (TotalText.empty() ? "" : ", ") + Field + " " + std::to_string(Count);
    }
    DSig::Test::Note(Name + ": " + std::to_string(C.Replays) + " replays; state " + std::to_string(C.StatePassed) + "/" +
                     std::to_string(C.Replays) + ", events " + std::to_string(C.EventsPassed) + "/" +
                     std::to_string(C.Replays) + ", call counts " + std::to_string(C.CallsPassed) + "/" +
                     std::to_string(C.CallsCompared) + " equal; find_one_match_diffing calls: " + TotalText + "; " +
                     std::to_string(C.AddMatches) + " add_match events");
    if (Name == "ls-old_vs_ls" && C.Replays == 3) {
      // 06 V3: 716 assembly and 426 pseudo-code find_one_match_diffing calls over the three outer
      // iterations of ls-old -> ls, every one with the inner iteration 1.
      CHECK_NUM_EQ(Totals["assembly"], 716);
      CHECK_NUM_EQ(Totals["pseudocode"], 426);
    }
  }
  if (Captures == 0) {
    DSig::Test::Skip("corpus replays", "no capture has a find_matches_diffing snapshot pair");
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
  const std::string Scratch = DSig::Test::ScratchDir("diff_callee");
  Run("documented walk", TestDocumentedWalk);
  Run("walk vectors", TestWalkVectors);
  Run("fixture scenarios", [&] { TestFixtureScenarios(Scratch); });
  Run("rules", [&] { TestRules(Scratch); });
  Run("raise and refuse", [&] { TestRaiseAndRefuse(Scratch); });
  Run("corpus", [&] { TestCorpusReplays(Scratch); });
  DSig::Test::RemoveScratchDir(Scratch);
  return DSig::Test::Finish();
}
