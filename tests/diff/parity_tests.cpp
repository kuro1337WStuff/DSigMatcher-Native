// diff_parity: full native diffs compared with Diaphora's own output (levels of docs/parity/README.md).
//
// Gated by DSIG_PARITY:
//   DSIG_PARITY unset  only the harness self-check below runs;
//   DSIG_PARITY=1      the committed `common` fixture pair and every finished short oracle pair;
//   DSIG_PARITY=long   also the long pairs (userenv / sechost labelled-to-unlabelled) once their
//                      oracle run1 is finished and valid.
// Each pair runs `RunDiff` in process and is compared at L2 (rows, `line` and stored order) when the
// runtime SQLite is the oracle's 3.51.1, at L1 otherwise. The first 20 differences are printed. An
// oracle run that is not valid (exit code, output, log lines, input sha256) is reported ORACLE_INVALID
// and not compared; tools/parity/run_parity.py applies the full rule set.

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "../../src/diff/FileIo.h"
#include "diff/CorpusPaths.h"
#include "diff/FixtureDb.h"
#include "diff/ResultsCompare.h"
#include "diff/TestHarness.h"
#include "diff/fixtures/common/FixtureExpect.h"
#include "dsigmatcher/Sha256.h"
#include "dsigmatcher/diff/Json.h"
#include "dsigmatcher/diff/Pipeline.h"

namespace {

using namespace DSig;
using namespace DSig::Diff;
using DSig::Test::PathToUtf8;
using DSig::Test::Utf8ToPath;

bool FileExists(const std::string& Path) {
  std::error_code Error;
  return std::filesystem::is_regular_file(Utf8ToPath(Path), Error);
}

std::string Join(const std::string& Dir, const std::string& Name) {
  return PathToUtf8(Utf8ToPath(Dir) / Utf8ToPath(Name));
}

// Runs the native diff and compares its output with `Expected` at L2 (oracle SQLite) or L1.
bool DiffAndCompare(const std::string& Label, const std::string& Db1, const std::string& Db2,
                    const Test::ResultsFile& Expected, const std::string& Out, bool ComparePaths) {
  DiffArgs Args;
  Args.Db1 = Db1;
  Args.Db2 = Db2;
  Args.Out = Out;
  Args.PairLabel = Label;
  Args.Quiet = true;
  Args.AllowSqliteMismatch = true;
  const DiffOutcome Outcome = RunDiff(Args);
  CHECK_NUM_EQ(static_cast<int>(Outcome.Status), static_cast<int>(DiffStatus::Ok));
  if (Outcome.Status != DiffStatus::Ok) {
    Test::Note(Label + ": native diff failed: " + Outcome.Message);
    return false;
  }
  const Test::ResultsFile Native = Test::ReadResultsFile(Out);
  const bool Exact = Test::OracleSqlite();
  const Test::CompareReport Report = Test::CompareResults(Expected, Native, 20, ComparePaths);
  const bool Ok = Report.DdlEqual && (Exact ? Report.L2Equal : Report.L1Equal);
  Test::Note(Label + ": mode " + std::string(1, Outcome.Mode) + ", native rows " +
             std::to_string(Native.Results.size()) + "/" + std::to_string(Native.Unmatched.size()) + ", oracle rows " +
             std::to_string(Expected.Results.size()) + "/" + std::to_string(Expected.Unmatched.size()) + ": " +
             (Exact ? "L2 " : "L1 ") +
             (Ok ? "EQUAL" : "DIFFERENT"));
  for (const std::string& Line : Report.Differences) {
    Test::Note("  " + Line);
  }
  CHECK(Report.DdlEqual);
  if (Exact) {
    CHECK(Report.L2Equal);
  } else {
    CHECK(Report.L1Equal);
  }
  return Ok;
}

// ---------------------------------------------------------------------------------------------
// Always: the comparison the gated tests rely on classifies a planted difference.

void TestHarnessSelfCheck() {
  Test::Suite("parity harness self-check: L1/L2 verdicts on the committed fixture's expected rows");
  const std::string Fixture = Join(Join(Test::TestDataDir(), "fixtures"), "common");
  if (Test::TestDataDir().empty() || !FileExists(Join(Fixture, "expected_results.tsv"))) {
    Test::Skip("harness self-check", "DSIG_TEST_DATA_DIR/fixtures/common not found");
    return;
  }
  const Test::ResultsFile Expected = Test::ReadExpectedFixture(Fixture);
  CHECK(Expected.Error.empty());
  CHECK(!Expected.Results.empty());
  const Test::CompareReport Same = Test::CompareResults(Expected, Expected);
  CHECK(Same.DdlEqual && Same.L1Equal && Same.L2Equal);
  if (Expected.Results.size() >= 2) {
    Test::ResultsFile Swapped = Expected;  // same multiset, other stored order: L1 yes, L2 no
    std::swap(Swapped.Results[0], Swapped.Results[1]);
    const Test::CompareReport Order = Test::CompareResults(Expected, Swapped);
    CHECK(Order.L1Equal && !Order.L2Equal);
    Test::ResultsFile Line = Expected;  // another line number only: L1 yes, L2 no
    Line.Results[0].Line = "99999";
    const Test::CompareReport Lines = Test::CompareResults(Expected, Line);
    CHECK(Lines.L1Equal && !Lines.L2Equal);
    Test::ResultsFile Ratio = Expected;  // another ratio text: neither
    Ratio.Results[0].Ratio = "0.1234567";
    const Test::CompareReport Ratios = Test::CompareResults(Expected, Ratio);
    CHECK(!Ratios.L1Equal && !Ratios.L2Equal);
    Test::ResultsFile Dropped = Expected;
    Dropped.Results.pop_back();
    CHECK(!Test::CompareResults(Expected, Dropped).L1Equal);
  }
}

// ---------------------------------------------------------------------------------------------
// DSIG_PARITY: the committed fixture pair

void TestFixtureParity(const std::string& Dir) {
  Test::Suite("parity: fixture common (tools/parity/make_fixture.py, real Diaphora 3.4.2-4-g621ec26)");
  const std::string Fixture = Join(Join(Test::TestDataDir(), "fixtures"), "common");
  if (Test::TestDataDir().empty() || !FileExists(Join(Fixture, "main.sql"))) {
    Test::Skip("parity fixture common", "fixture not found");
    return;
  }
  const std::string Main = Join(Dir, "common-main.sqlite");
  const std::string Diff = Join(Dir, "common-diff.sqlite");
  CHECK_TEXT_EQ(Test::BuildFixtureDb(Join(Fixture, "main.sql"), Main), "");
  CHECK_TEXT_EQ(Test::BuildFixtureDb(Join(Fixture, "diff.sql"), Diff), "");
  DiffAndCompare("fixture:common", Main, Diff, Test::ReadExpectedFixture(Fixture), Join(Dir, "common.diaphora"),
                 false);
}

// ---------------------------------------------------------------------------------------------
// DSIG_PARITY: the oracle pairs

struct OraclePair {
  std::string Pair, Ref, Target;
  bool Long = false;
};

std::optional<JsonValue> ReadJson(const std::string& Path) {
  try {
    return JsonParse(Detail::ReadFileBytes(Path));
  } catch (const std::exception&) {
    return std::nullopt;
  }
}

// The subset of the oracle validity rules (tools/parity/README.md, "Oracle status") that needs no
// Python: run.json exit code 0, the output exists, the log has `Diffing results saved in file` and no
// `Timeout with heuristic`, and both exports still have the manifest's sha256. Returns "" when valid,
// else the reason.
std::string OracleInvalid(const JsonValue& Manifest, const OraclePair& P) {
  const std::string RunDir = Join(Join(Join(Test::OracleDir(), "diffs"), P.Pair), "run1");
  const auto Run = ReadJson(Join(RunDir, "run.json"));
  if (!Run) {
    return "PENDING (no run1/run.json)";
  }
  const JsonValue* Exit = Run->Find("exit_code");
  if (Exit == nullptr || !Exit->IsNumber() || Exit->AsInt64() != 0) {
    return "exit code not 0";
  }
  if (!FileExists(Test::OracleResultsPath(P.Pair, 1))) {
    return "no output file";
  }
  std::string Log;
  try {
    Log = Detail::ReadFileBytes(Join(RunDir, "diaphora.log"));
  } catch (const std::exception&) {
    return "no diaphora.log";
  }
  if (Log.find("Diffing results saved in file") == std::string::npos) {
    return "log lacks 'Diffing results saved in file'";
  }
  if (Log.find("Timeout with heuristic") != std::string::npos) {
    return "log has 'Timeout with heuristic'";
  }
  for (const std::string& Id : {P.Ref, P.Target}) {
    const JsonValue* Exports = Manifest.Find("exports");
    const JsonValue* Entry = Exports != nullptr ? Exports->Find(Id) : nullptr;
    const JsonValue* Sha = Entry != nullptr ? Entry->Find("sqlite_sha256") : nullptr;
    bool Ok = false;
    const std::string Actual = Sha256::FileHex(Test::ExportPath(Id), Ok);
    if (Sha == nullptr || !Sha->IsString() || !Ok || Actual != Sha->AsString()) {
      return "export " + Id + " sha256 differs from the manifest";
    }
  }
  return "";
}

void TestOracleParity(const std::string& Dir, bool IncludeLong) {
  Test::Suite(IncludeLong ? "parity: oracle pairs (short and long)" : "parity: oracle pairs (short)");
  if (!Test::CorpusRoot()) {
    Test::Skip("parity oracle pairs", "DSIG_CORPUS_ROOT not set");
    return;
  }
  const auto Manifest = ReadJson(Join(Test::OracleDir(), "manifest.json"));
  if (!Manifest || Manifest->Find("diffs") == nullptr) {
    Test::Skip("parity oracle pairs", "no oracle manifest.json");
    return;
  }
  // The finished short pairs and the two long pairs (ORACLE.md).
  const OraclePair Pairs[] = {
      {"ls-old_vs_ls", "ls-old", "ls", false},
      {"ls_vs_ls-old", "ls", "ls-old", false},
      {"userenv-9168-pdb_vs_9278-pdb", "userenv-9168-pdb", "userenv-9278-pdb", false},
      {"win32u-9168-useri64_vs_9444-nopdb", "win32u-9168-useri64", "win32u-9444-nopdb", false},
      {"cryptbase-1-pdb_vs_8875-nopdb", "cryptbase-1-pdb", "cryptbase-8875-nopdb", false},
      {"cryptbase-8875-pdb_vs_9444-nopdb", "cryptbase-8875-pdb", "cryptbase-9444-nopdb", false},
      {"userenv-9168-pdb_vs_9278-nopdb", "userenv-9168-pdb", "userenv-9278-nopdb", true},
      {"sechost-9168-pdb_vs_9444-nopdb", "sechost-9168-pdb", "sechost-9444-nopdb", true},
  };
  size_t Compared = 0;
  size_t Equal = 0;
  for (const OraclePair& P : Pairs) {
    if (P.Long && !IncludeLong) {
      Test::Note(P.Pair + ": long pair, needs DSIG_PARITY=long");
      continue;
    }
    if (!Test::ExportAvailable(P.Ref) || !Test::ExportAvailable(P.Target)) {
      Test::Note(P.Pair + ": exports absent, skipped");
      continue;
    }
    const std::string Invalid = OracleInvalid(*Manifest, P);
    if (!Invalid.empty()) {
      Test::Note(P.Pair + ": ORACLE_INVALID or PENDING: " + Invalid + " (not compared)");
      continue;
    }
    // The oracle file is copied, never opened in place.
    const std::string OracleCopy = Join(Dir, P.Pair + ".oracle.diaphora");
    std::error_code Error;
    std::filesystem::copy_file(Utf8ToPath(Test::OracleResultsPath(P.Pair, 1)), Utf8ToPath(OracleCopy),
                               std::filesystem::copy_options::overwrite_existing, Error);
    CHECK(!Error);
    const Test::ResultsFile Oracle = Test::ReadResultsFile(OracleCopy);
    CHECK(Oracle.Error.empty());
    ++Compared;
    // The oracle was given absolute export paths; the same strings make config.main_db/diff_db equal.
    const bool SamePaths = Oracle.Config.size() == 1 && Oracle.Config[0][0] == Test::ExportPath(P.Ref);
    Equal += DiffAndCompare(P.Pair, Test::ExportPath(P.Ref), Test::ExportPath(P.Target), Oracle,
                            Join(Dir, P.Pair + ".native.diaphora"), SamePaths)
                 ? 1u
                 : 0u;
  }
  Test::Note(std::to_string(Equal) + " of " + std::to_string(Compared) + " oracle pairs equal");
}

}  // namespace

int main() {
  TestHarnessSelfCheck();
  const std::optional<std::string> Gate = Test::GetEnv("DSIG_PARITY");
  if (!Gate || (*Gate != "1" && *Gate != "long")) {
    Test::Skip("full-run parity", "set DSIG_PARITY=1 (fast pairs) or DSIG_PARITY=long to run it");
    return Test::Finish();
  }
  const std::string Dir = Test::ScratchDir("diff_parity");
  try {
    TestFixtureParity(Dir);
    TestOracleParity(Dir, *Gate == "long");
  } catch (const std::exception& Error) {
    Test::Report(false, "unexpected exception", __FILE__, __LINE__);
    Test::Note(std::string("exception: ") + Error.what());
  }
  Test::RemoveScratchDir(Dir);
  return Test::Finish();
}
