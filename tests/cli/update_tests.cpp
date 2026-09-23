// cli_update: `dsigmatcher update <labelled.sqlite> <new-binary> -o <new-labelled.sqlite>`.
//
// The ingest step needs IDA, so these tests hand RunUpdate a stand-in ingest (Cli::IngestRunner) that
// writes a prepared export where the real one would write it. Everything after the ingest (the
// in-process parity diff, the port, the files kept beside the output, the exit codes of each step) is
// the product code. The corpus part replays the cryptbase 1 -> 8875 step with the oracle's ingest of
// the 8875 DLL and compares the result with `diff` + `port --results`; it skips without the corpus.

#include <sqlite3.h>

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <map>
#include <string>
#include <vector>

#include "diff/CorpusPaths.h"
#include "diff/FixtureDb.h"
#include "diff/TestHarness.h"
#include "dsigmatcher/Provenance.h"
#include "dsigmatcher/cli/Commands.h"
#include "dsigmatcher/diff/Pipeline.h"

namespace {

using namespace DSig;
using DSig::Test::ScratchDir;

std::string Join(const std::string& Dir, const std::string& Name) {
  return (std::filesystem::path(Dir) / Name).string();
}

bool Exists(const std::string& Path) {
  std::error_code Error;
  return std::filesystem::exists(Path, Error);
}

std::string FileSha(const std::string& Path) { return FileSha256Hex(Path).value_or("<unreadable>"); }

std::string One(const std::string& Path, const std::string& Sql) {
  sqlite3* Db = nullptr;
  std::string Value = "<none>";
  const std::string Uri = ReadOnlyDatabaseUri(Path);
  if (sqlite3_open_v2(Uri.c_str(), &Db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, nullptr) == SQLITE_OK) {
    sqlite3_stmt* Statement = nullptr;
    if (sqlite3_prepare_v2(Db, Sql.c_str(), -1, &Statement, nullptr) == SQLITE_OK) {
      if (sqlite3_step(Statement) == SQLITE_ROW) {
        const unsigned char* Text = sqlite3_column_text(Statement, 0);
        Value = Text == nullptr ? "<NULL>" : reinterpret_cast<const char*>(Text);
      }
    } else {
      Value = std::string("<error: ") + sqlite3_errmsg(Db) + ">";
    }
    sqlite3_finalize(Statement);
  }
  sqlite3_close(Db);
  return Value;
}

// The label columns and the port log: what "the same labelled result" means.
const char* const kLabels =
    "select group_concat(address || '=' || quote(name) || '/' || quote(mangled_function), ',') "
    "from (select * from functions order by id)";
const char* const kLog =
    "select group_concat(results_rowid || ':' || type || ':' || action || ':' || quote(ref_name) || ':' || "
    "quote(name_before) || ':' || hops || ':' || confidence, ',') from (select * from dsig_port_log order by "
    "results_rowid)";
const char* const kOrigins =
    "select group_concat(address || ':' || name || ':' || origin_address || ':' || hops || ':' || cumulative_ratio "
    "|| ':' || heuristic, ',') from (select * from dsig_name_origin order by address)";

std::string FixturePath(const char* Name) { return DSig::Test::TestDataDir() + "/fixtures/common/" + Name; }

// A stand-in for `ingest`: records the call and builds the given fixture export at the output path.
struct FakeIngest {
  std::string FixtureSql;         // built at Args.Output; empty: copy CopyFrom instead
  std::string CopyFrom;           // an export (and its -wal) to copy to Args.Output
  int ExitCode = Cli::kExitOk;    // non-zero: fail without writing anything
  int Calls = 0;
  Cli::IngestArgs Seen;

  Cli::IngestRunner Runner() {
    return [this](const Cli::IngestArgs& Args) {
      ++Calls;
      Seen = Args;
      Cli::CommandOutcome Outcome;
      if (ExitCode != Cli::kExitOk) {
        Outcome.ExitCode = ExitCode;
        Outcome.Message = "ingest: IDA not found or not usable (stand-in)";
        return Outcome;
      }
      std::string Error;
      if (!FixtureSql.empty()) {
        Error = DSig::Test::BuildFixtureDb(FixtureSql, Args.Output);
      } else {
        std::error_code Copy;
        std::filesystem::copy_file(CopyFrom, Args.Output, std::filesystem::copy_options::overwrite_existing, Copy);
        if (!Copy && Exists(CopyFrom + "-wal")) {
          std::filesystem::copy_file(CopyFrom + "-wal", Args.Output + "-wal",
                                     std::filesystem::copy_options::overwrite_existing, Copy);
        }
        if (Copy) {
          Error = Copy.message();
        }
      }
      if (!Error.empty()) {
        Outcome.ExitCode = Cli::kExitIo;
        Outcome.Message = "ingest: stand-in failed: " + Error;
        return Outcome;
      }
      std::ofstream(Args.Output.substr(0, Args.Output.size() - 7) + ".export.json") << "{}";
      Outcome.Report = {"ingest: wrote " + Args.Output};
      return Outcome;
    };
  }
};

Cli::UpdateArgs Update(const std::string& Labelled, const std::string& Binary, const std::string& Output) {
  Cli::UpdateArgs Args;
  Args.Labelled = Labelled;
  Args.Binary = Binary;
  Args.Output = Output;
  Args.Port.Quiet = true;
  return Args;
}

std::string Member(const Diff::JsonValue& Object, const char* Key) {
  const Diff::JsonValue* Value = Object.IsObject() ? Object.Find(Key) : nullptr;
  if (Value == nullptr) {
    return "<absent>";
  }
  if (Value->IsNull()) {
    return "<null>";
  }
  return Value->IsString() ? Value->AsString() : Diff::JsonWrite(*Value);
}

void TestUpdateChain(const std::string& Dir) {
  DSig::Test::Suite("update: ingest -> in-process diff -> port, files kept beside the output");
  std::error_code Error;
  std::filesystem::create_directories(Dir, Error);
  const std::string Labelled = Join(Dir, "labelled.sqlite");
  CHECK(DSig::Test::BuildFixtureDb(FixturePath("main.sql"), Labelled).empty());
  const std::string Binary = Join(Dir, "new.dll");
  std::ofstream(Binary, std::ios::binary) << "MZ stand-in binary";
  const std::string LabelledSha = FileSha(Labelled), BinarySha = FileSha(Binary);

  FakeIngest Ingest;
  Ingest.FixtureSql = FixturePath("diff.sql");
  const std::string Output = Join(Dir, "new-labelled.sqlite");
  Cli::UpdateArgs Args = Update(Labelled, Binary, Output);
  Args.NoPdb = true;
  Args.Tools.TimeoutSeconds = 30;
  const Cli::CommandOutcome Outcome = Cli::RunUpdate(Args, Ingest.Runner());
  CHECK_NUM_EQ(Outcome.ExitCode, Cli::kExitOk);
  if (Outcome.ExitCode != Cli::kExitOk) {
    DSig::Test::Note(Outcome.Message);
    return;
  }
  CHECK_NUM_EQ(Ingest.Calls, 1);
  const std::string Export = Join(Dir, "new-labelled.ingest.sqlite");
  const std::string Results = Join(Dir, "new-labelled.diaphora");
  CHECK_TEXT_EQ(Ingest.Seen.Input, Binary);
  CHECK_TEXT_EQ(Ingest.Seen.Output, Export);
  CHECK(Ingest.Seen.NoPdb && Ingest.Seen.Pdb.empty() && Ingest.Seen.Tools.TimeoutSeconds == 30);
  CHECK_TEXT_EQ(Cli::UpdateExportPath(Output), Export);
  CHECK(Exists(Output) && Exists(Export) && Exists(Results));
  CHECK(Exists(Join(Dir, "new-labelled.ingest.export.json")));
  CHECK(!Exists(Output + ".dsig-tmp"));
  CHECK_TEXT_EQ(FileSha(Labelled), LabelledSha);
  CHECK_TEXT_EQ(FileSha(Binary), BinarySha);

  // The same result as the three commands run one after the other on the kept export.
  Diff::DiffArgs Diffing;
  Diffing.Db1 = Labelled;
  Diffing.Db2 = Export;
  Diffing.Out = Join(Dir, "separate.diaphora");
  Diffing.Quiet = true;
  CHECK(Diff::RunDiff(Diffing).Status == Diff::DiffStatus::Ok);
  Cli::PortFromResultsArgs Port;
  Port.Reference = Labelled;
  Port.Target = Export;
  Port.Output = Join(Dir, "separate.sqlite");
  Port.Results = Diffing.Out;
  CHECK_NUM_EQ(Cli::RunPortFromResults(Port).ExitCode, Cli::kExitOk);
  CHECK_TEXT_EQ(One(Output, kLabels), One(Port.Output, kLabels));
  CHECK_TEXT_EQ(One(Output, kLog), One(Port.Output, kLog));
  CHECK_TEXT_EQ(One(Results, "select count(*) from results"), One(Diffing.Out, "select count(*) from results"));
  CHECK_TEXT_EQ(One(Output, "select results_source || '|' || results_path from dsig_port_results"),
                "in-process diff|new-labelled.diaphora");
  CHECK_TEXT_EQ(One(Output, "select source_path from dsig_provenance"), "labelled.sqlite");

  // The report has the ingest lines, then the port's; the JSON outcome names every file.
  CHECK(!Outcome.Report.empty() && Outcome.Report[0] == "ingest: wrote " + Export);
  CHECK_TEXT_EQ(Member(Outcome.Data, "export"), Export);
  CHECK_TEXT_EQ(Member(Outcome.Data, "results"), Results);
  CHECK_TEXT_EQ(Member(Outcome.Data, "failed_step"), "<null>");
  const Diff::JsonValue* PortStep = Outcome.Data.Find("port");
  CHECK(PortStep != nullptr && Member(*PortStep, "exit_code") == "0");

  // The output is the reference of the next update.
  FakeIngest Next;
  Next.FixtureSql = FixturePath("diff.sql");
  const Cli::CommandOutcome Second =
      Cli::RunUpdate(Update(Output, Binary, Join(Dir, "next.sqlite")), Next.Runner());
  CHECK_NUM_EQ(Second.ExitCode, Cli::kExitOk);
  CHECK_TEXT_EQ(One(Join(Dir, "next.sqlite"), "select count(*) from dsig_provenance"), "2");
}

void TestUpdateStops(const std::string& Dir) {
  DSig::Test::Suite("update: every refusal comes before the ingest; a failing step stops with its exit code");
  std::error_code Error;
  std::filesystem::create_directories(Dir, Error);
  const std::string Labelled = Join(Dir, "labelled.sqlite");
  CHECK(DSig::Test::BuildFixtureDb(FixturePath("main.sql"), Labelled).empty());
  const std::string Binary = Join(Dir, "new.dll");
  std::ofstream(Binary, std::ios::binary) << "MZ stand-in binary";
  const std::string Output = Join(Dir, "out.sqlite");

  const auto Refused = [&](const std::string& Label, const Cli::UpdateArgs& Args, int Code, const std::string& Fragment) {
    FakeIngest Ingest;
    Ingest.FixtureSql = FixturePath("diff.sql");
    const bool OutputExisted = Exists(Args.Output);
    const Cli::CommandOutcome Outcome = Cli::RunUpdate(Args, Ingest.Runner());
    CHECK_NUM_EQ(Outcome.ExitCode, Code);
    CHECK_NUM_EQ(Ingest.Calls, 0);
    const bool Named = Outcome.Message.find(Fragment) != std::string::npos;
    CHECK(Named);
    if (Outcome.ExitCode != Code || !Named) {
      DSig::Test::Note(Label + ": exit " + std::to_string(Outcome.ExitCode) + ": " + Outcome.Message);
    }
    CHECK(OutputExisted || !Exists(Args.Output));
  };
  const std::string Nowhere = Join(Dir, "nowhere.sqlite");
  Refused("labelled missing", Update(Nowhere, Binary, Output), Cli::kExitIo, Nowhere);
  const std::string Text = Join(Dir, "junk.txt");
  std::ofstream(Text) << "not a database, just text long enough to fill a header";
  Refused("labelled not SQLite", Update(Text, Binary, Output), Cli::kExitIo, "not an SQLite database");
  const std::string ResultsFile = Join(Dir, "old.diaphora");
  {
    sqlite3* Db = nullptr;
    CHECK(sqlite3_open_v2(ResultsFile.c_str(), &Db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) == SQLITE_OK);
    CHECK(sqlite3_exec(Db, "create table results (type text); create table config (main_db text);", nullptr, nullptr,
                       nullptr) == SQLITE_OK);
    sqlite3_close(Db);
  }
  Refused("labelled is a results file", Update(ResultsFile, Binary, Output), Cli::kExitUnsupported,
          "results file, not a Diaphora export");
  Refused("binary missing", Update(Labelled, Join(Dir, "absent.dll"), Output), Cli::kExitIo, "absent.dll");
  const std::string LabelledSha = FileSha(Labelled);
  Refused("output is the labelled database", Update(Labelled, Binary, Labelled), Cli::kExitUsage,
          "refusing to overwrite an input");
  CHECK_TEXT_EQ(FileSha(Labelled), LabelledSha);
  Refused("output is the binary", Update(Labelled, Binary, Binary), Cli::kExitUsage, "refusing to overwrite an input");
  // labelled "x.ingest.sqlite" with -o "x.sqlite": the ingest would write over the labelled database
  const std::string IngestNamed = Join(Dir, "x.ingest.sqlite");
  CHECK(DSig::Test::BuildFixtureDb(FixturePath("main.sql"), IngestNamed).empty());
  const std::string IngestNamedSha = FileSha(IngestNamed);
  Refused("the intermediate export is the labelled database", Update(IngestNamed, Binary, Join(Dir, "x.sqlite")),
          Cli::kExitUsage, "the intermediate export '");
  CHECK_TEXT_EQ(FileSha(IngestNamed), IngestNamedSha);
  Refused("the results file would be the output", Update(Labelled, Binary, Join(Dir, "r.diaphora")), Cli::kExitUsage,
          "choose another -o");
  Refused("output directory missing", Update(Labelled, Binary, Join(Join(Dir, "no_such_dir"), "o.sqlite")),
          Cli::kExitIo, "output directory '");
  Cli::UpdateArgs WithResults = Update(Labelled, Binary, Output);
  WithResults.Port.Results = ResultsFile;
  Refused("--results", WithResults, Cli::kExitUsage, "--results does not apply");
  Cli::UpdateArgs StrippedAlone = Update(Labelled, Binary, Output);
  StrippedAlone.Port.OverwriteStripped = true;
  Refused("--overwrite-stripped alone", StrippedAlone, Cli::kExitUsage, "--overwrite-stripped needs");
  Cli::UpdateArgs BadRatio = Update(Labelled, Binary, Output);
  BadRatio.Port.MinRatio = 2.0;
  Refused("--min-ratio 2", BadRatio, Cli::kExitUsage, "min-ratio");
  Cli::UpdateArgs BothPdb = Update(Labelled, Binary, Output);
  BothPdb.Pdb = Join(Dir, "x.pdb");
  BothPdb.NoPdb = true;
  Refused("--pdb and --no-pdb", BothPdb, Cli::kExitUsage, "exclusive");

  // The ingest fails: its exit code, nothing else runs.
  {
    FakeIngest Ingest;
    Ingest.ExitCode = Cli::kExitUnsupported;
    const Cli::CommandOutcome Outcome = Cli::RunUpdate(Update(Labelled, Binary, Output), Ingest.Runner());
    CHECK_NUM_EQ(Outcome.ExitCode, Cli::kExitUnsupported);
    CHECK_NUM_EQ(Ingest.Calls, 1);
    CHECK(Outcome.Message.rfind("ingest: IDA not found", 0) == 0);
    CHECK_TEXT_EQ(Member(Outcome.Data, "failed_step"), "ingest");
    CHECK(!Exists(Output) && !Exists(Join(Dir, "out.diaphora")));
  }
  // The diff fails (an export without Diaphora's side tables): exit 4 from the diff step.
  {
    const std::string Reduced = Join(Dir, "reduced.sqlite");
    sqlite3* Db = nullptr;
    CHECK(sqlite3_open_v2(Reduced.c_str(), &Db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) == SQLITE_OK);
    CHECK(sqlite3_exec(Db,
                       "create table functions (id integer primary key, name text, address text, "
                       "mangled_function text); insert into functions values (1, 'sub_1000', '4096', 'sub_1000');"
                       "create table version (value text); insert into version values ('3.4');"
                       "create table program (id integer primary key, callgraph_primes text, "
                       "callgraph_all_primes text, processor text, md5sum text);"
                       "insert into program values (1, '2', '{\"2\": 1}', 'pc64', 'x');",
                       nullptr, nullptr, nullptr) == SQLITE_OK);
    sqlite3_close(Db);
    FakeIngest Ingest;
    Ingest.CopyFrom = Reduced;
    const Cli::CommandOutcome Outcome = Cli::RunUpdate(Update(Labelled, Binary, Output), Ingest.Runner());
    CHECK_NUM_EQ(Outcome.ExitCode, Cli::kExitUnsupported);
    CHECK(Outcome.Message.rfind("diff: ", 0) == 0);
    CHECK_TEXT_EQ(Member(Outcome.Data, "failed_step"), "diff");
    if (Outcome.ExitCode != Cli::kExitUnsupported) {
      DSig::Test::Note(Outcome.Message);
    }
    CHECK(!Exists(Output));
    CHECK(Exists(Cli::UpdateExportPath(Output)));  // the ingest's export is kept for inspection
  }
}

// cryptbase 1 (PDB) -> 8875: the oracle's no-PDB ingest of the 8875 DLL stands in for the ingest.
void TestUpdateCorpus() {
  const char* Name = "corpus: update of cryptbase-1-pdb with the 8875 export equals diff + port --results";
  if (!DSig::Test::ExportAvailable("cryptbase-1-pdb") || !DSig::Test::ExportAvailable("cryptbase-8875-nopdb")) {
    DSig::Test::Skip(Name, "corpus exports absent");
    return;
  }
  DSig::Test::Suite(Name);
  const std::string Dir = ScratchDir("cli_update_corpus");
  const std::string Labelled = Join(Dir, "cryptbase-1-pdb.sqlite");
  std::error_code Error;
  const std::string Source = DSig::Test::ExportPath("cryptbase-1-pdb");
  std::filesystem::copy_file(Source, Labelled, Error);
  if (!Error && Exists(Source + "-wal")) {
    std::filesystem::copy_file(Source + "-wal", Labelled + "-wal", Error);
  }
  CHECK(!Error);
  const std::string Binary = Join(Dir, "cryptbase.dll");
  std::ofstream(Binary, std::ios::binary) << "stand-in: the export below is the oracle's ingest of this build";
  FakeIngest Ingest;
  Ingest.CopyFrom = DSig::Test::ExportPath("cryptbase-8875-nopdb");
  const std::string Output = Join(Dir, "cryptbase-8875-labelled.sqlite");
  const Cli::CommandOutcome Outcome = Cli::RunUpdate(Update(Labelled, Binary, Output), Ingest.Runner());
  CHECK_NUM_EQ(Outcome.ExitCode, Cli::kExitOk);
  if (Outcome.ExitCode != Cli::kExitOk) {
    DSig::Test::Note(Outcome.Message);
    DSig::Test::RemoveScratchDir(Dir);
    return;
  }
  const std::string Export = Cli::UpdateExportPath(Output);
  Diff::DiffArgs Diffing;
  Diffing.Db1 = Labelled;
  Diffing.Db2 = Export;
  Diffing.Out = Join(Dir, "separate.diaphora");
  Diffing.Quiet = true;
  CHECK(Diff::RunDiff(Diffing).Status == Diff::DiffStatus::Ok);
  Cli::PortFromResultsArgs Port;
  Port.Reference = Labelled;
  Port.Target = Export;
  Port.Output = Join(Dir, "separate.sqlite");
  Port.Results = Diffing.Out;
  CHECK_NUM_EQ(Cli::RunPortFromResults(Port).ExitCode, Cli::kExitOk);
  CHECK_TEXT_EQ(One(Output, kLabels), One(Port.Output, kLabels));
  CHECK_TEXT_EQ(One(Output, kLog), One(Port.Output, kLog));
  CHECK_TEXT_EQ(One(Output, kOrigins), One(Port.Output, kOrigins));
  // The DllEntryPoint placeholder of the no-PDB build now takes the reference's name.
  CHECK_TEXT_EQ(One(Output, "select count(*) from functions where name = 'DllEntryPoint'"), "0");
  DSig::Test::Note("names applied: " + One(Output, "select names_applied from dsig_provenance where hop = 1") +
                   ", confirmed: " + One(Output, "select names_confirmed from dsig_port_results where hop = 1"));
  DSig::Test::RemoveScratchDir(Dir);
}

}

int main() {
  const std::string Dir = ScratchDir("cli_update");
  TestUpdateChain(Join(Dir, "chain"));
  TestUpdateStops(Join(Dir, "stops"));
  TestUpdateCorpus();
  DSig::Test::RemoveScratchDir(Dir);
  return DSig::Test::Finish();
}
