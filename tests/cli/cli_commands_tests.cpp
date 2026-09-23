// cli_commands: the command-line contract of the built executable (DSIG_CLI_PATH): the exit-code table
// for every command, per-command help, argument parsing (repeated options, numbers, harness
// sub-options), --json, and the internal-error guard.
//
// Audit findings covered here: F07 (exit codes of info and every other path), F17 (UNC paths through
// the CLI), F35 / F36 (strict numbers), F38 (internal errors: exit 70), F39 (repeated options), F40
// (help), F41 (--json), F59 (info shows the port settings), F60 (harness sub-options need their parent).

#include <sqlite3.h>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <new>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "diff/CorpusPaths.h"
#include "diff/FixtureDb.h"
#include "diff/TestHarness.h"
#include "dsigmatcher/Provenance.h"
#include "dsigmatcher/cli/Commands.h"
#include "dsigmatcher/diff/Json.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace {

using namespace DSig;
using DSig::Test::PathToUtf8;
using DSig::Test::Utf8ToPath;

std::string Join(const std::string& Dir, const std::string& Name) { return PathToUtf8(Utf8ToPath(Dir) / Utf8ToPath(Name)); }

bool Exists(const std::string& Path) {
  std::error_code Error;
  return std::filesystem::exists(Utf8ToPath(Path), Error);
}

std::string ReadFile(const std::string& Path) {
  std::ifstream In(Utf8ToPath(Path), std::ios::binary);
  std::ostringstream Text;
  Text << In.rdbuf();
  return Text.str();
}

struct CliRun {
  int Code = -1;
  std::string Out;
  std::string Err;
};

std::string gScratch;

#ifdef _WIN32
std::wstring Widen(const std::string& Utf8) {
  if (Utf8.empty()) {
    return std::wstring();
  }
  const int Size = MultiByteToWideChar(CP_UTF8, 0, Utf8.data(), static_cast<int>(Utf8.size()), nullptr, 0);
  std::wstring Out(static_cast<size_t>(Size), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, Utf8.data(), static_cast<int>(Utf8.size()), Out.data(), Size);
  return Out;
}

// One argument quoted for the CRT / CommandLineToArgvW splitting rules.
std::wstring Quote(const std::wstring& Argument) {
  if (!Argument.empty() && Argument.find_first_of(L" \t\n\v\"") == std::wstring::npos) {
    return Argument;
  }
  std::wstring Out = L"\"";
  for (size_t Index = 0;; ++Index) {
    size_t Backslashes = 0;
    while (Index < Argument.size() && Argument[Index] == L'\\') {
      ++Index;
      ++Backslashes;
    }
    if (Index == Argument.size()) {
      Out.append(Backslashes * 2, L'\\');
      break;
    }
    Out.append(Argument[Index] == L'"' ? Backslashes * 2 + 1 : Backslashes, L'\\');
    Out.push_back(Argument[Index]);
  }
  Out.push_back(L'"');
  return Out;
}

// Runs the CLI with UTF-8 arguments as a wide command line; stdout and stderr go to separate files.
CliRun Run(const std::vector<std::string>& Arguments) {
  CliRun Result;
  std::wstring Exe = Widen(DSIG_CLI_PATH);
  for (wchar_t& Ch : Exe) {
    if (Ch == L'/') {
      Ch = L'\\';
    }
  }
  std::wstring Line = Quote(Exe);
  for (const std::string& Argument : Arguments) {
    Line += L' ';
    Line += Quote(Widen(Argument));
  }
  const std::string OutPath = Join(gScratch, "stdout.txt");
  const std::string ErrPath = Join(gScratch, "stderr.txt");
  SECURITY_ATTRIBUTES Inherit{};
  Inherit.nLength = sizeof(Inherit);
  Inherit.bInheritHandle = TRUE;
  const HANDLE Out = CreateFileW(Widen(OutPath).c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &Inherit,
                                 CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  const HANDLE Err = CreateFileW(Widen(ErrPath).c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &Inherit,
                                 CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (Out == INVALID_HANDLE_VALUE || Err == INVALID_HANDLE_VALUE) {
    return Result;
  }
  STARTUPINFOW Startup{};
  Startup.cb = sizeof(Startup);
  Startup.dwFlags = STARTF_USESTDHANDLES;
  Startup.hStdOutput = Out;
  Startup.hStdError = Err;
  PROCESS_INFORMATION Process{};
  std::vector<wchar_t> Mutable(Line.begin(), Line.end());
  Mutable.push_back(L'\0');
  if (CreateProcessW(Exe.c_str(), Mutable.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &Startup,
                     &Process)) {
    WaitForSingleObject(Process.hProcess, 300000);
    DWORD Code = 0;
    GetExitCodeProcess(Process.hProcess, &Code);
    Result.Code = static_cast<int>(Code);
    CloseHandle(Process.hThread);
    CloseHandle(Process.hProcess);
  }
  CloseHandle(Out);
  CloseHandle(Err);
  Result.Out = ReadFile(OutPath);
  Result.Err = ReadFile(ErrPath);
  return Result;
}
#else
CliRun Run(const std::vector<std::string>& Arguments) {
  CliRun Result;
  const auto Quoted = [](const std::string& Text) {
    std::string Out = "'";
    for (const char Ch : Text) {
      Out += Ch == '\'' ? std::string("'\\''") : std::string(1, Ch);
    }
    return Out + "'";
  };
  const std::string OutPath = Join(gScratch, "stdout.txt");
  const std::string ErrPath = Join(gScratch, "stderr.txt");
  std::string Command = Quoted(DSIG_CLI_PATH);
  for (const std::string& Argument : Arguments) {
    Command += " " + Quoted(Argument);
  }
  Command += " >" + Quoted(OutPath) + " 2>" + Quoted(ErrPath);
  const int Status = std::system(Command.c_str());
  Result.Code = Status == -1 ? -1 : (Status >> 8) & 0xff;
  Result.Out = ReadFile(OutPath);
  Result.Err = ReadFile(ErrPath);
  return Result;
}
#endif

bool Contains(const std::string& Text, const std::string& Part) { return Text.find(Part) != std::string::npos; }

// Checks the exit code and, when given, a fragment of stderr; notes the run on a mismatch.
void Expect(const std::string& Label, const CliRun& R, int Code, const std::string& ErrPart = "") {
  CHECK_NUM_EQ(R.Code, Code);
  const bool ErrOk = ErrPart.empty() || Contains(R.Err, ErrPart);
  CHECK(ErrOk);
  if (R.Code != Code || !ErrOk) {
    DSig::Test::Note(Label + ": exit " + std::to_string(R.Code) + "\n    stdout: " + R.Out + "\n    stderr: " + R.Err);
  }
}

std::optional<Diff::JsonValue> ParseJson(const std::string& Text) {
  try {
    return Diff::JsonParse(Text);
  } catch (const std::exception&) {
    return std::nullopt;
  }
}

std::string Field(const Diff::JsonValue& Object, const char* Key) {
  const Diff::JsonValue* Value = Object.IsObject() ? Object.Find(Key) : nullptr;
  if (Value == nullptr) {
    return "<absent>";
  }
  return Value->IsString() ? Value->AsString() : Diff::JsonWrite(*Value);
}

// ---------------------------------------------------------------------------------------------
// fixtures: the committed common pair (a full Diaphora schema, so the in-process diff runs)

struct Fixture {
  std::string Dir, Main, Diff, Results, Text, ResultsFile;
  bool Ok = false;
};

Fixture MakeFixture(const std::string& Dir) {
  Fixture F;
  F.Dir = Dir;
  std::error_code Error;
  std::filesystem::create_directories(Utf8ToPath(Dir), Error);
  F.Main = Join(Dir, "main.sqlite");
  F.Diff = Join(Dir, "diff.sqlite");
  const std::string Base = DSig::Test::TestDataDir() + "/fixtures/common/";
  F.Ok = DSig::Test::BuildFixtureDb(Base + "main.sql", F.Main).empty() &&
         DSig::Test::BuildFixtureDb(Base + "diff.sql", F.Diff).empty();
  F.Text = Join(Dir, "junk.txt");
  std::ofstream(Utf8ToPath(F.Text)) << "this is a text file, not a database; long enough to hold a header";
  // A results file: `diff` of the pair.
  F.ResultsFile = Join(Dir, "pair.diaphora");
  const CliRun Diffed = Run({"diff", F.Main, F.Diff, "-o", F.ResultsFile, "--quiet"});
  F.Ok = F.Ok && Diffed.Code == 0 && Exists(F.ResultsFile);
  return F;
}

// ---------------------------------------------------------------------------------------------

void TestHelp() {
  DSig::Test::Suite("help: global, per command, --help-all; --help wins in any position (F40)");
  const CliRun Global = Run({"--help"});
  Expect("--help", Global, 0);
  CHECK(Contains(Global.Out, "exit codes (every command)"));
  CHECK(Contains(Global.Out, "70  internal error"));
  CHECK(Contains(Global.Out, "DIAPHORA_* variables are deliberately ignored"));
  CHECK(Contains(Global.Out, "dsigmatcher update <labelled.sqlite> <new-binary>"));
  CHECK(!Contains(Global.Out, "--snapshot-dir") && !Contains(Global.Out, "00-plan"));

  const CliRun Port = Run({"port", "--help"});
  Expect("port --help", Port, 0);
  CHECK(Contains(Port.Out, "usage: dsigmatcher port"));
  CHECK(Contains(Port.Out, "--overwrite-stripped") && Contains(Port.Out, "--no-keep-results") &&
        Contains(Port.Out, "--store-full-paths"));
  CHECK(Contains(Port.Out, "--overwrite)"));  // the alias is documented
  CHECK(!Contains(Port.Out, "--trace") && !Contains(Port.Out, "usage: dsigmatcher diff"));

  const CliRun Diff = Run({"diff", "--help"});
  Expect("diff --help", Diff, 0);
  CHECK(Contains(Diff.Out, "usage: dsigmatcher diff") && !Contains(Diff.Out, "--snapshot-dir"));
  const CliRun DiffAll = Run({"diff", "--help-all"});
  Expect("diff --help-all", DiffAll, 0);
  CHECK(Contains(DiffAll.Out, "--snapshot-dir") && Contains(DiffAll.Out, "--related-cu-source native|sql   how"));

  const CliRun Update = Run({"update", "--help"});
  Expect("update --help", Update, 0);
  CHECK(Contains(Update.Out, ".ingest.sqlite") && Contains(Update.Out, "default: no PDB"));
  const CliRun Ingest = Run({"ingest", "--help"});
  CHECK(Contains(Ingest.Out, "No PDB is loaded unless --pdb is given") && Contains(Ingest.Out, "(replaced)"));
  const CliRun Extract = Run({"extract", "--help"});
  CHECK(Contains(Extract.Out, "share/dsigmatcher/tools/export"));
  const CliRun HelpPort = Run({"help", "port"});
  CHECK_TEXT_EQ(HelpPort.Out, Port.Out);

  // --help wins over an argument error, before or after it
  Expect("diff --help --bogus", Run({"diff", "--help", "--bogus"}), 0);
  Expect("diff --bogus --help", Run({"diff", "--bogus", "--help"}), 0);
  Expect("port -o --help", Run({"port", "a", "--help"}), 0);

  // usage errors: one error line and a hint on stderr, nothing on stdout
  const CliRun Bogus = Run({"bogus"});
  Expect("bogus", Bogus, 2, "error: unknown command 'bogus'");
  CHECK(Contains(Bogus.Err, "run 'dsigmatcher --help' for usage"));
  CHECK(Bogus.Out.empty());
  const CliRun NoPath = Run({"info"});
  Expect("info", NoPath, 2, "error: 'info' expects 1 path(s), got 0");
  CHECK(Contains(NoPath.Err, "run 'dsigmatcher info --help' for usage"));
  CHECK(NoPath.Out.empty());
  CHECK(std::count(NoPath.Err.begin(), NoPath.Err.end(), '\n') == 2);
  const CliRun None = Run({});
  Expect("(no command)", None, 2);
  CHECK(None.Out.empty() && Contains(None.Err, "usage:"));
  Expect("port without -o", Run({"port", "a", "b"}), 2, "requires -o <output>");

  // removed with the legacy engine
  Expect("diff --engine legacy", Run({"diff", "a", "b", "--engine", "legacy"}), 2, "unknown option '--engine'");
  Expect("port --threads", Run({"port", "a", "b", "-o", "c", "--threads", "4"}), 2, "unknown option '--threads'");
  Expect("extract --pdb", Run({"extract", "a.i64", "-o", "c", "--pdb", "x"}), 2, "unknown option '--pdb'");
}

void TestRepeatedOptions(const Fixture& F) {
  DSig::Test::Suite("a value option given twice is a usage error (F39)");
  const std::string A = Join(F.Dir, "a.diaphora"), B = Join(F.Dir, "b.diaphora");
  Expect("diff -o a -o b", Run({"diff", "-o", A, "--quiet", F.Main, F.Diff, "-o", B}), 2,
         "option '--output' given more than once");
  Expect("diff -o a --output b", Run({"diff", F.Main, F.Diff, "-o", A, "--output", B}), 2, "given more than once");
  CHECK(!Exists(A) && !Exists(B));
  Expect("port --results x --results y",
         Run({"port", F.Main, F.Diff, "-o", Join(F.Dir, "p.sqlite"), "--results", F.ResultsFile, "--results",
              F.ResultsFile}),
         2, "option '--results' given more than once");
  CHECK(!Exists(Join(F.Dir, "p.sqlite")));
  Expect("--quiet twice is fine", Run({"diff", F.Main, F.Diff, "-o", A, "--quiet", "--quiet"}), 0);
}

void TestNumbers(const Fixture& F) {
  DSig::Test::Suite("numbers: --min-ratio, --max-hops, --timeout, --iteration are strict (F35, F36)");
  const std::string Out = Join(F.Dir, "n.sqlite");
  const auto Port = [&](const char* Option, const std::string& Value) {
    return Run({"port", F.Main, F.Diff, "-o", Out, "--results", F.ResultsFile, Option, Value});
  };
  for (const char* Bad : {"abc", "0.5x", "", "nan", "inf", " 0.5", "1e-400", "-0.1", "1.5", "0x1p-1", "1,5"}) {
    Expect(std::string("--min-ratio '") + Bad + "'", Port("--min-ratio", Bad), 2,
           "min-ratio must be a number between 0.0 and 1.0");
  }
  for (const char* Good : {"0", "1", "0.5", "5e-1"}) {
    Expect(std::string("--min-ratio ") + Good, Port("--min-ratio", Good), 0);
  }
  for (const char* Bad : {" 3", "3x", "+3", "-1", "99999999999999999999", "9223372036854775808", "3.0", ""}) {
    Expect(std::string("--max-hops '") + Bad + "'", Port("--max-hops", Bad), 2, "max-hops must be an integer");
  }
  for (const char* Good : {"0", "3", "9223372036854775807"}) {
    Expect(std::string("--max-hops ") + Good, Port("--max-hops", Good), 0);
  }
  for (const char* Bad : {"604801", "-1", " 3", "3s", "4294967296"}) {
    Expect(std::string("ingest --timeout '") + Bad + "'",
           Run({"ingest", F.Text, "-o", Join(F.Dir, "i.sqlite"), "--timeout", Bad}), 2, "--timeout must be an integer");
  }
  Expect("update --timeout 99999999999",
         Run({"update", F.Main, F.Text, "-o", Join(F.Dir, "u.sqlite"), "--timeout", "99999999999"}), 2,
         "--timeout must be an integer");
  Expect("diff --iteration 2147483648",
         Run({"diff", F.Main, F.Diff, "--replay", "r.json", "--stage", "s", "--snapshot-out", "o.json", "--iteration",
              "2147483648"}),
         2, "--iteration must be an integer from 0 to 2147483647");
  Expect("diff --heuristic 50",
         Run({"diff", F.Main, F.Diff, "--replay", "r.json", "--stage", "s", "--snapshot-out", "o.json", "--heuristic",
              "50"}),
         2, "--heuristic must be a HEURISTICS index 0..49");
}

void TestHarnessSubOptions(const Fixture& F) {
  DSig::Test::Suite("diff: harness sub-options need their parent option (F60)");
  const std::string Out = Join(F.Dir, "h.diaphora");
  Expect("--trace-rows", Run({"diff", F.Main, F.Diff, "-o", Out, "--trace-rows"}), 2, "--trace-rows needs --trace");
  Expect("--snapshot-points", Run({"diff", F.Main, F.Diff, "-o", Out, "--snapshot-points", "x"}), 2,
         "need --snapshot-dir");
  Expect("--snapshot-cache", Run({"diff", F.Main, F.Diff, "-o", Out, "--snapshot-cache", "x"}), 2,
         "need --snapshot-dir");
  const std::string Should = Join(F.Dir, "shouldnotexist.diaphora");
  Expect("--replay with -o",
         Run({"diff", F.Main, F.Diff, "--replay", "r.json", "--stage", "s", "--snapshot-out", Join(F.Dir, "o.json"),
              "-o", Should}),
         2, "-o/--output does not apply");
  CHECK(!Exists(Out) && !Exists(Should));
  Expect("--unreliable", Run({"diff", F.Main, F.Diff, "-o", Out, "--unreliable"}), 4, "is not supported");
}

void TestExitCodes(const Fixture& F) {
  DSig::Test::Suite("exit codes: every command maps missing / not SQLite / not an export / alias alike (F07)");
  const std::string Missing = Join(F.Dir, "nothere.sqlite");
  // info
  Expect("info missing", Run({"info", Missing}), 6, Missing);
  Expect("info junk", Run({"info", F.Text}), 6, "is not an SQLite database");
  Expect("info results file", Run({"info", F.ResultsFile}), 4, "is a Diaphora results file");
  Expect("info directory", Run({"info", F.Dir}), 6, "is a directory");
  const CliRun Info = Run({"info", F.Main});
  Expect("info export", Info, 0);
  CHECK(Contains(Info.Out, "functions        : ") && Contains(Info.Out, "provenance       : absent"));
  // port (in-process diff) and port --results
  const std::string Out = Join(F.Dir, "e.sqlite");
  Expect("port missing reference", Run({"port", Missing, F.Diff, "-o", Out, "--quiet"}), 6, Missing);
  Expect("port junk reference", Run({"port", F.Text, F.Diff, "-o", Out, "--quiet"}), 6, "is not an SQLite database");
  Expect("port results file as reference", Run({"port", F.ResultsFile, F.Diff, "-o", Out, "--quiet"}), 4,
         "not a Diaphora export");
  Expect("port output = target", Run({"port", F.Main, F.Diff, "-o", F.Diff, "--quiet"}), 2,
         "refusing to overwrite an input");
  Expect("port output dir missing", Run({"port", F.Main, F.Diff, "-o", Join(Join(F.Dir, "nodir"), "x.sqlite")}), 6,
         "output directory '");
  Expect("port --results junk", Run({"port", F.Main, F.Diff, "-o", Out, "--results", F.Text}), 6,
         "not an SQLite database");
  Expect("port --results missing", Run({"port", F.Main, F.Diff, "-o", Out, "--results", Missing}), 6, Missing);
  Expect("port --results export", Run({"port", F.Main, F.Diff, "-o", Out, "--results", F.Main}), 4,
         "no 'results' table");
  Expect("port --results --no-keep-results", Run({"port", F.Main, F.Diff, "-o", Out, "--results", F.ResultsFile,
                                                  "--no-keep-results"}),
         2, "do not apply to port --results");
  CHECK(!Exists(Out));
  // update (checks before the ingest, so no IDA is needed)
  Expect("update missing labelled", Run({"update", Missing, F.Text, "-o", Out}), 6, Missing);
  Expect("update binary missing", Run({"update", F.Main, Join(F.Dir, "absent.dll"), "-o", Out}), 6, "absent.dll");
  Expect("update output = labelled", Run({"update", F.Main, F.Text, "-o", F.Main}), 2, "refusing to overwrite an input");
  Expect("update --overwrite-stripped alone", Run({"update", F.Main, F.Text, "-o", Out, "--overwrite-stripped"}), 2,
         "--overwrite-stripped needs --overwrite-existing");
  // diff
  Expect("diff missing", Run({"diff", Missing, F.Diff, "-o", Join(F.Dir, "d.diaphora")}), 6);
}

void TestPortAndInfo(const Fixture& F) {
  DSig::Test::Suite("plain port runs the diff and keeps its results; info shows each hop's settings (F59)");
  const std::string Out = Join(F.Dir, "labelled.sqlite");
  const CliRun Port = Run({"port", F.Main, F.Diff, "-o", Out, "--quiet", "--max-hops", "5", "--min-ratio", "0.25"});
  Expect("port", Port, 0);
  CHECK(Exists(Out) && Exists(Join(F.Dir, "labelled.diaphora")));
  CHECK(Contains(Port.Out, "(in-process diff, kept)") && Contains(Port.Out, "diff             : mode "));
  const CliRun Info = Run({"info", Out});
  Expect("info", Info, 0);
  CHECK(Contains(Info.Out, "hop settings:"));
  CHECK(Contains(Info.Out, "min-ratio 0.25, max-hops 5"));
  CHECK(Contains(Info.Out, "results labelled.diaphora (in-process diff, sha256 "));
  CHECK(Contains(Info.Out, "overwrite-existing no, overwrite-stripped no"));
  // The output is the reference of the next port.
  const std::string Hop2 = Join(F.Dir, "hop2.sqlite");
  Expect("port hop 2", Run({"port", Out, F.Diff, "-o", Hop2, "--quiet"}), 0);
  const CliRun Info2 = Run({"info", Hop2});
  CHECK(Contains(Info2.Out, "hops recorded    : 2"));
  CHECK(Contains(Info2.Out, "  hop 2: source labelled.sqlite"));
  // --quiet configures the in-process diff: refused with --results.
  Expect("port --results --quiet",
         Run({"port", Out, F.Diff, "-o", Join(F.Dir, "hop2b.sqlite"), "--quiet", "--results", F.ResultsFile}), 2,
         "do not apply to port --results");
}

void TestJson(const Fixture& F) {
  DSig::Test::Suite("--json: one JSON object on stdout for diff, port, update and info (F41)");
  const CliRun Info = Run({"info", F.Main, "--json"});
  Expect("info --json", Info, 0);
  const auto InfoJson = ParseJson(Info.Out);
  CHECK(InfoJson.has_value());
  if (InfoJson) {
    CHECK_TEXT_EQ(Field(*InfoJson, "schema"), "1");
    CHECK_TEXT_EQ(Field(*InfoJson, "command"), "info");
    CHECK_TEXT_EQ(Field(*InfoJson, "exit_code"), "0");
    CHECK_TEXT_EQ(Field(*InfoJson, "path"), F.Main);
    CHECK(Field(*InfoJson, "functions") != "<absent>" && Field(*InfoJson, "file_sha256").size() == 64);
    CHECK_TEXT_EQ(Field(*InfoJson, "hops"), "[]");
  }
  const CliRun Diff = Run({"diff", F.Main, F.Diff, "-o", Join(F.Dir, "j.diaphora"), "--json", "--quiet"});
  Expect("diff --json", Diff, 0);
  const auto DiffJson = ParseJson(Diff.Out);
  CHECK(DiffJson.has_value());
  if (DiffJson) {
    CHECK_TEXT_EQ(Field(*DiffJson, "command"), "diff");
    CHECK(Field(*DiffJson, "mode").size() == 1 && Field(*DiffJson, "best") != "<absent>");
    CHECK_TEXT_EQ(Field(*DiffJson, "output"), Join(F.Dir, "j.diaphora"));
  }
  const std::string Out = Join(F.Dir, "json.sqlite");
  const CliRun Port = Run({"port", F.Main, F.Diff, "-o", Out, "--json", "--quiet"});
  Expect("port --json", Port, 0);
  const auto PortJson = ParseJson(Port.Out);
  CHECK(PortJson.has_value());
  if (PortJson) {
    CHECK_TEXT_EQ(Field(*PortJson, "command"), "port");
    CHECK_TEXT_EQ(Field(*PortJson, "output"), Out);
    CHECK_TEXT_EQ(Field(*PortJson, "results_source"), "in-process diff");
    CHECK_TEXT_EQ(Field(*PortJson, "hop"), "1");
    CHECK(Field(*PortJson, "names_confirmed") != "<absent>" && Field(*PortJson, "diff") != "null");
    CHECK(Field(*PortJson, "output_sha256").size() == 64);
  }
  // failures print JSON too (and the error line on stderr)
  const CliRun Failed = Run({"info", F.Text, "--json"});
  Expect("info --json junk", Failed, 6, "error: ");
  const auto FailedJson = ParseJson(Failed.Out);
  CHECK(FailedJson.has_value() && Field(*FailedJson, "exit_code") == "6" &&
        Contains(Field(*FailedJson, "message"), "not an SQLite database"));
  const CliRun Usage = Run({"port", F.Main, F.Diff, "-o", Out, "--json", "--min-ratio", "abc"});
  Expect("port --json usage", Usage, 2);
  const auto UsageJson = ParseJson(Usage.Out);
  CHECK(UsageJson.has_value() && Field(*UsageJson, "exit_code") == "2");
  const CliRun UpdateFailed = Run({"update", Join(F.Dir, "none.sqlite"), F.Text, "-o", Join(F.Dir, "u.sqlite"), "--json"});
  Expect("update --json", UpdateFailed, 6);
  const auto UpdateJson = ParseJson(UpdateFailed.Out);
  CHECK(UpdateJson.has_value() && Field(*UpdateJson, "command") == "update" &&
        Field(*UpdateJson, "export") == Join(F.Dir, "u.ingest.sqlite"));
}

void TestGuard() {
  DSig::Test::Suite("RunGuarded: an escaping exception is exit 70, never an abort (F38)");
  CHECK_NUM_EQ(Cli::RunGuarded([] { return 3; }), 3);
  CHECK_NUM_EQ(Cli::RunGuarded([]() -> int { throw std::runtime_error("boom"); }), Cli::kExitInternal);
  CHECK_NUM_EQ(Cli::RunGuarded([]() -> int { throw std::bad_alloc(); }), Cli::kExitInternal);
  CHECK_NUM_EQ(Cli::RunGuarded([]() -> int { throw 42; }), Cli::kExitInternal);
}

void TestUncCli(const Fixture& F) {
#ifndef _WIN32
  (void)F;
  DSig::Test::Skip("CLI over UNC paths", "Windows only");
#else
  const std::string Absolute = PathToUtf8(std::filesystem::absolute(Utf8ToPath(F.Dir)));
  if (Absolute.size() < 3 || Absolute[1] != ':') {
    DSig::Test::Skip("CLI over UNC paths", "scratch directory is not on a drive letter");
    return;
  }
  std::string Rest = Absolute.substr(2);
  for (char& Ch : Rest) {
    if (Ch == '/') {
      Ch = '\\';
    }
  }
  const std::string UncDir = std::string("\\\\localhost\\") + Absolute[0] + "$" + Rest;
  if (!Exists(UncDir + "\\main.sqlite")) {
    DSig::Test::Skip("CLI over UNC paths", "\\\\localhost\\" + std::string(1, Absolute[0]) + "$ is not reachable");
    return;
  }
  DSig::Test::Suite("CLI: info and port over UNC paths (F17)");
  Expect("info UNC", Run({"info", UncDir + "\\main.sqlite"}), 0);
  Expect("port UNC", Run({"port", UncDir + "\\main.sqlite", UncDir + "\\diff.sqlite", "-o", UncDir + "\\unc.sqlite",
                          "--quiet"}),
         0);
  CHECK(Exists(Join(F.Dir, "unc.sqlite")) && Exists(Join(F.Dir, "unc.diaphora")));
  Expect("port --results UNC", Run({"port", UncDir + "\\main.sqlite", UncDir + "\\diff.sqlite", "-o",
                                    UncDir + "\\unc2.sqlite", "--results", UncDir + "\\pair.diaphora"}),
         0);
#endif
}

}

int main() {
  gScratch = DSig::Test::ScratchDir("cli_commands");
  TestGuard();
  TestHelp();
  const Fixture F = MakeFixture(Join(gScratch, "fixture"));
  CHECK(F.Ok);
  if (F.Ok) {
    TestRepeatedOptions(F);
    TestNumbers(F);
    TestHarnessSubOptions(F);
    TestExitCodes(F);
    TestPortAndInfo(F);
    TestJson(F);
    TestUncCli(F);
  }
  DSig::Test::RemoveScratchDir(gScratch);
  return DSig::Test::Finish();
}
