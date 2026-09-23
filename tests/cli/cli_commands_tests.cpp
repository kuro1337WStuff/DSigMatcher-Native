// cli_commands: the command-line contract of the built executable (DSIG_CLI_PATH): the exit-code table
// for every command, per-command help, argument parsing (repeated options, numbers, harness
// sub-options), --json, and the internal-error guard.
//
// Audit findings covered here: F07 (exit codes of info and every other path), F17 (UNC paths through
// the CLI), F35 / F36 (strict numbers), F38 (internal errors: exit 70), F39 (repeated options), F40
// (help), F41 (--json), F42 (--timeout range), F46 (--allow-no-decompiler), F59 (info shows the port
// settings), F60 (harness sub-options need their parent).
//
// extract / ingest / update run with THIS executable as their "Python" (DSIG_TEST_CHILD_MODE): a
// stand-in dsig_export.py that records its arguments and writes an export and its sidecar, or fails
// with the script's error line, or (Windows) loads a deliberately broken idalib.dll the way idapro
// does. That last one runs dsigmatcher with the error mode cleared to 0: it must end with exit 4, not
// block behind a modal "Bad Image" dialog.

#include <sqlite3.h>

#include <algorithm>
#include <chrono>
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

#include "../../src/cli/ExportBridgeDetail.h"
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
#include <shellapi.h>
#ifdef _MSC_VER
#pragma comment(lib, "shell32.lib")
#endif
#else
#include <stdlib.h>
#endif

namespace {

using namespace DSig;
using DSig::Test::PathToUtf8;
using DSig::Test::Utf8ToPath;
namespace Bridge = DSig::Cli::ExportBridge;

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
  bool TimedOut = false;  // Windows: still running after the wait and killed
};

void SetEnv(const std::string& Name, const std::optional<std::string>& Value) {
#ifdef _WIN32
  const std::wstring WideName = Bridge::PathFromUtf8(Name).native();
  SetEnvironmentVariableW(WideName.c_str(), Value ? Bridge::PathFromUtf8(*Value).native().c_str() : nullptr);
#else
  if (Value) {
    setenv(Name.c_str(), Value->c_str(), 1);
  } else {
    unsetenv(Name.c_str());
  }
#endif
}

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

// Runs the CLI with UTF-8 arguments as a wide command line; stdout and stderr go to separate files. A
// run still going after WaitMs is killed and reported as TimedOut. The child inherits this process's
// error mode (no CREATE_DEFAULT_ERROR_MODE).
CliRun Run(const std::vector<std::string>& Arguments, unsigned WaitMs = 300000) {
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
    if (WaitForSingleObject(Process.hProcess, WaitMs) == WAIT_TIMEOUT) {
      Result.TimedOut = true;
      TerminateProcess(Process.hProcess, 1);
      WaitForSingleObject(Process.hProcess, INFINITE);
    }
    DWORD Code = 0;
    GetExitCodeProcess(Process.hProcess, &Code);
    Result.Code = Result.TimedOut ? -2 : static_cast<int>(Code);
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
CliRun Run(const std::vector<std::string>& Arguments, unsigned WaitMs = 300000) {
  (void)WaitMs;  // std::system has no timeout; POSIX has no dialogs to wait on
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

// Text without carriage returns (the CLI's stdout and stderr are text mode on Windows).
std::string NoCr(std::string Text) {
  Text.erase(std::remove(Text.begin(), Text.end(), '\r'), Text.end());
  return Text;
}

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
// This executable as the export tool's "Python": argv[1..] is -E -X utf8 -B -u <script> <mode> <input>
// -o <output> --sidecar <json> ...

constexpr size_t kModeIndex = 6;
constexpr size_t kInputIndex = 7;

std::vector<std::string> ChildArguments(int Argc, char** Argv) {
  std::vector<std::string> Result;
#ifdef _WIN32
  (void)Argc;
  (void)Argv;
  int Count = 0;
  LPWSTR* Wide = CommandLineToArgvW(GetCommandLineW(), &Count);
  for (int Index = 1; Wide != nullptr && Index < Count; ++Index) {
    Result.push_back(Bridge::PathToUtf8(std::filesystem::path(Wide[Index])));
  }
  if (Wide != nullptr) {
    LocalFree(Wide);
  }
#else
  for (int Index = 1; Index < Argc; ++Index) {
    Result.emplace_back(Argv[Index]);
  }
#endif
  return Result;
}

std::string ArgumentAfter(const std::vector<std::string>& Arguments, const std::string& Flag) {
  for (size_t Index = 0; Index + 1 < Arguments.size(); ++Index) {
    if (Arguments[Index] == Flag) {
      return Arguments[Index + 1];
    }
  }
  return std::string();
}

void WriteText(const std::string& Path, const std::string& Text) {
  std::ofstream(Utf8ToPath(Path), std::ios::binary | std::ios::trunc) << Text;
}

// A stand-in dsig_export.py. DSIG_TEST_CHILD_RECORD: write the arguments there, one per line.
// DSIG_TEST_CHILD_EXIT: fail with that code and the script's error line. DSIG_TEST_CHILD_COPY_FROM: the
// export is a copy of that database (so `update` can diff it); else a placeholder file.
int ChildFakeExport(const std::vector<std::string>& Arguments) {
  if (const auto Record = Bridge::GetEnvUtf8("DSIG_TEST_CHILD_RECORD")) {
    std::string Lines;
    for (const std::string& Argument : Arguments) {
      Lines += Argument + "\n";
    }
    WriteText(*Record, Lines);
  }
  std::printf("[dsig_export] fake progress line\n");
  std::fflush(stdout);
  const auto Exit = Bridge::GetEnvUtf8("DSIG_TEST_CHILD_EXIT");
  if (Exit) {
    std::printf("dsig_export: error: fake failure %s\n", Exit->c_str());
    return std::atoi(Exit->c_str());
  }
  if (Arguments.size() <= kInputIndex) {
    return 99;
  }
  const std::string Output = ArgumentAfter(Arguments, "-o");
  std::error_code Error;
  if (const auto From = Bridge::GetEnvUtf8("DSIG_TEST_CHILD_COPY_FROM")) {
    std::filesystem::copy_file(Utf8ToPath(*From), Utf8ToPath(Output), std::filesystem::copy_options::overwrite_existing,
                               Error);
  } else {
    WriteText(Output, "fake export database");
  }
  const std::string Json =
      "{\"schema\": \"dsig-export/1\", \"mode\": " + Diff::JsonQuote(Arguments[kModeIndex]) +
      ", \"input\": {\"sha256\": \"" + Bridge::FileSha256(Utf8ToPath(Arguments[kInputIndex])).value_or("") +
      "\", \"unchanged\": true}, \"output\": {\"sha256\": \"" +
      Bridge::FileSha256(Utf8ToPath(Output)).value_or("") +
      "\"}, \"counts\": {\"functions\": 3, \"functions_named\": 2, \"functions_sub\": 1, "
      "\"functions_with_pseudocode\": 3, \"ida_functions\": 4}, \"ida\": {\"kernel_version\": \"9.9\", "
      "\"idalib_version\": [9, 9, 1], \"hexrays_version\": \"9.9.0.1\"}, \"diaphora\": {\"version_value\": "
      "\"3.4\", \"git_describe\": \"fake\"}, \"pdb\": {\"applied\": false}}";
  WriteText(ArgumentAfter(Arguments, "--sidecar"), Json);
  std::printf("[dsig_export] fake export done\n");
  return 0;
}

int RunChild(const std::string& Mode, int Argc, char** Argv) {
  const std::vector<std::string> Arguments = ChildArguments(Argc, Argv);
  if (Mode == "fake-export") {
    return ChildFakeExport(Arguments);
  }
#ifdef _WIN32
  if (Mode == "bad-idalib") {
    // What idapro does with the idalib of --ida-dir. The error mode is the one inherited from
    // dsigmatcher (DSIG_TEST_KEEP_ERROR_MODE keeps the harness from setting its own): with critical-error
    // dialogs on, this LoadLibraryW blocks on a modal "Bad Image" hard error until someone clicks it.
    const std::filesystem::path Library = Utf8ToPath(ArgumentAfter(Arguments, "--ida-dir")) / "idalib.dll";
    const UINT Inherited = GetErrorMode();
    const HMODULE Module = LoadLibraryW(Library.c_str());
    const DWORD Error = Module == nullptr ? GetLastError() : 0;
    if (Module != nullptr) {
      FreeLibrary(Module);
    }
    if (const auto Record = Bridge::GetEnvUtf8("DSIG_TEST_CHILD_RECORD")) {
      WriteText(*Record, "ERRORMODE " + std::to_string(Inherited) + "\nLOADED " +
                             std::to_string(Module != nullptr ? 1 : 0) + "\n");
    }
    std::printf("dsig_export: error: IDA not usable: cannot load %s (error %lu)\n", PathToUtf8(Library).c_str(),
                static_cast<unsigned long>(Error));
    return Bridge::kToolIda;
  }
#endif
  return 98;
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
  // the real discovery order (F45: never an ancestor's tools/export), and the tool flags
  CHECK(Contains(Extract.Out, "else DSIG_EXPORT_SCRIPT, else beside the"));
  CHECK(Contains(Extract.Out, "else <prefix>/share/dsigmatcher/tools/export"));
  CHECK(!Contains(Extract.Out, "ancestor"));
  for (const CliRun* Each : {&Extract, &Ingest, &Update}) {
    CHECK(Contains(Each->Out, "--allow-no-decompiler") && Contains(Each->Out, "(0..2592000, 30 days; 0: none)"));
    CHECK(Contains(Each->Out, "--quiet") && Contains(Each->Out, "--json"));
  }
  CHECK(Contains(NoCr(Extract.Out),
                 "on\n                                   failure only the final error line is printed"));
  CHECK(Contains(Update.Out, "--quiet also stops the ingest's progress stream"));
  // diff -o and the exit-code table say what happens to files
  CHECK(Contains(Diff.Out, "results file, replaced only on success; an existing file"));
  CHECK(Contains(Diff.Out, "is left as it was on a non-zero exit"));
  CHECK(Contains(NoCr(Diff.Out), "replaced only on success; an existing file\n"));
  CHECK(!Contains(Diff.Out, "stages skipped"));
  CHECK(Contains(Global.Out, "2  usage error, or refused (a path that would overwrite an input"));
  CHECK(Contains(NoCr(Global.Out),
                 "for diff: db2 is not a\n      Diaphora export (Diaphora's empty results are still written"));
  CHECK(Contains(Global.Out, "6  I/O or environment failure"));
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
  // F42: range-checked as a 64-bit number before it is narrowed: 4294967301 must not become 5.
  for (const char* Bad : {"2592001", "-1", " 3", "3s", "4294967296", "4294967301", "99999999999999999999"}) {
    Expect(std::string("ingest --timeout '") + Bad + "'",
           Run({"ingest", F.Text, "-o", Join(F.Dir, "i.sqlite"), "--timeout", Bad}), 2,
           "--timeout must be an integer number of seconds from 0 to 2592000 (30 days)");
    Expect(std::string("extract --timeout '") + Bad + "'",
           Run({"extract", Join(F.Dir, "x.i64"), "-o", Join(F.Dir, "i.sqlite"), "--timeout", Bad}), 2,
           "--timeout must be an integer");
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
  // -o is replaced only on success: an existing file is left as it was on a non-zero exit
  const std::string Kept = Join(F.Dir, "kept.diaphora");
  WriteText(Kept, "an earlier results file");
  Expect("diff missing db1 over an existing -o", Run({"diff", Missing, F.Diff, "-o", Kept, "--quiet"}), 6);
  Expect("diff junk db2 over an existing -o", Run({"diff", F.Main, F.Text, "-o", Kept, "--quiet"}), 6);
  Expect("diff -o = db2", Run({"diff", F.Main, F.Diff, "-o", F.Diff, "--quiet"}), 2);
  CHECK_TEXT_EQ(ReadFile(Kept), "an earlier results file");
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

// ---------------------------------------------------------------------------------------------
// extract / ingest / update through the built executable, with this executable as the export tool

struct ExportTools {
  std::string Dir, Self, Script, Ida, Diaphora, Sample, Database, Record;
  std::vector<std::string> Options() const {
    return {"--python", Self, "--export-script", Script, "--ida-dir", Ida, "--diaphora-dir", Diaphora};
  }
};

ExportTools MakeExportTools() {
  ExportTools T;
  T.Dir = Join(gScratch, "export");
  std::error_code Error;
  T.Self = Bridge::PathToUtf8(Bridge::SelfExecutablePath());
  T.Ida = Join(T.Dir, "ida");
  T.Diaphora = Join(T.Dir, "diaphora");
  std::filesystem::create_directories(Utf8ToPath(T.Ida), Error);
  std::filesystem::create_directories(Utf8ToPath(T.Diaphora), Error);
#if defined(_WIN32)
  WriteText(Join(T.Ida, "idalib.dll"), "this is not a PE image");  // a broken idalib
#elif defined(__APPLE__)
  WriteText(Join(T.Ida, "libidalib.dylib"), "x");
#else
  WriteText(Join(T.Ida, "libidalib.so"), "x");
#endif
  for (const char* Name : {"diaphora.py", "diaphora_ida.py", "diaphora_config.py"}) {
    WriteText(Join(T.Diaphora, Name), "# placeholder\n");
  }
  T.Script = Join(T.Dir, "dsig_export.py");
  WriteText(T.Script, "# placeholder: the child is the test executable\n");
  T.Sample = Join(T.Dir, "sample.dll");
  WriteText(T.Sample, std::string("MZ fake binary \0\1\2", 18));
  T.Database = Join(T.Dir, "user.i64");
  WriteText(T.Database, "IDA2 fake database");
  T.Record = Join(T.Dir, "record.txt");
  return T;
}

std::vector<std::string> With(std::vector<std::string> Arguments, const std::vector<std::string>& More) {
  Arguments.insert(Arguments.end(), More.begin(), More.end());
  return Arguments;
}

std::vector<std::string> Lines(const std::string& Text) {
  std::vector<std::string> Result;
  std::stringstream Stream(Text);
  std::string Line;
  while (std::getline(Stream, Line)) {
    if (!Line.empty() && Line.back() == '\r') {
      Line.pop_back();
    }
    Result.push_back(Line);
  }
  return Result;
}

bool Recorded(const ExportTools& T, const std::string& Argument) {
  const std::vector<std::string> Arguments = Lines(ReadFile(T.Record));
  return std::find(Arguments.begin(), Arguments.end(), Argument) != Arguments.end();
}

const Diff::JsonValue* Path(const Diff::JsonValue& Root, std::initializer_list<const char*> Keys) {
  const Diff::JsonValue* Value = &Root;
  for (const char* Key : Keys) {
    Value = (Value != nullptr && Value->IsObject()) ? Value->Find(Key) : nullptr;
  }
  return Value;
}

std::string At(const Diff::JsonValue& Root, std::initializer_list<const char*> Keys) {
  const Diff::JsonValue* Value = Path(Root, Keys);
  if (Value == nullptr) {
    return "<absent>";
  }
  return Value->IsString() ? Value->AsString() : Diff::JsonWrite(*Value);
}

void TestExportCommands(const Fixture& F) {
  DSig::Test::Suite("extract / ingest / update: --json, --quiet, --allow-no-decompiler, --timeout (F41, F42, F46)");
  const ExportTools T = MakeExportTools();
  SetEnv("DSIG_TEST_CHILD_MODE", "fake-export");
  SetEnv("DSIG_TEST_CHILD_RECORD", T.Record);
  const std::string Out = Join(T.Dir, "out.sqlite");

  // ingest --json: one JSON object on stdout; the tool's progress still streams to stderr
  const CliRun Ingest = Run(With({"ingest", T.Sample, "-o", Out, "--json"}, T.Options()));
  Expect("ingest --json", Ingest, 0, "[dsig_export] fake progress line");
  const auto IngestJson = ParseJson(Ingest.Out);
  CHECK(IngestJson.has_value());
  if (IngestJson) {
    CHECK_TEXT_EQ(Field(*IngestJson, "command"), "ingest");
    CHECK_TEXT_EQ(Field(*IngestJson, "exit_code"), "0");
    CHECK_TEXT_EQ(Field(*IngestJson, "mode"), "binary");
    CHECK_TEXT_EQ(Field(*IngestJson, "functions"), "3");
    CHECK_TEXT_EQ(Field(*IngestJson, "tool_exit_code"), "0");
    CHECK_TEXT_EQ(Field(*IngestJson, "allow_no_decompiler"), "false");
    CHECK_TEXT_EQ(Field(*IngestJson, "input_sha256"),
                  Bridge::FileSha256(Utf8ToPath(T.Sample)).value_or("unreadable"));
    CHECK(Field(*IngestJson, "output_sha256").size() == 64 && Field(*IngestJson, "sidecar") != "null");
  }
  CHECK(!Contains(Ingest.Out, "ingest: wrote"));
  CHECK(!Recorded(T, "--allow-no-decompiler"));

  // extract --json
  const CliRun Extract = Run(With({"extract", T.Database, "-o", Out, "--json"}, T.Options()));
  Expect("extract --json", Extract, 0);
  const auto ExtractJson = ParseJson(Extract.Out);
  CHECK(ExtractJson.has_value() && Field(*ExtractJson, "command") == "extract" &&
        Field(*ExtractJson, "mode") == "idb" && Field(*ExtractJson, "functions") == "3");

  // --quiet on success: the summary on stdout, nothing streamed
  const CliRun Quiet = Run(With({"ingest", T.Sample, "-o", Out, "--quiet"}, T.Options()));
  Expect("ingest --quiet", Quiet, 0);
  CHECK(Contains(Quiet.Out, "ingest: wrote"));
  CHECK(!Contains(Quiet.Err, "fake progress line"));

  // failures: without --quiet the stream and the error; with --quiet only the final error line
  SetEnv("DSIG_TEST_CHILD_EXIT", "16");
  const CliRun Loud = Run(With({"ingest", T.Sample, "-o", Out}, T.Options()));
  Expect("ingest failing", Loud, 6,
         "error: ingest failed: the export failed (dsig_export.py exit 16): fake failure 16");
  CHECK(Contains(Loud.Err, "[dsig_export] fake progress line"));
  const CliRun QuietFail = Run(With({"extract", T.Database, "-o", Out, "--quiet"}, T.Options()));
  Expect("extract --quiet failing", QuietFail, 6);
  CHECK_TEXT_EQ(QuietFail.Err,
                "error: extract failed: the export failed (dsig_export.py exit 16): fake failure 16" +
                    std::string(QuietFail.Err.find("\r\n") != std::string::npos ? "\r\n" : "\n"));
  CHECK(QuietFail.Out.empty());
  const CliRun JsonFail = Run(With({"ingest", T.Sample, "-o", Out, "--quiet", "--json"}, T.Options()));
  Expect("ingest --quiet --json failing", JsonFail, 6);
  CHECK(Lines(JsonFail.Err).size() == 1);
  const auto FailJson = ParseJson(JsonFail.Out);
  CHECK(FailJson.has_value());
  if (FailJson) {
    CHECK_TEXT_EQ(Field(*FailJson, "exit_code"), "6");
    CHECK_TEXT_EQ(Field(*FailJson, "tool_exit_code"), "16");
    CHECK_TEXT_EQ(Field(*FailJson, "tool_error"), "fake failure 16");
    CHECK(Contains(Field(*FailJson, "message"), "the export failed (dsig_export.py exit 16)"));
  }
  // F46: exit 13 names dsigmatcher's own flag
  SetEnv("DSIG_TEST_CHILD_EXIT", "13");
  Expect("ingest without Hex-Rays", Run(With({"ingest", T.Sample, "-o", Out, "--quiet"}, T.Options())), 4,
         "[to export anyway, pass --allow-no-decompiler");

  // update passes --quiet and --json to its ingest step (and --allow-no-decompiler to the script)
  SetEnv("DSIG_TEST_CHILD_EXIT", "16");
  const std::string Updated = Join(T.Dir, "updated.sqlite");
  const CliRun UpdateFail =
      Run(With({"update", F.Main, T.Sample, "-o", Updated, "--quiet", "--json", "--allow-no-decompiler"}, T.Options()));
  Expect("update --quiet --json, ingest failing", UpdateFail, 6);
  CHECK(Lines(UpdateFail.Err).size() == 1 && Contains(UpdateFail.Err, "error: ingest: "));
  CHECK(!Contains(UpdateFail.Err, "fake progress line"));
  CHECK(Recorded(T, "--allow-no-decompiler"));
  const auto UpdateFailJson = ParseJson(UpdateFail.Out);
  CHECK(UpdateFailJson.has_value());
  if (UpdateFailJson) {
    CHECK_TEXT_EQ(Field(*UpdateFailJson, "failed_step"), "ingest");
    CHECK_TEXT_EQ(At(*UpdateFailJson, {"ingest", "outcome", "tool_exit_code"}), "16");
    CHECK_TEXT_EQ(At(*UpdateFailJson, {"ingest", "outcome", "allow_no_decompiler"}), "true");
  }
  SetEnv("DSIG_TEST_CHILD_EXIT", std::nullopt);
  SetEnv("DSIG_TEST_CHILD_COPY_FROM", F.Diff);  // the "new binary's" export: the fixture's diff side
  const CliRun Update =
      Run(With({"update", F.Main, T.Sample, "-o", Updated, "--quiet", "--json", "--allow-sqlite-mismatch"},
               T.Options()));
  SetEnv("DSIG_TEST_CHILD_COPY_FROM", std::nullopt);
  Expect("update --quiet --json", Update, 0);
  CHECK(!Contains(Update.Err, "fake progress line"));
  CHECK(Exists(Updated) && Exists(Join(T.Dir, "updated.ingest.sqlite")) && Exists(Join(T.Dir, "updated.diaphora")));
  const auto UpdateJson = ParseJson(Update.Out);
  CHECK(UpdateJson.has_value());
  if (UpdateJson) {
    CHECK_TEXT_EQ(Field(*UpdateJson, "command"), "update");
    CHECK_TEXT_EQ(Field(*UpdateJson, "failed_step"), "null");
    CHECK_TEXT_EQ(At(*UpdateJson, {"ingest", "exit_code"}), "0");
    CHECK_TEXT_EQ(At(*UpdateJson, {"ingest", "outcome", "functions"}), "3");
    CHECK_TEXT_EQ(At(*UpdateJson, {"port", "exit_code"}), "0");
  }

  // --allow-no-decompiler reaches the script from extract and ingest too
  Expect("extract --allow-no-decompiler",
         Run(With({"extract", T.Database, "-o", Out, "--allow-no-decompiler", "--quiet"}, T.Options())), 0);
  CHECK(Recorded(T, "--allow-no-decompiler"));
  Expect("ingest --allow-no-decompiler",
         Run(With({"ingest", T.Sample, "-o", Out, "--allow-no-decompiler", "--quiet"}, T.Options())), 0);
  CHECK(Recorded(T, "--allow-no-decompiler"));

  // F42: the largest --timeout is accepted and passed on as given
  Expect("ingest --timeout 2592000", Run(With({"ingest", T.Sample, "-o", Out, "--timeout", "2592000", "--quiet"},
                                             T.Options())),
         0);
  const std::vector<std::string> Arguments = Lines(ReadFile(T.Record));
  const auto Timeout = std::find(Arguments.begin(), Arguments.end(), "--timeout");
  CHECK(Timeout != Arguments.end() && Timeout + 1 != Arguments.end() && *(Timeout + 1) == "2592000");

  SetEnv("DSIG_TEST_CHILD_MODE", std::nullopt);
  SetEnv("DSIG_TEST_CHILD_RECORD", std::nullopt);
}

// No Windows dialogs, ever. The error mode is cleared to 0 first (what cmd.exe and ctest leave), then
// dsigmatcher.exe runs an ingest whose worker loads a deliberately broken idalib.dll. dsigmatcher must
// set the no-dialog mode itself, first thing, so the worker inherits it: the run ends on its own with
// exit 4 well within the wait instead of blocking behind a modal "Bad Image" dialog. With a real
// Python and the real dsig_export.py (when available) the same run goes through Python and idapro.
void TestNoDialogs() {
#ifndef _WIN32
  DSig::Test::Skip("no dialogs: broken idalib.dll through dsigmatcher", "Windows only");
#else
  DSig::Test::Suite("no dialogs: a broken idalib.dll through dsigmatcher with the error mode cleared to 0");
  const ExportTools T = MakeExportTools();
  const std::string Out = Join(T.Dir, "nodialog.sqlite");
  const UINT Saved = GetErrorMode();
  SetErrorMode(0);
  SetEnv("DSIG_TEST_CHILD_MODE", "bad-idalib");
  SetEnv("DSIG_TEST_CHILD_RECORD", T.Record);
  SetEnv("DSIG_TEST_KEEP_ERROR_MODE", "1");
  const auto Begin = std::chrono::steady_clock::now();
  const CliRun Broken = Run(With({"ingest", T.Sample, "-o", Out, "--timeout", "60"}, T.Options()), 120000);
  const auto Seconds =
      std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - Begin).count();
  SetEnv("DSIG_TEST_CHILD_MODE", std::nullopt);
  SetEnv("DSIG_TEST_CHILD_RECORD", std::nullopt);
  SetEnv("DSIG_TEST_KEEP_ERROR_MODE", std::nullopt);
  SetErrorMode(Saved);
  CHECK(!Broken.TimedOut);
  CHECK(Seconds < 60);
  Expect("ingest with a broken idalib.dll", Broken, 4, "IDA not found or not usable (dsig_export.py exit 11)");
  CHECK(Contains(Broken.Err, "IDA not usable: cannot load"));
  unsigned Mode = 0;
  bool Loaded = true;
  for (const std::string& Line : Lines(ReadFile(T.Record))) {
    if (Line.rfind("ERRORMODE ", 0) == 0) {
      Mode = static_cast<unsigned>(std::strtoul(Line.c_str() + 10, nullptr, 10));
    } else if (Line.rfind("LOADED ", 0) == 0) {
      Loaded = Line != "LOADED 0";
    }
  }
  CHECK_NUM_EQ(Mode & Bridge::kNoErrorDialogs, Bridge::kNoErrorDialogs);
  CHECK(!Loaded);
  CHECK(!Exists(Out));

  // The real chain: dsigmatcher -> python dsig_export.py -> python worker -> idapro -> idalib.dll.
  const Bridge::Located Python = Bridge::FindPython(std::string());
  const std::string Script = DSig::Test::TestDataDir().empty()
                                 ? std::string()
                                 : PathToUtf8(Utf8ToPath(DSig::Test::TestDataDir()).parent_path().parent_path() /
                                              "tools" / "export" / "dsig_export.py");
  if (!Python.Ok() || Python.Path.empty() || Script.empty() || !Exists(Script)) {
    DSig::Test::Skip("no dialogs: the real dsig_export.py", "no Python (DSIG_PYTHON or PATH) or no source tree");
    return;
  }
  const std::string Temp = Join(T.Dir, "work");
  const std::string IdaUsr = Join(T.Dir, "empty idausr");
  std::error_code Error;
  std::filesystem::create_directories(Utf8ToPath(Temp), Error);
  std::filesystem::create_directories(Utf8ToPath(IdaUsr), Error);
  const std::optional<std::string> SavedIdaUsr = Bridge::GetEnvUtf8("IDAUSR");
  SetEnv("IDAUSR", IdaUsr);  // the user's IDA directory is never read
  SetErrorMode(0);
  const CliRun Real = Run({"ingest", T.Sample, "-o", Out, "--python", Bridge::PathToUtf8(Python.Path),
                           "--export-script", Script, "--ida-dir", T.Ida, "--diaphora-dir", T.Diaphora,
                           "--temp-dir", Temp, "--timeout", "180", "--quiet"},
                          420000);
  SetErrorMode(Saved);
  SetEnv("IDAUSR", SavedIdaUsr);
  CHECK(!Real.TimedOut);
  Expect("ingest through the real dsig_export.py with a broken idalib.dll", Real, 4,
         "IDA not found or not usable (dsig_export.py exit 11)");
  CHECK(!Exists(Out));
#endif
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

int main(int Argc, char** Argv) {
  if (const auto Mode = Bridge::GetEnvUtf8("DSIG_TEST_CHILD_MODE")) {
    return RunChild(*Mode, Argc, Argv);
  }
  // This executable plays the export tool. Started as a child without a mode, it must not run the
  // whole suite again (which would start itself again, and so on).
  if (Bridge::GetEnvUtf8("DSIG_TEST_SUITE_ACTIVE")) {
    std::printf("cli_commands started as a child without DSIG_TEST_CHILD_MODE\n");
    return 97;
  }
  SetEnv("DSIG_TEST_SUITE_ACTIVE", "1");
  for (const char* Name : {"DSIG_TEST_CHILD_RECORD", "DSIG_TEST_CHILD_EXIT", "DSIG_TEST_CHILD_COPY_FROM",
                           "DSIG_TEST_KEEP_ERROR_MODE", "DSIG_EXPORT_SCRIPT", "DSIG_EXPORT_ALLOW_NO_DECOMPILER"}) {
    SetEnv(Name, std::nullopt);
  }
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
    TestExportCommands(F);
    TestUncCli(F);
  }
  TestNoDialogs();
  DSig::Test::RemoveScratchDir(gScratch);
  return DSig::Test::Finish();
}
