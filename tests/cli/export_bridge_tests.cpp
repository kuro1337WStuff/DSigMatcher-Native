// Suite cli_export_bridge: `dsigmatcher extract` / `ingest` (plan §7.1 D7, §7.2 lane L10).
//
// Three kinds of test:
//   * unit tests of the bridge's pieces: Windows argument quoting (round-tripped through
//     CommandLineToArgvW on Windows), UTF-8 handling, the sidecar name, the exit-code map;
//   * process tests that use THIS executable as the child (DSIG_TEST_CHILD_MODE = echo / sleep /
//     fake-export), so argument passing, output capture, timeouts, tool discovery, error messages and
//     the sidecar checks are exercised end to end without Python or IDA (ctest never needs either);
//   * the v1.0.0 audit regressions (F02 path aliasing, F15 batch-file interpreters, F16 working
//     directory and program lookup, F42 long timeouts, F45 script discovery, F46 Hex-Rays advice and
//     --allow-no-decompiler, F57 c messages, F64 error-line parsing, F66 PYTHON* isolation) and the
//     no-dialog guarantee (a broken idalib.dll with the error mode cleared to 0 first must end the run
//     with exit 4, not a modal "Bad Image" dialog), with the same child modes; and, when a
//     Python is available (DSIG_PYTHON or python on PATH; skipped otherwise), dsig_export.py's own
//     selftest (F02, F16, F42, F43, F44, F46, F57 d, F66 on the script side) and a run of the real script
//     under a hostile PYTHONPATH;
//   * real exports, gated on DSIG_EXPORT_TESTS=1 plus DSIG_IDADIR and DSIG_DIAPHORA_DIR (DSIG_PYTHON or a
//     python on PATH) and the corpus: ingest cryptbase 8875 with its PDB, ingest win32u 9444 without a
//     PDB, and extract a COPY of the user's win32u .i64. Each result must equal the oracle export table
//     for table (tools/oracle/compare_exports.py semantics: every table but sqlite_*, rowid order,
//     functions.export_time ignored). They skip cleanly when anything is missing.

#include <sqlite3.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <initializer_list>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "../../src/cli/ExportBridgeDetail.h"
#include "diff/CorpusPaths.h"
#include "diff/TestHarness.h"
#include "dsigmatcher/cli/Commands.h"
#include "dsigmatcher/diff/Database.h"
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
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#endif

namespace {

using namespace DSig;
using namespace DSig::Cli;
using namespace DSig::Cli::ExportBridge;
namespace fs = std::filesystem;

// ------------------------------------------------------------------------------------------------ helpers

std::string Hex(std::string_view Text) {
  static const char* Digits = "0123456789abcdef";
  std::string Out;
  for (const char Ch : Text) {
    const unsigned char Byte = static_cast<unsigned char>(Ch);
    Out.push_back(Digits[Byte >> 4]);
    Out.push_back(Digits[Byte & 15]);
  }
  return Out;
}

void SetEnv(const std::string& Name, const std::optional<std::string>& Value) {
#ifdef _WIN32
  const std::wstring WideName = PathFromUtf8(Name).native();
  SetEnvironmentVariableW(WideName.c_str(), Value ? PathFromUtf8(*Value).native().c_str() : nullptr);
#else
  if (Value) {
    setenv(Name.c_str(), Value->c_str(), 1);
  } else {
    unsetenv(Name.c_str());
  }
#endif
}

bool Contains(const std::string& Text, const std::string& Part) { return Text.find(Part) != std::string::npos; }

bool WriteFile(const fs::path& Path, const std::string& Content) {
  std::ofstream Stream(Path, std::ios::binary | std::ios::trunc);
  Stream << Content;
  return static_cast<bool>(Stream);
}

std::string ReadFile(const fs::path& Path) {
  std::ifstream Stream(Path, std::ios::binary);
  std::ostringstream Text;
  Text << Stream.rdbuf();
  return Text.str();
}

std::vector<std::string> SplitLines(const std::string& Text) {
  std::vector<std::string> Lines;
  std::string Line;
  for (const char Ch : Text) {
    if (Ch == '\n') {
      if (!Line.empty() && Line.back() == '\r') {
        Line.pop_back();
      }
      Lines.push_back(Line);
      Line.clear();
    } else {
      Line.push_back(Ch);
    }
  }
  if (!Line.empty()) {
    Lines.push_back(Line);
  }
  return Lines;
}

// The child's arguments as UTF-8 (argv[1..]). Windows: the wide command line, so nothing is lost to the
// ANSI code page.
std::vector<std::string> ChildArguments(int Argc, char** Argv) {
  std::vector<std::string> Result;
#ifdef _WIN32
  (void)Argc;
  (void)Argv;
  int Count = 0;
  LPWSTR* Wide = CommandLineToArgvW(GetCommandLineW(), &Count);
  for (int Index = 1; Wide != nullptr && Index < Count; ++Index) {
    Result.push_back(PathToUtf8(fs::path(Wide[Index])));
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

std::string JsonText(const Diff::JsonValue& Root, std::initializer_list<const char*> Keys) {
  const Diff::JsonValue* Value = &Root;
  for (const char* Key : Keys) {
    Value = Value->IsObject() ? Value->Find(Key) : nullptr;
    if (Value == nullptr) {
      return "<missing>";
    }
  }
  if (Value->IsString()) {
    return Value->AsString();
  }
  if (Value->IsNumber()) {
    return Value->NumberText();
  }
  if (Value->IsBool()) {
    return Value->AsBool() ? "true" : "false";
  }
  return Value->IsNull() ? "null" : "<complex>";
}

int EnvInt(const char* Name, int Default) {
  const auto Value = GetEnvUtf8(Name);
  return Value ? std::atoi(Value->c_str()) : Default;
}

// ------------------------------------------------------------------------------------------------ child modes

int ChildEcho(const std::vector<std::string>& Arguments) {
  std::printf("ARGC %d\n", static_cast<int>(Arguments.size()));
  for (const std::string& Argument : Arguments) {
    std::printf("ARG %s\n", Hex(Argument).c_str());
  }
  if (const auto Names = GetEnvUtf8("DSIG_TEST_CHILD_ENV")) {
    std::stringstream Stream(*Names);
    std::string Name;
    while (std::getline(Stream, Name, ',')) {
      const auto Value = GetEnvUtf8(Name.c_str());
      std::printf("ENV %s %s\n", Name.c_str(), Value ? Hex(*Value).c_str() : "-");
    }
  }
  std::fflush(stdout);
  std::fprintf(stderr, "stderr line from the child\n");
  std::fflush(stderr);
  return EnvInt("DSIG_TEST_CHILD_EXIT", 0);
}

std::string ArgumentAfter(const std::vector<std::string>& Arguments, const std::string& Flag) {
  for (size_t Index = 0; Index + 1 < Arguments.size(); ++Index) {
    if (Arguments[Index] == Flag) {
      return Arguments[Index + 1];
    }
  }
  return std::string();
}

// argv[1..] of the bridge's command line: -E -X utf8 -B -u <script> <mode> <input> -o <output> ...
constexpr size_t kScriptIndex = 5;
constexpr size_t kModeIndex = 6;
constexpr size_t kInputIndex = 7;

// Plays dsig_export.py: `<python> -E -X utf8 -B -u <script> <mode> <input> -o <output> --sidecar <json> ...`.
int ChildFakeExport(const std::vector<std::string>& Arguments) {
  if (const auto Record = GetEnvUtf8("DSIG_TEST_CHILD_RECORD")) {
    std::string Lines;
    for (const std::string& Argument : Arguments) {
      Lines += Hex(Argument) + "\n";
    }
    WriteFile(PathFromUtf8(*Record), Lines);
    std::error_code Error;
    const auto Switch = GetEnvUtf8("NoDefaultCurrentDirectoryInExePath");
    WriteFile(PathFromUtf8(*Record + ".env"), "cwd " + Hex(PathToUtf8(fs::current_path(Error))) + "\nnodefault " +
                                                  Hex(Switch.value_or("-")) + "\n");
  }
  const int Exit = EnvInt("DSIG_TEST_CHILD_EXIT", 0);
  if (Exit != 0) {
    std::printf("[dsig_export] pretending to fail\ndsig_export: error: fake failure %d\n", Exit);
    return Exit;
  }
  if (Arguments.size() < kInputIndex + 2) {
    return 99;
  }
  const fs::path Input = PathFromUtf8(Arguments[kInputIndex]);
  if (GetEnvUtf8("DSIG_TEST_CHILD_TOUCH_INPUT")) {
    std::ofstream(Input, std::ios::binary | std::ios::app) << "x";
  }
  if (GetEnvUtf8("DSIG_TEST_CHILD_NO_OUTPUT")) {
    return 0;
  }
  const fs::path Output = PathFromUtf8(ArgumentAfter(Arguments, "-o"));
  const fs::path Sidecar = PathFromUtf8(ArgumentAfter(Arguments, "--sidecar"));
  WriteFile(Output, "fake export database");
  const std::string InputSha = GetEnvUtf8("DSIG_TEST_CHILD_BAD_SHA") ? std::string(64, '0') : *FileSha256(Input);
  const bool Pdb = !ArgumentAfter(Arguments, "--pdb").empty();
  std::string Json = "{\"schema\": \"dsig-export/1\", \"mode\": " + Diff::JsonQuote(Arguments[kModeIndex]) +
                     ", \"input\": {\"sha256\": \"" + InputSha + "\", \"unchanged\": true}, \"output\": {\"sha256\": \"" +
                     *FileSha256(Output) +
                     "\"}, \"counts\": {\"functions\": 3, \"functions_named\": 2, \"functions_sub\": 1, "
                     "\"functions_with_pseudocode\": 3, \"ida_functions\": 4}, \"ida\": {\"kernel_version\": \"9.9\", "
                     "\"idalib_version\": [9, 9, 1], \"hexrays_version\": \"9.9.0.1\"}, \"diaphora\": {\"version_value\": "
                     "\"3.4\", \"git_describe\": \"fake\"}, \"pdb\": {\"applied\": " +
                     std::string(Pdb ? "true, \"symbols_loaded\": 12" : "false") + "}}";
  WriteFile(Sidecar, Json);
  std::printf("[dsig_export] fake export done\n");
  return 0;
}

int RunChild(const std::string& Mode, int Argc, char** Argv) {
  const std::vector<std::string> Arguments = ChildArguments(Argc, Argv);
  if (Mode == "echo") {
    return ChildEcho(Arguments);
  }
  if (Mode == "sleep") {
    std::this_thread::sleep_for(std::chrono::seconds(EnvInt("DSIG_TEST_CHILD_SLEEP", 60)));
    return 0;
  }
  if (Mode == "fake-export") {
    return ChildFakeExport(Arguments);
  }
  if (Mode == "find-script") {
    // What a dsigmatcher installed where this copy of the test executable lives would run.
    const Located Script = FindExportScript(std::string());
    if (Script.Ok()) {
      std::printf("SCRIPT %s\n", Hex(PathToUtf8(Script.Path)).c_str());
    } else {
      std::printf("ERROR %s\n", Script.Error.c_str());
    }
    return 0;
  }
#ifdef _WIN32
  if (Mode == "error-mode") {
    std::printf("ERRORMODE %u\n", GetErrorMode());
    return 0;
  }
  if (Mode == "bad-idalib") {
    // Plays dsig_export.py's IDA worker at the moment idapro loads idalib from --ida-dir. The error mode
    // is the one inherited through the bridge (DSIG_TEST_KEEP_ERROR_MODE keeps the harness from
    // setting its own): with critical-error dialogs on, LoadLibraryW blocks on a modal "Bad Image".
    const fs::path Library = PathFromUtf8(ArgumentAfter(Arguments, "--ida-dir")) / "idalib.dll";
    const UINT Inherited = GetErrorMode();
    const HMODULE Module = LoadLibraryW(Library.c_str());
    const DWORD Error = Module == nullptr ? GetLastError() : 0;
    if (Module != nullptr) {
      FreeLibrary(Module);
    }
    if (const auto Record = GetEnvUtf8("DSIG_TEST_CHILD_RECORD")) {
      WriteFile(PathFromUtf8(*Record), "ERRORMODE " + std::to_string(Inherited) + "\nLOADED " +
                                           std::to_string(Module != nullptr ? 1 : 0) + "\n");
    }
    std::printf("[dsig_export] loading %s\n", PathToUtf8(Library).c_str());
    std::printf("dsig_export: error: IDA not usable: cannot load %s (error %lu)\n", PathToUtf8(Library).c_str(),
                static_cast<unsigned long>(Error));
    return kToolIda;
  }
  if (Mode == "load-bad-image" && !Arguments.empty()) {
    // What idapro does with a broken idalib. With critical-error dialogs on, this blocks on a modal
    // "Bad Image" hard error until someone clicks it.
    const HMODULE Module = LoadLibraryW(PathFromUtf8(Arguments[0]).c_str());
    std::printf("LOADED %d\n", Module != nullptr ? 1 : 0);
    if (Module != nullptr) {
      FreeLibrary(Module);
    }
    return 0;
  }
#endif
  return 98;
}

// ------------------------------------------------------------------------------------------------ unit tests

void TestQuoting() {
  Test::Suite("windows argument quoting");
  CHECK_TEXT_EQ(QuoteWindowsArgument(""), "\"\"");
  CHECK_TEXT_EQ(QuoteWindowsArgument("abc"), "abc");
  CHECK_TEXT_EQ(QuoteWindowsArgument("C:\\dir\\file.py"), "C:\\dir\\file.py");
  CHECK_TEXT_EQ(QuoteWindowsArgument("a b"), "\"a b\"");
  CHECK_TEXT_EQ(QuoteWindowsArgument("a\tb"), "\"a\tb\"");
  CHECK_TEXT_EQ(QuoteWindowsArgument("a\"b"), "\"a\\\"b\"");
  CHECK_TEXT_EQ(QuoteWindowsArgument("a\\\"b"), "\"a\\\\\\\"b\"");
  CHECK_TEXT_EQ(QuoteWindowsArgument("C:\\a b\\"), "\"C:\\a b\\\\\"");
  CHECK_TEXT_EQ(QuoteWindowsArgument("C:\\a b\\\\"), "\"C:\\a b\\\\\\\\\"");
  CHECK_TEXT_EQ(QuoteWindowsArgument("x\\\\y z"), "\"x\\\\y z\"");
  CHECK_TEXT_EQ(QuoteWindowsArgument("\xC3\xBC \xE6\xB5\x8B"), "\"\xC3\xBC \xE6\xB5\x8B\"");
  CHECK_TEXT_EQ(BuildWindowsCommandLine({"C:\\p y\\python.exe", "-B", "a b", ""}),
                "\"C:\\p y\\python.exe\" -B \"a b\" \"\"");

#ifdef _WIN32
  // The real parser: CommandLineToArgvW applies the same rules as the C runtime Python uses.
  const std::vector<std::string> Vectors = {"C:\\Program Files\\python.exe", "", "plain", "two words", "\"",
                                            "\\", "\\\\", "a\\", "a b\\", "a b\\\\", "\\\"", "a\"b\"c",
                                            "tab\there", "new\nline", "\xC3\xBC\xC3\xB1\xC3\xAF \xE6\xB5\x8B\xE8\xAF\x95",
                                            "trailing space ", "--opt=\"quoted value\"", "C:\\x y\\\"z\\\\"};
  const std::string Line = BuildWindowsCommandLine(Vectors);
  int Count = 0;
  LPWSTR* Parsed = CommandLineToArgvW(PathFromUtf8(Line).native().c_str(), &Count);
  CHECK(Parsed != nullptr);
  CHECK_NUM_EQ(Count, Vectors.size());
  for (int Index = 0; Parsed != nullptr && Index < Count && Index < static_cast<int>(Vectors.size()); ++Index) {
    CHECK_TEXT_EQ(PathToUtf8(fs::path(Parsed[Index])), Vectors[static_cast<size_t>(Index)]);
  }
  if (Parsed != nullptr) {
    LocalFree(Parsed);
  }
#endif
}

void TestUtf8() {
  Test::Suite("utf-8");
  CHECK(IsValidUtf8(""));
  CHECK(IsValidUtf8("plain ascii"));
  CHECK(IsValidUtf8("\xC3\xBC"));                  // U+00FC
  CHECK(IsValidUtf8("\xE6\xB5\x8B\xE8\xAF\x95"));  // two CJK
  CHECK(IsValidUtf8("\xF0\x9F\x98\x80"));          // U+1F600
  CHECK(!IsValidUtf8("\xFC"));                     // Latin-1 u-umlaut (an ANSI argv)
  CHECK(!IsValidUtf8("\xC0\xAF"));                 // overlong '/'
  CHECK(!IsValidUtf8("\xE0\x80\xAF"));             // overlong
  CHECK(!IsValidUtf8("\xED\xA0\x80"));             // surrogate U+D800
  CHECK(!IsValidUtf8("\xF4\x90\x80\x80"));         // above U+10FFFF
  CHECK(!IsValidUtf8("\xE6\xB5"));                 // truncated
  CHECK(!IsValidUtf8("\xC3\x28"));                 // bad continuation
  const std::string Text = "dir \xC3\xBC\xC3\xB1 \xE6\xB5\x8B/file name.sqlite";
  CHECK_TEXT_EQ(PathToUtf8(PathFromUtf8(Text)), Text);
#ifdef _WIN32
  // A narrow argv holds the ANSI code page; such text is not UTF-8 and is converted from the ACP.
  if (GetACP() == 1252) {
    CHECK_TEXT_EQ(PathToUtf8(PathFromUtf8("\xFC")), "\xC3\xBC");
  }
#endif
}

void TestSidecarName() {
  Test::Suite("sidecar name");
  const fs::path Dir = PathFromUtf8("some dir");
  CHECK_TEXT_EQ(PathToUtf8(SidecarPathFor(Dir / "out.sqlite")), PathToUtf8(Dir / "out.export.json"));
  CHECK_TEXT_EQ(PathToUtf8(SidecarPathFor(Dir / "out")), PathToUtf8(Dir / "out.export.json"));
  CHECK_TEXT_EQ(PathToUtf8(SidecarPathFor(Dir / "a.b.sqlite")), PathToUtf8(Dir / "a.b.export.json"));
  CHECK_TEXT_EQ(PathToUtf8(SidecarPathFor(Dir / ".hidden")), PathToUtf8(Dir / ".hidden.export.json"));
  CHECK_TEXT_EQ(PathToUtf8(SidecarPathFor(Dir / "..x")), PathToUtf8(Dir / "..x.export.json"));
  CHECK_TEXT_EQ(PathToUtf8(SidecarPathFor(Dir / "a.")), PathToUtf8(Dir / "a.export.json"));
  CHECK_TEXT_EQ(PathToUtf8(SidecarPathFor(Dir / "x.export.json")), PathToUtf8(Dir / "x.export.export.json"));
}

void TestExitMapping() {
  Test::Suite("exit code map");
  CHECK_EQ(MapToolExit(kToolOk).ExitCode, kExitOk);
  CHECK_EQ(MapToolExit(kToolUsage).ExitCode, kExitUsage);
  CHECK_EQ(MapToolExit(kToolInput).ExitCode, kExitIo);
  CHECK_EQ(MapToolExit(kToolIda).ExitCode, kExitUnsupported);
  CHECK_EQ(MapToolExit(kToolDiaphora).ExitCode, kExitUnsupported);
  CHECK_EQ(MapToolExit(kToolHexRays).ExitCode, kExitUnsupported);
  CHECK_EQ(MapToolExit(kToolPdb).ExitCode, kExitUsage);
  CHECK_EQ(MapToolExit(kToolOpen).ExitCode, kExitUnsupported);
  CHECK_EQ(MapToolExit(kToolExport).ExitCode, kExitIo);
  CHECK_EQ(MapToolExit(kToolInputChanged).ExitCode, kExitIo);
  CHECK_EQ(MapToolExit(kToolTimeout).ExitCode, kExitIo);
  CHECK_EQ(MapToolExit(kToolOutput).ExitCode, kExitIo);
  CHECK_EQ(MapToolExit(kToolInternal).ExitCode, kExitIo);
  CHECK_EQ(MapToolExit(kToolInterrupted).ExitCode, kExitIo);
  CHECK_EQ(MapToolExit(1).ExitCode, kExitIo);
  CHECK(Contains(MapToolExit(kToolInputChanged).What, "INPUT CHANGED"));
}

void TestToolErrorLine() {
  Test::Suite("the script's error line (F64)");
  CHECK_TEXT_EQ(ToolErrorLine(""), "");
  CHECK_TEXT_EQ(ToolErrorLine("dsig_export: error: at the very start"), "at the very start");
  CHECK_TEXT_EQ(ToolErrorLine("x\ndsig_export: error: first\r\ny\ndsig_export: error: last\r\nz"), "last");
  // A prefix inside a line (quoted by IDA or Diaphora) is not the script's error line.
  CHECK_TEXT_EQ(ToolErrorLine("dsig_export: error: real\nlog: dsig_export: error: quoted"), "real");
  CHECK_TEXT_EQ(ToolErrorLine("only quoted: dsig_export: error: no"), "");
  CHECK_TEXT_EQ(ToolErrorLine("a\ndsig_export: error: "), "");
}

void TestSameFile(const std::string& Scratch) {
  Test::Suite("path identity and written-path aliasing (F02)");
  const fs::path Dir = PathFromUtf8(Scratch) / "same file";
  std::error_code Error;
  fs::create_directories(Dir, Error);
  WriteFile(Dir / "a.dll", "a");
  CHECK(SameFile(Dir / "a.dll", Dir / "." / "a.dll"));
  CHECK(!SameFile(Dir / "a.dll", Dir / "b.dll"));
  CHECK(!SameFile(Dir / "a.dll", fs::path()));
  fs::create_hard_link(Dir / "a.dll", Dir / "hard link.sqlite", Error);
  if (!Error) {
    CHECK(SameFile(Dir / "a.dll", Dir / "hard link.sqlite"));
  }
#if defined(_WIN32) || defined(__APPLE__)
  CHECK(SameFile(Dir / "a.dll", Dir / "A.DLL"));
#endif
  const fs::path Output = Dir / "out.sqlite";
  const fs::path Sidecar = SidecarPathFor(Output);
  const auto Refused = [&](const fs::path& Input) {
    WriteFile(Input, "input");
    const bool Result = WrittenPathAlias(Output, Sidecar, {{"the input", Input}}).has_value();
    fs::remove(Input, Error);
    return Result;
  };
  for (const char* Name : {"out.sqlite", "out.sqlite-wal", "out.sqlite-shm", "out.sqlite-journal", "out.sqlite-crash",
                           "out.export.json", "out.sqlite.dsig-tmp-17", "out.sqlite-wal.dsig-old-17",
                           "out.sqlite-crash.dsig-old-17", "out.export.json.tmp-17"}) {
    CHECK(Refused(Dir / Name));
  }
  for (const char* Name : {"out.sqlite-walrus.dll", "out.dll", "out.sqlite.bak", "xout.sqlite-wal"}) {
    CHECK(!Refused(Dir / Name));
  }
#if defined(_WIN32)
  CHECK(Refused(Dir / "OUT.SQLITE-WAL"));
  CHECK(Refused(Dir / "Out.Sqlite.DSIG-TMP-3"));
#endif
  const auto Message = WrittenPathAlias(Output, Sidecar, {{"the PDB", Dir / "a.dll"}, {"the input", Output}});
  CHECK(Message.has_value() && Contains(*Message, "refusing to overwrite an input (nothing was changed)"));
}

// ------------------------------------------------------------------------------------------------ processes

void TestRunProcess(const std::string& Scratch) {
  Test::Suite("process launch (this executable as the child)");
  const fs::path Self = SelfExecutablePath();
  CHECK(!Self.empty());
  const std::vector<std::string> Tricky = {"",           "plain",        "two words",  "quote\"inside",
                                           "back\\slash", "trail\\",      "trail sp\\", "\\\"lead",
                                           "\xC3\xBC\xC3\xB1\xC3\xAF \xE6\xB5\x8B\xE8\xAF\x95",
                                           "tab\there",  "-o",           "--x=\"y z\""};
  std::vector<std::string> Arguments = {PathToUtf8(Self)};
  Arguments.insert(Arguments.end(), Tricky.begin(), Tricky.end());
  const ProcessResult Run =
      RunProcess(Arguments,
                 {{"DSIG_TEST_CHILD_MODE", "echo"}, {"DSIG_TEST_CHILD_EXIT", "7"},
                  {"DSIG_TEST_CHILD_ENV", "DSIG_TEST_ECHO_VAR,PATH"},
                  {"DSIG_TEST_ECHO_VAR", "value \xC3\xBC with = sign"}},
                 60, nullptr);
  CHECK(Run.Started);
  CHECK_NUM_EQ(Run.ExitCode, 7);
  CHECK(!Run.TimedOut);
  const std::vector<std::string> Lines = SplitLines(Run.Tail);
  std::vector<std::string> Received;
  std::string EchoVar;
  bool PathSeen = false;
  for (const std::string& Line : Lines) {
    if (Line.rfind("ARG ", 0) == 0) {
      Received.push_back(Line.substr(4));
    } else if (Line.rfind("ENV DSIG_TEST_ECHO_VAR ", 0) == 0) {
      EchoVar = Line.substr(23);
    } else if (Line.rfind("ENV PATH ", 0) == 0) {
      PathSeen = Line.substr(9) != "-";
    }
  }
  CHECK(Contains(Run.Tail, "ARGC " + std::to_string(Tricky.size())));
  CHECK_NUM_EQ(Received.size(), Tricky.size());
  for (size_t Index = 0; Index < Tricky.size() && Index < Received.size(); ++Index) {
    CHECK_TEXT_EQ(Received[Index], Hex(Tricky[Index]));
  }
  CHECK_TEXT_EQ(EchoVar, Hex("value \xC3\xBC with = sign"));
  CHECK(PathSeen);  // the inherited environment is kept next to the overrides
  CHECK(Contains(Run.Tail, "stderr line from the child"));  // stderr is merged into the pipe

  const auto Started = std::chrono::steady_clock::now();
  const ProcessResult Slow = RunProcess({PathToUtf8(Self)}, {{"DSIG_TEST_CHILD_MODE", "sleep"}}, 1, nullptr);
  const auto Seconds =
      std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - Started).count();
  CHECK(Slow.Started);
  CHECK(Slow.TimedOut);
  CHECK(Seconds < 45);

  const ProcessResult Missing = RunProcess({PathToUtf8(Self.parent_path() / "no-such-program.exe")}, {}, 5, nullptr);
  CHECK(!Missing.Started);
  CHECK(!Missing.Error.empty());

  // F42: a long timeout is honoured, not wrapped. 4294848 s * 1000 used to wrap to 0.7 s as a DWORD.
  for (const int64_t Long : {int64_t{4294848}, int64_t{4294967} + 120, int64_t{1} << 40}) {
    const auto Begin = std::chrono::steady_clock::now();
    const ProcessResult Waited =
        RunProcess({PathToUtf8(Self)}, {{"DSIG_TEST_CHILD_MODE", "sleep"}, {"DSIG_TEST_CHILD_SLEEP", "2"}}, Long, nullptr);
    const auto Elapsed =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - Begin).count();
    CHECK(Waited.Started);
    CHECK(!Waited.TimedOut);
    CHECK_NUM_EQ(Waited.ExitCode, 0);
    CHECK(Elapsed >= 1500);
  }

#ifdef _WIN32
  // A child that fails to load a DLL must not block on a modal hard-error dialog. cmd.exe, and so ctest
  // under dsig_build.cmd, leaves those dialogs on; emulate that whatever started this suite.
  Test::Suite("process launch: no hard-error dialogs in the child");
  const UINT SavedMode = GetErrorMode();
  SetErrorMode(0);
  const ProcessResult ModeRun = RunProcess(
      {PathToUtf8(Self)}, {{"DSIG_TEST_CHILD_MODE", "error-mode"}, {"DSIG_TEST_KEEP_ERROR_MODE", "1"}}, 60, nullptr);
  CHECK_NUM_EQ(GetErrorMode(), 0u);  // this process's own mode is restored
  unsigned ChildMode = 0;
  for (const std::string& Line : SplitLines(ModeRun.Tail)) {
    if (Line.rfind("ERRORMODE ", 0) == 0) {
      ChildMode = static_cast<unsigned>(std::strtoul(Line.c_str() + 10, nullptr, 10));
    }
  }
  CHECK(ModeRun.Started);
  CHECK_NUM_EQ(ChildMode & kNoErrorDialogs, kNoErrorDialogs);
  CHECK_NUM_EQ(kNoErrorDialogs,
               static_cast<unsigned>(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX));
  const fs::path BadImage = PathFromUtf8(Scratch) / "bad image" / "idalib.dll";
  std::error_code Error;
  fs::create_directories(BadImage.parent_path(), Error);
  WriteFile(BadImage, "x");
  const ProcessResult Load =
      RunProcess({PathToUtf8(Self), PathToUtf8(BadImage)},
                 {{"DSIG_TEST_CHILD_MODE", "load-bad-image"}, {"DSIG_TEST_KEEP_ERROR_MODE", "1"}}, 60, nullptr);
  CHECK(Load.Started);
  CHECK(!Load.TimedOut);
  CHECK_NUM_EQ(Load.ExitCode, 0);
  CHECK(Contains(Load.Tail, "LOADED 0"));
  SetErrorMode(SavedMode);
#else
  (void)Scratch;
#endif
}

// F44: on POSIX the script runs in its own process group, which the bridge signals as a whole.
void TestProcessGroup(const std::string& Scratch) {
#ifdef _WIN32
  (void)Scratch;
  Test::Skip("process group (F44)", "POSIX only: Windows uses a kill-on-close job object");
#else
  Test::Suite("process group (F44)");
  const fs::path Dir = PathFromUtf8(Scratch) / "group";
  std::error_code Error;
  fs::create_directories(Dir, Error);
  const auto Alive = [](const fs::path& PidFile) {
    std::ifstream Stream(PidFile);
    int Pid = 0;
    return static_cast<bool>(Stream >> Pid) && Pid > 0 && kill(Pid, 0) == 0;
  };
  // A timeout reaches the script's own children, not only the script.
  const fs::path First = Dir / "first.pid";
  ProcessResult Run =
      RunProcess({"/bin/sh", "-c", "sleep 300 & echo $! > '" + PathToUtf8(First) + "'; sleep 300"}, {}, 1, nullptr);
  CHECK(Run.Started && Run.TimedOut);
  std::this_thread::sleep_for(std::chrono::milliseconds(300));
  CHECK(fs::exists(First) && !Alive(First));
  // A child the script left running dies with the group once the script has exited.
  const fs::path Second = Dir / "second.pid";
  Run = RunProcess({"/bin/sh", "-c", "sleep 300 & echo $! > '" + PathToUtf8(Second) + "'; exit 7"}, {}, 0, nullptr);
  CHECK_NUM_EQ(Run.ExitCode, 7);
  std::this_thread::sleep_for(std::chrono::milliseconds(300));
  CHECK(fs::exists(Second) && !Alive(Second));
  // SIGINT that reaches the launcher (here sent by the script to its parent) is forwarded to the group.
  // Not when this process ignores SIGINT (started as a background job): it then stays ignored.
  struct sigaction Before {};
  sigaction(SIGINT, nullptr, &Before);
  if (Before.sa_handler == SIG_IGN) {
    Test::Note("SIGINT is ignored by this process (a background job): forwarding not checked");
  } else {
    Run = RunProcess({"/bin/sh", "-c", "trap 'echo GOT-INT; exit 130' INT; kill -INT $PPID; sleep 30 & wait"}, {},
                     60, nullptr);
    CHECK_NUM_EQ(Run.ExitCode, 130);
    CHECK(Contains(Run.Tail, "GOT-INT"));
  }
  struct sigaction After {};
  sigaction(SIGINT, nullptr, &After);
  CHECK(After.sa_handler == Before.sa_handler);  // the launcher's own disposition is restored
#endif
}

void TestBatchRefusal(const std::string& Scratch) {
#ifdef _WIN32
  Test::Suite("batch files are never started (F15)");
  const fs::path Dir = PathFromUtf8(Scratch) / "batch";
  std::error_code Error;
  fs::create_directories(Dir, Error);
  const fs::path Marker = Dir / "batch ran";
  const fs::path Batch = Dir / "shim.bat";
  WriteFile(Batch, "@echo off\r\nmkdir \"" + PathToUtf8(Marker) + "\"\r\n");
  const ProcessResult Run = RunProcess({PathToUtf8(Batch), "a&b"}, {}, 30, nullptr);
  CHECK(!Run.Started);
  CHECK(Contains(Run.Error, "batch file"));
  CHECK(!fs::exists(Marker));
  CHECK(!InterpreterProblem(Batch).empty());
  CHECK(!InterpreterProblem(Dir / "SHIM.CMD").empty());
  CHECK(!InterpreterProblem(Dir / "shim.btm").empty());
  CHECK(!InterpreterProblem(PathFromUtf8(PathToUtf8(Batch) + ". .")).empty());
  WriteFile(Dir / "python", "#!/bin/sh\nexec python3 \"$@\"\n");
  CHECK(Contains(InterpreterProblem(Dir / "python"), "MZ"));
  CHECK(InterpreterProblem(SelfExecutablePath()).empty());
  CHECK(InterpreterProblem(Dir / "missing app alias.exe").empty());  // unreadable .exe: the Store alias case
  CHECK(!InterpreterProblem(Dir / "missing.txt").empty());
#else
  (void)Scratch;
  Test::Skip("batch files are never started (F15)", "Windows only: posix_spawn with an argv involves no shell");
#endif
}

struct FakeTools {
  fs::path Root;
  fs::path Script;
  fs::path IdaDir;
  fs::path DiaphoraDir;
  fs::path Input;
  fs::path Database;
  fs::path Pdb;
  fs::path Output;
  fs::path TempDir;
  fs::path Record;
};

FakeTools MakeFakeTools(const std::string& Scratch) {
  FakeTools Fake;
  Fake.Root = PathFromUtf8(Scratch) / PathFromUtf8("dir with spaces \xC3\xBC\xC3\xB1 \xE6\xB5\x8B\xE8\xAF\x95");
  std::error_code Error;
  fs::create_directories(Fake.Root, Error);
  Fake.Script = Fake.Root / "fake dsig_export.py";
  WriteFile(Fake.Script, "# placeholder: the child is the test executable\n");
  Fake.IdaDir = Fake.Root / "ida 9";
  fs::create_directories(Fake.IdaDir, Error);
#if defined(_WIN32)
  WriteFile(Fake.IdaDir / "idalib.dll", "x");
#elif defined(__APPLE__)
  WriteFile(Fake.IdaDir / "libidalib.dylib", "x");
#else
  WriteFile(Fake.IdaDir / "libidalib.so", "x");
#endif
  Fake.DiaphoraDir = Fake.Root / "diaphora ref";
  fs::create_directories(Fake.DiaphoraDir, Error);
  for (const char* Name : {"diaphora.py", "diaphora_ida.py", "diaphora_config.py"}) {
    WriteFile(Fake.DiaphoraDir / Name, "# placeholder\n");
  }
  Fake.Input = Fake.Root / PathFromUtf8("input \xC3\xBC.dll");
  WriteFile(Fake.Input, std::string("MZ fake binary \0\1\2", 18));
  Fake.Database = Fake.Root / PathFromUtf8("user db \xE6\xB5\x8B.i64");
  WriteFile(Fake.Database, "IDA2 fake database");
  Fake.Pdb = Fake.Root / PathFromUtf8("input \xC3\xBC.pdb");
  WriteFile(Fake.Pdb, "fake pdb");
  Fake.Output = Fake.Root / PathFromUtf8("out \xC3\xBC.sqlite");
  Fake.TempDir = Fake.Root / "tmp dir";
  fs::create_directories(Fake.TempDir, Error);
  Fake.Record = Fake.Root / "record.txt";
  return Fake;
}

ExportToolOptions FakeOptions(const FakeTools& Fake) {
  ExportToolOptions Tools;
  Tools.Python = PathToUtf8(SelfExecutablePath());
  Tools.IdaDir = PathToUtf8(Fake.IdaDir);
  Tools.DiaphoraDir = PathToUtf8(Fake.DiaphoraDir);
  Tools.ExportScript = PathToUtf8(Fake.Script);
  return Tools;
}

std::vector<std::string> RecordedArguments(const FakeTools& Fake) {
  return SplitLines(ReadFile(Fake.Record));
}

void ClearRecord(const FakeTools& Fake) {
  std::error_code Error;
  fs::remove(Fake.Record, Error);
  fs::remove(Fake.Output, Error);
  fs::remove(SidecarPathFor(Fake.Output), Error);
}

void TestFakeExports(const std::string& Scratch) {
  Test::Suite("extract / ingest through a fake dsig_export.py");
  const FakeTools Fake = MakeFakeTools(Scratch);
  SetEnv("DSIG_TEST_CHILD_MODE", "fake-export");
  SetEnv("DSIG_TEST_CHILD_RECORD", PathToUtf8(Fake.Record));

  // ingest --no-pdb, every tool option, a temp dir given with a trailing separator
  {
    ClearRecord(Fake);
    IngestArgs Args;
    Args.Input = PathToUtf8(Fake.Input);
    Args.Output = PathToUtf8(Fake.Output);
    Args.NoPdb = true;
    Args.Tools = FakeOptions(Fake);
    Args.Tools.TempDir = PathToUtf8(Fake.TempDir) + PathToUtf8(fs::path("/").make_preferred());
    Args.Tools.KeepTemp = true;
    Args.Tools.TimeoutSeconds = 7;
    const CommandOutcome Outcome = RunIngest(Args);
    CHECK_NUM_EQ(Outcome.ExitCode, kExitOk);
    CHECK(Outcome.Message.empty());
    CHECK(!Outcome.Report.empty() && Contains(Outcome.Report[0], "ingest: wrote " + PathToUtf8(Fake.Output)));
    bool Unchanged = false;
    bool NoPdbLine = false;
    bool Functions = false;
    for (const std::string& Line : Outcome.Report) {
      Unchanged = Unchanged || Contains(Line, *FileSha256(Fake.Input) + " (unchanged)");
      NoPdbLine = NoPdbLine || Contains(Line, "none (no PDB, no symbol server)");
      Functions = Functions || Contains(Line, "3 exported (2 named, 1 sub_*, 3 with pseudo-code) of 4 in IDA");
    }
    CHECK(Unchanged);
    CHECK(NoPdbLine);
    CHECK(Functions);
    // --json: the outcome's fields
    CHECK(Outcome.Data.IsObject());
    if (Outcome.Data.IsObject()) {
      CHECK_TEXT_EQ(JsonText(Outcome.Data, {"mode"}), "binary");
      CHECK_TEXT_EQ(JsonText(Outcome.Data, {"output"}), PathToUtf8(Fake.Output));
      CHECK_TEXT_EQ(JsonText(Outcome.Data, {"sidecar"}), PathToUtf8(SidecarPathFor(Fake.Output)));
      CHECK_TEXT_EQ(JsonText(Outcome.Data, {"input_sha256"}), *FileSha256(Fake.Input));
      CHECK_TEXT_EQ(JsonText(Outcome.Data, {"output_sha256"}), *FileSha256(Fake.Output));
      CHECK_TEXT_EQ(JsonText(Outcome.Data, {"tool_exit_code"}), "0");
      CHECK_TEXT_EQ(JsonText(Outcome.Data, {"functions"}), "3");
      CHECK_TEXT_EQ(JsonText(Outcome.Data, {"functions_with_pseudocode"}), "3");
      CHECK_TEXT_EQ(JsonText(Outcome.Data, {"ida_functions"}), "4");
      CHECK_TEXT_EQ(JsonText(Outcome.Data, {"pdb_applied"}), "false");
      CHECK_TEXT_EQ(JsonText(Outcome.Data, {"pdb"}), "null");
      CHECK_TEXT_EQ(JsonText(Outcome.Data, {"allow_no_decompiler"}), "false");
      CHECK_TEXT_EQ(JsonText(Outcome.Data, {"hexrays_version"}), "9.9.0.1");
      CHECK_TEXT_EQ(JsonText(Outcome.Data, {"diaphora_version"}), "3.4");
    }
    const std::vector<std::string> Expected = {
        "-E", "-X", "utf8", "-B", "-u", PathToUtf8(Fake.Script), "binary", PathToUtf8(Fake.Input), "-o",
        PathToUtf8(Fake.Output),
        "--sidecar", PathToUtf8(Fake.Root / PathFromUtf8("out \xC3\xBC.export.json")), "--ida-dir",
        PathToUtf8(Fake.IdaDir), "--diaphora-dir", PathToUtf8(Fake.DiaphoraDir), "--temp-dir",
        PathToUtf8(fs::absolute(PathFromUtf8(Args.Tools.TempDir)).lexically_normal()), "--keep-temp", "--timeout",
        "7", "--no-pdb"};
    const std::vector<std::string> Recorded = RecordedArguments(Fake);
    CHECK_NUM_EQ(Recorded.size(), Expected.size());
    for (size_t Index = 0; Index < Expected.size() && Index < Recorded.size(); ++Index) {
      CHECK_TEXT_EQ(Recorded[Index], Hex(Expected[Index]));
    }
    // F16: the script starts in its own directory with the current-directory program lookup switched off
    const std::vector<std::string> Env = SplitLines(ReadFile(PathFromUtf8(PathToUtf8(Fake.Record) + ".env")));
    CHECK(Env.size() == 2);
    if (Env.size() == 2) {
#ifdef _WIN32
      // Windows searches the current directory for programs and DLLs; POSIX does not, and posix_spawn
      // has no portable chdir, so the working directory is only set on Windows.
      CHECK_TEXT_EQ(Env[0], "cwd " + Hex(PathToUtf8(Fake.Script.parent_path())));
#endif
      CHECK_TEXT_EQ(Env[1], "nodefault " + Hex("1"));
    }
  }

  // F42: --timeout is range-checked; the largest accepted value is passed on as is
  {
    for (const int Bad : {-1, kMaxTimeoutSeconds + 1, 2147483647}) {
      ClearRecord(Fake);
      IngestArgs Args;
      Args.Input = PathToUtf8(Fake.Input);
      Args.Output = PathToUtf8(Fake.Output);
      Args.Tools = FakeOptions(Fake);
      Args.Tools.TimeoutSeconds = Bad;
      const CommandOutcome Outcome = RunIngest(Args);
      CHECK_NUM_EQ(Outcome.ExitCode, kExitUsage);
      CHECK(Contains(Outcome.Message, "--timeout must be between 0 and 2592000"));
      CHECK(!fs::exists(Fake.Record));
    }
    ClearRecord(Fake);
    IngestArgs Args;
    Args.Input = PathToUtf8(Fake.Input);
    Args.Output = PathToUtf8(Fake.Output);
    Args.Tools = FakeOptions(Fake);
    Args.Tools.TimeoutSeconds = kMaxTimeoutSeconds;
    CHECK_NUM_EQ(RunIngest(Args).ExitCode, kExitOk);
    CHECK(ArgumentAfter(RecordedArguments(Fake), Hex("--timeout")) == Hex("2592000"));
  }

  // F46: --allow-no-decompiler is forwarded to the script (and only when given), for both modes
  {
    for (const bool Allow : {true, false}) {
      ClearRecord(Fake);
      IngestArgs Args;
      Args.Input = PathToUtf8(Fake.Input);
      Args.Output = PathToUtf8(Fake.Output);
      Args.Tools = FakeOptions(Fake);
      Args.Tools.AllowNoDecompiler = Allow;
      const CommandOutcome Outcome = RunIngest(Args);
      CHECK_NUM_EQ(Outcome.ExitCode, kExitOk);
      const std::vector<std::string> Recorded = RecordedArguments(Fake);
      CHECK((std::find(Recorded.begin(), Recorded.end(), Hex("--allow-no-decompiler")) != Recorded.end()) == Allow);
      CHECK_TEXT_EQ(JsonText(Outcome.Data, {"allow_no_decompiler"}), Allow ? "true" : "false");
    }
    ClearRecord(Fake);
    ExtractArgs Args;
    Args.Input = PathToUtf8(Fake.Database);
    Args.Output = PathToUtf8(Fake.Output);
    Args.Tools = FakeOptions(Fake);
    Args.Tools.AllowNoDecompiler = true;
    CHECK_NUM_EQ(RunExtract(Args).ExitCode, kExitOk);
    const std::vector<std::string> Recorded = RecordedArguments(Fake);
    CHECK(std::find(Recorded.begin(), Recorded.end(), Hex("--allow-no-decompiler")) != Recorded.end());
  }

  // --quiet changes only what is streamed: the outcome, its message and its fields are the same
  {
    ClearRecord(Fake);
    IngestArgs Args;
    Args.Input = PathToUtf8(Fake.Input);
    Args.Output = PathToUtf8(Fake.Output);
    Args.Tools = FakeOptions(Fake);
    Args.Tools.Quiet = true;
    const CommandOutcome Outcome = RunIngest(Args);
    CHECK_NUM_EQ(Outcome.ExitCode, kExitOk);
    CHECK(!Outcome.Report.empty());
    SetEnv("DSIG_TEST_CHILD_EXIT", std::to_string(kToolExport));
    ClearRecord(Fake);
    const CommandOutcome Failed = RunIngest(Args);
    SetEnv("DSIG_TEST_CHILD_EXIT", std::nullopt);
    CHECK_NUM_EQ(Failed.ExitCode, kExitIo);
    CHECK(Contains(Failed.Message, "fake failure " + std::to_string(kToolExport)));
  }

  // F15: a sample whose name holds cmd metacharacters reaches the interpreter as one literal argument
  {
    ClearRecord(Fake);
    const fs::path Hostile = Fake.Root / PathFromUtf8("a&md,PWNED&b %PATH% ^x.dll");
    WriteFile(Hostile, std::string("MZ hostile name", 15));
    IngestArgs Args;
    Args.Input = PathToUtf8(Hostile);
    Args.Output = PathToUtf8(Fake.Output);
    Args.Tools = FakeOptions(Fake);
    CHECK_NUM_EQ(RunIngest(Args).ExitCode, kExitOk);
    const std::vector<std::string> Recorded = RecordedArguments(Fake);
    CHECK(Recorded.size() > kInputIndex && Recorded[kInputIndex] == Hex(PathToUtf8(Hostile)));
    std::error_code Error;
    CHECK(!fs::exists(Fake.Root / "PWNED", Error) && !fs::exists(fs::current_path(Error) / "PWNED", Error));
    fs::remove(Hostile, Error);
  }

  // ingest --pdb
  {
    ClearRecord(Fake);
    IngestArgs Args;
    Args.Input = PathToUtf8(Fake.Input);
    Args.Output = PathToUtf8(Fake.Output);
    Args.Pdb = PathToUtf8(Fake.Pdb);
    Args.Tools = FakeOptions(Fake);
    const CommandOutcome Outcome = RunIngest(Args);
    CHECK_NUM_EQ(Outcome.ExitCode, kExitOk);
    const std::vector<std::string> Recorded = RecordedArguments(Fake);
    CHECK(Recorded.size() >= 2 && Recorded[Recorded.size() - 2] == Hex("--pdb") &&
          Recorded.back() == Hex(PathToUtf8(Fake.Pdb)));
    bool PdbLine = false;
    for (const std::string& Line : Outcome.Report) {
      PdbLine = PdbLine || Contains(Line, PathToUtf8(Fake.Pdb) + " (12 symbols loaded)");
    }
    CHECK(PdbLine);
  }

  // extract: idb mode, no PDB arguments at all
  {
    ClearRecord(Fake);
    ExtractArgs Args;
    Args.Input = PathToUtf8(Fake.Database);
    Args.Output = PathToUtf8(Fake.Output);
    Args.Tools = FakeOptions(Fake);
    const CommandOutcome Outcome = RunExtract(Args);
    CHECK_NUM_EQ(Outcome.ExitCode, kExitOk);
    CHECK(!Outcome.Report.empty() && Contains(Outcome.Report[0], "extract: wrote"));
    const std::vector<std::string> Recorded = RecordedArguments(Fake);
    CHECK(Recorded.size() > kInputIndex && Recorded[kModeIndex] == Hex("idb") &&
          Recorded[kInputIndex] == Hex(PathToUtf8(Fake.Database)));
    bool AnyPdb = false;
    for (const std::string& Line : Recorded) {
      AnyPdb = AnyPdb || Line == Hex("--pdb") || Line == Hex("--no-pdb");
    }
    CHECK(!AnyPdb);
  }

  // discovery through the environment instead of flags
  {
    ClearRecord(Fake);
    SetEnv("DSIG_PYTHON", PathToUtf8(SelfExecutablePath()));
    SetEnv("DSIG_IDADIR", PathToUtf8(Fake.IdaDir));
    SetEnv("DSIG_DIAPHORA_DIR", PathToUtf8(Fake.DiaphoraDir));
    SetEnv("DSIG_EXPORT_SCRIPT", PathToUtf8(Fake.Script));
    IngestArgs Args;
    Args.Input = PathToUtf8(Fake.Input);
    Args.Output = PathToUtf8(Fake.Output);
    const CommandOutcome Outcome = RunIngest(Args);
    CHECK_NUM_EQ(Outcome.ExitCode, kExitOk);
    const std::vector<std::string> Recorded = RecordedArguments(Fake);
    CHECK(Recorded.size() > kScriptIndex && Recorded[kScriptIndex] == Hex(PathToUtf8(Fake.Script)));
    CHECK(ArgumentAfter(Recorded, Hex("--ida-dir")) == Hex(PathToUtf8(Fake.IdaDir)));
    CHECK(Recorded.back() == Hex("--no-pdb"));  // neither flag: no PDB is the default
    for (const char* Name : {"DSIG_PYTHON", "DSIG_IDADIR", "DSIG_DIAPHORA_DIR", "DSIG_EXPORT_SCRIPT"}) {
      SetEnv(Name, std::nullopt);
    }
  }

  // no IDA dir configured: nothing is passed and the script discovers it
  {
    ClearRecord(Fake);
    IngestArgs Args;
    Args.Input = PathToUtf8(Fake.Input);
    Args.Output = PathToUtf8(Fake.Output);
    Args.Tools = FakeOptions(Fake);
    Args.Tools.IdaDir.clear();
    CHECK_NUM_EQ(RunIngest(Args).ExitCode, kExitOk);
    const std::vector<std::string> Recorded = RecordedArguments(Fake);
    bool IdaFlag = false;
    for (const std::string& Line : Recorded) {
      IdaFlag = IdaFlag || Line == Hex("--ida-dir");
    }
    CHECK(!IdaFlag);
  }

  // the script's exit codes become the CLI's, with its own error line in the message
  struct Case {
    int ToolExit;
    int CliExit;
    const char* Text;
  };
  const Case Cases[] = {{kToolIda, kExitUnsupported, "IDA not found or not usable"},
                        {kToolDiaphora, kExitUnsupported, "Diaphora not found"},
                        {kToolHexRays, kExitUnsupported, "Hex-Rays"},
                        {kToolPdb, kExitUsage, "PDB"},
                        {kToolOpen, kExitUnsupported, "cannot open"},
                        {kToolExport, kExitIo, "the export failed"},
                        {kToolInputChanged, kExitIo, "INPUT CHANGED"},
                        {kToolTimeout, kExitIo, "timeout"},
                        {kToolOutput, kExitIo, "output"},
                        {kToolInterrupted, kExitIo, "interrupted"},
                        {kToolInput, kExitIo, "input"},
                        {99, kExitIo, "the export tool failed"}};
  for (const Case& Each : Cases) {
    ClearRecord(Fake);
    SetEnv("DSIG_TEST_CHILD_EXIT", std::to_string(Each.ToolExit));
    IngestArgs Args;
    Args.Input = PathToUtf8(Fake.Input);
    Args.Output = PathToUtf8(Fake.Output);
    Args.Tools = FakeOptions(Fake);
    const CommandOutcome Outcome = RunIngest(Args);
    CHECK_NUM_EQ(Outcome.ExitCode, Each.CliExit);
    CHECK(Contains(Outcome.Message, Each.Text));
    CHECK(Contains(Outcome.Message, "fake failure " + std::to_string(Each.ToolExit)));
    CHECK(Contains(Outcome.Message, "(dsig_export.py exit " + std::to_string(Each.ToolExit) + ")"));
    // F46: the advice names what works through dsigmatcher: its own flag, and the variable
    CHECK(Contains(Outcome.Message, "pass --allow-no-decompiler") == (Each.ToolExit == kToolHexRays));
    CHECK(Contains(Outcome.Message, "DSIG_EXPORT_ALLOW_NO_DECOMPILER=1") == (Each.ToolExit == kToolHexRays));
    // --json on failure: what the script said and how it ended
    CHECK_TEXT_EQ(JsonText(Outcome.Data, {"tool_exit_code"}), std::to_string(Each.ToolExit));
    CHECK_TEXT_EQ(JsonText(Outcome.Data, {"tool_error"}), "fake failure " + std::to_string(Each.ToolExit));
    CHECK_TEXT_EQ(JsonText(Outcome.Data, {"input_sha256"}), *FileSha256(Fake.Input));
  }
  SetEnv("DSIG_TEST_CHILD_EXIT", std::nullopt);

  // success claimed but no output, a sidecar that does not match, and an input changed behind our back
  {
    ClearRecord(Fake);
    SetEnv("DSIG_TEST_CHILD_NO_OUTPUT", "1");
    IngestArgs Args;
    Args.Input = PathToUtf8(Fake.Input);
    Args.Output = PathToUtf8(Fake.Output);
    Args.Tools = FakeOptions(Fake);
    CommandOutcome Outcome = RunIngest(Args);
    CHECK_NUM_EQ(Outcome.ExitCode, kExitIo);
    CHECK(Contains(Outcome.Message, "reported success but wrote no"));
    SetEnv("DSIG_TEST_CHILD_NO_OUTPUT", std::nullopt);

    ClearRecord(Fake);
    SetEnv("DSIG_TEST_CHILD_BAD_SHA", "1");
    Outcome = RunIngest(Args);
    CHECK_NUM_EQ(Outcome.ExitCode, kExitIo);
    CHECK(Contains(Outcome.Message, "does not match the run: input sha256"));
    SetEnv("DSIG_TEST_CHILD_BAD_SHA", std::nullopt);

    ClearRecord(Fake);
    const std::string Original = ReadFile(Fake.Input);
    SetEnv("DSIG_TEST_CHILD_TOUCH_INPUT", "1");
    Outcome = RunIngest(Args);
    CHECK_NUM_EQ(Outcome.ExitCode, kExitIo);
    CHECK(Contains(Outcome.Message, "THE INPUT CHANGED"));
    SetEnv("DSIG_TEST_CHILD_TOUCH_INPUT", std::nullopt);
    WriteFile(Fake.Input, Original);
  }

  SetEnv("DSIG_TEST_CHILD_MODE", std::nullopt);
  SetEnv("DSIG_TEST_CHILD_RECORD", std::nullopt);
}

void TestValidationAndMissingTools(const std::string& Scratch) {
  Test::Suite("argument validation and missing tools (bogus paths)");
  const FakeTools Fake = MakeFakeTools(Scratch);
  ClearRecord(Fake);
  const auto Ingest = [&](const std::function<void(IngestArgs&)>& Change) {
    IngestArgs Args;
    Args.Input = PathToUtf8(Fake.Input);
    Args.Output = PathToUtf8(Fake.Output);
    Args.Tools = FakeOptions(Fake);
    Change(Args);
    return RunIngest(Args);
  };
  const auto Extract = [&](const std::function<void(ExtractArgs&)>& Change) {
    ExtractArgs Args;
    Args.Input = PathToUtf8(Fake.Database);
    Args.Output = PathToUtf8(Fake.Output);
    Args.Tools = FakeOptions(Fake);
    Change(Args);
    return RunExtract(Args);
  };
  const fs::path Nowhere = Fake.Root / "no such dir";

  CommandOutcome Outcome = Ingest([&](IngestArgs& A) { A.Tools.Python = PathToUtf8(Nowhere / "python.exe"); });
  CHECK_NUM_EQ(Outcome.ExitCode, kExitUnsupported);
  CHECK(Contains(Outcome.Message, "Python not found: --python '"));
  CHECK(Contains(Outcome.Message, "does not exist"));

  SetEnv("DSIG_PYTHON", PathToUtf8(Nowhere / "python3"));
  Outcome = Ingest([&](IngestArgs& A) { A.Tools.Python.clear(); });
  CHECK_NUM_EQ(Outcome.ExitCode, kExitUnsupported);
  CHECK(Contains(Outcome.Message, "Python not found: DSIG_PYTHON '"));
  SetEnv("DSIG_PYTHON", std::nullopt);

  Outcome = Ingest([&](IngestArgs& A) { A.Tools.Python = "dsig-no-such-python-xyz"; });
  CHECK_NUM_EQ(Outcome.ExitCode, kExitUnsupported);
  CHECK(Contains(Outcome.Message, "is not on PATH"));

  Outcome = Ingest([&](IngestArgs& A) { A.Tools.IdaDir = PathToUtf8(Nowhere); });
  CHECK_NUM_EQ(Outcome.ExitCode, kExitUnsupported);
  CHECK(Contains(Outcome.Message, "IDA not found: --ida-dir '"));
  CHECK(Contains(Outcome.Message, "is not a directory"));

  Outcome = Ingest([&](IngestArgs& A) { A.Tools.IdaDir = PathToUtf8(Fake.DiaphoraDir); });
  CHECK_NUM_EQ(Outcome.ExitCode, kExitUnsupported);
  CHECK(Contains(Outcome.Message, "(IDA 9.0 or newer with idalib is required)"));

  Outcome = Ingest([&](IngestArgs& A) { A.Tools.DiaphoraDir = PathToUtf8(Nowhere); });
  CHECK_NUM_EQ(Outcome.ExitCode, kExitUnsupported);
  CHECK(Contains(Outcome.Message, "Diaphora not found: --diaphora-dir '"));

  Outcome = Ingest([&](IngestArgs& A) { A.Tools.DiaphoraDir.clear(); });
  CHECK_NUM_EQ(Outcome.ExitCode, kExitUnsupported);
  CHECK(Contains(Outcome.Message, "Diaphora not found: pass --diaphora-dir"));

  Outcome = Ingest([&](IngestArgs& A) { A.Tools.DiaphoraDir = PathToUtf8(Fake.IdaDir); });
  CHECK_NUM_EQ(Outcome.ExitCode, kExitUnsupported);
  CHECK(Contains(Outcome.Message, "has no diaphora.py, diaphora_ida.py, diaphora_config.py"));

  Outcome = Ingest([&](IngestArgs& A) { A.Tools.ExportScript = PathToUtf8(Nowhere / "dsig_export.py"); });
  CHECK_NUM_EQ(Outcome.ExitCode, kExitUnsupported);
  CHECK(Contains(Outcome.Message, "export script not found: --export-script '"));

#ifdef _WIN32
  // F15: a batch or script shim as the interpreter is refused before anything starts; the shim would
  // create the marker if cmd.exe ever ran it.
  {
    const fs::path Marker = Fake.Root / "shim ran";
    const std::string Body = "@echo off\r\nmkdir \"" + PathToUtf8(Marker) + "\"\r\n";
    WriteFile(Fake.Root / "python.bat", Body);
    WriteFile(Fake.Root / "python.CMD", Body);
    WriteFile(Fake.Root / "python", "#!/bin/sh\nexec python3 \"$@\"\n");
    for (const std::string& Shim : {PathToUtf8(Fake.Root / "python.bat"), PathToUtf8(Fake.Root / "python.bat") + ".",
                                    PathToUtf8(Fake.Root / "python")}) {
      Outcome = Ingest([&](IngestArgs& A) { A.Tools.Python = Shim; });
      CHECK_NUM_EQ(Outcome.ExitCode, kExitUnsupported);
      CHECK(Contains(Outcome.Message, "Python not found: --python '" + Shim + "'"));
      CHECK(Contains(Outcome.Message, "point --python at python.exe itself"));
    }
    SetEnv("DSIG_PYTHON", PathToUtf8(Fake.Root / "python.CMD"));
    Outcome = Ingest([&](IngestArgs& A) { A.Tools.Python.clear(); });
    CHECK_NUM_EQ(Outcome.ExitCode, kExitUnsupported);
    CHECK(Contains(Outcome.Message, "Python not found: DSIG_PYTHON '") && Contains(Outcome.Message, "batch file"));
    SetEnv("DSIG_PYTHON", std::nullopt);
    // A bare name means name.exe on Windows; a shim of that name on PATH is not picked up.
    const std::optional<std::string> SavedPath = GetEnvUtf8("PATH");
    WriteFile(Fake.Root / "dsigshim.bat", Body);
    WriteFile(Fake.Root / "dsigshim", "not a program");
    SetEnv("PATH", PathToUtf8(Fake.Root) + ";" + SavedPath.value_or(""));
    Outcome = Ingest([&](IngestArgs& A) { A.Tools.Python = "dsigshim"; });
    SetEnv("PATH", SavedPath);
    CHECK_NUM_EQ(Outcome.ExitCode, kExitUnsupported);
    CHECK(Contains(Outcome.Message, "is not on PATH"));
    CHECK(!fs::exists(Marker));
    CHECK(!fs::exists(Fake.Record));
  }
#endif

  // F02: nothing the script writes, replaces or moves aside may be the input or the PDB. Each refusal
  // is exit 2 before anything starts, and the protected file keeps its bytes.
  {
    const fs::path Dir = Fake.Root / "aliases";
    std::error_code Error;
    fs::create_directories(Dir, Error);
    const fs::path Out = Dir / "out.sqlite";
    const auto Refused = [&](const std::function<void(IngestArgs&)>& Change, const fs::path& Protected,
                             const char* What) {
      ClearRecord(Fake);
      const std::string Before = ReadFile(Protected);
      IngestArgs Args;
      Args.Input = PathToUtf8(Fake.Input);
      Args.Output = PathToUtf8(Out);
      Args.Tools = FakeOptions(Fake);
      Change(Args);
      const CommandOutcome Result = RunIngest(Args);
      CHECK_NUM_EQ(Result.ExitCode, kExitUsage);
      CHECK(ReadFile(Protected) == Before && !Before.empty());
      CHECK(!fs::exists(Fake.Record));
      if (Result.ExitCode != kExitUsage) {
        Test::Note(std::string(What) + ": " + Result.Message);
      }
      return Result.Message;
    };
    const auto Place = [&](const char* Name, const fs::path& From) {
      fs::copy_file(From, Dir / PathFromUtf8(Name), fs::copy_options::overwrite_existing, Error);
      return Dir / PathFromUtf8(Name);
    };
    // the audit's repro (a): -o <pdb> --pdb <pdb>
    const fs::path Pdb = Place("cryptbase.pdb", Fake.Pdb);
    std::string Message = Refused([&](IngestArgs& A) { A.Output = PathToUtf8(Pdb); A.Pdb = PathToUtf8(Pdb); }, Pdb,
                                  "-o pdb --pdb pdb");
    CHECK(Contains(Message, ".pdb"));
    // the audit's repro (b): an input named <out>-wal, and the other names PublishOutput renames aside
    for (const char* Suffix : {"-wal", "-shm", "-journal", "-crash"}) {
      const fs::path Input = Place((std::string("out.sqlite") + Suffix).c_str(), Fake.Input);
      Message = Refused([&](IngestArgs& A) { A.Input = PathToUtf8(Input); A.NoPdb = true; }, Input, Suffix);
      CHECK(Contains(Message, std::string("the output's ") + Suffix + " file"));
      CHECK(Contains(Message, "refusing to overwrite an input (nothing was changed)"));
      fs::rename(Input, Dir / "moved.pdb", Error);
      const fs::path AsPdb = Dir / PathFromUtf8(std::string("out.sqlite") + Suffix);
      fs::rename(Dir / "moved.pdb", AsPdb, Error);
      Message = Refused([&](IngestArgs& A) { A.Pdb = PathToUtf8(AsPdb); }, AsPdb, "--pdb <out>-wal");
      CHECK(Contains(Message, "the PDB"));
      fs::remove(AsPdb, Error);
    }
    for (const char* Name : {"out.export.json", "out.sqlite.dsig-tmp-4242", "out.sqlite-shm.dsig-old-4242",
                             "out.export.json.tmp-4242"}) {
      const fs::path Input = Place(Name, Fake.Input);
      Refused([&](IngestArgs& A) { A.Input = PathToUtf8(Input); }, Input, Name);
      fs::remove(Input, Error);
    }
#if defined(_WIN32)
    {
      const fs::path Input = Place("OUT.SQLITE-JOURNAL", Fake.Input);
      Refused([&](IngestArgs& A) { A.Input = PathToUtf8(Input); }, Input, "case variant");
      fs::remove(Input, Error);
      const fs::path WalPdb = Place("cb.sqlite-wal", Fake.Pdb);
      Refused([&](IngestArgs& A) { A.Output = PathToUtf8(Dir / "CB.SQLITE"); A.Pdb = PathToUtf8(WalPdb); }, WalPdb,
              "a PDB at the output's -wal name under another case");
      fs::remove(WalPdb, Error);
    }
#endif
    // a hard link of the input as the output is the input
    fs::create_hard_link(Fake.Input, Dir / "linked.sqlite", Error);
    if (!Error) {
      Message = Refused([&](IngestArgs& A) { A.Output = PathToUtf8(Dir / "linked.sqlite"); }, Fake.Input, "hard link");
      CHECK(Contains(Message, "the output is the input"));
      fs::remove(Dir / "linked.sqlite", Error);
    }
    // control: a name that only looks similar is accepted (and runs the fake export)
    {
      ClearRecord(Fake);
      const fs::path Input = Place("out.sqlite-walrus.dll", Fake.Input);
      IngestArgs Args;
      Args.Input = PathToUtf8(Input);
      Args.Output = PathToUtf8(Out);
      Args.Tools = FakeOptions(Fake);
      SetEnv("DSIG_TEST_CHILD_MODE", "fake-export");
      SetEnv("DSIG_TEST_CHILD_RECORD", PathToUtf8(Fake.Record));
      CHECK_NUM_EQ(RunIngest(Args).ExitCode, kExitOk);
      SetEnv("DSIG_TEST_CHILD_MODE", std::nullopt);
      SetEnv("DSIG_TEST_CHILD_RECORD", std::nullopt);
      fs::remove(Input, Error);
      fs::remove(Out, Error);
      fs::remove(SidecarPathFor(Out), Error);
    }
  }

  // all at once: every missing tool is named in one message
  Outcome = Ingest([&](IngestArgs& A) {
    A.Tools.Python = PathToUtf8(Nowhere / "python");
    A.Tools.IdaDir = PathToUtf8(Nowhere);
    A.Tools.DiaphoraDir = PathToUtf8(Nowhere);
  });
  CHECK_NUM_EQ(Outcome.ExitCode, kExitUnsupported);
  CHECK(Contains(Outcome.Message, "Python not found") && Contains(Outcome.Message, "IDA not found") &&
        Contains(Outcome.Message, "Diaphora not found"));

  Outcome = Ingest([&](IngestArgs& A) { A.Input = PathToUtf8(Nowhere / "a.dll"); });
  CHECK_NUM_EQ(Outcome.ExitCode, kExitIo);
  CHECK(Contains(Outcome.Message, "input not found"));
  Outcome = Ingest([&](IngestArgs& A) { A.Input = PathToUtf8(Fake.Database); });
  CHECK_NUM_EQ(Outcome.ExitCode, kExitUsage);
  CHECK(Contains(Outcome.Message, "use 'dsigmatcher extract'"));
  Outcome = Extract([&](ExtractArgs& A) { A.Input = PathToUtf8(Fake.Input); });
  CHECK_NUM_EQ(Outcome.ExitCode, kExitUsage);
  CHECK(Contains(Outcome.Message, "expects an IDA database"));
  Outcome = Ingest([&](IngestArgs& A) { A.Output = PathToUtf8(Fake.Root / "out.i64"); });
  CHECK_NUM_EQ(Outcome.ExitCode, kExitUsage);
  CHECK(Contains(Outcome.Message, "IDA extension"));
  Outcome = Ingest([&](IngestArgs& A) { A.Output = A.Input; });
  CHECK_NUM_EQ(Outcome.ExitCode, kExitUsage);
  CHECK(Contains(Outcome.Message, "the output is the input"));
  Outcome = Ingest([&](IngestArgs& A) { A.Output = PathToUtf8(Fake.Root); });
  CHECK_NUM_EQ(Outcome.ExitCode, kExitUsage);
  CHECK(Contains(Outcome.Message, "the output is a directory"));
  Outcome = Ingest([&](IngestArgs& A) { A.Output = PathToUtf8(Nowhere / "out.sqlite"); });
  CHECK_NUM_EQ(Outcome.ExitCode, kExitIo);
  CHECK(Contains(Outcome.Message, "output directory does not exist"));
  Outcome = Ingest([&](IngestArgs& A) { A.Pdb = PathToUtf8(Nowhere / "a.pdb"); });
  CHECK_NUM_EQ(Outcome.ExitCode, kExitIo);
  CHECK(Contains(Outcome.Message, "PDB not found"));
  Outcome = Ingest([&](IngestArgs& A) {
    A.Pdb = PathToUtf8(Fake.Pdb);
    A.NoPdb = true;
  });
  CHECK_NUM_EQ(Outcome.ExitCode, kExitUsage);
  CHECK(Contains(Outcome.Message, "exclusive"));
  Outcome = Ingest([&](IngestArgs& A) { A.Tools.TempDir = PathToUtf8(Nowhere); });
  CHECK_NUM_EQ(Outcome.ExitCode, kExitIo);
  CHECK(Contains(Outcome.Message, "--temp-dir does not exist"));
  Outcome = Ingest([&](IngestArgs& A) { A.Input.clear(); });
  CHECK_NUM_EQ(Outcome.ExitCode, kExitUsage);
  Outcome = Extract([&](ExtractArgs& A) { A.Output.clear(); });
  CHECK_NUM_EQ(Outcome.ExitCode, kExitUsage);
  CHECK(!fs::exists(Fake.Output));  // nothing was launched by any of the above
}

// F45 and F57 c: a release binary finds dsig_export.py only beside itself or in share/, never in an
// ancestor's tools/export/; the error lists the places it looked.
void TestScriptDiscovery(const std::string& Scratch) {
  Test::Suite("export script discovery (F45, F57 c)");
  const fs::path Exe = PathFromUtf8("some prefix") / "bin" / "dsigmatcher";
  const std::vector<fs::path> Candidates = ExportScriptCandidates(Exe);
  CHECK_NUM_EQ(Candidates.size(), 3);
  if (Candidates.size() == 3) {
    CHECK(Candidates[0] == Exe.parent_path() / "dsig_export.py");
    CHECK(Candidates[1] == Exe.parent_path() / "share" / "dsigmatcher" / "tools" / "export" / "dsig_export.py");
    CHECK(Candidates[2] == PathFromUtf8("some prefix") / "share" / "dsigmatcher" / "tools" / "export" / "dsig_export.py");
  }
  CHECK(ExportScriptCandidates(fs::path()).empty());

  // The audit's repro: the executable deep below a directory holding a planted tools/export/dsig_export.py.
  const fs::path Deep = PathFromUtf8(Scratch) / "deep";
  const fs::path Bin = Deep / "x" / "y" / "bin";
  std::error_code Error;
  fs::create_directories(Bin, Error);
  const fs::path Self = SelfExecutablePath();
  const fs::path Copy = Bin / Self.filename();
  fs::copy_file(Self, Copy, fs::copy_options::overwrite_existing, Error);
  CHECK(!Error);
  for (const fs::path& Ancestor : {Deep, Deep / "x", Deep / "x" / "y", Bin}) {
    fs::create_directories(Ancestor / "tools" / "export", Error);
    WriteFile(Ancestor / "tools" / "export" / "dsig_export.py", "print('PLANTED SCRIPT RAN')\n");
  }
  const std::vector<std::pair<std::string, std::string>> Child = {{"DSIG_TEST_CHILD_MODE", "find-script"},
                                                                  {"DSIG_EXPORT_SCRIPT", ""}};
  ProcessResult Run = RunProcess({PathToUtf8(Copy)}, Child, 60, nullptr);
  CHECK(Run.Started && Run.ExitCode == 0);
  CHECK(!Contains(Run.Tail, "SCRIPT "));
  CHECK(Contains(Run.Tail, "ERROR export script not found: no dsig_export.py at '" + PathToUtf8(Bin / "dsig_export.py")));
  CHECK(Contains(Run.Tail, PathToUtf8(Bin.parent_path() / "share" / "dsigmatcher" / "tools" / "export" / "dsig_export.py")));
  CHECK(Contains(Run.Tail, "(pass --export-script <path> or set DSIG_EXPORT_SCRIPT)"));
  // The install layout is still found: <prefix>/share/dsigmatcher/tools/export beside bin/.
  const fs::path Shared = Bin.parent_path() / "share" / "dsigmatcher" / "tools" / "export" / "dsig_export.py";
  fs::create_directories(Shared.parent_path(), Error);
  WriteFile(Shared, "# the installed script\n");
  Run = RunProcess({PathToUtf8(Copy)}, Child, 60, nullptr);
  CHECK(Contains(Run.Tail, "SCRIPT " + Hex(PathToUtf8(Shared))));
  // And beside the executable wins.
  WriteFile(Bin / "dsig_export.py", "# beside\n");
  Run = RunProcess({PathToUtf8(Copy)}, Child, 60, nullptr);
  CHECK(Contains(Run.Tail, "SCRIPT " + Hex(PathToUtf8(Bin / "dsig_export.py"))));
}

// No Windows dialogs, ever: with the error mode cleared to 0 first (what cmd.exe and ctest leave), the
// bridge runs a stand-in worker that loads a deliberately broken idalib.dll, the moment a real run would
// raise a modal "Bad Image" dialog. The run must end on its own, well within its timeout, with exit 4
// and the worker's error line; the worker must have inherited the no-dialog mode.
void TestBrokenIdalibNoDialog(const std::string& Scratch) {
#ifndef _WIN32
  (void)Scratch;
  Test::Skip("broken idalib.dll: no dialog", "Windows only: POSIX has no hard-error dialogs");
#else
  Test::Suite("broken idalib.dll with the error mode cleared: exit 4, no dialog");
  const FakeTools Fake = MakeFakeTools(Scratch);
  ClearRecord(Fake);
  WriteFile(Fake.IdaDir / "idalib.dll", "this is not a PE image");  // STATUS_INVALID_IMAGE_NOT_MZ on load
  const UINT SavedMode = GetErrorMode();
  SetErrorMode(0);
  SetEnv("DSIG_TEST_CHILD_MODE", "bad-idalib");
  SetEnv("DSIG_TEST_CHILD_RECORD", PathToUtf8(Fake.Record));
  SetEnv("DSIG_TEST_KEEP_ERROR_MODE", "1");
  IngestArgs Args;
  Args.Input = PathToUtf8(Fake.Input);
  Args.Output = PathToUtf8(Fake.Output);
  Args.Tools = FakeOptions(Fake);
  Args.Tools.TimeoutSeconds = 60;  // a dialog would hold the run until the backstop (180 s) kills it
  const auto Begin = std::chrono::steady_clock::now();
  const CommandOutcome Outcome = RunIngest(Args);
  const auto Seconds =
      std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - Begin).count();
  CHECK_NUM_EQ(GetErrorMode(), 0u);  // the bridge restores the caller's own mode
  SetErrorMode(SavedMode);
  SetEnv("DSIG_TEST_CHILD_MODE", std::nullopt);
  SetEnv("DSIG_TEST_CHILD_RECORD", std::nullopt);
  SetEnv("DSIG_TEST_KEEP_ERROR_MODE", std::nullopt);
  CHECK_NUM_EQ(Outcome.ExitCode, kExitUnsupported);
  CHECK(Contains(Outcome.Message, "IDA not found or not usable (dsig_export.py exit 11)"));
  CHECK(Contains(Outcome.Message, "IDA not usable: cannot load"));
  CHECK(!Contains(Outcome.Message, "timeout"));
  CHECK(Seconds < 60);
  CHECK(!fs::exists(Fake.Output));
  unsigned ChildMode = 0;
  bool Loaded = true;
  for (const std::string& Line : SplitLines(ReadFile(Fake.Record))) {
    if (Line.rfind("ERRORMODE ", 0) == 0) {
      ChildMode = static_cast<unsigned>(std::strtoul(Line.c_str() + 10, nullptr, 10));
    } else if (Line.rfind("LOADED ", 0) == 0) {
      Loaded = Line != "LOADED 0";
    }
  }
  CHECK_NUM_EQ(ChildMode & kNoErrorDialogs, kNoErrorDialogs);
  CHECK(!Loaded);
  if (Outcome.ExitCode != kExitUnsupported) {
    Test::Note("message: " + Outcome.Message);
  }
#endif
}

// With a real Python: dsig_export.py's selftest (the script-side regressions) and the real script under
// a PYTHONPATH whose sitecustomize kills any interpreter that loads it (F66).
void TestWithRealPython(const std::string& Scratch, const std::optional<std::string>& PythonHint) {
  const Located Python = FindPython(PythonHint.value_or(std::string()));
  const fs::path Tools = PathFromUtf8(Test::TestDataDir()).parent_path().parent_path() / "tools" / "export";
  if (!Python.Ok() || Python.Path.empty()) {
    Test::Skip("dsig_export.py with a real Python", "no Python (set DSIG_PYTHON or put python on PATH)");
    return;
  }
  if (Test::TestDataDir().empty() || !fs::is_regular_file(Tools / "dsig_export.py")) {
    Test::Skip("dsig_export.py with a real Python", "the source tree's tools/export is not available");
    return;
  }
  Test::Suite("dsig_export.py selftest with a real Python");
  const ProcessResult Selftest =
      RunProcess({PathToUtf8(Python.Path), "-B", PathToUtf8(Tools / "selftest_dsig_export.py")}, {}, 900, nullptr);
  CHECK(Selftest.Started);
  CHECK_NUM_EQ(Selftest.ExitCode, 0);
  CHECK(Contains(Selftest.Tail, " checks, 0 failed"));
  if (Selftest.ExitCode != 0) {
    const size_t Keep = 4000;
    Test::Note(Selftest.Tail.size() > Keep ? Selftest.Tail.substr(Selftest.Tail.size() - Keep) : Selftest.Tail);
  }
  // tools/e2e/selftest_e2e.py: its scoring cases, and git never taken from the current directory in
  // e2e_common.py and tools/oracle/build_oracle.py (F16).
  const fs::path E2e = Tools.parent_path() / "e2e" / "selftest_e2e.py";
  if (fs::is_regular_file(E2e)) {
    Test::Suite("tools/e2e selftest with a real Python (F16: git lookup in e2e_common and build_oracle)");
    const ProcessResult E2eRun = RunProcess({PathToUtf8(Python.Path), "-B", PathToUtf8(E2e)}, {}, 300, nullptr);
    CHECK(E2eRun.Started);
    CHECK_NUM_EQ(E2eRun.ExitCode, 0);
    CHECK(Contains(E2eRun.Tail, "selftest_e2e: PASSED"));
    if (E2eRun.ExitCode != 0) {
      Test::Note(E2eRun.Tail);
    }
  }

  Test::Suite("the real dsig_export.py ignores the caller's PYTHONPATH (F66)");
  const FakeTools Fake = MakeFakeTools(Scratch);
  const fs::path Poison = Fake.Root / "poison path";
  std::error_code Error;
  fs::create_directories(Poison, Error);
  WriteFile(Poison / "sitecustomize.py", "import os\nos._exit(42)\n");
  const std::optional<std::string> Saved = GetEnvUtf8("PYTHONPATH");
  const std::optional<std::string> SavedIdaUsr = GetEnvUtf8("IDAUSR");
  fs::create_directories(Fake.Root / "empty idausr", Error);
  SetEnv("IDAUSR", PathToUtf8(Fake.Root / "empty idausr"));  // the user's IDA directory is not read
  SetEnv("PYTHONPATH", PathToUtf8(Poison));
#ifdef _WIN32
  // As under cmd.exe and ctest: critical-error dialogs on. The worker's idapro then loads the
  // placeholder idalib; that must fail, not block the run behind a modal "Bad Image" dialog.
  const UINT SavedMode = GetErrorMode();
  SetErrorMode(0);
#endif
  IngestArgs Args;
  Args.Input = PathToUtf8(Fake.Input);
  Args.Output = PathToUtf8(Fake.Output);
  Args.NoPdb = true;
  Args.Tools.Python = PathToUtf8(Python.Path);
  Args.Tools.ExportScript = PathToUtf8(Tools / "dsig_export.py");
  Args.Tools.IdaDir = PathToUtf8(Fake.IdaDir);  // a placeholder idalib: the worker stops at "IDA not usable"
  Args.Tools.DiaphoraDir = PathToUtf8(Fake.DiaphoraDir);
  Args.Tools.TempDir = PathToUtf8(Fake.TempDir);
  Args.Tools.TimeoutSeconds = 180;  // a regression fails the suite instead of hanging it
  const CommandOutcome Outcome = RunIngest(Args);
#ifdef _WIN32
  SetErrorMode(SavedMode);
#endif
  SetEnv("PYTHONPATH", Saved);
  SetEnv("IDAUSR", SavedIdaUsr);
  CHECK(!Contains(Outcome.Message, "exit 42"));
  CHECK_NUM_EQ(Outcome.ExitCode, kExitUnsupported);
  CHECK(Contains(Outcome.Message, "IDA not found or not usable (dsig_export.py exit 11)"));
  CHECK(!fs::exists(Fake.Output));
  if (Outcome.ExitCode != kExitUnsupported) {
    Test::Note("message: " + Outcome.Message);
  }
  // The killed-or-finished run left no work directory behind.
  bool Leftover = false;
  for (const auto& Entry : fs::directory_iterator(Fake.TempDir, Error)) {
    Leftover = Leftover || PathToUtf8(Entry.path().filename()).rfind("dsig-export-", 0) == 0;
  }
  CHECK(!Leftover);
}

// ------------------------------------------------------------------------------------------------ real exports

struct Db {
  sqlite3* Handle = nullptr;
  ~Db() {
    if (Handle != nullptr) {
      sqlite3_close(Handle);
    }
  }
};

// immutable=1: never creates or touches -wal/-shm, so the oracle directory is only read.
bool OpenImmutable(const fs::path& Path, Db& Out) {
  const std::string Uri = Diff::DiffDatabase::UriForPath(PathToUtf8(Path), true) + "&immutable=1";
  return sqlite3_open_v2(Uri.c_str(), &Out.Handle, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, nullptr) == SQLITE_OK;
}

std::vector<std::string> QueryColumn(sqlite3* Handle, const std::string& Sql, int Column) {
  std::vector<std::string> Values;
  sqlite3_stmt* Statement = nullptr;
  if (sqlite3_prepare_v2(Handle, Sql.c_str(), -1, &Statement, nullptr) != SQLITE_OK) {
    return Values;
  }
  while (sqlite3_step(Statement) == SQLITE_ROW) {
    const unsigned char* Text = sqlite3_column_text(Statement, Column);
    Values.emplace_back(Text != nullptr ? reinterpret_cast<const char*>(Text) : "");
  }
  sqlite3_finalize(Statement);
  return Values;
}

bool SameValue(sqlite3_stmt* A, sqlite3_stmt* B, int Column) {
  const int Type = sqlite3_column_type(A, Column);
  if (Type != sqlite3_column_type(B, Column)) {
    return false;
  }
  switch (Type) {
    case SQLITE_NULL:
      return true;
    case SQLITE_INTEGER:
      return sqlite3_column_int64(A, Column) == sqlite3_column_int64(B, Column);
    case SQLITE_FLOAT: {
      const double X = sqlite3_column_double(A, Column);
      const double Y = sqlite3_column_double(B, Column);
      return std::memcmp(&X, &Y, sizeof(X)) == 0;
    }
    default: {
      const void* X = Type == SQLITE_TEXT ? static_cast<const void*>(sqlite3_column_text(A, Column))
                                          : sqlite3_column_blob(A, Column);
      const void* Y = Type == SQLITE_TEXT ? static_cast<const void*>(sqlite3_column_text(B, Column))
                                          : sqlite3_column_blob(B, Column);
      const int Size = sqlite3_column_bytes(A, Column);
      return Size == sqlite3_column_bytes(B, Column) && (Size == 0 || std::memcmp(X, Y, static_cast<size_t>(Size)) == 0);
    }
  }
}

// tools/oracle/compare_exports.py, natively and stricter (storage classes must match too).
void CheckExportsIdentical(const std::string& Label, const fs::path& Oracle, const fs::path& Mine) {
  Db A;
  Db B;
  CHECK(OpenImmutable(Oracle, A));
  CHECK(OpenImmutable(Mine, B));
  if (A.Handle == nullptr || B.Handle == nullptr) {
    return;
  }
  const std::string TablesSql =
      "select name from sqlite_master where type='table' and name not like 'sqlite_%' order by name";
  const std::vector<std::string> Tables = QueryColumn(A.Handle, TablesSql, 0);
  CHECK(!Tables.empty());
  CHECK(Tables == QueryColumn(B.Handle, TablesSql, 0));
  for (const std::string& Table : Tables) {
    const std::string Info = "pragma table_info('" + Table + "')";
    const std::vector<std::string> Columns = QueryColumn(A.Handle, Info, 1);
    const bool SameColumns = Columns == QueryColumn(B.Handle, Info, 1);
    CHECK(SameColumns);
    std::string Select;
    for (const std::string& Column : Columns) {
      if (Table == "functions" && Column == "export_time") {
        continue;  // wall clock (compare_exports.py VOLATILE)
      }
      Select += (Select.empty() ? "\"" : ", \"") + Column + "\"";
    }
    const std::string Sql = "select " + Select + " from '" + Table + "' order by rowid";
    sqlite3_stmt* SA = nullptr;
    sqlite3_stmt* SB = nullptr;
    const bool Prepared = sqlite3_prepare_v2(A.Handle, Sql.c_str(), -1, &SA, nullptr) == SQLITE_OK &&
                          sqlite3_prepare_v2(B.Handle, Sql.c_str(), -1, &SB, nullptr) == SQLITE_OK;
    CHECK(Prepared);
    long long Rows = 0;
    std::string FirstDifference;
    while (Prepared) {
      const int RA = sqlite3_step(SA);
      const int RB = sqlite3_step(SB);
      if (RA != RB) {
        FirstDifference = "row count differs after " + std::to_string(Rows) + " rows";
        break;
      }
      if (RA != SQLITE_ROW) {
        break;
      }
      for (int Column = 0; Column < sqlite3_column_count(SA); ++Column) {
        if (!SameValue(SA, SB, Column)) {
          FirstDifference = "row " + std::to_string(Rows) + " column " + sqlite3_column_name(SA, Column);
          break;
        }
      }
      if (!FirstDifference.empty()) {
        break;
      }
      ++Rows;
    }
    sqlite3_finalize(SA);
    sqlite3_finalize(SB);
    CHECK(FirstDifference.empty());
    Test::Note(Label + ": " + Table + (FirstDifference.empty() ? " identical (" + std::to_string(Rows) + " rows)"
                                                             : " DIFFERENT: " + FirstDifference));
  }
}

struct RealConfig {
  bool Enabled = false;
  std::string Why;
  ExportToolOptions Tools;
  fs::path Corpus;
};

RealConfig ReadRealConfig() {
  RealConfig Config;
  const auto Gate = GetEnvUtf8("DSIG_EXPORT_TESTS");
  if (!Gate || *Gate == "0") {
    Config.Why = "set DSIG_EXPORT_TESTS=1 (with DSIG_IDADIR, DSIG_DIAPHORA_DIR, DSIG_PYTHON or python on PATH) "
                 "to run real IDA exports";
    return Config;
  }
  const auto IdaDir = GetEnvUtf8("DSIG_IDADIR");
  const auto DiaphoraDir = GetEnvUtf8("DSIG_DIAPHORA_DIR");
  const auto Corpus = Test::CorpusRoot();
  if (!IdaDir || !DiaphoraDir) {
    Config.Why = "DSIG_IDADIR and DSIG_DIAPHORA_DIR are required";
    return Config;
  }
  if (!Corpus) {
    Config.Why = "no DSIG_CORPUS_ROOT";
    return Config;
  }
  Config.Tools.Python = GetEnvUtf8("DSIG_PYTHON").value_or(std::string());
  Config.Tools.IdaDir = *IdaDir;
  Config.Tools.DiaphoraDir = *DiaphoraDir;
  if (const auto Script = GetEnvUtf8("DSIG_EXPORT_SCRIPT")) {
    Config.Tools.ExportScript = *Script;
  } else if (!Test::TestDataDir().empty()) {
    Config.Tools.ExportScript =
        PathToUtf8(PathFromUtf8(Test::TestDataDir()).parent_path().parent_path() / "tools" / "export" / "dsig_export.py");
  }
  Config.Corpus = PathFromUtf8(*Corpus);
  Config.Enabled = true;
  return Config;
}

void ClearToolEnvironment() {
  for (const char* Name : {"DSIG_PYTHON", "DSIG_IDADIR", "DSIG_DIAPHORA_DIR", "DSIG_EXPORT_SCRIPT", "DSIG_TEST_CHILD_MODE",
                           "DSIG_TEST_CHILD_EXIT", "DSIG_TEST_CHILD_RECORD", "DSIG_TEST_KEEP_ERROR_MODE",
                           "DSIG_EXPORT_ALLOW_NO_DECOMPILER"}) {
    SetEnv(Name, std::nullopt);
  }
}

std::optional<Diff::JsonValue> ReadSidecar(const fs::path& Output) {
  try {
    return Diff::JsonParse(ReadFile(SidecarPathFor(Output)));
  } catch (const Diff::JsonError&) {
    return std::nullopt;
  }
}

void TestRealExports(const RealConfig& Config, const std::string& Scratch) {
  if (!Config.Enabled) {
    Test::Skip("real IDA exports", Config.Why);
    return;
  }
  const fs::path Oracle = Config.Corpus / "oracle";
  const fs::path OutDir = PathFromUtf8(Scratch) / "real";
  std::error_code Error;
  fs::create_directories(OutDir, Error);

  // (3) ingest --pdb of cryptbase 10.0.26100.8875 == oracle cryptbase-8875-pdb
  {
    const fs::path Binary = Oracle / "bin" / "cryptbase_100261008875" / "cryptbase.dll";
    const fs::path Pdb = Oracle / "bin" / "cryptbase_100261008875" / "cryptbase.pdb";
    const fs::path Expected = Oracle / "exports" / "cryptbase-8875-pdb" / "cryptbase-8875-pdb.sqlite";
    if (!fs::is_regular_file(Binary, Error) || !fs::is_regular_file(Pdb, Error) ||
        !fs::is_regular_file(Expected, Error)) {
      Test::Skip("ingest --pdb cryptbase 8875", "corpus files missing");
    } else {
      Test::Suite("ingest --pdb cryptbase 8875 == oracle cryptbase-8875-pdb");
      IngestArgs Args;
      Args.Input = PathToUtf8(Binary);
      Args.Pdb = PathToUtf8(Pdb);
      Args.Output = PathToUtf8(OutDir / "cryptbase-8875-pdb.sqlite");
      Args.Tools = Config.Tools;
      const CommandOutcome Outcome = RunIngest(Args);
      CHECK_NUM_EQ(Outcome.ExitCode, kExitOk);
      if (Outcome.ExitCode != kExitOk) {
        Test::Note("message: " + Outcome.Message);
      } else {
        CheckExportsIdentical("cryptbase-8875-pdb", Expected, PathFromUtf8(Args.Output));
        const auto Sidecar = ReadSidecar(PathFromUtf8(Args.Output));
        CHECK(Sidecar.has_value());
        if (Sidecar) {
          CHECK_TEXT_EQ(JsonText(*Sidecar, {"pdb", "applied"}), "true");
          CHECK_TEXT_EQ(JsonText(*Sidecar, {"counts", "functions"}), "43");
          CHECK_TEXT_EQ(JsonText(*Sidecar, {"diaphora", "options", "ida_subs"}), "true");
        }
      }
    }
  }

  // (2) ingest --no-pdb of win32u 10.0.26100.9444 == oracle win32u-9444-nopdb
  {
    const fs::path Binary = Oracle / "bin" / "win32u_100261009444" / "win32u.dll";
    const fs::path Expected = Oracle / "exports" / "win32u-9444-nopdb" / "win32u-9444-nopdb.sqlite";
    if (!fs::is_regular_file(Binary, Error) || !fs::is_regular_file(Expected, Error)) {
      Test::Skip("ingest --no-pdb win32u 9444", "corpus files missing");
    } else {
      Test::Suite("ingest --no-pdb win32u 9444 == oracle win32u-9444-nopdb");
      IngestArgs Args;
      Args.Input = PathToUtf8(Binary);
      Args.NoPdb = true;
      Args.Output = PathToUtf8(OutDir / "win32u-9444-nopdb.sqlite");
      Args.Tools = Config.Tools;
      const CommandOutcome Outcome = RunIngest(Args);
      CHECK_NUM_EQ(Outcome.ExitCode, kExitOk);
      if (Outcome.ExitCode != kExitOk) {
        Test::Note("message: " + Outcome.Message);
      } else {
        CheckExportsIdentical("win32u-9444-nopdb", Expected, PathFromUtf8(Args.Output));
        const auto Sidecar = ReadSidecar(PathFromUtf8(Args.Output));
        CHECK(Sidecar.has_value());
        if (Sidecar) {
          CHECK_TEXT_EQ(JsonText(*Sidecar, {"pdb", "applied"}), "false");
          CHECK_TEXT_EQ(JsonText(*Sidecar, {"pdb", "log_lines"}), "0");
          CHECK_TEXT_EQ(JsonText(*Sidecar, {"counts", "functions"}), "1512");
        }
      }
    }
  }

  // (1) extract of a COPY of the user's hand-saved win32u .i64 == oracle win32u-9168-useri64
  {
    const fs::path UserDatabase = Config.Corpus / "win32u" / "win32u_100261009168" / "win32u.dll.i64";
    const fs::path Expected = Oracle / "exports" / "win32u-9168-useri64" / "win32u-9168-useri64.sqlite";
    if (!fs::is_regular_file(UserDatabase, Error) || !fs::is_regular_file(Expected, Error)) {
      Test::Skip("extract win32u user .i64", "corpus files missing");
    } else {
      Test::Suite("extract (copy of the user's) win32u.dll.i64 == oracle win32u-9168-useri64");
      // The test never hands the user's file to anything: it copies it (the bridge copies again).
      const fs::path Copy = OutDir / "win32u.dll.i64";
      fs::copy_file(UserDatabase, Copy, fs::copy_options::overwrite_existing, Error);
      CHECK(!Error);
      const auto CopySha = FileSha256(Copy);
      CHECK(CopySha.has_value() && CopySha == FileSha256(UserDatabase));
      ExtractArgs Args;
      Args.Input = PathToUtf8(Copy);
      Args.Output = PathToUtf8(OutDir / "win32u-9168-useri64.sqlite");
      Args.Tools = Config.Tools;
      const CommandOutcome Outcome = RunExtract(Args);
      CHECK_NUM_EQ(Outcome.ExitCode, kExitOk);
      CHECK(FileSha256(Copy) == CopySha);  // the extract input is byte-identical afterwards
      if (Outcome.ExitCode != kExitOk) {
        Test::Note("message: " + Outcome.Message);
      } else {
        CheckExportsIdentical("win32u-9168-useri64", Expected, PathFromUtf8(Args.Output));
        Db A;
        Db B;
        if (OpenImmutable(Expected, A) && OpenImmutable(PathFromUtf8(Args.Output), B)) {
          const std::vector<std::string> Names = QueryColumn(A.Handle, "select name from functions order by id", 0);
          CHECK_NUM_EQ(Names.size(), 1510);
          CHECK(Names == QueryColumn(B.Handle, "select name from functions order by id", 0));
        }
        const auto Sidecar = ReadSidecar(PathFromUtf8(Args.Output));
        CHECK(Sidecar.has_value());
        if (Sidecar) {
          CHECK_TEXT_EQ(JsonText(*Sidecar, {"mode"}), "idb");
          CHECK_TEXT_EQ(JsonText(*Sidecar, {"idb", "copy_unchanged"}), "true");
          CHECK_TEXT_EQ(JsonText(*Sidecar, {"idb", "saved"}), "false");
          CHECK_TEXT_EQ(JsonText(*Sidecar, {"input", "sha256"}), CopySha.value_or(""));
          CHECK_TEXT_EQ(JsonText(*Sidecar, {"counts", "functions"}), "1510");
          CHECK_TEXT_EQ(JsonText(*Sidecar, {"ida", "function_names", "total"}), "1516");
        }
      }
    }
  }
}

}  // namespace

int main(int Argc, char** Argv) {
  if (const auto Mode = GetEnvUtf8("DSIG_TEST_CHILD_MODE")) {
    return RunChild(*Mode, Argc, Argv);
  }
  // This executable plays the child processes. Started as a child without a mode (a test that forgot to
  // set one), it must not run the whole suite again, which would start itself again, and so on.
  if (GetEnvUtf8("DSIG_TEST_SUITE_ACTIVE")) {
    std::printf("cli_export_bridge started as a child without DSIG_TEST_CHILD_MODE\n");
    return 97;
  }
  SetEnv("DSIG_TEST_SUITE_ACTIVE", "1");
  const RealConfig Real = ReadRealConfig();  // before the tool variables are cleared for the unit tests
  const std::optional<std::string> PythonHint = GetEnvUtf8("DSIG_PYTHON");
  ClearToolEnvironment();
  const std::string Scratch = Test::ScratchDir("cli_export_bridge");

  TestQuoting();
  TestUtf8();
  TestSidecarName();
  TestExitMapping();
  TestToolErrorLine();
  TestSameFile(Scratch);
  TestRunProcess(Scratch);
  TestBatchRefusal(Scratch);
  TestProcessGroup(Scratch);
  TestFakeExports(Scratch);
  TestValidationAndMissingTools(Scratch);
  TestScriptDiscovery(Scratch);
  TestBrokenIdalibNoDialog(Scratch);
  TestWithRealPython(Scratch, PythonHint);
  TestRealExports(Real, Scratch);

  Test::RemoveScratchDir(Scratch);
  return Test::Finish();
}
