// Suite cli_export_bridge: `dsigmatcher extract` / `ingest` (plan §7.1 D7, §7.2 lane L10).
//
// Three kinds of test:
//   * unit tests of the bridge's pieces: Windows argument quoting (round-tripped through
//     CommandLineToArgvW on Windows), UTF-8 handling, the sidecar name, the exit-code map;
//   * process tests that use THIS executable as the child (DSIG_TEST_CHILD_MODE = echo / sleep /
//     fake-export), so argument passing, output capture, timeouts, tool discovery, error messages and
//     the sidecar checks are exercised end to end without Python or IDA (ctest never needs either);
//   * real exports, gated on DSIG_EXPORT_TESTS=1 plus DSIG_IDADIR and DSIG_DIAPHORA_DIR (DSIG_PYTHON or a
//     python on PATH) and the corpus: ingest cryptbase 8875 with its PDB, ingest win32u 9444 without a
//     PDB, and extract a COPY of the user's win32u .i64. Each result must equal the oracle export table
//     for table (tools/oracle/compare_exports.py semantics: every table but sqlite_*, rowid order,
//     functions.export_time ignored). They skip cleanly when anything is missing.

#include <sqlite3.h>

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
#include <stdlib.h>
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

// Plays dsig_export.py: `<python> -B -u <script> <mode> <input> -o <output> --sidecar <json> ...`.
int ChildFakeExport(const std::vector<std::string>& Arguments) {
  if (const auto Record = GetEnvUtf8("DSIG_TEST_CHILD_RECORD")) {
    std::string Lines;
    for (const std::string& Argument : Arguments) {
      Lines += Hex(Argument) + "\n";
    }
    WriteFile(PathFromUtf8(*Record), Lines);
  }
  const int Exit = EnvInt("DSIG_TEST_CHILD_EXIT", 0);
  if (Exit != 0) {
    std::printf("[dsig_export] pretending to fail\ndsig_export: error: fake failure %d\n", Exit);
    return Exit;
  }
  if (Arguments.size() < 6) {
    return 99;
  }
  const fs::path Input = PathFromUtf8(Arguments[4]);
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
  std::string Json = "{\"schema\": \"dsig-export/1\", \"mode\": " + Diff::JsonQuote(Arguments[3]) +
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

// ------------------------------------------------------------------------------------------------ processes

void TestRunProcess() {
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
    const std::vector<std::string> Expected = {
        "-B", "-u", PathToUtf8(Fake.Script), "binary", PathToUtf8(Fake.Input), "-o", PathToUtf8(Fake.Output),
        "--sidecar", PathToUtf8(Fake.Root / PathFromUtf8("out \xC3\xBC.export.json")), "--ida-dir",
        PathToUtf8(Fake.IdaDir), "--diaphora-dir", PathToUtf8(Fake.DiaphoraDir), "--temp-dir",
        PathToUtf8(fs::absolute(PathFromUtf8(Args.Tools.TempDir)).lexically_normal()), "--keep-temp", "--timeout",
        "7", "--no-pdb"};
    const std::vector<std::string> Recorded = RecordedArguments(Fake);
    CHECK_NUM_EQ(Recorded.size(), Expected.size());
    for (size_t Index = 0; Index < Expected.size() && Index < Recorded.size(); ++Index) {
      CHECK_TEXT_EQ(Recorded[Index], Hex(Expected[Index]));
    }
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
    CHECK(Recorded.size() >= 5 && Recorded[3] == Hex("idb") && Recorded[4] == Hex(PathToUtf8(Fake.Database)));
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
    CHECK(Recorded.size() > 2 && Recorded[2] == Hex(PathToUtf8(Fake.Script)));
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
                           "DSIG_TEST_CHILD_EXIT", "DSIG_TEST_CHILD_RECORD"}) {
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
  const RealConfig Real = ReadRealConfig();  // before the tool variables are cleared for the unit tests
  ClearToolEnvironment();
  const std::string Scratch = Test::ScratchDir("cli_export_bridge");

  TestQuoting();
  TestUtf8();
  TestSidecarName();
  TestExitMapping();
  TestRunProcess();
  TestFakeExports(Scratch);
  TestValidationAndMissingTools(Scratch);
  TestRealExports(Real, Scratch);

  Test::RemoveScratchDir(Scratch);
  return Test::Finish();
}
