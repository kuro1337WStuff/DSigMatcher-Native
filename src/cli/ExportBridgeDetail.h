#pragma once

// Internals of the export bridge (`extract` / `ingest`, plan §7.1 D7, lane L10). The public API is
// DSig::Cli::RunExtract / RunIngest in include/dsigmatcher/cli/Commands.h; this header exists so that
// tests/cli/export_bridge_tests.cpp can check the pieces (argument quoting, process launch, discovery,
// exit-code mapping) on their own. Every string here is UTF-8.

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "dsigmatcher/cli/Commands.h"

namespace DSig::Cli::ExportBridge {

// Exit codes of tools/export/dsig_export.py (see its module docstring and tools/export/README.md).
inline constexpr int kToolOk = 0;
inline constexpr int kToolUsage = 2;
inline constexpr int kToolInput = 10;
inline constexpr int kToolIda = 11;
inline constexpr int kToolDiaphora = 12;
inline constexpr int kToolHexRays = 13;
inline constexpr int kToolPdb = 14;
inline constexpr int kToolOpen = 15;
inline constexpr int kToolExport = 16;
inline constexpr int kToolInputChanged = 17;
inline constexpr int kToolTimeout = 18;
inline constexpr int kToolOutput = 19;
inline constexpr int kToolInternal = 20;
inline constexpr int kToolInterrupted = 130;

// The longest --timeout the bridge accepts (30 days). dsig_export.py enforces the same cap: Python's
// subprocess wait cannot take much more than 2^32 ms on Windows, and the backstop (timeout + 120 s)
// must not wrap (audit F42).
inline constexpr int kMaxTimeoutSeconds = kMaxExportTimeoutSeconds;
// The backstop the bridge adds to --timeout before it kills the script's whole process tree.
inline constexpr int kBackstopGraceSeconds = 120;

// SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX: no loader ("Bad Image"),
// crash or missing-file dialog in this process or in any process it starts (the mode is inherited;
// RunProcess never passes CREATE_DEFAULT_ERROR_MODE).
// DSig::Cli::DisableErrorDialogs (Commands.h) adds it to this process's mode.
inline constexpr unsigned kNoErrorDialogs = 0x0001u | 0x0002u | 0x8000u;

struct ToolExit {
  int ExitCode;      // DSig::Cli::kExit*
  const char* What;  // one-line explanation
};
// Maps a dsig_export.py exit code to the CLI's exit code (Commands.h / plan §2.1).
ToolExit MapToolExit(int ToolExitCode);

bool IsValidUtf8(std::string_view Text);
// A path from UTF-8 text. On Windows, text that is not valid UTF-8 is read in the ANSI code page,
// which is what a narrow argv holds.
std::filesystem::path PathFromUtf8(std::string_view Text);
std::string PathToUtf8(const std::filesystem::path& Path);

// Quoting for CommandLineToArgvW and the Microsoft C runtime's argv parser: an argument that needs no
// quotes is kept; otherwise it is wrapped in quotes, a quote becomes \" and the backslashes before a
// quote (or before the closing quote) are doubled.
std::string QuoteWindowsArgument(std::string_view Argument);
std::string BuildWindowsCommandLine(const std::vector<std::string>& Arguments);

std::optional<std::string> GetEnvUtf8(const char* Name);  // unset and empty both give nullopt
std::filesystem::path SelfExecutablePath();                // empty when the platform cannot tell
// <output stem>.export.json, the rule of dsig_export.py DefaultSidecar (out.sqlite -> out.export.json).
std::filesystem::path SidecarPathFor(const std::filesystem::path& Output);
std::optional<std::string> FileSha256(const std::filesystem::path& Path);
// The last "dsig_export: error: ..." line (at the start of a line) in Tail, without the prefix; empty
// when there is none.
std::string ToolErrorLine(const std::string& Tail);

// True when A and B name one file: std::filesystem::equivalent when both exist (hard links, 8.3 short
// names, case variants), else the weakly canonical paths compared as the platform's file system
// compares names (case-insensitively on Windows and macOS).
bool SameFile(const std::filesystem::path& A, const std::filesystem::path& B);
// Every file an export run writes, replaces or renames aside must not be the input or the PDB (audit
// F02): the output, its -wal/-shm/-journal/-crash files, the sidecar, and the names that carry the
// script's pid (<output>.dsig-tmp-<pid>, <output><suffix>.dsig-old-<pid>, <sidecar>.tmp-<pid>).
// Protected holds (role, existing path) pairs. Returns a refusal message, or nullopt.
std::optional<std::string> WrittenPathAlias(const std::filesystem::path& Output, const std::filesystem::path& Sidecar,
                                            const std::vector<std::pair<std::string, std::filesystem::path>>& Protected);

// Why Path cannot be used as the Python interpreter, or empty when it can. Windows: a batch or script
// shim (.bat/.cmd/.btm, trailing dots and spaces ignored) or a readable file without an "MZ" header is
// refused, because CreateProcess hands such a file to cmd.exe, which re-parses the arguments ('&', '%';
// audit F15). A file that cannot be read (the Store's app-execution alias) is accepted only with an
// .exe or .com name. POSIX: always empty (posix_spawn with an argv involves no shell).
std::string InterpreterProblem(const std::filesystem::path& Path);

struct Located {
  std::filesystem::path Path;  // empty with an empty Error: not configured
  std::string Source;          // "--python", "DSIG_PYTHON", "PATH", ...
  std::string Error;           // a complete message when the tool is missing
  bool Ok() const { return Error.empty(); }
};
Located FindPython(const std::string& Flag);        // --python, DSIG_PYTHON, then PATH
Located FindExportScript(const std::string& Flag);  // --export-script, DSIG_EXPORT_SCRIPT, then beside the exe
// Where FindExportScript looks without a flag or DSIG_EXPORT_SCRIPT, in order: <exe dir>/dsig_export.py,
// <exe dir>/share/dsigmatcher/tools/export/, <exe dir>/../share/dsigmatcher/tools/export/. Never the
// executable's ancestors: a release binary in a deep directory would otherwise run whatever
// tools/export/dsig_export.py someone planted above it, such as <drive>/tools/export/ (audit F45).
std::vector<std::filesystem::path> ExportScriptCandidates(const std::filesystem::path& Executable);
Located FindIdaDir(const std::string& Flag);        // --ida-dir, DSIG_IDADIR; none: the tool discovers
Located FindDiaphoraDir(const std::string& Flag);   // --diaphora-dir, DSIG_DIAPHORA_DIR; required

struct ProcessResult {
  bool Started = false;
  std::string Error;      // why the process could not be started
  int ExitCode = -1;      // POSIX: 128 + signal when killed by a signal
  bool TimedOut = false;  // the timeout expired and the process (tree) was killed
  std::string Tail;       // the last 64 KiB of the merged stdout/stderr
};
// Runs Arguments[0] (a path, not searched) with Arguments[1..]. The child gets this process's
// environment plus Overrides, stdin from the null device, and one pipe for stdout and stderr, which is
// forwarded to Forward (when not null) as it arrives. TimeoutSeconds <= 0: none; any positive value is
// honoured in full (waits are chunked, nothing is narrowed to 32 bits).
//   Windows: CreateProcessW with a quoted UTF-16 command line in WorkingDirectory (when not empty),
//   only the pipe and the null device inherited, and a kill-on-close job object so the whole tree dies
//   on timeout or when this process exits. The child starts with SEM_FAILCRITICALERRORS and
//   SEM_NOOPENFILEERRORBOX added to the inherited error mode, so a failed DLL load in it fails instead of
//   blocking the run behind a modal "Bad Image" dialog.
//   POSIX: posix_spawn into a new process group, so a timeout (SIGTERM, then SIGKILL after 30 s) reaches
//   the script and its IDA worker together; SIGINT/SIGTERM/SIGHUP received meanwhile are forwarded to
//   that group; stragglers in the group are killed once the script has exited (audit F44).
//   WorkingDirectory is not applied on POSIX, where the current directory is never searched for
//   programs.
ProcessResult RunProcess(const std::vector<std::string>& Arguments,
                         const std::vector<std::pair<std::string, std::string>>& Overrides, int64_t TimeoutSeconds,
                         std::FILE* Forward, const std::filesystem::path& WorkingDirectory = {});

}
