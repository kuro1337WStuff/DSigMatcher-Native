#pragma once

// Internals of the export bridge (`extract` / `ingest`, plan §7.1 D7, lane L10). The public API is
// DSig::Cli::RunExtract / RunIngest in include/dsigmatcher/cli/Commands.h; this header exists so that
// tests/cli/export_bridge_tests.cpp can check the pieces (argument quoting, process launch, discovery,
// exit-code mapping) on their own. Every string here is UTF-8.

#include <cstdio>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

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

struct Located {
  std::filesystem::path Path;  // empty with an empty Error: not configured
  std::string Source;          // "--python", "DSIG_PYTHON", "PATH", ...
  std::string Error;           // a complete message when the tool is missing
  bool Ok() const { return Error.empty(); }
};
Located FindPython(const std::string& Flag);        // --python, DSIG_PYTHON, then PATH
Located FindExportScript(const std::string& Flag);  // --export-script, DSIG_EXPORT_SCRIPT, then beside the exe
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
// forwarded to Forward (when not null) as it arrives. Windows: CreateProcessW with a quoted UTF-16
// command line, only the pipe and the null device inherited, and a kill-on-close job object so the
// whole tree dies on timeout or when this process exits. POSIX: posix_spawn. TimeoutSeconds 0: none.
ProcessResult RunProcess(const std::vector<std::string>& Arguments,
                         const std::vector<std::pair<std::string, std::string>>& Overrides, int TimeoutSeconds,
                         std::FILE* Forward);

}
