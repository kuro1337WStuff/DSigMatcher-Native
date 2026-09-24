#pragma once

// Product commands around the diff engine:
//
//   dsigmatcher extract <in.i64|in.idb> -o <out.sqlite>                         (src/cli/ExportBridge.cpp)
//   dsigmatcher ingest  <new.exe|dll>  -o <out.sqlite> [--pdb <file>|--no-pdb]  (src/cli/ExportBridge.cpp)
//   dsigmatcher port <ref.sqlite> <target.sqlite> -o <out.sqlite> [--results <x.diaphora>]
//                                                                               (src/cli/PortResults.cpp)
//   dsigmatcher update <labelled.sqlite> <new-binary> -o <new-labelled.sqlite>  (src/cli/Update.cpp)
//
// extract / ingest launch tools/export/dsig_export.py (IDA idalib + the unmodified Diaphora exporter).
// Tool discovery: the flags below, else DSIG_PYTHON / DSIG_IDADIR / DSIG_DIAPHORA_DIR / DSIG_EXPORT_SCRIPT;
// without either, dsig_export.py is looked for beside the executable, then in
// <prefix>/share/dsigmatcher/tools/export (<prefix>: the executable's directory or its parent).
// Every command returns a process exit code from the table below (the same for every command).

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "dsigmatcher/diff/Json.h"

namespace DSig::Cli {

inline constexpr int kExitOk = 0;
inline constexpr int kExitUsage = 2;           // bad arguments; an output that would overwrite an input
inline constexpr int kExitWouldRaise = 3;      // Diaphora itself would raise on this input (no output)
inline constexpr int kExitUnsupported = 4;     // unsupported input or configuration; a tool is missing
inline constexpr int kExitSqliteMismatch = 5;  // --strict-sqlite and SQLite is not the oracle's 3.51.1
inline constexpr int kExitIo = 6;              // a file cannot be read or written; environment failure
inline constexpr int kExitInternal = 70;       // internal error (EX_SOFTWARE): a bug, or out of memory

// The longest --timeout extract / ingest / update accept (30 days). The CLI checks the 64-bit value
// against it before narrowing to int, and dsig_export.py enforces the same cap (audit F42).
inline constexpr int kMaxExportTimeoutSeconds = 30 * 24 * 3600;

struct ExportToolOptions {
  std::string Python;       // --python      (else DSIG_PYTHON)
  std::string IdaDir;       // --ida-dir     (else DSIG_IDADIR)
  std::string DiaphoraDir;  // --diaphora-dir (else DSIG_DIAPHORA_DIR)
  std::string TempDir;      // --temp-dir    (else the system temp directory)
  bool KeepTemp = false;    // --keep-temp
  int TimeoutSeconds = 0;   // --timeout (0: none; at most kMaxExportTimeoutSeconds)
  std::string ExportScript; // --export-script (else DSIG_EXPORT_SCRIPT, else found relative to the
                            // executable)
  bool AllowNoDecompiler = false;  // --allow-no-decompiler: forwarded to dsig_export.py (audit F46)
  bool Quiet = false;       // --quiet: the script's progress is not streamed to stderr (its last error
                            // line still reaches the outcome's message)
};

// `extract`: export an existing IDA database, keeping the user's labels. The input .i64/.idb is always
// copied to a temp dir first (idalib repacks in place) and its sha256 is checked before and after.
struct ExtractArgs {
  std::string Input;        // .i64 / .idb
  std::string Output;       // -o <out.sqlite>
  ExportToolOptions Tools;
};

// `ingest`: analyse a raw binary headless and export it.
struct IngestArgs {
  std::string Input;        // .exe / .dll / ELF
  std::string Output;       // -o <out.sqlite>
  std::string Pdb;          // --pdb <file>
  bool NoPdb = false;       // --no-pdb
  ExportToolOptions Tools;
};

// `port`: apply match proposals to a copy of the target export. With Results, the rows of that
// .diaphora file (ours or Diaphora's); without, the parity diff runs in-process first and writes its
// results file to ResultsOutput (default: <output dir>/<output stem>.diaphora), which is kept unless
// KeepResults is false.
struct PortFromResultsArgs {
  std::string Reference;           // <ref.sqlite>
  std::string Target;              // <target.sqlite>
  std::string Output;              // -o <out.sqlite>
  std::string Results;             // --results <x.diaphora>; empty: run the parity diff in-process
  std::string ResultsOutput;       // in-process diff only: where the .diaphora goes (empty: the default)
  bool KeepResults = true;         // in-process diff only: false = --no-keep-results
  bool IncludeMultimatch = false;  // --include-multimatch
  bool IncludeUnreliable = false;  // --include-unreliable
  bool Overwrite = false;          // --overwrite-existing
  bool OverwriteStripped = false;  // --overwrite-stripped (with --overwrite-existing)
  double MinRatio = 0.0;           // --min-ratio
  int64_t MaxHops = -1;            // --max-hops
  bool StoreFullPaths = false;     // --store-full-paths
  bool StrictSqlite = false;       // --strict-sqlite (in-process diff only)
  bool AllowSqliteMismatch = false;  // --allow-sqlite-mismatch (in-process diff only)
  bool IgnoreSmallFunctions = false; // --ignore-small-functions (in-process diff only)
  bool Quiet = false;              // --quiet: no Diaphora summary lines from the in-process diff
};

struct CommandOutcome {
  int ExitCode = kExitOk;
  std::string Message;                // error or summary text for the CLI
  std::vector<std::string> Report;    // lines the CLI prints on success
  Diff::JsonValue Data;               // the outcome fields for --json (an object, or null)
};

CommandOutcome RunExtract(const ExtractArgs& Args);
CommandOutcome RunIngest(const IngestArgs& Args);
CommandOutcome RunPortFromResults(const PortFromResultsArgs& Args);

// Where plain `port` keeps the results of its in-process diff: <output dir>/<output stem>.diaphora.
std::string DefaultResultsPath(const std::string& Output);

// `update`: ingest the new binary, diff the labelled export against it, port the labels. The
// intermediate export (<output dir>/<output stem>.ingest.sqlite, with the ingest's .export.json
// sidecar) and the results file (<output dir>/<output stem>.diaphora) are kept beside the output.
// Stops at the first failing step and returns that step's exit code.
struct UpdateArgs {
  std::string Labelled;            // <labelled.sqlite>: the reference
  std::string Binary;              // <new-binary>
  std::string Output;              // -o <new-labelled.sqlite>
  std::string Pdb;                 // ingest --pdb
  bool NoPdb = false;              // ingest --no-pdb
  ExportToolOptions Tools;         // ingest tool options
  PortFromResultsArgs Port;        // port options (Reference, Target, Output, Results are set by update)
};

// The ingest step; tests replace it (IDA is not available to the unit suites).
using IngestRunner = std::function<CommandOutcome(const IngestArgs&)>;

std::string UpdateExportPath(const std::string& Output);
CommandOutcome RunUpdate(const UpdateArgs& Args, const IngestRunner& Ingest = RunIngest);

// Windows: adds SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX to this
// process's error mode, so neither dsigmatcher nor anything it starts (Python, IDA; the mode is
// inherited) can block a headless run behind a loader ("Bad Image"), crash or missing-file dialog.
// Elsewhere it does nothing. dsigmatcher's entry point calls it before anything else.
void DisableErrorDialogs();

// Runs a command. An exception that escapes it is a bug (or out of memory): stdout is flushed,
// "error: internal error: <what>" goes to stderr and the exit code is kExitInternal (70), never an
// abort with lost output.
int RunGuarded(const std::function<int()>& Body);

}
