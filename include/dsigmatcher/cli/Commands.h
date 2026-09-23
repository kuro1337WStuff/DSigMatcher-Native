#pragma once

// Product commands around the diff engine (docs/parity/00-plan.md §7.1 D6/D7, §7.2):
//
//   dsigmatcher extract <in.i64|in.idb> -o <out.sqlite>                     (L10, src/cli/ExportBridge.cpp)
//   dsigmatcher ingest  <new.exe|dll>  -o <out.sqlite> [--pdb <file>|--no-pdb]  (L10)
//   dsigmatcher port <ref.sqlite> <target.sqlite> -o <out.sqlite> --results <x.diaphora>  (L11,
//                                                                        src/cli/PortResults.cpp)
//
// extract / ingest launch tools/export/dsig_export.py (IDA idalib + the unmodified Diaphora exporter).
// Tool discovery: the flags below, else DSIG_PYTHON / DSIG_IDADIR / DSIG_DIAPHORA_DIR.
// Every command returns a process exit code with the §2.1 meanings.

#include <cstdint>
#include <string>
#include <vector>

namespace DSig::Cli {

inline constexpr int kExitOk = 0;
inline constexpr int kExitUsage = 2;
inline constexpr int kExitWouldRaise = 3;
inline constexpr int kExitUnsupported = 4;  // also "not implemented"
inline constexpr int kExitSqliteMismatch = 5;
inline constexpr int kExitIo = 6;

struct ExportToolOptions {
  std::string Python;       // --python      (else DSIG_PYTHON)
  std::string IdaDir;       // --ida-dir     (else DSIG_IDADIR)
  std::string DiaphoraDir;  // --diaphora-dir (else DSIG_DIAPHORA_DIR)
  std::string TempDir;      // --temp-dir    (else the system temp directory)
  bool KeepTemp = false;    // --keep-temp
  int TimeoutSeconds = 0;   // --timeout (0: none)
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

// `port --results`: apply a .diaphora results file (ours or Diaphora's) to the target export.
struct PortFromResultsArgs {
  std::string Reference;           // <ref.sqlite>
  std::string Target;              // <target.sqlite>
  std::string Output;              // -o <out.sqlite>
  std::string Results;             // --results <x.diaphora>; empty: run the parity diff in-process (L9)
  bool IncludeMultimatch = false;  // --include-multimatch
  bool IncludeUnreliable = false;  // --include-unreliable
  bool Overwrite = false;          // --overwrite / --overwrite-existing
  double MinRatio = 0.0;           // --min-ratio
  int64_t MaxHops = -1;            // --max-hops
  bool StrictSqlite = false;       // --strict-sqlite (in-process diff only)
  bool IgnoreSmallFunctions = false;
};

struct CommandOutcome {
  int ExitCode = kExitOk;
  std::string Message;                // error or summary text for the CLI
  std::vector<std::string> Report;    // lines the CLI prints on success
};

CommandOutcome RunExtract(const ExtractArgs& Args);
CommandOutcome RunIngest(const IngestArgs& Args);
CommandOutcome RunPortFromResults(const PortFromResultsArgs& Args);

}
