#pragma once

// Provenance of ported labels and the label port itself (the engine behind `dsigmatcher port`).
//
// Every path is UTF-8 (the CLI converts the wide command line on Windows); every file access goes
// through std::filesystem::path built from UTF-8, so the functions work in any host process, with or
// without the executable's UTF-8 code-page manifest.

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace DSig {

// Why an operation failed, for the CLI's exit code: Usage 2 (bad arguments, an output that aliases an
// input), Input 4 (a readable file that is not what the command needs, e.g. not a Diaphora export),
// Io 6 (missing, unreadable or unwritable files, not an SQLite database).
enum class PortFailure : uint8_t { None, Usage, Input, Io };

struct NameOrigin {
  std::string Address;
  std::string Name;
  std::string OriginAddress;
  std::string OriginName;
  int64_t Hops = 0;
  double CumulativeRatio = 1.0;
  std::string Heuristic;
  std::string FirstLabelledAt;
};

// One row of dsig_provenance, plus the port settings of the same hop from dsig_port_results when the
// database has that table (HasPortSettings).
struct HopRecord {
  int64_t Hop = 0;
  std::string SourcePath;
  std::string SourceInputMd5;
  std::string SourceFileSha256;
  std::string TargetInputMd5;
  std::string TargetFileSha256Before;
  std::string AppliedAt;
  std::string ToolVersion;
  int64_t FunctionsReference = 0;
  int64_t FunctionsTarget = 0;
  int64_t Matches = 0;
  int64_t NamesApplied = 0;
  int64_t NamesSkippedExisting = 0;
  int64_t NamesSkippedHops = 0;
  int64_t NamesSkippedRatio = 0;
  double MinRatio = 0.0;
  int64_t MaxHops = -1;
  std::string Lineage;

  bool HasPortSettings = false;
  std::string ResultsPath;
  std::string ResultsSha256;
  std::string ResultsSource;             // "results file" or "in-process diff" (empty before 1.0.0)
  bool IncludeMultimatch = false;
  bool IncludeUnreliable = false;
  bool Overwrite = false;
  std::optional<bool> OverwriteStripped;  // not recorded before 1.0.0
  int64_t NamesConfirmed = 0;
  int64_t NamesSkippedNotPortable = 0;
  int64_t NamesSkippedConflict = 0;
  int64_t NamesSkippedDuplicate = 0;
};

struct DatabaseIdentity {
  std::string Path;
  bool Ok = false;
  PortFailure Failure = PortFailure::None;  // Io: missing, unreadable, not SQLite; Input: not an export
  std::string Error;                        // names the path
  bool IsResultsFile = false;               // a Diaphora results file (.diaphora) instead of an export
  std::string InputMd5;
  std::string Processor;
  std::string FileSha256;
  int64_t FunctionCount = 0;
  bool HasProvenance = false;
  int64_t HopCount = 0;
  std::string Lineage;
  std::vector<HopRecord> Hops;
};

std::string CurrentUtcTimestamp();

DatabaseIdentity InspectDatabase(const std::string& Path);

std::unordered_map<std::string, NameOrigin> ReadNameOrigins(const std::string& Path);

// The sha256 of a file (UTF-8 path), or nullopt when it cannot be read to the end.
std::optional<std::string> FileSha256Hex(const std::string& Path);

// How a path is stored in the dsig_* tables: the file name alone by default (the sha256 columns
// identify the files, and a full path would record the author's user name and directory layout), or
// with Full the absolute, normalised path.
std::string StoredPath(const std::string& Path, bool Full);

// ---------------------------------------------------------------------------------------------
// Label port from match proposals (docs/parity/00-plan.md §7.1 D6)
//
// The engine behind `port`. It applies match proposals (one per `.diaphora` results row) to a copy of
// the target export, so the output is itself a Diaphora export that can be the next hop's reference.
//
// The output never aliases an input: neither the output, the temporary "<output>.dsig-tmp" nor any
// -wal/-shm/-journal sidecar of the two is an input or an input's sidecar (refused as
// PortFailure::Usage before any I/O). A target that already carries the identical real name is a
// confirmation (no update, no origin row). Hops are the parent's + 1 and confidence is ratio x parent
// confidence (dsig_name_origin of the reference; the parent's values are inherited only while the
// reference function still carries the name its origin row recorded, else the name starts a new
// history at hop 1). --max-hops, --min-ratio; a real target name is never replaced unless
// OverwriteExistingNames, and never by a "Same binary with symbols stripped" row unless also
// OverwriteStripped. IDA placeholders (Naming.h: sub_, nullsub_, j_, unknown_libname_, DllEntryPoint,
// start) are never ported and never protect a target function. The first selected proposal in
// stored order claims its target function (a later one is skipped_conflict), and a name that would
// end up on two functions of the output is not applied (skipped_duplicate_name). Label columns
// written: functions.name and functions.mangled_function only (tools/e2e/README.md).
//
// The output's dsig_* tables describe one history: dsig_provenance and dsig_port_results are the
// reference's rows plus this hop, dsig_name_origin holds this hop's applied names and dsig_port_log
// this hop's decisions. dsig_* tables a ported target carried are replaced, not merged.

// One proposed label transfer, target function <- reference function.
struct LabelProposal {
  int64_t SourceRow = 0;                     // results rowid (stored order)
  std::string Category;                      // best | partial | unreliable | multimatch
  std::string Line;                          // results.line as stored
  std::string Description;                   // results.description: heuristic or pass name
  std::string RatioText;                     // results.ratio as stored ("%.7f")
  double Ratio = 0.0;                        // RatioText parsed
  uint64_t ReferenceEa = 0;                  // results.address  ("%08x" of int(ea))
  uint64_t TargetEa = 0;                     // results.address2
  std::optional<std::string> ReferenceName;  // results.name, checked against the reference row
  std::optional<std::string> TargetName;     // results.name2, checked against the target row
  bool Selected = true;                      // false: category not included, logged as not_selected
};

enum class LabelAction : uint8_t {
  NotSelected,
  Applied,
  Confirmed,
  SkippedNotPortable,
  SkippedConflict,
  SkippedHops,
  SkippedRatio,
  SkippedExisting,
  SkippedDuplicateName,
};

// The text stored in dsig_port_log.action ("applied", "skipped_existing", ...).
const char* LabelActionName(LabelAction Action);

struct LabelDecision {
  LabelAction Action = LabelAction::NotSelected;
  std::string TargetAddress;                     // functions.address text in the target
  std::string ReferenceAddress;                  // functions.address text in the reference
  std::optional<std::string> ReferenceName;      // reference functions.name
  std::optional<std::string> ReferenceMangled;   // reference functions.mangled_function
  std::optional<std::string> TargetNameBefore;   // target functions.name before the port
  std::optional<std::string> TargetMangledBefore;
  std::string WrittenMangled;                    // mangled_function written (Applied only)
  double Confidence = 0.0;                       // ratio x parent confidence (0 when not reached)
  int64_t Hops = 0;                              // parent hops + 1 (0 when not reached)
};

struct LabelPortOptions {
  std::string ReferencePath;
  std::string TargetPath;
  std::string OutputPath;
  std::vector<std::string> OtherInputs;  // further inputs (the results file): no written file may alias
                                         // one of them or its sidecars
  bool OverwriteExistingNames = false;
  bool OverwriteStripped = false;        // also let "Same binary with symbols stripped" rows overwrite
  double MinCumulativeRatio = 0.0;
  int64_t MaxHops = -1;
  bool StoreFullPaths = false;           // dsig_* path columns: absolute paths instead of file names
  // Recorded in dsig_port_results for the new hop.
  std::string ResultsPath;
  std::string ResultsSha256;
  std::string ResultsMainDb;
  std::string ResultsDiffDb;
  std::string ResultsVersion;
  std::string ResultsDate;
  std::string ResultsSource;             // "results file" or "in-process diff"
  bool IncludeMultimatch = false;
  bool IncludeUnreliable = false;
};

struct LabelPortResult {
  bool Ok = false;
  PortFailure Failure = PortFailure::None;
  std::string Error;
  int64_t Proposals = 0;  // every proposal (every results row)
  int64_t Selected = 0;   // proposals of the included categories: the hop's "matches"
  int64_t NamesApplied = 0;
  int64_t NamesConfirmed = 0;
  int64_t NamesSkippedNotPortable = 0;
  int64_t NamesSkippedConflict = 0;
  int64_t NamesSkippedHops = 0;
  int64_t NamesSkippedRatio = 0;
  int64_t NamesSkippedExisting = 0;
  int64_t NamesSkippedDuplicate = 0;
  int64_t FunctionsReference = 0;
  int64_t FunctionsTarget = 0;
  int64_t NewHop = 0;
  std::string OutputSha256;
  std::string Lineage;
  std::vector<LabelDecision> Decisions;  // one per proposal, in proposal order
};

LabelPortResult PortLabels(const LabelPortOptions& Options, const std::vector<LabelProposal>& Proposals);

// ---------------------------------------------------------------------------------------------
// Output / input aliasing. A command that writes a database must refuse before any I/O when one of
// the files it writes, deletes or lets SQLite create is an input or an input's sidecar.

// A file and what it is, for messages ("the output's -wal file").
struct NamedPath {
  std::string Role;
  std::string Path;
};

// The files SQLite may keep for the database at Path: the database itself and its "-wal", "-shm"
// and "-journal" sidecars (https://www.sqlite.org/tempfiles.html §2.1-2.3). Empty for an empty path.
std::vector<NamedPath> DatabaseFileSet(const std::string& Role, const std::string& Path);

// True when A and B (UTF-8) name one file: std::filesystem::equivalent when both exist (hard links,
// short names, a UNC share of a local drive), else weakly_canonical compared the way the platform's
// file system compares names (case-insensitively on Windows and macOS).
bool SameFilePath(const std::string& A, const std::string& B);

// The first (written, input) pair that names one file, as a refusal message ending in "refusing to
// overwrite an input (nothing was changed)"; nullopt when no written file aliases an input.
std::optional<std::string> FindPathAlias(const std::vector<NamedPath>& Written, const std::vector<NamedPath>& Inputs);

// The SQLite URI of a database path, without touching the file: "file:" + the path with '\' as '/'
// (Windows), '%', '?' and '#' escaped, a drive path as file:/C:/..., a UNC path \\server\share\x as
// file:////server/share/x (an empty URI authority; "file://server/..." would make the server the
// authority, which SQLite rejects), then "?mode=ro" and, when Immutable, "&immutable=1".
std::string SqliteReadOnlyUri(const std::string& Path, bool Immutable);

// A read-only SQLite URI for an input database (use with SQLITE_OPEN_READONLY | SQLITE_OPEN_URI).
// A WAL-mode file whose -wal is absent or empty is opened `immutable=1`, so reading an export never
// creates -wal/-shm files beside it; any other file is opened `mode=ro`.
std::string ReadOnlyDatabaseUri(const std::string& Path);

// Python int() of a decimal string, as Diaphora applies it to functions.address (01 §10.2):
// surrounding ASCII whitespace, an optional '+', and '_' between digits are accepted. Negative or
// out-of-range values are rejected.
std::optional<uint64_t> ParseDecimalAddress(std::string_view Text);

}
