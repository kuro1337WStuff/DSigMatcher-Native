#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "dsigmatcher/Heuristics.h"
#include "dsigmatcher/Types.h"

namespace DSig {

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
};

struct DatabaseIdentity {
  std::string Path;
  bool Ok = false;
  std::string Error;
  std::string InputMd5;
  std::string Processor;
  std::string FileSha256;
  int64_t FunctionCount = 0;
  bool HasProvenance = false;
  int64_t HopCount = 0;
  std::string Lineage;
  std::vector<HopRecord> Hops;
};

struct PortOptions {
  std::string ReferencePath;
  std::string TargetPath;
  std::string OutputPath;
  bool OverwriteExistingNames = false;
  double MinCumulativeRatio = 0.0;
  int64_t MaxHops = -1;
  DiffOptions Diff;
};

struct PortResult {
  bool Ok = false;
  std::string Error;
  int64_t Matches = 0;
  int64_t NamesApplied = 0;
  int64_t NamesConfirmed = 0;
  int64_t NamesSkippedExisting = 0;
  int64_t NamesSkippedHops = 0;
  int64_t NamesSkippedRatio = 0;
  int64_t NamesSkippedNotPortable = 0;
  int64_t NewHop = 0;
  std::string OutputSha256;
  std::string Lineage;
};

std::string CurrentUtcTimestamp();

DatabaseIdentity InspectDatabase(const std::string& Path);

std::unordered_map<std::string, NameOrigin> ReadNameOrigins(const std::string& Path);

PortResult PortSymbols(const PortOptions& Options);

// ---------------------------------------------------------------------------------------------
// Label port from match proposals (docs/parity/00-plan.md §7.1 D6, lane L11)
//
// The engine behind `port --results`. It applies match proposals (one per `.diaphora` results row
// today; one per in-process parity-diff item once lane L9 wires `port` without --results) to a copy
// of the target export, so the output is itself a Diaphora export that can be the next hop's
// reference.
//
// Carried over unchanged from PortSymbols: the output never aliases an input; a target that already
// carries the identical real name is a confirmation (no update, no origin row, no hop); hops are the
// parent's + 1 and confidence is ratio x parent confidence (dsig_name_origin of the reference);
// --max-hops, --min-ratio; a real target name is never replaced unless OverwriteExistingNames.
// New for proposals: the first selected proposal in stored order claims its target function (a
// later one is skipped_conflict), and a name that would end up on two functions of the output is
// not applied (skipped_duplicate_name). Label columns written: functions.name and
// functions.mangled_function only (tools/e2e/README.md, "What a port writes").

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
  std::vector<std::string> OtherInputs;  // further inputs the output must not alias (the results file)
  bool OverwriteExistingNames = false;
  double MinCumulativeRatio = 0.0;
  int64_t MaxHops = -1;
  // Recorded in dsig_port_results for the new hop.
  std::string ResultsPath;
  std::string ResultsSha256;
  std::string ResultsMainDb;
  std::string ResultsDiffDb;
  std::string ResultsVersion;
  std::string ResultsDate;
  bool IncludeMultimatch = false;
  bool IncludeUnreliable = false;
};

enum class PortFailure : uint8_t { None, Usage, Input, Io };

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

// A read-only SQLite URI for an input database (use with SQLITE_OPEN_READONLY | SQLITE_OPEN_URI).
// A WAL-mode file whose -wal is absent or empty is opened `immutable=1`, so reading an export never
// creates -wal/-shm files beside it; any other file is opened `mode=ro`.
std::string ReadOnlyDatabaseUri(const std::string& Path);

// Python int() of a decimal string, as Diaphora applies it to functions.address (01 §10.2):
// surrounding ASCII whitespace, an optional '+', and '_' between digits are accepted. Negative or
// out-of-range values are rejected.
std::optional<uint64_t> ParseDecimalAddress(std::string_view Text);

}
