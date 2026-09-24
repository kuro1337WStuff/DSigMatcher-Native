#pragma once

// Crash-resilient `diff` runs: checkpoints of the complete engine state after every top-level stage of
// diff() (`--checkpoint-dir`), and `--resume`, which continues a run from its last checkpoint and writes
// exactly the results file the uninterrupted run would have written.
//
// A checkpoint directory holds two kinds of files, and nothing else is ever created, replaced or deleted
// there:
//   manifest.json       small, human-readable: the binding (tool version, SQLite version, sha256 and
//                       size of db1 and db2 and their -wal files, the result-relevant options), the last
//                       completed stage, and the name, size and sha256 of the state file it vouches for;
//   state-NNNNNN.json   the engine state after that stage (schema kCheckpointStateSchema).
// Every file is written to "<name>.tmp", flushed to the disk and renamed over <name>. A new state file is
// written first, then the manifest that names it, then older state files are removed, so a kill at any
// moment leaves a manifest naming a complete state file (the new one or the previous one).
//
// The results file itself stays all-or-nothing (a partial .diaphora at -o could be mistaken for a complete
// one): progress survives a crash through the checkpoint instead, and the checkpoint files are removed
// only after the results file has been written.

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "dsigmatcher/diff/Snapshot.h"

namespace DSig::Diff {

inline constexpr std::string_view kCheckpointManifestSchema = "dsigmatcher-checkpoint-manifest/1";
inline constexpr std::string_view kCheckpointStateSchema = "dsigmatcher-checkpoint-state/1";
inline constexpr std::string_view kCheckpointManifestName = "manifest.json";

// The completed top-level stages of diff() (D:3568-3701), in execution order. Stages inside the
// convergence loop repeat per iteration; their position is (PipelineCursor::Iteration, step).
enum class PipelineStep : uint8_t {
  None = 0,                 // nothing completed yet (never written to a checkpoint)
  EqualMatches,             // version check, ingest checks, equal_db, check_callgraph, find_equal_matches
  DirtyHeuristics,          // is_same_processor, ratio preparation, apply_dirty_heuristics
  SameName,                 // find_same_name
  RemainingFunctions,       // find_remaining_functions (only when a dirty heuristic fired)
  BestCategory,             // run_heuristics_for_category("Best")
  PartialCategory,          // find_partial_matches: run_heuristics_for_category("Partial")
  SmallDifferences,         // find_partial_matches: search_small_differences
  LoopCleanupTop,           // loop k: cleanup_matches at D:3655
  MatchesDiffing,           // loop k: find_matches_diffing
  RelatedMatches,           // loop k: find_related_matches
  RelatedCompilationUnit,   // loop k: find_related_compilation_unit
  LocallyAffine,            // loop k: find_locally_affine_functions
  LoopCleanupBottom,        // loop k: cleanup_matches at D:3671 (and the convergence test)
  FinalPass,                // final_pass
  FindUnmatched,            // find_unmatched (only the results file remains to be written)
};

std::string_view PipelineStepName(PipelineStep Step);                  // "find_same_name", ...
std::optional<PipelineStep> PipelineStepFromName(std::string_view Name);
bool IsLoopStep(PipelineStep Step);

// Where diff() stands after a completed step: the step, the loop iteration it belongs to (0 outside the
// loop), and the two locals of diff() that outlive a step: skip_others (D:3616, set by the dirty
// heuristics) and old_total (D:3656, set by the loop's first cleanup).
struct PipelineCursor {
  PipelineStep Done = PipelineStep::None;
  int Iteration = 0;
  bool SkipOthers = false;
  int64_t OldTotal = 0;
  bool operator==(const PipelineCursor&) const = default;
};

// What a checkpoint is bound to. A checkpoint is resumed only when every field equals the value computed
// for the current command line and inputs.
struct CheckpointBinding {
  std::string ToolVersion;          // DSIG_VERSION
  std::string SqliteVersion;        // sqlite3_libversion()
  std::string Db1Sha256;            // the db1 file's bytes
  int64_t Db1Size = 0;
  std::string Db1WalSha256;         // "<db1>-wal" when it exists and is not empty, else ""
  std::string Db2Sha256;
  int64_t Db2Size = 0;
  std::string Db2WalSha256;
  bool IgnoreSmallFunctions = false;  // the only option that changes the results
  std::string RelatedCuSource;        // "native" or "sql"
  bool operator==(const CheckpointBinding&) const = default;
};

// sha256 (lowercase hex) and size of a file, read through the UTF-8 path helpers. Throws IoFailure.
std::pair<std::string, int64_t> FileSha256AndSize(const std::string& Utf8Path);

// The binding fields that describe one input: its sha256 and size, and its "-wal" file's sha256 when that
// file exists and holds data. Throws IoFailure when a file cannot be read.
void BindInput(const std::string& Utf8Path, std::string& Sha256, int64_t& Size, std::string& WalSha256);

// The first field that differs, as "db1 sha256 (checkpoint abc..., now def...)", or "" when equal.
std::string DescribeBindingMismatch(const CheckpointBinding& Saved, const CheckpointBinding& Now);

// One ratios_cache entry with its exact address texts (nullopt: Python None).
struct CheckpointCacheEntry {
  std::optional<std::string> Ea1;
  std::optional<std::string> Ea2;
  uint64_t RatioBits = 0;
  bool operator==(const CheckpointCacheEntry&) const = default;
};

// The complete engine state after a step. `State` carries all_matches, matched_primary/secondary, the
// flags and totals, the iteration, and (from final_pass on) the choosers and the unmatched lists; its
// ratios_cache is always empty (the cache is kept in RatiosCache with exact address texts).
struct EngineCheckpoint {
  CheckpointBinding Binding;
  PipelineCursor Cursor;
  StateSnapshot State;
  std::vector<CheckpointCacheEntry> RatiosCache;  // insertion order (Python dict order)
  // The patch-diff hook's `dones` set (scripts/patch_diff_vulns.py:67): pairs of names, None as nullopt.
  std::vector<std::pair<std::optional<std::string>, std::optional<std::string>>> HookDones;
  int64_t PointSeq = 0;                                  // harness point counter
  std::vector<std::pair<int, int64_t>> CleanupCounters;  // per cleanup site: calls so far
};

// Serialisation of the state file (compact JSON and one newline). Parse throws JsonError.
std::string SerializeCheckpointState(const EngineCheckpoint& Checkpoint);
EngineCheckpoint ParseCheckpointState(std::string_view Json);

// The manifest: the binding, the step it records, and the state file it vouches for.
struct CheckpointManifest {
  CheckpointBinding Binding;
  PipelineCursor Cursor;
  int64_t Generation = 0;       // 1 for the first checkpoint of a run, +1 per checkpoint
  std::string StateFile;        // "state-NNNNNN.json" (a file name, never a path)
  std::string StateSha256;
  int64_t StateBytes = 0;
  std::string Db1;              // the command line's db1 and db2, for people reading the manifest
  std::string Db2;
  bool CreatedDirectory = false;  // the first run of this checkpoint created the directory
};

std::string SerializeCheckpointManifest(const CheckpointManifest& Manifest);  // pretty JSON + newline
CheckpointManifest ParseCheckpointManifest(std::string_view Json);            // throws JsonError

// A checkpoint directory (UTF-8 path).
class CheckpointStore {
public:
  explicit CheckpointStore(std::string Dir);

  const std::string& Dir() const { return Dir_; }
  std::string ManifestPath() const;
  // True when `Name` (a file name) is one this store may create, replace or delete.
  static bool IsStoreFileName(std::string_view Name);

  // Creates the directory when missing (with its parents) and proves it writable with a probe file.
  // Returns true when this call created it (Remove then removes it again). Throws IoFailure.
  bool Prepare();
  // True when the directory holds a manifest.json (ours or not).
  bool HasManifest() const;

  // Reads and checks the manifest and the state file it names (size, sha256, schema, a binding equal to
  // the manifest's). Throws UnsupportedInput with a message that says what is wrong and what to do.
  // Continues the store's generation count and remembers whether the checkpoint's first run created the
  // directory.
  EngineCheckpoint Load(CheckpointManifest* ManifestOut = nullptr);

  // Writes a checkpoint: the state file, then the manifest, then removes older state files. Throws
  // IoFailure; the previous checkpoint is left usable whenever this throws.
  void Write(const EngineCheckpoint& Checkpoint, const std::string& Db1, const std::string& Db2);

  // Removes the manifest first (so the directory never looks like a checkpoint again), then every state
  // file and temporary file of the store, then the directory itself when the checkpoint's first run
  // created it and it is empty. Throws IoFailure when a file cannot be removed.
  void Remove();

  int64_t Generation() const { return Generation_; }

private:
  std::string Dir_;
  int64_t Generation_ = 0;
  bool CreatedDir_ = false;
};

}
