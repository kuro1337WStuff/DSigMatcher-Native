#pragma once

// Stage snapshots (schema: tools/parity/README.md), shared with the oracle
// instrumentation (tools/parity/oracle_trace.py). Snapshots hold plain strings, not interned ids, so
// they can be compared without a session. Schema "dsig-parity-snapshot/1":
//
// { "schema", "producer", "pair", "seq", "point", "iteration",
//   "flags": {"is_same_processor","is_patch_diff","is_symbols_stripped","hooks_loaded",
//             "total_functions1","total_functions2"},
//   "all_matches": {"best":[item...], "partial":[...], "unreliable":[...]},
//   "matched_primary": [[key, other, ratio_bits]...], "matched_secondary": [...],
//   "ratios_cache": [["ea1-ea2", ratio_bits]...]                     (optional)
//   "choosers": {"best":[item...],"partial":..,"unreliable":..,"multimatch":..}  (after:final_pass)
//   "unmatched": {"primary":[[ea,name]...] | null, "secondary": ... | null}      (after:find_unmatched) }
// item = [ea1, name1, ea2, name2, desc, ratio_bits, nodes1, nodes2]; names may be null (Python None);
// ratio_bits = struct.pack('>d', float(x)).hex() (16 lowercase hex digits).

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "dsigmatcher/diff/Json.h"

namespace DSig::Diff {

inline constexpr std::string_view kSnapshotSchema = "dsig-parity-snapshot/1";

struct SnapItem {
  std::string Ea1;
  std::optional<std::string> Name1;
  std::string Ea2;
  std::optional<std::string> Name2;
  std::string Desc;
  uint64_t RatioBits = 0;
  int64_t Nodes1 = 0;
  int64_t Nodes2 = 0;
  bool operator==(const SnapItem&) const = default;
};

struct SnapMatched {
  std::optional<std::string> Key;    // matched_primary / matched_secondary dict key (a name, or None)
  std::optional<std::string> Other;  // entry["name"]
  uint64_t RatioBits = 0;            // entry["ratio"]
  bool operator==(const SnapMatched&) const = default;
};

struct SnapFlags {
  bool IsSameProcessor = false;
  bool IsPatchDiff = false;
  bool IsSymbolsStripped = false;
  bool HooksLoaded = false;
  int64_t TotalFunctions1 = 0;
  int64_t TotalFunctions2 = 0;
  bool operator==(const SnapFlags&) const = default;
};

struct SnapUnmatched {
  std::string Ea;
  std::optional<std::string> Name;
  bool operator==(const SnapUnmatched&) const = default;
};

struct SnapCacheEntry {
  std::string Key;  // f"{ea1}-{ea2}" (D:1653)
  uint64_t RatioBits = 0;
  bool operator==(const SnapCacheEntry&) const = default;
};

struct SnapChoosers {
  std::vector<SnapItem> Best;
  std::vector<SnapItem> Partial;
  std::vector<SnapItem> Unreliable;
  std::vector<SnapItem> Multimatch;
  bool operator==(const SnapChoosers&) const = default;
};

struct SnapUnmatchedDump {
  std::optional<std::vector<SnapUnmatched>> Primary;    // self.unmatched_primary (diff functions)
  std::optional<std::vector<SnapUnmatched>> Secondary;  // self.unmatched_second (main functions)
  bool operator==(const SnapUnmatchedDump&) const = default;
};

struct StateSnapshot {
  std::string Schema = std::string(kSnapshotSchema);
  std::string Producer;             // "diaphora-3.4.2-4-g621ec26" or "dsigmatcher-<version>"
  std::string Pair;                 // "ls-old_vs_ls"
  int64_t Seq = 0;                  // point ordinal within the run (0-based)
  std::string Point;                // "before:find_matches_diffing:0"
  std::optional<int64_t> Iteration; // outer loop iteration; null before the loop starts
  SnapFlags Flags;
  std::vector<SnapItem> Best;       // all_matches["best"] in list order
  std::vector<SnapItem> Partial;
  std::vector<SnapItem> Unreliable;
  std::vector<SnapMatched> MatchedPrimary;    // dict insertion order
  std::vector<SnapMatched> MatchedSecondary;
  std::optional<std::vector<SnapCacheEntry>> RatiosCache;
  std::optional<SnapChoosers> Choosers;       // only at after:final_pass
  std::optional<SnapUnmatchedDump> Unmatched; // only at after:find_unmatched
};

// Serialisation. Parse/Read throw JsonError (malformed JSON or schema) or IoFailure (Read/Write).
StateSnapshot ParseSnapshot(std::string_view Json);
StateSnapshot SnapshotFromJson(const JsonValue& Root);  // ParseSnapshot on an already parsed value
StateSnapshot ReadSnapshot(const std::string& Path);
JsonValue SnapshotToJson(const StateSnapshot& Snapshot);
std::string SerializeSnapshot(const StateSnapshot& Snapshot, bool Pretty = false);
void WriteSnapshot(const std::string& Path, const StateSnapshot& Snapshot, bool Pretty = false);

// ratio_bits helpers: 16 lowercase hex digits of the big-endian IEEE-754 bits.
std::string RatioBitsHex(double Value);
uint64_t RatioBits(double Value);
double RatioFromBits(uint64_t Bits);
uint64_t ParseRatioBits(std::string_view Hex);  // throws JsonError unless exactly 16 hex digits

// Snapshot file naming: NNNNN_<sanitised point>.json with every character outside [A-Za-z0-9._-]
// replaced by '_' (":" becomes "_").
std::string SanitisePointName(std::string_view Point);
std::string SnapshotFileName(int64_t Seq, std::string_view Point);

// fnmatch-style glob ('*', '?', '[...]' not supported) used by --snapshot-points / --snapshot-cache.
bool PointMatchesGlob(std::string_view Point, std::string_view Glob);

// Parses "a|b|c" globs: true when any alternative matches.
bool PointMatchesAnyGlob(std::string_view Point, std::string_view Globs);

}
