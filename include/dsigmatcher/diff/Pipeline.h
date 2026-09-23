#pragma once

// The diff driver (docs/parity/00-plan.md §2.1, §2.4, §3.6): DiffSession owns everything one diff
// needs; RunPipeline is the literal port of CBinDiff.diff() (D:3568-3701); RunDiff is the only
// exception boundary (exit codes of §2.1); RunReplay runs one stage between two snapshots.

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <typeindex>
#include <typeinfo>
#include <utility>
#include <vector>

#include "dsigmatcher/diff/Config.h"
#include "dsigmatcher/diff/Consumer.h"
#include "dsigmatcher/diff/Database.h"
#include "dsigmatcher/diff/Interner.h"
#include "dsigmatcher/diff/MatchState.h"
#include "dsigmatcher/diff/Ratio.h"
#include "dsigmatcher/diff/Registry.h"
#include "dsigmatcher/diff/ResultsWriter.h"
#include "dsigmatcher/diff/Snapshot.h"
#include "dsigmatcher/diff/Table.h"
#include "dsigmatcher/diff/Trace.h"

namespace DSig::Diff {

// CBinDiff attributes the passes set (snapshot "flags", Appendix B).
struct DiffFlags {
  bool IsSameProcessor = false;    // D:3617
  bool IsPatchDiff = false;        // D:2612
  bool IsSymbolsStripped = false;  // D:2564
  bool HooksLoaded = false;        // D:2614-2619 (scripts/patch_diff_vulns.py in patch-diff mode)
};

// --related-cu-source (plan §0.3, L8).
enum class RelatedCuSource : uint8_t { Native = 0, Sql = 1 };

class DiffSession {
public:
  explicit DiffSession(DiffConfig Config = {});
  ~DiffSession();
  DiffSession(const DiffSession&) = delete;
  DiffSession& operator=(const DiffSession&) = delete;

  // ---- inputs ----------------------------------------------------------------------------
  // Opens db1 read-only, attaches db2 as `diff` and ingests both (leniently: see ExportData::Problems).
  // Throws IoFailure when a file cannot be opened (SqliteEnvironmentFailure for a corrupt one).
  void Open(const std::string& Db1, const std::string& Db2);
  bool IsOpen() const;
  // Throws UnsupportedInput when ingest recorded any problem (ExportData::Problems): a table the default
  // diff reads is missing, the functions table or one of its columns is missing, a column holds a value
  // of the wrong storage class, or two functions share an address. RunPipeline calls it right after the
  // diff.version check.
  void RequireIngest() const;

  // ---- components ------------------------------------------------------------------------
  const DiffConfig& Config() const;
  DiffConfig& MutableConfig();
  Interners& Ids();
  const Interners& Ids() const;
  DiffDatabase& Db();
  const DiffDatabase& Db() const;
  ExportData& Main();
  const ExportData& Main() const;
  ExportData& Diff();
  const ExportData& Diff() const;
  ExportData& Export(Side Which);
  const ExportData& Export(Side Which) const;
  MatchState& State();
  const MatchState& State() const;
  RatioEngine& Engine();
  IRatioProvider& Ratio();                        // the provider CheckMatch uses (Engine() unless replaced)
  void SetRatioProvider(IRatioProvider* Provider);  // nullptr restores Engine(); tests inject fakes
  DiffFlags& Flags();
  const DiffFlags& Flags() const;
  FinalResults& Final();
  const FinalResults& Final() const;
  TraceSink& Tracer();
  SummaryLog& Log();
  RelatedCuSource CuSource() const;
  void SetCuSource(RelatedCuSource Source);

  // ---- harness: points, snapshots, context -------------------------------------------------
  void SetPairLabel(std::string Pair);
  const std::string& PairLabel() const;
  // The capture layout of tools/parity/oracle_trace.py: snapshots of every point matching `PointGlobs`
  // ("a|b", fnmatch '*' '?') go to <Dir>/snapshots/NNNNN_<point>.json; <Dir>/index.json lists EVERY
  // point as [seq, point, file] (file relative to <Dir>, null when filtered out) and is rewritten at
  // each point. `CacheGlobs` selects the points whose snapshot also carries ratios_cache. Earlier
  // snapshot files in <Dir>/snapshots and the earlier index.json are removed. Throws UsageRefused when
  // Dir is (inside) an oracle capture (it holds run.json) or holds an index.json that is not a capture
  // index (audit F29), IoFailure when Dir cannot be created or a stale file cannot be removed. Paths
  // are UTF-8.
  void EnableSnapshots(const std::string& Dir, std::string PointGlobs = "*", std::string CacheGlobs = "");
  // Throws UsageRefused when the trace's directory is (inside) an oracle capture, IoFailure when the
  // file cannot be created.
  void EnableTrace(const std::string& Path, bool Rows);
  // Emits a named point: a trace "point" event and, when enabled and matching, a snapshot file.
  void Point(std::string_view Name);
  // A cleanup_matches() call at `Site`: "before:cleanup:<site>:<n>", State().Cleanup(Site), the
  // cleanup trace event, "after:cleanup:<site>:<n>"; n counts calls per site from 1.
  void Cleanup(CleanupSite Site);
  // Outer-loop iteration of the snapshots: k from the loop's first cleanup (D:3655) through its last
  // (D:3671); nullopt before the loop, in modes S and P, and from before:final_pass on (the oracle's
  // rule, tools/parity/README.md "iteration").
  std::optional<int> Iteration() const;
  void SetIteration(std::optional<int> Iteration);
  std::string_view Context() const;               // innermost context label, "diff" at top level
                                                  // (written as null in the trace, like the oracle)
  void PushContext(std::string Label);
  void PopContext();
  // The whole current state as a snapshot for `Point` (choosers at after:final_pass, unmatched at
  // after:find_unmatched, ratios_cache when `WithCache`).
  StateSnapshot Snapshot(std::string_view PointName, bool WithCache = false) const;
  // Restores flags, totals, all_matches, matched_* and (when present) ratios_cache from a snapshot.
  void Restore(const StateSnapshot& Before);
  // Throws UnsupportedInput unless every address `Before` holds is a function of its side (items of
  // all_matches and choosers: ea1 main, ea2 diff; unmatched primary: diff, secondary: main) and its
  // non-zero total_functions1/2 equal the loaded function counts (audit F28). RunDiff calls it before a
  // replay, so a snapshot of another pair is refused instead of replayed against the wrong databases.
  void CheckSnapshotMatchesInputs(const StateSnapshot& Before) const;
  // Writes <snapshot dir>/index.json, then flushes and closes the trace, checked: throws IoFailure when
  // either fails (audit F27). Safe to call more than once.
  void FinishHarness();

  // ---- per-lane session state ------------------------------------------------------------
  // A default-constructed T owned by the session, created on first use (for example the patch-diff
  // hook's dedup set). Lets a lane keep session state without changing this header.
  template <class T>
  T& Ext() {
    std::shared_ptr<void>& Slot = ExtSlot(std::type_index(typeid(T)));
    if (!Slot) {
      Slot = std::make_shared<T>();
    }
    return *static_cast<T*>(Slot.get());
  }

  char Mode() const;  // 'S' stripped, 'P' patch diff, 'N' normal (from Flags())

private:
  std::shared_ptr<void>& ExtSlot(std::type_index Type);

  struct Impl;
  std::unique_ptr<Impl> Impl_;
};

// RAII context label for trace events (restored on scope exit, including during unwinding).
class ContextScope {
public:
  ContextScope(DiffSession& S, std::string Label) : S_(S) { S_.PushContext(std::move(Label)); }
  ~ContextScope() { S_.PopContext(); }
  ContextScope(const ContextScope&) = delete;
  ContextScope& operator=(const ContextScope&) = delete;

private:
  DiffSession& S_;
};

// ---- driver ------------------------------------------------------------------------------------

// Literal port of diff() (D:3568-3701) on an open session. Returns diff()'s value: false when the
// diff.version check fails (D:3577-3591; save_results still writes empty tables). Throws
// DiaphoraWouldRaise / UnsupportedInput / IoFailure (SqliteEnvironmentFailure). Fills S.Final() and
// logs the final lines (D:3684-3695).
bool RunPipeline(DiffSession& S);

// Runs exactly one replayable stage (Appendix B, marked R) from `Before` and returns the after
// snapshot. `Stage` is a point base such as "find_same_name", "heuristic:41", "cleanup:3185:4",
// "find_matches_diffing:0", "run_heuristics_for_category:Best", "final_pass" or "find_unmatched";
// `Iteration` / `HeuristicId` supply the suffix when `Stage` omits it. Throws UnsupportedInput for
// an unknown stage.
StateSnapshot RunReplay(DiffSession& S, const StateSnapshot& Before, std::string_view Stage,
                        std::optional<int> Iteration = std::nullopt,
                        std::optional<int> HeuristicId = std::nullopt);

// Exit codes (§2.1, as amended for v1.0.0).
enum class DiffStatus : int {
  Ok = 0,
  Usage = 2,           // usage error, or a command line refused before any file was touched
                       // (an output aliasing an input, a write target inside an oracle capture)
  WouldRaise = 3,      // DIAPHORA_WOULD_RAISE: nothing written (an existing output is left as it was)
  Unsupported = 4,     // unsupported configuration or input quirk; also db2 not a usable Diaphora export,
                       // where Diaphora's empty results file IS written (audit F06)
  SqliteMismatch = 5,  // --strict-sqlite and sqlite3_libversion() != 3.51.1 (plan §7.1 D2)
  Io = 6,              // I/O or environment failure (disk full, missing TMP, a damaged database file)
  Internal = 70,       // an internal error (EX_SOFTWARE): a bug, never an input problem
};

struct DiffArgs {
  std::string Db1;                        // exactly as given (config.main_db)
  std::string Db2;                        // exactly as given (config.diff_db)
  std::string Out;                        // empty -> DefaultOutputName(Db1, Db2)
  DiffConfig Config;                      // only IgnoreSmallFunctions may differ from the defaults
  std::string TracePath;                  // --trace
  bool TraceRows = false;                 // --trace-rows
  std::string SnapshotDir;                // --snapshot-dir
  std::string SnapshotPoints = "*";       // --snapshot-points
  std::string SnapshotCache;              // --snapshot-cache (points that also dump ratios_cache)
  std::string PairLabel;                  // --pair (default stem(db1) + "_vs_" + stem(db2))
  std::string ReplayPath;                 // --replay <before.json>
  std::string ReplayStage;                // --stage
  std::optional<int> ReplayIteration;     // --iteration
  std::optional<int> ReplayHeuristic;     // --heuristic
  std::string SnapshotOut;                // --snapshot-out <after.json>
  RelatedCuSource CuSource = RelatedCuSource::Native;  // --related-cu-source
  bool StrictSqlite = false;              // --strict-sqlite: exit 5 unless SQLite is 3.51.1
  bool AllowSqliteMismatch = false;       // --allow-sqlite-mismatch: no warning
  bool Quiet = false;                     // no summary lines on stderr (the SQLite warning still prints)
};

struct DiffOutcome {
  DiffStatus Status = DiffStatus::Ok;
  std::string Message;          // the error text for non-zero statuses
  std::string OutputPath;       // the .diaphora path (or the replay snapshot)
  bool OutputWritten = false;
  bool DiffReturned = true;     // diff()'s return value (false: empty-result path)
  char Mode = 'N';
  size_t Best = 0;              // final chooser item counts (the "Final results" line)
  size_t Partial = 0;
  size_t Unreliable = 0;
  size_t Multimatch = 0;
  std::vector<std::string> Skipped;  // always empty: no stage is a stub any more (audit F63); kept only
                                     // until the CLI (src/main.cpp) stops printing it
  std::string SqliteVersion;
};

// Checks every path first (aliases, oracle captures, the output's directory: nothing is opened or
// written when one is refused), then Open, RunPipeline (or RunReplay when ReplayPath is set), write.
// Never throws.
DiffOutcome RunDiff(const DiffArgs& Args);

// Diaphora's default output name (D:3753-3755): basename(splitext(db1)[0]) + "_vs_" + ... + ".diaphora".
std::string DefaultOutputName(std::string_view Db1, std::string_view Db2);
// basename(splitext(path)[0]) with the host's os.path rules (ntpath on Windows, posixpath elsewhere).
std::string PathStem(std::string_view Path);

// The warning printed when parity mode runs on another SQLite (plan §7.1 D2).
std::string SqliteMismatchWarning(std::string_view Version);

}
