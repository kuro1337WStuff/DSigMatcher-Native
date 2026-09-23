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
  // Throws IoFailure when a file cannot be opened.
  void Open(const std::string& Db1, const std::string& Db2);
  bool IsOpen() const;
  // Throws UnsupportedInput when ingest recorded a problem (missing functions table or columns).
  // RunPipeline calls it right after the diff.version check.
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
  // Snapshots of every point matching `PointGlobs` ("a|b", fnmatch '*' '?') go to
  // <Dir>/NNNNN_<point>.json; <Dir>/index.json lists [seq, point, file]. `CacheGlobs` selects the
  // points whose snapshot also carries ratios_cache. Throws IoFailure when Dir cannot be created.
  void EnableSnapshots(const std::string& Dir, std::string PointGlobs = "*", std::string CacheGlobs = "");
  void EnableTrace(const std::string& Path, bool Rows);
  // Emits a named point: a trace "point" event and, when enabled and matching, a snapshot file.
  void Point(std::string_view Name);
  // A cleanup_matches() call at `Site`: "before:cleanup:<site>:<n>", State().Cleanup(Site), the
  // cleanup trace event, "after:cleanup:<site>:<n>"; n counts calls per site from 1.
  void Cleanup(CleanupSite Site);
  std::optional<int> Iteration() const;           // outer loop iteration; nullopt before the loop
  void SetIteration(std::optional<int> Iteration);
  std::string_view Context() const;               // innermost context label, "diff" at top level
  void PushContext(std::string Label);
  void PopContext();
  // The whole current state as a snapshot for `Point` (choosers at after:final_pass, unmatched at
  // after:find_unmatched, ratios_cache when `WithCache`).
  StateSnapshot Snapshot(std::string_view PointName, bool WithCache = false) const;
  // Restores flags, totals, all_matches, matched_* and (when present) ratios_cache from a snapshot.
  void Restore(const StateSnapshot& Before);
  // Writes <snapshot dir>/index.json and flushes the trace. Safe to call more than once.
  void FinishHarness();

  // ---- stub bookkeeping ------------------------------------------------------------------
  void NoteSkipped(std::string_view Stage, std::string_view Reason);
  const std::vector<std::string>& SkippedStages() const;

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

// L0 stub protocol: runs F; a StageNotImplemented thrown by a stub is logged as
// "SKIPPED <Name>: <reason>" and swallowed. Returns false when the stage was skipped.
bool InvokeStage(DiffSession& S, std::string_view Name, const std::function<void()>& F);

// ---- driver ------------------------------------------------------------------------------------

// Literal port of diff() (D:3568-3701) on an open session. Returns diff()'s value: false when the
// diff.version check fails (D:3577-3591; save_results still writes empty tables). Throws
// DiaphoraWouldRaise / UnsupportedInput. Fills S.Final() and logs the final lines (D:3684-3695).
bool RunPipeline(DiffSession& S);

// Runs exactly one replayable stage (Appendix B, marked R) from `Before` and returns the after
// snapshot. `Stage` is a point base such as "find_same_name", "heuristic:41", "cleanup:3185:4",
// "find_matches_diffing:0", "run_heuristics_for_category:Best", "final_pass" or "find_unmatched";
// `Iteration` / `HeuristicId` supply the suffix when `Stage` omits it. Throws UnsupportedInput for
// an unknown stage.
StateSnapshot RunReplay(DiffSession& S, const StateSnapshot& Before, std::string_view Stage,
                        std::optional<int> Iteration = std::nullopt,
                        std::optional<int> HeuristicId = std::nullopt);

// Exit codes (§2.1).
enum class DiffStatus : int {
  Ok = 0,              // includes Diaphora's empty-result case
  Usage = 2,
  WouldRaise = 3,      // DIAPHORA_WOULD_RAISE: no output written, as in Python
  Unsupported = 4,     // unsupported configuration or input quirk (also "not implemented" commands)
  SqliteMismatch = 5,  // --strict-sqlite and sqlite3_libversion() != 3.51.1 (plan §7.1 D2)
  Io = 6,
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
  bool Quiet = false;                     // no summary lines on stderr
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
  std::vector<std::string> Skipped;  // stages skipped because a stub is not implemented
  std::string SqliteVersion;
};

// Open, RunPipeline (or RunReplay when ReplayPath is set), write. Never throws.
DiffOutcome RunDiff(const DiffArgs& Args);

// Diaphora's default output name (D:3727-3731): basename(splitext(db1)[0]) + "_vs_" + ... + ".diaphora".
std::string DefaultOutputName(std::string_view Db1, std::string_view Db2);
// basename(splitext(path)[0]) with the host's os.path rules (ntpath on Windows, posixpath elsewhere).
std::string PathStem(std::string_view Path);

// The warning printed when parity mode runs on another SQLite (plan §7.1 D2).
std::string SqliteMismatchWarning(std::string_view Version);

}
