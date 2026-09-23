# 00: Implementation plan for full Diaphora diff parity

This is the execution plan for making `dsigmatcher diff` produce exactly what
`python diaphora.py db1.sqlite db2.sqlite -o out.diaphora` produces on the same two
Diaphora exports. Parallel agents will execute it in separate git worktrees, so it
is written at file level.

- **Inputs.** Specs `01`-`09` in this directory. The oracle manifest
  `<corpus>/oracle/ORACLE.md` and `ORACLE-results.md`. The native
  tree at `<repo>` (branch `parity`, HEAD `34ed418`).
- **Reference.** Diaphora at `<diaphora-ref>` (`3.4.2-4-g621ec26`,
  clean). `D:` means `diaphora.py`, `H:` means `diaphora_heuristics.py` and `C:`
  means `diaphora_config.py`.
- **Line checks.** Every `D:`/`H:`/`C:` line number quoted in §0-§3 was re-checked
  against the reference while this plan was written. Numbers that come only from a
  spec are cited to that spec's section.
- **Oracle status at writing time** (2026-09-23 03:01). Three pairs are finished
  and deterministic across two runs: `ls-old_vs_ls`, `ls_vs_ls-old` and
  `userenv-9168-pdb_vs_9278-pdb`.
  - `userenv-9168-pdb_vs_9278-nopdb` and `sechost-9168-pdb_vs_9444-nopdb` are
    still running detached, inside "Related compilation unit".
  - Do **not** re-run the diffs stage for those two pairs: `RunDiff` deletes the
    run directory first.

---

## 0. Decisions at a glance

1. **Target.** The default standalone configuration (§1.1). The gate compares the
   `results` and `unmatched` tables row for row, including `line` and stored row
   order (level **L2**, §1.3). Ratio text must match exactly, with no tolerance.
2. **Candidate rows come from Diaphora's own SQL** ("Path A"). The engine runs the
   verbatim SQL text through the SQLite C API. It uses the same SQLite build the
   oracle uses (conda 3.51.1) and the same, unmodified export files.
   - The evidence rules out native joins as the reference:
     - 31 of 43 default queries get a different plan on at least one real pair, and
       24 of 43 change their driving table (02 §18.3, Appendix C).
     - Removing `ORDER BY` or `DISTINCT` changes the plan (04a §6.4).
     - Changing only the select list changed the row order (05 H1).
   - The engine is still native C++. SQLite is a C library we already link.
3. **One native candidate generator in the parity path.** The "Related compilation
   unit" cartesian replay (06 §9.2) is generated in C++. A runtime
   `EXPLAIN QUERY PLAN` guard checks for `SCAN f` / `SCAN df` first and falls back
   to SQL if the plan differs. This is needed for speed: each call is about 334k
   rows on userenv and 738k on sechost (06 §9.2). Everything else uses Path A.
4. **Faithful C++ ports of the order-sensitive logic.** Row processing
   (`check_match` → `check_ratio` → `add_match`), cleanup, callee diffing
   (including a literal `difflib.SequenceMatcher` port), the related/affinity
   passes and the final pass are ported to C++. They run **strictly sequentially
   and online**, in Diaphora's order (heuristics in reverse list order,
   `jkutils/threads.py:40` `item = targets.pop()`).
5. **Stage-isolated replay is the main acceptance and debugging tool.** An
   instrumented oracle writes JSON snapshots of Diaphora's match state at named
   points. The native engine can load a "before" snapshot, run one stage, and
   write an "after" snapshot. Each stage lane can therefore be proven on real
   exports without waiting for the other lanes (§2).
6. **Python stays in `tools/parity/`.** It is used only for oracle instrumentation,
   comparison and vector generation. `ctest` never runs Python.
7. **The legacy engine stays untouched until parity.** That covers
   `Heuristics.cpp`, `MatchStore.cpp` and `port`. The new engine lives in
   `DSig::Diff` / `src/diff/`.
8. **Failure behaviour.**
   - Diaphora's exceptions are emulated lazily, at the same sites:
     - worker-thread heuristics are truncated and the run continues;
     - main-thread passes abort with no output file.
   - The 1,000,000-row cap is emulated.
   - Wall-clock timeouts are **not** emulated. Oracle runs that hit one are
     rejected instead (§1.6).

---

## 1. Parity definition

### 1.1 Configuration under test (verified against the reference)

The command is `python diaphora.py <db1> <db2> -o <out>`, with no `DIAPHORA_*`
environment variables set. These are the values that result:

| Setting | Value | Evidence |
|---|---|---|
| unreliable / relaxed ratio / experimental / slow | False / False / True / True | `C:46-49`. `slow_heuristics` comes from `get_value_for` at `D:409-411`. `MIN_FUNCTIONS_TO_DISABLE_SLOW` is referenced only at `diaphora_ida.py:3799` (grep), so standalone runs **never** auto-disable slow heuristics. The task brief's "auto-disabled at 4001" is wrong for this target. |
| ignore sub names / ignore all names / ignore small functions | True / **False (forced)** / False | `C:50-52`. `D:3759-3760`: `if not IS_IDA: bd.ignore_all_names = False`. |
| threads | 1 | `D:489-491`: `if not IS_IDA: self.cpu_count = 1` |
| row cap per `add_matches_internal` call | 1,000,000 | `C:90`, `D:1874-1880` |
| timeout | 300 s (not emulated) | `C:92` |
| ML | off (`classifier` stays None) | 03a §9 |
| hooks | none, except `scripts/patch_diff_vulns.py` in patch-diff mode (result-neutral, but it can raise) | 01 §5.4 |

`--unreliable`, relaxed ratio, ML, project scripts and env overrides are **out of
scope**. The native CLI refuses them.

### 1.2 What is compared

The `.diaphora` file that `save_results` writes (`D:2374-2429`) has three tables.
All values are stored as TEXT (09, "Results database schema").

- `results(type, line, address, name, address2, name2, ratio, nodes1, nodes2, description)`
  with `unique index uq_results(address, address2)`, filled with `insert or ignore`
  in the order best, partial, unreliable, multimatch (`D:2405-2424`).
- `unmatched(type, line, address, name)`, whose labels are **swapped**. `primary`
  rows are diff-DB functions and `secondary` rows are main-DB functions (`D:2323-2356`,
  09).
- `config(main_db, diff_db, version, date)`. `date` is always ignored. `main_db`
  and `diff_db` are ignored unless both runs were given the same argument strings.

### 1.3 Comparison levels

| Level | Definition | Use |
|---|---|---|
| **L0** | The detected mode (N, S or P, from the `Symbols stripped detected:` / `Patch diffing detected:` log lines) matches. So does the `Final results: Best b, Partial p, Unreliable u, Multimatches m` line (`D:3684-3692`). | smoke |
| **L1** | `results` as a multiset of `(type, address, address2, name, name2, ratio, nodes1, nodes2, description)`, and `unmatched` as a multiset of `(type, address, name)`, are equal. | CI with a non-oracle SQLite; tolerated-class accounting |
| **L2** | L1, plus identical `line` values and identical stored row order (`order by rowid`) in both tables. | **the parity gate** |
| **S-L2** | Stage level. For a named snapshot point, `all_matches` (three lists, in order, every field, ratios bit-exact), `matched_primary` and `matched_secondary` (as maps), the flags and, at `after:final_pass`, the raw chooser contents (in order) all equal the oracle's snapshot. | lane acceptance and debugging |

L2 is a stable target. On every finished pair, both oracle runs are identical in
stored order (`determinism.json`, `results_identical_in_order: true`).

### 1.4 Ratio tolerance: none

- The ratio column is `"%.7f"`, correctly rounded with half-even ties on the exact
  double (01 §10.2).
- Multimatch detection depends on exact double ties (`D:2839-2885`).
- Category routing uses exact `==`/`>=` against constants such as 0.549 and
  0.579 (07 §4.2 T1).

So any tolerance would hide real category errors. The compare tool still reports
`|Δratio|` for mismatched pairs, as a diagnostic.

### 1.5 Gate per oracle pair

| Pair | Mode | Oracle | Gate |
|---|---|---|---|
| `ls-old_vs_ls` | N | finished: 139/113/0/26, 278 rows; unmatched 56 primary / 14 secondary (06 V10) | full-run **L2** |
| `ls_vs_ls-old` | N | finished: 139/113/0/34, 286 rows | full-run **L2** |
| `userenv-9168-pdb_vs_9278-pdb` | P | finished: 635/8/0/0, 643 rows; 20 unmatched, all `primary` | full-run **L2** (first milestone) |
| `userenv-9168-pdb_vs_9278-nopdb` | N | running | S-L2 on every captured prefix snapshot now. Full-run **L2** when the oracle completes. If its `determinism.json` shows run-to-run differences, L1 with the tolerated class of §5 R3. |
| `sechost-9168-pdb_vs_9444-nopdb` | N | running (~17 h per outer iteration) | same as above. This is the only pair where `PYTHONHASHSEED` sensitivity has been observed (02 probe 16). |

### 1.6 Oracle validity rules (applied by the harness before any comparison)

An oracle run counts only if **all** of these hold. Otherwise the comparison is
reported as `ORACLE_INVALID`, not as a native failure.

- exit code 0;
- the output file exists;
- the log contains `Diffing results saved in file` (`D:2426`);
- the log has no `Timeout with heuristic`, and no heuristic span is longer than
  300 s (NO_FPS timeouts are silent, 02 §5.4);
- the sha256 of both inputs equals the manifest;
- `cdifflib` was absent (the import warning line is present);
- no `DIAPHORA_*` variable was set.

---

## 2. Parity harness

### 2.1 Native CLI

```
dsigmatcher diff <db1> <db2> [-o <out.diaphora>] [--engine parity|legacy] [--format diaphora|legacy]
                 [--trace <trace.jsonl>] [--trace-rows] [--snapshot-dir <dir>] [--snapshot-points <glob>]
                 [--replay <before-snapshot.json> --stage <stage-name> [--iteration k] [--heuristic id]
                  --snapshot-out <after.json>]
                 [--related-cu-source native|sql] [--allow-sqlite-mismatch] [--ignore-small-functions]
```

- `--engine parity` is the new default for `diff`. `legacy` keeps today's
  `matches` / `symbols_to_port` tables. `port` keeps using legacy until §4 L9.
- With no `-o`, the output name is Diaphora's default,
  `basename(stem(db1)) + "_vs_" + basename(stem(db2)) + ".diaphora"` (01 §1).
- The output is deleted first (`D:2379-2381`). An output path that aliases an input
  is refused (reuse `CanonicalPath` from `src/Provenance.cpp`).
- stderr gets Diaphora's summary lines with the same text:
  - `Current results: …` (`D:1622-1635`);
  - `Symbols stripped detected: …` and `Patch diffing detected: …` (`D:2562-2566`, `D:2609-2623`);
  - `Final results: …` and `Matched …` (`D:3684-3695`).

  They carry no timestamps, so a plain text diff against the oracle log (with
  timestamps stripped) works.
- Exit codes: 0 ok (this includes Diaphora's "empty result" case, §3.10), 2 usage,
  3 `DIAPHORA_WOULD_RAISE` (no output written, as in Python), 4 unsupported
  configuration or input quirk, 5 SQLite version mismatch, 6 I/O.

### 2.2 Trace and snapshot formats (shared by the native engine and the oracle instrumentation)

The exact JSON schemas are in Appendix B. Both producers must emit byte-compatible
field names. In summary:

- **Trace** (JSONL). One event per line:
  - `add_match`: context point, current heuristic or stage name, `name1`, `name2`,
    `ea1`, `ea2`, `desc`, `ratio_bits` (IEEE-754 bits as 16 lowercase hex digits),
    `chooser`, and `result` (`appended`, `duplicate` or `rejected_better`).
  - `cleanup`: site line number, per-site counter, and list sizes after the cleanup.
  - `point`: every snapshot point name, with list sizes.
  - optional `row` events (`--trace-rows`): one per consumed SQL row, with its
    decision (`nullsub`, `has_best`, `has_better`, `accepted_best`,
    `accepted_partial`, `below_min`).
- **Snapshot** (one JSON file per point):
  - point name and outer iteration;
  - flags: `is_same_processor`, `is_patch_diff`, `is_symbols_stripped`,
    `total_functions1/2`;
  - `all_matches` as three ordered lists of `[ea1, name1, ea2, name2, desc, ratio_bits, nodes1, nodes2]`;
  - `matched_primary` / `matched_secondary` as `[key, other, ratio_bits]` triples;
  - optionally `ratios_cache` as `["ea1-ea2", ratio_bits]`;
  - at `after:final_pass`, the raw chooser contents per chooser, in `add_item` order;
  - at `after:find_unmatched`, the two unmatched choosers (or `null`).
- **Point names** are listed in Appendix B. Examples: `after:find_same_name`,
  `before:heuristic:41`, `after:cleanup:3185:4`, `before:find_matches_diffing:0`,
  `before:final_pass`.

### 2.3 Oracle instrumentation (`tools/parity/oracle_trace.py`, Python)

- It imports the **unmodified** `<diaphora-ref>` read-only, with
  `sys.dont_write_bytecode = True` and `PYTHONDONTWRITEBYTECODE=1`. It never edits
  a file there.
- It wraps methods at run time. This is the same technique the spec authors used
  (02 §0, 06 §0 check 2). The wrapped methods are:
  - `add_match`, `cleanup_matches` (the call site comes from `sys._getframe(1).f_lineno`);
  - `check_match` (only with `--rows`);
  - the four `add_matches_from_*` wrappers (per-heuristic points; the heuristic is
    the thread name set by `threads_apply`, `threading.current_thread().name`);
  - every top-level stage method listed in Appendix B;
  - `CChooser.add_item` (raw chooser contents).

  Every wrapper calls the original with the original arguments and returns its
  result. Nothing is short-circuited.
- It replays `__main__`'s steps literally (`D:3757-3773`):
  `bd = CBinDiff(db1); bd.ignore_all_names = False; bd.db = sqlite3_connect(db1); bd.diff(db2); bd.save_results(out)`.
- It runs on **copies** of the two exports placed under
  `<corpus>/oracle/traces/<pair>/work/`, because Diaphora opens db1 read/write
  (`create_schema`, 01 §3.1). It uses `build_oracle.CleanEnv()` semantics.
- Output goes to `<corpus>/oracle/traces/<pair>/`: `trace.jsonl`,
  `snapshots/NNNNN_<point>.json`, `index.json` (points in order),
  `<pair>.diaphora`, `run.json`.
- Other options:
  - `--stop-at <point>`: capture a prefix of a long pair in minutes. It raises a
    private exception at that point and writes no `.diaphora`.
  - `--points <glob>`: limit which snapshots are written.
  - `--with-cache <glob>`: include `ratios_cache` at matching points.
  - `--force-const-order sorted|rsorted`: sensitivity measurement only (06 V4). It
    swaps in a verbatim copy of `find_related_constants` that iterates in a fixed
    order. Such a run is **never** used as the oracle.
- **Self-check.** An instrumented full run must produce a `.diaphora` identical in
  stored order to the oracle's `run1`. Otherwise the instrumentation is defective.

### 2.4 Native replay

- `--replay <before:X snapshot> --stage X` loads the flags and the state into
  `MatchState`. It can also seed `RatioEngine`'s cache from the snapshot's
  `ratios_cache`.
- It then runs exactly one stage function and writes the `after:X` snapshot.
- Replayable stages are the ones in Appendix B marked **R**. They include single
  heuristics, every loop sub-pass for a given iteration, `final_pass` and
  `find_unmatched`.
- The same entry point is available in-process to C++ tests, as
  `DSig::Diff::RunReplay`.

### 2.5 Comparison tools and reports (Python, `tools/parity/`)

| Tool | Does |
|---|---|
| `compare_results.py <oracle.diaphora> <native.diaphora> [--oracle-log] [--json out]` | Applies the L0/L1/L2 verdicts. Per `(type, description)` group it counts: matched in both, only in the oracle, only native, ratio mismatch (same pair, different text; also reports `|Δ|`), category mismatch (same pair, different type), description mismatch, name mismatch, nodes mismatch, and line or order mismatch. It also diffs `unmatched`. Descriptions are heuristic or pass names, so this is the per-heuristic and per-pass agreement table. |
| `compare_traces.py <a> <b>` | For two trace files, reports the first divergent event with 30 events of context, plus per-`(heuristic, stage)` counts of accepted `add_match` events on each side. For two snapshot directories, reports the first point whose snapshots differ, with an item-level diff. |
| `run_parity.py [--pairs …] [--long]` | Runs `dsigmatcher diff` on every valid oracle pair (§1.6). Checks input sha256 before and after. Calls `compare_results.py`. Writes `report.json`, `report.md`, native wall times and the per-group tables to `<corpus>/parity-reports/<timestamp>/`, **outside the repo**. Exits non-zero on any L2 failure. |
| `make_fixture.py <scenario.py> <outdir>` | Builds a Diaphora-schema fixture pair from `db_support/schema.py` `TABLES` plus every `INDICES` entry, then `analyze`, in WAL mode, exactly like a real export (07 §12). Runs **real** Diaphora on copies to produce the expected outputs. Emits text-only artefacts for the repo: `main.sql`, `diff.sql` (a dump that includes `sqlite_stat1` rows), `expected_results.tsv`, `expected_unmatched.tsv` and `oracle.json` (mode, final counts, SQLite version). |

### 2.6 C++ tests (ctest, no Python)

- `diff_foundation`:
  - registry checks against `tests/diff/generated/registry_expected.inc` (the
    sha256 of each verbatim SQL);
  - ingest census against `tests/diff/generated/corpus_census.inc`;
  - **row-sequence census**: for every default-run heuristic and every static stage
    query, on all 5 pairs, the Path A row sequence `(ea, ea2, description)` has the
    same count and sha256 as Python's `sqlite3` gives. This is the cheapest direct
    test that Path A reproduces the oracle's row order (07 §13).
  - Tests that need the corpus skip when `DSIG_CORPUS_ROOT` or the export is
    missing. Tests that need the oracle's SQLite skip unless `sqlite3_libversion()`
    is `3.51.1`.
- Lane suites (`diff_state`, `diff_ratio`, `diff_textdiff`, `diff_writer`,
  `diff_early`, `diff_tiers`, `diff_callee`, `diff_related`) each have three kinds
  of test:
  - pure unit tests;
  - vector tests (vectors generated from real Diaphora or the stdlib and committed
    as text; synthetic data only);
  - corpus replay tests that read oracle snapshots from
    `<corpus>/oracle/traces/…`. These skip when absent.
- `diff_parity` runs full native diffs in-process on the finished oracle pairs and
  compares them at L2, printing the first 20 differences.
  - It is gated by the environment variable `DSIG_PARITY=1` (fast pairs) or
    `DSIG_PARITY=long`, so ctest stays green while the engine is incomplete.
  - L9 flips the default to "run the fast pairs whenever the corpus exists".
- **Committed fixtures** (`tests/diff/fixtures/**`) are text. Tests build the
  SQLite files at run time with `tests/diff/FixtureDb.h`. They are compared at L2
  when the runtime SQLite is 3.51.1 and at L1 otherwise, so CI stays green on
  apt/brew/vcpkg SQLite builds.
- **Corpus-derived vectors are never committed.** Lane scripts write them under
  `<corpus>/oracle/vectors/`.

### 2.7 What is C++ and what is Python

| C++ (`src/diff`, `tests/diff`) | Python (`tools/parity`) |
|---|---|
| Everything that computes the result: ingest, Path A execution, consumer and state machine, ratio, difflib, all passes, the writer, trace and snapshot I/O, replay, all ctest suites | Oracle instrumentation and snapshots; the result, trace and snapshot comparators; parity runs and reports; fixture building; vector generators; registry and census generators |

---

## 3. Architecture changes

### 3.1 Layering

```
                  (pure)                                  (sequential, exact order)
Ingest ─► ExportData ─► Path A: SqlRowSource(verbatim SQL) ─┐
              │          native: CuReplaySource (plan-guarded)├─► Consumer (check_match / add_matches_*) ─► MatchState
              └─► RatioEngine (pure, cached, first-writer) ◄──┘                                              │
Pipeline (literal port of diff(), D:3568-3701) calls the stage functions in Diaphora's order ──────────────────┘
     └─► FinalPass ─► FindUnmatched ─► ResultsWriter (.diaphora) ; Trace/Snapshot at every point
```

### 3.2 New files

- Every header below is created by **L0** with its final public API. The headers
  are then **frozen**.
- Implementation-private state sits behind a pimpl (`struct Impl; std::unique_ptr<Impl>`),
  so owners never need to edit a header.
- If a lane needs an API change, the orchestrator approves it and L0-style rules
  apply.

```
include/dsigmatcher/diff/
  Config.h        DiffConfig (§1.1 defaults) + the C: constants used by the diff (0.5, 0.3, 0.01, 0.8, 0.006,
                  0.008, 99.0, 90.0, 0.6, 100, 25, 3, "3.4")
  Interner.h      Interner; NameId/DescId/AddrId; kNoneName (Python None, whose text in f-string keys is "None")
  Table.h         TextColumn{Pool,Offset(u64),Length,IsNull}, IntColumn{Value,IsNull,NotInteger}, FunctionTable (all
                  49 columns, rows in `order by id`), MdSqlReal/MdSqlNull, AddressSqlReal, SelectFieldsUtf8Bad,
                  AddrIdOf/NameIdOf/MangledIdOf, RowByAddr, RowsByName (ascending id); ExportData
  SideTables.h    program rows, version, table presence, row counts (the side-table contents are used through SQL)
  Database.h      DiffDatabase (main read-only via URI + `ATTACH 'file:<diff>?mode=ro' AS diff`), Statement,
                  ExplainQueryPlan(), LibVersion()/SourceId()/PragmaThreads()
  Candidates.h    HeuristicRow{Ea1,Ea2,Row1,Row2,Side1,Side2,Name1,Name2,Desc,Nodes1?,Nodes2?,Md1?,Md2?},
                  RowSource (virtual Next), SqlRowSource (Path A, reads aliases ea,name1,ea2,name2,description,
                  nodes1,nodes2,md1,md2 of SELECT_FIELDS, H:51-84), VectorRowSource
  Registry.h      HeuristicSpec{Id,Name,Category,RatioType,Min,HasMin,FlagUnreliable,FlagSlow,FlagSameCpu,Sql,
                  SqlSha256}; Heuristics() (50 entries); ApplyPostfix()
  StageSql.h      every non-registry SQL string used by the default diff (Appendix A), verbatim, with D: lines
  Json.h          minimal JSON DOM (numbers kept as text) for snapshots and Python-compat parsing
  Snapshot.h      StateSnapshot + Read/Write (Appendix B schema)
  Trace.h         Trace sink (JSONL, Appendix B) + stderr summary-line logger
  Errors.h        DiaphoraWouldRaise{Site,Detail}, UnsupportedInput{What}
  MatchState.h    Chooser{Best,Partial,Unreliable}, Item{Ea1,Name1,Ea2,Name2,Desc,Ratio(double),Nodes1,Nodes2},
                  MatchedEntry, CleanupSite{1551,2945,3185,3217,3340,3413,3471,3655,3671}, class MatchState
  Consumer.h      IRatioProvider; CheckMatch; AddMatchesInternal; AddMatchesFromQuery[Ratio|RatioMax|RatioMaxTrusted]
  Ratio.h         MdSource{Sql,Python}; class RatioEngine : IRatioProvider
  PyValue.h       PyValue (Python equality for JSON scalars), PyJsonLoadsList, PySet*, PyStr, PyFloat
  TextDiff.h      PySplitNewline, PySplitLines, CppNamesFindAll, SequenceMatcher, Opcode, UnifiedDiff
  ResultsWriter.h FinalResults, UnmatchedRow, WriteDiaphoraResults, FormatLine05/FormatAddr08x/FormatRatio7/AscTimeNow
  Stages.h        one function per Diaphora pass (listed per lane in §4)
  Pipeline.h      DiffArgs, DiffStatus, DiffOutcome, DiffSession, RunDiff, RunPipeline, RunReplay
src/diff/         Database.cpp Ingest.cpp SideTables.cpp Json.cpp Registry.cpp RegistrySql.inc(gen) StageSql.inc(gen)
                  Snapshot.cpp Trace.cpp Pipeline.cpp                               [L0]
                  MatchState.cpp Consumer.cpp FinalPass.cpp Unmatched.cpp            [L1]
                  Ratio.cpp PyValue.cpp                                               [L2]
                  TextDiff.cpp                                                        [L3]
                  ResultsWriter.cpp                                                   [L4]
                  stages/Preflight.cpp EqualMatches.cpp DirtyHeuristics.cpp SameName.cpp
                         RemainingFunctions.cpp PatchDiffHook.cpp                     [L5]
                  stages/HeuristicTiers.cpp SmallDifferences.cpp                      [L6]
                  stages/CalleeDiffing.cpp                                            [L7]
                  stages/RelatedConstants.cpp RelatedCompilationUnit.cpp LocalAffinity.cpp [L8]
```

Key signatures that the lanes build against. L0 writes them exactly like this; the
comments give the Diaphora source each one ports.

```cpp
namespace DSig::Diff {
// MatchState.h
class MatchState {
public:
  explicit MatchState(DiffSession& S); ~MatchState();
  void SetTotals(int64_t Total1, int64_t Total2);
  void AddMatch(NameId N1, NameId N2, double Ratio, const Item& It, std::optional<Chooser> C); // D:1340-1374
  bool HasBestMatch(NameId N1, NameId N2) const;                  // D:1376-1384
  bool HasBetterMatch(NameId N1, NameId N2, double Ratio) const;  // D:1386-1402
  void Cleanup(CleanupSite Site);                                 // D:1554-1605
  bool AllFunctionsMatched() const;                               // D:1777-1784
  size_t TotalMatchedFunctions() const;                           // D:3142-3148 (items in best+partial)
  std::vector<Item> SortedResults(Chooser C) const;               // D:3133-3140 (stable, desc, copy)
  const std::vector<Item>& Items(Chooser C) const;
  std::optional<MatchedEntry> Primary(NameId) const;  std::optional<MatchedEntry> Secondary(NameId) const;
  size_t PrimarySize() const;  size_t SecondarySize() const;
  StateSnapshot Export() const;  void Import(const StateSnapshot&);
private: struct Impl; std::unique_ptr<Impl> Impl_;
};
// Consumer.h
class IRatioProvider { public: virtual ~IRatioProvider() = default;
  virtual double CheckRatio(const HeuristicRow& Row, MdSource Src) = 0;     // check_match path (md from SQL cast)
  virtual double CompareFunctionRows(uint32_t MainRow, uint32_t DiffRow) = 0; };  // D:2479-2538 (md via Python float)
std::optional<double> CheckMatch(DiffSession& S, const HeuristicRow& Row);        // D:1786-1872
void AddMatchesInternal(DiffSession& S, RowSource& Rows, Chooser Best, std::optional<Chooser> Partial,
                        std::optional<double> Val = std::nullopt);                // D:1882-1948 (1M cap)
void AddMatchesFromQuery(DiffSession& S, RowSource& Rows, Chooser Category);      // D:2039-2083 NO_FPS
void AddMatchesFromQueryRatio(DiffSession& S, RowSource& Rows, Chooser Best, Chooser Partial);            // D:1950-1975
void AddMatchesFromQueryRatioMax(DiffSession& S, RowSource& Rows, Chooser Best, Chooser Partial, double V); // D:1977-2000
void AddMatchesFromQueryRatioMaxTrusted(DiffSession& S, RowSource& Rows, double V);                       // D:2002-2026
// Ratio.h
class RatioEngine final : public IRatioProvider { public:
  explicit RatioEngine(DiffSession& S); ~RatioEngine();
  void Prepare();                                   // after ingest and after IsSameProcessor is known (D:3617)
  double CheckRatio(const HeuristicRow& Row, MdSource Src) override;               // D:1645-1775
  double CompareFunctionRows(uint32_t MainRow, uint32_t DiffRow) override;
  void SeedCache(AddrId Ea1, AddrId Ea2, double R);  std::optional<double> Cached(AddrId, AddrId) const;
  static double QuickRatio(std::optional<std::string_view> A, std::optional<std::string_view> B); // D:150-165
  static double Round7(double V);                                                  // float("{0:.7f}".format(v))
  double DeepRatio(uint32_t MainRow, uint32_t DiffRow) const;                      // D:2749-2837
private: struct Impl; std::unique_ptr<Impl> Impl_; };
// TextDiff.h
std::vector<std::string_view> PySplitNewline(std::string_view S);      // str.split("\n")
std::vector<std::string_view> PySplitLines(std::string_view Utf8);     // str.splitlines(), 10 separators (03b §4.3.1)
std::vector<std::string_view> CppNamesFindAll(std::string_view Utf8);  // re.findall(CPP_NAMES_RE, s, re.I)[i][0], D:114
std::vector<std::string> UnifiedDiff(std::span<const std::string_view> A, std::span<const std::string_view> B,
                                     int N = 3, std::string_view LineTerm = "");   // difflib.py:1084-1161
// ResultsWriter.h
struct FinalResults { std::vector<Item> Best, Partial, Unreliable, Multimatch;
  std::optional<std::vector<UnmatchedRow>> UnmatchedPrimary /*diff funcs, D:2343-2354*/, UnmatchedSecondary /*main, D:2330-2341*/; };
void WriteDiaphoraResults(const WriteArgs& A, const FinalResults& R, const Interners& Ids);    // D:2374-2429
}
```

### 3.3 Data model and ingestion (`Ingest.cpp`, L0). Spec: 07 §4-§5, 08 §9

- `functions` is loaded with `select f.*, cast(f.md_index as real), cast(f.address as real) from functions f order by f.id`.
  - Check the storage class with `sqlite3_column_type` **before** extracting.
  - NULL stays NULL, never `''` (08 §9.1 rules 1-2).
  - Text keeps its exact bytes (`sqlite3_column_text` + `sqlite3_column_bytes`).
  - Each column gets its own pool with 64-bit offsets (07 T5).
- `MdSqlReal` comes **from SQLite**, because SQLite's cast is not correctly rounded
  for 28-digit strings: 2-3 real values in the corpus differ from Python `float()`
  (07 §5.3, 04a §2.3). The Python-`float()` value is computed by L2
  (`PyFloat`), not here.
- Per-row UTF-8 validity is recorded for every `SELECT_FIELDS` text column
  (`SelectFieldsUtf8Bad`). This lets native row sources reproduce Python's
  fetch-time `OperationalError` (01 §13).
- The side tables used by the default diff (`constants`, `compilation_units`,
  `compilation_unit_functions`, `instructions`, `bb_instructions`) are **read only
  through Path A SQL**. Ingest records only their presence and row counts. The
  `program` rows and the first `version` row are loaded (preflight needs them).
- Name, description and address texts are interned into `Interners`. The address
  of every item is an `AddrId`, and its text is the exact TEXT from the database.
  Python keys `ea_ratios`, `max_main`/`max_diff` and the ratio cache by this text.

### 3.4 Path A execution (`Database.cpp`, `Candidates.h`, L0)

- Connection setup:
  - `sqlite3_open_v2("file:<db1>?mode=ro", READONLY|URI)`, then
    `ATTACH 'file:<db2>?mode=ro' AS diff`;
  - `pragma threads` must stay 0, so the sorter is stable (04a §6.4);
  - never run `ANALYZE` and never create indexes: the files must stay byte-identical;
  - one connection for everything, since nested reads while a statement is active
    are fine.
- In parity mode, startup refuses to run (exit 5) unless `sqlite3_libversion()`
  equals the oracle's `3.51.1`, or `--allow-sqlite-mismatch` is given.
- CMake copies conda's `sqlite3.dll` beside the executables when it is found next
  to the linked import library, so that manual runs load the right DLL (07 §11.2).
- Parameters are bound with Python's types:
  - `str` becomes text (names, addresses, `str(constant)`);
  - `float` becomes double (CU bounds, `D:3453-3458`).
- `SqlRowSource::Next()` does the following:
  1. steps the statement;
  2. validates the UTF-8 of every TEXT column in the row, and throws
     `DiaphoraWouldRaise("fetch: invalid UTF-8")` if one is bad;
  3. maps `ea`/`ea2` text to rows through `RowByAddr`;
  4. interns the names and the description;
  5. reads `nodes1/2` and `md1/2` as optional values. Python's `int(None)` or
     `float(None)` is raised later, **at the consuming site**.

### 3.5 Registry and stage SQL (L0)

- `tools/parity/gen_registry.py` imports `diaphora_heuristics` from the reference,
  read-only, and emits `src/diff/RegistrySql.inc`. For each of the 50 entries it
  writes `name`, `category`, `ratio`, `min` (if present), the flags **list** and
  the verbatim final `sql` string (the one that still contains `%POSTFIX%`).
  - The SQL goes into raw string literals. The longest heuristic SQL is 3,723
    bytes (measured), so it fits under MSVC's 16 KB per-literal limit; the
    generator still splits any piece over 16 KB, as a guard.
  - It also writes `tests/diff/generated/registry_expected.inc`, which holds the
    counts and the sha256 of each SQL string.
  - Flags are list membership, not bits: `HEUR_FLAG_SAME_CPU = 3`, `H:44-48`
    (04a §2.1).
- The same script renders the stage SQL of Appendix A into `StageSql.inc`, using
  `diaphora_heuristics.get_query_fields`.
  - For each template it asserts that the literal pieces appear verbatim at the
    cited `D:` lines.
  - `%POSTFIX%` is applied with Python `str.replace` semantics, which replaces
    every occurrence. H10 (index 10) has two.

### 3.6 Driver (`Pipeline.cpp`, L0). Literal port of `D:3568-3701` (01 §5)

```
if !CheckVersion(): write empty results, exit 0            # D:3577-3591 (diff() returns False; save_results still runs)
EqualDb (log); CheckCallgraph (validate, may raise)         # D:661-687, D:1288-1338
FindEqualMatches (also sets totals)                         # D:1404-1442
IsSameProcessor = SameProcessor(); Ratio.Prepare()          # D:2950-2967, D:3617
skip = Experimental ? ApplyDirtyHeuristics() : false        # D:2629-2637
if !IgnoreAllNames: FindSameName(Partial)                   # D:3623-3624
if skip: FindRemainingFunctions()                           # D:2702-2716
else: RunCategory(Best); FindPartialMatches()               # D:1461-1552, D:2212-2221 (ML no-op; unreliable off)
      it=0; loop { Cleanup(3655); old=Total(); FindMatchesDiffing(it); if Slow: FindRelatedMatches(it);
                   FindRelatedCU(it); FindLocallyAffine(it); Cleanup(3671); if Total()<=old: break; ++it }
FinalPass(); FindUnmatched(); Write(); log final lines      # D:2937-2948, D:2323-2356, D:3684-3695
```

`RunDiff` is the only exception boundary. Its outcomes:

- `DiaphoraWouldRaise` → exit 3, and no output file.
- `UnsupportedInput` → exit 4.

Worker-thread truncation happens inside `StageRunHeuristicsForCategory` (L6), not
here.

### 3.7 State machine, consumer, final pass (L1)

These are exact ports of 01 §8-§10, 02 §6-§16 and 06 §12-§15. The points most often
got wrong are:

- **Keys.** State is keyed by `NameId`, never by row. `find_equal_matches` uses
  `mangled_function` keys (`D:1435-1440`).
- **Cleanup dedup key.** It is the **string** `name1 + "-" + name2`, with a `None`
  name rendered as `"None"`. The key is marked done **before** the `ea_ratios` test
  (02 §14 item 3).
- **Item membership.** `item not in list` uses a hash set of the 8-field tuple
  (with `1 == 1.0`), rebuilt after every cleanup.
- **`HasBetterMatch`.** When neither name is `sub_` and `name1` is already matched,
  it returns early and **ignores ratios**.
- **Same-name matches.** A same-name match stores a fake 1.0 in the state, and the
  next cleanup reverts it to the item's ratio.
- **Row cap.** It counts every fetched row, rejected ones included.
- **Sorts** are stable, descending, with a strict `>` on the double.
- **Final pass.** It is keyed by address text and ties become multimatches.
  `multi_main` and `multi_diff` share one `dones` set, and ignore flags are set only
  for items that were added. `add_final_chooser_items` drops every item below the
  per-ea1 or per-ea2 maximum.

### 3.8 Ratio engine (L2)

The spec is 03a. Implementation requirements:

- `QuickRatio` is a multiset intersection over pieces from `split("\n")`, with
  every distinct line interned per column.
- `Round7` uses the exact integer half-even algorithm of 03a §5. It is portable and
  avoids `from_chars`.
- `CheckRatio` keeps the evaluation order of 03a §6.3.
- `DeepRatio` adds its terms in order, with Python `None` semantics (03a §7.2).
- Constants use Python set semantics through `PyValue`.
- There are two md sources: `MdSqlReal` from ingest, and `PyFloat` of the text.
- The cache is keyed `(AddrId ea1, AddrId ea2)` and the first writer wins (03a §8).
- Exceptions are raised in Python's order: cache lookup, then `float(md)`, then the
  bytes-hash shortcut (03a §6.3).

### 3.9 difflib and text (L3)

The spec is 03b §4.3 and §5, plus 06 Appendix A.

- `SequenceMatcher` over interned `uint32` line ids, with autojunk (`n >= 200`,
  `count > n//100 + 1`, applied to `b` only).
- In the DP, a strict `>` keeps the first-found tie, and extension happens after
  the choice.
- `get_matching_blocks` uses the queue, then a sort, then an adjacent-block merge.
  `get_grouped_opcodes(3)` and `unified_diff(lineterm="")` emit the `"--- "` and
  `"+++ "` headers.
- `PySplitLines` works on UTF-8 code points.
- The `CppNamesFindAll` scanner works on code points and treats U+0130, U+0131,
  U+017F and U+212A as letters.

### 3.10 Writer (L4)

The spec is 01 §10.2-§11 and 09.

- The DDL is exactly Diaphora's statements.
- All values are bound as TEXT. `"%05lu"` counts per chooser **including** rows
  that `insert or ignore` later drops, which leaves gaps (01 E4).
- Formats: `"%08x" % int(ea)`, and `"%.7f"` correctly rounded.
- A `None` unmatched chooser writes no rows.
- The config row is `(db1 arg, db2 arg, "3.4", asctime)`.
- **Empty-result path.** If `diff.version` is missing or empty, the output has the
  `config` row and empty tables, and the exit code is 0 (01 §5.1).

### 3.11 Error model

- **Where exceptions are allowed.** The core style is "no exceptions" (07 §1.2).
  The parity engine uses them **inside** `DSig::Diff` because it is a literal port
  of Python propagation. They are converted to `DiffOutcome` at `RunDiff`.
- **Where each site raises.** Every Python raise site in the default path throws
  `DiaphoraWouldRaise(site)` at the same logical point:
  - 01 §13;
  - 07 §10.15;
  - 06 Hard parts 6.
- **What happens after the raise** depends on who called:
  - Heuristic workers (L6): NO_FPS swallows the error (`D:2080-2081`), and the
    RATIO* wrappers re-raise inside the thread (`D:1967-1973`). Either way that
    heuristic stops at that row, the adds made so far are kept, and the next
    heuristic runs.
  - Main-thread passes: the error propagates and the run aborts.
- Behaviour on the corpus is unaffected, because none of these conditions occurs in
  the 7 real exports (06 V5, 02 probe 14).

### 3.12 Build flags

- `dsigmatcher_diff` is a new static library, linked into `dsigmatcher`.
- MSVC gets `/fp:precise`; GCC and Clang get `-ffp-contract=off -fno-fast-math`
  (03a Hard parts 2). Never add `/arch:AVX2`, `-march=native` or `-ffast-math` to
  this library.
- `dsig_add_suite(<name> <src>)` is added once (07 §12). Every test source is
  listed explicitly. No globs.
- `DSIG_CORPUS_ROOT` and `DSIG_TEST_DATA_DIR` are passed to every `diff_*` suite.

### 3.13 Existing code

- Unchanged until L9: `Heuristics.*`, `MatchStore.*`, `ExportDatabase.*`,
  `Provenance.*`, `Naming.h`, `Types.h`, `bench/`, and all 5 existing suites
  (316 + 67 + 302 + 825 + 152,784 checks must keep passing).
- `src/main.cpp` gets the new `--engine`, `--format`, trace, snapshot and replay
  flags (L0).
- `README.md:41` says bit-exact scoring is out of scope, and its pipeline section
  describes an assignment model. L9 rewrites both.

---

## 4. Work lanes

### 4.0 Rules for every lane

- **Location.** Work only in your worktree of `<repo>`.
  Never touch `<repo-main-checkout>`. Never modify
  `<diaphora-ref>`: import it read-only with `-B` or
  `PYTHONDONTWRITEBYTECODE=1`, and run Diaphora only on **copies** of exports.
  Never re-run the oracle diffs stage.
- **Git.** No `git commit`, `push`, `stash` or branch operations. The orchestrator
  creates the worktrees, merges, and commits as **kuro1337WStuff**, with **no**
  `Co-Authored-By` or AI attribution (`AGENTS.md`). Journal notes (what changed,
  what was tested, what failed) go in the lane's final report. The orchestrator
  appends them to `JOURNAL.md`.
- **Files.** Edit only the files your lane owns. Frozen headers
  (`include/dsigmatcher/diff/*.h`), `CMakeLists.txt` and `src/main.cpp` belong to
  L0. After G0, change them only with orchestrator approval.
- **Build and test on this PC.**
  `<dsig-tools>\dsig_build.cmd <worktree> <scratch-build-dir> test`
  must print `BUILD_CLEAN` and `TESTS_PASSED`. `grep -iE "warning (C|:)"` on the
  build log must be empty (zero-warning policy, `/W4 /permissive-`).
- **Portability.** New code must compile on GCC, Clang and MSVC. Use no MSVC-only
  intrinsic without a portable fallback (for example, a 128-bit multiply). Tests
  that depend on the corpus or on SQLite 3.51.1 must **skip** cleanly without them,
  because CI has neither.
- **Evidence.** Every behavioural port cites `D:`/`H:`/`C:` lines in a comment
  next to the code. If source cannot settle a behaviour, write
  `NOT DETERMINED FROM SOURCE` in a comment and raise it in the lane report. Do not
  guess.

### 4.1 Waves and gates

```
Wave 0 (parallel): L0 Foundation (C++)          L0b Oracle instrumentation (Python)
        G0: skeleton builds; old suites green; foundation census green; oracle traces of the 3 finished pairs exist
Wave 1 (parallel): L1 State/Consumer/FinalPass   L2 Ratio   L3 difflib/text   L4 Writer + parity harness
        G1: each lane's replay/vector acceptance green
Wave 2 (parallel): L5 Pre-loop passes (mode P)   L6 Heuristic tiers   L7 Callee diffing   L8 Related + affinity
        G2: userenv pdb-vs-pdb full-run L2; all stage replays S-L2 on the available pairs
Wave 3 (single):   L9 Integration and parity closure
        G3: full-run L2 on the 3 finished pairs; long pairs per §1.5; then critics + audit (user)
```

**Long-pair prefix captures.** L0b should start detached instrumented captures of
the two long pairs as early as possible:

- `--stop-at before:find_related_compilation_unit:0` takes minutes;
- `--stop-at after:find_related_compilation_unit:0` takes about 2.5 h for userenv
  and about 17 h for sechost.

Wave-2 lanes use these captures when they exist, and do not block on them.

---

### L0: Foundation (one engineer, first)

- **Depends on:** nothing.
- **Owns:**
  - `CMakeLists.txt` and `src/main.cpp`;
  - every file in `include/dsigmatcher/diff/`;
  - `src/diff/Database.cpp`, `Ingest.cpp`, `SideTables.cpp`, `Json.cpp`,
    `Registry.cpp`, `RegistrySql.inc`, `StageSql.inc`, `Snapshot.cpp`, `Trace.cpp`,
    `Pipeline.cpp`;
  - `tests/diff/TestHarness.h`, `CorpusPaths.h`, `FixtureDb.h`,
    `ResultsCompare.h` (L1/L2 table compare **and** S-L2 snapshot compare) and
    `foundation_tests.cpp`;
  - `tests/diff/generated/*`;
  - `tools/parity/gen_registry.py` and `tools/parity/gen_corpus_census.py`;
  - **initial stubs** of every file that other lanes own (§3.2 list plus their test
    files). Each stub compiles. Stub stage functions throw
    `UnsupportedInput("stage X not implemented")`, and the pipeline catches that to
    log `SKIPPED` and continue. Stub test mains print `0 checks` and pass.
- **Spec:** 07 §4-§5, §11-§12; 08 §1, §8-§9; 01 §1, §5, §11; 02 §4-§5; 04a §2,
  §6.6; 09; this plan §2-§3 and Appendices A-B.
- **Implement:**
  - the headers of §3.2, with the signatures as given;
  - ingest (§3.3), Path A (§3.4), registry and stage SQL (§3.5), the driver (§3.6),
    the `RunReplay` dispatcher, trace and snapshot I/O (Appendix B);
  - the CLI (§2.1), the SQLite version guard, the DLL staging and the FP flags
    (§3.12).
- **Unit tests (`diff_foundation`):**
  - registry: 50 specs; categories 12/30/8; types NoFps 5 / Ratio 22 /
    RatioMax 22 / Trusted 1; flags enumerated from `HEURISTICS` while this plan was
    written (UNRELIABLE on 36-38; SLOW on 14, 21, 36-38, 41, 43-48; SAME_CPU on 0-3,
    5, 6, 9, 39); SQL sha256 equal to the generated file; `ApplyPostfix` on H10
    replaces both tokens (it has exactly 2);
  - snapshot and trace JSON round trip; the JSON parser on edge cases (bigints kept
    as text, escapes, `NaN` in compat mode);
  - `FixtureDb` builds a DB from `.sql`, with `sqlite_stat1` present;
  - corpus (skip if absent): for all 7 exports, ingest matches the census (row
    counts 304/318/643/628/663/1442/1419; NULL `pseudocode` 106/113/1/1/1/1/5;
    `name != mangled_function` 0/0/393/0/411/772/0; one `program` row each, `pc64`;
    `version = '3.4'`; export sha256 equal to the manifest);
  - SQLite 3.51.1 only (skip otherwise): the **row-sequence census** (§2.6) for all
    default-run heuristic SQL plus the Appendix A queries that need no bindings, on
    all 5 pairs;
  - `EXPLAIN QUERY PLAN` of `find_same_name` on the 4 pairs equals
    `SCAN f / MULTI-INDEX OR / … idx_3 … idx_2 … / USE TEMP B-TREE FOR DISTINCT`
    (02 Appendix C).
- **Acceptance (G0):**
  - clean build with zero warnings;
  - all 5 old suites green with unchanged check counts;
  - `diff_foundation` green;
  - `dsigmatcher diff <ls-old> <ls> -o x.diaphora` exits 0 and writes a valid
    `.diaphora` with Diaphora's exact DDL (`sqlite_master.sql` text equal to the
    oracle file's). The tables are empty because of the stubs;
  - `--snapshot-dir` writes every point name that Appendix B marks for mode N,
    with empty state.

### L0b: Oracle instrumentation (Python, parallel with L0)

- **Depends on:** nothing. It needs only the Appendix B schema.
- **Owns:** `tools/parity/oracle_trace.py`, `tools/parity/snapshot.py` (schema
  read/write/diff library), `tools/parity/compare_traces.py`,
  `tools/parity/README.md`. The generated data goes under
  `<corpus>/oracle/traces/` and is not committed.
- **Spec:** 09; 02 §0, §5.4, Appendix A; 06 §0, V3/V4; 01 §1; Appendix B of this
  plan.
- **Implement:** §2.3 in full, including `--stop-at`, `--points`, `--with-cache`,
  `--rows` and `--force-const-order`. Also `compare_traces.py` (§2.5).
  - Optional seed material from this session's scratchpad, if it still exists:
    `…/scratchpad/v06/instr.py`, the wrapper instrumentation used by 06 V3.
- **Tests:** a self-test mode that runs the three finished pairs twice and diffs
  the traces with timestamps ignored. `compare_traces.py` must report a planted
  divergence at the right event.
- **Acceptance on the oracle:**
  - For `ls-old_vs_ls`, `ls_vs_ls-old` and `userenv-9168-pdb_vs_9278-pdb`: the
    instrumented `.diaphora` is identical in stored order (results and unmatched) to
    oracle `run1`.
  - The `after:final_pass` chooser dump plus the `after:find_unmatched` dump
    reproduce the `.diaphora` rows.
  - Cleanup counts per site on `ls-old_vs_ls` equal 06 V3:
    3655×3, 3217×3, 3185×8, 3471×3, 3413×3, 3340×3, 3671×3, 2945×1, 1551×2.
    The outer totals are 206→287→291→291.
  - `git -C <diaphora-ref> status` is clean, and the export sha256 are
    unchanged.
  - The long-pair prefix captures have been launched detached (§4.1).

---

### L1: State machine, consumer, final pass, unmatched

- **Depends on:** L0, L0b.
- **Owns:** `src/diff/MatchState.cpp`, `Consumer.cpp`, `FinalPass.cpp`,
  `Unmatched.cpp`, `tests/diff/state_tests.cpp`, `tests/diff/vectors/state/**`,
  `tools/parity/gen_state_vectors.py`.
- **Spec:** 01 §6, §8-§10.3; 02 §2, §6-§16, §19; 05 §2.2-§2.5; 06 §2.3-§2.7,
  §12-§15; 07 §10.5, §10.12, §10.13.
- **Implement:**
  - `MatchState` (§3.7);
  - `CheckMatch`, with the call order nullsub → `has_best` → `CheckRatio`
    (`MdSource::Sql`) → `has_better` → the hook. When `S.HooksLoaded`, the hook
    calls `PatchDiffHookOnMatch` (L5);
  - `AddMatchesInternal` with the routing and the 1M cap, where the `unreliable`
    branch is dead (02 §10). `int(nodes)` raises after `check_match` accepts;
  - the four `AddMatchesFrom*` wrappers, including the `all_functions_matched()`
    early return;
  - `StageFinalPass` (`D:2937-2948`, `2839-2935`, `2732-2747`);
  - `StageFindUnmatched` (Path A `select name, address from functions` /
    `diff.functions`, with the labels swapped);
  - `Export` and `Import` for snapshots.
- **Unit tests.** Reproduce every documented probe exactly:
  - 02 Appendix A probe 1 (`hbm` outcomes, same-name fake, cleanup downgrade,
    ties, cross-category, `"a-b"+"c"` collision);
  - probe 10 (all 6 cleanup cases);
  - probe 6 (routing for RATIO, RATIO_MAX with min 0.2 and 0.7, TRUSTED 0.44, and
    maxrows 3 and 0), using a fake `IRatioProvider` and a `VectorRowSource`;
  - 01 E2 (multimatch split, the dropped same-name 0.9018889);
  - 01 §9.4 `KeyError` impossibility under defaults (as an assertion).
- **Acceptance on the oracle (S-L2), for the 3 finished pairs:**
  - For **every** cleanup call in the traces, `before:cleanup:<site>:<n>` →
    native `Cleanup(site)` → equals `after:cleanup:<site>:<n>`.
  - `before:final_pass` → native final pass → the chooser lists equal the oracle
    dump in order and in every field, and `line` numbering is implied by the order.
  - `after:final_pass` → `StageFindUnmatched` → equals `after:find_unmatched`.
  - The same checks on every long-pair prefix snapshot that exists.

### L2: Ratio engine and Python value semantics

- **Depends on:** L0, and L0b for the trace-based acceptance.
- **Owns:** `src/diff/Ratio.cpp`, `src/diff/PyValue.cpp`,
  `tests/diff/ratio_tests.cpp`, `tests/diff/vectors/ratio/**`,
  `tools/parity/gen_ratio_vectors.py`.
- **Spec:** 03a in full; 03b §4.1-§4.2; 07 §10.6; 08 §9.3, H-7, H-8.
- **Implement:**
  - §3.8;
  - `PyFloat` with Python `float()` semantics, correctly rounded. Try `from_chars`
    or C-locale `strtod` and verify with vectors on all three toolchains; otherwise
    port a correctly rounded parser;
  - `PyJsonLoadsList` with `json.loads` semantics: exact bigints, `NaN`/`Infinity`
    literals, strict control characters. A nested value is "unhashable" and raises
    when put in a set;
  - `PyValue` equality: int, float and bool compare across types by value; str
    compares by code points after unescaping;
  - `PyStr` (`str(constant)`);
  - `PySetIntersection`, in **first-appearance order of the main list**. This is a
    documented deviation, §5 R3.
- **Unit and vector tests** (generated by running the **real**
  `CBinDiff.check_ratio` / `compare_function_rows` in Python on synthetic
  Diaphora-schema pairs; the method is 03a §13):
  - 0 bit mismatches on both md paths across the 03a seed set;
  - the tie table of 03a §5; `0.99999995` → `0.9999999`; the next double →
    `1.0`; `2/3` → `0.6666667`;
  - the relaxed quirks are **not** needed;
  - md vectors where SQLite and Python disagree (for example
    `'3.050963036440351716676733804'`);
  - constant-set vectors from 03a §7.1;
  - the mutation table of 03a §13 must fail when each mutation is applied, as a
    self-test of the vectors;
  - `split("\n")` examples (`'a\nb\n'` vs `'a\nb'` gives 0.8).
- **Acceptance on the oracle:**
  - `gen_ratio_vectors.py --corpus` runs the real `check_ratio` (SQL path) and
    `compare_function_rows` over (a) every `(ea1, ea2)` that appears in any
    `add_match` event of the 3 finished traces, and (b) a 20k-pair random sample
    of each of the 5 pairs.
  - It writes the result to `<corpus>/oracle/vectors/ratio/`.
  - The native `CheckRatio` must be bit-identical on all of them.

### L3: difflib port, line splitting, name scanner

- **Depends on:** L0.
- **Owns:** `src/diff/TextDiff.cpp`, `tests/diff/textdiff_tests.cpp`,
  `tests/diff/vectors/textdiff/**`, `tools/parity/gen_textdiff_vectors.py`.
- **Spec:** 03b §4.3.1, §4.3.3, §5 (all subsections); 06 §6.1-§6.4, Appendix A;
  07 §10.11.1.
- **Implement:** §3.9, ported literally from `difflib.py` 3.13.12 (md5
  `60d095550edf66222f142d8bbb9feff5`, 03b §1).
  - Optional seeds, if present: `…/scratchpad/spec03b/port.py` and `hand.py`, the
    clean-room references with 0 mismatches.
- **Vector tests (committed, synthetic):**
  - ≥10,000 random `unified_diff` cases (lengths 0-1000, the 199/200/201
    boundaries, small alphabets, popular elements), checking the full row lists and
    `get_matching_blocks`;
  - every worked example of 03b §5.2 (the tie-break, the popular-extension case
    giving `(0,5,3)`, the empty-DP case);
  - `splitlines` over all 10 separators plus `\r\n`;
  - `CppNamesFindAll` on 120,000 strings including İ ı ſ K, and the 03b §4.3.3
    examples (`call Foo::Barbaz::x` → `['call','Barbaz::x']`,
    `mov eax, 0x401000` → `['x401000']`).
- **Acceptance on the oracle:** for every matched pair in the 3 finished oracle
  `.diaphora` files, and each field (`assembly`, `pseudocode`, both non-NULL), the
  hash of the native `UnifiedDiff(splitlines(a), splitlines(b))` row list equals
  Python's. The vectors are generated under `<corpus>/oracle/vectors/textdiff/`.

### L4: Results writer and parity harness

- **Depends on:** L0, and L0b for the snapshot-driven acceptance.
- **Owns:** `src/diff/ResultsWriter.cpp`, `tests/diff/writer_tests.cpp`,
  `tests/diff/parity_tests.cpp`, `tests/diff/fixtures/common/**`,
  `tools/parity/make_fixture.py`, `tools/parity/compare_results.py`,
  `tools/parity/run_parity.py`.
- **Spec:** 01 §10.2-§12; 09 "Results database schema"; 02 §16; 06 §16;
  §1.3-§1.6 and §2.5-§2.6 of this plan.
- **Implement:**
  - §3.10;
  - `FormatRatio7` with `std::to_chars(fixed, 7)`. Test it against 03a's tie
    table; L9 cross-checks it against `RatioEngine::Round7`;
  - `FormatAddr08x`, which parses the canonical decimal into `uint64` and prints
    lowercase hex with a minimum width of 8 (`4294967296` → `100000000`);
  - `FormatLine05` (`123456` → `123456`);
  - `AscTimeNow`, local time in the form `Wed Sep  3 …`;
  - the Python tools of §2.5;
  - `parity_tests.cpp` (§2.6).
- **Unit tests:**
  - DDL text equality;
  - every value `typeof = 'text'`;
  - a duplicate `(address, address2)` across best and multimatch is dropped, with a
    `line` gap (01 E4, 02 probe 9 case A);
  - `None` choosers write no rows;
  - the empty-result path.
  - For `compare_results.py`: self-compare passes, and planted drop, ratio, type
    and description changes are classified correctly.
- **Acceptance on the oracle:** feed the oracle's `after:final_pass` and
  `after:find_unmatched` raw chooser dumps for the 3 finished pairs into
  `WriteDiaphoraResults`. The resulting `.diaphora` must be **L2-identical** to
  oracle `run1`, with only `config.date` differing. `run_parity.py` must correctly
  mark the running pairs `ORACLE_INVALID`/`PENDING`.

---

### L5: Pre-loop passes and patch-diff mode (first full-run milestone)

- **Depends on:** L0, L0b, L1, L2, L3, L4.
- **Owns:** `src/diff/stages/Preflight.cpp` (version, `equal_db` log,
  `check_callgraph` validation including `Decimal`/JSON checks,
  `StageSameProcessor`), `EqualMatches.cpp`, `DirtyHeuristics.cpp`, `SameName.cpp`,
  `RemainingFunctions.cpp`, `PatchDiffHook.cpp`, `tests/diff/early_passes_tests.cpp`,
  `tests/diff/fixtures/early/**`.
- **Spec:** 01 §5.1-§5.9 and §13; 05 §3, §5-§9, §16-§18, §19.1; 07 §10.7-§10.9;
  03b §4.4 (hook); 08 §7.1-§7.2.
- **Implement:**
  - All SQL via Path A (Appendix A).
  - Stripped mode: `percent >= 99.0` as a double division. It runs through
    `AddMatchesFromQueryRatio` on the main thread, so errors propagate.
  - Patch-diff mode: `percent > 90.0` over the **pair** count, then set
    `IsPatchDiff` and `HooksLoaded`.
  - `find_same_name`: `all_functions_matched` is checked once, before the loop.
    Rows whose `mangled1` starts with `sub_` are skipped. The best item stores the
    int `1`. A partial gets `+0.01` only when `r + 0.01 < 1.0`, and there is no
    floor (05 H5).
  - `get_unmatched_functions` (`UNION`) and `search_remaining_functions`, which
    runs one query per pair with text binds and `val = 0.6`.
  - `PatchDiffHookOnMatch`, which reproduces **only the raising conditions** of
    `scripts/patch_diff_vulns.py` `on_match` / `find_vulns_using_assembly` /
    `find_vulns_using_pseudocode`. Read them verbatim from the script.
    - It uses `UnifiedDiff(..., LineTerm="\n")` over `split("\n")`, and keeps the
      `str([name1, name2])` dedup key.
    - When a raising condition is met, throw `DiaphoraWouldRaise`.
    - The hook's return value is always `(True, ratio)`.
- **Unit and fixture tests:**
  - 05 §19 scenarios A-E rebuilt with `make_fixture.py`: normal, stripped
    (19 best / 1 partial 0.878), patch, equal+mangled (duplicate best items, line
    gap, extra keys), and the quirks case (partial 0.003);
  - the E8 / probe 11 `IndexError` triggers;
  - `total_functions1 == 0` gives `DiaphoraWouldRaise`;
  - a missing `diff.version` gives the empty result.
- **Acceptance on the oracle:**
  - `userenv-9168-pdb_vs_9278-pdb` **full native run at L2**: mode P, and
    `Final results: Best 635, Partial 8, Unreliable 0, Multimatches 0`.
  - S-L2 for `after:find_equal_matches`, `after:apply_dirty_heuristics` and
    `after:find_same_name` on all 5 pairs. The long pairs use the prefix captures.
    sechost has 4 "100% equal" rows (05 §19.1).
  - The dirty percentages equal 05 §19.1 (37.500, 35.849, 15.811, 9.331, 100.000).

### L6: SQL heuristic tiers and small differences

- **Depends on:** L0, L0b, L1, L2.
- **Owns:** `src/diff/stages/HeuristicTiers.cpp`
  (`StageRunHeuristicsForCategory`, `StageRunSingleHeuristic`,
  `StageFindPartialMatches`), `src/diff/stages/SmallDifferences.cpp`,
  `tests/diff/tiers_tests.cpp`, `tests/diff/fixtures/tiers/**`.
- **Spec:** 01 §5.10-§5.12; 02 §4-§5, §10-§13; 04a §1-§5 and §10; 04b §3-§5 and
  §7; 05 §10-§11; 07 §10.3-§10.4, §10.10, §10.14.
- **Implement:**
  - The list build in `HEURISTICS` order, with the build-time
    `all_functions_matched` break and the flag filters (UNRELIABLE, SLOW, SAME_CPU).
  - Execution in **reverse**, each heuristic running to completion before the next
    (`jkutils/threads.py:40`).
  - Dispatch by `RatioType` with `%POSTFIX%` replaced. `min` applies only to the
    RATIO_MAX and TRUSTED types.
  - Per-heuristic `DiaphoraWouldRaise` truncation (§3.11).
  - `Cleanup(1551)` after each category.
  - `search_small_differences`:
    - it streams with no cap and never checks `all_functions_matched`;
    - `has_better_match` runs on the names ratio before `check_match`;
    - an empty-set `ZeroDivisionError` raises;
    - `json.loads(None)` on the diff side raises.
- **Unit and fixture tests:**
  - 02 probe 3 / 01 E1: every pair is labelled `Equal assembly` under reverse
    order, and `Same order and hash` under forward order (as a negative control);
  - 02 probe 5 (UNION tie → `sub_9100` wins);
  - flag filtering on different-CPU fixtures (5 Best / 26 Partial run).
- **Acceptance on the oracle.** For every Best and Partial heuristic that runs on
  `ls-old_vs_ls`, `ls_vs_ls-old` and, where prefix captures exist, the two long
  pairs:
  - `before:heuristic:<id>` → `StageRunSingleHeuristic(id)` → S-L2 equal to
    `after:heuristic:<id>`;
  - the category-level replays `after:find_same_name` →
    `after:run_heuristics_for_category:Best` and → `…:Partial` → S-L2;
  - `before:search_small_differences` → S-L2.

### L7: Callee diffing ("Callee found diffing matches …")

- **Depends on:** L0, L0b, L1, L2, L3.
- **Owns:** `src/diff/stages/CalleeDiffing.cpp`, `tests/diff/callee_tests.cpp`,
  `tests/diff/fixtures/callee/**`.
- **Spec:** 03b §4.3; 06 §4-§6 (including §6.7 churn); 07 §10.11.1; 02 §3.
- **Implement:** `find_matches_diffing`, `find_matches_diffing_internal` and
  `find_one_match_diffing` literally:
  - the leading `Cleanup(3217)`; assembly only when `IsSameProcessor`; inner
    iterations 1..3 that stop on `new == old`; `Cleanup(3185)`;
  - one **string-keyed** `dones` set shared by match keys and callee keys;
  - seeds taken from `SortedResults` snapshots (best, then a partial snapshot taken
    after the best loop);
  - rows fetched by name through Path A `get_function_row` (`D:2445-2460`);
  - the diff walk with the header rows in the buffers, trailing blocks never
    flushed, and positional pairing;
  - `functions_exists` through Path A (`D:2969-2991`, which requires exactly 2
    rows). If a duplicate-name "two rows from one database" case occurs, throw
    `UnsupportedInput`;
  - the `(min*100)/max` true division, where `max == 0` raises;
  - `CompareFunctionRows`; `best` if `r == 1.0`, `partial` if `r > 0.3`;
  - the bonus added **after** the chooser is picked;
  - the description `f"{heur} (iteration #{inner})"`.
- **Unit and fixture tests:**
  - 03b experiment A: `alpha_old_callee→beta_new_callee`, partial `0.9008889`,
    `(iteration #1)`; `gamma→delta` is never found;
  - experiment Z: `nodes = 0` on both sides raises;
  - the §4.3.2 quirks 1-4;
  - 06 V2 (`jmp` is not extracted; a leading-deletion block is discarded).
- **Acceptance on the oracle:**
  - For each outer iteration `k` of both ls pairs:
    `before:find_matches_diffing:k` → S-L2 equal to `after:find_matches_diffing:k`.
    The trace-level check is 716 assembly and 426 pseudocode
    `find_one_match_diffing` calls on `ls-old_vs_ls` (06 V3).
  - The same for iteration 0 of the long pairs, from the prefix captures.

### L8: Related constants, related compilation unit, local affinity

- **Depends on:** L0, L0b, L1, L2.
- **Owns:** `src/diff/stages/RelatedConstants.cpp` (also `StageFindRelatedMatches`),
  `RelatedCompilationUnit.cpp`, `LocalAffinity.cpp`, `tests/diff/related_tests.cpp`,
  `tests/diff/fixtures/related/**`.
- **Spec:** 06 §7-§11; 07 §10.11.2-§10.11.4; 02 §18.2; 08 H-4.
- **Implement:**
  - `find_related_matches`: `Cleanup(3471)`; best, then partial, from sorted
    snapshots; a local string `dones`; a **per-category** `break` at `ratio < 0.8`;
    rows by name; `constants_count > 0` on both sides.
  - `find_related_constants`: Path A SQL for each constant in the intersection,
    bound as `PyStr` text. The iteration order is the documented deviation (§5 R3).
  - `find_related_compilation_unit`:
    - `Cleanup(3413)`; one list, best followed by partial; a **whole-loop**
      `break` at `< 0.8`;
    - the CU lookup through Path A (`fetchone`);
    - `PyFloat` bounds;
    - the cartesian replay through `CuReplaySource`. It walks `(f.id, df.id)` in
      ascending order with `lo <= AddressSqlReal <= hi`, and runs only if
      `ExplainQueryPlan(kSqlCuCartesian)` is exactly `SCAN f` / `SCAN df`.
      Otherwise, or with `--related-cu-source sql`, it uses `SqlRowSource`;
    - `SelectFieldsUtf8Bad` rows raise the same way a Python fetch would;
    - it goes through `AddMatchesInternal` with the cap;
    - there is no dedup across seeds.
  - `find_locally_affine_functions`:
    - `Cleanup(3340)`; the best and partial items sorted by `[int(ea1), int(ea2)]`;
    - gap queries through Path A (`D:3236-3240`, text binds, so the ranges are
      lexicographic);
    - `MAX_FUNCTIONS_PER_GAP` 100;
    - the `nullsub_` and "at least one `sub_`" filters;
    - the `pseudocode_lines == 3` rule;
    - no `has_best_match` gate;
    - local score maps, written even when `add_match` rejects.
- **Unit and fixture tests:**
  - the 06 §8.3 `abs()` table (the `constants` rows that pass);
  - the 06 §11.1 lexicographic probe values (`4096 < a < 8192` selects `40970`);
  - CU `first_cu` with a function in two CUs (fixture only);
  - `CuReplaySource` and `SqlRowSource` give identical sequences on fixtures.
- **Acceptance on the oracle:**
  - For each iteration of both ls pairs, the three sub-passes each reach S-L2
    (from `before:` to `after:`).
  - For userenv and sechost iteration 0, `find_related_matches` reaches S-L2, and
    so does `find_related_compilation_unit` once the long capture exists.
  - The native and SQL CU replays produce identical row sequences for the first 50
    seeds on userenv and sechost.
  - **Performance:** the native `find_related_compilation_unit` for userenv
    iteration 0 finishes in under 5 minutes on this PC. Python took 2 h 23 min.
    Report the measured time.

---

### L9: Integration and parity closure (single engineer, may edit any file, sequentially)

- **Depends on:** L0-L8.
- **Owns:**
  - **Merge fixes** anywhere, one at a time, each with its evidence.
  - Flipping the `diff_parity` default (§2.6).
  - `README.md` scope and pipeline sections, and `HANDOFF.md`. `JOURNAL.md` is
    appended by the orchestrator.
  - Optionally, switching `port` to the parity engine, only after G3.
- **Work:**
  1. Run `run_parity.py` on all valid pairs. For each failure, bisect it:
     1. `compare_traces.py` on the snapshots, to find the first differing point;
     2. replay that stage;
     3. `--trace-rows`, to find the row.
  2. Cross-check `FormatRatio7` against `Round7` on 10^6 random doubles plus the tie
     table.
  3. When the long oracle runs finish (`findstr /c:"Final results" …\diaphora.log`),
     apply §1.6, then run a full native diff and compare at L2.
  4. Run `oracle_trace.py --force-const-order sorted|rsorted` on sechost to measure
     R3. If the outputs differ, list the affected
     "Same constants related matches" rows as the tolerated class.
- **Acceptance (G3):**
  - full-run L2 on the 3 finished pairs;
  - the long pairs per §1.5;
  - every suite green locally with zero warnings;
  - `run_parity.py` report archived with native wall times.
  - Then the user's critics and audit steps. CI workflow verification is a separate,
    later task (§5 R1).

### 4.x Post-parity lanes (not part of this plan's gate; the user's "other stuff")

- **Path B generators.** Native hash-join generators per heuristic group, each
  required to match Path A **row for row** on all pairs, under a plan guard.
- **CPython set-order emulation** (siphash13, set probing) for R3.
- **SQLite 3.51.1 amalgamation for CI.** Pin the amalgamation with conda's compile
  options and upgrade CI fixtures from L1 to L2.
- **Retire the legacy engine.** Retire `MatchStore`/`Heuristics.cpp` and the
  `resolve_tests` MatchStore suites.
- **Performance.** Fusion, AVX-512 and threading, following `HANDOFF.md`.

---

## 5. Risks and the things that cannot be bit-exact

| # | Risk | Why | Containment | Measurement |
|---|---|---|---|---|
| R1 | Row order depends on the SQLite build, its compile options, the `sqlite_stat1` in the files, and `pragma threads` | 02 §18.3; 04a §6.4 (the sorter is stable only single-threaded); 05 H1 | Use Path A with the oracle's DLL (3.51.1), unmodified inputs, `threads = 0`, and the version guard (§3.4). CI runs other SQLite versions, so CI fixtures compare at L1. | Row-sequence census in `diff_foundation`. The first real test of a new SQLite build is that census. |
| R2 | The long oracle pairs may never produce valid output. The main-thread related-CU call has a 300 s clock (`D:1894-1896`), which exits 0 with no file, and the observed margin is about 2x (02 §5.4). | Wall clock plus machine load | §1.6 validity rules. Fall back to S-L2 on every prefix snapshot. If needed, add a capture of the full run under `oracle_trace.py` on an idle machine. | `run.json`, the log checks, `determinism.json` |
| R3 | `find_related_constants` iterates a Python `set`, and the order of its string elements depends on `PYTHONHASHSEED` (`D:3389`). The native engine cannot reproduce CPython's order. | Only string constants with a zero numeric prefix produce rows (06 §8.3). sechost has 8 exposed seed pairs (06 V6). A seed changed the iteration-0 state, and the next cleanup erased the difference (02 probe 16). | The native engine iterates in first-appearance order of the main list, which is documented. If sensitivity is observed, differences confined to "Same constants related matches" rows are reported as a separate tolerated class. The tolerance is never silent. Emulation stays available as a post-parity lane. | L9 sorted/rsorted forced-order runs; oracle run1 vs run2 |
| R4 | Two md conversions plus a first-writer cache. SQLite's cast is not correctly rounded (03a §6.4). | Different `md_index` texts can collide under one parser and not the other | Carry both values: `MdSqlReal` from SQLite itself, never `from_chars`; `PyFloat` correctly rounded; key the cache by `(ea1, ea2)`, first writer wins. | L2 corpus vectors on both paths |
| R5 | Floating-point operation order and contraction | Exact ties decide multimatches | `/fp:precise`, `-ffp-contract=off`, no fast-math; the exact evaluation order of 03a §6.3 and §7.2; the integer `Round7` | L2 bit-exact vectors; FMA mutation test on clang/gcc in L9 or CI |
| R6 | Crash semantics. Diaphora writes no file on main-thread exceptions and truncates worker heuristics. | Inputs with NULLs, bad JSON, `nodes = 0`, invalid UTF-8, or the patch-diff hook's `IndexError` | Lazy `DiaphoraWouldRaise` at the Python sites (§3.11); exit 3 with no output. None of these conditions occurs on the 7 real exports. | L5/L7 fixtures for each raise site |
| R7 | Timeouts (300 s) are not reproducible | Wall clock | Not emulated. Oracle runs that hit one are rejected (§1.6), including the silent NO_FPS case. | Log span check |
| R8 | Related-CU cost. Path A would materialize about 45 columns, including large text, for about 738k rows per seed. | Plan `SCAN f` / `SCAN df` (02 Appendix C) | A native replay generator behind a plan guard, validated against Path A (L8) | L8 timing target; sequence equality on 50 seeds |
| R9 | Name-keyed quirks the corpus never exercises: duplicate names, `-` in names that makes key strings collide, `mangled_function` vs `name` keys | 0 duplicate names in all 7 exports (02 probe 14) | A literal port with string keys. Fixtures cover `mangled` vs `name` (05 scenario D). The `functions_exists` same-DB quirk raises `UnsupportedInput` rather than being guessed. | Fixture tests; the census flags duplicates in new inputs |
| R10 | The difflib port is inexact | Autojunk and tie-break rules (03b Hard parts 1) | A literal port plus 10k-case fuzz vectors and corpus hashes | L3 acceptance |
| R11 | Lexicographic address comparisons | Real exports have uniform digit lengths, so this is untested (06 OQ5) | Gap queries go through Path A, so they are exact by construction. The native CU replay uses the REAL cast, as the SQL does. | Fixture with a digit-boundary crossing |
| R12 | Oracle environment drift: IDA version, host DLLs, cdifflib, an edited `diaphora-ref` | 09 caveats | Compare only against exports whose sha256 is in the manifest. Check the reference `git describe` and that it is clean. Check that cdifflib is absent. | `run_parity.py` preflight |
| R13 | Parallel-lane integration: a lane needs an API change, or its stub semantics mismatch | Frozen headers | pimpl-backed frozen API. Changes go through the orchestrator. S-L2 replays isolate each stage. | G1/G2 gates |
| R14 | Scope. Path A may be judged "not native enough" (07 OQ2). | Policy | It is C++ over the SQLite C API. Path B stays as the post-parity optimisation, validated row for row. | User decision (§6) |

**Not bit-exact by design, and how that is reported:**

1. Wall-clock timeouts (R7): runs that hit one are rejected.
2. CPython `set` order in related constants (R3): a separate tolerated class, with
   its own counts.
3. Behaviour on inputs where Diaphora crashes: the native engine also refuses (exit
   3). "No file" matches "no file".
4. Row order on a SQLite other than 3.51.1 (R1): L1 only.
5. Non-default configurations, hooks and env overrides: refused (exit 4).
6. An oracle run with `cdifflib` installed: not an oracle.

---

## 6. Decisions needed from the user (defaults are taken if nobody objects)

1. **Parity engine = Path A.** The parity engine uses Diaphora's SQL through the
   SQLite C API (default: yes). Native joins come after parity, as validated
   accelerators.
2. **Parity mode refuses a non-3.51.1 SQLite unless overridden** (default: yes).
3. **CLI defaults.** `diff` defaults to the parity engine and `.diaphora` output,
   and the legacy tables stay behind `--engine legacy` (default: yes). `port` moves
   to the new engine after G3.
4. **Crash inputs.** The native engine mirrors "no output" with exit 3 (default:
   yes).
5. **Timeline.** The sechost oracle may take more than a day, so G3 accepts S-L2
   prefixes for it until it finishes (default: yes).

---

## Appendix A: stage SQL inventory (all verbatim in `StageSql.inc`; line numbers checked)

| Constant | Diaphora source | Binds |
|---|---|---|
| `kSqlVersion` | `D:3578` `select value from diff.version` | none |
| `kSqlEqualDbMd5`, `kSqlEqualDbExcept` | `D:668`, `D:673-680` | none |
| `kSqlCallgraph` | `D:1294-1296` | none |
| `kSqlTotals` | `D:1411-1413` | none |
| `kSqlEqualMatches` | `D:1424-1430` (`fields = "id, address, mangled_function, nodes, edges, size, bytes_hash"`) | none |
| `kSqlSameProcessor` | `D:2957-2960` | none |
| `kSqlStrippedCount`, `kSqlStrippedRows` | `D:2551-2554`, `D:2569-2577` (`get_query_fields('Same binary with symbols stripped')`) | none |
| `kSqlPatchCount` | `D:2599-2603` | none |
| `kSqlSameName` | `D:2158-2166` (`get_query_fields('Perfect match, same name')`) | none |
| `kSqlSmallDifferences` | `D:2093-2106` | none |
| `kSqlUnmatchedUnion` | `D:2647-2650` | none |
| `kSqlRemainingPair` | `D:2675-2685` (`get_query_fields("?", quote=False)` + `" and f.nodes >= 3 and df.nodes >= 3 "`) | desc text, ea1 text, ea2 text |
| `kSqlUnmatchedMain`, `kSqlUnmatchedDiff` | `D:2330`, `D:2343` | none |
| `kSqlFunctionRowMain`, `kSqlFunctionRowDiff` | `D:2453` (`select * from {db}.functions where name = ?`) | name text |
| `kSqlFunctionsExists` | `D:2976-2988` | name1 text, name2 text |
| `kSqlGapMain`, `kSqlGapDiff` | `D:3236-3240` | ea texts |
| `kSqlRelatedConstants` | `D:3375-3387` | `str(constant)` text |
| `kSqlCuLookupMain`, `kSqlCuLookupDiff` | `D:3419-3427` | name text |
| `kSqlCuCartesian` | `D:3429-3433` (`get_query_fields('Related compilation unit')`) | 4 doubles |

`get_query_fields`/`SELECT_FIELDS` are at `H:51-84`. All 50 heuristic SQL strings
come from `HEURISTICS[i]["sql"]` (`H:89-1177`).

## Appendix B: trace and snapshot schema

**Snapshot file** (`snapshots/NNNNN_<sanitised point>.json`; `index.json` lists `[seq, point, file]`):

```json
{ "schema": "dsig-parity-snapshot/1", "producer": "diaphora-3.4.2-4-g621ec26|dsigmatcher-<ver>",
  "pair": "ls-old_vs_ls", "seq": 17, "point": "before:find_matches_diffing:0", "iteration": 0,
  "flags": {"is_same_processor": true, "is_patch_diff": false, "is_symbols_stripped": false,
            "hooks_loaded": false, "total_functions1": 304, "total_functions2": 318},
  "all_matches": {"best": [["4198400","foo","4202496","foo","Perfect match, same name","3ff0000000000000",5,5]],
                  "partial": [], "unreliable": []},
  "matched_primary":   [["foo","foo","3ff0000000000000"]],
  "matched_secondary": [["foo","foo","3ff0000000000000"]],
  "ratios_cache": [["4198400-4202496","3fee666666666666"]],            // optional
  "choosers": {"best": [[ea, name, ea2, name2, desc, ratio_bits, nodes1, nodes2]], "partial": [],
               "unreliable": [], "multimatch": []},                       // only at after:final_pass
  "unmatched": {"primary": [[ea, name]] , "secondary": null} }          // only at after:find_unmatched
```

Field rules:

- Names can be `null` (Python `None`).
- `ratio_bits` is `struct.pack('>d', float(x)).hex()`. Python's int `1` and `0`
  serialise as `1.0` and `0.0`, which is correct because `1 == 1.0`.
- `matched_*` are listed in dict insertion order. Comparison treats them as maps.

**Trace line:**

```json
{"ev":"add_match","seq":1234,"ctx":"heuristic:41","name1":"…","name2":"…","ea1":"…","ea2":"…",
 "desc":"Loop count","ratio_bits":"…","chooser":"partial","result":"appended|duplicate|rejected_better"}
```

The other event types are `{"ev":"cleanup","site":3185,"n":4,"best":…,"partial":…,"unreliable":…}`,
`{"ev":"point","name":"…","best":…,"partial":…,"unreliable":…}` and, with `--rows`,
`{"ev":"row","ctx":…,"ea1":…,"ea2":…,"decision":…,"ratio_bits":…}`.

**Point names.** Those marked **R** are replayable by the native engine. `<id>` is
the `HEURISTICS` index, `<k>` the outer iteration and `<n>` the per-site call
counter, which starts at 1.

| Point | Wrapped Diaphora method |
|---|---|
| `after:find_equal_matches` | `find_equal_matches` `D:1404` |
| `after:apply_dirty_heuristics` | `apply_dirty_heuristics` `D:2629` |
| `before:`/`after:find_same_name` **R** | `find_same_name` `D:2152` |
| `before:`/`after:find_remaining_functions` **R** (modes S and P) | `D:2702` |
| `before:`/`after:heuristic:<id>` **R** | `add_matches_from_query*` `D:1950`/`1977`/`2002`/`2039`, from the thread name |
| `after:run_heuristics_for_category:<Best/Partial>` | `D:1461` |
| `before:`/`after:search_small_differences` **R** | `D:2085` |
| `before:`/`after:cleanup:<site>:<n>` **R** | `cleanup_matches` `D:1554`; site = caller line (1551, 2945, 3185, 3217, 3340, 3413, 3471, 3655, 3671) |
| `before:`/`after:find_matches_diffing:<k>` **R** | `D:3211` |
| `before:`/`after:find_related_matches:<k>` **R** | `D:3462` |
| `before:`/`after:find_related_compilation_unit:<k>` **R** | `D:3395` |
| `before:`/`after:find_locally_affine_functions:<k>` **R** | `D:3315` |
| `before:`/`after:final_pass` **R** | `D:2937` (the `after:` snapshot includes the raw `CChooser.add_item` contents) |
| `after:find_unmatched` **R** (from `after:final_pass`) | `D:2323` |

A "before" snapshot is taken at function entry, before the function's own leading
`cleanup_matches`. Replaying `X` from `before:X` runs `X` completely.

`heuristic:<id>` points are emitted only when the `add_matches_from_*` wrapper runs
on a heuristic worker thread. The thread's name is the heuristic `name`, set by
`threads_apply`; map it to its `HEURISTICS` index. The same wrappers are also
called on the main thread by the stripped pass (`D:2580`), and those calls are
covered by `apply_dirty_heuristics`. Calls made from a main-thread direct
`add_matches_internal` are covered by their enclosing stage points: related
constants `D:3391`, related CU `D:3458` and remaining functions `D:2696`.

---

## 7. Orchestrator decisions and added lanes (2026-09-23, supersede §6 and extend §4)

### 7.1 Decisions (§6)

- **D1 Path A:** accepted. Parity comes first. Native hash-join generators and fusion
  are post-parity and must match Path A row for row.
- **D2 SQLite version:** **warn, do not refuse.**
  - If `sqlite3_libversion()` is not `3.51.1`, parity mode prints one stderr warning
    and continues. The warning says row order may differ from the oracle, so results
    compare at L1.
  - `--strict-sqlite` gives the old behaviour: exit 5.
  - The L2 gate tests still run only under 3.51.1.
  - Reason: the tool will be called by another program and must not refuse to run on
    a different SQLite. Vendoring the SQLite 3.51.1 amalgamation is a post-parity item.
- **D3 CLI defaults:** accepted. `diff` defaults to the parity engine and writes a
  `.diaphora` file. `--engine legacy` keeps the old tables.
- **D4 Crash inputs:** accepted: exit 3, no output.
- **D5 Timeline:** accepted. The long pairs gate at S-L2 prefixes until their oracle
  runs finish.
- **D6 `port` is redesigned around results files.** This replaces "L9 optionally
  switches `port`".
  - `dsigmatcher port <ref.sqlite> <target.sqlite> -o <out.sqlite> [--results <x.diaphora>]`.
  - Given `--results` (from our `diff` **or** Diaphora's own), it applies those
    matches. Without it, it runs the parity diff in-process first.
  - It imports **best + partial** by default. Multimatch and unreliable rows need
    `--include-multimatch` / `--include-unreliable`.
  - Confidence is `ratio x parent confidence`. Hop count, origin name, the
    confirmation path, alias refusal and "never overwrite a real target name unless
    `--overwrite`" keep their existing semantics (`Provenance.cpp`, `JOURNAL.md`).
  - The output is a valid Diaphora export, so a chain continues db -> db.
  - This decouples the product flow from the diff engine: it can be proven today on
    Diaphora's own oracle results.
- **D7 `extract` / `ingest`** use the IDA bridge.
  - `dsigmatcher extract <in.i64|in.idb> -o out.sqlite` exports an existing IDA
    database and keeps the user's labels.
  - `dsigmatcher ingest <new.exe|dll> -o out.sqlite [--pdb <file>|--no-pdb]` analyses
    a raw binary headless.
  - Both launch `tools/export/dsig_export.py`, which runs IDA idalib plus the
    **unmodified** Diaphora exporter. The exporter's feature definitions *are* the
    parity contract, so it is not re-implemented.
  - Discovery: the flags `--python`, `--ida-dir`, `--diaphora-dir`, and the env vars
    `DSIG_PYTHON`, `DSIG_IDADIR`, `DSIG_DIAPHORA_DIR`.
  - Safety:
    - an input `.i64`/`.idb` is **always copied to a temp dir first**, because idalib
      unpacks and repacks in place;
    - the original's sha256 is checked before and after;
    - the exporter runs with an isolated `IDAUSR`, so user plugins do not load;
    - a `<out>.export.json` sidecar records the input sha256, the IDA and Diaphora
      versions, and the options used.
  - A native (no-IDA) ingest is post-parity. It must compute features identically on
    both sides.
- **D8 Ground truth.** This is a separate check from parity. The PDB of each target
  build names its functions.
  - `tools/e2e/score_ground_truth.py` scores a ported DB against a truth export of
    the same build.
    - It joins by function start address.
    - It reports correct, wrong and missing names, per category and per heuristic
      description.
    - It lists addresses where the PDB and no-PDB analyses disagree on function
      starts separately.
  - Diaphora's own results are scored as the **baseline**.
- **D9 Public-repo hygiene.**
  - Committed files must not contain personal absolute paths such as `C:/Users/...`.
  - Code and tests take paths from CMake cache variables, flags or the environment.
  - Docs use placeholders such as `<corpus>` and `<diaphora-ref>`.
  - Existing docs are sanitised in L9.
  - Never commit binaries, `.i64` files, exports, or names extracted from them.

### 7.2 Added lanes

- **O1 Oracle extension** (wave 0; Python and data; owns *new* files under
  `tools/oracle/` plus additions to `tools/oracle/README.md`).
  - **Do not edit** `tools/oracle/build_oracle.py` or `diaphora_export.py`: detached
    oracle processes still depend on them.
  - Build these, with exports under `<corpus>/oracle/exports/`:
    1. `win32u-9168-useri64`: export a **copy** of the user's hand-saved
       `<corpus>/win32u/win32u_100261009168/win32u.dll.i64`. Never open the original,
       and prove its sha256 is unchanged.
    2. `win32u-9444-nopdb`, plus `win32u-9444-pdb` for ground truth.
    3. `cryptbase` from the three WinSxS builds (10.0.26100.1, .8875 and .9444), each
       as `-pdb` and `-nopdb`.
  - Start Diaphora reference diffs **detached**, with run1 and run2 for determinism:
    - `win32u-9168-useri64_vs_9444-nopdb`;
    - `cryptbase-1-pdb_vs_8875-nopdb`;
    - `cryptbase-8875-pdb_vs_9444-nopdb`.
  - Write ground-truth tables (address -> PDB name) for every `-nopdb` build.
  - Update `ORACLE.md` and `manifest.json`.
- **L10 Export bridge** (wave 1).
  - Owns `tools/export/**` and `src/cli/ExportBridge.cpp`. The latter starts as a stub
    created by L0.
  - Owns `tests/cli/export_bridge_tests.cpp`, which skips without IDA or the corpus.
  - Acceptance:
    - `extract` of the user's win32u `.i64` gives tables identical to O1's export
      (`tools/oracle/compare_exports.py`), with all 1516 function names preserved and
      the original's sha256 unchanged;
    - `ingest --no-pdb` of the raw 9444 DLL gives tables identical to O1's
      `win32u-9444-nopdb`;
    - clear errors when IDA or Python is missing.
- **L11 Port on results, ground truth, chain** (wave 1).
  - Owns `src/cli/PortResults.cpp` (an L0 stub), `src/Provenance.cpp` and
    `include/dsigmatcher/Provenance.h`. The legacy `port` behaviour and its tests must
    keep passing.
  - Also owns `tests/cli/port_results_tests.cpp` and `tools/e2e/**`
    (`score_ground_truth.py`, `run_chain.py --differ diaphora|native`).
  - Acceptance, using Diaphora's **own** `.diaphora` results:
    - port and score every finished pair against the PDB truth, which gives Diaphora's
      baseline accuracy;
    - run the cryptbase 3-build chain (`--differ diaphora`, running standalone Diaphora
      on the hop-1 ported DB) and score both hops;
    - confirm that re-feeding a ported DB as a reference works.
- **L0 additions:**
  - a frozen header `include/dsigmatcher/cli/Commands.h` declaring
    `RunExtract`, `RunIngest` and `RunPortFromResults`;
  - stubs in `src/cli/ExportBridge.cpp` and `src/cli/PortResults.cpp` that return
    "not implemented" (exit 4);
  - `main.cpp` dispatch for `extract`, `ingest` and `port --results`;
  - CMake entries for the `tests/cli/` suites, as stub test mains.
- **L9** additionally owns:
  - switching `port` without `--results` to the parity engine;
  - the final end-to-end run: native `diff` -> `port` -> ground-truth score on every
    pair and on the cryptbase chain, compared with the Diaphora baseline;
  - the doc sanitising of D9.

### 7.3 Git and worktrees

- Each lane works in its own worktree, `<lane-worktrees>/<lane>`
  (branch `lane/<lane>`, created by the orchestrator from `parity`).
- Lanes **commit on their lane branch**. The repo hooks enforce the author and
  committer `kuro1337WStuff` and reject any `Co-Authored-By`, "Generated with" or AI
  attribution.
  - Never use `--no-verify`.
  - Never set another identity.
  - If a hook rejects a commit, fix the message.
- No push, no stash, no rebase of other branches. The orchestrator merges lane
  branches into `parity`.
- `dsig_build.cmd` caps build parallelism at 6 jobs. Do not raise it: detached oracle
  runs share this machine.
