# Parity tools (Python)

Python tools for Diaphora parity. They run **unmodified** Diaphora, record what it does, compare
the native engine with it, and regenerate the test data committed under `tests/diff/`. None of
them computes a diff result for the product, and `ctest` never runs Python. They are not needed to
use `dsigmatcher`.

There are three groups:

- **Trace tools** record Diaphora's internal match state and compare it stage by stage:
  `oracle_trace.py`, `snapshot.py`, `compare_traces.py`.
- **Result-parity tools** compare complete `.diaphora` results files: `run_parity.py` (the
  release evidence), `compare_results.py`, and `make_fixture.py` for small synthetic pairs.
- **Generators** rebuild committed files from an unmodified Diaphora checkout (and, for
  `gen_corpus_census.py`, from the oracle corpus): `gen_registry.py`, `gen_corpus_census.py`,
  `gen_foundation_fixture.py`, `gen_ratio_vectors.py`, `gen_ratio_clamp_vectors.py`,
  `gen_state_vectors.py`, `gen_textdiff_vectors.py`.

| File | Purpose |
|---|---|
| `run_parity.py` | Runs `dsigmatcher diff` on every valid oracle pair and compares it with Diaphora's output at L0/L1/L2; with `--score`, also ports both result sets and scores them against the PDB ground truth. Produces the parity evidence quoted in the top-level README. See [`run_parity.py`](#run_paritypy-the-release-evidence) below. |
| `compare_results.py` | Compares two `.diaphora` files at L0, L1 and L2, with a per-heuristic agreement table. Has a `--self-test`. |
| `make_fixture.py` | Builds a synthetic Diaphora-schema database pair from a scenario file, has real Diaphora diff it twice, and writes the pair and Diaphora's expected results as committed test fixtures. |
| `oracle_trace.py` | Instrumented Diaphora run of one oracle pair (`run`), the self-test (`selftest`), and a list of captures (`status`). |
| `snapshot.py` | Library for the trace and snapshot schema (see [Schema details](#schema-details)): writing, reading, S-L2 comparison, and rebuilding `.diaphora` rows from the chooser dumps. |
| `compare_traces.py` | First divergence between two traces, or first differing point between two captures. Has a planted-divergence `--self-test`. |
| `gen_registry.py` | Generates the verbatim Diaphora SQL the engine embeds (`src/diff/RegistrySql.inc`, `src/diff/StageSql.inc`) and its checksums (`tests/diff/generated/registry_expected.inc`). `--check` verifies the committed files instead. |
| `gen_corpus_census.py` | Generates `tests/diff/generated/corpus_census.inc`: counts and hashes (never names) of every oracle export and of every default query's row stream per pair. Needs the corpus. |
| `gen_foundation_fixture.py` | Generates `tests/diff/fixtures/foundation/{main,diff}.sql`, the synthetic pair of `diff_foundation`. |
| `gen_ratio_vectors.py` | Ratio and Python value-semantics vectors from real Diaphora: the committed suite in `tests/diff/vectors/ratio/`, plus larger sets and corpus vectors outside the repository. |
| `gen_ratio_clamp_vectors.py` | Ratio vectors that sit exactly on the 0.99 clamp boundary (`tests/diff/vectors/ratio/clamp-boundary-*.json`). |
| `gen_state_vectors.py` | Match-state-machine vectors (`add_match`, `cleanup_matches`, `final_pass`, `find_unmatched`, ...) from real Diaphora (`tests/diff/vectors/state/`). |
| `gen_textdiff_vectors.py` | `difflib`, `splitlines` and name-scanner vectors (`tests/diff/vectors/textdiff/`); with `--corpus`, acceptance vectors from the oracle results, outside the repository. |

Each script's docstring has its full usage, and `python -B <script> --help` prints its flags.

## What is written where

- **Trace tools** write only under `<corpus>/oracle/traces/<pair>/`.
- **`run_parity.py`** writes to `<corpus>/parity-reports/<timestamp>/`, or to `--out`, which must
  be outside the repository. Its reports contain names from the corpus and are never committed.
- **`compare_results.py`** writes only the `--json` / `--markdown` files you name.
- **Generators** rewrite committed files in this repository (the table above lists them), or,
  in their corpus and large modes, write under `<corpus>/oracle/vectors/`. Only synthetic data,
  counts and hashes are committed, never data taken from a real binary.
- **`make_fixture.py`** writes into the `<outdir>` you give it, normally a directory under
  `tests/diff/fixtures/`.

The oracle exports themselves are never modified: every tool opens them read-only
(`immutable=1`) or works on copies, because Diaphora opens its first database read/write.

## Paths

The scripts take every path from a flag or from the environment:

| Flag | Environment | Meaning |
|---|---|---|
| `--corpus` | `DSIG_CORPUS_ROOT` | corpus root; the oracle is `<corpus>/oracle` (its `manifest.json` names the pairs and export hashes) |
| `--diaphora-dir` | `DSIG_DIAPHORA_DIR` | the unmodified Diaphora checkout, `3.4.2-4-g621ec26` |

Run them with the oracle's Python (CPython 3.13.12, `sqlite3` 3.51.1, no
`cdifflib`). `run.json` records all three.

The native side needs the same SQLite, because Diaphora's results follow the
row order of SQLite's query planner (docs/parity/02-matching.md §18.3). The
default build bundles SQLite 3.51.1 compiled with the oracle's options
(`cmake/VendoredSqlite.cmake`; `build/dsig_sqlite_info` prints the version and
compile options), so native results compare at L2 (exact order, `line`,
ratios) on every platform. A build with `-DDSIG_VENDORED_SQLITE=OFF` uses the
system SQLite: unless that is also 3.51.1, `dsigmatcher diff` warns and only
L1 (same rows, any order) is meaningful.

## `run_parity.py`: the release evidence

```
python -B run_parity.py [--corpus <root>] [--dsigmatcher <exe>] [--pairs <pair> ...] [--long]
                        [--score] [--run 1] [--out <dir>] [--diaphora-dir <dir>] [--limit 20]
                        [--native-arg=<arg> ...] [--generate-aliases]
python -B run_parity.py --self-test [--dsigmatcher <exe>]
```

The v1.0.0 parity table was produced with:

```
python -B tools/parity/run_parity.py --corpus <corpus> --dsigmatcher <build>/dsigmatcher --long --score
```

For every pair in `<corpus>/oracle/manifest.json` (or `--pairs`), in manifest order:

1. **Oracle status.** `PENDING` when the oracle run has not finished;
   `SKIPPED_LONG` for a pair whose oracle run took more than an hour, unless `--long`;
   `ORACLE_INVALID` when the oracle run fails a validity rule (non-zero exit, missing output or
   log lines, a heuristic that hit Diaphora's 300 s timeout, changed export hashes, `cdifflib`
   present, any `DIAPHORA_*` variable). Such pairs are reported but never count as native
   failures.
2. **Native diff** of the same two exports, given as the same path strings the oracle was given,
   so `config.main_db` / `config.diff_db` compare too. Both exports are hashed before and after.
3. **Comparison** with `compare_results.py`: L0, L1, L2, the DDL, a per-(type, description)
   table and the `unmatched` rows.
4. **With `--score`**: `dsigmatcher port --results` for both the native and the oracle results,
   each scored by `tools/e2e/score_ground_truth.py` against the PDB ground truth of the target
   build, so parity and ground truth appear side by side. `--generate-aliases` lets
   `tools/e2e/pdb_aliases.py` build missing alias lists.

The levels: **L0**, the detected mode and Diaphora's `Final results` counts agree;
**L1**, `results` and `unmatched` are equal as multisets; **L2**, L1 plus identical `line` values
and stored row order. L2 is the parity gate.

Output: `report.md` and `report.json`, and per pair `native.diaphora`, `native.log`,
`compare.json`, `compare.md` and, with `--score`, the ported databases, port logs and
`score.json` / `score.md`.

Exit status: 1 when a compared pair fails L2, the native diff fails, or an export changed; 2 on a
usage error; 0 otherwise.

Flags and environment: `--corpus` (`DSIG_CORPUS_ROOT`), `--dsigmatcher` (`DSIG_EXE`; default
`<repo>/build/dsigmatcher[.exe]`), `--diaphora-dir` (`DSIG_DIAPHORA_DIR`; optional, only read to
record `git describe` and that the checkout is clean).

## `compare_results.py`

```
python -B compare_results.py <oracle.diaphora> <native.diaphora> [--oracle-log <log>]
                             [--native-log <log>] [--compare-config-paths] [--json <out>]
                             [--markdown <out>] [--limit 20] [--quiet]
python -B compare_results.py --self-test [--file <any .diaphora>]
```

L0 needs both logs; without them it is reported as not evaluated. Rows are paired per
(type, description) group by their `(address, address2)` key, and each group counts matched
rows, rows found in only one file, and differences in ratio, category, description, names,
nodes, `line` and order. Differences confined to "Same constants related matches" rows, which
depend on Python's set order (`D:3389`; 06 §8.3), are reported as the separate tolerated class
`r3_only`; the L1/L2 verdicts are never relaxed for them. Both files are opened read-only with
`immutable=1`. Exit status: 0 when L2 holds and the DDL is equal, 1 otherwise, 2 on a usage or
read error.

## `make_fixture.py`

```
python -B make_fixture.py <scenario.py> <outdir> [--diaphora-dir <dir>] [--python <exe>]
                          [--hash-seed 0] [--keep-work <dir>]
```

The scenario file defines `MAIN` and `DIFF`, one dict of synthetic rows per database. Each is
built like a real export (Diaphora's own schema, indices and `analyze`), and copies are diffed
twice by the unmodified Diaphora checkout: once with the oracle command line and once as an
in-process replay that records the raw chooser items. Both outputs must agree, or nothing is
written. `<outdir>` receives `main.sql` / `diff.sql` (the fixture databases as SQL dumps),
`expected_results.tsv`, `expected_unmatched.tsv`, two state snapshots and `oracle.json`. The
repository ignores `*.tsv`, so add the fixture files with `git add -f`. The fixtures under
`tests/diff/fixtures/` were made this way; some directories there have their own `gen_*.py` or
`generate.py`, which drive it for a set of scenarios.

## Regenerating committed data

Run the generators with the oracle's Python (CPython 3.13.12 with `sqlite3` 3.51.1 and without
`cdifflib`) and an unmodified Diaphora checkout at 3.4.2-4-g621ec26. Each records its environment
in its output, and the C++ suites fail when the committed data and the engine disagree.

```
set DSIG_DIAPHORA_DIR=<diaphora-ref>
set DSIG_CORPUS_ROOT=<corpus>
python -B tools/parity/gen_registry.py
python -B tools/parity/gen_corpus_census.py
python -B tools/parity/gen_foundation_fixture.py
python -B tools/parity/gen_ratio_vectors.py synthetic --set committed
python -B tools/parity/gen_ratio_vectors.py values
python -B tools/parity/gen_ratio_clamp_vectors.py
python -B tools/parity/gen_state_vectors.py
python -B tools/parity/gen_textdiff_vectors.py --synthetic
```

| Command | Rewrites |
|---|---|
| `gen_registry.py` (`--check` only verifies) | `src/diff/RegistrySql.inc`, `src/diff/StageSql.inc`, `tests/diff/generated/registry_expected.inc` |
| `gen_corpus_census.py` (needs the corpus) | `tests/diff/generated/corpus_census.inc` |
| `gen_foundation_fixture.py` | `tests/diff/fixtures/foundation/main.sql`, `diff.sql` |
| `gen_ratio_vectors.py synthetic --set committed` | `tests/diff/vectors/ratio/h03a-*.json`, `targeted.json` |
| `gen_ratio_vectors.py values` | `tests/diff/vectors/ratio/values.json` |
| `gen_ratio_clamp_vectors.py` | `tests/diff/vectors/ratio/clamp-boundary-*.json` |
| `gen_state_vectors.py` | `tests/diff/vectors/state/probes.json`, `random.json` |
| `gen_textdiff_vectors.py --synthetic` | `tests/diff/vectors/textdiff/*` |

The corpus and large modes (`gen_ratio_vectors.py synthetic --set 03a`,
`gen_ratio_vectors.py values --big`, `gen_ratio_vectors.py corpus`,
`gen_textdiff_vectors.py --corpus <corpus>`) write under `<corpus>/oracle/vectors/` and are never
committed. `gen_textdiff_vectors.py` refuses to run unless the Python's `difflib.py` is the exact
3.13.12 file the port follows.

## `oracle_trace.py run`

```
python -B oracle_trace.py run --pair <pair> [--out <dir>] [--stop-at <point>]
    [--points <glob> ...] [--with-cache <glob> ...] [--rows]
    [--force-const-order sorted|rsorted] [--hash-seed <n>] [--keep-work] [--force] [--detach]
```

What it does, in order:

1. It checks the sha256 of both exports against `manifest.json` and copies them
   to `<out>/work/`. Diaphora opens db1 read/write (`create_schema`), so it only
   ever sees the copies. Only the main `.sqlite` file is copied, because the
   oracle's `-wal` files are empty.
2. It records the state of the Diaphora checkout: `git describe`, `git status`,
   and the size and mtime of every file outside `.git`, ignored files included.
3. It removes every `DIAPHORA_*` variable from its own environment (the
   `build_oracle.CleanEnv()` semantics), sets `sys.dont_write_bytecode`, and
   imports `diaphora` from the checkout.
4. It replays `__main__` literally (`D:3757-3773`):
   `bd = CBinDiff(db1); bd.ignore_all_names = False; bd.db = sqlite3_connect(db1); bd.diff(db2); bd.save_results(out)`.
   Before `diff`, it wraps methods of `bd` (see below).
5. Afterwards it re-hashes the exports, re-checks the checkout, and applies
   the oracle validity rules to the log (as `run_parity.py` does). For a full
   run it compares the output with oracle `run1` (the self-check) and rebuilds
   the rows from the chooser dumps. The work copies are then deleted.

Exit codes: 0 means OK. 1 means the self-check failed, or the checkout or an
export changed. 3 means Diaphora itself aborted: an exception, or a main-thread
`SystemExit` timeout. In that case no `.diaphora` is written, as with Diaphora.

Output in `<out>` (default `<corpus>/oracle/traces/<pair>`):

| File | Content |
|---|---|
| `trace.jsonl` | one event per line (below) |
| `snapshots/NNNNN_<point>.json` | one state snapshot per point (below); `NNNNN` is the point's `seq` |
| `index.json` | every point in order, `[seq, point, file]`; `file` is `null` when `--points` filtered the snapshot out. Rewritten at every point, so it is usable while a run is in progress. |
| `<pair>.diaphora` | the instrumented output (full runs only) |
| `run.json` | status (`preparing`, `running`, `complete`, `stopped`, `diaphora_exception`, `diaphora_system_exit`), options, the Python, SQLite and seed used, input hashes before and after, the reference check, the log checks, the self-check, and stats (cleanup site counts, `find_one_match_diffing` call counts, heuristic spans) |
| `progress.log` | a timestamped line per point, with list sizes |
| `diaphora.log` | Diaphora's own stdout and stderr, comparable with the oracle's log |
| `console.log`, `launch.json` | detached runs only |

Options:

- `--stop-at <point>` ends the run at that point. The point's snapshot is
  written first, and no `.diaphora` is written. On the main thread a private
  `BaseException` unwinds through `diff()`. Heuristic points run on a worker
  thread, where an exception would only end that thread (`threads_apply` goes on
  with the next heuristic), so the process flushes everything and ends there
  with `os._exit(0)`. In that case the work copies stay in place.
- `--points <glob>` limits which snapshots are written. Every point still gets
  a `point` trace event and an `index.json` entry.
- `--with-cache <glob>` adds `ratios_cache` to the snapshots of matching
  points. The cache only ever grows, and the first writer wins (`D:1653-1655`,
  `D:1774`). Replays that compute ratios should seed it from the `before:`
  snapshot, because `check_ratio` can store 1.0 while returning `v3`
  (`D:1696-1697`). Suggested globs: `before:find_*`, `before:heuristic:*` and
  `before:search_small_differences`.
- `--rows` wraps `check_match` (and, to classify its rows, `add_matches_internal`
  and `check_ratio`) and writes one `row` event per call.
- `--force-const-order sorted|rsorted` swaps in a copy of
  `find_related_constants` (`D:3362-3393`) that is verbatim except for the
  iteration order of the constant set. It is for measurement only (06 V4).
  `run.json` then says `oracle_valid_config: false`.
- `--hash-seed <n>` re-runs the process under `PYTHONHASHSEED=<n>` and records
  the seed. See "Hash seed" below.
- `--detach` starts the same command as a process that outlives the launching
  session and returns at once. On Windows this goes through WMI
  (`Win32_Process.Create`), so the process is outside the launcher's job object.
  On POSIX it uses a new session.
  Caveat: a WMI-created process belongs to the WMI provider host, and all such
  processes die together when Windows recycles that host. This ended several
  oracle runs that had been going for hours. For runs of many hours, start the
  command as a Windows scheduled task instead.

### What is wrapped

Every wrapper calls the original with the original arguments and returns its
result. The wrappers are instance attributes of `bd`, except `CChooser.add_item`,
which is patched on the class in memory because `find_unmatched` creates its
choosers at run time. No file in the checkout is touched.

| Wrapped | Emits |
|---|---|
| `add_match` (`D:1340`) | `add_match` event |
| `cleanup_matches` (`D:1554`) | `before:`/`after:cleanup:<site>:<n>` points and a `cleanup` event. The site is the caller's line, `sys._getframe(1).f_lineno`. |
| the four `add_matches_from_*` (`D:1950`/`1977`/`2002`/`2039`) | `before:`/`after:heuristic:<id>`, only on a heuristic worker thread. The thread name is the heuristic name (`threads_apply`), mapped to its `HEURISTICS` index. |
| stage methods (`POINT_PATTERNS` in `snapshot.py` lists every point) | their `before:`/`after:` points |
| `CChooser.add_item` (`D:275`) | the raw chooser dumps in `after:final_pass` and `after:find_unmatched` |
| `find_one_match_diffing` (`D:3033`) | a call count per field and iteration in `run.json` (06 V3) |
| `check_match`, `add_matches_internal`, `check_ratio` | `row` events, only with `--rows` |

## Schema details

The native engine (`src/diff/Snapshot.cpp`, `src/diff/Trace.cpp`) and these tools
write the same field names. Compare by parsed JSON, never by bytes. The files
are compact UTF-8 JSON (`ensure_ascii=False`).

A snapshot (`snapshots/NNNNN_<sanitised point>.json`), shown indented:

```json
{"schema": "dsig-parity-snapshot/1", "producer": "diaphora-3.4.2-4-g621ec26",
 "pair": "ls-old_vs_ls", "seq": 17, "point": "before:find_matches_diffing:0", "iteration": 0,
 "flags": {"is_same_processor": true, "is_patch_diff": false, "is_symbols_stripped": false,
           "hooks_loaded": false, "total_functions1": 304, "total_functions2": 318},
 "all_matches": {"best": [["4198400", "foo", "4202496", "foo", "Perfect match, same name",
                           "3ff0000000000000", 5, 5]],
                 "partial": [], "unreliable": []},
 "matched_primary": [["foo", "foo", "3ff0000000000000"]],
 "matched_secondary": [["foo", "foo", "3ff0000000000000"]],
 "ratios_cache": [["4198400-4202496", "3fee666666666666"]]}
```

and a trace line:

```json
{"ev":"add_match","seq":1234,"ctx":"heuristic:41","name1":"foo","name2":"bar","ea1":"4198400",
 "ea2":"4202496","desc":"Loop count","ratio_bits":"3fe8000000000000","chooser":"partial",
 "result":"appended"}
```

- **Items** are `[ea1, name1, ea2, name2, desc, ratio_bits, nodes1, nodes2]`.
  `ea` values keep their Python type (the address TEXT from SQLite, so a JSON
  string). `ratio_bits` is `struct.pack('>d', float(x)).hex()`.
- **Snapshot keys**, in order: `schema`, `producer`, `pair`, `seq`, `point`,
  `iteration`, `flags`, `all_matches`, `matched_primary`, `matched_secondary`,
  then `ratios_cache`, `choosers` (only at `after:final_pass`) and `unmatched`
  (only at `after:find_unmatched`), when present.
- **`seq`** is 0-based and counts every point, including filtered ones. It is
  also the `NNNNN` of the file name. Comparisons ignore `seq` and `producer`.
- **`iteration`** is the outer-loop `k` (`D:3653-3675`) for every point from
  the loop's first `cleanup` (`D:3655`) through its last (`D:3671`). It is
  `null` everywhere else: before the loop, in modes S and P, and from
  `before:final_pass` on.
- **`unmatched`**: `primary` is `bd.unmatched_primary` and `secondary` is
  `bd.unmatched_second`. These are the labels `save_results` writes
  (`D:2414-2415`), so `primary` holds **diff-DB** functions (`D:2343-2354`).
  An item is `[ea, name]`. A chooser that `find_unmatched` never created is
  `null`.
- **`add_match` event**:
  - `seq` is the 0-based ordinal of `add_match` calls.
  - `ctx` is the innermost stage: `heuristic:<id>` on a worker thread;
    otherwise a stage name such as `find_equal_matches`,
    `apply_dirty_heuristics`, `find_same_name`, `find_remaining_functions`,
    `search_small_differences`, `find_matches_diffing:<k>`,
    `find_related_matches:<k>`, `find_related_compilation_unit:<k>` or
    `find_locally_affine_functions:<k>`.
  - `ratio_bits` is the `ratio` argument. That is the argument before
    `add_match`'s own same-name 1.0; the stored item keeps its own ratio.
  - `result` is inferred from the effect, without re-running Diaphora's tests:
    - `appended` when the list grew;
    - `duplicate` when the dicts were rewritten (`D:1373-1374` store a new dict
      object) but the list did not grow (`D:1370`);
    - `rejected_better` for the early return at `D:1353-1355`.
- **`cleanup` and `point` events** carry the three list lengths after the
  cleanup, or at the point.
- **`row` event** (`--rows`):
  - `ctx` as above; `ea1`/`ea2` are the row's `ea`/`ea2`.
  - `decision` for a rejected row is `nullsub`, `has_best` or `has_better`
    (`D:1846-1867`).
  - `decision` for an accepted row follows the caller's routing:
    - `add_matches_internal`: `accepted_best`, `accepted_partial` or
      `below_min` (`D:1922-1946`);
    - `add_matches_from_query`: `accepted_best` (`D:2073-2075`);
    - `find_same_name` and `search_small_differences`: `accepted_best` or
      `accepted_partial`.
  - Two further values never occur on the corpus: `accepted_unreliable`
    (`D:1940-1946`, dead under the defaults) and `raised`.
  - `ratio_bits` is the ratio `check_match` computed. It is `null` when none was
    computed (`nullsub`, `has_best`).
  - In patch-diff mode, a row that the `on_match` hook rejected would be
    labelled `has_better`. The default hook never rejects (01 §5.4).

### Point order (mode N, abridged)

```
after:find_equal_matches, after:apply_dirty_heuristics, before/after:find_same_name,
before/after:heuristic:<id> ... (reverse HEURISTICS order), before/after:cleanup:1551:1,
after:run_heuristics_for_category:Best, ... Partial ..., before/after:search_small_differences,
[loop k: cleanup:3655, find_matches_diffing:k (cleanup:3217, cleanup:3185 x1-2 per field),
 find_related_matches:k (cleanup:3471), find_related_compilation_unit:k (cleanup:3413),
 find_locally_affine_functions:k (cleanup:3340), cleanup:3671],
before:final_pass, cleanup:2945, after:final_pass, after:find_unmatched
```

In modes S and P, `before`/`after:find_remaining_functions` replaces the
heuristic tiers and the loop.

## Hash seed

`find_related_constants` iterates a Python `set` (`D:3389`). Its order follows
the string hash seed, which Python picks at random for every process. In the
self-test on the finished pairs, the effects were:

- The order of `row` events in `find_related_matches` changes on
  `ls-old_vs_ls`, `ls_vs_ls-old` and `cryptbase-1-pdb_vs_8875-nopdb`.
- On `ls_vs_ls-old`, `all_matches` itself differs from
  `after:find_related_matches:k` through `before:cleanup:3413:k` (iterations 0
  and 1). The next cleanup (`D:3413`) erases the difference, and the final
  output is identical.
- Seeds 1 to 8 on `ls_vs_ls-old` gave two distinct `after:find_related_matches:0`
  states, with 98 or 99 `partial` items.
- `--force-const-order sorted` and `rsorted` on `ls-old_vs_ls` both reproduce
  oracle `run1`, as 06 V4 found.

So a capture is reproducible only with a fixed seed. The self-test runs both
determinism captures under one seed (default 12345), and runs a third capture
under another seed (default 54321) to list the seed-sensitive points. The
long-pair captures were started with `--hash-seed 12345`. The oracle runs
themselves were not pinned.

## `oracle_trace.py selftest`

```
python -B oracle_trace.py selftest [--pairs ...] [--with-cache <glob> ...] [--hash-seed 12345] [--probe-seed 54321|--no-probe]
```

For every finished pair (both oracle runs done), or every pair in `--pairs`, it
does the following:

1. Two captures with `--rows` under the same seed: run 1 goes to
   `<corpus>/oracle/traces/<pair>` (the canonical capture) and run 2 to
   `traces/_selftest/<pair>.run2`.
2. Both captures must be identical (`compare_traces`: every event, every
   snapshot).
3. Each capture must pass its self-check against oracle `run1`, and the chooser
   dumps must reproduce the rows.
4. The checkout and the exports must be unchanged.
5. For `ls-old_vs_ls`, the 06 V3 figures are checked:
   - cleanup executions per site: 3655×3, 3217×3, 3185×8, 3471×3, 3413×3,
     3340×3, 3671×3, 2945×1, 1551×2;
   - outer totals 206→287→291→291;
   - `find_one_match_diffing` calls: assembly 716, pseudocode 426.
6. A third capture under `--probe-seed` records the seed-sensitive points. This
   step is informational only.

The report goes to `traces/_selftest/report.json`.

## `compare_traces.py`

```
python -B compare_traces.py a/trace.jsonl b/trace.jsonl [--context 30] [--events ...] [--prefix]
python -B compare_traces.py <capture a> <capture b> [--all] [--prefix] [--ignore FIELD ...]
python -B compare_traces.py a/snapshots/X.json b/snapshots/X.json
python -B compare_traces.py --self-test [--trace <trace.jsonl>] [--snapshots <capture dir>]
```

- **Traces.**
  - It reports the first divergent event, with 30 events of shared context
    before it and 30 after it on each side.
  - It prints per-`ctx` counts of `add_match` results
    (appended/duplicate/rejected_better) for each side.
  - `seq` is ignored.
  - If only one side has `row` events, row events are left out of the
    comparison.
- **Captures.**
  - It walks `index.json` in order and reports the first point whose snapshots
    differ at S-L2:
    - lists are compared in order, item by item, with ratio bits;
    - `matched_*` and `ratios_cache` are compared as maps;
    - flags, the choosers and the unmatched lists are compared too.
  - `--all` lists every differing point.
- **`--prefix`**: `a` is a `--stop-at` capture, so whatever `b` has past `a`'s
  last point is expected.
- **`--self-test`** plants changes, deletions, insertions and a truncation into
  a copy of a trace, and a ratio change and a `matched_primary` change into a
  copy of a capture. It checks that each one is reported at the planted place.
- **Exit codes**: 0 equal, 1 different, 2 usage.

## Long-pair prefix captures

One detached capture per long pair goes to `traces/<pair>/`, with
`--stop-at after:find_related_compilation_unit:0 --hash-seed 12345` and
`--with-cache` for `before:find_*`, `before:heuristic:*` and
`before:search_small_differences`. Expected run times:

- `userenv-9168-pdb_vs_9278-nopdb`: about 2.5 h;
- `sechost-9168-pdb_vs_9444-nopdb`: about 17 h.

Almost all of that time is the related-CU pass. Every snapshot up to and
including `before:find_related_compilation_unit:0` is written within minutes of
the start, so there is no separate short capture.

To check on them:

- run `python -B oracle_trace.py status --corpus <corpus>`, which prints status,
  point count, last point and whether the process is alive;
- or read `run.json` (`status`, `progress`), `progress.log` or `launch.json`.

A snapshot that is listed in `index.json` is final even while its run is still
going. When a capture ends, `run.json` says `stopped` with
`stopped_at: after:find_related_compilation_unit:0`. If Diaphora's 300 s
main-thread timeout fires in the related-CU pass, it says
`diaphora_system_exit`, and every snapshot before that point is still valid.

Relaunch command (same options):

```
python -B oracle_trace.py run --pair <pair> --stop-at after:find_related_compilation_unit:0 \
    --with-cache "before:find_*" --with-cache "before:heuristic:*" \
    --with-cache before:search_small_differences --hash-seed 12345 --detach
```
