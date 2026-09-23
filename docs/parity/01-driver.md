# 01 — Diff driver, config and output

Porting spec for the part of Diaphora that decides **which passes run, in what order, with what
shared state, and what gets written to the `.diaphora` result file**. The individual SQL heuristics
and `check_ratio`/`deep_ratio` are specified elsewhere; this document covers everything around them.

## Summary

- `python diaphora.py db1 db2 -o out` does exactly `CBinDiff(db1)` → `ignore_all_names = False` →
  `diff(db2)` → `save_results(out)`. `diff()`'s return value is ignored, so a failed diff still writes
  an empty result file. An **exception** means `save_results` never runs, so nothing new is written
  and **any file already at `out` stays as it was** (the delete is inside `save_results`, verified V9).
- Default standalone config: unreliable **off**, experimental **on** (its only effect is the "dirty"
  speed-up checks), slow heuristics **on regardless of function count**, relaxed ratio off, ML off,
  one worker thread. `MIN_FUNCTIONS_TO_DISABLE_SLOW = 4001` is read **only** by the IDA GUI dialog
  (`diaphora_ida.py:3798-3800`). The orchestrator's summary, which says it applies here, is wrong.
- After the "100% equal" pass the run takes one of **three modes**. **Stripped**: at least 99% of
  main functions have a same-address partner in db2. **Patch-diff** (checked only if stripped
  did not trigger): more than 90% same `mangled_function` pairs, counted as join rows over
  `total_functions1`, and `scripts/patch_diff_vulns.py` is loaded. In both S and P the SQL
  heuristic tier and the convergence loop do not run at all. **Normal**: everything else.
- In normal mode the `HEURISTICS` list runs **in reverse order** (`targets.pop()`). On a 1.0 tie the
  first row to arrive wins (`has_best_match`), so run order and SQLite row order decide the
  description and the chosen partner.
- All match bookkeeping is keyed by the **function name string** (`matched_primary` and
  `matched_secondary`). The multimatch and final filtering are keyed by the **address text**.
- The output is SQLite with tables `config`, `results` and `unmatched`, and every value is TEXT
  (except names, which are NULL when the export's name is NULL).
  Addresses are `"%08x"`, ratio is `"%.7f"`, and `line` is `"%05lu"` numbered per chooser. `insert or
  ignore` on `(address, address2)` silently drops duplicate pairs, which leaves gaps in `line`. The
  unmatched labels are **swapped**: `type='primary'` rows are db2 functions.
- `patch_diff_vulns.py` never changes match results. It can only abort the run: an `IndexError` at
  `patch_diff_vulns.py:162` is the known path, and any other exception inside a hook propagates the
  same way.
- Observed modes on the real oracle corpus (V12): `userenv-9168-pdb` vs `userenv-9278-pdb` runs in
  **mode P** (`643 matches out of 643, 100.0%`). `ls` vs `ls-old` (both directions) and both
  PDB-vs-no-PDB pairs run in **mode N**.

Reference revision: `<diaphora-ref>` at `621ec26` (`git describe` = `3.4.2-4-g621ec26`).
`git diff 3.4.2 HEAD --stat` touches only `README.md` and `diaphora_ida.py` (4 lines). `diaphora.py`,
`diaphora_config.py`, `diaphora_heuristics.py`, `jkutils/` and `scripts/` are byte-identical to tag
3.4.2. The oracle Python is `<python-home>/python.exe`: Python 3.13.12, SQLite 3.51.1,
no `cdifflib` (stdlib `difflib` is used), and sklearn/joblib/pandas present, so `ML_AVAILABLE=True`
but unused. No `DIAPHORA_*` or `PYTHONHASHSEED` environment variables are set on this PC.

---

## 0. How this was verified

Every behavioural claim cites source. The driver-level claims below were also **run** against a
scratch copy of Diaphora (`git archive HEAD` into the session scratchpad, run with `python -B`, so
the reference checkout was not touched). The inputs for E1-E8 were small synthetic exports built
with `db_support/schema.py`. The verification pass (V1-V14 in the "Verification log" at the end)
also used **real** IDA exports from `<corpus>/oracle/exports` (copied to the
scratchpad first) and the oracle's own logs in `oracle/diffs`.

| # | Experiment | Observed |
|---|---|---|
| E1 | 6+6 functions, normal mode | The log shows Best heuristics finishing in order `Microcode mnemonics…` → … → `Same RVA and hash` (reverse of `HEURISTICS`). A pair that matched both "Bytes hash" and "Equal assembly or pseudo-code" came out as `Equal assembly`. The unmatched db2 function was written with `type='primary'` and the db1 function with `type='secondary'`. |
| E2 | `all_matches` injected, then `cleanup_matches` → `find_multimatches` → `add_final_chooser_items` → `save_results` | Equal-ratio pairs sharing ea1 or ea2 went to `multimatch`. A lower ratio for the same ea1 was dropped. A same-name pair (0.9018889) was dropped from the output because another pair of the same ea1 had 0.95. `0.123456789` was written as `0.1234568`. The 64-bit ea 4294967296 was written as `100000000`. |
| E3 | 20+20 functions, 19 equal names, shifted addresses | Patch-diff mode: `Loading default script…`, then only "Perfect match, same name" and the "Renamed or anonymous…" pass ran. Output was **identical** with `RUN_DEFAULT_SCRIPTS=False` (20 rows each, `==` True). |
| E4 | `name` ≠ `mangled_function` for one identical function | The chooser held 3 best items, but only 2 rows were written (the `insert or ignore` duplicate was dropped). The log printed `All functions matched in at least one database, finishing.` while one main function was still unmatched. |
| E5 | `DIAPHORA_UNRELIABLE=0` | `get_value_for` returns the **string** `'0'`, which is truthy. `DIAPHORA_PROJECT_SCRIPT=` (empty) returns `''`. |
| E6 | `'%.7f' % x` | `0.00390625`→`0.0039062` (round-half-even on the exact binary value), `0.99999999`→`1.0000000`, `1`→`1.0000000`. |
| E7 | `explain query plan` | `UNION USING TEMP B-TREE` and `INTERSECT USING TEMP B-TREE`, so these compound queries return rows sorted by all selected columns. |
| E8 | `find_vulns_using_assembly` with an added line starting with a space | `IndexError: string index out of range`. |

---

## 1. Entry point (standalone `__main__`)

`diaphora.py:3714-3773` (verbatim, the version-warning lines 3705-3712 are omitted):

```python
  do_diff = True
  ...
  if os.getenv("DIAPHORA_AUTO_DIFF") is not None:
    db1 = os.getenv("DIAPHORA_DB1")
    if db1 is None:
      raise Exception("No database file specified!")

    db2 = os.getenv("DIAPHORA_DB2")
    if db2 is None:
      raise Exception("No database file to diff against specified!")

    diff_out = os.getenv("DIAPHORA_DIFF_OUT")
    if diff_out is None:
      raise Exception("No output file for diff specified!")
  elif IS_IDA:
    ...
    do_diff = False
  else:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("db1")
    parser.add_argument("db2")
    parser.add_argument("-o", "--outfile", help="Write output to <outfile>")
    args = parser.parse_args()
    db1 = args.db1
    db2 = args.db2
    if args.outfile:
      diff_out = args.outfile
    else:
      path1 = os.path.basename(os.path.splitext(db1)[0])
      path2 = os.path.basename(os.path.splitext(db2)[0])
      diff_out = f"{path1}_vs_{path2}.diaphora"

  if do_diff:
    bd = CBinDiff(db1)
    if not IS_IDA:
      bd.ignore_all_names = False

    bd.db = sqlite3_connect(db1)
    if os.getenv("DIAPHORA_PROFILE") is not None:
      ...
      profiler.runcall(bd.diff, db2)
      ...
    else:
      bd.diff(db2)
    bd.save_results(diff_out)
```

`IS_IDA` is `False` whenever `import idaapi` fails (`diaphora.py:82-87`).

**Porting spec**

```
main(argv):
  if env DIAPHORA_AUTO_DIFF is set (any value, even ""):
      db1 = env DIAPHORA_DB1, db2 = env DIAPHORA_DB2, out = env DIAPHORA_DIFF_OUT   // each missing -> fatal error
  else:
      db1, db2 = positional; out = -o/--outfile if non-empty
                 else basename(stem(db1)) + "_vs_" + basename(stem(db2)) + ".diaphora"   // relative to CWD
  bd = CBinDiff(db1)            // section 2
  bd.ignore_all_names = false   // unconditional override of any env value
  bd.diff(db2)                  // result ignored
  bd.save_results(out)          // always runs unless diff() threw
```

- `bd.db = sqlite3_connect(db1)` opens a **second** connection and stores it in `self.db` and
  `_DATABASES[db1]`. `db_cursor()` never uses it: it looks up `self.dbs_dict[thread-id]`, which
  still holds the connection opened in `__init__` (`diaphora.py:584-601`). **No effect on results.**
- The exit code is 0 on a normal run. An uncaught exception gives a traceback and exit code 1, and
  **no new output file**. A `SystemExit` escaping from a main-thread pass exits with code 0 after
  logging `Timeout with heuristic 'MainThread'`, again with no new output file (section 13). In
  both cases a file already at the output path is **not deleted**, because the delete at 2379-2381
  is inside `save_results`, which is never reached (V9 reproduced this: a sentinel file survived a
  `ZeroDivisionError` run). A harness must delete the output path before each oracle run.
  `tools/oracle/build_oracle.py` already does, since `RunDiff` removes the whole run directory
  first (lines 276-279).
- **Runs by default?** Yes, the argparse branch.

---

## 2. Configuration resolution

### 2.1 `get_value_for` — environment overrides

`diaphora.py:560-569`:

```python
  def get_value_for(self, value_name, default):
    """
    Try to search for a DIAPHORA_<value_name> environment variable.
    """
    value = os.getenv(f"DIAPHORA_{value_name.upper()}")
    if value is not None:
      if isinstance(value, type(default)):
        value = type(default)(value)
      return value
    return default
```

`value` is always a `str`, so the `isinstance` test only passes when `default` is a `str`. In
every other case the **raw string** is returned (E5). Consequences:

- A bool option set through the environment is **truthy for any non-empty string** (`"0"`, `"False"`)
  and falsy only for `""`.
- `DIAPHORA_SQL_TIMEOUT_LIMIT` / `DIAPHORA_SQL_MAX_PROCESSED_ROWS` become strings. Both
  comparisons live in `add_matches_internal`: `i < self.sql_max_processed_rows` in
  `continue_getting_sql_rows` (1878, evaluated **first**, as the `while` condition at 1893) and
  `time.monotonic() - t > self.timeout` (1894). Each raises `TypeError` wherever
  `add_matches_internal` runs, which is **both** on heuristic threads (the RATIO/RATIO_MAX/TRUSTED
  heuristics: that heuristic dies) and on the main thread (the stripped pass via
  `add_matches_from_query_ratio`, which re-raises at 1967-1973, plus the direct calls in
  `search_remaining_functions` 2696, `find_related_constants` 3391 and
  `find_related_compilation_unit` 3458: the run aborts). NO_FPS heuristics
  (`add_matches_from_query`), `find_same_name` and `search_small_differences` never reach it.
  Setting either variable breaks Diaphora. `DIAPHORA_SQL_TIMEOUT_LIMIT` never affects the
  per-thread timeout anyway: `threads_apply` is passed `config.SQL_TIMEOUT_LIMIT` directly (1548).
- The native port should either not support env overrides or reproduce "non-empty ⇒ true" for
  the bool ones. The parity oracle must run with **no** `DIAPHORA_*` variables set.
  `tools/oracle/build_oracle.py` `CleanEnv()` (lines 110-117) strips every `DIAPHORA_*` variable
  from the diff environment.

### 2.2 Config values that influence diffing (`diaphora_config.py`)

Line numbers are in `diaphora_config.py`. The "used at" column cites `diaphora.py` unless it says
otherwise.

| Constant (line) | Value | Used at | Effect in standalone diff |
|---|---|---|---|
| `DIFFING_ENABLE_UNRELIABLE` (46) | `False` | 400-402 | `self.unreliable` (section 3) |
| `DIFFING_ENABLE_RELAXED_RATIO` (47) | `False` | 403-405 | `self.relaxed_ratio`, which changes `check_ratio` and `find_same_name` |
| `DIFFING_ENABLE_EXPERIMENTAL` (48) | `True` | 406-408 | `self.experimental`, read **only** at 3618 (dirty heuristics) |
| `DIFFING_ENABLE_SLOW_HEURISTICS` (49) | `True` | 409-411 | `self.slow_heuristics` |
| `DIFFING_IGNORE_SUB_FUNCTION_NAMES` (50) | `True` | 468 | `self.ignore_sub_names` (`find_same_name`, 2179). **No env override.** |
| `DIFFING_IGNORE_ALL_FUNCTION_NAMES` (51) | `False` | 470-472 | forced to `False` at 3760 |
| `DIFFING_IGNORE_SMALL_FUNCTIONS` (52) | `False` | 474-476 | `%POSTFIX%` stays `""` (1471-1473) |
| `MIN_FUNCTIONS_TO_DISABLE_SLOW` (71) | `4001` | `diaphora_ida.py:3798-3800` only | **Not used by `diaphora.py`** |
| `SQL_MAX_PROCESSED_ROWS` (90) | `1000000` | 454-456, 1874-1880 | row cap per `add_matches_internal` call |
| `SQL_TIMEOUT_LIMIT` (92, `60 * 5`) | `300` | 451, 1548, 1894 | per-heuristic and per-call wall-clock abort |
| `MATCHES_BONUS_RATIO` (116) | `0.01` | 2203-2204, 3109-3110 | same-name partial and callee-diffing bonus |
| `DECIMAL_VALUES` (120) | `"7f"` | 282, 1676 | output ratio format `%.7f`; `check_ratio` rounding |
| `MAX_FUNCTIONS_PER_GAP` (124) | `100` | 3250, 3257 | local affinity |
| `SQL_DEFAULT_POSTFIX` (128) | `" and f.instructions > 5 and df.instructions > 5 "` | 1473 | only if `ignore_small_functions` |
| `MINIMUM_RARE_MD_INDEX` (133) | `10.0` | 1742 | relaxed only |
| `DEFAULT_PARTIAL_RATIO` (137) | `0.5` | many | partial threshold |
| `DEFAULT_TRUSTED_PARTIAL_RATIO` (141) | `0.3` | 3104 | callee diffing |
| `INCREASE_RATIO_PER_CONSTANT_MATCH_SAME_CPU` (147) | `0.006` | 2818 | `deep_ratio` |
| `INCREASE_RATIO_PER_CONSTANT_MATCH` (148) | `0.008` | 2820 | `deep_ratio` |
| `SPEEDUP_STRIPPED_BINARIES_MIN_PERCENT` (160) | `99.0` | 2563 | stripped-mode trigger (`>=`) |
| `SPEEDUP_PATCH_DIFF_SYMBOLS_MIN_PERCENT` (166) | `90.0` | 2610 | patch-diff trigger (`>`, strict) |
| `SPEEDUP_PATCH_DIFF_RENAMED_FUNCTION_MIN_RATIO` (172) | `0.6` | 2714 | renamed-function pass |
| `DIFFING_MATCHES_MAX_DIFFERENT_BBLOCKS_PERCENT` (177) | `25` | 3090 | callee diffing |
| `DIFFING_MATCHES_MIN_BBLOCKS` (183) | `3` | 3096-3098 | callee diffing |
| `RUN_DEFAULT_SCRIPTS` (186) | `True` | 2616 | loads the patch-diff script |
| `DEFAULT_SCRIPT_PATCH_DIFF` (189) | `<config dir>/scripts/patch_diff_vulns.py` | 2618 | see section 5.4 |
| `RELATED_MATCHES_MIN_RATIO` (194) | `0.8` | 3439, 3485 | related CU / constants |
| `THREADS_WAIT_TIME` (200) | `1` | 1546 | poll period (seconds) |
| `ML_USE_TRAINED_MODEL` (205) | `False` | 412-414, 3552 | classifier stays `None` |
| `ML_TRAINED_MODEL_MATCH_SCORE` (209) | `0.15` | 2825 | unreachable by default |
| `SHOW_IMPORT_WARNINGS` (218) | `True` | 46-49 | prints the cdifflib warning; no effect |

The remaining config values (colours, `EXPORTING_*`, `FUZZY_HASHING_BLOCK_SIZE`,
`CLEANING_CMP_REPS`/`REMS`, `SQLITE_*`, `MIN_FUNCTIONS_TO_CONSIDER_*`, `ML_TRAINED_MODEL`,
`ML_DEBUG_SHOW_MATCHES`, `DIAPHORA_WORKAROUND_*`) have **no effect** on the standalone diff. Some
are read, but only into attributes no diff-path code reads: `FUZZY_HASHING_BLOCK_SIZE` (392),
`EXPORTING_EXCLUDE_LIBRARY_THUNK`/`EXPORTING_USE_DECOMPILER` (415-420),
`EXPORTING_ONLY_NON_IDA_SUBS` (462), `EXPORTING_FUNCTION_SUMMARIES_ONLY` (465) and
`EXPORTING_USE_MICROCODE` (479-481). `ML_TRAINED_MODEL` is read only inside
`if ML_AVAILABLE and self.use_trained_model` (3552-3554). `CLEANING_CMP_*` feed
`get_cmp_asm*`/`get_cmp_pseudo_lines` (1037-1090) and `is_auto_generated` (1279-1286). Their
only callers are in `diaphora_ida.py` (exporter and IDA UI: 1889, 1908, 2687, 2960, 2995), never
`diff()`.

### 2.3 IDA vs standalone (do not port the IDA values)

`diaphora_ida.py:3797-3800` computes a GUI default. It is not used standalone:

```python
    self.unreliable = kwargs.get("unreliable", config.DIFFING_ENABLE_UNRELIABLE)
    self.slow = kwargs.get(
      "slow", total_functions <= config.MIN_FUNCTIONS_TO_DISABLE_SLOW
    )
```

`diaphora_ida.py:3727` also sets `bd.timeout = config.SQL_TIMEOUT_LIMIT * max(total_functions / 20000, 1)`,
which is IDA only. Standalone keeps `self.timeout = 300`.

**Runs by default?** In the standalone oracle, slow heuristics are **always on**, even above 4001
functions. The timeout is always 300 s.

---

## 3. `CBinDiff.__init__` — every attribute (`diaphora.py:374-493`)

```python
  def __init__(self, db_name, chooser=CChooser):
    self.names = dict()
    self.primes = primes(2048 * 2048)
    self.db_name = db_name
    self.dbs_dict = {}
    self.db = None  # Used exclusively by the exporter!
    self.open_db()

    self.all_matches = {"best": [], "partial": [], "unreliable": []}
    self.matched_primary = {}
    self.matched_secondary = {}
    ...
    # XXX: FIXME: Parallel diffing is broken outside of IDA due to parallelism problems
    if not IS_IDA:
      self.cpu_count = 1
```

| Attribute | Line | Standalone value | Read on the diff path? |
|---|---|---|---|
| `names` | 375 | `{}` | no (exporter/IDA) |
| `primes` | 376 | primes below 4,194,304 | no. Costs start-up time only |
| `db_name` | 377 | `db1` exactly as given on the CLI | yes: attached-DB owner, and `config.main_db` in the output |
| `dbs_dict` | 378 | `{main_tid: connA}` after `open_db` | yes (connection per thread) |
| `db` | 379-380, 3762 | connA, then replaced by connB in `__main__` | no |
| `all_matches` | 382 | `{"best": [], "partial": [], "unreliable": []}`. **Key order matters** (section 8) | yes |
| `matched_primary` / `matched_secondary` | 383-384 | `{}` | yes. `name -> {"name": other, "ratio": r}` |
| `total_functions1` / `2` | 386-387 | `None` until `find_equal_matches` | yes |
| `equal_callgraph` | 388 | `False` | log only |
| `kfh`, `pseudo`, `pseudo_hash`, `pseudo_comments`, `microcode` | 390-398 | — | no (exporter) |
| `unreliable` | 400 | `False` | yes |
| `relaxed_ratio` | 403 | `False` | yes |
| `experimental` | 406 | `True` | yes (3618 only) |
| `slow_heuristics` | 409 | `True` | yes |
| `use_trained_model` | 412 | `False` | yes (3552) |
| `exclude_library_thunk`, `use_decompiler` | 415-420 | — | no (exporter) |
| `project_script` | 421 | `None` (or env `DIAPHORA_PROJECT_SCRIPT`) | yes |
| `hooks` | 422 | `None` | yes |
| `chooser` | 425 | `CChooser` class | yes |
| (choosers) | 426 | `create_choosers()` (section 10.1) | yes |
| `last_diff_db` | 428 | `None`, then `db2` in `diff()` | yes (thread attach, `config.diff_db`) |
| `re_cache` | 429 | `{}` | no |
| `_funcs_cache` | 430 | `{}` | no (exporter) |
| `ratios_cache` | 431 | `{}`, reset in `diff()` | yes. Key `f"{ea1}-{ea2}"` |
| `items_lock` | 432 | `Lock()` | yes (serialises `add_match`/`cleanup_matches`) |
| `is_symbols_stripped` | 434 | `False` | log only |
| `is_patch_diff` | 435 | `False` | yes (2708) |
| `is_same_processor` | 436 | `False`, set in `diff()` at 3617 | yes |
| `unmatched_primary` / `unmatched_second` | 426 → 438-439 | `create_choosers()` (426, via 2369-2370) creates them first, and then lines 438-439 **overwrite both with `None`**. They are `None` after `__init__` (V1). `find_unmatched` reassigns each one only if its `select` returned ≥1 row (2333, 2346). Otherwise it stays `None` and `save_results` skips it (2420). | output |
| `do_continue` | 440 | `None`, then `True` | trivially `True` |
| `percent` | 443 | `0` | log only |
| `classifier` | 445 | `None` | yes. Stays `None` by default |
| `timeout` | 451 | `300` | yes |
| `sql_max_processed_rows` | 454 | `1000000` | yes |
| `min_ea`, `max_ea`, `ida_subs`, `function_summaries_only` | 458-465 | — | no (exporter) |
| `ignore_sub_names` | 468 | `True` | yes |
| `ignore_all_names` | 470, 3760 | `False` | yes |
| `ignore_small_functions` | 474 | `False` | yes |
| `export_microcode` | 479 | — | no |
| `cpu_count` | 484-491 | **1** (forced for `not IS_IDA`; env `DIAPHORA_CPU_COUNT` is overridden) | yes |

### 3.1 Database side effects of construction

`open_db` (`diaphora.py:571-581`) calls `create_schema()` on the **main** DB when it runs on the
main thread. `create_schema` (`diaphora.py:615-632`):

```python
      cur.execute("PRAGMA foreign_keys = ON")

      for sql in schema.TABLES:
        cur.execute(sql)

      cur.execute("select 1 from version")
      row = cur.fetchone()
      if not row:
        cur.execute("insert into main.version values (?)", (VERSION_VALUE,))
        cur.execute("commit")
```

This means **db1 is mutated** if it is missing any schema table (created empty with `create table
if not exists`, `db_support/schema.py:68-186`) or if its `version` table is empty (`'3.4'` is
inserted). If the db1 path **does not exist**, `sqlite3.connect` creates it, so it becomes a fresh
schema-only database. The run then has `total_functions1 == 0` and dies with `ZeroDivisionError`
at 2562 (default config). db2 is never schema-fixed.

**Porting spec:** do not write to the inputs. When db1 lacks a side table
(`constants`, `compilation_units`, `compilation_unit_functions`, `callgraph`, ...), treat it as
**present and empty**. When **db2** lacks one, Diaphora's SQL fails (section 13). Report that as an
unsupported input rather than emulating it.

**Runs by default?** Yes, on every run.

---

## 4. Connection and thread model

- Main thread: connA (opened in `__init__`). `diff()` runs `attach "<db2>" as diff` on it through
  `try_attach` (`diaphora.py:2431-2443`), which swallows any error. `attach` of a missing path
  **creates an empty (0-byte) file** (V10). The next `select value from diff.version` then fails
  with `no such table: diff.version` and `diff()` returns `False` (section 5.1). The path is
  spliced into a **double-quoted** token (2441). That only works because SQLite accepts a
  double-quoted string literal where an identifier is not found. A path containing `"` makes the
  attach fail silently, which gives the same empty result.
- Heuristic threads: `get_db()` (`diaphora.py:584-593`) opens a new connection to `db_name` for each
  new thread id and attaches `last_diff_db` through `attach_database` (651-659, **not** swallowed:
  a failure kills that heuristic). It does not run `create_schema` off the main thread. Thread
  idents can be reused after a thread exits, and a reused ident gets the earlier, already attached
  connection. This does not affect results.
- `threads_apply(threads=1, …)` (`jkutils/threads.py:27-72`) starts **one thread at a time** and
  waits for it before starting the next. There is no real concurrency, so results do not depend
  on thread timing. The exception is timeouts (section 13).
- An exception inside a heuristic thread kills **that heuristic only**. Matches it added before
  the exception are kept. Exceptions in main-thread passes abort the whole run.

**Porting spec:** run everything sequentially in the order below. Per-heuristic "abort and keep
partial results" only matters on malformed data or on timeouts.

---

## 5. `diff()` — orchestration (`diaphora.py:3568-3701`)

```python
  def diff(self, db):
    """
    Diff the current two databases (main and diff).
    """
    self.ratios_cache = {}
    self.last_diff_db = db
    cur = self.db_cursor()
    self.try_attach(cur, db)

    try:
      cur.execute("select value from diff.version")
    except:
      log(f"Error: {sys.exc_info()[1]}")
      log("The selected file does not look like a valid Diaphora exported database!")
      cur.close()
      return False

    row = cur.fetchone()
    if not row:
      log("Invalid database!")
      return False

    if row["value"] != VERSION_VALUE:
      log(f"WARNING: The database is from a different version (current {VERSION_VALUE}, database {row[0]})!")

    try:
      t0 = time.monotonic()
      cur_thread = threading.current_thread()
      cur_thread.timeout = False
      log_refresh("Diffing...", True)

      self.do_continue = True
      if self.equal_db():
        log("The databases seems to be 100% equal")

      if self.do_continue:
        # Compare the call graphs
        self.check_callgraph()

        if self.project_script is not None:
          log("Loading project specific Python script...")
          if not self.load_hooks():
            return False

        # Find the unmodified functions
        log_refresh("Finding equal matches...")
        self.find_equal_matches()

        skip_others = False
        self.is_same_processor = self.same_processor_both_databases()
        if self.experimental:
          # Dirty magic. Might or might not work...
          log_refresh("Checking 'dirty' heuristics...")
          skip_others = self.apply_dirty_heuristics()

        if not self.ignore_all_names:
          self.find_same_name("partial")

        if skip_others:
          self.find_remaining_functions()
        else:
          log_refresh("Finding best matches...")
          self.run_heuristics_for_category("Best")

          # Find the modified functions
          log_refresh("Finding partial matches")
          self.find_partial_matches()

          self.apply_machine_learning()

          if self.unreliable:
            ...
            self.find_unreliable_matches()
            ...
            self.find_experimental_matches()

          iteration = 0
          while 1:
            self.cleanup_matches()
            old_total = self.get_total_matched_functions()

            # Find new matches by diffing assembly and pseudo-code of previously
            # found matches
            self.find_matches_diffing(iteration)

            if self.slow_heuristics:
              # Find new matches by digging from previous very good matches
              self.find_related_matches(iteration)

            self.find_related_compilation_unit(iteration)

            # Find new matches in the functions between matches
            self.find_locally_affine_functions(iteration)

            self.cleanup_matches()
            new_total = self.get_total_matched_functions()
            if new_total <= old_total:
              break
            iteration += 1

        self.final_pass()

        # Show the list of unmatched functions in both databases
        log_refresh("Finding unmatched functions")
        self.find_unmatched()
        self.call_hook("on_finish", None, [])

        best = len(self.best_chooser.items)
        partial = len(self.partial_chooser.items)
        unreliable = len(self.unreliable_chooser.items)
        multi = len(self.multimatch_chooser.items)
        total = best + partial + unreliable
        percent = ((best + partial + unreliable) * 100) / self.total_functions1
        log(
          f"Final results: Best {best}, Partial {partial}, Unreliable {unreliable}, Multimatches {multi}"
        )
        ...
    finally:
      cur.close()
    return True
```

### 5.0 Pass table (default standalone config)

"Mode" is decided at step 7: **N** = normal, **S** = stripped, **P** = patch-diff.

| Step | Pass | Gate | Runs by default? | Changes matches? |
|---|---|---|---|---|
| 1 | attach + `diff.version` check | always | yes | abort path only |
| 2 | `equal_db` | always | yes | **no** (log only; can throw, for example when either DB lacks `program`/`functions` or the `md5sum`/`id`/`address`/`size`/`nodes`/`edges` columns) |
| 3 | `check_callgraph` | always | yes | **no** (log only; can throw) |
| 4 | `load_hooks` (user script) | `project_script is not None` | **no** (`None`) | — |
| 5 | `find_equal_matches` | always | yes | yes → `best` |
| 6 | `same_processor_both_databases` | always | yes | sets `is_same_processor` |
| 7 | `apply_dirty_heuristics` | `experimental` | **yes** | S adds matches; P loads hooks |
| 8 | `find_same_name("partial")` | `not ignore_all_names` | **yes** (forced) | yes |
| 9 | `find_remaining_functions` | `skip_others` (S or P) | S: no-op; P: yes | P only |
| 10 | `run_heuristics_for_category("Best")` | N | yes | yes |
| 11 | `find_partial_matches` = `run_heuristics_for_category("Partial")`, then `search_small_differences` (slow) | N | yes / yes | yes |
| 12 | `apply_machine_learning` | N and `ML_AVAILABLE and use_trained_model` | no-op | no |
| 13 | `find_unreliable_matches`, `find_experimental_matches` | N and `unreliable` | **no** | — |
| 14 | convergence loop (section 7) | N | yes, ≥1 iteration | yes |
| 15 | `final_pass` | always | yes | builds the choosers |
| 16 | `find_unmatched` | always | yes | builds the unmatched choosers |
| 17 | `on_finish` hook | hooks loaded | P only | no |

`find_experimental_matches` would be a no-op even when reached: no heuristic has
`category == "Experimental"`. The categories are Best (12), Partial (30) and Unreliable (8), from
`HEURISTICS` in `diaphora_heuristics.py`.

### 5.1 Step 1 — attach and version check

- `select value from diff.version` throws (for example "no such table") → `return False`, and
  `save_results` writes a config row with **empty** results.
- No row → `return False` (same result).
- `value != "3.4"` → warning only.

**Porting spec:** mirror it. db2 must have a `version` table with ≥1 row, otherwise emit an empty
result.

### 5.2 Step 2 — `equal_db` (`diaphora.py:661-687`)

```python
      sql = "select count(*) total from program p, diff.program dp where p.md5sum = dp.md5sum"
      cur.execute(sql)
      row = cur.fetchone()
      ret = row["total"] == 1
      if not ret:
        sql = """select count(*) total
                   from (select id, address, size, nodes, edges
                           from functions
                         except
                         select id, address, size, nodes, edges
                           from diff.functions) x"""
        cur.execute(sql)
        row = cur.fetchone()
        ret = row["total"] == 0
      else:
        log("Same MD5 in both databases")
```

Result: a log line only. `do_continue` is always `True` (3599). **Porting spec:** optional. If
implemented, only for the log. **Runs by default?** Yes, with no effect on matches.

### 5.3 Step 3 — `check_callgraph` / `get_callgraph_difference` (`diaphora.py:1288-1338`)

```python
      sql = """select callgraph_primes, callgraph_all_primes from program
        union all
        select callgraph_primes, callgraph_all_primes from diff.program"""
      cur.execute(sql)
      rows = cur.fetchall()
      if len(rows) == 2:
        cg1 = decimal.Decimal(rows[0]["callgraph_primes"])
        cg_factors1 = json.loads(rows[0]["callgraph_all_primes"])
        cg2 = decimal.Decimal(rows[1]["callgraph_primes"])
        cg_factors2 = json.loads(rows[1]["callgraph_all_primes"])

        if cg1 == cg2:
          self.equal_callgraph = True
          ...
          return 0
        else:
          FACTORS_CACHE[cg1] = cg_factors1
          FACTORS_CACHE[cg2] = cg_factors2
          diff = difference(cg1, cg2)
          total = sum(cg_factors1.values())
          if total == 0 or diff == 0:
            return 0

          percent = diff * 100.0 / total
          return percent
      else:
        raise Exception(f"Not enough rows in databases! Size is {len(rows)}")
```

`self.percent` and `self.equal_callgraph` are never read again (grep of `diaphora.py`). The pass
only **constrains the input**. The check at 1299 is on the **combined** row count of the
`union all`: it must be exactly 2. The intended case is one row per `program`. A (2, 0) or (0, 2)
split also passes silently, and then compares one DB's rows with each other, which is log only. A
NULL `callgraph_primes` raises `TypeError` in `Decimal(None)`. A non-numeric one raises
`decimal.InvalidOperation`. The tester sample uses scientific notation such as `9.98…E+365`
(`tester/samples/ls.cfg`). `callgraph_all_primes` must always be valid, non-NULL JSON (both
`json.loads` run first, 1301/1303). It must also be an object with numeric values when
`cg1 != cg2`, for `sum(cg_factors1.values())` at 1315. Any violation raises on the main thread, and
no new output is written.

**Porting spec:** validate the preconditions (2 rows in total, one per `program` in practice).
Computing the percent is optional and log only. **Runs by default?** Yes, with no effect on
matches.

### 5.4 Step 4 and hooks — `load_hooks`, `call_hook`, the patch-diff script

`load_hooks` (`diaphora.py:528-558`) returns `True` when `project_script` is `None` or `""`.
Otherwise it imports the file as module `diaphora_hooks` and instantiates
`HOOKS["DiaphoraHooks"](self)` into `self.hooks`. Failure → `False`. At step 4 that aborts `diff()`
(→ empty output). At step 7b the return value is ignored.

`call_hook` (`diaphora.py:1450-1459`):

```python
    if self.hooks is not None:
      method = getattr(self.hooks, func_name, None)
      if method is not None:
        return method(*args)
    return default_ret
```

Hook points on the diff path:

| Hook | Call site | Default | patch_diff_vulns.py |
|---|---|---|---|
| `get_queries_postfix(category, postfix)` | 1475. **Return value discarded** | — | returns `postfix` |
| `get_heuristics(category, list)` | 1477 | the list | returns it unchanged (79-80) |
| `on_launch_heuristic(name, sql)` | 1520. `None` skips the heuristic | the sql | returns sql (82-83) |
| `on_match(main_d, diff_d, desc, r)` | 1871 (`check_match`) | `[should_add, r]` | returns `(True, ratio)` (204-236) |
| `on_match(d1, d2, desc, r)` | 3029 (`call_on_match_hook`, only if `"on_match" in dir(self.hooks)`, 3008). It passes `name2 = main_row["name"]` (3013), a source bug that affects only the hook's arguments. Its callers, callee diffing (3112) and local affinity (3297), run only in mode N, where no default script is loaded. | `(True, r)` | same |
| `on_special_heuristic(heur, iteration)` | 3222, 3227, 3336, 3409, 3467 | `True` | **not defined → True** |
| `on_finish()` | 3682 | `None` | `self.chooser.show(force=True)`, a no-op standalone |

**Is the default script loaded?** Only in patch-diff mode (step 7b). Even then it **does not change
match results**. Every hook returns its input unchanged, and `on_match` always returns
`True, ratio` (`scripts/patch_diff_vulns.py:213, 236`). E3 confirmed identical output with the
script disabled. Its side effects are:

1. It creates an "Interesting matches" chooser (`patch_diff_vulns.py:70-71`), which is **never
   saved**.
2. It re-imports `diaphora.py` as the module `diaphora` (`from diaphora import CChooser, log`,
   line 13), which prints the import warnings a second time. The real userenv mode-P oracle log
   shows the `cdifflib` warning twice. It is harmless. The new module gets fresh globals, so its
   `_DATABASES` cleanup (329-337) closes nothing. The module-level `importlib.reload(config)` and
   the other reloads (89-94) re-execute unchanged files, and `__main__`'s already-bound
   `HEURISTICS`/`threads_apply` objects are unaffected.
3. It can **crash the run**. For every `on_match` with `ratio < 1.0` whose `str([name1, name2])`
   key is new (206-214), `find_vulns_using_assembly` walks `unified_diff(asm1.split("\n"),
   asm2.split("\n"))` (137). The header lines `--- ` and `+++ ` already set `removed='-- \n'`
   and `added='++ \n'` (148-152), so the check at 154 is live from the first real change onward.
   For each `-`/`+` line it computes `mnem1 = added.split(" ")[0].lower()` (156). If `mnem1` is
   not in `SIGNED_UNSIGNED_LIST`, it evaluates `mnem1[0]` (162). An **added** line that is empty
   or starts with a space therefore raises `IndexError` (E8). A **removed** line of that kind
   raises only when the current `mnem1` starts with `b`, because `mnem2[0]` sits behind a
   short-circuit `and`. The walk stops at the first signed/unsigned hit (`break`, 161/168). The
   exception propagates out of `check_match` in `find_same_name` or `search_remaining_functions`
   (main thread), so the run aborts and **no new output file is written**. Observed (V13): the
   real `ls`, `userenv-9168-pdb` and `userenv-9278-pdb` exports contain **no** empty or space-led
   assembly lines (19,530 / 29,757 / 30,923 lines checked), and the userenv mode-P oracle run
   completed with exit 0. This is a latent hazard, not one that appears on the current corpus.

**Porting spec:** implement no hooks. Document that the reference aborts in the item 3 case. The
parity harness should delete the output path before each run, then treat a missing output file as
"oracle crashed", not "zero matches". A crash does not remove an old file. **Runs by default?**
Hooks are loaded only in P mode, and they are result-neutral.

### 5.5 Step 5 — `find_equal_matches` (`diaphora.py:1404-1442`)

```python
      sql = """select count(*) total from functions
        union all
        select count(*) total from diff.functions"""
      ...
      self.total_functions1 = rows[0]["total"]
      self.total_functions2 = rows[1]["total"]

      fields = "id, address, mangled_function, nodes, edges, size, bytes_hash"
      sql = f"""select address ea, mangled_function, nodes, bytes_hash
                 from (select {fields}
                         from functions
                    intersect
                       select {fields}
                         from diff.functions) x"""
      cur.execute(sql)
      rows = cur.fetchall()
      if len(rows) > 0:
        for row in rows:
          name = row["mangled_function"]
          ea = row["ea"]
          nodes = int(row["nodes"])

          item = [ea, name, ea, name, "100% equal", 1, nodes, nodes]
          self.add_match(name, name, 1.0, item, "best")
```

**Porting spec**

```
total_functions1 = COUNT(*) of main.functions; total_functions2 = COUNT(*) of diff.functions
T = SET-INTERSECTION of tuples (id, address, mangled_function, nodes, edges, size, bytes_hash)
    // SQL INTERSECT semantics: NULL equals NULL here, and values compare with SQLite type rules
    // (integer 5 != text '5').
for t in T ordered ascending by the full tuple (SQLite temp-B-tree order: NULL < numbers < text < blob;
                                             text BINARY/memcmp):              // E7
    add_match(t.mangled_function, t.mangled_function, 1.0,
              [t.address, t.mangled_function, t.address, t.mangled_function, "100% equal", 1, int(t.nodes), int(t.nodes)],
              "best")
```

- Because the first compound column is `id`, an `integer primary key` (`schema.py:70`) and unique
  on each side, "ordered by the full tuple" works out to **ascending `id`**.
- The **name used is `mangled_function`, not `name`**. The exporter stores
  `name = demangle_name(true_name, INF_SHORT_DN) or true_name` and
  `mangled_function = true_name = get_func_name(ea)` (`diaphora_ida.py:2451-2453`, placed by
  `build_props_list` 3141-3156 into the column order of `diaphora.py:943-946`). On the real
  corpus (V11) `name != mangled_function` for 393 of 643 functions in `userenv-9168-pdb` and 411
  of 663 in `userenv-9278-pdb`, and 0 of 318 in `ls`. In the PDB exports `name` is the **full**
  demangled signature (for example `public: static long _tlgWriteTemplate<…>::Write<…>(…)`), not
  a short name. This has four effects:
  1. The output row shows the mangled name.
  2. `matched_primary` gets the mangled key, so a later `find_same_name` also matches the same
     pair under the demangled name. There are then two best items for one address pair, and the
     second is dropped at write time by `insert or ignore` (E4).
  3. `all_functions_matched()` can become true early (section 8.6).
  4. Name-keyed lookups such as `get_function_row(item.vfname)` in the convergence loop return
     `None` for these items, so they never seed callee diffing or related matches.
- `id` is part of the key: identical functions at a different `id` are **not** "100% equal".
- A NULL `mangled_function` gives name `None`. All such items share the cleanup key
  `"None-None"` and collapse to one (section 8.5). Native exports must never emit a NULL
  `mangled_function`.
- The `ratio` field is the int `1`. It formats as `1.0000000` and compares equal to `1.0`, so store
  a double.

**Runs by default?** Yes, always, in every mode.

### 5.6 Step 6 — `same_processor_both_databases` (`diaphora.py:2950-2967`)

```python
      sql = """ select 1
          from main.program mp,
             diff.program dp
         where mp.processor = dp.processor"""
      cur.execute(sql)
      row = cur.fetchone()
      if row is not None:
        ret = True
```

`is_same_processor` = the processor texts are equal (SQL `=`, case-sensitive BINARY; NULL never
equal). It is set **before** any ratio is computed, because `check_ratio` is first reached at step
7. It gates the `SAME_CPU` heuristics (1506), callee assembly diffing (3220), and the `deep_ratio`
constant bonus (2817-2820). **Runs by default?** Yes.

### 5.7 Step 7 — `apply_dirty_heuristics` (`diaphora.py:2629-2637`) → the mode decision

```python
    if self.search_just_stripped_binaries():
      return True
    if self.search_patchdiff_with_symbols():
      return True
    return False
```

#### 7a. Stripped mode (`diaphora.py:2540-2585`)

```python
      sql = """select count(0)
                 from main.functions f,
                      diff.functions df
                where f.address = df.address """
      cur.execute(sql)
      row = cur.fetchone()
      matches = row[0]
      ...
      percent = (matches * 100) / total
      if percent >= config.SPEEDUP_STRIPPED_BINARIES_MIN_PERCENT:
        self.is_symbols_stripped = True
        ...
        heur = "Same binary with symbols stripped"
        sql = (
          """
    select distinct """
          + get_query_fields(heur)
          + """
      from functions f,
           diff.functions df
     where f.address = df.address"""
        )
        ...
        self.add_matches_from_query_ratio(sql, "best", "partial")
        ret = True
```

- `total = self.total_functions1`. `total == 0` → **ZeroDivisionError**, and no new output file
  (a pre-existing one stays, V9).
- The trigger is `matches*100/total >= 99.0`, computed as a double (Python true division is
  correctly rounded, the same as IEEE double `(double)(matches*100)/total`). `matches` is a join
  count on the TEXT `address`.
- Matching runs on the **main thread** through `add_matches_from_query_ratio` → `add_matches_internal`
  with `val=None` → 0.5 and `unreliable=None`. That gives ratio 1.0 → `best`, ≥0.5 → `partial`,
  and anything below is dropped. The description is `'Same binary with symbols stripped'`.
- `add_matches_from_query_ratio` first returns immediately if `all_functions_matched()` (1956).
  It **catches `SystemExit`** (1965-1966), so a 300 s per-call timeout here only truncates the
  stripped pass silently after logging `Timeout with heuristic 'MainThread'`, and the run
  continues. Any other exception is re-raised (1967-1973) and aborts the run.
- Mode S then continues with steps 8 and 9 (a no-op) and then `final_pass`. **No SQL heuristics
  and no convergence loop run.**

#### 7b. Patch-diff mode (`diaphora.py:2587-2627`)

```python
      sql = """select count(0)
                 from main.functions f,
                      diff.functions df
                where f.mangled_function = df.mangled_function """
      ...
      percent = (matches * 100) / total
      if percent > config.SPEEDUP_PATCH_DIFF_SYMBOLS_MIN_PERCENT:
        ...
        self.is_patch_diff = True
        if self.project_script is None or self.project_script == "":
          if config.RUN_DEFAULT_SCRIPTS:
            log("Loading default script for patch diffing sessions...")
            self.project_script = config.DEFAULT_SCRIPT_PATCH_DIFF
            self.load_hooks()
        ...
        ret = True
```

- This is evaluated only if 7a did not trigger. The test is strict `>`: exactly 90.0% does **not**
  trigger. `matches` is a **join count**, so duplicate mangled names inflate it (it can exceed
  100%).
- It adds no matches itself. It sets `is_patch_diff` and loads the hooks (section 5.4).
- Mode P continues with step 8 (same name), step 9 (renamed functions) and `final_pass`. **No SQL
  heuristics and no convergence loop run.**

> This matters for the project's corpus, and it is now **observed** (V12, oracle logs in
> `<corpus>/oracle/diffs/*/run1/diaphora.log`):
> `userenv-9168-pdb_vs_9278-pdb` logged `Patch diffing detected: A total of 643 matches out of 643,
> 100.0% percent have the same name`, so it ran in **mode P** (Best 635, Partial 8, 20
> `unmatched` rows of type `primary`, which are the 663 − 643 db2-only functions). `ls_vs_ls-old`,
> `ls-old_vs_ls`, `sechost-9168-pdb_vs_9444-nopdb` and `userenv-9168-pdb_vs_9278-nopdb` logged
> neither detection line and ran the SQL heuristic tier, so they ran in **mode N**. The parity
> harness must keep recording which mode each oracle run took by parsing
> `Symbols stripped detected:` or `Patch diffing detected:`.

**Runs by default?** Yes, because `experimental=True`. Which mode results depends on the data.

### 5.8 Step 8 — `find_same_name("partial")` (`diaphora.py:2152-2210`)

This runs in **every** mode (`ignore_all_names` is forced to `False`). Key points (the full
semantics belong in the heuristics spec):

- SQL: `select distinct <fields 'Perfect match, same name'> from functions f, diff.functions df
  where (df.mangled_function = f.mangled_function or df.name = f.name) and f.name not like 'nullsub_%'`.
  LIKE is ASCII-case-insensitive and `_` is a wildcard. `fetchall()` is used, and the loop runs only
  if `not all_functions_matched()` holds at that moment (checked once).
- It skips a row when `ignore_sub_names and row["mangled1"].startswith("sub_")`. This tests the
  **main mangled name**, and a NULL `mangled1` raises `AttributeError` (main thread → abort).
- `check_match(row)` (section 8.3), then: if `float(ratio) == 1.0` (or relaxed with equal md) →
  `best` with item ratio `1`. Otherwise `partial`, with `ratio += 0.01` if `ratio + 0.01 < 1.0`.
  The description is always `'Perfect match, same name'`.
- `add_match(name1, name2, ratio, item, chooser)`. When `name1 == name2`, `add_match` forces the
  bookkeeping ratio to 1.0 (section 8.1).
- It runs on the main thread and does not go through `add_matches_internal`, so it has **no**
  timeout or row cap at all.

### 5.9 Step 9 — `find_remaining_functions` (`diaphora.py:2639-2716`)

```python
    main_unmatched, diff_unmatched = self.get_unmatched_functions()
    if self.is_patch_diff:
      heur = "Renamed or anonymous function match in patch diffing session"
      values = {
        "only_sub": True,
        "heur": heur,
        "small": False,
        "val": config.SPEEDUP_PATCH_DIFF_RENAMED_FUNCTION_MIN_RATIO,
      }
      self.search_remaining_functions(main_unmatched, diff_unmatched, values)
```

`get_unmatched_functions` (2647-2666) runs `select 'main' db_name, name, address from main.functions
union select 'diff' db_name, name, address from diff.functions`. The rows come back sorted by
(`db_name`, `name`, `address`), bytewise text (E7, `UNION USING TEMP B-TREE`). A row is kept when
`name not in matched_primary` (for main) or `not in matched_secondary` (for diff), and duplicate
`[ea, name]` pairs are dropped.

`search_remaining_functions` (2671-2700):

```python
    sql = (
      """select """
      + get_query_fields("?", quote=False)
      + """
         from main.functions f,
          diff.functions df
        where f.address = ?
        and df.address = ?"""
    )
    if not values["small"]:
      sql += " and f.nodes >= 3 and df.nodes >= 3 "
    ...
      for ea1, name1 in main_unmatched:
        if values["only_sub"]:
          if not name1.startswith("sub_"):
            continue

        for ea2, _ in diff_unmatched:
          cur.execute(sql, (values["heur"], ea1, ea2))
          self.add_matches_internal(
            cur, best="best", partial="partial", val=values["val"]
          )
```

**Porting spec:** the unmatched lists are snapshotted **once**. The candidates are the main
functions whose `name` starts with `sub_`, against **every** unmatched diff function (named or not).
Loop main-outer and diff-inner in the sorted order above. For each pair where both have
`nodes >= 3`, apply `add_matches_internal` with `val=0.6` and `unreliable=None`: 1.0 → `best`,
≥0.6 → `partial`, otherwise dropped. Earlier pairs block later ones through `check_match`'s
`has_best_match`/`has_better_match`, because pairs added in this loop are **not** removed from the
lists. The description is the bound parameter
`"Renamed or anonymous function match in patch diffing session"`.

**Runs by default?** Only in mode P. In mode S, `get_unmatched_functions` runs but nothing else
happens.

### 5.10 Steps 10-11 — `run_heuristics_for_category` (`diaphora.py:1461-1552`)

```python
    total_cpus = self.get_threads_count()
    ...
    postfix = ""
    if self.ignore_small_functions:
      postfix = config.SQL_DEFAULT_POSTFIX

    self.call_hook("get_queries_postfix", None, [arg_category, postfix])
    heuristics = list(HEURISTICS)
    heuristics = self.call_hook("get_heuristics", heuristics, [arg_category, heuristics])

    heuristic_functions = []
    for heur in heuristics:
      if len(self.matched_primary) == self.total_functions1 or\
         len(self.matched_secondary) == self.total_functions2:
        log("All functions matched in at least one database, finishing.")
        break

      category = heur["category"]
      if category != arg_category:
        continue
      ...
      flags = heur["flags"]
      if HEUR_FLAG_UNRELIABLE in flags and not self.unreliable:
        ... continue
      if HEUR_FLAG_SLOW in flags and not self.slow_heuristics:
        ... continue
      if HEUR_FLAG_SAME_CPU in flags and not self.is_same_processor:
        ... continue

      if arg_category.lower() == "unreliable":
        best = "partial"
        partial = "unreliable"
      else:
        best = "best"
        partial = "partial"
      ...
      sql = sql.replace("%POSTFIX%", postfix)
      sql = self.call_hook("on_launch_heuristic", sql, [name, sql])
      if sql is None:
        continue

      if ratio == HEUR_TYPE_NO_FPS:
        function = self.add_matches_from_query
        function_args = [sql, best]
      elif ratio == HEUR_TYPE_RATIO:
        function = self.add_matches_from_query_ratio
        function_args = [sql, best, partial]
      elif ratio == HEUR_TYPE_RATIO_MAX:
        function = self.add_matches_from_query_ratio_max
        function_args = [sql, best, partial, min_value]
      elif ratio == HEUR_TYPE_RATIO_MAX_TRUSTED:
        function = self.add_matches_from_query_ratio_max_trusted
        function_args = [sql, min_value]
      ...
      heur_item = {"name":name, "target": function, "args":function_args}
      heuristic_functions.append(heur_item)

    threads_apply(
      threads     = total_cpus,
      targets     = heuristic_functions,
      wait_time   = config.THREADS_WAIT_TIME,
      log_refresh = log_refresh,
      timeout     = config.SQL_TIMEOUT_LIMIT
    )

    self.cleanup_matches()
    self.show_summary()
```

`jkutils/threads.py:36-40`, the ordering-critical lines. The wait/reap loop, which also sets
`t.timeout`, is 55-64:

```python
  while first or len(targets) > 0 or len(threads_list) > 0:
    first = False
    times += 1
    if len(targets) > 0 and len(threads_list) < threads:
      item = targets.pop()
```

**Porting spec**

```
run_category(cat):
  eligible = []
  for h in HEURISTICS in list order:
      if len(matched_primary) == total_functions1 or len(matched_secondary) == total_functions2: break  // snapshot at build time
      if h.category != cat: continue
      if UNRELIABLE in h.flags and !unreliable: continue
      if SLOW in h.flags and !slow_heuristics: continue
      if SAME_CPU in h.flags and !is_same_processor: continue
      eligible.push(h with %POSTFIX% -> "")
  for h in REVERSE(eligible):                      // list.pop() == last element first (verified E1)
      run_one(h)                                   // each returns immediately if all_functions_matched()
  cleanup_matches()
  (show_summary: log only)
run_one dispatch (best/partial = "best"/"partial" for Best and Partial categories):
  NO_FPS            -> add_matches_from_query(sql, "best")
  RATIO             -> add_matches_from_query_ratio(sql, "best", "partial")               // val=0.5, unreliable=None
  RATIO_MAX         -> add_matches_from_query_ratio_max(sql, "best", "partial", h.min)    // val=min, unreliable="unreliable"
  RATIO_MAX_TRUSTED -> add_matches_from_query_ratio_max_trusted(sql, h.min)               // val=min, unreliable="partial"
```

- There is **no** `cleanup_matches` between heuristics inside a category. The state accumulates,
  and `has_best_match`/`has_better_match` see earlier heuristics' raw adds.
- The output `description` is the SQL column `description`, which is a literal in each query
  (`get_query_fields(NAME)` → `repr(NAME)`, `diaphora_heuristics.py:76-84`). It is **not** always
  `heur["name"]`. For example, "Equal assembly or pseudo-code" emits `'Equal pseudo-code'` or
  `'Equal assembly'` (`diaphora_heuristics.py:277, 287`).
- Category routing (`add_matches_internal`, `diaphora.py:1922-1946`): r == 1.0 → `best`, otherwise
  `r >= val and partial is not None` → `partial`, otherwise the third branch. That branch needs
  `r < 0.5 and r > val`, but it is reached only when `r < val` (partial is always non-None here),
  so it is **unreachable** for every SQL heuristic. It also hard-codes the literal chooser
  `"unreliable"` and ignores the value of the `unreliable` argument. The net routing by type is:
  NO_FPS → best only; RATIO → `[0.5, 1.0)` partial; RATIO_MAX and RATIO_MAX_TRUSTED → `[min, 1.0)`
  partial (so TRUSTED with min 0.44 admits `[0.44, 0.5)` into partial); anything lower is dropped.
  In the Best category, `Same RVA` (RATIO_MAX, min 0.7) therefore sends `[0.7, 1.0)` to
  **partial**.

Default-config eligibility and **actual execution order** (generated from `HEURISTICS`, not typed):

**Best: 12 defined. 12 run with the same CPU, 5 with different CPUs.**

| HEURISTICS idx | name | ratio type | min | flags | run position (same CPU) | run position (diff CPU) |
|---|---|---|---|---|---|---|
| 0 | Same RVA and hash | NO_FPS | - | SAME_CPU | 12 | skipped |
| 1 | Same order and hash | NO_FPS | - | SAME_CPU | 11 | skipped |
| 2 | Function Hash | NO_FPS | - | SAME_CPU | 10 | skipped |
| 3 | Bytes hash | NO_FPS | - | SAME_CPU | 9 | skipped |
| 4 | Same address and mnemonics | RATIO | - | - | 8 | 5 |
| 5 | Same cleaned assembly | RATIO | - | SAME_CPU | 7 | skipped |
| 6 | Same cleaned microcode | RATIO | - | SAME_CPU | 6 | skipped |
| 7 | Same cleaned pseudo-code | RATIO | - | - | 5 | 4 |
| 8 | Same address, nodes, edges and mnemonics | RATIO | - | - | 4 | 3 |
| 9 | Same RVA | RATIO_MAX | 0.7 | SAME_CPU | 3 | skipped |
| 10 | Equal assembly or pseudo-code | NO_FPS | - | - | 2 | 2 |
| 11 | Microcode mnemonics small primes product | RATIO | - | - | 1 | 1 |

**Partial: 30 defined. 27 run with the same CPU, 26 with different CPUs.**

| HEURISTICS idx | name | ratio type | min | flags | run position (same CPU) | run position (diff CPU) |
|---|---|---|---|---|---|---|
| 12 | Same named compilation unit function match | RATIO_MAX_TRUSTED | 0.44 | - | 27 | 26 |
| 13 | Same anonymous compilation unit function match | RATIO_MAX | 0.449 | - | 26 | 25 |
| 14 | Same compilation unit | RATIO | - | SLOW | 25 | 24 |
| 15 | Same KOKA hash and constants | RATIO | - | - | 24 | 23 |
| 16 | Same KOKA hash and MD-Index | RATIO | - | - | 23 | 22 |
| 17 | Same constants | RATIO_MAX | 0.5 | - | 22 | 21 |
| 18 | Same rare KOKA hash | RATIO_MAX | 0.45 | - | 21 | 20 |
| 19 | Same rare MD Index | RATIO | - | - | 20 | 19 |
| 20 | Same address and rare constant | RATIO_MAX | 0.5 | - | 19 | 18 |
| 21 | Same rare constant | RATIO_MAX | 0.2 | SLOW | 18 | 17 |
| 22 | Same MD Index and constants | RATIO | - | - | 17 | 16 |
| 23 | Import names hash | RATIO | - | - | 16 | 15 |
| 24 | Mnemonics and names | RATIO | - | - | 15 | 14 |
| 25 | Pseudo-code fuzzy hash | RATIO | - | - | 14 | 13 |
| 26 | Similar pseudo-code and names | RATIO_MAX | 0.579 | - | 13 | 12 |
| 27 | Mnemonics small-primes-product | RATIO_MAX | 0.6 | - | 12 | 11 |
| 28 | Same nodes, edges, loops and strongly connected components | RATIO_MAX | 0.549 | - | 11 | 10 |
| 29 | Same low complexity, prototype and names | RATIO_MAX | 0.5 | - | 10 | 9 |
| 30 | Same low complexity and names | RATIO_MAX | 0.5 | - | 9 | 8 |
| 31 | Switch structures | RATIO_MAX | 0.5 | - | 8 | 7 |
| 32 | Pseudo-code fuzzy (normal) | RATIO_MAX | 0.5 | - | 7 | 6 |
| 33 | Pseudo-code fuzzy (mixed) | RATIO | - | - | 6 | 5 |
| 34 | Pseudo-code fuzzy (reverse) | RATIO | - | - | 5 | 4 |
| 35 | Pseudo-code fuzzy AST hash | RATIO_MAX | 0.35 | - | 4 | 3 |
| 36 | Partial pseudo-code fuzzy hash (normal) | RATIO_MAX | 0.5 | SLOW, UNRELIABLE | skipped | skipped |
| 37 | Partial pseudo-code fuzzy hash (reverse) | RATIO_MAX | 0.5 | SLOW, UNRELIABLE | skipped | skipped |
| 38 | Partial pseudo-code fuzzy hash (mixed) | RATIO_MAX | 0.5 | SLOW, UNRELIABLE | skipped | skipped |
| 39 | Same rare assembly instruction | RATIO_MAX | 0.5 | SAME_CPU | 3 | skipped |
| 40 | Same rare basic block mnemonics list | RATIO_MAX | 0.5 | - | 2 | 2 |
| 41 | Loop count | RATIO_MAX | 0.49 | SLOW | 1 | 1 |

**Unreliable: 8 defined (idx 42-49), 0 run by default.** `find_unreliable_matches` is gated off.

**Runs by default?** Mode N only.

### 5.11 Step 11b — `search_small_differences` (`diaphora.py:2085-2150`, gated at 2218)

`find_partial_matches` (2212-2221) runs `run_heuristics_for_category("Partial")` and then, **if
`slow_heuristics`** (default on), `search_small_differences("partial")`. It runs on the main
thread. The `cleanup_matches()` at the end of the Partial category (1551) runs **immediately
before** it, and it has **no cleanup of its own and none after it** until the top of the
convergence loop (3655). It has no `all_functions_matched()` early return, no row cap and no
timeout: it iterates with `result_iter` (139-146, `fetchmany(1000)`). Its description is `'Nodes, edges, complexity and mnemonics with small differences'`. For each
row with equal nodes, edges, mnemonics and cyclomatic_complexity and `f.names != '[]'`, it computes
ratio = |names1 ∩ names2| / max(|names1|, |names2|) over `set(json.loads(...))`. Then:
has_better_match → skip. If ratio ≥ 0.5: `check_match` → `ratio2`, and chooser `best` if
ratio2 == 1.0, otherwise `"partial"`. Full detail belongs in the heuristics spec. **Runs by
default?** Yes in mode N (slow is on).

### 5.12 Steps 12-13 — ML, unreliable and experimental

`apply_machine_learning` (3551-3555): `if ML_AVAILABLE and self.use_trained_model:` is false, so
`classifier` stays `None` and the ML branch in `deep_ratio` (2823) never runs. The unreliable block
(3638-3651) and brute force (2318-2321) are off. **Runs by default?** No.

---

## 6. Keys and types of a match item

| Index | Content | Type in Python | Source |
|---|---|---|---|
| 0 | ea1 | **str** (decimal text of the `functions.address` TEXT column; `str(row["ea"])` or the raw TEXT value) | `address text unique` (`db_support/schema.py`) |
| 1 | name1 | str, or `None` if the DB has NULL | `f.name`, **`mangled_function` for "100% equal"**, or the regex-extracted name in callee diffing |
| 2 | ea2 | str | as ea1 |
| 3 | name2 | str / `None` | |
| 4 | description | str | SQL literal, bound param, or Python f-string |
| 5 | ratio | float, or int `1` | |
| 6 | nodes1 | int | `int(row["nodes1"])`; NULL → `TypeError` |
| 7 | nodes2 | int | |

**Porting spec:** keep ea1/ea2 as the **exact TEXT** from the DB (the keys are string keys) and
parse them to integers only for output formatting and address sorting. Store the ratio as a
double. Names are `optional<string>`. Where Python builds a string key from a `None` name, it
becomes `"None"`, and that is what collides.

String keys used by the driver, all built by plain concatenation with `-` and therefore ambiguous
when names contain `-` (for example `operator-` / `operator->` in demangled C++ names):

| Key | Built at | Used for |
|---|---|---|
| `f"{name1}-{name2}"` | 1575 (cleanup), 3168, 3479 (`dones`), 3067 (callee pairs) | de-duplication |
| `f"{ea1}-{ea2}"` | 1653 (`ratios_cache`), 2741, 2852 | ratio cache, multimatch dedup |

The native port must build the **same concatenated string**, not a `std::pair`. Otherwise
`("a-b","c")` and `("a","b-c")` stop colliding, and they do collide in Diaphora.

---

## 7. The convergence loop (mode N only, `diaphora.py:3653-3675`)

```
iteration = 0
loop:
  cleanup_matches()
  old_total = len(all_matches.best) + len(all_matches.partial)        // get_total_matched_functions
  find_matches_diffing(iteration)
  if slow_heuristics: find_related_matches(iteration)                 // default: yes
  find_related_compilation_unit(iteration)                            // always
  find_locally_affine_functions(iteration)                            // always
  cleanup_matches()
  new_total = len(all_matches.best) + len(all_matches.partial)
  if new_total <= old_total: break
  iteration += 1
```

It always runs at least once and has no upper bound. It ends when an iteration does not grow
best+partial (the item count, not unique functions). `iteration` reaches only the
`on_special_heuristic` hooks. It **does not** appear in any description.

Each sub-pass has its own gates and internal `cleanup_matches` calls. Their matching semantics
belong in the heuristics spec. What follows is only what the driver must get right:

| Sub-pass | Lines | Internal cleanup | Gate / order facts |
|---|---|---|---|
| `find_matches_diffing` | 3211-3229 | at its start (3217) | assembly diffing **only if `is_same_processor`**, then pseudo-code diffing always |
| `find_matches_diffing_internal` | 3150-3193 | after each inner iteration (3185) | inner `iteration` = 1..3 (hard cap). Stops when `new_total == old_total` (**equality**: a drop in the total continues the loop). The description is `f"{heur} (iteration #{iteration})"` with the **inner** counter, for example `Callee found diffing matches pseudo-code (iteration #1)`. One `dones` set per call holds **both** match keys and callee-pair keys, in the same `"n1-n2"` format. It walks `best`, then `partial`, each as a fresh sorted snapshot taken when that category's loop starts, so partial items added during the best walk are included. |
| `find_related_matches` | 3462-3494 | at its start (3471) | only if `slow_heuristics`. `best` then `partial` sorted. `break` (per category) at the first `ratio < 0.8`. Rows are fetched **by name** (`get_function_row`: first row with that `name`). Calls `find_related_constants`, which iterates a Python **`set`** of constants (3373-3391). For string constants the iteration order depends on `PYTHONHASHSEED` (see Hard parts). Its SQL ends `and mc.constant = ? and abs(mc.constant) == 0` (3386-3387). `constants.constant` is `text` (`schema.py:170-173`), and SQLite's `abs()` of non-numeric text is `0.0` (V14), so **only non-numeric string constants (and zero)** can produce rows. Those are exactly the hash-seed-sensitive elements: on `userenv-9168-pdb`, 147 of 559 `constants` rows pass, all of them strings such as `ntdll.dll`. |
| `find_related_compilation_unit` | 3395-3460 | at its start (3413) | one list = sorted best + sorted partial. `break` (whole loop) at the first `ratio < 0.8`. CU lookup by `f.name = ?`, first row. Uses `add_matches_internal(cur, "best", "partial")`. |
| `find_locally_affine_functions` | 3315-3360 | at its start (3340) | best+partial sorted by `[int(ea1), int(ea2)]` ascending. For each consecutive pair it calls `find_functions_between`, whose SQL `address > ? and address < ?` binds the **TEXT** eas, so the comparison is **lexicographic** (`'4096' > '10000'`), not numeric. |

Any `SystemExit` raised from `add_matches_internal` inside these passes (the 300 s per-call timer
at 1894-1896) is **not caught** (for example `find_related_constants` 3391,
`find_related_compilation_unit` 3458). The interpreter exits with code 0 and **no new output
file**. A pre-existing file at the output path is left untouched. In mode S the stripped pass is
different: `add_matches_from_query_ratio` catches the `SystemExit` (1965).

---

## 8. The match store (shared state all passes write through)

### 8.1 `add_match` (`diaphora.py:1340-1374`)

```python
    with self.items_lock:
      # If the function names are the same, it's a best match, regardless of the
      # ratio we got for the match, so fake the ratio as if it was 1.0.
      if name1 == name2:
        ratio = 1.0

      if ratio != 1.0:
        if self.has_better_match(name1, name2, ratio):
          return
        ... (debug logging only)

      if chooser is not None:
        if item not in self.all_matches[chooser]:
          self.all_matches[chooser].append(item)

      self.matched_primary[name1] = {"name": name2, "ratio": ratio}
      self.matched_secondary[name2] = {"name": name1, "ratio": ratio}
```

**Porting spec:**

```
add_match(n1, n2, r, item, chooser):
  if n1 == n2: r = 1.0                                      // item[5] is NOT changed
  if r != 1.0 and has_better_match(n1, n2, r): return
  if chooser != null and item not in all_matches[chooser]: // full 8-field value equality, 1 == 1.0
      all_matches[chooser].append(item)
  matched_primary[n1]   = {n2, r}                           // unconditional overwrite, even with a worse r
  matched_secondary[n2] = {n1, r}
```

### 8.2 `has_best_match` / `has_better_match` (`diaphora.py:1376-1402`)

```python
  def has_best_match(self, name1, name2):
    if name1 in self.matched_primary and self.matched_primary[name1]["ratio"] == 1.0:
      return True
    if name2 in self.matched_secondary and self.matched_secondary[name2]["ratio"] == 1.0:
      return True
    return False

  def has_better_match(self, name1, name2, ratio):
    # If we have a match by name, that's the best match
    if not name1.startswith("sub_") and not name2.startswith("sub_"):
      if name1 in self.matched_primary:
        return self.matched_primary[name1]["name"] == name1

    ratio = float(ratio)
    if name1 in self.matched_primary and self.matched_primary[name1]["ratio"] > ratio:
      return True
    if name2 in self.matched_secondary and self.matched_secondary[name2]["ratio"] > ratio:
      return True
    return False
```

Porting notes. These are exact semantics, not "fixes":

- If **both** names are non-`sub_` and `name1` is already matched, the answer is decided by
  whether `name1` is currently matched **to a function of the same name**. The ratios are not
  compared at all. That means `False` (allow) even when the existing match is better, or when
  `name2` already has a 1.0 match.
- Otherwise it is the strict `>` ratio comparison on either side. Equal ratio is allowed, which is
  how multimatches form.
- `startswith("sub_")` on a `None` name raises `AttributeError`.

### 8.3 `check_match` — the gate every SQL row passes (`diaphora.py:1786-1872`)

This is always called with `ratio=None` (every call site: 1906, 2063, 2129, 2183).

```
check_match(row):
  if name1.startswith("nullsub_") or name2.startswith("nullsub_"): return (false, 0.0)
  if has_best_match(name1, name2):                                   return (false, 0.0)
  r = check_ratio(main_d, diff_d)          // cached by f"{ea1}-{ea2}" for the whole diff() (ratios_cache)
  if has_better_match(name1, name2, r):                              return (false, 0.0)
  return on_match hook -> default (true, r)
```

`main_d`/`diff_d` are built from the SQL row's aliased columns (1798-1842). `md1`/`md2` are
`cast(md_index as real)`, so a NULL `md_index` reaches `float(None)` → `TypeError`.

### 8.4 Category routing — `add_matches_internal` (`diaphora.py:1882-1948`)

```
add_matches_internal(cur, best, partial, val=None, unreliable=None):
  if val is None: val = 0.5
  i = 0; t0 = now
  while sql_max_processed_rows != 0 and i < sql_max_processed_rows:   // at most 1,000,000 fetched rows per call
      if now - t0 > timeout(300s) or thread.timeout: raise SystemExit
      i += 1
      row = fetchone(); if none: break
      (ok, r) = check_match(row); if !ok: continue
      item = [str(row.ea), row.name1, row.ea2, row.name2, row.description, r, int(row.nodes1), int(row.nodes2)]
      if r == 1.0:                      add_match(.., r, item, best)
      elif r >= val and partial != None: add_match(.., r, item, partial)
      elif r < 0.5 and r > val and unreliable != None: add_match(.., r, item, "unreliable")  // literal chooser;
                                        // unreachable when partial != None (it would need val < r < val)
      // else dropped
```

The row cap counts **every fetched row**, including rejected ones. Rows beyond 1,000,000 in one
query are silently ignored, so the SQLite row order decides which rows are seen.

`add_matches_from_query` (NO_FPS, 2039-2083) has **no** row cap. It loops `while not
cur_thread.timeout`. Every accepted row is added as `best` with item ratio `1` and
`add_match(..., 1.0, ...)`, even if `check_ratio` returned less. Any exception is **swallowed**
(`except: log(...)`), which ends that heuristic early.

`add_matches_from_query_ratio*` (1950-2026) catch `SystemExit` (timeout) silently and **re-raise**
any other exception (the thread dies; earlier adds are kept). Every `add_matches_from_*` returns
immediately if `all_functions_matched()`.

### 8.5 `cleanup_matches` (`diaphora.py:1554-1605`)

```python
    with self.items_lock:
      dones = {}
      d = {}
      ea_ratios = {}
      for key, items in self.all_matches.items():
        d[key] = []

        l_items = sorted(items, key=lambda x: float(x[5]), reverse=True)
        for item in l_items:
          ea = item[0]
          name1 = item[1]
          name2 = item[3]
          ratio = item[5]

          # Ignore duplicated matches (might happen due to parallelism)
          match = f"{name1}-{name2}"
          if match in dones:
            continue

          if name1 == name2:
            debug_refresh(f"Using a fake 1.0 ratio for match {name1} - {name2}")
            ratio = 1.0

          dones[match] = ratio

          # If the previous ratio for a match with function @ea is worst, ignore
          # this match
          if ea in ea_ratios and ea_ratios[ea] > ratio:
            continue
          else:
            ea_ratios[ea] = ratio

          d[key].append(item)

      # Update now the dict of matched functions for both databases
      self.matched_primary = {}
      self.matched_secondary = {}
      for key, l_items in d.items():
        for item in l_items:
          name1 = item[1]
          name2 = item[3]
          ratio = item[5]
          self.matched_primary[name1] = {"name": name2, "ratio": ratio}
          self.matched_secondary[name2] = {"name": name1, "ratio": ratio}

      self.all_matches = d
```

**Porting spec:**

```
cleanup():
  dones = set<string>; ea_ratios = map<string ea1, double>
  for cat in [best, partial, unreliable]:                    // fixed dict order
     L = stable_sort(all_matches[cat], by ratio DESC)       // Python sorted(reverse=True) is stable: ties keep insertion order
     keep = []
     for it in L:
        k = str(n1) + "-" + str(n2); if k in dones: continue
        eff = (n1 == n2) ? 1.0 : it.ratio                   // "fake 1.0" only for these two checks
        dones.add(k)
        if ea_ratios.contains(it.ea1) and ea_ratios[it.ea1] > eff: continue
        ea_ratios[it.ea1] = eff
        keep.push(it)
     all_matches[cat] = keep
  rebuild matched_primary / matched_secondary from the kept items, iterating best -> partial -> unreliable,
  in kept order. Last writer wins, and the stored ratio is it.ratio (NOT the fake 1.0).
```

Consequences to reproduce:

- De-duplication is by **name pair** across all categories (the first in best → partial →
  unreliable order wins). The ratio filter is per **ea1 only**, not per ea2.
- `ea_ratios` is **shared across categories**: a best item at 1.0 removes every partial item for
  the same ea1.
- After cleanup, a same-name item's `matched_primary` ratio is its real ratio (for example 0.90),
  not the 1.0 that `add_match` stored. From then on `has_best_match` is false for it.
- A name can drop out of `matched_*` if all of its items were filtered, and then later passes see
  it as unmatched again.
- **Cleanup call points** (these change state, so they must match exactly): the end of each
  `run_heuristics_for_category` (1551); the start of `find_matches_diffing` (3217); after each
  inner diffing iteration (3185); the start of `find_related_matches` (3471, only if enabled);
  the start of `find_related_compilation_unit` (3413); the start of `find_locally_affine_functions`
  (3340); the top and bottom of each convergence iteration (3655, 3671); and `final_pass` (2945).
  There is **no** cleanup after `find_equal_matches`, the dirty heuristics, `find_same_name`,
  `search_small_differences` or `find_remaining_functions`. In modes S and P, the first cleanup
  is the one in `final_pass`.

### 8.6 Counters

```python
  def all_functions_matched(self):
    return (
      len(self.matched_primary) == self.total_functions1
      or len(self.matched_secondary) == self.total_functions2
    )
```
(`diaphora.py:1777-1784`)

```python
  def get_total_matched_functions(self):
    return len(self.all_matches["best"]) + len(
        self.all_matches["partial"]
      )
```
(`diaphora.py:3142-3148`)

```python
  def get_sorted_results(self, category):
    l = sorted(
          self.all_matches[category], key=lambda x: float(x[5]), reverse=True
        )
    return l
```
(`diaphora.py:3133-3140`)

- `all_functions_matched` compares **the number of distinct name keys** with **row counts**, using
  `==`. Duplicate names in a DB lower the number of distinct real names that side can reach, so
  that side becomes true only if extra keys make up the gap. Extra keys (the mangled plus
  demangled names from sections 5.5 and 5.8) can make it true **while functions are still
  unmatched**. It can also overshoot: `len > total` is not `==`, so it stays false. E4 logged
  `All functions matched…` with 1 of 3 main functions unmatched, which skipped every Best and
  Partial heuristic. An empty db2 (`total_functions2 == 0`) makes it true from the start.
  Reproduce it literally.
- `get_total_matched_functions` counts **items** in best+partial, not unique eas, and excludes
  unreliable. It drives both loop terminations.
- `get_sorted_results` returns a stable sort by `float(ratio)` descending, as a new list.
- `show_summary` (1622-1635) and `get_total_matches_for` / `count_different_matches` (1607-1620)
  are **log only**: they count distinct `item[0]` per category, and the percent is over
  `total_functions1`. `show_summary` is called at 1552 (end of each category) and 3186 (each
  inner callee-diffing iteration). `total_functions1 == 0` → `ZeroDivisionError` at 1631. Under
  the default `experimental=True` that is unreachable, because step 7a divides by the same value
  first (2562). With `DIAPHORA_EXPERIMENTAL=""` it would be the first crash site.

---

## 9. `final_pass` (`diaphora.py:2937-2948`) → multimatches and the final choosers

```python
  def final_pass(self):
    self.cleanup_matches()

    max_main, max_diff, ignore_main, ignore_diff = self.find_multimatches()
    self.add_final_chooser_items(ignore_main, ignore_diff, max_main, max_diff)
```

### 9.1 `find_unresolved_multimatches` (`diaphora.py:2839-2885`)

```python
    dones = set()
    for key, items in self.all_matches.items():
      l = sorted(items, key=lambda x: float(x[5]), reverse=True)
      for match in l:
        ea1 = match[0]
        ea2 = match[2]
        ratio = match[5]

        key = f"{ea1}-{ea2}"
        if key in dones:
          continue
        dones.add(key)

        if ea1 not in max_main:
          max_main[ea1] = ratio

        # If the previous ratio we got is less than this one, ignore
        if max_main[ea1] > ratio:
          continue
        max_main[ea1] = ratio

        item = [ea2, ratio, match]
        try:
          multi_main[ea1].append(item)
        except KeyError:
          multi_main[ea1] = [item]

        if ea2 not in max_diff:
          max_diff[ea2] = ratio

        # If the previous ratio we got is less than this one, ignore
        if max_diff[ea2] > ratio:
          continue
        max_diff[ea2] = ratio

        item = [ea1, ratio, match]
        try:
          multi_diff[ea2].append(item)
        except KeyError:
          multi_diff[ea2] = [item]
```

`multi_main` and `multi_diff` are insertion-ordered dicts. The order of their keys and of their
lists is the traversal order above. An item skipped by the `max_main` test never updates
`max_diff`.

### 9.2 `add_multimatches_to_chooser` (`diaphora.py:2732-2747`), called for `multi_main` then `multi_diff` with one shared `dones`

```python
    for ea in multi:
      if len(multi[ea]) > 1:
        for multi_match in multi[ea]:
          item = self.itemize_for_chooser(multi_match[2])
          key = f"{item.ea}-{item.ea2}"
          if key not in dones:
            dones.add(key)
            self.multimatch_chooser.add_item(item)
            ignore_list.add(ea)

    return ignore_list, dones
```

`ignore_main` collects ea1 keys and `ignore_diff` collects ea2 keys. A key is added only when at
least one of its items was **newly** added. Items already emitted from the `multi_main` side are
not added again.

### 9.3 `itemize_for_chooser` (`diaphora.py:2718-2730`) — mislabelled but correct

```python
    ea1 = item[0]
    vfname1 = item[1]
    ea2 = item[2]
    vfname2 = item[3]
    ratio = item[4]
    nodes1 = item[5]
    nodes2 = item[6]
    desc = item[7]
    return CChooser.Item(ea1, vfname1, ea2, vfname2, ratio, nodes1, nodes2, desc)
```

The local names are shifted by one, and `CChooser.Item`'s positional order
`(ea, name, ea2, name2, desc, ratio, nodes1, nodes2)` shifts them back. The net result is
`Item.description = item[4]`, `Item.ratio = item[5]`, `Item.nodes1 = int(item[6])`,
`Item.nodes2 = int(item[7])`, which is **correct**. Confirmed by E2's output rows. Do not
"reproduce the bug": there is none in effect.

### 9.4 `add_final_chooser_items` (`diaphora.py:2916-2935`)

```python
    CHOOSERS = {
      "best": self.best_chooser,
      "partial": self.partial_chooser,
      "unreliable": self.unreliable_chooser,
    }
    for key, l in self.all_matches.items():
      l = sorted(l, key=lambda x: float(x[5]), reverse=True)
      for match in l:
        item = self.itemize_for_chooser(match)
        if item.ea in ignore_main or item.ea2 in ignore_diff:
          continue
        if item.ratio < max_main[item.ea]:
          continue
        if item.ratio < max_diff[item.ea2]:
          continue
        CHOOSERS[key].add_item(item)
```

**Porting spec**

```
final_pass():
  cleanup()
  max_main, max_diff = map<ea,double>; multi_main, multi_diff = ordered_map<ea, vector<(otherEa, ratio, item)>>
  seen = set<string>
  for cat in [best, partial, unreliable]:
     for m in stable_sort(all_matches[cat], ratio DESC):
        k = m.ea1 + "-" + m.ea2; if k in seen: continue; seen.add(k)
        if !max_main.has(m.ea1): max_main[m.ea1] = m.ratio
        if max_main[m.ea1] > m.ratio: continue
        max_main[m.ea1] = m.ratio; multi_main[m.ea1].push(m)
        if !max_diff.has(m.ea2): max_diff[m.ea2] = m.ratio
        if max_diff[m.ea2] > m.ratio: continue
        max_diff[m.ea2] = m.ratio; multi_diff[m.ea2].push(m)
  emitted = set<string>; ignore_main = set; ignore_diff = set
  for (ea, list) in multi_main (insertion order): if list.size > 1: for m in list: if emit_multi(m): ignore_main.add(ea)
  for (ea, list) in multi_diff (insertion order): if list.size > 1: for m in list: if emit_multi(m): ignore_diff.add(ea)
     // emit_multi: key m.ea1+"-"+m.ea2 not in emitted -> add to emitted, multimatch_chooser.add(m), return true
  for cat in [best, partial, unreliable]:
     for m in stable_sort(all_matches[cat], ratio DESC):
        if m.ea1 in ignore_main or m.ea2 in ignore_diff: continue
        if m.ratio < max_main[m.ea1]: continue
        if m.ratio < max_diff[m.ea2]: continue      // (KeyError is impossible under default config, see below)
        chooser[cat].add(m)
```

What this means (reproduce all of it):

1. Every item that survived cleanup but is **not** at the per-ea1 or per-ea2 maximum is silently
   **dropped from the output**. Its names stay in `matched_*`, so these functions are **also
   missing from `unmatched`**. In E2, a same-name pair at 0.9018889 disappeared because another
   pair for the same ea1 had 0.95.
2. Items tied at the maximum for the same ea1 (or ea2) go **only** to `multimatch`, and every item
   of that ea is excluded from best/partial/unreliable.
3. `KeyError` analysis, determined from source:
   - `max_main[item.ea]` (2931) can **never** miss. Every item's `f"{ea1}-{ea2}"` key is either
     seen first, in which case 2857-2858 set `max_main[ea1]` before any `continue`, or is a
     duplicate of an earlier item with the same ea1.
   - `max_main` values only increase, since 2863 assigns only when the new ratio is not smaller.
     So any item that reaches 2933 (ratio ≥ final `max_main[ea1]`) and was **processed** in
     `find_unresolved_multimatches` passed 2861 and set `max_diff[ea2]` (2871-2872).
   - A miss at 2933 therefore needs an item Y that was **`dones`-skipped** (2853-2854) behind an
     earlier twin X with the same `ea1-ea2` key, where X failed 2861 and
     Y.ratio ≥ final `max_main[ea1]` > X.ratio. Each category is sorted descending, so Y must be
     in a **later** category (dict order best → partial → unreliable) with a strictly higher
     ratio than X. X and Y must also carry **different name pairs**, because cleanup's name-pair
     dedup (1575-1577) would otherwise have removed Y.
   - Under the default config this is impossible. `unreliable` is always empty: its only writers
     are `add_matches_internal`'s third branch (1940-1946), which cannot be reached with
     `partial` non-None, and `find_brute_force` (2279, 2300), which is gated off. Every best item
     has ratio `1`/`1.0` and every partial item is < 1.0, so X can be neither.
   - With `unreliable` enabled, `find_brute_force` puts ratio-1.0 items into `"unreliable"`
     (`best="unreliable"`), so a `KeyError` is possible in principle when the same ea pair sits
     in `partial` under another name pair with a lower ratio. Whether real exports produce that:
     NOT DETERMINED. It is irrelevant by default.

**Runs by default?** Yes, in every mode.

---

## 10. Choosers

### 10.1 `create_choosers` (`diaphora.py:2358-2372`)

```python
    self.unreliable_chooser = self.chooser("Unreliable matches", self)
    self.partial_chooser = self.chooser("Partial matches", self)
    self.best_chooser = self.chooser("Best matches", self)
    self.multimatch_chooser = self.chooser("Problematic matches", self)

    self.ml_chooser = self.chooser("ML matches", self)

    self.unmatched_second = self.chooser("Unmatched in secondary", self, False)
    self.unmatched_primary = self.chooser("Unmatched in primary", self, False)

    self.interesting_matches = None
```

`ml_chooser` and `interesting_matches` are never saved. The two `unmatched_*` choosers created
here **do not survive `__init__`**: `create_choosers()` runs at 426, and lines 438-439 then set
both attributes to `None` (V1 confirmed `None` after construction). They are set again only by
`find_unmatched` (2341, 2354), and only when the corresponding `select` returned ≥1 row.

### 10.2 `CChooser` and `CChooser.Item` (`diaphora.py:227-296`)

```python
    def __init__(self, ea, name, ea2=None, name2=None, desc=None, ratio=0, nodes1=0, nodes2=0):
      self.ea = ea
      self.vfname = name
      self.ea2 = ea2
      self.vfname2 = name2
      self.description = desc
      self.ratio = ratio
      self.nodes1 = int(nodes1)
      self.nodes2 = int(nodes2)
  ...
  def add_item(self, item):
    """
    Add a single item
    """
    if self.title.startswith("Unmatched in"):
      self.items.append(["%05lu" % self.n, "%08x" % int(item.ea), item.vfname])
    else:
      dec_vals = "%." + config.DECIMAL_VALUES
      self.items.append(
        [
          "%05lu" % self.n,
          "%08x" % int(item.ea),
          item.vfname,
          "%08x" % int(item.ea2),
          item.vfname2,
          dec_vals % item.ratio,
          "%d" % item.nodes1,
          "%d" % item.nodes2,
          item.description,
        ]
      )
    self.n += 1
```

`CChooser.__init__` (250-273) sets `n = 0`, `items = []`, the `title`, and `primary = False` only
for the exact title `"Unmatched in secondary"` (unused by the writer), plus IDA command handles
that are unused standalone. `show(force)` (309-313) is an empty stub. `Item.__str__` (247-248)
is `"%08x" % int(ea)`, which the writer never uses. The short "unmatched" row format is chosen by
`title.startswith("Unmatched in")` (279). Every other title, including `"Problematic matches"`
(multimatch) and the never-saved `"Interesting matches"`, uses the 9-field format.

A chooser item is a **list of already-formatted strings**. Only the names and description stay
raw (`str` or `None`).

| Field | Format | Porting rule |
|---|---|---|
| line | `"%05lu" % n` | per-chooser counter from 0, zero-padded to ≥5 digits (`123456` → `"123456"`). Python ignores the `l`. |
| address / address2 | `"%08x" % int(ea)` | parse the decimal TEXT ea, then lowercase hex, zero-padded to ≥8 (`4294967296` → `"100000000"`, E2). A non-decimal ea → `ValueError`. Python's `int(str)` also accepts surrounding whitespace, a sign, and `_` digit separators (`int(' 4096 ')` and `int('4_096')` both give `00001000`, V10). A negative value formats with a leading `-` counted inside the 8-character minimum width (`-1` → `-0000001`). Real exports store plain decimal text (`typeof(address)='text'` for every row, V11), so these cases are only relevant for hand-made inputs. |
| ratio | `"%.7f" % ratio` | **correctly rounded, round-half-even on the exact double** (E6: `0.00390625` → `0.0039062`; `0.99999999` → `1.0000000`, so a partial row can print as `1.0000000`). Use `std::to_chars(first, last, v, std::chars_format::fixed, 7)`, not `printf`, and test the tie case. |
| nodes1 / nodes2 | `"%d"` | decimal integer |
| description | raw | — |

**Runs by default?** Yes.

### 10.3 `find_unmatched` (`diaphora.py:2323-2356`) — **labels swapped**

```python
      sql = "select name, address from functions"
      cur.execute(sql)
      rows = cur.fetchall()
      if len(rows) > 0:
        choose = self.chooser("Unmatched in primary", self, False)
        for row in rows:
          name = row["name"]

          if name not in self.matched_primary:
            ea = row[1]
            choose.add_item(CChooser.Item(ea, name))
        self.unmatched_second = choose

      sql = "select name, address from diff.functions"
      ...
        choose = self.chooser("Unmatched in secondary", self, False)
        for row in rows:
          name = row["name"]

          if name not in self.matched_secondary:
            ea = row["address"]
            choose.add_item(CChooser.Item(ea, name))
        self.unmatched_primary = choose
```

**Porting spec:**

```
UM_main = [f in main.functions in table scan (rowid) order if f.name not in matched_primary]
UM_diff = [f in diff.functions in scan order        if f.name not in matched_secondary]
chooser "secondary"  <- UM_main      // self.unmatched_second
chooser "primary"    <- UM_diff      // self.unmatched_primary
```

- Membership is by **`name`** against keys built from `item[1]`/`item[3]`. Functions whose names
  appear in a dropped or multimatched item count as matched. Two functions with the same name are
  both hidden if either one is matched. A main function whose only match was keyed by
  `mangled_function` ("100% equal") shows up as **unmatched** unless its `name` is also a key.
- E1 confirmed the swap: the db2-only function came out with `type='primary'`. The real
  userenv mode-P oracle output confirms it too (V12): every one of the 643 db1 functions was
  matched, and the file holds exactly 20 `unmatched` rows, all `type='primary'`. That equals the
  663 − 643 surplus functions of **db2**.
  `diaphora_ida.py:3519-3527` reads it back with the same swap, so Diaphora is internally
  consistent.
- Each chooser is built only `if len(rows) > 0` (2333, 2346). For an empty `functions` table the
  attribute stays `None` from `__init__`, which writes the same zero rows.
- `select name, address from functions` has no ORDER BY, so the source does not fix the order.
  **Observed** (V7) on the real `ls.sqlite` export with all 31 `functions` indices plus
  `sqlite_stat1`, on SQLite 3.51.1: `explain query plan` gives `SCAN functions` and
  `SCAN diff.functions`, because no index covers both `name` and `address`
  (`schema.py:23-55`). The rows came back exactly in `order by id` order (`id` is the
  `integer primary key`, which is the rowid). Only the `line` column depends on it.

**Runs by default?** Yes, in every mode.

---

## 11. `save_results` — output file (`diaphora.py:2374-2429`)

```python
    if os.path.exists(filename):
      os.remove(filename)
      log(f"Previous diff results '{filename}' removed.")

    results_db = sqlite3_connect(filename)

    cur = results_db.cursor()
    try:
      sql = "create table config (main_db text, diff_db text, version text, date text)"
      cur.execute(sql)

      sql = "insert into config values (?, ?, ?, ?)"
      cur.execute(
        sql, (self.db_name, self.last_diff_db, VERSION_VALUE, time.asctime())
      )

      sql = """create table results (type, line, address, name, address2, name2,
                   ratio, nodes1, nodes2, description)"""
      cur.execute(sql)

      sql = "create unique index uq_results on results(address, address2)"
      cur.execute(sql)

      sql = "create table unmatched (type, line, address, name)"
      cur.execute(sql)

      with results_db:
        results_sql = "insert or ignore into results values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        unmatched_sql = "insert into unmatched values (?, ?, ?, ?)"

        d = {
          "best": [self.best_chooser, results_sql],
          "partial": [self.partial_chooser, results_sql],
          "unreliable": [self.unreliable_chooser, results_sql],
          "multimatch": [self.multimatch_chooser, results_sql],
          "primary": [self.unmatched_primary, unmatched_sql],
          "secondary": [self.unmatched_second, unmatched_sql],
        }

        for category, fields in d.items():
          chooser, sql_cmd = fields
          if chooser is not None:
            for item in chooser.items:
              item_list = list(item)
              item_list.insert(0, category)
              cur.execute(sql_cmd, item_list)
```

### 11.1 Exact output schema (dumped from E1)

```sql
CREATE TABLE config (main_db text, diff_db text, version text, date text)
CREATE TABLE results (type, line, address, name, address2, name2,
                   ratio, nodes1, nodes2, description)
CREATE UNIQUE INDEX uq_results on results(address, address2)
CREATE TABLE unmatched (type, line, address, name)
```

The `results` and `unmatched` columns have **no declared type** (no affinity), so every value is
stored exactly as bound. E1 checked `typeof()` on every column of every row: all **`text`**.
Names can be NULL.

### 11.2 Rows

| Table | Row | Value per column |
|---|---|---|
| `config` | exactly 1 | `main_db` = db1 string **exactly as passed** (relative paths stay relative); `diff_db` = db2 as passed; `version` = `'3.4'`; `date` = `time.asctime()` in local time, format `'%a %b %d %H:%M:%S %Y'` with a **space-padded** day (`'Wed Sep  3 …'`) |
| `results` | the best chooser, then partial, unreliable, multimatch | `type` ∈ {`'best'`,`'partial'`,`'unreliable'`,`'multimatch'`}, then the 9 formatted chooser fields (`line, address, name, address2, name2, ratio, nodes1, nodes2, description`) |
| `unmatched` | `'primary'` rows (**db2 functions**), then `'secondary'` rows (**db1 functions**) | `type, line, address, name` |

- **`insert or ignore`** plus the unique `(address, address2)` index means that when the same
  formatted address pair appears twice, only the first **in write order** (best → partial →
  unreliable → multimatch, each in chooser order) is stored. The ignored row's `line` number is
  **consumed**, which leaves a gap. E4: the chooser had 3 best items, the file had 2, and line
  `00002` was missing. The log line `Final results: Best N …` counts chooser items, not rows.
- `unmatched` uses a plain `insert` with no uniqueness.
- The Python connection runs in `sqlite3`'s legacy transaction mode. `create table config` runs
  in autocommit. The `insert into config` (2390-2393) implicitly opens a transaction, and the
  later `create table results`, the index and `create table unmatched` run **inside it**
  (Python ≥3.6 no longer commits before DDL). Everything is committed at the end of the
  `with results_db:` block. If a row insert inside the block raises, the context manager rolls
  back the config row **and** the three later DDL statements, leaving a file with only an empty
  `config` table (V8 reproduced this). Journal mode stays the default `delete` (V8:
  `pragma journal_mode` = `delete`).
- If the output path exists, `save_results` deletes it **before** anything else (2379-2381). A
  crash **inside `save_results`** after that point leaves no file or a partial one. A crash
  anywhere in `diff()` happens **before** `save_results`, so a pre-existing file is left
  untouched and stale (V9).

### 11.3 Example (E1, verbatim row dump)

```
('best', '00000', '00001000', 'equal_fn', '00001000', 'equal_fn', '1.0000000', '4', '4', '100% equal')
('best', '00001', '00003000', 'sub_3000', '00003400', 'sub_3400', '1.0000000', '4', '4', 'Equal assembly')
('partial', '00000', '00002000', 'named_fn', '00002100', 'named_fn', '0.9018889', '4', '4', 'Perfect match, same name')
unmatched: ('primary', '00000', '00004800', 'only_in_diff')  ('secondary', '00000', '00004000', 'only_in_main')
```

**Porting spec for the writer**

```
write_results(out):
  delete out if it exists
  exec "create table config (main_db text, diff_db text, version text, date text)"
  BEGIN                                             // Python opens it implicitly at the next INSERT
  insert config(db1_arg, db2_arg, "3.4", asctime_local())
  exec the other 3 DDL statements above verbatim (untyped columns, same index name)
  for (tag, chooser) in [("best",B),("partial",P),("unreliable",U),("multimatch",M)]:
     for row in chooser.rows: INSERT OR IGNORE INTO results VALUES (tag, row...)   // bind everything as TEXT
  for (tag, chooser) in [("primary", UM_diff), ("secondary", UM_main)]:            // skip a None chooser
     for row in chooser.rows: INSERT INTO unmatched VALUES (tag, row...)
  COMMIT
```

The transaction boundary matters only for crash behaviour, and a native writer need not
reproduce it.

**Parity comparison contract** (recommended for the harness): compare `results` as a **multiset of
`(type, address, address2, name, name2, ratio, description)`**, and `unmatched` as a multiset of
`(type, address, name)`. Compare `line` only once row order is proven to match (see Hard parts).
Ignore `config.date`, and ignore `config.main_db`/`diff_db` unless the same argument strings are
passed.

**Runs by default?** Yes, always, including after `diff()` returned `False` (empty tables).

---

## 12. Final log lines (optional, for operator parity)

`diaphora.py:3684-3698` logs `Final results: Best {b}, Partial {p}, Unreliable {u}, Multimatches
{m}` (chooser item counts, which include rows later ignored by the writer), then `"Matched %1.2f%%
of main binary functions (%d out of %d)"` with `(b+p+u)*100/total_functions1` (this can exceed
100%). These have no effect on results.

---

## 13. Abort and degenerate-input behaviour (what the oracle file looks like)

"**no file**" below means that **no new file is written**. A file already at the output path is
left untouched (V9), so the harness must delete it before running.

| Condition | Where | Oracle output |
|---|---|---|
| db2 has no `version` table / no row, or the attach failed | 3577-3588 | empty `results`/`unmatched`, config row present |
| `DIAPHORA_PROJECT_SCRIPT` set and it fails to load | 3607-3610 | empty tables |
| `equal_db` SQL fails (for example a missing `program`/`functions` table or column in either DB) | 661-687 | **no file** (exception) |
| the `program` `union all` does not return exactly 2 rows, or a NULL/non-numeric `callgraph_primes`, or bad JSON | 1294-1322 | **no file** (exception) |
| `total_functions1 == 0` (including a db1 path that did not exist) | 2562 (`ZeroDivisionError`) | **no file**, exit code 1 (V9) |
| NULL `mangled_function` on a same-name candidate row | 2179 | **no file** |
| NULL `name`, `nodes` or `md_index` reaching `check_match` / `int()` / `float()` | 1846, 1672, 1915 | NO_FPS heuristics swallow it (2080-2081) and stop early. RATIO* heuristic threads die (re-raise). Either way the partial results are kept. Main-thread passes: **no file** |
| Main-thread **direct** `add_matches_internal` call > 300 s: `search_remaining_functions` (2696), `find_related_constants` (3391), `find_related_compilation_unit` (3458) | 1894-1896 → `SystemExit` | **no file**, exit code 0, log `Timeout with heuristic 'MainThread'` |
| Stripped-mode pass > 300 s | 1894 → caught at 1965 | the pass is truncated silently after the same log line, and the run continues |
| RATIO* heuristic thread > 300 s | `jkutils/threads.py:62-63` + 1894 | that heuristic stops early after logging `Timeout with heuristic '<name>'`, and the rows added so far are kept (timing-dependent) |
| NO_FPS heuristic thread > 300 s | `jkutils/threads.py:62-63` + 2054 | the `while not cur_thread.timeout` loop just ends, **with no log line**, and the rows so far are kept |
| Patch-diff hook `IndexError` | `patch_diff_vulns.py:162` | **no file** |
| Invalid UTF-8 in a TEXT column | `db.text_factory = str` (346) | `sqlite3.OperationalError: Could not decode to UTF-8 column '<col>' with text '…'`, raised when the **row is fetched** (`fetchone`/`fetchall`), not at `execute` (V6). SQL that only filters or counts on the column does not raise. The first failing pass is therefore the first one that fetches such a row: a heuristic thread (that heuristic dies) or a main-thread pass (**no file**). Which one that is depends on the data. |

---

## 14. Gap versus the current native code (for orientation)

`src/main.cpp:174-250` (`WriteDiffResults`) writes `matches(ea1, name1, ea2, name2, description,
ratio real, category)` and `symbols_to_port(...)` into the `-o` file. It has no `config`,
`results`, `unmatched` or multimatch tables, uses a `best#<id>` description and a REAL ratio.
Parity needs a separate Diaphora-compatible writer (section 11) fed by a match store that
implements sections 8-10 **exactly**. That includes the name-keyed bookkeeping, the per-category
stable sorting and the final max/multimatch filter. The current `MatchStore` "greedy 1:1 resolve"
(`HANDOFF.md`) is a different algorithm.

---

## Hard parts

1. **First-come-wins on 1.0 ties depends on execution order and SQLite row order.**
   `has_best_match` blocks every later candidate once a name has a 1.0 match. The winner of a tie
   is therefore decided by (a) the reversed heuristic order in section 5.10, and (b) the order in
   which SQLite returns rows for each query, which has no ORDER BY and depends on the query plan,
   the indices (`schema.INDICES`) and the SQLite version. A native hash-join engine will not
   reproduce (b) by accident. You must either emulate SQLite's plan order per query, or accept
   and flag tie-dependent differences. The harness should classify a mismatch as "tie-order
   only" when both candidates scored 1.0.
2. **Name-keyed state versus address-keyed output.** `matched_primary`/`matched_secondary`, the
   cleanup de-duplication and `find_unmatched` use names, while cleanup's ratio filter, the
   multimatch pass and the writer use address text. Mixing `mangled_function` ("100% equal") with
   `name` (everything else) produces duplicates, early "all functions matched" exits (E4),
   functions reported both matched and unmatched, and rows silently dropped by `insert or ignore`.
   All of this has to be reproduced literally, including the `"n1-n2"` string-key collisions.
3. **The mode switch.** Stripped (≥99% same-address pairs) and patch-diff (>90% same-mangled
   pairs, strict) replace the entire heuristic engine. Symbolised version-to-version corpora will
   almost always be in patch-diff mode. That makes the whole heuristic tier irrelevant for them,
   and makes `find_same_name` + `check_ratio` + the renamed-`sub_` brute force the only things
   that matter.
4. **Final-pass filtering drops matches silently.** Anything below the per-ea1 or per-ea2 maximum
   vanishes from both `results` and `unmatched`, and ties become multimatches. A native resolver
   that "does the sensible thing" (Hungarian, greedy 1:1) will not match.
5. **Cleanup placement and in-place mutation.** `cleanup_matches` rewrites `matched_*` with item
   ratios, which turns same-name 1.0 into the real ratio. Its call points (section 8.5) change
   which later candidates pass `has_best_match`/`has_better_match`. There is none between
   heuristics inside a category.
6. **`has_better_match`'s asymmetric shortcut** for non-`sub_` names ignores ratios entirely
   (section 8.2).
7. **Non-determinism in the oracle itself.** (a) Wall-clock timeouts (300 s per heuristic thread
   and per `add_matches_internal` call) make large-DB results timing-dependent. NO_FPS
   heuristics time out **silently** (2054), so counting `Timeout with heuristic` log lines does
   not detect every timeout. (b) `find_related_constants` iterates a Python `set` of constants.
   For `str` elements the iteration order changes with `PYTHONHASHSEED`, which changes run order
   within that pass. Because of `abs(mc.constant) == 0` (3387), **only** the string constants
   (and zero) can produce rows (section 7), so the seed-sensitive elements are exactly the ones
   that matter. Run the oracle with a fixed `PYTHONHASHSEED` and small enough inputs, and still
   expect ties there to be unreproducible natively. (c) The 1,000,000-row cap per query depends
   on row order.
8. **Lexicographic TEXT comparisons** where the code "means" numbers:
   `find_functions_between` (`address > ? and address < ?` on TEXT). The parse-to-int must happen
   only where Python does it (`"%08x" % int(ea)`, the local-affinity sort key, `deep_ratio`).
9. **Ratio formatting.** `%.7f` must be correctly rounded, half-even on the exact binary value. A
   0.99999996+ partial prints as `1.0000000`.
10. **Loop termination uses item counts.** `new_total <= old_total` in the outer loop,
    `new_total == old_total` in the inner loop, with no outer iteration cap. An off-by-one here
    changes how many rounds of callee diffing run and which `(iteration #k)` descriptions appear.

## Open questions

1. **Which mode will the oracle corpus take?** **RESOLVED (observed, V12).** The exports and
   diffs now exist in `<corpus>/oracle`. `userenv-9168-pdb_vs_9278-pdb` → mode
   **P** (643/643 = 100.0% same `mangled_function`). `ls_vs_ls-old`, `ls-old_vs_ls`,
   `sechost-9168-pdb_vs_9444-nopdb` and `userenv-9168-pdb_vs_9278-nopdb` → mode **N**. No pair
   takes mode S. A PDB-vs-PDB `sechost` pair has not been built yet. Keep recording the detection
   log line for each run.
2. **SQLite row order**: will the parity target be "same set modulo 1.0-tie order", or must the
   native engine emulate per-query SQLite plan order? **Still needs a user decision.** Exact
   `line` parity requires the latter. New fact: the three finished oracle pairs gave
   byte-identical `results` and `unmatched` row order across two runs each
   (`oracle/diffs/*/determinism.json`: `results_identical_in_order: true`), so exact order is at
   least a stable target on this machine.
3. **`PYTHONHASHSEED`**: **RESOLVED from source: yes, pin it** (for example `PYTHONHASHSEED=0`).
   The only order-sensitive `set` iteration on the diff path is `for constant in inter_consts`
   (3389). The other sets are used only for membership, `len`, intersection size, or a max
   (`values_set` at 1755-1764 is order-independent). `abs(mc.constant) == 0` (3387) restricts
   that loop's effective rows to string constants, whose hash order depends on the seed. The
   current `tools/oracle/build_oracle.py` `CleanEnv()` does **not** set it. Its 2-run
   determinism check passing does not prove seed independence. Emulating CPython's set order
   natively is out of scope.
4. **Timeouts**: should the native port implement the 300 s per-heuristic and per-call aborts?
   **Still a design decision.** Source facts: RATIO* heuristics and main-thread calls log
   `Timeout with heuristic '<name>'` (1895), but NO_FPS heuristics stop **silently** (2054), so
   log-grepping (what `build_oracle.py` `timeouts_logged` does) under-counts. A robust detector
   compares the log timestamps of `[Single thread] Finding with heuristic` / `Heuristic '…' done`
   with 300 s. A main-thread per-call timeout exits with code 0 and **no new file**. Observed:
   finished oracle runs took 1.8-13.4 s wall-clock, far below 300 s. The two PDB-vs-no-PDB mode-N
   runs were still inside `find_related_compilation_unit` at 00:36 (started 00:27). That is a
   main-thread direct call, so the process exits if one call exceeds 300 s. The logs show many
   successive `add_matches_internal` calls: `sechost` calls reached about 700,000 rows each in
   about 50 s, and `userenv` calls about 300,000 rows each. Both are under the 300 s timer and
   the 1,000,000-row cap per call, but the total runtime is long. Check their `run.json`
   (`exit_code`, output present) before trusting them.
5. **Invalid UTF-8 names** in exports: **RESOLVED (V6).** With `text_factory = str`, Python's
   `sqlite3` raises `OperationalError: Could not decode to UTF-8 column …` when a row holding
   such a value is **fetched**. `execute`, and SQL that only filters or counts on the column, do
   not raise. Which Diaphora pass fetches it first depends on the data (see section 13). A native
   engine reading exports should flag such rows as unsupported input.
6. `select name, address from functions` (`find_unmatched`) and the SQL heuristics' result order
   are **observed** plan behaviour, not guaranteed by source. **Partly re-verified (V7)** on the
   real `ls.sqlite` export (31 indices, `sqlite_stat1` present, SQLite 3.51.1): `SCAN functions`
   (row order = `id` order), `INTERSECT USING TEMP B-TREE`, `UNION USING TEMP B-TREE`. The
   per-heuristic plans belong to the heuristics spec. Re-verify with `explain query plan` if the
   oracle's SQLite version changes.
7. **`KeyError` in `add_final_chooser_items` with unreliable enabled**: **RESOLVED from source**
   (section 9.4 item 3). It cannot happen under the default config. With `unreliable` on, it
   needs one ea pair carried under two name pairs across categories, with the later category's
   ratio higher. Whether real data does that: NOT DETERMINED, and irrelevant by default.

---

## Verification log

An adversarial pass on 2026-09-23 checked every behavioural claim, quoted excerpt and line number
against `<diaphora-ref>` at `621ec26`. `diaphora.py`, `diaphora_config.py`,
`diaphora_heuristics.py`, `jkutils/` and `scripts/` are identical to tag 3.4.2, so the line numbers
hold for both. Experiments ran on a `git archive HEAD` copy and on copies of the oracle exports in
the session scratchpad (`.../scratchpad/v01`). The reference checkout, the oracle exports and the
running oracle diffs were only read.

### Experiments run in this pass

| # | Experiment | Result |
|---|---|---|
| V1 | Construct `CBinDiff` on a scratch DB, no env | `unmatched_primary` and `unmatched_second` are **`None`**. `cpu_count=1`, `slow_heuristics=True`, `experimental=True`, `unreliable=False`, `timeout=300`, `sql_max_processed_rows=1000000`, `ignore_all_names=False`, `project_script=None`. |
| V2 | Regenerated the section 5.10 heuristic table from `HEURISTICS` | Identical to the doc: Best 12 / Partial 30 / Unreliable 8. Every run position and skip matched. Only idx 10 has descriptions that differ from its name (`Equal pseudo-code` / `Equal assembly`, `diaphora_heuristics.py:277/287`). |
| V3 | Every `diaphora_config.py` line/value and `diaphora.py` "used at" line in section 2.2 | All correct. `MIN_FUNCTIONS_TO_DISABLE_SLOW` is referenced only at `diaphora_ida.py:3799` in the whole repo. `self.experimental` is read only at 3618. |
| V4 | Oracle Python environment | Python 3.13.12, SQLite 3.51.1, no `cdifflib`, `ML_AVAILABLE=True`, no `DIAPHORA_*`/`PYTHONHASHSEED` in the process, user or machine environment. |
| V5 | Call-site greps | `check_match` is called only at 1906/2063/2129/2183, always with `ratio=None`. `cleanup_matches()` is called only at 1551/2945/3185/3217/3340/3413/3471/3655/3671, the list in section 8.5. |
| V6 | Invalid UTF-8 TEXT (`cast(x'66ff6f' as text)`) with `text_factory=str` | `execute` succeeds. `fetchone`/`fetchall` of that row raises `sqlite3.OperationalError: Could not decode to UTF-8 column 'name' ...`. `count(*)`/`like`/`length()` over the column do not raise. |
| V7 | `explain query plan` on a copy of the real `ls.sqlite` + `ls-old.sqlite` (31 `functions` indices, `sqlite_stat1`) | `find_unmatched`: `SCAN functions` / `SCAN diff.functions`, and the rows equal `order by id`. `find_equal_matches`: `INTERSECT USING TEMP B-TREE`. `get_unmatched_functions`: `UNION USING TEMP B-TREE`. The stripped/patch-diff counts use covering indices `idx_28` (address) and `idx_3` (mangled_function). |
| V8 | `save_results` on scratch data, then a forced bad row | Normal case: tables `config`, `results`, `uq_results`, `unmatched`; the `config` columns have `typeof`=text; `journal_mode=delete`. A binding error inside the `with` block rolled back the config row and the later DDL, leaving only an empty `config` table. |
| V9 | Pre-created a sentinel output file, then ran `python -B diaphora.py` with a 0-function db1 | Exit code 1, `ZeroDivisionError` at 2562, and the **sentinel file was left unchanged**. |
| V10 | `attach "missing.sqlite" as diff`, plus format checks | The attach creates a 0-byte file, and the next query fails with `no such table: diff.version`. `'%.7f'`: `0.00390625`→`0.0039062`, `0.99999999`→`1.0000000`, `1`→`1.0000000`. `'%08x' % int('4294967296')`→`100000000`, `'%05lu' % 123456`→`123456`. `int(' 4096 ')` and `int('4_096')` are accepted. |
| V11 | Real exports (copies) | `userenv-9168-pdb`: 643 functions, 393 with `name != mangled_function`. `userenv-9278-pdb`: 663 functions, 411 differ. `ls`: 318 functions, 0 differ. No NULL `name`/`mangled_function`, no duplicate names, `typeof(address)='text'` for every row, one `program` row each (`pc64`), `version`=`3.4`. |
| V12 | Oracle logs and `run.json` in `<corpus>/oracle/diffs` | userenv pdb-vs-pdb: `Patch diffing detected ... 643 out of 643, 100.0%` (mode P), the `cdifflib` warning printed twice (the script re-import), results 643 rows (best 635 / partial 8), `unmatched` 20 rows all `primary`, exit 0. `ls_vs_ls-old`: mode N, and the Best and Partial heuristics are logged as queued in list order and then finish (`[Parallel] Heuristic '…' done`) in exact reverse order. `ls-old_vs_ls`: mode N. Both pdb-vs-nopdb pairs: mode N, still running at 00:36. The three finished pairs are deterministic in row order across 2 runs. |
| V13 | Empty or space-led lines in `functions.assembly` | 0 of 19,530 (`ls`), 0 of 29,757 (`userenv-9168-pdb`), 0 of 30,923 (`userenv-9278-pdb`). |
| V14 | SQLite `abs()` on text, and the `constants` table | `abs('hello')=0.0`, `abs('123')=123.0`, `abs('0x10')=0.0`. `constants.constant` is `text`. In `userenv-9168-pdb`, 147 of 559 rows satisfy `abs(constant)==0`, all of them non-numeric strings. The JSON `functions.constants` holds both `str` and `int` elements. |

### Corrections made

1. **Section 3 attribute table, `unmatched_primary`/`unmatched_second`**: the doc said "`None`,
   then overwritten by `create_choosers`". The order is the reverse. `create_choosers()` runs at
   426 and lines 438-439 then set both to `None` (V1). `find_unmatched` reassigns each only when
   its `select` returns at least 1 row (2333/2346), and `save_results` skips `None` (2420).
2. **Section 10.1**: same error ("`unmatched_*` are replaced by `find_unmatched`"). Rewritten.
3. **Section 2.1**: the doc said the `TypeError` from a string `DIAPHORA_SQL_TIMEOUT_LIMIT` fires
   "inside the heuristic threads" and the one from `DIAPHORA_SQL_MAX_PROCESSED_ROWS` "on the main
   thread". Both comparisons are in `add_matches_internal` (1878/1894). The row-cap one is
   evaluated first, and both fire on heuristic threads **and** the main thread. Also added: the
   env timeout never reaches `threads_apply` (1548 passes the config value).
4. **Section 2.2**: the doc said the remaining config values are "never read". Several are read
   into unused attributes (392, 415-420, 462, 465, 479-481). Added `ML_TRAINED_MODEL` (3554,
   gated), `ML_DEBUG_SHOW_MATCHES`, and the `is_auto_generated` user of `CLEANING_CMP_REPS`.
5. **Section 4**: the cross-reference "timeouts (section 11.3)" pointed at the output example. It
   now points at section 13. Added the non-swallowed `attach_database` in threads, thread-ident
   reuse, and the double-quoted attach path.
6. **Section 5.3**: "each `program` table must hold exactly one row (total == 2)" was wrong: 1299
   checks the **combined** `union all` row count, so a (2, 0) or (0, 2) split also passes. Added
   the exact exception types (`TypeError` for NULL, `decimal.InvalidOperation` for non-numeric)
   and the JSON preconditions.
7. **Section 5.0 step 2**: `equal_db` was listed as log only with no failure mode. It can throw,
   which aborts with no new file. Also added to section 13.
8. **Section 5.11**: "no cleanup before or after" was wrong: the cleanup at the end of the
   Partial category (1551) runs immediately before `search_small_differences`. Added that the
   pass has no `all_functions_matched` return, no row cap and no timeout (`result_iter`).
9. **Section 8.6**: "Duplicate names mean it can never become true" was too strong: extra keys
   can still close the gap. "Already unreachable because step 7a divides first" holds only
   because `experimental=True` by default. Added the `show_summary` call sites (1552, 3186).
10. **Section 9.4 item 3**: the `KeyError` question was marked NOT DETERMINED. The `max_main`
    lookup can never miss. The exact precondition for a `max_diff` miss is now derived from
    source, and it is impossible under the default config.
11. **"No output file" throughout (Summary, sections 1, 5.4, 5.7a, 7, 11.2, 13)**: the old file at
    the output path is **not** deleted when `diff()` raises, because the delete is inside
    `save_results` (2379-2381). A crash leaves any previous file stale (V9). The harness must
    delete the output path first. `build_oracle.py` already removes the run directory (276-279).
12. **Section 13 timeout rows**: the doc said any main-thread `add_matches_internal` call over
    300 s exits. That is true only for the **direct** callers (2696, 3391, 3458). The stripped
    pass catches `SystemExit` (1965) and just truncates. Also added that NO_FPS heuristics time
    out **silently** (2054, no log line), and split the NULL-field row by NO_FPS (swallowed,
    2080-2081) versus RATIO* (thread dies).
13. **Section 13 invalid UTF-8**: was NOT DETERMINED. It is now determined by experiment (V6):
    the error is raised on **fetch** of the row.
14. **Section 5.4 item 3 (patch-diff crash)**: the doc said "an added or removed line that is
    empty or starts with a space raises". A removed line raises only when `mnem1` starts with `b`
    (short-circuit at 162). The `---`/`+++` headers pre-seed `added`/`removed`. Also added V13:
    the current corpus has no such lines.
15. **Section 5.5**: "`name` is the demangled short name" was wrong for the real corpus: it is
    `demangle_name(true_name, INF_SHORT_DN) or true_name`, which on the userenv PDB exports is
    the full demangled signature (V11). Added the export column mapping
    (`diaphora_ida.py:3141-3156`, `diaphora.py:943-946`), and that the INTERSECT order reduces to
    ascending `id`.
16. **Section 5.10**: the `jkutils/threads.py:36-53` citation actually quoted lines 36-40. Fixed,
    and the join/timeout loop is cited as 55-64.
17. **Section 10.3 row order**: was "NOT DETERMINED FROM SOURCE if an index is chosen". It is now
    observed on a real export (V7): `SCAN functions`, in rowid (= `id`) order.
18. **Section 11.2 transaction scope**: the doc said "committed at the end of the `with` block".
    The implicit transaction actually starts at the `insert into config` and includes the later
    DDL. A failure inside the block rolls back the config row too (V8). The writer pseudo-code
    was updated to match.
19. **Section 5.7 corpus note**: the doc predicted the modes and said the exports were empty. It
    now records the observed modes (V12) and adds the `add_matches_from_query_ratio` early
    return and `SystemExit` handling in mode S.

### Omissions added

- `CChooser.__init__` (250-273), the `show()` stub (309-313), `Item.__str__`, and which titles
  get the short "unmatched" row format (section 10.2).
- `int()` parsing quirks in the `%08x` address formatting (section 10.2).
- A nonexistent db1 path is created and schema-initialised, then dies at 2562 (section 3.1).
- `call_on_match_hook` passes `main_row["name"]` as `name2` (3013). Hook-only, never reached in
  mode P (section 5.4 table).
- The re-imported `diaphora` module's side effects are provably harmless (fresh `_DATABASES`,
  unchanged reloads) (section 5.4).
- `find_related_constants`' `abs(mc.constant) == 0` limits effective rows to string constants,
  exactly the `PYTHONHASHSEED`-sensitive ones (section 7, Hard parts 7, V14).
- The per-call row counts and durations observed in the long-running mode-N oracle runs (Open
  question 4).

### Checked and found correct (no change)

The section 1 `__main__` excerpt and porting spec. The `get_value_for` excerpt and its bool
semantics. Every section 2.2 line number and value. The section 3 attribute lines. The
`create_schema` excerpt. The `diff()` excerpt and the step order. The section 5.0 gates. The
section 5.10 dispatch and routing (including the unreachable third branch). The section 5.10
heuristic table (regenerated, V2). The section 6 key formats and line numbers. The section 7 loop
semantics and sub-pass lines. The section 8.1-8.5 excerpts, porting specs and cleanup call points
(V5). The section 9.1-9.4 excerpts and the `itemize_for_chooser` analysis. The section 10.2
formats (V10). The section 10.3 label swap (confirmed on real oracle output, V12). The section 11
schema and write order. The section 12 log lines. The `diaphora_ida.py` citations (2451-2453,
3519-3527, 3727, 3797-3800). The section 14 `src/main.cpp:174-250` description.

### Still open

- Parity target (set modulo 1.0 ties, or exact row order): a user decision. The oracle is at
  least order-deterministic across repeated runs (V12).
- Timeouts in the native port: a design decision. The detection must not rely only on
  `Timeout with heuristic` log lines, because NO_FPS timeouts are silent.
- Whether real data can trigger the unreliable-mode `KeyError` precondition in section 9.4: NOT
  DETERMINED, and irrelevant by default.
- Per-heuristic SQL row order is plan-dependent. That belongs to the heuristics spec, not this
  one.
- The PDB-vs-no-PDB oracle runs had not finished when this pass was done. Check their `run.json`.
