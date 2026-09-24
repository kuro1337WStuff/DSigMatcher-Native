# 05: Non-heuristic matching passes (Diaphora 3.4.2)

> **Historical spec.** Written on 2026-09-23 against an earlier revision (`34ed418`), before the port existed; its status remarks ("not implemented", test counts, runs "still running", open questions) are historical. See [README.md](README.md) in this directory for how to read it; quoted Diaphora code is (c) Joxean Koret, AGPL-3.0-or-later, and quoted CPython `difflib` code is under the PSF License Version 2.

**Summary.** These are the passes in `CBinDiff.diff()` that are *not* entries in `diaphora_heuristics.HEURISTICS`. Under the default standalone configuration (`python diaphora.py db1 db2 -o out`, no `DIAPHORA_*` env vars) the following run:
0. `equal_db()` (diaphora.py:3600), which is log-only (§1.2).
1. `check_callgraph`, which is log-only.
2. `find_equal_matches` (always, into **best**).
3. `apply_dirty_heuristics`, because `experimental=True`. It either detects "same binary, symbols stripped" (matched-address count ≥ 99% of the main function count), which matches pairs by address, or detects "patch diff" (mangled-name *pair* count > 90% of the main function count), which loads a pass-through hook script. Either way the Best/Partial/Unreliable heuristics, `search_small_differences`, ML and the whole iterative loop are skipped. `find_same_name`, `find_remaining_functions` and `final_pass` still run (§6).
4. `find_same_name` (always).
5. On the normal path only: the Best/Partial SQL heuristics (covered by the heuristics spec), then `search_small_differences` (`slow_heuristics=True` **regardless of function count** in standalone mode), and then `apply_machine_learning`, which is a no-op.
6. On the dirty path only: `find_remaining_functions`. It only does work when patch-diff was detected.

`find_unreliable_matches`, `find_brute_force` and `find_experimental_matches` **never run by default**. All three sit behind `if self.unreliable:` (default False), and no heuristic has category `"Experimental"`. `get_model_ratio` never runs, because `use_trained_model=False`. `is_auto_generated` is never called while diffing.

The parity traps:
- Row order of un-ordered SQL. SQLite's plan, and so the row order, **differs between real export pairs** (§19.1), so the verbatim SQL must run through SQLite (H1).
- Name-keyed bookkeeping. `find_equal_matches` keys on `mangled_function` and everything else keys on `name`.
- SQLite TEXT-affinity comparisons.
- `LIKE` is case-insensitive and treats `_` as a wildcard.
- `search_small_differences` records a partial match with **no lower ratio bound**. A ratio of 0.003 was reproduced.

Everything below was checked against the source and, where marked **[verified]**, against a live run of the unmodified reference on synthetic exports (§19). A later adversarial pass re-checked every claim against the source, measured plans and data on the real IDA oracle corpus (§19.1), and recorded its corrections in the **Verification log** at the end.

---

## 0. Sources, version, conventions

- Reference: `<diaphora-ref>`, HEAD `621ec26` (`git describe` = `3.4.2-4-g621ec26`). `git diff --stat 3.4.2 HEAD` touches only `README.md` and `diaphora_ida.py`, so **`diaphora.py`, `diaphora_heuristics.py`, `diaphora_config.py`, `db_support/*`, `jkutils/*`, `ml/*` and `scripts/*` are byte-identical to tag 3.4.2**. Every `diaphora.py:N` line reference below is valid for the tag. The `diaphora_ida.py` change is 4 CSS lines inserted at 3864+, so every `diaphora_ida.py:N` reference below (all ≤ 3800) is also valid for the tag.
- Oracle runtime on this PC: `<conda>/python.exe` 3.13.12 with SQLite **3.51.1**. The C++ build links SQLite from `miniconda3/Library`, and `Library/bin/sqlite3.exe --version` reports 3.51.1 as well. `cdifflib` is missing, so stdlib `difflib` is used. `joblib` 1.5.3, `sklearn` 1.8.0 and `pandas` 3.0.3 are present, so `ML_AVAILABLE=True`, but the ML path is still off by default (§12).
- "item" means the 8-element Python list that every pass appends to `self.all_matches[category]`:
  `[ea1:str(decimal text), name1:str, ea2:str(decimal text), name2:str, description:str, ratio:float|int, nodes1:int, nodes2:int]`.
  `ratio` is the Python **int** `1` in `find_equal_matches` (1439), in `find_same_name`'s best branch (2200) and in `add_matches_from_query` (2074, used by the `HEUR_TYPE_NO_FPS` Best heuristics). `check_ratio` can also return the **int `0`**: `values_set = set([v1, v2, v3, v4, v5])` (1755) keeps the first-inserted `0`, and `v1`/`v3` start as the int `0` (1699, 1685). When every component is zero and `deep_ratio` adds nothing (its `score` also starts as the int `0`, 2766), `r` stays the int `0`. That int can reach an item through `search_small_differences` or `add_matches_internal`. Everywhere else the ratio is a float. The difference is unobservable: Python `0 == 0.0` and `1 == 1.0`, sorting uses `float(x[5])`, and output formats with `"%.7f"` (diaphora.py:282-290). A C++ `double` is fine.
- `ea` values come from `functions.address`, which is declared `address text unique` (db_support/schema.py:72). SQLite TEXT affinity stores the exporter's int as **decimal text** (for example `'4198400'`). **[verified]**: `insert 4198400 into a text column -> typeof = 'text'`.

### 0.1 Configuration actually in effect (standalone)

| Setting | Source | Effective default | Evidence |
|---|---|---|---|
| `self.unreliable` | `get_value_for("unreliable", config.DIFFING_ENABLE_UNRELIABLE)` | **False** | diaphora.py:400-402, diaphora_config.py:46 |
| `self.relaxed_ratio` | `DIFFING_ENABLE_RELAXED_RATIO` | **False** | diaphora.py:403-405, config:47 |
| `self.experimental` | `DIFFING_ENABLE_EXPERIMENTAL` | **True** | diaphora.py:406-408, config:48 |
| `self.slow_heuristics` | `DIFFING_ENABLE_SLOW_HEURISTICS` | **True** | diaphora.py:409-411, config:49 |
| `self.use_trained_model` | `ML_USE_TRAINED_MODEL` | **False** | diaphora.py:412-414, config:205 |
| `self.ignore_sub_names` | `DIFFING_IGNORE_SUB_FUNCTION_NAMES` (no env override in diaphora.py) | **True** | diaphora.py:468, config:50 |
| `self.ignore_all_names` | config False, then forced False in `__main__` when not IDA | **False** | diaphora.py:470-472, 3759-3760 |
| `self.ignore_small_functions` | `DIFFING_IGNORE_SMALL_FUNCTIONS` | **False** (so `%POSTFIX%` is `""`) | diaphora.py:474-476, config:52 |
| `self.project_script` | env `DIAPHORA_PROJECT_SCRIPT` or None | **None** | diaphora.py:421 |
| `self.cpu_count` | forced to 1 outside IDA | **1** | diaphora.py:489-491 |
| `self.timeout` | `SQL_TIMEOUT_LIMIT` | **300 s** | diaphora.py:451, config:92 |
| `self.sql_max_processed_rows` | `SQL_MAX_PROCESSED_ROWS` | **1,000,000** | diaphora.py:454-456, config:90 |

**Correction to an earlier summary.** The claim "slow heuristics auto-disabled at `MIN_FUNCTIONS_TO_DISABLE_SLOW=4001`" is **IDA-GUI-only**. The constant's only use is the IDA options dialog default:

```python
# diaphora_ida.py:3798-3800
    self.slow = kwargs.get(
      "slow", total_functions <= config.MIN_FUNCTIONS_TO_DISABLE_SLOW
    )
```

`grep MIN_FUNCTIONS_TO_DISABLE_SLOW` finds only `diaphora_config.py:71` and `diaphora_ida.py:3799`. In standalone `diaphora.py`, `slow_heuristics = True` for any database size. **[verified]**: the trace prints `slow True`.

**Env-var quirk (it matters only if the oracle's environment is dirty):**

```python
# diaphora.py:560-569
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

`value` is always a `str`. For a bool or int default, `isinstance(str, bool/int)` is False, so the **raw string is returned**. For example `DIAPHORA_UNRELIABLE=0` gives `"0"`, which is truthy. `DIAPHORA_SQL_TIMEOUT_LIMIT=5` gives `"5"`, and the later `float > str` raises `TypeError`. **Parity runs must use an environment with no `DIAPHORA_*` variables.** On this PC `env | grep -i diaphora` is empty.

---

## 1. Where the passes sit in `diff()` (control flow)

```python
# diaphora.py:3603-3677 (abridged: the statements are verbatim, but blank lines 3642,
# 3652, 3657, 3661, 3665, 3667, 3670 and comment lines 3643-3649, 3658-3659, 3663,
# 3668 are removed; only 3643-3649 is marked below)
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
            # Find using likely unreliable methods modified functions
            log_refresh("Finding probably unreliable matches")
            self.find_unreliable_matches()
            # [comment lines 3643-3649 elided]
            log_refresh("Finding experimental matches")
            self.find_experimental_matches()

          iteration = 0
          while 1:
            self.cleanup_matches()
            old_total = self.get_total_matched_functions()
            self.find_matches_diffing(iteration)
            if self.slow_heuristics:
              self.find_related_matches(iteration)
            self.find_related_compilation_unit(iteration)
            self.find_locally_affine_functions(iteration)
            self.cleanup_matches()
            new_total = self.get_total_matched_functions()
            if new_total <= old_total:
              break
            iteration += 1

        self.final_pass()
```

I checked the indentation byte-for-byte with `cat -A`: spaces only, no tabs. `find_experimental_matches()` (line 3651) is **inside** `if self.unreliable:` (line 3638).

### 1.1 Porting pseudocode of the driver steps relevant to this doc

```
equal_db()                                # log only (section 1.2)
check_callgraph()                         # log only; may abort (see section 3)
find_equal_matches()                      # sets total_functions1/2 -- MUST run first
is_same_processor = any row(main.program.processor == diff.program.processor)
skip = False
if experimental (True):
    skip = search_just_stripped_binaries() or search_patchdiff_with_symbols()
if not ignore_all_names (True):
    find_same_name("partial")
if skip:
    find_remaining_functions()            # does work only if is_patch_diff
else:
    run_heuristics_for_category("Best")   # heuristics spec
    find_partial_matches()                # "Partial" heuristics + search_small_differences
    apply_machine_learning()              # no-op by default
    if unreliable (False):                # NOT DEFAULT
        find_unreliable_matches(); find_experimental_matches()
    iterative loop (other spec)
final_pass()                              # other spec
```

**[verified]** Traced with the unmodified module (§19).

| Scenario | Passes that ran, in order |
|---|---|
| Normal | `check_callgraph → find_equal_matches → apply_dirty_heuristics{stripped, patchdiff} → find_same_name → run_heuristics_for_category('Best') → find_partial_matches{run_heuristics_for_category('Partial'), search_small_differences} → apply_machine_learning → find_matches_diffing → find_related_matches → find_related_compilation_unit → find_locally_affine_functions → final_pass` |
| Stripped | `… → apply_dirty_heuristics{search_just_stripped_binaries} → find_same_name → find_remaining_functions{get_unmatched_functions} → final_pass` |
| Patch diff | `… → apply_dirty_heuristics{stripped, patchdiff{load_hooks}} → find_same_name → find_remaining_functions{get_unmatched_functions, search_remaining_functions} → final_pass` |

In none of the three scenarios did `find_unreliable_matches`, `find_experimental_matches` or `find_brute_force` appear.

### 1.2 What runs before 3603, and oracle outcomes that are not "results"

```python
# diaphora.py:3572-3601 (abridged: 3580-3582 = two log() calls + cur.close(); 3590-3591 =
# version-mismatch warning only; 3593-3597 = `try:`, t0, `cur_thread.timeout = False`,
# log_refresh. The last three lines sit inside that `try:` in the source.)
    self.ratios_cache = {}
    self.last_diff_db = db
    cur = self.db_cursor()
    self.try_attach(cur, db)                 # 2431-2443: attach errors are swallowed
    try:
      cur.execute("select value from diff.version")
    except:
      ...
      return False                           # 3583
    row = cur.fetchone()
    if not row:
      log("Invalid database!")
      return False                           # 3588
    ...
      self.do_continue = True
      if self.equal_db():
        log("The databases seems to be 100% equal")
```

- **`equal_db()` (diaphora.py:661-687) is log-only.** It counts `program p, diff.program dp where p.md5sum = dp.md5sum`, and if that count is not 1 it counts the rows of `(select id, address, size, nodes, edges from functions except select … from diff.functions)`. The return value only selects a log line. `do_continue` is never set to anything but `True`, so nothing is skipped.
- **`same_processor_both_databases()` (diaphora.py:2950-2967)** returns True iff `select 1 from main.program mp, diff.program dp where mp.processor = dp.processor` returns a row. NULL processors never match. It is evaluated at 3617, after `find_equal_matches` and before the dirty heuristics. It drives `HEUR_FLAG_SAME_CPU` and the per-constant bonus in `deep_ratio` (0.006 vs 0.008).
- **Early `return False` still writes an output file.** `__main__` calls `bd.diff(db2)` and then `bd.save_results(diff_out)` unconditionally (diaphora.py:3772-3773). When `diff()` returns False (no `diff.version` table or row, at 3583/3588, or `load_hooks()` failing at 3609-3610), `save_results` writes a valid `.diaphora` file with a `config` row and **empty** `results`/`unmatched` tables, and the process exits 0. A parity harness must treat "empty results" plus the `Invalid database!` or `does not look like a valid Diaphora exported database` log lines as an oracle failure, not as "no matches".
- `CBinDiff(db1)` → `open_db()` → `create_schema()` (diaphora.py:615-632) runs `create table if not exists …` for every `schema.TABLES` entry on the **main** DB. If `version` has no row it inserts `'3.4'` and commits. On a complete export this changes nothing. The oracle builder hashes the exports before and after the diffs stage to prove that.

---

## 2. Shared machinery the passes call

Other parity docs may also specify these helpers. If they do, the two specs must agree. They are restated here because no pass below can be implemented without them.

### 2.1 `get_query_fields`: the standard row shape

```python
# diaphora_heuristics.py:51-84 (line 50 is a "#----" comment)
SELECT_FIELDS = """ f.address ea, f.name name1, df.address ea2, df.name name2,
                  {heur} description,
                  f.pseudocode pseudo1, df.pseudocode pseudo2,
                  f.assembly asm1, df.assembly asm2,
                  f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                  f.nodes nodes1, df.nodes nodes2,
                  cast(f.md_index as real) md1, cast(df.md_index as real) md2,
                  f.clean_assembly clean_assembly1, df.clean_assembly clean_assembly2,
                  f.clean_pseudo clean_pseudo1, df.clean_pseudo clean_pseudo2,
                  f.mangled_function mangled1, df.mangled_function mangled2,
                  f.clean_microcode clean_micro1, df.clean_microcode clean_micro2,
                  f.bytes_hash bytes_hash1, df.bytes_hash bytes_hash2,
                  f.edges edges1, df.edges edges2,
                  f.indegree indegree1, df.indegree indegree2,
                  f.outdegree outdegree1, df.outdegree outdegree2,
                  f.instructions instructions1, df.instructions instructions2,
                  f.cyclomatic_complexity cc1, df.cyclomatic_complexity cc2,
                  f.strongly_connected strongly_connected1,
                  df.strongly_connected strongly_connected2,
                  f.loops loops1, df.loops loops2,
                  f.constants_count constants_count1,
                  df.constants_count constants_count2,
                  f.size size1, df.size size2,
                  f.kgh_hash kgh_hash1, df.kgh_hash kgh_hash2
"""
def get_query_fields(heur, quote=True):
  """
  Get the list of fields used in any and all SQL heuristics queries.
  """
  val = heur
  if quote:
    val = repr(val)
  ret = SELECT_FIELDS.format(heur=val)
  return ret
```

- With `quote=True`, the description is the Python `repr` of the name. For every name used in this doc that is a single-quoted SQL string literal, for example `'Perfect match, same name' description`. The C++ port only needs the `description` value, which is the plain name.
- With `quote=False` and `heur="?"` (used by `search_remaining_functions`), the description is a bound parameter.
- `md1`/`md2` are REAL, produced by `cast(md_index as real)`. `md_index` itself is TEXT (§2.8). `cast(NULL as real)` is NULL, and `check_ratio` then runs `float(None)` at diaphora.py:1672-1673, **before** the bytes-hash shortcut, so a NULL `md_index` crashes every ratio computation (H9).

### 2.2 `check_match`: the gate every SQL-row pass uses

```python
# diaphora.py:1786-1872 (dict construction lines 1798-1842 elided: main_d/diff_d
# copy ea,name,pseudo,asm,pseudocode_primes,nodes,md_index,clean_assembly,
# clean_pseudo,clean_micro,bytes_hash,edges,indegree,outdegree,instructions,
# cyclomatic_complexity,strongly_connected,loops,constants_count,size,kgh_hash
# from the *1 / *2 columns of SELECT_FIELDS)
  def check_match(self, row, ratio=None, debug=False):
    ea = row["ea"]
    ea2 = row["ea2"]
    name1 = row["name1"]
    name2 = row["name2"]
    desc = row["description"]
    ...
    if ratio != 1.0:
      nullsub = "nullsub_"
      if name1.startswith(nullsub) or name2.startswith(nullsub):
        debug_refresh(f"Ignoring nullsub functions {name1}-{name2}")
        return False, 0.0

      # Do we already have a 1.0 match for any of these functions?
      if self.has_best_match(name1, name2):
        debug_refresh(f"Ignoring as we have a best match {name1}-{name2}")
        return False, 0.0

      if ratio != 1.0:
        if ratio is None:
          r = self.check_ratio(main_d, diff_d)
          ...
        else:
          r = ratio

        # Do we have a previous match with a better comparison ratio than this?
        if self.has_better_match(name1, name2, r):
          debug_refresh(f"Ignoring as there is a better match than {r} for {name1}-{name2}")
          return False, 0.0

    should_add = True
    args = [main_d, diff_d, desc, r]
    should_add, r = self.call_hook("on_match", [should_add, r], args)
    return should_add, r
```

Every caller in this doc passes `ratio=None`, so the effective logic is:

```
check_match(row):
  if row.name1.startswith("nullsub_") or row.name2.startswith("nullsub_"):   # case-SENSITIVE
      return (False, 0.0)
  if has_best_match(row.name1, row.name2): return (False, 0.0)
  r = check_ratio(main_d(row), diff_d(row))          # cached per "ea1-ea2", see 2.7
  if has_better_match(row.name1, row.name2, r): return (False, 0.0)
  if hooks loaded and hooks has on_match:            # only after patch-diff detection, see 8.3
      return hooks.on_match(main_d, diff_d, row.description, r)   # pass-through by default
  return (True, r)
```

### 2.3 `add_matches_internal` and its wrappers

```python
# diaphora.py:1874-1948
  def continue_getting_sql_rows(self, i):
    """
    Determine if more rows should be read at the given stage
    """
    if self.sql_max_processed_rows != 0 and i < self.sql_max_processed_rows:
      return True
    return False

  def add_matches_internal(
    self, cur, best, partial, val=None, unreliable=None, debug=False
  ):
    i = 0
    matches = []
    cur_thread = threading.current_thread()
    t = time.monotonic()
    while self.continue_getting_sql_rows(i):
      if time.monotonic() - t > self.timeout or cur_thread.timeout:
        log(f"Timeout with heuristic '{cur_thread.name}'")
        raise SystemExit()

      i += 1
      if i % 50000 == 0:
        log(f"Processed {i} rows...")
      row = cur.fetchone()
      if row is None:
        break

      # Check the row match
      should_add, r = self.check_match(row, debug=debug)
      if not should_add:
        continue

      ea = str(row["ea"])
      name1 = row["name1"]
      ea2 = row["ea2"]
      name2 = row["name2"]
      desc = row["description"]
      nodes1 = int(row["nodes1"])
      nodes2 = int(row["nodes2"])

      done = True
      chooser = None
      item = None

      if val is None:
        val = config.DEFAULT_PARTIAL_RATIO

      if r == 1.0:
        chooser = best
        item = [ea, name1, ea2, name2, desc, r, nodes1, nodes2]
      elif r >= val and partial is not None:
        chooser = partial
        item = [ea, name1, ea2, name2, desc, r, nodes1, nodes2]
      else:
        done = False

      if done:
        matches.append([0, "0x%x" % int(ea), name1, ea2, name2])
        self.add_match(name1, name2, r, item, chooser)
      else:
        chooser = None
        item = None
        if r < config.DEFAULT_PARTIAL_RATIO and r > val and unreliable is not None:
          chooser = "unreliable"
          item = [ea, name1, ea2, name2, desc, r, nodes1, nodes2]
          matches.append([0, "0x%x" % int(ea), name1, ea2, name2])

        if chooser is not None:
          self.add_match(name1, name2, r, item, chooser)

    return matches
```

Porting spec:

```
add_matches_internal(rows, best, partial, val=None):
  t0 = monotonic(); i = 0
  while MAX_ROWS != 0 and i < MAX_ROWS:        # MAX_ROWS = 1_000_000; MAX_ROWS==0 means ZERO rows, not unlimited
      if monotonic() - t0 > 300s or thread_timeout_flag: raise Timeout   # see 2.3.1
      i += 1
      row = rows.next() or break
      (ok, r) = check_match(row); if not ok: continue
      v = 0.5 if val is None else val
      item = [str(row.ea), row.name1, row.ea2, row.name2, row.description, r, int(row.nodes1), int(row.nodes2)]
      if r == 1.0:                           add_match(row.name1, row.name2, r, item, best)
      elif r >= v and partial is not None:   add_match(row.name1, row.name2, r, item, partial)
      else:                                  drop
```

- **The `else`/"unreliable" branch (diaphora.py:1937-1946) is dead code at every call site.** To reach it, `not (r >= val and partial is not None)` and `r > val` must both hold. When `partial` is not None, that requires `r < val` and `r > val` at once. The only caller with `partial is None` is `find_brute_force`, which leaves `unreliable=None`. NaN fails both comparisons. The branch also writes the **literal** `"unreliable"`, not the `unreliable` argument, so the `unreliable=` argument never has any effect. `add_matches_from_query_ratio_max_trusted`'s docstring (diaphora.py:2004-2005: "assign those with a bad ratio to the partial chooser") is nevertheless honoured through a different route: it passes `partial="partial"` with `val=<heuristic min>` (for example 0.44), so `val ≤ r < 1.0` lands in **partial** through the ordinary `r >= val` branch. Port the three-way rule above and nothing else.
- The rows limit counts rows *fetched*, including the ones `check_match` rejects.
- `matches.append([0, "0x%x" % int(ea), …])` (1935) runs `int()` on the **text** address of every accepted row. A non-decimal address text raises `ValueError`. `deep_ratio` also does `int(main_d["ea"])` and looks the row up again by `str(int(ea))` (2763-2778), so an address with leading zeros, a sign or whitespace fails that lookup (`main_row` is None, then `TypeError`). Input contract: `functions.address` must be canonical decimal text. All 7 corpus exports satisfy it (§19.1).

#### 2.3.1 Timeout semantics

`self.timeout` is 300 s, measured from the start of **each** `add_matches_internal` call. `cur_thread.timeout` is set by `threads_apply` only on heuristic worker threads. The main thread has `timeout=False`, set at diaphora.py:3596. On timeout the code raises `SystemExit`, and what happens next depends on the wrapper:

| Wrapper | Handling |
|---|---|
| `add_matches_from_query_ratio`, `_ratio_max`, `_ratio_max_trusted` (1950-2026) | `except SystemExit: pass`. Matches found so far are kept and the rest is silently lost. |
| `add_matches_from_cursor_ratio_max` (2028-2037, used by `find_brute_force`) | No handler. `SystemExit` propagates out of `diff()` and the process exits **without writing results**. |
| `search_remaining_functions` | No handler, same outcome. Each call fetches at most 1 row, so it cannot realistically hit this. |

Timing cannot be reproduced natively. A parity harness should treat any oracle run whose log contains `Timeout with heuristic` as non-comparable.

**Exit status of the non-handled case.** `raise SystemExit()` has no argument, so the interpreter exits with status **0**. `save_results` never runs. `save_results` is also the only place that deletes a pre-existing output file (2379-2381), so **a stale `.diaphora` from an earlier run survives**. The harness must write every oracle run into a fresh directory, or delete the output first, and must require the output file to exist. A zero exit code alone proves nothing.

#### 2.3.2 The wrappers used in this doc

```python
# diaphora.py:1950-1975
  def add_matches_from_query_ratio(
    self, sql, best, partial, unreliable=None, debug=False
  ):
    """
    Find matches using the query @sql and the usual rules.
    """
    if self.all_functions_matched():
      return

    cur = self.db_cursor()
    try:
      cur.execute(sql)
      self.add_matches_internal(
        cur, best=best, partial=partial, unreliable=unreliable, debug=debug
      )
    except SystemExit:
      pass
    except:
      log(f"Error: {str(sys.exc_info()[1])}")
      print("*" * 80)
      print(sql)
      print("*" * 80)
      traceback.print_exc()
      raise
    finally:
      cur.close()
```

```python
# diaphora.py:2028-2037
  def add_matches_from_cursor_ratio_max(self, cur, best, partial, val):
    """
    Find matches using the cursor @sql with a ratio >= @val and assign matches
    to the corresponding lists.
    """
    if self.all_functions_matched():
      return

    matches = self.add_matches_internal(cur, best=best, partial=partial, val=val)
    return matches
```

### 2.4 `add_match`, `has_best_match`, `has_better_match`, `all_functions_matched`

```python
# diaphora.py:1340-1402 (abridged: docstrings 1341-1346, 1377-1379, 1387-1389 and the
# debug-message bodies 1359-1361, 1365-1367 omitted; every statement shown is verbatim)
  def add_match(self, name1, name2, ratio, item, chooser):
    with self.items_lock:
      # If the function names are the same, it's a best match, regardless of the
      # ratio we got for the match, so fake the ratio as if it was 1.0.
      if name1 == name2:
        ratio = 1.0

      if ratio != 1.0:
        if self.has_better_match(name1, name2, ratio):
          return

        if name1 in self.matched_primary:
          if self.matched_primary[name1]["ratio"] < ratio:
            ...debug log only...
        if name2 in self.matched_secondary:
          if self.matched_secondary[name2]["ratio"] < ratio:
            ...debug log only...

      if chooser is not None:
        if item not in self.all_matches[chooser]:
          self.all_matches[chooser].append(item)

      self.matched_primary[name1] = {"name": name2, "ratio": ratio}
      self.matched_secondary[name2] = {"name": name1, "ratio": ratio}

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

```python
# diaphora.py:1777-1784
  def all_functions_matched(self):
    return (
      len(self.matched_primary) == self.total_functions1
      or len(self.matched_secondary) == self.total_functions2
    )
```

Porting notes (all load-bearing):
- `matched_primary` and `matched_secondary` are dicts keyed by **function name string**, not by address. Two functions that share a name collide.
- `add_match` stores the **fake ratio 1.0** in `matched_*` whenever `name1 == name2`, even when the item carries a lower ratio, for example a same-name partial at 0.888. Until the next `cleanup_matches`, those functions count as having a *best* match for `has_best_match`.
- `has_better_match` has an early return. When **both** names lack the `sub_` prefix (case-sensitive) and `name1` is already in `matched_primary`, it returns `matched_primary[name1].name == name1` and **never looks at ratios or at `name2`**. Consequence: a non-`sub_` function already matched to a *differently named* function can be re-matched by a later candidate with any ratio, however low.
- Ratio comparisons in `has_better_match` are **strictly greater**, so ties are allowed through and become multimatches later.
- `item not in list` compares all eight elements with Python `==`. The C++ port needs "append if no identical 8-tuple exists in that category". The `'4198400'` string versus an int does not arise, because every pass uses text eas.
- `all_functions_matched` tests **equality** of dict sizes. A dict holding mangled *and* demangled keys can exceed `total_functions1` and then never compares equal (§5).

### 2.5 `cleanup_matches`

It is called at the end of every `run_heuristics_for_category`, which includes the one inside `find_partial_matches` just before `search_small_differences`. It is also called at the top of each iteration loop and inside `final_pass`.

```python
# diaphora.py:1554-1605 (abridged: docstring 1555-1557 and comment lines 1567-1568 omitted)
  def cleanup_matches(self):
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

Port it exactly:
- Categories are processed in dict insertion order `best, partial, unreliable` (diaphora.py:382).
- The sort is Python's **stable** `sorted(..., reverse=True)` on `float(item[5])`, so equal ratios keep insertion order.
- `dones` and `ea_ratios` are **shared across categories**.
- The dedup key is the concatenated string `name1 + "-" + name2`, which collides when a name contains `-`. Replicate the string key, not a pair.
- `ea_ratios` is keyed on `item[0]` (the primary ea text) only. There is no secondary-side dedup.
- After cleanup, `matched_*` is rebuilt from `item[5]`, the real ratio, **not** the fake 1.0.
- `dones[match] = ratio` (1583) is written **before** the `ea_ratios` test (1587). An item dropped by the `ea_ratios` test therefore still marks its `name1-name2` string as done, and a later item with the same string in a later category is also dropped.

### 2.6 `run_heuristics_for_category` (called by `find_partial_matches`, `find_unreliable_matches` and `find_experimental_matches`)

The SQL of each heuristic belongs to the heuristics spec. What matters here is the execution contract:

```python
# diaphora.py:1479-1552 (abridged: logging lines kept only where they matter)
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
        continue
      if HEUR_FLAG_SLOW in flags and not self.slow_heuristics:
        continue
      if HEUR_FLAG_SAME_CPU in flags and not self.is_same_processor:
        continue

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

```python
# jkutils/threads.py:36-53
  while first or len(targets) > 0 or len(threads_list) > 0:
    first = False
    times += 1
    if len(targets) > 0 and len(threads_list) < threads:
      item = targets.pop()
      ...
      t = threading.Thread(target=target, args=args)
      t.time = time.monotonic()
      t.timeout = False
      ...
      t.start()
      threads_list.append(t)
```

- **Heuristics execute in REVERSE list order.** `targets.pop()` takes the last element. With `cpu_count=1` (standalone), threads run strictly one after another. **[verified]**: the recorded thread-name order was `Microcode mnemonics small primes product … Same RVA and hash` for Best, then `Loop count … Same named compilation unit function match` for Partial, with the three `HEUR_FLAG_UNRELIABLE` Partial heuristics (indices 36-38) skipped.
- The "all matched" early exit is evaluated only while the target list is being **built**, before any heuristic of the category runs. Each `add_matches_*` wrapper re-checks `all_functions_matched()` at its own start.
- Each heuristic runs on a **new thread with its own SQLite connection** (`get_db` → `open_db` per thread id; diaphora.py:584-593). That affects neither semantics nor query plans.
- **Log order is not execution order.** The `"[Single thread] Finding with heuristic '<name>'"` lines (1517) are printed while the target list is *built*, in forward list order. Execution is in reverse. The thread's `name` attribute is set to the heuristic name through `setattr(t, key, item[key])` (jkutils/threads.py:48-50), and the `"Heuristic '<name>' done"` lines (threads.py:58) show the real order.
- `self.call_hook("get_queries_postfix", None, [arg_category, postfix])` (1475) **discards** its return value, so a hook cannot change `%POSTFIX%`.

### 2.7 `check_ratio`: summary only (the ratio spec is authoritative)

`check_ratio(main_d, diff_d)` (diaphora.py:1645-1775) under defaults (`relaxed_ratio=False`, so `fratio = quick_ratio` and values are rounded with `"{0:.7f}"`):
1. The cache key is `f"{ea1}-{ea2}"`, built from the text eas. The cache **persists across all passes** of one `diff()` and is reset only at diaphora.py:3572.
2. `bytes_hash1 == bytes_hash2` returns `1.0`. This includes both NULL: `None == None`.
3. `v1` is the 7-dp-rounded `quick_ratio(clean_pseudo)`, computed only when both `pseudocode` values are non-NULL and non-empty and both `clean_pseudo` values are non-empty.
4. `v2` is the 7-dp-rounded `quick_ratio(clean_assembly)`.
5. `v4 = min((v1+v2+0+3.0)/5, 1.0)` when `md1 == md2 and md1 > 0`.
6. `v5` is the 7-dp-rounded `quick_ratio(clean_microcode)` when both are non-NULL. **`v5 == 1` returns 1.0 early.**
7. `r = max{v1,v2,0,v4,v5}`. If `r == 1.0 and md1 != md2`, then `r` becomes the max of the values `!= 1.0` (0 if none).
8. If `r < 1.0`: `r += deep_ratio(...)`, or `r = 0.99` when `r + score >= 1.0`.

`quick_ratio(a, b)` is `0` if either input is None or `""`. Otherwise it is stdlib `SequenceMatcher(None, a.split("\n"), b.split("\n")).quick_ratio()` (diaphora.py:158-165).

`deep_ratio` (2749-2837) adds small bonuses:
- +0.001 for the same non-empty `source_file`.
- +0.001 for the same non-empty `pseudocode_primes`.
- +0.001 for the same non-zero `indegree`.
- +0.001 for the same non-zero `outdegree`.
- +0.003 for the same `switches` when it is not `"[]"`.
- +0.001 for the same non-zero `cyclomatic_complexity`.
- For each shared constant (JSON set intersection): +0.006 if `is_same_processor`, else +0.008.
- The ML term, §12.

NULL quirks of `deep_ratio` (diaphora.py:2792-2821): the tests are `in1 == in2 and in1 != 0`, `switches1 == switches2 and switches1 != "[]"`, and so on. Two NULLs therefore **earn** the indegree, outdegree, switches and cc bonuses (`None == None` and `None != 0`). `json.loads(None)` raises when `main.constants` is NULL, or when `main.constants != '[]'` and `diff.constants` is NULL. The ratio spec is authoritative on these.

**[verified]** Rounding: a pair with md equal, totally different asm, and in/out/cc equal scored exactly `0.603 = 3.0/5 + 0.003`.

### 2.8 Input encodings (what the exporter writes; this matters for SQL semantics)

| Column | Declared type (schema.py) | Written as | Evidence |
|---|---|---|---|
| `functions.address` | `text unique` (72) | decimal text of the int ea | `get_valid_prop` (diaphora.py:724-728) leaves ints ≤ 0xFFFFFFFF as Python ints and turns larger ones into `str(prop)`. Either way the TEXT affinity column stores decimal text. |
| `functions.name` | `varchar(255)` (71), so TEXT | IDA **demangled** short name if demanglable, else the raw name | diaphora_ida.py:2448-2453 `return demangled or true_name, true_name, demangled` |
| `functions.mangled_function` | text | IDA raw name (`get_func_name`) | diaphora_ida.py:2451, props slot 14 (`true_name`) |
| `nodes, edges, indegree, outdegree, instructions, cyclomatic_complexity, constants_count, size, loops, strongly_connected` | integer | ints | schema.py |
| `names`, `mnemonics`, `constants`, `switches` | text | `json.dumps(list(x), ensure_ascii=False, cls=CBytesEncoder)`; `names` is **sorted** before dumping; `mnemonics` is a list appended in instruction order (diaphora_ida.py:2852); empty is exactly `'[]'` | diaphora.py:933-941; diaphora_ida.py:3009-3011 |
| `md_index` | text (107) | `str(decimal.Decimal)` (28 significant digits) or the int `0`, stored as `'0'` | diaphora_ida.py:2514-2538 |
| `kgh_hash` | text (112) | `str(int)`, or `"NO-FUNCTION"` / `"NO-FLOW-GRAPH"` | jkutils/graph_hashes.py `calculate` returns `str(hash)` and the two literals |
| `source_file` | text | may be NULL or `''` | schema.py:113 |
| `program.callgraph_primes` | text | `str(Decimal product of all primes_value)` (default 28-digit context, may be scientific notation) | diaphora_ida.py:1250-1270 |
| `program.callgraph_all_primes` | text | `json.dumps({primes_value: count})`, so JSON object keys are **strings** | diaphora_ida.py:1251-1256, 1269 |
| `program.processor` | text | processor name | schema.py:123 |

Real exports carry the 41 indices of `schema.INDICES`, created as `idx_{i}` in list order (diaphora.py:634-649, called from diaphora_ida.py:1281), plus `ANALYZE` statistics (diaphora.py:646-647). **These drive the query plans, and so the row order.** See Hard part H1. The corpus exports confirm it: all 7 exports under `<corpus>/oracle/exports` have 41 `idx_*` indices, a `sqlite_stat1` table and `version = '3.4'` (§19.1).

---

## 3. `check_callgraph` / `get_callgraph_difference`

```python
# diaphora.py:1288-1338
  def get_callgraph_difference(self):
    """
    Get the percent of difference between the main and diff databases
    """
    cur = self.db_cursor()
    try:
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
          msg = "Call graph signature for both databases is equal, the programs seem to be 100% equal structurally"
          log(msg)
          Warning(msg)
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
    finally:
      cur.close()

  def check_callgraph(self):
    """
    Compare the call graphs of both databases and print out how different they are
    """
    percent = self.get_callgraph_difference()
    if percent == 0:
      log("Call graphs are 100% equal")
    elif percent >= 100:
      log("Call graphs are absolutely different")
    else:
      log(f"Call graphs from both programs differ in {percent}%")

    self.percent = percent
```

```python
# jkutils/factor.py:202-242
FACTORS_CACHE = {}
def _difference(num1, num2):
  nums = [num1,
          num2]
  s = []
  for num in nums:
    if num in FACTORS_CACHE:
      x = FACTORS_CACHE[num]
    else:
      x = factorization(int(num))
      FACTORS_CACHE[num] = x
    s.append(x)

  diffs = {}
  for x in list(s[0].keys()):
    if x in list(s[1].keys()):
      if s[0][x] != s[1][x]:
        diffs[x] = max(s[0][x], s[1][x]) - min(s[0][x], s[1][x])
    else:
      diffs[x] = s[0][x]

  for x in list(s[1].keys()):
    if x in list(s[0].keys()):
      if s[1][x] != s[0][x]:
        diffs[x] = max(s[0][x], s[1][x]) - min(s[0][x], s[1][x])
    else:
      diffs[x] = s[1][x]

  return diffs, s

def difference(num1, num2):
  diffs, _ = _difference(num1, num2)
  return sum(diffs.values())
```

**Algorithm.** `rows[0]` is `main.program` and `rows[1]` is `diff.program`, because `UNION ALL` keeps branch order. If `cg1 == cg2` (Decimal equality) the percent is 0. Otherwise both JSON dicts go into the cache, so `factorization` is never actually called. Then `diff = Σ_k |c1[k] − c2[k]|` over the union of keys, where a key present on one side only contributes its full count. `total = Σ c1`, and `percent = diff*100.0/total`, or 0 when `total == 0 or diff == 0`.

**Outputs.** `self.percent` and `self.equal_callgraph`. `grep` over every `.py` file of the reference (including `diaphora_ida.py` and `scripts/`) shows **neither is read anywhere else** (diaphora.py:388, 443, 1306, 1338 are the only hits). **No chooser or category is affected, and neither is any ratio.** `Warning(msg)` at 1309 only constructs an exception object; it is not raised. The excerpt of `jkutils/factor.py` above omits the docstrings at 204-206 and 237-240.

**Failure modes that abort the whole diff**, and so change "does the oracle produce output at all":
- `len(rows) != 2`, meaning the two `program` tables together do not hold exactly 2 rows. Note a hole: main with 2 rows and diff with 0 passes the check and compares main against itself.
- `callgraph_primes` NULL or unparsable (`decimal.Decimal(None)` raises `TypeError`, and bad text raises `InvalidOperation`).
- `callgraph_all_primes` NULL or not JSON.

**Porting spec.** Only the failure contract is required: check that main and diff `program` tables have exactly one row each, with parsable fields. Implement the percent only for logging, if at all. Our C++ exporter must write a valid `program` row (`str(Decimal)` product and a JSON object of `{primes_value_text: count}`), or the Python oracle crashes before matching.

**Runs by default?** **Yes, always.** diaphora.py:3605 is unconditional inside `if self.do_continue:`, and `do_continue = True` is set at 3599. It has no effect on matches.

---

## 4. `is_auto_generated`

```python
# diaphora.py:1279-1286
  def is_auto_generated(self, name):
    """
    Check if the function name looks like an IDA's auto-generated one
    """
    for rep in config.CLEANING_CMP_REPS:
      if name.startswith(rep):
        return True
    return False
```

```python
# diaphora_config.py:152-154
CLEANING_CMP_REPS = ["loc_", "j_nullsub_", "nullsub_", "j_sub_", "sub_",
  "qword_", "dword_", "byte_", "word_", "off_", "def_", "unk_", "asc_",
  "stru_", "dbl_", "locret_", "flt_", "jpt_"]
```

**Spec.** The function returns true iff `name` starts (case-sensitively) with any of the 18 prefixes. Order is irrelevant.

**Runs by default?** **No, never during diffing.** The only call sites are `diaphora_ida.py:1889` and `:1908`, inside IDA's symbol-import code. `grep` finds no caller in `diaphora.py`. Porting it is not needed for diff parity.

---

## 5. `find_equal_matches`

```python
# diaphora.py:1404-1442
  def find_equal_matches(self):
    """
    Find 100% equal matches in both databases
    """
    cur = self.db_cursor()
    try:
      # Start by calculating the total number of functions in both databases
      sql = """select count(*) total from functions
        union all
        select count(*) total from diff.functions"""
      cur.execute(sql)
      rows = cur.fetchall()
      if len(rows) != 2:
        Warning(f"Malformed database, only {len(rows)} rows!")
        cur.close()
        raise Exception("Malformed database!")

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
    finally:
      cur.close()
```

**Algorithm and porting spec.**

```
total_functions1 = count(main.functions); total_functions2 = count(diff.functions)   # REQUIRED by later passes
for each main row m, in ascending m.id:          # see "order" below
   if exists diff row d with the 7-tuple (id, address, mangled_function, nodes, edges, size, bytes_hash)
          equal under SQL set semantics (NULL == NULL, types must match):
       name = m.mangled_function                  # NOTE: mangled, not name
       item = [m.address(text), name, m.address(text), name, "100% equal", 1 (int), int(m.nodes), int(m.nodes)]
       add_match(name, name, 1.0, item, "best")   # name1==name2, so ratio 1.0, always appended once
```

- **The `id` column (rowid) is part of the tuple.** Only functions with the **same rowid** in both exports can match. Any inserted or removed function shifts the ids of everything after it, so on real version pairs this pass usually finds little.
- **INTERSECT treats NULLs as equal.** **[verified]**: a row with `h = NULL` on both sides survives. So two functions with NULL `bytes_hash` and all other fields equal *do* match.
- Neither `check_match`, `check_ratio`, the nullsub filter nor any hook is involved. There is also no `all_functions_matched` check.
- **Keying quirk.** The item and the `matched_*` keys use `mangled_function`. Every other pass keys on `functions.name`. When `name != mangled_function` (C++ symbols, since `name` is demangled), later passes do not see the function as matched: `has_best_match(name)` is False. So `find_same_name` adds a **second** best item for the same `(ea1, ea2)` pair keyed by the demangled name. **[verified]** in scenario D, below.
- **Order.** `INTERSECT USING TEMP B-TREE` emits rows sorted by the full compound tuple, which starts with `id`. That makes it ascending main `id`. **[verified]** by a direct test (ids inserted 3,1,2 came out 1,2,3) and by `EXPLAIN QUERY PLAN` (`COMPOUND QUERY / INTERSECT USING TEMP B-TREE`). Order only affects item order inside `best`, which in turn affects output `line` numbers and the stable-sort tie order.
- `int(row["nodes"])` crashes on NULL `nodes`, and `name` NULL would store a `None` key. Treat both as input-contract violations.
- The `if len(rows) != 2` guard (1416) is dead: `select count(*) … union all select count(*) …` always returns exactly two rows.
- **Corpus reality (§19.1).** `find_equal_matches` returns 0 rows for 4 of the 5 oracle pairs and 4 rows for `sechost-9168-pdb vs sechost-9444-nopdb`. Rowids shift between builds. The mangled-versus-name keying quirk is live, though: 393 to 772 functions in each PDB export have `name != mangled_function`.

**Inputs.** `main.functions` and `diff.functions`: `id, address, mangled_function, nodes, edges, size, bytes_hash`.

**Outputs.** Chooser **best**, description `"100% equal"`, ratio `1` (int). Also sets `total_functions1/2`.

**[verified] Scenario D** (20 C++-style functions: `name="ns::fN"`, `mangled="?fN@ns@@YAXXZ"`, same ids, 18 of 20 addresses equal, function 12 modified):
- 17 `"100% equal"` items were keyed by the mangled name.
- `find_same_name` then added 19 `"Perfect match, same name"` items (17 duplicates of the same address pairs plus f18 and f19) and 1 partial (f12).
- `matched_primary` held **37 keys** for 20 functions.
- In the final `results` table the duplicates were swallowed by `insert or ignore` on `uq_results(address, address2)` (diaphora.py:2399, 2406). The visible rows are the `"100% equal"` ones, with mangled names. `line` values jump from `00016` to `00034`.

**Runs by default?** **Yes, always.** diaphora.py:3614 is unconditional.

---

## 6. `apply_dirty_heuristics`

```python
# diaphora.py:2629-2637
  def apply_dirty_heuristics(self):
    """
    Apply what internally are called dirty heuristics (aka "speed ups").
    """
    if self.search_just_stripped_binaries():
      return True
    if self.search_patchdiff_with_symbols():
      return True
    return False
```

**Spec.** Short-circuit OR: patch-diff detection is **not evaluated** when stripped detection fires. The return value becomes `skip_others` (diaphora.py:3621). When it is True, **the Best, Partial and Unreliable heuristics, `search_small_differences`, ML, the whole iterative loop (`find_matches_diffing`, related constants, related CU, local affinity) are all skipped.** Only `find_same_name`, then `find_remaining_functions`, then `final_pass` run.

**Runs by default?** **Yes.** Gated by `if self.experimental:` (diaphora.py:3618), and `experimental=True` (config:48).

---

## 7. `search_just_stripped_binaries`

```python
# diaphora.py:2540-2585
  def search_just_stripped_binaries(self):
    ret = False
    total = self.total_functions1
    cur = self.db_cursor()

    try:
      sql = """select count(0)
                 from main.functions f,
                      diff.functions df
                where f.address = df.address """
      cur.execute(sql)
      row = cur.fetchone()
      matches = row[0]

      # If more than 99% of the best matches share the same exact address it is
      # clear it's the same binary with very little changes like, probably, just
      # symbols stripped.
      percent = (matches * 100) / total
      if percent >= config.SPEEDUP_STRIPPED_BINARIES_MIN_PERCENT:
        self.is_symbols_stripped = True
        message = f"A total of {matches} matches out of {total}, {percent}% percent have the same address"
        log(f"Symbols stripped detected: {message}")

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
        log_refresh(f"Finding via {repr(heur)}")

        self.add_matches_from_query_ratio(sql, "best", "partial")
        ret = True
    finally:
      cur.close()

    return ret
```

**Porting spec.**

```
matches = number of (f, df) pairs with f.address == df.address (text equality; address is unique per DB,
          so this is |addresses shared|)
percent = (matches * 100) / total_functions1       # float true division; total==0 raises ZeroDivisionError (crash)
if percent >= 99.0:                                 # SPEEDUP_STRIPPED_BINARIES_MIN_PERCENT, diaphora_config.py:160; >= (inclusive)
    is_symbols_stripped = True
    rows = every (f, df) with f.address == df.address, SELECT_FIELDS, description "Same binary with symbols stripped"
    add_matches_from_query_ratio(rows, best="best", partial="partial")
         # returns immediately without adding anything if all_functions_matched()
         # else add_matches_internal(val=None -> 0.5): r==1.0 -> best; r>=0.5 -> partial; else drop
    return True                                     # True even if nothing was added
return False
```

- Ratio is `check_ratio` via `check_match`, so the nullsub filter, `has_best_match`, `has_better_match` and hooks all apply. Hooks are never loaded at this point.
- `percent` in C++: `(double)(matches*100) / (double)total`. Python's int/int true division is correctly rounded, and IEEE `double` division of exactly representable operands gives the same result.
- **Order.** Observed plan: `SCAN f USING INDEX idx_28` (the `functions(address)` index), then `SEARCH df USING INDEX idx_28 (address=?)`, then `USE TEMP B-TREE FOR DISTINCT`, which filters and does not reorder. That makes rows ordered by **main address as TEXT** (lexicographic decimal strings: `"10485760" < "4198400"`). On real exports (§19.1) the planner **flips the join** for `userenv-9168-pdb vs userenv-9278-nopdb` (`SCAN df USING INDEX idx_28`, `SEARCH f USING INDEX idx_28`). Because the join condition is `f.address = df.address`, the diff-address order is the same text sequence, so **the row order does not change** in that case. Because the address join is 1:1, order only matters through name collisions in the `matched_*` dicts and through `line` order.
- `(matches * 100) / total` with `total == 0` raises `ZeroDivisionError` and aborts `diff()` (no handler). The same division runs again in `search_patchdiff_with_symbols` and `show_summary`.

**Inputs.** `functions.address` (both), then every SELECT_FIELDS column.

**Outputs.** **best** (r == 1.0) or **partial** (0.5 ≤ r < 1.0). The description is `"Same binary with symbols stripped"`. The ratio is `check_ratio` with no bonus.

**[verified] Scenario B.** 20 functions at identical addresses; diff names are `sub_…`; one body modified. Result: 19 best at `1.0000000`, 1 partial at `0.8780000`. After that, the only passes that ran were `find_same_name` and `find_remaining_functions{get_unmatched_functions}`.

**Runs by default?** **Yes, it is always evaluated** (first call inside `apply_dirty_heuristics`). It only adds matches when at least 99% of main functions share an address with a diff function.

---

## 8. `search_patchdiff_with_symbols` (and the default hook script)

```python
# diaphora.py:2587-2627
  def search_patchdiff_with_symbols(self):
    ret = False
    total = self.total_functions1
    cur = self.db_cursor()

    try:
      sql = """select count(0)
                 from main.functions f,
                      diff.functions df
                where f.mangled_function = df.mangled_function """
      cur.execute(sql)
      row = cur.fetchone()
      matches = row[0]

      # If more than 90% of the best matches share the same exact mangled name
      # it is clear where patch diffing 2 different versions of the same binary.
      percent = (matches * 100) / total
      if percent > config.SPEEDUP_PATCH_DIFF_SYMBOLS_MIN_PERCENT:
        # We already have them matched, just instruct the heuristic engine to
        # finish by doing brute forcing with the remaining functions and that's
        # about it.
        self.is_patch_diff = True
        if self.project_script is None or self.project_script == "":
          if config.RUN_DEFAULT_SCRIPTS:
            log("Loading default script for patch diffing sessions...")
            self.project_script = config.DEFAULT_SCRIPT_PATCH_DIFF
            self.load_hooks()

        msg = f"A total of {matches} matches out of {total}, {percent}% percent have the same name"
        log(f"Patch diffing detected: {msg}")
        ret = True
    finally:
      cur.close()

    return ret
```

### 8.1 Porting spec

```
matches = number of (f, df) pairs with f.mangled_function == df.mangled_function
          # a pair COUNT: NULLs never equal; duplicated mangled names multiply; can exceed total
percent = (matches * 100) / total_functions1        # float; can be > 100; total==0 raises (crash)
if percent > 90.0:                                  # SPEEDUP_PATCH_DIFF_SYMBOLS_MIN_PERCENT, config:166; STRICT >
    is_patch_diff = True
    if project_script is None or "": if RUN_DEFAULT_SCRIPTS (True, config:186):
        project_script = <diaphora dir>/scripts/patch_diff_vulns.py ; load_hooks()
    return True
return False
```

**No matches are added here.** The name matching itself is done by the following `find_same_name`, and the leftovers by `find_remaining_functions` (§18).

### 8.2 Inputs and outputs

- **Inputs:** `functions.mangled_function` (both sides).
- **Outputs:** sets `is_patch_diff` and loads hooks. No chooser is touched.

### 8.3 The default hook script: effect on results = none; effect on process = possible crash

`scripts/patch_diff_vulns.py` defines `CVulnerabilityPatches`. Its hooks are pass-through:

```python
# scripts/patch_diff_vulns.py:79-86
  def get_heuristics(self, category, heuristics):
    return heuristics

  def on_launch_heuristic(self, name, sql):
    return sql

  def get_queries_postfix(self, category, postfix):
    return postfix
```

```python
# scripts/patch_diff_vulns.py:204-236 (abridged)
  def on_match(self, func1, func2, description, ratio):
    # Ignore matches with ratio 1.0, as they contain no changes
    if ratio < 1.0:
      ...
      results = self.find_vulns_using_assembly(func1, func2, ratio)
      if not results.found:
        results = self.find_vulns_using_pseudocode(func1, func2, ratio)
      if results.found:
        ...log...
        self.chooser.add_item(item)      # "Interesting matches" chooser -- NOT saved by save_results
    return True, ratio
```

- `on_match` always returns `(True, ratio)` unchanged. `on_special_heuristic` is not defined, so `call_hook` returns its default `True`. The "Interesting matches" chooser is not among the six categories `save_results` writes (diaphora.py:2409-2416). **Matching results are unaffected.**
- **Crash hazard.** `find_vulns_using_assembly` (scripts/patch_diff_vulns.py:143-168) runs `mnem1 = added.split(" ")[0].lower()` and then evaluates `mnem1[0] == "b"`. It raises `IndexError` when a `+` content line of the unified assembly diff is empty or begins with a space, because `mnem1` is then `''`. `mnem2[0]` fails the same way for the current `removed` line, but only when `mnem1` starts with `b`. The diff's own header lines `'--- \n'` and `'+++ \n'` pass through the same loop and set `removed`/`added` first, harmlessly, so `removed` is never None by the time a content `+` line arrives. Only an earlier `break` (a signed/unsigned pair already found) avoids the crash. **Reproduced:** asm1 `'mov eax, 1\nret'` against asm2 `'mov eax, 1\n\nret'` or `'mov eax, 1\n ret'` raises `IndexError: string index out of range`. The hook only analyses pairs with `ratio < 1.0` that are not already in its `dones` set (204-214). It runs inside `check_match` from `find_same_name` and `search_remaining_functions`, both on the main thread with no `except`, so the exception kills `diff()`. The process exits non-zero and no results file is written.
  - IDA exports join `GetDisasm()` lines and, for multi-block functions, `"loc_%x:"` labels with `"\n"` (diaphora_ida.py:2593, 2708-2726). Whether `GetDisasm()` can return an empty string or a line with a leading space is IDA behaviour, **NOT DETERMINED FROM SOURCE**. The `UnicodeDecodeError` fallback `get_disasm` builds `f"{mnem.ljust(8)} {op1}"` (diaphora_ida.py:2440-2446), which starts with spaces whenever the mnemonic is empty. Empirically, none of the 7 corpus exports contains an empty assembly line, a line starting with a space, an empty `assembly`, or a trailing newline (§19.1).
  - **Contract for our C++ exporter:** never emit `assembly` lines that are empty or start with a space, or the Python oracle will crash on patch-diff pairs.
- `load_hooks()`'s return value is **ignored** here (2619). If the script fails to load, `is_patch_diff` stays True, `project_script` stays set and `hooks` stays None. The pipeline is the same, minus the hook.
- Loading the script executes `from diaphora import CChooser, log` (scripts/patch_diff_vulns.py:13). When the oracle runs as `python diaphora.py`, this **imports `diaphora.py` a second time** as module `diaphora`. That re-runs its top level: warnings are printed again and `importlib.reload(config)` and similar calls run. Nothing that the running `__main__` instance reads is changed. There is no result effect.

**[verified] Scenario C.** 19 of 20 mangled names shared at shifted addresses; one `sub_403000` in main renamed to `renamed_fn` in diff. Result: `load_hooks` ran and `hooks = CVulnerabilityPatches`. `find_same_name` gave 18 best and 1 partial (`func_2`, 0.888). `search_remaining_functions` added `sub_403000 → renamed_fn`, partial `0.8780000`, description `"Renamed or anonymous function match in patch diffing session"`.

**Runs by default?** **Yes, it is evaluated whenever stripped detection did not fire** (diaphora.py:2635). It flips the pipeline when the mangled-name *pair* count exceeds 90% of the main function count. That is not quite "90% of main functions have a partner", because duplicated mangled names multiply pairs.

**Corpus (§19.1).** It fires for `userenv-9168-pdb vs userenv-9278-pdb`. The oracle log shows `Loading default script for patch diffing sessions...` and `Patch diffing detected: A total of 643 matches out of 643, 100.0% percent have the same name`. The results hold only `"Perfect match, same name"` rows (635 best, 8 partial). Every main function was matched, so `search_remaining_functions` had nothing to iterate. The 20 unmatched diff functions are saved with `unmatched.type = 'primary'` (§16 note). It does not fire for the other 4 pairs, whose percentages are 9.3 to 37.5.

---

## 9. `find_same_name`

```python
# diaphora.py:2152-2210
  def find_same_name(self, choose):
    """
    Find matches by searching for the same name using both mangled and unmangled names.
    """
    cur = self.db_cursor()
    desc = "Perfect match, same name"
    sql = (
      """select distinct """
      + get_query_fields(desc)
      + """
         from functions f,
          diff.functions df
        where (df.mangled_function = f.mangled_function
         or df.name = f.name)
        and f.name not like 'nullsub_%'"""
    )

    log_refresh(f"Finding with heuristic '{desc}'")
    try:
      cur.execute(sql)
      rows = cur.fetchall()

      if len(rows) > 0 and not self.all_functions_matched():
        for row in rows:
          name = row["mangled1"]
          name1 = row["name1"]
          name2 = row["name2"]
          if self.ignore_sub_names and name.startswith("sub_"):
            continue

          # Check the row match
          should_add, ratio = self.check_match(row)
          if not should_add:
            continue

          ea = str(row["ea"])
          name1 = row["name1"]
          ea2 = row["ea2"]
          name2 = row["name2"]
          desc = row["description"]
          nodes1 = int(row["nodes1"])
          nodes2 = int(row["nodes2"])
          md1 = row["md1"]
          md2 = row["md2"]
          if float(ratio) == 1.0 or (
            self.relaxed_ratio and md1 != 0 and md1 == md2
          ):
            the_chooser = "best"
            item = [ea, name1, ea2, name2, desc, 1, nodes1, nodes2]
          else:
            the_chooser = choose
            if ratio + config.MATCHES_BONUS_RATIO < 1.0:
              ratio += config.MATCHES_BONUS_RATIO

            item = [ea, name1, ea2, name2, desc, ratio, nodes1, nodes2]

          self.add_match(name1, name2, ratio, item, the_chooser)
    finally:
      cur.close()
```

**Porting spec.**

```
rows = SELECT DISTINCT SELECT_FIELDS("Perfect match, same name")
       FROM main f x diff df
       WHERE (df.mangled_function = f.mangled_function OR df.name = f.name)   -- SQL '=': NULL never matches
         AND f.name NOT LIKE 'nullsub_%'                                       -- see LIKE semantics below
if rows empty or all_functions_matched(): return     # checked ONCE, before the loop
for row in rows (SQLite order, see below):
    if ignore_sub_names (True) and row.mangled1.startswith("sub_"): continue   # PRIMARY MANGLED name only, case-sensitive
    (ok, r) = check_match(row); if not ok: continue      # nullsub_ / has_best_match / check_ratio / has_better_match / hook
    if r == 1.0 (float compare) or (relaxed_ratio(False) and md1 != 0 and md1 == md2):
        add_match(name1, name2, r, [ea, name1, ea2, name2, "Perfect match, same name", 1, n1, n2], "best")
    else:
        if r + 0.01 < 1.0: r = r + 0.01                  # MATCHES_BONUS_RATIO, config:116; IEEE double add
        add_match(name1, name2, r, [ea, name1, ea2, name2, "Perfect match, same name", r, n1, n2], "partial")
```

- **SQLite `LIKE 'nullsub_%'` semantics** (default `case_sensitive_like=OFF`, no ESCAPE). `_` matches **exactly one character** and matching is **ASCII case-insensitive**. The clause therefore excludes every `f.name` whose length is at least 8 and whose first 7 characters, case-folded in ASCII, are `nullsub`. That includes `nullsubX`, `NULLSUB_2`, `Nullsub_abc` and `nullsub_`. It keeps `nullsub` (7 characters) and `j_nullsub_1`. NULL `f.name` is also excluded. **[verified]** by a direct SQLite test, and in scenario E: `nullsubX↔nullsubX` was *not* matched here, and a later heuristic matched it instead.
- The SQL filter applies to the **primary** name only. `check_match` then drops rows where either `name1` or `name2` starts with the case-sensitive prefix `nullsub_`.
- **`ignore_sub_names` tests `mangled1`**, the primary's raw name, not `name1`. **[verified]**: `prettyname` with mangled `sub_40C000` was skipped by this pass even though `name1 == name2`.
- Usually `name1 == name2`: the join is on `name`, or on the mangled name, which normally demangles identically. Then `add_match` forces the stored `matched_*` ratio to 1.0 and **skips its own** `has_better_match` call (1353-1355). A same-name partial therefore marks both functions as "best-matched" until the next `cleanup_matches`. `check_match` still consults `has_best_match` and `has_better_match(name1, name2, r)` **before** `add_match`. With `name1 == name2`, both non-`sub_` and `name1` already present, the early return gives True exactly when `name1` is already matched to itself.
- If `name1 != name2` (mangled equal but demangled names differ), the normal `has_better_match` path inside `add_match` applies. Whether IDA can demangle the same mangled name differently across the two IDBs is **NOT DETERMINED FROM SOURCE**. On the corpus there are 0 such pairs, and 0 pairs with equal `name` but different `mangled_function` (§19.1).
- A NULL `mangled1` on a row selected via `df.name = f.name` crashes (`None.startswith`). Input contract: `mangled_function` must be non-NULL.
- **[verified] Bonus arithmetic.** Scenario A/C/E partials show `check_ratio = 0.878` and a stored `0.888`. The bonus is skipped exactly when the IEEE-double sum `r + 0.01` is **not** `< 1.0`. `0.99 + 0.01 == 1.0` in doubles, so `r = 0.99` (the `check_ratio` cap, 1771) stays `0.99`. `nextafter(0.99, 0) + 0.01 = 0.9999999999999999 < 1.0`, so that value does get the bonus. "r ≥ 0.99" is therefore only approximately the rule. Port the literal comparison.
- **Corpus evidence.** In `ls-old vs ls` and `ls vs ls-old` the partial `"Perfect match, same name"` rows range from **0.0100000** (`check_ratio` below 5e-8, which is 0 in practice, plus 0.01) to **0.9900000** (the cap without bonus). That confirms both the missing floor and the skip rule on real data.
- **Order.** Observed plan: `SCAN f` (rowid order), then `MULTI-INDEX OR { INDEX 1: SEARCH df USING INDEX idx_3 (mangled_function=?) ; INDEX 2: SEARCH df USING INDEX idx_2 (name=?) }`, then `USE TEMP B-TREE FOR DISTINCT`. Per primary row, diff candidates come first from the mangled-name index (ties in rowid order), then from the name index, with rowids already emitted skipped. DISTINCT only filters. Order decides the winner when a primary name has several diff candidates (for example duplicated demangled names), because `has_better_match` passes ties. See H1 and H2. **The same plan was observed on all 5 real oracle pairs** (§19.1).
- **Corpus.** In `ls-old vs ls`, 8 of the 114 same-name rows have a `sub_…` `mangled1`, and this pass skips them.

**Inputs.** `name`, `mangled_function` (both sides), plus SELECT_FIELDS.

**Outputs.** **best**: ratio `1` (int), description `"Perfect match, same name"`. **partial** (argument `choose` is always `"partial"`, diaphora.py:3624): ratio is `check_ratio + 0.01` (unless that would reach 1.0), same description. **There is no minimum ratio.** A same-name pair with `check_ratio 0.05` is still recorded as partial 0.06.

**Runs by default?** **Yes, on both paths.** diaphora.py:3623-3624 `if not self.ignore_all_names:`, and `ignore_all_names` is forced False in standalone mode (3759-3760). It runs **after** the dirty heuristics, so in a patch-diff session the pass-through hook is already active.

---

## 10. `find_partial_matches`

```python
# diaphora.py:2212-2221
  def find_partial_matches(self):
    """
    Find matches using all heuristics assigned to the 'partial' category.
    """
    self.run_heuristics_for_category("Partial")

    if self.slow_heuristics:
      # Search using some of the previous criterias but calculating the edit distance
      log_refresh("Finding with heuristic 'Small names difference'")
      self.search_small_differences("partial")
```

**Spec.**
1. Run the 30 `category == "Partial"` heuristics through §2.6. The heuristics spec defines them.
   - They execute in reverse list order: `Loop count` (index 41) first, down to `Same named compilation unit function match` (index 12).
   - Skipped by default: indices 36-38 (`Partial pseudo-code fuzzy hash (normal/reverse/mixed)`), which carry `HEUR_FLAG_UNRELIABLE`.
   - Skipped when processors differ: `Same rare assembly instruction` (index 39, `HEUR_FLAG_SAME_CPU`).
   - Kept: `SLOW`-flagged heuristics (14 `Same compilation unit`, 21 `Same rare constant`, 41 `Loop count`), because `slow_heuristics=True`.
   - The step ends with `cleanup_matches()` and `show_summary()`.
2. If `slow_heuristics` is set, run `search_small_differences("partial")` (§11) on the **post-cleanup** state.

**Outputs.** Through the heuristics: **best** and **partial**. Through §11: **best** and **partial**.

**Runs by default?** **Yes, on the normal path** (diaphora.py:3634, inside the `else:` of `if skip_others:`). `search_small_differences` also runs by default, because `slow_heuristics=True` in standalone mode regardless of size (§0.1). **[verified]** in scenarios A and E. On the corpus, every normal-path oracle log contains `Finding with heuristic 'Small names difference'`. `search_small_differences` prints no summary of its own. The next `Current results` line comes after the first iterative-loop step, `Callee found diffing matches assembly`, so the log cannot attribute the partial-count change to this pass alone (sechost 817→822, userenv-nopdb 373→377).

---

## 11. `search_small_differences`

```python
# diaphora.py:2085-2150
  def search_small_differences(self, choose):
    """
    Find matches where most used names are the same.
    """
    cur = self.db_cursor()

    # Same basic blocks, edges, mnemonics, etc... but different names
    name = "Nodes, edges, complexity and mnemonics with small differences"
    sql = (
      """ select """
      + get_query_fields(name)
      + """ ,
           f.names  f_names,
           df.names df_names
        from functions f,
           diff.functions df
         where f.nodes = df.nodes
         and f.edges = df.edges
         and f.mnemonics = df.mnemonics
         and f.cyclomatic_complexity = df.cyclomatic_complexity
         and f.names != '[]' """
    )

    try:
      cur.execute(sql)
      rows = result_iter(cur)
      for row in rows:
        ea = str(row["ea"])
        name1 = row["name1"]
        name2 = row["name2"]

        nodes1 = int(row["nodes1"])
        nodes2 = int(row["nodes2"])

        s1 = set(json.loads(row["f_names"]))
        s2 = set(json.loads(row["df_names"]))
        total = max(len(s1), len(s2))
        commons = len(s1.intersection(s2))
        ratio = (commons * 1.0) / total
        if self.has_better_match(name1, name2, ratio):
          continue

        if ratio >= config.DEFAULT_PARTIAL_RATIO:
          # Check the row match
          should_add, ratio2 = self.check_match(row)
          if not should_add:
            continue

          ratio = ratio2
          ea = str(row["ea"])
          name1 = row["name1"]
          ea2 = row["ea2"]
          name2 = row["name2"]
          desc = row["description"]
          nodes1 = int(row["nodes1"])
          nodes2 = int(row["nodes2"])

          item = [ea, name1, ea2, name2, desc, ratio, nodes1, nodes2]
          if ratio == 1.0:
            the_chooser = "best"
          else:
            the_chooser = choose

          self.add_match(name1, name2, ratio, item, the_chooser)
    finally:
      cur.close()
```

**Porting spec.**

```
for row in (SELECT SELECT_FIELDS(desc), f.names, df.names
            WHERE f.nodes=df.nodes AND f.edges=df.edges AND f.mnemonics=df.mnemonics   -- exact TEXT equality of JSON
              AND f.cyclomatic_complexity=df.cyclomatic_complexity AND f.names != '[]'):  -- NULL f.names excluded
    s1 = set(parse_json_string_array(row.f_names)); s2 = set(parse_json_string_array(row.df_names))
    names_ratio = |s1 ∩ s2| / max(|s1|, |s2|)           # Python float; set semantics on the DECODED strings
    if has_better_match(name1, name2, names_ratio): continue       # uses the NAMES ratio
    if names_ratio >= 0.5:                                           # DEFAULT_PARTIAL_RATIO
        (ok, r) = check_match(row); if not ok: continue              # r = check_ratio (+hook)
        item = [str(ea), name1, ea2, name2, desc, r, int(nodes1), int(nodes2)]
        add_match(name1, name2, r, item, "best" if r == 1.0 else "partial")   # NO lower bound on r
```

- **`names_ratio` is only a gate.** The recorded ratio is `check_ratio`, and **it has no floor**. **[verified] Scenario E:** `lowA↔lowB` share 2 of 3 names (0.667 ≥ 0.5) but have entirely different assembly and different `md_index`. They were recorded as **partial `0.0030000`** with description `"Nodes, edges, complexity and mnemonics with small differences"`. With equal `md_index` the same pair scored 0.603.
- There is **no `all_functions_matched` check, no row cap and no timeout** in this pass. `result_iter` is `fetchmany(1000)` in a loop, which is semantically "all rows".
- `ZeroDivisionError` needs `total = max(len(s1), len(s2)) == 0`. The SQL only excludes an `f.names` spelled exactly `'[]'`, so the error happens when `f.names` is a *different* spelling of an empty list (for example `'[ ]'`) and `df.names` also decodes to an empty set, including the exact `'[]'`. The error is not caught (no `except`), so it aborts `diff()`. Our exporter must write `json.dumps([])` = `'[]'`.
- NULL `df.names` makes `json.loads(None)` raise `TypeError`, which crashes the diff. Input contract: `names` is non-NULL.
- JSON: `names` is written by `json.dumps(sorted_list, ensure_ascii=False)` (default separators `", "`). Parse the elements as strings and compare the decoded values.
- The log calls this pass `"Small names difference"`, but the **description stored in results** is `"Nodes, edges, complexity and mnemonics with small differences"`.
- **Order.** Observed plan (synthetic, and 4 of the 5 real pairs): `SCAN f` (rowid), then `SEARCH df USING INDEX idx_5 (nodes=? AND edges=? AND mnemonics=?)`. `idx_5` is `functions(nodes, edges, mnemonics, names, cyclomatic_complexity, prototype2, indegree, outdegree)` (schema.py:29). Per primary row, diff candidates therefore arrive **in that index's key order** after the three equality columns: `names`, then `cyclomatic_complexity`, `prototype2`, `indegree`, `outdegree`, then rowid. Index keys compare with SQLite's type ordering (NULL < numeric < TEXT < BLOB). Within a type, `names` and `prototype2` (TEXT) use BINARY collation, and `cyclomatic_complexity`, `indegree` and `outdegree` (INTEGER) compare **numerically**, not as text. `cyclomatic_complexity` is also constrained equal by the WHERE clause, so it never reorders emitted rows.
- **The outer side is NOT fixed on real exports (§19.1).** For `userenv-9168-pdb vs userenv-9278-nopdb` the verbatim query runs `SCAN df | SEARCH f USING INDEX idx_5 (…)`. The 4806 rows arrive in **diff** rowid order, with main candidates in main's `idx_5` key order. On the other pairs the rows arrive in main rowid order. **[verified]** by fetching the rows and mapping addresses back to rowids. Selecting only `f.id, df.id` instead of the verbatim column list produced yet another order (a covering-index plan), so even the select list affects the order. This pass is many-to-many (7192 candidate rows for sechost, 5946 for the userenv PDB pair) and the first-come candidate wins ties, so this order is load-bearing (H1).

**Inputs.** `nodes, edges, mnemonics, cyclomatic_complexity, names` (both sides), plus SELECT_FIELDS.

**Outputs.** **best** (r == 1.0) or **partial** (any r < 1.0, including below 0.5). The description is `"Nodes, edges, complexity and mnemonics with small differences"`.

**Runs by default?** **Yes, on the normal path**, through `find_partial_matches` when `slow_heuristics` is set. That flag is True in standalone mode for every size (§0.1).

---

## 12. `apply_machine_learning` / `get_model_ratio` (and the ML term in `deep_ratio`)

```python
# diaphora.py:3551-3555
  def apply_machine_learning(self):
    if ML_AVAILABLE and self.use_trained_model:
      import joblib
      self.classifier = joblib.load(config.ML_TRAINED_MODEL)
      log(f"Using ML classifier {self.classifier}")
```

```python
# diaphora.py:2823-2833 (inside deep_ratio)
      if self.classifier is not None:
        if self.get_model_ratio(main_d, diff_d) == 1:
          score += config.ML_TRAINED_MODEL_MATCH_SCORE
          vfname1 = main_d["name"]
          vfname2 = diff_d["name"]
          nodes1 = main_d["nodes"]
          nodes2 = diff_d["nodes"]
          desc = f"ML {self.classifier}"

          tmp_item = CChooser.Item(ea1, vfname1, ea2, vfname2, desc, ratio + score, nodes1, nodes2)
          self.ml_chooser.add_item(tmp_item)
```

```python
# diaphora.py:3496-3549
  def get_model_ratio(self, main_d, diff_d):
    SELECT_FIELDS = """f.name name1,
       f.nodes nodes1,
       f.edges edges1,
       f.indegree indegree1,
       f.outdegree outdegree1,
       f.cyclomatic_complexity cc1,
       f.primes_value primes_value1,
       f.clean_pseudo clean_pseudo1,
       f.pseudocode_primes pseudocode_primes1,
       f.strongly_connected strongly_connected1,
       f.strongly_connected_spp strongly_connected_spp1,
       f.loops loops1,
       f.constants constants1,
       f.source_file source_file1,
       df.name name2,
       df.nodes nodes2,
       df.edges edges2,
       df.indegree indegree2,
       df.outdegree outdegree2,
       df.cyclomatic_complexity cc2,
       df.primes_value primes_value2,
       df.clean_pseudo clean_pseudo2,
       df.pseudocode_primes pseudocode_primes2,
       df.strongly_connected strongly_connected2,
       df.strongly_connected_spp strongly_connected_spp2,
       df.loops loops2,
       df.constants constants2,
       df.source_file source_file2,
       f.id id1,
       df.id id2,
       f.address ea1,
       df.address ea2 """
    
    sql = f"""select {SELECT_FIELDS}
                from main.functions f,
                     diff.functions df
               where f.address = ?
                 and df.address = ? """
    cur = self.db_cursor()

    ret = 0
    try:
      cur.execute(sql, (main_d["ea"], diff_d["ea"]))
      row = cur.fetchone()
      d = dict(row)
      cmp_data = get_model_comparison_data(dict(row), self.is_same_processor)
      ret = self.classifier.predict(cmp_data)[0]
      if ret == 1:
        debug_refresh(f"ML model predicted {ret} for {main_d['name']} {diff_d['name']}")
    finally:
      cur.close()

    return ret
```

Feature construction (`ml/basic_engine.py`):

```python
# ml/basic_engine.py:35-49, 65-73, 92-103, 106-148, 151-157 (verbatim, abridged to the logic)
DATA_FRAME_FIELDS = [
  'cpu', 'arch', 'ratio', 'nodes', 'min_nodes', 'max_nodes', 'edges',
  'min_edges', 'max_edges', 'pseudocode_primes', 'strongly_connected',
  'min_strongly_connected', 'max_strongly_connected', 'strongly_connected_spp',
  'loops', 'min_loops', 'max_loops', 'constants', 'source_file'
]
FIELDS = ["nodes", "edges", "indegree", "outdegree", "cc",
  "primes_value", "clean_pseudo", "pseudocode_primes", "strongly_connected",
  "strongly_connected_spp", "loops", "constants", "source_file"
]
NUM_FIELDS = ["nodes", "edges", "indegree", "outdegree", "cc",
  "strongly_connected", "loops"
]
def int_compare_ratio(value1 : int, value2 : int) -> float:
  if value1 + value2 == 0:
    val = 1.0
  else:
    val = 1 - ( abs(value1 - value2) / max(value1, value2) )
  return val
def quick_ratio(buf1 : str, buf2 : str) -> float:     # NOTE: this one uses .ratio() on lower-cased lines
  if buf1 is None or buf2 is None or buf1 == "" or buf2 == "":
    return 0
  if buf1 == buf2:
    return 1.0
  s1 = buf1.lower().split('\n')
  s2 = buf2.lower().split('\n')
  seq = SequenceMatcher(None, s1, s2)
  return seq.ratio()
def compare_list(value1 : str, value2 : str) -> float:
  s1 = set( json.loads(value1) )
  s2 = set( json.loads(value2) )
  val = 0.0
  if len(s1) == 0 or len(s2) == 0:
    val = INVALID_SCORE            # -1
  else:
    inter = len(s1.intersection(s2))
    maxs  = len(max(s1, s2))       # max() of SETS uses subset ordering: s2 only if s2 is a proper superset of s1
    val = (inter * 100) / maxs
    val /= 100
  return val
# compare_row(d, same_binary=False): for each field in FIELDS:
#   int,int  -> int_compare_ratio ; str,str -> compare_list if val1.startswith("[") else quick_ratio ;
#   either None -> INVALID_VALUE (-2) ; mixed types -> raise Exception("wut?")
#   NUM_FIELDS also emit min_<f>/max_<f> of the RAW values (None -> -2); "ratio" = sum(field scores)/13
def get_model_comparison_data(d : dict, same_arch : bool) -> pd.DataFrame:
  ret = compare_row(d, False)
  ret.values["cpu"] = same_arch
  ret.values["arch"] = same_arch
  df = pd.DataFrame([ret.values])
  return df.loc[:,DATA_FRAME_FIELDS]
```

**Spec (only if the ML path is ever wanted).**
- When `use_trained_model` is set and sklearn, pandas and joblib import cleanly, `apply_machine_learning` loads `ml/diaphora-amalgamation-model.pkl` (config:207).
- From then on, every `deep_ratio` call adds **+0.15** (`ML_TRAINED_MODEL_MATCH_SCORE`, config:209) when `classifier.predict(features)[0] == 1`.
- Timing matters:
  - The classifier is loaded **after** the Best and Partial heuristics and `search_small_differences` (diaphora.py:3636). It can only influence *later* `check_ratio` calls: the unreliable/experimental passes and the iterative loop.
  - Pairs already in `ratios_cache` are **never re-scored**.
- The `ml_chooser` item is not saved to results.
- The model's decision logic is a pickled sklearn object: **NOT DETERMINED FROM SOURCE**.

**Inputs.** Listed in the SQL above. `primes_value`, `clean_pseudo`, `pseudocode_primes`, `strongly_connected_spp`, `constants` and `source_file` are TEXT. The count fields are INTEGER.

**Outputs.** No chooser. It is a +0.15 ratio bonus inside `deep_ratio`.

**Runs by default?**
- `apply_machine_learning()` is **called** on the normal path (diaphora.py:3636) but **does nothing**, because `use_trained_model=False` (config:205, diaphora.py:412-414). `self.classifier` stays `None`.
- `get_model_ratio` therefore **never runs** (deep_ratio:2823 guard). The C++ port needs no ML for default parity.

---

## 13. `find_unreliable_matches`

```python
# diaphora.py:2313-2321
  def find_unreliable_matches(self):
    """
    Launch unreliable heuristics. Subject to be removed in the near future.
    """
    self.run_heuristics_for_category("Unreliable")
    if self.slow_heuristics and self.unreliable:
      # Find using brute-force
      log_refresh("Brute-forcing...")
      self.find_brute_force()
```

**Spec (non-default).**
- Run the 8 `"Unreliable"` heuristics (indices 42-49) through §2.6, in reverse order (`Topological sort hash` first). Inside this category, **`best` maps to `"partial"` and `partial` maps to `"unreliable"`** (diaphora.py:1510-1512):
  - `HEUR_TYPE_RATIO` gives r == 1.0 → **partial**, 0.5 ≤ r < 1.0 → **unreliable**, and drops r < 0.5.
  - `HEUR_TYPE_RATIO_MAX` with min *m* (`Same graph` 0.5, `Strongly connected components` 0.8) gives r == 1.0 → **partial**, m ≤ r < 1.0 → **unreliable**, and drops anything else.
  - `SLOW`-flagged ones (indices 43-48) also require `slow_heuristics`.
- Then `find_brute_force()` if both `slow_heuristics` and `unreliable` are set.

**Runs by default?** **No.** Called only inside `if self.unreliable:` (diaphora.py:3638-3641), and `unreliable=False` (config:46). **[verified]**: absent from all traces.

---

## 14. `find_brute_force`

```python
# diaphora.py:2223-2305
  def find_brute_force(self):
    """
    Brute force the unmatched functions. This is unreliable at best.
    """
    cur = self.db_cursor()
    sql = "create temporary table unmatched(id integer null primary key, address, main)"
    cur.execute(sql)

    # Find functions not matched in the primary database
    sql = "select name, address from functions"
    cur.execute(sql)
    rows = cur.fetchall()
    if len(rows) > 0:
      sql = "insert into unmatched(address,main) values(?,?)"
      insert_args = []
      for row in rows:
        name = row["name"]
        if name not in self.matched_primary:
          ea = row[1]
          insert_args.append([ea, 1])
      cur.executemany(sql, insert_args)

    # Find functions not matched in the secondary database
    sql = "select name, address from diff.functions"
    cur.execute(sql)
    rows = cur.fetchall()
    if len(rows) > 0:
      sql = "insert into unmatched(address,main) values(?,?)"
      insert_args = []
      for row in rows:
        name = row["name"]
        if name not in self.matched_secondary:
          ea = row[1]
          insert_args.append([ea, 0])
      cur.executemany(sql, insert_args)

    if self.slow_heuristics:
      heur = "Brute forcing (MD-Index and KOKA hash)"
      sql = (
        """select """
        + get_query_fields(heur)
        + """
        from functions f,
            diff.functions df,
            unmatched um
        where ((f.address = um.address and um.main = 1)
          or (df.address = um.address and um.main = 0))
          and ((f.md_index = df.md_index
          and f.md_index > 1 and df.md_index > 1)
          or (f.kgh_hash = df.kgh_hash
          and f.kgh_hash > 7 and df.kgh_hash > 7))
          """
      )
      cur.execute(sql)
      log_refresh("Finding via brute-forcing (MD-Index and KOKA hash)...")
      self.add_matches_from_cursor_ratio_max(
        cur, best="unreliable", partial=None, val=config.DEFAULT_PARTIAL_RATIO
      )

    heur = "Brute forcing (Compilation Unit)"
    sql = (
      """select """
      + get_query_fields(heur)
      + """
         from functions f,
          diff.functions df,
          unmatched um
        where ((f.address = um.address and um.main = 1)
         or (df.address = um.address and um.main = 0))
        and f.source_file = df.source_file
        and f.source_file != ''
        and df.source_file is not null
        and f.kgh_hash > 7 and df.kgh_hash > 7 """
    )
    cur.execute(sql)
    log_refresh("Finding via brute-forcing (Compilation Unit)...")
    self.add_matches_from_cursor_ratio_max(
      cur, best="unreliable", partial=None, val=config.DEFAULT_PARTIAL_RATIO
    )

    if cur.connection.in_transaction:
      cur.execute("commit")
    cur.close()
```

**Porting spec (non-default).**

```
U1 = { m.address : m in main.functions, m.name not in matched_primary }     # post-cleanup state (the run_heuristics
U0 = { d.address : d in diff.functions, d.name not in matched_secondary }   #  for "Unreliable" ended with cleanup)
candidate pairs = { (f, df) : f.address in U1  OR  df.address in U0 }       # OR, not AND: one side unmatched suffices;
                                                                              # a pair with BOTH unmatched is emitted TWICE
if slow_heuristics:
   rows1 = candidate pairs where
           (f.md_index == df.md_index AND text(f.md_index) > '1' AND text(df.md_index) > '1')
        OR (f.kgh_hash == df.kgh_hash AND text(f.kgh_hash) > '7' AND text(df.kgh_hash) > '7')
   add_matches_internal(rows1, best="unreliable", partial=None, val=0.5)    # only r == 1.0 is kept, into UNRELIABLE
rows2 = candidate pairs where f.source_file == df.source_file AND f.source_file != '' (NULL fails)
        AND text(f.kgh_hash) > '7' AND text(df.kgh_hash) > '7'
add_matches_internal(rows2, best="unreliable", partial=None, val=0.5)       # only r == 1.0, into UNRELIABLE
```

- **TEXT comparisons, not numeric.** `md_index` and `kgh_hash` are TEXT columns. Against a bare integer literal SQLite applies TEXT affinity to the literal, so `f.md_index > 1` means `f.md_index > '1'` and `f.kgh_hash > 7` means `> '7'`, both lexicographic.
  - **[verified]** Over the values `0, 0.5, 1, 1.5, 10, 2, 12345, 7, 70, 8, 699999999, 5E-7, ''`, `x > 1` selects `1.5, 10, 2, 12345, 7, 70, 8, 699999999, 5E-7` and `x > 7` selects only `70, 8`.
  - `kgh_hash > 7` accepts only texts that sort after `'7'`: a leading `8` or `9`, a leading `7` followed by more characters, or the literals `'NO-FUNCTION'` and `'NO-FLOW-GRAPH'` (`'N' > '7'`). `kgh_hash` is `str()` of a positive integer product (jkutils/graph_hashes.py:109-180), so a leading `1`-`6` is rejected. On the corpus, 7.2% (`ls`) and 15.4% (`userenv-9168-pdb`) of functions pass `kgh_hash > 7`, and 47% and 64% pass `md_index > 1` (§19.1). The fraction depends on the data, not on the source.
- With `partial=None`, `add_matches_internal` keeps **only ratio 1.0 rows**, and they go to **unreliable** (§2.3: the else-branch is dead).
- `add_matches_from_cursor_ratio_max` has no `SystemExit` handler. A 300 s timeout in this pass kills the process (§2.3.1). The 1,000,000-row cap applies to each query separately.
- The duplicate row for a pair where both sides are unmatched is harmless: the second visit fails `has_best_match`.
- The `unmatched` temp table's `address` column has no declared type (BLOB affinity). The values inserted are Python `str`, which SQLite stores as TEXT, so text = text comparison with `functions.address` holds.
- Row order: the synthetic plan used `MULTI-INDEX OR` over `idx_24 (md_index>?)` and `idx_25 (kgh_hash>?)`. It is plan-dependent (H1). These plans were taken with an **empty** `temp.unmatched`, and at run time that table is populated but still has no `ANALYZE` statistics, so the plan at run time is **NOT DETERMINED** by these measurements. **Real exports vary (§19.1):** the range index is `idx_24` or `idx_27` depending on the pair, and for `ls vs ls-old` the outer `MULTI-INDEX OR` runs over **df**, not f. The Compilation-Unit query flips to `SEARCH df … | SEARCH f USING AUTOMATIC PARTIAL COVERING INDEX` for `userenv-9168-pdb vs userenv-9278-nopdb`.

**Outputs.** **unreliable**, ratio 1.0. Descriptions are `"Brute forcing (MD-Index and KOKA hash)"` and `"Brute forcing (Compilation Unit)"`.

**Runs by default?** **No.** It needs `self.slow_heuristics and self.unreliable` (diaphora.py:2318), and its caller `find_unreliable_matches` itself runs only when `unreliable` is set (3638). `unreliable=False`.

---

## 15. `find_experimental_matches`

```python
# diaphora.py:2307-2311
  def find_experimental_matches(self):
    """
    Run heuristics labeled as experimental.
    """
    self.run_heuristics_for_category("Experimental")
```

**Spec.** `run_heuristics_for_category("Experimental")`. **No heuristic in `HEURISTICS` has `category == "Experimental"`.** Enumerating `HEURISTICS` gives `Counter({'Partial': 30, 'Best': 12, 'Unreliable': 8})`. So the call reduces to `threads_apply` over an empty list, then `cleanup_matches()` and `show_summary()`. Its only observable effect is one extra `cleanup_matches()`, right after `find_unreliable_matches`.

**Outputs.** None, apart from the cleanup.

**Runs by default?** **No.** Called only at diaphora.py:3651, inside `if self.unreliable:` (3638). The `experimental=True` flag gates `apply_dirty_heuristics`, **not** this function.

---

## 16. `get_unmatched_functions`

```python
# diaphora.py:2639-2669
  def get_unmatched_functions(self):
    """
    Get the list of unmatched functions in both databases.
    """
    main = list()
    diff = list()
    cur = self.db_cursor()
    try:
      sql = """select 'main' db_name, name, address from main.functions
        union
         select 'diff' db_name, name, address from diff.functions
    """
      cur.execute(sql)
      rows = cur.fetchall()
      if len(rows) > 0:
        for row in rows:
          name = row["name"]
          d = self.matched_primary
          l = main
          if row["db_name"] == "diff":
            d = self.matched_secondary
            l = diff

          if name not in d:
            ea = row["address"]
            key = [ea, name]
            if key not in l:
              l.append(key)
    finally:
      cur.close()
    return main, diff
```

**Porting spec.**

```
main_unmatched = [ (address_text, name) for m in main.functions if m.name not in matched_primary ]
diff_unmatched = [ (address_text, name) for d in diff.functions if d.name not in matched_secondary ]
each list: de-duplicated on (address, name) and SORTED by (name, address) in SQLite BINARY collation
          (memcmp of UTF-8 bytes; NULL name sorts first; address is decimal TEXT, so "10" < "9")
```

- **Order.** `UNION` is compiled as `UNION USING TEMP B-TREE` and emits rows in the b-tree's key order, `(db_name, name, address)`. **[verified]** by a direct test: all `'diff'` rows come before all `'main'` rows, and within each, uppercase sorts before lowercase (`'Alpha' < 'sub_1'`). This is SQLite implementation behaviour (SQL does not promise it), but it is deterministic for 3.51.1. The `key not in l` check is redundant after `UNION`.
- The `matched_*` state is used **without** a preceding `cleanup_matches`. In the dirty path, the last cleanup was none at all: only `find_equal_matches`, the stripped match and `find_same_name` have written to it. So keys include mangled names from §5 and the fake 1.0 ratios from §2.4.
- A NULL `name` is appended as `None`. On the main side, `search_remaining_functions` crashes on `None.startswith` (2691), but only in a patch-diff session. On the diff side the name is ignored by the loop (`for ea2, _ in …`), but a returned row reaches `check_match`, where `name2.startswith("nullsub_")` crashes. In the stripped case nothing consumes the lists, so no crash. Input contract: `name` is non-NULL. All 7 corpus exports satisfy it.

**Outputs.** Two lists. No chooser.

**Runs by default?** **Only when a dirty heuristic fired.** It is called by `find_remaining_functions` (diaphora.py:2707), which runs only when `skip_others` is set (3626-3627). When it runs, it runs in both the stripped and the patch-diff cases (**[verified]** scenarios B and C). Its result is only consumed when `is_patch_diff` is set.

> Not to be confused with `find_unmatched` (diaphora.py:2323-2356), which builds the output "unmatched" lists after `final_pass`. There, the chooser titled "Unmatched in primary" (holding **main** functions) is stored in `self.unmatched_second`, and vice versa (2334-2354). `save_results` writes `self.unmatched_primary` under type `"primary"` (2414). The saved `unmatched.type` labels are therefore **swapped**. **[verified]** In the first variant of scenario E, where `lowA` and `lowB` stayed unmatched, the row `('primary', …, '0060a000', 'lowB')` is a *diff* function. That belongs to the output spec. It is flagged here only because the names are similar. **Corpus confirmation:** in `userenv-9168-pdb_vs_9278-pdb/run1` all 643 main functions were matched. All 20 `unmatched` rows are typed `'primary'`, and every one of their names exists only in the **diff** export. In `ls-old vs ls` (main 304, diff 318) the counts are `primary 56 / secondary 14`, and in `ls vs ls-old` they are `primary 29 / secondary 46`. Both are consistent with the swap.

---

## 17. `search_remaining_functions`

```python
# diaphora.py:2671-2700
  def search_remaining_functions(self, main_unmatched, diff_unmatched, values):
    """
    Search potentially renamed functions in a usual patch diffing session.
    """
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

    cur = self.db_cursor()
    try:
      for ea1, name1 in main_unmatched:
        if values["only_sub"]:
          if not name1.startswith("sub_"):
            continue

        for ea2, _ in diff_unmatched:
          cur.execute(sql, (values["heur"], ea1, ea2))
          self.add_matches_internal(
            cur, best="best", partial="partial", val=values["val"]
          )
    finally:
      cur.close()
```

**Porting spec** (with the only call site's `values`, §18):

```
for (ea1, name1) in main_unmatched (sorted by name, address):
    if only_sub (True) and not name1.startswith("sub_"): continue          # case-sensitive, PRIMARY name only
    for (ea2, _) in diff_unmatched (sorted by name, address):              # ALL diff leftovers, sub_ or not
        row = SELECT_FIELDS(desc=heur) for f.address==ea1, df.address==ea2
              AND f.nodes >= 3 AND df.nodes >= 3          # because small == False
        if no row: continue
        add_matches_internal([row], best="best", partial="partial", val=0.6)
              # r == 1.0 -> best ; 0.6 <= r < 1.0 -> partial ; else drop
```

- The lists are **snapshots**. They are not updated as matches are made. Only the live `matched_*` dicts, through `check_match` and `add_match`, stop re-use:
  - `has_best_match` blocks a function once it has a 1.0 match.
  - `has_better_match` blocks only a **strictly** better existing ratio.
  - `name1` always starts with `sub_`, so the early-return branch of `has_better_match` never applies.
  - A diff function can therefore be matched to several `sub_` primaries at equal or increasing ratios. Each match appends an item, and multimatch resolution happens in `final_pass`.
- Inner-loop order is the `(name, address)` sort from §16. It decides ties.
- A main `sub_X` can meet a diff function also named `sub_X`. `find_same_name` skipped both, because `ignore_sub_names` tests the primary's mangled name. `add_match` then sees `name1 == name2`, stores the fake 1.0 in `matched_*` (§2.4) and keeps the real ratio in the item.
- Complexity is |main `sub_` leftovers| × |diff leftovers| point queries. A native port should iterate in memory but **keep this exact nested order**.
- There is no `SystemExit` handler, but each call processes at most 1 row, so the timeout is not reachable in practice.

**Inputs.** Addresses from §16, then SELECT_FIELDS for the pair, and `nodes`.

**Outputs.** **best** or **partial**. Description `"Renamed or anonymous function match in patch diffing session"`. Ratio is `check_ratio` with no bonus.

**Runs by default?** **Only in a patch-diff session** (`is_patch_diff`), from `find_remaining_functions`. **[verified] Scenario C.**

---

## 18. `find_remaining_functions`

```python
# diaphora.py:2702-2716
  def find_remaining_functions(self):
    """
    After using a dirty heuristic doing patch diffing try to find the remaining
    functions, if any.
    """
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

**Spec.** Always compute both leftover lists (§16). If `is_patch_diff`, run §17 with `only_sub=True`, `small=False` (so `nodes >= 3` on both sides) and `val=0.6` (`SPEEDUP_PATCH_DIFF_RENAMED_FUNCTION_MIN_RATIO`, config:172). **In the stripped-binaries case this does nothing beyond the query**, because `is_patch_diff` stays False: the patch-diff check is short-circuited (§6).

**Runs by default?** **Only when `skip_others` is set** (diaphora.py:3626-3627), meaning a dirty heuristic fired.

---

## 19. Empirical verification performed for this spec

Everything ran against the **unmodified** reference, imported read-only with `sys.dont_write_bytecode = True` from scratch scripts outside the repo. Tracing was done by monkeypatching methods in the harness process. Environment: Python 3.13.12, SQLite 3.51.1, and no `DIAPHORA_*` variables. Synthetic exports were built with `db_support.schema.TABLES`, all `schema.INDICES` as `idx_{i}`, and `ANALYZE`, as a real export has.

| Scenario | Shape | Observed |
|---|---|---|
| A normal | 20 + 1 functions, shifted addresses, 10 named + 10 `sub_`, 2 bodies modified, plus 1 small-diff pair | Normal path. `find_same_name` gave 8 best and 2 partial at 0.888. Best heuristics added the `sub_` ones ("Equal assembly"). `search_small_differences` added `alpha_x↔beta_y` partial 0.653. |
| B stripped | same addresses; diff names `sub_…` | Stripped fired: 19 best and 1 partial (0.878). No heuristics ran afterwards. |
| C patch | 19 of 20 mangled names shared; 1 renamed `sub_` | Patch fired and hooks loaded. `find_same_name` gave 18 best and 1 partial. `search_remaining_functions` added `sub_403000↔renamed_fn` partial 0.878. |
| D equal + mangled | same ids, `name != mangled` | 17 "100% equal" items keyed by mangled name, duplicated by same-name items. `matched_primary` had 37 keys for 20 functions. The final best rows are the "100% equal" ones and `line` has gaps. |
| E normal quirks | `nullsubX`, `prettyname` with mangled `sub_…`, low-ratio small-diff pair | `nullsubX` and `prettyname` were skipped by `find_same_name` and matched later by "Mnemonics and names". `lowA↔lowB` recorded as partial **0.003**. The first variant of E, where 21 of 23 mangled names matched, took the patch path instead; it showed the swapped unmatched `type` labels. |

The heuristic execution order is reversed: the thread names were recorded in the order `Microcode mnemonics small primes product → … → Same RVA and hash`, then `Loop count → … → Same named compilation unit function match`.

Observed `EXPLAIN QUERY PLAN` output on the synthetic pair (3000 and 3100 functions, with indices and `ANALYZE`):

| Query | Plan |
|---|---|
| equal (§5) | `COMPOUND QUERY; SCAN functions; INTERSECT USING TEMP B-TREE; SCAN diff.functions; SCAN x` |
| same name (§9) | `SCAN f; MULTI-INDEX OR {SEARCH df USING INDEX idx_3 (mangled_function=?); SEARCH df USING INDEX idx_2 (name=?)}; USE TEMP B-TREE FOR DISTINCT` |
| small diff (§11) | `SCAN f; SEARCH df USING INDEX idx_5 (nodes=? AND edges=? AND mnemonics=?)` |
| stripped count and rows (§7) | `SCAN f USING [COVERING] INDEX idx_28; SEARCH df USING [COVERING] INDEX idx_28 (address=?)` (+ `USE TEMP B-TREE FOR DISTINCT`) |
| patch count (§8) | `SCAN f USING COVERING INDEX idx_3; SEARCH df USING COVERING INDEX idx_3 (mangled_function=?)` |
| unmatched (§16) | `COMPOUND QUERY; SCAN main.functions; UNION USING TEMP B-TREE; SCAN diff.functions` |
| remaining (§17) | `SEARCH f USING INDEX idx_28 (address=?); SEARCH df USING INDEX idx_28 (address=?)` |
| brute MD/KOKA (§14) | `MULTI-INDEX OR {idx_24 (md_index>?), idx_25 (kgh_hash>?)} on f; MULTI-INDEX OR {idx_27 (md_index=?), idx_25 (kgh_hash=?)} on df; SCAN um` |
| brute CU (§14) | `SEARCH f USING INDEX idx_25 (kgh_hash>?); SCAN um; SEARCH df USING AUTOMATIC PARTIAL COVERING INDEX (source_file=?)` |

### 19.1 Measurements on the real IDA oracle corpus (added during verification)

**Setup.**
- Corpus: `<corpus>/oracle/exports/<id>/<id>.sqlite`. These are real exports made by Diaphora's own exporter under IDA 9.4 idalib (see `tools/oracle/README.md` and `manifest.json`).
- Access: every export was opened read-only (`file:…?mode=ro`, with `diff` attached the same way), under Python 3.13.12 / SQLite 3.51.1.
- Query text: the verbatim SQL, built with `diaphora_heuristics.get_query_fields` imported with `-B` (no bytecode written).
- Integrity: the SHA-256 of all exports was identical before and after. `git status` in `diaphora-ref` stayed clean.
- Scratch scripts are in a scratch directory (`plans.py`, `ord2.py`, `dirty.py`, `names.py`, `res.py`, `unm.py`).

**Plans** (`EXPLAIN QUERY PLAN`, verbatim SQL):

| Query | ls-old→ls | ls→ls-old | sechost pdb→nopdb | userenv pdb→nopdb | userenv pdb→pdb |
|---|---|---|---|---|---|
| equal (§5) | synthetic plan | same | same | same | same |
| stripped count/rows (§7) | `SCAN f idx_28 / SEARCH df idx_28` | same | same | **`SCAN df idx_28 / SEARCH f idx_28`** | `SCAN f / SEARCH df` |
| patch count (§8) | `SCAN f idx_3 / SEARCH df idx_3` | same | same | **`SCAN df / SEARCH f`** | `SCAN f / SEARCH df` |
| same name (§9) | synthetic plan | same | same | same | same |
| small diff (§11) | `SCAN f / SEARCH df idx_5` | same | same | **`SCAN df / SEARCH f idx_5`** | `SCAN f / SEARCH df idx_5` |
| unmatched (§16) | `UNION USING TEMP B-TREE` | same | same | same | same |
| remaining (§17) | `SEARCH f idx_28; SEARCH df idx_28` | same | same | same | same |
| brute MD/KOKA (§14) | outer f via `idx_27`/`idx_25` | **outer df** via `idx_27`/`idx_25` | outer f via `idx_24`/`idx_25` | outer f `idx_27`, df `idx_24` | outer f `idx_27`, df `idx_24` |
| brute CU (§14) | `SEARCH f idx_25; SCAN um; AUTOMATIC idx on df` | same | same | **roles of f/df swapped** | same as first |

**Dirty-heuristic percentages and path taken:**

| Pair (main→diff) | total1 | stripped % | patch % | path | `find_equal_matches` rows |
|---|---|---|---|---|---|
| ls-old→ls | 304 | 2.961 | 37.500 | normal | 0 |
| ls→ls-old | 318 | 2.830 | 35.849 | normal | 0 |
| sechost-9168-pdb→9444-nopdb | 1442 | 61.234 | 15.811 | normal | 4 |
| userenv-9168-pdb→9278-nopdb | 643 | 4.666 | 9.331 | normal | 0 |
| userenv-9168-pdb→9278-pdb | 643 | 4.821 | 100.000 | **patch diff** (log confirms) | 0 |

The stripped path fires on none of these pairs. `same_processor_both_databases()` is True for all five (`pc64`).

**Per-export facts** (all 7 exports):
- 0 NULL `name`, `mangled_function`, `nodes`, `names`, `md_index` or `address` values.
- Every address is canonical decimal text.
- No empty or leading-space assembly lines.
- 0 names matching `nullsub_%`.
- Exactly one `program` row each.
- **0 duplicated `name` values and 0 duplicated `mangled_function` values** in any export.
- `name != mangled_function` for 772 (sechost-9168-pdb), 393 (userenv-9168-pdb) and 411 (userenv-9278-pdb) functions, and for 0 in the no-PDB and ELF exports.
- `callgraph_primes` is stored in scientific notation (for example `1.258765552879565110995976484E+366`).

**Oracle results** (`diffs/<pair>/run1`, finished pairs only; the sechost and userenv-nopdb runs were still in progress, owned by another process, and were not touched):
- `determinism.json` reports identical results in order across two runs for all three finished pairs.
- The best-category `line` values have no gaps in any of them.

---

## Hard parts

**H1. Row order of un-ordered SQL decides ties.** `find_same_name`, `search_small_differences`, the stripped pass and `find_brute_force` feed order-sensitive bookkeeping: first-come wins because `has_better_match` passes ties, and the stable sort in `cleanup_matches` keeps insertion order. None of these queries has `ORDER BY`. Their order is whatever SQLite 3.51.1 picks from the 41 `idx_*` indices and the `ANALYZE` statistics of the specific exports. Options:
- **(a) Required for parity, as measured on the real corpus.** Run the **verbatim SQL text, including the verbatim select list**, through the linked SQLite on the same two files, with `diff` attached under the alias `diff`, the main DB as `main`, and no extra indices or `ANALYZE`. Keep the input files unmodified: adding indices or stats changes plans.
- **(b) Native hash joins with one fixed plan order: rejected.** §19.1 shows the planner choosing a different outer table for the stripped, patch-count and small-diff queries on `userenv-9168-pdb vs userenv-9278-nopdb`, and different indices and outer sides for brute force across pairs. For small-diff this changes the row order the tie-breaking depends on. Changing only the select list also changed the order. A native reimplementation would have to replicate SQLite's cost-based planner decisions per pair. If (b) is ever attempted, it must at least branch on `EXPLAIN QUERY PLAN` output at run time.

Also pin SQLite 3.51.1 for parity tests. CI's vcpkg `sqlite3.dll` may be a different version and choose different plans. **Open:** whether vcpkg's version picks the same plans on the corpus has not been measured.

**H2. Bookkeeping keyed by name, not address.**
- `matched_primary` and `matched_secondary` are keyed by `functions.name`, except that `find_equal_matches` keys by `mangled_function`.
- Duplicate demangled names (possible whenever `name` is a demangled short name) cross-talk in `has_best_match` and `has_better_match`.
- `mangled != name` produces duplicate best items for the same `(ea1, ea2)`. It also lets the dict sizes exceed the function counts, so `all_functions_matched()` (an equality test) never fires.
- The `cleanup_matches` dedup key is the string `name1-name2`.

Replicate all of this literally. Do not "fix" it to address keys.

**Corpus exposure (§19.1).**
- There are 0 duplicate `name` and 0 duplicate `mangled_function` values in all 7 exports, so the collision cross-talk is **not exercised** by the current corpus.
- The `name != mangled_function` split **is** present, in 393 to 772 functions per PDB export. `find_equal_matches` found 0 rows on the PDB-to-PDB pair, though, so the duplicate-item effect of scenario D does not show up in the current oracle results either.
- Synthetic tests remain the only coverage for these paths.

**H3. The `has_better_match` early return** (both names non-`sub_` and `name1` already matched means "return whether `name1` is matched to itself") silently ignores ratios. It interacts with the fake 1.0 ratio that `add_match` stores for equal names.

**H4. SQLite semantics that a native port must emulate:**
- `TEXT > integer-literal` is a lexicographic text comparison (`md_index > 1`, `kgh_hash > 7`).
- `LIKE 'nullsub_%'` is ASCII-case-insensitive and treats `_` as a single-character wildcard.
- `INTERSECT` treats NULLs as equal.
- `UNION` output is sorted by `(db_name, name, address)` in BINARY collation.
- `=` never matches NULL.
- Addresses are decimal **text**, so text equality is used, not integer equality.

**H5. `search_small_differences` has no ratio floor** (recorded partial 0.003). `find_same_name` has none either (partial is `check_ratio + 0.01`). Porting code that assumes "partial means ≥ 0.5" is wrong for both.

**H6. The dirty-heuristic switch** changes the entire pipeline. The stripped test is inclusive (`>= 99.0`) and uses address matches over main count. The patch test is strict (`> 90.0`) and uses *pair* counts over main count. Both divide by `total_functions1` (a crash when it is 0). Floating-point percent must match Python's true division.

**H7. Non-reproducible limits.**
- 300 s per `add_matches_internal` call: some wrappers swallow the timeout and keep partial results, while others exit the process.
- 1,000,000 rows fetched per call.
- A parity harness must flag oracle runs that hit either limit (log `Timeout with heuristic` or `Processed 1000000 rows...`, printed every 50,000 rows).
- A main-thread timeout (`find_brute_force`, `search_remaining_functions`) exits with status 0 and writes no output (§2.3.1).
- **These limits are within reach on the corpus.** At verification time the live `sechost-9168-pdb vs 9444-nopdb` oracle run was logging `Processed 700000 rows...` inside the iterative-loop pass `Related compilation unit`. That pass is outside this doc's scope but goes through the same `add_matches_internal` cap. In the same run the Partial heuristics `Same rare constant`, `Same address and rare constant` and `Same KOKA hash and constants` each ran for 66 to 74 s, against the 300 s limit.

**H8. `check_ratio` is stateful.** The per-`"ea1-ea2"` cache spans the whole run, and the ML bonus, if ever enabled, only affects pairs first scored after `apply_machine_learning`. Pass order therefore affects ratios. It is also bit-sensitive: the 7-dp rounding goes through `float("{0:.7f}".format(v))`, the `+0.01` bonus is IEEE double addition, and `deep_ratio` accumulates `0.001` increments in a specific order. Replicate that order.

**H9. Input contracts the Python oracle silently depends on**, where a violation makes it crash rather than differ:
- Exactly one `program` row per DB, with parsable `callgraph_primes` and `callgraph_all_primes`.
- Non-NULL `name`, `mangled_function`, `nodes` and `names`.
- Non-NULL `md_index`: `float(None)` in `check_ratio`, diaphora.py:1672-1673.
- Non-NULL `constants` on the main side, and on the diff side whenever main's is not `'[]'` (`json.loads`, 2812-2814).
- `functions.address` as canonical decimal text (`int()` at 1935 and 2763, then re-lookup by `str(int(ea))` at 2774-2778).
- `'[]'` exactly for empty JSON lists.
- `assembly` lines never empty or starting with a space (needed for the patch-diff hook).
- A `diff.version` table with one row. Otherwise `diff()` returns False and an **empty but valid** results file is written with exit status 0 (§1.2).
- At least one main function (`total_functions1 > 0`). Otherwise `ZeroDivisionError` in `search_just_stripped_binaries`.

All 7 corpus exports satisfy every item that could be checked by query (§19.1).

Our C++ exporter must honour all of these if its exports are to be used as oracle inputs.

## Open questions

1. **Real-export query plans. RESOLVED by measurement (§19.1), not from source.** The answer is **no, not in general**. On the 5 corpus pairs, the equal, same-name, unmatched and remaining queries use the synthetic plans on every pair. The stripped, patch-count and small-diff queries flip their outer table for `userenv-9168-pdb vs userenv-9278-nopdb`. For stripped this leaves the row order unchanged (equality join on address). For small-diff it changes the order, and so the tie-breaking. Brute-force plans differ across pairs in index choice and outer side, and were measured with an empty temp table, so their run-time plan is still not determined. Consequence: H1 option (a) is required.
2. **Duplicate demangled names.** Whether IDA's `demangle_name(true_name, INF_SHORT_DN)` (diaphora_ida.py:2452) can map distinct functions to the same short name is IDA behaviour, **NOT DETERMINED FROM SOURCE**. **Measured:** 0 duplicate `name` values in all 7 corpus exports, including the PDB ones with 393 to 772 demangled names. So H2's collision paths are not exercised by the current corpus.
3. **What the parity comparison should include.** This is a **decision, NOT DETERMINED FROM SOURCE**. Facts that bear on it:
   - `line` is the chooser's running counter `"%05lu" % self.n` (diaphora.py:285, 296). It is incremented for every `add_item`, including items that `insert or ignore` (2406) later drops. Only a literal port reproduces such gaps.
   - The three finished corpus runs have no best-category line gaps and are identical in order across two runs (`determinism.json`).
   - Suggested harness: compare primarily as a set keyed by `(type, address, address2)` with `name`, `name2`, `ratio`, `nodes1`, `nodes2` and `description` as values, then compare `line`/row order as a secondary, stricter check.
4. **Non-default paths.** Whether parity is required is a **scope decision, NOT DETERMINED FROM SOURCE**. The source shows none of them runs by default (§12-§15). The ML model's decision logic (`ml/diaphora-amalgamation-model.pkl`) is **NOT DETERMINED FROM SOURCE**.
5. **Oracle timeouts and the row cap.** How to treat them is a **harness decision**. The source facts:
   - Worker-thread timeouts log `Timeout with heuristic '<name>'` and silently keep partial results.
   - Main-thread timeouts exit with status 0, write no output and leave any stale output in place (§2.3.1).
   - The row cap is silent apart from the `Processed 1000000 rows...` line.
   - Recommendation unchanged: mark those runs non-comparable, and always run the oracle into a fresh output path. §H7 shows these limits are reachable on the sechost pair.
6. **Output labels.** The swap is **confirmed from source** (diaphora.py:2334-2354, 2414-2415) **and on the corpus** (§16 note). Whether to reproduce it is an output-spec decision, NOT DETERMINED FROM SOURCE. For byte-level parity with the oracle's `unmatched` table the swap must be reproduced.

---

## Verification log

Adversarial verification pass. Each claim, excerpt and line number was checked against `<diaphora-ref>` (tag 3.4.2 + 4 commits, `git status` clean before and after). SQLite behaviour was re-tested in a scratch in-memory database. Plan, order and data claims were measured read-only on the real IDA oracle corpus (`<corpus>/oracle`, SHA-256 of the exports unchanged). No file other than this one was edited.

**Corrections (errors found and fixed in place):**
1. **Summary, item 3.** The doc said the dirty heuristics "skip every later heuristic / everything later". In fact `find_same_name`, `find_remaining_functions` and `final_pass` still run (diaphora.py:3623-3627, 3677). The thresholds were also restated precisely: address matches ≥ 99% of `total_functions1`, and mangled-name *pair* count > 90% of `total_functions1`.
2. **Summary and §1.1.** `equal_db()` (3600, body 661-687) was missing from the pass list. It is log-only.
3. **§0 item convention.** The doc said ratio is int `1` only in `find_equal_matches` and the `find_same_name` best branch, and "everywhere else it is a float". Wrong on two counts: `add_matches_from_query` also stores int `1` (2074), and `check_ratio` can return the int `0` (1685, 1699, 1755-1771, 2766). Checked in Python: `max(set([0, 0.0, 0, 0.0, 0.0]))` is an `int`. It is harmless for output.
4. **§1 excerpt.** It was labelled "verbatim, comments trimmed only where marked", but blank lines and comment lines 3658-3659, 3663 and 3668 had been removed without a mark. Relabelled as abridged.
5. **§1.2 (new).** Added:
   - `equal_db` and `same_processor_both_databases`.
   - The early `return False` paths (3583, 3588, 3610) still lead to `save_results` (3773), which writes an empty but valid results file and exits 0.
   - `create_schema()` side effects on the main DB (615-632).
6. **§2.1.** Line range `diaphora_heuristics.py:50-84` corrected to 51-84 (line 50 is a comment). Added that a NULL `md_index` crashes `check_ratio` at 1672-1673.
7. **§2.3.** The claim that `add_matches_from_query_ratio_max_trusted`'s documented intent "is not what the code does" was wrong. The intent is met through `val=min` in the `r >= val` branch; only the `unreliable=` argument is inert. Added the canonical-decimal-address contract (`int(ea)` at 1935, and the `deep_ratio` re-lookup at 2763-2778).
8. **§2.3.1.** Added: `raise SystemExit()` exits with **status 0**, and a stale output file survives because only `save_results` deletes it (2379-2381).
9. **§2.4 and §2.5 excerpts.** Presented as whole line ranges while omitting docstrings, comments and debug bodies; relabelled as abridged. Added the `dones`-before-`ea_ratios` ordering (1583 vs 1587).
10. **§2.6.** Added: the "Finding with heuristic" log lines are in forward order while execution is reversed. `get_queries_postfix`'s return value is discarded (1475).
11. **§2.7.** Added the NULL-equality bonuses in `deep_ratio` and the `json.loads(None)` crash (2792-2821).
12. **§2.8.** The `functions.address` evidence was imprecise: `get_valid_prop` (724-728) keeps small ints as ints and only stringifies ints above 0xFFFFFFFF; TEXT affinity does the rest. Added the `mnemonics` ordering (diaphora_ida.py:2852), `cls=CBytesEncoder`, and the corpus confirmation of the 41 `idx_*` indices and `sqlite_stat1` in all 7 exports.
13. **§3.** Stated the grep scope (all `.py` files). Added that `Warning(msg)` is constructed but never raised, and that the `factor.py` excerpt omits docstrings.
14. **§5.** Added that the `len(rows) != 2` guard is dead, and the corpus facts (0 to 4 equal rows; 393 to 772 `name != mangled` functions per PDB export).
15. **§7.** Added the real-export join flip (`SCAN df` for the userenv PDB-to-no-PDB pair) and explained why it leaves the row order unchanged. Added the `ZeroDivisionError` at `total == 0`.
16. **§8.** "Runs by default?" corrected to say the threshold compares a *pair* count, not "functions with a partner". Added corpus evidence: patch-diff fires for userenv PDB-to-PDB, and the log lines are quoted.
17. **§8.3.**
    - The claim that `GetDisasm()` lines "never start with a space" is IDA behaviour, now marked **NOT DETERMINED FROM SOURCE**. The `get_disasm` fallback (diaphora_ida.py:2440-2446) *can* start with spaces.
    - Line range corrected to 2593 and 2708-2726.
    - Crash mechanics refined: the header lines pre-set `removed`, and `mnem2` only fails when `mnem1` starts with `b`. The `IndexError` was reproduced with the real script.
    - Added that `load_hooks()`'s return value is ignored (2619).
18. **§9.**
    - "`has_better_match` is not consulted for these rows" was wrong. It **is** consulted in `check_match` (1865); only `add_match` skips it when the names are equal.
    - The bonus rule "r ≥ 0.99" replaced by the exact IEEE condition (`0.99 + 0.01 == 1.0`, `nextafter(0.99, 0) + 0.01 < 1.0`).
    - Added corpus evidence: partial same-name ratios span 0.0100000 to 0.9900000.
    - Added: the plan is identical on all 5 real pairs, 8 `sub_` mangled rows are skipped in the ls pair, and "mangled equal implies equal demangling" is NOT DETERMINED FROM SOURCE (0 counter-examples on the corpus).
19. **§10.** Added corpus log evidence, with the caveat that the log cannot attribute the count change to this pass alone.
20. **§11.**
    - The `ZeroDivisionError` condition ("`'[ ]'` on both sides") was wrong. It needs a non-`'[]'` empty spelling in `f.names` plus any empty `df.names`.
    - "All TEXT/BINARY comparisons" for the `idx_5` key order was wrong: `cyclomatic_complexity`, `indegree` and `outdegree` are INTEGER and compare numerically. `cyclomatic_complexity` is pinned equal by the WHERE clause.
    - Measured on real data: the verbatim query's outer table **flips to `df`** for userenv PDB-to-no-PDB. Rows then arrive in diff-rowid order (verified by fetching rows). Changing only the select list changed the order again.
21. **§14.**
    - "`kgh_hash > 7` rejects most real hashes" was a data claim stated as fact. It is now qualified with the exact lexicographic rule and corpus fractions: 7.2% and 15.4% pass `kgh > 7`; 47% and 64% pass `md_index > 1`.
    - Plan variation across pairs added (index `idx_24` vs `idx_27`; outer side flips for ls→ls-old).
    - Added that the measured plans used an empty temp table, so the run-time plan is NOT DETERMINED.
22. **§16.** The NULL-name crash was refined to say which side crashes and when. Added the corpus confirmation of the swapped `unmatched.type` labels: in userenv PDB-to-PDB, all 20 `'primary'` rows are diff-only names.
23. **§17.** Added the `sub_X` ↔ `sub_X` equal-name case.
24. **§19.1 (new).** Real-corpus plan table, dirty-heuristic percentages and paths, per-export input-contract checks, and determinism facts.
25. **H1.** Option (b), native joins with one fixed plan order, is now rejected on measured evidence. The select list must be verbatim too. vcpkg-SQLite plan parity is flagged as unmeasured.
26. **H2, H7, H9.** Added corpus exposure. Added the main-thread timeout's exit-status-0 behaviour and the corpus evidence that row counts of 700k+ and heuristic runtimes of 66 to 74 s occur. Added contracts: non-NULL `md_index` and `constants`, canonical decimal `address`, a `diff.version` row, `total_functions1 > 0`.
27. **Open questions.** Q1 resolved by measurement (no, plans differ). Q2 remains NOT DETERMINED FROM SOURCE, with a corpus count of 0 duplicates. Q3, Q4 and Q5 are decisions, now annotated with the source facts. Q6: the swap is confirmed from source and corpus; reproducing it is a decision.

**Confirmed correct (no change needed):**
- The §0.1 configuration table: every line and config reference.
- The `get_value_for` string quirk.
- `MIN_FUNCTIONS_TO_DISABLE_SLOW` is IDA-only (diaphora_ida.py:3799 is its only use).
- The nesting of `find_experimental_matches` inside `if self.unreliable:` (no tabs in 3603-3677).
- `check_match` logic.
- The `add_matches_internal` three-way rule and its dead unreliable branch.
- The `has_better_match` early return.
- `cleanup_matches` semantics.
- Reverse execution order through `targets.pop()`.
- Every heuristic index, category and flag cited: re-enumerated as `Counter({'Partial': 30, 'Best': 12, 'Unreliable': 8})`; UNRELIABLE flag on 36-38, SAME_CPU on 39, SLOW on 14/21/41 and 43-48.
- `get_callgraph_difference` and `difference()`.
- `is_auto_generated` call sites (diaphora_ida.py:1889, 1908 only).
- The `find_equal_matches` SQL, INTERSECT NULL-equality and ascending-id order (re-tested).
- The stripped and patch SQL and thresholds (`>= 99.0`, `> 90.0`, config:160/166/172/186).
- The `find_same_name` SQL and `LIKE 'nullsub_%'` semantics (re-tested, NULL excluded).
- The `search_small_differences` SQL and its missing ratio floor.
- The ML code paths and the default no-op.
- The brute-force SQL and TEXT-affinity comparisons (re-tested).
- No `"Experimental"` heuristic exists.
- The `get_unmatched_functions` UNION order (re-tested).
- `search_remaining_functions`, `find_remaining_functions` and the swapped labels (2334-2354, 2414-2415).
- The environment:
  - Python 3.13.12, SQLite 3.51.1 (the Python module and `Library/bin/sqlite3.exe`).
  - joblib 1.5.3, sklearn 1.8.0, pandas 3.0.3.
  - No `cdifflib`.
  - `build/CMakeCache.txt` links `miniconda3/Library/lib/sqlite3.lib`.
  - No `DIAPHORA_*` environment variables.

**Not independently re-run:** the numbers from synthetic scenarios A to E (0.603, 0.003, 0.878→0.888, 37 keys, the `00016→00034` line jump) and the synthetic plan table in §19. The original scratch scripts were not available. Each figure is consistent with the source as traced above, and the real-corpus results independently confirm the missing floor for same-name partials, the 0.99 cap, and the swapped labels.
