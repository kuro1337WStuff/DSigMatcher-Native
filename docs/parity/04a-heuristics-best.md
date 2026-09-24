# 04a: Heuristic runner, Best heuristics and the first Partial heuristics

> **Historical spec.** Written on 2026-09-23 against an earlier revision (`34ed418`), before the port existed; its status remarks ("not implemented", test counts, runs "still running", open questions) are historical. See [README.md](README.md) in this directory for how to read it; quoted Diaphora code is (c) Joxean Koret, AGPL-3.0-or-later, and quoted CPython `difflib` code is under the PSF License Version 2.

## Summary

- **Scope.** This spec covers `run_heuristics_for_category` (`diaphora.py:1461-1553`) and everything it calls to turn SQL rows into matches: the dispatch functions, `check_match`, `add_match`, `cleanup_matches` and the `threads_apply` scheduler. It also covers the heuristic record format and all 28 heuristics from **Same RVA and hash** (H01) through **Mnemonics small-primes-product** (H28), which is 12 Best and 16 Partial. The last section compares our `src/Heuristics.cpp`, which implements 12 of them, against Diaphora.
- **Biggest findings, all verified by source and experiment:**
  1. Diaphora runs each category's heuristics **in reverse definition order**, because `threads_apply` uses `targets.pop()`. Outside IDA it runs them strictly one at a time, since `cpu_count` is forced to 1. So in the Best pass, *Same RVA and hash* runs **last**.
  2. The category a match lands in (best, partial or dropped) comes from the **per-pair ratio** (`check_ratio` + `deep_ratio`), **not from the heuristic's category**. "Best" heuristics produce partial matches. "Partial" heuristics produce best matches when r == 1.0.
  3. Acceptance is a **stateful, order-dependent** process. It is keyed by function **name** (except the "100% equal" pre-pass, which keys by `mangled_function`, see §1.4) and has several quirks (`has_better_match`, `add_match`). The row order that SQLite emits therefore changes the result. That order is the query-plan order **of the exact SQL text**. It depends on indices and `ANALYZE` stats, and our hash joins cannot reproduce it. On real exports, removing the `ORDER BY` or the `DISTINCT` from a query changes its plan, so even the "unordered" order is not a usable proxy (§6.4).
  4. With default settings, `apply_dirty_heuristics` **skips the whole runner** when `count(join rows with f.address = df.address) * 100 / total_functions1 >= 99.0`, or when the same count over `f.mangled_function = df.mangled_function` is `> 90.0`. **Confirmed on a real export pair:** the oracle diff `userenv-9168-pdb` vs `userenv-9278-pdb` logged `Patch diffing detected: A total of 643 matches out of 643, 100.0% percent have the same name` and never logged `Finding best matches...`. A PDB-vs-PDB patch-diff corpus (such as `win32u` with both PDBs) is therefore expected to produce **no** results from these heuristics. The PDB-vs-no-PDB oracle pairs do run the runner.
  5. `kgh_hash != 0`, `md_index > 0` and `microcode_spp != 1` are **TEXT comparisons** against `'0'` / `'1'`, because of type affinity. They are not no-ops. An earlier note claimed `kgh_hash != 0` "does nothing"; that is wrong.
- **Recommendation for exact parity.** Execute the verbatim SQL through the linked SQLite. Conda ships 3.51.1, the same library Python's `sqlite3` uses here. Run it on a connection to db1 with db2 attached `as diff`, leaving `pragma threads` at its default 0. Re-implement only the Python row-processing state machine in C++. The native hash-join path can then be validated against this replay path. The verification pass on real IDA exports strengthened this recommendation: stripping `ORDER BY`/`DISTINCT` changes the join plan (§6.4), and SQLite's `cast(md_index as real)` is not always correctly rounded (§2.3).

---

## 0. Provenance and how the claims were checked

- Reference tree: `<diaphora-ref>`. `git describe` gives `3.4.2-4-g621ec26`. The 4 commits after the tag touch only `README.md` and `diaphora_ida.py` (`git diff --stat 3.4.2..HEAD`), so `diaphora.py`, `diaphora_heuristics.py`, `diaphora_config.py` and `jkutils/threads.py` are identical to tag 3.4.2.
- Python is `<conda>/python.exe` 3.13.12 with SQLite **3.51.1**. The conda `Library/include/sqlite3.h` that our CMake build uses is also 3.51.1 (`#define SQLITE_VERSION "3.51.1"` at line 153). cdifflib is absent, so the `diaphora.py:41-49` fallback to stdlib `difflib.SequenceMatcher` applies.
- **Experiments.** I built synthetic exports with Diaphora's own `db_support/schema.py` `TABLES` + `INDICES`, followed by `analyze`, exactly as `create_indices` (`diaphora.py:634-649`) does. I ran `python diaphora.py db1 db2 -o out.diaphora` on them, plus instrumented runs that monkeypatch `add_match` at runtime, and raw SQL probes. The scripts live in a scratch directory and are not committed. Their results are quoted where used. No tracked file in `diaphora-ref` was modified (`git status` is clean). The first run may have refreshed git-ignored `__pycache__` entries; later runs used `-B`.
- **Real exports (added by the verification pass).** IDA 9.4 exports now exist under `<corpus>/oracle/exports/` (`ls`, `ls-old`, `userenv-9168-pdb`, `userenv-9278-nopdb`, `userenv-9278-pdb`, `sechost-9168-pdb`, `sechost-9444-nopdb`), with Diaphora's own diff logs under `oracle/diffs/`. The `.sqlite` files were copied to a scratch directory and every probe ran on the copies (read-only URIs for raw SQL; an in-process `CBinDiff` run with `-B` for the instrumented checks). Every export has 41 `idx_*` indices and a `sqlite_stat1` table. Results from these copies are marked **real exports** below.

---

## 1. Where the runner sits in `diff()` and when it runs at all

### 1.1 Call order (`diaphora.py:3612-3651`)

```python
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
            ...
            log_refresh("Finding experimental matches")
            self.find_experimental_matches()
```

`find_partial_matches` (`diaphora.py:2212-2221`, docstring at 2213-2215 omitted):

```python
  def find_partial_matches(self):
    self.run_heuristics_for_category("Partial")

    if self.slow_heuristics:
      # Search using some of the previous criterias but calculating the edit distance
      log_refresh("Finding with heuristic 'Small names difference'")
      self.search_small_differences("partial")
```

**Porting spec, in order:**

1. `find_equal_matches()` (`1404-1442`) adds a "100% equal" item to `best` with ratio `1` for every row of `intersect` over `(id, address, mangled_function, nodes, edges, size, bytes_hash)`. It also sets `total_functions1/2` (`count(*)` of each `functions` table, `1411-1422`). **The name it uses is `mangled_function`, not `name`:**

   ```python
             name = row["mangled_function"]
             ea = row["ea"]
             nodes = int(row["nodes"])

             item = [ea, name, ea, name, "100% equal", 1, nodes, nodes]
             self.add_match(name, name, 1.0, item, "best")
   ```
   (`1435-1440`). So `matched_primary`/`matched_secondary` get the **mangled** name as key, while every later pass keys by `name` (the demangled name, §9). When `name != mangled_function` the same function can hold two keys, and `has_best_match(name1, ...)` with the demangled `name1` does not see the "100% equal" entry. Real exports: `name != mangled_function` for 393 of 643 rows in `userenv-9168-pdb`, 411 of 663 in `userenv-9278-pdb` and 772 of 1442 in `sechost-9168-pdb`, and for 0 rows in every no-PDB export and in `ls`/`ls-old`. Because the `intersect` also requires equal `id` and `address`, it produced **0** "100% equal" items for `userenv-9168-pdb` vs `userenv-9278-pdb` (instrumented run), so the double key only matters for near-identical binaries. A port must key these entries by `mangled_function` anyway.
2. `is_same_processor` = at least one row exists for `select 1 from main.program mp, diff.program dp where mp.processor = dp.processor` (`2950-2967`). This is SQL equality: NULL never matches, and `''` matches `''`.
3. If `experimental` (default True), run `apply_dirty_heuristics()`. If it returns True, **Best and Partial are never run** (see 1.2).
4. `find_same_name("partial")` runs, because `ignore_all_names` is forced to False in standalone mode (`3759-3760`).
5. `run_heuristics_for_category("Best")`, then `run_heuristics_for_category("Partial")`, then `search_small_differences` (slow heuristics are on by default).
6. `Unreliable` and `Experimental` are run **only if** `self.unreliable`, which defaults to False. No heuristic has category `"Experimental"`: `Counter` over `HEURISTICS` gives `{'Partial': 30, 'Best': 12, 'Unreliable': 8}`.

### 1.2 The runner-skipping gate: `apply_dirty_heuristics` (`diaphora.py:2629-2637`)

```python
  def apply_dirty_heuristics(self):
    if self.search_just_stripped_binaries():
      return True
    if self.search_patchdiff_with_symbols():
      return True
    return False
```

- Stripped check (`2551-2563`): `matches` = `select count(0) from main.functions f, diff.functions df where f.address = df.address`, and `percent = (matches * 100) / total` with `total = self.total_functions1`. `if percent >= config.SPEEDUP_STRIPPED_BINARIES_MIN_PERCENT:` (99.0). When this triggers, it runs its own "Same binary with symbols stripped" `add_matches_from_query_ratio(sql, "best", "partial")` and returns True.
- Patch-diff check (`2599-2623`): the same count over `f.mangled_function = df.mangled_function`. `if percent > config.SPEEDUP_PATCH_DIFF_SYMBOLS_MIN_PERCENT:` (90.0) sets `is_patch_diff`, loads the default hooks script `scripts/patch_diff_vulns.py` (`RUN_DEFAULT_SCRIPTS=True`) and returns True.
- **Verified:** two synthetic exports with identical names logged `Patch diffing detected: ... 100.0% percent have the same name`. The next lines were `Finding with heuristic 'Perfect match, same name'` and then `Finding unmatched functions`. No "Finding best matches..." line appeared, so the runner never executed.
- **Verified on real exports:** `oracle/diffs/userenv-9168-pdb_vs_9278-pdb/run1/diaphora.log` shows the same sequence (`Loading default script for patch diffing sessions...`, `Patch diffing detected: A total of 643 matches out of 643, 100.0% percent have the same name`, then `Finding unmatched functions`). The PDB-vs-no-PDB pairs (`userenv-9168-pdb_vs_9278-nopdb`, `sechost-9168-pdb_vs_9444-nopdb`) and `ls`/`ls-old` log `Checking 'dirty' heuristics...` followed by `Finding best matches...`, so the runner does run for them.
- The percentage numerator is a **join-row count**, not a count of distinct functions, and the denominator is `total_functions1` only. Duplicate `mangled_function` values would inflate it (none exist in the real exports).
- **Consequence for parity work:** every in-scope heuristic runs *only* when both ratios stay below their thresholds (<99% address pairs, ≤90% mangled-name pairs). For a parity oracle on symbol-rich corpora, either implement the dirty heuristics too, or run Diaphora with `DIAPHORA_EXPERIMENTAL=""` (see the `get_value_for` quirk in 1.3). The first option is covered by another spec.

### 1.3 Configuration that the runner reads (default standalone values)

| Setting | Source | Default | Effect here |
|---|---|---|---|
| `self.unreliable` | `diaphora.py:400-402`, `config.DIFFING_ENABLE_UNRELIABLE` (`diaphora_config.py:46`) | `False` | Skips `HEUR_FLAG_UNRELIABLE` heuristics (none in scope), and the Unreliable and Experimental passes. |
| `self.experimental` | `406-408`, `diaphora_config.py:48` | `True` | Enables `apply_dirty_heuristics` only. There is no heuristic flag for experimental. |
| `self.slow_heuristics` | `409-411`, `diaphora_config.py:49` | `True` | `HEUR_FLAG_SLOW` heuristics run. |
| `self.relaxed_ratio` | `403-405`, `diaphora_config.py:47` | `False` | `check_ratio` uses `quick_ratio` and 7-decimal formatting. |
| `self.ignore_small_functions` | `474-476`, `diaphora_config.py:52` | `False` | `%POSTFIX%` becomes `""`. |
| `self.ignore_all_names` | `470-472`, then forced `False` at `3759-3760` | `False` | `find_same_name` runs before Best. |
| `self.cpu_count` | `483-491` | forced to **1** when `not IS_IDA` | One heuristic at a time. |
| `self.timeout` | `451`, `config.SQL_TIMEOUT_LIMIT` (`diaphora_config.py:92`) | `300` s | Per-heuristic timeout (4.3). |
| `self.sql_max_processed_rows` | `454-456`, `diaphora_config.py:90` | `1000000` | Row cap per ratio heuristic (4.3). |
| `self.use_trained_model` | `412-414`, `diaphora_config.py:205` | `False` | Irrelevant to this runner. `self.classifier` is assigned only in `apply_machine_learning` (`3551-3555`), which `diff()` calls **after** `find_partial_matches()` (`3634-3636`). So during the Best and Partial passes `self.classifier` is `None` (`445`) **whatever this flag says**, and `deep_ratio` adds no ML bonus. |
| `self.project_script` / hooks | `421`, `load_hooks` 528-558 | `None` | `call_hook` returns its default, unless patch-diff mode loaded the default script (and in that mode the runner is skipped anyway). |

**`MIN_FUNCTIONS_TO_DISABLE_SLOW` does not apply in standalone mode.** It is read only in `diaphora_ida.py:3798-3800` (`self.slow = kwargs.get("slow", total_functions <= config.MIN_FUNCTIONS_TO_DISABLE_SLOW)`), the IDA GUI options. There the default is "on" for `total_functions <= 4001`, i.e. it is disabled from 4002 functions up, and `diaphora_ida.py:3714` copies it with `bd.slow_heuristics = opts.slow`. In `diaphora.py` the only assignment is the `get_value_for` default (`grep` shows no other writer). Standalone runs therefore keep slow heuristics on **regardless of function count**. An earlier summary says otherwise; that summary is wrong.

`get_value_for` quirk (`diaphora.py:560-569`):

```python
    value = os.getenv(f"DIAPHORA_{value_name.upper()}")
    if value is not None:
      if isinstance(value, type(default)):
        value = type(default)(value)
      return value
    return default
```

An environment override is always returned as the **raw string**, because the `isinstance` test is inverted. As a result, `DIAPHORA_SLOW_HEURISTICS=0` gives `'0'`, which is truthy, so slow heuristics stay **enabled**. Only an empty string disables a boolean. Verified: with `DIAPHORA_EXPERIMENTAL=""` and `DIAPHORA_SLOW_HEURISTICS=0`, `get_value_for` printed `'' '0'`. A numeric override such as `DIAPHORA_SQL_MAX_PROCESSED_ROWS=10` becomes the string `'10'`, and `i < '10'` then raises `TypeError`. The same happens with `DIAPHORA_SQL_TIMEOUT_LIMIT` (`451`): `time.monotonic() - t > self.timeout` (`1894`) would compare a float with a string.

The oracle harness does not hit this quirk. `tools/oracle/build_oracle.py:108-115` (`CleanEnv`) removes every environment variable whose name starts with `DIAPHORA_`, and the diff step at `284-291` runs `python diaphora.py <ref> <target> -o <out>` with that environment ("with no DIAPHORA_* variables set, so diaphora_config.py defaults apply").

### 1.4 State at the moment the Best pass starts

- `all_matches = {"best": [...], "partial": [...], "unreliable": []}`. It holds the "100% equal" items from step 1 and the find_same_name items from step 4 (`2152-2210`). The exact rule (`2196-2208`) is:
  - `float(ratio) == 1.0` (or, only with `relaxed_ratio`, `md1 != 0 and md1 == md2`) → chooser `best`, item ratio **int `1`**;
  - otherwise chooser `partial` (the `choose` argument), and `ratio += 0.01` **only if** `ratio + 0.01 < 1.0` (`2203-2204`);
  - `add_match(name1, name2, ratio, item, the_chooser)` is called with the possibly bonused ratio.
  - Rows whose `mangled1` starts with `sub_` are skipped first (`2179-2180`); `ignore_sub_names` comes straight from `config.DIFFING_IGNORE_SUB_FUNCTION_NAMES` (`468`, default `True`) with no environment override.
  - The SQL guard there is `f.name not like 'nullsub_%'` (`2166`), where `_` **is** a one-character wildcard, unlike the in-scope `'nullsub%'` patterns.
- `matched_primary[name1] = {"name": name2, "ratio": ...}` and `matched_secondary[name2]`. These are set by `add_match`, which forces ratio 1.0 whenever `name1 == name2`. **There is no `cleanup_matches` between find_same_name and the Best pass**, so every same-name match still has ratio 1.0 in `matched_*` and `has_best_match` blocks it for the whole Best pass. The "100% equal" entries are keyed by `mangled_function` (step 1 above).
- **Real exports** (instrumented run): at the start of the Best pass, `ls-old` vs `ls` had `len(matched_primary) = 106` (items: best 100, partial 6), and `userenv-9168-pdb` vs `userenv-9278-nopdb` had 60 (best 28, partial 32).
- `ratios_cache` holds every pair already scored by `check_ratio`. It is reset only at the start of `diff()` (`3572`).

---

## 2. Heuristic record format and constants (`diaphora_heuristics.py:21-87`)

### 2.1 Ratio types and flags (`diaphora_heuristics.py:27-48`)

```python
# Use only for heuristics generating 1.0 ratios, results without false positives
HEUR_TYPE_NO_FPS = 0

# Use it for most heuristics; it will assign 1.0 ratios to the best chooser,
# values between 0.5 and <1.0 to the specific partial chooser and <0.5 results
# to the unreliable chooser, if specified.
HEUR_TYPE_RATIO = 1

# Similar as before, but partial results are only assigned for matches with a
# min specified ratio.
HEUR_TYPE_RATIO_MAX = 2

# Similar as before, but 'unreliable' results are not unreliable, thus, they go
# to the 'partial' tab instead.
HEUR_TYPE_RATIO_MAX_TRUSTED = 3

#-------------------------------------------------------------------------------
HEUR_FLAG_NONE        = 0
HEUR_FLAG_UNRELIABLE  = 1
HEUR_FLAG_SLOW        = 2
# The heuristic should only be launched when diffing the same architecture
HEUR_FLAG_SAME_CPU    = 3
```

- **The flags are list members, not bit flags.** Records hold `"flags":[HEUR_FLAG_SAME_CPU]`, and the runner tests `HEUR_FLAG_X in flags`. `HEUR_FLAG_SAME_CPU = 3` equals `UNRELIABLE|SLOW` as bits, so a bitmask port would alias it. In C++, use a small set or enum array and test membership.
- The comments on `HEUR_TYPE_RATIO` and `HEUR_TYPE_RATIO_MAX_TRUSTED` do **not** describe what the code does (see 4.2): no ratio type ever produces "unreliable" by default, and TRUSTED never sends low ratios to partial.

### 2.2 Record keys

Each heuristic is a `dict` appended to `HEURISTICS` in file order. `check_field_names` (`1279-1302`) allows exactly these keys: `name`, `category`, `ratio`, `sql`, `flags`, and optionally `min`.

| Key | Type | Meaning |
|---|---|---|
| `name` | str | Heuristic name. It also serves as the **description** literal inside `sql`, except in H11. |
| `category` | `"Best"`, `"Partial"` or `"Unreliable"` | Selects which pass runs it. It is **not** the output chooser. |
| `ratio` | 0-3 | `HEUR_TYPE_*` dispatch. |
| `min` | float | Read **only** when `ratio` is `RATIO_MAX` or `RATIO_MAX_TRUSTED` (`diaphora.py:1493-1495`). |
| `flags` | list[int] | Any of `HEUR_FLAG_*`. |
| `sql` | str | Query text containing the token `%POSTFIX%`. |

`check_heuristics_ratio` asserts `Counter({1: 22, 2: 22, 0: 5, 3: 1})` over all 50 heuristics (`diaphora_heuristics.py:1262`).

### 2.3 `SELECT_FIELDS` and `get_query_fields` (`diaphora_heuristics.py:51-84`), verbatim except the docstring at 77-79

```python
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
  val = heur
  if quote:
    val = repr(val)
  ret = SELECT_FIELDS.format(heur=val)
  return ret
```

- `repr(NAME)` produces a single-quoted Python literal such as `'Same RVA and hash'`, which is a valid SQL string literal. None of the in-scope names contains a quote. The description column is therefore the name, except in H11, which passes `"Equal pseudo-code"` and `"Equal assembly"`.
- The list has **45** columns (`len(cursor.description)` on H11, real exports).
- **Every column that the row consumer reads comes from this list** (`check_match`, `diaphora.py:1792-1842`). `md1`/`md2` are **`cast(... as real)` done by SQLite**, so the SQLite text-to-real conversion applies, not Python's `float(str)`.
- **Real exports:** the two conversions differ. Across the 5,417 `md_index` values in the seven exports, 3 cast to a different double than Python's correctly-rounded `float()`. Example: `'3.050963036440351716676733804'` → SQLite `3.0509630364403515`, `float()` `3.050963036440352`. A C++ port must read `md1`/`md2` from SQLite (`sqlite3_column_double` on the cast expression), not parse the text with `strtod`/`from_chars`.
- The SELECT list is the key of the temp B-tree used for UNION/DISTINCT, so it also shapes row order in UNION queries (see 6.5).

To get the exact final SQL string of each heuristic for embedding:

```
python -B -c "import sys; sys.path.insert(0, r'<diaphora-ref>'); from diaphora_heuristics import HEURISTICS; [print('=== '+h['name']+'\n'+h['sql'].replace('%POSTFIX%','')) for h in HEURISTICS[:28]]"
```

### 2.4 `%POSTFIX%`

- The runner does `sql = sql.replace("%POSTFIX%", postfix)` (`diaphora.py:1518`). Python `str.replace` replaces **every** occurrence; H11 has two.
- `postfix` is `""` by default. With `ignore_small_functions` it is `config.SQL_DEFAULT_POSTFIX`, which is `" and f.instructions > 5 and df.instructions > 5 "` (`diaphora_config.py:128`).
- The token always sits inside the WHERE clause, before any ORDER BY. In H11 it sits in both UNION arms. In CTE heuristics (H19, H20) it lands in the **outer** WHERE, not in the CTE.

---

## 3. `run_heuristics_for_category` (`diaphora.py:1461-1553`), verbatim

```python
  def run_heuristics_for_category(self, arg_category):
    """
    Run a total of @total_cpus threads running SQL heuristics for category @arg_category
    """
    total_cpus = self.get_threads_count()

    mode = "[Parallel]"
    if total_cpus == 1:
      mode = "[Single thread]"

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

      name = heur["name"]
      sql = heur["sql"]
      ratio = heur["ratio"]
      min_value = 0.0
      if ratio in [HEUR_TYPE_RATIO_MAX, HEUR_TYPE_RATIO_MAX_TRUSTED]:
        min_value = heur["min"]

      flags = heur["flags"]
      if HEUR_FLAG_UNRELIABLE in flags and not self.unreliable:
        log_refresh(f"Skipping unreliable heuristic '{name}'")
        continue

      if HEUR_FLAG_SLOW in flags and not self.slow_heuristics:
        log_refresh(f"Skipping slow heuristic '{name}'")
        continue

      if HEUR_FLAG_SAME_CPU in flags and not self.is_same_processor:
        log_refresh(f"Skipping processor specific heuristic '{name}'")
        continue

      if arg_category.lower() == "unreliable":
        best = "partial"
        partial = "unreliable"
      else:
        best = "best"
        partial = "partial"

      log_refresh(f"{mode} Finding with heuristic '{name}'")
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
      else:
        traceback.print_exc()
        raise Exception("Invalid heuristic ratio calculation value!")

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

### 3.1 Porting spec (pseudocode)

```
RunCategory(cat):                       # cat ∈ {"Best","Partial","Unreliable","Experimental"}
  postfix = ignore_small_functions ? " and f.instructions > 5 and df.instructions > 5 " : ""
  # hooks: none by default (the get_queries_postfix return value is discarded anyway)
  jobs = []
  for h in HEURISTICS (file order):
     # Evaluated while building the list; no job has run yet, so it is constant
     # for the whole loop:
     if |matched_primary| == total_functions1 or |matched_secondary| == total_functions2:
         break
     if h.category != cat: continue            # exact, case-sensitive string compare
     minv = (h.ratio in {RATIO_MAX, RATIO_MAX_TRUSTED}) ? h.min : 0.0
     if UNRELIABLE ∈ h.flags and !unreliable:        continue
     if SLOW ∈ h.flags       and !slow_heuristics:   continue
     if SAME_CPU ∈ h.flags   and !is_same_processor: continue
     (best, partial) = lower(cat) == "unreliable" ? ("partial","unreliable") : ("best","partial")
     sql = replace_all(h.sql, "%POSTFIX%", postfix)
     switch h.ratio:
       NO_FPS            -> job = FromQuery(sql, category=best)
       RATIO             -> job = FromQueryRatio(sql, best, partial)                 # val defaults to 0.5
       RATIO_MAX         -> job = FromQueryRatioMax(sql, best, partial, minv)
       RATIO_MAX_TRUSTED -> job = FromQueryRatioMaxTrusted(sql, minv)                # ignores best/partial
     jobs.append(job)
  for job in reversed(jobs): job()             # see 3.3: strictly sequential, REVERSE order
  CleanupMatches()                             # section 7
  ShowSummary()                                # logging only; divides by total_functions1
```

### 3.2 Category demotion (only in the `"Unreliable"` pass, which is off by default)

| Ratio type | Best / Partial pass: r == 1.0 → | r ≥ val → | Unreliable pass: r == 1.0 → | r ≥ val → |
|---|---|---|---|---|
| NO_FPS | `best` (always, ratio 1) | n/a | `partial` (always, ratio 1) | n/a |
| RATIO | `best` | `partial` (val = 0.5) | `partial` | `unreliable` |
| RATIO_MAX | `best` | `partial` (val = min) | `partial` | `unreliable` |
| RATIO_MAX_TRUSTED | `best` | `partial` (val = min) | `best` (hard-coded) | `partial` (hard-coded) |

`add_matches_from_query_ratio_max_trusted` hard-codes `best="best", partial="partial"` (`2014`), so TRUSTED heuristics are never demoted. The only TRUSTED heuristic is H13.

### 3.3 Threading and execution order (`jkutils/threads.py:27-71`)

```python
def threads_apply(threads, targets, wait_time, log_refresh, timeout):
  times = 0
  first = True
  threads_list = []
  while first or len(targets) > 0 or len(threads_list) > 0:
    first = False
    times += 1
    if len(targets) > 0 and len(threads_list) < threads:
      item = targets.pop()
      target = item["target"]
      args = item["args"]

      t = threading.Thread(target=target, args=args)
      t.time = time.monotonic()
      t.timeout = False
      
      for key in item.keys():
        if key not in ["target", "args"]:
          setattr(t, key, item[key])

      t.start()
      threads_list.append(t)

    for i, t in enumerate(threads_list):
      if not t.is_alive():
        if log_refresh:
          log_refresh(f"[Parallel] Heuristic '{t.name}' done")
        del threads_list[i]
        break

      if time.monotonic() - t.time > timeout:
        t.timeout = True
      t.join(wait_time)
    ...
```

- `targets.pop()` takes the **last** element, so heuristics execute in **reverse file order**. With `threads == 1` (always true outside IDA, `diaphora.py:489-491`), only one thread is alive at a time. The order is therefore deterministic.
- **Verified on the synthetic run.** Setup lines print in file order, and completion lines print in reverse:
  - Best: `Microcode mnemonics small primes product` → `Equal assembly or pseudo-code` → `Same RVA` → `Same address, nodes, edges and mnemonics` → `Same cleaned pseudo-code` → `Same cleaned microcode` → `Same cleaned assembly` → `Same address and mnemonics` → `Bytes hash` → `Function Hash` → `Same order and hash` → `Same RVA and hash`.
  - Partial, default flags: `Loop count`, `Same rare basic block mnemonics list`, `Same rare assembly instruction`, `Pseudo-code fuzzy AST hash`, `Pseudo-code fuzzy (reverse)`, `Pseudo-code fuzzy (mixed)`, `Pseudo-code fuzzy (normal)` (these three are heuristics 33-35, flags `[]`; they are not the skipped `Partial pseudo-code fuzzy hash (...)` ones), `Switch structures`, `Same low complexity and names`, `Same low complexity, prototype and names`, `Same nodes, edges, loops and strongly connected components`, `Mnemonics small-primes-product`, `Similar pseudo-code and names`, `Pseudo-code fuzzy hash`, `Mnemonics and names`, `Import names hash`, `Same MD Index and constants`, `Same rare constant`, `Same address and rare constant`, `Same rare MD Index`, `Same rare KOKA hash`, `Same constants`, `Same KOKA hash and MD-Index`, `Same KOKA hash and constants`, `Same compilation unit`, `Same anonymous compilation unit function match`, `Same named compilation unit function match`.
  - The three `Partial pseudo-code fuzzy hash (...)` heuristics (37-39) carry `HEUR_FLAG_UNRELIABLE` and logged `Skipping unreliable heuristic`.
  - **Real exports:** the Diaphora log of `ls_vs_ls-old/run1` shows the same setup order and the same reversed completion order for both passes (27 Partial completions, 3 skips).
- Each heuristic runs in a **fresh Python thread**. `db_cursor()` → `get_db()` (`584-593`) opens a **new connection** keyed by thread ident and runs `attach "<db2>" as diff`. `create_schema` and `PRAGMA foreign_keys` run only on the main thread's connection (`579-581`). Python may reuse a finished thread's ident, and then the old connection (already attached) is reused. Nothing here affects SELECT results. Diaphora issues no other `PRAGMA` on the diff connections (grep: only `diaphora.py:621` and the exporter's `diaphora_ida.py:1185-1188`), so `pragma threads` keeps the library default (0 in the conda build, see §6.4).
- `setattr(t, "name", heur_name)` renames the thread. That name appears in the timeout log (`1895`).
- `self.items_lock` wraps `add_match` and `cleanup_matches`. With one thread it has no observable effect.
- Parity consequence: a C++ replay must run the list **back to front**, one heuristic at a time, and each heuristic must see the state left by the previous one.

---

## 4. Dispatch targets and the shared row loop

### 4.1 `add_matches_from_query` (NO_FPS) (`diaphora.py:2039-2083`), verbatim

```python
  def add_matches_from_query(self, sql, category):
    if self.all_functions_matched():
      return

    cur_thread = threading.current_thread()
    cur = self.db_cursor()
    try:
      cur.execute(sql)

      i = 0
      while not cur_thread.timeout:
        i += 1
        if i % 1000 == 0:
          log(f"Processed {i} rows...")
        row = cur.fetchone()
        if row is None:
          break

        # Check the row match
        should_add, r = self.check_match(row)
        if not should_add:
          continue

        ea = str(row["ea"])
        name1 = row["name1"]
        ea2 = row["ea2"]
        name2 = row["name2"]
        nodes1 = int(row["nodes1"])
        nodes2 = int(row["nodes2"])
        desc = row["description"]
        item = [ea, name1, ea2, name2, desc, 1, nodes1, nodes2]
        self.add_match(name1, name2, 1.0, item, category)
        if r < config.DEFAULT_PARTIAL_RATIO:
          debug_refresh(
            f"Warning: Best match 0x{ea}:{name1} -> 0x{ea2}x:{name2} have a bad ratio: {r}"
          )
    except:
      log(f"Error: {str(sys.exc_info()[1])}")
    finally:
      cur.close()
```

Spec:

- **No row cap.** Only the thread timeout flag applies.
- `check_match` still computes the real ratio `r` and applies `has_best_match` and `has_better_match(name1, name2, r)` using **r, not 1.0**. A NO_FPS row can therefore be **rejected** when either name already holds a match with a ratio above r.
- A surviving row is always added with item ratio **`1` (int)** and `add_match(..., 1.0, ...)` into `category` (the pass's `best` label).
- Any exception ends this heuristic silently (logged, not re-raised).

### 4.2 `add_matches_from_query_ratio`, `_ratio_max`, `_ratio_max_trusted` and `add_matches_internal`

`add_matches_from_query_ratio` (`1950-1975`), `add_matches_from_query_ratio_max` (`1977-2000`) and `add_matches_from_query_ratio_max_trusted` (`2002-2026`) share one body shape. Each begins with `if self.all_functions_matched(): return`, then runs `cur.execute(sql)` and calls `add_matches_internal`. On `SystemExit` they do `pass` (the timeout case). On any other exception they log, print the SQL and traceback, and **re-raise**, which kills that thread only. The calls are:

```python
# ratio:          add_matches_internal(cur, best=best, partial=partial, unreliable=unreliable, debug=debug)   # unreliable=None, val=None
# ratio_max:      add_matches_internal(cur, best=best, partial=partial, val=val, unreliable="unreliable")
# ratio_max_trusted: add_matches_internal(cur, best="best", partial="partial", val=val, unreliable="partial")
```

The three `# ...:` lines above are condensed summaries of `1962-1964`, `1987-1989` and `2013-2015`, not verbatim source.

`add_matches_internal` (`1882-1948`), verbatim from `1889` (the signature at `1882-1884` is `def add_matches_internal(self, cur, best, partial, val=None, unreliable=None, debug=False):`; the docstring is omitted):

```python
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

**Category decision (exact):**

```
val = (val is None) ? 0.5 : val          # 0.5 = config.DEFAULT_PARTIAL_RATIO (diaphora_config.py:137)
if   r == 1.0              -> add to `best`,    item ratio = r
elif r >= val              -> add to `partial`, item ratio = r    # partial is never None for these callers
else                       -> dropped
```

- **The "unreliable" branch is dead for every caller in scope.** It is reached only when `partial is not None` and `r < val`, but then it requires `r > val`, which is impossible. Even when the argument is `unreliable="partial"` (TRUSTED), the chooser literal is `"unreliable"`. So the TRUSTED docstring ("assign those with a bad ratio to the partial chooser") is **not** what happens: low-ratio TRUSTED rows are simply dropped.
- With RATIO_MAX or RATIO_MAX_TRUSTED and `min < 0.5` (H13 0.44 TRUSTED, H14 0.449, H19 0.45, H22 0.2), **partial accepts ratios below 0.5**. With `min > 0.5` (H10 0.7, H27 0.579, H28 0.6), ratios in `[0.5, min)` are dropped.
- The item layout is `[ea(str of address text), name1, ea2(address text as returned), name2, desc, r(float), nodes1(int), nodes2(int)]`.
- `"0x%x" % int(ea)` must succeed. The address column holds decimal text written by the exporter, so it does.

### 4.3 Row cap and timeouts

`continue_getting_sql_rows` (`1874-1880`):

```python
    if self.sql_max_processed_rows != 0 and i < self.sql_max_processed_rows:
      return True
    return False
```

- Ratio heuristics process **at most the first 1,000,000 rows** returned by SQLite, counting rejected rows too. `i` is tested before the increment, so row number 1,000,000 is processed and then the loop exits. A setting of `0` means **no rows at all**, which is a bug.
- Timeout: `add_matches_internal` compares its own clock against `self.timeout` (300 s) on every row. `threads_apply` also sets `t.timeout = True` once the thread is older than `config.SQL_TIMEOUT_LIMIT` (300 s; the env override is not used there). NO_FPS uses only the thread flag.
- **Timeouts are non-deterministic.** Parity is achievable only for runs where Diaphora's log contains no `Timeout with heuristic` line. The row cap *is* deterministic when the row order is reproduced. Watch for it on H16/H22 (constants joins, which can grow quadratically) and on large binaries.
- **Real exports:** in `oracle/diffs/sechost-9168-pdb_vs_9444-nopdb/run1/diaphora.log` no in-scope heuristic logged `Timeout` or reached 1,000,000 rows. The slowest were H16 `Same KOKA hash and constants` (about 74 s), H21 `Same address and rare constant` (about 68 s) and H22 `Same rare constant` (about 66 s, `Processed 50000 rows...`), measured while other oracle diffs ran in parallel. That is well below 300 s, but only by a factor of about 4.

### 4.4 `all_functions_matched` (`1777-1784`)

It returns true when `len(matched_primary) == total_functions1 or len(matched_secondary) == total_functions2`. The check runs at the start of each dispatch function, so it takes effect **between** heuristics as matches accumulate. The dicts are keyed by name, so duplicate names can keep this from ever becoming true. Conversely, a function with a "100% equal" entry (keyed by `mangled_function`, §1.1) and a same-name entry (keyed by `name`) counts twice, so the `==` test can become true before every function is matched, or be skipped past. The test is `==`, not `>=`.

---

## 5. Per-row acceptance: `check_match`, `has_best_match`, `has_better_match`, `add_match`

### 5.1 `check_match` (`diaphora.py:1786-1872`)

The code first builds `main_d`/`diff_d` from row aliases (`1798-1842`) and then:

```python
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

Every runner call passes `ratio=None`, so all three filters always apply:

```
CheckMatch(row):
  if name1.startswith("nullsub_") or name2.startswith("nullsub_"): reject   # case-SENSITIVE, with underscore
  if HasBestMatch(name1, name2): reject
  r = CheckRatio(main_d, diff_d)            # cached per "ea1-ea2" text key
  if HasBetterMatch(name1, name2, r): reject
  return (accept, r)                        # no hooks by default
```

`main_d["md_index"]` is the SQL `cast(... as real)` value. `check_ratio` calls `float()` on it (`1672-1673`). A NULL md_index would raise `TypeError`, which aborts that heuristic (see 4.1 and 4.2). The exporter never writes NULL md_index: it writes `0` or `str(Decimal)` (`diaphora_ida.py:2514-2538`). Note that `float(md)` runs **before** the `bytes_hash` shortcut (`1672` vs `1681`).

A NULL `name1`/`name2` would also abort the heuristic: `name1.startswith(nullsub)` (`1846`) raises `AttributeError` on `None`. SQL lets such rows through wherever there is no `not like` guard, e.g. NAMECOMPAT is TRUE for `f.name` NULL when `df.name` starts with `sub_`. Real exports contain no NULL or `''` names (0 of 5,417 rows), so this is theoretical.

### 5.2 `has_best_match` (`1376-1384`) and `has_better_match` (`1386-1402`), verbatim

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

**The quirk to reproduce.** When **both** names lack the `sub_` prefix and `name1` is already in `matched_primary`, the function returns `matched_primary[name1].name == name1` and **skips the ratio checks entirely**. That includes skipping the `name2` side. So a named function already matched to a *differently named* partner accepts **any** new candidate, even one with a lower ratio. `add_match` then overwrites `matched_primary[name1]`.

The comparisons are strict `>`, so equal ratios do not block.

### 5.3 `add_match` (`1340-1374`)

```python
    with self.items_lock:
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

Spec:

- Same-name pairs are recorded in `matched_*` with ratio 1.0. Their item keeps the real `r`, and the chooser was already picked from `r`.
- `has_better_match` is checked again. That is a no-op right after `check_match` because nothing changed in between.
- The item is appended unless an **identical 8-element list** already exists in that chooser list (Python list equality: `1 == 1.0`, `'x' == 'x'`).
- `matched_*` is **always overwritten**.

### 5.4 Consequences a C++ port must reproduce

- **1.0 matches are first-come-first-served.** Heuristics run in reverse order and rows arrive in SQLite order. The first accepted 1.0 row for name A (or X) blocks every later row that touches A or X, through `has_best_match`.
- In the synthetic trace, Best-pass matches carried the descriptions `Equal assembly` (25) and `Function Hash` (7). *Same RVA and hash* got none, because it runs last and everything it could find was already taken.
- **Real exports** (instrumented in-process run, items appended during the Best pass, by description and chooser):
  - `ls-old` vs `ls`: `Microcode mnemonics small primes product` 14 best + 3 partial, `Same cleaned pseudo-code` 8 best + 1 partial, `Equal assembly` 4, `Same cleaned microcode` 4, `Equal pseudo-code` 1. H01-H05 added nothing.
  - `userenv-9168-pdb` vs `userenv-9278-nopdb`: `Microcode mnemonics small primes product` **348 partial** + 80 best, `Bytes hash` 13 best, `Same address and mnemonics` 11 partial, `Same RVA` 9 partial, `Same cleaned microcode` 9 best, `Same address, nodes, edges and mnemonics` 8 partial, `Equal pseudo-code` 4 best.
  - In the Partial pass of `ls-old` vs `ls`, the Partial heuristic `Same low complexity and names` produced 2 **best** items.
- For non-1.0 matches the outcome depends on arrival order and on the name quirk. Example: candidates `(A,X,0.8)`, `(A,Y,0.9)` and `(B,X,0.7)`, all named with `sub_`.
  - **Order `(A,X),(A,Y),(B,X)`:**
    - `(A,X)` is accepted.
    - `(A,Y)` is accepted, because `0.8 > 0.9` is false. `matched_primary[A]` becomes `Y/0.9`, but `matched_secondary[X]` still holds `A/0.8`.
    - `(B,X)` is rejected, because `matched_secondary[X].ratio` `0.8 > 0.7`.
    - `cleanup_matches` then keeps only `(A,Y)`. The result is `{(A,Y)}`.
  - **Order `(A,Y),(A,X),(B,X)`:**
    - `(A,X)` is rejected (`0.9 > 0.8`), so X is never recorded.
    - `(B,X)` is accepted.
    - The result is `{(A,Y),(B,X)}`.
  - `cleanup_matches` cannot repair this, because it dedups per primary ea only.
  - **Verified** by calling Diaphora's own `has_best_match`, `has_better_match`, `add_match` and `cleanup_matches` on a bare `CBinDiff` object: the outputs were `[('sub_A','sub_Y')]` and `[('sub_A','sub_Y'), ('sub_B','sub_X')]`.

---

## 6. SQL semantics that decide which rows exist and in what order

### 6.1 Type affinity (schema `db_support/schema.py:69-118`)

The relevant `functions` columns are:

- **TEXT affinity:** `name varchar(255)`, `address text unique`, `rva text unique`, `segment_rva`, `mnemonics`, `names`, `bytes_hash`, `function_hash`, `md_index`, `kgh_hash`, `mnemonics_spp`, `microcode_spp`, `constants`, `pseudocode`, `pseudocode_hash1..3`, `pseudocode_primes`, `primes_value`, `prototype2`, `clean_*`, `source_file`.
- **INTEGER affinity:** `id` (rowid), `nodes`, `edges`, `indegree`, `outdegree`, `size`, `instructions`, `cyclomatic_complexity`, `pseudocode_lines`, `strongly_connected`, `loops`, `constants_count`.

A Python `int` bound into a TEXT column is **stored as text**. Big ints are pre-converted with `str()` by `get_valid_prop` (`diaphora.py:719-728`). When a TEXT column is compared with an integer literal, SQLite applies TEXT affinity to the literal. The comparison is therefore **text vs `'0'` / `'1'` / `'7'` under BINARY collation**.

Verified with Diaphora's schema. The rows were a=int 0, b='0', c=NULL, d='', e='123' / md '1.5', f=int 7 / md '0.25', g='NO-FUNCTION' / md '-1', h='99999999999' / md '1E-7':

```
kgh_hash != 0      -> ['d','e','f','g','h']     (excludes '0' and NULL; INCLUDES '')
md_index != 0      -> ['d','e','f','g','h']
md_index > 0       -> ['e','f','h']            (text compare with '0': '0.25' > '0', '-1' < '0', '' < '0')
microcode_spp != 1 -> ['d','e','f','g','h']
kgh_hash > 7       -> ['g','h']                (lexicographic: '123' < '7')
typeof(kgh_hash) for int 0 inserted -> 'text'
```

C++ rule: implement `col != 0` as `!isNull(col) && col != "0"`, `col > 0` as `!isNull(col) && memcmp-order(col, "0") > 0`, and `col != 1` as `!isNull(col) && col != "1"`. Equality between two TEXT columns is a byte comparison and never converts to a number.

### 6.2 NULL and empty string

- Any comparison with NULL yields NULL, which WHERE treats as false. `NULL = NULL` is NULL. `'' = ''` is **1**.
- `substr(NULL,1,4) = 'sub_'` is NULL.
- `NULL NOT LIKE 'nullsub%'` is NULL, so a row with a NULL name is **excluded** by every `not like` guard.

All of this was verified. Our loader maps NULL to `""` (`ExportDatabase.cpp:98-105`) and NULL integers to 0 (`sqlite3_column_int64`). It cannot tell the two apart; see D10.

**Real exports (all seven), `functions` table.** There are **zero** `''` values in `name`, `mangled_function`, `address`, `rva`, `segment_rva`, `bytes_hash`, `function_hash`, `mnemonics`, `names`, `md_index`, `kgh_hash`, `mnemonics_spp`, `microcode_spp`, `clean_assembly`, `clean_pseudo`, `clean_microcode`, `pseudocode`, `assembly`, `pseudocode_hash1..3`, `pseudocode_primes`, `primes_value`, `constants`, `source_file` or `switches`. Every value is `typeof = 'text'` or NULL.
- NULL appears only in `pseudocode`, `clean_pseudo`, `clean_microcode` and `pseudocode_primes`, always together on the same rows. There are 106 such rows in `ls-old`, 113 in `ls`, and 1-5 in each PE export. NULL also appears in `pseudocode_hash1..3` (most rows) and in `source_file`.
- `microcode_spp = '1'` exactly on the rows where `clean_microcode` is NULL.
- `md_index = '0'` on 111-192 rows per export.
- `kgh_hash` is never `'0'`, `'NO-FUNCTION'` or `'NO-FLOW-GRAPH'`.
- `compilation_units.name` **is** `''` on many rows: 13 of 14 in `ls-old`, 9 of 11 in `ls`, 19 of 67 in `sechost-9168-pdb`, 41 of 44 in `sechost-9444-nopdb`, and 2 of 11 in `userenv-9278-nopdb`.

So in these exports the `''`-versus-NULL distinction matters for CU names (H13 and H14 exclude `''`) and for NULL text columns (which never match). For the key columns of the implemented heuristics it matters only through NULL. That includes `clean_microcode` for H07.

### 6.3 LIKE

- `LIKE` is **ASCII case-insensitive** by default. Diaphora never sets `case_sensitive_like` (grep finds no pragma). Verified: `'NullSub_1' not like 'nullsub%'` gives 0, and `'NULLSUBX' like 'nullsub%'` gives 1.
- `%` matches any run of characters. `_` matches exactly one character. The in-scope patterns are all `'nullsub%'`, which contains no `_`. (Out of scope, `find_same_name` uses `'nullsub_%'` at `diaphora.py:2166`, where `_` is a wildcard.)
- The Python-side filter in `check_match` is **case-sensitive** `startswith("nullsub_")`. The SQL guard and the Python guard are therefore different predicates, and **both** apply.

### 6.4 Row order: what SQLite emits is what Python processes

Without ORDER BY, rows come out in **query-plan order**. The plan depends on the indices from `schema.INDICES` and on `sqlite_stat1` from `analyze`, and so on the data. Plans observed on the synthetic exports with `EXPLAIN QUERY PLAN` (illustrative, not normative):

| Heuristic | Observed plan |
|---|---|
| H01 | `SEARCH f USING INDEX idx_7 (nodes>?)`, then `SEARCH df USING INDEX idx_0 (bytes_hash=?)`, so the outer order is f by `(nodes, edges, cyclomatic_complexity, rowid)` |
| H04 | f via `idx_6 (instructions>?)`, i.e. `(instructions, mnemonics, names)` order |
| H17 | the **outer loop is df** (`SEARCH df USING INDEX idx_7`) |
| H23 | the outer loop is df via `idx_24 (md_index>?)` |

**The outer table and its index order vary per query and per dataset.** Hash joins that iterate main in id order will not reproduce this.

ORDER BY `f.source_file = df.source_file`:

- `source_file` is set by `save_compilation_units`: `update functions set source_file = ? where id = ?`, with value `None` when the CU name is `''` (`diaphora_ida.py:3356`, `3366-3368`, `3382`). A function in no CU keeps the NULL that `build_props_list` inserts (`diaphora_ida.py:3184`). So `source_file` is either a non-empty CU name or NULL, never `''`.
- The key is therefore NULL, 0 or 1, and ascending order puts **NULL first, then 0, then 1**, which means same-source-file pairs come **last**.
- **Real exports:** `source_file` is populated heavily in the PE exports: 618 of 643 rows in `userenv-9168-pdb`, 1221 of 1442 in `sechost-9168-pdb`, 851 of 1419 in `sechost-9444-nopdb`. In `ls`/`ls-old` it is mostly NULL (43/318 and 20/304 populated). Its values are CU names such as `onecore\ds\security\gina\profile\userenv\lib\copydir.cpp` or `Symbol: d:\os\obj\...\iprofilenotify_p.obj`. On `userenv-9168-pdb` vs `userenv-9278-nopdb`, H12's 558 rows split into 27 NULL, 14 `0` and 517 `1` keys, so the ORDER BY moves real rows.
- **CORRECTED (the original claim was wrong).** The original text said "the output equals a stable sort of the no-ORDER-BY output on that key". That held on the synthetic data but **fails on real exports**, because adding the `ORDER BY` changes the query plan. For H27 on `ls-old` vs `ls`, the plan with the ORDER BY is `SEARCH f USING INDEX idx_9 (pseudocode_lines>?)`, `SEARCH df USING INDEX idx_10 (names=?)`. Without it the plan is `... SEARCH df USING INDEX idx_9 (pseudocode_lines=?)`. All 34 rows have a NULL key, yet the two outputs differ in tie order. Across the 16 ORDER BY heuristics in scope and 5 real pairs, "stable sort of the unordered output" failed for H27 (`ls-old`→`ls`), H20 (`ls`→`ls-old`, both userenv pairs), H23 (both userenv pairs) and H09 (`sechost`). The plan changed in H05, H09, H23, H24 and H27 on at least one pair.
- **What does hold:** the sort is stable **relative to the ORDER BY query's own scan order**. Test: replace the key with `coalesce(f.source_file = df.source_file, 7) * 0`, which is constant but still forces a sort. When that surrogate query has an identical `EXPLAIN QUERY PLAN`, a stable sort of its output by the real key equals the real output. That held with **0 failures** across the 16 heuristics × 5 real pairs.
- **Resolved from SQLite 3.51.1 source** (tag `version-3.51.1` of the official `sqlite/sqlite` GitHub mirror, fetched into a scratch directory):
  - For `ORDER BY` without `LIMIT`, `select.c` switches the sort index to `OP_SorterOpen` and sets `SORTFLAG_UseSorter` (`if( p->iLimit==0 && sSort.addrSortIndex>=0 )`). Its KeyInfo comes from `sqlite3KeyInfoFromExprList(pParse, sSort.pOrderBy, 0, pEList->nExpr)`, so only the ORDER BY expression is a key field.
  - Ties compare as 0. `vdbeSorterCompareText` only calls the tail compare `if( pTask->pSorter->pKeyInfo->nKeyField>1 )`, and `sqlite3VdbeRecordUnpack` sets `p->default_rc = 0`.
  - The in-memory merge sort takes the **older** record on ties: `vdbeSorterMerge` has `if( res<=0 ){ *pp = p1; ...`, and `vdbeSorterSort` always passes the older run as `p1`, because the list is built newest-first (`pNew->u.pNext = pSorter->list.pList;`).
  - PMA merges also prefer the older record: "If the two values were equal, then the value from the oldest PMA should be considered smaller ... `if( iRes<0 || (iRes==0 && pReadr1<pReadr2) )`", and `vdbeMergeEngineCompare` has `if( res<=0 ){ iRes = i1; }`.
  - So the sort is **stable in single-threaded mode, including when it spills to disk**.
  - With worker threads (`pragma threads` > 0), PMAs are handed out "round-robin between the first (pSorter->nTask-1) tasks" and the final merge is over tasks, so tie order across tasks is **not** insertion order.
  - The conda build reports `pragma threads` = 0 and `compile_options` `DEFAULT_WORKER_THREADS=0`, `MAX_WORKER_THREADS=8`, and Diaphora never sets `pragma threads`. So for the oracle the sort **is** stable. A native replay must not enable worker threads on its connection.

DISTINCT:

- The `USE TEMP B-TREE FOR DISTINCT` step suppresses duplicates and keeps the scan order **of its own plan**.
- **CORRECTED:** the original text said "The comparison held for all 9 in-scope DISTINCT heuristics". On real exports, removing `DISTINCT` changes the plan for H05, H23, H24, H26 and H27 on some pairs. Order then differed for H27 (both `ls` directions and the userenv pdb pair) and H23 (both userenv pairs). Where the plan was unchanged, the DISTINCT output equalled the first-occurrence dedup of the plain output.
- For `functions × functions` joins, DISTINCT never removes anything, because `address` is unique and is selected. (Real exports: 0 duplicates removed in every DISTINCT heuristic on the four smaller pairs.)
- **Consequence:** the row order of a heuristic can only be reproduced by running its **exact** final SQL text. The ORDER BY, DISTINCT, CTE and UNION must all stay in the query; none of them can be stripped and re-applied in C++.

### 6.5 UNION (H11) and CTEs (H19, H20)

- H11's `UNION` is planned as `UNION USING TEMP B-TREE`. **Verified:** the output is **sorted by the full selected row** in SQLite order, starting with `(ea text, name1, ea2, name2, description, ...)`. The first ordering key is the main address as **text**, not as a number.
- When a pair qualifies in both arms, two rows exist, because the descriptions differ. `'Equal assembly'` sorts before `'Equal pseudo-code'`, so the assembly row wins and the pseudo row is then rejected by `has_best_match`.
- **Verified on real exports** (all 5 pairs): the H11 output equals `select * from (<H11>) order by 1,2,...,45` exactly, and `ea` is monotone as text. Pairs present in both arms: 2 for `ls-old`/`ls`, 73 for `userenv` pdb/pdb and 28 for `sechost`, each with `['Equal assembly', 'Equal pseudo-code']` in that order. The plan was always `COMPOUND QUERY` / `UNION USING TEMP B-TREE`. The outer table of each arm varied (f or df).
- CTEs with `UNION` are deduplicated sets. They appear in plans as `CO-ROUTINE shared_hashes` / `AUTOMATIC COVERING INDEX`. They only filter; they do not add rows.

### 6.6 Recommended parity implementation

1. Open `db1` and run `attach "<db2>" as diff`. Diaphora builds this exact text itself: `f'attach "{diff_db}" as diff'` at `diaphora.py:657` and `2441`.
2. Build each final SQL string exactly as Python does (see 2.3 and 2.4).
3. `sqlite3_prepare_v2` and step it, reading columns by alias name.
4. Feed rows to a C++ port of `check_match`, `check_ratio`, `add_match` and `add_matches_internal`.

This inherits SQLite's plan, affinity, LIKE, NULL, DISTINCT and UNION semantics for free. It also gets SQLite's `cast(md_index as real)` (§2.3).
- Keep the connection's `pragma threads` at 0 so the sorter stays stable (§6.4).
- Do not strip or rewrite any clause: ORDER BY and DISTINCT change the plan (§6.4).

The one remaining risk is the SQLite version. `.github/workflows/ci.yml:38-56` installs whatever `apt-get install -y libsqlite3-dev` (ubuntu-latest), `brew install sqlite3` (macos-latest) and `vcpkg install sqlite3:x64-windows` provide. None of them is pinned to the conda 3.51.1 that the oracle uses. Which versions CI actually gets, and whether their plans differ, is **NOT DETERMINED** from the repository.

---

## 7. `cleanup_matches` (`diaphora.py:1554-1605`), which runs at the end of every pass

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

Spec:

- Categories are processed in dict order `best`, `partial`, `unreliable` (`382`). `dones` and `ea_ratios` are **shared across categories**.
- Within a category, items are **stable**-sorted by ratio descending. Python `sorted(..., reverse=True)` keeps insertion order for ties.
- Pair dedup uses the key string `name1 + "-" + name2`. Name strings containing `-` could collide; this is not handled.
- The per-ea filter uses `ea` = **main address text**. It drops an item only if a *strictly greater* ratio was seen for that ea. Equal-ratio duplicates **survive**. The secondary side is **never** deduplicated here; multimatch detection happens later, in `final_pass` / `find_multimatches` (`2839-2935`), which is outside this spec.
- Same-name items count as ratio 1.0 for the filter, but the item keeps its own ratio.
- `matched_*` is rebuilt from the surviving items **with `item[5]`**, not with the forced 1.0. Later items overwrite earlier ones.
- **After the Best pass's cleanup, same-name matches whose item ratio is below 1 no longer count as best in `has_best_match` during the Partial pass.** When both names are non-`sub_`, they still block through the `has_better_match` quirk.
- `show_summary` (`1622-1635`) only logs.

---

## 8. `check_ratio` summary (dependency; `diaphora.py:1645-1775`)

This summary is only precise enough to predict categories. If a dedicated ratio spec exists, it is authoritative.

The defaults here are `relaxed_ratio=False`, `fratio=quick_ratio` and `decimal_values="{0:.7f}"` (`1675-1679`).

```
key = f"{ea1}-{ea2}" (address text);  if key in ratios_cache: return it
md1 = float(md1); md2 = float(md2)                          # md from SQL cast
if bytes_hash1 == bytes_hash2: return 1.0                   # Python ==; None == None is True
v1 = 0; if pseudo1/pseudo2 both non-None and non-"":
          if clean_pseudo1 == "" or clean_pseudo2 == "": log only
          else v1 = float(fmt7(quick_ratio(clean_pseudo1, clean_pseudo2)))   # no early exit when not relaxed
v2 = float(fmt7(quick_ratio(clean_assembly1, clean_assembly2)))              # no early exit when not relaxed
v3 = 0
v4 = 0.0; if md1 == md2 and md1 > 0.0: v4 = min((v1 + v2 + v3 + 3.0) / 5, 1.0)
v5 = 0.0; if clean_micro1 is not None and clean_micro2 is not None:
          v5 = float(fmt7(quick_ratio(clean_micro1, clean_micro2))); if v5 == 1: return 1.0
r = max({v1,v2,v3,v4,v5}); if r == 1.0 and md1 != md2: r = max(v for v in set if v != 1.0, default 0)
if r < 1.0: s = deep_ratio(...); r = r + s if r + s < 1.0 else 0.99
ratios_cache[key] = r
```

- `quick_ratio(a, b)` (`158-165`) returns 0 if either argument is None or `""`. Otherwise it is `difflib.SequenceMatcher(None, a.split("\n"), b.split("\n")).quick_ratio()`, a multiset-intersection bound: `2*matches/(len_a+len_b)`.
- **r == 1.0 happens only through:** equal `bytes_hash`; `v5 == 1`; or a max of 1.0 from v1, v2 or v4 **with `md1 == md2`**.
- `deep_ratio` (`2749-2837`) re-reads both rows with `select * from {db}.functions where address = ?` and adds, **in this order**:
  - +0.001 for the same non-empty `source_file`;
  - +0.001 for the same non-empty `pseudocode_primes`;
  - +0.001 for `indegree` equal and non-zero;
  - +0.001 for `outdegree` equal and non-zero;
  - +0.003 for `switches` equal and not `"[]"`;
  - +0.001 for `cyclomatic_complexity` equal and non-zero;
  - if main `constants != "[]"`: `len(set(json(main)) ∩ set(json(diff)))` times 0.006 on the same CPU or 0.008 otherwise;
  - an ML bonus only if a classifier is loaded (not by default).
  - Use Python double arithmetic in that same order.

---

## 9. Column encodings produced by the exporter

These matter for predicates. All references are `diaphora_ida.py` unless noted.

| Column | Encoding / typical values |
|---|---|
| `name` | `demangled or true_name` (`2448-2453`). May repeat if demangled names collide. Whether that happens in general is **NOT DETERMINED FROM SOURCE**. **Real exports:** 0 duplicate `name` values and 0 duplicate `mangled_function` values in all seven exports. That includes the three PDB exports, where `name` is a long-form demangled string (for example `public: static long _tlgWriteTemplate<...>::Write<...>(...)`) for 393/643, 411/663 and 772/1442 rows. `name like 'nullsub%'` matches 0 rows in all seven. The `sub_`-prefixed name counts are: `ls-old` 192/304, `ls` 193/318, `sechost-9168-pdb` 2/1442, `sechost-9444-nopdb` 1173/1419, `userenv-9168-pdb` 0/643, `userenv-9278-nopdb` 545/628 and `userenv-9278-pdb` 0/663. So in a PDB-vs-PDB pair, NAMECOMPAT and SUBEITHER reduce almost entirely to exact name equality, and SUBEITHER almost never passes. |
| `mangled_function` | Raw IDA name (`true_name`). |
| `address` | `str(int ea)` (decimal text); `unique`. |
| `rva` | `f - base`, stored as decimal text; `unique`. |
| `segment_rva` | `current_head - segm_start(current_head)`, where `current_head` is the **last** head processed, not the entry (`3004`). |
| `bytes_hash`, `function_hash` | `md5(...).hexdigest()` (`2977-2978`); never NULL or empty. |
| `mnemonics`, `names` | `json.dumps(list, ensure_ascii=False)`; empty list is `"[]"`. `names` is sorted (`3010-3011`). |
| `md_index` | `0`, stored as text `"0"`, when there is no topology; otherwise `str(Decimal)`, e.g. `"0.70710678..."` (`2514-2538`). |
| `kgh_hash` | `str(int ≥ 1)`, or `"NO-FUNCTION"` / `"NO-FLOW-GRAPH"` (`jkutils/graph_hashes.py:100-180`). |
| `mnemonics_spp` | Product of primes, starting from `1` (`3084`), stored as text. It is multiplied once per instruction by `mnemonics_spp_mult` (`2847`), which is `1` when the mnemonic is not in `cpu_ins_list` (`2712-2714`), so `'1'` is possible even for long functions. **Real exports:** 0 rows with `mnemonics_spp = '1'` and `instructions > 5`. |
| `microcode_spp` | `1` when there is no microcode (`2659`); otherwise a product. Text. |
| `clean_microcode` | `None` when there is no microcode (`2660`). |
| `pseudocode`, `pseudocode_hash1..3`, `pseudocode_primes` | `None` without the decompiler; `pseudocode_lines` is 0 (`2540-2566`). An empty fuzzy hash becomes `None`. |
| `clean_pseudo` | `None` when `pseudo` is `None` (`diaphora.py:1053-1054`). |
| `clean_assembly` | Cleaned text; `""` if cleaning raised an exception (`2959-2963`). |
| `constants` | JSON list mixing ints (possibly repeated) and deduped strings. `constants_count = len(list)`. |
| `constants` **table** | Rows `(func_id, constant text)` for each string longer than 4 characters, and each int/float/Decimal as `str()` (`diaphora.py:985-998`). **Repeats are possible**, since ints are appended per operand. Values below 0x1000 and single-bit flags are filtered out at export (`2412-2434`). |
| `primes_value` | `str(primes[cc])`, where cc is the cyclomatic complexity, or `0` on overflow (`2969-2973`). |
| `compilation_units` | `name` is the LFA module name, possibly `''` (inserted raw at `3370-3371`; many real CUs have `''`, §6.2). `pseudocode_primes`/`primes_value` are set by the `update` at `3351-3355`. They start as `1` (`3312-3315`) and are multiplied per function (`3322-3330`), so a CU with no decompiled function has `pseudocode_primes = '1'`, and every such CU equals every other one in H15. `compilation_unit_functions` is `insert or ignore` and each function is assigned at most once (`dones`, `3379-3381`). Real exports: 0 functions in more than one CU. |

---

## 10. Heuristics H01-H28

Common SQL fragments (verbatim) used below:

- **NAMECOMPAT** is `((f.name = df.name and substr(f.name, 1, 4) != 'sub_') or (substr(f.name, 1, 4) = 'sub_' or substr(df.name, 1, 4) = 'sub_'))`. Its C++ form is `(nn(f.name) && nn(df.name) && f.name == df.name && !sw(f.name,"sub_")) || (nn(f.name) && sw(f.name,"sub_")) || (nn(df.name) && sw(df.name,"sub_"))`, where `nn` means not NULL and `sw` means byte `starts_with`. `substr` counts characters, but `'sub_'` is ASCII, so byte and character prefixes agree.
- **NOTNULLSUB(x)** is `x.name not like 'nullsub%'`, i.e. `nn(x.name) && !starts_with_ascii_ci(x.name, "nullsub")`.
- **SUBEITHER** is `(substr(f.name, 1, 4) = 'sub_' or substr(df.name, 1, 4) = 'sub_')`. `==` is the same operator as `=` in SQLite.
- Every row also passes through `check_match` (5.1): the Python-side `nullsub_` filter, `has_best_match` and `has_better_match`.

"Runs by default?" assumes the runner executes at all, which requires §1.2 not to trigger. It also requires that not all functions are already matched (§4.4).

"Exec order" is the position in the reversed run list of that category when every flag passes.

---

### H01: Same RVA and hash (`diaphora_heuristics.py:89-107`)

```python
NAME = "Same RVA and hash"
HEURISTICS.append({
  "name":NAME,
  "category":"Best",
  "ratio":HEUR_TYPE_NO_FPS,
  "sql":""" select """ + get_query_fields(NAME) + """
              from functions f,
                   diff.functions df
             where (df.rva = f.rva
                 or df.segment_rva = f.segment_rva)
               and df.bytes_hash = f.bytes_hash
               and df.instructions = f.instructions
               and ((f.name = df.name and substr(f.name, 1, 4) != 'sub_')
                 or (substr(f.name, 1, 4) = 'sub_' or substr(df.name, 1, 4) = 'sub_'))
               and f.nodes >= 3
               and df.nodes >= 3
               %POSTFIX%""",
  "flags":[HEUR_FLAG_SAME_CPU]
})
```

- **Predicate:** `(rva== || segment_rva==)` (text) && `bytes_hash==` (text) && `instructions==` && NAMECOMPAT && `f.nodes>=3` && `df.nodes>=3`.
- **Reads:** `functions`: `rva`, `segment_rva`, `bytes_hash`, `instructions`, `name`, `nodes`, plus `SELECT_FIELDS`. No DISTINCT, no ORDER BY.
- **Output:** NO_FPS via `add_matches_from_query(sql, "best")`, giving item ratio `1` in `best`. The description is `Same RVA and hash`. **Exec order:** 12th of 12, i.e. last in the Best pass.
- **Subtle:** `segment_rva` is based on the *last* head, so the `or` clause can match unrelated functions whose tail offsets coincide. `bytes_hash` equality means `check_ratio` returns 1.0, so `has_better_match` cannot block the pair by ratio.
- **Runs by default?** Yes, when `is_same_processor` holds (`diaphora.py:1506-1508`, flags `[HEUR_FLAG_SAME_CPU]`).

### H02: Same order and hash (`109-127`)

```python
NAME = "Same order and hash"
HEURISTICS.append({
  "name":NAME,
  "category":"Best",
  "ratio":HEUR_TYPE_NO_FPS,
  "sql":""" select """ + get_query_fields(NAME) + """
              from functions f,
                   diff.functions df
             where df.id = f.id
               and df.bytes_hash = f.bytes_hash
               and df.instructions = f.instructions
               and ((f.name = df.name and substr(f.name, 1, 4) != 'sub_')
                 or (substr(f.name, 1, 4) = 'sub_' or substr(df.name, 1, 4) = 'sub_'))
               and ((f.nodes > 1 and df.nodes > 1
                 and f.instructions > 5 and df.instructions > 5)
                  or f.instructions > 10 and df.instructions > 10)
               %POSTFIX%""",
  "flags":[HEUR_FLAG_SAME_CPU]
})
```

- **Predicate:** `id==` (rowid, i.e. the same export position) && `bytes_hash==` && `instructions==` && NAMECOMPAT && `((nodes>1 both && instr>5 both) || (instr>10 both))`. AND binds tighter than OR, so the last clause parses as `(A) or (B and C)`.
- **Output:** NO_FPS into `best`. **Exec order:** 11th of 12.
- **Runs by default?** Yes, if on the same CPU.

### H03: Function Hash (`129-143`)

```python
NAME = "Function Hash"
HEURISTICS.append({
  "name":NAME,
  "category":"Best",
  "ratio":HEUR_TYPE_NO_FPS,
  "sql":""" select distinct """ + get_query_fields(NAME) + """
              from functions f,
                   diff.functions df
             where f.function_hash = df.function_hash 
               and ((f.nodes > 1 and df.nodes > 1
                 and f.instructions > 5 and df.instructions > 5)
                  or f.instructions > 10 and df.instructions > 10)
               %POSTFIX%""",
  "flags":[HEUR_FLAG_SAME_CPU]
})
```

- **Predicate:** `function_hash==` && the same size clause as H02. **No name check**, so it can match `named_a` to `named_b`.
- DISTINCT is a no-op on row content, and scan order is kept.
- **Output:** NO_FPS into `best`. `bytes_hash` may differ, so `r` from `check_ratio` can be below 1. The row is still added at 1.0 unless `has_better_match(r)` blocks it. **Exec order:** 10th.
- **Runs by default?** Yes, if on the same CPU.

### H04: Bytes hash (`145-157`)

```python
NAME = "Bytes hash"
HEURISTICS.append({
  "name":NAME,
  "category":"Best",
  "ratio":HEUR_TYPE_NO_FPS,
  "sql":""" select distinct """ + get_query_fields(NAME) + """
              from functions f,
                   diff.functions df
             where f.bytes_hash = df.bytes_hash
               and f.instructions > 5 and df.instructions > 5
               %POSTFIX%""",
  "flags":[HEUR_FLAG_SAME_CPU]
})
```

- **Predicate:** `bytes_hash==` && `instr>5` on both sides. There is no name check and no instruction-equality check (equal hashes imply equal bytes anyway).
- **Output:** NO_FPS into `best`. **Exec order:** 9th.
- **Duplicates:** when one main function shares a bytes_hash with several diff functions, the first row wins and the rest are rejected by `has_best_match`.
- **Runs by default?** Yes, if on the same CPU.

### H05: Same address and mnemonics (`159-176`)

```python
NAME = "Same address and mnemonics"
HEURISTICS.append({
  "name":NAME,
  "category":"Best",
  "ratio":HEUR_TYPE_RATIO,
  "sql":""" select distinct """ + get_query_fields(NAME) + """
              from functions f,
                   diff.functions df
             where df.address = f.address
               and df.mnemonics = f.mnemonics
               and df.instructions = f.instructions
               and df.instructions > 5
               and ((f.name = df.name and substr(f.name, 1, 4) != 'sub_')
                 or (substr(f.name, 1, 4) = 'sub_' or substr(df.name, 1, 4) = 'sub_'))
               %POSTFIX%
             order by f.source_file = df.source_file""",
  "flags":[]
})
```

- **Predicate:** `address==` (text) && `mnemonics==` (JSON text) && `instructions==` && `df.instructions>5` (which implies both, given equality) && NAMECOMPAT. Address is unique, so there is at most one row per main function.
- **Output:** RATIO with val=0.5. **Exec order:** 8th. **This is not a 1.0 heuristic:** r==1 goes to `best`, `0.5≤r<1` goes to `partial`, and anything lower is dropped.
- **Runs by default?** Yes, with no CPU flag.

### H06: Same cleaned assembly (`178-193`)

```python
NAME = "Same cleaned assembly"
HEURISTICS.append({
  "name":NAME,
  "category":"Best",
  "ratio":HEUR_TYPE_RATIO,
  "sql":""" select """ + get_query_fields(NAME) + """
        from functions f,
             diff.functions df
       where f.clean_assembly = df.clean_assembly
         and f.nodes >= 3 and df.nodes >= 3
         and f.name not like 'nullsub%'
         and df.name not like 'nullsub%'
         %POSTFIX%
       order by f.source_file = df.source_file""",
  "flags":[HEUR_FLAG_SAME_CPU]
})
```

- **Predicate:** `clean_assembly==` (text; **`''` matches `''`**) && `nodes>=3` on both sides && NOTNULLSUB on both sides.
- **Output:** RATIO with val=0.5. **Exec order:** 7th. With identical non-empty clean assembly, `v2 = 1.0`. r is then 1.0 when `md1 == md2` (the `1758-1764` rule; `md > 0` is not required for this), or when `bytes_hash` is equal (`1681-1683`), or when `v5 == 1`, i.e. identical non-empty clean microcode (`1751-1753`). Otherwise r is the best non-1.0 term plus `deep_ratio`, which sends the pair to partial or drops it.
- **Runs by default?** Yes, if on the same CPU.

### H07: Same cleaned microcode (`195-210`)

```python
NAME = "Same cleaned microcode"
HEURISTICS.append({
  "name":NAME,
  "category":"Best",
  "ratio":HEUR_TYPE_RATIO,
  "sql":""" select """ + get_query_fields(NAME) + """
        from functions f,
             diff.functions df
       where f.clean_microcode = df.clean_microcode
         and f.instructions > 3 and df.instructions > 3
         and f.name not like 'nullsub%'
         and df.name not like 'nullsub%'
         %POSTFIX%
       order by f.source_file = df.source_file""",
  "flags":[HEUR_FLAG_SAME_CPU]
})
```

- **Predicate:** `clean_microcode==` (NULL when there is no microcode, which excludes the row) && `instr>3` on both sides && NOTNULLSUB on both sides.
- **Output:** RATIO. When the equal `clean_microcode` is non-empty, `v5` is exactly 1, so `check_ratio` returns 1.0 at `1751-1753` (or 1.0 comes earlier from equal `bytes_hash`), and those rows land in `best`. If both sides are `''`, SQL still matches them, but `quick_ratio` returns 0 for empty buffers (`150-155`), so r comes from the other terms. **Exec order:** 6th.
- **Runs by default?** Yes, if on the same CPU. It needs microcode in the export (IDA with Hex-Rays and `EXPORTING_USE_MICROCODE`).

### H08: Same cleaned pseudo-code (`212-227`)

```python
NAME = "Same cleaned pseudo-code"
HEURISTICS.append({
  "name":NAME,
  "category":"Best",
  "ratio":HEUR_TYPE_RATIO,
  "sql":""" select """ + get_query_fields(NAME) + """
        from functions f,
             diff.functions df
       where f.clean_pseudo = df.clean_pseudo
         and f.pseudocode_lines > 5 and df.pseudocode_lines > 5
         and f.name not like 'nullsub%'
         and df.name not like 'nullsub%'
         %POSTFIX%
       order by f.source_file = df.source_file""",
  "flags":[]
})
```

- **Predicate:** `clean_pseudo==` && `pseudocode_lines>5` on both sides && NOTNULLSUB on both sides.
- **Output:** RATIO. `v1 = 1` (identical non-empty cleaned pseudo-code) survives as 1.0 only with `md1 == md2`. r can still be 1.0 through equal `bytes_hash` or `v5 == 1`, independently of md. **Exec order:** 5th.
- **Runs by default?** Yes, with no CPU flag. It needs decompiler output.

### H09: Same address, nodes, edges and mnemonics (`229-248`)

```python
NAME = "Same address, nodes, edges and mnemonics"
HEURISTICS.append({
  "name":NAME,
  "category":"Best",
  "ratio":HEUR_TYPE_RATIO,
  "sql":"""select """ + get_query_fields(NAME) + """
       from functions f,
            diff.functions df
      where f.rva = df.rva
        and f.instructions = df.instructions
        and f.nodes = df.nodes
        and f.edges = df.edges
        and f.mnemonics = df.mnemonics
        and f.instructions > 3
        and df.instructions > 3
        and f.nodes > 1
        %POSTFIX%
      order by f.source_file = df.source_file""",
  "flags":[]
})
```

- **Predicate:** `rva==` (the name says "address", but the column is **rva**) && `instructions==` && `nodes==` && `edges==` && `mnemonics==` && `instr>3` on both sides && `f.nodes>1`. There is **no name check** and no CPU flag.
- **Output:** RATIO. **Exec order:** 4th. The synthetic trace produced a `partial` item from this Best heuristic.
- **Runs by default?** Yes. **Not implemented in our code.**

### H10: Same RVA (`250-267`)

```python
NAME = "Same RVA"
HEURISTICS.append({
  "name":NAME,
  "category":"Best",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":""" select distinct """ + get_query_fields(NAME) + """
              from functions f,
                   diff.functions df
             where df.rva = f.rva
               and ((f.name = df.name and substr(f.name, 1, 4) != 'sub_')
                or (substr(f.name, 1, 4) = 'sub_' or substr(df.name, 1, 4) = 'sub_'))
               and  f.nodes >= 3
               and df.nodes >= 3
               %POSTFIX%
             order by f.source_file = df.source_file""",
  "min":0.7,
  "flags":[HEUR_FLAG_SAME_CPU]
})
```

- **Predicate:** `rva==` && NAMECOMPAT && `nodes>=3` on both sides.
- **Output:** RATIO_MAX with val=0.7: r==1 goes to `best`, `0.7≤r<1` goes to `partial`, anything lower is dropped. **Exec order:** 3rd. The synthetic trace produced a `partial` item.
- **Runs by default?** Yes, if on the same CPU. **Not implemented.**

### H11: Equal assembly or pseudo-code (`269-297`)

```python
#
# Seems not to find anything?
#
NAME = "Equal assembly or pseudo-code"
HEURISTICS.append({
  "name":NAME,
  "category":"Best",
  "ratio":HEUR_TYPE_NO_FPS,
  "sql":"""select """ + get_query_fields("Equal pseudo-code") + """
       from functions f,
            diff.functions df
      where f.pseudocode = df.pseudocode
        and df.pseudocode is not null
        and f.pseudocode_lines >= 5
        and f.name not like 'nullsub%'
        and df.name not like 'nullsub%'
        %POSTFIX%
      union
     select """ + get_query_fields("Equal assembly") + """
       from functions f,
            diff.functions df
      where f.assembly = df.assembly
        and df.assembly is not null
        and f.instructions >= 4 and df.instructions >= 4
        and f.name not like 'nullsub%'
        and df.name not like 'nullsub%'
        %POSTFIX% """,
  "flags":[]
})
```

- **Predicate, arm 1:** `pseudocode==` && `df.pseudocode not null` && `f.pseudocode_lines>=5` && NOTNULLSUB on both sides.
- **Predicate, arm 2:** `assembly==` && `df.assembly not null` && `instr>=4` on both sides && NOTNULLSUB on both sides.
- **Postfix:** appears in both arms.
- **Description:** `Equal pseudo-code` or `Equal assembly`, **not** the heuristic name.
- **Row order:** the UNION temp B-tree yields rows **sorted by the full SELECT row** (6.5). When a pair is in both arms, the `Equal assembly` row comes first.
- **Output:** NO_FPS into `best`. **Exec order:** 2nd. The synthetic trace gave 25 best items.
- **Flags:** `[]`, so there is no CPU check, even though raw assembly is compared.
- **Runs by default?** Yes. **Not implemented.**

### H12: Microcode mnemonics small primes product (`299-317`)

```python
NAME = "Microcode mnemonics small primes product"
HEURISTICS.append({
  "name":NAME,
  "category":"Best",
  "ratio":HEUR_TYPE_RATIO,
  "sql":""" select """ + get_query_fields(NAME) + """
        from functions f,
             diff.functions df
       where f.microcode_spp = df.microcode_spp
         and f.microcode_spp != 1
         and df.microcode_spp != 1
         and f.instructions > 5 and df.instructions > 5
         and f.nodes > 2 and df.nodes > 2
         and f.name not like 'nullsub%'
         and df.name not like 'nullsub%'
         %POSTFIX%
       order by f.source_file = df.source_file""",
  "flags":[]
})
```

- **Predicate:** `microcode_spp==` (text) && `microcode_spp != '1'` on both sides && `instr>5` on both sides && `nodes>2` on both sides && NOTNULLSUB on both sides. TEXT affinity turns the literal `1` into `'1'`. NULL is excluded by NULL semantics, not by affinity, and real exports have no NULL `microcode_spp` anyway (§6.2).
- **Output:** RATIO. **Exec order:** 1st, so it runs **first** in the Best pass. **Real exports:** it is the dominant Best-pass producer: 348 partial + 80 best items on `userenv-9168-pdb` vs `userenv-9278-nopdb`, and 14 best + 3 partial on `ls-old` vs `ls` (§5.4).
- **Runs by default?** Yes. It needs microcode. **Not implemented.**

### H13: Same named compilation unit function match (`319-351`)

```python
NAME = "Same named compilation unit function match"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX_TRUSTED,
  "sql":"""  select """ + get_query_fields(NAME) + """
               from main.compilation_units main_cu,
                    main.compilation_unit_functions mcuf,
                    main.functions f,
                    diff.compilation_units diff_cu,
                    diff.compilation_unit_functions dcuf,
                    diff.functions df
              where main_cu.name != ''
                and diff_cu.name != ''
                and main_cu.name = diff_cu.name
                and f.id = mcuf.func_id
                and df.id = dcuf.func_id
                and mcuf.cu_id = main_cu.id
                and dcuf.cu_id = diff_cu.id
                and df.primes_value = f.primes_value
                and df.nodes = f.nodes
                and f.nodes >= 5
                %POSTFIX% 
                """,
  "min":0.44,
  "flags":[]
})
```

- **Predicate:** both functions belong to compilation units with the **same non-empty, non-NULL name**; `primes_value==` (text prime of the cyclomatic complexity); `nodes==`; `f.nodes>=5`.
- **Reads:** `compilation_units(id,name)`, `compilation_unit_functions(cu_id,func_id)` and `functions.primes_value, nodes` on both sides. No DISTINCT, no ORDER BY. Each function is in at most one CU, so each pair appears once.
- **Output:** RATIO_MAX_TRUSTED with val=0.44: r==1 goes to `best`, `r≥0.44` goes to `partial`, anything lower is **dropped** (the "trusted" unreliable branch is dead, see 4.2). It is never demoted. **Exec order:** last of the Partial pass.
- **Runs by default?** Yes. It needs CUs in the export (`EXPORTING_COMPILATION_UNITS=True`, which relies on LFA finding modules). **Not implemented.**
- **Real exports:** 1685 rows for `userenv-9168-pdb` vs `userenv-9278-nopdb`. 1680 of them come from the single CU `onecore\ds\security\gina\profile\userenv\lib\copydir.cpp`, which covers 580 functions in main and 576 in diff. Every `(nodes, primes_value)`-equal pair inside it qualifies. The run appended 239 **partial** items. There are 0 rows for `ls`/`ls-old`, where most CU names are `''`.

### H14: Same anonymous compilation unit function match (`353-379`)

```python
NAME = "Same anonymous compilation unit function match"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""  select """ + get_query_fields(NAME) + """
               from main.compilation_units main_cu,
                    main.compilation_unit_functions mcuf,
                    main.functions f,
                    diff.compilation_units diff_cu,
                    diff.compilation_unit_functions dcuf,
                    diff.functions df
              where main_cu.name != ''
                and diff_cu.name != ''
                and main_cu.name = diff_cu.name
                and f.id = mcuf.func_id
                and df.id = dcuf.func_id
                and mcuf.cu_id = main_cu.id
                and dcuf.cu_id = diff_cu.id
                and df.pseudocode_primes = f.pseudocode_primes
                and df.nodes = f.nodes
                and f.nodes >= 5
                %POSTFIX% 
              order by f.source_file = df.source_file""",
  "min":0.449,
  "flags":[]
})
```

- **Predicate:** the same CU-name conditions as H13. **Despite the name, it requires a non-empty CU name.** It then requires `pseudocode_primes==` (NULL without the decompiler), `nodes==` and `f.nodes>=5`.
- **Output:** RATIO_MAX with val=0.449. **Exec order:** second to last.
- **Runs by default?** Yes. It needs CUs and pseudocode. **Not implemented.**

### H15: Same compilation unit (`381-412`)

```python
NAME = "Same compilation unit"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO,
  "sql":"""select """ + get_query_fields(NAME) + """
                from main.compilation_units mcu,
                  main.compilation_unit_functions mcuf,
                  main.functions f,
                  diff.compilation_units dcu,
                  diff.compilation_unit_functions dcuf,
                  diff.functions df
              where dcu.pseudocode_primes = mcu.pseudocode_primes
                and mcuf.cu_id = mcu.id
                and dcuf.cu_id = dcu.id
                and f.id = mcuf.func_id
                and df.id = dcuf.func_id
                and f.nodes > 4
                and df.nodes > 4
                and (substr(f.name, 1, 4) = 'sub_' or substr(df.name, 1, 4) == 'sub_')
                %POSTFIX% """,
  "flags":[HEUR_FLAG_SLOW]
})
```

- **Predicate:** both CUs have equal `pseudocode_primes`, with no CU-name condition; `nodes>4` on both sides; SUBEITHER. The source comments at `381-389` note that the ORDER BY was deliberately removed.
- **Output:** RATIO with val=0.5.
- **Runs by default?** **Yes** in standalone mode, because `slow_heuristics` is True regardless of size (§1.3). **Not implemented.**

### H16: Same KOKA hash and constants (`414-434`)

```python
NAME = "Same KOKA hash and constants"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO,
  "sql":"""select """ + get_query_fields(NAME) + """
       from main.constants mc,
            diff.constants dc,
            main.functions  f,
            diff.functions df
      where mc.constant = dc.constant
        and  f.id = mc.func_id
        and df.id = dc.func_id
        and f.kgh_hash = df.kgh_hash
        and f.nodes >= 3
        %POSTFIX% """,
  "flags":[]
})
```

- **Predicate:** at least one equal `(mc.constant, dc.constant)` text pair between the functions; `kgh_hash==`; `f.nodes>=3`.
- **Multiplicity:** there is **one row per equal constant-row pair**, with no DISTINCT (see the comment at `414-416`). Repeated constants multiply the rows. Real exports do contain repeated `(func_id, constant)` rows: 32 groups in `ls`, 54 in `userenv-9168-pdb` and 341 in `sechost-9168-pdb`.
- **CORRECTED:** the original text said "The duplicates are idempotent in `add_match`". That is true only of the **item list**, because `if item not in self.all_matches[chooser]` stops a second append (`1370`). The `matched_*` state is not idempotent. Example with non-`sub_` names, rows in order `(A,X,0.8)`, `(A,Y,0.9)`, then the duplicate `(A,X,0.8)`:
  - The duplicate passes `has_better_match`, because of the early return `return self.matched_primary[name1]["name"] == name1`, which gives `'Y' == 'A'` → False.
  - `add_match` then overwrites `matched_primary[A]` back to `{X, 0.8}` and re-sets `matched_secondary[X]`.
  - With `sub_` names, the duplicate is rejected by `0.9 > 0.8` instead.
  - Duplicates also count toward the 1,000,000-row cap.
- **Output:** RATIO.
- **Runs by default?** Yes. **Not implemented.** It needs the `constants` table.

### H17: Same KOKA hash and MD-Index (`436-457`)

```python
NAME = "Same KOKA hash and MD-Index"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO,
  "sql":"""
     select """ + get_query_fields(NAME) + """
       from functions f,
            diff.functions df
      where f.kgh_hash = df.kgh_hash
        and f.md_index = df.md_index
        and f.nodes = df.nodes
        and f.nodes >= 4
        and f.outdegree = df.outdegree
        and f.indegree  = df.indegree
        and (substr(f.name, 1, 4) = 'sub_' or substr(df.name, 1, 4) = 'sub_')
        %POSTFIX%
        """,
  "flags":[]
})
```

- **Predicate:** `kgh_hash==` && `md_index==` (text) && `nodes==` && `f.nodes>=4` && `outdegree==` && `indegree==` && SUBEITHER.
- **Output:** RATIO. r==1 goes to **`best`**, `≥0.5` goes to `partial`.
- **Runs by default?** Yes. **Implemented.**

### H18: Same constants (`459-474`)

```python
NAME = "Same constants"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""select """ + get_query_fields(NAME) + """
       from functions f,
            diff.functions df
      where f.constants = df.constants
        and f.constants_count = df.constants_count
        and f.constants_count > 1
        %POSTFIX%
      order by f.source_file = df.source_file""",
  "min":0.5,
  "flags":[]
})
```

- **Predicate:** `constants==` (JSON text, which is order-sensitive) && `constants_count==` && `f.constants_count>1`.
- **Output:** RATIO_MAX with val=0.5, which behaves the same as RATIO here.
- **Runs by default?** Yes. **Implemented.**

### H19: Same rare KOKA hash (`476-510`)

```python
NAME = "Same rare KOKA hash"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""
with shared_hashes as (
 select kgh_hash
   from diff.functions
  where kgh_hash != 0
  group by kgh_hash
 having count(*) <= 2
  union 
 select kgh_hash
   from main.functions
  where kgh_hash != 0
  group by kgh_hash
 having count(*) <= 2
)
select """ + get_query_fields(NAME) + """
  from functions f,
       diff.functions df,
       shared_hashes
 where f.kgh_hash = df.kgh_hash
   and df.kgh_hash = shared_hashes.kgh_hash
   and f.nodes > 5
   and (substr(f.name, 1, 4) = 'sub_'
     or substr(df.name, 1, 4) = 'sub_')
   %POSTFIX%
        """,
  "min":0.45,
  "flags":[]
})
```

- **CTE:** the set of kgh values `v` with `v != '0'` and `v` not NULL (**`''` is included**, §6.1), such that `count_in_diff(v) <= 2` **or** `count_in_main(v) <= 2`. Groups use BINARY text comparison.
- **Predicate:** `kgh==` && the value is in the CTE && `f.nodes>5` (main only) && SUBEITHER. A value rare on one side and common on the other still qualifies, so all cross pairs appear.
- **Output:** RATIO_MAX with val=**0.45**, which accepts `0.45≤r<0.5` into partial.
- **Runs by default?** Yes. **Implemented.**

### H20: Same rare MD Index (`512-541`)

```python
NAME = "Same rare MD Index"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO,
  "sql":"""
     with shared_mds as (
      select md_index
        from diff.functions
       where md_index != 0
       group by md_index
      having count(*) <= 2
      union 
      select md_index
        from main.functions
       where md_index != 0
       group by md_index
      having count(*) <= 2
     )
     select """ + get_query_fields(NAME) + """
       from functions f,
            diff.functions df,
            shared_mds
      where f.md_index = df.md_index
        and df.md_index = shared_mds.md_index
        and f.nodes > 10
        %POSTFIX%
      order by f.source_file = df.source_file""",
  "flags":[]
})
```

- **CTE:** like H19, over `md_index` with `!= '0'`.
- **Predicate:** `md_index==` && the value is in the CTE && `f.nodes>10` (main only).
- **Output:** RATIO with val=0.5. The record has no `min`.
- **Runs by default?** Yes. **Implemented.**

### H21: Same address and rare constant (`543-564`)

```python
NAME = "Same address and rare constant"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""select distinct """ + get_query_fields(NAME) + """
       from main.constants mc,
            diff.constants dc,
            main.functions  f,
            diff.functions df
      where mc.constant = dc.constant
        and  f.id = mc.func_id
        and df.id = dc.func_id
        and df.address = f.address
        %POSTFIX%
      order by f.source_file = df.source_file""",
  "min":0.5,
  "flags":[]
})
```

- **Predicate:** same `address` && at least one shared constant. **Nothing enforces rarity** despite the name. DISTINCT collapses the constant multiplicity to one row per pair.
- **Output:** RATIO_MAX with val=0.5.
- **Runs by default?** Yes. **Not implemented.**

### H22: Same rare constant (`566-585`)

```python
NAME = "Same rare constant"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""select """ + get_query_fields(NAME) + """
       from main.constants mc,
            diff.constants dc,
            main.functions  f,
            diff.functions df
      where mc.constant = dc.constant
        and  f.id = mc.func_id
        and df.id = dc.func_id
        and f.nodes >= 3 and df.nodes >= 3
        and f.constants_count > 0
        %POSTFIX% """,
  "min":0.2,
  "flags":[HEUR_FLAG_SLOW]
})
```

- **Predicate:** at least one shared constant && `nodes>=3` on both sides && `f.constants_count>0`. **Nothing enforces rarity.** There is no DISTINCT, so there is one row per matching constant pair. This is the most likely heuristic to hit the 1,000,000-row cap: common constants create a cartesian explosion.
- **Output:** RATIO_MAX with val=**0.2**, which accepts `0.2≤r<0.5` into partial.
- **Runs by default?** **Yes** in standalone mode (the SLOW flag is on).

### H23: Same MD Index and constants (`587-603`)

```python
NAME = "Same MD Index and constants"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO,
  "sql":""" select distinct """ + get_query_fields(NAME) + """
        from functions f,
             diff.functions df
       where f.md_index = df.md_index
         and f.md_index > 0
         and f.nodes >= 3 and df.nodes >= 3
         and ((f.constants = df.constants
         and f.constants_count > 0))
        %POSTFIX%
      order by f.source_file = df.source_file""",
  "flags":[]
})
```

- **Predicate:** `md_index==` && `f.md_index > '0'` (**text**, §6.1) && `nodes>=3` on both sides && `constants==` && `f.constants_count>0`.
- **Output:** RATIO. The observed plan used df as the outer table.
- **Runs by default?** Yes. **Not implemented.**

### H24: Import names hash (`605-621`)

```python
NAME = "Import names hash"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO,
  "sql":"""select distinct """ + get_query_fields(NAME) + """
              from functions f,
                  diff.functions df
            where f.names = df.names
              and f.names != '[]'
              and f.md_index = df.md_index
              and f.instructions = df.instructions
              and f.nodes > 5 and df.nodes > 5
              %POSTFIX%
            order by f.source_file = df.source_file""",
  "flags":[]
})
```

- **Predicate:** `names==` (sorted JSON) && `f.names!='[]'` && `md_index==` && `instructions==` && `nodes>5` on both sides.
- **Output:** RATIO.
- **Runs by default?** Yes. **Not implemented.**

### H25: Mnemonics and names (`623-639`)

```python
NAME = "Mnemonics and names"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO,
  "sql":""" select """ + get_query_fields(NAME) + """
        from functions f,
             diff.functions df
       where f.mnemonics = df.mnemonics
         and f.instructions = df.instructions
         and f.names = df.names
         and f.names != '[]'
         and f.instructions > 5 and df.instructions > 5
         %POSTFIX%
       order by f.source_file = df.source_file""",
  "flags":[]
})
```

- **Predicate:** `mnemonics==` && `instructions==` && `names==` && `f.names!='[]'` && `instr>5` on both sides.
- **Output:** RATIO.
- **Runs by default?** Yes. **Not implemented.**

### H26: Pseudo-code fuzzy hash (`641-660`)

```python
NAME = "Pseudo-code fuzzy hash"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO,
  "sql":"""select distinct """ + get_query_fields(NAME) + """
       from functions f,
            diff.functions df
      where df.pseudocode_hash1 = f.pseudocode_hash1
        and df.pseudocode_hash2 = f.pseudocode_hash2
        and df.pseudocode_hash3 = f.pseudocode_hash3
        and df.pseudocode_hash1 is not null
        and df.pseudocode_hash2 is not null
        and df.pseudocode_hash3 is not null
        and f.instructions > 5
        and df.instructions > 5
        %POSTFIX%
      order by f.source_file = df.source_file""",
  "flags":[]
})
```

- **Predicate:** all three `pseudocode_hashN` equal and not NULL (an empty hash is stored as NULL, see §9) && `instr>5` on both sides.
- **Output:** RATIO.
- **Runs by default?** Yes. It needs the decompiler. **Not implemented.**

### H27: Similar pseudo-code and names (`662-680`)

```python
NAME = "Similar pseudo-code and names"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""select distinct """ + get_query_fields(NAME) + """
       from functions f,
            diff.functions df
      where f.pseudocode_lines = df.pseudocode_lines
        and f.names = df.names
        and df.names != '[]'
        and df.pseudocode_lines > 5
        and df.pseudocode is not null 
        and f.pseudocode is not null
        %POSTFIX%
      order by f.source_file = df.source_file""",
  "min": 0.579,
  "flags":[]
})
```

- **Predicate:** `pseudocode_lines==` && `names==` && `df.names!='[]'` && `df.pseudocode_lines>5` && both pseudocodes not NULL.
- **Output:** RATIO_MAX with val=**0.579**, which **drops** `0.5≤r<0.579`.
- **Runs by default?** Yes. **Not implemented.**

### H28: Mnemonics small-primes-product (`682-697`)

```python
NAME = "Mnemonics small-primes-product"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":""" select """ + get_query_fields(NAME) + """
        from functions f,
             diff.functions df
       where f.mnemonics_spp = df.mnemonics_spp
         and f.instructions = df.instructions
         and f.nodes > 1 and df.nodes > 1
         and df.instructions > 5
         %POSTFIX% """,
  "min":0.6,
  "flags":[]
})
```

- **Predicate:** `mnemonics_spp==` (text) && `instructions==` && `nodes>1` on both sides && `df.instructions>5`. No DISTINCT, no ORDER BY. There is no `!= 1` guard. `instructions>5` does **not** strictly rule out `'1'`, because unknown mnemonics multiply by 1 (§9), but real exports have no such rows.
- **Output:** RATIO_MAX with val=**0.6**.
- **Runs by default?** Yes. **Not implemented.**

---

## 11. Comparison with our implementation (`src/Heuristics.cpp`)

Ours implements H01-H08 and H17-H20 (`Heuristics.cpp:298-311`). The missing in-scope heuristics are H09-H16 and H21-H28.

### 11.1 Divergences that affect all 12 implemented heuristics

| # | Diaphora | Ours | Evidence |
|---|---|---|---|
| D1 | The ratio per pair is `check_ratio` + `deep_ratio` (§8), cached per pair. | Ratio is 1.0, or 0.5 (`AmbiguousRatio`) when one main row has more than one candidate and `PenalizeAmbiguity` is set. | `Heuristics.cpp:18`, `65` |
| D2 | The output chooser comes **from r**: r==1 goes to `best`; `r≥val` goes to `partial`; anything lower is dropped. NO_FPS always goes to `best` at ratio 1. A Partial heuristic can emit `best`, and a Best RATIO heuristic can emit `partial` or nothing. | The category is fixed per definition (`Candidate.Category = Category`). There is no drop threshold and `min` is ignored. | `Heuristics.cpp:72`, `298-311`; diaphora.py:1925-1932 |
| D3 | Every row goes through `check_match`: case-sensitive `nullsub_` filter, `has_best_match`, and `has_better_match` with its name quirk. | None of these exist. | §5 |
| D4 | Execution is sequential, **in reverse definition order**, with state carried between heuristics. Rows are consumed in SQLite plan order. | All heuristics run in parallel (`ThreadPool::ParallelFor`), then a global stable sort by `(ratio desc, HeuristicId asc, Index1, Index2)` and a greedy 1:1 pass. **The priority is reversed:** for tied 1.0 matches ours prefers the *lower* id, i.e. earlier-defined heuristics, while Diaphora's first-come rule favors *later-defined* ones. | `Heuristics.cpp:380-388`; `MatchStore.cpp:41-52`, `76-115`; §3.3 |
| D5 | NO_FPS ambiguity: the first row wins and later rows sharing either name are rejected by `has_best_match`. | Every candidate is emitted at 1.0; the sort and greedy pass pick by index order. | `Heuristics.cpp:65` with `PenalizeAmbiguity=false` for H01-H04 |
| D6 | Pre-state: "100% equal" and `find_same_name` run first, then cleanup after the Best pass, then `search_small_differences` after the Partial pass. | None of these exist. | §1.1, §1.4 |
| D7 | The dirty-heuristic gate can skip the whole runner. | Always runs. | §1.2 |
| D8 | `cleanup_matches` dedups the primary ea only (ties kept), the secondary side stays duplicated, and multimatches are handled later. | Strict 1:1 on both sides. | `MatchStore.cpp:98-112` |
| D9 | `LIKE 'nullsub%'` is ASCII case-insensitive and excludes NULL names. | `IsNullSub` is a case-sensitive `StartsWith("nullsub")`. | `include/dsigmatcher/Naming.h:15-17` (corrected from `171-173`; the file has 32 lines) |
| D10 | NULL ≠ NULL and `''` = `''`. | The loader maps NULL to `""` (`ExportDatabase.cpp:98-105`) and NULL ints to 0. `JoinByKey` skips empty keys (`Heuristics.cpp:40-42`, `49-51`), so `''` keys never match. Non-key text equality treats NULL==NULL as true (mnemonics, md_index). `NameCompatible("", "")` is true (`include/dsigmatcher/Naming.h:26-30`, corrected from `182-186`) where SQL gives false. On the real exports, key columns hold NULL but never `''` (§6.2), so skipping empty keys currently gives the same result as SQL's NULL behavior on the join keys of all 12 implemented heuristics. That rests on the data, not on a guarantee. | §6.2 |
| D11 | Row cap of 1,000,000 per ratio heuristic, plus a 300 s timeout. | No cap. | §4.3 |
| D12 | Same-processor check: any `program` row pair with equal processor under SQL equality (`''`=`''` is true, NULL is false). | `main.cpp:287-290` reads the first row only and requires a non-empty value. `Provenance.cpp:351` uses plain `==`, where `""==""` is true. **The two code paths disagree with each other.** | `ExportDatabase.cpp:277` (`limit 1`) |
| D13 | The description is the heuristic name (for H11: `Equal pseudo-code` / `Equal assembly`). | Always `"best#<id>"`, even for partial matches. | `main.cpp:218` |
| D14 | The ratio is a Python double, shown as `%.7f`. | `float` (32-bit). | `Types.h:48` |
| D15 | State is keyed by function **name** (`matched_primary[name]`), so duplicate names conflate. The "100% equal" pre-pass keys by `mangled_function` instead (`diaphora.py:1435-1440`). | Keyed by row index. | §5, §1.1 |

### 11.2 Per-heuristic divergences (beyond 11.1)

- **H01 Same RVA and hash** (`Heuristics.cpp:78-96`).
  - The predicate matches, with `RvaEqual` requiring non-empty text, which agrees with SQL except in the NULL-vs-`''` corner.
  - With NULL names, SQL NAMECOMPAT is TRUE only if the other side starts with `sub_`. Ours treats `""==""` as a match.
  - Category and ratio agree (1.0, best). Missing: check_match rejection and first-come ordering.
- **H02 Same order and hash** (`98-118`). The predicate matches, including the `(A) or (B and C)` precedence. Same D-items as H01.
- **H03 Function Hash** (`120-134`). The predicate matches. Diaphora rejects a row when `check_ratio` r (possibly below 1 because bytes differ) loses to an existing match via `has_better_match`; ours never rejects.
- **H04 Bytes hash** (`136-144`). The predicate matches.
- **H05 Same address and mnemonics** (`146-159`).
  - The predicate matches: `A.Instructions[I] > 5` plus equality is equivalent to `df.instructions > 5`.
  - **The ratio type is wrong.** Diaphora uses RATIO, so the pair can become partial or be dropped. Ours always emits Best at 1.0, because the address is unique and there is never ambiguity.
  - Mnemonics NULL==NULL counts as equal in ours.
- **H06 Same cleaned assembly** (`161-173`).
  - The nullsub guard is case-sensitive (D9).
  - `''` clean_assembly pairs match in SQL but are skipped by ours.
  - The ratio is 1.0 or 0.5 in ours, versus the real ratio in Diaphora, where identical clean_asm is **not** automatically best (§H06). The category is fixed to Best in ours.
- **H07 Same cleaned microcode** (`175-187`). This is closest to parity: Diaphora's r is 1.0 through `v5`. Ours gives 0.5 when ambiguous. The nullsub case-sensitivity from D9 applies.
- **H08 Same cleaned pseudo-code** (`189-201`). Same items as H06. `RequiresSameProcessor=false` matches flags `[]`.
- **H17 Same KOKA hash and MD-Index** (`231-246`).
  - The predicate matches (`IsAutoNamed` is `starts_with("sub_")`).
  - The category is always Partial in ours, but Diaphora sends r==1 to **best**.
  - md NULL==NULL counts as equal in ours.
- **H18 Same constants** (`248-257`). The predicate matches; `min` 0.5 is ignored, and ours never drops.
- **H19 Same rare KOKA hash** (`259-274`).
  - Rarity uses `IsRare(ref) || IsRare(tgt)`, which is equivalent to the UNION CTE.
  - The exclusion set differs: `BuildRarity` skips `""` and `"0"` (`212`), while SQL skips `'0'` and NULL but **keeps `''`**. This only matters if an export contains `''` kgh values, which the exporter never writes.
  - `min` 0.45 is ignored.
  - **An earlier note ("`kgh_hash != 0` does nothing in SQLite") is incorrect.** It is `kgh_hash != '0'` (§6.1). Our behavior is accidentally right for `'0'`.
- **H20 Same rare MD Index** (`276-288`). Same exclusion-set note as H19 (md `''`). `f.nodes > 10` applies to main only, which matches.

### 11.3 What the loader must add for H09-H16 and H21-H28, and for ratio parity

- **Columns:** `pseudocode`, `assembly`, `pseudocode_primes`, `primes_value`, `names`, `pseudocode_hash1..3`, `mnemonics_spp`, `microcode_spp`, `switches`, `prototype2` (outside this scope), plus **NULL flags** for every text column.
- **Tables:** `constants`, `compilation_units`, `compilation_unit_functions`, and all `program` rows.

This whole list is moot if the SQL-replay design from §6.6 is adopted.

---

## Hard parts

1. **Row order equals SQLite plan order.** Greedy acceptance depends on it (§5.4), and the plan depends on indices, `ANALYZE` stats and data (§6.4). On real exports even the presence of `ORDER BY` or `DISTINCT` changes the plan (§6.4). The only robust way to match it is to execute the verbatim SQL with the same SQLite version (3.51.1) and `pragma threads = 0`. Our fast hash-join path can then be checked against that replay.
2. **Reverse execution order plus first-come 1.0 acceptance.** Most Best matches carry the description of whichever heuristic ran *first*, e.g. `Equal assembly` or `Microcode mnemonics small primes product`, not `Same RVA and hash`.
3. **The name-keyed state machine and its quirks:**
   - the early return in `has_better_match`;
   - the unconditional overwrite in `add_match`;
   - same-name pairs forced to 1.0, then reset to `item[5]` by cleanup;
   - cleanup keeping ratio ties and skipping secondary dedup.
4. **Ratio-driven categories.** The `check_ratio` details matter: 7-decimal formatting, the `md1 != md2` rule, the 0.99 cap, `deep_ratio` addition order, JSON-typed constant sets, and the SQLite `cast(... as real)` of md_index. The cast must be read from SQLite, not re-parsed with `strtod`: two texts differing beyond double precision can compare equal, and SQLite's conversion is not always correctly rounded (3 of 5,417 real `md_index` values differ from Python `float()` by one ULP, §2.3).
5. **The dirty-heuristic gate** can remove this entire pass. Parity tests need corpora below the 99% and 90% thresholds, or an oracle run with `DIAPHORA_EXPERIMENTAL=""` together with a matching native option. A PDB-vs-PDB pair triggers it (real `userenv` run, §1.2). The oracle's PDB-vs-no-PDB pairs and `ls`/`ls-old` do not.
6. **TEXT-affinity comparisons** (`!= 0`, `> 0`, `!= 1`) and the **NULL-vs-`''`** distinction. The loader currently loses the latter.
7. **The 1,000,000-row cap** (H16 and H22 are the likely offenders) is deterministic only when row order is reproduced. **Timeouts are not reproducible at all.**
8. **CI platforms.** Linux, macOS and Windows CI each install an unpinned SQLite (`ci.yml:38-56`), which may produce different plans, and therefore different outputs.

## Open questions

Status after the verification pass is marked on each item.

1. Will the real `win32u` exports trigger patch-diff mode (>90% same mangled names)? If so, Diaphora's default output has **no** runner matches. Should the oracle use `DIAPHORA_EXPERIMENTAL=""`, or should the dirty heuristics be ported first?
   - **Partly resolved.** There is still no `win32u` export in `dsig-corpus`, so the win32u case is **NOT DETERMINED**.
   - The real PDB-vs-PDB pair `userenv-9168-pdb` vs `userenv-9278-pdb` did trigger patch-diff mode at 100.0% (§1.2), and the runner never ran. A win32u pair with both PDBs is therefore expected to behave the same way.
   - The PDB-vs-no-PDB pairs already in the oracle (`userenv`, `sechost`) and `ls`/`ls-old` do run the runner, so they are the parity corpus for this spec as it stands.
   - Porting the dirty heuristics and `find_remaining_functions` versus running with `DIAPHORA_EXPERIMENTAL=""` is a design decision, not a source question.
2. Do real exports ever contain `''` (as opposed to NULL) in key columns such as `clean_assembly`, `kgh_hash` or `md_index`?
   - **Resolved empirically for the seven oracle exports:** there is no `''` in any of 26 probed `functions` columns (§6.2).
   - `compilation_units.name` **does** hold `''` on many rows.
   - From source, `clean_assembly` can be `''` only if cleaning raised (`diaphora_ida.py:2959-2963`).
3. Can `name` values collide within one export when `INF_SHORT_DN` demangling is used?
   - **Resolved empirically for the seven oracle exports:** there are 0 duplicate `name` values and 0 duplicate `mangled_function` values, including 393, 411 and 772 demangled names in the three PDB exports.
   - Whether collisions can happen in general remains **NOT DETERMINED FROM SOURCE**. Collisions would break name-keyed state and `all_functions_matched`.
4. Is SQLite's sorter tie-stability guaranteed across all configurations (multi-threaded sorter, `SQLITE_DEFAULT_WORKER_THREADS`)?
   - **Resolved from SQLite 3.51.1 source (§6.4).** The sort is stable when single-threaded, including PMA spills: ties take the older record or the oldest PMA.
   - With worker threads it is **not** stable across tasks.
   - The conda build defaults to `pragma threads` = 0, and Diaphora never changes it.
   - Caveat, also in §6.4: stability is relative to the ORDER BY query's **own** plan, which can differ from the plan without the ORDER BY.
5. Which SQLite versions and plans do the CI runners use? Is parity required on all three platforms, or only on the conda 3.51.1 build?
   - **Still open.** CI installs unpinned apt/brew/vcpkg SQLite (`ci.yml:38-56`), so the versions are **NOT DETERMINED** from the repository.
   - Whether parity is required on all three platforms is a policy decision.
6. Should the native tool reproduce Diaphora's `get_value_for` environment-string bug if the oracle harness sets `DIAPHORA_*` variables?
   - **Resolved for the current harness:** `tools/oracle/build_oracle.py` strips every `DIAPHORA_*` variable before the diff step (`108-115`, `284-291`), so the quirk never fires in the oracle. It needs porting only if the harness starts setting such variables.
   - An oracle run with `DIAPHORA_EXPERIMENTAL=""` would itself rely on the quirk: the raw `''` string is falsy.

---

## Verification log

An adversarial verification pass on 2026-09-23 re-checked this spec against `<diaphora-ref>` (`3.4.2-4-g621ec26`, clean `git status`; `git diff --stat 3.4.2..HEAD` touches only `README.md` and `diaphora_ida.py`) and against `src/Heuristics.cpp` at commit `34ed418`. It also used the seven real IDA 9.4 exports in `<corpus>/oracle/exports/` (copied to a scratch directory, never modified in place) and SQLite 3.51.1 source files fetched from the official `sqlite/sqlite` mirror at tag `version-3.51.1`.

**What was checked and held.**
- **Code excerpts.** Every line of every `python` block was checked. All lines appear verbatim in the source. The 28 heuristic records (H01-H28) match the source text exactly. Their line ranges include the comment headers that precede each `NAME =` line (H13 319-324, H15 381-389, H16 414-416, H17 436-437, H19 476-477, H21 543-545, H22 566).
- **Heuristic metadata.** Name, category, ratio type, `min`, flags, `%POSTFIX%` count (2 only in H11), DISTINCT and ORDER BY presence were re-derived by importing `HEURISTICS`, and all matched.
- **Counts.** `Counter` gives `{'Partial': 30, 'Best': 12, 'Unreliable': 8}` and ratios `{1: 22, 2: 22, 0: 5, 3: 1}`. There are 9 in-scope DISTINCT heuristics and 16 in-scope ORDER BY heuristics.
- **Runner and helpers.** The runner (`1461-1552`), `threads_apply` (`jkutils/threads.py:27-71`), `add_matches_*` (`1950-2083`), `add_matches_internal` (`1882-1948`), `check_match` (`1786-1872`), `has_best_match`/`has_better_match`/`add_match` (`1340-1402`), `cleanup_matches` (`1554-1605`), `check_ratio` (`1645-1775`), `deep_ratio` (`2749-2837`), the dirty gate (`2540-2637`), `get_value_for` (`560-569`) and the config defaults (`diaphora_config.py:46-205`) all match the source.
- **Real-export log order.** The reverse, sequential execution order is confirmed on the real `ls_vs_ls-old` Diaphora log.
- **Type-affinity table.** Every row of the §6.1 table was re-run against Diaphora's schema and matched.
- **Native references.** The native-code references in §11 were checked and held: `Heuristics.cpp` line refs, `MatchStore.cpp:41-52`/`76-115`, `ExportDatabase.cpp:98-105`/`277`, `main.cpp:218`/`287-290`, `Provenance.cpp:351` and `Types.h:48`. The exception is `Naming.h`; see correction 3.

**Corrections made.**
1. **§6.4 ORDER BY: false claim replaced.** The original text said "the output equals a stable sort of the no-ORDER-BY output on that key". On real exports, adding the ORDER BY changes the join plan, and the claim fails for H09, H20, H23 and H27 on at least one pair. Replaced it with this: the sort is stable relative to the ORDER BY query's own scan order (surrogate-key test, 0 failures over 16 heuristics × 5 pairs), plus the SQLite 3.51.1 source analysis.
2. **§6.4 DISTINCT: overstated claim qualified.** The original text said "The comparison held for all 9 in-scope DISTINCT heuristics". Removing `DISTINCT` changes the plan on real exports, and the order differs for H23 and H27. DISTINCT keeps the scan order of its own plan only.
3. **§11.1 D9/D10: wrong line numbers.** `Naming.h:171-173` and `182-186` do not exist; `include/dsigmatcher/Naming.h` has 32 lines. `IsNullSub` is at `15-17` and `NameCompatible` at `26-30`.
4. **§1.3 `use_trained_model`: wrong reason.** `self.classifier` is `None` during the Best and Partial passes **regardless** of the flag, because `apply_machine_learning` (`3551-3555`) runs only after `find_partial_matches()` (`3634-3636`).
5. **§1.1 step 1 / §1.4 / §4.4 / D15: missed keying.** `find_equal_matches` keys `matched_*` and fills the item's name fields with `mangled_function`, not `name` (`1435-1440`). Added the consequences for `has_best_match` and `all_functions_matched`, with real counts of `name != mangled_function` (393/643, 411/663, 772/1442 in the three PDB exports).
6. **§1.4: imprecise `find_same_name` rule.** The `+0.01` bonus applies only if `ratio + 0.01 < 1.0` (`2203-2204`). The best item ratio is int `1`. The `relaxed_ratio` clause, the `sub_` skip (`2179-2180`, `ignore_sub_names` from config at `468`) and the `'nullsub_%'` wildcard guard (`2166`) were added.
7. **H16: wrong idempotence claim.** "Duplicates are idempotent in `add_match`" holds only for the item list (`1370`). `matched_*` can be re-overwritten through the non-`sub_` early return in `has_better_match`. A worked example was added.
8. **H06/H08: overstated 1.0 condition.** "1.0 only if/with `md1 == md2`" ignored equal `bytes_hash` (`1681-1683`) and `v5 == 1` (`1751-1753`).
9. **H12: wrong mechanism.** NULL exclusion comes from NULL semantics, not from TEXT affinity.
10. **H28 / §9 `mnemonics_spp`: overconfident claim.** "No `!= 1` guard is needed since `instructions>5`" is not guaranteed, because unknown mnemonics multiply by 1 (`diaphora_ida.py:2712-2714`, `2847`). Real exports have no such rows.
11. **§3.3: ambiguous names.** The Partial-order entries `(reverse)`, `(mixed)`, `(normal)` now name `Pseudo-code fuzzy (...)` (heuristics 33-35), to separate them from the skipped `Partial pseudo-code fuzzy hash (...)` (37-39).
12. **§4.2 / §2.3 / §1.1: omissions presented as verbatim.** The excerpts labeled "verbatim" silently omitted a docstring or signature. They are now marked, and the `add_matches_internal` signature and defaults are stated. The three `# ratio...:` lines are marked as condensed, not verbatim.
13. **Summary 4 / §1.2: loose threshold wording.** The percentage is a join-row count × 100 / `total_functions1`. The wording was tightened and real-export confirmation added.
14. **§1.3: missing detail.** Added the exact IDA-side threshold (`total_functions <= 4001`, `diaphora_ida.py:3798-3800`, `3714`) and the `DIAPHORA_SQL_TIMEOUT_LIMIT` string-override failure (`451`, `1894`).

**Material added.**
- Real-export facts:
  - NULL/`''` census (§6.2) and CU-name `''` frequency.
  - `source_file` distribution and ORDER BY key split (§6.4).
  - Duplicate-name, `sub_` and `nullsub` counts (§9).
  - Repeated `(func_id, constant)` rows (H16).
  - H13 row explosion from one CU.
  - Best-pass and Partial-pass item provenance from an instrumented run (§5.4, H12).
  - Heuristic timings on `sechost`, with no timeout (§4.3).
  - H11 UNION ordering confirmed on 5 pairs (§6.5).
- SQLite's `cast(md_index as real)` is not correctly rounded for 3 of 5,417 real values (§2.3, Hard part 4).
- SQLite 3.51.1 sorter stability analysis, and the requirement to keep `pragma threads = 0` (§6.4, §6.6).
- The oracle harness strips `DIAPHORA_*` variables (`tools/oracle/build_oracle.py:108-115`, `284-291`) (§1.3).
- CI SQLite is unpinned (`.github/workflows/ci.yml:38-56`) (§6.6, Hard part 8).
- A NULL-name `AttributeError` path in `check_match` (`1846`) (§5.1).

**Open questions.** Q2, Q3 (for the oracle corpus), Q4 and Q6 (for the current harness) are resolved. Q1 is partly resolved: PDB-vs-PDB triggers patch-diff mode, and win32u exports still do not exist. Q5 remains open.

**Not re-verified.**
- The synthetic-data numbers quoted from the original author's scratch directory (§3.3, §5.4 synthetic bullets, the 38 MB spill test) could not be re-run, because those scripts are not in the repository.
- The SQLite plans on the CI platforms' SQLite versions are not known.
