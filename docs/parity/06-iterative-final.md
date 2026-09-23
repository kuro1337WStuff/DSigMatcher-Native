# 06: Iterative passes and final pass (Diaphora 3.4.2 porting spec)

**Scope:** `diaphora.py` post-heuristic iteration loop in `diff()`, callee diffing (`find_matches_diffing*`, `find_one_match_diffing`), `find_related_matches` / `find_related_constants`, `find_related_compilation_unit`, `find_locally_affine_functions` / `find_functions_between`, the final pass (`final_pass`, `find_multimatches`, `find_unresolved_multimatches`, `add_multimatches_to_chooser`, `add_final_chooser_items`, `itemize_for_chooser`) and the helpers `same_processor_both_databases`, `functions_exists`, `get_row_for_items`, `call_on_match_hook`, `get_callers_callees`.

## Summary

1. After the SQL heuristic tiers, `diff()` runs an **unbounded** fixed-point loop (`while 1`). Each outer iteration runs, in this order: callee diffing on assembly (only when both `program.processor` values are equal), callee diffing on pseudo-code, "Same constants related matches" (gated by `slow_heuristics`, which is **True** in standalone mode), "Related compilation unit" and "Local affinity". The loop stops when `len(best)+len(partial)` measured after `cleanup_matches()` did not grow.
2. Every pass writes only through `add_match()` into three ordered lists (`all_matches["best"|"partial"|"unreliable"]`) and two name maps (`matched_primary`, `matched_secondary`). `cleanup_matches()` is called from 7 sites inside the loop plus once in `final_pass`. One of those sites (`:3185`) runs once or twice per callee-diffing field (§5), so a default outer iteration executes it 8-10 times when both processors match (two fields) and 7-8 times when they differ (pseudo-code only). The instrumented real `ls-old`→`ls` run executed 10, 8 and 8 cleanups in its three outer iterations (verification log V3). Its exact dedupe rules steer later accept/reject decisions, so it must be ported exactly.
3. `final_pass` = `cleanup_matches` + a running-max multimatch scan over (category order, ratio-descending, stable) + a filter that fills the best/partial/unreliable/multimatch choosers. The choosers hold **formatted strings** (`%08x` addresses, `%.7f` ratio, `%05lu` line). These strings are what `save_results` writes.
4. Default standalone configuration: the loop runs unless the "stripped binary" or "patch diff" speed-ups fire. The "Experimental" category never runs (it is nested under `unreliable`, and no heuristic has that category). `MIN_FUNCTIONS_TO_DISABLE_SLOW` is **IDA-GUI only**. No hooks are active during the loop.
5. Parity traps: (a) the unified-diff state machine, including the `--- `/`+++ ` header lines, one-sided blocks that carry over, and trailing blocks that are never flushed; (b) the `dones` set, whose key space is shared between *existing matches* and *callee pairs*; (c) **lexicographic TEXT** comparison of decimal address strings in Local affinity; (d) `abs(text) == 0` in related constants, which lets through only constants whose SQLite numeric prefix is zero; (e) SQLite row order in the two cartesian joins; (f) Python's stable `sorted(..., reverse=True)`; (g) the description suffix, which is always `(iteration #1)`.
6. Verified: a SQL-free re-implementation written from this spec (Appendix B) reproduced Diaphora's `results` table byte for byte, **including line numbers**, on four synthetic database pairs and on the real IDA-exported pairs `ls-old`→`ls` (278 rows, three outer iterations) and `userenv-9168-pdb`→`userenv-9278-pdb` (643 rows, patch-diff branch). The real `userenv`-nopdb and `sechost` pairs could not finish in Python within the session (§9, Hard parts 9).

---

## 0. Provenance and verification method

- **Reference.** `<diaphora-ref>` is at `621ec26` (`git describe` = `3.4.2-4-g621ec26`). `git diff --stat 3.4.2 HEAD` touches only `README.md` and `diaphora_ida.py`, so **`diaphora.py`, `diaphora_config.py`, `diaphora_heuristics.py` and `db_support/schema.py` are byte-identical to tag 3.4.2.** The `diaphora_ida.py` change is a CSS-only hunk at line 3864 and later (four added `color:` lines in `CHtmlDiff`), so the `diaphora_ida.py` lines cited here (2412-2484, 3797-3800) are also identical to the tag. All line numbers below refer to these files.
- **Runtime used for experiments.** `<conda>/python.exe` = Python 3.13.12, `sqlite3.sqlite_version` = 3.51.1, `cdifflib` not installed. `unified_diff` always comes from stdlib `difflib`, even when `cdifflib` is installed (see `diaphora.py:51`).
- **The reference was not modified.** All experiments ran against a copy of Diaphora at `<scratch>/dcopy` (made with `tar --exclude=.git --exclude=__pycache__`) on copies of the databases. `<scratch>` is `<temp>/claude/C--Users-Loki/229334b0-3f04-4430-9a2d-fa45ecf15f33/scratchpad/exp/`. Everything there is ephemeral and not committed.
- **Real test data.** While this spec was being written, another agent produced real IDA/Diaphora exports under `<corpus>/oracle/exports/`. They were copied to `<scratch>/../real/` before use and never opened in place:
  - `ls-old` / `ls`: GNU `ls` ELF, `pc64`, 304 / 318 functions;
  - `userenv-9168-pdb` / `userenv-9278-nopdb` / `userenv-9278-pdb`: PE64, 643 / 628 / 663 functions;
  - `sechost-9168-pdb` / `sechost-9444-nopdb`: PE64, 1442 / 1419 functions.
- **Synthetic test data.** Before the real exports existed, the only export was `ls-old.sqlite` (GNU `ls`, `pc64`, 304 functions, 14 compilation units, 361 `constants` rows). A diff side was synthesised from a copy (`<scratch>/mutate.py`):
  - every address, `rva` and `segment_rva` and every CU range was shifted;
  - every `sub_` name was renamed to its new address, and 45 of the 112 named functions were renamed to `sub_…`, with references rewritten in `assembly`, `pseudocode`, `clean_*` and `names`;
  - a subset got an appended `nop` / `;` line plus perturbed hashes;
  - `md5sum` was changed.

  Four variants were built:

  | Variant | Shift | Perturbed | Notes |
  |---|---|---|---|
  | `a` | 0x100000 | 1/3 | |
  | `b` | 0x100000 | all renamed | |
  | `c` | 5,751,712 | 1/2 | crosses the 10,000,000 decimal-digit boundary |
  | `x` | 5,751,712 | 1/3 | crosses the same boundary |
- **Checks performed.**
  1. SQLite semantics probes: TEXT comparison, `abs()` on text, `cast(... as real)`, `UNION … ORDER BY`, and `EXPLAIN QUERY PLAN` for every query in scope.
  2. Instrumented runs, wrapping methods only (no source edits).
  3. `<scratch>/validate.py`, an independent re-implementation of the callee-name extraction. It was compared call by call against `find_one_match_diffing` over all 494 (pair, field) inputs of variant `a`: 0 mismatches.
  4. `<scratch>/spec_loop.py`, Appendix B. It replaces `find_matches_diffing`, `find_related_matches`, `find_related_compilation_unit`, `find_locally_affine_functions` and `final_pass` with SQL-free versions written from this spec. The `results` table, compared with `ORDER BY type, line`, was **IDENTICAL** to a plain Diaphora run for all four variants: `a` 290 rows, `b` 307, `c` 292, `x` 290.
  5. Determinism: variant `a` run under `PYTHONHASHSEED` values 0 through 5 gave identical results tables. The real `ls-old`→`ls` pair gave identical tables under seeds 0, 1, 2, 3 and 7.
  6. Real pairs, spec vs plain Diaphora. `ls-old`→`ls`: **IDENTICAL**, 278 rows (139 best, 113 partial, 26 multimatch). `userenv-9168-pdb`→`userenv-9278-pdb`: **IDENTICAL**, 643 rows. Patch diffing was detected there, so only `final_pass` of this scope ran.
  7. The plain harness is the CLI. Its output for both of those pairs is identical, including `line`, to the other agent's `python diaphora.py` oracle runs (`oracle/diffs/ls-old_vs_ls/run1/ls-old_vs_ls.diaphora` and `oracle/diffs/userenv-9168-pdb_vs_9278-pdb/run1/…`).
  8. `userenv-9168-pdb`→`userenv-9278-nopdb` and `sechost-9168-pdb`→`sechost-9444-nopdb` were started in both modes and stopped after about 25 minutes, still inside the first "Related compilation unit" pass. See §9 for why. Validate them later against the oracle outputs when `tools/oracle/build_oracle.py` finishes.
- **Limitations.** Full-loop validation on real data covers one small ELF pair. The PE pairs that exercise large compilation units were not completed. The paths no data exercised are listed under Open questions.

---

## 1. Where this code sits in `diff()`, and what runs by default

```python
# diaphora.py:3593-3682
 3593      try:
 3594        t0 = time.monotonic()
 3595        cur_thread = threading.current_thread()
 3596        cur_thread.timeout = False
 3597        log_refresh("Diffing...", True)
 3598  
 3599        self.do_continue = True
 3600        if self.equal_db():
 3601          log("The databases seems to be 100% equal")
 3602  
 3603        if self.do_continue:
 3604          # Compare the call graphs
 3605          self.check_callgraph()
 3606  
 3607          if self.project_script is not None:
 3608            log("Loading project specific Python script...")
 3609            if not self.load_hooks():
 3610              return False
 3611  
 3612          # Find the unmodified functions
 3613          log_refresh("Finding equal matches...")
 3614          self.find_equal_matches()
 3615  
 3616          skip_others = False
 3617          self.is_same_processor = self.same_processor_both_databases()
 3618          if self.experimental:
 3619            # Dirty magic. Might or might not work...
 3620            log_refresh("Checking 'dirty' heuristics...")
 3621            skip_others = self.apply_dirty_heuristics()
 3622  
 3623          if not self.ignore_all_names:
 3624            self.find_same_name("partial")
 3625  
 3626          if skip_others:
 3627            self.find_remaining_functions()
 3628          else:
 3629            log_refresh("Finding best matches...")
 3630            self.run_heuristics_for_category("Best")
 3631  
 3632            # Find the modified functions
 3633            log_refresh("Finding partial matches")
 3634            self.find_partial_matches()
 3635  
 3636            self.apply_machine_learning()
 3637  
 3638            if self.unreliable:
 3639              # Find using likely unreliable methods modified functions
 3640              log_refresh("Finding probably unreliable matches")
 3641              self.find_unreliable_matches()
 3642  
 3643              #
 3644              # Find using experimental methods modified functions.
 3645              #
 3646              # NOTES: While these are still called experimental, they aren't really
 3647              # that experimental, as most of the code but the brute forcing using
 3648              # compilation units has been tested since years ago.
 3649              #
 3650              log_refresh("Finding experimental matches")
 3651              self.find_experimental_matches()
 3652  
 3653            iteration = 0
 3654            while 1:
 3655              self.cleanup_matches()
 3656              old_total = self.get_total_matched_functions()
 3657  
 3658              # Find new matches by diffing assembly and pseudo-code of previously
 3659              # found matches
 3660              self.find_matches_diffing(iteration)
 3661  
 3662              if self.slow_heuristics:
 3663                # Find new matches by digging from previous very good matches
 3664                self.find_related_matches(iteration)
 3665  
 3666              self.find_related_compilation_unit(iteration)
 3667  
 3668              # Find new matches in the functions between matches
 3669              self.find_locally_affine_functions(iteration)
 3670  
 3671              self.cleanup_matches()
 3672              new_total = self.get_total_matched_functions()
 3673              if new_total <= old_total:
 3674                break
 3675              iteration += 1
 3676  
 3677          self.final_pass()
 3678  
 3679          # Show the list of unmatched functions in both databases
 3680          log_refresh("Finding unmatched functions")
 3681          self.find_unmatched()
 3682          self.call_hook("on_finish", None, [])
```

### 1.1 Configuration as resolved in standalone mode (`python diaphora.py db1 db2 -o out`)

```python
# diaphora.py:3757-3773
 3757    if do_diff:
 3758      bd = CBinDiff(db1)
 3759      if not IS_IDA:
 3760        bd.ignore_all_names = False
 3761  
 3762      bd.db = sqlite3_connect(db1)
 3763      if os.getenv("DIAPHORA_PROFILE") is not None:
 3764        log("*** Profiling ***")
 3765        import cProfile
 3766  
 3767        profiler = cProfile.Profile()
 3768        profiler.runcall(bd.diff, db2)
 3769        exported = True
 3770        profiler.print_stats(sort="tottime")
 3771      else:
 3772        bd.diff(db2)
 3773      bd.save_results(diff_out)
```

```python
# diaphora.py:400-414
  400      self.unreliable = self.get_value_for(
  401        "unreliable", config.DIFFING_ENABLE_UNRELIABLE
  402      )
  403      self.relaxed_ratio = self.get_value_for(
  404        "relaxed_ratio", config.DIFFING_ENABLE_RELAXED_RATIO
  405      )
  406      self.experimental = self.get_value_for(
  407        "experimental", config.DIFFING_ENABLE_EXPERIMENTAL
  408      )
  409      self.slow_heuristics = self.get_value_for(
  410        "slow_heuristics", config.DIFFING_ENABLE_SLOW_HEURISTICS
  411      )
  412      self.use_trained_model = self.get_value_for(
  413        "use_trained_model", config.ML_USE_TRAINED_MODEL
  414      )
```

```python
# diaphora.py:560-569
  560    def get_value_for(self, value_name, default):
  561      """
  562      Try to search for a DIAPHORA_<value_name> environment variable.
  563      """
  564      value = os.getenv(f"DIAPHORA_{value_name.upper()}")
  565      if value is not None:
  566        if isinstance(value, type(default)):
  567          value = type(default)(value)
  568        return value
  569      return default
```

`get_value_for` gotcha: `os.getenv` returns `str`, and `isinstance(str_value, bool)` is False. So a set `DIAPHORA_*` variable is returned **as a raw string**, and any non-empty value (including `"0"` and `"False"`) is truthy. With no environment variables set, the config defaults apply:

```python
# diaphora_config.py:46-52
   46  DIFFING_ENABLE_UNRELIABLE = False
   47  DIFFING_ENABLE_RELAXED_RATIO = False
   48  DIFFING_ENABLE_EXPERIMENTAL = True
   49  DIFFING_ENABLE_SLOW_HEURISTICS = True
   50  DIFFING_IGNORE_SUB_FUNCTION_NAMES = True
   51  DIFFING_IGNORE_ALL_FUNCTION_NAMES = False
   52  DIFFING_IGNORE_SMALL_FUNCTIONS = False
```

| Flag | Standalone default | Effect in this scope |
|---|---|---|
| `self.unreliable` | False (`diaphora_config.py:46`) | `find_unreliable_matches` and `find_experimental_matches` are **skipped**. Both sit under `if self.unreliable:` (`diaphora.py:3638-3651`; indentation checked with `cat -A`). The "Experimental" category is empty anyway: `Counter(h['category'] for h in HEURISTICS)` = `{'Partial': 30, 'Best': 12, 'Unreliable': 8}`. Outside this scope it also skips every heuristic flagged `HEUR_FLAG_UNRELIABLE` (`:1498`) and brute forcing (`:2318`). |
| `self.experimental` | True (`:48`) | Only gates `apply_dirty_heuristics()` (`diaphora.py:3618-3621`). If that returns True, `skip_others` is set and **the whole iteration loop is skipped** (`:3626-3627`). |
| `self.slow_heuristics` | True (`:49`) | `find_related_matches` runs (`diaphora.py:3662-3664`). |
| `self.relaxed_ratio` | False (`:47`) | No in-scope function reads it. It affects `check_ratio`/`ast_ratio` (`diaphora.py:1641-1742`, `03a-ratio.md`) and `find_same_name`'s best-match test (`:2196-2198`). |
| `self.ignore_all_names` | False (forced at `diaphora.py:3760`) | `find_same_name("partial")` runs before the loop. |
| `self.use_trained_model` | False (`diaphora_config.py:205`) | `self.classifier` stays None, so `deep_ratio` never adds ML chooser items. |
| `self.hooks` | None | `project_script` comes only from `DIAPHORA_PROJECT_SCRIPT` (`diaphora.py:421`). The default patch-diff script is loaded only when patch diffing is detected and `config.RUN_DEFAULT_SCRIPTS` is True (the default, `diaphora_config.py:186`) (`:2614-2619`). That also sets `skip_others`, so **no hook is ever active inside the loop by default**. The hook stays loaded for `find_same_name`, `find_remaining_functions` and `on_finish`, but `final_pass` calls no hook. `call_hook(...)` then returns its default (`on_special_heuristic` → True, `on_match` → `[True, r]`). |

**`MIN_FUNCTIONS_TO_DISABLE_SLOW = 4001` does not apply in standalone mode.** It is read only by the IDA export/diff dialog:

```python
# diaphora_ida.py:3797-3800
 3797      self.unreliable = kwargs.get("unreliable", config.DIFFING_ENABLE_UNRELIABLE)
 3798      self.slow = kwargs.get(
 3799        "slow", total_functions <= config.MIN_FUNCTIONS_TO_DISABLE_SLOW
 3800      )
```

In `diaphora.py` the only source of `slow_heuristics` is `get_value_for("slow_heuristics", config.DIFFING_ENABLE_SLOW_HEURISTICS)` (`diaphora.py:409-411`). A `grep -rn MIN_FUNCTIONS_TO_DISABLE_SLOW` over the whole repository finds only `diaphora_config.py:71` and `diaphora_ida.py:3799`.

**`skip_others` (speed-ups).** The "Same binary with symbols stripped" speed-up fires when ≥ 99 % of main functions have the same `address` in the diff DB (`diaphora.py:2551-2563`). The "patch diff" speed-up fires when > 90 % share a `mangled_function` (`:2599-2610`). Their details are in `05-passes.md` (and the driver in `01-driver.md`). Here it is enough that **when either fires, the loop does not run, but `final_pass` still does.**

### 1.2 "Runs by default?" summary (standalone, no env vars)

| Function | Runs by default? | Evidence |
|---|---|---|
| iteration loop (`diff()` 3653-3675) | Yes, unless `skip_others` | `diaphora.py:3626-3629` |
| `find_matches_diffing` | Yes, once per outer iteration | `:3660` |
| `find_matches_diffing_assembly` | Only if `is_same_processor` | `:3220-3224` |
| `find_matches_diffing_pseudo` | Yes | `:3226-3229` |
| `find_related_matches` / `find_related_constants` | Yes (`slow_heuristics` True) | `:3662-3664`, `:3493-3494` |
| `find_related_compilation_unit` | Yes, but a no-op when the CU tables are empty | `:3666` |
| `find_locally_affine_functions` / `find_functions_between` | Yes | `:3669`, `:3360` |
| `final_pass` and everything under it | Always, in both branches | `:3677` |
| `same_processor_both_databases` | Always | `:3617` |
| `functions_exists`, `get_row_for_items`, `itemize_for_chooser` | Yes, as helpers | call sites below |
| `call_on_match_hook` | Called, but a no-op (hooks None) | call sites `:3112`, `:3297`; the no-op test is `:3008` |
| `deep_ratio` (`:2749-2837`) | Yes, from `check_ratio` when `r < 1.0` | Inside this doc's line range but specified in `03a-ratio.md` |
| `get_model_ratio` / `apply_machine_learning` (`:3496-3555`) | `apply_machine_learning` is called (`:3636`) but loads nothing because `use_trained_model` is False. `get_model_ratio`'s only call site is `deep_ratio:2824`, behind `self.classifier is not None`, so it never runs. | `:3551-3552`, `:2823-2824` |
| `get_callers_callees` | **Never. Dead code**, no call site in any `.py` file | `grep -rn get_callers_callees` → only the def at `:3557` |

---

## 2. Shared state and primitives (read and written by every pass here)

`02-matching.md` specifies these primitives in full. They are restated here, verbatim, because every pass in this document depends on their exact behaviour.

### 2.1 The match item

```python
# diaphora.py:103-107
  103  ITEM_MAIN_EA = 0
  104  ITEM_MAIN_NAME = 1
  105  ITEM_DIFF_EA = 2
  106  ITEM_DIFF_NAME = 3
  107  ITEM_RATIO = 5
```

An item is a Python **list** `[ea1, name1, ea2, name2, description, ratio, nodes1, nodes2]`.

- `ea1` and `ea2` are **decimal TEXT strings**, exactly as stored in `functions.address`. The column is `address text unique` (`db_support/schema.py:72`), and TEXT affinity converts integers to text on insert, so reading it yields Python `str`. Every producer in scope stores the raw TEXT value:
  - `main_row["address"]` at `diaphora.py:3115-3116` and `:3299-3300`;
  - `str(row["ea"])` / `row["ea2"]` in `add_matches_internal`, at `:1910-1912`.

  Instrumentation confirmed `type(match[0]) == str` for all 556 gap computations in variant `a`, and `(str, str)` for both range arguments in all 865 `find_functions_between` calls of the real `ls-old`→`ls` run (V3). Items from earlier phases follow the same rule: `find_same_name` and `search_small_differences` store `str(row["ea"])` and `row["ea2"]` (`:2187-2189`, `:2134-2136`).
- `ratio` is a Python `float`, or the **int** `1` for items from `find_equal_matches` (`:1439`), `add_matches_from_query` (`:2074`) and `find_same_name`'s best branch (`:2200`). `1 == 1.0` in every comparison, and `"%.7f" % 1` = `1.0000000`, so C++ can store a `double`.
- `nodes1` and `nodes2` are `int`.
- **List equality** (`item not in list`, `:1370`) compares all 8 fields with Python `==`: strings exactly, ratio numerically.

C++: `struct MatchItem { std::string ea1, name1, ea2, name2, desc; double ratio; int64_t nodes1, nodes2; }`. Equality is field-wise, with ratio compared by `==` on `double`.

### 2.2 Global match state

```python
# diaphora.py:382-384
  382      self.all_matches = {"best": [], "partial": [], "unreliable": []}
  383      self.matched_primary = {}
  384      self.matched_secondary = {}
```

- `all_matches` is an **insertion-ordered dict**. The key order `best, partial, unreliable` is preserved by `cleanup_matches`, which rebuilds the dict in the same order (`:1560-1563`, `:1605`). Every "for category in all_matches" loop below iterates in that order.
- `matched_primary[name1] = {"name": name2, "ratio": r}` and `matched_secondary[name2] = {"name": name1, "ratio": r}` are keyed by **function name**, not address.
- `ratios_cache` (reset at the start of `diff()`, `:3572`) caches `check_ratio` results under the key `f"{ea1}-{ea2}"` (`:1651-1655`, `:1774`). A pair's ratio is therefore computed once per diff run and reused by every heuristic, including those in this document.

### 2.3 `add_match`: the only writer

```python
# diaphora.py:1340-1374
 1340    def add_match(self, name1, name2, ratio, item, chooser):
 1341      """
 1342      Add a single match to the internal lists before really adding them to the
 1343      choosers list.
 1344  
 1345      NOTE: Always call `add_match`, don't try to handle this manually at all ever!
 1346      """
 1347      with self.items_lock:
 1348        # If the function names are the same, it's a best match, regardless of the
 1349        # ratio we got for the match, so fake the ratio as if it was 1.0.
 1350        if name1 == name2:
 1351          ratio = 1.0
 1352  
 1353        if ratio != 1.0:
 1354          if self.has_better_match(name1, name2, ratio):
 1355            return
 1356  
 1357          if name1 in self.matched_primary:
 1358            if self.matched_primary[name1]["ratio"] < ratio:
 1359              old_ratio = self.matched_primary[name1]["ratio"]
 1360              message = f"Found a better match for function {name1} -> {name2}, {old_ratio} with {ratio}"
 1361              debug_refresh(message)
 1362  
 1363          if name2 in self.matched_secondary:
 1364            if self.matched_secondary[name2]["ratio"] < ratio:
 1365              old_ratio = self.matched_secondary[name2]["ratio"]
 1366              message = f"Found a better match for function {name1} -> {name2}, {old_ratio} with {ratio}"
 1367              debug_refresh(message)
 1368  
 1369        if chooser is not None:
 1370          if item not in self.all_matches[chooser]:
 1371            self.all_matches[chooser].append(item)
 1372  
 1373        self.matched_primary[name1] = {"name": name2, "ratio": ratio}
 1374        self.matched_secondary[name2] = {"name": name1, "ratio": ratio}
```

Porting spec:

```
add_match(name1, name2, ratio, item, chooser):
    if name1 == name2: ratio = 1.0                 # the fake 1.0 is NOT written into item[5]
    if ratio != 1.0 and has_better_match(name1, name2, ratio): return
    if chooser != null and !contains(all_matches[chooser], item /*8-field equality*/):
        all_matches[chooser].push_back(item)
    matched_primary[name1]   = {name2, ratio}      # updated even when the item was already present
    matched_secondary[name2] = {name1, ratio}
```

There is no `has_best_match` check here. Callers that bypass `check_match` (callee diffing, Local affinity) can therefore add a 1.0 match for a function that already has a different 1.0 match. The final pass later turns such duplicates into multimatches or drops them.

### 2.4 `has_best_match` / `has_better_match`

```python
# diaphora.py:1376-1402
 1376    def has_best_match(self, name1, name2):
 1377      """
 1378      Check if we have a best match for the given two functions (not for the pair).
 1379      """
 1380      if name1 in self.matched_primary and self.matched_primary[name1]["ratio"] == 1.0:
 1381        return True
 1382      if name2 in self.matched_secondary and self.matched_secondary[name2]["ratio"] == 1.0:
 1383        return True
 1384      return False
 1385  
 1386    def has_better_match(self, name1, name2, ratio):
 1387      """
 1388      Check if there if we found a better match already for either @name1 or @name2.
 1389      """
 1390  
 1391      # If we have a match by name, that's the best match
 1392      if not name1.startswith("sub_") and not name2.startswith("sub_"):
 1393        if name1 in self.matched_primary:
 1394          return self.matched_primary[name1]["name"] == name1
 1395  
 1396      ratio = float(ratio)
 1397      if name1 in self.matched_primary and self.matched_primary[name1]["ratio"] > ratio:
 1398        return True
 1399      if name2 in self.matched_secondary and self.matched_secondary[name2]["ratio"] > ratio:
 1400        return True
 1401  
 1402      return False
```

`has_better_match` has a **named-function shortcut**. When *neither* name starts with `sub_` and `name1` is already in `matched_primary`, the result is **only** `matched_primary[name1].name == name1`, so ratios are ignored. It returns True (reject) iff `name1` is currently matched to a function with the identical name. Otherwise it returns False (accept), even when the existing match has a higher ratio. In every other case it rejects iff an existing ratio on either side is **strictly greater** (`>`), so ties are accepted.

### 2.5 `cleanup_matches`

```python
# diaphora.py:1554-1605
 1554    def cleanup_matches(self):
 1555      """
 1556      Check in all the matches for duplicates and bad matches and remove them.
 1557      """
 1558      with self.items_lock:
 1559        dones = {}
 1560        d = {}
 1561        ea_ratios = {}
 1562        for key, items in self.all_matches.items():
 1563          d[key] = []
 1564  
 1565          l_items = sorted(items, key=lambda x: float(x[5]), reverse=True)
 1566          for item in l_items:
 1567            # An example item:
 1568            # item = [ea1, name1, ea2, name2, "100% equal", 1, nodes1, nodes2]
 1569            ea = item[0]
 1570            name1 = item[1]
 1571            name2 = item[3]
 1572            ratio = item[5]
 1573  
 1574            # Ignore duplicated matches (might happen due to parallelism)
 1575            match = f"{name1}-{name2}"
 1576            if match in dones:
 1577              continue
 1578  
 1579            if name1 == name2:
 1580              debug_refresh(f"Using a fake 1.0 ratio for match {name1} - {name2}")
 1581              ratio = 1.0
 1582  
 1583            dones[match] = ratio
 1584  
 1585            # If the previous ratio for a match with function @ea is worst, ignore
 1586            # this match
 1587            if ea in ea_ratios and ea_ratios[ea] > ratio:
 1588              continue
 1589            else:
 1590              ea_ratios[ea] = ratio
 1591  
 1592            d[key].append(item)
 1593  
 1594        # Update now the dict of matched functions for both databases
 1595        self.matched_primary = {}
 1596        self.matched_secondary = {}
 1597        for key, l_items in d.items():
 1598          for item in l_items:
 1599            name1 = item[1]
 1600            name2 = item[3]
 1601            ratio = item[5]
 1602            self.matched_primary[name1] = {"name": name2, "ratio": ratio}
 1603            self.matched_secondary[name2] = {"name": name1, "ratio": ratio}
 1604  
 1605        self.all_matches = d
```

Porting spec:

```
cleanup_matches():
    dones   = set<string>()            # ONE set shared across all categories
    eaRatio = map<string ea1, double>  # ONE map shared across all categories, keyed by MAIN ea only
    for cat in [best, partial, unreliable]:                        # all_matches order
        out[cat] = []
        for it in stable_sort_desc_by_ratio(all_matches[cat]):     # see 2.6
            key = it.name1 + "-" + it.name2
            if key in dones: continue
            r = (it.name1 == it.name2) ? 1.0 : it.ratio           # fake 1.0 only for this comparison
            dones.add(key)
            if eaRatio.contains(it.ea1) and eaRatio[it.ea1] > r: continue   # strict >, ties kept
            eaRatio[it.ea1] = r
            out[cat].push_back(it)
    matched_primary.clear(); matched_secondary.clear()
    for cat in [best, partial, unreliable]:
        for it in out[cat]:                                        # later entries overwrite earlier ones
            matched_primary[it.name1]   = {it.name2, it.ratio}     # item ratio, NOT the fake 1.0
            matched_secondary[it.name2] = {it.name1, it.ratio}
    all_matches = out                                              # lists are left in sorted order
```

Properties:

- A name pair survives in at most one category, the first one in category order.
- Nothing is deduplicated on the diff side (`ea2`). The final pass handles that.
- The fake 1.0 that `add_match` put in the maps is lost after a cleanup when `item[5] < 1`.
- The function is **idempotent**. Running it twice gives the same lists: the second stable sort is a no-op, no duplicate pairs remain, and dropped items never updated `eaRatio`. This holds only if names are unique per database.

**Call points** (the C++ must call it at exactly these places, because each call rebuilds the maps that `has_better_match` / `has_best_match` read):

| Where | Line |
|---|---|
| loop top | `diaphora.py:3655` |
| `find_matches_diffing` start | `:3217` |
| end of every internal iteration of `find_matches_diffing_internal` | `:3185` (per field) |
| `find_related_matches` start | `:3471` |
| `find_related_compilation_unit` start | `:3413` |
| `find_locally_affine_functions` start | `:3340` |
| loop bottom | `:3671` |
| `final_pass` start | `:2945` |

Before the loop, the Partial tier ends with a cleanup (`:1551`). `search_small_differences` then adds items *without* a cleanup (`:2218-2221`), and the loop-top cleanup absorbs them.

### 2.6 Sorting and counting helpers

```python
# diaphora.py:3133-3148
 3133    def get_sorted_results(self, category):
 3134      """
 3135      Get results for the given category sorted by ratio
 3136      """
 3137      l = sorted(
 3138            self.all_matches[category], key=lambda x: float(x[5]), reverse=True
 3139          )
 3140      return l
 3141  
 3142    def get_total_matched_functions(self):
 3143      """
 3144      Return the total functions matched in the 'best' or 'partial' categories
 3145      """
 3146      return len(self.all_matches["best"]) + len(
 3147          self.all_matches["partial"]
 3148        )
```

`sorted(..., key=float(ratio), reverse=True)` is **stable with respect to the original order** for equal keys. The Python docs say reverse sorting "still maintains sort stability". The C++ must use `std::stable_sort` with the comparator `a.ratio > b.ratio`. Do **not** stable-sort ascending and then reverse, because that inverts the order of ties. Because `cleanup_matches` leaves each list sorted, "list order" and "sorted order" coincide right after a cleanup, and ties keep their **insertion order across the whole run**. That insertion order also depends on earlier phases. For example, `threads_apply` pops heuristics LIFO (`jkutils/threads.py:39-40`, `targets.pop()`). Outside IDA the thread count is forced to 1 (`diaphora.py:489-491`), so only one heuristic thread is alive at a time (`jkutils/threads.py:39`, `len(threads_list) < threads`). Each tier's SQL heuristics therefore execute sequentially in **reverse** list order, as the run log shows.

`get_total_matched_functions()` counts **list entries** in `best` and `partial`. It does not count distinct functions, and `unreliable` is excluded. It is only meaningful right after a cleanup.

### 2.7 `check_match` and `add_matches_internal` (used by related-constants and related-CU)

```python
# diaphora.py:1786-1872
 1786    def check_match(self, row, ratio=None, debug=False):
 1787      """
 1788      Check a single SQL heuristic match and return whether it should be ignored
 1789      or not, and also the similarity ratio for this match.
 1790      """
 1791  
 1792      ea = row["ea"]
 1793      ea2 = row["ea2"]
 1794      name1 = row["name1"]
 1795      name2 = row["name2"]
 1796      desc = row["description"]
 1797  
 1798      main_d = {}
 1799      main_d["ea"] = row["ea"]
 1800      main_d["name"] = row["name1"]
 1801      main_d["pseudo"] = row["pseudo1"]
 1802      main_d["asm"] = row["asm1"]
 1803      main_d["pseudocode_primes"] = row["pseudo_primes1"]
 1804      main_d["nodes"] = row["nodes1"]
 1805      main_d["md_index"] = row["md1"]
 1806      main_d["clean_assembly"] = row["clean_assembly1"]
 1807      main_d["clean_pseudo"] = row["clean_pseudo1"]
 1808      main_d["clean_micro"] = row["clean_micro1"]
 1809      main_d["bytes_hash"] = row["bytes_hash1"]
 1810      main_d["edges"] = row["edges1"]
 1811      main_d["indegree"] = row["indegree1"]
 1812      main_d["outdegree"] = row["outdegree1"]
 1813      main_d["instructions"] = row["instructions1"]
 1814      main_d["cyclomatic_complexity"] = row["cc1"]
 1815      main_d["strongly_connected"] = row["strongly_connected1"]
 1816      main_d["loops"] = row["loops1"]
 1817      main_d["constants_count"] = row["constants_count1"]
 1818      main_d["size"] = row["size1"]
 1819      main_d["kgh_hash"] = row["kgh_hash1"]
 1820  
 1821      diff_d = {}
 1822      diff_d["ea"] = row["ea2"]
 1823      diff_d["name"] = row["name2"]
 1824      diff_d["pseudo"] = row["pseudo2"]
 1825      diff_d["asm"] = row["asm2"]
 1826      diff_d["pseudocode_primes"] = row["pseudo_primes2"]
 1827      diff_d["nodes"] = row["nodes2"]
 1828      diff_d["md_index"] = row["md2"]
 1829      diff_d["clean_assembly"] = row["clean_assembly2"]
 1830      diff_d["clean_pseudo"] = row["clean_pseudo2"]
 1831      diff_d["clean_micro"] = row["clean_micro2"]
 1832      diff_d["bytes_hash"] = row["bytes_hash2"]
 1833      diff_d["edges"] = row["edges2"]
 1834      diff_d["indegree"] = row["indegree2"]
 1835      diff_d["outdegree"] = row["outdegree2"]
 1836      diff_d["instructions"] = row["instructions2"]
 1837      diff_d["cyclomatic_complexity"] = row["cc2"]
 1838      diff_d["strongly_connected"] = row["strongly_connected2"]
 1839      diff_d["loops"] = row["loops2"]
 1840      diff_d["constants_count"] = row["constants_count2"]
 1841      diff_d["size"] = row["size2"]
 1842      diff_d["kgh_hash"] = row["kgh_hash2"]
 1843  
 1844      if ratio != 1.0:
 1845        nullsub = "nullsub_"
 1846        if name1.startswith(nullsub) or name2.startswith(nullsub):
 1847          debug_refresh(f"Ignoring nullsub functions {name1}-{name2}")
 1848          return False, 0.0
 1849  
 1850        # Do we already have a 1.0 match for any of these functions?
 1851        if self.has_best_match(name1, name2):
 1852          debug_refresh(f"Ignoring as we have a best match {name1}-{name2}")
 1853          return False, 0.0
 1854  
 1855        if ratio != 1.0:
 1856          if ratio is None:
 1857            r = self.check_ratio(main_d, diff_d)
 1858            if debug:
 1859              msg = "0x%x 0x%x %d" % (int(ea), int(ea2), r)
 1860              LOGGER.debug(msg)
 1861          else:
 1862            r = ratio
 1863  
 1864          # Do we have a previous match with a better comparison ratio than this?
 1865          if self.has_better_match(name1, name2, r):
 1866            debug_refresh(f"Ignoring as there is a better match than {r} for {name1}-{name2}")
 1867            return False, 0.0
 1868  
 1869      should_add = True
 1870      args = [main_d, diff_d, desc, r]
 1871      should_add, r = self.call_hook("on_match", [should_add, r], args)
 1872      return should_add, r
```

```python
# diaphora.py:1874-1948
 1874    def continue_getting_sql_rows(self, i):
 1875      """
 1876      Determine if more rows should be read at the given stage
 1877      """
 1878      if self.sql_max_processed_rows != 0 and i < self.sql_max_processed_rows:
 1879        return True
 1880      return False
 1881  
 1882    def add_matches_internal(
 1883      self, cur, best, partial, val=None, unreliable=None, debug=False
 1884    ):
 1885      """
 1886      Wrapper for various functions that find matches based on SQL queries. Always
 1887      use this function when issuing SQL heuristics (if it's possible).
 1888      """
 1889      i = 0
 1890      matches = []
 1891      cur_thread = threading.current_thread()
 1892      t = time.monotonic()
 1893      while self.continue_getting_sql_rows(i):
 1894        if time.monotonic() - t > self.timeout or cur_thread.timeout:
 1895          log(f"Timeout with heuristic '{cur_thread.name}'")
 1896          raise SystemExit()
 1897  
 1898        i += 1
 1899        if i % 50000 == 0:
 1900          log(f"Processed {i} rows...")
 1901        row = cur.fetchone()
 1902        if row is None:
 1903          break
 1904  
 1905        # Check the row match
 1906        should_add, r = self.check_match(row, debug=debug)
 1907        if not should_add:
 1908          continue
 1909  
 1910        ea = str(row["ea"])
 1911        name1 = row["name1"]
 1912        ea2 = row["ea2"]
 1913        name2 = row["name2"]
 1914        desc = row["description"]
 1915        nodes1 = int(row["nodes1"])
 1916        nodes2 = int(row["nodes2"])
 1917  
 1918        done = True
 1919        chooser = None
 1920        item = None
 1921  
 1922        if val is None:
 1923          val = config.DEFAULT_PARTIAL_RATIO
 1924  
 1925        if r == 1.0:
 1926          chooser = best
 1927          item = [ea, name1, ea2, name2, desc, r, nodes1, nodes2]
 1928        elif r >= val and partial is not None:
 1929          chooser = partial
 1930          item = [ea, name1, ea2, name2, desc, r, nodes1, nodes2]
 1931        else:
 1932          done = False
 1933  
 1934        if done:
 1935          matches.append([0, "0x%x" % int(ea), name1, ea2, name2])
 1936          self.add_match(name1, name2, r, item, chooser)
 1937        else:
 1938          chooser = None
 1939          item = None
 1940          if r < config.DEFAULT_PARTIAL_RATIO and r > val and unreliable is not None:
 1941            chooser = "unreliable"
 1942            item = [ea, name1, ea2, name2, desc, r, nodes1, nodes2]
 1943            matches.append([0, "0x%x" % int(ea), name1, ea2, name2])
 1944  
 1945          if chooser is not None:
 1946            self.add_match(name1, name2, r, item, chooser)
 1947  
 1948      return matches
```

As called in this scope, `add_matches_internal(cur, best="best", partial="partial")` has `val=None`, which becomes `DEFAULT_PARTIAL_RATIO = 0.5` (`diaphora_config.py:137`), and `unreliable=None`. For each row, in row order:

1. `nullsub_` filter: prefix `nullsub_` on either name, case-sensitive.
2. `has_best_match(name1, name2)`: skip if **either** function already has ratio == 1.0 in its map.
3. `r = check_ratio(...)`, cached.
4. `has_better_match(name1, name2, r)`: skip.
5. `r == 1.0` → `best`; `r >= 0.5` → `partial`; otherwise the row is dropped (the unreliable branch is unreachable because `unreliable is None`).
6. `add_match(name1, name2, r, [ea, name1, ea2, name2, desc, r, nodes1, nodes2], chooser)`, where `desc` is the SQL literal from `get_query_fields`.

Limits:

- **At most 1,000,000 rows** are read per call: `continue_getting_sql_rows(i)` with `SQL_MAX_PROCESSED_ROWS = 1000000` (`diaphora_config.py:90`). This cap is deterministic and **must** be ported, together with the exact row order.
- **Timeout**: after `SQL_TIMEOUT_LIMIT = 60 * 5` (300) s (`diaphora_config.py:92`, read into `self.timeout` at `diaphora.py:451`) *per call*, `raise SystemExit()` (`:1894-1896`). The clock starts at `t = time.monotonic()` (`:1892`) on entry to `add_matches_internal`, and it is checked only before each `fetchone()`. In this scope `cur_thread` is the main thread. Its `timeout` attribute is set to False at `:3596` and only `threads_apply` ever sets it to True (`jkutils/threads.py:63`, worker threads only), so only the wall-clock branch can fire here. In this scope nothing catches `SystemExit`:
  - `find_related_constants` and `find_related_compilation_unit` have only `try/finally`, unlike the `add_matches_from_query_ratio*` wrappers, which have `except SystemExit: pass` (`:1965-1966`, `:1990-1991`, `:2016-2017`);
  - `diff()` has only `try/finally` (`:3593`, `:3699`);
  - the `__main__` block has no `try` (`:3757-3773`).

  So the interpreter exits **without writing results** (`save_results` at `:3773` is never reached), and the **exit status is 0**, because `SystemExit()` carries no code (verified: `python -c "raise SystemExit()"` exits 0). An oracle harness must therefore treat "exit 0 but no `.diaphora` file" as a failure. This depends on timing and cannot be reproduced. The recommendation is not to port it.
- **Environment overrides of the limits.** `get_value_for` returns a set `DIAPHORA_SQL_MAX_PROCESSED_ROWS` or `DIAPHORA_SQL_TIMEOUT_LIMIT` as a raw `str` (§1.1). The first `continue_getting_sql_rows` call then evaluates `i < "…"`, and the first timeout test evaluates `float > str`. Both raise `TypeError` in Python 3 (`:1878`, `:1894`). Default runs set neither variable.

`get_query_fields`, which supplies the SELECT list and aliases these rows carry:

```python
# diaphora_heuristics.py:51-84
   51  SELECT_FIELDS = """ f.address ea, f.name name1, df.address ea2, df.name name2,
   52                    {heur} description,
   53                    f.pseudocode pseudo1, df.pseudocode pseudo2,
   54                    f.assembly asm1, df.assembly asm2,
   55                    f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
   56                    f.nodes nodes1, df.nodes nodes2,
   57                    cast(f.md_index as real) md1, cast(df.md_index as real) md2,
   58                    f.clean_assembly clean_assembly1, df.clean_assembly clean_assembly2,
   59                    f.clean_pseudo clean_pseudo1, df.clean_pseudo clean_pseudo2,
   60                    f.mangled_function mangled1, df.mangled_function mangled2,
   61                    f.clean_microcode clean_micro1, df.clean_microcode clean_micro2,
   62                    f.bytes_hash bytes_hash1, df.bytes_hash bytes_hash2,
   63                    f.edges edges1, df.edges edges2,
   64                    f.indegree indegree1, df.indegree indegree2,
   65                    f.outdegree outdegree1, df.outdegree outdegree2,
   66                    f.instructions instructions1, df.instructions instructions2,
   67                    f.cyclomatic_complexity cc1, df.cyclomatic_complexity cc2,
   68                    f.strongly_connected strongly_connected1,
   69                    df.strongly_connected strongly_connected2,
   70                    f.loops loops1, df.loops loops2,
   71                    f.constants_count constants_count1,
   72                    df.constants_count constants_count2,
   73                    f.size size1, df.size size2,
   74                    f.kgh_hash kgh_hash1, df.kgh_hash kgh_hash2
   75  """
   76  def get_query_fields(heur, quote=True):
   77    """
   78    Get the list of fields used in any and all SQL heuristics queries.
   79    """
   80    val = heur
   81    if quote:
   82      val = repr(val)
   83    ret = SELECT_FIELDS.format(heur=val)
   84    return ret
```

`repr(heur)` makes the description a single-quoted SQL string literal, so the returned `description` column is exactly the heuristic name, for example `Same constants related matches`. `md1`/`md2` are `cast(md_index as real)`.

### 2.8 `compare_function_rows` → `check_ratio`

```python
# diaphora.py:2479-2503
 2479    def compare_function_rows(self, main_row, diff_row):
 2480      """
 2481      Compare the functions of one SQL match.
 2482      """
 2483      fields = [
 2484        ["ea", "address"],   ["name", "name"], ["pseudo", "pseudocode"],
 2485        ["asm", "assembly"], ["pseudocode_primes", "pseudocode_primes"], ["nodes", "nodes"],
 2486        ["md_index", "md_index"],  ["clean_assembly", "clean_assembly"],
 2487        ["clean_pseudo", "clean_pseudo"], ["clean_micro", "clean_microcode"],
 2488        ["bytes_hash", "bytes_hash"], ["edges", "edges"]
 2489      ]
 2490  
 2491      main_d = {}
 2492      main_d["ea"] = main_row["address"]
 2493      main_d["name"] = main_row["name"]
 2494      main_d["pseudo"] = main_row["pseudocode"]
 2495      main_d["asm"] = main_row["assembly"]
 2496      main_d["pseudocode_primes"] = main_row["pseudocode_primes"]
 2497      main_d["nodes"] = main_row["nodes"]
 2498      main_d["md_index"] = main_row["md_index"]
 2499      main_d["clean_assembly"] = main_row["clean_assembly"]
 2500      main_d["clean_pseudo"] = main_row["clean_pseudo"]
 2501      main_d["clean_micro"] = main_row["clean_microcode"]
 2502      main_d["bytes_hash"] = main_row["bytes_hash"]
 2503      main_d["edges"] = main_row["edges"]
```

```python
# diaphora.py:2537-2538
 2537      ratio = self.check_ratio(main_d, diff_d)
 2538      return ratio
```

The full-row similarity (`check_ratio`, `deep_ratio`) is specified in `03a-ratio.md`. What matters here:

- It is cached for the whole run under the key `f"{main_row['address']}-{diff_row['address']}"`, the two decimal address strings.
- `compare_function_rows` passes the **raw TEXT** `md_index` column (`:2498`, `:2521`; `md_index text`, `schema.py:107`), which `check_ratio` converts with Python `float()` (`:1672-1673`). The SQL-row path (`check_match`, §2.7) passes `cast(md_index as real)` (`diaphora_heuristics.py:57`), which SQLite converts. **The two conversions are not always equal.** Real exports: `userenv-9168-pdb` (`int AddFileInfoNode(...)`) and `userenv-9278-nopdb` (`sub_1800029FC`) both store `md_index = '3.050963036440351716676733804'`. Python `float()` gives `0x1.8685f4ef68783p+1`, but SQLite 3.51.1 `cast(... as real)` gives `0x1.8685f4ef68782p+1`, one ulp lower (V7). Every other `md_index` in the six real exports converted identically. `check_ratio` uses `md1`/`md2` only in `md1 == md2`, `md1 != md2`, `md1 > 0.0` and (relaxed only) `md1 > MINIMUM_RARE_MD_INDEX` (`:1740-1742`, `:1758`). Equal texts therefore behave the same in either path, and a difference can arise only if two *distinct* `md_index` texts collide under one conversion but not the other. The ratio cache makes the first path to score a pair decide its ratio for the rest of the run. A non-numeric `md_index` text (for example `''`) would raise `ValueError` at `:1672` on the `compare_function_rows` path but become 0.0 on the SQL path. All six real exports have only numeric `md_index` text.
- `deep_ratio` re-reads both rows **by address** and uses `self.is_same_processor`, so it is only final after `diaphora.py:3617`.
- It returns a value in `[0, 1]`. Non-1.0 results are capped at 0.99 when the deep score would reach 1.0 (`:1766-1771`).

### 2.9 Row lookups by name: `get_function_row`, `get_row_for_items`

```python
# diaphora.py:2445-2460
 2445    def get_function_row(self, name, db_name="main"):
 2446      """
 2447      Get the full table row for the given function with name @name in the database
 2448      @db_name.
 2449      """
 2450      row = None
 2451      cur = self.db_cursor()
 2452      try:
 2453        sql = f"select * from {db_name}.functions where name = ?"
 2454        cur.execute(sql, [name])
 2455        row = cur.fetchone()
 2456      except:
 2457        log(f"ERROR at get_function_row: {str(sys.exc_info()[1])}")
 2458      finally:
 2459        cur.close()
 2460      return row
```

```python
# diaphora.py:2993-3001
 2993    def get_row_for_items(self, item):
 2994      """
 2995      Get the assembly source for the functions involved in a match
 2996      """
 2997  
 2998      main_asm = self.get_function_row(item.vfname)
 2999      diff_asm = self.get_function_row(item.vfname2, "diff")
 3000  
 3001      return main_asm, diff_asm
```

- Lookup is **by name** (`item.vfname` / `item.vfname2`), `fetchone()`. The observed plan is `SEARCH main.functions USING INDEX idx_2 (name=?)`, so with duplicate names the **lowest `id`** wins. The same holds without the index, since a rowid scan returns the lowest id first.
- A missing row gives None, and the caller skips the pair.

### 2.10 `functions_exists`

```python
# diaphora.py:2969-2991
 2969    def functions_exists(self, name1, name2):
 2970      """
 2971      Check if the given functions exist and return their respective rows.
 2972      """
 2973      l = []
 2974      cur = self.db_cursor()
 2975      try:
 2976        sql = """select * from (
 2977           select 'main' db_name, * from main.functions where name = ?
 2978          union
 2979           select 'diff' db_name, * from diff.functions where name = ?
 2980           ) order by db_name desc
 2981        """
 2982        cur.execute(sql, (name1, name2))
 2983        rows = cur.fetchall()
 2984        ret = False
 2985        if rows is not None:
 2986          size = len(rows)
 2987          ret = size == 2
 2988          l = rows
 2989      finally:
 2990        cur.close()
 2991      return ret, l
```

Porting spec:

```
functions_exists(n1, n2):
    l = [main rows with name == n1, ascending id] ++ [diff rows with name == n2, ascending id]
    return (l.size() == 2, l)
```

- `ORDER BY db_name DESC` puts `'main'` before `'diff'`.
- `UNION` never collapses rows here, because the rows differ in `db_name`/`id`.
- Ties within one `db_name` come out in ascending `id`. That is the observed order: the UNION temp B-tree is sorted by the whole row, and the ORDER BY sorter preserves it. It is *not guaranteed by SQL*. The probe returned `[('main', 12, 'dup', '77'), ('main', 13, 'dup', '66')]`.
- **Edge case (Diaphora bug, reproduce it):** if `n1` exists twice in main and `n2` does not exist in diff, then `size == 2` and `l[0]`, `l[1]` are **both main rows**. The caller then treats the second main function as the "diff" function (the probe confirmed `exists == True` with two main rows). The mirrored case (0 main, 2 diff) behaves the same way. On a normal IDA export names are unique, so this is dormant. All seven real exports checked have 0 duplicate names (Open question 3).

### 2.11 Hooks: `call_hook`, `call_on_match_hook`

```python
# diaphora.py:1450-1459
 1450    def call_hook(self, func_name, default_ret, args):
 1451      """
 1452      Call the given event @func_name(@args) returning @default_ret if it doesn't
 1453      exist.
 1454      """
 1455      if self.hooks is not None:
 1456        method = getattr(self.hooks, func_name, None)
 1457        if method is not None:
 1458          return method(*args)
 1459      return default_ret
```

```python
# diaphora.py:3003-3031
 3003    def call_on_match_hook(self, heur, r, main_row, diff_row):
 3004      """
 3005      Call the "on_match" hook, if it exists.
 3006      """
 3007      should_add = True
 3008      if self.hooks is not None and "on_match" in dir(self.hooks):
 3009        desc = heur
 3010        ea = main_row["address"]
 3011        ea2 = diff_row["address"]
 3012        name1 = main_row["name"]
 3013        name2 = main_row["name"]
 3014        pseudo1 = main_row["pseudocode"]
 3015        pseudo2 = diff_row["pseudocode"]
 3016        asm1 = main_row["assembly"]
 3017        asm2 = diff_row["assembly"]
 3018        ast1 = main_row["pseudocode_primes"]
 3019        ast2 = diff_row["pseudocode_primes"]
 3020        nodes1 = int(main_row["nodes"])
 3021        nodes2 = int(diff_row["nodes"])
 3022        md1 = main_row["md_index"]
 3023        md2 = diff_row["md_index"]
 3024  
 3025        d1 = { "ea": ea,  "nodes": nodes1, "name": name1, "pseudocode_primes": ast1,
 3026                "pseudo": pseudo1, "asm": asm1, "md_index": md1 }
 3027        d2 = { "ea": ea2, "nodes": nodes2, "name": name2, "pseudocode_primes": ast2,
 3028                "pseudo": pseudo2, "asm": asm2, "md_index": md2 }
 3029        tmp = self.call_hook("on_match", [should_add, r], [d1, d2, desc, r])
 3030        should_add, r = tmp
 3031      return should_add, r
```

With `self.hooks is None`, `call_on_match_hook` returns `(True, r)` unchanged. Diaphora bug, relevant only with hooks: `name2 = main_row["name"]` (`:3013`) passes the *main* name as `d2["name"]`. The C++ may omit hooks entirely. If hooks are ever ported, keep this bug.

### 2.12 `same_processor_both_databases`

```python
# diaphora.py:2950-2967
 2950    def same_processor_both_databases(self):
 2951      """
 2952      Check if the processor of both databases is the same.
 2953      """
 2954      ret = False
 2955      cur = self.db_cursor()
 2956      try:
 2957        sql = """ select 1
 2958            from main.program mp,
 2959               diff.program dp
 2960           where mp.processor = dp.processor"""
 2961        cur.execute(sql)
 2962        row = cur.fetchone()
 2963        if row is not None:
 2964          ret = True
 2965      finally:
 2966        cur.close()
 2967      return ret
```

True iff **some** row of `main.program` and **some** row of `diff.program` have equal `processor` (`processor text`, `schema.py:123`), compared as TEXT and case-sensitively. A `NULL` processor never matches. The sample value is `'pc64'`, as are all six real exports checked (V5). `is_same_processor` starts as `False` (`:436`). It is assigned at `:3617`, after `equal_db`, `check_callgraph` and `find_equal_matches`, none of which computes a ratio (`find_equal_matches` adds items with a literal `1`, `:1439-1440`), so every `check_ratio`/`deep_ratio` call sees the final value.

### 2.13 `get_callers_callees` (dead code)

```python
# diaphora.py:3557-3566
 3557    def get_callers_callees(self, db_name, func_id):
 3558      cur = self.db_cursor()
 3559      rows = []
 3560      try:
 3561        sql = "select * from {db}.callgraph where func_id = ?"
 3562        cur.execute(sql.format(db=db_name), (func_id,))
 3563        rows = list(cur.fetchall())
 3564      finally:
 3565        cur.close()
 3566      return rows
```

No call site exists anywhere in the repository, so do not port it.

### 2.14 `itemize_for_chooser`, `CChooser.Item`, `CChooser.add_item`

```python
# diaphora.py:2718-2730
 2718    def itemize_for_chooser(self, item):
 2719      """
 2720      Get a CChoser.Item object from the given list @item.
 2721      """
 2722      ea1 = item[0]
 2723      vfname1 = item[1]
 2724      ea2 = item[2]
 2725      vfname2 = item[3]
 2726      ratio = item[4]
 2727      nodes1 = item[5]
 2728      nodes2 = item[6]
 2729      desc = item[7]
 2730      return CChooser.Item(ea1, vfname1, ea2, vfname2, ratio, nodes1, nodes2, desc)
```

```python
# diaphora.py:232-245
  232    class Item:
  233      """
  234      A single chooser item.
  235      """
  236  
  237      def __init__(self, ea, name, ea2=None, name2=None, desc=None, ratio=0, nodes1=0, nodes2=0):
  238        self.ea = ea
  239        self.vfname = name
  240        self.ea2 = ea2
  241        self.vfname2 = name2
  242        self.description = desc
  243        self.ratio = ratio
  244        self.nodes1 = int(nodes1)
  245        self.nodes2 = int(nodes2)
```

```python
# diaphora.py:275-296
  275    def add_item(self, item):
  276      """
  277      Add a single item
  278      """
  279      if self.title.startswith("Unmatched in"):
  280        self.items.append(["%05lu" % self.n, "%08x" % int(item.ea), item.vfname])
  281      else:
  282        dec_vals = "%." + config.DECIMAL_VALUES
  283        self.items.append(
  284          [
  285            "%05lu" % self.n,
  286            "%08x" % int(item.ea),
  287            item.vfname,
  288            "%08x" % int(item.ea2),
  289            item.vfname2,
  290            dec_vals % item.ratio,
  291            "%d" % item.nodes1,
  292            "%d" % item.nodes2,
  293            item.description,
  294          ]
  295        )
  296      self.n += 1
```

**Trap:** the local variable names in `itemize_for_chooser` are off by one, and the positional call cancels the error. `Item(ea, name, ea2, name2, desc, ratio, nodes1, nodes2)` receives `desc=item[4]`, `ratio=item[5]`, `nodes1=int(item[6])`, `nodes2=int(item[7])`, which is the correct mapping for the layout in 2.1. **Port the effective mapping**, not the variable names.

`add_item` appends a list of 9 strings to `chooser.items`:

| # | Value | Format |
|---|---|---|
| 1 | line | `"%05lu" % n`, a per-chooser counter from 0 |
| 2 | `ea` | `"%08x" % int(ea)` (lowercase hex, zero-padded to at least 8) |
| 3 | `vfname` | |
| 4 | `ea2` | `"%08x" % int(ea2)` |
| 5 | `vfname2` | |
| 6 | ratio | `"%.7f" % ratio`, since `config.DECIMAL_VALUES = "7f"` (`diaphora_config.py:120`) |
| 7 | nodes1 | `"%d"` |
| 8 | nodes2 | `"%d"` |
| 9 | description | |

Python `%` float formatting is correctly rounded (round-half-even on the exact binary value). Use `std::to_chars(buf, v, std::chars_format::fixed, 7)`, not CRT `printf`. Example rows (unmodified Diaphora, variant `a`):

```
('best', '00000', '004045a4', 'start', '005045a4', 'start', '1.0000000', '1', '1', 'Perfect match, same name')
('multimatch', '00002', '004113b0', 'sub_4113B0', '00511420', 'sub_511420', '0.9900000', '6', '6', 'Microcode mnemonics small primes product')
```

---

## 3. The outer iteration loop (`diff()`)

```python
# diaphora.py:3653-3675
 3653            iteration = 0
 3654            while 1:
 3655              self.cleanup_matches()
 3656              old_total = self.get_total_matched_functions()
 3657  
 3658              # Find new matches by diffing assembly and pseudo-code of previously
 3659              # found matches
 3660              self.find_matches_diffing(iteration)
 3661  
 3662              if self.slow_heuristics:
 3663                # Find new matches by digging from previous very good matches
 3664                self.find_related_matches(iteration)
 3665  
 3666              self.find_related_compilation_unit(iteration)
 3667  
 3668              # Find new matches in the functions between matches
 3669              self.find_locally_affine_functions(iteration)
 3670  
 3671              self.cleanup_matches()
 3672              new_total = self.get_total_matched_functions()
 3673              if new_total <= old_total:
 3674                break
 3675              iteration += 1
```

Porting spec:

```
iteration = 0
loop forever:
    cleanup_matches()
    old_total = |best| + |partial|
    find_matches_diffing(iteration)                      # §4
    if slow_heuristics: find_related_matches(iteration)  # §7 (default: yes)
    find_related_compilation_unit(iteration)             # §9
    find_locally_affine_functions(iteration)             # §10
    cleanup_matches()
    new_total = |best| + |partial|
    if new_total <= old_total: break
    iteration += 1
final_pass()                                             # §12
```

- **Termination:** the loop stops at the first outer iteration whose post-cleanup entry count does not strictly grow. There is **no iteration cap**. Adds that a cleanup removes again (for example a same-name re-discovery, see §6.7) do not count.
- `iteration` is passed only to the `on_special_heuristic` hook (`:3222`, `:3227`, `:3336`, `:3409`, `:3467`). It is **never** used in a description. The callee-diffing description uses a separate internal counter (§5).
- Each outer iteration **re-runs everything from scratch** against the current match lists: callee diffing starts with a fresh `dones`, CU and constants queries are re-issued for every qualifying match, and every gap is re-examined. This is how matches found in iteration *k* get expanded in iteration *k+1*.
- Real `ls-old`→`ls`: **3** outer iterations, 206 → 287, then 287 → 291, then 291 → 291 and a break. Re-verified by wrapping `get_total_matched_functions` (V3): `diff()` read `(3656, 206), (3672, 287), (3656, 287), (3672, 291), (3656, 291), (3672, 291)`.
- Empirical (variant `a`): 2 outer iterations. Iteration 0 went 244 → 293; iteration 1 went 293 → 293 and broke out. Every stage changes the count. The counts below are raw list lengths *before* any cleanup, so they include churn. They were re-measured in V11, where the Local-affinity leading cleanup took 304 → 265 and then 28 items were added.

  | Stage | Before | After |
  |---|---|---|
  | `find_matches_diffing` | 244 | 247 |
  | `find_related_matches` | 247 | 257 |
  | `find_related_compilation_unit` | 257 | 304 |
  | `find_locally_affine_functions` (its own leading cleanup, then 28 adds) | 304 | 293 before the loop-bottom cleanup |

---

## 4. `find_matches_diffing(iteration)`

```python
# diaphora.py:3211-3229
 3211    def find_matches_diffing(self, iteration):
 3212      """
 3213      Find new matches by diffing the previously found matches.
 3214      """
 3215  
 3216      # First, remove duplicates, etc... just to be sure
 3217      self.cleanup_matches()
 3218  
 3219      # Only if the processor is the same for both databases we diff assembly
 3220      if self.is_same_processor:
 3221        heur = "Callee found diffing matches assembly"
 3222        enabled = self.call_hook("on_special_heuristic", True, [heur, iteration])
 3223        if enabled:
 3224          self.find_matches_diffing_assembly()
 3225  
 3226      heur = "Callee found diffing matches pseudo-code"
 3227      enabled = self.call_hook("on_special_heuristic", True, [heur, iteration])
 3228      if enabled:
 3229        self.find_matches_diffing_pseudo()
```

- **Inputs:** `self.is_same_processor` (§2.12).
- **Spec:** `cleanup_matches()`. Then, if `is_same_processor`, run `find_matches_diffing_internal("Callee found diffing matches assembly", "assembly")`. Then always run `find_matches_diffing_internal("Callee found diffing matches pseudo-code", "pseudocode")`. **Assembly runs first.**
- **Runs by default?** Yes, once per outer iteration. The assembly half runs only for identical processors, per the comment at `:3219` and the code at `:3220`.

---

## 5. `find_matches_diffing_internal` and the assembly/pseudo wrappers

```python
# diaphora.py:3150-3209
 3150    def find_matches_diffing_internal(self, heur, field_name):
 3151      """
 3152      Find funtions by diffing matches assembly or pseudo-codes.
 3153  
 3154      NOTE: Should this algorithm be parallelized?
 3155      """
 3156      log_refresh(f"Finding with heuristic '{heur}'")
 3157  
 3158      iteration = 1
 3159      dones = set()
 3160      # Should I let it run for some more iterations? There is a small chance of
 3161      # hitting an infinite loop, so I'm hardcoding an upper limit.
 3162      while iteration <= 3:
 3163        old_total = self.get_total_matched_functions()
 3164  
 3165        for key in ["best", "partial"]:
 3166          l = self.get_sorted_results(key)
 3167          for match in l:
 3168            match_key = f"{match[1]}-{match[3]}"
 3169            if match_key in dones:
 3170              continue
 3171            dones.add(match_key)
 3172  
 3173            item = self.itemize_for_chooser(match)
 3174            main_row, diff_row = self.get_row_for_items(item)
 3175            if main_row is not None and diff_row is not None:
 3176              if main_row[field_name] is None:
 3177                continue
 3178              if diff_row[field_name] is None:
 3179                continue
 3180  
 3181              dones = self.find_one_match_diffing(
 3182                main_row, diff_row, field_name, heur, iteration, dones
 3183              )
 3184  
 3185        self.cleanup_matches()
 3186        self.show_summary()
 3187  
 3188        new_total = self.get_total_matched_functions()
 3189        if new_total == old_total:
 3190          break
 3191  
 3192        log(f"New iteration with heuristic '{heur}'...")
 3193        iteration += 1
 3194  
 3195    def find_matches_diffing_assembly(self):
 3196      """
 3197      Try finding new matches by diffing assembly.
 3198      """
 3199      heur = "Callee found diffing matches assembly"
 3200      field_name = "assembly"
 3201      self.find_matches_diffing_internal(heur, field_name)
 3202  
 3203    def find_matches_diffing_pseudo(self):
 3204      """
 3205      Try finding new matches by diffing pseudo-codes.
 3206      """
 3207      heur = "Callee found diffing matches pseudo-code"
 3208      field_name = "pseudocode"
 3209      self.find_matches_diffing_internal(heur, field_name)
```

Porting spec:

```
find_matches_diffing_internal(heur, field):            # field ∈ {"assembly","pseudocode"}
    iteration = 1
    dones = set<string>()                              # shared by BOTH key kinds (see below)
    while iteration <= 3:
        old_total = |best| + |partial|
        for cat in [best, partial]:
            snapshot = stable_sort_desc_by_ratio(all_matches[cat])   # copy taken when this cat starts
            for m in snapshot:
                mk = m.name1 + "-" + m.name2
                if mk in dones: continue
                dones.add(mk)
                mr = first main row with name == m.name1      # §2.9
                dr = first diff row with name == m.name2
                if mr == null or dr == null: continue
                if mr[field] is NULL or dr[field] is NULL: continue   # "" is NOT skipped
                find_one_match_diffing(mr, dr, field, heur, iteration, dones)   # §6, mutates dones
        cleanup_matches()
        new_total = |best| + |partial|
        if new_total == old_total: break               # equality, NOT <=
        iteration += 1
```

**Snapshot semantics.** `get_sorted_results` returns a new list. Items added while iterating `best` land in the lists but not in the snapshot being walked. The `partial` snapshot is taken after the `best` walk, so it *contains* partial items added during that walk, but their keys are already in `dones` (see the next point).

**Shared `dones` key space.** Existing-match keys `f"{match[1]}-{match[3]}"` (`:3168`) and callee-pair keys `f"{name1}-{name2}"` (`:3067`) are the same format in the same set. Consequences:

- A callee pair is added to `dones` (`:3070`) **before** any filter. Any item that `find_one_match_diffing` creates therefore has its key in `dones` before it is appended (its `item[1]`/`item[3]` are exactly `name1`/`name2`, `:3121`, `:3123`).
- **An existing match whose name pair was already produced as a callee pair earlier in the same call is never expanded in this call.** Its key is in `dones` when the walk reaches it. Order of the walk therefore matters.

**The description always ends in `(iteration #1)` (proved from source, observed empirically).** At the start of internal iteration 2, every item in `best`/`partial` has its key in `dones`: pre-existing items were walked in iteration 1, and new items were created with their key pre-inserted. `cleanup_matches` only removes and reorders. So iteration 2 walks nothing and adds nothing, and cleanup is idempotent, which gives `new_total == old_total` and a break. At most two internal iterations run. The second one runs only when iteration 1 changed the count, and it is a no-op apart from `cleanup_matches()` (a no-op itself) and logging.

Evidence:

- The instrumentation counted `find_one_match_diffing` calls by `iteration` argument. Variant `a`: `{1: 207}` (asm) and `{1: 143}` (pseudo) in outer iteration 0, then `{1: 251}` and `{1: 158}` in outer iteration 1. Real `ls-old`→`ls`: `{1: 192}`/`{1: 98}`, `{1: 260}`/`{1: 162}` and `{1: 264}`/`{1: 166}` across its three outer iterations. The totals re-verified in V3 are `('assembly', 1): 716` = 192+260+264 and `('pseudocode', 1): 426` = 98+162+166; no call had `iteration != 1`. `:3185` executed 8 times over the 6 field calls, so two field calls entered the no-op second internal iteration.
- The run log shows the "New iteration with heuristic 'Callee found diffing matches assembly'..." line: the second internal iteration was entered and found nothing.
- The results tables of variants a, b, c and x contain only `… (iteration #1)` descriptions.

Implement the loop literally anyway. It is cheap, and it keeps the cleanup schedule identical.

**Runs by default?** Yes: assembly only with the same processor, pseudo-code always.

**Inputs:**

- `functions.name`, `functions.assembly` / `functions.pseudocode` (TEXT, NULL-able; a NULL means skip);
- plus everything `find_one_match_diffing` and `compare_function_rows` read.

**Outputs:** items in `best`/`partial` with description `Callee found diffing matches assembly (iteration #1)` or `Callee found diffing matches pseudo-code (iteration #1)`.

---

## 6. `find_one_match_diffing`: the callee-name extraction

```python
# diaphora.py:3033-3131
 3033    def find_one_match_diffing(
 3034      self, input_main_row, input_diff_row, field_name, heur, iteration, dones
 3035    ):
 3036      """
 3037      Diff the lines for the field @field_name and find matches of function names
 3038      (only function names for now) to find new matches candidates.
 3039      """
 3040      main_lines = input_main_row[field_name].splitlines(keepends=False)
 3041      diff_lines = input_diff_row[field_name].splitlines(keepends=False)
 3042      df = unified_diff(main_lines, diff_lines, lineterm="")
 3043  
 3044      minus = []
 3045      plus = []
 3046  
 3047      for row in df:
 3048        if len(row) == 0:
 3049          continue
 3050  
 3051        c = row[0]
 3052        if c == "-":
 3053          minus.append(row)
 3054        elif c == "+":
 3055          plus.append(row)
 3056        elif c == " ":
 3057          if len(minus) > 0 and len(plus) > 0:
 3058            matches1 = re.findall(CPP_NAMES_RE, "\n".join(minus), re.IGNORECASE)
 3059            matches2 = re.findall(CPP_NAMES_RE, "\n".join(plus), re.IGNORECASE)
 3060            minus = []
 3061            plus = []
 3062  
 3063            size = min(len(matches1), len(matches2))
 3064            for i in range(size):
 3065              name1 = matches1[i][0]
 3066              name2 = matches2[i][0]
 3067              key = f"{name1}-{name2}"
 3068              if key in dones:
 3069                continue
 3070              dones.add(key)
 3071  
 3072              if name1.startswith("nullsub") or name2.startswith("nullsub"):
 3073                # Ignore such functions
 3074                continue
 3075  
 3076              size = len(dones)
 3077              if size > 0 and size % 10000 == 0:
 3078                log(f"{size} callee matches processed so far...")
 3079  
 3080              exists, l = self.functions_exists(name1, name2)
 3081              if exists:
 3082                main_row = l[0]
 3083                diff_row = l[1]
 3084                min_nodes = min(main_row["nodes"], diff_row["nodes"])
 3085                max_nodes = max(main_row["nodes"], diff_row["nodes"])
 3086  
 3087                # If the number of basic blocks differ in more than 75% ignore...
 3088                if (
 3089                  (min_nodes * 100) / max_nodes
 3090                ) < config.DIFFING_MATCHES_MAX_DIFFERENT_BBLOCKS_PERCENT:
 3091                  continue
 3092  
 3093                # There is a high risk of false positives with small functions,
 3094                # therefore, it's preferred to miss functions than having false
 3095                # positives
 3096                if main_row["nodes"] < config.DIFFING_MATCHES_MIN_BBLOCKS:
 3097                  continue
 3098                if diff_row["nodes"] < config.DIFFING_MATCHES_MIN_BBLOCKS:
 3099                  continue
 3100  
 3101                r = self.compare_function_rows(main_row, diff_row)
 3102                if r == 1.0:
 3103                  chooser = "best"
 3104                elif r > config.DEFAULT_TRUSTED_PARTIAL_RATIO:
 3105                  chooser = "partial"
 3106                else:
 3107                  continue
 3108  
 3109                if r + config.MATCHES_BONUS_RATIO < 1.0:
 3110                  r += config.MATCHES_BONUS_RATIO
 3111  
 3112                should_add, r = self.call_on_match_hook(heur, r, main_row, diff_row)
 3113                if should_add:
 3114                  heur_text = f"{heur} (iteration #{iteration})"
 3115                  ea1 = main_row["address"]
 3116                  ea2 = diff_row["address"]
 3117                  nodes1 = int(main_row["nodes"])
 3118                  nodes2 = int(diff_row["nodes"])
 3119                  new_item = [
 3120                    ea1,
 3121                    name1,
 3122                    ea2,
 3123                    name2,
 3124                    heur_text,
 3125                    r,
 3126                    nodes1,
 3127                    nodes2,
 3128                  ]
 3129                  self.add_match(name1, name2, r, new_item, chooser)
 3130  
 3131      return dones
```

### 6.1 Line splitting

The text is split with `str.splitlines(keepends=False)`:

- It splits on `\n`, `\r`, `\r\n`, `\v` (`\x0b`), `\f` (`\x0c`), `\x1c`, `\x1d`, `\x1e`, `\x85`, `\u2028` and `\u2029`. The probe `"xyz\x0bq\x1cr\u2028s".splitlines()` gave `['xyz','q','r','s']`.
- There is no trailing empty element, and `""` → `[]`.

The C++ must decode the UTF-8 text to split on the non-ASCII separators, or at least on `\x85` (as the code point U+0085, not the raw byte), U+2028 and U+2029.

### 6.2 The unified-diff line stream (stdlib `difflib`, Appendix A)

`unified_diff(main_lines, diff_lines, lineterm="")` uses the defaults `fromfile=''`, `tofile=''` and `n=3`. It emits:

1. If there is **at least one group**: `"--- "` then `"+++ "` (exact strings, with a trailing space and no date). If the inputs are identical, `get_grouped_opcodes` yields nothing and **nothing** is emitted.
2. For each group from `SequenceMatcher(None, a, b).get_grouped_opcodes(3)` (**autojunk on**: for `len(b) >= 200`, any line occurring more than `len(b)//100 + 1` times in `b` is dropped from `b2j`):
   - `"@@ -… +… @@"` (only the first character, `@`, matters here);
   - then for each opcode: `equal` → `" "+line` for each `a` line; `replace` → all `"-"+a` lines **then** all `"+"+b` lines; `delete` → `"-"+a`; `insert` → `"+"+b`.

`a` is the MAIN text and `b` is the DIFF text. A faithful port of `SequenceMatcher.get_opcodes` is required (`find_longest_match` tie rules, the popular-element purge, the queue-based `get_matching_blocks` and the adjacent-block merge). All of it is in Appendix A.

### 6.3 Flush state machine (exact)

```
minus = [], plus = []
for row in stream:
    if row is empty: continue                  # never happens with lineterm=""
    c = row[0]
    if   c == '-': minus.push(row)             # includes the header "--- "
    elif c == '+': plus.push(row)              # includes the header "+++ "
    elif c == ' ':
        if minus nonempty and plus nonempty:
            m1 = findall(NAME, join(minus, "\n")); m2 = findall(NAME, join(plus, "\n"))
            minus = []; plus = []
            for i in 0 .. min(|m1|,|m2|)-1: yield (m1[i], m2[i])
    # '@' lines: ignored, and they do NOT flush
# end of stream: whatever is left in minus/plus is DISCARDED (never flushed)
```

Consequences:

- **The header lines count.** `"--- "` sits in `minus` and `"+++ "` sits in `plus`, so both lists are non-empty from the start, and the **first context line of the whole stream** flushes them. The headers contain no identifiers. Consequences:
  - When the first hunk begins with context (the usual case), the flush consumes only the headers and produces nothing.
  - When the texts differ at line 0, **every one-sided line before that first context line is discarded**, whether it is `+`-only (pure insertion) or `-`-only (pure deletion). Without the headers those lines would have carried over. `min(len(m1), len(m2))` is 0 because the other side holds only the header.
  - A two-sided (replace) block at line 0 pairs normally.

  Re-verified (V2): a leading pure deletion `"-call alpha_one"` followed later by a pure insertion `"+call delta_two"` gives `[]`; without the header effect it would give `[('call','call'), ('alpha_one','delta_two')]`. A leading replace `alpha_one`→`gamma_new` gives `[('call','call'), ('alpha_one','gamma_new')]`. The `diaphora_pairs` reproduction in `<scratch>/hdr.py` shows the insertion case:
  ```
  a = ctx1..ctx4, "call alpha_one", ctx5..ctxB, "call  beta_two", ctxC
  b = "call gamma_new", ctx1..ctx4, ctx5..ctxB, "call  delta_two", ctxC
  with header : [('call','call'), ('alpha_one','delta_two')]
  no header   : [('call','call'), ('alpha_one','gamma_new'), ('call','call'), ('beta_two','delta_two')]
  ```
- A one-sided block is **not** reset by context lines, `@@` lines or group boundaries. It accumulates until the other side appears and a context line follows, so positional pairing can span distant hunks, as `alpha_one ↔ delta_two` above shows.
- A block at the very end of the text (no trailing context line) is **never flushed**. For example, `"x1\nx2\nx3\ncall foo_a"` vs `"…call foo_b"` gives `[]`.
- Mnemonics are identifiers too, if they have at least 4 characters. `call`, `push` and `test` are extracted and paired positionally. `mov`, `jmp` and `lea` (3 characters) are **not** extracted. Probe: `findall` over `"jmp mov call push lea test"` gives `['call', 'push', 'test']`. Such pairs usually fail `functions_exists`, but they still enter `dones`.

### 6.4 The name regex

```python
# diaphora.py:114-114
  114  CPP_NAMES_RE = "([a-zA-Z_][a-zA-Z0-9_]{3,}((::){0,1}[a-zA-Z0-9_]+)*)"
```

`re.findall(CPP_NAMES_RE, text, re.IGNORECASE)` returns 3-tuples, and `[0]` is group 1, which spans the whole match. Equivalent formulation, used by the validator: `[a-zA-Z_][a-zA-Z0-9_]{3,}(?:(?:::)?[a-zA-Z0-9_]+)*` with `findall` returning whole matches. A scanner port:

```
pos = 0
while pos < len:
    if isStart(s[pos]) and the next 3 chars are all isWord:
        end = pos+1; while end < len and isWord(s[end]): end++      # greedy run
        loop: if s[end..end+1] == "::" and end+2 < len and isWord(s[end+2]):
                  end += 2; while end < len and isWord(s[end]): end++
              else break
        emit s[pos:end]; pos = end
    else pos++
```

Notes on this scanner:

- There is **no word boundary** at the start. `0x401000` yields `x401000`, `12abcd` yields `abcd`, and `std::vector::push_back` yields `vector::push_back` (`std` is too short to start a match). Probe output: `[('x401000'…), ('call'…), ('vector::push_back'…), ('sub_401000'…), ('ab_c'…)]`.
- The minimum length is 4 characters.
- Under `re.IGNORECASE` with a `str` pattern, `[a-zA-Z]` also matches exactly **four non-ASCII code points**: U+0130 `İ`, U+0131 `ı`, U+017F `ſ` and U+212A `K`. An exhaustive scan of all code points for `re.fullmatch('[a-zA-Z0-9_]', c, re.IGNORECASE)` returned `['0x130','0x131','0x17f','0x212a']`. `isStart` and `isWord` must accept them, which means scanning decoded code points.

### 6.5 Per-pair processing (in pair order)

For each `(name1, name2)` yielded:

1. `key = name1 + "-" + name2`. If `key` is in `dones`, skip. Otherwise add it to `dones`. This happens **before** the other filters, so rejected pairs are also remembered.
2. Skip if `name1.startswith("nullsub")` or `name2.startswith("nullsub")`. The prefix is `nullsub` with no underscore, case-sensitive.
3. `functions_exists(name1, name2)` (§2.10). If `size != 2`, skip. Otherwise `main_row = l[0]`, `diff_row = l[1]`.
4. `min*100/max < 25` → skip. This is true division in `double` with `DIFFING_MATCHES_MAX_DIFFERENT_BBLOCKS_PERCENT = 25` (`diaphora_config.py:177`). If `max_nodes == 0`, Python raises `ZeroDivisionError`, which aborts `diff()` (Hard parts).
5. `main_row.nodes < 3` or `diff_row.nodes < 3` → skip (`DIFFING_MATCHES_MIN_BBLOCKS = 3`, `:183`).
6. `r = compare_function_rows(main_row, diff_row)`. `r == 1.0` → `best`; `r > 0.3` (strict, `DEFAULT_TRUSTED_PARTIAL_RATIO`, `:141`) → `partial`; otherwise skip.
7. **Bonus after the category decision:** `if r + 0.01 < 1.0: r += 0.01` (`MATCHES_BONUS_RATIO`, `:116`), in IEEE double.
   - `0.99 + 0.01 == 1.0` in double, so the capped 0.99 ratio gets **no** bonus.
   - `best` stays 1.0.
   - Partial ratios end up in `(0.31, 1.0)`: `r + 0.01` when that sum is `< 1.0`, otherwise `r` unchanged (which happens for `r ∈ [0.99, 1.0)`).
8. The hook (no-op by default).
9. `add_match(name1, name2, r, [main_row.address, name1, diff_row.address, name2, heur + " (iteration #" + it + ")", r, int(main.nodes), int(diff.nodes)], chooser)`.

`size = len(dones)` at `:3076` shadows the loop bound, but `range(size)` was already evaluated, so there is no behavioural effect. Only logging uses it.

### 6.6 Inputs and outputs

**Inputs:**

- `functions.assembly` or `functions.pseudocode` (TEXT) of the seed pair;
- `functions.name`, `functions.nodes` (INTEGER) of the callee rows;
- all `compare_function_rows` fields: `address, name, pseudocode, assembly, pseudocode_primes, nodes, md_index, clean_assembly, clean_pseudo, clean_microcode, bytes_hash, edges, indegree, outdegree, instructions, cyclomatic_complexity, strongly_connected, loops, constants_count, size, kgh_hash`;
- plus what `deep_ratio` re-reads: `source_file, pseudocode_primes, indegree, outdegree, switches, cyclomatic_complexity, constants`.

**Outputs:** `best` (r == 1.0, no bonus) or `partial` (bonus applied), with description `Callee found diffing matches {assembly|pseudo-code} (iteration #1)`.

### 6.7 Re-discovery churn (observed)

The callee pairs include same-name pairs (`memcpy`↔`memcpy`) and pairs that are already matched. `add_match` fakes `ratio = 1.0` for equal names and, having no `has_best_match` check, **appends** the item, because the description differs from the existing one. The next `cleanup_matches` keeps only the first occurrence of each name pair in (category order, stable ratio-descending) order. That is normally the pre-existing item, but a new `best` item beats an existing `partial` item for the same pair. In variant `a`, callee diffing appended 18 `best` items per field (assembly and pseudo-code) in *each* outer iteration. In outer iteration 1, `|best|+|partial|` across `find_matches_diffing` was unchanged (293 → 293), so every append there was churn that a cleanup removed.

This churn is harmless to termination, because counts are taken after cleanup. However, between the append and the cleanup, `matched_primary` carries the faked ratio, and that feeds `has_better_match` for the rest of the call. Reproduce the churn; do not "optimise" it away.

---

## 7. `find_related_matches(iteration)`

```python
# diaphora.py:3462-3494
 3462    def find_related_matches(self, iteration):
 3463      """
 3464      Find matches from previous good matches using a number of heuristics.
 3465      """
 3466      heur = "Same constants related matches"
 3467      enabled = self.call_hook("on_special_heuristic", True, [heur, iteration])
 3468      if not enabled:
 3469        return
 3470  
 3471      self.cleanup_matches()
 3472  
 3473      log_refresh(f"Finding with heuristic '{heur}'")
 3474      dones = set()
 3475  
 3476      for key in ["best", "partial"]:
 3477        l = self.get_sorted_results(key)
 3478        for match in l:
 3479          match_key = f"{match[1]}-{match[3]}"
 3480          if match_key in dones:
 3481            continue
 3482          dones.add(match_key)
 3483  
 3484          ratio = match[5]
 3485          if ratio < config.RELATED_MATCHES_MIN_RATIO:
 3486            break
 3487  
 3488          item = self.itemize_for_chooser(match)
 3489          main_row, diff_row = self.get_row_for_items(item)
 3490          if main_row is None or diff_row is None:
 3491            continue
 3492  
 3493          if main_row["constants_count"] > 0 and diff_row["constants_count"] > 0:
 3494            self.find_related_constants(main_row, diff_row)
```

Porting spec:

```
find_related_matches(iteration):
    cleanup_matches()
    dones = set<string>()
    for cat in [best, partial]:
        for m in stable_sort_desc_by_ratio(all_matches[cat]):     # snapshot
            mk = m.name1 + "-" + m.name2
            if mk in dones: continue ; dones.add(mk)               # (never hits after a cleanup)
            if m.ratio < 0.8: break                                # RELATED_MATCHES_MIN_RATIO; breaks THIS category only
            mr, dr = rows by name (§2.9); if null: continue
            if mr.constants_count > 0 and dr.constants_count > 0:  # INTEGER; NULL → Python TypeError
                find_related_constants(mr, dr)                     # §8
```

- By default `best` holds only 1.0 items, so the `break` fires only inside `partial`, at the first item below 0.8.
- **Inputs:** `functions.constants_count` (INTEGER) and `functions.constants`.
- **Outputs:** via §8.
- **Runs by default?** Yes, because `slow_heuristics = True` in standalone mode (§1.1), with no function-count limit.

---

## 8. `find_related_constants(main_row, diff_row)`

```python
# diaphora.py:3362-3393
 3362    def find_related_constants(self, main_row, diff_row):
 3363      """
 3364      Try to find matches finding cross references to constants from functions 
 3365      that we already matched with a good ratio.
 3366      """
 3367      heur = "Same constants related matches"
 3368      cur = self.db_cursor()
 3369      try:
 3370        main_consts = set(json.loads(main_row["constants"]))
 3371        diff_consts = set(json.loads(diff_row["constants"]))
 3372        
 3373        inter_consts = main_consts.intersection(diff_consts)
 3374        if len(inter_consts) > 0:
 3375          sql = (
 3376            """ select """
 3377            + get_query_fields(heur)
 3378            + """
 3379           from main.functions f,
 3380                diff.functions df,
 3381                main.constants mc,
 3382                diff.constants dc
 3383          where f.id = mc.func_id
 3384            and df.id = dc.func_id
 3385            and dc.constant = mc.constant
 3386            and mc.constant = ?
 3387            and abs(mc.constant) == 0 """
 3388          )
 3389          for constant in inter_consts:
 3390            cur.execute(sql, (str(constant),))
 3391            self.add_matches_internal(cur, best="best", partial="partial")
 3392      finally:
 3393        cur.close()
```

### 8.1 Encodings

`functions.constants` is a JSON array written by `json.dumps(list(prop), ensure_ascii=False, cls=CBytesEncoder)` (`diaphora.py:936-939`). Its elements are **JSON integers** (immediates or displacements that passed `constant_filter`, so always ≥ 0x1000) and **JSON strings** (string literals referenced by the function). Examples: `[6394752, 6394760, "00"]`. The source is `diaphora_ida.py:2467-2484`:

```python
# diaphora_ida.py:2467-2484
 2467    def extract_function_constants(self, ins, x, constants):
 2468      for operand in ins.ops:
 2469        if operand.type == o_imm:
 2470          if self.is_constant(operand, x) and self.constant_filter(operand.value):
 2471            constants.append(operand.value)
 2472        elif operand.type == o_displ:
 2473          if self.constant_filter(operand.addr):
 2474            constants.append(operand.addr)
 2475  
 2476        drefs = DataRefsFrom(x)
 2477        for dref in drefs:
 2478          if get_func(dref) is None:
 2479            str_constant = get_string_at(dref)
 2480            if str_constant is not None:
 2481              str_constant = str_constant.decode("utf-8", "backslashreplace")
 2482              if str_constant not in constants:
 2483                constants.append(str_constant)
 2484      return constants
```

The `constants` table gets one row per list element (**duplicates kept**) with `constant` as TEXT. Ints are written as `str(int)`, and strings are kept only if `len > 4`:

```python
# diaphora.py:984-998
  984        # Phase 3: Insert the constants of the function
  985        sql = "insert into constants (func_id, constant) values (?, ?)"
  986        insert_args = []
  987        props_dict = self.create_function_dictionary(props)
  988        for constant in props_dict["constants"]:
  989          should_add = False
  990          if type(constant) in [str, bytes] and len(constant) > 4:
  991            should_add = True
  992          elif type(constant) in [int, float, decimal.Decimal]:
  993            should_add = True
  994            constant = str(constant)
  995  
  996          if should_add:
  997            insert_args.append([func_id, constant])
  998        cur.executemany(sql, insert_args)
```

Table definitions:

```python
# db_support/schema.py:170-173
  170    """create table if not exists constants (
  171                    id integer primary key,
  172                    func_id integer not null references functions(id) on delete cascade,
  173                    constant text not null)""",
```

The sample had 361 `constants` rows, all `typeof = text`, including 28 duplicated `(func_id, constant)` pairs, which were numeric.

### 8.2 The Python-side candidate set

- `set(json.loads(...))` intersection, with elements typed: int `4096` ≠ str `"4096"`.
- Each element is passed through `str(c)`, so ints become canonical decimal.
- C++: parse the JSON, represent each element as `(isString, text)`, intersect, and then use `text`.
- **Iteration order** is Python set order. For a set holding only `int` elements it is deterministic, because `hash(int)` does not depend on the seed. For `str` elements it depends on `PYTHONHASHSEED`, which is randomised per process by default. In a mixed set the positions of the `int` elements can shift too, because string slots cause different probe collisions. Only `str` elements can produce rows (§8.3), so only their relative order matters. See Hard parts and Open question 2. Seeds 0-5 on variant `a`, seeds 0, 1, 2, 3 and 7 on the real `ls-old`→`ls` pair, and forced sorted and reverse-sorted orders on `ls-old`→`ls` (V4) all gave identical output.

### 8.3 The SQL filter `abs(mc.constant) == 0` (only zero-prefix constants survive)

`mc.constant` is TEXT, so SQLite's `abs()` goes through `sqlite3_value_double`, which parses the **longest numeric prefix**:

- leading ASCII whitespace (space, `\t`, `\n`, `\v`, `\f`, `\r`) is skipped;
- then an optional sign, digits, an optional `.` and digits, and an optional exponent whose digits must be present;
- no prefix gives 0.0.

The row passes iff that value is 0. Probe results with SQLite 3.51.1 (value → `abs`, passes?):

| Input | `abs` | Passes? |
|---|---|---|
| `'hello'` | 0.0 | yes |
| `'4096'` | 4096.0 | no |
| `'123abc'` | 123.0 | no |
| `'  42 apples'` | 42.0 | no |
| `'0x10'` | 0.0 | yes |
| `'0 files'` | 0.0 | yes |
| `'1e5 x'` | 100000.0 | no |
| `'.5x'` | 0.5 | no |
| `'inf'` | 0.0 | yes |
| `'Infinity'` | 0.0 | yes |
| `'NaN'` | 0.0 | yes |
| `'-12'` | 12.0 | no |
| `'-0'` | -0.0 | yes |
| `'1e999'` | inf | no |
| `'\t7'` | 7.0 | no |
| `'\n5'` | 5.0 | no |
| `'\x0b5'` | 5.0 | no |
| `'+3a'` | 3.0 | no |
| `'0000'` | 0.0 | yes |
| `'e5'` | 0.0 | yes |
| `'1e'` | 1.0 | no |
| `'.e1'` | 0.0 | yes |
| `'-.5'` | 0.5 | no |
| `'..5'` | 0.0 | yes |
| `'\u0663'` | 0.0 | yes (only ASCII digits count) |
| `'\xa05'` | 0.0 | yes (NBSP is not whitespace) |
| `'1e-400'` | 0.0 | yes (underflow) |
| `'1e-320'` | 1e-320 | no (subnormal) |

Net effect:

- Every numeric constant is excluded: `str(int)` of an int ≥ 0x1000 is nonzero.
- Only **string constants with no nonzero numeric prefix** can produce rows.
- A string constant with `len <= 4` has no `constants` row, so it produces no rows either.
- C++: implement the prefix grammar above and evaluate the prefix with a correctly rounded parser (SQLite 3.51.1 `cast(... as real)` matched Python `float()` on 20,717 large-integer strings, 0 mismatches). Then test `== 0.0`.

### 8.4 Row order (not specified by SQL; observed plan)

`EXPLAIN QUERY PLAN` on the variant-`a` pair (with `sqlite_stat1` present):

```
SEARCH mc USING COVERING INDEX idx_35 (constant=?)
SEARCH f  USING INTEGER PRIMARY KEY (rowid=?)
SEARCH dc USING COVERING INDEX idx_35 (constant=?)
SEARCH df USING INTEGER PRIMARY KEY (rowid=?)
```

`idx_35` is `constants(constant, func_id)` (`schema.py:59`). The resulting order:

- **outer:** main `constants` rows with `constant == c`, ascending `(func_id, rowid)`, with duplicates repeated;
- **inner:** diff rows the same way;
- rows whose `f`/`df` does not exist are dropped (inner join).

Every row is the full cartesian product for `c`, including the seed pair itself and already-matched functions. `check_match` filters those.

### 8.5 Outputs and default

- **Outputs:** `add_matches_internal(cur, best="best", partial="partial")` (§2.7). `r == 1.0` → `best`, `r >= 0.5` → `partial`, and both use description `Same constants related matches`. There is **no** bonus.
- **Runs by default?** Yes, reached from §7 whenever both seeds have `constants_count > 0`, a non-empty JSON intersection, and a zero-prefix constant.

---

## 9. `find_related_compilation_unit(iteration)`

```python
# diaphora.py:3395-3460
 3395    def find_related_compilation_unit(self, iteration):
 3396      """
 3397      Try to find new matches in potential, or existing, compilation units
 3398  
 3399      The idea is the following: after we have a number of good matches, we find
 3400      the boundaries of the compilation units and the matched functions. If we've,
 3401      for example, a CU for binary A, no CU information for binary B, *BUT* we've
 3402      at least 2 matches from a single CU in binary A to 2 functions in binary B,
 3403      we can determine that everything between the matched functions in binary B
 3404      belong to the CU that we know about in binary A, therefore, we can try one
 3405      brute force approach of all functions in the CU from A to the functions in B
 3406      in that specific area.
 3407      """
 3408      heur = "Related compilation unit"
 3409      enabled = self.call_hook("on_special_heuristic", True, [heur, iteration])
 3410      if not enabled:
 3411        return
 3412  
 3413      self.cleanup_matches()
 3414      log_refresh(f"Finding with heuristic '{heur}'")
 3415  
 3416      l = self.get_sorted_results("best")
 3417      l.extend(self.get_sorted_results("partial"))
 3418  
 3419      sql = """SELECT distinct cus.id cu_id, cus.name cu_name, cus.start_ea start_ea, cus.end_ea end_ea
 3420                 FROM {db}.compilation_unit_functions cuf,
 3421                      {db}.compilation_units cus,
 3422                      {db}.functions f
 3423                WHERE f.id = cuf.func_id
 3424                  AND cus.id = cuf.cu_id
 3425                  AND f.name = ?"""
 3426      sql_main = sql.replace("{db}", "main")
 3427      sql_diff = sql.replace("{db}", "diff")
 3428  
 3429      sql = f"""select """ + get_query_fields(heur) + """
 3430                 from functions f,
 3431                      diff.functions df
 3432                where cast(f.address as real)  between ? and ?
 3433                  and cast(df.address as real) between ? and ? """
 3434  
 3435      cur = self.db_cursor()
 3436      try:
 3437        for match in l:
 3438          ratio = match[5]
 3439          if ratio < config.RELATED_MATCHES_MIN_RATIO:
 3440            break
 3441  
 3442          name1 = match[1]
 3443          name2 = match[3]
 3444          cur.execute(sql_main, (name1,))
 3445          main_row = cur.fetchone()
 3446  
 3447          cur.execute(sql_diff, (name2,))
 3448          diff_row = cur.fetchone()
 3449  
 3450          if main_row is None or diff_row is None:
 3451            continue
 3452  
 3453          main_start_ea = float(main_row["start_ea"])
 3454          main_end_ea   = float(main_row["end_ea"])
 3455          diff_start_ea = float(diff_row["start_ea"])
 3456          diff_end_ea   = float(diff_row["end_ea"])
 3457          cur.execute(sql, (main_start_ea, main_end_ea, diff_start_ea, diff_end_ea))
 3458          self.add_matches_internal(cur, "best", "partial")
 3459      finally:
 3460        cur.close()
```

### 9.1 Tables

```python
# db_support/schema.py:174-185
  174    """ create table if not exists compilation_units (
  175                    id integer primary key,
  176                    name text,
  177                    functions int,
  178                    primes_value text,
  179                    pseudocode_primes text,
  180                    start_ea text unique,
  181                    end_ea text)""",
  182    """ create table if not exists compilation_unit_functions (
  183                    id integer primary key,
  184                    cu_id integer not null references compilation_units(id) on delete cascade,
  185                    func_id integer not null references functions(id) on delete cascade)"""
```

`start_ea` and `end_ea` are decimal TEXT. Sample: `('4215968', '4219295')`.

### 9.2 Porting spec

```
find_related_compilation_unit(iteration):
    cleanup_matches()
    l = stable_sort_desc(best) ++ stable_sort_desc(partial)      # one list
    for m in l:
        if m.ratio < 0.8: break                                  # exits the WHOLE loop
        cu1 = first_cu(main, m.name1); cu2 = first_cu(diff, m.name2)
        if cu1 == null or cu2 == null: continue
        lo1,hi1 = double(cu1.start_ea), double(cu1.end_ea)       # Python float(): correctly rounded
        lo2,hi2 = double(cu2.start_ea), double(cu2.end_ea)
        rows = [ (f, df) for f in main.functions ordered by id asc
                          if lo1 <= double(f.address) <= hi1               # BETWEEN is inclusive
                          for df in diff.functions ordered by id asc
                          if lo2 <= double(df.address) <= hi2 ]
        add_matches_internal(rows, "best", "partial")            # §2.7: 1,000,000-row cap applies
```

`first_cu(db, name)`:

- Take the functions with that name in ascending `id` (plan: `SEARCH f USING COVERING INDEX idx_2 (name=?)`).
- For each, take its `compilation_unit_functions` rows in ascending `(func_id, rowid)` (`SEARCH cuf USING INDEX idx_39 (func_id=?)`).
- Return the first `cu_id` that has a `compilation_units` row.
- `DISTINCT` does not reorder, and `fetchone()` takes the first.
- The sample had no function in more than one CU.

Notes:

- **No deduplication across seeds.** Every seed match with ratio ≥ 0.8 re-runs its CU cartesian product, even when an earlier seed used the same `(cu1, cu2)` pair. The repeats are **not** idempotent with respect to state: accepted adds change `has_best_match` / `has_better_match`, and re-adding an identical item re-asserts the `matched_*` maps. Execute literally, once per seed, in order.
- **Row order** follows the plan `SCAN f` / `SCAN df`: nested loops in rowid order, with the `f` range filter applied in the outer loop, so the order is `(f.id, df.id)` ascending. For the **integer address strings** used here, `cast(address as real)` equals a correctly rounded parse of the decimal string (checked on 20,717 values, including 20-digit ones). Do **not** generalise that to arbitrary decimal text: SQLite 3.51.1 mis-rounds at least one long fractional `md_index` string by one ulp (§2.8). A cartesian product above 1,000,000 rows is truncated in exactly this order.
- `from functions f` (unqualified) resolves to the main schema.
- **Cost on real PE exports.** The largest CU ranges hold 580 and 576 functions in `userenv-9168-pdb` / `userenv-9278-nopdb`, and 867 and 851 in `sechost-9168-pdb` / `sechost-9444-nopdb`. Each seed that lands in them therefore replays a cartesian product of about 334k rows (userenv) or about 738k rows (sechost, under the 1,000,000 cap). In Python each userenv replay took about 12-17 s, and it is repeated for every qualifying seed in every outer iteration. This is why the Python runs of those pairs did not finish within the ~25 minutes they were given (§0). The oracle runs of the same pairs (`oracle/diffs/*/run1/diaphora.log`) were still inside the **first** outer iteration's "Related compilation unit" pass at 01:10, 43 minutes after they started (V9). By then userenv had logged 151 replays of at least 50,000 rows and sechost 51. In C++ the rows are cheap after the first pass (cached ratios, early `has_best_match` exits), but the *sequence* must still be replayed.
- **Inputs:** `compilation_units(id, start_ea, end_ea)`, `compilation_unit_functions(cu_id, func_id)`, `functions(id, name, address)` and the SELECT_FIELDS columns.
- **Outputs:** `best` (1.0) or `partial` (≥ 0.5), with description `Related compilation unit` and no bonus.
- **Runs by default?** Yes, in every outer iteration, without a gate. It is a no-op when either database has no CU rows (for example `EXPORTING_COMPILATION_UNITS = False` at export time).

---

## 10. `find_locally_affine_functions(iteration)`

```python
# diaphora.py:3315-3360
 3315    def find_locally_affine_functions(self, iteration):
 3316      """
 3317      Try to find functions between the unmatched functions space inside two
 3318      previously matched functions.
 3319  
 3320      So, let's suppose the following example:
 3321  
 3322        Bin1  Bin2  Matched?
 3323        ---   ---   ---
 3324        F1    F1'   Yes
 3325        F2    F2'   No
 3326        F3    F3'   No
 3327        F4    F4'   Yes
 3328  
 3329      Considering how compilers & linkers (in general) work, chances are very high
 3330      that functions F2 and F3 correspond to F2' and F3', so we try to find those
 3331      functions that should correspond to the gap between unmatched functions and
 3332      then brute force these subsets when they have a maximum hardcoded number of
 3333      MAX_FUNCTIONS_PER_GAP. We don't consider bigger gaps. For now.
 3334      """
 3335      heur = "Local affinity"
 3336      enabled = self.call_hook("on_special_heuristic", True, [heur, iteration])
 3337      if not enabled:
 3338        return
 3339  
 3340      self.cleanup_matches()
 3341      log_refresh("Finding locally affine functions")
 3342  
 3343      tmp_matches = list(self.all_matches["best"])
 3344      tmp_matches.extend(list(self.all_matches["partial"]))
 3345      tmp_matches = sorted(tmp_matches, key=lambda x: [int(x[0]), int(x[2])])
 3346  
 3347      size = len(tmp_matches)
 3348      for i, match in enumerate(tmp_matches):
 3349        if i == 0 or i == size:
 3350          continue
 3351  
 3352        prev = tmp_matches[i - 1]
 3353        prev_ea1 = prev[0]
 3354        prev_ea2 = prev[2]
 3355        curr_ea1 = match[0]
 3356        curr_ea2 = match[2]
 3357  
 3358        area1 = [prev_ea1, curr_ea1]
 3359        area2 = [prev_ea2, curr_ea2]
 3360        self.find_functions_between(area1, area2)
```

Porting spec:

```
find_locally_affine_functions(iteration):
    cleanup_matches()
    t = best ++ partial                                      # current list order (sorted by the cleanup)
    t = stable_sort(t, key = (uint64(ea1), uint64(ea2)))     # NUMERIC here; Python int() of the decimal text
    for i in 1 .. |t|-1:                                     # `i == size` is never true
        find_functions_between([t[i-1].ea1, t[i].ea1], [t[i-1].ea2, t[i].ea2])   # the TEXT strings
```

- The ranges are built from **consecutive entries in numeric `ea1` order**. The diff-side range `[prev.ea2, cur.ea2]` has no ordering guarantee and can be "reversed".
- Duplicate `ea1` entries (multimatch candidates) give empty main ranges.
- **Runs by default?** Yes, in every outer iteration.

## 11. `find_functions_between(range1, range2)`

```python
# diaphora.py:3231-3313
 3231    def find_functions_between(self, range1, range2):
 3232      """
 3233      Find the 'bester' matches in the functions gap specified by the given ranges
 3234      """
 3235      cur = self.db_cursor()
 3236      sql = """select *
 3237           from {db}.functions
 3238          where address > ?
 3239            and address < ?
 3240          order by address desc"""
 3241      try:
 3242        heur_text = "Local affinity"
 3243  
 3244        # First, retrieve the main database functions in that area...
 3245        cur.execute(sql.format(db="main"), range1)
 3246        main_rows = list(cur.fetchall())
 3247        size = len(main_rows)
 3248        # If the number of functions in that gap is less than a hardcoded size, do
 3249        # continue...
 3250        if size > 0 and size <= config.MAX_FUNCTIONS_PER_GAP:
 3251          # Then retrieve the diff database functions in that area...
 3252          cur.execute(sql.format(db="diff"), range2)
 3253          diff_rows = list(cur.fetchall())
 3254          size = len(diff_rows)
 3255          # Check again the same number of maximum hardcoded functions that we'll
 3256          # consider for this heuristic...
 3257          if size > 0 and size <= config.MAX_FUNCTIONS_PER_GAP:
 3258            local_main_matched = set()
 3259            main_score = {}
 3260            local_diff_matched = set()
 3261            diff_score = {}
 3262  
 3263            # And then, brute force all of these functions to find good matches
 3264            # regardless of the position.
 3265            for main_row in main_rows:
 3266              for diff_row in diff_rows:
 3267                name1 = main_row["name"]
 3268                name2 = diff_row["name"]
 3269                if name1.startswith("nullsub_") or name2.startswith("nullsub_"):
 3270                  continue
 3271                if not name1.startswith("sub_") and not name2.startswith("sub_"):
 3272                  continue
 3273  
 3274                pseudocode_lines1 = main_row["pseudocode_lines"]
 3275                pseudocode_lines2 = diff_row["pseudocode_lines"]
 3276                if pseudocode_lines1 + pseudocode_lines2 != 0:
 3277                  if pseudocode_lines1 == 3 or pseudocode_lines2 == 3:
 3278                    continue
 3279  
 3280                r = self.compare_function_rows(main_row, diff_row)
 3281                if r == 1.0:
 3282                  chooser = "best"
 3283                elif r >= config.DEFAULT_PARTIAL_RATIO:
 3284                  chooser = "partial"
 3285                else:
 3286                  continue
 3287  
 3288                # If we have a previous match with the same score we discard this
 3289                # second one, as this heuristics orders functions by address in
 3290                # both functions and due to how compilers/linkers work, the first
 3291                # matches are the best ones in this case.
 3292                if name1 in local_main_matched and main_score[name1] >= r:
 3293                  continue
 3294                if name2 in local_diff_matched and diff_score[name2] >= r:
 3295                  continue
 3296  
 3297                should_add, r = self.call_on_match_hook(heur_text, r, main_row, diff_row)
 3298                if should_add:
 3299                  ea1 = main_row["address"]
 3300                  ea2 = diff_row["address"]
 3301                  name1 = main_row["name"]
 3302                  name2 = diff_row["name"]
 3303                  nodes1 = int(main_row["nodes"])
 3304                  nodes2 = int(diff_row["nodes"])
 3305                  new_item = [ ea1, name1, ea2, name2, heur_text, r, nodes1, nodes2 ]
 3306                  self.add_match(name1, name2, r, new_item, chooser)
 3307  
 3308                  local_main_matched.add(name1)
 3309                  main_score[name1] = r
 3310                  local_diff_matched.add(name2)
 3311                  diff_score[name2] = r
 3312      finally:
 3313        cur.close()
```

### 11.1 Lexicographic TEXT comparison

`functions.address` has TEXT affinity and the bound parameters are Python `str`, so `address > ? AND address < ?` and `ORDER BY address DESC` compare **as byte strings** (BINARY collation). Probe (TEXT column holding 999, 1000, 4097, 5000, 8191, 9999, 10000, 12345, 40970, 99999, 100000):

```
(str)  4096 < a < 8192     -> ['8191', '5000', '40970', '4097']      # 40970 included!
(int)  same params as int  -> identical (TEXT affinity is applied to the parameter)
(str)  999  < a < 10000    -> []                                    # '999' > '10000' lexicographically
order by address desc      -> ['99999','9999','999','8191','5000','40970','4097','12345','100000','10000','1000']
```

- The plan is `SEARCH main.functions USING INDEX idx_28 (address>? AND address<?)` (`idx_28` = `functions(address)`, `schema.py:52`). The index delivers the DESC order directly, with no temp B-tree.
- C++: compare the decimal strings with `memcmp` semantics, and sort gap rows by the same byte order, descending.
- **Do not** compare numerically. That matches only while every address in play has the same number of decimal digits.
- Variants `c` and `x` shifted the diff side across 10,000,000, but numeric and text semantics still produced identical results, because the crossing gaps held no candidates. The divergence is real at the SQL level but was not exercised by outcomes (Open question 5).

### 11.2 Porting spec

```
find_functions_between(r1, r2):
    mains = [f in main.functions : r1[0] < f.address < r1[1] (bytewise)], sorted by address DESC (bytewise)
    if !(0 < |mains| <= 100): return                     # MAX_FUNCTIONS_PER_GAP = 100
    diffs = [same for diff with r2]
    if !(0 < |diffs| <= 100): return
    localMain = map<name,double>, localDiff = map<name,double>
    for a in mains:                                      # outer = main rows, DESC
        for b in diffs:                                  # inner = diff rows, DESC
            if a.name starts "nullsub_" or b.name starts "nullsub_": continue      # WITH underscore here
            if !a.name.starts("sub_") and !b.name.starts("sub_"): continue       # at least one anonymous
            p1, p2 = a.pseudocode_lines, b.pseudocode_lines                       # INTEGER; NULL → TypeError
            if p1 + p2 != 0 and (p1 == 3 or p2 == 3): continue
            r = compare_function_rows(a, b)
            if r == 1.0: ch = best elif r >= 0.5: ch = partial else continue      # >= here (DEFAULT_PARTIAL_RATIO)
            if a.name in localMain and localMain[a.name] >= r: continue
            if b.name in localDiff and localDiff[b.name] >= r: continue
            add_match(a.name, b.name, r, [a.address, a.name, b.address, b.name, "Local affinity", r, a.nodes, b.nodes], ch)
            localMain[a.name] = r; localDiff[b.name] = r     # recorded even if add_match silently rejected it
```

Notes:

- The gap rows include **already-matched functions** on both sides. Nothing filters them except `add_match`'s `has_better_match`. For example, a diff function matched elsewhere at 0.7 can be re-matched here at ≥ 0.7, which creates a diff-side duplicate for the final pass.
- There is **no** `has_best_match` check, no bonus and no `nullsub` check without an underscore.
- **Inputs:** `functions.address` (TEXT), `name`, `pseudocode_lines` (INTEGER), `nodes`, and the `compare_function_rows` fields.
- **Outputs:** `best` (1.0) or `partial` (≥ 0.5), with description `Local affinity`.
- **Runs by default?** Yes (via §10).

---

## 12. `final_pass`

```python
# diaphora.py:2937-2948
 2937    def final_pass(self):
 2938      """
 2939      Do the last pass:
 2940  
 2941      1. Remove duplicated or wrong matches.
 2942      2. Find multimatches.
 2943      3. Fill the choosers with the final cleaned up results.
 2944      """
 2945      self.cleanup_matches()
 2946  
 2947      max_main, max_diff, ignore_main, ignore_diff = self.find_multimatches()
 2948      self.add_final_chooser_items(ignore_main, ignore_diff, max_main, max_diff)
```

**Runs by default?** Always, in both branches (`diaphora.py:3677`). `equal_db()` never clears `do_continue`: it only logs, `:3600-3601`, and `do_continue` is set True at `:3599`. So only an exception or a failed `load_hooks()` (`:3609-3610`) prevents it. Its input is the in-memory `all_matches` after `cleanup_matches()`. That leading cleanup rebuilds `matched_primary`/`matched_secondary` (§2.5), and nothing else in the final pass touches them.

A consequence for the unmatched lists: `find_unmatched` (`diaphora.py:2323-2356`) runs after `final_pass` and uses those name maps as rebuilt by the final cleanup. A function whose only match was dropped by the final filter (or diverted to multimatch) is therefore **not** listed as unmatched.

## 13. `find_multimatches` / `find_unresolved_multimatches`

```python
# diaphora.py:2839-2914
 2839    def find_unresolved_multimatches(self, max_main, multi_main, max_diff, multi_diff):
 2840      """
 2841      Find unresolved multimatches.
 2842      """
 2843      # First pass, group them
 2844      dones = set()
 2845      for key, items in self.all_matches.items():
 2846        l = sorted(items, key=lambda x: float(x[5]), reverse=True)
 2847        for match in l:
 2848          ea1 = match[0]
 2849          ea2 = match[2]
 2850          ratio = match[5]
 2851  
 2852          key = f"{ea1}-{ea2}"
 2853          if key in dones:
 2854            continue
 2855          dones.add(key)
 2856  
 2857          if ea1 not in max_main:
 2858            max_main[ea1] = ratio
 2859  
 2860          # If the previous ratio we got is less than this one, ignore
 2861          if max_main[ea1] > ratio:
 2862            continue
 2863          max_main[ea1] = ratio
 2864  
 2865          item = [ea2, ratio, match]
 2866          try:
 2867            multi_main[ea1].append(item)
 2868          except KeyError:
 2869            multi_main[ea1] = [item]
 2870  
 2871          if ea2 not in max_diff:
 2872            max_diff[ea2] = ratio
 2873  
 2874          # If the previous ratio we got is less than this one, ignore
 2875          if max_diff[ea2] > ratio:
 2876            continue
 2877          max_diff[ea2] = ratio
 2878  
 2879          item = [ea1, ratio, match]
 2880          try:
 2881            multi_diff[ea2].append(item)
 2882          except KeyError:
 2883            multi_diff[ea2] = [item]
 2884  
 2885      return max_main, multi_main, max_diff, multi_diff
 2886  
 2887    def find_multimatches(self):
 2888      """
 2889      Find all the multimatches that were not solved.
 2890      """
 2891      max_main = {}
 2892      max_diff = {}
 2893      multi_main = {}
 2894      multi_diff = {}
 2895  
 2896      # First, find all the unresolved multimatches
 2897      values = self.find_unresolved_multimatches(
 2898        max_main, multi_main, max_diff, multi_diff
 2899      )
 2900      max_main, multi_main, max_diff, multi_diff = values
 2901  
 2902      # Now, add them to the corresponding chooser
 2903      ignore_main = set()
 2904      ignore_diff = set()
 2905      dones = set()
 2906  
 2907      ignore_main, dones = self.add_multimatches_to_chooser(
 2908        multi_main, ignore_main, dones
 2909      )
 2910      ignore_diff, dones = self.add_multimatches_to_chooser(
 2911        multi_diff, ignore_diff, dones
 2912      )
 2913  
 2914      return max_main, max_diff, ignore_main, ignore_diff
```

Porting spec:

```
maxMain, maxDiff : map<string ea, double>
multiMain, multiDiff : insertion-ordered map<string ea, vector<MatchItem>>
seen : set<string>
for cat in [best, partial, unreliable]:
    for m in stable_sort_desc_by_ratio(all_matches[cat]):
        k = m.ea1 + "-" + m.ea2                # ADDRESS key here (names in cleanup)
        if k in seen: continue ; seen.add(k)
        if m.ea1 not in maxMain: maxMain[m.ea1] = m.ratio
        if maxMain[m.ea1] > m.ratio: continue  # skips the diff side too
        maxMain[m.ea1] = m.ratio ; multiMain[m.ea1].push(m)
        if m.ea2 not in maxDiff: maxDiff[m.ea2] = m.ratio
        if maxDiff[m.ea2] > m.ratio: continue
        maxDiff[m.ea2] = m.ratio ; multiDiff[m.ea2].push(m)
```

- `multiMain[ea1]` collects every item visited while its ratio was **≥ the running maximum**. The visit order is category-major, so in general this is not just "ties at the max": an `unreliable` item with a higher ratio than a `partial` item for the same `ea1` is appended after it.
- **Default-config simplification:** `unreliable` is empty (see the note below), `best` items are 1.0 and `partial` items are < 1.0. Under these conditions `|multiMain[ea]| > 1` iff at least two items tie at the maximum.
- An item that tied on the main side but lost on the diff side stays in `multiMain`.
- The loop variable `key` is shadowed at `:2852`, with no effect.

Why `unreliable` is empty by default:

- In `add_matches_internal`, whenever `partial is not None`, every `r >= val` goes to `partial` (`:1928`). The `else` branch therefore sees only `r < val`, while the unreliable branch requires `r > val` (`:1940`), so it is dead for any such call, whatever `val` is. That covers this scope (`val=None` → 0.5) and the `HEUR_TYPE_RATIO_MAX`/`_TRUSTED` wrappers (`:1987-1989`, `:2013-2015`), which pass `unreliable=` but also a non-None `partial`. The only calls with `partial=None` are in `find_brute_force` (`:2278-2280`, `:2299-2301`, with `best="unreliable"`). The only calls with `partial="unreliable"` are Unreliable-category heuristics (`:1510-1512`). Both run only when `self.unreliable` is set (`:3638`, `:1498`, `:2318`).
- `find_unreliable_matches` / `find_brute_force` do not run.
- Instrumented runs reported `Unreliable 0` in all variants.

## 14. `add_multimatches_to_chooser`

```python
# diaphora.py:2732-2747
 2732    def add_multimatches_to_chooser(self, multi, ignore_list, dones):
 2733      """
 2734      Add the multimatches found in the list @multi and build the list of functions
 2735      to be ignored (@ignore_list).
 2736      """
 2737      for ea in multi:
 2738        if len(multi[ea]) > 1:
 2739          for multi_match in multi[ea]:
 2740            item = self.itemize_for_chooser(multi_match[2])
 2741            key = f"{item.ea}-{item.ea2}"
 2742            if key not in dones:
 2743              dones.add(key)
 2744              self.multimatch_chooser.add_item(item)
 2745              ignore_list.add(ea)
 2746  
 2747      return ignore_list, dones
```

Porting spec, called first with `(multiMain, ignoreMain, done)` and then with `(multiDiff, ignoreDiff, done)`, **sharing `done`**:

```
for (ea, list) in multi (insertion order):
    if |list| > 1:
        for m in list:
            k = m.ea1 + "-" + m.ea2
            if k not in done: done.add(k); multimatch_chooser.add_item(m); ignore.add(ea)
```

`ignore.add(ea)` happens **only when at least one of `ea`'s items was newly added**. Suppose every item of a `multiDiff[ea2]` group was already added during the main pass. Then `ea2` is **not** put in `ignoreDiff`. Those items are still excluded later, because their `ea1` is in `ignoreMain`.

## 15. `add_final_chooser_items`

```python
# diaphora.py:2916-2935
 2916    def add_final_chooser_items(self, ignore_main, ignore_diff, max_main, max_diff):
 2917      """
 2918      Build the final matches list and add matches to the corresponding chooser.
 2919      """
 2920      CHOOSERS = {
 2921        "best": self.best_chooser,
 2922        "partial": self.partial_chooser,
 2923        "unreliable": self.unreliable_chooser,
 2924      }
 2925      for key, l in self.all_matches.items():
 2926        l = sorted(l, key=lambda x: float(x[5]), reverse=True)
 2927        for match in l:
 2928          item = self.itemize_for_chooser(match)
 2929          if item.ea in ignore_main or item.ea2 in ignore_diff:
 2930            continue
 2931          if item.ratio < max_main[item.ea]:
 2932            continue
 2933          if item.ratio < max_diff[item.ea2]:
 2934            continue
 2935          CHOOSERS[key].add_item(item)
```

Porting spec:

```
for cat in [best, partial, unreliable]:
    for m in stable_sort_desc_by_ratio(all_matches[cat]):
        if m.ea1 in ignoreMain or m.ea2 in ignoreDiff: continue
        if m.ratio < maxMain[m.ea1]: continue
        if m.ratio < maxDiff[m.ea2]: continue
        chooser[cat].add_item(m)          # category is preserved: an item never changes category here
```

The `maxDiff[m.ea2]` lookup cannot raise `KeyError` when names are unique per database. Any item with `ratio ≥ final maxMain[ea1]` passed the main-side check when it was visited, and that check always initialises `maxDiff[ea2]`.

**Outputs:** the `best_chooser`, `partial_chooser`, `unreliable_chooser` and `multimatch_chooser` item lists (formatted per §2.14), in exactly the iteration order above.

## 16. From choosers to the `.diaphora` file (context)

```python
# diaphora.py:2374-2429
 2374    def save_results(self, filename):
 2375      """
 2376      Save all the results (best, partial, unreliable, multimatches and unmatched)
 2377      to the file @filename.
 2378      """
 2379      if os.path.exists(filename):
 2380        os.remove(filename)
 2381        log(f"Previous diff results '{filename}' removed.")
 2382  
 2383      results_db = sqlite3_connect(filename)
 2384  
 2385      cur = results_db.cursor()
 2386      try:
 2387        sql = "create table config (main_db text, diff_db text, version text, date text)"
 2388        cur.execute(sql)
 2389  
 2390        sql = "insert into config values (?, ?, ?, ?)"
 2391        cur.execute(
 2392          sql, (self.db_name, self.last_diff_db, VERSION_VALUE, time.asctime())
 2393        )
 2394  
 2395        sql = """create table results (type, line, address, name, address2, name2,
 2396                     ratio, nodes1, nodes2, description)"""
 2397        cur.execute(sql)
 2398  
 2399        sql = "create unique index uq_results on results(address, address2)"
 2400        cur.execute(sql)
 2401  
 2402        sql = "create table unmatched (type, line, address, name)"
 2403        cur.execute(sql)
 2404  
 2405        with results_db:
 2406          results_sql = "insert or ignore into results values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
 2407          unmatched_sql = "insert into unmatched values (?, ?, ?, ?)"
 2408  
 2409          d = {
 2410            "best": [self.best_chooser, results_sql],
 2411            "partial": [self.partial_chooser, results_sql],
 2412            "unreliable": [self.unreliable_chooser, results_sql],
 2413            "multimatch": [self.multimatch_chooser, results_sql],
 2414            "primary": [self.unmatched_primary, unmatched_sql],
 2415            "secondary": [self.unmatched_second, unmatched_sql],
 2416          }
 2417  
 2418          for category, fields in d.items():
 2419            chooser, sql_cmd = fields
 2420            if chooser is not None:
 2421              for item in chooser.items:
 2422                item_list = list(item)
 2423                item_list.insert(0, category)
 2424                cur.execute(sql_cmd, item_list)
 2425  
 2426        log(f"Diffing results saved in file '{filename}'.")
 2427      finally:
 2428        cur.close()
 2429        results_db.close()
```

- The output order is `best`, `partial`, `unreliable`, `multimatch`, then the unmatched lists.
- The `results` insert is `insert or ignore` with a UNIQUE index on `(address, address2)`, the formatted hex strings, so the first occurrence wins. §12-15 never produce the same address pair twice when names are unique.
- Every value is written as TEXT, because the chooser rows are strings. `create_choosers` (`:2358-2372`) creates `ml_chooser`, but `save_results` does not write it.
- **The unmatched labels are swapped** (context; specified in `01-driver.md` §10.3). `find_unmatched` stores the "Unmatched in primary" chooser, built from `select name, address from functions` (main), in `self.unmatched_second` (`:2334-2341`). It stores the diff-side chooser in `self.unmatched_primary` (`:2347-2354`). `save_results` writes `unmatched_primary` as `type='primary'` (`:2414-2415`), so **`type='primary'` rows are diff-database functions** and `type='secondary'` rows are main-database functions. Re-verified on the oracle `ls-old_vs_ls` run1 (V10). All 56 `primary` rows match an `ls` (diff) function by name and `%08x` address; 2 of them also coincide with an `ls-old` function. All 14 `secondary` rows match an `ls-old` (main) function; 1 of them also coincides with an `ls` function.

---

## Hard parts

1. **Porting `difflib` exactly.** Callee pairing depends on the exact `get_opcodes` output: `find_longest_match` prefers the earliest `i`, then the earliest `j`; popular lines are purged from `b` only when `len(b) >= 200`; junk extension loops; the queue order in `get_matching_blocks` then a sort then an adjacent merge; `get_grouped_opcodes(3)` trimming. The unified-diff stream must include the two header lines. A near-miss implementation (for example Myers' diff) will produce different hunks and different pairs. Appendix A has all the code involved.
2. **State-order sensitivity.** `has_better_match` (strict `>`, plus the named-function shortcut) and the rebuild of `matched_*` in `cleanup_matches` make results depend on the *exact* sequence of `add_match` calls and cleanups:
   - the walk order (stable ratio sort, insertion order among ties), which is inherited from every earlier phase;
   - SQL row order in §8 and §9 (plan-dependent);
   - bytewise-DESC order in §11;
   - Python set order in §8.

   The C++ `MatchStore` "greedy 1:1 resolve" model does **not** have these semantics. Parity needs an explicit emulation of `all_matches` + `matched_primary`/`matched_secondary` + `add_match` + `cleanup_matches` + the final pass, with ratios as `double` (`Match::Ratio` is currently `float` in `include/dsigmatcher/Types.h`).
3. **The shared `dones` namespace** in callee diffing. It decides which existing matches get expanded in a pass (§5), and it is easy to "fix" by accident. Keep a single `std::unordered_set<std::string>` of `name1 + "-" + name2` strings for both uses.
4. **TEXT-typed address comparisons (§11)** next to numeric sorts (§10, via `int()`) and REAL ranges (§9, via `cast(... as real)`). Three different orderings of the same column appear in adjacent heuristics.
5. **SQLite scalar semantics without SQLite.** `abs(text)` prefix parsing (§8.3), `cast(address as real)` (§9) and TEXT equality (§8, §2.9) must be emulated, because `ExportDatabase` loads rows into memory instead of running these queries. An alternative is to run the in-scope statements (§8, §9, §11, and the §2.9/§2.10 lookups) through SQLite with both DBs attached, which gives the same semantics, plan and order for free (but check Open question 1).
6. **NULL vs empty and crash paths.** Python distinguishes `None` from `""`:
   - `assembly`/`pseudocode` NULL → skipped; `""` → processed.

   Several NULLs raise in Diaphora and abort the whole `diff()` with no output:
   - `nodes` both 0 → `ZeroDivisionError` at `:3089`;
   - NULL `nodes` → `TypeError` at `:3084`;
   - NULL `pseudocode_lines` → `TypeError` at `:3276`;
   - NULL `constants_count` → `TypeError` at `:3493`;
   - NULL `constants` → `TypeError` in `json.loads` (`:3370-3371`);
   - NULL `name` → `AttributeError` on `.startswith` (`:3269`; also `has_better_match:1392` and `check_match:1846`);
   - NULL `compilation_units.start_ea`/`end_ea` → `TypeError` in `float(None)` (`:3453-3456`);
   - NULL `nodes1`/`nodes2` in an SQL row → `TypeError` in `int(...)` (`:1915-1916`), and in Local affinity `int(main_row["nodes"])` (`:3303-3304`);
   - non-numeric `md_index` text on the `compare_function_rows` path → `ValueError` at `:1672` (§2.8).

   Each of these propagates out of `diff()` (`try/finally` only, `:3593`/`:3699`) and out of the unguarded `bd.diff(db2)` (`:3772`). The interpreter prints a traceback, exits with status 1 and never reaches `save_results` (`:3773`). The timeout's `SystemExit` differs only in exiting with status 0 (§2.7).

   `FunctionTable`'s `PackedString` cannot represent NULL (`StringPool::View` returns an empty view for `Length == 0`, `include/dsigmatcher/Types.h:25-27`), and the integer columns are plain `int64_t` vectors. A NULL flag per column is needed, or at least for `assembly`, `pseudocode`, `constants`, `pseudocode_lines`, `nodes` and `constants_count`. As read for this verification, `FunctionTable` (`Types.h:52-84`) has **no** raw `assembly`, `pseudocode`, `pseudocode_primes` or `switches` column at all; it has only the `Clean*` text variants. §5/§6 (raw `assembly`/`pseudocode`) and `deep_ratio` (`pseudocode_primes`, `switches`) need those columns loaded.

   Real exports: `pseudocode` is NULL in 106/113/1/1/1/1/5 rows (ls-old/ls/userenv-9168/userenv-9278-nopdb/userenv-9278-pdb/sechost-9168/sechost-9444), and **none** of the crash-prone columns is NULL or 0 (`nodes`, `pseudocode_lines`, `constants_count`, `constants`). Re-verified on six of the seven exports (all except `userenv-9278-pdb`) (V5). `name`, `compilation_units.start_ea`/`end_ea` are never NULL there either, and every `md_index` parses with `float()`.
7. **Unicode details.** `splitlines` separators (§6.1) and the four extra IGNORECASE letters (§6.4) require decoding code points. Byte-level ASCII scanning mis-handles U+0085, U+2028/9, `ſ`, `K`, `İ` and `ı`.
8. **Output formatting.** `%.7f` must be correctly rounded (`std::to_chars`). `%08x` of the decimal address must use lowercase and a minimum width of 8. `%05lu` line counters are per chooser.
9. **Cost.** The outer loop is unbounded and re-does all work each round: every seed ≥ 0.8 re-runs its CU cartesian product (≤ 1,000,000 rows each), and every gap is re-brute-forced (≤ 100 × 100). The `ratios_cache` (keyed `"ea1-ea2"` for the whole run) is what keeps Diaphora tractable, so port it. On real PE exports the CU replays dominate: about 334k rows (userenv) and about 738k rows (sechost) per qualifying seed per outer iteration (§9).

## Open questions

1. **SQL row order.** The orders in §8.4, §9.2, §2.9 and §2.10 are SQLite plans, not SQL guarantees (NOT DETERMINED FROM SOURCE). They were confirmed identical, all with 48 `sqlite_stat1` rows (V5), on:
   - the synthetic pair;
   - the real `ls-old`/`ls` and `userenv-9168-pdb`/`userenv-9278-nopdb` exports;
   - in this verification, also `sechost-9168-pdb`/`sechost-9444-nopdb`.

   The plans observed on every pair:

   | Query | Plan |
   |---|---|
   | related constants | `SEARCH mc USING COVERING INDEX idx_35 (constant=?)`, then `f`, `dc`, `df` by rowid/`idx_35` |
   | CU lookup | `SEARCH f USING COVERING INDEX idx_2 (name=?)`, `SEARCH cuf USING INDEX idx_39 (func_id=?)`, `USE TEMP B-TREE FOR DISTINCT` |
   | CU cartesian product | `SCAN f` / `SCAN df` |
   | gap query | `SEARCH … USING INDEX idx_28 (address>? AND address<?)` |
   | `functions_exists` | `UNION USING TEMP B-TREE` + `USE TEMP B-TREE FOR ORDER BY` |
   | `get_function_row` | `SEARCH … USING INDEX idx_2 (name=?)` |

   The `idx_N` names come from `create_indices` numbering `schema.INDICES` from 0 (`diaphora.py:639-644`): `idx_2` = `functions(name)` (`schema.py:26`), `idx_28` = `functions(address)` (`:52`), `idx_35` = `constants(constant, func_id)` (`:59`), `idx_39` = `compilation_unit_functions(func_id)` (`:63`). A different SQLite version or different statistics could change the plans. Re-check `EXPLAIN QUERY PLAN` whenever the oracle environment changes. **Still open** as a guarantee; empirically stable.
2. **Python set iteration order in §8** (`for constant in inter_consts`, `diaphora.py:3389`). The source iterates a plain `set`, and Diaphora never fixes `PYTHONHASHSEED`, so the order of `str` elements is hash-seed dependent (NOT DETERMINED FROM SOURCE whether outputs depend on it). Evidence so far:
   - Variant `a` (seeds 0-5) and the real `ls-old`→`ls` pair (seeds 0, 1, 2, 3, 7) gave identical outputs.
   - **New (V4):** a wrapper that forces the constants loop into sorted and then reverse-sorted `(type, str)` order on `ls-old`→`ls` produced `results` and `unmatched` tables identical to the oracle, including `line`. Forcing two opposite orders is a stronger test than sampling seeds.
   - **Exposure (V6):** order can matter only when a seed pair's intersection holds ≥ 2 string constants that pass `abs(...) == 0` and have rows in both DBs.

     | Pair | Shared zero-prefix string constants | Main functions holding ≥ 2 of them | Same-name pairs whose intersection holds ≥ 2 |
     |---|---|---|---|
     | `ls-old`/`ls` | 110 | 16 | 1 |
     | `userenv-9168-pdb`/`9278-nopdb` | 91 | 27 | 0 |
     | `sechost-9168-pdb`/`9444-nopdb` | 226 | 59 | 8 |

     So sechost is where sensitivity, if any, would show.

   Recommendation unchanged: the C++ iterates in one fixed, documented order (for example first appearance in the main JSON list). Re-run the sorted/reverse-sorted harness (`<scratch>/v06/instr.py`, modes `sorted`/`rsorted`) on sechost once a full Python run is affordable, and treat any residual diffs as a known class.
3. **Duplicate function names within one DB.** These trigger the `functions_exists` mis-pairing (§2.10) and the lowest-id choice in `get_function_row` / `first_cu`. All seven real exports have **0** duplicated names (re-verified on six, V5), so these paths are dormant there. Keep the check (`select name, count(*) from functions group by name having count(*) > 1`) in the corpus audit. A probe on a scratch copy (V8) confirmed the §2.10 orders: two main rows named `dupname` (ids 302 and 304) with no diff row gave `[('main', 302), ('main', 304)]` and `exists == True`, and `get_function_row` returned id 302.
4. **Full-loop parity on `userenv-9168-pdb`→`9278-nopdb` and `sechost-9168-pdb`→`9444-nopdb`.** Still unvalidated. The oracle's own runs of these pairs (`oracle/diffs/<pair>/run1`) had produced no `.diaphora` file at 01:10, 43 minutes in, and were still inside the first "Related compilation unit" pass (V9). Compare against those outputs if and when they complete.
5. **Effect of lexicographic gaps on real binaries.** Only comparisons *within one DB* matter: the main range uses main addresses and the diff range uses diff addresses. Every real export here has a uniform decimal address length (`ls`/`ls-old` 7 digits, the PE64 exports 10; re-verified on six exports with `min/max(length(address))`, V5), so on them text order equals numeric order, and a reversed range selects nothing under both semantics. The hazard remains for images that straddle a power of ten, for example a 32-bit image based at 0x400000 that is larger than about 5.8 MB and so crosses 10,000,000. There, a "reversed" diff-side range such as `('10000500','9999000')` selects a *large* lexicographic slice, possibly ≤ 100 rows, and triggers a spurious brute force. No outcome here exercised either case; the C++ must still implement bytewise comparison.
6. **Crash parity.** For the NULL / zero-node / non-numeric paths in Hard parts §6, decide whether the C++ should (a) fail the same way, or (b) skip the pair and report a divergence. The source defines only (a): the exception escapes `diff()` and `__main__` (`:3593`/`:3699`, `:3772`), Python prints a traceback, exits with status 1 and writes no `.diaphora` file. The choice between (a) and (b) is the orchestrator's; it is not determinable from source.
7. **Timeouts.** Source facts (§2.7): the 300 s check is per `add_matches_internal` call, wall-clock only in this scope, and it raises an uncaught `SystemExit()`, so the process exits with **status 0 and no output file**. The recommendation stands: do not port the timeout, keep the deterministic 1,000,000-row cap, and have the oracle harness flag "exit 0 without output" as a timeout.
8. **Behaviour with hooks, `DIAPHORA_*` environment overrides, `unreliable=True` or `relaxed_ratio=True`.** These are out of the default path and were not validated here. The final-pass spec is written for the general case (including `unreliable`), but only the default configuration was exercised. Source facts relevant to the override case:
   - Every `DIAPHORA_*` value arrives as a raw `str` (§1.1), so `DIAPHORA_UNRELIABLE=0` *enables* unreliable mode.
   - The two limit overrides crash with `TypeError` on first use (§2.7).
   - With hooks loaded, `call_on_match_hook` passes the main name as `d2["name"]` (§2.11).

---

## Appendix A: stdlib `difflib` code used by `unified_diff` (Python 3.13.12, verbatim)

`03b-text-difflib.md` covers `SequenceMatcher` as used by the ratio functions. This appendix quotes exactly the parts that `unified_diff` needs. `SequenceMatcher(isjunk=None, a='', b='', autojunk=True)` (`difflib.py:120`). `unified_diff` constructs it as `SequenceMatcher(None, a, b)`, so there is no junk function, but autojunk is on.

```python
# <miniconda3>/Lib/difflib.py:266-303
  266      def __chain_b(self):
  267          # Because isjunk is a user-defined (not C) function, and we test
  268          # for junk a LOT, it's important to minimize the number of calls.
  269          # Before the tricks described here, __chain_b was by far the most
  270          # time-consuming routine in the whole module!  If anyone sees
  271          # Jim Roskind, thank him again for profile.py -- I never would
  272          # have guessed that.
  273          # The first trick is to build b2j ignoring the possibility
  274          # of junk.  I.e., we don't call isjunk at all yet.  Throwing
  275          # out the junk later is much cheaper than building b2j "right"
  276          # from the start.
  277          b = self.b
  278          self.b2j = b2j = {}
  279  
  280          for i, elt in enumerate(b):
  281              indices = b2j.setdefault(elt, [])
  282              indices.append(i)
  283  
  284          # Purge junk elements
  285          self.bjunk = junk = set()
  286          isjunk = self.isjunk
  287          if isjunk:
  288              for elt in b2j.keys():
  289                  if isjunk(elt):
  290                      junk.add(elt)
  291              for elt in junk: # separate loop avoids separate list of keys
  292                  del b2j[elt]
  293  
  294          # Purge popular elements that are not junk
  295          self.bpopular = popular = set()
  296          n = len(b)
  297          if self.autojunk and n >= 200:
  298              ntest = n // 100 + 1
  299              for elt, idxs in b2j.items():
  300                  if len(idxs) > ntest:
  301                      popular.add(elt)
  302              for elt in popular: # ditto; as fast for 1% deletion
  303                  del b2j[elt]
```

```python
# <miniconda3>/Lib/difflib.py:305-305
  305      def find_longest_match(self, alo=0, ahi=None, blo=0, bhi=None):
```

```python
# <miniconda3>/Lib/difflib.py:363-419
  363          a, b, b2j, isbjunk = self.a, self.b, self.b2j, self.bjunk.__contains__
  364          if ahi is None:
  365              ahi = len(a)
  366          if bhi is None:
  367              bhi = len(b)
  368          besti, bestj, bestsize = alo, blo, 0
  369          # find longest junk-free match
  370          # during an iteration of the loop, j2len[j] = length of longest
  371          # junk-free match ending with a[i-1] and b[j]
  372          j2len = {}
  373          nothing = []
  374          for i in range(alo, ahi):
  375              # look at all instances of a[i] in b; note that because
  376              # b2j has no junk keys, the loop is skipped if a[i] is junk
  377              j2lenget = j2len.get
  378              newj2len = {}
  379              for j in b2j.get(a[i], nothing):
  380                  # a[i] matches b[j]
  381                  if j < blo:
  382                      continue
  383                  if j >= bhi:
  384                      break
  385                  k = newj2len[j] = j2lenget(j-1, 0) + 1
  386                  if k > bestsize:
  387                      besti, bestj, bestsize = i-k+1, j-k+1, k
  388              j2len = newj2len
  389  
  390          # Extend the best by non-junk elements on each end.  In particular,
  391          # "popular" non-junk elements aren't in b2j, which greatly speeds
  392          # the inner loop above, but also means "the best" match so far
  393          # doesn't contain any junk *or* popular non-junk elements.
  394          while besti > alo and bestj > blo and \
  395                not isbjunk(b[bestj-1]) and \
  396                a[besti-1] == b[bestj-1]:
  397              besti, bestj, bestsize = besti-1, bestj-1, bestsize+1
  398          while besti+bestsize < ahi and bestj+bestsize < bhi and \
  399                not isbjunk(b[bestj+bestsize]) and \
  400                a[besti+bestsize] == b[bestj+bestsize]:
  401              bestsize += 1
  402  
  403          # Now that we have a wholly interesting match (albeit possibly
  404          # empty!), we may as well suck up the matching junk on each
  405          # side of it too.  Can't think of a good reason not to, and it
  406          # saves post-processing the (possibly considerable) expense of
  407          # figuring out what to do with it.  In the case of an empty
  408          # interesting match, this is clearly the right thing to do,
  409          # because no other kind of match is possible in the regions.
  410          while besti > alo and bestj > blo and \
  411                isbjunk(b[bestj-1]) and \
  412                a[besti-1] == b[bestj-1]:
  413              besti, bestj, bestsize = besti-1, bestj-1, bestsize+1
  414          while besti+bestsize < ahi and bestj+bestsize < bhi and \
  415                isbjunk(b[bestj+bestsize]) and \
  416                a[besti+bestsize] == b[bestj+bestsize]:
  417              bestsize = bestsize + 1
  418  
  419          return Match(besti, bestj, bestsize)
```

```python
# <miniconda3>/Lib/difflib.py:421-421
  421      def get_matching_blocks(self):
```

```python
# <miniconda3>/Lib/difflib.py:440-490
  440          if self.matching_blocks is not None:
  441              return self.matching_blocks
  442          la, lb = len(self.a), len(self.b)
  443  
  444          # This is most naturally expressed as a recursive algorithm, but
  445          # at least one user bumped into extreme use cases that exceeded
  446          # the recursion limit on their box.  So, now we maintain a list
  447          # ('queue`) of blocks we still need to look at, and append partial
  448          # results to `matching_blocks` in a loop; the matches are sorted
  449          # at the end.
  450          queue = [(0, la, 0, lb)]
  451          matching_blocks = []
  452          while queue:
  453              alo, ahi, blo, bhi = queue.pop()
  454              i, j, k = x = self.find_longest_match(alo, ahi, blo, bhi)
  455              # a[alo:i] vs b[blo:j] unknown
  456              # a[i:i+k] same as b[j:j+k]
  457              # a[i+k:ahi] vs b[j+k:bhi] unknown
  458              if k:   # if k is 0, there was no matching block
  459                  matching_blocks.append(x)
  460                  if alo < i and blo < j:
  461                      queue.append((alo, i, blo, j))
  462                  if i+k < ahi and j+k < bhi:
  463                      queue.append((i+k, ahi, j+k, bhi))
  464          matching_blocks.sort()
  465  
  466          # It's possible that we have adjacent equal blocks in the
  467          # matching_blocks list now.  Starting with 2.5, this code was added
  468          # to collapse them.
  469          i1 = j1 = k1 = 0
  470          non_adjacent = []
  471          for i2, j2, k2 in matching_blocks:
  472              # Is this block adjacent to i1, j1, k1?
  473              if i1 + k1 == i2 and j1 + k1 == j2:
  474                  # Yes, so collapse them -- this just increases the length of
  475                  # the first block by the length of the second, and the first
  476                  # block so lengthened remains the block to compare against.
  477                  k1 += k2
  478              else:
  479                  # Not adjacent.  Remember the first block (k1==0 means it's
  480                  # the dummy we started with), and make the second block the
  481                  # new block to compare against.
  482                  if k1:
  483                      non_adjacent.append((i1, j1, k1))
  484                  i1, j1, k1 = i2, j2, k2
  485          if k1:
  486              non_adjacent.append((i1, j1, k1))
  487  
  488          non_adjacent.append( (la, lb, 0) )
  489          self.matching_blocks = list(map(Match._make, non_adjacent))
  490          return self.matching_blocks
```

```python
# <miniconda3>/Lib/difflib.py:492-492
  492      def get_opcodes(self):
```

```python
# <miniconda3>/Lib/difflib.py:521-545
  521          if self.opcodes is not None:
  522              return self.opcodes
  523          i = j = 0
  524          self.opcodes = answer = []
  525          for ai, bj, size in self.get_matching_blocks():
  526              # invariant:  we've pumped out correct diffs to change
  527              # a[:i] into b[:j], and the next matching block is
  528              # a[ai:ai+size] == b[bj:bj+size].  So we need to pump
  529              # out a diff to change a[i:ai] into b[j:bj], pump out
  530              # the matching block, and move (i,j) beyond the match
  531              tag = ''
  532              if i < ai and j < bj:
  533                  tag = 'replace'
  534              elif i < ai:
  535                  tag = 'delete'
  536              elif j < bj:
  537                  tag = 'insert'
  538              if tag:
  539                  answer.append( (tag, i, ai, j, bj) )
  540              i, j = ai+size, bj+size
  541              # the list of matching blocks is terminated by a
  542              # sentinel with size 0
  543              if size:
  544                  answer.append( ('equal', ai, i, bj, j) )
  545          return answer
```

```python
# <miniconda3>/Lib/difflib.py:547-547
  547      def get_grouped_opcodes(self, n=3):
```

```python
# <miniconda3>/Lib/difflib.py:572-595
  572          codes = self.get_opcodes()
  573          if not codes:
  574              codes = [("equal", 0, 1, 0, 1)]
  575          # Fixup leading and trailing groups if they show no changes.
  576          if codes[0][0] == 'equal':
  577              tag, i1, i2, j1, j2 = codes[0]
  578              codes[0] = tag, max(i1, i2-n), i2, max(j1, j2-n), j2
  579          if codes[-1][0] == 'equal':
  580              tag, i1, i2, j1, j2 = codes[-1]
  581              codes[-1] = tag, i1, min(i2, i1+n), j1, min(j2, j1+n)
  582  
  583          nn = n + n
  584          group = []
  585          for tag, i1, i2, j1, j2 in codes:
  586              # End the current group and start a new one whenever
  587              # there is a large range with no changes.
  588              if tag == 'equal' and i2-i1 > nn:
  589                  group.append((tag, i1, min(i2, i1+n), j1, min(j2, j1+n)))
  590                  yield group
  591                  group = []
  592                  i1, j1 = max(i1, i2-n), max(j1, j2-n)
  593              group.append((tag, i1, i2, j1 ,j2))
  594          if group and not (len(group)==1 and group[0][0] == 'equal'):
  595              yield group
```

```python
# <miniconda3>/Lib/difflib.py:1095-1096
 1095  def unified_diff(a, b, fromfile='', tofile='', fromfiledate='',
 1096                   tofiledate='', n=3, lineterm='\n'):
```

```python
# <miniconda3>/Lib/difflib.py:1136-1161
 1136      _check_types(a, b, fromfile, tofile, fromfiledate, tofiledate, lineterm)
 1137      started = False
 1138      for group in SequenceMatcher(None,a,b).get_grouped_opcodes(n):
 1139          if not started:
 1140              started = True
 1141              fromdate = '\t{}'.format(fromfiledate) if fromfiledate else ''
 1142              todate = '\t{}'.format(tofiledate) if tofiledate else ''
 1143              yield '--- {}{}{}'.format(fromfile, fromdate, lineterm)
 1144              yield '+++ {}{}{}'.format(tofile, todate, lineterm)
 1145  
 1146          first, last = group[0], group[-1]
 1147          file1_range = _format_range_unified(first[1], last[2])
 1148          file2_range = _format_range_unified(first[3], last[4])
 1149          yield '@@ -{} +{} @@{}'.format(file1_range, file2_range, lineterm)
 1150  
 1151          for tag, i1, i2, j1, j2 in group:
 1152              if tag == 'equal':
 1153                  for line in a[i1:i2]:
 1154                      yield ' ' + line
 1155                  continue
 1156              if tag in {'replace', 'delete'}:
 1157                  for line in a[i1:i2]:
 1158                      yield '-' + line
 1159              if tag in {'replace', 'insert'}:
 1160                  for line in b[j1:j2]:
 1161                      yield '+' + line
```

With `isjunk=None`, `bjunk` is empty, so in `find_longest_match` the two `isbjunk(...)` extension loops never run. The two `not isbjunk(...)` loops extend over equal elements, **including popular ones**, which were removed only from `b2j`.

## Appendix B: validated SQL-free reference implementation

This is `<scratch>/spec_loop.py`, lines 11-246. It is Python written from this spec: in-memory joins, bytewise address comparison, observed SQLite row orders and a spec final pass. It reuses Diaphora's own `add_match`, `cleanup_matches`, `compare_function_rows` and `add_matches_internal`, which are the primitives specified in §2. With `SPEC=1` installed on a `CBinDiff` object before `diff()`, it produced a `results` table **identical, including line numbers**, to unmodified Diaphora on variants a, b, c and x. Port it function by function.

```python
# <scratch>/spec_loop.py:11-246
   11  NUM = re.compile(r"[ \t\n\v\f\r]*[+-]?([0-9]+\.?[0-9]*|\.[0-9]+)([eE][+-]?[0-9]+)?")
   12  def sqlite_real(t):
   13      if t is None: return None
   14      if isinstance(t, (int, float)): return float(t)
   15      m = NUM.match(t)
   16      if not m: return 0.0
   17      try: return float(m.group(0))
   18      except OverflowError: return float("inf")
   19  
   20  def spec_lines(a, b):
   21      started = False
   22      for group in difflib.SequenceMatcher(None, a, b).get_grouped_opcodes(3):
   23          if not started:
   24              started = True; yield "--- "; yield "+++ "
   25          yield "@@"
   26          for tag, i1, i2, j1, j2 in group:
   27              if tag == "equal":
   28                  for l in a[i1:i2]: yield " " + l
   29                  continue
   30              if tag in ("replace", "delete"):
   31                  for l in a[i1:i2]: yield "-" + l
   32              if tag in ("replace", "insert"):
   33                  for l in b[j1:j2]: yield "+" + l
   34  NAME = re.compile(r"[a-zA-Z_][a-zA-Z0-9_]{3,}(?:(?:::)?[a-zA-Z0-9_]+)*", re.IGNORECASE)
   35  def spec_pairs(t1, t2):
   36      minus, plus = [], []
   37      for row in spec_lines(t1.splitlines(), t2.splitlines()):
   38          c = row[0]
   39          if c == "-": minus.append(row)
   40          elif c == "+": plus.append(row)
   41          elif c == " " and minus and plus:
   42              m1 = NAME.findall("\n".join(minus)); m2 = NAME.findall("\n".join(plus))
   43              minus, plus = [], []
   44              yield from zip(m1, m2)
   45  
   46  class Mem:
   47      def __init__(self, db, schema):
   48          cur = db.cursor()
   49          self.rows = [dict(r) for r in cur.execute(f"select * from {schema}.functions order by id")]
   50          self.by_id = {r["id"]: r for r in self.rows}
   51          self.by_name = {}
   52          for r in self.rows: self.by_name.setdefault(r["name"], []).append(r)
   53          self.consts = {}
   54          for fid, c in cur.execute(f"select func_id, constant from {schema}.constants order by constant, func_id, id"):
   55              self.consts.setdefault(c, []).append(fid)
   56          self.cuf = {}
   57          for fid, cu in cur.execute(f"select func_id, cu_id from {schema}.compilation_unit_functions order by func_id, id"):
   58              self.cuf.setdefault(fid, []).append(cu)
   59          self.cus = {r[0]: (r[1], r[2]) for r in cur.execute(f"select id, start_ea, end_ea from {schema}.compilation_units")}
   60          cur.close()
   61      def first(self, name):
   62          l = self.by_name.get(name); return l[0] if l else None
   63      def cu_of(self, name):
   64          for f in self.by_name.get(name, []):
   65              for cu in self.cuf.get(f["id"], []):
   66                  if cu in self.cus: return self.cus[cu]
   67          return None
   68  
   69  def sel(f, df, heur):
   70      return {"ea": f["address"], "name1": f["name"], "ea2": df["address"], "name2": df["name"], "description": heur,
   71        "pseudo1": f["pseudocode"], "pseudo2": df["pseudocode"], "asm1": f["assembly"], "asm2": df["assembly"],
   72        "pseudo_primes1": f["pseudocode_primes"], "pseudo_primes2": df["pseudocode_primes"],
   73        "nodes1": f["nodes"], "nodes2": df["nodes"], "md1": sqlite_real(f["md_index"]), "md2": sqlite_real(df["md_index"]),
   74        "clean_assembly1": f["clean_assembly"], "clean_assembly2": df["clean_assembly"],
   75        "clean_pseudo1": f["clean_pseudo"], "clean_pseudo2": df["clean_pseudo"],
   76        "mangled1": f["mangled_function"], "mangled2": df["mangled_function"],
   77        "clean_micro1": f["clean_microcode"], "clean_micro2": df["clean_microcode"],
   78        "bytes_hash1": f["bytes_hash"], "bytes_hash2": df["bytes_hash"], "edges1": f["edges"], "edges2": df["edges"],
   79        "indegree1": f["indegree"], "indegree2": df["indegree"], "outdegree1": f["outdegree"], "outdegree2": df["outdegree"],
   80        "instructions1": f["instructions"], "instructions2": df["instructions"],
   81        "cc1": f["cyclomatic_complexity"], "cc2": df["cyclomatic_complexity"],
   82        "strongly_connected1": f["strongly_connected"], "strongly_connected2": df["strongly_connected"],
   83        "loops1": f["loops"], "loops2": df["loops"], "constants_count1": f["constants_count"], "constants_count2": df["constants_count"],
   84        "size1": f["size"], "size2": df["size"], "kgh_hash1": f["kgh_hash"], "kgh_hash2": df["kgh_hash"]}
   85  
   86  class FakeCur:
   87      def __init__(self, it): self.it = iter(it)
   88      def fetchone(self): return next(self.it, None)
   89  
   90  def install(bd):
   91      M = {}
   92      def mem():
   93          if not M:
   94              db = bd.get_db(); M["m"] = Mem(db, "main"); M["d"] = Mem(db, "diff")
   95          return M["m"], M["d"]
   96      total = lambda: len(bd.all_matches["best"]) + len(bd.all_matches["partial"])
   97      srt = lambda k: sorted(bd.all_matches[k], key=lambda x: float(x[5]), reverse=True)
   98      def one(mr, dr, field, heur, iteration, dones):
   99          m, d = mem()
  100          for n1, n2 in spec_pairs(mr[field], dr[field]):
  101              key = f"{n1}-{n2}"
  102              if key in dones: continue
  103              dones.add(key)
  104              if n1.startswith("nullsub") or n2.startswith("nullsub"): continue
  105              l = m.by_name.get(n1, []) + d.by_name.get(n2, [])
  106              if len(l) != 2: continue
  107              a, b = l[0], l[1]
  108              lo, hi = min(a["nodes"], b["nodes"]), max(a["nodes"], b["nodes"])
  109              if (lo * 100) / hi < config.DIFFING_MATCHES_MAX_DIFFERENT_BBLOCKS_PERCENT: continue
  110              if a["nodes"] < config.DIFFING_MATCHES_MIN_BBLOCKS or b["nodes"] < config.DIFFING_MATCHES_MIN_BBLOCKS: continue
  111              r = bd.compare_function_rows(a, b)
  112              if r == 1.0: ch = "best"
  113              elif r > config.DEFAULT_TRUSTED_PARTIAL_RATIO: ch = "partial"
  114              else: continue
  115              if r + config.MATCHES_BONUS_RATIO < 1.0: r += config.MATCHES_BONUS_RATIO
  116              item = [a["address"], n1, b["address"], n2, f"{heur} (iteration #{iteration})", r, int(a["nodes"]), int(b["nodes"])]
  117              bd.add_match(n1, n2, r, item, ch)
  118      def internal(heur, field):
  119          m, d = mem()
  120          it = 1; dones = set()
  121          while it <= 3:
  122              old = total()
  123              for key in ("best", "partial"):
  124                  for x in srt(key):
  125                      mk = f"{x[1]}-{x[3]}"
  126                      if mk in dones: continue
  127                      dones.add(mk)
  128                      a, b = m.first(x[1]), d.first(x[3])
  129                      if a is None or b is None or a[field] is None or b[field] is None: continue
  130                      one(a, b, field, heur, it, dones)
  131              bd.cleanup_matches()
  132              if total() == old: break
  133              it += 1
  134      def fmd(iteration):
  135          bd.cleanup_matches()
  136          if bd.is_same_processor: internal("Callee found diffing matches assembly", "assembly")
  137          internal("Callee found diffing matches pseudo-code", "pseudocode")
  138      def frm(iteration):
  139          m, d = mem()
  140          bd.cleanup_matches()
  141          dones = set()
  142          for key in ("best", "partial"):
  143              for x in srt(key):
  144                  mk = f"{x[1]}-{x[3]}"
  145                  if mk in dones: continue
  146                  dones.add(mk)
  147                  if x[5] < config.RELATED_MATCHES_MIN_RATIO: break
  148                  a, b = m.first(x[1]), d.first(x[3])
  149                  if a is None or b is None: continue
  150                  if a["constants_count"] > 0 and b["constants_count"] > 0:
  151                      inter = set(json.loads(a["constants"])) & set(json.loads(b["constants"]))
  152                      for c in inter:
  153                          c = str(c)
  154                          if sqlite_real(c) != 0: continue
  155                          def rows(c=c):
  156                              for fid in m.consts.get(c, []):
  157                                  f = m.by_id.get(fid)
  158                                  if f is None: continue
  159                                  for dfid in d.consts.get(c, []):
  160                                      df = d.by_id.get(dfid)
  161                                      if df is None: continue
  162                                      yield sel(f, df, "Same constants related matches")
  163                          bd.add_matches_internal(FakeCur(rows()), best="best", partial="partial")
  164      def fcu(iteration):
  165          m, d = mem()
  166          bd.cleanup_matches()
  167          l = srt("best") + srt("partial")
  168          for x in l:
  169              if x[5] < config.RELATED_MATCHES_MIN_RATIO: break
  170              c1, c2 = m.cu_of(x[1]), d.cu_of(x[3])
  171              if c1 is None or c2 is None: continue
  172              lo1, hi1, lo2, hi2 = float(c1[0]), float(c1[1]), float(c2[0]), float(c2[1])
  173              def rows():
  174                  for f in m.rows:
  175                      if not (lo1 <= sqlite_real(f["address"]) <= hi1): continue
  176                      for df in d.rows:
  177                          if lo2 <= sqlite_real(df["address"]) <= hi2:
  178                              yield sel(f, df, "Related compilation unit")
  179              bd.add_matches_internal(FakeCur(rows()), "best", "partial")
  180      def between(r1, r2):
  181          m, d = mem()
  182          # TEXT comparison: Python str order == SQLite BINARY (memcmp of UTF-8) for these ASCII digit strings
  183          mains = sorted([f for f in m.rows if r1[0] < f["address"] < r1[1]], key=lambda f: f["address"], reverse=True)
  184          if not (0 < len(mains) <= config.MAX_FUNCTIONS_PER_GAP): return
  185          diffs = sorted([f for f in d.rows if r2[0] < f["address"] < r2[1]], key=lambda f: f["address"], reverse=True)
  186          if not (0 < len(diffs) <= config.MAX_FUNCTIONS_PER_GAP): return
  187          lm, ms, ld, ds = set(), {}, set(), {}
  188          for a in mains:
  189              for b in diffs:
  190                  n1, n2 = a["name"], b["name"]
  191                  if n1.startswith("nullsub_") or n2.startswith("nullsub_"): continue
  192                  if not n1.startswith("sub_") and not n2.startswith("sub_"): continue
  193                  p1, p2 = a["pseudocode_lines"], b["pseudocode_lines"]
  194                  if p1 + p2 != 0 and (p1 == 3 or p2 == 3): continue
  195                  r = bd.compare_function_rows(a, b)
  196                  if r == 1.0: ch = "best"
  197                  elif r >= config.DEFAULT_PARTIAL_RATIO: ch = "partial"
  198                  else: continue
  199                  if n1 in lm and ms[n1] >= r: continue
  200                  if n2 in ld and ds[n2] >= r: continue
  201                  bd.add_match(n1, n2, r, [a["address"], n1, b["address"], n2, "Local affinity", r, int(a["nodes"]), int(b["nodes"])], ch)
  202                  lm.add(n1); ms[n1] = r; ld.add(n2); ds[n2] = r
  203      def fla(iteration):
  204          bd.cleanup_matches()
  205          t = sorted(list(bd.all_matches["best"]) + list(bd.all_matches["partial"]), key=lambda x: [int(x[0]), int(x[2])])
  206          for i in range(1, len(t)):
  207              between([t[i-1][0], t[i][0]], [t[i-1][2], t[i][2]])
  208  
  209      def spec_final():
  210          bd.cleanup_matches()
  211          allm = bd.all_matches
  212          max_main, max_diff, multi_main, multi_diff, seen = {}, {}, {}, {}, set()
  213          for key, items in allm.items():
  214              for m in sorted(items, key=lambda x: float(x[5]), reverse=True):
  215                  k = f"{m[0]}-{m[2]}"
  216                  if k in seen: continue
  217                  seen.add(k)
  218                  ea1, ea2, r = m[0], m[2], m[5]
  219                  max_main.setdefault(ea1, r)
  220                  if max_main[ea1] > r: continue
  221                  max_main[ea1] = r
  222                  multi_main.setdefault(ea1, []).append(m)
  223                  max_diff.setdefault(ea2, r)
  224                  if max_diff[ea2] > r: continue
  225                  max_diff[ea2] = r
  226                  multi_diff.setdefault(ea2, []).append(m)
  227          added, ign_m, ign_d = set(), set(), set()
  228          for multi, ign in ((multi_main, ign_m), (multi_diff, ign_d)):
  229              for ea, lst in multi.items():
  230                  if len(lst) > 1:
  231                      for m in lst:
  232                          k = f"{m[0]}-{m[2]}"
  233                          if k not in added:
  234                              added.add(k); bd.multimatch_chooser.add_item(diaphora.CChooser.Item(m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7])); ign.add(ea)
  235          ch = {"best": bd.best_chooser, "partial": bd.partial_chooser, "unreliable": bd.unreliable_chooser}
  236          for key, items in allm.items():
  237              for m in sorted(items, key=lambda x: float(x[5]), reverse=True):
  238                  if m[0] in ign_m or m[2] in ign_d: continue
  239                  if m[5] < max_main[m[0]]: continue
  240                  if m[5] < max_diff[m[2]]: continue
  241                  ch[key].add_item(diaphora.CChooser.Item(m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7]))
  242      bd.final_pass = spec_final
  243      bd.find_matches_diffing = fmd
  244      bd.find_related_matches = frm
  245      bd.find_related_compilation_unit = fcu
  246      bd.find_locally_affine_functions = fla
```

---

## Verification log

An adversarial verification pass, run 2026-09-23 against `<diaphora-ref>` (`3.4.2-4-g621ec26`) with Python 3.13.12 and SQLite 3.51.1. Every quoted excerpt and line number was re-checked mechanically. Every behavioural claim was re-read against the source, and the empirical claims were re-run where that was affordable. All experiments ran on copies:
- scripts in `<scratch>/v06/`;
- databases copied to `<scratch>/v06/db/`;
- the unmodified Diaphora copy `<scratch>/dcopy`, which was confirmed byte-identical to the reference for `diaphora.py`, `diaphora_config.py`, `diaphora_heuristics.py`, `db_support/schema.py`, `jkutils/{threads,factor,kfuzzy}.py` and `ml/basic_engine.py`.

Neither the reference nor the oracle exports were modified.

### Checks performed (referenced as V1-V12 above)

| # | Check | Result |
|---|---|---|
| V1 | `<scratch>/v06/verbatim.py` parsed every `# <file>:<a>-<b>` code block in this doc and compared each numbered line with the file: `diaphora.py`, `diaphora_config.py`, `diaphora_heuristics.py`, `db_support/schema.py`, `diaphora_ida.py` and `<miniconda3>/Lib/difflib.py`. | 57 blocks, 1,586 lines, **0 mismatches**, all ranges contiguous and equal to their headers. Appendix B (236 lines) is identical to `<scratch>/exp/spec_loop.py:11-246`. |
| V2 | Probes: `unified_diff` pairing (leading deletion, leading replace, trailing block, identical and empty inputs), `CPP_NAMES_RE`, IGNORECASE code-point scan, `splitlines`, `0.99 + 0.01`, `%.7f`/`%05lu`/`%08x`. | All as documented, except the two corrections below (leading-deletion discard; `jmp`). Extra IGNORECASE code points = `0x130, 0x131, 0x17f, 0x212a`. `0.99 + 0.01 == 1.0`. |
| V3 | Instrumented run on copies of `ls-old`→`ls` (`<scratch>/v06/instr.py`, mode `plain`), wrapping `cleanup_matches`, `get_total_matched_functions`, `find_one_match_diffing` and `find_functions_between`. | Outer totals 206→287→291→291 (3 iterations). `find_one_match_diffing` ran only with `iteration=1` (asm 716, pseudo 426). Cleanup executions per site: `3655`×3, `3217`×3, `3185`×8, `3471`×3, `3413`×3, `3340`×3, `3671`×3, `2945`×1, `1551`×2. All 865 gap calls got `str` ranges. Output identical to the oracle `run1` (278 rows, including `line`). |
| V4 | The same run with `find_related_constants` replaced by a copy that is verbatim except that it iterates the intersection in sorted, then reverse-sorted, `(type, str)` order (modes `sorted`/`rsorted`). | Both `results` and `unmatched` tables are identical to the oracle. |
| V5 | `EXPLAIN QUERY PLAN` of every in-scope statement, plus data audits on six real exports (`ls-old`, `ls`, `userenv-9168-pdb`, `userenv-9278-nopdb`, `sechost-9168-pdb`, `sechost-9444-nopdb`). | Plans are identical on all three pairs (Open question 1). Each export has 48 `sqlite_stat1` rows, 0 duplicate names and processor `pc64`. Address lengths are uniform (7 digits for `ls`, 10 for PE). Every address and CU bound is TEXT. No NULL `nodes`/`pseudocode_lines`/`constants_count`/`constants`/`name` and no zero `nodes`. NULL `pseudocode` counts are 106/113/1/1/1/5 in the order listed above. No function is in more than one CU. The largest CU address ranges hold 580/576/867/851 functions. |
| V6 | Set-order exposure count (Open question 2). | `ls` 1, `userenv` 0, `sechost` 8 same-name seed pairs with ≥ 2 zero-prefix shared string constants. |
| V7 | `float(md_index)` vs `cast(md_index as real)` on all six exports. | One mismatch per `userenv` export: `'3.050963036440351716676733804'` gives `…783p+1` (Python) vs `…782p+1` (SQLite). |
| V8 | Duplicate-name probe on scratch copies of `ls-old`/`ls` with two main rows renamed `dupname`. | `functions_exists` returns `[('main',302),('main',304)]` (`exists == True`) and `get_function_row` returns id 302, as §2.9/§2.10 state. |
| V9 | Oracle progress for the `*-nopdb` pairs (`oracle/diffs/*/run1/diaphora.log`) at 01:10. | Neither pair had an output file. Both were still in the first outer iteration's CU pass. userenv had logged 151 replays of at least 50,000 rows and sechost 51. |
| V10 | Unmatched-label swap on the oracle `ls-old_vs_ls` run1. | `primary` = 56 diff functions, `secondary` = 14 main functions. |
| V11 | Per-stage raw counts on synthetic variant `a` (`<scratch>/v06/stages.py`). | 244→247, 247→257, 257→304, then the LA cleanup took 304→265 and 28 adds gave 293. Iteration 1 ended at 293. This matches the §3 table. |
| V12 | The §8.3 `abs()` table (all 28 inputs), the §11.1 TEXT-comparison probe and `raise SystemExit()` exit status. | All `abs()` values and pass/fail results reproduced, and the TEXT probe output reproduced exactly. The `SystemExit()` exit status is 0. |

### Corrections made

1. **Summary item 2: the cleanup execution count was wrong.** It said "at least 8 executions per outer iteration". `:3185` runs once or twice per field, and the assembly field runs only with the same processor, so the count is 8-10 with the same processor and 7-8 without. `ls` measured 10, 8 and 8 (V3).
2. **§6.3: the header-flush consequence was too narrow.** It said the headers discard "pure-insertion (`+`-only) lines of the first hunk". In fact they discard *any* one-sided block, pure insertion **or pure deletion**, that precedes the first context line of the whole stream. When the first hunk starts with context, nothing is lost. Verified with a leading-deletion probe (V2).
3. **§6.3: wrong mnemonic example.** `jmp` was listed as a paired identifier, but it has 3 characters and is **not** extracted. The text now says `call`/`push`/`test` are extracted and `mov`/`jmp`/`lea` are not (V2).
4. **§1.1 table, `relaxed_ratio` row.** "Affects `check_ratio` only" was wrong. It is also read by `find_same_name` (`diaphora.py:2196-2198`), and no in-scope function reads it.
5. **§1.2 table, `call_on_match_hook` evidence.** It cited `:3008`, which is the internal hooks test. The call sites are `:3112` and `:3297`.
6. **§2.1: incomplete list of int-`1` ratio producers.** `find_same_name`'s best branch (`:2200`) was missing.
7. **§9 row-order note: overgeneralised claim.** "`cast(... as real)` equals a correctly rounded parse" holds for the integer address strings only. SQLite 3.51.1 mis-rounds a long fractional `md_index` string by one ulp (V7). A new §2.8 bullet documents the resulting two-path `md_index` conversion (raw TEXT → Python `float()` in `compare_function_rows` vs `cast(md_index as real)` in SQL rows) and its bounded effect.
8. **§12: self-contradictory statement.** "It does not touch `matched_primary`/`matched_secondary`" ignored the leading `cleanup_matches()`, which rebuilds them. Reworded. Also added that `equal_db()` never clears `do_continue` (`:3599-3601`).
9. **§13: argument for an empty `unreliable` list.** The reasoning was stated only for `val = 0.5`. It is now general: `:1928` catches every `r >= val` whenever `partial is not None`. The `partial=None` and `partial="unreliable"` call sites, all gated by `self.unreliable`, are listed with line numbers.
10. **§11.1: cross-reference.** A new Open question 4 was inserted (full-loop parity on the `*-nopdb` pairs, previously mentioned only in §0), so the lexicographic-gap reference "Open question 4" now reads "Open question 5". Crash parity, timeouts and non-default configurations are now 6, 7 and 8.

### Material added (omissions)

- §0: the `diaphora_ida.py` drift is CSS at line 3864 and later, so the cited `diaphora_ida.py` lines equal the tag.
- §1.1: `self.unreliable` also gates `HEUR_FLAG_UNRELIABLE` heuristics (`:1498`) and brute forcing (`:2318`). The default patch-diff script also requires `RUN_DEFAULT_SCRIPTS` (`diaphora_config.py:186`). `final_pass` calls no hook.
- §1.2: rows for `deep_ratio` (in range, specified in `03a-ratio.md`) and for `get_model_ratio`/`apply_machine_learning`, which are inert by default.
- §2.6: the thread count is forced to 1 outside IDA (`diaphora.py:489-491`), which is what makes the LIFO heuristic order sequential and deterministic.
- §2.7: timeout facts:
  - the clock is per call, and only the wall-clock branch applies in this scope;
  - `SystemExit()` exits with **status 0** and writes no output;
  - the `DIAPHORA_SQL_*` overrides raise `TypeError`.
- §2.12: `is_same_processor` starts `False` (`:436`) and is assigned before any ratio is computed; the reason is spelled out.
- §8.2: why `int` set order is seed-independent only in pure-`int` sets, and why only `str` order matters.
- §16: the swapped unmatched labels (cross-reference `01-driver.md` §10.3), re-verified (V10).
- Hard parts 6:
  - more crash paths: NULL `name`, NULL CU bounds, NULL `nodes1`/`nodes2` in `int()`, non-numeric `md_index`;
  - the exit behaviour: traceback, status 1, no output;
  - `FunctionTable` has no raw `assembly`/`pseudocode`/`pseudocode_primes`/`switches` columns, which §5/§6 and `deep_ratio` need.
- §3/§5: V3/V11 re-measurements attached to the empirical counts.
- Open questions: rewritten with resolution status. The new entry 4 (full-loop parity on the `*-nopdb` pairs) was extracted from §0; later entries are renumbered.

### Confirmed without change

Every other claim was confirmed against source or by re-run. That includes:
- the loop structure and termination (`<=` outer, `==` inner, `iteration <= 3`, at most two effective internal iterations, description always `(iteration #1)`);
- the shared `dones` key space;
- `add_match` / `has_best_match` / `has_better_match` / `cleanup_matches` semantics and call sites;
- all config values cited (`diaphora_config.py:46-52, 71, 90, 92, 116, 120, 124, 137, 141, 177, 183, 186, 194, 205`);
- `MIN_FUNCTIONS_TO_DISABLE_SLOW` being IDA-only (`diaphora_ida.py:3798-3799`, `:3714`);
- `get_callers_callees` having no call site;
- the SQL text of §8/§9/§11/§2.10/§2.12;
- the `itemize_for_chooser` off-by-one-names trap;
- the final-pass algorithm and ordering;
- the `save_results` order and `insert or ignore`;
- the §8.3 `abs()` table;
- the §11.1 TEXT-order probe;
- the §2.14 example rows (present in `<scratch>/exp/o_a_plain.diaphora`);
- the §8.1 JSON example (`[6394752, 6394760, "00"]` exists in `ls-old`) and its 361/28 `constants` counts.

### Still open after this pass

Open questions 1 (plan dependence), 2 (hash-seed order, now with a stronger negative result on `ls` and a measured exposure on sechost), 4 (full-loop parity on the two `*-nopdb` pairs, since the oracle has not finished), 5 (lexicographic gaps: unexercised, and impossible on the current corpus), 6/7 (crash and timeout policy: source facts documented, the decision is the orchestrator's) and 8 (non-default configurations).
