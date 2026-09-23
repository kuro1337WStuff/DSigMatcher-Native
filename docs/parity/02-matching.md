# 02: Match bookkeeping and heuristic SQL execution

Porting spec. The reference is Diaphora at `<diaphora-ref>`, commit `621ec26` (`git describe` gives `3.4.2-4-g621ec26`), run standalone as `python diaphora.py db1.sqlite db2.sqlite -o out.diaphora` with `<conda>/python.exe`: CPython 3.13.12, `sqlite3` module linked against SQLite 3.51.1, and `idaapi` not importable, so `IS_IDA = False`. Unless another file is named, every line number refers to `diaphora.py`. `config:N` means `diaphora_config.py:N`, `heur:N` means `diaphora_heuristics.py:N` and `threads.py:N` means `jkutils/threads.py:N`.

## Summary

- Diaphora's matcher is an **online, order-dependent state machine**, not a batch 1:1 assignment. Each candidate row is filtered against the *current* `matched_primary` and `matched_secondary` dicts, which are keyed by function **name**, and an accepted row changes those dicts immediately. `cleanup_matches` periodically prunes the per-category lists and rebuilds the dicts. Only `final_pass` resolves conflicts on the secondary side, using max ratio plus the "multimatch" category.
- **In standalone mode, matching runs one heuristic at a time.** Outside IDA, `cpu_count` is forced to 1 (L489-491), so `threads_apply` never has more than one heuristic thread alive. Under the default config, thread scheduling cannot change which match wins.
- **Within a category, heuristics run in REVERSE list order**, because `threads_apply` uses `targets.pop()` (threads.py:40). This was confirmed on a real run. With a forward order, the same input produces different descriptions in the output (Appendix A, probe 3).
- **How ties are broken:** at ratio 1.0 the **first** accepted row wins, because later rows fail `has_best_match`. At an equal ratio below 1.0 **both** items are kept and the dicts keep the **last** writer. `cleanup` keeps equal-ratio items that share a primary address (including across categories: a tie never favours the earlier category), never deduplicates by secondary address, and can *downgrade* `matched_secondary`.
- **The dict key is not always `functions.name`.** `find_equal_matches` keys its items and the dicts by `mangled_function` (L1435-1440). For every function whose `name` differs from its `mangled_function` (C++ names), a 1.0 "100% equal" match does **not** protect the demangled name, the output row shows the mangled name, and the same address pair can be matched twice (§2, §17; probe 9).
- **Which stages run depends on the data, not only on the config.** `apply_dirty_heuristics` picks one of three modes (§3 step 2). In stripped mode (S) and patch-diff mode (P) **none** of the SQL heuristic dispatch (§4, §11, §12), `search_small_differences` or the iteration loop runs. Two PDB-symbolised builds of the same DLL will very likely have more than 90% equal `mangled_function` values and run in mode P. This was observed on the real corpus: userenv-9168-pdb vs userenv-9278-pdb logged `Patch diffing detected`, while the pdb-vs-nopdb pairs and `ls` vs `ls-old` ran in mode N (`01-driver.md` §5.7, V12). Every "Runs by default?" answer below about heuristics means "in mode N (normal)".
- Row order therefore matters, and **SQLite defines it, not SQL**. UNION output is sorted by the whole row. `ORDER BY f.source_file = df.source_file` acts as a stable partition. Plain joins return rows in query-plan order. For parity, the safest path is to run the verbatim SQL through the same SQLite 3.51.1 library.
- Two non-deterministic inputs remain under the default config: wall-clock timeouts (300 s), and the `PYTHONHASHSEED`-dependent iteration order of a `set` in `find_related_constants` (L3389). On the real sechost pair the seed changed intermediate state, and the next cleanup erased the difference (probe 16). On sechost the related-CU pass runs at about half the 300 s per-call limit (probe 15). The row cap is 1,000,000 rows per `add_matches_internal` cursor. The NO_FPS path has no cap.
- Several things are dead code or misdocumented:
  - The `"unreliable"` chooser branch in `add_matches_internal` can never run.
  - The "Experimental" category holds zero heuristics and is only reached behind `if self.unreliable`.
  - `MIN_FUNCTIONS_TO_DISABLE_SLOW` applies only inside IDA.
  - The "Unmatched in primary" and "Unmatched in secondary" labels are swapped in the output.

---

## 0. How the claims were verified

- Each behavioural claim quotes the source with its `file:line`.
- Probes were run against a **copy** of Diaphora in the session scratchpad. `<diaphora-ref>` was never modified, and the probes ran with `PYTHONDONTWRITEBYTECODE=1`. Appendix A lists the probes and their verbatim results:
  1. Unit probes of `add_match`, `has_better_match` and `cleanup_matches` on a live `CBinDiff`.
  2. `threads_apply` ordering.
  3. A full standalone `diaphora.py` run on two synthetic exports built with Diaphora's own schema.
  4. The same run with a patched `targets.pop(0)`, in a second copy, to show that order matters.
  5. A tie scenario.
  6. `add_matches_internal` classification with a fake cursor.
  7. SQLite `ORDER BY` / `UNION` / `DISTINCT` ordering on 3.51.1.
  8. The environment-variable override typing bug.
  9. to 13. Added by the verification pass: `mangled_function` keys in `find_equal_matches`, the cleanup tie rules, the patch-diff hook `IndexError`, hash-seed order and SQLite `abs()`, and a re-check of SQLite ordering (Appendix A).
  14. to 16. Also added by the verification pass, on the **real** exports that now exist in `<corpus>/oracle/exports` (read-only, or copies): export facts, row counts and durations from the oracle logs, and hash-seed sensitivity. Appendix C holds the query plans.
- When this document was first written, no real IDA export existed (see `HANDOFF.md`, "Blockers"). The corpus now exists (ls, sechost and userenv builds, with and without PDB). The query-plan statements now cite Appendix C.

---

## 1. Effective default configuration (standalone)

| Setting | Effective value | Evidence |
|---|---|---|
| `unreliable` | `False` | config:46; `__init__` L400-402 |
| `relaxed_ratio` | `False` | config:47; L403-405 |
| `experimental` | `True`, but it **only** gates `apply_dirty_heuristics` (L3618-3621). The "Experimental" category has **zero** heuristics (Appendix B), and `find_experimental_matches()` is only called inside `if self.unreliable:` (L3638-3651). | config:48; L406-408 |
| `slow_heuristics` | `True` **whatever the function count**. `MIN_FUNCTIONS_TO_DISABLE_SLOW` (config:71) is read only by `diaphora_ida.py:3798-3800` (the default of the IDA options dialog) and never by `diaphora.py`. | config:49; L409-411 |
| `use_trained_model` / `classifier` | `False` / `None` | config:205; L3551-3555 |
| `ignore_all_names` | `False` (forced) | L3759-3760 |
| `ignore_sub_names` | `True` | config:50; L468 |
| `ignore_small_functions` | `False`, so `%POSTFIX%` becomes `""` | config:52; L474-476, L1471-1473, L1518 |
| `cpu_count` / threads | `1` | L484-491, L1444-1448 |
| `timeout` | `300` s | config:92; L451 |
| `sql_max_processed_rows` | `1000000` | config:90; L454-456 |
| `project_script` / `hooks` | `None`. The exception is patch-diff mode, which loads `scripts/patch_diff_vulns.py` (L2614-2619, config:186-189). | L421-422 |
| `is_same_processor` | Computed as "some row pair satisfies `main.program.processor = diff.program.processor`". A NULL processor on both sides gives `False`, because `NULL = NULL` is not true in SQL. It is `False` while `find_equal_matches` runs, which does not use it. | L436, L2950-2967, L3617 |

The environment-override trap, verbatim at L560-569:

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

`os.getenv` returns a `str`, so `isinstance(str, bool/int)` is False and the **raw string** is returned. Probe 8 confirmed that `DIAPHORA_SLOW_HEURISTICS=0` yields `'0'`, which is truthy. `DIAPHORA_SQL_MAX_PROCESSED_ROWS=10` yields `'10'`, and `continue_getting_sql_rows` then raises `TypeError: '<' not supported between instances of 'int' and 'str'`. **The oracle harness must not set any `DIAPHORA_*` variable** other than `DIAPHORA_LOG_PRINT` and `DIAPHORA_DEBUG`, which only affect logging (L194-223). `DIAPHORA_CPU_COUNT` is harmless in standalone mode because L490-491 overrides it (`tester/tester.py:218` sets it). `DIAPHORA_AUTO_DIFF`, `DIAPHORA_DB1`, `DIAPHORA_DB2` and `DIAPHORA_DIFF_OUT` only select another way to pass the file names (L3719-3730), and `DIAPHORA_PROFILE` only wraps `diff` in cProfile (L3763-3770).

Logging detail for the harness: without `DIAPHORA_LOG_PRINT`, `log()` goes to `LOGGER.info` (L201), a `StreamHandler` on **stderr** with format `"[Diaphora: %(asctime)s] %(levelname)s: %(message)s"` (L118-125), so the timestamps have millisecond resolution. With `DIAPHORA_LOG_PRINT` set, `log()` uses `print` to **stdout** with `time.asctime()` (L198-199), which has one-second resolution. For the per-heuristic timing checks in §5.4, leave `DIAPHORA_LOG_PRINT` unset and capture stderr.

---

## 2. State (the data model the port must hold)

L382-384, L431-432:

```python
    self.all_matches = {"best": [], "partial": [], "unreliable": []}
    self.matched_primary = {}
    self.matched_secondary = {}
```
```python
    self.ratios_cache = {}
    self.items_lock = Lock()
```

- **`all_matches`**: three **ordered lists**, iterated in the dict's insertion order: `best`, `partial`, `unreliable`. `cleanup_matches` rebuilds the dict in the same key order (L1562-1563, L1605). List order is semantically significant, because every later sort is stable.
- **Item layout** (the comment at L1567-1568): `[ea1, name1, ea2, name2, description, ratio, nodes1, nodes2]`, where:
  - `ea1` is always a **Python `str`** of the decimal address. `functions.address` is declared `text unique` (`db_support/schema.py`, `create table if not exists functions`), so SQLite returns TEXT, and `add_matches_internal` also applies `str()` (L1910).
  - `ea2` is the raw `df.address` value, also `str`.
  - `name1` and `name2` are `functions.name` values on every path **except `find_equal_matches`**. `functions.name` is the demangled short name, or the IDA name when demangling fails (`diaphora_ida.py:2451-2453`); `mangled_function` is the raw IDA name (`props[14] = true_name`, `diaphora_ida.py:3156` into the `mangled_function` column, L943-946). `find_equal_matches` instead uses `mangled_function` for **both** names and as the dict key (L1435-1440):
    ```python
          name = row["mangled_function"]
          ea = row["ea"]
          nodes = int(row["nodes"])

          item = [ea, name, ea, name, "100% equal", 1, nodes, nodes]
          self.add_match(name, name, 1.0, item, "best")
    ```
    When `name != mangled_function` (C++ symbols), this has these consequences, all confirmed by probe 9:
    - The "100% equal" output row shows the **mangled** name in both `name` and `name2`.
    - The 1.0 entry sits under the mangled key, so `has_best_match(name, name)` for the demangled name is False. `find_same_name` then matches the same address pair again under the demangled name, as a second best item with description `"Perfect match, same name"`. Cleanup keeps both (different `dones` keys, equal ratio). `final_pass` passes both to the best chooser, and `insert or ignore` drops the second at write time (§16).
    - `matched_primary` holds two keys for one function, so `len(matched_primary)` is not a count of matched functions (§13).
    - `find_unmatched` tests `row["name"]` (L2336-2338). If only the mangled key exists, a function present in the results is also listed as unmatched (probe 9, case B).
    - Name-keyed lookups (`get_function_row(item.vfname)`, L2998) find no row for these items, so they never seed the convergence-loop passes. That belongs to `05-passes.md`.
  - `ratio` is a Python `float`, the int `1` for NO_FPS, equal-matches and same-name best items, or the int `0`. `check_ratio` can return an int `0` in two ways: through `r = 0` at L1761, or when `v1` keeps its initial int `0` (L1699), every float component is `0.0` (so `set([v1, ...])` keeps the int, L1755-1757), and `deep_ratio` returns its initial int `score = 0` (L2766). `1 == 1.0` and `0 == 0.0` in every comparison and in `"%.7f"` formatting, so a port stores a double.
  - `nodes1` and `nodes2` are `int`.
- **`matched_primary[name1] = {"name": name2, "ratio": r}`** and **`matched_secondary[name2] = {"name": name1, "ratio": r}`**. The keys are names, not ids or addresses. Only membership, lookup and `len()` are ever used; the dicts are never iterated. Two different functions that share a `name` collapse into one entry. Whether names are unique inside an export is not determined from source: `name` stores the demangler's output (`diaphora_ida.py:2452`), and the schema puts no `unique` on it. On the real corpus they are unique (probe 14, Open question 2).
- **`ratios_cache`**: a memo of `check_ratio`, keyed by `f"{ea1}-{ea2}"` (L1653-1655), reset at the start of `diff` (L3572). The **first** computation for a key is returned to every later caller. It is a pure speed-up only if every caller would compute the same value for that key, and the callers build their inputs differently:
  - `check_match` passes `md_index` as SQLite's `cast(md_index as real)` (heur:57, L1805, L1828).
  - `compare_function_rows` (used by callee diffing and local affinity) passes the raw `md_index` **text** (L2498, L2521), which `check_ratio` converts with Python `float()` (L1672-1673).

  `md_index` is `str(Decimal)` with up to 28 significant digits (`diaphora_ida.py:2531-2537`). If SQLite's text-to-real conversion and Python's correctly rounded `float()` ever disagree on whether two different strings are equal, the two paths give different ratios, and the cache makes the first one win. Whether that happens on real exports is NOT DETERMINED FROM SOURCE. **Port rule:** keep a first-writer-wins cache with the same `"ea1-ea2"` key, and compute each caller's inputs the way that caller does.
- **`items_lock`**: a non-reentrant `threading.Lock`, held inside `add_match` and `cleanup_matches` only. With one thread it has no semantic effect.

---

## 3. Top-level call order under the default config

Verbatim, L3612-3677:

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

            #
            # Find using experimental methods modified functions.
            #
            # NOTES: While these are still called experimental, they aren't really
            # that experimental, as most of the code but the brute forcing using
            # compilation units has been tested since years ago.
            #
            log_refresh("Finding experimental matches")
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
```

The resulting sequence of **state mutations** (M) and **cleanups** (C) under the default config. Everything here runs on the main thread, except the SQL heuristics in step 5, which run on a single worker thread while the main thread waits:

1. **M** `find_equal_matches` (L1404-1442) calls `add_match(name, name, 1.0, item, "best")` for each INTERSECT row, with `name = row["mangled_function"]` (L1435), not `functions.name` (§2). It also sets `total_functions1` and `total_functions2`.
2. `apply_dirty_heuristics` (L2629-2637) decides `skip_others`:
   - **Stripped mode.** At least 99% of primary functions share an address (`percent >= 99.0`, L2562-2563). Then **M** `add_matches_from_query_ratio(sql, "best", "partial")` runs on the main thread (L2580).
   - **Patch-diff mode.** More than 90% share a `mangled_function` (`percent > 90.0`, L2609-2610). No matches are added, but hooks are loaded (L2614-2619).
3. **M** `find_same_name("partial")` (L2152-2210) runs in both branches.
4. If `skip_others` is set: **M** `find_remaining_functions` (L2702-2716). It only acts in patch-diff mode (`search_remaining_functions`, which calls `add_matches_internal` with `val=0.6`). The flow then jumps straight to step 8. **No cleanup happens before `final_pass`.** In this branch (modes S and P) **steps 5-7 never run**: no Best/Partial heuristic, no `search_small_differences` and no iteration loop. Mode P also has the `patch_diff_vulns` hooks loaded, so `on_match` runs inside every `check_match` of steps 3 and 4 (§6).
5. Otherwise: **M** `run_heuristics_for_category("Best")`, then **C**; **M** `run_heuristics_for_category("Partial")`, then **C**; then **M** `search_small_differences("partial")`. There is **no cleanup** after this last step before the loop's first `cleanup_matches`.
6. `apply_machine_learning()` does nothing (L3551-3555). The `unreliable` block is skipped.
7. The iteration loop (every step below runs on the main thread). The loop exits when the raw `len(best)+len(partial)` stops growing (L3672-3674):
   - **C**.
   - `find_matches_diffing`: **C**, then the assembly pass (same CPU only), which does **M** and a **C** per iteration of its own inner loop (L3185), then the pseudo-code pass, likewise (L3211-3229, L3150-3193).
   - `find_related_matches`: **C**, then **M** (slow heuristic, on by default; L3462-3494).
   - `find_related_compilation_unit`: **C**, then **M** (L3395-3460).
   - `find_locally_affine_functions`: **C**, then **M** (L3315-3360).
   - **C**.
8. `final_pass`: **C**, then the multimatch split and chooser fill (L2937-2948).
9. `find_unmatched` and `save_results`.

Note that **no cleanup runs between** `find_equal_matches`, `find_same_name` and the Best heuristics. The same-name items that `find_same_name` puts in `partial` therefore still carry a *fake* `1.0` in the dicts while the Best category runs (see §9 and §14).

---

## 4. Heuristic dispatch: `get_threads_count`, `run_heuristics_for_category`, `threads_apply`

### 4.1 `get_threads_count` (L1444-1448) and `cpu_count` (L483-491)

```python
    # Number of CPU threads/cores to use?
    cpus = cpu_count() - 1
    if cpus < 1:
      cpus = 1
    self.cpu_count = self.get_value_for("CPU_COUNT", cpus)

    # XXX: FIXME: Parallel diffing is broken outside of IDA due to parallelism problems
    if not IS_IDA:
      self.cpu_count = 1
```
```python
  def get_threads_count(self):
    """
    Return the maximum number of threads to run simultaneously
    """
    return max(self.cpu_count, 1)
```

**Port spec:** in standalone parity mode the thread count is `1`. Probe 1 printed `IS_IDA False cpu_count 1 threads 1` on a 32-thread machine.

**Runs by default?** Yes, and it returns 1.

### 4.2 `run_heuristics_for_category` (L1461-1552)

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

Things to notice:

- The "all matched" test runs **while the list is built**, before any heuristic has executed. No state changes during list building, so the test either stops everything at the first `heur` (so the category runs **nothing**) or never fires. Each worker also re-checks `all_functions_matched()` as it starts (§13).
- Flags are tested in the order UNRELIABLE, SLOW, SAME_CPU. `HEUR_FLAG_*` are the ints 1, 2 and 3 (heur:44-48), checked with list membership.
- The return value of `get_queries_postfix` is **discarded**, so that hook can never change the postfix. This is a latent bug and has no effect under the default config.
- The `%POSTFIX%` replacement is a plain substring replace.
- The same `best`/`partial` choosers serve every heuristic type except `RATIO_MAX_TRUSTED`, which hard-codes `"best"`/`"partial"` (L2013-2015).

**Runs by default?** Yes, for `"Best"` (L3630) and `"Partial"` (L2216), but only in mode N: both calls sit in the `else` of `if skip_others:` (L3626-3634). `"Unreliable"` and `"Experimental"` only run when `self.unreliable` is set (L3638-3651, L2317).

### 4.3 `threads_apply` (threads.py:27-71)

```python
def threads_apply(threads, targets, wait_time, log_refresh, timeout):
  """
  Run a number of @threads calling a function with arguments from @targets,
  waiting and checking the threads if they finished every @wait_time seconds,
  calling @log_refresh whenever it's required.
  """
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

    if times % 50 == 0:
      names = []
      for x in threads_list:
        names.append(x.name)
      tmp_names = ", ".join(names)
      log_refresh(f"[Parallel] {len(threads_list)} thread(s) still running: {tmp_names}")
```

Semantics:

- `targets.pop()` removes the **last** element. Heuristics therefore start in **reverse** order of `heuristic_functions`, which is itself in `HEURISTICS` order filtered by category and flags.
- With `threads == 1`, a new thread starts only when `len(threads_list) < 1`, meaning after the previous thread is found dead and deleted. **Execution is strictly serial.** The main thread stays inside this loop until every heuristic has finished, and only then calls `cleanup_matches`.
- `t.name` is set to the heuristic name through the `setattr` loop, because the item has key `"name"`. Diaphora's log prints `[Parallel] Heuristic '<name>' done` even in single-thread mode. **The oracle harness can parse those lines to recover the real execution order.** The `"[Single thread] Finding with heuristic"` lines are printed at list-build time, in *forward* order, and do not reflect execution order.
- The timeout flag `t.timeout` becomes True once `monotonic() - t.time > timeout`. The clock starts **at thread creation**, so it includes `cur.execute`, and `timeout = config.SQL_TIMEOUT_LIMIT` (300), **not** `self.timeout`. The flag is checked at most about once per `wait_time` (1 s, config:200).
- Each worker thread gets its **own SQLite connection**. `get_db` sees a new thread id, calls `open_db()` and then `attach_database(self.last_diff_db)` (L584-593). Thread ids may be reused after a thread exits, in which case the cached connection is reused, still with `diff` attached. Neither case affects results.
- An exception inside the target ends that thread. The traceback goes to the default `threading.excepthook`, and **the remaining heuristics still run**. Matches added before the exception are kept.

Probe 2 (Appendix A) printed `threads_apply(1) execution order: ['H3', 'H2', 'H1', 'H0']`. The full run (probe 3) printed "done" lines in exactly the reverse of the "Finding with heuristic" lines.

**Runs by default?** Yes in mode N, twice (Best and Partial), each time with `threads = 1`. Never in modes S and P.

### 4.4 Default execution order (reverse list order)

`#exec` is the start order; `idx` is the index in `HEURISTICS`; `L` is the `NAME = ...` line in `diaphora_heuristics.py`. The whole table was generated by importing `diaphora_heuristics` (Appendix B).

**Best**. There are 12 heuristics if the processors match. Otherwise only 5 run: #1, #2, #4, #5 and #8.

| #exec | idx | Heuristic | L | Type | min | Flags | Runs by default? |
|---|---|---|---|---|---|---|---|
| 1 | 11 | Microcode mnemonics small primes product | 299 | RATIO | - | - | yes |
| 2 | 10 | Equal assembly or pseudo-code | 272 | NO_FPS | - | - | yes |
| 3 | 9 | Same RVA | 250 | RATIO_MAX | 0.7 | SAME_CPU | if same processor |
| 4 | 8 | Same address, nodes, edges and mnemonics | 229 | RATIO | - | - | yes |
| 5 | 7 | Same cleaned pseudo-code | 212 | RATIO | - | - | yes |
| 6 | 6 | Same cleaned microcode | 195 | RATIO | - | SAME_CPU | if same processor |
| 7 | 5 | Same cleaned assembly | 178 | RATIO | - | SAME_CPU | if same processor |
| 8 | 4 | Same address and mnemonics | 159 | RATIO | - | - | yes |
| 9 | 3 | Bytes hash | 145 | NO_FPS | - | SAME_CPU | if same processor |
| 10 | 2 | Function Hash | 129 | NO_FPS | - | SAME_CPU | if same processor |
| 11 | 1 | Same order and hash | 109 | NO_FPS | - | SAME_CPU | if same processor |
| 12 | 0 | Same RVA and hash | 89 | NO_FPS | - | SAME_CPU | if same processor |

**Partial**. There are 27 heuristics if the processors match and 26 otherwise. The 3 heuristics flagged UNRELIABLE are always skipped. The last Partial step, `search_small_differences`, runs on the main thread after the category cleanup (L2218-2221).

| #exec | idx | Heuristic | L | Type | min | Flags | Runs by default? |
|---|---|---|---|---|---|---|---|
| 1 | 41 | Loop count | 981 | RATIO_MAX | 0.49 | SLOW | yes |
| 2 | 40 | Same rare basic block mnemonics list | 936 | RATIO_MAX | 0.5 | - | yes |
| 3 | 39 | Same rare assembly instruction | 888 | RATIO_MAX | 0.5 | SAME_CPU | if same processor |
| - | 38 | Partial pseudo-code fuzzy hash (mixed) | 872 | RATIO_MAX | 0.5 | SLOW, UNRELIABLE | **no** |
| - | 37 | Partial pseudo-code fuzzy hash (reverse) | 856 | RATIO_MAX | 0.5 | SLOW, UNRELIABLE | **no** |
| - | 36 | Partial pseudo-code fuzzy hash (normal) | 840 | RATIO_MAX | 0.5 | SLOW, UNRELIABLE | **no** |
| 4 | 35 | Pseudo-code fuzzy AST hash | 823 | RATIO_MAX | 0.35 | - | yes |
| 5 | 34 | Pseudo-code fuzzy (reverse) | 808 | RATIO | - | - | yes |
| 6 | 33 | Pseudo-code fuzzy (mixed) | 793 | RATIO | - | - | yes |
| 7 | 32 | Pseudo-code fuzzy (normal) | 777 | RATIO_MAX | 0.5 | - | yes |
| 8 | 31 | Switch structures | 760 | RATIO_MAX | 0.5 | - | yes |
| 9 | 30 | Same low complexity and names | 742 | RATIO_MAX | 0.5 | - | yes |
| 10 | 29 | Same low complexity, prototype and names | 723 | RATIO_MAX | 0.5 | - | yes |
| 11 | 28 | Same nodes, edges, loops and strongly connected components | 701 | RATIO_MAX | 0.549 | - | yes |
| 12 | 27 | Mnemonics small-primes-product | 682 | RATIO_MAX | 0.6 | - | yes |
| 13 | 26 | Similar pseudo-code and names | 662 | RATIO_MAX | 0.579 | - | yes |
| 14 | 25 | Pseudo-code fuzzy hash | 641 | RATIO | - | - | yes |
| 15 | 24 | Mnemonics and names | 623 | RATIO | - | - | yes |
| 16 | 23 | Import names hash | 605 | RATIO | - | - | yes |
| 17 | 22 | Same MD Index and constants | 587 | RATIO | - | - | yes |
| 18 | 21 | Same rare constant | 567 | RATIO_MAX | 0.2 | SLOW | yes |
| 19 | 20 | Same address and rare constant | 546 | RATIO_MAX | 0.5 | - | yes |
| 20 | 19 | Same rare MD Index | 512 | RATIO | - | - | yes |
| 21 | 18 | Same rare KOKA hash | 478 | RATIO_MAX | 0.45 | - | yes |
| 22 | 17 | Same constants | 459 | RATIO_MAX | 0.5 | - | yes |
| 23 | 16 | Same KOKA hash and MD-Index | 438 | RATIO | - | - | yes |
| 24 | 15 | Same KOKA hash and constants | 417 | RATIO | - | - | yes |
| 25 | 14 | Same compilation unit | 390 | RATIO | - | SLOW | yes |
| 26 | 13 | Same anonymous compilation unit function match | 353 | RATIO_MAX | 0.449 | - | yes |
| 27 | 12 | Same named compilation unit function match | 325 | RATIO_MAX_TRUSTED | 0.44 | - | yes |

**Unreliable** (8 heuristics, idx 42-49) does **not run by default**, because `find_unreliable_matches` sits behind `if self.unreliable:` (L3638). If it were enabled, its order would be 49, 48, ..., 42.

**Why the order matters, shown on a real run.** Probe 3 used two synthetic exports: 6 identical functions, `sub_` names on one side, same processor. Diaphora labelled every match `Equal assembly`, because heuristic idx 10 runs second. The same inputs with `targets.pop(0)` (forward order) labelled every match `Same order and hash` (idx 1). A port that runs heuristics in list order gets the categories and ratios right but the **descriptions wrong**. Where a row with ratio below 1.0 is involved, it can get the **pairs** wrong too.

### 4.5 Port spec (dispatch)

```text
run_category(cat):
  if |matched_primary| == total1 or |matched_secondary| == total2: log; goto CLEANUP   # whole category skipped
  list = []
  for h in HEURISTICS in declaration order:
     if h.category != cat: continue
     if UNRELIABLE in h.flags and !unreliable: continue
     if SLOW in h.flags and !slow: continue
     if SAME_CPU in h.flags and !same_processor: continue
     (best, partial) = (cat == "Unreliable") ? ("partial","unreliable") : ("best","partial")
     sql = h.sql.replace("%POSTFIX%", postfix)          # "" by default
     list.append(h, sql, best, partial)
  for h in reverse(list):                               # strictly serial; next starts after previous returns
     dispatch by h.ratio type (NO_FPS / RATIO / RATIO_MAX / RATIO_MAX_TRUSTED), see sections 11-12
     an exception inside a heuristic aborts only that heuristic; matches added so far stay
CLEANUP:
  cleanup_matches()
```

---

## 5. Fetching rows: `execute`, `fetchone`, `result_iter`, the row cap, timeouts and errors

### 5.1 How rows arrive

- Each heuristic does `cur.execute(sql)` and then pulls rows lazily: `fetchone()` in `add_matches_internal` (L1901) and `add_matches_from_query` (L2058), `fetchall()` in `find_same_name` (L2172), and `result_iter` in `search_small_differences` (L2110). **Rows are consumed in SQLite's output order, and each row's accept/reject decision depends on the state left by all earlier rows.**
- `result_iter` (L139-146):
  ```python
  def result_iter(cursor, arraysize=1000):
    """An iterator that uses fetchmany to keep memory usage down."""
    while True:
      results = cursor.fetchmany(arraysize)
      if not results:
        break
      for result in results:
        yield result
  ```
  It yields every row in order, in batches of 1000. It has no cap and no timeout. Porting it is simply "iterate every row".
  **Runs by default?** Yes in mode N, in `search_small_differences` (L2110), which runs because slow heuristics are on (L2218-2221). Its other users, `get_graph` (L1221, L1255), are only reached from the IDA graph viewer (`diaphora_ida.py:1769-1770`), not from `diff()`.
- The Python `sqlite3` connection settings are `db.text_factory = str` and `db.row_factory = sqlite3.Row` (L345-347). Values are converted by storage class: INTEGER to `int`, REAL to `float`, TEXT to `str`, NULL to `None`. `row["x"]` looks columns up by name, case-insensitively.
- While the outer cursor is open, `check_ratio` and `deep_ratio` run further `SELECT`s on the **same** connection (L2771-2778). SQLite allows this, and it has no effect on the outer row order, since nothing is written.

### 5.2 Row inputs (`get_query_fields`, heur:51-84)

Every SQL heuristic selects this exact column set. `{heur}` is `repr(name)`, a single-quoted SQL literal; none of the 50 names contains a quote (Appendix B):

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
  """
  Get the list of fields used in any and all SQL heuristics queries.
  """
  val = heur
  if quote:
    val = repr(val)
  ret = SELECT_FIELDS.format(heur=val)
  return ret
```

| Column | Type returned | Consumed by (in this document's scope) |
|---|---|---|
| `ea`, `ea2` | `str` (decimal; TEXT column) | item fields; `"0x%x" % int(ea)` (L1935); `check_ratio` cache key |
| `name1`, `name2` | `str` | every name-keyed check; nullsub test |
| `description` | `str`: the heuristic name, or the per-branch literal inside a UNION (for example `'Equal assembly'`) | item field 4 |
| `nodes1`, `nodes2` | `int` (`int(...)` is applied; NULL raises) | item fields 6 and 7 |
| `md1`, `md2` | `float`, or `None` if `md_index` is NULL. `float(None)` then raises in `check_ratio` (L1672-1673). | `check_ratio` |
| `pseudo*`, `asm*`, `pseudo_primes*`, `clean_*`, `bytes_hash*`, `kgh_hash*` | `str` or `None` | `check_ratio` and the `on_match` hook (ratio spec) |
| `mangled1` | `str` | `find_same_name` only (L2176) |
| others | `int` | copied into `main_d`/`diff_d` for hooks; not used by the default logic here |

`md1` and `md2` are **SQLite's** TEXT-to-REAL conversion of `md_index`, a decimal string. The ratio code only compares them for equality and against `> 0.0`. To be safe, a port should get these doubles from SQLite (`cast(... as real)`) or parse them with a routine that matches SQLite's `sqlite3AtoF`.

### 5.3 `continue_getting_sql_rows` (L1874-1880)

```python
  def continue_getting_sql_rows(self, i):
    """
    Determine if more rows should be read at the given stage
    """
    if self.sql_max_processed_rows != 0 and i < self.sql_max_processed_rows:
      return True
    return False
```

**Port spec:** `keep_going(i) = (maxRows != 0) && (i < maxRows)`.
- `maxRows == 0` means **zero rows are read**, not "unlimited". Probe 6 printed `maxrows=0 ... fetched 0`.
- With the default 1,000,000, at most **1,000,000 rows are fetched per `add_matches_internal` call**. That count includes rows that `check_match` rejects. Probe 6 printed `maxrows=3 ... fetched 3`.
- The cap applies per cursor: per heuristic, and in the per-pair or per-constant loops, per `add_matches_internal` call.
- `add_matches_from_query` (NO_FPS), `find_same_name` and `search_small_differences` **have no cap**.
- Because the cap truncates in SQLite row order, a heuristic that returns more than 1M rows can only be reproduced if the row order is reproduced too.

**Runs by default?** Yes, inside every `add_matches_internal` call.

### 5.4 Timeouts (wall-clock, not reproducible)

There are two independent clocks, both 300 s by default:

1. The per-thread flag set by `threads_apply` (threads.py:62-63). It measures from thread creation and uses `config.SQL_TIMEOUT_LIMIT`.
2. The per-call clock in `add_matches_internal` (L1892-1896). It measures from after `cur.execute` returns, which already includes the first `sqlite3_step`, and uses `self.timeout`:
   ```python
       cur_thread = threading.current_thread()
       t = time.monotonic()
       while self.continue_getting_sql_rows(i):
         if time.monotonic() - t > self.timeout or cur_thread.timeout:
           log(f"Timeout with heuristic '{cur_thread.name}'")
           raise SystemExit()
   ```
   `SystemExit` is caught **only** by the three `add_matches_from_query_ratio*` wrappers (L1965, L1990, L2016). Everywhere else it propagates:
   - From `add_matches_from_cursor_ratio_max`, `search_remaining_functions`, `find_related_constants` and `find_related_compilation_unit`, all on the main thread, it would end the whole process before `save_results`, with exit status 0 (§5.5). The main thread's `timeout` attribute is set to False at L3595-3596. On the real sechost pdb-vs-nopdb pair, single `find_related_compilation_unit` calls took about 135-150 s for up to 700,000 rows (probe 15), so this path has only about a 2x margin.
3. `add_matches_from_query` (NO_FPS) checks only the thread flag (`while not cur_thread.timeout:`, L2054). On timeout it **stops silently**, with no log line and no exception.

**Port spec:** do not implement wall-clock timeouts in parity mode. Instead, the oracle harness must reject any Diaphora run whose log contains `Timeout with heuristic`. A NO_FPS timeout leaves no trace in the log, so the harness should also check that no heuristic's "done" line arrives more than about 300 s after it started. No line marks a heuristic's start. With one thread, a heuristic starts right after the previous heuristic's "done" line, and the first one of a category starts after the last `Finding with heuristic` line of that category's list build (L1517), which is printed after `Finding best matches...` (L3629) or `Finding partial matches` (L3633).

### 5.5 Error semantics (deterministic, so they must be reproduced or excluded)

| Entry point | What happens on an exception while processing a row |
|---|---|
| `add_matches_from_query_ratio` / `_max` / `_max_trusted` (L1967-1973, L1992-1998, L2018-2024) | Logs, prints the SQL, **re-raises**. On a worker thread, the thread dies, **the rest of that heuristic's rows are skipped**, and later heuristics still run. On the main thread (stripped mode, L2580) the re-raise leaves `diff()` and the run aborts. |
| `add_matches_from_query` (L2080-2081) | `except: log(...)` **swallows** the error. The rest of that heuristic's rows are skipped. |
| main-thread callers (`find_same_name`, `search_small_differences`, `search_just_stripped_binaries`, `find_related_*`, `search_remaining_functions`) | The error propagates out of `diff()`, and **no output file** is written. |

Row values that trigger these errors include: NULL `nodes` (`int(None)`, L1915); NULL `md_index` (L1672); NULL `constants` in `deep_ratio` (`json.loads(None)`, L2812-2814); a NULL name (`None.startswith`, L1846); a NULL main `mangled_function` on a `find_same_name` row (`row["mangled1"].startswith`, L2176-2179); a NULL diff-side `names` on a `search_small_differences` row (`json.loads(None)`, L2120; the SQL only filters `f.names != '[]'`, L2105). A port can either treat these as "abort the rest of this heuristic" or assert that the exports contain no such NULLs. The second option is recommended, backed by a validation pass over the exports.

**How an aborted run looks to the harness.** An uncaught exception in `diff()` ends the process with exit status 1. A `SystemExit()` raised on the main thread (§5.4) ends it with exit status **0**, because `SystemExit` with no argument means success. In both cases `save_results` (L3773) never runs, so its `os.remove` of an old output file (L2379-2381) never runs either, and a **stale** `.diaphora` from an earlier run survives. The harness must delete the output file before each run, and treat a run as valid only if the file exists and the log contains `Diffing results saved in file` (L2426).

---

## 6. `check_match` (L1786-1872)

```python
  def check_match(self, row, ratio=None, debug=False):
    """
    Check a single SQL heuristic match and return whether it should be ignored
    or not, and also the similarity ratio for this match.
    """

    ea = row["ea"]
    ea2 = row["ea2"]
    name1 = row["name1"]
    name2 = row["name2"]
    desc = row["description"]

    main_d = {}
    main_d["ea"] = row["ea"]
    main_d["name"] = row["name1"]
    main_d["pseudo"] = row["pseudo1"]
    main_d["asm"] = row["asm1"]
    main_d["pseudocode_primes"] = row["pseudo_primes1"]
    main_d["nodes"] = row["nodes1"]
    main_d["md_index"] = row["md1"]
    main_d["clean_assembly"] = row["clean_assembly1"]
    main_d["clean_pseudo"] = row["clean_pseudo1"]
    main_d["clean_micro"] = row["clean_micro1"]
    main_d["bytes_hash"] = row["bytes_hash1"]
    main_d["edges"] = row["edges1"]
    main_d["indegree"] = row["indegree1"]
    main_d["outdegree"] = row["outdegree1"]
    main_d["instructions"] = row["instructions1"]
    main_d["cyclomatic_complexity"] = row["cc1"]
    main_d["strongly_connected"] = row["strongly_connected1"]
    main_d["loops"] = row["loops1"]
    main_d["constants_count"] = row["constants_count1"]
    main_d["size"] = row["size1"]
    main_d["kgh_hash"] = row["kgh_hash1"]

    diff_d = {}
    [... identical block for the *2 columns, L1821-1842 ...]

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
          if debug:
            msg = "0x%x 0x%x %d" % (int(ea), int(ea2), r)
            LOGGER.debug(msg)
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

(The `diff_d` block is the same as the `main_d` block with `2` in place of `1` in the column names. See L1821-1842.)

**Facts:**
- Every caller passes `ratio=None` (the calls at L1906, L2063, L2129 and L2183 are the only ones). The `ratio != 1.0` guard is therefore always true, and `r` always comes from `check_ratio`. If a caller ever passed `ratio=1.0`, `r` would be unbound (`UnboundLocalError`), but no caller does.
- The filter order is: nullsub prefix (on `name1` **or** `name2`, prefix `"nullsub_"`, case-sensitive); then `has_best_match`; then `check_ratio`; then `has_better_match` with the **computed** `r`; then the hook.
- `has_best_match` runs **before** the ratio is computed, so a pair whose partner already has a 1.0 match is dropped without ever being scored.
- The NO_FPS path also goes through this `has_better_match(…, r)` test with the real computed `r`, even though it later records the match as 1.0 (see §12).
- The `on_match` hook: with no hooks, `call_hook` returns the default `[should_add, r]` unchanged (L1450-1459). In patch-diff mode, `patch_diff_vulns.CVulnerabilityPatches.on_match` always returns `(True, ratio)` unchanged (`scripts/patch_diff_vulns.py:204-236`, with returns at L213 and L236). It has **no effect on matching**, but for `ratio < 1.0` it runs `find_vulns_using_assembly`, which **raises `IndexError`** at `patch_diff_vulns.py:162` when an added assembly diff line is empty or starts with a space (`added.split(" ")[0]` is then `""`), or when the added mnemonic starts with `b` and the removed line is empty or starts with a space. Probe 11 reproduced all three. In mode P the hook runs inside `check_match` on the main thread (in `find_same_name` and `search_remaining_functions`), so the exception aborts the diff with no output. Whether real exports contain such assembly lines is open (Open question 5).

**Port spec:**
```text
check_match(row) -> (bool accept, double r):
  if starts_with(row.name1,"nullsub_") or starts_with(row.name2,"nullsub_"): return (false, 0.0)
  if has_best_match(row.name1, row.name2): return (false, 0.0)
  r = check_ratio(row)                           # see ratio spec; memoised by "ea1-ea2"
  if has_better_match(row.name1, row.name2, r): return (false, 0.0)
  return (true, r)                               # hooks: identity under default config
```
**Inputs:** the `get_query_fields` columns (§5.2). **Outputs:** accept flag and ratio. It does not modify state (unless the ratio cache is counted).
**Runs by default?** Yes, for every SQL-heuristic row and in `find_same_name` and `search_small_differences`.

---

## 7. `has_best_match` (L1376-1384)

```python
  def has_best_match(self, name1, name2):
    """
    Check if we have a best match for the given two functions (not for the pair).
    """
    if name1 in self.matched_primary and self.matched_primary[name1]["ratio"] == 1.0:
      return True
    if name2 in self.matched_secondary and self.matched_secondary[name2]["ratio"] == 1.0:
      return True
    return False
```

**Port spec:** `mp.contains(n1) && mp[n1].ratio == 1.0 || ms.contains(n2) && ms[n2].ratio == 1.0`. The comparison is exact double equality. The stored ratio may be the **fake 1.0** from `add_match` for same-name pairs (§9). After a cleanup, it holds the item's real ratio instead (§14).
**Runs by default?** Yes, through `check_match`.

---

## 8. `has_better_match` (L1386-1402)

```python
  def has_better_match(self, name1, name2, ratio):
    """
    Check if there if we found a better match already for either @name1 or @name2.
    """

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

**Semantics. Read this carefully; it is not a ratio comparison when both names are real:**
- If **neither** name starts with `"sub_"` (case-sensitive; `j_sub_`, `nullsub_` and similar do *not* count as `sub_`), **and** `name1` is already in `matched_primary`, the function **returns immediately**. It returns True only if `name1`'s current partner has the same name as `name1`, that is, if name1 is held by a same-name match. It does **not** look at ratios or at `matched_secondary[name2]`. Consequence: a named function already matched to a *different* name at 0.9 **accepts** a new candidate at 0.5 (probe 1: `hbm(foo,baz,0.5) named short-circuit -> False`, after which `mp[foo]` became `baz, 0.5`).
- Otherwise the test is: `mp[name1].ratio > r` **or** `ms[name2].ratio > r`, with **strict** `>`. An **equal** ratio is **not** better, so the new match is accepted (probe 1: `hbm(sub_1,bar,0.9) equal ratio -> False`).
- `float(ratio)` is applied only after the name short-circuit.

**Port spec:**
```text
has_better_match(n1, n2, r):
  if !starts_with(n1,"sub_") && !starts_with(n2,"sub_"):
     if mp.contains(n1): return mp[n1].name == n1
  if mp.contains(n1) && mp[n1].ratio > r: return true
  if ms.contains(n2) && ms[n2].ratio > r: return true
  return false
```
**Runs by default?** Yes, in `check_match`, in `add_match` when the ratio is not 1.0, and in `search_small_differences` (L2124, with a names-overlap ratio).

---

## 9. `add_match` (L1340-1374)

```python
  def add_match(self, name1, name2, ratio, item, chooser):
    """
    Add a single match to the internal lists before really adding them to the
    choosers list.

    NOTE: Always call `add_match`, don't try to handle this manually at all ever!
    """
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
            old_ratio = self.matched_primary[name1]["ratio"]
            message = f"Found a better match for function {name1} -> {name2}, {old_ratio} with {ratio}"
            debug_refresh(message)

        if name2 in self.matched_secondary:
          if self.matched_secondary[name2]["ratio"] < ratio:
            old_ratio = self.matched_secondary[name2]["ratio"]
            message = f"Found a better match for function {name1} -> {name2}, {old_ratio} with {ratio}"
            debug_refresh(message)

      if chooser is not None:
        if item not in self.all_matches[chooser]:
          self.all_matches[chooser].append(item)

      self.matched_primary[name1] = {"name": name2, "ratio": ratio}
      self.matched_secondary[name2] = {"name": name1, "ratio": ratio}
```

**Semantics:**
1. **Same-name fake.** If `name1 == name2`, `ratio := 1.0`. This is only the value **stored in the dicts**. The item's own `item[5]` keeps the caller's ratio, and the caller has **already picked the chooser** (a same-name pair at 0.7 goes to `partial` with `item[5] = 0.7` and `mp[name].ratio = 1.0`). Probe 1 printed `same-name add: mp[foo]= {'name': 'foo', 'ratio': 1.0}`.
2. At ratio 1.0 (real or faked) there is **no** `has_better_match` test. The match **always** overwrites both dicts, even if the names were already matched elsewhere at 1.0. That is why 1.0 conflicts from paths that skip `check_match` (for example `find_equal_matches`, `find_one_match_diffing`, local affinity) create multimatches instead of being rejected.
3. Below 1.0, `has_better_match` is tested again. In single-thread mode it reaches the same answer `check_match` already reached, because the state has not changed. It still matters for callers that do not use `check_match`.
4. The debug lines have no effect.
5. **Duplicate test:** `item not in list` is a linear scan comparing all 8 fields for equality (`1 == 1.0`; `'10' != 10`, although eas are always `str` on every path from the DB). The same pair reached by two heuristics has a different `description`, so **both items are appended**. Cleanup later drops the second (§14).
6. The dicts are overwritten **unconditionally**, even when the item was a duplicate. Last writer wins.

**Port spec:**
```text
add_match(n1, n2, double r, const Item& item, Chooser* chooser):
  if n1 == n2: r = 1.0
  if r != 1.0 && has_better_match(n1, n2, r): return
  if chooser: if !contains_equal(all_matches[*chooser], item): all_matches[*chooser].push_back(item)
  mp[n1] = {n2, r}; ms[n2] = {n1, r}
```
For `contains_equal`, use a per-chooser hash set of the 8-field tuple, with ratios compared by numeric value. The set **must be rebuilt from the list after every `cleanup_matches`**, because cleanup removes items and a removed item can be appended again later.

**Inputs:** names and ratio from the caller; `item` built by the caller. **Outputs:** list append, and a write to both dicts.
**Runs by default?** Yes. Every match anywhere goes through here.

---

## 10. `add_matches_internal` (L1882-1948)

```python
  def add_matches_internal(
    self, cur, best, partial, val=None, unreliable=None, debug=False
  ):
    """
    Wrapper for various functions that find matches based on SQL queries. Always
    use this function when issuing SQL heuristics (if it's possible).
    """
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

**The `unreliable` branch (L1937-1946) can never run.** Proof: the `else` branch is reached only if `r != 1.0` and not (`r >= val` and `partial is not None`).
- If `partial is not None`, then `r < val`, so `r > val` is false and nothing is added.
- If `partial is None`: the only caller is `find_brute_force` (L2278-2280, L2299-2301), which passes `unreliable=None`, so nothing is added.

The literal chooser name `"unreliable"` (not the `unreliable` argument's value) never matters. Probe 6 confirmed this for every wrapper: nothing below `val` is ever added. The docstrings in heur:30-41 ("<0.5 results to the unreliable chooser", "'unreliable' results ... go to the 'partial' tab") describe **intended** behaviour that the code does not implement.

**Port spec:**
```text
add_matches_internal(cursor, best, partial /*nullable*/, optional<double> val):
  v = val.value_or(0.5)                     # DEFAULT_PARTIAL_RATIO, config:137
  i = 0
  while maxRows != 0 && i < maxRows:        # section 5.3
     [parity mode: no wall-clock timeout; see 5.4]
     ++i
     if !cursor.next(row): break
     (ok, r) = check_match(row)
     if !ok: continue
     item = { to_str(row.ea), row.name1, row.ea2, row.name2, row.description, r, int(row.nodes1), int(row.nodes2) }
     if r == 1.0:                    add_match(row.name1, row.name2, r, item, best)
     else if r >= v && partial:      add_match(row.name1, row.name2, r, item, partial)
     /* else: dropped */
```
- Everything is exact double arithmetic: `r == 1.0` is exact equality, and `r >= v` is inclusive.
- The return value (`matches`) is only returned by `add_matches_from_cursor_ratio_max`, and every caller ignores it. It is not needed.
- **Outputs:** by caller:

  | Caller | ratio 1.0 goes to | `r >= v` goes to | Otherwise |
  |---|---|---|---|
  | RATIO, Best/Partial category (`v = 0.5`) | `best` | `partial` | dropped |
  | RATIO_MAX, Best/Partial (`v = min`) | `best` | `partial`; min below 0.5 lets `[min, 0.5)` into partial (probe 6: `min=0.2 -> partial [0.6, 0.45, 0.3]`); min above 0.5 drops `[0.5, min)` | dropped |
  | RATIO_MAX_TRUSTED (`v = min`) | `best` (hard-coded) | `partial` (hard-coded) | dropped |
  | Unreliable category (not default) | `partial` | `unreliable` | dropped |
  | brute force (not default) | `unreliable` | (partial None) | dropped |
  | `search_remaining_functions` (patch-diff) | `best` | `partial` with `v = 0.6` (config:172) | dropped |
  | `find_related_constants`, `find_related_compilation_unit` | `best` | `partial`, `v = 0.5` | dropped |

**Runs by default?** Yes: every RATIO / RATIO_MAX / TRUSTED heuristic, plus `find_related_constants` (L3391), `find_related_compilation_unit` (L3458), stripped mode (L2580) and patch-diff mode (L2696).

---

## 11. The `add_matches_from_*` wrappers

### 11.1 `add_matches_from_query_ratio` (L1950-1975): HEUR_TYPE_RATIO

```python
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
**Spec:** if `all_functions_matched()`, return; otherwise execute, then `add_matches_internal(best, partial, val = none -> 0.5)`. **Runs by default?** Yes: RATIO heuristics in Best/Partial (see §4.4), and stripped mode (L2580, on the main thread).

### 11.2 `add_matches_from_query_ratio_max` (L1977-2000): HEUR_TYPE_RATIO_MAX

```python
  def add_matches_from_query_ratio_max(self, sql, best, partial, val):
    """
    Find matches using the query @sql with a ratio >= @val.
    """
    if self.all_functions_matched():
      return

    cur = self.db_cursor()
    try:
      cur.execute(sql)
      self.add_matches_internal(
        cur, best=best, partial=partial, val=val, unreliable="unreliable"
      )
    except SystemExit:
      pass
    except:
      [... identical error handling: log, print sql, traceback, raise ...]
    finally:
      cur.close()
```
**Spec:** the same as 11.1 with `val = heur["min"]`. `unreliable="unreliable"` has no effect (§10). **Runs by default?** Yes.

### 11.3 `add_matches_from_query_ratio_max_trusted` (L2002-2026): HEUR_TYPE_RATIO_MAX_TRUSTED

```python
  def add_matches_from_query_ratio_max_trusted(self, sql, val):
    """
    Find matches using the query @sql with a ratio >= @val and assign those with
    a bad ratio to the partial chooser, because they are reliable anyway.
    """
    if self.all_functions_matched():
      return

    cur = self.db_cursor()
    try:
      cur.execute(sql)
      self.add_matches_internal(
        cur, best="best", partial="partial", val=val, unreliable="partial"
      )
    except SystemExit:
      [... same as above ...]
```
**Spec:** the same as 11.2, but with the choosers hard-coded to `"best"`/`"partial"`, which ignores the category. In the Best/Partial categories this is **identical to RATIO_MAX**. The docstring's "assign those with a bad ratio to the partial chooser" is **not** implemented (§10). **Runs by default?** Yes, only for `Same named compilation unit function match` (idx 12, min 0.44). It is the **last** Partial heuristic to run.

### 11.4 `add_matches_from_cursor_ratio_max` (L2028-2037)

```python
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
It takes an already-executed cursor and does no exception handling (`SystemExit` would propagate). **Runs by default?** **No.** The only callers are in `find_brute_force` (L2278, L2299), which runs only if `self.slow_heuristics and self.unreliable` (L2318).

---

## 12. `add_matches_from_query` (L2039-2083): HEUR_TYPE_NO_FPS

```python
  def add_matches_from_query(self, sql, category):
    """
    Add all matches from this SQL query without performing any check.

    Warning: use this *only* if the ratio is known to be 1.00.
    """
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

**Semantics.** The docstring says "without performing any check", but that is **false**:
- Every row goes through the full `check_match`: nullsub, `has_best_match`, `check_ratio`, and then `has_better_match` with the **computed** ratio `r`.
- Only accepted rows are force-added with dict ratio `1.0` and `item[5] = 1` (int), into `category`. The Best category passes `"best"`; the Unreliable category would pass `"partial"`.
- There is **no row cap** and no per-call clock; only the thread flag stops the loop.
- Exceptions are **swallowed**.

**The consequence for ties:** once a row is accepted, both names hold ratio 1.0. Every later row involving either name then fails `has_best_match`. **At 1.0 the first accepted row wins.** Probe 5 shows this with a duplicate function in the secondary database: the NO_FPS heuristic "Equal assembly or pseudo-code" took the row that came first in SQLite's UNION output (`sub_9100`, ea2 text `'37120'` < `'38656'`), and the twin `sub_9700` ended unmatched, even though its raw join row came first.

**Port spec:**
```text
add_matches_from_query(sql, chooser):
  if all_functions_matched(): return
  for row in execute(sql):                 # no cap
     (ok, r) = check_match(row)
     if !ok: continue
     add_match(row.name1, row.name2, 1.0, {to_str(row.ea), row.name1, row.ea2, row.name2, row.description, 1, int(row.nodes1), int(row.nodes2)}, chooser)
```
**Runs by default?** Yes: idx 10 always runs; idx 0-3 run only with the same processor (§4.4).

---

## 13. `all_functions_matched` (L1777-1784)

```python
  def all_functions_matched(self):
    """
    Did we match already all the functions?
    """
    return (
      len(self.matched_primary) == self.total_functions1
      or len(self.matched_secondary) == self.total_functions2
    )
```

**Spec:** `mp.size() == total1 || ms.size() == total2`, using `==` and not `>=`. `total*` is `select count(*) from functions`, per database (L1411-1422).
- The dicts are keyed by **name**, so `len()` is a count of distinct keys, not of matched functions. It can be **too low**: functions that share a name collapse into one key. It can also be **too high**: `find_equal_matches` adds the `mangled_function` key and `find_same_name` can add the `name` key for the same function (§2). The test can therefore fire while functions are still unmatched (probe 9, case B: `len(matched_primary) == 3 == total_functions1` after `find_equal_matches` alone, so the stripped-mode heuristic returned at once and `find_same_name` skipped its row loop (L2174), and `Foo::Bar(int)` was listed as unmatched on both sides while its mangled row was in `best`). Because the test uses `==`, the size can also jump past the total and never fire.
- Between cleanups the dicts only grow. A cleanup rebuilds them from the surviving items, so the size can **shrink**.
- It is checked at **heuristic start** only (L1956, L1981, L2007, L2033, L2045), once in `find_same_name` (L2174), and in the list-build loop of `run_heuristics_for_category` (L1481-1484). It is **never** checked per row: a heuristic that is already running keeps processing rows after every function is matched.

**Runs by default?** Yes. Probe 3 shows it skipping the whole Partial category: `All functions matched in at least one database, finishing.`

---

## 14. `cleanup_matches` (L1554-1605): duplicate and conflict pruning

```python
  def cleanup_matches(self):
    """
    Check in all the matches for duplicates and bad matches and remove them.
    """
    with self.items_lock:
      dones = {}
      d = {}
      ea_ratios = {}
      for key, items in self.all_matches.items():
        d[key] = []

        l_items = sorted(items, key=lambda x: float(x[5]), reverse=True)
        for item in l_items:
          # An example item:
          # item = [ea1, name1, ea2, name2, "100% equal", 1, nodes1, nodes2]
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

**Exact semantics** (confirmed by probes 1 and 10; items 1, 3 and 4 were corrected by the verification pass):
1. **The category order is fixed:** `best`, then `partial`, then `unreliable`. `dones` and `ea_ratios` are **shared across the categories**. Cleanup never removes an item it has already kept, so a conflict between choosers can only drop the **later** item, and only in two cases: its name-pair string was already seen in an earlier category (whatever the ratios), or an item already kept for the same `ea1` has a **strictly** greater (possibly faked) ratio. **A tie keeps both items**, whichever category they are in (probe 10: best `X->A 1.0` and partial same-name `X->X 0.7`, faked to 1.0, both survive). A later item with a *higher* ratio also survives next to the earlier one. Under the default config every `best` item has ratio 1.0 and every `partial` item is below 1.0, so this last case does not occur there. `final_pass` settles the remaining conflicts (§16).
2. **The sort is stable and descending by `float(item[5])`.** Python's `sorted(..., reverse=True)` keeps the *original* relative order of equal keys. The C++ equivalent is `std::stable_sort` with `a.ratio > b.ratio`. Probe 1 printed `tie after cleanup partial= [('sub_A','sub_X',0.8), ('sub_A','sub_Y',0.8)]`, in insertion order.
3. **Deduplication is by the name pair string** `f"{name1}-{name2}"`. Only the first occurrence in (category order, sorted order) can survive, so its `description` and `item[5]` are kept. `dones[match]` is written **before** the `ea1` test (L1583 comes before L1587), so if that first occurrence is itself dropped by the `ea1` test, every later occurrence of the same name pair is dropped too, even one with a different `ea1` (probe 10: `(Y,B)` at `ea1='7'` lost to `(X,A) 0.9`, and `(Y,B)` at `ea1='8'` was then dropped as a duplicate). The key is a plain concatenation, so it **can collide** when names contain `-`. Probe 1: `("a-b","c")` and `("a","b-c")` both give `"a-b-c"`, and the second item was dropped. Reproduce this by building the same string key.
4. **A primary-address conflict removes only strictly worse items.** An item is dropped if a previously kept item (in any earlier category, or earlier in this one) with the same `ea1` **string** had a strictly greater (possibly faked) ratio. **Equal-ratio items for one `ea1` all survive** (unless a same-name item came before them, see below), and `final_pass` later turns them into multimatches. `ea_ratios[ea]` is overwritten by every surviving item and only rises (it is written only when `ratio >= ea_ratios[ea]`), so it equals the largest faked ratio kept so far for that `ea1`. The sort key is the *real* `item[5]`, but the comparison uses the *faked* ratio. A same-name item that sorts low (real 0.7) therefore survives as 1.0 and **blocks** every later item for that `ea1`, including items with the **same** real ratio that would otherwise tie and survive. Within one category the items after it already have a real ratio no higher than its own, so the effect there is limited to those equal-ratio items. Example (probe 10): partial `[(X->A 0.7), (X->X 0.7), (X->B 0.7)]`, inserted in that order, keeps `A` and `X` and drops `B`. Without the `X->X` item, `A` and `B` both survive. (An earlier version of this section gave `[(X->A 0.9), (X->X 0.7), (X->B 0.8)]` as the example. That is wrong: the stable descending sort puts `X->B 0.8` before `X->X 0.7`, and `X->A 0.9` drops it, same-name item or not.)
5. **The same-name fake 1.0 is used only for `dones` and `ea_ratios`,** so a same-name partial item survives next to a 1.0 best item for the same `ea1` (1.0 > 1.0 is false).
6. **Nothing is deduplicated on `ea2` or `name2`.** Several primaries matched to one secondary all survive cleanup (probe 1: `partial= [('sub_A','sub_C',0.9), ('sub_B','sub_C',0.7)]`).
7. **The dict rebuild** walks (category order, sorted order) and **the last writer wins**. The stored ratio is `item[5]`, **not** the fake 1.0. Consequences:
   - `matched_secondary` can be **downgraded** (probe 1: before cleanup `ms[sub_C] = sub_A 0.9`; after cleanup `ms[sub_C] = sub_B 0.7`).
   - A same-name partial pair **loses its fake 1.0** (probe 1: `after cleanup same-name: mp[foo]= {'name': 'foo', 'ratio': 0.7} has_best_match -> False`).
   - Across categories, a `partial` item for the same `name2` **overwrites** the `best` one (probe 1: `ms[sub_X]= {'name': 'sub_Q', 'ratio': 0.95}` although `sub_A -> sub_X` 1.0 is in best).

   These changes alter what later heuristics accept after the cleanup.
8. `all_matches` is **replaced by the sorted, pruned lists**. Later appends go after the sorted prefix, and that order feeds the next stable sort.

**Port spec:**
```text
cleanup():
  dones = hash_set<string>; ea_ratios = hash_map<string /*ea1 text*/, double>
  new_lists[3]
  for c in [best, partial, unreliable]:
    l = all_matches[c]; stable_sort(l, [](a,b){ return a.ratio > b.ratio; })
    for it in l:
      k = it.name1 + "-" + it.name2
      if dones.contains(k): continue
      r = (it.name1 == it.name2) ? 1.0 : it.ratio
      dones.insert(k)
      if ea_ratios.contains(it.ea1) && ea_ratios[it.ea1] > r: continue
      ea_ratios[it.ea1] = r
      new_lists[c].push_back(it)
  mp.clear(); ms.clear()
  for c in [best, partial, unreliable]: for it in new_lists[c]:
      mp[it.name1] = {it.name2, it.ratio}; ms[it.name2] = {it.name1, it.ratio}
  all_matches = new_lists; rebuild the per-chooser duplicate sets (section 9)
```
**Inputs:** `all_matches`. **Outputs:** pruned, sorted `all_matches`; rebuilt `matched_primary`/`matched_secondary`.
**Runs by default?** Yes, many times (§3).

---

## 15. Counters: `count_different_matches`, `get_total_matches_for`, `show_summary`, `get_total_matched_functions`, `get_sorted_results`

```python
  def count_different_matches(self, items):
    """
    Return the total number of different items using the first field.
    """
    dones = set()
    for item in items:
      dones.add(item[0])
    return len(dones)

  def get_total_matches_for(self, category):
    """
    Return the total number of matches found, so far, for the given category
    """
    return self.count_different_matches(self.all_matches[category])
```
(L1607-1620.) These count distinct `item[0]` (the `ea1` string). The **only** caller is `show_summary` (L1622-1635), which logs `Current results: Best b, Partial p, Unreliable u` and `Matched x% ...`. **They have no effect on matching.** The log lines are useful for the harness, as a per-stage checkpoint to diff against the port. `show_summary` divides by `total_functions1`, which raises ZeroDivisionError on an empty primary database.

`get_total_matched_functions` (L3142-3148) returns `len(best) + len(partial)`: **raw list lengths**, not distinct counts. It is the loop-termination measure at L3656/L3672 and in `find_matches_diffing_internal` (L3163/L3188). That makes it **behavioural**, so reproduce it exactly.

`get_sorted_results(category)` (L3133-3140) returns a stable descending sort by `float(x[5])`, without modifying the list.

**Runs by default?** Yes, all of them. Only the last two affect results.

---

## 16. Conflicts between choosers downstream: `final_pass` and `save_results`

`cleanup_matches` does **not** make the result 1:1. The final category of each pair is decided here (L2937-2948):

```python
  def final_pass(self):
    """
    Do the last pass:

    1. Remove duplicated or wrong matches.
    2. Find multimatches.
    3. Fill the choosers with the final cleaned up results.
    """
    self.cleanup_matches()

    max_main, max_diff, ignore_main, ignore_diff = self.find_multimatches()
    self.add_final_chooser_items(ignore_main, ignore_diff, max_main, max_diff)
```

`find_unresolved_multimatches` (L2839-2885):
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

    return max_main, multi_main, max_diff, multi_diff
```
`add_multimatches_to_chooser` (L2732-2747), called first for `multi_main` (with `ignore_main`) and then for `multi_diff` (with `ignore_diff`), **sharing one `dones` set** (L2903-2912):
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
```
`add_final_chooser_items` (L2916-2935):
```python
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

**Final-category rules** (these use the **raw** `item[5]`; the same-name fake plays no part here):
- These passes are keyed on **address strings** (`ea1`, `ea2`), unlike cleanup, which is keyed on names.
- `max_main[ea1]` is the running maximum over the items processed in (category order, stable descending) order. An item is appended to `multi_main[ea1]` only when `ratio >= max_main[ea1]` at that moment.
- `max_diff` and `multi_diff` are only updated for items that passed the `max_main` gate.
- **A multimatch** is any `multi_main[ea1]` or `multi_diff[ea2]` list with more than one entry. Every member not already in `dones` is emitted as a `multimatch` in `multi` iteration order, which is dict insertion order and therefore first-seen order. Its `ea1` (or `ea2`) goes into `ignore_main` (or `ignore_diff`). Only members that were actually added mark the address as ignored (L2742-2745).
- **Any other item** is emitted in its **own list's category** (best, partial or unreliable), and only if it is not ignored and its ratio is at least the maximum for **both** `ea1` and `ea2`. Items that lose on either side disappear silently.
- `itemize_for_chooser` (L2718-2730) names its variables misleadingly but passes the fields positionally into `CChooser.Item(ea, name, ea2, name2, desc, ratio, nodes1, nodes2)` (L237). The mapping is correct: `desc = item[4]`, `ratio = item[5]`, `nodes = item[6]`/`item[7]`.
- `save_results` (L2374-2429) writes `best`, then `partial`, then `unreliable`, then `multimatch` with `insert or ignore` against `unique index uq_results on results(address, address2)`. The **first** category written wins for a duplicate `(address, address2)`.
- Addresses are written as `"%08x" % int(ea)`, the ratio as `"%.7f"` (config:120, L282-290), and `line` is the running `"%05lu" % n` index within each chooser. `line` depends on list order.
- `add_item` increments `self.n` for **every** item (L296), including one that `insert or ignore` later drops. The written `line` values can therefore have **gaps**. Probe 9 (case A): the best chooser held `00000` ("100% equal", mangled names) and `00001` ("Perfect match, same name", demangled names) for the same address pair, and only `00000` was written. The final log line `Final results: Best N, ...` (L3684-3692) counts chooser items, not written rows, so it printed `Best 2` for one written row.
- The `name`/`name2` columns hold `item[1]`/`item[3]`, which for "100% equal" rows are `mangled_function` values (§2).

**The unmatched labels are swapped** (L2323-2356): the functions from the **main** database are stored in `self.unmatched_second` and written with `type = 'secondary'`, and the diff database's functions are written with `type = 'primary'`. Probe 5 confirmed that `('primary', '00000', '00009700', 'sub_9700')` is a diff-database function, and probe 9 confirmed it again. The parity comparator must reproduce or normalise this.

`find_unmatched` runs after `final_pass` and tests `row["name"] not in self.matched_primary` / `matched_secondary` (L2338, L2351), using the dicts that `final_pass`'s cleanup rebuilt. Two consequences:
- A function none of whose items was written (each was either below `max_main`/`max_diff`, or skipped through `ignore_main`/`ignore_diff` without being a multimatch member itself) is still a dict key after cleanup, so it appears **neither** in `results` **nor** in `unmatched`.
- A function matched only under its `mangled_function` key appears in **both** `results` (with the mangled name) and `unmatched` (with its `name`) (§2, probe 9 case B).

**Runs by default?** Yes, once, at the end.

---

## 17. Other callers of the bookkeeping API that run by default (bookkeeping aspects only)

The ratio, SQL and candidate-generation details of these callers belong to other parity documents. What follows is only what the bookkeeping needs.

- **`find_equal_matches`** (L1404-1442): `select ... from (select id, address, mangled_function, nodes, edges, size, bytes_hash from functions intersect select ... from diff.functions) x`. Each row gives `name = row["mangled_function"]` (L1435), `item = [ea, name, ea, name, "100% equal", 1, nodes, nodes]` and `add_match(name, name, 1.0, item, "best")`. The key and both item names are therefore `mangled_function`, not `functions.name` (§2). `id` is part of the intersected tuple, so identical functions with different `id`s are not "100% equal". There is no `check_match`. SQLite emits INTERSECT output in the order of its temp b-tree, sorted by the whole row with `id` (INTEGER) first. Probe 7 confirmed this with the plan `INTERSECT USING TEMP B-TREE`. It is the first writer.
- **`find_same_name(choose="partial")`** (L2152-2210). Its SQL is `select distinct ... where (df.mangled_function = f.mangled_function or df.name = f.name) and f.name not like 'nullsub_%'`, with `fetchall`. In SQLite `LIKE`, `_` matches any single character and ASCII letters match case-insensitively, so this drops every main name that starts with `nullsub` plus any character, in any case. The diff-side name is not filtered in SQL. `check_match` then applies the case-sensitive `"nullsub_"` prefix test to both names. The row loop is skipped entirely if `all_functions_matched()` is already true (L2174). For each row:
  - The row is skipped if `ignore_sub_names` is set and `mangled1.startswith("sub_")`.
  - Then `check_match` runs.
  - If `float(ratio) == 1.0`: best, with `item[5] = 1`.
  - Otherwise: partial, with `ratio += 0.01` when `ratio + 0.01 < 1.0` (config:116). There is **no minimum ratio**, so any accepted row, even at a ratio of 0.01, lands in `partial`.
  - Finally `add_match(name1, name2, ratio, item, chooser)`. When the names are equal, the fake 1.0 is stored in the dicts (§9).
  - It runs **before** the Best heuristics and with **no cleanup in between**. Same-name pairs therefore block both names (via `has_best_match` on the fake 1.0) throughout the Best category, until its closing cleanup reverts them to their real ratios.
- **`search_small_differences("partial")`** (L2085-2150). It runs because slow heuristics are on (L2218-2221), on the main thread, **after** the Partial cleanup. The steps are:
  1. `ratio` = |names1 ∩ names2| / max(|names1|, |names2|) over the JSON `names` lists.
  2. It pre-filters with `has_better_match(name1, name2, ratio)` on this names ratio.
  3. If the names ratio is at least 0.5, it calls `check_match`. The item takes `check_match`'s `r`, and the chooser is `"best"` if `r == 1.0`, otherwise `"partial"`. The final `r` has **no minimum**.
  4. It iterates with `result_iter`, with no cap and no timeout.
  5. It never calls `all_functions_matched()`. Its SQL (L2093-2106) has no `ORDER BY`, so rows come in join order (§18.3).
  6. Because the final `r` has no minimum, it can append `partial` items with a ratio of `0` (§2).
- **Stripped mode and patch-diff mode**: see §3 step 2. `get_unmatched_functions` (L2639-2669) uses `UNION`, so its lists come out in (db_name, name, address) text order (§18.3). `search_remaining_functions` then loops main-unmatched `sub_*` × all diff-unmatched and calls `add_matches_internal` once per pair (L2689-2698). The row cap applies to each of those calls, and each returns at most one row. The two lists are computed once, before the loop (L2707), so a function matched during the loop stays in them; `check_match` then filters it through the dicts. Because `values["small"]` is `False`, the SQL gets `" and f.nodes >= 3 and df.nodes >= 3 "` appended (L2684-2685). The description is a bound parameter (`get_query_fields("?", quote=False)`, L2677, bound at L2695).

---

## 18. Determinism analysis

### 18.1 Can thread scheduling change which match wins under the default config? **No.**

The evidence chain:
1. `IS_IDA` is False (`import idaapi` fails, L82-87), so `self.cpu_count = 1` (L489-491) and `get_threads_count()` returns 1 (L1448). No environment variable can change this, because L490-491 runs after `get_value_for("CPU_COUNT", ...)`.
2. `threads_apply(threads=1, ...)` starts a thread only when `threads_list` is empty (threads.py:39), and removes it only once `not t.is_alive()` (threads.py:56-60). No two heuristic bodies ever overlap.
3. The main thread does not touch the match state while it waits in `threads_apply`. It only runs `is_alive`, `join` and the timeout flag. It calls `cleanup_matches` only after the loop has drained (L1543-1551).
4. Every other matching routine (§3 steps 1-4 and 6-9, and `search_small_differences`) runs on the main thread.
5. Each worker has its own SQLite connection to the same unchanged files, with `diff` attached (L584-593), so its row order matches what the main connection would produce.

Probes 2 and 3 confirmed this: execution was strictly serial and in reverse order.

### 18.2 What *can* change the result between two default runs on the same inputs

| Source | Where | Effect | Mitigation |
|---|---|---|---|
| Wall-clock timeouts | threads.py:62-63; L1894-1896; L2054 | A heuristic that runs past 300 s is cut off at a row that depends on the machine and its load | Reject oracle runs that log `Timeout with heuristic`. Record per-heuristic durations (§5.4). |
| `PYTHONHASHSEED` | `find_related_constants`, L3370-3391: `for constant in inter_consts:` iterates a `set` built from `json.loads(constants)`. The set mixes `int` with **`str`** constants (exporter `diaphora_ida.py:2467-2484`), and the order of `str` hashes changes per process. Its SQL also only keeps constants where `abs(mc.constant) == 0` (L3387). `constants.constant` is `text not null`, and SQLite's `abs()` of a text value is the absolute value of its leading numeric prefix (leading spaces allowed; probe 12 gave `abs('  42x') = 42.0`), or `0.0` if there is none. So the filter keeps exactly the strings with no leading number (probe 12: `'abcde'`, `'0x1234'` and `'GetProcAddress'` pass; `'123abc'`, `'1e3zz'` and the int constant `'4096'` do not). The exporter's int constants are all `>= 0x1000` (`constant_filter`, `diaphora_ida.py:2418`), and only strings longer than 4 characters reach the `constants` table (L990-991). The only constants that produce rows are therefore the `str` elements, which are exactly the ones whose set order depends on the seed (probe 12 printed three different orders for seeds 0, 1 and 2). Scope: mode N only, inside the iteration loop, and only for matches with ratio `>= 0.8` whose rows both have `constants_count > 0` (L3484-3494). Observed on the real sechost pair (probe 16): the seed changed the iteration-0 state, and the next cleanup erased the difference. | Changes the order of `add_matches_internal` calls, and with it the tie outcomes: first wins at 1.0, and the dicts keep the last writer | Run the oracle with a fixed `PYTHONHASHSEED`, and also with 2-3 different seeds, to measure sensitivity. The port cannot reproduce CPython set order in general. See Open questions. |
| SQLite version, compile options or statistics | every `cur.execute` | Different query plans give different row orders, and so different ties, cap truncation and descriptions | Use the same SQLite (3.51.1, the conda `Library/bin/sqlite3.dll`) and the same export files, `sqlite_stat1` included. The exporter runs `create_indices()` + `analyze` (`diaphora_ida.py:1280-1281`, `:1322`; `create_indices` itself also ends with `analyze`, L634-649). |
| Environment variables | L560-569 | Can silently flip options, or crash (§1) | Clean environment |
| Exceptions on NULL data | §5.5 | Deterministic, but hard to mirror | Validate the exports |
| `ratios_cache` first writer | L1653-1655, §2 | Deterministic in one thread. The order of callers decides which input conversion (SQLite `cast` or Python `float()`) fixes a pair's ratio | Keep the cache and its key in the port |
| Patch-diff hook `IndexError` | `patch_diff_vulns.py:162`, §6 | Deterministic. Aborts a mode-P run with no output | Harness check from §5.5 |

None of the other `set`s in the matching path are iterated in an order-sensitive way: `check_ratio`'s `values_set` only takes a max (L1755-1764); `search_small_differences` and `deep_ratio` only take intersection sizes (L2119-2122, L2813-2815); every `dones` set is only tested for membership. Every `dict` involved iterates in insertion order (CPython 3.7+), which is deterministic.

### 18.3 SQLite row order (the port must reproduce it)

Probe 7 established these facts empirically for SQLite 3.51.1. They are implementation behaviour, not SQL guarantees:
- **`ORDER BY <expr>` is stable.** Rows with equal keys keep the order of the underlying scan or join. This held for 10 to 200,000 rows and payloads of 10 B to 5 KB, including spills larger than 40 MB. `ORDER BY f.source_file = df.source_file` (used by 32 of the 50 heuristics, Appendix B) is therefore a **stable partition**: first rows where the comparison is NULL (either `source_file` NULL), then false (0), then true (1), each group in join order. Rows with **equal source files come last**. Because 1.0 ties go to the first row, a same-source-file pair is the **least** favoured among exact ties. For equal non-1.0 ratios, the dicts keep the last writer, but both items survive cleanup anyway (§14).
- **`UNION` output is sorted by the whole result row** (BINARY collation, left to right: `ea` text, `name1`, `ea2` text, ...). The plan reads `UNION USING TEMP B-TREE`. This is how `'Equal assembly'` beats `'Equal pseudo-code'` for the same pair, and why `ea2 = '37120'` came before `'38656'` in probe 5. Note that the comparison is **textual**: `'10' < '9'`. Among the 50 heuristics only idx 10 has a top-level `UNION` (heur:277-295). Idx 18 and 19 use `UNION` inside a CTE (heur:484-496, heur:518-530), where it only builds a lookup set and does not directly order the output. `get_unmatched_functions` (L2647-2650, patch-diff mode) is also a top-level `UNION`.
- **`DISTINCT` kept first-occurrence scan order** in the probe. That depends on the plan: SQLite may implement DISTINCT through an index scan that reorders rows. On the real exports, every default query with a top-level `DISTINCT` (the 14 default heuristics in Appendix B plus `find_same_name`) got `USE TEMP B-TREE FOR DISTINCT` on all four pairs (Appendix C). That form only filters out rows it has already seen, so rows keep the join order and the first occurrence survives.
- **Plain multi-table joins** return rows in the nested-loop order the planner chose. That order depends on the indices and the `sqlite_stat1` statistics in the export files. It is not determined from source, so it was captured with `EXPLAIN QUERY PLAN` on the real exports (Appendix C). On four real pairs, **31 of 43** default queries got a different plan on at least one pair, and **24 of 43** changed their outer (driving) table between pairs. Example: `Same RVA and hash` drives from `df` on userenv-pdb vs userenv-nopdb and from `f` on the other three pairs. **A port cannot hard-code one join order per heuristic.** It has to reproduce SQLite's plan choice per input pair, and the simplest way to do that is to run the verbatim SQL through SQLite 3.51.1 on the same files.

### 18.4 IDA mode (for reference, not the parity target)

Inside IDA, `cpu_count = multiprocessing.cpu_count() - 1`, so up to N heuristics run at once. `check_match` reads `matched_*` without the lock (only `add_match` and `cleanup_matches` take it), and `all_matches` receives appends in interleaved order. Scheduling then decides which 1.0 tie wins, which writer the dicts keep, and the list order that later stable sorts depend on. The comment at L1574 ("might happen due to parallelism") admits this. **Diaphora running inside IDA with more than one CPU is not deterministic.** Do not use it as an oracle.

---

## 19. Normative ordering and tie-breaking rules for the native port

A deterministic port that matches standalone Diaphora must reproduce all of the following. Each rule is the result of the source excerpts above.

1. **The global stage order** is the one in §3, including where each cleanup happens (and does not happen).
2. **Heuristic order:** filter `HEURISTICS` by category and flags in declaration order, then execute in **reverse**, strictly serially (§4).
3. **Row order within a heuristic** is SQLite's output order for the verbatim SQL on the same files (§18.3). The simplest faithful approach is to execute the verbatim SQL (after the `%POSTFIX%` replace) through the same SQLite library and stream the rows. Hash joins are acceptable **only** if they reproduce this order exactly, including UNION sorting, the ORDER BY stable partition, DISTINCT first-occurrence and the plan's nested-loop order.
4. **Rows are processed online.** Each row's `check_match` sees the state produced by every earlier row of every earlier stage. There must be no batch "collect then resolve" step.
5. **Filters, in order, for SQL-heuristic rows:** nullsub prefix; `has_best_match`; `check_ratio`; `has_better_match(r)`; the chooser by `r == 1.0` / `r >= val`; `add_match` (the same-name fake, then `has_better_match` again unless 1.0, then the duplicate-item test, append, and overwrite both dicts).
6. **Tie outcomes that follow from rules 4 and 5:**
   - At ratio 1.0 the first accepted row wins. Later rows touching either name are rejected by `has_best_match`. This protects the **dict key**, which for "100% equal" items is `mangled_function`, not `functions.name`, so it does not protect the demangled name of a C++ function (§2).
   - At equal ratios below 1.0, later rows are **accepted**: `>` is strict, both items are appended, and the dicts keep the last writer.
   - With both names real (not `sub_`) and `name1` already matched to a different name, a new row is accepted **whatever its ratio**, provided neither name holds 1.0 in the dicts (`has_best_match` runs first) and `name1`'s current partner is not a same-name match.
   - A same-name pair stores ratio 1.0 in the dicts until the next cleanup.
   - Paths that do not use `check_match` (`find_equal_matches`, callee diffing, local affinity) add 1.0 matches without asking `has_best_match`, so they overwrite existing 1.0 dict entries (§9).
7. **Row cap:** 1,000,000 fetched rows per `add_matches_internal` call, counting rejected rows; none for NO_FPS, `find_same_name` or `search_small_differences`.
8. **Cleanup:** categories best → partial → unreliable; stable descending sort by `float(ratio)`; dedupe by the `name1 + "-" + name2` string (first wins); drop only items whose `ea1` string already has a strictly greater (same-name-faked) ratio; rebuild the dicts in iteration order, last writer wins, with the **real** `item[5]`; replace the lists with the pruned sorted lists.
9. **The final pass** follows §16 exactly. It is address-keyed, uses raw ratios, and applies the multimatch rules and the `insert or ignore` order.
10. **Numerics:** ratios are IEEE-754 **double**, with exact `==`, `>`, `>=` and `<` comparisons as written. The port must compute them in the same operation order as Python, with no FMA contraction (`/fp:precise` with no `/fp:contract` on MSVC, `-ffp-contract=off` on GCC and Clang). The 7-decimal rounding in `check_ratio` has to match Python's `"{0:.7f}".format`, which is correctly rounded. Those details belong to the ratio spec, but tie detection here depends on bit-exact doubles.
11. **Keys per path:** every dict key and cleanup name is `functions.name`, except `find_equal_matches`, which uses `mangled_function` (§2). `ea1`/`ea2` are the decimal address **strings** from the TEXT column.
12. **Ratio memo:** `check_ratio` results are memoised per `"ea1-ea2"` for the whole diff, and the first caller's value wins (§2).
13. **Mode:** decide mode S / P / N exactly as §3 step 2 does, because modes S and P skip steps 5-7 entirely.

---

## 20. Differences from the current native implementation (`src/MatchStore.cpp`, `include/dsigmatcher/Types.h`)

| Current native | What Diaphora actually does | Required change |
|---|---|---|
| Collect all candidates, then `ResolveSerial`: a stable sort by (ratio desc, HeuristicId asc, Index1, Index2) and greedy **1:1** by index | Online filtering in row order (§19.4-6); cleanup is **not** 1:1 (it keeps equal-ratio primaries and every secondary conflict); 1:1 is only approximated in `final_pass`, with multimatches split out | Replace `Resolve` with the §9-§16 state machine for parity mode |
| Heuristics in list order, deduplicated by HeuristicId | **Reverse** list order (§4) | Reverse the dispatch |
| Keyed by row index (`Index1`/`Index2`) | Keyed by **name** in the dicts and cleanup (`mangled_function` for "100% equal" items, `functions.name` elsewhere, §2), and by **address text** in the final pass | Keep the path-specific name and the address strings in `Item` |
| `float Ratio` (Types.h:48) | Python `float` = double | Use `double` |
| Category chosen per heuristic | Category chosen per row from `r` and the heuristic type (§10); multimatch at the end | Carry the chooser per item |
| No row cap | 1M rows per `add_matches_internal` call | Implement the cap for parity |

---

## Hard parts

1. **Reproducing SQLite row order** is the crux, because first-row-wins at 1.0, the dict writer, list order, the row cap and the `description` attribution all depend on it. Plans on real exports depend on the `sqlite_stat1` contents. Recommendation: in parity mode, run the verbatim heuristic SQL through the same conda SQLite 3.51.1 (the header in `miniconda3/Library/include/sqlite3.h` and Python's `sqlite3.sqlite_version` are both `3.51.1`), and keep the native hash joins as a "fast mode" validated against it. If only hash joins are used, every heuristic needs a proven emulation of its plan's order.
2. **The online state machine with name-keyed dicts** and its surprising rules: the `has_better_match` short-circuit for real names, the same-name fake 1.0 that cleanup reverts, cleanup downgrading `matched_secondary`, and the absence of any secondary-side dedup before `final_pass`. A batch or greedy design cannot reproduce these.
3. **Reverse execution order** is invisible in the "Finding with heuristic" log lines. Only the "done" lines show it.
4. **Hash-seed-dependent iteration** in `find_related_constants` (L3389) is iteration over a randomised Python set and cannot be matched by a native port. The oracle side must pin it, or the comparison must tolerate it.
5. **Wall-clock timeouts and silent NO_FPS truncation.** The oracle runs must be checked for them.
6. **Exception semantics** (abort the rest of the heuristic) on NULL data or odd values, differing between wrappers (§5.5).
7. **The O(n²) item-membership test** (`item not in list`). The port needs a hashed equivalent that stays exactly consistent with list pruning.
8. **Dead or misleading code paths.** Implementing the docstrings would *break* parity: the "unreliable" branch, TRUSTED's "partial" fallback, the "no checks" claim of NO_FPS, the `get_queries_postfix` hook, the Experimental category, `MIN_FUNCTIONS_TO_DISABLE_SLOW`.
9. **Output quirks:** the swapped primary/secondary unmatched labels, `insert or ignore` order, text-formatted addresses, and `line` numbering that depends on list order and has gaps where `insert or ignore` dropped a row.
10. **Two name spaces for one function.** "100% equal" items live under `mangled_function`, and everything else lives under `functions.name`. This produces duplicate best items, false "unmatched" rows and a misleading `all_functions_matched` (§2, §13). A port that normalises to one key per function breaks parity on every C++ symbol.
11. **The mode is decided by the data.** A port tested only in mode N can still diverge completely on a mode-P corpus (§3).

## Open questions

1. **Query plans on the real exports.** RESOLVED (recorded) for the corpus that now exists in `<corpus>/oracle/exports`. Appendix C lists the plans for every default Best/Partial heuristic and for `find_equal_matches`, `find_same_name`, `search_small_differences` and `find_related_compilation_unit`, on four pairs, using read-only immutable connections. 31 of 43 plans differ on at least one pair, and 24 of 43 change their driving table (§18.3). Hash-join emulation would need the planner's choice per pair, so running the verbatim SQL through SQLite remains the recommendation. In mode P the only plan-dependent row order is `find_same_name`'s `select distinct ... where (... or ...)` join: `find_equal_matches` (INTERSECT) and `get_unmatched_functions` (UNION) come out sorted, and `search_remaining_functions` fetches single rows. On all four pairs `find_same_name` got the same plan: `SCAN f > MULTI-INDEX OR (idx_3 mangled_function, then idx_2 name) > USE TEMP B-TREE FOR DISTINCT`.
2. **Are `functions.name` values unique inside an export?** Partly resolved. From source: the schema puts no `unique` on `name` (`db_support/schema.py:71`, only `address` and `rva` are unique), and `name` is the IDA demangler's short form (`diaphora_ida.py:2451-2453`), whose output is IDA runtime behaviour. Uniqueness is therefore NOT DETERMINED FROM SOURCE. **Observed on the real corpus (probe 14):** all seven exports (`ls`, `ls-old`, `sechost-9168-pdb`, `sechost-9444-nopdb`, `userenv-9168-pdb`, `userenv-9278-nopdb`, `userenv-9278-pdb`) have **no** duplicate `name` and no duplicate `mangled_function`, and no NULL `name`, `mangled_function`, `nodes`, `md_index`, `constants` or `names`. The PDB exports store the full demangled signature as `name`, which explains the uniqueness. Keep the check `select name, count(*) from functions group by name having count(*) > 1` in the export validator for new inputs. Independently of uniqueness, `all_functions_matched` is unreliable, because `find_equal_matches` adds `mangled_function` keys next to `name` keys (§2, §13, probe 9). On the corpus, `name != mangled_function` holds for 772 of 1442 functions (sechost-9168-pdb), 393 of 643 (userenv-9168-pdb), 411 of 663 (userenv-9278-pdb), and 0 in the no-PDB and `ls` exports. The effect needs a "100% equal" match, which needs equal `id` *and* `address` in both files. The real mode-P pair userenv-9168-pdb vs userenv-9278-pdb has no "100% equal" row at all (its 643 results are all "Perfect match, same name"), so the effect did not occur there.
3. **How large is the hash-seed sensitivity** of `find_related_constants` on the target corpus? Partly resolved. The mechanism is confirmed (probe 12): only `str` constants produce rows, and their set order changes with the seed. The only order-sensitive set iteration in the matching path is inside the iteration loop, which runs only in mode N, so **in modes S and P the seed cannot change the result**. Measured on the real corpus (probe 16):
   - `ls` vs `ls-old`: full runs identical for seeds 0, 1 and 2.
   - userenv pdb vs nopdb: the iteration-0 state after `find_related_matches` was identical.
   - sechost pdb vs nopdb: the seed **did** change the iteration-0 state, both the order of 8-9 partial items and one `matched_primary` last writer. The very next `cleanup_matches` (L3413) made the three states identical again.

   Whether later iterations, or a full sechost/userenv pdb-vs-nopdb run, can end with different output is NOT DETERMINED: those runs take hours (Q4). **Pin `PYTHONHASHSEED`** (for example `0`) for every oracle run, and keep 2-3 extra seeds as a sensitivity check on any pair that runs in mode N. A native port cannot emulate CPython's `str` hash order, so if a pair ever differs across seeds, the comparator must treat the affected "Same constants related matches" rows as tolerated.
4. **Does any default heuristic reach the 1,000,000-row cap,** or run past 300 s, on the target binaries? Mostly resolved for the current corpus (probe 15, from the oracle logs in `<corpus>/oracle/diffs`, two of which were still running at 00:43). No run logged `Timeout with heuristic` or `Processed 1000000 rows`.
   - The longest SQL heuristic took about 74 s (`Same KOKA hash and constants`, sechost pdb vs nopdb), well under the 300 s thread clock.
   - **The heavy pass is `find_related_compilation_unit`** (main thread, iteration loop, mode N). Its SQL filters on `cast(f.address as real) between ? and ?`, which gets the plan `SCAN f > SCAN df` (Appendix C). Each call is a full cross product filtered by two compilation-unit address ranges, and it runs once per best/partial match with ratio `>= 0.8` that has a CU on both sides. The rows per call are bounded by (functions in the largest main CU) × (functions in the largest diff CU): 737,817 for sechost pdb vs nopdb, 334,080 for userenv pdb vs nopdb, 346,840 for userenv pdb vs pdb, and 1,890 for `ls`. **So the 1M cap cannot be reached on these pairs.** The logs show calls of up to 700,000 rows taking about 135-150 s each on sechost, and 52 calls of at least 50,000 rows in the first 15 minutes on userenv.
   - **Risk:** the per-call clock is `self.timeout = 300` s (L1894) on the **main thread**. A call that slows past 300 s under machine load raises `SystemExit`, and the process then exits with status 0 and no output file (§5.4, §5.5). On sechost the observed margin is about 2x. The harness check from §5.5 is mandatory.
   - Row counts are logged by `add_matches_internal` every 50,000 rows (L1899-1900) and by NO_FPS every 1000 rows (L2056-2057). In mode P no SQL heuristic runs. The cost there is one query per (main `sub_*` unmatched × diff unmatched) pair in `search_remaining_functions`, each with its own 300 s clock. The userenv mode-P run took 0.19 s in total.
5. **`patch_diff_vulns.on_match` can raise `IndexError`** at `scripts/patch_diff_vulns.py:162`. Resolved for the code, open for the data. Probe 11 confirmed the `IndexError` for an empty added line, an added line starting with a space, and a `b...` added mnemonic against an empty removed line. The exporter builds `assembly` with `"\n".join` (`diaphora_ida.py:2593`) from `GetDisasm(x)` lines (`diaphora_ida.py:2649`), from the fallback `get_disasm` (`diaphora_ida.py:2439-2446`, which starts with `mnem.ljust(8)` and so starts with spaces when `print_insn_mnem` returns `""`), and from `"loc_%x:"` labels (`diaphora_ida.py:2724`), which are harmless. Whether `GetDisasm` or `print_insn_mnem` ever returns such text is NOT DETERMINED FROM SOURCE (IDA runtime). **Observed on the real corpus (probe 14):** 0 of 393,470 assembly lines across the seven exports are empty or start with a space, so the trigger does not occur there. Keep the check in the export validator. The hook only runs in mode P, only for rows with `ratio < 1.0` that pass `check_match`'s filters, in `find_same_name` and `search_remaining_functions`, and the exception aborts the diff with no output file (§5.5).
6. **Is SQLite's ORDER BY stability guaranteed** for every size and memory setting on 3.51.1? Probes up to 200k rows and more than 40 MB said yes (re-checked at 20,000 rows in probe 13), but it is implementation behaviour and the SQL standard leaves the order of equal keys undefined. A regression probe should live next to the parity tests.
7. **The parity target for the `line` column** and for the unmatched tables: should the comparator check the exact `line` numbers, or only the (type, address, address2, ratio, description) tuples? Still a product decision, but the source settles some facts. `line` values can have gaps whenever `insert or ignore` drops a row (probe 9), so a port has to replay every chooser `add_item`, including dropped ones, to match `line` exactly. The tuple should include `name` and `name2`, because "100% equal" rows carry `mangled_function` there. The unmatched tables need the label swap (§16) and can list a function that is also in `results` (§16, probe 9). Recommendation: compare (type, address, name, address2, name2, ratio, nodes1, nodes2, description) as a multiset for the parity gate, and report `line` differences separately.

---

## Appendix A: Probes (scratchpad scripts, never committed; verbatim results)

The environment for every probe was a copy of `diaphora-ref`, CPython 3.13.12, SQLite 3.51.1 and `PYTHONDONTWRITEBYTECODE=1`.

1. **Bookkeeping unit probe** (`CBinDiff` on an empty schema database, calling `add_match`, `has_better_match`, `cleanup_matches` and `count_different_matches` directly):
   ```
   IS_IDA False cpu_count 1 threads 1
   defaults: unreliable False slow True experimental True relaxed False ignore_all_names False ignore_sub_names True ignore_small False timeout 300 maxrows 1000000 use_trained_model False project_script None
   hbm(foo,baz,0.5) named short-circuit -> False
   after lower-ratio named add: mp[foo]= {'name': 'baz', 'ratio': 0.5} partial list len 2
   hbm(sub_1,bar,0.5) -> True  (bar has 0.9 in secondary)
   hbm(sub_1,bar,0.9) equal ratio -> False
   same-name add: mp[foo]= {'name': 'foo', 'ratio': 1.0} hbm(foo,zzz,0.95)-> True has_best_match -> True
   after cleanup same-name: mp[foo]= {'name': 'foo', 'ratio': 0.7} has_best_match -> False
   before cleanup ms[sub_C]= {'name': 'sub_A', 'ratio': 0.9}
   after cleanup ms[sub_C]= {'name': 'sub_B', 'ratio': 0.7} partial= [('sub_A', 'sub_C', 0.9), ('sub_B', 'sub_C', 0.7)]
   tie: mp[sub_A]= {'name': 'sub_Y', 'ratio': 0.8}
   tie after cleanup partial= [('sub_A', 'sub_X', 0.8), ('sub_A', 'sub_Y', 0.8)] mp[sub_A]= {'name': 'sub_Y', 'ratio': 0.8}
   xcat best= [('sub_A', 'sub_X', 1.0)] partial= [('sub_Q', 'sub_X', 0.95)] ms[sub_X]= {'name': 'sub_Q', 'ratio': 0.95}
   membership: best len 2 (1 == 1.0 equal; '10' != 10)
   after cleanup best len 1
   ea str vs int in cleanup: [('10', 0.9), (10, 0.6)]
   dones key collision survivors: [('a-b', 'c')]
   count_different_matches: 3
   ```
   A follow-up probe for §14 item 4 put partial `[(X->A 0.9), (X->X 0.7), (X->B 0.8)]`, all with `ea1='7'`, through cleanup. It printed `survivors [('X', 'A', 0.9), ('X', 'X', 0.7)] mp[X]= {'name': 'X', 'ratio': 0.7}`.
2. **`threads_apply(1, [H0..H3])`** printed `execution order: ['H3', 'H2', 'H1', 'H0']`. The thread names equal the heuristic names, and the `timeout` attribute starts `False`.
3. **Full standalone run** on two synthetic exports (6 functions each, the same content, `func_N` against `sub_XXXX`, different addresses, processor `metapc` on both sides). The log showed `Finding with heuristic` in forward order and `[Parallel] Heuristic '...' done` in reverse order, starting with `Microcode mnemonics small primes product`, then `Equal assembly or pseudo-code`, and so on. The Partial category was skipped (`All functions matched in at least one database, finishing.`). Result: 6 `best` rows, all with description `Equal assembly`. **The same inputs with `targets.pop(0)`** (in a second, patched copy) gave 6 `best` rows, all `Same order and hash`.
4. (See 3.)
5. **Tie:** the diff database held a twin `sub_9700` of `func_1` (inserted first, lower id) next to `sub_9100`. The raw join order was `sub_9700` then `sub_9100`, but the UNION output sorted `ea2` `'37120'` (sub_9100) before `'38656'` (sub_9700). The final result was `func_1 -> sub_9100` (best, `Equal assembly`), with `('primary', '00000', '00009700', 'sub_9700')` in `unmatched`, so the diff-database function carries the label `primary`.
6. **`add_matches_internal` with a fake cursor** and `check_match` ratios `[1.0, 0.6, 0.45, 0.3, 0.1]`:
   ```
   RATIO (val None)             {'best': [1.0], 'partial': [0.6], 'unreliable': []} fetched 5
   RATIO_MAX min=0.2            {'best': [1.0], 'partial': [0.6, 0.45, 0.3], 'unreliable': []} fetched 5
   RATIO_MAX min=0.7            {'best': [1.0], 'partial': [], 'unreliable': []} fetched 5
   TRUSTED min=0.44             {'best': [1.0], 'partial': [0.6, 0.45], 'unreliable': []} fetched 5
   Unreliable-cat RATIO         {'best': [], 'partial': [1.0], 'unreliable': [0.6]} fetched 5
   brute force (partial=None)   {'best': [], 'partial': [], 'unreliable': [1.0]} fetched 5
   maxrows=3                    {'best': [1.0], 'partial': [0.6], 'unreliable': []} fetched 3
   maxrows=0                    {'best': [], 'partial': [], 'unreliable': []} fetched 0
   ```
7. **SQLite 3.51.1 ordering:** `ORDER BY k` with k all NULL, or in {0, 1, NULL}, kept ascending insertion order within each key for N in {10, 1000, 20000, 200000} and payloads up to 5000 B. On a 4-row table, `UNION` returned rows sorted by the whole row (`('10','a',..)`, `('2','m',..)`, `('9','z',..)`), with the plan `UNION USING TEMP B-TREE`. `UNION ALL` kept scan order. `DISTINCT` kept first-occurrence order. `INTERSECT` (inside a `select ... from (... intersect ...) x`, the same shape as `find_equal_matches`) returned rows sorted by the whole row, integer `id` first: `[('z',1),('q',2),('m',3),('x',5),('b',10)]`, with the plan `INTERSECT USING TEMP B-TREE`.
8. **Environment overrides:** `DIAPHORA_SLOW_HEURISTICS=0` gave `'0'`, `DIAPHORA_SQL_MAX_PROCESSED_ROWS=10` gave `'10'`, and `continue_getting_sql_rows(0)` then raised `TypeError '<' not supported between instances of 'int' and 'str'`. `DIAPHORA_CPU_COUNT=8` still gave `cpu_count = 1`.

Probes 9-13 were added by the verification pass. They ran on a `git archive HEAD` copy of `diaphora-ref` in the session scratchpad, with the same Python and SQLite and `PYTHONDONTWRITEBYTECODE=1`. The synthetic exports were built by executing `db_support.schema.TABLES`.

9. **`mangled_function` keys** (full standalone `diaphora.py` runs, `PYTHONHASHSEED=0`, plus a driver that wraps `find_same_name` to print state).
   - Case A: one function with `name = 'Foo::Bar(int)'` and `mangled_function = '?Bar@Foo@@QEAAXH@Z'`, identical on both sides with the same `id` and address, plus three different `sub_` functions per side (mode N). Before `find_same_name`: `mp keys ['?Bar@Foo@@QEAAXH@Z']`. After it, best held `('?Bar@Foo@@QEAAXH@Z', '?Bar@Foo@@QEAAXH@Z', '100% equal', 1)` and `('Foo::Bar(int)', 'Foo::Bar(int)', 'Perfect match, same name', 1)`. Both survived to the best chooser (`'00000'` and `'00001'`, same addresses). The results table held one row: `('best', '00000', '00001000', '?Bar@Foo@@QEAAXH@Z', '00001000', '?Bar@Foo@@QEAAXH@Z', '1.0000000', '5', '5', '100% equal')`. The log said `Final results: Best 2`. Unmatched rows labelled `primary` were the diff database's `sub_5000`, `sub_6000` and `sub_7000`.
   - Case B: two identical 3-function exports (`Foo::Bar(int)` as above, `plainc`, `sub_3000`). The run took mode S (`Symbols stripped detected: ... 100.0%`). Before `find_same_name`: `mp keys ['?Bar@Foo@@QEAAXH@Z', 'plainc', 'sub_3000'] all_matched True`, `len mp 3 total1 3`. The results held 3 "100% equal" rows, and `unmatched` held `('primary', '00000', '00001000', 'Foo::Bar(int)')` and `('secondary', '00000', '00001000', 'Foo::Bar(int)')`.
10. **Cleanup rules** (`cleanup_matches` on a `CBinDiff` over an empty-schema file; all items `ea1='7'` unless shown):
    ```
    doc example best [] partial [('X', 'A', 0.9), ('X', 'X', 0.7)]
    no same-name best [] partial [('X', 'A', 0.9)]
    equal ratios w/ same-name best [] partial [('X', 'A', 0.7), ('X', 'X', 0.7)]
    equal ratios w/o same-name best [] partial [('X', 'A', 0.7), ('X', 'B', 0.7)]
    xcat tie best [('X', 'A', 1.0)] partial [('X', 'X', 0.7)]
    dones-before-ea best [] partial [('X', 'A', 0.9)]
    ```
    The last case was partial `[(X->A 0.9, ea1 '7'), (Y->B 0.8, ea1 '7'), (Y->B 0.8, ea1 '8')]`.
11. **`patch_diff_vulns.find_vulns_using_assembly`** called directly: `empty added line -> IndexError string index out of range`; `added line with leading space -> IndexError string index out of range`; `b-branch vs empty removed -> IndexError string index out of range`; `normal` (`jl` → `jb`) `-> found True`.
12. **Hash seed and `abs()`:** `list(set(json.loads(...)))` of a mixed int/str list printed the ints first in the same order for seeds 0, 1 and 2, and the five strings in three different orders. SQLite 3.51.1 `select abs(?), abs(?) == 0` gave `'abcde' (0.0, 1)`, `'123abc' (123.0, 0)`, `'0x1234' (0.0, 1)`, `'  42x' (42.0, 0)`, `'1e3zz' (1000.0, 0)`, `'-5abc' (5.0, 0)`, `'GetProcAddress' (0.0, 1)`, `'.5ab' (0.5, 0)`, `'inf' (0.0, 1)`. The int constant stored as text `'4096'` gave `abs(constant) == 0` → `0`.
13. **SQLite ordering re-check:** the `find_equal_matches` query shape returned `[('7','q',..), ('10','z',..), ('2','a',..), ('9','b',..)]` for ids 1, 2, 5, 10 (sorted by `id`), with plan `CO-ROUTINE x`, `INTERSECT USING TEMP B-TREE`. A two-branch `UNION` returned `('10','Equal asm'), ('10','Equal pseudo'), ('2', ...)`, with plan `UNION USING TEMP B-TREE`. `ORDER BY k` over 20,000 rows with `k` in {NULL, 0, 1} kept insertion order within each key, NULL first and 1 last. `'nullsub_1'`, `'NULLSUB_2'`, `'nullsubX'` and `'Nullsub_'` fail `not like 'nullsub_%'`; `'nullsub'` and `'j_nullsub_1'` pass.

Probes 14-16 use the **real** exports in `<corpus>/oracle/exports`. Queries opened them read-only with `mode=ro&immutable=1`. Every Diaphora run used copies in the session scratchpad, because constructing `CBinDiff` runs `create_schema` on db1. The corpus and its oracle outputs were not modified.

14. **Export facts** (all seven exports): no duplicate `name` or `mangled_function`; no NULL in `name`, `mangled_function`, `nodes`, `md_index`, `constants` or `names`; `sqlite_stat1` present; one `program` row each, processor `pc64`. Functions / `name != mangled_function` / compilation units: `ls` 318 / 0 / 11, `ls-old` 304 / 0 / 14, `sechost-9168-pdb` 1442 / 772 / 67, `sechost-9444-nopdb` 1419 / 0 / 44, `userenv-9168-pdb` 643 / 393 / 23, `userenv-9278-nopdb` 628 / 0 / 11, `userenv-9278-pdb` 663 / 411 / 21. Assembly lines that are empty or start with a space: 0 in every export (393,470 lines in total). The existing mode-P oracle output `userenv-9168-pdb_vs_9278-pdb` holds 635 best and 8 partial rows, all "Perfect match, same name", with contiguous best `line` values 0-634, and 20 unmatched rows, all labelled `primary` (diff-database functions, §16).
15. **Row counts and durations** parsed from the oracle logs (`diffs/*/run1/diaphora.log`; the two pdb-vs-nopdb runs were still running at 00:43). No `Timeout with heuristic`, no `Traceback`, no `Processed 1000000 rows`. Longest heuristic spans: sechost pdb vs nopdb `Same KOKA hash and constants` 73.7 s, `Same address and rare constant` 68.1 s, `Same rare constant` 66.1 s; userenv pdb vs nopdb `Same compilation unit` 3.0 s; `ls` 0.3 s. Every run of 50,000 rows or more came from `Related compilation unit` (sechost: 14 calls so far, up to 700,000 logged rows, about 135 s from the first to the last progress line of one call; userenv: 52 calls so far, up to 300,000 rows), plus one `Loop count` run of at least 50,000 rows on sechost. Computed bound for one `find_related_compilation_unit` call (largest main CU × largest diff CU, counted with `cast(address as real)` inside `[start_ea, end_ea]`): sechost 867 × 851 = 737,817; userenv pdb vs nopdb 580 × 576 = 334,080; userenv pdb vs pdb 580 × 598 = 346,840; `ls` 42 × 45 = 1,890.
16. **Hash-seed sensitivity** (copies; `PYTHONHASHSEED` = 0, 1, 2).
    - Full standalone runs of `ls` vs `ls-old` (mode N, about 8.5 s each): `results` and `unmatched` were identical in row order for all three seeds, and identical to the existing unpinned oracle run `diffs/ls_vs_ls-old/run1`. That output has no "Same constants related matches" row, so this pair barely exercises the seed-sensitive path.
    - A driver ran `diff` on the pdb-vs-nopdb pairs and raised at the start of `find_related_compilation_unit` in iteration 0, just after the first `find_related_matches`. It snapshotted `all_matches` (in order) and both dicts, and counted the `add_matches_internal` calls made by `find_related_constants`.
      - userenv-9168-pdb vs userenv-9278-nopdb: 717 calls, 148 with rows, 12,460 rows, 96 items appended. The snapshot was **identical** for all three seeds.
      - sechost-9168-pdb vs sechost-9444-nopdb: 2,048 calls, 305 with rows, 1,661 rows, 90 items appended. The snapshots **differed**. The `partial` multiset was the same, but 8-9 "Same constants related matches" items sat at different positions (from index 1168 on), and for seed 1 `matched_primary['long CreateRac(struct _ISOLATION_CONTAINER *,struct _ISO_ISOLATION_OPTIONS *)']` was `('DeleteIsolationContainer', 0.5443246)` instead of `('sub_180067758', 0.99)`.
    - Each snapshot was then fed to Diaphora's own `cleanup_matches`, which is what L3413 does next. The three post-cleanup states were **identical**: the lists (partial 1239 → 1149) and both dicts.

## Appendix B: Heuristic attributes (generated by importing `diaphora_heuristics`)

- There are 50 heuristics: 12 Best, 30 Partial and 8 Unreliable. **No heuristic has the category "Experimental".**
- Types: NO_FPS = idx {0, 1, 2, 3, 10}; RATIO_MAX_TRUSTED = idx {12}; the rest are RATIO or RATIO_MAX, as in the §4.4 tables (heur:1262 asserts `Counter({1: 22, 2: 22, 0: 5, 3: 1})`).
- Every name's `repr()` is single-quoted, so each `description` is a plain SQL string literal.
- `ORDER BY f.source_file = df.source_file` appears in 32 heuristics: idx 4, 5, 6, 7, 8, 9, 11, 13, 17, 19, 20, 22-26, 31-38, 41 and 43-49 (a regex count, `re.search(r'order\s+by\s+f\.source_file\s*=\s*df\.source_file', sql, re.I)`). Idx 40 has `order by total asc` inside one of its CTEs. Idx 42 orders by a DESC sum of equality indicators. Idx 10 is a UNION.
- (Added by the verification pass.) The outer query is `select distinct` in idx 2, 3, 4, 9, 20, 22, 23, 25, 26, 29, 32-38 and 44-47. Idx 39 uses `select distinct` only inside a CTE (heur:917). Idx 18 and 19 use `UNION` only inside a CTE (heur:490, heur:524). These were found with `re.finditer(r'select\s+distinct', sql, re.I)` and checked by reading the SQL.

## Appendix C: Query plans on the real exports (added by the verification pass)

`EXPLAIN QUERY PLAN` through Python's `sqlite3` (SQLite 3.51.1), main file opened as `file:...?mode=ro&immutable=1` and the diff file attached the same way, so nothing was written. The SQL is Diaphora's own, taken from `diaphora_heuristics.HEURISTICS` with `%POSTFIX%` replaced by `""`, plus the SQL of the four bookkeeping queries copied from L1424-1430, L2158-2166, L2093-2106 and L3429-3433 (with `?` for the parameters). Only the default heuristics are listed: Best and Partial, without the UNRELIABLE flag. Pairs, main vs diff:
- **UE**: userenv-9168-pdb vs userenv-9278-nopdb (mode N)
- **SH**: sechost-9168-pdb vs sechost-9444-nopdb (mode N)
- **LS**: ls vs ls-old (mode N)
- **UP**: userenv-9168-pdb vs userenv-9278-pdb (mode P: of the rows below, only `find_equal_matches` and `find_same_name` run there; the plans were still recorded)

"Same?" says whether the plan text is identical on all four pairs. "Outer" is the first base-table loop on each pair, which decides the primary row order of a plain join. "n/a" marks CTE or compound queries. The plan column shows the UE plan.

| Query | Same? | Outer | Plan (UE) |
|---|---|---|---|
| 0 Same RVA and hash | no | UE=df SH=f LS=f UP=f | `SEARCH df USING INDEX idx_7 (nodes>?) > SEARCH f USING INDEX idx_0 (bytes_hash=?)` |
| 1 Same order and hash | no | UE=df SH=f LS=f UP=f | `MULTI-INDEX OR > INDEX 1 > SEARCH df USING INDEX idx_6 (instructions>?) > INDEX 2 > SEARCH df USING INDEX idx_6 (instructions>?) > SEARCH f USING INTEGER PRIMARY KEY (rowid=?)` |
| 2 Function Hash | no | UE=df SH=f LS=f UP=f | `MULTI-INDEX OR > INDEX 1 > SEARCH df USING INDEX idx_7 (nodes>?) > INDEX 2 > SEARCH df USING INDEX idx_6 (instructions>?) > SEARCH f USING INDEX idx_23 (function_hash=?) > USE TEMP B-TREE FOR DISTINCT` |
| 3 Bytes hash | no | UE=df SH=f LS=f UP=f | `SEARCH df USING INDEX idx_6 (instructions>?) > SEARCH f USING INDEX idx_0 (bytes_hash=?) > USE TEMP B-TREE FOR DISTINCT` |
| 4 Same address and mnemonics | no | UE=df SH=f LS=f UP=f | `SEARCH df USING INDEX idx_6 (instructions>?) > SEARCH f USING INDEX idx_28 (address=?) > USE TEMP B-TREE FOR DISTINCT > USE TEMP B-TREE FOR ORDER BY` |
| 5 Same cleaned assembly | no | UE=df SH=f LS=f UP=f | `SEARCH df USING INDEX idx_7 (nodes>?) > SEARCH f USING INDEX idx_20 (clean_assembly=?) > USE TEMP B-TREE FOR ORDER BY` |
| 6 Same cleaned microcode | no | UE=df SH=f LS=f UP=f | `SEARCH df USING INDEX idx_6 (instructions>?) > SEARCH f USING AUTOMATIC PARTIAL COVERING INDEX (clean_microcode=?) > USE TEMP B-TREE FOR ORDER BY` |
| 7 Same cleaned pseudo-code | no | UE=df SH=df LS=f UP=f | `SEARCH df USING INDEX idx_9 (pseudocode_lines>?) > SEARCH f USING INDEX idx_21 (clean_pseudo=?) > USE TEMP B-TREE FOR ORDER BY` |
| 8 Same address, nodes, edges and mnemonics | no | UE=df SH=f LS=f UP=f | `SEARCH df USING INDEX idx_7 (nodes>?) > SEARCH f USING INDEX idx_17 (rva=?) > USE TEMP B-TREE FOR ORDER BY` |
| 9 Same RVA | no | UE=df SH=f LS=f UP=f | `SEARCH df USING INDEX idx_7 (nodes>?) > SEARCH f USING INDEX idx_17 (rva=?) > USE TEMP B-TREE FOR DISTINCT > USE TEMP B-TREE FOR ORDER BY` |
| 10 Equal assembly or pseudo-code | no | n/a | `COMPOUND QUERY > LEFT-MOST SUBQUERY > SEARCH f USING INDEX idx_9 (pseudocode_lines>?) > SEARCH df USING INDEX idx_1 (pseudocode=?) > UNION USING TEMP B-TREE > SEARCH df USING INDEX idx_6 (instructions>?) > SEARCH f USING INDEX idx_4 (assembly=?)` |
| 11 Microcode mnemonics small primes product | no | UE=df SH=f LS=f UP=f | `SEARCH df USING INDEX idx_7 (nodes>?) > SEARCH f USING INDEX idx_29 (microcode_spp=?) > USE TEMP B-TREE FOR ORDER BY` |
| 12 Same named compilation unit function match | no | UE=df SH=df LS=f UP=df | `SEARCH df USING INDEX idx_7 (nodes>?) > SEARCH dcuf USING INDEX idx_39 (func_id=?) > BLOOM FILTER ON diff_cu (id=?) > SEARCH diff_cu USING INTEGER PRIMARY KEY (rowid=?) > BLOOM FILTER ON main_cu (name=?) > SEARCH main_cu USING INDEX idx_38 (name=?) > SEARCH f USING INDEX idx_7 (nodes=?) > SEARCH mcuf USING INDEX idx_39 (func_id=?)` |
| 13 Same anonymous compilation unit function match | no | UE=df SH=df LS=f UP=df | `SEARCH df USING INDEX idx_7 (nodes>?) > SEARCH dcuf USING INDEX idx_39 (func_id=?) > BLOOM FILTER ON diff_cu (id=?) > SEARCH diff_cu USING INTEGER PRIMARY KEY (rowid=?) > BLOOM FILTER ON main_cu (name=?) > SEARCH main_cu USING INDEX idx_38 (name=?) > SEARCH f USING INDEX idx_7 (nodes=?) > SEARCH mcuf USING INDEX idx_39 (func_id=?) > USE TEMP B-TREE FOR ORDER BY` |
| 14 Same compilation unit | no | UE=f SH=f LS=f UP=f | `SEARCH f USING INDEX idx_7 (nodes>?) > SEARCH mcuf USING INDEX idx_39 (func_id=?) > SEARCH mcu USING INTEGER PRIMARY KEY (rowid=?) > SEARCH df USING INDEX idx_7 (nodes>?) > SEARCH dcuf USING INDEX idx_39 (func_id=?) > SEARCH dcu USING COVERING INDEX idx_37 (pseudocode_primes=? AND rowid=?)` |
| 15 Same KOKA hash and constants | no | UE=mc SH=mc LS=mc UP=mc | `SCAN mc > SEARCH f USING INTEGER PRIMARY KEY (rowid=?) > SEARCH df USING INDEX idx_25 (kgh_hash=?) > SEARCH dc USING COVERING INDEX idx_35 (constant=? AND func_id=?)` |
| 16 Same KOKA hash and MD-Index | no | UE=f SH=df LS=df UP=df | `SEARCH f USING INDEX idx_7 (nodes>?) > SEARCH df USING INDEX idx_25 (kgh_hash=?)` |
| 17 Same constants | yes | UE=df SH=df LS=df UP=df | `SEARCH df USING INDEX idx_26 (constants_count>?) > SEARCH f USING INDEX idx_26 (constants_count=? AND constants=?) > USE TEMP B-TREE FOR ORDER BY` |
| 18 Same rare KOKA hash | no | n/a | `CO-ROUTINE shared_hashes > COMPOUND QUERY > LEFT-MOST SUBQUERY > SCAN diff.functions USING COVERING INDEX idx_25 > UNION USING TEMP B-TREE > SCAN main.functions USING COVERING INDEX idx_25 > SEARCH f USING INDEX idx_7 (nodes>?) > SEARCH df USING INDEX idx_25 (kgh_hash=?) > SEARCH shared_hashes USING AUTOMATIC COVERING INDEX (kgh_hash=?)` |
| 19 Same rare MD Index | no | n/a | `CO-ROUTINE shared_mds > COMPOUND QUERY > LEFT-MOST SUBQUERY > SCAN diff.functions USING COVERING INDEX idx_24 > UNION USING TEMP B-TREE > SCAN main.functions USING COVERING INDEX idx_24 > SCAN shared_mds > SEARCH df USING INDEX idx_24 (md_index=?) > SEARCH f USING INDEX idx_24 (md_index=?) > USE TEMP B-TREE FOR ORDER BY` |
| 20 Same address and rare constant | yes | UE=mc SH=mc LS=mc UP=mc | `SCAN mc > SEARCH f USING INTEGER PRIMARY KEY (rowid=?) > SEARCH df USING INDEX idx_28 (address=?) > SEARCH dc USING COVERING INDEX idx_35 (constant=? AND func_id=?) > USE TEMP B-TREE FOR DISTINCT > USE TEMP B-TREE FOR ORDER BY` |
| 21 Same rare constant | no | UE=mc SH=mc LS=mc UP=mc | `SCAN mc > SEARCH f USING INTEGER PRIMARY KEY (rowid=?) > SEARCH dc USING COVERING INDEX idx_35 (constant=?) > BLOOM FILTER ON df (id=?) > SEARCH df USING INTEGER PRIMARY KEY (rowid=?)` |
| 22 Same MD Index and constants | no | UE=df SH=df LS=df UP=df | `SEARCH df USING INDEX idx_27 (md_index>?) > SEARCH f USING INDEX idx_27 (md_index=? AND constants_count>?) > USE TEMP B-TREE FOR DISTINCT > USE TEMP B-TREE FOR ORDER BY` |
| 23 Import names hash | no | UE=df SH=df LS=df UP=f | `SEARCH df USING INDEX idx_7 (nodes>?) > SEARCH f USING INDEX idx_10 (names=?) > USE TEMP B-TREE FOR DISTINCT > USE TEMP B-TREE FOR ORDER BY` |
| 24 Mnemonics and names | no | UE=df SH=df LS=f UP=f | `SEARCH df USING INDEX idx_6 (instructions>?) > SEARCH f USING INDEX idx_6 (instructions=? AND mnemonics=? AND names=?) > USE TEMP B-TREE FOR ORDER BY` |
| 25 Pseudo-code fuzzy hash | yes | UE=df SH=df LS=df UP=df | `SEARCH df USING INDEX idx_6 (instructions>?) > SEARCH f USING INDEX idx_13 (pseudocode_hash1=? AND pseudocode_hash2=? AND pseudocode_hash3=?) > USE TEMP B-TREE FOR DISTINCT > USE TEMP B-TREE FOR ORDER BY` |
| 26 Similar pseudo-code and names | no | UE=df SH=df LS=f UP=f | `SEARCH df USING INDEX idx_9 (pseudocode_lines>?) > SEARCH f USING INDEX idx_10 (names=?) > USE TEMP B-TREE FOR DISTINCT > USE TEMP B-TREE FOR ORDER BY` |
| 27 Mnemonics small-primes-product | no | UE=df SH=df LS=f UP=f | `SEARCH df USING INDEX idx_7 (nodes>?) > SEARCH f USING INDEX idx_19 (mnemonics_spp=?)` |
| 28 Same nodes, edges, loops and strongly connected components | no | UE=df SH=f LS=df UP=df | `SEARCH df USING INDEX idx_16 (loops>?) > SEARCH f USING INDEX idx_7 (nodes=? AND edges=?)` |
| 29 Same low complexity, prototype and names | yes | UE=df SH=df LS=df UP=df | `SEARCH df USING INDEX idx_8 (cyclomatic_complexity<?) > SEARCH f USING INDEX idx_10 (names=?) > USE TEMP B-TREE FOR DISTINCT` |
| 30 Same low complexity and names | yes | UE=df SH=df LS=df UP=df | `SEARCH df USING INDEX idx_8 (cyclomatic_complexity<?) > SEARCH f USING INDEX idx_10 (names=?)` |
| 31 Switch structures | no | UE=df SH=f LS=f UP=df | `SEARCH df USING INDEX idx_7 (nodes>?) > SEARCH f USING INDEX idx_7 (nodes>?) > USE TEMP B-TREE FOR ORDER BY` |
| 32 Pseudo-code fuzzy (normal) | no | UE=df SH=df LS=df UP=f | `SEARCH df USING INDEX idx_9 (pseudocode_lines>?) > SEARCH f USING INDEX idx_13 (pseudocode_hash1=?) > USE TEMP B-TREE FOR DISTINCT > USE TEMP B-TREE FOR ORDER BY` |
| 33 Pseudo-code fuzzy (mixed) | no | UE=f SH=df LS=df UP=f | `SEARCH f USING INDEX idx_9 (pseudocode_lines>?) > SEARCH df USING INDEX idx_9 (pseudocode_lines>?) > USE TEMP B-TREE FOR DISTINCT > USE TEMP B-TREE FOR ORDER BY` |
| 34 Pseudo-code fuzzy (reverse) | no | UE=f SH=df LS=df UP=f | `SEARCH f USING INDEX idx_9 (pseudocode_lines>?) > SEARCH df USING INDEX idx_9 (pseudocode_lines>?) > USE TEMP B-TREE FOR DISTINCT > USE TEMP B-TREE FOR ORDER BY` |
| 35 Pseudo-code fuzzy AST hash | yes | UE=f SH=f LS=f UP=f | `SEARCH f USING INDEX idx_9 (pseudocode_lines>?) > SEARCH df USING AUTOMATIC COVERING INDEX (pseudocode_primes=?) > USE TEMP B-TREE FOR DISTINCT > USE TEMP B-TREE FOR ORDER BY` |
| 39 Same rare assembly instruction | yes | n/a | `CO-ROUTINE query1 > CO-ROUTINE main_asm > SCAN inst > BLOOM FILTER ON f (id=?) > SEARCH f USING INTEGER PRIMARY KEY (rowid=?) > USE TEMP B-TREE FOR GROUP BY > MATERIALIZE diff_asm > SCAN inst > BLOOM FILTER ON f (id=?) > SEARCH f USING INTEGER PRIMARY KEY (rowid=?) > USE TEMP B-TREE FOR GROUP BY > SCAN main_asm > SEARCH diff_asm USING AUTOMATIC COVERING INDEX (disasm=?) > USE TEMP B-TREE FOR DISTINCT > SCAN query1 > SEARCH f USING INTEGER PRIMARY KEY (rowid=?) > SEARCH df USING INTEGER PRIMARY KEY (rowid=?)` |
| 40 Same rare basic block mnemonics list | yes | n/a | `CO-ROUTINE unique_main_bblocks > CO-ROUTINE main_bblocks > SCAN bb USING COVERING INDEX idx_33 > SEARCH inst USING INTEGER PRIMARY KEY (rowid=?) > SCAN main_bblocks > USE TEMP B-TREE FOR GROUP BY > USE TEMP B-TREE FOR ORDER BY > MATERIALIZE diff_bblocks > SCAN bb USING COVERING INDEX idx_33 > SEARCH inst USING INTEGER PRIMARY KEY (rowid=?) > SCAN diff_query > SEARCH df USING INTEGER PRIMARY KEY (rowid=?) > BLOOM FILTER ON main_query (mnemonics_list=?) > SEARCH main_query USING AUTOMATIC COVERING INDEX (mnemonics_list=?) > SEARCH f USING INTEGER PRIMARY KEY (rowid=?)` |
| 41 Loop count | yes | UE=f SH=f LS=f UP=f | `SEARCH f USING INDEX idx_16 (loops>?) > SEARCH df USING INDEX idx_16 (loops=?) > USE TEMP B-TREE FOR ORDER BY` |
| find_equal_matches | yes | n/a | `CO-ROUTINE x > COMPOUND QUERY > LEFT-MOST SUBQUERY > SCAN functions > INTERSECT USING TEMP B-TREE > SCAN diff.functions > SCAN x` |
| find_same_name | yes | UE=f SH=f LS=f UP=f | `SCAN f > MULTI-INDEX OR > INDEX 1 > SEARCH df USING INDEX idx_3 (mangled_function=?) > INDEX 2 > SEARCH df USING INDEX idx_2 (name=?) > USE TEMP B-TREE FOR DISTINCT` |
| search_small_differences | no | UE=df SH=f LS=f UP=f | `SCAN df > SEARCH f USING INDEX idx_5 (nodes=? AND edges=? AND mnemonics=?)` |
| find_related_compilation_unit | yes | UE=f SH=f LS=f UP=f | `SCAN f > SCAN df` |

---

## Verification log

An adversarial verification pass checked every behavioural claim, quoted excerpt and line number above against the source. `diaphora.py` at `621ec26` is byte-identical to tag `3.4.2`: `git diff --stat 3.4.2 HEAD` touches only `README.md` and `diaphora_ida.py`, and only after `diaphora_ida.py:3864`, so every `diaphora_ida.py` line cited here is also valid for the tag. New probes are 9-16 in Appendix A (14-16 on the real exports), and the query plans are in Appendix C.

### Checked and correct (unchanged)

- Every verbatim excerpt matches the source, apart from leading indentation inside list items and the elisions the text marks: `get_value_for` (L560-569), `get_threads_count` and `cpu_count` (L483-491, L1444-1448), `run_heuristics_for_category` (L1461-1552), `threads_apply` (threads.py:27-71), `result_iter` (L139-146), `SELECT_FIELDS` and `get_query_fields` (heur:51-84), `continue_getting_sql_rows` (L1874-1880), `check_match` (L1786-1872), `has_best_match` (L1376-1384), `has_better_match` (L1386-1402), `add_match` (L1340-1374), `add_matches_internal` (L1882-1948), the four wrappers (L1950-2037), `add_matches_from_query` (L2039-2083), `all_functions_matched` (L1777-1784), `cleanup_matches` (L1554-1605), `count_different_matches` and `get_total_matches_for` (L1607-1620), the §3 call order (L3612-3677), and the `final_pass` family (L2718-2948).
- The §1 values and their `config:` lines (46-52, 71, 90, 92, 116, 120, 137, 172, 186-189, 200, 205). `MIN_FUNCTIONS_TO_DISABLE_SLOW` is read only at `diaphora_ida.py:3799`, as the IDA dialog default `total_functions <= 4001`. Standalone `slow_heuristics` is therefore `True` at any size.
- The §4.4 tables. They were regenerated by importing `diaphora_heuristics` from a copy: every idx, `NAME` line, type, `min` and flag matches, and so do the counts 12 / 30 / 8 and 27 / 26.
- Reverse execution order (`targets.pop()`, threads.py:40). Probe 9's log printed the "done" lines from `Microcode mnemonics small primes product` down to `Same RVA and hash`.
- The dead `unreliable` branch of `add_matches_internal` (L1937-1946), the swapped unmatched labels (L2334-2354), the `insert or ignore` order (L2406-2424), the env-var typing trap, the row-cap semantics, the two timeout clocks, and the determinism verdict of §18.1. `threads_apply` is the only thread primitive in the diff path; `grep` found no other `Thread(`.

### Corrections made

1. **§2, §3 step 1, §17 — `find_equal_matches` keys by `mangled_function`, not `functions.name`.** The doc said `name1`/`name2` are "**not** `mangled_function`". L1435-1440 use `row["mangled_function"]` for both names and the dict key. Added the consequences: mangled names in the output, a duplicate same-pair best item from `find_same_name`, double dict keys, false "unmatched" entries, and no protection by `has_best_match` for the demangled name. Probe 9 confirmed each one. This matches `01-driver.md` §5.5, E4.
2. **§2 — ratio types.** `item[5]` can also be the int `0` (L1761; L1699 + L1755-1757 + L2766). Added.
3. **§2 — `ratios_cache` is not provably "a pure speed-up" that "a port may drop".** `check_match` passes `md_index` through SQLite `cast(... as real)` (heur:57, L1805, L1828), while `compare_function_rows` passes the text to Python `float()` (L2498, L2521, L1672). The first computation wins (L1654-1655). Changed the port rule to "keep a first-writer cache". Whether the two conversions ever disagree on real data is NOT DETERMINED FROM SOURCE.
4. **§14 item 1 — ties across categories.** The doc said conflicts "are decided in favour of the earlier category when ratios tie, and of the higher ratio otherwise". In fact cleanup never removes an item it has kept, a tie keeps **both** items (strict `>`, L1587), and a later higher-ratio item survives next to the earlier one. Probe 10 (`xcat tie`) confirmed this.
5. **§14 item 3 — `dones` is marked before the `ea1` test** (L1583 before L1587). A first occurrence that the `ea1` test drops also suppresses every later occurrence of that name pair. Added; probe 10 (`dones-before-ea`).
6. **§14 item 4 — wrong example.** In the doc's example, `(X->B 0.8)` is dropped by `(X->A 0.9)`: the stable descending sort puts it before `(X->X 0.7)`. The same-name item plays no part (probe 10: identical survivors without it). Replaced with an equal-ratio example in which the same-name fake alone drops `X->B`, and noted that `ea_ratios` only rises.
7. **§13 — `all_functions_matched`.** "Duplicate names mean the test can never fire" was incomplete. Mangled and demangled keys can push `len()` up to the total while functions are still unmatched. Probe 9, case B: the test fired after `find_equal_matches` alone.
8. **Summary, §3 step 4, §4.2, §4.3, §5.1 — "runs by default" ignored the data-dependent mode.** In modes S and P (L3626-3627) no SQL heuristic, `search_small_differences` or iteration-loop pass runs. Two symbolised builds of one DLL will very likely run in mode P. The answers are now qualified "mode N".
9. **§5.5 — wrapper exceptions on the main thread.** "The worker thread dies" does not hold for stripped mode (L2580, main thread): the re-raise aborts the run. Added two NULL triggers (L2176-2179, L2120). Added the exit status: 0 for a main-thread `SystemExit`, 1 for exceptions. Added the stale-output hazard: L2379-2381 are not reached.
10. **§5.4 — no log line marks a heuristic's start.** Explained how to infer the start from the previous "done" line.
11. **§6 — patch-diff `on_match`.** The possible `IndexError` is now confirmed (probe 11), with its exact triggers and the call sites it aborts.
12. **§16 — output details.** Added `line` gaps (L296, probe 9), the `Final results` log counting chooser items rather than written rows (L3684-3692), mangled names in "100% equal" rows, and two `find_unmatched` consequences (L2338, L2351).
13. **§17 — missed branches.** Added `find_same_name`'s `LIKE` wildcard and case semantics (probe 13) and its `all_functions_matched` skip (L2174). Added that `search_small_differences` has no `all_functions_matched` check and no `ORDER BY`, and can add partial items at ratio 0. Added `search_remaining_functions`'s `nodes >= 3` filter (L2684-2685), its one-time candidate lists (L2707) and the bound description (L2677, L2695).
14. **§18.2 — hash-seed row.** "Effectively non-numeric strings" is now exact: SQLite `abs()` of text uses its leading numeric prefix (probe 12). Added the constants-table filter (L990-991, `diaphora_ida.py:2418`) and the scope (mode N, ratio `>= 0.8`, `constants_count > 0`, L3484-3494). Added rows for the ratio cache and the hook `IndexError`.
15. **§18.3 — `UNION` scope.** Among the heuristics, only idx 10 has a top-level `UNION`; idx 18 and 19 use `UNION` only inside a CTE. Outside the heuristics, `get_unmatched_functions` (mode P, L2647-2650) also has a top-level `UNION`.
16. **§19 — rule 6 caveats and new rules 11-13.** Rule 6 now notes that the mangled key limits 1.0 protection, that "whatever its ratio" needs the `has_best_match` precondition, and that the non-`check_match` paths overwrite 1.0 entries. New rules cover keys per path, the ratio memo, and mode selection.
17. **§1 — details.** `is_same_processor` is `False` for NULL processors and starts `False` (L436). Added logging and harness details: stderr vs stdout (L118-125, L198-201) and the other `DIAPHORA_*` variables (L3719-3730, L3763-3770).
18. **Open questions.** Q2 is partly resolved (no unique constraint, schema.py:71; `all_functions_matched` unreliable regardless). Q3 is partly resolved: mechanism confirmed, and the seed cannot matter in modes S and P. Q5 is resolved for the code and open for the data. Q7 now lists source-determined facts and a recommendation. Q1 notes the single plan that matters in mode P.
19. **Appendices.** Added probes 9-13, and the top-level `DISTINCT` and CTE-only `UNION` lists to Appendix B.
20. **§0 and "no export exists".** Out of date. Real exports and oracle runs now exist in `<corpus>/oracle`, and probes 14-16 and Appendix C use them read-only or as scratchpad copies.
21. **§18.3 and Q1 — query plans recorded (Appendix C).** 31 of 43 default queries get a different plan on at least one of four real pairs, and 24 of 43 change their driving table. A fixed per-heuristic join order therefore cannot reproduce SQLite's row order. `find_same_name` has the same plan on all four pairs. `find_related_compilation_unit` is `SCAN f > SCAN df`.
22. **Q2 — resolved for the corpus.** No duplicate or NULL names in any of the seven exports. `name != mangled_function` for 393-772 functions per PDB export. The real mode-P pair has no "100% equal" rows, so the mangled-key effects did not occur there.
23. **Q4 — resolved for the corpus.** No timeout, and the 1M cap is unreachable: at most 737,817 rows per `find_related_compilation_unit` call. The longest heuristic takes about 74 s. The related-CU pass dominates run time at about 135-150 s per call on sechost. Its per-call 300 s clock on the main thread is a real exit-0-without-output risk under load.
24. **Q3 — measured.** Seed-insensitive on `ls` (full runs) and on userenv iteration 0. Seed-sensitive on sechost iteration 0 before the next cleanup and identical after it (probe 16). The recommendation to pin `PYTHONHASHSEED` stays.
25. **Q5 — resolved for the corpus.** 0 empty or space-led assembly lines in 393,470 lines.

### Still not determined

- Whether a **full** mode-N run on the sechost or userenv pdb-vs-nopdb pairs gives the same output for different `PYTHONHASHSEED` values. Each run takes hours in the related-CU pass (Q3, Q4).
- Whether IDA's `GetDisasm` or `print_insn_mnem` can ever produce an empty or leading-space assembly line on binaries outside the current corpus (the trigger for the Q5 `IndexError`).
- Whether SQLite `cast(text as real)` and Python `float()` ever disagree on equality for Diaphora's 28-digit `md_index` strings (the `ratios_cache` hazard in §2).
- The mode of any new pair. The harness must parse `Symbols stripped detected:` / `Patch diffing detected:`. On the current corpus, userenv pdb vs pdb runs in mode P and the other four pairs in mode N (`01-driver.md`, V12).
- SQLite `ORDER BY` stability beyond the tested sizes (Q6), and the product decision on `line` comparison (Q7).
