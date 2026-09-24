# 04b: Remaining Partial and Unreliable heuristics (H29-H50)

> **Historical spec.** Written on 2026-09-23 against an earlier revision (`34ed418`), before the port existed; its status remarks ("not implemented", test counts, runs "still running", open questions) are historical. See [README.md](README.md) in this directory for how to read it; quoted Diaphora code is (c) Joxean Koret, AGPL-3.0-or-later, and quoted CPython `difflib` code is under the PSF License Version 2.

## Summary

- **Scope.** `diaphora_heuristics.py:699-1323`: the last 14 Partial heuristics (H29-H42), all 8 Unreliable heuristics (H43-H50) and the self-test helpers at the end of the file. Numbering continues 04a: `H<n>` is `HEURISTICS[n-1]`.
- **Counts, generated from the imported module rather than typed:** 50 heuristics, **Best 12 / Partial 30 / Unreliable 8**. By ratio type: RATIO 22, RATIO_MAX 22, NO_FPS 5 and RATIO_MAX_TRUSTED 1. The file asserts the ratio split itself at `:1262`. This document covers 22 of them: 14 Partial and 8 Unreliable.
- **What runs in the default standalone oracle** (`python diaphora.py db1 db2 -o out`). Whenever the Partial pass runs, ten in-scope Partial heuristics run with no further per-heuristic condition: H29-H36, H41 and H42. H42 is flagged SLOW, and `slow_heuristics` is True by default at any size. **H40 Same rare assembly instruction** runs only when both `program.processor` values are equal. **H37-H39** (the three "Partial pseudo-code fuzzy hash" heuristics) are skipped because they carry `HEUR_FLAG_UNRELIABLE`. **None of H43-H50 run**, because the whole Unreliable pass is gated on `DIFFING_ENABLE_UNRELIABLE=False`. `MIN_FUNCTIONS_TO_DISABLE_SLOW` is read only by IDA's `BinDiffOptions` default (`diaphora_ida.py:3798-3800`), never by standalone `diaphora.py`.
- **None of these run at all** when the "dirty" speed-up fires, which it does when ≥99% of address pairs or >90% of mangled names are shared. **This is confirmed on the real oracle:** `userenv-9168-pdb_vs_9278-pdb` logs `Patch diffing detected: A total of 643 matches out of 643, 100.0% percent have the same name` and runs no heuristic from `HEURISTICS`. The other four oracle pairs do not trigger it (mangled-name shares of 37.50%, 35.85%, 9.33% and 15.81%). No `win32u` Diaphora export exists, so the open question about `win32u` stays **NOT DETERMINED**. Setting `DIAPHORA_EXPERIMENTAL=""` disables the speed-up; `self.experimental` is read nowhere else in `diaphora.py` (only at `:3618`).
- **Order.** Standalone runs one heuristic at a time in **reverse declaration order** (`threads_apply` calls `targets.pop()`), which was verified. The in-scope Partial heuristics therefore run **before** H13-H28, starting with H42 Loop count.
- **Routing depends on the per-pair ratio, not on the heuristic's category.** r == 1.0 goes to `best`, r ≥ min goes to `partial`, and anything else is dropped. The `unreliable` branch is dead code for every heuristic here. In the Unreliable pass everything moves down one tier: 1.0 goes to `partial` and ≥ min goes to `unreliable`.
- **SQL traps:**
  - NULL never equals NULL. The current loader collapses NULL to `0`/`""`, which must change.
  - `strongly_connected_spp > 1` is a **TEXT** comparison against `'1'`.
  - `NOT LIKE 'nullsub%'` is ASCII case-insensitive.
  - The two "rare" heuristics (H40, H41) count **microcode rows too**.
  - `(min*100)/max < 50` keeps only pairs whose node counts differ by **more than 2x**.
  - The `GROUP_CONCAT` order and the bare `func_id` in H41 come from the query plan.
- **Row order is plan-dependent.** Without ORDER BY, and among ties when there is one, rows arrive in query-plan order. I watched that order change between two synthetic datasets, so it is **NOT DETERMINED FROM SOURCE**. It matters, because match acceptance is order-dependent and there is a 1,000,000-row cap (see 04a §6.6 for the "run the verbatim SQL" recommendation).
- **Verification.** Every predicate below was re-implemented without SQL and diffed against SQLite 3.51.1 running the verbatim SQL on 52 randomized adversarial DB pairs. That produced **0 mismatches**, and the negative controls fail as they should (§10). The adversarial verification pass then re-ran an independent no-SQL implementation of this spec against the **real IDA 9.4 Diaphora exports** of the parity oracle (5 pairs × 22 heuristics). It also found **0 mismatches** (§10.1).

---

## 0. Provenance and method

- **Reference.** `<diaphora-ref>`, `git describe` = `3.4.2-4-g621ec26`. `git diff 3.4.2 HEAD --stat` touches only `README.md` and `diaphora_ida.py`, so `diaphora_heuristics.py`, `diaphora.py`, `diaphora_config.py`, `jkutils/threads.py` and `db_support/schema.py` are the 3.4.2 files.
- **Runtime.** `<conda>/python.exe` is 3.13.12 with SQLite **3.51.1**. `pragma compile_options` shows no ICU and no STAT4, so `ANALYZE` writes `sqlite_stat1` only and LIKE folds ASCII only.
- **Experiments.** All ran on a `git archive` copy of the reference in a scratch directory (`<scratch>/exp/`), with `PYTHONDONTWRITEBYTECODE=1`. The reference tree was not modified. Nothing was committed.
  - `order_probe.py` builds two synthetic exports with Diaphora's own `schema.TABLES` + `INDICES` + `analyze`, runs `CBinDiff.diff` and records which heuristic each `add_matches_from_*` call belongs to.
  - `unrel_probe.py` does the same for the Unreliable pass and also records the chooser of each `add_match`.
  - `sem_probe.py`, `bb_probe.py`, `tie_probe*.py` and `sort_stab.py` are SQLite semantics probes.
  - `plan_probe*.py` dumps `EXPLAIN QUERY PLAN` for every in-scope SQL.
  - `spec_check.py` is the no-SQL re-implementation of this spec, diffed against SQLite (§10).

---

## 1. Inventory (all 50, generated from the module; in-scope rows in bold)

Flags are **list membership** (`HEUR_FLAG_X in flags`, `diaphora.py:1498/1502/1506`), not bit masks: `SAME_CPU = 3` does not mean UNRELIABLE|SLOW.

"Lines" runs from the `NAME = ` line to the closing `})`. The per-heuristic section headings in §7 and §8 also include any comment block above `NAME`.

| H | Lines | Name | Category | Ratio type | min | Flags |
|---|---|---|---|---|---|---|
| 1 | 89-107 | Same RVA and hash | Best | NO_FPS | - | SAME_CPU |
| 2 | 109-127 | Same order and hash | Best | NO_FPS | - | SAME_CPU |
| 3 | 129-143 | Function Hash | Best | NO_FPS | - | SAME_CPU |
| 4 | 145-157 | Bytes hash | Best | NO_FPS | - | SAME_CPU |
| 5 | 159-176 | Same address and mnemonics | Best | RATIO | - | - |
| 6 | 178-193 | Same cleaned assembly | Best | RATIO | - | SAME_CPU |
| 7 | 195-210 | Same cleaned microcode | Best | RATIO | - | SAME_CPU |
| 8 | 212-227 | Same cleaned pseudo-code | Best | RATIO | - | - |
| 9 | 229-248 | Same address, nodes, edges and mnemonics | Best | RATIO | - | - |
| 10 | 250-267 | Same RVA | Best | RATIO_MAX | 0.7 | SAME_CPU |
| 11 | 272-297 | Equal assembly or pseudo-code | Best | NO_FPS | - | - |
| 12 | 299-317 | Microcode mnemonics small primes product | Best | RATIO | - | - |
| 13 | 325-351 | Same named compilation unit function match | Partial | RATIO_MAX_TRUSTED | 0.44 | - |
| 14 | 353-379 | Same anonymous compilation unit function match | Partial | RATIO_MAX | 0.449 | - |
| 15 | 390-412 | Same compilation unit | Partial | RATIO | - | SLOW |
| 16 | 417-434 | Same KOKA hash and constants | Partial | RATIO | - | - |
| 17 | 438-457 | Same KOKA hash and MD-Index | Partial | RATIO | - | - |
| 18 | 459-474 | Same constants | Partial | RATIO_MAX | 0.5 | - |
| 19 | 478-510 | Same rare KOKA hash | Partial | RATIO_MAX | 0.45 | - |
| 20 | 512-541 | Same rare MD Index | Partial | RATIO | - | - |
| 21 | 546-564 | Same address and rare constant | Partial | RATIO_MAX | 0.5 | - |
| 22 | 567-585 | Same rare constant | Partial | RATIO_MAX | 0.2 | SLOW |
| 23 | 587-603 | Same MD Index and constants | Partial | RATIO | - | - |
| 24 | 605-621 | Import names hash | Partial | RATIO | - | - |
| 25 | 623-639 | Mnemonics and names | Partial | RATIO | - | - |
| 26 | 641-660 | Pseudo-code fuzzy hash | Partial | RATIO | - | - |
| 27 | 662-680 | Similar pseudo-code and names | Partial | RATIO_MAX | 0.579 | - |
| 28 | 682-697 | Mnemonics small-primes-product | Partial | RATIO_MAX | 0.6 | - |
| **29** | **701-719** | **Same nodes, edges, loops and strongly connected components** | Partial | RATIO_MAX | 0.549 | - |
| **30** | **723-740** | **Same low complexity, prototype and names** | Partial | RATIO_MAX | 0.5 | - |
| **31** | **742-758** | **Same low complexity and names** | Partial | RATIO_MAX | 0.5 | - |
| **32** | **760-775** | **Switch structures** | Partial | RATIO_MAX | 0.5 | - |
| **33** | **777-791** | **Pseudo-code fuzzy (normal)** | Partial | RATIO_MAX | 0.5 | - |
| **34** | **793-806** | **Pseudo-code fuzzy (mixed)** | Partial | RATIO | - | - |
| **35** | **808-821** | **Pseudo-code fuzzy (reverse)** | Partial | RATIO | - | - |
| **36** | **823-838** | **Pseudo-code fuzzy AST hash** | Partial | RATIO_MAX | 0.35 | - |
| **37** | **840-854** | **Partial pseudo-code fuzzy hash (normal)** | Partial | RATIO_MAX | 0.5 | SLOW, UNRELIABLE |
| **38** | **856-870** | **Partial pseudo-code fuzzy hash (reverse)** | Partial | RATIO_MAX | 0.5 | SLOW, UNRELIABLE |
| **39** | **872-886** | **Partial pseudo-code fuzzy hash (mixed)** | Partial | RATIO_MAX | 0.5 | SLOW, UNRELIABLE |
| **40** | **888-934** | **Same rare assembly instruction** | Partial | RATIO_MAX | 0.5 | SAME_CPU |
| **41** | **936-979** | **Same rare basic block mnemonics list** | Partial | RATIO_MAX | 0.5 | - |
| **42** | **981-996** | **Loop count** | Partial | RATIO_MAX | 0.49 | SLOW |
| **43** | **998-1031** | **Same graph** | Unreliable | RATIO_MAX | 0.5 | - |
| **44** | **1036-1054** | **Strongly connected components** | Unreliable | RATIO_MAX | 0.8 | SLOW |
| **45** | **1059-1075** | **Nodes, edges, complexity and mnemonics** | Unreliable | RATIO | - | SLOW |
| **46** | **1081-1097** | **Nodes, edges, complexity and prototype** | Unreliable | RATIO | - | SLOW |
| **47** | **1102-1119** | **Nodes, edges, complexity, in-degree and out-degree** | Unreliable | RATIO | - | SLOW |
| **48** | **1124-1139** | **Nodes, edges and complexity** | Unreliable | RATIO | - | SLOW |
| **49** | **1144-1157** | **Same high complexity** | Unreliable | RATIO | - | SLOW |
| **50** | **1162-1177** | **Topological sort hash** | Unreliable | RATIO | - | - |

Cross-checks, all generated:

- `Counter(category)` gives `{'Partial': 30, 'Best': 12, 'Unreliable': 8}`.
- `Counter(ratio)` gives `{1: 22, 2: 22, 0: 5, 3: 1}`.
- Split by category and ratio type (re-counted in verification from a copy of the module): Best = NO_FPS 5 + RATIO 6 + RATIO_MAX 1; Partial = RATIO_MAX 19 + RATIO 10 + RATIO_MAX_TRUSTED 1; Unreliable = RATIO 6 + RATIO_MAX 2. The 50 `NAME = ` lines pair one-to-one with 50 `})` lines, and every row of the table above matches the module.
- `python diaphora_heuristics.py` on the scratch copy prints `All tests run OK!`.
- The categories present are exactly `{'Best','Partial','Unreliable'}`. There is **no** `"Experimental"` heuristic, so `find_experimental_matches` (`diaphora.py:2307-2311`) runs nothing.

In scope, by ratio type: RATIO_MAX has 14 (H29-H33, H36-H44) and RATIO has 8 (H34, H35, H45-H50). No NO_FPS or TRUSTED heuristic is in scope.

---

## 2. Shared definitions used by every section below

### 2.1 Ratio-type and flag constants (`diaphora_heuristics.py:27-48`, verbatim)

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

The comments describe an "unreliable" tier for ratios below 0.5. **The code never produces one** from these heuristics (§4.2).

### 2.2 `SELECT_FIELDS` / `get_query_fields` (`diaphora_heuristics.py:51-84`, verbatim)

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

- Every in-scope SQL calls `get_query_fields(NAME)`, so the `description` column is the SQL literal `'<NAME>'`. Python `repr` produces single quotes, and no in-scope name contains a quote. **The output description of every match from H29-H50 is exactly the heuristic's `name`.**
- The row carries both functions' `address, name, pseudocode, assembly, pseudocode_primes, nodes, md_index (cast to REAL), clean_assembly, clean_pseudo, mangled_function, clean_microcode, bytes_hash, edges, indegree, outdegree, instructions, cyclomatic_complexity, strongly_connected, loops, constants_count, size, kgh_hash`. These feed `check_match`/`check_ratio`; see 03a and 04a §5.
- `deep_ratio` (`diaphora.py:2749-2837`) additionally re-reads `select * from {db}.functions where address = ?` for both functions.

### 2.3 `%POSTFIX%`

`diaphora.py:1471-1473` and `1518`:

```python
    postfix = ""
    if self.ignore_small_functions:
      postfix = config.SQL_DEFAULT_POSTFIX
...
      sql = sql.replace("%POSTFIX%", postfix)
```

- The default is `DIFFING_IGNORE_SMALL_FUNCTIONS = False` (`diaphora_config.py:52`), so the placeholder becomes `""`.
- If the option is on, the postfix is `" and f.instructions > 5 and df.instructions > 5 "` (`diaphora_config.py:128`). It is inserted where `%POSTFIX%` sits: after the last WHERE predicate and before any ORDER BY, and in the **outer** query for H40/H41.
- The hook `get_queries_postfix` is called at `:1475`, but its return value is **discarded**.
- Short of editing `diaphora_config.py`, the only way to turn the option on in standalone mode is the environment variable `DIAPHORA_IGNORE_SMALL_FUNCTIONS`, and **any** non-empty string enables it (§3.1).

### 2.4 Notation for the C++ predicates

These match 04a §10. Values are SQL values, so any of them may be NULL.

| Symbol | Meaning (exact SQLite semantics) |
|---|---|
| `nn(x)` | `x` is not NULL |
| `EQ(a,b)` | `nn(a) && nn(b) && a == b`. Two INTEGER-affinity columns compare numerically. Two TEXT-affinity columns compare **bytewise** (BINARY collation = `memcmp`, then length). A TEXT column never converts to a number. |
| `GT(a,k)`, `GE`, `LT` | `nn(a) &&` a numeric comparison with an integer literal, for INTEGER-affinity columns |
| `NE(a,"s")` | `nn(a) && a != "s"`, byte comparison |
| `TGT(a,"1")` | TEXT-affinity column vs an integer literal: `nn(a) && bytes(a) > bytes("1")` lexicographically (unsigned bytes, a shorter prefix sorts first). §5.2. |
| `SUBEITHER` | `(substr(f.name,1,4) = 'sub_' or substr(df.name,1,4) = 'sub_')`. Three-valued: true iff `(nn(f.name) && starts_with(f.name,"sub_")) \|\| (nn(df.name) && starts_with(df.name,"sub_"))`. A byte prefix is exact, because `'sub_'` is ASCII. Case-sensitive: `SUB_x` does not count. |
| `NOTNULLSUB(n)` | `n not like 'nullsub%'`, which is `nn(n) && !(ascii_tolower(n[0..7)) == "nullsub")`. `NullSub_1` and `nullsubx` are both "like"; a NULL name is excluded. |
| `SUBSTR16(s)` | `substr(s,1,16)`. NULL if `s` is NULL, otherwise the first 16 **characters** (UTF-8 code points). The hash alphabet is base64 ASCII (`jkutils/kfuzzy.py:166`), so for real data that is the first 16 bytes, or the whole string if it is shorter. |
| `NR50(a,b)` | `((min(a,b)*100)/max(a,b)) < 50`, with multi-argument `min`/`max` and **int64 integer division**. `nn(a) && nn(b) && max(a,b) != 0 && (min*100)/max < 50`. For non-negative ints this equals `2*min(a,b) < max(a,b)`. Division by zero gives NULL, which excludes the row. Verified: `(min(3,7)*100)/max(3,7)` = 42, `(4,7)` = 57, `(5,10)` = 50, `(0,0)` = NULL. |

`==` in the SQL is the same operator as `=`.

---

## 3. When these heuristics run

### 3.1 Configuration as seen by the standalone oracle

`get_value_for` (`diaphora.py:560-569`, verbatim):

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

An environment override is returned as a **raw string**, because `isinstance(str, bool)` is false. Consequences:

- `DIAPHORA_UNRELIABLE=0` turns unreliable **on**, because `"0"` is truthy.
- `DIAPHORA_EXPERIMENTAL=""` turns experimental **off**. An empty string survives `subprocess` env passing on this Windows PC; verified with `os.getenv` returning `''` in a child process.
- A numeric override such as `DIAPHORA_SQL_MAX_PROCESSED_ROWS` makes `i < self.sql_max_processed_rows` compare an int with a str (`diaphora.py:1878`). That raises `TypeError` inside every RATIO/RATIO_MAX heuristic, which covers all of H29-H50, so do not use one.

Default values used below:

| Setting | Value | Source |
|---|---|---|
| `DIFFING_ENABLE_UNRELIABLE` | False | `diaphora_config.py:46`, read at `diaphora.py:400-402` |
| `DIFFING_ENABLE_EXPERIMENTAL` | True | config `:48`, `diaphora.py:406-408` |
| `DIFFING_ENABLE_SLOW_HEURISTICS` | True, **independent of size** | config `:49`, `diaphora.py:409-411` |
| `MIN_FUNCTIONS_TO_DISABLE_SLOW` = 4001 | **not used by `diaphora.py`** | only `diaphora_ida.py:3798-3800`: `"slow", total_functions <= config.MIN_FUNCTIONS_TO_DISABLE_SLOW` (the IDA options dialog) |
| `DIFFING_IGNORE_SMALL_FUNCTIONS` | False, so the postfix is `""` | config `:52` |
| CPU count | forced to 1 outside IDA | `diaphora.py:489-491`: `if not IS_IDA: self.cpu_count = 1` |
| `SQL_MAX_PROCESSED_ROWS` | 1,000,000 rows per heuristic | config `:90` |
| `SQL_TIMEOUT_LIMIT` | 300 s wall-clock per heuristic | config `:92` |
| `ignore_all_names` | False (standalone) | `diaphora.py:3759-3760` |

An earlier summary says slow heuristics are auto-disabled at 4001 functions. **That is IDA-only.** 01-driver, 02-matching, 03a and 04a reached the same conclusion independently.

### 3.2 The gate chain, in order

1. **Dirty speed-ups skip everything.** `diaphora.py:3616-3641`, verbatim:

```python
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
```

   `apply_dirty_heuristics` (`:2629-2637`) returns True in two cases:
   - `search_just_stripped_binaries`: `count(*)` of `f.address = df.address` pairs times 100, divided by `total_functions1`, is `>= 99.0` (`:2551-2563`).
   - `search_patchdiff_with_symbols`: the same count on `f.mangled_function = df.mangled_function` is `> 90.0` (`:2599-2610`).

   When either fires, **no heuristic from `HEURISTICS` runs**, in any category. See 01-driver §5.7.

2. **Partial pass.** `find_partial_matches` (`:2212-2221`) calls `run_heuristics_for_category("Partial")`, then `search_small_differences` if `slow_heuristics`.

3. **Unreliable pass.** It runs only `if self.unreliable` (`:3638`). `find_unreliable_matches` (`:2313-2321`) then runs `run_heuristics_for_category("Unreliable")`, followed by `find_brute_force` if both `slow_heuristics` and `unreliable` are set. The brute force is out of scope; see 05-passes.

4. **Per-heuristic flags** (`diaphora.py:1497-1508`, verbatim):

```python
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
```

   `is_same_processor` comes from `select 1 from main.program mp, diff.program dp where mp.processor = dp.processor` (`:2956-2962`). It is true if **any** row pair has an equal `processor` text. The exporter writes `idaapi.get_idp_name()`, plus `"64"` when `BADADDR == 0xFFFFFFFFFFFFFFFF` (`diaphora_ida.py:3402-3404`). That test is on IDA's address width, not on the binary's bitness. All 7 real oracle exports (IDA 9.4) store `'pc64'` in their single `program` row, so H40 runs on every oracle pair.

5. **All matched.** The run list is built only while `len(matched_primary) != total_functions1 and len(matched_secondary) != total_functions2` (`:1481-1484`; this is evaluated before any heuristic of the pass runs). Each `add_matches_from_*` also returns immediately when `all_functions_matched()` holds at the moment it starts (`:1956`, `:1981`, `:2007`). Both are keyed by **name**.

6. **Hooks.** `get_heuristics` and `on_launch_heuristic` apply only if a project script is loaded. If `on_launch_heuristic` returns `None`, the heuristic is skipped (`:1520-1522`). By default no script is loaded: the patch-diff script is auto-loaded only on the dirty path (`:2615-2619`), where no heuristic runs anyway. A script can also be forced with the environment variable `DIAPHORA_PROJECT_SCRIPT` (`:421`, loaded at `:3607-3610`). The oracle strips every `DIAPHORA_*` variable (09-oracle), so this does not apply there.

### 3.3 Execution order (reverse, serial), verified

`jkutils/threads.py:39-41`:

```python
    if len(targets) > 0 and len(threads_list) < threads:
      item = targets.pop()
      target = item["target"]
```

With `threads == 1`, the next heuristic starts only after the previous thread has died (see 02-matching §4.3). The instrumented run on synthetic exports (`order_probe.py`: default config, same processor, Best did not match everything) recorded this Partial order:

```
Loop count | Same rare basic block mnemonics list | Same rare assembly instruction |
Pseudo-code fuzzy AST hash | Pseudo-code fuzzy (reverse) | Pseudo-code fuzzy (mixed) |
Pseudo-code fuzzy (normal) | Switch structures | Same low complexity and names |
Same low complexity, prototype and names |
Same nodes, edges, loops and strongly connected components |
Similar pseudo-code and names ... Same named compilation unit function match
```

It exactly matches the reversed filtered list. The real oracle logs show the same order: `sechost-9168-pdb_vs_9444-nopdb/run1/diaphora.log` and `userenv-9168-pdb_vs_9278-nopdb/run1/diaphora.log` print their `Heuristic '...' done` lines as Loop count, Same rare basic block mnemonics list, Same rare assembly instruction, Pseudo-code fuzzy AST hash, … Same nodes, edges, loops and strongly connected components, Mnemonics small-primes-product, …. They also print the three `Skipping unreliable heuristic 'Partial pseudo-code fuzzy hash (...)'` lines. The `Finding with heuristic` lines are logged while the list is built (`diaphora.py:1517`), so they come out in declaration order. With `DIAPHORA_UNRELIABLE=1`, "Partial pseudo-code fuzzy hash (mixed)", "(reverse)" and "(normal)" appear, in that order, right after "Same rare assembly instruction". The Unreliable pass (`unrel_probe.py`) ran in this order:

```
Topological sort hash, Same high complexity, Nodes, edges and complexity,
Nodes, edges, complexity, in-degree and out-degree, Nodes, edges, complexity and prototype,
Nodes, edges, complexity and mnemonics, Strongly connected components, Same graph
```

Default Partial execution positions for the in-scope heuristics:

| Position | Heuristic |
|---|---|
| 1 | H42 |
| 2 | H41 |
| 3 | H40, same CPU only |
| - | H39, H38, H37 are skipped by default |
| 4 | H36 |
| 5 | H35 |
| 6 | H34 |
| 7 | H33 |
| 8 | H32 |
| 9 | H31 |
| 10 | H30 |
| 11 | H29 |

H28 through H13 follow. `cleanup_matches` runs **once**, after the whole pass (`:1551`), not between heuristics. The state that one heuristic leaves in `matched_primary` / `matched_secondary` is therefore visible to the next one.

---

## 4. How rows become matches (summary; full spec in 02-matching §6-11 and 04a §4-5)

### 4.1 Dispatch (`diaphora.py:1510-1535`, verbatim)

```python
      if arg_category.lower() == "unreliable":
        best = "partial"
        partial = "unreliable"
      else:
        best = "best"
        partial = "partial"
...
      if ratio == HEUR_TYPE_NO_FPS:
        function = self.add_matches_from_query
        function_args = [sql, best]
      elif ratio == HEUR_TYPE_RATIO:
        function = self.add_matches_from_query_ratio
        function_args = [sql, best, partial]
      elif ratio == HEUR_TYPE_RATIO_MAX:
        function = self.add_matches_from_query_ratio_max
        function_args = [sql, best, partial, min_value]
```

- `add_matches_from_query_ratio` calls `add_matches_internal(cur, best, partial, unreliable=None)`, so `val=None`.
- `add_matches_from_query_ratio_max` calls `add_matches_internal(cur, best, partial, val=min, unreliable="unreliable")` (`:1987-1989`).

### 4.2 Routing (`diaphora.py:1922-1946`; verbatim excerpt 1922-1941)

```python
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
```

In the `else` branch `partial` is never None, so `r < val` holds and `r > val` is impossible. **The "unreliable" fallback is dead code.** Resulting routing, where r is the double from `check_match` → `check_ratio` + `deep_ratio` (03a):

| Pass | Ratio type (min) | r == 1.0 | min ≤ r < 1.0 | r < min |
|---|---|---|---|---|
| Partial | RATIO (val = `DEFAULT_PARTIAL_RATIO` = 0.5) | `best` | `partial` | dropped |
| Partial | RATIO_MAX (min) | `best` | `partial`, **even when min < 0.5** (H36: 0.35, H42: 0.49) | dropped |
| Unreliable | RATIO (0.5) | `partial` | `unreliable` | dropped |
| Unreliable | RATIO_MAX (min) | `partial` | `unreliable` | dropped |

The table was verified by `unrel_probe.py`: "Topological sort hash" rows with r = 0.503 … 0.803 went to `unreliable`.

Before routing, every row passes `check_match` (`:1786-1872`):

- `name1.startswith("nullsub_") or name2.startswith("nullsub_")` drops the row. This check is **case-sensitive** and separate from the SQL `LIKE`.
- `has_best_match(name1, name2)` drops the row if either name already has a ratio of 1.0.
- `r = check_ratio(...)`, cached per `"ea1-ea2"` for the whole `diff()` (`:1653-1655`, reset at `:3572`).
- `has_better_match(name1, name2, r)` drops the row, including its name clause (04a §5.2).
- The `on_match` hook runs last.

`add_match` (`diaphora.py:1340-1374`) then does the following, verbatim:

```python
      if name1 == name2:
        ratio = 1.0

      if ratio != 1.0:
        if self.has_better_match(name1, name2, ratio):
          return
...
      if chooser is not None:
        if item not in self.all_matches[chooser]:
          self.all_matches[chooser].append(item)

      self.matched_primary[name1] = {"name": name2, "ratio": ratio}
      self.matched_secondary[name2] = {"name": name1, "ratio": ratio}
```

(`:1350-1355`, `:1369-1374`)

- **Same-name override.** When `name1 == name2`, the ratio stored in `matched_primary` / `matched_secondary` becomes **1.0**, and the `has_better_match` re-check is skipped. The chooser and the item were already chosen from the real `r`, so the item still carries `r`. From then on `has_best_match` is true for both names. This applies to every in-scope heuristic except H40, whose SQL has `f.name != df.name`.
- **Item dedup.** The item is appended **only if an identical item is not already in that chooser's list**.
- **Duplicate rows are not no-ops.** H41 can emit the same `(f,df)` more than once. A duplicate row never adds a second chooser item, but it re-runs `check_match` (with the cached ratio) and `add_match`. That rewrites `matched_primary[name1]` / `matched_secondary[name2]` to this pair again. If another row for `name1` or `name2` was accepted in between, the duplicate makes this pair the last writer again. **The port must feed every row, duplicates included, in order. It must not deduplicate them.**
- Items are `[ea, name1, ea2, name2, desc, r, nodes1, nodes2]`, where `ea = str(row["ea"])`, `nodes1 = int(row["nodes1"])` and `desc` is the heuristic name.
- `MATCHES_BONUS_RATIO` is **not** applied on this path.

### 4.3 Row cap and timeout (non-negotiable for parity; see 02-matching §5.3-5.4)

```python
  def continue_getting_sql_rows(self, i):
    """
    Determine if more rows should be read at the given stage
    """
    if self.sql_max_processed_rows != 0 and i < self.sql_max_processed_rows:
      return True
    return False
```

(`diaphora.py:1874-1880`)

- **Row cap.** At most 1,000,000 rows are **fetched** per heuristic, rejected rows included. A value of 0 means "process nothing", not "unlimited".
- **Timeout.** The check, verbatim, is at the top of every loop iteration, before the fetch:

  ```python
        if time.monotonic() - t > self.timeout or cur_thread.timeout:
          log(f"Timeout with heuristic '{cur_thread.name}'")
          raise SystemExit()
  ```

  (`diaphora.py:1894-1896`). There are **two independent clocks**:
  1. `t = time.monotonic()` is taken at the start of `add_matches_internal` (`:1892`), which is **after** `cur.execute(sql)` has returned. It is compared with `self.timeout`, which is `get_value_for("SQL_TIMEOUT_LIMIT", 300)` (`:451`).
  2. `cur_thread.timeout` is set to True by `threads_apply` when `time.monotonic() - t.time > timeout` (`jkutils/threads.py:62-63`). Here `t.time` is taken **before** `t.start()` (`:45`), and `timeout` is `config.SQL_TIMEOUT_LIMIT` (`diaphora.py:1548`), not the environment override. `threads_apply` checks this only about once per `THREADS_WAIT_TIME` = 1 s join.

  The check runs only between row fetches. A long `cur.execute` (for an ORDER BY query, typically the whole join and sort) or a long single `fetchone()` cannot be interrupted. `add_matches_from_query_ratio*` swallows the `SystemExit` (`except SystemExit: pass`), and **matches added before the timeout stay**.
- **Log signals.** `Processed {i} rows...` is logged when `i % 50000 == 0` (`:1899-1900`), **after** `i += 1` and **before** the fetch. `Processed 1000000 rows...` therefore appears whenever the result has at least 999,999 rows. It is necessary for truncation but not sufficient: truncation happens only if more than 1,000,000 rows exist. `Timeout with heuristic '<name>'` names the heuristic, because `threads_apply` copies the item's `name` key onto the thread (`threads.py:48-50`).
- **Which heuristics are exposed.** H42, H32, H36, H33-H35, H30-H31 and all of H45-H49 are near-cartesian on common keys: `loops`, `switches`, `names`, `cyclomatic_complexity` or a shared fuzzy hash. Larger binaries could exceed the cap, and at Python's per-row `check_ratio` cost they could exceed the timeout. If the cap truncates, **which** rows get processed depends on row order (§5.6). A timeout is wall-clock and not reproducible. Oracle runs must be checked for `Timeout with heuristic` in the log, and every heuristic's row count must be checked against 1,000,000.
- **Measured on the real oracle corpora** (§10.1): no in-scope heuristic comes close.
  - The largest row count is 49,616 (H48, which is Unreliable and so off by default, on sechost).
  - The largest for a default-on heuristic is 2,551 (H42, sechost).
  - Every default-on in-scope heuristic finished within about 5 s of wall-clock in the oracle logs.
  - No oracle log contains `Timeout`.

---

## 5. SQL semantics that decide which rows exist (with evidence)

### 5.1 NULL

- A comparison with NULL gives NULL, which WHERE treats as false. `NULL = NULL` does not match. `CASE WHEN NULL = NULL THEN 1 ELSE 0 END` gives **0** (verified).
- `NULL != 'int()'`, `NULL NOT LIKE 'nullsub%'`, `substr(NULL,1,16)`, `length(NULL) >= 35` and `min(NULL,3)` are all NULL (verified).
- Realistic NULLs in Diaphora exports:
  - `prototype2`: `idc.get_type(f)` returns None when IDA has no type (`diaphora_ida.py:2968`).
  - `pseudocode`, `pseudocode_hash1..3`, `pseudocode_primes`: None without decompilation, and an empty fuzzy hash also becomes None (`diaphora_ida.py:2540-2566`).
  - `tarjan_topological_sort`: None on `RecursionError` (`diaphora_ida.py:2621-2625`).
  - `source_file`: None unless a named compilation unit covers the function (`diaphora_ida.py:3356-3382`; `build_props_list` passes None at the `source_file` slot).
- **The current loader turns NULL into `""` / `0`** (`src/ExportDatabase.cpp:98-105`; `sqlite3_column_int64`). For H30, H46, H50 and H33-H39 that would, for example, match every pair of untyped functions (`prototype2`) or every pair of functions without pseudocode (`pseudocode_hash*`). The loader needs a per-column null flag.

### 5.2 Type affinity (schema `db_support/schema.py:69-118`)

- **INTEGER affinity:** `nodes`, `edges`, `indegree`, `outdegree`, `size`, `instructions`, `cyclomatic_complexity`, `pseudocode_lines`, `strongly_connected`, `loops`, and `instructions.func_id`. The exporter binds Python ints, so values are numeric.
- **TEXT affinity:** `name` (`varchar(255)`), `address`, `mnemonics`, `names`, `prototype2`, `primes_value`, `bytes_hash`, `pseudocode`, `pseudocode_hash1/2/3`, `pseudocode_primes` (but `pseudocode_lines` is INTEGER), `tarjan_topological_sort`, `strongly_connected_spp`, `switches`, `source_file`, and `instructions.disasm`/`mnemonic`. A Python int bound into a TEXT column is **stored as text**: `typeof` of int `0..100` inserted into a TEXT column gives `text`, verified.
- **TEXT column vs integer literal: TEXT affinity is applied to the literal.** `strongly_connected_spp > 1` (H44) is therefore `strongly_connected_spp > '1'`, a byte-wise comparison. Verified with SQLite 3.51.1:

```
s, s > 1, cast(s as integer) > 1
('02','text', 0, 1)  ('-3', 0, 0)  ('1a', 1, 0)  ('9', 1, 1)  ('10', 1, 1)  ('1.5', 1, 0)
('0', 0, ...) ('1', 0, ...) ('', 0, ...)  NULL -> NULL
```

  For canonical non-negative decimal strings, which is all the exporter writes (§6), this agrees with numeric `> 1`. For anything else it does not. **Implement it as text.** On the 7 real oracle exports, `typeof(strongly_connected_spp)` is `text` for every row, every value is canonical decimal, and the only values ≤ `'1'` are `'1'`. `'0'` (RecursionError) does not occur.
- TEXT = TEXT comparisons (`names`, `prototype2`, `switches`, `pseudocode_hash*`, `pseudocode_primes`, `tarjan_topological_sort`, `strongly_connected_spp` in H43, `mnemonics`) are plain byte equality and never numeric.

### 5.3 LIKE and prefixes

- `LIKE` is ASCII case-insensitive; there is no ICU and no `case_sensitive_like` pragma. Verified: `'NULLSUB_1' like 'nullsub%'` gives 1, `'Nullsubx' not like 'nullsub%'` gives 0, and `'ÄBC' like 'äbc'` gives 0.
- `substr(x,1,4)='sub_'` is **case-sensitive** (`substr('SUB_1',1,4)='sub_'` gives 0).
- `length(text)` counts characters. `length(12345)` gives 5.

### 5.4 Aggregates (H40, H41)

- `GROUP BY` on TEXT groups by exact bytes. NULL values form **one** group.
- `count(0)` counts rows, the same as `count(*)`.
- `GROUP_CONCAT(x)` uses the separator `,`, **skips NULLs** and still counts them in `count(0)`. It returns NULL if every value is NULL, and keeps empty strings (verified: groups `('a',NULL,'b')` give `'a,b'` with count 3, and `(NULL)` gives `NULL` with count 1).
- **Bare columns.** H40's `f.id, f.name` in a `HAVING count(0) = 1` group are unambiguous. H41's `inst.func_id` in `group by bb_id` is a bare column over a group that **can** span two functions (§6.3). SQLite documents the value as coming from an arbitrary row. Observed under the plan `SCAN bb USING COVERING INDEX idx_33`: the value comes from the **first** row of the group in `(basic_block_id, instruction_id)` order, i.e. the lowest `instruction_id` (`bb_probe.py`: block rows with func_ids `[2,1,3]` in id order gave `2`). This is **NOT DETERMINED FROM SOURCE**. **Real-export check:** the H41 CTE plan is `SCAN bb USING COVERING INDEX idx_33` on all 5 oracle pairs. On all 7 exports, every block's `GROUP BY` bare `func_id` equals the `func_id` of its lowest-`instruction_id` row, and every `GROUP_CONCAT` equals the ascending-`instruction_id` join. That includes the 11 (sechost) and 1 (userenv) blocks that span several functions (§6.3).
- **`GROUP_CONCAT` order in H41.** Under the same plan it is ascending `instruction_id` within the block, even when `bb_instructions` rows were inserted out of order (`bb_probe.py`: ids inserted as 3,1,2,4 gave `'a,b,c,x'`). Diaphora inserts instructions in block order (`diaphora.py:742-771`), so this is also the block's instruction order. This is plan-dependent, observed on two different datasets, and **NOT DETERMINED FROM SOURCE**.

### 5.5 DISTINCT

For two-table `functions × functions` queries (H30, H33-H39, H45-H48), `DISTINCT` never removes a row on exporter data, because `f.address` / `df.address` are UNIQUE, never NULL in an export, and selected. (`address text unique` would allow several NULL addresses, which DISTINCT would treat as equal. No export has one: 0 NULL addresses in all 7 oracle exports.) H40 has DISTINCT only inside `query1`, and H41 has no DISTINCT at all.

`distinct_probe.py` compared each query with its `select distinct` changed to `select`:

- Whenever the plan stayed the same apart from the `USE TEMP B-TREE FOR DISTINCT` step, the row order was identical. The DISTINCT step itself does not reorder rows.
- Removing DISTINCT **changed the chosen plan, and with it the row order**, for H30 and H45 on the dense dataset.

The keyword is therefore a no-op for the row **set**, but not for the planner. If the port takes row order from SQLite, it must keep the SQL verbatim.

### 5.6 Row order

- **No ORDER BY** (H29, H30, H31, H40, H41): the order is the query plan's nested-loop order, and the plan depends on the indices (`schema.INDICES`) and on `sqlite_stat1` (`create_indices` runs `analyze`, `diaphora.py:634-649`; called at export end, `diaphora_ida.py:1281`). **Observed plans differed between two synthetic datasets** for H29, H30, H31, H34, H36, H40, H41, H42, H45 and H47-H50; they were identical for H32, H33, H35, H37-H39, H43, H44 and H46. For example:
  - H29's outer loop was `df via idx_16 (loops>?)` in one dataset and `f via idx_7 (nodes>?)` in the other.
  - H40's outer loop was `SCAN f` in one dataset and `SCAN query1` in the other.
  - H41's outer loop was `f via idx_7` in one dataset and `SCAN diff_query` in the other.

  Row order is therefore **NOT DETERMINED FROM SOURCE**.
- **Plans on the real oracle exports** (SQLite 3.51.1, fresh connection plus `ATTACH`, which is what each Diaphora heuristic thread does via `get_db` → `open_db` + `attach_database`, `diaphora.py:584-593`, `651-659`). Pairs: `ls-old→ls`, `ls→ls-old`, `userenv-9168-pdb→9278-nopdb`, `userenv-9168-pdb→9278-pdb`, `sechost-9168-pdb→9444-nopdb`.
  - **One plan on all 5 pairs:** H30, H31, H36, H37-H39, H40, H41, H44.
  - **The plan differs between pairs** (outer and inner table swap, or a different index) for H29, H32 (3 plans), H33, H34 (3), H35 (3), H42, H43, H45, H46, H47, H48, H49 and H50. The direction of the pair alone changes the plan: H32, H33, H34, H35, H42, H43, H47, H48 and H50 each have different plans for `ls-old→ls` and `ls→ls-old`.
  - For example, H29 is `SEARCH df USING INDEX idx_16 (loops>?)` then `SEARCH f USING INDEX idx_7 (nodes=? AND edges=?)` on ls and userenv, but `SEARCH f USING INDEX idx_7 (nodes>?)` then `SEARCH df ... idx_7` on sechost.

  So on real data too, row order without ORDER BY (and among ties) depends on the data's `sqlite_stat1`. Only running the verbatim SQL reproduces it. Two row orders were observed under the single real-data plan of each: **H40** rows come out in ascending byte order of the lowest rare `disasm` string linking the pair (`query1` is driven by `main_asm`, whose `GROUP BY` sorter emits groups in BINARY `disasm` order). **H41** rows come out in ascending **diff** `basic_block_id` (outer `SCAN diff_query` over the materialized `diff_bblocks`, which is itself built by a `SCAN bb USING COVERING INDEX idx_33`). Both held on all 5 pairs. Both are plan-derived, **NOT DETERMINED FROM SOURCE**.
- **`ORDER BY f.source_file = df.source_file`** (H32-H39, H42, H44-H50) is **ascending**. The key is NULL when either side is NULL, 0 when they differ and 1 when they are equal, so the order is **NULL first, then 0, then 1**: same-compilation-unit pairs come **last**. Verified (`sem_probe.py`: `[(None,'a'),(None,None),('a','b'),('a','a'),('b','b')]`).
- **Tie order.** The ordered output equals a **stable** sort of the un-ordered (plan-order) output, verified on 200-row joins and on a 1.5 M-row sort far larger than the default sorter cache (whether it actually spilled to PMAs was not instrumented) (`tie_probe2.py`, `sort_stab.py`). On the real exports, dropping the ORDER BY left the join plan unchanged for H32-H39, H42, H44, H45 and H49 on every pair (and for H50 on 3 of 5). For each of those, the ordered output equalled a Python stable sort of the unordered output. For H46-H48 (and H50 on 2 pairs), dropping the ORDER BY **changes the join plan**, so the ORDER BY clause itself steers plan choice. Whether that stability holds for every sorter configuration is **NOT DETERMINED FROM SOURCE**; `vdbesort.c` was not audited.
- **H43** sorts `DESC` by a sum of 11 CASE terms (§H43), with ties in plan order.

---

## 6. Column and table encodings needed by H29-H50

References are to `diaphora_ida.py` unless marked `diaphora.py`. 04a §9 has the general table; this section covers only what the columns here need.

| Column | Encoding | NULL? |
|---|---|---|
| `nodes` | Count of processed FlowChart blocks (`accum['nodes'] += 1`, `2818`); blocks with `end_ea` 0/BADADDR are skipped | no |
| `edges` | +1 per successor **and** +1 per predecessor (`2897`, `2916`), so each edge is counted twice | no |
| `indegree` | `len(CodeRefsTo(f,1))` (`3072`) + 1 per successor edge (`2898`), i.e. "swapped" semantics | no |
| `outdegree` | Σ `len(CodeRefsFrom(head,0))` per instruction (`2737`) + 1 per predecessor edge (`2917`) | no |
| `cyclomatic_complexity` | `edges - nodes + 2` (`2966`), using the doubled edges | no |
| `size`, `instructions` | Σ decoded sizes / instruction count (`2845-2846`) | no |
| `strongly_connected` | `len(strongly_connected)` = **number of SCCs, singletons included** (`3167`); 0 after a RecursionError (`2624`) | no |
| `loops` | Number of SCCs with more than one node, plus singletons with a self-edge (`2630-2636`) | no |
| `strongly_connected_spp` | Starts at 1 and is multiplied by `primes[len(scc)]` for each SCC with more than one node (`2616-2620`). It stays at the initial 0 if `RecursionError` fires first (`2610`). Stored as TEXT: `'0'`, `'1'`, `'3'`, … Values above 0xFFFFFFFF are pre-stringified (`diaphora.py:724-725`). | no |
| `tarjan_topological_sort` | `json.dumps(robust_topological_sort(...))` (`2615`) | NULL on RecursionError (`2625`) |
| `names` | `json.dumps(sorted(set_of_referenced_names), ensure_ascii=False)` (`3010-3011`, `diaphora.py:936-939`). Names beginning with `sub_`/`nullsub_` are excluded (`2754-2759`). An empty set gives `'[]'`. | no |
| `mnemonics` | JSON list of mnemonics in block/instruction order (`2852`) | no |
| `prototype2` | `idc.get_type(f)` (`2968`), e.g. `'int()'` | **yes** |
| `primes_value` | `str(primes[cc])`, or int `0` → `'0'` (`2969-2973`) | no |
| `switches` | JSON `[[jtable_size, [case values…]], …]` (`2486-2509`), `'[]'` if none | no |
| `pseudocode_lines` | `len(pseudo lines)`, 0 without pseudocode (`2549`) | no |
| `pseudocode_hash1/2/3` | `kfh.hash_bytes(pseudo).split(";")`, where `""` becomes None (`2550-2558`). Base64 ASCII, at most 32 chars (`kfuzzy.py:60`, `166`). `hash1` = hash of `mix_blocks(pseudo)`, `hash2` = hash of `pseudo`, `hash3` = hash of reversed `pseudo` (`kfuzzy.py:280-290`). The heuristic **names do not match the data**: "(normal)" reads `hash1`, the *mixed* data; "(mixed)" reads `hash3`, the *reversed* data; "(reverse)" reads `hash2`, the *plain* data. **Follow the SQL columns, not the names.** In the real oracle exports these are NULL for **97-99.7%** of functions (for example sechost-9168: 1408 of 1442 NULL `hash1` and 1432 NULL `hash2`/`hash3`), because `kfh.bsize = 512` (`diaphora.py:392`). | **yes** |
| `pseudocode_primes` | `str(self.pseudo_hash[f])`, a big decimal integer (`2559`) | **yes** |
| `source_file` | Named compilation unit, or None (`3366-3382`) | **mostly** |
| `bytes_hash` | md5 hex (`2977`) | no |

### 6.1 Side table `instructions` (`schema.py:133-146`)

It holds **two kinds of rows**:

- **Native rows:** `asm_type='native'`, `mnemonic = print_insn_mnem(x)`, `disasm = GetDisasm(x)` (`diaphora.py:736-771`; `diaphora_ida.py:2646-2656`). `disasm` can be `''`.
- **Microcode rows:** `asm_type='microcode'`, `mnemonic` from `get_plain_microcode_line`, `disasm` = the plain microcode line (`diaphora.py:822-865`, `diaphora_ida.py:2191-2247`). They are inserted only when `mnemonic is not None` (`diaphora.py:850`), so microcode mnemonics are never NULL.

When microcode rows exist depends on the export path. The conditions:

- **All paths.** `get_microcode` returns `[], []` unless `self.decompiler_available and self.export_microcode` (`diaphora_ida.py:2263-2265`). `save_function_to_database` saves microcode only `if len(microcode_bblocks) > 0 and len(microcode_bbrelations) > 0` (`diaphora.py:914-918`). Native **and** microcode instruction and block rows are written only `if not self.function_summaries_only` (`diaphora.py:1001-1002`).
- **`BinDiffOptions` path.** This covers both the IDA dialog and `_diff_or_export(use_ui=False)`, which the oracle's `tools/oracle/diaphora_export.py` uses (09-oracle). `export_microcode` defaults to `total_functions <= MIN_FUNCTIONS_TO_CONSIDER_MEDIUM` (8001) (`diaphora_ida.py:3831-3832`). `func_summaries_only` defaults to `total_functions > 100000` (`:3821-3822`).
- **Headless `DIAPHORA_AUTO` path** (`diaphora_ida.py:4024-4070`, Diaphora's own tester). `export_microcode` keeps `CBinDiff`'s value `get_value_for("export_microcode", EXPORTING_USE_MICROCODE=True)` (`diaphora.py:479-481`) at **any** size. The later override reads the misspelled variable `DIAPHORA_SELF.EXPORT_MICROCODE` (`diaphora_ida.py:4061-4063`). `function_summaries_only` is `config.EXPORTING_FUNCTION_SUMMARIES_ONLY = False` unless `DIAPHORA_FUNCTION_SUMMARIES_ONLY` is set (`:4057-4059`). `use_decompiler` is False unless `DIAPHORA_USE_DECOMPILER` is set (`:4033-4035`). Whether `gen_microcode` works in that path without an earlier `init_hexrays_plugin()` is **NOT DETERMINED FROM SOURCE**.
- **Real oracle exports.** All 7 contain microcode rows. For example ls has 70,016 microcode and 16,227 native instructions; sechost-9168 has 367,026 and 113,095. None has NULL or `''` `mnemonic` / `disasm`.

With `function_summaries_only`, **no** instruction or basic-block rows exist, so H40 and H41 find nothing. **H40 and H41 do not filter on `asm_type`, so microcode rows count toward rarity and form mnemonic lists.**

### 6.2 Side table `bb_instructions` (`schema.py:156-159`)

It holds `(basic_block_id, instruction_id)` for native and microcode blocks alike. The index `idx_33` is on `(basic_block_id, instruction_id)` (`schema.py:57`). H41 does **not** read `basic_blocks` or `function_bblocks`.

### 6.3 Basic-block reuse

Native blocks are looked up by address before insertion, with no `asm_type` or function filter:

```python
      last_bb_id = self_get_bb_id(ins_ea)
      if last_bb_id is None:
        cur_execute(sql1, (num, str(ins_ea)))
        last_bb_id = cur.lastrowid
```

(`diaphora.py:792-795`; `get_bb_id` is `select id from basic_blocks where address = ?`, at `:701-717`.)

A native block whose RVA text already exists as some earlier `basic_blocks.address` **reuses that id**. Native keys are `block.start_ea - image_base` (`diaphora_ida.py:2821`, `2879`). Microcode blocks are inserted **without** a lookup, with `address` = the absolute `block.start` (`diaphora_ida.py:2247`; `diaphora.py:840-842`). Within one function the native blocks are saved before the microcode ones (`diaphora.py:907-918`). So a reused id needs one of two things:

- a shared native chunk (an earlier function's native block at the same RVA), or
- an earlier function's microcode block whose absolute start text equals this RVA. That needs the RVA range to overlap the absolute range (image base 0, or an image larger than its base) **and** an address shared between functions.

"Requires image base 0", as first written, was too narrow. The reused block's `bb_instructions` rows then belong to several functions, and this is the case where H41's bare `func_id` matters (§5.4).

**Measured on the real oracle exports:**

- Blocks spanning more than one `func_id`: ls 0, ls-old 0, each userenv export 1, each sechost export 11. One sechost block (`address '458843'`) is shared by 38 functions, with 418 `bb_instructions` rows.
- No block mixes `native` and `microcode` rows, so every observed reuse is a native shared chunk.
- The images have non-zero bases (ls `0x400000`, the DLLs `0x180000000`).
- In sechost-9168, 4 of the 11 shared main blocks have a unique mnemonic list, so they are H41 candidates.
- Blocks with a duplicated `address` text (32-54 per export) are microcode blocks, which are never looked up.

How often this happens on other corpora is **NOT DETERMINED**.

---

## 7. Partial heuristics H29-H42

"Runs by default?" assumes the Partial pass itself runs (§3.2 steps 1 and 5). "Row order" describes what the consumer sees (§5.6). Every "Output" line uses the §4.2 routing with the stated val.

### H29: Same nodes, edges, loops and strongly connected components (`diaphora_heuristics.py:699-719`)

```python
# The ORDER BY clause is removed because it was causing serious slowness problems
# with big and huge databases.
NAME = "Same nodes, edges, loops and strongly connected components"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""select """ + get_query_fields(NAME) + """
       from functions f,
            diff.functions df
      where f.nodes = df.nodes
        and f.edges = df.edges
        and f.strongly_connected = df.strongly_connected
        and f.loops = df.loops
        and f.nodes > 5 and df.nodes > 5
        and f.loops > 0
        and (substr(f.name, 1, 4) = 'sub_' or substr(df.name, 1, 4) == 'sub_')
        %POSTFIX% """,
  "min":0.549,
  "flags":[]
})
```

- **Metadata.** Partial, RATIO_MAX, min **0.549**, no flags, no DISTINCT, **no ORDER BY**.
- **Inputs.** `functions.nodes`, `edges`, `strongly_connected`, `loops` (INTEGER) and `name` (TEXT), for both sides.
- **Predicate:**
  ```
  EQ(f.nodes,df.nodes) && EQ(f.edges,df.edges) && EQ(f.strongly_connected,df.strongly_connected)
  && EQ(f.loops,df.loops) && GT(f.nodes,5) && GT(df.nodes,5) && GT(f.loops,0) && SUBEITHER
  ```
  A hash join on the key `(nodes, edges, strongly_connected, loops)`, prefiltered to `nodes > 5 && loops > 0`, is exact.
- **Row order:** plan order (§5.6; two different plans observed). **NOT DETERMINED FROM SOURCE.**
- **Output:** r == 1.0 goes to `best`, 0.549 ≤ r < 1 goes to `partial`, and anything else is dropped. The description is the name.
- **Runs by default?** **Yes.** No flags; position 11 of 11 in-scope (§3.3). Verified in `order_probe.py`.

### H30: Same low complexity, prototype and names (`diaphora_heuristics.py:721-740`)

```python
# The ORDER BY clause is removed because it was causing serious slowness problems
# with big and huge databases.
NAME = "Same low complexity, prototype and names"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""
       select distinct """ + get_query_fields(NAME) + """
         from functions f,
              diff.functions df
        where f.names = df.names
          and f.cyclomatic_complexity = df.cyclomatic_complexity
          and f.cyclomatic_complexity < 20
          and f.prototype2 = df.prototype2
          and df.names != '[]'
          %POSTFIX% """,
  "min":0.5,
  "flags":[]
})
```

- **Metadata.** Partial, RATIO_MAX, min 0.5, no flags. DISTINCT is a no-op here (§5.5). No ORDER BY.
- **Inputs.** `names` (TEXT JSON), `cyclomatic_complexity` (INTEGER), `prototype2` (TEXT, **nullable**).
- **Predicate:**
  ```
  EQ(f.names,df.names) && EQ(f.cc,df.cc) && LT(f.cc,20) && EQ(f.prototype2,df.prototype2) && NE(df.names,"[]")
  ```
  - There is **no `sub_` name condition and no node bound**.
  - A NULL `prototype2` on either side excludes the pair. On the real oracle exports only 1-21 functions per export have a NULL `prototype2`. By volume, the dominant NULL case is `pseudocode_hash1/2/3` (97-99.7% NULL, §6), which H33-H35 and H37-H39 compare, followed by `source_file` (the ORDER BY key).
- **Row order:** plan order. **NOT DETERMINED FROM SOURCE.**
- **Output:** min 0.5, so it behaves like RATIO.
- **Runs by default?** **Yes** (position 10).

### H31: Same low complexity and names (`diaphora_heuristics.py:742-758`)

```python
NAME = "Same low complexity and names"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""select """ + get_query_fields(NAME) + """
       from functions f,
            diff.functions df
      where f.names = df.names
        and f.cyclomatic_complexity = df.cyclomatic_complexity
        and f.cyclomatic_complexity < 15
        and df.names != '[]'
        and (substr(f.name, 1, 4) = 'sub_' or substr(df.name, 1, 4) == 'sub_')
        %POSTFIX% """,
  "min":0.5,
  "flags":[]
})
```

- **Metadata.** Partial, RATIO_MAX, min 0.5, no flags, no DISTINCT, no ORDER BY.
- **Inputs.** `names`, `cyclomatic_complexity`, `name`.
- **Predicate:** `EQ(f.names,df.names) && EQ(f.cc,df.cc) && LT(f.cc,15) && NE(df.names,"[]") && SUBEITHER`.
- **Row order:** plan order. **NOT DETERMINED FROM SOURCE.**
- **Output:** min 0.5.
- **Runs by default?** **Yes** (position 9).

### H32: Switch structures (`diaphora_heuristics.py:760-775`)

```python
NAME = "Switch structures"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""select """ + get_query_fields(NAME) + """
       from functions f,
            diff.functions df
      where f.switches = df.switches
        and df.switches != '[]'
        and f.nodes > 5 and df.nodes > 5
        %POSTFIX%
      order by f.source_file = df.source_file""",
  "min": 0.5,
  "flags":[]
})
```

- **Metadata.** Partial, RATIO_MAX, min 0.5, no flags, no DISTINCT, `ORDER BY f.source_file = df.source_file` ascending.
- **Inputs.** `switches` (TEXT JSON), `nodes`, `source_file`.
- **Predicate:** `EQ(f.switches,df.switches) && NE(df.switches,"[]") && GT(f.nodes,5) && GT(df.nodes,5)`. The JSON comparison is byte equality, so a differently ordered case-value list does not match.
- **Row order:** sort key `k = (nn(f.sf)&&nn(df.sf)) ? (f.sf==df.sf ? 1 : 0) : NULL`, ascending with NULL first. The sort is stable over plan order (§5.6).
- **Output:** min 0.5.
- **Runs by default?** **Yes** (position 8).

### H33: Pseudo-code fuzzy (normal) (`diaphora_heuristics.py:777-791`)

```python
NAME = "Pseudo-code fuzzy (normal)"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""select distinct """ + get_query_fields(NAME) + """
       from functions f,
            diff.functions df
      where df.pseudocode_hash1 = f.pseudocode_hash1
        and f.pseudocode_lines > 5 and df.pseudocode_lines > 5
        %POSTFIX%
      order by f.source_file = df.source_file""",
  "min": 0.5,
  "flags":[]
})
```

- **Metadata.** Partial, RATIO_MAX, min 0.5, no flags, DISTINCT (no-op), ORDER BY source_file equality ascending.
- **Inputs.** `pseudocode_hash1` (TEXT, **nullable**) and `pseudocode_lines` (INTEGER).
- **Predicate:** `EQ(f.pseudocode_hash1, df.pseudocode_hash1) && GT(f.pseudocode_lines,5) && GT(df.pseudocode_lines,5)`.
- **Row order:** source_file key ascending, stable over plan order.
- **Output:** min 0.5.
- **Runs by default?** **Yes** (position 7).
- **Note:** `hash1` is the mixed-blocks hash (§6).

### H34: Pseudo-code fuzzy (mixed) (`diaphora_heuristics.py:793-806`)

```python
NAME = "Pseudo-code fuzzy (mixed)"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO,
  "sql":"""select distinct """ + get_query_fields(NAME) + """
       from functions f,
            diff.functions df
      where df.pseudocode_hash3 = f.pseudocode_hash3
        and f.pseudocode_lines > 5 and df.pseudocode_lines > 5
        %POSTFIX%
      order by f.source_file = df.source_file""",
  "flags":[]
})
```

- **Metadata.** Partial, **RATIO** (no `min` key; val = 0.5), no flags, DISTINCT (no-op), ORDER BY source_file equality ascending.
- **Inputs.** `pseudocode_hash3` (nullable) and `pseudocode_lines`.
- **Predicate:** `EQ(f.pseudocode_hash3, df.pseudocode_hash3) && GT(f.pseudocode_lines,5) && GT(df.pseudocode_lines,5)`.
- **Row order:** as H33.
- **Output:** RATIO with val 0.5.
- **Runs by default?** **Yes** (position 6).
- **Note:** `hash3` is the reversed-data hash (§6).

### H35: Pseudo-code fuzzy (reverse) (`diaphora_heuristics.py:808-821`)

```python
NAME = "Pseudo-code fuzzy (reverse)"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO,
  "sql":"""select distinct """ + get_query_fields(NAME) + """
       from functions f,
            diff.functions df
      where df.pseudocode_hash2 = f.pseudocode_hash2
        and f.pseudocode_lines > 5 and df.pseudocode_lines > 5
        %POSTFIX%
      order by f.source_file = df.source_file""",
  "flags":[]
})
```

- **Metadata.** Partial, **RATIO** (val 0.5), no flags, DISTINCT (no-op), ORDER BY source_file equality ascending.
- **Inputs.** `pseudocode_hash2` (nullable) and `pseudocode_lines`.
- **Predicate:** `EQ(f.pseudocode_hash2, df.pseudocode_hash2) && GT(f.pseudocode_lines,5) && GT(df.pseudocode_lines,5)`.
- **Row order:** as H33.
- **Output:** RATIO with val 0.5.
- **Runs by default?** **Yes** (position 5).
- **Note:** `hash2` is the plain-data hash (§6).

### H36: Pseudo-code fuzzy AST hash (`diaphora_heuristics.py:823-838`)

```python
NAME = "Pseudo-code fuzzy AST hash"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""select distinct """ + get_query_fields(NAME) + """
       from functions f,
            diff.functions df
      where df.pseudocode_primes = f.pseudocode_primes
        and f.pseudocode_lines >= 3
        and length(f.pseudocode_primes) >= 35
        %POSTFIX%
      order by f.source_file = df.source_file""",
  "min": 0.35,
  "flags":[]
})
```

- **Metadata.** Partial, RATIO_MAX, min **0.35**, no flags, DISTINCT (no-op), ORDER BY source_file equality ascending.
- **Inputs.** `pseudocode_primes` (TEXT decimal, nullable) and `pseudocode_lines`.
- **Predicate:** `EQ(f.pseudocode_primes, df.pseudocode_primes) && GE(f.pseudocode_lines,3) && nn(f.pseudocode_primes) && charlen(f.pseudocode_primes) >= 35`.
  - Only the **main** side's line count is checked.
  - The length counts characters, which for the decimal digits the exporter writes is the byte length.
  - It is a TEXT comparison, so `'00123'` does not equal `'123'`. The exporter never writes leading zeros.
- **Row order:** as H33.
- **Output:** r == 1 goes to `best` and **0.35 ≤ r < 1 goes to `partial`**; below 0.5 still lands in partial (§4.2).
- **Runs by default?** **Yes** (position 4).

### H37: Partial pseudo-code fuzzy hash (normal) (`diaphora_heuristics.py:840-854`)

```python
NAME = "Partial pseudo-code fuzzy hash (normal)"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""  select distinct """ + get_query_fields(NAME) + """
         from functions f,
              diff.functions df
        where substr(df.pseudocode_hash1, 1, 16) = substr(f.pseudocode_hash1, 1, 16)
          and f.nodes > 5 and df.nodes > 5
          %POSTFIX%
        order by f.source_file = df.source_file""",
  "min":0.5,
  "flags":[HEUR_FLAG_SLOW, HEUR_FLAG_UNRELIABLE]
})
```

- **Metadata.** Partial, RATIO_MAX, min 0.5, **SLOW + UNRELIABLE**, DISTINCT (no-op), ORDER BY source_file equality ascending.
- **Inputs.** `pseudocode_hash1` (nullable) and `nodes`.
- **Predicate:** `nn(f.h1) && nn(df.h1) && SUBSTR16(f.h1) == SUBSTR16(df.h1) && GT(f.nodes,5) && GT(df.nodes,5)`.
  - A hash shorter than 16 characters compares whole, so `'short'` equals only `'short'`.
  - `''` would equal `''`, but the exporter never stores `''` (it converts it to NULL).
  - There is **no `pseudocode_lines` guard**, so treating NULL as `""` here would match every pseudocode-less pair with more than 5 nodes.
- **Row order:** as H33.
- **Output:** min 0.5.
- **Runs by default?** **No.** `HEUR_FLAG_UNRELIABLE in flags and not self.unreliable` → skip (`diaphora.py:1498-1500`). It runs only when `DIAPHORA_UNRELIABLE` is set to a non-empty string. Its position is then right after H40 (§3.3), or right after H41 when H40 is skipped for a processor mismatch. It also carries SLOW, which is satisfied by default.

### H38: Partial pseudo-code fuzzy hash (reverse) (`diaphora_heuristics.py:856-870`)

```python
NAME = "Partial pseudo-code fuzzy hash (reverse)"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""  select distinct """ + get_query_fields(NAME) + """
         from functions f,
              diff.functions df
        where substr(df.pseudocode_hash2, 1, 16) = substr(f.pseudocode_hash2, 1, 16)
          and f.nodes > 5 and df.nodes > 5
          %POSTFIX%
        order by f.source_file = df.source_file""",
  "min":0.5,
  "flags":[HEUR_FLAG_SLOW, HEUR_FLAG_UNRELIABLE]
})
```

- **Everything as H37**, with the column `pseudocode_hash2`.
- **Runs by default?** **No** (UNRELIABLE flag).

### H39: Partial pseudo-code fuzzy hash (mixed) (`diaphora_heuristics.py:872-886`)

```python
NAME = "Partial pseudo-code fuzzy hash (mixed)"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""  select distinct """ + get_query_fields(NAME) + """
         from functions f,
              diff.functions df
        where substr(df.pseudocode_hash3, 1, 16) = substr(f.pseudocode_hash3, 1, 16)
          and f.nodes > 5 and df.nodes > 5
          %POSTFIX%
        order by f.source_file = df.source_file""",
  "min":0.5,
  "flags":[HEUR_FLAG_SLOW, HEUR_FLAG_UNRELIABLE]
})
```

- **Everything as H37**, with the column `pseudocode_hash3`.
- **Runs by default?** **No** (UNRELIABLE flag).
- When enabled, the execution order is H39, H38, H37.

### H40: Same rare assembly instruction (`diaphora_heuristics.py:888-934`)

```python
NAME = "Same rare assembly instruction"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""
with main_asm as (
  select f.id, f.name, inst.disasm
    from main.instructions inst,
         main.functions f
   where f.id = inst.func_id
     and f.name not like 'nullsub%'
     and inst.disasm is not null
     and inst.disasm != ''
   group by inst.disasm
  having count(0) = 1
),
diff_asm as (
  select f.id, f.name, inst.disasm
    from diff.instructions inst,
         diff.functions f
   where f.id = inst.func_id
     and f.name not like 'nullsub%'
     and inst.disasm is not null
     and inst.disasm != ''
   group by inst.disasm
  having count(0) = 1
),
query1 as (
  select distinct main_asm.id main_func_id, diff_asm.id diff_func_id
    from main_asm,
         diff_asm
   where main_asm.disasm = diff_asm.disasm
)
select """ + get_query_fields(NAME) + """
  from main.functions f,
       diff.functions df,
       query1
 where f.id  = query1.main_func_id
   and df.id = query1.diff_func_id
   and f.name != df.name
   and ((min(f.nodes, df.nodes) * 100) / max(f.nodes, df.nodes)) < 50
   %POSTFIX%
""",
  "min":0.5,
  "flags":[HEUR_FLAG_SAME_CPU]
})
```

- **Metadata.** Partial, RATIO_MAX, min 0.5, **SAME_CPU**. DISTINCT only inside `query1`. No ORDER BY.
- **Inputs:**
  - `main.instructions(func_id, disasm)` and `diff.instructions(func_id, disasm)`, **all rows, native and microcode** (§6.1).
  - `functions.id`, `name`, `nodes` on both sides, plus the SELECT_FIELDS columns.
- **Porting spec:**
  ```
  rare(S):                                    // S = main or diff, computed independently
    cnt = map<bytes,int>; owner = map<bytes,int64>
    for r in S.instructions (every row, any asm_type):
        f = S.functions.by_id(r.func_id); if !f: continue          // inner join
        if !NOTNULLSUB(f.name): continue                            // NULL name excluded too
        if r.disasm is NULL or r.disasm == "": continue
        cnt[r.disasm] += 1; owner[r.disasm] = f.id                  // meaningful only when cnt == 1
    return { d -> owner[d] | cnt[d] == 1 }                          // exact byte key

  pairs = set{ (rare(main)[d], rare(diff)[d]) | d in keys(rare(main)) ∩ keys(rare(diff)) }   // DISTINCT
  for (a, b) in pairs:
      f = main.by_id(a); df = diff.by_id(b)
      if !(nn(f.name) && nn(df.name) && f.name != df.name): continue    // byte compare
      if !NR50(f.nodes, df.nodes): continue                              // 2*min < max
      [postfix]
      emit(f, df)
  ```
  - Rarity is counted per database over the join rows. A disasm string that occurs once in a normal function and again in a `nullsub*` function (case-insensitive) still counts as rare.
  - Instructions whose `func_id` has no `functions` row are ignored.
  - **`NR50` keeps only pairs whose node counts differ by more than 2x.** That looks like an inverted intent, but it is the behaviour. Do not "fix" it.
  - `f.name != df.name` removes same-named pairs.
  - Each `(f, df)` pair appears at most once.
- **Row order:** plan order. Two plans were observed on synthetic data: `SCAN f` + automatic index on `query1(main_func_id)`, and `SCAN query1` + rowid lookups. **NOT DETERMINED FROM SOURCE.** All 5 real oracle pairs use `SCAN query1` + rowid lookups, where `query1` is a co-routine driven by `SCAN main_asm` (a `GROUP BY` sorter). There, rows came out in ascending byte order of the lowest rare `disasm` string that links each pair (§5.6).
- **Output:** min 0.5.
- **Runs by default?** **Only if `is_same_processor`** (`diaphora.py:1506-1508`, `2950-2966`), at position 3. It ran in `order_probe.py`, where both processors were `'metapc64'`.

### H41: Same rare basic block mnemonics list (`diaphora_heuristics.py:936-979`)

```python
NAME = "Same rare basic block mnemonics list"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""
with main_bblocks as (
select inst.func_id, bb.basic_block_id bb_id, GROUP_CONCAT(inst.mnemonic) as mnemonics_list, count(0) inst_total
  from main.bb_instructions bb,
       main.instructions inst
 where bb.instruction_id = inst.id
 group by bb_id
),
diff_bblocks as (
select inst.func_id, bb.basic_block_id bb_id, GROUP_CONCAT(inst.mnemonic) as mnemonics_list, count(0) inst_total
  from diff.bb_instructions bb,
       diff.instructions inst
 where bb.instruction_id = inst.id
 group by bb_id
),
unique_main_bblocks as (
select func_id, mnemonics_list, count(0) total
  from main_bblocks
 group by mnemonics_list
having count(0) = 1
 order by total asc
)
select """ + get_query_fields(NAME) + """
  from unique_main_bblocks main_query,
       diff_bblocks diff_query,
       main.functions f,
       diff.functions df
 where main_query.mnemonics_list = diff_query.mnemonics_list
   and f.id = main_query.func_id
   and df.id = diff_query.func_id
   and f.nodes > 3
   and df.nodes > 3
   and diff_query.inst_total >= 6
   and ((min(f.nodes, df.nodes) * 100) / max(f.nodes, df.nodes)) < 50
   %POSTFIX%
""",
  "min":0.5,
  "flags":[]
})
```

- **Metadata.** Partial, RATIO_MAX, min 0.5, no flags. **No DISTINCT anywhere** in the final select. No outer ORDER BY. The `order by total asc` inside `unique_main_bblocks` cannot change the row **set**, because every `total` is 1. SQLite 3.51.1 still keeps it as a sort step (`USE TEMP B-TREE FOR ORDER BY` inside the co-routine), but in the real-data plan the outer query reaches `main_query` through an automatic index, so the sort does not decide the output order.
- **Inputs:**
  - `bb_instructions(basic_block_id, instruction_id)` and `instructions(id, func_id, mnemonic)` on both sides, **native and microcode** (§6.1-6.3).
  - `functions.id`, `nodes`, plus the SELECT_FIELDS columns.
  - The `nullsub` filter and the `basic_blocks` table are **not** used.
- **Porting spec:**
  ```
  blocks(S):                                   // one group per distinct basic_block_id
    rows = [ (bb.basic_block_id, bb.instruction_id, inst) for bb in S.bb_instructions
             if inst = S.instructions.by_id(bb.instruction_id) exists ]           // inner join
    group rows by basic_block_id                                  // a NULL block id would form one group
    for each group g, rows sorted by instruction_id ascending:    // OBSERVED plan order, §5.4
        g.func_id = first_row.inst.func_id                        // OBSERVED bare-column value, §5.4
        ms        = [inst.mnemonic for rows if inst.mnemonic is not NULL]   // '' kept
        g.list    = ms.empty() ? NULL : join(",", ms)
        g.total   = number of rows (NULL mnemonics included)

  M = blocks(main); D = blocks(diff)
  uniq = [ m in M | count of blocks in M whose list equals m.list (NULL==NULL for grouping) == 1 ]
  for m in uniq, for e in D:                                    // no DISTINCT: one row per block pair
      if m.list is NULL or e.list is NULL or m.list != e.list: continue
      f = main.by_id(m.func_id); df = diff.by_id(e.func_id); if !f or !df: continue
      if GT(f.nodes,3) && GT(df.nodes,3) && e.total >= 6 && NR50(f.nodes, df.nodes): emit(f, df)
  ```
  - Uniqueness is required **only on the main side**. A unique main block can match several diff blocks, including several blocks of the same `df`, which gives duplicate `(f, df)` rows. Duplicates are harmless downstream (§4.2) but still count toward the 1,000,000-row cap.
  - Only the **diff** block's instruction count is constrained (≥ 6).
  - Uniqueness is decided before joining `functions`. Blocks whose `func_id` has no function row still make other blocks non-unique.
  - The same inverted `NR50` rule as H40 applies: node counts must differ by more than 2x.
- **Row order:** plan order. Two plans were observed on synthetic data: outer `f via idx_7`, and outer `SCAN diff_query`. **NOT DETERMINED FROM SOURCE.** The `GROUP_CONCAT` order and the bare `func_id` are also plan-derived. Both are observed, not specified.
  - All 5 real oracle pairs use outer `SCAN diff_query` → `df` by rowid → `main_query` by automatic index on `mnemonics_list` → `f` by rowid. There, rows came out in ascending **diff** `basic_block_id`, with at most one row per diff block (§5.6).
  - Duplicate `(f,df)` rows occur on real data: 23 (ls-old→ls), 15 (ls→ls-old), 5 (each userenv pair). The port must feed them through (§4.2).
- **Output:** min 0.5.
- **Runs by default?** **Yes** (position 2).

### H42: Loop count (`diaphora_heuristics.py:981-996`)

```python
NAME = "Loop count"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""select """ + get_query_fields(NAME) + """
       from functions f,
            diff.functions df
      where f.loops = df.loops
        and df.loops > 1
        and f.nodes >= 3 and df.nodes >= 3
        %POSTFIX%
      order by f.source_file = df.source_file""",
  "min":0.49,
  "flags":[HEUR_FLAG_SLOW]
})
```

- **Metadata.** Partial, RATIO_MAX, min **0.49**, **SLOW**, no DISTINCT, ORDER BY source_file equality ascending.
- **Inputs.** `loops`, `nodes`, `source_file`.
- **Predicate:** `EQ(f.loops,df.loops) && GT(df.loops,1) && GE(f.nodes,3) && GE(df.nodes,3)`.
- **Row order:** source_file key ascending, stable over plan order.
- **Output:** r == 1 goes to `best` and **0.49 ≤ r < 1 goes to `partial`**.
- **Runs by default?** **Yes, and it runs first in the Partial pass.** SLOW is on in standalone whatever the size (§3.1).
- **This is the most cap- and timeout-exposed default-on heuristic here.** Every pair with the same loop count greater than 1 qualifies (§4.3). On the real oracle it yields 142 (ls), 365 (userenv) and 2,551 (sechost) rows, and it finishes in 0.1-2.4 s in the oracle logs.

---

## 8. Unreliable heuristics H43-H50 (none runs by default)

Common facts:

- **Runs by default? No, for all 8.** The whole pass needs `self.unreliable` (`diaphora.py:3638-3641`, default False). Short of editing `diaphora_config.py`, it is enabled only by `DIAPHORA_UNRELIABLE=<non-empty>`.
- **When enabled:**
  - The SLOW flag (H44-H49) is satisfied by default.
  - The execution order is H50, H49, H48, H47, H46, H45, H44, H43.
  - Routing moves down one tier (§4.2): r == 1.0 goes to `partial`, r ≥ val (0.5 for RATIO, or min) goes to `unreliable`, and anything else is dropped.
  - `find_brute_force` runs afterwards.

### H43: Same graph (`diaphora_heuristics.py:998-1031`)

```python
NAME = "Same graph"
HEURISTICS.append({
  "name":NAME,
  "category":"Unreliable",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":""" select """ + get_query_fields(NAME) + """
        from functions f,
             diff.functions df
       where f.nodes = df.nodes 
         and f.edges = df.edges
         and f.indegree = df.indegree
         and f.outdegree = df.outdegree
         and f.cyclomatic_complexity = df.cyclomatic_complexity
         and f.strongly_connected = df.strongly_connected
         and f.loops = df.loops
         and f.tarjan_topological_sort = df.tarjan_topological_sort
         and f.strongly_connected_spp = df.strongly_connected_spp
         and f.nodes > 5 and df.nodes > 5
         %POSTFIX%
       order by
             case when f.size = df.size then 1 else 0 end +
             case when f.instructions = df.instructions then 1 else 0 end +
             case when f.mnemonics = df.mnemonics then 1 else 0 end +
             case when f.names = df.names then 1 else 0 end +
             case when f.prototype2 = df.prototype2 then 1 else 0 end +
             case when f.primes_value = df.primes_value then 1 else 0 end +
             case when f.bytes_hash = df.bytes_hash then 1 else 0 end +
             case when f.pseudocode_hash1 = df.pseudocode_hash1 then 1 else 0 end +
             case when f.pseudocode_primes = df.pseudocode_primes then 1 else 0 end +
             case when f.pseudocode_hash2 = df.pseudocode_hash2 then 1 else 0 end +
             case when f.pseudocode_hash3 = df.pseudocode_hash3 then 1 else 0 end DESC""",
  "min":0.5,
  "flags":[]
})
```

- **Metadata.** Unreliable, RATIO_MAX, min 0.5, no flags, no DISTINCT, ORDER BY a score, **DESC**.
- **Inputs.**
  - WHERE: `nodes, edges, indegree, outdegree, cyclomatic_complexity, strongly_connected, loops` (INTEGER) and `tarjan_topological_sort, strongly_connected_spp` (TEXT). `tarjan_topological_sort` is nullable.
  - ORDER BY: `size, instructions` (INTEGER) and `mnemonics, names, prototype2, primes_value, bytes_hash, pseudocode_hash1, pseudocode_primes, pseudocode_hash2, pseudocode_hash3` (TEXT, several nullable).
- **Predicate:** the conjunction of `EQ` over the nine WHERE columns, with `strongly_connected_spp` as a **text** equality, plus `GT(f.nodes,5) && GT(df.nodes,5)`.
- **Row order:**
  ```
  score = Σ over [size, instructions, mnemonics, names, prototype2, primes_value, bytes_hash,
                  pseudocode_hash1, pseudocode_primes, pseudocode_hash2, pseudocode_hash3] of (EQ(f.c, df.c) ? 1 : 0)
  ```
  Rows are sorted by `score` descending, from 11 down to 0; `EQ` with a NULL counts 0. Ties are in plan order. Verified: `spec_check.py` checks that the SQL output is non-increasing in this score.
- **Output:** r == 1 goes to `partial`, 0.5 ≤ r < 1 goes to `unreliable`.
- **Runs by default?** **No.** It would run last in the Unreliable pass.

### H44: Strongly connected components (`diaphora_heuristics.py:1033-1054`)

```python
#
# Seems not to find anything?
#
NAME = "Strongly connected components"
HEURISTICS.append({
  "name":NAME,
  "category":"Unreliable",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""
     select """ + get_query_fields(NAME) + """
       from functions f,
            diff.functions df
      where f.strongly_connected = df.strongly_connected
        and df.strongly_connected > 1
        and f.nodes > 5 and df.nodes > 5
        and f.strongly_connected_spp > 1
        and df.strongly_connected_spp > 1
        %POSTFIX%
      order by f.source_file = df.source_file""",
  "min":0.8,
  "flags":[HEUR_FLAG_SLOW]
})
```

- **Metadata.** Unreliable, RATIO_MAX, min **0.8**, SLOW, no DISTINCT, ORDER BY source_file equality ascending.
- **Inputs.** `strongly_connected` (INTEGER, the number of SCCs), `strongly_connected_spp` (**TEXT**), `nodes`, `source_file`.
- **Predicate:** `EQ(f.sc,df.sc) && GT(df.sc,1) && GT(f.nodes,5) && GT(df.nodes,5) && TGT(f.spp,"1") && TGT(df.spp,"1")`.
  - The `spp` values are **not** compared with each other.
  - `TGT(x,"1")` is a byte comparison (§5.2). On exporter output it is true for every value except `'0'` and `'1'`, i.e. whenever at least one multi-node SCC exists.
- **Row order:** source_file key ascending, stable.
- **Output:** r == 1 goes to `partial`, 0.8 ≤ r < 1 goes to `unreliable`.
- **Runs by default?** **No.**

### H45: Nodes, edges, complexity and mnemonics (`diaphora_heuristics.py:1056-1075`)

```python
#
# Seems not to find anything?
#
NAME = "Nodes, edges, complexity and mnemonics"
HEURISTICS.append({
  "name":NAME,
  "category":"Unreliable",
  "ratio":HEUR_TYPE_RATIO,
  "sql":""" select distinct """ + get_query_fields(NAME) + """
        from functions f,
             diff.functions df
       where f.nodes = df.nodes
         and f.edges = df.edges
         and f.mnemonics = df.mnemonics
         and f.cyclomatic_complexity = df.cyclomatic_complexity
         and f.nodes > 1 and f.edges > 0
         %POSTFIX%
       order by f.source_file = df.source_file""",
  "flags":[HEUR_FLAG_SLOW]
})
```

- **Metadata.** Unreliable, RATIO (val 0.5), SLOW, DISTINCT (no-op), ORDER BY source_file equality ascending.
- **Inputs.** `nodes, edges, cyclomatic_complexity` (INTEGER) and `mnemonics` (TEXT JSON).
- **Predicate:** `EQ(nodes) && EQ(edges) && EQ(mnemonics) && EQ(cc) && GT(f.nodes,1) && GT(f.edges,0)`. The bounds apply to the main side only; equality makes them symmetric.
- **Row order:** source_file key ascending, stable.
- **Output:** r == 1 goes to `partial`, 0.5 ≤ r < 1 goes to `unreliable`.
- **Runs by default?** **No.**

### H46: Nodes, edges, complexity and prototype (`diaphora_heuristics.py:1077-1097`)

```python
#
# Seems not to find anything?
# Duplicate?
#
NAME = "Nodes, edges, complexity and prototype"
HEURISTICS.append({
  "name":NAME,
  "category":"Unreliable",
  "ratio":HEUR_TYPE_RATIO,
  "sql":""" select distinct """ + get_query_fields(NAME) + """
        from functions f,
             diff.functions df
       where f.nodes = df.nodes
         and f.edges = df.edges
         and f.prototype2 = df.prototype2
         and f.cyclomatic_complexity = df.cyclomatic_complexity
         and f.prototype2 != 'int()'
         %POSTFIX%
       order by f.source_file = df.source_file""",
  "flags":[HEUR_FLAG_SLOW]
})
```

- **Metadata.** Unreliable, RATIO (val 0.5), SLOW, DISTINCT (no-op), ORDER BY source_file equality ascending.
- **Inputs.** `nodes, edges, cyclomatic_complexity` and `prototype2` (nullable TEXT).
- **Predicate:** `EQ(nodes) && EQ(edges) && EQ(prototype2) && EQ(cc) && NE(f.prototype2,"int()")`.
  - There is **no size bound**, so single-block functions qualify.
  - NULL prototypes never match.
- **Row order:** source_file key ascending, stable.
- **Output:** as H45.
- **Runs by default?** **No.**

### H47: Nodes, edges, complexity, in-degree and out-degree (`diaphora_heuristics.py:1099-1119`)

```python
#
# Seems not to find anything?
#
NAME = "Nodes, edges, complexity, in-degree and out-degree"
HEURISTICS.append({
  "name":NAME,
  "category":"Unreliable",
  "ratio":HEUR_TYPE_RATIO,
  "sql":""" select distinct """ + get_query_fields(NAME) + """
        from functions f,
             diff.functions df
       where f.nodes = df.nodes
         and f.edges = df.edges
         and f.cyclomatic_complexity = df.cyclomatic_complexity
         and f.nodes >= 3 and f.edges > 2
         and f.indegree = df.indegree
         and f.outdegree = df.outdegree
         %POSTFIX%
       order by f.source_file = df.source_file""",
  "flags":[HEUR_FLAG_SLOW]
})
```

- **Metadata.** Unreliable, RATIO (val 0.5), SLOW, DISTINCT (no-op), ORDER BY source_file equality ascending.
- **Inputs.** `nodes, edges, cyclomatic_complexity, indegree, outdegree` (INTEGER; §6 explains the swapped degree semantics).
- **Predicate:** `EQ(nodes) && EQ(edges) && EQ(cc) && GE(f.nodes,3) && GT(f.edges,2) && EQ(indegree) && EQ(outdegree)`.
- **Row order:** source_file key ascending, stable.
- **Output:** as H45.
- **Runs by default?** **No.**

### H48: Nodes, edges and complexity (`diaphora_heuristics.py:1121-1139`)

```python
#
# Seems not to find anything?
#
NAME = "Nodes, edges and complexity"
HEURISTICS.append({
  "name":NAME,
  "category":"Unreliable",
  "ratio":HEUR_TYPE_RATIO,
  "sql":""" select distinct """ + get_query_fields(NAME) + """
        from functions f,
             diff.functions df
       where f.nodes = df.nodes
         and f.edges = df.edges
         and f.cyclomatic_complexity = df.cyclomatic_complexity
         and f.nodes > 1 and f.edges > 0
         %POSTFIX%
       order by f.source_file = df.source_file""",
  "flags":[HEUR_FLAG_SLOW]
})
```

- **Metadata.** Unreliable, RATIO (val 0.5), SLOW, DISTINCT (no-op), ORDER BY source_file equality ascending.
- **Predicate:** `EQ(nodes) && EQ(edges) && EQ(cc) && GT(f.nodes,1) && GT(f.edges,0)`.
  - Because `cc = edges - nodes + 2`, `EQ(cc)` is implied by equal nodes and edges. It is still evaluated, and it matters only for NULLs.
  - This is heavily cartesian (§4.3).
- **Row order:** source_file key ascending, stable.
- **Output:** as H45.
- **Runs by default?** **No.**

### H49: Same high complexity (`diaphora_heuristics.py:1141-1157`)

```python
#
# Seems not to find anything?
#
NAME = "Same high complexity"
HEURISTICS.append({
  "name":NAME,
  "category":"Unreliable",
  "ratio":HEUR_TYPE_RATIO,
  "sql":"""select """ + get_query_fields(NAME) + """
       from functions f,
            diff.functions df
      where f.cyclomatic_complexity = df.cyclomatic_complexity
        and f.cyclomatic_complexity >= 50
        %POSTFIX%
      order by f.source_file = df.source_file""",
  "flags":[HEUR_FLAG_SLOW]
})
```

- **Metadata.** Unreliable, RATIO (val 0.5), SLOW, no DISTINCT, ORDER BY source_file equality ascending.
- **Predicate:** `EQ(f.cc,df.cc) && GE(f.cc,50)`.
- **Row order:** source_file key ascending, stable.
- **Output:** as H45.
- **Runs by default?** **No.**

### H50: Topological sort hash (`diaphora_heuristics.py:1159-1177`)

```python
#
# Seems not to find anything?
#
NAME = "Topological sort hash"
HEURISTICS.append({
  "name":NAME,
  "category":"Unreliable",
  "ratio":HEUR_TYPE_RATIO,
  "sql":"""select """ + get_query_fields(NAME) + """
       from functions f,
            diff.functions df
      where f.strongly_connected = df.strongly_connected
        and f.tarjan_topological_sort = df.tarjan_topological_sort
        and f.strongly_connected >= 3
        and f.nodes > 10
        %POSTFIX%
      order by f.source_file = df.source_file""",
  "flags":[]
})
```

- **Metadata.** Unreliable, RATIO (val 0.5), **no flags**, no DISTINCT, ORDER BY source_file equality ascending.
- **Inputs.** `strongly_connected`, `tarjan_topological_sort` (TEXT JSON, nullable), `nodes` (main side only).
- **Predicate:** `EQ(sc) && EQ(tarjan_topological_sort) && GE(f.sc,3) && GT(f.nodes,10)`. `df.nodes` is not bounded.
- **Row order:** source_file key ascending, stable.
- **Output:** as H45. Verified in `unrel_probe.py`: r = 0.503 … 0.803 went to `unreliable`.
- **Runs by default?** **No.** When enabled, it runs **first** in the Unreliable pass.

---

## 9. Helpers at the end of the file (`diaphora_heuristics.py:1179-1323`)

Nothing here runs on import. `HEURISTICS` is **not** post-processed, normalized or validated at runtime. The only runtime transformations are in `run_heuristics_for_category`:

- copy with `list(HEURISTICS)`;
- the `get_heuristics` hook;
- the category filter;
- the flag filters;
- `%POSTFIX%`;
- the `on_launch_heuristic` hook.

The functions below are a developer self-test, run only by `python diaphora_heuristics.py` (`:1322-1323`).

| Function | Lines | What it checks | Port as |
|---|---|---|---|
| `check_categories` | 1180-1190 | prints the set of categories | unit test: exactly {Best, Partial, Unreliable} |
| `check_dupes` | 1193-1213 | counts names and prints duplicates. It never asserts on dupes; `assert "name" in dir(heur)` fires only when a name is missing, and `dir(dict)` never contains keys, so that assert always fails if reached | unit test: names unique |
| `check_heuristic_in_sql` | 1216-1241 | for every heuristic except `["Equal assembly or pseudo-code", "All or most attributes"]` (the latter no longer exists), asserts that the name occurs in the SQL (case-insensitive, via the `repr` description literal). It **prints but does not assert** when `%POSTFIX%` is missing. The message `f"...${NAME}"` prints a literal `$` plus the module-global `NAME`, i.e. the last definition, "Topological sort hash". | unit test: `description == name` for all but H11 |
| `check_heuristics_ratio` | 1244-1262 | `assert ratios == Counter({1: 22, 2: 22, 0: 5, 3: 1})` | unit test with the same numbers |
| `check_mandatory_fields` | 1265-1276 | keys `name, ratio, category, sql, flags` present | static table invariant |
| `check_field_names` | 1279-1301 | only the keys `name, ratio, category, min, sql, flags`, and every RATIO_MAX has `min`. Its assert uses `dir(heur)` and would always fail if reached; it is never reached. **RATIO_MAX_TRUSTED is not checked here**, but the runner reads `heur["min"]` for it (`diaphora.py:1494-1495`). H13 has it. | table invariant: RATIO_MAX and TRUSTED ⇒ min present |
| `run_tests` | 1304-1320 | runs the six checks in order and prints `All tests run OK!`, which is what the scratch copy printed | - |

`min` is read **only** for RATIO_MAX and RATIO_MAX_TRUSTED (`diaphora.py:1493-1495`). A `min` key on another type would be ignored; none exists.

---

## 10. Verification of this spec (the `spec_check.py` experiment)

- **Method.** `spec_check.py` implements every predicate above in plain Python, with no SQL: `EQ`, `TGT`, `SUBEITHER`, `NOTNULLSUB`, `SUBSTR16`, `NR50`, the H40 and H41 algorithms, and the order keys for H43 and source_file.
- **Data.** It generates randomized **adversarial** Diaphora-schema DB pairs with the real `INDICES` and `analyze`. They include:
  - NULLs in every nullable column, and NULL names and nodes;
  - `''` and `'[]'`;
  - `strongly_connected_spp` bound both as text and as int;
  - `pseudocode_primes` with 34, 35 and 40 digits, plus an int;
  - short hashes and hashes that share their first 16 characters;
  - `nullsub_`, `NullSub_`, `nullsubx`, `SUB_` and `sub_` names;
  - mixed native and microcode rows;
  - NULL and `''` mnemonics and disasm;
  - basic blocks shared across functions.
- **Comparison.** For each of H29-H50 it compares the `(ea, ea2)` multiset from SQLite 3.51.1 running the verbatim SQL with the spec's multiset. It also checks the ordering claims: the source_file key is non-decreasing, and the H43 score is non-increasing.
- **Results:**

| Run | Seeds | Mismatches | Coverage (rows compared, summed over seeds) |
|---|---|---|---|
| Sparse data (160 functions per side) | 22 | **0** | Every heuristic except H41 (2 rows) and H43 (0) had rows on most seeds. For example: H29 19, H30 780, H32 23,498, H36 29,721, H40 485, H42 40,978, H44 4,690, H47 20, H50 2,734. |
| Dense data (narrow value ranges) | 30 | **0** | **Every heuristic H29-H50 produced rows on all 30 seeds.** For example: H29 8,377, H40 749, H41 297, H42 185,076, H43 460, H44 98,152, H47 38,541. |

- **Negative controls.** H41 was re-run with the bare `func_id` taken from the *last* row, and with `GROUP_CONCAT` in *descending* id order. Both produce mismatches (2 of 30 seeds each), so the test does discriminate the observed behaviour. A separate probe showed that `s > 1` is **not** the same as numeric comparison (`'02'`, `'1a'`, `'1.5'`).
- **Limits.** Row order *within ties* and *without ORDER BY* was not compared, because it is plan-dependent (§5.6). The data is synthetic. (The original sentence here said that no real Diaphora export existed yet. That is outdated: the parity oracle, 09-oracle.md, has since produced real exports, and §10.1 runs the same check on them.)

### 10.1 Re-verification on the real oracle exports (added in the verification pass)

- **Data.** `<corpus>/oracle/exports/<id>/<id>.sqlite`: `ls`, `ls-old`, `userenv-9168-pdb`, `userenv-9278-nopdb`, `userenv-9278-pdb`, `sechost-9168-pdb` and `sechost-9444-nopdb`. They were made with IDA 9.4 idalib, Hex-Rays and Diaphora's own exporter (09-oracle). They were opened `?mode=ro&immutable=1`; their `-wal` files are empty, so nothing is missed and nothing is written. The pairs are the 5 oracle pairs, with db1 as `main` and db2 attached `as diff`.
- **Method.** `real_spec.py` (a scratch script of the verification pass) is an independent no-SQL implementation of this document's predicates: §2.4, the H40 `rare()` algorithm and the H41 `blocks()` algorithm with the first-row `func_id` and ascending-`instruction_id` `GROUP_CONCAT`. For every H29-H50 on every pair, it compared the `(ea, ea2)` multiset with SQLite 3.51.1 running the verbatim SQL (`%POSTFIX%` → `""`).
- **Result: 0 mismatches in 110 comparisons.** The ordering claims held on every pair: the source_file key is non-decreasing for the 16 ORDER BY heuristics, and the H43 score is non-increasing. The H41 multiset matched on sechost, whose 11 shared blocks exercise the bare-`func_id` rule.
- **Row counts:**

| Pair | H29 | H30 | H31 | H32 | H36 | H40 | H41 | H42 | H43 | H44 | H45 | H46 | H47 | H48 | H49 | H50 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| ls-old→ls | 13 | 35 | 40 | 3 | 28 | 123 | 84 | 142 | 18 | 117 | 54 | 209 | 51 | 904 | 3 | 12 |
| ls→ls-old | 13 | 35 | 40 | 3 | 28 | 123 | 64 | 142 | 18 | 117 | 54 | 209 | 51 | 904 | 3 | 12 |
| userenv 9168-pdb→9278-nopdb | 131 | 0 | 0 | 0 | 354 | 44 | 11 | 365 | 277 | 219 | 4,019 | 2,974 | 1,456 | 20,313 | 59 | 163 |
| userenv 9168-pdb→9278-pdb (dirty path; none run) | 0 | 518 | 0 | 0 | 720 | 38 | 11 | 365 | 279 | 219 | 4,841 | 3,530 | 1,462 | 22,940 | 59 | 165 |
| sechost 9168-pdb→9444-nopdb | 504 | 15 | 32 | 22 | 1,301 | 60 | 1 | 2,551 | 1,060 | 3,309 | 7,059 | 7,519 | 3,709 | 49,616 | 336 | 583 |

  H33-H35 and H37-H39 produce 0-4 rows on every pair, because their hash columns are almost always NULL.

---

## 11. Gap versus the current native code

**None of H29-H50 are implemented.** `src/Heuristics.cpp:299-310` (the `Definitions[]` table) lists **12** heuristics, none of them in this range: H1-H8 and H17-H20. (This first said 10, which was wrong.)

To implement them, the loader (`src/ExportDatabase.cpp:51-78`) needs:

- **New `functions` columns:** `names`, `prototype2`, `switches`, `pseudocode_hash1`, `pseudocode_hash2`, `pseudocode_hash3`, `pseudocode_primes`, `tarjan_topological_sort`, `strongly_connected_spp`, and `primes_value` (only for H43's ORDER BY).
- **Side tables:** `instructions(id, func_id, disasm, mnemonic)` including microcode rows, and `bb_instructions(basic_block_id, instruction_id)`.
- **A NULL flag** for every text and integer column used in a predicate. Today NULL becomes `""` / `0` (§5.1).
- Not specific to this range, but every H29-H50 row goes through `check_ratio` (03a), which reads `pseudocode` (`pseudo1`/`pseudo2`, only for the `is not None and != ""` test, `diaphora.py:1700-1705`). That column is not in the loader's `Columns[]` today.
- The loader reads only the first `program` row (`select processor, ... from program limit 1`, `src/ExportDatabase.cpp:277`). Diaphora's SAME_CPU test is true if **any** row pair matches (§3.2). Every export has exactly one `program` row, so this is only a theoretical difference.

`Match::Ratio` is a `float` (`include/dsigmatcher/Types.h`). Diaphora compares a Python **double** r against `0.549`, `0.35`, `0.49` and `0.8` with `>=`, and against `1.0` with `==`. Keep the ratio in `double` end to end. Otherwise values that sit exactly at a threshold after `deep_ratio`'s additions will round the wrong way (03a covers the arithmetic).

---

## Hard parts

1. **Row order.**
   - Tie order in H32-H39, H42-H50 and the whole order in H29-H31, H40 and H41 come from SQLite's plan. That plan changed between two synthetic datasets, and it also changes between the 5 **real** oracle pairs, even between the two directions of the same pair (§5.6).
   - Acceptance is order-dependent. `has_better_match` has a name clause, the last writer wins `matched_primary`, and the 1,000,000-row cap truncates by position.
   - The only exact reproduction is to ask SQLite, as 04a §6.6 recommends: execute the verbatim SQL on db1 with db2 attached `as diff`, using the same SQLite 3.51.1, and feed the rows to the C++ consumer.
   - A native hash join can reproduce the row **sets** exactly (§10), but not the order.
2. **NULL fidelity.** `prototype2`, `pseudocode_hash*`, `pseudocode_primes`, `tarjan_topological_sort` and `source_file` are routinely NULL. Collapsing NULL to `""` creates massive false candidate sets in H30, H33-H39, H43, H46 and H50, and breaks the source_file ORDER BY key, which has three values: NULL < 0 < 1.
3. **TEXT-affinity comparison** in H44 (`strongly_connected_spp > 1` compares as text against `'1'`), and TEXT equality of `strongly_connected_spp` in H43. Never parse these as numbers.
4. **H40 and H41 need the `instructions` and `bb_instructions` tables with microcode rows.** Rarity and uniqueness are counted over native **and** microcode rows in one pool. H40 excludes `nullsub*` names from counting, case-insensitively. H41 depends on plan-observed `GROUP_CONCAT` order and a plan-observed bare `func_id` whenever basic blocks are shared (§5.4, §6.3).
5. **Inverted node-ratio filter.** In H40 and H41, `NR50` keeps only pairs whose node counts differ by **more than 2x**, using integer division. Porting it as "similar size" silently changes results.
6. **Category is not the heuristic's category.** A Partial heuristic emits `best` when r == 1.0, and emits `partial` for r in [min, 0.5) when min < 0.5 (H36, H42). The documented "unreliable" tier never happens (§4.2). The Unreliable pass moves everything down one tier.
7. **Cartesian blow-up, the row cap and the timeout.** H42 (default-on and first in the pass), H32, H36, H33-H35 and H30-H31, and all of H45-H49 if enabled, could yield more than 1 M rows on large binaries. Diaphora then silently truncates at 1 M fetched rows, or at 300 s of wall-clock. The port must implement the same cap in the same order, and it must not materialize the full cartesian product in memory. On the current oracle corpora (≤ 1,442 functions) nothing comes close: the maxima are 2,551 rows default-on and 49,616 with Unreliable enabled, and there are no timeouts (§4.3, §10.1).
8. **The fuzzy-hash names lie.** "(normal)" uses `hash1`, which holds the mixed-blocks hash. "(mixed)" uses `hash3`, the reversed hash. "(reverse)" uses `hash2`, the plain hash. Bind to the SQL columns.
9. **Oracle configuration.**
   - On a same-named pair the default oracle takes the dirty patch-diff path, and then **none** of these heuristics run. This is confirmed for `userenv-9168-pdb_vs_9278-pdb` (100.0% same `mangled_function`). The other 4 oracle pairs take the normal path.
   - To compare heuristic behaviour, run the oracle with `DIAPHORA_EXPERIMENTAL=""` (verified to disable it) and keep a separate default-config oracle for end-to-end parity.
   - The numeric overrides `DIAPHORA_SQL_MAX_PROCESSED_ROWS` and `DIAPHORA_SQL_TIMEOUT_LIMIT` arrive as strings, and the int/str comparisons at `diaphora.py:1878` and `1894` then raise `TypeError` (§3.1). To change those limits, patch a copy of the config instead.

## Open questions

Each question has a status. Resolutions come from the verification pass, which ran against the real oracle exports in `<corpus>/oracle` (§10.1).

1. **Real-export query plans: PARTLY RESOLVED.**
   - The plans that SQLite 3.51.1 picks on the 5 real oracle pairs are recorded in §5.6. They differ between pairs for 13 of the 22 heuristics, including between the two directions of the ls pair. Row order without ORDER BY (and among ties) is therefore data-dependent on real exports too, and only running the verbatim SQL reproduces it.
   - Under the single real-data plans, H40 emits rows in ascending byte order of the linking rare `disasm`, and H41 in ascending diff `basic_block_id`. Both are observations, **NOT DETERMINED FROM SOURCE**.
   - Whether the Linux and macOS CI runners pick the same plans stays **NOT DETERMINED**. It depends on their SQLite version, and nothing in this repo pins it to 3.51.1. It matters only if the port takes row order from its own SQLite.
2. **`win32u` and `search_patchdiff_with_symbols`: RESOLVED FOR THE ORACLE; NOT DETERMINED FOR win32u.**
   - The oracle has no `win32u` export (09-oracle lists ls, userenv and sechost), so the `win32u` question itself is **NOT DETERMINED**.
   - On the oracle, `userenv-9168-pdb_vs_9278-pdb` does take the dirty patch-diff path (log: `643 matches out of 643, 100.0%`), and none of H29-H50 run there.
   - `ls-old→ls` (37.50%), `ls→ls-old` (35.85%), `userenv 9168-pdb→9278-nopdb` (9.33%) and `sechost 9168-pdb→9444-nopdb` (15.81%) do not. On those pairs the default oracle exercises H29-H36, H40, H41 and H42.
3. **Shared basic blocks: RESOLVED FOR THE ORACLE.**
   - Blocks spanning several `func_id`s: 0 in ls and ls-old, 1 in each userenv export, 11 in each sechost export (one shared by 38 functions). All are native shared chunks. No block mixes native and microcode rows, and the images have non-zero bases.
   - On all 7 exports the bare `func_id` is the lowest-`instruction_id` row's `func_id`, and `GROUP_CONCAT` is in ascending `instruction_id`, for every block. The H41 multiset matched the spec on every pair.
   - The general rule stays **NOT DETERMINED FROM SOURCE** (§5.4).
4. **Sorter stability: STILL NOT DETERMINED FROM SOURCE.** `vdbesort.c` was not audited. New evidence: on the real exports the ORDER BY output equalled a stable sort of the plan-order output in every case where dropping the ORDER BY kept the same join plan (§5.6).
5. **Timeout and row-cap exposure: RESOLVED FOR THE CURRENT CORPORA.**
   - Largest in-scope row count: 2,551 default-on (H42, sechost) and 49,616 with Unreliable on (H48, sechost). Both are far below 1,000,000.
   - The default-on in-scope heuristics finish in 0.7-4.7 s in total in the oracle logs.
   - No oracle log contains `Timeout`, and no in-scope heuristic logs `Processed 50000 rows`.
   - No patched-config oracle is needed for these corpora. The question comes back for any corpus that is much larger.
6. **Microcode availability: RESOLVED FOR THE ORACLE.**
   - All 7 oracle exports contain microcode rows, 3-5 times as many as native rows. The oracle's `_diff_or_export(use_ui=False)` path enables microcode for ≤ 8001 functions (§6.1), and every oracle binary has ≤ 1,442 functions. H40 and H41 therefore count microcode rows in the oracle.
   - An oracle binary with more than 8001 functions would export no microcode through that path. The headless `DIAPHORA_AUTO` path would still export it. Fixtures from either path are valid, but they are not interchangeable.

---

## Verification log

The verification pass checked every quoted excerpt mechanically. Every heuristic code block in §7 and §8, and every other excerpt from `diaphora_heuristics.py`, `diaphora.py` and `jkutils/threads.py`, was located verbatim at the cited lines (22 of 22 heuristic blocks, 11 of 11 other excerpts). The 2 excerpts added in this pass, `add_match` and the timeout check, were checked the same way. The inventory table (lines, names, categories, ratio types, `min`, flags) was regenerated from a copy of the module and matches in every row. The counts Best 12 / Partial 30 / Unreliable 8 and RATIO 22 / RATIO_MAX 22 / NO_FPS 5 / TRUSTED 1 were confirmed, and `python diaphora_heuristics.py` on a copy prints `All tests run OK!`. The SQLite semantics claims in §2.4 and §5.1-5.4 were re-run on SQLite 3.51.1 and all reproduce.

Corrections and additions:

1. **§11: wrong count.** `src/Heuristics.cpp:299-310` lists **12** implemented heuristics (H1-H8, H17-H20), not 10.
2. **§4.2: missing behaviour.** `add_match` forces `ratio = 1.0` when `name1 == name2` (`diaphora.py:1350-1351`). That changes what `matched_primary` / `matched_secondary` store and skips the `has_better_match` re-check. Added, with a verbatim excerpt.
3. **§4.2: overstated claim.** Duplicate `(f,df)` rows were called "idempotent". They add no second chooser item, but they re-run `check_match` / `add_match` and rewrite `matched_primary` / `matched_secondary` (last writer wins). The port must not deduplicate them.
4. **§4.3: imprecise timeout.** There are two clocks. `self.timeout` (env-overridable) runs from after `cur.execute`. The thread flag uses `config.SQL_TIMEOUT_LIMIT` and runs from before `t.start()`. The check runs only between fetches, so a long `execute` or `fetchone` is not interruptible.
5. **§4.3: wrong log signal.** `Processed 1000000 rows` is logged when `i` reaches 1,000,000, before the fetch, so it appears for results of ≥ 999,999 rows. It is necessary but not sufficient for truncation.
6. **§6.1: incomplete conditions for microcode and instruction rows.** Added the `len(microcode_bblocks) > 0 and len(microcode_bbrelations) > 0` gate (`diaphora.py:915`) and the `function_summaries_only` gate (`:1001`). The "≤ 8001" and "> 100,000" defaults belong to `BinDiffOptions` only. The headless `DIAPHORA_AUTO` path keeps `EXPORTING_USE_MICROCODE=True` at any size, and its override reads the misspelled `DIAPHORA_SELF.EXPORT_MICROCODE`.
7. **§6.3: too-narrow collision condition.** "Requires image base 0" was replaced by the actual condition: overlapping RVA and absolute ranges **and** a shared address. Added measured shared-block counts.
8. **Summary: outdated guess.** "`win32u` probably triggers" the dirty path was replaced by oracle facts (userenv pdb/pdb confirmed; the other 4 pairs not). `win32u` itself has no export.
9. **Summary: overstated claim.** "Ten in-scope Partial heuristics run unconditionally" now names the ten and states the conditions (the Partial pass runs; H42 needs `slow_heuristics`, which defaults to True).
10. **§10: outdated claim.** "No real Diaphora export exists yet" was superseded. Added §10.1, a no-SQL spec vs. SQLite comparison on the 5 real oracle pairs: 0 mismatches in 110 comparisons.
11. **§5.6: new material.** Added the real-export plan table. Added the observed H40 and H41 row-order rules. Added the observation that dropping ORDER BY changes the join plan for H46-H48, which is also added to §5.6 tie order.
12. **§5.4: new material.** Added the real-export confirmation of the first-row bare `func_id` and ascending-`instruction_id` `GROUP_CONCAT`.
13. **§5.5: precision.** DISTINCT is a row-set no-op only because addresses are non-NULL in exports; `UNIQUE` allows several NULLs.
14. **§5.2: precision.** "`pseudocode*`" wrongly implied that `pseudocode_lines` is TEXT; it is INTEGER. Added the real-export `strongly_connected_spp` facts (all text, canonical, no `'0'`).
15. **§3.2 step 4: precision.** The `"64"` suffix depends on IDA's `BADADDR` width. The real exports store `'pc64'`, so H40 runs on every oracle pair.
16. **§3.2 step 6: missing path.** `DIAPHORA_PROJECT_SCRIPT` can load hooks (`diaphora.py:421`, `3607-3610`).
17. **§7 H30: unsupported claim.** "Most important NULL case" was replaced with measured NULL rates. `pseudocode_hash*` is 97-99.7% NULL on real exports, which dominates H33-H35 and H37-H39.
18. **§7 H37: missing branch.** Its position falls after H41 when H40 is skipped for a processor mismatch.
19. **§7 H41: precision.** The inner `order by total asc` is kept in the plan but does not decide the output order. Added the real duplicate-row counts.
20. **§7 H42, §4.3, Hard parts 7 and 9: new material.** Added the measured row counts and timings. "Can yield more than 1 M rows on real binaries" was softened to "could, on large binaries", and the measured maxima were added.
21. **§11: new material.** Added the loader's missing `pseudocode` column (needed by `check_ratio`) and the `program ... limit 1` note.
22. **Open questions.** Each question was re-answered with a status, as above.

Items confirmed correct with no change: the ratio routing and the dead "unreliable" branch (`diaphora.py:1922-1946`); reverse serial execution (`threads.py:39-41`); the flag gates (`:1497-1508`); `%POSTFIX%` handling and its discarded hook return; the `get_value_for` string pitfalls; every §6 exporter line reference checked (`diaphora_ida.py` 2540-2566, 2607-2644, 2754-2759, 2818, 2845-2852, 2897-2917, 2966-2977, 3010-3011, 3072, 3167, 3356-3382, 3400-3405, 3798-3800, 3828-3832); the `kfuzzy.py` hash assignment (`:280-290`); the §9 helper descriptions; and the §2.4 NR50 arithmetic.
