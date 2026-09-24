# DSigMatcher fusion inventory

> **Status: planned, not started.** Fusion is a planned optimisation for after v1.0. **No fusion
> work has started**, and nothing described below is in v1.0.0: the v1.0.0 engine runs each of
> Diaphora's heuristic queries unchanged, one at a time, exactly as Diaphora does. This inventory
> was produced by a pre-release review on 2026-09-23. It measures where the ported engine spends
> its time on the two long reference pairs and lists what any fusion would have to preserve, above
> all Diaphora's row order. File and line citations refer to the reviewed snapshot and may have
> moved since. Measurements and scratch files it mentions were made on the review machine and
> are not part of the repository.

**What this is:** the list to come back to when fusion is approved. It is documentation only. No engine code, test, or tracked file was changed, and fusion was not started.

- **Reviewed snapshot:** `<review-snapshot>` (a checkout of the merged `parity` branch, before the v1.0.0 release work), using the prebuilt `build/dsigmatcher.exe` and `build/diff_tiers.exe`.
- **Date:** 2026-09-23. Scratch: `<scratch>/fusion` (a private working directory; not published).
- **Citations:** `D:` = diaphora.py, `H:` = diaphora_heuristics.py, `C:` = diaphora_config.py (Diaphora 3.4.2-4-g621ec26). Every other file:line is in the reviewed snapshot.
- **Abbreviations:** U = userenv-9168-pdb_vs_9278-nopdb, S = sechost-9168-pdb_vs_9444-nopdb.

---

## 0. Summary

1. **"Fusion" as the maintainer notes (not published) describe it is not where the time goes.** Those notes say the three text-keyed joins take about 69% of heuristic time. That figure comes from the old legacy engine. The measured phases of the parity engine are these:

   | phase | U (77.0 s wall) | S (476.2 s wall) |
   |---|---:|---:|
   | related compilation unit | 63.8 s (83%) | 266.3 s (56%) |
   | SQL heuristics | 6.6 s (9%) | 194.6 s (41%) |
   | callee diffing | 4.1 s (5%) | 10.6 s (2%) |

2. **On S, three constants joins cost 186 s: H21 55 s, H20 83 s and H15 48 s.** That is 95% of all heuristic time. The join itself is cheap. Almost all of the cost comes from SQLite building the 44-column `SELECT_FIELDS` row for every joined row:
   - Those rows include `pseudocode`, `assembly` and the `clean_*` texts, stored in overflow pages.
   - H15 returns 30,710 rows for only 498 distinct pairs.
   - H20 builds 30,080 rows in a DISTINCT temp B-tree to return 273.
   - With the output cut to `(f.address, df.address)`, the same three queries take 0.17 s in total, keep the same plan, and return the identical `(ea, ea2)` sequence on both pairs.
   - The consumer never reads those text columns (`Database.cpp:524-661` reads only ea, name, description, nodes and md). The ratio reads the ingested tables instead.
3. **Related compilation unit is the other big cost.** It is a workload that repeats itself:
   - U iteration 0: 581 seeds produce 180.8 M candidate rows, but only 7 distinct CU range pairs. One pair (334,080 rows) is replayed 541 times.
   - S iteration 0: 1,714 seeds produce about 708.8 M rows over only 60 range pairs. One pair (737,817 rows) is replayed 959 times.
   - Each row goes through `check_match` with the live state, so the rows cannot simply be deduplicated. §9 lists what would have to be proven first.
4. **Row order depends on the query plan, and the plans change between pairs.**
   - 27 of the 50 heuristic plans differ between U and S (23 of the 39 that run by default). Usually the driving table (f or df) or the driving index swaps, because each export has its own `sqlite_stat1`.
   - So "shares a join key" never means "same row order". A fused generator must rebuild each heuristic's own nested-loop order from its plan, behind a plan guard.
   - Cutting the output columns alone changed the row sequence of H2, H10, H35 and H44 on at least one pair. The causes are an AUTOMATIC covering index, a UNION that dedupes on the whole row, and plan changes.
5. **11 of the 50 heuristics never run in the parity engine**: H36-H38 (flag UNRELIABLE) and H42-H49 (the Unreliable tier). The engine only runs the default configuration: `Config.h:55-58`, `Pipeline.cpp:582`, `--unreliable` refused with exit 4. These heuristics need no fusion work.
6. **Findings outside fusion** (§10):
   - Transient SQLite errors such as SQLITE_FULL become silent heuristic truncations with exit 0.
   - Disk C: was at 54 MB to 4.3 GB free throughout this review. The fat constants joins spill temp B-trees there, and my own sechost timing query failed with `database or disk is full`.
   - The binary reports version 0.1.0.

---

## 1. How the costs were measured

| what | method | files (scratch) |
|---|---|---|
| native per-heuristic / per-pass wall time | prebuilt `dsigmatcher.exe diff` on scratch copies with `--snapshot-dir`. Each snapshot's mtime is the moment its point was reached, so the interval `before:X` → next point is stage X. U used every point, S used `before:*` plus a few `after:` points. Snapshot writes cost about 5 ms each. | `snap-userenv/stage_times.{txt,json}`, `snap-sechost/stage_times.{txt,json}`, `stage_times.py`, `phase_sums.py` |
| confirm the timed runs are real | U results and unmatched rows are identical to the oracle's `.diaphora` (2180 + 50 rows) for both timed U runs. S has no oracle yet, so its output was not checked. | `run-userenv/`, `snap-userenv/native.diaphora` |
| SQL alone | Python `sqlite3` 3.51.1 (the oracle's library) on immutable copies, full fetch of the verbatim SQL with `%POSTFIX%` = "". U is the min of 2 runs. S H0-H21 are 1 run. S H22-H49 come from `slim_check.py`'s full-query timing (1 run, `temp_store=memory`), because the first S run died with `database or disk is full` at H22. | `sql_timing.py`, `sql-userenv.json`, `sql-sechost.json`, `merge_sechost.py` |
| plans | `EXPLAIN QUERY PLAN` of every heuristic and stage SQL on both pairs | `plans.json`, `stage_plans.py` |
| projection probe (idea only) | the same SQL with the outer `SELECT_FIELDS` replaced by `f.address ea, df.address ea2`. Compares plan text and the exact `(ea, ea2)` row sequence. | `slim_check.py`, `slim-userenv.json`, `slim-sechost.json` |
| related-CU workload | seeds from the snapshot at the D:3413 cleanup: exact for U (the `after:cleanup` snapshot), approximate for S (the `before:cleanup` snapshot). Diaphora's own CU lookup SQL, rows per seed = the product of the two range sizes. | `cu_seeds.py` |
| constants duplicates | the raw join of H15/H20/H21 with the output cut and DISTINCT dropped, compared with the distinct `(ea, ea2)` pairs | `const_dups.py` |
| key signatures | `build/diff_tiers.exe` output (the heuristic tiers' `DataTouched` descriptor, `TiersDetail.h`, `HeuristicTiers.cpp:187-927`). 51/51 queries matched SQLite's authorizer. | `diff_tiers_out.txt` |

The machine was loaded throughout: 4 long oracle Python jobs, other `dsigmatcher` runs, and 32 logical CPUs. Treat any value below about 0.3 s as noise. For example, U H1 shows 0.258 s native for 5 rows, and the snapshot gap right after it was 0.129 s. `--trace` is not usable for timing: on U it wrote a 1.76 GB JSONL file and stretched the run from 77 s to 180 s.

---

## 2. Where the time goes (native, per phase)

| phase | code | U s | U % | S s | S % |
|---|---|---:|---:|---:|---:|
| startup + ingest + find_equal_matches | `Pipeline.cpp:497-532`, `EqualMatches.cpp:41` | ~0.10 | 0.1 | 0.38 | 0.1 |
| apply_dirty_heuristics | `DirtyHeuristics.cpp:111` | 0.02 | 0.0 | 0.32 | 0.1 |
| find_same_name | `SameName.cpp:36` | 0.01 | 0.0 | 0.03 | 0.0 |
| **SQL heuristics, Best + Partial (39 runnable)** | `HeuristicTiers.cpp:93-165` | **6.59** | 8.6 | **194.65** | 40.9 |
| category cleanups (L1551) | `HeuristicTiers.cpp:114` | 0.04 | 0.1 | 0.35 | 0.1 |
| search_small_differences | `SmallDifferences.cpp:183-235` | 0.07 | 0.1 | 0.17 | 0.0 |
| callee diffing (all iterations) | `CalleeDiffing.cpp:352` | 4.11 | 5.4 | 10.63 | 2.2 |
| related constants (all iterations) | `RelatedConstants.cpp:147` | 1.26 | 1.6 | 1.95 | 0.4 |
| **related compilation unit (all iterations)** | `RelatedCompilationUnit.cpp:276` | **63.81** | 83.4 | **266.31** | 56.0 |
| local affinity | `LocalAffinity.cpp:253` | 0.30 | 0.4 | 1.03 | 0.2 |
| loop cleanups L3655/L3671 | `Pipeline.cpp:585-605` | 0.24 | 0.3 | 0.15 | 0.0 |
| final_pass | `FinalPass.cpp:86` | 0.06 | 0.1 | 0.09 | 0.0 |
| **wall total** |  | **76.97** |  | **476.15** |  |

The convergence loop ran 2 iterations on U and 3 on S. Related-CU time per iteration was 28.6 s and 35.1 s on U, and 85.1 s, 86.9 s and 94.2 s on S. S final results: best 518, partial 718, multimatch 4580, exit 0.

---

## 3. Order constraints that every fused design must keep

These rules apply to every group in §7. Parity is row for row, so each one is a proof obligation.

1. **Heuristic order.**
   - `RunnableHeuristics` builds the list in HEURISTICS order, applying the category, flag and all_functions_matched filters (`HeuristicTiers.cpp:50-88`).
   - The list then runs **backwards, one heuristic at a time** (`HeuristicTiers.cpp:101-113`). Best runs 11→0. Partial runs 41, 40, 39, 35→12.
   - Each heuristic sees the state left by the one before it. A cleanup follows each category (`:114`).
   - Candidate generation may be fused or precomputed. Consumption must stay serial in exactly this order.
2. **Lazy execution gate.**
   - `all_functions_matched()` is checked when the list is built (`HeuristicTiers.cpp:59`) and again at the start of every wrapper, **before** the SQL runs (`Consumer.cpp:204, 238, 249, 258`).
   - A precomputed or fused generator must not show any effect of a heuristic that would have been skipped, including an error its SQL would have raised.
3. **Row order within a heuristic comes from SQLite's plan** (`02-matching.md:13, 1461`).
   - The plans depend on each export's `sqlite_stat1` and indexes (`idx_0`..`idx_40`, created by the exporter). They differ between U and S for 27 of the 50 heuristics (§5, "plan text differs").
   - A nested loop emits rows in the order of the outer driving index (for example `idx_7 (nodes, edges, cyclomatic_complexity)` then rowid), then in the inner index order.
   - Every generator needs a plan guard, as `CuReplayPlanOk` already does (`RelatedCompilationUnit.cpp:249-271`). It falls back to Path A when the plan text is not the expected one.
4. **The row-shaping operators each have their own rules.**
   - DISTINCT keeps the **first occurrence in scan order**.
   - `ORDER BY f.source_file = df.source_file` (32 heuristics) is a **stable partition relative to the ORDER BY query's own plan**. Adding the ORDER BY changes the plan, so "stable sort of the unordered output" is wrong (`04a-heuristics-best.md:815-819`).
   - UNION (H10) sorts and dedupes by the **whole row, including the description**, so the same pair can appear once per arm (`02-matching.md:1116`).
   - An **AUTOMATIC (covering) index** breaks ties inside a key by the index's column list. That list depends on which columns the query reads. Measured on H35 (U and S): its sequence changed when only the output columns changed. Heuristics with an AUTOMATIC index on at least one pair: H6, H18, H35, H39, H40. H2 and H44 (S) changed sequence through a plan change instead.
5. **Consumer semantics make duplicate rows significant.**
   - At 1.0 the first accepted row wins, because later rows fail `has_best_match` (`Consumer.cpp:99`).
   - `matched_primary` / `matched_secondary` are **last-writer-wins**, including on duplicate items (`MatchState.cpp:201-204`).
   - `has_better_match` reads the live dicts (`MatchState.cpp:140-160`).
   - H15 and H21 have no DISTINCT and return each `(f, df)` pair many times (S: H15 30,710 rows for 498 pairs, H21 58,236 rows for 9,129 pairs). Every duplicate must be replayed at its original position, because an equal-ratio duplicate can rewrite a dict entry back.
6. **Row cap and error position.**
   - RATIO* consumers stop after 1,000,000 **fetched** rows, rejected rows included (`Consumer.cpp:140-146`). NO_FPS has no cap.
   - An error (fetch-time invalid UTF-8, or a step error) truncates the heuristic at that row. Earlier matches are kept, and the category continues (`HeuristicTiers.cpp:153-163`). NO_FPS swallows the error (`Consumer.cpp:229-233`).
   - `search_small_differences` reproduces `fetchmany(1000)` batch-loss semantics (`SmallDifferences.cpp:51-160`).
   - A generator must report the exact raw row index at which an error would occur.
7. **Ratio cache: first writer wins, and the md source depends on the path.**
   - `check_ratio` from SQL rows uses `md = cast(md_index as real)` evaluated by SQLite. `compare_function_rows` (callee diffing, local affinity) uses Python `float()` of the text (`Ratio.cpp:808-822`).
   - Both paths store into one cache keyed by `(ea1, ea2)`, and the first writer wins (`Ratio.cpp:547-557, 794-795`; 03a §8).
   - Computing ratios speculatively, ahead of time or in parallel, can change the cached values. Precompute only from the same path that would have stored first, or keep the value computed off-path out of the cache.
8. **Cleanup points are fixed.**
   - The call sites are L1551 (end of each tier), L3655/L3671 (loop head and tail), L3217/L3185 (callee), L3471 (related constants), L3413 (related CU), L3340 (affinity) and L2945 (final).
   - Cleanup sorts stably by ratio, descending. It dedupes by the name-pair string, first wins, and drops only an item whose `ea1` already has a **strictly** greater ratio (`MatchState.cpp:226-274`, `02-matching.md:1211-1223`).
   - A fused pass must not move work across any of these points.
9. **Stage-local rules.**
   - Related-CU seeds are a snapshot of sorted best then partial. The loop breaks at the first ratio below 0.8, with no deduplication (`RelatedCompilationUnit.cpp:284-300`).
   - Related constants iterate a set whose order is the documented set-order deviation (06 §8.3; `RelatedConstants.cpp:9-12, 121-135`).
   - Callee diffing keeps a `dones` set per call, and its snapshot sorts are taken per category (`CalleeDiffing.cpp:305-348`).
   - Local affinity sorts by Python `int()` of addresses. Its gap queries use `address desc` with a bytewise TEXT compare (`LocalAffinity.cpp:253-293, 138-153`).
10. **Configuration.**
    - With `--ignore-small-functions`, `%POSTFIX%` becomes `and f.instructions > 5 and df.instructions > 5` (`Config.h:30-31, 51`), in every heuristic (twice in H10). That changes the plans too.
    - The SAME_CPU heuristics (0, 1, 2, 3, 5, 6, 9, 39) run only when the two `program.processor` values are equal (`HeuristicTiers.cpp:78`). That holds on both measured pairs.

---

## 4. The 50 heuristics: summary

The native times are the per-heuristic wall times of the real run. They include the row consumer: check_match, the ratio and add_match. The SQL times are the query alone. A `-` means the heuristic does not run.

| H | name | tier / type (min) | default run | flags | ORDER BY / DISTINCT / UNION / CTE | rows U | rows S | SQL s U | SQL s S | native s U | native s S |
|---:|---|---|---|---|---|---:|---:|---:|---:|---:|---:|
| 0 | Same RVA and hash | Best / NoFps | yes if same CPU | SAME_CPU | - | 1 | 121 | 0.000 | 0.015 | 0.007 | 0.179 |
| 1 | Same order and hash | Best / NoFps | yes if same CPU | SAME_CPU | - | 5 | 31 | 0.002 | 0.016 | 0.258 | 0.037 |
| 2 | Function Hash | Best / NoFps | yes if same CPU | SAME_CPU | DISTINCT | 48 | 237 | 0.004 | 0.037 | 0.013 | 0.066 |
| 3 | Bytes hash | Best / NoFps | yes if same CPU | SAME_CPU | DISTINCT | 52 | 257 | 0.003 | 0.023 | 0.011 | 0.053 |
| 4 | Same address and mnemonics | Best / Ratio | yes | - | ORDER BY, DISTINCT | 13 | 742 | 0.002 | 0.344 | 0.009 | 0.652 |
| 5 | Same cleaned assembly | Best / Ratio | yes if same CPU | SAME_CPU | ORDER BY | 19 | 94 | 0.006 | 0.043 | 0.016 | 0.478 |
| 6 | Same cleaned microcode | Best / Ratio | yes if same CPU | SAME_CPU | ORDER BY | 117 | 332 | 0.044 | 0.594 | 0.078 | 0.298 |
| 7 | Same cleaned pseudo-code | Best / Ratio | yes | - | ORDER BY | 21 | 168 | 0.006 | 0.050 | 0.017 | 0.229 |
| 8 | Same address, nodes, edges and mnemonics | Best / Ratio | yes | - | ORDER BY | 9 | 666 | 0.004 | 0.276 | 0.010 | 0.130 |
| 9 | Same RVA | Best / RatioMax 0.7 | yes if same CPU | SAME_CPU | ORDER BY, DISTINCT | 19 | 644 | 0.004 | 0.304 | 0.009 | 0.339 |
| 10 | Equal assembly or pseudo-code | Best / NoFps | yes | - | UNION | 23 | 185 | 0.017 | 0.212 | 0.032 | 0.112 |
| 11 | Microcode mnemonics small primes product | Best / Ratio | yes | - | ORDER BY | 558 | 1871 | 0.042 | 0.812 | 0.062 | 0.213 |
| 12 | Same named compilation unit function match | Partial / RatioMaxTrusted 0.44 | yes | - | - | 1685 | 4787 | 0.033 | 0.152 | 0.054 | 0.189 |
| 13 | Same anonymous compilation unit function match | Partial / RatioMax 0.449 | yes | - | ORDER BY | 66 | 429 | 0.007 | 0.068 | 0.024 | 0.112 |
| 14 | Same compilation unit | Partial / Ratio | yes | SLOW | - | 0 | 103 | 2.308 | 0.043 | 4.022 | 0.084 |
| 15 | Same KOKA hash and constants | Partial / Ratio | yes | - | - | 929 | 30710 | 0.031 | 56.566 | 0.049 | 47.859 |
| 16 | Same KOKA hash and MD-Index | Partial / Ratio | yes | - | - | 350 | 1159 | 0.018 | 0.091 | 0.036 | 0.112 |
| 17 | Same constants | Partial / RatioMax 0.5 | yes | - | ORDER BY | 211 | 510 | 0.023 | 0.123 | 0.046 | 0.120 |
| 18 | Same rare KOKA hash | Partial / RatioMax 0.45 | yes | - | CTE | 220 | 559 | 0.012 | 0.078 | 0.034 | 0.081 |
| 19 | Same rare MD Index | Partial / Ratio | yes | - | ORDER BY, CTE | 129 | 453 | 0.019 | 0.153 | 0.040 | 0.146 |
| 20 | Same address and rare constant | Partial / RatioMax 0.5 | yes | - | ORDER BY, DISTINCT | 2 | 273 | 0.000 | 82.574 | 0.010 | 82.634 |
| 21 | Same rare constant | Partial / RatioMax 0.2 | yes | SLOW | - | 5869 | 58236 | 0.202 | 62.305 | 0.243 | 55.276 |
| 22 | Same MD Index and constants | Partial / Ratio | yes | - | ORDER BY, DISTINCT | 461 | 1622 | 0.068 | 0.126 | 0.093 | 0.406 |
| 23 | Import names hash | Partial / Ratio | yes | - | ORDER BY, DISTINCT | 0 | 3 | 0.001 | 0.011 | 0.080 | 0.034 |
| 24 | Mnemonics and names | Partial / Ratio | yes | - | ORDER BY | 0 | 23 | 0.001 | 0.012 | 0.008 | 0.038 |
| 25 | Pseudo-code fuzzy hash | Partial / Ratio | yes | - | ORDER BY, DISTINCT | 0 | 0 | 0.000 | 0.006 | 0.008 | 0.029 |
| 26 | Similar pseudo-code and names | Partial / RatioMax 0.579 | yes | - | ORDER BY, DISTINCT | 0 | 24 | 0.001 | 0.012 | 0.014 | 0.038 |
| 27 | Mnemonics small-primes-product | Partial / RatioMax 0.6 | yes | - | - | 763 | 2083 | 0.021 | 0.089 | 0.037 | 0.116 |
| 28 | Same nodes, edges, loops and strongly connected components | Partial / RatioMax 0.549 | yes | - | - | 131 | 504 | 0.007 | 0.039 | 0.018 | 0.136 |
| 29 | Same low complexity, prototype and names | Partial / RatioMax 0.5 | yes | - | DISTINCT | 0 | 15 | 0.001 | 0.009 | 0.009 | 0.032 |
| 30 | Same low complexity and names | Partial / RatioMax 0.5 | yes | - | - | 0 | 32 | 0.001 | 0.007 | 0.009 | 0.023 |
| 31 | Switch structures | Partial / RatioMax 0.5 | yes | - | ORDER BY | 0 | 22 | 0.002 | 0.126 | 0.006 | 0.154 |
| 32 | Pseudo-code fuzzy (normal) | Partial / RatioMax 0.5 | yes | - | ORDER BY, DISTINCT | 0 | 0 | 0.000 | 0.005 | 0.006 | 0.148 |
| 33 | Pseudo-code fuzzy (mixed) | Partial / Ratio | yes | - | ORDER BY, DISTINCT | 0 | 0 | 0.073 | 0.005 | 0.087 | 0.115 |
| 34 | Pseudo-code fuzzy (reverse) | Partial / Ratio | yes | - | ORDER BY, DISTINCT | 0 | 0 | 0.073 | 0.005 | 0.090 | 0.021 |
| 35 | Pseudo-code fuzzy AST hash | Partial / RatioMax 0.35 | yes | - | ORDER BY, DISTINCT | 354 | 1301 | 0.058 | 0.141 | 0.092 | 0.526 |
| 36 | Partial pseudo-code fuzzy hash (normal) | Partial / RatioMax 0.5 | no (FLAG unreliable, C:46) | SLOW, UNRELIABLE | ORDER BY, DISTINCT | 0 | 3 | 0.011 | 2.070 | - | - |
| 37 | Partial pseudo-code fuzzy hash (reverse) | Partial / RatioMax 0.5 | no (FLAG unreliable, C:46) | SLOW, UNRELIABLE | ORDER BY, DISTINCT | 0 | 0 | 0.011 | 2.077 | - | - |
| 38 | Partial pseudo-code fuzzy hash (mixed) | Partial / RatioMax 0.5 | no (FLAG unreliable, C:46) | SLOW, UNRELIABLE | ORDER BY, DISTINCT | 0 | 1 | 0.011 | 1.970 | - | - |
| 39 | Same rare assembly instruction | Partial / RatioMax 0.5 | yes if same CPU | SAME_CPU | CTE | 44 | 60 | 0.712 | 1.400 | 0.348 | 1.587 |
| 40 | Same rare basic block mnemonics list | Partial / RatioMax 0.5 | yes | - | CTE | 11 | 1 | 0.091 | 0.451 | 0.139 | 0.666 |
| 41 | Loop count | Partial / RatioMax 0.49 | yes | SLOW | ORDER BY | 365 | 2551 | 0.050 | 0.304 | 0.064 | 1.177 |
| 42 | Same graph | Unreliable / RatioMax 0.5 | no (Unreliable tier not run, D:3638-3651) | - | ORDER BY | 277 | 1060 | 0.036 | 0.090 | - | - |
| 43 | Strongly connected components | Unreliable / RatioMax 0.8 | no (Unreliable tier not run, D:3638-3651) | SLOW | ORDER BY | 219 | 3309 | 0.027 | 0.168 | - | - |
| 44 | Nodes, edges, complexity and mnemonics | Unreliable / Ratio | no (Unreliable tier not run, D:3638-3651) | SLOW | ORDER BY, DISTINCT | 4019 | 7059 | 0.370 | 0.218 | - | - |
| 45 | Nodes, edges, complexity and prototype | Unreliable / Ratio | no (Unreliable tier not run, D:3638-3651) | SLOW | ORDER BY, DISTINCT | 2974 | 7519 | 0.168 | 0.297 | - | - |
| 46 | Nodes, edges, complexity, in-degree and out-degree | Unreliable / Ratio | no (Unreliable tier not run, D:3638-3651) | SLOW | ORDER BY, DISTINCT | 1456 | 3709 | 0.157 | 0.230 | - | - |
| 47 | Nodes, edges and complexity | Unreliable / Ratio | no (Unreliable tier not run, D:3638-3651) | SLOW | ORDER BY, DISTINCT | 20313 | 49616 | 1.684 | 1.580 | - | - |
| 48 | Same high complexity | Unreliable / Ratio | no (Unreliable tier not run, D:3638-3651) | SLOW | ORDER BY | 59 | 336 | 0.015 | 0.051 | - | - |
| 49 | Topological sort hash | Unreliable / Ratio | no (Unreliable tier not run, D:3638-3651) | - | ORDER BY | 163 | 583 | 0.029 | 0.088 | - | - |

**Reading the table:**

- **rows** is the raw row count of the verbatim SQL, before the consumer.
- **Runs by default:** H36-H38 and H42-H49 never run (§0 item 5).
- **SAME_CPU heuristics** ran on both pairs, because both are x64.
- **Fetched columns:** every heuristic fetches the same `SELECT_FIELDS`: 22 columns per side (address, name, pseudocode, assembly, pseudocode_primes, nodes, md_index, clean_assembly, clean_pseudo, mangled_function, clean_microcode, bytes_hash, edges, indegree, outdegree, instructions, cyclomatic_complexity, strongly_connected, loops, constants_count, size, kgh_hash) plus the description literal (`Database.cpp:467-477`). The consumer reads only `ea, name1, ea2, name2, description, nodes1/2, md1/2` (`Database.cpp:549-557`).
- **Ratio:** it uses the ingested `FunctionTable` (`Ingest.cpp:405`), never the SQL row.


---

## 5. Per-heuristic detail: (a) to (f)

Each block is generated by `gen_tables.py` from the verbatim SQL, the `diff_tiers` descriptor, the plans and the measurements. It lists (a) the tables and the columns beyond SELECT_FIELDS, (b) the equi-join keys, (c) the other predicates (ranges, LIKE, rarity CTEs; every heuristic also ends with `%POSTFIX%`, "" by default, §3.10), (d) whether it runs by default and where it sits in the execution order, (e) the measured cost, and (f) the order facts. The last line is the projection probe (an idea, §9 I-1).

#### H0 Same RVA and hash

- source: `src/diff/RegistrySql.inc:6` (H:89-107), Best / NoFps, flags "[3]"; descriptor `[2 tables, 48 columns]`
- (a) tables: diff.functions, main.functions. columns: SELECT_FIELDS (22 per side, all materialised per row) + non-SELECT_FIELDS columns df.{rva,segment_rva}; f.{rva,segment_rva}
- (b) equi-join keys: `f.bytes_hash=df.bytes_hash & f.instructions=df.instructions`
- (c) other predicates: `(df.rva = f.rva or df.segment_rva = f.segment_rva)`; `((f.name = df.name and substr(f.name, 1, 4) != 'sub_') or (substr(f.name, 1, 4) = 'sub_' or substr(df.name, 1, 4) = 'sub_'))`; `f.nodes >= 3`; `df.nodes >= 3`
- (d) default config: yes if same CPU; Best tier, position 12 of 12 (runs 11→0)
- (e) cost: userenv 1 rows, SQL 0.000 s, native 0.007 s; sechost 121 rows, SQL 0.015 s, native 0.179 s
- (f) order: row order = plan order; U: `SEARCH df USING INDEX idx_7 (nodes>?) | SEARCH f USING INDEX idx_0 (bytes_hash=?)`; S: `SEARCH f USING INDEX idx_7 (nodes>?) | SEARCH df USING INDEX idx_0 (bytes_hash=?)` (plan text differs from U); NO_FPS: no row cap, every error swallowed after the rows consumed so far (Consumer.cpp:202-234)
- idea probe (projection cut to ea, ea2): U plan same, (ea,ea2) sequence same, 0.003→0.000 s; S plan same, (ea,ea2) sequence same, 0.011→0.005 s

#### H1 Same order and hash

- source: `src/diff/RegistrySql.inc:58` (H:109-127), Best / NoFps, flags "[3]"; descriptor `[2 tables, 46 columns]`
- (a) tables: diff.functions, main.functions. columns: SELECT_FIELDS (22 per side, all materialised per row) + non-SELECT_FIELDS columns df.{id}; f.{id}
- (b) equi-join keys: `f.bytes_hash=df.bytes_hash & f.id=df.id & f.instructions=df.instructions`
- (c) other predicates: `((f.name = df.name and substr(f.name, 1, 4) != 'sub_') or (substr(f.name, 1, 4) = 'sub_' or substr(df.name, 1, 4) = 'sub_'))`; `((f.nodes > 1 and df.nodes > 1 and f.instructions > 5 and df.instructions > 5) or f.instructions > 10 and df.instructions > 10)`
- (d) default config: yes if same CPU; Best tier, position 11 of 12 (runs 11→0)
- (e) cost: userenv 5 rows, SQL 0.002 s, native 0.258 s; sechost 31 rows, SQL 0.016 s, native 0.037 s
- (f) order: row order = plan order; U: `MULTI-INDEX OR | INDEX 1 | SEARCH df USING INDEX idx_6 (instructions>?) | INDEX 2 | SEARCH df USING INDEX idx_6 (instructions>?) | SEARCH f USING INTEGER PRIMARY KEY (rowid=?)`; S: `MULTI-INDEX OR | INDEX 1 | SEARCH f USING INDEX idx_7 (nodes>?) | INDEX 2 | SEARCH f USING INDEX idx_6 (instructions>?) | SEARCH df USING INTEGER PRIMARY KEY (rowid=?)` (plan text differs from U); NO_FPS: no row cap, every error swallowed after the rows consumed so far (Consumer.cpp:202-234)
- idea probe (projection cut to ea, ea2): U plan same, (ea,ea2) sequence same, 0.005→0.002 s; S plan same, (ea,ea2) sequence same, 0.012→0.011 s

#### H2 Function Hash

- source: `src/diff/RegistrySql.inc:110` (H:129-143), Best / NoFps, flags "[3]"; descriptor `[2 tables, 46 columns, DISTINCT]`
- (a) tables: diff.functions, main.functions. columns: SELECT_FIELDS (22 per side, all materialised per row) + non-SELECT_FIELDS columns df.{function_hash}; f.{function_hash}
- (b) equi-join keys: `f.function_hash=df.function_hash`
- (c) other predicates: `((f.nodes > 1 and df.nodes > 1 and f.instructions > 5 and df.instructions > 5) or f.instructions > 10 and df.instructions > 10)`
- (d) default config: yes if same CPU; Best tier, position 10 of 12 (runs 11→0)
- (e) cost: userenv 48 rows, SQL 0.004 s, native 0.013 s; sechost 237 rows, SQL 0.037 s, native 0.066 s
- (f) order: row order = plan order; U: `MULTI-INDEX OR | INDEX 1 | SEARCH df USING INDEX idx_7 (nodes>?) | INDEX 2 | SEARCH df USING INDEX idx_6 (instructions>?) | SEARCH f USING INDEX idx_23 (function_hash=?) | USE TEMP B-TREE FOR DISTINCT`; S: `MULTI-INDEX OR | INDEX 1 | SEARCH f USING INDEX idx_7 (nodes>?) | INDEX 2 | SEARCH f USING INDEX idx_6 (instructions>?) | SEARCH df USING INDEX idx_23 (function_hash=?) | USE TEMP B-TREE FOR DISTINCT` (plan text differs from U); DISTINCT keeps the first occurrence in scan order; NO_FPS: no row cap, every error swallowed after the rows consumed so far (Consumer.cpp:202-234)
- idea probe (projection cut to ea, ea2): U plan same, (ea,ea2) sequence same, 0.009→0.006 s; S plan CHANGED, (ea,ea2) sequence DIFFERENT, 0.025→0.016 s

#### H3 Bytes hash

- source: `src/diff/RegistrySql.inc:158` (H:145-157), Best / NoFps, flags "[3]"; descriptor `[2 tables, 44 columns, DISTINCT]`
- (a) tables: diff.functions, main.functions. columns: SELECT_FIELDS (22 per side, all materialised per row) + non-SELECT_FIELDS columns -
- (b) equi-join keys: `f.bytes_hash=df.bytes_hash`
- (c) other predicates: `f.instructions > 5`; `df.instructions > 5`
- (d) default config: yes if same CPU; Best tier, position 9 of 12 (runs 11→0)
- (e) cost: userenv 52 rows, SQL 0.003 s, native 0.011 s; sechost 257 rows, SQL 0.023 s, native 0.053 s
- (f) order: row order = plan order; U: `SEARCH df USING INDEX idx_6 (instructions>?) | SEARCH f USING INDEX idx_0 (bytes_hash=?) | USE TEMP B-TREE FOR DISTINCT`; S: `SEARCH f USING INDEX idx_6 (instructions>?) | SEARCH df USING INDEX idx_0 (bytes_hash=?) | USE TEMP B-TREE FOR DISTINCT` (plan text differs from U); DISTINCT keeps the first occurrence in scan order; NO_FPS: no row cap, every error swallowed after the rows consumed so far (Consumer.cpp:202-234)
- idea probe (projection cut to ea, ea2): U plan same, (ea,ea2) sequence same, 0.004→0.002 s; S plan same, (ea,ea2) sequence same, 0.022→0.008 s

#### H4 Same address and mnemonics

- source: `src/diff/RegistrySql.inc:204` (H:159-176), Best / Ratio, flags "[]"; descriptor `[2 tables, 48 columns, DISTINCT, ORDER BY]`
- (a) tables: diff.functions, main.functions. columns: SELECT_FIELDS (22 per side, all materialised per row) + non-SELECT_FIELDS columns df.{mnemonics,source_file}; f.{mnemonics,source_file}
- (b) equi-join keys: `f.address=df.address & f.instructions=df.instructions & f.mnemonics=df.mnemonics`
- (c) other predicates: `df.instructions > 5`; `((f.name = df.name and substr(f.name, 1, 4) != 'sub_') or (substr(f.name, 1, 4) = 'sub_' or substr(df.name, 1, 4) = 'sub_'))`
- (d) default config: yes; Best tier, position 8 of 12 (runs 11→0)
- (e) cost: userenv 13 rows, SQL 0.002 s, native 0.009 s; sechost 742 rows, SQL 0.344 s, native 0.652 s
- (f) order: row order = plan order; U: `SEARCH df USING INDEX idx_6 (instructions>?) | SEARCH f USING INDEX idx_28 (address=?) | USE TEMP B-TREE FOR DISTINCT | USE TEMP B-TREE FOR ORDER BY`; S: `SEARCH f USING INDEX idx_6 (instructions>?) | SEARCH df USING INDEX idx_28 (address=?) | USE TEMP B-TREE FOR DISTINCT | USE TEMP B-TREE FOR ORDER BY` (plan text differs from U); DISTINCT keeps the first occurrence in scan order; ORDER BY is a stable partition relative to the ORDER BY query's own plan (02-matching.md:1444, 04a:815-819); Ratio: 1,000,000 fetched-row cap counting rejected rows; an error truncates the heuristic at that row (Consumer.cpp:137-181, HeuristicTiers.cpp:153-163)
- idea probe (projection cut to ea, ea2): U plan same, (ea,ea2) sequence same, 0.002→0.001 s; S plan same, (ea,ea2) sequence same, 0.077→0.016 s

#### H5 Same cleaned assembly

- source: `src/diff/RegistrySql.inc:255` (H:178-193), Best / Ratio, flags "[3]"; descriptor `[2 tables, 46 columns, ORDER BY]`
- (a) tables: diff.functions, main.functions. columns: SELECT_FIELDS (22 per side, all materialised per row) + non-SELECT_FIELDS columns df.{source_file}; f.{source_file}
- (b) equi-join keys: `f.clean_assembly=df.clean_assembly`
- (c) other predicates: `f.nodes >= 3`; `df.nodes >= 3`; `f.name not like 'nullsub%'`; `df.name not like 'nullsub%'`
- (d) default config: yes if same CPU; Best tier, position 7 of 12 (runs 11→0)
- (e) cost: userenv 19 rows, SQL 0.006 s, native 0.016 s; sechost 94 rows, SQL 0.043 s, native 0.478 s
- (f) order: row order = plan order; U: `SEARCH df USING INDEX idx_7 (nodes>?) | SEARCH f USING INDEX idx_20 (clean_assembly=?) | USE TEMP B-TREE FOR ORDER BY`; S: `SEARCH f USING INDEX idx_7 (nodes>?) | SEARCH df USING INDEX idx_20 (clean_assembly=?) | USE TEMP B-TREE FOR ORDER BY` (plan text differs from U); ORDER BY is a stable partition relative to the ORDER BY query's own plan (02-matching.md:1444, 04a:815-819); Ratio: 1,000,000 fetched-row cap counting rejected rows; an error truncates the heuristic at that row (Consumer.cpp:137-181, HeuristicTiers.cpp:153-163)
- idea probe (projection cut to ea, ea2): U plan same, (ea,ea2) sequence same, 0.011→0.010 s; S plan same, (ea,ea2) sequence same, 0.027→0.025 s

#### H6 Same cleaned microcode

- source: `src/diff/RegistrySql.inc:304` (H:195-210), Best / Ratio, flags "[3]"; descriptor `[2 tables, 46 columns, ORDER BY]`
- (a) tables: diff.functions, main.functions. columns: SELECT_FIELDS (22 per side, all materialised per row) + non-SELECT_FIELDS columns df.{source_file}; f.{source_file}
- (b) equi-join keys: `f.clean_microcode=df.clean_microcode`
- (c) other predicates: `f.instructions > 3`; `df.instructions > 3`; `f.name not like 'nullsub%'`; `df.name not like 'nullsub%'`
- (d) default config: yes if same CPU; Best tier, position 6 of 12 (runs 11→0)
- (e) cost: userenv 117 rows, SQL 0.044 s, native 0.078 s; sechost 332 rows, SQL 0.594 s, native 0.298 s
- (f) order: row order = plan order; U: `SEARCH df USING INDEX idx_6 (instructions>?) | SEARCH f USING AUTOMATIC PARTIAL COVERING INDEX (clean_microcode=?) | USE TEMP B-TREE FOR ORDER BY`; S: `SEARCH f USING INDEX idx_6 (instructions>?) | SEARCH df USING AUTOMATIC PARTIAL COVERING INDEX (clean_microcode=?) | USE TEMP B-TREE FOR ORDER BY` (plan text differs from U); uses an AUTOMATIC index: tie order inside a key follows the auto-index column list, which depends on the projection; ORDER BY is a stable partition relative to the ORDER BY query's own plan (02-matching.md:1444, 04a:815-819); Ratio: 1,000,000 fetched-row cap counting rejected rows; an error truncates the heuristic at that row (Consumer.cpp:137-181, HeuristicTiers.cpp:153-163)
- idea probe (projection cut to ea, ea2): U plan same, (ea,ea2) sequence same, 0.069→0.036 s; S plan same, (ea,ea2) sequence same, 0.096→0.072 s

#### H7 Same cleaned pseudo-code

- source: `src/diff/RegistrySql.inc:353` (H:212-227), Best / Ratio, flags "[]"; descriptor `[2 tables, 48 columns, ORDER BY]`
- (a) tables: diff.functions, main.functions. columns: SELECT_FIELDS (22 per side, all materialised per row) + non-SELECT_FIELDS columns df.{pseudocode_lines,source_file}; f.{pseudocode_lines,source_file}
- (b) equi-join keys: `f.clean_pseudo=df.clean_pseudo`
- (c) other predicates: `f.pseudocode_lines > 5`; `df.pseudocode_lines > 5`; `f.name not like 'nullsub%'`; `df.name not like 'nullsub%'`
- (d) default config: yes; Best tier, position 5 of 12 (runs 11→0)
- (e) cost: userenv 21 rows, SQL 0.006 s, native 0.017 s; sechost 168 rows, SQL 0.050 s, native 0.229 s
- (f) order: row order = plan order; U: `SEARCH df USING INDEX idx_9 (pseudocode_lines>?) | SEARCH f USING INDEX idx_21 (clean_pseudo=?) | USE TEMP B-TREE FOR ORDER BY`; S: same plan; ORDER BY is a stable partition relative to the ORDER BY query's own plan (02-matching.md:1444, 04a:815-819); Ratio: 1,000,000 fetched-row cap counting rejected rows; an error truncates the heuristic at that row (Consumer.cpp:137-181, HeuristicTiers.cpp:153-163)
- idea probe (projection cut to ea, ea2): U plan same, (ea,ea2) sequence same, 0.011→0.008 s; S plan same, (ea,ea2) sequence same, 0.033→0.027 s

#### H8 Same address, nodes, edges and mnemonics

- source: `src/diff/RegistrySql.inc:402` (H:229-248), Best / Ratio, flags "[]"; descriptor `[2 tables, 50 columns, ORDER BY]`
- (a) tables: diff.functions, main.functions. columns: SELECT_FIELDS (22 per side, all materialised per row) + non-SELECT_FIELDS columns df.{mnemonics,rva,source_file}; f.{mnemonics,rva,source_file}
- (b) equi-join keys: `f.edges=df.edges & f.instructions=df.instructions & f.mnemonics=df.mnemonics & f.nodes=df.nodes & f.rva=df.rva`
- (c) other predicates: `f.instructions > 3`; `df.instructions > 3`; `f.nodes > 1`
- (d) default config: yes; Best tier, position 4 of 12 (runs 11→0)
- (e) cost: userenv 9 rows, SQL 0.004 s, native 0.010 s; sechost 666 rows, SQL 0.276 s, native 0.130 s
- (f) order: row order = plan order; U: `SEARCH df USING INDEX idx_7 (nodes>?) | SEARCH f USING INDEX idx_17 (rva=?) | USE TEMP B-TREE FOR ORDER BY`; S: `SEARCH f USING INDEX idx_6 (instructions>?) | SEARCH df USING INDEX idx_17 (rva=?) | USE TEMP B-TREE FOR ORDER BY` (plan text differs from U); ORDER BY is a stable partition relative to the ORDER BY query's own plan (02-matching.md:1444, 04a:815-819); Ratio: 1,000,000 fetched-row cap counting rejected rows; an error truncates the heuristic at that row (Consumer.cpp:137-181, HeuristicTiers.cpp:153-163)
- idea probe (projection cut to ea, ea2): U plan same, (ea,ea2) sequence same, 0.005→0.005 s; S plan same, (ea,ea2) sequence same, 0.073→0.022 s

#### H9 Same RVA

- source: `src/diff/RegistrySql.inc:455` (H:250-267), Best / RatioMax min 0.7, flags "[3]"; descriptor `[2 tables, 48 columns, DISTINCT, ORDER BY]`
- (a) tables: diff.functions, main.functions. columns: SELECT_FIELDS (22 per side, all materialised per row) + non-SELECT_FIELDS columns df.{rva,source_file}; f.{rva,source_file}
- (b) equi-join keys: `f.rva=df.rva`
- (c) other predicates: `((f.name = df.name and substr(f.name, 1, 4) != 'sub_') or (substr(f.name, 1, 4) = 'sub_' or substr(df.name, 1, 4) = 'sub_'))`; `f.nodes >= 3`; `df.nodes >= 3`
- (d) default config: yes if same CPU; Best tier, position 3 of 12 (runs 11→0)
- (e) cost: userenv 19 rows, SQL 0.004 s, native 0.009 s; sechost 644 rows, SQL 0.304 s, native 0.339 s
- (f) order: row order = plan order; U: `SEARCH df USING INDEX idx_7 (nodes>?) | SEARCH f USING INDEX idx_17 (rva=?) | USE TEMP B-TREE FOR DISTINCT | USE TEMP B-TREE FOR ORDER BY`; S: `SEARCH f USING INDEX idx_7 (nodes>?) | SEARCH df USING INDEX idx_17 (rva=?) | USE TEMP B-TREE FOR DISTINCT | USE TEMP B-TREE FOR ORDER BY` (plan text differs from U); DISTINCT keeps the first occurrence in scan order; ORDER BY is a stable partition relative to the ORDER BY query's own plan (02-matching.md:1444, 04a:815-819); RatioMax: 1,000,000 fetched-row cap counting rejected rows; an error truncates the heuristic at that row (Consumer.cpp:137-181, HeuristicTiers.cpp:153-163)
- idea probe (projection cut to ea, ea2): U plan same, (ea,ea2) sequence same, 0.005→0.004 s; S plan same, (ea,ea2) sequence same, 0.087→0.022 s

#### H10 Equal assembly or pseudo-code

- source: `src/diff/RegistrySql.inc:505` (H:272-297), Best / NoFps, flags "[]"; descriptor `[2 tables, 45 columns, UNION]`
- (a) tables: diff.functions, main.functions. columns: SELECT_FIELDS (22 per side, all materialised per row) + non-SELECT_FIELDS columns f.{pseudocode_lines}
- (b) equi-join keys: `f.pseudocode=df.pseudocode | f.assembly=df.assembly`
- (c) other predicates (UNION arm 1): `df.pseudocode is not null`; `f.pseudocode_lines >= 5`; `f.name not like 'nullsub%'`; `df.name not like 'nullsub%'`
- (c) other predicates (UNION arm 2): `df.assembly is not null`; `f.instructions >= 4`; `df.instructions >= 4`; `f.name not like 'nullsub%'`; `df.name not like 'nullsub%'`
- (d) default config: yes; Best tier, position 2 of 12 (runs 11→0)
- (e) cost: userenv 23 rows, SQL 0.017 s, native 0.032 s; sechost 185 rows, SQL 0.212 s, native 0.112 s
- (f) order: row order = plan order; U: `COMPOUND QUERY | LEFT-MOST SUBQUERY | SEARCH f USING INDEX idx_9 (pseudocode_lines>?) | SEARCH df USING INDEX idx_1 (pseudocode=?) | UNION USING TEMP B-TREE | SEARCH df USING INDEX idx_6 (instructions>?) | SEARCH f USING INDEX idx_4 (assembly=?)`; S: same plan; UNION sorts and dedupes by the WHOLE row incl. description (02-matching.md:1116); NO_FPS: no row cap, every error swallowed after the rows consumed so far (Consumer.cpp:202-234)
- idea probe (projection cut to ea, ea2): U plan CHANGED, (ea,ea2) sequence same, 0.022→0.019 s; S plan CHANGED, (ea,ea2) sequence DIFFERENT, 0.084→0.080 s

#### H11 Microcode mnemonics small primes product

- source: `src/diff/RegistrySql.inc:588` (H:299-317), Best / Ratio, flags "[]"; descriptor `[2 tables, 48 columns, ORDER BY]`
- (a) tables: diff.functions, main.functions. columns: SELECT_FIELDS (22 per side, all materialised per row) + non-SELECT_FIELDS columns df.{microcode_spp,source_file}; f.{microcode_spp,source_file}
- (b) equi-join keys: `f.microcode_spp=df.microcode_spp`
- (c) other predicates: `f.microcode_spp != 1`; `df.microcode_spp != 1`; `f.instructions > 5`; `df.instructions > 5`; `f.nodes > 2`; `df.nodes > 2`; `f.name not like 'nullsub%'`; `df.name not like 'nullsub%'`
- (d) default config: yes; Best tier, position 1 of 12 (runs 11→0)
- (e) cost: userenv 558 rows, SQL 0.042 s, native 0.062 s; sechost 1871 rows, SQL 0.812 s, native 0.213 s
- (f) order: row order = plan order; U: `SEARCH df USING INDEX idx_7 (nodes>?) | SEARCH f USING INDEX idx_29 (microcode_spp=?) | USE TEMP B-TREE FOR ORDER BY`; S: `SEARCH f USING INDEX idx_7 (nodes>?) | SEARCH df USING INDEX idx_29 (microcode_spp=?) | USE TEMP B-TREE FOR ORDER BY` (plan text differs from U); ORDER BY is a stable partition relative to the ORDER BY query's own plan (02-matching.md:1444, 04a:815-819); Ratio: 1,000,000 fetched-row cap counting rejected rows; an error truncates the heuristic at that row (Consumer.cpp:137-181, HeuristicTiers.cpp:153-163)
- idea probe (projection cut to ea, ea2): U plan same, (ea,ea2) sequence same, 0.044→0.015 s; S plan same, (ea,ea2) sequence same, 0.106→0.042 s

#### H12 Same named compilation unit function match

- source: `src/diff/RegistrySql.inc:640` (H:325-351), Partial / RatioMaxTrusted min 0.44, flags "[]"; descriptor `[6 tables, 56 columns]`
- (a) tables: diff.compilation_unit_functions, diff.compilation_units, diff.functions, main.compilation_unit_functions, main.compilation_units, main.functions. columns: SELECT_FIELDS (22 per side, all materialised per row) + non-SELECT_FIELDS columns dcuf.{cu_id,func_id}; df.{id,primes_value}; diff_cu.{id,name}; f.{id,primes_value}; main_cu.{id,name}; mcuf.{cu_id,func_id}
- (b) equi-join keys: `mcuf.cu_id=mcu.id & mcuf.func_id=f.id & mcu.name=dcu.name & f.nodes=df.nodes & f.primes_value=df.primes_value & dcuf.cu_id=dcu.id & dcuf.func_id=df.id`
- (c) other predicates: `main_cu.name != ''`; `diff_cu.name != ''`; `f.nodes >= 5`
- (d) default config: yes; Partial tier, position 27 of 27 (runs 41,40,39,35→12)
- (e) cost: userenv 1685 rows, SQL 0.033 s, native 0.054 s; sechost 4787 rows, SQL 0.152 s, native 0.189 s
- (f) order: row order = plan order; U: `SEARCH df USING INDEX idx_7 (nodes>?) | SEARCH dcuf USING INDEX idx_39 (func_id=?) | BLOOM FILTER ON diff_cu (id=?) | SEARCH diff_cu USING INTEGER PRIMARY KEY (rowid=?) | BLOOM FILTER ON main_cu (name=?) | SEARCH main_cu USING INDEX idx_38 (name=?) | SEARCH f USING INDEX idx_7 (nodes=?) | SEARCH mcuf USING INDEX idx_39 (func_id=?)`; S: `SEARCH df USING INDEX idx_7 (nodes>?) | SEARCH dcuf USING INDEX idx_39 (func_id=?) | BLOOM FILTER ON diff_cu (id=?) | SEARCH diff_cu USING INTEGER PRIMARY KEY (rowid=?) | SEARCH f USING INDEX idx_7 (nodes=?) | SEARCH mcuf USING INDEX idx_39 (func_id=?) | BLOOM FILTER ON main_cu (name=? AND rowid=?) | SEARCH main_cu USING INDEX idx_38 (name=? AND rowid=?)` (plan text differs from U); RatioMaxTrusted: 1,000,000 fetched-row cap counting rejected rows; an error truncates the heuristic at that row (Consumer.cpp:137-181, HeuristicTiers.cpp:153-163)
- idea probe (projection cut to ea, ea2): U plan same, (ea,ea2) sequence same, 0.040→0.006 s; S plan same, (ea,ea2) sequence same, 0.111→0.019 s

#### H13 Same anonymous compilation unit function match

- source: `src/diff/RegistrySql.inc:699` (H:353-379), Partial / RatioMax min 0.449, flags "[]"; descriptor `[6 tables, 56 columns, ORDER BY]`
- (a) tables: diff.compilation_unit_functions, diff.compilation_units, diff.functions, main.compilation_unit_functions, main.compilation_units, main.functions. columns: SELECT_FIELDS (22 per side, all materialised per row) + non-SELECT_FIELDS columns dcuf.{cu_id,func_id}; df.{id,source_file}; diff_cu.{id,name}; f.{id,source_file}; main_cu.{id,name}; mcuf.{cu_id,func_id}
- (b) equi-join keys: `mcuf.cu_id=mcu.id & mcuf.func_id=f.id & mcu.name=dcu.name & f.nodes=df.nodes & f.pseudocode_primes=df.pseudocode_primes & dcuf.cu_id=dcu.id & dcuf.func_id=df.id`
- (c) other predicates: `main_cu.name != ''`; `diff_cu.name != ''`; `f.nodes >= 5`
- (d) default config: yes; Partial tier, position 26 of 27 (runs 41,40,39,35→12)
- (e) cost: userenv 66 rows, SQL 0.007 s, native 0.024 s; sechost 429 rows, SQL 0.068 s, native 0.112 s
- (f) order: row order = plan order; U: `SEARCH df USING INDEX idx_7 (nodes>?) | SEARCH dcuf USING INDEX idx_39 (func_id=?) | BLOOM FILTER ON diff_cu (id=?) | SEARCH diff_cu USING INTEGER PRIMARY KEY (rowid=?) | BLOOM FILTER ON main_cu (name=?) | SEARCH main_cu USING INDEX idx_38 (name=?) | SEARCH f USING INDEX idx_7 (nodes=?) | SEARCH mcuf USING INDEX idx_39 (func_id=?) | USE TEMP B-TREE FOR ORDER BY`; S: `SEARCH df USING INDEX idx_7 (nodes>?) | SEARCH dcuf USING INDEX idx_39 (func_id=?) | BLOOM FILTER ON diff_cu (id=?) | SEARCH diff_cu USING INTEGER PRIMARY KEY (rowid=?) | SEARCH f USING INDEX idx_7 (nodes=?) | SEARCH mcuf USING INDEX idx_39 (func_id=?) | BLOOM FILTER ON main_cu (name=? AND rowid=?) | SEARCH main_cu USING INDEX idx_38 (name=? AND rowid=?) | USE TEMP B-TREE FOR ORDER BY` (plan text differs from U); ORDER BY is a stable partition relative to the ORDER BY query's own plan (02-matching.md:1444, 04a:815-819); RatioMax: 1,000,000 fetched-row cap counting rejected rows; an error truncates the heuristic at that row (Consumer.cpp:137-181, HeuristicTiers.cpp:153-163)
- idea probe (projection cut to ea, ea2): U plan same, (ea,ea2) sequence same, 0.008→0.007 s; S plan same, (ea,ea2) sequence same, 0.044→0.023 s

#### H14 Same compilation unit

- source: `src/diff/RegistrySql.inc:758` (H:390-412), Partial / Ratio, flags "[2]"; descriptor `[6 tables, 54 columns]`
- (a) tables: diff.compilation_unit_functions, diff.compilation_units, diff.functions, main.compilation_unit_functions, main.compilation_units, main.functions. columns: SELECT_FIELDS (22 per side, all materialised per row) + non-SELECT_FIELDS columns dcu.{id,pseudocode_primes}; dcuf.{cu_id,func_id}; df.{id}; f.{id}; mcu.{id,pseudocode_primes}; mcuf.{cu_id,func_id}
- (b) equi-join keys: `mcuf.cu_id=mcu.id & mcuf.func_id=f.id & mcu.pseudocode_primes=dcu.pseudocode_primes & dcuf.cu_id=dcu.id & dcuf.func_id=df.id`
- (c) other predicates: `f.nodes > 4`; `df.nodes > 4`; `(substr(f.name, 1, 4) = 'sub_' or substr(df.name, 1, 4) == 'sub_')`
- (d) default config: yes; Partial tier, position 25 of 27 (runs 41,40,39,35→12)
- (e) cost: userenv 0 rows, SQL 2.308 s, native 4.022 s; sechost 103 rows, SQL 0.043 s, native 0.084 s
- (f) order: row order = plan order; U: `SEARCH f USING INDEX idx_7 (nodes>?) | SEARCH mcuf USING INDEX idx_39 (func_id=?) | SEARCH mcu USING INTEGER PRIMARY KEY (rowid=?) | SEARCH df USING INDEX idx_7 (nodes>?) | SEARCH dcuf USING INDEX idx_39 (func_id=?) | SEARCH dcu USING COVERING INDEX idx_37 (pseudocode_primes=? AND rowid=?)`; S: `SEARCH f USING INDEX idx_7 (nodes>?) | SEARCH mcuf USING INDEX idx_39 (func_id=?) | SEARCH mcu USING INTEGER PRIMARY KEY (rowid=?) | SEARCH dcu USING COVERING INDEX idx_37 (pseudocode_primes=?) | SEARCH dcuf USING INDEX idx_40 (cu_id=?) | BLOOM FILTER ON df (id=?) | SEARCH df USING INTEGER PRIMARY KEY (rowid=?)` (plan text differs from U); Ratio: 1,000,000 fetched-row cap counting rejected rows; an error truncates the heuristic at that row (Consumer.cpp:137-181, HeuristicTiers.cpp:153-163)
- idea probe (projection cut to ea, ea2): U plan same, (ea,ea2) sequence same, 3.412→3.843 s; S plan same, (ea,ea2) sequence same, 0.033→0.028 s

#### H15 Same KOKA hash and constants

- source: `src/diff/RegistrySql.inc:814` (H:417-434), Partial / Ratio, flags "[]"; descriptor `[4 tables, 50 columns]`
- (a) tables: diff.constants, diff.functions, main.constants, main.functions. columns: SELECT_FIELDS (22 per side, all materialised per row) + non-SELECT_FIELDS columns dc.{constant,func_id}; df.{id}; f.{id}; mc.{constant,func_id}
- (b) equi-join keys: `mc.constant=dc.constant & mc.func_id=f.id & f.kgh_hash=df.kgh_hash & dc.func_id=df.id`
- (c) other predicates: `f.nodes >= 3`
- (d) default config: yes; Partial tier, position 24 of 27 (runs 41,40,39,35→12)
- (e) cost: userenv 929 rows, SQL 0.031 s, native 0.049 s; sechost 30710 rows, SQL 56.566 s, native 47.859 s
- (f) order: row order = plan order; U: `SCAN mc | SEARCH f USING INTEGER PRIMARY KEY (rowid=?) | SEARCH df USING INDEX idx_25 (kgh_hash=?) | SEARCH dc USING COVERING INDEX idx_35 (constant=? AND func_id=?)`; S: `SCAN mc | BLOOM FILTER ON f (id=?) | SEARCH f USING INTEGER PRIMARY KEY (rowid=?) | SEARCH df USING INDEX idx_25 (kgh_hash=?) | SEARCH dc USING COVERING INDEX idx_35 (constant=? AND func_id=?)` (plan text differs from U); Ratio: 1,000,000 fetched-row cap counting rejected rows; an error truncates the heuristic at that row (Consumer.cpp:137-181, HeuristicTiers.cpp:153-163)
- idea probe (projection cut to ea, ea2): U plan same, (ea,ea2) sequence same, 0.049→0.005 s; S plan same, (ea,ea2) sequence same, 38.091→0.086 s

#### H16 Same KOKA hash and MD-Index

- source: `src/diff/RegistrySql.inc:865` (H:438-457), Partial / Ratio, flags "[]"; descriptor `[2 tables, 44 columns]`
- (a) tables: diff.functions, main.functions. columns: SELECT_FIELDS (22 per side, all materialised per row) + non-SELECT_FIELDS columns -
- (b) equi-join keys: `f.indegree=df.indegree & f.kgh_hash=df.kgh_hash & f.md_index=df.md_index & f.nodes=df.nodes & f.outdegree=df.outdegree`
- (c) other predicates: `f.nodes >= 4`; `(substr(f.name, 1, 4) = 'sub_' or substr(df.name, 1, 4) = 'sub_')`
- (d) default config: yes; Partial tier, position 23 of 27 (runs 41,40,39,35→12)
- (e) cost: userenv 350 rows, SQL 0.018 s, native 0.036 s; sechost 1159 rows, SQL 0.091 s, native 0.112 s
- (f) order: row order = plan order; U: `SEARCH f USING INDEX idx_7 (nodes>?) | SEARCH df USING INDEX idx_25 (kgh_hash=?)`; S: `SEARCH df USING INDEX idx_7 (nodes>?) | SEARCH f USING INDEX idx_25 (kgh_hash=?)` (plan text differs from U); Ratio: 1,000,000 fetched-row cap counting rejected rows; an error truncates the heuristic at that row (Consumer.cpp:137-181, HeuristicTiers.cpp:153-163)
- idea probe (projection cut to ea, ea2): U plan same, (ea,ea2) sequence same, 0.025→0.012 s; S plan same, (ea,ea2) sequence same, 0.070→0.031 s

#### H17 Same constants

- source: `src/diff/RegistrySql.inc:918` (H:459-474), Partial / RatioMax min 0.5, flags "[]"; descriptor `[2 tables, 48 columns, ORDER BY]`
- (a) tables: diff.functions, main.functions. columns: SELECT_FIELDS (22 per side, all materialised per row) + non-SELECT_FIELDS columns df.{constants,source_file}; f.{constants,source_file}
- (b) equi-join keys: `f.constants=df.constants & f.constants_count=df.constants_count`
- (c) other predicates: `f.constants_count > 1`
- (d) default config: yes; Partial tier, position 22 of 27 (runs 41,40,39,35→12)
- (e) cost: userenv 211 rows, SQL 0.023 s, native 0.046 s; sechost 510 rows, SQL 0.123 s, native 0.120 s
- (f) order: row order = plan order; U: `SEARCH df USING INDEX idx_26 (constants_count>?) | SEARCH f USING INDEX idx_26 (constants_count=? AND constants=?) | USE TEMP B-TREE FOR ORDER BY`; S: same plan; ORDER BY is a stable partition relative to the ORDER BY query's own plan (02-matching.md:1444, 04a:815-819); RatioMax: 1,000,000 fetched-row cap counting rejected rows; an error truncates the heuristic at that row (Consumer.cpp:137-181, HeuristicTiers.cpp:153-163)
- idea probe (projection cut to ea, ea2): U plan same, (ea,ea2) sequence same, 0.036→0.006 s; S plan same, (ea,ea2) sequence same, 0.051→0.007 s

#### H18 Same rare KOKA hash

- source: `src/diff/RegistrySql.inc:966` (H:478-510), Partial / RatioMax min 0.45, flags "[]"; descriptor `[2 tables, 44 columns, CTEs]`
- (a) tables: diff.functions, main.functions. columns: SELECT_FIELDS (22 per side, all materialised per row) + non-SELECT_FIELDS columns (cte) diff.functions.{kgh_hash}; (cte) main.functions.{kgh_hash}; shared_hashes.{kgh_hash}
- (b) equi-join keys: `f.kgh_hash=df.kgh_hash & df.kgh_hash=cte:shared_hashes.kgh_hash`
- (c) other predicates (outer query): `f.nodes > 5`; `(substr(f.name, 1, 4) = 'sub_' or substr(df.name, 1, 4) = 'sub_')`
- (c) rarity / CTE predicates: `shared_hashes` = UNION of diff and main `kgh_hash` values with `kgh_hash != 0 group by kgh_hash having count(*) <= 2` (rare on EITHER side, not both)
- (d) default config: yes; Partial tier, position 21 of 27 (runs 41,40,39,35→12)
- (e) cost: userenv 220 rows, SQL 0.012 s, native 0.034 s; sechost 559 rows, SQL 0.078 s, native 0.081 s
- (f) order: row order = plan order; U: `CO-ROUTINE shared_hashes | COMPOUND QUERY | LEFT-MOST SUBQUERY | SCAN diff.functions USING COVERING INDEX idx_25 | UNION USING TEMP B-TREE | SCAN main.functions USING COVERING INDEX idx_25 | SEARCH f USING INDEX idx_7 (nodes>?) | SEARCH df USING INDEX idx_25 (kgh_hash=?) | SEARCH shared_hashes USING AUTOMATIC COVERING INDEX (kgh_hash=?)`; S: `CO-ROUTINE shared_hashes | COMPOUND QUERY | LEFT-MOST SUBQUERY | SCAN diff.functions USING COVERING INDEX idx_25 | UNION USING TEMP B-TREE | SCAN main.functions USING COVERING INDEX idx_25 | SCAN shared_hashes | SEARCH f USING INDEX idx_25 (kgh_hash=?) | SEARCH df USING INDEX idx_25 (kgh_hash=?)` (plan text differs from U); uses an AUTOMATIC index: tie order inside a key follows the auto-index column list, which depends on the projection; CTE: the rarity set is a UNION (sorted, deduped) joined back; its AUTOMATIC index / SCAN choice differs U vs S; RatioMax: 1,000,000 fetched-row cap counting rejected rows; an error truncates the heuristic at that row (Consumer.cpp:137-181, HeuristicTiers.cpp:153-163)
- idea probe (projection cut to ea, ea2): U plan same, (ea,ea2) sequence same, 0.021→0.007 s; S plan same, (ea,ea2) sequence same, 0.048→0.011 s

#### H19 Same rare MD Index

- source: `src/diff/RegistrySql.inc:1031` (H:512-541), Partial / Ratio, flags "[]"; descriptor `[2 tables, 46 columns, CTEs, ORDER BY]`
- (a) tables: diff.functions, main.functions. columns: SELECT_FIELDS (22 per side, all materialised per row) + non-SELECT_FIELDS columns (cte) diff.functions.{md_index}; (cte) main.functions.{md_index}; df.{source_file}; f.{source_file}; shared_mds.{md_index}
- (b) equi-join keys: `f.md_index=df.md_index & df.md_index=cte:shared_mds.md_index`
- (c) other predicates (outer query): `f.nodes > 10`
- (c) rarity / CTE predicates: `shared_mds` = UNION of diff and main `md_index` values with `md_index != 0 group by md_index having count(*) <= 2` (rare on either side)
- (d) default config: yes; Partial tier, position 20 of 27 (runs 41,40,39,35→12)
- (e) cost: userenv 129 rows, SQL 0.019 s, native 0.040 s; sechost 453 rows, SQL 0.153 s, native 0.146 s
- (f) order: row order = plan order; U: `CO-ROUTINE shared_mds | COMPOUND QUERY | LEFT-MOST SUBQUERY | SCAN diff.functions USING COVERING INDEX idx_24 | UNION USING TEMP B-TREE | SCAN main.functions USING COVERING INDEX idx_24 | SCAN shared_mds | SEARCH df USING INDEX idx_24 (md_index=?) | SEARCH f USING INDEX idx_24 (md_index=?) | USE TEMP B-TREE FOR ORDER BY`; S: `CO-ROUTINE shared_mds | COMPOUND QUERY | LEFT-MOST SUBQUERY | SCAN diff.functions USING COVERING INDEX idx_24 | UNION USING TEMP B-TREE | SCAN main.functions USING COVERING INDEX idx_24 | SCAN shared_mds | SEARCH f USING INDEX idx_27 (md_index=?) | SEARCH df USING INDEX idx_27 (md_index=?) | USE TEMP B-TREE FOR ORDER BY` (plan text differs from U); ORDER BY is a stable partition relative to the ORDER BY query's own plan (02-matching.md:1444, 04a:815-819); CTE: the rarity set is a UNION (sorted, deduped) joined back; its AUTOMATIC index / SCAN choice differs U vs S; Ratio: 1,000,000 fetched-row cap counting rejected rows; an error truncates the heuristic at that row (Consumer.cpp:137-181, HeuristicTiers.cpp:153-163)
- idea probe (projection cut to ea, ea2): U plan same, (ea,ea2) sequence same, 0.034→0.006 s; S plan same, (ea,ea2) sequence same, 0.063→0.016 s

#### H20 Same address and rare constant

- source: `src/diff/RegistrySql.inc:1094` (H:546-564), Partial / RatioMax min 0.5, flags "[]"; descriptor `[4 tables, 52 columns, DISTINCT, ORDER BY]`
- (a) tables: diff.constants, diff.functions, main.constants, main.functions. columns: SELECT_FIELDS (22 per side, all materialised per row) + non-SELECT_FIELDS columns dc.{constant,func_id}; df.{id,source_file}; f.{id,source_file}; mc.{constant,func_id}
- (b) equi-join keys: `mc.constant=dc.constant & mc.func_id=f.id & f.address=df.address & dc.func_id=df.id`
- (c) other predicates: -
- (d) default config: yes; Partial tier, position 19 of 27 (runs 41,40,39,35→12)
- (e) cost: userenv 2 rows, SQL 0.000 s, native 0.010 s; sechost 273 rows, SQL 82.574 s, native 82.634 s
- (f) order: row order = plan order; U: `SCAN mc | SEARCH f USING INTEGER PRIMARY KEY (rowid=?) | SEARCH df USING INDEX idx_28 (address=?) | SEARCH dc USING COVERING INDEX idx_35 (constant=? AND func_id=?) | USE TEMP B-TREE FOR DISTINCT | USE TEMP B-TREE FOR ORDER BY`; S: same plan; DISTINCT keeps the first occurrence in scan order; ORDER BY is a stable partition relative to the ORDER BY query's own plan (02-matching.md:1444, 04a:815-819); RatioMax: 1,000,000 fetched-row cap counting rejected rows; an error truncates the heuristic at that row (Consumer.cpp:137-181, HeuristicTiers.cpp:153-163)
- idea probe (projection cut to ea, ea2): U plan same, (ea,ea2) sequence same, 0.001→0.000 s; S plan same, (ea,ea2) sequence same, 52.706→0.015 s

#### H21 Same rare constant

- source: `src/diff/RegistrySql.inc:1145` (H:567-585), Partial / RatioMax min 0.2, flags "[2]"; descriptor `[4 tables, 50 columns]`
- (a) tables: diff.constants, diff.functions, main.constants, main.functions. columns: SELECT_FIELDS (22 per side, all materialised per row) + non-SELECT_FIELDS columns dc.{constant,func_id}; df.{id}; f.{id}; mc.{constant,func_id}
- (b) equi-join keys: `mc.constant=dc.constant & mc.func_id=f.id & dc.func_id=df.id`
- (c) other predicates: `f.nodes >= 3`; `df.nodes >= 3`; `f.constants_count > 0`
- (d) default config: yes; Partial tier, position 18 of 27 (runs 41,40,39,35→12)
- (e) cost: userenv 5869 rows, SQL 0.202 s, native 0.243 s; sechost 58236 rows, SQL 62.305 s, native 55.276 s
- (f) order: row order = plan order; U: `SCAN mc | SEARCH f USING INTEGER PRIMARY KEY (rowid=?) | SEARCH dc USING COVERING INDEX idx_35 (constant=?) | BLOOM FILTER ON df (id=?) | SEARCH df USING INTEGER PRIMARY KEY (rowid=?)`; S: `SCAN mc | BLOOM FILTER ON f (id=?) | SEARCH f USING INTEGER PRIMARY KEY (rowid=?) | SEARCH dc USING COVERING INDEX idx_35 (constant=?) | BLOOM FILTER ON df (id=?) | SEARCH df USING INTEGER PRIMARY KEY (rowid=?)` (plan text differs from U); RatioMax: 1,000,000 fetched-row cap counting rejected rows; an error truncates the heuristic at that row (Consumer.cpp:137-181, HeuristicTiers.cpp:153-163)
- idea probe (projection cut to ea, ea2): U plan same, (ea,ea2) sequence same, 0.331→0.010 s; S plan same, (ea,ea2) sequence same, 46.039→0.074 s

#### H22 Same MD Index and constants

- source: `src/diff/RegistrySql.inc:1196` (H:587-603), Partial / Ratio, flags "[]"; descriptor `[2 tables, 48 columns, DISTINCT, ORDER BY]`
- (a) tables: diff.functions, main.functions. columns: SELECT_FIELDS (22 per side, all materialised per row) + non-SELECT_FIELDS columns df.{constants,source_file}; f.{constants,source_file}
- (b) equi-join keys: `f.constants=df.constants & f.md_index=df.md_index`
- (c) other predicates: `f.md_index > 0`; `f.nodes >= 3`; `df.nodes >= 3`; `((f.constants = df.constants and f.constants_count > 0))`
- (d) default config: yes; Partial tier, position 17 of 27 (runs 41,40,39,35→12)
- (e) cost: userenv 461 rows, SQL 0.068 s, native 0.093 s; sechost 1622 rows, SQL 0.126 s, native 0.406 s
- (f) order: row order = plan order; U: `SEARCH df USING INDEX idx_27 (md_index>?) | SEARCH f USING INDEX idx_27 (md_index=? AND constants_count>?) | USE TEMP B-TREE FOR DISTINCT | USE TEMP B-TREE FOR ORDER BY`; S: `SEARCH df USING INDEX idx_24 (md_index>?) | SEARCH f USING INDEX idx_27 (md_index=? AND constants_count>?) | USE TEMP B-TREE FOR DISTINCT | USE TEMP B-TREE FOR ORDER BY` (plan text differs from U); DISTINCT keeps the first occurrence in scan order; ORDER BY is a stable partition relative to the ORDER BY query's own plan (02-matching.md:1444, 04a:815-819); Ratio: 1,000,000 fetched-row cap counting rejected rows; an error truncates the heuristic at that row (Consumer.cpp:137-181, HeuristicTiers.cpp:153-163)
- idea probe (projection cut to ea, ea2): U plan same, (ea,ea2) sequence same, 0.087→0.009 s; S plan same, (ea,ea2) sequence same, 0.126→0.024 s

#### H23 Import names hash

- source: `src/diff/RegistrySql.inc:1246` (H:605-621), Partial / Ratio, flags "[]"; descriptor `[2 tables, 48 columns, DISTINCT, ORDER BY]`
- (a) tables: diff.functions, main.functions. columns: SELECT_FIELDS (22 per side, all materialised per row) + non-SELECT_FIELDS columns df.{names,source_file}; f.{names,source_file}
- (b) equi-join keys: `f.instructions=df.instructions & f.md_index=df.md_index & f.names=df.names`
- (c) other predicates: `f.names != '[]'`; `f.nodes > 5`; `df.nodes > 5`
- (d) default config: yes; Partial tier, position 16 of 27 (runs 41,40,39,35→12)
- (e) cost: userenv 0 rows, SQL 0.001 s, native 0.080 s; sechost 3 rows, SQL 0.011 s, native 0.034 s
- (f) order: row order = plan order; U: `SEARCH df USING INDEX idx_7 (nodes>?) | SEARCH f USING INDEX idx_10 (names=?) | USE TEMP B-TREE FOR DISTINCT | USE TEMP B-TREE FOR ORDER BY`; S: same plan; DISTINCT keeps the first occurrence in scan order; ORDER BY is a stable partition relative to the ORDER BY query's own plan (02-matching.md:1444, 04a:815-819); Ratio: 1,000,000 fetched-row cap counting rejected rows; an error truncates the heuristic at that row (Consumer.cpp:137-181, HeuristicTiers.cpp:153-163)
- idea probe (projection cut to ea, ea2): U plan same, (ea,ea2) sequence same, 0.002→0.001 s; S plan same, (ea,ea2) sequence same, 0.011→0.011 s

#### H24 Mnemonics and names

- source: `src/diff/RegistrySql.inc:1296` (H:623-639), Partial / Ratio, flags "[]"; descriptor `[2 tables, 50 columns, ORDER BY]`
- (a) tables: diff.functions, main.functions. columns: SELECT_FIELDS (22 per side, all materialised per row) + non-SELECT_FIELDS columns df.{mnemonics,names,source_file}; f.{mnemonics,names,source_file}
- (b) equi-join keys: `f.instructions=df.instructions & f.mnemonics=df.mnemonics & f.names=df.names`
- (c) other predicates: `f.names != '[]'`; `f.instructions > 5`; `df.instructions > 5`
- (d) default config: yes; Partial tier, position 15 of 27 (runs 41,40,39,35→12)
- (e) cost: userenv 0 rows, SQL 0.001 s, native 0.008 s; sechost 23 rows, SQL 0.012 s, native 0.038 s
- (f) order: row order = plan order; U: `SEARCH df USING INDEX idx_6 (instructions>?) | SEARCH f USING INDEX idx_6 (instructions=? AND mnemonics=? AND names=?) | USE TEMP B-TREE FOR ORDER BY`; S: same plan; ORDER BY is a stable partition relative to the ORDER BY query's own plan (02-matching.md:1444, 04a:815-819); Ratio: 1,000,000 fetched-row cap counting rejected rows; an error truncates the heuristic at that row (Consumer.cpp:137-181, HeuristicTiers.cpp:153-163)
- idea probe (projection cut to ea, ea2): U plan same, (ea,ea2) sequence same, 0.002→0.002 s; S plan same, (ea,ea2) sequence same, 0.012→0.010 s

#### H25 Pseudo-code fuzzy hash

- source: `src/diff/RegistrySql.inc:1346` (H:641-660), Partial / Ratio, flags "[]"; descriptor `[2 tables, 52 columns, DISTINCT, ORDER BY]`
- (a) tables: diff.functions, main.functions. columns: SELECT_FIELDS (22 per side, all materialised per row) + non-SELECT_FIELDS columns df.{pseudocode_hash1,pseudocode_hash2,pseudocode_hash3,source_file}; f.{pseudocode_hash1,pseudocode_hash2,pseudocode_hash3,source_file}
- (b) equi-join keys: `f.pseudocode_hash1=df.pseudocode_hash1 & f.pseudocode_hash2=df.pseudocode_hash2 & f.pseudocode_hash3=df.pseudocode_hash3`
- (c) other predicates: `df.pseudocode_hash1 is not null`; `df.pseudocode_hash2 is not null`; `df.pseudocode_hash3 is not null`; `f.instructions > 5`; `df.instructions > 5`
- (d) default config: yes; Partial tier, position 14 of 27 (runs 41,40,39,35→12)
- (e) cost: userenv 0 rows, SQL 0.000 s, native 0.008 s; sechost 0 rows, SQL 0.006 s, native 0.029 s
- (f) order: row order = plan order; U: `SEARCH df USING INDEX idx_6 (instructions>?) | SEARCH f USING INDEX idx_13 (pseudocode_hash1=? AND pseudocode_hash2=? AND pseudocode_hash3=?) | USE TEMP B-TREE FOR DISTINCT | USE TEMP B-TREE FOR ORDER BY`; S: same plan; DISTINCT keeps the first occurrence in scan order; ORDER BY is a stable partition relative to the ORDER BY query's own plan (02-matching.md:1444, 04a:815-819); Ratio: 1,000,000 fetched-row cap counting rejected rows; an error truncates the heuristic at that row (Consumer.cpp:137-181, HeuristicTiers.cpp:153-163)
- idea probe (projection cut to ea, ea2): U plan same, (ea,ea2) sequence same, 0.002→0.000 s; S plan same, (ea,ea2) sequence same, 0.006→0.006 s

#### H26 Similar pseudo-code and names

- source: `src/diff/RegistrySql.inc:1399` (H:662-680), Partial / RatioMax min 0.579, flags "[]"; descriptor `[2 tables, 50 columns, DISTINCT, ORDER BY]`
- (a) tables: diff.functions, main.functions. columns: SELECT_FIELDS (22 per side, all materialised per row) + non-SELECT_FIELDS columns df.{names,pseudocode_lines,source_file}; f.{names,pseudocode_lines,source_file}
- (b) equi-join keys: `f.names=df.names & f.pseudocode_lines=df.pseudocode_lines`
- (c) other predicates: `df.names != '[]'`; `df.pseudocode_lines > 5`; `df.pseudocode is not null`; `f.pseudocode is not null`
- (d) default config: yes; Partial tier, position 13 of 27 (runs 41,40,39,35→12)
- (e) cost: userenv 0 rows, SQL 0.001 s, native 0.014 s; sechost 24 rows, SQL 0.012 s, native 0.038 s
- (f) order: row order = plan order; U: `SEARCH df USING INDEX idx_9 (pseudocode_lines>?) | SEARCH f USING INDEX idx_10 (names=?) | USE TEMP B-TREE FOR DISTINCT | USE TEMP B-TREE FOR ORDER BY`; S: same plan; DISTINCT keeps the first occurrence in scan order; ORDER BY is a stable partition relative to the ORDER BY query's own plan (02-matching.md:1444, 04a:815-819); RatioMax: 1,000,000 fetched-row cap counting rejected rows; an error truncates the heuristic at that row (Consumer.cpp:137-181, HeuristicTiers.cpp:153-163)
- idea probe (projection cut to ea, ea2): U plan same, (ea,ea2) sequence same, 0.002→0.002 s; S plan same, (ea,ea2) sequence same, 0.012→0.011 s

#### H27 Mnemonics small-primes-product

- source: `src/diff/RegistrySql.inc:1450` (H:682-697), Partial / RatioMax min 0.6, flags "[]"; descriptor `[2 tables, 46 columns]`
- (a) tables: diff.functions, main.functions. columns: SELECT_FIELDS (22 per side, all materialised per row) + non-SELECT_FIELDS columns df.{mnemonics_spp}; f.{mnemonics_spp}
- (b) equi-join keys: `f.instructions=df.instructions & f.mnemonics_spp=df.mnemonics_spp`
- (c) other predicates: `f.nodes > 1`; `df.nodes > 1`; `df.instructions > 5`
- (d) default config: yes; Partial tier, position 12 of 27 (runs 41,40,39,35→12)
- (e) cost: userenv 763 rows, SQL 0.021 s, native 0.037 s; sechost 2083 rows, SQL 0.089 s, native 0.116 s
- (f) order: row order = plan order; U: `SEARCH df USING INDEX idx_7 (nodes>?) | SEARCH f USING INDEX idx_19 (mnemonics_spp=?)`; S: same plan; RatioMax: 1,000,000 fetched-row cap counting rejected rows; an error truncates the heuristic at that row (Consumer.cpp:137-181, HeuristicTiers.cpp:153-163)
- idea probe (projection cut to ea, ea2): U plan same, (ea,ea2) sequence same, 0.031→0.009 s; S plan same, (ea,ea2) sequence same, 0.089→0.020 s

#### H28 Same nodes, edges, loops and strongly connected components

- source: `src/diff/RegistrySql.inc:1498` (H:701-719), Partial / RatioMax min 0.549, flags "[]"; descriptor `[2 tables, 44 columns]`
- (a) tables: diff.functions, main.functions. columns: SELECT_FIELDS (22 per side, all materialised per row) + non-SELECT_FIELDS columns -
- (b) equi-join keys: `f.edges=df.edges & f.loops=df.loops & f.nodes=df.nodes & f.strongly_connected=df.strongly_connected`
- (c) other predicates: `f.nodes > 5`; `df.nodes > 5`; `f.loops > 0`; `(substr(f.name, 1, 4) = 'sub_' or substr(df.name, 1, 4) == 'sub_')`
- (d) default config: yes; Partial tier, position 11 of 27 (runs 41,40,39,35→12)
- (e) cost: userenv 131 rows, SQL 0.007 s, native 0.018 s; sechost 504 rows, SQL 0.039 s, native 0.136 s
- (f) order: row order = plan order; U: `SEARCH df USING INDEX idx_16 (loops>?) | SEARCH f USING INDEX idx_7 (nodes=? AND edges=?)`; S: `SEARCH f USING INDEX idx_7 (nodes>?) | SEARCH df USING INDEX idx_7 (nodes=? AND edges=?)` (plan text differs from U); RatioMax: 1,000,000 fetched-row cap counting rejected rows; an error truncates the heuristic at that row (Consumer.cpp:137-181, HeuristicTiers.cpp:153-163)
- idea probe (projection cut to ea, ea2): U plan same, (ea,ea2) sequence same, 0.010→0.002 s; S plan same, (ea,ea2) sequence same, 0.039→0.015 s

#### H29 Same low complexity, prototype and names

- source: `src/diff/RegistrySql.inc:1549` (H:723-740), Partial / RatioMax min 0.5, flags "[]"; descriptor `[2 tables, 48 columns, DISTINCT]`
- (a) tables: diff.functions, main.functions. columns: SELECT_FIELDS (22 per side, all materialised per row) + non-SELECT_FIELDS columns df.{names,prototype2}; f.{names,prototype2}
- (b) equi-join keys: `f.cyclomatic_complexity=df.cyclomatic_complexity & f.names=df.names & f.prototype2=df.prototype2`
- (c) other predicates: `f.cyclomatic_complexity < 20`; `df.names != '[]'`
- (d) default config: yes; Partial tier, position 10 of 27 (runs 41,40,39,35→12)
- (e) cost: userenv 0 rows, SQL 0.001 s, native 0.009 s; sechost 15 rows, SQL 0.009 s, native 0.032 s
- (f) order: row order = plan order; U: `SEARCH df USING INDEX idx_8 (cyclomatic_complexity<?) | SEARCH f USING INDEX idx_10 (names=?) | USE TEMP B-TREE FOR DISTINCT`; S: same plan; DISTINCT keeps the first occurrence in scan order; RatioMax: 1,000,000 fetched-row cap counting rejected rows; an error truncates the heuristic at that row (Consumer.cpp:137-181, HeuristicTiers.cpp:153-163)
- idea probe (projection cut to ea, ea2): U plan same, (ea,ea2) sequence same, 0.003→0.002 s; S plan same, (ea,ea2) sequence same, 0.009→0.006 s

#### H30 Same low complexity and names

- source: `src/diff/RegistrySql.inc:1599` (H:742-758), Partial / RatioMax min 0.5, flags "[]"; descriptor `[2 tables, 46 columns]`
- (a) tables: diff.functions, main.functions. columns: SELECT_FIELDS (22 per side, all materialised per row) + non-SELECT_FIELDS columns df.{names}; f.{names}
- (b) equi-join keys: `f.cyclomatic_complexity=df.cyclomatic_complexity & f.names=df.names`
- (c) other predicates: `f.cyclomatic_complexity < 15`; `df.names != '[]'`; `(substr(f.name, 1, 4) = 'sub_' or substr(df.name, 1, 4) == 'sub_')`
- (d) default config: yes; Partial tier, position 9 of 27 (runs 41,40,39,35→12)
- (e) cost: userenv 0 rows, SQL 0.001 s, native 0.009 s; sechost 32 rows, SQL 0.007 s, native 0.023 s
- (f) order: row order = plan order; U: `SEARCH df USING INDEX idx_8 (cyclomatic_complexity<?) | SEARCH f USING INDEX idx_10 (names=?)`; S: same plan; RatioMax: 1,000,000 fetched-row cap counting rejected rows; an error truncates the heuristic at that row (Consumer.cpp:137-181, HeuristicTiers.cpp:153-163)
- idea probe (projection cut to ea, ea2): U plan same, (ea,ea2) sequence same, 0.002→0.002 s; S plan same, (ea,ea2) sequence same, 0.007→0.006 s

#### H31 Switch structures

- source: `src/diff/RegistrySql.inc:1648` (H:760-775), Partial / RatioMax min 0.5, flags "[]"; descriptor `[2 tables, 48 columns, ORDER BY]`
- (a) tables: diff.functions, main.functions. columns: SELECT_FIELDS (22 per side, all materialised per row) + non-SELECT_FIELDS columns df.{source_file,switches}; f.{source_file,switches}
- (b) equi-join keys: `f.switches=df.switches`
- (c) other predicates: `df.switches != '[]'`; `f.nodes > 5`; `df.nodes > 5`
- (d) default config: yes; Partial tier, position 8 of 27 (runs 41,40,39,35→12)
- (e) cost: userenv 0 rows, SQL 0.002 s, native 0.006 s; sechost 22 rows, SQL 0.126 s, native 0.154 s
- (f) order: row order = plan order; U: `SEARCH df USING INDEX idx_7 (nodes>?) | SEARCH f USING INDEX idx_7 (nodes>?) | USE TEMP B-TREE FOR ORDER BY`; S: `SEARCH f USING INDEX idx_7 (nodes>?) | SEARCH df USING INDEX idx_22 (switches=?) | USE TEMP B-TREE FOR ORDER BY` (plan text differs from U); ORDER BY is a stable partition relative to the ORDER BY query's own plan (02-matching.md:1444, 04a:815-819); RatioMax: 1,000,000 fetched-row cap counting rejected rows; an error truncates the heuristic at that row (Consumer.cpp:137-181, HeuristicTiers.cpp:153-163)
- idea probe (projection cut to ea, ea2): U plan same, (ea,ea2) sequence same, 0.003→0.003 s; S plan same, (ea,ea2) sequence same, 0.126→0.123 s

#### H32 Pseudo-code fuzzy (normal)

- source: `src/diff/RegistrySql.inc:1696` (H:777-791), Partial / RatioMax min 0.5, flags "[]"; descriptor `[2 tables, 50 columns, DISTINCT, ORDER BY]`
- (a) tables: diff.functions, main.functions. columns: SELECT_FIELDS (22 per side, all materialised per row) + non-SELECT_FIELDS columns df.{pseudocode_hash1,pseudocode_lines,source_file}; f.{pseudocode_hash1,pseudocode_lines,source_file}
- (b) equi-join keys: `f.pseudocode_hash1=df.pseudocode_hash1`
- (c) other predicates: `f.pseudocode_lines > 5`; `df.pseudocode_lines > 5`
- (d) default config: yes; Partial tier, position 7 of 27 (runs 41,40,39,35→12)
- (e) cost: userenv 0 rows, SQL 0.000 s, native 0.006 s; sechost 0 rows, SQL 0.005 s, native 0.148 s
- (f) order: row order = plan order; U: `SEARCH df USING INDEX idx_9 (pseudocode_lines>?) | SEARCH f USING INDEX idx_13 (pseudocode_hash1=?) | USE TEMP B-TREE FOR DISTINCT | USE TEMP B-TREE FOR ORDER BY`; S: same plan; DISTINCT keeps the first occurrence in scan order; ORDER BY is a stable partition relative to the ORDER BY query's own plan (02-matching.md:1444, 04a:815-819); RatioMax: 1,000,000 fetched-row cap counting rejected rows; an error truncates the heuristic at that row (Consumer.cpp:137-181, HeuristicTiers.cpp:153-163)
- idea probe (projection cut to ea, ea2): U plan same, (ea,ea2) sequence same, 0.003→0.000 s; S plan same, (ea,ea2) sequence same, 0.005→0.005 s

#### H33 Pseudo-code fuzzy (mixed)

- source: `src/diff/RegistrySql.inc:1743` (H:793-806), Partial / Ratio, flags "[]"; descriptor `[2 tables, 50 columns, DISTINCT, ORDER BY]`
- (a) tables: diff.functions, main.functions. columns: SELECT_FIELDS (22 per side, all materialised per row) + non-SELECT_FIELDS columns df.{pseudocode_hash3,pseudocode_lines,source_file}; f.{pseudocode_hash3,pseudocode_lines,source_file}
- (b) equi-join keys: `f.pseudocode_hash3=df.pseudocode_hash3`
- (c) other predicates: `f.pseudocode_lines > 5`; `df.pseudocode_lines > 5`
- (d) default config: yes; Partial tier, position 6 of 27 (runs 41,40,39,35→12)
- (e) cost: userenv 0 rows, SQL 0.073 s, native 0.087 s; sechost 0 rows, SQL 0.005 s, native 0.115 s
- (f) order: row order = plan order; U: `SEARCH f USING INDEX idx_9 (pseudocode_lines>?) | SEARCH df USING INDEX idx_9 (pseudocode_lines>?) | USE TEMP B-TREE FOR DISTINCT | USE TEMP B-TREE FOR ORDER BY`; S: `SEARCH df USING INDEX idx_9 (pseudocode_lines>?) | SEARCH f USING INDEX idx_12 (pseudocode_hash3=?) | USE TEMP B-TREE FOR DISTINCT | USE TEMP B-TREE FOR ORDER BY` (plan text differs from U); DISTINCT keeps the first occurrence in scan order; ORDER BY is a stable partition relative to the ORDER BY query's own plan (02-matching.md:1444, 04a:815-819); Ratio: 1,000,000 fetched-row cap counting rejected rows; an error truncates the heuristic at that row (Consumer.cpp:137-181, HeuristicTiers.cpp:153-163)
- idea probe (projection cut to ea, ea2): U plan same, (ea,ea2) sequence same, 0.101→0.102 s; S plan same, (ea,ea2) sequence same, 0.005→0.005 s

#### H34 Pseudo-code fuzzy (reverse)

- source: `src/diff/RegistrySql.inc:1790` (H:808-821), Partial / Ratio, flags "[]"; descriptor `[2 tables, 50 columns, DISTINCT, ORDER BY]`
- (a) tables: diff.functions, main.functions. columns: SELECT_FIELDS (22 per side, all materialised per row) + non-SELECT_FIELDS columns df.{pseudocode_hash2,pseudocode_lines,source_file}; f.{pseudocode_hash2,pseudocode_lines,source_file}
- (b) equi-join keys: `f.pseudocode_hash2=df.pseudocode_hash2`
- (c) other predicates: `f.pseudocode_lines > 5`; `df.pseudocode_lines > 5`
- (d) default config: yes; Partial tier, position 5 of 27 (runs 41,40,39,35→12)
- (e) cost: userenv 0 rows, SQL 0.073 s, native 0.090 s; sechost 0 rows, SQL 0.005 s, native 0.021 s
- (f) order: row order = plan order; U: `SEARCH f USING INDEX idx_9 (pseudocode_lines>?) | SEARCH df USING INDEX idx_9 (pseudocode_lines>?) | USE TEMP B-TREE FOR DISTINCT | USE TEMP B-TREE FOR ORDER BY`; S: `SEARCH df USING INDEX idx_9 (pseudocode_lines>?) | SEARCH f USING INDEX idx_11 (pseudocode_hash2=?) | USE TEMP B-TREE FOR DISTINCT | USE TEMP B-TREE FOR ORDER BY` (plan text differs from U); DISTINCT keeps the first occurrence in scan order; ORDER BY is a stable partition relative to the ORDER BY query's own plan (02-matching.md:1444, 04a:815-819); Ratio: 1,000,000 fetched-row cap counting rejected rows; an error truncates the heuristic at that row (Consumer.cpp:137-181, HeuristicTiers.cpp:153-163)
- idea probe (projection cut to ea, ea2): U plan same, (ea,ea2) sequence same, 0.102→0.104 s; S plan same, (ea,ea2) sequence same, 0.005→0.005 s

#### H35 Pseudo-code fuzzy AST hash

- source: `src/diff/RegistrySql.inc:1837` (H:823-838), Partial / RatioMax min 0.35, flags "[]"; descriptor `[2 tables, 47 columns, DISTINCT, ORDER BY]`
- (a) tables: diff.functions, main.functions. columns: SELECT_FIELDS (22 per side, all materialised per row) + non-SELECT_FIELDS columns df.{source_file}; f.{pseudocode_lines,source_file}
- (b) equi-join keys: `f.pseudocode_primes=df.pseudocode_primes`
- (c) other predicates: `f.pseudocode_lines >= 3`; `length(f.pseudocode_primes) >= 35`
- (d) default config: yes; Partial tier, position 4 of 27 (runs 41,40,39,35→12)
- (e) cost: userenv 354 rows, SQL 0.058 s, native 0.092 s; sechost 1301 rows, SQL 0.141 s, native 0.526 s
- (f) order: row order = plan order; U: `SEARCH f USING INDEX idx_9 (pseudocode_lines>?) | SEARCH df USING AUTOMATIC COVERING INDEX (pseudocode_primes=?) | USE TEMP B-TREE FOR DISTINCT | USE TEMP B-TREE FOR ORDER BY`; S: same plan; uses an AUTOMATIC index: tie order inside a key follows the auto-index column list, which depends on the projection; DISTINCT keeps the first occurrence in scan order; ORDER BY is a stable partition relative to the ORDER BY query's own plan (02-matching.md:1444, 04a:815-819); RatioMax: 1,000,000 fetched-row cap counting rejected rows; an error truncates the heuristic at that row (Consumer.cpp:137-181, HeuristicTiers.cpp:153-163)
- idea probe (projection cut to ea, ea2): U plan same, (ea,ea2) sequence DIFFERENT, 0.160→0.010 s; S plan same, (ea,ea2) sequence DIFFERENT, 0.141→0.026 s

#### H36 Partial pseudo-code fuzzy hash (normal)

- source: `src/diff/RegistrySql.inc:1885` (H:840-854), Partial / RatioMax min 0.5, flags "[2, 1]"; descriptor `[2 tables, 48 columns, DISTINCT, ORDER BY]`
- (a) tables: diff.functions, main.functions. columns: SELECT_FIELDS (22 per side, all materialised per row) + non-SELECT_FIELDS columns df.{pseudocode_hash1,source_file}; f.{pseudocode_hash1,source_file}
- (b) equi-join keys: `(no conjunctive equi-join key)`
- (c) other predicates: `substr(df.pseudocode_hash1, 1, 16) = substr(f.pseudocode_hash1, 1, 16)`; `f.nodes > 5`; `df.nodes > 5`
- (d) default config: no (FLAG unreliable, C:46); never runs in the parity engine (DiffConfig::Supported refuses Unreliable=true, Config.h:55-58)
- (e) cost: userenv 0 rows, SQL 0.011 s, native - s; sechost 3 rows, SQL 2.070 s, native - s
- (f) order: row order = plan order; U: `SEARCH f USING INDEX idx_7 (nodes>?) | SEARCH df USING INDEX idx_7 (nodes>?) | USE TEMP B-TREE FOR DISTINCT | USE TEMP B-TREE FOR ORDER BY`; S: same plan; DISTINCT keeps the first occurrence in scan order; ORDER BY is a stable partition relative to the ORDER BY query's own plan (02-matching.md:1444, 04a:815-819); RatioMax: 1,000,000 fetched-row cap counting rejected rows; an error truncates the heuristic at that row (Consumer.cpp:137-181, HeuristicTiers.cpp:153-163)
- idea probe (projection cut to ea, ea2): U plan same, (ea,ea2) sequence same, 0.016→0.016 s; S plan same, (ea,ea2) sequence same, 2.070→2.129 s

#### H37 Partial pseudo-code fuzzy hash (reverse)

- source: `src/diff/RegistrySql.inc:1932` (H:856-870), Partial / RatioMax min 0.5, flags "[2, 1]"; descriptor `[2 tables, 48 columns, DISTINCT, ORDER BY]`
- (a) tables: diff.functions, main.functions. columns: SELECT_FIELDS (22 per side, all materialised per row) + non-SELECT_FIELDS columns df.{pseudocode_hash2,source_file}; f.{pseudocode_hash2,source_file}
- (b) equi-join keys: `(no conjunctive equi-join key)`
- (c) other predicates: `substr(df.pseudocode_hash2, 1, 16) = substr(f.pseudocode_hash2, 1, 16)`; `f.nodes > 5`; `df.nodes > 5`
- (d) default config: no (FLAG unreliable, C:46); never runs in the parity engine (DiffConfig::Supported refuses Unreliable=true, Config.h:55-58)
- (e) cost: userenv 0 rows, SQL 0.011 s, native - s; sechost 0 rows, SQL 2.077 s, native - s
- (f) order: row order = plan order; U: `SEARCH f USING INDEX idx_7 (nodes>?) | SEARCH df USING INDEX idx_7 (nodes>?) | USE TEMP B-TREE FOR DISTINCT | USE TEMP B-TREE FOR ORDER BY`; S: same plan; DISTINCT keeps the first occurrence in scan order; ORDER BY is a stable partition relative to the ORDER BY query's own plan (02-matching.md:1444, 04a:815-819); RatioMax: 1,000,000 fetched-row cap counting rejected rows; an error truncates the heuristic at that row (Consumer.cpp:137-181, HeuristicTiers.cpp:153-163)
- idea probe (projection cut to ea, ea2): U plan same, (ea,ea2) sequence same, 0.016→0.017 s; S plan same, (ea,ea2) sequence same, 2.077→1.987 s

#### H38 Partial pseudo-code fuzzy hash (mixed)

- source: `src/diff/RegistrySql.inc:1979` (H:872-886), Partial / RatioMax min 0.5, flags "[2, 1]"; descriptor `[2 tables, 48 columns, DISTINCT, ORDER BY]`
- (a) tables: diff.functions, main.functions. columns: SELECT_FIELDS (22 per side, all materialised per row) + non-SELECT_FIELDS columns df.{pseudocode_hash3,source_file}; f.{pseudocode_hash3,source_file}
- (b) equi-join keys: `(no conjunctive equi-join key)`
- (c) other predicates: `substr(df.pseudocode_hash3, 1, 16) = substr(f.pseudocode_hash3, 1, 16)`; `f.nodes > 5`; `df.nodes > 5`
- (d) default config: no (FLAG unreliable, C:46); never runs in the parity engine (DiffConfig::Supported refuses Unreliable=true, Config.h:55-58)
- (e) cost: userenv 0 rows, SQL 0.011 s, native - s; sechost 1 rows, SQL 1.970 s, native - s
- (f) order: row order = plan order; U: `SEARCH f USING INDEX idx_7 (nodes>?) | SEARCH df USING INDEX idx_7 (nodes>?) | USE TEMP B-TREE FOR DISTINCT | USE TEMP B-TREE FOR ORDER BY`; S: same plan; DISTINCT keeps the first occurrence in scan order; ORDER BY is a stable partition relative to the ORDER BY query's own plan (02-matching.md:1444, 04a:815-819); RatioMax: 1,000,000 fetched-row cap counting rejected rows; an error truncates the heuristic at that row (Consumer.cpp:137-181, HeuristicTiers.cpp:153-163)
- idea probe (projection cut to ea, ea2): U plan same, (ea,ea2) sequence same, 0.018→0.017 s; S plan same, (ea,ea2) sequence same, 1.970→1.936 s

#### H39 Same rare assembly instruction

- source: `src/diff/RegistrySql.inc:2026` (H:888-934), Partial / RatioMax min 0.5, flags "[3]"; descriptor `[4 tables, 50 columns, CTEs]`
- (a) tables: diff.functions, diff.instructions, main.functions, main.instructions. columns: SELECT_FIELDS (22 per side, all materialised per row) + non-SELECT_FIELDS columns df.{id}; diff_asm.{disasm,id}; f.{id}; inst.{disasm,func_id}; main_asm.{disasm,id}; query1.{diff_func_id,main_func_id}
- (b) equi-join keys: `f.id=cte:query1.main_func_id & df.id=cte:query1.diff_func_id`
- (c) other predicates (outer query): `f.name != df.name`; `((min(f.nodes, df.nodes) * 100) / max(f.nodes, df.nodes)) < 50`
- (c) rarity / CTE predicates: `main_asm` / `diff_asm`: `instructions ⋈ functions` on `f.id = inst.func_id`, `f.name not like 'nullsub%'`, `inst.disasm is not null and != ''`, `group by inst.disasm having count(0) = 1` (bare columns `f.id, f.name` of the single row); `query1` = DISTINCT `(main_asm.id, diff_asm.id)` on equal `disasm`
- (d) default config: yes if same CPU; Partial tier, position 3 of 27 (runs 41,40,39,35→12)
- (e) cost: userenv 44 rows, SQL 0.712 s, native 0.348 s; sechost 60 rows, SQL 1.400 s, native 1.587 s
- (f) order: row order = plan order; U: `CO-ROUTINE query1 | CO-ROUTINE main_asm | SCAN inst | BLOOM FILTER ON f (id=?) | SEARCH f USING INTEGER PRIMARY KEY (rowid=?) | USE TEMP B-TREE FOR GROUP BY | MATERIALIZE diff_asm | SCAN inst | BLOOM FILTER ON f (id=?) | SEARCH f USING INTEGER PRIMARY KEY (rowid=?) | USE TEMP B-TREE FOR GROUP BY | SCAN main_asm | SEARCH diff_asm USING AUTOMATIC COVERING INDEX (disasm=?) | USE TEMP B-TREE FOR DISTINCT | SCAN query1 | SEARCH f USING INTEGER PRIMARY KEY (rowid=?) | SEARCH df USING INTEGER PRIMARY KEY (rowid=?)`; S: same plan; uses an AUTOMATIC index: tie order inside a key follows the auto-index column list, which depends on the projection; CTE: GROUP BY bare-column values and GROUP_CONCAT order come from the CTE scan order (idx_33 / rowid); RatioMax: 1,000,000 fetched-row cap counting rejected rows; an error truncates the heuristic at that row (Consumer.cpp:137-181, HeuristicTiers.cpp:153-163)
- idea probe (projection cut to ea, ea2): U plan same, (ea,ea2) sequence same, 0.434→0.331 s; S plan same, (ea,ea2) sequence same, 1.400→1.340 s

#### H40 Same rare basic block mnemonics list

- source: `src/diff/RegistrySql.inc:2104` (H:936-979), Partial / RatioMax min 0.5, flags "[]"; descriptor `[6 tables, 56 columns, CTEs]`
- (a) tables: diff.bb_instructions, diff.functions, diff.instructions, main.bb_instructions, main.functions, main.instructions. columns: SELECT_FIELDS (22 per side, all materialised per row) + non-SELECT_FIELDS columns bb.{basic_block_id,instruction_id}; df.{id}; diff_query.{func_id,inst_total,mnemonics_list}; f.{id}; inst.{func_id,id,mnemonic}; main_query.{func_id,mnemonics_list}
- (b) equi-join keys: `f.id=cte:unique_main_bblocks.func_id & df.id=cte:diff_bblocks.func_id & cte:diff_bblocks.mnemonics_list=cte:unique_main_bblocks.mnemonics_list`
- (c) other predicates (outer query): `f.nodes > 3`; `df.nodes > 3`; `diff_query.inst_total >= 6`; `((min(f.nodes, df.nodes) * 100) / max(f.nodes, df.nodes)) < 50`
- (c) rarity / CTE predicates: `main_bblocks` / `diff_bblocks`: `bb_instructions ⋈ instructions` on `bb.instruction_id = inst.id`, `group by bb_id` with `GROUP_CONCAT(inst.mnemonic)` and `count(0) inst_total` (bare column `inst.func_id`); `unique_main_bblocks`: `group by mnemonics_list having count(0) = 1 order by total asc`; outer `diff_query.inst_total >= 6`
- (d) default config: yes; Partial tier, position 2 of 27 (runs 41,40,39,35→12)
- (e) cost: userenv 11 rows, SQL 0.091 s, native 0.139 s; sechost 1 rows, SQL 0.451 s, native 0.666 s
- (f) order: row order = plan order; U: `CO-ROUTINE unique_main_bblocks | CO-ROUTINE main_bblocks | SCAN bb USING COVERING INDEX idx_33 | SEARCH inst USING INTEGER PRIMARY KEY (rowid=?) | SCAN main_bblocks | USE TEMP B-TREE FOR GROUP BY | USE TEMP B-TREE FOR ORDER BY | MATERIALIZE diff_bblocks | SCAN bb USING COVERING INDEX idx_33 | SEARCH inst USING INTEGER PRIMARY KEY (rowid=?) | SCAN diff_query | SEARCH df USING INTEGER PRIMARY KEY (rowid=?) | BLOOM FILTER ON main_query (mnemonics_list=?) | SEARCH main_query USING AUTOMATIC COVERING INDEX (mnemonics_list=?) | SEARCH f USING INTEGER PRIMARY KEY (rowid=?)`; S: same plan; uses an AUTOMATIC index: tie order inside a key follows the auto-index column list, which depends on the projection; CTE: GROUP BY bare-column values and GROUP_CONCAT order come from the CTE scan order (idx_33 / rowid); RatioMax: 1,000,000 fetched-row cap counting rejected rows; an error truncates the heuristic at that row (Consumer.cpp:137-181, HeuristicTiers.cpp:153-163)
- idea probe (projection cut to ea, ea2): U plan same, (ea,ea2) sequence same, 0.133→0.128 s; S plan same, (ea,ea2) sequence same, 0.451→0.413 s

#### H41 Loop count

- source: `src/diff/RegistrySql.inc:2179` (H:981-996), Partial / RatioMax min 0.49, flags "[2]"; descriptor `[2 tables, 46 columns, ORDER BY]`
- (a) tables: diff.functions, main.functions. columns: SELECT_FIELDS (22 per side, all materialised per row) + non-SELECT_FIELDS columns df.{source_file}; f.{source_file}
- (b) equi-join keys: `f.loops=df.loops`
- (c) other predicates: `df.loops > 1`; `f.nodes >= 3`; `df.nodes >= 3`
- (d) default config: yes; Partial tier, position 1 of 27 (runs 41,40,39,35→12)
- (e) cost: userenv 365 rows, SQL 0.050 s, native 0.064 s; sechost 2551 rows, SQL 0.304 s, native 1.177 s
- (f) order: row order = plan order; U: `SEARCH f USING INDEX idx_16 (loops>?) | SEARCH df USING INDEX idx_16 (loops=?) | USE TEMP B-TREE FOR ORDER BY`; S: same plan; ORDER BY is a stable partition relative to the ORDER BY query's own plan (02-matching.md:1444, 04a:815-819); RatioMax: 1,000,000 fetched-row cap counting rejected rows; an error truncates the heuristic at that row (Consumer.cpp:137-181, HeuristicTiers.cpp:153-163)
- idea probe (projection cut to ea, ea2): U plan same, (ea,ea2) sequence same, 0.065→0.001 s; S plan same, (ea,ea2) sequence same, 0.304→0.008 s

#### H42 Same graph

- source: `src/diff/RegistrySql.inc:2227` (H:998-1031), Unreliable / RatioMax min 0.5, flags "[]"; descriptor `[2 tables, 62 columns, ORDER BY]`
- (a) tables: diff.functions, main.functions. columns: SELECT_FIELDS (22 per side, all materialised per row) + non-SELECT_FIELDS columns df.{mnemonics,names,primes_value,prototype2,pseudocode_hash1,pseudocode_hash2,pseudocode_hash3,strongly_connected_spp,tarjan_topological_sort}; f.{mnemonics,names,primes_value,prototype2,pseudocode_hash1,pseudocode_hash2,pseudocode_hash3,strongly_connected_spp,tarjan_topological_sort}
- (b) equi-join keys: `f.cyclomatic_complexity=df.cyclomatic_complexity & f.edges=df.edges & f.indegree=df.indegree & f.loops=df.loops & f.nodes=df.nodes & f.outdegree=df.outdegree & f.strongly_connected=df.strongly_connected & f.strongly_connected_spp=df.strongly_connected_spp & f.tarjan_topological_sort=df.tarjan_topological_sort`
- (c) other predicates: `f.nodes > 5`; `df.nodes > 5`
- (d) default config: no (Unreliable tier not run, D:3638-3651); never runs in the parity engine (DiffConfig::Supported refuses Unreliable=true, Config.h:55-58)
- (e) cost: userenv 277 rows, SQL 0.036 s, native - s; sechost 1060 rows, SQL 0.090 s, native - s
- (f) order: row order = plan order; U: `SEARCH f USING INDEX idx_7 (nodes>?) | SEARCH df USING INDEX idx_18 (tarjan_topological_sort=?) | USE TEMP B-TREE FOR ORDER BY`; S: same plan; ORDER BY is a stable partition relative to the ORDER BY query's own plan (02-matching.md:1444, 04a:815-819); RatioMax: 1,000,000 fetched-row cap counting rejected rows; an error truncates the heuristic at that row (Consumer.cpp:137-181, HeuristicTiers.cpp:153-163)
- idea probe (projection cut to ea, ea2): U plan same, (ea,ea2) sequence same, 0.045→0.008 s; S plan same, (ea,ea2) sequence same, 0.090→0.023 s

#### H43 Strongly connected components

- source: `src/diff/RegistrySql.inc:2293` (H:1036-1054), Unreliable / RatioMax min 0.8, flags "[2]"; descriptor `[2 tables, 48 columns, ORDER BY]`
- (a) tables: diff.functions, main.functions. columns: SELECT_FIELDS (22 per side, all materialised per row) + non-SELECT_FIELDS columns df.{source_file,strongly_connected_spp}; f.{source_file,strongly_connected_spp}
- (b) equi-join keys: `f.strongly_connected=df.strongly_connected`
- (c) other predicates: `df.strongly_connected > 1`; `f.nodes > 5`; `df.nodes > 5`; `f.strongly_connected_spp > 1`; `df.strongly_connected_spp > 1`
- (d) default config: no (Unreliable tier not run, D:3638-3651); never runs in the parity engine (DiffConfig::Supported refuses Unreliable=true, Config.h:55-58)
- (e) cost: userenv 219 rows, SQL 0.027 s, native - s; sechost 3309 rows, SQL 0.168 s, native - s
- (f) order: row order = plan order; U: `SEARCH f USING INDEX idx_14 (strongly_connected>?) | SEARCH df USING INDEX idx_14 (strongly_connected=?) | USE TEMP B-TREE FOR ORDER BY`; S: same plan; ORDER BY is a stable partition relative to the ORDER BY query's own plan (02-matching.md:1444, 04a:815-819); RatioMax: 1,000,000 fetched-row cap counting rejected rows; an error truncates the heuristic at that row (Consumer.cpp:137-181, HeuristicTiers.cpp:153-163)
- idea probe (projection cut to ea, ea2): U plan same, (ea,ea2) sequence same, 0.038→0.009 s; S plan same, (ea,ea2) sequence same, 0.168→0.032 s

#### H44 Nodes, edges, complexity and mnemonics

- source: `src/diff/RegistrySql.inc:2344` (H:1059-1075), Unreliable / Ratio, flags "[2]"; descriptor `[2 tables, 48 columns, DISTINCT, ORDER BY]`
- (a) tables: diff.functions, main.functions. columns: SELECT_FIELDS (22 per side, all materialised per row) + non-SELECT_FIELDS columns df.{mnemonics,source_file}; f.{mnemonics,source_file}
- (b) equi-join keys: `f.cyclomatic_complexity=df.cyclomatic_complexity & f.edges=df.edges & f.mnemonics=df.mnemonics & f.nodes=df.nodes`
- (c) other predicates: `f.nodes > 1`; `f.edges > 0`
- (d) default config: no (Unreliable tier not run, D:3638-3651); never runs in the parity engine (DiffConfig::Supported refuses Unreliable=true, Config.h:55-58)
- (e) cost: userenv 4019 rows, SQL 0.370 s, native - s; sechost 7059 rows, SQL 0.218 s, native - s
- (f) order: row order = plan order; U: `SEARCH df USING INDEX idx_7 (nodes>?) | SEARCH f USING INDEX idx_5 (nodes=? AND edges=? AND mnemonics=?) | USE TEMP B-TREE FOR DISTINCT | USE TEMP B-TREE FOR ORDER BY`; S: `SEARCH f USING INDEX idx_7 (nodes>?) | SEARCH df USING INDEX idx_5 (nodes=? AND edges=? AND mnemonics=?) | USE TEMP B-TREE FOR DISTINCT | USE TEMP B-TREE FOR ORDER BY` (plan text differs from U); DISTINCT keeps the first occurrence in scan order; ORDER BY is a stable partition relative to the ORDER BY query's own plan (02-matching.md:1444, 04a:815-819); Ratio: 1,000,000 fetched-row cap counting rejected rows; an error truncates the heuristic at that row (Consumer.cpp:137-181, HeuristicTiers.cpp:153-163)
- idea probe (projection cut to ea, ea2): U plan same, (ea,ea2) sequence same, 0.256→0.018 s; S plan CHANGED, (ea,ea2) sequence DIFFERENT, 0.218→0.047 s

#### H45 Nodes, edges, complexity and prototype

- source: `src/diff/RegistrySql.inc:2394` (H:1081-1097), Unreliable / Ratio, flags "[2]"; descriptor `[2 tables, 48 columns, DISTINCT, ORDER BY]`
- (a) tables: diff.functions, main.functions. columns: SELECT_FIELDS (22 per side, all materialised per row) + non-SELECT_FIELDS columns df.{prototype2,source_file}; f.{prototype2,source_file}
- (b) equi-join keys: `f.cyclomatic_complexity=df.cyclomatic_complexity & f.edges=df.edges & f.nodes=df.nodes & f.prototype2=df.prototype2`
- (c) other predicates: `f.prototype2 != 'int()'`
- (d) default config: no (Unreliable tier not run, D:3638-3651); never runs in the parity engine (DiffConfig::Supported refuses Unreliable=true, Config.h:55-58)
- (e) cost: userenv 2974 rows, SQL 0.168 s, native - s; sechost 7519 rows, SQL 0.297 s, native - s
- (f) order: row order = plan order; U: `SCAN df | SEARCH f USING INDEX idx_7 (nodes=? AND edges=? AND cyclomatic_complexity=?) | USE TEMP B-TREE FOR DISTINCT | USE TEMP B-TREE FOR ORDER BY`; S: `SCAN f | SEARCH df USING INDEX idx_7 (nodes=? AND edges=? AND cyclomatic_complexity=?) | USE TEMP B-TREE FOR DISTINCT | USE TEMP B-TREE FOR ORDER BY` (plan text differs from U); DISTINCT keeps the first occurrence in scan order; ORDER BY is a stable partition relative to the ORDER BY query's own plan (02-matching.md:1444, 04a:815-819); Ratio: 1,000,000 fetched-row cap counting rejected rows; an error truncates the heuristic at that row (Consumer.cpp:137-181, HeuristicTiers.cpp:153-163)
- idea probe (projection cut to ea, ea2): U plan same, (ea,ea2) sequence same, 0.206→0.039 s; S plan same, (ea,ea2) sequence same, 0.297→0.145 s

#### H46 Nodes, edges, complexity, in-degree and out-degree

- source: `src/diff/RegistrySql.inc:2444` (H:1102-1119), Unreliable / Ratio, flags "[2]"; descriptor `[2 tables, 46 columns, DISTINCT, ORDER BY]`
- (a) tables: diff.functions, main.functions. columns: SELECT_FIELDS (22 per side, all materialised per row) + non-SELECT_FIELDS columns df.{source_file}; f.{source_file}
- (b) equi-join keys: `f.cyclomatic_complexity=df.cyclomatic_complexity & f.edges=df.edges & f.indegree=df.indegree & f.nodes=df.nodes & f.outdegree=df.outdegree`
- (c) other predicates: `f.nodes >= 3`; `f.edges > 2`
- (d) default config: no (Unreliable tier not run, D:3638-3651); never runs in the parity engine (DiffConfig::Supported refuses Unreliable=true, Config.h:55-58)
- (e) cost: userenv 1456 rows, SQL 0.157 s, native - s; sechost 3709 rows, SQL 0.230 s, native - s
- (f) order: row order = plan order; U: `SEARCH f USING INDEX idx_7 (nodes>?) | SEARCH df USING INDEX idx_5 (nodes=? AND edges>?) | USE TEMP B-TREE FOR DISTINCT | USE TEMP B-TREE FOR ORDER BY`; S: same plan; DISTINCT keeps the first occurrence in scan order; ORDER BY is a stable partition relative to the ORDER BY query's own plan (02-matching.md:1444, 04a:815-819); Ratio: 1,000,000 fetched-row cap counting rejected rows; an error truncates the heuristic at that row (Consumer.cpp:137-181, HeuristicTiers.cpp:153-163)
- idea probe (projection cut to ea, ea2): U plan same, (ea,ea2) sequence same, 0.160→0.021 s; S plan same, (ea,ea2) sequence same, 0.230→0.050 s

#### H47 Nodes, edges and complexity

- source: `src/diff/RegistrySql.inc:2495` (H:1124-1139), Unreliable / Ratio, flags "[2]"; descriptor `[2 tables, 46 columns, DISTINCT, ORDER BY]`
- (a) tables: diff.functions, main.functions. columns: SELECT_FIELDS (22 per side, all materialised per row) + non-SELECT_FIELDS columns df.{source_file}; f.{source_file}
- (b) equi-join keys: `f.cyclomatic_complexity=df.cyclomatic_complexity & f.edges=df.edges & f.nodes=df.nodes`
- (c) other predicates: `f.nodes > 1`; `f.edges > 0`
- (d) default config: no (Unreliable tier not run, D:3638-3651); never runs in the parity engine (DiffConfig::Supported refuses Unreliable=true, Config.h:55-58)
- (e) cost: userenv 20313 rows, SQL 1.684 s, native - s; sechost 49616 rows, SQL 1.580 s, native - s
- (f) order: row order = plan order; U: `SEARCH f USING INDEX idx_7 (nodes>?) | SEARCH df USING INDEX idx_5 (nodes=? AND edges>?) | USE TEMP B-TREE FOR DISTINCT | USE TEMP B-TREE FOR ORDER BY`; S: same plan; DISTINCT keeps the first occurrence in scan order; ORDER BY is a stable partition relative to the ORDER BY query's own plan (02-matching.md:1444, 04a:815-819); Ratio: 1,000,000 fetched-row cap counting rejected rows; an error truncates the heuristic at that row (Consumer.cpp:137-181, HeuristicTiers.cpp:153-163)
- idea probe (projection cut to ea, ea2): U plan same, (ea,ea2) sequence same, 1.296→0.062 s; S plan same, (ea,ea2) sequence same, 1.580→0.155 s

#### H48 Same high complexity

- source: `src/diff/RegistrySql.inc:2544` (H:1144-1157), Unreliable / Ratio, flags "[2]"; descriptor `[2 tables, 46 columns, ORDER BY]`
- (a) tables: diff.functions, main.functions. columns: SELECT_FIELDS (22 per side, all materialised per row) + non-SELECT_FIELDS columns df.{source_file}; f.{source_file}
- (b) equi-join keys: `f.cyclomatic_complexity=df.cyclomatic_complexity`
- (c) other predicates: `f.cyclomatic_complexity >= 50`
- (d) default config: no (Unreliable tier not run, D:3638-3651); never runs in the parity engine (DiffConfig::Supported refuses Unreliable=true, Config.h:55-58)
- (e) cost: userenv 59 rows, SQL 0.015 s, native - s; sechost 336 rows, SQL 0.051 s, native - s
- (f) order: row order = plan order; U: `SEARCH f USING INDEX idx_8 (cyclomatic_complexity>?) | SEARCH df USING INDEX idx_8 (cyclomatic_complexity=?) | USE TEMP B-TREE FOR ORDER BY`; S: `SEARCH df USING INDEX idx_8 (cyclomatic_complexity>?) | SEARCH f USING INDEX idx_8 (cyclomatic_complexity=?) | USE TEMP B-TREE FOR ORDER BY` (plan text differs from U); ORDER BY is a stable partition relative to the ORDER BY query's own plan (02-matching.md:1444, 04a:815-819); Ratio: 1,000,000 fetched-row cap counting rejected rows; an error truncates the heuristic at that row (Consumer.cpp:137-181, HeuristicTiers.cpp:153-163)
- idea probe (projection cut to ea, ea2): U plan same, (ea,ea2) sequence same, 0.024→0.002 s; S plan same, (ea,ea2) sequence same, 0.051→0.013 s

#### H49 Topological sort hash

- source: `src/diff/RegistrySql.inc:2591` (H:1162-1177), Unreliable / Ratio, flags "[]"; descriptor `[2 tables, 48 columns, ORDER BY]`
- (a) tables: diff.functions, main.functions. columns: SELECT_FIELDS (22 per side, all materialised per row) + non-SELECT_FIELDS columns df.{source_file,tarjan_topological_sort}; f.{source_file,tarjan_topological_sort}
- (b) equi-join keys: `f.strongly_connected=df.strongly_connected & f.tarjan_topological_sort=df.tarjan_topological_sort`
- (c) other predicates: `f.strongly_connected >= 3`; `f.nodes > 10`
- (d) default config: no (Unreliable tier not run, D:3638-3651); never runs in the parity engine (DiffConfig::Supported refuses Unreliable=true, Config.h:55-58)
- (e) cost: userenv 163 rows, SQL 0.029 s, native - s; sechost 583 rows, SQL 0.088 s, native - s
- (f) order: row order = plan order; U: `SEARCH f USING INDEX idx_14 (strongly_connected>?) | SEARCH df USING INDEX idx_18 (tarjan_topological_sort=?) | USE TEMP B-TREE FOR ORDER BY`; S: `SEARCH df USING INDEX idx_14 (strongly_connected>?) | SEARCH f USING INDEX idx_18 (tarjan_topological_sort=?) | USE TEMP B-TREE FOR ORDER BY` (plan text differs from U); ORDER BY is a stable partition relative to the ORDER BY query's own plan (02-matching.md:1444, 04a:815-819); Ratio: 1,000,000 fetched-row cap counting rejected rows; an error truncates the heuristic at that row (Consumer.cpp:137-181, HeuristicTiers.cpp:153-163)
- idea probe (projection cut to ea, ea2): U plan same, (ea,ea2) sequence same, 0.041→0.007 s; S plan same, (ea,ea2) sequence same, 0.088→0.034 s


---

## 6. Non-SQL passes

"Default" means the run type of both measured pairs, mode N: no stripped binary and no patch diff. Times are native wall seconds, summed over all loop iterations.

| pass | code | (a) tables / columns read | (b) keys / lookups | (c) other predicates / gates | (d) default | (e) U / S | (f) order constraints |
|---|---|---|---|---|---|---|---|
| **find_equal_matches** | `EqualMatches.cpp:41-120`; SQL `StageSql.inc:54` (totals), `:66` (INTERSECT) | `functions` both sides: `id, address, mangled_function, nodes, edges, size, bytes_hash`; count(*) | whole 7-tuple INTERSECT (including `id`) | `int(nodes)` raises on NULL (`:108-114`) | always | ~0.1 / 0.38 (with ingest); 0 / 4 rows | INTERSECT temp B-tree order (ascending by tuple, `id` first); fetchall before any use; first stage to write the state (Best, 1.0) |
| **apply_dirty_heuristics** (stripped → patch-diff) | `DirtyHeuristics.cpp:57-111`; SQL `StageSql.inc:94`, `:107`, `:145` | `address` join count; stripped rows = DISTINCT `SELECT_FIELDS` on `f.address = df.address`; `mangled_function` join count | `f.address = df.address`; `f.mangled_function = df.mangled_function` | stripped if ≥ 99% of `total1` (C:160); patch if > 90% (C:166); short-circuit | yes (`Experimental = true`, `Config.h:41`) | 0.02 / 0.32; counts U 30 / 60, S 883 / 228 of 643 / 1442, so neither fired | stripped rows go through `AddMatchesFromQueryRatio` on the main thread (a raise aborts the run); decides the mode (N/S/P) that picks the rest of the pipeline |
| **find_same_name** | `SameName.cpp:36-136`; SQL `StageSql.inc:158` | DISTINCT `SELECT_FIELDS`; `name`, `mangled_function` | `df.mangled_function = f.mangled_function OR df.name = f.name` (MULTI-INDEX OR on `idx_3` / `idx_2`) | `f.name not like 'nullsub_%'` (ASCII case-insensitive, `_` wildcard); skip `mangled1` starting with `sub_` (C:50) | yes (`IgnoreAllNames = false`) | 0.01 / 0.03; 60 / 228 rows | fetchall first; `all_functions_matched` evaluated once before the loop (`:76`); plan `SCAN f` then OR-index |
| **find_remaining_functions** | `RemainingFunctions.cpp:57-148`; SQL `StageSql.inc:240`, `:253` | UNION of `(db, name, address)`; per pair `SELECT_FIELDS` by address | `f.address = ? AND df.address = ?` (`idx_28`) | only in modes S/P (`SkipOthers`); main name must start with `sub_`; `nodes >= 3` | **not in mode N** (did not run on U or S) | 0 / 0 (UNION: 1271 / 2861 rows) | an O(\|main unmatched sub_\| × \|diff unmatched\|) loop of single-pair queries; the lists are snapshots; `val = 0.6` |
| **search_small_differences** | `SmallDifferences.cpp:183-235`; SQL `StageSql.inc:197` | `SELECT_FIELDS` + `f.names`, `df.names` (JSON) | `nodes, edges, mnemonics, cyclomatic_complexity` equal (same key set as H44) | `f.names != '[]'`; names-Jaccard ≥ 0.5 **before** `check_match`; `has_better_match` on the names ratio (`:212`) | yes (`SlowHeuristics = true`) | 0.07 / 0.17; 4806 / 7192 rows | `fetchmany(1000)` batch-loss semantics (`:51-160`); plan differs between pairs (U `SCAN df`, S `SCAN f`, then `idx_5`); main thread (a raise aborts) |
| **callee diffing** (find_matches_diffing) | `CalleeDiffing.cpp:305-362`; SQL `StageSql.inc:311`, `:321`, `:331` | `select *` by name (`idx_2`); in-memory `assembly` / `pseudocode` / `nodes` | name → row (`functions_exists` UNION of both names) | min/max nodes ≥ 25%; nodes ≥ 3; ratio == 1.0 → best, > 0.3 → partial (+0.01 bonus) | yes (assembly only when same CPU) | 4.11 / 10.63 | per best-then-partial sorted snapshot; `dones` shared by match keys and callee keys; up to 3 inner rounds with cleanup L3185 after each; a unified_diff hunk flushes only at a context row |
| **related constants** (find_related_matches) | `RelatedConstants.cpp:101-183`; SQL `StageSql.inc:374` | `functions.constants` (JSON), `constants_count`; 4-way join `f, df, mc, dc` with `mc.constant = ?` and `abs(mc.constant) == 0` | `mc.constant = dc.constant`, `mc.func_id = f.id`, `dc.func_id = df.id` (the **FG-1 join with a bound constant**) | seeds with ratio ≥ 0.8 (break per category); both `constants_count > 0` | yes | 1.26 / 1.95 | intersection iteration order is the documented set-order deviation (06 §8.3); each constant's rows go through `add_matches_internal` (1M cap each) |
| **related compilation unit** | `RelatedCompilationUnit.cpp:276-317`; SQL `StageSql.inc:417`, `:433`, `:449` | CU lookup by name (`cuf`, `cus`, `f`); native replay of `SCAN f` × `SCAN df` over `cast(address as real)` ranges | name → first CU (`start_ea`, `end_ea`) | seeds with ratio ≥ 0.8 (break of the **whole** loop); both lookups must hit | yes | **63.81 / 266.31** | per seed: f rows in range ascending by id (outer) × df rows ascending by id (inner); plan guard `SCAN f` / `SCAN df` (`:249-271`); no dedup across seeds; 1M cap per seed |
| **local affinity** | `LocalAffinity.cpp:138-293`; SQL `StageSql.inc:346`, `:360` | gap rows `select *` by address range (`idx_28`); in-memory name, `pseudocode_lines`, `nodes` | consecutive matches by `int(ea)`; `address > ? and address < ?` (TEXT, bytewise) | ≤ 100 rows per gap (C:124); nullsub / `sub_` filters; `pseudocode_lines` 3-rule; r == 1.0 best / ≥ 0.5 partial | yes | 0.30 / 1.03 | stable sort by `int()` keys; `order by address desc`; per-gap score maps are written even when `add_match` rejects |
| **final_pass** | `FinalPass.cpp:86-162` | in-memory items only | keyed by **address** pair text (not name) | max_main / max_diff running maxima | yes | 0.06 / 0.09 | categories best → partial → unreliable, stable sorted; multimatch dict insertion order; one shared `dones` |

**Shared lookups across passes:**

- `get_function_row` by name, in callee diffing and related constants, uses `idx_2` for every seed. An in-memory name → row map is possible but must keep the bare-`except` semantics (`CalleeDiffing.cpp:117-136`).
- The CU membership that the related-CU lookup uses is the same `compilation_unit_functions ⋈ compilation_units` data as FG-2.

---

## 7. Candidate fusion groups

"Shared key" means the conjunctive equi-join keys from `diff_tiers` (the list at the end of `diff_tiers_out.txt`). The costs are the sums over each group's **default-run** members (§4).

| group | members (default run) | shared data / key | native U s | native S s | SQL alone U / S s | projection-cut SQL U / S s | est. saving | parity risk |
|---|---|---|---:|---:|---|---|---|---|
| **FG-1 constants** | H15, H20, H21 (+ related-constants stage SQL) | `main.constants ⋈ diff.constants` on `constant` (U 6,014 / S 59,267 pairs), then `func_id → f.id / df.id`; extra `kgh_hash` (H15), `address` (H20), `nodes`, `constants_count` (H21) | 0.30 | **185.77** | 0.23 / 201.4 | 0.015 / 0.174 | **S ≈ 185 s (39% of the S run)**; U ≈ 0.3 s | medium |
| **FG-2 compilation units** | H12, H13, H14 (+ CU lookups of related CU) | `cuf.func_id = f.id`, `cuf.cu_id = cu.id` on both sides; `mcu.name = dcu.name` (H12, H13); `mcu.pseudocode_primes = dcu.pseudocode_primes` (H14) | **4.10** (H14 4.02, 0 rows) | 0.39 | 2.35 / 0.26 | 3.86 / 0.07 | **U ≈ 4 s (5%)**; S ≈ 0.3 s | medium-high |
| **FG-3 functions: hash / text equality** | H0-H11, H25, H27, H32-H35 | in-memory `FunctionTable`; key columns `bytes_hash` {H0, H1, H3}, `function_hash` {H2}, `address` / `rva` {H4, H8, H9}, `clean_*` {H5, H6, H7}, `pseudocode` / `assembly` {H10}, `microcode_spp` {H11}, `mnemonics_spp` {H27}, `pseudocode_hash1-3` {H25, H32, H33, H34}, `pseudocode_primes` {H35} | 0.84 | 3.74 | 0.36 / 2.98 | 0.33 / 0.41 | ≤ 3.3 s S | medium (12 of 18 plans differ U vs S) |
| **FG-4 functions: feature equality** | H16-H19, H22-H24, H26, H28-H31, H41, + small differences | `md_index` {H16, H19, H22, H23}, `kgh_hash` {H16, H18}, `names` {H23, H24, H26, H29, H30}, `constants` {H17, H22}, `nodes` / `edges` / `loops` / `strongly_connected` {H28, H41}, `(nodes, edges, mnemonics, cc)` {small differences} | 0.46 (+0.07) | 2.50 (+0.17) | 0.20 / 1.09 | 0.05 / 0.28 | ≤ 2.4 s S | medium (rare CTEs H18/H19 use GROUP BY / HAVING; H18 uses an AUTOMATIC index on U) |
| **FG-5 instruction-table CTEs** | H39, H40 | one scan of `main/diff.instructions` (U 124k / S 480k rows) + `bb_instructions`: H39 groups by `disasm` with `count = 1`; H40 does `GROUP_CONCAT(mnemonic)` per basic block | 0.49 | 2.25 | 0.80 / 1.85 | 0.46 / 1.75 | ≤ 2 s S | **high** (bare GROUP BY columns, GROUP_CONCAT order, AUTOMATIC covering index in both) |
| FG-0 never run | H36-H38, H42-H49 | - | - | - | 2.52 / 8.84 | - | none | - |

### FG-1 constants (H15, H20, H21): details

- **Plans.** All six plans (3 heuristics × 2 pairs) start with `SCAN mc` (main.constants in rowid order), then `f` by rowid. The inner loops differ:
  - H21: `dc` via `idx_35 (constant=?)`, then `df` by rowid.
  - H15: `df` via `idx_25 (kgh_hash=?)`, then `dc` covering `(constant=? AND func_id=?)`.
  - H20: `df` via `idx_28 (address=?)`, then the same `dc` covering search. After that, `DISTINCT` (first occurrence), then the stable ORDER BY partition on `f.source_file = df.source_file` (NULL, then 0, then 1).
  - S adds `BLOOM FILTER ON f/df`, which filters only.
  - In every member, the inner rows for one `mc` row therefore come in ascending `df.id` order: `dc.func_id` equals `df.id`, and both `idx_35` and `idx_25` end in rowid. **This is a hypothesis to prove, not a result.**
- **Duplicates are part of the result.** Measured on S:

  | member | raw rows | distinct `(ea, ea2)` pairs |
  |---|---:|---:|
  | H15 | 30,710 | 498 |
  | H21 | 58,236 | 9,129 |
  | H20 (before DISTINCT) | 30,080 | 273 |

  H15 and H21 have no DISTINCT, so every duplicate must be emitted at its position (§3.5).
- **Proof obligations:**
  - The `(raw row index, ea, ea2)` sequence and the raw row count equal Path A for every member on all 7 oracle pairs.
  - Fixtures for:
    - duplicate `(constant, func_id)` rows;
    - one constant shared by many functions on both sides;
    - NULL `kgh_hash`, `source_file` and `constant`;
    - H21 crossing the 1,000,000-row cap;
    - an invalid-UTF-8 row in the middle of a run of duplicates.
  - A plan-text guard on each member, falling back to Path A otherwise.
- **Cheapest first step, with no generator at all:** keep the verbatim WHERE and plan, and cut the projection for these three only. The probe gave the same plan and the same sequence on both pairs (§5, H15/H20/H21). That still counts as leaving "verbatim SQL", so it carries the same proof obligations.

### FG-2 compilation units (H12, H13, H14): details

- **Plans.**
  - U H14 is a 6-way nested loop: `f idx_7 (nodes>?)` → mcuf → mcu → `df idx_7 (nodes>?)` → dcuf → `dcu covering idx_37 (pseudocode_primes=? AND rowid=?)`. That probes about |f| × |df| pairs to return 0 rows (4.0 s).
  - S H14 picks `dcu idx_37 (pseudocode_primes=?)` → `dcuf idx_40 (cu_id=?)` (0.08 s).
  - The H12/H13 plans also differ between U and S: the bloom filter and the `main_cu` search move.
- **A native CU-pair hash join** on `pseudocode_primes` or `name` would make H14 cost almost nothing. It would then have to rebuild **each** plan's emission order: the nested loop of the driving `f` order through `idx_7 (nodes, edges, cc, rowid)`. It can share its CU membership maps with the related-CU lookups (`StageSql.inc:417`, `:433`).
- **Proof obligations:** the same as FG-1, plus CUs with an empty `name` (H12/H13 filter `!= ''`) and functions in several CUs.

### FG-3 / FG-4 functions-only joins: details

- **What is shared.** Every member reads only `main.functions` / `diff.functions`, which are already ingested column-wise (`Ingest.cpp:405`, `order by f.id`). A per-column hash index over `df` (or `f`), built once, can serve every member that keys on that column.
- **What is not shared.** The emission order is the plan's order, and 12 of the 18 FG-3 plans and 6 of the 13 FG-4 plans swap the driving side between U and S. The generator therefore needs a small "plan template → order" emulator per plan shape:
  - `SEARCH X USING INDEX idx_k (col>?)` then `SEARCH Y USING INDEX idx_j (key=?)`: order by (the index tuple of X, X rowid), then (the index tuple of Y, Y rowid).
  - `MULTI-INDEX OR` (H1, H2): the rowid set of the OR arms, then the inner search.
  - `AUTOMATIC PARTIAL COVERING INDEX` (H6): ties ordered by the auto-index column list.
  - DISTINCT, ORDER BY partition and UNION (H10) on top.
- **Measured payoff:** small, at most about 6 s on S and about 1.3 s on U. Do these only if the consuming program needs fast runs on big inputs, after FG-1 and the related-CU work.

### FG-5 instruction CTEs (H39, H40): details

- **What could be shared.** One pass over `instructions` / `bb_instructions` per side could build both the `disasm` histogram (H39) and the per-basic-block mnemonic lists (H40).
- **What must be reproduced:**
  - SQLite's `GROUP BY` bare-column choice (`f.id`, `f.name` of a `count(0) = 1` group, i.e. its only row);
  - the `GROUP_CONCAT` order (`bb` scanned through `idx_33 (basic_block_id, instruction_id)`, then `inst` by rowid);
  - H40's `group by bb_id` only;
  - the CTE `order by total asc`;
  - the AUTOMATIC covering indexes on `diff_asm (disasm=?)` and `main_query (mnemonics_list=?)`.
- **Payoff and risk:** about 2 s on S, high risk. Last.

---

## 8. Recommended order when fusion is approved

1. **Build the proof harness first.**
   - It dumps, per heuristic and per pair: `(raw row index, ea, ea2, description)` for every row Path A emits, the raw row count, the plan text, and the position and kind of the first error.
   - Every generator is then tested against it row for row.
   - The `--replay --stage heuristic:<id>` machinery (`Pipeline.cpp:678-762`) and `diff_foundation`'s row-sequence census already cover part of this.
2. **Related CU hot path** (§9 I-2a): no ordering change, and the largest share on both pairs.
3. **FG-1 constants:** −185 s on S. Start with the projection cut for H15/H20/H21 behind a plan guard, then decide whether a native generator is still worth it.
4. **FG-2 H14:** −4 s on U.
5. **Callee-diff memo** (§9 I-3): pure function, low risk.
6. **FG-3 / FG-4**, if they are ever needed.
7. **FG-5** last.

**Expected effect:**

- S: about 476 s, down to about 290 s after FG-1 alone. The rest is dominated by related CU.
- U: about 77 s, still dominated by related CU. These are estimates from the measured stage times, not measurements.

---

## 9. Speed ideas that are not fusion

These are ideas, not work items. None is implemented, and each would need its own proof.

- **I-1 Cut the projection inside Path A.**
  - Replace the 44-column `SELECT_FIELDS` by the aliases the consumer reads: `ea, name1, ea2, name2, description, nodes1/2, md1/2`, plus `mangled1` for same_name and `f_names/df_names` for small differences.
  - Measured, summed over the 39 default-run heuristics (`group_sums.py`): on S, about 208 s of SQL becomes about 2.7 s. On U it stays at about 4 s either way. H14's nested loop dominates there, and the output columns do not affect it.
  - The fetch-time UTF-8 check is already per row through `SelectFieldsUtf8Bad` (`Database.cpp:634-637`), so the raise position is kept.
  - **Measured hazards:**
    - The sequence changed for H2 (S, plan change), H10 (S, the UNION now dedupes on `(ea, ea2)` instead of the whole row), H35 (U and S, AUTOMATIC covering index tie order) and H44 (S, plan change).
    - The plan text changed for H10 on U, with the same sequence.
  - A safe version needs, per heuristic, the same plan text, no AUTOMATIC index on a table whose column set changes (H6, H18, H35, H39, H40 on at least one pair), and no UNION.
- **I-2 Related compilation unit.**
  - **(a) Per-row cost.**
    - Measured: about 6.3 M rows/s on U (180.8 M rows in 28.6 s) and about 8.3 M rows/s on S. Every row builds a `HeuristicRow` (`RelatedCompilationUnit.cpp:174-225`), then runs `check_match`:
      - two dict lookups (`has_best`);
      - a ratio-cache lookup in a `std::unordered_map<uint64_t, uint32_t>` (`Ratio.cpp:484-486, 529-544`);
      - `has_better`.
    - A dense `(row1, row2)` cache index for "simple" addresses, plus an allocation-free row path, keeps the order unchanged. It could reach several times the throughput. The throughput is measured; the gain is an estimate, not profiled.
  - **(b) Replay memo.** Seeds that map to the same `(range1, range2)` replay the same product:
    - U: 7 distinct pairs, 358,836 rows once vs 180.8 M replayed;
    - S: 60 pairs, 839,882 rows once vs about 708.8 M replayed.
    - Skipping a replay is sound only if it is provably a no-op on the state. It is not obviously one:
      - `add_match` rewrites the dicts last-writer-wins on duplicates (`MatchState.cpp:201-204`);
      - the named branch of `has_better_match` ignores ratios (`MatchState.cpp:147-150`);
      - seeds of different pairs interleave (ratio-sorted);
      - the trace would lose its `duplicate` add_match events.
    - Test it empirically first with `--replay` snapshots before and after a seed group.
- **I-3 Callee diffing.**
  - `CalleeCandidatePairs(main_text, diff_text)` (`CalleeDiffing.cpp:38-91`: splitlines, unified_diff, regex) is a pure function of immutable texts.
  - It is recomputed for every match, in every inner round (up to 3) and every outer iteration.
  - Memoising it by `(MainRow, DiffRow, field)` cannot change the order.
  - Callee diffing costs 4.1 s on U and 10.6 s on S. How much of that is the diff was not profiled.
- **I-4 SQLite indexes cannot be added.**
  - The inputs are opened as they are, and plans must stay the oracle's plans (`sqlite_stat1` included; 02 §18.3). An index added to a copy or a temp schema would change the plans, and with them the row order.
  - Only native, in-memory indexes (Path B) are possible, for example over `FunctionTable` and a constants table ingested on demand.
- **I-5 `pragma temp_store = memory`.**
  - The DISTINCT / ORDER BY temp B-trees of the fat joins spill to `%TEMP%` on C:, which was nearly full during this review (§10 F-2).
  - Keeping temp data in RAM changes storage, not the sort algorithm. It must still pass the row-sequence census (04a §6.4: the sorter is stable only single-threaded).
  - Mixed evidence: H20 on S took 82.6 s natively (disk temp) and 52.7 s in Python with temp in memory. Those were different processes under load, so this is not a clean comparison.
- **I-6 Wide hashing (AVX-512).**
  - The Path B equality keys are long texts: `clean_assembly`, `clean_pseudo`, `clean_microcode`, full `pseudocode` / `assembly` for H10, and the fuzzy hashes. Hashing each once at ingest with a vectorised 64-bit hash, then confirming with `memcmp`, makes the per-column hash indexes cheap.
  - The numeric range predicates (`nodes >= 3`, `instructions > 5`, `pseudocode_lines > 5`) over the ingested integer columns can use AVX-512 compare + compress to build the driving row lists.
  - The maintainer notes mention about 16× for hashing. That was measured on the legacy engine.
- **I-7 Precompute candidates in parallel.**
  - The candidate rows of every heuristic are independent of the match state.
  - They could be generated on separate read-only connections while consumption stays serial in reverse registry order.
  - Obligations: §3.2 (never surface a skipped heuristic's effects or errors) and §3.6 (keep error positions).
  - Worth doing only if I-1 or FG-1 are not done, because it then hides the constants joins.

---

## 10. Findings from this review

| # | severity | finding | evidence / reproduction | suggested fix | confidence |
|---|---|---|---|---|---|
| F-1 | **major** | **Environment failures of SQLite become a silent heuristic truncation with exit 0.** `Statement::Step` turns every code other than ROW/DONE into `DiaphoraWouldRaise("sqlite3_step", ...)` (`Database.cpp:84-94`). That covers SQLITE_FULL (temp spill), IOERR, NOMEM and BUSY. `StageRunSingleHeuristic` records a truncation and the category continues (`HeuristicTiers.cpp:153-163`). NO_FPS swallows it (`Consumer.cpp:229-233`). The only signal is an `Error: ...` stderr line (`HeuristicTiers.cpp:162`), which `--quiet` suppresses (`Trace.cpp:182-189`). The recorded `HeuristicTruncations` (`TiersDetail.h:36-42`) are never read by `src/cli` or `Pipeline.cpp`: `grep -rn "HeuristicTruncations\|Truncat" src/cli src/diff/Pipeline.cpp include` finds nothing. The consuming program gets fewer matches and exit 0. | Observed trigger: C: fell to 54 MB free. The same SQL through Python sqlite3 3.51.1 on the S copies then raised `OperationalError: database or disk is full` at H22 (scratch `merge_sechost.py` header; run log). The native S run happened not to hit it: its stderr has no `Error:` line. Repro recipe (not executed; needs a small temp volume): set `TMP`/`TEMP` to a nearly full volume and run `dsigmatcher diff sechost-9168-pdb.sqlite sechost-9444-nopdb.sqlite -o out.diaphora --quiet`. By the code, it exits 0 with H20/H15/H21 cut short. | Classify step errors. SQLITE_FULL, IOERR*, NOMEM, CANTOPEN, BUSY and LOCKED become an environment failure: exit 6, no output. Keep `DiaphoraWouldRaise` for data-driven errors (UTF-8, overflow, SQL logic). Also report any truncation in the outcome, as an exit-code bit or a summary line that `--quiet` does not hide. | high (code path); medium (that the native run hits it in practice) |
| F-2 | **major (environment)** | **Disk C: was full during the review.** Observed free space: 54 MB, 341 MB, 892 MB, 2.6-4.3 GB. The fat constants joins spill SQLite temp B-trees to `%TEMP%` on C:. A U `--trace` run writes 1.76 GB. The pending sechost oracle and every parity or release run on this machine share that disk. | `df -h /c` during the review; Python `database or disk is full` above. I deleted my own 1.76 GB trace and ~180 MB of snapshots at once. | Before the next parity or oracle runs, free C: or point `TMP`/`TEMP` and the trace/snapshot dirs at a roomy volume. Check the pending sechost oracle's `diaphora.log` for `Error:` or `disk is full` before accepting it. | high |
| F-3 | minor | **`--trace` is very large and slow on real pairs.** U: 1.76 GB and 180 s instead of 77 s. `add_match` events dominate. S would be several times larger. Nothing warns about this. | `time_diff.py` run (points.json kept) | Document the cost in `--help`. Consider a points-only mode or a free-space check before writing. | high |
| F-4 | minor (release) | **The version is still 0.1.0, and there is no `--version`.** `CMakeLists.txt:4` has `VERSION 0.1.0`. `diff --help` prints "dsigmatcher 0.1.0". Snapshots record `producer: dsigmatcher-0.1.0`. `dsigmatcher --version` gives "error: unknown command '--version'". | `build/dsigmatcher.exe --version` | Bump to 1.0.0 for the release. Add `--version`, which the consuming program will want to check. | high |
| F-5 | nit (docs) | **The fusion guidance in the maintainer notes is stale** (69% of time in 3 text-keyed joins, 3.2×, AVX 16×). Those are legacy-engine numbers. The parity-engine profile is §2 here. | §2 | Replace it with a pointer to this inventory. | high |
| F-6 | nit (docs) | **`TiersDetail.h:13-15` / `:84-86` present `JoinKeys` / `KeySignature` as "the hash keys a fused generator could build once and share".** That is true for the keys only. The row order comes from the plan, which differs between pairs even for identical keys (§3.3, §5). | §5 | Add one sentence saying that shared keys do not mean a shared order, and that a plan guard is required. | high |

---

## 11. Checked and fine

- **`build/diff_tiers.exe`:**
  - 1622 checks, 0 failed.
  - The descriptor's columns equal SQLite's authorizer reads for 51/51 queries (50 heuristics plus small differences).
  - The key signatures are printed for all 50.
- **Registry text:** all 50 heuristic SQL strings parsed from `RegistrySql.inc` hash to their stored SHA-256 (independent check, `parse_reg.py`).
- **Execution order:** Best 11→0 and Partial 41, 40, 39, 35→12, both in `diff_tiers` and in the snapshot sequence of the real U and S runs. The SAME_CPU heuristics ran on both pairs.
- **Timed U runs match the oracle.** Both timed U runs (one with `--trace`, one with `--snapshot-dir`) produced `results` and `unmatched` rows identical to the oracle's `.diaphora` (2180 + 50 rows). The instrumentation does not change results.
- **Refusals:** `--unreliable` is refused with exit 4 and no output file, so H36-H38 and H42-H49 cannot run.
- **Native CU replay guard:** `EXPLAIN QUERY PLAN` of `kSqlCuCartesian` is `SCAN f | SCAN df` on both pairs, so the native replay path is the one in use (`RelatedCompilationUnit.cpp:249-271`).
- **Point flushing:** trace points are flushed at every point (`Trace.cpp:163`), and snapshots are written at every selected point. Both give usable per-stage timing without code changes.
- **Parity docs:** they already describe the ordering rules this inventory depends on (`02-matching.md` §18-§19, `04a-heuristics-best.md:810-819`). No contradiction was found against the measured plans.

---

## 12. Files in the scratch dir

| file | content |
|---|---|
| `reg.json`, `parse_reg.py`, `sql_bodies.txt` | the 50 registry entries (metadata + verbatim SQL, SHA-256 checked); the SQL without `SELECT_FIELDS` |
| `diff_tiers_out.txt` | full `diff_tiers.exe` output (key signatures, shared-key list) |
| `plans.json`, `stage_plans.py`, `stage_sql.json` | EXPLAIN QUERY PLAN of every heuristic on U and S; stage SQL plans |
| `sql-userenv.json`, `sql-sechost.json`, `sql_timing.py`, `merge_sechost.py` | SQL-alone timings and row counts |
| `slim-userenv.json`, `slim-sechost.json`, `slim-sechost.log`, `slim_check.py` | projection-cut probe (plan / sequence equality) |
| `snap-userenv/stage_times.*`, `snap-sechost/stage_times.*`, `stage_times.py`, `phase_sums.py`, `group_sums.py` | native per-point times, phase and group sums (snapshot JSONs deleted to free disk) |
| `cu_seeds.py`, `stage_sql_cu_main.sql` | related-CU workload |
| `const_dups.py`, `stage_rows.py` | FG-1 duplicate counts; stage-query row counts |
| `run-userenv/points.json`, `time_diff.py` | the `--trace`-based U run (trace file deleted: 1.76 GB) |
| `gen_tables.py`, `table_summary.md`, `table_detail.md` | generators of §4 / §5 |
| (deleted) `db/` | the four export copies used read-only; removed after the review to free disk |
