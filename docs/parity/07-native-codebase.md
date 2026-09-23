# 07: The native codebase and what has to change for Diaphora parity

## Summary

- **What exists now.** `dsig-parity` (branch `parity`, HEAD `34ed418`) holds a C++20 static library, `dsigmatcher_core`, plus a CLI (`diff`/`port`/`info`) and 5 test executables. The build is clean at /W4 and all 5 ctest suites pass: 316 + 67 + 302 + 825 + 152,784 checks, verified 2026-09-23 with `dsig_build.cmd`. The diff engine is 12 hash-join heuristics that run independently and in parallel. `MatchStore` then sorts their output and resolves it greedily to 1:1, and the ratio is binary (1.0, or 0.5 when a match is ambiguous).
- **How Diaphora differs.** Diaphora's `diff()` is a **sequential, order-sensitive state machine keyed by function *name***. It runs heuristics one at a time, and within each category it goes in **reverse** registration order (`targets.pop()`). Every SQL row goes through `check_match` → `check_ratio` (graded, using difflib `quick_ratio` rounded to 7 decimals, plus `deep_ratio` bonuses) → `add_match`. Each of those steps reads the state that earlier rows left behind. After the heuristics come an iterative loop (callee diffing, related constants, related compilation units, local affinity) and a final multimatch pass. The output is `.diaphora` tables (`results` and `unmatched`).
- **Why it cannot be patched in.** The current architecture cannot express this. It has no shared state between heuristics, no row order, no graded ratio, a single fixed category per heuristic, and no multimatch. The rewrite has four parts:
  1. Split every heuristic into a pure **candidate stream** (which can run in parallel) and a **sequential consumer** (the exact state machine).
  2. Replace `MatchStore` with a `MatchState` class that ports Diaphora's semantics exactly.
  3. Add a pure `RatioEngine`.
  4. Add a pipeline driver that follows `diff()` line for line, and a writer for `.diaphora` results.
- **Row order decides outcomes.** 16 of the 50 heuristic queries have no `ORDER BY`, and 32 sort only by the boolean `f.source_file = df.source_file`, which leaves massive ties. Either way, the effective order comes from SQLite's planner and sorter. The recommended parity path is to generate candidates by running **Diaphora's verbatim SQL through the SQLite C API**. Our build links the *same* SQLite 3.51.1 library that the reference Python uses. Which `sqlite3.dll` actually loads at run time depends on `PATH` (Section 11.2). Native hash joins then become an optimisation, and each one is validated row for row against the SQL path.
- **Scoping finding for symbolised version pairs such as win32u with PDBs.** When the number of `(main, diff)` row *pairs* with equal `mangled_function` is more than 90% of the main function count (`D:2599-2610`; a pair count, so duplicates inflate it), Diaphora takes the *patch-diff short-circuit*. In that mode **none of the 50 heuristics and none of the iterative loop run**. OBSERVED on the real oracle pair `userenv-9168-pdb_vs_9278-pdb`: its log says `Patch diffing detected: A total of 643 matches out of 643, 100.0%`. Parity for that corpus only needs these parts:
  - equal matches;
  - dirty-heuristic detection;
  - same name;
  - remaining-functions brute force;
  - `check_ratio`;
  - the final pass;
  - the unmatched listing;
  - the writer.

  Patch-diff mode also loads the default hook script `scripts/patch_diff_vulns.py`. Its `on_match` always returns its input unchanged, but it can raise (Section 10.8).
- **Parallel work.** Section 12 proposes a layout: one registry table created up front holding all 50 heuristics plus 11 stages, one file per heuristic group and per stage, and one test executable per group, so that engineers own disjoint files.

Evidence legend: `D:` = `<diaphora-ref>/diaphora.py`, `H:` = `diaphora_heuristics.py`, `C:` = `diaphora_config.py`, `S:` = `db_support/schema.py`.
- The checkout is `3.4.2-4-g621ec26`, 4 commits after the tag. `git diff 3.4.2 HEAD` touches only `README.md` and CSS colours in `diaphora_ida.py`, at line 3864 and later.
- So every `D:`/`H:`/`C:`/`S:` line number, and every cited `diaphora_ida.py` line below 3864, is the same at the tag.

Native paths are relative to `<repo>`. "OBSERVED" marks something verified by running code during this investigation (Section 1.3). "NOT DETERMINED FROM SOURCE" marks behaviour that depends on SQLite or CPython internals that the source does not specify.

---

## 1. Build, test and conventions

### 1.1 Exact commands (verified)

```bat
<dsig-tools>\dsig_build.cmd <src-dir> <build-dir> test
```

Verified run: `dsig_build.cmd <repo> <scratch>\b07 test` printed `BUILD_CLEAN`, then `100% tests passed, 0 tests failed out of 5`, then `TESTS_PASSED`. Re-verified in a fresh build directory during verification. There were **no compiler warnings**. A fresh configure does print one `CMake Deprecation Warning at .../deps/zydis-src/CMakeLists.txt:1 (cmake_minimum_required)`, which comes from the vendored Zydis and not from our code. `BUILD_CLEAN` only means that `cmake --build` succeeded. It is printed even when there are warnings, so the zero-warning check has to grep the log.

What the script does, verbatim (`dsig-tools/dsig_build.cmd`):

```bat
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul || (echo VCVARS_FAILED & exit /b 1)
set "DEPS=<dsig-tools>\deps"
if not exist "%BLD%\CMakeCache.txt" (
  cmake -S "%SRC%" -B "%BLD%" -G Ninja -DCMAKE_BUILD_TYPE=Release ^
    -DDSIG_CORPUS_ROOT=<corpus> ^
    -DFETCHCONTENT_SOURCE_DIR_ZYDIS=%DEPS%\zydis-src ^
    -DFETCHCONTENT_SOURCE_DIR_ZYCORE=%DEPS%\zycore-src ^
    -DFETCHCONTENT_SOURCE_DIR_SQLITE3=%DEPS%\sqlite3-src ^
    -DFETCHCONTENT_FULLY_DISCONNECTED=ON || (echo CONFIGURE_FAILED & exit /b 1)
)
cmake --build "%BLD%" || (echo BUILD_FAILED & exit /b 1)
echo BUILD_CLEAN
if /i "%~3"=="test" (
  set "PATH=<conda>\Library\bin;%PATH%"
  ctest --test-dir "%BLD%" --output-on-failure || (echo TESTS_FAILED & exit /b 1)
  echo TESTS_PASSED
)
```

- The script configures only once, when `CMakeCache.txt` is absent. Ninja reruns CMake by itself whenever `CMakeLists.txt` changes, so adding files is safe.
- `PATH` is prefixed with `miniconda3\Library\bin` so that the tests load **the same `sqlite3.dll` (3.51.1)** that the Python oracle uses. That DLL is the only one allowed in parity runs (see Section 11.2). Since SQLite 3.51.1 is bundled and linked statically (lane V1), the native build no longer loads any `sqlite3.dll` and the conda `CMAKE_PREFIX_PATH` was dropped from the script; the `PATH` prefix only matters for a `-DDSIG_VENDORED_SQLITE=OFF` build.
- Check counts per executable, OBSERVED by running each exe:

  | Executable | Last line of output |
  |---|---|
  | `dsigmatcher_tests` | `316 checks, 0 failed` |
  | `dsigmatcher_disasm_tests` | `67 checks, 0 failed` |
  | `dsigmatcher_pe_tests` | `302 checks run, 0 failed, 0 suites skipped` |
  | `dsigmatcher_resolve_tests` | `825 checks, 0 failed` |
  | `dsigmatcher_cfg_tests` | `152784 checks run, 0 failed, 0 suites skipped` |

### 1.2 Test and code conventions

- **No test framework.** Each test file re-declares its own harness in an anonymous namespace. There are **two variants**:
  - `dsigmatcher_tests.cpp`, `disassembler_tests.cpp` and `resolve_tests.cpp` use `CHECK`/`CHECK_EQ`. From `tests/dsigmatcher_tests.cpp:25-42`, reformatted onto fewer lines:
    ```cpp
    int ChecksRun = 0;
    int ChecksFailed = 0;
    void Report(bool Ok, const char* Expression, const char* File, int Line) { ++ChecksRun; if (!Ok) { ++ChecksFailed; std::printf("  FAIL %s:%d  %s\n", File, Line, Expression); } }
    void Suite(const char* Name) { std::printf("[%s]\n", Name); std::fflush(stdout); }
    #define CHECK(Expr) Report(static_cast<bool>(Expr), #Expr, __FILE__, __LINE__)
    #define CHECK_EQ(A, B) Report((A) == (B), #A " == " #B, __FILE__, __LINE__)
    ```
  - `peimage_tests.cpp` and `cfg_tests.cpp` use `CHECK`, `CHECK_NUM_EQ` and `CHECK_TEXT_EQ`, which print actual and expected values, plus a `SuitesSkipped` counter (`tests/cfg_tests.cpp:18-66`).
  - `main()` calls the `TestXxx()` functions in order, prints `"\n%d checks, %d failed\n"` (or `"%d checks run, %d failed, %d suites skipped"` in the second variant), and returns `ChecksFailed == 0 ? 0 : 1` (`tests/dsigmatcher_tests.cpp:1080-1097`).
  - Corpus gating is inconsistent:
    - Only `peimage_tests` receives `DSIG_CORPUS_ROOT` (`CMakeLists.txt:96-101`, `tests/peimage_tests.cpp:68-77`).
    - `cfg_tests` **hard-codes** `R"(<corpus>\win32u\win32u_100261009168\win32u.dll)"` (`tests/cfg_tests.cpp:68-69`) and skips when that file is absent (`:1081-1084`).
- **Registering a test:** each suite is its own executable, registered with `add_test(NAME <suite> COMMAND <exe>)` (`CMakeLists.txt:75-111`). The ctest names are `unit`, `disassembler`, `peimage`, `resolve` and `controlflowgraph`. `dsigmatcher_bench` is built but not registered.
- **Zero warnings is a policy, not something the build enforces.** `dsig_apply_warnings` (`CMakeLists.txt:43-49`) sets `/W4 /permissive- /utf-8 /Zc:__cplusplus` on MSVC and `-Wall -Wextra -Wpedantic` elsewhere. It does not set `/WX` or `-Werror`. Proposal: add `option(DSIG_WERROR ...)` and turn it on in CI.
- **Code style**, from the existing code: `namespace DSig`, PascalCase for identifiers and locals, trailing `_` on members, `#pragma once`, and no exceptions in the core (errors go through `Ok`/`Error` result structs).
- **CI** (`.github/workflows/ci.yml`) runs only on `push` to `main`, `v*` tags, `pull_request` and `workflow_dispatch`, so pushes to the `parity` branch do not trigger it. Each platform gets its SQLite from a different place:
  - Linux: `libsqlite3-dev` from apt.
  - macOS: `brew sqlite3`.
  - Windows: `vcpkg sqlite3:x64-windows`, with the DLL staged beside the exes.

  **These are different SQLite versions from the local 3.51.1.** See Hard part H2.
- **Git** (`AGENTS.md`): commits are authored only by kuro1337WStuff, with no `Co-Authored-By` and no AI attribution. In this workflow only the orchestrator commits.

### 1.3 Experiments run for this document (reproducible, scratch only)

All of these ran on copies in the session scratchpad with `python -B` and `PYTHONDONTWRITEBYTECODE=1`. `git status` in `diaphora-ref` stayed clean.

1. **Heuristic execution order.** Two 10-function Diaphora-schema databases were generated from `S:` with `sub_` names on both sides, then compared with `python -B diaphora.py db1 db2 -o out.diaphora` and `DIAPHORA_LOG_PRINT=1`.
   - The log prints `[Single thread] Finding with heuristic '<name>'` for all 12 Best heuristics **in list order**, because the log happens while the list is being built.
   - It prints `[Parallel] Heuristic '<name>' done` **in reverse list order**: `Microcode mnemonics small primes product` first and `Same RVA and hash` last.
   - Every pair was reported as `Equal assembly`. That is the **second** union branch of heuristic #10 (`H:287-295`; the first branch is `Equal pseudo-code`, `H:277-285`). #10 runs second, so it beat heuristics #0–#9.
   - The same reverse order is OBSERVED on a real export pair: `<corpus>/oracle/diffs/userenv-9168-pdb_vs_9278-nopdb/run1/diaphora.log` lists the `Finding with heuristic` lines for #0 to #11 in order, then the `done` lines from `Microcode mnemonics small primes product` down to `Same RVA and hash`.
2. **Output format.** `results` rows look like `('best','00000','180001000','sub_1000','180009000','sub_2000','1.0000000','4','4','Equal assembly')`. Every column is TEXT.
3. **Unmatched swap.** In a second pair, an unmatched function existed only in db2 (`sub_2002`) and another only in db1 (`sub_1002`). The output rows were `('primary','00000','180009200','sub_2002')` and `('secondary','00000','180001200','sub_1002')`, so the labels are swapped (Section 10.13).
4. **SQLite TEXT affinity, same library as Diaphora (3.51.1).** On a TEXT column holding `'0','',  '5', NULL, '0.0','10','1','abc','0x10',' 7'`:
   - `k != 0` keeps `'',5,0.0,10,1,abc,0x10,' 7'`. The literal `0` is compared as the text `'0'`: `''` is kept and `NULL` is dropped.
   - `k > 7` keeps only `'abc'`. The comparison is lexicographic, so `'10' > '7'` is false.
   - `abs(k)==0` keeps `'0','','0.0','abc','0x10'`.
   - `cast('' as real)` is `0.0`.
   - `'NULLSUB_1' like 'nullsub%'` is 1, because LIKE is ASCII case-insensitive.
   - `'nullsub' like 'nullsub_%'` is 0, because `_` needs one character.
   - `UNION` output came back sorted: `('diff','aa'),('main','aa'),('main','zz')`.
5. **Rounding ties.** Python `'{0:.7f}'.format(k/256)` gives `0.0039062, 0.0117188, 0.0195312, 0.0273438, 0.0351562, 0.0429688, 0.0507812, 0.9960938` for k = 1,3,5,7,9,11,13,255, which is round-half-even on the exact binary value. MSVC `std::to_chars(fixed, 7)` and `snprintf("%.7f")` produced identical strings.
   - Re-verified at scale during verification (MSVC 18, `/std:c++20 /O2`) with 200,000 doubles: every `k/65536` for k < 65,536, which includes many exact binary ties, plus 134,464 random doubles in [0, 1).
   - Both `to_chars` and `snprintf` matched Python `"%.7f" % v` on **all** of them (0 mismatches).
6. **Real-export row dumps** (added during verification). The 7 exports in `<corpus>/oracle/exports` were copied to the scratchpad and queried read-only with Python `sqlite3` (3.51.1): `userenv-9168-pdb`, `userenv-9278-pdb`, `userenv-9278-nopdb`, `sechost-9168-pdb`, `sechost-9444-nopdb`, `ls`, `ls-old`. Results:
   - All 7 exports:
     - journal mode is `wal`;
     - `sqlite_stat1` is present, with 44 indices;
     - there is 1 `program` row and `version` = `'3.4'`;
     - `select name, address from functions` equals rowid order;
     - there are no duplicate names, no function in more than one CU, and no NULL `md_index`, `constants`, `names`, `nodes` or CU bounds;
     - all addresses have the same length within an export.
   - UNION, INTERSECT, name-lookup and CU-lookup plans: see Sections 10.7, 10.8, 10.11.3 and H2.
   - `cast(md_index as real)` differs from Python `float(md_index)` on 2 of 4,754 values in the 6 exports checked (Section 5.3).
   - Under `re.IGNORECASE`, `CPP_NAMES_RE`'s ASCII classes also match U+0130, U+0131, U+017F and U+212A (Section 10.11.1).

---

## 2. Repository map (every file)

| Path | Lines | Role today | Parity relevance / action |
|---|---|---|---|
| `CMakeLists.txt` | 111 | One static lib `dsigmatcher_core` (13 sources), CLI `dsigmatcher`, bench, 5 test exes. Deps: `SQLite::SQLite3`, `Threads`, Zydis v4.1.1 through FetchContent. | Add the new `diff/` sources and test exes **once, up front** (Section 12) so that engineers never edit it. |
| `include/dsigmatcher/Types.h` / (header-only) | 156 | `PackedString`, `StringPool`, `MatchCategory`, `Match`, `FunctionTable` (27 columns), `ProgramInfo`. | **Replace** with the diff data model (Section 4). |
| `include/.../ExportDatabase.h`, `src/ExportDatabase.cpp` | 20 / 294 | Reads 27 `functions` columns and 3 `program` columns. | **Rewrite** (Section 5). |
| `include/.../Heuristics.h`, `src/Heuristics.cpp` | 45 / 407 | 12 heuristics as hash joins, a parallel runner, and a binary ratio. | **Superseded** by `src/diff/*`. Keep it only as the benchmark baseline, or delete it once the replacement is at parity. |
| `include/.../MatchStore.h`, `src/MatchStore.cpp` | 29 / 288 | Dedup, stable sort, then greedy 1:1. The partitioned path is disabled. | **Superseded** by `MatchState` (Section 10.5). |
| `include/.../Naming.h` | 32 | `IsAutoNamed`, `IsNullSub`, `IsPortableSymbol`, `NameCompatible`. | Split into Python and SQL predicates (Section 6.3). |
| `include/.../Provenance.h`, `src/Provenance.cpp` | 92 / 536 | The `port`/`info` implementation: hop chain and name origins. | Adapt it to the new result type (Section 9). |
| `src/main.cpp` | 444 | CLI parsing, `diff` output tables, `port` and `info` printing. | Add a Diaphora-format writer and a `--format` option (Section 8). |
| `include/.../ThreadPool.h`, `src/ThreadPool.cpp` | 82 / 122 | A persistent pool. `ParallelFor` uses dynamic chunks, the caller participates, and nested calls run inline. | **Keep.** Use it only for pure work: candidate generation and ratio prefetch. |
| `include/.../KghHash.h`, `src/KghHash.cpp` | 65 / 186 | Big-int KOKA hash, checked against an oracle. | Export side. Not needed for diff parity. |
| `include/.../PrimeTable.h`, `src/PrimeTable.cpp` | 26 / 42 | Prime sieves 2048² and 4096. | Export side. |
| `include/.../Md5.h`, `Sha256.h` + `.cpp` | 30+30 / 156+181 | Hash primitives. `Sha256` is used by provenance. | Keep. |
| `include/.../PeImage.h`, `src/PeImage.cpp` | 188 / 819 | PE parser, audited against pefile. | Export side. |
| `include/.../Disassembler.h`, `src/DisassemblerZydis.cpp` | 63 / 139 | Zydis backend. | Export side. |
| `include/.../ControlFlowGraph.h`, `src/ControlFlowGraph.cpp` | 138 / 894 | CFG, SCCs, loops, and Diaphora's quirks. | Export side. |
| `include/.../Synth.h`, `src/Synth.cpp` | 44 / 340 | Synthetic `FunctionTable` pairs with ground truth. Fills the 27 current columns. | Extend it, or replace it with Diaphora-schema fixtures (Section 13). |
| `tests/dsigmatcher_tests.cpp` | 1097 | Hashes, naming, `MatchStore`, synthetic accuracy (`RunExactHeuristics`), ingest round-trip, port path safety, provenance chain. | Expect breakage in `TestMatchStore` / `TestSyntheticAccuracy` when the engine is swapped. Keep the ingest, port and provenance tests. |
| `tests/resolve_tests.cpp` | 819 | ThreadPool tests and `MatchStore` resolve tests. | The `MatchStore` tests are obsolete for the new engine. The ThreadPool tests stay. Per HANDOFF they "deliberately assert order-dependent results". |
| `tests/cfg_tests.cpp`, `disassembler_tests.cpp`, `peimage_tests.cpp` | 1457 / 243 / 986 | Tests for the export-side modules. | Unaffected. |
| `bench/dsigmatcher_bench.cpp` | 255 | Times each heuristic with `RunHeuristic`, plus `Resolve`. | Re-target it at the candidate generators and `RatioEngine`. |
| `tools/schema_coverage.py` | 130 | Reports that 27 of 49 `functions` columns are ingested and 12 of 50 heuristics implemented (OBSERVED output). | Update its parser to the new ingestion table. |
| `tools/kgh_vectors.py`, `prime_vectors.py` | 66 / 61 | Oracle vector emitters. | This is the pattern to copy for ratio and difflib oracle vectors. |
| `tools/extract_pdb_symbols.py`, `compare_ground_truth.py`, `prepare_corpus.py` | 249 / 103 / 211 | Corpus and ground-truth tools. | Unchanged. |
| `tools/audit_pe_dump.py`, `dump_pe.cpp`, `cpu_features.cpp`, `hash_bench.cpp`, `join_bench.cpp` | 300 / 98 / 127 / 222 / 233 | Standalone audits and benches that are **not in CMake**. | Unchanged. |
| `tools/oracle/` (**untracked**: `build_oracle.py`, `diaphora_export.py`, `compare_exports.py`, `pdb_proof.py`) | 519 / 328 / 80 / 95 | Builds the real-export oracle under `<corpus>/oracle` (see `docs/parity/09-oracle.md`). It runs unmodified Diaphora twice per pair and writes `determinism.json` and `run.json` (`timeouts_logged`, `tracebacks_logged`). | This is the parity reference. It supersedes the synthetic-only plan in Section 13. |
| `docs/parity/*.md` (untracked) | — | The parity spec set (01–09). | Only this file is in scope here. |
| `README.md`, `HANDOFF.md`, `JOURNAL.md`, `AGENTS.md` | 222 / 123 / 1508 / 5 | Project docs. `AGENTS.md` forbids AI attribution. | See Open question 8 for `README.md`. |
| `.github/workflows/ci.yml` | 104 | 3-platform build and test. | See H2 for pinning SQLite. |

---

## 3. What runs today under `dsigmatcher diff`

`RunDiff` (`src/main.cpp:266-329`) does the following:
1. Loads both exports (Section 5).
2. Sets `SameProcessor` to true when `--assume-same-cpu` is given, or when both `program.processor` values are present, **non-empty** and equal (`src/main.cpp:287-290`).
3. Calls `RunExactHeuristics` (`src/Heuristics.cpp:347-405`), prints a table, and optionally writes `matches` and `symbols_to_port`.

`RunExactHeuristics` works like this:
- A `ThreadPool` sized to `ThreadCount`, or to the hardware thread count when that is 0, runs `ParallelFor` over the runnable heuristics. Each heuristic runs single-threaded into its own `Sinks[Slot]` vector.
- The sinks are then appended to a `MatchStore` in heuristic-index order, and `Store.Resolve(Requested)` is returned.
- A heuristic is skipped with the reason `"processor specific"` when `Definitions[Slot].RequiresSameProcessor && !Options.SameProcessor` (`src/Heuristics.cpp:367-371`).

Differences from Diaphora at this level:
- Diaphora compares `mp.processor = dp.processor` in SQL (`D:2957-2960`), so `''=''` counts as the same processor and `NULL` never matches. The native `diff` requires both to be non-empty. `port` (`src/Provenance.cpp:351`) accepts `''==''`, which matches Diaphora, but it diverges in two ways:
  - it treats missing `program` tables or rows as equal;
  - it treats two NULL processors as equal, because `ColumnString` maps NULL to `""` (`src/Provenance.cpp:68-75,211-216`).
- Diaphora never reports "all heuristics ran". Its early exit is `all_functions_matched()` (Section 10.4).

---

## 4. Data model: `Types.h` now, and what it must become

### 4.1 Current (verbatim excerpts)

`include/dsigmatcher/Types.h:10-13`:
```cpp
struct PackedString {
  uint32_t Offset = 0;
  uint32_t Length = 0;
};
```
`Types.h:44-50`:
```cpp
struct Match {
  uint32_t Index1 = 0;
  uint32_t Index2 = 0;
  uint16_t HeuristicId = 0;
  float Ratio = 1.0f;
  MatchCategory Category = MatchCategory::Best;
};
```
`Types.h:38-42`: `enum class MatchCategory : uint8_t { Best = 0, Partial = 1, Unreliable = 2 };`

`FunctionTable` (`Types.h:52-147`) is a struct of arrays over one `StringPool`. It has 12 `int64_t` columns and 15 `PackedString` columns (27 in total). `ProgramInfo` (`Types.h:149-154`) holds `Processor`, `Md5Sum`, `CallgraphPrimes` and `Present`.

### 4.2 Defects that block parity

| # | Defect | Why it matters (Diaphora evidence) |
|---|---|---|
| T1 | `float Ratio` | Python ratios are IEEE doubles. Thresholds such as `0.579`, `0.449` and `0.549` (`H:678,377,717`) are compared with `>=`. Output is `"%.7f"` (`D:282-290`), and multimatch detection depends on exact double equality (`D:2861,2931`). |
| T2 | No NULL representation | `ColumnText` returns an empty view for NULL (`src/ExportDatabase.cpp:98-105`), and int columns read NULL as 0. SQL treats `''` and NULL differently (`''=''` is true; `NULL=NULL` is NULL). Python treats `None==None` as True, and `deep_ratio` depends on that (Section 10.6.3). The exporter writes both: `clean_pseudo` is `None` when there is no decompilation, and `clean_assembly` is `""` when there is no assembly (`diaphora_ida.py:2960-2962,2995`). |
| T3 | No description, ea or name strings on a match | Diaphora items are `[ea, name1, ea2, name2, desc, ratio, nodes1, nodes2]` (`D:1927`). The description can be dynamic: `"Callee found diffing matches assembly (iteration #2)"` (`D:3114`), or `"Equal pseudo-code"` vs `"Equal assembly"` for the two union branches of #10 (`H:277,287`). |
| T4 | Category fixed per heuristic | In Diaphora the chooser depends on the **ratio**: a Best-category RATIO heuristic sends `r<1.0` to *partial* (`D:1925-1930`). There is also a fourth chooser, `multimatch` (`D:2365`). |
| T5 | 32-bit `StringPool` offsets in one shared pool | The parity path must ingest `pseudocode`, `assembly`, `clean_*` and `names`. Those are KB-scale per function, and a 100k-function export can exceed 4 GiB in one pool. |
| T6 | `HeuristicId` is our table index, not Diaphora's list index | Ours: `Definitions[]` indices 0-11 (`src/Heuristics.cpp:298-311`). Diaphora's: `HEURISTICS` positions 0-49. Output today prints `"best#<ourIndex>"` even for Partial heuristics (`src/main.cpp:218`, `src/Provenance.cpp:452`). |

### 4.3 Proposed diff data model (new header `include/dsigmatcher/diff/Table.h`)

```cpp
namespace DSig::Diff {

struct TextColumn {                 // one pool per column: no 4 GiB cliff across columns
  std::vector<char> Pool;           // UTF-8 bytes exactly as SQLite returned them
  std::vector<uint64_t> Offset;     // 64-bit
  std::vector<uint32_t> Length;
  std::vector<uint8_t> IsNull;      // 1 = SQL NULL (Python None)
  std::string_view View(uint32_t Row) const;
  bool Null(uint32_t Row) const { return IsNull[Row] != 0; }
};

struct IntColumn {
  std::vector<int64_t> Value;
  std::vector<uint8_t> IsNull;      // NULL != 0 in both SQL and Python semantics
  std::vector<uint8_t> NotInteger;  // storage class was TEXT/REAL (INTEGER affinity failed): flag and report
};

struct FunctionTable {              // row order == `select ... from functions` rowid order
  size_t Count() const;
  IntColumn Id, Nodes, Edges, Indegree, Outdegree, Size, Instructions, CyclomaticComplexity,
            PseudocodeLines, StronglyConnected, Loops, ConstantsCount;
  TextColumn Name, Address, Rva, SegmentRva, MangledFunction, BytesHash, FunctionHash, KghHash,
             MdIndex, Mnemonics, Names, PrimesValue, Pseudocode, PseudocodeHash1, PseudocodeHash2,
             PseudocodeHash3, PseudocodePrimes, Assembly, Prototype2, TarjanTopologicalSort,
             StronglyConnectedSpp, CleanAssembly, CleanPseudo, CleanMicrocode, MnemonicsSpp,
             MicrocodeSpp, Switches, Constants, SourceFile;
  std::vector<double> MdSqlReal;    // exactly `cast(md_index as real)` evaluated by SQLite (NULL -> NaN + flag)
  std::vector<uint8_t> MdSqlNull;
  std::vector<double> MdPyFloat;    // exactly Python float(md_index) (compare_function_rows path)
  std::vector<uint8_t> MdPyError;   // float() would raise (None / "" / junk)
  std::unordered_map<std::string_view, uint32_t> RowByAddress; // address is `text unique` (S:72); rva is also `text unique` (S:98)
  std::unordered_multimap<std::string_view, uint32_t> RowsByName; // names are NOT guaranteed unique
};
}
```

Interned names: every name that Diaphora uses as a dict key goes into one `NameTable` (`std::string` → `NameId`) shared by both sides. That covers `functions.name`, `functions.mangled_function`, and names extracted by the callee-diffing regex. `MatchState` keys on `NameId`, because Diaphora keys on the name string, not on the row (Section 10.5).

Side tables (new header `diff/SideTables.h`). Each is loaded in CSR form keyed by row index, and each is only needed if some default-run code reads it:

| Table (`S:` line) | Needed by (default run) | Load as |
|---|---|---|
| `program` (`S:119-125`) | Same-processor check, `equal_db` (log only), `check_callgraph` (log only, but it can throw) | all 5 columns, with a row count |
| `version` (`S:132`) | `diff()` validity check (`D:3578-3591`) | first row value |
| `constants` (`S:170-173`) | #15, #20, #21, `find_related_constants` | `func_id → [constant text]`, in rowid order |
| `compilation_units`, `compilation_unit_functions` (`S:174-185`) | #12, #13, #14, `find_related_compilation_unit` | `cu_id → {name, pseudocode_primes, start_ea, end_ea}` and `func_id → [cu_id]` |
| `instructions` (`S:133-146`) | #39 (SAME_CPU) and #40 | `func_id`, `disasm`, `mnemonic`, and `id` for the `bb_instructions` join |
| `bb_instructions` (`S:156-159`) | #40 | `basic_block_id → [instruction_id]` |
| `basic_blocks`, `bb_relations`, `function_bblocks`, `callgraph`, `program_data` | **Not read** by the default diff. They feed only the IDA GUI (`get_graph`, `D:1188-1267`) or ML. | skip |

---

## 5. `ExportDatabase` ingestion

### 5.1 Current behaviour (verbatim)

`src/ExportDatabase.cpp:51-79` holds the wanted-column table with 27 entries. Columns are discovered with `pragma table_info(functions)` (`:81-96,122`), and missing ones are silently omitted from the `select`. The query is `"select " + SelectList + " from functions"` (`:142`). It has **no `ORDER BY`**, so rows come back in rowid order for a plain table scan, and row position becomes `Index`.
- Integer columns use `sqlite3_column_int64`, which reads NULL as 0 and converts text leniently (`:186-221`).
- Text columns are `Pool.Append(ColumnText(...))` with NULL becoming `""` (`:98-105`).
- `program` is read with `select processor, md5sum, callgraph_primes from program limit 1` (`:277`), but only if `pragma table_info(program)` returns columns (`:274-275`). `ProgramInfo::Present` is set only when a row exists (`:279-280`), and NULL becomes `""`. The `callgraph_all_primes` column, the row count, and the `version` table are ignored.
- The file is opened with `SQLITE_OPEN_READONLY` (`:113`). A preliminary `select count(*) from functions` sizes the reservation (`:170-176`).

`tools/schema_coverage.py` (OBSERVED): 49 columns in the schema, 27 ingested. The 22 not ingested are:
- names
- prototype
- primes_value
- comment
- pseudocode
- pseudocode_hash1
- pseudocode_primes
- function_flags
- assembly
- prototype2
- pseudocode_hash2
- pseudocode_hash3
- tarjan_topological_sort
- strongly_connected_spp
- mnemonics_spp
- switches
- bytes_sum
- assembly_addrs
- userdata
- microcode
- microcode_spp
- export_time

### 5.2 Column requirements (derived from every default-run consumer)

Types are from `S:69-118`. All "text" columns have TEXT affinity. That matters for comparisons against numeric literals (experiment 4).

| Column | SQL type | Default-run consumers (evidence) | Ingested now? |
|---|---|---|---|
| id | integer pk | #1 `df.id = f.id` (`H:117`); `find_equal_matches` INTERSECT (`D:1424`); side-table joins | yes |
| name | varchar | every name-keyed state op; SQL `substr(name,1,4)`, `not like 'nullsub%'` | yes |
| address | text unique | ea of every item; `%08x` output; local-affinity text range (`D:3238-3239`); `cast(address as real)` (`D:3432`) | yes |
| nodes, edges, indegree, outdegree, size, instructions, cyclomatic_complexity, strongly_connected, loops, constants_count, pseudocode_lines | integer | WHERE clauses; `deep_ratio` in/out/cc (`D:2792-2810`); nodes1/nodes2 items | yes |
| mnemonics | text | #4, #8, #24; `search_small_differences` (`D:2103`) | yes |
| names | text (JSON list) | #23, #24, #26, #29, #30; `search_small_differences` parses it with `json.loads` (`D:2119-2120`) | **no** |
| primes_value | text | #12 (`H:344`) | **no** |
| mangled_function | text | `find_equal_matches` (names the match!), `find_same_name`, patch-diff detection | yes |
| bytes_hash | text | #0, #1, #3 (#2 joins on `function_hash`, `H:137`); `check_ratio` short-circuit (`D:1681`); `find_equal_matches` | yes |
| pseudocode | text | #10 (`H:280`), #26 `is not null`; `check_ratio` gate (`D:1700-1705`); callee diffing `field_name="pseudocode"` (`D:3208`) | **no** |
| pseudocode_hash1/2/3 | text | #25, #32-#34 (#36-#38 are not default) | **no** |
| pseudocode_primes | text | #13, #35 (`length()>=35`), CU table; `deep_ratio` (`D:2786-2790`) | **no** |
| assembly | text | #10 (`H:290`); callee diffing `field_name="assembly"` (`D:3200`) | **no** |
| prototype2 | text | #29 (`H:735`) | **no** |
| clean_assembly, clean_pseudo, clean_microcode | text | #5, #6, #7; `check_ratio` v2/v1/v5 | yes |
| mnemonics_spp | text | #27 | **no** |
| microcode_spp | text | #11 (`!= 1` is compared as text) | **no** |
| switches | text (JSON) | #31; `deep_ratio` (`D:2802-2805`) | **no** |
| function_hash | text | #2 | yes |
| md_index | text | #16, #19, #22, #23; `cast(... as real)` in `SELECT_FIELDS` (`H:57`); `float()` in `compare_function_rows` | yes (text only) |
| constants | text (JSON) | #17, #22; `deep_ratio`; `find_related_constants` (`D:3370-3371`) | yes |
| rva, segment_rva | text | #0, #8, #9 | yes |
| kgh_hash | text | #15, #16, #18 | yes |
| source_file | text | `order by f.source_file = df.source_file` in 32 heuristics, 22 of them default-run (OBSERVED count over `H:`); `deep_ratio` (`D:2780-2784`) | yes |
| tarjan_topological_sort, strongly_connected_spp | text | Unreliable only: #42, #43, #49 | no (not default) |
| prototype, comment, function_flags, bytes_sum, assembly_addrs, userdata, microcode, export_time | — | **not read** by diff code (grep: those names appear in `D:` only in `FUNCTION_FIELDS`/INSERT, `D:358-372,943-958`) | skip |

Totals: default parity needs **27 current + 12 new = 39 columns**, plus 2 more for the Unreliable heuristics. The 12 new ones are `names`, `primes_value`, `pseudocode`, `pseudocode_hash1`, `pseudocode_hash2`, `pseudocode_hash3`, `pseudocode_primes`, `assembly`, `prototype2`, `mnemonics_spp`, `microcode_spp` and `switches`.

### 5.3 Ingestion spec (new `src/diff/Ingest.cpp`)

1. **Open.** Open read-only. Record which of the 13 tables exist and their column sets (`pragma table_info`).
   - Missing required columns become a **hard error** in parity mode. Today they are silently skipped.
   - Also record `select count(*) from program`. Diaphora raises `"Not enough rows in databases!"` unless the `union all` of both `program` tables returns exactly 2 rows **in total** (`D:1294-1322`). One row per side is the normal case, but 2+0 also passes, and then rows[0] and rows[1] both come from main. Our parity mode must accept and refuse exactly the same inputs. OBSERVED: all 7 real oracle exports have exactly 1 `program` row.
2. **Functions.** Run `select <cols>, cast(md_index as real) from functions` with no `ORDER BY`, like `D:2330` / `D:2453`.
   - For every column, call `sqlite3_column_type` first. `SQLITE_NULL` sets the null flag. INTEGER-affinity columns that come back as non-integer set the `NotInteger` flag.
   - Keep the bytes exactly: `sqlite3_column_text` plus `sqlite3_column_bytes`.
3. **`md_index` has two parse paths** (they must be kept separate):
   - `MdSqlReal` is SQLite's own `cast(md_index as real)`, the same value `SELECT_FIELDS` gives the Python code as `md1`/`md2` (`H:57`). It is used for every row that comes from an SQL heuristic (`check_match`, `D:1805`).
   - `MdPyFloat` is Python `float(text)`, used by `compare_function_rows` (`D:2498` → `D:1672`). Python `float()` has these properties, OBSERVED with the reference Python 3.13.12:
     - It strips **Unicode** whitespace, not just ASCII (`float(" 1.5 ") == 1.5`).
     - It accepts a leading `+`, `_` between digits (`float("1_000.5") == 1000.5`), `inf`/`Infinity`/`nan` with a sign, and Unicode decimal digits (`float("١") == 1.0`).
     - Overflow gives `inf` without raising (`float("1e400")`).
     - It raises on `""`, on `"0x10"` and on None.

     Implement it as correctly rounded parsing (`std::from_chars(..., chars_format::general)` is correctly rounded like CPython). Pre-normalise the text first, because `from_chars` rejects a leading `+` and `_`, and it reports `result_out_of_range` instead of returning ±inf. Set `MdPyError` wherever Python would raise. In practice this only matters for malformed text: OBSERVED, every `md_index` in the 7 real exports is `typeof = 'text'` holding either `'0'` or a `Decimal` string.
   - **RESOLVED (OBSERVED), previously "NOT DETERMINED FROM SOURCE":** SQLite 3.51.1's `cast(text as real)` is **not** correctly rounded for the 28-digit `Decimal` strings that the exporter writes (`diaphora_ida.py:2531-2537`).
     - Over all 4,754 `md_index` values in the 6 real oracle exports that were checked, 2 differ from Python `float()` by 1 ULP. An example is `'3.050963036440351716676733804'`: SQLite gives `3.0509630364403515` and Python gives `3.050963036440352`.
     - Over 200,000 random 28-digit strings, 105 differ.

     Consequences:
     - `MdSqlReal` **must** be produced by SQLite itself: the Path A projection, or `select cast(md_index as real)` at ingestion. Alternatively, use a bit-exact port of SQLite's `sqlite3AtoF`. **Never** use `from_chars`.
     - `MdSqlReal` and `MdPyFloat` really can differ, which makes H7 and the first-writer-wins ratio cache (Section 10.6.2) observable.
4. **Text-derived precomputes.** These are pure, so they can run in parallel with `ThreadPool` (the functions for 4a–4c are specified in Section 10.6):
   - (a) `LineTokens[col]` for `clean_pseudo`, `clean_assembly` and `clean_microcode`: split on `'\n'` exactly like Python `str.split("\n")`, intern each line to a `uint32` shared by both tables, and store it as a sorted `(token, count)` run list plus the total line count.
   - (b) `ConstantsSet`: `json.loads(constants)`, canonicalised (Section 10.6.3).
   - (c) `NamesSet`: `set(json.loads(names))` for `search_small_differences`.
   - (d) `IsNullStr` flags for the Python-semantics checks.
5. **Side tables.** Load them as in Section 4.3.
6. **Keep the old `ExportDatabase` API.** `port`, `info` and the tests use it. It can become a thin adapter over the new loader.

---

## 6. `Heuristics.cpp`: current architecture and the divergences in the 12 implemented heuristics

### 6.1 How a heuristic is declared and run today (verbatim)

`src/Heuristics.cpp:290-311`:
```cpp
struct Definition {
  const char* Name;
  MatchCategory Category;
  bool RequiresSameProcessor;
  void (*Runner)(const FunctionTable&, const FunctionTable&, const DiffOptions&, std::vector<Match>&,
                 uint16_t);
};

const Definition Definitions[] = {
  {"Same RVA and hash", MatchCategory::Best, true, RunSameRvaAndHash},
  ...
  {"Same rare MD Index", MatchCategory::Partial, false, RunSameRareMdIndex},
};
```

Each `Run*` function is a call to `JoinByKey(A, B, Key, Accept, PenalizeAmbiguity, Id, Category, Sink)` (`:32-76`):
- It builds a `std::unordered_multimap<std::string_view,uint32_t>` over B, **skipping empty keys**.
- It iterates A in index order and collects every `J` in `equal_range` that passes `Accept`.
- It emits all of them with `Ratio = (PenalizeAmbiguity && Candidates.size() > 1) ? 0.5f : 1.0f` (`:65`).

The size gate `PassesSizeGate` emulates `SQL_DEFAULT_POSTFIX = " and f.instructions > 5 and df.instructions > 5 "` (`C:128`, `:24-30`). Rarity (`:203-229`) counts keys per side, skipping `""` and `"0"`.

### 6.2 Architectural divergences (all must go)

1. **Independence.** Heuristics run concurrently into private sinks (`:381-388`). Diaphora's `check_match` reads `matched_primary`/`matched_secondary` as they stand after every earlier row and earlier heuristic (`D:1851,1865`).
2. **No candidate order.** Candidates are A-index order × `equal_range` order, and the order within `equal_range` is unspecified by the C++ standard. `Resolve` hides this by sorting. Diaphora consumes rows in SQLite's order, and that order is consequential (Section 10.5).
3. **Binary ratio.** Diaphora computes `check_ratio` for every row that survives `check_match`'s `nullsub_` and `has_best_match` filters, NO_FPS rows included, and uses the result to decide whether to reject (`D:1844-1867`, `D:2063`). Computing a ratio also fills `ratios_cache`, which later `compare_function_rows` calls reuse (Section 10.6.2).
4. **Fixed category.** See T4.
5. **Ambiguity penalty.** Diaphora has no such concept. Ambiguity turns into multimatch only when the ratios tie exactly (Section 10.12).

### 6.3 Predicate-level divergences in the 12 implemented heuristics

| Our fn → Diaphora # | Divergence |
|---|---|
| `RunSameCleanedAssembly` → #5, `RunSameCleanedMicrocode` → #6, `RunSameCleanedPseudoCode` → #7 | SQL `f.name not like 'nullsub%'` (`H:188,205,222`) is **ASCII case-insensitive**, and `%` matches anything (experiment 4). `IsNullSub` (`Naming.h:15-17`) is case-sensitive. Empty key: `JoinByKey` skips `""`, but SQL `'' = ''` is **true**, so functions with an empty `clean_assembly` do join in SQL. NULL never joins. |
| all | NULL vs `''` conflation (T2). Our `NameCompatible` returns true for two empty names, while SQL's `f.name = df.name` with NULL is NULL, which is false. |
| `RunSameRareKokaHash` → #18, `RunSameRareMdIndex` → #19 | `where kgh_hash != 0` is evaluated as TEXT `!= '0'`, so `''` is **kept** and NULL dropped (experiment 4). HANDOFF says it "does nothing". That is wrong, and so is our skipping of `""`. The exporter writes `md_index = 0`, stored as `'0'`, when there is no graph (`diaphora_ida.py:2514`), so `'0'` really is excluded. |
| `RunSameAddressAndMnemonics` → #4 (plus #5, #6, #7, #17, #19) | `order by f.source_file = df.source_file` (`H:174`) sorts rows where the source files are *unequal* **first**, because 0 sorts before 1. Ties are ordered by SQLite's sorter: NOT DETERMINED FROM SOURCE. |
| `RunSameRvaAndHash` → #0 | SQL `(df.rva = f.rva or df.segment_rva = f.segment_rva)` holds for `''=''`. Native requires non-empty values. |
| `RunSameConstants` → #17 | Diaphora type is RATIO_MAX with `min 0.5` (`H:463,472`). The native version has no threshold. |
| every Python-side check | Python uses `name1.startswith("nullsub_")` **with** the underscore in `check_match` (`D:1845-1846`) and `find_functions_between` (`D:3269`), but `startswith("nullsub")` **without** it in `find_one_match_diffing` (`D:3072`). Three different "nullsub" predicates exist: `SqlNotLikeNullsub` (case-insensitive prefix `nullsub`), `PyStartsNullsubUnderscore` and `PyStartsNullsub`. `sub_` is always case-sensitive: in SQL `substr(...,1,4)='sub_'` uses BINARY collation, and in Python it is `startswith("sub_")`. |

New `include/dsigmatcher/diff/SqlSemantics.h` must provide:
- `SqlTextCompare(a, b)`: memcmp, then length, which is SQLite BINARY collation.
- `SqlTextVsIntLiteral(col, lit)`: the literal is rendered as decimal text, then text compare.
- `SqlLikePrefixCI(text, prefix)`.
- `SqlCastReal(text)`: delegate to SQLite, or precompute at ingestion.
- `SqlAbsIsZero(text)`: true for text that SQLite would convert to 0. Emulate `abs()` on TEXT: numeric prefix parsing.
- `SqlLengthChars(text)`: UTF-8 code points, for #35.

---

## 7. `MatchStore`: current semantics (to be retired)

`src/MatchStore.cpp:41-52`: order by `Ratio` descending, then `HeuristicId` ascending, then `Index1`, then `Index2`, with `std::stable_sort`.

`ResolveSerial` (`:76-115`) works in two steps:
1. Skip `(Index1,Index2)` pairs that have already been seen.
2. Greedy 1:1: accept a pair when neither side is used yet.

`PartitionedResolveEnabled()` returns `false` (`:64-66`), which is the HANDOFF kill switch.

The resulting semantics are **global greedy on (ratio, heuristic id)**, and that has no Diaphora counterpart. Diaphora allows the following, and the new engine must reproduce all of it:
- A later lower-ratio match can **overwrite** `matched_primary` for non-`sub_` names (`D:1392-1394`, Section 10.5.3).
- Ties at the maximum ratio survive to the final pass and become multimatches (`D:2861`, `D:2738`).
- The diff side is **not** de-duplicated by `cleanup_matches` (`D:1587`, which keys on `ea1` only).

`tests/resolve_tests.cpp` `TestDedupAndPreference`, `TestStabilityTieBreak`, and the related tests exercise the old semantics. They stay valid only for the legacy engine.

---

## 8. `main.cpp` CLI and output database

### 8.1 Current output (verbatim, `src/main.cpp:188-197`)

```cpp
"drop table if exists matches;"
"drop table if exists symbols_to_port;"
"create table matches (ea1 text, name1 text, ea2 text, name2 text, description text, ratio "
"real, category text);"
"create table symbols_to_port (ea2 text, current_name text, new_name text, ratio real, "
"description text);"
```
- `description` is `"best#" + HeuristicId` (`:218`), whatever the category.
- A `symbols_to_port` row is written unless `!IsPortableSymbol(Name1) || Name1 == Name2` (`:230`).
- `-o` is opened with `SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE`, so it can be **one of the inputs** (HANDOFF known issue). Diaphora `os.remove`s the output first (`D:2379-2381`).

### 8.2 Diaphora's output format (target; `D:2374-2429`, OBSERVED in experiments 2 and 3)

```python
sql = "create table config (main_db text, diff_db text, version text, date text)"
cur.execute(sql, (self.db_name, self.last_diff_db, VERSION_VALUE, time.asctime()))
sql = """create table results (type, line, address, name, address2, name2,
             ratio, nodes1, nodes2, description)"""
sql = "create unique index uq_results on results(address, address2)"
sql = "create table unmatched (type, line, address, name)"
results_sql = "insert or ignore into results values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
d = { "best": [self.best_chooser, results_sql], "partial": [...], "unreliable": [...],
      "multimatch": [self.multimatch_chooser, results_sql],
      "primary": [self.unmatched_primary, unmatched_sql], "secondary": [self.unmatched_second, unmatched_sql] }
```
Row formatting comes from `CChooser.add_item` (`D:275-296`):
- `line` is `"%05lu" % n`, with a separate counter per chooser starting at 0.
- `address` is `"%08x" % int(ea)`: lower-case hex, no `0x`, zero-padded to at least 8 digits.
- `ratio` is `"%.7f" % ratio`.
- `nodes` is `"%d"`.
- Unmatched rows are `[line, "%08x", name]`.

Every value is stored as TEXT (OBSERVED `typeof`, also on the real `ls-old_vs_ls.diaphora`). `config` holds `main_db`/`diff_db` exactly as passed on the command line, `version` is `"3.4"`, and `date` is `time.asctime()`, which must be excluded when comparing.

Writer semantics that are easy to miss (`D:2405-2424`):
- **`insert or ignore` with a unique index on `(address, address2)`.** Categories are written in the order best, partial, unreliable, multimatch. The first row for a given `(address, address2)` wins, and a later duplicate is silently dropped, which leaves a **gap in that chooser's `line` numbers**. Such duplicates can arise:
  - `find_equal_matches` keys on `mangled_function` (Section 10.7);
  - another producer can match the same address pair under the demangled `name`;
  - both items then survive `cleanup_matches`, because the `name1-name2` keys differ;
  - both can reach the best chooser.

  The native writer must use the same statement, or emulate it exactly.
- `unmatched` rows are inserted with a plain `insert`, with no index.
- `unmatched_primary` and `unmatched_second` start as `None` (`D:438-439`, which runs after `create_choosers` at `D:426`). `find_unmatched` assigns them only when that side has at least one function (`D:2333,2346`). A `None` chooser is skipped (`D:2420`).

### 8.3 Required CLI changes

- `dsigmatcher diff <db1> <db2> -o <out> [--format diaphora|legacy]`.
  - `diaphora` writes exactly the Section 8.2 tables, removing `out` first like `D:2379-2381`, and refuses when `out` aliases an input (reuse `CanonicalPath` from `src/Provenance.cpp:58-66`).
  - `legacy` keeps today's tables for `port` consumers.
- Add parity flags mirroring Diaphora's config, all defaulting to Diaphora's standalone values:
  - `--unreliable`
  - `--relaxed-ratio`
  - `--no-experimental`
  - `--no-slow`
  - `--ignore-small-functions` (already exists)
  - `--ignore-all-names`
  - `--no-ignore-sub-names`
  - `--max-rows N` (default 1000000)
- Print the same summary lines Diaphora logs (`D:1631-1635,3690-3695`) so that runs can be compared with a text diff.

---

## 9. `Provenance` / `port` chain

Current flow (`src/Provenance.cpp:304-534`):
1. Refuse output paths that alias an input (`:311-318`).
2. Run `InspectDatabase` on both sides: file SHA-256, `program.processor`/`md5sum`, `dsig_provenance` hops.
3. Load both tables and run `RunExactHeuristics` with `SameProcessor ||= processor equality` (`:351-353`).
4. Read `dsig_name_origin` from the reference, then copy target → output as bytes (`:359`).
5. For each resolved match:
   - Skip non-portable reference names.
   - Count `TargetName == ReferenceName` as confirmed.
   - Otherwise compute `Hops = inherited+1` and `Cumulative = PreviousRatio * Item.Ratio` (`:423-428`), apply the `--max-hops` and `--min-ratio` filters, and skip existing real names unless `--overwrite-existing` is set.
   - Run `update functions set name = ?, mangled_function = ? where address = ?` (`:392`), binding the reference `name` to both columns.
   - Upsert `dsig_name_origin` with `heuristic = "best#<id>"` (`:452`).
6. Rewrite `dsig_provenance` with the parent hops plus the new hop (`:476-515`). Lineage is `parent -> targetMd5`.

Changes the new engine forces:
- `PortSymbols` must consume the new `DiffResult`: the final chooser lists after the final pass (Section 10.12). A new option decides which choosers to port, defaulting to `best,partial`. Multimatch items are never applied.
- The ratio becomes `double` and `heuristic` becomes the description text. That changes the `dsig_name_origin.heuristic` format, so old values `best#N` must still be readable.
- Diaphora keys every match on the `name` string. A port output whose `name` column holds the same string at two addresses can happen: the reference name is written even if the target already uses that name elsewhere, because `NamesSkippedExisting` looks only at the target function's own name (`:438-442`). If that output becomes the next hop's reference, Diaphora-parity behaviour conflates the two functions. `port` should check global name uniqueness in the target before renaming.
- `mangled_function = name` loses the mangled form. Diaphora's `find_same_name` still matches because it compares `df.mangled_function = f.mangled_function or df.name = f.name` (`D:2164-2165`). `find_equal_matches`, however, keys on `mangled_function` (`D:1435-1440`), so hop-to-hop results can differ from an IDA re-export. Documented, not a blocker.

---

## 10. Diaphora's pipeline as the native engine must host it

### 10.1 Effective configuration in standalone mode (`python diaphora.py db1 db2 -o out`)

| Setting | Value | Evidence |
|---|---|---|
| `unreliable` | False | `C:46`; `D:400-402` |
| `relaxed_ratio` | False | `C:47`; `D:403-405` |
| `experimental` | True | `C:48`; `D:406-408` |
| `slow_heuristics` | **True**. `MIN_FUNCTIONS_TO_DISABLE_SLOW` is applied **only** in the IDA options dialog (`diaphora_ida.py:3798-3800`), never in standalone mode. | `C:49`; `D:409-411` |
| `use_trained_model` | False, so `classifier` stays None | `C:205`; `D:412-414,3551-3555` |
| `ignore_sub_names` | True (`find_same_name` skips `sub_` names). Read straight from config, **not** through `get_value_for`, so no env override exists. | `C:50`; `D:468` |
| `ignore_all_names` | False | `C:51`; `D:470-472`; forced at `D:3759-3760` |
| `ignore_small_functions` | False, so `%POSTFIX%` becomes `""` | `C:52`; `D:474-476,1471-1473` |
| `cpu_count` | **1**, because `if not IS_IDA: self.cpu_count = 1` | `D:484-491` |
| `project_script` | None, unless the env var `DIAPHORA_PROJECT_SCRIPT` is set | `D:421` |
| `sql_max_processed_rows` | 1000000 | `C:90`; `D:454-456` |
| `timeout` | 300 s. `self.timeout` is used per `add_matches_internal` call (`D:1894`); `threads_apply` gets `config.SQL_TIMEOUT_LIMIT` directly (`D:1548`). | `C:92`; `D:451` |

Environment overrides (`D:560-569`, verbatim):
```python
value = os.getenv(f"DIAPHORA_{value_name.upper()}")
if value is not None:
  if isinstance(value, type(default)):
    value = type(default)(value)
  return value
```
Every env value is a `str`, and `isinstance(str, bool)` is False, so the **raw string** is returned. `DIAPHORA_UNRELIABLE=0` therefore *enables* unreliable, because `"0"` is truthy. Only an empty value is falsy. Parity harnesses must not rely on env toggles to switch flags off.

Diaphora **writes to db1**: `open_db` → `create_schema` runs `PRAGMA foreign_keys = ON`, then every `create table if not exists`, then inserts `version` if it is empty (`D:571-632`). The oracle must always be run on **copies** of the exports.

### 10.2 `diff()` control flow (`D:3568-3701`), condensed core (log calls and the `load_hooks` failure return elided)

```python
self.do_continue = True
if self.equal_db(): log("The databases seems to be 100% equal")
if self.do_continue:
  self.check_callgraph()
  if self.project_script is not None: ... self.load_hooks()
  self.find_equal_matches()
  skip_others = False
  self.is_same_processor = self.same_processor_both_databases()
  if self.experimental:
    skip_others = self.apply_dirty_heuristics()
  if not self.ignore_all_names:
    self.find_same_name("partial")
  if skip_others:
    self.find_remaining_functions()
  else:
    self.run_heuristics_for_category("Best")
    self.find_partial_matches()
    self.apply_machine_learning()
    if self.unreliable:
      self.find_unreliable_matches()
      self.find_experimental_matches()      # <- inside `if self.unreliable:` (D:3638-3651)
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
  self.find_unmatched()
  self.call_hook("on_finish", None, [])
```
Afterwards the main script calls `bd.save_results(diff_out)` (`D:3773`).

Stage table. Each row names the native owner file from Section 12.

| # | Stage | Runs by default? | Native file |
|---|---|---|---|
| S0 | validity (`select value from diff.version`, `D:3577-3591`), `equal_db` (`D:661-687`), `check_callgraph` (`D:1288-1338`) | Yes. `equal_db` and `check_callgraph` affect **logging only**: `do_continue` is always True, and `self.percent`/`equal_callgraph` are never read again (grep `D:388,443,1306,1338`). `check_callgraph` can **raise**, though (Section 10.15). | `stages/Preflight.cpp` |
| S1 | `find_equal_matches` | Yes | `stages/EqualMatches.cpp` |
| S2 | `same_processor_both_databases` | Yes | `Pipeline.cpp` |
| S3 | `apply_dirty_heuristics` (stripped check, then patch-diff check) | Yes (`experimental=True`) | `stages/DirtyHeuristics.cpp` |
| S4 | `find_same_name("partial")` | Yes | `stages/SameName.cpp` |
| S5a | `find_remaining_functions` | Only when S3 returned True; it acts only if `is_patch_diff` | `stages/DirtyHeuristics.cpp` |
| S5b | `run_heuristics_for_category("Best")` | Yes, unless skip_others | `Pipeline.cpp` + `heuristics/*` |
| S5c | `find_partial_matches` = Partial category + `search_small_differences` (slow) | Yes, unless skip_others | `Pipeline.cpp` + `stages/SmallDifferences.cpp` |
| S5d | `apply_machine_learning` | No-op (model off) | — |
| S5e | Unreliable category + brute force + Experimental category | **No**: `self.unreliable` is False. There is also no heuristic with `"category":"Experimental"` in `H:` (OBSERVED enumeration: 12 Best, 30 Partial, 8 Unreliable). | `heuristics/Unreliable.cpp` (non-default) |
| S6 | iterative loop: callee diffing (assembly only when same CPU), related constants (slow), related CU, local affinity | Yes, unless skip_others | `stages/CalleeDiffing.cpp`, `RelatedConstants.cpp`, `RelatedCompilationUnit.cpp`, `LocalAffinity.cpp` |
| S7 | `final_pass` | Yes | `stages/FinalPass.cpp` |
| S8 | `find_unmatched` + `save_results` | Yes | `stages/Unmatched.cpp`, `ResultsWriter.cpp` |

### 10.3 Heuristic scheduling: `threads_apply` runs them in **reverse** order

`jkutils/threads.py:36-64`, verbatim with elisions:
```python
while first or len(targets) > 0 or len(threads_list) > 0:
  first = False
  times += 1
  if len(targets) > 0 and len(threads_list) < threads:
    item = targets.pop()
    ...
    t.start()
    threads_list.append(t)
  for i, t in enumerate(threads_list):
    if not t.is_alive():
      ...
      del threads_list[i]
      break
    if time.monotonic() - t.time > timeout:
      t.timeout = True
    t.join(wait_time)
```

Porting spec:
- With `threads = 1` (`D:1465` via `D:1444-1448` and `D:489-491`), heuristics run **one at a time in reverse order of the filtered list** built by `run_heuristics_for_category`. That is OBSERVED in experiment 1.
- The native driver must iterate the category's runnable specs **from the last to the first**, fully consuming each before starting the next.
- An exception inside a heuristic thread ends only that thread. Python threads print the traceback and die, and the main loop continues, so a crashing heuristic is **truncated at the crashing row**, not fatal. This matches `add_matches_from_query`, which swallows errors (`D:2080-2081`), and `add_matches_from_query_ratio*`, which re-raise inside the thread (`D:1967-1973`).

### 10.4 `run_heuristics_for_category(arg_category)` (`D:1461-1552`)

Verbatim filter and dispatch:
```python
for heur in heuristics:
  if len(self.matched_primary) == self.total_functions1 or\
     len(self.matched_secondary) == self.total_functions2:
    log("All functions matched in at least one database, finishing.")
    break
  category = heur["category"]
  if category != arg_category: continue
  ...
  if HEUR_FLAG_UNRELIABLE in flags and not self.unreliable: continue
  if HEUR_FLAG_SLOW in flags and not self.slow_heuristics: continue
  if HEUR_FLAG_SAME_CPU in flags and not self.is_same_processor: continue
  if arg_category.lower() == "unreliable":
    best = "partial"; partial = "unreliable"
  else:
    best = "best"; partial = "partial"
  sql = sql.replace("%POSTFIX%", postfix)
  if ratio == HEUR_TYPE_NO_FPS:            function = self.add_matches_from_query;               function_args = [sql, best]
  elif ratio == HEUR_TYPE_RATIO:           function = self.add_matches_from_query_ratio;         function_args = [sql, best, partial]
  elif ratio == HEUR_TYPE_RATIO_MAX:       function = self.add_matches_from_query_ratio_max;     function_args = [sql, best, partial, min_value]
  elif ratio == HEUR_TYPE_RATIO_MAX_TRUSTED: function = self.add_matches_from_query_ratio_max_trusted; function_args = [sql, min_value]
threads_apply(threads=total_cpus, targets=heuristic_functions, ...)
self.cleanup_matches()
self.show_summary()
```
Porting spec:
```
runnable = []
for spec in Registry (index order 0..49):
  if AllMatchedCount(): break                      # evaluated while BUILDING the list, before anything runs
  if spec.Category != cat: continue
  if spec has UNRELIABLE and !cfg.Unreliable: continue
  if spec has SLOW and !cfg.Slow: continue
  if spec has SAME_CPU and !state.IsSameProcessor: continue
  runnable.push(spec)
for spec in reverse(runnable):
  if state.AllFunctionsMatched(): continue          # each add_matches_* begins with this check (D:1956,1981,2007,2045)
  Consume(spec, best, partial)                      # Section 10.5.1
state.Cleanup()
```
Notes:
- `matched_primary`'s size counts **distinct key strings**, and `total_functions1` is `count(*)` (`D:1411-1422`). The keys mix `name` values with the `mangled_function` values that `find_equal_matches` uses (Section 10.7), so the test is unreliable in both directions:
  - duplicate names keep it below the row count, so it never fires;
  - a function keyed under both its mangled and its demangled name counts twice, so it can fire while functions are still unmatched.

  Port the comparison literally on key counts.
- `run_heuristics_for_category` uses `config.SQL_TIMEOUT_LIMIT` for `threads_apply` (`D:1548`), but `add_matches_internal` uses `self.timeout` (`D:1894`). The two differ only when `DIAPHORA_SQL_TIMEOUT_LIMIT` is set, and then `self.timeout` is a `str` (Section 10.1).
- A hook script can rewrite the heuristic list (`D:1477`) or the SQL (`D:1520`). The only default hook returns every value unchanged but can raise (Section 10.8). It is loaded only in patch-diff mode, and in that mode `run_heuristics_for_category` is never reached.

### 10.5 The match state machine (replaces `MatchStore`)

#### 10.5.1 Consumers: `add_matches_internal` and friends (`D:1882-2083`)

Verbatim routing (`D:1918-1946`):
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
    ...
  if chooser is not None:
    self.add_match(name1, name2, r, item, chooser)
```
Porting spec, by ratio type (`H:28-41`):

| Type | Call | Row cap | Routing (Best/Partial categories) |
|---|---|---|---|
| NO_FPS (0) | `add_matches_from_query(sql, best)` `D:2039-2083` | **none**; loops `while not cur_thread.timeout` | after `check_match` passes, always `add_match(name1, name2, 1.0, item(ratio=1), best)`. The computed `r` is used only for rejection inside `check_match`. |
| RATIO (1) | `..._ratio(sql, best, partial)` → `val=None` → 0.5, `unreliable=None` | 1,000,000 rows | `r == 1.0` → best; `r >= 0.5` → partial; else drop |
| RATIO_MAX (2) | `..._ratio_max(sql,best,partial,min)` with `unreliable="unreliable"` | 1,000,000 | `r == 1.0` → best; `r >= min` → partial; else drop |
| RATIO_MAX_TRUSTED (3) | `..._trusted(sql,min)` → `best="best"`, `partial="partial"`, `unreliable="partial"` | 1,000,000 | **Identical to RATIO_MAX**. The docstring says bad ratios go to "partial", but the code assigns the **literal** `"unreliable"`, and that branch is unreachable anyway (below). |

**The `unreliable` branch is dead in every default path.** The else-branch is reached only when `r < val` (given `partial` is non-None), while the unreliable condition needs `r > val`. So the **unreliable chooser is always empty by default**. In the Unreliable category (non-default), `best="partial"` and `partial="unreliable"`.

Row cap (`D:1874-1880`, `D:1893-1903`): the loop runs `while (i < 1000000)`, then `i += 1`, then `fetchone`, so **at most 1,000,000 rows are fetched** per call. Rejected rows and duplicate rows count toward the cap.

Timeout: `time.monotonic() - t > 300` raises `SystemExit`, which is swallowed (`D:1894-1896,1965-1966`). The timeout depends on wall-clock time and **cannot be reproduced**; see H5.

#### 10.5.2 `check_match(row)` (`D:1786-1872`)

The `ratio` parameter is always None at every call site (grep: `D:1906,2063,2129,2183`), so `ratio != 1.0` is always true. Verbatim core:
```python
if ratio != 1.0:
  nullsub = "nullsub_"
  if name1.startswith(nullsub) or name2.startswith(nullsub):
    return False, 0.0
  if self.has_best_match(name1, name2):
    return False, 0.0
  if ratio != 1.0:
    if ratio is None:
      r = self.check_ratio(main_d, diff_d)
    ...
    if self.has_better_match(name1, name2, r):
      return False, 0.0
should_add = True
args = [main_d, diff_d, desc, r]
should_add, r = self.call_hook("on_match", [should_add, r], args)
return should_add, r
```
Spec: `CheckMatch(row) → optional<double>`:
1. Apply the nullsub filter.
2. Apply `HasBestMatch`.
3. Compute `r = RatioEngine.CheckRatio(i, j, Source::Sql)`.
4. Apply `HasBetterMatch(r)`.
5. Apply the hook, which is always accept-unchanged by default.

`main_d`/`diff_d` are built from the row's `SELECT_FIELDS` projection (`H:51-75`). The fields `check_ratio` actually reads are `ea`, `pseudocode_primes`, `pseudo`, `md_index` (as `cast(... as real)`), `clean_assembly`, `clean_pseudo`, `clean_micro` and `bytes_hash`.

#### 10.5.3 `add_match`, `has_best_match`, `has_better_match` (`D:1340-1402`), verbatim

```python
def add_match(self, name1, name2, ratio, item, chooser):
  with self.items_lock:
    if name1 == name2:
      ratio = 1.0
    if ratio != 1.0:
      if self.has_better_match(name1, name2, ratio):
        return
      ...  # debug logging only
    if chooser is not None:
      if item not in self.all_matches[chooser]:
        self.all_matches[chooser].append(item)
    self.matched_primary[name1] = {"name": name2, "ratio": ratio}
    self.matched_secondary[name2] = {"name": name1, "ratio": ratio}

def has_best_match(self, name1, name2):
  if name1 in self.matched_primary and self.matched_primary[name1]["ratio"] == 1.0: return True
  if name2 in self.matched_secondary and self.matched_secondary[name2]["ratio"] == 1.0: return True
  return False

def has_better_match(self, name1, name2, ratio):
  if not name1.startswith("sub_") and not name2.startswith("sub_"):
    if name1 in self.matched_primary:
      return self.matched_primary[name1]["name"] == name1
  ratio = float(ratio)
  if name1 in self.matched_primary and self.matched_primary[name1]["ratio"] > ratio: return True
  if name2 in self.matched_secondary and self.matched_secondary[name2]["ratio"] > ratio: return True
  return False
```
Semantics to port exactly:
- The state is two `unordered_map<NameId, {NameId other; double ratio}>`, keyed by the **name strings the producer passed**. Most producers pass `f.name`/`df.name`, but `find_equal_matches` passes **`mangled_function`** (`D:1435-1440`), and callee diffing passes regex-extracted names (Section 10.11.1).
- **Overwrite, not reject.**
  - When neither name starts with `sub_` **and** `name1` is already in `matched_primary`, the result is exactly `matched_primary[name1]["name"] == name1`. In words: True **only** if `name1` is currently matched to a function that is literally also named `name1`, that is, a same-name match. Otherwise it is False, so the new match is accepted and **overwrites** `matched_primary[name1]`, even at a lower ratio. The ratio checks and the secondary-side check are skipped completely.
  - In every other case the function falls through to the ratio checks at `D:1396-1402`. That covers a pair where either name starts with `sub_`, and also a non-`sub_` pair whose `name1` is not mapped yet. Rejection then needs a **strictly** greater existing ratio on either side. Equal ratios are accepted and add a second item, which is how multimatches arise.
- `name1 == name2` forces the *state* ratio to 1.0, but the *item* keeps its original ratio. After the next `Cleanup`, state is rebuilt from item ratios (`D:1597-1603`), so the forced 1.0 disappears from the state.
- `item not in list` compares all 8 fields, and in Python `1 == 1.0`. Store ratio 1.0 as `double 1.0`. The difference cannot be observed: `"%.7f" % 1` gives `"1.0000000"` (OBSERVED).
- `items_lock` is irrelevant because everything runs on one thread.

#### 10.5.4 `cleanup_matches` (`D:1554-1605`), condensed (the rebuild loop re-reads `name1`/`name2`/`ratio` from `item[1]`/`item[3]`/`item[5]` at `D:1599-1601`)

```python
dones = {}; d = {}; ea_ratios = {}
for key, items in self.all_matches.items():          # "best", "partial", "unreliable" (D:382)
  d[key] = []
  l_items = sorted(items, key=lambda x: float(x[5]), reverse=True)
  for item in l_items:
    ea = item[0]; name1 = item[1]; name2 = item[3]; ratio = item[5]
    match = f"{name1}-{name2}"
    if match in dones: continue
    if name1 == name2: ratio = 1.0
    dones[match] = ratio
    if ea in ea_ratios and ea_ratios[ea] > ratio: continue
    else: ea_ratios[ea] = ratio
    d[key].append(item)
self.matched_primary = {}; self.matched_secondary = {}
for key, l_items in d.items():
  for item in l_items:
    self.matched_primary[name1] = {"name": name2, "ratio": ratio}   # item[1], item[3], item[5]
    self.matched_secondary[name2] = {"name": name1, "ratio": ratio}
self.all_matches = d
```
Spec:
- Python `sorted(..., reverse=True)` is **stable**: items with equal ratios keep their insertion order. Use `std::stable_sort` with a strict `>` on double.
- `dones` is keyed on the **concatenated string** `name1 + "-" + name2` and shared across categories. Keep it as a `std::string` key, because the concatenation *collides* when names contain `-` (for example demangled `operator-`, `operator->`).
- `ea_ratios` is keyed on `ea1` text only and uses a strict `>`. Ties on `ea1` survive, and the **diff side is not de-duplicated**. For `name1 == name2` the ratio used is the forced 1.0, but the stored item keeps its ratio.
- The state is rebuilt by iterating categories in order, so a later item for the same name overwrites an earlier one. Within a category the surviving items are in descending-ratio order, so for equal-name ties the **last** (lowest-ratio, or later-inserted equal-ratio) item ends up as the state.
- `self.all_matches = d` (`D:1605`) **replaces every list with its sorted, filtered copy**. After each cleanup, "insertion order" therefore means sorted order followed by later appends. Every cleanup call site must be ported exactly: `D:1551,2945,3185,3217,3340,3413,3471,3655,3671`.

#### 10.5.5 Helpers

- `all_functions_matched()`: `len(matched_primary) == total_functions1 or len(matched_secondary) == total_functions2` (`D:1777-1784`).
- `get_total_matched_functions()`: `len(best) + len(partial)` **items**, not functions (`D:3142-3148`). Unreliable items are not counted, and ties are counted.
- `get_sorted_results(cat)`: a stable sort by ratio, descending, that returns a **copy** (`D:3133-3140`). The loops iterate these snapshots while `add_match` appends to the live lists.

### 10.6 Ratio engine (`RatioEngine`: pure, cacheable, and safe to parallelise)

#### 10.6.1 `quick_ratio` and rounding

`D:150-165`:
```python
def check_bufs(buf1, buf2):
  if buf1 is None or buf2 is None: return False
  if buf1 == "" or buf2 == "": return False
  return True
def quick_ratio(buf1, buf2):
  if not check_bufs(buf1, buf2): return 0
  seq = SequenceMatcher(None, buf1.split("\n"), buf2.split("\n"))
  return seq.quick_ratio()
```
`cdifflib` is not installed (`D:41-49`), so this is stdlib `difflib` (`miniconda3/Lib/difflib.py:622-649`, verbatim):
```python
if self.fullbcount is None:
    self.fullbcount = fullbcount = {}
    for elt in self.b:
        fullbcount[elt] = fullbcount.get(elt, 0) + 1
fullbcount = self.fullbcount
avail = {}
availhas, matches = avail.__contains__, 0
for elt in self.a:
    if availhas(elt): numb = avail[elt]
    else: numb = fullbcount.get(elt, 0)
    avail[elt] = numb - 1
    if numb > 0: matches = matches + 1
return _calculate_ratio(matches, len(self.a) + len(self.b))
```
with `_calculate_ratio = 2.0 * matches / length if length else 1.0` (`difflib.py:39-42`).

Spec:
- `QuickRatio(a, b) = 2.0 * Σ_x min(ca[x], cb[x]) / (na + nb)`, where `n` counts `split('\n')` pieces. A trailing `\n` yields an extra `""` piece, and `\r` is kept.
- Return `0` when either side is NULL or `""`.
- `autojunk` does **not** affect `quick_ratio`, because `fullbcount` is built from raw `b`.
- Implement it as a merge of the precomputed sorted `(token, count)` runs.
- Rounding: `v = float("{0:.7f}".format(v))` (`D:1676,1710`). Use `std::to_chars(buf, end, v, std::chars_format::fixed, 7)` followed by `std::from_chars`. OBSERVED identical to Python on exact ties (experiment 5). Near-1 values round to exactly `1.0`: `0.99999996 → "1.0000000"`. The rounding must happen before any `== 1.0` test.
- `real_quick_ratio` (`D:169-176`) = `2*min(na,nb)/(na+nb)`. It is used only when `relaxed_ratio` is on, which is not the default.

#### 10.6.2 `check_ratio(main_d, diff_d)` (`D:1645-1775`), condensed (relaxed-only branches elided with `...`)

```python
key = f"{ea1}-{ea2}"
if key in self.ratios_cache: return self.ratios_cache[key]
...
md1 = float(md1); md2 = float(md2)
fratio = quick_ratio
decimal_values = "{0:.%s}" % config.DECIMAL_VALUES          # "{0:.7f}"
if bytes_hash1 == bytes_hash2:
  self.ratios_cache[key] = 1.0
  return 1.0
v3 = 0
... (relaxed-only AST block)
v1 = 0
if pseudo1 is not None and pseudo2 is not None and pseudo1 != "" and pseudo2 != "":
  if clean_pseudo1 == "" or clean_pseudo2 == "":
    log("Error cleaning pseudo-code!")
  else:
    v1 = fratio(clean_pseudo1, clean_pseudo2)
    v1 = float(decimal_values.format(v1))
    if v1 == 1.0:
      if fratio == real_quick_ratio: ...   # relaxed only
v2 = fratio(clean_assembly1, clean_assembly2)
v2 = float(decimal_values.format(v2))
if v2 == 1:
  if fratio == real_quick_ratio: ...       # relaxed only
if self.relaxed_ratio and not ast_done: ... # relaxed only
v4 = 0.0
if md1 == md2 and md1 > 0.0:
  if self.relaxed_ratio and md1 > config.MINIMUM_RARE_MD_INDEX: ...
  v4 = min((v1 + v2 + v3 + 3.0) / 5, 1.0)
v5 = 0.0
if clean_micro1 is not None and clean_micro2 is not None:
  v5 = fratio(clean_micro1, clean_micro2)
  v5 = float(decimal_values.format(v5))
  if v5 == 1:
    self.ratios_cache[key] = 1.0
    return 1.0
values_set = set([v1, v2, v3, v4, v5])
r = max(values_set)
if r == 1.0 and md1 != md2:
  r = 0
  for v in values_set:
    if v != 1.0 and v > r: r = v
if r < 1.0:
  score = self.deep_ratio(main_d, diff_d, r)
  if r + score < 1.0: r += score
  else: r = 0.99
self.ratios_cache[key] = r
return r
```
Default-mode spec (relaxed off):
```
double CheckRatio(i, j, MdSource src):
  if cache has (i,j): return it                      # key = ea1 + "-" + ea2 (the addresses are unique, so (i,j) is equivalent)
  md1, md2 = (src==Sql) ? (MdSqlReal[i], MdSqlReal[j]) : (MdPyFloat[i], MdPyFloat[j])
      # Python float(None) or float('') raises TypeError/ValueError -> see H6
  if PyEq(bytes_hash_i, bytes_hash_j): return 1.0    # Python ==: None == None is True
  v1 = 0; if pseudo_i,pseudo_j non-NULL non-empty:
      if clean_pseudo_i == "" or clean_pseudo_j == "": v1 = 0 (logged)
      else v1 = Round7(QuickRatio(clean_pseudo_i, clean_pseudo_j))
  v2 = Round7(QuickRatio(clean_asm_i, clean_asm_j))
  v3 = 0
  v4 = (md1 == md2 && md1 > 0.0) ? min((v1 + v2 + v3 + 3.0) / 5, 1.0) : 0.0    # keep this exact evaluation order
  v5 = 0; if clean_micro_i, clean_micro_j both non-NULL:
      v5 = Round7(QuickRatio(...)); if v5 == 1.0: return 1.0   # ignores md!
  r = max(v1..v5)
  if r == 1.0 && md1 != md2: r = max{ v in {v1..v5} : v != 1.0 } (0 if none)
  if r < 1.0: s = DeepRatio(i, j); r = (r + s < 1.0) ? r + s : 0.99
  cache (i,j) = r; return r
```
- The only inputs are per-function columns plus `is_same_processor`, which is constant after S2. The function is therefore **pure**, and ratios can be pre-computed in parallel.
- **The exception** is when `use_trained_model` is on. The classifier is loaded after the Partial category (`D:3636`), and `ratios_cache` then freezes the non-ML ratios computed earlier. That is not the default.
- **The two call paths share one cache**, keyed `f"{ea1}-{ea2}"` (`D:1653-1655`), but take md from different sources. `SELECT_FIELDS` casts md in SQL; `compare_function_rows` reads TEXT through `select *` and parses it with `float()`. A pair's cached ratio therefore comes from **whichever path computed it first**, and the native cache must behave the same way: first write wins, no recomputation. The two parses of the same text **do** differ for some real values (OBSERVED, Section 5.3 step 3). Both sides of a pair always use the same parser, though, so `md1 == md2` for equal texts holds either way. A divergence needs two *different* texts that collide under only one of the parsers.
- **Eager or parallel prefetch must not raise early.** `check_ratio` can raise:
  - `float(None)` at `D:1672`;
  - `json.loads(None)` in `deep_ratio` (`D:2813-2814`);
  - `deep_ratio`'s `main_row[...]` when the address lookup `str(int(ea))` finds no row (`D:2763-2780`).

  A prefetch that computes a ratio Diaphora never computes must store "would raise" as a value, and surface it only when the sequential consumer actually asks for that pair.

#### 10.6.3 `deep_ratio` (`D:2749-2837`), verbatim key lines

```python
cur.execute(sql.format(db="main"), (str(ea1),)); main_row = cur.fetchone()     # select * ... where address = ?
cur.execute(sql.format(db="diff"), (str(ea2),)); diff_row = cur.fetchone()
if source1 is not None and source2 is not None:
  if source1 == source2 and source1 != "": score += 0.001
if pseudocode_primes1 is not None and pseudocode_primes2 is not None:
  if pseudocode_primes1 == pseudocode_primes2 and pseudocode_primes1 != "": score += 0.001
if in1 == in2 and in1 != 0: score += 0.001
if out1 == out2 and out1 != 0: score += 0.001
if switches1 == switches2 and switches1 != "[]": score += 0.003
if cc1 == cc2 and cc1 != 0: score += 0.001
if main_row["constants"] != "[]":
  set1 = set(json.loads(main_row["constants"])); set2 = set(json.loads(diff_row["constants"]))
  set_result = set1.intersection(set2)
  if len(set_result) > 0:
    tmp = INCREASE_RATIO_PER_CONSTANT_MATCH_SAME_CPU if self.is_same_processor else INCREASE_RATIO_PER_CONSTANT_MATCH
    score += len(set_result) * tmp            # 0.006 same CPU / 0.008 otherwise (C:147-148)
if self.classifier is not None: ...           # off by default
```
Spec:
- Accumulate in a `double` that starts at 0, **in exactly this order**, because floating-point addition is order-dependent.
- Python `None` semantics apply. Two NULL `switches` are equal and `None != "[]"`, so both NULL gives +0.003. Two NULL `indegree`/`outdegree`/`cyclomatic_complexity` values give +0.001 each, because `None == None` and `None != 0`.
- `json.loads(None)` raises when main `constants` is NULL; see H6.
- **Set equality follows Python rules:** numbers compare by mathematical value (`1 == 1.0`, `hash(1) == hash(1.0)`), and strings compare by exact code points. JSON cannot produce `True`/`False` values unless the export contains a literal `true`, which would equal 1. Canonicalise at ingestion to a sorted vector of `{kind: int|float|str, value}` where an integral float equals the corresponding int. Big ints must stay exact (Python ints are unbounded), so keep them as decimal text.

### 10.7 `find_equal_matches` (`D:1404-1442`)

```python
fields = "id, address, mangled_function, nodes, edges, size, bytes_hash"
sql = f"""select address ea, mangled_function, nodes, bytes_hash
           from (select {fields} from functions intersect select {fields} from diff.functions) x"""
for row in rows:
  name = row["mangled_function"]; ea = row["ea"]; nodes = int(row["nodes"])
  item = [ea, name, ea, name, "100% equal", 1, nodes, nodes]
  self.add_match(name, name, 1.0, item, "best")
```
- **Inputs:** `id`, `address`, `mangled_function`, `nodes`, `edges`, `size`, `bytes_hash`. INTERSECT uses SQL value equality with NULLs treated as equal. It requires **identical `id` and `address`** on both sides.
- **Outputs:**
  - Best items with description `"100% equal"`. Name fields and state keys are **`mangled_function`**.
  - `ea1 == ea2`, taken from main.
  - There is no `check_match` and no ratio computation.
- Row order is SQLite's INTERSECT order, sorted in practice (NOT DETERMINED FROM SOURCE). It affects only item insertion order, which matters for later ties and for `line` numbering.
  - OBSERVED plan: `INTERSECT USING TEMP B-TREE`.
  - OBSERVED: 0 rows on both `userenv-9168-pdb`/`9278-pdb` and `ls-old`/`ls`, because the builds differ in `id`/`address`. This stage only matters for near-identical binaries.
- `int(row["nodes"])` raises on a NULL `nodes` in an intersected row (`D:1437`, main thread).
- **Runs by default?** Yes (`D:3614`).

### 10.8 Dirty heuristics (`D:2540-2637`) and `find_remaining_functions` (`D:2639-2716`)

```python
def apply_dirty_heuristics(self):
  if self.search_just_stripped_binaries(): return True
  if self.search_patchdiff_with_symbols(): return True
  return False
```

**Stripped binaries** (`D:2540-2585`):
- `matches = select count(0) from main.functions f, diff.functions df where f.address = df.address`.
- `percent = (matches * 100) / total_functions1`.
- If `percent >= 99.0` (`C:160`):
  - Set `is_symbols_stripped = True`.
  - Run `select distinct <fields 'Same binary with symbols stripped'> from functions f, diff.functions df where f.address = df.address` through `add_matches_from_query_ratio(sql, "best", "partial")`, which is RATIO routing.
  - Return True.

**Patch diff** (`D:2587-2627`):
- `matches = count of pairs with f.mangled_function = df.mangled_function`. Because this is a pair count, duplicate names inflate it.
- If `percent > 90.0` (`C:166`, strictly greater):
  - Set `is_patch_diff = True`.
  - If no project script is set and `RUN_DEFAULT_SCRIPTS` is on (`C:186`), load `scripts/patch_diff_vulns.py` as hooks.
  - Return True.
- **That hook never changes a returned result, but it can raise.**
  - Its `on_match` returns `True, ratio` on every path (`scripts/patch_diff_vulns.py:204-236`).
  - `get_heuristics`/`on_launch_heuristic` return their input unchanged (`:79-83`).
  - The return value of `get_queries_postfix` is discarded by the caller (`D:1475`).
  - It defines no `on_special_heuristic`, so `call_hook` defaults to True.
  - It fills an "Interesting matches" chooser that `save_results` never writes (`D:2409-2416`).

  However, for every match with `ratio < 1.0` it runs `unified_diff` over `asm`/`pseudo` and string heuristics. That code can raise on unusual input: for example `mnem1[0]` at `:162` raises `IndexError` when an added assembly line's first space-separated token is empty. It runs inside `check_match` (`D:1871`), which is called from main-thread stages in patch-diff mode (`find_same_name`, `find_remaining_functions`), so an exception there **aborts the whole diff**.

  The script also does `from diaphora import CChooser, log` (`:13`), which imports `diaphora.py` a second time as module `diaphora`. The only side effect is that module-level code runs again.

  Native: no hook *logic* is needed for results. Parity mode should either port the raising conditions of `find_vulns_using_assembly`/`find_vulns_using_pseudocode`, or document them as a known DIAPHORA_WOULD_RAISE gap (Section 10.15).
- `find_remaining_functions` always calls `get_unmatched_functions` (`D:2707`), including in stripped-binaries mode, but it only acts when `is_patch_diff` (`D:2708`).

**`find_remaining_functions`** (only when `is_patch_diff`):
- The input lists come from `select 'main' db_name, name, address from main.functions union select 'diff' ..., name, address from diff.functions`, each de-duplicated (`D:2647-2666`). The source does not specify an order.
  - OBSERVED on fixtures, and on copies of the real exports `userenv-9168-pdb`+`userenv-9278-pdb` (1,306 rows) and `ls-old`+`ls` (622 rows) under SQLite 3.51.1:
    - the plan is `COMPOUND QUERY / SCAN main.functions / UNION USING TEMP B-TREE / SCAN diff.functions`;
    - the output is sorted by `(db_name, name, address)`, so each list is in `(name, address)` BINARY order.
  - It is still planner behaviour, so Path A must reproduce it by running the same SQL.
- The pair loop (`D:2689-2698`):
  ```python
  for ea1, name1 in main_unmatched:
    if values["only_sub"]:
      if not name1.startswith("sub_"): continue
    for ea2, _ in diff_unmatched:
      cur.execute(sql, (values["heur"], ea1, ea2))     # where f.address = ? and df.address = ? and f.nodes >= 3 and df.nodes >= 3
      self.add_matches_internal(cur, best="best", partial="partial", val=values["val"])   # val = 0.6 (C:172)
  ```
  Each pair goes through `CheckMatch` and RATIO_MAX routing with a minimum of 0.6. The description is `"Renamed or anonymous function match in patch diffing session"`.
- The unmatched lists are snapshots taken before the loop.
- **Runs by default?** S3 always runs. S5a runs only when a dirty heuristic fires.

### 10.9 `find_same_name("partial")` (`D:2152-2210`)

```python
sql = """select distinct <fields 'Perfect match, same name'> from functions f, diff.functions df
          where (df.mangled_function = f.mangled_function or df.name = f.name)
          and f.name not like 'nullsub_%'"""
rows = cur.fetchall()
if len(rows) > 0 and not self.all_functions_matched():
  for row in rows:
    name = row["mangled1"]
    if self.ignore_sub_names and name.startswith("sub_"): continue
    should_add, ratio = self.check_match(row)
    if not should_add: continue
    if float(ratio) == 1.0 or (self.relaxed_ratio and md1 != 0 and md1 == md2):
      the_chooser = "best"; item = [ea, name1, ea2, name2, desc, 1, nodes1, nodes2]
    else:
      the_chooser = choose
      if ratio + config.MATCHES_BONUS_RATIO < 1.0: ratio += config.MATCHES_BONUS_RATIO   # 0.01 (C:116)
      item = [ea, name1, ea2, name2, desc, ratio, nodes1, nodes2]
    self.add_match(name1, name2, ratio, item, the_chooser)
```
- **Partial has no minimum ratio.** Any ratio that is not rejected goes to partial with +0.01.
- `not like 'nullsub_%'` is case-insensitive and needs at least one character after `nullsub`.
- `all_functions_matched()` is checked once, before the loop.
- **Runs by default?** Yes. `ignore_all_names` is False (`D:3623-3624`).

### 10.10 `search_small_differences("partial")` (`D:2085-2150`)

This runs after all Partial heuristics, inside `find_partial_matches` (`D:2212-2221`), when `slow_heuristics` is on.

```python
where f.nodes = df.nodes and f.edges = df.edges and f.mnemonics = df.mnemonics
  and f.cyclomatic_complexity = df.cyclomatic_complexity and f.names != '[]'
s1 = set(json.loads(row["f_names"])); s2 = set(json.loads(row["df_names"]))
total = max(len(s1), len(s2)); commons = len(s1.intersection(s2)); ratio = (commons * 1.0) / total
if self.has_better_match(name1, name2, ratio): continue
if ratio >= config.DEFAULT_PARTIAL_RATIO:
  should_add, ratio2 = self.check_match(row)
  if not should_add: continue
  ratio = ratio2
  the_chooser = "best" if ratio == 1.0 else choose
  self.add_match(name1, name2, ratio, item, the_chooser)
```
- It streams (`result_iter`, `D:139-146`) and has **no row cap**.
- The final ratio is `check_ratio`'s value, with **no minimum**.
- The description is `"Nodes, edges, complexity and mnemonics with small differences"`.
- `total = max(len(s1), len(s2))` is at least 1 whenever the main-side JSON list is non-empty, and the SQL filter `f.names != '[]'` usually guarantees that. It is not guaranteed for non-canonical JSON such as `'[ ]'`, which passes the text filter but parses to an empty list. If both sets are empty, the division by zero raises `ZeroDivisionError` in the main thread and the run aborts (H6). The exporter writes `json.dumps(list)` (`D:936-939`), which is canonical, so this is an edge case only.
- The filter covers only `f.names`. A NULL `df.names` makes `json.loads(None)` raise `TypeError` (`D:2120`), which also aborts the run. OBSERVED: no NULL `names` in the 7 real exports.
- The SQL has no `DISTINCT`, no `%POSTFIX%` and no `ORDER BY` (`D:2093-2106`), and `has_better_match` is evaluated with the **names** ratio *before* `check_match` (`D:2124`).
- `set(json.loads(...))` over names: only the sizes are used, so iteration order does not matter here.
- **Runs by default?** Yes (slow on).

### 10.11 The iterative loop (S6)

#### 10.11.1 Callee diffing: `find_matches_diffing` → `find_matches_diffing_internal` → `find_one_match_diffing` (`D:3033-3229`)

- `find_matches_diffing(iteration)` first calls `cleanup_matches()`.
- If `is_same_processor`, it runs field `"assembly"` with heur `"Callee found diffing matches assembly"`. It always runs field `"pseudocode"` with `"Callee found diffing matches pseudo-code"`.
- Each field gets its own inner loop, `iteration = 1..3` (`D:3158-3193`). The **outer** `iteration` argument is not used in descriptions.

```python
dones = set()
while iteration <= 3:
  old_total = self.get_total_matched_functions()
  for key in ["best", "partial"]:
    l = self.get_sorted_results(key)
    for match in l:
      match_key = f"{match[1]}-{match[3]}"
      if match_key in dones: continue
      dones.add(match_key)
      item = self.itemize_for_chooser(match)
      main_row, diff_row = self.get_row_for_items(item)     # select * from {db}.functions where name = ?  (fetchone)
      if main_row is not None and diff_row is not None:
        if main_row[field_name] is None: continue
        if diff_row[field_name] is None: continue
        dones = self.find_one_match_diffing(main_row, diff_row, field_name, heur, iteration, dones)
  self.cleanup_matches(); ...
  if new_total == old_total: break
  iteration += 1
```
`find_one_match_diffing`, condensed core (the progress log at `D:3076-3078` is dropped):
```python
main_lines = input_main_row[field_name].splitlines(keepends=False)
diff_lines = input_diff_row[field_name].splitlines(keepends=False)
df = unified_diff(main_lines, diff_lines, lineterm="")
minus = []; plus = []
for row in df:
  if len(row) == 0: continue
  c = row[0]
  if c == "-": minus.append(row)
  elif c == "+": plus.append(row)
  elif c == " ":
    if len(minus) > 0 and len(plus) > 0:
      matches1 = re.findall(CPP_NAMES_RE, "\n".join(minus), re.IGNORECASE)
      matches2 = re.findall(CPP_NAMES_RE, "\n".join(plus), re.IGNORECASE)
      minus = []; plus = []
      size = min(len(matches1), len(matches2))
      for i in range(size):
        name1 = matches1[i][0]; name2 = matches2[i][0]
        key = f"{name1}-{name2}"
        if key in dones: continue
        dones.add(key)
        if name1.startswith("nullsub") or name2.startswith("nullsub"): continue
        exists, l = self.functions_exists(name1, name2)
        if exists:
          main_row = l[0]; diff_row = l[1]
          min_nodes = min(main_row["nodes"], diff_row["nodes"]); max_nodes = max(...)
          if ((min_nodes * 100) / max_nodes) < config.DIFFING_MATCHES_MAX_DIFFERENT_BBLOCKS_PERCENT: continue   # 25
          if main_row["nodes"] < config.DIFFING_MATCHES_MIN_BBLOCKS: continue                                   # 3
          if diff_row["nodes"] < config.DIFFING_MATCHES_MIN_BBLOCKS: continue
          r = self.compare_function_rows(main_row, diff_row)
          if r == 1.0: chooser = "best"
          elif r > config.DEFAULT_TRUSTED_PARTIAL_RATIO: chooser = "partial"       # 0.3, strict >
          else: continue
          if r + config.MATCHES_BONUS_RATIO < 1.0: r += config.MATCHES_BONUS_RATIO
          should_add, r = self.call_on_match_hook(heur, r, main_row, diff_row)
          if should_add:
            new_item = [ea1, name1, ea2, name2, f"{heur} (iteration #{iteration})", r, nodes1, nodes2]
            self.add_match(name1, name2, r, new_item, chooser)
```
Spec and quirks:
- `CPP_NAMES_RE = "([a-zA-Z_][a-zA-Z0-9_]{3,}((::){0,1}[a-zA-Z0-9_]+)*)"` (`D:114`). `findall` returns the leftmost non-overlapping matches, and `[0]` is the whole match.
  - A hand-written scanner is equivalent: at each position, try `[A-Za-z_]` followed by at least 3 `[A-Za-z0-9_]` (greedy), then zero or more of `(::)?[A-Za-z0-9_]+`. On failure, advance one character. This means `0x1234abcd` yields `x1234abcd`.
  - Verify the scanner against Python with an oracle vector file rather than trusting `std::regex`.
  - **The scanner must work on Unicode code points, not bytes.** Under `re.IGNORECASE` on a `str` pattern, `[a-zA-Z_]` and `[a-zA-Z0-9_]` also match exactly four non-ASCII characters, OBSERVED by enumerating every code point: U+0130 `İ`, U+0131 `ı`, U+017F `ſ` and U+212A `K` (Kelvin sign). For example `findall` returns `'ſub_1234'` and `'Kernel'`. Decode UTF-8, treat those four as letters, and treat every other non-ASCII code point as a separator.
- `str.splitlines()` splits on `\n`, `\r`, `\r\n`, `\v`, `\f`, `\x1c`, `\x1d`, `\x1e`, `\x85`, `\u2028` and `\u2029`. OBSERVED: `'a\x0bb\x1cc\u2028d\r\ne'.splitlines()` gives `['a','b','c','d','e']`. This is **not** `split('\n')`.
- `unified_diff(a, b, lineterm="")` with the default `n=3`:
  - It yields the headers `"--- "` and `"+++ "`. The first starts with `-` and the second with `+`, so they are appended to `minus`/`plus` but contain no identifiers.
  - `"@@ ... @@"` lines are ignored.
  - A change with no context line after it is **never flushed**. Accumulation carries across hunk boundaries.
  - This needs a **faithful port of `difflib.SequenceMatcher`**: `find_longest_match`, `get_matching_blocks`, `get_opcodes`, `get_grouped_opcodes`, including `autojunk=True` (the popularity rule applies when `len(b) >= 200`) — see H3.
- `functions_exists` (`D:2969-2991`) runs `select * from (select 'main' db_name, * from main.functions where name = ? union select 'diff' db_name, * from diff.functions where name = ?) order by db_name desc`. It returns `size == 2`, and `l[0]` is main because `'main' > 'diff'`.
  - **Quirk:** `size == 2` also holds when `name1` has **two** rows in main and `name2` has none in diff, or the other way round. The caller then uses two rows from the *same* database as `main_row`/`diff_row` (`D:3080-3083`).
  - Normally both names must exist exactly once on their side. OBSERVED: names are unique in all 7 real exports, so the quirk needs duplicate names.
- `(min*100)/max` is Python true division. `max_nodes == 0` raises `ZeroDivisionError` and aborts the whole diff; see H6.
- `compare_function_rows` → `check_ratio` with **Python-float** md (Section 10.6.2).
- `dones` is shared between match keys and callee keys, both concatenated with `-`.
- Name lookups `get_function_row(name)` run `select * from functions where name = ?` and take the first row with `fetchone` (`D:2445-2460`). In practice that is the lowest-rowid row, whether SQLite scans the table or uses the `name` index `S:26`, but this is NOT DETERMINED FROM SOURCE. The question only matters when names are duplicated. For `"100% equal"` items, `name1` holds `mangled_function`, so the lookup can fail, and the item is skipped.
- **Runs by default?** Yes. The pseudocode field always runs; the assembly field runs only on the same processor.

#### 10.11.2 `find_related_matches` → `find_related_constants` (`D:3362-3394,3462-3494`)

- It is gated by `slow_heuristics`, which is on. It begins with `cleanup_matches()`.
- For each key in `best`, `partial` and each match in `get_sorted_results(key)`:
  - Skip the match if `f"{name1}-{name2}"` is in the local `dones`.
  - `break` the key's loop at the first `ratio < 0.8` (`C:194`).
  - Fetch both rows by name. If both `constants_count > 0`, run:
```python
main_consts = set(json.loads(main_row["constants"])); diff_consts = set(json.loads(diff_row["constants"]))
inter_consts = main_consts.intersection(diff_consts)
if len(inter_consts) > 0:
  sql = """ select <fields 'Same constants related matches'> from main.functions f, diff.functions df,
            main.constants mc, diff.constants dc
            where f.id = mc.func_id and df.id = dc.func_id and dc.constant = mc.constant
              and mc.constant = ? and abs(mc.constant) == 0 """
  for constant in inter_consts:
    cur.execute(sql, (str(constant),))
    self.add_matches_internal(cur, best="best", partial="partial")      # RATIO routing (val 0.5), cap 1e6
```
- `abs(mc.constant) == 0` keeps only constants that SQLite reads as numeric zero: non-numeric strings, `'0'`, `''`, `'0.0'` and hex text such as `'0x10'` (experiment 4). In practice this heuristic joins on **string constants**.
- The bound value is `str(constant)` (`D:3390`) of the parsed JSON element: an `int` becomes its decimal text, and a `str` is passed unchanged.
  - A non-zero `int` therefore never yields rows.
  - A numeric-looking `str` such as `"2"`, which occurs in real exports, never passes `abs()==0` either.
- **The iteration order of `inter_consts` is CPython `set` order.** For `str` elements it depends on `PYTHONHASHSEED` (randomised per process), so this stage is **non-deterministic in Diaphora itself**; see H4.
- **Runs by default?** Yes.

#### 10.11.3 `find_related_compilation_unit` (`D:3395-3460`)

```python
l = self.get_sorted_results("best"); l.extend(self.get_sorted_results("partial"))
for match in l:
  if match[5] < config.RELATED_MATCHES_MIN_RATIO: break          # 0.8; breaks the WHOLE loop
  cur.execute(sql_main, (name1,)); main_row = cur.fetchone()     # CU of name1 (first row)
  cur.execute(sql_diff, (name2,)); diff_row = cur.fetchone()
  if main_row is None or diff_row is None: continue
  cur.execute(sql, (float(start1), float(end1), float(start2), float(end2)))
     # select <fields 'Related compilation unit'> from functions f, diff.functions df
     #  where cast(f.address as real) between ? and ? and cast(df.address as real) between ? and ?
  self.add_matches_internal(cur, "best", "partial")               # RATIO routing, cap 1e6
```
- **Inputs:** `compilation_units` (name, start_ea, end_ea), `compilation_unit_functions`, `functions.name`, `functions.address`.
- The CU lookup is `SELECT distinct ... WHERE f.name = ?` with `fetchone`. When a function belongs to several CUs, which one comes back is planner order: NOT DETERMINED FROM SOURCE.
  - OBSERVED plan on the real exports (SQLite 3.51.1, with `sqlite_stat1` present):
    1. `SEARCH f USING COVERING INDEX idx_2 (name=?)`;
    2. `SEARCH cuf USING INDEX idx_39 (func_id=?)`;
    3. `SEARCH cus USING INTEGER PRIMARY KEY`;
    4. `USE TEMP B-TREE FOR DISTINCT`.

    The first row is therefore the function's `compilation_unit_functions` link with the lowest rowid.
  - OBSERVED: in all 7 real oracle exports, **no function belongs to more than one CU**, so the ambiguity does not arise on the current corpus.
- There is no `dones` set: every match with ratio ≥ 0.8 re-runs its CU range query, even when an earlier match already covered the same CU pair.
- `float(main_row["start_ea"])` and its three siblings (`D:3453-3456`) raise on a NULL or `''` `start_ea`/`end_ea`. That is a main-thread abort (Section 10.15). OBSERVED: none in the real exports.
- **Runs by default?** Yes (gated only by the hook, which defaults to True).

#### 10.11.4 `find_locally_affine_functions` → `find_functions_between` (`D:3231-3360`)

```python
tmp_matches = list(self.all_matches["best"]); tmp_matches.extend(list(self.all_matches["partial"]))
tmp_matches = sorted(tmp_matches, key=lambda x: [int(x[0]), int(x[2])])
for i, match in enumerate(tmp_matches):
  if i == 0 or i == size: continue
  area1 = [prev[0], match[0]]; area2 = [prev[2], match[2]]
  self.find_functions_between(area1, area2)
# find_functions_between:
sql = "select * from {db}.functions where address > ? and address < ? order by address desc"
main_rows (0 < n <= 100)  then diff_rows (0 < n <= 100)      # MAX_FUNCTIONS_PER_GAP (C:124)
for main_row in main_rows:
  for diff_row in diff_rows:
    if name1.startswith("nullsub_") or name2.startswith("nullsub_"): continue
    if not name1.startswith("sub_") and not name2.startswith("sub_"): continue
    if pseudocode_lines1 + pseudocode_lines2 != 0:
      if pseudocode_lines1 == 3 or pseudocode_lines2 == 3: continue
    r = self.compare_function_rows(main_row, diff_row)
    if r == 1.0: chooser = "best"
    elif r >= config.DEFAULT_PARTIAL_RATIO: chooser = "partial"
    else: continue
    if name1 in local_main_matched and main_score[name1] >= r: continue
    if name2 in local_diff_matched and diff_score[name2] >= r: continue
    should_add, r = self.call_on_match_hook(heur_text, r, main_row, diff_row)
    if should_add:
      self.add_match(name1, name2, r, [ea1, name1, ea2, name2, "Local affinity", r, nodes1, nodes2], chooser)
      local_main_matched.add(name1); main_score[name1] = r; local_diff_matched.add(name2); diff_score[name2] = r
```
- `find_locally_affine_functions` starts with the hook check and then `cleanup_matches()` (`D:3336-3340`). `tmp_matches` is a snapshot of best+partial sorted by `[int(ea1), int(ea2)]`.
- `address > ? and address < ?` compares **TEXT** (the column is `text`, and the parameters are the `str` addresses from items). It is lexicographic, and equals numeric order only when both sides have the same number of digits. OBSERVED: within each of the 7 real exports all addresses have the same decimal length (10 digits for the PE files, 7 for `ls`). The range can come out inverted when `ea2` values are not monotonic, and then the query returns nothing.
- `order by address desc` is also text ordering.
- There is **no `has_best_match` gate**, so an `r == 1.0` result goes through `add_match` unconditionally. That can create a second 1.0 item for a function, which then becomes a multimatch. For `r < 1.0`, `add_match`'s own `has_better_match` (`D:1353-1355`) still applies.
- `pseudocode_lines1 + pseudocode_lines2` raises `TypeError` if either is NULL (`D:3276`).
- `local_*` scores are per gap.
- **Runs by default?** Yes.

### 10.12 `final_pass` (`D:2937-2948`) = `cleanup_matches` + `find_multimatches` + `add_final_chooser_items`

`find_unresolved_multimatches` (`D:2839-2885`), condensed core (the source's `try: ....append(item) except KeyError: ... = [item]` is shown as `setdefault`):
```python
dones = set()
for key, items in self.all_matches.items():
  l = sorted(items, key=lambda x: float(x[5]), reverse=True)
  for match in l:
    ea1 = match[0]; ea2 = match[2]; ratio = match[5]
    key = f"{ea1}-{ea2}"
    if key in dones: continue
    dones.add(key)
    if ea1 not in max_main: max_main[ea1] = ratio
    if max_main[ea1] > ratio: continue
    max_main[ea1] = ratio
    multi_main.setdefault(ea1, []).append([ea2, ratio, match])
    if ea2 not in max_diff: max_diff[ea2] = ratio
    if max_diff[ea2] > ratio: continue
    max_diff[ea2] = ratio
    multi_diff.setdefault(ea2, []).append([ea1, ratio, match])
```
`add_multimatches_to_chooser` (`D:2732-2747`) is called for `multi_main` and then for `multi_diff`, with a **shared** `dones`:
```python
for ea in multi:
  if len(multi[ea]) > 1:
    for multi_match in multi[ea]:
      item = self.itemize_for_chooser(multi_match[2])
      key = f"{item.ea}-{item.ea2}"
      if key not in dones:
        dones.add(key)
        self.multimatch_chooser.add_item(item)
        ignore_list.add(ea)          # only when the item was new: an ea2 whose items were all added via multi_main is NOT ignored
```
`add_final_chooser_items` (`D:2916-2935`):
```python
for key, l in self.all_matches.items():
  l = sorted(l, key=lambda x: float(x[5]), reverse=True)
  for match in l:
    item = self.itemize_for_chooser(match)
    if item.ea in ignore_main or item.ea2 in ignore_diff: continue
    if item.ratio < max_main[item.ea]: continue
    if item.ratio < max_diff[item.ea2]: continue
    CHOOSERS[key].add_item(item)
```
- `itemize_for_chooser` (`D:2718-2730`) labels its locals misleadingly (`ratio = item[4]`, `nodes1 = item[5]`, ...), but it passes them positionally into `Item(ea, name, ea2, name2, desc, ratio, nodes1, nodes2)`, so the mapping comes out correct.
- Dict iteration follows insertion order, which gives the multimatch output order.
- `max_diff[item.ea2]` can raise `KeyError` only when the same `ea1-ea2` pair appears in an earlier category with a *lower* ratio than in a later one. In default flows best items are always 1.0, so this cannot happen. Note it as an edge case.
- A multimatch needs **exact double ties** at the maximum ratio. Any arithmetic deviation in `RatioEngine` changes categories.
- **Runs by default?** Yes.

### 10.13 `find_unmatched` (`D:2323-2356`) and the swapped labels

- `select name, address from functions`, in rowid order: rows whose `name not in matched_primary` go into the chooser titled `"Unmatched in primary"`, but that chooser is stored in **`self.unmatched_second`**.
- The diff side goes into `"Unmatched in secondary"`, stored in **`self.unmatched_primary`**.
- `save_results` writes `"primary": self.unmatched_primary` (`D:2414-2415`).
- **Output rows with `type='primary'` therefore list diff-database functions, and `type='secondary'` list main-database functions.** OBSERVED in experiment 3, and again on the real `ls-old_vs_ls.diaphora`: all 56 `primary` rows have diff-side names and addresses, and all 14 `secondary` rows have main-side ones.
- Functions in multimatches are *not* listed as unmatched, because they are still in `matched_primary`.
- The test is `name not in matched_primary`, keyed on the **`name` column**. A function matched only through `find_equal_matches`, whose key is `mangled_function`, is therefore listed as unmatched whenever its `name` differs from its `mangled_function` and nothing else matched it under `name`.
- **Runs by default?** Yes.

### 10.14 Registry of the 50 SQL heuristics and their default status

Generated by enumerating `diaphora_heuristics.HEURISTICS` (OBSERVED). "Native" gives today's `Definitions[]` slot. The chooser mapping follows Section 10.5.1.

| Id | Name | Cat | Type | min | Flags | Runs by default? | Native | Side tables |
|---|---|---|---|---|---|---|---|---|
| 0 | Same RVA and hash | Best | NO_FPS | | SAME_CPU | if same CPU | #0 | |
| 1 | Same order and hash | Best | NO_FPS | | SAME_CPU | if same CPU | #1 | |
| 2 | Function Hash | Best | NO_FPS | | SAME_CPU | if same CPU | #2 | |
| 3 | Bytes hash | Best | NO_FPS | | SAME_CPU | if same CPU | #3 | |
| 4 | Same address and mnemonics | Best | RATIO | | | yes | #4 | |
| 5 | Same cleaned assembly | Best | RATIO | | SAME_CPU | if same CPU | #5 | |
| 6 | Same cleaned microcode | Best | RATIO | | SAME_CPU | if same CPU | #6 | |
| 7 | Same cleaned pseudo-code | Best | RATIO | | | yes | #7 | |
| 8 | Same address, nodes, edges and mnemonics | Best | RATIO | | | yes | – | |
| 9 | Same RVA | Best | RATIO_MAX | 0.7 | SAME_CPU | if same CPU | – | |
| 10 | Equal assembly or pseudo-code (UNION; descs "Equal pseudo-code" / "Equal assembly") | Best | NO_FPS | | | yes | – | |
| 11 | Microcode mnemonics small primes product | Best | RATIO | | | yes | – | |
| 12 | Same named compilation unit function match | Partial | RATIO_MAX_TRUSTED | 0.44 | | yes | – | CU, CUF |
| 13 | Same anonymous compilation unit function match | Partial | RATIO_MAX | 0.449 | | yes | – | CU, CUF |
| 14 | Same compilation unit | Partial | RATIO | | SLOW | yes | – | CU, CUF |
| 15 | Same KOKA hash and constants | Partial | RATIO | | | yes | – | constants |
| 16 | Same KOKA hash and MD-Index | Partial | RATIO | | | yes | #8 | |
| 17 | Same constants | Partial | RATIO_MAX | 0.5 | | yes | #9 | |
| 18 | Same rare KOKA hash | Partial | RATIO_MAX | 0.45 | | yes | #10 | |
| 19 | Same rare MD Index | Partial | RATIO | | | yes | #11 | |
| 20 | Same address and rare constant | Partial | RATIO_MAX | 0.5 | | yes | – | constants |
| 21 | Same rare constant | Partial | RATIO_MAX | 0.2 | SLOW | yes | – | constants |
| 22 | Same MD Index and constants | Partial | RATIO | | | yes | – | |
| 23 | Import names hash | Partial | RATIO | | | yes | – | |
| 24 | Mnemonics and names | Partial | RATIO | | | yes | – | |
| 25 | Pseudo-code fuzzy hash | Partial | RATIO | | | yes | – | |
| 26 | Similar pseudo-code and names | Partial | RATIO_MAX | 0.579 | | yes | – | |
| 27 | Mnemonics small-primes-product | Partial | RATIO_MAX | 0.6 | | yes | – | |
| 28 | Same nodes, edges, loops and strongly connected components | Partial | RATIO_MAX | 0.549 | | yes | – | |
| 29 | Same low complexity, prototype and names | Partial | RATIO_MAX | 0.5 | | yes | – | |
| 30 | Same low complexity and names | Partial | RATIO_MAX | 0.5 | | yes | – | |
| 31 | Switch structures | Partial | RATIO_MAX | 0.5 | | yes | – | |
| 32 | Pseudo-code fuzzy (normal) | Partial | RATIO_MAX | 0.5 | | yes | – | |
| 33 | Pseudo-code fuzzy (mixed) | Partial | RATIO | | | yes | – | |
| 34 | Pseudo-code fuzzy (reverse) | Partial | RATIO | | | yes | – | |
| 35 | Pseudo-code fuzzy AST hash | Partial | RATIO_MAX | 0.35 | | yes | – | |
| 36 | Partial pseudo-code fuzzy hash (normal) | Partial | RATIO_MAX | 0.5 | SLOW, UNRELIABLE | **no** | – | |
| 37 | Partial pseudo-code fuzzy hash (reverse) | Partial | RATIO_MAX | 0.5 | SLOW, UNRELIABLE | **no** | – | |
| 38 | Partial pseudo-code fuzzy hash (mixed) | Partial | RATIO_MAX | 0.5 | SLOW, UNRELIABLE | **no** | – | |
| 39 | Same rare assembly instruction | Partial | RATIO_MAX | 0.5 | SAME_CPU | if same CPU | – | instructions |
| 40 | Same rare basic block mnemonics list | Partial | RATIO_MAX | 0.5 | | yes | – | bb_instructions, instructions |
| 41 | Loop count | Partial | RATIO_MAX | 0.49 | SLOW | yes | – | |
| 42 | Same graph | Unreliable | RATIO_MAX | 0.5 | | **no** | – | |
| 43 | Strongly connected components | Unreliable | RATIO_MAX | 0.8 | SLOW | **no** | – | |
| 44 | Nodes, edges, complexity and mnemonics | Unreliable | RATIO | | SLOW | **no** | – | |
| 45 | Nodes, edges, complexity and prototype | Unreliable | RATIO | | SLOW | **no** | – | |
| 46 | Nodes, edges, complexity, in-degree and out-degree | Unreliable | RATIO | | SLOW | **no** | – | |
| 47 | Nodes, edges and complexity | Unreliable | RATIO | | SLOW | **no** | – | |
| 48 | Same high complexity | Unreliable | RATIO | | SLOW | **no** | – | |
| 49 | Topological sort hash | Unreliable | RATIO | | | **no** | – | |

Default-run totals:
- On the same processor, 12 Best + 27 Partial.
- On different processors, 5 Best (4, 7, 8, 10, 11) and 26 Partial (#39 drops out).
- None of these run when a dirty heuristic fires.
- Consumption order is always **descending Id within each category** (Section 10.3).

Also note these exact SQL features. SQLite evaluates them, and a native generator must reproduce them:
- `select distinct`
- duplicate rows from the constants-table joins (#15 and #21 have no DISTINCT, so the same pair repeats once per shared constant)
- `union` in #10 and the CTEs
- `group by`/`GROUP_CONCAT` ordering in #40
- `order by f.source_file = df.source_file`
- `order by case ... end DESC` in #42
- **integer** division in `((min(f.nodes, df.nodes) * 100) / max(f.nodes, df.nodes)) < 50` (#39 `H:929`, #40 `H:974`):
  - both operands are INTEGER, so SQLite truncates, for example `(3*100)/7 = 42` (OBSERVED);
  - division by zero yields NULL, not an error;
  - this is unlike the Python true division in callee diffing (`D:3089`).
- bare, non-aggregated columns in `GROUP BY` queries: `f.id, f.name` in #39's CTEs (`H:895,906`) and `inst.func_id`/`func_id` in #40's CTEs (`H:943,950,957`). Their value comes from an arbitrary row of the group. That is only deterministic when every row of the group carries the same value. It holds for one-row groups (`having count(0) = 1` in #39 and in `unique_main_bblocks`), and in practice for #40's per-basic-block groups, because all instructions of a block share one `func_id`.
- the description literal is `repr(NAME)` (`H:80-84`). Python `repr` switches to double quotes when the text contains `'`, which none of the 50 names or the stage descriptions do today.

### 10.15 Things that make Diaphora raise instead of returning results (native parity mode must report the same outcome)

| Condition | Where | Effect |
|---|---|---|
| `program` union has ≠ 2 rows, or `callgraph_primes` is not a Decimal, or `callgraph_all_primes` is not JSON | `D:1297-1322` | exception in the main thread → the whole run aborts and **no `.diaphora` is written** |
| `diff.version` missing or empty | `D:3577-3588` | `diff()` returns False, but `save_results` still writes **empty** results (`D:3772-3773`) |
| NULL `md_index` in a SQL-path row | `float(None)` at `D:1672` | inside a heuristic thread: that heuristic ends. In main-thread stages (same name, small differences, the loop): the run aborts |
| `max_nodes == 0` in callee diffing | `D:3088-3091` | run aborts |
| NULL `nodes` (`int(row["nodes1"])`), NULL `constants` in `deep_ratio` (`json.loads(None)`), NULL names (`.startswith` on None) | various | as above, depending on the thread |
| heuristic > 300 s | `D:1894-1896` / `threads.py:62-63` | heuristic truncated, wall-clock dependent |
| `total_functions1 == 0` (empty main `functions`) | `percent = (matches * 100) / total` at `D:2562` (S3, experimental is on); also `show_summary` `D:1631` and the final log `D:3689` | `ZeroDivisionError` in the main thread: the run aborts, no `.diaphora` |
| NULL or `''` `compilation_units.start_ea`/`end_ea` for a matched function's CU | `float(...)` at `D:3453-3456` | main-thread abort |
| NULL `df.names` in a `search_small_differences` row | `json.loads(None)` at `D:2120` | main-thread abort |
| a single `add_matches_internal` call running > 300 s in a **main-thread** caller (`search_remaining_functions` `D:2696`, `find_related_constants` `D:3391`, `find_related_compilation_unit` `D:3458`) | `raise SystemExit()` at `D:1896` | Not caught there, and `diff()` has only `try/finally`, so the interpreter exits (status 0) **without writing** the `.diaphora`. The stripped-binaries path is different: it goes through `add_matches_from_query_ratio`, which swallows `SystemExit` (`D:1965-1966`). |
| a side table missing on the **diff** side (for example `compilation_units` in an old export) | `create_schema` only creates missing tables on **main** (`D:615-632`) | thread heuristics that reference it die (#12–#14 truncated to nothing); `find_related_compilation_unit` (main thread) aborts the run |
| the patch-diff hook raising (Section 10.8) | `scripts/patch_diff_vulns.py:162` and similar | main-thread abort in `find_same_name` or `find_remaining_functions` |

Real IDA exports should not contain these conditions. OBSERVED on the 7 real oracle exports:
- no NULL `md_index`, `constants`, `names` or `nodes`;
- no NULL CU bounds;
- one `program` row each;
- `version = '3.4'`.

The engine must detect these conditions and report `DIAPHORA_WOULD_RAISE <where>` instead of silently diverging.

---

## 11. What must change: concrete architecture

### 11.1 Separate pure candidate generation from sequential consumption

```
                          (parallel, pure)                          (sequential, exact order)
Ingest ──► tables ──► CandidateSource[h] (rows in SQLite order) ──► Consumer (CheckMatch/AddMatch) ──► MatchState
                  └─► RatioEngine prefetch (parallel, cached)  ───────────────▲
Stages (equal, dirty, same-name, small-diff, loop, final pass) read/write MatchState directly, in diff() order.
```

1. **Candidate streams are pure functions** of `(main, diff, postfix, is_same_processor)` for all 50 SQL heuristics and for S1, S3, S4 and S5c. They do not depend on match state. All of them can be generated up front and in parallel on the `ThreadPool` (one heuristic per work item), and bounded to 1,000,000 rows per stream wherever a cap applies.
   - Exceptions whose candidates depend on state: `find_remaining_functions` (unmatched lists), callee diffing, related constants, related CU and local affinity. These generate lazily at their stage.
2. **Ratios are pure** in default mode (Section 10.6.2). Keep a `PairCache` (a concurrent map, or a two-phase design: prefetch ratios for the next K rows of the current stream in parallel, then consume in order). The results are identical whether computation is lazy or eager, because rows rejected by `HasBestMatch` never needed a ratio, and computing one does not change state.
3. **The consumer is single-threaded** and implements Sections 10.4–10.5 exactly.

### 11.2 Two interchangeable `CandidateSource` implementations

- **Path A, `SqlCandidateSource` (the reference). Build it first.**
  1. Open main with `sqlite3_open_v2(..., SQLITE_OPEN_READONLY | SQLITE_OPEN_URI)`.
  2. Run `ATTACH 'file:<diff>?mode=ro' AS diff`.
  3. Execute the heuristic's **verbatim** SQL from the registry, with `%POSTFIX%` substituted.
  4. Read `ea`, `ea2` and `description` from each row and map `ea` → row index through `RowByAddress`.

  This path reproduces, by construction:
  - the row order;
  - `DISTINCT` and the duplicate rows;
  - NULL and affinity semantics;
  - LIKE;
  - `GROUP_CONCAT`;
  - the md cast.

  It depends on using the **same SQLite build** and **the same files**.
  - The build is 3.51.1. `CMakeCache.txt` OBSERVED `SQLite3_INCLUDE_DIR=<conda>/Library/include`, `SQLite3_LIBRARY=.../Library/lib/sqlite3.lib`, and the header's `SQLITE_VERSION "3.51.1"`. Python reports `sqlite3.sqlite_version == '3.51.1'`.
  - The files matter because `sqlite_stat1` from the exporter's `analyze` (`D:634-649`, called from `diaphora_ida.py:1281`) steers the planner. OBSERVED: all 7 real exports have `sqlite_stat1` and 44 indices.

  It is not Python, so it satisfies the "native C++, minimal Python" rule. Caveats:
  - **The DLL is resolved at run time.** The exe links the import library, so which `sqlite3.dll` loads depends on the loader search order: the exe directory, then System32, then `PATH`. `dsig_build.cmd` prepends `miniconda3\Library\bin` to `PATH` for ctest only. There is no `System32\sqlite3.dll` on this PC, only `winsqlite3.dll`, which has a different name. Parity mode should check `sqlite3_libversion()` at startup and refuse anything other than the oracle's version, or stage the DLL beside the exe as CI does.
  - **The exports are in WAL mode.** OBSERVED `pragma journal_mode` = `wal` on all 7, set by the exporter at `diaphora_ida.py:1187-1188`. A read-only open needs the `-shm`/`-wal` sidecars to exist or to be creatable (SQLite ≥ 3.22).
  - **Diaphora's main connection is read-write.** `create_schema` runs `create table if not exists` for every table on **main** (`D:615-632`). An old main export that lacks a side table therefore gets an empty one, and queries against it return no rows. A read-only Path A connection would fail with "no such table" instead. Treat a missing table as empty on the main side only.
- **Path B, native generators (optimisation).** Hash joins over the in-memory tables, which must emit **exactly Path A's row sequence**. Every Path B generator ships with a test that compares its rows to Path A's on fixtures. When exact order emulation is infeasible (planner order, sorter ties), keep Path A for that heuristic.

### 11.3 Replace `Match`/`MatchCategory`/`MatchStore`

New types (`diff/MatchState.h`):
```cpp
enum class Chooser : uint8_t { Best = 0, Partial = 1, Unreliable = 2, Multimatch = 3 };
struct Item {                    // Diaphora item [ea, name1, ea2, name2, desc, ratio, nodes1, nodes2]
  uint32_t Main, Diff;           // row indices; ea text = Address.View(Main)
  NameId Name1, Name2;           // the exact strings the producer used
  DescId Description;            // interned text, e.g. "Callee found diffing matches pseudo-code (iteration #2)"
  double Ratio;
  int64_t Nodes1, Nodes2;
  bool operator==(const Item&) const = default;     // Python list equality (Section 10.5.3)
};
class MatchState {
public:
  void AddMatch(NameId N1, NameId N2, double Ratio, const Item& It, std::optional<Chooser> C);
  bool HasBestMatch(NameId N1, NameId N2) const;
  bool HasBetterMatch(NameId N1, NameId N2, double Ratio) const;
  void Cleanup();
  bool AllFunctionsMatched() const;
  size_t TotalMatchedFunctions() const;             // best.size() + partial.size()
  std::vector<Item> SortedResults(Chooser C) const; // stable, desc ratio, copy
  const std::vector<Item>& Items(Chooser C) const;
private:
  std::vector<Item> All_[3];                        // best, partial, unreliable (insertion order)
  std::unordered_map<NameId, std::pair<NameId,double>> Primary_, Secondary_;
  // `item not in list`: keep an unordered_set<ItemKey> per chooser for O(1) membership
};
```
`final_pass` produces `FinalResults { vector<Item> Best, Partial, Unreliable, Multimatch; vector<uint32_t> UnmatchedMain, UnmatchedDiff; }`. `ResultsWriter` and `PortSymbols` consume it.

### 11.4 Pipeline driver

`DiffSession::Run()` follows Section 10.2 literally, with stage functions `void Stage_X(DiffSession&)`. `DiffConfig` mirrors Section 10.1. The session owns the tables, side tables, `NameTable`, `MatchState`, `RatioEngine`, `CandidateSource` and a `Log` sink that emits Diaphora's summary lines.

### 11.5 Status of the existing modules

- `ThreadPool` is unchanged.
- `Heuristics.cpp` and `MatchStore.cpp` become the "legacy fast engine". Keep them behind `--engine legacy` until the new engine reaches parity, then delete them together with `resolve_tests`' `MatchStore` suites.
- `Naming.h` keeps `IsPortableSymbol`, which is used by `port`. The Python and SQL predicates move into `diff/SqlSemantics.h` and `diff/PySemantics.h`.

---

## 12. Proposed file layout for parallel implementation (disjoint ownership)

Rule: the **lead creates every file below in one scaffolding commit**:
- all headers with final signatures;
- the registry with all 50 specs, including verbatim SQL, and all stage entries;
- every generator and stage as a compiling stub that returns `NotImplemented` (the pipeline then falls back to Path A for heuristics, and a stub stage is logged as skipped);
- every test executable registered in CMake.

After that commit, **engineers edit only the files they own**, and nobody touches `CMakeLists.txt`, `Registry.cpp` or shared headers without the lead.

```
include/dsigmatcher/diff/
  Table.h            FunctionTable v2, TextColumn/IntColumn, NameTable            [lead]
  SideTables.h       constants/CU/instructions/bb_instructions/program/version    [lead]
  SqlSemantics.h     text compare, literal affinity, LIKE, abs/cast, length       [owner: semantics]
  PySemantics.h      startswith variants, None-equality helpers, float() parse    [owner: semantics]
  Registry.h         HeuristicSpec, StageSpec, enums, Heuristics(), Stages()      [lead, frozen]
  Candidates.h       CandidateRow, CandidateStream, generator declarations x50    [lead, frozen]
  MatchState.h       Section 11.3                                                 [owner: state]
  Ratio.h            RatioEngine (QuickRatio, Round7, CheckRatio, DeepRatio)      [owner: ratio]
  TextDiff.h         SequenceMatcher port, unified_diff, splitlines, name scanner [owner: textdiff]
  Pipeline.h         DiffConfig, DiffSession, stage declarations                  [lead]
  ResultsWriter.h    .diaphora writer + legacy tables                             [owner: output]
src/diff/
  Registry.cpp                 the 50 + 11 table (verbatim SQL literals)          [lead, frozen after M0]
  Ingest.cpp                   Section 5.3                                        [owner: ingest]
  SideTables.cpp                                                                  [owner: ingest]
  SqlCandidateSource.cpp       Path A                                             [lead]
  MatchState.cpp               Sections 10.5.3-10.5.5                             [owner: state]
  Consumer.cpp                 check_match + add_matches_* routing (10.5.1-2)     [owner: state]
  Ratio.cpp                    Section 10.6                                       [owner: ratio]
  TextDiff.cpp                 Section 10.11.1 difflib/regex/splitlines           [owner: textdiff]
  SqlSemantics.cpp, PySemantics.cpp                                               [owner: semantics]
  Pipeline.cpp                 Section 10.2 driver + S2 + category runner (10.3/10.4) [lead]
  ResultsWriter.cpp            Section 8.2                                        [owner: output]
  heuristics/Best_Hashes.cpp          Ids 0,1,2,3                                 [owner: H-a]
  heuristics/Best_TextEqual.cpp       Ids 4,5,6,7,8,10                            [owner: H-a]
  heuristics/Best_RvaSpp.cpp          Ids 9,11                                    [owner: H-a]
  heuristics/Partial_CompUnit.cpp     Ids 12,13,14                                [owner: H-b]
  heuristics/Partial_KokaMd.cpp       Ids 15,16,18,19,22                          [owner: H-b]
  heuristics/Partial_Constants.cpp    Ids 17,20,21                                [owner: H-b]
  heuristics/Partial_Names.cpp        Ids 23,24,26,29,30                          [owner: H-c]
  heuristics/Partial_PseudoFuzzy.cpp  Ids 25,32,33,34,35,36,37,38                 [owner: H-c]
  heuristics/Partial_Structure.cpp    Ids 27,28,31,41                             [owner: H-d]
  heuristics/Partial_Instructions.cpp Ids 39,40                                   [owner: H-d]
  heuristics/Unreliable.cpp           Ids 42..49 (non-default)                    [owner: H-d]
  stages/Preflight.cpp          S0 (version, equal_db log, callgraph checks)      [owner: stages-1]
  stages/EqualMatches.cpp       S1 (10.7)                                         [owner: stages-1]
  stages/DirtyHeuristics.cpp    S3 + S5a (10.8)                                   [owner: stages-1]
  stages/SameName.cpp           S4 (10.9)                                         [owner: stages-1]
  stages/SmallDifferences.cpp   S5c tail (10.10)                                  [owner: stages-2]
  stages/CalleeDiffing.cpp      10.11.1                                           [owner: stages-2]
  stages/RelatedConstants.cpp   10.11.2                                           [owner: stages-3]
  stages/RelatedCompilationUnit.cpp 10.11.3                                       [owner: stages-3]
  stages/LocalAffinity.cpp      10.11.4                                           [owner: stages-3]
  stages/FinalPass.cpp          10.12                                             [owner: state]
  stages/Unmatched.cpp          10.13                                             [owner: output]
tests/
  TestHarness.h                 shared CHECK/CHECK_EQ/Suite/Report (from tests/dsigmatcher_tests.cpp:25-42) [lead]
  diff/registry_tests.cpp       50 specs: names/category/type/min/flags equal the H: enumeration [lead]
  diff/semantics_tests.cpp      experiment-4 vectors                              [semantics]
  diff/state_tests.cpp          add_match/has_better/cleanup/final-pass vectors   [state]
  diff/ratio_tests.cpp          quick_ratio/Round7/check_ratio/deep_ratio oracle vectors [ratio]
  diff/textdiff_tests.cpp       unified_diff/splitlines/name-scanner oracle vectors [textdiff]
  diff/heuristics_<group>_tests.cpp  Path B rows == Path A rows on fixtures       [each H owner]
  diff/stages_<n>_tests.cpp                                                       [each stage owner]
  diff/parity_tests.cpp         fixture pairs: native .diaphora == oracle .diaphora (Section 13) [lead]
tools/parity/
  make_fixture.py     builds Diaphora-schema DBs from S:TABLES (as in Section 1.3), PLUS every S:INDICES entry
                      (S:23-65), `analyze`, and WAL mode, exactly like a real export (D:634-649,
                      diaphora_ida.py:1187-1188). Without them the planner, and so the row order, differs from real exports.
  run_oracle.py       copies inputs, runs `python -B diaphora.py db1 db2 -o out` with PYTHONHASHSEED=0,
                      DIAPHORA_LOG_PRINT=1, PYTHONDONTWRITEBYTECODE=1; saves out + log
  dump_rows.py        for each heuristic SQL: row sequence (ea, ea2, description) via Python sqlite3
  compare.py          compares results/unmatched tables (ignoring config.date; line/order optional)
  gen_vectors.py      emits C++ .inc oracle vectors (quick_ratio, Round7, splitlines, findall, unified_diff)
```

The registry is declared once:
```cpp
// Registry.h
enum class RatioType : uint8_t { NoFps = 0, Ratio = 1, RatioMax = 2, RatioMaxTrusted = 3 }; // H:28-41
enum class HeurCategory : uint8_t { Best, Partial, Unreliable, Experimental };
enum HeurFlag : uint8_t { FlagUnreliable = 1u << 0, FlagSlow = 1u << 1, FlagSameCpu = 1u << 2 };
// Our own bitmask. Diaphora's flags are NOT bits: HEUR_FLAG_NONE=0, UNRELIABLE=1, SLOW=2, SAME_CPU=3 (H:44-48)
// are list elements, tested by membership (`HEUR_FLAG_SLOW in flags`, D:1498-1508). Derive the mask by membership.
using CandidateGenerator = GenStatus (*)(const GenContext&, CandidateStream&);   // NotImplemented => Path A
struct HeuristicSpec {
  uint16_t Id;                   // == index in diaphora_heuristics.HEURISTICS (0..49)
  const char* Name;              // verbatim NAME
  HeurCategory Category;
  RatioType Type;
  double Min;                    // heur["min"]; 0.0 when absent (D:1493-1495)
  uint8_t Flags;
  const char* Sql;               // verbatim, including %POSTFIX%
  CandidateGenerator Native;     // defined in heuristics/<group>.cpp
};
std::span<const HeuristicSpec> Heuristics();
```
CMake: the lead adds a helper function once:
```cmake
function(dsig_add_suite Name Source)
  add_executable(${Name} ${Source})
  target_link_libraries(${Name} PRIVATE dsigmatcher_core)
  dsig_apply_warnings(${Name})
  add_test(NAME ${Name} COMMAND ${Name})
endfunction()
```
The lead then lists every `src/diff/**` source and every `dsig_add_suite(...)` explicitly. Globs are ruled out because they break incremental reconfiguration and hide files.

---

## 13. Parity harness and milestones

- **Real exports now exist.** HANDOFF Blocker 1 is superseded. `<corpus>/oracle` holds 7 IDA 9.4 + Diaphora exports and 5 pairs (`docs/parity/09-oracle.md`), built by the untracked `tools/oracle/build_oracle.py`. That tool already runs Diaphora twice per pair and records `determinism.json` and `run.json` (with `timeouts_logged`). Use it as the L1–L3 reference. The rest of this bullet covers the synthetic fixtures, which remain useful for targeted cases.
  - OBSERVED:
    - `ls-old_vs_ls`, `ls_vs_ls-old` and `userenv-9168-pdb_vs_9278-pdb` finished and were deterministic across the two runs.
    - `userenv-9168-pdb_vs_9278-pdb` takes the patch-diff short-circuit.
    - The `*-nopdb` pairs were still running during this verification, at over 400,000 rows in one heuristic.
- **Fixtures.** Use `tools/parity/make_fixture.py` to generate schema-exact pairs that target each heuristic and stage. Run `run_oracle.py` on **copies** (Diaphora writes to db1, Section 10.1). Commit the fixture generator and the expected outputs as small SQLite files, or regenerate them at test time only when Python is available, and skip otherwise, in the same way `DSIG_CORPUS_ROOT` is handled.
- **Comparison levels.**
  - L1: the set of `(type, address, address2)` plus `ratio` text plus `description`.
  - L2: L1 plus `name`/`name2`/`nodes`.
  - L3: L2 plus `line` numbers and row order.
  - Unmatched: the set of `(type, address)`.
- **Milestones.**
  - **M0 (lead):** scaffolding, the registry, Path A, `MatchState`, `RatioEngine`, the writer, and the driver with S0–S8. S4 same name, S5a remaining functions and S7 final pass are enough for the win32u pair (patch-diff mode, Section 10.8).
  - **M1 (parallel):** stage owners and Path B generators per group.
  - **M2:** L3 parity on all fixtures plus real exports; retire the legacy engine.
- **Order sanity check.** `dump_rows.py`, run under Python's sqlite3, versus Path A under the C API. The same DLL should give identical sequences; this is the cheapest test of H2.

---

## Hard parts

- **H1: order sensitivity everywhere.**
  - The outcome depends on heuristic order (reverse per category), row order within a heuristic, and `all_matches` insertion order, which feeds stable sorts, cleanup's first-come dedup, multimatch detection and output line numbers.
  - The overwrite rule for non-`sub_` names (Section 10.5.3) means that even a *lower* ratio later can replace the state.
  - Nothing here can be batched or reordered. Only the pure parts (candidate rows, ratios) can go parallel.
- **H2: SQL row order is set by SQLite, not by source.** Counts are OBSERVED over `H:`. It depends on:
  - no `ORDER BY` in 16 of 50 heuristics (Ids 0, 1, 2, 3, 10, 12, 14, 15, 16, 18, 21, 27, 28, 29, 30 and 39), and none on the outer query of #40;
  - `order by f.source_file = df.source_file` in 32 heuristics, a boolean key with massive ties;
  - #42's `order by case ... DESC`, also full of ties;
  - UNION/INTERSECT/DISTINCT implementation;
  - `GROUP_CONCAT` element order (#40);
  - `fetchone` of multi-row CU lookups.

  All of it depends on SQLite version, indices and `sqlite_stat1`. Path A fixes this locally (same DLL, OBSERVED 3.51.1 on both sides).
  - OBSERVED plans on the real exports:
    - `select name, address from functions` is `SCAN functions`, and its output equals `order by rowid` on all 7 exports;
    - the `name = ?` lookup uses `idx_2 (name=?)`;
    - `find_equal_matches` is `INTERSECT USING TEMP B-TREE`, with 0 rows on both finished real pairs, because they are different builds. **CI links different SQLite builds** (apt/brew/vcpkg), so order-exact parity tests can fail there. Either pin SQLite (for example the amalgamation 3.51.1 via FetchContent, which also changes local builds) or run L3 parity tests only locally, with CI at L1.
- **H3: a faithful difflib port for callee diffing.** `unified_diff` → `get_grouped_opcodes(3)` → `get_matching_blocks` → `find_longest_match` with `autojunk` popularity pruning and the `isbjunk` extension loops. The pruning rule, verbatim from `miniconda3/Lib/difflib.py:297-303`: `if self.autojunk and n >= 200: ntest = n // 100 + 1`, and then every element with `len(idxs) > ntest` is removed from `b2j`. Pair it with CPython-exact `str.splitlines` and a hand scanner for `CPP_NAMES_RE`. Any deviation changes which identifier pairs are proposed. Vendor-test it against thousands of Python-generated vectors.
- **H4: Diaphora is itself non-deterministic in `find_related_constants`.** It iterates a Python `set` of constants (`D:3389`), and for strings that order depends on `PYTHONHASHSEED`. Options:
  - (a) run the oracle with `PYTHONHASHSEED=0` and emulate CPython's set iteration: SipHash-1-3 with key 0, set table size and probing;
  - (b) run the oracle under two seeds and exclude pairs whose results differ, recorded as "oracle-unstable";
  - (c) accept L1 divergence for this stage.

  Recommended: (b) first, then (a) if divergences show up in practice.
  - `tools/oracle/build_oracle.py` already implements (b): it runs each pair twice and does not set `PYTHONHASHSEED`, so each run gets a random seed.
  - OBSERVED: `ls-old_vs_ls`, `ls_vs_ls-old` and `userenv-9168-pdb_vs_9278-pdb` gave `results` and `unmatched` identical in order across their two runs (`determinism.json`: `results_identical_in_order`, `unmatched_identical_in_order` and `deterministic` are all `true`).
  - Two runs are weak evidence, but on those pairs the order of `inter_consts` did not matter.
  - OBSERVED: in real exports, `functions.constants` JSON mixes `str` and `int` elements (userenv-9168: 348 str, 412 int). `abs(mc.constant) == 0` keeps 147 of 559 `constants` rows in userenv-9168 and 169 of 358 in `ls`.
- **H5: wall-clock timeouts and the 1e6-row cap.** The cap is deterministic and must be emulated per stream, including duplicate rows. The 300 s timeout is not deterministic. `run_oracle.py` must grep the log for `Timeout with heuristic` and mark the run as non-comparable. `build_oracle.py` already records `timeouts_logged` in each `run.json`.
  - The timer covers per-row `check_ratio`/`deep_ratio` work too, not just SQL.
  - For main-thread callers a timeout exits the whole process (Section 10.15).
- **H6: exception semantics.** Section 10.15 shows that Diaphora aborts on some inputs, truncates heuristics on others, and writes empty results on a bad version. The native engine must detect those preconditions and report them, never silently diverge.
- **H7: two floating-point parse paths and exact arithmetic.**
  - `md` comes from `cast(... as real)` in SQL rows but from Python `float()` in `compare_function_rows` rows. These really differ by 1 ULP on some 28-digit values: 2 of 4,754 real `md_index` values, and about 0.05% of random 28-digit strings (OBSERVED, Section 5.3 step 3). SQLite's cast is not correctly rounded; Python's is.
  - Rounding is `"{0:.7f}"`: round-half-even on the exact binary value, which `std::to_chars` matches (OBSERVED).
  - `v4 = min((v1+v2+v3+3.0)/5, 1.0)`, `deep_ratio`'s addition order, `r + score < 1.0`, and thresholds compared as doubles must all be reproduced operation for operation. Multimatch depends on **exact** ties.
- **H8: mixed NULL semantics.** SQL paths use three-valued logic with `''` ≠ NULL. Python paths use `None == None` is True, `None != "[]"` is True, and `.startswith` on None raises. TEXT-affinity literals such as `kgh_hash != 0`, `microcode_spp != 1` and `strongly_connected_spp > 1` compare as text. The ingestion layer must preserve NULL for every column.
- **H9: name-keyed state.**
  - Names are not guaranteed unique: `name` is IDA's *demangled short* name (`diaphora_ida.py:2451-2453`), so overloads can collide.
  - `find_equal_matches` keys on `mangled_function`.
  - Keys built by string concatenation with `-` can collide.
  - Emulate this with interned name strings and concatenated-string keys. Never key on row indices.
- **H10: memory.** Path A plus in-memory tables hold `pseudocode`/`assembly` for both sides, KB-scale per function. Use per-column pools with 64-bit offsets (T5), and consider memory-mapping or lazy loading of `assembly`/`pseudocode`. Only callee diffing, #10 and the `check_ratio` pseudo gate need them.

## Open questions

1. **Scope of "parity".** Is the target the default standalone config only (Section 10.1)? Or must `--unreliable`, `--relaxed-ratio` and `ML_USE_TRAINED_MODEL` also match? The ML path needs the sklearn pickle, and IDA-mode multi-threaded runs are non-deterministic (`D:489-491` disables threads outside IDA precisely because "Parallel diffing is broken").
   - *Partly resolved by the task statement, not by source:* the workflow defines parity as `python diaphora.py db1 db2 -o out` with the shipped `diaphora_config.py`, which is exactly Section 10.1.
   - Non-default modes stay out of scope until someone asks for them.
   - Environment toggles (Section 10.1) cannot switch flags *off*, so oracle runs must not set `DIAPHORA_*` variables.
2. **Path A acceptability.** Is running Diaphora's SQL through the SQLite C API an acceptable permanent reference engine under the "native C++" rule? It is native, but it is SQL-driven. Or is it only a test oracle, with Path B mandatory for every heuristic?
3. **SQLite pinning.** Should the project vendor SQLite 3.51.1 (amalgamation) for all platforms so that row order is identical in CI? That changes the CI's vcpkg/apt/brew setup.
   - This is a policy decision (NOT DETERMINED FROM SOURCE).
   - Fact: the oracle's SQLite is the miniconda 3.51.1 DLL. A vendored amalgamation of the same version compiled with different options could still differ in planner behaviour only if compile-time options differ.
   - Fact: `ci.yml` never runs Python, so CI can only compare against stored oracle outputs.
4. **Oracle non-determinism (H4).** Should we emulate CPython set order, or classify pairs as oracle-unstable?
   - *Partly resolved:* `build_oracle.py` already runs every pair twice with random hash seeds.
   - The 3 finished real pairs were deterministic (H4). Classify a pair as oracle-unstable only when `determinism.json` says it is not deterministic.
   - Emulation remains the fallback.
5. **Diaphora crash inputs (H6).** Should native parity mode fail the same way (no output), or produce output with a warning?
6. **Output default.** Should `diff -o` default to the `.diaphora` format, with `--format legacy` for today's tables, or the other way round? Which choosers should `port` apply by default (`best` only? `best,partial`?), and should it refuse to create duplicate names (Section 9)?
7. **Real exports.** The win32u pair with PDB symbols will almost certainly take the patch-diff short-circuit, since more than 90% of `mangled_function` values match. That means it cannot exercise the 50 heuristics or the loop. Can the user provide exports that do: one side unsymbolised, or a copy of db2 with names rewritten to `sub_<hex>`? Or should the fixtures carry that load until then?
   - **RESOLVED (OBSERVED):** such exports already exist in `<corpus>/oracle/exports` (`docs/parity/09-oracle.md`).
   - `userenv-9168-pdb_vs_9278-nopdb` and `sechost-9168-pdb_vs_9444-nopdb` are labelled-to-unlabelled pairs. Their logs show the Best and Partial categories running, so no dirty short-circuit fires.
   - `ls-old_vs_ls` runs the full pipeline, including callee diffing, related constants, related CU and local affinity (see its `diaphora.log`).
   - `userenv-9168-pdb_vs_9278-pdb` confirms the patch-diff prediction: 643 of 643 names match, 100%.
8. **README scope statement.** `README.md:41` says bit-for-bit reproduction of scoring is out of scope, and the pipeline section describes Hopcroft–Karp/LSH assignment (`README.md:45-73`). Both contradict the new goal. The orchestrator should decide whether to rewrite those sections.
   - Verified: line 41 reads "Out of scope: reproducing Diaphora's Python plugin surface, and bit-for-bit reproducing its scoring weights."
   - Verified: `## Matching pipeline` spans lines 45–73, with Stage 7 Hopcroft–Karp at lines 70–71.
9. **CU lookup ambiguity (Section 10.11.3) and `find_remaining_functions` UNION order (Section 10.8).** Both rest on SQLite behaviour that was OBSERVED, not specified. Confirm them with `dump_rows.py` on real exports before relying on Path B for these stages.
   - **RESOLVED for the current corpus (OBSERVED with Python `sqlite3`, SQLite 3.51.1, on copies of the real exports):**
     - The UNION output is sorted by `(db_name, name, address)` on both `userenv-9168-pdb`+`9278-pdb` and `ls-old`+`ls`.
     - No function belongs to more than one CU in any of the 7 exports, so the CU `fetchone` is unambiguous.
     - The plans are recorded in Sections 10.8, 10.11.3 and H2.
   - Both behaviours are still planner-dependent. Path A reproduces them, and any Path B replacement needs a row-sequence test.

---

## Verification log

An adversarial verification pass was run on 2026-09-23 against the source.
- Native source: `dsig-parity` at `34ed418`.
- Diaphora: `diaphora-ref` at `3.4.2-4-g621ec26`, read only.
- Python: `miniconda3/python.exe` 3.13.12 with `sqlite3` 3.51.1, stdlib difflib (no `cdifflib`).
- Real exports: the oracle corpus `<corpus>/oracle`, **copied** to the session scratchpad before querying.

Every native file:line reference in Sections 1–9 was opened and checked. So was every `D:`/`H:`/`C:`/`S:`/`difflib.py`/`threads.py`/`diaphora_ida.py`/`patch_diff_vulns.py` reference in Sections 10–13, all 50 registry rows (enumerated from `diaphora_heuristics.HEURISTICS`), the build, and all five test executables.

**Corrections made in place:**

1. §1.1: "The build log contained no `warning` lines at all" was wrong. There are no *compiler* warnings, but a fresh configure prints a CMake Deprecation Warning from the vendored Zydis. Also, `BUILD_CLEAN` does not mean zero warnings.
2. §1.2: "Every test file re-declares the same harness" was wrong. There are two harness variants (`CHECK`/`CHECK_EQ` versus `CHECK_NUM_EQ`/`CHECK_TEXT_EQ` + `SuitesSkipped`).
   - The quoted harness is reformatted onto fewer lines, not verbatim.
   - "The corpus-gated suites ... use `DSIG_CORPUS_ROOT`" was wrong: only `peimage_tests` does, and `cfg_tests` hard-codes `<corpus>\...` (`tests/cfg_tests.cpp:68-69`).
   - Added the ctest names.
3. §1.3 experiment 1: `Equal assembly` is the **second** UNION branch of #10 (`H:287`), not the first (`H:277` is `Equal pseudo-code`). Added the reverse-order observation from a real oracle log.
4. §1.3 experiment 5: re-verified with 200,000 doubles (0 mismatches). Added experiment 6, the real-export row dumps.
5. §2: the map omitted `tools/oracle/` (untracked, the real parity reference), `docs/parity/`, `README.md`, `HANDOFF.md`, `JOURNAL.md` and `AGENTS.md`. Added them, plus the line counts that were missing.
6. §3: `port` also treats two NULL processors as equal (`ColumnString` maps NULL to `""`), unlike Diaphora's SQL `=`.
7. §4.3: noted that `rva` is also `text unique` (`S:98`).
8. §5.1: added the read-only open (`:113`), the `program` read gating (`:274-280`) and the `Present` semantics.
9. §5.2: `bytes_hash` consumers "#0-#3" was wrong. #2 joins on `function_hash` (`H:137`), so it is #0, #1 and #3.
10. §5.3 step 1: "exactly one row per side" was wrong. Diaphora requires exactly 2 `program` rows **in total** (`D:1299`), so 2+0 also passes.
11. §5.3 step 3:
    - Python `float()` strips **Unicode** whitespace (not only ASCII), accepts `+` and Unicode digits, and overflows to `inf`. `from_chars` needs pre-normalisation.
    - **Resolved** the "NOT DETERMINED FROM SOURCE" SQLite rounding question: SQLite's `cast(text as real)` is not correctly rounded (2 of 4,754 real `md_index` values and 105 of 200,000 random 28-digit strings differ from Python by 1 ULP).
    - So `MdSqlReal` must come from SQLite, never from `from_chars`.
12. §6.2(3): "computes `check_ratio` for **every** row" was overstated. Only rows that survive the `nullsub_`/`has_best_match` filters get a ratio.
13. §8.2: added the writer semantics that were missing:
    - `insert or ignore` plus the unique `(address, address2)` index, which can drop duplicate address pairs and leave `line` gaps;
    - the plain `insert` for `unmatched`;
    - the `None` unmatched choosers (`D:438-439,2333,2346,2420`).
14. §10.1: `ignore_sub_names` has no env override (`D:468`). `threads_apply` uses `config.SQL_TIMEOUT_LIMIT` (`D:1548`) while rows use `self.timeout` (`D:1894`).
15. §10.3: the `threads.py` range is `36-64`, not `36-60`, and the excerpt has elisions.
16. §10.4: "With duplicate names the early exit never fires" was wrong in general. `matched_primary` mixes `name` and `mangled_function` keys, so the test can also fire early.
17. §10.5.3: the `has_better_match` description was incomplete or misleading.
    - The early branch applies only when neither name is `sub_` **and** `name1` is already mapped. It tests `partner == name1`.
    - Every other case, including non-`sub_` pairs with an unmapped `name1`, falls through to the strict-greater ratio checks on both sides.
18. §10.5.4:
    - Added that `all_matches` is *replaced* by the sorted, filtered lists (`D:1605`).
    - Added that the last item wins the rebuilt state.
    - Listed all 9 `cleanup_matches` call sites.
    - The heading now says "condensed".
19. §10.6.2: the two md parsers *do* differ on real data, so the cache's first-writer-wins rule is observable. Added that parallel ratio prefetch must defer exceptions (`D:1672,2763-2780,2813-2814`). The heading now says "condensed".
20. §10.7: added the OBSERVED INTERSECT plan, 0 rows on the real pairs, and the `int(row["nodes"])` NULL abort (`D:1437`).
21. §10.8:
    - "That hook does not change results" was incomplete. It never changes a returned result, but it can **raise**, for example an `IndexError` at `scripts/patch_diff_vulns.py:162`, inside main-thread stages in patch-diff mode.
    - Noted the second import of `diaphora` (`:13`).
    - The UNION order is now OBSERVED on real exports.
    - `get_unmatched_functions` also runs in stripped mode.
22. §10.10: added the NULL `df.names` abort (`D:2120`). Added that the SQL has no `DISTINCT`, `%POSTFIX%` or `ORDER BY`, and that `has_better_match` runs on the names ratio before `check_match`.
23. §10.11.1:
    - Under `re.IGNORECASE`, `CPP_NAMES_RE`'s classes also match U+0130, U+0131, U+017F and U+212A, so the scanner must work on code points.
    - "size == 2, so the name must be unique on each side" was incomplete: two rows from one side and none from the other also give 2, and then both rows come from the same database.
    - Relabelled the `find_one_match_diffing` excerpt as condensed.
24. §10.11.2: `abs()==0` also keeps `'0.0'` and hex text. The bound parameter is `str(constant)` (`D:3390`).
25. §10.11.3:
    - The CU lookup plan is now OBSERVED, and no real export has a function in more than one CU.
    - There is no `dones` set.
    - `float(start_ea)` raises on a NULL bound (`D:3453-3456`).
26. §10.11.4: added the leading `cleanup_matches` (`D:3340`), the fact that `add_match`'s `has_better_match` still applies for `r < 1.0`, the NULL `pseudocode_lines` `TypeError` (`D:3276`), and the observed uniform address lengths.
27. §10.12: the multimatch excerpt shows `setdefault` for the source's `try/except KeyError`. It is relabelled as condensed.
28. §10.13: confirmed the label swap on a real `.diaphora`. Added that a function matched only under its `mangled_function` key is still listed as unmatched.
29. §10.14: added the SQL features a native generator must reproduce:
    - integer division in #39/#40;
    - bare `GROUP BY` columns;
    - `repr()` quoting of descriptions.
30. §10.15: added 7 abort conditions that were missing:
    - `total_functions1 == 0` → `ZeroDivisionError` at `D:2562`;
    - NULL CU bounds;
    - NULL `df.names`;
    - a main-thread `SystemExit` timeout, which exits the process without output;
    - a missing side table on the diff side;
    - the hook raising;
    - NULL `nodes` in `find_equal_matches`, noted in §10.7.
31. §11.2:
    - `sqlite3.dll` is resolved at run time via the loader search order (check `sqlite3_libversion()`).
    - The exports are WAL-mode.
    - Diaphora's main connection is read-write and creates missing main tables (`D:615-632`).
32. §12: the registry comment implied Diaphora's flags are bit-encoded. They are list values `0..3` tested by membership (`H:44-48`, `D:1498-1508`).
33. §13: real exports now exist, which supersedes HANDOFF Blocker 1. `make_fixture.py` must also create `S:INDICES`, run `analyze` and use WAL, or the planner order differs from real exports.
34. Hard parts H2, H4, H5 and H7: added real-export plan, determinism, timeout and md-parse observations.
35. Summary:
    - The patch-diff trigger is a **pair** count over the main function count, not "main-side functions with a partner".
    - Added the unmatched listing and the hook caveat.
    - "Links the same DLL" now points to the run-time resolution caveat.
36. Headings for §10.2 and §10.6.2 were labelled "verbatim" but contained elisions. They are now labelled "condensed".
37. Evidence legend: `diaphora-ref` is 4 commits past tag 3.4.2. Checked with `git diff 3.4.2 HEAD` that no cited line moved.

**Open questions resolved from source or by observation:** 7 (real exports that exercise the full pipeline exist) and 9 (UNION order and CU uniqueness observed on the real exports). Questions 1 and 4 are partly resolved. Questions 2, 3, 5, 6 and 8 are policy decisions: NOT DETERMINED FROM SOURCE, with the facts now attached.

**Checked and found correct (no change):**
- §1.1: the script transcription and all five check counts (re-run: 316/67/302/825/152,784).
- §2: the line counts.
- §4.1: the `Types.h` excerpts.
- §§6.1 and 7: the `Heuristics.cpp` and `MatchStore.cpp` line references.
- §8.1: the `main.cpp` schema.
- §9: the `Provenance.cpp` flow.
- §10.1: the config table.
- §10.2: the control flow, including `find_experimental_matches` inside `if self.unreliable:`.
- §10.5.1: the routing table, the dead `unreliable` branch and the row cap.
- §10.5.2: `check_match`.
- §10.6.1: `quick_ratio` and the difflib lines.
- §10.6.3: `deep_ratio`.
- §10.9: `find_same_name`.
- §10.12: `itemize_for_chooser`'s positional mapping and the `KeyError` analysis.
- §10.14: all 50 registry rows (name, category, type, min, flags), the 16 no-`ORDER BY` Ids, the 32 `source_file` Ids (22 default-run), and the default-run totals.
