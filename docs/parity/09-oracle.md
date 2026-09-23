# 09 — The parity oracle

Parity with Diaphora is measured, not assumed. The **oracle** is a set of real
Diaphora exports of real binaries, plus the results that unmodified Diaphora
produces when it diffs them. Our native `diff` must reproduce those results on
the same two exports: the same pairs, the same category (best, partial,
unreliable, multimatch), the same heuristic description and the same ratio.

The oracle binaries, IDA databases, exports and results are **never
committed**. They live in a corpus directory outside the repository. The
scripts that rebuild them are in `tools/oracle/`; see `tools/oracle/README.md`
for the commands.

Line references below are to Diaphora tag 3.4.2 + 4 commits (`621ec26`).

## Pairs

Reference is the older build (Diaphora's `db1`, the "main" database). Target is
the newer build (`db2`, the "diff" database).

| Pair | Reference | Target | What it exercises |
|---|---|---|---|
| `ls-old_vs_ls` | `ls-old` | `ls` | Diaphora's own tester sample (ELF x86-64) |
| `ls_vs_ls-old` | `ls` | `ls-old` | Same sample, the direction `tester/samples/ls.cfg` uses |
| `userenv-9168-pdb_vs_9278-nopdb` | userenv.dll 10.0.26100.9168, **with** PDB | 10.0.26100.9278, **without** PDB | The real use case: label one build, port to an unlabelled one |
| `userenv-9168-pdb_vs_9278-pdb` | 9168, with PDB | 9278, with PDB | Symbols on both sides, so Diaphora's same-name path and patch-diff mode |
| `sechost-9168-pdb_vs_9444-nopdb` | sechost.dll 10.0.26100.9168, with PDB | 10.0.26100.9444, without PDB | A larger labelled-to-unlabelled port (about 1,400 functions) |

The Windows builds are the amd64 files in `C:\Windows\WinSxS`, picked by
`FileVersionRaw` and copied out before analysis. Their PDBs come from the
Microsoft symbol server by RSDS GUID (`tools/prepare_corpus.py`).

## How an export is made

- **IDA 9.4 idalib**, with a fresh auto-analysis of a copy of the binary, and
  Hex-Rays for the decompiler and microcode.
- **Diaphora's own exporter**, `diaphora_ida._diff_or_export(use_ui=False,
  file_out=...)`. Only the output path is passed, so every option comes from
  `diaphora_config.py`. The resolved values are recorded per export:
  decompiler on, microcode on, `exclude_library_thunk=True`,
  `function_summaries_only=False`, `ida_subs=True`.
- **`sub_*` functions are exported.** The config name is misleading.
  `EXPORTING_ONLY_NON_IDA_SUBS = True` (`diaphora_config.py:56`) becomes
  `ida_subs=True` (`diaphora_ida.py`, `BinDiffOptions`), and the skip is
  `if not self.ida_subs:` (`diaphora_ida.py:3112`). The GUI checkbox is the
  inverse: `self.rNonIdaSubs.checked = not opts.ida_subs`
  (`diaphora_ida.py:776`). The previous `idb_export.py` passed
  `ida_subs=False` and silently dropped every unnamed function.
- **Without PDB**: IDA gets `-Opdb:off`, and `_NT_SYMBOL_PATH` is an empty
  local directory, so no symbol-server fallback is possible. IDA's log then
  has no `PDB:` lines at all.
- **With PDB**: the PDB sits next to the binary, and `_NT_SYMBOL_PATH` is that
  directory only. IDA logs `PDB: total N symbols loaded`.
- `pdb_proof.py` classifies every exported name as `sub_*`, a PE export (including
  IDA's `<MODULE>_<ordinal>` names), or other. A no-PDB export must have almost
  no "other" names.
- `IDAUSR` points at an empty directory, so user plugins stay out.

### Validation of the export pipeline

1. The `validate` stage re-exports `ls` and `ls-old` with Diaphora's own
   tester command line (`idat -A -B -S diaphora.py`, `DIAPHORA_AUTO=1`,
   `tester/tester.py` `launch_export`). Every table is **identical** to the
   idalib export. The only column ignored is `functions.export_time`.
2. Re-exporting the same binary gives an identical database. This was checked
   for `userenv-9168-pdb` and `userenv-9278-nopdb`.
3. `tester/samples/*.cfg` hold expected counts. They were recorded on
   2023-06-21 (commit `3e812ff`, "Added the testing suite") and never updated.
   Function, instruction, constant, call-graph and compilation-unit counts match
   them exactly for `ls-old`. Basic-block, microcode and program-data counts
   differ by 1 to 35 (per-key table in `ORACLE.md`). The .cfg does not record
   which IDA produced it (the tester README's example path is `ida83`). Both IDA
   (9.4 here) and Diaphora's exporter have changed since, and the oracle does
   not separate the two causes. The expected
   *diff* numbers (best 132, partial 101/109, multimatch 3) do **not** match
   current Diaphora. Current Diaphora gives best 139, partial 113, and
   multimatch 34 (for `ls` vs `ls-old`) or 26 (for `ls-old` vs `ls`). Running
   the 2023 engine (`3e812ff`, Python 3.11) on **our** exports gives best 133,
   partial 95/104, multimatch 3, which is close to the recorded values. So the
   pipeline is sound, and the tester's diff expectations describe an older
   engine.

## How a reference diff is made

```
cd <diaphora checkout>
python diaphora.py <ref.sqlite> <target.sqlite> -o <pair>.diaphora
```

Every `DIAPHORA_*` variable is removed from the environment. Standalone mode
differs from running inside IDA in ways that matter for parity:

- **Single-threaded.** `self.cpu_count = 1` when not in IDA
  (`diaphora.py:489-491`).
- **Slow heuristics stay on at any size.** `slow_heuristics` is read straight
  from `DIFFING_ENABLE_SLOW_HEURISTICS` (`diaphora.py:409-411`). The cut-off at
  `MIN_FUNCTIONS_TO_DISABLE_SLOW = 4001` exists only in the IDA UI path
  (`diaphora_ida.py:3798-3800`).
- **Names are used.** `bd.ignore_all_names = False` (`diaphora.py:3760`), so
  `find_same_name("partial")` runs (`diaphora.py:3623-3624`).
- **Heuristics run in reverse list order.** `threads_apply` takes work with
  `item = targets.pop()` (`jkutils/threads.py:40`), so the last heuristic in
  `HEURISTICS` runs first. The log prints the "Finding with heuristic" lines
  in list order, but the "done" lines come out in reverse.
- **Patch-diff mode.** When more than 90% of the main functions share a
  `mangled_function` with the diff database, Diaphora loads
  `scripts/patch_diff_vulns.py` as hooks (`diaphora.py:2610-2619`), and it
  skips the normal heuristic passes. `userenv-9168-pdb_vs_9278-pdb` takes this
  path (100% same name).
- **Wall-clock timeout.** A SQL heuristic that reads rows for more than
  `SQL_TIMEOUT_LIMIT` (300 s) raises `SystemExit` (`diaphora.py:1894-1896`).
  In the main thread (for example "Related compilation unit"), that would end
  the process without saving. No finished oracle run logged a timeout.

Each pair is diffed twice and the two `results` tables are compared row by row
(`determinism.json`). The export databases are hashed before and after
diffing. Diaphora opens `db1` read/write in WAL mode, so it is worth checking
that it did not change the exports.

## Results database (`.diaphora`) schema

`save_results` (`diaphora.py:2374-2426`) writes three tables. The columns have
no declared type, and every value is stored as **TEXT**.

```sql
create table config (main_db text, diff_db text, version text, date text)
create table results (type, line, address, name, address2, name2,
                      ratio, nodes1, nodes2, description)
create unique index uq_results on results(address, address2)
create table unmatched (type, line, address, name)
```

| Column | Content | Source |
|---|---|---|
| `results.type` | `best`, `partial`, `unreliable` or `multimatch` | category key in `save_results` |
| `results.line` | `"%05lu"`, the item's index **within its chooser** (restarts at `00000` per type) | `CChooser.add_item`, `diaphora.py:275-296` |
| `results.address` | Main (reference) function address, `"%08x"` (lowercase, no `0x`, absolute VA such as `180001010`) | same |
| `results.name` / `name2` | Diaphora's function `name` column, which is the **demangled** name when IDA has one (for example `long StringCchCopyW(unsigned short *,...)`) | export |
| `results.address2` | Diff (target) function address, same format | same |
| `results.ratio` | `"%.7f"` (`DECIMAL_VALUES = "7f"`), for example `1.0000000` or `0.9978707` | `diaphora.py:282` |
| `results.nodes1` / `nodes2` | Basic-block counts, `"%d"` | same |
| `results.description` | Name of the heuristic that produced the match | match item `[4]` |
| `unmatched.type` | `primary` / `secondary`, **swapped** (see below) | `diaphora.py:2341,2354,2414-2415` |
| `config` | One row: main db path, diff db path, `VERSION_VALUE` (`3.4`), `time.asctime()` | `diaphora.py:2390-2392` |

Rules that a parity comparison must reproduce or allow for:

- **Row order.** Inside each category, rows are sorted by `float(ratio)`
  descending with a **stable** sort (`diaphora.py:2926`). Ties keep insertion
  order, and insertion order follows heuristic execution order.
- **Duplicates are dropped silently.** It is `insert or ignore` into a unique
  `(address, address2)` index (`diaphora.py:2399,2406`), and categories are
  written in the order best, partial, unreliable, multimatch. A pair already
  written under an earlier category disappears from a later one. The log's
  `Final results:` line counts chooser items *before* this dedup. In every
  pair checked so far, the two counts were equal.
- **`unmatched` is swapped.** `find_unmatched` stores the functions of the
  **main** database in `self.unmatched_second` and those of the **diff**
  database in `self.unmatched_primary` (`diaphora.py:2334-2354`).
  `save_results` then writes them as `primary` and `secondary` respectively.
  So `unmatched.type = 'primary'` lists **target** functions, and
  `'secondary'` lists **reference** functions. The oracle data confirms it:
  every `primary` address of `userenv-9168-pdb_vs_9278-pdb` is a 9278
  function.
- **"Unmatched" means by name.** It is computed by name, not address
  (`name not in self.matched_primary`), so a name shared by several functions
  counts as matched once for all of them.
- **Reading trap in `itemize_for_chooser`.** Its local variables are named
  `ratio, nodes1, nodes2, desc` for items `[4]..[7]`, and it calls
  `CChooser.Item(ea1, vfname1, ea2, vfname2, ratio, nodes1, nodes2, desc)`
  (`diaphora.py:2718-2730`). The match layout is really
  `[ea1, name1, ea2, name2, desc, ratio, nodes1, nodes2]`
  (`diaphora.py:1568`), which lines up with the `Item(ea, name, ea2, name2,
  desc, ratio, nodes1, nodes2)` signature. The names are wrong, but the
  positions are right.

## Run time

The ls pairs take about 13 s, and the userenv pdb-to-pdb pair takes 2 s
(patch-diff mode). The two labelled-to-unlabelled pairs take **hours**.
Almost all of that time is "Related compilation unit"
(`diaphora.py:3395-3460`):

- Diaphora's compilation-unit detection puts most functions into one giant
  unit: 580 of 643 in userenv, 867 of 1442 in sechost.
- For every best/partial match with ratio >= 0.8 (`RELATED_MATCHES_MIN_RATIO`),
  the heuristic re-queries the cross product of the two units' address
  ranges. That is about 300k rows per match for userenv and about 700k for
  sechost.
- The outer `while 1` loop repeats all of this for as long as new matches
  appear.
- userenv iteration 0 took 2 h 23 min (521 such queries). sechost runs at
  about 1.3 queries per minute over about 1,300 matches.

The oracle keeps these runs going detached. `ORACLE-results.md` in the corpus
directory is regenerated when they finish. A native implementation that
reproduces this heuristic should expect to spend most of its time in it too.

## Determinism

See `ORACLE.md` (narrative) and `ORACLE-results.md` (generated tables) in the
corpus directory for the current per-pair verdicts. For
the pairs finished so far, both runs gave **identical** `results` and
`unmatched` tables, even in stored row order. The standalone engine is
single-threaded, and Python's randomised string hashing did not change any
result. The only wall-clock-dependent code path found in the diff engine is the
300 s heuristic timeout. No run logged it.

## Caveats

- Exports depend on the IDA version (9.4 build 260610 here; 9.2 moves ls by
  ±1 best/partial). They also depend on the analysing host: IDA's PE loader
  reads `C:\Windows\System32\<import>.dll` to name imports by ordinal. The
  oracle is only valid for the exact `.sqlite` files it records by SHA-256.
- Export `.sqlite` files are in WAL mode (`SQLITE_JOURNAL_MODE = "WAL"`). An
  empty `-wal`/`-shm` pair may linger next to them after a diff. The main file
  hash does not change.
- Diaphora's standalone diff falls back to stdlib `difflib` when `cdifflib`
  is missing, as it is here. Ratios come from `SequenceMatcher`, and the two
  should agree, but this oracle only vouches for the stdlib path.
