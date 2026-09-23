# Parity oracle tools

Scripts that build the **Diaphora parity oracle**: real Diaphora exports of real
binaries, plus the results unmodified Diaphora produces when it diffs them. The
native `diff` is measured against these results. How the oracle is built and
what the results database looks like is in `docs/parity/09-oracle.md`.

Nothing here writes into the repository. All output (binaries, `.i64`,
`.sqlite`, `.diaphora`, logs) goes under the `--root` you pass, which must be
outside the repo.

| Script | Runs under | Purpose |
|---|---|---|
| `build_oracle.py` | any Python 3 | Orchestrator. Stages `exports`, `validate`, `diffs`, `summary`, or `all`. |
| `diaphora_export.py` | Python that can `import idapro` (IDA 9.x idalib) | Analyse one binary and export it with Diaphora's own exporter (`diaphora_ida._diff_or_export(use_ui=False)`). Writes a JSON sidecar describing the run. |
| `compare_exports.py` | any Python 3 | Table-by-table comparison of two exports (ignores `functions.export_time`). |
| `pdb_proof.py` | Python with `pefile` | Classifies every exported function name (sub_* / PE export / other) to prove whether a PDB was applied. |

## Requirements

- IDA Pro 9.x with idalib and the Hex-Rays decompiler for the target
  architecture. The `idapro` package must be importable by `--python`.
- An unmodified Diaphora checkout (`--diaphora-dir`). The oracle was built from
  tag 3.4.2 plus 4 commits (`621ec26`).
- `pefile` (for `pdb_proof.py`, and `tools/prepare_corpus.py`).
- Windows binaries and PDBs laid out by `tools/prepare_corpus.py`
  (`<bin-dir>/<name>_<version>/<file>.dll` plus `<file>.pdb`).

## Rebuilding the oracle end to end

```bat
rem 1. Copy the Windows builds out of WinSxS and fetch their PDBs.
python tools\prepare_corpus.py <root>\bin ^
    C:\Windows\WinSxS\amd64_microsoft-windows-userenv_..._10.0.26100.9168_...\userenv.dll ^
    C:\Windows\WinSxS\amd64_microsoft-windows-userenv_..._10.0.26100.9278_...\userenv.dll ^
    C:\Windows\WinSxS\amd64_microsoft-windows-sechost_..._10.0.26100.9168_...\sechost.dll ^
    C:\Windows\WinSxS\amd64_microsoft-windows-sechost_..._10.0.26100.9444_...\sechost.dll

rem 2. Export, validate, diff twice per pair, write <root>\manifest.json.
python tools\oracle\build_oracle.py all --root <root> ^
    --diaphora-dir <diaphora checkout> --ida-dir "<IDA 9.x install>" --jobs 10
```

Stages can be re-run on their own (`exports`, `validate`, `diffs`, `summary`),
and `--only <id> ...` restricts a stage to some exports or pairs. `summary`
writes `<root>/manifest.json` and `<root>/ORACLE-results.md`, which holds
Markdown tables of every export, run, determinism verdict, tester .cfg
comparison, and per-heuristic row counts.

**Run time.** Exports take seconds to about 2 minutes each. The ls and
pdb-to-pdb diffs take seconds. The no-PDB userenv and sechost diffs take hours
to about a day, because Diaphora's "Related compilation unit" heuristic
dominates (see `docs/parity/09-oracle.md`). Launch those detached if the
launching shell may exit, and prefer a Windows scheduled task for them (see
"Detached jobs" below).

## What each stage guarantees

- **exports**: every binary is copied into `<root>/exports/<id>/` and analysed
  from scratch there (IDA writes the `.i64` next to its input). `IDAUSR` points
  at an empty directory so personal plugins and settings stay out.
  - *Without PDB*: `-Opdb:off` is passed to IDA, and `_NT_SYMBOL_PATH` points at
    an empty local directory (no `SRV*` entry, so no symbol-server download).
  - *With PDB*: the matching PDB is copied next to the binary and
    `_NT_SYMBOL_PATH` is that directory only.
  - Only the output path is passed to Diaphora. Every export option keeps its
    `diaphora_config.py` default, and the resolved values are recorded in
    `<id>.export.json`. In particular `ida_subs` stays `True`, so `sub_*`
    functions **are** exported. The exporter refuses to write an export without
    Hex-Rays, and it fails if Diaphora's `do_export()` raised, because
    Diaphora's `export()` swallows that exception.
- **validate**: re-exports the ELF samples with Diaphora's own tester command
  line (`idat -A -B -S diaphora.py`, `DIAPHORA_AUTO=1`) and requires the result
  to be identical, table by table, to the idalib export.
- **diffs**: runs `python diaphora.py <ref.sqlite> <target.sqlite> -o <out>`
  from the Diaphora checkout with every `DIAPHORA_*` variable removed from the
  environment. Each pair runs `--runs` times (default 2). The runs are compared
  row by row (`determinism.json`), and the export databases are hashed before
  and after the stage, to prove diffing did not modify them.

## Extending the oracle: new builds, pairs and ground truth

`oracle_extend.py` adds builds, exports and pairs to an existing oracle root
without touching what `build_oracle.py` built. Detached long diffs still run
from `build_oracle.py` and `diaphora_export.py`, so those two files stay
unchanged: the extension imports or invokes them.

| Script | Runs under | Purpose |
|---|---|---|
| `oracle_extend.py` | any Python 3 (`pefile`; `psutil` for process status) | Stages `prepare`, `exports`, `truth`, `diffs`, `status`, `summary`, `keeper`, `user-i64`, `all`. |
| `ground_truth.py` | any Python 3 | Address -> PDB-name table for a no-PDB export, taken from the with-PDB export of the same build. |
| `pdb_info.py` | any Python 3 | Reads a PDB's GUID and ages from the MSF 7.00 container and checks them against a PE's RSDS record. |
| `selftest_oracle_extend.py` | any Python 3 | Synthetic self-test of the three tools above; it prints a check count. |

What the extension adds (the ids are in `oracle_extend.py`):

- **Builds.**
  - win32u 10.0.26100.9168 and .9444, from `--win32u-dir`.
  - cryptbase 10.0.26100.1, .8875 and .9444, found in WinSxS by their
    version resource.
  - Each PDB is copied, or fetched by RSDS GUID. Its GUID and DBI age must
    match the binary.
- **Exports.**
  - `win32u-9168-useri64`: a **copy** of the user's hand-saved IDA database,
    opened without auto-analysis, with the PDB plugin off, and not saved.
  - `win32u-9444-{nopdb,pdb}` and `cryptbase-{1,8875,9444}-{nopdb,pdb}`.
  - `sechost-9444-pdb`, which gives ground truth for `sechost-9444-nopdb`.
- **Pairs.** `win32u-9168-useri64_vs_9444-nopdb`, `cryptbase-1-pdb_vs_8875-nopdb`
  and `cryptbase-8875-pdb_vs_9444-nopdb`, each with run1 and run2.
- **Ground truth.** `<root>/ground_truth/<nopdb id>.tsv` (plus a `.json`
  sidecar) for every `-nopdb` export.
  - Columns: `address` (decimal, as stored in the export), `address_hex`
    (`%08x`, as in `.diaphora`), `status` (`both`, `pdb_only` or
    `nopdb_only`), `name`, `mangled_function` and `nopdb_name`.
  - `pdb_only` and `nopdb_only` rows are function starts that the two
    analyses of one binary disagree on.

```bat
python -B tools\oracle\oracle_extend.py prepare --root <corpus>\oracle --win32u-dir <corpus>\win32u
python -B tools\oracle\oracle_extend.py exports --root <corpus>\oracle --diaphora-dir <diaphora checkout> ^
    --ida-dir "<IDA 9.x install>" --win32u-dir <corpus>\win32u --expect-user-i64-sha256 <sha256> --jobs 4
python -B tools\oracle\oracle_extend.py truth   --root <corpus>\oracle
python -B tools\oracle\oracle_extend.py diffs   --root <corpus>\oracle --diaphora-dir <diaphora checkout> ^
    --ida-dir "<IDA 9.x install>" --diff-python <python>
python -B tools\oracle\oracle_extend.py status  --root <corpus>\oracle
python -B tools\oracle\selftest_oracle_extend.py
```

Guarantees:

- **Base ids are refused.** A base export or pair id is refused, even with
  `--force`. Re-running a base pair's diffs would delete its run directory.
- **Existing extension ids need `--force`.** An existing extension export or
  pair is refused without `--force`, and with `--force` a pair that still has
  live processes is refused.
- **The user's database.**
  - It is hashed before and after the export. With
    `--expect-user-i64-sha256`, the export refuses to run on any other value.
  - Only a copy is opened, and the copy is not saved.
  - `user-i64` re-checks the hash at any time.
- **Detached jobs.** `diffs` starts a detached worker, and `keeper` starts a
  detached keeper. On Windows both are created through WMI
  (`Win32_Process.Create`), so they outlive the launching shell. They run from
  a snapshot of these scripts under `<root>/extension/tools/<stamp>/`, so a
  later edit or removal of the checkout cannot affect them.
  Caveat: WMI-created processes belong to the WMI provider host, and all of
  them die together when Windows recycles that host. This ended several oracle
  runs that had been going for hours. For runs of many hours, start the same
  command as a Windows scheduled task instead.
- **The keeper.** It re-runs `oracle_extend.py summary` whenever
  `manifest.json` lacks the extension or is older than a pair's results. A
  plain `build_oracle.py summary` (run by the base long jobs when they finish)
  writes the manifest without the extension.
- **`summary`** runs `build_oracle.py`'s own summary over base and extension
  specs. It then adds `manifest.json` `extension` (source builds, user-database
  hashes, per-export PDB proof and verdict, ground-truth counts, launch
  records) and an "Extension" section to `ORACLE-results.md`.
- **`status`** lists every pair, base and extension: finished (from
  `run.json`), running (from the process list) with its last `Current results`
  and heuristic lines, or dead. It also shows determinism, input integrity and
  the worker and keeper PIDs.
