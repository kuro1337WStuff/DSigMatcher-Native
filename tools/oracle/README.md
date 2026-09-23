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
launching shell may exit.

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
