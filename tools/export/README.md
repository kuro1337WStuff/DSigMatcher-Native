# Export bridge: `dsig_export.py`

`dsig_export.py` turns a binary, or an IDA database, into a Diaphora export (`.sqlite`). It runs IDA
9.x **idalib** and Diaphora's **own, unmodified** exporter
(`diaphora_ida._diff_or_export(use_ui=False, file_out=...)`). The exporter's feature definitions are
the parity contract of the native diff (`docs/parity/00-plan.md` §7.1 D7), so nothing here
re-implements them.

The native CLI launches it:

```
dsigmatcher extract <in.i64|in.idb> -o <out.sqlite> [tool options]
dsigmatcher ingest  <in.exe|dll|elf> -o <out.sqlite> [--pdb <file> | --no-pdb] [tool options]

tool options: --python <exe> --ida-dir <dir> --diaphora-dir <dir> --export-script <dsig_export.py>
              --temp-dir <dir> --keep-temp --timeout <seconds>
```

It can also be run directly:

```
python dsig_export.py idb    <in.i64|in.idb> -o <out.sqlite> --diaphora-dir <diaphora> [--ida-dir <IDA>]
python dsig_export.py binary <binary> -o <out.sqlite> --diaphora-dir <diaphora> [--pdb <file> | --no-pdb]
```

## Requirements

- IDA Pro 9.0 or newer with idalib, and the Hex-Rays decompiler for the binary's architecture.
- A Python 3.8+ that can load idalib. If the `idapro` wheel is not installed in that Python, the
  copy in `<IDA>/idalib/python` is used.
- A Diaphora checkout. Diaphora is AGPL, so it is **never bundled or modified**: it is imported
  read-only (no `__pycache__` is written) from the directory you name. The parity oracle used
  3.4.2 + 4 commits (`621ec26`); the sidecar records `git describe` and `VERSION_VALUE`.
- Diaphora's own Python dependencies (for example `pygments`) in the same Python.

## Discovery

| What | Order |
|---|---|
| Python (C++ CLI) | `--python`, `DSIG_PYTHON`, then `python.exe`/`python3.exe` (Windows) or `python3`/`python` on `PATH` |
| `dsig_export.py` (C++ CLI) | `--export-script`, `DSIG_EXPORT_SCRIPT`, then next to the executable, `<prefix>/share/dsigmatcher/tools/export/`, or `tools/export/` in the executable's directory or any of its parents (a build directory inside the source tree) |
| IDA | `--ida-dir`, `DSIG_IDADIR`, `IDADIR`, then idapro's `ida-config.json` (`Paths.ida-install-dir`) in the user's IDA directory |
| Diaphora | `--diaphora-dir`, `DSIG_DIAPHORA_DIR`; required |

The C++ side checks every tool before it starts anything and names **all** missing ones in one
message, with exit code 4.

## Modes

**`idb` (`extract`)**: an existing `.i64`/`.idb` keeps every name and type the user gave it.

- The database is hashed, **copied** into a private work directory, and only the copy is opened.
  idalib unpacks and repacks a database in place, so the original is never handed to IDA.
- It is opened **without auto-analysis** and closed **without saving**. The auto-analysis queue is
  not run; if the database was saved with pending analysis, a warning is recorded and it is exported
  as saved.
- IDA gets `-Opdb:off` and an empty `_NT_SYMBOL_PATH`, so no PDB can be loaded on top of the user's
  names (the oracle's `win32u-9168-useri64` export used the same settings).
- The original's sha256 (and mtime) is checked before and after, by the script **and** by the C++
  launcher. A change fails the run with exit 17 / "THE INPUT CHANGED".
- Unpacked `.id0/.id1/.id2/.nam/.til` files next to the input mean the database may be open in IDA;
  that is reported, and the export reflects the last **saved** state.

**`binary` (`ingest`)**: a raw PE, ELF or anything IDA loads is analysed from scratch in the work
directory.

- **Default: no PDB and fully offline.** For a PE, IDA gets `-Opdb:off`; `_NT_SYMBOL_PATH` is an
  empty local directory, so no symbol server can be reached. Only the binary is copied into the work
  directory, so a PDB lying next to the original cannot be picked up either. The run fails if IDA
  prints any `PDB:` line or the fresh database has a `$ pdb` netnode.
- **`--pdb <file>` applies exactly that PDB.** Its GUID and DBI age must equal the binary's RSDS
  record (read from the MSF 7.00 container; exit 14 otherwise). It is copied next to the work copy
  under the name the RSDS record asks for, and `_NT_SYMBOL_PATH` is that directory only (no `SRV*`
  entry, so still offline). The run fails unless IDA logs `PDB: total N symbols loaded` and creates
  the `$ pdb` netnode. This is the layout the oracle's `-pdb` exports used.
- A non-PE binary gets no `-Opdb:off` switch (as the oracle's ELF samples), and `--pdb` is refused.

## What is exported

Only the output path is passed to Diaphora, so every option is its `diaphora_config.py` default, as
in the oracle. The resolved values go into the sidecar. The ones that matter most:

- `sub_*` functions **are** exported: `ida_subs` defaults to `EXPORTING_ONLY_NON_IDA_SUBS = True`
  (`diaphora_ida.py:3809`, `diaphora_config.py:56`), and the skip is `if not self.ida_subs`
  (`diaphora_ida.py:3112`). The run fails if `ida_subs` is ever false.
- Library and thunk functions are **skipped** (`EXPORTING_EXCLUDE_LIBRARY_THUNK = True`). IDA can
  therefore show more functions than the export has: the user's win32u database has 1516 in IDA and
  1510 in the export (1 library function and 5 thunks). The sidecar records both counts.
- Pseudo-code and microcode come from Hex-Rays. Without Hex-Rays the run is refused (exit 13),
  because such an export is not comparable with one that has them; `--allow-no-decompiler` (or
  `DSIG_EXPORT_ALLOW_NO_DECOMPILER=1`) exports anyway and records it.
- Diaphora's own size defaults still apply and are reported as warnings: microcode export is off
  above `MIN_FUNCTIONS_TO_CONSIDER_MEDIUM` (8001) functions, and only function summaries are exported
  above `MIN_FUNCTIONS_TO_CONSIDER_HUGE` (100000).
- An exception inside Diaphora's `do_export()` is caught (Diaphora's `export()` only logs it and still
  writes a partial database), as are a left-over `-crash` marker, an export with no functions and an
  export with no pseudo-code although Hex-Rays is available.

## Isolation and what it does not cover

- `IDAUSR` is a private, empty directory, so the user's own plugins, scripts, `idapythonrc.py` and
  settings do not load. Only licence files (`*.hexlic`) are copied into it from the user's IDA
  directory, since IDA may keep its licence there.
- **Plugins inside the IDA installation's own `plugins/` directory still load.** IDA always loads
  that directory, whatever `IDAUSR` says. If a third-party plugin was copied there, it runs during the
  export. The sidecar lists the directory's contents (`ida.install_plugins`) and the `...: Plugin
  loaded` lines IDA printed (`ida.plugins_loaded_log`) so such a plugin is visible.
- On Windows IDA also keeps some settings in the registry (`HKCU\Software\Hex-Rays`), which an
  isolated `IDAUSR` does not cover. The oracle exports were made the same way, and re-exports matched
  them table for table, but settings changed there are not controlled.
- Every `DIAPHORA_*` variable is removed from the environment (Diaphora reads them through
  `get_value_for`, `diaphora.py:400-421`), as are `IDA_IS_INTERACTIVE`, `_NT_ALT_SYMBOL_PATH` and
  `_NT_SYMCACHE_PATH`.
- Results still depend on the IDA version and on the analysing host: IDA's PE loader reads
  `System32\<import>.dll` to name ordinal imports (see `docs/parity/09-oracle.md`, "Caveats"). An
  export is only comparable with the oracle when the IDA build, the Diaphora revision and the host
  match; the sidecar records the first two.
- For ELF and Mach-O inputs, IDA uses the debug information inside the binary as usual. Separate
  debug files next to the original are not visible, because only the binary is copied; lookups IDA
  makes elsewhere (for example system debug directories) are not controlled.

## Outputs

- `<out.sqlite>`: written to the work directory first, checked, then copied beside the destination
  and moved into place, so the destination changes only when the export succeeded. An old output is
  replaced, together with any stale `-wal`, `-shm` or `-crash` file next to it.
- `<out stem>.export.json` (schema `dsig-export/1`; `-o out.sqlite` gives `out.export.json`):
  `input` (path, kind, size, sha256 before and after, `unchanged`), `idb` (copy hashes, `saved:
  false`), `pdb` (mode, file and its identity, the binary's RSDS record, the name it was placed under,
  the `PDB:` log lines, symbols loaded, netnode, `applied`), `options`, `ida` (directory and how it was
  found, idalib, kernel and Hex-Rays versions, IDA's function counts, install plugins), `isolation`,
  `diaphora` (directory, `VERSION_VALUE`, `git describe`, dirty flag, resolved options and config),
  `output` (sha256), `counts` (exported, named, `sub_*`, with pseudo-code, with microcode, the
  tester's per-table counts), `timing` and `warnings`. The C++ launcher re-checks the input and
  output hashes it records.
- The work directory (`--temp-dir`, else the system temp directory) holds the copies, the private
  `IDAUSR` and the worker log. It is removed unless `--keep-temp`.

## Exit codes

| `dsig_export.py` | Meaning | `dsigmatcher` |
|---|---|---|
| 0 | ok | 0 |
| 2 | usage (bad arguments, wrong input kind for the mode, output name) | 2 |
| 10 | input or PDB file missing or unreadable | 6 |
| 11 | IDA not found, or idalib cannot be loaded (licence, wrong Python) | 4 |
| 12 | Diaphora not found, or it fails to import | 4 |
| 13 | Hex-Rays unavailable | 4 |
| 14 | the PDB does not belong to the binary, or `--pdb` on a non-PE | 2 |
| 15 | IDA cannot open the input | 4 |
| 16 | the export failed (Diaphora raised, crash marker, PDB not applied or applied unexpectedly, ...) | 6 |
| 17 | THE INPUT CHANGED during the export | 6 |
| 18 | timeout (`--timeout`) | 6 |
| 19 | the output, sidecar or work directory cannot be written | 6 |
| 20 | internal error | 6 |
| 130 | interrupted | 6 |

The launcher itself also returns 2 for its own argument checks, 4 when Python, the script, IDA or
Diaphora is missing (and for the Windows Store `python` placeholder, exit 9009), and 6 when the input
is missing, the process cannot be started, the backstop timeout (`--timeout` + 120 s) kills the
process tree, or the sidecar does not match the run. Its message always ends with the script's own
`dsig_export: error: ...` line when there is one.

## How the launcher runs the script

- `python -B -u dsig_export.py <mode> <input> -o <output> --sidecar <json> ...`, with
  `PYTHONIOENCODING=utf-8`, `PYTHONUTF8=1`, `PYTHONDONTWRITEBYTECODE=1` and `PYTHONUNBUFFERED=1`
  added to the inherited environment. Paths are absolute.
- Windows: `CreateProcessW` with a UTF-16 command line quoted by the C runtime's rules (the rules
  `CommandLineToArgvW` and Python use), only the output pipe and `NUL` inherited, and a
  kill-on-close job object so a timeout, or the launcher exiting, ends the script and its IDA worker
  together. Ctrl+C is left to the script, which stops IDA and removes its work directory.
- POSIX: `posix_spawn`; on timeout SIGTERM (the script cleans up), then SIGKILL after 30 s.
- The script's output (IDA's console, Diaphora's log) is streamed to stderr. On success `dsigmatcher`
  prints a summary to stdout: output, function counts, the unchanged input sha256, the PDB, the tool
  versions and the sidecar path.
- Arguments are UTF-8. On Windows the CLI's narrow `argv` is in the ANSI code page; text that is not
  valid UTF-8 is read in that code page, so characters outside it cannot reach the bridge from the
  command line (library callers pass UTF-8 and are not affected).

## Tests

- `ctest -R cli_export_bridge` (C++, `tests/cli/export_bridge_tests.cpp`) needs neither Python nor
  IDA: the test executable plays the child process (echo, sleep and a fake `dsig_export.py`), which
  covers argument quoting round trips, UTF-8 paths with spaces, output capture, timeouts, discovery,
  bogus-path errors, the exit-code map and the sidecar checks.
- With `DSIG_EXPORT_TESTS=1`, `DSIG_IDADIR`, `DSIG_DIAPHORA_DIR` (and `DSIG_PYTHON` or a `python` on
  `PATH`) and the corpus (`DSIG_CORPUS_ROOT`), the same suite also runs three real exports and
  requires each to equal the oracle export table for table: `ingest --pdb` of cryptbase 10.0.26100.8875
  (`cryptbase-8875-pdb`), `ingest --no-pdb` of win32u 10.0.26100.9444 (`win32u-9444-nopdb`), and
  `extract` of a copy of the user's win32u `.i64` (`win32u-9168-useri64`, 1510 functions).
- `python -B tools/export/selftest_dsig_export.py` checks the script's PE/PDB identity readers on
  synthetic files and its argument and tool checks, without IDA.
- To compare an export with an oracle export by hand, run `tools/oracle/compare_exports.py` on
  **copies**: it opens both files read-write, which removes the leftover `-wal`/`-shm` pair next to an
  oracle export.
