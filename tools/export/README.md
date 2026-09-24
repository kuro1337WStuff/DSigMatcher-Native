# Export bridge: `dsig_export.py`

`dsig_export.py` turns a binary, or an IDA database, into a Diaphora export (`.sqlite`). It runs IDA
9.x **idalib** and Diaphora's **own, unmodified** exporter
(`diaphora_ida._diff_or_export(use_ui=False, file_out=...)`). The exporter's feature definitions are
the parity contract of the native diff, so nothing here re-implements them.

The native CLI launches it:

```
dsigmatcher extract <in.i64|in.idb> -o <out.sqlite> [tool options]
dsigmatcher ingest  <in.exe|dll|elf> -o <out.sqlite> [--pdb <file> | --no-pdb] [tool options]

tool options: --python <exe> --ida-dir <dir> --diaphora-dir <dir> --export-script <dsig_export.py>
              --temp-dir <dir> --keep-temp --timeout <seconds> --allow-no-decompiler
              --quiet --json
```

`dsigmatcher update` takes the same tool options for its ingest step (and passes `--quiet` and
`--json` through: its JSON object holds the ingest's outcome under `ingest.outcome`).

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
| Python (C++ CLI) | `--python`, `DSIG_PYTHON`, then `python.exe`/`python3.exe` (Windows) or `python3`/`python` on `PATH`. On Windows a bare name means `<name>.exe`. |
| `dsig_export.py` (C++ CLI) | `--export-script`, `DSIG_EXPORT_SCRIPT`, then `<exe dir>/dsig_export.py` (CMake copies it next to every built executable; ship it there in a zip), `<exe dir>/share/dsigmatcher/tools/export/`, or `<exe dir>/../share/dsigmatcher/tools/export/` (an install prefix). The executable's parent directories are **not** searched: a script planted higher up (for example `<drive>/tools/export/`) would otherwise run. The error lists every place that was searched. |
| IDA | `--ida-dir`, `DSIG_IDADIR`, `IDADIR`, then idapro's `ida-config.json` (`Paths.ida-install-dir`) in the user's IDA directory |
| Diaphora | `--diaphora-dir`, `DSIG_DIAPHORA_DIR`; required |

The C++ side checks every tool before it starts anything and names **all** missing ones in one
message, with exit code 4.

**`--python` must be a real interpreter executable.** On Windows a `.bat`, `.cmd` or `.btm` file, or a
file without an `MZ` header, is refused (exit 4). Such a file would be run by `cmd.exe`, which
re-parses the arguments: a sample named `a&command&b.dll` would run `command`. This rules out the
pyenv-win and conda shims, which are batch files. Point `--python` at the `python.exe` inside the
environment instead. The Store's `python.exe` app-execution alias is still accepted.

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
  because such an export is not comparable with one that has them. `--allow-no-decompiler` exports
  anyway and records it; `dsigmatcher extract`, `ingest` and `update` forward their own
  `--allow-no-decompiler` to the script. `DSIG_EXPORT_ALLOW_NO_DECOMPILER=1` in the environment does
  the same (the launcher passes the environment on).
- IDA must find at least one function. A file IDA loads but finds no code in (a text file, a data
  blob) is refused with exit 15 (`dsigmatcher` exit 4), "IDA found no functions".
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
- Every `PYTHON*` variable is removed too (`PYTHONPATH`, `PYTHONHOME`, `PYTHONSTARTUP`, ...), except
  the four the worker needs (`PYTHONDONTWRITEBYTECODE`, `PYTHONIOENCODING`, `PYTHONUTF8`,
  `PYTHONUNBUFFERED`). A module on the caller's `PYTHONPATH` therefore cannot shadow `idapro`,
  Diaphora or the script. The launcher starts the driver with `python -E`, so the driver ignores them
  as well. The sidecar lists the removed names (never their values) under
  `isolation.removed_environment`. If your `idapro` wheel is only reachable through `PYTHONPATH`,
  install it into the interpreter instead; the copy in `<IDA>/idalib/python` is also used as a
  fallback.
- No program is looked up in the current directory. `git` (for the Diaphora revision) is resolved from
  absolute `PATH` entries only and runs inside the Diaphora checkout. The launcher and the script set
  `NoDefaultCurrentDirectoryInExePath=1` for everything they start, and the launcher starts the script
  in the script's own directory rather than the caller's (often the sample's folder).
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
  `IDAUSR` and the worker log. It is removed unless `--keep-temp`. On Windows its path must be
  ASCII: IDA hands `IDAUSR` to IDAPython in the ANSI code page, IDAPython decodes it as UTF-8, and
  the worker then crashes (0xC0000005). A non-ASCII root (for example the temp directory of a user
  whose name is not ASCII) is therefore replaced by its 8.3 short form or, without one, by
  `%ProgramData%\dsigmatcher\tmp\<user SID>`, which the script restricts to that user, SYSTEM and
  Administrators. When neither is available the run is refused (exit 2) and asks for an ASCII
  `--temp-dir`.
- A run that is killed (the launcher terminated, a crash, a power cut) cannot remove its work
  directory, which may hold a copy of the user's database. Each work directory therefore has an
  `owner.json` naming the driver and worker processes (pid and start time). Every run first removes
  the `dsig-export-XXXXXXXX` directories in the same place whose processes are all gone. A directory
  kept with `--keep-temp` is marked as kept and left alone. A directory without an owner file (an older
  version) is removed only after 48 hours.

**Refused output names.** Nothing the run writes, replaces or moves aside may be the input or the
PDB. That covers the output, its `-wal`, `-shm`, `-journal` and `-crash` files, the sidecar, and the
pid-named staging files (`<out>.dsig-tmp-<pid>`, `<out>-wal.dsig-old-<pid>`,
`<sidecar>.tmp-<pid>`). Aliases are detected by name (case-insensitively on Windows and macOS), by hard
link and by 8.3 short name. A `.pdb` output name is always refused. Every such refusal is exit 2,
before anything runs, and leaves all files as they were. Both the launcher and the script check this.

## Exit codes

| `dsig_export.py` | Meaning | `dsigmatcher` |
|---|---|---|
| 0 | ok | 0 |
| 2 | usage (bad arguments, wrong input kind for the mode, output name, an output that aliases the input or PDB, `--timeout` above 2592000 s) | 2 |
| 10 | input or PDB file missing or unreadable | 6 |
| 11 | IDA not found, or idalib cannot be loaded (licence, wrong Python) | 4 |
| 12 | Diaphora not found, or it fails to import | 4 |
| 13 | Hex-Rays unavailable | 4 |
| 14 | the PDB does not belong to the binary, or `--pdb` on a non-PE | 2 |
| 15 | IDA cannot open the input, or finds no functions in it | 4 |
| 16 | the export failed (Diaphora raised, crash marker, PDB not applied or applied unexpectedly, ...) | 6 |
| 17 | THE INPUT CHANGED during the export | 6 |
| 18 | timeout (`--timeout`) | 6 |
| 19 | the output, sidecar or work directory cannot be written | 6 |
| 20 | internal error | 6 |
| 130 | interrupted, or the launcher went away (nothing is published) | 6 |

The launcher itself also returns 2 for its own argument checks, 4 when Python, the script, IDA or
Diaphora is missing or Python cannot be started (and for the Windows Store `python` placeholder,
exit 9009), and 6 when the input is missing, the backstop timeout (`--timeout` + 120 s) kills the
process tree, or the sidecar does not match the run. With `--json`, `timed_out` is true after
either timeout: the script's own (exit 18) and the backstop kill. Its message always ends with the script's own
`dsig_export: error: ...` line when there is one. After exit 13 it adds how to export anyway
(`--allow-no-decompiler`, or `DSIG_EXPORT_ALLOW_NO_DECOMPILER=1`).

`--timeout` accepts 0 (none) to 2592000 seconds (30 days) in both the launcher and the script. Longer
waits cannot be expressed on every platform: a Windows wait is 32-bit milliseconds.

## How the launcher runs the script

- `python -E -X utf8 -B -u dsig_export.py <mode> <input> -o <output> --sidecar <json> ...`, started
  in the script's directory, with `PYTHONIOENCODING=utf-8`, `PYTHONUTF8=1`,
  `PYTHONDONTWRITEBYTECODE=1`, `PYTHONUNBUFFERED=1` and `NoDefaultCurrentDirectoryInExePath=1` added to
  the inherited environment. Paths are absolute. `-E` makes the driver ignore `PYTHON*` variables;
  `-I` and `-s` are not used, because the `idapro` wheel may live in the user's site-packages.
- Windows: `CreateProcessW` with a UTF-16 command line quoted by the C runtime's rules (the rules
  `CommandLineToArgvW` and Python use), only the output pipe and `NUL` inherited, and a
  kill-on-close job object so a timeout, or the launcher exiting, ends the script and its IDA worker
  together. Ctrl+C is left to the script, which stops IDA and removes its work directory. A batch file
  is never started.
- POSIX: `posix_spawn` into a new process group, so the script and its IDA worker are signalled
  together. On timeout the group gets SIGTERM (the script cleans up), then SIGKILL after 30 s; once
  the script has exited, anything left in its group is killed. SIGINT, SIGTERM and SIGHUP that reach
  the launcher are forwarded to the group, because the group is no longer the terminal's foreground
  group. If the launcher itself dies, the script notices that it has been re-parented, kills the
  worker and publishes nothing (exit 130).
- The script's output (IDA's console, Diaphora's log) is streamed to stderr; with `--quiet` it is not,
  and a failure prints only the final `error: ...` line (which still ends with the script's own error
  line). On success `dsigmatcher` prints a summary to stdout: output, function counts, the unchanged
  input sha256, the PDB, the tool versions and the sidecar path. With `--json` it prints one JSON
  object on stdout instead, on success and on failure (`exit_code`, `message`, `input`, `output`,
  `sidecar`, `input_sha256`, `tool_exit_code`, and on success the counts and tool versions).
- No Windows dialogs: `dsigmatcher` adds `SEM_FAILCRITICALERRORS`, `SEM_NOGPFAULTERRORBOX` and
  `SEM_NOOPENFILEERRORBOX` to its error mode before anything else, the script does the same before
  it starts the IDA worker, and no child is created with `CREATE_DEFAULT_ERROR_MODE`. A broken or
  foreign `idalib.dll` therefore fails the run (exit 11, `dsigmatcher` exit 4) instead of blocking it
  behind a modal "Bad Image" dialog, and a crash ends the process instead of waiting on the Windows
  Error Reporting dialog.
- Arguments are UTF-8. On Windows the CLI's narrow `argv` is in the ANSI code page; text that is not
  valid UTF-8 is read in that code page, so characters outside it cannot reach the bridge from the
  command line (library callers pass UTF-8 and are not affected).

## Tests

- `ctest -R cli_export_bridge` (C++, `tests/cli/export_bridge_tests.cpp`) needs neither Python nor
  IDA: the test executable plays the child process (echo, sleep and a fake `dsig_export.py`), which
  covers argument quoting round trips, UTF-8 paths with spaces, output capture, timeouts, discovery,
  bogus-path errors, the exit-code map and the sidecar checks. It also runs the bridge against a
  deliberately broken `idalib.dll` with the error mode cleared to 0 first and requires a clean exit 4
  within the timeout (no dialog). `ctest -R cli_commands` checks `--json`, `--quiet`,
  `--allow-no-decompiler` and `--timeout` through the built executable, again with a stand-in
  `dsig_export.py`, and repeats the broken-`idalib.dll` run through `dsigmatcher.exe` itself.
- With `DSIG_EXPORT_TESTS=1`, `DSIG_IDADIR`, `DSIG_DIAPHORA_DIR` (and `DSIG_PYTHON` or a `python` on
  `PATH`) and the corpus (`DSIG_CORPUS_ROOT`), the same suite also runs three real exports and
  requires each to equal the oracle export table for table: `ingest --pdb` of cryptbase 10.0.26100.8875
  (`cryptbase-8875-pdb`), `ingest --no-pdb` of win32u 10.0.26100.9444 (`win32u-9444-nopdb`), and
  `extract` of a copy of the user's win32u `.i64` (`win32u-9168-useri64`, 1510 functions).
- `python -B tools/export/selftest_dsig_export.py` checks the script's PE/PDB identity readers on
  synthetic files and its argument and tool checks, without IDA. It then runs whole driver + worker
  exports against stand-in idalib and Diaphora modules: output aliasing, git lookup, the work-directory
  sweep, the launcher-gone check, the timeout cap, the Hex-Rays advice, the no-functions refusal and
  the `PYTHON*` isolation. `cli_export_bridge` runs this selftest whenever a Python is available
  (`DSIG_PYTHON` or `python` on `PATH`), and skips it otherwise. It also runs the real script under a
  `PYTHONPATH` whose `sitecustomize` would kill any interpreter that loaded it.
- To compare an export with an oracle export by hand, run `tools/oracle/compare_exports.py` on
  **copies**: it opens both files read-write, which removes the leftover `-wal`/`-shm` pair next to an
  oracle export.
