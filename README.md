# DSigMatcher Native

**Diaphora's binary diff as one native executable, with the same results, row for row.**

DSigMatcher Native (`dsigmatcher`) matches the functions of two builds of a program and carries
names from a labelled build to a new one. Its diff engine is a C++20 port of
[Diaphora](https://github.com/joxeankoret/diaphora) 3.4.2 by Joxean Koret. It reads the same
SQLite exports Diaphora's exporter writes, runs Diaphora's own SQL heuristics through SQLite, and
writes the same `.diaphora` results file. On every reference pair tested, the output is identical
to Diaphora's: the same rows, in the same order, with the same line numbers and ratios.

What it adds around the diff:

- **Speed.** One native process, no Python. On the largest finished reference pair, a native diff
  takes about a minute where Diaphora takes hours.
- **Label once, carry forward.** You name functions in one build in IDA. `port` then writes those
  names into the export of the next build, and that output is itself a valid export, so it becomes
  the reference for the build after that. Each hop is recorded, with a confidence that shrinks as
  a name travels.
- **One command per step.** `extract` and `ingest` drive IDA's headless library (idalib) and
  Diaphora's unmodified exporter for you; `update` does a whole release step in one go.

| | |
|---|---|
| Version | 1.0.0 |
| Platforms | Windows x64, Linux x64, macOS universal2 (arm64 + x86_64) |
| Licence | AGPL-3.0-or-later (see [Licence and attribution](#licence-and-attribution)) |
| Parity reference | Diaphora 3.4.2-4-g621ec26, default configuration, SQLite 3.51.1 |

Contents: [Download](#download) · [Requirements](#requirements) · [Quick start](#quick-start) ·
[Querying the results](#querying-the-results) · [Command reference](#command-reference) ·
[Exit codes](#exit-codes) · [Crash recovery](#crash-recovery) ·
[Parity guarantee](#parity-guarantee) · [Known limitations](#known-limitations) ·
[Building from source](#building-from-source) · [Licence](#licence-and-attribution)

---

## Download

Release archives are on the
[v1.0.0 release page](https://github.com/kuro1337WStuff/DSigMatcher-Native/releases/tag/v1.0.0).

| Platform | Archive | Contents |
|---|---|---|
| Windows x64 | `dsigmatcher-1.0.0-windows-x64.zip` | `dsigmatcher.exe`, `dsig_export.py` and the documents, all in one folder |
| Linux x64 (any distribution) | `dsigmatcher-1.0.0-linux-x64.tar.gz` | `bin/dsigmatcher`, `share/dsigmatcher/tools/export/dsig_export.py`, `share/doc/dsigmatcher/`, the documents |
| macOS 13 or later, Apple silicon and Intel | `dsigmatcher-1.0.0-macos-universal2.tar.gz` | same layout as Linux |

Each archive also holds `README.md` (this file), `LICENSE`, `NOTICE` and `THIRD_PARTY_NOTICES.md`.

The binaries have no run-time dependencies beyond the operating system. SQLite 3.51.1 and the
C/C++ runtime are linked in. On Windows, `dsigmatcher.exe` is a single executable that needs no
DLL besides Windows' own: there is no `sqlite3.dll` or Visual C++ redistributable to install.
The Linux binary is fully static (no shared libraries, no dynamic loader) and runs on any x86-64
distribution. The macOS binary is one universal2 file for macOS 13 or later, ad-hoc signed and not
notarised. DSigMatcher was developed and measured on Windows 11; the release workflow tests each
archive on its platform's CI runners. `dsig_export.py` is only used by `extract`, `ingest` and
`update`; keep it next to the executable (Windows) or in the `share/` tree beside `bin/`
(Linux, macOS).

### Verify the download

`SHA256SUMS` on the release page lists the SHA-256 of every archive.

```sh
# Linux
sha256sum --check --ignore-missing SHA256SUMS
# macOS
shasum -a 256 --check --ignore-missing SHA256SUMS
```

```powershell
# Windows (PowerShell): compare the printed hash with the line in SHA256SUMS
Get-FileHash .\dsigmatcher-1.0.0-windows-x64.zip -Algorithm SHA256
```

Then check the binary:

```
$ dsigmatcher --version
dsigmatcher 1.0.0
SQLite 3.51.1
```

On macOS, a browser download is quarantined; run
`xattr -d com.apple.quarantine bin/dsigmatcher` once, or allow it under System Settings, Privacy
& Security. On Windows, SmartScreen may warn because the executable is not code-signed.

---

## Requirements

**`diff`, `port`, `info` and `version` need only the binary.** They work on Diaphora exports
(`.sqlite`) and results files (`.diaphora`) that already exist, including exports made by
Diaphora's own IDA plugin.

**`extract`, `ingest` and `update` need IDA and Diaphora**, because they produce exports with
Diaphora's exporter running inside IDA (`update` ingests the new build as its first step).

| Requirement | Details |
|---|---|
| IDA Pro 9.x with idalib | The headless IDA library. Exports need the **Hex-Rays decompiler** for the binary's architecture; without it the export is refused (exit 4) unless `--allow-no-decompiler` is given (see [`extract` and `ingest`](#extract-and-ingest)). |
| A Python that can load idalib | Python 3.8 or later. If the `idapro` package is not installed in it, the copy in `<IDA>/idalib/python` is used. Diaphora's own Python dependencies (for example `pygments`) must be installed in the same Python. |
| A Diaphora checkout | Diaphora is **not bundled**. Use revision 3.4.2-4-g621ec26 (commit `621ec26`), the one the parity guarantee was measured with. It is imported read-only and never modified. |

The tools are found in this order; the first one that exists wins:

| Tool | Flag | Environment | Then |
|---|---|---|---|
| Python | `--python <exe>` | `DSIG_PYTHON` | `python.exe` / `python3.exe` (Windows) or `python3` / `python` on `PATH` |
| IDA | `--ida-dir <dir>` | `DSIG_IDADIR`, then `IDADIR` | the install directory recorded in idalib's `ida-config.json` |
| Diaphora | `--diaphora-dir <dir>` | `DSIG_DIAPHORA_DIR` | required, no default |
| `dsig_export.py` | `--export-script <file>` | `DSIG_EXPORT_SCRIPT` | beside the executable, then `<prefix>/share/dsigmatcher/tools/export/` |

Every tool is checked before anything starts, and all missing ones are named in one message
(exit 4). `tools/export/README.md` describes the export bridge in full: isolation from your IDA
settings and plugins, PDB handling, the JSON sidecar it writes, and its own exit codes.

Environment variables named `DIAPHORA_*` are ignored on purpose. The engine always runs
Diaphora's default configuration; see [Parity guarantee](#parity-guarantee).

---

## Quick start

The workflow is **label once, carry forward**: name functions in one build, then move those names
to every later build without opening IDA again.

```sh
# 1. Export the build you labelled in IDA (the .i64 is copied first and never modified).
dsigmatcher extract app-v1.i64 -o v1.sqlite --diaphora-dir /path/to/diaphora

# 2. Export the new build straight from the binary (analysed from scratch, no PDB).
dsigmatcher ingest app-v2.dll -o v2.sqlite --diaphora-dir /path/to/diaphora

# 3. Diff them. The results file is the same file Diaphora would write.
dsigmatcher diff v1.sqlite v2.sqlite -o v1_vs_v2.diaphora

# 4. Carry the names over. The output is a copy of v2.sqlite with v1's names applied.
dsigmatcher port v1.sqlite v2.sqlite --results v1_vs_v2.diaphora -o v2_labelled.sqlite
#    (Steps 3 and 4 in one: without --results, port runs the diff itself and keeps the
#    results file beside the output, here as v2_labelled.diaphora.)

# 5. See what happened.
dsigmatcher info v2_labelled.sqlite
```

Set `DSIG_DIAPHORA_DIR` (and `DSIG_IDADIR` if IDA is not found on its own) to leave out the
flags. For the next release, `v2_labelled.sqlite` is the reference:

```sh
dsigmatcher ingest app-v3.dll -o v3.sqlite
dsigmatcher diff v2_labelled.sqlite v3.sqlite -o v2_vs_v3.diaphora
dsigmatcher port v2_labelled.sqlite v3.sqlite --results v2_vs_v3.diaphora -o v3_labelled.sqlite
```

**One step: `update`.** `update` ingests the new binary, diffs it against the labelled export
and ports the names, in one command:

```sh
dsigmatcher update v2_labelled.sqlite app-v3.dll -o v3_labelled.sqlite
```

Beside the output it keeps the intermediate files, so every step can be inspected:
`v3_labelled.ingest.sqlite` (the unlabelled export of the new build), its sidecar
`v3_labelled.ingest.export.json`, and `v3_labelled.diaphora` (the results that were applied).
Run `dsigmatcher update --help` for its options.

What `port` applies, by default:

- **best** and **partial** rows of the results file. **multimatch** and **unreliable** rows are
  applied only with `--include-multimatch` / `--include-unreliable`: on the reference pairs,
  multimatch rows were mostly wrong.
- only real names: IDA's placeholder names (`sub_*`, `nullsub_*`, `j_*`, `unknown_libname_*`,
  `DllEntryPoint`, `start`) and empty names are never ported, and never count as a name the
  target already has.
- never over a real name the target already has, unless `--overwrite-existing`. A hand label
  always beats an inferred one. Rows from Diaphora's "stripped binary" shortcut never replace a
  real name unless `--overwrite-stripped` is given as well.
- A name that would end up on two functions is dropped from both.

---

## Querying the results

Both outputs are ordinary SQLite databases; open them with the `sqlite3` shell or any SQLite
library.

### The `.diaphora` results file (`diff`)

The same layout as Diaphora's:

| Table | Columns |
|---|---|
| `config` | `main_db`, `diff_db` (the two exports, as given on the command line), `version`, `date` |
| `results` | `type` (`best`, `partial`, `unreliable`, `multimatch`), `line`, `address`, `name`, `address2`, `name2`, `ratio`, `nodes1`, `nodes2`, `description` (the heuristic or pass that produced the match) |
| `unmatched` | `type` (`primary`, `secondary`), `line`, `address`, `name` |

Addresses are stored as lower-case hex text of at least 8 digits (`%08x`) and ratios as text
with 7 decimals, as Diaphora writes them. `address`/`name` belong to the first database given to
`diff`, and `address2`/`name2` to the second.

```sql
-- How many matches each heuristic produced, per category
SELECT type, description, COUNT(*) AS n
FROM results
GROUP BY type, description
ORDER BY type, n DESC;

-- The weakest partial matches: good candidates for a manual look
SELECT address, name, address2, name2, ratio, description
FROM results
WHERE type = 'partial'
ORDER BY CAST(ratio AS REAL)
LIMIT 20;
```

### The labelled export (`port`, `update`)

A byte copy of the target export in which only `functions.name` and `functions.mangled_function`
change, plus four tables that Diaphora ignores:

| Table | One row per | Main columns |
|---|---|---|
| `dsig_provenance` | hop, carried forward from the reference | `hop`, `source_input_md5`, `target_input_md5`, `source_file_sha256`, `applied_at`, `tool_version`, `matches`, `names_applied`, `lineage` (the md5 chain of every build the names passed through) |
| `dsig_name_origin` | ported name | `address`, `name`, `origin_address`, `origin_name` (in the hand-labelled build), `hops`, `cumulative_ratio` (the product of the ratios of every hop), `heuristic` |
| `dsig_port_results` | hop, carried forward from the reference | the results file that was applied (name and SHA-256), the flags used, and the count of every decision |
| `dsig_port_log` | results row of this hop | reference and target names, `confidence`, `hops`, `action` (`applied`, `confirmed`, `not_selected`, `skipped_not_portable`, `skipped_conflict`, `skipped_existing`, `skipped_hops`, `skipped_ratio`, `skipped_duplicate_name`) |

```sql
-- Names that have travelled far or lost confidence
SELECT o.address, f.name, o.origin_name, o.hops, o.cumulative_ratio, o.heuristic
FROM dsig_name_origin AS o
JOIN functions AS f ON f.address = o.address
WHERE o.cumulative_ratio < 0.8 OR o.hops > 3
ORDER BY o.cumulative_ratio;

-- The hop history of this database
SELECT hop, applied_at, source_input_md5, target_input_md5, matches, names_applied
FROM dsig_provenance
ORDER BY hop;
```

In an export, `functions.address` is decimal text; in a results file it is hex. To join the two,
compare `printf('%08x', f.address)` with `results.address2`.

`dsigmatcher info <db>` prints the same identity, lineage and confidence summary without SQL.

---

## Command reference

```
dsigmatcher extract <in.i64|in.idb> -o <out.sqlite> [tool options]
dsigmatcher ingest  <binary> -o <out.sqlite> [--pdb <file> | --no-pdb] [tool options]
dsigmatcher diff    <db1.sqlite> <db2.sqlite> [-o <out.diaphora>] [options]
dsigmatcher port    <reference.sqlite> <target.sqlite> -o <out.sqlite> [--results <x.diaphora>] [options]
dsigmatcher update  <labelled.sqlite> <new binary> -o <new-labelled.sqlite> [options]
dsigmatcher info    <database.sqlite> [--json]
dsigmatcher version            (also --version, -V)
```

`dsigmatcher --help` lists the commands and the exit codes. `dsigmatcher <command> --help` lists one
command's options, and `dsigmatcher <command> --help-all` (or `dsigmatcher --help-all` for every
command) also lists the developer options: tracing, state snapshots and single-stage replay, used by
the parity tools. `extract`, `ingest`, `diff`, `port`, `update` and `info` accept `--json`, which
prints one JSON object with the outcome on stdout instead of the text summary. Paths may contain any
Unicode character, and on Windows they may be UNC paths (`\\server\share\...`).

### `diff`

Runs Diaphora's diff on two exports and writes Diaphora's results file. Without `-o` the file is
named `<db1 stem>_vs_<db2 stem>.diaphora`, as Diaphora would name it. An existing output is
replaced; an output that names one of the inputs is refused.

| Option | Meaning |
|---|---|
| `-o, --output <path>` | The results file. |
| `--ignore-small-functions` | Diaphora's `DIFFING_IGNORE_SMALL_FUNCTIONS` option: the SQL heuristics skip functions with 5 instructions or fewer. Off by default, as in Diaphora; the parity measurements used the default. |
| `--strict-sqlite` | Exit 5 unless the SQLite in use is 3.51.1 (always true for the release binaries). |
| `--allow-sqlite-mismatch` | Do not warn when SQLite is another version (source builds against a system SQLite). |
| `--quiet` | Do not print Diaphora's progress and summary lines on stderr. |
| `--json` | Print one JSON object with the outcome on stdout. |
| `--checkpoint-dir <dir>` | Save the diff's state in `<dir>` after every stage, so that an interrupted run can be resumed (see [Crash recovery](#crash-recovery)). |
| `--resume <dir>` | Continue an interrupted run from the last stage saved in `<dir>`, with the same two exports. The results are the same as those of an uninterrupted run. |

The options that change Diaphora's configuration away from its defaults (`--unreliable`,
`--relaxed-ratio`, `--use-trained-model`, `--project-script`) are refused with exit 4.

### `port`

Applies match results to the target export and writes a labelled copy. The inputs are never
modified. With `--results`, the rows of that file are applied (from `dsigmatcher diff` or from
Diaphora itself). Without it, `port` first runs the same diff as `dsigmatcher diff` and keeps its
results file beside the output as `<output stem>.diaphora`; the `diff` options
`--ignore-small-functions`, `--strict-sqlite`, `--allow-sqlite-mismatch` and `--quiet` then apply
to that diff.

| Option | Meaning |
|---|---|
| `-o, --output <path>` | Required. The labelled copy of the target. |
| `--results <x.diaphora>` | The results file to apply. Its rows must belong to these two exports, or nothing is written (exit 4). |
| `--include-multimatch` | Also apply multimatch rows. |
| `--include-unreliable` | Also apply unreliable rows. |
| `--min-ratio <r>` | Skip names whose cumulative confidence would fall below `r` (0.0 to 1.0). |
| `--max-hops <n>` | Skip names that have already travelled through more than `n` ports. |
| `--overwrite-existing` | Replace real names that the target already has (alias `--overwrite`). |
| `--overwrite-stripped` | With `--overwrite-existing`: let rows from Diaphora's "stripped binary" shortcut replace real names too. |
| `--store-full-paths` | Record absolute input paths in the provenance tables instead of file names. |
| `--no-keep-results` | Without `--results`: delete the results file of the diff that `port` ran, after the port. |
| `--json` | Print one JSON object with the outcome on stdout. |

### `update`

The whole carry-forward step in one command: the new binary is exported (as `ingest`), diffed
against the labelled export, and the names are ported into `-o`. The intermediate export, its
sidecar and the results file are kept beside the output (`<output stem>.ingest.sqlite`,
`<output stem>.ingest.export.json`, `<output stem>.diaphora`). It takes `ingest`'s `--pdb` /
`--no-pdb` and tool options, the `port` options, `diff`'s `--ignore-small-functions`,
`--strict-sqlite`, `--allow-sqlite-mismatch` and `--quiet`, and `--json`. Every argument and path
is checked before the export starts; after that, the first step that fails stops the command with
that step's exit code, and the files of the steps that finished stay beside the output (see
[Crash recovery](#crash-recovery)).

### `extract` and `ingest`

`extract` exports an existing IDA database with every name and type in it. The database is copied
into a private work directory, opened without auto-analysis and closed without saving; its SHA-256
is checked before and after.

`ingest` analyses a raw binary from scratch. By default no PDB is used and no symbol server is
contacted. `--pdb <file>` applies exactly that PDB, which must match the binary (GUID and age);
`--no-pdb` states the default explicitly.

Both write the export and a JSON sidecar (`<out stem>.export.json`) describing how it was made.

| Tool option | Meaning |
|---|---|
| `--python <exe>` | The Python that runs idalib and Diaphora. |
| `--ida-dir <dir>` | The IDA 9.x installation. |
| `--diaphora-dir <dir>` | The Diaphora checkout. |
| `--export-script <file>` | `dsig_export.py`, if it is not in its usual place. |
| `--temp-dir <dir>` | Where the work directory is created (default: the system temp directory). |
| `--keep-temp` | Keep the work directory (copies, logs) after the run. |
| `--timeout <seconds>` | Stop the export after this long (exit 6). |
| `--allow-no-decompiler` | Export even when the Hex-Rays decompiler is not available, instead of refusing with exit 4. The export then has no pseudo-code, so Diaphora's pseudo-code heuristics find nothing in it, and a diff against it matches fewer functions than a diff against an export made with the decompiler. |
| `--quiet` | Do not print the export's progress lines on stderr (errors are still printed). |
| `--json` | Print one JSON object with the outcome on stdout. |

### `info`

Prints a database's identity (file SHA-256, function count, processor, input MD5), its provenance
chain and hop history, and a summary of how many ported names there are and how confident they
are. `--json` prints the same as one JSON object.

### `version`

Prints `dsigmatcher <version>` on the first line and the linked SQLite version on the second.

---

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success. |
| 2 | Usage error: bad arguments, or an output path that would overwrite an input. |
| 3 | Diaphora itself would raise an error on these inputs; nothing is written. |
| 4 | Unsupported input, configuration or tool: a refused non-default option; an SQLite database that is not a Diaphora export (either input of `diff`; when it is the second one, `db2`, Diaphora first writes an empty results file, and so does `diff`) or not a results file; results that belong to other exports; or a missing tool (Python, IDA, Hex-Rays, Diaphora, `dsig_export.py`). |
| 5 | SQLite is not 3.51.1 and `--strict-sqlite` was given. |
| 6 | I/O or environment failure: a missing or unreadable input, a file that is not SQLite at all, an unwritable output, a failed or timed-out export. |
| 70 | Internal error (a bug; please report it with the command line). |

`extract`, `ingest` and `update` map the export script's own exit codes onto this table; the
mapping is in `tools/export/README.md`.

---

## Crash recovery

**No output is ever half-written.** Every command writes its output under a temporary name in the
output's directory and renames it over the output only when it is complete. If a run is killed,
crashes, runs out of disk space or loses power, the output path still holds the previous file (or
nothing), never a partial file that could be mistaken for a complete one. Temporary files left by a
killed run sit next to the output, named after it with a `.tmp-…` or `.dsig-…` suffix, and can be
deleted.

**Long diffs can be resumed.** A diff runs through a fixed series of stages: the pre-loop passes,
the SQL heuristics, callee diffing, the related passes and the final pass. With
`--checkpoint-dir <dir>`, `diff` saves its complete state in `<dir>` after every stage. If the run
stops, start it again with `--resume <dir>`:

```sh
dsigmatcher diff v1.sqlite v2.sqlite -o v1_vs_v2.diaphora --checkpoint-dir v1_vs_v2.ckpt
# ... interrupted ...
dsigmatcher diff v1.sqlite v2.sqlite -o v1_vs_v2.diaphora --resume v1_vs_v2.ckpt
```

The stages that were saved are not run again. The `.diaphora` file is still written only at the
end, and it holds the same rows as an uninterrupted run would write: progress survives in the
checkpoint directory, not in a partial results file.

**`update` keeps what it finished.** Each step's output is complete before the next step starts. If
`update` stops in the diff or the port, `<output stem>.ingest.sqlite` (the export of the new build,
the slow part) is already complete beside the output, and `diff` and `port` can be run on it by hand
instead of exporting again.

---

## Parity guarantee

For two Diaphora exports, `dsigmatcher diff` writes the same `.diaphora` file as

```
python diaphora.py db1.sqlite db2.sqlite -o out.diaphora
```

run from Diaphora 3.4.2-4-g621ec26 in its **default configuration** (no `DIAPHORA_*` variables):
the same `results` and `unmatched` rows, in the same stored order, with the same `line` numbers,
ratios, categories and descriptions. This is "L2" parity. Only the `config` row can differ: its
`date` is the time of the run, and `main_db` / `diff_db` are the two paths as you typed them.

It was measured on every finished pair of the reference set: real Diaphora exports of real
binaries, each diffed by unmodified Diaphora and by `dsigmatcher`, then compared field by field
with `tools/parity/run_parity.py`.

| Pair | Diaphora mode | Rows | Parity | Native time |
|---|---|---:|---|---:|
| ls-old → ls (Diaphora's test samples) | normal | 278 | identical | 2.2 s |
| ls → ls-old | normal | 286 | identical | 1.6 s |
| userenv 9168 (PDB) → 9278 (no PDB) | normal | 2180 | identical | 63 s (Diaphora: hours) |
| userenv 9168 (PDB) → 9278 (PDB) | patch diff | 643 | identical | 0.13 s |
| win32u 9168 (hand-labelled `.i64`) → 9444 (no PDB) | stripped binary | 1510 | identical | 0.15 s |
| cryptbase 1 (PDB) → 8875 (no PDB) | normal | 29 | identical | 0.2 s |
| cryptbase 8875 (PDB) → 9444 (no PDB) | stripped binary | 43 | identical | 0.03 s |

Conditions:

- **SQLite 3.51.1.** Diaphora's results depend on the order in which SQLite's query planner returns
  rows, so the engine runs Diaphora's SQL through the same SQLite version the reference runs used,
  compiled with the same options. The release binaries bundle it. A source build against another
  SQLite (`-DDSIG_VENDORED_SQLITE=OFF`) warns, and then only the set of rows is expected to match,
  not their order.
- **The same exports.** Exports depend on the IDA version, the Diaphora revision and the analysing
  machine; `extract` and `ingest` use Diaphora's own exporter, but the guarantee is about the diff
  of two given exports.
- **Measured on Windows x64.** The reference pairs need the private corpus and were run on Windows.
  On Linux and macOS the release builds use the same bundled SQLite and pass the same test suites
  in CI, including the stage-by-stage suites whose expected values come from real Diaphora, but the
  full reference pairs have not been rerun there.

An eighth pair (sechost, PDB → no PDB), whose Diaphora run takes about a day, is being run again;
its parity result is pending, so it is not in the table.

Diaphora's result is not always right: the parity guarantee means DSigMatcher makes the same
mistakes Diaphora makes. These are the names `port` applies, scored against the PDB names of
target builds that were analysed without their PDB:

| Pair | Functions | Correct | Wrong | Missed |
|---|---:|---:|---:|---:|
| userenv 9168 → 9278 | 622 | 482 (+1 correct under an alias) | 35 | 104 |
| cryptbase 1 → 8875 | 43 | 27 | 2 | 14 |
| cryptbase 8875 → 9444 | 43 | 43 | 0 | 0 |

Because the results files are identical, porting Diaphora's own results gives the same scores. On
cryptbase 8875 → 9444, names that IDA generates for the unnamed target, such as `DllEntryPoint`,
count as placeholders, so the real name from the reference replaces them.

---

## Known limitations

- **One Python set-order effect.** Diaphora's "Same constants related matches" pass iterates a
  Python `set`, whose order changes with Python's per-process string hash seed. DSigMatcher uses
  one fixed order. Intermediate states can then differ from a particular Diaphora run in that pass
  only; on every reference pair the next cleanup step removed the difference and the final results
  were identical.
- **Diaphora's defaults only.** Heuristics that Diaphora marks unreliable, the unreliable category,
  relaxed ratios, the machine-learning model and project scripts are all off in Diaphora's
  default configuration, and DSigMatcher does not offer them (exit 4).
- **`extract`, `ingest` and `update` need IDA.** There is no native exporter yet.
- **"Stripped binary" mode inherits Diaphora's shortcut.** When Diaphora decides two exports are
  the same binary with symbols stripped, it pairs functions by address. On a build where functions
  moved, many of those best rows are wrong (1172 of 1509 on the win32u pair). `port` never lets
  those rows replace a real name unless asked twice (`--overwrite-existing --overwrite-stripped`),
  but review stripped-mode results before porting them into an unnamed target.
- **Multimatch rows are opt-in** because most of them were wrong on the reference pairs (73
  correct, 1580 wrong on userenv).
- **A function missed once stays unnamed.** A name that is not ported at one hop is absent from
  the reference of the next hop.
- **IDA's other automatic names** (beyond the placeholders listed under Quick start, for example
  names IDA derives from imports or strings) count as real names, as they do in Diaphora.
- **Recorded paths.** The provenance tables store input file names only (the SHA-256 columns
  identify the files); `--store-full-paths` stores absolute paths, which include your user name
  and directory layout if you share the database.
- **Speed.** v1.0 runs Diaphora's SQL heuristics unchanged, so the cost of a few wide constants
  joins is still SQLite's. Planned optimisations are in `docs/fusion/INVENTORY.md` and
  `docs/design-future.md`.

---

## Building from source

Requirements: CMake 3.20 or later, Ninja, a C++20 compiler and a C compiler, and network access at
configure time (CMake downloads Zydis, Zycore and the SQLite 3.51.1 amalgamation, each pinned by
hash or commit).

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

- **Windows:** Visual Studio 2022 or later with the C++ workload. Run the commands from an
  "x64 Native Tools" prompt (or after `vcvars64.bat`); CMake and Ninja ship with Visual Studio.
- **Linux:** GCC or Clang, CMake and Ninja from the distribution.
- **macOS:** Xcode command-line tools, and CMake and Ninja (for example from Homebrew). Add
  `-DCMAKE_OSX_DEPLOYMENT_TARGET=13.0` (the release's target) and
  `"-DCMAKE_OSX_ARCHITECTURES=arm64;x86_64"` for a universal binary.

Build options:

| Option | Default | Effect |
|---|---|---|
| `DSIG_VENDORED_SQLITE` | `ON` | Build the bundled SQLite 3.51.1 with the reference options. `OFF` uses the system SQLite (`find_package(SQLite3)`); see [Parity guarantee](#parity-guarantee). |
| `DSIG_STATIC_RUNTIME` | `ON` | Link the C/C++ runtime statically (MSVC `/MT`; `-static-libstdc++ -static-libgcc` on Linux). |
| `DSIG_FULLY_STATIC` | `OFF` | Linux: link fully statically. Meant for musl (Alpine); the Linux release is built this way. |
| `BUILD_TESTING` | `ON` | Build the test suites. |
| `FETCHCONTENT_SOURCE_DIR_SQLITE3` | | An unpacked amalgamation directory, for offline builds. |

`cmake --install build --prefix <dir> --component dsigmatcher` installs `bin/dsigmatcher`,
`share/dsigmatcher/tools/export/dsig_export.py`, and `LICENSE`, `NOTICE`,
`THIRD_PARTY_NOTICES.md` and `README.md` in `share/doc/dsigmatcher/`. The official archives are
built only by `.github/workflows/release.yml`.

The design documents in `docs/parity/` describe how each part of Diaphora was ported. `tools/`
holds the Python tools that build the reference results and check parity; they are not needed to
use `dsigmatcher`.

---

## Licence and attribution

DSigMatcher Native is free software under the **GNU Affero General Public License, version 3 or
(at your option) any later version**. See [`LICENSE`](LICENSE).

- The diff engine is a C++ translation of the diffing logic of **Diaphora**, Copyright (c)
  2015-2026 Joxean Koret, AGPL-3.0-or-later, revision 3.4.2-4-g621ec26. It embeds Diaphora's
  heuristic and stage SQL verbatim (`src/diff/RegistrySql.inc`, `src/diff/StageSql.inc`).
  [`NOTICE`](NOTICE) has the full attribution and a description of the changes.
- The text-diff code is a translation of **CPython 3.13's `difflib`** (PSF License Version 2).
  **Zydis** and **Zycore** (MIT) are linked in, and **SQLite** (public domain) is bundled.
  [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) has their licence texts.
- Diaphora, IDA Pro and the Hex-Rays decompiler are **not** included. `extract`, `ingest` and
  `update` use your own installation of each.

**Source code.** The complete corresponding source of each release is the git tag of the same
name in <https://github.com/kuro1337WStuff/DSigMatcher-Native>, for example
[`v1.0.0`](https://github.com/kuro1337WStuff/DSigMatcher-Native/tree/v1.0.0); the release page
also offers it as an archive.
