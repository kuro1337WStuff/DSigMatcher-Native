#!/usr/bin/env python3

"""Build the Diaphora parity oracle: real exports plus Diaphora's own diff results.

Stages (run in this order; each can be re-run on its own):

  exports   analyse every binary in EXPORTS with IDA (idalib) and export it with
            Diaphora's exporter (diaphora_export.py). Independent exports run in
            parallel processes.
  validate  re-export the ELF samples with Diaphora's own tester command line
            (idat -A -B -S diaphora.py) and compare with the idalib exports.
  diffs     run unmodified Diaphora, `python diaphora.py <ref> <target> -o <out>`,
            from the Diaphora checkout, twice per pair, and compare the two runs.
  summary   collect <root>/manifest.json and write it as Markdown tables to
            <root>/ORACLE-results.md (also printed).

Everything is written under --root (never inside a repository):

  <root>/exports/<id>/        working copy of the binary, its .i64, <id>.sqlite,
                              <id>.export.json (how it was produced), export.log
  <root>/diffs/<pair>/runN/   <pair>.diaphora, diaphora.log, run.json
  <root>/diffs/<pair>/determinism.json
  <root>/manifest.json        everything above, collected
  <root>/ORACLE-results.md    generated tables (summary stage)

Windows binaries and PDBs are expected under <bin-dir>, as laid out by
tools/prepare_corpus.py (one <name>_<version> directory per build). Diaphora's
own ls/ls-old samples come from <diaphora-dir>/tester/samples.

Example:
  python build_oracle.py --root C:/corpus/oracle --diaphora-dir C:/diaphora \
      --ida-dir "C:/IDA Professional 9.4" all
"""

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

# pdb: "n/a" (not a PE), None (analyse WITHOUT a PDB), or a path template.
EXPORTS = [
    {"id": "ls-old", "source": "{samples}/ls-old", "pdb": "n/a"},
    {"id": "ls", "source": "{samples}/ls", "pdb": "n/a"},
    {"id": "userenv-9168-pdb", "source": "{bin}/userenv_100261009168/userenv.dll",
     "pdb": "{bin}/userenv_100261009168/userenv.pdb"},
    {"id": "userenv-9278-nopdb", "source": "{bin}/userenv_100261009278/userenv.dll", "pdb": None},
    {"id": "userenv-9278-pdb", "source": "{bin}/userenv_100261009278/userenv.dll",
     "pdb": "{bin}/userenv_100261009278/userenv.pdb"},
    {"id": "sechost-9168-pdb", "source": "{bin}/sechost_100261009168/sechost.dll",
     "pdb": "{bin}/sechost_100261009168/sechost.pdb"},
    {"id": "sechost-9444-nopdb", "source": "{bin}/sechost_100261009444/sechost.dll", "pdb": None},
]

# ref = older build (Diaphora's db1, "main"), target = newer build (db2, "diff").
DIFFS = [
    {"id": "ls-old_vs_ls", "ref": "ls-old", "target": "ls",
     "tester_cfg": "ls-old.cfg"},
    {"id": "ls_vs_ls-old", "ref": "ls", "target": "ls-old",
     "tester_cfg": "ls.cfg"},
    {"id": "userenv-9168-pdb_vs_9278-nopdb", "ref": "userenv-9168-pdb", "target": "userenv-9278-nopdb"},
    {"id": "userenv-9168-pdb_vs_9278-pdb", "ref": "userenv-9168-pdb", "target": "userenv-9278-pdb"},
    {"id": "sechost-9168-pdb_vs_9444-nopdb", "ref": "sechost-9168-pdb", "target": "sechost-9444-nopdb"},
]

RESULT_COLUMNS = ("type", "line", "address", "name", "address2", "name2",
                  "ratio", "nodes1", "nodes2", "description")


def Log(Message):
    print(Message, flush=True)


def Sha256OfFile(Path):
    Digest = hashlib.sha256()
    with open(Path, "rb") as Handle:
        for Chunk in iter(lambda: Handle.read(1024 * 1024), b""):
            Digest.update(Chunk)
    return Digest.hexdigest()


def WriteJson(Path, Data):
    with open(Path, "w", encoding="utf-8") as Handle:
        json.dump(Data, Handle, indent=2, default=str)


def ReadJson(Path):
    with open(Path, "r", encoding="utf-8") as Handle:
        return json.load(Handle)


def Expand(Template, Args):
    return os.path.abspath(Template.format(samples=Args.samples_dir, bin=Args.bin_dir))


def FindProgramOnPath(Name):
    """The absolute path of program Name found in an ABSOLUTE PATH entry, or None.

    Never the current directory: on Windows, CreateProcess (and so subprocess with a bare "git") and
    shutil.which before Python 3.12 look there first, and the current directory may hold a planted
    git.exe (audit F16). Empty and relative PATH entries ("", ".", "bin") are skipped for the same
    reason. tools/export/dsig_export.py and tools/e2e/e2e_common.py have the same function."""
    Names = [Name + ".exe"] if sys.platform == "win32" and not os.path.splitext(Name)[1] else [Name]
    for Entry in os.environ.get("PATH", "").split(os.pathsep):
        Entry = Entry.strip().strip('"')
        if not Entry or not os.path.isabs(Entry):
            continue
        for Candidate in (os.path.join(Entry, Each) for Each in Names):
            if os.path.isfile(Candidate) and (sys.platform == "win32" or os.access(Candidate, os.X_OK)):
                return os.path.abspath(Candidate)
    return None


def ChildEnv(Base=None):
    """Base (default: this process's environment) with NoDefaultCurrentDirectoryInExePath=1, so no child
    resolves a program started by a bare name in its current directory (audit F16)."""
    Env = dict(os.environ if Base is None else Base)
    Env["NoDefaultCurrentDirectoryInExePath"] = "1"
    return Env


def DiaphoraRevision(DiaphoraDir):
    Git = FindProgramOnPath("git")
    if Git is None:
        return "unknown (no git in an absolute PATH entry)"
    try:
        return subprocess.run([Git, "-C", DiaphoraDir, "describe", "--tags", "--long", "--dirty"],
                              capture_output=True, text=True, check=True, env=ChildEnv(),
                              stdin=subprocess.DEVNULL).stdout.strip()
    except Exception as Exc:
        return "unknown (%s)" % Exc


def CleanEnv():
    """The caller's environment minus anything that steers Diaphora.

    PYTHONDONTWRITEBYTECODE only stops __pycache__ files appearing in the
    Diaphora checkout; it does not change what Diaphora computes.
    NoDefaultCurrentDirectoryInExePath=1 keeps a child from resolving a program
    started by a bare name in its current directory (audit F16)."""
    Env = {Key: Value for Key, Value in os.environ.items() if not Key.upper().startswith("DIAPHORA_")}
    Env["PYTHONDONTWRITEBYTECODE"] = "1"
    return ChildEnv(Env)


# ----------------------------------------------------------------------------- exports

def RunExport(Spec, Args):
    WorkDir = os.path.join(Args.root, "exports", Spec["id"])
    if os.path.isdir(WorkDir):
        shutil.rmtree(WorkDir)
    os.makedirs(WorkDir)

    Source = Expand(Spec["source"], Args)
    Binary = os.path.join(WorkDir, os.path.basename(Source))
    shutil.copyfile(Source, Binary)

    Env = CleanEnv()
    Env["IDADIR"] = Args.ida_dir
    # An empty IDAUSR keeps the user's own plugins and settings out of the oracle.
    Env["IDAUSR"] = os.path.join(Args.root, "idausr")
    os.makedirs(Env["IDAUSR"], exist_ok=True)
    IdaArgs = ""
    if Spec["pdb"] is None:
        # No PDB: disable the PDB plugin and point the symbol path at an empty,
        # local-only directory so nothing can be fetched from a symbol server.
        IdaArgs = "-Opdb:off"
        Env["_NT_SYMBOL_PATH"] = os.path.join(Args.root, "nosymbols")
        os.makedirs(Env["_NT_SYMBOL_PATH"], exist_ok=True)
    elif Spec["pdb"] == "n/a":
        Env["_NT_SYMBOL_PATH"] = os.path.join(Args.root, "nosymbols")
        os.makedirs(Env["_NT_SYMBOL_PATH"], exist_ok=True)
    else:
        # With PDB: the matching PDB sits next to the binary and the symbol
        # path is that directory only (no SRV* entry, so no network).
        Pdb = Expand(Spec["pdb"], Args)
        shutil.copyfile(Pdb, os.path.join(WorkDir, os.path.basename(Pdb)))
        Env["_NT_SYMBOL_PATH"] = WorkDir
    Env.pop("_NT_ALT_SYMBOL_PATH", None)

    OutSqlite = os.path.join(WorkDir, Spec["id"] + ".sqlite")
    MetaPath = os.path.join(WorkDir, Spec["id"] + ".export.json")
    LogPath = os.path.join(WorkDir, "export.log")
    Command = [Args.python, os.path.join(HERE, "diaphora_export.py"),
               "--input", Binary, "--out", OutSqlite,
               "--diaphora-dir", Args.diaphora_dir, "--meta", MetaPath]
    if IdaArgs:
        # "=" form: argparse would otherwise read "-Opdb:off" as an option.
        Command += ["--ida-args=" + IdaArgs]

    Log("[export] %s: start" % Spec["id"])
    Started = time.monotonic()
    with open(LogPath, "w", encoding="utf-8", errors="replace") as Handle:
        Code = subprocess.call(Command, cwd=WorkDir, env=Env, stdout=Handle, stderr=subprocess.STDOUT)
    Wall = round(time.monotonic() - Started, 3)

    Meta = ReadJson(MetaPath) if os.path.isfile(MetaPath) else {}
    if Code == 0 and Spec["pdb"] != "n/a":
        import pdb_proof
        Proof = pdb_proof.Classify(OutSqlite, Binary)
        WriteJson(os.path.join(WorkDir, "pdb_proof.json"), Proof)
        Proof["other_names"] = Proof["other_names"][:25]
        Meta["pdb_proof"] = Proof
    Meta.update({
        "id": Spec["id"],
        "source": Source,
        "pdb_mode": "n/a" if Spec["pdb"] == "n/a" else ("without" if Spec["pdb"] is None else "with"),
        "pdb_source": None if Spec["pdb"] in (None, "n/a") else Expand(Spec["pdb"], Args),
        "command": Command,
        "exit_code": Code,
        "wall_seconds": Wall,
    })
    WriteJson(MetaPath, Meta)
    Log("[export] %s: exit %d in %.1fs" % (Spec["id"], Code, Wall))
    return Meta


def StageExports(Args):
    Selected = [Spec for Spec in EXPORTS if not Args.only or Spec["id"] in Args.only]
    with ThreadPoolExecutor(max_workers=Args.jobs) as Pool:
        Results = list(Pool.map(lambda Spec: RunExport(Spec, Args), Selected))
    Failed = [Meta["id"] for Meta in Results if Meta.get("exit_code") != 0]
    SymbolCache = os.path.join(os.environ.get("TEMP", ""), "ida")
    Log("[export] IDA default symbol cache %s exists: %s" % (SymbolCache, os.path.exists(SymbolCache)))
    if Failed:
        Log("[export] FAILED: %s" % ", ".join(Failed))
        return 1
    return 0


# ----------------------------------------------------------------------------- validate

def StageValidate(Args):
    """Re-export the non-PE samples with Diaphora's own tester command line
    (tester/tester.py launch_export: `idat -A -B -S diaphora.py`, DIAPHORA_AUTO=1)
    and compare each database with the idalib export, table by table."""
    Idat = os.path.join(Args.ida_dir, "idat.exe" if os.name == "nt" else "idat")
    Code = 0
    for Spec in EXPORTS:
        if Spec["pdb"] != "n/a" or (Args.only and Spec["id"] not in Args.only):
            continue
        WorkDir = os.path.join(Args.root, "validate", Spec["id"])
        if os.path.isdir(WorkDir):
            shutil.rmtree(WorkDir)
        os.makedirs(WorkDir)
        Source = Expand(Spec["source"], Args)
        Binary = os.path.join(WorkDir, os.path.basename(Source))
        shutil.copyfile(Source, Binary)
        OutSqlite = os.path.join(WorkDir, Spec["id"] + ".sqlite")
        Env = CleanEnv()
        Env.update({"DIAPHORA_CPU_COUNT": "1", "DIAPHORA_AUTO": "1", "DIAPHORA_LOG_PRINT": "1",
                    "DIAPHORA_EXPORT_FILE": OutSqlite, "DIAPHORA_USE_DECOMPILER": "1",
                    "PYTHONWARNINGS": "ignore",
                    "IDAUSR": os.path.join(Args.root, "idausr"),
                    "_NT_SYMBOL_PATH": os.path.join(Args.root, "nosymbols")})
        Command = [Idat, "-A", "-B", "-S" + os.path.join(Args.diaphora_dir, "diaphora.py"),
                   "-L" + os.path.join(WorkDir, "ida.log"), Binary]
        Log("[validate] %s: %s" % (Spec["id"], " ".join(Command)))
        subprocess.call(Command, cwd=WorkDir, env=Env)
        Reference = os.path.join(Args.root, "exports", Spec["id"], Spec["id"] + ".sqlite")
        with open(os.path.join(WorkDir, "compare.txt"), "w", encoding="utf-8") as Handle:
            Result = subprocess.call([sys.executable, os.path.join(HERE, "compare_exports.py"),
                                      Reference, OutSqlite], stdout=Handle, stderr=subprocess.STDOUT,
                                     env=ChildEnv())
        with open(os.path.join(WorkDir, "compare.txt"), "r", encoding="utf-8") as Handle:
            Log(Handle.read())
        Log("[validate] %s: idalib export %s the tester-path export"
            % (Spec["id"], "MATCHES" if Result == 0 else "DIFFERS FROM"))
        Code |= Result
    return Code


# ----------------------------------------------------------------------------- diffs

def ReadResults(DiaphoraPath):
    Handle = sqlite3.connect(DiaphoraPath)
    try:
        Results = Handle.execute("select %s from results" % ", ".join(RESULT_COLUMNS)).fetchall()
        Unmatched = Handle.execute("select type, line, address, name from unmatched").fetchall()
        Config = Handle.execute("select main_db, diff_db, version, date from config").fetchall()
    finally:
        Handle.close()
    return Results, Unmatched, Config


def CategoryCounts(Results):
    Counts = {}
    for Row in Results:
        Counts[Row[0]] = Counts.get(Row[0], 0) + 1
    return Counts


def FinalResultsLine(LogPath):
    Line = None
    with open(LogPath, "r", encoding="utf-8", errors="replace") as Handle:
        for Text in Handle:
            if "Final results:" in Text:
                Line = Text.strip()
    return Line


def RunDiff(Pair, RunIndex, Args):
    RunDir = os.path.join(Args.root, "diffs", Pair["id"], "run%d" % RunIndex)
    if os.path.isdir(RunDir):
        shutil.rmtree(RunDir)
    os.makedirs(RunDir)
    Ref = os.path.join(Args.root, "exports", Pair["ref"], Pair["ref"] + ".sqlite")
    Target = os.path.join(Args.root, "exports", Pair["target"], Pair["target"] + ".sqlite")
    Out = os.path.join(RunDir, Pair["id"] + ".diaphora")
    LogPath = os.path.join(RunDir, "diaphora.log")
    # Exactly what a user types, from the Diaphora checkout, with no DIAPHORA_*
    # variables set, so diaphora_config.py defaults apply.
    Command = [Args.diff_python, "diaphora.py", Ref, Target, "-o", Out]
    Log("[diff] %s run%d: start" % (Pair["id"], RunIndex))
    Started = time.monotonic()
    with open(LogPath, "w", encoding="utf-8", errors="replace") as Handle:
        Code = subprocess.call(Command, cwd=Args.diaphora_dir, env=CleanEnv(),
                               stdout=Handle, stderr=subprocess.STDOUT)
    Wall = round(time.monotonic() - Started, 3)
    Info = {"pair": Pair["id"], "run": RunIndex, "command": Command, "cwd": Args.diaphora_dir,
            "exit_code": Code, "wall_seconds": Wall, "final_results": FinalResultsLine(LogPath)}
    with open(LogPath, "r", encoding="utf-8", errors="replace") as Handle:
        Text = Handle.read()
    Info["timeouts_logged"] = Text.count("Timeout with heuristic")
    Info["tracebacks_logged"] = Text.count("Traceback (most recent call last)")
    if os.path.isfile(Out):
        Results, Unmatched, Config = ReadResults(Out)
        Info["results_rows"] = len(Results)
        Info["results_by_type"] = CategoryCounts(Results)
        Info["unmatched_rows"] = CategoryCounts(Unmatched)
        Info["config_row"] = Config
        Info["diaphora_sha256"] = Sha256OfFile(Out)
    WriteJson(os.path.join(RunDir, "run.json"), Info)
    Log("[diff] %s run%d: exit %d in %.1fs: %s" % (Pair["id"], RunIndex, Code, Wall, Info["final_results"]))
    return Info


def CompareRuns(Pair, Args):
    """Row-for-row comparison of run1 and run2 of one pair."""
    Paths = [os.path.join(Args.root, "diffs", Pair["id"], "run%d" % Index, Pair["id"] + ".diaphora")
             for Index in (1, 2)]
    (R1, U1, _), (R2, U2, _) = ReadResults(Paths[0]), ReadResults(Paths[1])
    Report = {"pair": Pair["id"]}
    # 1. Exact equality in stored order (rowid order = chooser insertion order).
    Report["results_identical_in_order"] = R1 == R2
    Report["unmatched_identical_in_order"] = U1 == U2
    # 2. Equality as sets of full rows, ignoring the chooser 'line' column.
    def Key(Row):
        return (Row[0],) + tuple(Row[2:])
    S1, S2 = set(map(Key, R1)), set(map(Key, R2))
    Report["results_identical_as_sets_ignoring_line"] = S1 == S2
    # 3. Which (address, address2) pairs differ, and how.
    ByPair1 = {(Row[2], Row[4]): Row for Row in R1}
    ByPair2 = {(Row[2], Row[4]): Row for Row in R2}
    OnlyIn1 = sorted(set(ByPair1) - set(ByPair2))
    OnlyIn2 = sorted(set(ByPair2) - set(ByPair1))
    Changed = []
    for Both in sorted(set(ByPair1) & set(ByPair2)):
        A, B = ByPair1[Both], ByPair2[Both]
        Fields = [RESULT_COLUMNS[Index] for Index in range(len(RESULT_COLUMNS))
                  if A[Index] != B[Index] and RESULT_COLUMNS[Index] != "line"]
        if Fields:
            Changed.append({"pair": Both, "fields": Fields, "run1": A, "run2": B})
    Report["pairs_only_in_run1"] = [ByPair1[P] for P in OnlyIn1]
    Report["pairs_only_in_run2"] = [ByPair2[P] for P in OnlyIn2]
    Report["pairs_changed"] = Changed
    Report["deterministic"] = (Report["results_identical_as_sets_ignoring_line"]
                               and sorted(U1) == sorted(U2))
    WriteJson(os.path.join(Args.root, "diffs", Pair["id"], "determinism.json"), Report)
    Log("[diff] %s: deterministic=%s (in-order=%s, only1=%d, only2=%d, changed=%d)"
        % (Pair["id"], Report["deterministic"], Report["results_identical_in_order"],
           len(OnlyIn1), len(OnlyIn2), len(Changed)))
    return Report


def ExportHashes(Args, Pairs):
    Ids = sorted({Pair[Side] for Pair in Pairs for Side in ("ref", "target")})
    return {Id: Sha256OfFile(os.path.join(Args.root, "exports", Id, Id + ".sqlite")) for Id in Ids}


def StageDiffs(Args):
    Selected = [Pair for Pair in DIFFS if not Args.only or Pair["id"] in Args.only]
    Before = ExportHashes(Args, Selected)
    Jobs = [(Pair, Run) for Run in range(1, Args.runs + 1) for Pair in Selected]
    with ThreadPoolExecutor(max_workers=Args.jobs) as Pool:
        list(Pool.map(lambda Job: RunDiff(Job[0], Job[1], Args), Jobs))
    if Args.runs >= 2:
        for Pair in Selected:
            CompareRuns(Pair, Args)
    # Diaphora opens the main export read/write (WAL, "create table if not
    # exists"); make sure diffing left the inputs untouched.
    After = ExportHashes(Args, Selected)
    Changed = sorted(Id for Id in Before if Before[Id] != After[Id])
    WriteJson(os.path.join(Args.root, "diffs", "input_hashes.json"),
              {"before": Before, "after": After, "changed": Changed})
    Log("[diff] export databases modified by diffing: %s" % (Changed or "none"))
    return 0


# ----------------------------------------------------------------------------- manifest

def TesterExpectations(Args, CfgName):
    import configparser
    Parser = configparser.ConfigParser()
    Parser.read(os.path.join(Args.samples_dir, CfgName))
    return {Section: dict(Parser[Section]) for Section in ("Export", "Diff") if Section in Parser}


def StageManifest(Args):
    Manifest = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "diaphora_dir": Args.diaphora_dir,
        "diaphora_revision": DiaphoraRevision(Args.diaphora_dir),
        "ida_dir": Args.ida_dir,
        "exports": {},
        "diffs": {},
    }
    for Spec in EXPORTS:
        MetaPath = os.path.join(Args.root, "exports", Spec["id"], Spec["id"] + ".export.json")
        if os.path.isfile(MetaPath):
            Manifest["exports"][Spec["id"]] = ReadJson(MetaPath)
    for Pair in DIFFS:
        Entry = {"ref": Pair["ref"], "target": Pair["target"], "runs": []}
        for Index in range(1, 10):
            RunJson = os.path.join(Args.root, "diffs", Pair["id"], "run%d" % Index, "run.json")
            if os.path.isfile(RunJson):
                Entry["runs"].append(ReadJson(RunJson))
        Determinism = os.path.join(Args.root, "diffs", Pair["id"], "determinism.json")
        if os.path.isfile(Determinism):
            Report = ReadJson(Determinism)
            Entry["determinism"] = {Key: Report[Key] for Key in Report
                                    if not Key.startswith("pairs_")}
            Entry["determinism"]["pairs_only_in_run1"] = len(Report["pairs_only_in_run1"])
            Entry["determinism"]["pairs_only_in_run2"] = len(Report["pairs_only_in_run2"])
            Entry["determinism"]["pairs_changed"] = len(Report["pairs_changed"])
        if Pair.get("tester_cfg"):
            Entry["tester_expected"] = TesterExpectations(Args, Pair["tester_cfg"])
        Manifest["diffs"][Pair["id"]] = Entry
    WriteJson(os.path.join(Args.root, "manifest.json"), Manifest)
    Log("[manifest] %s" % os.path.join(Args.root, "manifest.json"))
    return Manifest


def StageSummary(Args):
    Manifest = StageManifest(Args)
    Lines = ["# Oracle results (generated)", "",
             "Generated by `build_oracle.py summary` at %s from `manifest.json`. Do not edit;"
             " re-run the summary stage instead." % time.strftime("%Y-%m-%d %H:%M:%S")]

    def Out(Text):
        Log(Text)
        Lines.extend(Text.split("\n"))

    Out("\n| export | PDB | IDA funcs | exported | named | sub_* | pseudocode | sqlite bytes | sqlite sha256 (first 16) | analysis s | export s |")
    Out("|---|---|---|---|---|---|---|---|---|---|---|")
    for Id, Meta in Manifest["exports"].items():
        Stats = Meta.get("export_stats", {})
        Out("| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |" % (
            Id, Meta.get("pdb_mode"), Meta.get("ida_function_names", {}).get("total"),
            Stats.get("functions"), Stats.get("functions_named"), Stats.get("functions_sub"),
            Stats.get("functions_with_pseudocode"), Meta.get("sqlite_size"),
            (Meta.get("sqlite_sha256") or "")[:16], Meta.get("analysis_seconds"),
            Meta.get("export_seconds")))
    Out("\n| export | input sha256 | sqlite sha256 | IDA | Hex-Rays | Diaphora VERSION_VALUE | IDA args | pdb_proof sub/export/other |")
    Out("|---|---|---|---|---|---|---|---|")
    for Id, Meta in Manifest["exports"].items():
        Proof = Meta.get("pdb_proof")
        Out("| %s | %s | %s | %s | %s | %s | %s | %s |" % (
            Id, Meta.get("input_sha256"), Meta.get("sqlite_sha256"),
            ".".join(str(Part) for Part in Meta.get("idalib_version", [])), Meta.get("hexrays_version"),
            Meta.get("diaphora_version_value"), Meta.get("ida_args") or "-",
            "%d/%d/%d" % (Proof["sub"], Proof["export"], Proof["other"]) if Proof else "n/a"))
    Out("\n| pair | run | wall s | Final results | results rows by type | timeouts |")
    Out("|---|---|---|---|---|---|")
    for Id, Entry in Manifest["diffs"].items():
        for Run in Entry["runs"]:
            Out("| %s | %d | %s | %s | %s | %s |" % (
                Id, Run["run"], Run["wall_seconds"], Run["final_results"],
                Run.get("results_by_type"), Run.get("timeouts_logged")))
    # Diaphora's tester expectations (tester/samples/<id>.cfg) next to ours.
    for Spec in EXPORTS:
        Cfg = os.path.join(Args.samples_dir, Spec["id"] + ".cfg")
        Meta = Manifest["exports"].get(Spec["id"])
        if Spec["pdb"] != "n/a" or not os.path.isfile(Cfg) or not Meta:
            continue
        Expected = TesterExpectations(Args, Spec["id"] + ".cfg").get("Export", {})
        Ours = Meta.get("export_stats", {}).get("tester_export_query", {})
        Out("\n| %s.cfg [Export] key | tester .cfg | this oracle | delta |" % Spec["id"])
        Out("|---|---|---|---|")
        for Key in Ours:
            Want = Expected.get(Key)
            Got = Ours[Key]
            if Want is None:
                Delta = "n/a"
            else:
                try:
                    Delta = "%+d" % (int(Got) - int(Want))
                except (TypeError, ValueError):
                    Delta = "same" if str(Got) == str(Want) else "differs"
            Out("| %s | %s | %s | %s |" % (Key, Want if Want is not None else "(not in cfg)", Got, Delta))
    for Id, Entry in Manifest["diffs"].items():
        Expected = Entry.get("tester_expected", {}).get("Diff")
        if not Expected or not Entry["runs"]:
            continue
        Counts = Entry["runs"][0].get("results_by_type", {})
        Out("\n| %s [Diff] (%s) | tester .cfg | this oracle (results table, run1) |" % (Id, Expected.get("output")))
        Out("|---|---|---|")
        for Key, Type in (("best", "best"), ("partial", "partial"),
                          ("unreliable", "unreliable"), ("multimatches", "multimatch")):
            Out("| %s | %s | %s |" % (Key, Expected.get(Key), Counts.get(Type, 0)))
    # Which heuristics produced the stored rows (run1), per category.
    for Pair in DIFFS:
        Path = os.path.join(Args.root, "diffs", Pair["id"], "run1", Pair["id"] + ".diaphora")
        if not os.path.isfile(Path):
            continue
        Handle = sqlite3.connect(Path)
        try:
            Rows = Handle.execute("select type, description, count(*) from results group by 1, 2 "
                                  "order by 1, 3 desc, 2").fetchall()
        finally:
            Handle.close()
        Out("\n| %s: type | description | rows |" % Pair["id"])
        Out("|---|---|---|")
        for Type, Description, Count in Rows:
            Out("| %s | %s | %d |" % (Type, Description, Count))
    Out("\n| pair | deterministic | identical in stored order | only run1 | only run2 | changed |")
    Out("|---|---|---|---|---|---|")
    for Id, Entry in Manifest["diffs"].items():
        D = Entry.get("determinism")
        if D:
            Out("| %s | %s | %s | %s | %s | %s |" % (
                Id, D["deterministic"], D["results_identical_in_order"],
                D["pairs_only_in_run1"], D["pairs_only_in_run2"], D["pairs_changed"]))
    Pending = [Id for Id, Entry in Manifest["diffs"].items()
               if len(Entry["runs"]) < 2 or not all(Run.get("final_results") for Run in Entry["runs"])]
    Out("\nPairs without two finished runs at generation time: %s" % (", ".join(Pending) or "none"))
    with open(os.path.join(Args.root, "ORACLE-results.md"), "w", encoding="utf-8") as Handle:
        Handle.write("\n".join(Lines) + "\n")
    Log("[summary] %s" % os.path.join(Args.root, "ORACLE-results.md"))
    return 0


def ParseArgs():
    Parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    Parser.add_argument("stage", choices=["exports", "validate", "diffs", "summary", "all"])
    Parser.add_argument("--root", required=True, help="oracle output directory (outside any repo)")
    Parser.add_argument("--diaphora-dir", required=True, help="unmodified Diaphora checkout")
    Parser.add_argument("--ida-dir", default=os.environ.get("IDADIR"), help="IDA install dir (idalib)")
    Parser.add_argument("--bin-dir", default=None, help="prepare_corpus.py output (default <root>/bin)")
    Parser.add_argument("--samples-dir", default=None,
                        help="Diaphora tester samples (default <diaphora-dir>/tester/samples)")
    Parser.add_argument("--python", default=sys.executable, help="Python that can import idapro")
    Parser.add_argument("--diff-python", default=sys.executable, help="Python used to run diaphora.py")
    Parser.add_argument("--jobs", type=int, default=4, help="parallel processes")
    Parser.add_argument("--runs", type=int, default=2, help="diff runs per pair (determinism check)")
    Parser.add_argument("--only", nargs="*", default=None, help="restrict to these export/pair ids")
    Args = Parser.parse_args()
    Args.root = os.path.abspath(Args.root)
    Args.diaphora_dir = os.path.abspath(Args.diaphora_dir)
    Args.bin_dir = os.path.abspath(Args.bin_dir or os.path.join(Args.root, "bin"))
    Args.samples_dir = os.path.abspath(Args.samples_dir or os.path.join(Args.diaphora_dir, "tester", "samples"))
    if Args.stage in ("exports", "validate", "all") and not Args.ida_dir:
        Parser.error("--ida-dir (or IDADIR) is required for the exports and validate stages")
    return Args


def Main():
    Args = ParseArgs()
    Code = 0
    if Args.stage in ("exports", "all"):
        Code = StageExports(Args)
        if Code:
            return Code
    if Args.stage in ("validate", "all"):
        Code = StageValidate(Args)
    if Args.stage in ("diffs", "all"):
        Code = StageDiffs(Args)
    if Args.stage in ("summary", "all"):
        StageSummary(Args)
    return Code


if __name__ == "__main__":
    sys.exit(Main())
