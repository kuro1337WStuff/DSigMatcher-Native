#!/usr/bin/env python3

"""Extend the Diaphora parity oracle with new builds, pairs and ground truth.

This adds to what build_oracle.py built; it never rebuilds or re-diffs anything
that build_oracle.py owns. build_oracle.py and diaphora_export.py are imported
or invoked unchanged (detached oracle jobs still run from them).

Stages:

  prepare     copy the new builds into <root>/bin/<name>_<version>/: win32u from
              --win32u-dir, cryptbase from WinSxS (selected by the file version
              resource, i.e. FileVersionRaw). PDBs are copied or fetched from the
              Microsoft symbol server by RSDS GUID (tools/prepare_corpus.py), and
              every PDB's own GUID and DBI age are checked against the PE
              (pdb_info.py). New entries are appended to bin/corpus_manifest.txt.
  exports     export the new builds with build_oracle.RunExport (and so with
              diaphora_export.py). The user's IDA database is exported from a
              COPY; its sha256 is recorded before and after and must not change.
  truth       ground-truth TSVs (address -> PDB name) for every -nopdb export,
              from the -pdb export of the same build (ground_truth.py).
  diffs       start the new reference diffs DETACHED (run1 and run2 per pair) in
              a worker that outlives this process, plus the manifest keeper.
  status      progress of every oracle pair (base and extension).
  summary     build_oracle's summary over base + extension exports and pairs,
              plus the extension section of manifest.json and ORACLE-results.md.
  keeper      start the detached keeper: the base tooling's own summary (run by
              the long detached jobs when they finish) rewrites manifest.json
              without the extension; the keeper puts it back.
  user-i64    print the user's database sha256 and compare it with the value
              recorded before the export.
  all         prepare, exports, truth, diffs, summary.

Internal (started detached by `diffs` / `keeper`): run-diffs, keeper-loop.

Everything is written under --root (outside any repository):

  <root>/bin/<label>/                       new source builds + PDBs
  <root>/exports/<id>/                      as build_oracle.py
  <root>/diffs/<pair>/run{1,2}/             as build_oracle.py
  <root>/diffs/<pair>/input_hashes.json     export sha256 before/after that pair
  <root>/ground_truth/<nopdb id>.tsv|.json  ground truth
  <root>/extension/                         prepare.json, user_i64.json, launch
                                            records, worker and keeper logs

Example (paths are placeholders):

  python -B tools/oracle/oracle_extend.py all --root <corpus>/oracle \
      --diaphora-dir <diaphora checkout> --ida-dir "<IDA 9.x install>" \
      --win32u-dir <corpus>/win32u --expect-user-i64-sha256 <sha256>
  python -B tools/oracle/oracle_extend.py status --root <corpus>/oracle
"""

import argparse
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import time
import types
from concurrent.futures import ThreadPoolExecutor, as_completed

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, TOOLS)

import build_oracle  # noqa: E402  (unchanged base tooling)
import ground_truth  # noqa: E402
import pdb_info  # noqa: E402

EXTENSION_MARKER = "## Extension (oracle_extend.py)"

# ----------------------------------------------------------------------------- specs

# Source builds added by the extension. "win32u" builds are copied from
# --win32u-dir (DLL + PDB already there); "winsxs" builds are selected in
# WinSxS by their version resource and their PDB is fetched by RSDS GUID.
# Labels follow tools/prepare_corpus.py Label(): <base>_<version without dots>.
EXT_BUILDS = [
    {"label": "win32u_100261009168", "kind": "win32u", "dir": "win32u_100261009168",
     "file": "win32u.dll", "version": "10.0.26100.9168"},
    {"label": "win32u_100261009444", "kind": "win32u", "dir": "win32u_100261009444",
     "file": "win32u.dll", "version": "10.0.26100.9444"},
    {"label": "cryptbase_100261001", "kind": "winsxs",
     "component": "amd64_microsoft-windows-cryptbase_31bf3856ad364e35_",
     "file": "cryptbase.dll", "version": "10.0.26100.1"},
    {"label": "cryptbase_100261008875", "kind": "winsxs",
     "component": "amd64_microsoft-windows-cryptbase_31bf3856ad364e35_",
     "file": "cryptbase.dll", "version": "10.0.26100.8875"},
    {"label": "cryptbase_100261009444", "kind": "winsxs",
     "component": "amd64_microsoft-windows-cryptbase_31bf3856ad364e35_",
     "file": "cryptbase.dll", "version": "10.0.26100.9444"},
]

# New exports. Same spec shape as build_oracle.EXPORTS ("pdb": None = without a
# PDB, a template = with that PDB). "kind": "user-i64" is an export of a COPY of
# the user's own IDA database, not a fresh analysis.
EXT_EXPORTS = [
    {"id": "win32u-9168-useri64", "kind": "user-i64", "source": "{user_i64}",
     "binary": "{bin}/win32u_100261009168/win32u.dll", "pdb": None},
    {"id": "win32u-9444-nopdb", "source": "{bin}/win32u_100261009444/win32u.dll", "pdb": None},
    {"id": "win32u-9444-pdb", "source": "{bin}/win32u_100261009444/win32u.dll",
     "pdb": "{bin}/win32u_100261009444/win32u.pdb"},
    {"id": "cryptbase-1-nopdb", "source": "{bin}/cryptbase_100261001/cryptbase.dll", "pdb": None},
    {"id": "cryptbase-1-pdb", "source": "{bin}/cryptbase_100261001/cryptbase.dll",
     "pdb": "{bin}/cryptbase_100261001/cryptbase.pdb"},
    {"id": "cryptbase-8875-nopdb", "source": "{bin}/cryptbase_100261008875/cryptbase.dll", "pdb": None},
    {"id": "cryptbase-8875-pdb", "source": "{bin}/cryptbase_100261008875/cryptbase.dll",
     "pdb": "{bin}/cryptbase_100261008875/cryptbase.pdb"},
    {"id": "cryptbase-9444-nopdb", "source": "{bin}/cryptbase_100261009444/cryptbase.dll", "pdb": None},
    {"id": "cryptbase-9444-pdb", "source": "{bin}/cryptbase_100261009444/cryptbase.dll",
     "pdb": "{bin}/cryptbase_100261009444/cryptbase.pdb"},
    # Ground truth for the base export sechost-9444-nopdb needs a with-PDB export
    # of the same build; the base oracle has none.
    {"id": "sechost-9444-pdb", "source": "{bin}/sechost_100261009444/sechost.dll",
     "pdb": "{bin}/sechost_100261009444/sechost.pdb"},
]

# ref = older build (Diaphora's db1, "main"), target = newer build (db2, "diff").
EXT_DIFFS = [
    {"id": "win32u-9168-useri64_vs_9444-nopdb", "ref": "win32u-9168-useri64", "target": "win32u-9444-nopdb"},
    {"id": "cryptbase-1-pdb_vs_8875-nopdb", "ref": "cryptbase-1-pdb", "target": "cryptbase-8875-nopdb"},
    {"id": "cryptbase-8875-pdb_vs_9444-nopdb", "ref": "cryptbase-8875-pdb", "target": "cryptbase-9444-nopdb"},
]

BASE_EXPORT_IDS = frozenset(Spec["id"] for Spec in build_oracle.EXPORTS)
BASE_PAIR_IDS = frozenset(Pair["id"] for Pair in build_oracle.DIFFS)
EXT_EXPORT_IDS = frozenset(Spec["id"] for Spec in EXT_EXPORTS)
EXT_PAIR_IDS = frozenset(Pair["id"] for Pair in EXT_DIFFS)
assert not (BASE_EXPORT_IDS & EXT_EXPORT_IDS), "extension export ids collide with base ids"
assert not (BASE_PAIR_IDS & EXT_PAIR_IDS), "extension pair ids collide with base ids"


def AllExportIds():
    return [Spec["id"] for Spec in build_oracle.EXPORTS if Spec["id"] in BASE_EXPORT_IDS] + \
           [Spec["id"] for Spec in EXT_EXPORTS]


def TruthPairs(ExportIds=None):
    """(nopdb id, pdb id) for every -nopdb export: the -pdb export of the same build."""
    Ids = list(ExportIds or AllExportIds())
    Pairs = []
    for Id in Ids:
        if Id.endswith("-nopdb"):
            Pairs.append((Id, Id[:-len("-nopdb")] + "-pdb"))
    return Pairs


def InstallExtensionSpecs():
    """Make build_oracle's own summary/manifest code see the extension (idempotent)."""
    Known = {Spec["id"] for Spec in build_oracle.EXPORTS}
    for Spec in EXT_EXPORTS:
        if Spec["id"] not in Known:
            build_oracle.EXPORTS.append(Spec)
    Known = {Pair["id"] for Pair in build_oracle.DIFFS}
    for Pair in EXT_DIFFS:
        if Pair["id"] not in Known:
            build_oracle.DIFFS.append(Pair)


# ----------------------------------------------------------------------------- helpers

Log = build_oracle.Log
Sha256OfFile = build_oracle.Sha256OfFile
ReadJson = build_oracle.ReadJson


def WriteJson(Path, Data):
    """Atomic JSON write (a reader never sees a half-written file)."""
    os.makedirs(os.path.dirname(Path), exist_ok=True)
    Temp = "%s.%d.tmp" % (Path, os.getpid())
    with open(Temp, "w", encoding="utf-8") as Handle:
        json.dump(Data, Handle, indent=2, default=str)
    os.replace(Temp, Path)


def ReadJsonOr(Path, Default=None):
    try:
        return ReadJson(Path)
    except (OSError, ValueError):
        return Default


def ExtDir(Args):
    return os.path.join(Args.root, "extension")


def ExportDir(Args, Id):
    return os.path.join(Args.root, "exports", Id)


def ExportSqlite(Args, Id):
    return os.path.join(ExportDir(Args, Id), Id + ".sqlite")


def ExportMeta(Args, Id):
    return ReadJsonOr(os.path.join(ExportDir(Args, Id), Id + ".export.json"))


def ExpandExt(Template, Args):
    Values = {"bin": Args.bin_dir, "samples": Args.samples_dir, "user_i64": Args.user_i64 or ""}
    return os.path.abspath(Template.format(**Values))


def BaseArgs(Args):
    """The argument namespace build_oracle's stage functions read."""
    return types.SimpleNamespace(
        root=Args.root, diaphora_dir=Args.diaphora_dir, ida_dir=Args.ida_dir,
        bin_dir=Args.bin_dir, samples_dir=Args.samples_dir, python=Args.python,
        diff_python=Args.diff_python, jobs=Args.jobs, runs=Args.runs, only=None)


def RedirectOutput(LogPath):
    """Detached workers have no console: send stdout/stderr to their log file."""
    if not LogPath:
        return
    os.makedirs(os.path.dirname(os.path.abspath(LogPath)), exist_ok=True)
    Handle = open(LogPath, "a", encoding="utf-8", errors="replace", buffering=1)
    sys.stdout = Handle
    sys.stderr = Handle


def Now():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def FileVersion(Path):
    """The fixed file version (VS_FIXEDFILEINFO, what PowerShell calls FileVersionRaw)."""
    import pefile
    Pe = pefile.PE(Path, fast_load=True)
    try:
        Pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
        Fixed = getattr(Pe, "VS_FIXEDFILEINFO", None)
        if not Fixed:
            return None
        Ms, Ls = Fixed[0].FileVersionMS, Fixed[0].FileVersionLS
        return "%d.%d.%d.%d" % (Ms >> 16, Ms & 0xFFFF, Ls >> 16, Ls & 0xFFFF)
    finally:
        Pe.close()


def ProcessesMatching(Needle):
    """[(pid, cmdline)] of live processes whose command line contains Needle (needs psutil)."""
    try:
        import psutil
    except ImportError:
        return None
    Needle = Needle.lower()
    Found = []
    for Proc in psutil.process_iter(["pid", "cmdline"]):
        try:
            Line = " ".join(Proc.info["cmdline"] or [])
        except Exception:
            continue
        if Needle in Line.lower():
            Found.append((Proc.info["pid"], Line))
    return Found


def PidAlive(Pid):
    try:
        import psutil
        return psutil.pid_exists(int(Pid))
    except ImportError:
        return None


def LaunchDetached(Command, Cwd):
    """Start Command so that it outlives this process and the shell that ran it.

    On Windows the process is created through WMI (Win32_Process.Create), so its
    parent is the WMI provider host and it is outside any job object of the
    caller; this is how the base oracle's long diffs were started. The command
    line travels in an environment variable, so no quoting is involved.
    Elsewhere it is a new session. The child writes its own log (--log)."""
    if os.name == "nt":
        Env = dict(os.environ)
        Env["DSIG_LAUNCH_CMD"] = subprocess.list2cmdline(Command)
        Env["DSIG_LAUNCH_CWD"] = Cwd
        Script = ("$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments "
                  "@{CommandLine=$env:DSIG_LAUNCH_CMD; CurrentDirectory=$env:DSIG_LAUNCH_CWD}; "
                  "Write-Output ('{0} {1}' -f $r.ReturnValue, $r.ProcessId)")
        Out = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", Script],
                             env=Env, capture_output=True, text=True)
        Parts = Out.stdout.split()
        if Out.returncode != 0 or len(Parts) != 2 or Parts[0] != "0":
            raise RuntimeError("Win32_Process.Create failed: rc=%s out=%r err=%r"
                               % (Out.returncode, Out.stdout, Out.stderr))
        return int(Parts[1])
    Proc = subprocess.Popen(Command, cwd=Cwd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, start_new_session=True)
    return Proc.pid


# Everything a detached worker or keeper can import, relative to tools/.
SNAPSHOT_FILES = ["oracle/oracle_extend.py", "oracle/build_oracle.py", "oracle/ground_truth.py",
                  "oracle/pdb_info.py", "oracle/pdb_proof.py", "oracle/diaphora_export.py",
                  "oracle/compare_exports.py", "prepare_corpus.py"]
_Snapshot = {}


def LaunchScript(Args):
    """oracle_extend.py inside a snapshot of the tools under <root>/extension/tools/<stamp>/.

    Detached jobs run for hours or days. Running them from a copy means a later
    edit, merge or removal of the repository checkout cannot change or break them
    (the base oracle's long jobs depend on the checkout they were started from)."""
    if "script" in _Snapshot:
        return _Snapshot["script"], _Snapshot["files"]
    Base = os.path.join(ExtDir(Args), "tools", time.strftime("%Y%m%d-%H%M%S"))
    Files = {}
    for Relative in SNAPSHOT_FILES:
        Source = os.path.join(TOOLS, *Relative.split("/"))
        Destination = os.path.join(Base, *Relative.split("/"))
        os.makedirs(os.path.dirname(Destination), exist_ok=True)
        shutil.copyfile(Source, Destination)
        Files[Relative] = Sha256OfFile(Destination)
    _Snapshot.update(script=os.path.join(Base, "oracle", "oracle_extend.py"), files=Files)
    return _Snapshot["script"], Files


class Guard(Exception):
    pass


def GuardExport(Args, Id):
    if Id in BASE_EXPORT_IDS:
        raise Guard("%s is a base export owned by build_oracle.py; the extension never rebuilds it" % Id)
    if Id not in EXT_EXPORT_IDS:
        raise Guard("%s is not an extension export" % Id)
    if os.path.exists(ExportDir(Args, Id)) and not Args.force:
        raise Guard("%s already exists (%s); pass --force to rebuild it" % (Id, ExportDir(Args, Id)))


def GuardPair(Args, PairId):
    if PairId in BASE_PAIR_IDS:
        raise Guard("%s is a base pair: re-running its diffs would delete its run directory" % PairId)
    if PairId not in EXT_PAIR_IDS:
        raise Guard("%s is not an extension pair" % PairId)
    PairDir = os.path.join(Args.root, "diffs", PairId)
    if os.path.exists(PairDir):
        if not Args.force:
            raise Guard("%s already has a diff directory (%s); pass --force to discard it" % (PairId, PairDir))
        Live = ProcessesMatching(PairDir)
        if Live:
            raise Guard("%s still has live processes: %s" % (PairId, [Pid for Pid, _ in Live]))


# ----------------------------------------------------------------------------- prepare

def FindWinSxs(Args, Spec):
    Pattern = os.path.join(Args.winsxs_dir, Spec["component"] + "*", Spec["file"])
    Candidates = []
    for Path in sorted(glob.glob(Pattern)):
        Version = FileVersion(Path)
        if Version == Spec["version"]:
            Candidates.append(Path)
    if not Candidates:
        raise RuntimeError("no %s with file version %s under %s" % (Spec["file"], Spec["version"], Pattern))
    Digests = {Sha256OfFile(Path) for Path in Candidates}
    if len(Digests) != 1:
        raise RuntimeError("%s %s: %d different files carry that version: %s"
                           % (Spec["file"], Spec["version"], len(Digests), Candidates))
    return Candidates[0]


def CopyChecked(Source, Destination, Args):
    Digest = Sha256OfFile(Source)
    if os.path.isfile(Destination):
        if Sha256OfFile(Destination) == Digest:
            return Digest, "already present"
        if not Args.force:
            raise Guard("%s exists with different content; pass --force to replace it" % Destination)
    shutil.copyfile(Source, Destination)
    if Sha256OfFile(Destination) != Digest:
        raise RuntimeError("copy of %s is not identical" % Source)
    return Digest, "copied"


def PrepareOne(Spec, Args):
    import prepare_corpus
    Target = os.path.join(Args.bin_dir, Spec["label"])
    os.makedirs(Target, exist_ok=True)
    if Spec["kind"] == "winsxs":
        Source = FindWinSxs(Args, Spec)
        if prepare_corpus.Label(Source) != Spec["label"]:
            raise RuntimeError("label mismatch: %s vs %s" % (prepare_corpus.Label(Source), Spec["label"]))
    else:
        Source = os.path.join(Args.win32u_dir, Spec["dir"], Spec["file"])
    Version = FileVersion(Source)
    if Version != Spec["version"]:
        raise RuntimeError("%s has file version %s, expected %s" % (Source, Version, Spec["version"]))
    Binary = os.path.join(Target, Spec["file"])
    BinaryDigest, BinaryAction = CopyChecked(Source, Binary, Args)

    CodeView = prepare_corpus.ReadCodeView(Binary)
    if CodeView is None:
        raise RuntimeError("%s has no RSDS record" % Binary)
    Pdb = os.path.join(Target, CodeView["pdb_name"])
    Url = prepare_corpus.SymbolUrl(CodeView)
    LocalPdb = os.path.join(os.path.dirname(Source), CodeView["pdb_name"])
    if Spec["kind"] == "win32u" and os.path.isfile(LocalPdb):
        PdbAction = CopyChecked(LocalPdb, Pdb, Args)[1] + " from " + LocalPdb
    elif os.path.isfile(Pdb) and pdb_info.MatchPe(Pdb, Binary).get("match"):
        PdbAction = "already present"
    else:
        Ok, Detail = prepare_corpus.Fetch(Url, Pdb)
        if not Ok:
            raise RuntimeError("PDB download failed for %s: %s" % (Url, Detail))
        PdbAction = "fetched (%s)" % Detail
    Identity = pdb_info.MatchPe(Pdb, Binary)
    if not Identity.get("match"):
        raise RuntimeError("%s does not belong to %s: %s" % (Pdb, Binary, Identity))
    Entry = {
        "label": Spec["label"], "kind": Spec["kind"], "source": Source, "file_version": Version,
        "binary": os.path.relpath(Binary, Args.bin_dir), "binary_sha256": BinaryDigest,
        "binary_size": os.path.getsize(Binary), "binary_action": BinaryAction,
        "pdb": os.path.relpath(Pdb, Args.bin_dir), "pdb_sha256": Sha256OfFile(Pdb),
        "pdb_url": Url, "pdb_guid": CodeView["guid"], "pdb_age": CodeView["age"],
        "pdb_action": PdbAction, "pdb_identity": Identity,
    }
    Log("[prepare] %s: %s %s (%s), pdb %s, GUID/age match %s" % (
        Spec["label"], Spec["file"], Version, BinaryAction, PdbAction, Identity["match"]))
    return Entry


def AppendCorpusManifest(Args, Entries):
    """Add new labels to bin/corpus_manifest.txt in prepare_corpus.py's format; never rewrite old ones."""
    Path = os.path.join(Args.bin_dir, "corpus_manifest.txt")
    Existing = ""
    if os.path.isfile(Path):
        with open(Path, "r", encoding="utf-8") as Handle:
            Existing = Handle.read()
    Present = set(re.findall(r"^label:\s+(\S+)\s*$", Existing, re.M))
    New = [Entry for Entry in Entries if Entry["label"] not in Present]
    if not New:
        return []
    with open(Path, "a", encoding="utf-8") as Handle:
        if Existing and not Existing.endswith("\n\n"):
            Handle.write("\n" if Existing.endswith("\n") else "\n\n")
        for Entry in New:
            Record = {Key: Entry[Key] for Key in ("label", "binary", "binary_sha256", "pdb", "pdb_sha256",
                                                  "pdb_url", "pdb_guid", "pdb_age")}
            for Key in sorted(Record):
                Handle.write("%-16s %s\n" % (Key + ":", Record[Key]))
            Handle.write("\n")
    return [Entry["label"] for Entry in New]


def StagePrepare(Args):
    Entries = [PrepareOne(Spec, Args) for Spec in EXT_BUILDS]
    Added = AppendCorpusManifest(Args, Entries)
    WriteJson(os.path.join(ExtDir(Args), "prepare.json"), {"generated": Now(), "builds": Entries,
                                                            "corpus_manifest_added": Added})
    Log("[prepare] corpus_manifest.txt: added %s" % (Added or "nothing (all present)"))
    return 0


# ----------------------------------------------------------------------------- exports

PDB_TOTAL_RE = re.compile(r"^PDB: total (\d+) symbols loaded", re.M)


def PdbLogEvidence(LogPath):
    """What IDA's console said about PDB loading during the export run."""
    if not os.path.isfile(LogPath):
        return {"log": None}
    with open(LogPath, "r", encoding="utf-8", errors="replace") as Handle:
        Text = Handle.read()
    Lines = [Line for Line in Text.splitlines() if Line.startswith("PDB:")]
    Totals = [int(Match) for Match in PDB_TOTAL_RE.findall(Text)]
    return {"pdb_log_lines": len(Lines), "pdb_symbols_loaded": Totals[-1] if Totals else None,
            "pdb_log_first_lines": Lines[:6]}


def AugmentMeta(Spec, Args, Meta, Extra):
    Id = Spec["id"]
    MetaPath = os.path.join(ExportDir(Args, Id), Id + ".export.json")
    Meta = dict(Meta or ReadJsonOr(MetaPath, {}))
    Meta["pdb_log"] = PdbLogEvidence(os.path.join(ExportDir(Args, Id), "export.log"))
    Meta["extension"] = {"tool": "tools/oracle/oracle_extend.py", "at": Now()}
    Meta.update(Extra)
    build_oracle.WriteJson(MetaPath, Meta)
    return Meta


def RunUserI64Export(Spec, Args):
    """Export a COPY of the user's hand-saved IDA database.

    The original is only ever read (sha256 before, one copy, sha256 after). IDA
    opens the copy without auto-analysis (diaphora_export.py treats .i64/.idb
    inputs as databases), with the PDB plugin off and an empty symbol path, and
    does not save it (--no-save), so every name comes from the user's database."""
    Original = ExpandExt(Spec["source"], Args)
    Binary = ExpandExt(Spec["binary"], Args)
    Id = Spec["id"]
    Record = {"path": Original, "size": os.path.getsize(Original),
              "mtime_before": os.path.getmtime(Original), "sha256_before": Sha256OfFile(Original),
              "checked_before_at": Now()}
    if Args.expect_user_i64_sha256 and Record["sha256_before"] != Args.expect_user_i64_sha256.lower():
        raise Guard("the user's database sha256 %s differs from --expect-user-i64-sha256 %s"
                    % (Record["sha256_before"], Args.expect_user_i64_sha256))
    WorkDir = ExportDir(Args, Id)
    if os.path.isdir(WorkDir):
        shutil.rmtree(WorkDir)
    os.makedirs(WorkDir)
    Copy = os.path.join(WorkDir, os.path.basename(Original))
    shutil.copyfile(Original, Copy)
    Record["copy"] = Copy
    Record["copy_sha256"] = Sha256OfFile(Copy)
    if Record["copy_sha256"] != Record["sha256_before"]:
        raise RuntimeError("the copy of the user's database is not identical")

    Env = build_oracle.CleanEnv()
    Env["IDADIR"] = Args.ida_dir
    Env["IDAUSR"] = os.path.join(Args.root, "idausr")
    Env["_NT_SYMBOL_PATH"] = os.path.join(Args.root, "nosymbols")
    Env.pop("_NT_ALT_SYMBOL_PATH", None)
    os.makedirs(Env["IDAUSR"], exist_ok=True)
    os.makedirs(Env["_NT_SYMBOL_PATH"], exist_ok=True)
    OutSqlite = ExportSqlite(Args, Id)
    MetaPath = os.path.join(WorkDir, Id + ".export.json")
    Command = [Args.python, os.path.join(HERE, "diaphora_export.py"), "--input", Copy, "--out", OutSqlite,
               "--diaphora-dir", Args.diaphora_dir, "--meta", MetaPath, "--ida-args=-Opdb:off", "--no-save"]
    Log("[export] %s: start (copy of the user's database)" % Id)
    Started = time.monotonic()
    with open(os.path.join(WorkDir, "export.log"), "w", encoding="utf-8", errors="replace") as Handle:
        Code = subprocess.call(Command, cwd=WorkDir, env=Env, stdout=Handle, stderr=subprocess.STDOUT)
    Wall = round(time.monotonic() - Started, 3)

    Record["sha256_after"] = Sha256OfFile(Original)
    Record["mtime_after"] = os.path.getmtime(Original)
    Record["checked_after_at"] = Now()
    Record["unchanged"] = (Record["sha256_after"] == Record["sha256_before"]
                           and Record["mtime_after"] == Record["mtime_before"])
    Record["copy_sha256_after_export"] = Sha256OfFile(Copy)
    WriteJson(os.path.join(ExtDir(Args), "user_i64.json"), Record)
    if not Record["unchanged"]:
        raise RuntimeError("THE USER'S DATABASE CHANGED: %s" % Record)

    Meta = ReadJsonOr(MetaPath, {})
    if Code == 0:
        import pdb_proof
        Proof = pdb_proof.Classify(OutSqlite, Binary)
        build_oracle.WriteJson(os.path.join(WorkDir, "pdb_proof.json"), Proof)
        Proof["other_names"] = Proof["other_names"][:25]
        Meta["pdb_proof"] = Proof
    Meta.update({
        "id": Id, "source": Original, "pdb_mode": "user-i64", "pdb_source": None,
        "pe_binary_for_proof": Binary, "command": Command, "exit_code": Code, "wall_seconds": Wall,
        "user_i64": Record,
    })
    Meta = AugmentMeta(Spec, Args, Meta, {})
    Log("[export] %s: exit %d in %.1fs; user database unchanged=%s" % (Id, Code, Wall, Record["unchanged"]))
    return Meta


def RunOneExport(Spec, Args):
    try:
        if Spec.get("kind") == "user-i64":
            return RunUserI64Export(Spec, Args)
        Meta = build_oracle.RunExport(Spec, BaseArgs(Args))
        Extra = {}
        if Spec["pdb"]:
            Pdb = ExpandExt(Spec["pdb"], Args)
            Extra["pdb_identity"] = pdb_info.MatchPe(Pdb, ExpandExt(Spec["source"], Args))
        return AugmentMeta(Spec, Args, Meta, Extra)
    except Exception as Exc:
        Log("[export] %s: FAILED: %s" % (Spec["id"], Exc))
        return {"id": Spec["id"], "exit_code": -1, "error": str(Exc)}


def StageExports(Args):
    Selected = [Spec for Spec in EXT_EXPORTS if not Args.only or Spec["id"] in Args.only]
    for Spec in Selected:
        GuardExport(Args, Spec["id"])
        if not os.path.isfile(ExpandExt(Spec["source"], Args)):
            raise Guard("%s: source %s is missing (run the prepare stage)" % (Spec["id"], Spec["source"]))
    Results = {}
    with ThreadPoolExecutor(max_workers=Args.jobs) as Pool:
        Futures = {Pool.submit(RunOneExport, Spec, Args): Spec["id"] for Spec in Selected}
        for Future in as_completed(Futures):
            Results[Futures[Future]] = Future.result()
    Failed = sorted(Id for Id, Meta in Results.items() if Meta.get("exit_code") != 0)
    Log("[export] done: %d ok, failed: %s" % (len(Results) - len(Failed), Failed or "none"))
    return 1 if Failed else 0


# ----------------------------------------------------------------------------- truth

def StageTruth(Args):
    OutDir = os.path.join(Args.root, "ground_truth")
    os.makedirs(OutDir, exist_ok=True)
    Code = 0
    for NoPdb, Pdb in TruthPairs():
        if Args.only and NoPdb not in Args.only:
            continue
        Paths = (ExportSqlite(Args, Pdb), ExportSqlite(Args, NoPdb))
        if not all(os.path.isfile(Path) for Path in Paths):
            Log("[truth] %s: MISSING export(s) %s" % (NoPdb, [P for P in Paths if not os.path.isfile(P)]))
            Code = 1
            continue
        Info = ground_truth.Generate(Paths[0], Paths[1], os.path.join(OutDir, NoPdb + ".tsv"),
                                     os.path.join(OutDir, NoPdb + ".json"),
                                     {"nopdb_id": NoPdb, "pdb_id": Pdb})
        Counts = Info["status_counts"]
        Log("[truth] %s <- %s: %d rows (both %d, pdb_only %d, nopdb_only %d; same name %d)" % (
            NoPdb, Pdb, Info["rows"], Counts["both"], Counts["pdb_only"], Counts["nopdb_only"],
            Info["both_with_identical_name"]))
    return Code


# ----------------------------------------------------------------------------- diffs

def StageDiffs(Args):
    """Start the extension pairs' reference diffs in a detached worker."""
    Selected = [Pair for Pair in EXT_DIFFS if not Args.only or Pair["id"] in Args.only]
    for Pair in Selected:
        GuardPair(Args, Pair["id"])
        for Side in ("ref", "target"):
            Meta = ExportMeta(Args, Pair[Side])
            if not Meta or Meta.get("exit_code") != 0 or not os.path.isfile(ExportSqlite(Args, Pair[Side])):
                raise Guard("%s: export %s is missing or failed" % (Pair["id"], Pair[Side]))
    LogPath = os.path.join(ExtDir(Args), "run-diffs.log")
    Script, Files = LaunchScript(Args)
    Command = [sys.executable, "-B", Script, "run-diffs", "--root", Args.root,
               "--diaphora-dir", Args.diaphora_dir, "--diff-python", Args.diff_python,
               "--jobs", str(len(Selected) * Args.runs), "--runs", str(Args.runs), "--log", LogPath,
               "--only"] + [Pair["id"] for Pair in Selected]
    if Args.ida_dir:
        Command += ["--ida-dir", Args.ida_dir]
    if Args.force:
        Command += ["--force"]
    Pid = LaunchDetached(Command, Args.root)
    Record = {"started": Now(), "pid": Pid, "command": Command, "log": LogPath, "tools_snapshot": Files,
              "pairs": [Pair["id"] for Pair in Selected], "runs": Args.runs,
              "status_check": "python -B tools/oracle/oracle_extend.py status --root <root>"}
    WriteJson(os.path.join(ExtDir(Args), "launch-diffs.json"), Record)
    Log("[diffs] detached worker pid %d for %s; log %s" % (Pid, Record["pairs"], LogPath))
    if not Args.no_keeper:
        StageKeeper(Args)
    return 0


def StageRunDiffs(Args):
    """The detached worker: run1..runN of every selected pair, then compare and summarise."""
    RedirectOutput(Args.log)
    Log("[run-diffs] %s pid %d: %s" % (Now(), os.getpid(), Args.only))
    Selected = [Pair for Pair in EXT_DIFFS if not Args.only or Pair["id"] in Args.only]
    if not Args.force:
        for Pair in Selected:
            if os.path.exists(os.path.join(Args.root, "diffs", Pair["id"])):
                Log("[run-diffs] REFUSED: %s already has a diff directory" % Pair["id"])
                return 2
    BArgs = BaseArgs(Args)

    def Inputs(Pair):
        return {Pair[Side]: ExportSqlite(Args, Pair[Side]) for Side in ("ref", "target")}

    Before = {Pair["id"]: {Id: Sha256OfFile(Path) for Id, Path in Inputs(Pair).items()} for Pair in Selected}
    Jobs = [(Pair, Run) for Run in range(1, Args.runs + 1) for Pair in Selected]
    Pending = {Pair["id"]: Args.runs for Pair in Selected}
    with ThreadPoolExecutor(max_workers=Args.jobs) as Pool:
        Futures = {Pool.submit(build_oracle.RunDiff, Pair, Run, BArgs): Pair for Pair, Run in Jobs}
        for Future in as_completed(Futures):
            Pair = Futures[Future]
            try:
                Future.result()
            except Exception as Exc:
                Log("[run-diffs] %s: a run raised %r" % (Pair["id"], Exc))
            Pending[Pair["id"]] -= 1
            if Pending[Pair["id"]]:
                continue
            # Both runs of this pair are done: determinism, input integrity, summary.
            try:
                if Args.runs >= 2:
                    build_oracle.CompareRuns(Pair, BArgs)
            except Exception as Exc:
                Log("[run-diffs] %s: CompareRuns failed: %r" % (Pair["id"], Exc))
            After = {Id: Sha256OfFile(Path) for Id, Path in Inputs(Pair).items()}
            Changed = sorted(Id for Id in After if After[Id] != Before[Pair["id"]][Id])
            WriteJson(os.path.join(Args.root, "diffs", Pair["id"], "input_hashes.json"),
                      {"before": Before[Pair["id"]], "after": After, "changed": Changed})
            Log("[run-diffs] %s: finished; export databases modified by diffing: %s"
                % (Pair["id"], Changed or "none"))
            try:
                StageSummary(Args)
            except Exception as Exc:
                Log("[run-diffs] summary failed: %r" % (Exc,))
    Log("[run-diffs] %s all done" % Now())
    return 0


# ----------------------------------------------------------------------------- status

def RunState(Args, PairId, Run):
    RunDir = os.path.join(Args.root, "diffs", PairId, "run%d" % Run)
    RunJson = os.path.join(RunDir, "run.json")
    LogPath = os.path.join(RunDir, "diaphora.log")
    if os.path.isfile(RunJson):
        Info = ReadJsonOr(RunJson, {})
        State = "FINISHED" if Info.get("exit_code") == 0 and Info.get("final_results") else "FAILED"
        return {"state": State, "exit_code": Info.get("exit_code"), "wall_seconds": Info.get("wall_seconds"),
                "final_results": Info.get("final_results"), "results_by_type": Info.get("results_by_type"),
                "timeouts_logged": Info.get("timeouts_logged")}
    if not os.path.isfile(LogPath):
        return {"state": "NOT STARTED"}
    Current = Heuristic = Last = None
    Checkpoints = 0
    BatchesSinceHeuristic = 0
    with open(LogPath, "r", encoding="utf-8", errors="replace") as Handle:
        for Line in Handle:
            Line = Line.rstrip("\n")
            if not Line.strip():
                continue
            Last = Line
            if "Current results" in Line:
                Current = Line
                Checkpoints += 1
            elif "Finding with heuristic" in Line:
                Heuristic = Line
                BatchesSinceHeuristic = 0
            elif "Processed 50000 rows" in Line:
                # Diaphora logs every 50,000 rows of one query (D:1899-1900), so the
                # first such line of each query counts the big queries of this heuristic.
                BatchesSinceHeuristic += 1
    Live = ProcessesMatching(os.path.join(RunDir, ""))
    State = "RUNNING" if Live else ("UNKNOWN (psutil missing)" if Live is None else "DEAD (no run.json, no process)")
    return {"state": State, "pids": [Pid for Pid, _ in (Live or [])],
            "log_age_seconds": round(time.time() - os.path.getmtime(LogPath)),
            "current_results_checkpoints": Checkpoints,
            "last_current_results": Current[-200:] if Current else None,
            "last_heuristic_line": Heuristic[-200:] if Heuristic else None,
            "queries_over_50k_rows_since_heuristic_start": BatchesSinceHeuristic,
            "last_line": Last[-200:] if Last else None}


def PairState(Args, PairId):
    Runs = {"run%d" % Run: RunState(Args, PairId, Run) for Run in (1, 2)}
    Det = ReadJsonOr(os.path.join(Args.root, "diffs", PairId, "determinism.json"))
    Hashes = ReadJsonOr(os.path.join(Args.root, "diffs", PairId, "input_hashes.json"))
    return {"runs": Runs,
            "determinism": None if not Det else {Key: Det[Key] for Key in Det if not Key.startswith("pairs_")},
            "inputs_changed": None if not Hashes else Hashes.get("changed")}


def StageStatus(Args):
    Report = {"generated": Now(), "pairs": {}}
    for PairId in [Pair["id"] for Pair in build_oracle.DIFFS if Pair["id"] in BASE_PAIR_IDS] + \
                  [Pair["id"] for Pair in EXT_DIFFS]:
        State = PairState(Args, PairId)
        Report["pairs"][PairId] = State
        Tag = "ext " if PairId in EXT_PAIR_IDS else "base"
        print("%s %s" % (Tag, PairId))
        for Run, Info in State["runs"].items():
            if Info["state"] in ("FINISHED", "FAILED"):
                print("    %s %s exit=%s wall=%ss %s" % (Run, Info["state"], Info["exit_code"],
                                                        Info["wall_seconds"], Info["final_results"]))
            elif Info["state"] == "NOT STARTED":
                print("    %s NOT STARTED" % Run)
            else:
                print("    %s %s pids=%s log-age=%ss" % (Run, Info["state"], Info.get("pids"),
                                                        Info.get("log_age_seconds")))
                for Key in ("last_current_results", "last_heuristic_line"):
                    if Info.get(Key):
                        print("        %s" % Info[Key])
                print("        checkpoints=%d, queries of >=50k rows since that heuristic started: %d" % (
                    Info["current_results_checkpoints"], Info["queries_over_50k_rows_since_heuristic_start"]))
        if State["determinism"]:
            D = State["determinism"]
            print("    determinism: deterministic=%s in-order=%s" % (D.get("deterministic"),
                                                                    D.get("results_identical_in_order")))
        if State["inputs_changed"] is not None:
            print("    export databases modified by diffing: %s" % (State["inputs_changed"] or "none"))
    for Name in ("launch-diffs", "launch-keeper"):
        Launch = ReadJsonOr(os.path.join(ExtDir(Args), Name + ".json"))
        if Launch:
            Alive = PidAlive(Launch["pid"])
            Report[Name] = {"pid": Launch["pid"], "alive": Alive, "log": Launch.get("log")}
            print("%s: pid %s alive=%s log=%s" % (Name, Launch["pid"], Alive, Launch.get("log")))
    User = ReadJsonOr(os.path.join(ExtDir(Args), "user_i64.json"))
    if User:
        print("user .i64: sha256 before %s after %s unchanged=%s" % (
            User.get("sha256_before"), User.get("sha256_after"), User.get("unchanged")))
    if Args.json:
        WriteJson(os.path.abspath(Args.json), Report)
    return 0


# ----------------------------------------------------------------------------- summary

def PdbVerdict(Meta):
    Mode = Meta.get("pdb_mode")
    Log_ = Meta.get("pdb_log") or {}
    Lines = Log_.get("pdb_log_lines")
    Loaded = Log_.get("pdb_symbols_loaded")
    Netnode = (Meta.get("pdb_evidence") or {}).get("pdb_netnode_exists")
    IdaNames = Meta.get("ida_function_names") or {}
    Args_ = Meta.get("ida_args") or ""
    Identity = (Meta.get("pdb_identity") or {}).get("match")
    if Mode == "with":
        Ok = bool(Lines) and bool(Loaded) and Netnode is True and Identity is not False
        return "PDB applied" if Ok else "CHECK: with-PDB evidence incomplete"
    if Mode == "without":
        Ok = Lines == 0 and Netnode is False and "-Opdb:off" in Args_
        return "no PDB" if Ok else "CHECK: no-PDB evidence incomplete"
    if Mode == "user-i64":
        Ok = Lines == 0 and "-Opdb:off" in Args_ and IdaNames.get("sub_prefixed") == 0
        return ("user database names; no PDB loaded by this run" if Ok
                else "CHECK: user-database evidence incomplete")
    return "n/a"


def ProofRecord(Args, Id):
    Meta = ExportMeta(Args, Id)
    if not Meta or Meta.get("pdb_mode") in (None, "n/a"):
        return None
    if "pdb_log" not in Meta:
        # Base exports predate the extension: read their logs now (read-only).
        Meta = dict(Meta)
        Meta["pdb_log"] = PdbLogEvidence(os.path.join(ExportDir(Args, Id), "export.log"))
        if Meta.get("pdb_mode") == "with" and "pdb_identity" not in Meta:
            # The PDB copy and the binary copy IDA analysed sit in the export directory.
            Pdb = os.path.join(ExportDir(Args, Id), os.path.basename(Meta.get("pdb_source") or ""))
            Binary = os.path.join(ExportDir(Args, Id), os.path.basename(Meta.get("source") or ""))
            if os.path.isfile(Pdb) and os.path.isfile(Binary):
                try:
                    Meta["pdb_identity"] = pdb_info.MatchPe(Pdb, Binary)
                except Exception as Exc:
                    Meta["pdb_identity"] = {"match": False, "error": str(Exc)}
    Proof = Meta.get("pdb_proof") or {}
    return {
        "pdb_mode": Meta.get("pdb_mode"),
        "ida_args": Meta.get("ida_args"),
        "nt_symbol_path": (Meta.get("env") or {}).get("_NT_SYMBOL_PATH"),
        "pdb_log_lines": Meta["pdb_log"].get("pdb_log_lines"),
        "pdb_symbols_loaded": Meta["pdb_log"].get("pdb_symbols_loaded"),
        "pdb_netnode_exists": (Meta.get("pdb_evidence") or {}).get("pdb_netnode_exists"),
        "pdb_identity_match": (Meta.get("pdb_identity") or {}).get("match"),
        "pdb_proof": {Key: Proof.get(Key) for Key in ("functions", "sub", "export", "other")},
        "ida_functions": Meta.get("ida_function_names"),
        "exported_functions": (Meta.get("export_stats") or {}).get("functions"),
        "sqlite_sha256": Meta.get("sqlite_sha256"),
        "verdict": PdbVerdict(Meta),
    }


def ExtensionSection(Args):
    Section = {
        "generated": Now(),
        "generator": "tools/oracle/oracle_extend.py",
        "exports": [Spec["id"] for Spec in EXT_EXPORTS],
        "diffs": [Pair["id"] for Pair in EXT_DIFFS],
        "sources": ReadJsonOr(os.path.join(ExtDir(Args), "prepare.json")),
        "user_i64": ReadJsonOr(os.path.join(ExtDir(Args), "user_i64.json")),
        "pdb_proofs": {},
        "ground_truth": {},
        "diff_launch": ReadJsonOr(os.path.join(ExtDir(Args), "launch-diffs.json")),
        "keeper_launch": ReadJsonOr(os.path.join(ExtDir(Args), "launch-keeper.json")),
        "diff_input_hashes": {},
        "status_check": "python -B tools/oracle/oracle_extend.py status --root <root>",
    }
    for Id in AllExportIds():
        Record = ProofRecord(Args, Id)
        if Record:
            Section["pdb_proofs"][Id] = Record
    for NoPdb, Pdb in TruthPairs():
        Info = ReadJsonOr(os.path.join(Args.root, "ground_truth", NoPdb + ".json"))
        if Info:
            Section["ground_truth"][NoPdb] = Info
    for Pair in EXT_DIFFS:
        Hashes = ReadJsonOr(os.path.join(Args.root, "diffs", Pair["id"], "input_hashes.json"))
        if Hashes:
            Section["diff_input_hashes"][Pair["id"]] = Hashes
    return Section


def ExtensionMarkdown(Section):
    Out = ["", EXTENSION_MARKER, "",
           "Written by `oracle_extend.py summary` (the sections above come from build_oracle.py's own"
           " summary code, run over base + extension exports and pairs)."]
    User = Section.get("user_i64")
    if User:
        Out += ["", "User database (exported from a copy): `%s`" % User.get("path"), "",
                "| sha256 before | sha256 after | unchanged | size |", "|---|---|---|---|",
                "| %s | %s | %s | %s |" % (User.get("sha256_before"), User.get("sha256_after"),
                                          User.get("unchanged"), User.get("size"))]
    Sources = (Section.get("sources") or {}).get("builds") or []
    if Sources:
        Out += ["", "| build | file version | source | sha256 | PDB GUID/age | PDB identity match |",
                "|---|---|---|---|---|---|"]
        for Entry in Sources:
            Out.append("| %s | %s | `%s` | %s | %s/%s | %s |" % (
                Entry["label"], Entry["file_version"], Entry["source"], Entry["binary_sha256"],
                Entry["pdb_guid"], Entry["pdb_age"], Entry["pdb_identity"].get("match")))
    Out += ["", "| export | PDB mode | IDA args | `PDB:` log lines | symbols loaded | `$ pdb` netnode |"
            " PDB/PE identity | sub/export/other | IDA funcs (sub_) | verdict |",
            "|---|---|---|---|---|---|---|---|---|---|"]
    for Id, P in Section["pdb_proofs"].items():
        Proof = P["pdb_proof"]
        Ida = P.get("ida_functions") or {}
        Out.append("| %s | %s | %s | %s | %s | %s | %s | %s | %s (%s) | %s |" % (
            Id, P["pdb_mode"], P["ida_args"] or "-", P["pdb_log_lines"], P["pdb_symbols_loaded"],
            P["pdb_netnode_exists"], P["pdb_identity_match"],
            "%s/%s/%s" % (Proof.get("sub"), Proof.get("export"), Proof.get("other")),
            Ida.get("total"), Ida.get("sub_prefixed"), P["verdict"]))
    Out += ["", "| ground truth (no-PDB export) | from | rows | both | pdb_only | nopdb_only |"
            " both, same name | TSV sha256 (first 16) |", "|---|---|---|---|---|---|---|---|"]
    for NoPdb, Info in Section["ground_truth"].items():
        C = Info["status_counts"]
        Out.append("| %s | %s | %d | %d | %d | %d | %d | %s |" % (
            NoPdb, Info.get("pdb_id"), Info["rows"], C["both"], C["pdb_only"], C["nopdb_only"],
            Info["both_with_identical_name"], Info["tsv_sha256"][:16]))
    if Section["diff_input_hashes"]:
        Out += ["", "| extension pair | export databases modified by diffing |", "|---|---|"]
        for PairId, Hashes in Section["diff_input_hashes"].items():
            Out.append("| %s | %s |" % (PairId, ", ".join(Hashes.get("changed") or []) or "none"))
    return Out


class SummaryLock(object):
    """Keep two extension summaries (worker, keeper) from interleaving their writes."""

    def __init__(self, Args, Stale=600):
        self.Path = os.path.join(ExtDir(Args), "summary.lock")
        self.Stale = Stale

    def __enter__(self):
        os.makedirs(os.path.dirname(self.Path), exist_ok=True)
        Deadline = time.time() + 3 * self.Stale
        while True:
            try:
                Fd = os.open(self.Path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.write(Fd, str(os.getpid()).encode())
                os.close(Fd)
                return self
            except FileExistsError:
                try:
                    if time.time() - os.path.getmtime(self.Path) > self.Stale:
                        os.remove(self.Path)
                        continue
                except OSError:
                    continue
                if time.time() > Deadline:
                    raise RuntimeError("summary lock %s is held" % self.Path)
                time.sleep(2)

    def __exit__(self, *Exc):
        try:
            os.remove(self.Path)
        except OSError:
            pass


def StageSummary(Args):
    InstallExtensionSpecs()
    with SummaryLock(Args):
        build_oracle.StageSummary(BaseArgs(Args))
        ManifestPath = os.path.join(Args.root, "manifest.json")
        Manifest = ReadJson(ManifestPath)
        Section = ExtensionSection(Args)
        Manifest["extension"] = Section
        WriteJson(ManifestPath, Manifest)
        ResultsPath = os.path.join(Args.root, "ORACLE-results.md")
        with open(ResultsPath, "r", encoding="utf-8") as Handle:
            Lines = Handle.read().rstrip("\n").split("\n")
        # Keep build_oracle's closing "Pairs without two finished runs ..." line last.
        Closing = Lines.pop() if Lines and Lines[-1].startswith("Pairs without two finished runs") else None
        Lines += ExtensionMarkdown(Section)
        if Closing:
            Lines += ["", Closing]
        Temp = ResultsPath + ".%d.tmp" % os.getpid()
        with open(Temp, "w", encoding="utf-8") as Handle:
            Handle.write("\n".join(Lines) + "\n")
        os.replace(Temp, ResultsPath)
    Log("[summary] manifest.json and ORACLE-results.md now include the extension")
    return 0


# ----------------------------------------------------------------------------- keeper

def ExtensionPresent(Args):
    Manifest = ReadJsonOr(os.path.join(Args.root, "manifest.json"))
    if not Manifest or "extension" not in Manifest:
        return False
    if not EXT_EXPORT_IDS <= set(Manifest.get("exports", {})) or not EXT_PAIR_IDS <= set(Manifest.get("diffs", {})):
        return False
    try:
        with open(os.path.join(Args.root, "ORACLE-results.md"), "r", encoding="utf-8") as Handle:
            return EXTENSION_MARKER in Handle.read()
    except OSError:
        return False


def ManifestStale(Args):
    """True when a pair's run.json / determinism.json / input_hashes.json is newer than manifest.json.

    The base helper that waits for the userenv pair calls build_oracle.StageSummary
    with a namespace that has no ida_dir, so StageManifest raises after
    determinism.json is written and the summary is never refreshed. The keeper
    refreshes it instead."""
    try:
        Reference = os.path.getmtime(os.path.join(Args.root, "manifest.json"))
    except OSError:
        return True
    for PairId in list(BASE_PAIR_IDS) + list(EXT_PAIR_IDS):
        PairDir = os.path.join(Args.root, "diffs", PairId)
        Candidates = [os.path.join(PairDir, Name) for Name in ("determinism.json", "input_hashes.json")]
        Candidates += [os.path.join(PairDir, "run%d" % Run, "run.json") for Run in (1, 2)]
        for Path in Candidates:
            try:
                if os.path.getmtime(Path) > Reference:
                    return True
            except OSError:
                continue
    return False


def AllPairsFinished(Args):
    for PairId in list(BASE_PAIR_IDS) + list(EXT_PAIR_IDS):
        for Run in (1, 2):
            if not os.path.isfile(os.path.join(Args.root, "diffs", PairId, "run%d" % Run, "run.json")):
                return False
    return True


def StageKeeperLoop(Args):
    RedirectOutput(Args.log)
    Log("[keeper] %s pid %d: poll %ds, grace %ds, cap %.1f days" % (
        Now(), os.getpid(), Args.poll, Args.grace, Args.keeper_days))
    Deadline = time.time() + Args.keeper_days * 86400
    while time.time() < Deadline:
        try:
            if not ExtensionPresent(Args):
                Log("[keeper] %s manifest/results lack the extension: regenerating" % Now())
                StageSummary(Args)
            elif ManifestStale(Args):
                Log("[keeper] %s a pair finished after the last summary: regenerating" % Now())
                StageSummary(Args)
            Manifest = os.path.join(Args.root, "manifest.json")
            Quiet = time.time() - os.path.getmtime(Manifest) > Args.grace
            if AllPairsFinished(Args) and Quiet and ExtensionPresent(Args) and not ManifestStale(Args):
                Log("[keeper] %s every pair has two finished runs and the manifest is stable: exit" % Now())
                return 0
        except Exception as Exc:
            Log("[keeper] %s error: %r" % (Now(), Exc))
        time.sleep(Args.poll)
    Log("[keeper] %s cap reached: exit" % Now())
    return 0


def StageKeeper(Args):
    Previous = ReadJsonOr(os.path.join(ExtDir(Args), "launch-keeper.json"))
    if Previous and PidAlive(Previous["pid"]) and ProcessesMatching("keeper-loop"):
        Log("[keeper] already running (pid %s)" % Previous["pid"])
        return 0
    LogPath = os.path.join(ExtDir(Args), "keeper.log")
    Script, Files = LaunchScript(Args)
    Command = [sys.executable, "-B", Script, "keeper-loop", "--root", Args.root,
               "--diaphora-dir", Args.diaphora_dir, "--log", LogPath,
               "--poll", str(Args.poll), "--grace", str(Args.grace), "--keeper-days", str(Args.keeper_days)]
    if Args.ida_dir:
        Command += ["--ida-dir", Args.ida_dir]
    Pid = LaunchDetached(Command, Args.root)
    WriteJson(os.path.join(ExtDir(Args), "launch-keeper.json"),
              {"started": Now(), "pid": Pid, "command": Command, "log": LogPath, "tools_snapshot": Files})
    Log("[keeper] detached keeper pid %d; log %s" % (Pid, LogPath))
    return 0


# ----------------------------------------------------------------------------- user-i64

def StageUserI64(Args):
    Record = ReadJsonOr(os.path.join(ExtDir(Args), "user_i64.json"))
    Path = Args.user_i64 or (Record or {}).get("path")
    if not Path:
        print("no user database path (pass --user-i64 or --win32u-dir)")
        return 2
    Digest = Sha256OfFile(Path)
    print("user database: %s" % Path)
    print("sha256 now:    %s" % Digest)
    if Record:
        print("sha256 before: %s (recorded %s)" % (Record["sha256_before"], Record.get("checked_before_at")))
        print("unchanged:     %s" % (Digest == Record["sha256_before"]))
        return 0 if Digest == Record["sha256_before"] else 1
    return 0


# ----------------------------------------------------------------------------- main

def ParseArgs(Argv=None):
    Parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    Parser.add_argument("stage", choices=["prepare", "exports", "truth", "diffs", "status", "summary",
                                          "keeper", "user-i64", "all", "run-diffs", "keeper-loop"])
    Parser.add_argument("--root", required=True, help="oracle directory (outside any repo)")
    Parser.add_argument("--diaphora-dir", default=None, help="unmodified Diaphora checkout")
    Parser.add_argument("--ida-dir", default=os.environ.get("IDADIR"), help="IDA install dir (idalib)")
    Parser.add_argument("--bin-dir", default=None, help="source builds (default <root>/bin)")
    Parser.add_argument("--samples-dir", default=None, help="default <diaphora-dir>/tester/samples")
    Parser.add_argument("--win32u-dir", default=None,
                        help="directory holding win32u_<version>/ builds (default <root>/../win32u)")
    Parser.add_argument("--user-i64", default=None,
                        help="the user's IDA database (default <win32u-dir>/win32u_100261009168/win32u.dll.i64)")
    Parser.add_argument("--expect-user-i64-sha256", default=None,
                        help="refuse to export unless the user's database has this sha256")
    Parser.add_argument("--winsxs-dir", default=os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "WinSxS"))
    Parser.add_argument("--python", default=sys.executable, help="Python that can import idapro")
    Parser.add_argument("--diff-python", default=sys.executable, help="Python used to run diaphora.py")
    Parser.add_argument("--jobs", type=int, default=4, help="parallel processes")
    Parser.add_argument("--runs", type=int, default=2, help="diff runs per pair (determinism check)")
    Parser.add_argument("--only", nargs="*", default=None, help="restrict to these extension ids")
    Parser.add_argument("--force", action="store_true", help="rebuild extension exports / pairs that exist")
    Parser.add_argument("--no-keeper", action="store_true", help="diffs: do not start the keeper")
    Parser.add_argument("--log", default=None, help="log file (detached stages)")
    Parser.add_argument("--json", default=None, help="status: also write the report here")
    Parser.add_argument("--poll", type=int, default=300, help="keeper poll interval, seconds")
    Parser.add_argument("--grace", type=int, default=1800,
                        help="keeper: seconds the manifest must stay untouched after the last pair finishes")
    Parser.add_argument("--keeper-days", type=float, default=14.0, help="keeper: hard cap")
    Args = Parser.parse_args(Argv)
    Args.root = os.path.abspath(Args.root)
    Args.bin_dir = os.path.abspath(Args.bin_dir or os.path.join(Args.root, "bin"))
    Args.win32u_dir = os.path.abspath(Args.win32u_dir or os.path.join(os.path.dirname(Args.root), "win32u"))
    if Args.user_i64 is None:
        Args.user_i64 = os.path.join(Args.win32u_dir, "win32u_100261009168", "win32u.dll.i64")
    Args.user_i64 = os.path.abspath(Args.user_i64)
    if Args.diaphora_dir:
        Args.diaphora_dir = os.path.abspath(Args.diaphora_dir)
    Args.samples_dir = os.path.abspath(Args.samples_dir or os.path.join(Args.diaphora_dir or "", "tester", "samples"))
    Needs = {"exports": ("diaphora_dir", "ida_dir"), "diffs": ("diaphora_dir",), "run-diffs": ("diaphora_dir",),
             "summary": ("diaphora_dir",), "keeper": ("diaphora_dir",), "keeper-loop": ("diaphora_dir",),
             "all": ("diaphora_dir", "ida_dir")}
    for Name in Needs.get(Args.stage, ()):
        if not getattr(Args, Name):
            Parser.error("--%s is required for the %s stage" % (Name.replace("_", "-"), Args.stage))
    return Args


def Main(Argv=None):
    Args = ParseArgs(Argv)
    Stages = {"prepare": StagePrepare, "exports": StageExports, "truth": StageTruth, "diffs": StageDiffs,
              "status": StageStatus, "summary": StageSummary, "keeper": StageKeeper,
              "user-i64": StageUserI64, "run-diffs": StageRunDiffs, "keeper-loop": StageKeeperLoop}
    try:
        if Args.stage != "all":
            return Stages[Args.stage](Args)
        for Name in ("prepare", "exports", "truth", "diffs", "summary"):
            Code = Stages[Name](Args)
            if Code:
                return Code
        return 0
    except Guard as Exc:
        Log("REFUSED: %s" % Exc)
        return 3


if __name__ == "__main__":
    sys.exit(Main())
