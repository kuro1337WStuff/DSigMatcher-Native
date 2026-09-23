"""Shared helpers for tools/e2e (plan §7.1 D6/D8, §7.2 L11).

Every path comes from a flag or the environment (plan §7.1 D9); nothing here names a personal path.

| Flag            | Environment         | Meaning                                                     |
|-----------------|---------------------|-------------------------------------------------------------|
| --corpus        | DSIG_CORPUS_ROOT    | corpus root; the oracle is <corpus>/oracle                  |
| --diaphora-dir  | DSIG_DIAPHORA_DIR   | the unmodified Diaphora checkout (run on COPIES only)       |
| --python        | DSIG_PYTHON         | the Python that runs diaphora.py (default: this Python)     |
| --dsigmatcher   | DSIG_EXE            | the dsigmatcher executable (default: <repo>/build/...)      |

Reports go to <corpus>/e2e-reports/<timestamp>-<kind>/ unless --out is given; they are never
committed (they hold names extracted from the corpus).
"""

import datetime
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)

import pdb_aliases  # noqa: E402

PORT_SUMMARY_KEYS = ["results rows", "selected", "names applied", "names confirmed", "skipped existing",
                     "skipped hop cap", "skipped ratio", "skipped no symbol", "skipped conflict", "skipped duplicate",
                     "hop", "lineage", "output sha256"]


class E2eError(RuntimeError):
    pass


def Log(Text):
    print("[%s] %s" % (time.strftime("%H:%M:%S"), Text), flush=True)


def CorpusRoot(Arg):
    Root = Arg or os.environ.get("DSIG_CORPUS_ROOT")
    if not Root or not os.path.isdir(os.path.join(Root, "oracle")):
        raise E2eError("no corpus: pass --corpus or set DSIG_CORPUS_ROOT (a directory holding oracle/)")
    return os.path.abspath(Root)


def DiaphoraDir(Arg):
    Directory = Arg or os.environ.get("DSIG_DIAPHORA_DIR")
    if not Directory or not os.path.isfile(os.path.join(Directory, "diaphora.py")):
        raise E2eError("no Diaphora checkout: pass --diaphora-dir or set DSIG_DIAPHORA_DIR")
    return os.path.abspath(Directory)


def PythonExe(Arg):
    return Arg or os.environ.get("DSIG_PYTHON") or sys.executable


def Dsigmatcher(Arg):
    Candidates = [Arg, os.environ.get("DSIG_EXE")]
    for Build in ("build", os.path.join("build", "Release"), os.path.join("build", "RelWithDebInfo")):
        for Name in ("dsigmatcher.exe", "dsigmatcher"):
            Candidates.append(os.path.join(REPO, Build, Name))
    for Candidate in Candidates:
        if Candidate and os.path.isfile(Candidate):
            return os.path.abspath(Candidate)
    raise E2eError("no dsigmatcher executable: pass --dsigmatcher or set DSIG_EXE (or build into <repo>/build)")


def ExportPath(Corpus, Id):
    return os.path.join(Corpus, "oracle", "exports", Id, Id + ".sqlite")


def OracleResults(Corpus, Pair, Run=1):
    return os.path.join(Corpus, "oracle", "diffs", Pair, "run%d" % Run, Pair + ".diaphora")


def Manifest(Corpus):
    Path = os.path.join(Corpus, "oracle", "manifest.json")
    try:
        with open(Path, "r", encoding="utf-8") as Handle:
            return json.load(Handle)
    except (OSError, ValueError):
        return {}


def PairSides(Corpus, Pair):
    Entry = Manifest(Corpus).get("diffs", {}).get(Pair, {})
    if Entry.get("ref") and Entry.get("target"):
        return Entry["ref"], Entry["target"]
    # <ref>_vs_<target>, where the target may drop the ref's leading "<name>-" (userenv-9168-pdb_vs_9278-pdb)
    Ref, _, Target = Pair.partition("_vs_")
    if not os.path.isfile(ExportPath(Corpus, Target)):
        Target = Ref.split("-", 1)[0] + "-" + Target
    return Ref, Target


def BuildOf(ExportId):
    """'win32u-9444-nopdb' -> 'win32u-9444'; None when the id carries no build number."""
    for Suffix in ("-nopdb", "-pdb", "-useri64"):
        if ExportId.endswith(Suffix):
            Base = ExportId[: -len(Suffix)]
            Name, _, Version = Base.rpartition("-")
            return Base if Name and Version.isdigit() else None
    return None


def TruthFor(Corpus, TargetId):
    """(truth path, kind) for a target export: the O1 ground-truth TSV, else a -pdb export of the same
    build, else the target's own names ('self', e.g. the ELF ls sample, which has symbols)."""
    Tsv = os.path.join(Corpus, "oracle", "ground_truth", TargetId + ".tsv")
    if os.path.isfile(Tsv):
        return Tsv, "tsv"
    Build = BuildOf(TargetId)
    if Build and os.path.isfile(ExportPath(Corpus, Build + "-pdb")):
        return ExportPath(Corpus, Build + "-pdb"), "pdb-export"
    return ExportPath(Corpus, TargetId), "self"


def AliasesFor(Corpus, TargetId):
    Build = BuildOf(TargetId)
    if not Build:
        return None
    Cached = pdb_aliases.CachePath(Corpus, Build)
    if os.name != "nt":
        return Cached if os.path.isfile(Cached) else None
    return pdb_aliases.EnsureAliases(Corpus, Build, Log=Log)


def Sha256(Path):
    Digest = hashlib.sha256()
    with open(Path, "rb") as Handle:
        for Block in iter(lambda: Handle.read(1 << 20), b""):
            Digest.update(Block)
    return Digest.hexdigest()


def ReportDir(Corpus, Kind, Out=None):
    Directory = Out or os.path.join(Corpus, "e2e-reports",
                                    datetime.datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + Kind)
    os.makedirs(Directory, exist_ok=True)
    return os.path.abspath(Directory)


def CleanEnv():
    """build_oracle.CleanEnv(): the caller's environment minus DIAPHORA_*, with PYTHONDONTWRITEBYTECODE=1."""
    Env = {Key: Value for Key, Value in os.environ.items() if not Key.upper().startswith("DIAPHORA_")}
    Env["PYTHONDONTWRITEBYTECODE"] = "1"
    return Env


def RunLogged(Command, LogPath, Cwd=None, Env=None):
    Started = time.monotonic()
    with open(LogPath, "w", encoding="utf-8", errors="replace") as Handle:
        Handle.write("$ %s\n" % subprocess.list2cmdline(Command))
        Handle.flush()
        Code = subprocess.call(Command, cwd=Cwd, env=Env, stdout=Handle, stderr=subprocess.STDOUT)
    return Code, round(time.monotonic() - Started, 3)


def ReadText(Path):
    with open(Path, "r", encoding="utf-8", errors="replace") as Handle:
        return Handle.read()


def CopyExport(Source, Destination):
    """Main file plus a -wal that holds frames; stale sidecars at the destination are removed first."""
    for Suffix in ("", "-wal", "-shm", "-journal"):
        if os.path.exists(Destination + Suffix):
            os.remove(Destination + Suffix)
    shutil.copyfile(Source, Destination)
    if os.path.isfile(Source + "-wal") and os.path.getsize(Source + "-wal") > 0:
        shutil.copyfile(Source + "-wal", Destination + "-wal")


def Port(Exe, Ref, Target, Out, Results, Extra, LogPath):
    """Runs `dsigmatcher port --results`; returns {"exit_code", "wall_seconds", "summary": {key: value}}."""
    Command = [Exe, "port", Ref, Target, "-o", Out, "--results", Results] + list(Extra or [])
    Code, Wall = RunLogged(Command, LogPath)
    Summary = {}
    for Line in ReadText(LogPath).splitlines():
        Key, Separator, Value = Line.partition(":")
        if Separator and Key.strip() in PORT_SUMMARY_KEYS:
            Summary[Key.strip()] = Value.strip()
    return {"command": Command, "exit_code": Code, "wall_seconds": Wall, "summary": Summary, "log": LogPath}


def ResultsCounts(Path):
    Db = sqlite3.connect("file:%s?mode=ro" % os.path.abspath(Path).replace("\\", "/").replace("?", "%3f"), uri=True)
    try:
        Counts = dict(Db.execute("select type, count(*) from results group by type").fetchall())
        Unmatched = dict(Db.execute("select type, count(*) from unmatched group by type").fetchall())
    finally:
        Db.close()
    return {"results": Counts, "unmatched": Unmatched}


def ResultsRows(Path):
    Db = sqlite3.connect("file:%s?mode=ro" % os.path.abspath(Path).replace("\\", "/").replace("?", "%3f"), uri=True)
    try:
        Results = Db.execute("select * from results order by rowid").fetchall()
        Unmatched = Db.execute("select * from unmatched order by rowid").fetchall()
    finally:
        Db.close()
    return Results, Unmatched


def Provenance(Path):
    Db = sqlite3.connect("file:%s?mode=ro&immutable=1" % os.path.abspath(Path).replace("\\", "/").replace("?", "%3f"),
                         uri=True)
    try:
        Hops = [dict(zip(("hop", "source_path", "matches", "names_applied", "lineage"), Row)) for Row in Db.execute(
            "select hop, source_path, matches, names_applied, lineage from dsig_provenance order by hop")]
        Histogram = dict(Db.execute("select hops, count(*) from dsig_name_origin group by hops").fetchall())
        Confidence = Db.execute("select min(cumulative_ratio), avg(cumulative_ratio) from dsig_name_origin").fetchone()
    finally:
        Db.close()
    return {"hops": Hops, "name_origin_hops_histogram": Histogram,
            "confidence_min": Confidence[0], "confidence_avg": Confidence[1]}


def WriteJson(Path, Data):
    with open(Path, "w", encoding="utf-8", newline="\n") as Handle:
        json.dump(Data, Handle, indent=2)
        Handle.write("\n")


def WriteText(Path, Text):
    with open(Path, "w", encoding="utf-8", newline="\n") as Handle:
        Handle.write(Text)


def GitState(Directory):
    """`git describe` and `git status --porcelain` of a checkout (the Diaphora reference must stay clean)."""
    def Git(*Arguments):
        try:
            return subprocess.run(["git", "-C", Directory] + list(Arguments), capture_output=True, text=True,
                                  timeout=60).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            return None
    return {"describe": Git("describe", "--tags", "--always"), "status": Git("status", "--porcelain")}
