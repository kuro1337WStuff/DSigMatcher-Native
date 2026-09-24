#!/usr/bin/env python3
"""Run `dsigmatcher diff` on every valid oracle pair and compare it with Diaphora.

    python -B run_parity.py [--corpus <root>] [--dsigmatcher <exe>] [--pairs <pair> ...] [--long]
                            [--score] [--run 1] [--out <dir>] [--diaphora-dir <dir>] [--limit 20]
                            [--native-arg=<arg> ...] [--generate-aliases]
    python -B run_parity.py --self-test [--dsigmatcher <exe>]

For every pair of <corpus>/oracle/manifest.json (or --pairs), in manifest order:

1. Oracle status. The compared oracle output is diffs/<pair>/run<N> (run1 by default).
   - PENDING: run<N>/run.json does not exist yet (the detached oracle job is still running). Nothing
     of that run is read.
   - SKIPPED_LONG: a long pair (an oracle run took more than an hour) without --long.
   - ORACLE_INVALID: any of these fails, and the pair is then not compared:
       exit code 0; the output file exists; the log has `Diffing results saved in file` (D:2426);
       the log has no `Timeout with heuristic` and no heuristic ran longer than 300 s (spans from the
       log timestamps, because NO_FPS timeouts are silent, 02 §5.4); both exports' sha256 equal the
       manifest; the `cdifflib` import warning is present (so cdifflib was absent); no DIAPHORA_*
       variable (build_oracle.py runs Diaphora under CleanEnv(); the command line in run.json must be
       exactly `python diaphora.py <db1> <db2> -o <out>`).
   The run<N> vs run<other> determinism.json verdict is reported next to it.
2. Native diff: `dsigmatcher diff <db1> <db2> -o <report>/<pair>/native.diaphora --pair <pair>` with
   the same <db1>/<db2> strings the oracle was given (so config.main_db / diff_db compare too), stdout
   and stderr in native.log, wall time recorded. Both exports are hashed before and after.
3. compare_results.py (L0 from both logs, L1, L2, DDL, per-(type, description) tables, unmatched).
4. --score: `dsigmatcher port <ref> <target> --results <x>` for the native results AND for the
   oracle's results, each scored by tools/e2e/score_ground_truth.py against the PDB ground truth of
   the target build, so the report shows parity (vs Diaphora) and ground truth (vs PDB)
   side by side. Alias lists come from the existing cache under <corpus>/oracle/ground_truth/aliases/
   (--generate-aliases lets pdb_aliases.py build missing ones).

Reports go to <corpus>/parity-reports/<timestamp>/ (or --out, which must be outside the repository):
report.json, report.md, and per pair native.diaphora, native.log, compare.json, compare.md and, with
--score, the ported databases, port logs and score.json / score.md files. They hold names from the
corpus and are never committed.

Exit status: 1 when a compared pair fails L2 (or the native diff fails, or an export changed), 2 on a
usage error, 0 otherwise. PENDING, SKIPPED_LONG and ORACLE_INVALID pairs never fail the run: they are
not native failures.

Paths come from flags or the environment only:
  --corpus        (env DSIG_CORPUS_ROOT)   the corpus root; the oracle is <corpus>/oracle
  --dsigmatcher   (env DSIG_EXE)           the executable (default: <repo>/build/dsigmatcher[.exe])
  --diaphora-dir  (env DSIG_DIAPHORA_DIR)  optional: the Diaphora checkout, to record `git describe`
                                           and that it is clean; only read
"""

import sys

sys.dont_write_bytecode = True

import argparse  # noqa: E402
import datetime  # noqa: E402
import hashlib  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import re  # noqa: E402
import sqlite3  # noqa: E402
import subprocess  # noqa: E402
import time  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
E2E = os.path.join(REPO, "tools", "e2e")
for Directory in (HERE, E2E):
    if Directory not in sys.path:
        sys.path.insert(0, Directory)

import compare_results as Compare  # noqa: E402

HEURISTIC_TIMEOUT_SECONDS = 300    # C:92 SQL_TIMEOUT_LIMIT
LONG_PAIR_SECONDS = 3600           # an oracle run longer than this makes a pair "long"
LOG_TIME_RE = re.compile(r"^\[Diaphora: (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),(\d{3})\] ")


class UsageError(RuntimeError):
    pass


def Log(Text):
    print("[%s] %s" % (time.strftime("%H:%M:%S"), Text), flush=True)


# ----------------------------------------------------------------------------- safe reading

def ReadShared(Path):
    """The file's bytes. On Windows the handle also shares DELETE, so a detached job that replaces the
    file (os.replace of manifest.json by the oracle keeper) is never blocked by this read."""
    if os.name != "nt":
        with open(Path, "rb") as Handle:
            return Handle.read()
    import ctypes
    from ctypes import wintypes
    Kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    CreateFileW = Kernel32.CreateFileW
    CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD,
                            wintypes.DWORD, wintypes.HANDLE]
    CreateFileW.restype = wintypes.HANDLE
    ReadFile = Kernel32.ReadFile
    ReadFile.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                         wintypes.LPVOID]
    CloseHandle = Kernel32.CloseHandle
    GenericRead, ShareAll, OpenExisting = 0x80000000, 0x7, 3
    Handle = CreateFileW(os.path.abspath(Path), GenericRead, ShareAll, None, OpenExisting, 0x80, None)
    if Handle in (None, wintypes.HANDLE(-1).value):
        raise OSError(ctypes.get_last_error(), "cannot open", Path)
    try:
        Chunks = []
        Buffer = ctypes.create_string_buffer(1 << 20)
        Got = wintypes.DWORD(0)
        while True:
            if not ReadFile(Handle, Buffer, len(Buffer), ctypes.byref(Got), None):
                raise OSError(ctypes.get_last_error(), "cannot read", Path)
            if Got.value == 0:
                break
            Chunks.append(Buffer.raw[:Got.value])
        return b"".join(Chunks)
    finally:
        CloseHandle(Handle)


def ReadJson(Path):
    try:
        return json.loads(ReadShared(Path).decode("utf-8"))
    except (OSError, ValueError):
        return None


def ReadText(Path):
    try:
        return ReadShared(Path).decode("utf-8", errors="replace")
    except OSError:
        return None


def Sha256(Path):
    Digest = hashlib.sha256()
    with open(Path, "rb") as Handle:
        for Block in iter(lambda: Handle.read(1 << 20), b""):
            Digest.update(Block)
    return Digest.hexdigest()


def WriteJson(Path, Data):
    with open(Path, "w", encoding="utf-8", newline="\n") as Handle:
        json.dump(Data, Handle, indent=1, ensure_ascii=False)
        Handle.write("\n")


def WriteText(Path, Text):
    with open(Path, "w", encoding="utf-8", newline="\n") as Handle:
        Handle.write(Text)


# ----------------------------------------------------------------------------- environment

def CorpusRoot(Arg):
    Root = Arg or os.environ.get("DSIG_CORPUS_ROOT")
    if not Root or not os.path.isfile(os.path.join(Root, "oracle", "manifest.json")):
        raise UsageError("no oracle: pass --corpus or set DSIG_CORPUS_ROOT (a directory holding oracle/manifest.json)")
    return os.path.abspath(Root)


def Executable(Arg):
    Candidates = [Arg, os.environ.get("DSIG_EXE")]
    for Build in ("build", os.path.join("build", "Release"), os.path.join("build", "RelWithDebInfo")):
        for Name in ("dsigmatcher.exe", "dsigmatcher"):
            Candidates.append(os.path.join(REPO, Build, Name))
    for Candidate in Candidates:
        if Candidate and os.path.isfile(Candidate):
            return os.path.abspath(Candidate)
    raise UsageError("no dsigmatcher executable: pass --dsigmatcher or set DSIG_EXE")


def Inside(Path, Directory):
    Path, Directory = os.path.normcase(os.path.abspath(Path)), os.path.normcase(os.path.abspath(Directory))
    return Path == Directory or Path.startswith(Directory.rstrip("\\/") + os.sep)


def CleanEnv():
    """build_oracle.CleanEnv() semantics: no DIAPHORA_* variable, PYTHONDONTWRITEBYTECODE=1."""
    Env = {Key: Value for Key, Value in os.environ.items() if not Key.upper().startswith("DIAPHORA_")}
    Env["PYTHONDONTWRITEBYTECODE"] = "1"
    return Env


def Git(Directory, *Arguments):
    try:
        return subprocess.run(["git", "--no-optional-locks", "-C", Directory] + list(Arguments),
                              capture_output=True, text=True, timeout=120).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None


# ----------------------------------------------------------------------------- oracle validity

def ParseLogTime(Line):
    Match = LOG_TIME_RE.match(Line)
    if not Match:
        return None
    return datetime.datetime.strptime(Match.group(1), "%Y-%m-%d %H:%M:%S").timestamp() + int(Match.group(2)) / 1000.0


def HeuristicSpans(LogText):
    """Wall time of every SQL heuristic thread from the log (02 §5.4). run_heuristics_for_category
    logs every `<mode> Finding with heuristic '<name>'` line first (D:1510), then threads_apply runs the
    heuristics one at a time (cpu_count 1, D:489-491) and logs `[Parallel] Heuristic '<name>' done` as
    each ends (jkutils/threads.py:52-54). A heuristic therefore runs from the previous `done` line (or
    the category's last `Finding with` line) to its own `done` line."""
    Spans = []
    Previous = None
    for Line in LogText.splitlines():
        Stamp = ParseLogTime(Line)
        if Stamp is None:
            continue
        if "] Finding with heuristic '" in Line and ("[Single thread]" in Line or "[Parallel]" in Line):
            Previous = Stamp
        elif "[Parallel] Heuristic '" in Line and Line.rstrip().endswith("' done"):
            Name = Line.split("[Parallel] Heuristic '", 1)[1].rsplit("' done", 1)[0]
            if Previous is not None:
                Spans.append({"heuristic": Name, "seconds": round(Stamp - Previous, 3)})
            Previous = Stamp
    return Spans


def OracleStatus(Corpus, Manifest, Pair, Run, AllowLong):
    """(status, details): PENDING, SKIPPED_LONG, ORACLE_INVALID or VALID."""
    Oracle = os.path.join(Corpus, "oracle")
    Entry = Manifest.get("diffs", {}).get(Pair, {})
    Ref, Target = Entry.get("ref"), Entry.get("target")
    RunDir = os.path.join(Oracle, "diffs", Pair, "run%d" % Run)
    Output = os.path.join(RunDir, Pair + ".diaphora")
    Details = {"ref": Ref, "target": Target, "run_dir": RunDir, "output": Output}
    if not Ref or not Target:
        return "ORACLE_INVALID", dict(Details, reasons=["pair not in the manifest"])
    RunJsonPath = os.path.join(RunDir, "run.json")
    if not os.path.isfile(RunJsonPath):
        # build_oracle writes run.json when Diaphora exits: the run is still going (or never started).
        return "PENDING", dict(Details, reasons=["run%d/run.json does not exist yet" % Run])
    RunInfo = ReadJson(RunJsonPath) or {}
    Walls = [R.get("wall_seconds") or 0 for R in Entry.get("runs", [])] + [RunInfo.get("wall_seconds") or 0]
    Details["oracle_wall_seconds"] = RunInfo.get("wall_seconds")
    Details["long"] = max(Walls) > LONG_PAIR_SECONDS
    if Details["long"] and not AllowLong:
        return "SKIPPED_LONG", dict(Details, reasons=["oracle run took %.0f s; pass --long" % max(Walls)])

    Checks = {}
    Checks["exit_code_0"] = RunInfo.get("exit_code") == 0
    Checks["output_exists"] = os.path.isfile(Output)
    LogText = ReadText(os.path.join(RunDir, "diaphora.log")) or ""
    Checks["saved_line"] = "Diffing results saved in file" in LogText
    Checks["no_timeout_logged"] = "Timeout with heuristic" not in LogText
    Spans = HeuristicSpans(LogText)
    Long = [S for S in Spans if S["seconds"] > HEURISTIC_TIMEOUT_SECONDS]
    Checks["no_heuristic_over_300s"] = not Long
    Details["longest_heuristic"] = max(Spans, key=lambda S: S["seconds"]) if Spans else None
    Details["heuristics_over_300s"] = Long
    Checks["cdifflib_absent"] = "Python library 'cdifflib' not found" in LogText
    Command = RunInfo.get("command") or []
    Exports = Manifest.get("exports", {})
    RefPath = os.path.join(Oracle, "exports", Ref, Ref + ".sqlite")
    TargetPath = os.path.join(Oracle, "exports", Target, Target + ".sqlite")
    # build_oracle.py RunDiff: [python, "diaphora.py", db1, db2, "-o", out] under CleanEnv() (no DIAPHORA_*).
    Checks["default_command_no_diaphora_env"] = (
        len(Command) == 6 and os.path.basename(Command[1]) == "diaphora.py" and Command[4] == "-o" and
        os.path.normcase(os.path.abspath(Command[2])) == os.path.normcase(os.path.abspath(RefPath)) and
        os.path.normcase(os.path.abspath(Command[3])) == os.path.normcase(os.path.abspath(TargetPath)))
    Hashes = {}
    for Id, Path in ((Ref, RefPath), (Target, TargetPath)):
        Expected = Exports.get(Id, {}).get("sqlite_sha256")
        Actual = Sha256(Path) if os.path.isfile(Path) else None
        Hashes[Id] = {"path": Path, "manifest": Expected, "before": Actual}
    Checks["inputs_match_manifest"] = all(H["manifest"] and H["manifest"] == H["before"] for H in Hashes.values())
    Details.update(checks=Checks, inputs=Hashes, db1_arg=Command[2] if len(Command) > 3 else RefPath,
                   db2_arg=Command[3] if len(Command) > 3 else TargetPath, final_results=RunInfo.get("final_results"),
                   oracle_log=os.path.join(RunDir, "diaphora.log"))
    Determinism = ReadJson(os.path.join(Oracle, "diffs", Pair, "determinism.json"))
    Details["determinism"] = None if Determinism is None else {
        Key: Determinism.get(Key) for Key in ("deterministic", "results_identical_in_order",
                                              "unmatched_identical_in_order")}
    Failed = [Key for Key, Ok in Checks.items() if not Ok]
    if Failed:
        return "ORACLE_INVALID", dict(Details, reasons=Failed)
    return "VALID", dict(Details, reasons=[])


# ----------------------------------------------------------------------------- per pair

def RunNative(Exe, Db1, Db2, Out, LogPath, Pair, Extra):
    for Suffix in ("", "-journal"):
        if os.path.exists(Out + Suffix):
            os.remove(Out + Suffix)
    Command = [Exe, "diff", Db1, Db2, "-o", Out, "--pair", Pair] + list(Extra or [])
    Started = time.monotonic()
    with open(LogPath, "w", encoding="utf-8", errors="replace", newline="\n") as Handle:
        Handle.write("$ %s\n" % subprocess.list2cmdline(Command))
        Handle.flush()
        Code = subprocess.call(Command, env=CleanEnv(), stdout=Handle, stderr=subprocess.STDOUT)
    Wall = round(time.monotonic() - Started, 3)
    Text = ReadText(LogPath) or ""
    Skipped = [Line.split(":", 1)[0][len("SKIPPED "):] for Line in Text.splitlines() if Line.startswith("SKIPPED ")]
    Sqlite = re.search(r"SQLite (\d+\.\d+\.\d+)", Text)
    return {"command": Command, "exit_code": Code, "wall_seconds": Wall, "log": LogPath,
            "skipped_stages": Skipped, "sqlite_warning": Sqlite.group(0) if Sqlite else None}


def ScoreBoth(Exe, Corpus, Pair, Ref, Target, Results, PairDir, GenerateAliases):
    """Port + ground-truth score of the native and the oracle results (tools/e2e)."""
    import e2e_common as E
    import score_ground_truth
    RefPath, TargetPath = E.ExportPath(Corpus, Ref), E.ExportPath(Corpus, Target)
    TruthPath, TruthKind = E.TruthFor(Corpus, Target)
    Aliases = E.AliasesFor(Corpus, Target) if GenerateAliases else None  # None: the cached list, if any
    Out = {"truth": TruthPath, "truth_kind": TruthKind}
    for Side, ResultsFile in (("native", Results["native"]), ("oracle", Results["oracle"])):
        Ported = os.path.join(PairDir, "%s-ported.sqlite" % Side)
        for Suffix in ("", "-wal", "-shm", "-journal"):
            if os.path.exists(Ported + Suffix):
                os.remove(Ported + Suffix)
        Before = {Path: Sha256(Path) for Path in (RefPath, TargetPath, ResultsFile)}
        Port = E.Port(Exe, RefPath, TargetPath, Ported, ResultsFile, [], os.path.join(PairDir, "%s-port.log" % Side))
        After = {Path: Sha256(Path) for Path in (RefPath, TargetPath, ResultsFile)}
        Entry = {"port_exit_code": Port["exit_code"], "port_summary": Port["summary"],
                 "inputs_unchanged": Before == After}
        if Port["exit_code"] == 0:
            Score = score_ground_truth.Score(Ported, TruthPath, Aliases)
            WriteJson(os.path.join(PairDir, "%s-score.json" % Side), Score)
            WriteText(os.path.join(PairDir, "%s-score.md" % Side),
                      score_ground_truth.Markdown(Score, "%s: %s results (truth: %s)" % (Pair, Side, TruthKind)))
            Entry.update(label=Score["label"], match_by_category=Score["match_by_category"],
                         truth_only=Score["truth_only"], ported_only=Score["ported_only"],
                         aliases=Score["aliases"], summary=score_ground_truth.Summary(Score))
        Out[Side] = Entry
    return Out


# ----------------------------------------------------------------------------- report

def Fmt(Value):
    return "n/a" if Value is None else ("yes" if Value is True else ("NO" if Value is False else str(Value)))


def GroundTruthCell(Score):
    if not Score or "label" not in Score:
        return "port failed" if Score else "-"
    Label = Score["label"]
    Parts = ["%d+%d/%d/%d of %d" % (Label["correct"], Label["correct_alias"], Label["wrong"], Label["missing"],
                                    Label["total"])]
    for Category in ("best", "partial", "multimatch"):
        Counts = Score["match_by_category"].get(Category)
        if Counts:
            Parts.append("%s %d/%d" % (Category[0], Counts["correct"] + Counts["correct_alias"], Counts["wrong"]))
    return "; ".join(Parts)


def ReportMarkdown(Report):
    Lines = ["# Parity report %s" % Report["timestamp"], "",
             "- corpus: `%s`" % Report["corpus"], "- dsigmatcher: `%s` (sha256 %s)" % (Report["dsigmatcher"],
                                                                                       Report["dsigmatcher_sha256"][:16]),
             "- Diaphora reference: %s" % (Report["diaphora_reference"] or "not checked (no --diaphora-dir)"),
             "- Python sqlite3 %s; oracle run compared: run%d; long pairs %s; ground truth %s" % (
                 Report["python_sqlite"], Report["run"], "included" if Report["long"] else "skipped",
                 "scored" if Report["score"] else "not scored (--score)"),
             "- verdict: %s" % Report["verdict"], ""]
    Header = ("| pair | status | mode (oracle) | L0 | L1 | L2 | rows oracle / native | unmatched oracle / native | "
              "native s | skipped stages")
    Rule = "|---|---|---|---|---|---|---|---|---:|---:"
    if Report["score"]:
        Header += " | GT native: label ok+alias/wrong/missing; match ok/wrong | GT oracle: same"
        Rule += "|---|---"
    Lines += [Header + " |", Rule + "|"]
    for Pair, Entry in Report["pairs"].items():
        Comparison = Entry.get("compare")
        if not Comparison:
            Row = "| %s | %s (%s) | | | | | | | | " % (Pair, Entry["status"], "; ".join(Entry.get("reasons", [])))
            if Report["score"]:
                Row += "| | "
            Lines.append(Row + "|")
            continue
        V, C = Comparison["verdict"], Comparison["counts"]
        OracleL0 = (Comparison["l0"]["oracle"] or {})
        Row = "| %s | %s | %s | %s | %s | %s | %d / %d | %d / %d | %.2f | %d " % (
            Pair, Entry["status"], OracleL0.get("mode"), Fmt(V["L0"]), Fmt(V["L1"]), Fmt(V["L2"]),
            sum(C["oracle_results"].values()), sum(C["native_results"].values()),
            sum(C["oracle_unmatched"].values()), sum(C["native_unmatched"].values()),
            Entry["native"]["wall_seconds"], len(Entry["native"]["skipped_stages"]))
        if Report["score"]:
            Score = Entry.get("ground_truth") or {}
            Row += "| %s | %s " % (GroundTruthCell(Score.get("native")), GroundTruthCell(Score.get("oracle")))
        Lines.append(Row + "|")
    Lines += ["", "Status: COMPARED (the oracle run is valid and was compared), PENDING (the oracle run has not "
              "finished), SKIPPED_LONG (pass --long), ORACLE_INVALID (never a native failure). "
              "GT = ground truth against the PDB of the target build (tools/e2e/score_ground_truth.py): label "
              "level correct+alias/wrong/missing of scored addresses, then match level ok/wrong per category "
              "(b best, p partial, m multimatch).", ""]
    for Pair, Entry in Report["pairs"].items():
        if Entry.get("compare"):
            Lines.append(Compare.Markdown(Entry["compare"], Title=Pair))
            Oracle = Entry["oracle"]
            Lines.append("- oracle: determinism %s, longest heuristic %s, final results `%s`" % (
                Oracle.get("determinism"), Oracle.get("longest_heuristic"), Oracle.get("final_results")))
            Lines.append("- native: exit %d, %.2f s, %d stages skipped%s" % (
                Entry["native"]["exit_code"], Entry["native"]["wall_seconds"], len(Entry["native"]["skipped_stages"]),
                ", %s" % Entry["native"]["sqlite_warning"] if Entry["native"]["sqlite_warning"] else ""))
            if Entry.get("ground_truth"):
                for Side in ("native", "oracle"):
                    Score = Entry["ground_truth"].get(Side) or {}
                    Lines.append("- ground truth, %s results: %s" % (Side, Score.get("summary", "port exit %s" % Score.get(
                        "port_exit_code"))))
            Lines.append("")
    return "\n".join(Lines)


# ----------------------------------------------------------------------------- main

def Run(Args):
    """One parity run; Args carries the command-line options. Returns the report (its exit_code field
    is the process exit status)."""
    Corpus = CorpusRoot(Args.corpus)
    Exe = Executable(Args.dsigmatcher)
    Manifest = ReadJson(os.path.join(Corpus, "oracle", "manifest.json"))
    if not Manifest or "diffs" not in Manifest:
        raise UsageError("unreadable oracle manifest")
    Stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    Out = os.path.abspath(Args.out or os.path.join(Corpus, "parity-reports", Stamp))
    if Inside(Out, REPO):
        raise UsageError("--out must be outside the repository (reports hold corpus names): %s" % Out)
    os.makedirs(Out, exist_ok=True)
    Pairs = Args.pairs or list(Manifest["diffs"].keys())
    Unknown = [Pair for Pair in Pairs if Pair not in Manifest["diffs"]]
    if Unknown:
        raise UsageError("unknown pair(s): %s" % ", ".join(Unknown))

    Reference = None
    if Args.diaphora_dir and os.path.isdir(Args.diaphora_dir):
        Describe = Git(Args.diaphora_dir, "describe", "--tags")
        Status = Git(Args.diaphora_dir, "status", "--porcelain")
        Reference = "%s, %s, manifest revision %s" % (Describe, "clean" if Status == "" else "NOT CLEAN",
                                                       Manifest.get("diaphora_revision"))
    Report = {"timestamp": Stamp, "corpus": Corpus, "out": Out, "dsigmatcher": Exe, "dsigmatcher_sha256": Sha256(Exe),
              "python_sqlite": sqlite3.sqlite_version, "run": Args.run, "long": Args.long, "score": Args.score,
              "diaphora_reference": Reference, "pairs": {}}
    Log("parity: %d pair(s) -> %s" % (len(Pairs), Out))

    Failures = 0
    for Pair in Pairs:
        Status, Details = OracleStatus(Corpus, Manifest, Pair, Args.run, Args.long)
        Entry = {"status": Status, "reasons": Details.get("reasons", []), "oracle": Details}
        Report["pairs"][Pair] = Entry
        if Status != "VALID":
            Log("%s: %s (%s)" % (Pair, Status, "; ".join(Entry["reasons"])))
            continue
        PairDir = os.path.join(Out, Pair)
        os.makedirs(PairDir, exist_ok=True)
        NativeFile = os.path.join(PairDir, "native.diaphora")
        Native = RunNative(Exe, Details["db1_arg"], Details["db2_arg"], NativeFile, os.path.join(PairDir, "native.log"),
                           Pair, Args.native_arg)
        After = {Id: Sha256(Info["path"]) for Id, Info in Details["inputs"].items()}
        Native["inputs_unchanged"] = all(After[Id] == Info["before"] for Id, Info in Details["inputs"].items())
        Entry["native"] = Native
        Entry["status"] = "COMPARED"
        if Native["exit_code"] != 0 or not os.path.isfile(NativeFile) or not Native["inputs_unchanged"]:
            Entry["status"] = "NATIVE_FAILED"
            Failures += 1
            Log("%s: native diff FAILED (exit %d, output %s, inputs unchanged %s); see %s" % (
                Pair, Native["exit_code"], os.path.isfile(NativeFile), Native["inputs_unchanged"], Native["log"]))
            continue
        # Same argument strings as the oracle run, so config.main_db / diff_db are compared too.
        Comparison = Compare.CompareFiles(Details["output"], NativeFile, Details["oracle_log"], Native["log"],
                                          ComparePaths=True, Limit=Args.limit)
        Entry["compare"] = Comparison
        WriteJson(os.path.join(PairDir, "compare.json"), Comparison)
        WriteText(os.path.join(PairDir, "compare.md"), Compare.Markdown(Comparison, Title=Pair))
        if not Comparison["verdict"]["ok"]:
            Failures += 1
        Log("%s: %s; native %.2f s, %d stages skipped" % (Pair, Compare.Summary(Comparison), Native["wall_seconds"],
                                                          len(Native["skipped_stages"])))
        if Args.score:
            Entry["ground_truth"] = ScoreBoth(Exe, Corpus, Pair, Details["ref"], Details["target"],
                                              {"native": NativeFile, "oracle": Details["output"]}, PairDir,
                                              Args.generate_aliases)
            for Side in ("native", "oracle"):
                Log("%s: ground truth (%s results): %s" % (Pair, Side, Entry["ground_truth"][Side].get(
                    "summary", "port exit %s" % Entry["ground_truth"][Side].get("port_exit_code"))))

    Counts = {}
    for Entry in Report["pairs"].values():
        Counts[Entry["status"]] = Counts.get(Entry["status"], 0) + 1
    Passed = sum(1 for Entry in Report["pairs"].values() if Entry.get("compare", {}).get("verdict", {}).get("ok"))
    Report["verdict"] = "%s; L2 passed on %d of %d compared pair(s)" % (
        ", ".join("%s %d" % Item for Item in sorted(Counts.items())), Passed,
        Counts.get("COMPARED", 0) + Counts.get("NATIVE_FAILED", 0))
    Report["exit_code"] = 1 if Failures else 0
    WriteJson(os.path.join(Out, "report.json"), Report)
    WriteText(os.path.join(Out, "report.md"), ReportMarkdown(Report))
    Log("parity: %s -> %s" % (Report["verdict"], os.path.join(Out, "report.md")))
    return Report


# ----------------------------------------------------------------------------- self-test

# A stand-in differ for the self-test: writes the oracle's own rows for the pair (so L2 holds) with the
# config paths it was given, and prints the oracle's Final results line (so L0 holds).
FAKE_DIFFER = r'''
import os, sys
sys.dont_write_bytecode = True
sys.path.insert(0, %(here)r)
import compare_results
args = sys.argv[1:]
db1, db2 = args[1], args[2]
out, pair = args[args.index("-o") + 1], args[args.index("--pair") + 1]
oracle = os.path.join(os.environ["DSIG_FAKE_CORPUS"], "oracle", "diffs", pair, "run1")
rows = compare_results.ReadResultsDb(os.path.join(oracle, pair + ".diaphora"))
compare_results.WriteResultsDb(out, [(db1, db2, "3.4", "Thu Jan  1 00:00:00 1970")], rows["results"], rows["unmatched"])
with open(os.path.join(oracle, "diaphora.log"), encoding="utf-8") as handle:
    for line in handle:
        if "Final results:" in line:
            print(line.split("INFO: ", 1)[-1].strip())
'''


def SelfTest(Exe=None):
    """The validity classification on a synthetic corpus built from the committed `common` fixture, then
    whole runs: with a stand-in differ that reproduces the oracle (L2 equal, exit 0), with a planted
    oracle difference (L2 fails, exit 1) and, when a dsigmatcher executable is found, with the real one
    (the report is written and the exit status follows the L2 verdict). Returns the failure count."""
    import shutil
    import tempfile
    Fixture = os.path.join(REPO, "tests", "diff", "fixtures", "common")
    Failures = []

    def Check(Label, Condition):
        print("  %-72s %s" % (Label, "ok" if Condition else "FAILED"))
        if not Condition:
            Failures.append(Label)

    Work = tempfile.mkdtemp(prefix="dsig-run-parity-")
    try:
        Corpus = os.path.join(Work, "corpus")
        Oracle = os.path.join(Corpus, "oracle")
        Exports = {}
        for Id, Sql in (("fx-main", "main.sql"), ("fx-diff", "diff.sql"), ("fx-other", "diff.sql")):
            Directory = os.path.join(Oracle, "exports", Id)
            os.makedirs(Directory)
            Path = os.path.join(Directory, Id + ".sqlite")
            with open(os.path.join(Fixture, Sql), "r", encoding="utf-8") as Handle:
                Text = Handle.read()
            Db = sqlite3.connect(Path, isolation_level=None)
            Db.executescript(Text)
            Db.close()
            Exports[Id] = {"sqlite_sha256": Sha256(Path)}
        Exports["fx-other"]["sqlite_sha256"] = "0" * 64  # the manifest disagrees with the file
        Results, Unmatched = [], []
        for Name, Rows in (("expected_results.tsv", Results), ("expected_unmatched.tsv", Unmatched)):
            with open(os.path.join(Fixture, Name), "r", encoding="utf-8") as Handle:
                for Line in Handle.read().split("\n")[1:]:
                    if Line:
                        Rows.append([None if Field == "\\N" else Field for Field in Line.split("\t")])
        Stamp = "[Diaphora: 2026-09-23 00:%02d:%02d,000] INFO: "
        Base = [Stamp % (0, 0) + "[Single thread] Finding with heuristic 'A'",
                Stamp % (0, 0) + "[Single thread] Finding with heuristic 'B'",
                Stamp % (0, 1) + "[Parallel] Heuristic 'B' done",
                Stamp % (0, 2) + "[Parallel] Heuristic 'A' done",
                Stamp % (0, 3) + "Final results: Best 4, Partial 1, Unreliable 0, Multimatches 0",
                Stamp % (0, 3) + "Diffing results saved in file 'x'.",
                "WARNING: Python library 'cdifflib' not found. Installing it will significantly improve text "
                "diffing performance."]
        Slow = list(Base)
        Slow[3] = Stamp % (5, 2) + "[Parallel] Heuristic 'A' done"  # 'A' ran 301 s
        Cases = {
            # pair: (target export, log lines, run.json fields (None: no run.json), write the output?, expected)
            "fx_valid": ("fx-diff", Base, {}, True, ("VALID", [])),
            "fx_pending": ("fx-diff", Base, None, False, ("PENDING", None)),
            "fx_exit": ("fx-diff", Base, {"exit_code": 1}, True, ("ORACLE_INVALID", ["exit_code_0"])),
            "fx_nofile": ("fx-diff", Base, {}, False, ("ORACLE_INVALID", ["output_exists"])),
            "fx_unsaved": ("fx-diff", [L for L in Base if "saved in file" not in L], {}, True,
                           ("ORACLE_INVALID", ["saved_line"])),
            "fx_timeout": ("fx-diff", Base + [Stamp % (0, 4) + "Timeout with heuristic 'A'"], {}, True,
                           ("ORACLE_INVALID", ["no_timeout_logged"])),
            "fx_slow": ("fx-diff", Slow, {}, True, ("ORACLE_INVALID", ["no_heuristic_over_300s"])),
            "fx_cdifflib": ("fx-diff", [L for L in Base if "cdifflib" not in L], {}, True,
                            ("ORACLE_INVALID", ["cdifflib_absent"])),
            "fx_args": ("fx-diff", Base, {"extra_args": ["--relaxed-ratio"]}, True,
                        ("ORACLE_INVALID", ["default_command_no_diaphora_env"])),
            "fx_sha": ("fx-other", Base, {}, True, ("ORACLE_INVALID", ["inputs_match_manifest"])),
            "fx_long": ("fx-diff", Base, {"wall_seconds": 2 * LONG_PAIR_SECONDS}, True, ("SKIPPED_LONG", None)),
        }
        Db1 = os.path.join(Oracle, "exports", "fx-main", "fx-main.sqlite")
        Manifest = {"diaphora_revision": "3.4.2-4-g621ec26", "exports": Exports, "diffs": {}}
        for Pair, (Target, Lines, RunInfo, Output, _) in Cases.items():
            RunDir = os.path.join(Oracle, "diffs", Pair, "run1")
            os.makedirs(RunDir)
            Db2 = os.path.join(Oracle, "exports", Target, Target + ".sqlite")
            Out = os.path.join(RunDir, Pair + ".diaphora")
            WriteText(os.path.join(RunDir, "diaphora.log"), "\n".join(Lines) + "\n")
            if Output:
                Compare.WriteResultsDb(Out, [(Db1, Db2, "3.4", "Wed Sep 23 00:00:03 2026")], Results, Unmatched)
            Manifest["diffs"][Pair] = {"ref": "fx-main", "target": Target, "runs": []}
            if RunInfo is not None:
                Fields = dict(RunInfo)
                Info = {"exit_code": 0, "wall_seconds": 3.0,
                        "command": ["python", "diaphora.py", Db1, Db2, "-o", Out] + Fields.pop("extra_args", [])}
                Info.update(Fields)
                WriteJson(os.path.join(RunDir, "run.json"), Info)
                Manifest["diffs"][Pair]["runs"].append({"wall_seconds": Info["wall_seconds"]})
        WriteJson(os.path.join(Oracle, "manifest.json"), Manifest)

        print("oracle validity on a synthetic corpus:")
        for Pair, (_, _, _, _, (Expected, Reasons)) in Cases.items():
            Status, Details = OracleStatus(Corpus, Manifest, Pair, 1, False)
            Check("%s -> %s%s" % (Pair, Expected, " %s" % Reasons if Reasons else ""),
                  Status == Expected and (Reasons is None or Details.get("reasons") == Reasons))
        Status, _ = OracleStatus(Corpus, Manifest, "fx_long", 1, True)
        Check("fx_long with --long -> VALID", Status == "VALID")
        Spans = HeuristicSpans("\n".join(Slow))
        Check("heuristic spans from the log timestamps: B 1 s, A 301 s",
              [(S["heuristic"], S["seconds"]) for S in Spans] == [("B", 1.0), ("A", 301.0)])

        def Options(ExePath, Out, Pairs):
            return argparse.Namespace(corpus=Corpus, dsigmatcher=ExePath, pairs=Pairs, long=False, score=False, run=1,
                                      out=Out, diaphora_dir=None, limit=20, native_arg=[], generate_aliases=False)

        Fake = os.path.join(Work, "fake_differ.py")
        WriteText(Fake, FAKE_DIFFER % {"here": HERE})
        if os.name == "nt":
            FakeExe = os.path.join(Work, "fake_differ.cmd")
            WriteText(FakeExe, '@"%s" -B "%s" %%*\r\n' % (sys.executable, Fake))
        else:
            FakeExe = os.path.join(Work, "fake_differ")
            WriteText(FakeExe, '#!/bin/sh\nexec "%s" -B "%s" "$@"\n' % (sys.executable, Fake))
            os.chmod(FakeExe, 0o755)
        os.environ["DSIG_FAKE_CORPUS"] = Corpus
        print("whole runs:")
        Report = Run(Options(FakeExe, os.path.join(Work, "report-fake"), ["fx_valid", "fx_pending", "fx_exit"]))
        Pairs = Report["pairs"]
        Check("stand-in differ: fx_valid COMPARED, L0, L1 and L2 equal, exit 0",
              Pairs["fx_valid"]["status"] == "COMPARED" and Pairs["fx_valid"]["compare"]["verdict"]["ok"] and
              Pairs["fx_valid"]["compare"]["verdict"]["L0"] is True and Report["exit_code"] == 0)
        Check("PENDING and ORACLE_INVALID pairs never fail the run",
              Pairs["fx_pending"]["status"] == "PENDING" and Pairs["fx_exit"]["status"] == "ORACLE_INVALID")
        Check("report.json and report.md written",
              os.path.isfile(os.path.join(Work, "report-fake", "report.json")) and
              os.path.isfile(os.path.join(Work, "report-fake", "report.md")))
        # A planted ratio change in the oracle output. The stand-in keeps reproducing the unplanted rows
        # (from a copy of the corpus), so the harness must see one ratio mismatch, fail L2 and exit 1.
        Clean = os.path.join(Work, "clean")
        shutil.copytree(Corpus, Clean)
        os.environ["DSIG_FAKE_CORPUS"] = Clean
        Target = os.path.join(Oracle, "diffs", "fx_valid", "run1", "fx_valid.diaphora")
        Db2 = os.path.join(Oracle, "exports", "fx-diff", "fx-diff.sqlite")
        Planted = [list(Row) for Row in Results]
        Planted[-1][6] = "0.1234567"
        Compare.WriteResultsDb(Target, [(Db1, Db2, "3.4", "Wed Sep 23 00:00:03 2026")], Planted, Unmatched)
        Report = Run(Options(FakeExe, os.path.join(Work, "report-planted"), ["fx_valid"]))
        Entry = Report["pairs"]["fx_valid"]
        Check("planted oracle ratio change: ratio mismatch 1, L2 fails, exit 1",
              Entry["status"] == "COMPARED" and not Entry["compare"]["verdict"]["L2"] and Report["exit_code"] == 1 and
              sum(Group["ratio"] for Group in Entry["compare"]["groups"]) == 1)
        Compare.WriteResultsDb(Target, [(Db1, Db2, "3.4", "Wed Sep 23 00:00:03 2026")], Results, Unmatched)
        try:
            Real = Executable(Exe)
        except UsageError:
            Real = None
        if Real:
            Report = Run(Options(Real, os.path.join(Work, "report-real"), ["fx_valid", "fx_pending"]))
            Entry = Report["pairs"]["fx_valid"]
            Ok = Entry.get("compare", {}).get("verdict", {}).get("ok")
            Check("real dsigmatcher: fx_valid compared, exit status follows L2 (%s)" % ("equal" if Ok else "differs"),
                  Entry["status"] == "COMPARED" and Report["exit_code"] == (0 if Ok else 1) and
                  Report["pairs"]["fx_pending"]["status"] == "PENDING")
        else:
            print("  (no dsigmatcher executable: the real-differ run is skipped)")
    finally:
        os.environ.pop("DSIG_FAKE_CORPUS", None)
        shutil.rmtree(Work, ignore_errors=True)
    print("self-test: %d failure(s)" % len(Failures))
    return len(Failures)


def Main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    Parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    Parser.add_argument("--corpus")
    Parser.add_argument("--dsigmatcher")
    Parser.add_argument("--pairs", nargs="*")
    Parser.add_argument("--long", action="store_true", help="also run the long pairs (hours in Diaphora)")
    Parser.add_argument("--score", action="store_true", help="ground-truth scores of the native and oracle results")
    Parser.add_argument("--run", type=int, default=1, help="the oracle run to compare with (default 1)")
    Parser.add_argument("--out")
    Parser.add_argument("--diaphora-dir", default=os.environ.get("DSIG_DIAPHORA_DIR"))
    Parser.add_argument("--limit", type=int, default=20)
    Parser.add_argument("--native-arg", action="append", default=[])
    Parser.add_argument("--generate-aliases", action="store_true")
    Parser.add_argument("--self-test", action="store_true",
                        help="check the validity rules and the exit status on a synthetic corpus (no oracle needed)")
    Args = Parser.parse_args()
    if Args.self_test:
        return 1 if SelfTest(Args.dsigmatcher) else 0
    return Run(Args)["exit_code"]


if __name__ == "__main__":
    try:
        sys.exit(Main())
    except UsageError as Error:
        print("error: %s" % Error, file=sys.stderr)
        sys.exit(2)
