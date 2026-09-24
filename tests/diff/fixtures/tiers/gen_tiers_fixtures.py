#!/usr/bin/env python3
"""Record the heuristic-tier fixtures (tests/diff/fixtures/tiers/<scenario>/) from real Diaphora.

    python -B gen_tiers_fixtures.py [--only probe3,probe5,...] [--diaphora-dir <dir>] [--python <exe>]

For every scenario directory next to this script (<scenario>/scenario.py, synthetic data only):

1. tools/parity/make_fixture.py builds the fixture pair like a real export and runs the unmodified
   Diaphora checkout on copies (main.sql, diff.sql, expected_*.tsv, after_*.json, oracle.json).
2. The two databases are rebuilt from main.sql / diff.sql exactly as tests/diff/FixtureDb.h does,
   and copies are diffed once more in a child process instrumented with
   tools/parity/oracle_trace.py's Instrument (every point, ratios_cache at every before: point, row
   events), under the fixture's PYTHONHASHSEED and with no DIAPHORA_* variable. The capture goes to
   <scenario>/capture/: index.json, snapshots/*.json and trace.jsonl, cut after the point
   after:search_small_differences (the end of the heuristic tiers; like an oracle_trace.py --stop-at
   capture). run.json and progress.log hold local paths and timings and are not kept.
3. Scenarios listed in FORWARD also get <scenario>/capture_forward/: the same instrumented run with
   threads_apply replaced, in memory, by a verbatim copy of jkutils/threads.py:27-71 that pops the
   FIRST target (`targets.pop(0)`), i.e. the heuristics in forward order. This is the negative
   control of 02 probe 3 only; it is never an oracle.

The checkout is imported read-only (-B, PYTHONDONTWRITEBYTECODE=1) and make_fixture.py checks that its
`git describe` / `git status` are unchanged. Paths come from flags or the environment only:
--diaphora-dir (DSIG_DIAPHORA_DIR), --python (DSIG_PYTHON).
"""

import sys

sys.dont_write_bytecode = True

import argparse  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import shutil  # noqa: E402
import subprocess  # noqa: E402
import tempfile  # noqa: E402
import threading  # noqa: E402
import time  # noqa: E402
import types  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
PARITY = os.path.join(REPO, "tools", "parity")
if PARITY not in sys.path:
    sys.path.insert(0, PARITY)

import make_fixture as Mf  # noqa: E402

SEED = 0
FORWARD = {"probe3"}
CUT = "after:search_small_differences"


def Scenarios():
    return sorted(Name for Name in os.listdir(HERE)
                  if os.path.isfile(os.path.join(HERE, Name, "scenario.py")))


def ForwardThreadsApply(threads, targets, wait_time, log_refresh, timeout):
    """jkutils/threads.py:27-71 verbatim except `targets.pop(0)` (forward order). Negative control."""
    times = 0
    first = True
    threads_list = []
    while first or len(targets) > 0 or len(threads_list) > 0:
        first = False
        times += 1
        if len(targets) > 0 and len(threads_list) < threads:
            item = targets.pop(0)
            target = item["target"]
            args = item["args"]

            t = threading.Thread(target=target, args=args)
            t.time = time.monotonic()
            t.timeout = False

            for key in item.keys():
                if key not in ["target", "args"]:
                    setattr(t, key, item[key])

            t.start()
            threads_list.append(t)

        for i, t in enumerate(threads_list):
            if not t.is_alive():
                if log_refresh:
                    log_refresh(f"[Parallel] Heuristic '{t.name}' done")
                del threads_list[i]
                break

            if time.monotonic() - t.time > timeout:
                t.timeout = True
            t.join(wait_time)

        if times % 50 == 0:
            names = []
            for x in threads_list:
                names.append(x.name)
            tmp_names = ", ".join(names)
            log_refresh(f"[Parallel] {len(threads_list)} thread(s) still running: {tmp_names}")


def CaptureMain(DiaphoraDir, Db1, Db2, OutDir, Pair, Forward):
    """Child process: diaphora.py __main__ (D:3757-3773) under oracle_trace.Instrument."""
    import oracle_trace as Ot

    sys.path.insert(0, DiaphoraDir)
    import diaphora as D  # the unmodified checkout, read-only

    if D.IS_IDA:
        raise SystemExit("idaapi is importable; this is not a standalone run")
    if Forward == "1":
        D.threads_apply = ForwardThreadsApply  # the name run_heuristics_for_category calls (D:1543)
    Args = types.SimpleNamespace(points=["*"], with_cache=["before:*"], rows=True, stop_at=None,
                                 force_const_order=None)
    os.makedirs(OutDir, exist_ok=True)
    Describe = Mf.Git(DiaphoraDir, "describe", "--tags") or "?"
    Bd = D.CBinDiff(Db1)
    Bd.ignore_all_names = False
    Bd.db = D.sqlite3_connect(Db1)
    Instr = Ot.Instrument(D, Bd, Args, OutDir, Pair, "diaphora-" + Describe, {"status": "running"})
    Instr.Install()
    try:
        Bd.diff(Db2)
        Bd.save_results(os.path.join(OutDir, "out.diaphora"))
    finally:
        Instr.Close()
        Instr.RestoreChooser()
        for Handle in list(D._DATABASES.values()) + list(getattr(Bd, "dbs_dict", {}).values()) + [Bd.db]:
            try:
                Handle.close()
            except Exception:
                pass
    if Instr.WorkerExceptions:
        raise SystemExit("worker exceptions: %r" % Instr.WorkerExceptions)
    return 0


def Capture(Python, DiaphoraDir, Scenario, OutDir, Forward, Work):
    Paths = {}
    for Name in ("main", "diff"):
        with open(os.path.join(OutDir, "..", Name + ".sql"), "r", encoding="utf-8") as Handle:
            Text = Handle.read()
        Paths[Name] = os.path.join(Work, Name + ".sqlite")
        Mf.RebuildLikeFixtureDb(Text, Paths[Name])
        shutil.copyfile(Paths[Name], Paths[Name] + ".copy")  # Diaphora opens db1 read/write: copies only
    Raw = os.path.join(Work, "capture")
    Log = os.path.join(Work, "capture.log")
    with open(Log, "w", encoding="utf-8", errors="replace") as Handle:
        Code = subprocess.call([Python, "-B", os.path.abspath(__file__), "--_capture", DiaphoraDir,
                                Paths["main"] + ".copy", Paths["diff"] + ".copy", Raw, Scenario,
                                "1" if Forward else "0"],
                               cwd=DiaphoraDir, env=Mf.CleanEnv(SEED), stdout=Handle, stderr=subprocess.STDOUT)
    if Code != 0:
        raise SystemExit("capture of %s failed (exit %d); see %s" % (Scenario, Code, Log))
    if os.path.isdir(OutDir):
        shutil.rmtree(OutDir)
    os.makedirs(os.path.join(OutDir, "snapshots"))
    # Keep the prefix up to and including CUT: index rows, their snapshot files and the trace events.
    with open(os.path.join(Raw, "index.json"), "r", encoding="utf-8") as Handle:
        Index = json.load(Handle)
    Kept = []
    for Row in Index:
        Kept.append(Row)
        if Row[1] == CUT:
            break
    else:
        raise SystemExit("capture of %s never reached %s" % (Scenario, CUT))
    with open(os.path.join(OutDir, "index.json"), "w", encoding="utf-8", newline="\n") as Handle:
        Handle.write(json.dumps(Kept, ensure_ascii=False, separators=(",", ":")) + "\n")
    for _, _, File in Kept:
        if File is not None:
            shutil.copyfile(os.path.join(Raw, File), os.path.join(OutDir, File))
    Needle = '"ev":"point","name":%s,' % json.dumps(CUT)
    with open(os.path.join(Raw, "trace.jsonl"), "r", encoding="utf-8") as In, \
            open(os.path.join(OutDir, "trace.jsonl"), "w", encoding="utf-8", newline="\n") as Out:
        for Line in In:
            Out.write(Line)
            if Needle in Line:
                break


def Main():
    if len(sys.argv) > 1 and sys.argv[1] == "--_capture":
        return CaptureMain(*sys.argv[2:8])
    Parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    Parser.add_argument("--only", help="comma-separated scenario names")
    Parser.add_argument("--diaphora-dir", default=os.environ.get("DSIG_DIAPHORA_DIR"))
    Parser.add_argument("--python", default=os.environ.get("DSIG_PYTHON") or sys.executable)
    Args = Parser.parse_args()
    if not Args.diaphora_dir or not os.path.isfile(os.path.join(Args.diaphora_dir, "diaphora.py")):
        Parser.error("--diaphora-dir (or DSIG_DIAPHORA_DIR) must name the Diaphora checkout")
    DiaphoraDir = os.path.abspath(Args.diaphora_dir)
    Names = Scenarios() if not Args.only else Args.only.split(",")
    for Scenario in Names:
        Dir = os.path.join(HERE, Scenario)
        Code = subprocess.call([Args.python, "-B", os.path.join(PARITY, "make_fixture.py"),
                                os.path.join(Dir, "scenario.py"), Dir, "--diaphora-dir", DiaphoraDir,
                                "--python", Args.python, "--hash-seed", str(SEED)],
                               env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
        if Code != 0:
            raise SystemExit("make_fixture.py failed for %s" % Scenario)
        for Forward in ((False, True) if Scenario in FORWARD else (False,)):
            Work = tempfile.mkdtemp(prefix="dsig-tiers-fixture-")
            try:
                Capture(Args.python, DiaphoraDir, Scenario,
                        os.path.join(Dir, "capture_forward" if Forward else "capture"), Forward, Work)
            finally:
                shutil.rmtree(Work, ignore_errors=True)
        print("%s: capture%s written" % (Scenario, " and capture_forward" if Scenario in FORWARD else ""))
    return 0


if __name__ == "__main__":
    sys.exit(Main())
