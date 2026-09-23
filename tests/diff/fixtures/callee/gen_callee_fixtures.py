#!/usr/bin/env python3
"""Record what REAL Diaphora does in callee diffing (lane L7) on synthetic data, for tests/diff/callee_tests.cpp.

    python -B tests/diff/fixtures/callee/gen_callee_fixtures.py [--diaphora-dir <dir>] [--python <exe>]
                                                                [--hash-seed 0] [--only <scenario>] [--no-walk]

Two kinds of artefacts, both text and synthetic only (plan §2.6: never names or bytes of a real binary):

1. walk_vectors.json: the diff walk of find_one_match_diffing (D:3040-3074) on generated text pairs. The
   UNMODIFIED CBinDiff.find_one_match_diffing runs on each (main text, diff text) with a stand-in `self`
   whose functions_exists records its arguments and returns (False, []), a `dones` set that records the
   order of its add() calls, and the diaphora module's `re` name replaced (in memory, in the child process
   only) by a proxy that records every re.findall result. For each case the file holds:
     pairs   the positional (name1, name2) pairs of every flushed block, in order (from the findall calls,
             which alternate matches1 / matches2, D:3058-3066), before the dones filter;
     keys    the keys added to dones, in order (D:3067-3070);
     exists  the functions_exists calls, in order (after the nullsub filter, D:3072-3080).
   The inputs are the documented quirks (03b §4.3.2-§4.3.3, 06 §6.1-§6.4 and V2) plus random cases
   (fixed seed) over a small token alphabet, the ten splitlines separators, the four extra IGNORECASE
   letters and inputs of 200+ lines (difflib autojunk).

2. One directory per scenario (<name>/scenario.py, the format of tools/parity/make_fixture.py): main.sql and
   diff.sql (the fixture databases, built exactly like make_fixture.py builds them), then an instrumented
   in-process run of diaphora.py's __main__ (D:3757-3773) on COPIES, with tools/parity/oracle_trace.py's
   Instrument installed (all points, ratios_cache at before:find_*). For every outer iteration k that
   reached before:find_matches_diffing:k it writes
     before_<k>.json   the before:find_matches_diffing:<k> snapshot (with ratios_cache),
     after_<k>.json    the after:find_matches_diffing:<k> snapshot (absent when Diaphora raised inside),
     events_<k>.jsonl  every trace event strictly between those two points (or to the end of the trace),
   and expect.json: the find_one_match_diffing call counts per "<field>:outer<k>:inner<i>", the exception
   Diaphora raised (type, message, line and function of the innermost diaphora.py frame) or null, the
   mode, the SQLite / Python / Diaphora versions and the hash seed.

The Diaphora checkout is imported read-only (python -B, PYTHONDONTWRITEBYTECODE=1) and its `git describe` /
`git status` are checked unchanged afterwards. Nothing is written outside this directory and a temporary
work directory. Paths come from flags or the environment only (plan §7.1 D9):
  --diaphora-dir  (env DSIG_DIAPHORA_DIR)   the unmodified Diaphora checkout
  --python        (env DSIG_PYTHON)         the Python that runs Diaphora (default: this one)
"""

import sys

sys.dont_write_bytecode = True

import argparse  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import random  # noqa: E402
import shutil  # noqa: E402
import subprocess  # noqa: E402
import tempfile  # noqa: E402
import traceback  # noqa: E402
import types  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.normpath(os.path.join(HERE, "..", "..", "..", "..", "tools", "parity"))
if TOOLS not in sys.path:
    sys.path.insert(0, TOOLS)

import make_fixture as MF  # noqa: E402  (tools/parity, lane L4)
import snapshot as Snap  # noqa: E402  (tools/parity, lane L0b)

WALK_SEED = 20260923


# ----------------------------------------------------------------------------- walk vectors

def DocCases():
    """The documented examples (03b §4.3.2-§4.3.3, 06 §6.3-§6.4, 06 V2)."""
    NL = "\n"
    Ctx = ["ctx%d" % I for I in range(1, 13)]
    Cases = [
        # 03b §4.3.2 quirk 1: a change at the very end has no trailing context row and is never flushed.
        ("a\nb\nc\ncall foo_old", "a\nb\nc\ncall foo_new"),
        ("x1\nx2\nx3\ncall foo_a", "x1\nx2\nx3\ncall foo_b"),
        # quirk 2: a leading delete-only block is flushed with "+++ " at the first context row (no pairs).
        (NL.join(["call alpha_one", "x1", "x2", "x3", "x4"]), NL.join(["x1", "x2", "x3", "x4"])),
        # 06 V2: leading pure deletion, later pure insertion -> [] (the header makes the deletion vanish).
        (NL.join(["call alpha_one"] + Ctx[:10] + ["call  beta_two", "ctxC"]),
         NL.join(Ctx[:10] + ["call  delta_two", "call  beta_two", "ctxC"])),
        # 06 V2: leading replace -> [('call','call'), ('alpha_one','gamma_new')].
        (NL.join(["call alpha_one"] + Ctx[:6]), NL.join(["call gamma_new"] + Ctx[:6])),
        # 06 §6.3 insertion case (hdr.py): header discards the leading insertion; the later replace pairs
        # positionally across the carried block.
        (NL.join(Ctx[:4] + ["call alpha_one"] + Ctx[4:11] + ["call  beta_two", "ctx12"]),
         NL.join(["call gamma_new"] + Ctx[:4] + Ctx[4:11] + ["call  delta_two", "ctx12"])),
        # quirk 3: a middle delete-only hunk is carried into a later insert-only hunk (14 lines).
        (NL.join(Ctx[:4] + ["call alpha_one"] + Ctx[4:12]), NL.join(Ctx[:4] + Ctx[4:9] + ["call gamma_new"] + Ctx[9:12])),
        (NL.join(["l%02d" % I for I in range(14)][:3] + ["call alpha_one"] + ["l%02d" % I for I in range(3, 14)]),
         NL.join(["l%02d" % I for I in range(12)] + ["call gamma_new"] + ["l%02d" % I for I in range(12, 14)])),
        # quirk 4: positional pairing over every token; one extra token shifts the rest.
        (NL.join(["c0", "c1", "c2", "call pos_old_a", "c3", "c4", "c5"]),
         NL.join(["c0", "c1", "c2", "call extra_tok pos_new_a", "c3", "c4", "c5"])),
        # 06 §6.3 / V2: 3-character mnemonics are not tokens; call, push, test, qword are.
        (NL.join(["s0", "s1", "jmp mov call push lea test", "s2", "s3"]),
         NL.join(["s0", "s1", "jmp mov call push lea test extra", "s2", "s3"])),
        # 03b §4.3.3 scanner examples.
        (NL.join(["q0", "call Foo::Barbaz::x", "q1"]), NL.join(["q0", "call abc::defg", "q1"])),
        (NL.join(["q0", "push qword ptr [rax]", "q1"]), NL.join(["q0", "mov eax, 0x401000", "q1"])),
        (NL.join(["q0", "12abcd std::vector::push_back", "q1"]), NL.join(["q0", "ab_c sub_401000", "q1"])),
        # the four extra IGNORECASE letters (U+0130, U+0131, U+017F, U+212A) and other non-ASCII text.
        (NL.join(["u0", "call \u017fub_1234 \u212aernel", "u1"]), NL.join(["u0", "call \u0130dent_x \u0131dent_y", "u1"])),
        (NL.join(["u0", "call caf\u00e9_fn \u00fcber_fn", "u1"]), NL.join(["u0", "call na\u00efve_fn", "u1"])),
        # splitlines separators (03b §4.3.1): \v \f \x1c \x1d \x1e \x85 U+2028 U+2029, \r, \r\n.
        ("p0\x0bcall sep_old_one\x0cp1\x1cp2\x1dp3", "p0\x0bcall sep_new_one\x0cp1\x1cp2\x1dp3"),
        ("p0\x1ecall sep_old_two\x85p1\u2028p2\u2029p3", "p0\x1ecall sep_new_two\x85p1\u2028p2\u2029p3"),
        ("p0\rcall sep_old_three\r\np1\r\np2\n", "p0\rcall sep_new_three\r\np1\r\np2\n"),
        ("p0\n\ncall blank_old\n\np1\n", "p0\n\ncall blank_new\n\np1\n"),
        # nullsub filter (D:3072): the key is still added to dones first.
        (NL.join(["n0", "call nullsub_12 nullsubfoo helper_one", "n1"]),
         NL.join(["n0", "call nullsub_34 realfunc helper_two", "n1"])),
        # a repeated pair within one call is skipped by dones (D:3068).
        (NL.join(["d0", "call same_old", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "call same_old", "d8"]),
         NL.join(["d0", "call same_new", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "call same_new", "d8"])),
        # identical inputs, empty inputs.
        ("same\ntext\nhere", "same\ntext\nhere"),
        ("", "call only_new\nx"),
        ("call only_old\nx", ""),
        ("", ""),
    ]
    return Cases


def RandomCases(Count):
    Rng = random.Random(WALK_SEED)
    Tokens = ["call", "push", "mov", "jmp", "lea", "test", "qword", "sub_401000", "sub_402000", "alpha_one",
              "beta_two", "gamma_new", "delta_two", "Foo::Barbaz::x", "abc::defg", "nullsub_1", "nullsub_2",
              "0x401000", "12abcd", "\u017fub_1234", "\u212aernel", "\u0130dent", "x1", "eax", "[rax+8]", ",", ";",
              "loc_1", "func_a", "func_b", "Func_C", "__imp_Sleep", "caf\u00e9"]
    Seps = ["\n"] * 12 + ["\r\n", "\r", "\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"]

    def Line():
        return " ".join(Rng.choice(Tokens) for _ in range(Rng.randint(0, 4)))

    def Text(Lines):
        Out = ""
        for Index, L in enumerate(Lines):
            Out += L
            if Index + 1 < len(Lines) or Rng.random() < 0.3:
                Out += Rng.choice(Seps)
        return Out

    Cases = []
    for Index in range(Count):
        Big = Index % 40 == 0
        N = Rng.randint(200, 420) if Big else Rng.randint(0, 40)
        if Big:
            # popular lines: autojunk purges lines occurring more than len(b)//100 + 1 times in b (n >= 200)
            Pool = [Line() for _ in range(12)] + ["nop"] * 8
            A = [Rng.choice(Pool) if Rng.random() < 0.6 else Line() for _ in range(N)]
        else:
            A = [Line() for _ in range(N)]
        B = []
        for L in A:
            R = Rng.random()
            if R < 0.08:
                continue  # delete
            if R < 0.16:
                B.append(Line())  # replace
                continue
            if R < 0.22:
                B.append(Line())  # insert before
            B.append(L)
        if Rng.random() < 0.3:
            B.append(Line())
        Cases.append((Text(A), Text(B)))
    return Cases


def WalkChild(DiaphoraDir, CasesPath, OutPath):
    """Child process: the unmodified find_one_match_diffing on every case."""
    sys.path.insert(0, DiaphoraDir)
    import diaphora as D  # the unmodified checkout, read-only

    class RecordingSet(set):
        def __init__(self):
            super().__init__()
            self.Order = []

        def add(self, Key):  # noqa: A003 - set.add
            self.Order.append(Key)
            super().add(Key)

    class RecordingRe:
        def __init__(self, Real):
            self.Real = Real
            self.Calls = []

        def findall(self, Pattern, Text, Flags=0):
            Result = self.Real.findall(Pattern, Text, Flags)
            self.Calls.append([M[0] for M in Result])
            return Result

        def __getattr__(self, Name):
            return getattr(self.Real, Name)

    class StandIn:
        def __init__(self):
            self.Exists = []

        def functions_exists(self, Name1, Name2):
            self.Exists.append([Name1, Name2])
            return False, []

    with open(CasesPath, "r", encoding="utf-8") as Handle:
        Cases = json.load(Handle)
    Proxy = RecordingRe(D.re)
    D.re = Proxy  # the module global find_one_match_diffing resolves at call time (D:3058-3059)
    Out = []
    for Main, Diff in Cases:
        Proxy.Calls = []
        Self = StandIn()
        Dones = RecordingSet()
        Result = D.CBinDiff.find_one_match_diffing(Self, {"assembly": Main}, {"assembly": Diff}, "assembly",
                                                   "Callee found diffing matches assembly", 1, Dones)
        if Result is not Dones:
            raise RuntimeError("find_one_match_diffing did not return its dones set")
        if len(Proxy.Calls) % 2 != 0:
            raise RuntimeError("odd number of re.findall calls")
        Pairs = []
        for Index in range(0, len(Proxy.Calls), 2):
            Pairs.extend([A, B] for A, B in zip(Proxy.Calls[Index], Proxy.Calls[Index + 1]))
        Out.append({"main": Main, "diff": Diff, "pairs": Pairs, "keys": Dones.Order, "exists": Self.Exists})
    with open(OutPath, "w", encoding="utf-8", newline="\n") as Handle:
        json.dump({"cases": Out, "python": sys.version.split()[0], "has_cdifflib": D.HAS_CDIFFLIB}, Handle,
                  ensure_ascii=False)
    return 0


# ----------------------------------------------------------------------------- scenario captures

def CaptureChild(DiaphoraDir, Db1, Db2, OutDir):
    """Child process: diaphora.py __main__ (D:3757-3773) under oracle_trace.Instrument."""
    sys.path.insert(0, DiaphoraDir)
    import diaphora as D  # the unmodified checkout, read-only
    import oracle_trace as OT  # tools/parity (lane L0b)

    Bd = D.CBinDiff(Db1)
    if not D.IS_IDA:
        Bd.ignore_all_names = False
    Bd.db = D.sqlite3_connect(Db1)
    Args = types.SimpleNamespace(with_cache=["before:find_*"], points=["*"], stop_at=None, rows=False,
                                 force_const_order=None)
    Instr = OT.Instrument(D, Bd, Args, OutDir, "fixture", "diaphora", {"status": "running"})
    Instr.Install()
    Exception_ = None
    try:
        Bd.diff(Db2)
    except Exception as Error:  # noqa: BLE001 - recorded, as the process would have died here
        Frames = [F for F in traceback.extract_tb(Error.__traceback__)
                  if os.path.basename(F.filename) == "diaphora.py"]
        Exception_ = {"type": type(Error).__name__, "message": str(Error),
                      "line": Frames[-1].lineno if Frames else None,
                      "function": Frames[-1].name if Frames else None}
    Instr.Close()
    with open(os.path.join(OutDir, "capture.json"), "w", encoding="utf-8", newline="\n") as Handle:
        json.dump({"exception": Exception_, "stats": Instr.StatsSummary(), "python": sys.version.split()[0],
                   "sqlite_version": D.sqlite3.sqlite_version, "has_cdifflib": D.HAS_CDIFFLIB,
                   "pythonhashseed": os.environ.get("PYTHONHASHSEED"),
                   "mode": "S" if Bd.is_symbols_stripped else ("P" if Bd.is_patch_diff else "N")}, Handle)
    for Handle in list(getattr(D, "_DATABASES", {}).values()) + [Bd.db]:
        try:
            Handle.close()
        except Exception:  # noqa: BLE001
            pass
    return 0


def RunChild(Python, DiaphoraDir, Arguments, Log, Seed):
    with open(Log, "w", encoding="utf-8", errors="replace") as Handle:
        return subprocess.call([Python, "-B", os.path.abspath(__file__)] + Arguments, cwd=DiaphoraDir,
                               env=MF.CleanEnv(Seed), stdout=Handle, stderr=subprocess.STDOUT)


def ScenarioOutputs(Capture, Scenario, Describe, Seed):
    """Split an instrumented capture into the committed per-iteration files."""
    Index = Snap.ReadIndex(Capture)
    Events = [Event for _, Event in Snap.ReadTrace(os.path.join(Capture, "trace.jsonl"))]
    with open(os.path.join(Capture, "capture.json"), "r", encoding="utf-8") as Handle:
        Info = json.load(Handle)
    Iterations = []
    for Seq, Point, File in Index:
        if Point.startswith("before:find_matches_diffing:"):
            Iterations.append(int(Point.rsplit(":", 1)[1]))
    Written = {}
    for K in Iterations:
        Before = "before:find_matches_diffing:%d" % K
        After = "after:find_matches_diffing:%d" % K
        Entries = {Point: (Seq, File) for Seq, Point, File in Index}
        Written["before_%d.json" % K] = Snap.DumpJson(Snap.ReadJson(os.path.join(Capture, Entries[Before][1]))) + "\n"
        if After in Entries:
            Written["after_%d.json" % K] = Snap.DumpJson(Snap.ReadJson(os.path.join(Capture, Entries[After][1]))) + "\n"
        Segment, On = [], False
        for Event in Events:
            if Event.get("ev") == "point" and Event.get("name") == Before:
                On = True
                continue
            if Event.get("ev") == "point" and Event.get("name") == After:
                break
            if On:
                Segment.append(Event)
        Written["events_%d.jsonl" % K] = "".join(Snap.DumpJson(Event) + "\n" for Event in Segment)
    Stats = Info["stats"]
    Expect = {
        "generator": "tests/diff/fixtures/callee/gen_callee_fixtures.py",
        "scenario": Scenario,
        "diaphora": Describe,
        "python": Info["python"],
        "sqlite_version": Info["sqlite_version"],
        "has_cdifflib": Info["has_cdifflib"],
        "pythonhashseed": str(Seed),
        "mode": Info["mode"],
        "iterations": Iterations,
        "after_present": [K for K in Iterations if ("after_%d.json" % K) in Written],
        "find_one_match_diffing": Stats.get("find_one_match_diffing", {}),
        "cleanup_sites": Stats.get("cleanup_sites", {}),
        "exception": Info["exception"],
    }
    Written["expect.json"] = json.dumps(Expect, indent=1, ensure_ascii=False) + "\n"
    return Written


def Main():
    if len(sys.argv) > 1 and sys.argv[1] == "--_walk":
        return WalkChild(*sys.argv[2:5])
    if len(sys.argv) > 1 and sys.argv[1] == "--_capture":
        return CaptureChild(*sys.argv[2:6])
    Parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    Parser.add_argument("--diaphora-dir", default=os.environ.get("DSIG_DIAPHORA_DIR"))
    Parser.add_argument("--python", default=os.environ.get("DSIG_PYTHON") or sys.executable)
    Parser.add_argument("--hash-seed", type=int, default=0)
    Parser.add_argument("--only", action="append", help="regenerate only this scenario directory (repeatable)")
    Parser.add_argument("--no-walk", action="store_true", help="do not regenerate walk_vectors.json")
    Parser.add_argument("--keep-work", help="keep the work files in this directory")
    Args = Parser.parse_args()
    if not Args.diaphora_dir or not os.path.isfile(os.path.join(Args.diaphora_dir, "diaphora.py")):
        Parser.error("--diaphora-dir (or DSIG_DIAPHORA_DIR) must name the Diaphora checkout")
    DiaphoraDir = os.path.abspath(Args.diaphora_dir)
    Describe = MF.Git(DiaphoraDir, "describe", "--tags")
    StatusBefore = MF.Git(DiaphoraDir, "status", "--porcelain")

    Work = os.path.abspath(Args.keep_work) if Args.keep_work else tempfile.mkdtemp(prefix="dsig-callee-fixtures-")
    os.makedirs(Work, exist_ok=True)
    Outputs = {}  # relative path -> text
    try:
        if not Args.no_walk:
            Cases = DocCases() + RandomCases(400)
            CasesPath = os.path.join(Work, "walk_cases.json")
            with open(CasesPath, "w", encoding="utf-8", newline="\n") as Handle:
                json.dump(Cases, Handle, ensure_ascii=False)
            WalkOut = os.path.join(Work, "walk_out.json")
            Code = RunChild(Args.python, DiaphoraDir, ["--_walk", DiaphoraDir, CasesPath, WalkOut],
                            os.path.join(Work, "walk.log"), Args.hash_seed)
            if Code != 0:
                raise SystemExit("walk child failed (exit %d); see %s" % (Code, os.path.join(Work, "walk.log")))
            with open(WalkOut, "r", encoding="utf-8") as Handle:
                Walk = json.load(Handle)
            if Walk["has_cdifflib"]:
                raise SystemExit("cdifflib is installed: not an oracle environment (plan \u00a71.6)")
            Walk.update({"generator": "tests/diff/fixtures/callee/gen_callee_fixtures.py", "diaphora": Describe,
                         "seed": WALK_SEED, "doc_cases": len(DocCases())})
            # one case per line, so a regenerated file diffs line by line
            Head = {Key: Value for Key, Value in Walk.items() if Key != "cases"}
            Outputs["walk_vectors.json"] = (json.dumps(Head, ensure_ascii=False)[:-1] + ',\n"cases": [\n' +
                                            ",\n".join(json.dumps(Case, ensure_ascii=False) for Case in Walk["cases"]) +
                                            "\n]}\n")

        Schema = MF.LoadSchema(DiaphoraDir)
        Scenarios = sorted(Name for Name in os.listdir(HERE)
                           if os.path.isfile(os.path.join(HERE, Name, "scenario.py")))
        if Args.only:
            Scenarios = [Name for Name in Scenarios if Name in Args.only]
        for Name in Scenarios:
            Scenario = MF.LoadScenario(os.path.join(HERE, Name, "scenario.py"))
            Dumps = {"main": MF.BuildDump(Schema, Scenario["MAIN"], 6), "diff": MF.BuildDump(Schema, Scenario["DIFF"], 10)}
            RunDir = os.path.join(Work, Name)
            os.makedirs(RunDir, exist_ok=True)
            Paths = {}
            for Side, Text in Dumps.items():
                Paths[Side] = os.path.join(RunDir, Side + ".sqlite")
                MF.RebuildLikeFixtureDb(Text, Paths[Side])  # Diaphora opens db1 read/write: these are copies
            Capture = os.path.join(RunDir, "capture")
            os.makedirs(Capture, exist_ok=True)
            Code = RunChild(Args.python, DiaphoraDir, ["--_capture", DiaphoraDir, Paths["main"], Paths["diff"], Capture],
                            os.path.join(RunDir, "diaphora.log"), Args.hash_seed)
            if Code != 0:
                raise SystemExit("%s: capture child failed (exit %d); see %s" % (Name, Code, RunDir))
            Files = ScenarioOutputs(Capture, Name, Describe, Args.hash_seed)
            if not any(Key.startswith("before_") for Key in Files):
                raise SystemExit("%s: find_matches_diffing never ran (mode or crash before the loop)" % Name)
            Outputs[os.path.join(Name, "main.sql")] = Dumps["main"]
            Outputs[os.path.join(Name, "diff.sql")] = Dumps["diff"]
            for File, Text in Files.items():
                Outputs[os.path.join(Name, File)] = Text

        if MF.Git(DiaphoraDir, "describe", "--tags") != Describe or MF.Git(DiaphoraDir, "status", "--porcelain") != StatusBefore:
            raise SystemExit("the Diaphora checkout changed: nothing written")
        for Name in Scenarios:  # stale per-iteration files of a regenerated scenario
            for File in os.listdir(os.path.join(HERE, Name)):
                if File.startswith(("before_", "after_", "events_")):
                    os.remove(os.path.join(HERE, Name, File))
        for Relative, Text in sorted(Outputs.items()):
            with open(os.path.join(HERE, Relative), "w", encoding="utf-8", newline="\n") as Handle:
                Handle.write(Text)
            print("wrote", Relative.replace(os.sep, "/"))
        return 0
    finally:
        if not Args.keep_work:
            shutil.rmtree(Work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(Main())
