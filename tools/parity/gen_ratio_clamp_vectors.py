#!/usr/bin/env python3
"""Ratio vectors on the 0.99 clamp boundary (lane F1; spec docs/parity/03a-ratio.md §6.3, §13).

check_ratio ends with (D:1766-1771):

    if r < 1.0:
      score = self.deep_ratio(main_d, diff_d, r)
      if r + score < 1.0:
        r += score
      else:
        r = 0.99

The committed suites (gen_ratio_vectors.py) have r + score above and below 1.0 but never EQUAL to 1.0,
so a port that wrote `<=` for `<` passed them. Every labelled case here is built so that the double sum
r + score is exactly 1.0: r is a rounded quick_ratio (v1, v2 or v5: float("{0:.7f}".format(2M/T)),
D:1710-1753) or v4 = min((v1 + v2 + v3 + 3.0) / 5, 1.0) (D:1740), and score is deep_ratio's running
sum in its own order (source_file, pseudocode_primes, indegree, outdegree, switches,
cyclomatic_complexity, then len(common constants) x 0.006 on the same CPU or x 0.008 otherwise,
D:2780-2821, C:147-148). The expected value is then 0.99; with `<=` it would be 1.0.

Every expected value comes from the REAL, unmodified Diaphora through gen_ratio_vectors.EvaluatePair
(check_ratio on the check_match SQL path and compare_function_rows on the row path, on COPIES of
synthetic databases). CBinDiff.deep_ratio is wrapped at run time (the wrapper calls the original with
the original arguments and returns its result) only to record the r and score of each call, so the
generator can prove that each labelled case really sits on the boundary; it exits non-zero otherwise.

    python -B tools/parity/gen_ratio_clamp_vectors.py [--diaphora-dir DIR] [--out DIR]

--diaphora-dir defaults to DSIG_DIAPHORA_DIR; --out defaults to tests/diff/vectors/ratio. Writes
clamp-boundary-same.json (same processor) and clamp-boundary-other.json (different processors), in the
schema of the other committed synthetic vectors plus a "boundary" list:
[{"label", "main", "diff", "r", "score", "expected"}] with IEEE-754 bits as 16 hex digits.
Run it with the oracle's Python (CPython 3.13.12, sqlite3 3.51.1, no cdifflib).
"""
import argparse
import json
import os
import shutil
import sys
import tempfile

sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gen_ratio_vectors as G  # noqa: E402  (same directory; reused, not modified)

CLAMP = 0.99  # D:1771

# deep_ratio's terms in evaluation order (D:2780-2810); constants are added last (D:2812-2821).
DEEP_FEATURES = {
    "source": dict(source_file="a.c"),                 # D:2780-2783, +0.001
    "primes": dict(pseudocode_primes="30"),           # D:2785-2788, +0.001
    "in": dict(indegree=2),                            # D:2792-2795, +0.001
    "out": dict(outdegree=1),                          # D:2797-2800, +0.001
    "switches": dict(switches="[[3, [0, 1, 2]]]"),     # D:2802-2805, +0.003
    "cc": dict(cyclomatic_complexity=4),               # D:2807-2810, +0.001
}


def Fn(**Cols):
    Row = {"name": None, "address": None, "nodes": 3, "edges": 2, "indegree": 0, "outdegree": 0,
           "cyclomatic_complexity": 0, "bytes_hash": None, "pseudocode": None, "clean_pseudo": None,
           "assembly": "x", "clean_assembly": None, "clean_microcode": None, "md_index": "0",
           "pseudocode_primes": None, "source_file": None, "switches": "[]", "constants": "[]",
           "constants_count": 0, "size": 10, "instructions": 5, "loops": 0, "strongly_connected": 1,
           "kgh_hash": "0", "mangled_function": None}
    Row.update(Cols)
    return Row


def Texts(Column, Matching, Total):
    """Two texts of Total lines each, Matching of them shared: quick_ratio = 2 * Matching / (2 * Total)."""
    Main = G.Lines(a=Matching, b=Total - Matching)
    Diff = G.Lines(a=Matching, c=Total - Matching)
    Extra = {"pseudocode": ("p", "q")} if Column == "clean_pseudo" else {}
    return ({Column: Main, **{K: V[0] for K, V in Extra.items()}},
            {Column: Diff, **{K: V[1] for K, V in Extra.items()}})


class Builder:
    def __init__(self, Base):
        self.Main, self.Diff, self.Labels, self.Boundary = [], [], [], []
        self.Base = Base

    def Add(self, Label, Main, Diff, Features=(), Constants=0, OnBoundary=True):
        K = len(self.Main)
        for Name in Features:
            Main.update(DEEP_FEATURES[Name])
            Diff.update(DEEP_FEATURES[Name])
        if Constants:
            Values = [4096 + 16 * I for I in range(Constants)]
            Main.update(constants=json.dumps(Values), constants_count=Constants)
            Diff.update(constants=json.dumps(Values + [7]), constants_count=Constants + 1)
        Main.update(name=f"f{K:02d}", mangled_function=f"f{K:02d}", bytes_hash=f"m{K:02d}",
                    address=str(self.Base + 16 * K))
        Diff.update(name=f"g{K:02d}", mangled_function=f"g{K:02d}", bytes_hash=f"d{K:02d}",
                    address=str(self.Base + 0x100000 + 16 * K))
        self.Main.append(Main)
        self.Diff.append(Diff)
        self.Labels.append(Label)
        if OnBoundary:
            self.Boundary.append(K)


def SameCpuCases():
    B = Builder(5000000)
    M, D = Texts("clean_assembly", 497, 500)          # v2 = 0.994
    B.Add("v2 0.994 + one constant x 0.006", Fn(**M), Fn(**D), Constants=1)
    M, D = Texts("clean_assembly", 199, 200)          # v2 = 0.995
    B.Add("v2 0.995 + source, primes, switches", Fn(**M), Fn(**D), Features=("source", "primes", "switches"))
    M, D = Texts("clean_assembly", 999, 1000)         # v2 = 0.999
    B.Add("v2 0.999 + source", Fn(**M), Fn(**D), Features=("source",))
    M, D = Texts("clean_pseudo", 497, 500)            # v1 = 0.994
    B.Add("v1 0.994 + one constant x 0.006", Fn(**M), Fn(**D), Constants=1)
    M, D = Texts("clean_microcode", 993, 1000)        # v5 = 0.993
    B.Add("v5 0.993 + source + one constant x 0.006", Fn(**M), Fn(**D), Features=("source",), Constants=1)
    M, D = Texts("clean_assembly", 494, 500)          # v2 = 0.988
    B.Add("v2 0.988 + two constants x 0.006", Fn(**M), Fn(**D), Constants=2)
    # v4 = (0.98 + 0.98 + 0 + 3.0) / 5 = 0.992 with md1 == md2 > 0 (D:1736-1740), plus 0.008 of features
    Mp, Dp = Texts("clean_pseudo", 49, 50)
    Ma, Da = Texts("clean_assembly", 49, 50)
    B.Add("v4 0.992 + source, primes, in, out, switches, cc", Fn(md_index="2.5", **Mp, **Ma),
          Fn(md_index="2.5", **Dp, **Da), Features=("source", "primes", "in", "out", "switches", "cc"))
    # v4 = (0.99 + 0.99 + 0 + 3.0) / 5 = 0.9960000000000001, plus 0.004: still exactly 1.0
    Mp, Dp = Texts("clean_pseudo", 99, 100)
    Ma, Da = Texts("clean_assembly", 99, 100)
    B.Add("v4 0.9960000000000001 + source, primes, in, out", Fn(md_index="2.5", **Mp, **Ma),
          Fn(md_index="2.5", **Dp, **Da), Features=("source", "primes", "in", "out"))
    # controls one feature away from the boundary: below (r + score) and above (0.99)
    M, D = Texts("clean_assembly", 497, 500)
    B.Add("control below: v2 0.994 + source, primes, switches", Fn(**M), Fn(**D),
          Features=("source", "primes", "switches"), OnBoundary=False)
    M, D = Texts("clean_assembly", 199, 200)
    B.Add("control above: v2 0.995 + one constant x 0.006", Fn(**M), Fn(**D), Constants=1, OnBoundary=False)
    return B


def OtherCpuCases():
    B = Builder(7000000)
    M, D = Texts("clean_assembly", 124, 125)          # v2 = 0.992
    B.Add("v2 0.992 + one constant x 0.008", Fn(**M), Fn(**D), Constants=1)
    M, D = Texts("clean_assembly", 99, 100)           # v2 = 0.99
    B.Add("v2 0.99 + source, primes + one constant x 0.008", Fn(**M), Fn(**D), Features=("source", "primes"),
          Constants=1)
    M, D = Texts("clean_assembly", 991, 1000)         # v2 = 0.991; score 0.009000000000000001
    B.Add("v2 0.991 + source + one constant x 0.008", Fn(**M), Fn(**D), Features=("source",), Constants=1)
    M, D = Texts("clean_assembly", 246, 250)          # v2 = 0.984
    B.Add("v2 0.984 + two constants x 0.008", Fn(**M), Fn(**D), Constants=2)
    M, D = Texts("clean_microcode", 124, 125)         # v5 = 0.992
    B.Add("v5 0.992 + one constant x 0.008", Fn(**M), Fn(**D), Constants=1)
    M, D = Texts("clean_assembly", 124, 125)
    B.Add("control below: v2 0.992 + source, primes, in", Fn(**M), Fn(**D), Features=("source", "primes", "in"),
          OnBoundary=False)
    M, D = Texts("clean_assembly", 99, 100)
    B.Add("control above: v2 0.99 + source, primes, in + one constant x 0.008", Fn(**M), Fn(**D),
          Features=("source", "primes", "in"), Constants=1, OnBoundary=False)
    return B


def Main():
    Parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    Parser.add_argument("--diaphora-dir", default=os.environ.get("DSIG_DIAPHORA_DIR"))
    Parser.add_argument("--out", default=os.path.join(G.REPO, "tests", "diff", "vectors", "ratio"))
    Args = Parser.parse_args()
    if not Args.diaphora_dir:
        raise SystemExit("pass --diaphora-dir or set DSIG_DIAPHORA_DIR")
    Diaphora, Schema, Heuristics, Env = G.LoadDiaphora(Args.diaphora_dir)

    Calls = []
    Original = Diaphora.CBinDiff.deep_ratio

    def RecordingDeepRatio(Self, MainD, DiffD, Ratio):
        Score = Original(Self, MainD, DiffD, Ratio)
        Calls.append((str(MainD["ea"]), str(DiffD["ea"]), Ratio, Score))
        return Score

    Diaphora.CBinDiff.deep_ratio = RecordingDeepRatio
    Work = tempfile.mkdtemp(prefix="dsig-ratio-clamp-")
    Failures = []
    try:
        for Name, Cases, SameCpu in (("clamp-boundary-same", SameCpuCases(), True),
                                     ("clamp-boundary-other", OtherCpuCases(), False)):
            Calls.clear()
            Doc = G.EvaluatePair(Diaphora, Heuristics, Schema, Env, Name, Cases.Main, Cases.Diff, SameCpu, Work,
                                 Rle=True, Labels=Cases.Labels)
            Doc["generator"] = "tools/parity/gen_ratio_clamp_vectors.py"
            Doc["boundary"] = []
            Columns = len(Cases.Diff)
            for K, Label in enumerate(Cases.Labels):
                Ea1, Ea2 = Cases.Main[K]["address"], Cases.Diff[K]["address"]
                Seen = {(R, S) for A, B, R, S in Calls if A == Ea1 and B == Ea2}
                Outcome = Doc["outcomes"][Doc["results"][K * Columns + K]]
                if len(Seen) != 1:
                    Failures.append(f"{Name} {Label}: deep_ratio saw {sorted(Seen)}")
                    continue
                R, S = Seen.pop()
                OnSum = R + S == 1.0
                if K in Cases.Boundary:
                    if not OnSum or Outcome != G.Hex(CLAMP):
                        Failures.append(f"{Name} {Label}: r {R!r} + score {S!r} = {R + S!r}, outcome {Outcome}")
                    Doc["boundary"].append({"label": Label, "main": K, "diff": K, "r": G.Hex(R), "score": G.Hex(S),
                                            "expected": G.Hex(CLAMP)})
                elif OnSum:
                    Failures.append(f"{Name} {Label}: a control sits on the boundary")
                print(f"{Name}: {Label}: r {R!r} + score {S!r} = {R + S!r} -> {Outcome}")
            Path, _ = G.WriteJson(os.path.join(Args.out, Name + ".json"), Doc)
            print(f"{os.path.basename(Path)}: {Doc['stats']}, {len(Doc['boundary'])} boundary cases")
    finally:
        Diaphora.CBinDiff.deep_ratio = Original
        shutil.rmtree(Work, ignore_errors=True)
    if Failures:
        for Failure in Failures:
            print("FAIL " + Failure, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(Main())
