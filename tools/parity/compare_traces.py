#!/usr/bin/env python3

"""Find where two parity traces, or two snapshot captures, first diverge.

    compare_traces.py <a/trace.jsonl> <b/trace.jsonl> [--context 30] [--events add_match,cleanup,...]
    compare_traces.py <capture dir a> <capture dir b> [--all] [--ignore FIELD ...]
    compare_traces.py <a/snapshots/X.json> <b/snapshots/X.json>
    compare_traces.py --self-test [--trace <trace.jsonl>] [--snapshots <capture dir>]

Traces: reports the first divergent event with `--context` events
before it and after it on each side, plus per-(heuristic, stage) counts of
add_match events on each side (appended / duplicate / rejected_better, keyed by
the event's `ctx`). Events are compared as parsed JSON objects, so key order
and whitespace never matter; `seq` is ignored by default because it only
numbers events. When exactly one side carries `row` events (a `--rows` or
`--trace-rows` capture against one without), row events are left out on both
sides and a note says so.

Capture directories (a directory holding index.json and snapshots/): walks the
points in order and reports the first point whose snapshots differ at S-L2,
with an item-level diff (`--all` goes on past the first).

Exit code 0 when equal, 1 when different, 2 on usage errors.
"""

import argparse
import collections
import copy
import itertools
import json
import os
import shutil
import sys
import tempfile

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import snapshot as Snap  # noqa: E402

TRACE_IGNORE = ("seq",)


# ----------------------------------------------------------------------------- traces

def _CountRowEvents(Path):
    Count = 0
    with open(Path, "r", encoding="utf-8") as Handle:
        for Line in Handle:
            if '"ev":"row"' in Line or '"ev": "row"' in Line:
                Count += 1
    return Count


def _Normalise(Event, Ignore):
    return {Key: Value for Key, Value in Event.items() if Key not in Ignore}


def _Filtered(Path, Events):
    """(index, line number, event) of the events whose type is kept."""
    Index = 0
    for Line, Event in Snap.ReadTrace(Path):
        if Events is not None and Event.get("ev") not in Events:
            continue
        yield Index, Line, Event
        Index += 1


def CompareTraceFiles(PathA, PathB, Ignore=TRACE_IGNORE, Context=30, Events=None, Prefix=False):
    """Compare two trace files event by event. Returns a report dict with
    `identical`, `events` [count a, count b], `first_divergence` (index into
    the compared stream, the two file line numbers, both events, the context)
    and `add_match_counts` per ctx. With Prefix, trace A may end early (a
    --stop-at capture): events of B past the end of A are not a divergence."""
    Ignore = set(Ignore or ())
    Report = {"a": PathA, "b": PathB, "ignored_fields": sorted(Ignore)}
    if Events is None:
        RowsA, RowsB = _CountRowEvents(PathA), _CountRowEvents(PathB)
        if (RowsA == 0) != (RowsB == 0):
            Events = {"add_match", "cleanup", "point"}
            Report["note"] = ("row events only on one side (%d vs %d); compared add_match, cleanup and point "
                              "events only" % (RowsA, RowsB))
    Report["event_types"] = sorted(Events) if Events is not None else "all"
    Before = collections.deque(maxlen=Context)
    Counts = {"a": {}, "b": {}}
    Divergence = None
    AfterA, AfterB = [], []
    Total = [0, 0]

    def Count(Side, Event):
        if Event.get("ev") != "add_match":
            return
        PerCtx = Counts[Side].setdefault(str(Event.get("ctx")), {})
        Result = str(Event.get("result"))
        PerCtx[Result] = PerCtx.get(Result, 0) + 1

    for EntryA, EntryB in itertools.zip_longest(_Filtered(PathA, Events), _Filtered(PathB, Events)):
        if EntryA is not None:
            Total[0] += 1
            Count("a", EntryA[2])
        if EntryB is not None:
            Total[1] += 1
            Count("b", EntryB[2])
        NormA = _Normalise(EntryA[2], Ignore) if EntryA is not None else None
        NormB = _Normalise(EntryB[2], Ignore) if EntryB is not None else None
        if Divergence is None:
            if EntryA is None and Prefix:
                continue
            if NormA == NormB:
                Before.append((EntryA[0], EntryA[1], EntryB[1], EntryA[2]))
                continue
            Index = EntryA[0] if EntryA is not None else EntryB[0]
            Divergence = {"index": Index,
                          "line_a": EntryA[1] if EntryA is not None else None,
                          "line_b": EntryB[1] if EntryB is not None else None,
                          "a": EntryA[2] if EntryA is not None else None,
                          "b": EntryB[2] if EntryB is not None else None,
                          "differing_fields": sorted(Key for Key in set(NormA or {}) | set(NormB or {})
                                                     if (NormA or {}).get(Key) != (NormB or {}).get(Key)),
                          "before": [{"index": I, "line_a": La, "line_b": Lb, "event": E}
                                     for I, La, Lb, E in Before]}
            continue
        if EntryA is not None and len(AfterA) < Context:
            AfterA.append({"index": EntryA[0], "line": EntryA[1], "event": EntryA[2]})
        if EntryB is not None and len(AfterB) < Context:
            AfterB.append({"index": EntryB[0], "line": EntryB[1], "event": EntryB[2]})
    Report["events"] = Total
    Report["prefix_mode"] = Prefix
    Report["identical"] = Divergence is None
    if Divergence is not None:
        Divergence["after_a"] = AfterA
        Divergence["after_b"] = AfterB
        Report["first_divergence"] = Divergence
    Table = []
    for Ctx in sorted(set(Counts["a"]) | set(Counts["b"]), key=_CtxOrder):
        A, B = Counts["a"].get(Ctx, {}), Counts["b"].get(Ctx, {})
        Table.append({"ctx": Ctx, "a": A, "b": B, "equal": A == B})
    Report["add_match_counts"] = Table
    return Report


def _CtxOrder(Ctx):
    Parts = Ctx.split(":")
    return [(0, int(P)) if P.isdigit() else (1, P) for P in Parts]


def PrintTraceReport(Report, Out=sys.stdout):
    W = Out.write
    W("a: %s\nb: %s\n" % (Report["a"], Report["b"]))
    if Report.get("note"):
        W("note: %s\n" % Report["note"])
    W("events compared: %d vs %d (ignoring fields %s)\n" % (Report["events"][0], Report["events"][1],
                                                            ", ".join(Report["ignored_fields"]) or "none"))
    if Report["identical"]:
        W("IDENTICAL\n")
    else:
        D = Report["first_divergence"]
        W("FIRST DIVERGENCE at event #%d (a line %s, b line %s); fields: %s\n" % (
            D["index"], D["line_a"], D["line_b"], ", ".join(D["differing_fields"])))
        W("--- %d events of shared context before it:\n" % len(D["before"]))
        for Entry in D["before"]:
            W("  = #%-7d %s\n" % (Entry["index"], Snap.DumpJson(Entry["event"])))
        W("  a #%-7d %s\n" % (D["index"], Snap.DumpJson(D["a"])))
        W("  b #%-7d %s\n" % (D["index"], Snap.DumpJson(D["b"])))
        W("--- next %d events of a:\n" % len(D["after_a"]))
        for Entry in D["after_a"]:
            W("  a #%-7d %s\n" % (Entry["index"], Snap.DumpJson(Entry["event"])))
        W("--- next %d events of b:\n" % len(D["after_b"]))
        for Entry in D["after_b"]:
            W("  b #%-7d %s\n" % (Entry["index"], Snap.DumpJson(Entry["event"])))
    W("add_match events per ctx (appended/duplicate/rejected_better), a | b:\n")
    for Row in Report["add_match_counts"]:
        def Fmt(C):
            return "%d/%d/%d" % (C.get("appended", 0), C.get("duplicate", 0), C.get("rejected_better", 0))
        W("  %s %-45s %-14s | %-14s\n" % (" " if Row["equal"] else "*", Row["ctx"], Fmt(Row["a"]), Fmt(Row["b"])))


# ----------------------------------------------------------------------------- snapshots

def _Keyed(Entries):
    """[(key, entry)] where key = (point, occurrence) so repeated names pair up."""
    Seen, Out = {}, []
    for Entry in Entries:
        Occurrence = Seen.get(Entry[1], 0)
        Seen[Entry[1]] = Occurrence + 1
        Out.append(((Entry[1], Occurrence), Entry))
    return Out


def CompareSnapshotDirs(DirA, DirB, Ignore=Snap.DEFAULT_IGNORE, Limit=10, All=False, Prefix=False):
    """Walk the points of capture A in order and compare each with the same
    point of capture B. Returns a report dict with `identical`,
    `points_compared`, `first_difference` and the structural differences.
    With Prefix, capture A may stop early (--stop-at): B's points after A's
    last point are expected and not a difference."""
    EntriesA, EntriesB = Snap.ReadIndex(DirA), Snap.ReadIndex(DirB)
    KeyedA, KeyedB = _Keyed(EntriesA), _Keyed(EntriesB)
    MapB = dict(KeyedB)
    Report = {"a": DirA, "b": DirB, "points_a": len(EntriesA), "points_b": len(EntriesB),
              "ignored_fields": sorted(Ignore)}
    NamesA, NamesB = [K for K, _ in KeyedA], [K for K, _ in KeyedB]
    Report["only_in_a"] = ["%s#%d" % K for K in NamesA if K not in MapB][:Limit]
    SetA = set(NamesA)
    OnlyB = [K for K in NamesB if K not in SetA]
    if Prefix and NamesA:
        Last = NamesB.index(NamesA[-1]) if NamesA[-1] in NamesB else len(NamesB)
        Report["points_after_prefix"] = len(NamesB) - Last - 1
        OnlyB = [K for K in OnlyB if NamesB.index(K) < Last]
    Report["only_in_b"] = ["%s#%d" % K for K in OnlyB][:Limit]
    Common = [K for K in NamesA if K in MapB]
    CommonB = [K for K in NamesB if K in SetA]
    OrderIndex = next((I for I in range(len(Common)) if Common[I] != CommonB[I]), None)
    Report["order_differs_at"] = None if OrderIndex is None else {"a": "%s#%d" % Common[OrderIndex],
                                                                  "b": "%s#%d" % CommonB[OrderIndex]}
    Compared, Skipped, Differences = 0, 0, []
    for Key, EntryA in KeyedA:
        EntryB = MapB.get(Key)
        if EntryB is None:
            continue
        if EntryA[2] is None or EntryB[2] is None:
            Skipped += 1
            continue
        SnapA, SnapB = Snap.LoadSnapshot(DirA, EntryA), Snap.LoadSnapshot(DirB, EntryB)
        Compared += 1
        Diffs = Snap.CompareSnapshots(SnapA, SnapB, Ignore=Ignore, Limit=Limit)
        if Diffs:
            Differences.append({"point": Key[0], "occurrence": Key[1], "seq_a": EntryA[0], "seq_b": EntryB[0],
                                "file_a": EntryA[2], "file_b": EntryB[2], "diffs": Diffs})
            if not All:
                break
    Report["points_compared"] = Compared
    Report["points_without_snapshot"] = Skipped
    Report["differences"] = Differences
    if Differences:
        Report["first_difference"] = Differences[0]
    Report["identical"] = (not Differences and not Report["only_in_a"] and not Report["only_in_b"]
                           and OrderIndex is None)
    return Report


def PrintSnapshotReport(Report, Out=sys.stdout, Limit=10):
    W = Out.write
    W("a: %s (%d points)\nb: %s (%d points)\n" % (Report["a"], Report["points_a"], Report["b"], Report["points_b"]))
    W("snapshots compared: %d (skipped %d without a file on one side)\n" % (
        Report["points_compared"], Report["points_without_snapshot"]))
    if Report["only_in_a"]:
        W("points only in a: %s\n" % ", ".join(Report["only_in_a"]))
    if Report["only_in_b"]:
        W("points only in b: %s\n" % ", ".join(Report["only_in_b"]))
    if Report["order_differs_at"]:
        W("point order differs: a has %s where b has %s\n" % (Report["order_differs_at"]["a"],
                                                              Report["order_differs_at"]["b"]))
    for Index, Difference in enumerate(Report["differences"]):
        W("%s DIFFERENCE at point %s (seq a %s, seq b %s)\n" % ("FIRST" if Index == 0 else "NEXT",
                                                                Difference["point"], Difference["seq_a"],
                                                                Difference["seq_b"]))
        W(Snap.FormatDifferences(Difference["diffs"], Limit) + "\n")
    W("IDENTICAL\n" if Report["identical"] else "DIFFERENT\n")


def CompareSnapshotFiles(PathA, PathB, Ignore, Limit):
    Diffs = Snap.CompareSnapshots(Snap.ReadJson(PathA), Snap.ReadJson(PathB), Ignore=Ignore, Limit=Limit)
    return {"a": PathA, "b": PathB, "identical": not Diffs, "diffs": Diffs}


# ----------------------------------------------------------------------------- self-test

def _SyntheticTrace(Path):
    Events = []
    Sizes = {"best": 0, "partial": 0, "unreliable": 0}
    Seq = 0
    for Step in range(60):
        Events.append({"ev": "point", "name": "before:heuristic:%d" % Step, **Sizes})
        for Item in range(3):
            Chooser = "best" if Item == 0 else "partial"
            Sizes[Chooser] += 1
            Events.append({"ev": "add_match", "seq": Seq, "ctx": "heuristic:%d" % Step, "name1": "f%d_%d" % (Step, Item),
                           "name2": "g%d_%d" % (Step, Item), "ea1": str(4096 + Step), "ea2": str(8192 + Item),
                           "desc": "synthetic", "ratio_bits": Snap.RatioBits(1.0 / (Item + 1)), "chooser": Chooser,
                           "result": "appended"})
            Seq += 1
        Events.append({"ev": "cleanup", "site": 1551, "n": Step + 1, **Sizes})
        Events.append({"ev": "point", "name": "after:heuristic:%d" % Step, **Sizes})
    _WriteTrace(Path, Events)
    return Events


def _WriteTrace(Path, Events):
    with open(Path, "w", encoding="utf-8", newline="\n") as Handle:
        for Event in Events:
            Handle.write(Snap.DumpJson(Event) + "\n")


def _LoadEvents(Path):
    return [Event for _, Event in Snap.ReadTrace(Path)]


def _Mutate(Event):
    Event = copy.deepcopy(Event)
    if Event.get("ev") == "add_match":
        Event["ratio_bits"] = Snap.RatioBits(Snap.BitsToFloat(Event["ratio_bits"]) + 2 ** -40)
    elif Event.get("ev") == "row":
        Event["decision"] = "below_min" if Event.get("decision") != "below_min" else "has_better"
    elif Event.get("ev") in ("cleanup", "point"):
        Event["best"] = Event.get("best", 0) + 1
    else:
        Event["planted"] = True
    return Event


def SelfTest(TracePath=None, SnapshotDir=None):
    """Plant divergences and check that they are reported at the right place."""
    Results = []
    Work = tempfile.mkdtemp(prefix="compare_traces_selftest_")
    try:
        Base = os.path.join(Work, "base.jsonl")
        if TracePath:
            shutil.copyfile(TracePath, Base)
            Events = _LoadEvents(Base)
        else:
            Events = _SyntheticTrace(Base)
        N = len(Events)
        AddMatch = [I for I, E in enumerate(Events) if E.get("ev") == "add_match"]
        Positions = sorted(set([0, N // 2, N - 1] + ([AddMatch[len(AddMatch) // 3]] if AddMatch else [])))

        def Check(Name, Mutated, Expected):
            Path = os.path.join(Work, "mut.jsonl")
            _WriteTrace(Path, Mutated)
            Report = CompareTraceFiles(Base, Path, Context=5)
            Got = None if Report["identical"] else Report["first_divergence"]["index"]
            Results.append({"case": Name, "expected": Expected, "reported": Got, "ok": Got == Expected})

        Norm = [_Normalise(E, set(TRACE_IGNORE)) for E in Events]

        def AfterDeletion(K):
            # Deleting event K shifts the stream; the first visible difference is
            # the first I >= K whose event differs from its successor.
            I = K
            while I < N - 1 and Norm[I] == Norm[I + 1]:
                I += 1
            return I

        Check("identical copy", Events, None)
        Check("seq renumbered only", [dict(E, seq=E["seq"] + 1000) if "seq" in E else E for E in Events], None)
        Check("keys reordered only", [dict(reversed(list(E.items()))) for E in Events], None)
        for K in Positions:
            Check("changed event %d (%s)" % (K, Events[K].get("ev")), Events[:K] + [_Mutate(Events[K])] + Events[K + 1:], K)
            Check("deleted event %d" % K, Events[:K] + Events[K + 1:], AfterDeletion(K))
            Check("inserted before event %d" % K, Events[:K] + [{"ev": "point", "name": "planted", "best": 0,
                                                                 "partial": 0, "unreliable": 0}] + Events[K:], K)
        Check("truncated after event %d" % (N // 2), Events[:N // 2], N // 2)

        if SnapshotDir:
            Results.extend(_SnapshotSelfTest(SnapshotDir, Work))
    finally:
        shutil.rmtree(Work, ignore_errors=True)
    Ok = all(R["ok"] for R in Results)
    for R in Results:
        print("%s %-45s expected %-12s reported %s" % ("PASS" if R["ok"] else "FAIL", R["case"],
                                                      R["expected"], R["reported"]))
    print("compare_traces self-test: %d/%d checks passed" % (sum(R["ok"] for R in Results), len(Results)))
    return Ok


def _SnapshotSelfTest(SnapshotDir, Work):
    Results = []
    Copy = os.path.join(Work, "capture")
    os.makedirs(os.path.join(Copy, "snapshots"))
    shutil.copyfile(os.path.join(SnapshotDir, "index.json"), os.path.join(Copy, "index.json"))
    Entries = [E for E in Snap.ReadIndex(SnapshotDir) if E[2]]
    for Entry in Entries:
        shutil.copyfile(os.path.join(SnapshotDir, Entry[2]), os.path.join(Copy, Entry[2]))

    def Run(Name, ExpectedPoint, ExpectedField, ExpectedIndex=None):
        Report = CompareSnapshotDirs(SnapshotDir, Copy)
        First = Report.get("first_difference")
        Got = None if First is None else (First["point"], First["diffs"][0]["field"],
                                          First["diffs"][0].get("first_index"))
        Want = None if ExpectedPoint is None else (ExpectedPoint, ExpectedField, ExpectedIndex)
        Results.append({"case": Name, "expected": Want, "reported": Got, "ok": Got == Want})

    Run("snapshot copy identical", None, None)
    # Plant a ratio change in the middle point that has partial items.
    Candidates = [E for E in Entries if Snap.ReadJson(os.path.join(SnapshotDir, E[2]))["all_matches"]["partial"]]
    if Candidates:
        Target = Candidates[len(Candidates) // 2]
        Path = os.path.join(Copy, Target[2])
        Obj = Snap.ReadJson(Path)
        Index = len(Obj["all_matches"]["partial"]) // 2
        Obj["all_matches"]["partial"][Index][5] = Snap.RatioBits(Snap.BitsToFloat(Obj["all_matches"]["partial"][Index][5])
                                                                 + 2 ** -45)
        Snap.WriteJsonAtomic(Path, Obj)
        Run("planted partial ratio change at %s[%d]" % (Target[1], Index), Target[1], "all_matches.partial", Index)
        shutil.copyfile(os.path.join(SnapshotDir, Target[2]), Path)
    # Plant a matched_primary change in the last point.
    Last = Entries[-1]
    Path = os.path.join(Copy, Last[2])
    Obj = Snap.ReadJson(Path)
    if Obj["matched_primary"]:
        Obj["matched_primary"][0][1] = "planted_name"
        Snap.WriteJsonAtomic(Path, Obj)
        Run("planted matched_primary change at %s" % Last[1], Last[1], "matched_primary")
        shutil.copyfile(os.path.join(SnapshotDir, Last[2]), Path)
    return Results


# ----------------------------------------------------------------------------- main

def Main():
    Parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                     formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    Parser.add_argument("a", nargs="?")
    Parser.add_argument("b", nargs="?")
    Parser.add_argument("--context", type=int, default=30, help="events of context around the divergence")
    Parser.add_argument("--events", help="comma-separated event types to compare (default: all)")
    Parser.add_argument("--ignore", action="append", default=None,
                        help="field to ignore (repeatable; default seq for traces, seq+producer for snapshots)")
    Parser.add_argument("--all", action="store_true", help="snapshots: report every differing point")
    Parser.add_argument("--prefix", action="store_true",
                        help="a is a --stop-at capture: what b has past a's end is not a difference")
    Parser.add_argument("--limit", type=int, default=10, help="items shown per difference")
    Parser.add_argument("--json", help="also write the report as JSON to this file")
    Parser.add_argument("--self-test", action="store_true", help="plant divergences and check the reports")
    Parser.add_argument("--trace", help="--self-test: a real trace to mutate (default: synthetic)")
    Parser.add_argument("--snapshots", help="--self-test: a capture directory to mutate")
    Args = Parser.parse_args()

    if Args.self_test:
        return 0 if SelfTest(Args.trace, Args.snapshots) else 1
    if not Args.a or not Args.b:
        Parser.error("two traces, two capture directories or two snapshot files are required")
    if os.path.isdir(Args.a) and os.path.isdir(Args.b):
        Ignore = tuple(Args.ignore) if Args.ignore is not None else Snap.DEFAULT_IGNORE
        Report = CompareSnapshotDirs(Args.a, Args.b, Ignore=Ignore, Limit=Args.limit, All=Args.all,
                                     Prefix=Args.prefix)
        PrintSnapshotReport(Report, Limit=Args.limit)
    elif os.path.isfile(Args.a) and os.path.isfile(Args.b) and Args.a.endswith(".jsonl"):
        Events = set(Args.events.split(",")) if Args.events else None
        Ignore = tuple(Args.ignore) if Args.ignore is not None else TRACE_IGNORE
        Report = CompareTraceFiles(Args.a, Args.b, Ignore=Ignore, Context=Args.context, Events=Events,
                                   Prefix=Args.prefix)
        PrintTraceReport(Report)
    elif os.path.isfile(Args.a) and os.path.isfile(Args.b):
        Ignore = tuple(Args.ignore) if Args.ignore is not None else Snap.DEFAULT_IGNORE
        Report = CompareSnapshotFiles(Args.a, Args.b, Ignore, Args.limit)
        print(Snap.FormatDifferences(Report["diffs"], Args.limit) if Report["diffs"] else "IDENTICAL")
    else:
        Parser.error("arguments must be two files or two directories")
    if Args.json:
        with open(Args.json, "w", encoding="utf-8") as Handle:
            json.dump(Report, Handle, indent=1, ensure_ascii=False)
    return 0 if Report["identical"] else 1


if __name__ == "__main__":
    sys.exit(Main())
