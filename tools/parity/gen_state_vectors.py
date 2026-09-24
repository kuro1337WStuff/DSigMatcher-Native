#!/usr/bin/env python3
"""Match-state-machine vectors (specs docs/parity/01-driver.md §8-§10, 02-matching.md §6-§16).

Every expected value comes from the REAL, unmodified Diaphora: a CBinDiff whose match-state methods
are called directly on synthetic data, exactly like the spec probes did (02 Appendix A probes 1, 6
and 10; 01 E2). Covered:

  add_match (D:1340-1374), has_best_match / has_better_match (D:1376-1402), cleanup_matches
  (D:1554-1605), all_functions_matched (D:1777-1784), get_sorted_results / get_total_matched_functions
  (D:3133-3148), check_match + add_matches_internal + the four add_matches_from_* wrappers
  (D:1786-2083) over a fake cursor, final_pass (D:2937-2948 with D:2718-2935) and find_unmatched
  (D:2323-2356), including Python int() of odd address texts at D:280, D:286/D:288 and D:1935 (with
  the digit limit that diaphora.py switches off at D:96-97).

Only check_ratio is replaced (by a table of scripted ratios per (ea, ea2), or a raise), and the
cursors are fakes that hand out scripted rows; everything else is Diaphora's own code. The row and
add_match outcomes are classified exactly like tools/parity/oracle_trace.py does (WrapRows,
WrapAddMatch), so the native trace events can be compared one to one.

Usage
  python -B gen_state_vectors.py [--diaphora-dir DIR] [--out DIR] [--seed N] [--random N]

Paths come from flags or the environment only: --diaphora-dir / DSIG_DIAPHORA_DIR; --out defaults to
tests/diff/vectors/state in this repository. All data is synthetic (no corpus names). Diaphora is
imported read-only (sys.dont_write_bytecode); CBinDiff's constructor opens a database read/write
(create_schema), so it is given a fresh file in a temporary directory that is deleted afterwards.
Run with the oracle's Python (CPython 3.13.12); the environment is recorded in every output.
"""
import argparse
import contextlib
import io
import json
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import threading

sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
SCHEMA_ID = "dsig-state-vectors/1"
_MISSING = object()


def Hex(Value):
    """IEEE-754 bits of float(x) as 16 lowercase hex digits (the snapshot schema's ratio_bits)."""
    return struct.pack(">d", float(Value)).hex()


def Git(Dir, *ArgList):
    return subprocess.run(["git", "-C", Dir] + list(ArgList), capture_output=True, text=True).stdout.strip()


def LoadDiaphora(Dir):
    for Key in [K for K in os.environ if K.upper().startswith("DIAPHORA_")]:
        del os.environ[Key]  # build_oracle.CleanEnv() semantics: the default configuration (01 §2)
    sys.path.insert(0, Dir)
    import diaphora  # noqa: E402  (the unmodified checkout)
    Env = {
        "python": sys.version.split()[0],
        "diaphora": Git(Dir, "describe", "--tags", "--long", "--dirty"),
        "diaphora_status_clean": Git(Dir, "status", "--porcelain") == "",
    }
    return diaphora, Env


# ------------------------------------------------------------------------------------------------
# JSON encodings shared with tests/diff/state_tests.cpp

def EncItem(It):
    """[ea1, name1, ea2, name2, desc, ratio_bits, nodes1, nodes2] (the snapshot item layout)."""
    return [It[0], It[1], It[2], It[3], It[4], Hex(It[5]), int(It[6]), int(It[7])]


def EncDict(D):
    return [[K, V["name"], Hex(V["ratio"])] for K, V in D.items()]


def EncState(Bd):
    return {"best": [EncItem(I) for I in Bd.all_matches["best"]],
            "partial": [EncItem(I) for I in Bd.all_matches["partial"]],
            "unreliable": [EncItem(I) for I in Bd.all_matches["unreliable"]],
            "mp": EncDict(Bd.matched_primary), "ms": EncDict(Bd.matched_secondary)}


def Sizes(Bd):
    """[len(best), len(partial), len(unreliable), len(matched_primary), len(matched_secondary)]."""
    return [len(Bd.all_matches["best"]), len(Bd.all_matches["partial"]), len(Bd.all_matches["unreliable"]),
            len(Bd.matched_primary), len(Bd.matched_secondary)]


def EncChooserRaw(Chooser):
    return list(getattr(Chooser, "_dsig_raw", [])) if Chooser is not None else None


class FakeRow(dict):
    """A sqlite3.Row stand-in: row["alias"] (a missing alias reads as None, like the NULL columns
    check_match copies into main_d/diff_d) and row[index]."""

    def __init__(self, Values, Order):
        super().__init__(Values)
        self._order = Order

    def __missing__(self, Key):
        if isinstance(Key, int):
            return self[self._order[Key]]
        return None


class FakeCursor:
    """cur.execute / fetchone / fetchall / close over scripted rows (the SQL text is not run)."""

    def __init__(self, Rows=None, BySql=None):
        self.Rows = list(Rows or [])
        self.BySql = BySql
        self.Fetched = 0

    def execute(self, Sql, *Args):
        if self.BySql is not None:
            self.Rows = list(self.BySql(Sql))
        return self

    def fetchone(self):
        if not self.Rows:
            return None
        self.Fetched += 1
        return self.Rows.pop(0)

    def fetchall(self):
        Out, self.Rows = self.Rows, []
        self.Fetched += len(Out)
        return Out

    def close(self):
        pass


# ------------------------------------------------------------------------------------------------
# The instrumented CBinDiff

class Machine:
    def __init__(self, D, WorkDir):
        self.D = D
        # CBinDiff.__init__ (D:374-493) runs open_db/create_schema on db_name: a fresh scratch file.
        self.Bd = D.CBinDiff(os.path.join(WorkDir, "state_vectors.sqlite"))
        threading.current_thread().timeout = False  # set by diff() at D:3595-3596 on the main thread
        self.Events = None
        self.Ratios = {}
        self.InstallChooserHook()
        self.WrapRows()
        self.WrapAddMatch()
        self.Bd.check_ratio = self.FakeCheckRatio

    def Reset(self, Totals):
        Bd = self.Bd
        Bd.all_matches = {"best": [], "partial": [], "unreliable": []}
        Bd.matched_primary = {}
        Bd.matched_secondary = {}
        Bd.total_functions1, Bd.total_functions2 = Totals
        Bd.ratios_cache = {}
        Bd.sql_max_processed_rows = self.D.config.SQL_MAX_PROCESSED_ROWS
        Bd.hooks = None
        Bd.create_choosers()  # D:2358-2372 (as __init__ does at D:426) ...
        Bd.unmatched_primary = None  # ... then D:438-439
        Bd.unmatched_second = None
        self.Ratios = {}

    def InstallChooserHook(self):
        """Record the raw fields every CChooser.add_item call receives, like oracle_trace.py
        InstallChooserHook (the class is patched in memory only)."""
        Cls = self.D.CChooser
        Original = Cls.__dict__["add_item"]

        def add_item(chooser_self, item):
            Result = Original(chooser_self, item)
            if chooser_self.title.startswith("Unmatched in"):
                Raw = [item.ea, item.vfname]
            else:
                Raw = [item.ea, item.vfname, item.ea2, item.vfname2, item.description, Hex(item.ratio),
                       item.nodes1, item.nodes2]
            if not hasattr(chooser_self, "_dsig_raw"):
                chooser_self._dsig_raw = []
            chooser_self._dsig_raw.append(Raw)
            return Result

        Cls.add_item = add_item

    def FakeCheckRatio(self, main_d, diff_d, *Args, **Kwargs):
        Value = self.Ratios[(main_d["ea"], diff_d["ea"])]
        if Value == "raise":
            raise ValueError("scripted check_ratio failure")
        return Value

    def Emit(self, Event):
        if self.Events is not None:
            self.Events.append(Event)

    def WrapAddMatch(self):
        """oracle_trace.py WrapAddMatch: the result is inferred from the effect."""
        Bd, M = self.Bd, self
        Original = Bd.add_match

        def add_match(name1, name2, ratio, item, chooser):
            List0 = Bd.all_matches.get(chooser) if isinstance(chooser, str) else None
            Len0 = len(List0) if isinstance(List0, list) else None
            Prev = Bd.matched_primary.get(name1, _MISSING)
            Result = Original(name1, name2, ratio, item, chooser)
            List1 = Bd.all_matches.get(chooser) if isinstance(chooser, str) else None
            if Len0 is not None and List1 is List0 and len(List1) > Len0:
                Outcome = "appended"
            else:
                Outcome = "duplicate" if Bd.matched_primary.get(name1, _MISSING) is not Prev else "rejected_better"
            M.Emit(["add", Outcome, Hex(ratio), chooser])
            return Result

        Bd.add_match = add_match

    def WrapRows(self):
        """oracle_trace.py WrapRows: one row event per check_match call, classified the same way."""
        Bd, M, D = self.Bd, self, self.D
        OrigInternal = Bd.add_matches_internal
        OrigCheckMatch = Bd.check_match
        PartialRatio = D.config.DEFAULT_PARTIAL_RATIO
        Routing = []

        def add_matches_internal(cur, best, partial, val=None, unreliable=None, debug=False):
            Routing.append((best, partial, val, unreliable))
            try:
                return OrigInternal(cur, best, partial, val=val, unreliable=unreliable, debug=debug)
            finally:
                Routing.pop()

        def check_match(row, ratio=None, debug=False):
            Frame = sys._getframe(1)
            Caller = Frame.f_code.co_name
            del Frame
            try:
                Result = OrigCheckMatch(row, ratio=ratio, debug=debug)
            except BaseException:
                M.Emit(["row", "raised", None])
                raise
            ShouldAdd, R = Result
            if ShouldAdd:
                Decision = "accepted"
                if Caller == "add_matches_internal":
                    Best, Partial, Val, Unreliable = Routing[-1]
                    if Val is None:
                        Val = PartialRatio
                    if R == 1.0:
                        Decision = "accepted_best"
                    elif R >= Val and Partial is not None:
                        Decision = "accepted_partial"
                    elif R < PartialRatio and R > Val and Unreliable is not None:
                        Decision = "accepted_unreliable"
                    else:
                        Decision = "below_min"
                elif Caller == "add_matches_from_query":
                    Decision = "accepted_best"
                M.Emit(["row", Decision, Hex(R)])
            else:
                Name1, Name2 = row["name1"], row["name2"]
                if Name1.startswith("nullsub_") or Name2.startswith("nullsub_"):
                    M.Emit(["row", "nullsub", None])
                elif Bd.has_best_match(Name1, Name2):
                    M.Emit(["row", "has_best", None])
                else:
                    M.Emit(["row", "has_better", Hex(M.LastRatio(row))])
            return Result

        Bd.add_matches_internal = add_matches_internal
        Bd.check_match = check_match

    def LastRatio(self, Row):
        return self.Ratios[(Row["ea"], Row["ea2"])]

    # --------------------------------------------------------------------------------------------
    # Ops

    def Run(self, Case):
        """Runs Case["ops"] (built by the case builders with Python values) and returns the JSON case
        with every op's "expect"."""
        self.Reset(Case["totals"])
        self.Ratios = dict(Case.get("ratios_py", {}))
        Used = set()
        for Op in Case["ops"]:
            for Row in Op.get("rows", []) if Op["op"] == "consume" else []:
                Used.add((Row[0], Row[2]))
        Out = {"name": Case["name"], "totals": list(Case["totals"]),
               "ratios": [[K[0], K[1], V if V == "raise" else Hex(V)] for K, V in self.Ratios.items() if K in Used],
               "ops": []}
        for Op in Case["ops"]:
            Out["ops"].append(self.RunOp(Op))
        return Out

    def RunOp(self, Op):
        Bd = self.Bd
        Kind = Op["op"]
        Enc = {K: V for K, V in Op.items() if not K.endswith("_py")}
        Expect = {}
        Sink = io.StringIO()
        with contextlib.redirect_stdout(Sink), contextlib.redirect_stderr(Sink):
            if Kind == "set_state":
                St = Op["state_py"]
                Bd.all_matches = {"best": [list(I) for I in St.get("best", [])],
                                  "partial": [list(I) for I in St.get("partial", [])],
                                  "unreliable": [list(I) for I in St.get("unreliable", [])]}
                Bd.matched_primary = {K: {"name": O, "ratio": R} for K, O, R in St.get("mp", [])}
                Bd.matched_secondary = {K: {"name": O, "ratio": R} for K, O, R in St.get("ms", [])}
                Enc["state"] = EncState(Bd)
            elif Kind == "set_totals":
                Bd.total_functions1, Bd.total_functions2 = Op["t1"], Op["t2"]
            elif Kind == "add_match":
                Item = list(Op["item_py"])
                Enc["ratio"] = Hex(Op["ratio_py"])
                Enc["item"] = EncItem(Item)
                self.Events = []
                try:
                    Bd.add_match(Op["n1"], Op["n2"], Op["ratio_py"], Item, Op["chooser"])
                    Expect["result"] = self.Events[-1][1]
                except Exception as Exc:  # noqa: BLE001
                    Expect["result"] = "raised"
                    Expect["error"] = type(Exc).__name__
                self.Events = None
                Entry = Bd.matched_primary.get(Op["n1"], None)
                Expect["mp"] = None if Entry is None else [Entry["name"], Hex(Entry["ratio"])]
                Entry = Bd.matched_secondary.get(Op["n2"], None)
                Expect["ms"] = None if Entry is None else [Entry["name"], Hex(Entry["ratio"])]
                Expect["len"] = len(Bd.all_matches[Op["chooser"]]) if Op["chooser"] is not None else None
            elif Kind == "has_best_match":
                Expect["value"] = bool(Bd.has_best_match(Op["n1"], Op["n2"]))
            elif Kind == "has_better_match":
                Enc["ratio"] = Hex(Op["ratio_py"])
                try:
                    Expect["value"] = bool(Bd.has_better_match(Op["n1"], Op["n2"], Op["ratio_py"]))
                except Exception as Exc:  # noqa: BLE001
                    Expect["raised"] = type(Exc).__name__
            elif Kind == "all_functions_matched":
                Expect["value"] = bool(Bd.all_functions_matched())
            elif Kind == "total_matched":
                Expect["value"] = Bd.get_total_matched_functions()
            elif Kind == "sorted_results":
                Expect["items"] = [EncItem(I) for I in Bd.get_sorted_results(Op["chooser"])]
            elif Kind == "cleanup":
                Bd.cleanup_matches()
                Expect["state"] = EncState(Bd)
            elif Kind == "state":
                Expect["state"] = EncState(Bd)
            elif Kind == "final_pass":
                try:
                    Bd.final_pass()
                    Expect["raised"] = None
                except Exception as Exc:  # noqa: BLE001
                    Expect["raised"] = type(Exc).__name__
                Expect["state"] = EncState(Bd)
                Expect["choosers"] = {"best": EncChooserRaw(Bd.best_chooser),
                                      "partial": EncChooserRaw(Bd.partial_chooser),
                                      "unreliable": EncChooserRaw(Bd.unreliable_chooser),
                                      "multimatch": EncChooserRaw(Bd.multimatch_chooser)}
            elif Kind == "consume":
                Expect.update(self.Consume(Op))
            elif Kind == "find_unmatched":
                Main = [FakeRow({"name": N, "address": A}, ["name", "address"]) for N, A in Op["main"]]
                Diff = [FakeRow({"name": N, "address": A}, ["name", "address"]) for N, A in Op["diff"]]
                Saved = Bd.db_cursor
                Bd.db_cursor = lambda: FakeCursor(BySql=lambda Sql: Diff if "diff.functions" in Sql else Main)
                try:
                    Bd.find_unmatched()
                    Expect["raised"] = None
                except Exception as Exc:  # noqa: BLE001
                    Expect["raised"] = type(Exc).__name__
                finally:
                    Bd.db_cursor = Saved
                Expect["primary"] = EncChooserRaw(Bd.unmatched_primary)
                Expect["secondary"] = EncChooserRaw(Bd.unmatched_second)
            else:
                raise ValueError("unknown op " + Kind)
        Enc["expect"] = Expect
        return Enc

    def Consume(self, Op):
        Bd = self.Bd
        Rows = []
        for Ea, N1, Ea2, N2, Desc, Nodes1, Nodes2 in Op["rows"]:
            Rows.append(FakeRow({"ea": Ea, "name1": N1, "ea2": Ea2, "name2": N2, "description": Desc,
                                 "nodes1": Nodes1, "nodes2": Nodes2}, ["ea", "name1", "ea2", "name2"]))
        Cur = FakeCursor(Rows)
        Saved = Bd.db_cursor
        Bd.db_cursor = lambda: Cur
        Bd.sql_max_processed_rows = Op.get("maxrows", self.D.config.SQL_MAX_PROCESSED_ROWS)
        self.Events = []
        Raised = None
        try:
            Which = Op["kind"]
            if Which == "internal":
                Bd.add_matches_internal(Cur, best=Op["best"], partial=Op["partial"], val=Op["val"])
            elif Which == "from_query":
                Bd.add_matches_from_query("-- scripted rows", Op["category"])
            elif Which == "ratio":
                Bd.add_matches_from_query_ratio("-- scripted rows", Op["best"], Op["partial"])
            elif Which == "ratio_max":
                Bd.add_matches_from_query_ratio_max("-- scripted rows", Op["best"], Op["partial"], Op["val"])
            elif Which == "trusted":
                Bd.add_matches_from_query_ratio_max_trusted("-- scripted rows", Op["val"])
            else:
                raise ValueError(Which)
        except Exception as Exc:  # noqa: BLE001
            Raised = type(Exc).__name__
        finally:
            Bd.db_cursor = Saved
            Bd.sql_max_processed_rows = self.D.config.SQL_MAX_PROCESSED_ROWS
        Events, self.Events = self.Events, None
        return {"fetched": Cur.Fetched, "events": Events, "raised": Raised, "sizes": Sizes(Bd)}


# ------------------------------------------------------------------------------------------------
# Named cases: the documented probes, reproduced with real Diaphora

def I(Ea1, N1, Ea2, N2, Desc, R, A=3, B=3):
    return [Ea1, N1, Ea2, N2, Desc, R, A, B]


def AddOp(N1, N2, R, Item, Chooser):
    return {"op": "add_match", "n1": N1, "n2": N2, "ratio_py": R, "item_py": Item, "chooser": Chooser}


def NamedCases():
    Cases = []
    # 02 Appendix A probe 1 (the spec authors' probe_bookkeeping.py, sections 2-8; the int-ea parts
    # cannot occur, every ea is the address TEXT on every path, 02 §2).
    Cases.append({"name": "probe1_named_shortcircuit", "totals": [100, 100], "ops": [
        AddOp("foo", "bar", 0.9, I("1", "foo", "2", "bar", "h", 0.9), "partial"),
        {"op": "has_better_match", "n1": "foo", "n2": "baz", "ratio_py": 0.5},
        AddOp("foo", "baz", 0.5, I("1", "foo", "3", "baz", "h", 0.5), "partial"),
        {"op": "has_better_match", "n1": "sub_1", "n2": "bar", "ratio_py": 0.5},
        {"op": "has_better_match", "n1": "sub_1", "n2": "bar", "ratio_py": 0.9},
    ]})
    Cases.append({"name": "probe1_same_name_fake", "totals": [100, 100], "ops": [
        AddOp("foo", "foo", 0.7, I("1", "foo", "2", "foo", "h", 0.7), "partial"),
        {"op": "has_better_match", "n1": "foo", "n2": "zzz", "ratio_py": 0.95},
        {"op": "has_best_match", "n1": "foo", "n2": "zzz"},
        {"op": "cleanup"},
        {"op": "has_best_match", "n1": "foo", "n2": "zzz"},
    ]})
    Cases.append({"name": "probe1_cleanup_downgrade", "totals": [100, 100], "ops": [
        AddOp("sub_B", "sub_C", 0.7, I("20", "sub_B", "30", "sub_C", "h", 0.7), "partial"),
        AddOp("sub_A", "sub_C", 0.9, I("10", "sub_A", "30", "sub_C", "h", 0.9), "partial"),
        {"op": "cleanup"},
    ]})
    Cases.append({"name": "probe1_tie", "totals": [100, 100], "ops": [
        AddOp("sub_A", "sub_X", 0.8, I("10", "sub_A", "40", "sub_X", "h1", 0.8), "partial"),
        AddOp("sub_A", "sub_Y", 0.8, I("10", "sub_A", "50", "sub_Y", "h2", 0.8), "partial"),
        {"op": "cleanup"},
    ]})
    Cases.append({"name": "probe1_cross_category", "totals": [100, 100], "ops": [
        AddOp("sub_A", "sub_X", 1.0, I("10", "sub_A", "40", "sub_X", "h1", 1.0), "best"),
        {"op": "set_state", "state_py": {
            "best": [I("10", "sub_A", "40", "sub_X", "h1", 1.0)],
            "partial": [I("10", "sub_A", "40", "sub_X", "h2", 0.8), I("10", "sub_A", "41", "sub_Z", "h3", 0.95),
                        I("11", "sub_Q", "40", "sub_X", "h4", 0.95)],
            "mp": [("sub_A", "sub_X", 1.0)], "ms": [("sub_X", "sub_A", 1.0)]}},
        {"op": "cleanup"},
    ]})
    Cases.append({"name": "probe1_membership_int_float", "totals": [100, 100], "ops": [
        AddOp("sub_A", "sub_X", 1.0, I("10", "sub_A", "40", "sub_X", "h", 1), "best"),
        AddOp("sub_A", "sub_X", 1.0, I("10", "sub_A", "40", "sub_X", "h", 1.0), "best"),
        {"op": "cleanup"},
    ]})
    # D:1369-1374: a duplicate item is not appended, but both dicts are still rewritten (02 §9 item 6).
    Cases.append({"name": "duplicate_item_rewrites_dicts", "totals": [100, 100], "ops": [
        AddOp("sub_A", "sub_X", 0.9, I("10", "sub_A", "40", "sub_X", "h", 0.9), "partial"),
        AddOp("sub_A", "sub_Y", 0.9, I("10", "sub_A", "50", "sub_Y", "h", 0.9), "partial"),
        AddOp("sub_A", "sub_X", 0.9, I("10", "sub_A", "40", "sub_X", "h", 0.9), "partial"),
        {"op": "state"},
    ]})
    Cases.append({"name": "probe1_dones_key_collision", "totals": [100, 100], "ops": [
        {"op": "set_state", "state_py": {"partial": [I("1", "a-b", "2", "c", "h", 0.9), I("3", "a", "4", "b-c", "h", 0.8)]}},
        {"op": "cleanup"},
    ]})
    # 02 Appendix A probe 10 (probe/unit.py): all six cleanup cases, every item ea1 '7' unless shown.
    def P10(Name, Partial, Best=()):
        Cases.append({"name": "probe10_" + Name, "totals": [100, 100], "ops": [
            {"op": "set_state", "state_py": {"best": list(Best), "partial": list(Partial)}},
            {"op": "cleanup"}]})

    def It(N1, N2, R, Ea="7", Ea2="9"):
        return [Ea, N1, Ea2, N2, "d", R, 1, 1]
    P10("doc_example", [It("X", "A", 0.9), It("X", "X", 0.7), It("X", "B", 0.8)])
    P10("no_same_name", [It("X", "A", 0.9), It("X", "B", 0.8)])
    P10("equal_ratios_with_same_name", [It("X", "A", 0.7), It("X", "X", 0.7), It("X", "B", 0.7)])
    P10("equal_ratios_without_same_name", [It("X", "A", 0.7), It("X", "B", 0.7)])
    P10("xcat_tie", [It("X", "X", 0.7)], Best=[It("X", "A", 1.0)])
    P10("dones_before_ea", [It("X", "A", 0.9, Ea="7"), It("Y", "B", 0.8, Ea="7"), It("Y", "B", 0.8, Ea="8")])
    # 02 Appendix A probe 6 (probe_internal.py): add_matches_internal routing over a fake cursor with
    # check_match ratios [1.0, 0.6, 0.45, 0.3, 0.1] and distinct sub_ names.
    Rs = [1.0, 0.6, 0.45, 0.3, 0.1]
    Rows = [[str(100 + K), "sub_A%d" % K, str(200 + K), "sub_B%d" % K, "h", 3, 3] for K in range(len(Rs))]
    Ratios = {(str(100 + K), str(200 + K)): R for K, R in enumerate(Rs)}

    def P6(Name, **Kw):
        Op = {"op": "consume", "rows": Rows}
        Op.update(Kw)
        Cases.append({"name": "probe6_" + Name, "totals": [1000, 1000], "ratios_py": Ratios, "ops": [Op]})
    P6("ratio", kind="ratio", best="best", partial="partial")
    P6("ratio_max_0_2", kind="ratio_max", best="best", partial="partial", val=0.2)
    P6("ratio_max_0_7", kind="ratio_max", best="best", partial="partial", val=0.7)
    P6("trusted_0_44", kind="trusted", val=0.44)
    P6("unreliable_category_ratio", kind="ratio", best="partial", partial="unreliable")
    P6("brute_force_partial_none", kind="internal", best="unreliable", partial=None, val=0.5)
    P6("internal_default", kind="internal", best="best", partial="partial", val=None)
    P6("maxrows_3", kind="internal", best="best", partial="partial", val=None, maxrows=3)
    P6("maxrows_0", kind="internal", best="best", partial="partial", val=None, maxrows=0)
    P6("no_fps", kind="from_query", category="best")
    # 01 E2 (the spec authors' drv/exp_final.py): multimatch split, the dropped same-name 0.9018889.
    Cases.append({"name": "e2_final_pass", "totals": [100, 100], "ops": [
        {"op": "set_state", "state_py": {
            "best": [I("400", "f400", "500", "g500", "best one", 1), I("4096", "same", "4096", "same", "100% equal", 1)],
            "partial": [
                I("100", "a1", "200", "b1", "mm-main", 0.8), I("100", "a1", "300", "b2", "mm-main", 0.8),
                I("600", "a6", "700", "b7", "mm-diff", 0.7), I("800", "a8", "700", "b7", "mm-diff", 0.7),
                I("900", "a9", "1000", "b10", "hi", 0.9), I("900", "a9", "1100", "b11", "lo", 0.6),
                I("1200", "dup", "1300", "dup2", "dup-lo", 0.55), I("1200", "dup", "1300", "dup2", "dup-hi", 0.65),
                I("1400", "nm", "1500", "nm", "same name", 0.9018889),
                I("1400", "zz", "1600", "zz2", "worse for 1400", 0.95),
                I("1700", "r1", "1800", "r2", "round", 0.123456789),
                I("4294967296", "big", "4294967297", "big2", "64bit", 0.51)],
            "unreliable": [I("100", "a1", "200", "b1x", "dup ea pair diff names", 0.8)]}},
        {"op": "cleanup"},
        {"op": "final_pass"},
    ]})
    # 01 §9.4: the D:2933 KeyError needs a dones-skipped twin in a LATER category with a higher ratio
    # (not reachable under the defaults, where unreliable is empty).
    Cases.append({"name": "final_pass_keyerror_nondefault", "totals": [100, 100], "ops": [
        {"op": "set_state", "state_py": {
            "partial": [I("1", "z1", "20", "z2", "z", 0.6), I("1", "n", "2", "n", "x", 0.5)],
            "unreliable": [I("1", "p", "2", "q", "y", 1.0)]}},
        {"op": "final_pass"},
    ]})
    # D:2742-2745: ignore_list.add(ea) runs only when an item of multi[ea] is NEWLY added. Here every
    # item of multi_diff["50"] (A, B) was already added from multi_main (shared dones, D:2905-2912),
    # so "50" stays out of ignore_diff and Z (partial, 3->50, dones-skipped in the first pass behind
    # its lower best twin T) reaches the partial chooser. Not reachable under the defaults (best
    # items are 1.0 there); it pins the literal port of the conditional.
    Cases.append({"name": "final_pass_ignore_only_on_new_add", "totals": [100, 100], "ops": [
        {"op": "set_state", "state_py": {
            "best": [I("1", "a", "50", "e", "hA", 0.5), I("1", "a", "51", "e1", "hA2", 0.5),
                     I("2", "b", "50", "e", "hB", 0.5), I("2", "b", "52", "e2", "hB2", 0.5),
                     I("3", "c", "50", "e", "hT", 0.4)],
            "partial": [I("3", "c2", "50", "e", "hZ", 0.9)]}},
        {"op": "final_pass"},
    ]})
    # find_unmatched (D:2323-2356): labels swapped, name membership, None names, empty tables.
    Cases.append({"name": "unmatched_basic", "totals": [3, 3], "ops": [
        AddOp("f", "g", 0.9, I("10", "f", "20", "g", "h", 0.9), "partial"),
        {"op": "find_unmatched", "main": [["f", "10"], ["only_main", "11"], [None, "12"]],
         "diff": [["g", "20"], ["only_diff", "21"]]},
    ]})
    Cases.append({"name": "unmatched_empty_tables", "totals": [0, 0], "ops": [
        {"op": "find_unmatched", "main": [], "diff": []},
    ]})
    Cases.append({"name": "unmatched_all_matched_main", "totals": [1, 2], "ops": [
        AddOp("f", "f", 0.7, I("10", "f", "20", "f", "h", 0.7), "partial"),
        {"op": "find_unmatched", "main": [["f", "10"]], "diff": [["f", "20"], ["x", "21"]]},
    ]})
    Cases.append({"name": "unmatched_none_key", "totals": [3, 3], "ops": [
        {"op": "set_state", "state_py": {"partial": [I("10", None, "20", "g", "h", 0.9)],
                                         "mp": [(None, "g", 0.9)], "ms": [("g", None, 0.9)]}},
        {"op": "find_unmatched", "main": [[None, "10"], ["None", "11"]], "diff": [[None, "20"], ["g", "21"]]},
    ]})
    Cases.append({"name": "unmatched_bad_address", "totals": [3, 3], "ops": [
        {"op": "find_unmatched", "main": [["a", "10"], ["b", "0x11"]], "diff": [["c", "20"]]},
    ]})
    Cases.append({"name": "unmatched_python_int_forms", "totals": [3, 3], "ops": [
        {"op": "find_unmatched", "main": [["a", " 10 "], ["b", "1_1"], ["c", "+12"], ["d", "-13"], ["e", "0014"]],
         "diff": [["c", "20\t"]]},
    ]})
    # int() of an address text at every site it is evaluated (D:280 find_unmatched, D:286/D:288 final
    # pass add_item, D:1935 add_matches_internal): CPython strips only Py_ISSPACE (space, TAB, LF, VT,
    # FF, CR), not the 0x1c-0x1f separators that str.isspace() accepts. CPython's default limit of
    # 4300 digits does NOT apply: diaphora.py calls sys.set_int_max_str_digits(0) when it is loaded
    # (D:96-97), so the 4301-digit addresses below are accepted.
    Limit, Over = "1" * 4300, "2" * 4301
    Cases.append({"name": "unmatched_int_py_isspace", "totals": [3, 3], "ops": [
        {"op": "find_unmatched", "main": [["a", "\x0b10\x0c"], ["b", "\r11\n"]], "diff": [["c", " \t20"]]},
    ]})
    Cases.append({"name": "unmatched_int_separator_main", "totals": [3, 3], "ops": [
        {"op": "find_unmatched", "main": [["a", "10"], ["b", "\x1c11"]], "diff": [["c", "20"]]},
    ]})
    Cases.append({"name": "unmatched_int_separator_diff", "totals": [3, 3], "ops": [
        {"op": "find_unmatched", "main": [["a", "10"]], "diff": [["c", "20\x1f"]]},
    ]})
    Cases.append({"name": "unmatched_int_digit_limit", "totals": [3, 3], "ops": [
        {"op": "find_unmatched", "main": [["a", Limit], ["b", "0" * 4299 + "7"]],
         "diff": [["c", "1" + "_1" * 4299], ["d", "-" + Limit]]},
    ]})
    Cases.append({"name": "unmatched_int_digit_limit_exceeded", "totals": [3, 3], "ops": [
        {"op": "find_unmatched", "main": [["a", "10"]], "diff": [["c", "0" * 4301]]},
    ]})
    Cases.append({"name": "consume_int_digit_limit", "totals": [100, 100],
                  "ratios_py": {(Limit, "20"): 1.0, (Over, "21"): 0.9}, "ops": [
        {"op": "consume", "kind": "internal", "best": "best", "partial": "partial", "val": None,
         "rows": [[Limit, "sub_A", "20", "sub_B", "h", 3, 3], [Over, "sub_C", "21", "sub_D", "h", 3, 3]]},
    ]})
    Cases.append({"name": "consume_int_separator", "totals": [100, 100],
                  "ratios_py": {("\x0b6", "20"): 1.0, ("\x1c5", "21"): 1.0}, "ops": [
        {"op": "consume", "kind": "internal", "best": "best", "partial": "partial", "val": None,
         "rows": [["\x0b6", "sub_A", "20", "sub_B", "h", 3, 3], ["\x1c5", "sub_C", "21", "sub_D", "h", 3, 3]]},
    ]})
    Cases.append({"name": "final_pass_int_digit_limit", "totals": [100, 100], "ops": [
        {"op": "set_state", "state_py": {
            "best": [I(Limit, "a", "2", "b", "h", 1.0)],
            "partial": [I("3", "c", "4", "d", "h2", 0.9), I("5", "e", Over, "f", "h3", 0.8)]}},
        {"op": "final_pass"},
    ]})
    return Cases


# ------------------------------------------------------------------------------------------------
# Random cases

NAMES = ["sub_1", "sub_2", "sub_3", "sub_4", "f", "g", "h", "a-b", "c", "a", "b-c", "nullsub_1", "None", "sub_"]
EAS1 = ["10", "7", "100", "8", "4294967296"]
EAS2 = ["20", "9", "200", "30", "7"]
DESCS = ["h1", "h2", "Perfect match, same name", "d"]
RATIOS = [1, 1.0, 0.9, 0.8, 0.7, 0.6, 0.5, 0.45, 0.3, 0.30000000000000004, 0.2, 0.0, 0.9018889, 0.99, 0.5000001]
CHOOSERS = ["best", "partial", "unreliable"]


def RandomName(Rng, NoneRate):
    if Rng.random() < NoneRate:
        return None
    return Rng.choice(NAMES)


def RandomItem(Rng, N1, N2, R, Shape):
    Ea1 = Rng.choice(EAS1)
    Ea2 = Rng.choice(EAS2)
    if Shape == "odd_ea" and Rng.random() < 0.3:
        Ea1 = Rng.choice([" 7", "1_0", "x9", "+8"])
    return [Ea1, N1, Ea2, N2, Rng.choice(DESCS), R, Rng.choice([1, 3, 5]), Rng.choice([1, 3, 5])]


def RandomCase(Rng, Index):
    # Shapes: "default" keeps the default-configuration invariants (best items 1.0, partial < 1.0,
    # unreliable empty, no None names); "free" and "odd_ea" do not.
    Shape = Rng.choice(["default", "default", "free", "odd_ea"])
    NoneRate = 0.0 if Shape == "default" else 0.05
    Totals = [Rng.choice([3, 5, 8, 100]), Rng.choice([3, 5, 8, 100])]
    Ratios = {}
    for Ea1 in EAS1:
        for Ea2 in EAS2:
            if Shape != "default" and Rng.random() < 0.05:
                Ratios[(Ea1, Ea2)] = "raise"
            else:
                Ratios[(Ea1, Ea2)] = Rng.choice(RATIOS)
    Ops = []
    for _ in range(Rng.randint(4, 30)):
        Pick = Rng.random()
        Previous = [O for O in Ops if O["op"] == "add_match"]
        if Previous and Rng.random() < 0.1:
            Ops.append(dict(Rng.choice(Previous)))  # the same item again: a duplicate or a re-add
        elif Pick < 0.45:
            N1 = RandomName(Rng, NoneRate)
            N2 = N1 if Rng.random() < 0.2 else RandomName(Rng, NoneRate)
            if Shape == "default":
                Chooser = Rng.choice(["best", "partial"])
                R = 1 if Chooser == "best" else Rng.choice([X for X in RATIOS if float(X) < 1.0])
            else:
                Chooser = Rng.choice(CHOOSERS + [None])
                R = Rng.choice(RATIOS)
            Item = RandomItem(Rng, N1, N2, R, Shape)
            if Shape != "default" and Rng.random() < 0.1:
                Item[1] = RandomName(Rng, NoneRate)  # an item whose names differ from the dict keys
            Ops.append(AddOp(N1, N2, R if Rng.random() < 0.8 else Rng.choice(RATIOS), Item, Chooser))
        elif Pick < 0.52:
            Ops.append({"op": "has_best_match", "n1": RandomName(Rng, NoneRate), "n2": RandomName(Rng, NoneRate)})
        elif Pick < 0.59:
            Ops.append({"op": "has_better_match", "n1": RandomName(Rng, NoneRate), "n2": RandomName(Rng, NoneRate),
                        "ratio_py": Rng.choice(RATIOS)})
        elif Pick < 0.69:
            Ops.append({"op": "cleanup"})
        elif Pick < 0.72:
            Ops.append({"op": "all_functions_matched"})
        elif Pick < 0.74:
            Ops.append({"op": "total_matched"})
        elif Pick < 0.77:
            Ops.append({"op": "sorted_results", "chooser": Rng.choice(CHOOSERS)})
        elif Pick < 0.79:
            Ops.append({"op": "set_totals", "t1": Rng.choice([1, 2, 3, 4, 5, 100]), "t2": Rng.choice([1, 2, 3, 4, 5, 100])})
        else:
            Rows = []
            for _ in range(Rng.randint(0, 12)):
                N1 = RandomName(Rng, NoneRate)
                N2 = N1 if Rng.random() < 0.15 else RandomName(Rng, NoneRate)
                Nodes1 = None if (Shape != "default" and Rng.random() < 0.03) else Rng.choice([1, 3, 5])
                Rows.append([Rng.choice(EAS1), N1, Rng.choice(EAS2), N2, Rng.choice(DESCS), Nodes1, Rng.choice([1, 3, 5])])
            Kind = Rng.choice(["internal", "from_query", "ratio", "ratio_max", "trusted"])
            Op = {"op": "consume", "kind": Kind, "rows": Rows}
            if Kind == "internal":
                Op["best"] = "best"
                Op["partial"] = Rng.choice(["partial", None]) if Shape != "default" else "partial"
                Op["val"] = Rng.choice([None, 0.2, 0.5, 0.7])
            elif Kind == "from_query":
                Op["category"] = "best"
            elif Kind == "ratio":
                Op["best"], Op["partial"] = ("best", "partial") if Shape == "default" else Rng.choice(
                    [("best", "partial"), ("partial", "unreliable")])
            elif Kind == "ratio_max":
                Op["best"], Op["partial"] = "best", "partial"
                Op["val"] = Rng.choice([0.2, 0.449, 0.5, 0.579, 0.7])
            else:
                Op["val"] = Rng.choice([0.44, 0.3, 0.6])
            if Rng.random() < 0.1:
                Op["maxrows"] = Rng.choice([0, 1, 2, 5])
            Ops.append(Op)
    Ops.append({"op": "state"})
    if Rng.random() < 0.5:
        Ops.append({"op": "cleanup"})
    Ops.append({"op": "final_pass"})
    if Rng.random() < 0.5:
        Used1, Used2 = set(), set()
        Main, Diff = [], []
        for _ in range(Rng.randint(0, 6)):
            Ea = Rng.choice(EAS1 + ["11", "12", "13"])
            if Ea not in Used1:
                Used1.add(Ea)
                Main.append([RandomName(Rng, 0.1), Ea])
        for _ in range(Rng.randint(0, 6)):
            Ea = Rng.choice(EAS2 + ["21", "22", "23"])
            if Ea not in Used2:
                Used2.add(Ea)
                Diff.append([RandomName(Rng, 0.1), Ea])
        Ops.append({"op": "find_unmatched", "main": Main, "diff": Diff})
    return {"name": "random_%04d_%s" % (Index, Shape), "totals": Totals, "ratios_py": Ratios, "ops": Ops}


# ------------------------------------------------------------------------------------------------

def Main():
    Parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    Parser.add_argument("--diaphora-dir", default=os.environ.get("DSIG_DIAPHORA_DIR"))
    Parser.add_argument("--out", default=os.path.join(REPO, "tests", "diff", "vectors", "state"))
    Parser.add_argument("--seed", type=int, default=20260923)
    Parser.add_argument("--random", type=int, default=200, help="number of random cases")
    Args = Parser.parse_args()
    if not Args.diaphora_dir:
        raise SystemExit("--diaphora-dir or DSIG_DIAPHORA_DIR is required")
    D, Env = LoadDiaphora(os.path.abspath(Args.diaphora_dir))
    if not Env["diaphora_status_clean"]:
        raise SystemExit("the Diaphora checkout is not clean")
    Work = tempfile.mkdtemp(prefix="dsig-state-vectors-")
    M = None
    try:
        M = Machine(D, Work)
        os.makedirs(Args.out, exist_ok=True)
        Header = {"schema": SCHEMA_ID, "generator": "tools/parity/gen_state_vectors.py", "python": Env["python"],
                  "diaphora": Env["diaphora"]}
        Named = dict(Header, seed=None, cases=[M.Run(C) for C in NamedCases()])
        Rng = random.Random(Args.seed)
        Random = dict(Header, seed=Args.seed, cases=[M.Run(RandomCase(Rng, K)) for K in range(Args.random)])
        for Name, Doc in (("probes.json", Named), ("random.json", Random)):
            Path = os.path.join(Args.out, Name)
            with open(Path, "w", encoding="utf-8", newline="\n") as F:
                json.dump(Doc, F, ensure_ascii=False, separators=(",", ":"))
                F.write("\n")
            print("wrote %s (%d cases)" % (Path, len(Doc["cases"])))
        if Git(os.path.abspath(Args.diaphora_dir), "status", "--porcelain") != "":
            raise SystemExit("the Diaphora checkout changed")
    finally:
        del M
        shutil.rmtree(Work, ignore_errors=True)


if __name__ == "__main__":
    Main()
