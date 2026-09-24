#!/usr/bin/env python3
"""Expected vectors of the diff_related suite, recorded from REAL Diaphora (spec 06 §7-§11).

    python -B generate.py fixtures  --diaphora-dir <diaphora-ref>
    python -B generate.py set-order --diaphora-dir <diaphora-ref> --corpus <corpus> --capture <name> [...]

`fixtures` (synthetic data only; its outputs are committed next to this file):
  1. Builds two Diaphora-schema fixture pairs, `related` and `errors`, exactly as
     tools/parity/make_fixture.py builds them (schema.py TABLES, the rows, every INDICES entry, `analyze`,
     then Python's iterdump(), which includes the sqlite_stat1 rows): <pair>_main.sql / <pair>_diff.sql.
  2. For every case below it rebuilds the pair like tests/diff/FixtureDb.h does, on COPIES, imports the
     unmodified Diaphora checkout read-only, restores the case's starting state with Diaphora's own
     add_match (D:1340-1374), runs ONE stage method (find_related_matches, find_related_compilation_unit
     or find_locally_affine_functions, D:3462 / D:3395 / D:3315) and records the state after it (as a
     snapshot), every add_match call (with the oracle's result inference, tools/parity/README.md) and the
     (ea, ea2) of every check_match call, i.e. the rows of every cursor the stage consumed. When Diaphora
     raises, the exception type and message are recorded instead of the after state.
  3. find_related_constants iterates a CPython set (D:3389, 06 §8.3). The cases run it through a copy
     that is verbatim except that the set is iterated in first appearance order of the main function's
     JSON list: the native engine's documented order. `forced_const_order` says so in cases.json.
  Output: cases.json.

`set-order` (corpus-derived, never committed): for a finished oracle capture recorded under a fixed
PYTHONHASHSEED (tools/parity/README.md "Hash seed"), writes the CPython iteration order of
`main_consts.intersection(diff_consts)` (D:3370-3373) for every match of the capture's
before:find_related_matches:<k> snapshots with two or more common constants, to
<corpus>/oracle/vectors/related/<capture>.set_order.json. The process re-executes itself under the
capture's seed; the set order of the same list under the same seed and CPython is reproducible, which
lets diff_related replay the capture's constant order exactly (src/diff/stages/RelatedDetail.h).
Only finished captures (run.json "complete" / "stopped", or a capture whose writer is gone) may be
named: this script reads their snapshots and exports and writes nothing next to them.

Paths come from flags or the environment only: --diaphora-dir (DSIG_DIAPHORA_DIR),
--corpus (DSIG_CORPUS_ROOT). Exports are opened read-only with immutable=1.
"""

import sys

sys.dont_write_bytecode = True

import argparse  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import shutil  # noqa: E402
import sqlite3  # noqa: E402
import subprocess  # noqa: E402
import tempfile  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
sys.path.insert(0, os.path.join(REPO, "tools", "parity"))

import make_fixture as MF  # noqa: E402
import snapshot as Snap  # noqa: E402

Function = MF.Function


# ----------------------------------------------------------------------------- synthetic scenarios

def Code(Seed, Lines, Changed=()):
    """Deterministic synthetic assembly; `Changed` rewrites the listed line indices (the diff side)."""
    Out = []
    for Index in range(Lines):
        Value = (Seed * 97 + Index * 13) % 251
        Text = ["mov eax, %d" % Value, "add ebx, %d" % (Value + 1), "xor ecx, %d" % (Value + 2),
                "cmp edx, %d" % (Value + 3)][Index % 4]
        if Index in Changed:
            Text = "sub esi, %d" % (Value + 7)
        Out.append(Text)
    Out.append("retn")
    return "\n".join(Out)


def Consts(Values):
    """functions.constants JSON (diaphora.py:936-939, ensure_ascii=False) and constants_count."""
    return {"constants": json.dumps(Values, ensure_ascii=False), "constants_count": len(Values)}


def ConstantRows(Functions):
    """constants table rows as the exporter writes them (diaphora.py:984-998): ints as str, strings only
    when len > 4, duplicates kept."""
    Rows = []
    for Row in Functions:
        if Row.get("constants") is None:
            continue
        try:
            Values = json.loads(Row["constants"])
        except ValueError:
            continue
        for Value in Values:
            if isinstance(Value, str) and "\ud800" <= max(Value, default=" ") and any(
                    "\ud800" <= Ch <= "\udfff" for Ch in Value):
                continue  # a lone surrogate cannot be stored as TEXT (it only lives in the JSON escape)
            if isinstance(Value, str) and len(Value) > 4:
                Rows.append({"func_id": Row["id"], "constant": Value})
            elif isinstance(Value, int) and not isinstance(Value, bool):
                Rows.append({"func_id": Row["id"], "constant": str(Value)})
    return Rows


def F(Id, Name, Address, Asm, Constants=None, **Overrides):
    Row = Function(Id, Name, Address, Asm.count("\n"), Asm, None, **Overrides)
    if Constants is not None:
        Row.update(Consts(Constants))
    for Key, Value in Overrides.items():
        Row[Key] = Value
    return Row


# 06 §8.3: values whose SQLite abs() is / is not 0 (the table's inputs).
ABS_TABLE = ["hello", "4096", "123abc", "  42 apples", "0x10", "0 files", "1e5 x", ".5x", "inf", "Infinity", "NaN",
             "-12", "-0", "1e999", "\t7", "\n5", "\x0b5", "+3a", "0000", "e5", "1e", ".e1", "-.5", "..5",
             chr(0x663), "\xa05", "1e-400", "1e-320"]


def RelatedScenario():
    Main = [
        # related constants / related CU group (main 20100.., diff 30100..)
        F(1, "alpha", 20100, Code(1, 12), ["Hello related world", "0x1234 zero prefix", 8192, "123 numeric prefix",
                                           "shared text A", "second shared B"]),
        F(2, "sub_20200", 20200, Code(2, 10), ["shared text A", "Hello related world"]),
        F(3, "sub_20300", 20300, Code(3, 10), ["second shared B"]),
        F(4, "gamma", 20400, Code(4, 10), ["shared text A", "tail constant C"]),
        F(5, "delta", 20500, Code(5, 10), ["delta only text"]),
        F(6, "nullsub_20600", 20600, Code(6, 4), ["shared text A"]),
        F(7, "epsilon", 20700, Code(7, 10), ["Hello related world"]),
        F(8, "zeta", 20800, Code(8, 10), []),
        F(9, "sub_20900", 20900, Code(9, 10), ["tail constant C", "shared text A"]),
        F(10, "abs_probe", 21000, Code(10, 8), ABS_TABLE),
        # local affinity group: main 4096..8192 plus 40970 (inside ('4096', '8192') as TEXT), 9990..10010
        F(20, "la_anchor1", 4096, Code(20, 6)),
        F(21, "sub_5000", 5000, Code(21, 10)),
        F(22, "nullsub_6000", 6000, Code(22, 10)),
        F(23, "la_named", 7000, Code(23, 10)),
        F(24, "sub_8191", 8191, Code(24, 10), pseudocode="int f()\n{\n}", pseudocode_lines=3,
          clean_pseudo="int f()\n{\n}"),
        F(25, "la_anchor2", 8192, Code(25, 6)),
        F(26, "sub_40970", 40970, Code(26, 10)),
        F(27, "la_anchor3", 9990, Code(27, 6)),
        F(28, "sub_9995", 9995, Code(28, 10)),
        F(29, "sub_10005", 10005, Code(29, 10)),
        F(30, "la_anchor4", 10010, Code(30, 6)),
        F(31, "sub_7500", 7500, Code(31, 10)),
        # D:3276-3278: 3 + (-3) == 0, so the "== 3" skip does not apply
        F(32, "sub_7600", 7600, Code(32, 10), pseudocode_lines=3),
    ]
    Diff = [
        F(1, "alpha", 30100, Code(1, 12), ["second shared B", "Hello related world", "0x1234 zero prefix", 8192,
                                           "shared text A"]),
        F(2, "sub_30200", 30200, Code(2, 10, (3,)), ["shared text A"]),
        F(3, "sub_30300", 30300, Code(3, 10, (2, 7)), ["Hello related world", "second shared B"]),
        F(4, "gamma2", 30400, Code(4, 10, (5,)), ["shared text A", "tail constant C"]),
        F(5, "delta", 30500, Code(5, 10, (1, 4)), ["delta only text"]),
        F(6, "nullsub_30600", 30600, Code(6, 4), ["shared text A"]),
        F(7, "epsilon", 30700, Code(7, 10, (0, 3, 6)), ["Hello related world"]),
        F(8, "zeta", 30800, Code(8, 10), [], constants_count=None),
        F(9, "sub_30900", 30900, Code(9, 10, (8,)), ["tail constant C", "shared text A"]),
        F(10, "sub_31000", 31000, Code(2, 10, (1, 3)), ["shared text A"]),
        F(11, "abs_probe", 31100, Code(10, 8), ABS_TABLE),
        # local affinity group: diff 14096..18192, 19990..19995
        F(20, "la_anchor1", 14096, Code(20, 6)),
        F(21, "sub_15000", 15000, Code(21, 10, (4,))),
        F(22, "sub_16000", 16000, Code(26, 10, (2,))),
        F(23, "la_named2", 17000, Code(23, 10, (1,))),
        F(24, "sub_18000", 18000, Code(24, 10, (6,))),
        F(25, "la_anchor2", 18192, Code(25, 6)),
        F(26, "sub_15500", 15500, Code(31, 10, (9,))),
        F(27, "la_anchor4", 19990, Code(30, 6)),
        F(28, "sub_19992", 19992, Code(28, 10)),
        F(29, "la_anchor3", 19995, Code(27, 6)),
        # a second near copy of sub_5000: its ratio ties the first one's, and main_score >= r skips it
        F(30, "sub_15100", 15100, Code(21, 10, (6,))),
        F(31, "sub_15600", 15600, Code(32, 10, (5,)), pseudocode_lines=-3),
    ]
    MainCus = [{"id": 1, "name": "cu_a", "functions": 4, "start_ea": "20100", "end_ea": "20400"},
               {"id": 2, "name": "cu_b", "functions": 5, "start_ea": "20500", "end_ea": "20900"}]
    # gamma (4) is in both CUs; its FIRST link (lowest rowid) is cu_b (06 §9.2 first_cu).
    MainCuf = [{"cu_id": 2, "func_id": 4}, {"cu_id": 1, "func_id": 1}, {"cu_id": 1, "func_id": 2},
               {"cu_id": 1, "func_id": 3}, {"cu_id": 1, "func_id": 4}, {"cu_id": 2, "func_id": 5},
               {"cu_id": 2, "func_id": 6}, {"cu_id": 2, "func_id": 7}, {"cu_id": 2, "func_id": 8},
               {"cu_id": 2, "func_id": 9}]
    DiffCus = [{"id": 1, "name": "cu_a2", "functions": 4, "start_ea": "30100", "end_ea": "30400"},
               {"id": 2, "name": "cu_b2", "functions": 5, "start_ea": "30500", "end_ea": "31000"}]
    # diff epsilon (7) is in no CU.
    DiffCuf = [{"cu_id": 1, "func_id": 1}, {"cu_id": 1, "func_id": 2}, {"cu_id": 1, "func_id": 3},
               {"cu_id": 1, "func_id": 4}, {"cu_id": 2, "func_id": 5}, {"cu_id": 2, "func_id": 6},
               {"cu_id": 2, "func_id": 8}, {"cu_id": 2, "func_id": 9}, {"cu_id": 2, "func_id": 10}]
    # abs_probe also gets a constants row for every 06 §8.3 input the exporter would leave out (len <= 4),
    # so the SQL filter `abs(mc.constant) == 0` sees the whole table.
    MainConstants = ConstantRows(Main) + [{"func_id": 10, "constant": V} for V in ABS_TABLE if len(V) <= 4]
    DiffConstants = ConstantRows(Diff) + [{"func_id": 11, "constant": V} for V in ABS_TABLE if len(V) <= 4]
    return ({"functions": Main, "tables": {"constants": MainConstants, "compilation_units": MainCus,
                                          "compilation_unit_functions": MainCuf}},
            {"functions": Diff, "tables": {"constants": DiffConstants, "compilation_units": DiffCus,
                                          "compilation_unit_functions": DiffCuf}})


def ErrorsScenario():
    Main = [
        F(1, "e_count_null", 70100, Code(40, 8), ["abcdefgh"], constants_count=None),
        F(2, "e_consts_null", 70200, Code(41, 8), constants=None, constants_count=1),
        F(3, "e_json_bad", 70300, Code(42, 8), constants='["abcdefgh",', constants_count=1),
        F(4, "e_surrogate", 70400, Code(43, 8), constants='["\\ud800abcdef", "plain text"]', constants_count=2),
        F(5, "e_cu_null", 70500, Code(44, 8)),
        F(6, "e_cu_bad", 70600, Code(45, 8)),
        F(7, "e_la_a", 1000, Code(46, 6)),
        F(8, "sub_2000", 2000, Code(47, 8), pseudocode_lines=None),
        F(9, "e_la_b", 3000, Code(48, 6)),
        F(10, "e_la_c", 4000, Code(49, 6)),
        F(11, None, 5000, Code(50, 8), mangled_function=None),
        F(12, "e_la_d", 6000, Code(51, 6)),
    ]
    Diff = [
        F(1, "e_count_null", 80100, Code(40, 8), ["abcdefgh"]),
        F(2, "e_consts_null", 80200, Code(41, 8), ["abcdefgh"]),
        F(3, "e_json_bad", 80300, Code(42, 8), ["abcdefgh"]),
        F(4, "e_surrogate", 80400, Code(43, 8), constants='["plain text", "\\ud800abcdef"]', constants_count=2),
        F(5, "e_cu_null", 80500, Code(44, 8)),
        F(6, "e_cu_bad", 80600, Code(45, 8)),
        F(7, "e_la_a", 11000, Code(46, 6)),
        F(8, "sub_12000", 12000, Code(47, 8, (2,))),
        F(9, "e_la_b", 13000, Code(48, 6)),
        F(10, "e_la_c", 14000, Code(49, 6)),
        F(11, "sub_15000", 15000, Code(50, 8, (3,))),
        F(12, "e_la_d", 16000, Code(51, 6)),
    ]
    MainCus = [{"id": 1, "name": "cu_null", "functions": 1, "start_ea": None, "end_ea": "70500"},
               {"id": 2, "name": "cu_bad", "functions": 1, "start_ea": "zz", "end_ea": "70600"}]
    MainCuf = [{"cu_id": 1, "func_id": 5}, {"cu_id": 2, "func_id": 6}]
    DiffCus = [{"id": 1, "name": "cu_d", "functions": 2, "start_ea": "80500", "end_ea": "80600"}]
    DiffCuf = [{"cu_id": 1, "func_id": 5}, {"cu_id": 1, "func_id": 6}]
    return ({"functions": Main, "tables": {"constants": ConstantRows(Main), "compilation_units": MainCus,
                                          "compilation_unit_functions": MainCuf}},
            {"functions": Diff, "tables": {"constants": ConstantRows(Diff), "compilation_units": DiffCus,
                                          "compilation_unit_functions": DiffCuf}})


SCENARIOS = {"related": RelatedScenario, "errors": ErrorsScenario}


def It(Ea1, Name1, Ea2, Name2, Desc, Ratio, Nodes1=10, Nodes2=10):
    return [str(Ea1), Name1, str(Ea2), Name2, Desc, Ratio, Nodes1, Nodes2]


# The starting states: add_match(name1, name2, ratio, item, chooser) calls, in order.
RM_STATE = [
    ("best", It(20100, "alpha", 30100, "alpha", "Perfect match, same name", 1)),
    ("best", It(20300, "sub_20300", 30300, "sub_30300", "Loop count", 0.75)),
    ("best", It(21000, "abs_probe", 31100, "abs_probe", "Perfect match, same name", 1)),
    ("best", It(99999, None, 30200, "sub_30200", "Synthetic None name", 1)),
    ("partial", It(20400, "gamma", 30400, "gamma2", "Bytes hash", 0.9)),
    ("partial", It(20800, "zeta", 30800, "zeta", "Same name", 0.88)),
    ("partial", It(20500, "delta", 30500, "delta", "Same name", 0.85)),
    ("partial", It(20200, "sub_20200", 39999, "sub_missing", "Mnemonics", 0.84)),
    ("partial", It(20700, "epsilon", 30700, "epsilon", "Same name", 0.7)),
    ("partial", It(20900, "sub_20900", 30900, "sub_30900", "Mnemonics", 0.83)),
]
CU_STATE = [
    ("best", It(20100, "alpha", 30100, "alpha", "Perfect match, same name", 1)),
    ("best", It(99999, None, 30200, "sub_30200", "Synthetic None name", 1)),
    ("partial", It(20400, "gamma", 30400, "gamma2", "Bytes hash", 0.9)),
    ("partial", It(20500, "delta", 30500, "delta", "Same name", 0.86)),
    ("partial", It(20700, "epsilon", 30700, "epsilon", "Same name", 0.84)),
    ("partial", It(20300, "sub_20300", 30300, "sub_30300", "Loop count", 0.82)),
    ("partial", It(20900, "sub_20900", 30900, "sub_30900", "Mnemonics", 0.79)),
    ("partial", It(20200, "sub_20200", 30200, "sub_30200", "Mnemonics", 0.95)),
]
LA_STATE = [
    ("best", It(4096, "la_anchor1", 14096, "la_anchor1", "Perfect match, same name", 1)),
    ("best", It(8192, "la_anchor2", 18192, "la_anchor2", "Perfect match, same name", 1)),
    ("best", It(9990, "la_anchor3", 19995, "la_anchor3", "Perfect match, same name", 1)),
    ("best", It(10010, "la_anchor4", 19990, "la_anchor4", "Perfect match, same name", 1)),
    ("partial", It(40970, "sub_40970", 19992, "sub_19992", "Mnemonics", 0.97)),
]

CASES = [
    {"name": "related_matches", "scenario": "related", "stage": "find_related_matches", "state": RM_STATE},
    {"name": "related_cu", "scenario": "related", "stage": "find_related_compilation_unit", "state": CU_STATE},
    {"name": "local_affinity", "scenario": "related", "stage": "find_locally_affine_functions", "state": LA_STATE},
    {"name": "err_count_null", "scenario": "errors", "stage": "find_related_matches",
     "state": [("partial", It(70100, "e_count_null", 80100, "e_count_null", "Same name", 0.9))]},
    {"name": "err_consts_null", "scenario": "errors", "stage": "find_related_matches",
     "state": [("partial", It(70200, "e_consts_null", 80200, "e_consts_null", "Same name", 0.9))]},
    {"name": "err_json_bad", "scenario": "errors", "stage": "find_related_matches",
     "state": [("partial", It(70300, "e_json_bad", 80300, "e_json_bad", "Same name", 0.9))]},
    {"name": "err_surrogate", "scenario": "errors", "stage": "find_related_matches",
     "state": [("partial", It(70400, "e_surrogate", 80400, "e_surrogate", "Same name", 0.9))]},
    {"name": "err_cu_null", "scenario": "errors", "stage": "find_related_compilation_unit",
     "state": [("partial", It(70500, "e_cu_null", 80500, "e_cu_null", "Same name", 0.9))]},
    {"name": "err_cu_bad", "scenario": "errors", "stage": "find_related_compilation_unit",
     "state": [("partial", It(70600, "e_cu_bad", 80600, "e_cu_bad", "Same name", 0.9))]},
    {"name": "err_la_lines_null", "scenario": "errors", "stage": "find_locally_affine_functions",
     "state": [("best", It(1000, "e_la_a", 11000, "e_la_a", "Same name", 1)),
               ("best", It(3000, "e_la_b", 13000, "e_la_b", "Same name", 1))]},
    {"name": "err_la_name_null", "scenario": "errors", "stage": "find_locally_affine_functions",
     "state": [("best", It(4000, "e_la_c", 14000, "e_la_c", "Same name", 1)),
               ("best", It(6000, "e_la_d", 16000, "e_la_d", "Same name", 1))]},
]


# ----------------------------------------------------------------------------- running one case

def FirstAppearanceOrder(MainList, InterConsts):
    """The native engine's documented order (06 §8.3): the intersection's own key objects, in first
    appearance order of the main JSON list."""
    Rep = {C: C for C in InterConsts}
    Out = []
    for C in dict.fromkeys(MainList):
        if C in Rep:
            Out.append(Rep[C])
    return Out


def InstallFirstAppearance(Bd, D):
    """find_related_constants (D:3362-3393) verbatim except the iteration order (as oracle_trace.py
    --force-const-order does)."""
    json_ = D.json
    get_query_fields = D.get_query_fields

    def find_related_constants(main_row, diff_row):
        self_ = Bd
        heur = "Same constants related matches"
        cur = self_.db_cursor()
        try:
            main_consts = set(json_.loads(main_row["constants"]))
            diff_consts = set(json_.loads(diff_row["constants"]))

            inter_consts = main_consts.intersection(diff_consts)
            if len(inter_consts) > 0:
                sql = (
                    """ select """
                    + get_query_fields(heur)
                    + """
         from main.functions f,
              diff.functions df,
              main.constants mc,
              diff.constants dc
        where f.id = mc.func_id
          and df.id = dc.func_id
          and dc.constant = mc.constant
          and mc.constant = ?
          and abs(mc.constant) == 0 """
                )
                # The only change: first appearance order of the main list instead of set order.
                for constant in FirstAppearanceOrder(json_.loads(main_row["constants"]), inter_consts):
                    cur.execute(sql, (str(constant),))
                    self_.add_matches_internal(cur, best="best", partial="partial")
        finally:
            cur.close()

    Bd.find_related_constants = find_related_constants


def SnapshotOf(Bd, Point, Iteration):
    return {"schema": Snap.SCHEMA, "producer": "diaphora", "pair": "fixture", "seq": 0, "point": Point,
            "iteration": Iteration,
            "flags": {"is_same_processor": Bd.is_same_processor, "is_patch_diff": Bd.is_patch_diff,
                      "is_symbols_stripped": Bd.is_symbols_stripped, "hooks_loaded": Bd.hooks is not None,
                      "total_functions1": Bd.total_functions1, "total_functions2": Bd.total_functions2},
            "all_matches": {Key: [[X[0], X[1], X[2], X[3], X[4], Snap.RatioBits(X[5]), X[6], X[7]]
                                  for X in Bd.all_matches.get(Key, [])] for Key in Snap.LISTS},
            "matched_primary": [[K, V["name"], Snap.RatioBits(V["ratio"])] for K, V in Bd.matched_primary.items()],
            "matched_secondary": [[K, V["name"], Snap.RatioBits(V["ratio"])] for K, V in Bd.matched_secondary.items()]}


def RunCase(DiaphoraDir, Case, MainDb, DiffDb):
    """Child process body: one stage of real Diaphora on copies of the fixture pair."""
    sys.path.insert(0, DiaphoraDir)
    import diaphora as D  # the unmodified checkout, read-only

    Bd = D.CBinDiff(MainDb)
    Bd.ignore_all_names = False  # D:3759-3760
    Bd.db = D.sqlite3_connect(MainDb)
    # the first steps of diff() (D:3572-3575): the ratio cache and the attached diff database
    Bd.ratios_cache = {}
    Bd.last_diff_db = DiffDb
    Cur = Bd.db_cursor()
    Bd.try_attach(Cur, DiffDb)
    Cur.close()
    Cur = Bd.db_cursor()
    Cur.execute("select count(0) total from functions")
    Bd.total_functions1 = Cur.fetchone()[0]
    Cur.execute("select count(0) total from diff.functions")
    Bd.total_functions2 = Cur.fetchone()[0]
    Cur.close()
    D.threading.current_thread().timeout = False  # D:3595-3596
    Bd.is_same_processor = Bd.same_processor_both_databases()  # D:3617
    for Chooser, Item in Case["state"]:
        Bd.add_match(Item[1], Item[3], Item[5], list(Item), Chooser)
    Before = SnapshotOf(Bd, "before:%s:0" % Case["stage"], 0)
    InstallFirstAppearance(Bd, D)

    Events = []
    Rows = []
    OrigAdd = Bd.add_match
    OrigCheck = Bd.check_match

    def add_match(name1, name2, ratio, item, chooser):
        Lists = Bd.all_matches
        Size = len(Lists[chooser]) if chooser is not None else None
        Previous = Bd.matched_primary.get(name1)
        Result = OrigAdd(name1, name2, ratio, item, chooser)
        if chooser is not None and len(Bd.all_matches[chooser]) != Size:
            Outcome = "appended"
        elif Bd.matched_primary.get(name1) is not Previous:
            Outcome = "duplicate"
        else:
            Outcome = "rejected_better"
        Events.append([name1, name2, item[0], item[2], item[4], Snap.RatioBits(ratio), chooser, Outcome])
        return Result

    def check_match(row, *Args, **Kwargs):
        Rows.append([row["ea"], row["ea2"]])
        return OrigCheck(row, *Args, **Kwargs)

    Bd.add_match = add_match
    Bd.check_match = check_match
    Raised = None
    try:
        getattr(Bd, Case["stage"])(0)
    except Exception as Error:  # noqa: BLE001 - recorded, the native engine must raise too
        Raised = {"type": type(Error).__name__, "message": str(Error)}
    After = None if Raised else SnapshotOf(Bd, "after:%s:0" % Case["stage"], 0)
    return {"name": Case["name"], "scenario": Case["scenario"], "stage": Case["stage"], "iteration": 0,
            "forced_const_order": "main_first_appearance", "before": Before, "after": After, "raised": Raised,
            "add_match": Events, "rows": Rows}


def Child(DiaphoraDir, CaseName, MainDb, DiffDb, Out):
    Case = next(C for C in CASES if C["name"] == CaseName)
    Result = RunCase(DiaphoraDir, Case, MainDb, DiffDb)
    with open(Out, "w", encoding="utf-8", newline="\n") as Handle:
        json.dump(Result, Handle, ensure_ascii=False)
    return 0


def CleanEnv(Seed):
    Env = {Key: Value for Key, Value in os.environ.items() if not Key.upper().startswith("DIAPHORA_")}
    Env["PYTHONDONTWRITEBYTECODE"] = "1"
    Env["PYTHONHASHSEED"] = str(Seed)
    # diaphora.py imports its ML module, which pulls in numpy/scipy: keep their thread pools (and the
    # memory they commit per thread) at one thread.
    for Name in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS"):
        Env[Name] = "1"
    return Env


def Fixtures(Args):
    DiaphoraDir = os.path.abspath(Args.diaphora_dir)
    Describe = MF.Git(DiaphoraDir, "describe", "--tags")
    StatusBefore = MF.Git(DiaphoraDir, "status", "--porcelain")
    Schema = MF.LoadSchema(DiaphoraDir)
    Dumps = {}
    for Name, Build in SCENARIOS.items():
        Main, Diff = Build()
        Dumps[Name] = {"main": MF.BuildDump(Schema, Main, 6), "diff": MF.BuildDump(Schema, Diff, 10)}
    Work = tempfile.mkdtemp(prefix="dsig-related-fixture-")
    Results = []
    try:
        for Case in CASES:
            Dir = os.path.join(Work, Case["name"])
            os.makedirs(Dir)
            Paths = {}
            for Side in ("main", "diff"):
                Paths[Side] = os.path.join(Dir, Side + ".sqlite")
                MF.RebuildLikeFixtureDb(Dumps[Case["scenario"]][Side], Paths[Side])
            Out = os.path.join(Dir, "case.json")
            Results_ = []
            for Seed in (0, 1):  # the forced order makes the result independent of the hash seed
                Code = subprocess.call([Args.python, "-B", os.path.abspath(__file__), "--_case", DiaphoraDir,
                                        Case["name"], Paths["main"], Paths["diff"], Out], cwd=DiaphoraDir,
                                       env=CleanEnv(Seed))
                if Code != 0:
                    raise SystemExit("case %s failed (exit %d)" % (Case["name"], Code))
                with open(Out, "r", encoding="utf-8") as Handle:
                    Results_.append(json.load(Handle))
            if Results_[0] != Results_[1]:
                raise SystemExit("case %s depends on PYTHONHASHSEED" % Case["name"])
            Results.append(Results_[0])
            print("%-20s %s: %s, %d add_match, %d rows" % (Case["name"], Case["stage"],
                                                           Results_[0]["raised"]["type"] if Results_[0]["raised"]
                                                           else "ok", len(Results_[0]["add_match"]),
                                                           len(Results_[0]["rows"])))
    finally:
        shutil.rmtree(Work, ignore_errors=True)
    if MF.Git(DiaphoraDir, "describe", "--tags") != Describe or MF.Git(DiaphoraDir, "status", "--porcelain") != StatusBefore:
        raise SystemExit("the Diaphora checkout changed; nothing written")
    for Name, Pair in Dumps.items():
        for Side, Text in Pair.items():
            with open(os.path.join(HERE, "%s_%s.sql" % (Name, Side)), "w", encoding="utf-8", newline="\n") as Handle:
                Handle.write(Text)
    Doc = {"generator": "tests/diff/fixtures/related/generate.py", "diaphora": Describe,
           "python": sys.version.split()[0], "sqlite_version": sqlite3.sqlite_version, "cases": Results}
    with open(os.path.join(HERE, "cases.json"), "w", encoding="utf-8", newline="\n") as Handle:
        Handle.write(json.dumps(Doc, ensure_ascii=False, indent=1) + "\n")
    return 0


# ----------------------------------------------------------------------------- corpus set order

def ImmutableUri(Path):
    Path = os.path.abspath(Path).replace("\\", "/")
    if not Path.startswith("/"):
        Path = "/" + Path
    return "file:" + Path.replace("%", "%25").replace("?", "%3f").replace("#", "%23") + "?mode=ro&immutable=1"


def ExportIds(Corpus, Pair):
    Ref, Tail = Pair.split("_vs_", 1)
    Exports = os.path.join(Corpus, "oracle", "exports")

    def Exists(Id):
        return os.path.isfile(os.path.join(Exports, Id, Id + ".sqlite"))

    if Exists(Tail):
        return Ref, Tail
    Guess = Ref.split("-", 1)[0] + "-" + Tail
    if Exists(Guess):
        return Ref, Guess
    raise SystemExit("no exports for %s" % Pair)


def SetOrder(Args):
    Corpus = os.path.abspath(Args.corpus)
    OutDir = os.path.join(Corpus, "oracle", "vectors", "related")
    os.makedirs(OutDir, exist_ok=True)
    for Capture in Args.capture:
        CapDir = os.path.join(Corpus, "oracle", "traces", Capture)
        # The capture's seed comes from the flag: run.json is not read, so this never touches a file a
        # running capture replaces (tools/parity/README.md: every capture used --hash-seed 12345).
        Seed = Args.hash_seed
        if os.environ.get("PYTHONHASHSEED") != str(Seed):
            Env = dict(os.environ)
            Env["PYTHONHASHSEED"] = str(Seed)
            Env["PYTHONDONTWRITEBYTECODE"] = "1"
            Code = subprocess.call([Args.python, "-B", os.path.abspath(__file__), "set-order", "--corpus", Corpus,
                                    "--diaphora-dir", Args.diaphora_dir, "--capture", Capture,
                                    "--hash-seed", str(Seed)], env=Env)
            if Code != 0:
                return Code
            continue
        Pair = Capture.split(".", 1)[0]
        MainId, DiffId = ExportIds(Corpus, Pair)
        Db = sqlite3.connect(ImmutableUri(os.path.join(Corpus, "oracle", "exports", MainId, MainId + ".sqlite")),
                             uri=True)
        Db.execute("attach ? as diff", (ImmutableUri(os.path.join(Corpus, "oracle", "exports", DiffId,
                                                                   DiffId + ".sqlite")),))
        Snapshots = sorted(os.listdir(os.path.join(CapDir, "snapshots")))
        Orders = {}
        Seen = set()
        for Name in Snapshots:
            if "_before_find_related_matches_" not in Name or not Name.endswith(".json"):
                continue
            with open(os.path.join(CapDir, "snapshots", Name), "r", encoding="utf-8") as Handle:
                State = json.load(Handle)
            for Key in ("best", "partial"):
                for Item in State["all_matches"][Key]:
                    if (Item[1], Item[3]) in Seen or Item[1] is None or Item[3] is None:
                        continue
                    Seen.add((Item[1], Item[3]))
                    # get_function_row (D:2445-2460): the first row by name
                    Main = Db.execute("select constants from main.functions where name = ?", (Item[1],)).fetchone()
                    Diff = Db.execute("select constants from diff.functions where name = ?", (Item[3],)).fetchone()
                    if Main is None or Diff is None or Main[0] is None or Diff[0] is None:
                        continue
                    try:
                        Inter = list(set(json.loads(Main[0])).intersection(set(json.loads(Diff[0]))))  # D:3370-3373
                    except (ValueError, TypeError):
                        continue
                    if len(Inter) >= 2:
                        Orders[Item[1] + "\u0000" + Item[3]] = [str(C) for C in Inter]
        Db.close()
        Out = os.path.join(OutDir, Capture + ".set_order.json")
        with open(Out, "w", encoding="utf-8", newline="\n") as Handle:
            json.dump({"capture": Capture, "pair": Pair, "hash_seed": int(Seed), "python": sys.version.split()[0],
                       "orders": Orders}, Handle, ensure_ascii=False)
        print("%s: %d seed pairs with two or more common constants -> %s" % (Capture, len(Orders), Out))
    return 0


def Main():
    if len(sys.argv) > 1 and sys.argv[1] == "--_case":
        return Child(*sys.argv[2:7])
    Parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    Sub = Parser.add_subparsers(dest="command", required=True)
    for Name in ("fixtures", "set-order"):
        P = Sub.add_parser(Name)
        P.add_argument("--diaphora-dir", default=os.environ.get("DSIG_DIAPHORA_DIR"))
        P.add_argument("--python", default=os.environ.get("DSIG_PYTHON") or sys.executable)
        if Name == "set-order":
            P.add_argument("--corpus", default=os.environ.get("DSIG_CORPUS_ROOT"))
            P.add_argument("--capture", action="append", required=True)
            P.add_argument("--hash-seed", type=int, default=12345)
    Args = Parser.parse_args()
    if not Args.diaphora_dir or not os.path.isfile(os.path.join(Args.diaphora_dir, "diaphora.py")):
        Parser.error("--diaphora-dir (or DSIG_DIAPHORA_DIR) must name the Diaphora checkout")
    if Args.command == "fixtures":
        return Fixtures(Args)
    if not Args.corpus:
        Parser.error("--corpus (or DSIG_CORPUS_ROOT) is required")
    return SetOrder(Args)


if __name__ == "__main__":
    sys.exit(Main())
