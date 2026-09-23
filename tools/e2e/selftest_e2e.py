#!/usr/bin/env python3
"""Self-test of score_ground_truth.py on planted synthetic cases (no corpus, no dsigmatcher needed).

    selftest_e2e.py [--keep]

Builds a truth TSV (tools/oracle/ground_truth.py columns), an alias TSV (pdb_aliases.py columns) and a
"ported" database with the dsig_* tables a `dsigmatcher port --results` writes, each address planting
one scoring case, then checks every count of the report. Exit code 0 when all checks pass.
"""

import os
import shutil
import sqlite3
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import pdb_aliases  # noqa: E402
import score_ground_truth  # noqa: E402

BASE = 0x180001000

# address index -> (truth status, truth name, truth mangled, ported label, ported mangled)
CASES = {
    1: ("both", "Foo", "?Foo@@YAXXZ", "Foo", "?Foo@@YAXXZ"),  # ported by best, correct
    2: ("both", "Bar", "Bar", "Baz", "Baz"),                  # ported by partial, wrong
    3: ("both", "ZwQux", "ZwQux", "NtQux", "NtQux"),          # target's own name, a PDB alias
    4: ("both", "Real4", "Real4", "_Other4", "_Other4"),      # alias; dbghelp dropped the '_'
    5: ("both", "Miss", "Miss", "sub_180001500", "sub_180001500"),  # only a multimatch row proposed it
    6: ("both", "Six", "Six", "sub_180001600", "sub_180001600"),    # never matched
    7: ("pdb_only", "Seven", "Seven", None, None),            # not a function of the ported DB
    8: ("nopdb_only", "", "", "sub_180001800", "sub_180001800"),  # no truth for this start
    9: ("both", "sub_180001900", "sub_180001900", "Nine", "Nine"),  # truth has no real name
    10: ("both", "Ten", "Ten", "Ten", "Ten"),                 # confirmed: the target already had it
}

# (address index, type, description, ratio, ref_name, ref_mangled, action)
LOG = [
    (10, "best", "100% equal", "1.0000000", "Ten", "Ten", "confirmed"),
    (1, "best", "Bytes hash", "1.0000000", "Foo", "?Foo@@YAXXZ", "applied"),
    (2, "partial", "Loop count", "0.7000000", "Baz", "Baz", "applied"),
    (3, "partial", "Mnemonics", "0.6000000", "ZwQux", "ZwQux", "skipped_existing"),
    (8, "partial", "Loop count", "0.5000000", "Eight", "Eight", "applied"),
    (4, "partial", "Loop count", "0.4000000", "sub_1", "sub_1", "skipped_not_portable"),
    (5, "multimatch", "Related compilation unit", "0.6000000", "Miss", "Miss", "not_selected"),
]


def Ea(Index):
    return BASE + Index * 0x100


def Build(Directory):
    Truth = os.path.join(Directory, "demo-9999-nopdb.tsv")
    with open(Truth, "w", encoding="utf-8", newline="\n") as Handle:
        Handle.write("address\taddress_hex\tstatus\tname\tmangled_function\tnopdb_name\n")
        for Index, (Status, Name, Mangled, Label, _) in sorted(CASES.items()):
            Handle.write("%d\t%08x\t%s\t%s\t%s\t%s\n" % (Ea(Index), Ea(Index), Status, Name, Mangled, Label or ""))
    os.makedirs(os.path.join(Directory, "aliases"))
    Aliases = os.path.join(Directory, "aliases", "demo-9999.tsv")
    with open(Aliases, "w", encoding="utf-8", newline="\n") as Handle:
        Handle.write("\t".join(pdb_aliases.COLUMNS) + "\n")
        for Index, Name in ((3, "NtQux"), (3, "ZwQux"), (4, "Real4"), (4, "Other4")):
            Handle.write("%x\t%d\t%08x\t10\t0\t%s\t%s\n" % (Ea(Index) - 0x180000000, Ea(Index), Ea(Index), Name, Name))
    Ported = os.path.join(Directory, "ported.sqlite")
    Db = sqlite3.connect(Ported)
    Db.executescript(
        "create table functions (id integer primary key, name text, address text unique, mangled_function text);"
        "create table dsig_provenance (hop integer primary key);"
        "insert into dsig_provenance values (1);"
        "create table dsig_name_origin (address text primary key, name text, origin_address text, origin_name text,"
        " hops integer, cumulative_ratio real, heuristic text, first_labelled_at text);"
        "create table dsig_port_log (hop integer, results_rowid integer, type text, line text, description text,"
        " ratio text, address text, ref_address text, ref_name text, ref_mangled text, name_before text,"
        " mangled_before text, confidence real, hops integer, action text);")
    for Index, (_, _, _, Label, Mangled) in sorted(CASES.items()):
        if Label is not None:
            Db.execute("insert into functions (name, address, mangled_function) values (?, ?, ?)",
                       (Label, str(Ea(Index)), Mangled))
    for Row, (Index, Type, Description, Ratio, Name, Mangled, Action) in enumerate(LOG, start=1):
        Db.execute("insert into dsig_port_log values (1, ?, ?, '00000', ?, ?, ?, '1', ?, ?, NULL, NULL, 1.0, 1, ?)",
                   (Row, Type, Description, Ratio, str(Ea(Index)), Name, Mangled, Action))
        if Action == "applied":
            Db.execute("insert into dsig_name_origin values (?, ?, '1', ?, 1, 1.0, ?, 'now')",
                       (str(Ea(Index)), Name, Name, Type + ":" + Description))
    Db.commit()
    Db.close()
    return Ported, Truth, Aliases


def Check(Failures, Label, Actual, Expected):
    if Actual != Expected:
        Failures.append("%s: %r != %r" % (Label, Actual, Expected))


def main():
    Directory = tempfile.mkdtemp(prefix="dsig-e2e-selftest-")
    Failures = []
    try:
        Ported, Truth, Aliases = Build(Directory)
        # The alias TSV is found next to the truth TSV (<dir>/aliases/<build>.tsv) without --aliases.
        Check(Failures, "default alias path", score_ground_truth.DefaultAliasPath(Truth), Aliases)
        Report = score_ground_truth.Score(Ported, Truth)
        Label = Report["label"]
        Check(Failures, "scored", Report["scored_addresses"], 7)       # 1-6, 10
        Check(Failures, "truth_only", Report["truth_only"], 1)         # 7
        Check(Failures, "ported_only", Report["ported_only"], 1)       # 8
        Check(Failures, "ported_only labelled", Report["ported_only_labelled_by_port"], 1)
        Check(Failures, "truth_unnamed", Report["truth_unnamed"], 1)   # 9
        Check(Failures, "tsv status", Report["truth_tsv_status"], {"both": 8, "pdb_only": 1, "nopdb_only": 1})
        Check(Failures, "label correct", Label["correct"], 2)          # 1, 10
        Check(Failures, "label alias", Label["correct_alias"], 2)      # 3, 4
        Check(Failures, "label wrong", Label["wrong"], 1)              # 2
        Check(Failures, "label missing", Label["missing"], 2)          # 5, 6
        Check(Failures, "missing reasons", Report["missing_reasons"], {"not_selected:multimatch": 1, "no_match": 1})
        Sources = {Key: (Value["correct"], Value["correct_alias"], Value["wrong"], Value["missing"])
                   for Key, Value in Report["label_by_source"].items()}
        Check(Failures, "sources", Sources, {"ported:best": (1, 0, 0, 0), "ported:partial": (0, 0, 1, 0),
                                             "target": (0, 2, 0, 0), "none": (0, 0, 0, 2),
                                             "confirmed:best": (1, 0, 0, 0)})
        Match = {Key: (Value["correct"], Value["correct_alias"], Value["wrong"], Value["no_name"], Value["no_truth"])
                 for Key, Value in Report["match_by_category"].items()}
        # best: Ten, Foo correct. partial: Baz wrong, ZwQux correct (exact), Eight no_truth, sub_1 no_name.
        Check(Failures, "match", Match, {"best": (2, 0, 0, 0, 0), "partial": (1, 0, 1, 1, 1),
                                         "multimatch": (1, 0, 0, 0, 0)})
        Check(Failures, "unmatched", Report["unmatched_scored_addresses"],
              {"no_best_or_partial_row": 2, "no_row_at_all": 1})
        Check(Failures, "precision", Label["precision"], round(4 / 5, 4))
        Check(Failures, "recall", Label["recall"], round(4 / 7, 4))
        # The same truth given as an export instead of a TSV scores the same named addresses.
        Export = os.path.join(Directory, "exports", "demo-9999-pdb")
        os.makedirs(Export)
        ExportPath = os.path.join(Export, "demo-9999-pdb.sqlite")
        Db = sqlite3.connect(ExportPath)
        Db.execute("create table functions (id integer primary key, name text, address text, mangled_function text)")
        for Index, (Status, Name, Mangled, _, _) in sorted(CASES.items()):
            if Status in ("both", "pdb_only"):
                Db.execute("insert into functions (name, address, mangled_function) values (?, ?, ?)",
                           (Name, str(Ea(Index)), Mangled))
        Db.commit()
        Db.close()
        FromExport = score_ground_truth.Score(Ported, ExportPath, Aliases)
        Check(Failures, "export truth label", FromExport["label"], Report["label"])
        Check(Failures, "export truth ported_only", FromExport["ported_only"], 1)
        Text = score_ground_truth.Markdown(Report, "selftest")
        Check(Failures, "markdown mentions alias", "by alias" in Text, True)
    finally:
        if "--keep" in sys.argv:
            print("kept %s" % Directory)
        else:
            shutil.rmtree(Directory, ignore_errors=True)
    for Failure in Failures:
        print("FAIL %s" % Failure)
    print("selftest_e2e: %s (%d failure(s))" % ("PASSED" if not Failures else "FAILED", len(Failures)))
    return 0 if not Failures else 1


if __name__ == "__main__":
    sys.exit(main())
