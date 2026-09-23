#!/usr/bin/env python3

"""Compare two Diaphora export databases table by table.

Used to check that two export pipelines (for example idalib vs Diaphora's own
`idat -A -B -S diaphora.py` batch mode) produce the same database. Columns that
only record when the export ran are ignored.

    python compare_exports.py a.sqlite b.sqlite [--show 5]

Exit code 0 when every table matches, 1 otherwise.
"""

import argparse
import sqlite3
import sys

# (table, column) pairs that hold wall-clock data, not analysis results.
VOLATILE = {("functions", "export_time")}


def Tables(Handle):
    return [Row[0] for Row in Handle.execute(
        "select name from sqlite_master where type='table' and name not like 'sqlite_%' order by name")]


def Columns(Handle, Table):
    return [Row[1] for Row in Handle.execute("pragma table_info('%s')" % Table)]


def Main():
    Parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    Parser.add_argument("a")
    Parser.add_argument("b")
    Parser.add_argument("--show", type=int, default=3, help="differing rows to print per table")
    Args = Parser.parse_args()

    A = sqlite3.connect(Args.a)
    B = sqlite3.connect(Args.b)
    TablesA, TablesB = Tables(A), Tables(B)
    AllEqual = TablesA == TablesB
    if not AllEqual:
        print("table sets differ: %s vs %s" % (TablesA, TablesB))

    for Table in sorted(set(TablesA) & set(TablesB)):
        ColsA, ColsB = Columns(A, Table), Columns(B, Table)
        if ColsA != ColsB:
            print("%-28s columns differ" % Table)
            AllEqual = False
            continue
        Keep = [Col for Col in ColsA if (Table, Col) not in VOLATILE]
        Sql = "select %s from '%s' order by rowid" % (", ".join('"%s"' % Col for Col in Keep), Table)
        RowsA, RowsB = A.execute(Sql).fetchall(), B.execute(Sql).fetchall()
        if RowsA == RowsB:
            print("%-28s identical (%d rows)" % (Table, len(RowsA)))
            continue
        AllEqual = False
        SetA, SetB = set(RowsA), set(RowsB)
        print("%-28s DIFFERENT: %d vs %d rows; %d only in a, %d only in b%s" % (
            Table, len(RowsA), len(RowsB), len(SetA - SetB), len(SetB - SetA),
            " (same rows, different order)" if SetA == SetB else ""))
        if Table == "functions":
            ByAddrA = {Row[Keep.index("address")]: Row for Row in RowsA}
            ByAddrB = {Row[Keep.index("address")]: Row for Row in RowsB}
            Shown = 0
            for Address in sorted(set(ByAddrA) & set(ByAddrB), key=int):
                RowA, RowB = ByAddrA[Address], ByAddrB[Address]
                Diff = [Keep[I] for I in range(len(Keep)) if RowA[I] != RowB[I] and Keep[I] != "id"]
                if Diff and Shown < Args.show:
                    print("    function %s (%s): columns %s" % (
                        hex(int(Address)), RowA[Keep.index("name")], Diff))
                    Shown += 1
            Missing = set(ByAddrA) ^ set(ByAddrB)
            if Missing:
                print("    functions present in only one side: %s" % sorted(hex(int(X)) for X in Missing)[:20])
    return 0 if AllEqual else 1


if __name__ == "__main__":
    sys.exit(Main())
