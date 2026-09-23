#!/usr/bin/env python3

"""Report how much of Diaphora's schema this project actually ingests.

Parses the functions-table column list out of Diaphora's schema.py and out of the
native ExportDatabase.cpp column table, then reports the gap. Intended to be
re-run as columns are added, so the remaining work is a number rather than a guess.
"""

import os
import re
import sqlite3
import sys

DIAPHORA_REF = r"<diaphora-ref>"

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXPORT_CPP = os.path.join(PROJECT_ROOT, "src", "ExportDatabase.cpp")
HEURISTICS_CPP = os.path.join(PROJECT_ROOT, "src", "Heuristics.cpp")


def DiaphoraSchema():
    """Materialize Diaphora's own TABLES list in memory and read the real columns."""
    sys.path.insert(0, DIAPHORA_REF)
    from db_support.schema import TABLES

    Connection = sqlite3.connect(":memory:")
    for Statement in TABLES:
        Connection.execute(Statement)

    Schema = {}
    for Row in Connection.execute(
            "select name from sqlite_master where type='table' order by name"):
        Table = Row[0]
        Schema[Table] = [Info[1] for Info in
                         Connection.execute('pragma table_info("%s")' % Table)]
    Connection.close()
    return Schema


def NativeIngestedColumns():
    with open(EXPORT_CPP, "r", encoding="utf-8", errors="replace") as Handle:
        Text = Handle.read()
    return re.findall(r'\{\s*"(\w+)"\s*,\s*Field::', Text)


def NativeHeuristicNames():
    with open(HEURISTICS_CPP, "r", encoding="utf-8", errors="replace") as Handle:
        Text = Handle.read()
    return re.findall(r'\{\s*"([^"]+)"\s*,\s*MatchCategory::(\w+)', Text)


def DiaphoraHeuristicNames():
    Path = os.path.join(DIAPHORA_REF, "diaphora_heuristics.py")
    with open(Path, "r", encoding="utf-8", errors="replace") as Handle:
        Text = Handle.read()
    Entries = re.findall(r'NAME\s*=\s*"([^"]+)"[\s\S]{0,200}?"category"\s*:\s*"([^"]+)"', Text)
    return Entries


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    if not os.path.isdir(DIAPHORA_REF):
        print("diaphora reference checkout not found at %s" % DIAPHORA_REF)
        return 1

    Schema = DiaphoraSchema()
    SchemaColumns = Schema.get("functions", [])
    Ingested = NativeIngestedColumns()

    IngestedSet = set(Ingested)
    SchemaSet = set(SchemaColumns)

    Missing = [C for C in SchemaColumns if C not in IngestedSet]
    Extra = [C for C in Ingested if C not in SchemaSet]

    print("Diaphora functions table")
    print("  columns in schema      : %d" % len(SchemaColumns))
    print("  columns ingested       : %d" % len(Ingested))
    print("  coverage               : %.1f%%" % (100.0 * len(IngestedSet & SchemaSet) /
                                                 max(1, len(SchemaColumns))))
    print("  ingested but not in schema (typos?): %s" % (Extra if Extra else "none"))
    print("")
    print("  not ingested (%d):" % len(Missing))
    for Column in Missing:
        print("    %s" % Column)

    print("")
    print("Diaphora tables: %d" % len(Schema))
    for Table in sorted(Schema):
        print("  %-28s %d columns" % (Table, len(Schema[Table])))

    Native = NativeHeuristicNames()
    Reference = DiaphoraHeuristicNames()

    print("")
    print("Heuristics")
    print("  in Diaphora            : %d" % len(Reference))
    for Category in ("Best", "Partial", "Unreliable", "Experimental"):
        Count = sum(1 for _, C in Reference if C == Category)
        if Count:
            print("    %-14s : %d" % (Category, Count))
    print("  implemented natively   : %d" % len(Native))
    for Category in ("Best", "Partial", "Unreliable"):
        Count = sum(1 for _, C in Native if C == Category)
        if Count:
            print("    %-14s : %d" % (Category, Count))

    NativeNames = {Name for Name, _ in Native}
    ReferenceNames = {Name for Name, _ in Reference}
    Unknown = sorted(NativeNames - ReferenceNames)
    if Unknown:
        print("")
        print("  WARNING implemented names not found in Diaphora: %s" % Unknown)

    print("")
    print("  remaining (%d):" % len(ReferenceNames - NativeNames))
    for Name, Category in Reference:
        if Name not in NativeNames:
            print("    [%-11s] %s" % (Category, Name))

    return 0


if __name__ == "__main__":
    sys.exit(main())
