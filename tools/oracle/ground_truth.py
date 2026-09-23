#!/usr/bin/env python3

"""Ground truth for a no-PDB export: function start address -> PDB function name.

The same build of a binary is exported twice by the oracle: once with its PDB
(`<name>-<build>-pdb`) and once without (`<name>-<build>-nopdb`). IDA places
both at the PE's preferred image base, so a function start has the same
address in both exports, and the PDB export's name at that address is the
truth for anything that names the no-PDB export (a Diaphora port, our port).

The table has one row per function start found in EITHER export:

  address           the export's `functions.address` text: decimal, exactly as
                    Diaphora stores it (`address text unique`,
                    db_support/schema.py:72; the value inserted by
                    save_function, diaphora.py:943-953)
  address_hex       "%08x" of the same value, the spelling of `.diaphora`
                    results (CChooser.add_item, diaphora.py:280-290)
  status            both       a function starts here in both exports
                    pdb_only   only the PDB analysis has a function here
                    nopdb_only only the no-PDB analysis has a function here
  name              the PDB export's `functions.name` (demangled when IDA has
                    a demangled form); empty for nopdb_only
  mangled_function  the PDB export's `functions.mangled_function`; empty for
                    nopdb_only
  nopdb_name        the no-PDB export's `functions.name`; empty for pdb_only

`pdb_only` and `nopdb_only` rows are where the two analyses disagree about
function starts; a scorer should report them separately, not as naming errors.
Rows are sorted by numeric address. Names are written verbatim; a name holding
a tab, CR or LF cannot be represented and aborts the run.

Both exports are opened read-only and immutable (no WAL/-shm access), so a
Diaphora diff that has one of them open is not disturbed. The JSON sidecar
records both files' sha256 and the counts.

    python ground_truth.py <pdb.sqlite> <nopdb.sqlite> --out <truth.tsv> [--json <truth.json>]
"""

import argparse
import hashlib
import json
import os
import sqlite3
import sys
import time
import urllib.parse

COLUMNS = ("address", "address_hex", "status", "name", "mangled_function", "nopdb_name")


def Sha256OfFile(Path):
    Digest = hashlib.sha256()
    with open(Path, "rb") as Handle:
        for Chunk in iter(lambda: Handle.read(1024 * 1024), b""):
            Digest.update(Chunk)
    return Digest.hexdigest()


def ConnectReadOnly(Path):
    """Open an export without writing anything next to it (immutable=1: no locks, no -shm)."""
    Uri = "file:%s?mode=ro&immutable=1" % urllib.parse.quote(os.path.abspath(Path).replace("\\", "/"))
    return sqlite3.connect(Uri, uri=True)


def ReadFunctions(Path):
    """{int address: (address text, name, mangled_function)}; duplicates are an error."""
    Handle = ConnectReadOnly(Path)
    try:
        Rows = Handle.execute("select address, name, mangled_function from functions order by id").fetchall()
    finally:
        Handle.close()
    Functions = {}
    for Address, Name, Mangled in Rows:
        if Address is None:
            raise ValueError("%s: a function has a NULL address" % Path)
        Key = int(Address)
        if Key in Functions:
            raise ValueError("%s: duplicate function address %s" % (Path, Address))
        Functions[Key] = (str(Address), Name, Mangled)
    return Functions


def Text(Value):
    if Value is None:
        return ""
    Value = str(Value)
    if any(Char in Value for Char in "\t\r\n"):
        raise ValueError("name %r holds a tab or line break; the TSV cannot represent it" % Value)
    return Value


def Build(PdbSqlite, NoPdbSqlite):
    Pdb = ReadFunctions(PdbSqlite)
    NoPdb = ReadFunctions(NoPdbSqlite)
    Rows = []
    Counts = {"both": 0, "pdb_only": 0, "nopdb_only": 0}
    NullNames = 0
    SameName = 0
    for Address in sorted(set(Pdb) | set(NoPdb)):
        InPdb, InNoPdb = Address in Pdb, Address in NoPdb
        Status = "both" if InPdb and InNoPdb else ("pdb_only" if InPdb else "nopdb_only")
        Counts[Status] += 1
        AddressText = (Pdb.get(Address) or NoPdb.get(Address))[0]
        if InPdb and InNoPdb and Pdb[Address][0] != NoPdb[Address][0]:
            raise ValueError("address %d is spelled %r and %r" % (Address, Pdb[Address][0], NoPdb[Address][0]))
        Name = Pdb[Address][1] if InPdb else None
        Mangled = Pdb[Address][2] if InPdb else None
        NoPdbName = NoPdb[Address][1] if InNoPdb else None
        if InPdb and Name is None:
            NullNames += 1
        if InPdb and InNoPdb and Name == NoPdbName:
            SameName += 1
        Rows.append((AddressText, "%08x" % Address, Status, Text(Name), Text(Mangled), Text(NoPdbName)))
    Stats = {
        "pdb_functions": len(Pdb),
        "nopdb_functions": len(NoPdb),
        "rows": len(Rows),
        "status_counts": Counts,
        "pdb_null_names": NullNames,
        "both_with_identical_name": SameName,
        "both_with_different_name": Counts["both"] - SameName,
    }
    return Rows, Stats


def WriteTsv(Path, Rows):
    Temp = Path + ".tmp"
    with open(Temp, "w", encoding="utf-8", newline="\n") as Handle:
        Handle.write("\t".join(COLUMNS) + "\n")
        for Row in Rows:
            Handle.write("\t".join(Row) + "\n")
    os.replace(Temp, Path)


def Generate(PdbSqlite, NoPdbSqlite, OutTsv, OutJson=None, Extra=None):
    Before = {"pdb": Sha256OfFile(PdbSqlite), "nopdb": Sha256OfFile(NoPdbSqlite)}
    Rows, Stats = Build(PdbSqlite, NoPdbSqlite)
    After = {"pdb": Sha256OfFile(PdbSqlite), "nopdb": Sha256OfFile(NoPdbSqlite)}
    if Before != After:
        raise RuntimeError("an export changed while the ground truth was read: %s -> %s" % (Before, After))
    WriteTsv(OutTsv, Rows)
    Info = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "generator": "tools/oracle/ground_truth.py",
        "columns": list(COLUMNS),
        "pdb_export": os.path.abspath(PdbSqlite),
        "pdb_export_sha256": Before["pdb"],
        "nopdb_export": os.path.abspath(NoPdbSqlite),
        "nopdb_export_sha256": Before["nopdb"],
        "tsv": os.path.abspath(OutTsv),
        "tsv_sha256": Sha256OfFile(OutTsv),
    }
    Info.update(Stats)
    if Extra:
        Info.update(Extra)
    if OutJson:
        with open(OutJson, "w", encoding="utf-8") as Handle:
            json.dump(Info, Handle, indent=2)
    return Info


def Main():
    Parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    Parser.add_argument("pdb_sqlite", help="export of the build WITH its PDB")
    Parser.add_argument("nopdb_sqlite", help="export of the same build WITHOUT a PDB")
    Parser.add_argument("--out", required=True, help="TSV to write")
    Parser.add_argument("--json", default=None, help="JSON sidecar to write")
    Args = Parser.parse_args()
    Info = Generate(Args.pdb_sqlite, Args.nopdb_sqlite, Args.out, Args.json)
    print("rows=%d both=%d pdb_only=%d nopdb_only=%d (pdb %d / nopdb %d functions)" % (
        Info["rows"], Info["status_counts"]["both"], Info["status_counts"]["pdb_only"],
        Info["status_counts"]["nopdb_only"], Info["pdb_functions"], Info["nopdb_functions"]))
    return 0


if __name__ == "__main__":
    sys.exit(Main())
