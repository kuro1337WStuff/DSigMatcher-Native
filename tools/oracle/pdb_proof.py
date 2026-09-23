#!/usr/bin/env python3

"""Evidence of whether a PDB was applied to a Diaphora export of a PE file.

Every function name in the export is classified by where IDA could have taken
it from without a PDB:

  sub_*       IDA's placeholder for an unnamed function
  export      a name from the PE export directory, or IDA's name for an
              ordinal-only export (<MODULE>_<ordinal>, optionally _<n> suffixed)
  other       anything else: FLIRT library names, loader-generated names, or
              names that only a PDB can supply

An export analysed WITHOUT a PDB should have almost no "other" names, and those
it has should be recognisable runtime/FLIRT names. An export analysed WITH a PDB
should have many "other" names and (almost) no sub_*.

    python pdb_proof.py export.sqlite binary.dll [--json out.json] [--list 40]
"""

import argparse
import json
import re
import sqlite3
import sys

import pefile


def ExportNames(BinaryPath):
    Pe = pefile.PE(BinaryPath, fast_load=True)
    try:
        Pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
        Names = set()
        Ordinals = set()
        Module = ""
        Directory = getattr(Pe, "DIRECTORY_ENTRY_EXPORT", None)
        if Directory is not None:
            if Directory.name:
                Module = Directory.name.decode("ascii", "replace").split(".")[0].upper()
            for Symbol in Directory.symbols:
                if Symbol.name:
                    Names.add(Symbol.name.decode("ascii", "replace"))
                else:
                    Ordinals.add(Symbol.ordinal)
        return Names, Ordinals, Module
    finally:
        Pe.close()


def Classify(SqlitePath, BinaryPath):
    Exported, Ordinals, Module = ExportNames(BinaryPath)
    OrdinalName = re.compile(r"^%s_(\d+)(_\d+)?$" % re.escape(Module)) if Module else None
    Handle = sqlite3.connect(SqlitePath)
    try:
        Names = [Row[0] for Row in Handle.execute("select name from functions order by cast(address as integer)")]
    finally:
        Handle.close()
    Result = {"functions": len(Names), "sub": 0, "export": 0, "other": 0, "other_names": []}
    for Name in Names:
        if Name.startswith("sub_"):
            Result["sub"] += 1
        elif Name in Exported:
            Result["export"] += 1
        elif OrdinalName and OrdinalName.match(Name) and int(OrdinalName.match(Name).group(1)) in Ordinals:
            Result["export"] += 1
        else:
            Result["other"] += 1
            Result["other_names"].append(Name)
    Result["pe_export_names"] = len(Exported)
    Result["pe_export_ordinal_only"] = len(Ordinals)
    return Result


def Main():
    Parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    Parser.add_argument("sqlite")
    Parser.add_argument("binary")
    Parser.add_argument("--json", default=None, help="write the classification here")
    Parser.add_argument("--list", type=int, default=40, help="'other' names to print")
    Args = Parser.parse_args()
    Result = Classify(Args.sqlite, Args.binary)
    print("functions=%d sub_=%d export-table=%d other=%d" % (
        Result["functions"], Result["sub"], Result["export"], Result["other"]))
    for Name in Result["other_names"][:Args.list]:
        print("  other: %s" % Name)
    if Args.json:
        with open(Args.json, "w", encoding="utf-8") as Handle:
            json.dump(Result, Handle, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(Main())
