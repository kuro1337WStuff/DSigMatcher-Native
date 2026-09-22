#!/usr/bin/env python3

import hashlib
import os
import sqlite3
import sys

FUNCTIONS_DDL = """
create table functions (
  id integer primary key,
  name varchar(255),
  address text unique,
  nodes integer,
  edges integer,
  indegree integer,
  outdegree integer,
  size integer,
  instructions integer,
  mnemonics text,
  names text,
  prototype text,
  cyclomatic_complexity integer,
  primes_value text,
  comment text,
  mangled_function text,
  bytes_hash text,
  pseudocode text,
  pseudocode_lines integer,
  pseudocode_hash1 text,
  pseudocode_primes text,
  function_flags integer,
  assembly text,
  prototype2 text,
  pseudocode_hash2 text,
  pseudocode_hash3 text,
  strongly_connected integer,
  loops integer,
  rva text unique,
  tarjan_topological_sort text,
  strongly_connected_spp text,
  clean_assembly text,
  clean_pseudo text,
  mnemonics_spp text,
  switches text,
  function_hash text,
  bytes_sum integer,
  md_index text,
  constants text,
  constants_count integer,
  segment_rva text,
  assembly_addrs text,
  kgh_hash text,
  source_file text,
  userdata text,
  microcode text,
  clean_microcode text,
  microcode_spp text,
  export_time real
)
"""

PROGRAM_DDL = """
create table program (
  id integer primary key,
  callgraph_primes text,
  callgraph_all_primes text,
  processor text,
  md5sum text
)
"""

INSERT_COLUMNS = [
    "id", "name", "address", "nodes", "edges", "indegree", "outdegree", "size",
    "instructions", "mnemonics", "mangled_function", "cyclomatic_complexity",
    "bytes_hash", "pseudocode_lines", "strongly_connected", "loops", "rva",
    "clean_assembly", "clean_pseudo", "function_hash", "md_index",
    "constants_count", "segment_rva", "kgh_hash", "source_file", "clean_microcode",
]


def Digest(Value):
    return hashlib.sha256(str(Value).encode("utf-8")).hexdigest()


def BuildRow(Index, Name, Base, AddressOffset):
    Address = 0x140000000 + AddressOffset + Index * 0x100
    return {
        "id": Index + 1,
        "name": Name,
        "address": "0x%X" % Address,
        "nodes": Base["nodes"],
        "edges": Base["edges"],
        "indegree": Base.get("indegree", 1),
        "outdegree": Base.get("outdegree", 1),
        "size": Base["instructions"] * 4,
        "instructions": Base["instructions"],
        "mnemonics": Base["mnemonics"],
        "mangled_function": Name,
        "cyclomatic_complexity": Base["nodes"],
        "bytes_hash": Digest(Base["body"]),
        "pseudocode_lines": Base["pseudo_lines"],
        "strongly_connected": 1,
        "loops": Base.get("loops", 0),
        "rva": "0x%X" % (Address - 0x140000000),
        "clean_assembly": Base["clean_asm"],
        "clean_pseudo": Base["clean_pseudo"],
        "function_hash": Digest(Base["body"] + "|fh"),
        "md_index": Base.get("md_index", "1.0"),
        "constants_count": Base.get("constants", 0),
        "segment_rva": "0x%X" % (Address - 0x140000000),
        "kgh_hash": Digest(Base["body"] + "|kgh"),
        "source_file": Base.get("source", "main.cpp"),
        "clean_microcode": Base["clean_micro"],
    }


def MakeBases():
    Bases = []

    for Index in range(6):
        Bases.append({
            "nodes": 4, "edges": 5, "instructions": 20,
            "mnemonics": "push mov call ret",
            "body": "identical-body-%d" % Index,
            "pseudo_lines": 8,
            "clean_asm": "asm-identical-%d" % Index,
            "clean_pseudo": "pseudo-identical-%d" % Index,
            "clean_micro": "micro-identical-%d" % Index,
            "kind": "exact",
        })

    for Index in range(3):
        Bases.append({
            "nodes": 5, "edges": 6, "instructions": 30,
            "mnemonics": "push sub mov call add pop ret",
            "body": "asm-only-body-%d" % Index,
            "pseudo_lines": 3,
            "clean_asm": "asm-shared-%d" % Index,
            "clean_pseudo": "pseudo-distinct-asm-%d" % Index,
            "clean_micro": "micro-distinct-asm-%d" % Index,
            "kind": "assembly",
        })

    for Index in range(2):
        Bases.append({
            "nodes": 6, "edges": 7, "instructions": 40,
            "mnemonics": "push mov lea call jmp ret",
            "body": "pseudo-only-body-%d" % Index,
            "pseudo_lines": 12,
            "clean_asm": "asm-distinct-pseudo-%d" % Index,
            "clean_pseudo": "pseudo-shared-%d" % Index,
            "clean_micro": "micro-distinct-pseudo-%d" % Index,
            "kind": "pseudo",
        })

    Bases.append({
        "nodes": 3, "edges": 3, "instructions": 15,
        "mnemonics": "xor test jz ret",
        "body": "reference-only-body",
        "pseudo_lines": 6,
        "clean_asm": "asm-reference-only",
        "clean_pseudo": "pseudo-reference-only",
        "clean_micro": "micro-reference-only",
        "kind": "unique",
    })

    Bases.append({
        "nodes": 3, "edges": 3, "instructions": 15,
        "mnemonics": "xor test jnz ret",
        "body": "target-only-body",
        "pseudo_lines": 6,
        "clean_asm": "asm-target-only",
        "clean_pseudo": "pseudo-target-only",
        "clean_micro": "micro-target-only",
        "kind": "unique",
    })

    return Bases


def WriteDatabase(Path, Rows, Processor):
    if os.path.exists(Path):
        os.remove(Path)

    Connection = sqlite3.connect(Path)
    Cursor = Connection.cursor()
    Cursor.execute(FUNCTIONS_DDL)
    Cursor.execute(PROGRAM_DDL)
    Cursor.execute("create table version (value text)")
    Cursor.execute("insert into version values ('3.4.2')")
    Cursor.execute(
        "insert into program (id, callgraph_primes, callgraph_all_primes, processor, md5sum) "
        "values (1, '2', '2', ?, ?)",
        (Processor, Digest(Path)),
    )

    Placeholders = ", ".join(["?"] * len(INSERT_COLUMNS))
    Statement = "insert into functions (%s) values (%s)" % (
        ", ".join(INSERT_COLUMNS), Placeholders)
    for Row in Rows:
        Cursor.execute(Statement, [Row[Column] for Column in INSERT_COLUMNS])

    Connection.commit()
    Connection.close()


def main():
    OutDir = sys.argv[1] if len(sys.argv) > 1 else "."
    os.makedirs(OutDir, exist_ok=True)

    Bases = MakeBases()
    PairedCount = len(Bases) - 2

    ReferenceRows = []
    TargetRows = []

    for Index in range(PairedCount):
        Base = Bases[Index]
        ReferenceName = "RealSymbol_%d" % Index
        TargetName = "sub_%X" % (0x1000 + Index * 0x10)

        ReferenceRows.append(BuildRow(Index, ReferenceName, Base, 0x0))

        TargetBase = dict(Base)
        if Base["kind"] == "assembly":
            TargetBase["body"] = Base["body"] + "-recompiled"
        if Base["kind"] == "pseudo":
            TargetBase["body"] = Base["body"] + "-recompiled"
            TargetBase["clean_asm"] = Base["clean_asm"] + "-changed"

        TargetRows.append(BuildRow(Index, TargetName, TargetBase, 0x40000))

    ReferenceRows.append(BuildRow(PairedCount, "OrphanReference", Bases[PairedCount], 0x0))
    TargetRows.append(BuildRow(PairedCount + 1, "sub_FFFF", Bases[PairedCount + 1], 0x40000))

    ReferencePath = os.path.join(OutDir, "reference.sqlite")
    TargetPath = os.path.join(OutDir, "target.sqlite")

    WriteDatabase(ReferencePath, ReferenceRows, "metapc")
    WriteDatabase(TargetPath, TargetRows, "metapc")

    print("reference : %s (%d functions)" % (ReferencePath, len(ReferenceRows)))
    print("target    : %s (%d functions)" % (TargetPath, len(TargetRows)))
    print("expected 1:1 matches : %d" % PairedCount)
    print("  exact-hash tier    : %d" % sum(1 for B in Bases if B["kind"] == "exact"))
    print("  cleaned-assembly   : %d" % sum(1 for B in Bases if B["kind"] == "assembly"))
    print("  cleaned-pseudocode : %d" % sum(1 for B in Bases if B["kind"] == "pseudo"))
    print("expected unmatched   : 1 per side")



if __name__ == "__main__":
    main()
