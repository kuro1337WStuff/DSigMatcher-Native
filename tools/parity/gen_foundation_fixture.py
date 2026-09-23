#!/usr/bin/env python3
"""Generate tests/diff/fixtures/foundation/{main,diff}.sql, the synthetic fixture pair of diff_foundation.

Builds two Diaphora-schema databases from db_support/schema.py TABLES plus every INDICES entry
(imported read-only from an unmodified Diaphora checkout), inserts hand-made synthetic rows (no data
from any real export), runs `analyze` like create_indices (D:634-649) and writes Python's iterdump()
of each, which includes the sqlite_stat1 rows. tests/diff/FixtureDb.h rebuilds the databases from
these files at test time.

The pair is shaped for a mode-N run: different addresses (not stripped, D:2540-2585), one shared name
out of six (not patch-diff, D:2587-2627), plus NULL-vs-'' cells, a 28-digit md_index whose SQLite
cast is not correctly rounded, a nullsub_ and a mangled name.

Usage:
  python -B tools/parity/gen_foundation_fixture.py --diaphora-dir <diaphora-ref> [--out <dir>]
"""
import argparse
import importlib
import os
import sqlite3
import sys

sys.dont_write_bytecode = True
REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
PARSER = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
PARSER.add_argument("--diaphora-dir", default=os.environ.get("DSIG_DIAPHORA_DIR"),
                    help="unmodified Diaphora checkout (default: $DSIG_DIAPHORA_DIR)")
PARSER.add_argument("--out", default=os.path.join(REPO, "tests", "diff", "fixtures", "foundation"))
ARGS = PARSER.parse_args()
if not ARGS.diaphora_dir:
    PARSER.error("--diaphora-dir (or DSIG_DIAPHORA_DIR) is required")
OUT = ARGS.out
sys.path.insert(0, os.path.join(ARGS.diaphora_dir, "db_support"))
schema = importlib.import_module("schema")
sys.path.pop(0)

COLUMNS = ["id", "name", "address", "nodes", "edges", "indegree", "outdegree", "size", "instructions", "mnemonics",
           "names", "prototype", "cyclomatic_complexity", "primes_value", "comment", "mangled_function",
           "bytes_hash", "pseudocode", "pseudocode_lines", "pseudocode_hash1", "pseudocode_primes",
           "function_flags", "assembly", "prototype2", "pseudocode_hash2", "pseudocode_hash3",
           "strongly_connected", "loops", "rva", "tarjan_topological_sort", "strongly_connected_spp",
           "clean_assembly", "clean_pseudo", "mnemonics_spp", "switches", "function_hash", "bytes_sum",
           "md_index", "constants", "constants_count", "segment_rva", "assembly_addrs", "kgh_hash",
           "source_file", "userdata", "microcode", "clean_microcode", "microcode_spp", "export_time"]


def function(fid, name, address, nodes, asm, pseudo, md, consts, mangled=None, clean_asm=None, rva=None):
    row = {c: None for c in COLUMNS}
    row.update({
        "id": fid, "name": name, "address": str(address), "nodes": nodes, "edges": max(nodes - 1, 0),
        "indegree": 1, "outdegree": 2, "size": 10 * nodes, "instructions": 3 * nodes,
        "mnemonics": '["push", "mov", "ret"]', "names": '["callee_%d"]' % (fid % 3),
        "prototype": None, "cyclomatic_complexity": 1, "primes_value": str(2 * nodes + 1), "comment": None,
        "mangled_function": mangled if mangled is not None else name,
        "bytes_hash": "%032x" % (address * 7919), "pseudocode": pseudo,
        "pseudocode_lines": 0 if pseudo is None else pseudo.count("\n") + 1,
        "pseudocode_hash1": None if pseudo is None else "h1_%d" % fid, "pseudocode_primes": None,
        "function_flags": 0, "assembly": asm, "prototype2": None, "pseudocode_hash2": None,
        "pseudocode_hash3": None, "strongly_connected": 1, "loops": 0,
        "rva": str(rva if rva is not None else address - 4096), "tarjan_topological_sort": "[[0]]",
        "strongly_connected_spp": "2", "clean_assembly": clean_asm if clean_asm is not None else asm,
        "clean_pseudo": pseudo, "mnemonics_spp": str(30 + nodes), "switches": "[]",
        "function_hash": "%040x" % (address * 104729), "bytes_sum": address % 1000, "md_index": md,
        "constants": consts, "constants_count": 0 if consts == "[]" else consts.count(",") + 1,
        "segment_rva": str(address - 4096), "assembly_addrs": "[]", "kgh_hash": "0", "source_file": None,
        "userdata": None, "microcode": None, "clean_microcode": None, "microcode_spp": "1",
        "export_time": 0.001 * fid,
    })
    return row


def build(path, rows, processor):
    if os.path.exists(path):
        os.remove(path)
    con = sqlite3.connect(path)
    for sql in schema.TABLES:
        con.execute(sql)
    for i, (table, fields) in enumerate(schema.INDICES):
        con.execute(f"create index if not exists idx_{i} on {table}({fields})")
    con.execute("insert into version values ('3.4')")
    con.execute("insert into program (id, callgraph_primes, callgraph_all_primes, processor, md5sum) "
                "values (1, '6', '{\"2\": 1, \"3\": 1}', ?, ?)", (processor, "00" * 16))
    for row in rows:
        con.execute("insert into functions (%s) values (%s)" % (", ".join(COLUMNS), ", ".join("?" * len(COLUMNS))),
                    [row[c] for c in COLUMNS])
    con.execute("insert into constants (func_id, constant) values (1, 'kernel32.dll')")
    con.execute("insert into constants (func_id, constant) values (2, '4096')")
    con.commit()
    con.execute("analyze")
    con.commit()
    text = "\n".join(con.iterdump()) + "\n"
    con.close()
    os.remove(path)
    return text


ASM_A = "push rbp\nmov rbp, rsp\ncall sub_1000\npop rbp\nret"
ASM_B = "push rbx\nxor eax, eax\nret"
main_rows = [
    function(1, "alpha", 4096, 5, ASM_A, "int alpha()\n{\n  return 1;\n}", "3.050963036440351716676733804",
             '["kernel32.dll", 4096]'),
    function(2, "beta", 5120, 3, ASM_B, None, "0", "[]", clean_asm=""),
    function(3, "gamma", 6144, 7, ASM_A + "\nnop", "void gamma()\n{\n}", "1.25", "[]"),
    function(4, "?delta@@YAXXZ", 7168, 4, ASM_B + "\nnop", "void delta(void)\n{\n}", "2.5", "[]",
             mangled="?delta@@YAXXZ"),
    function(5, "sub_5000", 8192, 6, ASM_A + "\nint3", "int sub_5000()\n{\n  return 0;\n}", "2.5", "[]"),
    function(6, "nullsub_1", 9216, 1, "retn", None, "0", "[]"),
]
diff_rows = [
    function(1, "alpha", 12288, 5, ASM_A, "int alpha()\n{\n  return 1;\n}", "3.050963036440351716676733804",
             '["kernel32.dll", 4096]'),
    function(2, "sub_3400", 13312, 3, ASM_B, None, "0", "[]", clean_asm=""),
    function(3, "sub_3800", 14336, 7, ASM_A + "\nnop", "void sub_3800()\n{\n}", "1.25", "[]"),
    function(4, "sub_3C00", 15360, 4, ASM_B + "\nnop", "void sub_3C00(void)\n{\n}", "2.5", "[]"),
    function(5, "sub_4000", 16384, 6, ASM_A + "\nint3", "int sub_4000()\n{\n  return 0;\n}", "2.5", "[]"),
    function(6, "sub_4400", 17408, 2, "xor eax, eax\nretn", None, "0", "[]"),
    function(7, "sub_4800", 18432, 9, ASM_A + "\nhlt", "int sub_4800()\n{\n}", "7.75", "[]"),
]
os.makedirs(OUT, exist_ok=True)
for name, rows in (("main", main_rows), ("diff", diff_rows)):
    text = build(os.path.join(OUT, name + ".tmp.sqlite"), rows, "metapc")
    with open(os.path.join(OUT, name + ".sql"), "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
print("ok", sqlite3.sqlite_version)
