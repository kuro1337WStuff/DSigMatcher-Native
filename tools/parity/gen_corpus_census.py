#!/usr/bin/env python3
"""Generate tests/diff/generated/corpus_census.inc from the oracle corpus.

The census is what `diff_foundation` checks the native ingest and Path A against:

  * per export: file sha256 (must equal the oracle manifest), functions row count, NULL pseudocode
    count, `name != mangled_function` count, program rows / processor, first version value, table
    presence and row counts, index count, and for every one of the 49 `functions` columns a NULL
    count plus the sha256 of its cell stream in `order by id` order (see CELL ENCODING);
    also the sha256 of `cast(md_index as real)` and `cast(address as real)` in the same order;
  * per oracle pair: for every default-run heuristic (Best and Partial, without the UNRELIABLE flag,
    %POSTFIX% replaced by "") and every Appendix A stage query that needs no bindings, the number of
    rows and the sha256 of the row stream exactly as Python's sqlite3 returns it (ROW ENCODING);
  * the EXPLAIN QUERY PLAN detail rows of `find_same_name` per pair.

Only counts and hashes are written: no function names or other export contents (plan §7.1 D9).

CELL ENCODING (shared with tests/diff/foundation_tests.cpp): per value
    NULL -> "N";  INTEGER -> "I" + decimal;  REAL -> "R" + 16 lowercase hex digits of the IEEE bits;
    TEXT or BLOB -> "S" + byte length + ":" + bytes
  values of one row are joined with 0x1F and each row ends with 0x1E.
ROW ENCODING: the CELL ENCODING of the columns (ea, ea2, description) when the result has all three
  aliases, otherwise of every result column in order.

The exports are opened read-only (`file:...?mode=ro`, diff attached the same way), exactly the way the
native engine opens them; nothing is written to the corpus. Python must be the oracle's interpreter
(sqlite3.sqlite_version 3.51.1), otherwise row order is not the oracle's.

Usage:
  python -B tools/parity/gen_corpus_census.py --corpus <corpus-root> --diaphora-dir <diaphora-ref>
Both paths can also come from DSIG_CORPUS_ROOT / DSIG_DIAPHORA_DIR.
"""

import argparse
import hashlib
import importlib
import json
import os
import pathlib
import sqlite3
import struct
import sys
import time

sys.dont_write_bytecode = True

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

EXPORTS = ["ls-old", "ls", "userenv-9168-pdb", "userenv-9278-nopdb", "userenv-9278-pdb",
           "sechost-9168-pdb", "sechost-9444-nopdb"]
PAIRS = [("ls-old", "ls"), ("ls", "ls-old"), ("userenv-9168-pdb", "userenv-9278-pdb"),
         ("userenv-9168-pdb", "userenv-9278-nopdb"), ("sechost-9168-pdb", "sechost-9444-nopdb")]
# 02 Appendix C records the find_same_name plan on these four (UE, SH, LS, UP)
EQP_PAIRS = [("userenv-9168-pdb", "userenv-9278-nopdb"), ("sechost-9168-pdb", "sechost-9444-nopdb"),
             ("ls", "ls-old"), ("userenv-9168-pdb", "userenv-9278-pdb")]

FUNCTION_COLUMNS = [
    "id", "name", "address", "nodes", "edges", "indegree", "outdegree", "size", "instructions", "mnemonics",
    "names", "prototype", "cyclomatic_complexity", "primes_value", "comment", "mangled_function", "bytes_hash",
    "pseudocode", "pseudocode_lines", "pseudocode_hash1", "pseudocode_primes", "function_flags", "assembly",
    "prototype2", "pseudocode_hash2", "pseudocode_hash3", "strongly_connected", "loops", "rva",
    "tarjan_topological_sort", "strongly_connected_spp", "clean_assembly", "clean_pseudo", "mnemonics_spp",
    "switches", "function_hash", "bytes_sum", "md_index", "constants", "constants_count", "segment_rva",
    "assembly_addrs", "kgh_hash", "source_file", "userdata", "microcode", "clean_microcode", "microcode_spp",
    "export_time"]
TABLES = ["functions", "program", "program_data", "version", "instructions", "basic_blocks", "bb_relations",
          "bb_instructions", "function_bblocks", "callgraph", "constants", "compilation_units",
          "compilation_unit_functions", "sqlite_stat1"]
# sequences slower than this under Python are flagged Long: diff_foundation runs them only with
# DSIG_CENSUS_LONG=1 so every lane's ctest stays fast (sechost H15/H20/H21 take about a minute each)
LONG_SECONDS = 5.0
# Appendix A queries that need no bindings, in StageSql.inc order
STAGE_NO_BIND = ["kSqlVersion", "kSqlEqualDbMd5", "kSqlEqualDbExcept", "kSqlCallgraph", "kSqlTotals",
                 "kSqlEqualMatches", "kSqlSameProcessor", "kSqlStrippedCount", "kSqlStrippedRows",
                 "kSqlPatchCount", "kSqlSameName", "kSqlSmallDifferences", "kSqlUnmatchedUnion",
                 "kSqlUnmatchedMain", "kSqlUnmatchedDiff"]


def cell(value):
    if value is None:
        return b"N"
    if isinstance(value, int):
        return b"I" + str(value).encode("ascii")
    if isinstance(value, float):
        return b"R" + struct.pack(">d", value).hex().encode("ascii")
    if isinstance(value, str):
        value = value.encode("utf-8", "surrogatepass")
    return b"S" + str(len(value)).encode("ascii") + b":" + bytes(value)


def row_bytes(values):
    return b"\x1f".join(cell(v) for v in values) + b"\x1e"


def uri(path):
    text = pathlib.Path(path).resolve().as_posix()
    text = text.replace("%", "%25").replace("?", "%3f").replace("#", "%23")
    if len(text) > 1 and text[1] == ":":
        text = "/" + text
    return "file:" + text + "?mode=ro"


def open_pair(main, diff):
    con = sqlite3.connect(uri(main), uri=True)
    con.text_factory = bytes
    con.execute("attach database ? as diff", (uri(diff),))
    return con


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def export_path(corpus, export_id):
    return os.path.join(corpus, "oracle", "exports", export_id, export_id + ".sqlite")


def census_export(corpus, export_id, manifest):
    path = export_path(corpus, export_id)
    sha = sha256_file(path)
    expected = manifest["exports"][export_id]["sqlite_sha256"]
    if sha != expected:
        raise SystemExit(f"{export_id}: sha256 {sha} != manifest {expected}")
    con = sqlite3.connect(uri(path), uri=True)
    con.text_factory = bytes
    result = {"id": export_id, "sha256": sha}
    names = {row[0].decode() for row in con.execute("select name from sqlite_master where type = 'table'")}
    tables = []
    for table in TABLES:
        if table in names:
            count = con.execute(f"select count(*) from {table}").fetchone()[0]
            tables.append((table, 1, count))
        else:
            tables.append((table, 0, 0))
    result["tables"] = tables
    result["indices"] = con.execute(
        "select count(*) from sqlite_master where type = 'index' and name like 'idx\\_%' escape '\\'").fetchone()[0]
    result["rows"] = con.execute("select count(*) from functions").fetchone()[0]
    result["null_pseudocode"] = con.execute("select count(*) from functions where pseudocode is null").fetchone()[0]
    result["name_ne_mangled"] = con.execute(
        "select count(*) from functions where name != mangled_function").fetchone()[0]
    result["program_rows"] = con.execute("select count(*) from program").fetchone()[0]
    processor = con.execute("select processor from program order by id").fetchone()
    result["processor"] = processor[0].decode("utf-8") if processor and processor[0] is not None else ""
    version = con.execute("select value from version").fetchone()
    result["version"] = version[0].decode("utf-8") if version and version[0] is not None else ""
    columns = []
    for column in FUNCTION_COLUMNS:
        digest = hashlib.sha256()
        nulls = 0
        for (value,) in con.execute(f"select {column} from functions order by id"):
            if value is None:
                nulls += 1
            digest.update(row_bytes([value]))
        columns.append((column, nulls, digest.hexdigest()))
    result["columns"] = columns
    for label, expr in (("md_sqlreal", "cast(md_index as real)"), ("address_sqlreal", "cast(address as real)")):
        digest = hashlib.sha256()
        for (value,) in con.execute(f"select {expr} from functions order by id"):
            digest.update(row_bytes([value]))
        result[label] = digest.hexdigest()
    con.close()
    return result


def select_columns(description):
    names = [d[0].lower() for d in description]
    if all(n in names for n in ("ea", "ea2", "description")):
        return [names.index("ea"), names.index("ea2"), names.index("description")]
    return list(range(len(names)))


def run_sequence(con, sql):
    cursor = con.execute(sql)
    picks = select_columns(cursor.description)
    digest = hashlib.sha256()
    count = 0
    while True:
        rows = cursor.fetchmany(32)
        if not rows:
            break
        for row in rows:
            digest.update(row_bytes([row[i] for i in picks]))
            count += 1
    return count, digest.hexdigest()


def load_stage_sql(diaphora_dir):
    sys.path.insert(0, os.path.join(REPO, "tools", "parity"))
    try:
        gen = importlib.import_module("gen_registry")
    finally:
        sys.path.pop(0)
    module, _ = gen.load_heuristics(diaphora_dir)
    src = gen.DiaphoraSource(diaphora_dir)
    stages = {s["name"]: s["sql"] for s in gen.build_stage_sql(src, module)}
    return module, stages


def census_pairs(corpus, module, stages, verbose):
    queries = []
    for index, heur in enumerate(module.HEURISTICS):
        if heur["category"] not in ("Best", "Partial"):
            continue
        if module.HEUR_FLAG_UNRELIABLE in heur["flags"]:
            continue
        queries.append((f"heuristic:{index}", heur["sql"].replace("%POSTFIX%", "")))
    for name in STAGE_NO_BIND:
        queries.append((name, stages[name]))
    results = []
    for main, diff in PAIRS:
        con = open_pair(export_path(corpus, main), export_path(corpus, diff))
        for label, sql in queries:
            started = time.monotonic()
            count, digest = run_sequence(con, sql)
            elapsed = time.monotonic() - started
            if verbose:
                print(f"  {main}_vs_{diff} {label}: {count} rows, {elapsed:.2f}s", flush=True)
            results.append((f"{main}_vs_{diff}", main, diff, label, count, digest, elapsed > LONG_SECONDS))
        con.close()
    return results


def census_eqp(corpus, stages):
    results = []
    for main, diff in EQP_PAIRS:
        con = open_pair(export_path(corpus, main), export_path(corpus, diff))
        details = [row[3].decode() if isinstance(row[3], bytes) else row[3]
                   for row in con.execute("explain query plan " + stages["kSqlSameName"])]
        con.close()
        results.append((f"{main}_vs_{diff}", main, diff, details))
    return results


def c_string(text):
    return json.dumps(text)  # ASCII-only JSON string literal is a valid C++ string literal here


def render(exports, sequences, eqp, python_sqlite):
    out = []
    out.append("// Generated by tools/parity/gen_corpus_census.py from the oracle corpus (counts and sha256")
    out.append(f"// only; SQLite {python_sqlite} through Python's sqlite3). Do not edit by hand.")
    out.append("// clang-format off")
    out.append(f'#define DSIG_CENSUS_SQLITE_VERSION "{python_sqlite}"')
    out.append("struct CensusColumn { const char* Name; long long Nulls; const char* Sha256; };")
    out.append("struct CensusTable { const char* Name; int Present; long long Rows; };")
    out.append("struct CensusExport { const char* Id; const char* Sha256; long long Rows; long long NullPseudocode;")
    out.append("  long long NameNeMangled; long long ProgramRows; const char* Processor; const char* Version;")
    out.append("  long long IndexCount; const char* MdSqlRealSha256; const char* AddressSqlRealSha256;")
    out.append("  CensusTable Tables[%d]; CensusColumn Columns[%d]; };" % (len(TABLES), len(FUNCTION_COLUMNS)))
    out.append("static const CensusExport kCensusExports[] = {")
    for e in exports:
        out.append("  {" + f"{c_string(e['id'])}, {c_string(e['sha256'])}, {e['rows']}, {e['null_pseudocode']},")
        out.append(f"   {e['name_ne_mangled']}, {e['program_rows']}, {c_string(e['processor'])}, "
                   f"{c_string(e['version'])}, {e['indices']}, {c_string(e['md_sqlreal'])}, "
                   f"{c_string(e['address_sqlreal'])},")
        out.append("   {" + ", ".join("{%s, %d, %d}" % (c_string(t), p, c) for t, p, c in e["tables"]) + "},")
        out.append("   {")
        for name, nulls, digest in e["columns"]:
            out.append(f"    {{{c_string(name)}, {nulls}, {c_string(digest)}}},")
        out.append("   }},")
    out.append("};")
    out.append("struct CensusSequence { const char* Pair; const char* Main; const char* Diff; const char* Query;")
    out.append("  long long Rows; const char* Sha256; int Long; };")
    out.append("static const CensusSequence kCensusSequences[] = {")
    for pair, main, diff, label, count, digest, slow in sequences:
        out.append(f"  {{{c_string(pair)}, {c_string(main)}, {c_string(diff)}, {c_string(label)}, {count}, "
                   f"{c_string(digest)}, {1 if slow else 0}}},")
    out.append("};")
    out.append("struct CensusPlan { const char* Pair; const char* Main; const char* Diff; int Count; const char* Detail[16]; };")
    out.append("static const CensusPlan kCensusSameNamePlans[] = {")
    for pair, main, diff, details in eqp:
        if len(details) > 16:
            raise SystemExit("plan too long")
        out.append(f"  {{{c_string(pair)}, {c_string(main)}, {c_string(diff)}, {len(details)}, "
                   "{" + ", ".join(c_string(d) for d in details) + "}},")
    out.append("};")
    out.append("// clang-format on")
    return "\n".join(out) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--corpus", default=os.environ.get("DSIG_CORPUS_ROOT"),
                        help="corpus root holding oracle/ (default: $DSIG_CORPUS_ROOT)")
    parser.add_argument("--diaphora-dir", default=os.environ.get("DSIG_DIAPHORA_DIR"),
                        help="unmodified Diaphora checkout (default: $DSIG_DIAPHORA_DIR)")
    parser.add_argument("--repo", default=REPO)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--allow-other-sqlite", action="store_true",
                        help="do not insist on the oracle's SQLite 3.51.1 (the census is then not the oracle's)")
    args = parser.parse_args()
    if not args.corpus or not args.diaphora_dir:
        parser.error("--corpus and --diaphora-dir (or DSIG_CORPUS_ROOT / DSIG_DIAPHORA_DIR) are required")
    if sqlite3.sqlite_version != "3.51.1" and not args.allow_other_sqlite:
        raise SystemExit(f"Python's sqlite3 is {sqlite3.sqlite_version}, the oracle's is 3.51.1")

    with open(os.path.join(args.corpus, "oracle", "manifest.json"), "r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    module, stages = load_stage_sql(args.diaphora_dir)

    started = time.monotonic()
    exports = [census_export(args.corpus, e, manifest) for e in EXPORTS]
    print(f"ingest census: {len(exports)} exports in {time.monotonic() - started:.1f}s", flush=True)
    started = time.monotonic()
    sequences = census_pairs(args.corpus, module, stages, args.verbose)
    print(f"row-sequence census: {len(sequences)} sequences in {time.monotonic() - started:.1f}s", flush=True)
    eqp = census_eqp(args.corpus, stages)

    path = os.path.join(args.repo, "tests", "diff", "generated", "corpus_census.inc")
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(render(exports, sequences, eqp, sqlite3.sqlite_version))
    print(f"wrote {os.path.relpath(path, args.repo)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
