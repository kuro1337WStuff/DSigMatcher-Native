#!/usr/bin/env python3
"""Ratio vectors for lane L2 (docs/parity/00-plan.md §4 L2; spec docs/parity/03a-ratio.md §13).

Every expected value is produced by the REAL, unmodified Diaphora (or CPython itself):
  * CBinDiff.check_ratio on main_d/diff_d built exactly like check_match (D:1798-1842) from a
    SELECT_FIELDS row (H:51-84): the SQL path, md from `cast(md_index as real)`;
  * CBinDiff.compare_function_rows (D:2479-2538) on `select *` rows: the row path, md from float(text);
  * float("{0:.7f}".format(v)), float(str), repr(float), json.loads + set, diaphora.quick_ratio.
ratios_cache is emptied before every evaluation, so each value comes from the path it is filed under.

Subcommands
  synthetic --set committed [--out DIR]   the synthetic suite committed under tests/diff/vectors/ratio
  synthetic --set 03a --out DIR           the 03a §13 harness seed set (86,800 pairs, both paths); too
                                          large to commit, so it goes to <corpus>/oracle/vectors/ratio
  values [--big] [--out DIR]              Python value-semantics vectors (values.json, or values-big.json)
  corpus [--pairs P ...] [--sample N]     oracle exports: every (ea1, ea2) of the add_match events (and,
                                          for finished pairs, the row events) of the traces plus an
                                          N-pair random sample (default 20,000) of every pair, written
                                          to <corpus>/oracle/vectors/ratio/corpus/ (never committed)

Paths come from flags or the environment only: --diaphora-dir / DSIG_DIAPHORA_DIR, --corpus /
DSIG_CORPUS_ROOT. Diaphora is imported read-only (sys.dont_write_bytecode) and only ever opens COPIES
of databases, because CBinDiff opens db1 read/write (create_schema, D:571-580).

Run with the oracle's Python (CPython 3.13.12, sqlite3 3.51.1, no cdifflib); the environment is
recorded in every output.
"""
import argparse
import hashlib
import json
import os
import random
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
sys.set_int_max_str_digits(0)  # as diaphora.py does at import (D:96-97)

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
SCHEMA_ID = "dsig-ratio-vectors/1"


# ------------------------------------------------------------------------------------------------
# Environment

def Hex(Value):
    """IEEE-754 bits of float(x) as 16 lowercase hex digits (plan Appendix B ratio_bits)."""
    return struct.pack(">d", float(Value)).hex()


def Git(Dir, *ArgList):
    return subprocess.run(["git", "-C", Dir] + list(ArgList), capture_output=True, text=True).stdout.strip()


def LoadDiaphora(Dir):
    for Key in [K for K in os.environ if K.upper().startswith("DIAPHORA_")]:
        del os.environ[Key]  # build_oracle.CleanEnv() semantics: the default configuration (plan §1.1)
    sys.path.insert(0, Dir)
    import diaphora  # noqa: E402  (the unmodified checkout)
    from db_support import schema  # noqa: E402
    import diaphora_heuristics  # noqa: E402
    Env = {
        "python": sys.version.split()[0],
        "sqlite": sqlite3.sqlite_version,
        "diaphora": Git(Dir, "describe", "--tags", "--long", "--dirty"),
        "cdifflib": bool(getattr(diaphora, "HAS_CDIFFLIB", False)),
        "relaxed_ratio": False,
    }
    if Env["cdifflib"]:
        raise SystemExit("cdifflib is installed: this Python is not an oracle (plan §1.6)")
    return diaphora, schema, diaphora_heuristics, Env


class RatioOracle:
    """A CBinDiff on COPIES of two databases, set up exactly as `__main__` + diff() do."""

    def __init__(self, Diaphora, Heuristics, Db1, Db2):
        self.D = Diaphora
        self.Bd = Diaphora.CBinDiff(Db1)             # D:3757 (opens db1, create_schema)
        self.Bd.ignore_all_names = False             # D:3759-3760
        self.Bd.db = Diaphora.sqlite3_connect(Db1)   # D:3761
        Cur = self.Bd.db_cursor()
        self.Bd.try_attach(Cur, Db2)                 # D:3575
        Cur.close()
        self.Bd.last_diff_db = Db2
        self.Bd.ratios_cache = {}                    # D:3572
        self.Bd.is_same_processor = self.Bd.same_processor_both_databases()  # D:3617
        assert not self.Bd.relaxed_ratio and self.Bd.classifier is None
        self.Fields = Heuristics.get_query_fields("ratio vector")

    def Cursor(self):
        return self.Bd.db_cursor()

    def Close(self):
        """Closes every connection (diaphora keeps them in _DATABASES and dbs_dict), so the copies can
        be deleted on Windows."""
        Seen = set()
        for Db in [self.Bd.db] + list(self.Bd.dbs_dict.values()) + list(getattr(self.D, "_DATABASES", {}).values()):
            if Db is not None and id(Db) not in Seen:
                Seen.add(id(Db))
                try:
                    Db.close()
                except Exception:  # noqa: BLE001 - already closed
                    pass
        self.Bd.dbs_dict.clear()
        getattr(self.D, "_DATABASES", {}).clear()
        self.Bd.db = None

    @staticmethod
    def MainD(Row, Suffix):
        # check_match's dict builder (D:1798-1842), the keys check_ratio reads
        return {
            "ea": Row["ea" if Suffix == "1" else "ea2"], "name": Row["name" + Suffix],
            "pseudo": Row["pseudo" + Suffix], "asm": Row["asm" + Suffix],
            "pseudocode_primes": Row["pseudo_primes" + Suffix], "nodes": Row["nodes" + Suffix],
            "md_index": Row["md" + Suffix], "clean_assembly": Row["clean_assembly" + Suffix],
            "clean_pseudo": Row["clean_pseudo" + Suffix], "clean_micro": Row["clean_micro" + Suffix],
            "bytes_hash": Row["bytes_hash" + Suffix], "edges": Row["edges" + Suffix],
            "indegree": Row["indegree" + Suffix], "outdegree": Row["outdegree" + Suffix],
            "instructions": Row["instructions" + Suffix], "cyclomatic_complexity": Row["cc" + Suffix],
            "strongly_connected": Row["strongly_connected" + Suffix], "loops": Row["loops" + Suffix],
            "constants_count": Row["constants_count" + Suffix], "size": Row["size" + Suffix],
            "kgh_hash": Row["kgh_hash" + Suffix],
        }

    def SqlRatio(self, Row):
        """check_ratio through the check_match path for one SELECT_FIELDS row."""
        self.Bd.ratios_cache = {}
        try:
            return Hex(self.Bd.check_ratio(self.MainD(Row, "1"), self.MainD(Row, "2")))
        except Exception as Error:  # noqa: BLE001 - every Python exception is an outcome
            return "raise:" + type(Error).__name__

    def RowRatio(self, MainRow, DiffRow):
        self.Bd.ratios_cache = {}
        try:
            return Hex(self.Bd.compare_function_rows(MainRow, DiffRow))
        except Exception as Error:  # noqa: BLE001
            return "raise:" + type(Error).__name__

    def SelectFieldsRow(self, Ea1, Ea2):
        Cur = self.Cursor()
        try:
            Cur.execute("select " + self.Fields + " from main.functions f, diff.functions df "
                        "where f.address = ? and df.address = ?", (Ea1, Ea2))
            return Cur.fetchone()
        finally:
            Cur.close()

    def FullRow(self, Db, Ea):
        Cur = self.Cursor()
        try:
            Cur.execute(f"select * from {Db}.functions where address = ?", (Ea,))
            return Cur.fetchone()
        finally:
            Cur.close()


# ------------------------------------------------------------------------------------------------
# Synthetic databases

FUNCTION_COLUMNS = ["id", "name", "address", "nodes", "edges", "indegree", "outdegree", "size", "instructions",
                    "mnemonics", "names", "prototype", "cyclomatic_complexity", "primes_value", "comment",
                    "mangled_function", "bytes_hash", "pseudocode", "pseudocode_lines", "pseudocode_hash1",
                    "pseudocode_primes", "function_flags", "assembly", "prototype2", "pseudocode_hash2",
                    "pseudocode_hash3", "strongly_connected", "loops", "rva", "tarjan_topological_sort",
                    "strongly_connected_spp", "clean_assembly", "clean_pseudo", "mnemonics_spp", "switches",
                    "function_hash", "bytes_sum", "md_index", "constants", "constants_count", "segment_rva",
                    "assembly_addrs", "kgh_hash", "source_file", "userdata", "microcode", "clean_microcode",
                    "microcode_spp", "export_time"]


def BuildDb(Schema, Path, Rows, Processor):
    for Suffix in ("", "-wal", "-shm", "-journal"):
        if os.path.exists(Path + Suffix):
            os.remove(Path + Suffix)
    Con = sqlite3.connect(Path)
    for Sql in Schema.TABLES:
        Con.execute(Sql)
    Con.execute("insert into version values ('3.4')")
    Con.execute("insert into program (callgraph_primes, callgraph_all_primes, processor, md5sum) "
                "values ('1', '{}', ?, 'x')", (Processor,))
    Columns = sorted({C for Row in Rows for C in Row})
    for C in Columns:
        assert C in FUNCTION_COLUMNS, C
    Con.executemany(f"insert into functions ({','.join(Columns)}) values ({','.join('?' * len(Columns))})",
                    [tuple(Row.get(C) for C in Columns) for Row in Rows])
    Con.commit()
    Con.close()
    return Columns


def EncodeValue(Value, Rle, Vocab):
    """null | int | str | {"b": hex} (bytes, a BLOB cell) | {"t": [[vocab index, count], ...]}: the text
    is the vocab lines, each repeated count times, run after run, joined with a newline."""
    if isinstance(Value, bytes):
        return {"b": Value.hex()}
    if isinstance(Value, str) and Rle:
        Pieces = Value.split("\n")
        if len(Pieces) > 4:
            Runs = []
            for Piece in Pieces:
                Index = Vocab.setdefault(Piece, len(Vocab))
                if Runs and Runs[-1][0] == Index:
                    Runs[-1][1] += 1
                else:
                    Runs.append([Index, 1])
            return {"t": Runs}
    return Value


def EvaluatePair(Diaphora, Heuristics, Schema, Env, Name, MainRows, DiffRows, SameCpu, WorkDir, Rle, Labels=None):
    """Builds the two databases, runs the real Diaphora over the cross product and returns the vector
    document (functions, SQL-path md values, expected results)."""
    Db1 = os.path.join(WorkDir, Name + "-main.sqlite")
    Db2 = os.path.join(WorkDir, Name + "-diff.sqlite")
    for Index, Row in enumerate(MainRows):
        Row["id"] = Index + 1
    for Index, Row in enumerate(DiffRows):
        Row["id"] = Index + 1
    Columns1 = BuildDb(Schema, Db1, MainRows, "metapc")
    Columns2 = BuildDb(Schema, Db2, DiffRows, "metapc" if SameCpu else "arm")
    Oracle = RatioOracle(Diaphora, Heuristics, Db1, Db2)
    assert Oracle.Bd.is_same_processor == SameCpu
    Cur = Oracle.Cursor()
    SqlRows = {}
    Cur.execute("select " + Oracle.Fields + " from main.functions f, diff.functions df")
    for Row in Cur.fetchall():
        SqlRows[(Row["ea"], Row["ea2"])] = Row
    MainFull = {R["address"]: R for R in Cur.execute("select * from main.functions order by id").fetchall()}
    DiffFull = {R["address"]: R for R in Cur.execute("select * from diff.functions order by id").fetchall()}
    MdSql1 = [R[0] for R in Cur.execute("select cast(md_index as real) from main.functions order by id")]
    MdSql2 = [R[0] for R in Cur.execute("select cast(md_index as real) from diff.functions order by id")]
    Cur.close()
    Results = []
    Differ = 0
    for M in MainRows:
        for D in DiffRows:
            Sql = Oracle.SqlRatio(SqlRows[(M["address"], D["address"])])
            Py = Oracle.RowRatio(MainFull[M["address"]], DiffFull[D["address"]])
            Differ += Sql != Py
            Results.append(Sql if Sql == Py else Sql + "|" + Py)
    Oracle.Close()
    Doc = {
        "schema": SCHEMA_ID,
        "name": Name,
        "generator": "tools/parity/gen_ratio_vectors.py",
        "environment": Env,
        "same_processor": SameCpu,
        "ddl": [Sql for Sql in Schema.TABLES if "table functions" in " ".join(Sql.split()).lower()
                or "table if not exists functions" in " ".join(Sql.split()).lower()],
        "columns": sorted(set(Columns1) | set(Columns2)),
    }
    Cols = Doc["columns"]
    Vocab = {}
    Doc["main"] = [[EncodeValue(R.get(C), Rle, Vocab) for C in Cols] for R in MainRows]
    Doc["diff"] = [[EncodeValue(R.get(C), Rle, Vocab) for C in Cols] for R in DiffRows]
    Doc["vocab"] = list(Vocab)
    Doc["main_md_sql"] = [None if V is None else Hex(V) for V in MdSql1]
    Doc["diff_md_sql"] = [None if V is None else Hex(V) for V in MdSql2]
    if Labels:
        Doc["labels"] = Labels
    # results[i * len(diff) + j] indexes outcomes: "<sql bits>" when both paths agree, else
    # "<sql>|<py>"; bits are 16 hex digits, "raise:<Exception>" is a Python exception
    Outcomes = {}
    Doc["outcomes"] = []
    Doc["results"] = []
    for Result in Results:
        if Result not in Outcomes:
            Outcomes[Result] = len(Outcomes)
            Doc["outcomes"].append(Result)
        Doc["results"].append(Outcomes[Result])
    Doc["stats"] = {"pairs": len(Results), "sql_py_differ": Differ,
                    "raises": sum(1 for R in Results if "raise" in R)}
    return Doc


# ---- the 03a §13 harness generator, verbatim in its random draws -------------------------------------

HARNESS_VOCAB = [f"mov eax, XXXX{i}" for i in range(12)] + ["", "ret", "push ebp", "call XXXX"]
HARNESS_MD_POOL = ["0", "1.414213562373095048801688724", "3.162277660168379332", "12.5",
                   "0.7071067811865475244008443621", "0.70710678118654752440084436210",
                   "0.7071067811865475244008443622"]
HARNESS_CONST_POOL = [4096, 5000, 70000, 18446744073709551615, 18446744073709551614, "hello world",
                      "café string", "\\u0041BCDE", 4294967296]


def HarnessRows(Seed, N, NearCopy):
    """The generator of the 03a verification harness (scratch harness.py): the same random.Random
    draws in the same order, so seeds reproduce its databases. NearCopy=False is the pre-change
    variant (seeds 1,2,3,7,11,12 / 5,6,21); NearCopy=True the later one (seeds 3,4,8,13 / 9)."""
    Rnd = random.Random(Seed)

    def RandText():
        R = Rnd.random()
        if R < 0.06:
            return None
        if R < 0.10:
            return ""
        Count = Rnd.choice([1, 2, 3, 5, 8, 20, 64, 255, 256, 257])
        Lines = [Rnd.choice(HARNESS_VOCAB) for _ in range(Count)]
        Text = "\n".join(Lines)
        if Rnd.random() < 0.1:
            Text += "\n"
        return Text

    def MakeRows(SeedShift, Base):
        Rows = []
        for I in range(N):
            Addr = 0x401000 + I * 0x10 + (0 if SeedShift == 0 else Rnd.choice([0, 0x10000]))
            Pseudo = RandText()
            CleanPseudo = Pseudo if Rnd.random() < 0.8 else RandText()
            Consts = Rnd.sample(HARNESS_CONST_POOL, Rnd.randint(0, 4))
            if Rnd.random() < 0.2:
                Consts = Consts + Consts
            Switches = Rnd.choice(["[]", "[[3, [0, 1, 2]]]", "[[4, [0, 1, 2, 3]]]", None])
            Rows.append(dict(
                name=f"sub_{Addr:X}" if Rnd.random() < 0.7 else f"func_{I}",
                address=Addr, nodes=Rnd.randint(1, 9), edges=Rnd.randint(0, 9),
                indegree=Rnd.choice([0, 1, 2, None]), outdegree=Rnd.choice([0, 1, 2]),
                cyclomatic_complexity=Rnd.choice([0, 1, 2, 3]),
                bytes_hash=Rnd.choice(["aa", "bb", "cc", "dd", "ee", None]),
                pseudocode=Pseudo, clean_pseudo=CleanPseudo,
                assembly="x", clean_assembly=RandText(),
                clean_microcode=RandText(),
                md_index=Rnd.choice(HARNESS_MD_POOL),
                pseudocode_primes=Rnd.choice([None, "", "6", "30", "210", "1155", "7"]),
                source_file=Rnd.choice([None, "", "a.c", "b.c"]),
                switches=Switches,
                constants=json.dumps(Consts, ensure_ascii=False),
                constants_count=len(Consts), size=10, instructions=5, loops=0, strongly_connected=1,
                kgh_hash="0", mangled_function=f"m{I}",
            ))
        if SeedShift != 0 and NearCopy and Rnd.random() < 2:
            for I, Row in enumerate(Rows):
                if Rnd.random() < 0.6:
                    B = dict(Base[I])
                    B["address"] = Row["address"]
                    B["name"] = Row["name"]
                    for Col in ("clean_pseudo", "clean_assembly", "clean_microcode"):
                        T = B[Col]
                        if T and Rnd.random() < 0.7:
                            Ls = T.split(chr(10))
                            J = Rnd.randrange(len(Ls))
                            Ls[J] = Ls[J] + "_x"
                            B[Col] = chr(10).join(Ls)
                    if Rnd.random() < 0.5:
                        B["bytes_hash"] = "zz"
                    if Rnd.random() < 0.3:
                        B["md_index"] = Rnd.choice(HARNESS_MD_POOL)
                    Rows[I] = B
        return Rows

    Main = MakeRows(0, None)
    Diff = MakeRows(1, [dict(R) for R in Main])
    for Row in Main + Diff:
        Row["address"] = str(Row["address"])  # TEXT affinity stores the int as decimal text
    return Main, Diff


def SortLines(Rows):
    """Canonical line order for the committed suite (quick_ratio is a multiset formula, 03a §2, and the
    databases are BUILT from the sorted text, so Python sees exactly what is committed)."""
    for Row in Rows:
        for Col in ("pseudocode", "clean_pseudo", "clean_assembly", "clean_microcode"):
            if isinstance(Row.get(Col), str):
                Row[Col] = "\n".join(sorted(Row[Col].split("\n")))
    return Rows


# ---- the hand-made scenarios of the committed suite ---------------------------------------------

def Lines(**Counts):
    """A text with the given line counts, e.g. Lines(a=253, b=3); '_' names map to odd lines."""
    Parts = []
    for Key, Count in Counts.items():
        Parts += [Key] * Count
    return "\n".join(Parts)


def FindMdDivergence(Count, Seed):
    """28-digit md_index strings (the exporter's str(Decimal)) where SQLite 3.51.1's cast differs from
    Python float() (03a §6.4), with partner strings that collide under exactly one converter."""
    Rnd = random.Random(Seed)
    Con = sqlite3.connect(":memory:")
    Found = []
    while len(Found) < Count:
        Text = f"{Rnd.randint(1, 9)}." + "".join(str(Rnd.randint(0, 9)) for _ in range(27))
        SqlValue = Con.execute("select cast(? as real)", (Text,)).fetchone()[0]
        PyValue = float(Text)
        if SqlValue == PyValue:
            continue
        SqlPartner = repr(SqlValue)   # SQLite-equal, Python-different
        PyPartner = repr(PyValue)     # Python-equal, SQLite-different
        Ok = (Con.execute("select cast(? as real)", (SqlPartner,)).fetchone()[0] == SqlValue
              and float(SqlPartner) != PyValue
              and float(PyPartner) == PyValue
              and Con.execute("select cast(? as real)", (PyPartner,)).fetchone()[0] != SqlValue)
        if Ok:
            Found.append((Text, SqlPartner, PyPartner))
    Con.close()
    return Found


def TargetedRows():
    """Hand-made functions: every quirk of 03a §5-§8 and every mutation of 03a §13 is hit by at least
    one (main[k], diff[k]) pair; the cross product adds the combinations."""
    Divergent = FindMdDivergence(3, 20260923)
    Main, Diff, Labels = [], [], []
    AUTO = "<auto>"

    def Fn(**Cols):
        Row = {"name": None, "address": None, "nodes": 3, "edges": 2, "indegree": 0, "outdegree": 0,
               "cyclomatic_complexity": 0, "bytes_hash": AUTO, "pseudocode": None, "clean_pseudo": None,
               "assembly": "x", "clean_assembly": None, "clean_microcode": None, "md_index": "0",
               "pseudocode_primes": None, "source_file": None, "switches": "[]", "constants": "[]",
               "constants_count": 0, "size": 10, "instructions": 5, "loops": 0, "strongly_connected": 1,
               "kgh_hash": "0", "mangled_function": None}
        Row.update(Cols)
        return Row

    def Add(Label, M, D):
        K = len(Main)
        if M["bytes_hash"] == AUTO:
            M["bytes_hash"] = f"m{K:02d}"   # distinct hashes unless a scenario sets them
        if D["bytes_hash"] == AUTO:
            D["bytes_hash"] = f"d{K:02d}"
        if M["address"] is None:
            M["address"] = str(5000000 + 16 * K)
        if D["address"] is None:
            D["address"] = str(6000000 + 16 * K)
        M["name"] = M["name"] or f"f{K:02d}"
        D["name"] = D["name"] or f"g{K:02d}"
        M["mangled_function"] = M["name"]
        D["mangled_function"] = D["name"]
        Main.append(M)
        Diff.append(D)
        Labels.append(Label)

    # 03a §5 ties (denominator 256): v2, v1, v5, and L = 1536
    Add("tie v2 m=1 L=512", Fn(clean_assembly=Lines(a=1, b=255)), Fn(clean_assembly=Lines(a=1, c=255)))
    Add("tie v2 m=253 L=512", Fn(clean_assembly=Lines(a=253, b=3), md_index="2.5"),
        Fn(clean_assembly=Lines(a=253, c=3), md_index="2.5"))
    Add("tie v1 m=255 L=512", Fn(pseudocode="p", clean_pseudo=Lines(a=255, b=1)),
        Fn(pseudocode="q", clean_pseudo=Lines(a=255, c=1)))
    Add("tie v5 m=3 L=1536", Fn(clean_microcode=Lines(a=3, b=765)), Fn(clean_microcode=Lines(a=3, c=765)))
    Add("tie v2 m=5 L=512 + deep", Fn(clean_assembly=Lines(a=5, b=251), indegree=2),
        Fn(clean_assembly=Lines(a=5, c=251), indegree=2))
    # v5 == 1.0 short-circuits even with different MD-Indices (03a §6.3)
    Add("v5 short circuit", Fn(clean_microcode="x\ny", md_index="1.5", clean_assembly=Lines(a=2, b=2)),
        Fn(clean_microcode="x\ny", md_index="2.5", clean_assembly=Lines(a=2, c=2)))
    # v2 == 1.0 dropped when the MD-Indices differ (D:1757-1764)
    Add("md guard", Fn(clean_assembly="a\nb\nc", md_index="1.5", pseudocode="p", clean_pseudo=Lines(a=1, b=1)),
        Fn(clean_assembly="a\nb\nc", md_index="2.5", pseudocode="q", clean_pseudo=Lines(a=1, c=1)))
    # the 0.99 clamp (D:1766-1770): v4 = (0.99 + 0.99 + 3) / 5 = 0.996 plus 0.007 of deep bonus
    Deep = dict(source_file="a.c", pseudocode_primes="30", indegree=2, outdegree=1, switches="[[3, [0, 1, 2]]]")
    Add("clamp 0.99", Fn(pseudocode="p", clean_pseudo=Lines(a=99, b=1), clean_assembly=Lines(a=99, b=1),
                         md_index="3.5", **Deep),
        Fn(pseudocode="q", clean_pseudo=Lines(a=99, c=1), clean_assembly=Lines(a=99, c=1), md_index="3.5", **Deep))
    Add("below clamp", Fn(clean_assembly=Lines(a=9, b=1), md_index="3.5", source_file="a.c"),
        Fn(clean_assembly=Lines(a=9, c=1), md_index="3.5", source_file="a.c"))
    # constants: exact big integers (a double would merge them), per-constant 0.006 / 0.008
    Add("u64 constants", Fn(clean_assembly="a\nb", constants="[18446744073709551615]", constants_count=1),
        Fn(clean_assembly="a\nc", constants="[18446744073709551614]", constants_count=1))
    Add("two shared constants", Fn(clean_assembly="a\nb", constants='[4096, "hello world"]'),
        Fn(clean_assembly="a\nc", constants='[4096, "hello world", 5]'))
    # None == None for bytes_hash gives 1.0 (D:1681)
    Add("NULL bytes_hash", Fn(bytes_hash=None, clean_assembly="a"),
        Fn(bytes_hash=None, clean_assembly="b"))
    # float(None) raises before the bytes_hash shortcut (03a §6.3 order of failure)
    Add("NULL md raises first", Fn(md_index=None, bytes_hash="zz"),
        Fn(md_index="1.5", bytes_hash="zz"))
    # md converters: SQLite cast vs Python float() (03a §6.4)
    Text, SqlPartner, PyPartner = Divergent[0]
    Add("md SQLite-equal", Fn(clean_assembly="a\nb\nc", md_index=Text), Fn(clean_assembly="a\nb\nc", md_index=SqlPartner))
    Text, SqlPartner, PyPartner = Divergent[1]
    Add("md Python-equal", Fn(clean_assembly=Lines(a=3, b=1), md_index=Text),
        Fn(clean_assembly=Lines(a=3, c=1), md_index=PyPartner))
    Text, SqlPartner, PyPartner = Divergent[2]
    Add("md SQLite-equal partial", Fn(clean_assembly=Lines(a=3, b=1), md_index=SqlPartner),
        Fn(clean_assembly=Lines(a=3, c=1), md_index=Text))
    Add("md equal value, different text", Fn(clean_assembly=Lines(a=3, b=2), md_index="1.5"),
        Fn(clean_assembly=Lines(a=3, c=2), md_index="1.50"))
    Add("md nan", Fn(clean_assembly="a\nb", md_index="nan"), Fn(clean_assembly="a\nb", md_index="nan"))
    Add("md inf", Fn(clean_assembly=Lines(a=2, b=1), md_index="inf"), Fn(clean_assembly=Lines(a=2, c=1), md_index="inf"))
    Add("md not a number", Fn(clean_assembly="a", md_index="abc"), Fn(clean_assembly="a", md_index="0"))
    Add("md python syntax", Fn(clean_assembly=Lines(a=2, b=1), md_index=" 1_000 "),
        Fn(clean_assembly=Lines(a=2, c=1), md_index="1e3"))
    Add("md zero", Fn(clean_assembly=Lines(a=2, b=1), md_index="0"), Fn(clean_assembly=Lines(a=2, c=1), md_index="0.0"))
    # str.split("\n") keeps the trailing empty piece and "\r" (03a §2)
    Add("trailing newline", Fn(clean_assembly="a\nb\n"), Fn(clean_assembly="a\nb"))
    Add("carriage return", Fn(clean_assembly="a\r\nb\rc"), Fn(clean_assembly="a\nb\nc"))
    Add("embedded NUL", Fn(clean_assembly="a\x00b\nc\nd"), Fn(clean_assembly="a\x00b\nc\ne"))
    Add("non-ASCII lines", Fn(clean_assembly="mov é\nret\n中"), Fn(clean_assembly="mov é\nnop\n中"))
    # v1 preconditions (D:1699-1720)
    Add("empty clean_pseudo", Fn(pseudocode="p", clean_pseudo="", clean_assembly="a\nb"),
        Fn(pseudocode="q", clean_pseudo="a\nb", clean_assembly="a\nc"))
    Add("NULL clean_pseudo", Fn(pseudocode="p", clean_pseudo=None, clean_assembly="a\nb"),
        Fn(pseudocode="q", clean_pseudo="a\nb", clean_assembly="a\nc"))
    Add("empty pseudocode", Fn(pseudocode="", clean_pseudo="a\nb", clean_assembly="x"),
        Fn(pseudocode="q", clean_pseudo="a\nb", clean_assembly="y"))
    Add("identical pseudo, same md", Fn(pseudocode="p", clean_pseudo="a\nb", md_index="4.25", clean_assembly="x"),
        Fn(pseudocode="q", clean_pseudo="a\nb", md_index="4.25", clean_assembly="y"))
    Add("empty microcode", Fn(clean_microcode="", clean_assembly="a"), Fn(clean_microcode="", clean_assembly="a\nb"))
    # set semantics of json.loads(constants) (03a §7.1)
    Add("NaN constants", Fn(clean_assembly="a\nb", constants="[NaN]"), Fn(clean_assembly="a\nc", constants="[NaN, 1]"))
    Add("true vs 1", Fn(clean_assembly="a\nb", constants='[true, "x"]'), Fn(clean_assembly="a\nc", constants='[1, "y"]'))
    Add("escaped vs raw str", Fn(clean_assembly="a\nb", constants='["\\u00e9", "\\ud83d\\ude00"]'),
        Fn(clean_assembly="a\nc", constants='["é", "\U0001F600", "z"]'))
    Add("dict constants", Fn(clean_assembly="a\nb", constants='{"a": 1, "b": [1]}'),
        Fn(clean_assembly="a\nc", constants='["a", "c"]'))
    Add("str constants", Fn(clean_assembly="a\nb", constants='"abc"'), Fn(clean_assembly="a\nc", constants='["a", "z"]'))
    Add("float constants", Fn(clean_assembly="a\nb", constants="[1.0, 2.5, -0.0]"),
        Fn(clean_assembly="a\nc", constants="[1, 3, 0]"))
    Add("inf constants", Fn(clean_assembly="a\nb", constants="[Infinity, 18446744073709551616]"),
        Fn(clean_assembly="a\nc", constants="[1e400, 1.8446744073709552e19]"))
    Add("duplicate constants", Fn(clean_assembly="a\nb", constants='[4096, 4096, 1, 1.0, "1"]'),
        Fn(clean_assembly="a\nc", constants='[4096, 1, "1", "1"]'))
    Add("constants raise: invalid JSON", Fn(clean_assembly="a\nb", constants="[1,"), Fn(clean_assembly="a\nc", constants="[1]"))
    Add("constants raise: nested list", Fn(clean_assembly="a\nb", constants="[[1]]"), Fn(clean_assembly="a\nc", constants="[1]"))
    Add("constants raise: NULL main", Fn(clean_assembly="a\nb", constants=None), Fn(clean_assembly="a\nc", constants="[1]"))
    Add("constants raise: NULL diff", Fn(clean_assembly="a\nb", constants="[1]"), Fn(clean_assembly="a\nc", constants=None))
    Add("constants raise: not iterable", Fn(clean_assembly="a\nb", constants="[2]"), Fn(clean_assembly="a\nc", constants="5"))
    Add("constants not parsed", Fn(clean_assembly="a\nb", constants="[]"), Fn(clean_assembly="a\nc", constants="[1,"))
    # None == None earns the degree / switches / complexity bonuses (03a Hard parts 4)
    Add("NULL degrees and switches", Fn(clean_assembly="a\nb", indegree=None, outdegree=None, switches=None,
                                        cyclomatic_complexity=None),
        Fn(clean_assembly="a\nc", indegree=None, outdegree=None, switches=None, cyclomatic_complexity=None))
    Add("all deep features", Fn(clean_assembly=Lines(a=5, b=5), source_file="x.c", pseudocode_primes="210",
                                indegree=3, outdegree=2, switches='[[2, [0, 1]]]', cyclomatic_complexity=4,
                                constants='[4096, 5000, "s"]'),
        Fn(clean_assembly=Lines(a=5, c=5), source_file="x.c", pseudocode_primes="210", indegree=3, outdegree=2,
           switches='[[2, [0, 1]]]', cyclomatic_complexity=4, constants='[4096, 5000, "s", 7]'))
    # Python bytes (BLOB cells): == with str is False, bytes.split("\n") raises (D:163)
    Add("BLOB bytes_hash equal", Fn(bytes_hash=b"zz", clean_assembly="a"),
        Fn(bytes_hash=b"zz", clean_assembly="b"))
    Add("BLOB vs str bytes_hash", Fn(bytes_hash=b"yy", clean_assembly="a\nb"),
        Fn(bytes_hash="yy", clean_assembly="a\nc"))
    Add("BLOB clean_assembly raises", Fn(clean_assembly=b"a\nb"), Fn(clean_assembly="a\nb"))
    Add("BLOB switches and source", Fn(clean_assembly="a\nb", switches=b"[1]", source_file=b"s.c"),
        Fn(clean_assembly="a\nc", switches=b"[1]", source_file=b"s.c"))
    # deep_ratio re-reads rows by str(int(ea)) (D:2763-2778)
    Add("non-canonical address", Fn(address="004198400", clean_assembly=Lines(a=2, b=1), indegree=1),
        Fn(clean_assembly=Lines(a=2, c=1), indegree=5))
    Add("canonical twin", Fn(address="4198400", clean_assembly="z", indegree=5), Fn(clean_assembly="w", indegree=5))
    Add("address with spaces", Fn(address=" 777 ", clean_assembly=Lines(a=2, b=1)), Fn(clean_assembly=Lines(a=2, c=1)))
    Add("address not an int", Fn(address="0x10", clean_assembly=Lines(a=2, b=1)), Fn(clean_assembly=Lines(a=2, c=1)))
    Add("large texts", Fn(clean_assembly=Lines(**{f"l{I}": 3 + I % 4 for I in range(150)}), md_index="7.75"),
        Fn(clean_assembly=Lines(**{f"l{I}": 2 + I % 5 for I in range(20, 190)}), md_index="7.75"))
    return Main, Diff, Labels


def CmdSynthetic(Args):
    Diaphora, Schema, Heuristics, Env = LoadDiaphora(Args.diaphora_dir)
    Out = Args.out or (os.path.join(REPO, "tests", "diff", "vectors", "ratio") if Args.set == "committed" else None)
    if not Out:
        raise SystemExit("--out is required for --set 03a (it must not be the repository)")
    os.makedirs(Out, exist_ok=True)
    Work = tempfile.mkdtemp(prefix="dsig-ratio-")
    Written = []
    try:
        if Args.set == "committed":
            Configs = [("h03a-s3-n24-same-near", 3, 24, True, True), ("h03a-s9-n24-other-near", 9, 24, False, True),
                       ("h03a-s5-n24-other", 5, 24, False, False), ("h03a-s11-n24-same", 11, 24, True, False)]
        else:
            Configs = ([(f"h03a-s{S}-n80-same", S, 80, True, False) for S in (1, 2, 3, 11, 12)]
                       + [("h03a-s7-n60-same", 7, 60, True, False)]
                       + [(f"h03a-s{S}-n80-other", S, 80, False, False) for S in (5, 6, 21)]
                       + [(f"h03a-s{S}-n80-same-near", S, 80, True, True) for S in (3, 4, 8, 13)]
                       + [("h03a-s9-n80-other-near", 9, 80, False, True)])
        for Name, Seed, N, SameCpu, NearCopy in Configs:
            Main, Diff = HarnessRows(Seed, N, NearCopy)
            if Args.set == "committed":
                SortLines(Main)
                SortLines(Diff)
            Doc = EvaluatePair(Diaphora, Heuristics, Schema, Env, Name, Main, Diff, SameCpu, Work,
                               Rle=Args.set == "committed")
            Doc["harness"] = {"seed": Seed, "n": N, "near_copy": NearCopy, "sorted_lines": Args.set == "committed"}
            Written.append(WriteJson(os.path.join(Out, Name + ".json"), Doc))
        if Args.set == "committed":
            Main, Diff, Labels = TargetedRows()
            Doc = EvaluatePair(Diaphora, Heuristics, Schema, Env, "targeted", Main, Diff, True, Work, Rle=True,
                               Labels=Labels)
            Written.append(WriteJson(os.path.join(Out, "targeted.json"), Doc))
    finally:
        shutil.rmtree(Work, ignore_errors=True)
    for Path, Doc in Written:
        print(f"{os.path.basename(Path)}: {Doc['stats']}")


def WriteJson(Path, Doc):
    with open(Path, "w", encoding="utf-8", newline="\n") as Handle:
        json.dump(Doc, Handle, ensure_ascii=False, separators=(",", ":"))
        Handle.write("\n")
    return Path, Doc


# ------------------------------------------------------------------------------------------------
# Python value semantics

def F7(V):
    return float("{0:.7f}".format(V))  # D:1676 / D:1710


def TaggedPy(Value):
    """A JSON description of a Python value from json.loads (types kept apart)."""
    if Value is None:
        return None
    if isinstance(Value, bool):
        return {"bool": Value}
    if isinstance(Value, int):
        return {"int": str(Value)}
    if isinstance(Value, float):
        return {"float": "nan" if Value != Value else Hex(Value)}
    if isinstance(Value, str):
        return {"str": Value.encode("utf-8", "surrogatepass").hex()}
    if isinstance(Value, list):
        return {"list": [TaggedPy(V) for V in Value]}
    if isinstance(Value, dict):
        return {"dict": [[K.encode("utf-8", "surrogatepass").hex(), TaggedPy(V)] for K, V in Value.items()]}
    raise TypeError(type(Value))


def Depth(Value):
    """Container nesting depth (a top-level list is 1), the unit of the port's JSON depth limit."""
    if isinstance(Value, list):
        return 1 + max([Depth(V) for V in Value], default=0)
    if isinstance(Value, dict):
        return 1 + max([Depth(V) for V in Value.values()], default=0)
    return 0


def ElementText(Value):
    return type(Value).__name__ + ":" + str(Value).encode("utf-8", "surrogatepass").hex()


def FloatOutcome(Text):
    try:
        V = float(Text)
    except ValueError:
        return "ValueError"
    if V != V:
        return "-nan" if struct.pack(">d", V)[0] & 0x80 else "nan"
    return Hex(V)


def CmdValues(Args):
    Diaphora, Schema, Heuristics, Env = LoadDiaphora(Args.diaphora_dir)
    Big = Args.big
    Out = Args.out or (None if Big else os.path.join(REPO, "tests", "diff", "vectors", "ratio"))
    if not Out:
        raise SystemExit("--out is required with --big (it must not be the repository)")
    os.makedirs(Out, exist_ok=True)
    Rnd = random.Random(20260923)
    Doc = {"schema": SCHEMA_ID, "name": "values-big" if Big else "values",
           "generator": "tools/parity/gen_ratio_vectors.py values", "environment": Env}

    # "{0:.7f}" rounding (03a §5): every exact tie 2m/L at the 8th decimal for L <= 4096, the spec's
    # examples, boundaries and random doubles.
    from fractions import Fraction
    Round = []
    Seen = set()

    def AddRound(V):
        if V in Seen and V == V:
            return
        Seen.add(V)
        Round.append([Hex(V), Hex(F7(V))])

    MaxL = 20000 if Big else 4096
    for L in range(2, MaxL + 1):
        for M in range(0, L + 1):
            V = 2.0 * M / L
            Scaled = Fraction(V) * 10 ** 7
            if Scaled.denominator == 2:
                AddRound(V)
    for V in [0.00390625, 0.98828125, 0.99609375, 0.01953125, 0.01171875, 0.005859375, 0.0048828125, 2.0 / 3.0,
              0.0, 1.0, 0.99999995, 0.9999999500000001, 0.12345675, 5e-08, 4.9999999999999996e-08, 1.5e-08,
              1e-300, 5e-324, 2.2250738585072014e-308, 0.5, 0.25, 0.1, 0.3, 0.7, 123.456789012345, 4503599627370495.5,
              4503599627370496.0, 9007199254740993.0, 1e22, 1e300, -0.0, -0.00000005, -0.12345675, -2.0 / 3.0,
              0.99609375 + 2 ** -53, 0.6012, 0.8, 0.9999999, 0.99999994, 0.99999996]:
        AddRound(V)
    for _ in range(200000 if Big else 400):
        AddRound(Rnd.random())
    for _ in range(50000 if Big else 150):
        AddRound(Rnd.random() * 10 ** Rnd.randint(-12, 18))
    for _ in range(50000 if Big else 150):
        AddRound(struct.unpack(">d", Rnd.getrandbits(64).to_bytes(8, "big"))[0])
    Doc["round7"] = [R for R in Round if not R[0].startswith("7ff") and not R[0].startswith("fff")]

    # float(str) (03a §6.4): md strings like the exporter's str(Decimal), the SQLite-divergent ones,
    # Python syntax edges.
    Con = sqlite3.connect(":memory:")
    Texts = []
    for _ in range(200000 if Big else 400):
        Digits = "".join(Rnd.choice("0123456789") for _ in range(28))
        Point = Rnd.randint(1, 3)
        Text = (Digits[:Point].lstrip("0") or "0") + "." + Digits[Point:]
        if Rnd.random() < 0.3:
            Text = Text.rstrip("0").rstrip(".")
        Texts.append(Text)
    Divergent = []
    for Text, SqlPartner, PyPartner in FindMdDivergence(2000 if Big else 60, 7):
        Divergent += [Text, SqlPartner, PyPartner]
    Texts += Divergent
    Texts += ["0", "1", "-0", "+3", " 2.5 ", "\t2.5\n", "\x0b\x0c2.5\r", "\x1c1.5", "1.5\x00", "1\x005", "",
              " ", "abc", "1.5abc", "0x10", "nan", "NaN", "-nan", "+nan", "inf", "-inf", "Infinity", "-InFiNiTy",
              "infin", "infinityx", "1e5", "1E+5", "1e-5", "1e", "1e+", "e5", ".5", "5.", ".", "+.5", "-.5e1", "1_0",
              "1__0", "_1", "1_", "1_.5", "1._5", "1e1_0", "1_0e5", "1e_5", "1.5e+", "1e400", "-1e400", "1e-400",
              "1e99999999999999999999", "1e-99999999999999999999", "0e99999999999999", "1" * 400,
              "0." + "0" * 400 + "1", "0." + "0" * 300 + "1", "1" + "0" * 308, "1" + "0" * 309,
              "1.7976931348623157e308", "1.7976931348623158e308", "1.7976931348623159e308",
              "2.4703282292062327e-324", "2.4703282292062328e-324", "4.9406564584124654e-324",
              "2.2250738585072011e-308", "2.2250738585072014e-308", "9007199254740993", "9007199254740992.5",
              "0.1", "0.30000000000000004", "123456789012345678901234567890",
              "0.4008152925841381442166209413", "2.015185537900030743935567273", "12.5", "3.162277660168379332",
              "1.414213562373095048801688724", "0.70710678118654752440084436210",
              "8.98846567431158e307", "4.4501477170144023e-308", "4.4501477170144022e-308",
              "7.2057594037927933e16", "0.000000000000000000000000000000000000000000001",
              "123456789" * 40 + "e-300", "1." + "9" * 800, "0." + "4" * 20 + "5" * 800 + "1"]
    Doc["pyfloat"] = []
    for Text in Texts:
        Sql = Con.execute("select cast(? as real)", (Text,)).fetchone()[0] if "\x00" not in Text else None
        Doc["pyfloat"].append([Text, FloatOutcome(Text), None if Sql is None else Hex(Sql)])
    Con.close()

    # repr(float): shortest round trip, 'r' formatting (exponent when decpt <= -4 or > 16)
    Reprs = [0.0, -0.0, 1.0, 0.1, 1e16, 1e15, 0.0001, 0.00001, 1.5e300, 123456789012345678.0, 5e-324,
             2.2250738585072014e-308, 1.7976931348623157e308, 9007199254740993.0, 2.0 / 3.0, 1e22, 1e23, 1e-7,
             0.99, 0.01, 1234567890123456.0, 12345678901234567.0, 100.0, 1e100, 2.0 ** 63, 2.0 ** -1022, 2.0 ** 1023]
    for _ in range(100000 if Big else 300):
        Reprs.append(struct.unpack(">d", Rnd.getrandbits(64).to_bytes(8, "big"))[0])
    for _ in range(20000 if Big else 150):
        Reprs.append(Rnd.random())
    for _ in range(20000 if Big else 100):
        Reprs.append(float(Rnd.randint(1, 10 ** Rnd.randint(1, 25))))
    Doc["repr"] = [[Hex(V), repr(V)] for V in Reprs if V == V and abs(V) != float("inf")]

    # json.loads and set semantics (03a §7.1, H-8)
    JsonTexts = ['[1, 1.0, "1"]', "[true, false, null]", "[NaN, Infinity, -Infinity]", '["\\u00e9", "é"]',
                 '"\\ud83d\\ude00"', '"\\ud83d x"', '"\\ud83d\\ud83d"', '"\\udc00"', '{"a": 1, "b": 2, "a": 3}',
                 "[18446744073709551615, 18446744073709551616, -0, 0, 1e400, -0.0]", '"abc"', "5", "null", "true",
                 "[[1]]", '[{"a":1}]', '{"a": [[1]]}', "[1,]", "[1", "01", "1.", ".5", "-", "[1e]", "[1E5, 1e-5]",
                 '"\\/"', '"\\x"', "{1:2}", ' [1] \n', "\x0b[1]", '"a\x7fb"', '"a\x1fb"', '"\\u0000"', "[-NaN]",
                 "[" + "9" * 400 + "]", "[1" + "0" * 30 + "e-30]", '"\\u00"', '["a" "b"]', "{}", "[]", '""',
                 '{"k": {"x": [1, {"y": null}]}}', "[0.1, 0.2, 0.30000000000000004]", "[2.5e-324, 5e-324]",
                 '"\\"\\\\\\/\\b\\f\\n\\r\\t"', '[4096, "4096", 4096.0, 4096.5]', '"' + "中é\U0001F600" + '"',
                 "[1, 2, 3", "﻿[1]", "[" * 600 + "]" * 600, '{"a":' + "[" * 600 + "]" * 600 + "}",
                 "[" + "[" * 100 + "]" * 100 + "]"]
    Doc["json_loads"] = []
    for Text in JsonTexts:
        try:
            Value = json.loads(Text)
            Nesting = Depth(Value)
            Doc["json_loads"].append([Text, TaggedPy(Value) if Nesting <= 200 else "deep", Nesting])
        except RecursionError:
            Doc["json_loads"].append([Text, "RecursionError"])
        except ValueError:
            Doc["json_loads"].append([Text, "raise"])
    SetPairs = [('[1, 1.0, "1"]', "[1]"), ("[1]", "[1.0]"), ("[1, 2]", "[1.0]"), ("[1]", "[1.0, 5]"),
                ("[1.0]", "[1, 5]"), ("[true]", "[1]"), ("[false]", "[0, 5]"), ("[true]", "[1.0]"),
                ('["1"]', "[1]"), ("[NaN]", "[NaN]"), ("[NaN, NaN]", "[1]"), ("[Infinity]", "[1e400]"),
                ("[18446744073709551616]", "[1.8446744073709552e19]"),
                ("[18446744073709551615]", "[1.8446744073709552e19]"), ("[-0.0]", "[0]"),
                ('["\\u00e9"]', '["é"]'), ('"abc"', '["a", "b", "x"]'), ('{"a": 1, "b": [1]}', '["a"]'),
                ("5", "[5]"), ("[1]", "5"), ("null", "[1]"), ("[[1]]", "[1]"), ("[1]", "[[1]]"), ('[{"a":1}]', "[1]"),
                ("[1,", "[1]"), ("[1]", "[1,"), ("[]", "[]"), ("[4096, 5000, 70000]", "[70000, 4096, 1]"),
                ('[4096, "hello world", "café string", "\\\\u0041BCDE"]', '["\\\\u0041BCDE", 4096, "café string"]'),
                ("[4294967296, 18446744073709551615, 18446744073709551614]", "[18446744073709551614, 4294967296.0]"),
                ('[null, "None"]', "[null]"), ("[1.5, 2.5]", "[1.5]"), ('"\\ud83d\\ude00x"', '["\\ud83d", "x"]'),
                ('"\U0001F600"', '["\\ud83d\\ude00"]'), ("[" + "[" * 700 + "]" * 700 + "]", "[1]")]
    Doc["json_sets"] = []
    for T1, T2 in SetPairs:
        Row = {"a": T1, "b": T2}
        try:
            S1 = set(json.loads(T1))
        except (ValueError, TypeError, RecursionError) as Error:
            Row["raise"] = "a:" + type(Error).__name__
            Doc["json_sets"].append(Row)
            continue
        try:
            S2 = set(json.loads(T2))
        except (ValueError, TypeError, RecursionError) as Error:
            Row["raise"] = "b:" + type(Error).__name__
            Doc["json_sets"].append(Row)
            continue
        Inter = S1.intersection(S2)
        Row.update({"len_a": len(S1), "len_b": len(S2), "common": len(Inter),
                    "elements": sorted(ElementText(V) for V in Inter)})
        Doc["json_sets"].append(Row)

    # quick_ratio (D:158-165) on raw texts
    QuickPairs = [("a\nb\n", "a\nb"), ("\n", "\n\n"), (None, "a"), ("", "a"), ("a", ""), ("a", "a"), ("a\rb", "a\nb"),
                  ("a\r\nb", "a\nb"), ("x\ny\nx", "x\nx\nz"), ("é\na", "é\nb"), ("a\x00b", "a\x00b\nc"),
                  ("a\n" * 255 + "b", "a\n" * 255 + "c"), ("\n\n\n", "\n"), ("a b\nc", "a  b\nc")]
    for _ in range(20 if not Big else 4000):
        Vocab = ["", "a", "b", "c", "mov eax, 1", "\r", " ", "é"]
        A = "\n".join(Rnd.choice(Vocab) for _ in range(Rnd.randint(1, 30)))
        B = "\n".join(Rnd.choice(Vocab) for _ in range(Rnd.randint(1, 30)))
        QuickPairs.append((A, B))
    Doc["quick_ratio"] = [[A, B, Hex(Diaphora.quick_ratio(A, B))] for A, B in QuickPairs]

    Path, _ = WriteJson(os.path.join(Out, Doc["name"] + ".json"), Doc)
    print(f"{Path}: round7 {len(Doc['round7'])}, pyfloat {len(Doc['pyfloat'])}, repr {len(Doc['repr'])}, "
          f"json_loads {len(Doc['json_loads'])}, json_sets {len(Doc['json_sets'])}, quick {len(Doc['quick_ratio'])}")


# ------------------------------------------------------------------------------------------------
# Corpus vectors

def Sha256(Path):
    H = hashlib.sha256()
    with open(Path, "rb") as Handle:
        for Block in iter(lambda: Handle.read(1 << 20), b""):
            H.update(Block)
    return H.hexdigest()


def ReadTraceEvents(Path, WithRows):
    """(ea1, ea2) of every add_match event, and of every row event when WithRows, in first-appearance
    order, with the in-situ check_match ratio of row events (ratios_cache made them per pair)."""
    Pairs = {}
    InSitu = {}
    Conflicts = 0
    with open(Path, "r", encoding="utf-8") as Handle:
        for Line in Handle:
            try:
                Event = json.loads(Line)
            except ValueError:
                continue  # a line still being written by a running capture
            Kind = Event.get("ev")
            if Kind == "add_match":
                Pairs.setdefault((Event["ea1"], Event["ea2"]), set()).add("add_match")
            elif Kind == "row" and WithRows:
                Key = (Event["ea1"], Event["ea2"])
                Pairs.setdefault(Key, set()).add("row")
                if Event.get("ratio_bits") is not None:
                    if Key in InSitu and InSitu[Key] != Event["ratio_bits"]:
                        Conflicts += 1
                    InSitu.setdefault(Key, Event["ratio_bits"])
    return Pairs, InSitu, Conflicts


def LastCacheSnapshot(TraceDir):
    """The last snapshot of a capture that carries ratios_cache: the real run's cache, which only grows
    (first writer wins, D:1653-1655 / D:1774)."""
    IndexPath = os.path.join(TraceDir, "index.json")
    if not os.path.exists(IndexPath):
        return None
    Best = None
    for _, Point, File in json.load(open(IndexPath, encoding="utf-8")):
        if File and Point.startswith("before:find_"):
            Best = File
    if Best is None:
        return None
    Snap = json.load(open(os.path.join(TraceDir, Best), encoding="utf-8"))
    return Snap if Snap.get("ratios_cache") is not None else None


def CmdCorpus(Args):
    Diaphora, Schema, Heuristics, Env = LoadDiaphora(Args.diaphora_dir)
    if not Args.corpus:
        raise SystemExit("--corpus (or DSIG_CORPUS_ROOT) is required")
    Oracle = os.path.join(Args.corpus, "oracle")
    Manifest = json.load(open(os.path.join(Oracle, "manifest.json"), encoding="utf-8"))
    OutDir = os.path.join(Oracle, "vectors", "ratio", "corpus")
    Work = os.path.join(Oracle, "vectors", "ratio", "work")
    os.makedirs(OutDir, exist_ok=True)
    os.makedirs(Work, exist_ok=True)
    Pairs = Args.pairs or sorted(Manifest["diffs"])
    Summary = {"environment": Env, "sample": Args.sample, "pairs": {}, "exports": {}}
    SummaryPath = os.path.join(OutDir, "summary.json")
    if os.path.exists(SummaryPath):
        Old = json.load(open(SummaryPath, encoding="utf-8"))
        Summary["pairs"].update(Old.get("pairs", {}))
        Summary["exports"].update(Old.get("exports", {}))
    try:
        for Pair in Pairs:
            Started = time.time()
            Info = Manifest["diffs"][Pair]
            Ref, Target = Info["ref"], Info["target"]
            Copies = []
            for Id in (Ref, Target):
                Source = os.path.join(Oracle, "exports", Id, Id + ".sqlite")
                Expected = Manifest["exports"][Id]["sqlite_sha256"]
                if Sha256(Source) != Expected:
                    raise SystemExit(f"{Id}: export sha256 differs from the manifest")
                Copy = os.path.join(Work, f"{Pair}.{'1' if Id == Ref else '2'}.sqlite")
                shutil.copyfile(Source, Copy)
                Copies.append(Copy)
            Or = RatioOracle(Diaphora, Heuristics, Copies[0], Copies[1])
            Cur = Or.Cursor()
            Main = [R[0] for R in Cur.execute("select address from main.functions order by id")]
            Diff = [R[0] for R in Cur.execute("select address from diff.functions order by id")]
            Cur.close()
            # md files per export (every function): SQLite cast and Python float() of md_index
            for Id, Db in ((Ref, "main"), (Target, "diff")):
                Cur = Or.Cursor()
                Rows = Cur.execute(f"select address, cast(md_index as real), md_index from {Db}.functions order by id").fetchall()
                Cur.close()
                with open(os.path.join(OutDir, f"md-{Id}.tsv"), "w", encoding="utf-8", newline="\n") as Handle:
                    Handle.write("address\tmd_sql\tmd_py\n")
                    for Address, Cast, Text in Rows:
                        Py = "raise:TypeError" if Text is None else FloatOutcome(Text)
                        Handle.write(f"{Address}\t{'null' if Cast is None else Hex(Cast)}\t{Py}\n")
                Summary["exports"][Id] = {"functions": len(Rows), "sha256": Manifest["exports"][Id]["sqlite_sha256"]}
            # candidate pairs
            TracePath = os.path.join(Oracle, "traces", Pair, "trace.jsonl")
            Finished = len(Info.get("runs", [])) >= 2 and all(R.get("exit_code", 1) == 0 and R.get("final_results")
                                                              for R in Info.get("runs", []))
            Candidates = {}
            InSitu = {}
            Conflicts = 0
            if os.path.exists(TracePath):
                Candidates, InSitu, Conflicts = ReadTraceEvents(TracePath, WithRows=Finished or Args.long_rows)
            CacheSnapshot = LastCacheSnapshot(os.path.join(Oracle, "traces", Pair))
            CacheCount = 0
            if CacheSnapshot:
                for Key, Bits in CacheSnapshot["ratios_cache"]:
                    Ea1, Ea2 = Key.split("-")
                    Candidates.setdefault((Ea1, Ea2), set()).add("cache")
                    InSitu.setdefault((Ea1, Ea2), Bits)
                    CacheCount += 1
            Rnd = random.Random(f"{Pair}:{Args.sample}")
            Total = len(Main) * len(Diff)
            for Index in Rnd.sample(range(Total), min(Args.sample, Total)):
                Candidates.setdefault((Main[Index // len(Diff)], Diff[Index % len(Diff)]), set()).add("sample")
            Counts = {"vectors": 0, "sql_raise": 0, "py_raise": 0, "sql_py_differ": 0, "insitu": 0,
                      "insitu_equals_sql": 0, "insitu_equals_py_only": 0, "insitu_mismatch": 0,
                      "insitu_conflicts": Conflicts, "cache_entries": CacheCount,
                      "cache_point": CacheSnapshot["point"] if CacheSnapshot else None}
            Path = os.path.join(OutDir, Pair + ".tsv")
            with open(Path, "w", encoding="utf-8", newline="\n") as Handle:
                Handle.write(f"# pair\t{Pair}\n# ref\t{Ref}\n# target\t{Target}\n"
                             f"# same_processor\t{int(Or.Bd.is_same_processor)}\n"
                             f"# environment\t{json.dumps(Env, sort_keys=True)}\n")
                Handle.write("ea1\tea2\tsql\tpy\tsources\tinsitu\n")
                for (Ea1, Ea2), Sources in Candidates.items():
                    Row = Or.SelectFieldsRow(Ea1, Ea2)
                    Sql = Or.SqlRatio(Row)
                    Py = Or.RowRatio(Or.FullRow("main", Ea1), Or.FullRow("diff", Ea2))
                    Seen = InSitu.get((Ea1, Ea2), "-")
                    Counts["vectors"] += 1
                    Counts["sql_raise"] += Sql.startswith("raise")
                    Counts["py_raise"] += Py.startswith("raise")
                    Counts["sql_py_differ"] += Sql != Py
                    if Seen != "-":
                        Counts["insitu"] += 1
                        Counts["insitu_equals_sql"] += Seen == Sql
                        Counts["insitu_equals_py_only"] += Seen != Sql and Seen == Py
                        Counts["insitu_mismatch"] += Seen != Sql and Seen != Py
                    Handle.write(f"{Ea1}\t{Ea2}\t{Sql}\t{Py}\t{','.join(sorted(Sources))}\t{Seen}\n")
            Or.Close()
            for Copy in Copies:
                for Suffix in ("", "-wal", "-shm", "-journal"):
                    try:
                        os.remove(Copy + Suffix)
                    except OSError:
                        pass
            Counts["seconds"] = round(time.time() - Started, 1)
            Counts["trace"] = os.path.exists(TracePath)
            Counts["trace_rows_used"] = bool(Finished or Args.long_rows)
            Summary["pairs"][Pair] = Counts
            print(f"{Pair}: {Counts}", flush=True)
            WriteJson(SummaryPath, Summary)
    finally:
        for Name in os.listdir(Work):
            try:
                os.remove(os.path.join(Work, Name))
            except OSError:
                pass


def Main():
    Parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    Sub = Parser.add_subparsers(dest="cmd", required=True)
    for Name in ("synthetic", "values", "corpus"):
        P = Sub.add_parser(Name)
        P.add_argument("--diaphora-dir", default=os.environ.get("DSIG_DIAPHORA_DIR"),
                       help="unmodified Diaphora checkout (default: env DSIG_DIAPHORA_DIR)")
        P.add_argument("--out", help="output directory")
        if Name == "synthetic":
            P.add_argument("--set", choices=("committed", "03a"), default="committed")
        if Name == "values":
            P.add_argument("--big", action="store_true", help="the large variant (outside the repository)")
        if Name == "corpus":
            P.add_argument("--corpus", default=os.environ.get("DSIG_CORPUS_ROOT"),
                           help="corpus root (default: env DSIG_CORPUS_ROOT)")
            P.add_argument("--pairs", nargs="*", help="oracle pairs (default: every pair in manifest.json)")
            P.add_argument("--sample", type=int, default=20000, help="random pairs per oracle pair")
            P.add_argument("--long-rows", action="store_true",
                           help="also use the row events of traces whose oracle pair has not finished")
    Args = Parser.parse_args()
    if not Args.diaphora_dir:
        Parser.error("--diaphora-dir (or DSIG_DIAPHORA_DIR) is required")
    {"synthetic": CmdSynthetic, "values": CmdValues, "corpus": CmdCorpus}[Args.cmd](Args)


if __name__ == "__main__":
    Main()
