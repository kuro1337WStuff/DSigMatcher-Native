#!/usr/bin/env python3
"""Build a Diaphora-schema fixture pair from a scenario and record what real Diaphora makes of it.

    python -B make_fixture.py <scenario.py> <outdir> [--diaphora-dir <dir>] [--python <exe>]
                              [--hash-seed 0] [--keep-work <dir>]

Fixtures are built exactly like real exports (07 §12).

1. The scenario file is executed with `Function`, `COLUMNS` and `SCHEMA_VERSION` predefined. It must
   define `MAIN` and `DIFF`, one dict per database:

       MAIN = {"functions": [Function(1, "name", 4096, ...), ...],   # functions rows (dicts)
               "program": {...},       # optional overrides of the single program row
               "tables": {"constants": [{"func_id": 1, "constant": "x"}], ...}}   # optional

   Only synthetic data belongs in a scenario: never names or bytes taken from a real binary.
2. Each database is built like a real export: every `db_support/schema.py` TABLES statement, the
   version row, the rows, then every INDICES entry and `analyze` (create_indices, D:634-649). Python's
   `iterdump()` of it (which includes the sqlite_stat1 rows) becomes `main.sql` / `diff.sql`.
3. Those dumps are rebuilt exactly as tests/diff/FixtureDb.h rebuilds them (executescript, then
   `PRAGMA journal_mode=WAL`, diaphora_ida.py:1187-1188) and **copies** are diffed twice by the
   unmodified Diaphora checkout, with no DIAPHORA_* variable, PYTHONDONTWRITEBYTECODE=1 and a fixed
   PYTHONHASHSEED:
     a. `python -B diaphora.py main.sqlite diff.sqlite -o out.diaphora`, the oracle command line;
     b. an in-process replay of diaphora.py's __main__ (D:3757-3773) with CChooser.add_item recording
        the raw chooser items in memory (as tools/parity/oracle_trace.py does).
   Both outputs must be identical in stored order, and the rows rebuilt from the chooser dumps
   (snapshot.RowsFromDumps) must equal them, or nothing is written.
4. Text artefacts for the repository, in <outdir>:
     main.sql, diff.sql              the fixture databases (dumps, sqlite_stat1 included)
     expected_results.tsv            `results` in rowid order (all ten columns, `line` included)
     expected_unmatched.tsv          `unmatched` in rowid order
     after_final_pass.json           snapshot (tools/parity/README.md) with the raw `choosers` dump
     after_find_unmatched.json       snapshot with the raw `unmatched` dump
     oracle.json                     mode, Final results counts, SQLite / Python / Diaphora versions,
                                     hash seed, the self-checks; no paths
   TSV: a header line, then one line per row; NULL is `\\N`, and `\\`, TAB, LF and CR inside a value are
   written as `\\\\`, `\\t`, `\\n`, `\\r`. (The repository's .gitignore ignores *.tsv: add the fixture
   files with `git add -f`.)

The Diaphora checkout is imported read-only (sys.dont_write_bytecode, -B) and its `git describe` and
`git status` are checked unchanged afterwards. Nothing is written outside <outdir> and a temporary
work directory (removed unless --keep-work names one).

Paths come from flags or the environment only:
  --diaphora-dir  (env DSIG_DIAPHORA_DIR)   the unmodified Diaphora checkout
  --python        (env DSIG_PYTHON)         the Python that runs Diaphora (default: this one)
"""

import sys

sys.dont_write_bytecode = True

import argparse  # noqa: E402
import importlib  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import re  # noqa: E402
import shutil  # noqa: E402
import sqlite3  # noqa: E402
import subprocess  # noqa: E402
import tempfile  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import snapshot as Snap  # noqa: E402

SCHEMA_VERSION = "3.4"  # VERSION_VALUE, D:100

# functions columns in db_support/schema.py order (08 §5.1).
COLUMNS = ["id", "name", "address", "nodes", "edges", "indegree", "outdegree", "size", "instructions", "mnemonics",
           "names", "prototype", "cyclomatic_complexity", "primes_value", "comment", "mangled_function",
           "bytes_hash", "pseudocode", "pseudocode_lines", "pseudocode_hash1", "pseudocode_primes",
           "function_flags", "assembly", "prototype2", "pseudocode_hash2", "pseudocode_hash3",
           "strongly_connected", "loops", "rva", "tarjan_topological_sort", "strongly_connected_spp",
           "clean_assembly", "clean_pseudo", "mnemonics_spp", "switches", "function_hash", "bytes_sum",
           "md_index", "constants", "constants_count", "segment_rva", "assembly_addrs", "kgh_hash",
           "source_file", "userdata", "microcode", "clean_microcode", "microcode_spp", "export_time"]

RESULTS_COLUMNS = ["type", "line", "address", "name", "address2", "name2", "ratio", "nodes1", "nodes2",
                   "description"]
UNMATCHED_COLUMNS = ["type", "line", "address", "name"]


def Function(Id, Name, Address, Nodes=4, Assembly=None, Pseudocode=None, **Overrides):
    """One synthetic functions row with plausible values for every column. Keyword arguments
    override any column by name (use mangled_function=... for a C++ name)."""
    if Assembly is None:
        Assembly = "\n".join(["push rbp", "mov rbp, rsp"] + ["add eax, %d" % (Id * 7 + I) for I in range(Nodes)] +
                             ["pop rbp", "ret"])
    Lines = Assembly.split("\n")
    Mnemonics = [Line.split(" ", 1)[0] for Line in Lines]
    Row = {Column: None for Column in COLUMNS}
    Row.update({
        "id": Id, "name": Name, "address": str(Address), "nodes": Nodes, "edges": max(Nodes - 1, 0),
        "indegree": 1, "outdegree": 1, "size": 4 * len(Lines), "instructions": len(Lines),
        "mnemonics": json.dumps(Mnemonics), "names": "[]", "prototype": None, "cyclomatic_complexity": 1,
        "primes_value": str(2 * Nodes + 1), "comment": None, "mangled_function": Name,
        "bytes_hash": _Hash(Assembly),
        "pseudocode": Pseudocode,
        "pseudocode_lines": 0 if Pseudocode is None else Pseudocode.count("\n") + 1,
        "pseudocode_hash1": None if Pseudocode is None else _Hash(Pseudocode)[:16],
        "pseudocode_primes": None, "function_flags": 0, "assembly": Assembly, "prototype2": None,
        "pseudocode_hash2": None, "pseudocode_hash3": None, "strongly_connected": 1, "loops": 0,
        "rva": str(Address & 0xFFFFFFF), "tarjan_topological_sort": "[[0]]", "strongly_connected_spp": "2",
        "clean_assembly": Assembly, "clean_pseudo": Pseudocode, "mnemonics_spp": str(30 + Nodes),
        "switches": "[]", "function_hash": _Hash("fh" + Assembly), "bytes_sum": Address % 1000,
        "md_index": "0", "constants": "[]", "constants_count": 0, "segment_rva": str(Address & 0xFFFFFFF),
        "assembly_addrs": "[]", "kgh_hash": "0", "source_file": None, "userdata": None, "microcode": None,
        "clean_microcode": None, "microcode_spp": "1", "export_time": 0.001 * Id,
    })
    for Key, Value in Overrides.items():
        if Key not in Row:
            raise SystemExit("Function(): unknown column %r" % Key)
        Row[Key] = Value
    return Row


def _Hash(Text):
    import hashlib
    return hashlib.md5(Text.encode("utf-8")).hexdigest()


# ----------------------------------------------------------------------------- building

def LoadSchema(DiaphoraDir):
    sys.path.insert(0, os.path.join(DiaphoraDir, "db_support"))
    try:
        return importlib.import_module("schema")
    finally:
        sys.path.pop(0)


def LoadScenario(Path):
    Namespace = {"Function": Function, "COLUMNS": COLUMNS, "SCHEMA_VERSION": SCHEMA_VERSION,
                 "__file__": os.path.abspath(Path), "__name__": "scenario"}
    with open(Path, "r", encoding="utf-8") as Handle:
        Code = compile(Handle.read(), os.path.abspath(Path), "exec")
    exec(Code, Namespace)  # noqa: S102 - a local scenario file the caller names
    for Key in ("MAIN", "DIFF"):
        if not isinstance(Namespace.get(Key), dict) or not Namespace[Key].get("functions"):
            raise SystemExit("%s must define %s = {'functions': [...], ...}" % (Path, Key))
    return Namespace


def BuildDump(Schema, Side, Seed):
    """The iterdump() text of one fixture database built like a real export."""
    Work = tempfile.mkdtemp(prefix="dsig-fixture-")
    Path = os.path.join(Work, "x.sqlite")
    try:
        Con = sqlite3.connect(Path)
        for Sql in Schema.TABLES:  # create_schema
            Con.execute(Sql)
        Con.execute("insert into version values (?)", (SCHEMA_VERSION,))
        Program = {"id": 1, "callgraph_primes": str(Seed), "callgraph_all_primes": json.dumps({str(Seed): 1}),
                   "processor": "metapc", "md5sum": "%032x" % Seed}
        Program.update(Side.get("program", {}))
        Con.execute("insert into program (%s) values (%s)" % (", ".join(Program), ", ".join("?" * len(Program))),
                    list(Program.values()))
        for Row in Side["functions"]:
            Con.execute("insert into functions (%s) values (%s)" % (", ".join(COLUMNS), ", ".join("?" * len(COLUMNS))),
                        [Row[C] for C in COLUMNS])
        for Table, Rows in Side.get("tables", {}).items():
            for Row in Rows:
                Con.execute("insert into %s (%s) values (%s)" % (Table, ", ".join(Row), ", ".join("?" * len(Row))),
                            list(Row.values()))
        Con.commit()
        # create_indices (D:634-649): every INDICES entry, then analyze.
        for Index, (Table, Fields) in enumerate(Schema.INDICES):
            Con.execute("create index if not exists idx_%d on %s(%s)" % (Index, Table, Fields))
        Con.execute("analyze")
        Con.commit()
        Text = "\n".join(Con.iterdump()) + "\n"
        Con.close()
        return Text
    finally:
        shutil.rmtree(Work, ignore_errors=True)


def RebuildLikeFixtureDb(Text, Path):
    """tests/diff/FixtureDb.h BuildFixtureDbFromText: exec the dump, then WAL mode."""
    for Suffix in ("", "-wal", "-shm", "-journal"):
        if os.path.exists(Path + Suffix):
            os.remove(Path + Suffix)
    Con = sqlite3.connect(Path, isolation_level=None)
    Con.executescript(Text)
    Con.execute("PRAGMA journal_mode=WAL")
    Con.close()


# ----------------------------------------------------------------------------- running Diaphora

def CleanEnv(Seed):
    """build_oracle.CleanEnv() semantics plus a fixed hash seed."""
    Env = {Key: Value for Key, Value in os.environ.items() if not Key.upper().startswith("DIAPHORA_")}
    Env["PYTHONDONTWRITEBYTECODE"] = "1"
    Env["PYTHONHASHSEED"] = str(Seed)
    return Env


def Git(Directory, *Arguments):
    try:
        return subprocess.run(["git", "--no-optional-locks", "-C", Directory] + list(Arguments),
                              capture_output=True, text=True, timeout=120).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None


def RunCli(Python, DiaphoraDir, Db1, Db2, Out, Log, Seed):
    """The oracle command line: python -B diaphora.py db1 db2 -o out (09 "How a reference diff is made")."""
    with open(Log, "w", encoding="utf-8", errors="replace") as Handle:
        Code = subprocess.call([Python, "-B", os.path.join(DiaphoraDir, "diaphora.py"), Db1, Db2, "-o", Out],
                               cwd=DiaphoraDir, env=CleanEnv(Seed), stdout=Handle, stderr=subprocess.STDOUT)
    return Code


def RunInstrumented(Python, DiaphoraDir, Db1, Db2, Out, Dump, Log, Seed):
    with open(Log, "w", encoding="utf-8", errors="replace") as Handle:
        Code = subprocess.call([Python, "-B", os.path.abspath(__file__), "--_capture", DiaphoraDir, Db1, Db2, Out, Dump],
                               cwd=DiaphoraDir, env=CleanEnv(Seed), stdout=Handle, stderr=subprocess.STDOUT)
    return Code


def CaptureMain(DiaphoraDir, Db1, Db2, Out, Dump):
    """Child process: diaphora.py __main__ (D:3757-3773) with CChooser.add_item recording raw items."""
    sys.path.insert(0, DiaphoraDir)
    import diaphora as D  # the unmodified checkout, read-only

    Raw = {}
    Cls = D.CChooser
    Original = Cls.__dict__["add_item"]

    def add_item(ChooserSelf, Item):
        Result = Original(ChooserSelf, Item)
        if ChooserSelf.title.startswith("Unmatched in"):
            Entry = [Item.ea, Item.vfname]
        else:
            Entry = [Item.ea, Item.vfname, Item.ea2, Item.vfname2, Item.description, Snap.RatioBits(Item.ratio),
                     Item.nodes1, Item.nodes2]
        Raw.setdefault(id(ChooserSelf), (ChooserSelf, []))[1].append(Entry)
        return Result

    Cls.add_item = add_item

    def Dumped(Chooser):
        if Chooser is None:
            return None
        Entry = Raw.get(id(Chooser))
        Items = Entry[1] if Entry is not None and Entry[0] is Chooser else []
        if len(Items) != len(Chooser.items):
            raise RuntimeError("chooser %r: %d raw items, %d formatted" % (Chooser.title, len(Items), len(Chooser.items)))
        return list(Items)

    Bd = D.CBinDiff(Db1)
    if not D.IS_IDA:
        Bd.ignore_all_names = False
    Bd.db = D.sqlite3_connect(Db1)
    Bd.diff(Db2)

    def Snapshot(Point, Seq):
        Obj = {"schema": Snap.SCHEMA, "producer": "diaphora-" + (Git(DiaphoraDir, "describe", "--tags") or "?"),
               "pair": "fixture", "seq": Seq, "point": Point, "iteration": None,
               "flags": {"is_same_processor": Bd.is_same_processor, "is_patch_diff": Bd.is_patch_diff,
                         "is_symbols_stripped": Bd.is_symbols_stripped, "hooks_loaded": Bd.hooks is not None,
                         "total_functions1": Bd.total_functions1, "total_functions2": Bd.total_functions2},
               "all_matches": {Key: [[X[0], X[1], X[2], X[3], X[4], Snap.RatioBits(X[5]), X[6], X[7]]
                                     for X in Bd.all_matches.get(Key, [])] for Key in Snap.LISTS},
               "matched_primary": [[K, V["name"], Snap.RatioBits(V["ratio"])] for K, V in Bd.matched_primary.items()],
               "matched_secondary": [[K, V["name"], Snap.RatioBits(V["ratio"])]
                                     for K, V in Bd.matched_secondary.items()]}
        return Obj

    # final_pass and find_unmatched are the last two stages of diff() (D:3677-3681); neither changes
    # all_matches or matched_*, so the end state is the state of both points.
    Final = Snapshot("after:final_pass", 0)
    Final["choosers"] = {"best": Dumped(Bd.best_chooser), "partial": Dumped(Bd.partial_chooser),
                         "unreliable": Dumped(Bd.unreliable_chooser), "multimatch": Dumped(Bd.multimatch_chooser)}
    Unm = Snapshot("after:find_unmatched", 1)
    # save_results labels (D:2414-2415): primary = unmatched_primary (diff DB), secondary = unmatched_second.
    Unm["unmatched"] = {"primary": Dumped(Bd.unmatched_primary), "secondary": Dumped(Bd.unmatched_second)}
    Bd.save_results(Out)
    with open(Dump, "w", encoding="utf-8", newline="\n") as Handle:
        json.dump({"after_final_pass": Final, "after_find_unmatched": Unm, "sqlite_version": D.sqlite3.sqlite_version,
                   "python": sys.version.split()[0], "has_cdifflib": D.HAS_CDIFFLIB,
                   "pythonhashseed": os.environ.get("PYTHONHASHSEED")}, Handle, ensure_ascii=False)
    for Handle in list(D._DATABASES.values()) + list(getattr(Bd, "dbs_dict", {}).values()) + [Bd.db]:
        try:
            Handle.close()
        except Exception:
            pass
    return 0


# ----------------------------------------------------------------------------- output

def TsvField(Value):
    if Value is None:
        return "\\N"
    if not isinstance(Value, str):
        raise SystemExit("non-text value %r in a results file" % (Value,))
    return Value.replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n").replace("\r", "\\r")


def WriteTsv(Path, Columns, Rows):
    with open(Path, "w", encoding="utf-8", newline="\n") as Handle:
        Handle.write("\t".join(Columns) + "\n")
        for Row in Rows:
            Handle.write("\t".join(TsvField(V) for V in Row) + "\n")


def LogFacts(Path):
    with open(Path, "r", encoding="utf-8", errors="replace") as Handle:
        Text = Handle.read()
    Mode = "N"
    if "Symbols stripped detected:" in Text:
        Mode = "S"
    elif "Patch diffing detected:" in Text:
        Mode = "P"
    Final = re.search(r"Final results: Best (\d+), Partial (\d+), Unreliable (\d+), Multimatches (\d+)", Text)
    return {"mode": Mode,
            "final_results": dict(zip(("best", "partial", "unreliable", "multimatch"), map(int, Final.groups())))
            if Final else None,
            "saved_line_present": "Diffing results saved in file" in Text,
            "timeouts_logged": Text.count("Timeout with heuristic"),
            "tracebacks_logged": Text.count("Traceback (most recent call last)"),
            "cdifflib_warning_present": "Python library 'cdifflib' not found" in Text}


def Main():
    if len(sys.argv) > 1 and sys.argv[1] == "--_capture":
        return CaptureMain(*sys.argv[2:7])
    Parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    Parser.add_argument("scenario")
    Parser.add_argument("outdir")
    Parser.add_argument("--diaphora-dir", default=os.environ.get("DSIG_DIAPHORA_DIR"))
    Parser.add_argument("--python", default=os.environ.get("DSIG_PYTHON") or sys.executable)
    Parser.add_argument("--hash-seed", type=int, default=0)
    Parser.add_argument("--keep-work", help="keep the work files (databases, logs, outputs) in this directory")
    Args = Parser.parse_args()
    if not Args.diaphora_dir or not os.path.isfile(os.path.join(Args.diaphora_dir, "diaphora.py")):
        Parser.error("--diaphora-dir (or DSIG_DIAPHORA_DIR) must name the Diaphora checkout")
    DiaphoraDir = os.path.abspath(Args.diaphora_dir)
    Describe, StatusBefore = Git(DiaphoraDir, "describe", "--tags"), Git(DiaphoraDir, "status", "--porcelain")

    Schema = LoadSchema(DiaphoraDir)
    Scenario = LoadScenario(Args.scenario)
    Dumps = {"main": BuildDump(Schema, Scenario["MAIN"], 6), "diff": BuildDump(Schema, Scenario["DIFF"], 10)}

    Work = os.path.abspath(Args.keep_work) if Args.keep_work else tempfile.mkdtemp(prefix="dsig-make-fixture-")
    os.makedirs(Work, exist_ok=True)
    try:
        Paths = {}
        for Name, Text in Dumps.items():
            Paths[Name] = os.path.join(Work, Name + ".sqlite")
            RebuildLikeFixtureDb(Text, Paths[Name])
        Runs = {}
        for Run in ("cli", "capture"):
            RunDir = os.path.join(Work, Run)
            os.makedirs(RunDir, exist_ok=True)
            Copies = {}
            for Name, Path in Paths.items():  # Diaphora opens db1 read/write (01 §3.1): copies only
                Copies[Name] = os.path.join(RunDir, Name + ".sqlite")
                shutil.copyfile(Path, Copies[Name])
            Out = os.path.join(RunDir, "out.diaphora")
            Log = os.path.join(RunDir, "diaphora.log")
            if Run == "cli":
                Code = RunCli(Args.python, DiaphoraDir, Copies["main"], Copies["diff"], Out, Log, Args.hash_seed)
                Dump = None
            else:
                Dump = os.path.join(RunDir, "dump.json")
                Code = RunInstrumented(Args.python, DiaphoraDir, Copies["main"], Copies["diff"], Out, Dump, Log,
                                       Args.hash_seed)
            if Code != 0 or not os.path.isfile(Out):
                raise SystemExit("%s run failed (exit %d); see %s" % (Run, Code, Log))
            Runs[Run] = {"out": Out, "log": Log, "dump": Dump, "facts": LogFacts(Log)}

        CliResults, CliUnmatched, CliConfig = Snap.ReadDiaphora(Runs["cli"]["out"])
        CapResults, CapUnmatched, _ = Snap.ReadDiaphora(Runs["capture"]["out"])
        with open(Runs["capture"]["dump"], "r", encoding="utf-8") as Handle:
            Captured = json.load(Handle)
        DumpResults, DumpUnmatched = Snap.RowsFromDumps(Captured["after_final_pass"]["choosers"],
                                                        Captured["after_find_unmatched"]["unmatched"])
        SelfCheck = {"capture_vs_cli_results": Snap.CompareRowLists(CliResults, CapResults),
                     "capture_vs_cli_unmatched": Snap.CompareRowLists(CliUnmatched, CapUnmatched),
                     "dumps_vs_cli_results": Snap.CompareRowLists(CliResults, DumpResults),
                     "dumps_vs_cli_unmatched": Snap.CompareRowLists(CliUnmatched, DumpUnmatched)}
        Facts = Runs["cli"]["facts"]
        Problems = [Key for Key, Value in SelfCheck.items() if not Value["identical_in_order"]]
        if not Facts["saved_line_present"] or Facts["timeouts_logged"] or Facts["tracebacks_logged"]:
            Problems.append("log checks: %r" % Facts)
        if Runs["capture"]["facts"]["final_results"] != Facts["final_results"]:
            Problems.append("the two runs logged different Final results")
        StatusAfter = Git(DiaphoraDir, "status", "--porcelain")
        if Git(DiaphoraDir, "describe", "--tags") != Describe or StatusAfter != StatusBefore:
            Problems.append("the Diaphora checkout changed")
        if Problems:
            raise SystemExit("fixture NOT written: %s (work files in %s)" % (Problems, Work))

        os.makedirs(Args.outdir, exist_ok=True)
        for Name, Text in Dumps.items():
            with open(os.path.join(Args.outdir, Name + ".sql"), "w", encoding="utf-8", newline="\n") as Handle:
                Handle.write(Text)
        WriteTsv(os.path.join(Args.outdir, "expected_results.tsv"), RESULTS_COLUMNS, CliResults)
        WriteTsv(os.path.join(Args.outdir, "expected_unmatched.tsv"), UNMATCHED_COLUMNS, CliUnmatched)
        for Point in ("after_final_pass", "after_find_unmatched"):
            with open(os.path.join(Args.outdir, Point + ".json"), "w", encoding="utf-8", newline="\n") as Handle:
                Handle.write(Snap.DumpJson(Captured[Point]) + "\n")
        Counts = {}
        for Row in CliResults:
            Counts[Row[0]] = Counts.get(Row[0], 0) + 1
        UnmatchedCounts = {}
        for Row in CliUnmatched:
            UnmatchedCounts[Row[0]] = UnmatchedCounts.get(Row[0], 0) + 1
        Oracle = {
            "generator": "tools/parity/make_fixture.py",
            "scenario": os.path.basename(Args.scenario),
            "diaphora": Describe,
            "python": Captured["python"],
            "sqlite_version": Captured["sqlite_version"],
            "has_cdifflib": Captured["has_cdifflib"],
            "cdifflib_warning_present": Facts["cdifflib_warning_present"],
            "pythonhashseed": str(Args.hash_seed),
            "mode": Facts["mode"],
            "final_results": Facts["final_results"],
            "results_rows": len(CliResults),
            "results_by_type": Counts,
            "unmatched_rows": UnmatchedCounts,
            "config_version": [Row[2] for Row in CliConfig],
            "self_check": {Key: Value["identical_in_order"] for Key, Value in SelfCheck.items()},
        }
        with open(os.path.join(Args.outdir, "oracle.json"), "w", encoding="utf-8", newline="\n") as Handle:
            json.dump(Oracle, Handle, indent=1)
            Handle.write("\n")
        print("fixture written to %s: mode %s, %s, %d results rows, unmatched %s, SQLite %s"
              % (Args.outdir, Oracle["mode"], Oracle["final_results"], len(CliResults), UnmatchedCounts,
                 Oracle["sqlite_version"]))
        return 0
    finally:
        if not Args.keep_work:
            shutil.rmtree(Work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(Main())
