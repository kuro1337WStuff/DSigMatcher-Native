#!/usr/bin/env python3
"""Records what real Diaphora does with the `early` fixtures (pre-loop passes, patch-diff mode; 05 §19).

    python -B tests/diff/fixtures/early/gen_early.py [--diaphora-dir <dir>] [--python <exe>]
                                                     [--only <name> ...] [--skip-captures]

Run it after tools/parity/make_fixture.py has (re)built the scenario directories next to this file
(normal, stripped, patch, equal_mangled, quirks). It writes, all text and synthetic data only:

  <scenario>/capture/{index.json, trace.jsonl, snapshots/*.json}
      An instrumented run of each scenario with tools/parity/oracle_trace.py's Instrument (every point,
      row events, ratios_cache at before:find_*). Modes S and P run to the end; mode N stops at
      after:find_same_name (the later passes have their own fixtures: tiers, callee, related).
  vectors.json
      Mutation vectors: a scenario's two databases, rebuilt exactly as tests/diff/FixtureDb.h rebuilds
      them, then changed by SQL statements run on the finished files (sqlite3 executescript here,
      sqlite3_exec in the C++ test), then diffed by `python -B diaphora.py db1 db2 -o out` (the oracle
      command line). Recorded per vector: the exit code, whether the output file was written, the
      exception (type and innermost frame inside the Diaphora checkout) when Diaphora raised, the mode
      and the Diaphora log lines the native engine also writes, the `results` / `unmatched` rows in
      rowid order and, for a mode-N run, the snapshots of the four early points.

The Diaphora checkout is imported and run read-only (python -B, PYTHONDONTWRITEBYTECODE=1) on copies of
the databases; its `git describe` and `git status` are checked unchanged afterwards. No DIAPHORA_*
variable reaches it and PYTHONHASHSEED is fixed (make_fixture.CleanEnv).

Paths come from flags or the environment only:
  --diaphora-dir  (env DSIG_DIAPHORA_DIR)   the unmodified Diaphora checkout
  --python        (env DSIG_PYTHON)         the Python that runs Diaphora (default: this one)
"""

import sys

sys.dont_write_bytecode = True

import argparse  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import re  # noqa: E402
import shutil  # noqa: E402
import sqlite3  # noqa: E402
import subprocess  # noqa: E402
import tempfile  # noqa: E402
import types  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
PARITY = os.path.join(REPO, "tools", "parity")
if PARITY not in sys.path:
    sys.path.insert(0, PARITY)

import make_fixture as MF  # noqa: E402
import snapshot as Snap  # noqa: E402

SCENARIOS = ["normal", "stripped", "patch", "equal_mangled", "quirks"]
EARLY_POINTS = ["after:find_equal_matches", "after:apply_dirty_heuristics", "before:find_same_name",
                "after:find_same_name"]
SEED = 0

# Log lines (timestamps and levels stripped) the native engine writes to its summary log too.
LOG_PREFIXES = ("Error: ", "The selected file does not look like", "Invalid database!",
                "WARNING: The database is from a different version", "Same MD5 in both databases",
                "The databases seems to be 100% equal", "Call graph", "Symbols stripped detected:",
                "Patch diffing detected:", "Final results:")


# ----------------------------------------------------------------------------- mutation vectors

COPIED = [C for C in MF.COLUMNS if C not in ("id", "name", "address", "mangled_function", "rva")]


def CopiesOf(Template, Count, FirstId, BaseAddress, NameExpr, MangledExpr):
    """INSERT ... SELECT adding `Count` copies of the function named `Template`: ids FirstId + i,
    address (and the unique rva, schema.py:98) BaseAddress + i*256 as text."""
    return ("WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i < %d) "
            "INSERT INTO functions (id, name, address, mangled_function, rva, %s) "
            "SELECT %d + n.i, %s, CAST(%d + n.i * 256 AS TEXT), %s, CAST(%d + n.i * 256 AS TEXT), %s "
            "FROM n, functions f WHERE f.name = '%s';"
            % (Count - 1, ", ".join(COPIED), FirstId, NameExpr, BaseAddress, MangledExpr, BaseAddress,
               ", ".join("f." + C for C in COPIED), Template))


def ExtraFunctions(Count, FirstId, BaseAddress, NamePrefix, Template):
    """`Count` copies of `Template` named and mangled NamePrefix || i."""
    return CopiesOf(Template, Count, FirstId, BaseAddress, "'%s' || n.i" % NamePrefix, "'%s' || n.i" % NamePrefix)


def Program(Primes=None, AllPrimes=None, Raw=None):
    """UPDATE of the single program row; Raw gives SQL literals, the others are text values."""
    Sets = []
    if Raw is not None:
        Sets += ["%s = %s" % (K, V) for K, V in Raw.items()]
    if Primes is not None:
        Sets.append("callgraph_primes = '%s'" % Primes.replace("'", "''"))
    if AllPrimes is not None:
        Sets.append("callgraph_all_primes = '%s'" % AllPrimes.replace("'", "''"))
    return "UPDATE program SET %s;" % ", ".join(Sets)


BIG = "1" + "0" * 400  # 10**400: too large for a double

VECTORS = [
    # --- diff.version (D:3577-3591) ------------------------------------------------------------
    {"name": "version_missing", "base": "stripped", "diff_sql": "DROP TABLE version;"},
    {"name": "version_empty", "base": "stripped", "diff_sql": "DELETE FROM version;"},
    {"name": "version_other", "base": "stripped", "diff_sql": "UPDATE version SET value = '3.3';"},
    {"name": "version_blob", "base": "stripped", "diff_sql": "UPDATE version SET value = X'332E34';"},
    # --- totals / program rows ---------------------------------------------------------------------
    {"name": "main_empty", "base": "stripped", "main_sql": "DELETE FROM functions;"},
    {"name": "program_extra_row", "base": "stripped",
     "main_sql": "INSERT INTO program (callgraph_primes, callgraph_all_primes, processor, md5sum) "
                 "VALUES ('6', '{\"6\": 1}', 'metapc', 'x');"},
    {"name": "program_missing_row", "base": "stripped", "main_sql": "DELETE FROM program;"},
    # --- check_callgraph (D:1288-1338, jkutils/factor.py:202-242) ----------------------------------
    {"name": "cg_null_primes", "base": "stripped", "main_sql": Program(Raw={"callgraph_primes": "NULL"})},
    {"name": "cg_blob_primes", "base": "stripped", "main_sql": Program(Raw={"callgraph_primes": "X'36'"})},
    {"name": "cg_bad_primes", "base": "stripped", "main_sql": Program(Primes="abc")},
    {"name": "cg_bad_json", "base": "stripped", "main_sql": Program(AllPrimes="{bad")},
    {"name": "cg_null_json", "base": "stripped", "diff_sql": Program(Raw={"callgraph_all_primes": "NULL"})},
    {"name": "cg_equal_nondict", "base": "stripped", "main_sql": Program("7", "[1, 2]"),
     "diff_sql": Program("7", "\"text\"")},
    {"name": "cg_list_json", "base": "stripped", "main_sql": Program(AllPrimes="[1, 2]")},
    {"name": "cg_string_values", "base": "stripped", "main_sql": Program(AllPrimes="{\"6\": \"x\"}"),
     "diff_sql": Program(AllPrimes="{\"6\": \"y\"}")},
    {"name": "cg_null_value", "base": "stripped", "main_sql": Program(AllPrimes="{\"6\": null}")},
    {"name": "cg_equal_strings_in_both", "base": "stripped", "main_sql": Program(AllPrimes="{\"6\": \"x\", \"7\": 1}"),
     "diff_sql": Program(AllPrimes="{\"6\": \"x\", \"7\": 2}")},
    {"name": "cg_snan", "base": "stripped", "main_sql": Program(Primes="sNaN")},
    {"name": "cg_qnan", "base": "stripped", "main_sql": Program(Primes="NaN"),
     "diff_sql": Program(Primes="nan")},
    {"name": "cg_infinity_equal", "base": "stripped", "main_sql": Program("-Infinity", "[]"),
     "diff_sql": Program("-inf", "null")},
    {"name": "cg_bigint_overflow", "base": "stripped", "main_sql": Program(AllPrimes="{\"6\": %s}" % BIG),
     "diff_sql": Program(AllPrimes="{\"6\": 1}")},
    {"name": "cg_bigint_cancel", "base": "stripped",
     "main_sql": Program(AllPrimes="{\"6\": %s, \"7\": -%s}" % (BIG, BIG)),
     "diff_sql": Program(AllPrimes="{\"6\": %s, \"7\": -%s, \"8\": 1}" % (BIG, BIG))},
    {"name": "cg_bigint_mixed_float", "base": "stripped", "main_sql": Program(AllPrimes="{\"6\": %s}" % BIG),
     "diff_sql": Program(AllPrimes="{\"6\": 1.5}")},
    # A float total whose zero test decides whether a huge int diff is converted: the native engine
    # refuses these (Preflight.cpp, NOT PORTED: float sum() values), whatever Python does.
    {"name": "cg_float_total_nonzero_bigint_diff", "base": "stripped",
     "main_sql": Program(AllPrimes="{\"6\": 0.5, \"7\": -0.5, \"9\": 1}"),
     "diff_sql": Program(AllPrimes="{\"6\": 0.5, \"7\": -0.5, \"9\": %s}" % BIG), "native_unsupported": True},
    {"name": "cg_float_total_zero_bigint_diff", "base": "stripped",
     "main_sql": Program(AllPrimes="{\"6\": 0.5, \"7\": -0.5, \"9\": 0}"),
     "diff_sql": Program(AllPrimes="{\"6\": 0.5, \"7\": -0.5, \"9\": %s}" % BIG), "native_unsupported": True},
    {"name": "cg_float_counts", "base": "stripped", "main_sql": Program(AllPrimes="{\"6\": 1.5}"),
     "diff_sql": Program(AllPrimes="{\"6\": 2}"), "native_log_omitted": True},
    {"name": "cg_int_counts", "base": "stripped",
     "main_sql": Program(AllPrimes="{\"2\": 3, \"3\": 1, \"5\": 2, \"7\": 1}"),
     "diff_sql": Program(AllPrimes="{\"2\": 1, \"3\": 1, \"11\": 4, \"13\": true}")},
    {"name": "cg_scientific_equal", "base": "stripped",
     "main_sql": Program("1.258765552879565110995976484E+366"),
     "diff_sql": Program("1258765552879565110995976484E+339")},
    {"name": "cg_underscore_space_equal", "base": "stripped", "main_sql": Program(" 1_0 "),
     "diff_sql": Program("10.000")},
    {"name": "cg_duplicate_keys", "base": "stripped", "main_sql": Program(AllPrimes="{\"6\": 1, \"6\": 3}"),
     "diff_sql": Program(AllPrimes="{\"6\": 3}")},
    # --- find_equal_matches / find_same_name ------------------------------------------------------
    {"name": "equal_null_nodes", "base": "stripped",
     "main_sql": "UPDATE functions SET nodes = NULL WHERE name = 'DllMain';",
     "diff_sql": "UPDATE functions SET nodes = NULL WHERE name = 'DllMain';"},
    {"name": "same_name_null_mangled", "base": "patch",
     "main_sql": "UPDATE functions SET mangled_function = NULL WHERE name = 'func_5';"},
    {"name": "same_name_null_nodes", "base": "patch",
     "main_sql": "UPDATE functions SET nodes = NULL WHERE name = 'func_4';"},
    # --- the patch-diff hook (scripts/patch_diff_vulns.py) -----------------------------------------
    {"name": "hook_added_empty_line", "base": "patch",
     "diff_sql": "UPDATE functions SET assembly = replace(assembly, 'nop', char(10) || 'nop') "
                 "WHERE name = 'func_3';"},
    {"name": "hook_added_leading_space", "base": "patch",
     "diff_sql": "UPDATE functions SET assembly = replace(assembly, 'nop', ' nop') WHERE name = 'func_3';"},
    {"name": "hook_removed_empty_b", "base": "patch",
     "main_sql": "UPDATE functions SET assembly = replace(assembly, 'mov eax, ebx', char(10) || 'mov eax, ebx') "
                 "WHERE name = 'func_3';",
     "diff_sql": "UPDATE functions SET assembly = replace(assembly, 'mov eax, ebx', 'bswap eax' || char(10) || "
                 "'mov eax, ebx') WHERE name = 'func_3';"},
    {"name": "hook_removed_empty_not_b", "base": "patch",
     "main_sql": "UPDATE functions SET assembly = replace(assembly, 'mov eax, ebx', char(10) || 'mov eax, ebx') "
                 "WHERE name = 'func_3';",
     "diff_sql": "UPDATE functions SET assembly = replace(assembly, 'mov eax, ebx', 'xchg eax, eax' || char(10) || "
                 "'mov eax, ebx') WHERE name = 'func_3';"},
    {"name": "hook_break_before_bad_line", "base": "patch",
     "diff_sql": "UPDATE functions SET assembly = assembly || char(10) WHERE name = 'func_2';"},
    {"name": "hook_found_null_nodes", "base": "patch",
     "diff_sql": "UPDATE functions SET nodes = NULL WHERE name = 'func_3';"},
    {"name": "hook_remaining_added_empty_line", "base": "patch",
     "diff_sql": "UPDATE functions SET assembly = replace(assembly, 'nop', char(10) || 'nop') "
                 "WHERE name = 'renamed_fn';"},
    # --- find_remaining_functions gates (D:2639-2716) ------------------------------------------------
    # only_sub (D:2690-2692): a main leftover whose name does not start with "sub_" is never searched, so
    # renamed_fn stays unmatched although it is similar to it.
    {"name": "remaining_non_sub_leftover", "base": "patch",
     "main_sql": "UPDATE functions SET name = 'named_leftover', mangled_function = 'named_leftover' "
                 "WHERE name = 'sub_180004000';"},
    # name1.startswith on a NULL name (D:2691): AttributeError, no output.
    {"name": "remaining_null_name", "base": "patch",
     "main_sql": "UPDATE functions SET name = NULL WHERE name = 'sub_180004000';"},
    # `if name not in d` (D:2662): a sub_ function already matched is not a leftover. find_same_name skips
    # sub_ names (ignore_sub_names, D:2179), so the diff twin gets the main function's id, address, name,
    # nodes, edges, size and bytes hash and find_equal_matches pairs them ("100% equal", D:1426-1440).
    {"name": "remaining_matched_excluded", "base": "patch",
     "main_sql": "UPDATE functions SET edges = 9, size = 99, bytes_hash = 'eq' WHERE name = 'sub_180004000';",
     "diff_sql": "UPDATE functions SET name = 'sub_180004000', mangled_function = 'sub_180004000', "
                 "address = '6442467328', nodes = 5, edges = 9, size = 99, bytes_hash = 'eq' "
                 "WHERE name = 'renamed_fn';"},
    # A diff function with the main leftover's sub_ name but another address: find_same_name leaves sub_
    # names alone, so the remaining search pairs them.
    {"name": "remaining_same_sub_name", "base": "patch",
     "diff_sql": "UPDATE functions SET name = 'sub_180004000', mangled_function = 'sub_180004000' "
                 "WHERE name = 'renamed_fn';"},
    # `if self.is_patch_diff` (D:2708): in stripped mode the leftover lists are built but never searched,
    # so a main sub_ copy of Worker_2 and a diff copy of its stripped twin, at different addresses, stay
    # unmatched. 100 more address-sharing pairs keep the stripped test (C:160, >= 99%) satisfied.
    {"name": "remaining_stripped_mode", "base": "stripped",
     "main_sql": ExtraFunctions(100, 1000, 0x190000000, "extra_", "Worker_2") + " " +
                 CopiesOf("Worker_2", 1, 3000, 0x1A0000000, "'sub_1A0000000'", "'sub_1A0000000'"),
     "diff_sql": ExtraFunctions(100, 1000, 0x190000000, "sub_extra_", "sub_180001200") + " " +
                 CopiesOf("sub_180001200", 1, 3000, 0x1A0000100, "'sub_1A0000100'", "'sub_1A0000100'")},
    # --- the dirty-heuristic thresholds (C:160 >= 99.0, C:166 > 90.0) ------------------------------
    {"name": "stripped_exactly_99", "base": "stripped",
     "main_sql": ExtraFunctions(80, 1000, 0x190000000, "extra_", "Worker_2"),
     "diff_sql": ExtraFunctions(79, 1000, 0x190000000, "sub_extra_", "sub_180001200")},
    {"name": "stripped_below_99", "base": "stripped",
     "main_sql": ExtraFunctions(80, 1000, 0x190000000, "extra_", "Worker_2"),
     "diff_sql": ExtraFunctions(78, 1000, 0x190000000, "sub_extra_", "sub_180001200")},
    {"name": "patch_exactly_90", "base": "patch",
     "main_sql": "DELETE FROM functions WHERE name = 'sub_180005000';",
     "diff_sql": "UPDATE functions SET name = 'other_19', mangled_function = 'other_19' WHERE name = 'func_19';"},
    {"name": "patch_over_100", "base": "patch",
     "diff_sql": CopiesOf("func_1", 3, 100, 0x180100000, "f.name", "f.mangled_function")},
]


# ----------------------------------------------------------------------------- building and running

def BuildPair(Scenario, MainSql, DiffSql, Work):
    os.makedirs(Work, exist_ok=True)
    Paths = {}
    for Side, Extra in (("main", MainSql), ("diff", DiffSql)):
        with open(os.path.join(HERE, Scenario, Side + ".sql"), "r", encoding="utf-8") as Handle:
            Text = Handle.read()
        Path = os.path.join(Work, Side + ".sqlite")
        MF.RebuildLikeFixtureDb(Text, Path)  # tests/diff/FixtureDb.h BuildFixtureDbFromText
        if Extra:
            Con = sqlite3.connect(Path, isolation_level=None)
            Con.executescript(Extra)
            Con.close()
        Paths[Side] = Path
    return Paths


def CopyPair(Paths, Dir):
    os.makedirs(Dir, exist_ok=True)
    Copies = {}
    for Side, Path in Paths.items():
        Copies[Side] = os.path.join(Dir, Side + ".sqlite")
        shutil.copyfile(Path, Copies[Side])
    return Copies


def LogLines(Path):
    Out = []
    with open(Path, "r", encoding="utf-8", errors="replace") as Handle:
        for Line in Handle:
            Line = Line.rstrip("\n")
            Match = re.match(r"^\[Diaphora: [^\]]*\] [A-Z]+: (.*)$", Line)
            if Match and Match.group(1).startswith(LOG_PREFIXES):
                Out.append(Match.group(1))
    return Out


def ExceptionOf(LogPath, DiaphoraDir):
    """The last traceback of the log: exception type, message and the innermost frame whose file is
    inside the Diaphora checkout (relative, '/' separators)."""
    with open(LogPath, "r", encoding="utf-8", errors="replace") as Handle:
        Lines = Handle.read().split("\n")
    Start = None
    for Index, Line in enumerate(Lines):
        if Line.startswith("Traceback (most recent call last):"):
            Start = Index
    if Start is None:
        return None
    Frame = None
    Root = os.path.normcase(os.path.abspath(DiaphoraDir))
    Last = None
    for Line in Lines[Start + 1:]:
        Match = re.match(r'^  File "(.*)", line (\d+), in (.*)$', Line)
        if Match:
            File = os.path.normcase(os.path.abspath(Match.group(1)))
            if File.startswith(Root):
                Frame = {"file": os.path.relpath(File, Root).replace("\\", "/"), "line": int(Match.group(2)),
                         "function": Match.group(3)}
            continue
        if Line and not Line.startswith(" ") and not Line.startswith("~") and not Line.startswith("^"):
            Last = Line
            break
    Type, _, Message = (Last or "").partition(":")
    return {"type": Type.strip().split(".")[-1], "message": Message.strip(), "frame": Frame}


def RunCli(Python, DiaphoraDir, Copies, Out, Log):
    with open(Log, "w", encoding="utf-8", errors="replace") as Handle:
        return subprocess.call([Python, "-B", os.path.join(DiaphoraDir, "diaphora.py"), Copies["main"],
                                Copies["diff"], "-o", Out], cwd=DiaphoraDir, env=MF.CleanEnv(SEED),
                               stdout=Handle, stderr=subprocess.STDOUT)


def RunCapture(Python, DiaphoraDir, Copies, OutDir, StopAt, Log):
    os.makedirs(OutDir, exist_ok=True)
    with open(Log, "w", encoding="utf-8", errors="replace") as Handle:
        return subprocess.call([Python, "-B", os.path.abspath(__file__), "--_capture", DiaphoraDir, Copies["main"],
                                Copies["diff"], OutDir, StopAt or ""], cwd=DiaphoraDir, env=MF.CleanEnv(SEED),
                               stdout=Handle, stderr=subprocess.STDOUT)


def CaptureChild(DiaphoraDir, Db1, Db2, OutDir, StopAt):
    """Child process: diaphora.py __main__ (D:3757-3773) under oracle_trace.Instrument."""
    sys.path.insert(0, DiaphoraDir)
    import diaphora as D  # the unmodified checkout, read-only
    import oracle_trace as OT
    Args = types.SimpleNamespace(points=["*"], with_cache=["before:find_*"], stop_at=StopAt or None, rows=True,
                                 force_const_order=None)
    Bd = D.CBinDiff(Db1)
    if not D.IS_IDA:
        Bd.ignore_all_names = False
    Bd.db = D.sqlite3_connect(Db1)
    Instr = OT.Instrument(D, Bd, Args, OutDir, "fixture", "diaphora-" + (MF.Git(DiaphoraDir, "describe", "--tags")
                                                                           or "?"), {})
    Instr.Install()
    Status = 0
    try:
        Bd.diff(Db2)
    except OT.StopCapture:
        pass
    finally:
        Instr.Close()
        Instr.RestoreChooser()
        for Handle in list(D._DATABASES.values()) + list(getattr(Bd, "dbs_dict", {}).values()) + [Bd.db]:
            try:
                Handle.close()
            except Exception:
                pass
    return Status


def KeepCapture(Src, Dst):
    """index.json, trace.jsonl and the snapshots of a capture (not run.json / progress.log)."""
    if os.path.isdir(Dst):
        shutil.rmtree(Dst)
    os.makedirs(os.path.join(Dst, "snapshots"))
    for Name in ("index.json", "trace.jsonl"):
        shutil.copyfile(os.path.join(Src, Name), os.path.join(Dst, Name))
    for Name in sorted(os.listdir(os.path.join(Src, "snapshots"))):
        if Name.endswith(".json"):
            shutil.copyfile(os.path.join(Src, "snapshots", Name), os.path.join(Dst, "snapshots", Name))


def ModeOf(Lines):
    if any(L.startswith("Symbols stripped detected:") for L in Lines):
        return "S"
    if any(L.startswith("Patch diffing detected:") for L in Lines):
        return "P"
    return "N"


def Main():
    if len(sys.argv) > 1 and sys.argv[1] == "--_capture":
        return CaptureChild(*sys.argv[2:7])
    Parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    Parser.add_argument("--diaphora-dir", default=os.environ.get("DSIG_DIAPHORA_DIR"))
    Parser.add_argument("--python", default=os.environ.get("DSIG_PYTHON") or sys.executable)
    Parser.add_argument("--only", nargs="*", help="only these scenarios / vectors")
    Parser.add_argument("--skip-captures", action="store_true")
    Args = Parser.parse_args()
    if not Args.diaphora_dir or not os.path.isfile(os.path.join(Args.diaphora_dir, "diaphora.py")):
        Parser.error("--diaphora-dir (or DSIG_DIAPHORA_DIR) must name the Diaphora checkout")
    DiaphoraDir = os.path.abspath(Args.diaphora_dir)
    Describe, StatusBefore = MF.Git(DiaphoraDir, "describe", "--tags"), MF.Git(DiaphoraDir, "status", "--porcelain")
    Work = tempfile.mkdtemp(prefix="dsig-gen-early-")
    try:
        if not Args.skip_captures:
            for Scenario in SCENARIOS:
                if Args.only and Scenario not in Args.only:
                    continue
                with open(os.path.join(HERE, Scenario, "oracle.json"), "r", encoding="utf-8") as Handle:
                    Mode = json.load(Handle)["mode"]
                Dir = os.path.join(Work, "scenario-" + Scenario)
                Copies = CopyPair(BuildPair(Scenario, None, None, os.path.join(Dir, "db")), os.path.join(Dir, "run"))
                Capture = os.path.join(Dir, "capture")
                Code = RunCapture(Args.python, DiaphoraDir, Copies, Capture,
                                  "after:find_same_name" if Mode == "N" else "", os.path.join(Dir, "capture.log"))
                if Code != 0:
                    raise SystemExit("capture of %s failed (exit %d), see %s" % (Scenario, Code, Dir))
                KeepCapture(Capture, os.path.join(HERE, Scenario, "capture"))
                print("capture %s: mode %s, %d points" % (Scenario, Mode,
                                                           len(Snap.ReadJson(os.path.join(Capture, "index.json")))))

        Previous = {}
        VectorsPath = os.path.join(HERE, "vectors.json")
        if Args.only and os.path.isfile(VectorsPath):
            Previous = {V["name"]: V for V in Snap.ReadJson(VectorsPath)["vectors"]}
        Results = []
        for Vector in VECTORS:
            if Args.only and Vector["name"] not in Args.only:
                if Vector["name"] in Previous:
                    Results.append(Previous[Vector["name"]])
                continue
            Dir = os.path.join(Work, "vector-" + Vector["name"])
            Paths = BuildPair(Vector["base"], Vector.get("main_sql"), Vector.get("diff_sql"), os.path.join(Dir, "db"))
            Copies = CopyPair(Paths, os.path.join(Dir, "cli"))
            Out = os.path.join(Dir, "cli", "out.diaphora")
            Log = os.path.join(Dir, "cli", "diaphora.log")
            Code = RunCli(Args.python, DiaphoraDir, Copies, Out, Log)
            Lines = LogLines(Log)
            Record = {"name": Vector["name"], "base": Vector["base"], "main_sql": Vector.get("main_sql", ""),
                      "diff_sql": Vector.get("diff_sql", ""), "exit_code": Code, "output_written": os.path.isfile(Out),
                      "exception": ExceptionOf(Log, DiaphoraDir) if Code != 0 else None,
                      "mode": ModeOf(Lines), "log": Lines,
                      "native_log_omitted": bool(Vector.get("native_log_omitted", False)),
                      "native_unsupported": bool(Vector.get("native_unsupported", False))}
            if Record["output_written"]:
                Rows, Unmatched, _ = Snap.ReadDiaphora(Out)
                Record["results"] = Rows
                Record["unmatched"] = Unmatched
            if Code == 0 and Record["mode"] == "N":
                Capture = os.path.join(Dir, "capture")
                Copies2 = CopyPair(Paths, os.path.join(Dir, "capture-db"))
                if RunCapture(Args.python, DiaphoraDir, Copies2, Capture, "after:find_same_name",
                              os.path.join(Dir, "capture.log")) != 0:
                    raise SystemExit("capture of vector %s failed, see %s" % (Vector["name"], Dir))
                Early = {}
                Index = os.path.join(Capture, "index.json")
                for Seq, Point, File in (Snap.ReadJson(Index) if os.path.isfile(Index) else []):
                    if Point in EARLY_POINTS and File:
                        Early[Point] = Snap.ReadJson(os.path.join(Capture, File))
                Record["early_points"] = Early
            Results.append(Record)
            Summary = Record["exception"]
            print("vector %-34s exit %d, output %s, mode %s%s" % (
                Vector["name"], Code, Record["output_written"], Record["mode"],
                ", raised %s at %s" % (Summary["type"], Summary["frame"]) if Summary else ""))
        Python = subprocess.run([Args.python, "-c", "import sys, sqlite3; print(sys.version.split()[0], "
                                 "sqlite3.sqlite_version)"], capture_output=True, text=True).stdout.split()
        with open(VectorsPath, "w", encoding="utf-8", newline="\n") as Handle:
            json.dump({"generator": "tests/diff/fixtures/early/gen_early.py", "diaphora": Describe,
                       "python": Python[0] if Python else None, "sqlite_version": Python[1] if Python else None,
                       "pythonhashseed": str(SEED), "vectors": Results}, Handle, ensure_ascii=False, indent=1)
            Handle.write("\n")
    finally:
        shutil.rmtree(Work, ignore_errors=True)
    if MF.Git(DiaphoraDir, "describe", "--tags") != Describe or MF.Git(DiaphoraDir, "status", "--porcelain") != StatusBefore:
        raise SystemExit("the Diaphora checkout changed")
    return 0


if __name__ == "__main__":
    sys.exit(Main())
