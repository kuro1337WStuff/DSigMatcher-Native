#!/usr/bin/env python3
"""Compare two Diaphora results files (.diaphora) at the parity levels of docs/parity/00-plan.md §1.3.

    python -B compare_results.py <oracle.diaphora> <native.diaphora> [--oracle-log <log>]
                                 [--native-log <log>] [--compare-config-paths] [--json <out>]
                                 [--markdown <out>] [--limit 20] [--quiet]
    python -B compare_results.py --self-test [--file <any .diaphora>]

Levels (plan §1.3):
  L0  the detected mode (N, S or P, from the `Symbols stripped detected:` / `Patch diffing detected:`
      log lines) and the `Final results: Best b, Partial p, Unreliable u, Multimatches m` line
      (D:3684-3692) agree. Needs both logs; otherwise it is reported as not evaluated.
  L1  `results` as a multiset of (type, address, address2, name, name2, ratio, nodes1, nodes2,
      description) and `unmatched` as a multiset of (type, address, name) are equal, and so is
      config.version (config.main_db / diff_db only with --compare-config-paths; config.date never).
  L2  L1 plus identical `line` values and identical stored row order (`order by rowid`) in both tables:
      the parity gate.
The DDL (sqlite_master) is compared as well and reported as `ddl_equal`.

Per (type, description) group, rows are paired by their (address, address2) key, which is unique in a
results table (`uq_results`, D:2399). The table counts, per group:
  matched            the pair is in both files with every field but `line` equal
  only_oracle        the pair is missing from the native file (grouped by the oracle row)
  only_native        the pair is missing from the oracle file (grouped by the native row)
  ratio              same pair, different ratio text (|delta| of the parsed values is reported)
  category           same pair, different type (best / partial / unreliable / multimatch)
  description_mismatch  same pair, different description
  name               same pair, different name or name2
  nodes              same pair, different nodes1 or nodes2
  line               same pair, different `line`
  order              same pair, different rank among the pairs both files share (stored order)
A pair in both files is grouped under the oracle's (type, description); one row can count in several
mismatch columns. Descriptions are heuristic or pass names, so this is the per-heuristic and per-pass
agreement table. `unmatched` is diffed per type the same way on (type, address, name).

Plan §5 R3: rows described "Same constants related matches" (D:3368) depend on CPython's set order.
Differences confined to them are reported as the separate tolerated class `r3_only`; the L1/L2
verdicts are never relaxed for them.

Both files are opened read-only with immutable=1 (no journal or -wal/-shm file is ever created).
Exit status: 0 when L2 holds and the DDL is equal, 1 otherwise, 2 on a usage or read error.
"""

import sys

sys.dont_write_bytecode = True

import argparse  # noqa: E402
import collections  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import pathlib  # noqa: E402
import re  # noqa: E402
import shutil  # noqa: E402
import sqlite3  # noqa: E402
import tempfile  # noqa: E402

RESULTS_COLUMNS = ("type", "line", "address", "name", "address2", "name2", "ratio", "nodes1", "nodes2",
                   "description")
UNMATCHED_COLUMNS = ("type", "line", "address", "name")
CATEGORIES = ("best", "partial", "unreliable", "multimatch")
R3_DESCRIPTION = "Same constants related matches"  # find_related_constants, D:3368
MISMATCH_KINDS = ("ratio", "category", "description_mismatch", "name", "nodes", "line", "order")

# save_results (D:2387-2403), verbatim.
DDL = ("create table config (main_db text, diff_db text, version text, date text)",
       """create table results (type, line, address, name, address2, name2,
                   ratio, nodes1, nodes2, description)""",
       "create unique index uq_results on results(address, address2)",
       "create table unmatched (type, line, address, name)")


class CompareError(RuntimeError):
    pass


# ----------------------------------------------------------------------------- reading

def ReadOnlyUri(Path):
    return pathlib.Path(os.path.abspath(Path)).as_uri() + "?mode=ro&immutable=1"


def ReadResultsDb(Path):
    """{schema, config, results, unmatched} of a results file; rows in rowid order, values as stored."""
    if not os.path.isfile(Path):
        raise CompareError("no such file: %s" % Path)
    try:
        Db = sqlite3.connect(ReadOnlyUri(Path), uri=True)
    except sqlite3.Error as Error:
        raise CompareError("cannot open %s: %s" % (Path, Error))
    try:
        Schema = Db.execute("select type, name, tbl_name, sql from sqlite_master order by rowid").fetchall()
        Config = Db.execute("select main_db, diff_db, version, date from config order by rowid").fetchall()
        Results = Db.execute("select %s from results order by rowid" % ", ".join(RESULTS_COLUMNS)).fetchall()
        Unmatched = Db.execute("select %s from unmatched order by rowid" % ", ".join(UNMATCHED_COLUMNS)).fetchall()
        NonText = Db.execute(
            "select count(*) from results where typeof(type) != 'text' or typeof(line) != 'text' or "
            "typeof(address) != 'text' or typeof(address2) != 'text' or typeof(ratio) != 'text' or "
            "typeof(nodes1) != 'text' or typeof(nodes2) != 'text' or typeof(description) != 'text' or "
            "typeof(name) not in ('text', 'null') or typeof(name2) not in ('text', 'null')").fetchone()[0]
        NonText += Db.execute(
            "select count(*) from unmatched where typeof(type) != 'text' or typeof(line) != 'text' or "
            "typeof(address) != 'text' or typeof(name) not in ('text', 'null')").fetchone()[0]
    except sqlite3.Error as Error:
        raise CompareError("%s is not a Diaphora results file: %s" % (Path, Error))
    finally:
        Db.close()
    return {"path": Path, "schema": Schema, "config": Config, "results": Results, "unmatched": Unmatched,
            "non_text_values": NonText}


def LogFacts(Path):
    """L0 facts from a Diaphora log or a `dsigmatcher diff` stderr log; None without a log."""
    if not Path:
        return None
    try:
        with open(Path, "r", encoding="utf-8", errors="replace") as Handle:
            Text = Handle.read()
    except OSError:
        return None
    Final = None
    for Match in re.finditer(r"Final results: Best (\d+), Partial (\d+), Unreliable (\d+), Multimatches (\d+)", Text):
        Final = [int(Value) for Value in Match.groups()]
    Mode = None
    if "Symbols stripped detected:" in Text:
        Mode = "S"
    elif "Patch diffing detected:" in Text:
        Mode = "P"
    elif Final is not None:
        Mode = "N"
    return {"mode": Mode, "final_results": Final}


# ----------------------------------------------------------------------------- comparison

def _L1Key(Row):
    return (Row[0], Row[2], Row[4], Row[3], Row[5], Row[6], Row[7], Row[8], Row[9])


def _Describe(Row, Columns):
    return " | ".join("None" if Value is None else str(Value) for Value in Row) if Row is not None else "-"


def _Float(Text):
    try:
        return float(Text)
    except (TypeError, ValueError):
        return None


def _Ranks(Keys, Common):
    Ranks = {}
    for Key in Keys:
        if Key in Common and Key not in Ranks:
            Ranks[Key] = len(Ranks)
    return Ranks


def NewGroup():
    Group = {"matched": 0, "only_oracle": 0, "only_native": 0, "max_abs_delta": 0.0}
    for Kind in MISMATCH_KINDS:
        Group[Kind] = 0
    return Group


def Compare(Oracle, Native, OracleLog=None, NativeLog=None, ComparePaths=False, Limit=20):
    """The comparison report (a JSON-serialisable dict) of two ReadResultsDb() results."""
    Differences = []

    def Note(Text):
        if len(Differences) < Limit:
            Differences.append(Text)

    Report = {"oracle": Oracle["path"], "native": Native["path"]}
    DdlEqual = [tuple(Row) for Row in Oracle["schema"]] == [tuple(Row) for Row in Native["schema"]]
    if not DdlEqual:
        Note("sqlite_master differs: oracle %r native %r" % (Oracle["schema"], Native["schema"]))

    # config: the version always, the paths on request, the date never (plan §1.2).
    ConfigEqual = len(Oracle["config"]) == len(Native["config"]) and all(
        A[2] == B[2] and (not ComparePaths or (A[0], A[1]) == (B[0], B[1]))
        for A, B in zip(Oracle["config"], Native["config"]))
    if not ConfigEqual:
        Note("config differs: oracle %r native %r (date ignored%s)"
             % ([Row[:3] for Row in Oracle["config"]], [Row[:3] for Row in Native["config"]],
                "" if ComparePaths else ", paths ignored"))

    # results, paired by (address, address2)
    OracleByKey = collections.OrderedDict(((Row[2], Row[4]), Row) for Row in Oracle["results"])
    NativeByKey = collections.OrderedDict(((Row[2], Row[4]), Row) for Row in Native["results"])
    Common = set(OracleByKey) & set(NativeByKey)
    OracleRank = _Ranks(OracleByKey, Common)
    NativeRank = _Ranks(NativeByKey, Common)
    Groups = collections.OrderedDict()
    R3Rows = 0
    NonR3Differences = 0

    def GroupOf(Row):
        Key = (Row[0], Row[9])
        if Key not in Groups:
            Groups[Key] = NewGroup()
        return Groups[Key]

    for Key, Row in OracleByKey.items():
        Group = GroupOf(Row)
        Other = NativeByKey.get(Key)
        if Other is None:
            Group["only_oracle"] += 1
            Note("only in oracle: %s" % _Describe(Row, RESULTS_COLUMNS))
            if Row[9] == R3_DESCRIPTION:
                R3Rows += 1
            else:
                NonR3Differences += 1
            continue
        Kinds = []
        if Row[6] != Other[6]:
            Kinds.append("ratio")
            A, B = _Float(Row[6]), _Float(Other[6])
            if A is not None and B is not None:
                Group["max_abs_delta"] = max(Group["max_abs_delta"], abs(A - B))
        if Row[0] != Other[0]:
            Kinds.append("category")
        if Row[9] != Other[9]:
            Kinds.append("description_mismatch")
        if (Row[3], Row[5]) != (Other[3], Other[5]):
            Kinds.append("name")
        if (Row[7], Row[8]) != (Other[7], Other[8]):
            Kinds.append("nodes")
        if not Kinds:
            Group["matched"] += 1
        if Row[1] != Other[1]:
            Kinds.append("line")
        if OracleRank[Key] != NativeRank[Key]:
            Kinds.append("order")
        for Kind in Kinds:
            Group[Kind] += 1
        if Kinds:
            Note("%s: oracle [%s] native [%s]" % ("/".join(Kinds), _Describe(Row, RESULTS_COLUMNS),
                                                  _Describe(Other, RESULTS_COLUMNS)))
            if R3_DESCRIPTION in (Row[9], Other[9]):
                R3Rows += 1
            else:
                NonR3Differences += 1
    for Key, Row in NativeByKey.items():
        if Key not in OracleByKey:
            GroupOf(Row)["only_native"] += 1
            Note("only in native: %s" % _Describe(Row, RESULTS_COLUMNS))
            if Row[9] == R3_DESCRIPTION:
                R3Rows += 1
            else:
                NonR3Differences += 1

    # unmatched, per type, on (type, address, name) with multiplicity
    UnmatchedTypes = collections.OrderedDict()

    def Counter(Rows):
        return collections.Counter((Row[0], Row[2], Row[3]) for Row in Rows)

    OracleCount, NativeCount = Counter(Oracle["unmatched"]), Counter(Native["unmatched"])
    for Key in list(OracleCount) + [K for K in NativeCount if K not in OracleCount]:
        Entry = UnmatchedTypes.setdefault(Key[0], {"both": 0, "only_oracle": 0, "only_native": 0, "line": 0,
                                                   "order": 0})
        Both = min(OracleCount[Key], NativeCount[Key])
        Entry["both"] += Both
        Entry["only_oracle"] += OracleCount[Key] - Both
        Entry["only_native"] += NativeCount[Key] - Both
        if OracleCount[Key] > Both:
            Note("unmatched only in oracle: %s" % (Key,))
        if NativeCount[Key] > Both:
            Note("unmatched only in native: %s" % (Key,))
    # line / order for unmatched rows present on both sides (first occurrence per key)
    OracleUn = collections.OrderedDict()
    for Row in Oracle["unmatched"]:
        OracleUn.setdefault((Row[0], Row[2], Row[3]), Row)
    NativeUn = collections.OrderedDict()
    for Row in Native["unmatched"]:
        NativeUn.setdefault((Row[0], Row[2], Row[3]), Row)
    CommonUn = set(OracleUn) & set(NativeUn)
    OracleUnRank, NativeUnRank = _Ranks(OracleUn, CommonUn), _Ranks(NativeUn, CommonUn)
    for Key in CommonUn:
        Entry = UnmatchedTypes[Key[0]]
        if OracleUn[Key][1] != NativeUn[Key][1]:
            Entry["line"] += 1
            Note("unmatched line: oracle %s native %s" % (OracleUn[Key], NativeUn[Key]))
        if OracleUnRank[Key] != NativeUnRank[Key]:
            Entry["order"] += 1

    ResultsL1 = collections.Counter(map(_L1Key, Oracle["results"])) == collections.Counter(map(_L1Key, Native["results"]))
    UnmatchedL1 = OracleCount == NativeCount
    L1 = ResultsL1 and UnmatchedL1 and ConfigEqual
    ResultsL2 = [tuple(Row) for Row in Oracle["results"]] == [tuple(Row) for Row in Native["results"]]
    UnmatchedL2 = [tuple(Row) for Row in Oracle["unmatched"]] == [tuple(Row) for Row in Native["unmatched"]]
    L2 = L1 and ResultsL2 and UnmatchedL2
    if L1 and not L2:
        for Index, (A, B) in enumerate(zip(Oracle["results"], Native["results"])):
            if tuple(A) != tuple(B):
                Note("first stored-order difference in results at row %d: oracle [%s] native [%s]"
                     % (Index, _Describe(A, RESULTS_COLUMNS), _Describe(B, RESULTS_COLUMNS)))
                break

    # L0
    OracleFacts, NativeFacts = LogFacts(OracleLog), LogFacts(NativeLog)
    L0 = None
    if OracleFacts and NativeFacts and OracleFacts["final_results"] is not None:
        L0 = (OracleFacts["mode"] == NativeFacts["mode"] and
              OracleFacts["final_results"] == NativeFacts["final_results"])

    def Counts(Rows):
        Out = collections.OrderedDict((Category, 0) for Category in CATEGORIES)
        for Row in Rows:
            Out[Row[0]] = Out.get(Row[0], 0) + 1
        return Out

    Report.update({
        "verdict": {"L0": L0, "L1": L1, "L2": L2, "ddl_equal": DdlEqual, "config_equal": ConfigEqual,
                    "results_l1": ResultsL1, "unmatched_l1": UnmatchedL1, "results_l2": ResultsL2,
                    "unmatched_l2": UnmatchedL2, "ok": L2 and DdlEqual},
        "l0": {"oracle": OracleFacts, "native": NativeFacts},
        "counts": {"oracle_results": Counts(Oracle["results"]), "native_results": Counts(Native["results"]),
                   "oracle_unmatched": dict(collections.Counter(Row[0] for Row in Oracle["unmatched"])),
                   "native_unmatched": dict(collections.Counter(Row[0] for Row in Native["unmatched"])),
                   "non_text_values": {"oracle": Oracle["non_text_values"], "native": Native["non_text_values"]}},
        "groups": [dict(type=Key[0], description=Key[1], **Value) for Key, Value in Groups.items()],
        "unmatched": UnmatchedTypes,
        "tolerated": {"r3_rows": R3Rows, "r3_only": R3Rows > 0 and NonR3Differences == 0 and UnmatchedL1 and
                      ConfigEqual},
        "differences": Differences,
    })
    return Report


def CompareFiles(OracleFile, NativeFile, OracleLog=None, NativeLog=None, ComparePaths=False, Limit=20):
    return Compare(ReadResultsDb(OracleFile), ReadResultsDb(NativeFile), OracleLog, NativeLog, ComparePaths, Limit)


# ----------------------------------------------------------------------------- output

def _Yes(Value):
    return "n/a" if Value is None else ("yes" if Value else "NO")


def Summary(Report):
    V = Report["verdict"]
    Parts = ["L0 %s" % _Yes(V["L0"]), "L1 %s" % _Yes(V["L1"]), "L2 %s" % _Yes(V["L2"]), "DDL %s" % _Yes(V["ddl_equal"])]
    Oracle = sum(Report["counts"]["oracle_results"].values())
    Native = sum(Report["counts"]["native_results"].values())
    Parts.append("rows oracle %d native %d" % (Oracle, Native))
    if Report["tolerated"]["r3_rows"]:
        Parts.append("R3 rows %d%s" % (Report["tolerated"]["r3_rows"],
                                       " (only R3 differs)" if Report["tolerated"]["r3_only"] else ""))
    return ", ".join(Parts)


def Markdown(Report, Title=None):
    Lines = []
    if Title:
        Lines += ["## %s" % Title, ""]
    Lines += ["- oracle: `%s`" % Report["oracle"], "- native: `%s`" % Report["native"],
              "- verdict: %s" % Summary(Report), ""]
    L0 = Report["l0"]
    if L0["oracle"] or L0["native"]:
        Lines.append("- L0: oracle mode %s final %s; native mode %s final %s" % (
            (L0["oracle"] or {}).get("mode"), (L0["oracle"] or {}).get("final_results"),
            (L0["native"] or {}).get("mode"), (L0["native"] or {}).get("final_results")))
        Lines.append("")
    Lines += ["| type | description | matched | only oracle | only native | ratio (max abs delta) | category | "
              "desc. mismatch | name | nodes | line | order |",
              "|---|---|---:|---:|---:|---|---:|---:|---:|---:|---:|---:|"]
    for Group in sorted(Report["groups"], key=lambda G: (CATEGORIES.index(G["type"]) if G["type"] in CATEGORIES
                                                         else 9, G["description"])):
        Lines.append("| %s | %s | %d | %d | %d | %d%s | %d | %d | %d | %d | %d | %d |" % (
            Group["type"], Group["description"], Group["matched"], Group["only_oracle"], Group["only_native"],
            Group["ratio"], " (%.7g)" % Group["max_abs_delta"] if Group["ratio"] else "", Group["category"],
            Group["description_mismatch"],
            Group["name"], Group["nodes"], Group["line"], Group["order"]))
    Lines += ["", "| unmatched type | both | only oracle | only native | line | order |", "|---|---:|---:|---:|---:|---:|"]
    for Type, Entry in Report["unmatched"].items():
        Lines.append("| %s | %d | %d | %d | %d | %d |" % (Type, Entry["both"], Entry["only_oracle"],
                                                         Entry["only_native"], Entry["line"], Entry["order"]))
    if Report["differences"]:
        Lines += ["", "First differences:", ""] + ["- %s" % Text for Text in Report["differences"]]
    Lines.append("")
    return "\n".join(Lines)


# ----------------------------------------------------------------------------- self-test

def WriteResultsDb(Path, Config, Results, Unmatched):
    """A results file with save_results' DDL and the given rows, in order (rows are bound as given)."""
    if os.path.exists(Path):
        os.remove(Path)
    Db = sqlite3.connect(Path)
    try:
        Db.execute(DDL[0])
        for Row in Config:
            Db.execute("insert into config values (?, ?, ?, ?)", Row)
        for Sql in DDL[1:]:
            Db.execute(Sql)
        for Row in Results:
            Db.execute("insert or ignore into results values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", Row)
        for Row in Unmatched:
            Db.execute("insert into unmatched values (?, ?, ?, ?)", Row)
        Db.commit()
    finally:
        Db.close()


SYNTHETIC_RESULTS = [
    ("best", "00000", "00001000", "f", "00002000", "f", "1.0000000", "5", "5", "Perfect match, same name"),
    ("best", "00001", "00001100", "g", "00002100", "sub_2100", "1.0000000", "3", "3", "Equal assembly"),
    ("best", "00002", "00001200", "h", "00002200", "sub_2200", "1.0000000", "4", "4", "Equal assembly"),
    ("partial", "00000", "00001300", "i", "00002300", "sub_2300", "0.9041765", "6", "6", "Loop count"),
    ("partial", "00001", "00001400", "j", "00002400", "sub_2400", "0.8000000", "2", "2",
     "Same constants related matches"),
    ("partial", "00002", "00001500", "k", "00002500", None, "0.7500000", "2", "3", "Loop count"),
    ("multimatch", "00000", "00001600", "l", "00002600", "sub_2600", "0.5000000", "1", "1",
     "Related compilation unit"),
    ("multimatch", "00001", "00001600", "l", "00002700", "sub_2700", "0.5000000", "1", "1",
     "Related compilation unit"),
]
SYNTHETIC_UNMATCHED = [("primary", "00000", "00002800", "sub_2800"), ("primary", "00001", "00002900", None),
                       ("secondary", "00000", "00001700", "m")]
SYNTHETIC_CONFIG = [("db1.sqlite", "db2.sqlite", "3.4", "Wed Sep  3 12:34:56 2026")]


def SelfTest(BaseFile=None):
    """Plants changes into a copy and checks their classification. Returns the number of failures."""
    Work = tempfile.mkdtemp(prefix="dsig-compare-results-")
    Failures = []

    def Check(Label, Condition):
        print("  %-60s %s" % (Label, "ok" if Condition else "FAILED"))
        if not Condition:
            Failures.append(Label)

    try:
        if BaseFile:
            Base = ReadResultsDb(BaseFile)  # read only; the plants go into new files
            Config, Results, Unmatched = Base["config"], Base["results"], Base["unmatched"]
            print("self-test on the rows of %s (%d results, %d unmatched)" % (BaseFile, len(Results), len(Unmatched)))
        else:
            Config, Results, Unmatched = SYNTHETIC_CONFIG, SYNTHETIC_RESULTS, SYNTHETIC_UNMATCHED
            print("self-test on synthetic rows (%d results, %d unmatched)" % (len(Results), len(Unmatched)))
        if len(Results) < 4 or not Unmatched:
            raise CompareError("the self-test needs at least 4 results rows and 1 unmatched row")
        Results = [list(Row) for Row in Results]
        Unmatched = [list(Row) for Row in Unmatched]
        OraclePath = os.path.join(Work, "oracle.diaphora")
        WriteResultsDb(OraclePath, Config, Results, Unmatched)

        def Planted(Name, NewResults, NewUnmatched=None, NewConfig=None):
            Path = os.path.join(Work, Name + ".diaphora")
            WriteResultsDb(Path, NewConfig or Config, NewResults, Unmatched if NewUnmatched is None else NewUnmatched)
            return CompareFiles(OraclePath, Path)

        def GroupOf(Report, Row):
            for Group in Report["groups"]:
                if (Group["type"], Group["description"]) == (Row[0], Row[9]):
                    return Group
            return NewGroup()

        def Totals(Report):
            Out = collections.Counter()
            for Group in Report["groups"]:
                for Key in ("matched", "only_oracle", "only_native") + MISMATCH_KINDS:
                    Out[Key] += Group[Key]
            return Out

        Same = Planted("same", Results)
        Check("self-compare: L1, L2, DDL", Same["verdict"]["L1"] and Same["verdict"]["L2"] and Same["verdict"]["ok"])
        Check("self-compare: every pair matched, no mismatch",
              Totals(Same)["matched"] == len({(R[2], R[4]) for R in Results}) and
              sum(Totals(Same)[K] for K in ("only_oracle", "only_native") + MISMATCH_KINDS) == 0)

        Victim = 3  # a row with a ratio below 1 in the synthetic set
        Drop = Planted("drop", [Row for I, Row in enumerate(Results) if I != Victim])
        Check("planted drop: only_oracle 1 in its group, L1 fails",
              GroupOf(Drop, Results[Victim])["only_oracle"] == 1 and Totals(Drop)["only_oracle"] == 1 and
              not Drop["verdict"]["L1"] and Totals(Drop)["only_native"] == 0)

        Changed = [list(Row) for Row in Results]
        Old = float(Changed[Victim][6])
        Changed[Victim][6] = "%.7f" % (Old - 0.0100000 if Old > 0.5 else Old + 0.01)
        Ratio = Planted("ratio", Changed)
        Group = GroupOf(Ratio, Results[Victim])
        Check("planted ratio change: ratio 1 with |delta| 0.01, L1 fails",
              Group["ratio"] == 1 and abs(Group["max_abs_delta"] - 0.01) < 1e-9 and Totals(Ratio)["ratio"] == 1 and
              Totals(Ratio)["category"] == 0 and not Ratio["verdict"]["L1"])

        Changed = [list(Row) for Row in Results]
        Changed[Victim][0] = "best" if Changed[Victim][0] != "best" else "partial"
        Type = Planted("type", Changed)
        Check("planted type change: category 1, nothing else, L1 fails",
              GroupOf(Type, Results[Victim])["category"] == 1 and Totals(Type)["category"] == 1 and
              Totals(Type)["ratio"] == 0 and Totals(Type)["description_mismatch"] == 0 and not Type["verdict"]["L1"])

        Changed = [list(Row) for Row in Results]
        Changed[Victim][9] = "Planted description"
        Desc = Planted("description", Changed)
        Check("planted description change: description 1, L1 fails",
              GroupOf(Desc, Results[Victim])["description_mismatch"] == 1 and Totals(Desc)["description_mismatch"] == 1 and
              Totals(Desc)["category"] == 0 and not Desc["verdict"]["L1"])

        Changed = [list(Row) for Row in Results]
        Changed[Victim][3] = "planted_name"
        Changed[Victim][7] = str(int(Changed[Victim][7]) + 1)
        NameNodes = Planted("name_nodes", Changed)
        Check("planted name + nodes change: name 1, nodes 1",
              Totals(NameNodes)["name"] == 1 and Totals(NameNodes)["nodes"] == 1 and not NameNodes["verdict"]["L1"])

        Changed = [list(Row) for Row in Results]
        Changed[Victim][1] = "99999"
        Line = Planted("line", Changed)
        Check("planted line change: line 1, L1 holds, L2 fails",
              Totals(Line)["line"] == 1 and Totals(Line)["matched"] == len({(R[2], R[4]) for R in Results}) and
              Line["verdict"]["L1"] and not Line["verdict"]["L2"])

        Changed = [list(Row) for Row in Results]
        Changed[0], Changed[1] = Changed[1], Changed[0]
        Order = Planted("order", Changed)
        Check("planted order swap: order 2, L1 holds, L2 fails",
              Totals(Order)["order"] == 2 and Order["verdict"]["L1"] and not Order["verdict"]["L2"])

        Extra = [list(Row) for Row in Results] + [["partial", "00099", "7fff0000", "x", "7fff1000", "y", "0.6000000",
                                                   "1", "1", "Planted extra"]]
        Add = Planted("extra", Extra)
        Check("planted extra native row: only_native 1, L1 fails",
              Totals(Add)["only_native"] == 1 and not Add["verdict"]["L1"])

        Un = Planted("unmatched", Results, NewUnmatched=[list(Row) for Row in Unmatched[1:]])
        Check("planted unmatched drop: only_oracle 1 in unmatched, L1 fails",
              Un["unmatched"][Unmatched[0][0]]["only_oracle"] == 1 and not Un["verdict"]["L1"] and
              Un["verdict"]["results_l1"])

        Cfg = Planted("config", Results, NewConfig=[(Row[0], Row[1], "9.9", Row[3]) for Row in Config])
        Check("planted config.version change: L1 fails", not Cfg["verdict"]["L1"])
        Date = Planted("date", Results, NewConfig=[(Row[0], Row[1], Row[2], "Thu Jan  1 00:00:00 1970")
                                                   for Row in Config])
        Check("config.date differs only: L2 holds", Date["verdict"]["L2"])

        R3 = [Index for Index, Row in enumerate(Results) if Row[9] == R3_DESCRIPTION]
        if R3:
            Changed = [list(Row) for Row in Results]
            Changed[R3[0]][6] = "0.1111111"
            Tolerated = Planted("r3", Changed)
            Check("planted R3-only change: r3_only, L1 still fails",
                  Tolerated["tolerated"]["r3_only"] and not Tolerated["verdict"]["L1"])
    finally:
        shutil.rmtree(Work, ignore_errors=True)
    print("self-test: %d failure(s)" % len(Failures))
    return len(Failures)


# ----------------------------------------------------------------------------- main

def Main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    Parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    Parser.add_argument("oracle", nargs="?")
    Parser.add_argument("native", nargs="?")
    Parser.add_argument("--oracle-log")
    Parser.add_argument("--native-log")
    Parser.add_argument("--compare-config-paths", action="store_true")
    Parser.add_argument("--json")
    Parser.add_argument("--markdown")
    Parser.add_argument("--limit", type=int, default=20)
    Parser.add_argument("--quiet", action="store_true")
    Parser.add_argument("--self-test", action="store_true")
    Parser.add_argument("--file", help="with --self-test: plant the changes into a copy of this file's rows")
    Args = Parser.parse_args()
    try:
        if Args.self_test:
            return 1 if SelfTest(Args.file) else 0
        if not Args.oracle or not Args.native:
            Parser.error("two results files are required")
        Report = CompareFiles(Args.oracle, Args.native, Args.oracle_log, Args.native_log, Args.compare_config_paths,
                              Args.limit)
    except CompareError as Error:
        print("error: %s" % Error, file=sys.stderr)
        return 2
    if Args.json:
        with open(Args.json, "w", encoding="utf-8", newline="\n") as Handle:
            json.dump(Report, Handle, indent=1, ensure_ascii=False)
            Handle.write("\n")
    Text = Markdown(Report)
    if Args.markdown:
        with open(Args.markdown, "w", encoding="utf-8", newline="\n") as Handle:
            Handle.write(Text)
    if not Args.quiet:
        print(Text)
    print(Summary(Report))
    return 0 if Report["verdict"]["ok"] else 1


if __name__ == "__main__":
    sys.exit(Main())
