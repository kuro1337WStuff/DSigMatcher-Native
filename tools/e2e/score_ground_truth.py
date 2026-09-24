#!/usr/bin/env python3
"""Score a ported database against the PDB ground truth of the same build.

    score_ground_truth.py <ported.sqlite> <truth> [--aliases <tsv>] [--json <out>] [--markdown <out>]
                          [--title <text>] [--samples <n>]

<truth> is either
  * a ground-truth TSV written by tools/oracle/ground_truth.py (<corpus>/oracle/ground_truth/<id>.tsv:
    address, address_hex, status, name, mangled_function, nopdb_name), or
  * a Diaphora export of the same build analysed WITH its PDB (functions.address/name/mangled_function).
<ported.sqlite> is a `dsigmatcher port` output (any Diaphora export works; without the dsig_* tables
only the label-level score is available).

Everything joins on the function start address (functions.address, decimal text, parsed to int).

Aliases. A PDB can name one address several times (win32u: a Zw* alias on every Nt* stub, and several
publics folded onto 0x180001010). A label is correct when it names ANY symbol the PDB has at that
address: the truth row's name / mangled_function, or a symbol from the alias TSV of
tools/e2e/pdb_aliases.py. dbghelp strips one leading underscore from public names and returns C++
names undecorated, so a label is also compared, against the alias symbols only, with one leading '_'
removed and (on Windows, through dbghelp) with its mangled name undecorated. Correct-by-alias counts
are reported separately. --aliases defaults to <truth dir>/aliases/<build>.tsv for a ground-truth TSV,
or <corpus>/oracle/ground_truth/aliases/<build>.tsv for a <corpus>/oracle/exports/<build>-pdb export.

Function starts the two analyses disagree on are never mixed into the score:
  truth_only   truth addresses that are not functions of the ported DB (the ground-truth TSV's pdb_only
               rows when the ported DB is a no-PDB analysis: userenv 41, sechost 16);
  ported_only  functions of the ported DB with no truth row (the TSV's nopdb_only rows: userenv 6).
Truth rows whose own name is not a real symbol (sub_..., as in the ELF ls sample used as its own
truth) are not scorable either and are counted as truth_unnamed.

Two scores are reported.
  Label level: what the ported DB now says at every scored address. Source 'ported' (a name this port
    applied, by category and heuristic description, from dsig_port_log), 'confirmed' (the target
    already had the proposed name), 'target' (the target's own name, no proposal agreed with it) or
    'none' (no real name). Verdict correct / wrong, or missing when the address has no real name.
    Every missing address gets the reason the port left it unnamed.
  Match level: every results row the port read (dsig_port_log, all categories, applied or not),
    judged by whether the REFERENCE name it proposes is a truth name of the TARGET address. This is
    the accuracy of the diff itself (Diaphora's baseline when the results came from Diaphora),
    independent of what the port was allowed to write. Rows whose reference name is not a real
    symbol are 'no_name'; rows on ported_only addresses are 'no_truth'.
"""

import argparse
import collections
import ctypes
import json
import os
import sqlite3
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import pdb_aliases  # noqa: E402

SELECTED_BY_DEFAULT = ("best", "partial")
CATEGORY_ORDER = ["best", "partial", "unreliable", "multimatch"]


def IsPortable(Name):
    """Naming.h IsPortableSymbol: a real name, not IDA's sub_/nullsub placeholder."""
    return bool(Name) and not Name.startswith("sub_") and not Name.startswith("nullsub") and Name != "..."


def ReadOnlyUri(Path):
    Normal = os.path.abspath(Path).replace("\\", "/").replace("%", "%25").replace("?", "%3f").replace("#", "%23")
    if len(Normal) >= 2 and Normal[1] == ":":
        Normal = "/" + Normal
    # immutable=1: never create -wal/-shm beside an oracle export (they are opened read-only).
    Immutable = not (os.path.isfile(Path + "-wal") and os.path.getsize(Path + "-wal") > 0)
    return "file:%s?mode=ro%s" % (Normal, "&immutable=1" if Immutable else "")


def Connect(Path):
    return sqlite3.connect(ReadOnlyUri(Path), uri=True)


def TableExists(Db, Name):
    return Db.execute("select 1 from sqlite_master where type = 'table' and name = ?", (Name,)).fetchone() is not None


class Undecorator:
    """dbghelp UnDecorateSymbolName(UNDNAME_NAME_ONLY), when available (Windows)."""

    def __init__(self):
        self.Function = None
        self.Cache = {}
        if os.name == "nt":
            try:
                from ctypes import wintypes
                DbgHelp = ctypes.WinDLL("dbghelp")
                DbgHelp.UnDecorateSymbolName.restype = wintypes.DWORD
                DbgHelp.UnDecorateSymbolName.argtypes = [ctypes.c_char_p, ctypes.c_char_p, wintypes.DWORD,
                                                         wintypes.DWORD]
                self.Function = DbgHelp.UnDecorateSymbolName
                self.Buffer = ctypes.create_string_buffer(4096)
            except (OSError, AttributeError):
                self.Function = None

    def __call__(self, Name):
        if not Name or not Name.startswith("?") or self.Function is None:
            return None
        if Name not in self.Cache:
            Length = self.Function(Name.encode("utf-8"), self.Buffer, len(self.Buffer), pdb_aliases.UNDNAME_NAME_ONLY)
            self.Cache[Name] = self.Buffer.value.decode("utf-8", "replace") if Length else None
        return self.Cache[Name]


UNDECORATE = Undecorator()


def LabelKeys(Name, Mangled):
    """Spellings of one label to look up among the alias symbols (dbghelp's spellings)."""
    Keys = set()
    for Value in (Name, Mangled):
        if Value:
            Keys.add(Value)
            if Value.startswith("_"):
                Keys.add(Value[1:])
    Undecorated = UNDECORATE(Mangled)
    if Undecorated:
        Keys.add(Undecorated)
    return Keys


class Truth:
    def __init__(self, Path, AliasPath):
        self.Path = Path
        self.AliasPath = AliasPath
        self.Names = {}        # ea -> (name, mangled), real names only
        self.Unnamed = set()   # truth rows whose name is not a real symbol (sub_...): not scorable
        self.TsvStatus = {}    # ea -> status (TSV truth only)
        self.Kind = None
        if Path.lower().endswith(".tsv"):
            self.Kind = "tsv"
            with open(Path, "r", encoding="utf-8") as Handle:
                Header = Handle.readline().rstrip("\n").split("\t")
                Index = {Name: Position for Position, Name in enumerate(Header)}
                for Required in ("address", "status", "name", "mangled_function"):
                    if Required not in Index:
                        raise ValueError("%s: no '%s' column" % (Path, Required))
                for Line in Handle:
                    Parts = Line.rstrip("\n").split("\t")
                    Ea = int(Parts[Index["address"]])
                    Status = Parts[Index["status"]]
                    self.TsvStatus[Ea] = Status
                    if Status in ("both", "pdb_only"):
                        self.Add(Ea, Parts[Index["name"]], Parts[Index["mangled_function"]])
        else:
            self.Kind = "export"
            Db = Connect(Path)
            for Address, Name, Mangled in Db.execute("select address, name, mangled_function from functions"):
                self.Add(int(Address), Name, Mangled)
            Db.close()
        self.Aliases = pdb_aliases.LoadAliases(AliasPath) if AliasPath else {}

    def Add(self, Ea, Name, Mangled):
        if IsPortable(Name) or IsPortable(Mangled):
            self.Names[Ea] = (Name, Mangled)
        else:
            self.Unnamed.add(Ea)

    def Judge(self, Ea, Name, Mangled):
        """'correct', 'correct_alias' or 'wrong' for a real label at a truth address."""
        TruthName, TruthMangled = self.Names[Ea]
        Exact = {Value for Value in (TruthName, TruthMangled) if Value}
        if Name in Exact or Mangled in Exact:
            return "correct"
        Symbols = self.Aliases.get(Ea)
        if Symbols and LabelKeys(Name, Mangled) & Symbols:
            return "correct_alias"
        return "wrong"


def DefaultAliasPath(TruthPath):
    Directory, File = os.path.split(os.path.abspath(TruthPath))
    Stem = File.rsplit(".", 1)[0]
    for Suffix in ("-nopdb", "-pdb"):
        if Stem.endswith(Suffix):
            Build = Stem[: -len(Suffix)]
            break
    else:
        return None
    if File.lower().endswith(".tsv"):
        Candidate = os.path.join(Directory, "aliases", Build + ".tsv")
    else:
        # <corpus>/oracle/exports/<id>/<id>.sqlite -> <corpus>/oracle/ground_truth/aliases/<build>.tsv
        Oracle = os.path.dirname(os.path.dirname(Directory))
        Candidate = os.path.join(Oracle, "ground_truth", "aliases", Build + ".tsv")
    return Candidate if os.path.isfile(Candidate) else None


def NewCounts():
    return collections.OrderedDict((Key, 0) for Key in ("correct", "correct_alias", "wrong", "missing"))


def Finish(Counts):
    Right = Counts.get("correct", 0) + Counts.get("correct_alias", 0)
    Named = Right + Counts.get("wrong", 0)
    Total = Named + Counts.get("missing", 0)
    Counts["total"] = Total
    Counts["precision"] = round(Right / Named, 4) if Named else None
    Counts["recall"] = round(Right / Total, 4) if Total else None
    return Counts


def Score(PortedPath, TruthPath, AliasPath=None, Samples=15):
    if AliasPath is None:
        AliasPath = DefaultAliasPath(TruthPath)
    TruthData = Truth(TruthPath, AliasPath)

    Db = Connect(PortedPath)
    Functions = {}
    for Address, Name, Mangled in Db.execute("select address, name, mangled_function from functions"):
        Functions[int(Address)] = (Address, Name, Mangled)
    Log = []
    if TableExists(Db, "dsig_port_log"):
        Columns = ["hop", "results_rowid", "type", "line", "description", "ratio", "address", "ref_address",
                   "ref_name", "ref_mangled", "name_before", "mangled_before", "confidence", "hops", "action"]
        for Row in Db.execute("select %s from dsig_port_log order by hop, results_rowid" % ", ".join(Columns)):
            Log.append(dict(zip(Columns, Row)))
    Origins = {}
    if TableExists(Db, "dsig_name_origin"):
        for Address, Heuristic, Hops in Db.execute("select address, heuristic, hops from dsig_name_origin"):
            Origins[int(Address)] = (Heuristic, Hops)
    Hops = []
    if TableExists(Db, "dsig_provenance"):
        Hops = [Row[0] for Row in Db.execute("select hop from dsig_provenance order by hop")]
    Db.close()

    LogByEa = collections.defaultdict(list)
    for Entry in Log:
        LogByEa[int(Entry["address"])].append(Entry)

    Ported = set(Functions)
    TruthEas = set(TruthData.Names)
    Scored = sorted(Ported & TruthEas)
    TruthOnly = sorted(TruthEas - Ported)
    PortedOnly = sorted(Ported - TruthEas - TruthData.Unnamed)

    # ---- label level
    LabelTotal = NewCounts()
    BySource = collections.OrderedDict()
    ByDescription = collections.OrderedDict()
    MissingReasons = collections.Counter()
    WrongSamples = []
    for Ea in Scored:
        _, Name, Mangled = Functions[Ea]
        Entries = LogByEa.get(Ea, [])
        Applied = next((Entry for Entry in Entries if Entry["action"] == "applied"), None)
        Confirmed = next((Entry for Entry in Entries if Entry["action"] == "confirmed"), None)
        if Applied is not None:
            Source, Key = "ported", (Applied["type"], Applied["description"])
        elif Ea in Origins:
            Source, Key = "ported-earlier", ("-", Origins[Ea][0])
        elif not IsPortable(Name):
            Source, Key = "none", None
        elif Confirmed is not None:
            Source, Key = "confirmed", (Confirmed["type"], Confirmed["description"])
        else:
            Source, Key = "target", None
        if IsPortable(Name):
            Verdict = TruthData.Judge(Ea, Name, Mangled)
        else:
            Verdict = "missing"
            Selected = [Entry for Entry in Entries if Entry["action"] != "not_selected"]
            if Selected:
                MissingReasons[Selected[0]["action"]] += 1
            elif Entries:
                MissingReasons["not_selected:" + Entries[0]["type"]] += 1
            else:
                MissingReasons["no_match"] += 1
        LabelTotal[Verdict] += 1
        SourceKey = Source if Key is None else "%s:%s" % (Source, Key[0])
        BySource.setdefault(SourceKey, NewCounts())[Verdict] += 1
        if Key is not None:
            ByDescription.setdefault("%s | %s | %s" % (Source, Key[0], Key[1]), NewCounts())[Verdict] += 1
        if Verdict == "wrong" and len(WrongSamples) < Samples:
            WrongSamples.append({"address": "%08x" % Ea, "label": Name, "label_mangled": Mangled,
                                 "truth": TruthData.Names[Ea][0], "truth_mangled": TruthData.Names[Ea][1],
                                 "source": SourceKey, "description": Key[1] if Key else None})

    # ---- match level
    MatchByCategory = collections.OrderedDict()
    MatchByDescription = collections.OrderedDict()
    MatchByAction = collections.OrderedDict()
    MatchSamples = []
    for Entry in Log:
        Ea = int(Entry["address"])
        if Ea not in TruthData.Names:
            Verdict = "no_truth"
        elif not IsPortable(Entry["ref_name"]):
            Verdict = "no_name"
        else:
            Verdict = TruthData.Judge(Ea, Entry["ref_name"], Entry["ref_mangled"])
        for Table, Key in ((MatchByCategory, Entry["type"]),
                           (MatchByDescription, "%s | %s" % (Entry["type"], Entry["description"])),
                           (MatchByAction, Entry["action"])):
            Counts = Table.setdefault(Key, collections.OrderedDict(
                (Name, 0) for Name in ("correct", "correct_alias", "wrong", "no_name", "no_truth")))
            Counts[Verdict] += 1
        if Verdict == "wrong" and len(MatchSamples) < Samples:
            MatchSamples.append({"address": "%08x" % Ea, "type": Entry["type"], "description": Entry["description"],
                                 "ratio": Entry["ratio"], "proposed": Entry["ref_name"],
                                 "truth": TruthData.Names[Ea][0], "action": Entry["action"]})
    for Table in (MatchByCategory, MatchByDescription, MatchByAction):
        for Counts in Table.values():
            Right = Counts["correct"] + Counts["correct_alias"]
            Judged = Right + Counts["wrong"]
            Counts["precision"] = round(Right / Judged, 4) if Judged else None
    MatchedAddresses = {int(Entry["address"]) for Entry in Log if Entry["type"] in SELECTED_BY_DEFAULT}
    AnyAddresses = {int(Entry["address"]) for Entry in Log}
    ScoredSet = set(Scored)

    TsvStatus = collections.Counter(TruthData.TsvStatus.values()) if TruthData.TsvStatus else None
    Report = collections.OrderedDict()
    Report["ported"] = os.path.abspath(PortedPath)
    Report["truth"] = os.path.abspath(TruthPath)
    Report["truth_kind"] = TruthData.Kind
    Report["aliases"] = os.path.abspath(AliasPath) if AliasPath else None
    Report["alias_addresses"] = len(TruthData.Aliases)
    Report["undecorator"] = UNDECORATE.Function is not None
    Report["hops_recorded"] = Hops
    Report["port_log_rows"] = len(Log)
    Report["functions_ported_db"] = len(Ported)
    Report["truth_named_addresses"] = len(TruthEas)
    Report["truth_unnamed"] = len(TruthData.Unnamed)
    Report["scored_addresses"] = len(Scored)
    Report["truth_only"] = len(TruthOnly)
    Report["ported_only"] = len(PortedOnly)
    Report["truth_tsv_status"] = dict(TsvStatus) if TsvStatus else None
    Report["ported_only_labelled_by_port"] = sum(
        1 for Ea in PortedOnly if any(Entry["action"] == "applied" for Entry in LogByEa.get(Ea, [])))
    Report["label"] = Finish(LabelTotal)
    Report["label_by_source"] = {Key: Finish(Value) for Key, Value in BySource.items()}
    Report["label_by_description"] = {Key: Finish(Value) for Key, Value in ByDescription.items()}
    Report["missing_reasons"] = dict(MissingReasons.most_common())
    Report["match_by_category"] = MatchByCategory
    Report["match_by_description"] = MatchByDescription
    Report["match_by_action"] = MatchByAction
    Report["unmatched_scored_addresses"] = {
        "no_best_or_partial_row": len(ScoredSet - MatchedAddresses),
        "no_row_at_all": len(ScoredSet - AnyAddresses),
    }
    Report["truth_only_sample"] = ["%08x" % Ea for Ea in TruthOnly[:Samples]]
    Report["ported_only_sample"] = ["%08x" % Ea for Ea in PortedOnly[:Samples]]
    Report["wrong_label_samples"] = WrongSamples
    Report["wrong_match_samples"] = MatchSamples
    return Report


def Pct(Value):
    return "-" if Value is None else "%.1f%%" % (100.0 * Value)


def Markdown(Report, Title=None):
    Lines = []
    Lines.append("## %s" % (Title or os.path.basename(Report["ported"])))
    Lines.append("")
    Lines.append("- ported: `%s`" % Report["ported"])
    Lines.append("- truth: `%s` (%s); aliases: `%s` (%d addresses)"
                 % (Report["truth"], Report["truth_kind"], Report["aliases"], Report["alias_addresses"]))
    Lines.append("- hops recorded: %s; port log rows: %d" % (Report["hops_recorded"], Report["port_log_rows"]))
    Lines.append("- functions: ported DB %d, truth %d named (+%d without a real name, not scored), scored %d; "
                 "truth_only %d, ported_only %d (ported_only labelled by this port: %d)"
                 % (Report["functions_ported_db"], Report["truth_named_addresses"], Report["truth_unnamed"],
                    Report["scored_addresses"], Report["truth_only"], Report["ported_only"],
                    Report["ported_only_labelled_by_port"]))
    if Report["truth_tsv_status"]:
        Lines.append("- truth TSV status counts: %s" % ", ".join(
            "%s %d" % Item for Item in sorted(Report["truth_tsv_status"].items())))
    Label = Report["label"]
    Lines.append("")
    Lines.append("**Label level** (scored addresses): correct %d (+%d by alias), wrong %d, missing %d of %d; "
                 "precision %s, recall %s" % (Label["correct"], Label["correct_alias"], Label["wrong"],
                                                Label["missing"], Label["total"], Pct(Label["precision"]),
                                                Pct(Label["recall"])))
    Lines.append("")
    Lines.append("| source | correct | by alias | wrong | missing | total | precision |")
    Lines.append("|---|---:|---:|---:|---:|---:|---:|")
    for Key, Counts in Report["label_by_source"].items():
        Lines.append("| %s | %d | %d | %d | %d | %d | %s |" % (Key, Counts["correct"], Counts["correct_alias"],
                                                             Counts["wrong"], Counts["missing"], Counts["total"],
                                                             Pct(Counts["precision"])))
    if Report["label_by_description"]:
        Lines.append("")
        Lines.append("| source \\| category \\| description | correct | by alias | wrong | total |")
        Lines.append("|---|---:|---:|---:|---:|")
        for Key, Counts in Report["label_by_description"].items():
            Lines.append("| %s | %d | %d | %d | %d |" % (Key.replace("|", "\\|"), Counts["correct"],
                                                        Counts["correct_alias"], Counts["wrong"], Counts["total"]))
    if Report["missing_reasons"]:
        Lines.append("")
        Lines.append("Missing (no real name at a scored address), by reason: " + ", ".join(
            "%s %d" % Item for Item in Report["missing_reasons"].items()))
    Lines.append("")
    Lines.append("**Match level** (every results row, reference name judged against the target's truth):")
    Lines.append("")
    Lines.append("| category | correct | by alias | wrong | no_name | no_truth | precision |")
    Lines.append("|---|---:|---:|---:|---:|---:|---:|")
    for Key in sorted(Report["match_by_category"], key=lambda K: CATEGORY_ORDER.index(K) if K in CATEGORY_ORDER else 9):
        Counts = Report["match_by_category"][Key]
        Lines.append("| %s | %d | %d | %d | %d | %d | %s |" % (Key, Counts["correct"], Counts["correct_alias"],
                                                             Counts["wrong"], Counts["no_name"], Counts["no_truth"],
                                                             Pct(Counts["precision"])))
    Lines.append("")
    Lines.append("| category \\| description | correct | by alias | wrong | no_name | no_truth | precision |")
    Lines.append("|---|---:|---:|---:|---:|---:|---:|")
    for Key, Counts in Report["match_by_description"].items():
        Lines.append("| %s | %d | %d | %d | %d | %d | %s |" % (Key.replace("|", "\\|"), Counts["correct"],
                                                             Counts["correct_alias"], Counts["wrong"],
                                                             Counts["no_name"], Counts["no_truth"],
                                                             Pct(Counts["precision"])))
    Lines.append("")
    Lines.append("| port action | correct | by alias | wrong | no_name | no_truth |")
    Lines.append("|---|---:|---:|---:|---:|---:|")
    for Key, Counts in Report["match_by_action"].items():
        Lines.append("| %s | %d | %d | %d | %d | %d |" % (Key, Counts["correct"], Counts["correct_alias"],
                                                        Counts["wrong"], Counts["no_name"], Counts["no_truth"]))
    Unmatched = Report["unmatched_scored_addresses"]
    Lines.append("")
    Lines.append("Scored addresses with no best/partial row: %d (no row of any category: %d)."
                 % (Unmatched["no_best_or_partial_row"], Unmatched["no_row_at_all"]))
    if Report["wrong_label_samples"]:
        Lines.append("")
        Lines.append("Wrong labels (sample):")
        Lines.append("")
        for Sample in Report["wrong_label_samples"]:
            Lines.append("- `%s` label `%s`, truth `%s` (%s%s)" % (
                Sample["address"], Sample["label"], Sample["truth"], Sample["source"],
                ", " + Sample["description"] if Sample["description"] else ""))
    if Report["wrong_match_samples"]:
        Lines.append("")
        Lines.append("Wrong matches (sample):")
        Lines.append("")
        for Sample in Report["wrong_match_samples"]:
            Lines.append("- `%s` %s %s %s: proposed `%s`, truth `%s` (%s)" % (
                Sample["address"], Sample["type"], Sample["ratio"], Sample["description"], Sample["proposed"],
                Sample["truth"], Sample["action"]))
    Lines.append("")
    return "\n".join(Lines)


def Summary(Report):
    Label = Report["label"]
    Parts = ["label: correct %d (+%d alias) wrong %d missing %d / %d" % (
        Label["correct"], Label["correct_alias"], Label["wrong"], Label["missing"], Label["total"])]
    for Key in CATEGORY_ORDER:
        if Key in Report["match_by_category"]:
            Counts = Report["match_by_category"][Key]
            Parts.append("%s %d/%d/%d" % (Key, Counts["correct"] + Counts["correct_alias"], Counts["wrong"],
                                          Counts["no_name"] + Counts["no_truth"]))
    Parts.append("truth_only %d ported_only %d" % (Report["truth_only"], Report["ported_only"]))
    return "; ".join(Parts)


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    Parser = argparse.ArgumentParser(description="Score a ported DB against PDB ground truth.")
    Parser.add_argument("ported")
    Parser.add_argument("truth")
    Parser.add_argument("--aliases")
    Parser.add_argument("--json")
    Parser.add_argument("--markdown")
    Parser.add_argument("--title")
    Parser.add_argument("--samples", type=int, default=15)
    Args = Parser.parse_args()
    Report = Score(Args.ported, Args.truth, Args.aliases, Args.samples)
    if Args.json:
        with open(Args.json, "w", encoding="utf-8", newline="\n") as Handle:
            json.dump(Report, Handle, indent=2)
            Handle.write("\n")
    Text = Markdown(Report, Args.title)
    if Args.markdown:
        with open(Args.markdown, "w", encoding="utf-8", newline="\n") as Handle:
            Handle.write(Text)
    print(Text)
    print(Summary(Report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
