#!/usr/bin/env python3
"""End-to-end label chain: hop i = diff(ref_i, target_i) -> port -> ref_{i+1} (plan §7.1 D6/D8, §7.2 L11).

    run_chain.py --differ diaphora|native [--chain cryptbase]
                 [--ref <export id or .sqlite> --targets <id|path> ... [--truths <tsv|sqlite> ...]]
                 [--corpus <root>] [--diaphora-dir <dir>] [--python <exe>] [--dsigmatcher <exe>]
                 [--out <dir>] [--port-arg=<arg> ...] [--no-oracle-compare]

Presets: --chain cryptbase = cryptbase-1-pdb -> cryptbase-8875-nopdb -> cryptbase-9444-nopdb.
An id names <corpus>/oracle/exports/<id>/<id>.sqlite; a truth defaults to the target's ground truth
(e2e_common.TruthFor).

Per hop, in <out>/hop<i>/:
  1. work/: COPIES of ref_i and target_i. Diaphora opens db1 read/write (create_schema), so it never
     sees an oracle export or an earlier hop's output, only these copies.
  2. results.diaphora from the differ:
       diaphora  `<python> diaphora.py work/<ref> work/<target> -o results.diaphora`, cwd = the
                 unmodified Diaphora checkout, every DIAPHORA_* variable removed and
                 PYTHONDONTWRITEBYTECODE=1 (build_oracle.CleanEnv). The run must exit 0, save its file and
                 log no timeout or traceback (plan §1.6); the checkout's git state is checked unchanged.
       native    `dsigmatcher diff work/<ref> work/<target> -o results.diaphora` (the parity engine;
                 stub-level until its lanes land, so it may find nothing yet).
  3. ported.sqlite = `dsigmatcher port <ref_i> <target_i> -o ported.sqlite --results results.diaphora`.
     ref_1 is the original export (read without being modified); ref_{i+1} is hop i's ported.sqlite, so
     hop 2 re-feeds a ported DB as the reference and its provenance records hops = 2.
  4. score_ground_truth.py of ported.sqlite against target_i's truth.
  5. When the same (ref, target) pair has an oracle run (hop 1 of the preset), the fresh results are
     compared row for row with oracle run1, and the oracle's own PDB-reference pair for the same target
     (for hop 2: cryptbase-8875-pdb_vs_9444-nopdb) is ported and scored alongside as the control.
Writes <out>/chain.json and <out>/chain.md. Exit code 0 only when every hop diffed, ported and scored,
and every input export and the Diaphora checkout are unchanged.
"""

import argparse
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import e2e_common as E  # noqa: E402
import score_ground_truth  # noqa: E402

PRESETS = {
    "cryptbase": ("cryptbase-1-pdb", ["cryptbase-8875-nopdb", "cryptbase-9444-nopdb"]),
}


def Resolve(Corpus, Value):
    """(id, path) for an export id or a path."""
    if os.path.isfile(Value):
        return os.path.splitext(os.path.basename(Value))[0], os.path.abspath(Value)
    Path = E.ExportPath(Corpus, Value)
    if not os.path.isfile(Path):
        raise E.E2eError("no export '%s' (looked for %s)" % (Value, Path))
    return Value, Path


def FinalResultsLine(LogText):
    Match = re.search(r"Final results: Best (\d+), Partial (\d+), Unreliable (\d+), Multimatches (\d+)", LogText)
    return {"best": int(Match.group(1)), "partial": int(Match.group(2)), "unreliable": int(Match.group(3)),
            "multimatch": int(Match.group(4))} if Match else None


def RunDiaphora(Args, WorkRef, WorkTarget, Results, HopDir):
    DiaphoraDir = E.DiaphoraDir(Args.diaphora_dir)
    Before = E.GitState(DiaphoraDir)
    Command = [E.PythonExe(Args.python), "diaphora.py", WorkRef, WorkTarget, "-o", Results]
    LogPath = os.path.join(HopDir, "diaphora.log")
    Code, Wall = E.RunLogged(Command, LogPath, Cwd=DiaphoraDir, Env=E.CleanEnv())
    After = E.GitState(DiaphoraDir)
    Text = E.ReadText(LogPath)
    Info = {"command": Command, "cwd": DiaphoraDir, "exit_code": Code, "wall_seconds": Wall, "log": LogPath,
            "final_results": FinalResultsLine(Text), "saved": "Diffing results saved in file" in Text,
            "timeouts": Text.count("Timeout with heuristic"),
            "tracebacks": Text.count("Traceback (most recent call last)"),
            "cdifflib_absent": "cdifflib" in Text, "git_before": Before, "git_after": After,
            "checkout_unchanged": Before == After and not (After.get("status") or "")}
    Info["valid"] = (Code == 0 and os.path.isfile(Results) and Info["saved"] and not Info["timeouts"]
                     and not Info["tracebacks"] and Info["checkout_unchanged"])
    return Info


def RunNative(Args, WorkRef, WorkTarget, Results, HopDir):
    Command = [E.Dsigmatcher(Args.dsigmatcher), "diff", WorkRef, WorkTarget, "-o", Results]
    LogPath = os.path.join(HopDir, "diff.log")
    Code, Wall = E.RunLogged(Command, LogPath)
    Info = {"command": Command, "exit_code": Code, "wall_seconds": Wall, "log": LogPath,
            "final_results": FinalResultsLine(E.ReadText(LogPath))}
    Info["valid"] = Code == 0 and os.path.isfile(Results)
    return Info


def CompareWithOracle(Fresh, Oracle):
    FreshResults, FreshUnmatched = E.ResultsRows(Fresh)
    OracleResults, OracleUnmatched = E.ResultsRows(Oracle)
    return {"oracle": Oracle, "results_identical_in_order": FreshResults == OracleResults,
            "unmatched_identical_in_order": FreshUnmatched == OracleUnmatched,
            "fresh_rows": len(FreshResults), "oracle_rows": len(OracleResults)}


def OraclePairFor(Corpus, RefId, TargetId):
    for Pair in sorted(E.Manifest(Corpus).get("diffs", {})):
        if E.PairSides(Corpus, Pair) == (RefId, TargetId) and os.path.isfile(E.OracleResults(Corpus, Pair)):
            return Pair
    return None


def ControlFor(Corpus, TargetId):
    """The oracle pair that diffs the PDB export of the target's predecessor build against this target."""
    for Pair in sorted(E.Manifest(Corpus).get("diffs", {})):
        Ref, Target = E.PairSides(Corpus, Pair)
        if Target == TargetId and Ref.endswith("-pdb") and os.path.isfile(E.OracleResults(Corpus, Pair)):
            return Pair, Ref
    return None, None


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    Parser = argparse.ArgumentParser(description="Diff -> port -> re-feed chain over several builds, scored.")
    Parser.add_argument("--differ", choices=["diaphora", "native"], required=True)
    Parser.add_argument("--chain", choices=sorted(PRESETS))
    Parser.add_argument("--ref")
    Parser.add_argument("--targets", nargs="*")
    Parser.add_argument("--truths", nargs="*")
    Parser.add_argument("--corpus")
    Parser.add_argument("--diaphora-dir")
    Parser.add_argument("--python")
    Parser.add_argument("--dsigmatcher")
    Parser.add_argument("--out")
    Parser.add_argument("--port-arg", action="append", default=[])
    Parser.add_argument("--no-oracle-compare", action="store_true")
    Args = Parser.parse_args()

    Corpus = E.CorpusRoot(Args.corpus)
    if Args.chain:
        RefValue, TargetValues = PRESETS[Args.chain]
    elif Args.ref and Args.targets:
        RefValue, TargetValues = Args.ref, Args.targets
    else:
        Parser.error("give --chain <preset>, or --ref and --targets")
    if Args.truths and len(Args.truths) != len(TargetValues):
        Parser.error("--truths needs one entry per target")
    Exe = E.Dsigmatcher(Args.dsigmatcher)
    Name = Args.chain or "custom"
    Out = E.ReportDir(Corpus, "chain-%s-%s" % (Name, Args.differ), Args.out)
    E.Log("chain %s, differ %s -> %s" % (Name, Args.differ, Out))

    RefId, RefPath = Resolve(Corpus, RefValue)
    Inputs = {RefPath: E.Sha256(RefPath)}
    Chain = {"name": Name, "differ": Args.differ, "corpus": Corpus, "dsigmatcher": Exe, "port_args": Args.port_arg,
             "hops": []}
    Ok = True
    CurrentRefId, CurrentRefPath = RefId, RefPath
    for Index, TargetValue in enumerate(TargetValues, start=1):
        TargetId, TargetPath = Resolve(Corpus, TargetValue)
        Inputs.setdefault(TargetPath, E.Sha256(TargetPath))
        HopDir = os.path.join(Out, "hop%d" % Index)
        WorkDir = os.path.join(HopDir, "work")
        os.makedirs(WorkDir, exist_ok=True)
        Hop = {"hop": Index, "ref": CurrentRefId, "ref_path": CurrentRefPath, "target": TargetId,
               "target_path": TargetPath}
        Chain["hops"].append(Hop)

        WorkRef = os.path.join(WorkDir, "%s.sqlite" % CurrentRefId)
        WorkTarget = os.path.join(WorkDir, "%s.sqlite" % TargetId)
        E.CopyExport(CurrentRefPath, WorkRef)
        E.CopyExport(TargetPath, WorkTarget)
        Hop["work_sha256_before"] = {"ref": E.Sha256(WorkRef), "target": E.Sha256(WorkTarget)}
        Results = os.path.join(HopDir, "results.diaphora")
        E.Log("hop %d: %s(%s, %s)" % (Index, Args.differ, CurrentRefId, TargetId))
        Diff = (RunDiaphora if Args.differ == "diaphora" else RunNative)(Args, WorkRef, WorkTarget, Results, HopDir)
        Hop["diff"] = Diff
        Hop["work_sha256_after"] = {"ref": E.Sha256(WorkRef), "target": E.Sha256(WorkTarget)}
        if not Diff["valid"]:
            E.Log("hop %d: the differ failed (exit %d); see %s" % (Index, Diff["exit_code"], Diff["log"]))
            Ok = False
            break
        Hop["results_counts"] = E.ResultsCounts(Results)
        E.Log("hop %d: %s results %s" % (Index, Args.differ, Hop["results_counts"]["results"]))

        OraclePair = None if Args.no_oracle_compare else OraclePairFor(Corpus, CurrentRefId, TargetId)
        if OraclePair:
            Hop["oracle_compare"] = CompareWithOracle(Results, E.OracleResults(Corpus, OraclePair))
            E.Log("hop %d: fresh results vs oracle %s run1: identical in order %s"
                  % (Index, OraclePair, Hop["oracle_compare"]["results_identical_in_order"]))

        Ported = os.path.join(HopDir, "ported.sqlite")
        Port = E.Port(Exe, CurrentRefPath, TargetPath, Ported, Results, Args.port_arg,
                      os.path.join(HopDir, "port.log"))
        Hop["port"] = Port
        if Port["exit_code"] != 0:
            E.Log("hop %d: port failed (exit %d); see %s" % (Index, Port["exit_code"], Port["log"]))
            Ok = False
            break
        Hop["provenance"] = E.Provenance(Ported)
        TruthPath, TruthKind = ((Args.truths[Index - 1], "given") if Args.truths else E.TruthFor(Corpus, TargetId))
        Aliases = E.AliasesFor(Corpus, TargetId)
        Score = score_ground_truth.Score(Ported, TruthPath, Aliases)
        Hop.update({"truth": TruthPath, "truth_kind": TruthKind, "aliases": Aliases, "score": Score})
        E.WriteJson(os.path.join(HopDir, "score.json"), Score)
        E.WriteText(os.path.join(HopDir, "score.md"), score_ground_truth.Markdown(
            Score, "hop %d: %s -> %s (%s)" % (Index, CurrentRefId, TargetId, Args.differ)))
        E.Log("hop %d: port hop %s, applied %s; %s" % (Index, Port["summary"].get("hop"),
                                                        Port["summary"].get("names applied"),
                                                        score_ground_truth.Summary(Score)))

        if not Args.no_oracle_compare and Index > 1:
            ControlPair, ControlRef = ControlFor(Corpus, TargetId)
            if ControlPair:
                ControlDir = os.path.join(HopDir, "control-" + ControlPair)
                os.makedirs(ControlDir, exist_ok=True)
                ControlPorted = os.path.join(ControlDir, "ported.sqlite")
                ControlPort = E.Port(Exe, E.ExportPath(Corpus, ControlRef), TargetPath, ControlPorted,
                                     E.OracleResults(Corpus, ControlPair), Args.port_arg,
                                     os.path.join(ControlDir, "port.log"))
                Control = {"pair": ControlPair, "port": ControlPort}
                if ControlPort["exit_code"] == 0:
                    Control["score"] = score_ground_truth.Score(ControlPorted, TruthPath, Aliases)
                    E.WriteText(os.path.join(ControlDir, "score.md"), score_ground_truth.Markdown(
                        Control["score"], "control: %s (oracle run1, PDB reference)" % ControlPair))
                    E.Log("hop %d: control %s: %s" % (Index, ControlPair,
                                                       score_ground_truth.Summary(Control["score"])))
                Hop["control"] = Control

        CurrentRefId, CurrentRefPath = "hop%d-ported" % Index, Ported

    Chain["inputs_unchanged"] = all(E.Sha256(Path) == Digest for Path, Digest in Inputs.items())
    Chain["ok"] = Ok and Chain["inputs_unchanged"]
    E.WriteJson(os.path.join(Out, "chain.json"), Chain)
    E.WriteText(os.path.join(Out, "chain.md"), Markdown(Chain))
    E.Log("chain: ok %s, inputs unchanged %s; wrote %s" % (Chain["ok"], Chain["inputs_unchanged"],
                                                           os.path.join(Out, "chain.md")))
    return 0 if Chain["ok"] else 1


def Markdown(Chain):
    Lines = ["# Chain %s, differ %s" % (Chain["name"], Chain["differ"]), "",
             "- dsigmatcher: `%s`; port args: %s" % (Chain["dsigmatcher"], " ".join(Chain["port_args"]) or "(default)"),
             "- inputs unchanged: %s; ok: %s" % (Chain["inputs_unchanged"], Chain["ok"]), "",
             "| hop | reference | target | differ results (b/p/u/m) | vs oracle run1 | port hop | applied | "
             "confirmed | provenance hops | name_origin hops histogram | label correct / wrong / missing | "
             "match best / partial (ok/wrong) |",
             "|---:|---|---|---|---|---:|---|---:|---|---|---|---|"]
    Details = []
    for Hop in Chain["hops"]:
        Counts = Hop.get("results_counts", {}).get("results", {})
        Score = Hop.get("score")
        Compare = Hop.get("oracle_compare")
        Port = Hop.get("port", {}).get("summary", {})
        Provenance = Hop.get("provenance", {})

        def Match(Category):
            Value = Score["match_by_category"].get(Category) if Score else None
            return "%d/%d" % (Value["correct"] + Value["correct_alias"], Value["wrong"]) if Value else "-"

        Label = Score["label"] if Score else None
        Lines.append("| %d | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |" % (
            Hop["hop"], Hop["ref"], Hop["target"],
            "%d/%d/%d/%d" % (Counts.get("best", 0), Counts.get("partial", 0), Counts.get("unreliable", 0),
                             Counts.get("multimatch", 0)) if Counts else "-",
            ("identical" if Compare["results_identical_in_order"] else "DIFFERENT") if Compare else "-",
            Port.get("hop", "-"), Port.get("names applied", "-"), Port.get("names confirmed", "-"),
            ",".join(str(Entry["hop"]) for Entry in Provenance.get("hops", [])) or "-",
            Provenance.get("name_origin_hops_histogram", "-"),
            "%d (+%d alias) / %d / %d of %d" % (Label["correct"], Label["correct_alias"], Label["wrong"],
                                                Label["missing"], Label["total"]) if Label else "-",
            "%s / %s" % (Match("best"), Match("partial"))))
        if Score:
            Details.append(score_ground_truth.Markdown(Score, "hop %d: %s -> %s" % (Hop["hop"], Hop["ref"],
                                                                                    Hop["target"])))
        Control = Hop.get("control")
        if Control and Control.get("score"):
            ControlLabel = Control["score"]["label"]
            Lines.append("| %d (control) | oracle %s | %s | | | | %s | %s | | | %d (+%d alias) / %d / %d of %d | |" % (
                Hop["hop"], Control["pair"], Hop["target"], Control["port"]["summary"].get("names applied", "-"),
                Control["port"]["summary"].get("names confirmed", "-"), ControlLabel["correct"],
                ControlLabel["correct_alias"], ControlLabel["wrong"], ControlLabel["missing"], ControlLabel["total"]))
            Details.append(score_ground_truth.Markdown(Control["score"], "hop %d control: %s (PDB reference)" % (
                Hop["hop"], Control["pair"])))
    Lines.append("")
    return "\n".join(Lines + Details)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except E.E2eError as Error:
        print("error: %s" % Error, file=sys.stderr)
        sys.exit(2)
