#!/usr/bin/env python3
"""Diaphora's baseline: port every finished oracle pair from Diaphora's OWN results and score it.

    run_baseline.py [--corpus <root>] [--dsigmatcher <exe>] [--pairs <pair> ...] [--run <n>]
                    [--out <dir>] [--port-arg=<arg> ...]

For each oracle pair whose run<n> finished validly (run.json exit code 0, the .diaphora exists, the log
says "Diffing results saved in file" and logs no timeout or traceback; plan §1.6):
  1. `dsigmatcher port <ref> <target> -o <out>/<pair>/ported.sqlite --results <oracle .diaphora>`
     (best + partial, the default; extra port flags via --port-arg);
  2. the sha256 of both exports and of the results file is checked unchanged;
  3. score_ground_truth.py against the target's truth: the O1 ground-truth TSV for a no-PDB target,
     the target export itself for a -pdb target, and the target's own names for the ELF ls sample
     ('self': those two exports have symbols on both sides, so this measures whether each match pairs
     same-named functions). PDB aliases come from pdb_aliases.py (cached under
     <corpus>/oracle/ground_truth/aliases/).
Writes <out>/baseline.json, <out>/baseline.md and per pair port.log, score.json, score.md.
The long pairs that are still running have no run.json and are listed as pending.
"""

import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import e2e_common as E  # noqa: E402
import score_ground_truth  # noqa: E402


def RunValidity(Corpus, Pair, Run):
    RunDir = os.path.join(Corpus, "oracle", "diffs", Pair, "run%d" % Run)
    Info = {}
    try:
        import json
        with open(os.path.join(RunDir, "run.json"), "r", encoding="utf-8") as Handle:
            Info = json.load(Handle)
    except (OSError, ValueError):
        return "pending (no run.json)"
    if Info.get("exit_code") != 0:
        return "invalid (exit code %s)" % Info.get("exit_code")
    if not os.path.isfile(E.OracleResults(Corpus, Pair, Run)):
        return "invalid (no .diaphora)"
    LogText = E.ReadText(os.path.join(RunDir, "diaphora.log")) if os.path.isfile(
        os.path.join(RunDir, "diaphora.log")) else ""
    if "Diffing results saved in file" not in LogText:
        return "invalid (no 'Diffing results saved in file')"
    if "Timeout with heuristic" in LogText or "Traceback (most recent call last)" in LogText:
        return "invalid (timeout or traceback logged)"
    return "ok"


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    Parser = argparse.ArgumentParser(description="Port and score Diaphora's own results on every oracle pair.")
    Parser.add_argument("--corpus")
    Parser.add_argument("--dsigmatcher")
    Parser.add_argument("--pairs", nargs="*")
    Parser.add_argument("--run", type=int, default=1)
    Parser.add_argument("--out")
    Parser.add_argument("--port-arg", action="append", default=[])
    Args = Parser.parse_args()

    Corpus = E.CorpusRoot(Args.corpus)
    Exe = E.Dsigmatcher(Args.dsigmatcher)
    Out = E.ReportDir(Corpus, "baseline", Args.out)
    Pairs = Args.pairs or sorted(os.listdir(os.path.join(Corpus, "oracle", "diffs")))
    E.Log("baseline: %d pair(s) -> %s" % (len(Pairs), Out))

    Summary = {"corpus": Corpus, "dsigmatcher": Exe, "run": Args.run, "port_args": Args.port_arg, "pairs": {}}
    Failures = 0
    for Pair in Pairs:
        Status = RunValidity(Corpus, Pair, Args.run)
        Entry = {"status": Status}
        Summary["pairs"][Pair] = Entry
        if Status != "ok":
            E.Log("%s: %s, skipped" % (Pair, Status))
            continue
        Ref, Target = E.PairSides(Corpus, Pair)
        RefPath, TargetPath = E.ExportPath(Corpus, Ref), E.ExportPath(Corpus, Target)
        Results = E.OracleResults(Corpus, Pair, Args.run)
        PairDir = os.path.join(Out, Pair)
        os.makedirs(PairDir, exist_ok=True)
        Before = {Path: E.Sha256(Path) for Path in (RefPath, TargetPath, Results)}
        Ported = os.path.join(PairDir, "ported.sqlite")
        Port = E.Port(Exe, RefPath, TargetPath, Ported, Results, Args.port_arg, os.path.join(PairDir, "port.log"))
        After = {Path: E.Sha256(Path) for Path in (RefPath, TargetPath, Results)}
        Entry.update({"ref": Ref, "target": Target, "results": Results, "results_counts": E.ResultsCounts(Results),
                      "port": Port, "inputs_unchanged": Before == After})
        if Port["exit_code"] != 0 or Before != After:
            Failures += 1
            E.Log("%s: port FAILED (exit %d, inputs unchanged %s); see %s"
                  % (Pair, Port["exit_code"], Before == After, Port["log"]))
            continue
        TruthPath, TruthKind = E.TruthFor(Corpus, Target)
        Aliases = E.AliasesFor(Corpus, Target)
        Score = score_ground_truth.Score(Ported, TruthPath, Aliases)
        Title = "%s (Diaphora run%d results, truth: %s)" % (Pair, Args.run, TruthKind)
        E.WriteJson(os.path.join(PairDir, "score.json"), Score)
        E.WriteText(os.path.join(PairDir, "score.md"), score_ground_truth.Markdown(Score, Title))
        Entry.update({"truth": TruthPath, "truth_kind": TruthKind, "aliases": Aliases,
                      "provenance": E.Provenance(Ported), "score": Score})
        E.Log("%s: applied %s, confirmed %s; %s" % (Pair, Port["summary"].get("names applied"),
                                                     Port["summary"].get("names confirmed"),
                                                     score_ground_truth.Summary(Score)))

    E.WriteJson(os.path.join(Out, "baseline.json"), Summary)
    E.WriteText(os.path.join(Out, "baseline.md"), Markdown(Summary))
    E.Log("baseline: wrote %s" % os.path.join(Out, "baseline.md"))
    return 1 if Failures else 0


def Markdown(Summary):
    Lines = ["# Diaphora baseline: port --results on Diaphora's own run%d results, scored" % Summary["run"], "",
             "- corpus: `%s`" % Summary["corpus"], "- dsigmatcher: `%s`" % Summary["dsigmatcher"],
             "- port args: %s" % (" ".join(Summary["port_args"]) or "(default: best + partial)"), "",
             "| pair | truth | rows (b/p/u/m) | applied | confirmed | kept existing | label correct / wrong / "
             "missing (of scored) | match best: ok/wrong | match partial: ok/wrong | match multimatch: ok/wrong | "
             "truth_only / ported_only |",
             "|---|---|---|---:|---:|---:|---|---|---|---|---|"]
    Details = []
    for Pair, Entry in Summary["pairs"].items():
        if "score" not in Entry:
            Lines.append("| %s | %s | | | | | | | | | |" % (Pair, Entry["status"]))
            continue
        Counts = Entry["results_counts"]["results"]
        Score = Entry["score"]
        Label = Score["label"]

        def Match(Category):
            Value = Score["match_by_category"].get(Category)
            if not Value:
                return "-"
            return "%d / %d" % (Value["correct"] + Value["correct_alias"], Value["wrong"])

        Lines.append("| %s | %s | %d/%d/%d/%d | %s | %s | %s | %d (+%d alias) / %d / %d of %d | %s | %s | %s | %d / %d |" % (
            Pair, Entry["truth_kind"], Counts.get("best", 0), Counts.get("partial", 0), Counts.get("unreliable", 0),
            Counts.get("multimatch", 0), Entry["port"]["summary"].get("names applied", "?").split(" ")[0],
            Entry["port"]["summary"].get("names confirmed", "?"),
            Entry["port"]["summary"].get("skipped existing", "?"), Label["correct"], Label["correct_alias"],
            Label["wrong"], Label["missing"], Label["total"], Match("best"), Match("partial"), Match("multimatch"),
            Score["truth_only"], Score["ported_only"]))
        Details.append(score_ground_truth.Markdown(Score, "%s (truth: %s)" % (Pair, Entry["truth_kind"])))
    Lines.append("")
    Lines.append("Label level = what the ported DB says at each address both analyses have (truth_only / ported_only "
                 "are function starts the two analyses disagree on, reported apart). Match level = every results "
                 "row, judged by whether the reference name it proposes is a truth name of the target address.")
    Lines.append("")
    return "\n".join(Lines + Details)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except E.E2eError as Error:
        print("error: %s" % Error, file=sys.stderr)
        sys.exit(2)
