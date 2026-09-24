#!/usr/bin/env python3

"""Self-test for the oracle extension tools (pdb_info.py, ground_truth.py, oracle_extend.py).

Synthetic data only, written to a temporary directory: no corpus, no IDA, no
network, no Diaphora run. Prints one line per failed check and a total.

    python -B tools/oracle/selftest_oracle_extend.py
"""

import hashlib
import json
import os
import sqlite3
import struct
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import build_oracle  # noqa: E402
import ground_truth  # noqa: E402
import oracle_extend  # noqa: E402
import pdb_info  # noqa: E402
import prepare_corpus  # noqa: E402

Checks = 0
Failures = []


def Check(Condition, Label):
    global Checks
    Checks += 1
    if not Condition:
        Failures.append(Label)
        print("FAIL: %s" % Label)


def Raises(Function, Exception_, Label):
    try:
        Function()
    except Exception_:
        Check(True, Label)
        return
    except Exception as Other:
        Check(False, "%s (raised %r)" % (Label, Other))
        return
    Check(False, "%s (did not raise)" % Label)


def Sha(Path):
    with open(Path, "rb") as Handle:
        return hashlib.sha256(Handle.read()).hexdigest()


# ----------------------------------------------------------------------------- pdb_info

def BuildMsf(Guid, InfoAge, DbiAge, BlockSize=512):
    """A minimal MSF 7.00 file: streams 0 (empty), 1 (PDB info), 2 (nil), 3 (DBI, two
    non-adjacent blocks), with the directory reached through the block map."""
    Data1, Data2, Data3, Data4 = Guid
    Info = struct.pack("<3I", 20000404, 0x12345678, InfoAge) + struct.pack("<IHH", Data1, Data2, Data3) + Data4
    Dbi = struct.pack("<iII", -1, 19990903, DbiAge) + bytes(range(256)) * 2 + b"\x00" * (600 - 12 - 512)
    Blocks = {5: Info, 6: Dbi[:BlockSize], 7: b"filler", 8: Dbi[BlockSize:]}
    Directory = struct.pack("<I", 4) + struct.pack("<4I", 0, len(Info), 0xFFFFFFFF, len(Dbi))
    Directory += struct.pack("<I", 5) + struct.pack("<2I", 6, 8)
    Blocks[4] = Directory
    Blocks[3] = struct.pack("<I", 4)
    NumBlocks = 9
    Super = pdb_info.MSF7_MAGIC + struct.pack("<6I", BlockSize, 1, NumBlocks, len(Directory), 0, 3)
    Blocks[0] = Super
    Blob = bytearray(BlockSize * NumBlocks)
    for Index, Content in Blocks.items():
        Blob[Index * BlockSize:Index * BlockSize + len(Content)] = Content
    return bytes(Blob), Dbi


def TestPdbInfo(Temp):
    Guid = (0x3B99E6AC, 0x1E88, 0x5968, bytes.fromhex("EBBCA13F4EC0C4B1"))
    Blob, Dbi = BuildMsf(Guid, 3, 1)
    Path = os.path.join(Temp, "synthetic.pdb")
    with open(Path, "wb") as Handle:
        Handle.write(Blob)
    Identity = pdb_info.ReadPdbIdentity(Path)
    Check(Identity["guid"] == "3B99E6AC1E885968EBBCA13F4EC0C4B1", "pdb_info: GUID text")
    Check(Identity["info_age"] == 3, "pdb_info: info-stream age")
    Check(Identity["dbi_age"] == 1, "pdb_info: DBI age")
    Check(Identity["info_version"] == 20000404, "pdb_info: info-stream version")
    Streams = pdb_info.ReadStreams(Blob, {2, 3})
    Check(Streams[3] == Dbi, "pdb_info: a two-block stream is reassembled from non-adjacent blocks")
    Check(Streams[2] == b"", "pdb_info: a nil stream reads as empty")
    Check(pdb_info.GuidText(1, 2, 3, b"\x00" * 7 + b"\xab") == "000000010002000300000000000000AB",
          "pdb_info: GuidText zero padding")
    Bad = os.path.join(Temp, "bad.pdb")
    with open(Bad, "wb") as Handle:
        Handle.write(b"Microsoft C/C++ program database 2.00\r\n" + Blob[40:])
    Raises(lambda: pdb_info.ReadPdbIdentity(Bad), pdb_info.PdbFormatError, "pdb_info: MSF 2.00 / bad magic refused")
    Short = os.path.join(Temp, "short.pdb")
    with open(Short, "wb") as Handle:
        Handle.write(Blob[:512 * 4])
    Raises(lambda: pdb_info.ReadPdbIdentity(Short), pdb_info.PdbFormatError, "pdb_info: truncated file refused")

    Original = prepare_corpus.ReadCodeView
    try:
        prepare_corpus.ReadCodeView = lambda _Path: {"pdb_name": "x.pdb", "guid": Identity["guid"], "age": 1,
                                                     "machine": "0x8664"}
        Check(pdb_info.MatchPe(Path, "unused.dll")["match"] is True, "pdb_info: MatchPe equal GUID and DBI age")
        prepare_corpus.ReadCodeView = lambda _Path: {"pdb_name": "x.pdb", "guid": Identity["guid"], "age": 3,
                                                     "machine": "0x8664"}
        Result = pdb_info.MatchPe(Path, "unused.dll")
        Check(Result["match"] is False and Result["age_match"] is False,
              "pdb_info: MatchPe compares the DBI age, not the info-stream age")
        prepare_corpus.ReadCodeView = lambda _Path: {"pdb_name": "x.pdb", "guid": "0" * 32, "age": 1,
                                                     "machine": "0x8664"}
        Check(pdb_info.MatchPe(Path, "unused.dll")["guid_match"] is False, "pdb_info: MatchPe GUID mismatch")
        prepare_corpus.ReadCodeView = lambda _Path: None
        Check(pdb_info.MatchPe(Path, "unused.dll")["match"] is False, "pdb_info: MatchPe without RSDS")
    finally:
        prepare_corpus.ReadCodeView = Original


# ----------------------------------------------------------------------------- ground_truth

def MakeExport(Path, Rows, Unique=True):
    Handle = sqlite3.connect(Path)
    Handle.execute("pragma journal_mode = WAL")
    Handle.execute("create table functions (id integer primary key, address text%s, name text, "
                   "mangled_function text)" % (" unique" if Unique else ""))
    Handle.executemany("insert into functions (address, name, mangled_function) values (?, ?, ?)", Rows)
    Handle.commit()
    Handle.close()


def TestGroundTruth(Temp):
    Pdb = os.path.join(Temp, "x-1-pdb.sqlite")
    NoPdb = os.path.join(Temp, "x-1-nopdb.sqlite")
    # 999 < 1000 numerically but "1000" < "999" as text: the sort must be numeric.
    MakeExport(Pdb, [("4096", "Beta", "?Beta@@YAXXZ"), ("999", "Alpha", "Alpha"),
                     ("1000", "Gamma", "Gamma"), ("6442455056", "Delta", "Delta")])
    MakeExport(NoPdb, [("1000", "Gamma", "Gamma"), ("4096", "sub_1000", "sub_1000"),
                       ("5000", "sub_1388", "sub_1388"), ("6442455056", "sub_180001010", "sub_180001010")])
    Before = (Sha(Pdb), Sha(NoPdb))
    Rows, Stats = ground_truth.Build(Pdb, NoPdb)
    Check([Row[0] for Row in Rows] == ["999", "1000", "4096", "5000", "6442455056"], "truth: numeric address order")
    Check([Row[2] for Row in Rows] == ["pdb_only", "both", "both", "nopdb_only", "both"], "truth: status per row")
    Check(Rows[0][1] == "000003e7" and Rows[4][1] == "180001010", "truth: %08x address_hex")
    Check(Rows[2][3:] == ("Beta", "?Beta@@YAXXZ", "sub_1000"), "truth: name, mangled, nopdb name")
    Check(Rows[3][3:] == ("", "", "sub_1388"), "truth: nopdb_only row has no PDB name")
    Check(Rows[0][5] == "", "truth: pdb_only row has no no-PDB name")
    Check(Stats["status_counts"] == {"both": 3, "pdb_only": 1, "nopdb_only": 1}, "truth: status counts")
    Check(Stats["both_with_identical_name"] == 1 and Stats["both_with_different_name"] == 2, "truth: same-name counts")
    Out = os.path.join(Temp, "x-1-nopdb.tsv")
    Info = ground_truth.Generate(Pdb, NoPdb, Out, Out[:-4] + ".json", {"nopdb_id": "x-1-nopdb"})
    with open(Out, "r", encoding="utf-8") as Handle:
        Text = Handle.read()
    Lines = Text.split("\n")
    Check(Lines[0] == "\t".join(ground_truth.COLUMNS), "truth: TSV header")
    Check(len(Lines) == 7 and Lines[-1] == "", "truth: one line per row plus header, LF terminated")
    Check("\r" not in Text, "truth: no CR in the TSV")
    Check(Info["nopdb_id"] == "x-1-nopdb" and Info["rows"] == 5, "truth: JSON sidecar")
    with open(Out[:-4] + ".json", "r", encoding="utf-8") as Handle:
        Check(json.load(Handle)["tsv_sha256"] == Sha(Out), "truth: sidecar records the TSV sha256")
    Check((Sha(Pdb), Sha(NoPdb)) == Before, "truth: exports unchanged by reading")
    Check(not any(os.path.exists(P + Suffix) for P in (Pdb, NoPdb) for Suffix in ("-wal", "-shm")),
          "truth: immutable read creates no -wal/-shm")
    Tab = os.path.join(Temp, "tab.sqlite")
    MakeExport(Tab, [("1", "bad\tname", "bad")])
    Raises(lambda: ground_truth.Build(Tab, NoPdb), ValueError, "truth: a tab in a name is refused")
    Dup = os.path.join(Temp, "dup.sqlite")
    MakeExport(Dup, [("1", "a", "a"), ("1", "b", "b")], Unique=False)
    Raises(lambda: ground_truth.Build(Dup, NoPdb), ValueError, "truth: duplicate address is refused")
    Null = os.path.join(Temp, "null.sqlite")
    MakeExport(Null, [(None, "a", "a")], Unique=False)
    Raises(lambda: ground_truth.Build(Null, NoPdb), ValueError, "truth: NULL address is refused")


# ----------------------------------------------------------------------------- oracle_extend

def TestSpecs():
    Base = {Spec["id"] for Spec in build_oracle.EXPORTS}
    Check(not (Base & oracle_extend.EXT_EXPORT_IDS), "specs: extension exports are new ids")
    Check(not ({P["id"] for P in build_oracle.DIFFS} & oracle_extend.EXT_PAIR_IDS), "specs: extension pairs are new ids")
    All = set(oracle_extend.AllExportIds())
    for NoPdb, Pdb in oracle_extend.TruthPairs():
        Check(Pdb in All, "specs: %s has its with-PDB export %s" % (NoPdb, Pdb))
    Expected = {"userenv-9278-nopdb", "sechost-9444-nopdb", "win32u-9444-nopdb", "cryptbase-1-nopdb",
                "cryptbase-8875-nopdb", "cryptbase-9444-nopdb"}
    Check({NoPdb for NoPdb, _ in oracle_extend.TruthPairs()} == Expected, "specs: every -nopdb export gets truth")
    for Pair in oracle_extend.EXT_DIFFS:
        Check(Pair["ref"] in All and Pair["target"] in All, "specs: %s inputs are known exports" % Pair["id"])
        Prefix = Pair["ref"].split("-")[0] + "-"
        Check(Pair["id"] == Pair["ref"] + "_vs_" + Pair["target"][len(Prefix):],
              "specs: %s follows the <ref>_vs_<target build> naming" % Pair["id"])
    Check({P["id"] for P in oracle_extend.EXT_DIFFS} == {"win32u-9168-useri64_vs_9444-nopdb",
                                                        "cryptbase-1-pdb_vs_8875-nopdb",
                                                        "cryptbase-8875-pdb_vs_9444-nopdb"},
          "specs: the three extension diffs")
    for Spec in oracle_extend.EXT_EXPORTS:
        if Spec.get("kind") != "user-i64":
            Check("{bin}/" in Spec["source"] and "{" not in Spec["source"].replace("{bin}", ""),
                  "specs: %s source uses only the {bin} placeholder" % Spec["id"])
    for Build in oracle_extend.EXT_BUILDS:
        Check(Build["label"] == "%s_%s" % (Build["file"].split(".")[0], Build["version"].replace(".", "")),
              "specs: %s label follows prepare_corpus.Label" % Build["label"])
    Count = len(build_oracle.EXPORTS)
    oracle_extend.InstallExtensionSpecs()
    oracle_extend.InstallExtensionSpecs()
    Check(len(build_oracle.EXPORTS) == Count + len(oracle_extend.EXT_EXPORTS), "specs: install is idempotent")


def TestGuards(Temp):
    Args = oracle_extend.ParseArgs(["status", "--root", os.path.join(Temp, "oracle")])
    Check(Args.win32u_dir == os.path.join(Temp, "win32u"), "args: --win32u-dir defaults to <root>/../win32u")
    Check(Args.user_i64 == os.path.join(Temp, "win32u", "win32u_100261009168", "win32u.dll.i64"),
          "args: --user-i64 default")
    Raises(lambda: oracle_extend.GuardExport(Args, "ls"), oracle_extend.Guard, "guard: base export refused")
    Raises(lambda: oracle_extend.GuardExport(Args, "unknown"), oracle_extend.Guard, "guard: unknown export refused")
    oracle_extend.GuardExport(Args, "cryptbase-1-pdb")
    Check(True, "guard: new extension export allowed")
    os.makedirs(os.path.join(Args.root, "exports", "cryptbase-1-pdb"))
    Raises(lambda: oracle_extend.GuardExport(Args, "cryptbase-1-pdb"), oracle_extend.Guard,
           "guard: existing extension export needs --force")
    Args.force = True
    oracle_extend.GuardExport(Args, "cryptbase-1-pdb")
    Check(True, "guard: --force allows a rebuild")
    Raises(lambda: oracle_extend.GuardExport(Args, "sechost-9444-nopdb"), oracle_extend.Guard,
           "guard: --force never allows a base export")
    Raises(lambda: oracle_extend.GuardPair(Args, "sechost-9168-pdb_vs_9444-nopdb"), oracle_extend.Guard,
           "guard: --force never re-runs a base pair")
    Args.force = False
    os.makedirs(os.path.join(Args.root, "diffs", "cryptbase-1-pdb_vs_8875-nopdb", "run1"))
    Raises(lambda: oracle_extend.GuardPair(Args, "cryptbase-1-pdb_vs_8875-nopdb"), oracle_extend.Guard,
           "guard: existing extension pair needs --force")
    oracle_extend.GuardPair(Args, "cryptbase-8875-pdb_vs_9444-nopdb")
    Check(True, "guard: new extension pair allowed")


def TestCorpusManifest(Temp):
    Args = oracle_extend.ParseArgs(["status", "--root", os.path.join(Temp, "oracle2")])
    os.makedirs(Args.bin_dir)
    Existing = "binary:          a\\a.dll\nlabel:           a_1\n\n"
    Path = os.path.join(Args.bin_dir, "corpus_manifest.txt")
    with open(Path, "w", encoding="utf-8", newline="") as Handle:
        Handle.write(Existing)
    Entry = {"label": "b_2", "binary": "b_2\\b.dll", "binary_sha256": "00", "pdb": "b_2\\b.pdb",
             "pdb_sha256": "11", "pdb_url": "u", "pdb_guid": "G", "pdb_age": 1}
    Check(oracle_extend.AppendCorpusManifest(Args, [Entry, dict(Entry, label="a_1")]) == ["b_2"],
          "manifest: only new labels are appended")
    Check(oracle_extend.AppendCorpusManifest(Args, [Entry]) == [], "manifest: a second append adds nothing")
    with open(Path, "r", encoding="utf-8", newline="") as Handle:
        Check(Handle.read().startswith(Existing), "manifest: existing entries are kept byte for byte")
    # prepare_corpus.py writes in text mode (platform newlines); the append does too.
    with open(Path, "r", encoding="utf-8") as Handle:
        Text = Handle.read()
    Check(Text.count("label:           b_2\n") == 1 and Text.endswith("\n\n"), "manifest: prepare_corpus format")


def TestVerdicts():
    With = {"pdb_mode": "with", "pdb_log": {"pdb_log_lines": 6, "pdb_symbols_loaded": 10},
            "pdb_evidence": {"pdb_netnode_exists": True}, "pdb_identity": {"match": True}}
    Check(oracle_extend.PdbVerdict(With) == "PDB applied", "verdict: with PDB")
    Check(oracle_extend.PdbVerdict(dict(With, pdb_identity={"match": False})).startswith("CHECK"),
          "verdict: a wrong PDB is flagged")
    Check(oracle_extend.PdbVerdict(dict(With, pdb_log={"pdb_log_lines": 0})).startswith("CHECK"),
          "verdict: with-PDB export without PDB log lines is flagged")
    Without = {"pdb_mode": "without", "pdb_log": {"pdb_log_lines": 0}, "ida_args": "-Opdb:off",
               "pdb_evidence": {"pdb_netnode_exists": False}}
    Check(oracle_extend.PdbVerdict(Without) == "no PDB", "verdict: without PDB")
    Check(oracle_extend.PdbVerdict(dict(Without, pdb_evidence={"pdb_netnode_exists": True})).startswith("CHECK"),
          "verdict: a no-PDB export with a $ pdb netnode is flagged")
    User = {"pdb_mode": "user-i64", "pdb_log": {"pdb_log_lines": 0}, "ida_args": "-Opdb:off",
            "ida_function_names": {"sub_prefixed": 0}}
    Check(oracle_extend.PdbVerdict(User).startswith("user database names"), "verdict: user database")
    Check(oracle_extend.PdbVerdict(dict(User, ida_function_names={"sub_prefixed": 3})).startswith("CHECK"),
          "verdict: user database with sub_ names is flagged")


def TestRunStateAndSummary(Temp):
    Root = os.path.join(Temp, "oracle3")
    Args = oracle_extend.ParseArgs(["summary", "--root", Root, "--diaphora-dir", os.path.join(Temp, "nodiaphora")])
    RunDir = os.path.join(Root, "diffs", "cryptbase-1-pdb_vs_8875-nopdb", "run1")
    os.makedirs(RunDir)
    Check(oracle_extend.RunState(Args, "cryptbase-1-pdb_vs_8875-nopdb", 2)["state"] == "NOT STARTED",
          "status: no log means not started")
    with open(os.path.join(RunDir, "diaphora.log"), "w", encoding="utf-8") as Handle:
        Handle.write("[D] INFO: Current results: Best 1, Partial 2, Unreliable 0\n"
                     "[D] INFO: Finding with heuristic 'Related compilation unit'\n"
                     "[D] INFO: Processed 50000 rows...\n[D] INFO: Processed 100000 rows...\n"
                     "[D] INFO: Processed 50000 rows...\n")
    State = oracle_extend.RunState(Args, "cryptbase-1-pdb_vs_8875-nopdb", 1)
    Check(State["state"].startswith("DEAD") or State["state"].startswith("UNKNOWN"),
          "status: a log without run.json or process is not reported as running")
    Check(State["current_results_checkpoints"] == 1 and State["queries_over_50k_rows_since_heuristic_start"] == 2,
          "status: checkpoints and big-query count")
    with open(os.path.join(RunDir, "run.json"), "w", encoding="utf-8") as Handle:
        json.dump({"pair": "cryptbase-1-pdb_vs_8875-nopdb", "run": 1, "exit_code": 0, "wall_seconds": 1.0,
                   "final_results": "Final results: Best 1", "results_by_type": {}, "timeouts_logged": 0}, Handle)
    Check(oracle_extend.RunState(Args, "cryptbase-1-pdb_vs_8875-nopdb", 1)["state"] == "FINISHED",
          "status: run.json with final results means finished")

    Stdout = sys.stdout
    try:
        sys.stdout = open(os.devnull, "w")
        oracle_extend.StageSummary(Args)
    finally:
        sys.stdout.close()
        sys.stdout = Stdout
    with open(os.path.join(Root, "manifest.json"), "r", encoding="utf-8") as Handle:
        Manifest = json.load(Handle)
    Check("extension" in Manifest and "win32u-9168-useri64_vs_9444-nopdb" in Manifest["diffs"],
          "summary: manifest carries base + extension pairs and the extension section")
    with open(os.path.join(Root, "ORACLE-results.md"), "r", encoding="utf-8") as Handle:
        Lines = Handle.read().rstrip("\n").split("\n")
    Check(oracle_extend.EXTENSION_MARKER in Lines, "summary: results carry the extension section")
    Check(Lines[-1].startswith("Pairs without two finished runs"), "summary: the closing line stays last")
    Check(not os.path.exists(os.path.join(Root, "extension", "summary.lock")), "summary: lock released")
    Check(not oracle_extend.ManifestStale(Args), "keeper: manifest is current right after a summary")
    Later = os.path.getmtime(os.path.join(Root, "manifest.json")) + 60
    os.utime(os.path.join(RunDir, "run.json"), (Later, Later))
    Check(oracle_extend.ManifestStale(Args), "keeper: a run.json newer than the manifest makes it stale")
    Check(oracle_extend.ExtensionPresent(Args) is False,
          "keeper: extension counted missing while extension exports have no export.json")


def TestSnapshot(Temp):
    Args = oracle_extend.ParseArgs(["status", "--root", os.path.join(Temp, "oracle4")])
    Script, Files = oracle_extend.LaunchScript(Args)
    Check(os.path.isfile(Script) and Script.startswith(os.path.join(Args.root, "extension", "tools")),
          "snapshot: detached jobs run from a copy under <root>/extension/tools")
    Check(sorted(Files) == sorted(oracle_extend.SNAPSHOT_FILES), "snapshot: every importable tool is copied")
    for Relative, Digest in Files.items():
        Check(Digest == Sha(os.path.join(os.path.dirname(HERE), *Relative.split("/"))),
              "snapshot: %s is identical to the repository file" % Relative)
    Check(oracle_extend.LaunchScript(Args)[0] == Script, "snapshot: one snapshot per process")


def Main():
    with tempfile.TemporaryDirectory() as Temp:
        TestPdbInfo(Temp)
        TestGroundTruth(Temp)
        TestSpecs()
        TestGuards(Temp)
        TestCorpusManifest(Temp)
        TestVerdicts()
        TestRunStateAndSummary(Temp)
        TestSnapshot(Temp)
    print("selftest_oracle_extend: %d checks, %d failed" % (Checks, len(Failures)))
    return 1 if Failures else 0


if __name__ == "__main__":
    sys.exit(Main())
