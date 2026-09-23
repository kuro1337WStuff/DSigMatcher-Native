#!/usr/bin/env python3

"""Instrumented run of unmodified Diaphora: trace events and state snapshots.

Implements docs/parity/00-plan.md §2.3 and Appendix B. The Diaphora checkout is
imported read-only and never edited. Methods of the live `CBinDiff` object are
wrapped at run time; every wrapper calls the original with the original
arguments and returns its result. Nothing is short-circuited.

Subcommands:

  run       one instrumented diff of one oracle pair (copies of the exports)
  selftest  run the finished pairs twice, diff the captures, check them against
            the oracle and against 06 V3 (plan §4 L0b acceptance)
  status    list the captures under <corpus>/oracle/traces and whether they run

Paths come from flags or the environment, never from this file:
  --corpus        (env DSIG_CORPUS_ROOT)   the corpus root; the oracle is <corpus>/oracle
  --diaphora-dir  (env DSIG_DIAPHORA_DIR)  the unmodified Diaphora checkout

Example:
  python -B oracle_trace.py run --pair ls-old_vs_ls --rows
  python -B oracle_trace.py run --pair sechost-9168-pdb_vs_9444-nopdb \\
      --stop-at after:find_related_compilation_unit:0 --detach
"""

import sys

# Must happen before anything is imported from the Diaphora checkout, so that
# no __pycache__ directory is ever written there (plan §2.3).
sys.dont_write_bytecode = True

import argparse
import hashlib
import inspect
import io
import json
import os
import shutil
import subprocess
import threading
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import snapshot as Snap  # noqa: E402

# Stored-order cleanup sites of the default run (plan Appendix B, 06 V3). They
# are recorded as observed; this table only drives the selftest expectations.
V3_CLEANUP_COUNTS = {3655: 3, 3217: 3, 3185: 8, 3471: 3, 3413: 3, 3340: 3, 3671: 3, 2945: 1, 1551: 2}
V3_OUTER_TOTALS = [206, 287, 291, 291]
V3_ONE_MATCH_DIFFING = {"assembly": 716, "pseudocode": 426}

# The four heuristic entry points (D:1950, D:1977, D:2002, D:2039).
HEURISTIC_WRAPPERS = ("add_matches_from_query_ratio", "add_matches_from_query_ratio_max",
                      "add_matches_from_query_ratio_max_trusted", "add_matches_from_query")

STATUS_RUNNING = "running"
EXIT_OK, EXIT_FAIL, EXIT_USAGE, EXIT_DIAPHORA_ABORT = 0, 1, 2, 3


class StopCapture(BaseException):
    """Raised at the --stop-at point. A BaseException so that no `except
    Exception` between the point and our runner can swallow it."""


_MISSING = object()


# ----------------------------------------------------------------------------- small helpers

def Now():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def Sha256OfFile(Path):
    Digest = hashlib.sha256()
    with open(Path, "rb") as Handle:
        for Chunk in iter(lambda: Handle.read(1024 * 1024), b""):
            Digest.update(Chunk)
    return Digest.hexdigest()


def Say(Message):
    """Our own progress lines. They go to the process's original stderr, never
    into diaphora.log, so that log stays comparable with the oracle's."""
    Stream = sys.__stderr__ or sys.stderr
    try:
        Stream.write("[oracle_trace %s] %s\n" % (Now(), Message))
        Stream.flush()
    except Exception:
        pass


def Git(DiaphoraDir, *Args):
    try:
        return subprocess.run(["git", "-C", DiaphoraDir] + list(Args), capture_output=True, text=True,
                              check=True).stdout
    except Exception as Exc:
        return "ERROR: %s" % Exc


def ReferenceState(DiaphoraDir):
    """git describe/status plus (size, mtime) of every file outside .git,
    ignored files included, so that any write into the checkout (for example a
    new __pycache__ entry) is detected, not only tracked-file edits."""
    Files = {}
    for Root, Dirs, Names in os.walk(DiaphoraDir):
        Dirs[:] = [D for D in Dirs if D != ".git"]
        for Name in Names:
            Path = os.path.join(Root, Name)
            try:
                Info = os.stat(Path)
            except OSError:
                continue
            Files[os.path.relpath(Path, DiaphoraDir).replace("\\", "/")] = [Info.st_size, Info.st_mtime_ns]
    return {"describe": Git(DiaphoraDir, "describe", "--tags", "--long", "--dirty").strip(),
            "status_porcelain": Git(DiaphoraDir, "status", "--porcelain").strip(),
            "files": Files}


def CompareReferenceStates(Before, After):
    Changed = sorted(K for K in set(Before["files"]) | set(After["files"])
                     if Before["files"].get(K) != After["files"].get(K))
    return {"describe_before": Before["describe"], "describe_after": After["describe"],
            "git_status_clean_before": Before["status_porcelain"] == "",
            "git_status_clean_after": After["status_porcelain"] == "",
            "files_checked": len(After["files"]), "files_changed": Changed,
            "unchanged": Before["status_porcelain"] == "" and After["status_porcelain"] == ""
            and not Changed and Before["describe"] == After["describe"]}


def ProcessAlive(Pid):
    """Portable liveness check. On Windows os.kill(pid, 0) would *terminate*
    the process, so use OpenProcess/GetExitCodeProcess instead."""
    if not Pid:
        return False
    if os.name == "nt":
        import ctypes
        Kernel = ctypes.windll.kernel32
        Handle = Kernel.OpenProcess(0x1000, False, int(Pid))  # PROCESS_QUERY_LIMITED_INFORMATION
        if not Handle:
            return False
        try:
            Code = ctypes.c_ulong()
            if not Kernel.GetExitCodeProcess(Handle, ctypes.byref(Code)):
                return False
            return Code.value == 259  # STILL_ACTIVE
        finally:
            Kernel.CloseHandle(Handle)
    try:
        os.kill(int(Pid), 0)
        return True
    except OSError:
        return False


class Tee(io.TextIOBase):
    """Duplicates Diaphora's stdout/stderr into diaphora.log (UTF-8)."""

    def __init__(self, Primary, LogHandle, Lock):
        self.Primary = Primary
        self.LogHandle = LogHandle
        self.Lock = Lock

    @property
    def encoding(self):
        return "utf-8"

    def writable(self):
        return True

    def isatty(self):
        return False

    def write(self, Text):
        with self.Lock:
            try:
                self.LogHandle.write(Text)
                if "\n" in Text:
                    self.LogHandle.flush()
            except Exception:
                pass
            if self.Primary is not None:
                try:
                    self.Primary.write(Text)
                except UnicodeEncodeError:
                    self.Primary.write(Text.encode("ascii", "backslashreplace").decode("ascii"))
                except Exception:
                    pass
        return len(Text)

    def flush(self):
        with self.Lock:
            for Stream in (self.LogHandle, self.Primary):
                try:
                    if Stream is not None:
                        Stream.flush()
                except Exception:
                    pass


# ----------------------------------------------------------------------------- corpus

class Corpus:
    def __init__(self, Root):
        self.Root = os.path.abspath(Root)
        self.Oracle = os.path.join(self.Root, "oracle")
        self.ManifestPath = os.path.join(self.Oracle, "manifest.json")
        if not os.path.isfile(self.ManifestPath):
            raise SystemExit("no oracle manifest at %s" % self.ManifestPath)
        self.Manifest = Snap.ReadJson(self.ManifestPath)
        self.Traces = os.path.join(self.Oracle, "traces")

    def Pairs(self):
        return list(self.Manifest.get("diffs", {}).keys())

    def Pair(self, PairId):
        Diffs = self.Manifest.get("diffs", {})
        if PairId not in Diffs:
            raise SystemExit("unknown pair %r; known: %s" % (PairId, ", ".join(Diffs)))
        return Diffs[PairId]

    def Export(self, ExportId):
        Path = os.path.join(self.Oracle, "exports", ExportId, ExportId + ".sqlite")
        Sha = self.Manifest.get("exports", {}).get(ExportId, {}).get("sqlite_sha256")
        return Path, Sha

    def OracleRun1(self, PairId):
        return os.path.join(self.Oracle, "diffs", PairId, "run1", PairId + ".diaphora")

    def FinishedPairs(self):
        """Pairs whose two oracle runs are done (build_oracle writes
        determinism.json only then)."""
        return [P for P in self.Pairs() if os.path.isfile(self.OracleRun1(P)) and os.path.isfile(
            os.path.join(self.Oracle, "diffs", P, "determinism.json"))]


# ----------------------------------------------------------------------------- instrumentation

class Instrument:
    """All wrappers plus the trace/snapshot writers for one live CBinDiff."""

    def __init__(self, Diaphora, Bd, Args, OutDir, Pair, Producer, RunInfo):
        self.D = Diaphora
        self.Bd = Bd
        self.Args = Args
        self.Out = OutDir
        self.Pair = Pair
        self.Producer = Producer
        self.RunInfo = RunInfo
        self.Lock = threading.RLock()
        self.Local = threading.local()
        self.MainCtx = []                 # stage names on the main thread (innermost last)
        self.Iteration = None             # outer loop iteration k, None outside the loop
        self.LoopStartSite = None         # caller line of the loop's first cleanup (D:3655)
        self.SiteCounts = {}
        self.PointSeq = 0
        self.AddMatchSeq = 0
        self.Index = []
        self.Chooser = {}                 # id(chooser) -> (chooser, raw items)
        self.HeurIndex = {H["name"]: I for I, H in enumerate(Diaphora.HEURISTICS)}
        self.HeuristicSpans = []
        self.WorkerExceptions = []
        self.OneMatchDiffing = {}
        self.Stats = {"add_match": {"appended": 0, "duplicate": 0, "rejected_better": 0}, "rows": 0}
        self.StopReached = False
        self.LoopEndSite = None
        self.RestoreChooser = lambda: None
        self.Started = time.monotonic()
        os.makedirs(os.path.join(OutDir, "snapshots"), exist_ok=True)
        self.TraceHandle = open(os.path.join(OutDir, "trace.jsonl"), "w", encoding="utf-8", newline="\n")
        self.ProgressHandle = open(os.path.join(OutDir, "progress.log"), "w", encoding="utf-8", newline="\n")

    # -- context -------------------------------------------------------------

    def Ctx(self):
        Local = getattr(self.Local, "ctx", None)
        if Local is not None:
            return Local
        return self.MainCtx[-1] if self.MainCtx else None

    # -- writers ---------------------------------------------------------------

    def Emit(self, Event):
        with self.Lock:
            self.TraceHandle.write(Snap.DumpJson(Event))
            self.TraceHandle.write("\n")

    def Sizes(self):
        Matches = self.Bd.all_matches
        return {Key: len(Matches.get(Key, [])) for Key in Snap.LISTS}

    def ItemJson(self, Item):
        # Match layout [ea1, name1, ea2, name2, desc, ratio, nodes1, nodes2]
        # (D:1567-1568 comment, 02 §2).
        return [Item[0], Item[1], Item[2], Item[3], Item[4], Snap.RatioBits(Item[5]), Item[6], Item[7]]

    def ChooserDump(self, Chooser):
        if Chooser is None:
            return None
        Entry = self.Chooser.get(id(Chooser))
        Raw = Entry[1] if Entry is not None and Entry[0] is Chooser else []
        if len(Raw) != len(Chooser.items):
            raise RuntimeError("chooser %r: %d raw items recorded but %d formatted items"
                               % (Chooser.title, len(Raw), len(Chooser.items)))
        return list(Raw)

    def BuildSnapshot(self, Point, Seq):
        Bd = self.Bd
        Obj = {
            "schema": Snap.SCHEMA,
            "producer": self.Producer,
            "pair": self.Pair,
            "seq": Seq,
            "point": Point,
            "iteration": self.Iteration,
            "flags": {
                "is_same_processor": Bd.is_same_processor,
                "is_patch_diff": Bd.is_patch_diff,
                "is_symbols_stripped": Bd.is_symbols_stripped,
                "hooks_loaded": Bd.hooks is not None,
                "total_functions1": Bd.total_functions1,
                "total_functions2": Bd.total_functions2,
            },
            "all_matches": {Key: [self.ItemJson(X) for X in Bd.all_matches.get(Key, [])] for Key in Snap.LISTS},
            "matched_primary": [[K, V["name"], Snap.RatioBits(V["ratio"])] for K, V in Bd.matched_primary.items()],
            "matched_secondary": [[K, V["name"], Snap.RatioBits(V["ratio"])]
                                  for K, V in Bd.matched_secondary.items()],
        }
        if Snap.MatchesAny(Point, self.Args.with_cache):
            Obj["ratios_cache"] = [[K, Snap.RatioBits(V)] for K, V in Bd.ratios_cache.items()]
        if Point == "after:final_pass":
            # Raw CChooser.add_item contents, in add_item order (Appendix B).
            Obj["choosers"] = {"best": self.ChooserDump(Bd.best_chooser),
                               "partial": self.ChooserDump(Bd.partial_chooser),
                               "unreliable": self.ChooserDump(Bd.unreliable_chooser),
                               "multimatch": self.ChooserDump(Bd.multimatch_chooser)}
        if Point == "after:find_unmatched":
            # "primary"/"secondary" are the labels save_results writes
            # (D:2414-2415): primary = self.unmatched_primary = diff-DB functions,
            # secondary = self.unmatched_second = main-DB functions (D:2334-2354).
            Obj["unmatched"] = {"primary": self.ChooserDump(Bd.unmatched_primary),
                                "secondary": self.ChooserDump(Bd.unmatched_second)}
        return Obj

    def WriteRunInfo(self, **Updates):
        self.RunInfo.update(Updates)
        Snap.WriteJsonAtomic(os.path.join(self.Out, "run.json"), self.RunInfo, Indent=1)

    def Point(self, Name):
        with self.Lock:
            Seq = self.PointSeq
            self.PointSeq += 1
            Sizes = self.Sizes()
            Event = {"ev": "point", "name": Name}
            Event.update(Sizes)
            self.Emit(Event)
            File = None
            if Snap.MatchesAny(Name, self.Args.points):
                File = "snapshots/" + Snap.SnapshotFileName(Seq, Name)
                Snap.WriteJsonAtomic(os.path.join(self.Out, File), self.BuildSnapshot(Name, Seq))
            self.Index.append([Seq, Name, File])
            Snap.WriteJsonAtomic(os.path.join(self.Out, "index.json"), self.Index)
            self.TraceHandle.flush()
            Elapsed = time.monotonic() - self.Started
            self.ProgressHandle.write("%s +%9.1fs %5d %-55s best=%d partial=%d unreliable=%d\n" % (
                Now(), Elapsed, Seq, Name, Sizes["best"], Sizes["partial"], Sizes["unreliable"]))
            self.ProgressHandle.flush()
            self.RunInfo["progress"] = {"points": Seq + 1, "last_point": Name, "updated": Now(),
                                        "elapsed_seconds": round(Elapsed, 1)}
            if Seq % 10 == 0 or Name == self.Args.stop_at:
                self.WriteRunInfo()
            if Name == self.Args.stop_at:
                self.StopReached = True
                self.Stop(Name)

    def Stop(self, Name):
        """--stop-at: the point's snapshot is written; end the run here and write
        no .diaphora (plan §2.3). On the main thread a private exception unwinds
        through diff(); a heuristic point lives on a worker thread, where an
        exception would only end that thread (threads_apply goes on with the
        next heuristic), so the process is ended there after flushing."""
        Say("stop point %s reached" % Name)
        if threading.current_thread() is threading.main_thread():
            raise StopCapture(Name)
        self.Finish()
        self.WriteRunInfo(status="stopped", stopped_at=Name, finished=Now(),
                          note="stopped on a heuristic worker thread; work copies left in place",
                          exit_code=EXIT_OK)
        try:
            sys.__stderr__.flush()
            sys.__stdout__.flush()
        except Exception:
            pass
        os._exit(EXIT_OK)

    def Finish(self):
        with self.Lock:
            for Handle in (self.TraceHandle, self.ProgressHandle):
                try:
                    Handle.flush()
                except Exception:
                    pass
            self.RunInfo["stats"] = self.StatsSummary()

    def Close(self):
        self.Finish()
        for Handle in (self.TraceHandle, self.ProgressHandle):
            try:
                Handle.close()
            except Exception:
                pass

    def StatsSummary(self):
        Stats = dict(self.Stats)
        Stats["cleanup_sites"] = {str(K): V for K, V in sorted(self.SiteCounts.items())}
        Stats["loop_start_site"] = self.LoopStartSite
        Stats["loop_end_site"] = self.LoopEndSite
        Stats["find_one_match_diffing"] = dict(sorted(self.OneMatchDiffing.items()))
        Stats["points"] = self.PointSeq
        Stats["heuristic_spans"] = self.HeuristicSpans
        Stats["longest_heuristic_seconds"] = max([S["seconds"] for S in self.HeuristicSpans] or [0])
        Stats["worker_exceptions"] = self.WorkerExceptions
        return Stats

    # -- installation ----------------------------------------------------------

    def Install(self):
        self.InstallChooserHook()
        self.WrapAddMatch()
        self.WrapCleanup()
        for Name in HEURISTIC_WRAPPERS:
            self.WrapHeuristic(Name)
        # Stage points (Appendix B). (method, point base, before?, after?, suffix)
        self.WrapStage("find_equal_matches", "find_equal_matches", False, True)          # D:1404
        self.WrapStage("apply_dirty_heuristics", "apply_dirty_heuristics", False, True)  # D:2629
        self.WrapStage("find_same_name", "find_same_name", True, True)                  # D:2152
        self.WrapStage("find_remaining_functions", "find_remaining_functions", True, True)  # D:2702
        self.WrapStage("run_heuristics_for_category", "run_heuristics_for_category", False, True,
                       Suffix="arg_category")                                             # D:1461
        self.WrapStage("search_small_differences", "search_small_differences", True, True)  # D:2085
        for Name in ("find_matches_diffing", "find_related_matches", "find_related_compilation_unit",
                     "find_locally_affine_functions"):                                    # D:3211/3462/3395/3315
            self.WrapStage(Name, Name, True, True, Suffix="iteration")
        self.WrapStage("final_pass", "final_pass", True, True)                          # D:2937
        self.WrapStage("find_unmatched", "find_unmatched", False, True)                  # D:2323
        self.WrapOneMatchDiffing()
        if self.Args.rows:
            self.WrapRows()
        if self.Args.force_const_order:
            self.ForceConstOrder(self.Args.force_const_order)

    def InstallChooserHook(self):
        """CChooser.add_item (D:275-296) is patched on the class, in memory, because
        find_unmatched creates its choosers at run time (D:2336, D:2349)."""
        Instr = self
        Cls = self.D.CChooser
        Original = Cls.__dict__["add_item"]

        def add_item(chooser_self, item):
            Result = Original(chooser_self, item)
            if chooser_self.title.startswith("Unmatched in"):
                Raw = [item.ea, item.vfname]
            else:
                Raw = [item.ea, item.vfname, item.ea2, item.vfname2, item.description,
                       Snap.RatioBits(item.ratio), item.nodes1, item.nodes2]
            with Instr.Lock:
                Entry = Instr.Chooser.get(id(chooser_self))
                if Entry is None or Entry[0] is not chooser_self:
                    Entry = (chooser_self, [])
                    Instr.Chooser[id(chooser_self)] = Entry
                Entry[1].append(Raw)
            return Result

        Cls.add_item = add_item
        self.RestoreChooser = lambda: setattr(Cls, "add_item", Original)

    def WrapAddMatch(self):
        """add_match (D:1340-1374). `result` is inferred from the effect of the
        call, without re-evaluating Diaphora's conditions: the list grew ->
        appended; the dicts were rewritten (D:1373-1374 store a new dict object)
        but the list did not grow -> duplicate (`item in list`, D:1370); neither
        -> rejected_better (the early return at D:1353-1355)."""
        Bd, Instr = self.Bd, self
        Original = Bd.add_match

        def add_match(name1, name2, ratio, item, chooser):
            List0 = Bd.all_matches.get(chooser) if isinstance(chooser, str) else None
            Len0 = len(List0) if isinstance(List0, list) else None
            try:
                Prev = Bd.matched_primary.get(name1, _MISSING)
            except TypeError:
                Prev = _MISSING
            Result = Original(name1, name2, ratio, item, chooser)
            List1 = Bd.all_matches.get(chooser) if isinstance(chooser, str) else None
            if Len0 is not None and List1 is List0 and len(List1) > Len0:
                Outcome = "appended"
            else:
                try:
                    Now1 = Bd.matched_primary.get(name1, _MISSING)
                except TypeError:
                    Now1 = _MISSING
                Outcome = "duplicate" if Now1 is not Prev else "rejected_better"
            with Instr.Lock:
                Seq = Instr.AddMatchSeq
                Instr.AddMatchSeq += 1
                Instr.Stats["add_match"][Outcome] += 1
                Instr.Emit({"ev": "add_match", "seq": Seq, "ctx": Instr.Ctx(), "name1": name1, "name2": name2,
                            "ea1": item[0] if item is not None else None,
                            "ea2": item[2] if item is not None else None,
                            "desc": item[4] if item is not None else None,
                            "ratio_bits": Snap.RatioBits(ratio), "chooser": chooser, "result": Outcome})
            return Result

        Bd.add_match = add_match

    def WrapCleanup(self):
        """cleanup_matches (D:1554-1605). The site is the caller's line
        (sys._getframe(1).f_lineno), the plan's CleanupSite value."""
        Bd, Instr = self.Bd, self
        Original = Bd.cleanup_matches

        def cleanup_matches():
            Frame = sys._getframe(1)
            Site, Caller = Frame.f_lineno, Frame.f_code.co_name
            del Frame
            with Instr.Lock:
                N = Instr.SiteCounts.get(Site, 0) + 1
                Instr.SiteCounts[Site] = N
                if Caller == "diff":
                    # The loop in diff() (D:3653-3675) calls cleanup twice per
                    # iteration; the first site ever seen from diff() is the
                    # loop head (D:3655), so its n-th call starts iteration n-1.
                    if Instr.LoopStartSite is None:
                        Instr.LoopStartSite = Site
                    if Site == Instr.LoopStartSite:
                        Instr.Iteration = N - 1
                    elif Instr.LoopEndSite is None:
                        Instr.LoopEndSite = Site  # D:3671
            Name = "cleanup:%d:%d" % (Site, N)
            Instr.Point("before:" + Name)
            Result = Original()
            Event = {"ev": "cleanup", "site": Site, "n": N}
            Event.update(Instr.Sizes())
            Instr.Emit(Event)
            Instr.Point("after:" + Name)
            return Result

        Bd.cleanup_matches = cleanup_matches

    def WrapHeuristic(self, MethodName):
        """Per-heuristic points. threads_apply names each worker thread after its
        heuristic (jkutils/threads.py:44-50 via heur_item["name"], D:1540); the
        same wrappers also run on the main thread for the stripped pass (D:2580),
        which is covered by apply_dirty_heuristics instead (Appendix B)."""
        Bd, Instr = self.Bd, self
        Original = getattr(Bd, MethodName)

        def Wrapper(*Args, **Kwargs):
            Thread = threading.current_thread()
            HeurId = None
            if Thread is not threading.main_thread():
                HeurId = Instr.HeurIndex.get(Thread.name)
            if HeurId is None:
                return Original(*Args, **Kwargs)
            Ctx = "heuristic:%d" % HeurId
            Instr.Local.ctx = Ctx
            Instr.Point("before:" + Ctx)
            Started = time.monotonic()
            try:
                return Original(*Args, **Kwargs)
            except BaseException as Exc:
                Instr.WorkerExceptions.append({"heuristic": HeurId, "name": Thread.name, "method": MethodName,
                                               "exception": repr(Exc)})
                raise
            finally:
                Seconds = round(time.monotonic() - Started, 3)
                Instr.HeuristicSpans.append({"heuristic": HeurId, "name": Thread.name, "seconds": Seconds})
                Instr.Local.ctx = None
                Instr.Point("after:" + Ctx)

        Wrapper.__name__ = MethodName
        setattr(Bd, MethodName, Wrapper)

    def WrapStage(self, MethodName, Base, Before, After, Suffix=None):
        Bd, Instr = self.Bd, self
        Original = getattr(Bd, MethodName)
        Signature = inspect.signature(Original)

        def Wrapper(*Args, **Kwargs):
            Name = Base
            if Suffix is not None:
                Bound = Signature.bind(*Args, **Kwargs)
                Value = Bound.arguments[Suffix]
                Name = "%s:%s" % (Base, Value)
                if Suffix == "iteration":
                    with Instr.Lock:
                        if Instr.Iteration != Value:
                            Instr.RunInfo.setdefault("warnings", []).append(
                                "iteration argument %r of %s differs from the loop count %r"
                                % (Value, MethodName, Instr.Iteration))
                        Instr.Iteration = Value
            if MethodName == "final_pass":
                Instr.Iteration = None  # the outer loop is over (D:3653-3677)
            Instr.MainCtx.append(Name)
            try:
                if Before:
                    Instr.Point("before:" + Name)
                Result = Original(*Args, **Kwargs)
            finally:
                Instr.MainCtx.pop()
            if After:
                Instr.Point("after:" + Name)
            return Result

        Wrapper.__name__ = MethodName
        setattr(Bd, MethodName, Wrapper)

    def WrapOneMatchDiffing(self):
        """Counts find_one_match_diffing calls (D:3033) per field and outer
        iteration, for the 06 V3 figures (asm 716 / pseudo 426 on ls-old_vs_ls)."""
        Bd, Instr = self.Bd, self
        Original = Bd.find_one_match_diffing
        Signature = inspect.signature(Original)

        def find_one_match_diffing(*Args, **Kwargs):
            Bound = Signature.bind(*Args, **Kwargs)
            Key = "%s:outer%s:inner%s" % (Bound.arguments["field_name"], Instr.Iteration,
                                          Bound.arguments["iteration"])
            with Instr.Lock:
                Instr.OneMatchDiffing[Key] = Instr.OneMatchDiffing.get(Key, 0) + 1
            return Original(*Args, **Kwargs)

        Bd.find_one_match_diffing = find_one_match_diffing

    def WrapRows(self):
        """--rows: one `row` event per check_match call (D:1786-1872).

        The decision for an accepted row repeats the routing of the caller:
        add_matches_internal (D:1922-1946, needs its best/partial/val/unreliable,
        taken from a wrapper around it), add_matches_from_query (D:2073-2075,
        always the given category with ratio 1), find_same_name (D:2196-2206) and
        search_small_differences (D:2143-2146). A rejected row is classified after
        the call, from state check_match does not change: nullsub (D:1846-1848),
        has_best (D:1851-1853) or has_better (D:1865-1867). ratio_bits is the ratio
        check_match computed or returned; null when it computed none."""
        Bd, Instr, D = self.Bd, self, self.D
        OrigInternal = Bd.add_matches_internal
        SigInternal = inspect.signature(OrigInternal)
        OrigCheckMatch = Bd.check_match
        SigCheckMatch = inspect.signature(OrigCheckMatch)
        OrigCheckRatio = Bd.check_ratio
        PartialRatio = D.config.DEFAULT_PARTIAL_RATIO

        def add_matches_internal(*Args, **Kwargs):
            Bound = SigInternal.bind(*Args, **Kwargs)
            Bound.apply_defaults()
            Stack = getattr(Instr.Local, "routing", None)
            if Stack is None:
                Stack = Instr.Local.routing = []
            Stack.append((Bound.arguments["best"], Bound.arguments["partial"], Bound.arguments["val"],
                          Bound.arguments["unreliable"]))
            try:
                return OrigInternal(*Args, **Kwargs)
            finally:
                Stack.pop()

        def check_ratio(*Args, **Kwargs):
            Result = OrigCheckRatio(*Args, **Kwargs)
            Instr.Local.last_ratio = Result
            return Result

        def check_match(*Args, **Kwargs):
            Frame = sys._getframe(1)
            Caller = Frame.f_code.co_name
            del Frame
            Bound = SigCheckMatch.bind(*Args, **Kwargs)
            Row = Bound.arguments["row"]
            Instr.Local.last_ratio = _MISSING
            try:
                Result = OrigCheckMatch(*Args, **Kwargs)
            except BaseException:
                Instr.EmitRow(Row, "raised", None)
                raise
            ShouldAdd, R = Result
            if ShouldAdd:
                Decision = "accepted"
                if Caller == "add_matches_internal":
                    Stack = getattr(Instr.Local, "routing", None) or [(None, None, None, None)]
                    Best, Partial, Val, Unreliable = Stack[-1]
                    if Val is None:
                        Val = PartialRatio  # D:1922-1923
                    if R == 1.0:
                        Decision = "accepted_best"
                    elif R >= Val and Partial is not None:
                        Decision = "accepted_partial"
                    elif R < PartialRatio and R > Val and Unreliable is not None:
                        Decision = "accepted_unreliable"
                    else:
                        Decision = "below_min"
                elif Caller == "add_matches_from_query":
                    Decision = "accepted_best"
                elif Caller == "find_same_name":
                    Decision = "accepted_best" if float(R) == 1.0 else "accepted_partial"
                elif Caller == "search_small_differences":
                    Decision = "accepted_best" if R == 1.0 else "accepted_partial"
                Instr.EmitRow(Row, Decision, R)
            else:
                Name1, Name2 = Row["name1"], Row["name2"]
                if Name1.startswith("nullsub_") or Name2.startswith("nullsub_"):
                    Instr.EmitRow(Row, "nullsub", None)
                elif Bd.has_best_match(Name1, Name2):
                    Instr.EmitRow(Row, "has_best", None)
                else:
                    Last = getattr(Instr.Local, "last_ratio", _MISSING)
                    Instr.EmitRow(Row, "has_better", None if Last is _MISSING else Last)
            return Result

        Bd.add_matches_internal = add_matches_internal
        Bd.check_ratio = check_ratio
        Bd.check_match = check_match

    def EmitRow(self, Row, Decision, Ratio):
        with self.Lock:
            self.Stats["rows"] += 1
            self.Emit({"ev": "row", "ctx": self.Ctx(), "ea1": Row["ea"], "ea2": Row["ea2"], "decision": Decision,
                       "ratio_bits": None if Ratio is None else Snap.RatioBits(Ratio)})

    def ForceConstOrder(self, Mode):
        """--force-const-order: sensitivity measurement only (06 V4, plan §5 R3).
        The body is D:3362-3393 verbatim except that the intersection is iterated
        in a fixed order instead of Python set order. Never an oracle run."""
        Bd, D = self.Bd, self.D
        json_ = D.json
        get_query_fields = D.get_query_fields
        Reverse = Mode == "rsorted"

        def find_related_constants(main_row, diff_row):
            self_ = Bd
            heur = "Same constants related matches"
            cur = self_.db_cursor()
            try:
                main_consts = set(json_.loads(main_row["constants"]))
                diff_consts = set(json_.loads(diff_row["constants"]))

                inter_consts = main_consts.intersection(diff_consts)
                if len(inter_consts) > 0:
                    sql = (
                        """ select """
                        + get_query_fields(heur)
                        + """
         from main.functions f,
              diff.functions df,
              main.constants mc,
              diff.constants dc
        where f.id = mc.func_id
          and df.id = dc.func_id
          and dc.constant = mc.constant
          and mc.constant = ?
          and abs(mc.constant) == 0 """
                    )
                    # The only change: a fixed order instead of `for constant in inter_consts`.
                    for constant in sorted(inter_consts, key=lambda X: (type(X).__name__, str(X)), reverse=Reverse):
                        cur.execute(sql, (str(constant),))
                        self_.add_matches_internal(cur, best="best", partial="partial")
            finally:
                cur.close()

        Bd.find_related_constants = find_related_constants


# ----------------------------------------------------------------------------- run

def ResolvePaths(Args):
    Args.corpus = Args.corpus or os.environ.get("DSIG_CORPUS_ROOT")
    Args.diaphora_dir = Args.diaphora_dir or os.environ.get("DSIG_DIAPHORA_DIR")
    if not Args.corpus:
        raise SystemExit("--corpus (or DSIG_CORPUS_ROOT) is required")
    if not Args.diaphora_dir:
        raise SystemExit("--diaphora-dir (or DSIG_DIAPHORA_DIR) is required")
    Args.corpus = os.path.abspath(Args.corpus)
    Args.diaphora_dir = os.path.abspath(Args.diaphora_dir)
    if not os.path.isfile(os.path.join(Args.diaphora_dir, "diaphora.py")):
        raise SystemExit("no diaphora.py in %s" % Args.diaphora_dir)


def CaptureDir(Args, CorpusObj):
    return os.path.abspath(Args.out) if Args.out else os.path.join(CorpusObj.Traces, Args.pair)


def PrepareOutDir(OutDir, Force):
    RunJson = os.path.join(OutDir, "run.json")
    if os.path.isfile(RunJson) and not Force:
        try:
            Previous = Snap.ReadJson(RunJson)
        except Exception:
            Previous = {}
        if Previous.get("status") in (STATUS_RUNNING, "preparing") and ProcessAlive(Previous.get("pid")):
            raise SystemExit("%s is still being written by pid %s (use --force to override)"
                             % (OutDir, Previous.get("pid")))
    os.makedirs(OutDir, exist_ok=True)
    for Name in ("trace.jsonl", "index.json", "run.json", "progress.log", "diaphora.log", "self_check.json"):
        Path = os.path.join(OutDir, Name)
        if os.path.exists(Path):
            os.remove(Path)
    for Name in os.listdir(OutDir):
        if Name.endswith(".diaphora"):
            os.remove(os.path.join(OutDir, Name))
    for Name in ("snapshots", "work"):
        Path = os.path.join(OutDir, Name)
        if os.path.isdir(Path):
            shutil.rmtree(Path)


def CheckAgainstOracle(OutDir, Pair, OutFile, OracleFile, Index):
    """Plan §2.3 self-check and §4 L0b: the instrumented .diaphora equals oracle
    run1 in stored order, and the chooser dumps reproduce its rows."""
    Report = {"oracle": OracleFile}
    if not os.path.isfile(OracleFile):
        Report["skipped"] = "no oracle run1 for this pair"
        return Report, True
    OracleResults, OracleUnmatched, OracleConfig = Snap.ReadDiaphora(OracleFile)
    Ok = True
    if os.path.isfile(OutFile):
        Results, Unmatched, Config = Snap.ReadDiaphora(OutFile)
        Report["results"] = Snap.CompareRowLists(OracleResults, Results)
        Report["unmatched"] = Snap.CompareRowLists(OracleUnmatched, Unmatched)
        Report["config_version_equal"] = [R[2] for R in OracleConfig] == [R[2] for R in Config]
        Ok = (Report["results"]["identical_in_order"] and Report["unmatched"]["identical_in_order"]
              and Report["config_version_equal"])
    else:
        Report["missing_output"] = OutFile
        Ok = False
    Files = {Point: File for _, Point, File in Index}
    FinalFile, UnmatchedFile = Files.get("after:final_pass"), Files.get("after:find_unmatched")
    if FinalFile and UnmatchedFile:
        Final = Snap.ReadJson(os.path.join(OutDir, FinalFile))
        Unm = Snap.ReadJson(os.path.join(OutDir, UnmatchedFile))
        DumpResults, DumpUnmatched = Snap.RowsFromDumps(Final["choosers"], Unm["unmatched"])
        Report["dump_results"] = Snap.CompareRowLists(OracleResults, DumpResults)
        Report["dump_unmatched"] = Snap.CompareRowLists(OracleUnmatched, DumpUnmatched)
        Report["dump_counts"] = {K: len(V) for K, V in Final["choosers"].items()}
        Ok = Ok and Report["dump_results"]["identical_in_order"] and Report["dump_unmatched"]["identical_in_order"]
    else:
        Report["dump_check"] = "after:final_pass / after:find_unmatched snapshots not written"
    Report["ok"] = Ok
    return Report, Ok


def LogChecks(LogPath):
    """The log-based oracle validity rules of plan §1.6."""
    with open(LogPath, "r", encoding="utf-8", errors="replace") as Handle:
        Text = Handle.read()
    Final = None
    for Line in Text.splitlines():
        if "Final results:" in Line:
            Final = Line.split("INFO: ", 1)[-1].strip()
    return {"saved_line_present": "Diffing results saved in file" in Text,
            "timeouts_logged": Text.count("Timeout with heuristic"),
            "tracebacks_logged": Text.count("Traceback (most recent call last)"),
            "cdifflib_warning_present": "Python library 'cdifflib' not found" in Text,
            "final_results": Final}


def CommandRun(Args):
    ResolvePaths(Args)
    if Args.stop_at and not Snap.IsPointName(Args.stop_at):
        raise SystemExit("--stop-at %r is not an Appendix B point name" % Args.stop_at)
    CorpusObj = Corpus(Args.corpus)
    PairInfo = CorpusObj.Pair(Args.pair)
    OutDir = CaptureDir(Args, CorpusObj)

    if Args.detach:
        return Detach(Args, OutDir)
    if Args.hash_seed is not None and os.environ.get("PYTHONHASHSEED") != str(Args.hash_seed):
        # String hashing is fixed at interpreter start-up, so re-run under the seed.
        Env = dict(os.environ, PYTHONHASHSEED=str(Args.hash_seed), PYTHONDONTWRITEBYTECODE="1")
        return subprocess.call([sys.executable, "-B", os.path.abspath(__file__)] + sys.argv[1:], env=Env)

    PrepareOutDir(OutDir, Args.force)
    Ref, Target = PairInfo["ref"], PairInfo["target"]
    RefPath, RefSha = CorpusObj.Export(Ref)
    TargetPath, TargetSha = CorpusObj.Export(Target)
    OutFile = os.path.join(OutDir, Args.pair + ".diaphora")
    RunInfo = {
        "status": "preparing", "pair": Args.pair, "ref": Ref, "target": Target, "pid": os.getpid(),
        "started": Now(), "out_dir": OutDir, "argv": sys.argv,
        "options": {"stop_at": Args.stop_at, "points": Args.points, "with_cache": Args.with_cache,
                    "rows": Args.rows, "force_const_order": Args.force_const_order},
        "oracle_valid_config": not Args.force_const_order,
        "python": sys.version, "python_executable": sys.executable,
        "pythonhashseed": os.environ.get("PYTHONHASHSEED"),
        "hash_randomization": sys.flags.hash_randomization,
        "dont_write_bytecode": sys.dont_write_bytecode,
        "diaphora_dir": Args.diaphora_dir,
    }
    Snap.WriteJsonAtomic(os.path.join(OutDir, "run.json"), RunInfo, Indent=1)

    RefBefore = ReferenceState(Args.diaphora_dir)
    Say("pair %s -> %s" % (Args.pair, OutDir))
    Inputs = {}
    for Id, Path, Sha in ((Ref, RefPath, RefSha), (Target, TargetPath, TargetSha)):
        Inputs[Id] = {"path": Path, "manifest_sha256": Sha, "sha256_before": Sha256OfFile(Path)}
    WorkDir = os.path.join(OutDir, "work")
    os.makedirs(WorkDir)
    Copies = {}
    for Id in (Ref, Target):
        Copy = os.path.join(WorkDir, Id + ".sqlite")
        # Only the main file: the oracle's -wal files are empty (09 caveats).
        shutil.copyfile(Inputs[Id]["path"], Copy)
        Inputs[Id]["copy"] = Copy
        Inputs[Id]["copy_sha256"] = Sha256OfFile(Copy)
        Copies[Id] = Copy
    RunInfo["inputs"] = Inputs
    Bad = [Id for Id in Inputs if not (Inputs[Id]["sha256_before"] == Inputs[Id]["manifest_sha256"]
                                       == Inputs[Id]["copy_sha256"])]
    if Bad:
        RunInfo.update(status="refused", reason="export sha256 differs from the manifest: %s" % Bad)
        Snap.WriteJsonAtomic(os.path.join(OutDir, "run.json"), RunInfo, Indent=1)
        raise SystemExit(RunInfo["reason"])

    # build_oracle.CleanEnv() semantics, in-process: no DIAPHORA_* variable
    # reaches Diaphora (D:560-569 reads them at run time).
    Removed = sorted(Key for Key in os.environ if Key.upper().startswith("DIAPHORA_"))
    for Key in Removed:
        del os.environ[Key]
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    RunInfo["removed_env"] = Removed

    LogLock = threading.Lock()
    LogHandle = open(os.path.join(OutDir, "diaphora.log"), "w", encoding="utf-8", newline="\n")
    SavedOut, SavedErr = sys.stdout, sys.stderr
    sys.stdout = Tee(SavedOut, LogHandle, LogLock)
    sys.stderr = Tee(SavedErr, LogHandle, LogLock)

    Instr = None
    ExitCode = EXIT_OK
    Diaphora = None
    Bd = None
    try:
        sys.path.insert(0, Args.diaphora_dir)
        import diaphora as Diaphora  # the unmodified checkout, read-only
        Producer = "diaphora-" + RefBefore["describe"]
        RunInfo.update(status=STATUS_RUNNING, producer=Producer, is_ida=Diaphora.IS_IDA,
                       has_cdifflib=Diaphora.HAS_CDIFFLIB, diaphora_module=Diaphora.__file__,
                       sqlite_version=Diaphora.sqlite3.sqlite_version)
        if Diaphora.IS_IDA:
            raise SystemExit("idaapi is importable; this is not a standalone run")

        Db1, Db2 = Copies[Ref], Copies[Target]
        # __main__ of diaphora.py, literally (D:3757-3773).
        Bd = Diaphora.CBinDiff(Db1)
        if not Diaphora.IS_IDA:
            Bd.ignore_all_names = False
        Bd.db = Diaphora.sqlite3_connect(Db1)
        Instr = Instrument(Diaphora, Bd, Args, OutDir, Args.pair, Producer, RunInfo)
        Instr.Install()
        Instr.WriteRunInfo()
        Started = time.monotonic()
        try:
            Bd.diff(Db2)
            Bd.save_results(OutFile)
            RunInfo.update(status="complete")
        except StopCapture as Stop:
            RunInfo.update(status="stopped", stopped_at=str(Stop))
        except SystemExit as Exc:
            # A main-thread timeout (D:1894-1896): Diaphora would exit 0 with no file.
            RunInfo.update(status="diaphora_system_exit", exception=repr(Exc))
            ExitCode = EXIT_DIAPHORA_ABORT
        except BaseException as Exc:
            RunInfo.update(status="diaphora_exception", exception=repr(Exc), traceback=traceback.format_exc())
            ExitCode = EXIT_DIAPHORA_ABORT
        RunInfo["diff_seconds"] = round(time.monotonic() - Started, 3)
    finally:
        sys.stdout.flush()
        sys.stderr.flush()
        sys.stdout, sys.stderr = SavedOut, SavedErr
        LogHandle.close()
        if Instr is not None:
            Instr.Close()
            Instr.RestoreChooser()
        # Close every connection so the work copies can be deleted: the ones in
        # _DATABASES (D:340-349), the per-thread ones in bd.dbs_dict (D:575-581;
        # sqlite3_connect overwrites _DATABASES[db1], so these are not all there)
        # and bd.db (D:3762).
        Handles = []
        if Diaphora is not None:
            Handles += list(Diaphora._DATABASES.values())
        if Bd is not None:
            Handles += list(getattr(Bd, "dbs_dict", {}).values()) + [getattr(Bd, "db", None)]
        for Handle in Handles:
            try:
                if Handle is not None:
                    Handle.close()
            except Exception:
                pass
        Bd = None
        import gc
        gc.collect()

    if Args.stop_at and RunInfo["status"] == "complete":
        RunInfo.setdefault("warnings", []).append("stop point %s was never reached" % Args.stop_at)
    RunInfo["log_checks"] = LogChecks(os.path.join(OutDir, "diaphora.log"))
    for Id in Inputs:
        Inputs[Id]["sha256_after"] = Sha256OfFile(Inputs[Id]["path"])
        Inputs[Id]["unchanged"] = Inputs[Id]["sha256_after"] == Inputs[Id]["sha256_before"] == \
            Inputs[Id]["manifest_sha256"]
        Inputs[Id]["copy_sha256_after"] = Sha256OfFile(Inputs[Id]["copy"])
    RunInfo["reference"] = CompareReferenceStates(RefBefore, ReferenceState(Args.diaphora_dir))
    RunInfo["heuristic_timeout_suspects"] = [S for S in (Instr.HeuristicSpans if Instr else [])
                                            if S["seconds"] > 300]
    if RunInfo["status"] == "complete":
        RunInfo["output"] = {"path": OutFile, "sha256": Sha256OfFile(OutFile)}
        Checks = RunInfo["log_checks"]
        RunInfo["oracle_validity"] = {
            "saved": Checks["saved_line_present"], "no_timeouts": Checks["timeouts_logged"] == 0
            and not RunInfo["heuristic_timeout_suspects"],
            "cdifflib_absent": not RunInfo["has_cdifflib"] and Checks["cdifflib_warning_present"],
            "no_diaphora_env": True, "inputs_unchanged": all(I["unchanged"] for I in Inputs.values()),
            "default_config": RunInfo["oracle_valid_config"]}
        Check, Ok = CheckAgainstOracle(OutDir, Args.pair, OutFile, CorpusObj.OracleRun1(Args.pair),
                                       Snap.ReadJson(os.path.join(OutDir, "index.json")))
        RunInfo["self_check"] = Check
        if not Ok and not Args.force_const_order:
            ExitCode = EXIT_FAIL
            Say("SELF-CHECK FAILED: the instrumented output differs from oracle run1")
    if not RunInfo["reference"]["unchanged"]:
        ExitCode = EXIT_FAIL
        Say("the Diaphora checkout changed during the run: %s" % RunInfo["reference"]["files_changed"][:10])
    if not all(I["unchanged"] for I in Inputs.values()):
        ExitCode = EXIT_FAIL
        Say("an oracle export changed during the run")
    if not Args.keep_work:
        try:
            shutil.rmtree(WorkDir)
            RunInfo["work_dir_removed"] = True
        except OSError as Exc:
            RunInfo["work_dir_removed"] = "failed: %s" % Exc
    RunInfo.update(finished=Now(), exit_code=ExitCode)
    Snap.WriteJsonAtomic(os.path.join(OutDir, "run.json"), RunInfo, Indent=1)
    Say("%s: %s (exit %d)%s" % (Args.pair, RunInfo["status"], ExitCode,
                                ", self-check %s" % ("OK" if RunInfo.get("self_check", {}).get("ok") else
                                                     RunInfo.get("self_check", {}).get("skipped", "FAILED"))
                                if "self_check" in RunInfo else ""))
    return ExitCode


# ----------------------------------------------------------------------------- detach

def Detach(Args, OutDir):
    """Start this run as a process that outlives the launching session.

    Windows: through WMI (Win32_Process.Create), so the process is not in the
    launching shell's job object. POSIX: a new session. The child's console
    output goes to <out>/console.log; launch.json records how to check on it."""
    os.makedirs(OutDir, exist_ok=True)
    Argv = [A for A in sys.argv[1:] if A != "--detach"]
    Command = [sys.executable, "-B", os.path.abspath(__file__)] + Argv + ["--console-log",
                                                                        os.path.join(OutDir, "console.log")]
    if "--corpus" not in Argv:
        Command += ["--corpus", Args.corpus]
    if "--diaphora-dir" not in Argv:
        Command += ["--diaphora-dir", Args.diaphora_dir]
    Launch = {"launched": Now(), "command": Command, "out_dir": OutDir}
    if os.name == "nt":
        CommandLine = subprocess.list2cmdline(Command)
        Script = ("$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments "
                  "@{CommandLine = $env:DSIG_LAUNCH_CMD; CurrentDirectory = $env:DSIG_LAUNCH_CWD}; "
                  "Write-Output \"$($r.ReturnValue) $($r.ProcessId)\"")
        Env = dict(os.environ, DSIG_LAUNCH_CMD=CommandLine, DSIG_LAUNCH_CWD=OutDir)
        Output = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", Script], env=Env,
                                capture_output=True, text=True)
        Parts = Output.stdout.split()
        if Output.returncode != 0 or len(Parts) != 2 or Parts[0] != "0":
            raise SystemExit("WMI launch failed: %s %s" % (Output.stdout, Output.stderr))
        Launch.update(method="wmi Win32_Process.Create", pid=int(Parts[1]))
    else:
        with open(os.path.join(OutDir, "console.log"), "ab") as Log:
            Child = subprocess.Popen(Command, stdin=subprocess.DEVNULL, stdout=Log, stderr=subprocess.STDOUT,
                                     start_new_session=True, cwd=OutDir)
        Launch.update(method="posix new session", pid=Child.pid)
    Launch["check"] = ("python -B %s status --corpus <corpus>   (or read %s: status, progress.last_point; "
                       "tail progress.log)" % (os.path.basename(__file__), os.path.join(OutDir, "run.json")))
    Snap.WriteJsonAtomic(os.path.join(OutDir, "launch.json"), Launch, Indent=1)
    Say("detached pid %s -> %s" % (Launch["pid"], OutDir))
    return EXIT_OK


# ----------------------------------------------------------------------------- selftest

def RunCapture(Args, Pair, OutDir, Extra, Seed):
    Command = [sys.executable, "-B", os.path.abspath(__file__), "run", "--pair", Pair, "--out", OutDir,
               "--corpus", Args.corpus, "--diaphora-dir", Args.diaphora_dir, "--force",
               "--hash-seed", str(Seed)] + Extra
    os.makedirs(OutDir, exist_ok=True)
    Say("capture %s (PYTHONHASHSEED=%s) -> %s" % (Pair, Seed, OutDir))
    Env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONHASHSEED=str(Seed))
    with open(os.path.join(OutDir, "console.log"), "w", encoding="utf-8", errors="replace") as Log:
        Code = subprocess.call(Command, stdout=Log, stderr=subprocess.STDOUT, env=Env)
    return Code, Snap.ReadJson(os.path.join(OutDir, "run.json"))


def V3Check(CaptureDirPath):
    """06 V3 on ls-old_vs_ls: cleanup executions per site, the outer totals
    (best+partial after the loop's cleanups, D:3656/D:3672) and the
    find_one_match_diffing call counts."""
    Sites, Outer = {}, []
    RunInfo = Snap.ReadJson(os.path.join(CaptureDirPath, "run.json"))
    LoopSites = (RunInfo["stats"]["loop_start_site"], RunInfo["stats"]["loop_end_site"])
    for _, Event in Snap.ReadTrace(os.path.join(CaptureDirPath, "trace.jsonl")):
        if Event["ev"] == "cleanup":
            Sites[Event["site"]] = Sites.get(Event["site"], 0) + 1
            if Event["site"] in LoopSites:
                Outer.append(Event["best"] + Event["partial"])
    Totals = [Outer[0]] + [Outer[I] for I in range(1, len(Outer), 2)] if Outer else []
    OneMatch = {}
    for Key, Count in RunInfo["stats"]["find_one_match_diffing"].items():
        Field = Key.split(":")[0]
        OneMatch[Field] = OneMatch.get(Field, 0) + Count
    Result = {"cleanup_sites": {str(K): V for K, V in sorted(Sites.items())},
              "expected_cleanup_sites": {str(K): V for K, V in sorted(V3_CLEANUP_COUNTS.items())},
              "cleanup_sites_ok": Sites == V3_CLEANUP_COUNTS,
              "loop_totals_raw": Outer, "outer_totals": Totals, "expected_outer_totals": V3_OUTER_TOTALS,
              "outer_totals_ok": Totals == V3_OUTER_TOTALS,
              "find_one_match_diffing": OneMatch, "expected_find_one_match_diffing": V3_ONE_MATCH_DIFFING,
              "find_one_match_diffing_ok": OneMatch == V3_ONE_MATCH_DIFFING}
    Result["ok"] = Result["cleanup_sites_ok"] and Result["outer_totals_ok"] and Result["find_one_match_diffing_ok"]
    return Result


def CommandSelftest(Args):
    """Plan §4 L0b tests and acceptance. Both determinism runs use the same
    PYTHONHASHSEED: find_related_constants iterates a Python set of constants
    (D:3389), whose order follows the string hash seed (plan §5 R3), so two
    unpinned runs can legitimately differ in row order and in intermediate
    state. A third run under another seed measures that (informational)."""
    ResolvePaths(Args)
    import compare_traces as CT
    CorpusObj = Corpus(Args.corpus)
    Pairs = Args.pairs or CorpusObj.FinishedPairs()
    SelfDir = os.path.join(CorpusObj.Traces, "_selftest")
    os.makedirs(SelfDir, exist_ok=True)
    Extra = ["--rows"]
    for Glob in Args.with_cache or []:
        Extra += ["--with-cache", Glob]
    Report = {"started": Now(), "pairs": {}, "options": Extra, "hash_seed": Args.hash_seed,
              "probe_seed": Args.probe_seed}
    AllOk = True
    for Pair in Pairs:
        Entry = {}
        DirA = os.path.join(CorpusObj.Traces, Pair)
        DirB = os.path.join(SelfDir, Pair + ".run2")
        CodeA, InfoA = RunCapture(Args, Pair, DirA, Extra, Args.hash_seed)
        CodeB, InfoB = RunCapture(Args, Pair, DirB, Extra, Args.hash_seed)
        for Label, Code, Info in (("run1", CodeA, InfoA), ("run2", CodeB, InfoB)):
            Entry[Label] = {"exit_code": Code, "status": Info.get("status"),
                            "self_check_ok": Info.get("self_check", {}).get("ok"),
                            "results": Info.get("self_check", {}).get("results"),
                            "unmatched": Info.get("self_check", {}).get("unmatched"),
                            "dump_results_identical": Info.get("self_check", {}).get("dump_results", {})
                            .get("identical_in_order"),
                            "dump_unmatched_identical": Info.get("self_check", {}).get("dump_unmatched", {})
                            .get("identical_in_order"),
                            "reference_unchanged": Info.get("reference", {}).get("unchanged"),
                            "inputs_unchanged": all(I.get("unchanged") for I in Info.get("inputs", {}).values()),
                            "oracle_validity": Info.get("oracle_validity"),
                            "final_results": Info.get("log_checks", {}).get("final_results"),
                            "diff_seconds": Info.get("diff_seconds")}
        TraceCmp = CT.CompareTraceFiles(os.path.join(DirA, "trace.jsonl"), os.path.join(DirB, "trace.jsonl"))
        SnapCmp = CT.CompareSnapshotDirs(DirA, DirB)
        Entry["trace_run1_vs_run2"] = {"identical": TraceCmp["identical"], "events": TraceCmp["events"],
                                       "first_divergence": TraceCmp.get("first_divergence")}
        Entry["snapshots_run1_vs_run2"] = {"identical": SnapCmp["identical"], "points": SnapCmp["points_compared"],
                                           "first_difference": SnapCmp.get("first_difference")}
        Ok = (CodeA == 0 and CodeB == 0 and TraceCmp["identical"] and SnapCmp["identical"]
              and all(Entry[L]["self_check_ok"] and Entry[L]["reference_unchanged"] and Entry[L]["inputs_unchanged"]
                      for L in ("run1", "run2")))
        if Pair == "ls-old_vs_ls":
            Entry["v3"] = V3Check(DirA)
            Ok = Ok and Entry["v3"]["ok"]
        if Args.probe_seed is not None:
            DirC = os.path.join(SelfDir, "%s.seed%d" % (Pair, Args.probe_seed))
            CodeC, InfoC = RunCapture(Args, Pair, DirC, Extra, Args.probe_seed)
            Probe = CT.CompareSnapshotDirs(DirA, DirC, All=True)
            Entry["seed_probe"] = {
                "seeds": [Args.hash_seed, Args.probe_seed], "exit_code": CodeC,
                "final_output_equals_oracle": InfoC.get("self_check", {}).get("ok"),
                "snapshots_identical": Probe["identical"],
                "seed_sensitive_points": [D["point"] for D in Probe["differences"]],
                "seed_sensitive_fields": sorted({Diff["field"] for D in Probe["differences"] for Diff in D["diffs"]})}
        Entry["ok"] = Ok
        AllOk = AllOk and Ok
        Report["pairs"][Pair] = Entry
        Say("%s: %s" % (Pair, "OK" if Ok else "FAILED"))
    Report["reference_git_status"] = Git(Args.diaphora_dir, "status", "--porcelain").strip()
    Report["reference_describe"] = Git(Args.diaphora_dir, "describe", "--tags", "--long", "--dirty").strip()
    Report["ok"] = AllOk and Report["reference_git_status"] == ""
    Report["finished"] = Now()
    ReportPath = os.path.abspath(Args.report) if Args.report else os.path.join(SelfDir, "report.json")
    Snap.WriteJsonAtomic(ReportPath, Report, Indent=1)
    print(json.dumps(Report, indent=1, ensure_ascii=False))
    Say("selftest %s; report %s" % ("PASSED" if Report["ok"] else "FAILED", ReportPath))
    return EXIT_OK if Report["ok"] else EXIT_FAIL


# ----------------------------------------------------------------------------- status

def CommandStatus(Args):
    Args.corpus = Args.corpus or os.environ.get("DSIG_CORPUS_ROOT")
    if not Args.corpus:
        raise SystemExit("--corpus (or DSIG_CORPUS_ROOT) is required")
    Traces = os.path.join(os.path.abspath(Args.corpus), "oracle", "traces")
    Rows = []
    for Root, Dirs, Names in os.walk(Traces):
        Dirs[:] = [D for D in Dirs if D not in ("snapshots", "work")]
        if "run.json" not in Names:
            continue
        try:
            Info = Snap.ReadJson(os.path.join(Root, "run.json"))
        except Exception as Exc:
            Rows.append((os.path.relpath(Root, Traces), "unreadable run.json: %s" % Exc, "", "", ""))
            continue
        Progress = dict(Info.get("progress", {}))
        try:
            # index.json is rewritten at every point; run.json only every 10.
            Index = Snap.ReadJson(os.path.join(Root, "index.json"))
            if Index:
                Progress.update(points=len(Index), last_point=Index[-1][1])
        except Exception:
            pass
        Alive = ProcessAlive(Info.get("pid")) if Info.get("status") in (STATUS_RUNNING, "preparing") else False
        Status = Info.get("status", "?")
        if Status in (STATUS_RUNNING, "preparing") and not Alive:
            Status += " (process gone)"
        Rows.append((os.path.relpath(Root, Traces), Status, str(Info.get("options", {}).get("stop_at")),
                     "%s pts, last %s" % (Progress.get("points"), Progress.get("last_point")),
                     "pid %s%s, updated %s" % (Info.get("pid"), " alive" if Alive else "", Progress.get("updated"))))
    for Row in sorted(Rows):
        print(" | ".join(Row))
    return EXIT_OK


# ----------------------------------------------------------------------------- main

def RedirectConsole(Path):
    """--console-log: send fds 1/2 (and so every print) to a file. Used by
    detached runs, which have no console."""
    Handle = open(Path, "ab", buffering=0)
    os.dup2(Handle.fileno(), 1)
    os.dup2(Handle.fileno(), 2)
    sys.stdout = io.TextIOWrapper(os.fdopen(1, "wb", buffering=0), encoding="utf-8", errors="replace",
                                  line_buffering=True, write_through=True)
    sys.stderr = io.TextIOWrapper(os.fdopen(2, "wb", buffering=0), encoding="utf-8", errors="replace",
                                  line_buffering=True, write_through=True)
    sys.__stdout__, sys.__stderr__ = sys.stdout, sys.stderr


def ParseArgs(Argv=None):
    Parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                     formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    Sub = Parser.add_subparsers(dest="command", required=True)

    def Common(P):
        P.add_argument("--corpus", help="corpus root (default: env DSIG_CORPUS_ROOT)")
        P.add_argument("--diaphora-dir", help="unmodified Diaphora checkout (default: env DSIG_DIAPHORA_DIR)")
        P.add_argument("--console-log", help=argparse.SUPPRESS)

    Run = Sub.add_parser("run", help="one instrumented diff")
    Common(Run)
    Run.add_argument("--pair", required=True, help="oracle pair id from manifest.json")
    Run.add_argument("--out", help="capture directory (default <corpus>/oracle/traces/<pair>)")
    Run.add_argument("--stop-at", help="end the run at this point (its snapshot is written; no .diaphora)")
    Run.add_argument("--points", action="append", default=None,
                     help="fnmatch glob of points to snapshot (repeatable; default all)")
    Run.add_argument("--with-cache", action="append", default=[],
                     help="fnmatch glob of points whose snapshot includes ratios_cache (repeatable)")
    Run.add_argument("--rows", action="store_true", help="emit one `row` event per check_match call")
    Run.add_argument("--force-const-order", choices=["sorted", "rsorted"],
                     help="sensitivity measurement only (06 V4); never an oracle run")
    Run.add_argument("--hash-seed", type=int, help="run under PYTHONHASHSEED=<n> (recorded in run.json)")
    Run.add_argument("--keep-work", action="store_true", help="keep the export copies under <out>/work")
    Run.add_argument("--force", action="store_true", help="overwrite a capture that looks like it is running")
    Run.add_argument("--detach", action="store_true", help="start detached (survives this session) and return")

    Self = Sub.add_parser("selftest", help="plan §4 L0b acceptance on the finished pairs")
    Common(Self)
    Self.add_argument("--pairs", nargs="*", help="default: every pair with an oracle run1 .diaphora")
    Self.add_argument("--with-cache", action="append", default=[], help="passed to each capture")
    Self.add_argument("--hash-seed", type=int, default=12345,
                      help="PYTHONHASHSEED of the two determinism runs (default 12345)")
    Self.add_argument("--probe-seed", type=int, default=54321,
                      help="PYTHONHASHSEED of the extra R3 sensitivity run (default 54321)")
    Self.add_argument("--no-probe", dest="probe_seed", action="store_const", const=None,
                      help="skip the R3 sensitivity run")
    Self.add_argument("--report", help="report path (default <corpus>/oracle/traces/_selftest/report.json)")

    Status = Sub.add_parser("status", help="list captures and whether they are still running")
    Common(Status)

    Args = Parser.parse_args(Argv)
    if getattr(Args, "points", None) is None and Args.command == "run":
        Args.points = ["*"]
    return Args


def Main():
    Args = ParseArgs()
    if getattr(Args, "console_log", None):
        RedirectConsole(Args.console_log)
    if Args.command == "run":
        return CommandRun(Args)
    if Args.command == "selftest":
        return CommandSelftest(Args)
    return CommandStatus(Args)


if __name__ == "__main__":
    sys.exit(Main())
