#!/usr/bin/env python3

"""Headless Diaphora export of one binary under idalib (IDA 9.x).

Runs Diaphora's own exporter, diaphora_ida._diff_or_export(use_ui=False), inside
idalib and writes a JSON sidecar that records how the export was produced.

Derived from an earlier idb_export.py. The fixes over that script:
  * ida_subs is left at Diaphora's default (True), so sub_* functions ARE
    exported. The old script forced ida_subs=False, which drops every unnamed
    function and makes an export of a stripped build useless.
  * A raw binary can be analysed from scratch (auto-analysis on), with extra
    IDA command-line switches (for example -Opdb:off).
  * An exception inside Diaphora's do_export() is detected. Diaphora's
    export() catches it, logs it and still writes a partial database.
  * Every other export option is left at Diaphora's default and recorded.

Run it with a Python that can import idapro. The caller controls PDB lookup
through the environment (_NT_SYMBOL_PATH) and --ida-args; see build_oracle.py.

    python diaphora_export.py --input work/userenv.dll --out work/userenv.sqlite \
        --diaphora-dir <diaphora checkout> --meta work/userenv.export.json \
        [--ida-args "-Opdb:off"] [--no-save]
"""

import idapro  # must be the first IDA import; it loads and initialises idalib

import argparse
import hashlib
import json
import os
import sqlite3
import sys
import time
import traceback

# Diaphora's tester (tester/tester.py EXPORT_QUERY), reused verbatim so these
# numbers compare directly with the [Export] sections of tester/samples/*.cfg.
TESTER_EXPORT_QUERY = """
select 1, "Total Basic Blocks", count(*) from basic_blocks where asm_type = 'native'
union
select 2, "Total BBlocks Instructions", count(*) from bb_instructions
union
select 3, "Total BBlocks Relations", count(*) from bb_relations
union
select 4, "Total Call Graph items", count(*) from callgraph
union
select 5, "Total Constants", count(*) from constants
union
select 6, "Total Functions BBlocks", count(*) from function_bblocks
union
select 7, "Total Functions", count(*) from functions
union
select 8, "Total Instructions", count(*) from instructions where asm_type = 'native'
union
select 9, "Total Program Items", count(*) from program
union
select 10, "Total Program Data Items", count(*) from program_data
union
select 11, "Call Graph Primes", callgraph_primes from program
union
select 12, "Compilation Units", count(*) from compilation_units
union
select 13, "Named Compilation Units", count(*) from compilation_units where name != '' and name is not null
union
select 14, "Total Microcode Basic Blocks", count(*) from basic_blocks where asm_type = 'microcode'
union
select 15, "Total Microcode Instructions", count(*) from instructions where asm_type = 'microcode'
union
select 16, "Total Callers", count(*) from callgraph where type = 'caller'
union
select 17, "Total Callees", count(*) from callgraph where type = 'callee'
"""


def Log(Message):
    print(Message, flush=True)


def Sha256OfFile(Path):
    Digest = hashlib.sha256()
    with open(Path, "rb") as Handle:
        for Chunk in iter(lambda: Handle.read(1024 * 1024), b""):
            Digest.update(Chunk)
    return Digest.hexdigest()


def ParseArgs():
    Parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    Parser.add_argument("--input", required=True,
                        help="binary to analyse, or an existing .i64/.idb")
    Parser.add_argument("--out", required=True, help="Diaphora .sqlite to write")
    Parser.add_argument("--diaphora-dir", required=True, help="Diaphora source tree")
    Parser.add_argument("--meta", required=True, help="JSON sidecar to write")
    Parser.add_argument("--ida-args", default="",
                        help="extra IDA command-line switches passed to open_database")
    Parser.add_argument("--no-save", action="store_true",
                        help="do not save the IDA database on close")
    return Parser.parse_args()


def ShimDiaphoraUi(DiaphoraIda):
    """Replace the few UI calls Diaphora makes during an export.

    None of them changes what is exported: they are progress boxes, the
    'overwrite?' question (the output is deleted beforehand) and warnings.
    """
    def NoOp(*Args, **Kwargs):
        return None

    def Warn(Message, *Args):
        Log("[diaphora:warning] %s" % str(Message).replace("\n", " ").strip())

    for Name in ("show_wait_box", "hide_wait_box", "replace_wait_box"):
        setattr(DiaphoraIda, Name, NoOp)
    DiaphoraIda.warning = Warn
    DiaphoraIda.ask_yn = lambda *Args, **Kwargs: 1


def FunctionNameStats():
    import ida_funcs
    import ida_name
    import idautils

    Total = 0
    Sub = 0
    Lib = 0
    Thunk = 0
    for Ea in idautils.Functions():
        Total += 1
        Name = ida_name.get_name(Ea) or ""
        if Name.startswith("sub_"):
            Sub += 1
        Func = ida_funcs.get_func(Ea)
        if Func is not None:
            if Func.flags & ida_funcs.FUNC_LIB:
                Lib += 1
            if Func.flags & ida_funcs.FUNC_THUNK:
                Thunk += 1
    return {"total": Total, "sub_prefixed": Sub, "non_sub": Total - Sub,
            "library_flag": Lib, "thunk_flag": Thunk}


def PdbEvidence():
    """What the IDA database says about PDB loading."""
    import ida_netnode
    Evidence = {}
    try:
        Node = ida_netnode.netnode("$ pdb", 0, False)
        Exists = Node.index() != ida_netnode.BADNODE
        Evidence["pdb_netnode_exists"] = Exists
        if Exists:
            Evidence["pdb_netnode_supvals"] = {}
            Evidence["pdb_netnode_altvals"] = {}
            for Index in range(0, 8):
                Value = Node.supstr(Index)
                if Value:
                    Evidence["pdb_netnode_supvals"][Index] = Value
                Alt = Node.altval(Index)
                if Alt:
                    Evidence["pdb_netnode_altvals"][Index] = Alt
    except Exception as Exc:
        Evidence["error"] = str(Exc)
    return Evidence


def ExportStats(SqlitePath):
    Handle = sqlite3.connect(SqlitePath)
    try:
        Cursor = Handle.cursor()
        Stats = {}
        Cursor.execute(TESTER_EXPORT_QUERY)
        Stats["tester_export_query"] = {Row[1].lower(): Row[2] for Row in Cursor.fetchall()}

        def One(Sql):
            Cursor.execute(Sql)
            return Cursor.fetchone()[0]

        Stats["functions"] = One("select count(*) from functions")
        Stats["functions_named"] = One("select count(*) from functions where name not like 'sub\\_%' escape '\\'")
        Stats["functions_sub"] = One("select count(*) from functions where name like 'sub\\_%' escape '\\'")
        Stats["functions_with_pseudocode"] = One(
            "select count(*) from functions where pseudocode is not null and pseudocode != ''")
        Stats["functions_with_microcode"] = One(
            "select count(*) from functions where microcode is not null and microcode != ''")
        Stats["version_table"] = One("select value from version")
        Cursor.execute("select name from sqlite_master where type='table' order by name")
        Stats["tables"] = [Row[0] for Row in Cursor.fetchall()]
        return Stats
    finally:
        Handle.close()


def Main():
    Args = ParseArgs()
    InputPath = os.path.abspath(Args.input)
    OutSqlite = os.path.abspath(Args.out)
    DiaphoraDir = os.path.abspath(Args.diaphora_dir)
    Meta = {
        "input": InputPath,
        "input_sha256": Sha256OfFile(InputPath),
        "input_size": os.path.getsize(InputPath),
        "out": OutSqlite,
        "ida_args": Args.ida_args,
        "env": {Key: os.environ.get(Key) for Key in
                ("_NT_SYMBOL_PATH", "_NT_ALT_SYMBOL_PATH", "IDAUSR", "IDADIR")},
        "idalib_version": list(idapro.get_library_version() or ()),
        "python": sys.version,
    }

    IsDatabase = InputPath.lower().endswith((".i64", ".idb"))
    idapro.enable_console_messages(True)
    Log("[oracle] opening %s (auto-analysis=%s, args=%r)" % (InputPath, not IsDatabase, Args.ida_args))
    Started = time.monotonic()
    Status = idapro.open_database(InputPath, not IsDatabase, Args.ida_args or None)
    if Status != 0:
        Log("[oracle] open_database failed with code %s" % Status)
        return 2
    Meta["analysis_seconds"] = round(time.monotonic() - Started, 3)
    Log("[oracle] database ready in %.1fs" % Meta["analysis_seconds"])

    ExitCode = 0
    try:
        import idaapi
        import ida_auto
        import ida_hexrays

        ida_auto.auto_wait()
        # diaphora_ida only imports PySide6 when not in batch mode.
        idaapi.cvar.batch = True
        Meta["ida_kernel_version"] = idaapi.get_kernel_version()
        Meta["ida_function_names"] = FunctionNameStats()
        Meta["pdb_evidence"] = PdbEvidence()

        HexRays = bool(ida_hexrays.init_hexrays_plugin())
        Meta["hexrays_available"] = HexRays
        Meta["hexrays_version"] = ida_hexrays.get_hexrays_version() if HexRays else None
        Log("[oracle] hex-rays: %s" % Meta["hexrays_version"])
        if not HexRays:
            raise RuntimeError("Hex-Rays decompiler is not available; refusing a decompiler-less export")

        sys.path.insert(0, DiaphoraDir)
        import diaphora_config
        import diaphora_ida
        ShimDiaphoraUi(diaphora_ida)

        # Detect an exception inside do_export(); Diaphora's export() swallows it.
        Failures = []
        OriginalDoExport = diaphora_ida.CIDABinDiff.do_export

        def CheckedDoExport(Self, *A, **K):
            try:
                return OriginalDoExport(Self, *A, **K)
            except BaseException as Exc:
                Failures.append("".join(traceback.format_exception(Exc)))
                raise
        diaphora_ida.CIDABinDiff.do_export = CheckedDoExport

        for Stale in (OutSqlite, OutSqlite + "-wal", OutSqlite + "-shm", OutSqlite + "-crash"):
            if os.path.exists(Stale):
                os.remove(Stale)

        # Only the output path is passed. Every other option falls back to
        # BinDiffOptions' defaults, i.e. diaphora_config.py.
        Log("[oracle] diaphora %s export -> %s" % (diaphora_ida.diaphora.VERSION_VALUE, OutSqlite))
        ExportStarted = time.monotonic()
        Bd = diaphora_ida._diff_or_export(use_ui=False, file_out=OutSqlite, file_in="")
        Meta["export_seconds"] = round(time.monotonic() - ExportStarted, 3)
        if Bd is None:
            raise RuntimeError("_diff_or_export returned None; the export did not run")
        if Failures:
            raise RuntimeError("Diaphora do_export raised:\n" + Failures[0])
        if os.path.exists(OutSqlite + "-crash"):
            raise RuntimeError("Diaphora left a -crash marker; the export is incomplete")

        Meta["diaphora_version_value"] = diaphora_ida.diaphora.VERSION_VALUE
        Meta["diaphora_options"] = {
            "use_decompiler": Bd.use_decompiler,
            "decompiler_available_after_export": Bd.decompiler_available,
            "export_microcode": Bd.export_microcode,
            "ida_subs": Bd.ida_subs,
            "exclude_library_thunk": Bd.exclude_library_thunk,
            "function_summaries_only": Bd.function_summaries_only,
            "min_ea": hex(Bd.min_ea),
            "max_ea": hex(Bd.max_ea),
            "project_script": Bd.project_script,
        }
        Meta["diaphora_config"] = {Key: getattr(diaphora_config, Key) for Key in (
            "EXPORTING_USE_DECOMPILER", "EXPORTING_EXCLUDE_LIBRARY_THUNK",
            "EXPORTING_ONLY_NON_IDA_SUBS", "EXPORTING_FUNCTION_SUMMARIES_ONLY",
            "EXPORTING_USE_MICROCODE", "EXPORTING_COMPILATION_UNITS",
            "MIN_FUNCTIONS_TO_CONSIDER_MEDIUM", "MIN_FUNCTIONS_TO_CONSIDER_HUGE",
            "DIAPHORA_WORKAROUND_MAX_TINFO_T")}
        if not Bd.ida_subs:
            raise RuntimeError("ida_subs is False: sub_* functions would have been dropped")
        if not Bd.decompiler_available:
            raise RuntimeError("Diaphora lost the decompiler during the export")
    except Exception as Exc:
        traceback.print_exc()
        Meta["error"] = str(Exc)
        ExitCode = 1
    finally:
        idapro.close_database(not Args.no_save)
        Log("[oracle] database closed (save=%s)" % (not Args.no_save))

    if ExitCode == 0:
        for Leftover in (OutSqlite + "-wal", OutSqlite + "-shm"):
            if os.path.exists(Leftover):
                Meta.setdefault("warnings", []).append("leftover " + Leftover)
        Meta["sqlite_size"] = os.path.getsize(OutSqlite)
        Meta["sqlite_sha256"] = Sha256OfFile(OutSqlite)
        Meta["export_stats"] = ExportStats(OutSqlite)
        Stats = Meta["export_stats"]
        Log("[oracle] exported %d functions (%d named, %d sub_*, %d with pseudocode, %d with microcode)"
            % (Stats["functions"], Stats["functions_named"], Stats["functions_sub"],
               Stats["functions_with_pseudocode"], Stats["functions_with_microcode"]))
        if Stats["functions_with_pseudocode"] == 0:
            Meta["error"] = "no function has pseudocode"
            ExitCode = 1

    with open(Args.meta, "w", encoding="utf-8") as Handle:
        json.dump(Meta, Handle, indent=2, default=str)
    Log("[oracle] meta -> %s" % Args.meta)
    return ExitCode


if __name__ == "__main__":
    sys.exit(Main())
