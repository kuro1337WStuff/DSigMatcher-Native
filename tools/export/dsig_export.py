#!/usr/bin/env python3

"""dsig_export: export a binary or an IDA database with IDA idalib and the unmodified Diaphora exporter.

    python dsig_export.py idb    <in.i64|in.idb> -o <out.sqlite> --diaphora-dir <diaphora> [options]
    python dsig_export.py binary <in.exe|dll|elf> -o <out.sqlite> --diaphora-dir <diaphora>
                                 [--pdb <file> | --no-pdb] [options]

Modes:
  idb     Export an existing IDA database and keep every name the user gave it. The database is
          copied into a private work directory first (idalib unpacks and repacks a database in
          place), opened WITHOUT auto-analysis, and closed WITHOUT saving. The sha256 of the
          original is checked before and after; a change fails the run.
  binary  Analyse a raw PE/ELF/Mach-O from scratch (auto-analysis) in a private work directory.
          The default is NO PDB and no symbol server: IDA's PDB plugin is switched off
          (-Opdb:off) and _NT_SYMBOL_PATH is an empty local directory, so the result does not
          depend on the network. `--pdb <file>` applies exactly that PDB: its GUID and age must
          match the binary's RSDS record, it is placed next to the work copy under the name the
          binary asks for, and _NT_SYMBOL_PATH is that directory only (no SRV* entry).

Both modes run Diaphora's own exporter, diaphora_ida._diff_or_export(use_ui=False, file_out=...),
from the Diaphora checkout named by --diaphora-dir (or DSIG_DIAPHORA_DIR). Diaphora is AGPL and is
never vendored or modified: it is imported read-only (no bytecode written). Only the output path is
passed, so every export option is Diaphora's diaphora_config.py default. In particular sub_*
functions ARE exported (ida_subs=True) and library/thunk functions are skipped
(exclude_library_thunk=True). The resolved options are recorded in the sidecar.

IDA runs with an isolated, empty IDAUSR, so the user's own plugins, scripts and settings do not
load. Plugins that live in the IDA installation's own plugins/ directory DO still load (for example
third-party DLLs or scripts someone copied there); their names are recorded in the sidecar.

The output is written atomically: the destination is replaced only after the export has been
checked. Next to it goes a JSON sidecar, <output stem>.export.json (schema dsig-export/1), with the
input sha256 (before and after), the IDA, Hex-Rays and Diaphora versions, the options and the
export counts.

Exit codes (mirrored by src/cli/ExportBridge.cpp):
  0 ok               2 usage                 10 input missing or unreadable
  11 IDA not found   12 Diaphora not found   13 Hex-Rays decompiler unavailable
  14 PDB invalid     15 IDA cannot open it   16 export failed
  17 INPUT CHANGED   18 timeout              19 output not writable
  20 internal error  130 interrupted
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback

TOOL_NAME = "dsig_export"
TOOL_VERSION = "1.0"
SIDECAR_SCHEMA = "dsig-export/1"

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_INPUT = 10
EXIT_IDA = 11
EXIT_DIAPHORA = 12
EXIT_HEXRAYS = 13
EXIT_PDB = 14
EXIT_OPEN = 15
EXIT_EXPORT = 16
EXIT_INPUT_CHANGED = 17
EXIT_TIMEOUT = 18
EXIT_OUTPUT = 19
EXIT_INTERNAL = 20
EXIT_INTERRUPTED = 130

# Diaphora refuses to export into these (diaphora_ida.py:3978-3987 is_ida_file, used at :3664). A .pdb
# is never a valid export name either (audit F02: `-o x.pdb --pdb x.pdb` replaced the PDB).
IDA_EXTENSIONS = (".idb", ".i64", ".til", ".id0", ".id1", ".nam")
REFUSED_OUTPUT_EXTENSIONS = IDA_EXTENSIONS + (".pdb",)

# The longest --timeout (30 days), the same cap as src/cli/ExportBridge.cpp kMaxTimeoutSeconds: on Windows
# Popen.wait cannot take much more than 2^32 ms (audit F42).
MAX_TIMEOUT_SECONDS = 30 * 24 * 3600

# Work directories: tempfile.mkdtemp(prefix=WORK_PREFIX) names, and the file that says who owns one.
WORK_PREFIX = "dsig-export-"
WORK_NAME_RE = re.compile(r"^dsig-export-[a-z0-9_]{8}$")
OWNER_FILE = "owner.json"
# A work directory without an owner file (a version before owner files, or a run killed in the instant
# between mkdtemp and the owner file) is only swept once it is this old.
UNOWNED_SWEEP_AGE_SECONDS = 48 * 3600
# What an IDA database left unpacked next to its packed file looks like (open in IDA, or crashed).
UNPACKED_EXTENSIONS = (".id0", ".id1", ".id2", ".nam", ".til")

# Diaphora's tester (tester/tester.py EXPORT_QUERY), the same numbers tools/oracle records.
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

PDB_TOTAL_RE = re.compile(r"PDB: total (\d+) symbols loaded")
PLUGIN_LOADED_RE = re.compile(r"^(.+?): [Pp]lugin (?:has been )?loaded")


class ExportError(Exception):
    def __init__(self, Code, Message):
        Exception.__init__(self, Message)
        self.Code = Code
        self.Message = Message


def Log(Message):
    try:
        print("[%s] %s" % (TOOL_NAME, Message), flush=True)
    except (OSError, ValueError):
        pass  # the reader of our stdout went away; keep cleaning up


def LogError(Message):
    try:
        print("%s: error: %s" % (TOOL_NAME, Message), flush=True)
    except (OSError, ValueError):
        pass


def Sha256OfFile(Path):
    Digest = hashlib.sha256()
    with open(Path, "rb") as Handle:
        for Chunk in iter(lambda: Handle.read(1024 * 1024), b""):
            Digest.update(Chunk)
    return Digest.hexdigest()


def UtcNow():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def WriteJsonAtomic(Path, Data):
    Temporary = "%s.tmp-%d" % (Path, os.getpid())
    with open(Temporary, "w", encoding="utf-8") as Handle:
        json.dump(Data, Handle, indent=2, default=str, ensure_ascii=False)
        Handle.write("\n")
    os.replace(Temporary, Path)


def DefaultSidecar(Output):
    """<output stem>.export.json: -o out.sqlite gives out.export.json (the oracle's <id>.export.json)."""
    Root, Extension = os.path.splitext(Output)
    return (Root if Extension else Output) + ".export.json"


# Windows creation flags of the IDA worker: none. In particular never CREATE_DEFAULT_ERROR_MODE
# (0x04000000), which would give the worker the default error mode, with "Bad Image" and crash dialogs.
WORKER_CREATION_FLAGS = 0

# The only PYTHON* variables the IDA worker gets; every other one is removed by CleanEnv.
WORKER_PYTHON_ENV = {"PYTHONDONTWRITEBYTECODE": "1", "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1",
                     "PYTHONUNBUFFERED": "1"}


def CleanEnv():
    """The caller's environment minus everything that steers Diaphora (CBinDiff.__init__ reads
    DIAPHORA_<name> through get_value_for, diaphora.py:400-421 and :560-569) or idapro, and minus every
    PYTHON* variable but the four set here: PYTHONPATH, PYTHONHOME, PYTHONSTARTUP and the like would let
    a module from the caller's environment shadow idapro, Diaphora or this script in the worker (audit
    F66). The names removed (never the values) are returned for the sidecar.

    NoDefaultCurrentDirectoryInExePath=1 keeps Windows from resolving a program started by a bare name
    in the current directory, for the worker and everything it starts (audit F16)."""
    Removed = [Key for Key in os.environ
               if Key.upper().startswith("DIAPHORA_")
               or (Key.upper().startswith("PYTHON") and Key.upper() not in WORKER_PYTHON_ENV)]
    Env = {Key: Value for Key, Value in os.environ.items() if Key not in Removed}
    for Key in ("IDA_IS_INTERACTIVE", "_NT_ALT_SYMBOL_PATH", "_NT_SYMCACHE_PATH"):
        if Key in Env:
            Env.pop(Key)
            Removed.append(Key)
    for Key in [Key for Key in Env if Key.upper() in WORKER_PYTHON_ENV]:
        Env.pop(Key)  # a case variant on POSIX; the canonical spelling is set below
    Env.update(WORKER_PYTHON_ENV)
    Env["NoDefaultCurrentDirectoryInExePath"] = "1"
    return Env, sorted(Removed)


# ----------------------------------------------------------------------------- PE / PDB identity

def InputKind(Path):
    with open(Path, "rb") as Handle:
        Head = Handle.read(4)
    if Head[:2] == b"MZ":
        return "pe" if ReadPe(Path)[0] is not None else "mz"
    if Head == b"\x7fELF":
        return "elf"
    if Head in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
                b"\xca\xfe\xba\xbe"):
        return "macho"
    return "other"


def ReadPe(Path):
    """(headers, error) for a PE file: machine, sections and data directories."""
    with open(Path, "rb") as Handle:
        Data = Handle.read()
    if len(Data) < 0x40 or Data[:2] != b"MZ":
        return None, "no MZ header"
    PeOffset = struct.unpack_from("<I", Data, 0x3C)[0]
    if PeOffset + 24 > len(Data) or Data[PeOffset:PeOffset + 4] != b"PE\x00\x00":
        return None, "no PE signature"
    Machine, SectionCount, _Stamp, _Symbols, _SymbolCount, OptionalSize, _Flags = struct.unpack_from(
        "<HHIIIHH", Data, PeOffset + 4)
    Optional = PeOffset + 24
    if Optional + 2 > len(Data):
        return None, "truncated optional header"
    Magic = struct.unpack_from("<H", Data, Optional)[0]
    if Magic == 0x10B:
        DirectoryOffset = Optional + 96
    elif Magic == 0x20B:
        DirectoryOffset = Optional + 112
    else:
        return None, "unknown optional header magic 0x%x" % Magic
    DirectoryCount = struct.unpack_from("<I", Data, DirectoryOffset - 4)[0]
    Directories = []
    for Index in range(min(DirectoryCount, 16)):
        if DirectoryOffset + 8 * Index + 8 > len(Data):
            break
        Directories.append(struct.unpack_from("<II", Data, DirectoryOffset + 8 * Index))
    Sections = []
    SectionTable = Optional + OptionalSize
    for Index in range(SectionCount):
        Offset = SectionTable + 40 * Index
        if Offset + 40 > len(Data):
            break
        _Name, VirtualSize, VirtualAddress, RawSize, RawPointer = struct.unpack_from("<8sIIII", Data, Offset)
        Sections.append((VirtualAddress, max(VirtualSize, RawSize), RawPointer, RawSize))
    return {"data": Data, "machine": Machine, "directories": Directories, "sections": Sections}, None


def RvaToOffset(Pe, Rva):
    for VirtualAddress, Size, RawPointer, RawSize in Pe["sections"]:
        if VirtualAddress <= Rva < VirtualAddress + Size and Rva - VirtualAddress < RawSize:
            return RawPointer + (Rva - VirtualAddress)
    return None


def ReadCodeView(Path):
    """The PE's CodeView RSDS record: {"pdb_name", "pdb_path", "guid", "age"}, or (None, why).

    Same GUID spelling as tools/prepare_corpus.py ReadCodeView (upper-case hex, no dashes)."""
    Pe, Error = ReadPe(Path)
    if Pe is None:
        return None, "not a PE file (%s)" % Error
    if len(Pe["directories"]) <= 6 or Pe["directories"][6][1] == 0:
        return None, "the PE has no debug directory"
    DebugRva, DebugSize = Pe["directories"][6]
    DebugOffset = RvaToOffset(Pe, DebugRva)
    if DebugOffset is None:
        return None, "the debug directory is outside every section"
    Data = Pe["data"]
    for Index in range(DebugSize // 28):
        Offset = DebugOffset + 28 * Index
        if Offset + 28 > len(Data):
            break
        (_Characteristics, _Stamp, _Major, _Minor, Type, Size, AddressOfRawData,
         PointerToRawData) = struct.unpack_from("<IIHHIIII", Data, Offset)
        if Type != 2 or Size < 24:  # IMAGE_DEBUG_TYPE_CODEVIEW
            continue
        Start = PointerToRawData if PointerToRawData else RvaToOffset(Pe, AddressOfRawData)
        if Start is None or Start + Size > len(Data):
            continue
        Blob = Data[Start:Start + Size]
        if Blob[:4] != b"RSDS":
            continue
        Data1, Data2, Data3 = struct.unpack_from("<IHH", Blob, 4)
        Age = struct.unpack_from("<I", Blob, 20)[0]
        RawName = Blob[24:].split(b"\x00", 1)[0].decode("utf-8", "replace")
        return {"pdb_path": RawName,
                "pdb_name": os.path.basename(RawName.replace("\\", "/")),
                "guid": "%08X%04X%04X%s" % (Data1, Data2, Data3, Blob[12:20].hex().upper()),
                "age": Age}, None
    return None, "the PE has no RSDS CodeView record"


MSF7_MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"


def ReadPdbIdentity(Path):
    """GUID and ages of an MSF 7.00 PDB (the layout tools/oracle/pdb_info.py documents), reading only
    the superblock, the stream directory, the PDB info stream and the first block of the DBI stream."""
    with open(Path, "rb") as Handle:
        Size = os.fstat(Handle.fileno()).st_size
        Head = Handle.read(len(MSF7_MAGIC) + 24)
        if len(Head) < len(MSF7_MAGIC) + 24 or not Head.startswith(MSF7_MAGIC):
            raise ValueError("not an MSF 7.00 PDB")
        BlockSize, _FreeMap, BlockCount, DirectoryBytes, _Unknown, BlockMapAddress = struct.unpack_from(
            "<6I", Head, len(MSF7_MAGIC))
        if BlockSize not in (512, 1024, 2048, 4096, 8192, 16384, 32768):
            raise ValueError("unexpected MSF block size %d" % BlockSize)
        if BlockCount * BlockSize > Size:
            raise ValueError("the PDB is shorter than its %d blocks" % BlockCount)

        def Block(Index):
            if Index >= BlockCount:
                raise ValueError("MSF block %d out of range" % Index)
            Handle.seek(Index * BlockSize)
            return Handle.read(BlockSize)

        def Blocks(Bytes):
            return (Bytes + BlockSize - 1) // BlockSize

        DirectoryBlockCount = Blocks(DirectoryBytes)
        Handle.seek(BlockMapAddress * BlockSize)
        DirectoryBlocks = struct.unpack("<%dI" % DirectoryBlockCount, Handle.read(4 * DirectoryBlockCount))
        Directory = b"".join(Block(Index) for Index in DirectoryBlocks)[:DirectoryBytes]
        (StreamCount,) = struct.unpack_from("<I", Directory, 0)
        Sizes = struct.unpack_from("<%dI" % StreamCount, Directory, 4)
        Offset = 4 + 4 * StreamCount
        Streams = {}
        for Stream, StreamSize in enumerate(Sizes):
            Count = 0 if StreamSize == 0xFFFFFFFF else Blocks(StreamSize)
            BlockList = struct.unpack_from("<%dI" % Count, Directory, Offset)
            Offset += 4 * Count
            if Stream == 1 and Count:
                Streams[1] = b"".join(Block(Index) for Index in BlockList)[:StreamSize]
            elif Stream == 3 and Count:
                Streams[3] = Block(BlockList[0])[:min(StreamSize, BlockSize)]
            if Stream >= 3:
                break
    Info = Streams.get(1, b"")
    if len(Info) < 28:
        raise ValueError("the PDB info stream is missing or short")
    _Version, _Signature, InfoAge = struct.unpack_from("<3I", Info, 0)
    Data1, Data2, Data3 = struct.unpack_from("<IHH", Info, 12)
    Identity = {"guid": "%08X%04X%04X%s" % (Data1, Data2, Data3, Info[20:28].hex().upper()),
                "info_age": InfoAge, "dbi_age": None}
    Dbi = Streams.get(3, b"")
    if len(Dbi) >= 12:
        # DBI header: int32 VersionSignature, uint32 VersionHeader, uint32 Age (the RSDS age).
        Identity["dbi_age"] = struct.unpack_from("<I", Dbi, 8)[0]
    return Identity


# ----------------------------------------------------------------------------- tool discovery

def IdaLibraryName():
    if sys.platform == "win32":
        return "idalib.dll"
    if sys.platform == "darwin":
        return "libidalib.dylib"
    return "libidalib.so"


def FindIdaLibrary(Directory, MaxDepth=3):
    """The idapro package's search (idapro/__init__.py find_file: os.walk from the root), limited to a
    few levels so a wrong directory (a drive root, say) fails quickly instead of walking the disk."""
    Name = IdaLibraryName()
    if os.path.isfile(os.path.join(Directory, Name)):
        return os.path.join(Directory, Name)
    Base = Directory.rstrip("\\/").count(os.sep)
    for Root, Dirs, Files in os.walk(Directory):
        if Name in Files:
            return os.path.join(Root, Name)
        if Root.rstrip("\\/").count(os.sep) - Base >= MaxDepth:
            Dirs[:] = []
    return None


def UserIdaDirectories():
    """The user's real IDAUSR directories (before we isolate it), for ida-config.json and licences."""
    Value = os.environ.get("IDAUSR")
    if Value:
        return [Part for Part in Value.split(os.pathsep) if Part]
    if sys.platform == "win32":
        return [os.path.join(os.environ.get("APPDATA", ""), "Hex-Rays", "IDA Pro")]
    return [os.path.join(os.path.expanduser("~"), ".idapro")]


def ResolveIdaDir(Flag):
    """--ida-dir, else DSIG_IDADIR, else IDADIR, else idapro's ida-config.json "ida-install-dir"."""
    Candidates = [(Flag, "--ida-dir"), (os.environ.get("DSIG_IDADIR"), "DSIG_IDADIR"),
                  (os.environ.get("IDADIR"), "IDADIR")]
    for Directory in UserIdaDirectories():
        ConfigPath = os.path.join(Directory, "ida-config.json")
        try:
            with open(ConfigPath, "r", encoding="utf-8") as Handle:
                Value = (json.load(Handle).get("Paths") or {}).get("ida-install-dir")
            Candidates.append((Value, ConfigPath))
        except (OSError, ValueError, AttributeError):
            pass
    for Value, Source in Candidates:
        if not Value:
            continue
        Directory = os.path.abspath(Value)
        if not os.path.isdir(Directory):
            raise ExportError(EXIT_IDA, "IDA not found: %s = '%s' is not a directory" % (Source, Value))
        Library = FindIdaLibrary(Directory)
        if Library is None:
            raise ExportError(EXIT_IDA, "IDA not found: no %s under '%s' (from %s); IDA 9.0 or newer with "
                              "idalib is required" % (IdaLibraryName(), Directory, Source))
        return Directory, Source, Library
    raise ExportError(EXIT_IDA, "IDA not found: pass --ida-dir <IDA install> or set DSIG_IDADIR")


def ResolveDiaphoraDir(Flag):
    Value, Source = (Flag, "--diaphora-dir") if Flag else (os.environ.get("DSIG_DIAPHORA_DIR"), "DSIG_DIAPHORA_DIR")
    if not Value:
        raise ExportError(EXIT_DIAPHORA, "Diaphora not found: pass --diaphora-dir <Diaphora checkout> or set "
                          "DSIG_DIAPHORA_DIR (Diaphora is not bundled; it is AGPL)")
    Directory = os.path.abspath(Value)
    if not os.path.isdir(Directory):
        raise ExportError(EXIT_DIAPHORA, "Diaphora not found: %s = '%s' is not a directory" % (Source, Value))
    Missing = [Name for Name in ("diaphora.py", "diaphora_ida.py", "diaphora_config.py")
               if not os.path.isfile(os.path.join(Directory, Name))]
    if Missing:
        raise ExportError(EXIT_DIAPHORA, "Diaphora not found: '%s' (from %s) has no %s"
                          % (Directory, Source, ", ".join(Missing)))
    return Directory, Source


def FindProgramOnPath(Name):
    """The absolute path of program Name found in an ABSOLUTE PATH entry, or None.

    Never the current directory: on Windows, CreateProcess (and so subprocess with a bare "git") and
    shutil.which before Python 3.12 look there first, and the current directory is often the folder of
    the sample being analysed, where anyone can plant a git.exe (audit F16). Empty and relative PATH
    entries ("", ".", "bin") are skipped for the same reason."""
    Names = [Name + ".exe"] if sys.platform == "win32" and not os.path.splitext(Name)[1] else [Name]
    for Entry in os.environ.get("PATH", "").split(os.pathsep):
        Entry = Entry.strip().strip('"')
        if not Entry or not os.path.isabs(Entry):
            continue
        for Candidate in (os.path.join(Entry, Each) for Each in Names):
            if os.path.isfile(Candidate) and (sys.platform == "win32" or os.access(Candidate, os.X_OK)):
                return os.path.abspath(Candidate)
    return None


# What `git describe --tags --long --always` prints: tag-count-gsha, or a bare abbreviated sha.
GIT_DESCRIBE_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._/+-]{0,199}$")


def DiaphoraIdentity(Directory):
    """VERSION_VALUE (read from diaphora.py:100 as text, not imported) and the git revision.

    git runs with GIT_OPTIONAL_LOCKS=0 and without `describe --dirty`, so it never rewrites the
    checkout's index: the Diaphora tree is only ever read. git is found on PATH only
    (FindProgramOnPath), runs inside the Diaphora checkout with no stdin, and what it prints is kept only
    when it looks like a describe string."""
    Identity = {"version_value": None, "git_describe": None, "git_dirty": None}
    try:
        with open(os.path.join(Directory, "diaphora.py"), "r", encoding="utf-8", errors="replace") as Handle:
            Match = re.search(r'^VERSION_VALUE\s*=\s*"([^"]*)"', Handle.read(), re.M)
        Identity["version_value"] = Match.group(1) if Match else None
    except OSError:
        pass
    Git = FindProgramOnPath("git")
    if Git is None:
        return Identity
    Env = dict(os.environ, GIT_OPTIONAL_LOCKS="0", NoDefaultCurrentDirectoryInExePath="1")
    try:
        Describe = subprocess.run([Git, "-C", Directory, "describe", "--tags", "--long", "--always"],
                                  capture_output=True, text=True, env=Env, cwd=Directory,
                                  stdin=subprocess.DEVNULL, timeout=30)
        Text = Describe.stdout.strip()
        if Describe.returncode == 0 and GIT_DESCRIBE_RE.match(Text):
            Identity["git_describe"] = Text
            Status = subprocess.run([Git, "-C", Directory, "status", "--porcelain", "--untracked-files=no"],
                                    capture_output=True, text=True, env=Env, cwd=Directory,
                                    stdin=subprocess.DEVNULL, timeout=60)
            if Status.returncode == 0:
                Identity["git_dirty"] = bool(Status.stdout.strip())
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    return Identity


# ----------------------------------------------------------------------------- driver

def ParseArgs(Argv):
    Parser = argparse.ArgumentParser(
        prog="dsig_export.py", formatter_class=argparse.RawDescriptionHelpFormatter,
        description=__doc__.split("\n\n")[0], epilog="See tools/export/README.md.")
    Parser.add_argument("--version", action="version", version="%s %s" % (TOOL_NAME, TOOL_VERSION))
    Modes = Parser.add_subparsers(dest="mode", metavar="{idb,binary}")
    Modes.required = True
    Common = argparse.ArgumentParser(add_help=False)
    Common.add_argument("-o", "--output", required=True, help="Diaphora export (.sqlite) to write; "
                        "replaced only when the export succeeds")
    Common.add_argument("--ida-dir", help="IDA 9.x installation with idalib (else DSIG_IDADIR, IDADIR, "
                        "then idapro's ida-config.json)")
    Common.add_argument("--diaphora-dir", help="Diaphora checkout (else DSIG_DIAPHORA_DIR); used unmodified")
    Common.add_argument("--temp-dir", help="parent of the private work directory (else the system temp)")
    Common.add_argument("--keep-temp", action="store_true", help="keep the work directory")
    Common.add_argument("--timeout", type=int, default=0, help="stop IDA after this many seconds (0: none)")
    Common.add_argument("--sidecar", help="sidecar path (default: <output stem>.export.json)")
    Common.add_argument("--allow-no-decompiler", action="store_true",
                        default=os.environ.get("DSIG_EXPORT_ALLOW_NO_DECOMPILER") == "1",
                        help="export even without Hex-Rays (no pseudo-code or microcode); such an export "
                        "must not be diffed against one that has them (dsigmatcher extract/ingest/update "
                        "forward their own --allow-no-decompiler; default: DSIG_EXPORT_ALLOW_NO_DECOMPILER=1)")
    Idb = Modes.add_parser("idb", parents=[Common], help="export an existing .i64/.idb (copied, never saved)")
    Idb.add_argument("input", help="IDA database (.i64 or .idb)")
    Binary = Modes.add_parser("binary", parents=[Common], help="analyse a raw binary and export it")
    Binary.add_argument("input", help="PE, ELF or other binary IDA can load")
    Pdb = Binary.add_mutually_exclusive_group()
    Pdb.add_argument("--pdb", help="apply exactly this PDB (it must match the binary's RSDS GUID and age)")
    Pdb.add_argument("--no-pdb", action="store_true", help="no PDB and no symbol server (the default)")
    Args = Parser.parse_args(Argv)
    if Args.timeout < 0 or Args.timeout > MAX_TIMEOUT_SECONDS:
        Parser.error("--timeout must be between 0 and %d seconds (30 days)" % MAX_TIMEOUT_SECONDS)
    if Args.mode == "idb":
        Args.pdb = None
        Args.no_pdb = False
    return Args


class WorkerOutput(threading.Thread):
    """Streams the worker's merged stdout/stderr to ours and to worker.log, and keeps the evidence
    the checks need (PDB lines, plugin lines)."""

    def __init__(self, Stream, LogPath):
        threading.Thread.__init__(self, daemon=True)
        self.Stream = Stream
        self.LogPath = LogPath
        self.PdbLines = []
        self.PdbTotals = []
        self.PluginLines = []

    def run(self):
        with open(self.LogPath, "wb") as LogHandle:
            for Raw in iter(self.Stream.readline, b""):
                LogHandle.write(Raw)
                Line = Raw.decode("utf-8", "replace").rstrip("\r\n")
                if Line.startswith("PDB:"):
                    self.PdbLines.append(Line)
                self.PdbTotals += [int(Value) for Value in PDB_TOTAL_RE.findall(Line)]
                if PLUGIN_LOADED_RE.match(Line.strip()):
                    self.PluginLines.append(Line.strip())
                try:
                    sys.stdout.write(Line + "\n")
                    sys.stdout.flush()
                except (OSError, ValueError):
                    pass


def RemoveTree(Path):
    for Attempt in range(10):
        try:
            shutil.rmtree(Path)
            return True
        except FileNotFoundError:
            return True
        except OSError:
            time.sleep(0.2 * (Attempt + 1))
    return not os.path.exists(Path)


def RemoveIfFile(Path):
    if os.path.isfile(Path):
        os.remove(Path)


# Files that belong to the database at an output path: SQLite's -wal, -shm and -journal
# (https://www.sqlite.org/tempfiles.html; a stale -wal or a hot -journal would be replayed into the NEW
# file on its next open) and Diaphora's -crash marker (diaphora_ida.py:1292, :3672).
OUTPUT_SIDECARS = ("-wal", "-shm", "-journal", "-crash")


def PublishOutput(Source, Output):
    """Replaces Output with a copy of Source atomically, without losing the previous output on failure.

    The copy is staged beside the destination and moved over it with os.replace. The previous output's
    sidecars must not outlive the replace, but they are only renamed aside until the replace has
    succeeded and are renamed back when it fails, so a failed publish leaves the previous output and
    its -wal (which may hold committed transactions) exactly as they were (lane F1: they used to be
    deleted before the replace was even attempted)."""
    Staging = "%s.dsig-tmp-%d" % (Output, os.getpid())
    try:
        shutil.copyfile(Source, Staging)
    except OSError as Exc:
        RemoveIfFile(Staging)
        raise ExportError(EXIT_OUTPUT, "cannot write the output %s: %s" % (Output, Exc))
    Aside = []
    try:
        for Suffix in OUTPUT_SIDECARS:
            Path = Output + Suffix
            if os.path.isfile(Path):
                Moved = "%s.dsig-old-%d" % (Path, os.getpid())
                os.replace(Path, Moved)
                Aside.append((Path, Moved))
        os.replace(Staging, Output)
    except OSError as Exc:
        Kept = []
        for Path, Moved in reversed(Aside):
            try:
                os.replace(Moved, Path)
            except OSError:
                Kept.append(Moved)
        RemoveIfFile(Staging)
        Where = (" (the previous output's sidecars could not be moved back and are kept as %s)" % ", ".join(Kept)
                 if Kept else "; the previous output was left as it was")
        raise ExportError(EXIT_OUTPUT, "cannot write the output %s: %s%s" % (Output, Exc, Where))
    for _Path, Moved in Aside:
        try:
            os.remove(Moved)
        except OSError as Exc:
            Log("warning: could not remove %s: %s" % (Moved, Exc))


def CopyLicences(IdaUsr):
    """IDA looks for its *.hexlic licence in the install directory and in IDAUSR. The isolated IDAUSR
    would hide a licence kept in the user's directory, so licence files (and only those) are copied."""
    Copied = []
    for Directory in UserIdaDirectories():
        try:
            Names = os.listdir(Directory)
        except OSError:
            continue
        for Name in Names:
            if Name.lower().endswith(".hexlic") and not os.path.exists(os.path.join(IdaUsr, Name)):
                shutil.copyfile(os.path.join(Directory, Name), os.path.join(IdaUsr, Name))
                Copied.append(Name)
    return Copied


def InstallPlugins(IdaDir):
    try:
        return sorted(os.listdir(os.path.join(IdaDir, "plugins")))
    except OSError:
        return []


# ----------------------------------------------------------------------------- path aliasing (audit F02)

def SamePath(A, B):
    """A and B name one file: equal once normalised (case-insensitively where the platform's normcase
    is), or both exist and os.path.samefile says so (hard links, 8.3 short names)."""
    if os.path.normcase(os.path.abspath(A)) == os.path.normcase(os.path.abspath(B)):
        return True
    try:
        return os.path.exists(A) and os.path.exists(B) and os.path.samefile(A, B)
    except (OSError, ValueError):
        return False


def WrittenPathAlias(Output, Sidecar, Protected):
    """A refusal message when a file this run writes, replaces or moves aside is one of Protected
    ((role, path) pairs: the input and the PDB), else None. Mirrors src/cli/ExportBridge.cpp
    WrittenPathAlias: the output, its OUTPUT_SIDECARS (PublishOutput renames them aside and deletes them),
    the sidecar, and the pid-named staging, moved-aside and temporary files."""
    Refusal = "; refusing to overwrite an input (nothing was changed)"
    Written = ([("the output", Output)] + [("the output's %s file" % Suffix, Output + Suffix) for Suffix in OUTPUT_SIDECARS]
               + [("the sidecar", Sidecar)])
    for WrittenRole, WrittenPath in Written:
        for Role, Path in Protected:
            if SamePath(WrittenPath, Path):
                return "%s '%s' is %s '%s'%s" % (WrittenRole, WrittenPath, Role, Path, Refusal)
    OutputName = os.path.normcase(os.path.basename(Output))
    Prefixes = ([("the output's staging copy", OutputName + ".dsig-tmp-")]
                + [("the previous output's %s file moved aside" % Suffix, OutputName + Suffix + ".dsig-old-")
                   for Suffix in OUTPUT_SIDECARS]
                + [("the sidecar's temporary file", os.path.normcase(os.path.basename(Sidecar)) + ".tmp-")])
    for Role, Path in Protected:
        if not SamePath(os.path.dirname(Path), os.path.dirname(Output)):
            continue
        Name = os.path.normcase(os.path.basename(Path))
        for WrittenRole, Prefix in Prefixes:
            if Name.startswith(Prefix):
                return "%s '%s' has the name of %s ('%s<pid>')%s" % (Role, Path, WrittenRole, Prefix, Refusal)
    return None


# ----------------------------------------------------------------------------- work directory ownership (audit F43)

def _WindowsProcess(Pid):
    """(alive, creation time) of a process on Windows; (True, None) when it exists but cannot be queried."""
    import ctypes
    from ctypes import wintypes
    Kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    Kernel32.OpenProcess.restype = wintypes.HANDLE
    Kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    Kernel32.GetExitCodeProcess.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
    Kernel32.GetProcessTimes.argtypes = (wintypes.HANDLE,) + (ctypes.POINTER(wintypes.FILETIME),) * 4
    Kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    Handle = Kernel32.OpenProcess(0x1000, False, Pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not Handle:
        # ERROR_INVALID_PARAMETER: no such process. Anything else (access denied): it exists.
        return ctypes.get_last_error() != 87, None
    try:
        Code = wintypes.DWORD()
        Running = bool(Kernel32.GetExitCodeProcess(Handle, ctypes.byref(Code))) and Code.value == 259
        Times = [wintypes.FILETIME() for _ in range(4)]
        Created = None
        if Kernel32.GetProcessTimes(Handle, *(ctypes.byref(Each) for Each in Times)):
            Created = (Times[0].dwHighDateTime << 32) | Times[0].dwLowDateTime
        return Running, Created
    finally:
        Kernel32.CloseHandle(Handle)


def _LinuxStart(Pid):
    try:
        with open("/proc/%d/stat" % Pid, "rb") as Handle:
            Fields = Handle.read().rsplit(b")", 1)[1].split()
        return int(Fields[19])  # field 22, starttime in clock ticks since boot
    except (OSError, IndexError, ValueError):
        return None


def ProcessStart(Pid):
    """A token for when process Pid started (None when the platform cannot tell), so that a recycled pid
    is not mistaken for the process that owned a work directory."""
    try:
        if sys.platform == "win32":
            return _WindowsProcess(Pid)[1]
        return _LinuxStart(Pid)
    except Exception:
        return None


def ProcessAlive(Pid, Start=None):
    """Whether process Pid still runs (and, when both start tokens are known, is the same process).
    Doubtful cases count as alive: the sweep must never delete a running export's directory."""
    if not isinstance(Pid, int) or isinstance(Pid, bool) or Pid <= 0:
        return False
    try:
        if sys.platform == "win32":
            Running, Created = _WindowsProcess(Pid)
            return Running and (Start is None or Created is None or Created == Start)
        os.kill(Pid, 0)  # POSIX only: signal 0 just probes (on Windows os.kill would terminate)
    except ProcessLookupError:
        return False
    except PermissionError:
        pass
    except Exception:
        return True
    Now = _LinuxStart(Pid) if Start is not None else None
    return Start is None or Now is None or Now == Start


def WriteOwner(TempRoot, Worker=None, Kept=False):
    """owner.json in the work directory: which processes use it, so a later run can tell a directory
    left behind by a killed run (dsigmatcher terminated, a crash, a power cut) from a live one."""
    Record = {"tool": TOOL_NAME, "pid": os.getpid(), "start": ProcessStart(os.getpid()), "created_utc": UtcNow(),
              "kept": Kept}
    if Worker is not None:
        Record.update({"worker_pid": Worker.pid, "worker_start": ProcessStart(Worker.pid)})
    WriteJsonAtomic(os.path.join(TempRoot, OWNER_FILE), Record)


def SweepWorkDirectories(Parent):
    """Removes the dsig-export-<8 chars> work directories under Parent that a killed run left behind:
    their owner.json names no live process (or, without an owner file, they are older than
    UNOWNED_SWEEP_AGE_SECONDS). A directory kept with --keep-temp, one whose owner file cannot be read,
    and anything whose name is not exactly mkdtemp's are left alone. Returns the removed paths."""
    Removed = []
    try:
        Names = os.listdir(Parent)
    except OSError:
        return Removed
    IsJunction = getattr(os.path, "isjunction", lambda _Path: False)
    for Name in Names:
        if not WORK_NAME_RE.match(Name):
            continue
        Path = os.path.join(Parent, Name)
        try:
            if os.path.islink(Path) or IsJunction(Path) or not os.path.isdir(Path):
                continue
            with open(os.path.join(Path, OWNER_FILE), "r", encoding="utf-8") as Handle:
                Owner = json.load(Handle)
        except FileNotFoundError:
            Owner = None
        except (OSError, ValueError):
            continue
        if Owner is None:
            try:
                if time.time() - os.path.getmtime(Path) < UNOWNED_SWEEP_AGE_SECONDS:
                    continue
            except OSError:
                continue
        elif not isinstance(Owner, dict) or Owner.get("tool") != TOOL_NAME or Owner.get("kept"):
            continue
        elif any(ProcessAlive(Pid, Start) for Pid, Start in ((Owner.get("pid"), Owner.get("start")),
                                                             (Owner.get("worker_pid"), Owner.get("worker_start")))
                 if Pid is not None):
            continue
        if RemoveTree(Path):
            Removed.append(Path)
            Log("removed the work directory %s left behind by an earlier run" % Path)
        else:
            Log("warning: could not remove the stale work directory %s" % Path)
    return Removed


class ParentWatch(threading.Thread):
    """Notices the launcher going away (audit F44). POSIX re-parents an orphan, so os.getppid() changes:
    the IDA worker is then killed and nothing is published after the caller has already seen a failure.
    On Windows os.getppid() never changes, and dsigmatcher's kill-on-close job object ends the tree."""

    def __init__(self):
        threading.Thread.__init__(self, daemon=True)
        self.Parent = os.getppid()
        self.Gone = threading.Event()
        self.Stopped = threading.Event()
        self.Worker = None

    def run(self):
        while not self.Stopped.wait(1.0):
            if os.getppid() != self.Parent:
                self.Gone.set()
                Worker = self.Worker
                if Worker is not None and Worker.poll() is None:
                    try:
                        Worker.kill()
                    except OSError:
                        pass
                return

    def Check(self):
        if self.Gone.is_set() or os.getppid() != self.Parent:
            self.Gone.set()
            raise ExportError(EXIT_INTERRUPTED, "the launcher (process %d) went away; nothing was published"
                              % self.Parent)


class Terminated(BaseException):
    pass


def OnSigterm(_Signal, _Frame):
    raise Terminated()


def Drive(Args):
    Started = time.monotonic()
    Warnings = []
    Input = os.path.abspath(Args.input)
    Output = os.path.abspath(Args.output)
    Sidecar = os.path.abspath(Args.sidecar) if Args.sidecar else DefaultSidecar(Output)

    # ---- the input
    if not os.path.isfile(Input):
        raise ExportError(EXIT_INPUT, "input not found: %s" % Input)
    Extension = os.path.splitext(Input)[1].lower()
    if Args.mode == "idb" and Extension not in (".i64", ".idb"):
        raise ExportError(EXIT_USAGE, "idb mode needs an IDA database (.i64 or .idb), got '%s'; use binary "
                          "mode for a raw binary" % Input)
    if Args.mode == "binary" and Extension in (".i64", ".idb"):
        raise ExportError(EXIT_USAGE, "binary mode needs a raw binary, got the IDA database '%s'; use idb "
                          "mode" % Input)
    try:
        Kind = "ida-database" if Args.mode == "idb" else InputKind(Input)
    except OSError as Exc:
        raise ExportError(EXIT_INPUT, "input not readable: %s (%s)" % (Input, Exc))

    # ---- the output
    if Output.lower().endswith(REFUSED_OUTPUT_EXTENSIONS):
        raise ExportError(EXIT_USAGE, "the output must not have an IDA or PDB extension (%s): %s"
                          % (", ".join(REFUSED_OUTPUT_EXTENSIONS), Output))
    if os.path.normcase(Output) == os.path.normcase(Input) or (
            os.path.exists(Output) and os.path.samefile(Output, Input)):
        raise ExportError(EXIT_USAGE, "the output is the input: %s" % Output)
    if os.path.normcase(Sidecar) in (os.path.normcase(Output), os.path.normcase(Input)):
        raise ExportError(EXIT_USAGE, "the sidecar path collides with the input or output: %s" % Sidecar)
    if not os.path.isdir(os.path.dirname(Output)):
        raise ExportError(EXIT_OUTPUT, "the output directory does not exist: %s" % os.path.dirname(Output))

    # ---- the PDB
    PdbRecord = {"mode": "database" if Args.mode == "idb" else ("file" if Args.pdb else "none")}
    CodeView = None
    PdbPath = os.path.abspath(Args.pdb) if Args.pdb else None
    if PdbPath is not None and not os.path.isfile(PdbPath):
        raise ExportError(EXIT_INPUT, "PDB not found: %s" % PdbPath)
    # Nothing this run writes, replaces or moves aside may be the input or the PDB (audit F02).
    Alias = WrittenPathAlias(Output, Sidecar, [("the input", Input)] + ([("the PDB", PdbPath)] if PdbPath else []))
    if Alias:
        raise ExportError(EXIT_USAGE, Alias)
    if Args.pdb:
        CodeView, Why = ReadCodeView(Input)
        if CodeView is None:
            raise ExportError(EXIT_PDB, "--pdb needs a PE that names a PDB: %s: %s" % (Input, Why))
        try:
            Identity = ReadPdbIdentity(PdbPath)
        except (OSError, ValueError, struct.error) as Exc:
            raise ExportError(EXIT_PDB, "not a readable PDB: %s (%s)" % (PdbPath, Exc))
        if Identity["guid"] != CodeView["guid"] or Identity["dbi_age"] != CodeView["age"]:
            raise ExportError(EXIT_PDB, "the PDB does not match the binary: %s wants %s GUID %s age %d, "
                              "%s is GUID %s age %s" % (os.path.basename(Input), CodeView["pdb_name"],
                                                        CodeView["guid"], CodeView["age"], PdbPath,
                                                        Identity["guid"], Identity["dbi_age"]))
        if not CodeView["pdb_name"] or CodeView["pdb_name"] in (".", ".."):
            raise ExportError(EXIT_PDB, "the binary's RSDS record has no usable PDB name")
        if os.path.normcase(CodeView["pdb_name"]) == os.path.normcase(os.path.basename(Input)):
            raise ExportError(EXIT_PDB, "the binary's PDB name equals its own file name")
        PdbRecord.update({"path": PdbPath, "sha256": Sha256OfFile(PdbPath), "size": os.path.getsize(PdbPath),
                          "identity": Identity, "binary_codeview": CodeView})

    # ---- the tools
    IdaDir, IdaSource, IdaLibrary = ResolveIdaDir(Args.ida_dir)
    DiaphoraDir, DiaphoraSource = ResolveDiaphoraDir(Args.diaphora_dir)
    Diaphora = DiaphoraIdentity(DiaphoraDir)
    Diaphora.update({"dir": DiaphoraDir, "dir_source": DiaphoraSource})
    if Diaphora["git_dirty"]:
        Warnings.append("the Diaphora checkout has local modifications (%s)" % Diaphora["git_describe"])

    if Args.temp_dir and not os.path.isdir(Args.temp_dir):
        raise ExportError(EXIT_OUTPUT, "--temp-dir does not exist: %s" % Args.temp_dir)
    # A run that was killed (dsigmatcher terminated, a crash) cannot remove its work directory, which
    # holds a copy of the user's database; the next run in the same place does (audit F43).
    SweepWorkDirectories(Args.temp_dir or tempfile.gettempdir())
    try:
        TempRoot = tempfile.mkdtemp(prefix=WORK_PREFIX, dir=Args.temp_dir or None)
    except OSError as Exc:
        raise ExportError(EXIT_OUTPUT, "cannot create a work directory: %s" % Exc)
    Log("work directory %s" % TempRoot)
    Worker = None
    Watch = ParentWatch()
    Watch.start()
    try:
        try:
            WriteOwner(TempRoot)
        except OSError as Exc:
            raise ExportError(EXIT_OUTPUT, "cannot write to the work directory %s: %s" % (TempRoot, Exc))
        WorkDir = os.path.join(TempRoot, "work")
        IdaUsr = os.path.join(TempRoot, "idausr")
        NoSymbols = os.path.join(TempRoot, "nosymbols")
        for Directory in (WorkDir, IdaUsr, NoSymbols):
            os.makedirs(Directory)

        # ---- hash, then copy: IDA only ever sees the copy
        InputRecord = {"path": Input, "kind": Kind, "size": os.path.getsize(Input),
                       "mtime_before": os.path.getmtime(Input), "sha256_before": Sha256OfFile(Input)}
        Copy = os.path.join(WorkDir, os.path.basename(Input))
        shutil.copyfile(Input, Copy)
        CopySha = Sha256OfFile(Copy)
        if CopySha != InputRecord["sha256_before"]:
            raise ExportError(EXIT_INPUT, "the work copy of the input differs from the original (it changed "
                              "while it was being copied?)")
        IdbRecord = None
        if Args.mode == "idb":
            Stem = os.path.splitext(Input)[0]
            Siblings = [Stem + Ext for Ext in UNPACKED_EXTENSIONS if os.path.exists(Stem + Ext)]
            IdbRecord = {"copy_sha256_before": CopySha, "unpacked_siblings": Siblings, "saved": False}
            if Siblings:
                Warnings.append("unpacked database files lie next to the input (%s): the database may be open "
                                "in IDA; the export reflects the last SAVED state of the .i64/.idb"
                                % ", ".join(os.path.basename(Name) for Name in Siblings))

        Env, RemovedEnv = CleanEnv()
        Env["IDADIR"] = IdaDir
        Env["IDAUSR"] = IdaUsr
        Licences = CopyLicences(IdaUsr)
        if Args.pdb:
            # The oracle's with-PDB layout (tools/oracle/build_oracle.py RunExport): the PDB next to the
            # binary under the name its RSDS record asks for, and a symbol path of that directory only.
            shutil.copyfile(PdbRecord["path"], os.path.join(WorkDir, CodeView["pdb_name"]))
            PdbRecord["placed_as"] = CodeView["pdb_name"]
            Env["_NT_SYMBOL_PATH"] = WorkDir
            IdaArgs = ""
        else:
            # No PDB: an empty local symbol path, so no symbol server can be reached, and for a PE (or a
            # database, as oracle_extend.py RunUserI64Export) the PDB plugin switched off. A non-PE binary
            # gets no switch, exactly as tools/oracle/build_oracle.py RunExport treats the ELF samples.
            Env["_NT_SYMBOL_PATH"] = NoSymbols
            IdaArgs = "-Opdb:off" if Kind in ("ida-database", "pe", "mz") else ""

        ResultPath = os.path.join(TempRoot, "result.json")
        ExportPath = os.path.join(TempRoot, "export.sqlite")
        Spec = {"mode": Args.mode, "input": Copy, "out": ExportPath, "result": ResultPath,
                "ida_dir": IdaDir, "diaphora_dir": DiaphoraDir, "ida_args": IdaArgs,
                "auto_analysis": Args.mode == "binary", "allow_no_decompiler": bool(Args.allow_no_decompiler)}
        SpecPath = os.path.join(TempRoot, "worker.json")
        with open(SpecPath, "w", encoding="utf-8") as Handle:
            json.dump(Spec, Handle, indent=2)

        Command = [sys.executable, "-B", "-u", os.path.abspath(__file__), "_worker", SpecPath]
        Log("%s: %s -> %s (IDA %s, Diaphora %s %s)" % (Args.mode, Input, Output, IdaDir,
                                                       Diaphora["version_value"], Diaphora["git_describe"]))
        WorkerStarted = time.monotonic()
        # The worker inherits the error mode: set it again right before the start (Main already did;
        # this keeps a caller that imports Drive covered) and never ask for CREATE_DEFAULT_ERROR_MODE.
        QuietHardErrors()
        Worker = subprocess.Popen(Command, cwd=WorkDir, env=Env, stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  creationflags=WORKER_CREATION_FLAGS)
        Watch.Worker = Worker
        try:
            WriteOwner(TempRoot, Worker)
        except OSError as Exc:
            raise ExportError(EXIT_OUTPUT, "cannot write to the work directory %s: %s" % (TempRoot, Exc))
        Reader = WorkerOutput(Worker.stdout, os.path.join(TempRoot, "worker.log"))
        Reader.start()
        try:
            WorkerCode = Worker.wait(timeout=Args.timeout or None)
        except subprocess.TimeoutExpired:
            Worker.kill()
            Worker.wait()
            Reader.join(30)
            raise ExportError(EXIT_TIMEOUT, "timeout: IDA did not finish within %d s" % Args.timeout)
        Reader.join(60)
        WorkerSeconds = round(time.monotonic() - WorkerStarted, 3)
        Watch.Check()

        # ---- the original must be untouched, whatever happened
        InputRecord["sha256_after"] = Sha256OfFile(Input)
        InputRecord["mtime_after"] = os.path.getmtime(Input)
        InputRecord["unchanged"] = (InputRecord["sha256_after"] == InputRecord["sha256_before"]
                                    and InputRecord["mtime_after"] == InputRecord["mtime_before"])
        InputRecord["sha256"] = InputRecord["sha256_before"]
        if not InputRecord["unchanged"]:
            raise ExportError(EXIT_INPUT_CHANGED, "THE INPUT CHANGED during the export: %s (sha256 %s -> %s)"
                              % (Input, InputRecord["sha256_before"], InputRecord["sha256_after"]))
        if IdbRecord is not None:
            IdbRecord["copy_sha256_after"] = Sha256OfFile(Copy)
            IdbRecord["copy_unchanged"] = IdbRecord["copy_sha256_after"] == CopySha

        Result = {}
        if os.path.isfile(ResultPath):
            with open(ResultPath, "r", encoding="utf-8") as Handle:
                Result = json.load(Handle)
        if WorkerCode != 0:
            Code = Result.get("exit_code") if Result.get("exit_code") not in (None, 0) else EXIT_EXPORT
            Message = Result.get("error") or ("the IDA worker failed with exit code %d (0x%08X) and left no "
                                              "result" % (WorkerCode, WorkerCode & 0xFFFFFFFF))
            raise ExportError(Code, Message)
        if not Result.get("ok"):
            raise ExportError(EXIT_EXPORT, "the IDA worker exited 0 without a successful result")

        # ---- PDB evidence must agree with the mode
        NetnodeExists = (Result.get("pdb_evidence") or {}).get("pdb_netnode_exists")
        PdbRecord.update({"log_lines": len(Reader.PdbLines), "log_first_lines": Reader.PdbLines[:8],
                          "symbols_loaded": Reader.PdbTotals[-1] if Reader.PdbTotals else None,
                          "netnode_exists": NetnodeExists})
        if Args.pdb:
            if not Reader.PdbTotals or not NetnodeExists:
                raise ExportError(EXIT_EXPORT, "IDA did not apply the PDB %s (no 'PDB: total N symbols loaded' "
                                  "line or no $ pdb netnode)" % PdbRecord["path"])
            PdbRecord["applied"] = True
        else:
            if Reader.PdbLines:
                raise ExportError(EXIT_EXPORT, "IDA loaded PDB information although the run had no PDB: %s"
                                  % Reader.PdbLines[0])
            if Args.mode == "binary" and NetnodeExists:
                raise ExportError(EXIT_EXPORT, "the fresh analysis has a $ pdb netnode although no PDB was given")
            PdbRecord["applied"] = False

        # ---- the export itself
        for Suffix in ("-crash",):
            if os.path.exists(ExportPath + Suffix):
                raise ExportError(EXIT_EXPORT, "Diaphora left a %s marker; the export is incomplete" % Suffix)
        Wal = ExportPath + "-wal"
        if os.path.exists(Wal) and os.path.getsize(Wal) > 0:
            raise ExportError(EXIT_EXPORT, "the export still has a non-empty -wal file")
        if not os.path.isfile(ExportPath):
            raise ExportError(EXIT_EXPORT, "Diaphora wrote no database")

        # ---- publish: copy beside the destination, then an atomic replace
        Watch.Check()
        PublishOutput(ExportPath, Output)

        Stats = Result.get("export_stats") or {}
        Record = {
            "schema": SIDECAR_SCHEMA,
            "tool": {"name": TOOL_NAME, "version": TOOL_VERSION, "script": os.path.abspath(__file__),
                     "script_sha256": Sha256OfFile(os.path.abspath(__file__)),
                     "python": sys.version, "python_executable": sys.executable},
            "created_utc": UtcNow(),
            "mode": Args.mode,
            "input": InputRecord,
            "idb": IdbRecord,
            "pdb": PdbRecord,
            "options": {"mode": Args.mode, "pdb": Args.pdb and PdbRecord["path"], "no_pdb": not Args.pdb,
                        "ida_args": IdaArgs, "auto_analysis": Args.mode == "binary", "database_saved": False,
                        "timeout": Args.timeout, "allow_no_decompiler": bool(Args.allow_no_decompiler),
                        "diaphora_arguments": {"use_ui": False, "file_out": "<output>", "file_in": ""}},
            "ida": {"dir": IdaDir, "dir_source": IdaSource, "library": IdaLibrary,
                    "idalib_version": Result.get("idalib_version"),
                    "kernel_version": Result.get("ida_kernel_version"),
                    "hexrays_available": Result.get("hexrays_available"),
                    "hexrays_version": Result.get("hexrays_version"),
                    "auto_queue_empty_at_open": Result.get("auto_queue_empty_at_open"),
                    "function_names": Result.get("ida_function_names"),
                    "install_plugins": InstallPlugins(IdaDir),
                    "plugins_loaded_log": Reader.PluginLines},
            "isolation": {"idausr": "private empty directory (licence files copied: %s)" % (Licences or "none"),
                          "nt_symbol_path": "the work directory holding only the given PDB" if Args.pdb
                          else "an empty local directory",
                          "removed_environment": RemovedEnv,
                          "note": "plugins inside the IDA installation's plugins directory still load"},
            "diaphora": dict(Diaphora, options=Result.get("diaphora_options"),
                             config=Result.get("diaphora_config"),
                             version_value_imported=Result.get("diaphora_version_value")),
            "output": {"path": Output, "size": os.path.getsize(Output), "sha256": Sha256OfFile(Output),
                       "sidecar": Sidecar},
            "counts": {"ida_functions": (Result.get("ida_function_names") or {}).get("total"),
                       "functions": Stats.get("functions"), "functions_named": Stats.get("functions_named"),
                       "functions_sub": Stats.get("functions_sub"),
                       "functions_with_pseudocode": Stats.get("functions_with_pseudocode"),
                       "functions_with_microcode": Stats.get("functions_with_microcode"),
                       "tables": Stats.get("tables"),
                       "tester_export_query": Stats.get("tester_export_query")},
            "timing": {"analysis_seconds": Result.get("analysis_seconds"),
                       "export_seconds": Result.get("export_seconds"), "worker_seconds": WorkerSeconds,
                       "wall_seconds": round(time.monotonic() - Started, 3)},
            "warnings": Warnings + (Result.get("warnings") or []),
        }
        if Record["output"]["sha256"] != Result.get("sqlite_sha256"):
            raise ExportError(EXIT_OUTPUT, "the published output differs from the exported database")
        try:
            WriteJsonAtomic(Sidecar, Record)
        except OSError as Exc:
            raise ExportError(EXIT_OUTPUT, "cannot write the sidecar %s: %s" % (Sidecar, Exc))
        for Warning in Record["warnings"]:
            Log("warning: %s" % Warning)
        Log("exported %s functions (%s named, %s sub_*, %s with pseudo-code) -> %s"
            % (Stats.get("functions"), Stats.get("functions_named"), Stats.get("functions_sub"),
               Stats.get("functions_with_pseudocode"), Output))
        Log("sidecar %s" % Sidecar)
        Log("input sha256 %s unchanged" % InputRecord["sha256"])
        return EXIT_OK
    except (KeyboardInterrupt, Terminated):
        raise ExportError(EXIT_INTERRUPTED, "interrupted")
    finally:
        Watch.Stopped.set()
        if Worker is not None and Worker.poll() is None:
            Worker.kill()
            Worker.wait()
        if Args.keep_temp:
            try:
                WriteOwner(TempRoot, Kept=True)  # a later run's sweep leaves it alone
            except OSError:
                pass
            Log("work directory kept: %s" % TempRoot)
        elif not RemoveTree(TempRoot):
            Log("warning: could not remove the work directory %s" % TempRoot)


# ----------------------------------------------------------------------------- worker (runs under idalib)

def ShimDiaphoraUi(DiaphoraIda):
    """Replace the few UI calls Diaphora makes during an export (same shim as tools/oracle).

    None of them changes what is exported: progress boxes, the 'overwrite?' question (the output is
    removed beforehand) and warnings."""
    def NoOp(*_Args, **_Kwargs):
        return None

    def Warn(Message, *_Args):
        print("[diaphora:warning] %s" % str(Message).replace("\n", " ").strip(), flush=True)

    for Name in ("show_wait_box", "hide_wait_box", "replace_wait_box"):
        setattr(DiaphoraIda, Name, NoOp)
    DiaphoraIda.warning = Warn
    DiaphoraIda.ask_yn = lambda *_Args, **_Kwargs: 1


def ImportDiaphora(Directory):
    """(diaphora_config, diaphora_ida) imported from the checkout, after checking the interface the export
    uses: diaphora_ida.CIDABinDiff (diaphora_ida.py:1075) with do_export (:1191), _diff_or_export (:3635),
    and diaphora_ida.diaphora.VERSION_VALUE (diaphora_ida.py:82 `import diaphora`, diaphora.py:100).

    A directory whose files carry Diaphora's names but that is not Diaphora is "Diaphora not usable"
    (EXIT_DIAPHORA, which the C++ bridge reports with exit 4), not an export failure: the attribute
    accesses below used to happen outside the import check and surfaced as EXIT_EXPORT (lane F1)."""
    sys.path.insert(0, Directory)
    try:
        import diaphora_config
        import diaphora_ida
    except Exception as Exc:
        raise ExportError(EXIT_DIAPHORA, "Diaphora could not be imported from %s: %s: %s"
                          % (Directory, type(Exc).__name__, Exc))
    Missing = []
    BinDiff = getattr(diaphora_ida, "CIDABinDiff", None)
    if not isinstance(BinDiff, type):
        Missing.append("diaphora_ida.CIDABinDiff")
    elif not callable(getattr(BinDiff, "do_export", None)):
        Missing.append("diaphora_ida.CIDABinDiff.do_export")
    if not callable(getattr(diaphora_ida, "_diff_or_export", None)):
        Missing.append("diaphora_ida._diff_or_export")
    if not isinstance(getattr(getattr(diaphora_ida, "diaphora", None), "VERSION_VALUE", None), str):
        Missing.append("diaphora_ida.diaphora.VERSION_VALUE")
    if Missing:
        raise ExportError(EXIT_DIAPHORA, "Diaphora not usable: %s imports, but it is not Diaphora's exporter "
                          "(no %s)" % (Directory, ", ".join(Missing)))
    return diaphora_config, diaphora_ida


def FunctionNameStats():
    import warnings
    import ida_funcs
    import ida_name
    import idautils

    Stats = {"total": 0, "sub_prefixed": 0, "library_flag": 0, "thunk_flag": 0}
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        for Ea in idautils.Functions():
            Stats["total"] += 1
            if (ida_name.get_name(Ea) or "").startswith("sub_"):
                Stats["sub_prefixed"] += 1
            Func = ida_funcs.get_func(Ea)
            if Func is not None:
                Stats["library_flag"] += 1 if Func.flags & ida_funcs.FUNC_LIB else 0
                Stats["thunk_flag"] += 1 if Func.flags & ida_funcs.FUNC_THUNK else 0
    Stats["non_sub"] = Stats["total"] - Stats["sub_prefixed"]
    return Stats


def PdbEvidence():
    import ida_netnode
    try:
        Node = ida_netnode.netnode("$ pdb", 0, False)  # does not create the node
        return {"pdb_netnode_exists": Node.index() != ida_netnode.BADNODE}
    except Exception as Exc:
        return {"error": str(Exc)}


def ExportStats(SqlitePath):
    import sqlite3
    Handle = sqlite3.connect(SqlitePath)
    try:
        Cursor = Handle.cursor()

        def One(Sql):
            Cursor.execute(Sql)
            return Cursor.fetchone()[0]

        Cursor.execute(TESTER_EXPORT_QUERY)
        Stats = {"tester_export_query": {Row[1].lower(): Row[2] for Row in Cursor.fetchall()}}
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


def RunWorker(SpecPath):
    with open(SpecPath, "r", encoding="utf-8") as Handle:
        Spec = json.load(Handle)
    Result = {"ok": False, "exit_code": EXIT_INTERNAL, "error": None, "warnings": []}

    def Finish(Code, Error=None):
        Result["exit_code"] = Code
        Result["error"] = Error
        Result["ok"] = Code == EXIT_OK
        with open(Spec["result"], "w", encoding="utf-8") as Handle:
            json.dump(Result, Handle, indent=2, default=str)
        if Error:
            # The driver prints the one "dsig_export: error:" line (the launcher quotes the last one).
            Log("worker failed (exit %d): %s" % (Code, Error.splitlines()[0]))
        return Code

    sys.dont_write_bytecode = True  # neither IDA's python directory nor the Diaphora checkout gets __pycache__
    try:
        import idapro  # must be the first IDA import: it loads and initialises idalib
    except ImportError as FirstError:
        # A Python without the idapro wheel: use the copy shipped inside the IDA installation.
        sys.path.append(os.path.join(Spec["ida_dir"], "idalib", "python"))
        try:
            import idapro  # noqa: F811
        except ImportError as Exc:
            return Finish(EXIT_IDA, "IDA not usable: cannot import idapro (%s; %s). Install IDA's "
                          "idalib/python/idapro wheel into this Python or check the IDA licence"
                          % (FirstError, Exc))
    Result["idalib_version"] = list(idapro.get_library_version() or ())

    idapro.enable_console_messages(True)
    Log("opening %s (auto-analysis=%s, args=%r)" % (Spec["input"], Spec["auto_analysis"], Spec["ida_args"]))
    Started = time.monotonic()
    Status = idapro.open_database(Spec["input"], Spec["auto_analysis"], Spec["ida_args"] or None)
    if Status != 0:
        return Finish(EXIT_OPEN, "IDA could not open %s (open_database returned %s)"
                      % (os.path.basename(Spec["input"]), Status))
    Result["analysis_seconds"] = round(time.monotonic() - Started, 3)

    Code, Error = EXIT_OK, None
    try:
        import idaapi
        import ida_auto
        import ida_hexrays

        if Spec["auto_analysis"]:
            ida_auto.auto_wait()
        else:
            # idb mode never analyses: the queue is only reported (a saved database normally has it empty).
            Result["auto_queue_empty_at_open"] = bool(ida_auto.auto_is_ok())
            if not Result["auto_queue_empty_at_open"]:
                Result["warnings"].append("the database was saved with pending auto-analysis; it was exported "
                                          "as saved, without running it")
        # diaphora_ida only imports PySide6 when not in batch mode (diaphora_ida.py:72).
        idaapi.cvar.batch = True
        Result["ida_kernel_version"] = idaapi.get_kernel_version()
        Result["ida_function_names"] = FunctionNameStats()
        Result["pdb_evidence"] = PdbEvidence()

        HexRays = bool(ida_hexrays.init_hexrays_plugin())
        Result["hexrays_available"] = HexRays
        Result["hexrays_version"] = ida_hexrays.get_hexrays_version() if HexRays else None
        Log("hex-rays: %s" % Result["hexrays_version"])
        if not HexRays:
            if not Spec["allow_no_decompiler"]:
                raise ExportError(EXIT_HEXRAYS, "the Hex-Rays decompiler is not available for this binary; an "
                                  "export without pseudo-code and microcode is not comparable with one that "
                                  "has them (to export anyway pass --allow-no-decompiler to dsigmatcher "
                                  "extract/ingest/update or to dsig_export.py, or set "
                                  "DSIG_EXPORT_ALLOW_NO_DECOMPILER=1)")
            Result["warnings"].append("exported WITHOUT Hex-Rays: no pseudo-code or microcode")

        # A file IDA loads but finds no code in (a text file, data) would otherwise surface as Diaphora's
        # "_diff_or_export returned None" (audit F57 d). An unsupported input: exit 15 (CLI exit 4).
        import ida_funcs
        if ida_funcs.get_func_qty() == 0:
            raise ExportError(EXIT_OPEN, "IDA found no functions in '%s' (not an executable IDA can analyse, or "
                              "the analysis failed)" % os.path.basename(Spec["input"]))

        diaphora_config, diaphora_ida = ImportDiaphora(Spec["diaphora_dir"])
        ShimDiaphoraUi(diaphora_ida)

        # Diaphora's export() catches an exception from do_export(), logs it and still writes a partial
        # database (diaphora_ida.py:1300-1315), so the failure is caught here.
        Failures = []
        OriginalDoExport = diaphora_ida.CIDABinDiff.do_export

        def CheckedDoExport(Self, *A, **K):
            try:
                return OriginalDoExport(Self, *A, **K)
            except BaseException as Exc:
                Failures.append("".join(traceback.format_exception(type(Exc), Exc, Exc.__traceback__)))
                raise
        diaphora_ida.CIDABinDiff.do_export = CheckedDoExport

        Out = Spec["out"]
        for Stale in (Out, Out + "-wal", Out + "-shm", Out + "-crash"):
            RemoveIfFile(Stale)
        # Only the output path is passed: every other option is BinDiffOptions' default, i.e.
        # diaphora_config.py (diaphora_ida.py:3780-3832). ida_subs defaults to EXPORTING_ONLY_NON_IDA_SUBS
        # = True (diaphora_ida.py:3809, diaphora_config.py:56), so sub_* functions are exported (the skip
        # is `if not self.ida_subs`, diaphora_ida.py:3112).
        Log("diaphora %s export -> %s" % (diaphora_ida.diaphora.VERSION_VALUE, Out))
        ExportStarted = time.monotonic()
        Bd = diaphora_ida._diff_or_export(use_ui=False, file_out=Out, file_in="")
        Result["export_seconds"] = round(time.monotonic() - ExportStarted, 3)
        if Bd is None:
            raise ExportError(EXIT_EXPORT, "Diaphora's _diff_or_export returned None: the export did not run")
        if Failures:
            raise ExportError(EXIT_EXPORT, "Diaphora's do_export raised:\n" + Failures[0])
        if os.path.exists(Out + "-crash"):
            raise ExportError(EXIT_EXPORT, "Diaphora left a -crash marker; the export is incomplete")

        Result["diaphora_version_value"] = diaphora_ida.diaphora.VERSION_VALUE
        Result["diaphora_options"] = {
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
        Result["diaphora_config"] = {Key: getattr(diaphora_config, Key, None) for Key in (
            "EXPORTING_USE_DECOMPILER", "EXPORTING_EXCLUDE_LIBRARY_THUNK", "EXPORTING_ONLY_NON_IDA_SUBS",
            "EXPORTING_FUNCTION_SUMMARIES_ONLY", "EXPORTING_USE_MICROCODE", "EXPORTING_COMPILATION_UNITS",
            "MIN_FUNCTIONS_TO_CONSIDER_MEDIUM", "MIN_FUNCTIONS_TO_CONSIDER_HUGE",
            "DIAPHORA_WORKAROUND_MAX_TINFO_T")}
        if not Bd.ida_subs:
            raise ExportError(EXIT_EXPORT, "ida_subs is False: sub_* functions would have been dropped")
        if HexRays and not Bd.decompiler_available:
            raise ExportError(EXIT_EXPORT, "Diaphora lost the decompiler during the export")
        if HexRays and not Bd.export_microcode:
            Result["warnings"].append("Diaphora's default left microcode export off for this database (more "
                                      "than MIN_FUNCTIONS_TO_CONSIDER_MEDIUM functions, diaphora_ida.py:3831)")
        if Bd.function_summaries_only:
            Result["warnings"].append("Diaphora exported function summaries only (more than "
                                      "MIN_FUNCTIONS_TO_CONSIDER_HUGE functions, diaphora_ida.py:3822)")
    except ExportError as Exc:
        Code, Error = Exc.Code, Exc.Message
    except Exception as Exc:
        traceback.print_exc()
        Code, Error = EXIT_EXPORT, "the export failed: %s: %s" % (type(Exc).__name__, Exc)
    finally:
        # Never saved: a database input stays exactly as the user left it, and a fresh analysis is
        # thrown away with the work directory.
        idapro.close_database(False)
        Log("database closed without saving")

    if Code != EXIT_OK:
        return Finish(Code, Error)
    try:
        Stats = ExportStats(Spec["out"])
    except Exception as Exc:
        return Finish(EXIT_EXPORT, "the export database is unreadable: %s" % Exc)
    Result["export_stats"] = Stats
    if Stats["functions"] == 0:
        return Finish(EXIT_EXPORT, "the export has no functions")
    if Result.get("hexrays_available") and Stats["functions_with_pseudocode"] == 0:
        return Finish(EXIT_EXPORT, "no exported function has pseudo-code although Hex-Rays is available")
    Result["sqlite_sha256"] = Sha256OfFile(Spec["out"])
    return Finish(EXIT_OK)


# ----------------------------------------------------------------------------- entry

SEM_FAILCRITICALERRORS = 0x0001
SEM_NOGPFAULTERRORBOX = 0x0002
SEM_NOOPENFILEERRORBOX = 0x8000
NO_ERROR_DIALOGS = SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX


def QuietHardErrors():
    """Windows: a failed DLL load or a crash fails instead of raising a modal dialog.

    Under cmd.exe, PowerShell or Explorer a process may show critical-error dialogs. When idapro then
    loads a broken or foreign idalib, Windows raises a modal "Bad Image" hard error and the headless
    run blocks until someone clicks it; a crash shows the Windows Error Reporting dialog. The worker
    started by the driver inherits this mode (it is never started with CREATE_DEFAULT_ERROR_MODE).
    Returns the new mode (None elsewhere, or when it cannot be set)."""
    if sys.platform != "win32":
        return None
    try:
        import ctypes
        Kernel32 = ctypes.WinDLL("kernel32")
        Kernel32.GetErrorMode.restype = ctypes.c_uint
        Kernel32.SetErrorMode.argtypes = (ctypes.c_uint,)
        Kernel32.SetErrorMode(Kernel32.GetErrorMode() | NO_ERROR_DIALOGS)
        return Kernel32.GetErrorMode()
    except (OSError, AttributeError):
        return None


def Main(Argv=None):
    Argv = sys.argv[1:] if Argv is None else Argv
    QuietHardErrors()
    if Argv[:1] == ["_worker"]:
        if len(Argv) != 2:
            LogError("usage: dsig_export.py _worker <spec.json>")
            return EXIT_USAGE
        return RunWorker(Argv[1])
    sys.dont_write_bytecode = True
    Args = ParseArgs(Argv)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, OnSigterm)
    try:
        return Drive(Args)
    except ExportError as Exc:
        LogError(Exc.Message)
        return Exc.Code
    except (KeyboardInterrupt, Terminated):
        LogError("interrupted")
        return EXIT_INTERRUPTED
    except Exception as Exc:
        traceback.print_exc()
        LogError("internal error: %s: %s" % (type(Exc).__name__, Exc))
        return EXIT_INTERNAL


if __name__ == "__main__":
    sys.exit(Main())
