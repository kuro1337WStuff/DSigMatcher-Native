#!/usr/bin/env python3

"""Self-test of dsig_export.py that needs neither IDA nor Diaphora.

Checks the pieces that run before IDA starts: the PE RSDS reader and the MSF 7.00 PDB identity reader
on synthetic files, the sidecar name, the environment cleaning, and the driver's argument and tool
checks with their exit codes (tool discovery is pointed at empty or fake directories, so the user's
real IDA configuration is never read). Then whole driver + worker runs against stand-in idalib and
Diaphora modules written at run time (lane F1): a directory with Diaphora's file names that is not
Diaphora is "Diaphora not usable" (exit 12), and publishing never deletes the previous output's
sidecars before the atomic replace has succeeded. The v1.0.0 audit regressions: no written file may
alias the input or the PDB (F02), git is never taken from the current directory (F16), a run that
was killed leaves no work directory behind for long (F43), a run whose launcher died publishes
nothing (F44), a --timeout too large for the platform is refused (F42), a Hex-Rays refusal names the
variable that works through dsigmatcher (F46), an input without functions is "unsupported input"
(F57 d), and the caller's PYTHON* variables never reach the worker (F66). Prints "<n> checks, <f>
failed" and exits non-zero on failure.

    python -B tools/export/selftest_dsig_export.py
"""

import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dsig_export  # noqa: E402

CHECKS = [0, 0]


def Check(Condition, What):
    CHECKS[0] += 1
    if not Condition:
        CHECKS[1] += 1
        print("  FAIL %s" % What)


GUID = bytes(range(0x10, 0x20))
GUID_TEXT = "%08X%04X%04X%s" % (struct.unpack_from("<IHH", GUID, 0) + (GUID[8:].hex().upper(),))


def SyntheticPe(Path, PdbPath="C:\\build\\obj\\foo.pdb", Age=1, Guid=GUID):
    """A minimal PE32+ whose debug directory holds one CodeView RSDS record."""
    Data = bytearray(0x400)
    Data[0:2] = b"MZ"
    struct.pack_into("<I", Data, 0x3C, 0x80)
    Data[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", Data, 0x84, 0x8664, 1, 0, 0, 0, 240, 0x22)
    Optional = 0x98
    struct.pack_into("<H", Data, Optional, 0x20B)
    struct.pack_into("<I", Data, Optional + 108, 16)
    struct.pack_into("<II", Data, Optional + 112 + 8 * 6, 0x1000, 28)
    Section = Optional + 240
    struct.pack_into("<8sIIII", Data, Section, b".rdata", 0x200, 0x1000, 0x200, 0x200)
    Name = PdbPath.encode("utf-8") + b"\x00"
    struct.pack_into("<IIHHIIII", Data, 0x200, 0, 0, 0, 0, 2, 24 + len(Name), 0x1020, 0x220)
    Record = b"RSDS" + Guid + struct.pack("<I", Age) + Name
    Data[0x220:0x220 + len(Record)] = Record
    with open(Path, "wb") as Handle:
        Handle.write(bytes(Data))


def SyntheticPdb(Path, Guid=GUID, DbiAge=1, InfoAge=3):
    """A 7-block MSF 7.00 file: superblock, two free maps, block map, directory, info and DBI streams."""
    BlockSize = 512
    Blocks = [bytearray(BlockSize) for _ in range(7)]
    Directory = struct.pack("<I", 4) + struct.pack("<4I", 0, 28, 0, 12) + struct.pack("<2I", 5, 6)
    Header = dsig_export.MSF7_MAGIC + struct.pack("<6I", BlockSize, 1, 7, len(Directory), 0, 3)
    Blocks[0][0:len(Header)] = Header
    struct.pack_into("<I", Blocks[3], 0, 4)
    Blocks[4][0:len(Directory)] = Directory
    Blocks[5][0:28] = struct.pack("<3I", 20000404, 0, InfoAge) + Guid
    Blocks[6][0:12] = struct.pack("<iII", -1, 19990903, DbiAge)
    with open(Path, "wb") as Handle:
        Handle.write(b"".join(bytes(Block) for Block in Blocks))


def RunMain(Argv):
    try:
        return dsig_export.Main(Argv)
    except SystemExit as Exc:  # argparse usage errors
        return Exc.code


def TestIdentityReaders(Dir):
    print("[pe / pdb identity]")
    Pe = os.path.join(Dir, "foo.dll")
    SyntheticPe(Pe)
    CodeView, Why = dsig_export.ReadCodeView(Pe)
    Check(CodeView is not None, "RSDS found (%s)" % Why)
    if CodeView:
        Check(CodeView["pdb_name"] == "foo.pdb", "pdb name from a Windows path: %s" % CodeView["pdb_name"])
        Check(CodeView["guid"] == GUID_TEXT, "guid %s" % CodeView["guid"])
        Check(CodeView["age"] == 1, "age")
    Check(dsig_export.InputKind(Pe) == "pe", "kind pe")
    Pdb = os.path.join(Dir, "foo.pdb")
    SyntheticPdb(Pdb)
    Identity = dsig_export.ReadPdbIdentity(Pdb)
    Check(Identity["guid"] == GUID_TEXT, "pdb guid %s" % Identity["guid"])
    Check(Identity["dbi_age"] == 1 and Identity["info_age"] == 3, "pdb ages %s" % Identity)
    Elf = os.path.join(Dir, "a.out")
    with open(Elf, "wb") as Handle:
        Handle.write(b"\x7fELF" + bytes(60))
    Check(dsig_export.InputKind(Elf) == "elf", "kind elf")
    Check(dsig_export.ReadCodeView(Elf)[0] is None, "no RSDS in an ELF")
    NotPdb = os.path.join(Dir, "not.pdb")
    with open(NotPdb, "wb") as Handle:
        Handle.write(b"hello" * 100)
    try:
        dsig_export.ReadPdbIdentity(NotPdb)
        Check(False, "a non-MSF file must be refused")
    except ValueError:
        Check(True, "")


def TestSmallPieces():
    print("[sidecar name / environment]")
    Cases = {os.path.join("d", "out.sqlite"): os.path.join("d", "out.export.json"),
             os.path.join("d", "out"): os.path.join("d", "out.export.json"),
             os.path.join("d", "a.b.sqlite"): os.path.join("d", "a.b.export.json"),
             os.path.join("d", ".hidden"): os.path.join("d", ".hidden.export.json"),
             os.path.join("d", "a."): os.path.join("d", "a.export.json")}
    for Output, Expected in Cases.items():
        Check(dsig_export.DefaultSidecar(Output) == Expected, "sidecar of %s" % Output)
    Planted = {"DIAPHORA_USE_DECOMPILER": "0", "diaphora_lowercase": "1", "IDA_IS_INTERACTIVE": "1",
               "PYTHONPATH": "planted", "PYTHONHOME": "planted", "PYTHONSTARTUP": "planted.py",
               "PYTHONINSPECT": "1", "PYTHONUTF8": "0"}
    Saved = {Key: os.environ.get(Key) for Key in Planted}
    os.environ.update(Planted)
    try:
        Env, Removed = dsig_export.CleanEnv()
        Check(not any(Key.upper().startswith("DIAPHORA_") for Key in Env), "DIAPHORA_* removed")
        Check("IDA_IS_INTERACTIVE" not in Env, "IDA_IS_INTERACTIVE removed")
        Check(Env.get("PYTHONDONTWRITEBYTECODE") == "1", "no bytecode")
        # F66: every PYTHON* variable but the four the worker needs is dropped and reported by name
        Extra = sorted(Key for Key in Env if Key.upper().startswith("PYTHON")
                       and Key.upper() not in dsig_export.WORKER_PYTHON_ENV)
        Check(not Extra, "no caller PYTHON* variable reaches the worker: %s" % Extra)
        Check(Env.get("PYTHONUTF8") == "1", "PYTHONUTF8 is the worker's own value")
        for Key in ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONINSPECT", "IDA_IS_INTERACTIVE",
                    "DIAPHORA_USE_DECOMPILER"):
            Check(any(Name.upper() == Key for Name in Removed), "%s is listed as removed" % Key)
        Check("planted" not in json.dumps(Removed), "only names are reported, never values")
        # F16: nothing the worker starts by a bare name is looked up in the current directory
        Check(Env.get("NoDefaultCurrentDirectoryInExePath") == "1", "NoDefaultCurrentDirectoryInExePath=1")
    finally:
        for Key, Value in Saved.items():
            if Value is None:
                os.environ.pop(Key, None)
            else:
                os.environ[Key] = Value


def TestDriverChecks(Dir):
    print("[driver checks and exit codes]")
    # Discovery must never see the user's real IDA or Diaphora.
    for Key in ("DSIG_IDADIR", "IDADIR", "DSIG_DIAPHORA_DIR", "DSIG_EXPORT_ALLOW_NO_DECOMPILER"):
        os.environ.pop(Key, None)
    EmptyUser = os.path.join(Dir, "empty idausr")
    os.makedirs(EmptyUser)
    os.environ["IDAUSR"] = EmptyUser
    FakeIda = os.path.join(Dir, "ida")
    os.makedirs(FakeIda)
    with open(os.path.join(FakeIda, dsig_export.IdaLibraryName()), "wb") as Handle:
        Handle.write(b"x")
    FakeDiaphora = os.path.join(Dir, "diaphora")
    os.makedirs(FakeDiaphora)
    for Name in ("diaphora.py", "diaphora_ida.py", "diaphora_config.py"):
        with open(os.path.join(FakeDiaphora, Name), "w") as Handle:
            Handle.write('VERSION_VALUE = "9.9"\n' if Name == "diaphora.py" else "")
    Pe = os.path.join(Dir, "bin \u00fc.dll")
    SyntheticPe(Pe)
    Database = os.path.join(Dir, "user.i64")
    with open(Database, "wb") as Handle:
        Handle.write(b"IDA2")
    Out = os.path.join(Dir, "out.sqlite")
    Missing = os.path.join(Dir, "missing")

    Check(RunMain(["binary", os.path.join(Dir, "nope.dll"), "-o", Out]) == dsig_export.EXIT_INPUT, "missing input")
    Check(RunMain(["idb", Pe, "-o", Out]) == dsig_export.EXIT_USAGE, "idb mode on a binary")
    Check(RunMain(["binary", Database, "-o", Out]) == dsig_export.EXIT_USAGE, "binary mode on a database")
    Check(RunMain(["binary", Pe, "-o", os.path.join(Dir, "x.i64")]) == dsig_export.EXIT_USAGE, "IDA output name")
    Check(RunMain(["binary", Pe, "-o", Pe]) == dsig_export.EXIT_USAGE, "output is the input")
    Check(RunMain(["binary", Pe, "-o", os.path.join(Missing, "o.sqlite")]) == dsig_export.EXIT_OUTPUT,
          "output directory missing")
    Check(RunMain(["binary", Pe, "-o", Out, "--pdb", "x.pdb", "--no-pdb"]) == dsig_export.EXIT_USAGE,
          "--pdb with --no-pdb")
    Check(RunMain(["idb", Database, "-o", Out, "--pdb", "x.pdb"]) == dsig_export.EXIT_USAGE, "--pdb in idb mode")
    Check(RunMain(["binary", Pe, "-o", Out, "--pdb", os.path.join(Dir, "no.pdb")]) == dsig_export.EXIT_INPUT,
          "PDB missing")
    WrongPdb = os.path.join(Dir, "wrong.pdb")
    SyntheticPdb(WrongPdb, Guid=bytes(16))
    Check(RunMain(["binary", Pe, "-o", Out, "--pdb", WrongPdb]) == dsig_export.EXIT_PDB, "PDB GUID mismatch")
    OldPdb = os.path.join(Dir, "old.pdb")
    SyntheticPdb(OldPdb, DbiAge=2)
    Check(RunMain(["binary", Pe, "-o", Out, "--pdb", OldPdb]) == dsig_export.EXIT_PDB, "PDB age mismatch")
    Elf = os.path.join(Dir, "tool")
    with open(Elf, "wb") as Handle:
        Handle.write(b"\x7fELF" + bytes(60))
    GoodPdb = os.path.join(Dir, "good.pdb")
    SyntheticPdb(GoodPdb)
    Check(RunMain(["binary", Elf, "-o", Out, "--pdb", GoodPdb]) == dsig_export.EXIT_PDB, "--pdb on an ELF")
    Check(RunMain(["binary", Pe, "-o", Out, "--diaphora-dir", FakeDiaphora]) == dsig_export.EXIT_IDA,
          "no IDA configured anywhere")
    Check(RunMain(["binary", Pe, "-o", Out, "--ida-dir", Missing, "--diaphora-dir", FakeDiaphora])
          == dsig_export.EXIT_IDA, "IDA dir missing")
    Check(RunMain(["binary", Pe, "-o", Out, "--ida-dir", FakeDiaphora, "--diaphora-dir", FakeDiaphora])
          == dsig_export.EXIT_IDA, "IDA dir without idalib")
    Check(RunMain(["binary", Pe, "-o", Out, "--ida-dir", FakeIda]) == dsig_export.EXIT_DIAPHORA,
          "no Diaphora configured")
    Check(RunMain(["binary", Pe, "-o", Out, "--ida-dir", FakeIda, "--diaphora-dir", FakeIda])
          == dsig_export.EXIT_DIAPHORA, "Diaphora dir without diaphora_ida.py")
    Check(RunMain(["binary", Pe, "-o", Out, "--ida-dir", FakeIda, "--diaphora-dir", FakeDiaphora, "--temp-dir",
                   Missing]) == dsig_export.EXIT_OUTPUT, "--temp-dir missing")
    Check(not os.path.exists(Out), "nothing was written")
    Identity = dsig_export.DiaphoraIdentity(FakeDiaphora)
    Check(Identity["version_value"] == "9.9", "VERSION_VALUE read as text")

    # F42: a timeout the platform cannot wait for is a usage error, not a wrapped or crashing wait
    Check(RunMain(["binary", Pe, "-o", Out, "--timeout", str(dsig_export.MAX_TIMEOUT_SECONDS + 1)])
          == dsig_export.EXIT_USAGE, "--timeout above the cap")
    Check(RunMain(["binary", Pe, "-o", Out, "--timeout", "4294848"]) == dsig_export.EXIT_USAGE,
          "--timeout 4294848 (the audit's value)")

    TestAliasRefusals(Dir, Pe, FakeIda, FakeDiaphora)
    os.environ.pop("IDAUSR", None)


def TestAliasRefusals(Dir, Pe, FakeIda, FakeDiaphora):
    """F02: no file the run writes, replaces or moves aside may be the input or the PDB. Each case must
    exit 2 before anything is touched, whatever tools are configured."""
    print("[written paths never alias the input or the PDB]")
    Tools = ["--ida-dir", FakeIda, "--diaphora-dir", FakeDiaphora]
    Aliases = os.path.join(Dir, "aliases")
    os.makedirs(Aliases)
    Out = os.path.join(Aliases, "out.sqlite")

    def Copy(Name, Source=Pe):
        Path = os.path.join(Aliases, Name)
        shutil.copyfile(Source, Path)
        return Path

    def Refused(Argv, Protected, What):
        Before = {Path: ReadBytes(Path) for Path in Protected}
        Code = RunMain(Argv + Tools)
        Check(Code == dsig_export.EXIT_USAGE, "%s: exit %s, want %d" % (What, Code, dsig_export.EXIT_USAGE))
        for Path, Data in Before.items():
            Check(os.path.isfile(Path) and ReadBytes(Path) == Data, "%s: %s is unchanged" % (What, os.path.basename(Path)))

    Pdb = os.path.join(Aliases, "cryptbase.pdb")
    SyntheticPdb(Pdb)
    Refused(["binary", Pe, "-o", Pdb, "--pdb", Pdb], [Pdb], "-o <pdb> --pdb <pdb>")
    Refused(["binary", Pe, "-o", os.path.join(Aliases, "other.pdb"), "--no-pdb"], [Pe], "-o <anything>.pdb")
    for Suffix in ("-wal", "-shm", "-journal", "-crash"):
        Input = Copy("out.sqlite" + Suffix)
        Refused(["binary", Input, "-o", Out, "--no-pdb"], [Input], "an input named <out>%s" % Suffix)
        AsPdb = Copy("out.sqlite%s.pdb" % Suffix, Pdb)
        os.replace(AsPdb, os.path.join(Aliases, "out.sqlite" + Suffix))
        Refused(["binary", Pe, "-o", Out, "--pdb", os.path.join(Aliases, "out.sqlite" + Suffix)],
                [os.path.join(Aliases, "out.sqlite" + Suffix)], "--pdb <out>%s" % Suffix)
        os.remove(os.path.join(Aliases, "out.sqlite" + Suffix))
    Input = Copy("out.export.json")
    Refused(["binary", Input, "-o", Out, "--no-pdb"], [Input], "an input at the sidecar path")
    Input = Copy("out.sqlite.dsig-tmp-4242")
    Refused(["binary", Input, "-o", Out, "--no-pdb"], [Input], "an input named like the staging copy")
    Input = Copy("out.sqlite-wal.dsig-old-4242")
    Refused(["binary", Input, "-o", Out, "--no-pdb"], [Input], "an input named like a moved-aside sidecar")
    Input = Copy("out.export.json.tmp-4242")
    Refused(["binary", Input, "-o", Out, "--no-pdb"], [Input], "an input named like the sidecar's temporary file")
    if sys.platform == "win32":
        Input = Copy("OUT.SQLITE-WAL")
        Refused(["binary", Input, "-o", Out, "--no-pdb"], [Input], "a case variant (Windows)")
        Upper = os.path.join(Aliases, "CRYPTBASE.PDB")
        Refused(["binary", Pe, "-o", os.path.join(Aliases, "cryptbase.sqlite"), "--pdb", Upper,
                 "--sidecar", Pdb], [Pdb], "a sidecar that is the PDB under another case")
    Check(not os.path.exists(Out), "nothing was written by any refused run")


def TestGitLookup(Dir, FakeDiaphora):
    """F16: git is never resolved from the current directory, which is often the sample's own folder."""
    print("[git is never taken from the current directory]")
    Plant = os.path.join(Dir, "sample folder")
    os.makedirs(Plant)
    Marker = os.path.join(Dir, "planted git ran")
    if sys.platform == "win32":
        # The audit's repro: a copy of cmd.exe named git.exe; its banner used to become git_describe.
        shutil.copyfile(os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32", "cmd.exe"),
                        os.path.join(Plant, "git.exe"))
    else:
        with open(os.path.join(Plant, "git"), "w") as Handle:
            Handle.write("#!/bin/sh\necho PLANTED\ntouch '%s'\n" % Marker)
        os.chmod(os.path.join(Plant, "git"), 0o755)
    Saved = {Key: os.environ.get(Key) for Key in ("PATH", "NoDefaultCurrentDirectoryInExePath")}
    Cwd = os.getcwd()
    try:
        os.environ.pop("NoDefaultCurrentDirectoryInExePath", None)
        os.environ["PATH"] = os.pathsep.join([".", "", "sample folder"] + [Saved["PATH"] or ""])
        os.chdir(Plant)
        Found = dsig_export.FindProgramOnPath("git")
        Check(Found is None or os.path.normcase(os.path.dirname(Found)) != os.path.normcase(Plant),
              "git resolves outside the current directory: %s" % Found)
        Describe = dsig_export.DiaphoraIdentity(FakeDiaphora)["git_describe"]
        Check(Describe is None or ("Microsoft" not in Describe and "PLANTED" not in Describe),
              "git_describe is not the planted program's output: %r" % Describe)
        Check(not os.path.exists(Marker), "the planted git did not run")
    finally:
        os.chdir(Cwd)
        for Key, Value in Saved.items():
            if Value is None:
                os.environ.pop(Key, None)
            else:
                os.environ[Key] = Value


# Stand-ins for the idalib Python modules the worker imports (RunWorker, FunctionNameStats,
# PdbEvidence): enough for a whole driver + worker run without IDA. They are put first on the
# worker's PYTHONPATH, so a real idapro wheel in this Python is never loaded.
FAKE_IDALIB = {
    "idapro.py": "def get_library_version():\n    return (9, 9, 0)\n"
                 "def enable_console_messages(Enable):\n    pass\n"
                 "def open_database(Path, Auto, Args=None):\n    return 0\n"
                 "def close_database(Save=False):\n    pass\n",
    "idaapi.py": "class _Cvar:\n    batch = False\ncvar = _Cvar()\n"
                 "def get_kernel_version():\n    return '9.9'\n",
    "ida_auto.py": "def auto_wait():\n    return True\ndef auto_is_ok():\n    return True\n",
    "ida_hexrays.py": "import os\ndef init_hexrays_plugin():\n    return os.environ.get('FAKE_HEXRAYS', '1') == '1'\n"
                      "def get_hexrays_version():\n    return '9.9.0.1'\n",
    "ida_funcs.py": "import os\nFUNC_LIB = 4\nFUNC_THUNK = 128\ndef get_func(Ea):\n    return None\n"
                    "def get_func_qty():\n    return int(os.environ.get('FAKE_FUNC_QTY', '2'))\n",
    "ida_name.py": "def get_name(Ea):\n    return 'sub_%X' % Ea\n",
    "idautils.py": "def Functions():\n    return iter([0x1000, 0x2000])\n",
    "ida_netnode.py": "BADNODE = -1\nclass netnode:\n    def __init__(self, *Args):\n        pass\n"
                      "    def index(self):\n        return BADNODE\n",
}

# A stand-in with Diaphora's exporter interface (diaphora_ida.CIDABinDiff.do_export, _diff_or_export,
# diaphora.VERSION_VALUE) that writes a tiny database with the tables the driver's checks read.
FAKE_DIAPHORA = {
    "diaphora.py": 'VERSION_VALUE = "9.9"\n',
    "diaphora_config.py": "EXPORTING_USE_DECOMPILER = True\n",
    "diaphora_ida.py": '''import sqlite3
import diaphora

SCHEMA = """
create table functions (id integer primary key, name text, pseudocode text, microcode text);
create table basic_blocks (id integer primary key, asm_type text);
create table bb_instructions (id integer primary key);
create table bb_relations (id integer primary key);
create table callgraph (id integer primary key, type text);
create table constants (id integer primary key);
create table function_bblocks (id integer primary key);
create table instructions (id integer primary key, asm_type text);
create table program (id integer primary key, callgraph_primes text);
create table program_data (id integer primary key);
create table compilation_units (id integer primary key, name text);
create table version (value text);
insert into functions (name, pseudocode, microcode) values ('main', 'int main() {}', 'm'), ('sub_1000', 'x', 'y');
insert into program (callgraph_primes) values ('6');
insert into version values ('9.9');
"""


class CIDABinDiff:
    def __init__(self, Out):
        self.Out = Out
        self.use_decompiler = True
        self.decompiler_available = True
        self.export_microcode = True
        self.ida_subs = True
        self.exclude_library_thunk = True
        self.function_summaries_only = False
        self.min_ea = 0
        self.max_ea = 0xFFFFFFFF
        self.project_script = None

    def do_export(self, crashed_before=False):
        Con = sqlite3.connect(self.Out)
        Con.executescript(SCHEMA)
        Con.commit()
        Con.close()


def _diff_or_export(use_ui, **options):
    Bd = CIDABinDiff(options["file_out"])
    Bd.do_export()
    return Bd
''',
}


def WriteFiles(Dir, Files):
    os.makedirs(Dir, exist_ok=True)
    for Name, Text in Files.items():
        with open(os.path.join(Dir, Name), "w", encoding="utf-8", newline="\n") as Handle:
            Handle.write(Text)


def ReadBytes(Path):
    with open(Path, "rb") as Handle:
        return Handle.read()


def TestFakeIdaRuns(Dir):
    """Whole driver + worker runs against stand-in idalib modules (lane F1)."""
    print("[driver + worker with stand-in idalib and Diaphora]")
    for Key in ("DSIG_IDADIR", "IDADIR", "DSIG_DIAPHORA_DIR", "DSIG_EXPORT_ALLOW_NO_DECOMPILER"):
        os.environ.pop(Key, None)
    Saved = {Key: os.environ.get(Key) for Key in ("IDAUSR", "PYTHONPATH", "FAKE_HEXRAYS", "FAKE_FUNC_QTY",
                                                  "DSIG_EXPORT_ALLOW_NO_DECOMPILER")}
    EmptyUser = os.path.join(Dir, "fake idausr")
    os.makedirs(EmptyUser)
    os.environ["IDAUSR"] = EmptyUser
    Idalib = os.path.join(Dir, "fake idalib")
    WriteFiles(Idalib, FAKE_IDALIB)
    # CleanEnv drops the caller's PYTHONPATH (F66), so the stand-ins are put on the worker's path here,
    # after the cleaning, exactly as a test double and never through the environment.
    RealCleanEnv = dsig_export.CleanEnv

    def CleanEnvWithStandIns():
        Env, Removed = RealCleanEnv()
        Env["PYTHONPATH"] = Idalib
        return Env, Removed

    dsig_export.CleanEnv = CleanEnvWithStandIns
    FakeIda = os.path.join(Dir, "fake ida")
    os.makedirs(FakeIda)
    with open(os.path.join(FakeIda, dsig_export.IdaLibraryName()), "wb") as Handle:
        Handle.write(b"x")
    Working = os.path.join(Dir, "fake diaphora")
    WriteFiles(Working, FAKE_DIAPHORA)
    # The right file names, but not Diaphora: every module imports, none has the exporter.
    NotDiaphora = os.path.join(Dir, "not diaphora")
    WriteFiles(NotDiaphora, {"diaphora.py": "", "diaphora_ida.py": "", "diaphora_config.py": ""})
    Broken = os.path.join(Dir, "broken diaphora")
    WriteFiles(Broken, {"diaphora.py": "", "diaphora_ida.py": "this is not python\n", "diaphora_config.py": ""})
    Pe = os.path.join(Dir, "fake.dll")
    SyntheticPe(Pe)
    Out = os.path.join(Dir, "fake out.sqlite")
    Tools = ["--ida-dir", FakeIda, "--temp-dir", Dir]
    try:
        # (a) not Diaphora: the "Diaphora not usable" class (12, CLI exit 4), not an export failure (16)
        Code = RunMain(["binary", Pe, "-o", Out, "--diaphora-dir", NotDiaphora] + Tools)
        Check(Code == dsig_export.EXIT_DIAPHORA, "a directory with Diaphora's file names that is not Diaphora: "
              "exit %s, want %d" % (Code, dsig_export.EXIT_DIAPHORA))
        Code = RunMain(["binary", Pe, "-o", Out, "--diaphora-dir", Broken] + Tools)
        Check(Code == dsig_export.EXIT_DIAPHORA, "a Diaphora that does not import: exit %s" % Code)
        Check(not os.path.exists(Out), "nothing was written")

        # a successful run replaces a previous output and clears that output's stale sidecars
        Stale = {Out: b"previous output", Out + "-wal": b"old wal", Out + "-shm": b"old shm",
                 Out + "-journal": b"old journal", Out + "-crash": b""}
        for Path, Data in Stale.items():
            with open(Path, "wb") as Handle:
                Handle.write(Data)
        Code = RunMain(["binary", Pe, "-o", Out, "--diaphora-dir", Working] + Tools)
        Check(Code == dsig_export.EXIT_OK, "a run with the stand-ins succeeds: exit %s" % Code)
        Check(ReadBytes(Out)[:15] == b"SQLite format 3", "the output is the new database")
        Check(all(not os.path.exists(Out + Suffix) for Suffix in ("-wal", "-shm", "-journal", "-crash")),
              "the previous output's sidecars are gone")
        Check(os.path.isfile(dsig_export.DefaultSidecar(Out)), "the .export.json sidecar was written")
        Leftovers = [Name for Name in os.listdir(Dir) if ".dsig-tmp-" in Name or ".dsig-old-" in Name]
        Check(not Leftovers, "no staging or moved-aside files are left: %s" % Leftovers)

        # (b) the replace fails: the previous output and ALL its sidecars stay exactly as they were
        Previous = {Out: ReadBytes(Out), Out + "-wal": b"committed frames of the previous output",
                    Out + "-shm": b"shm of the previous output", Out + "-journal": b"journal of the previous output"}
        for Path, Data in Previous.items():
            with open(Path, "wb") as Handle:
                Handle.write(Data)
        RealReplace = os.replace
        Target = os.path.normcase(os.path.abspath(Out))

        def FailingReplace(Source, Destination, *Args, **Kwargs):
            if os.path.normcase(os.path.abspath(Destination)) == Target:
                raise PermissionError(13, "simulated: the output is in use", Destination)
            return RealReplace(Source, Destination, *Args, **Kwargs)

        os.replace = FailingReplace
        try:
            Code = RunMain(["binary", Pe, "-o", Out, "--diaphora-dir", Working] + Tools)
        finally:
            os.replace = RealReplace
        Check(Code == dsig_export.EXIT_OUTPUT, "a failed replace is an output error: exit %s" % Code)
        for Path, Data in Previous.items():
            Check(os.path.isfile(Path) and ReadBytes(Path) == Data,
                  "after a failed replace %s is unchanged" % os.path.basename(Path))
        Leftovers = [Name for Name in os.listdir(Dir) if ".dsig-tmp-" in Name or ".dsig-old-" in Name]
        Check(not Leftovers, "no staging or moved-aside files are left after the failure: %s" % Leftovers)

        Good = ["binary", Pe, "-o", Out, "--diaphora-dir", Working] + Tools
        TestCallerPythonPath(Dir, Good, Out)
        TestNoFunctionsAndHexRays(Good, Out)
        TestSweep(Dir, Good)
        TestLauncherGone(Good, Out)
    finally:
        dsig_export.CleanEnv = RealCleanEnv
        for Key, Value in Saved.items():
            if Value is None:
                os.environ.pop(Key, None)
            else:
                os.environ[Key] = Value


def TestCallerPythonPath(Dir, Good, Out):
    """F66: a sitecustomize on the caller's PYTHONPATH that would kill the worker is never loaded, and the
    sidecar records that PYTHONPATH was removed."""
    print("[the caller's PYTHONPATH does not reach the worker]")
    Poison = os.path.join(Dir, "poison path")
    WriteFiles(Poison, {"sitecustomize.py": "import os\nos._exit(42)\n"})
    Saved = os.environ.get("PYTHONPATH")
    os.environ["PYTHONPATH"] = Poison
    try:
        Code = RunMain(Good)
    finally:
        if Saved is None:
            os.environ.pop("PYTHONPATH", None)
        else:
            os.environ["PYTHONPATH"] = Saved
    Check(Code == dsig_export.EXIT_OK, "the run ignores a PYTHONPATH sitecustomize: exit %s" % Code)
    try:
        with open(dsig_export.DefaultSidecar(Out), "r", encoding="utf-8") as Handle:
            Removed = json.load(Handle)["isolation"]["removed_environment"]
    except (OSError, ValueError, KeyError) as Exc:
        Removed = "unreadable: %s" % Exc
    Check(isinstance(Removed, list) and "PYTHONPATH" in Removed,
          "the sidecar lists PYTHONPATH as removed: %s" % Removed)


def TestNoFunctionsAndHexRays(Good, Out):
    print("[no functions (F57 d) and Hex-Rays advice (F46)]")
    Before = ReadBytes(Out)
    os.environ["FAKE_FUNC_QTY"] = "0"
    try:
        Code = RunMain(Good)
    finally:
        os.environ.pop("FAKE_FUNC_QTY", None)
    Check(Code == dsig_export.EXIT_OPEN, "IDA found no functions: exit %s, want %d (CLI exit 4)"
          % (Code, dsig_export.EXIT_OPEN))
    Check(ReadBytes(Out) == Before, "the previous output is kept")

    Messages = []
    RealLogError = dsig_export.LogError
    dsig_export.LogError = lambda Message: (Messages.append(Message), RealLogError(Message))
    os.environ["FAKE_HEXRAYS"] = "0"
    try:
        Code = RunMain(Good)
        Check(Code == dsig_export.EXIT_HEXRAYS, "no Hex-Rays: exit %s, want %d" % (Code, dsig_export.EXIT_HEXRAYS))
        Check(any("DSIG_EXPORT_ALLOW_NO_DECOMPILER=1" in Message for Message in Messages),
              "the refusal names the variable that works through dsigmatcher: %s" % Messages)
        os.environ["DSIG_EXPORT_ALLOW_NO_DECOMPILER"] = "1"
        Code = RunMain(Good)
        Check(Code == dsig_export.EXIT_OK, "DSIG_EXPORT_ALLOW_NO_DECOMPILER=1 exports anyway: exit %s" % Code)
    finally:
        dsig_export.LogError = RealLogError
        os.environ.pop("FAKE_HEXRAYS", None)
        os.environ.pop("DSIG_EXPORT_ALLOW_NO_DECOMPILER", None)


def TestSweep(Dir, Good):
    """F43: a run removes the work directories of runs that were killed, and only those."""
    print("[work directories left by killed runs are swept]")
    Dead = 0x7FFFFFF0  # no such process on any platform (above every pid_max; invalid on Windows)

    def MakeWork(Name, Owner, AgeSeconds=0):
        Path = os.path.join(Dir, Name)
        os.makedirs(os.path.join(Path, "work"))
        with open(os.path.join(Path, "work", "copy.i64"), "wb") as Handle:
            Handle.write(b"IDA2 copy of the user's database")
        if Owner is not None:
            with open(os.path.join(Path, dsig_export.OWNER_FILE), "w", encoding="utf-8") as Handle:
                json.dump(Owner, Handle)
        if AgeSeconds:
            Then = time.time() - AgeSeconds
            os.utime(Path, (Then, Then))
        return Path

    Tool = dsig_export.TOOL_NAME
    Killed = MakeWork("dsig-export-dead0001", {"tool": Tool, "pid": Dead, "start": None})
    KilledWithWorker = MakeWork("dsig-export-dead0002", {"tool": Tool, "pid": Dead, "worker_pid": Dead + 1})
    Live = MakeWork("dsig-export-live0001", {"tool": Tool, "pid": os.getpid(),
                                             "start": dsig_export.ProcessStart(os.getpid())})
    LiveWorker = MakeWork("dsig-export-live0002", {"tool": Tool, "pid": Dead, "worker_pid": os.getpid()})
    Kept = MakeWork("dsig-export-kept0001", {"tool": Tool, "pid": Dead, "kept": True})
    FreshUnowned = MakeWork("dsig-export-noown001", None)
    OldUnowned = MakeWork("dsig-export-oldnown1", None, AgeSeconds=3 * 24 * 3600)
    NotOurs = MakeWork("dsig-export-selftest-abcdefgh", None, AgeSeconds=3 * 24 * 3600)
    Foreign = MakeWork("dsig-export-frgn0001", {"tool": "something else", "pid": Dead})
    Code = RunMain(Good)
    Check(Code == dsig_export.EXIT_OK, "the sweeping run succeeds: exit %s" % Code)
    for Path in (Killed, KilledWithWorker, OldUnowned):
        Check(not os.path.exists(Path), "removed: %s" % os.path.basename(Path))
    for Path in (Live, LiveWorker, Kept, FreshUnowned, NotOurs, Foreign):
        Check(os.path.isdir(Path), "kept: %s" % os.path.basename(Path))
    # A process that really ran and was killed: its pid is dead afterwards.
    Child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    Start = dsig_export.ProcessStart(Child.pid)
    Check(dsig_export.ProcessAlive(Child.pid, Start), "a running process is alive")
    Child.kill()
    Child.wait()
    Check(not dsig_export.ProcessAlive(Child.pid, Start), "a killed process is not alive")
    # --keep-temp marks its directory kept, so the next run does not sweep it.
    Code = RunMain(Good + ["--keep-temp"])
    Check(Code == dsig_export.EXIT_OK, "a --keep-temp run succeeds: exit %s" % Code)
    KeptDirs = [Name for Name in os.listdir(Dir) if dsig_export.WORK_NAME_RE.match(Name)
                and Name not in ("dsig-export-live0001", "dsig-export-live0002", "dsig-export-kept0001",
                                 "dsig-export-noown001", "dsig-export-frgn0001")]
    Check(len(KeptDirs) == 1, "one kept work directory: %s" % KeptDirs)
    if KeptDirs:
        with open(os.path.join(Dir, KeptDirs[0], dsig_export.OWNER_FILE), "r", encoding="utf-8") as Handle:
            Check(json.load(Handle).get("kept") is True, "its owner file says kept")
        Code = RunMain(Good)
        Check(os.path.isdir(os.path.join(Dir, KeptDirs[0])), "a later run leaves the kept directory alone")
        shutil.rmtree(os.path.join(Dir, KeptDirs[0]), ignore_errors=True)
    for Path in (Live, LiveWorker, Kept, FreshUnowned, NotOurs, Foreign):
        shutil.rmtree(Path, ignore_errors=True)


def TestLauncherGone(Good, Out):
    """F44: when the launcher dies (POSIX re-parents the script, so getppid changes), nothing is published."""
    print("[a run whose launcher went away publishes nothing]")
    Before = ReadBytes(Out)
    RealGetppid = os.getppid
    Calls = [0]

    def Reparented():
        Calls[0] += 1
        return RealGetppid() if Calls[0] == 1 else RealGetppid() + 1  # the first call is the watch's baseline

    os.getppid = Reparented
    try:
        Code = RunMain(Good)
    finally:
        os.getppid = RealGetppid
    Check(Code == dsig_export.EXIT_INTERRUPTED, "exit %s, want %d" % (Code, dsig_export.EXIT_INTERRUPTED))
    Check(ReadBytes(Out) == Before, "the output was not replaced")


def TestImportDiaphora(Dir):
    print("[ImportDiaphora: the exporter interface]")
    NotDiaphora = os.path.join(Dir, "import not diaphora")
    WriteFiles(NotDiaphora, {"diaphora.py": "", "diaphora_ida.py": "class CIDABinDiff:\n    pass\n",
                             "diaphora_config.py": ""})
    Names = ("diaphora", "diaphora_ida", "diaphora_config")
    try:
        dsig_export.ImportDiaphora(NotDiaphora)
        Check(False, "a module without the exporter interface must be refused")
    except dsig_export.ExportError as Exc:
        Check(Exc.Code == dsig_export.EXIT_DIAPHORA and "Diaphora not usable" in Exc.Message
              and "CIDABinDiff.do_export" in Exc.Message and "_diff_or_export" in Exc.Message,
              "refusal names what is missing: %s" % Exc.Message)
    finally:
        for Name in Names:
            sys.modules.pop(Name, None)
        while NotDiaphora in sys.path:
            sys.path.remove(NotDiaphora)


def Main():
    Dir = tempfile.mkdtemp(prefix="dsig-export-selftest-")
    try:
        TestIdentityReaders(Dir)
        TestSmallPieces()
        TestDriverChecks(Dir)
        TestGitLookup(Dir, os.path.join(Dir, "diaphora"))
        TestImportDiaphora(Dir)
        TestFakeIdaRuns(os.path.join(Dir, "runs"))
    finally:
        shutil.rmtree(Dir, ignore_errors=True)
    print("\n%d checks, %d failed" % (CHECKS[0], CHECKS[1]))
    return 0 if CHECKS[1] == 0 else 1


if __name__ == "__main__":
    sys.exit(Main())
