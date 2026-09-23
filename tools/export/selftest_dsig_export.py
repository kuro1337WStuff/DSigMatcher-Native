#!/usr/bin/env python3

"""Self-test of dsig_export.py that needs neither IDA nor Diaphora.

Checks the pieces that run before IDA starts: the PE RSDS reader and the MSF 7.00 PDB identity reader
on synthetic files, the sidecar name, the environment cleaning, and the driver's argument and tool
checks with their exit codes (tool discovery is pointed at empty or fake directories, so the user's
real IDA configuration is never read). Then whole driver + worker runs against stand-in idalib and
Diaphora modules written at run time (lane F1): a directory with Diaphora's file names that is not
Diaphora is "Diaphora not usable" (exit 12), and publishing never deletes the previous output's
sidecars before the atomic replace has succeeded. Prints "<n> checks, <f> failed" and exits non-zero
on failure.

    python -B tools/export/selftest_dsig_export.py
"""

import os
import shutil
import struct
import sys
import tempfile

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
    os.environ["DIAPHORA_USE_DECOMPILER"] = "0"
    os.environ["diaphora_lowercase"] = "1"
    os.environ["IDA_IS_INTERACTIVE"] = "1"
    try:
        Env, Removed = dsig_export.CleanEnv()
        Check(not any(Key.upper().startswith("DIAPHORA_") for Key in Env), "DIAPHORA_* removed")
        Check("IDA_IS_INTERACTIVE" not in Env, "IDA_IS_INTERACTIVE removed")
        Check(Env.get("PYTHONDONTWRITEBYTECODE") == "1", "no bytecode")
        Check(len(Removed) >= 1, "removed variables are reported")
    finally:
        for Key in ("DIAPHORA_USE_DECOMPILER", "diaphora_lowercase", "IDA_IS_INTERACTIVE"):
            os.environ.pop(Key, None)


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
    os.environ.pop("IDAUSR", None)


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
    "ida_hexrays.py": "def init_hexrays_plugin():\n    return True\ndef get_hexrays_version():\n    return '9.9.0.1'\n",
    "ida_funcs.py": "FUNC_LIB = 4\nFUNC_THUNK = 128\ndef get_func(Ea):\n    return None\n",
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
    Saved = {Key: os.environ.get(Key) for Key in ("IDAUSR", "PYTHONPATH")}
    EmptyUser = os.path.join(Dir, "fake idausr")
    os.makedirs(EmptyUser)
    os.environ["IDAUSR"] = EmptyUser
    Idalib = os.path.join(Dir, "fake idalib")
    WriteFiles(Idalib, FAKE_IDALIB)
    os.environ["PYTHONPATH"] = Idalib  # inherited by the worker through CleanEnv()
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
    finally:
        for Key, Value in Saved.items():
            if Value is None:
                os.environ.pop(Key, None)
            else:
                os.environ[Key] = Value


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
        TestImportDiaphora(Dir)
        TestFakeIdaRuns(os.path.join(Dir, "runs"))
    finally:
        shutil.rmtree(Dir, ignore_errors=True)
    print("\n%d checks, %d failed" % (CHECKS[0], CHECKS[1]))
    return 0 if CHECKS[1] == 0 else 1


if __name__ == "__main__":
    sys.exit(Main())
