#!/usr/bin/env python3

"""Self-test of dsig_export.py that needs neither IDA nor Diaphora.

Checks the pieces that run before IDA starts: the PE RSDS reader and the MSF 7.00 PDB identity reader
on synthetic files, the sidecar name, the environment cleaning, and the driver's argument and tool
checks with their exit codes (tool discovery is pointed at empty or fake directories, so the user's
real IDA configuration is never read). Prints "<n> checks, <f> failed" and exits non-zero on failure.

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


def Main():
    Dir = tempfile.mkdtemp(prefix="dsig-export-selftest-")
    try:
        TestIdentityReaders(Dir)
        TestSmallPieces()
        TestDriverChecks(Dir)
    finally:
        shutil.rmtree(Dir, ignore_errors=True)
    print("\n%d checks, %d failed" % (CHECKS[0], CHECKS[1]))
    return 0 if CHECKS[1] == 0 else 1


if __name__ == "__main__":
    sys.exit(Main())
