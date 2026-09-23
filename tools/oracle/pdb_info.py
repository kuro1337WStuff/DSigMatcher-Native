#!/usr/bin/env python3

"""Read the identity (GUID and ages) of an MSF 7.00 PDB, and compare it with a PE.

A PE names its PDB through a CodeView "RSDS" debug record: a GUID, an age and
a file name (tools/prepare_corpus.py ReadCodeView). The symbol server files a
PDB under that GUID and age, but a downloaded file can still be the wrong one
(a cached copy, a manual copy, a truncated response). This script opens the
PDB itself and reads:

  * the PDB info stream (stream 1): version, signature, age, GUID;
  * the DBI stream (stream 3) header: its age, which is the one the linker
    writes into the RSDS record.

A PDB matches a PE when the GUIDs are equal and the DBI age equals the RSDS
age. The layout is the documented MSF 7.00 container: a superblock, a block map
holding the stream directory's block list, and a directory of stream sizes and
block lists.

    python pdb_info.py some.pdb [--pe some.dll]
"""

import argparse
import json
import os
import struct
import sys

MSF7_MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"
NIL_STREAM = 0xFFFFFFFF
PDB_INFO_STREAM = 1
DBI_STREAM = 3


class PdbFormatError(Exception):
    pass


def GuidText(Data1, Data2, Data3, Data4):
    """Same spelling as tools/prepare_corpus.py ReadCodeView (upper-case hex, no dashes)."""
    return "%08X%04X%04X%s" % (Data1, Data2, Data3, Data4.hex().upper())


def _Blocks(Size, BlockSize):
    return (Size + BlockSize - 1) // BlockSize


def ReadStreams(Blob, Wanted):
    """Return {stream index: bytes} for the wanted streams of an MSF 7.00 file."""
    if len(Blob) < len(MSF7_MAGIC) + 24 or not Blob.startswith(MSF7_MAGIC):
        raise PdbFormatError("not an MSF 7.00 file")
    BlockSize, _FreeMap, NumBlocks, DirBytes, _Unknown, BlockMapAddr = struct.unpack_from(
        "<6I", Blob, len(MSF7_MAGIC))
    if BlockSize not in (512, 1024, 2048, 4096, 8192, 16384, 32768):
        raise PdbFormatError("unexpected block size %d" % BlockSize)
    if NumBlocks * BlockSize > len(Blob):
        raise PdbFormatError("file is shorter than its %d blocks" % NumBlocks)

    def Block(Index):
        if Index >= NumBlocks:
            raise PdbFormatError("block %d out of range" % Index)
        return Blob[Index * BlockSize:(Index + 1) * BlockSize]

    DirBlockCount = _Blocks(DirBytes, BlockSize)
    MapOffset = BlockMapAddr * BlockSize
    DirBlockList = struct.unpack_from("<%dI" % DirBlockCount, Blob, MapOffset)
    Directory = b"".join(Block(Index) for Index in DirBlockList)[:DirBytes]

    (NumStreams,) = struct.unpack_from("<I", Directory, 0)
    Sizes = struct.unpack_from("<%dI" % NumStreams, Directory, 4)
    Offset = 4 + 4 * NumStreams
    Result = {}
    for Stream, Size in enumerate(Sizes):
        Count = 0 if Size == NIL_STREAM else _Blocks(Size, BlockSize)
        BlockList = struct.unpack_from("<%dI" % Count, Directory, Offset)
        Offset += 4 * Count
        if Stream in Wanted:
            Result[Stream] = b"".join(Block(Index) for Index in BlockList)[:0 if Size == NIL_STREAM else Size]
    return Result


def ReadPdbIdentity(Path):
    with open(Path, "rb") as Handle:
        Blob = Handle.read()
    Streams = ReadStreams(Blob, {PDB_INFO_STREAM, DBI_STREAM})
    Info = Streams.get(PDB_INFO_STREAM, b"")
    if len(Info) < 28:
        raise PdbFormatError("PDB info stream is missing or short (%d bytes)" % len(Info))
    Version, Signature, InfoAge = struct.unpack_from("<3I", Info, 0)
    Data1, Data2, Data3 = struct.unpack_from("<IHH", Info, 12)
    Guid = GuidText(Data1, Data2, Data3, Info[20:28])
    Identity = {"guid": Guid, "info_age": InfoAge, "info_version": Version,
                "info_signature": Signature, "dbi_age": None}
    Dbi = Streams.get(DBI_STREAM, b"")
    if len(Dbi) >= 12:
        # DBI header: int32 VersionSignature, uint32 VersionHeader, uint32 Age.
        Identity["dbi_age"] = struct.unpack_from("<I", Dbi, 8)[0]
    return Identity


def MatchPe(PdbPath, PePath):
    """Compare a PDB's identity with the RSDS record of a PE (read with prepare_corpus.ReadCodeView)."""
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
    import prepare_corpus
    CodeView = prepare_corpus.ReadCodeView(PePath)
    Identity = ReadPdbIdentity(PdbPath)
    Result = {"pdb": Identity, "pe_codeview": CodeView}
    if CodeView is None:
        Result["match"] = False
        Result["reason"] = "the PE has no RSDS record"
        return Result
    GuidOk = CodeView["guid"] == Identity["guid"]
    AgeOk = Identity["dbi_age"] == CodeView["age"]
    Result["guid_match"] = GuidOk
    Result["age_match"] = AgeOk
    Result["match"] = GuidOk and AgeOk
    return Result


def Main():
    Parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    Parser.add_argument("pdb")
    Parser.add_argument("--pe", default=None, help="compare with this PE's RSDS record")
    Args = Parser.parse_args()
    if Args.pe:
        Result = MatchPe(Args.pdb, Args.pe)
    else:
        Result = ReadPdbIdentity(Args.pdb)
    print(json.dumps(Result, indent=2))
    return 0 if (not Args.pe or Result.get("match")) else 1


if __name__ == "__main__":
    sys.exit(Main())
