#!/usr/bin/env python3

"""Collect a versioned pair of Microsoft binaries plus their PDBs for benchmarking.

Reads each PE's CodeView debug record to recover the PDB name, GUID and age, then
fetches the matching PDB from the Microsoft public symbol server. Writes a manifest
with SHA-256 digests so a corpus can be reproduced or verified later.
"""

import hashlib
import os
import shutil
import struct
import sys
import urllib.error
import urllib.request

import pefile

SYMBOL_SERVER = "https://msdl.microsoft.com/download/symbols"
IMAGE_DEBUG_TYPE_CODEVIEW = 2
RSDS = b"RSDS"


def Sha256OfFile(Path):
    Digest = hashlib.sha256()
    with open(Path, "rb") as Handle:
        for Chunk in iter(lambda: Handle.read(1024 * 1024), b""):
            Digest.update(Chunk)
    return Digest.hexdigest()


def ReadCodeView(Path):
    Pe = pefile.PE(Path, fast_load=True)
    try:
        Pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"]])

        Entries = getattr(Pe, "DIRECTORY_ENTRY_DEBUG", None)
        if not Entries:
            return None

        Raw = None
        with open(Path, "rb") as Handle:
            Raw = Handle.read()

        for Entry in Entries:
            if Entry.struct.Type != IMAGE_DEBUG_TYPE_CODEVIEW:
                continue

            Size = int(Entry.struct.SizeOfData)
            if Size < 24:
                continue

            Offset = int(Entry.struct.PointerToRawData)
            if Offset > 0 and Offset + Size <= len(Raw):
                Blob = Raw[Offset:Offset + Size]
            else:
                try:
                    Blob = Pe.get_data(int(Entry.struct.AddressOfRawData), Size)
                except Exception:
                    continue

            if Blob[:4] != RSDS:
                continue

            Data1, Data2, Data3 = struct.unpack_from("<IHH", Blob, 4)
            Data4 = Blob[12:20]
            Age = struct.unpack_from("<I", Blob, 20)[0]

            NameBytes = Blob[24:].split(b"\x00", 1)[0]
            PdbName = os.path.basename(NameBytes.decode("utf-8", "replace").replace("\\", "/"))

            Guid = "%08X%04X%04X%s" % (Data1, Data2, Data3, Data4.hex().upper())

            return {
                "pdb_name": PdbName,
                "guid": Guid,
                "age": Age,
                "machine": hex(Pe.FILE_HEADER.Machine),
            }
    finally:
        Pe.close()


def SymbolUrl(CodeView):
    Key = "%s%X" % (CodeView["guid"], CodeView["age"])
    return "%s/%s/%s/%s" % (SYMBOL_SERVER, CodeView["pdb_name"], Key, CodeView["pdb_name"])


def Fetch(Url, Destination):
    Request = urllib.request.Request(Url, headers={"User-Agent": "dsigmatcher-corpus/0.1"})
    try:
        with urllib.request.urlopen(Request, timeout=180) as Response:
            Data = Response.read()
    except urllib.error.HTTPError as Error:
        return False, "HTTP %d" % Error.code
    except Exception as Error:
        return False, str(Error)

    if not Data:
        return False, "empty response"

    with open(Destination, "wb") as Handle:
        Handle.write(Data)
    return True, "%d bytes" % len(Data)


def Label(Path):
    Base = os.path.splitext(os.path.basename(Path))[0]
    Parent = os.path.basename(os.path.dirname(Path))

    for Token in Parent.split("_"):
        if Token.count(".") == 3 and Token[0].isdigit():
            return "%s_%s" % (Base, Token.replace(".", ""))

    Version = None
    try:
        import win32api
        Version = win32api.GetFileVersionInfo(Path, "\\")
    except Exception:
        Version = None

    if Version:
        High = Version["FileVersionMS"]
        Low = Version["FileVersionLS"]
        Parts = (High >> 16, High & 0xFFFF, Low >> 16, Low & 0xFFFF)
        return "%s_%d%d%d%d" % (Base, Parts[0], Parts[1], Parts[2], Parts[3])

    return "%s_%s" % (Base, Parent[-8:] if Parent else "unknown")


def main():
    if len(sys.argv) < 3:
        print("usage: prepare_corpus.py <outdir> <binary> [<binary> ...]")
        return 1

    OutDir = sys.argv[1]
    Sources = sys.argv[2:]
    os.makedirs(OutDir, exist_ok=True)

    Manifest = []

    for Source in Sources:
        if not os.path.isfile(Source):
            print("skip (not a file): %s" % Source)
            continue

        Name = Label(Source)
        VersionDir = os.path.join(OutDir, Name)
        os.makedirs(VersionDir, exist_ok=True)

        BinaryOut = os.path.join(VersionDir, os.path.basename(Source))
        shutil.copyfile(Source, BinaryOut)
        print("\n%s" % Name)
        print("  source   : %s" % Source)
        print("  binary   : %s" % BinaryOut)

        CodeView = ReadCodeView(BinaryOut)
        if CodeView is None:
            print("  no CodeView RSDS record; PDB cannot be resolved")
            Manifest.append({
                "label": Name, "binary": os.path.relpath(BinaryOut, OutDir),
                "binary_sha256": Sha256OfFile(BinaryOut), "pdb": None,
            })
            continue

        PdbOut = os.path.join(VersionDir, CodeView["pdb_name"])

        print("  pdb      : %s  guid=%s age=%d machine=%s"
              % (CodeView["pdb_name"], CodeView["guid"], CodeView["age"], CodeView["machine"]))

        Url = SymbolUrl(CodeView)
        print("  fetching : %s" % Url)
        Ok, Detail = Fetch(Url, PdbOut)
        if not Ok:
            print("  FAILED   : %s" % Detail)
            Manifest.append({
                "label": Name, "binary": os.path.relpath(BinaryOut, OutDir),
                "binary_sha256": Sha256OfFile(BinaryOut), "pdb": None,
                "pdb_url": Url, "pdb_error": Detail,
            })
            continue

        print("  saved    : %s (%s)" % (PdbOut, Detail))
        Manifest.append({
            "label": Name,
            "binary": os.path.relpath(BinaryOut, OutDir),
            "binary_sha256": Sha256OfFile(BinaryOut),
            "pdb": os.path.relpath(PdbOut, OutDir),
            "pdb_sha256": Sha256OfFile(PdbOut),
            "pdb_url": Url,
            "pdb_guid": CodeView["guid"],
            "pdb_age": CodeView["age"],
        })

    ManifestPath = os.path.join(OutDir, "corpus_manifest.txt")
    with open(ManifestPath, "w", encoding="utf-8") as Handle:
        for Entry in Manifest:
            for Key in sorted(Entry):
                Handle.write("%-16s %s\n" % (Key + ":", Entry[Key]))
            Handle.write("\n")

    print("\nmanifest   : %s" % ManifestPath)
    Resolved = sum(1 for Entry in Manifest if Entry.get("pdb"))
    print("resolved   : %d of %d binaries have a PDB" % (Resolved, len(Manifest)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
