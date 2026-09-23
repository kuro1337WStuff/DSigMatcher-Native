#!/usr/bin/env python3

"""Cross-audit the native PeImage parser against pefile, an independent implementation.

Reads a dump produced by tools/dump_pe.cpp and compares every field it can against
pefile's view of the same binary. Any mismatch is a bug in one of the two, and is
reported rather than tolerated.
"""

import os
import sys

import pefile


def ParseDump(Path):
    Sections = []
    Exports = []
    Headers = {}
    ExportDir = {}
    CodeView = {}
    RoundTripFailures = []
    Current = None

    with open(Path, "r", encoding="utf-8") as Handle:
        for Line in Handle:
            Line = Line.rstrip("\n").rstrip("\r")
            if not Line:
                continue
            if Line.startswith("#"):
                Current = Line[1:]
                continue

            if Current == "HEADERS":
                Key, _, Value = Line.partition(" ")
                Headers[Key] = Value
            elif Current == "SECTIONS":
                Parts = Line.split(" ")
                Sections.append({
                    "name": Parts[0],
                    "vaddr": int(Parts[1]),
                    "vsize": int(Parts[2]),
                    "rawptr": int(Parts[3]),
                    "rawsize": int(Parts[4]),
                    "nreloc": int(Parts[5]),
                    "nline": int(Parts[6]),
                    "chars": int(Parts[7]),
                })
            elif Current == "EXPORTDIR":
                Key, _, Value = Line.partition(" ")
                ExportDir[Key] = Value
            elif Current == "EXPORTS":
                Parts = Line.split(" ")
                Exports.append({
                    "ordinal": int(Parts[0]),
                    "rva": int(Parts[1]),
                    "named": Parts[2] == "1",
                    "forwarder": Parts[3] == "1",
                    "name": " ".join(Parts[4:]),
                })
            elif Current == "CODEVIEW":
                Key, _, Value = Line.partition(" ")
                CodeView[Key] = Value
            elif Current == "RVAMAP":
                if Line.startswith("rva_roundtrip_failure"):
                    RoundTripFailures.append(Line)

    return {
        "headers": Headers,
        "sections": Sections,
        "exportdir": ExportDir,
        "exports": Exports,
        "codeview": CodeView,
        "roundtrip_failures": RoundTripFailures,
    }


def ReadManifestGuid(ManifestPath, Label):
    if not os.path.isfile(ManifestPath):
        return None

    Result = None
    CurrentLabel = None
    CurrentGuid = None

    with open(ManifestPath, "r", encoding="utf-8") as Handle:
        for Line in Handle:
            Line = Line.rstrip()
            if not Line:
                if CurrentLabel == Label and CurrentGuid:
                    Result = CurrentGuid
                CurrentLabel = None
                CurrentGuid = None
                continue
            Key, _, Value = Line.partition(" ")
            Key = Key.rstrip(":")
            Value = Value.strip()
            if Key == "label":
                CurrentLabel = Value
            elif Key == "pdb_guid":
                CurrentGuid = Value

    if CurrentLabel == Label and CurrentGuid:
        Result = CurrentGuid
    return Result


def Audit(Label, DumpPath, DllPath):
    if not os.path.isfile(DumpPath):
        print("%s: dump missing (%s)" % (Label, DumpPath))
        return 1
    if not os.path.isfile(DllPath):
        print("%s: dll missing (%s)" % (Label, DllPath))
        return 1

    Dump = ParseDump(DumpPath)
    Pe = pefile.PE(DllPath, fast_load=True)
    Pe.parse_data_directories(directories=[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"],
    ])

    Mismatches = []

    def Compare(Field, Native, Expected):
        if Native != Expected:
            Mismatches.append("%s: native=%r pefile=%r" % (Field, Native, Expected))

    FileHeader = Pe.FILE_HEADER
    Optional = Pe.OPTIONAL_HEADER

    Compare("machine", int(Dump["headers"]["machine"]), FileHeader.Machine)
    Compare("number_of_sections", int(Dump["headers"]["number_of_sections"]),
            FileHeader.NumberOfSections)
    Compare("timedatestamp", int(Dump["headers"]["timedatestamp"]), FileHeader.TimeDateStamp)
    Compare("characteristics", int(Dump["headers"]["characteristics"]), FileHeader.Characteristics)
    Compare("optional_magic", int(Dump["headers"]["optional_magic"]), Optional.Magic)
    Compare("is_pe32_plus", int(Dump["headers"]["is_pe32_plus"]),
            1 if Optional.Magic == 0x20B else 0)
    Compare("size_of_code", int(Dump["headers"]["size_of_code"]), Optional.SizeOfCode)
    Compare("address_of_entry_point", int(Dump["headers"]["address_of_entry_point"]),
            Optional.AddressOfEntryPoint)
    Compare("base_of_code", int(Dump["headers"]["base_of_code"]), Optional.BaseOfCode)
    Compare("image_base", int(Dump["headers"]["image_base"]), Optional.ImageBase)
    Compare("section_alignment", int(Dump["headers"]["section_alignment"]),
            Optional.SectionAlignment)
    Compare("file_alignment", int(Dump["headers"]["file_alignment"]), Optional.FileAlignment)
    Compare("subsystem", int(Dump["headers"]["subsystem"]), Optional.Subsystem)
    Compare("dll_characteristics", int(Dump["headers"]["dll_characteristics"]),
            Optional.DllCharacteristics)
    Compare("size_of_image", int(Dump["headers"]["size_of_image"]), Optional.SizeOfImage)
    Compare("size_of_headers", int(Dump["headers"]["size_of_headers"]), Optional.SizeOfHeaders)
    Compare("checksum", int(Dump["headers"]["checksum"]), Optional.CheckSum)
    Compare("buffer_size", int(Dump["headers"]["buffer_size"]), os.path.getsize(DllPath))
    Compare("is_dll", int(Dump["headers"]["is_dll"]), 1 if Pe.is_dll() else 0)

    Compare("section_count", len(Dump["sections"]), len(Pe.sections))
    for Index, Native in enumerate(Dump["sections"]):
        if Index >= len(Pe.sections):
            break
        Expected = Pe.sections[Index]
        Prefix = "section[%d]" % Index
        Compare(Prefix + ".name", Native["name"],
                Expected.Name.rstrip(b"\x00").decode("utf-8", "replace"))
        Compare(Prefix + ".vaddr", Native["vaddr"], Expected.VirtualAddress)
        Compare(Prefix + ".vsize", Native["vsize"], Expected.Misc_VirtualSize)
        Compare(Prefix + ".rawptr", Native["rawptr"], Expected.PointerToRawData)
        Compare(Prefix + ".rawsize", Native["rawsize"], Expected.SizeOfRawData)
        Compare(Prefix + ".chars", Native["chars"], Expected.Characteristics)

    NativeExports = Dump["exports"]
    PefileExports = []
    if hasattr(Pe, "DIRECTORY_ENTRY_EXPORT"):
        for Entry in Pe.DIRECTORY_ENTRY_EXPORT.symbols:
            PefileExports.append({
                "ordinal": Entry.ordinal,
                "rva": Entry.address,
                "name": Entry.name.decode("utf-8", "replace") if Entry.name else None,
                "forwarder": Entry.forwarder.decode("utf-8", "replace") if Entry.forwarder else None,
            })

    Compare("export_count", len(NativeExports), len(PefileExports))

    NativeSet = {(E["ordinal"], E["rva"], E["name"] if E["named"] else None) for E in NativeExports}
    PefileSet = {(E["ordinal"], E["rva"], E["name"]) for E in PefileExports}
    Compare("export_set", len(NativeSet), len(PefileSet))
    Compare("export_set_equal", NativeSet == PefileSet, True)

    if NativeSet != PefileSet:
        OnlyNative = sorted(NativeSet - PefileSet)[:5]
        OnlyPefile = sorted(PefileSet - NativeSet)[:5]
        Mismatches.append("  only in native (first 5): %s" % OnlyNative)
        Mismatches.append("  only in pefile (first 5): %s" % OnlyPefile)

    NativeForwarders = sum(1 for E in NativeExports if E["forwarder"])
    PefileForwarders = sum(1 for E in PefileExports if E["forwarder"])
    Compare("forwarder_count", NativeForwarders, PefileForwarders)

    if hasattr(Pe, "DIRECTORY_ENTRY_EXPORT"):
        Compare("ordinal_base", int(Dump["exportdir"]["ordinal_base"]),
                Pe.DIRECTORY_ENTRY_EXPORT.struct.Base)
        Compare("number_of_functions", int(Dump["exportdir"]["number_of_functions"]),
                Pe.DIRECTORY_ENTRY_EXPORT.struct.NumberOfFunctions)
        Compare("number_of_names", int(Dump["exportdir"]["number_of_names"]),
                Pe.DIRECTORY_ENTRY_EXPORT.struct.NumberOfNames)

    PefileCodeView = None
    if hasattr(Pe, "DIRECTORY_ENTRY_DEBUG"):
        for Entry in Pe.DIRECTORY_ENTRY_DEBUG:
            if Entry.struct.Type == 2 and getattr(Entry, "entry", None) is not None:
                PefileCodeView = Entry.entry
                break

    Compare("codeview_present", int(Dump["codeview"].get("present", "0")),
            1 if PefileCodeView is not None else 0)

    if PefileCodeView is not None:
        Data4 = PefileCodeView.Signature_Data4
        Prefix = "%08X%04X%04X" % (
            PefileCodeView.Signature_Data1 & 0xFFFFFFFF,
            PefileCodeView.Signature_Data2 & 0xFFFF,
            PefileCodeView.Signature_Data3 & 0xFFFF,
        )
        NativeGuid = Dump["codeview"].get("guid", "")

        PefileReadableHex = Prefix
        if isinstance(Data4, int) and Data4 <= 0xFF:
            PefileReadableHex += "%02X" % Data4
            Note = ("pefile exposes Signature_Data4 as a single byte (0x%02X), so only the "
                    "first 9 GUID bytes are comparable" % Data4)
        else:
            Raw = bytes(Data4)[:8] if not isinstance(Data4, int) else Data4.to_bytes(8, "little")
            PefileReadableHex += Raw.hex().upper()
            Note = "pefile exposed the full 8-byte Data4"

        print("  guid (pefile)      : %s   [%s]" % (PefileReadableHex, Note))
        print("  guid (native)      : %s" % NativeGuid)

        if not NativeGuid.startswith(PefileReadableHex):
            Mismatches.append(
                "codeview_guid prefix: native=%s does not start with pefile=%s"
                % (NativeGuid, PefileReadableHex))

        Compare("codeview_age", int(Dump["codeview"].get("age", "-1")), PefileCodeView.Age)
        ExpectedPdb = os.path.basename(
            PefileCodeView.PdbFileName.rstrip(b"\x00").decode("utf-8", "replace").replace("\\", "/"))
        Compare("codeview_pdb_name", Dump["codeview"].get("pdb_name"), ExpectedPdb)

    ManifestPath = os.path.join(os.path.dirname(DllPath), "..", "corpus_manifest.txt")
    ExpectedGuid = ReadManifestGuid(ManifestPath, os.path.basename(os.path.dirname(DllPath)))
    if ExpectedGuid:
        Compare("codeview_guid vs symbol-server-validated manifest",
                Dump["codeview"].get("guid"), ExpectedGuid)
        print("  guid (manifest)    : %s  (validated by a successful symbol-server download)"
              % ExpectedGuid)

    Compare("rva_roundtrip_failures", len(Dump["roundtrip_failures"]), 0)

    print("%s  (%s)" % (Label, os.path.basename(DllPath)))
    print("  sections          : %d" % len(Dump["sections"]))
    print("  exports           : %d (pefile: %d)" % (len(NativeExports), len(PefileExports)))
    print("  distinct names    : %d" % len({E["name"] for E in NativeExports if E["named"]}))
    print("  forwarders        : %d" % NativeForwarders)
    print("  codeview guid     : %s age %s" % (Dump["codeview"].get("guid"),
                                               Dump["codeview"].get("age")))
    print("  rva roundtrip fail: %d" % len(Dump["roundtrip_failures"]))
    if Mismatches:
        print("  MISMATCHES        : %d" % len(Mismatches))
        for Item in Mismatches:
            print("    %s" % Item)
    else:
        print("  MISMATCHES        : 0  (all compared fields agree)")

    Pe.close()
    return len(Mismatches)


def main():
    Corpus = os.path.join(os.environ.get("DSIG_CORPUS_ROOT", "corpus"), "win32u")
    Verify = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "build", "verify")

    Pairs = [
        ("win32u_100261009168", os.path.join(Verify, "pe_a.txt"),
         os.path.join(Corpus, "win32u_100261009168", "win32u.dll")),
        ("win32u_100261009444", os.path.join(Verify, "pe_b.txt"),
         os.path.join(Corpus, "win32u_100261009444", "win32u.dll")),
    ]

    Total = 0
    for Label, DumpPath, DllPath in Pairs:
        Total += Audit(Label, DumpPath, DllPath)
        print("")

    print("total mismatches: %d" % Total)
    return 0 if Total == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
