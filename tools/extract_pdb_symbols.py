#!/usr/bin/env python3

"""Extract ground-truth function names and RVAs from a PDB using dbghelp.

Writes a TSV of rva, name, size, tag. Used as the oracle when scoring a diff: a
match is a true positive only if the PDB names on both sides agree.
"""

import ctypes
import os
import sys
from ctypes import wintypes

SYMOPT_UNDNAMES = 0x00000001
SYMOPT_DEFERRED_LOADS = 0x00000004
SYMOPT_LOAD_LINES = 0x00000010
SYMOPT_AUTO_PUBLICS = 0x00010000
SYMOPT_FAIL_CRITICAL_ERRORS = 0x00000020

SYMTAG_FUNCTION = 5
SYMTAG_PUBLIC = 10

FAKE_PROCESS = 0x1000
IMAGE_BASE = 0x180000000


class SYMBOL_INFO(ctypes.Structure):
    _fields_ = [
        ("SizeOfStruct", wintypes.ULONG),
        ("TypeIndex", wintypes.ULONG),
        ("Reserved", ctypes.c_uint64 * 2),
        ("Index", wintypes.ULONG),
        ("Size", wintypes.ULONG),
        ("ModBase", ctypes.c_uint64),
        ("Flags", wintypes.ULONG),
        ("Value", ctypes.c_uint64),
        ("Address", ctypes.c_uint64),
        ("Register", wintypes.ULONG),
        ("Scope", wintypes.ULONG),
        ("Tag", wintypes.ULONG),
        ("NameLen", wintypes.ULONG),
        ("MaxNameLen", wintypes.ULONG),
        ("Name", ctypes.c_char * 2048),
    ]


IMAGEHLP_SYMBOLW = SYMBOL_INFO

EnumProc = ctypes.WINFUNCTYPE(
    wintypes.BOOL, ctypes.POINTER(SYMBOL_INFO), wintypes.ULONG, ctypes.c_uint64)


class IMAGEHLP_MODULE64(ctypes.Structure):
    _fields_ = [
        ("SizeOfStruct", wintypes.DWORD),
        ("BaseOfImage", ctypes.c_uint64),
        ("ImageSize", wintypes.DWORD),
        ("TimeDateStamp", wintypes.DWORD),
        ("CheckSum", wintypes.DWORD),
        ("NumSyms", wintypes.DWORD),
        ("SymType", wintypes.DWORD),
        ("ModuleName", ctypes.c_wchar * 32),
        ("ImageName", ctypes.c_wchar * 256),
        ("LoadedPdbName", ctypes.c_wchar * 256),
        ("CVSig", wintypes.DWORD),
        ("CVData", ctypes.c_wchar * 780),
        ("PdbSig", wintypes.DWORD),
        ("PdbSig70", ctypes.c_byte * 16),
        ("PdbAge", wintypes.DWORD),
        ("PdbUnmatched", wintypes.BOOL),
        ("DbgUnmatched", wintypes.BOOL),
        ("LineNumbers", wintypes.BOOL),
        ("GlobalSymbols", wintypes.BOOL),
        ("TypeInfo", wintypes.BOOL),
        ("SourceIndexed", wintypes.BOOL),
        ("Publics", wintypes.BOOL),
        ("MachineType", wintypes.DWORD),
        ("Reserved", wintypes.DWORD),
    ]


SYM_TYPE_NAMES = {
    0: "SymNone", 1: "SymCoff", 2: "SymCv", 3: "SymPdb", 4: "SymExport",
    5: "SymDeferred", 6: "SymSym", 7: "SymDia", 8: "SymVirtual",
}


def ConfigurePrototypes(DbgHelp):
    DbgHelp.SymGetOptions.restype = wintypes.DWORD
    DbgHelp.SymGetOptions.argtypes = []

    DbgHelp.SymSetOptions.restype = wintypes.DWORD
    DbgHelp.SymSetOptions.argtypes = [wintypes.DWORD]

    DbgHelp.SymInitialize.restype = wintypes.BOOL
    DbgHelp.SymInitialize.argtypes = [ctypes.c_void_p, ctypes.c_char_p, wintypes.BOOL]

    DbgHelp.SymLoadModuleEx.restype = ctypes.c_uint64
    DbgHelp.SymLoadModuleEx.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p,
        ctypes.c_uint64, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD]

    DbgHelp.SymGetModuleInfo64.restype = wintypes.BOOL
    DbgHelp.SymGetModuleInfo64.argtypes = [
        ctypes.c_void_p, ctypes.c_uint64, ctypes.POINTER(IMAGEHLP_MODULE64)]

    DbgHelp.SymEnumSymbols.restype = wintypes.BOOL
    DbgHelp.SymEnumSymbols.argtypes = [
        ctypes.c_void_p, ctypes.c_uint64, ctypes.c_char_p, EnumProc, ctypes.c_uint64]

    DbgHelp.SymUnloadModule64.restype = wintypes.BOOL
    DbgHelp.SymUnloadModule64.argtypes = [ctypes.c_void_p, ctypes.c_uint64]

    DbgHelp.SymCleanup.restype = wintypes.BOOL
    DbgHelp.SymCleanup.argtypes = [ctypes.c_void_p]


def SanitizeWide(Value):
    Text = str(Value or "").split("\x00", 1)[0]
    return "".join(Character for Character in Text if 32 <= ord(Character) < 127)


def Extract(DllPath, SearchPath):
    DbgHelp = ctypes.WinDLL("dbghelp")
    ConfigurePrototypes(DbgHelp)
    Collected = []
    Diagnostics = {}

    Previous = DbgHelp.SymGetOptions()
    DbgHelp.SymSetOptions(
        Previous | SYMOPT_UNDNAMES | SYMOPT_LOAD_LINES |
        SYMOPT_AUTO_PUBLICS | SYMOPT_FAIL_CRITICAL_ERRORS)

    if not DbgHelp.SymInitialize(FAKE_PROCESS, SearchPath.encode("utf-8"), False):
        raise RuntimeError("SymInitialize failed")

    try:
        Base = DbgHelp.SymLoadModuleEx(
            FAKE_PROCESS, None, DllPath.encode("utf-8"), None,
            ctypes.c_uint64(IMAGE_BASE), 0, None, 0)
        if not Base:
            raise RuntimeError("SymLoadModuleEx failed for %s" % DllPath)

        Diagnostics["base"] = Base

        def Callback(SymbolPointer, SymbolSize, UserContext):
            Info = SymbolPointer.contents
            Raw = ctypes.string_at(ctypes.addressof(Info) + SYMBOL_INFO.Name.offset,
                                   Info.NameLen)
            Name = Raw.decode("utf-8", "replace")
            Rva = Info.Address - Base
            Collected.append((Rva, Name, int(Info.Size), int(Info.Tag)))
            return True

        Probe = EnumProc(Callback)
        if not DbgHelp.SymEnumSymbols(FAKE_PROCESS, ctypes.c_uint64(Base), b"*", Probe, 0):
            raise RuntimeError("SymEnumSymbols failed")

        ModuleInfo = IMAGEHLP_MODULE64()
        ModuleInfo.SizeOfStruct = ctypes.sizeof(IMAGEHLP_MODULE64)
        if DbgHelp.SymGetModuleInfo64(FAKE_PROCESS, ctypes.c_uint64(Base),
                                      ctypes.byref(ModuleInfo)):
            Diagnostics["sym_type"] = SYM_TYPE_NAMES.get(
                int(ModuleInfo.SymType), str(int(ModuleInfo.SymType)))
            Diagnostics["num_syms"] = int(ModuleInfo.NumSyms)
            Diagnostics["pdb"] = SanitizeWide(ModuleInfo.LoadedPdbName)
            Diagnostics["pdb_unmatched"] = bool(ModuleInfo.PdbUnmatched)
            Diagnostics["publics"] = bool(ModuleInfo.Publics)

        DbgHelp.SymUnloadModule64(FAKE_PROCESS, ctypes.c_uint64(Base))
    finally:
        DbgHelp.SymCleanup(FAKE_PROCESS)
        DbgHelp.SymSetOptions(Previous)

    return Collected, Diagnostics


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    if len(sys.argv) < 2:
        print("usage: extract_pdb_symbols.py <version-dir> [<version-dir> ...]")
        return 1

    for VersionDir in sys.argv[1:]:
        if not os.path.isdir(VersionDir):
            print("skip (not a directory): %s" % VersionDir)
            continue

        Dll = None
        Pdb = None
        for Entry in sorted(os.listdir(VersionDir)):
            Full = os.path.join(VersionDir, Entry)
            if Entry.lower().endswith(".dll") and Dll is None:
                Dll = Full
            if Entry.lower().endswith(".pdb") and Pdb is None:
                Pdb = Full

        if Dll is None or Pdb is None:
            print("skip (needs both a .dll and a .pdb): %s" % VersionDir)
            continue

        Label = os.path.basename(os.path.normpath(VersionDir))
        try:
            Symbols, Diagnostics = Extract(Dll, VersionDir)
        except Exception as Error:
            print("%s: FAILED %s" % (Label, Error))
            continue

        Functions = [S for S in Symbols if S[3] in (SYMTAG_FUNCTION, SYMTAG_PUBLIC)]
        Named = [S for S in Functions if S[1] and not S[1].startswith("?_")]

        TagHistogram = {}
        for Symbol in Symbols:
            TagHistogram[Symbol[3]] = TagHistogram.get(Symbol[3], 0) + 1

        OutPath = os.path.join(VersionDir, "ground_truth.tsv")
        with open(OutPath, "w", encoding="utf-8", newline="\n") as Handle:
            Handle.write("rva\tname\tsize\ttag\n")
            for Rva, Name, Size, Tag in sorted(Functions):
                Handle.write("%x\t%s\t%d\t%d\n" % (Rva, Name, Size, Tag))

        WithSize = sum(1 for S in Functions if S[2] > 0)
        print("%s" % Label)
        print("  dll              : %s" % os.path.basename(Dll))
        print("  pdb              : %s" % os.path.basename(Pdb))
        print("  symtype          : %s  pdb_unmatched=%s  publics=%s"
              % (Diagnostics.get("sym_type", "?"),
                 Diagnostics.get("pdb_unmatched", "?"),
                 Diagnostics.get("publics", "?")))
        print("  loaded pdb       : %s" % Diagnostics.get("pdb", "<none>"))
        print("  symbols total    : %d" % len(Symbols))
        print("  tag histogram    : %s"
              % ", ".join("%d:%d" % Item for Item in sorted(TagHistogram.items())))
        print("  functions/publics: %d" % len(Functions))
        print("  named            : %d" % len(Named))
        print("  with a size      : %d" % WithSize)
        print("  written          : %s" % OutPath)
        for Sample in sorted(Functions)[:6]:
            print("    %08x  %-40s size=%d tag=%d" % Sample)

    return 0


if __name__ == "__main__":
    sys.exit(main())
