#!/usr/bin/env python3
"""Every PDB function/public symbol per address of one build, cached as TSV.

A PDB can name one address several times: win32u's syscall stubs carry an exported `Nt*` name and a
`Zw*` alias, and identical-code folding puts several publics on one stub. A ground-truth scorer that
only knows the one name IDA picked would count a correct alias as wrong, so the scorer reads this
list and accepts any symbol at the address.

The dbghelp bindings come from tools/extract_pdb_symbols.py. That script enumerates with
SYMOPT_UNDNAMES; this one enumerates the stored (decorated) names and undecorates each one with
UnDecorateSymbolName(UNDNAME_NAME_ONLY), so both spellings are available: IDA keeps the decorated
name in functions.mangled_function and a demangled one in functions.name (08 §5.1 #0, #14).

Output TSV (UTF-8, LF, one header line), sorted by address then name:
    rva_hex  address  address_hex  tag  size  name  undecorated
`address` is the decimal image base + RVA, the spelling of functions.address; `address_hex` is
"%08x", the spelling of a .diaphora file. The image base is read from the PE header. A JSON sidecar
records the sha256 of the DLL and the PDB; a cached TSV is reused only while both still match.

Usage:
    pdb_aliases.py --bin-dir <dir with one .dll and one .pdb> --out <file.tsv> [--force]
    pdb_aliases.py --corpus <root> --build <name>-<version> [--force]    e.g. --build win32u-9444
    pdb_aliases.py --corpus <root> --all [--force]
With --corpus the build's files are <corpus>/oracle/bin/<name>_10026100<version>/ and the cache is
<corpus>/oracle/ground_truth/aliases/<name>-<version>.tsv. --corpus defaults to DSIG_CORPUS_ROOT.
Windows only (dbghelp).
"""

import argparse
import ctypes
import hashlib
import json
import os
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))  # tools/, for extract_pdb_symbols

COLUMNS = ["rva_hex", "address", "address_hex", "tag", "size", "name", "undecorated"]
UNDNAME_NAME_ONLY = 0x1000
SYMTAG_FUNCTION = 5
SYMTAG_PUBLIC = 10
GENERATOR = "tools/e2e/pdb_aliases.py"


def Sha256OfFile(Path):
    Digest = hashlib.sha256()
    with open(Path, "rb") as Handle:
        for Block in iter(lambda: Handle.read(1 << 20), b""):
            Digest.update(Block)
    return Digest.hexdigest()


def PeImageBase(DllPath):
    """ImageBase from the PE optional header (PE32 or PE32+)."""
    with open(DllPath, "rb") as Handle:
        Data = Handle.read(4096)
    if Data[:2] != b"MZ":
        raise ValueError("%s: not a PE file" % DllPath)
    Offset = struct.unpack_from("<I", Data, 0x3C)[0]
    if Data[Offset:Offset + 4] != b"PE\0\0":
        raise ValueError("%s: no PE signature" % DllPath)
    Optional = Offset + 24
    Magic = struct.unpack_from("<H", Data, Optional)[0]
    if Magic == 0x20B:
        return struct.unpack_from("<Q", Data, Optional + 24)[0]
    if Magic == 0x10B:
        return struct.unpack_from("<I", Data, Optional + 28)[0]
    raise ValueError("%s: unknown optional header magic 0x%x" % (DllPath, Magic))


def Enumerate(DllPath, SearchPath, ImageBase):
    """[(rva, decorated, undecorated, size, tag)] for SymTagFunction / SymTagPublic symbols."""
    import extract_pdb_symbols as Eps  # dbghelp bindings (tools/extract_pdb_symbols.py)
    from ctypes import wintypes

    DbgHelp = ctypes.WinDLL("dbghelp")
    Eps.ConfigurePrototypes(DbgHelp)
    DbgHelp.UnDecorateSymbolName.restype = wintypes.DWORD
    DbgHelp.UnDecorateSymbolName.argtypes = [ctypes.c_char_p, ctypes.c_char_p, wintypes.DWORD, wintypes.DWORD]

    Collected = []
    Previous = DbgHelp.SymGetOptions()
    # No SYMOPT_UNDNAMES: keep the names as the PDB stores them.
    DbgHelp.SymSetOptions((Previous & ~Eps.SYMOPT_UNDNAMES) | Eps.SYMOPT_AUTO_PUBLICS
                          | Eps.SYMOPT_FAIL_CRITICAL_ERRORS)
    if not DbgHelp.SymInitialize(Eps.FAKE_PROCESS, SearchPath.encode("utf-8"), False):
        DbgHelp.SymSetOptions(Previous)
        raise RuntimeError("SymInitialize failed")
    try:
        Base = DbgHelp.SymLoadModuleEx(Eps.FAKE_PROCESS, None, DllPath.encode("utf-8"), None,
                                       ctypes.c_uint64(ImageBase), 0, None, 0)
        if not Base:
            raise RuntimeError("SymLoadModuleEx failed for %s" % DllPath)
        Info = Eps.IMAGEHLP_MODULE64()
        Info.SizeOfStruct = ctypes.sizeof(Eps.IMAGEHLP_MODULE64)
        if DbgHelp.SymGetModuleInfo64(Eps.FAKE_PROCESS, ctypes.c_uint64(Base), ctypes.byref(Info)):
            SymType = Eps.SYM_TYPE_NAMES.get(int(Info.SymType), str(int(Info.SymType)))
            if SymType != "SymPdb" or bool(Info.PdbUnmatched):
                raise RuntimeError("%s: dbghelp loaded %s (pdb_unmatched=%s), not the matching PDB"
                                   % (DllPath, SymType, bool(Info.PdbUnmatched)))

        def Callback(SymbolPointer, SymbolSize, UserContext):
            Symbol = SymbolPointer.contents
            Raw = ctypes.string_at(ctypes.addressof(Symbol) + Eps.SYMBOL_INFO.Name.offset, Symbol.NameLen)
            Tag = int(Symbol.Tag)
            if Tag in (SYMTAG_FUNCTION, SYMTAG_PUBLIC):
                Collected.append((int(Symbol.Address - Base), Raw, int(Symbol.Size), Tag))
            return True

        Probe = Eps.EnumProc(Callback)
        if not DbgHelp.SymEnumSymbols(Eps.FAKE_PROCESS, ctypes.c_uint64(Base), b"*", Probe, 0):
            raise RuntimeError("SymEnumSymbols failed")
        DbgHelp.SymUnloadModule64(Eps.FAKE_PROCESS, ctypes.c_uint64(Base))

        Result = []
        Buffer = ctypes.create_string_buffer(4096)
        for Rva, Raw, Size, Tag in Collected:
            Name = Raw.decode("utf-8", "replace")
            Undecorated = Name
            if Raw.startswith(b"?"):
                Length = DbgHelp.UnDecorateSymbolName(Raw, Buffer, len(Buffer), UNDNAME_NAME_ONLY)
                if Length:
                    Undecorated = Buffer.value.decode("utf-8", "replace")
            Result.append((Rva, Name, Undecorated, Size, Tag))
        return Result
    finally:
        DbgHelp.SymCleanup(Eps.FAKE_PROCESS)
        DbgHelp.SymSetOptions(Previous)


def FindBuildFiles(BinDir):
    Dll = Pdb = None
    for Entry in sorted(os.listdir(BinDir)):
        Full = os.path.join(BinDir, Entry)
        if Entry.lower().endswith(".dll") and Dll is None:
            Dll = Full
        if Entry.lower().endswith(".pdb") and Pdb is None:
            Pdb = Full
    if Dll is None or Pdb is None:
        raise FileNotFoundError("%s: needs one .dll and one .pdb" % BinDir)
    return Dll, Pdb


def CachedIsValid(OutPath, Dll, Pdb):
    Sidecar = OutPath[:-4] + ".json" if OutPath.endswith(".tsv") else OutPath + ".json"
    if not (os.path.isfile(OutPath) and os.path.isfile(Sidecar)):
        return False
    try:
        with open(Sidecar, "r", encoding="utf-8") as Handle:
            Info = json.load(Handle)
    except (OSError, ValueError):
        return False
    return (Info.get("dll_sha256") == Sha256OfFile(Dll) and Info.get("pdb_sha256") == Sha256OfFile(Pdb)
            and Info.get("tsv_sha256") == Sha256OfFile(OutPath))


def BuildAliases(BinDir, OutPath, Force=False, Log=print):
    """Writes (or reuses) the alias TSV for the build in BinDir. Returns OutPath."""
    Dll, Pdb = FindBuildFiles(BinDir)
    if not Force and CachedIsValid(OutPath, Dll, Pdb):
        Log("aliases: cached %s" % OutPath)
        return OutPath
    ImageBase = PeImageBase(Dll)
    Symbols = Enumerate(Dll, BinDir, ImageBase)
    Rows = sorted((ImageBase + Rva, Name, Undecorated, Size, Tag) for Rva, Name, Undecorated, Size, Tag in Symbols)
    os.makedirs(os.path.dirname(os.path.abspath(OutPath)), exist_ok=True)
    Temporary = OutPath + ".tmp"
    with open(Temporary, "w", encoding="utf-8", newline="\n") as Handle:
        Handle.write("\t".join(COLUMNS) + "\n")
        for Address, Name, Undecorated, Size, Tag in Rows:
            Handle.write("%x\t%d\t%08x\t%d\t%d\t%s\t%s\n" % (Address - ImageBase, Address, Address, Tag, Size,
                                                            Name.replace("\t", " "), Undecorated.replace("\t", " ")))
    os.replace(Temporary, OutPath)
    Addresses = {Row[0] for Row in Rows}
    PerAddress = {}
    for Row in Rows:
        PerAddress[Row[0]] = PerAddress.get(Row[0], 0) + 1
    Info = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "generator": GENERATOR,
        "dll": Dll,
        "dll_sha256": Sha256OfFile(Dll),
        "pdb": Pdb,
        "pdb_sha256": Sha256OfFile(Pdb),
        "image_base": "0x%x" % ImageBase,
        "symbols": len(Rows),
        "addresses": len(Addresses),
        "addresses_with_several_names": sum(1 for Count in PerAddress.values() if Count > 1),
        "tsv": OutPath,
        "tsv_sha256": Sha256OfFile(OutPath),
    }
    Sidecar = OutPath[:-4] + ".json" if OutPath.endswith(".tsv") else OutPath + ".json"
    with open(Sidecar, "w", encoding="utf-8", newline="\n") as Handle:
        json.dump(Info, Handle, indent=2)
        Handle.write("\n")
    Log("aliases: wrote %s (%d symbols at %d addresses, %d with several names)"
        % (OutPath, Info["symbols"], Info["addresses"], Info["addresses_with_several_names"]))
    return OutPath


def LoadAliases(Path):
    """{int address: set of names (decorated and undecorated)} from an alias TSV."""
    Aliases = {}
    with open(Path, "r", encoding="utf-8") as Handle:
        Header = Handle.readline().rstrip("\n").split("\t")
        if Header != COLUMNS:
            raise ValueError("%s: unexpected header %r" % (Path, Header))
        for Line in Handle:
            Parts = Line.rstrip("\n").split("\t")
            if len(Parts) != len(COLUMNS):
                continue
            Names = Aliases.setdefault(int(Parts[1]), set())
            for Name in (Parts[5], Parts[6]):
                if Name:
                    Names.add(Name)
    return Aliases


def BuildBinDir(Corpus, Build):
    """<corpus>/oracle/bin/<name>_10026100<version> for a build id such as 'win32u-9444'."""
    Name, _, Version = Build.rpartition("-")
    if not Name or not Version.isdigit():
        raise ValueError("build id %r is not <name>-<version>" % Build)
    return os.path.join(Corpus, "oracle", "bin", "%s_10026100%s" % (Name, Version))


def CachePath(Corpus, Build):
    return os.path.join(Corpus, "oracle", "ground_truth", "aliases", Build + ".tsv")


def EnsureAliases(Corpus, Build, Force=False, Log=print):
    """Alias TSV path for a corpus build, building the cache when needed; None when the build has no PDB."""
    BinDir = BuildBinDir(Corpus, Build)
    if not os.path.isdir(BinDir):
        return None
    try:
        FindBuildFiles(BinDir)
    except FileNotFoundError:
        return None
    return BuildAliases(BinDir, CachePath(Corpus, Build), Force=Force, Log=Log)


def AllBuilds(Corpus):
    Builds = []
    BinRoot = os.path.join(Corpus, "oracle", "bin")
    for Entry in sorted(os.listdir(BinRoot)):
        Name, _, Label = Entry.partition("_")
        if Label.startswith("10026100") and os.path.isdir(os.path.join(BinRoot, Entry)):
            Builds.append("%s-%s" % (Name, Label[len("10026100"):]))
    return Builds


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    Parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    Parser.add_argument("--bin-dir")
    Parser.add_argument("--out")
    Parser.add_argument("--corpus", default=os.environ.get("DSIG_CORPUS_ROOT"))
    Parser.add_argument("--build", action="append", default=[])
    Parser.add_argument("--all", action="store_true")
    Parser.add_argument("--force", action="store_true")
    Args = Parser.parse_args()
    if Args.bin_dir:
        if not Args.out:
            Parser.error("--bin-dir needs --out")
        BuildAliases(Args.bin_dir, Args.out, Force=Args.force)
        return 0
    if not Args.corpus:
        Parser.error("give --bin-dir/--out, or --corpus (or DSIG_CORPUS_ROOT) with --build or --all")
    Builds = AllBuilds(Args.corpus) if Args.all else Args.build
    if not Builds:
        Parser.error("nothing to do: give --build <name>-<version> or --all")
    for Build in Builds:
        if EnsureAliases(Args.corpus, Build, Force=Args.force) is None:
            print("aliases: %s has no .dll + .pdb under %s" % (Build, BuildBinDir(Args.corpus, Build)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
