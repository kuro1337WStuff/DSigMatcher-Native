#include "dsigmatcher/PeImage.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>

namespace DSig {

namespace {

constexpr uint64_t DosHeaderMinimumSize = 64;
constexpr uint64_t DosHeaderLfanewOffset = 0x3c;
constexpr uint64_t NtSignatureSize = 4;
constexpr uint64_t CoffHeaderSize = 20;
constexpr uint64_t SectionHeaderSize = 40;
constexpr uint64_t ExportDirectoryHeaderSize = 40;
constexpr uint64_t DebugDirectoryEntrySize = 28;
constexpr uint64_t CodeViewHeaderSize = 24;
constexpr uint64_t DataDirectoryEntrySize = 8;
constexpr uint64_t OptionalHeaderPe32Size = 96;
constexpr uint64_t OptionalHeaderPe32PlusSize = 112;
constexpr uint64_t DataDirectoryPe32Offset = 96;
constexpr uint64_t DataDirectoryPe32PlusOffset = 112;
constexpr uint32_t DosMagic = 0x5a4d;
constexpr uint32_t NtSignature = 0x00004550;
constexpr uint32_t MaximumExportEntries = 4000000;
constexpr uint32_t MaximumDebugEntries = 4096;
constexpr uint32_t MaximumCodeViewPathLength = 4096;
constexpr const char* SymbolServerRoot = "https://msdl.microsoft.com/download/symbols";
constexpr const char HexDigits[] = "0123456789ABCDEF";

struct ByteReader {
  const uint8_t* Data = nullptr;
  uint64_t Size = 0;

  bool Range(uint64_t Offset, uint64_t Length, const uint8_t*& OutBytes) const {
    if (Offset > Size) {
      return false;
    }
    if (Length > Size - Offset) {
      return false;
    }
    OutBytes = Data + Offset;
    return true;
  }

  bool Fits(uint64_t Offset, uint64_t Length) const {
    const uint8_t* Unused = nullptr;
    return Range(Offset, Length, Unused);
  }

  bool U8(uint64_t Offset, uint8_t& Out) const {
    const uint8_t* Raw = nullptr;
    if (!Range(Offset, 1, Raw)) {
      return false;
    }
    Out = Raw[0];
    return true;
  }

  bool U16(uint64_t Offset, uint16_t& Out) const {
    const uint8_t* Raw = nullptr;
    if (!Range(Offset, 2, Raw)) {
      return false;
    }
    Out = static_cast<uint16_t>(static_cast<uint16_t>(Raw[0]) |
                                static_cast<uint16_t>(static_cast<uint16_t>(Raw[1]) << 8));
    return true;
  }

  bool U32(uint64_t Offset, uint32_t& Out) const {
    const uint8_t* Raw = nullptr;
    if (!Range(Offset, 4, Raw)) {
      return false;
    }
    Out = static_cast<uint32_t>(Raw[0]) | (static_cast<uint32_t>(Raw[1]) << 8) |
          (static_cast<uint32_t>(Raw[2]) << 16) | (static_cast<uint32_t>(Raw[3]) << 24);
    return true;
  }

  bool U64(uint64_t Offset, uint64_t& Out) const {
    const uint8_t* Raw = nullptr;
    if (!Range(Offset, 8, Raw)) {
      return false;
    }
    uint64_t Value = 0;
    for (uint64_t Index = 0; Index < 8u; ++Index) {
      Value |= static_cast<uint64_t>(Raw[Index]) << (Index * 8u);
    }
    Out = Value;
    return true;
  }

  bool Bytes(uint64_t Offset, uint64_t Length, uint8_t* Out) const {
    const uint8_t* Raw = nullptr;
    if (!Range(Offset, Length, Raw)) {
      return false;
    }
    std::memcpy(Out, Raw, static_cast<size_t>(Length));
    return true;
  }

  bool CString(uint64_t Offset, std::string_view& Out) const {
    const uint8_t* Raw = nullptr;
    if (!Range(Offset, 1, Raw)) {
      return false;
    }
    const uint64_t Limit = Size - Offset;
    for (uint64_t Index = 0; Index < Limit; ++Index) {
      if (Raw[Index] == 0) {
        Out = std::string_view(reinterpret_cast<const char*>(Raw), static_cast<size_t>(Index));
        return true;
      }
    }
    return false;
  }
};

void AppendUpperHex(std::string& Target, uint8_t Value) {
  Target += HexDigits[(Value >> 4) & 0x0f];
  Target += HexDigits[Value & 0x0f];
}

std::string BaseNameOfSymbolPath(std::string_view Path) {
  size_t Start = 0;
  for (size_t Index = 0; Index < Path.size(); ++Index) {
    if (Path[Index] == '\\' || Path[Index] == '/') {
      Start = Index + 1;
    }
  }
  return std::string(Path.substr(Start));
}

bool MapRvaRange(const PeImage& Image, uint32_t Rva, uint64_t Length, uint64_t& OutOffset) {
  uint32_t Offset = 0;
  if (!Image.RvaToOffset(Rva, Offset)) {
    return false;
  }
  const uint64_t Start = Offset;
  if (Length > Image.BufferSize()) {
    return false;
  }
  if (Start > Image.BufferSize() - Length) {
    return false;
  }
  OutOffset = Start;
  return true;
}

bool ReadMappedString(const PeImage& Image, const ByteReader& Reader, uint32_t Rva,
                      std::string_view& Out) {
  uint64_t Offset = 0;
  if (!MapRvaRange(Image, Rva, 1, Offset)) {
    return false;
  }
  return Reader.CString(Offset, Out);
}

bool ParseSectionTable(PeImage& Image, const ByteReader& Reader, uint64_t SectionTableOffset,
                       std::string& OutError) {
  const uint64_t RequiredBytes = static_cast<uint64_t>(Image.Headers.NumberOfSections) * SectionHeaderSize;
  if (!Reader.Fits(SectionTableOffset, RequiredBytes)) {
    OutError = "section table extends past the end of the file";
    return false;
  }

  Image.Sections.reserve(Image.Headers.NumberOfSections);
  for (uint16_t Index = 0; Index < Image.Headers.NumberOfSections; ++Index) {
    const uint64_t Base = SectionTableOffset + static_cast<uint64_t>(Index) * SectionHeaderSize;

    PeSection Entry;
    const uint8_t* NameBytes = nullptr;
    if (!Reader.Range(Base, PeSectionNameLength, NameBytes)) {
      OutError = "section header is truncated";
      return false;
    }
    size_t NameLength = 0;
    while (NameLength < PeSectionNameLength && NameBytes[NameLength] != 0) {
      ++NameLength;
    }
    Entry.Name = std::string_view(reinterpret_cast<const char*>(NameBytes), NameLength);

    Reader.U32(Base + 8, Entry.VirtualSize);
    Reader.U32(Base + 12, Entry.VirtualAddress);
    Reader.U32(Base + 16, Entry.SizeOfRawData);
    Reader.U32(Base + 20, Entry.PointerToRawData);
    Reader.U32(Base + 24, Entry.PointerToRelocations);
    Reader.U32(Base + 28, Entry.PointerToLinenumbers);
    Reader.U16(Base + 32, Entry.NumberOfRelocations);
    Reader.U16(Base + 34, Entry.NumberOfLinenumbers);
    Reader.U32(Base + 36, Entry.Characteristics);

    if (Entry.SizeOfRawData != 0 && !Reader.Fits(Entry.PointerToRawData, Entry.SizeOfRawData)) {
      OutError = "section '" + std::string(Entry.Name) +
                 "' claims raw data past the end of the file";
      return false;
    }

    Image.Sections.push_back(Entry);
  }

  return true;
}

bool ParseExportDirectory(PeImage& Image, const ByteReader& Reader, std::string& OutError) {
  const PeDataDirectory* Directory = Image.Headers.Directory(PeDirectoryEntryExport);
  if (Directory == nullptr || (Directory->Rva == 0 && Directory->Size == 0)) {
    return true;
  }
  if (Directory->Rva == 0 || Directory->Size == 0) {
    OutError = "export directory has a zero RVA or a zero size";
    return false;
  }

  uint64_t HeaderOffset = 0;
  if (!MapRvaRange(Image, Directory->Rva, ExportDirectoryHeaderSize, HeaderOffset)) {
    OutError = "export directory does not map into the file";
    return false;
  }

  uint32_t NameRva = 0;
  uint32_t OrdinalBase = 0;
  uint32_t NumberOfFunctions = 0;
  uint32_t NumberOfNames = 0;
  uint32_t FunctionsRva = 0;
  uint32_t NamesRva = 0;
  uint32_t OrdinalsRva = 0;
  Reader.U32(HeaderOffset + 12, NameRva);
  Reader.U32(HeaderOffset + 16, OrdinalBase);
  Reader.U32(HeaderOffset + 20, NumberOfFunctions);
  Reader.U32(HeaderOffset + 24, NumberOfNames);
  Reader.U32(HeaderOffset + 28, FunctionsRva);
  Reader.U32(HeaderOffset + 32, NamesRva);
  Reader.U32(HeaderOffset + 36, OrdinalsRva);

  if (NumberOfFunctions > MaximumExportEntries || NumberOfNames > MaximumExportEntries) {
    OutError = "export directory claims an implausible number of entries";
    return false;
  }

  Image.ExportDirectory.Rva = Directory->Rva;
  Image.ExportDirectory.Size = Directory->Size;
  Image.ExportDirectory.RvaEnd =
      static_cast<uint64_t>(Directory->Rva) +
      (Directory->Size >= ExportDirectoryHeaderSize
           ? static_cast<uint64_t>(Directory->Size)
           : ExportDirectoryHeaderSize);
  Image.ExportDirectory.OrdinalBase = OrdinalBase;
  Image.ExportDirectory.NumberOfFunctions = NumberOfFunctions;
  Image.ExportDirectory.NumberOfNames = NumberOfNames;

  if (NameRva != 0) {
    if (!ReadMappedString(Image, Reader, NameRva, Image.ExportDirectory.DllName)) {
      OutError = "export directory DLL name is not readable";
      return false;
    }
  }

  if (NumberOfFunctions == 0 && NumberOfNames == 0) {
    Image.ExportDirectory.Present = true;
    return true;
  }
  if (FunctionsRva == 0 || NamesRva == 0 || OrdinalsRva == 0) {
    OutError = "export directory declares entries but has a null array RVA";
    return false;
  }

  uint64_t FunctionsOffset = 0;
  if (!MapRvaRange(Image, FunctionsRva, static_cast<uint64_t>(NumberOfFunctions) * 4, FunctionsOffset)) {
    OutError = "export address table does not map into the file";
    return false;
  }

  uint64_t NamesOffset = 0;
  if (!MapRvaRange(Image, NamesRva, static_cast<uint64_t>(NumberOfNames) * 4, NamesOffset)) {
    OutError = "export name pointer table does not map into the file";
    return false;
  }

  uint64_t OrdinalsOffset = 0;
  if (!MapRvaRange(Image, OrdinalsRva, static_cast<uint64_t>(NumberOfNames) * 2, OrdinalsOffset)) {
    OutError = "export ordinal table does not map into the file";
    return false;
  }

  std::vector<uint8_t> Referenced(static_cast<size_t>(NumberOfFunctions), 0);
  Image.Exports.reserve(static_cast<size_t>(NumberOfFunctions));

  for (uint32_t Index = 0; Index < NumberOfNames; ++Index) {
    uint32_t EntryNameRva = 0;
    uint16_t AddressIndex = 0;
    if (!Reader.U32(NamesOffset + static_cast<uint64_t>(Index) * 4, EntryNameRva)) {
      OutError = "export name pointer table is truncated";
      return false;
    }
    if (!Reader.U16(OrdinalsOffset + static_cast<uint64_t>(Index) * 2, AddressIndex)) {
      OutError = "export ordinal table is truncated";
      return false;
    }
    if (AddressIndex >= NumberOfFunctions) {
      OutError = "export ordinal is outside the export address table";
      return false;
    }

    uint32_t FunctionRva = 0;
    if (!Reader.U32(FunctionsOffset + static_cast<uint64_t>(AddressIndex) * 4, FunctionRva)) {
      OutError = "export address table is truncated";
      return false;
    }
    Referenced[AddressIndex] = 1;

    PeExport Entry;
    Entry.AddressIndex = AddressIndex;
    Entry.Ordinal = OrdinalBase + AddressIndex;
    Entry.Rva = FunctionRva;
    Entry.IsNamed = true;

    if (EntryNameRva != 0) {
      if (!ReadMappedString(Image, Reader, EntryNameRva, Entry.Name)) {
        OutError = "export name is not readable";
        return false;
      }
    } else {
      Entry.IsNamed = false;
    }

    if (Image.IsInsideExportDirectory(FunctionRva)) {
      if (!ReadMappedString(Image, Reader, FunctionRva, Entry.ForwarderName)) {
        OutError = "forwarded export string is not readable";
        return false;
      }
      Entry.IsForwarder = true;
    }

    Image.Exports.push_back(Entry);
  }

  for (uint32_t Index = 0; Index < NumberOfFunctions; ++Index) {
    if (Referenced[Index] != 0) {
      continue;
    }
    uint32_t FunctionRva = 0;
    if (!Reader.U32(FunctionsOffset + static_cast<uint64_t>(Index) * 4, FunctionRva)) {
      OutError = "export address table is truncated";
      return false;
    }
    if (FunctionRva == 0) {
      continue;
    }

    PeExport Entry;
    Entry.AddressIndex = Index;
    Entry.Ordinal = OrdinalBase + Index;
    Entry.Rva = FunctionRva;
    Entry.IsNamed = false;

    if (Image.IsInsideExportDirectory(FunctionRva)) {
      if (!ReadMappedString(Image, Reader, FunctionRva, Entry.ForwarderName)) {
        OutError = "forwarded export string is not readable";
        return false;
      }
      Entry.IsForwarder = true;
    }

    Image.Exports.push_back(Entry);
  }

  std::sort(Image.Exports.begin(), Image.Exports.end(),
            [](const PeExport& Left, const PeExport& Right) {
              if (Left.Ordinal != Right.Ordinal) {
                return Left.Ordinal < Right.Ordinal;
              }
              return Left.AddressIndex < Right.AddressIndex;
            });

  std::vector<uint32_t> Addresses;
  Addresses.reserve(Image.Exports.size());
  for (const PeExport& Entry : Image.Exports) {
    if (Entry.IsForwarder) {
      ++Image.ExportDirectory.ForwarderCount;
      continue;
    }
    if (Entry.IsNamed) {
      ++Image.ExportDirectory.NamedExportCount;
    } else {
      ++Image.ExportDirectory.UnnamedExportCount;
    }
    Addresses.push_back(Entry.Rva);
  }
  std::sort(Addresses.begin(), Addresses.end());
  Image.ExportDirectory.DistinctAddressCount =
      static_cast<uint32_t>(std::unique(Addresses.begin(), Addresses.end()) - Addresses.begin());

  Image.ExportDirectory.Present = true;
  return true;
}

bool ParseDebugDirectory(PeImage& Image, const ByteReader& Reader, std::string& OutError) {
  const PeDataDirectory* Directory = Image.Headers.Directory(PeDirectoryEntryDebug);
  if (Directory == nullptr || (Directory->Rva == 0 && Directory->Size == 0)) {
    Image.CodeView.Error = "image has no debug directory";
    return true;
  }
  if (Directory->Rva == 0 || Directory->Size == 0) {
    OutError = "debug directory has a zero RVA or a zero size";
    return false;
  }

  const uint32_t EntryCount = static_cast<uint32_t>(
      static_cast<uint64_t>(Directory->Size) / DebugDirectoryEntrySize);
  if (EntryCount == 0) {
    Image.CodeView.Error = "debug directory is smaller than one entry";
    return true;
  }
  if (EntryCount > MaximumDebugEntries) {
    OutError = "debug directory claims an implausible number of entries";
    return false;
  }

  uint64_t BaseOffset = 0;
  if (!MapRvaRange(Image, Directory->Rva,
                   static_cast<uint64_t>(EntryCount) * DebugDirectoryEntrySize, BaseOffset)) {
    OutError = "debug directory does not map into the file";
    return false;
  }

  Image.DebugEntries.reserve(EntryCount);
  for (uint32_t Index = 0; Index < EntryCount; ++Index) {
    const uint64_t Base = BaseOffset + static_cast<uint64_t>(Index) * DebugDirectoryEntrySize;
    PeDebugEntry Entry;
    Reader.U32(Base + 0, Entry.Characteristics);
    Reader.U32(Base + 4, Entry.TimeDateStamp);
    Reader.U16(Base + 8, Entry.MajorVersion);
    Reader.U16(Base + 10, Entry.MinorVersion);
    Reader.U32(Base + 12, Entry.Type);
    Reader.U32(Base + 16, Entry.SizeOfData);
    Reader.U32(Base + 20, Entry.AddressOfRawData);
    Reader.U32(Base + 24, Entry.PointerToRawData);
    Image.DebugEntries.push_back(Entry);
  }

  return true;
}

void ParseCodeViewRecord(PeImage& Image, const ByteReader& Reader) {
  for (const PeDebugEntry& Entry : Image.DebugEntries) {
    if (Entry.Type != PeDebugTypeCodeView) {
      continue;
    }
    if (Entry.SizeOfData < CodeViewHeaderSize) {
      Image.CodeView.Error = "CodeView debug entry is too small to hold an RSDS record";
      continue;
    }
    if (Entry.SizeOfData > MaximumCodeViewPathLength * 4) {
      Image.CodeView.Error = "CodeView debug entry is implausibly large";
      continue;
    }

    uint64_t BlobOffset = 0;
    bool Mapped = false;
    const uint64_t RawStart = Entry.PointerToRawData;
    const uint64_t RawLength = Entry.SizeOfData;
    if (RawStart != 0 && RawLength <= Reader.Size && RawStart <= Reader.Size - RawLength) {
      BlobOffset = RawStart;
      Mapped = true;
    } else if (MapRvaRange(Image, Entry.AddressOfRawData, RawLength, BlobOffset)) {
      Mapped = true;
    }
    if (!Mapped) {
      Image.CodeView.Error = "CodeView blob is not reachable from the file";
      continue;
    }

    const uint8_t* Blob = nullptr;
    if (!Reader.Range(BlobOffset, RawLength, Blob)) {
      Image.CodeView.Error = "CodeView blob is not reachable from the file";
      continue;
    }
    if (Blob[0] != 'R' || Blob[1] != 'S' || Blob[2] != 'D' || Blob[3] != 'S') {
      Image.CodeView.Error = "CodeView record is not an RSDS record";
      continue;
    }

    Image.CodeView.Signature = std::string_view(reinterpret_cast<const char*>(Blob), 4);
    Reader.U32(BlobOffset + 4, Image.CodeView.Data1);
    Reader.U16(BlobOffset + 8, Image.CodeView.Data2);
    Reader.U16(BlobOffset + 10, Image.CodeView.Data3);
    if (!Reader.Bytes(BlobOffset + 12, 8, Image.CodeView.Data4)) {
      Image.CodeView.Error = "CodeView record is truncated inside the GUID";
      Image.CodeView.Signature = std::string_view();
      continue;
    }
    Reader.U32(BlobOffset + 20, Image.CodeView.Age);

    std::string_view Path;
    if (Reader.CString(BlobOffset + CodeViewHeaderSize, Path)) {
      Image.CodeView.PdbPath = Path;
    } else {
      Image.CodeView.PdbPath = std::string_view(
          reinterpret_cast<const char*>(Blob) + CodeViewHeaderSize,
          static_cast<size_t>(RawLength - CodeViewHeaderSize));
    }
    Image.CodeView.PdbName = BaseNameOfSymbolPath(Image.CodeView.PdbPath);

    char GuidHead[32];
    std::snprintf(GuidHead, sizeof(GuidHead), "%08X%04X%04X",
                  static_cast<unsigned>(Image.CodeView.Data1),
                  static_cast<unsigned>(Image.CodeView.Data2),
                  static_cast<unsigned>(Image.CodeView.Data3));
    Image.CodeView.Guid = GuidHead;
    for (uint64_t Index = 0; Index < 8u; ++Index) {
      AppendUpperHex(Image.CodeView.Guid, Image.CodeView.Data4[Index]);
    }

    char AgeText[16];
    std::snprintf(AgeText, sizeof(AgeText), "%X", static_cast<unsigned>(Image.CodeView.Age));
    Image.CodeView.SymbolKey = Image.CodeView.Guid + AgeText;

    Image.CodeView.SymbolUrl = std::string(SymbolServerRoot) + "/" + Image.CodeView.PdbName + "/" +
                               Image.CodeView.SymbolKey + "/" + Image.CodeView.PdbName;
    Image.CodeView.Present = true;
    Image.CodeView.Error.clear();
    return;
  }

  if (!Image.CodeView.Present && Image.CodeView.Error.empty()) {
    Image.CodeView.Error = "image has no CodeView debug entry";
  }
}

}

void PeImage::Reset() {
  Buffer_.clear();
  Headers = PeHeaders();
  Sections.clear();
  ExportDirectory = PeExportDirectoryInfo();
  Exports.clear();
  DebugEntries.clear();
  CodeView = PeCodeViewRecord();
}

const PeSection* PeImage::SectionContainingRva(uint32_t Rva) const {
  for (const PeSection& Entry : Sections) {
    if (Entry.HoldsRva(Rva)) {
      return &Entry;
    }
  }
  return nullptr;
}

const PeSection* PeImage::SectionContainingOffset(uint32_t Offset) const {
  for (const PeSection& Entry : Sections) {
    if (Entry.HoldsOffset(Offset)) {
      return &Entry;
    }
  }
  return nullptr;
}

bool PeImage::RvaToOffset(uint32_t Rva, uint32_t& OutOffset) const {
  const PeSection* Owner = SectionContainingRva(Rva);
  if (Owner != nullptr) {
    const uint64_t Delta = static_cast<uint64_t>(Rva) - Owner->VirtualAddress;
    if (Delta > Owner->SizeOfRawData) {
      return false;
    }
    const uint64_t Offset = static_cast<uint64_t>(Owner->PointerToRawData) + Delta;
    if (Offset >= Buffer_.size()) {
      return false;
    }
    OutOffset = static_cast<uint32_t>(Offset);
    return true;
  }

  const uint64_t HeaderLimit = Sections.empty()
                                   ? static_cast<uint64_t>(Headers.SizeOfHeaders)
                                   : static_cast<uint64_t>(Sections.front().VirtualAddress);
  if (Rva < HeaderLimit && static_cast<uint64_t>(Rva) < Buffer_.size()) {
    OutOffset = Rva;
    return true;
  }
  return false;
}

bool PeImage::OffsetToRva(uint32_t Offset, uint32_t& OutRva) const {
  const PeSection* Owner = SectionContainingOffset(Offset);
  if (Owner != nullptr) {
    const uint64_t Rva = static_cast<uint64_t>(Owner->VirtualAddress) +
                         (static_cast<uint64_t>(Offset) - Owner->PointerToRawData);
    if (Rva > 0xffffffffu) {
      return false;
    }
    OutRva = static_cast<uint32_t>(Rva);
    return true;
  }

  const uint64_t HeaderLimit = Sections.empty()
                                   ? static_cast<uint64_t>(Headers.SizeOfHeaders)
                                   : static_cast<uint64_t>(Sections.front().PointerToRawData);
  if (Offset < HeaderLimit && static_cast<uint64_t>(Offset) < Buffer_.size()) {
    OutRva = Offset;
    return true;
  }
  return false;
}

bool PeImage::RvaRangeToOffset(uint32_t Rva, uint64_t Length, uint32_t& OutOffset) const {
  uint64_t Resolved = 0;
  if (!MapRvaRange(*this, Rva, Length, Resolved)) {
    return false;
  }
  OutOffset = static_cast<uint32_t>(Resolved);
  return true;
}

const PeExport* PeImage::FindExportByName(std::string_view Name) const {
  if (Name.empty()) {
    return nullptr;
  }
  for (const PeExport& Entry : Exports) {
    if (Entry.IsNamed && Entry.Name == Name) {
      return &Entry;
    }
  }
  return nullptr;
}

bool PeImage::IsInsideExportDirectory(uint32_t Rva) const {
  if (ExportDirectory.Rva == 0 || ExportDirectory.RvaEnd == 0) {
    return false;
  }
  const uint64_t Value = Rva;
  return Value >= ExportDirectory.Rva && Value < ExportDirectory.RvaEnd;
}

PeLoadResult PeImage::Parse(std::vector<uint8_t> Buffer) {
  PeLoadResult Result;
  Reset();
  Buffer_ = std::move(Buffer);

  const ByteReader Reader{Buffer_.data(), static_cast<uint64_t>(Buffer_.size())};

  if (Reader.Size < 2u) {
    Result.Error = "file is smaller than a DOS header";
    return Result;
  }

  uint16_t DosMagicValue = 0;
  if (!Reader.U16(0, DosMagicValue) || DosMagicValue != DosMagic) {
    Result.Error = "missing MZ signature; not a PE image";
    return Result;
  }
  if (Reader.Size < DosHeaderMinimumSize) {
    Result.Error = "DOS header is truncated";
    return Result;
  }

  uint32_t Lfanew = 0;
  if (!Reader.U32(DosHeaderLfanewOffset, Lfanew)) {
    Result.Error = "DOS header is truncated before e_lfanew";
    return Result;
  }
  if (Lfanew < DosHeaderMinimumSize) {
    Result.Error = "e_lfanew points inside the DOS header";
    return Result;
  }

  uint32_t Signature = 0;
  if (!Reader.U32(Lfanew, Signature)) {
    Result.Error = "file ends before the NT headers";
    return Result;
  }
  if (Signature != NtSignature) {
    Result.Error = "missing PE signature at e_lfanew";
    return Result;
  }

  const uint64_t CoffOffset = static_cast<uint64_t>(Lfanew) + NtSignatureSize;
  if (!Reader.Fits(CoffOffset, CoffHeaderSize)) {
    Result.Error = "COFF file header is truncated";
    return Result;
  }

  Headers.NtHeaderOffset = Lfanew;
  Reader.U16(CoffOffset + 0, Headers.Machine);
  Reader.U16(CoffOffset + 2, Headers.NumberOfSections);
  Reader.U32(CoffOffset + 4, Headers.TimeDateStamp);
  Reader.U32(CoffOffset + 8, Headers.PointerToSymbolTable);
  Reader.U32(CoffOffset + 12, Headers.NumberOfSymbols);
  Reader.U16(CoffOffset + 16, Headers.SizeOfOptionalHeader);
  Reader.U16(CoffOffset + 18, Headers.Characteristics);

  const uint64_t OptionalOffset = CoffOffset + CoffHeaderSize;
  const uint64_t OptionalSize = Headers.SizeOfOptionalHeader;
  if (OptionalSize < 2u) {
    Result.Error = "optional header is missing";
    return Result;
  }
  if (!Reader.Fits(OptionalOffset, OptionalSize)) {
    Result.Error = "optional header extends past the end of the file";
    return Result;
  }

  uint16_t Magic = 0;
  if (!Reader.U16(OptionalOffset, Magic)) {
    Result.Error = "optional header magic is unreadable";
    return Result;
  }
  if (Magic != PeOptionalMagicPe32 && Magic != PeOptionalMagicPe32Plus) {
    Result.Error = "unknown optional header magic";
    return Result;
  }
  Headers.OptionalMagic = Magic;
  Headers.IsPe32Plus = Magic == PeOptionalMagicPe32Plus;

  const uint64_t RequiredOptionalSize =
      Headers.IsPe32Plus ? OptionalHeaderPe32PlusSize : OptionalHeaderPe32Size;
  if (OptionalSize < RequiredOptionalSize) {
    Result.Error = "optional header is truncated before the data directory count";
    return Result;
  }

  const uint64_t ImageBaseOffset = OptionalOffset + (Headers.IsPe32Plus ? 24 : 28);
  const uint64_t DirectoryCountOffset = OptionalOffset + (Headers.IsPe32Plus ? 108 : 92);
  const uint64_t DirectoryOffset =
      OptionalOffset + (Headers.IsPe32Plus ? DataDirectoryPe32PlusOffset : DataDirectoryPe32Offset);

  Reader.U8(OptionalOffset + 2, Headers.MajorLinkerVersion);
  Reader.U8(OptionalOffset + 3, Headers.MinorLinkerVersion);
  Reader.U32(OptionalOffset + 4, Headers.SizeOfCode);
  Reader.U32(OptionalOffset + 8, Headers.SizeOfInitializedData);
  Reader.U32(OptionalOffset + 12, Headers.SizeOfUninitializedData);
  Reader.U32(OptionalOffset + 16, Headers.AddressOfEntryPoint);
  Reader.U32(OptionalOffset + 20, Headers.BaseOfCode);

  if (Headers.IsPe32Plus) {
    uint64_t WideImageBase = 0;
    Reader.U64(ImageBaseOffset, WideImageBase);
    Headers.ImageBase = WideImageBase;
  } else {
    uint32_t NarrowImageBase = 0;
    Reader.U32(ImageBaseOffset, NarrowImageBase);
    Headers.ImageBase = NarrowImageBase;
  }

  Reader.U32(OptionalOffset + 32, Headers.SectionAlignment);
  Reader.U32(OptionalOffset + 36, Headers.FileAlignment);
  Reader.U16(OptionalOffset + 68, Headers.Subsystem);
  Reader.U16(OptionalOffset + 70, Headers.DllCharacteristics);
  Reader.U32(OptionalOffset + 56, Headers.SizeOfImage);
  Reader.U32(OptionalOffset + 60, Headers.SizeOfHeaders);
  Reader.U32(OptionalOffset + 64, Headers.CheckSum);
  Reader.U32(DirectoryCountOffset, Headers.DeclaredDataDirectories);

  uint32_t DirectoryCount =
      Headers.DeclaredDataDirectories < PeDataDirectoryCount ? Headers.DeclaredDataDirectories
                                                             : PeDataDirectoryCount;
  const uint64_t DirectorySpace =
      (OptionalSize - (Headers.IsPe32Plus ? DataDirectoryPe32PlusOffset : DataDirectoryPe32Offset)) /
      DataDirectoryEntrySize;
  if (DirectorySpace < DirectoryCount) {
    DirectoryCount = static_cast<uint32_t>(DirectorySpace);
  }

  Headers.DataDirectories.resize(DirectoryCount);
  for (uint32_t Index = 0; Index < DirectoryCount; ++Index) {
    const uint64_t Base = DirectoryOffset + static_cast<uint64_t>(Index) * DataDirectoryEntrySize;
    Reader.U32(Base + 0, Headers.DataDirectories[Index].Rva);
    Reader.U32(Base + 4, Headers.DataDirectories[Index].Size);
  }

  const uint64_t SectionTableOffset = OptionalOffset + OptionalSize;
  if (!ParseSectionTable(*this, Reader, SectionTableOffset, Result.Error)) {
    return Result;
  }

  if (!ParseExportDirectory(*this, Reader, Result.Error)) {
    return Result;
  }
  if (!ParseDebugDirectory(*this, Reader, Result.Error)) {
    return Result;
  }
  ParseCodeViewRecord(*this, Reader);

  Result.Ok = true;
  return Result;
}

PeLoadResult PeImage::Load(const std::string& Path) {
  PeLoadResult Result;
  Reset();

  std::ifstream Stream(Path, std::ios::binary | std::ios::ate);
  if (!Stream.is_open()) {
    Result.Error = "unable to open '" + Path + "'";
    return Result;
  }

  const std::streampos End = Stream.tellg();
  if (End <= 0) {
    Result.Error = "file '" + Path + "' is empty or its size is unreadable";
    return Result;
  }

  Stream.seekg(0, std::ios::beg);
  std::vector<uint8_t> Contents(static_cast<size_t>(End));
  Stream.read(reinterpret_cast<char*>(Contents.data()), static_cast<std::streamsize>(Contents.size()));
  const std::streamsize Got = Stream.gcount();
  if (Got != static_cast<std::streamsize>(Contents.size())) {
    Result.Error = "short read on '" + Path + "'";
    return Result;
  }

  return Parse(std::move(Contents));
}

}
