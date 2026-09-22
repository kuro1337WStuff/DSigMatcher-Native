#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace DSig {

inline constexpr uint32_t PeDataDirectoryCount = 16;
inline constexpr uint32_t PeDirectoryEntryExport = 0;
inline constexpr uint32_t PeDirectoryEntryDebug = 6;
inline constexpr uint32_t PeDebugTypeCodeView = 2;
inline constexpr uint16_t PeOptionalMagicPe32 = 0x10b;
inline constexpr uint16_t PeOptionalMagicPe32Plus = 0x20b;
inline constexpr uint16_t PeMachineI386 = 0x14c;
inline constexpr uint16_t PeMachineAmd64 = 0x8664;
inline constexpr size_t PeSectionNameLength = 8;

struct PeLoadResult {
  bool Ok = false;
  std::string Error;
};

struct PeDataDirectory {
  uint32_t Rva = 0;
  uint32_t Size = 0;
};

struct PeSection {
  std::string_view Name;
  uint32_t VirtualSize = 0;
  uint32_t VirtualAddress = 0;
  uint32_t SizeOfRawData = 0;
  uint32_t PointerToRawData = 0;
  uint32_t PointerToRelocations = 0;
  uint32_t PointerToLinenumbers = 0;
  uint16_t NumberOfRelocations = 0;
  uint16_t NumberOfLinenumbers = 0;
  uint32_t Characteristics = 0;

  uint64_t VirtualEnd() const {
    return static_cast<uint64_t>(VirtualAddress) +
           (VirtualSize != 0 ? static_cast<uint64_t>(VirtualSize)
                             : static_cast<uint64_t>(SizeOfRawData));
  }

  uint64_t RawEnd() const {
    return static_cast<uint64_t>(PointerToRawData) + static_cast<uint64_t>(SizeOfRawData);
  }

  bool HoldsRva(uint32_t Rva) const {
    return Rva >= VirtualAddress && static_cast<uint64_t>(Rva) < VirtualEnd();
  }

  bool HoldsOffset(uint32_t Offset) const {
    return SizeOfRawData != 0 && Offset >= PointerToRawData &&
           static_cast<uint64_t>(Offset) < RawEnd();
  }
};

struct PeExport {
  std::string_view Name;
  uint32_t Ordinal = 0;
  uint32_t AddressIndex = 0;
  uint32_t Rva = 0;
  bool IsForwarder = false;
  bool IsNamed = false;
  std::string_view ForwarderName;
};

struct PeExportDirectoryInfo {
  bool Present = false;
  std::string Error;
  std::string_view DllName;
  uint32_t Rva = 0;
  uint32_t Size = 0;
  uint32_t OrdinalBase = 0;
  uint32_t NumberOfFunctions = 0;
  uint32_t NumberOfNames = 0;
  uint32_t NamedExportCount = 0;
  uint32_t UnnamedExportCount = 0;
  uint32_t ForwarderCount = 0;
  uint32_t DistinctAddressCount = 0;
  uint64_t RvaEnd = 0;
};

struct PeDebugEntry {
  uint32_t Characteristics = 0;
  uint32_t TimeDateStamp = 0;
  uint16_t MajorVersion = 0;
  uint16_t MinorVersion = 0;
  uint32_t Type = 0;
  uint32_t SizeOfData = 0;
  uint32_t AddressOfRawData = 0;
  uint32_t PointerToRawData = 0;
};

struct PeCodeViewRecord {
  bool Present = false;
  std::string Error;
  std::string_view Signature;
  uint32_t Data1 = 0;
  uint16_t Data2 = 0;
  uint16_t Data3 = 0;
  uint8_t Data4[8] = {};
  uint32_t Age = 0;
  std::string_view PdbPath;
  std::string PdbName;
  std::string Guid;
  std::string SymbolKey;
  std::string SymbolUrl;
};

struct PeHeaders {
  uint32_t NtHeaderOffset = 0;
  uint16_t Machine = 0;
  uint16_t NumberOfSections = 0;
  uint32_t TimeDateStamp = 0;
  uint32_t PointerToSymbolTable = 0;
  uint32_t NumberOfSymbols = 0;
  uint16_t SizeOfOptionalHeader = 0;
  uint16_t Characteristics = 0;
  uint16_t OptionalMagic = 0;
  bool IsPe32Plus = false;
  uint8_t MajorLinkerVersion = 0;
  uint8_t MinorLinkerVersion = 0;
  uint32_t SizeOfCode = 0;
  uint32_t SizeOfInitializedData = 0;
  uint32_t SizeOfUninitializedData = 0;
  uint32_t AddressOfEntryPoint = 0;
  uint32_t BaseOfCode = 0;
  uint64_t ImageBase = 0;
  uint32_t SectionAlignment = 0;
  uint32_t FileAlignment = 0;
  uint16_t Subsystem = 0;
  uint16_t DllCharacteristics = 0;
  uint32_t SizeOfImage = 0;
  uint32_t SizeOfHeaders = 0;
  uint32_t CheckSum = 0;
  uint32_t DeclaredDataDirectories = 0;
  std::vector<PeDataDirectory> DataDirectories;

  bool IsDll() const { return (Characteristics & 0x2000u) != 0; }

  const PeDataDirectory* Directory(uint32_t Index) const {
    if (Index >= DataDirectories.size()) {
      return nullptr;
    }
    return &DataDirectories[Index];
  }
};

class PeImage {
public:
  PeImage() = default;
  PeImage(const PeImage&) = delete;
  PeImage& operator=(const PeImage&) = delete;
  PeImage(PeImage&&) = default;
  PeImage& operator=(PeImage&&) = default;

  PeLoadResult Parse(std::vector<uint8_t> Buffer);
  PeLoadResult Load(const std::string& Path);
  void Reset();

  const std::vector<uint8_t>& Bytes() const { return Buffer_; }
  size_t BufferSize() const { return Buffer_.size(); }

  const PeSection* SectionContainingRva(uint32_t Rva) const;
  const PeSection* SectionContainingOffset(uint32_t Offset) const;
  bool RvaToOffset(uint32_t Rva, uint32_t& OutOffset) const;
  bool OffsetToRva(uint32_t Offset, uint32_t& OutRva) const;
  bool RvaRangeToOffset(uint32_t Rva, uint64_t Length, uint32_t& OutOffset) const;
  const PeExport* FindExportByName(std::string_view Name) const;
  bool IsInsideExportDirectory(uint32_t Rva) const;

  PeHeaders Headers;
  std::vector<PeSection> Sections;
  PeExportDirectoryInfo ExportDirectory;
  std::vector<PeExport> Exports;
  std::vector<PeDebugEntry> DebugEntries;
  PeCodeViewRecord CodeView;

private:
  std::vector<uint8_t> Buffer_;
};

}
