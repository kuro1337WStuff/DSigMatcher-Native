#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "dsigmatcher/PeImage.h"

#include "NoErrorDialogs.h"

namespace {

using namespace DSig;

int ChecksRun = 0;
int ChecksFailed = 0;
int SuitesSkipped = 0;

void Report(bool Ok, const char* Expression, const char* File, int Line) {
  ++ChecksRun;
  if (!Ok) {
    ++ChecksFailed;
    std::printf("  FAIL %s:%d  %s\n", File, Line, Expression);
  }
}

void ReportValues(bool Ok, const char* Expression, long long Actual, long long Expected,
                  const char* File, int Line) {
  ++ChecksRun;
  if (!Ok) {
    ++ChecksFailed;
    std::printf("  FAIL %s:%d  %s\n       actual   : %lld\n       expected : %lld\n", File, Line,
                Expression, Actual, Expected);
  }
}

void ReportText(bool Ok, const char* Expression, const std::string& Actual,
                const std::string& Expected, const char* File, int Line) {
  ++ChecksRun;
  if (!Ok) {
    ++ChecksFailed;
    std::printf("  FAIL %s:%d  %s\n       actual   : %s\n       expected : %s\n", File, Line,
                Expression, Actual.c_str(), Expected.c_str());
  }
}

void Suite(const char* Name) {
  std::printf("[%s]\n", Name);
}

void NoteText(const char* Label, const std::string& Value) {
  std::printf("  %-24s %s\n", Label, Value.c_str());
}

void NoteNumber(const char* Label, long long Value) {
  std::printf("  %-24s %lld\n", Label, Value);
}

#define CHECK(Expr) Report(static_cast<bool>(Expr), #Expr, __FILE__, __LINE__)
#define CHECK_NUM_EQ(A, B) \
  ReportValues(static_cast<long long>(A) == static_cast<long long>(B), #A " == " #B, \
               static_cast<long long>(A), static_cast<long long>(B), __FILE__, __LINE__)
#define CHECK_TEXT_EQ(A, B) \
  ReportText(std::string(A) == std::string(B), #A " == " #B, std::string(A), std::string(B), \
             __FILE__, __LINE__)

#ifndef DSIG_CORPUS_ROOT
#define DSIG_CORPUS_ROOT "corpus"
#endif

const std::string CorpusOlderWin32uStorage =
    std::string(DSIG_CORPUS_ROOT) + "/win32u/win32u_100261009168/win32u.dll";
const std::string CorpusNewerWin32uStorage =
    std::string(DSIG_CORPUS_ROOT) + "/win32u/win32u_100261009444/win32u.dll";
const std::string CorpusAbsentFileStorage =
    std::string(DSIG_CORPUS_ROOT) + "/this-file-does-not-exist.dll";

const char* const CorpusOlderWin32u = CorpusOlderWin32uStorage.c_str();
const char* const CorpusNewerWin32u = CorpusNewerWin32uStorage.c_str();
const char* const CorpusAbsentFile = CorpusAbsentFileStorage.c_str();

constexpr size_t SynthTotalSizePe32Plus = 0x600;
constexpr size_t SynthTotalSizePe32 = 0x400;
constexpr size_t SynthLfanewRaw = 0x3c;
constexpr size_t SynthNtHeaderOffset = 0x80;
constexpr size_t SynthOptionalOffset = 0x98;
constexpr size_t SynthOptionalSizeFieldRaw = 0x94;
constexpr size_t SynthSectionTableOffsetPe32Plus = 0x188;
constexpr size_t SynthSectionTableOffsetPe32 = 0x178;
constexpr size_t SynthSectionHeaderSize = 40;
constexpr size_t SynthTextRaw = 0x200;
constexpr size_t SynthDataRaw = 0x400;
constexpr size_t SynthDataRawToRva = 0x1c00;
constexpr size_t SynthDebugDirectoryRaw = 0x500;
constexpr size_t SynthCodeViewRaw = 0x520;
constexpr size_t SynthExportDataDirectoryRaw = 0x108;
constexpr size_t SynthDebugDataDirectoryRaw = 0x138;
constexpr size_t SynthSecondSectionSizeOfRawDataField = 0x1c0;
constexpr size_t SynthSizeOfDataFieldInDebugEntry = 16;
constexpr size_t SynthAddressOfRawDataFieldInDebugEntry = 20;
constexpr size_t SynthPointerToRawDataFieldInDebugEntry = 24;
constexpr size_t SynthTypeFieldInDebugEntry = 12;
constexpr size_t SynthExportNameRvaField = 12;
constexpr size_t SynthExportNumberOfFunctionsField = 20;
constexpr size_t SynthExportNumberOfNamesField = 24;
constexpr size_t SynthExportAddressOfFunctionsField = 28;

constexpr uint32_t SynthExportRva = 0x2000;
constexpr uint32_t SynthExportSize = 0x100;
constexpr uint32_t SynthFunctionsArrayRva = 0x2028;
constexpr uint32_t SynthNamesArrayRva = 0x2038;
constexpr uint32_t SynthOrdinalsArrayRva = 0x2044;
constexpr uint32_t SynthDllNameRva = 0x2050;
constexpr uint32_t SynthNameAlphaRva = 0x2060;
constexpr uint32_t SynthNameBetaRva = 0x2066;
constexpr uint32_t SynthNameForwardedRva = 0x206b;
constexpr uint32_t SynthForwarderStringRva = 0x2078;
constexpr uint32_t SynthDebugRva = 0x2100;
constexpr uint32_t SynthCodeViewRva = 0x2120;
constexpr uint32_t SynthCodeViewSize = 38;
constexpr uint32_t SynthAlphaRva = 0x1000;
constexpr uint32_t SynthBetaRva = 0x1010;
constexpr uint32_t SynthUnnamedRva = 0x1030;
constexpr uint32_t SynthOrdinalBase = 1;

const uint8_t SynthCodeViewData4[8] = {0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44};
const char* const SynthExpectedGuid = "DEADBEEF123456789ABCDEF011223344";
const char* const SynthExpectedSymbolKey = "DEADBEEF123456789ABCDEF0112233443";
const char* const SynthExpectedSymbolUrl =
    "https://msdl.microsoft.com/download/symbols/synthetic.pdb/"
    "DEADBEEF123456789ABCDEF0112233443/synthetic.pdb";

void PutU16(std::vector<uint8_t>& Buffer, size_t Offset, uint16_t Value) {
  Buffer[Offset] = static_cast<uint8_t>(Value & 0xffu);
  Buffer[Offset + 1] = static_cast<uint8_t>((Value >> 8) & 0xffu);
}

void PutU32(std::vector<uint8_t>& Buffer, size_t Offset, uint32_t Value) {
  Buffer[Offset] = static_cast<uint8_t>(Value & 0xffu);
  Buffer[Offset + 1] = static_cast<uint8_t>((Value >> 8) & 0xffu);
  Buffer[Offset + 2] = static_cast<uint8_t>((Value >> 16) & 0xffu);
  Buffer[Offset + 3] = static_cast<uint8_t>((Value >> 24) & 0xffu);
}

void PutU64(std::vector<uint8_t>& Buffer, size_t Offset, uint64_t Value) {
  for (size_t Index = 0; Index < 8u; ++Index) {
    Buffer[Offset + Index] = static_cast<uint8_t>((Value >> (Index * 8u)) & 0xffu);
  }
}

void PutText(std::vector<uint8_t>& Buffer, size_t Offset, const char* Text, size_t Count) {
  for (size_t Index = 0; Index < Count; ++Index) {
    Buffer[Offset + Index] = static_cast<uint8_t>(Text[Index]);
  }
}

void PutBytes(std::vector<uint8_t>& Buffer, size_t Offset, const uint8_t* Values, size_t Count) {
  for (size_t Index = 0; Index < Count; ++Index) {
    Buffer[Offset + Index] = Values[Index];
  }
}

void PutString(std::vector<uint8_t>& Buffer, size_t Offset, const char* Text) {
  size_t Index = Offset;
  for (const char* Cursor = Text; *Cursor != '\0'; ++Cursor) {
    Buffer[Index] = static_cast<uint8_t>(*Cursor);
    ++Index;
  }
  Buffer[Index] = 0;
}

size_t RvaToSynthDataRaw(uint32_t Rva) {
  return static_cast<size_t>(Rva) - SynthDataRawToRva;
}

void WriteDosHeader(std::vector<uint8_t>& Buffer) {
  PutU16(Buffer, 0, 0x5a4d);
  PutU32(Buffer, SynthLfanewRaw, static_cast<uint32_t>(SynthNtHeaderOffset));
}

void WriteCoffHeader(std::vector<uint8_t>& Buffer, uint16_t Machine, uint16_t SectionCount,
                     uint16_t OptionalSize, uint16_t Characteristics) {
  PutU32(Buffer, SynthNtHeaderOffset, 0x00004550);
  PutU16(Buffer, SynthNtHeaderOffset + 4, Machine);
  PutU16(Buffer, SynthNtHeaderOffset + 6, SectionCount);
  PutU32(Buffer, SynthNtHeaderOffset + 8, 0x60000000);
  PutU16(Buffer, SynthNtHeaderOffset + 20, OptionalSize);
  PutU16(Buffer, SynthNtHeaderOffset + 22, Characteristics);
}

void WriteSectionHeader(std::vector<uint8_t>& Buffer, size_t TableOffset, uint32_t Index,
                        const char* Name, uint32_t VirtualSize, uint32_t VirtualAddress,
                        uint32_t RawSize, uint32_t RawPointer, uint32_t Characteristics) {
  const size_t Base = TableOffset + static_cast<size_t>(Index) * SynthSectionHeaderSize;
  for (size_t Slot = 0; Slot < 8u; ++Slot) {
    Buffer[Base + Slot] = Name[Slot] != '\0' ? static_cast<uint8_t>(Name[Slot]) : 0;
  }
  PutU32(Buffer, Base + 8, VirtualSize);
  PutU32(Buffer, Base + 12, VirtualAddress);
  PutU32(Buffer, Base + 16, RawSize);
  PutU32(Buffer, Base + 20, RawPointer);
  PutU32(Buffer, Base + 36, Characteristics);
}

void WriteExportDirectory(std::vector<uint8_t>& Buffer) {
  const size_t Base = RvaToSynthDataRaw(SynthExportRva);
  PutU32(Buffer, Base + 0, 0);
  PutU32(Buffer, Base + 4, 0x60000000);
  PutU32(Buffer, Base + SynthExportNameRvaField, SynthDllNameRva);
  PutU32(Buffer, Base + 16, SynthOrdinalBase);
  PutU32(Buffer, Base + SynthExportNumberOfFunctionsField, 4);
  PutU32(Buffer, Base + SynthExportNumberOfNamesField, 3);
  PutU32(Buffer, Base + SynthExportAddressOfFunctionsField, SynthFunctionsArrayRva);
  PutU32(Buffer, Base + 32, SynthNamesArrayRva);
  PutU32(Buffer, Base + 36, SynthOrdinalsArrayRva);

  const size_t Functions = RvaToSynthDataRaw(SynthFunctionsArrayRva);
  PutU32(Buffer, Functions + 0, SynthAlphaRva);
  PutU32(Buffer, Functions + 4, SynthBetaRva);
  PutU32(Buffer, Functions + 8, SynthForwarderStringRva);
  PutU32(Buffer, Functions + 12, SynthUnnamedRva);

  const size_t Names = RvaToSynthDataRaw(SynthNamesArrayRva);
  PutU32(Buffer, Names + 0, SynthNameAlphaRva);
  PutU32(Buffer, Names + 4, SynthNameBetaRva);
  PutU32(Buffer, Names + 8, SynthNameForwardedRva);

  const size_t Ordinals = RvaToSynthDataRaw(SynthOrdinalsArrayRva);
  PutU16(Buffer, Ordinals + 0, 0);
  PutU16(Buffer, Ordinals + 2, 1);
  PutU16(Buffer, Ordinals + 4, 2);

  PutString(Buffer, RvaToSynthDataRaw(SynthDllNameRva), "synthetic.dll");
  PutString(Buffer, RvaToSynthDataRaw(SynthNameAlphaRva), "Alpha");
  PutString(Buffer, RvaToSynthDataRaw(SynthNameBetaRva), "Beta");
  PutString(Buffer, RvaToSynthDataRaw(SynthNameForwardedRva), "Forwarded");
  PutString(Buffer, RvaToSynthDataRaw(SynthForwarderStringRva), "OtherDll.Target");
}

void WriteDebugDirectory(std::vector<uint8_t>& Buffer, uint32_t PointerToRawData) {
  PutU32(Buffer, SynthDebugDirectoryRaw + 0, 0);
  PutU32(Buffer, SynthDebugDirectoryRaw + 4, 0x60000000);
  PutU32(Buffer, SynthDebugDirectoryRaw + SynthTypeFieldInDebugEntry, 2);
  PutU32(Buffer, SynthDebugDirectoryRaw + SynthSizeOfDataFieldInDebugEntry, SynthCodeViewSize);
  PutU32(Buffer, SynthDebugDirectoryRaw + SynthAddressOfRawDataFieldInDebugEntry, SynthCodeViewRva);
  PutU32(Buffer, SynthDebugDirectoryRaw + SynthPointerToRawDataFieldInDebugEntry, PointerToRawData);
}

void WriteCodeViewBlob(std::vector<uint8_t>& Buffer) {
  PutText(Buffer, SynthCodeViewRaw, "RSDS", 4);
  PutU32(Buffer, SynthCodeViewRaw + 4, 0xdeadbeef);
  PutU16(Buffer, SynthCodeViewRaw + 8, 0x1234);
  PutU16(Buffer, SynthCodeViewRaw + 10, 0x5678);
  PutBytes(Buffer, SynthCodeViewRaw + 12, SynthCodeViewData4, 8);
  PutU32(Buffer, SynthCodeViewRaw + 20, 3);
  PutString(Buffer, SynthCodeViewRaw + 24, "synthetic.pdb");
}

std::vector<uint8_t> BuildSyntheticPe32Plus() {
  std::vector<uint8_t> Buffer(SynthTotalSizePe32Plus, 0);

  WriteDosHeader(Buffer);
  WriteCoffHeader(Buffer, 0x8664, 2, 0xf0, 0x2022);

  PutU16(Buffer, SynthOptionalOffset + 0, 0x20b);
  Buffer[SynthOptionalOffset + 2] = 14;
  PutU32(Buffer, SynthOptionalOffset + 4, 0x200);
  PutU32(Buffer, SynthOptionalOffset + 8, 0x400);
  PutU32(Buffer, SynthOptionalOffset + 16, SynthAlphaRva);
  PutU32(Buffer, SynthOptionalOffset + 20, SynthAlphaRva);
  PutU64(Buffer, SynthOptionalOffset + 24, 0x140000000ull);
  PutU32(Buffer, SynthOptionalOffset + 32, 0x1000);
  PutU32(Buffer, SynthOptionalOffset + 36, 0x200);
  PutU32(Buffer, SynthOptionalOffset + 56, 0x3000);
  PutU32(Buffer, SynthOptionalOffset + 60, 0x200);
  PutU16(Buffer, SynthOptionalOffset + 68, 2);
  PutU32(Buffer, SynthOptionalOffset + 108, 16);

  PutU32(Buffer, SynthExportDataDirectoryRaw + 0, SynthExportRva);
  PutU32(Buffer, SynthExportDataDirectoryRaw + 4, SynthExportSize);
  PutU32(Buffer, SynthDebugDataDirectoryRaw + 0, SynthDebugRva);
  PutU32(Buffer, SynthDebugDataDirectoryRaw + 4, 28);

  WriteSectionHeader(Buffer, SynthSectionTableOffsetPe32Plus, 0, ".text", 0x100, SynthAlphaRva,
                     0x200, static_cast<uint32_t>(SynthTextRaw), 0x60000020);
  WriteSectionHeader(Buffer, SynthSectionTableOffsetPe32Plus, 1, ".rdata", 0x200, SynthExportRva,
                     0x200, static_cast<uint32_t>(SynthDataRaw), 0x40000040);

  WriteExportDirectory(Buffer);
  WriteDebugDirectory(Buffer, static_cast<uint32_t>(SynthCodeViewRaw));
  WriteCodeViewBlob(Buffer);

  return Buffer;
}

std::vector<uint8_t> BuildSyntheticPe32() {
  std::vector<uint8_t> Buffer(SynthTotalSizePe32, 0);

  WriteDosHeader(Buffer);
  WriteCoffHeader(Buffer, 0x14c, 1, 0xe0, 0x0102);

  PutU16(Buffer, SynthOptionalOffset + 0, 0x10b);
  PutU32(Buffer, SynthOptionalOffset + 4, 0x200);
  PutU32(Buffer, SynthOptionalOffset + 16, SynthAlphaRva);
  PutU32(Buffer, SynthOptionalOffset + 20, SynthAlphaRva);
  PutU32(Buffer, SynthOptionalOffset + 24, 0x2000);
  PutU32(Buffer, SynthOptionalOffset + 28, 0x00400000);
  PutU32(Buffer, SynthOptionalOffset + 32, 0x1000);
  PutU32(Buffer, SynthOptionalOffset + 36, 0x200);
  PutU32(Buffer, SynthOptionalOffset + 56, 0x2000);
  PutU32(Buffer, SynthOptionalOffset + 60, 0x200);
  PutU16(Buffer, SynthOptionalOffset + 68, 3);
  PutU32(Buffer, SynthOptionalOffset + 92, 16);

  WriteSectionHeader(Buffer, SynthSectionTableOffsetPe32, 0, ".text", 0x100, SynthAlphaRva, 0x200,
                     static_cast<uint32_t>(SynthTextRaw), 0x60000020);

  return Buffer;
}

void ExpectParseFailure(const std::vector<uint8_t>& Bytes, const char* Label) {
  PeImage Image;
  const PeLoadResult Result = Image.Parse(Bytes);
  ++ChecksRun;
  if (Result.Ok) {
    ++ChecksFailed;
    std::printf("  FAIL %-40s expected a clean parse failure but parsing succeeded\n", Label);
    return;
  }
  ++ChecksRun;
  if (Result.Error.empty()) {
    ++ChecksFailed;
    std::printf("  FAIL %-40s parse failed without an error string\n", Label);
    return;
  }
  std::printf("  ok   %-40s -> %s\n", Label, Result.Error.c_str());
}

void ExpectCodeViewFailure(const std::vector<uint8_t>& Bytes, const char* Label) {
  PeImage Image;
  const PeLoadResult Result = Image.Parse(Bytes);
  ++ChecksRun;
  if (!Result.Ok) {
    ++ChecksFailed;
    std::printf("  FAIL %-40s image should still parse, got: %s\n", Label, Result.Error.c_str());
    return;
  }
  ++ChecksRun;
  if (Image.CodeView.Present || Image.CodeView.Error.empty()) {
    ++ChecksFailed;
    std::printf("  FAIL %-40s expected a CodeView error, present=%d error='%s'\n", Label,
                Image.CodeView.Present ? 1 : 0, Image.CodeView.Error.c_str());
    return;
  }
  std::printf("  ok   %-40s -> %s\n", Label, Image.CodeView.Error.c_str());
}

struct RealImageExpectation {
  const char* Path;
  const char* Label;
  const char* Guid;
  uint32_t Age;
  const char* PdbName;
  const char* SymbolKey;
  const char* DllName;
  uint32_t NamedCount;
  uint32_t DistinctAddressCount;
  uint32_t PeekMessageOrdinal;
  uint32_t PeekMessageRva;
  uint32_t ThunkAddress;
  uint32_t ThunkNameCount;
  uint32_t NtPrefixedCount;
  uint32_t ZwPrefixedCount;
};

void RunRealImageTests(const RealImageExpectation& Expected) {
  Suite(Expected.Label);

  std::error_code Probe;
  if (!std::filesystem::exists(Expected.Path, Probe)) {
    ++SuitesSkipped;
    std::printf("  SKIP corpus file is absent: %s\n", Expected.Path);
    return;
  }

  PeImage Image;
  const PeLoadResult Result = Image.Load(Expected.Path);
  CHECK(Result.Ok);
  if (!Result.Ok) {
    std::printf("  load error: %s\n", Result.Error.c_str());
    return;
  }

  NoteText("path", Expected.Path);
  NoteNumber("buffer size", static_cast<long long>(Image.BufferSize()));
  NoteNumber("machine", Image.Headers.Machine);
  NoteNumber("pe32 plus", Image.Headers.IsPe32Plus ? 1 : 0);
  NoteNumber("image base", static_cast<long long>(Image.Headers.ImageBase));
  NoteNumber("entry point rva", Image.Headers.AddressOfEntryPoint);
  NoteNumber("section alignment", Image.Headers.SectionAlignment);
  NoteNumber("file alignment", Image.Headers.FileAlignment);
  NoteNumber("size of image", Image.Headers.SizeOfImage);
  NoteNumber("size of headers", Image.Headers.SizeOfHeaders);
  NoteNumber("characteristics", Image.Headers.Characteristics);
  NoteNumber("timestamp", Image.Headers.TimeDateStamp);
  NoteNumber("data directories", static_cast<long long>(Image.Headers.DataDirectories.size()));
  NoteNumber("sections", static_cast<long long>(Image.Sections.size()));

  CHECK_NUM_EQ(Image.Headers.Machine, 0x8664);
  CHECK(Image.Headers.IsPe32Plus);
  CHECK(Image.Headers.IsDll());
  CHECK(Image.Headers.SectionAlignment > 0u);
  CHECK(Image.Headers.FileAlignment > 0u);
  CHECK(Image.Headers.SizeOfImage > 0u);
  CHECK_NUM_EQ(Image.Headers.NumberOfSections, Image.Sections.size());
  CHECK_NUM_EQ(Image.Headers.DataDirectories.size(), 16u);

  CHECK(Image.Sections.size() >= 1u);
  CHECK(Image.Sections.size() <= 96u);

  size_t RawRangeFailures = 0;
  for (const PeSection& Section : Image.Sections) {
    std::printf("  section %-9s va=0x%08x vsize=0x%08x raw=0x%08x rawsize=0x%08x chars=0x%08x\n",
                std::string(Section.Name).c_str(), Section.VirtualAddress, Section.VirtualSize,
                Section.PointerToRawData, Section.SizeOfRawData, Section.Characteristics);
    if (Section.SizeOfRawData == 0) {
      continue;
    }
    const uint64_t RawEnd = static_cast<uint64_t>(Section.PointerToRawData) +
                            static_cast<uint64_t>(Section.SizeOfRawData);
    if (RawEnd > Image.BufferSize()) {
      ++RawRangeFailures;
    }
  }
  CHECK_NUM_EQ(RawRangeFailures, 0u);

  uint32_t EntryPointOffset = 0;
  CHECK(Image.RvaToOffset(Image.Headers.AddressOfEntryPoint, EntryPointOffset));

  CHECK(Image.ExportDirectory.Present);
  CHECK(!Image.Exports.empty());
  NoteText("export dll name", std::string(Image.ExportDirectory.DllName));
  NoteNumber("export ordinal base", Image.ExportDirectory.OrdinalBase);
  NoteNumber("number of functions", Image.ExportDirectory.NumberOfFunctions);
  NoteNumber("number of names", Image.ExportDirectory.NumberOfNames);
  NoteNumber("named exports", Image.ExportDirectory.NamedExportCount);
  NoteNumber("unnamed exports", Image.ExportDirectory.UnnamedExportCount);
  NoteNumber("forwarders", Image.ExportDirectory.ForwarderCount);
  NoteNumber("distinct addresses", Image.ExportDirectory.DistinctAddressCount);
  NoteNumber("exports collected", static_cast<long long>(Image.Exports.size()));

  CHECK_TEXT_EQ(Image.ExportDirectory.DllName, Expected.DllName);
  CHECK_NUM_EQ(Image.ExportDirectory.OrdinalBase, 1u);
  CHECK_NUM_EQ(Image.ExportDirectory.NumberOfNames, Expected.NamedCount);
  CHECK_NUM_EQ(Image.ExportDirectory.NumberOfFunctions, Expected.NamedCount);
  CHECK_NUM_EQ(Image.ExportDirectory.NamedExportCount, Expected.NamedCount);
  CHECK_NUM_EQ(Image.ExportDirectory.UnnamedExportCount, 0u);
  CHECK_NUM_EQ(Image.ExportDirectory.ForwarderCount, 0u);
  CHECK_NUM_EQ(Image.ExportDirectory.DistinctAddressCount, Expected.DistinctAddressCount);
  CHECK_NUM_EQ(Image.Exports.size(), Expected.NamedCount);

  const PeExport* PeekMessage = Image.FindExportByName("NtUserPeekMessage");
  CHECK(PeekMessage != nullptr);
  if (PeekMessage != nullptr) {
    NoteNumber("NtUserPeekMessage rva", PeekMessage->Rva);
    NoteNumber("NtUserPeekMessage ordinal", PeekMessage->Ordinal);
    CHECK(PeekMessage->Rva != 0u);
    CHECK(!PeekMessage->IsForwarder);
    CHECK(PeekMessage->IsNamed);
    CHECK_NUM_EQ(PeekMessage->Ordinal, Expected.PeekMessageOrdinal);
    CHECK_NUM_EQ(PeekMessage->Rva, Expected.PeekMessageRva);
  }

  size_t NamedCount = 0;
  size_t ForwarderCount = 0;
  size_t UnnamedCount = 0;
  size_t RoundTripFailures = 0;
  size_t NtPrefixed = 0;
  size_t ZwPrefixed = 0;
  std::set<uint32_t> NamedAddresses;
  std::set<uint32_t> AllAddresses;
  std::set<std::string> DistinctNames;
  std::map<uint32_t, uint32_t> AddressMultiplicity;
  for (const PeExport& Entry : Image.Exports) {
    uint32_t Offset = 0;
    const bool Mapped = Image.RvaToOffset(Entry.Rva, Offset);
    uint32_t RoundTrip = 0;
    const bool Reversed = Mapped && Image.OffsetToRva(Offset, RoundTrip);
    if (!Mapped || !Reversed || RoundTrip != Entry.Rva) {
      ++RoundTripFailures;
    }
    if (Entry.IsForwarder) {
      ++ForwarderCount;
      continue;
    }
    AllAddresses.insert(Entry.Rva);
    if (!Entry.IsNamed) {
      ++UnnamedCount;
      continue;
    }
    ++NamedCount;
    NamedAddresses.insert(Entry.Rva);
    DistinctNames.insert(std::string(Entry.Name));
    ++AddressMultiplicity[Entry.Rva];
    if (Entry.Name.size() >= 2u && Entry.Name[0] == 'N' && Entry.Name[1] == 't') {
      ++NtPrefixed;
    }
    if (Entry.Name.size() >= 2u && Entry.Name[0] == 'Z' && Entry.Name[1] == 'w') {
      ++ZwPrefixed;
    }
  }

  uint32_t PeakAddress = 0;
  uint32_t PeakMultiplicity = 0;
  for (const auto& Slot : AddressMultiplicity) {
    if (Slot.second > PeakMultiplicity) {
      PeakMultiplicity = Slot.second;
      PeakAddress = Slot.first;
    }
  }

  CHECK_NUM_EQ(RoundTripFailures, 0u);
  CHECK(NamedCount > 0u);
  NoteNumber("round-tripped exports", static_cast<long long>(Image.Exports.size()));
  NoteNumber("named (non-forwarder)", static_cast<long long>(NamedCount));
  NoteNumber("unnamed (non-forwarder)", static_cast<long long>(UnnamedCount));
  NoteNumber("forwarders (not functions)", static_cast<long long>(ForwarderCount));
  NoteNumber("distinct named rvas", static_cast<long long>(NamedAddresses.size()));
  NoteNumber("distinct all rvas", static_cast<long long>(AllAddresses.size()));
  NoteNumber("distinct name strings", static_cast<long long>(DistinctNames.size()));
  NoteNumber("Nt* prefixed names", static_cast<long long>(NtPrefixed));
  NoteNumber("Zw* prefixed names", static_cast<long long>(ZwPrefixed));
  std::printf("  %-24s 0x%08x (%u names)\n", "busiest address", PeakAddress, PeakMultiplicity);

  CHECK(!NamedAddresses.empty());
  CHECK_NUM_EQ(DistinctNames.size(), NamedCount);
  CHECK_NUM_EQ(NamedCount, Expected.NamedCount);
  CHECK_NUM_EQ(NamedAddresses.size(), Expected.DistinctAddressCount);
  CHECK_NUM_EQ(AllAddresses.size(), Expected.DistinctAddressCount);
  CHECK_NUM_EQ(NtPrefixed, Expected.NtPrefixedCount);
  CHECK_NUM_EQ(ZwPrefixed, Expected.ZwPrefixedCount);
  CHECK_NUM_EQ(PeakAddress, Expected.ThunkAddress);
  CHECK_NUM_EQ(PeakMultiplicity, Expected.ThunkNameCount);

  const double Ratio = static_cast<double>(NamedCount) / static_cast<double>(NamedAddresses.size());
  std::printf("  %-24s %.4f\n", "names per address", Ratio);
  CHECK(Ratio >= 1.0);
  CHECK(Ratio <= 1.2);
  CHECK(NamedAddresses.size() < NamedCount);

  CHECK(!Image.DebugEntries.empty());
  CHECK(Image.CodeView.Present);
  if (!Image.CodeView.Present) {
    std::printf("  codeview error: %s\n", Image.CodeView.Error.c_str());
    return;
  }

  NoteText("codeview signature", std::string(Image.CodeView.Signature));
  NoteText("pdb path", std::string(Image.CodeView.PdbPath));
  NoteText("pdb name", Image.CodeView.PdbName);
  NoteText("guid", Image.CodeView.Guid);
  NoteNumber("age", Image.CodeView.Age);
  NoteText("symbol key", Image.CodeView.SymbolKey);
  NoteText("symbol url", Image.CodeView.SymbolUrl);

  CHECK_TEXT_EQ(Image.CodeView.Signature, "RSDS");
  CHECK_TEXT_EQ(Image.CodeView.Guid, Expected.Guid);
  CHECK_NUM_EQ(Image.CodeView.Age, Expected.Age);
  CHECK_TEXT_EQ(Image.CodeView.PdbName, Expected.PdbName);
  CHECK_TEXT_EQ(Image.CodeView.SymbolKey, Expected.SymbolKey);

  const std::string ExpectedUrl = std::string("https://msdl.microsoft.com/download/symbols/") +
                                  Expected.PdbName + "/" + Expected.SymbolKey + "/" +
                                  Expected.PdbName;
  CHECK_TEXT_EQ(Image.CodeView.SymbolUrl, ExpectedUrl);
}

void CheckSyntheticCodeView(const PeImage& Image) {
  CHECK(Image.CodeView.Present);
  CHECK(Image.CodeView.Error.empty());
  CHECK_TEXT_EQ(Image.CodeView.Signature, "RSDS");
  CHECK_NUM_EQ(Image.CodeView.Data1, 0xdeadbeefu);
  CHECK_NUM_EQ(Image.CodeView.Data2, 0x1234);
  CHECK_NUM_EQ(Image.CodeView.Data3, 0x5678);
  CHECK_NUM_EQ(Image.CodeView.Data4[0], 0x9a);
  CHECK_NUM_EQ(Image.CodeView.Data4[3], 0xf0);
  CHECK_NUM_EQ(Image.CodeView.Data4[7], 0x44);
  CHECK_NUM_EQ(Image.CodeView.Age, 3u);
  CHECK_TEXT_EQ(Image.CodeView.PdbPath, "synthetic.pdb");
  CHECK_TEXT_EQ(Image.CodeView.PdbName, "synthetic.pdb");
  CHECK_TEXT_EQ(Image.CodeView.Guid, SynthExpectedGuid);
  CHECK_TEXT_EQ(Image.CodeView.SymbolKey, SynthExpectedSymbolKey);
  CHECK_TEXT_EQ(Image.CodeView.SymbolUrl, SynthExpectedSymbolUrl);
}

void RunSyntheticPe32PlusTests() {
  Suite("synthetic pe32+ image");

  PeImage Image;
  const PeLoadResult Result = Image.Parse(BuildSyntheticPe32Plus());
  CHECK(Result.Ok);
  if (!Result.Ok) {
    std::printf("  parse error: %s\n", Result.Error.c_str());
    return;
  }

  CHECK_NUM_EQ(Image.Headers.Machine, 0x8664);
  CHECK(Image.Headers.IsPe32Plus);
  CHECK_NUM_EQ(Image.Headers.OptionalMagic, 0x20b);
  CHECK_NUM_EQ(Image.Headers.MajorLinkerVersion, 14);
  CHECK_NUM_EQ(Image.Headers.ImageBase, 0x140000000ull);
  CHECK_NUM_EQ(Image.Headers.AddressOfEntryPoint, SynthAlphaRva);
  CHECK_NUM_EQ(Image.Headers.SectionAlignment, 0x1000);
  CHECK_NUM_EQ(Image.Headers.FileAlignment, 0x200);
  CHECK_NUM_EQ(Image.Headers.SizeOfImage, 0x3000);
  CHECK_NUM_EQ(Image.Headers.SizeOfHeaders, 0x200);
  CHECK_NUM_EQ(Image.Headers.Characteristics, 0x2022);
  CHECK_NUM_EQ(Image.Headers.Subsystem, 2);
  CHECK(Image.Headers.IsDll());
  CHECK_NUM_EQ(Image.Sections.size(), 2u);
  CHECK_NUM_EQ(Image.Headers.DataDirectories.size(), 16u);
  CHECK_TEXT_EQ(Image.Sections[0].Name, ".text");
  CHECK_TEXT_EQ(Image.Sections[1].Name, ".rdata");

  uint32_t Offset = 0;
  CHECK(Image.RvaToOffset(SynthAlphaRva, Offset));
  CHECK_NUM_EQ(Offset, SynthTextRaw);
  uint32_t Rva = 0;
  CHECK(Image.OffsetToRva(static_cast<uint32_t>(SynthTextRaw), Rva));
  CHECK_NUM_EQ(Rva, SynthAlphaRva);
  CHECK(Image.RvaToOffset(SynthExportRva, Offset));
  CHECK_NUM_EQ(Offset, SynthDataRaw);
  CHECK(Image.OffsetToRva(static_cast<uint32_t>(SynthDataRaw), Rva));
  CHECK_NUM_EQ(Rva, SynthExportRva);
  CHECK(Image.RvaToOffset(0, Offset));
  CHECK_NUM_EQ(Offset, 0u);
  CHECK(!Image.RvaToOffset(0x9000, Offset));
  CHECK(Image.SectionContainingRva(SynthBetaRva) != nullptr);
  CHECK(Image.SectionContainingOffset(static_cast<uint32_t>(SynthCodeViewRaw)) != nullptr);

  uint32_t RangeOffset = 0;
  CHECK(Image.RvaRangeToOffset(SynthCodeViewRva, SynthCodeViewSize, RangeOffset));
  CHECK_NUM_EQ(RangeOffset, SynthCodeViewRaw);
  CHECK(!Image.RvaRangeToOffset(SynthCodeViewRva, 0x10000, RangeOffset));

  CHECK(Image.ExportDirectory.Present);
  CHECK(Image.ExportDirectory.Error.empty());
  CHECK_TEXT_EQ(Image.ExportDirectory.DllName, "synthetic.dll");
  CHECK_NUM_EQ(Image.ExportDirectory.OrdinalBase, SynthOrdinalBase);
  CHECK_NUM_EQ(Image.ExportDirectory.NumberOfFunctions, 4u);
  CHECK_NUM_EQ(Image.ExportDirectory.NumberOfNames, 3u);
  CHECK_NUM_EQ(Image.ExportDirectory.Rva, SynthExportRva);
  CHECK_NUM_EQ(Image.ExportDirectory.Size, SynthExportSize);
  CHECK_NUM_EQ(Image.Exports.size(), 4u);
  CHECK_NUM_EQ(Image.ExportDirectory.NamedExportCount, 2u);
  CHECK_NUM_EQ(Image.ExportDirectory.UnnamedExportCount, 1u);
  CHECK_NUM_EQ(Image.ExportDirectory.ForwarderCount, 1u);
  CHECK_NUM_EQ(Image.ExportDirectory.DistinctAddressCount, 3u);

  CHECK(Image.IsInsideExportDirectory(SynthForwarderStringRva));
  CHECK(Image.IsInsideExportDirectory(SynthExportRva));
  CHECK(!Image.IsInsideExportDirectory(SynthAlphaRva));
  CHECK(!Image.IsInsideExportDirectory(SynthDebugRva));
  CHECK(!Image.IsInsideExportDirectory(0));

  const PeExport* Alpha = Image.FindExportByName("Alpha");
  CHECK(Alpha != nullptr);
  if (Alpha != nullptr) {
    CHECK_NUM_EQ(Alpha->Ordinal, 1u);
    CHECK_NUM_EQ(Alpha->Rva, SynthAlphaRva);
    CHECK(!Alpha->IsForwarder);
    CHECK(Alpha->IsNamed);
    CHECK(Alpha->ForwarderName.empty());
  }

  const PeExport* Beta = Image.FindExportByName("Beta");
  CHECK(Beta != nullptr);
  if (Beta != nullptr) {
    CHECK_NUM_EQ(Beta->Ordinal, 2u);
    CHECK_NUM_EQ(Beta->Rva, SynthBetaRva);
    CHECK(!Beta->IsForwarder);
  }

  const PeExport* Forwarded = Image.FindExportByName("Forwarded");
  CHECK(Forwarded != nullptr);
  if (Forwarded != nullptr) {
    CHECK(Forwarded->IsForwarder);
    CHECK_NUM_EQ(Forwarded->Ordinal, 3u);
    CHECK_NUM_EQ(Forwarded->Rva, SynthForwarderStringRva);
    CHECK_TEXT_EQ(Forwarded->ForwarderName, "OtherDll.Target");
    NoteText("forwarder target", std::string(Forwarded->ForwarderName));
  }

  CHECK(Image.FindExportByName("NoSuchExport") == nullptr);
  CHECK(Image.FindExportByName("") == nullptr);

  const PeExport* Unnamed = nullptr;
  for (const PeExport& Entry : Image.Exports) {
    if (!Entry.IsNamed) {
      Unnamed = &Entry;
      break;
    }
  }
  CHECK(Unnamed != nullptr);
  if (Unnamed != nullptr) {
    CHECK(Unnamed->Name.empty());
    CHECK_NUM_EQ(Unnamed->Ordinal, 4u);
    CHECK_NUM_EQ(Unnamed->Rva, SynthUnnamedRva);
    CHECK(!Unnamed->IsForwarder);
  }

  size_t ForwarderCountedByAddress = 0;
  for (const PeExport& Entry : Image.Exports) {
    if (Entry.IsForwarder && !Image.IsInsideExportDirectory(Entry.Rva)) {
      ++ForwarderCountedByAddress;
    }
  }
  CHECK_NUM_EQ(ForwarderCountedByAddress, 0u);

  CHECK_NUM_EQ(Image.DebugEntries.size(), 1u);
  CHECK_NUM_EQ(Image.DebugEntries[0].Type, 2u);
  CHECK_NUM_EQ(Image.DebugEntries[0].SizeOfData, SynthCodeViewSize);
  CHECK_NUM_EQ(Image.DebugEntries[0].AddressOfRawData, SynthCodeViewRva);
  CHECK_NUM_EQ(Image.DebugEntries[0].PointerToRawData, SynthCodeViewRaw);

  CheckSyntheticCodeView(Image);
}

void RunSyntheticPe32Tests() {
  Suite("synthetic pe32 image");

  PeImage Image;
  const PeLoadResult Result = Image.Parse(BuildSyntheticPe32());
  CHECK(Result.Ok);
  if (!Result.Ok) {
    std::printf("  parse error: %s\n", Result.Error.c_str());
    return;
  }

  CHECK_NUM_EQ(Image.Headers.Machine, 0x14c);
  CHECK(!Image.Headers.IsPe32Plus);
  CHECK_NUM_EQ(Image.Headers.OptionalMagic, 0x10b);
  CHECK_NUM_EQ(Image.Headers.ImageBase, 0x00400000);
  CHECK_NUM_EQ(Image.Headers.AddressOfEntryPoint, SynthAlphaRva);
  CHECK_NUM_EQ(Image.Headers.SectionAlignment, 0x1000);
  CHECK_NUM_EQ(Image.Headers.FileAlignment, 0x200);
  CHECK_NUM_EQ(Image.Headers.SizeOfImage, 0x2000);
  CHECK_NUM_EQ(Image.Headers.SizeOfHeaders, 0x200);
  CHECK_NUM_EQ(Image.Headers.Subsystem, 3);
  CHECK(!Image.Headers.IsDll());
  CHECK_NUM_EQ(Image.Sections.size(), 1u);
  CHECK_TEXT_EQ(Image.Sections[0].Name, ".text");
  CHECK_NUM_EQ(Image.Headers.DataDirectories.size(), 16u);
  CHECK(!Image.ExportDirectory.Present);
  CHECK(Image.Exports.empty());
  CHECK(Image.DebugEntries.empty());
  CHECK(!Image.CodeView.Present);
  CHECK(!Image.CodeView.Error.empty());
  NoteText("pe32 codeview error", Image.CodeView.Error);

  uint32_t Offset = 0;
  CHECK(Image.RvaToOffset(SynthAlphaRva, Offset));
  CHECK_NUM_EQ(Offset, SynthTextRaw);
  uint32_t Rva = 0;
  CHECK(Image.OffsetToRva(static_cast<uint32_t>(SynthTextRaw), Rva));
  CHECK_NUM_EQ(Rva, SynthAlphaRva);
  CHECK(!Image.RvaToOffset(0x9000, Offset));
}

void RunCodeViewRawPointerFallbackTest() {
  Suite("codeview rva fallback");

  std::vector<uint8_t> Bytes = BuildSyntheticPe32Plus();
  PutU32(Bytes, SynthDebugDirectoryRaw + SynthPointerToRawDataFieldInDebugEntry, 0);

  PeImage Image;
  const PeLoadResult Result = Image.Parse(Bytes);
  CHECK(Result.Ok);
  if (!Result.Ok) {
    std::printf("  parse error: %s\n", Result.Error.c_str());
    return;
  }
  CHECK_NUM_EQ(Image.DebugEntries[0].PointerToRawData, 0u);
  CheckSyntheticCodeView(Image);
  NoteText("resolved via rva", Image.CodeView.SymbolKey);
}

void RunSectionNameTests() {
  Suite("section name handling");

  std::vector<uint8_t> Bytes = BuildSyntheticPe32Plus();
  const size_t SecondSectionName = SynthSectionTableOffsetPe32Plus + SynthSectionHeaderSize;
  PutText(Bytes, SecondSectionName, ".longsectname", 8);

  PeImage Image;
  const PeLoadResult Result = Image.Parse(Bytes);
  CHECK(Result.Ok);
  if (!Result.Ok) {
    std::printf("  parse error: %s\n", Result.Error.c_str());
    return;
  }
  CHECK_NUM_EQ(Image.Sections[1].Name.size(), 8u);
  CHECK_TEXT_EQ(Image.Sections[1].Name, ".longsec");
  NoteText("unterminated name", std::string(Image.Sections[1].Name));
}

void RunMalformedTests() {
  Suite("malformed and hostile images");

  std::vector<uint8_t> Empty;
  ExpectParseFailure(Empty, "empty buffer");

  std::vector<uint8_t> OneByte(1, 0x4d);
  ExpectParseFailure(OneByte, "single byte buffer");

  std::vector<uint8_t> Truncated = BuildSyntheticPe32Plus();
  Truncated.resize(16);
  ExpectParseFailure(Truncated, "truncated dos header");

  std::vector<uint8_t> BadMagic = BuildSyntheticPe32Plus();
  BadMagic[0] = 'X';
  ExpectParseFailure(BadMagic, "bad MZ magic");

  std::vector<uint8_t> BadNtSignature = BuildSyntheticPe32Plus();
  PutU32(BadNtSignature, SynthNtHeaderOffset, 0x00004551);
  ExpectParseFailure(BadNtSignature, "bad NT signature");

  std::vector<uint8_t> LfanewPastEnd = BuildSyntheticPe32Plus();
  PutU32(LfanewPastEnd, SynthLfanewRaw, 0x5000);
  ExpectParseFailure(LfanewPastEnd, "e_lfanew past end of buffer");

  std::vector<uint8_t> LfanewInsideDos = BuildSyntheticPe32Plus();
  PutU32(LfanewInsideDos, SynthLfanewRaw, 0x10);
  ExpectParseFailure(LfanewInsideDos, "e_lfanew inside dos header");

  std::vector<uint8_t> BadOptionalMagic = BuildSyntheticPe32Plus();
  PutU16(BadOptionalMagic, SynthOptionalOffset, 0x999);
  ExpectParseFailure(BadOptionalMagic, "unknown optional header magic");

  std::vector<uint8_t> TruncatedOptional = BuildSyntheticPe32Plus();
  PutU16(TruncatedOptional, SynthOptionalSizeFieldRaw, 0x40);
  ExpectParseFailure(TruncatedOptional, "optional header too short");

  std::vector<uint8_t> TruncatedSectionTable = BuildSyntheticPe32Plus();
  TruncatedSectionTable.resize(SynthSectionTableOffsetPe32Plus + 16);
  ExpectParseFailure(TruncatedSectionTable, "truncated section table");

  std::vector<uint8_t> SectionRawPastEnd = BuildSyntheticPe32Plus();
  PutU32(SectionRawPastEnd, SynthSecondSectionSizeOfRawDataField, 0x400);
  ExpectParseFailure(SectionRawPastEnd, "section raw range past end");

  std::vector<uint8_t> ExportDirectoryOutside = BuildSyntheticPe32Plus();
  PutU32(ExportDirectoryOutside, SynthExportDataDirectoryRaw, 0x9000);
  ExpectParseFailure(ExportDirectoryOutside, "export directory outside image");

  std::vector<uint8_t> ExportDirectoryZeroSize = BuildSyntheticPe32Plus();
  PutU32(ExportDirectoryZeroSize, SynthExportDataDirectoryRaw + 4, 0);
  ExpectParseFailure(ExportDirectoryZeroSize, "export directory zero size");

  std::vector<uint8_t> DebugDirectoryOutside = BuildSyntheticPe32Plus();
  PutU32(DebugDirectoryOutside, SynthDebugDataDirectoryRaw, 0x9000);
  ExpectParseFailure(DebugDirectoryOutside, "debug directory outside image");

  std::vector<uint8_t> FunctionsArrayOutside = BuildSyntheticPe32Plus();
  PutU32(FunctionsArrayOutside, RvaToSynthDataRaw(SynthExportRva) + SynthExportAddressOfFunctionsField,
         0x9000);
  ExpectParseFailure(FunctionsArrayOutside, "export address table outside image");

  std::vector<uint8_t> NamesArrayOutside = BuildSyntheticPe32Plus();
  PutU32(NamesArrayOutside, RvaToSynthDataRaw(SynthNamesArrayRva), 0x9000);
  ExpectParseFailure(NamesArrayOutside, "export name pointer outside image");

  std::vector<uint8_t> OrdinalOutOfRange = BuildSyntheticPe32Plus();
  PutU16(OrdinalOutOfRange, RvaToSynthDataRaw(SynthOrdinalsArrayRva), 99);
  ExpectParseFailure(OrdinalOutOfRange, "export ordinal outside address table");

  std::vector<uint8_t> HugeExportCounts = BuildSyntheticPe32Plus();
  PutU32(HugeExportCounts, RvaToSynthDataRaw(SynthExportRva) + SynthExportNumberOfFunctionsField,
         0xfffffff0);
  PutU32(HugeExportCounts, RvaToSynthDataRaw(SynthExportRva) + SynthExportNumberOfNamesField,
         0xfffffff0);
  ExpectParseFailure(HugeExportCounts, "implausible export entry counts");

  std::vector<uint8_t> CodeViewTooSmall = BuildSyntheticPe32Plus();
  PutU32(CodeViewTooSmall, SynthDebugDirectoryRaw + SynthSizeOfDataFieldInDebugEntry, 8);
  ExpectCodeViewFailure(CodeViewTooSmall, "codeview blob smaller than rsds");

  std::vector<uint8_t> CodeViewNotRsds = BuildSyntheticPe32Plus();
  PutText(CodeViewNotRsds, SynthCodeViewRaw, "NB10", 4);
  ExpectCodeViewFailure(CodeViewNotRsds, "non-rsds codeview signature");

  std::vector<uint8_t> CodeViewUnreachable = BuildSyntheticPe32Plus();
  PutU32(CodeViewUnreachable, SynthDebugDirectoryRaw + SynthPointerToRawDataFieldInDebugEntry, 0x9000);
  PutU32(CodeViewUnreachable, SynthDebugDirectoryRaw + SynthAddressOfRawDataFieldInDebugEntry, 0x9000);
  ExpectCodeViewFailure(CodeViewUnreachable, "codeview blob unreachable");

  std::vector<uint8_t> NoCodeViewEntry = BuildSyntheticPe32Plus();
  PutU32(NoCodeViewEntry, SynthDebugDirectoryRaw + SynthTypeFieldInDebugEntry, 13);
  ExpectCodeViewFailure(NoCodeViewEntry, "no codeview debug entry");
}

void RunReuseTests() {
  Suite("parser reuse and reset");

  PeImage Image;
  const PeLoadResult First = Image.Parse(BuildSyntheticPe32Plus());
  CHECK(First.Ok);
  CHECK(Image.CodeView.Present);
  CHECK_NUM_EQ(Image.Exports.size(), 4u);

  const PeLoadResult Second = Image.Parse(BuildSyntheticPe32());
  CHECK(Second.Ok);
  CHECK(!Image.CodeView.Present);
  CHECK(Image.Exports.empty());
  CHECK_NUM_EQ(Image.Sections.size(), 1u);
  CHECK_NUM_EQ(Image.Headers.Machine, 0x14c);

  Image.Reset();
  CHECK(Image.Bytes().empty());
  CHECK(Image.Sections.empty());
  CHECK(!Image.CodeView.Present);
  CHECK(!Image.ExportDirectory.Present);

  PeImage Missing;
  const PeLoadResult LoadFailure = Missing.Load(CorpusAbsentFile);
  CHECK(!LoadFailure.Ok);
  CHECK(!LoadFailure.Error.empty());
  NoteText("missing file error", LoadFailure.Error);
}

const RealImageExpectation ExpectedOlderWin32u = {
    CorpusOlderWin32u,
    "real image win32u_100261009168",
    "3B99E6AC1E885968EBBCA13F4EC0C4B1",
    1,
    "win32u.pdb",
    "3B99E6AC1E885968EBBCA13F4EC0C4B11",
    "win32u.dll",
    1548,
    1506,
    1228,
    0x12d0,
    0x1010,
    43,
    1540,
    0};

const RealImageExpectation ExpectedNewerWin32u = {
    CorpusNewerWin32u,
    "real image win32u_100261009444",
    "6295787D0B7E537E98F77F31F4426D1C",
    1,
    "win32u.pdb",
    "6295787D0B7E537E98F77F31F4426D1C1",
    "win32u.dll",
    1552,
    1508,
    1232,
    0x12d0,
    0x1010,
    45,
    1544,
    0};

}

int main() {
  DSig::Test::DisableErrorDialogs();  // first: no loader, crash or missing-file dialog (Windows)
  std::printf("peimage tests\n");
  std::printf("real image export expectations are taken from the PE export table,\n");
  std::printf("cross-checked against the independent pefile implementation\n\n");

  RunRealImageTests(ExpectedOlderWin32u);
  RunRealImageTests(ExpectedNewerWin32u);

  RunSyntheticPe32PlusTests();
  RunSyntheticPe32Tests();
  RunCodeViewRawPointerFallbackTest();
  RunSectionNameTests();
  RunMalformedTests();
  RunReuseTests();

  std::printf("\n%d checks run, %d failed, %d suites skipped\n", ChecksRun, ChecksFailed,
              SuitesSkipped);
  return ChecksFailed == 0 ? 0 : 1;
}
