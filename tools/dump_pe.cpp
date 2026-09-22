#include <cstdio>
#include <string>

#include "dsigmatcher/PeImage.h"

int main(int Argc, char** Argv) {
  if (Argc < 2) {
    std::fprintf(stderr, "usage: dump_pe <file.pe>\n");
    return 1;
  }

  DSig::PeImage Image;
  const DSig::PeLoadResult Result = Image.Load(Argv[1]);
  if (!Result.Ok) {
    std::fprintf(stderr, "load failed: %s\n", Result.Error.c_str());
    return 2;
  }

  const DSig::PeHeaders& Headers = Image.Headers;

  std::printf("#HEADERS\n");
  std::printf("machine %u\n", Headers.Machine);
  std::printf("number_of_sections %u\n", Headers.NumberOfSections);
  std::printf("timedatestamp %u\n", Headers.TimeDateStamp);
  std::printf("characteristics %u\n", Headers.Characteristics);
  std::printf("optional_magic %u\n", Headers.OptionalMagic);
  std::printf("is_pe32_plus %d\n", Headers.IsPe32Plus ? 1 : 0);
  std::printf("size_of_code %u\n", Headers.SizeOfCode);
  std::printf("address_of_entry_point %u\n", Headers.AddressOfEntryPoint);
  std::printf("base_of_code %u\n", Headers.BaseOfCode);
  std::printf("image_base %llu\n", static_cast<unsigned long long>(Headers.ImageBase));
  std::printf("section_alignment %u\n", Headers.SectionAlignment);
  std::printf("file_alignment %u\n", Headers.FileAlignment);
  std::printf("subsystem %u\n", Headers.Subsystem);
  std::printf("dll_characteristics %u\n", Headers.DllCharacteristics);
  std::printf("size_of_image %u\n", Headers.SizeOfImage);
  std::printf("size_of_headers %u\n", Headers.SizeOfHeaders);
  std::printf("checksum %u\n", Headers.CheckSum);
  std::printf("declared_data_directories %u\n", Headers.DeclaredDataDirectories);
  std::printf("is_dll %d\n", Headers.IsDll() ? 1 : 0);
  std::printf("buffer_size %zu\n", Image.BufferSize());

  std::printf("#SECTIONS\n");
  for (const DSig::PeSection& Section : Image.Sections) {
    std::printf("%.*s %u %u %u %u %u %u %u\n",
                static_cast<int>(Section.Name.size()), Section.Name.data(), Section.VirtualAddress,
                Section.VirtualSize, Section.PointerToRawData, Section.SizeOfRawData,
                Section.NumberOfRelocations, Section.NumberOfLinenumbers,
                Section.Characteristics);
  }

  std::printf("#EXPORTDIR\n");
  const DSig::PeExportDirectoryInfo& Directory = Image.ExportDirectory;
  std::printf("present %d\n", Directory.Present ? 1 : 0);
  std::printf("ordinal_base %u\n", Directory.OrdinalBase);
  std::printf("number_of_functions %u\n", Directory.NumberOfFunctions);
  std::printf("number_of_names %u\n", Directory.NumberOfNames);
  std::printf("named_export_count %u\n", Directory.NamedExportCount);
  std::printf("unnamed_export_count %u\n", Directory.UnnamedExportCount);
  std::printf("forwarder_count %u\n", Directory.ForwarderCount);
  std::printf("distinct_address_count %u\n", Directory.DistinctAddressCount);
  std::printf("rva %u\n", Directory.Rva);
  std::printf("size %u\n", Directory.Size);

  std::printf("#EXPORTS\n");
  for (const DSig::PeExport& Export : Image.Exports) {
    std::printf("%u %u %d %d %.*s\n", Export.Ordinal, Export.Rva, Export.IsNamed ? 1 : 0,
                Export.IsForwarder ? 1 : 0, static_cast<int>(Export.Name.size()),
                Export.Name.data());
  }

  std::printf("#CODEVIEW\n");
  std::printf("present %d\n", Image.CodeView.Present ? 1 : 0);
  std::printf("guid %s\n", Image.CodeView.Guid.c_str());
  std::printf("age %u\n", Image.CodeView.Age);
  std::printf("pdb_name %s\n", Image.CodeView.PdbName.c_str());
  std::printf("symbol_key %s\n", Image.CodeView.SymbolKey.c_str());
  std::printf("debug_entries %zu\n", Image.DebugEntries.size());

  std::printf("#RVAMAP\n");
  uint32_t Offset = 0;
  bool Mapped = Image.RvaToOffset(Headers.AddressOfEntryPoint, Offset);
  std::printf("entry_rva_to_offset %d %u\n", Mapped ? 1 : 0, Offset);

  for (const DSig::PeExport& Export : Image.Exports) {
    uint32_t ExportOffset = 0;
    const bool Ok = Image.RvaToOffset(Export.Rva, ExportOffset);
    uint32_t RoundTripRva = 0;
    const bool Back = Ok && Image.OffsetToRva(ExportOffset, RoundTripRva);
    if (!Ok || !Back || RoundTripRva != Export.Rva) {
      std::printf("rva_roundtrip_failure %u %d %d %u\n", Export.Rva, Ok ? 1 : 0, Back ? 1 : 0,
                  RoundTripRva);
    }
  }
  std::printf("#END\n");

  return 0;
}
