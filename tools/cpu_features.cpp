#include <intrin.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

namespace {

struct CpuidResult {
  int Eax = 0;
  int Ebx = 0;
  int Ecx = 0;
  int Edx = 0;
};

CpuidResult Cpuid(int Leaf, int Subleaf) {
  CpuidResult Result;
  int Registers[4] = {0, 0, 0, 0};
  __cpuidex(Registers, Leaf, Subleaf);
  Result.Eax = Registers[0];
  Result.Ebx = Registers[1];
  Result.Ecx = Registers[2];
  Result.Edx = Registers[3];
  return Result;
}

std::string VendorString() {
  const CpuidResult Leaf0 = Cpuid(0, 0);
  char Buffer[13] = {0};
  std::memcpy(Buffer + 0, &Leaf0.Ebx, 4);
  std::memcpy(Buffer + 4, &Leaf0.Edx, 4);
  std::memcpy(Buffer + 8, &Leaf0.Ecx, 4);
  return std::string(Buffer);
}

std::string BrandString() {
  char Buffer[49] = {0};
  for (int Index = 0; Index < 3; ++Index) {
    const CpuidResult Leaf = Cpuid(0x80000002 + Index, 0);
    std::memcpy(Buffer + Index * 16 + 0, &Leaf.Eax, 4);
    std::memcpy(Buffer + Index * 16 + 4, &Leaf.Ebx, 4);
    std::memcpy(Buffer + Index * 16 + 8, &Leaf.Ecx, 4);
    std::memcpy(Buffer + Index * 16 + 12, &Leaf.Edx, 4);
  }
  std::string Result(Buffer);
  size_t Start = Result.find_first_not_of(' ');
  return Start == std::string::npos ? Result : Result.substr(Start);
}

bool HasBit(int Value, int Bit) {
  return (Value & (1 << Bit)) != 0;
}

void Report(const char* Name, bool Present) {
  std::printf("  %-24s %s\n", Name, Present ? "yes" : "no");
}

}

int main() {
  std::printf("vendor     : %s\n", VendorString().c_str());
  std::printf("brand      : %s\n", BrandString().c_str());
  std::printf("hw threads : %u\n\n", std::thread::hardware_concurrency());

  const CpuidResult Leaf1 = Cpuid(1, 0);
  const bool Osxsave = HasBit(Leaf1.Ecx, 27);
  const bool AvxCpu = HasBit(Leaf1.Ecx, 28);

  unsigned long long Xcr0 = 0;
  if (Osxsave) {
    Xcr0 = _xgetbv(0);
  }
  const bool OsYmm = (Xcr0 & 0x6ull) == 0x6ull;
  const bool OsZmm = (Xcr0 & 0xE6ull) == 0xE6ull;

  const CpuidResult Leaf7 = Cpuid(7, 0);

  std::printf("os support:\n");
  Report("XSAVE (osxsave)", Osxsave);
  Report("OS enables YMM (AVX)", Osxsave && OsYmm);
  Report("OS enables ZMM (AVX512)", Osxsave && OsZmm);

  std::printf("\nisa:\n");
  Report("SSE4.2", HasBit(Leaf1.Ecx, 20));
  Report("AVX", AvxCpu && Osxsave && OsYmm);
  Report("AVX2", HasBit(Leaf7.Ebx, 5) && Osxsave && OsYmm);
  Report("AVX512F", HasBit(Leaf7.Ebx, 16) && Osxsave && OsZmm);
  Report("AVX512BW", HasBit(Leaf7.Ebx, 30) && Osxsave && OsZmm);
  Report("AVX512VL", HasBit(Leaf7.Ebx, 31) && Osxsave && OsZmm);
  Report("AVX512DQ", HasBit(Leaf7.Ebx, 17) && Osxsave && OsZmm);
  Report("AVX512CD", HasBit(Leaf7.Ebx, 28) && Osxsave && OsZmm);
  Report("AVX512_VBMI", HasBit(Leaf7.Ecx, 1) && Osxsave && OsZmm);
  Report("AVX512_VBMI2", HasBit(Leaf7.Ecx, 6) && Osxsave && OsZmm);
  Report("AVX512_VNNI", HasBit(Leaf7.Ecx, 11) && Osxsave && OsZmm);
  Report("AVX512_VPOPCNTDQ", HasBit(Leaf7.Ecx, 14) && Osxsave && OsZmm);
  Report("AVX512_BF16", HasBit(Leaf7.Edx, 5) && Osxsave && OsZmm);
  Report("BMI1", HasBit(Leaf7.Ebx, 3));
  Report("BMI2", HasBit(Leaf7.Ebx, 8));
  Report("POPCNT", HasBit(Leaf1.Ecx, 23));

  std::printf("\ncache (deterministic parameters):\n");
  const std::string Vendor = VendorString();
  const int CacheLeaf = Vendor == "AuthenticAMD" ? 0x8000001D : 4;

  for (int Index = 0; Index < 16; ++Index) {
    const CpuidResult Leaf = Cpuid(CacheLeaf, Index);
    const uint32_t Type = static_cast<uint32_t>(Leaf.Eax) & 0x1Fu;
    if (Type == 0) {
      break;
    }
    const uint32_t Level = (static_cast<uint32_t>(Leaf.Eax) >> 5) & 0x7u;
    const uint32_t LineSize = (static_cast<uint32_t>(Leaf.Ebx) & 0xFFFu) + 1;
    const uint32_t Partitions = ((static_cast<uint32_t>(Leaf.Ebx) >> 12) & 0x3FFu) + 1;
    const uint32_t Ways = ((static_cast<uint32_t>(Leaf.Ebx) >> 22) & 0x3FFu) + 1;
    const uint32_t Sets = static_cast<uint32_t>(Leaf.Ecx) + 1;
    const uint32_t SharedBy = static_cast<uint32_t>(Leaf.Eax) >> 14 & 0xFFFu;
    const uint64_t SizeKb =
        static_cast<uint64_t>(Ways) * Partitions * LineSize * Sets / 1024u;
    const char* Kind = Type == 1 ? "data" : (Type == 2 ? "instruction" : "unified");
    std::printf("  L%u %-12s : %5llu KB, line %u B, %u-way, shared by %u thread(s)\n", Level, Kind,
                static_cast<unsigned long long>(SizeKb), LineSize, Ways, SharedBy + 1);
  }

  return 0;
}
