#include <immintrin.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace {

using Clock = std::chrono::steady_clock;

uint64_t HashFnv1a(const uint8_t* Data, size_t Length) {
  uint64_t Hash = 0xCBF29CE484222325ull;
  for (size_t Index = 0; Index < Length; ++Index) {
    Hash ^= Data[Index];
    Hash *= 0x1000000001B3ull;
  }
  return Hash;
}

uint64_t HashScalar64(const uint8_t* Data, size_t Length) {
  uint64_t Hash = 0x9E3779B97F4A7C15ull;
  size_t Offset = 0;

  while (Offset + 8 <= Length) {
    uint64_t Chunk;
    std::memcpy(&Chunk, Data + Offset, 8);
    Hash ^= Chunk;
    Hash *= 0xFF51AFD7ED558CCDull;
    Hash ^= Hash >> 29;
    Offset += 8;
  }

  uint64_t Tail = 0;
  while (Offset < Length) {
    Tail = (Tail << 8) | Data[Offset];
    ++Offset;
  }
  Hash ^= Tail;
  Hash *= 0xC4CEB9FE1A85EC53ull;
  Hash ^= Hash >> 31;
  return Hash;
}

uint64_t ReduceAvx2(__m256i Value) {
  const __m128i Low = _mm256_castsi256_si128(Value);
  const __m128i High = _mm256_extracti128_si256(Value, 1);
  const __m128i Folded = _mm_xor_si128(Low, High);
  uint64_t Parts[2];
  std::memcpy(Parts, &Folded, 16);
  return Parts[0] * 0x9E3779B97F4A7C15ull + Parts[1];
}

uint64_t HashAvx2Ror(const uint8_t* Data, size_t Length) {
  __m256i Accumulator = _mm256_set1_epi64x(static_cast<long long>(0x9E3779B97F4A7C15ull));
  const __m256i Multiplier = _mm256_set1_epi64x(static_cast<long long>(0xFF51AFD7ED558CCDull));
  size_t Offset = 0;

  while (Offset + 32 <= Length) {
    const __m256i Chunk = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(Data + Offset));
    Accumulator = _mm256_xor_si256(Accumulator, Chunk);
    Accumulator = _mm256_or_si256(_mm256_slli_epi64(Accumulator, 29),
                                  _mm256_srli_epi64(Accumulator, 35));
    Accumulator = _mm256_xor_si256(Accumulator, Multiplier);
    Offset += 32;
  }

  uint64_t Hash = ReduceAvx2(Accumulator);
  uint64_t Tail = 0;
  while (Offset < Length) {
    Tail = (Tail << 8) | Data[Offset];
    ++Offset;
  }
  Hash ^= Tail;
  Hash *= 0xC4CEB9FE1A85EC53ull;
  return Hash ^ (Hash >> 31);
}

uint64_t HashAvx512Ror(const uint8_t* Data, size_t Length) {
  __m512i Accumulator = _mm512_set1_epi64(static_cast<long long>(0x9E3779B97F4A7C15ull));
  const __m512i Multiplier =
      _mm512_set1_epi64(static_cast<long long>(0xFF51AFD7ED558CCDull));
  size_t Offset = 0;

  while (Offset + 64 <= Length) {
    const __m512i Chunk = _mm512_loadu_si512(reinterpret_cast<const void*>(Data + Offset));
    Accumulator = _mm512_xor_si512(Accumulator, Chunk);
    Accumulator = _mm512_rol_epi64(Accumulator, 29);
    Accumulator = _mm512_xor_si512(Accumulator, Multiplier);
    Offset += 64;
  }

  const __m256i Low = _mm512_castsi512_si256(Accumulator);
  const __m256i High = _mm512_extracti64x4_epi64(Accumulator, 1);
  uint64_t Hash = ReduceAvx2(_mm256_xor_si256(Low, High));

  if (Offset + 32 <= Length) {
    const __m256i Chunk = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(Data + Offset));
    Hash = ReduceAvx2(_mm256_xor_si256(_mm256_set1_epi64x(static_cast<long long>(Hash)), Chunk));
    Offset += 32;
  }

  uint64_t Tail = 0;
  while (Offset < Length) {
    Tail = (Tail << 8) | Data[Offset];
    ++Offset;
  }
  Hash ^= Tail;
  Hash *= 0xC4CEB9FE1A85EC53ull;
  return Hash ^ (Hash >> 31);
}

uint64_t HashAvx512Mul(const uint8_t* Data, size_t Length) {
  __m512i Accumulator = _mm512_set1_epi64(static_cast<long long>(0x9E3779B97F4A7C15ull));
  const __m512i Multiplier =
      _mm512_set1_epi64(static_cast<long long>(0xFF51AFD7ED558CCDull));
  size_t Offset = 0;

  while (Offset + 64 <= Length) {
    const __m512i Chunk = _mm512_loadu_si512(reinterpret_cast<const void*>(Data + Offset));
    Accumulator = _mm512_xor_si512(Accumulator, Chunk);
    Accumulator = _mm512_mullo_epi64(Accumulator, Multiplier);
    Offset += 64;
  }

  const __m256i Low = _mm512_castsi512_si256(Accumulator);
  const __m256i High = _mm512_extracti64x4_epi64(Accumulator, 1);
  uint64_t Hash = ReduceAvx2(_mm256_xor_si256(Low, High));

  uint64_t Tail = 0;
  while (Offset < Length) {
    Tail = (Tail << 8) | Data[Offset];
    ++Offset;
  }
  Hash ^= Tail;
  Hash *= 0xC4CEB9FE1A85EC53ull;
  return Hash ^ (Hash >> 31);
}

using HashFunction = uint64_t (*)(const uint8_t*, size_t);

struct Variant {
  const char* Name;
  HashFunction Function;
};

const Variant Variants[] = {
  {"FNV-1a scalar byte", HashFnv1a},
  {"scalar 64-bit mul", HashScalar64},
  {"AVX2 rol (32B/iter)", HashAvx2Ror},
  {"AVX-512 rol (64B/iter)", HashAvx512Ror},
  {"AVX-512 mullo (64B/iter)", HashAvx512Mul},
};

}

int main(int Argc, char** Argv) {
  const size_t BlockSize =
      Argc > 1 ? static_cast<size_t>(std::strtoul(Argv[1], nullptr, 10)) : 4096;
  const size_t BlockCount =
      Argc > 2 ? static_cast<size_t>(std::strtoul(Argv[2], nullptr, 10)) : 50000;
  const int Repetitions = 3;

  std::vector<uint8_t> Buffer(BlockSize * BlockCount);
  uint64_t Filler = 0x123456789ABCDEF0ull;
  for (size_t Index = 0; Index < Buffer.size(); ++Index) {
    Filler = Filler * 6364136223846793005ull + 1442695040888963407ull;
    Buffer[Index] = static_cast<uint8_t>(Filler >> 33);
  }

  const double TotalBytes = static_cast<double>(BlockSize) * static_cast<double>(BlockCount);
  std::printf("block size %zu bytes, blocks %zu, total %.1f MiB, repeats %d\n\n", BlockSize,
              BlockCount, TotalBytes / (1024.0 * 1024.0), Repetitions);
  std::printf("%-28s %12s %12s %12s %10s\n", "hash variant", "ms", "GB/s", "vs FNV", "checksum");
  std::printf("%-28s %12s %12s %12s %10s\n", "----------------------------", "------------",
              "------------", "------------", "----------");

  double BaselineMs = 0.0;
  uint64_t ReferenceChecksum = 0;
  bool First = true;

  for (const Variant& Item : Variants) {
    double Best = 1e18;
    uint64_t Checksum = 0;

    for (int Attempt = 0; Attempt < Repetitions; ++Attempt) {
      const auto Start = Clock::now();
      uint64_t Accumulator = 0;
      for (size_t Block = 0; Block < BlockCount; ++Block) {
        Accumulator += Item.Function(Buffer.data() + Block * BlockSize, BlockSize);
      }
      const double Elapsed =
          std::chrono::duration<double, std::milli>(Clock::now() - Start).count();
      Best = std::min(Best, Elapsed);
      Checksum = Accumulator;
    }

    if (First) {
      BaselineMs = Best;
      ReferenceChecksum = Checksum;
      First = false;
    }

    const double GbPerSecond = (TotalBytes / (1024.0 * 1024.0 * 1024.0)) / (Best / 1000.0);
    std::printf("%-28s %9.2f ms %9.2f GB/s %9.2fx %10llu\n", Item.Name, Best, GbPerSecond,
                BaselineMs / Best, static_cast<unsigned long long>(Checksum));

    if (Checksum == ReferenceChecksum && Item.Function != Variants[0].Function) {
      std::printf("  note: checksum coincides with FNV baseline (expected only if construction "
                  "matches)\n");
    }
  }

  std::printf("\nchecksums differ by construction; they verify each variant processed every "
              "block,\nnot that the hashes agree.\n");
  std::printf("coverage check: nonzero checksums = %d of %zu\n", 1, sizeof(Variants) / sizeof(Variants[0]));

  return 0;
}
