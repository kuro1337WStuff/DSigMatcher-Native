#include "dsigmatcher/Md5.h"

#include <cstring>

namespace DSig {

namespace {

const uint32_t RoundConstants[64] = {
    0xd76aa478u, 0xe8c7b756u, 0x242070dbu, 0xc1bdceeeu, 0xf57c0fafu, 0x4787c62au, 0xa8304613u,
    0xfd469501u, 0x698098d8u, 0x8b44f7afu, 0xffff5bb1u, 0x895cd7beu, 0x6b901122u, 0xfd987193u,
    0xa679438eu, 0x49b40821u, 0xf61e2562u, 0xc040b340u, 0x265e5a51u, 0xe9b6c7aau, 0xd62f105du,
    0x02441453u, 0xd8a1e681u, 0xe7d3fbc8u, 0x21e1cde6u, 0xc33707d6u, 0xf4d50d87u, 0x455a14edu,
    0xa9e3e905u, 0xfcefa3f8u, 0x676f02d9u, 0x8d2a4c8au, 0xfffa3942u, 0x8771f681u, 0x6d9d6122u,
    0xfde5380cu, 0xa4beea44u, 0x4bdecfa9u, 0xf6bb4b60u, 0xbebfbc70u, 0x289b7ec6u, 0xeaa127fau,
    0xd4ef3085u, 0x04881d05u, 0xd9d4d039u, 0xe6db99e5u, 0x1fa27cf8u, 0xc4ac5665u, 0xf4292244u,
    0x432aff97u, 0xab9423a7u, 0xfc93a039u, 0x655b59c3u, 0x8f0ccc92u, 0xffeff47du, 0x85845dd1u,
    0x6fa87e4fu, 0xfe2ce6e0u, 0xa3014314u, 0x4e0811a1u, 0xf7537e82u, 0xbd3af235u, 0x2ad7d2bbu,
    0xeb86d391u};

const uint32_t RotateAmounts[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9,  14, 20, 5, 9,
    14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

uint32_t RotateLeft(uint32_t Value, uint32_t Bits) {
  return (Value << Bits) | (Value >> (32u - Bits));
}

}

Md5::Md5() : State_{}, BitCount_(0), Buffer_{}, BufferLength_(0) {
  State_[0] = 0x67452301u;
  State_[1] = 0xefcdab89u;
  State_[2] = 0x98badcfeu;
  State_[3] = 0x10325476u;
}

void Md5::Transform(const uint8_t* Block) {
  uint32_t Words[16];
  for (int Index = 0; Index < 16; ++Index) {
    Words[Index] = static_cast<uint32_t>(Block[Index * 4]) |
                   (static_cast<uint32_t>(Block[Index * 4 + 1]) << 8) |
                   (static_cast<uint32_t>(Block[Index * 4 + 2]) << 16) |
                   (static_cast<uint32_t>(Block[Index * 4 + 3]) << 24);
  }

  uint32_t A = State_[0];
  uint32_t B = State_[1];
  uint32_t C = State_[2];
  uint32_t D = State_[3];

  for (int Index = 0; Index < 64; ++Index) {
    uint32_t F = 0;
    int WordIndex = 0;

    if (Index < 16) {
      F = (B & C) | (~B & D);
      WordIndex = Index;
    } else if (Index < 32) {
      F = (D & B) | (~D & C);
      WordIndex = (5 * Index + 1) % 16;
    } else if (Index < 48) {
      F = B ^ C ^ D;
      WordIndex = (3 * Index + 5) % 16;
    } else {
      F = C ^ (B | ~D);
      WordIndex = (7 * Index) % 16;
    }

    F = F + A + RoundConstants[Index] + Words[WordIndex];
    A = D;
    D = C;
    C = B;
    B = B + RotateLeft(F, RotateAmounts[Index]);
  }

  State_[0] += A;
  State_[1] += B;
  State_[2] += C;
  State_[3] += D;
}

void Md5::Update(const void* Data, size_t Length) {
  const uint8_t* Cursor = static_cast<const uint8_t*>(Data);
  BitCount_ += static_cast<uint64_t>(Length) * 8u;

  while (Length > 0) {
    const size_t Space = sizeof(Buffer_) - BufferLength_;
    const size_t Chunk = Length < Space ? Length : Space;
    std::memcpy(Buffer_ + BufferLength_, Cursor, Chunk);
    BufferLength_ += Chunk;
    Cursor += Chunk;
    Length -= Chunk;

    if (BufferLength_ == sizeof(Buffer_)) {
      Transform(Buffer_);
      BufferLength_ = 0;
    }
  }
}

void Md5::Update(std::string_view Text) {
  Update(Text.data(), Text.size());
}

std::string Md5::Hex(const void* Data, size_t Length) {
  static const char Digits[] = "0123456789abcdef";
  const uint8_t* Bytes = static_cast<const uint8_t*>(Data);
  std::string Result;
  Result.resize(Length * 2);
  for (size_t Index = 0; Index < Length; ++Index) {
    Result[Index * 2] = Digits[Bytes[Index] >> 4];
    Result[Index * 2 + 1] = Digits[Bytes[Index] & 0x0Fu];
  }
  return Result;
}

std::string Md5::FinishHex() {
  const uint64_t Bits = BitCount_;

  const uint8_t Marker = 0x80u;
  Update(&Marker, 1);
  BitCount_ = Bits;

  const uint8_t Zero = 0x00u;
  while (BufferLength_ != 56) {
    Update(&Zero, 1);
    BitCount_ = Bits;
  }

  uint8_t Tail[8];
  for (int Index = 0; Index < 8; ++Index) {
    Tail[Index] = static_cast<uint8_t>((Bits >> (Index * 8)) & 0xFFu);
  }
  Update(Tail, sizeof(Tail));
  BitCount_ = Bits;

  uint8_t Digest[16];
  for (int Index = 0; Index < 4; ++Index) {
    Digest[Index * 4] = static_cast<uint8_t>(State_[Index]);
    Digest[Index * 4 + 1] = static_cast<uint8_t>(State_[Index] >> 8);
    Digest[Index * 4 + 2] = static_cast<uint8_t>(State_[Index] >> 16);
    Digest[Index * 4 + 3] = static_cast<uint8_t>(State_[Index] >> 24);
  }

  return Hex(Digest, sizeof(Digest));
}

std::string Md5::OfString(std::string_view Text) {
  Md5 Hasher;
  Hasher.Update(Text);
  return Hasher.FinishHex();
}

}
