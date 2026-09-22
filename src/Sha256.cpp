#include "dsigmatcher/Sha256.h"

#include <cstdio>
#include <fstream>
#include <vector>

namespace DSig {

namespace {

const uint32_t RoundConstants[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u,
    0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu,
    0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu,
    0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u,
    0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u,
    0xc67178f2u};

uint32_t RotateRight(uint32_t Value, unsigned Bits) {
  return (Value >> Bits) | (Value << (32u - Bits));
}

}

Sha256::Sha256() : State_{}, BitCount_(0), Buffer_{}, BufferLength_(0) {
  State_[0] = 0x6a09e667u;
  State_[1] = 0xbb67ae85u;
  State_[2] = 0x3c6ef372u;
  State_[3] = 0xa54ff53au;
  State_[4] = 0x510e527fu;
  State_[5] = 0x9b05688cu;
  State_[6] = 0x1f83d9abu;
  State_[7] = 0x5be0cd19u;
}

void Sha256::Transform(const uint8_t* Block) {
  uint32_t Schedule[64];
  for (int Index = 0; Index < 16; ++Index) {
    Schedule[Index] = (static_cast<uint32_t>(Block[Index * 4]) << 24) |
                      (static_cast<uint32_t>(Block[Index * 4 + 1]) << 16) |
                      (static_cast<uint32_t>(Block[Index * 4 + 2]) << 8) |
                      static_cast<uint32_t>(Block[Index * 4 + 3]);
  }
  for (int Index = 16; Index < 64; ++Index) {
    const uint32_t Previous = Schedule[Index - 15];
    const uint32_t Older = Schedule[Index - 2];
    const uint32_t Sigma0 = RotateRight(Previous, 7) ^ RotateRight(Previous, 18) ^ (Previous >> 3);
    const uint32_t Sigma1 = RotateRight(Older, 17) ^ RotateRight(Older, 19) ^ (Older >> 10);
    Schedule[Index] = Schedule[Index - 16] + Sigma0 + Schedule[Index - 7] + Sigma1;
  }

  uint32_t Working[8];
  for (int Index = 0; Index < 8; ++Index) {
    Working[Index] = State_[Index];
  }

  for (int Index = 0; Index < 64; ++Index) {
    const uint32_t BigSigma1 =
        RotateRight(Working[4], 6) ^ RotateRight(Working[4], 11) ^ RotateRight(Working[4], 25);
    const uint32_t Choose =
        (Working[4] & Working[5]) ^ (~Working[4] & Working[6]);
    const uint32_t Temporary1 =
        Working[7] + BigSigma1 + Choose + RoundConstants[Index] + Schedule[Index];
    const uint32_t BigSigma0 =
        RotateRight(Working[0], 2) ^ RotateRight(Working[0], 13) ^ RotateRight(Working[0], 22);
    const uint32_t Majority = (Working[0] & Working[1]) ^ (Working[0] & Working[2]) ^
                              (Working[1] & Working[2]);
    const uint32_t Temporary2 = BigSigma0 + Majority;

    const uint32_t OldD = Working[3];
    for (int Slot = 7; Slot > 0; --Slot) {
      Working[Slot] = Working[Slot - 1];
    }
    Working[4] = OldD + Temporary1;
    Working[0] = Temporary1 + Temporary2;
  }

  for (int Index = 0; Index < 8; ++Index) {
    State_[Index] += Working[Index];
  }
}

void Sha256::Update(const void* Data, size_t Length) {
  const uint8_t* Cursor = static_cast<const uint8_t*>(Data);
  BitCount_ += static_cast<uint64_t>(Length) * 8u;

  while (Length > 0) {
    const size_t Space = sizeof(Buffer_) - BufferLength_;
    const size_t Chunk = Length < Space ? Length : Space;
    for (size_t Index = 0; Index < Chunk; ++Index) {
      Buffer_[BufferLength_ + Index] = Cursor[Index];
    }
    BufferLength_ += Chunk;
    Cursor += Chunk;
    Length -= Chunk;

    if (BufferLength_ == sizeof(Buffer_)) {
      Transform(Buffer_);
      BufferLength_ = 0;
    }
  }
}

void Sha256::Update(std::string_view Text) {
  Update(Text.data(), Text.size());
}

std::string Sha256::Hex(const void* Data, size_t Length) {
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

std::string Sha256::FinishHex() {
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
    Tail[Index] = static_cast<uint8_t>((Bits >> (56 - Index * 8)) & 0xFFu);
  }
  Update(Tail, sizeof(Tail));
  BitCount_ = Bits;

  uint8_t Digest[32];
  for (int Index = 0; Index < 8; ++Index) {
    Digest[Index * 4] = static_cast<uint8_t>(State_[Index] >> 24);
    Digest[Index * 4 + 1] = static_cast<uint8_t>(State_[Index] >> 16);
    Digest[Index * 4 + 2] = static_cast<uint8_t>(State_[Index] >> 8);
    Digest[Index * 4 + 3] = static_cast<uint8_t>(State_[Index]);
  }

  return Hex(Digest, sizeof(Digest));
}

std::string Sha256::FileHex(const std::string& Path, bool& OutOk) {
  OutOk = false;

  std::ifstream Stream(Path, std::ios::binary);
  if (!Stream.is_open()) {
    return std::string();
  }

  Sha256 Hasher;
  std::vector<char> Buffer(1024 * 1024);
  while (Stream) {
    Stream.read(Buffer.data(), static_cast<std::streamsize>(Buffer.size()));
    const std::streamsize Got = Stream.gcount();
    if (Got > 0) {
      Hasher.Update(Buffer.data(), static_cast<size_t>(Got));
    }
  }

  if (!Stream.eof() && Stream.fail()) {
    return std::string();
  }

  OutOk = true;
  return Hasher.FinishHex();
}

}
