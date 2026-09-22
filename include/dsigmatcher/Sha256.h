#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace DSig {

class Sha256 {
public:
  Sha256();

  void Update(const void* Data, size_t Length);
  void Update(std::string_view Text);
  std::string FinishHex();

  static std::string Hex(const void* Data, size_t Length);
  static std::string FileHex(const std::string& Path, bool& OutOk);

private:
  void Transform(const uint8_t* Block);

  uint32_t State_[8];
  uint64_t BitCount_;
  uint8_t Buffer_[64];
  size_t BufferLength_;
};

}
