#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace DSig {

class Md5 {
public:
  Md5();

  void Update(const void* Data, size_t Length);
  void Update(std::string_view Text);
  std::string FinishHex();

  static std::string Hex(const void* Data, size_t Length);
  static std::string OfString(std::string_view Text);

private:
  void Transform(const uint8_t* Block);

  uint32_t State_[4];
  uint64_t BitCount_;
  uint8_t Buffer_[64];
  size_t BufferLength_;
};

}
