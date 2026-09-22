#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string_view>
#include <vector>

namespace DSig {

enum class DecodeStatus : uint8_t {
  Success = 0,
  NoMoreData,
  DecodingError,
  InstructionTooLong,
  BadRegister,
  OtherError
};

enum class OperandKind : uint8_t {
  Unused = 0,
  Register,
  Memory,
  Immediate,
  Pointer
};

struct OperandInfo {
  OperandKind Kind = OperandKind::Unused;
  int64_t Immediate = 0;
  bool ImmediateIsRelative = false;
  int64_t Displacement = 0;
  bool HasDisplacement = false;
  uint16_t BaseRegister = 0;
  uint16_t IndexRegister = 0;
  uint8_t Scale = 0;
};

constexpr size_t MaxVisibleOperands = 5;

struct InstructionInfo {
  uint32_t Offset = 0;
  uint8_t Length = 0;
  uint16_t Mnemonic = 0;
  uint8_t OperandCount = 0;
  OperandInfo Operands[MaxVisibleOperands];
};

class DisassemblerBackend {
public:
  virtual ~DisassemblerBackend() = default;

  virtual DecodeStatus DecodeRange(const uint8_t* Code, size_t Length, uint64_t RuntimeAddress,
                                   std::vector<InstructionInfo>& Out) = 0;
  virtual std::string_view MnemonicName(uint16_t Mnemonic) const = 0;
  virtual const char* BackendName() const = 0;
};

std::unique_ptr<DisassemblerBackend> CreateX64Disassembler();

const char* DecodeStatusName(DecodeStatus Status);

}
