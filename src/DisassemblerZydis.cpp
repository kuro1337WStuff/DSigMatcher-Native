#include "dsigmatcher/Disassembler.h"

#include <Zydis/Zydis.h>

namespace DSig {

namespace {

DecodeStatus MapStatus(ZyanStatus Status) {
  if (Status == ZYDIS_STATUS_NO_MORE_DATA) {
    return DecodeStatus::NoMoreData;
  }
  if (Status == ZYDIS_STATUS_DECODING_ERROR) {
    return DecodeStatus::DecodingError;
  }
  if (Status == ZYDIS_STATUS_INSTRUCTION_TOO_LONG) {
    return DecodeStatus::InstructionTooLong;
  }
  if (Status == ZYDIS_STATUS_BAD_REGISTER) {
    return DecodeStatus::BadRegister;
  }
  return DecodeStatus::OtherError;
}

OperandInfo MapOperand(const ZydisDecodedOperand& Operand) {
  OperandInfo Info;

  switch (Operand.type) {
  case ZYDIS_OPERAND_TYPE_REGISTER:
    Info.Kind = OperandKind::Register;
    break;
  case ZYDIS_OPERAND_TYPE_MEMORY:
    Info.Kind = OperandKind::Memory;
    Info.HasDisplacement = Operand.mem.disp.has_displacement != ZYAN_FALSE;
    Info.Displacement = Operand.mem.disp.value;
    Info.BaseRegister = static_cast<uint16_t>(Operand.mem.base);
    Info.IndexRegister = static_cast<uint16_t>(Operand.mem.index);
    Info.Scale = Operand.mem.scale;
    break;
  case ZYDIS_OPERAND_TYPE_IMMEDIATE:
    Info.Kind = OperandKind::Immediate;
    Info.Immediate = Operand.imm.is_signed ? static_cast<int64_t>(Operand.imm.value.s)
                                           : static_cast<int64_t>(Operand.imm.value.u);
    Info.ImmediateIsRelative = Operand.imm.is_relative != ZYAN_FALSE;
    break;
  case ZYDIS_OPERAND_TYPE_POINTER:
    Info.Kind = OperandKind::Pointer;
    break;
  default:
    break;
  }

  return Info;
}

class ZydisBackend final : public DisassemblerBackend {
public:
  ZydisBackend() {
    ZydisDecoderInit(&Decoder_, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
  }

  DecodeStatus DecodeRange(const uint8_t* Code, size_t Length, uint64_t,
                           std::vector<InstructionInfo>& Out) override {
    if (Code == nullptr || Length == 0) {
      return DecodeStatus::Success;
    }

    size_t Offset = 0;
    while (Offset < Length) {
      ZydisDecodedInstruction Instruction;
      ZydisDecodedOperand Operands[ZYDIS_MAX_OPERAND_COUNT];

      const ZyanStatus Status = ZydisDecoderDecodeFull(&Decoder_, Code + Offset, Length - Offset,
                                                       &Instruction, Operands);
      if (!ZYAN_SUCCESS(Status)) {
        return MapStatus(Status);
      }
      if (Instruction.length == 0) {
        return DecodeStatus::OtherError;
      }

      InstructionInfo Info;
      Info.Offset = static_cast<uint32_t>(Offset);
      Info.Length = Instruction.length;
      Info.Mnemonic = static_cast<uint16_t>(Instruction.mnemonic);
      Info.OperandCount = Instruction.operand_count_visible < MaxVisibleOperands
                              ? Instruction.operand_count_visible
                              : static_cast<ZyanU8>(MaxVisibleOperands);

      for (uint8_t Index = 0; Index < Info.OperandCount; ++Index) {
        Info.Operands[Index] = MapOperand(Operands[Index]);
      }

      Out.push_back(Info);
      Offset += Instruction.length;
    }

    return DecodeStatus::Success;
  }

  std::string_view MnemonicName(uint16_t Mnemonic) const override {
    const char* Text = ZydisMnemonicGetString(static_cast<ZydisMnemonic>(Mnemonic));
    if (Text == nullptr) {
      return std::string_view();
    }
    return std::string_view(Text);
  }

  const char* BackendName() const override { return "zydis"; }

private:
  ZydisDecoder Decoder_;
};

}

std::unique_ptr<DisassemblerBackend> CreateX64Disassembler() {
  return std::make_unique<ZydisBackend>();
}

const char* DecodeStatusName(DecodeStatus Status) {
  switch (Status) {
  case DecodeStatus::Success:
    return "success";
  case DecodeStatus::NoMoreData:
    return "no-more-data";
  case DecodeStatus::DecodingError:
    return "decoding-error";
  case DecodeStatus::InstructionTooLong:
    return "instruction-too-long";
  case DecodeStatus::BadRegister:
    return "bad-register";
  case DecodeStatus::OtherError:
    return "other-error";
  }
  return "unknown";
}

}
