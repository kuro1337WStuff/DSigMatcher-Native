#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "dsigmatcher/Disassembler.h"

namespace {

using namespace DSig;

int ChecksRun = 0;
int ChecksFailed = 0;

void Report(bool Ok, const char* Expression, const char* File, int Line) {
  ++ChecksRun;
  if (!Ok) {
    ++ChecksFailed;
    std::printf("  FAIL %s:%d  %s\n", File, Line, Expression);
  }
}

void Suite(const char* Name) {
  std::printf("[%s]\n", Name);
}

#define CHECK(Expr) Report(static_cast<bool>(Expr), #Expr, __FILE__, __LINE__)
#define CHECK_EQ(A, B) Report((A) == (B), #A " == " #B, __FILE__, __LINE__)

std::vector<uint8_t> Bytes(std::initializer_list<int> Values) {
  std::vector<uint8_t> Result;
  Result.reserve(Values.size());
  for (const int Value : Values) {
    Result.push_back(static_cast<uint8_t>(Value));
  }
  return Result;
}

bool FindMemoryOperand(const InstructionInfo& Info, int64_t& OutDisplacement) {
  for (uint8_t Index = 0; Index < Info.OperandCount; ++Index) {
    if (Info.Operands[Index].Kind == OperandKind::Memory) {
      OutDisplacement = Info.Operands[Index].Displacement;
      return true;
    }
  }
  return false;
}

void TestBackendBasics() {
  Suite("Disassembler backend");

  const std::unique_ptr<DisassemblerBackend> Backend = CreateX64Disassembler();
  CHECK(Backend != nullptr);
  CHECK_EQ(std::string(Backend->BackendName()), std::string("zydis"));

  const std::vector<uint8_t> Ret = Bytes({0xC3});
  std::vector<InstructionInfo> Decoded;
  const DecodeStatus Status = Backend->DecodeRange(Ret.data(), Ret.size(), 0x140001000ull, Decoded);

  CHECK(Status == DecodeStatus::Success);
  CHECK_EQ(Decoded.size(), static_cast<size_t>(1));
  CHECK_EQ(static_cast<int>(Decoded[0].Length), 1);
  CHECK_EQ(std::string(Backend->MnemonicName(Decoded[0].Mnemonic)), std::string("ret"));
  CHECK_EQ(static_cast<int>(Decoded[0].OperandCount), 0);
}

void TestDisplacementExtraction() {
  Suite("Memory displacement extraction");

  const std::unique_ptr<DisassemblerBackend> Backend = CreateX64Disassembler();

  const std::vector<uint8_t> Getter = Bytes({0x48, 0x8B, 0x41, 0x48});
  std::vector<InstructionInfo> Decoded;
  const DecodeStatus Status =
      Backend->DecodeRange(Getter.data(), Getter.size(), 0x140001000ull, Decoded);

  CHECK(Status == DecodeStatus::Success);
  CHECK_EQ(Decoded.size(), static_cast<size_t>(1));
  CHECK_EQ(std::string(Backend->MnemonicName(Decoded[0].Mnemonic)), std::string("mov"));
  CHECK_EQ(static_cast<int>(Decoded[0].Length), 4);
  CHECK_EQ(static_cast<int>(Decoded[0].OperandCount), 2);
  CHECK(Decoded[0].Operands[0].Kind == OperandKind::Register);
  CHECK(Decoded[0].Operands[1].Kind == OperandKind::Memory);

  int64_t Displacement = 0;
  CHECK(FindMemoryOperand(Decoded[0], Displacement));
  CHECK_EQ(Displacement, static_cast<int64_t>(0x48));
  CHECK(Decoded[0].Operands[1].HasDisplacement);

  const std::vector<uint8_t> StoreRsp = Bytes({0x48, 0x89, 0x5C, 0x24, 0x08});
  std::vector<InstructionInfo> StoreDecoded;
  CHECK(Backend->DecodeRange(StoreRsp.data(), StoreRsp.size(), 0, StoreDecoded) ==
        DecodeStatus::Success);
  CHECK_EQ(StoreDecoded.size(), static_cast<size_t>(1));
  CHECK_EQ(static_cast<int>(StoreDecoded[0].Length), 5);

  int64_t StoreDisplacement = 0;
  CHECK(FindMemoryOperand(StoreDecoded[0], StoreDisplacement));
  CHECK_EQ(StoreDisplacement, static_cast<int64_t>(8));
}

void TestGetterFamilyIsDistinguishedByOffset() {
  Suite("Struct getters: identical shape, distinct offsets");

  const std::unique_ptr<DisassemblerBackend> Backend = CreateX64Disassembler();

  const std::vector<int> Offsets = {0x48, 0x50, 0x58, 0x100 & 0xFF};
  std::vector<int64_t> ObservedDisplacements;
  std::vector<uint8_t> ObservedLengths;
  std::vector<std::string> ObservedMnemonics;

  for (const int Offset : Offsets) {
    const std::vector<uint8_t> Getter = Bytes({0x48, 0x8B, 0x41, Offset});
    std::vector<InstructionInfo> Decoded;
    const DecodeStatus Status =
        Backend->DecodeRange(Getter.data(), Getter.size(), 0, Decoded);
    CHECK(Status == DecodeStatus::Success);
    CHECK_EQ(Decoded.size(), static_cast<size_t>(1));

    int64_t Displacement = -1;
    CHECK(FindMemoryOperand(Decoded[0], Displacement));
    ObservedDisplacements.push_back(Displacement);
    ObservedLengths.push_back(Decoded[0].Length);
    ObservedMnemonics.push_back(std::string(Backend->MnemonicName(Decoded[0].Mnemonic)));
  }

  CHECK_EQ(ObservedLengths.size(), static_cast<size_t>(4));
  for (const uint8_t Length : ObservedLengths) {
    CHECK_EQ(static_cast<int>(Length), 4);
  }
  for (const std::string& Mnemonic : ObservedMnemonics) {
    CHECK_EQ(Mnemonic, std::string("mov"));
  }

  bool AllDistinct = true;
  for (size_t Outer = 0; Outer < ObservedDisplacements.size(); ++Outer) {
    for (size_t Inner = Outer + 1; Inner < ObservedDisplacements.size(); ++Inner) {
      if (ObservedDisplacements[Outer] == ObservedDisplacements[Inner]) {
        AllDistinct = false;
      }
    }
  }
  CHECK(AllDistinct);

  std::printf("  four getters: same mnemonic, same length, displacements ");
  for (const int64_t Value : ObservedDisplacements) {
    std::printf("0x%llx ", static_cast<unsigned long long>(Value));
  }
  std::printf("\n");
}

void TestRelativeImmediate() {
  Suite("Relative call immediate");

  const std::unique_ptr<DisassemblerBackend> Backend = CreateX64Disassembler();

  const std::vector<uint8_t> Call = Bytes({0xE8, 0x10, 0x20, 0x30, 0x40});
  std::vector<InstructionInfo> Decoded;
  CHECK(Backend->DecodeRange(Call.data(), Call.size(), 0, Decoded) == DecodeStatus::Success);
  CHECK_EQ(Decoded.size(), static_cast<size_t>(1));
  CHECK_EQ(std::string(Backend->MnemonicName(Decoded[0].Mnemonic)), std::string("call"));

  bool FoundRelative = false;
  for (uint8_t Index = 0; Index < Decoded[0].OperandCount; ++Index) {
    if (Decoded[0].Operands[Index].Kind == OperandKind::Immediate &&
        Decoded[0].Operands[Index].ImmediateIsRelative) {
      FoundRelative = true;
      CHECK_EQ(Decoded[0].Operands[Index].Immediate, static_cast<int64_t>(0x40302010));
    }
  }
  CHECK(FoundRelative);
}

void TestDecodeFailures() {
  Suite("Truncated and invalid encodings");

  const std::unique_ptr<DisassemblerBackend> Backend = CreateX64Disassembler();

  const std::vector<uint8_t> Truncated = Bytes({0x48, 0x8B});
  std::vector<InstructionInfo> TruncatedOut;
  const DecodeStatus TruncatedStatus =
      Backend->DecodeRange(Truncated.data(), Truncated.size(), 0, TruncatedOut);
  CHECK(TruncatedStatus == DecodeStatus::NoMoreData);
  CHECK_EQ(TruncatedOut.size(), static_cast<size_t>(0));
  std::printf("  truncated      : %s\n", DecodeStatusName(TruncatedStatus));

  const std::vector<uint8_t> Invalid = Bytes({0x06});
  std::vector<InstructionInfo> InvalidOut;
  const DecodeStatus InvalidStatus =
      Backend->DecodeRange(Invalid.data(), Invalid.size(), 0, InvalidOut);
  CHECK(InvalidStatus == DecodeStatus::DecodingError);
  std::printf("  0x06 (push es) : %s\n", DecodeStatusName(InvalidStatus));

  const DecodeStatus NullStatus = Backend->DecodeRange(nullptr, 0, 0, InvalidOut);
  CHECK(NullStatus == DecodeStatus::Success);

  const std::vector<uint8_t> Empty;
  std::vector<InstructionInfo> EmptyOut;
  CHECK(Backend->DecodeRange(Empty.data(), Empty.size(), 0, EmptyOut) == DecodeStatus::Success);
  CHECK_EQ(EmptyOut.size(), static_cast<size_t>(0));
}

void TestLinearWalk() {
  Suite("Linear decode offsets accumulate");

  const std::unique_ptr<DisassemblerBackend> Backend = CreateX64Disassembler();

  const std::vector<uint8_t> Buffer = {0xC3, 0x48, 0x8B, 0x41, 0x48, 0x90, 0xC3};

  std::vector<InstructionInfo> Decoded;
  CHECK(Backend->DecodeRange(Buffer.data(), Buffer.size(), 0x1000, Decoded) ==
        DecodeStatus::Success);
  CHECK_EQ(Decoded.size(), static_cast<size_t>(4));

  const std::vector<uint32_t> ExpectedOffsets = {0, 1, 5, 6};
  const std::vector<uint8_t> ExpectedLengths = {1, 4, 1, 1};
  for (size_t Index = 0; Index < Decoded.size(); ++Index) {
    CHECK_EQ(Decoded[Index].Offset, ExpectedOffsets[Index]);
    CHECK_EQ(static_cast<int>(Decoded[Index].Length), static_cast<int>(ExpectedLengths[Index]));
  }

  uint32_t Covered = 0;
  for (const InstructionInfo& Info : Decoded) {
    Covered += Info.Length;
  }
  CHECK_EQ(Covered, static_cast<uint32_t>(Buffer.size()));

  CHECK_EQ(std::string(Backend->MnemonicName(Decoded[2].Mnemonic)), std::string("nop"));
}

}

int main() {
  TestBackendBasics();
  TestDisplacementExtraction();
  TestGetterFamilyIsDistinguishedByOffset();
  TestRelativeImmediate();
  TestDecodeFailures();
  TestLinearWalk();

  std::printf("\n%d checks, %d failed\n", ChecksRun, ChecksFailed);
  return ChecksFailed == 0 ? 0 : 1;
}
