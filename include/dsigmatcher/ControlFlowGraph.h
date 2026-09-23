#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "dsigmatcher/Disassembler.h"

namespace DSig {

inline constexpr uint32_t CfgNoBlock = 0xFFFFFFFFu;
inline constexpr int32_t CfgNoTarget = INT32_MIN;
inline constexpr uint32_t CfgDecodeWindowBytes = 512;
inline constexpr uint32_t CfgSuccessorCapacity = 2;
inline constexpr size_t CfgMaxRangeBytes = 512 * 1024;
inline constexpr uint32_t CfgMaxBlocks = 32768;
inline constexpr uint32_t CfgMaxInstructions = 262144;

enum class CfgStatus : uint8_t {
  Ok = 0,
  NullCode,
  EmptyRange,
  RangeTooLarge,
  BackendUnavailable,
  EntryUndecodable,
  BlockLimitReached,
  InstructionLimitReached
};

enum class CfgBlockEnd : uint8_t {
  Fallthrough = 0,
  RangeEnd,
  DirectBranch,
  ConditionalBranch,
  IndirectBranch,
  Return,
  NoReturn,
  DecodeError
};

const char* CfgStatusName(CfgStatus Status);
const char* CfgBlockEndName(CfgBlockEnd End);

struct CfgBlock {
  uint32_t Offset = 0;
  uint32_t Size = 0;
  uint32_t InstructionCount = 0;
  uint32_t FirstSuccessor = 0;
  uint32_t SuccessorCount = 0;
  uint32_t FirstPredecessor = 0;
  uint32_t PredecessorCount = 0;
  CfgBlockEnd End = CfgBlockEnd::Fallthrough;
  int32_t TargetOffset = CfgNoTarget;
  bool TargetOutsideRange = false;
  bool IndirectTargetUnresolved = false;
};

struct ControlFlowGraph {
  CfgStatus Status = CfgStatus::Ok;
  std::string Error;

  std::vector<CfgBlock> Blocks;
  std::vector<uint32_t> SuccessorBlocks;
  std::vector<uint32_t> PredecessorBlocks;
  std::vector<uint32_t> ComponentOfBlock;
  std::vector<uint32_t> ComponentNodeCounts;
  std::vector<uint8_t> ComponentIsLoop;

  uint32_t EntryBlock = CfgNoBlock;
  uint32_t NodeCount = 0;
  uint32_t EdgeCount = 0;
  uint32_t InstructionCount = 0;
  uint32_t DecodedBytes = 0;
  uint32_t StronglyConnectedCount = 0;
  uint32_t LoopCount = 0;
  uint32_t ConnectedComponentCount = 0;
  int64_t CyclomaticComplexity = 0;
  uint32_t CallCount = 0;
  uint32_t DecodeErrorCount = 0;
  uint32_t OutOfRangeBranchCount = 0;
  uint32_t UnresolvedIndirectBranchCount = 0;
  uint32_t DroppedSuccessorCount = 0;
  uint32_t OverlappingLeaderCount = 0;
  uint32_t ExitBlockCount = 0;
  uint32_t RangeBytes = 0;

  bool Ok() const { return Status == CfgStatus::Ok; }

  std::span<const uint32_t> BlockSuccessors(uint32_t Block) const {
    if (Block >= Blocks.size()) {
      return std::span<const uint32_t>();
    }
    const CfgBlock& Item = Blocks[Block];
    if (Item.FirstSuccessor >= SuccessorBlocks.size()) {
      return std::span<const uint32_t>();
    }
    const size_t Available = SuccessorBlocks.size() - static_cast<size_t>(Item.FirstSuccessor);
    const size_t Count = static_cast<size_t>(Item.SuccessorCount) < Available
                             ? static_cast<size_t>(Item.SuccessorCount)
                             : Available;
    return std::span<const uint32_t>(SuccessorBlocks.data() + Item.FirstSuccessor, Count);
  }

  std::span<const uint32_t> BlockPredecessors(uint32_t Block) const {
    if (Block >= Blocks.size()) {
      return std::span<const uint32_t>();
    }
    const CfgBlock& Item = Blocks[Block];
    if (Item.FirstPredecessor >= PredecessorBlocks.size()) {
      return std::span<const uint32_t>();
    }
    const size_t Available = PredecessorBlocks.size() - static_cast<size_t>(Item.FirstPredecessor);
    const size_t Count = static_cast<size_t>(Item.PredecessorCount) < Available
                             ? static_cast<size_t>(Item.PredecessorCount)
                             : Available;
    return std::span<const uint32_t>(PredecessorBlocks.data() + Item.FirstPredecessor, Count);
  }

  bool HasSelfEdge(uint32_t Block) const {
    for (const uint32_t Successor : BlockSuccessors(Block)) {
      if (Successor == Block) {
        return true;
      }
    }
    return false;
  }

  uint32_t BlockAtOffset(uint32_t Offset) const;
};

ControlFlowGraph BuildControlFlowGraph(DisassemblerBackend& Backend, const uint8_t* Code,
                                       size_t Length, uint64_t RuntimeAddress);
ControlFlowGraph BuildControlFlowGraph(const uint8_t* Code, size_t Length,
                                       uint64_t RuntimeAddress);

}
