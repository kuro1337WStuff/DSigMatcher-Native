#include "dsigmatcher/ControlFlowGraph.h"

#include <algorithm>
#include <memory>
#include <string_view>

namespace DSig {

namespace {

constexpr uint8_t CfgSlotUnknown = 0;
constexpr uint8_t CfgSlotKnown = 1;
constexpr int32_t CfgOutsideRangeTarget = INT32_MAX;
constexpr uint32_t CfgUnvisited = 0xFFFFFFFFu;

enum class CfgInstructionRole : uint8_t {
  Normal = 0,
  DirectBranch,
  ConditionalBranch,
  IndirectBranch,
  DirectCall,
  IndirectCall,
  Return,
  NoReturn,
  Invalid
};

enum class CfgNameKind : uint8_t {
  None = 0,
  Jump,
  Call,
  ConditionalJump,
  Return,
  NoReturn
};

struct CfgDecodedSlot {
  int32_t RelativeTarget = CfgNoTarget;
  uint16_t Mnemonic = 0;
  uint8_t Length = 0;
  CfgInstructionRole Role = CfgInstructionRole::Normal;
};

struct CfgTarjanFrame {
  uint32_t Node = 0;
  uint32_t Cursor = 0;
};

constexpr std::string_view CfgConditionalJumpNames[] = {
    "jo",    "jno",   "jb",    "jnb",   "jbe",   "jnbe", "jl",    "jnl",
    "jle",   "jnle",  "jz",    "jnz",   "js",    "jns",  "jp",    "jnp",
    "jcxz",  "jecxz", "jrcxz", "jkzd",  "jknzd", "loop", "loope", "loopne"};

bool IsConditionalJumpName(std::string_view Name) {
  for (const std::string_view Candidate : CfgConditionalJumpNames) {
    if (Candidate == Name) {
      return true;
    }
  }
  return false;
}

CfgNameKind NameKindOf(std::string_view Name) {
  if (Name.empty()) {
    return CfgNameKind::None;
  }

  switch (Name[0]) {
  case 'j':
    if (Name == "jmp") {
      return CfgNameKind::Jump;
    }
    if (IsConditionalJumpName(Name)) {
      return CfgNameKind::ConditionalJump;
    }
    return CfgNameKind::None;
  case 'c':
    if (Name == "call") {
      return CfgNameKind::Call;
    }
    return CfgNameKind::None;
  case 'r':
    if (Name == "ret") {
      return CfgNameKind::Return;
    }
    return CfgNameKind::None;
  case 'i':
    if (Name == "iret" || Name == "iretd" || Name == "iretq") {
      return CfgNameKind::Return;
    }
    if (Name == "int" || Name == "int3") {
      return CfgNameKind::NoReturn;
    }
    return CfgNameKind::None;
  case 'l':
    if (IsConditionalJumpName(Name)) {
      return CfgNameKind::ConditionalJump;
    }
    return CfgNameKind::None;
  case 'u':
    if (Name == "ud0" || Name == "ud1" || Name == "ud2") {
      return CfgNameKind::NoReturn;
    }
    return CfgNameKind::None;
  case 'h':
    if (Name == "hlt") {
      return CfgNameKind::NoReturn;
    }
    return CfgNameKind::None;
  default:
    return CfgNameKind::None;
  }
}

bool RelativeDisplacementOf(const InstructionInfo& Info, int64_t& OutDisplacement) {
  for (uint8_t Index = 0; Index < Info.OperandCount; ++Index) {
    const OperandInfo& Operand = Info.Operands[Index];
    if (Operand.Kind == OperandKind::Immediate && Operand.ImmediateIsRelative) {
      OutDisplacement = Operand.Immediate;
      return true;
    }
  }
  return false;
}

int32_t RelativeTargetOf(uint32_t Offset, uint8_t Length, int64_t Displacement) {
  const int64_t Candidate =
      static_cast<int64_t>(Offset) + static_cast<int64_t>(Length) + Displacement;
  if (Candidate > static_cast<int64_t>(CfgOutsideRangeTarget) - 1) {
    return CfgOutsideRangeTarget;
  }
  if (Candidate < static_cast<int64_t>(INT32_MIN) + 1) {
    return CfgOutsideRangeTarget;
  }
  return static_cast<int32_t>(Candidate);
}

bool TargetInsideRange(int32_t Target, uint32_t Length) {
  return Target != CfgNoTarget && Target >= 0 && Target < static_cast<int32_t>(Length);
}

CfgDecodedSlot MakeSlot(const DisassemblerBackend& Backend, const InstructionInfo& Info,
                        uint32_t Offset) {
  CfgDecodedSlot Slot;
  Slot.Mnemonic = Info.Mnemonic;
  Slot.Length = Info.Length;

  int64_t Displacement = 0;
  const bool HasDisplacement = RelativeDisplacementOf(Info, Displacement);

  switch (NameKindOf(Backend.MnemonicName(Info.Mnemonic))) {
  case CfgNameKind::Jump:
    if (HasDisplacement) {
      Slot.Role = CfgInstructionRole::DirectBranch;
      Slot.RelativeTarget = RelativeTargetOf(Offset, Info.Length, Displacement);
    } else {
      Slot.Role = CfgInstructionRole::IndirectBranch;
    }
    break;
  case CfgNameKind::ConditionalJump:
    if (HasDisplacement) {
      Slot.Role = CfgInstructionRole::ConditionalBranch;
      Slot.RelativeTarget = RelativeTargetOf(Offset, Info.Length, Displacement);
    } else {
      Slot.Role = CfgInstructionRole::IndirectBranch;
    }
    break;
  case CfgNameKind::Call:
    Slot.Role = HasDisplacement ? CfgInstructionRole::DirectCall : CfgInstructionRole::IndirectCall;
    break;
  case CfgNameKind::Return:
    Slot.Role = CfgInstructionRole::Return;
    break;
  case CfgNameKind::NoReturn:
    Slot.Role = CfgInstructionRole::NoReturn;
    break;
  case CfgNameKind::None:
  default:
    Slot.Role = CfgInstructionRole::Normal;
    break;
  }

  return Slot;
}

CfgDecodedSlot MakeInvalidSlot() {
  CfgDecodedSlot Slot;
  Slot.Role = CfgInstructionRole::Invalid;
  Slot.Length = 1;
  return Slot;
}

uint32_t CfgFindRoot(std::vector<uint32_t>& Parent, uint32_t Node) {
  uint32_t Root = Node;
  while (Parent[Root] != Root) {
    Root = Parent[Root];
  }
  uint32_t Cursor = Node;
  while (Parent[Cursor] != Cursor) {
    const uint32_t Next = Parent[Cursor];
    Parent[Cursor] = Root;
    Cursor = Next;
  }
  return Root;
}

void CfgUnion(std::vector<uint32_t>& Parent, std::vector<uint32_t>& Rank, uint32_t Left,
              uint32_t Right) {
  if (Left == Right) {
    return;
  }
  if (Rank[Left] < Rank[Right]) {
    Parent[Left] = Right;
  } else if (Rank[Left] > Rank[Right]) {
    Parent[Right] = Left;
  } else {
    Parent[Right] = Left;
    ++Rank[Left];
  }
}

class CfgScanner {
public:
  CfgScanner(DisassemblerBackend& Backend, const uint8_t* Code, uint32_t Length,
             uint64_t RuntimeAddress, ControlFlowGraph& Out)
      : Backend_(Backend),
        Code_(Code),
        Length_(Length),
        RuntimeAddress_(RuntimeAddress),
        Out_(Out),
        Slots_(Length),
        SlotState_(Length, CfgSlotUnknown),
        IsLeader_(Length, 0) {}

  void Run();

private:
  bool Halted() const { return Out_.Status != CfgStatus::Ok; }
  bool DecodeHalted() const { return Out_.Status == CfgStatus::InstructionLimitReached; }
  void Fail(CfgStatus Status, const char* Message);
  void DecodeWindowAt(uint32_t Offset);
  void AddLeader(uint32_t Offset);
  void AddBranchLeader(const CfgDecodedSlot& Slot);
  void DiscoverLeaders();
  void BuildBlocks();
  void BuildSuccessors();
  void BuildPredecessors();
  void ComputeStronglyConnected();
  void ComputeConnectedComponents();
  void ComputeStatistics();
  uint32_t ResolveSuccessor(uint32_t Offset);

  DisassemblerBackend& Backend_;
  const uint8_t* Code_;
  uint32_t Length_;
  uint64_t RuntimeAddress_;
  ControlFlowGraph& Out_;

  std::vector<CfgDecodedSlot> Slots_;
  std::vector<uint8_t> SlotState_;
  std::vector<uint8_t> IsLeader_;
  std::vector<uint32_t> Leaders_;
  std::vector<InstructionInfo> DecodeScratch_;
  uint32_t DecodedSlotCount_ = 0;
};

void CfgScanner::Fail(CfgStatus Status, const char* Message) {
  if (Halted()) {
    return;
  }
  Out_.Status = Status;
  Out_.Error = Message;
}

void CfgScanner::DecodeWindowAt(uint32_t Offset) {
  if (Offset >= Length_ || SlotState_[Offset] != CfgSlotUnknown) {
    return;
  }

  const size_t Window = std::min<size_t>(static_cast<size_t>(Length_) - static_cast<size_t>(Offset),
                                         static_cast<size_t>(CfgDecodeWindowBytes));

  DecodeScratch_.clear();
  Backend_.DecodeRange(Code_ + Offset, Window, RuntimeAddress_ + Offset, DecodeScratch_);

  for (const InstructionInfo& Info : DecodeScratch_) {
    const uint32_t SlotOffset = Offset + Info.Offset;
    if (SlotOffset >= Length_) {
      break;
    }
    if (Info.Length == 0 || SlotState_[SlotOffset] != CfgSlotUnknown) {
      continue;
    }
    if (DecodedSlotCount_ >= CfgMaxInstructions) {
      Fail(CfgStatus::InstructionLimitReached,
           "instruction limit reached while decoding the code range");
      return;
    }
    Slots_[SlotOffset] = MakeSlot(Backend_, Info, SlotOffset);
    SlotState_[SlotOffset] = CfgSlotKnown;
    ++DecodedSlotCount_;
  }

  if (Halted()) {
    return;
  }

  if (SlotState_[Offset] == CfgSlotUnknown) {
    if (DecodedSlotCount_ >= CfgMaxInstructions) {
      Fail(CfgStatus::InstructionLimitReached,
           "instruction limit reached while decoding the code range");
      return;
    }
    Slots_[Offset] = MakeInvalidSlot();
    SlotState_[Offset] = CfgSlotKnown;
    ++DecodedSlotCount_;
  }
}

void CfgScanner::AddLeader(uint32_t Offset) {
  if (Offset >= Length_ || IsLeader_[Offset] != 0) {
    return;
  }
  if (Leaders_.size() >= static_cast<size_t>(CfgMaxBlocks)) {
    Fail(CfgStatus::BlockLimitReached, "block limit reached while collecting block leaders");
    return;
  }
  IsLeader_[Offset] = 1;
  Leaders_.push_back(Offset);
}

void CfgScanner::AddBranchLeader(const CfgDecodedSlot& Slot) {
  if (!TargetInsideRange(Slot.RelativeTarget, Length_)) {
    return;
  }
  AddLeader(static_cast<uint32_t>(Slot.RelativeTarget));
}

void CfgScanner::DiscoverLeaders() {
  AddLeader(0);

  size_t Cursor = 0;
  while (Cursor < Leaders_.size() && !Halted()) {
    const uint32_t Leader = Leaders_[Cursor];
    ++Cursor;

    uint32_t Offset = Leader;
    while (Offset < Length_) {
      if (Offset != Leader && IsLeader_[Offset] != 0) {
        break;
      }
      if (SlotState_[Offset] == CfgSlotUnknown) {
        DecodeWindowAt(Offset);
        if (Halted()) {
          return;
        }
      }

      const CfgDecodedSlot Slot = Slots_[Offset];
      uint32_t Next = Offset + Slot.Length;
      if (Next > Length_ || Next <= Offset) {
        Next = Length_;
      }

      bool Stop = false;
      switch (Slot.Role) {
      case CfgInstructionRole::DirectBranch:
        AddBranchLeader(Slot);
        Stop = true;
        break;
      case CfgInstructionRole::ConditionalBranch:
        AddBranchLeader(Slot);
        AddLeader(Next);
        Stop = true;
        break;
      case CfgInstructionRole::IndirectBranch:
      case CfgInstructionRole::Return:
      case CfgInstructionRole::NoReturn:
      case CfgInstructionRole::Invalid:
        Stop = true;
        break;
      case CfgInstructionRole::Normal:
      case CfgInstructionRole::DirectCall:
      case CfgInstructionRole::IndirectCall:
      default:
        break;
      }

      if (Stop || Halted()) {
        break;
      }
      Offset = Next;
    }
  }
}

void CfgScanner::BuildBlocks() {
  std::vector<uint32_t> Ordered = Leaders_;
  std::sort(Ordered.begin(), Ordered.end());
  Out_.Blocks.reserve(Ordered.size());

  uint32_t CoveredUntil = 0;
  for (const uint32_t Start : Ordered) {
    if (Start < CoveredUntil) {
      ++Out_.OverlappingLeaderCount;
      continue;
    }
    if (Out_.Blocks.size() >= static_cast<size_t>(CfgMaxBlocks)) {
      Fail(CfgStatus::BlockLimitReached, "block limit reached while partitioning the code range");
      break;
    }

    CfgBlock Block;
    Block.Offset = Start;

    uint32_t Offset = Start;
    while (Offset < Length_) {
      if (Offset != Start && IsLeader_[Offset] != 0) {
        Block.End = CfgBlockEnd::Fallthrough;
        break;
      }
      if (SlotState_[Offset] == CfgSlotUnknown) {
        if (DecodeHalted()) {
          Block.End = CfgBlockEnd::RangeEnd;
          break;
        }
        DecodeWindowAt(Offset);
        if (SlotState_[Offset] == CfgSlotUnknown) {
          Block.End = CfgBlockEnd::RangeEnd;
          break;
        }
      }

      const CfgDecodedSlot Slot = Slots_[Offset];
      uint32_t Next = Offset + Slot.Length;
      if (Next > Length_ || Next <= Offset) {
        Next = Length_;
      }
      ++Block.InstructionCount;

      bool Stop = false;
      switch (Slot.Role) {
      case CfgInstructionRole::Invalid:
        Block.End = CfgBlockEnd::DecodeError;
        ++Out_.DecodeErrorCount;
        Stop = true;
        break;
      case CfgInstructionRole::DirectBranch:
        Block.End = CfgBlockEnd::DirectBranch;
        if (TargetInsideRange(Slot.RelativeTarget, Length_)) {
          Block.TargetOffset = Slot.RelativeTarget;
        } else {
          Block.TargetOutsideRange = true;
          ++Out_.OutOfRangeBranchCount;
        }
        Stop = true;
        break;
      case CfgInstructionRole::ConditionalBranch:
        Block.End = CfgBlockEnd::ConditionalBranch;
        if (TargetInsideRange(Slot.RelativeTarget, Length_)) {
          Block.TargetOffset = Slot.RelativeTarget;
        } else {
          Block.TargetOutsideRange = true;
          ++Out_.OutOfRangeBranchCount;
        }
        Stop = true;
        break;
      case CfgInstructionRole::IndirectBranch:
        Block.End = CfgBlockEnd::IndirectBranch;
        Block.IndirectTargetUnresolved = true;
        ++Out_.UnresolvedIndirectBranchCount;
        Stop = true;
        break;
      case CfgInstructionRole::Return:
        Block.End = CfgBlockEnd::Return;
        Stop = true;
        break;
      case CfgInstructionRole::NoReturn:
        Block.End = CfgBlockEnd::NoReturn;
        Stop = true;
        break;
      case CfgInstructionRole::DirectCall:
      case CfgInstructionRole::IndirectCall:
        ++Out_.CallCount;
        break;
      case CfgInstructionRole::Normal:
      default:
        break;
      }

      Offset = Next;
      if (Stop) {
        break;
      }
      if (Offset >= Length_) {
        Block.End = CfgBlockEnd::RangeEnd;
        break;
      }
    }

    Block.Size = Offset - Start;
    if (Block.InstructionCount == 0) {
      continue;
    }
    Out_.Blocks.push_back(Block);
    CoveredUntil = Block.Offset + Block.Size;
  }

  Out_.NodeCount = static_cast<uint32_t>(Out_.Blocks.size());

  if (Out_.NodeCount == 1 && Out_.Blocks.front().Offset == 0 &&
      Out_.Blocks.front().Size == 1 && Out_.Blocks.front().InstructionCount == 1 &&
      Out_.Blocks.front().End == CfgBlockEnd::DecodeError) {
    Out_.Blocks.clear();
    Out_.NodeCount = 0;
    Out_.DecodeErrorCount = 0;
    Fail(CfgStatus::EntryUndecodable, "the first instruction of the range does not decode");
  }
}

uint32_t CfgScanner::ResolveSuccessor(uint32_t Offset) {
  if (Offset >= Length_) {
    return CfgNoBlock;
  }
  const uint32_t Block = Out_.BlockAtOffset(Offset);
  if (Block == CfgNoBlock) {
    ++Out_.DroppedSuccessorCount;
  }
  return Block;
}

void CfgScanner::BuildSuccessors() {
  Out_.SuccessorBlocks.reserve(static_cast<size_t>(Out_.NodeCount));

  for (uint32_t Index = 0; Index < Out_.NodeCount; ++Index) {
    CfgBlock& Block = Out_.Blocks[Index];
    Block.FirstSuccessor = static_cast<uint32_t>(Out_.SuccessorBlocks.size());

    uint32_t Candidates[CfgSuccessorCapacity] = {CfgNoBlock, CfgNoBlock};
    const uint32_t FallthroughOffset = Block.Offset + Block.Size;

    switch (Block.End) {
    case CfgBlockEnd::ConditionalBranch:
      if (Block.TargetOffset != CfgNoTarget) {
        Candidates[0] = ResolveSuccessor(static_cast<uint32_t>(Block.TargetOffset));
      }
      Candidates[1] = ResolveSuccessor(FallthroughOffset);
      break;
    case CfgBlockEnd::DirectBranch:
      if (Block.TargetOffset != CfgNoTarget) {
        Candidates[0] = ResolveSuccessor(static_cast<uint32_t>(Block.TargetOffset));
      }
      break;
    case CfgBlockEnd::Fallthrough:
    case CfgBlockEnd::RangeEnd:
      Candidates[0] = ResolveSuccessor(FallthroughOffset);
      break;
    case CfgBlockEnd::IndirectBranch:
    case CfgBlockEnd::Return:
    case CfgBlockEnd::NoReturn:
    case CfgBlockEnd::DecodeError:
    default:
      break;
    }

    for (const uint32_t Candidate : Candidates) {
      if (Candidate == CfgNoBlock) {
        continue;
      }
      bool Duplicate = false;
      for (uint32_t Taken = 0; Taken < Block.SuccessorCount; ++Taken) {
        if (Out_.SuccessorBlocks[static_cast<size_t>(Block.FirstSuccessor) + Taken] == Candidate) {
          Duplicate = true;
          break;
        }
      }
      if (Duplicate) {
        continue;
      }
      Out_.SuccessorBlocks.push_back(Candidate);
      ++Block.SuccessorCount;
    }

    if (Block.SuccessorCount == 0) {
      ++Out_.ExitBlockCount;
    }
  }

  Out_.EdgeCount = static_cast<uint32_t>(Out_.SuccessorBlocks.size());
}

void CfgScanner::BuildPredecessors() {
  std::vector<uint32_t> Counts(static_cast<size_t>(Out_.NodeCount), 0);
  for (const uint32_t Successor : Out_.SuccessorBlocks) {
    if (Successor < Out_.NodeCount) {
      ++Counts[Successor];
    }
  }

  uint32_t Running = 0;
  for (uint32_t Index = 0; Index < Out_.NodeCount; ++Index) {
    CfgBlock& Block = Out_.Blocks[Index];
    Block.FirstPredecessor = Running;
    Block.PredecessorCount = Counts[Index];
    Running += Counts[Index];
  }

  Out_.PredecessorBlocks.assign(static_cast<size_t>(Running), 0);
  std::vector<uint32_t> Cursor(static_cast<size_t>(Out_.NodeCount), 0);
  for (uint32_t Index = 0; Index < Out_.NodeCount; ++Index) {
    Cursor[Index] = Out_.Blocks[Index].FirstPredecessor;
  }
  for (uint32_t Index = 0; Index < Out_.NodeCount; ++Index) {
    for (const uint32_t Successor : Out_.BlockSuccessors(Index)) {
      if (Successor < Out_.NodeCount) {
        Out_.PredecessorBlocks[Cursor[Successor]] = Index;
        ++Cursor[Successor];
      }
    }
  }
}

void CfgScanner::ComputeStronglyConnected() {
  Out_.ComponentOfBlock.assign(static_cast<size_t>(Out_.NodeCount), 0);
  Out_.ComponentNodeCounts.clear();
  Out_.ComponentIsLoop.clear();

  if (Out_.NodeCount == 0) {
    return;
  }

  std::vector<uint32_t> Index(static_cast<size_t>(Out_.NodeCount), CfgUnvisited);
  std::vector<uint32_t> LowLink(static_cast<size_t>(Out_.NodeCount), 0);
  std::vector<uint8_t> OnStack(static_cast<size_t>(Out_.NodeCount), 0);
  std::vector<uint32_t> SccStack;
  std::vector<CfgTarjanFrame> Frames;
  SccStack.reserve(static_cast<size_t>(Out_.NodeCount));

  uint32_t NextIndex = 0;
  uint32_t NextComponent = 0;

  for (uint32_t Root = 0; Root < Out_.NodeCount; ++Root) {
    if (Index[Root] != CfgUnvisited) {
      continue;
    }

    Index[Root] = NextIndex;
    LowLink[Root] = NextIndex;
    ++NextIndex;
    SccStack.push_back(Root);
    OnStack[Root] = 1;
    Frames.clear();
    Frames.push_back(CfgTarjanFrame{Root, 0});

    while (!Frames.empty()) {
      const uint32_t Node = Frames.back().Node;
      const uint32_t Cursor = Frames.back().Cursor;
      const std::span<const uint32_t> Successors = Out_.BlockSuccessors(Node);

      if (Cursor < Successors.size()) {
        Frames.back().Cursor = Cursor + 1;
        const uint32_t Child = Successors[Cursor];
        if (Child >= Out_.NodeCount) {
          continue;
        }
        if (Index[Child] == CfgUnvisited) {
          Index[Child] = NextIndex;
          LowLink[Child] = NextIndex;
          ++NextIndex;
          SccStack.push_back(Child);
          OnStack[Child] = 1;
          Frames.push_back(CfgTarjanFrame{Child, 0});
        } else if (OnStack[Child] != 0 && Index[Child] < LowLink[Node]) {
          LowLink[Node] = Index[Child];
        }
        continue;
      }

      if (LowLink[Node] == Index[Node]) {
        uint32_t Members = 0;
        while (!SccStack.empty()) {
          const uint32_t Top = SccStack.back();
          SccStack.pop_back();
          OnStack[Top] = 0;
          Out_.ComponentOfBlock[Top] = NextComponent;
          ++Members;
          if (Top == Node) {
            break;
          }
        }
        Out_.ComponentNodeCounts.push_back(Members);
        Out_.ComponentIsLoop.push_back(static_cast<uint8_t>(Members > 1 ? 1 : 0));
        ++NextComponent;
      }

      Frames.pop_back();
      if (!Frames.empty()) {
        const uint32_t Parent = Frames.back().Node;
        if (LowLink[Node] < LowLink[Parent]) {
          LowLink[Parent] = LowLink[Node];
        }
      }
    }
  }

  Out_.StronglyConnectedCount = NextComponent;

  for (uint32_t Node = 0; Node < Out_.NodeCount; ++Node) {
    const uint32_t Component = Out_.ComponentOfBlock[Node];
    if (Component >= Out_.ComponentNodeCounts.size()) {
      continue;
    }
    if (Out_.ComponentNodeCounts[Component] == 1 && Out_.HasSelfEdge(Node)) {
      Out_.ComponentIsLoop[Component] = 1;
    }
  }

  uint32_t Loops = 0;
  for (const uint8_t IsLoop : Out_.ComponentIsLoop) {
    if (IsLoop != 0) {
      ++Loops;
    }
  }
  Out_.LoopCount = Loops;
}

void CfgScanner::ComputeConnectedComponents() {
  Out_.ConnectedComponentCount = 0;
  if (Out_.NodeCount == 0) {
    return;
  }

  std::vector<uint32_t> Parent(static_cast<size_t>(Out_.NodeCount));
  std::vector<uint32_t> Rank(static_cast<size_t>(Out_.NodeCount), 0);
  for (uint32_t Index = 0; Index < Out_.NodeCount; ++Index) {
    Parent[Index] = Index;
  }

  for (uint32_t Index = 0; Index < Out_.NodeCount; ++Index) {
    for (const uint32_t Successor : Out_.BlockSuccessors(Index)) {
      if (Successor >= Out_.NodeCount) {
        continue;
      }
      const uint32_t Left = CfgFindRoot(Parent, Index);
      const uint32_t Right = CfgFindRoot(Parent, Successor);
      CfgUnion(Parent, Rank, Left, Right);
    }
  }

  uint32_t Components = 0;
  for (uint32_t Index = 0; Index < Out_.NodeCount; ++Index) {
    if (Parent[Index] == Index) {
      ++Components;
    }
  }
  Out_.ConnectedComponentCount = Components;
}

void CfgScanner::ComputeStatistics() {
  uint32_t Instructions = 0;
  uint32_t Bytes = 0;
  for (const CfgBlock& Block : Out_.Blocks) {
    Instructions += Block.InstructionCount;
    Bytes += Block.Size;
  }
  Out_.InstructionCount = Instructions;
  Out_.DecodedBytes = Bytes;
  Out_.EntryBlock = Out_.BlockAtOffset(0);

  if (Out_.NodeCount == 0) {
    Out_.CyclomaticComplexity = 0;
    return;
  }

  const int64_t Complexity = static_cast<int64_t>(Out_.EdgeCount) -
                             static_cast<int64_t>(Out_.NodeCount) +
                             2 * static_cast<int64_t>(Out_.ConnectedComponentCount);
  Out_.CyclomaticComplexity = Complexity < 1 ? 1 : Complexity;
}

void CfgScanner::Run() {
  Out_.RangeBytes = Length_;

  DiscoverLeaders();
  BuildBlocks();

  if (Out_.Status == CfgStatus::EntryUndecodable) {
    return;
  }

  BuildSuccessors();
  BuildPredecessors();
  ComputeStronglyConnected();
  ComputeConnectedComponents();
  ComputeStatistics();
}

}

uint32_t ControlFlowGraph::BlockAtOffset(uint32_t Offset) const {
  if (Blocks.empty()) {
    return CfgNoBlock;
  }
  const auto Found =
      std::lower_bound(Blocks.begin(), Blocks.end(), Offset,
                       [](const CfgBlock& Block, uint32_t Value) { return Block.Offset < Value; });
  if (Found == Blocks.end() || Found->Offset != Offset) {
    return CfgNoBlock;
  }
  return static_cast<uint32_t>(Found - Blocks.begin());
}

const char* CfgStatusName(CfgStatus Status) {
  switch (Status) {
  case CfgStatus::Ok:
    return "ok";
  case CfgStatus::NullCode:
    return "null-code";
  case CfgStatus::EmptyRange:
    return "empty-range";
  case CfgStatus::RangeTooLarge:
    return "range-too-large";
  case CfgStatus::BackendUnavailable:
    return "backend-unavailable";
  case CfgStatus::EntryUndecodable:
    return "entry-undecodable";
  case CfgStatus::BlockLimitReached:
    return "block-limit-reached";
  case CfgStatus::InstructionLimitReached:
    return "instruction-limit-reached";
  }
  return "unknown";
}

const char* CfgBlockEndName(CfgBlockEnd End) {
  switch (End) {
  case CfgBlockEnd::Fallthrough:
    return "fallthrough";
  case CfgBlockEnd::RangeEnd:
    return "range-end";
  case CfgBlockEnd::DirectBranch:
    return "direct-branch";
  case CfgBlockEnd::ConditionalBranch:
    return "conditional-branch";
  case CfgBlockEnd::IndirectBranch:
    return "indirect-branch";
  case CfgBlockEnd::Return:
    return "return";
  case CfgBlockEnd::NoReturn:
    return "no-return";
  case CfgBlockEnd::DecodeError:
    return "decode-error";
  }
  return "unknown";
}

ControlFlowGraph BuildControlFlowGraph(DisassemblerBackend& Backend, const uint8_t* Code,
                                       size_t Length, uint64_t RuntimeAddress) {
  ControlFlowGraph Graph;

  if (Length == 0) {
    Graph.Status = CfgStatus::EmptyRange;
    Graph.Error = "code range is empty";
    return Graph;
  }
  if (Code == nullptr) {
    Graph.Status = CfgStatus::NullCode;
    Graph.Error = "code pointer is null";
    return Graph;
  }
  if (Length > CfgMaxRangeBytes) {
    Graph.Status = CfgStatus::RangeTooLarge;
    Graph.Error = "code range exceeds CfgMaxRangeBytes";
    return Graph;
  }

  CfgScanner Scanner(Backend, Code, static_cast<uint32_t>(Length), RuntimeAddress, Graph);
  Scanner.Run();
  return Graph;
}

ControlFlowGraph BuildControlFlowGraph(const uint8_t* Code, size_t Length,
                                       uint64_t RuntimeAddress) {
  const std::unique_ptr<DisassemblerBackend> Backend = CreateX64Disassembler();
  if (Backend == nullptr) {
    ControlFlowGraph Graph;
    Graph.Status = CfgStatus::BackendUnavailable;
    Graph.Error = "no x64 disassembler backend available";
    return Graph;
  }
  return BuildControlFlowGraph(*Backend, Code, Length, RuntimeAddress);
}

}
