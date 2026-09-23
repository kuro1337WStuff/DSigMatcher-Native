#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <initializer_list>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "dsigmatcher/ControlFlowGraph.h"
#include "dsigmatcher/PeImage.h"

namespace {

using namespace DSig;

int ChecksRun = 0;
int ChecksFailed = 0;
int SuitesSkipped = 0;

void Report(bool Ok, const char* Expression, const char* File, int Line) {
  ++ChecksRun;
  if (!Ok) {
    ++ChecksFailed;
    std::printf("  FAIL %s:%d  %s\n", File, Line, Expression);
  }
}

void ReportValues(bool Ok, const char* Expression, long long Actual, long long Expected,
                  const char* File, int Line) {
  ++ChecksRun;
  if (!Ok) {
    ++ChecksFailed;
    std::printf("  FAIL %s:%d  %s\n       actual   : %lld\n       expected : %lld\n", File, Line,
                Expression, Actual, Expected);
  }
}

void ReportText(bool Ok, const char* Expression, const std::string& Actual,
                const std::string& Expected, const char* File, int Line) {
  ++ChecksRun;
  if (!Ok) {
    ++ChecksFailed;
    std::printf("  FAIL %s:%d  %s\n       actual   : %s\n       expected : %s\n", File, Line,
                Expression, Actual.c_str(), Expected.c_str());
  }
}

void Suite(const char* Name) { std::printf("[%s]\n", Name); }

void NoteText(const char* Label, const std::string& Value) {
  std::printf("  %-28s %s\n", Label, Value.c_str());
}

void NoteNumber(const char* Label, long long Value) {
  std::printf("  %-28s %lld\n", Label, Value);
}

#define CHECK(Expr) Report(static_cast<bool>(Expr), #Expr, __FILE__, __LINE__)
#define CHECK_NUM_EQ(A, B) \
  ReportValues(static_cast<long long>(A) == static_cast<long long>(B), #A " == " #B, \
               static_cast<long long>(A), static_cast<long long>(B), __FILE__, __LINE__)
#define CHECK_TEXT_EQ(A, B) \
  ReportText(std::string(A) == std::string(B), #A " == " #B, std::string(A), std::string(B), \
             __FILE__, __LINE__)

const char* const CorpusWin32u =
    R"(C:\Users\Loki\dsig-corpus\win32u\win32u_100261009168\win32u.dll)";

const uint64_t TestRuntimeBase = 0x140001000ull;

DisassemblerBackend& SharedBackend() {
  static std::unique_ptr<DisassemblerBackend> Instance = CreateX64Disassembler();
  return *Instance;
}

std::vector<uint8_t> Bytes(std::initializer_list<int> Values) {
  std::vector<uint8_t> Result;
  Result.reserve(Values.size());
  for (const int Value : Values) {
    Result.push_back(static_cast<uint8_t>(Value));
  }
  return Result;
}

ControlFlowGraph Build(const std::vector<uint8_t>& Code) {
  return BuildControlFlowGraph(SharedBackend(), Code.data(), Code.size(), TestRuntimeBase);
}

std::string SuccessorText(const ControlFlowGraph& Graph, uint32_t Block) {
  std::string Result;
  for (const uint32_t Successor : Graph.BlockSuccessors(Block)) {
    if (!Result.empty()) {
      Result += ",";
    }
    Result += std::to_string(Successor);
  }
  return Result;
}

std::string PredecessorText(const ControlFlowGraph& Graph, uint32_t Block) {
  std::string Result;
  for (const uint32_t Predecessor : Graph.BlockPredecessors(Block)) {
    if (!Result.empty()) {
      Result += ",";
    }
    Result += std::to_string(Predecessor);
  }
  return Result;
}

void PrintSummary(const char* Label, const ControlFlowGraph& Graph) {
  std::printf("  %s: status=%s nodes=%u edges=%u instrs=%u bytes=%u/%u scc=%u loops=%u cc=%lld "
              "calls=%u exits=%u decode-errors=%u out-of-range=%u indirect=%u dropped=%u "
              "overlap=%u\n",
              Label, CfgStatusName(Graph.Status), Graph.NodeCount, Graph.EdgeCount,
              Graph.InstructionCount, Graph.DecodedBytes, Graph.RangeBytes,
              Graph.StronglyConnectedCount, Graph.LoopCount,
              static_cast<long long>(Graph.CyclomaticComplexity), Graph.CallCount,
              Graph.ExitBlockCount, Graph.DecodeErrorCount, Graph.OutOfRangeBranchCount,
              Graph.UnresolvedIndirectBranchCount, Graph.DroppedSuccessorCount,
              Graph.OverlappingLeaderCount);
}

void PrintGraph(const char* Label, const ControlFlowGraph& Graph) {
  PrintSummary(Label, Graph);
  for (uint32_t Index = 0; Index < Graph.NodeCount; ++Index) {
    const CfgBlock& Block = Graph.Blocks[Index];
    std::printf("    b%-2u off=0x%04x size=%-3u instrs=%-3u end=%-19s succ=[%s] pred=[%s]", Index,
                Block.Offset, Block.Size, Block.InstructionCount, CfgBlockEndName(Block.End),
                SuccessorText(Graph, Index).c_str(), PredecessorText(Graph, Index).c_str());
    if (Block.TargetOffset != CfgNoTarget) {
      std::printf(" target=0x%04x", static_cast<uint32_t>(Block.TargetOffset));
    }
    if (Block.TargetOutsideRange) {
      std::printf(" target-outside-range");
    }
    if (Block.IndirectTargetUnresolved) {
      std::printf(" indirect-unresolved");
    }
    std::printf("\n");
  }
}

void ExpectShape(const ControlFlowGraph& Graph, uint32_t Nodes, uint32_t Edges, uint32_t Instrs,
                 uint32_t DecodedBytes, uint32_t Scc, uint32_t Loops, long long Complexity) {
  CHECK_NUM_EQ(Graph.NodeCount, Nodes);
  CHECK_NUM_EQ(Graph.EdgeCount, Edges);
  CHECK_NUM_EQ(Graph.InstructionCount, Instrs);
  CHECK_NUM_EQ(Graph.DecodedBytes, DecodedBytes);
  CHECK_NUM_EQ(Graph.StronglyConnectedCount, Scc);
  CHECK_NUM_EQ(Graph.LoopCount, Loops);
  CHECK_NUM_EQ(Graph.CyclomaticComplexity, Complexity);
}

void ExpectBlock(const ControlFlowGraph& Graph, uint32_t Index, uint32_t Offset, uint32_t Size,
                 uint32_t Instrs, CfgBlockEnd End) {
  if (Index >= Graph.NodeCount) {
    Report(false, "block index within node count", __FILE__, __LINE__);
    return;
  }
  const CfgBlock& Block = Graph.Blocks[Index];
  CHECK_NUM_EQ(Block.Offset, Offset);
  CHECK_NUM_EQ(Block.Size, Size);
  CHECK_NUM_EQ(Block.InstructionCount, Instrs);
  CHECK_TEXT_EQ(CfgBlockEndName(Block.End), CfgBlockEndName(End));
}

void ExpectSuccessors(const ControlFlowGraph& Graph, uint32_t Index,
                      std::initializer_list<uint32_t> Expected) {
  if (Index >= Graph.NodeCount) {
    Report(false, "block index within node count", __FILE__, __LINE__);
    return;
  }
  const std::string Actual = SuccessorText(Graph, Index);
  std::string Wanted;
  for (const uint32_t Successor : Expected) {
    if (!Wanted.empty()) {
      Wanted += ",";
    }
    Wanted += std::to_string(Successor);
  }
  CHECK_TEXT_EQ(Actual, Wanted);
}

void ExpectPredecessors(const ControlFlowGraph& Graph, uint32_t Index,
                        std::initializer_list<uint32_t> Expected) {
  if (Index >= Graph.NodeCount) {
    Report(false, "block index within node count", __FILE__, __LINE__);
    return;
  }
  const std::string Actual = PredecessorText(Graph, Index);
  std::string Wanted;
  for (const uint32_t Predecessor : Expected) {
    if (!Wanted.empty()) {
      Wanted += ",";
    }
    Wanted += std::to_string(Predecessor);
  }
  CHECK_TEXT_EQ(Actual, Wanted);
}

void CheckInvariants(const ControlFlowGraph& Graph, const char* Label) {
  if (!Graph.Ok()) {
    Report(false, Label, __FILE__, __LINE__);
    std::printf("    status=%s error=%s\n", CfgStatusName(Graph.Status), Graph.Error.c_str());
    return;
  }

  CHECK_NUM_EQ(Graph.NodeCount, Graph.Blocks.size());
  CHECK_NUM_EQ(Graph.ComponentOfBlock.size(), Graph.NodeCount);
  CHECK_NUM_EQ(Graph.StronglyConnectedCount, Graph.ComponentNodeCounts.size());
  CHECK_NUM_EQ(Graph.ComponentIsLoop.size(), Graph.StronglyConnectedCount);

  uint64_t SuccessorTotal = 0;
  uint64_t PredecessorTotal = 0;
  uint64_t SizeTotal = 0;
  uint64_t InstructionTotal = 0;
  uint64_t ComponentMembers = 0;
  uint64_t PreviousEnd = 0;

  for (uint32_t Index = 0; Index < Graph.NodeCount; ++Index) {
    const CfgBlock& Block = Graph.Blocks[Index];

    Report(Block.InstructionCount > 0, "every block holds at least one instruction", __FILE__,
           __LINE__);
    Report(Block.Size > 0, "every block covers at least one byte", __FILE__, __LINE__);
    Report(Block.Offset >= PreviousEnd, "blocks are sorted and disjoint", __FILE__, __LINE__);
    Report(Block.Offset + Block.Size <= Graph.RangeBytes, "block stays inside the range", __FILE__,
           __LINE__);
    PreviousEnd = Block.Offset + Block.Size;

    SizeTotal += Block.Size;
    InstructionTotal += Block.InstructionCount;
    SuccessorTotal += Block.SuccessorCount;
    PredecessorTotal += Block.PredecessorCount;

    CHECK_NUM_EQ(Block.SuccessorCount, Graph.BlockSuccessors(Index).size());
    CHECK_NUM_EQ(Block.PredecessorCount, Graph.BlockPredecessors(Index).size());

    for (const uint32_t Successor : Graph.BlockSuccessors(Index)) {
      Report(Successor < Graph.NodeCount, "successor index in range", __FILE__, __LINE__);
    }
    for (const uint32_t Predecessor : Graph.BlockPredecessors(Index)) {
      Report(Predecessor < Graph.NodeCount, "predecessor index in range", __FILE__, __LINE__);
    }

    const uint32_t Component = Graph.ComponentOfBlock[Index];
    Report(Component < Graph.StronglyConnectedCount, "component id in range", __FILE__, __LINE__);
  }

  for (const uint32_t Members : Graph.ComponentNodeCounts) {
    Report(Members > 0, "component has at least one node", __FILE__, __LINE__);
    ComponentMembers += Members;
  }
  CHECK_NUM_EQ(ComponentMembers, Graph.NodeCount);

  CHECK_NUM_EQ(SuccessorTotal, Graph.EdgeCount);
  CHECK_NUM_EQ(PredecessorTotal, Graph.EdgeCount);
  CHECK_NUM_EQ(Graph.SuccessorBlocks.size(), Graph.EdgeCount);
  CHECK_NUM_EQ(Graph.PredecessorBlocks.size(), Graph.EdgeCount);
  CHECK_NUM_EQ(SizeTotal, Graph.DecodedBytes);
  CHECK_NUM_EQ(InstructionTotal, Graph.InstructionCount);
  CHECK(SizeTotal <= Graph.RangeBytes);

  const long long ExpectedComplexity =
      Graph.NodeCount == 0
          ? 0
          : std::max<long long>(
                1, static_cast<long long>(Graph.EdgeCount) -
                       static_cast<long long>(Graph.NodeCount) +
                       2 * static_cast<long long>(Graph.ConnectedComponentCount));
  CHECK_NUM_EQ(Graph.CyclomaticComplexity, ExpectedComplexity);

  uint32_t ObservedExits = 0;
  for (uint32_t Index = 0; Index < Graph.NodeCount; ++Index) {
    if (Graph.BlockSuccessors(Index).empty()) {
      ++ObservedExits;
    }
  }
  CHECK_NUM_EQ(Graph.ExitBlockCount, ObservedExits);
}

void TestStraightLine() {
  Suite("Straight-line range with no branches");

  const std::vector<uint8_t> Nops = Bytes({0x90, 0x90, 0x90});
  const ControlFlowGraph NopGraph = Build(Nops);
  PrintGraph("three nops", NopGraph);
  CHECK(NopGraph.Ok());
  CHECK_NUM_EQ(NopGraph.EntryBlock, 0u);
  ExpectShape(NopGraph, 1, 0, 3, 3, 1, 0, 1);
  ExpectBlock(NopGraph, 0, 0, 3, 3, CfgBlockEnd::RangeEnd);
  ExpectSuccessors(NopGraph, 0, {});
  ExpectPredecessors(NopGraph, 0, {});
  CHECK_NUM_EQ(NopGraph.ExitBlockCount, 1u);
  CheckInvariants(NopGraph, "three nops invariants");

  const std::vector<uint8_t> Getter = Bytes({0x48, 0x8B, 0x41, 0x48, 0xC3});
  const ControlFlowGraph GetterGraph = Build(Getter);
  PrintGraph("mov+ret", GetterGraph);
  CHECK(GetterGraph.Ok());
  ExpectShape(GetterGraph, 1, 0, 2, 5, 1, 0, 1);
  ExpectBlock(GetterGraph, 0, 0, 5, 2, CfgBlockEnd::Return);
  ExpectSuccessors(GetterGraph, 0, {});
  CheckInvariants(GetterGraph, "mov+ret invariants");
}

void TestSimpleIfDiamond() {
  Suite("Simple if: diamond with one conditional jump");

  const std::vector<uint8_t> Code = Bytes({
      0x48, 0x85, 0xC9,
      0x74, 0x06,
      0x48, 0x8B, 0x41, 0x08,
      0xEB, 0x02,
      0x33, 0xC0,
      0xC3,
  });
  const ControlFlowGraph Graph = Build(Code);
  PrintGraph("diamond", Graph);
  CHECK(Graph.Ok());

  ExpectShape(Graph, 4, 4, 6, 14, 4, 0, 2);
  CHECK_NUM_EQ(Graph.ConnectedComponentCount, 1u);
  CHECK_NUM_EQ(Graph.EntryBlock, 0u);
  CHECK_NUM_EQ(Graph.ExitBlockCount, 1u);

  ExpectBlock(Graph, 0, 0x00, 5, 2, CfgBlockEnd::ConditionalBranch);
  ExpectBlock(Graph, 1, 0x05, 6, 2, CfgBlockEnd::DirectBranch);
  ExpectBlock(Graph, 2, 0x0B, 2, 1, CfgBlockEnd::Fallthrough);
  ExpectBlock(Graph, 3, 0x0D, 1, 1, CfgBlockEnd::Return);

  CHECK_NUM_EQ(Graph.Blocks[0].TargetOffset, 0x0B);
  CHECK_NUM_EQ(Graph.Blocks[1].TargetOffset, 0x0D);

  ExpectSuccessors(Graph, 0, {2, 1});
  ExpectSuccessors(Graph, 1, {3});
  ExpectSuccessors(Graph, 2, {3});
  ExpectSuccessors(Graph, 3, {});

  ExpectPredecessors(Graph, 0, {});
  ExpectPredecessors(Graph, 1, {0});
  ExpectPredecessors(Graph, 2, {0});
  ExpectPredecessors(Graph, 3, {1, 2});

  CheckInvariants(Graph, "diamond invariants");
}

void TestCountedLoop() {
  Suite("Counted loop: back edge gives one multi-node SCC and one loop");

  const std::vector<uint8_t> Code = Bytes({
      0x33, 0xC0,
      0x48, 0x83, 0xF8, 0x0A,
      0x7D, 0x05,
      0x48, 0xFF, 0xC0,
      0xEB, 0xF5,
      0xC3,
  });
  const ControlFlowGraph Graph = Build(Code);
  PrintGraph("counted loop", Graph);
  CHECK(Graph.Ok());

  ExpectShape(Graph, 4, 4, 6, 14, 3, 1, 2);
  CHECK_NUM_EQ(Graph.ConnectedComponentCount, 1u);

  ExpectBlock(Graph, 0, 0x00, 2, 1, CfgBlockEnd::Fallthrough);
  ExpectBlock(Graph, 1, 0x02, 6, 2, CfgBlockEnd::ConditionalBranch);
  ExpectBlock(Graph, 2, 0x08, 5, 2, CfgBlockEnd::DirectBranch);
  ExpectBlock(Graph, 3, 0x0D, 1, 1, CfgBlockEnd::Return);

  CHECK_NUM_EQ(Graph.Blocks[1].TargetOffset, 0x0D);
  CHECK_NUM_EQ(Graph.Blocks[2].TargetOffset, 0x02);

  ExpectSuccessors(Graph, 0, {1});
  ExpectSuccessors(Graph, 1, {3, 2});
  ExpectSuccessors(Graph, 2, {1});
  ExpectSuccessors(Graph, 3, {});

  CHECK(Graph.ComponentOfBlock[1] == Graph.ComponentOfBlock[2]);
  CHECK(Graph.ComponentOfBlock[0] != Graph.ComponentOfBlock[1]);
  CHECK(Graph.ComponentOfBlock[3] != Graph.ComponentOfBlock[1]);

  uint32_t LoopComponent = CfgNoBlock;
  for (uint32_t Component = 0; Component < Graph.StronglyConnectedCount; ++Component) {
    if (Graph.ComponentIsLoop[Component] != 0) {
      LoopComponent = Component;
    }
  }
  CHECK(LoopComponent != CfgNoBlock);
  if (LoopComponent != CfgNoBlock) {
    CHECK_NUM_EQ(Graph.ComponentNodeCounts[LoopComponent], 2u);
  }

  CheckInvariants(Graph, "counted loop invariants");
}

void TestSelfLoop() {
  Suite("Self loop: single-node SCC with a self edge counts as a loop");

  const std::vector<uint8_t> Retry = Bytes({
      0x48, 0xFF, 0xC8,
      0x75, 0xFB,
      0xC3,
  });
  const ControlFlowGraph RetryGraph = Build(Retry);
  PrintGraph("dec/jnz self loop", RetryGraph);
  CHECK(RetryGraph.Ok());

  ExpectShape(RetryGraph, 2, 2, 3, 6, 2, 1, 2);
  ExpectBlock(RetryGraph, 0, 0x00, 5, 2, CfgBlockEnd::ConditionalBranch);
  ExpectBlock(RetryGraph, 1, 0x05, 1, 1, CfgBlockEnd::Return);
  CHECK_NUM_EQ(RetryGraph.Blocks[0].TargetOffset, 0x00);
  ExpectSuccessors(RetryGraph, 0, {0, 1});
  ExpectSuccessors(RetryGraph, 1, {});
  CHECK(RetryGraph.HasSelfEdge(0));
  CHECK(!RetryGraph.HasSelfEdge(1));
  CHECK_NUM_EQ(RetryGraph.ComponentNodeCounts[RetryGraph.ComponentOfBlock[0]], 1u);
  CHECK_NUM_EQ(RetryGraph.ComponentIsLoop[RetryGraph.ComponentOfBlock[0]], 1u);
  CHECK_NUM_EQ(RetryGraph.ComponentIsLoop[RetryGraph.ComponentOfBlock[1]], 0u);
  CheckInvariants(RetryGraph, "dec/jnz self loop invariants");

  const std::vector<uint8_t> Spin = Bytes({0xEB, 0xFE});
  const ControlFlowGraph SpinGraph = Build(Spin);
  PrintGraph("jmp $ spin", SpinGraph);
  CHECK(SpinGraph.Ok());
  ExpectShape(SpinGraph, 1, 1, 1, 2, 1, 1, 2);
  ExpectBlock(SpinGraph, 0, 0x00, 2, 1, CfgBlockEnd::DirectBranch);
  ExpectSuccessors(SpinGraph, 0, {0});
  CHECK(SpinGraph.HasSelfEdge(0));
  CHECK_NUM_EQ(SpinGraph.ComponentIsLoop[0], 1u);
  CheckInvariants(SpinGraph, "jmp $ spin invariants");
}

void TestReturnInMiddle() {
  Suite("Return in the middle produces two exit blocks");

  const std::vector<uint8_t> Code = Bytes({
      0x48, 0x85, 0xC9,
      0x74, 0x05,
      0x48, 0x8B, 0x41, 0x08,
      0xC3,
      0x33, 0xC0,
      0xC3,
  });
  const ControlFlowGraph Graph = Build(Code);
  PrintGraph("early return", Graph);
  CHECK(Graph.Ok());

  ExpectShape(Graph, 3, 2, 6, 13, 3, 0, 1);
  CHECK_NUM_EQ(Graph.ExitBlockCount, 2u);

  ExpectBlock(Graph, 0, 0x00, 5, 2, CfgBlockEnd::ConditionalBranch);
  ExpectBlock(Graph, 1, 0x05, 5, 2, CfgBlockEnd::Return);
  ExpectBlock(Graph, 2, 0x0A, 3, 2, CfgBlockEnd::Return);

  ExpectSuccessors(Graph, 0, {2, 1});
  ExpectSuccessors(Graph, 1, {});
  ExpectSuccessors(Graph, 2, {});
  ExpectPredecessors(Graph, 1, {0});
  ExpectPredecessors(Graph, 2, {0});

  CheckInvariants(Graph, "early return invariants");
}

void TestIndirectBranches() {
  Suite("Indirect jump is an unresolved terminator, calls are not terminators");

  const std::vector<uint8_t> JumpTable = Bytes({
      0x48, 0x8B, 0xC1,
      0x48, 0xFF, 0xE0,
      0xC3,
  });
  const ControlFlowGraph JumpGraph = Build(JumpTable);
  PrintGraph("jmp rax", JumpGraph);
  CHECK(JumpGraph.Ok());

  ExpectShape(JumpGraph, 1, 0, 2, 6, 1, 0, 1);
  ExpectBlock(JumpGraph, 0, 0x00, 6, 2, CfgBlockEnd::IndirectBranch);
  CHECK(JumpGraph.Blocks[0].IndirectTargetUnresolved);
  CHECK(!JumpGraph.Blocks[0].TargetOutsideRange);
  CHECK_NUM_EQ(JumpGraph.Blocks[0].TargetOffset, CfgNoTarget);
  CHECK_NUM_EQ(JumpGraph.UnresolvedIndirectBranchCount, 1u);
  CHECK_NUM_EQ(JumpGraph.ExitBlockCount, 1u);
  ExpectSuccessors(JumpGraph, 0, {});
  CheckInvariants(JumpGraph, "jmp rax invariants");

  const std::vector<uint8_t> IndirectCall = Bytes({0x48, 0xFF, 0xD0, 0xC3});
  const ControlFlowGraph IndirectCallGraph = Build(IndirectCall);
  PrintGraph("call rax", IndirectCallGraph);
  CHECK(IndirectCallGraph.Ok());
  ExpectShape(IndirectCallGraph, 1, 0, 2, 4, 1, 0, 1);
  ExpectBlock(IndirectCallGraph, 0, 0x00, 4, 2, CfgBlockEnd::Return);
  CHECK_NUM_EQ(IndirectCallGraph.CallCount, 1u);
  CHECK_NUM_EQ(IndirectCallGraph.UnresolvedIndirectBranchCount, 0u);
  CheckInvariants(IndirectCallGraph, "call rax invariants");

  const std::vector<uint8_t> DirectCall = Bytes({0xE8, 0x00, 0x00, 0x00, 0x00, 0xC3});
  const ControlFlowGraph DirectCallGraph = Build(DirectCall);
  PrintGraph("call rel32", DirectCallGraph);
  CHECK(DirectCallGraph.Ok());
  ExpectShape(DirectCallGraph, 1, 0, 2, 6, 1, 0, 1);
  ExpectBlock(DirectCallGraph, 0, 0x00, 6, 2, CfgBlockEnd::Return);
  CHECK_NUM_EQ(DirectCallGraph.CallCount, 1u);
  CheckInvariants(DirectCallGraph, "call rel32 invariants");

  const std::vector<uint8_t> MemoryJump = Bytes({0xFF, 0x24, 0xC5, 0x00, 0x10, 0x40, 0x00, 0xC3});
  const ControlFlowGraph MemoryJumpGraph = Build(MemoryJump);
  PrintGraph("jmp [rax*8+table]", MemoryJumpGraph);
  CHECK(MemoryJumpGraph.Ok());
  ExpectBlock(MemoryJumpGraph, 0, 0x00, 7, 1, CfgBlockEnd::IndirectBranch);
  CHECK(MemoryJumpGraph.Blocks[0].IndirectTargetUnresolved);
  CHECK_NUM_EQ(MemoryJumpGraph.UnresolvedIndirectBranchCount, 1u);
  ExpectSuccessors(MemoryJumpGraph, 0, {});
  CheckInvariants(MemoryJumpGraph, "jmp [rax*8+table] invariants");

  const std::vector<uint8_t> NoReturn = Bytes({0x48, 0x8B, 0xC1, 0x0F, 0x0B, 0xC3});
  const ControlFlowGraph NoReturnGraph = Build(NoReturn);
  PrintGraph("ud2", NoReturnGraph);
  CHECK(NoReturnGraph.Ok());
  ExpectBlock(NoReturnGraph, 0, 0x00, 5, 2, CfgBlockEnd::NoReturn);
  ExpectSuccessors(NoReturnGraph, 0, {});
  CheckInvariants(NoReturnGraph, "ud2 invariants");

  const std::vector<uint8_t> Trap = Bytes({0x90, 0xCC, 0xC3});
  const ControlFlowGraph TrapGraph = Build(Trap);
  PrintGraph("int3", TrapGraph);
  CHECK(TrapGraph.Ok());
  ExpectBlock(TrapGraph, 0, 0x00, 2, 2, CfgBlockEnd::NoReturn);
  ExpectSuccessors(TrapGraph, 0, {});
  CheckInvariants(TrapGraph, "int3 invariants");
}

void TestMidBlockSplit() {
  Suite("Branch target inside a decoded run forces a block split");

  const std::vector<uint8_t> Code = Bytes({
      0x90,
      0xEB, 0x01,
      0x90,
      0x48, 0x85, 0xC9,
      0x75, 0xF8,
      0xC3,
  });
  const ControlFlowGraph Graph = Build(Code);
  PrintGraph("split", Graph);
  CHECK(Graph.Ok());

  ExpectShape(Graph, 4, 4, 5, 9, 3, 1, 2);

  ExpectBlock(Graph, 0, 0x00, 1, 1, CfgBlockEnd::Fallthrough);
  ExpectBlock(Graph, 1, 0x01, 2, 1, CfgBlockEnd::DirectBranch);
  ExpectBlock(Graph, 2, 0x04, 5, 2, CfgBlockEnd::ConditionalBranch);
  ExpectBlock(Graph, 3, 0x09, 1, 1, CfgBlockEnd::Return);

  CHECK_NUM_EQ(Graph.Blocks[1].TargetOffset, 0x04);
  CHECK_NUM_EQ(Graph.Blocks[2].TargetOffset, 0x01);

  ExpectSuccessors(Graph, 0, {1});
  ExpectSuccessors(Graph, 1, {2});
  ExpectSuccessors(Graph, 2, {1, 3});
  ExpectSuccessors(Graph, 3, {});

  CHECK(Graph.HasSelfEdge(1) == false);
  CHECK(Graph.ComponentOfBlock[1] == Graph.ComponentOfBlock[2]);
  CHECK_NUM_EQ(Graph.ComponentNodeCounts[Graph.ComponentOfBlock[1]], 2u);
  CHECK_NUM_EQ(Graph.ComponentIsLoop[Graph.ComponentOfBlock[1]], 1u);

  CheckInvariants(Graph, "split invariants");
}

void TestDuplicateSuccessorCollapse() {
  Suite("Conditional branch whose target is its own fallthrough yields one edge");

  const std::vector<uint8_t> Code = Bytes({0x74, 0x00, 0xC3});
  const ControlFlowGraph Graph = Build(Code);
  PrintGraph("jz to fallthrough", Graph);
  CHECK(Graph.Ok());
  ExpectShape(Graph, 2, 1, 2, 3, 2, 0, 1);
  ExpectBlock(Graph, 0, 0x00, 2, 1, CfgBlockEnd::ConditionalBranch);
  ExpectBlock(Graph, 1, 0x02, 1, 1, CfgBlockEnd::Return);
  ExpectSuccessors(Graph, 0, {1});
  ExpectPredecessors(Graph, 1, {0});
  CheckInvariants(Graph, "jz to fallthrough invariants");

  const std::vector<uint8_t> JumpNext = Bytes({0xEB, 0x00, 0xC3});
  const ControlFlowGraph JumpNextGraph = Build(JumpNext);
  PrintGraph("jmp to next instruction", JumpNextGraph);
  CHECK(JumpNextGraph.Ok());
  ExpectShape(JumpNextGraph, 2, 1, 2, 3, 2, 0, 1);
  ExpectBlock(JumpNextGraph, 0, 0x00, 2, 1, CfgBlockEnd::DirectBranch);
  ExpectSuccessors(JumpNextGraph, 0, {1});
  CheckInvariants(JumpNextGraph, "jmp to next instruction invariants");
}

void TestUndecodableBytes() {
  Suite("Undecodable and truncated bytes");

  const std::vector<uint8_t> InvalidMid = Bytes({0x90, 0x06, 0xC3});
  const ControlFlowGraph InvalidGraph = Build(InvalidMid);
  PrintGraph("invalid byte mid block", InvalidGraph);
  CHECK(InvalidGraph.Ok());
  ExpectShape(InvalidGraph, 1, 0, 2, 2, 1, 0, 1);
  ExpectBlock(InvalidGraph, 0, 0x00, 2, 2, CfgBlockEnd::DecodeError);
  CHECK_NUM_EQ(InvalidGraph.DecodeErrorCount, 1u);
  ExpectSuccessors(InvalidGraph, 0, {});
  CheckInvariants(InvalidGraph, "invalid byte mid block invariants");

  const std::vector<uint8_t> Truncated = Bytes({0x90, 0x48, 0x8B});
  const ControlFlowGraph TruncatedGraph = Build(Truncated);
  PrintGraph("truncated instruction", TruncatedGraph);
  CHECK(TruncatedGraph.Ok());
  ExpectShape(TruncatedGraph, 1, 0, 2, 2, 1, 0, 1);
  ExpectBlock(TruncatedGraph, 0, 0x00, 2, 2, CfgBlockEnd::DecodeError);
  CHECK_NUM_EQ(TruncatedGraph.DecodeErrorCount, 1u);
  CheckInvariants(TruncatedGraph, "truncated instruction invariants");

  const std::vector<uint8_t> BadEntry = Bytes({0x06});
  const ControlFlowGraph BadEntryGraph = Build(BadEntry);
  PrintGraph("undecodable entry", BadEntryGraph);
  CHECK(BadEntryGraph.Status == CfgStatus::EntryUndecodable);
  CHECK(!BadEntryGraph.Ok());
  CHECK_NUM_EQ(BadEntryGraph.NodeCount, 0u);
  CHECK_NUM_EQ(BadEntryGraph.Blocks.size(), 0u);
  CHECK_NUM_EQ(BadEntryGraph.EdgeCount, 0u);
  CHECK_NUM_EQ(BadEntryGraph.CyclomaticComplexity, 0);
  CHECK_TEXT_EQ(CfgStatusName(BadEntryGraph.Status), "entry-undecodable");
  NoteText("error", BadEntryGraph.Error);

  const std::vector<uint8_t> TailAfterReturn = Bytes({0xC3, 0x06, 0x06, 0x06});
  const ControlFlowGraph TailGraph = Build(TailAfterReturn);
  PrintGraph("garbage after ret", TailGraph);
  CHECK(TailGraph.Ok());
  ExpectShape(TailGraph, 1, 0, 1, 1, 1, 0, 1);
  ExpectBlock(TailGraph, 0, 0x00, 1, 1, CfgBlockEnd::Return);
  CHECK_NUM_EQ(TailGraph.DecodeErrorCount, 0u);
  CheckInvariants(TailGraph, "garbage after ret invariants");
}

void TestEmptyAndNullRanges() {
  Suite("Empty range and null pointer");

  const std::vector<uint8_t> Empty;
  const ControlFlowGraph EmptyGraph =
      BuildControlFlowGraph(SharedBackend(), Empty.data(), Empty.size(), TestRuntimeBase);
  CHECK(EmptyGraph.Status == CfgStatus::EmptyRange);
  CHECK(!EmptyGraph.Ok());
  CHECK_NUM_EQ(EmptyGraph.NodeCount, 0u);
  CHECK_NUM_EQ(EmptyGraph.EdgeCount, 0u);
  CHECK_NUM_EQ(EmptyGraph.Blocks.size(), 0u);
  CHECK_TEXT_EQ(CfgStatusName(EmptyGraph.Status), "empty-range");
  NoteText("empty range error", EmptyGraph.Error);

  const ControlFlowGraph NullGraph =
      BuildControlFlowGraph(SharedBackend(), nullptr, 0, TestRuntimeBase);
  CHECK(NullGraph.Status == CfgStatus::EmptyRange);
  CHECK_NUM_EQ(NullGraph.NodeCount, 0u);

  const std::vector<uint8_t> Code = Bytes({0xC3});
  const ControlFlowGraph NullWithLength =
      BuildControlFlowGraph(SharedBackend(), nullptr, Code.size(), TestRuntimeBase);
  CHECK(NullWithLength.Status == CfgStatus::NullCode);
  CHECK_NUM_EQ(NullWithLength.NodeCount, 0u);
  CHECK_TEXT_EQ(CfgStatusName(NullWithLength.Status), "null-code");
  NoteText("null code error", NullWithLength.Error);

  const ControlFlowGraph StandaloneNullGraph = BuildControlFlowGraph(nullptr, Code.size(),
                                                                     TestRuntimeBase);
  CHECK(StandaloneNullGraph.Status == CfgStatus::NullCode);

  const std::vector<uint8_t> Oversized(CfgMaxRangeBytes + 1, 0x90);
  const ControlFlowGraph OversizedGraph =
      BuildControlFlowGraph(SharedBackend(), Oversized.data(), Oversized.size(), TestRuntimeBase);
  CHECK(OversizedGraph.Status == CfgStatus::RangeTooLarge);
  CHECK_NUM_EQ(OversizedGraph.NodeCount, 0u);
  CHECK_TEXT_EQ(CfgStatusName(OversizedGraph.Status), "range-too-large");
  NoteText("oversized range error", OversizedGraph.Error);

  const ControlFlowGraph StandaloneGraph = BuildControlFlowGraph(Code.data(), Code.size(),
                                                                 TestRuntimeBase);
  CHECK(StandaloneGraph.Ok());
  ExpectShape(StandaloneGraph, 1, 0, 1, 1, 1, 0, 1);
  CheckInvariants(StandaloneGraph, "backend-less overload invariants");
}

void TestTargetsOutsideRange() {
  Suite("Branch targets outside the given range");

  const std::vector<uint8_t> ForwardJump = Bytes({0xE9, 0x00, 0x01, 0x00, 0x00, 0x90, 0xC3});
  const ControlFlowGraph ForwardGraph = Build(ForwardJump);
  PrintGraph("jmp far forward", ForwardGraph);
  CHECK(ForwardGraph.Ok());
  ExpectShape(ForwardGraph, 1, 0, 1, 5, 1, 0, 1);
  ExpectBlock(ForwardGraph, 0, 0x00, 5, 1, CfgBlockEnd::DirectBranch);
  CHECK(ForwardGraph.Blocks[0].TargetOutsideRange);
  CHECK_NUM_EQ(ForwardGraph.Blocks[0].TargetOffset, CfgNoTarget);
  CHECK_NUM_EQ(ForwardGraph.OutOfRangeBranchCount, 1u);
  ExpectSuccessors(ForwardGraph, 0, {});
  CheckInvariants(ForwardGraph, "jmp far forward invariants");

  const std::vector<uint8_t> ForwardBranch =
      Bytes({0x0F, 0x85, 0x00, 0x01, 0x00, 0x00, 0xC3});
  const ControlFlowGraph BranchGraph = Build(ForwardBranch);
  PrintGraph("jnz far forward", BranchGraph);
  CHECK(BranchGraph.Ok());
  ExpectShape(BranchGraph, 2, 1, 2, 7, 2, 0, 1);
  ExpectBlock(BranchGraph, 0, 0x00, 6, 1, CfgBlockEnd::ConditionalBranch);
  ExpectBlock(BranchGraph, 1, 0x06, 1, 1, CfgBlockEnd::Return);
  CHECK(BranchGraph.Blocks[0].TargetOutsideRange);
  CHECK_NUM_EQ(BranchGraph.OutOfRangeBranchCount, 1u);
  ExpectSuccessors(BranchGraph, 0, {1});
  CheckInvariants(BranchGraph, "jnz far forward invariants");

  const std::vector<uint8_t> BackwardJump = Bytes({0xEB, 0xFC});
  const ControlFlowGraph BackwardGraph = Build(BackwardJump);
  PrintGraph("jmp before range start", BackwardGraph);
  CHECK(BackwardGraph.Ok());
  ExpectShape(BackwardGraph, 1, 0, 1, 2, 1, 0, 1);
  ExpectBlock(BackwardGraph, 0, 0x00, 2, 1, CfgBlockEnd::DirectBranch);
  CHECK(BackwardGraph.Blocks[0].TargetOutsideRange);
  CHECK_NUM_EQ(BackwardGraph.OutOfRangeBranchCount, 1u);
  ExpectSuccessors(BackwardGraph, 0, {});
  CheckInvariants(BackwardGraph, "jmp before range start invariants");
}

void TestWideBranchTable() {
  Suite("Every conditional jump form terminates its block with two successors");

  const std::vector<uint8_t> Code = Bytes({
      0x0F, 0x84, 0x05, 0x00, 0x00, 0x00,
      0xE9, 0x00, 0x00, 0x00, 0x00,
      0xC3,
  });
  const ControlFlowGraph Graph = Build(Code);
  PrintGraph("je rel32 over jmp", Graph);
  CHECK(Graph.Ok());
  ExpectShape(Graph, 3, 3, 3, 12, 3, 0, 2);
  ExpectBlock(Graph, 0, 0x00, 6, 1, CfgBlockEnd::ConditionalBranch);
  ExpectBlock(Graph, 1, 0x06, 5, 1, CfgBlockEnd::DirectBranch);
  ExpectBlock(Graph, 2, 0x0B, 1, 1, CfgBlockEnd::Return);
  CHECK_NUM_EQ(Graph.Blocks[0].TargetOffset, 0x0B);
  CHECK_NUM_EQ(Graph.Blocks[1].TargetOffset, 0x0B);
  ExpectSuccessors(Graph, 0, {2, 1});
  ExpectSuccessors(Graph, 1, {2});
  ExpectSuccessors(Graph, 2, {});
  ExpectPredecessors(Graph, 2, {0, 1});
  CHECK_NUM_EQ(Graph.DroppedSuccessorCount, 0u);
  CheckInvariants(Graph, "je rel32 over jmp invariants");

  const std::vector<uint8_t> LoopInstruction = Bytes({0xE2, 0xFE, 0xC3});
  const ControlFlowGraph LoopGraph = Build(LoopInstruction);
  PrintGraph("loop back to self", LoopGraph);
  CHECK(LoopGraph.Ok());
  ExpectBlock(LoopGraph, 0, 0x00, 2, 1, CfgBlockEnd::ConditionalBranch);
  CHECK_NUM_EQ(LoopGraph.Blocks[0].TargetOffset, 0x00);
  CHECK(LoopGraph.HasSelfEdge(0));
  ExpectSuccessors(LoopGraph, 0, {0, 1});
  CHECK_NUM_EQ(LoopGraph.LoopCount, 1u);
  CheckInvariants(LoopGraph, "loop back to self invariants");

  const std::vector<uint8_t> SyscallStub = Bytes({
      0x4C, 0x8B, 0xD1,
      0xB8, 0x10, 0x10, 0x00, 0x00,
      0xF6, 0x04, 0x25, 0x08, 0x03, 0xFE, 0x7F, 0x01,
      0x75, 0x02,
      0x0F, 0x05,
      0xC3,
  });
  const ControlFlowGraph StubGraph = Build(SyscallStub);
  PrintGraph("win32u style syscall stub", StubGraph);
  CHECK(StubGraph.Ok());
  ExpectShape(StubGraph, 3, 3, 6, 21, 3, 0, 2);
  ExpectBlock(StubGraph, 0, 0x00, 18, 4, CfgBlockEnd::ConditionalBranch);
  ExpectBlock(StubGraph, 1, 0x12, 2, 1, CfgBlockEnd::Fallthrough);
  ExpectBlock(StubGraph, 2, 0x14, 1, 1, CfgBlockEnd::Return);
  CHECK_NUM_EQ(StubGraph.Blocks[0].TargetOffset, 0x14);
  ExpectSuccessors(StubGraph, 0, {2, 1});
  ExpectSuccessors(StubGraph, 1, {2});
  ExpectSuccessors(StubGraph, 2, {});
  ExpectPredecessors(StubGraph, 2, {0, 1});
  CheckInvariants(StubGraph, "win32u style syscall stub invariants");
}

void TestOverlappingInstructions() {
  Suite("Branch target inside an instruction keeps blocks disjoint");

  const std::vector<uint8_t> Code = Bytes({
      0x0F, 0x84, 0x01, 0x00, 0x00, 0x00,
      0xE9, 0x01, 0x00, 0x00, 0x00,
      0xC3,
      0xC3,
  });
  const ControlFlowGraph Graph = Build(Code);
  PrintGraph("jump into instruction middle", Graph);
  CHECK(Graph.Ok());

  ExpectShape(Graph, 3, 2, 3, 12, 3, 0, 1);
  ExpectBlock(Graph, 0, 0x00, 6, 1, CfgBlockEnd::ConditionalBranch);
  ExpectBlock(Graph, 1, 0x06, 5, 1, CfgBlockEnd::DirectBranch);
  ExpectBlock(Graph, 2, 0x0C, 1, 1, CfgBlockEnd::Return);

  CHECK_NUM_EQ(Graph.Blocks[0].TargetOffset, 0x07);
  CHECK(Graph.BlockAtOffset(0x07) == CfgNoBlock);
  CHECK_NUM_EQ(Graph.OverlappingLeaderCount, 1u);
  CHECK_NUM_EQ(Graph.DroppedSuccessorCount, 1u);

  ExpectSuccessors(Graph, 0, {1});
  ExpectSuccessors(Graph, 1, {2});
  ExpectSuccessors(Graph, 2, {});

  uint32_t Covered = 0;
  for (const CfgBlock& Block : Graph.Blocks) {
    Covered += Block.Size;
  }
  CHECK(Covered <= Graph.RangeBytes);
  CheckInvariants(Graph, "jump into instruction middle invariants");
}

void TestRuntimeAddressDoesNotChangeShape() {
  Suite("Runtime base address does not change the block structure");

  const std::vector<uint8_t> Code = Bytes({
      0x48, 0x85, 0xC9,
      0x74, 0x06,
      0x48, 0x8B, 0x41, 0x08,
      0xEB, 0x02,
      0x33, 0xC0,
      0xC3,
  });

  const ControlFlowGraph Low = BuildControlFlowGraph(SharedBackend(), Code.data(), Code.size(), 0);
  const ControlFlowGraph High =
      BuildControlFlowGraph(SharedBackend(), Code.data(), Code.size(), 0x7FF600001000ull);

  CHECK(Low.Ok());
  CHECK(High.Ok());
  CHECK_NUM_EQ(Low.NodeCount, High.NodeCount);
  CHECK_NUM_EQ(Low.EdgeCount, High.EdgeCount);
  CHECK_NUM_EQ(Low.InstructionCount, High.InstructionCount);
  CHECK_NUM_EQ(Low.DecodedBytes, High.DecodedBytes);
  CHECK_NUM_EQ(Low.StronglyConnectedCount, High.StronglyConnectedCount);
  CHECK_NUM_EQ(Low.LoopCount, High.LoopCount);
  CHECK_NUM_EQ(Low.CyclomaticComplexity, High.CyclomaticComplexity);
  for (uint32_t Index = 0; Index < Low.NodeCount && Index < High.NodeCount; ++Index) {
    CHECK_NUM_EQ(Low.Blocks[Index].Offset, High.Blocks[Index].Offset);
    CHECK_NUM_EQ(Low.Blocks[Index].Size, High.Blocks[Index].Size);
    CHECK_NUM_EQ(Low.Blocks[Index].TargetOffset, High.Blocks[Index].TargetOffset);
    CHECK_TEXT_EQ(SuccessorText(Low, Index), SuccessorText(High, Index));
  }
  CheckInvariants(High, "high base invariants");
}

void TestBackendIsReentrant() {
  Suite("One backend serves repeated builds without state carry-over");

  const std::vector<uint8_t> Diamond = Bytes({
      0x48, 0x85, 0xC9,
      0x74, 0x06,
      0x48, 0x8B, 0x41, 0x08,
      0xEB, 0x02,
      0x33, 0xC0,
      0xC3,
  });

  const ControlFlowGraph First = Build(Diamond);
  const ControlFlowGraph Second = Build(Diamond);
  const ControlFlowGraph Third = Build(Diamond);

  CHECK_NUM_EQ(First.NodeCount, Second.NodeCount);
  CHECK_NUM_EQ(Second.NodeCount, Third.NodeCount);
  CHECK_NUM_EQ(First.EdgeCount, Third.EdgeCount);
  CHECK_TEXT_EQ(SuccessorText(First, 0), SuccessorText(Third, 0));
  CHECK_NUM_EQ(First.CyclomaticComplexity, Third.CyclomaticComplexity);
}

std::vector<uint8_t> MakeBranchChain(uint32_t Units, bool CloseWithBackEdge) {
  std::vector<uint8_t> Code;
  Code.reserve(static_cast<size_t>(Units) * 3 + 2);
  for (uint32_t Index = 0; Index < Units; ++Index) {
    const int Displacement = static_cast<int>(Units * 3) - static_cast<int>(Index * 3 + 3);
    Code.push_back(0x90);
    Code.push_back(0x74);
    Code.push_back(static_cast<uint8_t>(Displacement));
  }
  if (CloseWithBackEdge) {
    const int Back = -(static_cast<int>(Units * 3) + 2);
    Code.push_back(0xEB);
    Code.push_back(static_cast<uint8_t>(Back & 0xFF));
  } else {
    Code.push_back(0xC3);
  }
  return Code;
}

void TestGeneratedChains() {
  Suite("Generated chain of conditional blocks");

  const uint32_t Units = 40;

  const std::vector<uint8_t> Open = MakeBranchChain(Units, false);
  const ControlFlowGraph OpenGraph = Build(Open);
  PrintSummary("40 unit chain to shared exit", OpenGraph);
  CHECK(OpenGraph.Ok());
  CHECK_NUM_EQ(Open.size(), static_cast<size_t>(Units) * 3 + 1);
  ExpectShape(OpenGraph, Units + 1, Units * 2 - 1, Units * 2 + 1, Units * 3 + 1, Units + 1, 0,
              static_cast<long long>(Units));
  CHECK_NUM_EQ(OpenGraph.ConnectedComponentCount, 1u);
  CHECK_NUM_EQ(OpenGraph.ExitBlockCount, 1u);
  CHECK_NUM_EQ(OpenGraph.EntryBlock, 0u);

  ExpectBlock(OpenGraph, 0, 0x00, 3, 2, CfgBlockEnd::ConditionalBranch);
  ExpectBlock(OpenGraph, Units - 1, (Units - 1) * 3, 3, 2, CfgBlockEnd::ConditionalBranch);
  ExpectBlock(OpenGraph, Units, Units * 3, 1, 1, CfgBlockEnd::Return);
  CHECK_NUM_EQ(OpenGraph.Blocks[0].TargetOffset, Units * 3);
  ExpectSuccessors(OpenGraph, 0, {Units, 1});
  ExpectSuccessors(OpenGraph, Units - 1, {Units});
  ExpectSuccessors(OpenGraph, Units, {});
  CHECK_NUM_EQ(OpenGraph.Blocks[Units].PredecessorCount, Units);
  ExpectPredecessors(OpenGraph, 1, {0});
  ExpectPredecessors(OpenGraph, Units - 1, {Units - 2});
  CheckInvariants(OpenGraph, "40 unit chain to shared exit invariants");

  const std::vector<uint8_t> Closed = MakeBranchChain(Units, true);
  const ControlFlowGraph ClosedGraph = Build(Closed);
  PrintSummary("40 unit chain closing on itself", ClosedGraph);
  CHECK(ClosedGraph.Ok());
  CHECK_NUM_EQ(Closed.size(), static_cast<size_t>(Units) * 3 + 2);
  ExpectShape(ClosedGraph, Units + 1, Units * 2, Units * 2 + 1, Units * 3 + 2, 1, 1,
              static_cast<long long>(Units) + 1);
  CHECK_NUM_EQ(ClosedGraph.ConnectedComponentCount, 1u);
  CHECK_NUM_EQ(ClosedGraph.ExitBlockCount, 0u);
  CHECK_NUM_EQ(ClosedGraph.StronglyConnectedCount, 1u);
  CHECK_NUM_EQ(ClosedGraph.ComponentNodeCounts[0], Units + 1);
  CHECK_NUM_EQ(ClosedGraph.ComponentIsLoop[0], 1u);
  ExpectBlock(ClosedGraph, Units, Units * 3, 2, 1, CfgBlockEnd::DirectBranch);
  CHECK_NUM_EQ(ClosedGraph.Blocks[Units].TargetOffset, 0);
  ExpectSuccessors(ClosedGraph, Units, {0});
  ExpectSuccessors(ClosedGraph, 0, {Units, 1});
  for (uint32_t Index = 0; Index < ClosedGraph.NodeCount; ++Index) {
    CHECK_NUM_EQ(ClosedGraph.ComponentOfBlock[Index], 0u);
  }
  CheckInvariants(ClosedGraph, "40 unit chain closing on itself invariants");
}

void TestBlockLimitIsReported() {
  Suite("Block limit is reported instead of silently truncating");

  const uint32_t Units = CfgMaxBlocks;
  std::vector<uint8_t> Code;
  Code.reserve(static_cast<size_t>(Units) * 7 + 1);
  for (uint32_t Index = 0; Index < Units; ++Index) {
    const int32_t Displacement =
        static_cast<int32_t>(Units * 7) - static_cast<int32_t>(Index * 7 + 7);
    Code.push_back(0x90);
    Code.push_back(0x0F);
    Code.push_back(0x84);
    Code.push_back(static_cast<uint8_t>(Displacement & 0xFF));
    Code.push_back(static_cast<uint8_t>((Displacement >> 8) & 0xFF));
    Code.push_back(static_cast<uint8_t>((Displacement >> 16) & 0xFF));
    Code.push_back(static_cast<uint8_t>((Displacement >> 24) & 0xFF));
  }
  Code.push_back(0xC3);

  CHECK(Code.size() <= CfgMaxRangeBytes);
  const ControlFlowGraph Graph = Build(Code);
  CHECK(Graph.Status == CfgStatus::BlockLimitReached);
  CHECK(!Graph.Ok());
  CHECK_TEXT_EQ(CfgStatusName(Graph.Status), "block-limit-reached");
  NoteText("error", Graph.Error);
  NoteNumber("range bytes", static_cast<long long>(Code.size()));
  NoteNumber("nodes", Graph.NodeCount);
  NoteNumber("edges", Graph.EdgeCount);
  NoteNumber("instructions", Graph.InstructionCount);
  NoteNumber("decoded bytes", Graph.DecodedBytes);
  NoteNumber("strongly connected", Graph.StronglyConnectedCount);
  NoteNumber("loops", Graph.LoopCount);
  NoteNumber("cyclomatic complexity", static_cast<long long>(Graph.CyclomaticComplexity));

  CHECK_NUM_EQ(Graph.NodeCount, CfgMaxBlocks);
  CHECK(Graph.EdgeCount > 0);
  CHECK(Graph.InstructionCount > 0);
  CHECK(Graph.DecodedBytes <= Code.size());
  CHECK_NUM_EQ(Graph.SuccessorBlocks.size(), Graph.EdgeCount);
  CHECK_NUM_EQ(Graph.PredecessorBlocks.size(), Graph.EdgeCount);
  CHECK_NUM_EQ(Graph.ComponentOfBlock.size(), Graph.NodeCount);
  CHECK_NUM_EQ(Graph.StronglyConnectedCount, Graph.ComponentNodeCounts.size());

  uint64_t SuccessorTotal = 0;
  uint64_t PredecessorTotal = 0;
  for (uint32_t Index = 0; Index < Graph.NodeCount; ++Index) {
    SuccessorTotal += Graph.Blocks[Index].SuccessorCount;
    PredecessorTotal += Graph.Blocks[Index].PredecessorCount;
    for (const uint32_t Successor : Graph.BlockSuccessors(Index)) {
      CHECK(Successor < Graph.NodeCount);
    }
  }
  CHECK_NUM_EQ(SuccessorTotal, Graph.EdgeCount);
  CHECK_NUM_EQ(PredecessorTotal, Graph.EdgeCount);
}

void TestInstructionLimitIsReported() {
  Suite("Instruction limit is reported with a usable partial graph");

  const size_t RangeBytes = static_cast<size_t>(CfgMaxInstructions) + 4096;
  CHECK(RangeBytes <= CfgMaxRangeBytes);
  const std::vector<uint8_t> Code(RangeBytes, 0x90);

  const ControlFlowGraph Graph = Build(Code);
  CHECK(Graph.Status == CfgStatus::InstructionLimitReached);
  CHECK(!Graph.Ok());
  CHECK_TEXT_EQ(CfgStatusName(Graph.Status), "instruction-limit-reached");
  NoteText("error", Graph.Error);
  NoteNumber("range bytes", static_cast<long long>(RangeBytes));
  NoteNumber("nodes", Graph.NodeCount);
  NoteNumber("edges", Graph.EdgeCount);
  NoteNumber("instructions", Graph.InstructionCount);
  NoteNumber("decoded bytes", Graph.DecodedBytes);
  NoteNumber("dropped successors", Graph.DroppedSuccessorCount);

  CHECK(!Graph.Error.empty());
  CHECK_NUM_EQ(Graph.NodeCount, 1u);
  CHECK_NUM_EQ(Graph.RangeBytes, RangeBytes);
  CHECK_NUM_EQ(Graph.EdgeCount, 0u);
  CHECK_NUM_EQ(Graph.ExitBlockCount, 1u);
  if (Graph.NodeCount == 1) {
    CHECK_NUM_EQ(Graph.Blocks[0].Offset, 0u);
    CHECK_TEXT_EQ(CfgBlockEndName(Graph.Blocks[0].End), CfgBlockEndName(CfgBlockEnd::RangeEnd));
    CHECK(Graph.Blocks[0].InstructionCount > 0);
    CHECK(Graph.Blocks[0].InstructionCount <= CfgMaxInstructions);
    CHECK_NUM_EQ(Graph.Blocks[0].Size, Graph.Blocks[0].InstructionCount);
    CHECK_NUM_EQ(Graph.DecodedBytes, Graph.Blocks[0].Size);
    CHECK(Graph.DecodedBytes < RangeBytes);
  }
  CHECK_NUM_EQ(Graph.DroppedSuccessorCount, 1u);
}

struct CorpusCandidate {
  uint32_t Rva = 0;
  std::string Name;
};

struct CorpusOutcome {
  uint32_t Rva = 0;
  uint32_t Length = 0;
  uint32_t Nodes = 0;
  uint32_t Edges = 0;
  uint32_t Instructions = 0;
  uint32_t StronglyConnected = 0;
  uint32_t Loops = 0;
  int64_t Complexity = 0;
  std::string Name;
};

uint32_t CorpusRangeLength(const PeImage& Image, uint32_t Rva, uint32_t Cap,
                           uint32_t& OutFileOffset) {
  uint64_t Limit = Cap;
  const PeSection* Owner = Image.SectionContainingRva(Rva);
  if (Owner != nullptr && Owner->VirtualEnd() > Rva) {
    const uint64_t SectionRoom = Owner->VirtualEnd() - Rva;
    if (SectionRoom < Limit) {
      Limit = SectionRoom;
    }
  }
  while (Limit >= 16) {
    uint32_t FileOffset = 0;
    if (Image.RvaRangeToOffset(Rva, Limit, FileOffset) &&
        static_cast<uint64_t>(FileOffset) + Limit <= Image.Bytes().size()) {
      OutFileOffset = FileOffset;
      return static_cast<uint32_t>(Limit);
    }
    Limit /= 2;
  }
  return 0;
}

void TestRealBinaryFunctions() {
  Suite("Real binary: win32u.dll exported functions");

  if (!std::filesystem::exists(CorpusWin32u)) {
    ++SuitesSkipped;
    std::printf("  SKIP corpus file is absent: %s\n", CorpusWin32u);
    return;
  }

  PeImage Image;
  const PeLoadResult Load = Image.Load(CorpusWin32u);
  if (!Load.Ok) {
    ++SuitesSkipped;
    std::printf("  SKIP corpus file did not parse: %s\n", Load.Error.c_str());
    return;
  }

  std::vector<CorpusCandidate> Candidates;
  for (const PeExport& Export : Image.Exports) {
    if (!Export.IsNamed || Export.IsForwarder || Export.Rva == 0) {
      continue;
    }
    bool Duplicate = false;
    for (const CorpusCandidate& Existing : Candidates) {
      if (Existing.Rva == Export.Rva) {
        Duplicate = true;
        break;
      }
    }
    if (Duplicate) {
      continue;
    }
    CorpusCandidate Candidate;
    Candidate.Rva = Export.Rva;
    Candidate.Name = std::string(Export.Name);
    Candidates.push_back(std::move(Candidate));
  }

  if (Candidates.empty()) {
    ++SuitesSkipped;
    std::printf("  SKIP corpus file exports no named functions\n");
    return;
  }

  std::sort(Candidates.begin(), Candidates.end(),
            [](const CorpusCandidate& Left, const CorpusCandidate& Right) {
              return Left.Rva < Right.Rva;
            });

  NoteNumber("named exports", static_cast<long long>(Candidates.size()));

  uint64_t TotalNodes = 0;
  uint64_t TotalEdges = 0;
  uint64_t TotalInstructions = 0;
  uint64_t TotalDecodedBytes = 0;
  uint32_t Built = 0;
  uint32_t Unmapped = 0;
  uint32_t MaxNodes = 0;
  uint32_t WithLoops = 0;
  uint32_t WithIndirectBranch = 0;
  uint32_t WithDecodeErrors = 0;
  uint32_t WithDroppedEdges = 0;
  uint32_t WithOverlap = 0;
  std::vector<CorpusOutcome> Outcomes;
  Outcomes.reserve(Candidates.size());

  for (const CorpusCandidate& Candidate : Candidates) {
    uint32_t FileOffset = 0;
    const uint32_t Length = CorpusRangeLength(Image, Candidate.Rva, 4096, FileOffset);
    if (Length == 0) {
      ++Unmapped;
      continue;
    }

    const uint64_t RuntimeAddress = Image.Headers.ImageBase + Candidate.Rva;
    const ControlFlowGraph Graph = BuildControlFlowGraph(
        SharedBackend(), Image.Bytes().data() + FileOffset, Length, RuntimeAddress);

    CheckInvariants(Graph, Candidate.Name.c_str());
    CHECK(Graph.NodeCount > 0);
    if (Graph.NodeCount > 0) {
      CHECK(Graph.Blocks[0].Offset == 0);
      CHECK(Graph.EntryBlock == 0);
      CHECK(Graph.InstructionCount > 0);
      CHECK(Graph.DecodedBytes <= Length);
      CHECK(Graph.StronglyConnectedCount <= Graph.NodeCount);
      CHECK(Graph.LoopCount <= Graph.StronglyConnectedCount);
      for (uint32_t Block = 0; Block < Graph.NodeCount; ++Block) {
        CHECK(Graph.Blocks[Block].InstructionCount > 0);
        CHECK(Graph.Blocks[Block].SuccessorCount <= CfgSuccessorCapacity);
      }
    }

    ++Built;
    TotalNodes += Graph.NodeCount;
    TotalEdges += Graph.EdgeCount;
    TotalInstructions += Graph.InstructionCount;
    TotalDecodedBytes += Graph.DecodedBytes;
    if (Graph.NodeCount > MaxNodes) {
      MaxNodes = Graph.NodeCount;
    }
    if (Graph.LoopCount > 0) {
      ++WithLoops;
    }
    if (Graph.UnresolvedIndirectBranchCount > 0) {
      ++WithIndirectBranch;
    }
    if (Graph.DecodeErrorCount > 0) {
      ++WithDecodeErrors;
    }
    if (Graph.DroppedSuccessorCount > 0) {
      ++WithDroppedEdges;
    }
    if (Graph.OverlappingLeaderCount > 0) {
      ++WithOverlap;
    }

    CorpusOutcome Outcome;
    Outcome.Rva = Candidate.Rva;
    Outcome.Length = Length;
    Outcome.Nodes = Graph.NodeCount;
    Outcome.Edges = Graph.EdgeCount;
    Outcome.Instructions = Graph.InstructionCount;
    Outcome.StronglyConnected = Graph.StronglyConnectedCount;
    Outcome.Loops = Graph.LoopCount;
    Outcome.Complexity = Graph.CyclomaticComplexity;
    Outcome.Name = Candidate.Name;
    Outcomes.push_back(std::move(Outcome));
  }

  NoteNumber("graphs built", Built);
  NoteNumber("unmapped rvas", Unmapped);
  NoteNumber("total nodes", static_cast<long long>(TotalNodes));
  NoteNumber("total edges", static_cast<long long>(TotalEdges));
  NoteNumber("total instructions", static_cast<long long>(TotalInstructions));
  NoteNumber("total decoded bytes", static_cast<long long>(TotalDecodedBytes));
  NoteNumber("largest node count", MaxNodes);
  NoteNumber("graphs with loops", WithLoops);
  NoteNumber("graphs with indirect jmp", WithIndirectBranch);
  NoteNumber("graphs with decode errors", WithDecodeErrors);
  NoteNumber("graphs with dropped edges", WithDroppedEdges);
  NoteNumber("graphs with overlap", WithOverlap);

  CHECK(Built > 0);
  CHECK(MaxNodes >= 3);
  CHECK(TotalNodes >= Built);
  CHECK(TotalDecodedBytes > 0);

  std::sort(Outcomes.begin(), Outcomes.end(),
            [](const CorpusOutcome& Left, const CorpusOutcome& Right) {
              if (Left.Nodes != Right.Nodes) {
                return Left.Nodes > Right.Nodes;
              }
              return Left.Rva < Right.Rva;
            });

  const size_t Detailed = Outcomes.size() < 5 ? Outcomes.size() : static_cast<size_t>(5);
  for (size_t Index = 0; Index < Detailed; ++Index) {
    const CorpusOutcome& Outcome = Outcomes[Index];
    uint32_t FileOffset = 0;
    const uint32_t Length = CorpusRangeLength(Image, Outcome.Rva, Outcome.Length, FileOffset);
    if (Length == 0) {
      continue;
    }
    const ControlFlowGraph Graph = BuildControlFlowGraph(
        SharedBackend(), Image.Bytes().data() + FileOffset, Length,
        Image.Headers.ImageBase + Outcome.Rva);

    std::printf("  --- %s rva=0x%x base=0x%llx range=%u nodes=%u edges=%u instrs=%u scc=%u "
                "loops=%u cc=%lld\n",
                Outcome.Name.c_str(), Outcome.Rva,
                static_cast<unsigned long long>(Image.Headers.ImageBase + Outcome.Rva), Length,
                Outcome.Nodes, Outcome.Edges, Outcome.Instructions, Outcome.StronglyConnected,
                Outcome.Loops, static_cast<long long>(Outcome.Complexity));
    PrintGraph("win32u", Graph);
  }
}

void TestRealBinaryCodeSection() {
  Suite("Real binary: win32u.dll code section stride scan");

  if (!std::filesystem::exists(CorpusWin32u)) {
    ++SuitesSkipped;
    std::printf("  SKIP corpus file is absent: %s\n", CorpusWin32u);
    return;
  }

  PeImage Image;
  const PeLoadResult Load = Image.Load(CorpusWin32u);
  if (!Load.Ok) {
    ++SuitesSkipped;
    std::printf("  SKIP corpus file did not parse: %s\n", Load.Error.c_str());
    return;
  }

  const PeSection* CodeSection = nullptr;
  for (const PeSection& Section : Image.Sections) {
    if ((Section.Characteristics & 0x20000000u) == 0 || (Section.Characteristics & 0x20u) == 0) {
      continue;
    }
    if (CodeSection == nullptr || Section.VirtualSize > CodeSection->VirtualSize) {
      CodeSection = &Section;
    }
  }
  if (CodeSection == nullptr || CodeSection->VirtualSize < 256) {
    ++SuitesSkipped;
    std::printf("  SKIP corpus file has no usable code section\n");
    return;
  }

  const uint64_t Span = CodeSection->VirtualSize;
  uint64_t Stride = Span / 64;
  if (Stride < 0x40) {
    Stride = 0x40;
  }

  NoteText("code section", std::string(CodeSection->Name));
  NoteNumber("section virtual size", static_cast<long long>(Span));
  NoteNumber("stride", static_cast<long long>(Stride));

  uint64_t TotalNodes = 0;
  uint64_t TotalEdges = 0;
  uint64_t TotalInstructions = 0;
  uint32_t Built = 0;
  uint32_t MaxNodes = 0;
  uint32_t MaxLoops = 0;
  uint32_t WithLoops = 0;
  uint32_t WithIndirectBranch = 0;
  uint32_t WithDecodeErrors = 0;
  uint32_t WithDroppedEdges = 0;
  uint32_t WithOverlap = 0;
  uint32_t MisalignedEntries = 0;
  uint32_t UnexpectedStatus = 0;
  uint32_t MaxComplexity = 0;
  CorpusOutcome Largest;

  for (uint64_t Delta = 0; Delta + 16 < Span; Delta += Stride) {
    const uint32_t Rva = CodeSection->VirtualAddress + static_cast<uint32_t>(Delta);
    uint32_t FileOffset = 0;
    const uint32_t Length = CorpusRangeLength(Image, Rva, 4096, FileOffset);
    if (Length == 0) {
      continue;
    }

    const uint64_t RuntimeAddress = Image.Headers.ImageBase + Rva;
    const ControlFlowGraph Graph = BuildControlFlowGraph(
        SharedBackend(), Image.Bytes().data() + FileOffset, Length, RuntimeAddress);

    const std::string Label = "stride rva 0x" + std::to_string(Rva);
    if (!Graph.Ok()) {
      if (Graph.Status == CfgStatus::EntryUndecodable) {
        ++MisalignedEntries;
      } else {
        ++UnexpectedStatus;
      }
      std::printf("    %s status=%s error=%s\n", Label.c_str(), CfgStatusName(Graph.Status),
                  Graph.Error.c_str());
      continue;
    }
    CheckInvariants(Graph, Label.c_str());

    ++Built;
    TotalNodes += Graph.NodeCount;
    TotalEdges += Graph.EdgeCount;
    TotalInstructions += Graph.InstructionCount;
    if (Graph.NodeCount > MaxNodes) {
      MaxNodes = Graph.NodeCount;
      Largest.Rva = Rva;
      Largest.Length = Length;
      Largest.Nodes = Graph.NodeCount;
      Largest.Edges = Graph.EdgeCount;
      Largest.Instructions = Graph.InstructionCount;
      Largest.StronglyConnected = Graph.StronglyConnectedCount;
      Largest.Loops = Graph.LoopCount;
      Largest.Complexity = Graph.CyclomaticComplexity;
    }
    if (Graph.LoopCount > MaxLoops) {
      MaxLoops = Graph.LoopCount;
    }
    if (Graph.LoopCount > 0) {
      ++WithLoops;
    }
    if (Graph.UnresolvedIndirectBranchCount > 0) {
      ++WithIndirectBranch;
    }
    if (Graph.DecodeErrorCount > 0) {
      ++WithDecodeErrors;
    }
    if (Graph.DroppedSuccessorCount > 0) {
      ++WithDroppedEdges;
    }
    if (Graph.OverlappingLeaderCount > 0) {
      ++WithOverlap;
    }
    if (Graph.CyclomaticComplexity > static_cast<int64_t>(MaxComplexity)) {
      MaxComplexity = static_cast<uint32_t>(Graph.CyclomaticComplexity);
    }

    std::printf("  rva=0x%06x range=%-5u nodes=%-4u edges=%-4u instrs=%-5u scc=%-4u loops=%-3u "
                "cc=%-4lld indirect=%-2u decode-errors=%-2u dropped=%-2u overlap=%u\n",
                Rva, Length, Graph.NodeCount, Graph.EdgeCount, Graph.InstructionCount,
                Graph.StronglyConnectedCount, Graph.LoopCount,
                static_cast<long long>(Graph.CyclomaticComplexity),
                Graph.UnresolvedIndirectBranchCount, Graph.DecodeErrorCount,
                Graph.DroppedSuccessorCount, Graph.OverlappingLeaderCount);
  }

  NoteNumber("graphs built", Built);
  NoteNumber("misaligned entries", MisalignedEntries);
  NoteNumber("unexpected statuses", UnexpectedStatus);
  NoteNumber("total nodes", static_cast<long long>(TotalNodes));
  NoteNumber("total edges", static_cast<long long>(TotalEdges));
  NoteNumber("total instructions", static_cast<long long>(TotalInstructions));
  NoteNumber("largest node count", MaxNodes);
  NoteNumber("largest loop count", MaxLoops);
  NoteNumber("largest complexity", MaxComplexity);
  NoteNumber("graphs with loops", WithLoops);
  NoteNumber("graphs with indirect jmp", WithIndirectBranch);
  NoteNumber("graphs with decode errors", WithDecodeErrors);
  NoteNumber("graphs with dropped edges", WithDroppedEdges);
  NoteNumber("graphs with overlap", WithOverlap);

  CHECK(Built > 0);
  CHECK(UnexpectedStatus == 0);
  CHECK(MaxNodes >= 3);
  CHECK(TotalInstructions > TotalNodes);
  CHECK(TotalNodes >= Built);

  if (Largest.Nodes > 0) {
    uint32_t FileOffset = 0;
    const uint32_t Length = CorpusRangeLength(Image, Largest.Rva, Largest.Length, FileOffset);
    if (Length > 0) {
      const ControlFlowGraph Graph = BuildControlFlowGraph(
          SharedBackend(), Image.Bytes().data() + FileOffset, Length,
          Image.Headers.ImageBase + Largest.Rva);
      std::printf("  --- largest graph at rva=0x%x range=%u\n", Largest.Rva, Length);
      PrintSummary("win32u", Graph);
      const uint32_t Shown = Graph.NodeCount < 24 ? Graph.NodeCount : 24;
      for (uint32_t Index = 0; Index < Shown; ++Index) {
        const CfgBlock& Block = Graph.Blocks[Index];
        std::printf("    b%-3u off=0x%04x size=%-4u instrs=%-4u end=%-19s succ=[%s] pred=[%s]\n",
                    Index, Block.Offset, Block.Size, Block.InstructionCount,
                    CfgBlockEndName(Block.End), SuccessorText(Graph, Index).c_str(),
                    PredecessorText(Graph, Index).c_str());
      }
      if (Shown < Graph.NodeCount) {
        std::printf("    ... %u further blocks\n", Graph.NodeCount - Shown);
      }
    }
  }
}

}

int main() {
  TestStraightLine();
  TestSimpleIfDiamond();
  TestCountedLoop();
  TestSelfLoop();
  TestReturnInMiddle();
  TestIndirectBranches();
  TestMidBlockSplit();
  TestDuplicateSuccessorCollapse();
  TestUndecodableBytes();
  TestEmptyAndNullRanges();
  TestTargetsOutsideRange();
  TestWideBranchTable();
  TestOverlappingInstructions();
  TestGeneratedChains();
  TestBlockLimitIsReported();
  TestInstructionLimitIsReported();
  TestRuntimeAddressDoesNotChangeShape();
  TestBackendIsReentrant();
  TestRealBinaryFunctions();
  TestRealBinaryCodeSection();

  std::printf("\n%d checks run, %d failed, %d suites skipped\n", ChecksRun, ChecksFailed,
              SuitesSkipped);
  return ChecksFailed == 0 ? 0 : 1;
}
