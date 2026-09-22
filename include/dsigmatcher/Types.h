#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace DSig {

struct PackedString {
  uint32_t Offset = 0;
  uint32_t Length = 0;
};

class StringPool {
public:
  PackedString Append(std::string_view Text) {
    PackedString Result;
    Result.Offset = static_cast<uint32_t>(Storage_.size());
    Result.Length = static_cast<uint32_t>(Text.size());
    Storage_.insert(Storage_.end(), Text.begin(), Text.end());
    return Result;
  }

  std::string_view View(PackedString Slot) const {
    if (Slot.Length == 0) {
      return std::string_view();
    }
    return std::string_view(Storage_.data() + Slot.Offset, Slot.Length);
  }

  size_t Bytes() const { return Storage_.size(); }

private:
  std::vector<char> Storage_;
};

enum class MatchCategory : uint8_t {
  Best = 0,
  Partial = 1,
  Unreliable = 2
};

struct Match {
  uint32_t Index1 = 0;
  uint32_t Index2 = 0;
  uint16_t HeuristicId = 0;
  float Ratio = 1.0f;
  MatchCategory Category = MatchCategory::Best;
};

struct FunctionTable {
  StringPool Pool;

  std::vector<int64_t> Id;
  std::vector<int64_t> Nodes;
  std::vector<int64_t> Edges;
  std::vector<int64_t> Instructions;
  std::vector<int64_t> Size;
  std::vector<int64_t> CyclomaticComplexity;
  std::vector<int64_t> Indegree;
  std::vector<int64_t> Outdegree;
  std::vector<int64_t> ConstantsCount;
  std::vector<int64_t> Loops;
  std::vector<int64_t> StronglyConnected;
  std::vector<int64_t> PseudocodeLines;

  std::vector<PackedString> Name;
  std::vector<PackedString> Address;
  std::vector<PackedString> Rva;
  std::vector<PackedString> SegmentRva;
  std::vector<PackedString> MangledFunction;
  std::vector<PackedString> BytesHash;
  std::vector<PackedString> FunctionHash;
  std::vector<PackedString> KghHash;
  std::vector<PackedString> MdIndex;
  std::vector<PackedString> Mnemonics;
  std::vector<PackedString> CleanAssembly;
  std::vector<PackedString> CleanPseudo;
  std::vector<PackedString> CleanMicrocode;
  std::vector<PackedString> SourceFile;

  size_t Count() const { return Id.size(); }

  std::string_view Text(const PackedString& Slot) const { return Pool.View(Slot); }

  void Reserve(size_t Rows) {
    Id.reserve(Rows);
    Nodes.reserve(Rows);
    Edges.reserve(Rows);
    Instructions.reserve(Rows);
    Size.reserve(Rows);
    CyclomaticComplexity.reserve(Rows);
    Indegree.reserve(Rows);
    Outdegree.reserve(Rows);
    ConstantsCount.reserve(Rows);
    Loops.reserve(Rows);
    StronglyConnected.reserve(Rows);
    PseudocodeLines.reserve(Rows);
    Name.reserve(Rows);
    Address.reserve(Rows);
    Rva.reserve(Rows);
    SegmentRva.reserve(Rows);
    MangledFunction.reserve(Rows);
    BytesHash.reserve(Rows);
    FunctionHash.reserve(Rows);
    KghHash.reserve(Rows);
    MdIndex.reserve(Rows);
    Mnemonics.reserve(Rows);
    CleanAssembly.reserve(Rows);
    CleanPseudo.reserve(Rows);
    CleanMicrocode.reserve(Rows);
    SourceFile.reserve(Rows);
  }

  void Resize(size_t Rows) {
    Id.resize(Rows);
    Nodes.resize(Rows);
    Edges.resize(Rows);
    Instructions.resize(Rows);
    Size.resize(Rows);
    CyclomaticComplexity.resize(Rows);
    Indegree.resize(Rows);
    Outdegree.resize(Rows);
    ConstantsCount.resize(Rows);
    Loops.resize(Rows);
    StronglyConnected.resize(Rows);
    PseudocodeLines.resize(Rows);
    Name.resize(Rows);
    Address.resize(Rows);
    Rva.resize(Rows);
    SegmentRva.resize(Rows);
    MangledFunction.resize(Rows);
    BytesHash.resize(Rows);
    FunctionHash.resize(Rows);
    KghHash.resize(Rows);
    MdIndex.resize(Rows);
    Mnemonics.resize(Rows);
    CleanAssembly.resize(Rows);
    CleanPseudo.resize(Rows);
    CleanMicrocode.resize(Rows);
    SourceFile.resize(Rows);
  }
};

struct ProgramInfo {
  std::string Processor;
  std::string Md5Sum;
  std::string CallgraphPrimes;
  bool Present = false;
};

}
