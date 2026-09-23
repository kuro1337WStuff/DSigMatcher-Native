#include "dsigmatcher/Synth.h"

#include <algorithm>
#include <cstdio>
#include <string>
#include <utility>
#include <vector>

namespace DSig {

namespace {

class SplitMix64 {
public:
  explicit SplitMix64(uint64_t Seed) : State_(Seed) {}

  uint64_t Next() {
    State_ += 0x9E3779B97F4A7C15ull;
    uint64_t Value = State_;
    Value = (Value ^ (Value >> 30)) * 0xBF58476D1CE4E5B9ull;
    Value = (Value ^ (Value >> 27)) * 0x94D049BB133111EBull;
    return Value ^ (Value >> 31);
  }

  size_t Below(size_t Bound) {
    return Bound == 0 ? 0 : static_cast<size_t>(Next() % Bound);
  }

  size_t Range(size_t Low, size_t High) {
    return High <= Low ? Low : Low + Below(High - Low + 1);
  }

private:
  uint64_t State_;
};

std::string HexToken(uint64_t High, uint64_t Low) {
  char Buffer[33];
  std::snprintf(Buffer, sizeof(Buffer), "%016llx%016llx",
                static_cast<unsigned long long>(High), static_cast<unsigned long long>(Low));
  return std::string(Buffer);
}

std::string AddressToken(uint64_t Value) {
  char Buffer[24];
  std::snprintf(Buffer, sizeof(Buffer), "0x%llX", static_cast<unsigned long long>(Value));
  return std::string(Buffer);
}

enum class Kind { Identical, Recompiled, Ambiguous, OrphanReference, OrphanTarget };

struct Spec {
  Kind Kind = Kind::Identical;
  uint64_t Body = 0;
  uint64_t GroupKey = 0;
  size_t Instructions = 8;
  size_t Nodes = 3;
  size_t PseudoLines = 4;
  bool StableAddress = false;
  uint64_t ReferenceAddress = 0;
  uint64_t TargetAddress = 0;
};

struct SpecHashes {
  std::string BytesHash;
  std::string FunctionHash;
  std::string KghHash;
  std::string CleanAssembly;
  std::string CleanPseudo;
  std::string CleanMicrocode;
  std::string Mnemonics;
};

std::string MakeListing(uint64_t Seed, size_t Lines, size_t BytesPerLine) {
  SplitMix64 Rng(Seed);
  std::string Result;
  Result.reserve(Lines * (BytesPerLine + 1));

  for (size_t Line = 0; Line < Lines; ++Line) {
    size_t Filled = 0;
    while (Filled + 16 <= BytesPerLine) {
      char Buffer[17];
      std::snprintf(Buffer, sizeof(Buffer), "%016llx",
                    static_cast<unsigned long long>(Rng.Next()));
      Result.append(Buffer, 16);
      Filled += 16;
    }
    while (Filled < BytesPerLine) {
      char Buffer[3];
      std::snprintf(Buffer, sizeof(Buffer), "%02x",
                    static_cast<unsigned>(Rng.Next() & 0xFFull));
      Result.append(Buffer, 2);
      Filled += 2;
    }
    Result.push_back('\n');
  }

  return Result;
}

SpecHashes DeriveTexts(const Spec& Item, const SynthOptions& Options) {
  SpecHashes Texts;

  Texts.BytesHash = HexToken(Item.Body, 0xA5A5A5A5A5A5A5A5ull);
  Texts.FunctionHash = HexToken(Item.Body ^ 0x5F5F5F5F5F5F5F5Full, Item.Body);
  Texts.KghHash = HexToken(Item.Body, Item.Body ^ 0x1234567890ABCDEFull);

  const uint64_t Identity = Item.Kind == Kind::Ambiguous ? Item.GroupKey : Item.Body;
  const bool Scaled = Options.TextBytesPerInstruction > 0;

  if (Scaled) {
    const size_t AssemblyBytes = Item.Instructions * Options.TextBytesPerInstruction;
    Texts.CleanAssembly = MakeListing(Identity ^ 0x1111111111111111ull, Item.Instructions,
                                      Options.TextBytesPerInstruction);
    Texts.CleanMicrocode = MakeListing(Identity ^ 0x2222222222222222ull, Item.Instructions,
                                       Options.TextBytesPerInstruction);
    Texts.CleanPseudo =
        MakeListing(Identity ^ 0x3333333333333333ull, Item.PseudoLines, Options.PseudoBytesPerLine);
    Texts.Mnemonics = MakeListing(Identity ^ 0x4444444444444444ull, 1, AssemblyBytes / 4 + 8);
  } else if (Item.Kind == Kind::Ambiguous) {
    Texts.CleanAssembly = "asm-group-" + HexToken(Item.GroupKey, 4);
    Texts.CleanMicrocode = "micro-group-" + HexToken(Item.GroupKey, 5);
    Texts.CleanPseudo = "pseudo-group-" + HexToken(Item.GroupKey, 6);
    Texts.Mnemonics = "mnem-group-" + HexToken(Item.GroupKey, 7);
  } else {
    Texts.CleanAssembly = "asm-" + HexToken(Item.Body, 1);
    Texts.CleanMicrocode = "micro-" + HexToken(Item.Body, 2);
    Texts.CleanPseudo = "pseudo-" + HexToken(Item.Body, 3);
    Texts.Mnemonics = "mnem-" + HexToken(Item.Body & 0xFFFFFFFFFFFFull, 8);
  }

  return Texts;
}

void EmitRow(FunctionTable& Table, const Spec& Item, const SpecHashes& Texts, uint64_t Address,
             uint64_t ImageBase, int64_t Id, const std::string& Name) {
  const size_t Row = Table.Id.size();
  Table.Resize(Row + 1);

  Table.Id[Row] = Id;
  Table.Nodes[Row] = static_cast<int64_t>(Item.Nodes);
  Table.Edges[Row] = static_cast<int64_t>(Item.Nodes + 1);
  Table.Instructions[Row] = static_cast<int64_t>(Item.Instructions);
  Table.Size[Row] = static_cast<int64_t>(Item.Instructions * 4);
  Table.CyclomaticComplexity[Row] = static_cast<int64_t>(Item.Nodes);
  Table.Indegree[Row] = 1;
  Table.Outdegree[Row] = 1;
  Table.ConstantsCount[Row] = 0;
  Table.Loops[Row] = 0;
  Table.StronglyConnected[Row] = 1;
  Table.PseudocodeLines[Row] = static_cast<int64_t>(Item.PseudoLines);

  const std::string Rva = AddressToken(Address - ImageBase);

  Table.Name[Row] = Table.Pool.Append(Name);
  Table.MangledFunction[Row] = Table.Pool.Append(Name);
  Table.Address[Row] = Table.Pool.Append(AddressToken(Address));
  Table.Rva[Row] = Table.Pool.Append(Rva);
  Table.SegmentRva[Row] = Table.Pool.Append(Rva);
  Table.BytesHash[Row] = Table.Pool.Append(Texts.BytesHash);
  Table.FunctionHash[Row] = Table.Pool.Append(Texts.FunctionHash);
  Table.KghHash[Row] = Table.Pool.Append(Texts.KghHash);
  Table.MdIndex[Row] = Table.Pool.Append("1.0");
  Table.Mnemonics[Row] = Table.Pool.Append(Texts.Mnemonics);
  Table.CleanAssembly[Row] = Table.Pool.Append(Texts.CleanAssembly);
  Table.CleanPseudo[Row] = Table.Pool.Append(Texts.CleanPseudo);
  Table.CleanMicrocode[Row] = Table.Pool.Append(Texts.CleanMicrocode);
  Table.SourceFile[Row] = Table.Pool.Append("main.cpp");
}

struct Prepared {
  Spec Item;
  SpecHashes ReferenceTexts;
  SpecHashes TargetTexts;
  int64_t Id = 0;
  std::string ReferenceName;
  std::string TargetName;
  bool EmitReference = false;
  bool EmitTarget = false;
};

}

SynthPair MakeSyntheticPair(const SynthOptions& Options) {
  SynthPair Pair;

  const size_t Total = Options.FunctionCount;
  const size_t Identical = Total * Options.IdenticalPercent / 100;
  const size_t Recompiled = Total * Options.RecompiledPercent / 100;
  const size_t Ambiguous = Total * Options.AmbiguousPercent / 100;
  const size_t OrphanEach = Total * Options.OrphanPercent / 200;

  Pair.IdenticalCount = Identical;
  Pair.RecompiledCount = Recompiled;
  Pair.AmbiguousCount = Ambiguous;
  Pair.OrphanReferenceCount = OrphanEach;
  Pair.OrphanTargetCount = OrphanEach;

  SplitMix64 Random(Options.Seed);

  const uint64_t ReferenceBase = 0x140000000ull;
  const uint64_t TargetBase = 0x180000000ull;

  std::vector<Spec> Specs;
  const size_t GroupSize = Options.AmbiguousGroupSize > 0 ? Options.AmbiguousGroupSize : 1;

  const auto AddGroup = [&](Kind ItemKind, size_t Count) {
    for (size_t Index = 0; Index < Count; ++Index) {
      Spec Item;
      Item.Kind = ItemKind;
      Item.Body = Random.Next();

      const size_t GroupIndex = Specs.size() / GroupSize;
      Item.GroupKey = static_cast<uint64_t>(GroupIndex) * 0x100000001ull;

      if (ItemKind == Kind::Ambiguous) {
        SplitMix64 GroupRandom(
            Options.Seed ^ (static_cast<uint64_t>(GroupIndex) * 0xD6E8FEB86659FD93ull));
        Item.Instructions = GroupRandom.Range(Options.MinInstructions, Options.MaxInstructions);
        Item.Nodes = GroupRandom.Range(3, 12);
        Item.PseudoLines = GroupRandom.Range(8, 40);
      } else {
        Item.Instructions = Random.Range(Options.MinInstructions, Options.MaxInstructions);
        Item.Nodes = Random.Range(2, 12);
        Item.PseudoLines = Random.Range(2, 40);
      }

      Item.StableAddress = Random.Below(100) < Options.StableAddressPercent;

      const size_t Slot = Specs.size();
      Item.ReferenceAddress = ReferenceBase + Slot * 0x40ull;
      Item.TargetAddress = Item.StableAddress ? ReferenceBase + Slot * 0x40ull
                                              : TargetBase + Slot * 0x40ull;
      Specs.push_back(Item);
    }
  };

  AddGroup(Kind::Identical, Identical);
  AddGroup(Kind::Recompiled, Recompiled);
  AddGroup(Kind::Ambiguous, Ambiguous);
  AddGroup(Kind::OrphanReference, OrphanEach);
  AddGroup(Kind::OrphanTarget, OrphanEach);

  std::vector<Prepared> Items;
  Items.reserve(Specs.size());

  int64_t NextId = 1;
  for (const Spec& Base : Specs) {
    Prepared Entry;
    Entry.Item = Base;
    Entry.Id = NextId++;
    Entry.ReferenceTexts = DeriveTexts(Entry.Item, Options);
    Entry.TargetTexts = Entry.ReferenceTexts;

    if (Entry.Item.Kind == Kind::Recompiled || Entry.Item.Kind == Kind::Ambiguous) {
      Spec Mutated = Entry.Item;
      Mutated.Body ^= 0xDEADBEEFCAFEBABEull;
      SpecHashes MutatedTexts = DeriveTexts(Mutated, Options);

      MutatedTexts.CleanAssembly = Entry.ReferenceTexts.CleanAssembly;
      MutatedTexts.CleanMicrocode = Entry.ReferenceTexts.CleanMicrocode;
      MutatedTexts.CleanPseudo = Entry.ReferenceTexts.CleanPseudo;
      if (Entry.Item.Kind == Kind::Recompiled) {
        MutatedTexts.Mnemonics = Entry.ReferenceTexts.Mnemonics;
      }
      Entry.TargetTexts = MutatedTexts;
    }

    char NameBuffer[48];
    std::snprintf(NameBuffer, sizeof(NameBuffer), "Real_%lld", static_cast<long long>(Entry.Id));
    Entry.ReferenceName = NameBuffer;
    std::snprintf(NameBuffer, sizeof(NameBuffer), "sub_%llX",
                  static_cast<unsigned long long>(Entry.Item.TargetAddress & 0xFFFFFFull));
    Entry.TargetName = NameBuffer;

    Entry.EmitReference = Entry.Item.Kind != Kind::OrphanTarget;
    Entry.EmitTarget = Entry.Item.Kind != Kind::OrphanReference;
    Items.push_back(std::move(Entry));
  }

  const size_t SpecCount = Items.size();
  Pair.Reference.Reserve(SpecCount + 1);
  Pair.Target.Reserve(SpecCount + 1);

  std::vector<uint32_t> ReferenceIndexBySpec(SpecCount, 0xFFFFFFFFu);
  std::vector<uint32_t> TargetIndexBySpec(SpecCount, 0xFFFFFFFFu);

  for (size_t Slot = 0; Slot < SpecCount; ++Slot) {
    const Prepared& Entry = Items[Slot];
    if (!Entry.EmitReference) {
      continue;
    }
    ReferenceIndexBySpec[Slot] = static_cast<uint32_t>(Pair.Reference.Id.size());
    EmitRow(Pair.Reference, Entry.Item, Entry.ReferenceTexts, Entry.Item.ReferenceAddress,
            ReferenceBase, Entry.Id, Entry.ReferenceName);
  }

  std::vector<size_t> TargetOrder;
  TargetOrder.reserve(SpecCount);
  for (size_t Slot = 0; Slot < SpecCount; ++Slot) {
    if (Items[Slot].EmitTarget) {
      TargetOrder.push_back(Slot);
    }
  }

  SplitMix64 Shuffler(Options.Seed ^ 0xABCDEF0123456789ull);
  for (size_t Position = TargetOrder.size(); Position > 1; --Position) {
    std::swap(TargetOrder[Position - 1], TargetOrder[Shuffler.Below(Position)]);
  }

  for (const size_t Slot : TargetOrder) {
    const Prepared& Entry = Items[Slot];
    const uint64_t ImageBase = Entry.Item.StableAddress ? ReferenceBase : TargetBase;
    TargetIndexBySpec[Slot] = static_cast<uint32_t>(Pair.Target.Id.size());
    EmitRow(Pair.Target, Entry.Item, Entry.TargetTexts, Entry.Item.TargetAddress, ImageBase,
            Entry.Id, Entry.TargetName);
  }

  Pair.ReferenceToTarget.assign(Pair.Reference.Count(), 0xFFFFFFFFu);
  Pair.TargetToReference.assign(Pair.Target.Count(), 0xFFFFFFFFu);

  for (size_t Slot = 0; Slot < SpecCount; ++Slot) {
    const uint32_t ReferenceIndex = ReferenceIndexBySpec[Slot];
    const uint32_t TargetIndex = TargetIndexBySpec[Slot];
    if (ReferenceIndex != 0xFFFFFFFFu && TargetIndex != 0xFFFFFFFFu) {
      Pair.ReferenceToTarget[ReferenceIndex] = TargetIndex;
      Pair.TargetToReference[TargetIndex] = ReferenceIndex;
    }
  }

  return Pair;
}

}
