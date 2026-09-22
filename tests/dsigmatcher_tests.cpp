#include <sqlite3.h>

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <string>
#include <vector>

#include "dsigmatcher/ExportDatabase.h"
#include "dsigmatcher/Heuristics.h"
#include "dsigmatcher/MatchStore.h"
#include "dsigmatcher/Naming.h"
#include "dsigmatcher/Provenance.h"
#include "dsigmatcher/Sha256.h"
#include "dsigmatcher/Synth.h"
#include "dsigmatcher/Types.h"

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

std::filesystem::path ScratchDirectory() {
  std::filesystem::path Directory = std::filesystem::temp_directory_path() / "dsigmatcher_tests";
  std::filesystem::create_directories(Directory);
  return Directory;
}

struct TestFunction {
  int64_t Id = 0;
  std::string Name;
  std::string Address;
  std::string Rva;
  std::string BytesHash;
  std::string FunctionHash;
  std::string CleanAssembly;
  std::string CleanPseudo;
  std::string CleanMicrocode;
  std::string Mnemonics;
  int64_t Instructions = 20;
  int64_t Nodes = 4;
  int64_t PseudocodeLines = 8;
};

bool CreateExport(const std::string& Path, const std::vector<TestFunction>& Rows,
                  const std::string& Processor) {
  std::error_code Removed;
  std::filesystem::remove(Path, Removed);

  sqlite3* Handle = nullptr;
  if (sqlite3_open_v2(Path.c_str(), &Handle, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) !=
      SQLITE_OK) {
    if (Handle != nullptr) {
      sqlite3_close(Handle);
    }
    return false;
  }

  char* ErrorMessage = nullptr;

  if (sqlite3_exec(Handle,
                   "create table functions (id integer primary key, name text, address text "
                   "unique, rva text, segment_rva text, mangled_function text, bytes_hash text, "
                   "function_hash text, kgh_hash text, md_index text, mnemonics text, "
                   "clean_assembly text, clean_pseudo text, clean_microcode text, source_file "
                   "text, nodes integer, edges integer, instructions integer, size integer, "
                   "cyclomatic_complexity integer, indegree integer, outdegree integer, "
                   "constants_count integer, loops integer, strongly_connected integer, "
                   "pseudocode_lines integer);"
                   "create table program (id integer primary key, callgraph_primes text, "
                   "callgraph_all_primes text, processor text, md5sum text);"
                   "create table version (value text);"
                   "insert into version values ('3.4.2');",
                   nullptr, nullptr, &ErrorMessage) != SQLITE_OK) {
    sqlite3_free(ErrorMessage);
    sqlite3_close(Handle);
    return false;
  }

  sqlite3_stmt* ProgramStatement = nullptr;
  if (sqlite3_prepare_v2(Handle,
                         "insert into program (id, callgraph_primes, callgraph_all_primes, "
                         "processor, md5sum) values (1, '2', '2', ?, ?)",
                         -1, &ProgramStatement, nullptr) != SQLITE_OK) {
    sqlite3_close(Handle);
    return false;
  }
  sqlite3_bind_text(ProgramStatement, 1, Processor.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(ProgramStatement, 2, Path.c_str(), -1, SQLITE_TRANSIENT);
  const bool ProgramInserted = sqlite3_step(ProgramStatement) == SQLITE_DONE;
  sqlite3_finalize(ProgramStatement);
  if (!ProgramInserted) {
    sqlite3_close(Handle);
    return false;
  }

  sqlite3_stmt* Insert = nullptr;
  sqlite3_prepare_v2(
      Handle,
      "insert into functions (id, name, address, rva, segment_rva, mangled_function, bytes_hash, "
      "function_hash, kgh_hash, md_index, mnemonics, clean_assembly, clean_pseudo, "
      "clean_microcode, source_file, nodes, edges, instructions, size, cyclomatic_complexity, "
      "indegree, outdegree, constants_count, loops, strongly_connected, pseudocode_lines) "
      "values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      -1, &Insert, nullptr);

  for (const TestFunction& Row : Rows) {
    sqlite3_bind_int64(Insert, 1, Row.Id);
    sqlite3_bind_text(Insert, 2, Row.Name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(Insert, 3, Row.Address.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(Insert, 4, Row.Rva.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(Insert, 5, Row.Rva.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(Insert, 6, Row.Name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(Insert, 7, Row.BytesHash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(Insert, 8, Row.FunctionHash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(Insert, 9, Row.BytesHash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(Insert, 10, "1.0", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(Insert, 11, Row.Mnemonics.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(Insert, 12, Row.CleanAssembly.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(Insert, 13, Row.CleanPseudo.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(Insert, 14, Row.CleanMicrocode.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(Insert, 15, "main.cpp", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(Insert, 16, Row.Nodes);
    sqlite3_bind_int64(Insert, 17, Row.Nodes + 1);
    sqlite3_bind_int64(Insert, 18, Row.Instructions);
    sqlite3_bind_int64(Insert, 19, Row.Instructions * 4);
    sqlite3_bind_int64(Insert, 20, Row.Nodes);
    sqlite3_bind_int64(Insert, 21, 1);
    sqlite3_bind_int64(Insert, 22, 1);
    sqlite3_bind_int64(Insert, 23, 0);
    sqlite3_bind_int64(Insert, 24, 0);
    sqlite3_bind_int64(Insert, 25, 1);
    sqlite3_bind_int64(Insert, 26, Row.PseudocodeLines);
    sqlite3_step(Insert);
    sqlite3_reset(Insert);
  }

  sqlite3_finalize(Insert);
  sqlite3_close(Handle);
  return true;
}

double ReadCumulativeRatio(const std::string& Path, const std::string& Name) {
  sqlite3* Handle = nullptr;
  if (sqlite3_open_v2(Path.c_str(), &Handle, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
    if (Handle != nullptr) {
      sqlite3_close(Handle);
    }
    return -1.0;
  }

  sqlite3_stmt* Statement = nullptr;
  sqlite3_prepare_v2(
      Handle,
      "select cumulative_ratio from dsig_name_origin o join functions f on f.address = o.address "
      "where f.name = ?",
      -1, &Statement, nullptr);
  sqlite3_bind_text(Statement, 1, Name.c_str(), -1, SQLITE_TRANSIENT);

  double Value = -1.0;
  if (sqlite3_step(Statement) == SQLITE_ROW) {
    Value = sqlite3_column_double(Statement, 0);
  }
  sqlite3_finalize(Statement);
  sqlite3_close(Handle);
  return Value;
}

std::string ReadNameAtAddress(const std::string& Path, const std::string& Address) {
  sqlite3* Handle = nullptr;
  if (sqlite3_open_v2(Path.c_str(), &Handle, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
    if (Handle != nullptr) {
      sqlite3_close(Handle);
    }
    return std::string();
  }

  sqlite3_stmt* Statement = nullptr;
  sqlite3_prepare_v2(Handle, "select name from functions where address = ?", -1, &Statement, nullptr);
  sqlite3_bind_text(Statement, 1, Address.c_str(), -1, SQLITE_TRANSIENT);

  std::string Value;
  if (sqlite3_step(Statement) == SQLITE_ROW) {
    const unsigned char* Text = sqlite3_column_text(Statement, 0);
    if (Text != nullptr) {
      Value = reinterpret_cast<const char*>(Text);
    }
  }
  sqlite3_finalize(Statement);
  sqlite3_close(Handle);
  return Value;
}

void TestSha256() {
  Suite("Sha256 known vectors");

  Sha256 Empty;
  CHECK_EQ(Empty.FinishHex(),
           std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));

  Sha256 Abc;
  Abc.Update("abc");
  CHECK_EQ(Abc.FinishHex(),
           std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));

  Sha256 Quick;
  Quick.Update("The quick brown fox jumps over the lazy dog");
  CHECK_EQ(Quick.FinishHex(),
           std::string("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"));

  Sha256 Long;
  const std::string MillionA(1000000, 'a');
  Long.Update(MillionA);
  CHECK_EQ(Long.FinishHex(),
           std::string("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));

  Sha256 Chunked;
  for (int Index = 0; Index < 1000; ++Index) {
    Chunked.Update("abcdefghij");
  }

  std::string Repeated;
  Repeated.reserve(10000);
  for (int Index = 0; Index < 1000; ++Index) {
    Repeated.append("abcdefghij");
  }
  Sha256 Whole;
  Whole.Update(Repeated.data(), Repeated.size());
  CHECK_EQ(Repeated.size(), static_cast<size_t>(10000));
  CHECK_EQ(Chunked.FinishHex(), Whole.FinishHex());
}

void TestStringPool() {
  Suite("StringPool");

  StringPool Pool;
  const PackedString Empty = Pool.Append("");
  CHECK_EQ(Pool.View(Empty).size(), static_cast<size_t>(0));

  const PackedString First = Pool.Append("alpha");
  const PackedString Second = Pool.Append("beta");
  const PackedString Third = Pool.Append("a much longer string with spaces");

  CHECK_EQ(std::string(Pool.View(First)), std::string("alpha"));
  CHECK_EQ(std::string(Pool.View(Second)), std::string("beta"));
  CHECK_EQ(std::string(Pool.View(Third)), std::string("a much longer string with spaces"));
  CHECK_EQ(Pool.Bytes(), static_cast<size_t>(5 + 4 + 32));
}

void TestNaming() {
  Suite("Naming predicates");

  CHECK(IsAutoNamed("sub_140001000"));
  CHECK(!IsAutoNamed("NtUserPeekMessage"));
  CHECK(!IsAutoNamed("sub"));
  CHECK(IsNullSub("nullsub_1"));
  CHECK(!IsNullSub("sub_null"));

  CHECK(IsPortableSymbol("RealFunction"));
  CHECK(!IsPortableSymbol("sub_1000"));
  CHECK(!IsPortableSymbol("nullsub_2"));
  CHECK(!IsPortableSymbol(""));
  CHECK(!IsPortableSymbol("..."));

  CHECK(NameCompatible("Same", "Same"));
  CHECK(!NameCompatible("Left", "Right"));
  CHECK(NameCompatible("Real", "sub_1000"));
  CHECK(NameCompatible("sub_1000", "Real"));
  CHECK(!NameCompatible("sub_1000", "sub_2000") == false);
}

void TestMatchStore() {
  Suite("MatchStore resolution");

  MatchStore Dedup;
  for (int Index = 0; Index < 5; ++Index) {
    Match Item;
    Item.Index1 = 3;
    Item.Index2 = 7;
    Item.HeuristicId = static_cast<uint16_t>(Index);
    Item.Ratio = 1.0f;
    Dedup.Add(Item);
  }
  CHECK_EQ(Dedup.RawCount(), static_cast<size_t>(5));
  CHECK_EQ(Dedup.Resolve().size(), static_cast<size_t>(1));

  MatchStore Conflict;
  Match High;
  High.Index1 = 1;
  High.Index2 = 2;
  High.Ratio = 0.9f;
  Match Low;
  Low.Index1 = 1;
  Low.Index2 = 5;
  Low.Ratio = 0.4f;
  Conflict.Add(Low);
  Conflict.Add(High);
  const std::vector<Match> Resolved = Conflict.Resolve();
  CHECK_EQ(Resolved.size(), static_cast<size_t>(1));
  CHECK_EQ(Resolved[0].Index2, static_cast<uint32_t>(2));

  MatchStore Determinism;
  std::vector<Match> Shuffled;
  for (uint32_t Index = 0; Index < 200; ++Index) {
    Match Item;
    Item.Index1 = Index;
    Item.Index2 = (Index * 37u) % 200u;
    Item.Ratio = static_cast<float>((Index % 10)) / 10.0f;
    Item.HeuristicId = static_cast<uint16_t>(Index % 8);
    Shuffled.push_back(Item);
  }
  Determinism.AddAll(Shuffled);
  const std::vector<Match> FirstPass = Determinism.Resolve();

  std::vector<Match> Reversed = Shuffled;
  std::reverse(Reversed.begin(), Reversed.end());
  MatchStore Reordered;
  Reordered.AddAll(Reversed);
  const std::vector<Match> SecondPass = Reordered.Resolve();

  CHECK_EQ(FirstPass.size(), SecondPass.size());
  bool Identical = FirstPass.size() == SecondPass.size();
  for (size_t Index = 0; Identical && Index < FirstPass.size(); ++Index) {
    Identical = FirstPass[Index].Index1 == SecondPass[Index].Index1 &&
                FirstPass[Index].Index2 == SecondPass[Index].Index2;
  }
  CHECK(Identical);
}

void TestSyntheticAccuracy() {
  Suite("Heuristics against synthetic ground truth");

  SynthOptions Options;
  Options.FunctionCount = 4000;
  Options.Seed = 0xC0FFEEull;
  const SynthPair Pair = MakeSyntheticPair(Options);

  CHECK_EQ(Pair.Reference.Count(), Pair.Target.Count());
  CHECK(Pair.Reference.Count() > 0);

  DiffOptions Diff;
  Diff.SameProcessor = true;
  Diff.ThreadCount = 1;

  const DiffResult Result = RunExactHeuristics(Pair.Reference, Pair.Target, Diff);

  size_t TruePositives = 0;
  size_t FalsePositives = 0;
  for (const Match& Item : Result.Resolved) {
    if (Pair.ReferenceToTarget[Item.Index1] == Item.Index2) {
      ++TruePositives;
    } else {
      ++FalsePositives;
    }
  }

  size_t LeftUsed = 0;
  std::vector<char> Used(Pair.Reference.Count(), 0);
  for (const Match& Item : Result.Resolved) {
    if (Used[Item.Index1] == 0) {
      Used[Item.Index1] = 1;
      ++LeftUsed;
    }
  }
  CHECK_EQ(LeftUsed, Result.Resolved.size());

  const double Precision =
      Result.Resolved.empty() ? 0.0 : static_cast<double>(TruePositives) /
                                          static_cast<double>(Result.Resolved.size());
  const double Recall = Pair.PairedCount() == 0
                            ? 0.0
                            : static_cast<double>(TruePositives) / static_cast<double>(Pair.PairedCount());

  std::printf("  functions        : %zu per side (%zu paired, %zu+%zu orphans)\n",
              Pair.Reference.Count(), Pair.PairedCount(), Pair.OrphanReferenceCount,
              Pair.OrphanTargetCount);
  std::printf("  resolved matches : %zu\n", Result.Resolved.size());
  std::printf("  true positives   : %zu\n", TruePositives);
  std::printf("  false positives  : %zu\n", FalsePositives);
  std::printf("  precision        : %.4f\n", Precision);
  std::printf("  recall           : %.4f\n", Recall);

  CHECK(Recall > 0.85);
  CHECK(Precision > 0.85);
  CHECK(Precision < 0.999);
  CHECK(Result.Resolved.size() <= Pair.Reference.Count());

  DiffOptions Parallel = Diff;
  Parallel.ThreadCount = 8;
  const DiffResult ParallelResult = RunExactHeuristics(Pair.Reference, Pair.Target, Parallel);
  CHECK_EQ(ParallelResult.Resolved.size(), Result.Resolved.size());
  CHECK_EQ(ParallelResult.RawMatches, Result.RawMatches);
}

void TestIngestRoundTrip() {
  Suite("ExportDatabase ingest");

  const std::filesystem::path Directory = ScratchDirectory();
  const std::string Path = (Directory / "ingest.sqlite").string();

  std::vector<TestFunction> Rows;
  for (int Index = 0; Index < 25; ++Index) {
    TestFunction Row;
    Row.Id = Index + 1;
    Row.Name = "Function_" + std::to_string(Index);
    Row.Address = "0x14000" + std::to_string(1000 + Index);
    Row.Rva = std::to_string(4096 + Index);
    Row.BytesHash = "byteshash" + std::to_string(Index);
    Row.FunctionHash = "funchash" + std::to_string(Index);
    Row.CleanAssembly = "asm" + std::to_string(Index);
    Row.CleanPseudo = "pseudo" + std::to_string(Index);
    Row.CleanMicrocode = "micro" + std::to_string(Index);
    Row.Mnemonics = "push mov ret";
    Row.Instructions = 12 + Index;
    Row.Nodes = 3;
    Row.PseudocodeLines = 9;
    Rows.push_back(Row);
  }

  CHECK(CreateExport(Path, Rows, "metapc"));

  ExportDatabase Loader;
  FunctionTable Table;
  ProgramInfo Program;
  const LoadResult Loaded = Loader.Load(Path, Table, Program);

  CHECK(Loaded.Ok);
  CHECK_EQ(Loaded.RowsRead, static_cast<int64_t>(25));
  CHECK_EQ(Table.Count(), static_cast<size_t>(25));
  CHECK(Program.Present);
  CHECK_EQ(Program.Processor, std::string("metapc"));

  CHECK_EQ(std::string(Table.Text(Table.Name[7])), std::string("Function_7"));
  CHECK_EQ(std::string(Table.Text(Table.BytesHash[7])), std::string("byteshash7"));
  CHECK_EQ(Table.Instructions[7], static_cast<int64_t>(19));
  CHECK_EQ(Table.Nodes[7], static_cast<int64_t>(3));
  CHECK_EQ(Table.PseudocodeLines[7], static_cast<int64_t>(9));
  CHECK_EQ(Table.Id[0], static_cast<int64_t>(1));
  CHECK_EQ(Table.Id[24], static_cast<int64_t>(25));

  FunctionTable Missing;
  ProgramInfo MissingProgram;
  const LoadResult BadLoad = Loader.Load((Directory / "does_not_exist.sqlite").string(), Missing,
                                         MissingProgram);
  CHECK(!BadLoad.Ok);
}

std::string HexAddress(uint64_t Value) {
  char Buffer[24];
  std::snprintf(Buffer, sizeof(Buffer), "0x%llX", static_cast<unsigned long long>(Value));
  return std::string(Buffer);
}

void TestProvenanceChain() {
  Suite("Provenance chain across two hops");

  const std::filesystem::path Directory = ScratchDirectory();

  const auto MakeVersion = [](const std::string& Suffix, bool Labelled, uint64_t Delta) {
    std::vector<TestFunction> Rows;

    TestFunction Unique;
    Unique.Id = 1;
    Unique.Name = Labelled ? "Real_Unique" : "sub_1000";
    Unique.Address = HexAddress(0x140001000ull + Delta);
    Unique.Rva = std::to_string(0x1000ull + Delta);
    Unique.BytesHash = "stable-unique-bytes";
    Unique.FunctionHash = "stable-unique-fh";
    Unique.CleanAssembly = "asm-unique";
    Unique.CleanPseudo = "pseudo-unique";
    Unique.CleanMicrocode = "micro-unique";
    Unique.Mnemonics = "push mov call ret";
    Unique.Instructions = 20;
    Unique.Nodes = 4;
    Unique.PseudocodeLines = 9;
    Rows.push_back(Unique);

    for (int Index = 0; Index < 2; ++Index) {
      TestFunction Ambiguous;
      Ambiguous.Id = 2 + Index;
      Ambiguous.Name = Labelled ? ("Real_Ambig_" + std::to_string(Index))
                                : ("sub_200" + std::to_string(Index));
      Ambiguous.Address = HexAddress(0x140002000ull + Delta + Index * 16);
      Ambiguous.Rva = std::to_string(0x2000ull + Delta + Index * 16);
      Ambiguous.BytesHash = "ambig-bytes-" + Suffix + "-" + std::to_string(Index);
      Ambiguous.FunctionHash = "ambig-fh-" + Suffix + "-" + std::to_string(Index);
      Ambiguous.CleanAssembly = "asm-shared-ambiguous";
      Ambiguous.CleanPseudo = "pseudo-ambig-" + std::to_string(Index);
      Ambiguous.CleanMicrocode = "micro-shared-ambiguous";
      Ambiguous.Mnemonics = "push mov lea call jmp ret";
      Ambiguous.Instructions = 40;
      Ambiguous.Nodes = 6;
      Ambiguous.PseudocodeLines = 3;
      Rows.push_back(Ambiguous);
    }

    return Rows;
  };

  const std::string V0 = (Directory / "chain_v0.sqlite").string();
  const std::string V1 = (Directory / "chain_v1.sqlite").string();
  const std::string V2 = (Directory / "chain_v2.sqlite").string();
  const std::string V1Labelled = (Directory / "chain_v1_labelled.sqlite").string();
  const std::string V2Labelled = (Directory / "chain_v2_labelled.sqlite").string();

  const uint64_t DeltaV0 = 0;
  const uint64_t DeltaV1 = 0x100000;
  const uint64_t DeltaV2 = 0x200000;
  const std::string V1UniqueAddress = HexAddress(0x140001000ull + DeltaV1);
  const std::string V2UniqueAddress = HexAddress(0x140001000ull + DeltaV2);

  CHECK(CreateExport(V0, MakeVersion("v0", true, DeltaV0), "metapc"));
  CHECK(CreateExport(V1, MakeVersion("v1", false, DeltaV1), "metapc"));
  CHECK(CreateExport(V2, MakeVersion("v2", false, DeltaV2), "metapc"));

  const DatabaseIdentity RawIdentity = InspectDatabase(V1);
  CHECK(RawIdentity.Ok);
  CHECK(!RawIdentity.HasProvenance);
  CHECK_EQ(RawIdentity.FunctionCount, static_cast<int64_t>(3));
  CHECK(!RawIdentity.FileSha256.empty());

  PortOptions FirstHop;
  FirstHop.ReferencePath = V0;
  FirstHop.TargetPath = V1;
  FirstHop.OutputPath = V1Labelled;
  FirstHop.Diff.SameProcessor = true;
  FirstHop.Diff.ThreadCount = 1;
  const PortResult FirstResult = PortSymbols(FirstHop);

  CHECK(FirstResult.Ok);
  CHECK_EQ(FirstResult.NewHop, static_cast<int64_t>(1));
  CHECK_EQ(FirstResult.NamesApplied, static_cast<int64_t>(3));
  CHECK_EQ(ReadNameAtAddress(V1Labelled, V1UniqueAddress), std::string("Real_Unique"));

  const double AmbiguousHop1 = ReadCumulativeRatio(V1Labelled, "Real_Ambig_0");
  std::printf("  hop1 ambiguous cumulative : %.4f\n", AmbiguousHop1);
  CHECK(AmbiguousHop1 > 0.4 && AmbiguousHop1 < 0.6);

  const DatabaseIdentity LabelledIdentity = InspectDatabase(V1Labelled);
  CHECK(LabelledIdentity.HasProvenance);
  CHECK_EQ(LabelledIdentity.HopCount, static_cast<int64_t>(1));

  PortOptions SecondHop;
  SecondHop.ReferencePath = V1Labelled;
  SecondHop.TargetPath = V2;
  SecondHop.OutputPath = V2Labelled;
  SecondHop.Diff.SameProcessor = true;
  SecondHop.Diff.ThreadCount = 1;
  const PortResult SecondResult = PortSymbols(SecondHop);

  CHECK(SecondResult.Ok);
  CHECK_EQ(SecondResult.NewHop, static_cast<int64_t>(2));
  CHECK_EQ(ReadNameAtAddress(V2Labelled, V2UniqueAddress), std::string("Real_Unique"));

  const DatabaseIdentity FinalIdentity = InspectDatabase(V2Labelled);
  CHECK_EQ(FinalIdentity.HopCount, static_cast<int64_t>(2));

  const double UniqueHop2 = ReadCumulativeRatio(V2Labelled, "Real_Unique");
  const double AmbiguousHop2 = ReadCumulativeRatio(V2Labelled, "Real_Ambig_0");
  std::printf("  hop2 unique cumulative    : %.4f\n", UniqueHop2);
  std::printf("  hop2 ambiguous cumulative : %.4f\n", AmbiguousHop2);
  CHECK(UniqueHop2 > 0.99);
  CHECK(AmbiguousHop2 > 0.20 && AmbiguousHop2 < 0.30);
  CHECK(AmbiguousHop2 < AmbiguousHop1);

  const std::string Capped = (Directory / "chain_capped.sqlite").string();
  PortOptions CappedHop;
  CappedHop.ReferencePath = V1Labelled;
  CappedHop.TargetPath = V2;
  CappedHop.OutputPath = Capped;
  CappedHop.MaxHops = 1;
  CappedHop.Diff.SameProcessor = true;
  CappedHop.Diff.ThreadCount = 1;
  const PortResult CappedResult = PortSymbols(CappedHop);
  CHECK(CappedResult.Ok);
  CHECK_EQ(CappedResult.NamesSkippedHops, static_cast<int64_t>(3));
  CHECK_EQ(CappedResult.NamesApplied, static_cast<int64_t>(0));

  const std::string Filtered = (Directory / "chain_filtered.sqlite").string();
  PortOptions FilteredHop;
  FilteredHop.ReferencePath = V1Labelled;
  FilteredHop.TargetPath = V2;
  FilteredHop.OutputPath = Filtered;
  FilteredHop.MinCumulativeRatio = 0.4;
  FilteredHop.Diff.SameProcessor = true;
  FilteredHop.Diff.ThreadCount = 1;
  const PortResult FilteredResult = PortSymbols(FilteredHop);
  CHECK(FilteredResult.Ok);
  CHECK_EQ(FilteredResult.NamesSkippedRatio, static_cast<int64_t>(2));
  CHECK_EQ(FilteredResult.NamesApplied, static_cast<int64_t>(1));
}

}

int main() {
  TestSha256();
  TestStringPool();
  TestNaming();
  TestMatchStore();
  TestIngestRoundTrip();
  TestSyntheticAccuracy();
  TestProvenanceChain();

  std::printf("\n%d checks, %d failed\n", ChecksRun, ChecksFailed);
  return ChecksFailed == 0 ? 0 : 1;
}
