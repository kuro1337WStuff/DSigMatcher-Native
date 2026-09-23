#include <sqlite3.h>

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <string>
#include <vector>

#include "dsigmatcher/ExportDatabase.h"
#include "dsigmatcher/Heuristics.h"
#include "dsigmatcher/KghHash.h"
#include "dsigmatcher/MatchStore.h"
#include "dsigmatcher/Md5.h"
#include "dsigmatcher/Naming.h"
#include "dsigmatcher/PrimeTable.h"
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
  std::fflush(stdout);
}

void Checkpoint(const char* Label) {
  std::printf("  ck: %s\n", Label);
  std::fflush(stdout);
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
  Checkpoint("ce: enter");

  std::error_code Removed;
  std::filesystem::remove(Path, Removed);
  Checkpoint("ce: old file removed");

  sqlite3* Handle = nullptr;
  if (sqlite3_open_v2(Path.c_str(), &Handle, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) !=
      SQLITE_OK) {
    Checkpoint("ce: open failed branch");
    if (Handle != nullptr) {
      sqlite3_close(Handle);
    }
    return false;
  }
  Checkpoint("ce: database opened");

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
  Checkpoint("ce: schema created");

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
  Checkpoint("ce: program row inserted");

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

  Checkpoint("ce: function rows inserted");
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

void TestMd5() {
  Suite("Md5 RFC 1321 vectors");

  CHECK_EQ(Md5::OfString(""), std::string("d41d8cd98f00b204e9800998ecf8427e"));
  CHECK_EQ(Md5::OfString("a"), std::string("0cc175b9c0f1b6a831c399e269772661"));
  CHECK_EQ(Md5::OfString("abc"), std::string("900150983cd24fb0d6963f7d28e17f72"));
  CHECK_EQ(Md5::OfString("message digest"),
           std::string("f96b697d7cb7938d525a2f31aaf161d0"));
  CHECK_EQ(Md5::OfString("abcdefghijklmnopqrstuvwxyz"),
           std::string("c3fcd3d76192e4007dfb496cca67e13b"));
  CHECK_EQ(Md5::OfString("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
           std::string("d174ab98d277d9f5a5611c2c9f419d9f"));
  CHECK_EQ(Md5::OfString("12345678901234567890123456789012345678901234567890123456789012345678"
                         "901234567890"),
           std::string("57edf4a22be3c955ac49da2e2107b67a"));

  Md5 Million;
  const std::string MillionA(1000000, 'a');
  Million.Update(MillionA);
  CHECK_EQ(Million.FinishHex(), std::string("7707d6ae4e027c70eea2a935c2296f21"));

  Md5 Chunked;
  for (int Index = 0; Index < 1000; ++Index) {
    Chunked.Update("abcdefghij");
  }

  std::string Repeated;
  Repeated.reserve(10000);
  for (int Index = 0; Index < 1000; ++Index) {
    Repeated.append("abcdefghij");
  }
  Md5 Whole;
  Whole.Update(Repeated);
  CHECK_EQ(Repeated.size(), static_cast<size_t>(10000));
  CHECK_EQ(Chunked.FinishHex(), Whole.FinishHex());

  Md5 Padding56;
  Padding56.Update(std::string(56, 'y'));
  Md5 Padding64;
  Padding64.Update(std::string(64, 'y'));
  CHECK(Padding56.FinishHex() != Padding64.FinishHex());

  const size_t BoundaryLengths[] = {54, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128};
  const size_t ChunkSizes[] = {1, 3, 7, 13, 32, 55, 56, 64, 65};
  size_t BoundaryChecks = 0;

  for (const size_t Total : BoundaryLengths) {
    std::string Payload(Total, 'z');
    for (size_t Index = 0; Index < Total; ++Index) {
      Payload[Index] = static_cast<char>('a' + (Index % 26));
    }

    Md5 SingleShot;
    SingleShot.Update(Payload);
    const std::string Expected = SingleShot.FinishHex();

    for (const size_t Chunk : ChunkSizes) {
      Md5 Streamed;
      size_t Offset = 0;
      while (Offset < Total) {
        const size_t Take = Total - Offset < Chunk ? Total - Offset : Chunk;
        Streamed.Update(Payload.data() + Offset, Take);
        Offset += Take;
      }
      CHECK_EQ(Streamed.FinishHex(), Expected);
      ++BoundaryChecks;
    }
  }

  std::printf("  padding boundary : %zu chunked-vs-single comparisons across 11 lengths\n",
              BoundaryChecks);
}

void TestBigUIntBasics() {
  Suite("BigUInt arithmetic");

  CHECK_EQ(BigUInt(0).ToDecimalString(), std::string("0"));
  CHECK_EQ(BigUInt(1).ToDecimalString(), std::string("1"));
  CHECK_EQ(BigUInt(999999999u).ToDecimalString(), std::string("999999999"));
  CHECK_EQ(BigUInt(1000000000u).ToDecimalString(), std::string("1000000000"));

  CHECK_EQ(BigUInt::Power(2, 10).ToDecimalString(), std::string("1024"));
  CHECK_EQ(BigUInt::Power(2, 64).ToDecimalString(), std::string("18446744073709551616"));
  CHECK_EQ(BigUInt::Power(10, 18).ToDecimalString(), std::string("1000000000000000000"));
  CHECK_EQ(BigUInt::Power(7, 0).ToDecimalString(), std::string("1"));

  BigUInt Carry(999999999u);
  Carry.MultiplySmall(999999999u);
  CHECK_EQ(Carry.ToDecimalString(), std::string("999999998000000001"));

  BigUInt Squared = BigUInt::Power(123456789u, 2);
  CHECK_EQ(Squared.ToDecimalString(), std::string("15241578750190521"));

  BigUInt Product(1);
  for (int Index = 0; Index < 50; ++Index) {
    Product.MultiplySmall(47);
  }
  CHECK_EQ(Product.ToDecimalString(), BigUInt::Power(47, 50).ToDecimalString());

  BigUInt Zero(0);
  BigUInt Other(12345);
  Zero.MultiplyBig(Other);
  CHECK_EQ(Zero.ToDecimalString(), std::string("0"));

  BigUInt ByZero(12345);
  ByZero.MultiplyBig(BigUInt(0));
  CHECK_EQ(ByZero.ToDecimalString(), std::string("0"));
}

void TestKghAgainstPythonOracle() {
  Suite("KGH decimal rendering vs Python bignum oracle");

  struct OracleVector {
    const char* Label;
    uint64_t Exponents[KghPrimeCount];
    size_t Digits;
    const char* Digest;
  };

  const OracleVector Vectors[] = {
    {"all zero", {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 1,
     "c4ca4238a0b923820dcc509a6f75849b"},
    {"single entry block", {1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0}, 4,
     "2cbca44843a864533ec05b321ae1f9d1"},
    {"typical five block function", {1, 1, 5, 6, 6, 1, 3, 2, 3, 4, 0, 0, 0}, 35,
     "106761923034e794eb67fec9def33503"},
    {"library thunk noret", {1, 1, 2, 2, 2, 0, 1, 0, 1, 2, 1, 1, 1}, 17,
     "9d7d12bbb51dfa501d2e4566b5ec9ba8"},
    {"hundred blocks", {1, 1, 100, 120, 120, 5, 40, 30, 40, 60, 0, 0, 0}, 556,
     "36a3a6bf61600fff565a86ca81bc1c0b"},
    {"thousand blocks", {1, 1, 1000, 1200, 1200, 50, 400, 300, 400, 600, 0, 0, 0}, 5549,
     "d0e1630b9f50b66ef6adbdc2d3e60a18"},
    {"large exponent on 2", {100000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 30103,
     "caff1a3811c1e6e757ff28137e0fc206"},
    {"all primes moderate", {7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7}, 109,
     "3dab1698f2f73fcce5a33c4d1b7a0f68"},
  };

  for (const OracleVector& Vector : Vectors) {
    KghAccumulator Accumulator;
    for (int Index = 0; Index < KghPrimeCount; ++Index) {
      Accumulator.MultiplyPower(static_cast<KghPrimeIndex>(Index), Vector.Exponents[Index]);
    }

    const std::string Decimal = Accumulator.ToDecimalString();
    const bool SizeOk = Decimal.size() == Vector.Digits;
    const std::string Digest = Md5::OfString(Decimal);
    const bool DigestOk = Digest == Vector.Digest;

    if (!SizeOk || !DigestOk) {
      std::printf("  FAIL %-28s digits %zu (expected %zu) md5 %s (expected %s)\n", Vector.Label,
                  Decimal.size(), Vector.Digits, Digest.c_str(), Vector.Digest);
    }
    CHECK(SizeOk);
    CHECK(DigestOk);
  }

  KghAccumulator StressCase;
  StressCase.MultiplyPower(KghFeatureFuncThunk, 100000);
  const std::string StressDecimal = StressCase.ToDecimalString();
  CHECK_EQ(StressDecimal.size(), static_cast<size_t>(167210));
  CHECK_EQ(Md5::OfString(StressDecimal), std::string("d36cec0bfb94d5fa76d821fd709c4398"));
  std::printf("  stress 47^100000       : %zu digits, digest verified\n", StressDecimal.size());
}

void TestKghAccumulatorSemantics() {
  Suite("KGH accumulation mirrors Diaphora's feature rules");

  KghAccumulator Single;
  Single.AddBlock(0, 0);
  CHECK_EQ(Single.Exponent(KghNodeEntry), static_cast<uint64_t>(1));
  CHECK_EQ(Single.Exponent(KghNodeExit), static_cast<uint64_t>(1));
  CHECK_EQ(Single.Exponent(KghNodeNormal), static_cast<uint64_t>(1));
  CHECK_EQ(Single.Exponent(KghEdgeInConditional), static_cast<uint64_t>(0));
  CHECK_EQ(Single.Exponent(KghEdgeOutConditional), static_cast<uint64_t>(0));
  CHECK_EQ(Single.ToDecimalString(), std::string("30"));

  KghAccumulator Middle;
  Middle.AddBlock(2, 3);
  CHECK_EQ(Middle.Exponent(KghNodeEntry), static_cast<uint64_t>(0));
  CHECK_EQ(Middle.Exponent(KghNodeExit), static_cast<uint64_t>(0));
  CHECK_EQ(Middle.Exponent(KghNodeNormal), static_cast<uint64_t>(1));
  CHECK_EQ(Middle.Exponent(KghEdgeOutConditional), static_cast<uint64_t>(2));
  CHECK_EQ(Middle.Exponent(KghEdgeInConditional), static_cast<uint64_t>(3));
  CHECK_EQ(Middle.ToDecimalString(), std::string("207515"));

  KghAccumulator Flags;
  Flags.AddFunctionFlags(true, false, true);
  CHECK_EQ(Flags.Exponent(KghFeatureFuncNoRet), static_cast<uint64_t>(1));
  CHECK_EQ(Flags.Exponent(KghFeatureFuncLib), static_cast<uint64_t>(0));
  CHECK_EQ(Flags.Exponent(KghFeatureFuncThunk), static_cast<uint64_t>(1));
  CHECK_EQ(Flags.ToDecimalString(), std::string("1927"));

  KghAccumulator Components;
  Components.AddLoopComponents(3);
  Components.AddStronglyConnectedCount(7);
  CHECK_EQ(Components.Exponent(KghFeatureLoop), static_cast<uint64_t>(3));
  CHECK_EQ(Components.Exponent(KghFeatureStronglyConnected), static_cast<uint64_t>(7));

  KghAccumulator InstructionFeatures;
  for (int Index = 0; Index < 4; ++Index) {
    InstructionFeatures.Multiply(KghFeatureCall);
  }
  InstructionFeatures.Multiply(KghFeatureDataRefs);
  InstructionFeatures.MultiplyPower(KghFeatureCallRef, 6);
  CHECK_EQ(InstructionFeatures.Exponent(KghFeatureCall), static_cast<uint64_t>(4));
  CHECK_EQ(InstructionFeatures.Exponent(KghFeatureDataRefs), static_cast<uint64_t>(1));
  CHECK_EQ(InstructionFeatures.Exponent(KghFeatureCallRef), static_cast<uint64_t>(6));
}

bool IsPrimeByTrialDivision(uint64_t Value) {
  if (Value < 2) {
    return false;
  }
  if (Value % 2 == 0) {
    return Value == 2;
  }
  for (uint64_t Divisor = 3; Divisor * Divisor <= Value; Divisor += 2) {
    if (Value % Divisor == 0) {
      return false;
    }
  }
  return true;
}

void TestPrimeTables() {
  Suite("Prime tables vs Diaphora primesbelow oracle");

  const PrimeTable& Pseudo = PrimeTable::Pseudocode();
  CHECK_EQ(Pseudo.Limit(), static_cast<uint32_t>(4096));
  CHECK_EQ(Pseudo.Count(), static_cast<size_t>(564));

  const uint32_t ExpectedHead[] = {2, 3, 5, 7, 11, 13, 17, 19};
  for (size_t Index = 0; Index < 8; ++Index) {
    CHECK_EQ(Pseudo.At(Index), ExpectedHead[Index]);
  }
  CHECK_EQ(Pseudo.At(10), static_cast<uint32_t>(31));
  CHECK_EQ(Pseudo.At(47), static_cast<uint32_t>(223));
  CHECK_EQ(Pseudo.At(100), static_cast<uint32_t>(547));
  CHECK_EQ(Pseudo.At(561), static_cast<uint32_t>(4079));
  CHECK_EQ(Pseudo.At(562), static_cast<uint32_t>(4091));
  CHECK_EQ(Pseudo.At(563), static_cast<uint32_t>(4093));

  CHECK(!Pseudo.InRange(564));
  CHECK_EQ(Pseudo.At(564), static_cast<uint32_t>(0));
  CHECK(Pseudo.At(563) < Pseudo.Limit());

  size_t ExhaustivePrimes = 0;
  size_t Position = 0;
  bool ExhaustiveOk = true;
  for (uint32_t Value = 2; Value < 4096; ++Value) {
    if (!IsPrimeByTrialDivision(Value)) {
      if (Position < Pseudo.Count() && Pseudo.At(Position) == Value) {
        ExhaustiveOk = false;
      }
      continue;
    }
    ++ExhaustivePrimes;
    if (Position >= Pseudo.Count() || Pseudo.At(Position) != Value) {
      ExhaustiveOk = false;
    }
    ++Position;
  }
  CHECK_EQ(ExhaustivePrimes, Pseudo.Count());
  CHECK_EQ(Position, Pseudo.Count());
  CHECK(ExhaustiveOk);
  std::printf("  pseudocode table   : %zu primes, exhaustively verified below 4096\n",
              ExhaustivePrimes);

  const PrimeTable& Main = PrimeTable::Main();
  CHECK_EQ(Main.Limit(), static_cast<uint32_t>(2048u * 2048u));
  CHECK_EQ(Main.Count(), static_cast<size_t>(295947));

  for (size_t Index = 0; Index < 8; ++Index) {
    CHECK_EQ(Main.At(Index), ExpectedHead[Index]);
  }
  CHECK_EQ(Main.At(10), static_cast<uint32_t>(31));
  CHECK_EQ(Main.At(47), static_cast<uint32_t>(223));
  CHECK_EQ(Main.At(100), static_cast<uint32_t>(547));
  CHECK_EQ(Main.At(1000), static_cast<uint32_t>(7927));
  CHECK_EQ(Main.At(10000), static_cast<uint32_t>(104743));
  CHECK_EQ(Main.At(100000), static_cast<uint32_t>(1299721));
  CHECK_EQ(Main.At(295944), static_cast<uint32_t>(4194277));
  CHECK_EQ(Main.At(295945), static_cast<uint32_t>(4194287));
  CHECK_EQ(Main.At(295946), static_cast<uint32_t>(4194301));
  CHECK(!Main.InRange(295947));
  CHECK(Main.At(295946) < Main.Limit());

  bool SampledPrimality = true;
  bool SampledGaps = true;
  const size_t Stride = Main.Count() / 512 + 1;
  for (size_t Index = 0; Index < Main.Count(); Index += Stride) {
    if (!IsPrimeByTrialDivision(Main.At(Index))) {
      SampledPrimality = false;
    }
    if (Index + 1 < Main.Count()) {
      for (uint32_t Between = Main.At(Index) + 1; Between < Main.At(Index + 1); ++Between) {
        if (IsPrimeByTrialDivision(Between)) {
          SampledGaps = false;
          break;
        }
      }
    }
  }
  CHECK(SampledPrimality);
  CHECK(SampledGaps);

  bool PrefixAgrees = true;
  for (size_t Index = 0; Index < Pseudo.Count(); ++Index) {
    if (Main.At(Index) != Pseudo.At(Index)) {
      PrefixAgrees = false;
      break;
    }
  }
  CHECK(PrefixAgrees);
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
  Checkpoint("scratch dir resolved");

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
  Checkpoint("rows built");

  CHECK(CreateExport(Path, Rows, "metapc"));
  Checkpoint("export database created");

  ExportDatabase Loader;
  FunctionTable Table;
  ProgramInfo Program;
  const LoadResult Loaded = Loader.Load(Path, Table, Program);
  Checkpoint("load returned");

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
  Checkpoint("field assertions done, loading a nonexistent path");
  const LoadResult BadLoad = Loader.Load((Directory / "does_not_exist.sqlite").string(), Missing,
                                         MissingProgram);
  CHECK(!BadLoad.Ok);
  Checkpoint("nonexistent path rejected");
}

std::string HexAddress(uint64_t Value) {
  char Buffer[24];
  std::snprintf(Buffer, sizeof(Buffer), "0x%llX", static_cast<unsigned long long>(Value));
  return std::string(Buffer);
}

void TestPortPathSafety() {
  Suite("Port refuses to overwrite its own inputs");

  const std::filesystem::path Directory = ScratchDirectory();
  const std::string Reference = (Directory / "safety_ref.sqlite").string();
  const std::string Target = (Directory / "safety_target.sqlite").string();

  std::vector<TestFunction> ReferenceRows;
  std::vector<TestFunction> TargetRows;
  for (int Index = 0; Index < 4; ++Index) {
    TestFunction Row;
    Row.Id = Index + 1;
    Row.Name = "Real_Named_" + std::to_string(Index);
    Row.Address = HexAddress(0x140001000ull + Index * 0x40ull);
    Row.Rva = std::to_string(0x1000ull + Index * 0x40ull);
    Row.BytesHash = "safety-bytes-" + std::to_string(Index);
    Row.FunctionHash = "safety-fh-" + std::to_string(Index);
    Row.CleanAssembly = "safety-asm-" + std::to_string(Index);
    Row.CleanPseudo = "safety-pseudo-" + std::to_string(Index);
    Row.CleanMicrocode = "safety-micro-" + std::to_string(Index);
    Row.Mnemonics = "push mov call ret";
    Row.Instructions = 20;
    Row.Nodes = 4;
    Row.PseudocodeLines = 9;
    ReferenceRows.push_back(Row);

    TestFunction TargetRow = Row;
    if (Index != 0) {
      TargetRow.Name = "sub_200" + std::to_string(Index);
    }
    TargetRows.push_back(TargetRow);
  }

  CHECK(CreateExport(Reference, ReferenceRows, "metapc"));
  CHECK(CreateExport(Target, TargetRows, "metapc"));

  bool HashOk = false;
  const std::string TargetBefore = Sha256::FileHex(Target, HashOk);
  CHECK(HashOk);
  const uintmax_t TargetSizeBefore = std::filesystem::file_size(Target);

  PortOptions InPlace;
  InPlace.ReferencePath = Reference;
  InPlace.TargetPath = Target;
  InPlace.OutputPath = Target;
  InPlace.Diff.SameProcessor = true;
  InPlace.Diff.ThreadCount = 1;
  const PortResult InPlaceResult = PortSymbols(InPlace);

  CHECK(!InPlaceResult.Ok);
  std::printf("  output == target     : rejected with '%s'\n", InPlaceResult.Error.c_str());

  bool StillReadable = false;
  const std::string TargetAfter = Sha256::FileHex(Target, StillReadable);
  CHECK(StillReadable);
  CHECK_EQ(TargetAfter, TargetBefore);
  CHECK_EQ(std::filesystem::file_size(Target), TargetSizeBefore);

  FunctionTable Survivor;
  ProgramInfo SurvivorProgram;
  ExportDatabase Loader;
  const LoadResult Reload = Loader.Load(Target, Survivor, SurvivorProgram);
  CHECK(Reload.Ok);
  CHECK_EQ(Survivor.Count(), static_cast<size_t>(4));

  PortOptions OntoReference;
  OntoReference.ReferencePath = Reference;
  OntoReference.TargetPath = Target;
  OntoReference.OutputPath = Reference;
  OntoReference.Diff.SameProcessor = true;
  OntoReference.Diff.ThreadCount = 1;
  const PortResult OntoReferenceResult = PortSymbols(OntoReference);
  CHECK(!OntoReferenceResult.Ok);
  std::printf("  output == reference  : rejected with '%s'\n",
              OntoReferenceResult.Error.c_str());

  FunctionTable ReferenceSurvivor;
  ProgramInfo ReferenceSurvivorProgram;
  const LoadResult ReferenceReload =
      Loader.Load(Reference, ReferenceSurvivor, ReferenceSurvivorProgram);
  CHECK(ReferenceReload.Ok);
  CHECK_EQ(ReferenceSurvivor.Count(), static_cast<size_t>(4));

  PortOptions EquivalentPath;
  EquivalentPath.ReferencePath = Reference;
  EquivalentPath.TargetPath = Target;
  EquivalentPath.OutputPath = (Directory / "." / "safety_target.sqlite").string();
  EquivalentPath.Diff.SameProcessor = true;
  EquivalentPath.Diff.ThreadCount = 1;
  const PortResult EquivalentResult = PortSymbols(EquivalentPath);
  CHECK(!EquivalentResult.Ok);
  std::printf("  output via .\\ alias  : rejected with '%s'\n", EquivalentResult.Error.c_str());

  bool AliasStillReadable = false;
  const std::string TargetAfterAlias = Sha256::FileHex(Target, AliasStillReadable);
  CHECK(AliasStillReadable);
  CHECK_EQ(TargetAfterAlias, TargetBefore);

  PortOptions MissingDirectory;
  MissingDirectory.ReferencePath = Reference;
  MissingDirectory.TargetPath = Target;
  MissingDirectory.OutputPath = (Directory / "no_such_subdir" / "out.sqlite").string();
  MissingDirectory.Diff.SameProcessor = true;
  MissingDirectory.Diff.ThreadCount = 1;
  const PortResult MissingResult = PortSymbols(MissingDirectory);
  CHECK(!MissingResult.Ok);
  std::printf("  output dir missing   : rejected with '%s'\n", MissingResult.Error.c_str());

  const std::string GoodOutput = (Directory / "safety_out.sqlite").string();
  PortOptions Valid;
  Valid.ReferencePath = Reference;
  Valid.TargetPath = Target;
  Valid.OutputPath = GoodOutput;
  Valid.Diff.SameProcessor = true;
  Valid.Diff.ThreadCount = 1;
  const PortResult ValidResult = PortSymbols(Valid);
  CHECK(ValidResult.Ok);
  CHECK_EQ(ValidResult.Matches, static_cast<int64_t>(4));
  CHECK_EQ(ValidResult.NamesApplied, static_cast<int64_t>(3));
  CHECK_EQ(ValidResult.NamesConfirmed, static_cast<int64_t>(1));
  CHECK_EQ(ReadNameAtAddress(GoodOutput, HexAddress(0x140001040ull)),
           std::string("Real_Named_1"));

  bool TargetUntouched = false;
  CHECK_EQ(Sha256::FileHex(Target, TargetUntouched), TargetBefore);
  CHECK(TargetUntouched);
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

    TestFunction Shared;
    Shared.Id = 4;
    Shared.Name = "Real_Shared";
    Shared.Address = HexAddress(0x140003000ull + Delta);
    Shared.Rva = std::to_string(0x3000ull + Delta);
    Shared.BytesHash = "shared-stable-bytes";
    Shared.FunctionHash = "shared-stable-fh";
    Shared.CleanAssembly = "asm-shared-stable";
    Shared.CleanPseudo = "pseudo-shared-stable";
    Shared.CleanMicrocode = "micro-shared-stable";
    Shared.Mnemonics = "push mov call ret";
    Shared.Instructions = 24;
    Shared.Nodes = 4;
    Shared.PseudocodeLines = 10;
    Rows.push_back(Shared);

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
  CHECK_EQ(RawIdentity.FunctionCount, static_cast<int64_t>(4));
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
  CHECK_EQ(FirstResult.Matches, static_cast<int64_t>(4));
  CHECK_EQ(FirstResult.NamesConfirmed, static_cast<int64_t>(1));
  CHECK_EQ(FirstResult.NamesSkippedExisting, static_cast<int64_t>(0));
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
  TestMd5();
  TestBigUIntBasics();
  TestKghAgainstPythonOracle();
  TestKghAccumulatorSemantics();
  TestPrimeTables();
  TestStringPool();
  TestNaming();
  TestMatchStore();
  TestIngestRoundTrip();
  TestPortPathSafety();
  TestSyntheticAccuracy();
  TestProvenanceChain();

  std::printf("\n%d checks, %d failed\n", ChecksRun, ChecksFailed);
  return ChecksFailed == 0 ? 0 : 1;
}
