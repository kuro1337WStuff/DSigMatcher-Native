// dsigmatcher_tests: the hash primitives (Sha256, Md5, KGH, prime tables), the naming rules and the
// provenance library (src/Provenance.cpp) in a process WITHOUT the executable's UTF-8 code-page
// manifest, so every path the library takes must reach the file system as UTF-8 by itself.

#include <sqlite3.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <optional>
#include <random>
#include <string>
#include <utility>
#include <vector>

#include "dsigmatcher/KghHash.h"
#include "dsigmatcher/Md5.h"
#include "dsigmatcher/Naming.h"
#include "dsigmatcher/PrimeTable.h"
#include "dsigmatcher/Provenance.h"
#include "dsigmatcher/Sha256.h"

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

#define CHECK(Expr) Report(static_cast<bool>(Expr), #Expr, __FILE__, __LINE__)
#define CHECK_EQ(A, B) Report((A) == (B), #A " == " #B, __FILE__, __LINE__)

std::filesystem::path PathOf(const std::string& Utf8) {
  return std::filesystem::path(std::u8string(Utf8.begin(), Utf8.end()));
}

std::string Utf8Of(const std::filesystem::path& Path) {
  const std::u8string Text = Path.u8string();
  return std::string(Text.begin(), Text.end());
}

// A scratch directory of this process only (several worktrees may run the suite at once), removed at
// the end of main().
const std::filesystem::path& ScratchDirectory() {
  static const std::filesystem::path Directory = [] {
    std::random_device Device;
    const std::string Unique = std::to_string(Device()) + "-" +
                               std::to_string(static_cast<unsigned long long>(
                                   std::chrono::steady_clock::now().time_since_epoch().count() & 0xFFFFFFFFull));
    std::filesystem::path Path = std::filesystem::temp_directory_path() / ("dsigmatcher_tests-" + Unique);
    std::filesystem::create_directories(Path);
    return Path;
  }();
  return Directory;
}

bool Exec(sqlite3* Handle, const std::string& Sql) {
  char* Message = nullptr;
  const bool Ok = sqlite3_exec(Handle, Sql.c_str(), nullptr, nullptr, &Message) == SQLITE_OK;
  if (!Ok) {
    std::printf("  sqlite: %s\n", Message != nullptr ? Message : "?");
  }
  sqlite3_free(Message);
  return Ok;
}

// A minimal Diaphora export at a UTF-8 path: functions(id, name, address, mangled_function) and
// program(processor, md5sum). Addresses are decimal text, as Diaphora stores them.
bool CreateExport(const std::string& Utf8Path, const std::vector<std::pair<uint64_t, std::string>>& Rows,
                  const std::string& Md5) {
  std::error_code Error;
  std::filesystem::remove(PathOf(Utf8Path), Error);
  sqlite3* Handle = nullptr;
  if (sqlite3_open_v2(Utf8Path.c_str(), &Handle, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) != SQLITE_OK) {
    sqlite3_close(Handle);
    return false;
  }
  std::string Sql =
      "create table functions (id integer primary key, name text, address text unique, mangled_function text);"
      "create table program (id integer primary key, processor text, md5sum text);"
      "insert into program values (1, 'metapc', '" + Md5 + "');";
  int64_t Id = 1;
  for (const auto& [Ea, Name] : Rows) {
    Sql += "insert into functions values (" + std::to_string(Id++) + ", '" + Name + "', '" + std::to_string(Ea) +
           "', '" + Name + "');";
  }
  const bool Ok = Exec(Handle, Sql);
  sqlite3_close(Handle);
  return Ok;
}

std::string NameAt(const std::string& Utf8Path, uint64_t Ea) {
  sqlite3* Handle = nullptr;
  std::string Value = "<none>";
  if (sqlite3_open_v2(Utf8Path.c_str(), &Handle, SQLITE_OPEN_READONLY, nullptr) == SQLITE_OK) {
    sqlite3_stmt* Statement = nullptr;
    const std::string Sql = "select name from functions where address = '" + std::to_string(Ea) + "'";
    if (sqlite3_prepare_v2(Handle, Sql.c_str(), -1, &Statement, nullptr) == SQLITE_OK &&
        sqlite3_step(Statement) == SQLITE_ROW) {
      Value = reinterpret_cast<const char*>(sqlite3_column_text(Statement, 0));
    }
    sqlite3_finalize(Statement);
  }
  sqlite3_close(Handle);
  return Value;
}

LabelProposal Proposal(int64_t Row, uint64_t Ea, const std::string& Name, uint64_t Ea2, const std::string& Name2) {
  LabelProposal P;
  P.SourceRow = Row;
  P.Category = "best";
  P.Line = "00000";
  P.Description = "Bytes hash";
  P.RatioText = "1.0000000";
  P.Ratio = 1.0;
  P.ReferenceEa = Ea;
  P.TargetEa = Ea2;
  P.ReferenceName = Name;
  P.TargetName = Name2;
  return P;
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


void TestNaming() {
  Suite("Naming: IDA placeholders are not real names");

  CHECK(IsAutoNamed("sub_140001000"));
  CHECK(!IsAutoNamed("NtUserPeekMessage"));
  CHECK(!IsAutoNamed("sub"));
  CHECK(IsNullSub("nullsub_1"));
  CHECK(!IsNullSub("sub_null"));

  CHECK(IsPortableSymbol("RealFunction"));
  CHECK(IsPortableSymbol("CryptBaseInitialize"));
  CHECK(IsPortableSymbol("_DllMainCRTStartup"));
  CHECK(IsPortableSymbol("startup"));          // only the exact name "start" is IDA's
  CHECK(IsPortableSymbol("Start"));
  CHECK(IsPortableSymbol("DllEntryPointEx"));
  CHECK(IsPortableSymbol("j"));
  CHECK(IsPortableSymbol("subroutine"));
  CHECK(IsPortableSymbol("unknown_libname"));  // no trailing '_'
  for (const char* Placeholder : {"sub_1000", "nullsub_2", "nullsub", "", "...", "j_memcpy", "j_sub_1400",
                                  "unknown_libname_12", "DllEntryPoint", "start"}) {
    CHECK(IsPlaceholderName(Placeholder));
    CHECK(!IsPortableSymbol(Placeholder));
  }
  CHECK_EQ(std::string(kStrippedDescription), std::string("Same binary with symbols stripped"));
}

void TestTimestamp() {
  Suite("CurrentUtcTimestamp: YYYY-MM-DDTHH:MM:SSZ through strftime (F61)");
  const std::string Stamp = CurrentUtcTimestamp();
  CHECK_EQ(Stamp.size(), static_cast<size_t>(20));
  bool Shape = Stamp.size() == 20;
  for (size_t Index = 0; Shape && Index < Stamp.size(); ++Index) {
    const char Ch = Stamp[Index];
    switch (Index) {
      case 4:
      case 7:
        Shape = Ch == '-';
        break;
      case 10:
        Shape = Ch == 'T';
        break;
      case 13:
      case 16:
        Shape = Ch == ':';
        break;
      case 19:
        Shape = Ch == 'Z';
        break;
      default:
        Shape = Ch >= '0' && Ch <= '9';
        break;
    }
  }
  CHECK(Shape);
  CHECK(Stamp.compare(0, 2, "20") == 0);
}

void TestInspectFailures() {
  Suite("InspectDatabase: failure kinds, and every message names the path (F07)");
  const std::filesystem::path Dir = ScratchDirectory() / "inspect";
  std::filesystem::create_directories(Dir);

  const std::string Missing = Utf8Of(Dir / "nothere.sqlite");
  const DatabaseIdentity M = InspectDatabase(Missing);
  CHECK(!M.Ok && M.Failure == PortFailure::Io);
  CHECK(M.Error.find(Missing) != std::string::npos);

  const DatabaseIdentity D = InspectDatabase(Utf8Of(Dir));
  CHECK(!D.Ok && D.Failure == PortFailure::Io);
  CHECK(D.Error.find("is a directory") != std::string::npos);

  const std::string Text = Utf8Of(Dir / "junk.txt");
  std::ofstream(PathOf(Text)) << "this is not a database, it is a text file with enough bytes to be read";
  const DatabaseIdentity J = InspectDatabase(Text);
  CHECK(!J.Ok && J.Failure == PortFailure::Io);
  CHECK(J.Error.find("is not an SQLite database") != std::string::npos);
  CHECK(J.Error.find(Text) != std::string::npos);

  const std::string Results = Utf8Of(Dir / "r.diaphora");
  {
    sqlite3* Handle = nullptr;
    CHECK(sqlite3_open_v2(Results.c_str(), &Handle, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) == SQLITE_OK);
    CHECK(Exec(Handle, "create table config (main_db text); create table results (type text);"));
    sqlite3_close(Handle);
  }
  const DatabaseIdentity R = InspectDatabase(Results);
  CHECK(!R.Ok && R.Failure == PortFailure::Input && R.IsResultsFile);
  CHECK(R.Error.find("results file") != std::string::npos);
  CHECK(R.Error.find("not a Diaphora export") != std::string::npos);

  const std::string Empty = Utf8Of(Dir / "empty.sqlite");
  std::ofstream(PathOf(Empty)).close();  // a zero-byte file is an empty SQLite database
  const DatabaseIdentity E = InspectDatabase(Empty);
  CHECK(!E.Ok && E.Failure == PortFailure::Input && !E.IsResultsFile);
  CHECK(E.Error.find("no 'functions' table") != std::string::npos);

  const std::string Good = Utf8Of(Dir / "good.sqlite");
  CHECK(CreateExport(Good, {{0x1000, "Alpha"}}, "00112233445566778899aabbccddeeff"));
  const DatabaseIdentity G = InspectDatabase(Good);
  CHECK(G.Ok && G.Failure == PortFailure::None && G.FunctionCount == 1);
  CHECK_EQ(G.InputMd5, std::string("00112233445566778899aabbccddeeff"));
  CHECK(!G.HasProvenance);
}

void TestFileHashAndStoredPath() {
  Suite("FileSha256Hex and StoredPath (F34 path policy, F64 read errors)");
  const std::filesystem::path Dir = ScratchDirectory() / "hash";
  std::filesystem::create_directories(Dir);
  const std::string File = Utf8Of(Dir / "abc.bin");
  std::ofstream(PathOf(File), std::ios::binary) << "abc";
  CHECK(FileSha256Hex(File) ==
        std::optional<std::string>("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
  CHECK(!FileSha256Hex(Utf8Of(Dir / "absent.bin")).has_value());
  CHECK(!FileSha256Hex(Utf8Of(Dir)).has_value());  // a directory cannot be read to its end

  CHECK_EQ(StoredPath(File, false), std::string("abc.bin"));
  CHECK_EQ(StoredPath("abc.bin", false), std::string("abc.bin"));
  CHECK_EQ(StoredPath("", false), std::string());
  const std::string Full = StoredPath(File, true);
  CHECK(PathOf(Full).is_absolute());
  CHECK(std::filesystem::equivalent(PathOf(Full), PathOf(File)));
  const std::string Relative = StoredPath("some/dir/../x.sqlite", true);
  CHECK(PathOf(Relative).is_absolute());
  CHECK(Relative.find("..") == std::string::npos);
}

// F47: a port to and from paths outside every ANSI code page, in this manifest-less process.
void TestUnicodePort() {
  Suite("PortLabels with non-ANSI UTF-8 paths, no code-page manifest (F47)");
  // "ポート-дсиг-ü": Japanese, Cyrillic and Latin-1 in one directory name
  const std::string Name = "\xe3\x83\x9d\xe3\x83\xbc\xe3\x83\x88-\xd0\xb4\xd1\x81\xd0\xb8\xd0\xb3-\xc3\xbc";
  const std::filesystem::path Dir = ScratchDirectory() / PathOf(Name);
  std::filesystem::create_directories(Dir);
  const std::string Ref = Utf8Of(Dir / PathOf("r\xc3\xa9" "f.sqlite"));
  const std::string Target = Utf8Of(Dir / PathOf("\xe3\x82\xbf\xe3\x83\xbc\xe3\x82\xb2\xe3\x83\x83\xe3\x83\x88.sqlite"));
  const std::string OutName = "\xe3\x83\x9d\xe3\x83\xbc\xe3\x83\x88.sqlite";
  const std::string Out = Utf8Of(Dir / PathOf(OutName));
  CHECK(CreateExport(Ref, {{0x1000, "Alpha"}, {0x2000, "Beta"}}, "11"));
  CHECK(CreateExport(Target, {{0x5000, "sub_5000"}, {0x6000, "DllEntryPoint"}}, "22"));
  CHECK(std::filesystem::exists(PathOf(Ref)) && std::filesystem::exists(PathOf(Target)));

  LabelPortOptions Options;
  Options.ReferencePath = Ref;
  Options.TargetPath = Target;
  Options.OutputPath = Out;
  const LabelPortResult Result = PortLabels(
      Options, {Proposal(1, 0x1000, "Alpha", 0x5000, "sub_5000"), Proposal(2, 0x2000, "Beta", 0x6000, "DllEntryPoint")});
  CHECK(Result.Ok);
  if (!Result.Ok) {
    std::printf("  error: %s\n", Result.Error.c_str());
    return;
  }
  CHECK(std::filesystem::is_regular_file(PathOf(Out)));  // under exactly that name
  CHECK(!std::filesystem::exists(PathOf(Out + ".dsig-tmp")));
  CHECK_EQ(NameAt(Out, 0x5000), std::string("Alpha"));
  CHECK_EQ(NameAt(Out, 0x6000), std::string("Beta"));  // DllEntryPoint is a placeholder: replaced
  CHECK_EQ(Result.NamesApplied, static_cast<int64_t>(2));
  CHECK(Result.OutputSha256 == FileSha256Hex(Out).value_or("?"));
  const DatabaseIdentity Identity = InspectDatabase(Out);
  CHECK(Identity.Ok && Identity.HopCount == 1);
  if (!Identity.Hops.empty()) {
    CHECK_EQ(Identity.Hops[0].SourcePath, std::string("r\xc3\xa9" "f.sqlite"));  // the file name only
  }
  CHECK(SameFilePath(Out, Utf8Of(Dir / ".." / PathOf(Name) / PathOf(OutName))));

  // A second port over the existing output replaces it.
  const LabelPortResult Again = PortLabels(Options, {Proposal(1, 0x1000, "Alpha", 0x5000, "sub_5000")});
  CHECK(Again.Ok);
  CHECK_EQ(NameAt(Out, 0x6000), std::string("DllEntryPoint"));
}

}

int main() {
  TestSha256();
  TestMd5();
  TestBigUIntBasics();
  TestKghAgainstPythonOracle();
  TestKghAccumulatorSemantics();
  TestPrimeTables();
  TestNaming();
  TestTimestamp();
  TestInspectFailures();
  TestFileHashAndStoredPath();
  TestUnicodePort();

  std::error_code Error;
  std::filesystem::remove_all(ScratchDirectory(), Error);
  std::printf("\n%d checks, %d failed\n", ChecksRun, ChecksFailed);
  return ChecksFailed == 0 ? 0 : 1;
}
