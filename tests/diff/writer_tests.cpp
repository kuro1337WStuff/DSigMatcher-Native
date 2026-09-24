// diff_writer: the .diaphora results writer (01 §10.2-§11; 09 "Results database schema"; 02 §16;
// 06 §16).
//
// 1. Formatting: FormatLine05, FormatAddr08x (Python int() of the address text, then "%08x"),
//    FormatRatio7 ("%.7f", ties to even) against the 03a tie table and Python-generated strings, and
//    cross-checked against the exact big-integer formatter and RatioEngine::Round7 on 10^6 doubles;
//    FormatFixedExact(v, 2), the trace's "%1.2f" percent (Trace.cpp FormatPercent2, which uses no
//    floating-point std::to_chars so it builds with older Apple libc++), against Python strings and
//    against std::to_chars where the standard library has it.
// 2. The writer on hand-made choosers: DDL text, TEXT storage, `insert or ignore` drops with `line`
//    gaps, None choosers, NULL names, the empty-result path, the config row, output replacement,
//    formatting errors that leave an old output untouched, non-ASCII output paths.
// 3. The committed `common` fixture (tools/parity/make_fixture.py, real Diaphora): its chooser dumps
//    written by WriteDiaphoraResults equal Diaphora's own rows at L2. Runs on any SQLite: the writer's
//    output does not depend on the SQLite build.
// 4. Corpus (skips without DSIG_CORPUS_ROOT or the captures): the oracle's after:final_pass and
//    after:find_unmatched dumps of every complete capture, written by WriteDiaphoraResults, are
//    L2-identical to oracle run1, with only config.date differing.

#include <sqlite3.h>

#include <algorithm>
#include <charconv>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <optional>
#include <random>
#include <string>
#include <string_view>
#include <vector>

#include "../../src/diff/FileIo.h"
#include "../../src/diff/ResultsWriterDetail.h"
#include "diff/CorpusPaths.h"
#include "diff/ResultsCompare.h"
#include "diff/TestHarness.h"
#include "diff/fixtures/common/FixtureExpect.h"
#include "dsigmatcher/diff/Errors.h"
#include "dsigmatcher/diff/Json.h"
#include "dsigmatcher/diff/PyValue.h"
#include "dsigmatcher/diff/Ratio.h"
#include "dsigmatcher/diff/ResultsWriter.h"
#include "dsigmatcher/diff/Snapshot.h"
#include "dsigmatcher/diff/Trace.h"

namespace {

using namespace DSig;
using namespace DSig::Diff;
using DSig::Test::PathToUtf8;
using DSig::Test::Utf8ToPath;

double FromBits(uint64_t Bits) {
  double Value = 0.0;
  std::memcpy(&Value, &Bits, sizeof(Value));
  return Value;
}

uint64_t ToBits(double Value) {
  uint64_t Bits = 0;
  std::memcpy(&Bits, &Value, sizeof(Bits));
  return Bits;
}

template <class F>
bool Raises(F&& Fn) {
  try {
    Fn();
  } catch (const DiaphoraWouldRaise&) {
    return true;
  } catch (...) {
    return false;
  }
  return false;
}

template <class F>
bool Unsupported(F&& Fn) {
  try {
    Fn();
  } catch (const UnsupportedInput&) {
    return true;
  } catch (...) {
    return false;
  }
  return false;
}

// ---------------------------------------------------------------------------------------------
// 1. Formatting

void TestFormatLine05() {
  Test::Suite("FormatLine05: \"%05lu\" % n (D:280, D:285)");
  CHECK_TEXT_EQ(FormatLine05(0), "00000");
  CHECK_TEXT_EQ(FormatLine05(7), "00007");
  CHECK_TEXT_EQ(FormatLine05(1234), "01234");
  CHECK_TEXT_EQ(FormatLine05(12345), "12345");
  CHECK_TEXT_EQ(FormatLine05(123456), "123456");  // 01 §10.2
  CHECK_TEXT_EQ(FormatLine05(std::numeric_limits<uint64_t>::max()), "18446744073709551615");
}

void TestFormatAddr08x() {
  Test::Suite("FormatAddr08x: \"%08x\" % int(ea) (D:280, D:286, D:288; 01 §10.2)");
  // Expected strings from CPython 3.13.12: '%08x' % int(s).
  CHECK_TEXT_EQ(FormatAddr08x("4096"), "00001000");
  CHECK_TEXT_EQ(FormatAddr08x("4294967296"), "100000000");  // 01 §10.2, E2
  CHECK_TEXT_EQ(FormatAddr08x("6442455040"), "180001000");
  CHECK_TEXT_EQ(FormatAddr08x("0"), "00000000");
  CHECK_TEXT_EQ(FormatAddr08x("-0"), "00000000");
  CHECK_TEXT_EQ(FormatAddr08x("-1"), "-0000001");        // the sign counts inside the width
  CHECK_TEXT_EQ(FormatAddr08x("-1234"), "-00004d2");
  CHECK_TEXT_EQ(FormatAddr08x("-4294967296"), "-100000000");
  CHECK_TEXT_EQ(FormatAddr08x("-4886718345"), "-123456789");
  CHECK_TEXT_EQ(FormatAddr08x(" 4096 "), "00001000");    // V10
  CHECK_TEXT_EQ(FormatAddr08x("4_096"), "00001000");     // V10
  CHECK_TEXT_EQ(FormatAddr08x("1_2_3"), "0000007b");
  CHECK_TEXT_EQ(FormatAddr08x("0_0"), "00000000");
  CHECK_TEXT_EQ(FormatAddr08x("+5"), "00000005");
  CHECK_TEXT_EQ(FormatAddr08x("007"), "00000007");
  CHECK_TEXT_EQ(FormatAddr08x("-5 "), "-0000005");
  CHECK_TEXT_EQ(FormatAddr08x("\t\n5\r\n"), "00000005");
  CHECK_TEXT_EQ(FormatAddr08x("\v5"), "00000005");
  CHECK_TEXT_EQ(FormatAddr08x(" \f-12\n"), "-000000c");
  CHECK_TEXT_EQ(FormatAddr08x("18446744073709551615"), "ffffffffffffffff");
  CHECK_TEXT_EQ(FormatAddr08x("18446744073709551616"), "10000000000000000");  // beyond uint64
  CHECK_TEXT_EQ(FormatAddr08x("1180591620717411303424"), "400000000000000000");  // 2**70
  // D:96-97 set_int_max_str_digits(0): no 4300-digit limit.
  CHECK_TEXT_EQ(FormatAddr08x(std::string(5000, '0') + "255"), "000000ff");
  // ValueError sites.
  for (const char* Bad : {"", " ", "+", "-", "0x10", "4__0", "_4", "4_", "5.0", "1e3", "- 5", "--5", "+-5", "5-",
                          "0b1", "1 2", "+_1", "\x1c" "5", "5\x1f", "abc"}) {
    CHECK(Raises([&] { FormatAddr08x(Bad); }));
  }
  CHECK(Raises([&] { FormatAddr08x(std::string_view("5\0", 2)); }));
  CHECK(Raises([&] { FormatAddr08x(std::string_view("\0" "5", 2)); }));
  // Non-ASCII: Python maps Unicode digits / spaces first; not ported, so refused (exit 4), never guessed.
  CHECK(Unsupported([&] { FormatAddr08x("\xc2\xa0" "5"); }));
  CHECK(Unsupported([&] { FormatAddr08x("\xd9\xa5"); }));
}

struct RatioCase {
  uint64_t Bits;
  const char* Python;
};

// '%.7f' % v from CPython 3.13.12 for these exact doubles (struct.pack('>d', v).hex()).
const RatioCase kRatioCases[] = {
    {0x3f70000000000000ull, "0.0039062"},  // 03a §5 tie table: 1/256, half-even down
    {0x3fefa00000000000ull, "0.9882812"},  // 253/256
    {0x3fefe00000000000ull, "0.9960938"},  // 255/256, half-even up
    {0x3f94000000000000ull, "0.0195312"},  // 5/256
    {0x3f88000000000000ull, "0.0117188"},  // 3/256
    {0x3fe5555555555555ull, "0.6666667"},  // 2/3
    {0x0000000000000000ull, "0.0000000"},
    {0x8000000000000000ull, "-0.0000000"},
    {0x3ff0000000000000ull, "1.0000000"},
    {0x3fefffffe5280d65ull, "0.9999999"},  // 0.99999995
    {0x3fefffffe5280d66ull, "1.0000000"},  // the next double
    {0x3feffffffaa19c47ull, "1.0000000"},  // 0.99999999 (E6): a partial can print as 1.0000000
    {0x3fefffffe5280d0bull, "0.9999999"},
    {0x3e6ad7f29abcaf48ull, "0.0000000"},  // 5e-8, just below the half
    {0x3e7ad7f29abcaf48ull, "0.0000001"},  // 1e-7
    {0x3e8421f5f40d8376ull, "0.0000001"},  // 1.5e-7
    {0x3e90c6f7a0b5ed8dull, "0.0000002"},  // 2.5e-7
    {0x0000000000000001ull, "0.0000000"},  // the smallest subnormal
    {0xbe112e0be826d695ull, "-0.0000000"},  // -1e-9 keeps its sign
    {0x3fe0000000000000ull, "0.5000000"},
    {0x3fecef038e29f9cfull, "0.9041765"},
    {0x3fc3333333333333ull, "0.1500000"},
    {0x3fd3333333333334ull, "0.3000000"},  // 0.1 + 0.2
    {0x419d6f34547e6b72ull, "123456789.1234567"},
    {0x40c81c8000006b60ull, "12345.0000001"},
    {0x432fffffffffffffull, "4503599627370495.5000000"},
    {0x4340000000000000ull, "9007199254740992.0000000"},
    {0x7e37e43c8800759cull,
     "1000000000000000052504760255204420248704468581108159154915854115511802457988908195786371375080447864043704443"
     "832883878176942523235360430575644792184786706982848387200926575803737830233794788090059368953234970799945081"
     "119038967640880074652742780142494579258788820056842838115669472196386865459400540160.0000000"},  // 1e300
    {0x7fefffffffffffffull,
     "179769313486231570814527423731704356798070567525844996598917476803157260780028538760589558632766878171540458"
     "953514382464234321326889464182768467546703537516986049910576551282076245490090389328944075868508455133942304"
     "583236903222948165808559332123348274797826204144723168738177180919299881250404026184124858368.0000000"},  // DBL_MAX
};

void TestFormatRatio7() {
  Test::Suite("FormatRatio7: \"%.7f\" % ratio, correctly rounded half-even (D:290; 01 §10.2; 03a §5)");
  Test::Note(std::string("std::to_chars backend: ") + (Detail::FormatRatio7UsesToChars() ? "yes" : "no (exact fallback)"));
  for (const RatioCase& Case : kRatioCases) {
    const double Value = FromBits(Case.Bits);
    CHECK_TEXT_EQ(FormatRatio7(Value), Case.Python);
    CHECK_TEXT_EQ(Detail::FormatRatio7Exact(Value), Case.Python);
  }
  // Python spells every NaN "nan" (the sign bit is ignored) and the infinities "inf" / "-inf".
  CHECK_TEXT_EQ(FormatRatio7(std::numeric_limits<double>::quiet_NaN()), "nan");
  CHECK_TEXT_EQ(FormatRatio7(-std::numeric_limits<double>::quiet_NaN()), "nan");
  CHECK_TEXT_EQ(FormatRatio7(std::numeric_limits<double>::infinity()), "inf");
  CHECK_TEXT_EQ(FormatRatio7(-std::numeric_limits<double>::infinity()), "-inf");
  CHECK_TEXT_EQ(Detail::FormatRatio7Exact(-std::numeric_limits<double>::quiet_NaN()), "nan");
  CHECK_TEXT_EQ(Detail::FormatRatio7Exact(-std::numeric_limits<double>::infinity()), "-inf");
  // The 03a §5 half-up mutation gives the other answer on every tie of the table.
  CHECK(FormatRatio7(0.00390625) != "0.0039063");
}

// Every finite double: FormatRatio7 == the exact formatter, and float(FormatRatio7(v)) == Round7(v)
// bit for bit (Round7 is float("{0:.7f}".format(v)), D:1676/1710, exact for every finite double).
struct CrossCheck {
  size_t Count = 0;
  size_t TextMismatch = 0;
  size_t RoundMismatch = 0;
  std::string FirstFailure;
};

void CrossCheckOne(double Value, CrossCheck& Out) {
  ++Out.Count;
  const std::string Text = FormatRatio7(Value);
  const std::string Exact = Detail::FormatRatio7Exact(Value);
  if (Text != Exact) {
    ++Out.TextMismatch;
    if (Out.FirstFailure.empty()) {
      Out.FirstFailure = "bits " + RatioBitsHex(Value) + ": to_chars " + Text + " exact " + Exact;
    }
  }
  const std::optional<double> Parsed = PyFloat(Text);
  const double Rounded = RatioEngine::Round7(Value);
  if (!Parsed || ToBits(*Parsed) != ToBits(Rounded)) {
    ++Out.RoundMismatch;
    if (Out.FirstFailure.empty()) {
      Out.FirstFailure = "bits " + RatioBitsHex(Value) + ": text " + Text + " Round7 bits " + RatioBitsHex(Rounded);
    }
  }
}

void TestFormatRatio7CrossCheck() {
  Test::Suite("FormatRatio7 vs exact formatter vs RatioEngine::Round7 (10^6 random doubles + ties + ratio grid)");
  CrossCheck Out;
  std::mt19937_64 Rng(0x4C34u);  // fixed seed: reproducible
  std::uniform_real_distribution<double> Unit(0.0, 1.0);
  for (int I = 0; I < 400000; ++I) {
    CrossCheckOne(Unit(Rng), Out);  // the ratio range
  }
  std::uniform_int_distribution<int> Exponent(1023 - 40, 1023 + 30);  // about 1e-12 .. 1e9
  for (int I = 0; I < 300000; ++I) {
    const uint64_t Bits = (static_cast<uint64_t>(Rng() & 1u) << 63) | (static_cast<uint64_t>(Exponent(Rng)) << 52) |
                          (Rng() & ((uint64_t{1} << 52) - 1u));
    CrossCheckOne(FromBits(Bits), Out);
  }
  for (int I = 0; I < 300000; ++I) {
    const uint64_t Bits = Rng();  // any bit pattern: subnormals, huge values
    const double Value = FromBits(Bits);
    if (std::isfinite(Value)) {
      CrossCheckOne(Value, Out);
    } else {
      CrossCheckOne(FromBits(Bits & ~(uint64_t{1} << 62)), Out);
    }
  }
  const size_t Random = Out.Count;
  // Every 7-decimal tie in [0, 64]: v * 10^7 is a half-integer exactly for the odd multiples of 1/256.
  for (int K = 1; K < 64 * 256; K += 2) {
    CrossCheckOne(K / 256.0, Out);
  }
  // Quick-ratio shaped values 2m/L (03a §2), every m for L up to 1200.
  for (int L = 1; L <= 1200; ++L) {
    for (int M = 0; 2 * M <= L; ++M) {
      CrossCheckOne((2.0 * M) / L, Out);
    }
  }
  Test::Note(std::to_string(Random) + " random + " + std::to_string(Out.Count - Random) +
             " tie/grid values; text mismatches " + std::to_string(Out.TextMismatch) + ", Round7 mismatches " +
             std::to_string(Out.RoundMismatch) + (Out.FirstFailure.empty() ? "" : "; first: " + Out.FirstFailure));
  CHECK_NUM_EQ(Random, 1000000);
  CHECK_NUM_EQ(Out.TextMismatch, 0);
  CHECK_NUM_EQ(Out.RoundMismatch, 0);
}

// "%1.2f" % v (Python 3.13) for the trace's percent, and the exact formatter at other precisions.
void TestFormatFixed2() {
  Test::Suite("FormatFixedExact(v, 2) = Python \"%1.2f\" (the trace percent, no floating-point to_chars)");
  const std::vector<std::pair<double, const char*>> Python = {
      {0.125, "0.12"},    {0.375, "0.38"},   {2.675, "2.67"},   {0.005, "0.01"},     {1.005, "1.00"},
      {0.015, "0.01"},    {0.0025, "0.00"},  {99.995, "100.00"}, {45.724, "45.72"},   {100.0, "100.00"},
      {-0.0, "-0.00"},    {-0.004, "-0.00"}, {-1.125, "-1.12"}, {66.66666666666667, "66.67"},
      {1e22, "10000000000000000000000.00"},  {5e-324, "0.00"},  {0.995, "0.99"},     {0.9950000000000001, "1.00"},
  };
  for (const auto& [Value, Text] : Python) {
    CHECK_TEXT_EQ(Detail::FormatFixedExact(Value, 2), Text);
    CHECK_TEXT_EQ(FormatPercent2(Value), Text);
  }
  CHECK_TEXT_EQ(Detail::FormatFixedExact(0.00000005, 7), "0.0000000");  // a tie below, to even
  CHECK_TEXT_EQ(Detail::FormatFixedExact(1.5, 1), "1.5");
  CHECK_TEXT_EQ(Detail::FormatFixedExact(0.25, 1), "0.2");               // an exact tie, to even
  CHECK_TEXT_EQ(Detail::FormatFixedExact(123.456, 9), "123.456000000");
#if defined(__cpp_lib_to_chars) && __cpp_lib_to_chars >= 201611L && !defined(__APPLE__)
  // Where the standard library has floating-point to_chars, it must agree everywhere (not on Apple
  // platforms, where the overloads are unavailable before macOS 13.3).
  size_t Count = 0;
  size_t Mismatch = 0;
  std::string First;
  const auto One = [&](double Value) {
    char Buffer[400];
    const std::to_chars_result Done = std::to_chars(Buffer, Buffer + sizeof(Buffer), Value, std::chars_format::fixed, 2);
    const std::string Want(Buffer, Done.ptr);
    const std::string Got = Detail::FormatFixedExact(Value, 2);
    ++Count;
    if (Got != Want) {
      ++Mismatch;
      if (First.empty()) {
        First = RatioBitsHex(Value) + ": to_chars " + Want + " exact " + Got;
      }
    }
  };
  std::mt19937_64 Rng(0x50321u);
  std::uniform_real_distribution<double> Percent(0.0, 100.0);
  for (int I = 0; I < 200000; ++I) {
    One(Percent(Rng));
  }
  for (int I = 0; I < 100000; ++I) {
    const uint64_t Bits = Rng();
    const double Value = FromBits(Bits);
    One(std::isfinite(Value) ? Value : FromBits(Bits & ~(uint64_t{1} << 62)));
  }
  for (int K = 1; K < 800 * 8; K += 2) {
    One(K / 8.0);  // every 2-decimal tie in [0, 800]: the odd multiples of 1/8
  }
  for (int L = 1; L <= 1500; ++L) {
    for (int M = 0; M <= L; ++M) {
      One(static_cast<double>(M * 100) / L);  // show_summary's (total * 100) / total_functions1
    }
  }
  Test::Note(std::to_string(Count) + " values against std::to_chars; mismatches " + std::to_string(Mismatch) +
             (First.empty() ? "" : "; first: " + First));
  CHECK_NUM_EQ(Mismatch, 0);
#else
  Test::Note("no floating-point std::to_chars in this standard library: checked against Python strings only");
#endif
}

// ---------------------------------------------------------------------------------------------
// 2. The writer on hand-made choosers

Item MakeItem(Interners& Ids, const char* Ea1, std::optional<const char*> Name1, const char* Ea2,
              std::optional<const char*> Name2, const char* Desc, double Ratio, int64_t Nodes1, int64_t Nodes2) {
  Item It;
  It.Ea1 = Ids.Addr(Ea1);
  It.Name1 = Name1 ? Ids.Name(*Name1) : kNoneName;
  It.Ea2 = Ids.Addr(Ea2);
  It.Name2 = Name2 ? Ids.Name(*Name2) : kNoneName;
  It.Desc = Ids.Desc(Desc);
  It.Ratio = Ratio;
  It.Nodes1 = Nodes1;
  It.Nodes2 = Nodes2;
  return It;
}

std::string Scratch(const std::string& Dir, const std::string& Name) { return PathToUtf8(Utf8ToPath(Dir) / Utf8ToPath(Name)); }

bool FileExists(const std::string& Path) {
  std::error_code Error;
  return std::filesystem::exists(Utf8ToPath(Path), Error);
}

std::string ReadBytes(const std::string& Path) {
  std::string Out;
  Test::ReadTextFile(Path, Out);
  return Out;
}

void WriteBytes(const std::string& Path, const std::string& Bytes) {
  std::ofstream Out(Utf8ToPath(Path), std::ios::binary | std::ios::trunc);
  Out << Bytes;
}

// typeof() of every stored value, one string per row ("text,text,..."), plus the sqlite_master count.
std::vector<std::string> TypeOfRows(const std::string& Path, const char* Sql) {
  std::vector<std::string> Rows;
  DiffDatabase Db;
  Db.OpenSingle(Path);
  Statement S = Db.Prepare(Sql);
  while (S.Step()) {
    std::string Row;
    for (int C = 0; C < S.ColumnCount(); ++C) {
      Row += (C ? "," : "") + std::string(S.Text(C));
    }
    Rows.push_back(Row);
  }
  return Rows;
}

bool LooksLikeAscTime(const std::string& Text) {
  // "%s %s%3d %.2d:%.2d:%.2d %d": "Wed Sep  3 12:34:56 2026"
  static const char* const Days[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
  static const char* const Months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                       "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
  if (Text.size() < 24) {
    return false;
  }
  bool Day = false;
  bool Month = false;
  for (const char* D : Days) {
    Day = Day || Text.compare(0, 3, D) == 0;
  }
  for (const char* M : Months) {
    Month = Month || Text.compare(4, 3, M) == 0;
  }
  const auto Digit = [&](size_t I) { return Text[I] >= '0' && Text[I] <= '9'; };
  const bool DayOfMonth = (Text[8] == ' ' || Digit(8)) && Digit(9) && (Text[8] != '0');
  return Day && Month && Text[3] == ' ' && Text[7] == ' ' && DayOfMonth && Text[10] == ' ' && Digit(11) &&
         Digit(12) && Text[13] == ':' && Digit(14) && Digit(15) && Text[16] == ':' && Digit(17) && Digit(18) &&
         Text[19] == ' ' && Digit(20) && Digit(21) && Digit(22) && Digit(23);
}

void TestWriterRows(const std::string& Dir) {
  Test::Suite("WriteDiaphoraResults: DDL, TEXT storage, insert-or-ignore line gaps, None choosers (D:2374-2429)");
  Interners Ids;
  FinalResults R;
  // 02 probe 9 case A: one address pair twice in best ("100% equal" under the mangled key, then the
  // same-name match); the second row is dropped and line 00001 is consumed.
  R.Best.push_back(MakeItem(Ids, "4096", "?f@@YAXXZ", "4096", "?f@@YAXXZ", "100% equal", 1.0, 5, 5));
  R.Best.push_back(MakeItem(Ids, "4096", "f(void)", "4096", "f(void)", "Perfect match, same name", 1.0, 5, 5));
  R.Best.push_back(MakeItem(Ids, "8192", "g", "12288", "g2", "Equal assembly", 1.0, 3, 3));
  R.Partial.push_back(MakeItem(Ids, "20480", "h", "24576", "h", "Perfect match, same name", 0.00390625, 2, 2));
  // Multimatch rows duplicating a best pair are dropped too (01 E4); " 08192" formats like "8192", so
  // the formatted pair collides although the address texts differ.
  R.Multimatch.push_back(MakeItem(Ids, "8192", "g", "12288", "g2", "Related compilation unit", 0.5, 3, 3));
  R.Multimatch.push_back(MakeItem(Ids, " 08192", "g", "12288", "g2", "Related compilation unit", 0.5, 3, 3));
  R.Multimatch.push_back(MakeItem(Ids, "28672", "m", "32768", std::nullopt, "Related compilation unit", 0.5, 1, -1));
  R.UnmatchedPrimary = std::vector<UnmatchedRow>{{Ids.Addr("4294967296"), Ids.Name("only_diff")},
                                                 {Ids.Addr("12"), kNoneName}};
  R.UnmatchedSecondary = std::nullopt;  // find_unmatched never created it: no rows (D:2420)

  WriteArgs A;
  A.OutPath = Scratch(Dir, "rows.diaphora");
  A.MainDb = "rel/db1.sqlite";
  A.DiffDb = "C:\\x\\db2.sqlite";
  A.Date = "Wed Sep  3 12:34:56 2026";
  WriteDiaphoraResults(A, R, Ids);

  const Test::ResultsFile File = Test::ReadResultsFile(A.OutPath);
  CHECK(File.Error.empty());
  CHECK(File.Schema == Test::DiaphoraSchema());
  CHECK(File.AllText);
  CHECK_NUM_EQ(File.Config.size(), 1);
  if (File.Config.size() == 1) {
    CHECK_TEXT_EQ(File.Config[0][0], "rel/db1.sqlite");  // exactly as passed (D:2392)
    CHECK_TEXT_EQ(File.Config[0][1], "C:\\x\\db2.sqlite");
    CHECK_TEXT_EQ(File.Config[0][2], "3.4");
    CHECK_TEXT_EQ(File.Config[0][3], "Wed Sep  3 12:34:56 2026");
  }
  const std::vector<std::string> Expected = {
      "best 00000 00001000 ?f@@YAXXZ 00001000 ?f@@YAXXZ 1.0000000 5 5 100% equal",
      "best 00002 00002000 g 00003000 g2 1.0000000 3 3 Equal assembly",
      "partial 00000 00005000 h 00006000 h 0.0039062 2 2 Perfect match, same name",
      "multimatch 00002 00007000 m 00008000 None 0.5000000 1 -1 Related compilation unit",
  };
  CHECK_NUM_EQ(File.Results.size(), Expected.size());
  for (size_t I = 0; I < File.Results.size() && I < Expected.size(); ++I) {
    CHECK_TEXT_EQ(Test::Describe(File.Results[I]), Expected[I]);
  }
  if (File.Results.size() == 4) {
    CHECK(File.Results[3].Name2Null);  // Python None binds NULL
    CHECK(!File.Results[3].NameNull);
  }
  CHECK_NUM_EQ(File.Unmatched.size(), 2);
  if (File.Unmatched.size() == 2) {
    CHECK_TEXT_EQ(File.Unmatched[0].Type + " " + File.Unmatched[0].Line + " " + File.Unmatched[0].Address + " " +
                      File.Unmatched[0].Name,
                  "primary 00000 100000000 only_diff");
    CHECK_TEXT_EQ(File.Unmatched[1].Type + " " + File.Unmatched[1].Line + " " + File.Unmatched[1].Address,
                  "primary 00001 0000000c");
    CHECK(File.Unmatched[1].NameNull);
  }
  // typeof(): TEXT everywhere, NULL only for the None name.
  const auto Types = TypeOfRows(A.OutPath,
                                "select typeof(type), typeof(line), typeof(address), typeof(name), typeof(address2), "
                                "typeof(name2), typeof(ratio), typeof(nodes1), typeof(nodes2), typeof(description) "
                                "from results order by rowid");
  CHECK_NUM_EQ(Types.size(), 4);
  if (Types.size() == 4) {
    CHECK_TEXT_EQ(Types[0], "text,text,text,text,text,text,text,text,text,text");
    CHECK_TEXT_EQ(Types[3], "text,text,text,text,text,null,text,text,text,text");
  }
  const auto ConfigTypes =
      TypeOfRows(A.OutPath, "select typeof(main_db), typeof(diff_db), typeof(version), typeof(date) from config");
  CHECK(ConfigTypes.size() == 1 && ConfigTypes[0] == "text,text,text,text");
  // Default journal mode, like Python's sqlite3.connect (01 §11.2, V8).
  const auto Journal = TypeOfRows(A.OutPath, "pragma journal_mode");
  CHECK(Journal.size() == 1 && Journal[0] == "delete");

  // The secondary chooser as an empty list and as rows; line numbers restart per chooser.
  R.UnmatchedSecondary = std::vector<UnmatchedRow>{};
  WriteDiaphoraResults(A, R, Ids);
  CHECK_NUM_EQ(Test::ReadResultsFile(A.OutPath).Unmatched.size(), 2);
  R.UnmatchedSecondary = std::vector<UnmatchedRow>{{Ids.Addr("4096"), Ids.Name("?f@@YAXXZ")}};
  R.UnmatchedPrimary = std::nullopt;
  WriteDiaphoraResults(A, R, Ids);
  const Test::ResultsFile Secondary = Test::ReadResultsFile(A.OutPath);
  CHECK(Secondary.Unmatched.size() == 1 && Secondary.Unmatched[0].Type == "secondary" &&
        Secondary.Unmatched[0].Line == "00000" && Secondary.Unmatched[0].Address == "00001000");
}

void TestWriterEmptyAndReplace(const std::string& Dir) {
  Test::Suite("WriteDiaphoraResults: empty-result path, config row, output replacement (01 §5.1, §11.2)");
  Interners Ids;
  const FinalResults Empty;  // diff() returned False, or nothing matched: save_results still runs
  WriteArgs A;
  A.OutPath = Scratch(Dir, "empty.diaphora");
  A.MainDb = "db1.sqlite";
  A.DiffDb = "db2.sqlite";
  WriteBytes(A.OutPath, "stale bytes, not a database");  // D:2379-2381 removes an existing file first
  WriteDiaphoraResults(A, Empty, Ids);
  const Test::ResultsFile File = Test::ReadResultsFile(A.OutPath);
  CHECK(File.Error.empty());
  CHECK(File.Schema == Test::DiaphoraSchema());
  CHECK(File.Results.empty());
  CHECK(File.Unmatched.empty());
  CHECK_NUM_EQ(File.Config.size(), 1);
  if (File.Config.size() == 1) {
    CHECK_TEXT_EQ(File.Config[0][2], "3.4");
    CHECK(LooksLikeAscTime(File.Config[0][3]));  // WriteArgs.Date empty -> AscTimeNow()
  }
  CHECK(LooksLikeAscTime(AscTimeNow()));
  CHECK(LooksLikeAscTime("Wed Sep  3 12:34:56 2026"));
  CHECK(!LooksLikeAscTime("Wed Sep 03 12:34:56 2026"));  // %3d pads with a space, never a zero
}

void TestWriterErrors(const std::string& Dir) {
  Test::Suite("WriteDiaphoraResults: formatting errors leave the old output untouched (01 §11.2 V9, §13)");
  const std::string Out = Scratch(Dir, "errors.diaphora");
  const std::string Old = "previous results";
  {
    Interners Ids;
    FinalResults R;
    R.Best.push_back(MakeItem(Ids, "4096", "f", "4096", "f", "100% equal", 1.0, 1, 1));
    R.Partial.push_back(MakeItem(Ids, "0x1000", "g", "8192", "g", "Loop count", 0.5, 1, 1));  // int() ValueError
    WriteBytes(Out, Old);
    WriteArgs A;
    A.OutPath = Out;
    CHECK(Raises([&] { WriteDiaphoraResults(A, R, Ids); }));
    CHECK_TEXT_EQ(ReadBytes(Out), Old);  // add_item raised inside diff(): save_results never ran
  }
  {
    Interners Ids;
    FinalResults R;
    R.UnmatchedSecondary = std::vector<UnmatchedRow>{{kNoneAddr, Ids.Name("f")}};  // int(None): TypeError
    WriteArgs A;
    A.OutPath = Out;
    CHECK(Raises([&] { WriteDiaphoraResults(A, R, Ids); }));
    CHECK_TEXT_EQ(ReadBytes(Out), Old);
  }
  {
    Interners Ids;
    FinalResults R;
    R.Best.push_back(MakeItem(Ids, "4096", "f", "\xd9\xa5", "f", "100% equal", 1.0, 1, 1));  // Unicode digit
    WriteArgs A;
    A.OutPath = Out;
    CHECK(Unsupported([&] { WriteDiaphoraResults(A, R, Ids); }));
    CHECK_TEXT_EQ(ReadBytes(Out), Old);
  }
  {
    // os.remove() of a directory raises: I/O failure, nothing written.
    Interners Ids;
    const std::string DirOut = Scratch(Dir, "a_directory.diaphora");
    std::error_code Error;
    std::filesystem::create_directories(Utf8ToPath(DirOut), Error);
    WriteArgs A;
    A.OutPath = DirOut;
    bool Io = false;
    try {
      WriteDiaphoraResults(A, FinalResults{}, Ids);
    } catch (const IoFailure&) {
      Io = true;
    }
    CHECK(Io);
  }
  {
    // A missing parent directory: sqlite3.connect raises "unable to open database file".
    Interners Ids;
    WriteArgs A;
    A.OutPath = Scratch(Dir, "no/such/dir/out.diaphora");
    bool Io = false;
    try {
      WriteDiaphoraResults(A, FinalResults{}, Ids);
    } catch (const IoFailure&) {
      Io = true;
    }
    CHECK(Io);
  }
}

void TestWriterUnicodePath(const std::string& Dir) {
  Test::Suite("WriteDiaphoraResults: non-ASCII output path, in process (FileIo.h)");
  Interners Ids;
  FinalResults R;
  R.Best.push_back(MakeItem(Ids, "4096", "f\xc3\xbc", "8192", "\xe6\x97\xa5", "Perfect match, same name", 1.0, 2, 2));
  WriteArgs A;
  A.OutPath = Scratch(Dir, "r\xc3\xa9sultats_\xc3\xbc_\xe6\x97\xa5\xe6\x9c\xac.diaphora");  // résultats_ü_日本
  A.MainDb = "d\xc3\xa9j\xc3\xa0.sqlite";
  WriteBytes(A.OutPath, "old");
  WriteDiaphoraResults(A, R, Ids);
  CHECK(Detail::PathExists(A.OutPath));
  const Test::ResultsFile File = Test::ReadResultsFile(A.OutPath);
  CHECK(File.Error.empty());
  CHECK(File.Results.size() == 1 && File.Results[0].Name == "f\xc3\xbc" && File.Results[0].Name2 == "\xe6\x97\xa5");
  CHECK(File.Config.size() == 1 && File.Config[0][0] == "d\xc3\xa9j\xc3\xa0.sqlite");
  // No stray file under the ANSI-mangled name next to it.
  size_t Entries = 0;
  std::error_code Error;
  for (const auto& Entry : std::filesystem::directory_iterator(Utf8ToPath(Dir), Error)) {
    Entries += PathToUtf8(Entry.path().filename()).find("sultats_") != std::string::npos ? 1u : 0u;
  }
  CHECK_NUM_EQ(Entries, 1);
}

// ---------------------------------------------------------------------------------------------
// 3. The committed `common` fixture

void TestCommonFixture(const std::string& Dir) {
  Test::Suite("fixture common: chooser dumps of real Diaphora -> WriteDiaphoraResults == Diaphora's rows (L2)");
  const std::string Fixture = PathToUtf8(Utf8ToPath(Test::TestDataDir()) / "fixtures" / "common");
  if (Test::TestDataDir().empty() || !FileExists(PathToUtf8(Utf8ToPath(Fixture) / "after_final_pass.json"))) {
    Test::Skip("fixture common", "DSIG_TEST_DATA_DIR/fixtures/common not found");
    return;
  }
  const StateSnapshot Final = ReadSnapshot(PathToUtf8(Utf8ToPath(Fixture) / "after_final_pass.json"));
  const StateSnapshot Unm = ReadSnapshot(PathToUtf8(Utf8ToPath(Fixture) / "after_find_unmatched.json"));
  Interners Ids;
  const FinalResults R = Test::FinalResultsFromDumps(Ids, Final, Unm);
  WriteArgs A;
  A.OutPath = Scratch(Dir, "common.diaphora");
  WriteDiaphoraResults(A, R, Ids);
  const Test::ResultsFile Expected = Test::ReadExpectedFixture(Fixture);
  CHECK(Expected.Error.empty());
  const Test::ResultsFile Native = Test::ReadResultsFile(A.OutPath);
  const Test::CompareReport Report = Test::CompareResults(Expected, Native);
  for (const std::string& Line : Report.Differences) {
    Test::Note(Line);
  }
  CHECK(Report.DdlEqual);
  CHECK(Report.L1Equal);
  CHECK(Report.L2Equal);
  CHECK(Native.AllText);
  // What the fixture exercises: a dropped duplicate (line 00001 missing), >8-digit addresses, a NULL
  // unmatched name, a UTF-8 name.
  CHECK(Native.Results.size() >= 2 && Native.Results[0].Line == "00000" && Native.Results[1].Line == "00002");
  CHECK(!Native.Results.empty() && Native.Results[0].Address.size() > 8);
  bool NullName = false;
  bool Utf8Name = false;
  for (const auto& Row : Native.Unmatched) {
    NullName = NullName || Row.NameNull;
    Utf8Name = Utf8Name || Row.Name.find('\xc3') != std::string::npos;
  }
  CHECK(NullName);
  CHECK(Utf8Name);
  // `Final results:` counts chooser items, including the dropped row (01 §12).
  std::string OracleText;
  CHECK(Test::ReadTextFile(PathToUtf8(Utf8ToPath(Fixture) / "oracle.json"), OracleText));
  if (!OracleText.empty()) {
    const JsonValue Oracle = JsonParse(OracleText);
    const JsonValue& Counts = Oracle.At("final_results");
    CHECK_NUM_EQ(R.Best.size(), Counts.At("best").AsInt64());
    CHECK_NUM_EQ(R.Partial.size(), Counts.At("partial").AsInt64());
    CHECK_NUM_EQ(R.Unreliable.size(), Counts.At("unreliable").AsInt64());
    CHECK_NUM_EQ(R.Multimatch.size(), Counts.At("multimatch").AsInt64());
    CHECK_NUM_EQ(static_cast<int64_t>(Native.Results.size()), Oracle.At("results_rows").AsInt64());
  }
}

// ---------------------------------------------------------------------------------------------
// 4. Corpus: the oracle's chooser dumps -> the oracle's .diaphora

// Oracle pairs with instrumented captures (tools/parity/README.md). A capture is used only when it
// finished: its <pair>.diaphora exists (written by save_results at the very end) and run.json says
// "complete". run.json is read through the share-delete reader, so a running capture's os.replace is
// never blocked.
const char* const kCapturePairs[] = {
    "ls-old_vs_ls",
    "ls_vs_ls-old",
    "userenv-9168-pdb_vs_9278-pdb",
    "win32u-9168-useri64_vs_9444-nopdb",
    "cryptbase-1-pdb_vs_8875-nopdb",
    "cryptbase-8875-pdb_vs_9444-nopdb",
    "userenv-9168-pdb_vs_9278-nopdb",
    "sechost-9168-pdb_vs_9444-nopdb",
};

std::optional<std::string> CompleteCapture(const std::string& Pair) {
  for (const std::string& Dir : {Test::TracesDir(Pair), Test::TracesDir(Pair) + ".full"}) {
    if (!FileExists(PathToUtf8(Utf8ToPath(Dir) / Utf8ToPath(Pair + ".diaphora")))) {
      continue;
    }
    try {
      const JsonValue Run = JsonParse(Detail::ReadFileBytes(PathToUtf8(Utf8ToPath(Dir) / "run.json")));
      const JsonValue* Status = Run.Find("status");
      if (Status != nullptr && Status->IsString() && Status->AsString() == "complete") {
        return Dir;
      }
    } catch (const std::exception&) {
    }
  }
  return std::nullopt;
}

std::optional<std::string> IndexFile(const std::string& Capture, std::string_view Point) {
  const JsonValue Index = JsonParse(Detail::ReadFileBytes(PathToUtf8(Utf8ToPath(Capture) / "index.json")));
  for (const JsonValue& Entry : Index.Items()) {
    if (Entry.Items().size() == 3 && Entry.Items()[1].IsString() && Entry.Items()[1].AsString() == Point &&
        Entry.Items()[2].IsString()) {
      return PathToUtf8(Utf8ToPath(Capture) / Utf8ToPath(Entry.Items()[2].AsString()));
    }
  }
  return std::nullopt;
}

void TestOracleDumps(const std::string& Dir) {
  Test::Suite("corpus: oracle after:final_pass + after:find_unmatched dumps -> .diaphora == oracle run1 (L2)");
  if (!Test::CorpusRoot()) {
    Test::Skip("corpus writer replay", "DSIG_CORPUS_ROOT not set");
    return;
  }
  size_t Compared = 0;
  for (const char* Pair : kCapturePairs) {
    const std::string OracleFile = Test::OracleResultsPath(Pair, 1);
    const std::optional<std::string> Capture = CompleteCapture(Pair);
    if (!Capture || !FileExists(OracleFile)) {
      Test::Note(std::string(Pair) + ": no complete capture or no oracle run1 yet, skipped");
      continue;
    }
    const auto FinalFile = IndexFile(*Capture, "after:final_pass");
    const auto UnmatchedFile = IndexFile(*Capture, "after:find_unmatched");
    if (!FinalFile || !UnmatchedFile) {
      Test::Note(std::string(Pair) + ": the capture has no after:final_pass / after:find_unmatched snapshot "
                 "(--points filter?), skipped");
      continue;
    }
    // The oracle file is copied, never opened in place (09: oracle files are read-only artefacts).
    const std::string OracleCopy = Scratch(Dir, std::string(Pair) + ".oracle.diaphora");
    std::error_code Error;
    std::filesystem::copy_file(Utf8ToPath(OracleFile), Utf8ToPath(OracleCopy),
                               std::filesystem::copy_options::overwrite_existing, Error);
    CHECK(!Error);
    const Test::ResultsFile Oracle = Test::ReadResultsFile(OracleCopy);
    CHECK(Oracle.Error.empty() && Oracle.Config.size() == 1);
    if (!Oracle.Error.empty() || Oracle.Config.size() != 1) {
      continue;
    }
    Interners Ids;
    const FinalResults R = Test::FinalResultsFromDumps(Ids, ReadSnapshot(*FinalFile), ReadSnapshot(*UnmatchedFile));
    WriteArgs A;
    A.OutPath = Scratch(Dir, std::string(Pair) + ".native.diaphora");
    A.MainDb = Oracle.Config[0][0];  // the same argument strings, so config.main_db / diff_db compare too
    A.DiffDb = Oracle.Config[0][1];
    WriteDiaphoraResults(A, R, Ids);
    const Test::ResultsFile Native = Test::ReadResultsFile(A.OutPath);
    const Test::CompareReport Report = Test::CompareResults(Oracle, Native, 20, /*CompareConfigPaths=*/true);
    for (const std::string& Line : Report.Differences) {
      Test::Note(std::string(Pair) + ": " + Line);
    }
    CHECK(Report.DdlEqual);
    CHECK(Report.L2Equal);
    CHECK(Native.AllText);
    CHECK(Native.Config.size() == 1 && LooksLikeAscTime(Native.Config[0][3]));
    CHECK(Oracle.Schema == Test::DiaphoraSchema());  // the committed DDL constant is the oracle's
    size_t Dropped = R.Best.size() + R.Partial.size() + R.Unreliable.size() + R.Multimatch.size() -
                     Native.Results.size();
    Test::Note(std::string(Pair) + ": capture " + PathToUtf8(Utf8ToPath(*Capture).filename()) + ", " +
               std::to_string(Native.Results.size()) + " results rows (" + std::to_string(Dropped) +
               " dropped by insert or ignore), " + std::to_string(Native.Unmatched.size()) + " unmatched rows: " +
               (Report.L2Equal && Report.DdlEqual ? "L2 identical" : "DIFFERENT"));
    ++Compared;
  }
  Test::Note(std::to_string(Compared) + " oracle pairs compared");
  if (Compared == 0) {
    Test::Skip("corpus writer replay", "no complete capture with an oracle run1");
  }
}

}  // namespace

// Audit F26: the file is written as "<out>.tmp-<pid>" and renamed over <out> after the commit. A failure
// (or a kill) at any step leaves <out> exactly as it was and no partial file anywhere; before, the config
// table was created on <out> itself, so a failure mid-write left a half-written file there.
std::vector<std::string> FilesIn(const std::string& Dir) {
  std::vector<std::string> Names;
  std::error_code Error;
  for (const auto& Entry : std::filesystem::directory_iterator(Utf8ToPath(Dir), Error)) {
    Names.push_back(Test::PathToUtf8(Entry.path().filename()));
  }
  std::sort(Names.begin(), Names.end());
  return Names;
}

void TestWriterAtomicReplace(const std::string& Dir) {
  Test::Suite("WriteDiaphoraResults: written under a temporary name, renamed after the commit (audit F26)");
  const std::string Folder = Scratch(Dir, "atomic");
  std::error_code Error;
  std::filesystem::create_directories(Utf8ToPath(Folder), Error);
  const std::string Out = Test::PathToUtf8(Utf8ToPath(Folder) / "r.diaphora");
  Interners Ids;
  FinalResults R;
  R.Best.push_back(MakeItem(Ids, "4096", "f", "4096", "f", "100% equal", 1.0, 1, 1));
  R.UnmatchedPrimary = std::vector<UnmatchedRow>{{Ids.Addr("8192"), Ids.Name("g")}};
  WriteArgs A;
  A.OutPath = Out;
  A.MainDb = "db1.sqlite";
  A.DiffDb = "db2.sqlite";
  A.Date = "fixed";
  const std::string Sentinel = "results of an earlier diff";
  for (const char* Step : {"open", "config", "results", "unmatched", "committed"}) {
    WriteBytes(Out, Sentinel);
    static std::string FailAt;
    FailAt = Step;
    Detail::SetWriterFaultHook([](std::string_view Current) {
      if (Current == FailAt) {
        throw IoFailure("injected failure at " + std::string(Current));
      }
    });
    bool Threw = false;
    try {
      WriteDiaphoraResults(A, R, Ids);
    } catch (const IoFailure&) {
      Threw = true;
    }
    Detail::SetWriterFaultHook(nullptr);
    Test::Report(Threw, (std::string("failure injected at ") + Step).c_str(), __FILE__, __LINE__);
    CHECK_TEXT_EQ(ReadBytes(Out), Sentinel);  // the earlier file is untouched
    const std::vector<std::string> Left = FilesIn(Folder);
    CHECK(Left.size() == 1 && Left[0] == "r.diaphora");  // no temporary file or journal left behind
  }
  // Success replaces the file; a stale journal of the replaced file is removed so SQLite never rolls
  // it back into the new one.
  WriteBytes(Out + "-journal", "a hot journal of the old file");
  WriteDiaphoraResults(A, R, Ids);
  const Test::ResultsFile File = Test::ReadResultsFile(Out);
  CHECK(File.Error.empty() && File.Results.size() == 1 && File.Unmatched.size() == 1);
  const std::vector<std::string> Left = FilesIn(Folder);
  CHECK(Left.size() == 1 && Left[0] == "r.diaphora");
  CHECK(!ResultsWriterScratchPaths(Out).empty() && ResultsWriterScratchPaths(Out)[0].rfind(Out + ".tmp-", 0) == 0);
}

int main() {
  TestFormatLine05();
  TestFormatAddr08x();
  TestFormatRatio7();
  TestFormatRatio7CrossCheck();
  TestFormatFixed2();
  const std::string Dir = Test::ScratchDir("diff_writer");
  try {
    TestWriterRows(Dir);
    TestWriterEmptyAndReplace(Dir);
    TestWriterErrors(Dir);
    TestWriterAtomicReplace(Dir);
    TestWriterUnicodePath(Dir);
    TestCommonFixture(Dir);
    TestOracleDumps(Dir);
  } catch (const std::exception& Error) {
    Test::Report(false, "unexpected exception", __FILE__, __LINE__);
    Test::Note(std::string("exception: ") + Error.what());
  }
  Test::RemoveScratchDir(Dir);
  return Test::Finish();
}
