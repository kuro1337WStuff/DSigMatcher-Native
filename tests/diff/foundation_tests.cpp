// diff_foundation: the L0 foundation of the parity engine (docs/parity/00-plan.md §2.6, §4 L0).
//
//   * registry and stage SQL against tests/diff/generated/registry_expected.inc;
//   * JSON, snapshot, trace and interner units;
//   * FixtureDb, ingest and Path A on the committed synthetic fixture (tests/diff/fixtures/foundation);
//   * the pipeline end to end: exit codes, Diaphora's DDL, the mode-N points (G0);
//   * corpus (skipped without DSIG_CORPUS_ROOT): ingest census of the 7 exports, the diff of
//     ls-old vs ls against the oracle file's DDL, results comparison self-checks;
//   * SQLite 3.51.1 only: the Path A row-sequence census on the 5 oracle pairs and the
//     find_same_name EXPLAIN QUERY PLAN (02 Appendix C). Sequences Python needed more than 5 s for run
//     only with DSIG_CENSUS_LONG=1.
//   * lane R0 (reconciliation): the trace/snapshot conventions of tools/parity/oracle_trace.py, checked
//     byte for byte against a finished oracle capture (skipped without it); the final-results log
//     order (D:3689 before D:3690); the SQLite warning under --quiet (skipped on the oracle's SQLite);
//     missing side tables refused with exit 4; Unicode and UNC paths, in process and through the CLI.
//   * lane F1: reading an input creates no -wal/-shm beside it (immutable=1 when no committed -wal
//     frame or hot -journal waits), committed -wal frames are still read, a hot -journal is refused;
//     non-ASCII and UNC paths through the immutable URI.

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <functional>
#include <iterator>
#include <fstream>
#include <limits>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <io.h>
#include <share.h>
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <unistd.h>
#endif

#include <sqlite3.h>

#include "FileIo.h"
#include "diff/CorpusPaths.h"
#include "diff/FixtureDb.h"
#include "diff/ResultsCompare.h"
#include "diff/TestHarness.h"
#include "dsigmatcher/Sha256.h"
#include "dsigmatcher/Version.h"
#include "dsigmatcher/diff/Candidates.h"
#include "dsigmatcher/diff/Config.h"
#include "dsigmatcher/diff/Database.h"
#include "dsigmatcher/diff/Errors.h"
#include "dsigmatcher/diff/Interner.h"
#include "dsigmatcher/diff/Json.h"
#include "dsigmatcher/diff/Pipeline.h"
#include "dsigmatcher/diff/Registry.h"
#include "dsigmatcher/diff/Snapshot.h"
#include "dsigmatcher/diff/StageSql.h"
#include "dsigmatcher/diff/Table.h"
#include "dsigmatcher/diff/Trace.h"

namespace {

#include "diff/generated/corpus_census.inc"
#include "diff/generated/registry_expected.inc"

using namespace DSig::Diff;
namespace fs = std::filesystem;

std::string Sha256Of(std::string_view Bytes) {
  DSig::Sha256 Hash;
  Hash.Update(Bytes);
  return Hash.FinishHex();
}

size_t CountOf(std::string_view Text, std::string_view Needle) {
  size_t Count = 0;
  for (size_t Pos = Text.find(Needle); Pos != std::string_view::npos; Pos = Text.find(Needle, Pos + Needle.size())) {
    ++Count;
  }
  return Count;
}

// The whole file ("" when it cannot be read). UTF-8 path; shared-delete read on Windows (FileIo.h),
// so reading an oracle capture never blocks a writer that replaces its files.
std::string ReadFile(const std::string& Path) {
  try {
    return DSig::Diff::Detail::ReadFileBytes(Path);
  } catch (const std::exception&) {
    return std::string();
  }
}

using DSig::Test::PathToUtf8;
using DSig::Test::Utf8ToPath;

// Path join over UTF-8 strings.
std::string Join(const std::string& Dir, const std::string& Name) {
  return PathToUtf8(Utf8ToPath(Dir) / Utf8ToPath(Name));
}

bool Exists(const std::string& Utf8Path) {
  std::error_code Error;
  return fs::exists(Utf8ToPath(Utf8Path), Error);
}

// ---------------------------------------------------------------------------------------------
// Registry (plan §4 L0 unit tests; 04a §2; 07 §10.14)

void TestRegistry() {
  DSig::Test::Suite("registry");
  const auto Specs = Heuristics();
  CHECK_NUM_EQ(Specs.size(), 50);
  CHECK_NUM_EQ(Specs.size(), DSIG_EXPECTED_HEURISTIC_COUNT);

  int Best = 0, Partial = 0, Unreliable = 0, Experimental = 0;
  int NoFps = 0, Ratio = 0, RatioMax = 0, Trusted = 0;
  std::set<int> FlagUnreliable, FlagSlow, FlagSameCpu;
  for (size_t Index = 0; Index < Specs.size(); ++Index) {
    const HeuristicSpec& Spec = Specs[Index];
    CHECK_NUM_EQ(Spec.Id, Index);
    CHECK_EQ(&Heuristic(static_cast<int>(Index)), &Spec);
    switch (Spec.Category) {
      case HeurCategory::Best: ++Best; break;
      case HeurCategory::Partial: ++Partial; break;
      case HeurCategory::Unreliable: ++Unreliable; break;
      case HeurCategory::Experimental: ++Experimental; break;
    }
    switch (Spec.RatioType) {
      case HeurType::NoFps: ++NoFps; break;
      case HeurType::Ratio: ++Ratio; break;
      case HeurType::RatioMax: ++RatioMax; break;
      case HeurType::RatioMaxTrusted: ++Trusted; break;
    }
    if (Spec.FlagUnreliable) FlagUnreliable.insert(Spec.Id);
    if (Spec.FlagSlow) FlagSlow.insert(Spec.Id);
    if (Spec.FlagSameCpu) FlagSameCpu.insert(Spec.Id);
    // SQL bytes are exactly the generator's (sha256 and length from registry_expected.inc)
    const ExpectedHeuristicSql& Expected = kExpectedHeuristicSql[Index];
    CHECK_NUM_EQ(Expected.Id, Index);
    CHECK_TEXT_EQ(Sha256Of(Spec.Sql), Expected.Sha256);
    CHECK_TEXT_EQ(std::string(Spec.SqlSha256), Expected.Sha256);
    CHECK_NUM_EQ(Spec.Sql.size(), Expected.Length);
    // min is present for every RATIO_MAX / TRUSTED entry (H:1293-1297 check_field_names)
    if (Spec.RatioType == HeurType::RatioMax || Spec.RatioType == HeurType::RatioMaxTrusted) {
      CHECK(Spec.HasMin);
    }
    // every entry carries the token; only H10 has two (04a §2.4)
    CHECK_NUM_EQ(CountOf(Spec.Sql, "%POSTFIX%"), Spec.Id == 10 ? 2 : 1);
    CHECK(Spec.SourceLineBegin > 0 && Spec.SourceLineEnd > Spec.SourceLineBegin);
  }
  // categories 12/30/8 and types 5/22/22/1 (plan §4 L0; H:1262 asserts the type counter)
  CHECK_NUM_EQ(Best, 12);
  CHECK_NUM_EQ(Partial, 30);
  CHECK_NUM_EQ(Unreliable, 8);
  CHECK_NUM_EQ(Experimental, 0);
  CHECK_NUM_EQ(Best, DSIG_EXPECTED_BEST);
  CHECK_NUM_EQ(Partial, DSIG_EXPECTED_PARTIAL);
  CHECK_NUM_EQ(Unreliable, DSIG_EXPECTED_UNRELIABLE);
  CHECK_NUM_EQ(NoFps, 5);
  CHECK_NUM_EQ(Ratio, 22);
  CHECK_NUM_EQ(RatioMax, 22);
  CHECK_NUM_EQ(Trusted, 1);
  CHECK_NUM_EQ(NoFps, DSIG_EXPECTED_NOFPS);
  CHECK_NUM_EQ(Trusted, DSIG_EXPECTED_TRUSTED);
  // flags enumerated from HEURISTICS (plan §4 L0)
  CHECK((FlagUnreliable == std::set<int>{36, 37, 38}));
  CHECK((FlagSlow == std::set<int>{14, 21, 36, 37, 38, 41, 43, 44, 45, 46, 47, 48}));
  CHECK((FlagSameCpu == std::set<int>{0, 1, 2, 3, 5, 6, 9, 39}));
  // spot values (07 §10.14)
  CHECK_TEXT_EQ(std::string(Heuristic(0).Name), "Same RVA and hash");
  CHECK_TEXT_EQ(std::string(Heuristic(10).Name), "Equal assembly or pseudo-code");
  CHECK_TEXT_EQ(std::string(Heuristic(49).Name), "Topological sort hash");
  CHECK(Heuristic(12).RatioType == HeurType::RatioMaxTrusted && Heuristic(12).Min == 0.44);
  CHECK(Heuristic(9).RatioType == HeurType::RatioMax && Heuristic(9).Min == 0.7);
  CHECK(Heuristic(13).Min == 0.449);
  CHECK(Heuristic(21).Min == 0.2);
  CHECK(Heuristic(41).Min == 0.49);
  CHECK(Heuristic(28).Min == 0.549);
  CHECK(Heuristic(26).Min == 0.579);
  CHECK(!Heuristic(4).HasMin);
  CHECK_TEXT_EQ(std::string(Heuristic(0).FlagsRepr), "[3]");

  // default-run lists (07 §10.14): 12 Best + 27 Partial on the same CPU, 5 + 26 otherwise
  for (const bool SameCpu : {true, false}) {
    int RunBest = 0;
    int RunPartial = 0;
    for (const HeuristicSpec& Spec : Specs) {
      if (Spec.FlagUnreliable || (Spec.FlagSameCpu && !SameCpu)) {
        continue;
      }
      RunBest += Spec.Category == HeurCategory::Best ? 1 : 0;
      RunPartial += Spec.Category == HeurCategory::Partial ? 1 : 0;
    }
    CHECK_NUM_EQ(RunBest, SameCpu ? 12 : 5);
    CHECK_NUM_EQ(RunPartial, SameCpu ? 27 : 26);
  }

  // ApplyPostfix: Python str.replace semantics; H10 has exactly two tokens (04a §2.4)
  const std::string_view H10 = Heuristic(10).Sql;
  CHECK_NUM_EQ(CountOf(H10, "%POSTFIX%"), 2);
  CHECK_NUM_EQ(CountOf(H10, "%POSTFIX%"), DSIG_EXPECTED_H10_POSTFIX_TOKENS);
  const std::string Empty = ApplyPostfix(H10, "");
  CHECK_NUM_EQ(CountOf(Empty, "%POSTFIX%"), 0);
  CHECK_NUM_EQ(Empty.size(), H10.size() - 2 * 9);
  const std::string Small = ApplyPostfix(H10, kSqlDefaultPostfix);
  CHECK_NUM_EQ(CountOf(Small, kSqlDefaultPostfix), 2);
  CHECK_TEXT_EQ(ApplyPostfix("a%POSTFIX%b%POSTFIX%%POSTFIX%", "X"), "aXbXX");
  CHECK_TEXT_EQ(ApplyPostfix("no token", "X"), "no token");
  CHECK_TEXT_EQ(std::string(CategoryName(HeurCategory::Partial)), "Partial");
  CHECK_TEXT_EQ(std::string(HeurTypeName(HeurType::RatioMaxTrusted)), "RATIO_MAX_TRUSTED");

  // Stage SQL (Appendix A)
  const auto Stages = StageSqls();
  CHECK_NUM_EQ(Stages.size(), 25);
  CHECK_NUM_EQ(Stages.size(), DSIG_EXPECTED_STAGE_SQL_COUNT);
  for (size_t Index = 0; Index < Stages.size(); ++Index) {
    const StageSqlSpec& Spec = Stages[Index];
    CHECK_TEXT_EQ(std::string(Spec.Name), kExpectedStageSql[Index].Name);
    CHECK_TEXT_EQ(Sha256Of(Spec.Sql), kExpectedStageSql[Index].Sha256);
    CHECK_NUM_EQ(Spec.Sql.size(), kExpectedStageSql[Index].Length);
    CHECK_NUM_EQ(CountOf(Spec.Sql, "?"), Spec.BindCount);
    CHECK_EQ(StageSql(Spec.Name).Sql.data(), Spec.Sql.data());
  }
  CHECK_TEXT_EQ(std::string(kSqlVersion), "select value from diff.version");
  CHECK_TEXT_EQ(std::string(kSqlUnmatchedMain), "select name, address from functions");
  CHECK_TEXT_EQ(std::string(kSqlUnmatchedDiff), "select name, address from diff.functions");
  CHECK_TEXT_EQ(std::string(kSqlFunctionRowMain), "select * from main.functions where name = ?");
  CHECK_TEXT_EQ(std::string(kSqlFunctionRowDiff), "select * from diff.functions where name = ?");
  CHECK(kSqlSameName.find("'Perfect match, same name' description") != std::string_view::npos);
  CHECK(kSqlCuCartesian.find("cast(df.address as real) between ? and ?") != std::string_view::npos);
  CHECK(kSqlRemainingPair.find(" and f.nodes >= 3 and df.nodes >= 3 ") != std::string_view::npos);
  CHECK(kSqlGapDiff.find("from diff.functions") != std::string_view::npos);
  CHECK(kSqlCuLookupDiff.find("diff.compilation_unit_functions") != std::string_view::npos);
  bool Threw = false;
  try {
    (void)StageSql("kSqlNoSuchThing");
  } catch (const std::out_of_range&) {
    Threw = true;
  }
  CHECK(Threw);
}

// ---------------------------------------------------------------------------------------------
// Interner

void TestInterner() {
  DSig::Test::Suite("interner");
  Interners Ids;
  const NameId Foo = Ids.Name("foo");
  CHECK(Foo != kNoneName);
  CHECK(Ids.Name("foo") == Foo);
  CHECK(Ids.NameOpt(std::optional<std::string_view>()) == kNoneName);
  const NameId NoneText = Ids.Name("None");
  CHECK(NoneText != kNoneName);  // Python: None and "None" are different dict keys
  CHECK_TEXT_EQ(std::string(Ids.NameKeyText(kNoneName)), "None");  // ... but render alike in f-strings
  CHECK_TEXT_EQ(std::string(Ids.NameKeyText(NoneText)), "None");
  CHECK(!Ids.NameOrNone(kNoneName).has_value());
  CHECK_TEXT_EQ(std::string(*Ids.NameOrNone(Foo)), "foo");
  CHECK(Ids.FindName("foo") == Foo);
  CHECK(!Ids.FindName("bar").has_value());
  CHECK_NUM_EQ(Ids.NameCount(), 2);
  const AddrId Ea = Ids.Addr("4198400");
  CHECK(Ea != kNoneAddr);
  CHECK_TEXT_EQ(std::string(Ids.AddrText(Ea)), "4198400");
  CHECK_TEXT_EQ(std::string(Ids.AddrKeyText(kNoneAddr)), "None");
  CHECK(Ids.AddrOpt(std::optional<std::string_view>()) == kNoneAddr);
  const DescId D1 = Ids.Desc("Loop count");
  CHECK(Ids.Desc("Loop count") == D1);
  CHECK_TEXT_EQ(std::string(Ids.DescText(D1)), "Loop count");
  // stability of views across growth
  const std::string_view First = Ids.NameText(Foo);
  for (int Index = 0; Index < 10000; ++Index) {
    Ids.Name("name_" + std::to_string(Index));
  }
  CHECK(First.data() == Ids.NameText(Foo).data());
  // byte-exact keys: an embedded NUL and non-ASCII bytes are distinct names
  CHECK(Ids.Name(std::string_view("a\0b", 3)) != Ids.Name("a"));
  CHECK(Ids.Name("\xc3\xa9") != Ids.Name("e"));
}

// ---------------------------------------------------------------------------------------------
// JSON (plan §4 L0: bigints kept as text, escapes, NaN in compat mode)

void TestJson() {
  DSig::Test::Suite("json");
  const JsonValue V = JsonParse(R"({"a": [1, -0, 18446744073709551616, 1.5e3, "x\u00e9\ud83d\ude00\n"], "b": null,
                                    "c": true, "a2": {}, "e": []})");
  CHECK(V.IsObject());
  const auto& A = V.At("a").Items();
  CHECK_NUM_EQ(A.size(), 5);
  CHECK_TEXT_EQ(A[0].NumberText(), "1");
  CHECK_NUM_EQ(A[0].AsInt64(), 1);
  CHECK_TEXT_EQ(A[1].NumberText(), "-0");
  CHECK_TEXT_EQ(A[2].NumberText(), "18446744073709551616");  // bigint kept as text
  bool Threw = false;
  try {
    (void)A[2].AsInt64();
  } catch (const JsonError&) {
    Threw = true;
  }
  CHECK(Threw);
  CHECK(A[3].AsDouble() == 1500.0);
  CHECK(!A[3].IsIntegerText());
  CHECK_TEXT_EQ(A[4].AsString(), "x\xc3\xa9\xf0\x9f\x98\x80\n");
  CHECK(V.At("b").IsNull());
  CHECK(V.At("c").AsBool());
  CHECK(V.Find("zz") == nullptr);
  CHECK(V.At("a2").Members().empty());
  CHECK(V.At("e").Items().empty());

  // escapes and a lone surrogate (kept as its 3-byte form, like Python keeps the code point)
  CHECK_TEXT_EQ(JsonParse(R"("\"\\\/\b\f\n\r\t")").AsString(), "\"\\/\b\f\n\r\t");
  CHECK_TEXT_EQ(JsonParse(R"("\ud800")").AsString(), "\xed\xa0\x80");
  // duplicate keys: the last value wins in the first position (Python dict)
  const JsonValue Dup = JsonParse(R"({"k": 1, "j": 2, "k": 3})");
  CHECK_NUM_EQ(Dup.Members().size(), 2);
  CHECK_TEXT_EQ(Dup.Members()[0].first, "k");
  CHECK_NUM_EQ(Dup.At("k").AsInt64(), 3);

  // NaN / Infinity only in compat mode
  const auto Rejects = [](std::string_view Text, const JsonParseOptions& Options) {
    try {
      (void)JsonParse(Text, Options);
      return false;
    } catch (const JsonError&) {
      return true;
    }
  };
  JsonParseOptions Compat;
  Compat.PythonCompat = true;
  CHECK(Rejects("[NaN]", JsonParseOptions()));
  CHECK(!Rejects("[NaN, Infinity, -Infinity]", Compat));
  const JsonValue Special = JsonParse("[NaN, Infinity, -Infinity]", Compat);
  CHECK(std::isnan(Special.Items()[0].AsDouble()));
  CHECK(Special.Items()[1].AsDouble() == std::numeric_limits<double>::infinity());
  CHECK(Special.Items()[2].AsDouble() == -std::numeric_limits<double>::infinity());
  // strictness: control characters, trailing data, bad numbers, leading zeros
  CHECK(Rejects("\"a\tb\"", JsonParseOptions()));
  JsonParseOptions Lenient;
  Lenient.StrictControlChars = false;
  CHECK(!Rejects("\"a\tb\"", Lenient));
  CHECK(Rejects("[1] x", JsonParseOptions()));
  CHECK(Rejects("01", JsonParseOptions()));
  CHECK(Rejects("[1,]", JsonParseOptions()));
  CHECK(Rejects("{'a': 1}", JsonParseOptions()));
  CHECK(Rejects("\"\\x\"", JsonParseOptions()));
  CHECK(Rejects("", JsonParseOptions()));
  CHECK(!Rejects(" \t\r\n[1] \n", JsonParseOptions()));
  // numbers follow Python's NUMBER_RE (optional fraction and exponent groups)
  CHECK(Rejects("1.", JsonParseOptions()));
  CHECK_TEXT_EQ(JsonParse("-12.5E+3").NumberText(), "-12.5E+3");
  CHECK(JsonParse("1e400").AsDouble() == std::numeric_limits<double>::infinity());

  // write / parse round trip
  JsonValue Root = JsonValue::Object();
  Root.Set("s", JsonValue::String("q\"\\\n\x01\xc3\xa9"));
  Root.Set("n", JsonValue::Number("12345678901234567890123"));
  Root.Set("i", JsonValue::Int(-7));
  Root.Set("u", JsonValue::UInt(18446744073709551615ull));
  JsonValue List = JsonValue::Array();
  List.Push(JsonValue::Null());
  List.Push(JsonValue::Bool(false));
  Root.Set("l", std::move(List));
  for (const bool Pretty : {false, true}) {
    JsonWriteOptions Options;
    Options.Pretty = Pretty;
    const std::string Text = JsonWrite(Root, Options);
    CHECK(JsonParse(Text) == Root);
  }
  CHECK_TEXT_EQ(JsonQuote("a\x1f"), "\"a\\u001f\"");
  CHECK_NUM_EQ(JsonParse(JsonWrite(Root)).At("u").AsUInt64(), 18446744073709551615ull);

  // The compact writer is the oracle's json.dumps(ensure_ascii=False, separators=(",", ":")) byte for
  // byte (tools/parity/snapshot.py DumpJson); the expected text was produced by CPython 3.13 for the
  // same object ("c" holds quote, backslash, slash, the five named control escapes, U+0001, U+001F,
  // U+007F, U+00E9 and U+2028).
  {
    JsonValue Obj = JsonValue::Object();
    Obj.Set("a", JsonValue::Int(1));
    JsonValue Items = JsonValue::Array();
    Items.Push(JsonValue::Null());
    Items.Push(JsonValue::Bool(true));
    Items.Push(JsonValue::String("x"));
    Obj.Set("b", std::move(Items));
    Obj.Set("c", JsonValue::String("\"\\/\b\f\n\r\t\x01\x1f\x7f\xc3\xa9\xe2\x80\xa8"));
    CHECK_TEXT_EQ(JsonWrite(Obj),
                  "{\"a\":1,\"b\":[null,true,\"x\"],\"c\":\"\\\"\\\\/\\b\\f\\n\\r\\t\\u0001\\u001f\x7f\xc3\xa9\xe2\x80\xa8\"}");
    CHECK_TEXT_EQ(JsonWrite(JsonValue::Array()), "[]");
    CHECK_TEXT_EQ(JsonWrite(JsonValue::Object()), "{}");
  }
}

// ---------------------------------------------------------------------------------------------
// Snapshot schema (Appendix B)

StateSnapshot SampleSnapshot() {
  StateSnapshot S;
  S.Producer = "dsigmatcher-test";
  S.Pair = "ls-old_vs_ls";
  S.Seq = 17;
  S.Point = "before:find_matches_diffing:0";
  S.Iteration = 0;
  S.Flags.IsSameProcessor = true;
  S.Flags.TotalFunctions1 = 304;
  S.Flags.TotalFunctions2 = 318;
  S.Best.push_back(SnapItem{"4198400", std::string("foo"), "4202496", std::string("foo"), "Perfect match, same name",
                            RatioBits(1.0), 5, 5});
  S.Partial.push_back(SnapItem{"4198500", std::nullopt, "4202500", std::string("sub_1"), "Loop count",
                               RatioBits(0.9018889), 3, 4});
  S.MatchedPrimary.push_back(SnapMatched{std::string("foo"), std::string("foo"), RatioBits(1.0)});
  S.MatchedPrimary.push_back(SnapMatched{std::nullopt, std::string("sub_1"), RatioBits(0.9018889)});
  S.MatchedSecondary.push_back(SnapMatched{std::string("foo"), std::string("foo"), RatioBits(1.0)});
  S.RatiosCache = std::vector<SnapCacheEntry>{SnapCacheEntry{"4198400-4202496", RatioBits(0.95)}};
  SnapChoosers Choosers;
  Choosers.Multimatch = S.Partial;
  S.Choosers = Choosers;
  SnapUnmatchedDump Unmatched;
  Unmatched.Primary = std::vector<SnapUnmatched>{SnapUnmatched{"4210688", std::string("only_in_diff")},
                                                  SnapUnmatched{"4210700", std::nullopt}};
  S.Unmatched = Unmatched;
  return S;
}

bool SameSnapshot(const StateSnapshot& A, const StateSnapshot& B) {
  return A.Schema == B.Schema && A.Producer == B.Producer && A.Pair == B.Pair && A.Seq == B.Seq &&
         A.Point == B.Point && A.Iteration == B.Iteration && A.Flags == B.Flags && A.Best == B.Best &&
         A.Partial == B.Partial && A.Unreliable == B.Unreliable && A.MatchedPrimary == B.MatchedPrimary &&
         A.MatchedSecondary == B.MatchedSecondary && A.RatiosCache == B.RatiosCache && A.Choosers == B.Choosers &&
         A.Unmatched == B.Unmatched;
}

void TestSnapshot() {
  DSig::Test::Suite("snapshot");
  CHECK_TEXT_EQ(RatioBitsHex(1.0), "3ff0000000000000");
  CHECK_TEXT_EQ(RatioBitsHex(0.0), "0000000000000000");
  CHECK_TEXT_EQ(RatioBitsHex(0.95), "3fee666666666666");  // the Appendix B example value
  CHECK(ParseRatioBits("3fee666666666666") == RatioBits(0.95));
  CHECK(RatioFromBits(RatioBits(0.123456789)) == 0.123456789);
  bool Threw = false;
  try {
    (void)ParseRatioBits("3ff");
  } catch (const JsonError&) {
    Threw = true;
  }
  CHECK(Threw);

  const StateSnapshot Sample = SampleSnapshot();
  for (const bool Pretty : {false, true}) {
    const StateSnapshot Back = ParseSnapshot(SerializeSnapshot(Sample, Pretty));
    CHECK(SameSnapshot(Sample, Back));
  }
  // Byte-exact with the oracle's writer: snapshot.py DumpJson of the same object (key order of
  // oracle_trace.py Instrument.BuildSnapshot), generated with CPython 3.13.
  CHECK_TEXT_EQ(SerializeSnapshot(Sample),
                "{\"schema\":\"dsig-parity-snapshot/1\",\"producer\":\"dsigmatcher-test\",\"pair\":\"ls-old_vs_ls\",\""
                "seq\":17,\"point\":\"before:find_matches_diffing:0\",\"iteration\":0,\"flags\":{\"is_same_processor"
                "\":true,\"is_patch_diff\":false,\"is_symbols_stripped\":false,\"hooks_loaded\":false,\"total_functio"
                "ns1\":304,\"total_functions2\":318},\"all_matches\":{\"best\":[[\"4198400\",\"foo\",\"4202496\",\"fo"
                "o\",\"Perfect match, same name\",\"3ff0000000000000\",5,5]],\"partial\":[[\"4198500\",null,\"4202500"
                "\",\"sub_1\",\"Loop count\",\"3fecdc461c440365\",3,4]],\"unreliable\":[]},\"matched_primary\":[[\"fo"
                "o\",\"foo\",\"3ff0000000000000\"],[null,\"sub_1\",\"3fecdc461c440365\"]],\"matched_secondary\":[[\"f"
                "oo\",\"foo\",\"3ff0000000000000\"]],\"ratios_cache\":[[\"4198400-4202496\",\"3fee666666666666\"]],\""
                "choosers\":{\"best\":[],\"partial\":[],\"unreliable\":[],\"multimatch\":[[\"4198500\",null,\"4202500"
                "\",\"sub_1\",\"Loop count\",\"3fecdc461c440365\",3,4]]},\"unmatched\":{\"primary\":[[\"4210688\",\"o"
                "nly_in_diff\"],[\"4210700\",null]],\"secondary\":null}}");
  {
    // iteration null and the optional members absent (the common case)
    StateSnapshot Plain;
    Plain.Producer = "p";
    Plain.Point = "after:find_equal_matches";
    CHECK_TEXT_EQ(SerializeSnapshot(Plain),
                  "{\"schema\":\"dsig-parity-snapshot/1\",\"producer\":\"p\",\"pair\":\"\",\"seq\":0,\"point\":"
                  "\"after:find_equal_matches\",\"iteration\":null,\"flags\":{\"is_same_processor\":false,"
                  "\"is_patch_diff\":false,\"is_symbols_stripped\":false,\"hooks_loaded\":false,\"total_functions1\":0,"
                  "\"total_functions2\":0},\"all_matches\":{\"best\":[],\"partial\":[],\"unreliable\":[]},"
                  "\"matched_primary\":[],\"matched_secondary\":[]}");
  }
  // secondary null vs empty list survive
  const StateSnapshot Back = ParseSnapshot(SerializeSnapshot(Sample));
  CHECK(Back.Unmatched && Back.Unmatched->Primary && !Back.Unmatched->Secondary);
  CHECK(Back.Partial[0].Name1 == std::nullopt);

  // the literal example of Appendix B parses (comments removed)
  const std::string Example = R"({ "schema": "dsig-parity-snapshot/1", "producer": "diaphora-3.4.2-4-g621ec26",
  "pair": "ls-old_vs_ls", "seq": 17, "point": "before:find_matches_diffing:0", "iteration": 0,
  "flags": {"is_same_processor": true, "is_patch_diff": false, "is_symbols_stripped": false,
            "hooks_loaded": false, "total_functions1": 304, "total_functions2": 318},
  "all_matches": {"best": [["4198400","foo","4202496","foo","Perfect match, same name","3ff0000000000000",5,5]],
                  "partial": [], "unreliable": []},
  "matched_primary":   [["foo","foo","3ff0000000000000"]],
  "matched_secondary": [["foo","foo","3ff0000000000000"]],
  "ratios_cache": [["4198400-4202496","3fee666666666666"]] })";
  const StateSnapshot Parsed = ParseSnapshot(Example);
  CHECK_TEXT_EQ(Parsed.Point, "before:find_matches_diffing:0");
  CHECK(Parsed.Iteration == 0);
  CHECK(Parsed.Flags.IsSameProcessor && Parsed.Flags.TotalFunctions2 == 318);
  CHECK_NUM_EQ(Parsed.Best.size(), 1);
  CHECK(Parsed.Best[0].RatioBits == RatioBits(1.0) && Parsed.Best[0].Nodes2 == 5);
  CHECK(Parsed.RatiosCache && (*Parsed.RatiosCache)[0].RatioBits == RatioBits(0.95));
  CHECK(!Parsed.Choosers && !Parsed.Unmatched);

  // a wrong schema is refused
  Threw = false;
  try {
    (void)ParseSnapshot(R"({"schema": "other", "point": "x"})");
  } catch (const JsonError&) {
    Threw = true;
  }
  CHECK(Threw);

  // file names and globs
  CHECK_TEXT_EQ(SanitisePointName("before:cleanup:3185:4"), "before_cleanup_3185_4");
  CHECK_TEXT_EQ(SnapshotFileName(17, "after:final_pass"), "00017_after_final_pass.json");
  CHECK_TEXT_EQ(SnapshotFileName(123456, "a b"), "123456_a_b.json");
  // re.sub over a Python str replaces each code point (é, €, U+1F600) with one '_' (snapshot.py)
  CHECK_TEXT_EQ(SanitisePointName("a:\xc3\xa9\xe2\x82\xac\xf0\x9f\x98\x80" "b-._Z9"), "a____b-._Z9");
  CHECK_TEXT_EQ(SanitisePointName("x\xffy"), "x_y");  // a stray byte counts alone
  CHECK(PointMatchesGlob("before:heuristic:41", "*heuristic:*"));
  CHECK(PointMatchesGlob("after:final_pass", "*"));
  CHECK(PointMatchesGlob("after:cleanup:3185:4", "after:cleanup:31??:*"));
  CHECK(!PointMatchesGlob("after:cleanup:3185:4", "before:*"));
  CHECK(!PointMatchesGlob("abc", "ab"));
  CHECK(PointMatchesAnyGlob("after:final_pass", "before:*|after:final_pass"));
  CHECK(!PointMatchesAnyGlob("after:final_pass", ""));

  // write/read through a file: compact text plus one newline, like WriteJsonAtomic
  const std::string Dir = DSig::Test::ScratchDir("foundation-snapshot");
  const std::string Path = Join(Dir, "s.json");
  WriteSnapshot(Path, Sample, true);
  CHECK(SameSnapshot(ReadSnapshot(Path), Sample));
  WriteSnapshot(Path, Sample);
  CHECK_TEXT_EQ(ReadFile(Path), SerializeSnapshot(Sample) + "\n");
  DSig::Test::RemoveScratchDir(Dir);
}

// ---------------------------------------------------------------------------------------------
// Trace sink (Appendix B)

void TestTrace() {
  DSig::Test::Suite("trace");
  const std::string Dir = DSig::Test::ScratchDir("foundation-trace");
  const std::string Path = Join(Dir, "trace.jsonl");
  {
    TraceSink Sink;
    CHECK(!Sink.Enabled());
    Sink.Point("ignored", 0, 0, 0);  // disabled: no effect
    Sink.Open(Path, true);
    CHECK(Sink.Enabled() && Sink.RowsEnabled());
    Sink.AddMatch("heuristic:41", std::string_view("foo"), std::nullopt, "4198400", "4202496", "Loop count", 0.95,
                  std::string_view("partial"), AddMatchResult::Appended);
    Sink.Cleanup(3185, 4, 1, 2, 0);
    Sink.Point("after:final_pass", 3, 4, 0);
    Sink.Row("heuristic:41", "1", "2", RowDecision::BelowMin, std::nullopt);
    // an empty ctx is Python None; seq counts add_match calls only (1 here, not 4)
    Sink.AddMatch("", std::string_view("a\xc3\xa9"), std::string_view("b\n"), "1", "2", "d", 1.0, std::nullopt,
                  AddMatchResult::RejectedBetter);
    Sink.Row("find_same_name", "1", "2", RowDecision::AcceptedUnreliable, 0.5);
    CHECK_NUM_EQ(Sink.Events(), 6);
    Sink.Close();
  }
  // The same events written by CPython 3.13 through tools/parity/snapshot.py DumpJson with the keys in
  // oracle_trace.py's order: the native lines must be byte-identical.
  const std::string Expected =
      "{\"ev\":\"add_match\",\"seq\":0,\"ctx\":\"heuristic:41\",\"name1\":\"foo\",\"name2\":null,\"ea1\":\"4198400\","
      "\"ea2\":\"4202496\",\"desc\":\"Loop count\",\"ratio_bits\":\"3fee666666666666\",\"chooser\":\"partial\","
      "\"result\":\"appended\"}\n"
      "{\"ev\":\"cleanup\",\"site\":3185,\"n\":4,\"best\":1,\"partial\":2,\"unreliable\":0}\n"
      "{\"ev\":\"point\",\"name\":\"after:final_pass\",\"best\":3,\"partial\":4,\"unreliable\":0}\n"
      "{\"ev\":\"row\",\"ctx\":\"heuristic:41\",\"ea1\":\"1\",\"ea2\":\"2\",\"decision\":\"below_min\",\"ratio_bits\":null}\n"
      "{\"ev\":\"add_match\",\"seq\":1,\"ctx\":null,\"name1\":\"a\xc3\xa9\",\"name2\":\"b\\n\",\"ea1\":\"1\",\"ea2\":\"2\","
      "\"desc\":\"d\",\"ratio_bits\":\"3ff0000000000000\",\"chooser\":null,\"result\":\"rejected_better\"}\n"
      "{\"ev\":\"row\",\"ctx\":\"find_same_name\",\"ea1\":\"1\",\"ea2\":\"2\",\"decision\":\"accepted_unreliable\","
      "\"ratio_bits\":\"3fe0000000000000\"}\n";
  CHECK_TEXT_EQ(ReadFile(Path), Expected);
  CHECK_TEXT_EQ(std::string(AddMatchResultName(AddMatchResult::RejectedBetter)), "rejected_better");
  CHECK_TEXT_EQ(std::string(RowDecisionName(RowDecision::HasBest)), "has_best");
  // every decision name of tools/parity/README.md "row event"
  const std::pair<RowDecision, const char*> Decisions[] = {
      {RowDecision::Nullsub, "nullsub"},           {RowDecision::HasBest, "has_best"},
      {RowDecision::HasBetter, "has_better"},      {RowDecision::AcceptedBest, "accepted_best"},
      {RowDecision::AcceptedPartial, "accepted_partial"}, {RowDecision::BelowMin, "below_min"},
      {RowDecision::AcceptedUnreliable, "accepted_unreliable"}, {RowDecision::Raised, "raised"}};
  for (const auto& [Decision, Name] : Decisions) {
    CHECK_TEXT_EQ(std::string(RowDecisionName(Decision)), Name);
  }
  // "%1.2f" formatting of the summary lines
  CHECK_TEXT_EQ(FormatPercent2(100.0), "100.00");
  CHECK_TEXT_EQ(FormatPercent2(0.125), "0.12");   // exact binary tie, half-even
  CHECK_TEXT_EQ(FormatPercent2(0.375), "0.38");
  CHECK_TEXT_EQ(FormatPercent2(45.724), "45.72");
  DSig::Test::RemoveScratchDir(Dir);
}

// ---------------------------------------------------------------------------------------------
// Final results (orchestrator decision R0 (b)): D:3689 computes percent, and raises ZeroDivisionError
// when total_functions1 is 0, BEFORE D:3690 logs "Final results".

void TestFinalResults() {
  DSig::Test::Suite("final-results");
  {
    DiffSession S;
    S.Log().SetQuiet(true);
    S.State().SetTotals(0, 5);
    bool Threw = false;
    std::string Site;
    try {
      LogFinalResults(S);
    } catch (const DiaphoraWouldRaise& Error) {
      Threw = true;
      Site = Error.Site;
    }
    CHECK(Threw);
    CHECK_TEXT_EQ(Site, "D:3689 ZeroDivisionError");
    CHECK(S.Log().Lines().empty());  // no "Final results" line before the raise
  }
  {
    DiffSession S;
    S.Log().SetQuiet(true);
    S.State().SetTotals(8, 9);
    Item It;
    S.Final().Best = {It, It, It};
    S.Final().Partial = {It};
    S.Final().Multimatch = {It, It};
    LogFinalResults(S);
    const std::vector<std::string> Expected = {"Final results: Best 3, Partial 1, Unreliable 0, Multimatches 2",
                                               "Matched 50.00% of main binary functions (4 out of 8)"};
    CHECK(S.Log().Lines() == Expected);
  }
  {
    // show_summary (D:1631) raises before its first line too
    DiffSession S;
    S.Log().SetQuiet(true);
    bool Threw = false;
    try {
      LogShowSummary(S);
    } catch (const DiaphoraWouldRaise& Error) {
      Threw = Error.Site == "D:1631 ZeroDivisionError";
    }
    CHECK(Threw);
    CHECK(S.Log().Lines().empty());
  }
}

// ---------------------------------------------------------------------------------------------
// Configuration, names, URIs

void TestConfigAndNames() {
  DSig::Test::Suite("config");
  const DiffConfig C;
  CHECK(!C.Unreliable && !C.RelaxedRatio && C.Experimental && C.SlowHeuristics && !C.UseTrainedModel);
  CHECK(C.IgnoreSubNames && !C.IgnoreAllNames && !C.IgnoreSmallFunctions && C.CpuCount == 1);
  CHECK_NUM_EQ(C.MaxProcessedRows, 1000000);
  CHECK(C.Supported());
  CHECK(C.Postfix().empty());
  DiffConfig Small;
  Small.IgnoreSmallFunctions = true;
  CHECK(Small.Supported());
  CHECK(Small.Postfix() == " and f.instructions > 5 and df.instructions > 5 ");
  DiffConfig Unreliable;
  Unreliable.Unreliable = true;
  CHECK(!Unreliable.Supported());
  CHECK(kVersionValue == "3.4");
  CHECK(kDefaultPartialRatio == 0.5 && kDefaultTrustedPartialRatio == 0.3 && kMatchesBonusRatio == 0.01);
  CHECK(kRelatedMatchesMinRatio == 0.8 && kIncreaseRatioPerConstantMatchSameCpu == 0.006 &&
        kIncreaseRatioPerConstantMatch == 0.008);
  CHECK(kSpeedupStrippedBinariesMinPercent == 99.0 && kSpeedupPatchDiffSymbolsMinPercent == 90.0 &&
        kSpeedupPatchDiffRenamedFunctionMinRatio == 0.6);
  CHECK(kMaxFunctionsPerGap == 100 && kDiffingMatchesMaxDifferentBblocksPercent == 25 &&
        kDiffingMatchesMinBblocks == 3);

  // D:3727-3731 default output name
  CHECK_TEXT_EQ(DefaultOutputName("a/b/ls-old.sqlite", "ls.sqlite"), "ls-old_vs_ls.diaphora");
  CHECK_TEXT_EQ(DefaultOutputName("x.tar.gz", "y"), "x.tar_vs_y.diaphora");
  CHECK_TEXT_EQ(PathStem(".hidden"), ".hidden");
  CHECK_TEXT_EQ(PathStem("dir.d/file"), "file");
  CHECK_TEXT_EQ(PathStem("..x.sqlite"), "..x");
#ifdef _WIN32
  CHECK_TEXT_EQ(PathStem("C:\\exports\\ls-old.sqlite"), "ls-old");
  CHECK_TEXT_EQ(PathStem("C:ls.sqlite"), "ls");
#endif

  CHECK_TEXT_EQ(DiffDatabase::UriForPath("rel/a.sqlite"), "file:rel/a.sqlite?mode=ro");
  CHECK_TEXT_EQ(DiffDatabase::UriForPath("/x/a?b#c%d.sqlite"), "file:/x/a%3fb%23c%25d.sqlite?mode=ro");
  CHECK_TEXT_EQ(DiffDatabase::UriForPath("C:/x/a.sqlite", false), "file:/C:/x/a.sqlite");
  // a UNC path keeps an empty URI authority: file:////server/share/... (lane R0 (f))
  CHECK_TEXT_EQ(DiffDatabase::UriForPath("//server/share/a.sqlite"), "file:////server/share/a.sqlite?mode=ro");
#ifdef _WIN32
  CHECK_TEXT_EQ(DiffDatabase::UriForPath("\\\\server\\share\\a b.sqlite"), "file:////server/share/a b.sqlite?mode=ro");
  CHECK_TEXT_EQ(DiffDatabase::UriForPath("C:\\x\\a.sqlite"), "file:/C:/x/a.sqlite?mode=ro");
#endif
  CHECK(!DiffDatabase::LibVersion().empty());
  CHECK(!DiffDatabase::SourceId().empty());
  CHECK(SqliteMismatchWarning("3.45.0").find("3.51.1") != std::string::npos);
  DSig::Test::Note("sqlite3_libversion() = " + DiffDatabase::LibVersion());
}

// ---------------------------------------------------------------------------------------------
// Fixture, ingest, Path A (synthetic data only)

struct FixturePair {
  std::string Dir;
  std::string Main;
  std::string Diff;
  bool Ok = false;
};

// The committed foundation fixture pair, built in `Dir` (UTF-8) under the given file names.
FixturePair BuildFoundationFixtureIn(const std::string& Dir, const std::string& MainName, const std::string& DiffName,
                                     const std::string& ExtraMainSql = "", const std::string& ExtraDiffSql = "") {
  FixturePair Pair;
  Pair.Dir = Dir;
  Pair.Main = Join(Pair.Dir, MainName);
  Pair.Diff = Join(Pair.Dir, DiffName);
  const std::string Base = DSig::Test::TestDataDir() + "/fixtures/foundation/";
  const std::string MainSql = ReadFile(Base + "main.sql") + ExtraMainSql;
  const std::string DiffSql = ReadFile(Base + "diff.sql") + ExtraDiffSql;
  const std::string E1 = DSig::Test::BuildFixtureDbFromText(MainSql, Pair.Main);
  const std::string E2 = DSig::Test::BuildFixtureDbFromText(DiffSql, Pair.Diff);
  if (!E1.empty()) {
    DSig::Test::Note("fixture main: " + E1);
  }
  if (!E2.empty()) {
    DSig::Test::Note("fixture diff: " + E2);
  }
  Pair.Ok = E1.empty() && E2.empty();
  return Pair;
}

FixturePair BuildFoundationFixture(const std::string& Suite, const std::string& ExtraMainSql = "",
                                   const std::string& ExtraDiffSql = "") {
  return BuildFoundationFixtureIn(DSig::Test::ScratchDir(Suite), "main.sqlite", "diff.sqlite", ExtraMainSql,
                                  ExtraDiffSql);
}

void TestFixtureIngest() {
  DSig::Test::Suite("fixture-ingest");
  FixturePair Pair = BuildFoundationFixture("foundation-ingest");
  CHECK(Pair.Ok);
  if (!Pair.Ok) {
    return;
  }
  {
    DiffDatabase Db;
    Db.Open(Pair.Main, Pair.Diff);
    CHECK(Db.TableExists("main", "sqlite_stat1"));  // FixtureDb keeps the analyze statistics
    CHECK(Db.TableExists("diff", "sqlite_stat1"));
    CHECK(!Db.TableExists("main", "no_such_table"));
    CHECK_NUM_EQ(Db.PragmaThreads(), 0);  // the sorter stays stable (04a §6.4)
    Statement Stat = Db.Prepare("select count(*) from main.sqlite_stat1");
    CHECK(Stat.Step() && Stat.Int(0) > 0);
    const auto Plan = Db.ExplainQueryPlan(kSqlSameName);
    CHECK(!Plan.empty());
    // both databases are read-only: the open (lane R0 (f); the immutable URI of lane F1) keeps
    // SQLITE_OPEN_READONLY and the ATTACH inherits it (attach.c flags = db->openFlags). SQLITE_READONLY is
    // an environment failure (audit F03), never a Diaphora-parity raise a heuristic worker could swallow.
    for (const char* Sql : {"create table main.r0_probe (a)", "create table diff.r0_probe (a)",
                            "delete from diff.functions"}) {
      bool Refused = false;
      try {
        Statement Write = Db.Prepare(Sql);
        Write.Step();
      } catch (const SqliteEnvironmentFailure& Error) {
        Refused = Error.What.find("readonly") != std::string::npos && (Error.Code & 0xff) == SQLITE_READONLY;
      } catch (const DiaphoraWouldRaise&) {
        Refused = false;
      }
      CHECK(Refused);
    }
  }

  DiffSession S;
  S.Open(Pair.Main, Pair.Diff);
  CHECK(S.IsOpen());
  S.RequireIngest();
  const FunctionTable& M = S.Main().Functions;
  const FunctionTable& D = S.Diff().Functions;
  CHECK_NUM_EQ(M.Count(), 6);
  CHECK_NUM_EQ(D.Count(), 7);
  CHECK(S.Main().Problems.empty() && S.Diff().Problems.empty());
  // every column is loaded for every row
  for (const std::string_view Column : FunctionTable::ColumnNames()) {
    const auto Kind = FunctionTable::KindOf(Column);
    CHECK(Kind.has_value());
    size_t Size = 0;
    if (const IntColumn* I = M.IntColumnNamed(Column)) {
      Size = I->Size();
    } else if (const TextColumn* T = M.TextColumnNamed(Column)) {
      Size = T->Size();
    } else if (const RealColumn* R = M.RealColumnNamed(Column)) {
      Size = R->Size();
    }
    CHECK_NUM_EQ(Size, 6);
  }
  CHECK_NUM_EQ(FunctionTable::ColumnNames().size(), 49);
  // rows are in `order by id`, NULL stays distinct from '' (08 §9.1)
  CHECK_NUM_EQ(M.Id.Value[0], 1);
  CHECK_TEXT_EQ(std::string(M.Name.View(0)), "alpha");
  CHECK(M.Pseudocode.Null(1));                 // beta: pseudocode NULL
  CHECK(!M.CleanAssembly.Null(1) && M.CleanAssembly.View(1).empty());  // beta: clean_assembly ''
  CHECK(M.CleanMicrocode.Null(0));
  CHECK(M.Prototype.Null(0));
  CHECK_TEXT_EQ(std::string(M.MdIndex.View(0)), "3.050963036440351716676733804");
  // MdSqlReal is SQLite's own cast (07 §5.3): compare with the value SQLite computes
  {
    Statement Cast = S.Db().Prepare("select cast('3.050963036440351716676733804' as real)");
    CHECK(Cast.Step());
    CHECK(RatioBits(M.MdSqlReal[0]) == RatioBits(Cast.Real(0)));
  }
  CHECK(!M.MdSqlNull[0] && M.MdSqlReal[1] == 0.0);
  CHECK(M.AddressSqlReal[0] == 4096.0 && !M.AddressSqlNull[0]);
  CHECK(M.ExportTime.Value[0] == 0.001);
  CHECK(M.IntColumnNamed("nodes")->Value[0] == 5);
  CHECK(M.TextColumnNamed("name") == &M.Name);
  CHECK(M.RealColumnNamed("export_time") == &M.ExportTime);
  CHECK(M.IntColumnNamed("name") == nullptr);
  // interned ids and lookups
  const AddrId Alpha = S.Ids().Addr("4096");
  CHECK(M.AddrIdOf[0] == Alpha);
  CHECK(M.FindRow(Alpha) == 0u);
  CHECK(!D.FindRow(Alpha).has_value());
  CHECK(M.NameIdOf[3] == S.Ids().Name("?delta@@YAXXZ"));
  CHECK(M.MangledIdOf[3] == M.NameIdOf[3]);
  CHECK_NUM_EQ(M.RowsNamed(S.Ids().Name("alpha")).size(), 1);
  CHECK_NUM_EQ(D.RowsNamed(S.Ids().Name("alpha")).size(), 1);
  CHECK(M.RowsNamed(S.Ids().Name("nothing")).empty());
  for (size_t Row = 0; Row < M.Count(); ++Row) {
    CHECK(M.SelectFieldsUtf8Bad[Row] == 0 && M.AnyColumnUtf8Bad[Row] == 0);
  }
  // side tables
  const SideTables& T = S.Main().Tables;
  CHECK_NUM_EQ(T.Program.size(), 1);
  CHECK(T.Program.size() == 1 && T.Program[0].Processor.TextOrNull() == std::string_view("metapc"));
  CHECK(T.Version.size() == 1 && T.Version[0].TextOrNull() == std::string_view("3.4"));
  CHECK_NUM_EQ(T.IndexCount, 41);
  CHECK(T.HasStat1);
  CHECK(T.Has("constants") && T.Rows("constants") == 2);
  CHECK(T.Has("compilation_units") && T.Rows("compilation_units") == 0);
  CHECK_NUM_EQ(T.Tables.size(), SideTableNames().size());
  CHECK(T.Find("functions") != nullptr && T.Find("functions")->Columns.size() == 49);

  // Path A: SqlRowSource over find_same_name's SQL (only 'alpha' is shared)
  {
    SqlRowSource Rows(S, std::string(kSqlSameName));
    HeuristicRow Row;
    std::vector<HeuristicRow> Seen;
    while (Rows.Next(Row)) {
      Seen.push_back(Row);
    }
    CHECK_NUM_EQ(Seen.size(), 1);
    CHECK_NUM_EQ(Rows.Fetched(), 1);
    if (Seen.size() == 1) {
      CHECK_TEXT_EQ(std::string(S.Ids().AddrText(Seen[0].Ea1)), "4096");
      CHECK_TEXT_EQ(std::string(S.Ids().AddrText(Seen[0].Ea2)), "12288");
      CHECK(Seen[0].Row1 == 0 && Seen[0].Row2 == 0);
      CHECK(Seen[0].Side1 == Side::Main && Seen[0].Side2 == Side::Diff);
      CHECK_TEXT_EQ(std::string(S.Ids().NameText(Seen[0].Name1)), "alpha");
      CHECK_TEXT_EQ(std::string(S.Ids().DescText(Seen[0].Desc)), "Perfect match, same name");
      CHECK(Seen[0].Nodes1 == 5 && Seen[0].Nodes2 == 5);
      CHECK(Seen[0].Md1.has_value() && RatioBits(*Seen[0].Md1) == RatioBits(M.MdSqlReal[0]));
    }
    CHECK(!Rows.Next(Row));  // stays exhausted
  }
  // a heuristic with a bound Python-style parameter (search_remaining_functions shape)
  {
    std::vector<BindValue> Binds = {BindValue::Str("Renamed"), BindValue::Str("8192"), BindValue::Str("16384")};
    SqlRowSource Rows(S, std::string(kSqlRemainingPair), Binds);
    HeuristicRow Row;
    CHECK(Rows.Next(Row));
    CHECK_TEXT_EQ(std::string(S.Ids().DescText(Row.Desc)), "Renamed");
    CHECK(Row.Row1 == 4 && Row.Row2 == 4);
    CHECK(!Rows.Next(Row));
  }
  // bind count mismatch raises like Python's ProgrammingError
  {
    SqlRowSource Rows(S, std::string(kSqlRemainingPair));
    HeuristicRow Row;
    bool Threw = false;
    try {
      Rows.Next(Row);
    } catch (const DiaphoraWouldRaise&) {
      Threw = true;
    }
    CHECK(Threw);
  }
  // a query without SELECT_FIELDS is not a row source
  {
    SqlRowSource Rows(S, "select 1");
    HeuristicRow Row;
    bool Threw = false;
    try {
      Rows.Next(Row);
    } catch (const UnsupportedInput&) {
      Threw = true;
    }
    CHECK(Threw);
  }
  // every default heuristic prepares and runs on the fixture
  for (const HeuristicSpec& Spec : Heuristics()) {
    SqlRowSource Rows(S, ApplyPostfix(Spec.Sql, ""));
    HeuristicRow Row;
    bool Ok = true;
    try {
      while (Rows.Next(Row)) {
      }
    } catch (const std::exception& Failure) {
      Ok = false;
      DSig::Test::Note("heuristic " + std::to_string(Spec.Id) + ": " + Failure.what());
    }
    CHECK(Ok);
  }
  // full-row lookups (get_function_row / functions_exists shapes)
  {
    const BindValue Name = BindValue::Str("alpha");
    const auto Rows = FetchFunctionRows(S, kSqlFunctionRowMain, std::span<const BindValue>(&Name, 1), Side::Main, 1);
    CHECK(Rows.size() == 1 && Rows[0].Row == 0 && Rows[0].Which == Side::Main);
    std::vector<BindValue> Both = {BindValue::Str("alpha"), BindValue::Str("sub_3400")};
    const auto Pair2 = FetchFunctionRows(S, kSqlFunctionsExists, Both, Side::Main);
    CHECK_NUM_EQ(Pair2.size(), 2);
    if (Pair2.size() == 2) {
      // order by db_name desc: 'main' first (D:2980)
      CHECK(Pair2[0].Which == Side::Main && Pair2[0].Row == 0);
      CHECK(Pair2[1].Which == Side::Diff && Pair2[1].Row == 1);
    }
  }
  // VectorRowSource
  {
    HeuristicRow A;
    A.Ea1 = Alpha;
    VectorRowSource Rows({A, A});
    HeuristicRow Out;
    CHECK(Rows.Next(Out) && Out.Ea1 == Alpha);
    CHECK(Rows.Next(Out));
    CHECK(!Rows.Next(Out));
    CHECK_NUM_EQ(Rows.Fetched(), 2);
  }
  DSig::Test::RemoveScratchDir(Pair.Dir);
}

// Invalid UTF-8 at fetch (01 §13) and refused exports.
void TestIngestQuirks() {
  DSig::Test::Suite("ingest-quirks");
  // clean_pseudo of `gamma` (id 3) becomes TEXT with an invalid UTF-8 byte sequence
  FixturePair Pair =
      BuildFoundationFixture("foundation-quirks", "update functions set clean_pseudo = cast(X'C328' as text) "
                                                  "where id = 3;\nupdate functions set comment = cast(X'FF' as text) "
                                                  "where id = 2;\n");
  CHECK(Pair.Ok);
  if (!Pair.Ok) {
    return;
  }
  DiffSession S;
  S.Open(Pair.Main, Pair.Diff);
  const FunctionTable& M = S.Main().Functions;
  CHECK(M.SelectFieldsUtf8Bad[2] == 1 && M.AnyColumnUtf8Bad[2] == 1);
  CHECK(M.SelectFieldsUtf8Bad[1] == 0 && M.AnyColumnUtf8Bad[1] == 1);  // comment is not a SELECT_FIELDS column
  // a SELECT_FIELDS row that includes gamma raises at fetch
  {
    const std::string Sql = std::string(kSqlRemainingPair);
    std::vector<BindValue> Binds = {BindValue::Str("x"), BindValue::Str("6144"), BindValue::Str("14336")};
    SqlRowSource Rows(S, Sql, Binds);
    HeuristicRow Row;
    bool Threw = false;
    try {
      Rows.Next(Row);
    } catch (const DiaphoraWouldRaise& Error) {
      Threw = Error.Site == "fetch";
    }
    CHECK(Threw);
  }
  // ... and a `select *` fetch of beta raises too (comment decodes), but not gamma's neighbours
  {
    const BindValue Beta = BindValue::Str("beta");
    bool Threw = false;
    try {
      (void)FetchFunctionRows(S, kSqlFunctionRowMain, std::span<const BindValue>(&Beta, 1), Side::Main, 1);
    } catch (const DiaphoraWouldRaise&) {
      Threw = true;
    }
    CHECK(Threw);
    const BindValue Alpha = BindValue::Str("alpha");
    CHECK_NUM_EQ(FetchFunctionRows(S, kSqlFunctionRowMain, std::span<const BindValue>(&Alpha, 1), Side::Main).size(), 1);
  }
  CHECK(IsValidUtf8("plain ascii"));
  CHECK(IsValidUtf8("\xc3\xa9\xe2\x82\xac\xf0\x9f\x98\x80"));
  CHECK(!IsValidUtf8("\xc3"));
  CHECK(!IsValidUtf8("\xc0\xaf"));          // overlong
  CHECK(!IsValidUtf8("\xed\xa0\x80"));      // surrogate
  CHECK(!IsValidUtf8("\xf4\x90\x80\x80"));  // above U+10FFFF
  CHECK(!IsValidUtf8("abcdefgh\x80"));
  DSig::Test::RemoveScratchDir(Pair.Dir);

  // an export without `functions` columns is recorded, then refused after the version check
  FixturePair Broken = BuildFoundationFixture("foundation-broken",
                                              "drop index idx_22;\nalter table functions drop column switches;\n");
  CHECK(Broken.Ok);
  if (Broken.Ok) {
    DiffSession B;
    B.Open(Broken.Main, Broken.Diff);
    CHECK_NUM_EQ(B.Main().Problems.size(), 1);
    CHECK(B.Diff().Problems.empty());
    bool Threw = false;
    try {
      B.RequireIngest();
    } catch (const UnsupportedInput& Error) {
      Threw = Error.What.find("switches") != std::string::npos;
    }
    CHECK(Threw);
    DiffArgs Args;
    Args.Db1 = Broken.Main;
    Args.Db2 = Broken.Diff;
    Args.Out = Join(Broken.Dir, "out.diaphora");
    Args.Quiet = true;
    const DiffOutcome Outcome = RunDiff(Args);
    CHECK(Outcome.Status == DiffStatus::Unsupported);
    CHECK(!Outcome.OutputWritten);
    DSig::Test::RemoveScratchDir(Broken.Dir);
  }
}

// ---------------------------------------------------------------------------------------------
// The pipeline end to end (G0) on the fixture

const std::vector<DSig::Test::SchemaRow>& DiaphoraDdl() {
  // D:2387-2403 as stored in sqlite_master (01 §11.1)
  static const std::vector<DSig::Test::SchemaRow> Rows = {
      {"table", "config", "config", "CREATE TABLE config (main_db text, diff_db text, version text, date text)"},
      {"table", "results", "results",
       "CREATE TABLE results (type, line, address, name, address2, name2,\n"
       "                   ratio, nodes1, nodes2, description)"},
      {"index", "uq_results", "results", "CREATE UNIQUE INDEX uq_results on results(address, address2)"},
      {"table", "unmatched", "unmatched", "CREATE TABLE unmatched (type, line, address, name)"},
  };
  return Rows;
}

// A capture directory in the layout of tools/parity/oracle_trace.py (README "Output"): <Dir>/index.json
// lists every point as [seq, point, file], and `file` ("snapshots/NNNNN_<point>.json", relative to
// <Dir>) is null for a point whose snapshot was filtered out.
struct IndexRow {
  int64_t Seq = 0;
  std::string Point;
  std::optional<std::string> File;
};

std::vector<IndexRow> ReadIndex(const std::string& Dir) {
  std::vector<IndexRow> Rows;
  const JsonValue Index = JsonParse(ReadFile(Join(Dir, "index.json")));
  for (const JsonValue& Row : Index.Items()) {
    IndexRow Entry;
    Entry.Seq = Row.Items().at(0).AsInt64();
    Entry.Point = Row.Items().at(1).AsString();
    if (!Row.Items().at(2).IsNull()) {
      Entry.File = Row.Items().at(2).AsString();
    }
    Rows.push_back(std::move(Entry));
  }
  return Rows;
}

std::vector<std::string> ReadIndexPoints(const std::string& Dir) {
  std::vector<std::string> Points;
  for (const IndexRow& Row : ReadIndex(Dir)) {
    Points.push_back(Row.Point);
  }
  return Points;
}

// Every line of a JSONL file (without its newline).
std::vector<std::string> ReadLines(const std::string& Path) {
  std::vector<std::string> Lines;
  const std::string Text = ReadFile(Path);
  size_t Start = 0;
  while (Start < Text.size()) {
    size_t End = Text.find('\n', Start);
    if (End == std::string::npos) {
      End = Text.size();
    }
    Lines.push_back(Text.substr(Start, End - Start));
    Start = End + 1;
  }
  return Lines;
}

// The oracle's snapshot "iteration" rule (tools/parity/README.md, oracle_trace.py WrapCleanup /
// WrapStage) computed from a point sequence alone: the n-th "before:cleanup:3655:<n>" (the loop head,
// D:3655) starts iteration n-1, which holds through the loop's last cleanup (D:3671); null before the
// loop, in modes S and P, and from before:final_pass on.
std::vector<std::optional<int64_t>> ExpectedIterations(const std::vector<std::string>& Points) {
  static const std::string Head = "before:cleanup:3655:";
  std::vector<std::optional<int64_t>> Out;
  std::optional<int64_t> Current;
  for (const std::string& Point : Points) {
    if (Point.rfind(Head, 0) == 0) {
      Current = std::stoll(Point.substr(Head.size())) - 1;
    }
    if (Point == "before:final_pass") {
      Current.reset();
    }
    Out.push_back(Current);
  }
  return Out;
}

void WriteText(const std::string& Path, std::string_view Text) {
  std::ofstream Out(Utf8ToPath(Path), std::ios::binary | std::ios::trunc);
  Out.write(Text.data(), static_cast<std::streamsize>(Text.size()));
}

void TestPipeline() {
  DSig::Test::Suite("pipeline");
  FixturePair Pair = BuildFoundationFixture("foundation-pipeline");
  CHECK(Pair.Ok);
  if (!Pair.Ok) {
    return;
  }
  // The oracle's capture layout: index.json, snapshots/ and trace.jsonl in one directory.
  const std::string Capture = Join(Pair.Dir, "capture");
  const std::string Trace = Join(Capture, "trace.jsonl");
  {
    // a stale snapshot of an earlier run is removed; an unrelated file is left alone
    std::error_code Error;
    fs::create_directories(Utf8ToPath(Join(Capture, "snapshots")), Error);
    WriteText(Join(Join(Capture, "snapshots"), "99999_stale_point.json"), "{}");
    WriteText(Join(Join(Capture, "snapshots"), "notes.txt"), "keep");
  }
  DiffArgs Args;
  Args.Db1 = Pair.Main;
  Args.Db2 = Pair.Diff;
  Args.Out = Join(Pair.Dir, "out.diaphora");
  Args.SnapshotDir = Capture;
  Args.TracePath = Trace;
  Args.TraceRows = true;
  Args.Quiet = true;
  Args.AllowSqliteMismatch = true;
  WriteText(Args.Out, "stale");  // D:2379-2381: an existing output is replaced
  const DiffOutcome Outcome = RunDiff(Args);
  CHECK(Outcome.Status == DiffStatus::Ok);
  if (Outcome.Status != DiffStatus::Ok) {
    DSig::Test::Note("RunDiff: " + Outcome.Message);
  }
  CHECK(Outcome.OutputWritten);
  CHECK(Outcome.Mode == 'N');
  CHECK(Outcome.DiffReturned);
  CHECK(!Exists(Join(Join(Capture, "snapshots"), "99999_stale_point.json")));
  CHECK(Exists(Join(Join(Capture, "snapshots"), "notes.txt")));
  const DSig::Test::ResultsFile File = DSig::Test::ReadResultsFile(Args.Out);
  CHECK(File.Error.empty());
  CHECK(File.Schema == DiaphoraDdl());  // Diaphora's exact DDL
  CHECK(File.AllText);
  CHECK_NUM_EQ(File.Config.size(), 1);
  if (File.Config.size() == 1) {
    CHECK_TEXT_EQ(File.Config[0][0], Args.Db1);  // exactly as passed
    CHECK_TEXT_EQ(File.Config[0][1], Args.Db2);
    CHECK_TEXT_EQ(File.Config[0][2], "3.4");
    CHECK_NUM_EQ(File.Config[0][3].size(), 24);  // time.asctime()
  }

  // mode-N points of Appendix B (plan §4 L0 acceptance)
  const std::vector<IndexRow> Index = ReadIndex(Capture);
  const std::vector<std::string> Points = ReadIndexPoints(Capture);
  const std::set<std::string> Have(Points.begin(), Points.end());
  const std::vector<std::string> Required = {
      "after:find_equal_matches",
      "after:apply_dirty_heuristics",
      "before:find_same_name",
      "after:find_same_name",
      "before:heuristic:11",
      "after:heuristic:11",
      // SAME_CPU heuristics (H:44-48) run: both fixture exports are metapc
      // (same_processor_both_databases, D:2950-2967)
      "before:heuristic:0",
      "after:heuristic:0",
      "before:heuristic:39",
      "before:cleanup:1551:1",
      "after:cleanup:1551:1",
      "after:run_heuristics_for_category:Best",
      "before:search_small_differences",
      "after:search_small_differences",
      "before:cleanup:3655:1",
      "after:cleanup:3655:1",
      "before:find_matches_diffing:0",
      "before:cleanup:3217:1",
      "after:find_matches_diffing:0",
      "before:find_related_matches:0",
      "before:cleanup:3471:1",
      "after:find_related_matches:0",
      "before:find_related_compilation_unit:0",
      "before:cleanup:3413:1",
      "after:find_related_compilation_unit:0",
      "before:find_locally_affine_functions:0",
      "before:cleanup:3340:1",
      "after:find_locally_affine_functions:0",
      "before:cleanup:3671:1",
      "after:cleanup:3671:1",
      "before:final_pass",
      "before:cleanup:2945:1",
      "after:final_pass",
      "after:find_unmatched",
  };
  for (const std::string& Name : Required) {
    const bool Present = Have.count(Name) != 0;
    CHECK(Present);
    if (!Present) {
      DSig::Test::Note("missing point " + Name);
    }
  }
  // "Partial" category point: present unless every function got matched before the Partial list
  CHECK(Have.count("after:run_heuristics_for_category:Partial") == 1 ||
        Have.count("after:run_heuristics_for_category:Best") == 1);
  // mode N never visits find_remaining_functions
  CHECK(Have.count("before:find_remaining_functions") == 0);
  // points are unique and in emission order: before < after for each stage
  CHECK_NUM_EQ(Have.size(), Points.size());
  const auto Pos = [&](const std::string& Name) {
    return std::find(Points.begin(), Points.end(), Name) - Points.begin();
  };
  CHECK(Pos("before:final_pass") < Pos("after:final_pass"));
  CHECK(Pos("after:final_pass") < Pos("after:find_unmatched"));
  CHECK(Pos("after:find_equal_matches") < Pos("before:find_same_name"));

  // index.json: compact JSON plus one newline (snapshot.py WriteJsonAtomic); seq is 0-based and counts
  // every point; file is "snapshots/" + SnapshotFileName(seq, point)
  const std::string IndexText = ReadFile(Join(Capture, "index.json"));
  CHECK_TEXT_EQ(IndexText, JsonWrite(JsonParse(IndexText)) + "\n");
  const std::vector<std::optional<int64_t>> Iterations = ExpectedIterations(Points);
  for (size_t Position = 0; Position < Index.size(); ++Position) {
    const IndexRow& Row = Index[Position];
    CHECK_NUM_EQ(Row.Seq, Position);
    CHECK(Row.File.has_value());
    if (!Row.File) {
      continue;
    }
    CHECK_TEXT_EQ(*Row.File, "snapshots/" + SnapshotFileName(Row.Seq, Row.Point));
    const std::string Bytes = ReadFile(Join(Capture, *Row.File));
    const StateSnapshot Snap = ParseSnapshot(Bytes);
    CHECK_TEXT_EQ(SerializeSnapshot(Snap) + "\n", Bytes);  // the writer's own format, compact
    CHECK_TEXT_EQ(Snap.Point, Row.Point);
    CHECK_NUM_EQ(Snap.Seq, Row.Seq);
    CHECK(Snap.Choosers.has_value() == (Snap.Point == "after:final_pass"));
    CHECK(Snap.Unmatched.has_value() == (Snap.Point == "after:find_unmatched"));
    CHECK_NUM_EQ(Snap.Flags.TotalFunctions1, 6);
    CHECK_NUM_EQ(Snap.Flags.TotalFunctions2, 7);
    CHECK(Snap.Producer.rfind("dsigmatcher-", 0) == 0);
    CHECK_TEXT_EQ(Snap.Pair, "main_vs_diff");
    // iteration: k inside the loop only, null again from before:final_pass (tools/parity/README.md)
    CHECK(Snap.Iteration == Iterations[Position]);
    // is_same_processor is set after find_equal_matches (D:3613-3617)
    CHECK(Snap.Flags.IsSameProcessor == (Row.Point != "after:find_equal_matches"));
  }
  CHECK(Iterations[static_cast<size_t>(Pos("after:cleanup:3671:1"))] == std::optional<int64_t>(0));
  CHECK(!Iterations[static_cast<size_t>(Pos("before:final_pass"))].has_value());

  // the trace: the oracle's event shapes; one point event per point, in the same order; only add_match
  // events carry "seq"; a cleanup event sits right before its "after:cleanup:<site>:<n>" point
  {
    std::vector<std::string> TracePoints;
    std::string LastCleanup;
    bool CleanupsPaired = true;
    bool SeqOnlyOnAddMatch = true;
    for (const std::string& Line : ReadLines(Trace)) {
      const JsonValue Event = JsonParse(Line);
      const std::string Kind = Event.At("ev").AsString();
      CHECK_TEXT_EQ(JsonWrite(Event), Line);  // compact, in the writer's key order
      if (Kind != "add_match" && Event.Find("seq") != nullptr) {
        SeqOnlyOnAddMatch = false;
      }
      if (Kind == "point") {
        const std::string Name = Event.At("name").AsString();
        TracePoints.push_back(Name);
        if (Name.rfind("after:cleanup:", 0) == 0 && Name != "after:cleanup:" + LastCleanup) {
          CleanupsPaired = false;
        }
        LastCleanup.clear();
      } else if (Kind == "cleanup") {
        LastCleanup = std::to_string(Event.At("site").AsInt64()) + ":" + std::to_string(Event.At("n").AsInt64());
      }
    }
    CHECK(TracePoints == Points);
    CHECK(SeqOnlyOnAddMatch);
    CHECK(CleanupsPaired);
  }

  // --snapshot-points filters snapshot files only: index.json still lists every point with its seq,
  // and the filtered ones have a null file (oracle --points)
  {
    DiffArgs Filtered = Args;
    Filtered.Out = Join(Pair.Dir, "filtered.diaphora");
    Filtered.SnapshotDir = Join(Pair.Dir, "filtered");
    Filtered.TracePath.clear();
    Filtered.SnapshotPoints = "after:*";
    CHECK(RunDiff(Filtered).Status == DiffStatus::Ok);
    const std::vector<IndexRow> Rows = ReadIndex(Filtered.SnapshotDir);
    CHECK_NUM_EQ(Rows.size(), Index.size());
    for (size_t Position = 0; Position < Rows.size() && Position < Index.size(); ++Position) {
      CHECK_TEXT_EQ(Rows[Position].Point, Index[Position].Point);
      CHECK_NUM_EQ(Rows[Position].Seq, Position);
      const bool Kept = Rows[Position].Point.rfind("after:", 0) == 0;
      CHECK(Rows[Position].File.has_value() == Kept);
      CHECK(Exists(Join(Join(Filtered.SnapshotDir, "snapshots"), SnapshotFileName(Rows[Position].Seq,
                                                                                   Rows[Position].Point))) == Kept);
    }
  }

  // an oracle capture (a directory holding run.json) is never written into
  {
    const std::string Oracle = Join(Pair.Dir, "oracle-capture");
    std::error_code Error;
    fs::create_directories(Utf8ToPath(Oracle), Error);
    WriteText(Join(Oracle, "run.json"), "{\"status\": \"complete\"}\n");
    DiffArgs Guard = Args;
    Guard.Out = Join(Pair.Dir, "guard.diaphora");
    Guard.SnapshotDir = Oracle;
    Guard.TracePath.clear();
    const DiffOutcome Refused = RunDiff(Guard);
    CHECK(Refused.Status == DiffStatus::Usage);  // refused before anything is opened (exit 2)
    CHECK(Refused.Message.find("run.json") != std::string::npos);
    CHECK(!Exists(Join(Oracle, "index.json")) && !Exists(Join(Oracle, "snapshots")));
    Guard.SnapshotDir = Join(Oracle, "snapshots");  // inside one
    CHECK(RunDiff(Guard).Status == DiffStatus::Usage);
    Guard.SnapshotDir.clear();
    Guard.TracePath = Join(Oracle, "trace.jsonl");
    CHECK(RunDiff(Guard).Status == DiffStatus::Usage);
    CHECK(!Exists(Join(Oracle, "trace.jsonl")));
    CHECK_TEXT_EQ(ReadFile(Join(Oracle, "run.json")), "{\"status\": \"complete\"}\n");
  }

  const auto Find = [&](const std::string& Name) {
    return Join(Join(Capture, "snapshots"), SnapshotFileName(Pos(Name), Name));
  };
  // replay: a cleanup from its before snapshot reproduces the after snapshot (S-L2, point and
  // iteration included)
  {
    DiffSession S;
    S.Open(Pair.Main, Pair.Diff);
    const StateSnapshot Before = ReadSnapshot(Find("before:cleanup:3655:1"));
    const StateSnapshot Expected = ReadSnapshot(Find("after:cleanup:3655:1"));
    const StateSnapshot After = RunReplay(S, Before, "cleanup:3655:1");
    CHECK_TEXT_EQ(After.Point, "after:cleanup:3655:1");
    CHECK(After.Iteration == std::optional<int64_t>(0));
    const DSig::Test::CompareReport Report = DSig::Test::CompareSnapshots(Expected, After);
    CHECK(Report.L2Equal);
    for (const std::string& Line : Report.Differences) {
      DSig::Test::Note(Line);
    }
    StateSnapshot Relabelled = After;
    Relabelled.Iteration = 1;
    CHECK(!DSig::Test::CompareSnapshots(Expected, Relabelled).L2Equal);  // iteration is compared
    CHECK(DSig::Test::CompareSnapshots(Expected, Relabelled, 20, false).L2Equal);
    bool Threw = false;
    try {
      (void)RunReplay(S, Before, "no_such_stage");
    } catch (const UnsupportedInput&) {
      Threw = true;
    }
    CHECK(Threw);
  }
  // the CLI replay path writes the after snapshot, compact like every oracle snapshot
  {
    DiffArgs Replay;
    Replay.Db1 = Pair.Main;
    Replay.Db2 = Pair.Diff;
    Replay.ReplayPath = Find("before:cleanup:3671:1");
    Replay.ReplayStage = "cleanup:3671:1";
    Replay.SnapshotOut = Join(Pair.Dir, "after.json");
    Replay.Quiet = true;
    const DiffOutcome Out = RunDiff(Replay);
    CHECK(Out.Status == DiffStatus::Ok);
    CHECK(Out.OutputWritten && Exists(Replay.SnapshotOut));
    const std::string Written = ReadFile(Replay.SnapshotOut);
    CHECK_TEXT_EQ(Written, SerializeSnapshot(ParseSnapshot(Written)) + "\n");
    Replay.SnapshotOut.clear();
    CHECK(RunDiff(Replay).Status == DiffStatus::Usage);
  }

  // exit codes (plan §2.1)
  {
    DiffArgs Bad = Args;
    Bad.SnapshotDir.clear();
    Bad.TracePath.clear();
    Bad.Config.Unreliable = true;
    CHECK(RunDiff(Bad).Status == DiffStatus::Unsupported);
    DiffArgs Alias = Bad;
    Alias.Config = DiffConfig();
    Alias.Out = Pair.Diff;  // aliases an input
    CHECK(RunDiff(Alias).Status == DiffStatus::Usage);
    DiffArgs Missing = Alias;
    Missing.Out = Join(Pair.Dir, "x.diaphora");
    Missing.Db2 = Join(Pair.Dir, "no-such.sqlite");
    const DiffOutcome Io = RunDiff(Missing);
    CHECK(Io.Status == DiffStatus::Io);
    CHECK(!Exists(Missing.Db2));  // a read-only open never creates the input
    DiffArgs Strict = Alias;
    Strict.Out = Join(Pair.Dir, "strict.diaphora");
    Strict.StrictSqlite = true;
    const DiffStatus Expected = DiffDatabase::IsOracleSqlite() ? DiffStatus::Ok : DiffStatus::SqliteMismatch;
    CHECK(RunDiff(Strict).Status == Expected);
    CHECK(static_cast<int>(DiffStatus::WouldRaise) == 3 && static_cast<int>(DiffStatus::Io) == 6);
  }

  // the session helpers
  {
    DiffSession S;
    CHECK(S.Context() == "diff");
    {
      ContextScope Scope(S, "heuristic:7");
      CHECK(S.Context() == "heuristic:7");
    }
    CHECK(S.Context() == "diff");
    struct Counter {
      int Value = 0;
    };
    S.Ext<Counter>().Value += 2;
    S.Ext<Counter>().Value += 3;
    CHECK_NUM_EQ(S.Ext<Counter>().Value, 5);
    CHECK(S.Mode() == 'N');
    S.Flags().IsPatchDiff = true;
    CHECK(S.Mode() == 'P');
  }
  // trace ctx: the top-level context "diff" is written as null, like the oracle's None
  {
    const std::string Dir = DSig::Test::ScratchDir("foundation-ctx");
    const std::string Path = Join(Dir, "ctx.jsonl");
    DiffSession S;
    S.EnableTrace(Path, true);
    Interners& Ids = S.Ids();
    Item It;
    It.Ea1 = Ids.Addr("4096");
    It.Ea2 = Ids.Addr("8192");
    It.Desc = Ids.Desc("d");
    TraceAddMatch(S, Ids.Name("a"), Ids.Name("b"), 0.5, It, Chooser::Partial, AddMatchResult::Appended);
    {
      ContextScope Scope(S, "find_same_name");
      TraceAddMatch(S, Ids.Name("a"), kNoneName, 0.5, It, std::nullopt, AddMatchResult::Duplicate);
    }
    S.FinishHarness();
    const std::vector<std::string> Lines = ReadLines(Path);
    CHECK_NUM_EQ(Lines.size(), 2);
    if (Lines.size() == 2) {
      CHECK_TEXT_EQ(Lines[0],
                    "{\"ev\":\"add_match\",\"seq\":0,\"ctx\":null,\"name1\":\"a\",\"name2\":\"b\",\"ea1\":\"4096\","
                    "\"ea2\":\"8192\",\"desc\":\"d\",\"ratio_bits\":\"3fe0000000000000\",\"chooser\":\"partial\","
                    "\"result\":\"appended\"}");
      CHECK_TEXT_EQ(Lines[1],
                    "{\"ev\":\"add_match\",\"seq\":1,\"ctx\":\"find_same_name\",\"name1\":\"a\",\"name2\":null,"
                    "\"ea1\":\"4096\",\"ea2\":\"8192\",\"desc\":\"d\",\"ratio_bits\":\"3fe0000000000000\","
                    "\"chooser\":null,\"result\":\"duplicate\"}");
    }
    DSig::Test::RemoveScratchDir(Dir);
  }
  DSig::Test::RemoveScratchDir(Pair.Dir);
}

// ---------------------------------------------------------------------------------------------
// Missing side tables (orchestrator decision R0 (d)): refused with UnsupportedInput, exit 4, naming the
// table, never a raw "no such table" SQL error.

void TestMissingSideTables() {
  DSig::Test::Suite("missing-side-tables");
  struct Case {
    const char* Side;
    const char* Table;
  };
  const Case Cases[] = {{"main", "constants"},    {"diff", "compilation_unit_functions"},
                        {"main", "program"},      {"diff", "bb_instructions"},
                        {"diff", "instructions"}, {"main", "compilation_units"}};
  for (const Case& C : Cases) {
    const std::string Drop = std::string("drop table ") + C.Table + ";\n";
    const bool OnMain = std::string(C.Side) == "main";
    FixturePair Pair =
        BuildFoundationFixture(std::string("foundation-missing-") + C.Table, OnMain ? Drop : "", OnMain ? "" : Drop);
    CHECK(Pair.Ok);
    if (!Pair.Ok) {
      continue;
    }
    const std::string Expected = std::string(C.Side) + "." + C.Table + ": table is missing";
    {
      DiffSession S;
      S.Open(Pair.Main, Pair.Diff);
      CHECK_NUM_EQ((OnMain ? S.Main() : S.Diff()).Problems.size(), 1);
      CHECK((OnMain ? S.Diff() : S.Main()).Problems.empty());
      bool Named = false;
      try {
        S.RequireIngest();
      } catch (const UnsupportedInput& Error) {
        Named = Error.What.find(Expected) != std::string::npos;
      }
      CHECK(Named);
    }
    DiffArgs Args;
    Args.Db1 = Pair.Main;
    Args.Db2 = Pair.Diff;
    Args.Out = Join(Pair.Dir, "out.diaphora");
    Args.Quiet = true;
    Args.AllowSqliteMismatch = true;
    const DiffOutcome Outcome = RunDiff(Args);
    CHECK(Outcome.Status == DiffStatus::Unsupported);
    CHECK_NUM_EQ(static_cast<int>(Outcome.Status), 4);
    CHECK(Outcome.Message.find(Expected) != std::string::npos);
    CHECK(Outcome.Message.find("no such table") == std::string::npos);
    CHECK(!Outcome.OutputWritten && !Exists(Args.Out));
    DSig::Test::RemoveScratchDir(Pair.Dir);
  }
  // diff.version is not required by ingest: without it Diaphora takes the empty-result path
  // (D:3577-3591), which is the version check's decision (L5), not a refusal.
  {
    FixturePair Pair = BuildFoundationFixture("foundation-missing-version", "", "drop table version;\n");
    CHECK(Pair.Ok);
    if (Pair.Ok) {
      DiffSession S;
      S.Open(Pair.Main, Pair.Diff);
      CHECK(S.Main().Problems.empty() && S.Diff().Problems.empty());
      DSig::Test::RemoveScratchDir(Pair.Dir);
    }
  }
}

// ---------------------------------------------------------------------------------------------
// The SQLite version warning is not silenced by --quiet (orchestrator decision R0 (c)).

// Runs F with file descriptor 2 redirected into `File` and returns what was written to it.
std::string CaptureStderr(const std::string& File, const std::function<void()>& F) {
  std::fflush(stderr);
#ifdef _WIN32
  int Sink = -1;
  if (_wsopen_s(&Sink, Utf8ToPath(File).c_str(), _O_WRONLY | _O_CREAT | _O_TRUNC | _O_BINARY, _SH_DENYNO,
                _S_IREAD | _S_IWRITE) != 0) {
    F();
    return "<stderr capture failed>";
  }
  const int Saved = _dup(2);
  _dup2(Sink, 2);
  try {
    F();
  } catch (...) {
    std::fflush(stderr);
    _dup2(Saved, 2);
    _close(Saved);
    _close(Sink);
    throw;
  }
  std::fflush(stderr);
  _dup2(Saved, 2);
  _close(Saved);
  _close(Sink);
#else
  const int Sink = open(File.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (Sink < 0) {
    F();
    return "<stderr capture failed>";
  }
  const int Saved = dup(2);
  dup2(Sink, 2);
  try {
    F();
  } catch (...) {
    std::fflush(stderr);
    dup2(Saved, 2);
    close(Saved);
    close(Sink);
    throw;
  }
  std::fflush(stderr);
  dup2(Saved, 2);
  close(Saved);
  close(Sink);
#endif
  return ReadFile(File);
}

void TestSqliteWarning() {
  if (DiffDatabase::IsOracleSqlite()) {
    DSig::Test::Skip("sqlite-warning", "SQLite is the oracle's 3.51.1, so there is no mismatch warning to check "
                                       "(run this suite against another sqlite3 build to exercise it)");
    return;
  }
  DSig::Test::Suite("sqlite-warning");
  FixturePair Pair = BuildFoundationFixture("foundation-warning");
  CHECK(Pair.Ok);
  if (!Pair.Ok) {
    return;
  }
  DiffArgs Args;
  Args.Db1 = Pair.Main;
  Args.Db2 = Pair.Diff;
  Args.Out = Join(Pair.Dir, "quiet.diaphora");
  Args.Quiet = true;  // silences Diaphora's summary lines only
  DiffOutcome Outcome;
  std::string Err = CaptureStderr(Join(Pair.Dir, "stderr1.txt"), [&] { Outcome = RunDiff(Args); });
  CHECK(Outcome.Status == DiffStatus::Ok);
  CHECK(Err.find(SqliteMismatchWarning(DiffDatabase::LibVersion())) != std::string::npos);
  CHECK(Err.find("Final results") == std::string::npos);
  Args.Out = Join(Pair.Dir, "allowed.diaphora");
  Args.AllowSqliteMismatch = true;  // the explicit acknowledgement
  Err = CaptureStderr(Join(Pair.Dir, "stderr2.txt"), [&] { Outcome = RunDiff(Args); });
  CHECK(Outcome.Status == DiffStatus::Ok);
  CHECK(Err.find("WARNING: SQLite") == std::string::npos);
  DSig::Test::RemoveScratchDir(Pair.Dir);
}

// ---------------------------------------------------------------------------------------------
// Unicode and UNC paths (orchestrator decision R0 (f)), in process and through the CLI binary.

#ifdef DSIG_CLI_PATH
#ifdef _WIN32
std::wstring Utf8ToWide(const std::string& Utf8) {
  if (Utf8.empty()) {
    return std::wstring();
  }
  const int Size = MultiByteToWideChar(CP_UTF8, 0, Utf8.data(), static_cast<int>(Utf8.size()), nullptr, 0);
  std::wstring Out(static_cast<size_t>(Size), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, Utf8.data(), static_cast<int>(Utf8.size()), Out.data(), Size);
  return Out;
}

// One argument quoted for the CRT / CommandLineToArgvW splitting rules.
std::wstring QuoteArgument(const std::wstring& Argument) {
  if (!Argument.empty() && Argument.find_first_of(L" \t\n\v\"") == std::wstring::npos) {
    return Argument;
  }
  std::wstring Out = L"\"";
  for (size_t Index = 0;; ++Index) {
    size_t Backslashes = 0;
    while (Index < Argument.size() && Argument[Index] == L'\\') {
      ++Index;
      ++Backslashes;
    }
    if (Index == Argument.size()) {
      Out.append(Backslashes * 2, L'\\');
      break;
    }
    if (Argument[Index] == L'"') {
      Out.append(Backslashes * 2 + 1, L'\\');
    } else {
      Out.append(Backslashes, L'\\');
    }
    Out.push_back(Argument[Index]);
  }
  Out.push_back(L'"');
  return Out;
}

// Runs the CLI with the UTF-8 arguments as a WIDE command line (so no code page is involved on our
// side); its stdout and stderr go to LogPath. Returns the exit code, or -1 if it could not start.
int RunCli(const std::vector<std::string>& Arguments, const std::string& LogPath) {
  std::wstring Exe = Utf8ToWide(DSIG_CLI_PATH);
  std::replace(Exe.begin(), Exe.end(), L'/', L'\\');
  std::wstring Line = QuoteArgument(Exe);
  for (const std::string& Argument : Arguments) {
    Line += L' ';
    Line += QuoteArgument(Utf8ToWide(Argument));
  }
  SECURITY_ATTRIBUTES Inherit{};
  Inherit.nLength = sizeof(Inherit);
  Inherit.bInheritHandle = TRUE;
  const HANDLE Log = CreateFileW(Utf8ToWide(LogPath).c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 &Inherit, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (Log == INVALID_HANDLE_VALUE) {
    return -1;
  }
  STARTUPINFOW Startup{};
  Startup.cb = sizeof(Startup);
  Startup.dwFlags = STARTF_USESTDHANDLES;
  Startup.hStdInput = nullptr;
  Startup.hStdOutput = Log;
  Startup.hStdError = Log;
  PROCESS_INFORMATION Process{};
  std::vector<wchar_t> Mutable(Line.begin(), Line.end());
  Mutable.push_back(L'\0');
  if (!CreateProcessW(Exe.c_str(), Mutable.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr,
                      &Startup, &Process)) {
    CloseHandle(Log);
    return -1;
  }
  WaitForSingleObject(Process.hProcess, 300000);
  DWORD Code = 0;
  GetExitCodeProcess(Process.hProcess, &Code);
  CloseHandle(Process.hThread);
  CloseHandle(Process.hProcess);
  CloseHandle(Log);
  return static_cast<int>(Code);
}
#else
// POSIX: argv bytes are passed through unchanged, so there is no conversion to test; the CLI checks
// that do not depend on the platform still run.
int RunCli(const std::vector<std::string>& Arguments, const std::string& LogPath) {
  std::string Command = "'" DSIG_CLI_PATH "'";
  for (const std::string& Argument : Arguments) {
    std::string Quoted = "'";
    for (const char Ch : Argument) {
      Quoted += Ch == '\'' ? std::string("'\\''") : std::string(1, Ch);
    }
    Command += " " + Quoted + "'";
  }
  Command += " >'" + LogPath + "' 2>&1";
  const int Status = std::system(Command.c_str());
  if (Status == -1) {
    return -1;
  }
  return (Status >> 8) & 0xff;  // WEXITSTATUS without <sys/wait.h>
}
#endif
#endif

void TestUnicodePaths() {
  DSig::Test::Suite("unicode-paths");
  const std::string Base = DSig::Test::ScratchDir("foundation-unicode");
  // A directory name no ANSI code page holds: Latin-1, Cyrillic, Japanese, an astral-plane character
  // and a space ("dsig-üñî-дсиг-テスト-📁 x").
  const std::string Dir = Join(Base, "dsig-\xc3\xbc\xc3\xb1\xc3\xae-\xd0\xb4\xd1\x81\xd0\xb8\xd0\xb3-"
                                     "\xe3\x83\x86\xe3\x82\xb9\xe3\x83\x88-\xf0\x9f\x93\x81 x");
  std::error_code Error;
  fs::create_directories(Utf8ToPath(Dir), Error);
  CHECK(Exists(Dir));
  FixturePair Pair = BuildFoundationFixtureIn(Dir, "m\xc3\xa4" "in.sqlite", "d\xc3\xaf" "ff.sqlite");
  CHECK(Pair.Ok);
  if (!Pair.Ok) {
    DSig::Test::RemoveScratchDir(Base);
    return;
  }
  CHECK(Exists(Pair.Main) && Exists(Pair.Diff));
  {
    DiffDatabase Db;
    Db.Open(Pair.Main, Pair.Diff);
    CHECK(Db.TableExists("main", "functions") && Db.TableExists("diff", "functions"));
  }
  DiffArgs Args;
  Args.Db1 = Pair.Main;
  Args.Db2 = Pair.Diff;
  Args.Out = Join(Dir, "\xe3\x83\xaf out.diaphora");
  Args.SnapshotDir = Join(Dir, "sn\xc3\xa4" "ps");
  Args.TracePath = Join(Args.SnapshotDir, "tr\xc3\xa4" "ce.jsonl");
  Args.Quiet = true;
  Args.AllowSqliteMismatch = true;
  const DiffOutcome Outcome = RunDiff(Args);
  CHECK(Outcome.Status == DiffStatus::Ok);
  if (Outcome.Status != DiffStatus::Ok) {
    DSig::Test::Note("RunDiff: " + Outcome.Message);
  }
  CHECK(Exists(Args.Out) && Exists(Args.TracePath) && Exists(Join(Args.SnapshotDir, "index.json")));
  const DSig::Test::ResultsFile File = DSig::Test::ReadResultsFile(Args.Out);
  CHECK(File.Error.empty());
  CHECK(File.Config.size() == 1 && File.Config[0][0] == Args.Db1 && File.Config[0][1] == Args.Db2);
  const std::vector<IndexRow> Index = ReadIndex(Args.SnapshotDir);
  CHECK(!Index.empty());
  for (const IndexRow& Row : Index) {
    if (Row.Point != "before:cleanup:3655:1" || !Row.File) {
      continue;
    }
    CHECK_TEXT_EQ(ReadSnapshot(Join(Args.SnapshotDir, *Row.File)).Point, Row.Point);
    DiffArgs Replay;  // a replay reads and writes snapshots through UTF-8 paths too
    Replay.Db1 = Pair.Main;
    Replay.Db2 = Pair.Diff;
    Replay.ReplayPath = Join(Args.SnapshotDir, *Row.File);
    Replay.ReplayStage = "cleanup:3655:1";
    Replay.SnapshotOut = Join(Dir, "\xc3\xa4" "fter.json");
    Replay.Quiet = true;
    CHECK(RunDiff(Replay).Status == DiffStatus::Ok);
    CHECK_TEXT_EQ(ReadSnapshot(Replay.SnapshotOut).Point, "after:cleanup:3655:1");
  }

#ifdef _WIN32
  // UNC: the same files through the local administrative share, \\localhost\<drive>$\...
  if (Dir.size() > 2 && Dir[1] == ':') {
    std::string Rest = Dir.substr(2);
    std::replace(Rest.begin(), Rest.end(), '/', '\\');
    const std::string UncDir = std::string("\\\\localhost\\") + Dir[0] + "$" + Rest;
    const std::string UncMain = Join(UncDir, "m\xc3\xa4" "in.sqlite");
    const std::string UncDiff = Join(UncDir, "d\xc3\xaf" "ff.sqlite");
    if (Exists(UncMain)) {
      DiffDatabase Db;
      bool Opened = true;
      try {
        Db.Open(UncMain, UncDiff);
      } catch (const std::exception& Failure) {
        Opened = false;
        DSig::Test::Note(std::string("UNC open: ") + Failure.what());
      }
      CHECK(Opened);
      CHECK(Opened && Db.TableExists("main", "functions") && Db.TableExists("diff", "functions"));
      Db.Close();
      DiffArgs Unc = Args;
      Unc.Db1 = UncMain;
      Unc.Db2 = UncDiff;
      Unc.Out = Join(UncDir, "unc.diaphora");
      Unc.SnapshotDir = Join(UncDir, "unc-snaps");
      Unc.TracePath = Join(Unc.SnapshotDir, "trace.jsonl");
      const DiffOutcome UncOutcome = RunDiff(Unc);
      CHECK(UncOutcome.Status == DiffStatus::Ok);
      if (UncOutcome.Status != DiffStatus::Ok) {
        DSig::Test::Note("RunDiff over UNC: " + UncOutcome.Message);
      }
      CHECK(Exists(Join(Dir, "unc.diaphora")) && Exists(Join(Join(Dir, "unc-snaps"), "index.json")));
      // the URI form of a UNC path (DiffDatabase::UriForPath) opens as well
      sqlite3* Handle = nullptr;
      const std::string Uri = DiffDatabase::UriForPath(UncMain);
      CHECK(Uri.rfind("file:////localhost/", 0) == 0);
      const int Code = sqlite3_open_v2(Uri.c_str(), &Handle, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, nullptr);
      CHECK(Code == SQLITE_OK &&
            sqlite3_exec(Handle, "select count(*) from functions", nullptr, nullptr, nullptr) == SQLITE_OK);
      sqlite3_close(Handle);
      DSig::Test::Note("UNC checks ran through \\\\localhost\\" + std::string(1, Dir[0]) + "$");
    } else {
      DSig::Test::Note("UNC checks not run: \\\\localhost\\" + std::string(1, Dir[0]) + "$ is not reachable");
    }
  }
#endif

#ifdef DSIG_CLI_PATH
  // The CLI binary itself, with the Unicode paths as command-line arguments (wmain /
  // CommandLineToArgvW on Windows).
  {
    const std::string Log = Join(Dir, "cli.log");
    const std::string CliOut = Join(Dir, "cli \xe2\x86\x92 out.diaphora");  // "cli → out.diaphora"
    const std::string CliSnaps = Join(Dir, "cli-sn\xc3\xa4" "ps");
    const int Code = RunCli({"diff", Pair.Main, Pair.Diff, "-o", CliOut, "--snapshot-dir", CliSnaps, "--quiet",
                             "--allow-sqlite-mismatch"},
                            Log);
    CHECK_NUM_EQ(Code, 0);
    if (Code != 0) {
      DSig::Test::Note("cli: " + ReadFile(Log));
    }
    CHECK(Exists(CliOut) && Exists(Join(CliSnaps, "index.json")));
    const DSig::Test::ResultsFile CliFile = DSig::Test::ReadResultsFile(CliOut);
    // the arguments reached the engine with every character intact
    CHECK(CliFile.Config.size() == 1 && CliFile.Config[0][0] == Pair.Main && CliFile.Config[0][1] == Pair.Diff);
    // a refused input through the CLI: exit 4, naming the table
    FixturePair Broken = BuildFoundationFixtureIn(Dir, "br\xc3\xb6" "ken-main.sqlite", "br\xc3\xb6" "ken-diff.sqlite",
                                                  "drop table constants;\n");
    CHECK(Broken.Ok);
    CHECK_NUM_EQ(RunCli({"diff", Broken.Main, Broken.Diff, "-o", Join(Dir, "broken.diaphora"), "--quiet"}, Log), 4);
    CHECK(ReadFile(Log).find("main.constants: table is missing") != std::string::npos);
    // --help documents that DIAPHORA_* variables are ignored (orchestrator decision R0 (e))
    CHECK_NUM_EQ(RunCli({"--help"}, Log), 0);
    CHECK(ReadFile(Log).find("DIAPHORA_* variables are deliberately ignored") != std::string::npos);
    DSig::Test::Note("CLI ran with Unicode path arguments (exit 0), a refused input (exit 4) and --help");
#ifdef _WIN32
    if (Dir.size() > 2 && Dir[1] == ':') {
      std::string Rest = Dir.substr(2);
      std::replace(Rest.begin(), Rest.end(), '/', '\\');
      const std::string UncDir = std::string("\\\\localhost\\") + Dir[0] + "$" + Rest;
      if (Exists(Join(UncDir, "m\xc3\xa4" "in.sqlite"))) {
        const int UncCode = RunCli({"diff", Join(UncDir, "m\xc3\xa4" "in.sqlite"), Join(UncDir, "d\xc3\xaf" "ff.sqlite"),
                                    "-o", Join(UncDir, "cli-unc.diaphora"), "--quiet", "--allow-sqlite-mismatch"},
                                   Log);
        CHECK_NUM_EQ(UncCode, 0);
        CHECK(Exists(Join(Dir, "cli-unc.diaphora")));
      }
    }
#endif
  }
#endif
  DSig::Test::RemoveScratchDir(Base);
}

// ---------------------------------------------------------------------------------------------
// Lane F1: reading an input never creates files beside it (Database.cpp InputFileName)

bool WalModeHeader(const std::string& Utf8Path) {
  const std::string Bytes = ReadFile(Utf8Path).substr(0, 20);
  return Bytes.size() == 20 && Bytes.compare(0, 15, "SQLite format 3") == 0 && Bytes[18] == 2 && Bytes[19] == 2;
}

bool NoSidecars(const std::string& Db) {
  return !Exists(Db + "-wal") && !Exists(Db + "-shm") && !Exists(Db + "-journal");
}

uintmax_t SizeOf(const std::string& Utf8Path) {
  std::error_code Error;
  const uintmax_t Size = fs::file_size(Utf8ToPath(Utf8Path), Error);
  return Error ? static_cast<uintmax_t>(-1) : Size;
}

void TestReadOnlyInputs() {
  DSig::Test::Suite("read-only inputs: no -wal/-shm beside a WAL-mode input, committed -wal frames still read");
  const std::string Base = DSig::Test::ScratchDir("foundation-readonly");
  // A non-ASCII directory, so the immutable URI carries UTF-8 through as well.
  const std::string Dir = Join(Base, "inp\xc3\xbcts \xd0\xb4 #1%");
  std::error_code Error;
  fs::create_directories(Utf8ToPath(Dir), Error);
  FixturePair Pair = BuildFoundationFixtureIn(Dir, "m\xc3\xa4in.sqlite", "diff.sqlite");
  CHECK(Pair.Ok);
  if (!Pair.Ok) {
    DSig::Test::RemoveScratchDir(Base);
    return;
  }
  // Like a finished export: WAL mode in the header and no sidecar on disk.
  CHECK(WalModeHeader(Pair.Main) && WalModeHeader(Pair.Diff));
  CHECK(NoSidecars(Pair.Main) && NoSidecars(Pair.Diff));
  const std::string MainSha = Sha256Of(ReadFile(Pair.Main));
  const std::string DiffSha = Sha256Of(ReadFile(Pair.Diff));

  {
    DiffDatabase Db;
    Db.Open(Pair.Main, Pair.Diff);
    CHECK(Db.TableExists("main", "functions") && Db.TableExists("diff", "functions"));
    Statement Count = Db.Prepare("select (select count(*) from main.functions), (select count(*) from diff.functions)");
    CHECK(Count.Step() && Count.Int(0) > 0 && Count.Int(1) > 0);
    CHECK(NoSidecars(Pair.Main) && NoSidecars(Pair.Diff));  // not even while the connection is open
  }
  DiffArgs Args;
  Args.Db1 = Pair.Main;
  Args.Db2 = Pair.Diff;
  Args.Out = Join(Dir, "out.diaphora");
  Args.Quiet = true;
  Args.AllowSqliteMismatch = true;
  const DiffOutcome Outcome = RunDiff(Args);
  CHECK(Outcome.Status == DiffStatus::Ok);
  if (Outcome.Status != DiffStatus::Ok) {
    DSig::Test::Note("RunDiff: " + Outcome.Message);
  }
  CHECK(NoSidecars(Pair.Main));
  CHECK(NoSidecars(Pair.Diff));
  CHECK_TEXT_EQ(Sha256Of(ReadFile(Pair.Main)), MainSha);
  CHECK_TEXT_EQ(Sha256Of(ReadFile(Pair.Diff)), DiffSha);
  {
    const DSig::Test::ResultsFile File = DSig::Test::ReadResultsFile(Args.Out);  // OpenSingle on a results file
    CHECK(File.Error.empty());
    CHECK(NoSidecars(Args.Out));
  }

  // Committed frames still in the -wal are read: that input keeps the ordinary read-only open.
#ifdef SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE
  {
    const std::string Wal = Join(Dir, "committed.sqlite");
    CHECK(DSig::Test::BuildFixtureDbFromText(ReadFile(DSig::Test::TestDataDir() + "/fixtures/foundation/main.sql"),
                                             Wal)
              .empty());
    sqlite3* Writer = nullptr;
    CHECK(sqlite3_open_v2(Wal.c_str(), &Writer, SQLITE_OPEN_READWRITE, nullptr) == SQLITE_OK);
    int Disabled = 0;
    sqlite3_db_config(Writer, SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, 1, &Disabled);
    CHECK(sqlite3_exec(Writer, "update functions set name = 'only_in_the_wal' where id = (select min(id) from functions)",
                       nullptr, nullptr, nullptr) == SQLITE_OK);
    sqlite3_close(Writer);
    CHECK(SizeOf(Wal + "-wal") > 0 && SizeOf(Wal + "-wal") != static_cast<uintmax_t>(-1));
    DiffDatabase Db;
    Db.OpenSingle(Wal);
    Statement Name = Db.Prepare("select name from functions order by id limit 1");
    CHECK(Name.Step() && Name.Text(0) == "only_in_the_wal");
    Db.Close();
    DiffDatabase Pairing;  // the attached side follows the same rule
    Pairing.Open(Pair.Main, Wal);
    Statement DiffName = Pairing.Prepare("select name from diff.functions order by id limit 1");
    CHECK(DiffName.Step() && DiffName.Text(0) == "only_in_the_wal");
  }
#endif

  // A zero-byte -wal (a reader of the old code left one): still read immutable, nothing added.
  {
    const std::string Empty = Join(Dir, "empty-wal.sqlite");
    CHECK(DSig::Test::BuildFixtureDbFromText(ReadFile(DSig::Test::TestDataDir() + "/fixtures/foundation/diff.sql"),
                                             Empty)
              .empty());
    WriteText(Empty + "-wal", "");
    const std::string Sha = Sha256Of(ReadFile(Empty));
    {
      DiffDatabase Db;
      Db.OpenSingle(Empty);
      CHECK(Db.TableExists("main", "functions"));
    }
    CHECK(!Exists(Empty + "-shm"));
    CHECK_NUM_EQ(SizeOf(Empty + "-wal"), 0);
    CHECK_TEXT_EQ(Sha256Of(ReadFile(Empty)), Sha);
  }

  // A non-empty -journal beside a rollback-journal database is never read immutable (that would read
  // a possibly half-written file): SQLite refuses the hot journal on a read-only connection, and the
  // journal is left as it was.
  {
    const std::string Rollback = Join(Dir, "rollback.sqlite");
    CHECK(DSig::Test::BuildFixtureDbFromText(ReadFile(DSig::Test::TestDataDir() + "/fixtures/foundation/diff.sql"),
                                             Rollback, false)
              .empty());
    CHECK(!WalModeHeader(Rollback));
    WriteText(Rollback + "-journal", "not a journal header, but a non-zero first byte");
    const std::string JournalSha = Sha256Of(ReadFile(Rollback + "-journal"));
    bool Refused = false;
    try {
      DiffDatabase Db;
      Db.OpenSingle(Rollback);
    } catch (const IoFailure&) {
      Refused = true;
    }
    CHECK(Refused);
    CHECK_TEXT_EQ(Sha256Of(ReadFile(Rollback + "-journal")), JournalSha);
  }

#ifdef _WIN32
  // UNC: the same inputs through the local administrative share, \\localhost\<drive>$\...
  if (Dir.size() > 2 && Dir[1] == ':') {
    std::string Rest = Dir.substr(2);
    std::replace(Rest.begin(), Rest.end(), '/', '\\');
    const std::string UncDir = std::string("\\\\localhost\\") + Dir[0] + "$" + Rest;
    const std::string UncMain = Join(UncDir, "m\xc3\xa4in.sqlite");
    const std::string UncDiff = Join(UncDir, "diff.sqlite");
    if (Exists(UncMain)) {
      bool Opened = true;
      try {
        DiffDatabase Db;
        Db.Open(UncMain, UncDiff);
        Opened = Db.TableExists("main", "functions") && Db.TableExists("diff", "functions");
      } catch (const std::exception& Failure) {
        Opened = false;
        DSig::Test::Note(std::string("UNC open: ") + Failure.what());
      }
      CHECK(Opened);
      DiffArgs Unc = Args;
      Unc.Db1 = UncMain;
      Unc.Db2 = UncDiff;
      Unc.Out = Join(UncDir, "unc.diaphora");
      CHECK(RunDiff(Unc).Status == DiffStatus::Ok);
      CHECK(NoSidecars(Pair.Main) && NoSidecars(Pair.Diff));
      DSig::Test::Note("UNC read-only inputs checked through \\\\localhost\\" + std::string(1, Dir[0]) + "$");
    } else {
      DSig::Test::Note("UNC checks not run: \\\\localhost\\" + std::string(1, Dir[0]) + "$ is not reachable");
    }
  }
#endif
  DSig::Test::RemoveScratchDir(Base);
}

// ---------------------------------------------------------------------------------------------
// Corpus: ingest census (plan §4 L0), skipped without the corpus

std::string CensusCell(const IntColumn& Column, uint32_t Row, bool& Unrepresentable) {
  if (Column.Null(Row)) {
    return "N";
  }
  if (Column.NotInteger[Row]) {
    Unrepresentable = true;
  }
  return "I" + std::to_string(Column.Value[Row]);
}

std::string CensusCell(const TextColumn& Column, uint32_t Row) {
  if (Column.Null(Row)) {
    return "N";
  }
  const std::string_view Bytes = Column.View(Row);
  return "S" + std::to_string(Bytes.size()) + ":" + std::string(Bytes);
}

std::string CensusReal(double Value, bool Null) { return Null ? std::string("N") : "R" + RatioBitsHex(Value); }

void TestCorpusIngestCensus() {
  if (!DSig::Test::CorpusRoot()) {
    DSig::Test::Skip("corpus-ingest-census", "DSIG_CORPUS_ROOT not set");
    return;
  }
  DSig::Test::Suite("corpus-ingest-census");
  // The literal values of plan §4 L0, independent of the generated census.
  struct PlanValues {
    const char* Id;
    long long Rows, NullPseudocode, NameNeMangled;
  };
  const PlanValues Plan[] = {{"ls-old", 304, 106, 0},          {"ls", 318, 113, 0},
                             {"userenv-9168-pdb", 643, 1, 393}, {"userenv-9278-nopdb", 628, 1, 0},
                             {"userenv-9278-pdb", 663, 1, 411}, {"sechost-9168-pdb", 1442, 1, 772},
                             {"sechost-9444-nopdb", 1419, 5, 0}};
  CHECK_NUM_EQ(std::size(kCensusExports), std::size(Plan));
  for (size_t Index = 0; Index < std::size(Plan) && Index < std::size(kCensusExports); ++Index) {
    CHECK_TEXT_EQ(kCensusExports[Index].Id, Plan[Index].Id);
    CHECK_NUM_EQ(kCensusExports[Index].Rows, Plan[Index].Rows);
    CHECK_NUM_EQ(kCensusExports[Index].NullPseudocode, Plan[Index].NullPseudocode);
    CHECK_NUM_EQ(kCensusExports[Index].NameNeMangled, Plan[Index].NameNeMangled);
    CHECK_NUM_EQ(kCensusExports[Index].ProgramRows, 1);
    CHECK_TEXT_EQ(kCensusExports[Index].Processor, "pc64");
    CHECK_TEXT_EQ(kCensusExports[Index].Version, "3.4");
  }
  for (const CensusExport& E : kCensusExports) {
    if (!DSig::Test::ExportAvailable(E.Id)) {
      DSig::Test::Skip(E.Id, "export missing");
      continue;
    }
    const std::string Path = DSig::Test::ExportPath(E.Id);
    bool HashOk = false;
    const std::string Sha = DSig::Sha256::FileHex(Path, HashOk);
    CHECK(HashOk);
    CHECK_TEXT_EQ(Sha, E.Sha256);  // equal to the census (which asserted the manifest at generation)
    const std::string ManifestPath = Join(DSig::Test::OracleDir(), "manifest.json");
    if (Exists(ManifestPath)) {  // and to the oracle manifest itself
      const JsonValue Manifest = JsonParse(ReadFile(ManifestPath));
      const JsonValue* Entry = Manifest.At("exports").Find(E.Id);
      CHECK(Entry != nullptr);
      if (Entry != nullptr) {
        CHECK_TEXT_EQ(Sha, Entry->At("sqlite_sha256").AsString());
      }
    }

    DiffDatabase Db;
    Db.OpenSingle(Path);
    Interners Ids;
    ExportData Data;
    IngestExport(Db, Side::Main, Ids, Data);
    CHECK(Data.Problems.empty());
    const FunctionTable& T = Data.Functions;
    CHECK_NUM_EQ(T.Count(), E.Rows);
    long long NullPseudo = 0;
    long long NameNeMangled = 0;
    for (uint32_t Row = 0; Row < T.Count(); ++Row) {
      NullPseudo += T.Pseudocode.Null(Row) ? 1 : 0;
      if (!T.Name.Null(Row) && !T.MangledFunction.Null(Row) && T.Name.View(Row) != T.MangledFunction.View(Row)) {
        ++NameNeMangled;  // SQL `name != mangled_function` skips NULLs
      }
    }
    CHECK_NUM_EQ(NullPseudo, E.NullPseudocode);
    CHECK_NUM_EQ(NameNeMangled, E.NameNeMangled);
    CHECK_NUM_EQ(Data.Tables.Program.size(), E.ProgramRows);
    if (!Data.Tables.Program.empty()) {
      CHECK(Data.Tables.Program[0].Processor.TextOrNull() == std::string_view(E.Processor));
    }
    CHECK(!Data.Tables.Version.empty() && Data.Tables.Version[0].TextOrNull() == std::string_view(E.Version));
    CHECK_NUM_EQ(Data.Tables.IndexCount, E.IndexCount);
    CHECK(Data.Tables.HasStat1);
    for (const CensusTable& Table : E.Tables) {
      const TableInfo* Info = Data.Tables.Find(Table.Name);
      CHECK(Info != nullptr);
      if (Info != nullptr) {
        CHECK_NUM_EQ(Info->Present ? 1 : 0, Table.Present);
        CHECK_NUM_EQ(Info->Rows, Table.Rows);
      }
    }
    // every one of the 49 columns, byte for byte and NULL for NULL (08 §9.1)
    for (const CensusColumn& Column : E.Columns) {
      DSig::Sha256 Hash;
      long long Nulls = 0;
      bool Unrepresentable = false;
      const std::string_view Name = Column.Name;
      for (uint32_t Row = 0; Row < T.Count(); ++Row) {
        std::string Cell;
        if (const IntColumn* I = T.IntColumnNamed(Name)) {
          Nulls += I->Null(Row) ? 1 : 0;
          Cell = CensusCell(*I, Row, Unrepresentable);
        } else if (const TextColumn* X = T.TextColumnNamed(Name)) {
          Nulls += X->Null(Row) ? 1 : 0;
          Cell = CensusCell(*X, Row);
        } else if (const RealColumn* R = T.RealColumnNamed(Name)) {
          Nulls += R->Null(Row) ? 1 : 0;
          Unrepresentable = Unrepresentable || (!R->Null(Row) && R->NotReal[Row] != 0);
          Cell = CensusReal(R->Value[Row], R->Null(Row));
        }
        Cell += '\x1e';
        Hash.Update(Cell);
      }
      CHECK(!Unrepresentable);
      CHECK_NUM_EQ(Nulls, Column.Nulls);
      const std::string Digest = Hash.FinishHex();
      if (Digest != Column.Sha256) {
        DSig::Test::Note(std::string(E.Id) + "." + Column.Name + " differs");
      }
      CHECK_TEXT_EQ(Digest, Column.Sha256);
    }
    DSig::Sha256 Md;
    DSig::Sha256 Address;
    for (uint32_t Row = 0; Row < T.Count(); ++Row) {
      Md.Update(CensusReal(T.MdSqlReal[Row], T.MdSqlNull[Row] != 0) + '\x1e');
      Address.Update(CensusReal(T.AddressSqlReal[Row], T.AddressSqlNull[Row] != 0) + '\x1e');
    }
    CHECK_TEXT_EQ(Md.FinishHex(), E.MdSqlRealSha256);
    CHECK_TEXT_EQ(Address.FinishHex(), E.AddressSqlRealSha256);
  }
}

// ---------------------------------------------------------------------------------------------
// SQLite 3.51.1 only: the Path A row-sequence census (plan §2.6) and the find_same_name plan

std::string StatementCell(const Statement& Stmt, int Column) {
  switch (Stmt.Type(Column)) {
    case SqlType::Null:
      return "N";
    case SqlType::Integer:
      return "I" + std::to_string(Stmt.Int(Column));
    case SqlType::Real:
      return "R" + RatioBitsHex(Stmt.Real(Column));
    case SqlType::Text:
    case SqlType::Blob: {
      const std::string_view Bytes = Stmt.Text(Column);
      return "S" + std::to_string(Bytes.size()) + ":" + std::string(Bytes);
    }
  }
  return "?";
}

void TestRowSequenceCensus() {
  if (!DSig::Test::CorpusRoot()) {
    DSig::Test::Skip("row-sequence-census", "DSIG_CORPUS_ROOT not set");
    return;
  }
  if (!DSig::Test::OracleSqlite()) {
    DSig::Test::Skip("row-sequence-census", "SQLite " + DiffDatabase::LibVersion() + " is not the oracle's 3.51.1");
    return;
  }
  // Orchestrator decision R0 (a): DSIG_CORPUS_ROOT set but the exports absent is a skip, not a failure.
  bool AnyPair = false;
  for (const CensusSequence& Seq : kCensusSequences) {
    AnyPair = AnyPair || (DSig::Test::ExportAvailable(Seq.Main) && DSig::Test::ExportAvailable(Seq.Diff));
  }
  if (!AnyPair) {
    DSig::Test::Skip("row-sequence-census", "no oracle export pair under DSIG_CORPUS_ROOT");
    return;
  }
  DSig::Test::Suite("row-sequence-census");
  const bool Long = DSig::Test::GetEnv("DSIG_CENSUS_LONG").value_or("") == "1";
  std::string OpenPair;
  std::unique_ptr<DiffSession> Session;
  int Ran = 0;
  int SkippedLong = 0;
  for (const CensusSequence& Seq : kCensusSequences) {
    if (Seq.Long != 0 && !Long) {
      ++SkippedLong;
      continue;
    }
    if (!DSig::Test::ExportAvailable(Seq.Main) || !DSig::Test::ExportAvailable(Seq.Diff)) {
      continue;
    }
    if (OpenPair != Seq.Pair) {
      Session = std::make_unique<DiffSession>();
      Session->Open(DSig::Test::ExportPath(Seq.Main), DSig::Test::ExportPath(Seq.Diff));
      OpenPair = Seq.Pair;
    }
    DiffSession& S = *Session;
    DSig::Sha256 Hash;
    long long Rows = 0;
    const std::string_view Query = Seq.Query;
    if (Query.rfind("heuristic:", 0) == 0) {
      // Path A through SqlRowSource: (ea, ea2, description) of every row in SQLite's order
      const int Id = std::stoi(std::string(Query.substr(10)));
      SqlRowSource Source(S, ApplyPostfix(Heuristic(Id).Sql, ""));
      HeuristicRow Row;
      while (Source.Next(Row)) {
        const std::string_view Ea = S.Ids().AddrText(Row.Ea1);
        const std::string_view Ea2 = S.Ids().AddrText(Row.Ea2);
        const std::string_view Desc = S.Ids().DescText(Row.Desc);
        Hash.Update("S" + std::to_string(Ea.size()) + ":" + std::string(Ea) + '\x1f' + "S" +
                    std::to_string(Ea2.size()) + ":" + std::string(Ea2) + '\x1f' + "S" + std::to_string(Desc.size()) +
                    ":" + std::string(Desc) + '\x1e');
        ++Rows;
      }
    } else {
      Statement Stmt = S.Db().Prepare(StageSql(Query).Sql);
      std::vector<int> Columns;
      const int Ea = Stmt.FindColumn("ea");
      const int Ea2 = Stmt.FindColumn("ea2");
      const int Desc = Stmt.FindColumn("description");
      if (Ea >= 0 && Ea2 >= 0 && Desc >= 0) {
        Columns = {Ea, Ea2, Desc};
      } else {
        for (int Column = 0; Column < Stmt.ColumnCount(); ++Column) {
          Columns.push_back(Column);
        }
      }
      while (Stmt.Step()) {
        std::string Line;
        for (size_t Index = 0; Index < Columns.size(); ++Index) {
          if (Index > 0) {
            Line += '\x1f';
          }
          Line += StatementCell(Stmt, Columns[Index]);
        }
        Line += '\x1e';
        Hash.Update(Line);
        ++Rows;
      }
    }
    const std::string Digest = Hash.FinishHex();
    const bool Same = Rows == Seq.Rows && Digest == Seq.Sha256;
    CHECK(Same);
    if (!Same) {
      DSig::Test::Note(std::string(Seq.Pair) + " " + Seq.Query + ": " + std::to_string(Rows) + " rows (census " +
                       std::to_string(Seq.Rows) + ")");
    }
    ++Ran;
  }
  DSig::Test::Note(std::to_string(Ran) + " sequences compared, " + std::to_string(SkippedLong) +
                   " long ones skipped (set DSIG_CENSUS_LONG=1 to run them)");
  CHECK(Ran > 0);
}

void TestSameNamePlan() {
  if (!DSig::Test::CorpusRoot() || !DSig::Test::OracleSqlite()) {
    DSig::Test::Skip("same-name-plan", "needs DSIG_CORPUS_ROOT and SQLite 3.51.1");
    return;
  }
  // Orchestrator decision R0 (a): DSIG_CORPUS_ROOT set but the exports absent is a skip, not a failure.
  size_t Available = 0;
  for (const CensusPlan& Plan : kCensusSameNamePlans) {
    Available += DSig::Test::ExportAvailable(Plan.Main) && DSig::Test::ExportAvailable(Plan.Diff) ? 1 : 0;
  }
  if (Available == 0) {
    DSig::Test::Skip("same-name-plan", "no oracle export pair under DSIG_CORPUS_ROOT");
    return;
  }
  DSig::Test::Suite("same-name-plan");
  // 02 Appendix C: SCAN f > MULTI-INDEX OR > INDEX 1 > idx_3 > INDEX 2 > idx_2 > TEMP B-TREE FOR DISTINCT
  const std::vector<std::string> Expected = {"SCAN f",
                                             "MULTI-INDEX OR",
                                             "INDEX 1",
                                             "SEARCH df USING INDEX idx_3 (mangled_function=?)",
                                             "INDEX 2",
                                             "SEARCH df USING INDEX idx_2 (name=?)",
                                             "USE TEMP B-TREE FOR DISTINCT"};
  int Checked = 0;
  for (const CensusPlan& Plan : kCensusSameNamePlans) {
    if (!DSig::Test::ExportAvailable(Plan.Main) || !DSig::Test::ExportAvailable(Plan.Diff)) {
      continue;
    }
    DiffDatabase Db;
    Db.Open(DSig::Test::ExportPath(Plan.Main), DSig::Test::ExportPath(Plan.Diff));
    std::vector<std::string> Details;
    for (const PlanRow& Row : Db.ExplainQueryPlan(kSqlSameName)) {
      Details.push_back(Row.Detail);
    }
    std::vector<std::string> Census;
    for (int Index = 0; Index < Plan.Count; ++Index) {
      Census.push_back(Plan.Detail[Index]);
    }
    CHECK(Details == Census);
    CHECK(Details == Expected);
    ++Checked;
  }
  if (Available == std::size(kCensusSameNamePlans)) {
    CHECK_NUM_EQ(Checked, 4);  // the 4 pairs of 02 Appendix C
  } else {
    DSig::Test::Note(std::to_string(Available) + " of " + std::to_string(std::size(kCensusSameNamePlans)) +
                     " plan pairs available");
    CHECK_NUM_EQ(Checked, Available);
  }
}

// ---------------------------------------------------------------------------------------------
// Corpus: `diff ls-old ls` writes Diaphora's exact DDL (G0), results comparison

void TestCorpusDiffDdl() {
  if (!DSig::Test::ExportAvailable("ls-old") || !DSig::Test::ExportAvailable("ls") ||
      !Exists(DSig::Test::OracleResultsPath("ls-old_vs_ls"))) {
    DSig::Test::Skip("corpus-diff-ddl", "ls-old / ls exports or the oracle results are missing");
    return;
  }
  DSig::Test::Suite("corpus-diff-ddl");
  const std::string Dir = DSig::Test::ScratchDir("foundation-corpus");
  DiffArgs Args;
  Args.Db1 = DSig::Test::ExportPath("ls-old");
  Args.Db2 = DSig::Test::ExportPath("ls");
  Args.Out = Join(Dir, "ls-old_vs_ls.diaphora");
  Args.Quiet = true;
  const DiffOutcome Outcome = RunDiff(Args);
  CHECK(Outcome.Status == DiffStatus::Ok);
  if (Outcome.Status != DiffStatus::Ok) {
    DSig::Test::Note(Outcome.Message);
  }
  const DSig::Test::ResultsFile Native = DSig::Test::ReadResultsFile(Args.Out);
  const DSig::Test::ResultsFile Oracle = DSig::Test::ReadResultsFile(DSig::Test::OracleResultsPath("ls-old_vs_ls"));
  CHECK(Native.Error.empty() && Oracle.Error.empty());
  CHECK(Native.Schema == Oracle.Schema);  // sqlite_master.sql text equal to the oracle file's
  CHECK(Oracle.Schema == DiaphoraDdl());
  CHECK(Native.AllText && Oracle.AllText);
  CHECK(Native.Config.size() == 1 && Native.Config[0][2] == Oracle.Config[0][2]);
  // comparison self-checks on the oracle (run1 vs run1, run1 vs run2: determinism.json says equal)
  const DSig::Test::CompareReport Self = DSig::Test::CompareResults(Oracle, Oracle);
  CHECK(Self.DdlEqual && Self.L1Equal && Self.L2Equal);
  if (Exists(DSig::Test::OracleResultsPath("ls-old_vs_ls", 2))) {
    const DSig::Test::ResultsFile Run2 = DSig::Test::ReadResultsFile(DSig::Test::OracleResultsPath("ls-old_vs_ls", 2));
    const DSig::Test::CompareReport Runs = DSig::Test::CompareResults(Oracle, Run2);
    CHECK(Runs.L2Equal);
  }
  CHECK_NUM_EQ(Oracle.Results.size(), 278);  // 139 + 113 + 26 (plan §1.5)
  // a planted change is classified: same multiset, different order breaks L2 only
  DSig::Test::ResultsFile Swapped = Oracle;
  std::swap(Swapped.Results[0], Swapped.Results[1]);
  const DSig::Test::CompareReport Order = DSig::Test::CompareResults(Oracle, Swapped);
  CHECK(Order.L1Equal && !Order.L2Equal);
  DSig::Test::ResultsFile Dropped = Oracle;
  Dropped.Results.pop_back();
  CHECK(!DSig::Test::CompareResults(Oracle, Dropped).L1Equal);
  DSig::Test::RemoveScratchDir(Dir);
}

// ---------------------------------------------------------------------------------------------
// Lane R0: the oracle instrumentation (tools/parity/oracle_trace.py, lane L0b) is the reference for the
// trace and snapshot conventions, because hours-long oracle captures already exist in its format.
// Checked on the finished ls-old_vs_ls capture (skipped without it):
//   * index.json and every snapshot round-trip byte for byte through the native reader and writer
//     (and, modulo the producer string, the native writer produces the oracle's bytes);
//   * the capture's file names, seq and iteration values follow the rules the native engine applies;
//   * every trace event, re-emitted through TraceSink, reproduces the oracle's line byte for byte;
//   * a native run of ls-old vs ls emits the oracle's points with the same keys, labels, flags and
//     iteration at every shared point, and S-L2-equal snapshots wherever the oracle's state is still empty.

std::vector<std::string> MemberNames(const JsonValue& Object) {
  std::vector<std::string> Names;
  for (const auto& Member : Object.Members()) {
    Names.push_back(Member.first);
  }
  return Names;
}

std::optional<std::string_view> OptionalText(const JsonValue& Value) {
  if (Value.IsNull()) {
    return std::nullopt;
  }
  return std::string_view(Value.AsString());
}

// Re-emits one oracle trace event through the native sink. False for an event it cannot express.
bool EchoTraceEvent(TraceSink& Sink, const JsonValue& Event) {
  const std::string Kind = Event.At("ev").AsString();
  const auto Ctx = [&](const JsonValue& Value) { return Value.IsNull() ? std::string_view() : std::string_view(Value.AsString()); };
  const auto Size = [&](const char* Name) { return static_cast<size_t>(Event.At(Name).AsInt64()); };
  if (Kind == "add_match") {
    static const std::map<std::string, AddMatchResult> Results = {{"appended", AddMatchResult::Appended},
                                                                  {"duplicate", AddMatchResult::Duplicate},
                                                                  {"rejected_better", AddMatchResult::RejectedBetter}};
    const auto Result = Results.find(Event.At("result").AsString());
    if (Result == Results.end() || Event.At("ea1").IsNull() || Event.At("ea2").IsNull() || Event.At("desc").IsNull()) {
      return false;
    }
    Sink.AddMatch(Ctx(Event.At("ctx")), OptionalText(Event.At("name1")), OptionalText(Event.At("name2")),
                  Event.At("ea1").AsString(), Event.At("ea2").AsString(), Event.At("desc").AsString(),
                  RatioFromBits(ParseRatioBits(Event.At("ratio_bits").AsString())), OptionalText(Event.At("chooser")),
                  Result->second);
    return true;
  }
  if (Kind == "cleanup") {
    Sink.Cleanup(static_cast<int>(Event.At("site").AsInt64()), Event.At("n").AsInt64(), Size("best"), Size("partial"),
                 Size("unreliable"));
    return true;
  }
  if (Kind == "point") {
    Sink.Point(Event.At("name").AsString(), Size("best"), Size("partial"), Size("unreliable"));
    return true;
  }
  if (Kind == "row") {
    static const std::map<std::string, RowDecision> Decisions = {
        {"nullsub", RowDecision::Nullsub},           {"has_best", RowDecision::HasBest},
        {"has_better", RowDecision::HasBetter},      {"accepted_best", RowDecision::AcceptedBest},
        {"accepted_partial", RowDecision::AcceptedPartial}, {"below_min", RowDecision::BelowMin},
        {"accepted_unreliable", RowDecision::AcceptedUnreliable}, {"raised", RowDecision::Raised}};
    const auto Decision = Decisions.find(Event.At("decision").AsString());
    if (Decision == Decisions.end() || !Event.At("ea1").IsString() || !Event.At("ea2").IsString()) {
      return false;
    }
    std::optional<double> Ratio;
    if (!Event.At("ratio_bits").IsNull()) {
      Ratio = RatioFromBits(ParseRatioBits(Event.At("ratio_bits").AsString()));
    }
    Sink.Row(Ctx(Event.At("ctx")), Event.At("ea1").AsString(), Event.At("ea2").AsString(), Decision->second, Ratio);
    return true;
  }
  return false;
}

void TestOracleConventions() {
  const std::string PairName = "ls-old_vs_ls";
  const std::string Capture = DSig::Test::TracesDir(PairName);
  if (!DSig::Test::CorpusRoot() || !Exists(Join(Capture, "index.json")) || !Exists(Join(Capture, "trace.jsonl")) ||
      !Exists(Join(Capture, "run.json"))) {
    DSig::Test::Skip("oracle-conventions", "no oracle capture " + PairName + " under DSIG_CORPUS_ROOT");
    return;
  }
  // Only a finished capture is read: a running oracle_trace.py still rewrites its index.json.
  const JsonValue Run = JsonParse(ReadFile(Join(Capture, "run.json")));
  const JsonValue* Status = Run.Find("status");
  if (Status == nullptr || !Status->IsString() || Status->AsString() != "complete") {
    DSig::Test::Skip("oracle-conventions", "the " + PairName + " capture is not complete");
    return;
  }
  DSig::Test::Suite("oracle-conventions");

  // 1. index.json and the snapshots, byte for byte
  const std::string IndexText = ReadFile(Join(Capture, "index.json"));
  CHECK_TEXT_EQ(JsonWrite(JsonParse(IndexText)) + "\n", IndexText);
  const std::vector<IndexRow> Index = ReadIndex(Capture);
  std::vector<std::string> Points;
  for (const IndexRow& Row : Index) {
    Points.push_back(Row.Point);
  }
  const std::vector<std::optional<int64_t>> Iterations = ExpectedIterations(Points);
  size_t Files = 0;
  size_t SeqOk = 0;
  size_t Named = 0;
  size_t RoundTrips = 0;
  size_t ProducerSwaps = 0;
  size_t Labels = 0;
  std::string FirstMismatch;
  std::map<std::string, JsonValue> OracleByPoint;  // parsed oracle snapshots, for part 3
  for (size_t Position = 0; Position < Index.size(); ++Position) {
    const IndexRow& Row = Index[Position];
    SeqOk += Row.Seq == static_cast<int64_t>(Position) ? 1 : 0;  // 0-based, every point counted
    if (!Row.File) {
      continue;
    }
    ++Files;
    Named += *Row.File == "snapshots/" + SnapshotFileName(Row.Seq, Row.Point) ? 1 : 0;
    const std::string Bytes = ReadFile(Join(Capture, *Row.File));
    StateSnapshot Snap;
    try {
      Snap = ParseSnapshot(Bytes);
    } catch (const std::exception& Failure) {
      DSig::Test::Note(*Row.File + ": " + Failure.what());
      continue;
    }
    if (SerializeSnapshot(Snap) + "\n" == Bytes) {
      ++RoundTrips;
    } else if (FirstMismatch.empty()) {
      FirstMismatch = *Row.File;
    }
    // modulo producer: the native producer in place of the oracle's changes only that string
    StateSnapshot Native = Snap;
    Native.Producer = std::string("dsigmatcher-") + DSIG_VERSION;
    std::string Swapped = Bytes;
    const std::string From = "\"producer\":" + JsonQuote(Snap.Producer);
    const size_t At = Swapped.find(From);
    if (At != std::string::npos) {
      Swapped.replace(At, From.size(), "\"producer\":" + JsonQuote(Native.Producer));
    }
    ProducerSwaps += SerializeSnapshot(Native) + "\n" == Swapped ? 1 : 0;
    Labels += Snap.Seq == Row.Seq && Snap.Point == Row.Point && Snap.Iteration == Iterations[Position] &&
                      Snap.Pair == PairName
                  ? 1
                  : 0;
    OracleByPoint.emplace(Row.Point, JsonParse(Bytes));
  }
  CHECK(Files > 0);
  CHECK_NUM_EQ(SeqOk, Index.size());
  CHECK_NUM_EQ(Named, Files);
  CHECK_NUM_EQ(RoundTrips, Files);
  CHECK_NUM_EQ(ProducerSwaps, Files);
  CHECK_NUM_EQ(Labels, Files);
  if (!FirstMismatch.empty()) {
    DSig::Test::Note("first snapshot that does not round-trip: " + FirstMismatch);
  }
  DSig::Test::Note(std::to_string(Files) + " oracle snapshots and index.json round-trip byte for byte");
  // the capture exercises the outer loop (06 V3: three iterations)
  CHECK(std::find(Iterations.begin(), Iterations.end(), std::optional<int64_t>(2)) != Iterations.end());

  // 2. the trace, event by event through the native sink
  {
    const std::string Scratch = DSig::Test::ScratchDir("foundation-oracle-trace");
    const std::string Echo = Join(Scratch, "echo.jsonl");
    const std::string Text = ReadFile(Join(Capture, "trace.jsonl"));
    std::map<std::string, size_t> Kinds;
    size_t Unexpressible = 0;
    {
      TraceSink Sink;
      Sink.Open(Echo, true);
      size_t Start = 0;
      while (Start < Text.size()) {
        size_t End = Text.find('\n', Start);
        if (End == std::string::npos) {
          End = Text.size();
        }
        const JsonValue Event = JsonParse(std::string_view(Text).substr(Start, End - Start));
        ++Kinds[Event.At("ev").AsString()];
        Unexpressible += EchoTraceEvent(Sink, Event) ? 0 : 1;
        Start = End + 1;
      }
      Sink.Close();
    }
    const std::string Written = ReadFile(Echo);
    CHECK_NUM_EQ(Unexpressible, 0);
    CHECK_NUM_EQ(Written.size(), Text.size());
    const bool Same = Written == Text;
    CHECK(Same);
    if (!Same) {
      size_t Line = 1;
      size_t Index2 = 0;
      while (Index2 < Written.size() && Index2 < Text.size() && Written[Index2] == Text[Index2]) {
        Line += Text[Index2] == '\n' ? 1 : 0;
        ++Index2;
      }
      DSig::Test::Note("trace differs first on line " + std::to_string(Line));
    }
    std::string Summary = "trace events re-emitted byte for byte:";
    for (const auto& [Kind, Count] : Kinds) {
      Summary += " " + Kind + "=" + std::to_string(Count);
    }
    DSig::Test::Note(Summary);
    CHECK(Kinds["add_match"] > 0 && Kinds["cleanup"] > 0 && Kinds["point"] == Index.size());
    DSig::Test::RemoveScratchDir(Scratch);
  }

  // 3. a native run against the capture
  if (!DSig::Test::ExportAvailable("ls-old") || !DSig::Test::ExportAvailable("ls")) {
    DSig::Test::Note("ls-old / ls exports missing: native comparison not run");
    return;
  }
  const std::string Scratch = DSig::Test::ScratchDir("foundation-oracle-native");
  DiffArgs Args;
  Args.Db1 = DSig::Test::ExportPath("ls-old");
  Args.Db2 = DSig::Test::ExportPath("ls");
  Args.Out = Join(Scratch, PairName + ".diaphora");
  Args.SnapshotDir = Join(Scratch, PairName);
  Args.TracePath = Join(Args.SnapshotDir, "trace.jsonl");
  Args.TraceRows = true;
  Args.PairLabel = PairName;
  Args.Quiet = true;
  Args.AllowSqliteMismatch = true;
  // the capture's own --with-cache globs (run.json options), so ratios_cache sits at the same points
  if (const JsonValue* Options = Run.Find("options"); Options != nullptr && Options->Find("with_cache") != nullptr) {
    for (const JsonValue& Glob : Options->At("with_cache").Items()) {
      Args.SnapshotCache += (Args.SnapshotCache.empty() ? "" : "|") + Glob.AsString();
    }
  }
  const DiffOutcome Outcome = RunDiff(Args);
  CHECK(Outcome.Status == DiffStatus::Ok);
  const std::vector<IndexRow> NativeIndex = ReadIndex(Args.SnapshotDir);
  std::vector<std::string> NativePoints;
  for (const IndexRow& Row : NativeIndex) {
    NativePoints.push_back(Row.Point);
  }
  // an in-order subsequence of the oracle's points; equal once no stage is skipped any more
  size_t Cursor = 0;
  bool Subsequence = true;
  for (const std::string& Point : NativePoints) {
    while (Cursor < Points.size() && Points[Cursor] != Point) {
      ++Cursor;
    }
    if (Cursor == Points.size()) {
      Subsequence = false;
      DSig::Test::Note("native point not in the oracle's order: " + Point);
      break;
    }
    ++Cursor;
  }
  CHECK(Subsequence);
  CHECK(NativePoints.size() >= 3);
  CHECK(NativePoints == Points);
  size_t Shared = 0;
  size_t SameShape = 0;
  size_t EmptyState = 0;
  size_t EmptyStateEqual = 0;
  for (const IndexRow& Row : NativeIndex) {
    const auto Oracle = OracleByPoint.find(Row.Point);
    if (!Row.File || Oracle == OracleByPoint.end()) {
      continue;
    }
    ++Shared;
    const JsonValue NativeJson = JsonParse(ReadFile(Join(Args.SnapshotDir, *Row.File)));
    const JsonValue& OracleJson = Oracle->second;
    const bool Shape = MemberNames(NativeJson) == MemberNames(OracleJson) &&
                       NativeJson.At("schema") == OracleJson.At("schema") &&
                       NativeJson.At("pair") == OracleJson.At("pair") &&
                       NativeJson.At("point") == OracleJson.At("point") &&
                       NativeJson.At("iteration") == OracleJson.At("iteration") &&
                       NativeJson.At("flags") == OracleJson.At("flags") &&
                       MemberNames(NativeJson.At("flags")) == MemberNames(OracleJson.At("flags"));
    SameShape += Shape ? 1 : 0;
    if (!Shape) {
      DSig::Test::Note("labels or flags differ at " + Row.Point);
    }
    // where the oracle's match state is still empty, the whole snapshot is S-L2 equal
    const StateSnapshot OracleSnap = ParseSnapshot(JsonWrite(OracleJson));
    if (OracleSnap.Best.empty() && OracleSnap.Partial.empty() && OracleSnap.Unreliable.empty() &&
        OracleSnap.MatchedPrimary.empty() && OracleSnap.MatchedSecondary.empty() && !OracleSnap.Choosers &&
        !OracleSnap.Unmatched && (!OracleSnap.RatiosCache || OracleSnap.RatiosCache->empty())) {
      ++EmptyState;
      EmptyStateEqual += DSig::Test::CompareSnapshots(OracleSnap, ParseSnapshot(JsonWrite(NativeJson))).L2Equal ? 1 : 0;
    }
  }
  CHECK_NUM_EQ(Shared, NativeIndex.size());
  CHECK_NUM_EQ(SameShape, Shared);
  CHECK(EmptyState >= 3);  // after:find_equal_matches, after:apply_dirty_heuristics, before:find_same_name
  CHECK_NUM_EQ(EmptyStateEqual, EmptyState);
  DSig::Test::Note(std::to_string(Shared) + " shared points: same keys, labels, flags and iteration; " +
                   std::to_string(EmptyStateEqual) + " S-L2 equal");
  DSig::Test::RemoveScratchDir(Scratch);
}

}

// ---------------------------------------------------------------------------------------------
// v1.0.0 hardening (lane R1, audit findings F01, F03, F06, F25, F27, F28, F29, F30, F58): every case
// here is a way to break the tool that the audit found; each check failed before its fix.

// The snapshot file of `Point` in a capture directory ("" when absent).
std::string CaptureSnapshotFile(const std::string& Capture, const std::string& Point) {
  for (const IndexRow& Row : ReadIndex(Capture)) {
    if (Row.Point == Point && Row.File) {
      return Join(Capture, *Row.File);
    }
  }
  return std::string();
}

void CopyFileTo(const std::string& From, const std::string& To) {
  std::error_code Error;
  fs::copy_file(Utf8ToPath(From), Utf8ToPath(To), fs::copy_options::overwrite_existing, Error);
  CHECK(!Error);
}

#ifdef _WIN32
// One environment variable of this process (inherited by RunCli's child), restored on destruction.
class ScopedEnv {
public:
  ScopedEnv(const wchar_t* Name, const std::wstring& Value) : Name_(Name) {
    wchar_t Buffer[32768];
    const DWORD Length = GetEnvironmentVariableW(Name, Buffer, 32768);
    Had_ = Length > 0 && Length < 32768;
    if (Had_) {
      Old_.assign(Buffer, Length);
    }
    SetEnvironmentVariableW(Name, Value.c_str());
  }
  ~ScopedEnv() { SetEnvironmentVariableW(Name_, Had_ ? Old_.c_str() : nullptr); }
  ScopedEnv(const ScopedEnv&) = delete;
  ScopedEnv& operator=(const ScopedEnv&) = delete;

private:
  const wchar_t* Name_;
  bool Had_ = false;
  std::wstring Old_;
};
#endif

// F01: every path diff writes or deletes is checked against every input (and their SQLite sidecars)
// before anything is opened; an alias is refused with exit 2 and no byte of any input changes.
void TestPathAliases(const FixturePair& Pair) {
  DSig::Test::Suite("F01 output / input aliases");
  const std::string MainSha = Sha256Of(ReadFile(Pair.Main));
  const std::string DiffSha = Sha256Of(ReadFile(Pair.Diff));
  const auto InputsIntact = [&] {
    return Sha256Of(ReadFile(Pair.Main)) == MainSha && Sha256Of(ReadFile(Pair.Diff)) == DiffSha;
  };
  DiffArgs Base;
  Base.Db1 = Pair.Main;
  Base.Db2 = Pair.Diff;
  Base.Out = Join(Pair.Dir, "alias.diaphora");
  Base.Quiet = true;
  Base.AllowSqliteMismatch = true;
  const auto Refused = [&](const DiffArgs& Args, const char* Label, const std::string& Mentions) {
    const DiffOutcome Outcome = RunDiff(Args);
    const bool Ok = Outcome.Status == DiffStatus::Usage && Outcome.Message.find(Mentions) != std::string::npos;
    DSig::Test::Report(Ok, Label, __FILE__, __LINE__);
    if (!Ok) {
      DSig::Test::Note(std::string(Label) + ": status " + std::to_string(static_cast<int>(Outcome.Status)) + ", " +
                       Outcome.Message);
    }
    CHECK(InputsIntact());
    CHECK(!Exists(Base.Out));  // refused before the pipeline: nothing was written
  };
  {
    DiffArgs A = Base;
    A.TracePath = Pair.Main;  // --trace <db1> truncated the input and exited 0
    Refused(A, "--trace <db1>", "db1");
  }
  {
    DiffArgs A = Base;
    A.TracePath = Pair.Main + "-wal";  // --trace onto the input's WAL lost its committed frames
    Refused(A, "--trace <db1>-wal", "-wal");
    CHECK(!Exists(Pair.Main + "-wal"));
  }
  {
    DiffArgs A = Base;
    A.Out = Pair.Diff + "-journal";  // a results DB posing as db2's hot journal broke the next diff
    Refused(A, "-o <db2>-journal", "-journal");
    CHECK(!Exists(Pair.Diff + "-journal"));
  }
  {
    DiffArgs A = Base;
    A.Out = Pair.Main + "-shm";
    Refused(A, "-o <db1>-shm", "-shm");
    CHECK(!Exists(Pair.Main + "-shm"));
  }
  {
    DiffArgs A = Base;
    A.TracePath = Base.Out;  // two outputs in one file
    Refused(A, "--trace == -o", "different files");
  }
  {
    // --snapshot-dir whose index.json is db1: the 5.4 MB input became a 38-byte index
    const std::string Dir = Join(Pair.Dir, "ix");
    std::error_code Error;
    fs::create_directories(Utf8ToPath(Dir), Error);
    const std::string Index = Join(Dir, "index.json");
    CopyFileTo(Pair.Main, Index);
    const std::string IndexSha = Sha256Of(ReadFile(Index));
    DiffArgs A = Base;
    A.Db1 = Index;
    A.SnapshotDir = Dir;
    A.SnapshotPoints = "none";
    Refused(A, "--snapshot-dir whose index.json is db1", "db1");
    CHECK_TEXT_EQ(Sha256Of(ReadFile(Index)), IndexSha);
    CHECK(!Exists(Join(Dir, "snapshots")));
    // the trace onto that index.json is refused too
    DiffArgs B = Base;
    B.SnapshotDir = Dir;
    B.TracePath = Index;
    CHECK(RunDiff(B).Status == DiffStatus::Usage);
    CHECK_TEXT_EQ(Sha256Of(ReadFile(Index)), IndexSha);
  }
  {
    // an input inside <snapshot-dir>/snapshots, where snapshot-named files are deleted
    const std::string Dir = Join(Pair.Dir, "inside");
    std::error_code Error;
    fs::create_directories(Utf8ToPath(Join(Dir, "snapshots")), Error);
    const std::string Inside = Join(Join(Dir, "snapshots"), "00001_diff.json");
    CopyFileTo(Pair.Diff, Inside);
    DiffArgs A = Base;
    A.Db2 = Inside;
    A.SnapshotDir = Dir;
    Refused(A, "db2 inside <snapshot-dir>/snapshots", "inside the snapshot directory");
    CHECK(Exists(Inside));
  }
  {
    // -o into a directory that holds run.json (an oracle capture), like --snapshot-dir there
    const std::string Oracle = Join(Pair.Dir, "capture-with-run-json");
    std::error_code Error;
    fs::create_directories(Utf8ToPath(Oracle), Error);
    WriteText(Join(Oracle, "run.json"), "{}\n");
    DiffArgs A = Base;
    A.Out = Join(Oracle, "x.diaphora");
    const DiffOutcome Outcome = RunDiff(A);
    CHECK(Outcome.Status == DiffStatus::Usage && Outcome.Message.find("run.json") != std::string::npos);
    CHECK(!Exists(A.Out));
  }
  {
    // the same file under another name: a hard link, another case, an 8.3 short name
    const std::string Link = Join(Pair.Dir, "hard-link-to-diff.sqlite");
    std::error_code Error;
    fs::create_hard_link(Utf8ToPath(Pair.Diff), Utf8ToPath(Link), Error);
    if (!Error) {
      DiffArgs A = Base;
      A.Out = Link;
      Refused(A, "-o <hard link to db2>", "db2");
    } else {
      DSig::Test::Note("hard links not supported here: " + Error.message());
    }
#ifdef _WIN32
    std::string Upper = Pair.Diff;
    const size_t Slash = Upper.find_last_of("\\/");
    for (size_t Index = Slash == std::string::npos ? 0 : Slash + 1; Index < Upper.size(); ++Index) {
      Upper[Index] = static_cast<char>(std::toupper(static_cast<unsigned char>(Upper[Index])));
    }
    DiffArgs Cased = Base;
    Cased.Out = Upper;
    Refused(Cased, "-o <db2 in another case>", "db2");
    const std::string LongName = Join(Pair.Dir, "a-long-input-database-name.sqlite");
    CopyFileTo(Pair.Diff, LongName);
    wchar_t Short[4096];
    const std::wstring Wide = Utf8ToPath(LongName).native();
    const DWORD Length = GetShortPathNameW(Wide.c_str(), Short, 4096);
    const std::wstring ShortName(Short, Length > 0 && Length < 4096 ? Length : 0);
    if (!ShortName.empty() && ShortName != Wide) {
      DiffArgs A = Base;
      A.Db2 = LongName;
      A.Out = PathToUtf8(fs::path(ShortName));
      const DiffOutcome Outcome = RunDiff(A);
      CHECK(Outcome.Status == DiffStatus::Usage);
      CHECK(Exists(LongName));
    } else {
      DSig::Test::Note("8.3 short names are disabled on this volume; that alias form is not exercised");
    }
#endif
  }
#ifdef DSIG_CLI_PATH
  {
    // the CLI maps the refusal to exit 2 and leaves the inputs alone
    const std::string Log = Join(Pair.Dir, "alias-cli.log");
    CHECK_NUM_EQ(RunCli({"diff", Pair.Main, Pair.Diff, "-o", Join(Pair.Dir, "c.diaphora"), "--trace", Pair.Main,
                         "--quiet", "--allow-sqlite-mismatch"},
                        Log),
                 2);
    CHECK(ReadFile(Log).find("refusing to overwrite an input") != std::string::npos);
    CHECK_NUM_EQ(RunCli({"diff", Pair.Main, Pair.Diff, "-o", Pair.Diff + "-journal", "--quiet",
                         "--allow-sqlite-mismatch"},
                        Log),
                 2);
    CHECK(!Exists(Pair.Diff + "-journal"));
    CHECK(InputsIntact());
  }
#endif
  // Detail::ReplaceFileBytes never rewrites a target in place: the index.json data-loss path
  {
    const std::string Target = Join(Pair.Dir, "replace-target.json");
    Detail::ReplaceFileBytes(Target, "one\n");
    Detail::ReplaceFileBytes(Target, "two\n");
    CHECK_TEXT_EQ(ReadFile(Target), "two\n");
    CHECK(!Exists(Target + ".tmp"));
#ifdef _WIN32
    // a reader that holds the file without delete sharing: the replace fails, the old bytes stay
    const HANDLE Held = CreateFileW(Utf8ToPath(Target).c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                    FILE_ATTRIBUTE_NORMAL, nullptr);
    CHECK(Held != INVALID_HANDLE_VALUE);
    bool Threw = false;
    try {
      Detail::ReplaceFileBytes(Target, "three, much longer than before\n");
    } catch (const IoFailure&) {
      Threw = true;
    }
    if (Held != INVALID_HANDLE_VALUE) {
      CloseHandle(Held);
    }
    CHECK(Threw);
    CHECK_TEXT_EQ(ReadFile(Target), "two\n");
    CHECK(!Exists(Target + ".tmp"));
#endif
  }
}

// F03: an environment failure inside SQLite ends the run with exit 6 and writes nothing; it is never
// swallowed by a heuristic worker as if it were one of Diaphora's per-heuristic raises.
void TestSqliteEnvironmentFailures(const FixturePair& Pair) {
  DSig::Test::Suite("F03 SQLite environment failures");
  for (const int Code : {SQLITE_FULL, SQLITE_IOERR, SQLITE_IOERR_SHORT_READ, SQLITE_IOERR_WRITE, SQLITE_CANTOPEN,
                         SQLITE_NOMEM, SQLITE_CORRUPT, SQLITE_NOTADB, SQLITE_BUSY, SQLITE_LOCKED,
                         SQLITE_READONLY, SQLITE_READONLY_ROLLBACK, SQLITE_PERM, SQLITE_INTERRUPT}) {
    DSig::Test::Report(IsEnvironmentalSqliteError(Code), ("environmental: " + std::to_string(Code)).c_str(), __FILE__,
                       __LINE__);
  }
  for (const int Code : {SQLITE_ERROR, SQLITE_MISMATCH, SQLITE_RANGE, SQLITE_CONSTRAINT, SQLITE_TOOBIG, SQLITE_MISUSE}) {
    DSig::Test::Report(!IsEnvironmentalSqliteError(Code), ("a parity raise: " + std::to_string(Code)).c_str(),
                       __FILE__, __LINE__);
  }
  // A damaged database: the root page of its functions table overwritten, so it opens and attaches
  // but fails when the export is read. That is not Diaphora's parity raise (it gave exit 3); it is an
  // I/O failure (exit 6), and no results file appears.
  {
    const std::string Damaged = Join(Pair.Dir, "damaged.sqlite");
    CopyFileTo(Pair.Diff, Damaged);
    int64_t Root = 0;
    int64_t PageSize = 0;
    {
      sqlite3* Handle = nullptr;
      CHECK(sqlite3_open_v2(Damaged.c_str(), &Handle, SQLITE_OPEN_READONLY, nullptr) == SQLITE_OK);
      sqlite3_stmt* Query = nullptr;
      if (sqlite3_prepare_v2(Handle,
                             "select (select rootpage from sqlite_master where type = 'table' and name = 'functions'),"
                             " (select page_size from pragma_page_size())",
                             -1, &Query, nullptr) == SQLITE_OK &&
          sqlite3_step(Query) == SQLITE_ROW) {
        Root = sqlite3_column_int64(Query, 0);
        PageSize = sqlite3_column_int64(Query, 1);
      }
      sqlite3_finalize(Query);
      sqlite3_close(Handle);
    }
    std::string Bytes = ReadFile(Damaged);
    CHECK(Root > 1 && PageSize >= 512 && static_cast<size_t>(Root * PageSize) <= Bytes.size());
    if (Root > 1 && PageSize >= 512 && static_cast<size_t>(Root * PageSize) <= Bytes.size()) {
      for (size_t Index = static_cast<size_t>((Root - 1) * PageSize); Index < static_cast<size_t>(Root * PageSize);
           ++Index) {
        Bytes[Index] = static_cast<char>(0xA5);
      }
    }
    WriteText(Damaged, Bytes);
    DiffArgs Args;
    Args.Db1 = Pair.Main;
    Args.Db2 = Damaged;
    Args.Out = Join(Pair.Dir, "damaged.diaphora");
    Args.Quiet = true;
    Args.AllowSqliteMismatch = true;
    const DiffOutcome Outcome = RunDiff(Args);
    CHECK_NUM_EQ(static_cast<int>(Outcome.Status), static_cast<int>(DiffStatus::Io));
    const bool Named = Outcome.Message.find("malformed") != std::string::npos ||
                       Outcome.Message.find("not a database") != std::string::npos;
    CHECK(Named);
    if (!Named) {
      DSig::Test::Note("damaged db2: " + Outcome.Message);
    }
    CHECK(!Exists(Args.Out));
    // the statement level: the failure type, not DiaphoraWouldRaise
    bool Environment = false;
    try {
      DiffDatabase Broken;
      Broken.OpenSingle(Damaged);
      Statement Query = Broken.Prepare("select * from functions");
      while (Query.Step()) {
      }
    } catch (const SqliteEnvironmentFailure& Error) {
      Environment = IsEnvironmentalSqliteError(Error.Code);
    } catch (const DiaphoraWouldRaise&) {
      Environment = false;
    }
    CHECK(Environment);
  }
#if defined(_WIN32) && defined(DSIG_CLI_PATH)
  // The audit's reproduction: TMP / TEMP point at a missing directory, so SQLite cannot create the
  // temporary b-trees four ls-old vs ls heuristics need. It exited 0 with 6 (type, description) groups
  // silently changed; now it is exit 6 and no results file.
  if (DSig::Test::ExportAvailable("ls-old") && DSig::Test::ExportAvailable("ls")) {
    const std::string Main = Join(Pair.Dir, "ls-old.sqlite");
    const std::string Diff = Join(Pair.Dir, "ls.sqlite");
    CopyFileTo(DSig::Test::ExportPath("ls-old"), Main);
    CopyFileTo(DSig::Test::ExportPath("ls"), Diff);
    const std::string Out = Join(Pair.Dir, "ls-tmp.diaphora");
    const std::string Log = Join(Pair.Dir, "ls-tmp.log");
    int Code = -1;
    {
      const std::wstring Missing = Utf8ToPath(Join(Pair.Dir, "no-such-temp-dir")).native();
      ScopedEnv Tmp(L"TMP", Missing);
      ScopedEnv Temp(L"TEMP", Missing);
      Code = RunCli({"diff", Main, Diff, "-o", Out, "--quiet", "--allow-sqlite-mismatch"}, Log);
    }
    CHECK_NUM_EQ(Code, 6);
    CHECK(!Exists(Out));
    CHECK(ReadFile(Log).find("environment failure") != std::string::npos);
    if (Code != 6) {
      DSig::Test::Note("ls-old vs ls with a missing TMP: exit " + std::to_string(Code) + "; " + ReadFile(Log));
    }
  } else {
    DSig::Test::Skip("F03 missing TMP", "ls-old / ls exports not in the corpus");
  }
#endif
}

// F06: db2 that is not a Diaphora export: Diaphora's empty results file is still written (parity), but
// the process exits 4 with an "error:" line, --quiet or not.
void TestNotAnExport(const FixturePair& Pair) {
  DSig::Test::Suite("F06 db2 not a Diaphora export");
  const std::string Empty = Join(Pair.Dir, "zero-bytes.sqlite");
  WriteText(Empty, "");
  const std::string Foreign = Join(Pair.Dir, "foreign.sqlite");
  CHECK(DSig::Test::BuildFixtureDbFromText("create table notes (a text);\ninsert into notes values ('x');\n", Foreign)
            .empty());
  const std::string NoVersionRow = Join(Pair.Dir, "no-version-row.sqlite");
  CHECK(DSig::Test::BuildFixtureDbFromText(
            ReadFile(DSig::Test::TestDataDir() + "/fixtures/foundation/diff.sql") + "delete from version;\n",
            NoVersionRow)
            .empty());
  for (const std::string& Db2 : {Empty, Foreign, NoVersionRow}) {
    DiffArgs Args;
    Args.Db1 = Pair.Main;
    Args.Db2 = Db2;
    Args.Out = Join(Pair.Dir, "not-an-export.diaphora");
    Args.Quiet = true;
    Args.AllowSqliteMismatch = true;
    const DiffOutcome Outcome = RunDiff(Args);
    CHECK_NUM_EQ(static_cast<int>(Outcome.Status), static_cast<int>(DiffStatus::Unsupported));
    CHECK(Outcome.Message.find("not a usable Diaphora export") != std::string::npos);
    CHECK(Outcome.OutputWritten && !Outcome.DiffReturned);
    const DSig::Test::ResultsFile File = DSig::Test::ReadResultsFile(Args.Out);
    CHECK(File.Error.empty() && File.Results.empty() && File.Unmatched.empty() && File.Schema == DiaphoraDdl());
#ifdef DSIG_CLI_PATH
    for (const bool Quiet : {false, true}) {
      const std::string Log = Join(Pair.Dir, "not-an-export.log");
      std::vector<std::string> Command = {"diff", Pair.Main, Db2, "-o", Args.Out, "--allow-sqlite-mismatch"};
      if (Quiet) {
        Command.push_back("--quiet");
      }
      CHECK_NUM_EQ(RunCli(Command, Log), 4);
      CHECK(ReadFile(Log).find("error: db2") != std::string::npos);
      CHECK(Exists(Args.Out));
    }
#endif
  }
}

// F25: an output whose directory is missing, or that is a directory, fails before the inputs are read.
void TestOutputLocation(const FixturePair& Pair) {
  DSig::Test::Suite("F25 output location checked first");
  DiffArgs Args;
  Args.Db1 = Pair.Main;
  Args.Db2 = Pair.Diff;
  Args.Quiet = true;
  Args.AllowSqliteMismatch = true;
  Args.TracePath = Join(Pair.Dir, "f25-trace.jsonl");  // created only if the run got past the check
  for (const std::string& Out : {Join(Join(Pair.Dir, "no-such-dir"), "r.diaphora"), Pair.Dir}) {
    Args.Out = Out;
    const DiffOutcome Outcome = RunDiff(Args);
    CHECK_NUM_EQ(static_cast<int>(Outcome.Status), static_cast<int>(DiffStatus::Io));
    CHECK(Outcome.Message.find("does not exist") != std::string::npos ||
          Outcome.Message.find("is a directory") != std::string::npos);
    CHECK(!Exists(Args.TracePath));
  }
  CHECK(!Exists(Join(Pair.Dir, "no-such-dir")));  // never created
}

// F28 / F30 / F58: replay inputs that are not what they claim.
void TestReplayGuards(const FixturePair& Pair) {
  DSig::Test::Suite("F28 / F30 / F58 replay guards");
  const std::string Capture = Join(Pair.Dir, "guards-capture");
  {
    DiffArgs Args;
    Args.Db1 = Pair.Main;
    Args.Db2 = Pair.Diff;
    Args.Out = Join(Pair.Dir, "guards.diaphora");
    Args.SnapshotDir = Capture;
    Args.Quiet = true;
    Args.AllowSqliteMismatch = true;
    CHECK(RunDiff(Args).Status == DiffStatus::Ok);
  }
  const std::string BeforeFile = CaptureSnapshotFile(Capture, "before:final_pass");
  CHECK(!BeforeFile.empty());
  if (BeforeFile.empty()) {
    return;
  }
  const std::string Text = ReadFile(BeforeFile);
  const StateSnapshot Good = ParseSnapshot(Text);
  CHECK(!Good.Best.empty() || !Good.Partial.empty());
  DiffArgs Replay;
  Replay.Db1 = Pair.Main;
  Replay.Db2 = Pair.Diff;
  Replay.ReplayStage = "final_pass";
  Replay.SnapshotOut = Join(Pair.Dir, "guards-after.json");
  Replay.Quiet = true;
  Replay.AllowSqliteMismatch = true;
  const auto Run = [&](const std::string& SnapshotText, const std::string& Name) {
    const std::string Path = Join(Pair.Dir, Name);
    WriteText(Path, SnapshotText);
    DiffArgs A = Replay;
    A.ReplayPath = Path;
    return RunDiff(A);
  };
  CHECK(Run(Text, "good.json").Status == DiffStatus::Ok);  // the baseline replay works

  // F28: an address of another pair, a function total of another pair, a --pair of another pair
  {
    StateSnapshot Foreign = Good;
    SnapItem Stranger = Foreign.Best.empty() ? Foreign.Partial.front() : Foreign.Best.front();
    Stranger.Ea1 = "987654321987";
    Foreign.Partial.push_back(Stranger);
    const DiffOutcome Outcome = Run(SerializeSnapshot(Foreign) + "\n", "foreign-address.json");
    CHECK_NUM_EQ(static_cast<int>(Outcome.Status), static_cast<int>(DiffStatus::Unsupported));
    CHECK(Outcome.Message.find("987654321987") != std::string::npos);
    StateSnapshot Totals = Good;
    Totals.Flags.TotalFunctions1 += 1000;
    CHECK(Run(SerializeSnapshot(Totals) + "\n", "foreign-totals.json").Status == DiffStatus::Unsupported);
    StateSnapshot Labelled = Good;
    Labelled.Pair = "ls-old_vs_ls";
    const std::string Path = Join(Pair.Dir, "labelled.json");
    WriteText(Path, SerializeSnapshot(Labelled) + "\n");
    DiffArgs A = Replay;
    A.ReplayPath = Path;
    A.PairLabel = "cryptbase-1-pdb_vs_8875-nopdb";
    CHECK(RunDiff(A).Status == DiffStatus::Unsupported);
    CHECK(!Exists(Replay.SnapshotOut + ".tmp"));
  }
  // F30: nesting deep enough to overflow the stack of a recursive parser is a clean exit 6
  {
    std::string Deep = Text;
    while (!Deep.empty() && (Deep.back() == '\n' || Deep.back() == '}')) {
      const bool Brace = Deep.back() == '}';
      Deep.pop_back();
      if (Brace) {
        break;
      }
    }
    Deep += ",\"extra\":" + std::string(20000, '[') + std::string(20000, ']') + "}\n";
    const DiffOutcome Outcome = Run(Deep, "deep.json");
    CHECK_NUM_EQ(static_cast<int>(Outcome.Status), static_cast<int>(DiffStatus::Io));
    CHECK(Outcome.Message.find("nesting too deep") != std::string::npos);
    bool Threw = false;
    try {
      (void)JsonParse(std::string(kMaxJsonDepth, '[') + std::string(kMaxJsonDepth, ']'));
    } catch (const JsonError&) {
      Threw = true;
    }
    CHECK(!Threw);  // exactly kMaxJsonDepth levels parse
    Threw = false;
    try {
      (void)JsonParse(std::string(kMaxJsonDepth + 1, '[') + std::string(kMaxJsonDepth + 1, ']'));
    } catch (const JsonError& Error) {
      Threw = std::string(Error.what()).find("nesting too deep") != std::string::npos;
    }
    CHECK(Threw);
    std::string Objects;
    for (int Level = 0; Level <= kMaxJsonDepth; ++Level) {
      Objects += "{\"a\":";
    }
    Objects += "1" + std::string(static_cast<size_t>(kMaxJsonDepth) + 1, '}');
    Threw = false;
    try {
      (void)JsonParse(Objects);
    } catch (const JsonError&) {
      Threw = true;
    }
    CHECK(Threw);
  }
  // F58: the message names the member, and no "at offset 0" for a value error
  {
    JsonValue Root = JsonParse(Text, JsonParseOptions{true, true});
    bool Edited = false;
    for (auto& [Key, Value] : Root.Members()) {
      if (Key != "all_matches") {
        continue;
      }
      for (auto& [List, Items] : Value.Members()) {
        if (!Items.Items().empty() && !Edited) {
          Items.Items()[0].Items()[6] = JsonValue::String("x");
          Edited = true;
          const std::string Want = "all_matches." + List + "[0][6]: JSON value is not an integer";
          const DiffOutcome Outcome = Run(JsonWrite(Root) + "\n", "bad-nodes.json");
          CHECK_NUM_EQ(static_cast<int>(Outcome.Status), static_cast<int>(DiffStatus::Io));
          CHECK_TEXT_EQ(Outcome.Message, "invalid snapshot JSON: " + Want);
          bool Threw = false;
          try {
            (void)ParseSnapshot(JsonWrite(Root));
          } catch (const JsonError& Error) {
            Threw = Error.Path == "all_matches." + List + "[0][6]" && std::string(Error.what()) == Want;
          }
          CHECK(Threw);
        }
      }
    }
    CHECK(Edited);
    // a syntax error keeps its offset
    bool Offset = false;
    try {
      (void)ParseSnapshot("{\"schema\": ");
    } catch (const JsonError& Error) {
      Offset = std::string(Error.what()).find(" at offset ") != std::string::npos;
    }
    CHECK(Offset);
  }
  // F62 (b): the after snapshot is written through <path>.tmp and a rename; no .tmp stays behind
  CHECK(Exists(Replay.SnapshotOut) && !Exists(Replay.SnapshotOut + ".tmp"));
}

// F29: --snapshot-dir clears only an earlier capture; a foreign index.json is refused, untouched.
void TestForeignSnapshotDir(const FixturePair& Pair) {
  DSig::Test::Suite("F29 foreign snapshot directory");
  const std::string Dir = Join(Pair.Dir, "someone-elses-dir");
  std::error_code Error;
  fs::create_directories(Utf8ToPath(Dir), Error);
  const std::string Index = Join(Dir, "index.json");
  const std::string Foreign = "{\"name\": \"my web app\", \"version\": 3}\n";
  WriteText(Index, Foreign);
  DiffArgs Args;
  Args.Db1 = Pair.Main;
  Args.Db2 = Pair.Diff;
  Args.Out = Join(Pair.Dir, "f29.diaphora");
  Args.SnapshotDir = Dir;
  Args.Quiet = true;
  Args.AllowSqliteMismatch = true;
  const DiffOutcome Outcome = RunDiff(Args);
  CHECK_NUM_EQ(static_cast<int>(Outcome.Status), static_cast<int>(DiffStatus::Usage));
  CHECK(Outcome.Message.find("not a snapshot capture index") != std::string::npos);
  CHECK_TEXT_EQ(ReadFile(Index), Foreign);
  CHECK(!Exists(Join(Dir, "snapshots")) && !Exists(Args.Out));
  // an earlier capture's index (even an empty one) is replaced as before
  WriteText(Index, "[]\n");
  CHECK(RunDiff(Args).Status == DiffStatus::Ok);
  CHECK(ReadFile(Index).size() > 3);
}

// F27: a trace write, flush or close that fails ends the run with IoFailure (exit 6), once.
void TestTraceWriteFailures(const FixturePair& Pair) {
  DSig::Test::Suite("F27 trace write failures");
  const std::string Path = Join(Pair.Dir, "failing-trace.jsonl");
  const auto Throws = [](const std::function<void()>& Fn) {
    try {
      Fn();
    } catch (const IoFailure& Error) {
      return Error.What.find("cannot write trace") != std::string::npos;
    }
    return false;
  };
  {
    TraceSink Sink;
    Sink.Open(Path, true);
    Sink.Point("before:x", 0, 0, 0);
    Sink.InjectWriteFailureForTest();
    CHECK(Throws([&] { Sink.AddMatch("", "a", "b", "1", "2", "d", 0.5, "best", AddMatchResult::Appended); }));
    CHECK(!Sink.Enabled());  // disabled: nothing more is attempted while the error unwinds
    CHECK(!Throws([&] { Sink.Point("after:x", 0, 0, 0); }));
    CHECK(!Throws([&] { Sink.Finish(); }));
  }
  {
    TraceSink Sink;
    Sink.Open(Path, false);
    Sink.InjectWriteFailureForTest();
    CHECK(Throws([&] { Sink.Point("before:x", 0, 0, 0); }));
  }
  {
    TraceSink Sink;
    Sink.Open(Path, false);
    Sink.Point("before:x", 0, 0, 0);
    Sink.InjectWriteFailureForTest();
    CHECK(Throws([&] { Sink.Finish(); }));
  }
  {
    // FinishHarness reports it, so RunDiff cannot exit 0 with a cut trace
    DiffSession S;
    S.EnableTrace(Path, false);
    S.Point("before:x");
    S.Tracer().InjectWriteFailureForTest();
    CHECK(Throws([&] { S.FinishHarness(); }));
  }
}

// F31: sqlite3_initialize before every open, with a clear error when it fails. Runs last: it shuts
// SQLite down (no connection may be open) and restores it.
void TestSqliteInitialize() {
  DSig::Test::Suite("F31 sqlite3_initialize");
  if (sqlite3_shutdown() != SQLITE_OK) {
    DSig::Test::Skip("F31 sqlite3_initialize", "sqlite3_shutdown refused (a connection is still open)");
    return;
  }
  sqlite3_mem_methods Saved{};
  CHECK(sqlite3_config(SQLITE_CONFIG_GETMALLOC, &Saved) == SQLITE_OK);
  sqlite3_mem_methods Failing = Saved;
  Failing.xInit = [](void*) { return SQLITE_NOMEM; };
  CHECK(sqlite3_config(SQLITE_CONFIG_MALLOC, &Failing) == SQLITE_OK);
  std::string Message;
  try {
    DiffDatabase Db;
    Db.OpenSingle("never-opened.sqlite");
  } catch (const IoFailure& Error) {
    Message = Error.What;
  }
  CHECK(Message.find("sqlite3_initialize failed") != std::string::npos);
  std::string WriterMessage;
  try {
    WriteArgs Args;
    Args.OutPath = ":memory:";
    WriteDiaphoraResults(Args, FinalResults{}, Interners{});
  } catch (const IoFailure& Error) {
    WriterMessage = Error.What;
  }
  CHECK(WriterMessage.find("sqlite3_initialize failed") != std::string::npos);
  sqlite3_shutdown();
  CHECK(sqlite3_config(SQLITE_CONFIG_MALLOC, &Saved) == SQLITE_OK);
  CHECK(sqlite3_initialize() == SQLITE_OK);
  EnsureSqliteInitialized();  // idempotent once initialised
  CHECK(!DiffDatabase::LibVersion().empty());
}

// F58: the fetch-time decode errors and ingest problems name the row.
void TestErrorContext() {
  DSig::Test::Suite("F58 error messages name the row");
  FixturePair Pair = BuildFoundationFixture(
      "foundation-f58",
      "alter table functions rename column name to name_text;\n"
      "alter table functions add column name integer;\n"
      "update functions set name = name_text;\n"
      "update functions set name = 42 where id = (select min(id) from functions);\n");
  CHECK(Pair.Ok);
  if (!Pair.Ok) {
    return;
  }
  DiffSession S;
  S.Open(Pair.Main, Pair.Diff);
  bool Named = false;
  for (const std::string& Problem : S.Main().Problems) {
    Named = Named || (Problem.find("functions.name row with id ") != std::string::npos &&
                      Problem.find("holds a number in a TEXT column") != std::string::npos);
  }
  CHECK(Named);
  DSig::Test::RemoveScratchDir(Pair.Dir);
}

void TestReleaseHardening() {
  FixturePair Pair = BuildFoundationFixture("foundation-hardening");
  CHECK(Pair.Ok);
  if (!Pair.Ok) {
    return;
  }
  TestPathAliases(Pair);
  TestSqliteEnvironmentFailures(Pair);
  TestNotAnExport(Pair);
  TestOutputLocation(Pair);
  TestReplayGuards(Pair);
  TestForeignSnapshotDir(Pair);
  TestTraceWriteFailures(Pair);
  TestErrorContext();
  DSig::Test::RemoveScratchDir(Pair.Dir);
}

int main() {
  TestRegistry();
  TestInterner();
  TestJson();
  TestSnapshot();
  TestTrace();
  TestConfigAndNames();
  TestFixtureIngest();
  TestIngestQuirks();
  TestPipeline();
  TestFinalResults();
  TestMissingSideTables();
  TestSqliteWarning();
  TestUnicodePaths();
  TestReadOnlyInputs();
  TestCorpusIngestCensus();
  TestRowSequenceCensus();
  TestSameNamePlan();
  TestCorpusDiffDdl();
  TestOracleConventions();
  TestReleaseHardening();
  TestSqliteInitialize();  // last: it shuts SQLite down and restores it
  return DSig::Test::Finish();
}
