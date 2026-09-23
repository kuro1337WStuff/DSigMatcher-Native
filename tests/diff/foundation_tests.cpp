// diff_foundation: the L0 foundation of the parity engine (docs/parity/00-plan.md §2.6, §4 L0).
//
//   * registry and stage SQL against tests/diff/generated/registry_expected.inc;
//   * JSON, snapshot, trace and interner units;
//   * FixtureDb, ingest and Path A on the committed synthetic fixture (tests/diff/fixtures/foundation);
//   * the stubbed pipeline end to end: exit codes, Diaphora's DDL, the mode-N points (G0);
//   * corpus (skipped without DSIG_CORPUS_ROOT): ingest census of the 7 exports, the stubbed diff of
//     ls-old vs ls against the oracle file's DDL, results comparison self-checks;
//   * SQLite 3.51.1 only: the Path A row-sequence census on the 5 oracle pairs and the
//     find_same_name EXPLAIN QUERY PLAN (02 Appendix C). Sequences Python needed more than 5 s for run
//     only with DSIG_CENSUS_LONG=1.

#include <algorithm>
#include <cmath>
#include <cstring>
#include <filesystem>
#include <iterator>
#include <fstream>
#include <limits>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "diff/CorpusPaths.h"
#include "diff/FixtureDb.h"
#include "diff/ResultsCompare.h"
#include "diff/TestHarness.h"
#include "dsigmatcher/Sha256.h"
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

std::string ReadFile(const std::string& Path) {
  std::ifstream In(Path, std::ios::binary);
  std::ostringstream Buffer;
  Buffer << In.rdbuf();
  return Buffer.str();
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
  CHECK(PointMatchesGlob("before:heuristic:41", "*heuristic:*"));
  CHECK(PointMatchesGlob("after:final_pass", "*"));
  CHECK(PointMatchesGlob("after:cleanup:3185:4", "after:cleanup:31??:*"));
  CHECK(!PointMatchesGlob("after:cleanup:3185:4", "before:*"));
  CHECK(!PointMatchesGlob("abc", "ab"));
  CHECK(PointMatchesAnyGlob("after:final_pass", "before:*|after:final_pass"));
  CHECK(!PointMatchesAnyGlob("after:final_pass", ""));

  // write/read through a file
  const std::string Dir = DSig::Test::ScratchDir("foundation-snapshot");
  const std::string Path = (fs::path(Dir) / "s.json").string();
  WriteSnapshot(Path, Sample, true);
  CHECK(SameSnapshot(ReadSnapshot(Path), Sample));
  DSig::Test::RemoveScratchDir(Dir);
}

// ---------------------------------------------------------------------------------------------
// Trace sink (Appendix B)

void TestTrace() {
  DSig::Test::Suite("trace");
  const std::string Dir = DSig::Test::ScratchDir("foundation-trace");
  const std::string Path = (fs::path(Dir) / "trace.jsonl").string();
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
    CHECK_NUM_EQ(Sink.Events(), 4);
    Sink.Close();
  }
  std::ifstream In(Path, std::ios::binary);
  std::vector<JsonValue> Lines;
  for (std::string Line; std::getline(In, Line);) {
    Lines.push_back(JsonParse(Line));
  }
  CHECK_NUM_EQ(Lines.size(), 4);
  if (Lines.size() == 4) {
    CHECK_TEXT_EQ(Lines[0].At("ev").AsString(), "add_match");
    CHECK_NUM_EQ(Lines[0].At("seq").AsInt64(), 0);
    CHECK_TEXT_EQ(Lines[0].At("ctx").AsString(), "heuristic:41");
    CHECK_TEXT_EQ(Lines[0].At("name1").AsString(), "foo");
    CHECK(Lines[0].At("name2").IsNull());
    CHECK_TEXT_EQ(Lines[0].At("ratio_bits").AsString(), "3fee666666666666");
    CHECK_TEXT_EQ(Lines[0].At("chooser").AsString(), "partial");
    CHECK_TEXT_EQ(Lines[0].At("result").AsString(), "appended");
    CHECK_TEXT_EQ(Lines[1].At("ev").AsString(), "cleanup");
    CHECK_NUM_EQ(Lines[1].At("site").AsInt64(), 3185);
    CHECK_NUM_EQ(Lines[1].At("n").AsInt64(), 4);
    CHECK_NUM_EQ(Lines[1].At("partial").AsInt64(), 2);
    CHECK_TEXT_EQ(Lines[2].At("name").AsString(), "after:final_pass");
    CHECK_TEXT_EQ(Lines[3].At("decision").AsString(), "below_min");
    CHECK(Lines[3].At("ratio_bits").IsNull());
    CHECK_NUM_EQ(Lines[3].At("seq").AsInt64(), 3);
  }
  CHECK_TEXT_EQ(std::string(AddMatchResultName(AddMatchResult::RejectedBetter)), "rejected_better");
  CHECK_TEXT_EQ(std::string(RowDecisionName(RowDecision::HasBest)), "has_best");
  // "%1.2f" formatting of the summary lines
  CHECK_TEXT_EQ(FormatPercent2(100.0), "100.00");
  CHECK_TEXT_EQ(FormatPercent2(0.125), "0.12");   // exact binary tie, half-even
  CHECK_TEXT_EQ(FormatPercent2(0.375), "0.38");
  CHECK_TEXT_EQ(FormatPercent2(45.724), "45.72");
  In.close();
  DSig::Test::RemoveScratchDir(Dir);
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

FixturePair BuildFoundationFixture(const std::string& Suite, const std::string& ExtraMainSql = "") {
  FixturePair Pair;
  Pair.Dir = DSig::Test::ScratchDir(Suite);
  Pair.Main = (fs::path(Pair.Dir) / "main.sqlite").string();
  Pair.Diff = (fs::path(Pair.Dir) / "diff.sqlite").string();
  const std::string Base = DSig::Test::TestDataDir() + "/fixtures/foundation/";
  const std::string MainSql = ReadFile(Base + "main.sql") + ExtraMainSql;
  const std::string E1 = DSig::Test::BuildFixtureDbFromText(MainSql, Pair.Main);
  const std::string E2 = DSig::Test::BuildFixtureDb(Base + "diff.sql", Pair.Diff);
  if (!E1.empty()) {
    DSig::Test::Note("fixture main: " + E1);
  }
  if (!E2.empty()) {
    DSig::Test::Note("fixture diff: " + E2);
  }
  Pair.Ok = E1.empty() && E2.empty();
  return Pair;
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
    Args.Out = (fs::path(Broken.Dir) / "out.diaphora").string();
    Args.Quiet = true;
    const DiffOutcome Outcome = RunDiff(Args);
    CHECK(Outcome.Status == DiffStatus::Unsupported);
    CHECK(!Outcome.OutputWritten);
    DSig::Test::RemoveScratchDir(Broken.Dir);
  }
}

// ---------------------------------------------------------------------------------------------
// The stubbed pipeline end to end (G0) on the fixture

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

std::vector<std::string> ReadIndexPoints(const std::string& Dir) {
  std::vector<std::string> Points;
  const JsonValue Index = JsonParse(ReadFile((fs::path(Dir) / "index.json").string()));
  for (const JsonValue& Row : Index.Items()) {
    Points.push_back(Row.Items()[1].AsString());
  }
  return Points;
}

void TestPipeline() {
  DSig::Test::Suite("pipeline");
  FixturePair Pair = BuildFoundationFixture("foundation-pipeline");
  CHECK(Pair.Ok);
  if (!Pair.Ok) {
    return;
  }
  const std::string Snapshots = (fs::path(Pair.Dir) / "snapshots").string();
  const std::string Trace = (fs::path(Pair.Dir) / "trace.jsonl").string();
  DiffArgs Args;
  Args.Db1 = Pair.Main;
  Args.Db2 = Pair.Diff;
  Args.Out = (fs::path(Pair.Dir) / "out.diaphora").string();
  Args.SnapshotDir = Snapshots;
  Args.TracePath = Trace;
  Args.TraceRows = true;
  Args.Quiet = true;
  Args.AllowSqliteMismatch = true;
  {
    std::ofstream Stale(Args.Out);  // D:2379-2381: an existing output is replaced
    Stale << "stale";
  }
  const DiffOutcome Outcome = RunDiff(Args);
  CHECK(Outcome.Status == DiffStatus::Ok);
  if (Outcome.Status != DiffStatus::Ok) {
    DSig::Test::Note("RunDiff: " + Outcome.Message);
  }
  CHECK(Outcome.OutputWritten);
  CHECK(Outcome.Mode == 'N');
  CHECK(Outcome.DiffReturned);
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
  const std::vector<std::string> Points = ReadIndexPoints(Snapshots);
  const std::set<std::string> Have(Points.begin(), Points.end());
  const std::vector<std::string> Required = {
      "after:find_equal_matches",
      "after:apply_dirty_heuristics",
      "before:find_same_name",
      "after:find_same_name",
      "before:heuristic:11",
      "after:heuristic:11",
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
  // every snapshot parses; the special dumps are where Appendix B puts them
  const JsonValue Index = JsonParse(ReadFile((fs::path(Snapshots) / "index.json").string()));
  for (const JsonValue& Row : Index.Items()) {
    const StateSnapshot Snap = ReadSnapshot((fs::path(Snapshots) / Row.Items()[2].AsString()).string());
    CHECK_TEXT_EQ(Snap.Point, Row.Items()[1].AsString());
    CHECK_NUM_EQ(Snap.Seq, Row.Items()[0].AsInt64());
    CHECK(Snap.Choosers.has_value() == (Snap.Point == "after:final_pass"));
    CHECK(Snap.Unmatched.has_value() == (Snap.Point == "after:find_unmatched"));
    CHECK_NUM_EQ(Snap.Flags.TotalFunctions1, 6);
    CHECK_NUM_EQ(Snap.Flags.TotalFunctions2, 7);
    CHECK(Snap.Producer.rfind("dsigmatcher-", 0) == 0);
    CHECK(Snap.Iteration.has_value() == (Pos(Snap.Point) >= Pos("before:cleanup:3655:1")));
  }
  // the trace carries one point event per point, in the same order
  {
    std::ifstream In(Trace, std::ios::binary);
    std::vector<std::string> TracePoints;
    for (std::string Line; std::getline(In, Line);) {
      const JsonValue Event = JsonParse(Line);
      if (Event.At("ev").AsString() == "point") {
        TracePoints.push_back(Event.At("name").AsString());
      }
    }
    CHECK(TracePoints == Points);
  }

  // replay: a cleanup from its before snapshot reproduces the after snapshot (S-L2)
  {
    DiffSession S;
    S.Open(Pair.Main, Pair.Diff);
    const auto Find = [&](const std::string& Name) {
      return (fs::path(Snapshots) / SnapshotFileName(Pos(Name), Name)).string();
    };
    const StateSnapshot Before = ReadSnapshot(Find("before:cleanup:3655:1"));
    const StateSnapshot Expected = ReadSnapshot(Find("after:cleanup:3655:1"));
    const StateSnapshot After = RunReplay(S, Before, "cleanup:3655:1");
    CHECK_TEXT_EQ(After.Point, "after:cleanup:3655:1");
    const DSig::Test::CompareReport Report = DSig::Test::CompareSnapshots(Expected, After);
    CHECK(Report.L2Equal);
    for (const std::string& Line : Report.Differences) {
      DSig::Test::Note(Line);
    }
    bool Threw = false;
    try {
      (void)RunReplay(S, Before, "no_such_stage");
    } catch (const UnsupportedInput&) {
      Threw = true;
    }
    CHECK(Threw);
  }
  // the CLI replay path writes the after snapshot
  {
    DiffArgs Replay;
    Replay.Db1 = Pair.Main;
    Replay.Db2 = Pair.Diff;
    Replay.ReplayPath = (fs::path(Snapshots) / SnapshotFileName(Pos("before:cleanup:3671:1"), "before:cleanup:3671:1")).string();
    Replay.ReplayStage = "cleanup:3671:1";
    Replay.SnapshotOut = (fs::path(Pair.Dir) / "after.json").string();
    Replay.Quiet = true;
    const DiffOutcome Out = RunDiff(Replay);
    CHECK(Out.Status == DiffStatus::Ok);
    CHECK(Out.OutputWritten && fs::exists(Replay.SnapshotOut));
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
    Missing.Out = (fs::path(Pair.Dir) / "x.diaphora").string();
    Missing.Db2 = (fs::path(Pair.Dir) / "no-such.sqlite").string();
    const DiffOutcome Io = RunDiff(Missing);
    CHECK(Io.Status == DiffStatus::Io);
    CHECK(!fs::exists(Missing.Db2));  // a read-only open never creates the input
    DiffArgs Strict = Alias;
    Strict.Out = (fs::path(Pair.Dir) / "strict.diaphora").string();
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
    CHECK(!InvokeStage(S, "stub", [] { throw StageNotImplemented("x"); }));
    CHECK(InvokeStage(S, "real", [] {}));
    CHECK_NUM_EQ(S.SkippedStages().size(), 1);
    bool Propagated = false;
    try {
      InvokeStage(S, "raises", [] { throw DiaphoraWouldRaise("D:1", "x"); });
    } catch (const DiaphoraWouldRaise&) {
      Propagated = true;
    }
    CHECK(Propagated);
    CHECK(S.Mode() == 'N');
    S.Flags().IsPatchDiff = true;
    CHECK(S.Mode() == 'P');
  }
  DSig::Test::RemoveScratchDir(Pair.Dir);
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
    const std::string ManifestPath = (fs::path(DSig::Test::OracleDir()) / "manifest.json").string();
    if (fs::exists(ManifestPath)) {  // and to the oracle manifest itself
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
  CHECK_NUM_EQ(Checked, 4);
}

// ---------------------------------------------------------------------------------------------
// Corpus: the stubbed `diff ls-old ls` writes Diaphora's exact DDL (G0), results comparison

void TestCorpusDiffDdl() {
  if (!DSig::Test::ExportAvailable("ls-old") || !DSig::Test::ExportAvailable("ls") ||
      !fs::exists(DSig::Test::OracleResultsPath("ls-old_vs_ls"))) {
    DSig::Test::Skip("corpus-diff-ddl", "ls-old / ls exports or the oracle results are missing");
    return;
  }
  DSig::Test::Suite("corpus-diff-ddl");
  const std::string Dir = DSig::Test::ScratchDir("foundation-corpus");
  DiffArgs Args;
  Args.Db1 = DSig::Test::ExportPath("ls-old");
  Args.Db2 = DSig::Test::ExportPath("ls");
  Args.Out = (fs::path(Dir) / "ls-old_vs_ls.diaphora").string();
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
  if (fs::exists(DSig::Test::OracleResultsPath("ls-old_vs_ls", 2))) {
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
  TestCorpusIngestCensus();
  TestRowSequenceCensus();
  TestSameNamePlan();
  TestCorpusDiffDdl();
  return DSig::Test::Finish();
}
