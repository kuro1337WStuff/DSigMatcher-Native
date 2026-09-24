// Suite diff_textdiff: str.split("\n"), str.splitlines(), the CPP_NAMES_RE scanner (D:114) and the
// literal port of CPython 3.13.12 difflib (SequenceMatcher, unified_diff). Spec: 03b §4.3.1, §4.3.3, §5;
// 06 §6.1-§6.4 and Appendix A; 07 §10.11.1.
//
// Parts:
//   1. unit tests with the worked examples of the spec (expected values quoted from 03b / 06 / 07 and
//      re-checked against CPython 3.13.12);
//   2. committed synthetic vectors, tests/diff/vectors/textdiff/ (tools/parity/gen_textdiff_vectors.py
//      --synthetic): explicit examples, plus SplitMix64 fuzz cases that this file regenerates exactly
//      the way the generator does (GenUdiffCase / GenString below mirror gen_udiff_case / gen_string,
//      call for call) and compares by hash;
//   3. corpus acceptance (skips without DSIG_CORPUS_ROOT or the vectors): for every row of the finished
//      oracle .diaphora files and each of assembly / pseudocode, the row list of
//      UnifiedDiff(PySplitLines(a), PySplitLines(b)) hashes to what Python's
//      unified_diff(a.splitlines(), b.splitlines(), lineterm="") gives (D:3040-3042). Vectors:
//      <corpus>/oracle/vectors/textdiff/udiff_corpus_<pair>.txt (gen_textdiff_vectors.py --corpus).
//
// Hash encodings are defined in the generator's docstring (HASHES).

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "diff/CorpusPaths.h"
#include "diff/TestHarness.h"
#include "dsigmatcher/Sha256.h"
#include "dsigmatcher/diff/Database.h"
#include "dsigmatcher/diff/Json.h"
#include "dsigmatcher/diff/TextDiff.h"

namespace fs = std::filesystem;
using DSig::Diff::CppNamesFindAll;
using DSig::Diff::JsonParse;
using DSig::Diff::JsonValue;
using DSig::Diff::MatchingBlock;
using DSig::Diff::Opcode;
using DSig::Diff::OpTag;
using DSig::Diff::PySplitLines;
using DSig::Diff::PySplitNewline;
using DSig::Diff::SequenceMatcher;
using DSig::Diff::UnifiedDiff;

namespace {

// ------------------------------------------------------------------------------------------ helpers
std::optional<std::string> ReadFile(const std::string& Path) {
  std::ifstream In(Path, std::ios::binary);
  if (!In) {
    return std::nullopt;
  }
  std::ostringstream Buffer;
  Buffer << In.rdbuf();
  return Buffer.str();
}

// Text lines of a vector file; tolerates CRLF checkouts.
std::vector<std::string> FileLines(const std::string& Content) {
  std::vector<std::string> Lines;
  size_t Start = 0;
  while (Start < Content.size()) {
    size_t End = Content.find('\n', Start);
    if (End == std::string::npos) {
      End = Content.size();
    }
    std::string Line = Content.substr(Start, End - Start);
    if (!Line.empty() && Line.back() == '\r') {
      Line.pop_back();
    }
    Lines.push_back(std::move(Line));
    Start = End + 1;
  }
  return Lines;
}

std::vector<std::string> Strings(const std::vector<std::string_view>& Items) {
  return std::vector<std::string>(Items.begin(), Items.end());
}

std::vector<std::string> JsonStrings(const JsonValue& Array) {
  std::vector<std::string> Out;
  for (const JsonValue& Item : Array.Items()) {
    Out.push_back(Item.AsString());
  }
  return Out;
}

std::vector<std::string_view> Views(const std::vector<std::string>& Items) {
  return std::vector<std::string_view>(Items.begin(), Items.end());
}

std::string Joined(const std::vector<std::string>& Items) {
  std::string Out = "[";
  for (size_t I = 0; I < Items.size(); ++I) {
    Out += (I ? ", " : "");
    Out += "'" + Items[I] + "'";
  }
  return Out + "]";
}

// frame(x) = len + ":" + x + "\n"; frame_list(xs) = len(xs) + "#" + frames (generator HASHES)
std::string Frame(std::string_view Text) { return std::to_string(Text.size()) + ":" + std::string(Text) + "\n"; }

template <class T>
std::string FrameList(const std::vector<T>& Items) {
  std::string Out = std::to_string(Items.size()) + "#";
  for (const auto& Item : Items) {
    Out += Frame(Item);
  }
  return Out;
}

std::string RowsHash(const std::vector<std::string>& Rows) {
  DSig::Sha256 H;
  for (const std::string& Row : Rows) {
    H.Update(Frame(Row));
  }
  return H.FinishHex();
}

std::string BlocksHash(const std::vector<MatchingBlock>& Blocks) {
  DSig::Sha256 H;
  for (const MatchingBlock& B : Blocks) {
    H.Update(std::to_string(B.A) + "," + std::to_string(B.B) + "," + std::to_string(B.Size) + "\n");
  }
  return H.FinishHex();
}

std::string Bits(double X) {
  uint64_t U = 0;
  std::memcpy(&U, &X, sizeof U);
  char Buffer[17];
  std::snprintf(Buffer, sizeof Buffer, "%016llx", static_cast<unsigned long long>(U));
  return Buffer;
}

std::string Sha256Hex(std::string_view Text) {
  DSig::Sha256 H;
  H.Update(Text);
  return H.FinishHex();
}

std::string BlocksText(const std::vector<MatchingBlock>& Blocks) {
  std::string Out;
  for (const MatchingBlock& B : Blocks) {
    Out += "(" + std::to_string(B.A) + "," + std::to_string(B.B) + "," + std::to_string(B.Size) + ")";
  }
  return Out;
}

std::string OpcodesText(const std::vector<Opcode>& Codes) {
  std::string Out;
  for (const Opcode& C : Codes) {
    Out += "(" + std::string(DSig::Diff::OpTagName(C.Tag)) + "," + std::to_string(C.I1) + "," + std::to_string(C.I2) +
           "," + std::to_string(C.J1) + "," + std::to_string(C.J2) + ")";
  }
  return Out;
}

// Dense ids for a list of Python str lines (equal text <-> equal id).
std::vector<uint32_t> Intern(const std::vector<std::string>& Lines, std::unordered_map<std::string, uint32_t>& Ids) {
  std::vector<uint32_t> Out;
  for (const std::string& Line : Lines) {
    const auto [It, Inserted] = Ids.emplace(Line, static_cast<uint32_t>(Ids.size()));
    (void)Inserted;
    Out.push_back(It->second);
  }
  return Out;
}

// ------------------------------------------------------------------------------------------ SplitMix64
// Mirrors gen_textdiff_vectors.py (PRNG). below(n) = next() % n; pick(seq) = seq[below(len(seq))].
class SplitMix64 {
public:
  explicit SplitMix64(uint64_t Seed) : State_(Seed) {}
  uint64_t Next() {
    State_ += 0x9E3779B97F4A7C15ull;
    uint64_t Z = State_;
    Z = (Z ^ (Z >> 30)) * 0xBF58476D1CE4E5B9ull;
    Z = (Z ^ (Z >> 27)) * 0x94D049BB133111EBull;
    return Z ^ (Z >> 31);
  }
  uint64_t Below(uint64_t N) { return Next() % N; }
  template <class T>
  const T& Pick(const std::vector<T>& Seq) {
    return Seq[static_cast<size_t>(Below(Seq.size()))];
  }

private:
  uint64_t State_;
};

SplitMix64 CaseRng(uint64_t Base, uint64_t Index) { return SplitMix64(Base ^ (Index * 0xD1B54A32D192ED03ull)); }

// ------------------------------------------------------------------------------------------ 1. split
void TestPySplitNewline() {
  DSig::Test::Suite("PySplitNewline (str.split(\"\\n\"), D:159/D:170)");
  using V = std::vector<std::string>;
  CHECK(Strings(PySplitNewline("")) == V{""});
  CHECK(Strings(PySplitNewline("a")) == V{"a"});
  CHECK(Strings(PySplitNewline("a\n")) == (V{"a", ""}));
  CHECK(Strings(PySplitNewline("a\n\n")) == (V{"a", "", ""}));
  CHECK(Strings(PySplitNewline("\n")) == (V{"", ""}));
  CHECK(Strings(PySplitNewline("a\r\nb")) == (V{"a\r", "b"}));
  CHECK(Strings(PySplitNewline("a\n\r")) == (V{"a", "\r"}));
  // 03a §2: 'a\nb\n' vs 'a\nb' differ by the trailing "" piece
  CHECK(Strings(PySplitNewline("a\nb\n")) == (V{"a", "b", ""}));
  CHECK(Strings(PySplitNewline("a\nb")) == (V{"a", "b"}));
  // other line breaks are not separators for split("\n")
  CHECK(Strings(PySplitNewline("a\x0b"
                               "b\x1c"
                               "c\xE2\x80\xA8"
                               "d\r\ne")) == (V{"a\x0b"
                                                "b\x1c"
                                                "c\xE2\x80\xA8"
                                                "d\r",
                                                "e"}));
}

void TestPySplitLines() {
  DSig::Test::Suite("PySplitLines (str.splitlines(), 03b §4.3.1, 06 §6.1)");
  using V = std::vector<std::string>;
  // 03b §4.3.1 examples
  CHECK(Strings(PySplitLines("a\n")) == V{"a"});
  CHECK(Strings(PySplitLines("a\n\n")) == (V{"a", ""}));
  CHECK(Strings(PySplitLines("\n")) == V{""});
  CHECK(Strings(PySplitLines("")).empty());
  CHECK(Strings(PySplitLines("a\n\r")) == (V{"a", ""}));
  CHECK(Strings(PySplitLines("a\r\r\n")) == (V{"a", ""}));
  // 06 §6.1 probe: "xyz\x0bq\x1cr\u2028s" -> ['xyz','q','r','s']
  CHECK(Strings(PySplitLines("xyz\x0b"
                             "q\x1c"
                             "r\xE2\x80\xA8s")) == (V{"xyz", "q", "r", "s"}));
  // 07 §10.11.1: 'a\x0bb\x1cc\u2028d\r\ne' -> ['a','b','c','d','e']
  CHECK(Strings(PySplitLines("a\x0b"
                             "b\x1c"
                             "c\xE2\x80\xA8"
                             "d\r\ne")) == (V{"a", "b", "c", "d", "e"}));
  // "\r\n" is one separator; "\n\r" is two
  CHECK(Strings(PySplitLines("\r\n\r\n")) == (V{"", ""}));
  CHECK(Strings(PySplitLines("a\r\n")) == V{"a"});
  CHECK(Strings(PySplitLines("a\n\rb")) == (V{"a", "", "b"}));
  CHECK(Strings(PySplitLines("a\rb")) == (V{"a", "b"}));
  CHECK(Strings(PySplitLines("\r")) == V{""});
  // every separator of the enumerated set, alone, leading, trailing, doubled
  const std::vector<std::string> Seps{"\n", "\x0b", "\x0c", "\r", "\x1c", "\x1d", "\x1e", "\xC2\x85", "\xE2\x80\xA8",
                                      "\xE2\x80\xA9", "\r\n"};
  for (const std::string& Sep : Seps) {
    CHECK(Strings(PySplitLines(Sep)) == V{""});
    CHECK(Strings(PySplitLines("a" + Sep)) == V{"a"});
    CHECK(Strings(PySplitLines(Sep + "a")) == (V{"", "a"}));
    CHECK(Strings(PySplitLines("a" + Sep + "b")) == (V{"a", "b"}));
    CHECK(Strings(PySplitLines("a" + Sep + Sep + "b")) == (V{"a", "", "b"}));
  }
  // near misses are not separators: U+0084, U+0086, U+001F, U+2027, U+202A, and the raw byte 0x85 as a
  // continuation of another code point (U+0145 is C5 85)
  const std::vector<std::string> NotSeps{"\xC2\x84", "\xC2\x86", "\x1f", "\xE2\x80\xA7", "\xE2\x80\xAA", "\xC5\x85",
                                         "\t", " "};
  for (const std::string& S : NotSeps) {
    CHECK(Strings(PySplitLines("a" + S + "b")) == V{"a" + S + "b"});
  }
  // U+2029 then U+0085
  CHECK(Strings(PySplitLines("a\xE2\x80\xA9\xC2\x85"
                             "b")) == (V{"a", "", "b"}));
}

void TestSplitVectors() {
  DSig::Test::Suite("splitlines / split vectors (splitlines_examples.jsonl, splitlines_fuzz.txt)");
  const std::string Dir = DSig::Test::TestDataDir() + "/vectors/textdiff/";
  const auto Examples = ReadFile(Dir + "splitlines_examples.jsonl");
  const auto Fuzz = ReadFile(Dir + "splitlines_fuzz.txt");
  CHECK(Examples.has_value());
  CHECK(Fuzz.has_value());
  if (!Examples || !Fuzz) {
    return;
  }
  int Count = 0;
  for (const std::string& Line : FileLines(*Examples)) {
    if (Line.empty()) {
      continue;
    }
    const JsonValue Rec = JsonParse(Line);
    const std::string& S = Rec.At("s").AsString();
    const auto Lines = Strings(PySplitLines(S));
    const auto Want = JsonStrings(Rec.At("splitlines"));
    if (Lines != Want) {
      DSig::Test::Note("splitlines mismatch for " + Line);
    }
    CHECK(Lines == Want);
    CHECK(Strings(PySplitNewline(S)) == JsonStrings(Rec.At("split_nl")));
    ++Count;
  }
  DSig::Test::Note(std::to_string(Count) + " explicit strings");
  CHECK(Count > 600);

  const auto Lines = FileLines(*Fuzz);
  CHECK(Lines.size() >= 2);
  if (Lines.size() < 2) {
    return;
  }
  const JsonValue Header = JsonParse(Lines[1]);
  const uint64_t Seed = Header.At("seed").AsUInt64();
  const uint64_t Block = Header.At("block").AsUInt64();
  const uint64_t MaxFragments = Header.At("max_fragments").AsUInt64();
  const std::vector<std::string> Fragments = JsonStrings(Header.At("fragments"));
  uint64_t NumStrings = 0;
  for (size_t L = 2; L < Lines.size(); ++L) {
    if (Lines[L].empty()) {
      continue;
    }
    std::istringstream In(Lines[L]);
    uint64_t BlockIndex = 0, NStrings = 0, Pieces = 0;
    std::string H1, H2;
    In >> BlockIndex >> NStrings >> Pieces >> H1 >> H2;
    CHECK_NUM_EQ(NStrings, Block);
    DSig::Sha256 Hash1;
    DSig::Sha256 Hash2;
    uint64_t GotPieces = 0;
    for (uint64_t I = BlockIndex * Block; I < (BlockIndex + 1) * Block; ++I) {
      SplitMix64 R = CaseRng(Seed, I);
      const uint64_t Count2 = R.Below(MaxFragments + 1);
      std::string S;
      for (uint64_t K = 0; K < Count2; ++K) {
        S += R.Pick(Fragments);
      }
      const auto SplitLinesResult = PySplitLines(S);
      GotPieces += SplitLinesResult.size();
      Hash1.Update(FrameList(SplitLinesResult));
      Hash2.Update(FrameList(PySplitNewline(S)));
      ++NumStrings;
    }
    CHECK_NUM_EQ(GotPieces, Pieces);
    CHECK_TEXT_EQ(Hash1.FinishHex().substr(0, 16), H1);
    CHECK_TEXT_EQ(Hash2.FinishHex().substr(0, 16), H2);
  }
  DSig::Test::Note(std::to_string(NumStrings) + " fuzz strings (splitlines and split)");
  CHECK(NumStrings >= 40000);
}

// ------------------------------------------------------------------------------------------ 2. names
void TestCppNames() {
  DSig::Test::Suite("CppNamesFindAll (CPP_NAMES_RE, D:114; 03b §4.3.3; 06 §6.3-§6.4; 07 §10.11.1)");
  using V = std::vector<std::string>;
  // 03b §4.3.3 examples (verified with re.findall there)
  CHECK(Strings(CppNamesFindAll("call Foo::Barbaz::x")) == (V{"call", "Barbaz::x"}));
  CHECK(Strings(CppNamesFindAll("call abc::defg")) == (V{"call", "defg"}));
  CHECK(Strings(CppNamesFindAll("push qword ptr [rax]")) == (V{"push", "qword"}));
  CHECK(Strings(CppNamesFindAll("mov eax, 0x401000")) == V{"x401000"});
  CHECK(Strings(CppNamesFindAll("12abcd")) == V{"abcd"});
  // 06 §6.3 / §6.4 probes
  CHECK(Strings(CppNamesFindAll("jmp mov call push lea test")) == (V{"call", "push", "test"}));
  CHECK(Strings(CppNamesFindAll("std::vector::push_back")) == V{"vector::push_back"});
  // 07 §10.11.1: U+017F and U+212A are letters under re.I
  CHECK(Strings(CppNamesFindAll("\xC5\xBF"
                                "ub_1234")) == V{"\xC5\xBF"
                                                 "ub_1234"});
  CHECK(Strings(CppNamesFindAll("\xE2\x84\xAA"
                                "ernel")) == V{"\xE2\x84\xAA"
                                               "ernel"});
  // "{3,}" counts code points: 4 special letters (9 bytes) match, 3 (6 bytes) do not
  CHECK(Strings(CppNamesFindAll("\xC4\xB0\xC4\xB1\xC5\xBF\xE2\x84\xAA")) == V{"\xC4\xB0\xC4\xB1\xC5\xBF\xE2\x84\xAA"});
  CHECK(Strings(CppNamesFindAll("\xC4\xB0\xC4\xB1\xC5\xBF")).empty());
  // "::" extensions (re-checked with re.findall)
  CHECK(Strings(CppNamesFindAll("abcd::")) == V{"abcd"});
  CHECK(Strings(CppNamesFindAll("abcd:::e")) == V{"abcd"});
  CHECK(Strings(CppNamesFindAll("abcd::1x")) == V{"abcd::1x"});
  CHECK(Strings(CppNamesFindAll("x::abcd")) == V{"abcd"});
  CHECK(Strings(CppNamesFindAll("abcd::_::efgh")) == V{"abcd::_::efgh"});
  CHECK(Strings(CppNamesFindAll("abcd::efgh::")) == V{"abcd::efgh"});
  CHECK(Strings(CppNamesFindAll("abcd::\xC4\xB0x")) == V{"abcd::\xC4\xB0x"});
  // other non-ASCII code points are separators: "ab" + U+00E9 + "cdef" -> ['cdef']
  CHECK(Strings(CppNamesFindAll("ab\xC3\xA9"
                                "cdef")) == V{"cdef"});
  // near neighbours of the special letters are not letters (U+0132 C4 B2, U+017E C5 BE, U+212B E2 84 AB)
  CHECK(Strings(CppNamesFindAll("ab\xC4\xB2"
                                "cd")).empty());
  CHECK(Strings(CppNamesFindAll("ab\xC5\xBE"
                                "cd")).empty());
  CHECK(Strings(CppNamesFindAll("ab\xE2\x84\xAB"
                                "cd")).empty());
  CHECK(Strings(CppNamesFindAll("")).empty());
  CHECK(Strings(CppNamesFindAll("abc")).empty());
  CHECK(Strings(CppNamesFindAll("____")) == V{"____"});
  CHECK(Strings(CppNamesFindAll("1234")).empty());
  // the headers of the unified diff contribute nothing (03b §4.3.2 quirk 2)
  CHECK(Strings(CppNamesFindAll("--- \n-call foo_old")) == (V{"call", "foo_old"}));
}

void TestNamesVectors() {
  DSig::Test::Suite("CppNamesFindAll vectors (names_examples.jsonl, names_fuzz.txt: re.findall(CPP_NAMES_RE, s, re.I))");
  const std::string Dir = DSig::Test::TestDataDir() + "/vectors/textdiff/";
  const auto Examples = ReadFile(Dir + "names_examples.jsonl");
  const auto Fuzz = ReadFile(Dir + "names_fuzz.txt");
  CHECK(Examples.has_value());
  CHECK(Fuzz.has_value());
  if (!Examples || !Fuzz) {
    return;
  }
  int Count = 0;
  for (const std::string& Line : FileLines(*Examples)) {
    if (Line.empty()) {
      continue;
    }
    const JsonValue Rec = JsonParse(Line);
    const auto Got = Strings(CppNamesFindAll(Rec.At("s").AsString()));
    const auto Want = JsonStrings(Rec.At("names"));
    if (Got != Want) {
      DSig::Test::Note("names mismatch for " + Line + " got " + Joined(Got));
    }
    CHECK(Got == Want);
    ++Count;
  }
  DSig::Test::Note(std::to_string(Count) + " explicit strings");
  CHECK(Count >= 1000);

  const auto Lines = FileLines(*Fuzz);
  CHECK(Lines.size() >= 2);
  if (Lines.size() < 2) {
    return;
  }
  const JsonValue Header = JsonParse(Lines[1]);
  const uint64_t Seed = Header.At("seed").AsUInt64();
  const uint64_t Block = Header.At("block").AsUInt64();
  const uint64_t MaxFragments = Header.At("max_fragments").AsUInt64();
  const std::vector<std::string> Fragments = JsonStrings(Header.At("fragments"));
  uint64_t NumStrings = 0;
  uint64_t Special = 0;
  for (size_t L = 2; L < Lines.size(); ++L) {
    if (Lines[L].empty()) {
      continue;
    }
    std::istringstream In(Lines[L]);
    uint64_t BlockIndex = 0, NStrings = 0, Matches = 0;
    std::string Want;
    In >> BlockIndex >> NStrings >> Matches >> Want;
    CHECK_NUM_EQ(NStrings, Block);
    DSig::Sha256 Hash;
    uint64_t GotMatches = 0;
    for (uint64_t I = BlockIndex * Block; I < (BlockIndex + 1) * Block; ++I) {
      SplitMix64 R = CaseRng(Seed, I);
      const uint64_t Count2 = R.Below(MaxFragments + 1);
      std::string S;
      for (uint64_t K = 0; K < Count2; ++K) {
        S += R.Pick(Fragments);
      }
      const auto Names = CppNamesFindAll(S);
      GotMatches += Names.size();
      for (const std::string_view Name : Names) {
        if (Name.find("\xC4\xB0") != std::string_view::npos || Name.find("\xC4\xB1") != std::string_view::npos ||
            Name.find("\xC5\xBF") != std::string_view::npos || Name.find("\xE2\x84\xAA") != std::string_view::npos) {
          ++Special;
        }
      }
      Hash.Update(FrameList(Names));
      ++NumStrings;
    }
    CHECK_NUM_EQ(GotMatches, Matches);
    CHECK_TEXT_EQ(Hash.FinishHex().substr(0, 16), Want);
  }
  DSig::Test::Note(std::to_string(NumStrings) + " fuzz strings, " + std::to_string(Special) +
                   " matches containing U+0130/U+0131/U+017F/U+212A");
  CHECK(NumStrings >= 120000);
  CHECK(Special > 0);
}

// ------------------------------------------------------------------------------------------ 3. SequenceMatcher
std::vector<uint32_t> Chars(std::string_view S) {
  std::vector<uint32_t> Out;
  for (const char C : S) {
    Out.push_back(static_cast<unsigned char>(C));
  }
  return Out;
}

void TestSequenceMatcherWorkedExamples() {
  DSig::Test::Suite("SequenceMatcher worked examples (03b §5.1-§5.7; difflib.py:266-661)");
  // Tie-break: the earliest run in a, then in b (03b §5.2)
  {
    const auto A = Chars("abXab");
    const auto B = Chars("ab_ab");
    SequenceMatcher M(A, B);
    CHECK(M.FindLongestMatch(0, 5, 0, 5) == (MatchingBlock{0, 0, 2}));
  }
  {
    const auto A = Chars("ab");
    const auto B = Chars("abab");
    SequenceMatcher M(A, B);
    CHECK(M.FindLongestMatch(0, 2, 0, 4) == (MatchingBlock{0, 0, 2}));
  }
  // Popular extension after the choice: b = [P*5, q, P*5, u0..u188], a = [q,P,P,z,P,P,P,q,P,P] -> (0,5,3)
  const uint32_t P = 1000;
  const uint32_t Q = 1001;
  const uint32_t Z = 1002;
  const uint32_t X = 1003;
  {
    std::vector<uint32_t> B(5, P);
    B.push_back(Q);
    B.insert(B.end(), 5, P);
    for (uint32_t U = 0; U < 189; ++U) {
      B.push_back(U);
    }
    const std::vector<uint32_t> A{Q, P, P, Z, P, P, P, Q, P, P};
    CHECK_NUM_EQ(B.size(), 200);
    SequenceMatcher M(A, B);
    CHECK(M.FindLongestMatch(0, A.size(), 0, B.size()) == (MatchingBlock{0, 5, 3}));
  }
  // Empty DP: the block starts at (alo, blo, 0) and extends forward only (03b §5.2)
  {
    std::vector<uint32_t> B(4, P);
    for (uint32_t U = 0; U < 196; ++U) {
      B.push_back(U);
    }
    {
      const std::vector<uint32_t> A{P, X};
      SequenceMatcher M(A, B);
      CHECK(M.FindLongestMatch(0, 2, 0, 200) == (MatchingBlock{0, 0, 1}));
    }
    {
      const std::vector<uint32_t> A{X, P};
      SequenceMatcher M(A, B);
      CHECK(M.FindLongestMatch(0, 2, 0, 200) == (MatchingBlock{0, 0, 0}));
      CHECK(M.GetMatchingBlocks() == (std::vector<MatchingBlock>{{2, 200, 0}}));
      CHECK_TEXT_EQ(Bits(M.Ratio()), Bits(0.0));
      CHECK_TEXT_EQ(Bits(M.QuickRatio()), Bits(2.0 * 1.0 / 202.0));  // 0.009900990099009901
    }
  }
  // Autojunk: b = [u0..u195, P,P,P,P], a = [P,P,P,P] -> [(4,200,0)], ratio 0; autojunk off keeps the run
  {
    std::vector<uint32_t> B;
    for (uint32_t U = 0; U < 196; ++U) {
      B.push_back(U);
    }
    B.insert(B.end(), 4, P);
    const std::vector<uint32_t> A(4, P);
    SequenceMatcher On(A, B, true);
    CHECK(On.GetMatchingBlocks() == (std::vector<MatchingBlock>{{4, 200, 0}}));
    CHECK_TEXT_EQ(Bits(On.Ratio()), Bits(0.0));
    SequenceMatcher Off(A, B, false);
    CHECK(Off.GetMatchingBlocks() == (std::vector<MatchingBlock>{{0, 196, 4}, {4, 200, 0}}));
    CHECK_TEXT_EQ(Bits(Off.Ratio()), Bits(2.0 * 4.0 / 204.0));  // 0.0392156862745098
  }
  // ntest = n // 100 + 1, popular iff count > ntest, only for n >= 200 (03b §5.1). a = [P], b = n unique
  // fillers with `copies` P planted at 1, 8, 15, ...
  {
    struct Row {
      size_t N;
      size_t Copies;
      MatchingBlock Want;
    };
    const std::vector<Row> Rows{{199, 3, {0, 1, 1}}, {199, 4, {0, 1, 1}}, {200, 3, {0, 1, 1}}, {200, 4, {0, 0, 0}},
                                {299, 3, {0, 1, 1}}, {299, 4, {0, 0, 0}}, {300, 4, {0, 1, 1}}, {300, 5, {0, 0, 0}}};
    for (const Row& R : Rows) {
      std::vector<uint32_t> B;
      for (uint32_t U = 0; U < R.N; ++U) {
        B.push_back(U);
      }
      for (size_t K = 0; K < R.Copies; ++K) {
        B[1 + K * 7] = P;
      }
      const std::vector<uint32_t> A{P};
      SequenceMatcher M(A, B);
      CHECK(M.FindLongestMatch(0, 1, 0, R.N) == R.Want);
    }
  }
  // Only b is purged: the same popular element in a is irrelevant (asymmetric, 03b §5.1)
  {
    std::vector<uint32_t> A;
    for (uint32_t U = 0; U < 196; ++U) {
      A.push_back(U);
    }
    A.insert(A.end(), 4, P);
    const std::vector<uint32_t> B(4, P);
    SequenceMatcher M(A, B);
    CHECK(M.GetMatchingBlocks() == (std::vector<MatchingBlock>{{196, 0, 4}, {200, 4, 0}}));
  }
  // difflib docstring (difflib.py:612-618): "abcd" vs "bcde" -> 0.75, 0.75, 1.0
  {
    const auto A = Chars("abcd");
    const auto B = Chars("bcde");
    SequenceMatcher M(A, B);
    CHECK_TEXT_EQ(Bits(M.Ratio()), Bits(0.75));
    CHECK_TEXT_EQ(Bits(M.QuickRatio()), Bits(0.75));
    CHECK_TEXT_EQ(Bits(M.RealQuickRatio()), Bits(1.0));
    CHECK_TEXT_EQ(OpcodesText(M.GetOpcodes()), "(delete,0,1,0,0)(equal,1,4,0,3)(insert,4,4,3,4)");
  }
  // Empty sequences: ratio 1.0 (_calculate_ratio, difflib.py:39-42), blocks [(0,0,0)], no opcodes, no groups
  {
    const std::vector<uint32_t> Empty;
    SequenceMatcher M(Empty, Empty);
    CHECK_TEXT_EQ(Bits(M.Ratio()), Bits(1.0));
    CHECK_TEXT_EQ(Bits(M.QuickRatio()), Bits(1.0));
    CHECK_TEXT_EQ(Bits(M.RealQuickRatio()), Bits(1.0));
    CHECK(M.GetMatchingBlocks() == (std::vector<MatchingBlock>{{0, 0, 0}}));
    CHECK(M.GetOpcodes().empty());
    CHECK(M.GetGroupedOpcodes(3).empty());
  }
  // 03b §5.5: a empty, b non-empty -> one group [('insert',0,0,0,lb)]; identical non-empty -> nothing
  {
    const std::vector<uint32_t> Empty;
    const std::vector<uint32_t> B{7, 8};
    SequenceMatcher M(Empty, B);
    const auto Groups = M.GetGroupedOpcodes(3);
    CHECK_NUM_EQ(Groups.size(), 1);
    CHECK(Groups.size() == 1 && OpcodesText(Groups[0]) == "(insert,0,0,0,2)");
    SequenceMatcher Same(B, B);
    CHECK(Same.GetGroupedOpcodes(3).empty());
  }
  // Grouping at > 2n equal lines, n = 3 and n = 0 (verified with get_grouped_opcodes)
  {
    const auto A = Chars("abcdefghijklmnop");
    const auto B = Chars("abcdXfghijklmnoY");
    SequenceMatcher M(A, B);
    const auto G3 = M.GetGroupedOpcodes(3);
    CHECK_NUM_EQ(G3.size(), 2);
    CHECK(G3.size() == 2 && OpcodesText(G3[0]) == "(equal,1,4,1,4)(replace,4,5,4,5)(equal,5,8,5,8)");
    CHECK(G3.size() == 2 && OpcodesText(G3[1]) == "(equal,12,15,12,15)(replace,15,16,15,16)");
    const auto G0 = M.GetGroupedOpcodes(0);
    CHECK_NUM_EQ(G0.size(), 2);
    CHECK(G0.size() == 2 && OpcodesText(G0[0]) == "(equal,4,4,4,4)(replace,4,5,4,5)(equal,5,5,5,5)");
    CHECK(G0.size() == 2 && OpcodesText(G0[1]) == "(equal,15,15,15,15)(replace,15,16,15,16)");
    // get_grouped_opcodes trims the cached opcode list in place, as Python does (difflib.py:576-581)
    CHECK_TEXT_EQ(OpcodesText(M.GetOpcodes()), "(equal,4,4,4,4)(replace,4,5,4,5)(equal,5,15,5,15)(replace,15,16,15,16)");
  }
  // ...so the call order is observable (verified on CPython 3.13.12): n=3 then get_opcodes, and n=0 then n=3
  {
    const auto A = Chars("abcdefghijklmnop");
    const auto B = Chars("abcdXfghijklmnoY");
    SequenceMatcher M3(A, B);
    (void)M3.GetGroupedOpcodes(3);
    CHECK_TEXT_EQ(OpcodesText(M3.GetOpcodes()),
                  "(equal,1,4,1,4)(replace,4,5,4,5)(equal,5,15,5,15)(replace,15,16,15,16)");
    SequenceMatcher M0(A, B);
    (void)M0.GetGroupedOpcodes(0);
    const auto G = M0.GetGroupedOpcodes(3);
    CHECK_NUM_EQ(G.size(), 2);
    CHECK(G.size() == 2 && OpcodesText(G[0]) == "(equal,4,4,4,4)(replace,4,5,4,5)(equal,5,8,5,8)");
    CHECK(G.size() == 2 && OpcodesText(G[1]) == "(equal,12,15,12,15)(replace,15,16,15,16)");
    // identical inputs: no group, and both fix-ups trim the single cached equal block
    const auto Same18 = Chars("xabcdefghijklmnopq");
    SequenceMatcher Same(Same18, Same18);
    CHECK(Same.GetGroupedOpcodes(3).empty());
    CHECK_TEXT_EQ(OpcodesText(Same.GetOpcodes()), "(equal,15,18,15,18)");
    // empty inputs: the fallback list is local, the cache stays empty
    const std::vector<uint32_t> Empty;
    SequenceMatcher EmptyMatcher(Empty, Empty);
    CHECK(EmptyMatcher.GetGroupedOpcodes(3).empty());
    CHECK(EmptyMatcher.GetOpcodes().empty());
  }
  // Values that are not dense ids take the hash-map path and give the same blocks
  {
    const auto A = Chars("the quick brown fox jumps over the lazy dog");
    const auto B = Chars("the quack brown fix jumped over a lazy dog!");
    std::vector<uint32_t> A2;
    std::vector<uint32_t> B2;
    for (const uint32_t V : A) {
      A2.push_back(V * 2654435761u + 0x9E3779B9u);
    }
    for (const uint32_t V : B) {
      B2.push_back(V * 2654435761u + 0x9E3779B9u);
    }
    SequenceMatcher M1(A, B);
    SequenceMatcher M2(A2, B2);
    CHECK(M1.GetMatchingBlocks() == M2.GetMatchingBlocks());
    CHECK(M1.GetOpcodes() == M2.GetOpcodes());
  }
}

void TestUnifiedDiffUnit() {
  DSig::Test::Suite("UnifiedDiff (difflib.py:1084-1161; 03b §5.6; 06 §6.2)");
  using V = std::vector<std::string>;
  auto Diff = [](std::string_view A, std::string_view B, int N = 3, std::string_view LineTerm = "") {
    const auto La = PySplitLines(A);
    const auto Lb = PySplitLines(B);
    return UnifiedDiff(La, Lb, N, LineTerm);
  };
  // 03b §4.3.2 quirk 1: a trailing change with no context after it
  CHECK(Diff("a\nb\nc\ncall foo_old", "a\nb\nc\ncall foo_new") ==
        (V{"--- ", "+++ ", "@@ -1,4 +1,4 @@", " a", " b", " c", "-call foo_old", "+call foo_new"}));
  // 03b §4.3.2 quirk 2: a change at line 1 shares the buffers with the headers
  CHECK(Diff("call alpha_one\nx1\nx2\nx3\nx4", "x1\nx2\nx3\nx4") ==
        (V{"--- ", "+++ ", "@@ -1,4 +1,3 @@", "-call alpha_one", " x1", " x2", " x3"}));
  // _format_range_unified: empty ranges give "start,0" with the line before (difflib.py:1084-1093)
  CHECK(Diff("", "x") == (V{"--- ", "+++ ", "@@ -0,0 +1 @@", "+x"}));
  CHECK(Diff("x", "") == (V{"--- ", "+++ ", "@@ -1 +0,0 @@", "-x"}));
  // nothing at all for identical or empty inputs (03b §5.5)
  CHECK(Diff("", "").empty());
  CHECK(Diff("a\nb", "a\nb").empty());
  CHECK(Diff("a\nb\n", "a\r\nb").empty());  // same lines after splitlines
  // the default lineterm "\n" (patch_diff_vulns.py:137,186) terminates only the header rows
  {
    const V A{"a", "b"};
    const V B{"a", "c"};
    const auto Va = Views(A);
    const auto Vb = Views(B);
    CHECK(UnifiedDiff(Va, Vb, 3, "\n") == (V{"--- \n", "+++ \n", "@@ -1,2 +1,2 @@\n", " a", "-b", "+c"}));
  }
  // two hunks, replace rows emitted "-" first then "+"
  CHECK(Diff("a\nb\nc\nd\ne\nf\ng\nh\ni\nj\nk\nl\nm\nn\no\np", "a\nb\nc\nd\nX\nf\ng\nh\ni\nj\nk\nl\nm\nn\no\nY") ==
        (V{"--- ", "+++ ", "@@ -2,7 +2,7 @@", " b", " c", " d", "-e", "+X", " f", " g", " h", "@@ -13,4 +13,4 @@",
           " m", " n", " o", "-p", "+Y"}));
  // negative context sizes are refused (not a Diaphora path)
  bool Threw = false;
  try {
    (void)Diff("a", "b", -1);
  } catch (const std::invalid_argument&) {
    Threw = true;
  }
  CHECK(Threw);
}

void TestUdiffExamples() {
  DSig::Test::Suite("unified_diff / SequenceMatcher explicit vectors (udiff_examples.jsonl)");
  const auto Content = ReadFile(DSig::Test::TestDataDir() + "/vectors/textdiff/udiff_examples.jsonl");
  CHECK(Content.has_value());
  if (!Content) {
    return;
  }
  int Count = 0;
  int Failed = 0;
  for (const std::string& Line : FileLines(*Content)) {
    if (Line.empty()) {
      continue;
    }
    const JsonValue Rec = JsonParse(Line);
    const auto A = JsonStrings(Rec.At("a"));
    const auto B = JsonStrings(Rec.At("b"));
    const int N = static_cast<int>(Rec.At("n").AsInt64());
    const std::string& LineTerm = Rec.At("lineterm").AsString();
    const auto Va = Views(A);
    const auto Vb = Views(B);
    const auto Rows = UnifiedDiff(Va, Vb, N, LineTerm);
    const auto WantRows = JsonStrings(Rec.At("rows"));

    // Same matcher usage as the generator's udiff_eval: sm (blocks, find_longest_match, ratios),
    // sm2 (get_opcodes), sm3 (get_grouped_opcodes, then get_opcodes on the trimmed cache).
    std::unordered_map<std::string, uint32_t> Ids;
    const auto Ia = Intern(A, Ids);
    const auto Ib = Intern(B, Ids);
    SequenceMatcher M(Ia, Ib);
    SequenceMatcher M2(Ia, Ib);
    SequenceMatcher M3(Ia, Ib);
    std::vector<MatchingBlock> WantBlocks;
    for (const JsonValue& T : Rec.At("blocks").Items()) {
      WantBlocks.push_back(MatchingBlock{static_cast<size_t>(T.Items()[0].AsUInt64()),
                                         static_cast<size_t>(T.Items()[1].AsUInt64()),
                                         static_cast<size_t>(T.Items()[2].AsUInt64())});
    }
    auto OpText = [](const JsonValue& Op) {
      return "(" + Op.Items()[0].AsString() + "," + Op.Items()[1].NumberText() + "," + Op.Items()[2].NumberText() +
             "," + Op.Items()[3].NumberText() + "," + Op.Items()[4].NumberText() + ")";
    };
    std::string WantOpcodes;
    for (const JsonValue& Op : Rec.At("opcodes").Items()) {
      WantOpcodes += OpText(Op);
    }
    std::string WantGrouped;
    for (const JsonValue& G : Rec.At("grouped").Items()) {
      WantGrouped += "[";
      for (const JsonValue& Op : G.Items()) {
        WantGrouped += OpText(Op);
      }
      WantGrouped += "]";
    }
    std::string WantAfter;
    for (const JsonValue& Op : Rec.At("opcodes_after_grouped").Items()) {
      WantAfter += OpText(Op);
    }
    const std::string GotOpcodes = OpcodesText(M2.GetOpcodes());
    std::string GotGrouped;
    for (const auto& G : M3.GetGroupedOpcodes(N)) {
      GotGrouped += "[" + OpcodesText(G) + "]";
    }
    const std::string GotAfter = OpcodesText(M3.GetOpcodes());
    const JsonValue& Flm = Rec.At("flm");
    const MatchingBlock WantFlm{static_cast<size_t>(Flm.Items()[0].AsUInt64()),
                                static_cast<size_t>(Flm.Items()[1].AsUInt64()),
                                static_cast<size_t>(Flm.Items()[2].AsUInt64())};

    const bool Ok = Rows == WantRows && M.GetMatchingBlocks() == WantBlocks && GotOpcodes == WantOpcodes &&
                    GotGrouped == WantGrouped && GotAfter == WantAfter &&
                    M.FindLongestMatch(0, A.size(), 0, B.size()) == WantFlm &&
                    Bits(M.Ratio()) == Rec.At("ratio").AsString() &&
                    Bits(M.QuickRatio()) == Rec.At("quick_ratio").AsString() &&
                    Bits(M.RealQuickRatio()) == Rec.At("real_quick_ratio").AsString();
    CHECK(Ok);
    if (!Ok && ++Failed <= 3) {
      DSig::Test::Note("case " + Rec.At("case").NumberText() + ": rows " + std::to_string(Rows.size()) + "/" +
                       std::to_string(WantRows.size()) + " blocks " + BlocksText(M.GetMatchingBlocks()) + " want " +
                       BlocksText(WantBlocks) + " opcodes " + GotOpcodes + " want " + WantOpcodes + " grouped " +
                       GotGrouped + " want " + WantGrouped + " after " + GotAfter + " want " + WantAfter);
    }
    ++Count;
  }
  DSig::Test::Note(std::to_string(Count) + " explicit cases");
  CHECK(Count >= 200);
}

// ------------------------------------------------------------------------------------------ 4. fuzz
// Mirrors gen_textdiff_vectors.py token_text / gen_length / gen_udiff_case call for call.
std::string TokenText(uint32_t K) {
  if (K == 0) {
    return "";
  }
  if (K % 11 == 5) {
    return "\xC3\xA9" + std::to_string(K);  // U+00E9
  }
  return "L" + std::to_string(K);
}

size_t GenLength(SplitMix64& R, size_t Cap) {
  static const std::vector<size_t> Boundary{199, 200, 201};
  const uint64_t X = R.Below(100);
  size_t N = 0;
  if (X < 30) {
    N = static_cast<size_t>(R.Below(21));
  } else if (X < 50) {
    N = 190 + static_cast<size_t>(R.Below(21));
  } else if (X < 60) {
    N = R.Pick(Boundary);
  } else if (X < 85) {
    N = static_cast<size_t>(R.Below(301));
  } else {
    N = static_cast<size_t>(R.Below(1001));
  }
  return std::min(N, Cap);
}

struct UdiffCase {
  std::vector<uint32_t> A;
  std::vector<uint32_t> B;
  int N = 3;
  std::string LineTerm;
};

UdiffCase GenUdiffCase(SplitMix64& R, size_t Cap = 1000) {
  static const std::vector<uint32_t> Alphas{1, 2, 3, 5, 10, 40, 400};
  static const std::vector<size_t> Targets{199, 200, 201, 299, 300, 301};
  static const std::vector<int> OtherN{0, 1, 2, 5};
  const uint32_t Alpha = R.Pick(Alphas);
  std::vector<uint32_t> Pool;
  for (uint32_t I = 0; I < Alpha + 1; ++I) {
    Pool.push_back(static_cast<uint32_t>(R.Below(Alpha + 1)));
  }
  auto Elem = [&]() -> uint32_t {
    if (R.Below(10) < 7) {
      return R.Pick(Pool);
    }
    return Pool[0];
  };
  auto Edit = [&](std::vector<uint32_t>& Seq) {
    const uint64_t Count = R.Below(31);
    for (uint64_t K = 0; K < Count; ++K) {
      const uint64_t Op = R.Below(3);
      if (Op == 0) {
        if (!Seq.empty()) {
          const size_t Pos = static_cast<size_t>(R.Below(Seq.size()));
          Seq.erase(Seq.begin() + static_cast<std::ptrdiff_t>(Pos));
        }
      } else if (Op == 1) {
        const size_t Pos = static_cast<size_t>(R.Below(Seq.size() + 1));
        const uint32_t E = Elem();
        Seq.insert(Seq.begin() + static_cast<std::ptrdiff_t>(Pos), E);
      } else {
        if (!Seq.empty()) {
          const size_t Pos = static_cast<size_t>(R.Below(Seq.size()));
          const uint32_t E = Elem();
          Seq[Pos] = E;
        }
      }
    }
  };

  UdiffCase C;
  const uint64_t Mode = R.Below(4);
  const size_t La = GenLength(R, Cap);
  for (size_t I = 0; I < La; ++I) {
    C.A.push_back(Elem());
  }
  if (Mode == 0 || Mode == 3) {
    C.B = C.A;
    Edit(C.B);
    if (R.Below(10) < 3) {
      const size_t Tail = static_cast<size_t>(R.Below(301));
      C.B.insert(C.B.end(), Tail, Pool[0]);
    }
  } else if (Mode == 1) {
    const size_t Lb = GenLength(R, Cap);
    for (size_t I = 0; I < Lb; ++I) {
      C.B.push_back(Elem());
    }
  } else {
    const size_t Target = R.Pick(Targets);
    C.B = C.A;
    Edit(C.B);
    while (C.B.size() < Target) {
      const size_t Pos = static_cast<size_t>(R.Below(C.B.size() + 1));
      const uint32_t E = Elem();
      C.B.insert(C.B.begin() + static_cast<std::ptrdiff_t>(Pos), E);
    }
    if (C.B.size() > Target) {
      C.B.resize(Target);
    }
    const size_t NTest = Target / 100 + 1;
    const size_t Want = NTest + static_cast<size_t>(R.Below(2));
    const uint32_t Planted = Alpha + 1;
    for (size_t K = 0; K < Want; ++K) {
      size_t Idx = static_cast<size_t>(R.Below(C.B.size()));
      while (C.B[Idx] == Planted) {
        Idx = (Idx + 1) % C.B.size();
      }
      C.B[Idx] = Planted;
    }
    const uint64_t Extra = R.Below(4);
    for (uint64_t K = 0; K < Extra; ++K) {
      if (!C.A.empty()) {
        C.A[static_cast<size_t>(R.Below(C.A.size()))] = Planted;
      }
    }
  }
  if (C.B.size() > Cap) {
    C.B.resize(Cap);
  }
  if (Mode == 3) {
    std::swap(C.A, C.B);
  }
  C.N = (R.Below(10) < 8) ? 3 : R.Pick(OtherN);
  C.LineTerm = (R.Below(10) < 9) ? "" : "\n";
  return C;
}

void TestUdiffFuzz() {
  DSig::Test::Suite("unified_diff / get_matching_blocks fuzz vectors (udiff_fuzz.txt)");
  const auto Content = ReadFile(DSig::Test::TestDataDir() + "/vectors/textdiff/udiff_fuzz.txt");
  CHECK(Content.has_value());
  if (!Content) {
    return;
  }
  const auto Lines = FileLines(*Content);
  size_t L = 0;
  while (L < Lines.size() && (Lines[L].empty() || Lines[L][0] == '#')) {
    ++L;
  }
  CHECK(L < Lines.size() && Lines[L].rfind("seed ", 0) == 0);
  if (L >= Lines.size()) {
    return;
  }
  uint64_t Seed = 0;
  uint64_t Cases = 0;
  {
    std::istringstream In(Lines[L]);
    std::string SeedWord, CasesWord;
    In >> SeedWord >> Seed >> CasesWord >> Cases;
  }
  ++L;
  uint64_t Checked = 0;
  uint64_t Elements = 0;
  uint64_t Popular = 0;
  size_t Failed = 0;
  for (uint64_t K = 0; K < Cases && L < Lines.size(); ++K, ++L) {
    std::istringstream In(Lines[L]);
    size_t WantBlocks = 0, WantRows = 0;
    std::string WantHash;
    In >> WantBlocks >> WantRows >> WantHash;

    SplitMix64 R = CaseRng(Seed, K);
    const UdiffCase C = GenUdiffCase(R);
    Elements += C.A.size() + C.B.size();
    if (C.B.size() >= 200) {
      ++Popular;
    }
    std::vector<std::string> TextA;
    std::vector<std::string> TextB;
    for (const uint32_t T : C.A) {
      TextA.push_back(TokenText(T));
    }
    for (const uint32_t T : C.B) {
      TextB.push_back(TokenText(T));
    }
    const auto Va = Views(TextA);
    const auto Vb = Views(TextB);
    const auto Rows = UnifiedDiff(Va, Vb, C.N, C.LineTerm);

    // TokenText is injective, so matching on the raw tokens is matching on the lines.
    SequenceMatcher M(C.A, C.B);
    const auto& Blocks = M.GetMatchingBlocks();
    const MatchingBlock Flm = M.FindLongestMatch(0, C.A.size(), 0, C.B.size());
    const std::string Aux = std::to_string(Flm.A) + "," + std::to_string(Flm.B) + "," + std::to_string(Flm.Size) + ";" +
                            Bits(M.Ratio()) + ";" + Bits(M.QuickRatio()) + ";" + Bits(M.RealQuickRatio());
    const std::string CaseHash = Sha256Hex(BlocksHash(Blocks) + RowsHash(Rows) + Sha256Hex(Aux)).substr(0, 16);
    const bool Ok = Blocks.size() == WantBlocks && Rows.size() == WantRows && CaseHash == WantHash;
    CHECK_NUM_EQ(Blocks.size(), WantBlocks);
    CHECK_NUM_EQ(Rows.size(), WantRows);
    CHECK_TEXT_EQ(CaseHash, WantHash);
    if (!Ok && ++Failed <= 5) {
      DSig::Test::Note("udiff_fuzz case " + std::to_string(K) + " differs (la " + std::to_string(C.A.size()) + ", lb " +
                       std::to_string(C.B.size()) + ", n " + std::to_string(C.N) +
                       "); dump it with gen_textdiff_vectors.py --dump-case " + std::to_string(K));
    }
    // every 8th case: the hash-map key path (values far from dense) gives identical blocks
    if (K % 8 == 0) {
      std::vector<uint32_t> A2;
      std::vector<uint32_t> B2;
      for (const uint32_t V : C.A) {
        A2.push_back(V * 2654435761u + 0x9E3779B9u);
      }
      for (const uint32_t V : C.B) {
        B2.push_back(V * 2654435761u + 0x9E3779B9u);
      }
      SequenceMatcher M2(A2, B2);
      CHECK(M2.GetMatchingBlocks() == Blocks);
    }
    ++Checked;
  }
  DSig::Test::Note(std::to_string(Checked) + " fuzz cases, " + std::to_string(Elements) + " elements, " +
                   std::to_string(Popular) + " with len(b) >= 200 (autojunk active)");
  CHECK(Checked >= 10000);
  CHECK_NUM_EQ(Checked, Cases);
}

// ------------------------------------------------------------------------------------------ 5. corpus
struct FunctionTexts {
  std::optional<std::string> Assembly;
  std::optional<std::string> Pseudocode;
};

std::unordered_map<std::string, FunctionTexts> LoadTexts(const std::string& Id) {
  DSig::Diff::DiffDatabase Db;
  Db.OpenSingle(DSig::Test::ExportPath(Id));
  auto Stmt = Db.Prepare("select address, assembly, pseudocode from functions");
  std::unordered_map<std::string, FunctionTexts> Out;
  while (Stmt.Step()) {
    FunctionTexts T;
    if (const auto A = Stmt.TextOrNull(1)) {
      T.Assembly = std::string(*A);
    }
    if (const auto P = Stmt.TextOrNull(2)) {
      T.Pseudocode = std::string(*P);
    }
    Out.emplace(std::string(Stmt.Text(0)), std::move(T));
  }
  return Out;
}

std::vector<std::string> SplitTabs(const std::string& Line) {
  std::vector<std::string> Out;
  size_t Start = 0;
  for (;;) {
    const size_t Tab = Line.find('\t', Start);
    Out.push_back(Line.substr(Start, Tab == std::string::npos ? std::string::npos : Tab - Start));
    if (Tab == std::string::npos) {
      return Out;
    }
    Start = Tab + 1;
  }
}

void TestCorpusUnifiedDiff() {
  const char* Name = "corpus unified_diff row-list hashes (D:3040-3042 on every oracle results row)";
  if (!DSig::Test::CorpusRoot()) {
    DSig::Test::Skip(Name, "DSIG_CORPUS_ROOT not set");
    return;
  }
  const std::string Dir = DSig::Test::VectorsDir("textdiff");
  std::error_code Error;
  if (!fs::is_directory(Dir, Error)) {
    DSig::Test::Skip(Name, "no vectors; run tools/parity/gen_textdiff_vectors.py --corpus");
    return;
  }
  std::vector<std::string> Files;
  for (const auto& Entry : fs::directory_iterator(Dir, Error)) {
    const std::string File = Entry.path().filename().string();
    if (File.rfind("udiff_corpus_", 0) == 0 && Entry.path().extension() == ".txt") {
      Files.push_back(Entry.path().string());
    }
  }
  std::sort(Files.begin(), Files.end());
  if (Files.empty()) {
    DSig::Test::Skip(Name, "no udiff_corpus_*.txt in " + Dir);
    return;
  }
  DSig::Test::Suite(Name);
  size_t TotalMatched = 0;
  size_t TotalSample = 0;
  size_t Pairs = 0;
  for (const std::string& File : Files) {
    const auto Content = ReadFile(File);
    CHECK(Content.has_value());
    if (!Content) {
      continue;
    }
    std::string Pair;
    std::string MainId, MainSha, DiffId, DiffSha;
    std::vector<std::vector<std::string>> Records;
    for (const std::string& Line : FileLines(*Content)) {
      if (Line.empty() || Line[0] == '#') {
        continue;
      }
      auto Fields = SplitTabs(Line);
      if (Fields[0] == "pair" && Fields.size() == 2) {
        Pair = Fields[1];
      } else if (Fields[0] == "main" && Fields.size() == 3) {
        MainId = Fields[1];
        MainSha = Fields[2];
      } else if (Fields[0] == "diff" && Fields.size() == 3) {
        DiffId = Fields[1];
        DiffSha = Fields[2];
      } else {
        Records.push_back(std::move(Fields));
      }
    }
    if (!DSig::Test::ExportAvailable(MainId) || !DSig::Test::ExportAvailable(DiffId)) {
      DSig::Test::Skip(Pair.c_str(), "exports " + MainId + " / " + DiffId + " missing");
      continue;
    }
    // The vectors must have been computed from exactly these files. A different export means stale
    // vectors, not a native failure (oracle problems are reported separately), so the pair is skipped.
    bool MainOk = false;
    bool DiffOk = false;
    const std::string MainNow = DSig::Sha256::FileHex(DSig::Test::ExportPath(MainId), MainOk);
    const std::string DiffNow = DSig::Sha256::FileHex(DSig::Test::ExportPath(DiffId), DiffOk);
    if (!MainOk || !DiffOk || MainNow != MainSha || DiffNow != DiffSha) {
      DSig::Test::Skip(Pair.c_str(), "export sha256 differs from the vectors' (stale vectors: rerun "
                                     "tools/parity/gen_textdiff_vectors.py --corpus)");
      continue;
    }
    CHECK(MainOk && DiffOk);
    const auto Main = LoadTexts(MainId);
    const auto Diff = LoadTexts(DiffId);
    size_t Matched = 0;
    size_t Sample = 0;
    size_t Failed = 0;
    for (const auto& F : Records) {
      // kind field address1 address2 lines1 lines2 nrows rows_sha256
      CHECK_NUM_EQ(F.size(), 8);
      if (F.size() != 8) {
        continue;
      }
      const auto It1 = Main.find(F[2]);
      const auto It2 = Diff.find(F[3]);
      CHECK(It1 != Main.end() && It2 != Diff.end());
      if (It1 == Main.end() || It2 == Diff.end()) {
        continue;
      }
      const bool Asm = F[1] == "assembly";
      const auto& T1 = Asm ? It1->second.Assembly : It1->second.Pseudocode;
      const auto& T2 = Asm ? It2->second.Assembly : It2->second.Pseudocode;
      CHECK(T1.has_value() && T2.has_value());
      if (!T1 || !T2) {
        continue;
      }
      const auto Lines1 = PySplitLines(*T1);  // D:3040
      const auto Lines2 = PySplitLines(*T2);  // D:3041
      const auto Rows = UnifiedDiff(Lines1, Lines2, 3, "");  // D:3042
      const std::string Hash = RowsHash(Rows);
      const bool Ok = std::to_string(Lines1.size()) == F[4] && std::to_string(Lines2.size()) == F[5] &&
                      std::to_string(Rows.size()) == F[6] && Hash == F[7];
      CHECK(Ok);
      if (!Ok && ++Failed <= 5) {
        DSig::Test::Note(Pair + " " + F[0] + " " + F[1] + " " + F[2] + "/" + F[3] + ": lines " +
                         std::to_string(Lines1.size()) + "/" + std::to_string(Lines2.size()) + " rows " +
                         std::to_string(Rows.size()) + " want " + F[4] + "/" + F[5] + " rows " + F[6]);
      }
      (F[0] == "matched" ? Matched : Sample)++;
    }
    DSig::Test::Note(Pair + ": " + std::to_string(Matched) + " results-row diffs, " + std::to_string(Sample) +
                     " sampled cross-pair diffs");
    TotalMatched += Matched;
    TotalSample += Sample;
    ++Pairs;
  }
  DSig::Test::Note(std::to_string(Pairs) + " pairs, " + std::to_string(TotalMatched) + " results-row diffs, " +
                   std::to_string(TotalSample) + " sampled diffs");
}

}  // namespace

int main() {
  TestPySplitNewline();
  TestPySplitLines();
  TestSplitVectors();
  TestCppNames();
  TestNamesVectors();
  TestSequenceMatcherWorkedExamples();
  TestUnifiedDiffUnit();
  TestUdiffExamples();
  TestUdiffFuzz();
  TestCorpusUnifiedDiff();
  return DSig::Test::Finish();
}
