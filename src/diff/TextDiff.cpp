// Lane L3: line splitting, the callee-name scanner and a literal port of CPython 3.13.12 difflib.
//
// Reference: <python>/Lib/difflib.py, 2056 lines, md5 60d095550edf66222f142d8bbb9feff5 (03b §1).
// "difflib.py:N" below cites that file; "D:N" cites diaphora.py at 3.4.2-4-g621ec26.
// Spec: 03b §4.3.1 (splitlines), §4.3.3 (CPP_NAMES_RE), §5 (SequenceMatcher / unified_diff);
// 06 §6.1-§6.4 and Appendix A; 07 §10.11.1.
//
// Every call site in the default diff uses SequenceMatcher(None, a, b) (isjunk=None, autojunk=True):
// unified_diff builds it at difflib.py:1138, Diaphora's quick_ratio at D:159-165. With isjunk=None
// `bjunk` is always empty (difflib.py:285-292), so the junk-extension loops of find_longest_match
// (difflib.py:410-417) can never run and `not isbjunk(...)` (difflib.py:395, 399) is always true.
// They are therefore not ported; the public API has no isjunk parameter.

#include "dsigmatcher/diff/TextDiff.h"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>

namespace DSig::Diff {

// ---------------------------------------------------------------------------------------------
// str.split("\n"): D:159 / D:170 (quick_ratio / real_quick_ratio) and scripts/patch_diff_vulns.py:137,
// 186. Python's split with an explicit separator keeps empty pieces, so "" gives [""] and a trailing
// "\n" gives a trailing "" (03b §5.8).
std::vector<std::string_view> PySplitNewline(std::string_view S) {
  std::vector<std::string_view> Out;
  size_t Start = 0;
  for (;;) {
    const size_t Pos = S.find('\n', Start);
    if (Pos == std::string_view::npos) {
      Out.push_back(S.substr(Start));
      return Out;
    }
    Out.push_back(S.substr(Start, Pos - Start));
    Start = Pos + 1;
  }
}

// ---------------------------------------------------------------------------------------------
// str.splitlines(keepends=False): D:3040-3041. The line-break set on Python 3.13.12 is exactly
// U+000A, U+000B, U+000C, U+000D, U+001C, U+001D, U+001E, U+0085, U+2028, U+2029 (03b §4.3.1, enumerated
// over all code points; re-checked for this lane). "\r\n" is one separator and a trailing separator
// yields no trailing empty element; "" gives [].
//
// The structure follows CPython's stringlib splitlines: find the next break, append [j, eol), consume
// the break ("\r\n" as one), continue from there; the loop ends when the scan position reaches the end,
// so no element is appended after a final break.
//
// Byte-level detection is exact for valid UTF-8: 0xC2 and 0xE2 are lead bytes that never occur as
// continuation bytes, so "C2 85" is always U+0085 and "E2 80 A8" / "E2 80 A9" are always U+2028 /
// U+2029. Invalid UTF-8 never reaches splitlines in Python (sqlite3's fetch raises first, 03b open
// question 4); on such input this port simply applies the same byte patterns.
namespace {

// Byte length of the line break starting at S[I], or 0. "\r\n" is handled by the caller.
size_t LineBreakAt(std::string_view S, size_t I) {
  const auto C = static_cast<unsigned char>(S[I]);
  switch (C) {
    case 0x0A:
    case 0x0B:
    case 0x0C:
    case 0x0D:
    case 0x1C:
    case 0x1D:
    case 0x1E:
      return 1;
    case 0xC2:
      return (I + 1 < S.size() && static_cast<unsigned char>(S[I + 1]) == 0x85) ? 2 : 0;
    case 0xE2:
      if (I + 2 < S.size() && static_cast<unsigned char>(S[I + 1]) == 0x80) {
        const auto C2 = static_cast<unsigned char>(S[I + 2]);
        if (C2 == 0xA8 || C2 == 0xA9) {
          return 3;
        }
      }
      return 0;
    default:
      return 0;
  }
}

}  // namespace

std::vector<std::string_view> PySplitLines(std::string_view Utf8) {
  std::vector<std::string_view> Out;
  const size_t Length = Utf8.size();
  size_t I = 0;
  size_t J = 0;
  while (I < Length) {
    size_t Break = 0;
    while (I < Length && (Break = LineBreakAt(Utf8, I)) == 0) {
      ++I;
    }
    const size_t Eol = I;
    if (I < Length) {
      if (Utf8[I] == '\r' && I + 1 < Length && Utf8[I + 1] == '\n') {
        I += 2;
      } else {
        I += Break;
      }
    }
    Out.push_back(Utf8.substr(J, Eol - J));
    J = I;
  }
  return Out;
}

// ---------------------------------------------------------------------------------------------
// re.findall(CPP_NAMES_RE, text, re.IGNORECASE), element [i][0] (group 1 = the whole match).
// D:114: CPP_NAMES_RE = "([a-zA-Z_][a-zA-Z0-9_]{3,}((::){0,1}[a-zA-Z0-9_]+)*)"; D:3058-3059 call it on
// "\n".join(minus / plus).
//
// Regex-free scanner of 03b §4.3.3 / 06 §6.4 (fuzzed there against re.findall, 0 mismatches):
//   at each position, a start char ([a-zA-Z_]) followed by at least 3 word chars (greedy run, so the
//   run from the start must be >= 4 code points), then zero or more "::"+word+ extensions (a "::" not
//   followed by a word char ends the match); on failure advance one code point. No word boundary at
//   the start: "0x401000" gives "x401000".
// Under re.IGNORECASE with a str pattern, [a-zA-Z] and [a-zA-Z0-9_] also match exactly four non-ASCII
// code points: U+0130, U+0131, U+017F, U+212A (enumerated over all code points in 06 §6.4 / 07 §10.11.1,
// re-checked for this lane). Every other non-ASCII code point is a non-word char. "{3,}" counts code
// points; since every word char is either ASCII or one of those four, a run length in code points is
// the number of word chars scanned.
//
// Byte-level matching of the four special letters is exact for valid UTF-8: their lead bytes 0xC4,
// 0xC5, 0xE2 never occur as continuation bytes. Advancing one byte through a non-word multi-byte code
// point is equivalent to advancing one code point, because its continuation bytes (0x80-0xBF) are
// neither ASCII word chars nor lead bytes of a special letter.
namespace {

// Byte length of the word char ([a-zA-Z0-9_] under re.I) at S[I], or 0.
size_t WordCharAt(std::string_view S, size_t I) {
  const auto C = static_cast<unsigned char>(S[I]);
  if ((C >= 'a' && C <= 'z') || (C >= 'A' && C <= 'Z') || (C >= '0' && C <= '9') || C == '_') {
    return 1;
  }
  if (C == 0xC4 && I + 1 < S.size()) {  // U+0130 C4 B0, U+0131 C4 B1
    const auto C1 = static_cast<unsigned char>(S[I + 1]);
    return (C1 == 0xB0 || C1 == 0xB1) ? 2 : 0;
  }
  if (C == 0xC5 && I + 1 < S.size()) {  // U+017F C5 BF
    return static_cast<unsigned char>(S[I + 1]) == 0xBF ? 2 : 0;
  }
  if (C == 0xE2 && I + 2 < S.size()) {  // U+212A E2 84 AA
    return (static_cast<unsigned char>(S[I + 1]) == 0x84 && static_cast<unsigned char>(S[I + 2]) == 0xAA) ? 3
                                                                                                         : 0;
  }
  return 0;
}

// [a-zA-Z_] under re.I: a word char that is not an ASCII digit.
bool StartCharAt(std::string_view S, size_t I) {
  const auto C = static_cast<unsigned char>(S[I]);
  return WordCharAt(S, I) != 0 && !(C >= '0' && C <= '9');
}

}  // namespace

std::vector<std::string_view> CppNamesFindAll(std::string_view Utf8) {
  std::vector<std::string_view> Out;
  const size_t Length = Utf8.size();
  size_t I = 0;
  while (I < Length) {
    if (StartCharAt(Utf8, I)) {
      size_t J = I + WordCharAt(Utf8, I);
      size_t Run = 1;  // code points in the greedy [a-zA-Z_][a-zA-Z0-9_]* run
      for (size_t W = 0; J < Length && (W = WordCharAt(Utf8, J)) != 0; J += W) {
        ++Run;
      }
      if (Run >= 4) {  // [a-zA-Z_][a-zA-Z0-9_]{3,}
        // ((::){0,1}[a-zA-Z0-9_]+)*: the greedy run already consumed every adjacent word char, so each
        // further repetition needs "::" followed by at least one word char.
        while (J + 2 < Length && Utf8[J] == ':' && Utf8[J + 1] == ':' && WordCharAt(Utf8, J + 2) != 0) {
          J += 2;
          for (size_t W = 0; J < Length && (W = WordCharAt(Utf8, J)) != 0; J += W) {
          }
        }
        Out.push_back(Utf8.substr(I, J - I));
        I = J;
        continue;
      }
    }
    ++I;
  }
  return Out;
}

// ---------------------------------------------------------------------------------------------

std::string_view OpTagName(OpTag Tag) {
  switch (Tag) {
    case OpTag::Replace:
      return "replace";
    case OpTag::Delete:
      return "delete";
    case OpTag::Insert:
      return "insert";
    case OpTag::Equal:
      return "equal";
  }
  return "";
}

namespace {

constexpr uint32_t kAbsent = std::numeric_limits<uint32_t>::max();

// _calculate_ratio (difflib.py:39-42): 2.0 * matches / length, or 1.0 for length 0. The integer
// operands are exact in double, so the two IEEE operations match Python's float arithmetic.
double CalculateRatio(size_t Matches, size_t Length) {
  if (Length != 0) {
    return 2.0 * static_cast<double>(Matches) / static_cast<double>(Length);
  }
  return 1.0;
}

}  // namespace

struct SequenceMatcher::Impl {
  std::vector<uint32_t> A;
  std::vector<uint32_t> B;
  bool AutoJunk = true;

  // b2j (difflib.py:278-282) over dense keys: KeyOf maps an element value to its dense key (the index
  // of its first appearance in b), B2j[key] is the ascending index list, emptied for popular elements
  // (difflib.py:295-303: they are deleted from b2j, so b2j.get() returns `nothing`). AKey[i] is the
  // dense key of a[i], or kAbsent when a[i] does not occur in b.
  std::vector<std::vector<uint32_t>> B2j;
  std::vector<uint8_t> Popular;
  std::vector<uint32_t> AKey;
  std::vector<uint32_t> BKey;

  bool HaveMatchingBlocks = false;  // self.matching_blocks is not None (difflib.py:440-441)
  std::vector<MatchingBlock> MatchingBlocks;
  bool HaveOpcodes = false;  // self.opcodes is not None (difflib.py:521-522)
  std::vector<Opcode> Opcodes;

  void ChainB();
};

// __chain_b (difflib.py:266-303) with isjunk=None.
void SequenceMatcher::Impl::ChainB() {
  const size_t N = B.size();

  // Dense keys for the element values. Values are arbitrary uint32 ids; small ones (the normal case:
  // UnifiedDiff interns lines densely) use a direct table, others a hash map.
  uint32_t MaxValue = 0;
  for (const uint32_t V : A) {
    MaxValue = std::max(MaxValue, V);
  }
  for (const uint32_t V : B) {
    MaxValue = std::max(MaxValue, V);
  }
  const bool Direct = static_cast<uint64_t>(MaxValue) < 2 * static_cast<uint64_t>(A.size() + B.size()) + 4096;
  std::vector<uint32_t> Table;
  std::unordered_map<uint32_t, uint32_t> Map;
  if (Direct) {
    Table.assign(static_cast<size_t>(MaxValue) + 1, kAbsent);
  } else {
    Map.reserve(N);
  }
  auto Lookup = [&](uint32_t V) -> uint32_t {
    if (Direct) {
      return Table[V];
    }
    const auto It = Map.find(V);
    return It == Map.end() ? kAbsent : It->second;
  };

  // for i, elt in enumerate(b): b2j.setdefault(elt, []).append(i)   (difflib.py:280-282)
  BKey.resize(N);
  for (size_t I = 0; I < N; ++I) {
    const uint32_t V = B[I];
    uint32_t Key = Lookup(V);
    if (Key == kAbsent) {
      Key = static_cast<uint32_t>(B2j.size());
      B2j.emplace_back();
      if (Direct) {
        Table[V] = Key;
      } else {
        Map.emplace(V, Key);
      }
    }
    B2j[Key].push_back(static_cast<uint32_t>(I));
    BKey[I] = Key;
  }

  // Purge popular elements (difflib.py:294-303): only when autojunk and n >= 200; ntest = n // 100 + 1;
  // popular iff len(idxs) > ntest (strict). Only b is purged; popular elements are NOT junk.
  Popular.assign(B2j.size(), 0);
  if (AutoJunk && N >= 200) {
    const size_t NTest = N / 100 + 1;
    for (size_t Key = 0; Key < B2j.size(); ++Key) {
      if (B2j[Key].size() > NTest) {
        Popular[Key] = 1;
      }
    }
    for (size_t Key = 0; Key < B2j.size(); ++Key) {
      if (Popular[Key] != 0) {
        B2j[Key].clear();
        B2j[Key].shrink_to_fit();
      }
    }
  }

  AKey.resize(A.size());
  for (size_t I = 0; I < A.size(); ++I) {
    AKey[I] = Lookup(A[I]);
  }
}

// __init__ / set_seqs / set_seq2 (difflib.py:179-182, 243-248): store a and b, then __chain_b.
SequenceMatcher::SequenceMatcher(std::span<const uint32_t> A, std::span<const uint32_t> B, bool AutoJunk)
    : Impl_(std::make_unique<Impl>()) {
  if (A.size() >= kAbsent || B.size() >= kAbsent) {
    throw std::length_error("SequenceMatcher: sequence too long");
  }
  Impl_->A.assign(A.begin(), A.end());
  Impl_->B.assign(B.begin(), B.end());
  Impl_->AutoJunk = AutoJunk;
  Impl_->ChainB();
}

SequenceMatcher::~SequenceMatcher() = default;

// find_longest_match (difflib.py:363-419), isjunk=None.
MatchingBlock SequenceMatcher::FindLongestMatch(size_t Alo, size_t Ahi, size_t Blo, size_t Bhi) const {
  const Impl& M = *Impl_;
  const auto& A = M.A;
  const auto& B = M.B;
  if (Ahi > A.size() || Bhi > B.size() || Alo > Ahi || Blo > Bhi) {
    throw std::out_of_range("SequenceMatcher::FindLongestMatch: range out of bounds");
  }

  size_t BestI = Alo;  // besti, bestj, bestsize = alo, blo, 0   (difflib.py:368)
  size_t BestJ = Blo;
  size_t BestSize = 0;

  // j2len / newj2len (difflib.py:372-388). Each row's dict holds keys j from the single b2j list of
  // that row's a[i], ascending and restricted to [blo, bhi), so a row is a vector of (j, k) in ascending
  // j, and prev.get(j-1, 0) is resolved with a monotone pointer (03b §5.2 implementation note).
  std::vector<std::pair<uint32_t, uint32_t>> Prev;
  std::vector<std::pair<uint32_t, uint32_t>> Cur;
  for (size_t I = Alo; I < Ahi; ++I) {  // for i in range(alo, ahi)
    Cur.clear();
    const uint32_t Key = M.AKey[I];
    if (Key != kAbsent) {  // b2j.get(a[i], nothing): absent and popular elements give nothing
      const std::vector<uint32_t>& Js = M.B2j[Key];
      // `if j < blo: continue` records nothing, so starting at the first j >= blo is equivalent.
      auto It = std::lower_bound(Js.begin(), Js.end(), static_cast<uint32_t>(Blo));
      size_t P = 0;
      for (; It != Js.end(); ++It) {
        const uint32_t J = *It;
        if (J >= Bhi) {  // if j >= bhi: break
          break;
        }
        // k = newj2len[j] = j2lenget(j-1, 0) + 1
        uint32_t Previous = 0;
        if (J > 0) {
          while (P < Prev.size() && Prev[P].first < J - 1) {
            ++P;
          }
          if (P < Prev.size() && Prev[P].first == J - 1) {
            Previous = Prev[P].second;
          }
        }
        const uint32_t K = Previous + 1;
        Cur.emplace_back(J, K);
        if (K > BestSize) {  // strict: the first-found run wins ties (difflib.py:386-387)
          BestI = I - K + 1;
          BestJ = J - K + 1;
          BestSize = K;
        }
      }
    }
    std::swap(Prev, Cur);  // j2len = newj2len
  }

  // Extend the best by non-junk elements on each end (difflib.py:394-401). bjunk is empty, so this
  // extends over any equal elements, popular ones included.
  while (BestI > Alo && BestJ > Blo && A[BestI - 1] == B[BestJ - 1]) {
    --BestI;
    --BestJ;
    ++BestSize;
  }
  while (BestI + BestSize < Ahi && BestJ + BestSize < Bhi && A[BestI + BestSize] == B[BestJ + BestSize]) {
    ++BestSize;
  }
  // difflib.py:410-417 (junk extension) cannot run: bjunk is empty.
  return MatchingBlock{BestI, BestJ, BestSize};
}

// get_matching_blocks (difflib.py:440-490).
const std::vector<MatchingBlock>& SequenceMatcher::GetMatchingBlocks() {
  Impl& M = *Impl_;
  if (M.HaveMatchingBlocks) {
    return M.MatchingBlocks;
  }
  const size_t La = M.A.size();
  const size_t Lb = M.B.size();

  struct Range {
    size_t Alo, Ahi, Blo, Bhi;
  };
  std::vector<Range> Queue{Range{0, La, 0, Lb}};  // queue = [(0, la, 0, lb)]
  std::vector<MatchingBlock> Blocks;
  while (!Queue.empty()) {
    const Range R = Queue.back();  // queue.pop()
    Queue.pop_back();
    const MatchingBlock X = FindLongestMatch(R.Alo, R.Ahi, R.Blo, R.Bhi);
    const size_t I = X.A;
    const size_t J = X.B;
    const size_t K = X.Size;
    if (K != 0) {  // if k is 0, there was no matching block
      Blocks.push_back(X);
      if (R.Alo < I && R.Blo < J) {
        Queue.push_back(Range{R.Alo, I, R.Blo, J});
      }
      if (I + K < R.Ahi && J + K < R.Bhi) {
        Queue.push_back(Range{I + K, R.Ahi, J + K, R.Bhi});
      }
    }
  }
  // matching_blocks.sort(): tuples (i, j, k) in lexicographic order.
  std::sort(Blocks.begin(), Blocks.end(), [](const MatchingBlock& L, const MatchingBlock& R) {
    if (L.A != R.A) {
      return L.A < R.A;
    }
    if (L.B != R.B) {
      return L.B < R.B;
    }
    return L.Size < R.Size;
  });

  // Collapse adjacent blocks (difflib.py:469-486).
  size_t I1 = 0;
  size_t J1 = 0;
  size_t K1 = 0;
  std::vector<MatchingBlock> NonAdjacent;
  for (const MatchingBlock& Block : Blocks) {
    if (I1 + K1 == Block.A && J1 + K1 == Block.B) {
      K1 += Block.Size;
    } else {
      if (K1 != 0) {
        NonAdjacent.push_back(MatchingBlock{I1, J1, K1});
      }
      I1 = Block.A;
      J1 = Block.B;
      K1 = Block.Size;
    }
  }
  if (K1 != 0) {
    NonAdjacent.push_back(MatchingBlock{I1, J1, K1});
  }
  NonAdjacent.push_back(MatchingBlock{La, Lb, 0});  // sentinel (difflib.py:488)
  M.MatchingBlocks = std::move(NonAdjacent);
  M.HaveMatchingBlocks = true;
  return M.MatchingBlocks;
}

// get_opcodes (difflib.py:521-545).
const std::vector<Opcode>& SequenceMatcher::GetOpcodes() {
  Impl& M = *Impl_;
  if (M.HaveOpcodes) {
    return M.Opcodes;
  }
  size_t I = 0;
  size_t J = 0;
  std::vector<Opcode> Answer;
  for (const MatchingBlock& Block : GetMatchingBlocks()) {
    const size_t Ai = Block.A;
    const size_t Bj = Block.B;
    const size_t Size = Block.Size;
    bool HaveTag = true;
    OpTag Tag = OpTag::Equal;
    if (I < Ai && J < Bj) {
      Tag = OpTag::Replace;
    } else if (I < Ai) {
      Tag = OpTag::Delete;
    } else if (J < Bj) {
      Tag = OpTag::Insert;
    } else {
      HaveTag = false;  // tag = ''
    }
    if (HaveTag) {
      Answer.push_back(Opcode{Tag, I, Ai, J, Bj});
    }
    I = Ai + Size;
    J = Bj + Size;
    if (Size != 0) {  // the matching blocks end with a size-0 sentinel
      Answer.push_back(Opcode{OpTag::Equal, Ai, I, Bj, J});
    }
  }
  M.Opcodes = std::move(Answer);
  M.HaveOpcodes = true;
  return M.Opcodes;
}

// get_grouped_opcodes (difflib.py:572-595). Python binds `codes` to the list cached by get_opcodes and
// rewrites codes[0] / codes[-1] in place, so a later get_opcodes() or get_grouped_opcodes(n) on the same
// matcher sees the trimmed equal blocks. That is ported literally (the cache is modified), except when
// the cache is empty: `codes = [("equal", 0, 1, 0, 1)]` rebinds the local name and leaves the cache
// alone. 03b §5.5 suggests working on a copy because unified_diff (difflib.py:1138) uses a fresh matcher
// and consumes the generator once, so Diaphora cannot observe the difference; the literal form keeps
// every call sequence identical to Python. The generator is evaluated eagerly, which is the same as
// consuming it fully. Diaphora only ever uses n=3 (the unified_diff default, D:3042;
// scripts/patch_diff_vulns.py:137,186). A negative n makes Python produce negative indices that later act
// as slice offsets from the end; that is not ported and is refused.
std::vector<std::vector<Opcode>> SequenceMatcher::GetGroupedOpcodes(int N) {
  if (N < 0) {
    throw std::invalid_argument("SequenceMatcher::GetGroupedOpcodes: negative context size is not supported");
  }
  const size_t Nn = static_cast<size_t>(N);
  GetOpcodes();  // codes = self.get_opcodes()
  std::vector<Opcode> Fallback;
  std::vector<Opcode>& Codes = Impl_->Opcodes.empty() ? Fallback : Impl_->Opcodes;
  if (Codes.empty()) {
    Codes.push_back(Opcode{OpTag::Equal, 0, 1, 0, 1});
  }
  // Fix up leading and trailing groups if they show no changes. With n >= 0 every value stays in
  // [i1, i2] / [j1, j2], so size_t arithmetic is exact.
  if (Codes.front().Tag == OpTag::Equal) {
    Opcode& C = Codes.front();
    C.I1 = std::max(C.I1, C.I2 >= Nn ? C.I2 - Nn : 0);
    C.J1 = std::max(C.J1, C.J2 >= Nn ? C.J2 - Nn : 0);
  }
  if (Codes.back().Tag == OpTag::Equal) {
    Opcode& C = Codes.back();
    C.I2 = std::min(C.I2, C.I1 + Nn);
    C.J2 = std::min(C.J2, C.J1 + Nn);
  }

  const size_t TwoN = Nn + Nn;  // nn = n + n
  std::vector<std::vector<Opcode>> Groups;
  std::vector<Opcode> Group;
  for (Opcode C : Codes) {
    // End the current group and start a new one whenever there is a large range with no changes.
    if (C.Tag == OpTag::Equal && C.I2 - C.I1 > TwoN) {
      Group.push_back(Opcode{C.Tag, C.I1, std::min(C.I2, C.I1 + Nn), C.J1, std::min(C.J2, C.J1 + Nn)});
      Groups.push_back(std::move(Group));
      Group.clear();
      C.I1 = std::max(C.I1, C.I2 >= Nn ? C.I2 - Nn : 0);
      C.J1 = std::max(C.J1, C.J2 >= Nn ? C.J2 - Nn : 0);
    }
    Group.push_back(C);
  }
  if (!Group.empty() && !(Group.size() == 1 && Group.front().Tag == OpTag::Equal)) {
    Groups.push_back(std::move(Group));
  }
  return Groups;
}

// ratio (difflib.py:619-620).
double SequenceMatcher::Ratio() {
  size_t Matches = 0;
  for (const MatchingBlock& Block : GetMatchingBlocks()) {
    Matches += Block.Size;
  }
  return CalculateRatio(Matches, Impl_->A.size() + Impl_->B.size());
}

// quick_ratio (difflib.py:632-649): fullbcount counts the FULL b (no popular purge); avail tracks
// what is left per element while walking a.
double SequenceMatcher::QuickRatio() {
  const Impl& M = *Impl_;
  std::vector<int64_t> FullBCount(M.B2j.size(), 0);  // indexed by dense key
  for (const uint32_t Key : M.BKey) {
    ++FullBCount[Key];
  }
  std::vector<int64_t> Avail(M.B2j.size(), 0);
  std::vector<uint8_t> AvailHas(M.B2j.size(), 0);
  size_t Matches = 0;
  for (const uint32_t Key : M.AKey) {
    if (Key == kAbsent) {
      continue;  // fullbcount.get(elt, 0) == 0: numb = 0, never a match
    }
    int64_t Numb = 0;
    if (AvailHas[Key] != 0) {
      Numb = Avail[Key];
    } else {
      Numb = FullBCount[Key];
    }
    Avail[Key] = Numb - 1;
    AvailHas[Key] = 1;
    if (Numb > 0) {
      ++Matches;
    }
  }
  return CalculateRatio(Matches, M.A.size() + M.B.size());
}

// real_quick_ratio (difflib.py:658-661).
double SequenceMatcher::RealQuickRatio() const {
  const size_t La = Impl_->A.size();
  const size_t Lb = Impl_->B.size();
  return CalculateRatio(std::min(La, Lb), La + Lb);
}

// ---------------------------------------------------------------------------------------------
namespace {

// _format_range_unified (difflib.py:1084-1093).
std::string FormatRangeUnified(size_t Start, size_t Stop) {
  size_t Beginning = Start + 1;  // lines start numbering with one
  const size_t Length = Stop - Start;
  if (Length == 1) {
    return std::to_string(Beginning);
  }
  if (Length == 0) {
    Beginning -= 1;  // empty ranges begin at line just before the range
  }
  return std::to_string(Beginning) + "," + std::to_string(Length);
}

std::string Prefixed(char Prefix, std::string_view Line) {
  std::string Row;
  Row.reserve(Line.size() + 1);
  Row.push_back(Prefix);
  Row.append(Line);
  return Row;
}

}  // namespace

// unified_diff(a, b, fromfile='', tofile='', fromfiledate='', tofiledate='', n, lineterm)
// (difflib.py:1095-1161). Lines are compared as Python str, i.e. by their exact UTF-8 bytes, so they are
// interned into dense uint32 ids and matched with SequenceMatcher(None, a, b) (difflib.py:1138).
std::vector<std::string> UnifiedDiff(std::span<const std::string_view> A, std::span<const std::string_view> B,
                                     int N, std::string_view LineTerm) {
  std::unordered_map<std::string_view, uint32_t> Ids;
  Ids.reserve(A.size() + B.size());
  auto Intern = [&Ids](std::string_view Line) {
    const auto [It, Inserted] = Ids.emplace(Line, static_cast<uint32_t>(Ids.size()));
    (void)Inserted;
    return It->second;
  };
  std::vector<uint32_t> IdsA;
  IdsA.reserve(A.size());
  for (const std::string_view Line : A) {
    IdsA.push_back(Intern(Line));
  }
  std::vector<uint32_t> IdsB;
  IdsB.reserve(B.size());
  for (const std::string_view Line : B) {
    IdsB.push_back(Intern(Line));
  }

  SequenceMatcher Matcher(IdsA, IdsB, true);
  const std::vector<std::vector<Opcode>> Groups = Matcher.GetGroupedOpcodes(N);

  std::vector<std::string> Rows;
  bool Started = false;
  for (const std::vector<Opcode>& Group : Groups) {
    if (!Started) {
      Started = true;
      // '--- {}{}{}'.format(fromfile, fromdate, lineterm) with fromfile='' and no date (difflib.py:1141-1144)
      Rows.push_back("--- " + std::string(LineTerm));
      Rows.push_back("+++ " + std::string(LineTerm));
    }
    const Opcode& First = Group.front();
    const Opcode& Last = Group.back();
    const std::string File1Range = FormatRangeUnified(First.I1, Last.I2);
    const std::string File2Range = FormatRangeUnified(First.J1, Last.J2);
    Rows.push_back("@@ -" + File1Range + " +" + File2Range + " @@" + std::string(LineTerm));

    for (const Opcode& C : Group) {
      if (C.Tag == OpTag::Equal) {
        for (size_t I = C.I1; I < C.I2; ++I) {
          Rows.push_back(Prefixed(' ', A[I]));
        }
        continue;
      }
      if (C.Tag == OpTag::Replace || C.Tag == OpTag::Delete) {
        for (size_t I = C.I1; I < C.I2; ++I) {
          Rows.push_back(Prefixed('-', A[I]));
        }
      }
      if (C.Tag == OpTag::Replace || C.Tag == OpTag::Insert) {
        for (size_t J = C.J1; J < C.J2; ++J) {
          Rows.push_back(Prefixed('+', B[J]));
        }
      }
    }
  }
  return Rows;
}

}
