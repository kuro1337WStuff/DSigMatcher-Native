#pragma once

// Text splitting, the callee-name scanner and a literal port of CPython 3.13.12 difflib.
// Spec: 03b §4.3.1, §4.3.3, §5; 06 §6.1-§6.4 and Appendix A; 07 §10.11.1.

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace DSig::Diff {

std::vector<std::string_view> PySplitNewline(std::string_view S);      // str.split("\n")
std::vector<std::string_view> PySplitLines(std::string_view Utf8);     // str.splitlines(), 10 separators (03b §4.3.1)
std::vector<std::string_view> CppNamesFindAll(std::string_view Utf8);  // re.findall(CPP_NAMES_RE, s, re.I)[i][0], D:114

// difflib opcode tags.
enum class OpTag : uint8_t { Replace, Delete, Insert, Equal };
std::string_view OpTagName(OpTag Tag);  // "replace", "delete", "insert", "equal"

struct Opcode {
  OpTag Tag = OpTag::Equal;
  size_t I1 = 0;
  size_t I2 = 0;
  size_t J1 = 0;
  size_t J2 = 0;
  bool operator==(const Opcode&) const = default;
};

// difflib's Match(a, b, size).
struct MatchingBlock {
  size_t A = 0;
  size_t B = 0;
  size_t Size = 0;
  bool operator==(const MatchingBlock&) const = default;
};

// difflib.SequenceMatcher(None, a, b, autojunk) over interned element ids (difflib.py 3.13.12).
class SequenceMatcher {
public:
  SequenceMatcher(std::span<const uint32_t> A, std::span<const uint32_t> B, bool AutoJunk = true);
  ~SequenceMatcher();
  SequenceMatcher(const SequenceMatcher&) = delete;
  SequenceMatcher& operator=(const SequenceMatcher&) = delete;

  MatchingBlock FindLongestMatch(size_t Alo, size_t Ahi, size_t Blo, size_t Bhi) const;  // difflib.py:363-419
  const std::vector<MatchingBlock>& GetMatchingBlocks();                                 // difflib.py:440-490
  const std::vector<Opcode>& GetOpcodes();                                               // difflib.py:521-545
  std::vector<std::vector<Opcode>> GetGroupedOpcodes(int N = 3);                         // difflib.py:572-595
  double Ratio();
  double QuickRatio();
  double RealQuickRatio() const;

private:
  struct Impl;
  std::unique_ptr<Impl> Impl_;
};

// difflib.unified_diff(a, b, fromfile='', tofile='', n=N, lineterm=LineTerm) (difflib.py:1084-1161),
// including the "--- " / "+++ " header rows.
std::vector<std::string> UnifiedDiff(std::span<const std::string_view> A, std::span<const std::string_view> B,
                                     int N = 3, std::string_view LineTerm = "");

}
