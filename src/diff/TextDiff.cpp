// L0 STUB of lane L3 (difflib port, line splitting, name scanner). L3 replaces this file with the
// literal port of difflib.py 3.13.12 (spec: 03b §4.3, §5; 06 §6, Appendix A).

#include "dsigmatcher/diff/TextDiff.h"

#include "dsigmatcher/diff/Errors.h"

namespace DSig::Diff {

std::vector<std::string_view> PySplitNewline(std::string_view) { throw StageNotImplemented("PySplitNewline (L3)"); }

std::vector<std::string_view> PySplitLines(std::string_view) { throw StageNotImplemented("PySplitLines (L3)"); }

std::vector<std::string_view> CppNamesFindAll(std::string_view) {
  throw StageNotImplemented("CppNamesFindAll (L3)");
}

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

struct SequenceMatcher::Impl {};

SequenceMatcher::SequenceMatcher(std::span<const uint32_t>, std::span<const uint32_t>, bool) {
  throw StageNotImplemented("SequenceMatcher (L3)");
}

SequenceMatcher::~SequenceMatcher() = default;

MatchingBlock SequenceMatcher::FindLongestMatch(size_t, size_t, size_t, size_t) const {
  throw StageNotImplemented("SequenceMatcher::FindLongestMatch (L3)");
}

const std::vector<MatchingBlock>& SequenceMatcher::GetMatchingBlocks() {
  throw StageNotImplemented("SequenceMatcher::GetMatchingBlocks (L3)");
}

const std::vector<Opcode>& SequenceMatcher::GetOpcodes() {
  throw StageNotImplemented("SequenceMatcher::GetOpcodes (L3)");
}

std::vector<std::vector<Opcode>> SequenceMatcher::GetGroupedOpcodes(int) {
  throw StageNotImplemented("SequenceMatcher::GetGroupedOpcodes (L3)");
}

double SequenceMatcher::Ratio() { throw StageNotImplemented("SequenceMatcher::Ratio (L3)"); }

double SequenceMatcher::QuickRatio() { throw StageNotImplemented("SequenceMatcher::QuickRatio (L3)"); }

double SequenceMatcher::RealQuickRatio() const {
  throw StageNotImplemented("SequenceMatcher::RealQuickRatio (L3)");
}

std::vector<std::string> UnifiedDiff(std::span<const std::string_view>, std::span<const std::string_view>, int,
                                     std::string_view) {
  throw StageNotImplemented("UnifiedDiff (L3)");
}

}
