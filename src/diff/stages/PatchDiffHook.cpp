// The default patch-diff hook, scripts/patch_diff_vulns.py (loaded by D:2615-2619 in
// patch-diff mode). Spec: 01 §5.4, 03b §4.4, 05 §8.3, 07 §10.8. P: = scripts/patch_diff_vulns.py,
// D: = diaphora.py, both at 3.4.2-4-g621ec26.
//
// on_match (P:204-236) returns (True, ratio) on every path, so it never changes a result: what it can
// do is raise, and a raise inside check_match (D:1869-1871) aborts diff() on the main thread
// (find_same_name D:2183, search_remaining_functions via add_matches_internal D:1906), with no output
// file. This file reproduces exactly the control flow that decides whether it raises:
//   * the ratio < 1.0 gate and the str([name1, name2]) dedup set (P:206-214);
//   * find_vulns_using_assembly (P:125-175): the unified_diff walk and its IndexError at P:162;
//   * find_vulns_using_pseudocode (P:177-202), which only decides `found`;
//   * when something was found (P:222-234): CChooser.Item(...) (D:237-245 int(nodes1), int(nodes2)) and
//     CChooser.add_item (D:275-296: "%08x" % int(item.ea), "%08x" % int(item.ea2)).
// The log lines (P:224-226) and the "Interesting matches" chooser (never saved, D:2409-2416) are not
// reproduced.
//
// Text semantics. Every value is valid UTF-8 here (a row with invalid UTF-8 raises when fetched, 01
// §13). The walk only looks at ASCII: the tag character, `split(" ")[0]` (a byte split on 0x20),
// `.lower()` compared with ASCII keys, the first and last character of a mnemonic, `endswith(":")`,
// `find` / `startswith` of ASCII patterns and `strip(" ")`. Unicode lower() maps no non-ASCII
// character to an ASCII letter other than U+212A KELVIN SIGN -> 'k' (and U+0130 -> "i" + U+0307), and
// no key or tested letter is 'k' or 'i', so ASCII lowering of the bytes decides every comparison the
// same way; a UTF-8 lead or continuation byte is never an ASCII byte, so first/last-byte tests equal
// first/last-character tests.

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "EarlyPasses.h"
#include "StateDetail.h"
#include "dsigmatcher/diff/Errors.h"
#include "dsigmatcher/diff/Pipeline.h"
#include "dsigmatcher/diff/Stages.h"
#include "dsigmatcher/diff/Table.h"
#include "dsigmatcher/diff/TextDiff.h"

namespace DSig::Diff {

namespace {

// func["asm"] / func["pseudo"] (D:1797-1842: row["asm1"] = f.assembly, row["pseudo1"] = f.pseudocode):
// None, a str, or (a BLOB cell) bytes.
struct TextValue {
  bool IsNone = false;
  bool IsBytes = false;
  std::string_view Text;
};

TextValue ColumnValue(const TextColumn& Column, uint32_t Row) {
  TextValue Out;
  if (Row == kNoRow || Row >= Column.Size()) {
    throw UnsupportedInput("patch_diff_vulns on_match: the row's function is not in the export");
  }
  if (Column.Null(Row)) {
    Out.IsNone = true;
    return Out;
  }
  Out.IsBytes = Column.IsBlob[Row] != 0;
  Out.Text = Column.View(Row);
  return Out;
}

// P:137 / P:186 `x.split("\n")` on bytes raises TypeError (a str separator).
void RequireStr(const TextValue& Value, const char* Site) {
  if (Value.IsBytes) {
    throw DiaphoraWouldRaise(std::string(Site) + " TypeError", "a bytes-like object is required, not 'str'");
  }
}

char AsciiLower(char Ch) { return Ch >= 'A' && Ch <= 'Z' ? static_cast<char>(Ch - 'A' + 'a') : Ch; }

std::string AsciiLowerText(std::string_view Text) {
  std::string Out(Text);
  for (char& Ch : Out) {
    Ch = AsciiLower(Ch);
  }
  return Out;
}

// SIGNED_UNSIGNED_LIST (P:43-53): jl/jb, jle/jbe, jg/ja, jge/jae, both directions.
std::optional<std::string_view> SignedUnsignedPartner(std::string_view Lower) {
  static const std::pair<std::string_view, std::string_view> Pairs[] = {
      {"jl", "jb"}, {"jle", "jbe"}, {"jg", "ja"}, {"jge", "jae"},
      {"jb", "jl"}, {"jbe", "jle"}, {"ja", "jg"}, {"jae", "jge"}};
  for (const auto& [Key, Value] : Pairs) {
    if (Lower == Key) {
      return Value;
    }
  }
  return std::nullopt;
}

// `text.split(" ")[0]`
std::string_view FirstToken(std::string_view Text) { return Text.substr(0, Text.find(' ')); }

[[noreturn]] void RaiseIndexError() {
  throw DiaphoraWouldRaise("scripts/patch_diff_vulns.py:162 IndexError", "string index out of range");
}

// find_vulns_using_assembly (P:125-175): returns results.found.
bool FindVulnsUsingAssembly(const TextValue& Asm1, const TextValue& Asm2) {
  if (Asm1.IsNone || Asm2.IsNone) {  // P:134-135
    return false;
  }
  RequireStr(Asm1, "scripts/patch_diff_vulns.py:137");
  RequireStr(Asm2, "scripts/patch_diff_vulns.py:137");
  // P:137-138 lines = list(unified_diff(asm1.split("\n"), asm2.split("\n"))): default n=3 and
  // lineterm="\n", so the "--- ", "+++ " and "@@" rows end with "\n" and the content rows do not
  // (difflib.py:1084-1161, TextDiff.cpp).
  const std::vector<std::string_view> A = PySplitNewline(Asm1.Text);
  const std::vector<std::string_view> B = PySplitNewline(Asm2.Text);
  const std::vector<std::string> Lines = UnifiedDiff(A, B, 3, "\n");
  std::optional<std::string_view> Added;    // P:139
  std::optional<std::string_view> Removed;  // P:140
  for (const std::string& Line : Lines) {   // P:143
    // P:144 c = line[0]: every unified_diff row has at least its tag character.
    const char C = Line.empty() ? '\0' : Line[0];
    if (C != '-' && C != '+') {             // P:146
      continue;
    }
    const std::string_view Rest = std::string_view(Line).substr(1);
    if (C == '+') {                         // P:147-148
      Added = Rest;
    } else {                                // P:149-152
      if (!Rest.empty() && Rest.back() == ':') {
        continue;
      }
      Removed = Rest;
    }
    // P:154: the header rows "--- \n" / "+++ \n" set both right away (removed = "-- \n",
    // added = "++ \n"), so the check runs from the first real change on (01 §5.4 item 3).
    if (!Added || !Removed) {
      continue;
    }
    const std::string_view Mnem1 = FirstToken(*Added);    // P:156 (then .lower())
    const std::string_view Mnem2 = FirstToken(*Removed);  // P:157
    const std::string Lower1 = AsciiLowerText(Mnem1);
    const std::string Lower2 = AsciiLowerText(Mnem2);
    if (const auto Partner = SignedUnsignedPartner(Lower1)) {  // P:158
      if (*Partner == Lower2) {                               // P:159-161
        return true;  // found = True; break
      }
      continue;
    }
    // P:162 `elif mnem1[0] == "b" and mnem2[0] == "b"`: mnem1[0] raises for an empty mnemonic (an
    // added line that is empty or starts with a space); mnem2[0] only when mnem1 starts with "b".
    if (Lower1.empty()) {
      RaiseIndexError();
    }
    if (Lower1[0] != 'b') {
      continue;
    }
    if (Lower2.empty()) {
      RaiseIndexError();
    }
    if (Lower2[0] != 'b') {
      continue;
    }
    // P:164-168: exactly one of the last characters is "s" (both non-empty here).
    const char Last1 = Lower1.back();
    const char Last2 = Lower2.back();
    if ((Last1 == 's' || Last2 == 's') && Last1 != Last2) {
      return true;
    }
  }
  return false;
}

// search_pseudo_patterns (P:93-107) and search_for_added_size_check (P:109-123).
bool SearchPseudoPatterns(std::string_view Line) {
  static const std::string_view Patterns[] = {  // PATTERNS (P:18-28)
      "cpy", "printf", "strcat", "strncat", "gets", "mem", "system", "scanf", "alloc", "free", "strto",
      "ShellExecute", "WinExec", "LoadLibrary", "CreateProcess", "ProbeForWrite", "ProbeForRead", "UNC"};
  for (const std::string_view Pattern : Patterns) {
    if (Line.find(Pattern) != std::string_view::npos) {
      return true;
    }
  }
  return false;
}

bool SearchForAddedSizeCheck(std::string_view Line) {
  if (!Line.starts_with("if ")) {  // P:114
    return false;
  }
  static const std::string_view Comparisons[] = {" < ", " > ", " <= ", " >= "};  // COMPARISONS (P:30)
  for (const std::string_view Pattern : Comparisons) {
    if (Line.find(Pattern) != std::string_view::npos) {                // P:116
      if (Line.find(std::string(Pattern) + "0 ") == std::string_view::npos) {  // P:118
        return true;
      }
    }
  }
  return false;
}

// line[2:]: drops the tag and the next CHARACTER (a UTF-8 sequence of 1-4 bytes).
std::string_view AfterTwoCharacters(std::string_view Line) {
  if (Line.size() <= 1) {
    return std::string_view();
  }
  size_t Pos = 2;  // the tag is ASCII
  while (Pos < Line.size() && (static_cast<unsigned char>(Line[Pos]) & 0xC0) == 0x80) {
    ++Pos;  // continuation bytes of the second character
  }
  return Pos >= Line.size() ? std::string_view() : Line.substr(Pos);
}

std::string_view StripSpaces(std::string_view Text) {  // str.strip(" ")
  const size_t First = Text.find_first_not_of(' ');
  if (First == std::string_view::npos) {
    return std::string_view();
  }
  const size_t Last = Text.find_last_not_of(' ');
  return Text.substr(First, Last - First + 1);
}

// find_vulns_using_pseudocode (P:177-202): returns results.found.
bool FindVulnsUsingPseudocode(const TextValue& Pseudo1, const TextValue& Pseudo2) {
  if (Pseudo1.IsNone || Pseudo2.IsNone) {  // P:183-184
    return false;
  }
  RequireStr(Pseudo1, "scripts/patch_diff_vulns.py:186");
  RequireStr(Pseudo2, "scripts/patch_diff_vulns.py:186");
  const std::vector<std::string_view> A = PySplitNewline(Pseudo1.Text);
  const std::vector<std::string_view> B = PySplitNewline(Pseudo2.Text);
  const std::vector<std::string> Lines = UnifiedDiff(A, B, 3, "\n");  // P:186
  for (const std::string& Line : Lines) {                               // P:187
    const char C = Line.empty() ? '\0' : Line[0];                        // P:188
    if (C != '-' && C != '+') {                                          // P:190
      continue;
    }
    const std::string_view Source = StripSpaces(AfterTwoCharacters(Line));  // P:191
    if (SearchPseudoPatterns(Source)) {                                   // P:193
      return true;                                                        // P:199-200
    }
    if (C == '+' && SearchForAddedSizeCheck(Source)) {                    // P:194-197
      return true;
    }
  }
  return false;
}

}

void PatchDiffHookOnMatch(DiffSession& S, const HeuristicRow& Row, double Ratio) {
  // P:206 `if ratio < 1.0:`; otherwise P:236 return True, ratio.
  if (!(Ratio < 1.0)) {
    return;
  }
  // P:207-214: key = str([name1, name2]) with name1/name2 = func["name"] = row["name1"] / row["name2"]
  // (D:1798-1822); an analysed key returns at once.
  Early::PatchDiffHookState& State = S.Ext<Early::PatchDiffHookState>();
  if (!State.Dones.insert({Row.Name1, Row.Name2}).second) {
    return;
  }
  Early::EarlyFacts& Facts = S.Ext<Early::EarlyFacts>();
  ++Facts.HookAnalysed;
  const FunctionTable& Main = S.Export(Row.Side1).Functions;
  const FunctionTable& Diff = S.Export(Row.Side2).Functions;
  // P:216-218
  bool Found = FindVulnsUsingAssembly(ColumnValue(Main.Assembly, Row.Row1), ColumnValue(Diff.Assembly, Row.Row2));
  if (!Found) {
    Found = FindVulnsUsingPseudocode(ColumnValue(Main.Pseudocode, Row.Row1), ColumnValue(Diff.Pseudocode, Row.Row2));
  }
  if (!Found) {
    return;  // P:236
  }
  ++Facts.HookFound;
  // P:229-233 item = CChooser.Item(ea1, name1, ea2, name2, description, ratio, bb1, bb2) with
  // bb = func["nodes"] = row["nodes1"/"nodes2"]: Item.__init__ runs int(nodes1), int(nodes2)
  // (D:244-245); int(None) raises TypeError.
  if (!Row.Nodes1 || !Row.Nodes2) {
    throw DiaphoraWouldRaise(Row.Nodes1 ? "D:245 TypeError" : "D:244 TypeError",
                             "int() argument must be a string, a bytes-like object or a real number, not 'NoneType'");
  }
  // P:234 self.chooser.add_item(item): the "Interesting matches" title does not start with
  // "Unmatched in", so D:286 "%08x" % int(item.ea) and D:288 "%08x" % int(item.ea2) run
  // ("%.7f" % ratio and "%d" % nodes cannot raise for these values).
  Detail::RequirePyInt(S.Ids(), Row.Ea1, "D:286");
  Detail::RequirePyInt(S.Ids(), Row.Ea2, "D:288");
}

}
