#pragma once

// Internal helpers of MatchState.cpp, Consumer.cpp, FinalPass.cpp and Unmatched.cpp. Private to
// src/diff; not part of the public API.

#include <cstddef>
#include <string>
#include <string_view>

#include "dsigmatcher/diff/Errors.h"
#include "dsigmatcher/diff/Interner.h"

namespace DSig::Diff::Detail {

// Python's int(text) for a str argument with base 10, as evaluated by `"0x%x" % int(ea)` (D:1935,
// D:1943) and CChooser.add_item's `"%08x" % int(item.ea)` / `int(item.ea2)` (D:280, D:286, D:288),
// under the oracle's CPython 3.13.12 (oracle/ORACLE.md). For ASCII text:
//  - PyLong_FromUnicodeObject (Objects/longobject.c) hands the text to
//    _PyUnicode_TransformDecimalAndSpaceToASCII, which returns an ASCII str UNCHANGED (it maps only
//    non-ASCII spaces and digits), and then to PyLong_FromString;
//  - PyLong_FromString skips Py_ISSPACE characters (CPython include/cpython/pyctype.h:27, class
//    PY_CTF_SPACE: space, TAB, LF, VT, FF, CR), then one optional '+' or '-'. long_from_string_base
//    then needs one or more decimal digits, with single '_' separators between two digits (no
//    leading, trailing or double '_'), and only Py_ISSPACE characters may follow. Leading zeros are
//    allowed for base 10. The separators 0x1c-0x1f, which str.isspace() accepts, are NOT Py_ISSPACE,
//    so int() rejects them;
//  - there is NO digit limit. CPython 3.11+ makes int() raise ValueError for a text with more than
//    sys.get_int_max_str_digits() digits (default 4300, include/internal/pycore_long.h:30), but
//    diaphora.py disables the limit when it is loaded (D:96-97 `sys.set_int_max_str_digits(0)`),
//    so any number of digits is accepted. The vector cases unmatched_int_digit_limit_exceeded,
//    consume_int_digit_limit and final_pass_int_digit_limit (4301 digits, real Diaphora) pin this.
// The whitespace rules were also checked on the oracle interpreter (3.13.12): int() of "\x1c" "5"
// and of "5\x1f" raises ValueError, while "\x0b" "5" and "\x0c" "5" give 5. The real-Diaphora vector
// cases unmatched_int_separator_main, unmatched_int_separator_diff and consume_int_separator raise
// at D:280 and D:1935.
// Non-ASCII text is not evaluated here (Unicode digits and spaces would be accepted by CPython):
// RequirePyInt refuses it with UnsupportedInput instead of guessing. The exporter writes every
// address as str(int) (08 §9, 06 §2.1), so none of this is reachable on real exports.
inline bool PyIntAsciiAccepts(std::string_view Text) {
  const auto IsSpace = [](char Ch) {  // Py_ISSPACE
    return Ch == ' ' || Ch == '\t' || Ch == '\n' || Ch == '\v' || Ch == '\f' || Ch == '\r';
  };
  const auto IsDigit = [](char Ch) { return Ch >= '0' && Ch <= '9'; };
  std::size_t Begin = 0;
  std::size_t End = Text.size();
  while (Begin < End && IsSpace(Text[Begin])) {
    ++Begin;
  }
  while (End > Begin && IsSpace(Text[End - 1])) {
    --End;
  }
  if (Begin < End && (Text[Begin] == '+' || Text[Begin] == '-')) {
    ++Begin;
  }
  if (Begin >= End || !IsDigit(Text[Begin])) {
    return false;
  }
  bool PrevDigit = false;
  for (std::size_t Index = Begin; Index < End; ++Index) {
    const char Ch = Text[Index];
    if (IsDigit(Ch)) {
      PrevDigit = true;
    } else if (Ch == '_' && PrevDigit && Index + 1 < End && IsDigit(Text[Index + 1])) {
      PrevDigit = false;
    } else {
      return false;
    }
  }
  return true;
}

inline bool IsAscii(std::string_view Text) {
  for (const char Ch : Text) {
    if (static_cast<unsigned char>(Ch) >= 0x80) {
      return false;
    }
  }
  return true;
}

// Throws where Python's int(ea) raises: TypeError for None, ValueError for text int() rejects.
// `Site` names the Python line, e.g. "D:1935".
inline void RequirePyInt(const Interners& Ids, AddrId Ea, std::string_view Site) {
  if (Ea == kNoneAddr) {
    throw DiaphoraWouldRaise(std::string(Site) + " TypeError",
                             "int() argument must be a string, a bytes-like object or a real number, not 'NoneType'");
  }
  const std::string_view Text = Ids.AddrText(Ea);
  if (!IsAscii(Text)) {
    throw UnsupportedInput("address text '" + std::string(Text) + "' is not ASCII: Python int() of it (" +
                           std::string(Site) + ") is not ported");
  }
  if (!PyIntAsciiAccepts(Text)) {
    throw DiaphoraWouldRaise(std::string(Site) + " ValueError",
                             "invalid literal for int() with base 10: '" + std::string(Text) + "'");
  }
}

}
