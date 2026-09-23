#pragma once

// Internal helpers of lane L1 (MatchState.cpp, Consumer.cpp, FinalPass.cpp, Unmatched.cpp). Private to
// src/diff; not part of the frozen API.

#include <string>
#include <string_view>

#include "dsigmatcher/diff/Errors.h"
#include "dsigmatcher/diff/Interner.h"

namespace DSig::Diff::Detail {

// Python's int(text) for a str argument with base 10, as evaluated by `"0x%x" % int(ea)` (D:1935,
// D:1943) and CChooser.add_item's `"%08x" % int(item.ea)` / `int(item.ea2)` (D:280, D:286, D:288).
// Returns true when int() accepts the text. CPython 3.13 (Objects/longobject.c PyLong_FromUnicodeObject
// -> _PyUnicode_TransformDecimalAndSpaceToASCII -> PyLong_FromString): leading and trailing
// whitespace is skipped (str.isspace() characters, which in ASCII are \t \n \v \f \r, space and
// \x1c-\x1f), then an optional '+'/'-', then one or more decimal digits where a single '_' may sit
// between two digits; nothing else may follow. Leading zeros are allowed for base 10.
// Non-ASCII text is not evaluated here (Unicode digits and spaces would be accepted by CPython):
// RequirePyInt refuses it with UnsupportedInput instead of guessing. The exporter writes every
// address as str(int) (08 §9, 06 §2.1), so none of this is reachable on real exports.
inline bool PyIntAsciiAccepts(std::string_view Text) {
  const auto IsSpace = [](char Ch) {
    return Ch == ' ' || Ch == '\t' || Ch == '\n' || Ch == '\v' || Ch == '\f' || Ch == '\r' ||
           (Ch >= '\x1c' && Ch <= '\x1f');
  };
  const auto IsDigit = [](char Ch) { return Ch >= '0' && Ch <= '9'; };
  size_t Begin = 0;
  size_t End = Text.size();
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
  for (size_t Index = Begin; Index < End; ++Index) {
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
