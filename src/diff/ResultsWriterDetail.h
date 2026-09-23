#pragma once

// Internal helpers of the results writer (lane L4), exposed for diff_writer only. Not part of the
// frozen API in include/dsigmatcher/diff/ResultsWriter.h.

#include <string>
#include <string_view>

namespace DSig::Diff::Detail {

// "%.7f" % v through exact big-integer arithmetic (no <charconv>): round-half-even on the exact
// binary value, the same digits Python's float formatting produces (01 §10.2). FormatRatio7 uses
// std::to_chars(fixed, 7) where the standard library provides it and this function otherwise; the
// writer suite cross-checks the two.
std::string FormatRatio7Exact(double Value);

// True when FormatRatio7 is backed by std::to_chars on this standard library.
bool FormatRatio7UsesToChars();

// Python int(str) for base 10 on ASCII text (Objects/longobject.c PyLong_FromString): surrounding
// whitespace (" \t\n\v\f\r") stripped, an optional sign, digits with single '_' separators between
// digits. Returns false where Python raises ValueError; `Negative` / `Digits` receive the sign and
// the digit string without separators or leading zeros ("0" for zero). Throws UnsupportedInput for
// non-ASCII text (Python maps Unicode digits and spaces first; that mapping is not ported).
bool PyIntParse(std::string_view Text, bool& Negative, std::string& Digits);

// Test hook (diff_writer only): WriteDiaphoraResults calls it at each step ("open", "config",
// "results", "unmatched", "committed"); a hook that throws simulates a failure or a kill at that step.
// nullptr (the default) disables it. Not thread-safe: tests set it around one call.
using WriterFaultHook = void (*)(std::string_view Step);
void SetWriterFaultHook(WriterFaultHook Hook);

}
