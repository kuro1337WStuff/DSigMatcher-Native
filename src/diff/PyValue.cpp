// Python value semantics the diff depends on (lane L2). Spec: 03a §6.4 (float(str) for md_index),
// §7.1 (set(json.loads(constants)) with Python equality), 03b §4.1-§4.2, 08 §9.3 and H-7/H-8.
//
// Everything here is a port of CPython 3.13.12 behaviour (the oracle's Python, 03a "Environment of
// record"), cited by the CPython source it mirrors:
//   * float(str)      Objects/floatobject.c PyFloat_FromString / float_from_string_inner,
//                     Python/pystrtod.c _PyOS_ascii_strtod / _Py_parse_inf_or_nan, Python/dtoa.c
//                     _Py_dg_strtod (correctly rounded), Objects/longobject.c
//                     _Py_string_to_number_with_underscores;
//   * json.loads      Lib/json/decoder.py + Modules/_json.c (scan_once_unicode, _match_number_unicode,
//                     scanstring_unicode with strict=True, _CONSTANTS for NaN/Infinity);
//   * set semantics   Objects/setobject.c (set_add_entry keeps the first equal key; set_intersection
//                     iterates the smaller set and adds ITS keys), Objects/floatobject.c
//                     float_richcompare (exact int/float comparison);
//   * repr(float)     Python/pystrtod.c format_float_short with mode 'r' (shortest round trip,
//                     exponent form when decpt <= -4 or decpt > 16).
// This file uses no floating-point from_chars/to_chars (older Apple libc++ lacks them, 03a §5): its
// decimal to double conversion is exact big-integer arithmetic, portable to MSVC, GCC and Clang. Json.cpp
// AsDouble converts through PyFloat and Trace.cpp FormatPercent2 through the writer's exact formatter for
// the same reason; ResultsWriter.cpp uses std::to_chars only where __cpp_lib_to_chars says it exists and
// never on Apple platforms.

#include "dsigmatcher/diff/PyValue.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <limits>
#include <string>

#include "dsigmatcher/diff/Errors.h"
#include "dsigmatcher/diff/Json.h"

namespace DSig::Diff {

namespace {

// ---------------------------------------------------------------------------------------------
// Unsigned big integer, 32-bit limbs, little endian. Only what exact decimal <-> binary conversion
// needs.

class BigUInt {
public:
  BigUInt() = default;
  explicit BigUInt(uint64_t Value) {
    while (Value != 0) {
      Limbs_.push_back(static_cast<uint32_t>(Value));
      Value >>= 32;
    }
  }

  bool IsZero() const { return Limbs_.empty(); }

  void MulAdd(uint32_t Factor, uint32_t Addend) {
    uint64_t Carry = Addend;
    for (uint32_t& Limb : Limbs_) {
      const uint64_t Product = static_cast<uint64_t>(Limb) * Factor + Carry;
      Limb = static_cast<uint32_t>(Product);
      Carry = Product >> 32;
    }
    if (Carry != 0) {
      Limbs_.push_back(static_cast<uint32_t>(Carry));
    }
  }

  void MulPow10(int64_t Count) {
    static constexpr uint32_t kPow10[] = {1u,      10u,      100u,      1000u,      10000u,
                                          100000u, 1000000u, 10000000u, 100000000u, 1000000000u};
    while (Count >= 9) {
      MulAdd(1000000000u, 0);
      Count -= 9;
    }
    if (Count > 0) {
      MulAdd(kPow10[Count], 0);
    }
  }

  void MulPow5(int64_t Count) {
    while (Count >= 13) {
      MulAdd(1220703125u, 0);  // 5^13
      Count -= 13;
    }
    uint32_t Factor = 1;
    for (int64_t Index = 0; Index < Count; ++Index) {
      Factor *= 5;
    }
    if (Factor != 1) {
      MulAdd(Factor, 0);
    }
  }

  void ShiftLeft(uint64_t Bits) {
    if (IsZero() || Bits == 0) {
      return;
    }
    const size_t Words = static_cast<size_t>(Bits / 32);
    const unsigned Rest = static_cast<unsigned>(Bits % 32);
    if (Rest != 0) {
      uint32_t Carry = 0;
      for (uint32_t& Limb : Limbs_) {
        const uint32_t Next = Limb >> (32 - Rest);
        Limb = (Limb << Rest) | Carry;
        Carry = Next;
      }
      if (Carry != 0) {
        Limbs_.push_back(Carry);
      }
    }
    if (Words != 0) {
      Limbs_.insert(Limbs_.begin(), Words, 0u);
    }
  }

  void ShiftRightOne() {
    uint32_t Carry = 0;
    for (size_t Index = Limbs_.size(); Index-- > 0;) {
      const uint32_t Next = Limbs_[Index] & 1u;
      Limbs_[Index] = (Limbs_[Index] >> 1) | (Carry << 31);
      Carry = Next;
    }
    Trim();
  }

  uint64_t BitLength() const {
    if (IsZero()) {
      return 0;
    }
    uint32_t Top = Limbs_.back();
    uint64_t Bits = 0;
    while (Top != 0) {
      ++Bits;
      Top >>= 1;
    }
    return (Limbs_.size() - 1) * 32 + Bits;
  }

  static int Compare(const BigUInt& A, const BigUInt& B) {
    if (A.Limbs_.size() != B.Limbs_.size()) {
      return A.Limbs_.size() < B.Limbs_.size() ? -1 : 1;
    }
    for (size_t Index = A.Limbs_.size(); Index-- > 0;) {
      if (A.Limbs_[Index] != B.Limbs_[Index]) {
        return A.Limbs_[Index] < B.Limbs_[Index] ? -1 : 1;
      }
    }
    return 0;
  }

  // *this -= Other; requires *this >= Other.
  void Subtract(const BigUInt& Other) {
    int64_t Borrow = 0;
    for (size_t Index = 0; Index < Limbs_.size(); ++Index) {
      int64_t Value = static_cast<int64_t>(Limbs_[Index]) - Borrow -
                      (Index < Other.Limbs_.size() ? static_cast<int64_t>(Other.Limbs_[Index]) : 0);
      Borrow = 0;
      if (Value < 0) {
        Value += int64_t{1} << 32;
        Borrow = 1;
      }
      Limbs_[Index] = static_cast<uint32_t>(Value);
    }
    Trim();
  }

  // Divides in place by Divisor (< 2^32) and returns the remainder.
  uint32_t DivSmall(uint32_t Divisor) {
    uint64_t Remainder = 0;
    for (size_t Index = Limbs_.size(); Index-- > 0;) {
      const uint64_t Current = (Remainder << 32) | Limbs_[Index];
      Limbs_[Index] = static_cast<uint32_t>(Current / Divisor);
      Remainder = Current % Divisor;
    }
    Trim();
    return static_cast<uint32_t>(Remainder);
  }

  std::string ToDecimal() const {
    if (IsZero()) {
      return "0";
    }
    BigUInt Work = *this;
    std::vector<uint32_t> Chunks;  // base 10^9, little endian
    while (!Work.IsZero()) {
      Chunks.push_back(Work.DivSmall(1000000000u));
    }
    std::string Out = std::to_string(Chunks.back());
    for (size_t Index = Chunks.size() - 1; Index-- > 0;) {
      const std::string Part = std::to_string(Chunks[Index]);
      Out.append(9 - Part.size(), '0');
      Out += Part;
    }
    return Out;
  }

  static BigUInt FromDecimal(std::string_view Digits) {
    BigUInt Result;
    size_t Pos = 0;
    const size_t Head = Digits.size() % 9;
    auto Chunk = [&](size_t Count) {
      uint32_t Value = 0;
      uint32_t Scale = 1;
      for (size_t Index = 0; Index < Count; ++Index) {
        Value = Value * 10 + static_cast<uint32_t>(Digits[Pos + Index] - '0');
        Scale *= 10;
      }
      Pos += Count;
      Result.MulAdd(Scale, Value);
    };
    if (Head != 0) {
      Chunk(Head);
    }
    while (Pos < Digits.size()) {
      Chunk(9);
    }
    return Result;
  }

private:
  void Trim() {
    while (!Limbs_.empty() && Limbs_.back() == 0) {
      Limbs_.pop_back();
    }
  }

  std::vector<uint32_t> Limbs_;
};

// Python dtoa.c MAX_ABS_EXP: exponents with more digits or a larger value are clamped to this.
constexpr int64_t kMaxAbsExp = 1100000000;
// A halfway point between two doubles has at most 769 significant decimal digits, so keeping 800
// digits plus a sticky '1' preserves the correctly rounded result of any longer input.
constexpr size_t kMaxSignificantDigits = 800;

int CountLeadingZeros64(uint64_t Value) {
  int Count = 0;
  for (uint64_t Mask = uint64_t{1} << 63; Mask != 0 && (Value & Mask) == 0; Mask >>= 1) {
    ++Count;
  }
  return Count;
}

// The double nearest to Digits * 10^Exp10 (ties to even), exactly like _Py_dg_strtod.
double DecimalToDouble(bool Negative, std::string_view Digits, int64_t Exp10) {
  const double SignedZero = Negative ? -0.0 : 0.0;
  const size_t First = Digits.find_first_not_of('0');
  if (First == std::string_view::npos) {
    return SignedZero;
  }
  Digits.remove_prefix(First);
  const size_t Last = Digits.find_last_not_of('0');
  Exp10 += static_cast<int64_t>(Digits.size() - 1 - Last);
  Digits = Digits.substr(0, Last + 1);
  std::string Truncated;
  if (Digits.size() > kMaxSignificantDigits) {
    Exp10 += static_cast<int64_t>(Digits.size() - kMaxSignificantDigits - 1);
    Truncated.assign(Digits.substr(0, kMaxSignificantDigits));
    Truncated += '1';  // the dropped tail is non-zero (trailing zeros were stripped)
    Digits = Truncated;
  }
  // value lies in [10^(Magnitude-1), 10^Magnitude)
  const int64_t Magnitude = static_cast<int64_t>(Digits.size()) + Exp10;
  if (Magnitude > 310) {
    return Negative ? -std::numeric_limits<double>::infinity() : std::numeric_limits<double>::infinity();
  }
  if (Magnitude <= -324) {
    return SignedZero;  // below half of the smallest subnormal (2^-1075 ~ 2.47e-324)
  }

  BigUInt Numerator = BigUInt::FromDecimal(Digits);
  BigUInt Denominator(1);
  if (Exp10 >= 0) {
    Numerator.MulPow10(Exp10);
  } else {
    Denominator.MulPow10(-Exp10);
  }
  // Scale so that the quotient has 63 or 64 bits.
  const int64_t K = 63 - (static_cast<int64_t>(Numerator.BitLength()) - static_cast<int64_t>(Denominator.BitLength()));
  if (K > 0) {
    Numerator.ShiftLeft(static_cast<uint64_t>(K));
  } else if (K < 0) {
    Denominator.ShiftLeft(static_cast<uint64_t>(-K));
  }
  BigUInt Step = Denominator;
  Step.ShiftLeft(63);
  uint64_t Quotient = 0;
  for (int Bit = 63; Bit >= 0; --Bit) {
    if (BigUInt::Compare(Numerator, Step) >= 0) {
      Numerator.Subtract(Step);
      Quotient |= uint64_t{1} << Bit;
    }
    Step.ShiftRightOne();
  }
  const bool Sticky = !Numerator.IsZero();
  const int Bits = 64 - CountLeadingZeros64(Quotient);  // 63 or 64
  const int64_t Exp2 = Bits - 1 - K;                     // value in [2^Exp2, 2^(Exp2+1))
  if (Exp2 > 1023) {
    return Negative ? -std::numeric_limits<double>::infinity() : std::numeric_limits<double>::infinity();
  }
  const int64_t Keep = Exp2 >= -1022 ? 53 : Exp2 + 1075;  // subnormals keep fewer bits
  const int64_t Shift = Bits - Keep;
  uint64_t Kept = 0;
  bool RoundUp = false;
  if (Shift < 64) {
    Kept = Quotient >> Shift;
    const uint64_t Dropped = Quotient & ((uint64_t{1} << Shift) - 1);
    const uint64_t Half = uint64_t{1} << (Shift - 1);
    RoundUp = Dropped > Half || (Dropped == Half && (Sticky || (Kept & 1) != 0));
  } else if (Shift == 64) {
    const uint64_t Half = uint64_t{1} << 63;
    RoundUp = Quotient > Half || (Quotient == Half && Sticky);
  }
  if (RoundUp) {
    ++Kept;
  }
  // Kept <= 2^53 is exact as a double, and ldexp is exact for representable results; an overflow
  // after rounding gives inf, as Python's float() does.
  const double Result = std::ldexp(static_cast<double>(Kept), static_cast<int>(Shift - K));
  return Negative ? -Result : Result;
}

bool IsAsciiDigit(char Ch) { return Ch >= '0' && Ch <= '9'; }

// Py_ISSPACE (pyctype.c): space, \t, \n, \v, \f, \r.
bool IsPySpace(char Ch) { return Ch == ' ' || Ch == '\t' || Ch == '\n' || Ch == '\v' || Ch == '\f' || Ch == '\r'; }

bool EqualsIgnoreCase(std::string_view Text, size_t Pos, std::string_view Word) {
  if (Pos + Word.size() > Text.size()) {
    return false;
  }
  for (size_t Index = 0; Index < Word.size(); ++Index) {
    char Ch = Text[Pos + Index];
    if (Ch >= 'A' && Ch <= 'Z') {
      Ch = static_cast<char>(Ch - 'A' + 'a');
    }
    if (Ch != Word[Index]) {
      return false;
    }
  }
  return true;
}

// float() of ASCII bytes (the bytes path of PyFloat_FromString, and the str path once the text is
// known to be ASCII, where _PyUnicode_TransformDecimalAndSpaceToASCII returns it unchanged).
std::optional<double> PyFloatAscii(std::string_view Input) {
  // An embedded NUL fails both the underscore path (`p != last`) and float_from_string_inner
  // (`end != last`).
  if (Input.find('\0') != std::string_view::npos) {
    return std::nullopt;
  }
  // _Py_string_to_number_with_underscores: '_' only between two digits.
  std::string Clean;
  std::string_view Text = Input;
  if (Input.find('_') != std::string_view::npos) {
    char Prev = '\0';
    for (const char Ch : Input) {
      if (Ch == '_') {
        if (!IsAsciiDigit(Prev)) {
          return std::nullopt;
        }
      } else {
        if (Prev == '_' && !IsAsciiDigit(Ch)) {
          return std::nullopt;
        }
        Clean += Ch;
      }
      Prev = Ch;
    }
    if (Prev == '_') {
      return std::nullopt;
    }
    Text = Clean;
  }
  // float_from_string_inner: strip Py_ISSPACE on both sides; an all-space string fails.
  size_t Begin = 0;
  size_t End = Text.size();
  while (Begin < End && IsPySpace(Text[Begin])) {
    ++Begin;
  }
  if (Begin == End) {
    return std::nullopt;
  }
  while (End > Begin + 1 && IsPySpace(Text[End - 1])) {
    --End;
  }
  const std::string_view Body = Text.substr(Begin, End - Begin);

  // _Py_dg_strtod: [sign] digits [. digits] [e [sign] digits]; at least one mantissa digit.
  size_t Pos = 0;
  bool Negative = false;
  if (Pos < Body.size() && (Body[Pos] == '+' || Body[Pos] == '-')) {
    Negative = Body[Pos] == '-';
    ++Pos;
  }
  std::string Digits;
  int64_t FracDigits = 0;
  bool Any = false;
  while (Pos < Body.size() && IsAsciiDigit(Body[Pos])) {
    Digits += Body[Pos++];
    Any = true;
  }
  if (Pos < Body.size() && Body[Pos] == '.') {
    ++Pos;
    while (Pos < Body.size() && IsAsciiDigit(Body[Pos])) {
      Digits += Body[Pos++];
      ++FracDigits;
      Any = true;
    }
  }
  if (!Any) {
    // _Py_parse_inf_or_nan: [sign] (inf | infinity | nan), case-insensitive.
    size_t Probe = 0;
    bool NegativeSpecial = false;
    if (Probe < Body.size() && (Body[Probe] == '+' || Body[Probe] == '-')) {
      NegativeSpecial = Body[Probe] == '-';
      ++Probe;
    }
    if (EqualsIgnoreCase(Body, Probe, "inf")) {
      Probe += 3;
      if (EqualsIgnoreCase(Body, Probe, "inity")) {
        Probe += 5;
      }
      if (Probe != Body.size()) {
        return std::nullopt;
      }
      return NegativeSpecial ? -std::numeric_limits<double>::infinity() : std::numeric_limits<double>::infinity();
    }
    if (EqualsIgnoreCase(Body, Probe, "nan")) {
      Probe += 3;
      if (Probe != Body.size()) {
        return std::nullopt;
      }
      const double Nan = std::numeric_limits<double>::quiet_NaN();
      return NegativeSpecial ? -Nan : Nan;
    }
    return std::nullopt;
  }
  int64_t Exponent = 0;
  if (Pos < Body.size() && (Body[Pos] == 'e' || Body[Pos] == 'E')) {
    size_t Probe = Pos + 1;
    bool ExpNegative = false;
    if (Probe < Body.size() && (Body[Probe] == '+' || Body[Probe] == '-')) {
      ExpNegative = Body[Probe] == '-';
      ++Probe;
    }
    if (Probe < Body.size() && IsAsciiDigit(Body[Probe])) {
      while (Probe < Body.size() && Body[Probe] == '0') {
        ++Probe;
      }
      const size_t Start = Probe;
      int64_t Value = 0;
      while (Probe < Body.size() && IsAsciiDigit(Body[Probe])) {
        if (Value <= kMaxAbsExp) {
          Value = Value * 10 + (Body[Probe] - '0');
        }
        ++Probe;
      }
      if (Probe - Start > 8 || Value > kMaxAbsExp) {
        Value = kMaxAbsExp;  // dtoa.c: "Avoid confusion from exponents so large that e might overflow"
      }
      Exponent = ExpNegative ? -Value : Value;
      Pos = Probe;
    }
    // else: no exponent digits, the 'e' is not consumed (and then fails the end check)
  }
  if (Pos != Body.size()) {
    return std::nullopt;
  }
  return DecimalToDouble(Negative, Digits, Exponent - FracDigits);
}

// ---------------------------------------------------------------------------------------------
// Exact decimal expansion of a positive finite double: Digits (no leading/trailing zeros) and the
// decimal point position DecPt, so that V = 0.Digits * 10^DecPt.

void ExactDecimal(double V, std::string& Digits, int64_t& DecPt) {
  int Exp = 0;
  const double Fraction = std::frexp(V, &Exp);             // V = Fraction * 2^Exp, Fraction in [0.5, 1)
  uint64_t Mantissa = static_cast<uint64_t>(std::ldexp(Fraction, 53));  // exact: 53 bits
  int64_t Exp2 = static_cast<int64_t>(Exp) - 53;
  while ((Mantissa & 1u) == 0) {
    Mantissa >>= 1;
    ++Exp2;
  }
  BigUInt Value(Mantissa);
  if (Exp2 >= 0) {
    Value.ShiftLeft(static_cast<uint64_t>(Exp2));
    Digits = Value.ToDecimal();
    DecPt = static_cast<int64_t>(Digits.size());
  } else {
    Value.MulPow5(-Exp2);  // m * 2^-k = m * 5^k / 10^k
    Digits = Value.ToDecimal();
    DecPt = static_cast<int64_t>(Digits.size()) + Exp2;
  }
  const size_t Last = Digits.find_last_not_of('0');
  Digits.resize(Last + 1);
}

// Increments a decimal digit string; returns true when it carried into a new leading digit.
bool IncrementDigits(std::string& Digits) {
  for (size_t Index = Digits.size(); Index-- > 0;) {
    if (Digits[Index] != '9') {
      ++Digits[Index];
      return false;
    }
    Digits[Index] = '0';
  }
  Digits.insert(Digits.begin(), '1');
  return true;
}

// The shortest digit string that round-trips to V (dtoa mode 0), with its decimal point position.
void ShortestDigits(double V, std::string& OutDigits, int64_t& OutDecPt) {
  std::string Exact;
  int64_t DecPt = 0;
  ExactDecimal(V, Exact, DecPt);
  for (size_t Precision = 1; Precision <= 17; ++Precision) {
    if (Exact.size() <= Precision) {
      OutDigits = Exact;
      OutDecPt = DecPt;
      return;
    }
    std::string Down = Exact.substr(0, Precision);
    std::string Up = Down;
    int64_t UpDecPt = DecPt;
    if (IncrementDigits(Up)) {
      ++UpDecPt;
      Up.pop_back();  // "100..0" with one digit more: same value with Precision digits
    }
    const bool DownOk = DecimalToDouble(false, Down, DecPt - static_cast<int64_t>(Down.size())) == V;
    const bool UpOk = DecimalToDouble(false, Up, UpDecPt - static_cast<int64_t>(Up.size())) == V;
    if (!DownOk && !UpOk) {
      continue;
    }
    bool TakeUp = UpOk && !DownOk;
    if (DownOk && UpOk) {
      // nearest to the exact value; an exact tie takes the even last digit
      const std::string_view Rest = std::string_view(Exact).substr(Precision);
      const int Cmp = Rest[0] > '5' ? 1 : Rest[0] < '5' ? -1 : (Rest.size() > 1 ? 1 : 0);
      TakeUp = Cmp > 0 || (Cmp == 0 && ((Down.back() - '0') % 2) != 0);
    }
    if (TakeUp) {
      OutDigits = Up;
      OutDecPt = UpDecPt;
    } else {
      OutDigits = Down;
      OutDecPt = DecPt;
    }
    const size_t Last = OutDigits.find_last_not_of('0');
    OutDigits.resize(Last + 1);
    return;
  }
  OutDigits = Exact;  // unreachable: 17 significant digits always round-trip
  OutDecPt = DecPt;
}

// ---------------------------------------------------------------------------------------------
// Numeric helpers for Python equality between int, float and bool.

// Canonical decimal of an integral finite double ("-0.0" -> "0").
std::string IntegralDoubleDigits(double V) {
  if (V == 0.0) {
    return "0";
  }
  const bool Negative = V < 0.0;
  const double Magnitude = Negative ? -V : V;
  std::string Digits;
  if (Magnitude < 9007199254740992.0) {
    Digits = std::to_string(static_cast<uint64_t>(Magnitude));
  } else {
    int64_t DecPt = 0;
    ExactDecimal(Magnitude, Digits, DecPt);
    Digits.append(static_cast<size_t>(DecPt - static_cast<int64_t>(Digits.size())), '0');
  }
  return Negative ? "-" + Digits : Digits;
}

bool IsIntegralFinite(double V) { return std::isfinite(V) && std::floor(V) == V; }

// The canonical integer digits of a numeric value when it is integral (int, bool, integral float).
std::optional<std::string> IntegralDigits(const PyValue& Value) {
  switch (Value.Type) {
    case PyValue::Kind::Bool:
      return std::string(Value.BoolValue ? "1" : "0");
    case PyValue::Kind::Int:
      return Value.IntDigits;
    case PyValue::Kind::Float:
      if (IsIntegralFinite(Value.FloatValue)) {
        return IntegralDoubleDigits(Value.FloatValue);
      }
      return std::nullopt;
    default:
      return std::nullopt;
  }
}

bool IsNumeric(PyValue::Kind Kind) {
  return Kind == PyValue::Kind::Bool || Kind == PyValue::Kind::Int || Kind == PyValue::Kind::Float;
}

size_t HashBytes(std::string_view Bytes, uint64_t Seed) {
  uint64_t Hash = 1469598103934665603ull ^ Seed;  // FNV-1a
  for (const char Ch : Bytes) {
    Hash ^= static_cast<unsigned char>(Ch);
    Hash *= 1099511628211ull;
  }
  return static_cast<size_t>(Hash ^ (Hash >> 29));
}

std::string KindName(PyValue::Kind Kind) {
  switch (Kind) {
    case PyValue::Kind::None:
      return "NoneType";
    case PyValue::Kind::Bool:
      return "bool";
    case PyValue::Kind::Int:
      return "int";
    case PyValue::Kind::Float:
      return "float";
    case PyValue::Kind::Str:
      return "str";
    case PyValue::Kind::List:
      return "list";
    case PyValue::Kind::Dict:
      return "dict";
  }
  return "object";
}

// ---------------------------------------------------------------------------------------------
// json.loads (Modules/_json.c, strict=True). Operates on the UTF-8 bytes of the str; every
// structural character is ASCII and every non-ASCII byte outside a string is an error either way.

// The C scanner raises RecursionError somewhere between depth 2500 and 3000 on this Python
// (measured: dict nesting 2500 decodes, 3000 raises); the exact limit depends on the caller's stack
// depth. NOT DETERMINED FROM SOURCE for Diaphora's stack, so the port stops well below it, at the
// engine-wide kMaxJsonDepth (Json.h), which JsonParse shares.

struct JsonDepthExceeded {};

class PyJsonParser {
public:
  explicit PyJsonParser(std::string_view Text) : Text_(Text) {}

  PyValue Document() {
    SkipWs();
    PyValue Value = ParseValue(0);
    SkipWs();
    if (Pos_ != Text_.size()) {
      Fail("Extra data");
    }
    return Value;
  }

private:
  [[noreturn]] void Fail(const char* Message) const {
    throw DiaphoraWouldRaise("json.loads", std::string("JSONDecodeError: ") + Message + " (char " +
                                               std::to_string(Pos_) + ")");
  }

  void SkipWs() {
    while (Pos_ < Text_.size() &&
           (Text_[Pos_] == ' ' || Text_[Pos_] == '\t' || Text_[Pos_] == '\n' || Text_[Pos_] == '\r')) {
      ++Pos_;
    }
  }

  bool Literal(std::string_view Word) {
    if (Text_.substr(Pos_, Word.size()) == Word) {
      Pos_ += Word.size();
      return true;
    }
    return false;
  }

  PyValue ParseValue(int Depth) {
    if (Pos_ >= Text_.size()) {
      Fail("Expecting value");
    }
    PyValue Value;
    switch (Text_[Pos_]) {
      case '"':
        Value.Type = PyValue::Kind::Str;
        Value.StrValue = ParseString();
        return Value;
      case '{':
        return ParseObject(Depth + 1);
      case '[':
        return ParseArray(Depth + 1);
      case 'n':
        if (Literal("null")) {
          return Value;
        }
        break;
      case 't':
        if (Literal("true")) {
          Value.Type = PyValue::Kind::Bool;
          Value.BoolValue = true;
          return Value;
        }
        break;
      case 'f':
        if (Literal("false")) {
          Value.Type = PyValue::Kind::Bool;
          Value.BoolValue = false;
          return Value;
        }
        break;
      case 'N':
        if (Literal("NaN")) {  // json.decoder._CONSTANTS['NaN']: one shared float object
          Value.Type = PyValue::Kind::Float;
          Value.FloatValue = std::numeric_limits<double>::quiet_NaN();
          return Value;
        }
        break;
      case 'I':
        if (Literal("Infinity")) {
          Value.Type = PyValue::Kind::Float;
          Value.FloatValue = std::numeric_limits<double>::infinity();
          return Value;
        }
        break;
      case '-':
        if (Literal("-Infinity")) {
          Value.Type = PyValue::Kind::Float;
          Value.FloatValue = -std::numeric_limits<double>::infinity();
          return Value;
        }
        return ParseNumber();
      default:
        if (IsAsciiDigit(Text_[Pos_])) {
          return ParseNumber();
        }
        break;
    }
    Fail("Expecting value");
  }

  // _match_number_unicode
  PyValue ParseNumber() {
    bool Negative = false;
    if (Text_[Pos_] == '-') {
      Negative = true;
      ++Pos_;
      if (Pos_ >= Text_.size()) {
        Fail("Expecting value");
      }
    }
    const size_t IntStart = Pos_;
    if (Text_[Pos_] >= '1' && Text_[Pos_] <= '9') {
      ++Pos_;
      while (Pos_ < Text_.size() && IsAsciiDigit(Text_[Pos_])) {
        ++Pos_;
      }
    } else if (Text_[Pos_] == '0') {
      ++Pos_;
    } else {
      Fail("Expecting value");
    }
    const std::string_view IntPart = Text_.substr(IntStart, Pos_ - IntStart);
    std::string_view FracPart;
    bool IsFloat = false;
    if (Pos_ + 1 < Text_.size() && Text_[Pos_] == '.' && IsAsciiDigit(Text_[Pos_ + 1])) {
      IsFloat = true;
      const size_t FracStart = ++Pos_;
      while (Pos_ < Text_.size() && IsAsciiDigit(Text_[Pos_])) {
        ++Pos_;
      }
      FracPart = Text_.substr(FracStart, Pos_ - FracStart);
    }
    int64_t Exponent = 0;
    if (Pos_ + 1 < Text_.size() && (Text_[Pos_] == 'e' || Text_[Pos_] == 'E')) {
      size_t Probe = Pos_ + 1;
      bool ExpNegative = false;
      if (Probe + 1 < Text_.size() && (Text_[Probe] == '-' || Text_[Probe] == '+')) {
        ExpNegative = Text_[Probe] == '-';
        ++Probe;
      }
      const size_t DigitsStart = Probe;
      int64_t Value = 0;
      size_t Significant = 0;
      while (Probe < Text_.size() && IsAsciiDigit(Text_[Probe])) {
        if (Significant > 0 || Text_[Probe] != '0') {
          ++Significant;
        }
        if (Value <= kMaxAbsExp) {
          Value = Value * 10 + (Text_[Probe] - '0');
        }
        ++Probe;
      }
      if (Probe > DigitsStart) {  // a digit ends the exponent: it is a float; else backtrack
        IsFloat = true;
        Pos_ = Probe;
        if (Significant > 8 || Value > kMaxAbsExp) {  // dtoa.c: `s - s1 > 8 || L > MAX_ABS_EXP`
          Value = kMaxAbsExp;
        }
        Exponent = ExpNegative ? -Value : Value;
      }
    }
    PyValue Result;
    if (!IsFloat) {
      // PyLong_FromString: exact and unbounded (sys.set_int_max_str_digits(0), D:96-97); "-0" is 0.
      Result.Type = PyValue::Kind::Int;
      Result.IntDigits = (IntPart == "0" || !Negative) ? std::string(IntPart) : "-" + std::string(IntPart);
      return Result;
    }
    // PyFloat_FromString of the matched text: correctly rounded, overflow gives inf.
    std::string Digits(IntPart);
    Digits.append(FracPart);
    Result.Type = PyValue::Kind::Float;
    Result.FloatValue = DecimalToDouble(Negative, Digits, Exponent - static_cast<int64_t>(FracPart.size()));
    return Result;
  }

  uint32_t Hex4() {
    if (Pos_ + 4 > Text_.size()) {
      Fail("Invalid \\uXXXX escape");
    }
    uint32_t Value = 0;
    for (int Index = 0; Index < 4; ++Index) {
      const char Ch = Text_[Pos_++];
      Value <<= 4;
      if (Ch >= '0' && Ch <= '9') {
        Value |= static_cast<uint32_t>(Ch - '0');
      } else if (Ch >= 'a' && Ch <= 'f') {
        Value |= static_cast<uint32_t>(Ch - 'a' + 10);
      } else if (Ch >= 'A' && Ch <= 'F') {
        Value |= static_cast<uint32_t>(Ch - 'A' + 10);
      } else {
        Fail("Invalid \\uXXXX escape");
      }
    }
    return Value;
  }

  static void AppendCodePoint(std::string& Out, uint32_t Code) {
    if (Code < 0x80) {
      Out += static_cast<char>(Code);
    } else if (Code < 0x800) {
      Out += static_cast<char>(0xC0 | (Code >> 6));
      Out += static_cast<char>(0x80 | (Code & 0x3F));
    } else if (Code < 0x10000) {  // includes a lone surrogate (kept as a code point by Python)
      Out += static_cast<char>(0xE0 | (Code >> 12));
      Out += static_cast<char>(0x80 | ((Code >> 6) & 0x3F));
      Out += static_cast<char>(0x80 | (Code & 0x3F));
    } else {
      Out += static_cast<char>(0xF0 | (Code >> 18));
      Out += static_cast<char>(0x80 | ((Code >> 12) & 0x3F));
      Out += static_cast<char>(0x80 | ((Code >> 6) & 0x3F));
      Out += static_cast<char>(0x80 | (Code & 0x3F));
    }
  }

  // scanstring_unicode with strict=True: raw U+0000-U+001F is an error; a \u high surrogate
  // immediately followed by a \u low surrogate combines into one code point.
  std::string ParseString() {
    ++Pos_;
    std::string Out;
    while (true) {
      if (Pos_ >= Text_.size()) {
        Fail("Unterminated string starting at");
      }
      const unsigned char Ch = static_cast<unsigned char>(Text_[Pos_]);
      if (Ch == '"') {
        ++Pos_;
        return Out;
      }
      if (Ch < 0x20) {
        Fail("Invalid control character at");
      }
      if (Ch != '\\') {
        Out += static_cast<char>(Ch);
        ++Pos_;
        continue;
      }
      ++Pos_;
      if (Pos_ >= Text_.size()) {
        Fail("Unterminated string starting at");
      }
      const char Escape = Text_[Pos_++];
      switch (Escape) {
        case '"':
          Out += '"';
          break;
        case '\\':
          Out += '\\';
          break;
        case '/':
          Out += '/';
          break;
        case 'b':
          Out += '\b';
          break;
        case 'f':
          Out += '\f';
          break;
        case 'n':
          Out += '\n';
          break;
        case 'r':
          Out += '\r';
          break;
        case 't':
          Out += '\t';
          break;
        case 'u': {
          uint32_t Code = Hex4();
          if (Code >= 0xD800 && Code <= 0xDBFF && Pos_ + 6 < Text_.size() && Text_[Pos_] == '\\' &&
              Text_[Pos_ + 1] == 'u') {
            const size_t Save = Pos_;
            Pos_ += 2;
            const uint32_t Low = Hex4();  // an invalid escape here raises, as in _json.c
            if (Low >= 0xDC00 && Low <= 0xDFFF) {
              Code = 0x10000 + ((Code - 0xD800) << 10) + (Low - 0xDC00);
            } else {
              Pos_ = Save;
            }
          }
          AppendCodePoint(Out, Code);
          break;
        }
        default:
          Fail("Invalid \\escape");
      }
    }
  }

  PyValue ParseArray(int Depth) {
    if (Depth > kMaxJsonDepth) {
      throw JsonDepthExceeded{};
    }
    ++Pos_;
    PyValue Result;
    Result.Type = PyValue::Kind::List;
    SkipWs();
    if (Pos_ < Text_.size() && Text_[Pos_] == ']') {
      ++Pos_;
      return Result;
    }
    while (true) {
      Result.Items.push_back(ParseValue(Depth));
      SkipWs();
      if (Pos_ < Text_.size() && Text_[Pos_] == ']') {
        ++Pos_;
        return Result;
      }
      if (Pos_ >= Text_.size() || Text_[Pos_] != ',') {
        Fail("Expecting ',' delimiter");
      }
      ++Pos_;
      SkipWs();
      if (Pos_ < Text_.size() && Text_[Pos_] == ']') {
        Fail("Illegal trailing comma before end of array");
      }
    }
  }

  PyValue ParseObject(int Depth) {
    if (Depth > kMaxJsonDepth) {
      throw JsonDepthExceeded{};
    }
    ++Pos_;
    PyValue Result;
    Result.Type = PyValue::Kind::Dict;
    SkipWs();
    if (Pos_ < Text_.size() && Text_[Pos_] == '}') {
      ++Pos_;
      return Result;
    }
    while (true) {
      if (Pos_ >= Text_.size() || Text_[Pos_] != '"') {
        Fail("Expecting property name enclosed in double quotes");
      }
      PyValue Key;
      Key.Type = PyValue::Kind::Str;
      Key.StrValue = ParseString();
      SkipWs();
      if (Pos_ >= Text_.size() || Text_[Pos_] != ':') {
        Fail("Expecting ':' delimiter");
      }
      ++Pos_;
      SkipWs();
      PyValue Member = ParseValue(Depth);
      // dict assignment: an existing key keeps its position (and object), the value is replaced
      bool Replaced = false;
      for (size_t Index = 0; Index < Result.Items.size(); ++Index) {
        if (Result.Items[Index].StrValue == Key.StrValue) {
          Result.DictValues[Index] = std::move(Member);
          Replaced = true;
          break;
        }
      }
      if (!Replaced) {
        Result.Items.push_back(std::move(Key));
        Result.DictValues.push_back(std::move(Member));
      }
      SkipWs();
      if (Pos_ < Text_.size() && Text_[Pos_] == '}') {
        ++Pos_;
        return Result;
      }
      if (Pos_ >= Text_.size() || Text_[Pos_] != ',') {
        Fail("Expecting ',' delimiter");
      }
      ++Pos_;
      SkipWs();
      if (Pos_ < Text_.size() && Text_[Pos_] == '}') {
        Fail("Illegal trailing comma before end of object");
      }
    }
  }

  std::string_view Text_;
  size_t Pos_ = 0;
};

// Splits UTF-8 (generalized: a lone surrogate is one 3-byte code point) into code points.
std::vector<std::string_view> CodePoints(std::string_view Text) {
  std::vector<std::string_view> Out;
  size_t Pos = 0;
  while (Pos < Text.size()) {
    const unsigned char Lead = static_cast<unsigned char>(Text[Pos]);
    size_t Length = 1;
    if (Lead >= 0xF0) {
      Length = 4;
    } else if (Lead >= 0xE0) {
      Length = 3;
    } else if (Lead >= 0xC0) {
      Length = 2;
    }
    Length = std::min(Length, Text.size() - Pos);
    Out.push_back(Text.substr(Pos, Length));
    Pos += Length;
  }
  return Out;
}

}  // namespace

// ---------------------------------------------------------------------------------------------
// Equality and hashing (set membership)

bool PyEquals(const PyValue& A, const PyValue& B) {
  if (IsNumeric(A.Type) && IsNumeric(B.Type)) {
    if (A.Type == PyValue::Kind::Float && B.Type == PyValue::Kind::Float) {
      if (std::isnan(A.FloatValue) && std::isnan(B.FloatValue)) {
        return true;  // the json module's single NaN object: identity makes it equal to itself
      }
      return A.FloatValue == B.FloatValue;
    }
    if (A.Type == PyValue::Kind::Float || B.Type == PyValue::Kind::Float) {
      // float_richcompare: exact comparison with an int (or bool)
      const PyValue& F = A.Type == PyValue::Kind::Float ? A : B;
      const PyValue& I = A.Type == PyValue::Kind::Float ? B : A;
      const auto Digits = IntegralDigits(F);
      return Digits.has_value() && *Digits == *IntegralDigits(I);
    }
    return *IntegralDigits(A) == *IntegralDigits(B);
  }
  if (A.Type != B.Type) {
    return false;  // str never equals a number, None only equals None
  }
  switch (A.Type) {
    case PyValue::Kind::None:
      return true;
    case PyValue::Kind::Str:
      return A.StrValue == B.StrValue;
    case PyValue::Kind::List: {
      if (A.Items.size() != B.Items.size()) {
        return false;
      }
      for (size_t Index = 0; Index < A.Items.size(); ++Index) {
        if (!PyEquals(A.Items[Index], B.Items[Index])) {
          return false;
        }
      }
      return true;
    }
    case PyValue::Kind::Dict: {
      // dict equality ignores insertion order; JSON keys are str
      if (A.Items.size() != B.Items.size()) {
        return false;
      }
      for (size_t Index = 0; Index < A.Items.size(); ++Index) {
        bool Found = false;
        for (size_t Other = 0; Other < B.Items.size(); ++Other) {
          if (PyEquals(A.Items[Index], B.Items[Other])) {
            Found = PyEquals(A.DictValues[Index], B.DictValues[Other]);
            break;
          }
        }
        if (!Found) {
          return false;
        }
      }
      return true;
    }
    default:
      return false;
  }
}

size_t PyHash(const PyValue& Value) {
  switch (Value.Type) {
    case PyValue::Kind::None:
      return static_cast<size_t>(0x9e3779b97f4a7c15ull);
    case PyValue::Kind::Str:
      return HashBytes(Value.StrValue, 0x53);
    case PyValue::Kind::Bool:
    case PyValue::Kind::Int:
    case PyValue::Kind::Float: {
      if (Value.Type == PyValue::Kind::Float && std::isnan(Value.FloatValue)) {
        return 0x7ff8;
      }
      if (const auto Digits = IntegralDigits(Value)) {
        return HashBytes(*Digits, 0x49);
      }
      uint64_t Bits = 0;
      std::memcpy(&Bits, &Value.FloatValue, sizeof Bits);
      return HashBytes(std::string_view(reinterpret_cast<const char*>(&Bits), sizeof Bits), 0x46);
    }
    case PyValue::Kind::List:
    case PyValue::Kind::Dict:
      break;
  }
  throw DiaphoraWouldRaise("hash", "TypeError: unhashable type: '" + KindName(Value.Type) + "'");
}

// ---------------------------------------------------------------------------------------------
// json.loads

PyValue PyJsonLoads(std::string_view Text) {
  try {
    return PyJsonParser(Text).Document();
  } catch (const JsonDepthExceeded&) {
    throw UnsupportedInput("json.loads: nesting deeper than " + std::to_string(kMaxJsonDepth) +
                           " (Python's RecursionError depth is NOT DETERMINED FROM SOURCE)");
  }
}

std::vector<PyValue> PyJsonLoadsList(std::string_view Text) {
  PyValue Value;
  try {
    Value = PyJsonParser(Text).Document();
  } catch (const JsonDepthExceeded&) {
    // A list this deep has a list element, so set() raises TypeError (or json.loads raises
    // RecursionError first): Python raises either way. A deep dict value is not an element of
    // set(dict), so there the outcome depends on the undetermined recursion limit.
    size_t Pos = 0;
    while (Pos < Text.size() && (Text[Pos] == ' ' || Text[Pos] == '\t' || Text[Pos] == '\n' || Text[Pos] == '\r')) {
      ++Pos;
    }
    if (Pos < Text.size() && Text[Pos] == '[') {
      throw DiaphoraWouldRaise("set(json.loads)", "TypeError: unhashable type: 'list' (nesting deeper than " +
                                                      std::to_string(kMaxJsonDepth) + ")");
    }
    throw UnsupportedInput("json.loads: nesting deeper than " + std::to_string(kMaxJsonDepth) +
                           " (Python's RecursionError depth is NOT DETERMINED FROM SOURCE)");
  }
  switch (Value.Type) {
    case PyValue::Kind::List:
      return std::move(Value.Items);
    case PyValue::Kind::Dict:
      return std::move(Value.Items);  // iterating a dict yields its keys
    case PyValue::Kind::Str: {
      std::vector<PyValue> Chars;
      for (const std::string_view Char : CodePoints(Value.StrValue)) {
        PyValue Item;
        Item.Type = PyValue::Kind::Str;
        Item.StrValue = std::string(Char);
        Chars.push_back(std::move(Item));
      }
      return Chars;
    }
    default:
      throw DiaphoraWouldRaise("set(json.loads)",
                               "TypeError: '" + KindName(Value.Type) + "' object is not iterable");
  }
}

// ---------------------------------------------------------------------------------------------
// set

bool PySet::Insert(const PyValue& Value) {
  if (!Value.Hashable()) {
    throw DiaphoraWouldRaise("set", "TypeError: unhashable type: '" + KindName(Value.Type) + "'");
  }
  const size_t Hash = PyHash(Value);
  const auto Range = Index_.equal_range(Hash);
  for (auto It = Range.first; It != Range.second; ++It) {
    if (PyEquals(Items_[It->second], Value)) {
      return false;  // set_add_entry keeps the key already present
    }
  }
  Index_.emplace(Hash, static_cast<uint32_t>(Items_.size()));
  Items_.push_back(Value);
  return true;
}

bool PySet::Contains(const PyValue& Value) const {
  if (!Value.Hashable()) {
    throw DiaphoraWouldRaise("set", "TypeError: unhashable type: '" + KindName(Value.Type) + "'");
  }
  const auto Range = Index_.equal_range(PyHash(Value));
  for (auto It = Range.first; It != Range.second; ++It) {
    if (PyEquals(Items_[It->second], Value)) {
      return true;
    }
  }
  return false;
}

PySet PySetFromList(const std::vector<PyValue>& Items) {
  PySet Result;
  for (const PyValue& Item : Items) {
    Result.Insert(Item);
  }
  return Result;
}

std::vector<PyValue> PySetIntersection(const PySet& Main, const PySet& Diff) {
  // set_intersection (Objects/setobject.c): with `other` a set, it iterates the smaller of the two
  // (the argument when the sizes are equal) and adds the iterated set's keys. The key objects are
  // therefore Diff's unless Diff is strictly larger. That only matters for equal values of different
  // types (1 / 1.0 / True), where str() differs. The iteration ORDER is CPython hash order; the port
  // uses Main's first-appearance order (documented deviation, plan §5 R3).
  const bool KeysFromDiff = Diff.Size() <= Main.Size();
  std::vector<PyValue> Result;
  for (const PyValue& Item : Main.Ordered()) {
    if (!Diff.Contains(Item)) {
      continue;
    }
    if (KeysFromDiff && Item.Type != PyValue::Kind::Str && Item.Type != PyValue::Kind::None) {
      for (const PyValue& Other : Diff.Ordered()) {
        if (PyEquals(Other, Item)) {
          Result.push_back(Other);
          break;
        }
      }
    } else {
      Result.push_back(Item);  // an equal str or None is the same value
    }
  }
  return Result;
}

size_t PySetIntersectionSize(const PySet& A, const PySet& B) {
  const PySet& Small = A.Size() <= B.Size() ? A : B;
  const PySet& Large = A.Size() <= B.Size() ? B : A;
  size_t Count = 0;
  for (const PyValue& Item : Small.Ordered()) {
    if (Large.Contains(Item)) {
      ++Count;
    }
  }
  return Count;
}

// ---------------------------------------------------------------------------------------------
// str(), float(), repr(float)

std::string PyStr(const PyValue& Value) {
  switch (Value.Type) {
    case PyValue::Kind::None:
      return "None";
    case PyValue::Kind::Bool:
      return Value.BoolValue ? "True" : "False";
    case PyValue::Kind::Int:
      return Value.IntDigits;
    case PyValue::Kind::Float:
      return PyReprFloat(Value.FloatValue);  // str(float) is repr(float) in Python 3
    case PyValue::Kind::Str:
      return Value.StrValue;
    case PyValue::Kind::List:
    case PyValue::Kind::Dict:
      break;
  }
  // Unreachable from set elements (unhashable); str(list) would need Python's repr of str.
  throw UnsupportedInput("PyStr: str() of a " + KindName(Value.Type) + " is not ported");
}

std::optional<double> PyFloat(std::string_view Text) {
  for (const char Ch : Text) {
    if (static_cast<unsigned char>(Ch) >= 0x80) {
      // PyFloat_FromString maps Unicode decimal digits and Unicode whitespace to ASCII first
      // (_PyUnicode_TransformDecimalAndSpaceToASCII); that needs the Unicode database.
      throw UnsupportedInput("float(): non-ASCII text is not ported (Unicode digit/space mapping)");
    }
  }
  return PyFloatAscii(Text);
}

std::string PyReprFloat(double Value) {
  if (std::isnan(Value)) {
    return "nan";
  }
  if (std::isinf(Value)) {
    return Value < 0 ? "-inf" : "inf";
  }
  if (Value == 0.0) {
    return std::signbit(Value) ? "-0.0" : "0.0";
  }
  const bool Negative = Value < 0.0;
  std::string Digits;
  int64_t DecPt = 0;
  ShortestDigits(Negative ? -Value : Value, Digits, DecPt);
  std::string Out = Negative ? "-" : "";
  const int64_t Count = static_cast<int64_t>(Digits.size());
  if (DecPt <= -4 || DecPt > 16) {
    // exponent form: d[.ddd]e[+-]XX (at least two exponent digits)
    Out += Digits[0];
    if (Count > 1) {
      Out += '.';
      Out.append(Digits, 1, std::string::npos);
    }
    const int64_t Exp = DecPt - 1;
    Out += Exp < 0 ? "e-" : "e+";
    const std::string ExpDigits = std::to_string(Exp < 0 ? -Exp : Exp);
    if (ExpDigits.size() < 2) {
      Out += '0';
    }
    Out += ExpDigits;
  } else if (DecPt <= 0) {
    Out += "0.";
    Out.append(static_cast<size_t>(-DecPt), '0');
    Out += Digits;
  } else if (DecPt >= Count) {
    Out += Digits;
    Out.append(static_cast<size_t>(DecPt - Count), '0');
    Out += ".0";  // Py_DTSF_ADD_DOT_0
  } else {
    Out.append(Digits, 0, static_cast<size_t>(DecPt));
    Out += '.';
    Out.append(Digits, static_cast<size_t>(DecPt), std::string::npos);
  }
  return Out;
}

}
