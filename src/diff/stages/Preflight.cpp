// The checks CBinDiff.diff() makes before any matching. Spec: 01 §5.1-§5.3, §5.6, §13;
// 05 §1.2, §3; 08 §7.1-§7.2. D: = diaphora.py at 3.4.2-4-g621ec26.
//   StageCheckVersion    D:3577-3591  `select value from diff.version`
//   StageEqualDb         D:661-687    equal_db (log only)
//   StageCheckCallgraph  D:1288-1338  get_callgraph_difference + check_callgraph (log only, but raises);
//                                     jkutils/factor.py:202-242 (FACTORS_CACHE, _difference, difference)
//   StageSameProcessor   D:2950-2967  same_processor_both_databases
//
// Python's sqlite3 (text_factory = str, D:346) decodes a TEXT cell when the row is FETCHED; invalid
// UTF-8 raises OperationalError there (01 §13). `cur.execute` of a SELECT prepares and steps once;
// fetchone() builds the row from that step and then steps again (CPython 3.13 Modules/_sqlite/cursor.c
// pysqlite_cursor_iternext); fetchall() builds every row first. The helpers below follow that order.

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "EarlyPasses.h"
#include "dsigmatcher/diff/Errors.h"
#include "dsigmatcher/diff/Pipeline.h"
#include "dsigmatcher/diff/PyValue.h"
#include "dsigmatcher/diff/StageSql.h"
#include "dsigmatcher/diff/Stages.h"
#include "dsigmatcher/diff/Table.h"

namespace DSig::Diff {

namespace {

// ---------------------------------------------------------------------------------------------
// Row decoding

// The OperationalError Python's fetch raises for a TEXT cell that is not valid UTF-8 (01 §13).
void RequireDecodable(const Statement& Q, int Column) {
  if (Q.Type(Column) == SqlType::Text && !IsValidUtf8(Q.Text(Column))) {
    throw DiaphoraWouldRaise("fetch", "OperationalError: Could not decode to UTF-8 column '" +
                                          std::string(Q.ColumnName(Column)) + "'");
  }
}

void RequireRowDecodable(const Statement& Q) {
  const int Count = Q.ColumnCount();
  for (int Column = 0; Column < Count; ++Column) {
    RequireDecodable(Q, Column);
  }
}

// A `select count(...)` value: always an INTEGER cell.
int64_t CountValue(const Statement& Q, int Column, std::string_view What) {
  if (Q.Type(Column) != SqlType::Integer) {
    throw UnsupportedInput(std::string(What) + ": the count is not an INTEGER");
  }
  return Q.Int(Column);
}

// Python's repr() of a bytes value (the log text of a BLOB cell): b'...' with \\, \t, \n, \r, \xhh
// escapes, and double quotes when the bytes hold a ' but no ".
std::string PyBytesRepr(std::string_view Bytes) {
  const bool HasSingle = Bytes.find('\'') != std::string_view::npos;
  const bool HasDouble = Bytes.find('"') != std::string_view::npos;
  const char Quote = HasSingle && !HasDouble ? '"' : '\'';
  std::string Out = "b";
  Out += Quote;
  static const char Hex[] = "0123456789abcdef";
  for (const char Raw : Bytes) {
    const unsigned char Ch = static_cast<unsigned char>(Raw);
    if (Ch == static_cast<unsigned char>(Quote) || Ch == '\\') {
      Out += '\\';
      Out += static_cast<char>(Ch);
    } else if (Ch == '\t') {
      Out += "\\t";
    } else if (Ch == '\n') {
      Out += "\\n";
    } else if (Ch == '\r') {
      Out += "\\r";
    } else if (Ch < 0x20 || Ch >= 0x7f) {
      Out += "\\x";
      Out += Hex[Ch >> 4];
      Out += Hex[Ch & 15];
    } else {
      Out += static_cast<char>(Ch);
    }
  }
  Out += Quote;
  return Out;
}

// f"{value}" of a fetched cell (only used for a log line).
std::string PyStrOfCell(const Statement& Q, int Column) {
  switch (Q.Type(Column)) {
    case SqlType::Null:
      return "None";
    case SqlType::Integer:
      return std::to_string(Q.Int(Column));
    case SqlType::Real:
      return PyReprFloat(Q.Real(Column));
    case SqlType::Text:
      return std::string(Q.Text(Column));
    case SqlType::Blob:
      return PyBytesRepr(Q.Text(Column));
  }
  return std::string();
}

// ---------------------------------------------------------------------------------------------
// Arbitrary-precision helpers for check_callgraph. Magnitudes are decimal digit strings, most
// significant digit first, without leading zeros ("" is zero).

int CompareMag(std::string_view A, std::string_view B) {
  if (A.size() != B.size()) {
    return A.size() < B.size() ? -1 : 1;
  }
  const int Cmp = A.compare(B);
  return Cmp < 0 ? -1 : (Cmp > 0 ? 1 : 0);
}

std::string AddMag(std::string_view A, std::string_view B) {
  std::string Out;
  Out.reserve(std::max(A.size(), B.size()) + 1);
  int Carry = 0;
  size_t I = A.size();
  size_t J = B.size();
  while (I > 0 || J > 0 || Carry != 0) {
    int Sum = Carry;
    if (I > 0) {
      Sum += A[--I] - '0';
    }
    if (J > 0) {
      Sum += B[--J] - '0';
    }
    Out.push_back(static_cast<char>('0' + Sum % 10));
    Carry = Sum / 10;
  }
  std::string Reversed(Out.rbegin(), Out.rend());
  const size_t First = Reversed.find_first_not_of('0');
  return First == std::string::npos ? std::string() : Reversed.substr(First);
}

// A - B for A >= B.
std::string SubMag(std::string_view A, std::string_view B) {
  std::string Out;
  Out.reserve(A.size());
  int Borrow = 0;
  size_t I = A.size();
  size_t J = B.size();
  while (I > 0) {
    int Digit = (A[--I] - '0') - Borrow;
    if (J > 0) {
      Digit -= B[--J] - '0';
    }
    Borrow = Digit < 0 ? 1 : 0;
    Out.push_back(static_cast<char>('0' + Digit + Borrow * 10));
  }
  std::string Reversed(Out.rbegin(), Out.rend());
  const size_t First = Reversed.find_first_not_of('0');
  return First == std::string::npos ? std::string() : Reversed.substr(First);
}

std::string MulMagSmall(std::string_view A, unsigned Factor) {
  if (A.empty() || Factor == 0) {
    return std::string();
  }
  std::string Out;
  Out.reserve(A.size() + 3);
  uint64_t Carry = 0;
  for (size_t I = A.size(); I > 0; --I) {
    const uint64_t Product = static_cast<uint64_t>(A[I - 1] - '0') * Factor + Carry;
    Out.push_back(static_cast<char>('0' + Product % 10));
    Carry = Product / 10;
  }
  while (Carry != 0) {
    Out.push_back(static_cast<char>('0' + Carry % 10));
    Carry /= 10;
  }
  return std::string(Out.rbegin(), Out.rend());
}

std::string MagOfU64(uint64_t Value) { return Value == 0 ? std::string() : std::to_string(Value); }

struct BigInt {
  bool Negative = false;
  std::string Mag;
};

BigInt BigAdd(const BigInt& A, const BigInt& B) {
  if (A.Negative == B.Negative) {
    return BigInt{A.Negative, AddMag(A.Mag, B.Mag)};
  }
  const int Cmp = CompareMag(A.Mag, B.Mag);
  if (Cmp == 0) {
    return BigInt{};
  }
  return Cmp > 0 ? BigInt{A.Negative, SubMag(A.Mag, B.Mag)} : BigInt{B.Negative, SubMag(B.Mag, A.Mag)};
}

// |A - B|
BigInt BigAbsDiff(const BigInt& A, const BigInt& B) {
  BigInt NegB = B;
  NegB.Negative = !B.Negative && !B.Mag.empty();
  BigInt R = BigAdd(A, NegB);
  R.Negative = false;
  return R;
}

std::string BigText(const BigInt& V) {
  if (V.Mag.empty()) {
    return "0";
  }
  return (V.Negative ? "-" : "") + V.Mag;
}

// float(int) raises OverflowError from |n| >= 2**1024 - 2**970: those values round (half-even on 53
// bits) to 2**1024, which is not a double (CPython PyLong_AsDouble; checked on the oracle's 3.13.12:
// float(2**1024-2**970) raises, float(2**1024-2**970-1) == 1.7976931348623157e+308).
const std::string& FloatOverflowMag() {
  static const std::string Threshold = [] {
    std::string P970 = "1";
    for (int K = 0; K < 970; ++K) {
      P970 = MulMagSmall(P970, 2);
    }
    std::string P1024 = P970;
    for (int K = 970; K < 1024; ++K) {
      P1024 = MulMagSmall(P1024, 2);
    }
    return SubMag(P1024, P970);
  }();
  return Threshold;
}

bool FloatOverflows(const BigInt& V) { return CompareMag(V.Mag, FloatOverflowMag()) >= 0; }

double BigToDouble(const BigInt& V) {
  // float(int) is correctly rounded (half-even); PyFloat of the decimal text is too (PyValue.cpp).
  const std::optional<double> Value = PyFloat(BigText(V));
  if (!Value) {
    throw UnsupportedInput("check_callgraph: cannot convert " + BigText(V) + " to float");
  }
  return *Value;
}

// ---------------------------------------------------------------------------------------------
// decimal.Decimal (CPython 3.13.12, C implementation _decimal / libmpdec) as far as
// get_callgraph_difference uses it: construction (D:1300, D:1302) and == (D:1305).

struct PyDecimal {
  enum class Kind : uint8_t { Finite, Infinity, QuietNaN, SignalingNaN };
  Kind Type = Kind::Finite;
  bool Negative = false;
  std::string Coefficient;  // no leading and (after Normalise) no trailing zeros; "" for zero
  int64_t Exponent = 0;     // value = coefficient * 10**Exponent

  void Normalise() {
    const size_t First = Coefficient.find_first_not_of('0');
    Coefficient = First == std::string::npos ? std::string() : Coefficient.substr(First);
    if (Coefficient.empty()) {
      Exponent = 0;
      return;
    }
    while (Coefficient.back() == '0') {
      Coefficient.pop_back();
      ++Exponent;
    }
  }
};

bool IsPyAsciiSpace(char Ch) {
  // Py_UNICODE_ISSPACE for ASCII: \t \n \v \f \r, 0x1c-0x1f and the space (str.isspace()). Checked on
  // the oracle's CPython: Decimal("\x1c5") == Decimal("\x0b5") == Decimal("5").
  return Ch == ' ' || (Ch >= '\t' && Ch <= '\r') || (Ch >= '\x1c' && Ch <= '\x1f');
}

bool EqualsIgnoreCase(std::string_view A, std::string_view B) {
  if (A.size() != B.size()) {
    return false;
  }
  for (size_t I = 0; I < A.size(); ++I) {
    char X = A[I];
    char Y = B[I];
    if (X >= 'A' && X <= 'Z') {
      X = static_cast<char>(X - 'A' + 'a');
    }
    if (Y >= 'A' && Y <= 'Z') {
      Y = static_cast<char>(Y - 'A' + 'a');
    }
    if (X != Y) {
      return false;
    }
  }
  return true;
}

bool AllDigits(std::string_view Text) {
  for (const char Ch : Text) {
    if (Ch < '0' || Ch > '9') {
      return false;
    }
  }
  return true;
}

// Decimal(str). nullopt: Python raises decimal.InvalidOperation ([ConversionSyntax]).
// _decimal numeric_as_ascii strips leading and trailing whitespace, then drops every '_'; libmpdec
// mpd_qset_string then parses [sign] (digits [. [digits]] | . digits) [e [sign] digits] | inf |
// infinity | nan [digits] | snan [digits], case-insensitively. Verified on the oracle's CPython:
// "1__0" -> 10, " _1 " -> 1, "_ 1" and "1 _" raise, "i_nf" -> Infinity, "1e-_5" -> 0.00001,
// "1.e5" -> 1E+5, ".e5", "+", "_" and "infinit" raise.
// Not ported (UnsupportedInput): non-ASCII text (Python accepts Unicode digits and spaces there) and
// exponents of 16 or more digits (libmpdec's MPD_MAX_EMAX / MPD_MIN_ETINY limits apply there).
std::optional<PyDecimal> ParsePyDecimal(std::string_view Raw) {
  for (const char Ch : Raw) {
    if (static_cast<unsigned char>(Ch) >= 0x80) {
      throw UnsupportedInput("check_callgraph: a non-ASCII callgraph_primes text is not ported (Python's Decimal "
                             "accepts Unicode digits and spaces)");
    }
  }
  size_t Begin = 0;
  size_t End = Raw.size();
  while (End > Begin && IsPyAsciiSpace(Raw[End - 1])) {
    --End;
  }
  while (Begin < End && IsPyAsciiSpace(Raw[Begin])) {
    ++Begin;
  }
  std::string Text;
  for (size_t I = Begin; I < End; ++I) {
    if (Raw[I] != '_') {
      Text.push_back(Raw[I]);
    }
  }
  PyDecimal Out;
  std::string_view Rest = Text;
  if (!Rest.empty() && (Rest[0] == '+' || Rest[0] == '-')) {
    Out.Negative = Rest[0] == '-';
    Rest.remove_prefix(1);
  }
  if (EqualsIgnoreCase(Rest, "inf") || EqualsIgnoreCase(Rest, "infinity")) {
    Out.Type = PyDecimal::Kind::Infinity;
    return Out;
  }
  if (Rest.size() >= 3 && EqualsIgnoreCase(Rest.substr(0, 3), "nan") && AllDigits(Rest.substr(3))) {
    Out.Type = PyDecimal::Kind::QuietNaN;
    return Out;
  }
  if (Rest.size() >= 4 && EqualsIgnoreCase(Rest.substr(0, 4), "snan") && AllDigits(Rest.substr(4))) {
    Out.Type = PyDecimal::Kind::SignalingNaN;
    return Out;
  }
  size_t Pos = 0;
  std::string IntPart;
  std::string FracPart;
  while (Pos < Rest.size() && Rest[Pos] >= '0' && Rest[Pos] <= '9') {
    IntPart.push_back(Rest[Pos++]);
  }
  if (Pos < Rest.size() && Rest[Pos] == '.') {
    ++Pos;
    while (Pos < Rest.size() && Rest[Pos] >= '0' && Rest[Pos] <= '9') {
      FracPart.push_back(Rest[Pos++]);
    }
  }
  if (IntPart.empty() && FracPart.empty()) {
    return std::nullopt;  // "", ".", "+", ".e5"
  }
  int64_t Exponent = 0;
  if (Pos < Rest.size() && (Rest[Pos] == 'e' || Rest[Pos] == 'E')) {
    ++Pos;
    bool ExpNegative = false;
    if (Pos < Rest.size() && (Rest[Pos] == '+' || Rest[Pos] == '-')) {
      ExpNegative = Rest[Pos] == '-';
      ++Pos;
    }
    const size_t DigitsBegin = Pos;
    while (Pos < Rest.size() && Rest[Pos] >= '0' && Rest[Pos] <= '9') {
      ++Pos;
    }
    if (Pos == DigitsBegin) {
      return std::nullopt;  // "1e", "1e+"
    }
    std::string_view ExpDigits = Rest.substr(DigitsBegin, Pos - DigitsBegin);
    while (ExpDigits.size() > 1 && ExpDigits[0] == '0') {
      ExpDigits.remove_prefix(1);
    }
    if (ExpDigits.size() > 15) {
      throw UnsupportedInput("check_callgraph: a Decimal exponent of " + std::to_string(ExpDigits.size()) +
                             " digits is not ported (libmpdec exponent limits)");
    }
    Exponent = std::stoll(std::string(ExpDigits));
    if (ExpNegative) {
      Exponent = -Exponent;
    }
  }
  if (Pos != Rest.size()) {
    return std::nullopt;  // trailing garbage, interior spaces, "1e1e1", "1.2.3"
  }
  Out.Coefficient = IntPart + FracPart;
  Out.Exponent = Exponent - static_cast<int64_t>(FracPart.size());
  Out.Normalise();
  return Out;
}

// Decimal(int) and Decimal(float): exact values.
PyDecimal DecimalOfInt(int64_t Value) {
  PyDecimal Out;
  Out.Negative = Value < 0;
  const uint64_t Magnitude = Value < 0 ? 0 - static_cast<uint64_t>(Value) : static_cast<uint64_t>(Value);
  Out.Coefficient = MagOfU64(Magnitude);
  Out.Normalise();
  return Out;
}

PyDecimal DecimalOfDouble(double Value) {
  PyDecimal Out;
  Out.Negative = std::signbit(Value);
  if (std::isnan(Value)) {
    Out.Type = PyDecimal::Kind::QuietNaN;  // Decimal(float('nan')) is Decimal('NaN')
    return Out;
  }
  if (std::isinf(Value)) {
    Out.Type = PyDecimal::Kind::Infinity;
    return Out;
  }
  int Exp2 = 0;
  const double Fraction = std::frexp(std::fabs(Value), &Exp2);  // |Value| = Fraction * 2**Exp2
  uint64_t Mantissa = static_cast<uint64_t>(std::ldexp(Fraction, 53));
  int Shift = Exp2 - 53;  // |Value| = Mantissa * 2**Shift, exactly
  std::string Coefficient = MagOfU64(Mantissa);
  if (Shift >= 0) {
    for (int K = 0; K < Shift; ++K) {
      Coefficient = MulMagSmall(Coefficient, 2);
    }
  } else {
    for (int K = 0; K < -Shift; ++K) {  // Mantissa * 2**-k = Mantissa * 5**k * 10**-k
      Coefficient = MulMagSmall(Coefficient, 5);
    }
    Out.Exponent = Shift;
  }
  Out.Coefficient = Coefficient;
  Out.Normalise();
  return Out;
}

// Decimal(value) of a fetched cell (D:1300 / D:1302).
PyDecimal DecimalOfCell(const SqlCell& Cell, const char* Site) {
  switch (Cell.Type) {
    case SqlType::Null:
      throw DiaphoraWouldRaise(std::string(Site) + " TypeError", "conversion from NoneType to Decimal is not supported");
    case SqlType::Blob:
      throw DiaphoraWouldRaise(std::string(Site) + " TypeError", "conversion from bytes to Decimal is not supported");
    case SqlType::Integer:
      return DecimalOfInt(Cell.Int);
    case SqlType::Real:
      return DecimalOfDouble(Cell.Real);
    case SqlType::Text: {
      const std::optional<PyDecimal> Value = ParsePyDecimal(Cell.Bytes);
      if (!Value) {
        throw DiaphoraWouldRaise(std::string(Site) + " decimal.InvalidOperation",
                                 "[<class 'decimal.ConversionSyntax'>] for '" + Cell.Bytes + "'");
      }
      return *Value;
    }
  }
  return PyDecimal();
}

// cg1 == cg2 (D:1305). A signalling NaN operand raises InvalidOperation (checked on the oracle's
// CPython: Decimal("sNaN") == Decimal(1) raises); a quiet NaN is never equal.
bool DecimalEquals(const PyDecimal& A, const PyDecimal& B) {
  if (A.Type == PyDecimal::Kind::SignalingNaN || B.Type == PyDecimal::Kind::SignalingNaN) {
    throw DiaphoraWouldRaise("D:1305 decimal.InvalidOperation", "comparison with a signaling NaN");
  }
  if (A.Type == PyDecimal::Kind::QuietNaN || B.Type == PyDecimal::Kind::QuietNaN) {
    return false;
  }
  if (A.Type == PyDecimal::Kind::Infinity || B.Type == PyDecimal::Kind::Infinity) {
    return A.Type == B.Type && A.Negative == B.Negative;
  }
  if (A.Coefficient.empty() || B.Coefficient.empty()) {
    return A.Coefficient.empty() && B.Coefficient.empty();  // 0 == -0 == 0E+5
  }
  return A.Negative == B.Negative && A.Coefficient == B.Coefficient && A.Exponent == B.Exponent;
}

// json.loads(value) of a fetched cell (D:1301 / D:1303).
PyValue JsonOfCell(const SqlCell& Cell, const char* Site) {
  switch (Cell.Type) {
    case SqlType::Text:
      try {
        return PyJsonLoads(Cell.Bytes);  // raises like json.loads (PyValue.cpp)
      } catch (const DiaphoraWouldRaise& Error) {
        throw DiaphoraWouldRaise(std::string(Site) + " " + Error.Site, Error.Detail);
      }
    case SqlType::Null:
      throw DiaphoraWouldRaise(std::string(Site) + " TypeError",
                               "the JSON object must be str, bytes or bytearray, not NoneType");
    case SqlType::Integer:
      throw DiaphoraWouldRaise(std::string(Site) + " TypeError", "the JSON object must be str, bytes or bytearray, not int");
    case SqlType::Real:
      throw DiaphoraWouldRaise(std::string(Site) + " TypeError",
                               "the JSON object must be str, bytes or bytearray, not float");
    case SqlType::Blob:
      // json.loads(bytes) first picks an encoding (json.detect_encoding); not ported.
      throw UnsupportedInput("check_callgraph: a BLOB callgraph_all_primes is not ported (json.loads of bytes)");
  }
  return PyValue();
}

// ---------------------------------------------------------------------------------------------
// The numbers of jkutils/factor.py _difference / difference and D:1315-1319.

struct PyNumber {
  bool IsFloat = false;
  BigInt Int;          // int or bool (True is 1)
  double Float = 0.0;  // float
};

std::optional<PyNumber> AsNumber(const PyValue& V) {
  PyNumber N;
  switch (V.Type) {
    case PyValue::Kind::Bool:
      N.Int.Mag = V.BoolValue ? "1" : "";
      return N;
    case PyValue::Kind::Int: {
      std::string_view Digits = V.IntDigits;
      if (!Digits.empty() && Digits[0] == '-') {
        N.Int.Negative = true;
        Digits.remove_prefix(1);
      }
      N.Int.Mag = Digits == "0" ? std::string() : std::string(Digits);
      N.Int.Negative = N.Int.Negative && !N.Int.Mag.empty();
      return N;
    }
    case PyValue::Kind::Float:
      N.IsFloat = true;
      N.Float = V.FloatValue;
      return N;
    default:
      return std::nullopt;
  }
}

// int == float, compared exactly as Python does (no rounding of the int).
bool IntEqualsFloat(const BigInt& I, double F) {
  if (!std::isfinite(F) || F != std::floor(F)) {
    return false;
  }
  const PyDecimal D = DecimalOfDouble(F);  // integral: exponent >= 0 after normalisation
  if (D.Coefficient.empty()) {
    return I.Mag.empty();
  }
  std::string Mag = D.Coefficient;
  Mag.append(static_cast<size_t>(D.Exponent), '0');
  return I.Negative == D.Negative && I.Mag == Mag;
}

// `a != b` for two JSON values (factor.py:221 / :228). Numbers compare by value (a float NaN is never
// equal, even to itself: float.__ne__ has no identity shortcut); anything else by Python ==, which
// PyEquals implements (containers compare their items with the identity shortcut, and json's NaN is
// one shared object, so a nested NaN equals itself).
bool PyNotEqual(const PyValue& A, const PyValue& B) {
  const std::optional<PyNumber> X = AsNumber(A);
  const std::optional<PyNumber> Y = AsNumber(B);
  if (X && Y) {
    if (!X->IsFloat && !Y->IsFloat) {
      return X->Int.Negative != Y->Int.Negative || X->Int.Mag != Y->Int.Mag;
    }
    if (X->IsFloat && Y->IsFloat) {
      return X->Float != Y->Float;
    }
    return X->IsFloat ? !IntEqualsFloat(Y->Int, X->Float) : !IntEqualsFloat(X->Int, Y->Float);
  }
  return !PyEquals(A, B);
}

[[noreturn]] void RaiseIntTooLarge(const char* Site) {
  throw DiaphoraWouldRaise(std::string(Site) + " OverflowError", "int too large to convert to float");
}

// max(a, b) - min(a, b) (factor.py:222 / :229) for two values that are not equal. Only numbers
// support '-' among JSON types, so any other operand raises TypeError (in the comparison inside max()
// or in the subtraction). A mixed int / float pair converts the int: OverflowError when it is too
// large for a double. The float result's value is only kept approximately (see SumValues).
PyNumber MaxMinusMin(const PyValue& A, const PyValue& B) {
  const std::optional<PyNumber> X = AsNumber(A);
  const std::optional<PyNumber> Y = AsNumber(B);
  if (!X || !Y) {
    throw DiaphoraWouldRaise("jkutils/factor.py:222 TypeError", "max()/min()/- of non-numeric JSON values");
  }
  PyNumber R;
  if (!X->IsFloat && !Y->IsFloat) {
    R.Int = BigAbsDiff(X->Int, Y->Int);
    return R;
  }
  if (!X->IsFloat && FloatOverflows(X->Int)) {
    RaiseIntTooLarge("jkutils/factor.py:222");
  }
  if (!Y->IsFloat && FloatOverflows(Y->Int)) {
    RaiseIntTooLarge("jkutils/factor.py:222");
  }
  const double Fx = X->IsFloat ? X->Float : BigToDouble(X->Int);
  const double Fy = Y->IsFloat ? Y->Float : BigToDouble(Y->Int);
  R.IsFloat = true;
  R.Float = std::fabs(Fx - Fy);
  return R;
}

// sum(values) (factor.py:242 and D:1315): start 0, left to right. int + int stays exact; the first
// float converts the running int, and every later int is converted (OverflowError past the double
// range: CPython's builtin sum() falls back to PyNumber_Add for ints that do not fit a C long, with
// the same result and the same errors as `+`); any other value raises TypeError. Whether it raises
// does not depend on float values. The float VALUE of such a sum is not reproduced (CPython 3.12+
// sums floats with Neumaier compensation): the value is approximate and flagged by IsFloat.
PyNumber SumValues(const std::vector<PyNumber>& Values, const char* Site) {
  PyNumber Acc;  // int 0
  for (const PyNumber& V : Values) {
    if (!Acc.IsFloat && !V.IsFloat) {
      Acc.Int = BigAdd(Acc.Int, V.Int);
    } else if (!Acc.IsFloat) {
      if (FloatOverflows(Acc.Int)) {
        RaiseIntTooLarge(Site);
      }
      Acc.Float = BigToDouble(Acc.Int) + V.Float;
      Acc.IsFloat = true;
    } else if (!V.IsFloat) {
      if (FloatOverflows(V.Int)) {
        RaiseIntTooLarge(Site);
      }
      Acc.Float += BigToDouble(V.Int);
    } else {
      Acc.Float += V.Float;
    }
  }
  return Acc;
}

std::vector<PyNumber> NumbersOf(const std::vector<const PyValue*>& Values, const char* Site) {
  std::vector<PyNumber> Out;
  Out.reserve(Values.size());
  for (const PyValue* V : Values) {
    const std::optional<PyNumber> N = AsNumber(*V);
    if (!N) {
      throw DiaphoraWouldRaise(std::string(Site) + " TypeError", "unsupported operand type(s) for +");
    }
    Out.push_back(*N);
  }
  return Out;
}

struct CallgraphOutcome {
  bool Equal = false;                // cg1 == cg2 (D:1305)
  std::optional<double> Percent;     // the returned percent, when it is exactly known
};

// The body of get_callgraph_difference after the two rows are read (D:1305-1320).
CallgraphOutcome CallgraphDifference(const PyDecimal& Cg1, const PyValue& Factors1, const PyDecimal& Cg2,
                                     const PyValue& Factors2) {
  CallgraphOutcome Out;
  if (DecimalEquals(Cg1, Cg2)) {  // D:1305-1310
    Out.Equal = true;
    Out.Percent = 0.0;
    return Out;
  }
  // D:1312-1313 FACTORS_CACHE[cg] = factors: hash(Decimal) raises only for a signalling NaN, which
  // the == above already raised for. factor.py:210-215: both numbers are then found in the cache, so
  // s = [cg_factors1, cg_factors2] and factorization() is never called.
  // factor.py:219 list(s[0].keys()); factor.py:220 list(s[1].keys()) inside the first loop, or
  // factor.py:226 when s[0] is empty: both values must be dicts (AttributeError otherwise).
  if (Factors1.Type != PyValue::Kind::Dict) {
    throw DiaphoraWouldRaise("jkutils/factor.py:219 AttributeError", "the main callgraph_all_primes JSON is not an object");
  }
  if (Factors2.Type != PyValue::Kind::Dict) {
    throw DiaphoraWouldRaise(Factors1.Items.empty() ? "jkutils/factor.py:226 AttributeError"
                                                    : "jkutils/factor.py:220 AttributeError",
                             "the diff callgraph_all_primes JSON is not an object");
  }
  std::unordered_map<std::string, size_t> Keys2;
  for (size_t Index = 0; Index < Factors2.Items.size(); ++Index) {
    Keys2.emplace(Factors2.Items[Index].StrValue, Index);
  }
  std::unordered_map<std::string, size_t> Keys1;
  for (size_t Index = 0; Index < Factors1.Items.size(); ++Index) {
    Keys1.emplace(Factors1.Items[Index].StrValue, Index);
  }
  // diffs (factor.py:218-231), in dict insertion order: a key keeps its first position when reassigned.
  std::vector<std::string> Order;
  std::unordered_map<std::string, std::pair<std::optional<PyNumber>, const PyValue*>> Diffs;
  const auto Assign = [&](const std::string& Key, std::optional<PyNumber> Number, const PyValue* Raw) {
    if (Diffs.find(Key) == Diffs.end()) {
      Order.push_back(Key);
    }
    Diffs[Key] = {std::move(Number), Raw};
  };
  for (size_t Index = 0; Index < Factors1.Items.size(); ++Index) {  // factor.py:219-224
    const std::string& Key = Factors1.Items[Index].StrValue;
    const PyValue& A = Factors1.DictValues[Index];
    const auto Found = Keys2.find(Key);
    if (Found != Keys2.end()) {
      const PyValue& B = Factors2.DictValues[Found->second];
      if (PyNotEqual(A, B)) {
        Assign(Key, MaxMinusMin(A, B), nullptr);
      }
    } else {
      Assign(Key, std::nullopt, &A);
    }
  }
  for (size_t Index = 0; Index < Factors2.Items.size(); ++Index) {  // factor.py:226-231
    const std::string& Key = Factors2.Items[Index].StrValue;
    const PyValue& B = Factors2.DictValues[Index];
    const auto Found = Keys1.find(Key);
    if (Found != Keys1.end()) {
      const PyValue& A = Factors1.DictValues[Found->second];
      if (PyNotEqual(B, A)) {
        Assign(Key, MaxMinusMin(A, B), nullptr);  // max(s[0][x], s[1][x]) - min(...)
      }
    } else {
      Assign(Key, std::nullopt, &B);
    }
  }
  // factor.py:242 sum(diffs.values())
  std::vector<PyNumber> DiffValues;
  for (const std::string& Key : Order) {
    const auto& Entry = Diffs[Key];
    if (Entry.first) {
      DiffValues.push_back(*Entry.first);
    } else {
      const std::optional<PyNumber> N = AsNumber(*Entry.second);
      if (!N) {
        throw DiaphoraWouldRaise("jkutils/factor.py:242 TypeError", "unsupported operand type(s) for +");
      }
      DiffValues.push_back(*N);
    }
  }
  const PyNumber Diff = SumValues(DiffValues, "jkutils/factor.py:242");
  // D:1315 total = sum(cg_factors1.values())
  std::vector<const PyValue*> Values1;
  for (const PyValue& V : Factors1.DictValues) {
    Values1.push_back(&V);
  }
  const PyNumber Total = SumValues(NumbersOf(Values1, "D:1315"), "D:1315");
  // D:1316-1319: `if total == 0 or diff == 0: return 0`, then percent = diff * 100.0 / total. Only an
  // int operand can raise there (OverflowError converting it to float). The value of a float sum is not
  // reproduced (SumValues), so a float's `== 0` is only known when it decides nothing that is observable:
  // with no big int left to convert, the float case just leaves the (log-only) percent unknown; with one,
  // whether Python raises depends on that zero test, and the input is refused instead of guessed.
  const bool DiffBig = !Diff.IsFloat && FloatOverflows(Diff.Int);
  const bool TotalBig = !Total.IsFloat && FloatOverflows(Total.Int);
  if (!Total.IsFloat && Total.Int.Mag.empty()) {
    Out.Percent = 0.0;  // total == 0
    return Out;
  }
  if (Total.IsFloat) {
    if (!Diff.IsFloat && Diff.Int.Mag.empty()) {
      Out.Percent = 0.0;  // total == 0 or diff == 0: returns 0 either way
      return Out;
    }
    if (DiffBig) {
      throw UnsupportedInput("check_callgraph: NOT PORTED: a float sum() zero test (total == 0, D:1316) decides whether "
                             "an int too large for a double is converted (D:1319)");
    }
    return Out;  // no raise possible; the percent is not reproduced
  }
  if (!Diff.IsFloat && Diff.Int.Mag.empty()) {
    Out.Percent = 0.0;  // diff == 0
    return Out;
  }
  if (Diff.IsFloat) {
    if (TotalBig) {
      throw UnsupportedInput("check_callgraph: NOT PORTED: a float sum() zero test (diff == 0, D:1316) decides whether "
                             "an int too large for a double is converted (D:1319)");
    }
    return Out;
  }
  if (DiffBig || TotalBig) {
    RaiseIntTooLarge("D:1319");  // diff * 100.0 or / total converts the int
  }
  Out.Percent = BigToDouble(Diff.Int) * 100.0 / BigToDouble(Total.Int);  // D:1319
  return Out;
}

}

bool StageCheckVersion(DiffSession& S) {
  // D:3577-3583: cur.execute("select value from diff.version") inside try/except: any error (no such
  // table, no such column, a corrupt file) logs two lines and diff() returns False; __main__ still
  // calls save_results (D:3772-3773), which writes empty tables (01 §5.1).
  Statement Q;
  bool HasRow = false;
  try {
    Q = S.Db().Prepare(kSqlVersion);
    HasRow = Q.Step();  // execute steps a SELECT once
  } catch (const DiaphoraWouldRaise& Error) {
    S.Log().Info("Error: " + Error.Detail);                                                      // D:3580
    S.Log().Info("The selected file does not look like a valid Diaphora exported database!");  // D:3581
    return false;                                                                                // D:3583
  }
  // D:3585-3588: row = cur.fetchone(); `if not row` is true only for None (a sqlite3.Row of one
  // column is truthy).
  if (!HasRow) {
    S.Log().Info("Invalid database!");
    return false;
  }
  // fetchone() decodes the row (outside the try: an invalid UTF-8 value propagates) and steps again.
  RequireDecodable(Q, 0);
  const bool Matches = Q.Type(0) == SqlType::Text && Q.Text(0) == kVersionValue;
  const std::string Shown = PyStrOfCell(Q, 0);
  Q.Step();
  // D:3590-3591: a different value only logs the warning (row[0] rendered by the f-string).
  if (!Matches) {
    S.Log().Info("WARNING: The database is from a different version (current " + std::string(kVersionValue) +
                 ", database " + Shown + ")!");
  }
  return true;
}

bool StageEqualDb(DiffSession& S) {
  // D:668-671 md5 count; `row["total"] == 1`.
  Statement Md5 = S.Db().Prepare(kSqlEqualDbMd5);
  Md5.Step();
  bool Ret = CountValue(Md5, 0, "equal_db") == 1;
  if (!Ret) {
    // D:673-681 rows of (id, address, size, nodes, edges) only in main; `row["total"] == 0`.
    Statement Except = S.Db().Prepare(kSqlEqualDbExcept);
    Except.Step();
    Ret = CountValue(Except, 0, "equal_db") == 0;
  } else {
    S.Log().Info("Same MD5 in both databases");  // D:683
  }
  S.Ext<Early::EarlyFacts>().EqualDb = Ret;
  return Ret;  // D:687; diff() only logs it (D:3600-3601)
}

void StageCheckCallgraph(DiffSession& S) {
  // D:1294-1298: the program rows of both databases (union all keeps main first), fetchall(): every
  // row is fetched and decoded before any is used.
  Statement Q = S.Db().Prepare(kSqlCallgraph);
  const int ColPrimes = Q.FindColumn("callgraph_primes");
  const int ColAll = Q.FindColumn("callgraph_all_primes");
  std::vector<std::pair<SqlCell, SqlCell>> Rows;
  while (Q.Step()) {
    RequireRowDecodable(Q);
    Rows.emplace_back(Q.Cell(ColPrimes), Q.Cell(ColAll));
  }
  if (Rows.size() != 2) {  // D:1299, D:1321-1322
    throw DiaphoraWouldRaise("D:1322 Exception", "Not enough rows in databases! Size is " + std::to_string(Rows.size()));
  }
  // D:1300-1303, in this order.
  const PyDecimal Cg1 = DecimalOfCell(Rows[0].first, "D:1300");
  const PyValue Factors1 = JsonOfCell(Rows[0].second, "D:1301");
  const PyDecimal Cg2 = DecimalOfCell(Rows[1].first, "D:1302");
  const PyValue Factors2 = JsonOfCell(Rows[1].second, "D:1303");

  const CallgraphOutcome Outcome = CallgraphDifference(Cg1, Factors1, Cg2, Factors2);
  std::optional<std::string> Line;
  if (Outcome.Equal) {
    // D:1307-1308 (Warning(msg) at D:1309 only builds an exception object)
    S.Log().Info("Call graph signature for both databases is equal, the programs seem to be 100% equal structurally");
  }
  // check_callgraph (D:1330-1336); self.percent (D:1338) is never read again (05 §3).
  if (Outcome.Percent) {
    const double Percent = *Outcome.Percent;
    if (Percent == 0) {
      Line = "Call graphs are 100% equal";
    } else if (Percent >= 100) {
      Line = "Call graphs are absolutely different";
    } else {
      Line = "Call graphs from both programs differ in " + PyReprFloat(Percent) + "%";
    }
    S.Log().Info(*Line);
  }
  // Otherwise a float took part in the sums and the value (not whether it raises) is not reproduced:
  // the log line is left out.
  S.Ext<Early::EarlyFacts>().CallgraphLog = Line;
}

bool StageSameProcessor(DiffSession& S) {
  // D:2957-2964: `select 1 from main.program mp, diff.program dp where mp.processor = dp.processor`,
  // fetchone() is not None. SQL `=`: TEXT compared with BINARY collation, NULL never equal (01 §5.6).
  Statement Q = S.Db().Prepare(kSqlSameProcessor);
  const bool Ret = Q.Step();
  if (Ret) {
    Q.Step();  // fetchone() steps once more after building the row
  }
  return Ret;
}

}
