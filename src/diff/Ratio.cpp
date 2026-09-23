// The similarity ratio (lane L2). Literal port of CBinDiff.check_ratio (D:1645-1775), deep_ratio
// (D:2749-2837), compare_function_rows (D:2479-2538), quick_ratio / check_bufs (D:150-165) over
// difflib.SequenceMatcher.quick_ratio (difflib.py:622-649, _calculate_ratio 39-42), the 7-decimal
// rounding float("{0:.7f}".format(v)) (D:1676) and ratios_cache (D:431, D:1653-1655, D:1774).
// Spec: 03a in full, 03b §4.1-§4.2, 07 §10.6, plan §3.8. Default configuration only (03a §0): relaxed
// ratio and ML are refused by DiffConfig::Supported, so their branches (D:1677-1697, 1732-1737,
// 1742-1744, 2823-2833) are not ported.
//
// Python semantics kept on purpose:
//   * the cache is looked up first (D:1654), then float(md1), float(md2) run (D:1672-1673), then the
//     bytes_hash shortcut (D:1681); an exception stores nothing (03a §6.3, §8);
//   * None == None is True for bytes_hash, indegree, outdegree, switches and cyclomatic_complexity,
//     and None != 0 / None != "[]" are True (03a §7.1, Hard parts 4);
//   * floating point in exactly Python's evaluation order; the library is built with /fp:precise or
//     -ffp-contract=off (plan §3.12, 03a Hard parts 2);
//   * a BLOB cell (Python bytes) is followed where Python's behaviour is plain (== and != with str),
//     raises where Python raises (bytes.split("\n") in quick_ratio) and is refused where Python would
//     need more than that (json.loads(bytes), non-INTEGER integer cells).

#include "dsigmatcher/diff/Ratio.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <limits>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "dsigmatcher/diff/Config.h"
#include "dsigmatcher/diff/Errors.h"
#include "dsigmatcher/diff/Pipeline.h"
#include "dsigmatcher/diff/PyValue.h"
#include "dsigmatcher/diff/Table.h"

namespace DSig::Diff {

// Test seam for the vector self-test of plan §4 L2 ("the mutation table of 03a §13 must fail when
// each mutation is applied"). Declared here and in tests/diff/ratio_tests.cpp only; never called by
// the engine or the CLI. An empty name clears every mutation; returns false for an unknown name.
namespace Testing {
bool SetRatioMutationForTesting(std::string_view Name);
}

namespace {

// ---------------------------------------------------------------------------------------------
// Mutations (03a §13). Zero in every production run.

enum RatioMutation : uint32_t {
  kMutRoundHalfUp = 1u << 0,          // "round half-up"
  kMutNoRounding = 1u << 1,           // "no rounding"
  kMutNoClamp = 1u << 2,              // "no 0.99 clamp"
  kMutConstantsAsDoubles = 1u << 3,   // "constants as doubles"
  kMutNoV5ShortCircuit = 1u << 4,     // "no v5 short-circuit"
  kMutNoMdGuard = 1u << 5,            // "no md guard"
  kMutNullBytesHashNotEqual = 1u << 6,  // "NULL bytes_hash not equal"
  kMutSplitLines = 1u << 7,           // "splitlines instead of split("\n")"
  kMutAlways008 = 1u << 8,            // "always 0.008 per constant"
  kMutMdAsStrings = 1u << 9,          // "md compared as strings (row path)"
  kMutSwapMdSource = 1u << 10,        // md from the other converter (plan §4 L2 md vectors)
};

uint32_t g_Mutations = 0;

// ---------------------------------------------------------------------------------------------
// Portable 128-bit arithmetic for the rounding step (no unsigned __int128 on MSVC).

struct U128 {
  uint64_t Hi = 0;
  uint64_t Lo = 0;
};

U128 Mul64(uint64_t A, uint64_t B) {
  const uint64_t ALo = A & 0xFFFFFFFFu;
  const uint64_t AHi = A >> 32;
  const uint64_t BLo = B & 0xFFFFFFFFu;
  const uint64_t BHi = B >> 32;
  const uint64_t LoLo = ALo * BLo;
  const uint64_t HiLo = AHi * BLo;
  const uint64_t LoHi = ALo * BHi;
  const uint64_t HiHi = AHi * BHi;
  const uint64_t Cross = (LoLo >> 32) + (HiLo & 0xFFFFFFFFu) + LoHi;
  U128 Result;
  Result.Lo = (Cross << 32) | (LoLo & 0xFFFFFFFFu);
  Result.Hi = HiHi + (HiLo >> 32) + (Cross >> 32);
  return Result;
}

U128 ShiftRight(U128 V, unsigned S) {  // S < 128
  if (S == 0) {
    return V;
  }
  if (S >= 64) {
    return U128{0, V.Hi >> (S - 64)};
  }
  return U128{V.Hi >> S, (V.Lo >> S) | (V.Hi << (64 - S))};
}

U128 ShiftLeft(U128 V, unsigned S) {  // S < 128
  if (S == 0) {
    return V;
  }
  if (S >= 64) {
    return U128{V.Lo << (S - 64), 0};
  }
  return U128{(V.Hi << S) | (V.Lo >> (64 - S)), V.Lo << S};
}

U128 Subtract(U128 A, U128 B) {
  U128 Result;
  Result.Lo = A.Lo - B.Lo;
  Result.Hi = A.Hi - B.Hi - (A.Lo < B.Lo ? 1u : 0u);
  return Result;
}

int Compare(U128 A, U128 B) {
  if (A.Hi != B.Hi) {
    return A.Hi < B.Hi ? -1 : 1;
  }
  if (A.Lo != B.Lo) {
    return A.Lo < B.Lo ? -1 : 1;
  }
  return 0;
}

std::string ToDecimal(U128 V) {
  if (V.Hi == 0) {
    return std::to_string(V.Lo);
  }
  // long division by 10 over four 32-bit limbs
  uint32_t Limbs[4] = {static_cast<uint32_t>(V.Hi >> 32), static_cast<uint32_t>(V.Hi),
                       static_cast<uint32_t>(V.Lo >> 32), static_cast<uint32_t>(V.Lo)};
  std::string Reversed;
  while (Limbs[0] != 0 || Limbs[1] != 0 || Limbs[2] != 0 || Limbs[3] != 0) {
    uint64_t Remainder = 0;
    for (uint32_t& Limb : Limbs) {
      const uint64_t Current = (Remainder << 32) | Limb;
      Limb = static_cast<uint32_t>(Current / 10);
      Remainder = Current % 10;
    }
    Reversed += static_cast<char>('0' + Remainder);
  }
  return std::string(Reversed.rbegin(), Reversed.rend());
}

// float("{0:.7f}".format(V)): Python formats the exact binary value correctly rounded with ties to
// even, and float() parses the text correctly rounded (03a §5). Integer algorithm of 03a §5 for any
// finite double; the result k / 10^7 is one IEEE division when k < 2^53, else an exact parse.
double RoundDecimal7(double V, uint32_t Mutations) {
  if ((Mutations & kMutNoRounding) != 0) {
    return V;
  }
  if (!std::isfinite(V) || V == 0.0) {
    return V;  // "nan" / "inf" / "0.0000000" (with its sign) parse back to the same value
  }
  constexpr uint64_t kScale = 10000000;  // 10^7, DECIMAL_VALUES = "7f" (C:120)
  const bool Negative = std::signbit(V);
  const double Magnitude = Negative ? -V : V;
  uint64_t Bits = 0;
  std::memcpy(&Bits, &Magnitude, sizeof Bits);
  const int Biased = static_cast<int>((Bits >> 52) & 0x7FF);
  uint64_t Mantissa = Bits & ((uint64_t{1} << 52) - 1);
  int64_t Exp2 = -1074;
  if (Biased != 0) {
    Mantissa |= uint64_t{1} << 52;
    Exp2 = Biased - 1075;
  }
  if (Exp2 >= 0) {
    return V;  // an integer (>= 2^52): the 7-decimal text is exact
  }
  const int64_t Shift = -Exp2;  // V = Mantissa / 2^Shift
  const U128 Numerator = Mul64(Mantissa, kScale);  // < 2^77
  U128 Quotient;
  if (Shift < 128) {
    const unsigned S = static_cast<unsigned>(Shift);
    Quotient = ShiftRight(Numerator, S);
    const U128 Remainder = Subtract(Numerator, ShiftLeft(Quotient, S));
    const U128 Half = ShiftLeft(U128{0, 1}, S - 1);
    const int Cmp = Compare(Remainder, Half);
    const bool Odd = (Quotient.Lo & 1u) != 0;
    const bool Up = Cmp > 0 || (Cmp == 0 && ((Mutations & kMutRoundHalfUp) != 0 || Odd));
    if (Up) {
      Quotient.Lo += 1;
      if (Quotient.Lo == 0) {
        Quotient.Hi += 1;
      }
    }
  }
  // Shift >= 128: V < 2^-75, far below 0.5e-7, so the quotient stays 0 (the 03a §5 guard).
  double Result = 0.0;
  if (Quotient.Hi == 0 && Quotient.Lo < (uint64_t{1} << 53)) {
    Result = static_cast<double>(Quotient.Lo) / static_cast<double>(kScale);
  } else {
    Result = *PyFloat(ToDecimal(Quotient) + "e-7");
  }
  return Negative ? -Result : Result;
}

// ---------------------------------------------------------------------------------------------
// Cell helpers with Python semantics

struct TextCell {
  bool Null = true;
  bool Blob = false;
  std::string_view Bytes;
};

TextCell CellOf(const TextColumn& Column, uint32_t Row) {
  TextCell Cell;
  if (Column.Null(Row)) {
    return Cell;
  }
  Cell.Null = false;
  Cell.Blob = Column.IsBlob[Row] != 0;
  Cell.Bytes = Column.View(Row);
  return Cell;
}

// Python ==: None == None; str never equals bytes.
bool PyEq(const TextCell& A, const TextCell& B) {
  if (A.Null || B.Null) {
    return A.Null && B.Null;
  }
  return A.Blob == B.Blob && A.Bytes == B.Bytes;
}

// Python `x != "<literal>"` (None and bytes are never equal to a str).
bool PyNe(const TextCell& A, std::string_view Literal) { return A.Null || A.Blob || A.Bytes != Literal; }

bool IsEmptyStr(const TextCell& A) { return !A.Null && !A.Blob && A.Bytes.empty(); }

void RequireInteger(const IntColumn& Column, uint32_t Row, const char* Name) {
  if (!Column.Null(Row) && Column.NotInteger[Row] != 0) {
    throw UnsupportedInput(std::string("functions.") + Name +
                           " holds a non-INTEGER value (Python float/str comparison semantics not ported)");
  }
}

// Python `a == b` on (None | int).
bool PyEqInt(const IntColumn& A, uint32_t RowA, const IntColumn& B, uint32_t RowB, const char* Name) {
  RequireInteger(A, RowA, Name);
  RequireInteger(B, RowB, Name);
  if (A.Null(RowA) || B.Null(RowB)) {
    return A.Null(RowA) && B.Null(RowB);
  }
  return A.Value[RowA] == B.Value[RowB];
}

// Python `a != 0` on (None | int): None != 0 is True.
bool PyNeZero(const IntColumn& A, uint32_t Row) { return A.Null(Row) || A.Value[Row] != 0; }

// int(str) for ASCII text (Objects/longobject.c PyLong_FromString, base 10): Py_ISSPACE stripped on
// both sides, an optional sign, digits with single '_' separators between digits. Returns
// str(int(text)); nullopt where Python raises ValueError.
std::optional<std::string> PyIntCanonical(std::string_view Text) {
  for (const char Ch : Text) {
    if (static_cast<unsigned char>(Ch) >= 0x80) {
      throw UnsupportedInput("int(): non-ASCII address text is not ported (Unicode digit/space mapping)");
    }
  }
  auto Space = [](char Ch) {
    return Ch == ' ' || Ch == '\t' || Ch == '\n' || Ch == '\v' || Ch == '\f' || Ch == '\r';
  };
  size_t Begin = 0;
  size_t End = Text.size();
  while (Begin < End && Space(Text[Begin])) {
    ++Begin;
  }
  while (End > Begin && Space(Text[End - 1])) {
    --End;
  }
  bool Negative = false;
  if (Begin < End && (Text[Begin] == '+' || Text[Begin] == '-')) {
    Negative = Text[Begin] == '-';
    ++Begin;
  }
  std::string Digits;
  char Prev = '\0';
  for (size_t Pos = Begin; Pos < End; ++Pos) {
    const char Ch = Text[Pos];
    if (Ch == '_') {
      if (!(Prev >= '0' && Prev <= '9')) {
        return std::nullopt;
      }
    } else if (Ch >= '0' && Ch <= '9') {
      Digits += Ch;
    } else {
      return std::nullopt;
    }
    Prev = Ch;
  }
  if (Digits.empty() || Prev == '_') {
    return std::nullopt;
  }
  const size_t First = Digits.find_first_not_of('0');
  if (First == std::string::npos) {
    return std::string("0");
  }
  Digits.erase(0, First);
  return Negative ? "-" + Digits : Digits;
}

// ---------------------------------------------------------------------------------------------
// quick_ratio over prepared line multisets (03a §2: order-independent, exact line equality)

enum class CellState : uint8_t { Null, EmptyStr, Blob, Text };

struct PreparedText {
  CellState State = CellState::Null;
  uint32_t Begin = 0;   // first (line id, count) run in Runs
  uint32_t Count = 0;   // number of runs
  uint64_t Pieces = 0;  // len(text.split("\n"))
};

struct PreparedColumn {
  std::vector<PreparedText> Rows[2];                           // [Side]
  std::vector<std::pair<uint32_t, uint32_t>> Runs[2];          // sorted by line id per row
  std::unordered_map<std::string_view, uint32_t> LineIds;      // shared by both sides
};

// str.split("\n") keeps empty fields: "a\nb\n" -> ["a", "b", ""] (03a §2). The mutation instead
// approximates str.splitlines() (no trailing empty piece, \r and \r\n also split).
void SplitPieces(std::string_view Text, bool SplitLinesMutation, std::vector<std::string_view>& Out) {
  Out.clear();
  if (!SplitLinesMutation) {
    size_t Start = 0;
    while (true) {
      const size_t Newline = Text.find('\n', Start);
      if (Newline == std::string_view::npos) {
        Out.push_back(Text.substr(Start));
        return;
      }
      Out.push_back(Text.substr(Start, Newline - Start));
      Start = Newline + 1;
    }
  }
  size_t Start = 0;
  size_t Pos = 0;
  while (Pos < Text.size()) {
    const char Ch = Text[Pos];
    if (Ch == '\n' || Ch == '\r' || Ch == '\v' || Ch == '\f') {
      Out.push_back(Text.substr(Start, Pos - Start));
      if (Ch == '\r' && Pos + 1 < Text.size() && Text[Pos + 1] == '\n') {
        ++Pos;
      }
      Start = Pos + 1;
    }
    ++Pos;
  }
  if (Start < Text.size()) {
    Out.push_back(Text.substr(Start));
  }
}

void PrepareColumn(PreparedColumn& Target, const TextColumn* Columns[2], bool SplitLinesMutation) {
  Target.LineIds.clear();
  std::vector<std::string_view> Pieces;
  std::vector<uint32_t> Ids;
  for (int SideIndex = 0; SideIndex < 2; ++SideIndex) {
    const TextColumn& Column = *Columns[SideIndex];
    auto& Rows = Target.Rows[SideIndex];
    auto& Runs = Target.Runs[SideIndex];
    Rows.assign(Column.Size(), PreparedText{});
    Runs.clear();
    for (uint32_t Row = 0; Row < Column.Size(); ++Row) {
      PreparedText& Out = Rows[Row];
      if (Column.Null(Row)) {
        Out.State = CellState::Null;
        continue;
      }
      if (Column.IsBlob[Row] != 0) {
        Out.State = CellState::Blob;
        continue;
      }
      const std::string_view Text = Column.View(Row);
      if (Text.empty()) {
        Out.State = CellState::EmptyStr;
        continue;
      }
      Out.State = CellState::Text;
      SplitPieces(Text, SplitLinesMutation, Pieces);
      Out.Pieces = Pieces.size();
      Ids.clear();
      for (const std::string_view Piece : Pieces) {
        const auto Inserted = Target.LineIds.emplace(Piece, static_cast<uint32_t>(Target.LineIds.size()));
        Ids.push_back(Inserted.first->second);
      }
      std::sort(Ids.begin(), Ids.end());
      Out.Begin = static_cast<uint32_t>(Runs.size());
      for (size_t Index = 0; Index < Ids.size();) {
        size_t Next = Index + 1;
        while (Next < Ids.size() && Ids[Next] == Ids[Index]) {
          ++Next;
        }
        Runs.emplace_back(Ids[Index], static_cast<uint32_t>(Next - Index));
        Index = Next;
      }
      Out.Count = static_cast<uint32_t>(Runs.size()) - Out.Begin;
    }
  }
}

// D:158-165 quick_ratio -> difflib quick_ratio: 2.0 * matches / (len(a) + len(b)).
double QuickPrepared(const PreparedColumn& Column, int SideA, uint32_t RowA, int SideB, uint32_t RowB,
                     const char* Name) {
  const PreparedText& A = Column.Rows[SideA][RowA];
  const PreparedText& B = Column.Rows[SideB][RowB];
  // D:150-155 check_bufs: None or "" on either side gives the int 0
  if (A.State == CellState::Null || B.State == CellState::Null) {
    return 0.0;
  }
  if (A.State == CellState::EmptyStr || B.State == CellState::EmptyStr) {
    return 0.0;
  }
  if (A.State == CellState::Blob || B.State == CellState::Blob) {
    // D:163 `buf1.split("\n")` on bytes
    throw DiaphoraWouldRaise("D:163 quick_ratio",
                             std::string("TypeError: a bytes-like object is required, not 'str' (BLOB in ") + Name +
                                 ")");
  }
  const auto* RunA = Column.Runs[SideA].data() + A.Begin;
  const auto* RunB = Column.Runs[SideB].data() + B.Begin;
  const auto* EndA = RunA + A.Count;
  const auto* EndB = RunB + B.Count;
  uint64_t Matches = 0;  // difflib.py:634-648: sum over lines of min(count_a, count_b)
  while (RunA != EndA && RunB != EndB) {
    if (RunA->first < RunB->first) {
      ++RunA;
    } else if (RunB->first < RunA->first) {
      ++RunB;
    } else {
      Matches += std::min(RunA->second, RunB->second);
      ++RunA;
      ++RunB;
    }
  }
  // difflib.py:39-42 _calculate_ratio: 2.0 * matches / length (length >= 2 here)
  return (2.0 * static_cast<double>(Matches)) / static_cast<double>(A.Pieces + B.Pieces);
}

// ---------------------------------------------------------------------------------------------
// Cached per-row values whose computation can raise: they raise again on every use, as Python
// recomputes them on every call.

struct Failure {
  bool Unsupported = false;
  std::string Site;
  std::string Detail;

  [[noreturn]] void Throw() const {
    if (Unsupported) {
      throw UnsupportedInput(Detail);
    }
    throw DiaphoraWouldRaise(Site, Detail);
  }
};

struct MdValue {
  uint8_t State = 0;  // 0 not computed, 1 value, 2 failure
  double Value = 0.0;
  Failure Error;
};

struct ConstSet {
  uint8_t State = 0;  // 0 not computed, 1 set, 2 failure
  PySet Set;
  Failure Error;
};

}  // namespace

// ---------------------------------------------------------------------------------------------

struct RatioEngine::Impl {
  explicit Impl(DiffSession& Session) : S(Session) {}

  DiffSession& S;

  // ratios_cache (D:431, reset at D:3572). Python keys it by the text f"{ea1}-{ea2}" (D:1653). A pair
  // of dash-free address texts other than "None" has exactly one '-' in its key, so it can never
  // collide with any other pair and is keyed by ids; every other pair is keyed by the exact text.
  std::unordered_map<uint64_t, uint32_t> ById;
  std::unordered_map<std::string, uint32_t> ByText;
  std::vector<CacheEntry> Entries;

  // Prepared data (Prepare): valid for these table sizes and this mutation mask.
  bool Prepared = false;
  size_t PreparedMain = 0;
  size_t PreparedDiff = 0;
  uint32_t PreparedMutations = 0;
  PreparedColumn CleanPseudo;
  PreparedColumn CleanAssembly;
  PreparedColumn CleanMicrocode;
  std::vector<MdValue> MdPy[2];
  std::vector<ConstSet> Consts[2];

  const FunctionTable& Table(Side Which) const { return S.Export(Which).Functions; }

  static int SideIndex(Side Which) { return Which == Side::Main ? 0 : 1; }

  // ---- cache ----
  mutable std::vector<int8_t> SimpleById;  // per AddrId: -1 unknown, 0 text key, 1 id key

  bool SimpleAddr(AddrId Id) const {
    if (Id == kNoneAddr) {
      return false;
    }
    const size_t Index = static_cast<size_t>(Id);
    if (Index >= SimpleById.size()) {
      SimpleById.resize(Index + 1024, -1);
    }
    if (SimpleById[Index] < 0) {
      const std::string_view Text = S.Ids().AddrText(Id);
      SimpleById[Index] = (Text != "None" && Text.find('-') == std::string_view::npos) ? 1 : 0;
    }
    return SimpleById[Index] == 1;
  }

  static uint64_t IdKey(AddrId Ea1, AddrId Ea2) {
    return (static_cast<uint64_t>(static_cast<uint32_t>(Ea1)) << 32) | static_cast<uint32_t>(Ea2);
  }

  std::string TextKey(AddrId Ea1, AddrId Ea2) const {
    std::string Key(S.Ids().AddrKeyText(Ea1));  // f"{ea1}-{ea2}" (D:1653); None renders "None"
    Key += '-';
    Key += S.Ids().AddrKeyText(Ea2);
    return Key;
  }

  std::optional<double> Find(AddrId Ea1, AddrId Ea2) const {
    if (SimpleAddr(Ea1) && SimpleAddr(Ea2)) {
      const auto Found = ById.find(IdKey(Ea1, Ea2));
      if (Found != ById.end()) {
        return Entries[Found->second].Ratio;
      }
      return std::nullopt;
    }
    const auto Found = ByText.find(TextKey(Ea1, Ea2));
    if (Found != ByText.end()) {
      return Entries[Found->second].Ratio;
    }
    return std::nullopt;
  }

  void Store(AddrId Ea1, AddrId Ea2, double Ratio) {
    const uint32_t Index = static_cast<uint32_t>(Entries.size());
    bool Inserted = false;
    if (SimpleAddr(Ea1) && SimpleAddr(Ea2)) {
      Inserted = ById.emplace(IdKey(Ea1, Ea2), Index).second;
    } else {
      Inserted = ByText.emplace(TextKey(Ea1, Ea2), Index).second;
    }
    if (Inserted) {  // check_ratio stores only on a miss, so the first writer always wins (03a §8)
      Entries.push_back(CacheEntry{Ea1, Ea2, Ratio});
    }
  }

  // ---- preparation ----
  void EnsurePrepared() {
    if (!Prepared || PreparedMutations != g_Mutations || PreparedMain != Table(Side::Main).Count() ||
        PreparedDiff != Table(Side::Diff).Count()) {
      PrepareAll();
    }
  }

  void PrepareAll() {
    const FunctionTable& Main = Table(Side::Main);
    const FunctionTable& Diff = Table(Side::Diff);
    const bool SplitLines = (g_Mutations & kMutSplitLines) != 0;
    const TextColumn* Pseudo[2] = {&Main.CleanPseudo, &Diff.CleanPseudo};
    const TextColumn* Assembly[2] = {&Main.CleanAssembly, &Diff.CleanAssembly};
    const TextColumn* Micro[2] = {&Main.CleanMicrocode, &Diff.CleanMicrocode};
    PrepareColumn(CleanPseudo, Pseudo, SplitLines);
    PrepareColumn(CleanAssembly, Assembly, SplitLines);
    PrepareColumn(CleanMicrocode, Micro, SplitLines);
    MdPy[0].assign(Main.Count(), MdValue{});
    MdPy[1].assign(Diff.Count(), MdValue{});
    Consts[0].assign(Main.Count(), ConstSet{});
    Consts[1].assign(Diff.Count(), ConstSet{});
    PreparedMain = Main.Count();
    PreparedDiff = Diff.Count();
    PreparedMutations = g_Mutations;
    Prepared = true;
  }

  // ---- md_index ----
  // compare_function_rows path: float(<md_index TEXT>) (D:2498 -> D:1672).
  double MdPython(Side Which, uint32_t Row) {
    MdValue& Slot = MdPy[SideIndex(Which)][Row];
    if (Slot.State == 0) {
      const TextCell Cell = CellOf(Table(Which).MdIndex, Row);
      Slot.State = 2;
      if (Cell.Null) {
        Slot.Error = Failure{false, "D:1672 float(md_index)",
                             "TypeError: float() argument must be a string or a real number, not 'NoneType'"};
      } else {
        try {
          bool Ascii = true;
          for (const char Ch : Cell.Bytes) {
            Ascii = Ascii && static_cast<unsigned char>(Ch) < 0x80;
          }
          // float(bytes) parses the raw bytes (no Unicode mapping), so non-ASCII simply fails there
          const std::optional<double> Value = (Cell.Blob && !Ascii) ? std::nullopt : PyFloat(Cell.Bytes);
          if (Value) {
            Slot.State = 1;
            Slot.Value = *Value;
          } else {
            Slot.Error = Failure{false, "D:1672 float(md_index)",
                                 "ValueError: could not convert string to float: '" + std::string(Cell.Bytes) + "'"};
          }
        } catch (const UnsupportedInput& Error) {
          Slot.Error = Failure{true, "", Error.What};
        }
      }
    }
    if (Slot.State == 2) {
      Slot.Error.Throw();
    }
    return Slot.Value;
  }

  // check_match path: row["md1"] = cast(f.md_index as real) evaluated by SQLite (H:57, 03a §6.4).
  static double MdSqlOf(const std::optional<double>& Value) {
    if (!Value) {
      throw DiaphoraWouldRaise("D:1672 float(md)",
                               "TypeError: float() argument must be a string or a real number, not 'NoneType'");
    }
    return *Value;
  }

  double MdSqlFromTable(Side Which, uint32_t Row) const {
    const FunctionTable& T = Table(Which);
    return MdSqlOf(T.MdSqlNull[Row] != 0 ? std::nullopt : std::optional<double>(T.MdSqlReal[Row]));
  }

  // ---- constants ----
  // set(json.loads(row["constants"])) (D:2813-2814).
  const PySet& ConstantsOf(Side Which, uint32_t Row) {
    ConstSet& Slot = Consts[SideIndex(Which)][Row];
    if (Slot.State == 0) {
      const TextCell Cell = CellOf(Table(Which).Constants, Row);
      Slot.State = 2;
      if (Cell.Null) {
        Slot.Error = Failure{false, "D:2813 json.loads(constants)",
                             "TypeError: the JSON object must be str, bytes or bytearray, not NoneType"};
      } else if (Cell.Blob) {
        Slot.Error = Failure{true, "", "functions.constants is a BLOB (json.loads(bytes) encoding detection not ported)"};
      } else {
        try {
          std::vector<PyValue> Items = PyJsonLoadsList(Cell.Bytes);
          if ((g_Mutations & kMutConstantsAsDoubles) != 0) {
            for (PyValue& Item : Items) {
              if (Item.Type == PyValue::Kind::Int) {
                Item.Type = PyValue::Kind::Float;
                Item.FloatValue = *PyFloat(Item.IntDigits);
              }
            }
          }
          Slot.Set = PySetFromList(Items);
          Slot.State = 1;
        } catch (const DiaphoraWouldRaise& Error) {
          Slot.Error = Failure{false, Error.Site, Error.Detail};
        } catch (const UnsupportedInput& Error) {
          Slot.Error = Failure{true, "", Error.What};
        }
      }
    }
    if (Slot.State == 2) {
      Slot.Error.Throw();
    }
    return Slot.Set;
  }

  // ---- deep_ratio ----
  // D:2749-2837 on the two full rows. The additions happen one at a time in this order (03a §7.2).
  double DeepScore(uint32_t MainRow, uint32_t DiffRow) {
    EnsurePrepared();
    const FunctionTable& M = Table(Side::Main);
    const FunctionTable& D = Table(Side::Diff);
    double Score = 0.0;  // Python int 0; 0 + 0.001 == 0.001 exactly

    // D:2780-2784
    const TextCell Source1 = CellOf(M.SourceFile, MainRow);
    const TextCell Source2 = CellOf(D.SourceFile, DiffRow);
    if (!Source1.Null && !Source2.Null) {
      if (PyEq(Source1, Source2) && PyNe(Source1, "")) {
        Score += 0.001;
      }
    }
    // D:2786-2790
    const TextCell Primes1 = CellOf(M.PseudocodePrimes, MainRow);
    const TextCell Primes2 = CellOf(D.PseudocodePrimes, DiffRow);
    if (!Primes1.Null && !Primes2.Null) {
      if (PyEq(Primes1, Primes2) && PyNe(Primes1, "")) {
        Score += 0.001;
      }
    }
    // D:2792-2795
    if (PyEqInt(M.Indegree, MainRow, D.Indegree, DiffRow, "indegree") && PyNeZero(M.Indegree, MainRow)) {
      Score += 0.001;
    }
    // D:2797-2800
    if (PyEqInt(M.Outdegree, MainRow, D.Outdegree, DiffRow, "outdegree") && PyNeZero(M.Outdegree, MainRow)) {
      Score += 0.001;
    }
    // D:2802-2805: raw text equality, not parsed
    const TextCell Switches1 = CellOf(M.Switches, MainRow);
    const TextCell Switches2 = CellOf(D.Switches, DiffRow);
    if (PyEq(Switches1, Switches2) && PyNe(Switches1, "[]")) {
      Score += 0.003;
    }
    // D:2807-2810
    if (PyEqInt(M.CyclomaticComplexity, MainRow, D.CyclomaticComplexity, DiffRow, "cyclomatic_complexity") &&
        PyNeZero(M.CyclomaticComplexity, MainRow)) {
      Score += 0.001;
    }
    // D:2812-2821
    if (PyNe(CellOf(M.Constants, MainRow), "[]")) {
      const PySet& Set1 = ConstantsOf(Side::Main, MainRow);
      const PySet& Set2 = ConstantsOf(Side::Diff, DiffRow);
      const size_t Common = PySetIntersectionSize(Set1, Set2);
      if (Common > 0) {
        double Tmp = kIncreaseRatioPerConstantMatch;  // C:148
        if (S.Flags().IsSameProcessor && (g_Mutations & kMutAlways008) == 0) {
          Tmp = kIncreaseRatioPerConstantMatchSameCpu;  // C:147
        }
        const double Product = static_cast<double>(Common) * Tmp;  // len(set_result) * tmp
        Score += Product;
      }
    }
    // D:2823-2833: self.classifier is None in the parity configuration (ML off, 03a §9)
    return Score;
  }

  // D:2763-2764 int(main_d["ea"]), int(diff_d["ea"]); the lookups below bind str() of the result.
  std::string CanonicalAddress(AddrId Ea, const char* Site) const {
    if (Ea == kNoneAddr) {
      throw DiaphoraWouldRaise(Site, "TypeError: int() argument must be a string, a bytes-like object or a real "
                                     "number, not 'NoneType'");
    }
    const std::string_view Text = S.Ids().AddrText(Ea);
    std::optional<std::string> Canonical = PyIntCanonical(Text);
    if (!Canonical) {
      throw DiaphoraWouldRaise(Site, "ValueError: invalid literal for int() with base 10: '" + std::string(Text) + "'");
    }
    return std::move(*Canonical);
  }

  // D:2772-2778 `select * from {db}.functions where address = ?` + fetchone(): address is `text
  // unique`, TEXT = TEXT is byte equality, and the fetch decodes every column of the row.
  uint32_t FetchRowByAddress(Side Which, const std::string& Canonical, const char* Site) const {
    const FunctionTable& T = Table(Which);
    std::optional<uint32_t> Row;
    if (const std::optional<AddrId> Id = S.Ids().FindAddr(Canonical)) {
      Row = T.FindRow(*Id);
    }
    if (Row && T.Address.IsBlob[*Row] != 0) {
      Row.reset();  // a TEXT parameter never equals a BLOB cell in SQLite
    }
    if (Row && T.AnyColumnUtf8Bad[*Row] != 0) {
      throw DiaphoraWouldRaise(Site, "OperationalError: Could not decode to UTF-8 a functions column");
    }
    return Row ? *Row : kNoRow;
  }

  double DeepRatioByAddress(AddrId Ea1, AddrId Ea2) {
    const std::string Address1 = CanonicalAddress(Ea1, "D:2763 deep_ratio int(ea1)");
    const std::string Address2 = CanonicalAddress(Ea2, "D:2764 deep_ratio int(ea2)");
    const uint32_t MainRow = FetchRowByAddress(Side::Main, Address1, "D:2775 deep_ratio fetchone (main)");
    const uint32_t DiffRow = FetchRowByAddress(Side::Diff, Address2, "D:2778 deep_ratio fetchone (diff)");
    // D:2780-2781 main_row["source_file"], diff_row["source_file"] on a None row
    if (MainRow == kNoRow) {
      throw DiaphoraWouldRaise("D:2780 deep_ratio", "TypeError: 'NoneType' object is not subscriptable (main row)");
    }
    if (DiffRow == kNoRow) {
      throw DiaphoraWouldRaise("D:2781 deep_ratio", "TypeError: 'NoneType' object is not subscriptable (diff row)");
    }
    return DeepScore(MainRow, DiffRow);
  }

  // ---- check_ratio ----
  double CheckRatio(AddrId Ea1, AddrId Ea2, Side Side1, uint32_t Row1, Side Side2, uint32_t Row2, MdSource Src,
                    const std::optional<double>& SqlMd1, const std::optional<double>& SqlMd2) {
    // D:1651-1655
    if (const std::optional<double> Hit = Find(Ea1, Ea2)) {
      return *Hit;
    }
    EnsurePrepared();
    if (Row1 == kNoRow || Row2 == kNoRow || Row1 >= Table(Side1).Count() || Row2 >= Table(Side2).Count()) {
      throw UnsupportedInput("check_ratio: an address of the pair has no function row");
    }
    const double Ratio = Compute(Ea1, Ea2, Side1, Row1, Side2, Row2, Src, SqlMd1, SqlMd2);
    Store(Ea1, Ea2, Ratio);  // D:1682/1718/1729/1736/1743/1752/1774: every return path stores its value
    return Ratio;
  }

  double Compute(AddrId Ea1, AddrId Ea2, Side Side1, uint32_t Row1, Side Side2, uint32_t Row2, MdSource Src,
                 const std::optional<double>& SqlMd1, const std::optional<double>& SqlMd2) {
    const FunctionTable& T1 = Table(Side1);
    const FunctionTable& T2 = Table(Side2);
    const int S1 = SideIndex(Side1);
    const int S2 = SideIndex(Side2);
    const uint32_t M = g_Mutations;

    // D:1672-1673 md1 = float(md1); md2 = float(md2)
    bool UsePython = Src == MdSource::Python;
    if ((M & kMutSwapMdSource) != 0) {
      UsePython = !UsePython;
    }
    double Md1 = 0.0;
    double Md2 = 0.0;
    if (UsePython) {
      Md1 = MdPython(Side1, Row1);
      Md2 = MdPython(Side2, Row2);
    } else if (Src == MdSource::Sql) {
      Md1 = MdSqlOf(SqlMd1);
      Md2 = MdSqlOf(SqlMd2);
    } else {
      Md1 = MdSqlFromTable(Side1, Row1);
      Md2 = MdSqlFromTable(Side2, Row2);
    }
    if ((M & kMutMdAsStrings) != 0 && Src == MdSource::Python) {
      const bool SameText = PyEq(CellOf(T1.MdIndex, Row1), CellOf(T2.MdIndex, Row2));
      Md2 = SameText ? Md1 : std::nextafter(Md1, std::numeric_limits<double>::infinity());
    }

    // D:1681-1683: Python ==, so None == None is True
    const TextCell Hash1 = CellOf(T1.BytesHash, Row1);
    const TextCell Hash2 = CellOf(T2.BytesHash, Row2);
    bool SameHash = PyEq(Hash1, Hash2);
    if ((M & kMutNullBytesHashNotEqual) != 0 && Hash1.Null) {
      SameHash = false;
    }
    if (SameHash) {
      return 1.0;
    }

    // D:1685-1686 v3 = 0 (the relaxed AST block D:1687-1697 is off)
    // D:1699-1720 v1: raw pseudocode both non-None and != "", then the cleaned text
    double V1 = 0.0;
    const TextCell Pseudo1 = CellOf(T1.Pseudocode, Row1);
    const TextCell Pseudo2 = CellOf(T2.Pseudocode, Row2);
    if (!Pseudo1.Null && !Pseudo2.Null && PyNe(Pseudo1, "") && PyNe(Pseudo2, "")) {
      if (IsEmptyStr(CellOf(T1.CleanPseudo, Row1)) || IsEmptyStr(CellOf(T2.CleanPseudo, Row2))) {
        // D:1707 log("Error cleaning pseudo-code!"); v1 stays 0. A None clean_pseudo is not "" and
        // goes through quick_ratio, which returns 0 (03a Hard parts 4).
      } else {
        V1 = RoundDecimal7(QuickPrepared(CleanPseudo, S1, Row1, S2, Row2, "clean_pseudo"), M);
        // D:1711-1720: the v1 == 1.0 recheck runs only with real_quick_ratio (relaxed)
      }
    }
    // D:1721-1730 v2 (the v2 == 1 recheck is relaxed-only too)
    const double V2 = RoundDecimal7(QuickPrepared(CleanAssembly, S1, Row1, S2, Row2, "clean_assembly"), M);
    const double V3 = 0.0;  // D:1732-1737 relaxed only
    // D:1739-1745 v4
    double V4 = 0.0;
    if (Md1 == Md2 && Md1 > 0.0) {
      const double X = (((V1 + V2) + V3) + 3.0) / 5.0;  // (v1 + v2 + v3 + 3.0) / 5
      V4 = (1.0 < X) ? 1.0 : X;                         // min(x, 1.0) keeps x unless 1.0 < x
    }
    // D:1747-1753 v5: both clean_microcode non-None ("" passes and gives 0)
    double V5 = 0.0;
    const TextCell Micro1 = CellOf(T1.CleanMicrocode, Row1);
    const TextCell Micro2 = CellOf(T2.CleanMicrocode, Row2);
    if (!Micro1.Null && !Micro2.Null) {
      V5 = RoundDecimal7(QuickPrepared(CleanMicrocode, S1, Row1, S2, Row2, "clean_microcode"), M);
      if (V5 == 1.0 && (M & kMutNoV5ShortCircuit) == 0) {
        return 1.0;  // even when the MD-Indices differ
      }
    }
    // D:1755-1764: only the numeric values of the set matter
    const double Values[5] = {V1, V2, V3, V4, V5};
    double R = Values[0];
    for (const double V : Values) {
      if (V > R) {
        R = V;
      }
    }
    if (R == 1.0 && Md1 != Md2 && (M & kMutNoMdGuard) == 0) {
      R = 0.0;
      for (const double V : Values) {
        if (V != 1.0 && V > R) {
          R = V;
        }
      }
    }
    // D:1766-1770
    if (R < 1.0) {
      const double Score = DeepRatioByAddress(Ea1, Ea2);
      if (R + Score < 1.0 || (M & kMutNoClamp) != 0) {
        R += Score;
      } else {
        R = 0.99;  // the clamp can lower r (03a Hard parts 7)
      }
    }
    return R;
  }
};

RatioEngine::RatioEngine(DiffSession& S) : Impl_(std::make_unique<Impl>(S)) {}
RatioEngine::~RatioEngine() = default;

void RatioEngine::Prepare() { Impl_->PrepareAll(); }

double RatioEngine::CheckRatio(const HeuristicRow& Row, MdSource Src) {
  // check_match (D:1798-1842) builds main_d/diff_d from the SELECT_FIELDS aliases of the row: ea,
  // md1 = cast(f.md_index as real) and the text columns of Row1/Row2.
  return Impl_->CheckRatio(Row.Ea1, Row.Ea2, Row.Side1, Row.Row1, Row.Side2, Row.Row2, Src, Row.Md1, Row.Md2);
}

double RatioEngine::CompareFunctionRows(uint32_t MainRow, uint32_t DiffRow) {
  // D:2479-2538: main_d/diff_d from `select *` rows, md_index as raw TEXT (float() in check_ratio).
  const FunctionTable& Main = Impl_->Table(Side::Main);
  const FunctionTable& Diff = Impl_->Table(Side::Diff);
  if (MainRow >= Main.Count() || DiffRow >= Diff.Count()) {
    throw UnsupportedInput("compare_function_rows: row out of range");
  }
  if (Main.Address.IsBlob[MainRow] != 0 || Diff.Address.IsBlob[DiffRow] != 0) {
    throw UnsupportedInput("compare_function_rows: a BLOB address (bytes in the cache key) is not ported");
  }
  return Impl_->CheckRatio(Main.AddrIdOf[MainRow], Diff.AddrIdOf[DiffRow], Side::Main, MainRow, Side::Diff, DiffRow,
                           MdSource::Python, std::nullopt, std::nullopt);
}

void RatioEngine::ClearCache() {
  Impl_->ById.clear();
  Impl_->ByText.clear();
  Impl_->Entries.clear();
}

void RatioEngine::SeedCache(AddrId Ea1, AddrId Ea2, double R) { Impl_->Store(Ea1, Ea2, R); }

std::optional<double> RatioEngine::Cached(AddrId Ea1, AddrId Ea2) const { return Impl_->Find(Ea1, Ea2); }

std::vector<RatioEngine::CacheEntry> RatioEngine::CacheSnapshot() const { return Impl_->Entries; }

double RatioEngine::QuickRatio(std::optional<std::string_view> A, std::optional<std::string_view> B) {
  // D:150-155 check_bufs
  if (!A || !B || A->empty() || B->empty()) {
    return 0.0;
  }
  // D:163-165 SequenceMatcher(None, a.split("\n"), b.split("\n")).quick_ratio()
  std::vector<std::string_view> PiecesA;
  std::vector<std::string_view> PiecesB;
  SplitPieces(*A, false, PiecesA);
  SplitPieces(*B, false, PiecesB);
  std::unordered_map<std::string_view, int64_t> Available;  // fullbcount, then avail (difflib.py:627-647)
  for (const std::string_view Piece : PiecesB) {
    ++Available[Piece];
  }
  uint64_t Matches = 0;
  for (const std::string_view Piece : PiecesA) {
    const auto Found = Available.find(Piece);
    if (Found != Available.end() && Found->second > 0) {
      --Found->second;
      ++Matches;
    }
  }
  return (2.0 * static_cast<double>(Matches)) / static_cast<double>(PiecesA.size() + PiecesB.size());
}

double RatioEngine::Round7(double V) { return RoundDecimal7(V, 0); }

double RatioEngine::DeepRatio(uint32_t MainRow, uint32_t DiffRow) const {
  if (MainRow >= Impl_->Table(Side::Main).Count() || DiffRow >= Impl_->Table(Side::Diff).Count()) {
    throw UnsupportedInput("deep_ratio: row out of range");
  }
  return Impl_->DeepScore(MainRow, DiffRow);
}

namespace Testing {

bool SetRatioMutationForTesting(std::string_view Name) {
  static const std::pair<std::string_view, uint32_t> kNames[] = {
      {"round_half_up", kMutRoundHalfUp},
      {"no_rounding", kMutNoRounding},
      {"no_clamp", kMutNoClamp},
      {"constants_as_doubles", kMutConstantsAsDoubles},
      {"no_v5_short_circuit", kMutNoV5ShortCircuit},
      {"no_md_guard", kMutNoMdGuard},
      {"null_bytes_hash_not_equal", kMutNullBytesHashNotEqual},
      {"splitlines", kMutSplitLines},
      {"always_0008", kMutAlways008},
      {"md_as_strings", kMutMdAsStrings},
      {"swap_md_source", kMutSwapMdSource},
  };
  if (Name.empty()) {
    g_Mutations = 0;
    return true;
  }
  for (const auto& Entry : kNames) {
    if (Entry.first == Name) {
      g_Mutations = Entry.second;
      return true;
    }
  }
  return false;
}

}  // namespace Testing

}
