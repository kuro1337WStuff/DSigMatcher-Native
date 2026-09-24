// find_locally_affine_functions (D:3315-3360) and find_functions_between (D:3231-3313), the
// "Local affinity" heuristic of the convergence loop (spec 06 §10-§11, 07 §10.11.4, 08 H-1).
// D: = diaphora.py at 3.4.2-4-g621ec26, C: = diaphora_config.py.
//
// Three orderings of the same address column meet here (06 Hard parts 4): the matches are sorted by
// Python int() of their address texts (D:3345), while the gap queries compare the TEXT column with the
// bound address strings (`address > ? and address < ?`, `order by address desc`, D:3236-3240), which
// is bytewise (06 §11.1). The gap queries are Diaphora's SQL run through Path A, so the lexicographic
// semantics and the row order are SQLite's by construction.

#include <algorithm>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "../StateDetail.h"
#include "dsigmatcher/diff/Config.h"
#include "dsigmatcher/diff/Consumer.h"
#include "dsigmatcher/diff/Errors.h"
#include "dsigmatcher/diff/Pipeline.h"
#include "dsigmatcher/diff/StageSql.h"
#include "dsigmatcher/diff/Stages.h"

namespace DSig::Diff {

namespace {

constexpr std::string_view kLocalAffinity = "Local affinity";  // D:3242 heur_text

// Python int() of an address text as a comparable value: sign and the decimal digits without leading
// zeros or '_' separators. Detail::RequirePyInt (StateDetail.h) raises first where int() raises
// (None: TypeError; text int() rejects: ValueError; non-ASCII text is refused).
struct PyIntKey {
  bool Negative = false;
  std::string Digits;  // no leading zeros; "" is zero

  // Python int ordering.
  static int Compare(const PyIntKey& A, const PyIntKey& B) {
    if (A.Negative != B.Negative) {
      return A.Negative ? -1 : 1;
    }
    int Magnitude = 0;
    if (A.Digits.size() != B.Digits.size()) {
      Magnitude = A.Digits.size() < B.Digits.size() ? -1 : 1;
    } else {
      const int Cmp = A.Digits.compare(B.Digits);
      Magnitude = Cmp < 0 ? -1 : (Cmp > 0 ? 1 : 0);
    }
    return A.Negative ? -Magnitude : Magnitude;
  }
};

PyIntKey IntKeyOf(const Interners& Ids, AddrId Ea, const char* Site) {
  Detail::RequirePyInt(Ids, Ea, Site);
  const std::string_view Text = Ids.AddrText(Ea);
  PyIntKey Key;
  bool Leading = true;
  for (const char Ch : Text) {
    if (Ch == '-') {
      Key.Negative = true;
    } else if (Ch >= '0' && Ch <= '9') {
      if (Leading && Ch == '0') {
        continue;
      }
      Leading = false;
      Key.Digits.push_back(Ch);
    }
    // whitespace, '+' and '_' separators carry no value (PyIntAsciiAccepts validated the layout)
  }
  if (Key.Digits.empty()) {
    Key.Negative = false;  // -0 == 0
  }
  return Key;
}

// An item address bound as Python binds it (D:3245, D:3252): the str text; None would bind NULL.
BindValue BindAddress(const Interners& Ids, AddrId Ea) {
  if (Ea == kNoneAddr) {
    return BindValue::Null();
  }
  return BindValue::Str(Ids.AddrText(Ea));
}

// `name.startswith(prefix)` on a fetched row's name (D:3269, D:3271): None raises AttributeError; a
// BLOB name is Python bytes, and bytes.startswith(str) raises TypeError.
bool RowNameStartsWith(const FunctionTable& T, uint32_t Row, std::string_view Prefix, const char* Site) {
  if (T.Name.Null(Row)) {
    throw DiaphoraWouldRaise(Site, "AttributeError: 'NoneType' object has no attribute 'startswith'");
  }
  if (T.Name.IsBlob[Row] != 0) {
    throw DiaphoraWouldRaise(Site, "TypeError: startswith first arg must be bytes or a tuple of bytes, not str");
  }
  return T.Name.View(Row).starts_with(Prefix);
}

// row["pseudocode_lines"] as a Python int (D:3274-3275). None reaches `None + x` and raises TypeError
// at D:3276; a REAL / TEXT / BLOB cell (NotInteger) would follow Python rules the column does not keep.
int64_t PseudocodeLines(const FunctionTable& T, uint32_t Row) {
  if (T.PseudocodeLines.Null(Row)) {
    throw DiaphoraWouldRaise("D:3276", "TypeError: unsupported operand type(s) for +: 'NoneType' and 'int'");
  }
  if (T.PseudocodeLines.NotInteger[Row] != 0) {
    throw UnsupportedInput("D:3276: functions.pseudocode_lines is not INTEGER (not ported)");
  }
  return T.PseudocodeLines.Value[Row];
}

// Python `a + b != 0` on two int64 values without overflow: the true sum lies in [-2^64, 2^64 - 2],
// and it is a multiple of 2^64 only when it is 0 or -2^64 (both values INT64_MIN).
bool SumIsNonZero(int64_t A, int64_t B) {
  const uint64_t Sum = static_cast<uint64_t>(A) + static_cast<uint64_t>(B);
  if (Sum != 0) {
    return true;
  }
  return A == INT64_MIN && B == INT64_MIN;
}

// int(row["nodes"]) (D:3303-3304, and D:3020-3021 inside call_on_match_hook): int(None) raises TypeError.
int64_t IntOfNodes(const FunctionTable& T, uint32_t Row, const char* Site) {
  if (T.Nodes.Null(Row)) {
    throw DiaphoraWouldRaise(Site, "TypeError: int() argument must be a string, a bytes-like object or a real "
                                   "number, not 'NoneType'");
  }
  if (T.Nodes.NotInteger[Row] != 0) {
    throw UnsupportedInput(std::string(Site) + ": functions.nodes is not INTEGER (int() semantics not ported)");
  }
  return T.Nodes.Value[Row];
}

// The gap rows (D:3245-3246, D:3252-3253): cur.execute(sql, range) with the two address strings, then
// list(cur.fetchall()); fetchall converts every row, so a row with invalid UTF-8 raises there
// (FetchFunctionRows), and nothing catches it (try/finally only, D:3241/D:3312).
std::vector<uint32_t> GapRows(DiffSession& S, Side Which, AddrId Low, AddrId High) {
  const BindValue Binds[2] = {BindAddress(S.Ids(), Low), BindAddress(S.Ids(), High)};
  const std::vector<FunctionRowRef> Rows =
      FetchFunctionRows(S, Which == Side::Main ? kSqlGapMain : kSqlGapDiff, std::span<const BindValue>(Binds, 2), Which);
  std::vector<uint32_t> Out;
  Out.reserve(Rows.size());
  for (const FunctionRowRef& Ref : Rows) {
    if (Ref.Row == kNoRow) {
      // `address > ? and address < ?` with TEXT binds selects only TEXT addresses (NULL compares as
      // unknown, BLOB sorts after every TEXT), so every row maps; kept as a guard.
      throw UnsupportedInput("find_functions_between: a gap row's address is not a TEXT address of the export");
    }
    Out.push_back(Ref.Row);
  }
  return Out;
}

// call_on_match_hook (D:3003-3031). self.hooks is None in mode N, which is the only mode that runs the
// convergence loop (in modes S and P, D:3626-3627 run find_remaining_functions instead), so the
// default path returns (True, r). Kept literal for a replay that restores hooks_loaded = true: the
// hook object is scripts/patch_diff_vulns.py, which has on_match; the dictionaries it receives carry
// the MAIN name as d2["name"] (D:3013, a Diaphora bug 06 §2.11 says to keep), and int(nodes) runs
// on both rows first (D:3020-3021). The hook's only effect is to raise (PatchDiffHookOnMatch).
double CallOnMatchHook(DiffSession& S, uint32_t MainRow, uint32_t DiffRow, double R) {
  if (!S.Flags().HooksLoaded) {
    return R;
  }
  const FunctionTable& Main = S.Main().Functions;
  const FunctionTable& Diff = S.Diff().Functions;
  HeuristicRow Row;
  Row.Side1 = Side::Main;
  Row.Side2 = Side::Diff;
  Row.Row1 = MainRow;
  Row.Row2 = DiffRow;
  Row.Ea1 = Main.AddrIdOf[MainRow];               // D:3010 main_row["address"]
  Row.Ea2 = Diff.AddrIdOf[DiffRow];               // D:3011 diff_row["address"]
  Row.Name1 = Main.NameIdOf[MainRow];             // D:3012
  Row.Name2 = Main.NameIdOf[MainRow];             // D:3013 name2 = main_row["name"] (sic)
  Row.Desc = S.Ids().Desc(kLocalAffinity);        // D:3009 desc = heur
  Row.Nodes1 = IntOfNodes(Main, MainRow, "D:3020");
  Row.Nodes2 = IntOfNodes(Diff, DiffRow, "D:3021");
  PatchDiffHookOnMatch(S, Row, R);                // D:3029 call_hook("on_match", ...) -> (True, r)
  return R;
}

// find_functions_between(range1, range2) (D:3231-3313).
void FindFunctionsBetween(DiffSession& S, AddrId Low1, AddrId High1, AddrId Low2, AddrId High2) {
  // D:3245-3250: main rows first; the diff query runs only when 0 < len(main_rows) <= 100 (C:124).
  const std::vector<uint32_t> MainRows = GapRows(S, Side::Main, Low1, High1);
  if (MainRows.empty() || MainRows.size() > static_cast<size_t>(kMaxFunctionsPerGap)) {
    return;
  }
  const std::vector<uint32_t> DiffRows = GapRows(S, Side::Diff, Low2, High2);  // D:3252-3254
  if (DiffRows.empty() || DiffRows.size() > static_cast<size_t>(kMaxFunctionsPerGap)) {  // D:3257
    return;
  }
  const FunctionTable& Main = S.Main().Functions;
  const FunctionTable& Diff = S.Diff().Functions;
  // D:3258-3261: per-gap maps keyed by name (the sets and score dicts are always written together).
  std::unordered_map<NameId, double> MainScore;
  std::unordered_map<NameId, double> DiffScore;
  const DescId Desc = S.Ids().Desc(kLocalAffinity);
  for (const uint32_t A : MainRows) {    // D:3265 (address DESC, bytewise)
    for (const uint32_t B : DiffRows) {  // D:3266
      // D:3269: `name1.startswith("nullsub_") or name2.startswith("nullsub_")`, short-circuit.
      if (RowNameStartsWith(Main, A, "nullsub_", "D:3269") || RowNameStartsWith(Diff, B, "nullsub_", "D:3269")) {
        continue;
      }
      // D:3271: `not name1.startswith("sub_") and not name2.startswith("sub_")`: at least one sub_.
      if (!RowNameStartsWith(Main, A, "sub_", "D:3271") && !RowNameStartsWith(Diff, B, "sub_", "D:3271")) {
        continue;
      }
      // D:3274-3278
      const int64_t Lines1 = PseudocodeLines(Main, A);
      const int64_t Lines2 = PseudocodeLines(Diff, B);
      if (SumIsNonZero(Lines1, Lines2)) {
        if (Lines1 == 3 || Lines2 == 3) {
          continue;
        }
      }
      // D:3280 compare_function_rows (D:2479-2538): md_index through Python float(), cached by
      // f"{address}-{address}" (03a §8). No has_best_match gate here (06 §11.2 notes).
      double R = S.Ratio().CompareFunctionRows(A, B);
      std::optional<Chooser> Target;
      if (R == 1.0) {  // D:3281-3282
        Target = Chooser::Best;
      } else if (R >= kDefaultPartialRatio) {  // D:3283-3284 (C:137, >=)
        Target = Chooser::Partial;
      } else {
        continue;  // D:3285-3286
      }
      const NameId Name1 = Main.NameIdOf[A];
      const NameId Name2 = Diff.NameIdOf[B];
      // D:3292-3295: `name in local_*_matched and *_score[name] >= r`.
      if (const auto Found = MainScore.find(Name1); Found != MainScore.end() && Found->second >= R) {
        continue;
      }
      if (const auto Found = DiffScore.find(Name2); Found != DiffScore.end() && Found->second >= R) {
        continue;
      }
      R = CallOnMatchHook(S, A, B, R);  // D:3297 (should_add is always True)
      // D:3299-3306: the item from the fetched rows (address TEXT as stored, int(nodes)).
      const int64_t Nodes1 = IntOfNodes(Main, A, "D:3303");
      const int64_t Nodes2 = IntOfNodes(Diff, B, "D:3304");
      const Item It{Main.AddrIdOf[A], Name1, Diff.AddrIdOf[B], Name2, Desc, R, Nodes1, Nodes2};
      S.State().AddMatch(Name1, Name2, R, It, Target);  // D:3306 (may reject silently: has_better_match)
      // D:3308-3311: recorded whether or not add_match kept it (06 §11.2).
      MainScore[Name1] = R;
      DiffScore[Name2] = R;
    }
  }
}

}

void StageFindLocallyAffineFunctions(DiffSession& S, int /*Iteration*/) {
  // D:3335-3338: call_hook("on_special_heuristic", True, ...) returns the default True (no hooks in
  // mode N; scripts/patch_diff_vulns.py defines no on_special_heuristic).
  S.Cleanup(CleanupSite::L3340);  // D:3340
  // D:3341 log_refresh only.
  // D:3343-3344: the current lists (left in sorted order by the cleanup), best then partial.
  std::vector<Item> Matches = S.State().Items(Chooser::Best);
  {
    const std::vector<Item>& Partial = S.State().Items(Chooser::Partial);
    Matches.insert(Matches.end(), Partial.begin(), Partial.end());
  }
  // D:3345 sorted(..., key=lambda x: [int(x[0]), int(x[2])]): list.sort computes every key first, in
  // list order (int(ea1) then int(ea2) per item), so the first failing int() raises before any
  // comparison; then a stable sort on the two-int lists.
  const Interners& Ids = S.Ids();
  std::vector<std::pair<PyIntKey, PyIntKey>> Keys;
  Keys.reserve(Matches.size());
  for (const Item& It : Matches) {
    PyIntKey Ea1 = IntKeyOf(Ids, It.Ea1, "D:3345 int(x[0])");
    PyIntKey Ea2 = IntKeyOf(Ids, It.Ea2, "D:3345 int(x[2])");
    Keys.emplace_back(std::move(Ea1), std::move(Ea2));
  }
  std::vector<size_t> Order(Matches.size());
  for (size_t Index = 0; Index < Order.size(); ++Index) {
    Order[Index] = Index;
  }
  std::stable_sort(Order.begin(), Order.end(), [&Keys](size_t A, size_t B) {
    const int First = PyIntKey::Compare(Keys[A].first, Keys[B].first);
    if (First != 0) {
      return First < 0;
    }
    return PyIntKey::Compare(Keys[A].second, Keys[B].second) < 0;
  });
  // D:3347-3360: consecutive pairs; `i == size` is never true inside enumerate.
  for (size_t Index = 1; Index < Order.size(); ++Index) {
    const Item& Prev = Matches[Order[Index - 1]];
    const Item& Curr = Matches[Order[Index]];
    // D:3358-3360: area1 = [prev_ea1, curr_ea1], area2 = [prev_ea2, curr_ea2] (the TEXT strings).
    FindFunctionsBetween(S, Prev.Ea1, Curr.Ea1, Prev.Ea2, Curr.Ea2);
  }
}

}
