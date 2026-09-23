// Lane L8: find_related_matches (D:3462-3494) and find_related_constants (D:3362-3393), the
// "Same constants related matches" heuristic of the convergence loop (plan §4 L8; spec 06 §7-§8,
// 07 §10.11.2, 02 §18.2, 08 H-4, H-8). D: = diaphora.py at 3.4.2-4-g621ec26, C: = diaphora_config.py.
//
// All SQL is Diaphora's own, run through Path A: the function rows by name (get_function_row, D:2453)
// and the per-constant join (D:3375-3387). `abs(mc.constant) == 0` is therefore evaluated by SQLite
// itself (08 H-4), so only constants without a nonzero numeric prefix produce rows (06 §8.3).
//
// Documented deviation (plan §5 R3): `for constant in inter_consts` (D:3389) iterates a CPython set,
// whose order for str elements depends on PYTHONHASHSEED. The native engine iterates the intersection
// in first-appearance order of the main function's JSON list (PySetIntersection, L2). Every other
// step, including which set's key objects the intersection keeps, is exact.

#include <algorithm>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#include "RelatedDetail.h"
#include "dsigmatcher/diff/Config.h"
#include "dsigmatcher/diff/Consumer.h"
#include "dsigmatcher/diff/Errors.h"
#include "dsigmatcher/diff/Pipeline.h"
#include "dsigmatcher/diff/PyValue.h"
#include "dsigmatcher/diff/StageSql.h"
#include "dsigmatcher/diff/Stages.h"

namespace DSig::Diff {

namespace {

// get_function_row(name, db_name) (D:2445-2460): `select * from {db}.functions where name = ?`,
// cur.fetchone(). The whole body is in `try: ... except: log(...)`, so any Python exception there (a
// fetch-time UTF-8 decode error of the row, 01 §13) is swallowed and the row stays None. Python binds
// None as NULL, which matches no row. Returns kNoRow for None.
uint32_t GetFunctionRow(DiffSession& S, Side Which, NameId Name) {
  const BindValue Bind = Name == kNoneName ? BindValue::Null() : BindValue::Str(S.Ids().NameText(Name));
  const std::string_view Sql = Which == Side::Main ? kSqlFunctionRowMain : kSqlFunctionRowDiff;
  std::vector<FunctionRowRef> Rows;
  try {
    Rows = FetchFunctionRows(S, Sql, std::span<const BindValue>(&Bind, 1), Which, 1);
  } catch (const DiaphoraWouldRaise&) {
    return kNoRow;  // D:2456-2457 `except: log(f"ERROR at get_function_row: ...")`
  }
  if (Rows.empty()) {
    return kNoRow;  // fetchone() is None
  }
  if (Rows[0].Row == kNoRow) {
    // A row whose address is not TEXT (the exporter always writes str(int)): Python would go on with
    // that row; the native tables cannot represent it.
    throw UnsupportedInput("get_function_row: the fetched row's address is not a TEXT address of the export");
  }
  return Rows[0].Row;
}

// `row["constants_count"] > 0` (D:3493): None > 0 raises TypeError (06 Hard parts 6). A REAL, TEXT or
// BLOB cell (NotInteger) would compare by Python rules the native column does not keep: refused.
bool ConstantsCountPositive(const FunctionTable& T, uint32_t Row, const char* Site) {
  if (T.ConstantsCount.Null(Row)) {
    throw DiaphoraWouldRaise(Site, "TypeError: '>' not supported between instances of 'NoneType' and 'int'");
  }
  if (T.ConstantsCount.NotInteger[Row] != 0) {
    throw UnsupportedInput(std::string(Site) + ": functions.constants_count is not INTEGER (not ported)");
  }
  return T.ConstantsCount.Value[Row] > 0;
}

// set(json.loads(row["constants"])) (D:3370-3371): json.loads(None) raises TypeError; invalid JSON, a
// non-iterable value or an unhashable element raise inside PyJsonLoadsList / PySetFromList (L2). A
// BLOB cell would go through json.loads(bytes) with encoding detection, which is not ported.
PySet ConstantsSet(const FunctionTable& T, uint32_t Row, const char* Site) {
  const TextColumn& Column = T.Constants;
  if (Column.Null(Row)) {
    throw DiaphoraWouldRaise(Site, "TypeError: the JSON object must be str, bytes or bytearray, not NoneType");
  }
  if (Column.IsBlob[Row] != 0) {
    throw UnsupportedInput(std::string(Site) + ": functions.constants is a BLOB (json.loads(bytes) not ported)");
  }
  return PySetFromList(PyJsonLoadsList(Column.View(Row)));
}

// Python's sqlite3 binds a str by encoding it to UTF-8; a lone surrogate (which json.loads produces
// from a "\udXXX" escape; PyValue keeps it as its 3-byte generalized UTF-8 form ED A0..BF xx) raises
// UnicodeEncodeError "surrogates not allowed" at cur.execute (D:3390). Verified on the oracle's
// CPython 3.13.12: sqlite3.connect(':memory:').execute('select ?', ('\ud800',)) raises it.
void RequireBindableStr(std::string_view Text, const char* Site) {
  for (size_t Index = 0; Index + 1 < Text.size(); ++Index) {
    const auto Lead = static_cast<unsigned char>(Text[Index]);
    const auto Next = static_cast<unsigned char>(Text[Index + 1]);
    if (Lead == 0xED && Next >= 0xA0 && Next <= 0xBF) {
      throw DiaphoraWouldRaise(Site, "UnicodeEncodeError: 'utf-8' codec can't encode a surrogate: surrogates not allowed");
    }
  }
}

}

void FindRelatedConstants(DiffSession& S, uint32_t MainRow, uint32_t DiffRow) {
  // D:3367 heur = "Same constants related matches" (the SQL literal's description, H:52).
  const FunctionTable& Main = S.Main().Functions;
  const FunctionTable& Diff = S.Diff().Functions;
  // D:3370-3371, in this order: json.loads + set() of main, then of diff.
  const PySet MainConsts = ConstantsSet(Main, MainRow, "D:3370 set(json.loads(main constants))");
  const PySet DiffConsts = ConstantsSet(Diff, DiffRow, "D:3371 set(json.loads(diff constants))");
  // D:3373 main_consts.intersection(diff_consts): the key objects of the iterated (smaller) set, the
  // order is the documented deviation (plan §5 R3).
  const std::vector<PyValue> InterConsts = PySetIntersection(MainConsts, DiffConsts);
  if (InterConsts.empty()) {  // D:3374
    return;
  }
  // D:3390 str(constant) of every element (str() of a hashable JSON value cannot raise, so computing
  // them before the loop changes nothing).
  std::vector<std::string> Texts;
  Texts.reserve(InterConsts.size());
  for (const PyValue& Constant : InterConsts) {
    Texts.push_back(PyStr(Constant));
  }
  if (Texts.size() >= 2) {
    // RelatedDetail.h: an installed CPython order for one run replaces the documented order.
    const Detail::RelatedConstantOrder& Order = S.Ext<Detail::RelatedConstantOrder>();
    if (Order.Reorder) {
      std::vector<std::string> Reordered = Order.Reorder(Main.Name.View(MainRow), Diff.Name.View(DiffRow), Texts);
      std::vector<std::string> A = Texts;
      std::vector<std::string> B = Reordered;
      std::sort(A.begin(), A.end());
      std::sort(B.begin(), B.end());
      if (A != B) {
        throw UnsupportedInput("RelatedConstantOrder: the installed order is not a permutation of the intersection");
      }
      Texts = std::move(Reordered);
    }
  }
  const std::string Sql(kSqlRelatedConstants);  // D:3375-3388
  for (const std::string& Text : Texts) {        // D:3389
    // D:3390 cur.execute(sql, (str(constant),)): bound as TEXT.
    RequireBindableStr(Text, "D:3390 cur.execute(str(constant))");
    SqlRowSource Rows(S, Sql, {BindValue::Str(Text)});
    // D:3391 add_matches_internal(cur, best="best", partial="partial"): val None -> 0.5, unreliable
    // None, the 1,000,000-row cap per constant.
    AddMatchesInternal(S, Rows, Chooser::Best, Chooser::Partial);
  }
}

void StageFindRelatedMatches(DiffSession& S, int /*Iteration*/) {
  // D:3466-3469: call_hook("on_special_heuristic", True, ...) returns the default True (no hooks in
  // mode N; scripts/patch_diff_vulns.py defines no on_special_heuristic).
  S.Cleanup(CleanupSite::L3471);  // D:3471
  // D:3473 log_refresh only.
  std::unordered_set<std::string> Dones;  // D:3474: local, shared by both categories
  const Interners& Ids = S.Ids();
  for (const Chooser Category : {Chooser::Best, Chooser::Partial}) {  // D:3476
    const std::vector<Item> Sorted = S.State().SortedResults(Category);  // D:3477 (a snapshot)
    for (const Item& Match : Sorted) {                                   // D:3478
      // D:3479 f"{match[1]}-{match[3]}": plain concatenation, None renders as "None".
      std::string Key(Ids.NameKeyText(Match.Name1));
      Key += '-';
      Key += Ids.NameKeyText(Match.Name2);
      if (!Dones.insert(std::move(Key)).second) {  // D:3480-3482
        continue;
      }
      // D:3484-3486: `ratio < RELATED_MATCHES_MIN_RATIO` (C:194, 0.8) ends THIS category's loop only.
      if (Match.Ratio < kRelatedMatchesMinRatio) {
        break;
      }
      // D:3488 itemize_for_chooser -> CChooser.Item(...) (D:237-245): int(nodes1), int(nodes2) of the
      // item's int node counts cannot raise. D:3489 get_row_for_items (D:2993-3001): main row by
      // item.vfname (match[1]), then diff row by item.vfname2 (match[3]); both lookups always run.
      const uint32_t MainRow = GetFunctionRow(S, Side::Main, Match.Name1);
      const uint32_t DiffRow = GetFunctionRow(S, Side::Diff, Match.Name2);
      if (MainRow == kNoRow || DiffRow == kNoRow) {  // D:3490-3491
        continue;
      }
      // D:3493: short-circuit `and`, so the diff count is read only when the main one is positive.
      if (ConstantsCountPositive(S.Main().Functions, MainRow, "D:3493 main constants_count > 0") &&
          ConstantsCountPositive(S.Diff().Functions, DiffRow, "D:3493 diff constants_count > 0")) {
        FindRelatedConstants(S, MainRow, DiffRow);  // D:3494
      }
    }
  }
}

}
