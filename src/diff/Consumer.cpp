// Row consumers (lane L1): check_match (D:1786-1872), add_matches_internal (D:1874-1948) and the
// add_matches_from_* wrappers (D:1950-2083). Spec: 02 §5.3, §6, §10-§13; 05 §2.2-§2.3; 06 §2.7;
// 07 §10.5.1-§10.5.2. D: = diaphora.py at 3.4.2-4-g621ec26, C: = diaphora_config.py.
//
// Row trace events (--trace-rows) follow tools/parity/README.md "row event" and the oracle's
// check_match wrapper (tools/parity/oracle_trace.py WrapRows): CheckMatch writes exactly one row
// event per call, after check_match's own work and before the caller's add_match:
//   * rejected rows: nullsub / has_best (ratio null) or has_better (the ratio check_ratio computed);
//   * a raise inside check_match (check_ratio, a None name, the hook): raised (ratio null);
//   * accepted rows: the decision the CALLER's routing gives the returned ratio. The oracle takes it
//     from the caller's name; here the callers in this file push a routing frame, and every other
//     caller (find_same_name D:2183, search_small_differences D:2129 -- the only other check_match
//     call sites, 02 §6) gets their shared rule: accepted_best when r == 1.0, else accepted_partial.
// Callers of CheckMatch must therefore not write row events themselves.

#include "dsigmatcher/diff/Consumer.h"

#include <string>
#include <vector>

#include "StateDetail.h"
#include "dsigmatcher/diff/Config.h"
#include "dsigmatcher/diff/Errors.h"
#include "dsigmatcher/diff/Pipeline.h"
#include "dsigmatcher/diff/Stages.h"
#include "dsigmatcher/diff/Trace.h"

namespace DSig::Diff {

namespace {

// The routing of the innermost consumer loop, for the accepted-row decision of the row trace event.
struct RoutingFrame {
  enum class Kind : uint8_t { Internal, FromQuery };
  Kind Which = Kind::Internal;
  std::optional<Chooser> Partial;  // add_matches_internal's `partial` (None -> nullopt)
  std::optional<double> Val;       // `val` before its default (D:1922-1923)
  bool UnreliableGiven = false;    // `unreliable is not None`
};

struct RoutingStack {
  std::vector<RoutingFrame> Frames;
};

class RoutingScope {
public:
  RoutingScope(DiffSession& S, RoutingFrame Frame) : Stack_(S.Ext<RoutingStack>()) { Stack_.Frames.push_back(Frame); }
  ~RoutingScope() { Stack_.Frames.pop_back(); }
  RoutingScope(const RoutingScope&) = delete;
  RoutingScope& operator=(const RoutingScope&) = delete;

private:
  RoutingStack& Stack_;
};

// oracle_trace.py WrapRows: the decision for an accepted row repeats the caller's routing.
RowDecision AcceptedDecision(DiffSession& S, double R) {
  const RoutingStack& Stack = S.Ext<RoutingStack>();
  if (Stack.Frames.empty()) {
    // find_same_name (D:2196-2206: float(ratio) == 1.0 -> best) and search_small_differences
    // (D:2143-2146: r == 1.0 -> best): the same rule for a double.
    return R == 1.0 ? RowDecision::AcceptedBest : RowDecision::AcceptedPartial;
  }
  const RoutingFrame& Frame = Stack.Frames.back();
  if (Frame.Which == RoutingFrame::Kind::FromQuery) {
    return RowDecision::AcceptedBest;  // D:2074-2075: always the category, with ratio 1
  }
  const double Val = Frame.Val.value_or(kDefaultPartialRatio);  // D:1922-1923
  if (R == 1.0) {                                                // D:1925
    return RowDecision::AcceptedBest;
  }
  if (R >= Val && Frame.Partial) {                               // D:1928
    return RowDecision::AcceptedPartial;
  }
  if (R < kDefaultPartialRatio && R > Val && Frame.UnreliableGiven) {  // D:1940
    return RowDecision::AcceptedUnreliable;
  }
  return RowDecision::BelowMin;
}

bool NameStartsWith(DiffSession& S, NameId Name, std::string_view Prefix, const char* Site) {
  if (Name == kNoneName) {
    throw DiaphoraWouldRaise(Site, "AttributeError: 'NoneType' object has no attribute 'startswith'");
  }
  return S.Ids().NameText(Name).starts_with(Prefix);
}

std::optional<double> CheckMatchBody(DiffSession& S, const HeuristicRow& Row) {
  // D:1792-1842 read the row into main_d / diff_d; reading cannot raise (the NULL values reach
  // check_ratio, which raises where Python does: 03a §6.3).
  // D:1844 `if ratio != 1.0:` is always true: every call site passes ratio=None (02 §6).
  // D:1845-1848 nullsub filter, `name1.startswith(nullsub) or name2.startswith(nullsub)`: case-sensitive
  // prefix; name2 is evaluated only when name1 does not match; a None name raises AttributeError.
  if (NameStartsWith(S, Row.Name1, "nullsub_", "D:1846") || NameStartsWith(S, Row.Name2, "nullsub_", "D:1846")) {
    TraceRow(S, Row, RowDecision::Nullsub, std::nullopt);
    return std::nullopt;  // D:1848 return False, 0.0
  }
  // D:1851-1853: a 1.0 match for either name (checked before the ratio is computed).
  if (S.State().HasBestMatch(Row.Name1, Row.Name2)) {
    TraceRow(S, Row, RowDecision::HasBest, std::nullopt);
    return std::nullopt;
  }
  // D:1855-1857: ratio is None -> r = check_ratio(main_d, diff_d), md from `cast(md_index as real)`
  // (H:57), cached by f"{ea1}-{ea2}" inside the ratio engine (D:1651-1655).
  const double R = S.Ratio().CheckRatio(Row, MdSource::Sql);
  // D:1865-1867
  if (S.State().HasBetterMatch(Row.Name1, Row.Name2, R)) {
    TraceRow(S, Row, RowDecision::HasBetter, R);
    return std::nullopt;
  }
  // D:1869-1871: should_add, r = call_hook("on_match", [True, r], [main_d, diff_d, desc, r]).
  // call_hook (D:1450-1459) returns the default unless hooks are loaded; the only hook of the
  // parity configuration is scripts/patch_diff_vulns.py in patch-diff mode, whose on_match returns
  // (True, ratio) on every path, so only its raising conditions are reproduced (plan §4 L5).
  if (S.Flags().HooksLoaded) {
    PatchDiffHookOnMatch(S, Row, R);
  }
  TraceRow(S, Row, AcceptedDecision(S, R), R);
  return R;  // D:1872
}

// ea = str(row["ea"]) (D:1910, D:2067): the address TEXT; str(None) is the text "None".
AddrId StrOfEa(DiffSession& S, AddrId Ea) { return Ea == kNoneAddr ? S.Ids().Addr("None") : Ea; }

// int(row["nodes1"]) (D:1915-1916, D:2071-2072): int(None) raises TypeError.
int64_t IntOfNodes(const std::optional<int64_t>& Nodes, const char* Site) {
  if (!Nodes) {
    throw DiaphoraWouldRaise(Site, "TypeError: int() argument must be a string, a bytes-like object or a real "
                                   "number, not 'NoneType'");
  }
  return *Nodes;
}

// add_matches_internal (D:1882-1948) with its `unreliable` argument, which the public signature
// (Consumer.h) leaves out because the branch it enables is unreachable whenever `partial` is given
// (02 §10): it only changes the row trace decision (accepted_unreliable) and the dead branch.
void AddMatchesInternalImpl(DiffSession& S, RowSource& Rows, Chooser Best, std::optional<Chooser> Partial,
                            std::optional<double> Val, bool UnreliableGiven) {
  RoutingScope Routing(S, RoutingFrame{RoutingFrame::Kind::Internal, Partial, Val, UnreliableGiven});
  const int64_t MaxRows = S.Config().MaxProcessedRows;  // D:454-456 sql_max_processed_rows (C:90)
  int64_t I = 0;                                        // D:1889
  // D:1893 `while self.continue_getting_sql_rows(i)` = (max != 0 and i < max) (D:1874-1880): the cap
  // counts every fetched row, rejected ones included; max == 0 reads no row at all (02 §5.3).
  while (MaxRows != 0 && I < MaxRows) {
    // D:1894-1896: the 300 s wall-clock timeout is not emulated (plan §0.8, §5 R7).
    ++I;                        // D:1898
    HeuristicRow Row;
    if (!Rows.Next(Row)) {      // D:1901-1903 fetchone() is None -> break
      break;
    }
    const std::optional<double> R = CheckMatch(S, Row);  // D:1906
    if (!R) {                                            // D:1907-1908
      continue;
    }
    const double Ratio = *R;
    const AddrId Ea = StrOfEa(S, Row.Ea1);                     // D:1910 ea = str(row["ea"])
    const int64_t Nodes1 = IntOfNodes(Row.Nodes1, "D:1915");   // D:1915
    const int64_t Nodes2 = IntOfNodes(Row.Nodes2, "D:1916");   // D:1916
    const double V = Val.value_or(kDefaultPartialRatio);       // D:1922-1923 (C:137)
    const Item It{Ea, Row.Name1, Row.Ea2, Row.Name2, Row.Desc, Ratio, Nodes1, Nodes2};  // D:1927 / D:1930
    std::optional<Chooser> Target;
    if (Ratio == 1.0) {                 // D:1925-1927
      Target = Best;
    } else if (Ratio >= V && Partial) { // D:1928-1930
      Target = *Partial;
    }
    if (Target) {
      // D:1935 matches.append([0, "0x%x" % int(ea), ...]) runs int() on the address text first.
      Detail::RequirePyInt(S.Ids(), Ea, "D:1935");
      S.State().AddMatch(Row.Name1, Row.Name2, Ratio, It, Target);  // D:1936
    } else if (Ratio < kDefaultPartialRatio && Ratio > V && UnreliableGiven) {
      // D:1940-1946: the literal "unreliable" chooser (not the argument's value). Unreachable when
      // `partial` is given (it would need r < val and r > val); kept literally (02 §10).
      Detail::RequirePyInt(S.Ids(), Ea, "D:1943");
      S.State().AddMatch(Row.Name1, Row.Name2, Ratio, It, Chooser::Unreliable);  // D:1946
    }
    // otherwise the row is dropped
  }
  // D:1948 `return matches` is only returned by add_matches_from_cursor_ratio_max and ignored by
  // every caller (02 §10), so nothing is returned here.
}

}

std::optional<double> CheckMatch(DiffSession& S, const HeuristicRow& Row) {
  try {
    return CheckMatchBody(S, Row);
  } catch (const DiaphoraWouldRaise&) {
    // oracle_trace.py WrapRows: a BaseException out of check_match -> a "raised" row event.
    TraceRow(S, Row, RowDecision::Raised, std::nullopt);
    throw;
  }
}

void AddMatchesInternal(DiffSession& S, RowSource& Rows, Chooser Best, std::optional<Chooser> Partial,
                        std::optional<double> Val) {
  // Direct callers (find_related_constants D:3391, find_related_compilation_unit D:3458,
  // search_remaining_functions D:2696, stripped mode D:2580 through the wrapper) pass unreliable=None.
  AddMatchesInternalImpl(S, Rows, Best, Partial, Val, false);
}

void AddMatchesFromQuery(DiffSession& S, RowSource& Rows, Chooser Category) {
  // D:2039-2083 (HEUR_TYPE_NO_FPS): no row cap, a forced 1.0, every exception swallowed.
  if (S.State().AllFunctionsMatched()) {  // D:2045-2046
    return;
  }
  RoutingScope Routing(S, RoutingFrame{RoutingFrame::Kind::FromQuery, std::nullopt, std::nullopt, false});
  try {
    // D:2051 cur.execute(sql) happens on the first Rows.Next() (Candidates.h), inside this try, as
    // in Python. D:2054 `while not cur_thread.timeout`: the timeout flag is not emulated.
    // D:2053-2057: the counter `i` only feeds the progress log line.
    while (true) {
      HeuristicRow Row;
      if (!Rows.Next(Row)) {  // D:2058-2060
        break;
      }
      const std::optional<double> R = CheckMatch(S, Row);  // D:2063
      if (!R) {                                            // D:2064-2065
        continue;
      }
      const AddrId Ea = StrOfEa(S, Row.Ea1);                    // D:2067
      const int64_t Nodes1 = IntOfNodes(Row.Nodes1, "D:2071");  // D:2071
      const int64_t Nodes2 = IntOfNodes(Row.Nodes2, "D:2072");  // D:2072
      // D:2074 item = [ea, name1, ea2, name2, desc, 1, nodes1, nodes2]: the item ratio is the int 1.
      const Item It{Ea, Row.Name1, Row.Ea2, Row.Name2, Row.Desc, 1.0, Nodes1, Nodes2};
      S.State().AddMatch(Row.Name1, Row.Name2, 1.0, It, Category);  // D:2075
      // D:2076-2079: debug message only.
    }
  } catch (const DiaphoraWouldRaise&) {
    // D:2080-2081 `except: log(f"Error: ...")`: the error ends this heuristic; the adds made so far
    // are kept (02 §12). The log line carries Python's exception text, which is not reproduced.
    // Native refusals (UnsupportedInput) are not Python exceptions and are not swallowed.
  }
}

void AddMatchesFromQueryRatio(DiffSession& S, RowSource& Rows, Chooser Best, Chooser Partial) {
  // D:1950-1975 (HEUR_TYPE_RATIO), called with [sql, best, partial] (D:1527-1529): unreliable=None.
  if (S.State().AllFunctionsMatched()) {  // D:1956-1957
    return;
  }
  // D:1961-1964: execute + add_matches_internal(val=None -> 0.5). D:1965-1966 `except SystemExit:
  // pass` only catches the timeout, which is not emulated; D:1967-1973 log and re-raise everything
  // else, so errors propagate to the caller (the worker thread dies; plan §3.11).
  AddMatchesInternalImpl(S, Rows, Best, Partial, std::nullopt, false);
}

void AddMatchesFromQueryRatioMax(DiffSession& S, RowSource& Rows, Chooser Best, Chooser Partial, double V) {
  // D:1977-2000 (HEUR_TYPE_RATIO_MAX): add_matches_internal(best, partial, val=V, unreliable="unreliable").
  if (S.State().AllFunctionsMatched()) {  // D:1981-1982
    return;
  }
  AddMatchesInternalImpl(S, Rows, Best, Partial, V, true);  // D:1986-1989; errors re-raised (D:1992-1998)
}

void AddMatchesFromQueryRatioMaxTrusted(DiffSession& S, RowSource& Rows, double V) {
  // D:2002-2026 (HEUR_TYPE_RATIO_MAX_TRUSTED): best="best", partial="partial" hard-coded,
  // unreliable="partial" (a non-None value; the branch it enables is dead, 02 §11.3).
  if (S.State().AllFunctionsMatched()) {  // D:2007-2008
    return;
  }
  AddMatchesInternalImpl(S, Rows, Chooser::Best, Chooser::Partial, V, true);  // D:2012-2015
}

}
