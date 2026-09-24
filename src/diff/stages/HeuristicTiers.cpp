// Lane L6: the SQL heuristic tiers. run_heuristics_for_category (D:1461-1552) with threads_apply
// (jkutils/threads.py:27-71), the per-heuristic worker (the add_matches_from_* wrappers, D:1950-2083,
// ported by L1 in Consumer.cpp) and find_partial_matches (D:2212-2221). Spec: 01 §5.10-§5.12;
// 02 §4-§5, §10-§13; 04a §1-§5; 04b §3-§5; 07 §10.3-§10.4, §10.14. D: = diaphora.py, H: =
// diaphora_heuristics.py, C: = diaphora_config.py (Diaphora 3.4.2-4-g621ec26).
//
// Also the read-only "data touched" descriptor of a heuristic's SQL (TiersDetail.h), for a
// post-parity fusion pass; nothing in the diff consults it.

#include <algorithm>
#include <cctype>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "TiersDetail.h"
#include "dsigmatcher/diff/Consumer.h"
#include "dsigmatcher/diff/Errors.h"
#include "dsigmatcher/diff/Pipeline.h"
#include "dsigmatcher/diff/Stages.h"
#include "dsigmatcher/diff/Trace.h"

namespace DSig::Diff {

namespace {

// Per-session record of truncated heuristics (TiersDetail.h HeuristicTruncations).
struct TruncationLog {
  std::vector<Tiers::HeuristicTruncation> Entries;
};

// The (best, partial) chooser pair of run_heuristics_for_category (D:1510-1515):
// `arg_category.lower() == "unreliable"` demotes both by one chooser. A heuristic only runs in the
// category it belongs to (D:1486-1488), so its own category stands for arg_category.
std::pair<Chooser, Chooser> ChoosersFor(HeurCategory Category) {
  if (Category == HeurCategory::Unreliable) {
    return {Chooser::Partial, Chooser::Unreliable};  // D:1510-1512
  }
  return {Chooser::Best, Chooser::Partial};  // D:1513-1515
}

}  // namespace

namespace Tiers {

std::vector<int> RunnableHeuristics(DiffSession& S, HeurCategory Category) {
  // D:1471-1477: the postfix is computed here (applied per heuristic below, D:1518); the
  // get_queries_postfix / get_heuristics hooks return their default unless hooks are loaded, and the
  // only hook of the parity configuration (scripts/patch_diff_vulns.py, patch-diff mode) returns its
  // arguments unchanged (patch_diff_vulns.py:79-86), so the list is HEURISTICS itself.
  std::vector<int> Runnable;
  for (const HeuristicSpec& Spec : Heuristics()) {  // D:1480
    // D:1481-1484: evaluated for every entry while the list is built; nothing runs until
    // threads_apply, so it either fires at the first entry (the category runs nothing) or never.
    if (S.State().AllFunctionsMatched()) {
      S.Log().Info("All functions matched in at least one database, finishing.");  // D:1483
      break;
    }
    if (Spec.Category != Category) {  // D:1486-1488 (exact, case-sensitive category text)
      continue;
    }
    // D:1493-1495: heur["min"] is read only for RATIO_MAX / RATIO_MAX_TRUSTED; a missing key would
    // raise KeyError on the main thread (every such entry of HEURISTICS has one, H:89-1177).
    if ((Spec.RatioType == HeurType::RatioMax || Spec.RatioType == HeurType::RatioMaxTrusted) && !Spec.HasMin) {
      throw DiaphoraWouldRaise("D:1495 KeyError", "'min' missing in heuristic " + std::to_string(Spec.Id));
    }
    // D:1497-1508: flags are list membership (H:44-48), tested in this order. log_refresh lines only.
    if (Spec.FlagUnreliable && !S.Config().Unreliable) {  // D:1498-1500
      continue;
    }
    if (Spec.FlagSlow && !S.Config().SlowHeuristics) {  // D:1502-1504
      continue;
    }
    if (Spec.FlagSameCpu && !S.Flags().IsSameProcessor) {  // D:1506-1508
      continue;
    }
    // D:1520-1522: on_launch_heuristic returns the SQL unchanged (patch_diff_vulns.py:82-83), never
    // None. D:1524-1538: every registry entry has one of the four ratio types (the else branch that
    // raises "Invalid heuristic ratio calculation value!" is unreachable).
    Runnable.push_back(Spec.Id);  // D:1540-1541
  }
  return Runnable;
}

const std::vector<HeuristicTruncation>& HeuristicTruncations(DiffSession& S) { return S.Ext<TruncationLog>().Entries; }

}  // namespace Tiers

void StageRunHeuristicsForCategory(DiffSession& S, HeurCategory Category) {
  // D:1465-1469 total_cpus = get_threads_count() = max(cpu_count, 1) = 1 outside IDA (D:489-491,
  // D:1444-1448); `mode` only feeds log lines.
  const std::vector<int> Runnable = Tiers::RunnableHeuristics(S, Category);  // D:1479-1541
  // D:1543-1549 threads_apply(threads=1, ...): `item = targets.pop()` takes the LAST entry
  // (jkutils/threads.py:40), and a new thread starts only after the previous one was reaped
  // (`len(threads_list) < threads`, threads.py:39, 55-59), so the heuristics run strictly one at a
  // time, in reverse list order, each seeing the state the previous one left (02 §4.3).
  for (auto It = Runnable.rbegin(); It != Runnable.rend(); ++It) {
    const int Id = *It;
    // oracle_trace.py WrapHeuristic: the add_matches_from_* wrapper of the worker thread emits
    // before:/after:heuristic:<id> (the latter in a `finally`, so also after a truncation) and makes
    // "heuristic:<id>" the trace ctx of the thread.
    const std::string Label = "heuristic:" + std::to_string(Id);
    S.Point("before:" + Label);
    {
      ContextScope Scope(S, Label);
      StageRunSingleHeuristic(S, Id);
    }
    S.Point("after:" + Label);
  }
  S.Cleanup(CleanupSite::L1551);  // D:1551 self.cleanup_matches()
  LogShowSummary(S);              // D:1552 self.show_summary() (may raise ZeroDivisionError, D:1631)
  // oracle_trace.py WrapStage("run_heuristics_for_category", After=True): the point follows the
  // method's return, after the cleanup and the summary.
  S.Point("after:run_heuristics_for_category:" + std::string(CategoryName(Category)));
}

void StageRunSingleHeuristic(DiffSession& S, int Id) {
  if (Id < 0 || static_cast<size_t>(Id) >= Heuristics().size()) {
    throw UnsupportedInput("heuristic id " + std::to_string(Id) + " is not an index of HEURISTICS (0.." +
                           std::to_string(Heuristics().size() - 1) + ")");
  }
  const HeuristicSpec& Spec = Heuristic(Id);
  const auto [Best, Partial] = ChoosersFor(Spec.Category);  // D:1510-1515
  // D:1518 sql.replace("%POSTFIX%", postfix): every occurrence (H10 has two); postfix is
  // config.SQL_DEFAULT_POSTFIX only with ignore_small_functions (D:1471-1473, C:128).
  // The worker's cur.execute(sql) runs at the source's first Next(), i.e. after the wrapper's
  // all_functions_matched() early return, inside the wrapper's try (Candidates.h SqlRowSource).
  SqlRowSource Rows(S, ApplyPostfix(Spec.Sql, S.Config().Postfix()));
  try {
    switch (Spec.RatioType) {
      case HeurType::NoFps:
        // D:1524-1526 add_matches_from_query(sql, best). It swallows every exception itself
        // (D:2080-2081, Consumer.cpp), so nothing reaches the catch below from it.
        AddMatchesFromQuery(S, Rows, Best);
        break;
      case HeurType::Ratio:
        AddMatchesFromQueryRatio(S, Rows, Best, Partial);  // D:1527-1529 [sql, best, partial]
        break;
      case HeurType::RatioMax:
        // D:1530-1532 [sql, best, partial, min_value]; min_value = heur["min"] (D:1493-1495).
        AddMatchesFromQueryRatioMax(S, Rows, Best, Partial, Spec.Min);
        break;
      case HeurType::RatioMaxTrusted:
        // D:1533-1535 [sql, min_value]: the wrapper hard-codes "best" / "partial" (D:2012-2015), so
        // even the Unreliable category's demotion does not apply to it.
        AddMatchesFromQueryRatioMaxTrusted(S, Rows, Spec.Min);
        break;
    }
  } catch (const DiaphoraWouldRaise& Error) {
    // Plan §3.11, 02 §5.5, 07 §10.3: the RATIO* wrappers log, print the SQL and re-raise inside the
    // worker thread (D:1967-1973, D:1992-1998, D:2018-2024). The exception ends that thread only
    // (threading.excepthook prints the traceback), threads_apply reaps it and starts the next
    // heuristic, and every match added before the failing row stays. So the heuristic is truncated
    // at the raising row and the category goes on. Native refusals (UnsupportedInput) and environment
    // failures (IoFailure, SqliteEnvironmentFailure: a full disk, a missing TMP directory) are not
    // Python-parity raises and propagate, so the run ends with exit 4 / 6 instead of silently losing
    // the rest of this heuristic's rows (audit F03). D:1968 log(f"Error: {str(sys.exc_info()[1])}"): Python's exception
    // text is not reproduced; the native site and detail are logged instead.
    S.Ext<TruncationLog>().Entries.push_back(Tiers::HeuristicTruncation{Id, Error.Site, Error.Detail});
    S.Log().Info("Error: " + std::string(Error.what()));
  }
}

void StageFindPartialMatches(DiffSession& S) {
  // D:2212-2221 find_partial_matches.
  StageFindPartialMatchesCategory(S);
  StageFindPartialMatchesSmallDifferences(S);
}

void StageFindPartialMatchesCategory(DiffSession& S) {
  // oracle_trace.py WrapStage makes "run_heuristics_for_category:Partial" the main-thread ctx for the
  // call (find_partial_matches itself is not wrapped), as RunPipeline does for Best.
  ContextScope Scope(S, "run_heuristics_for_category:Partial");
  StageRunHeuristicsForCategory(S, HeurCategory::Partial);  // D:2216
}

void StageFindPartialMatchesSmallDifferences(DiffSession& S) {
  if (S.Config().SlowHeuristics) {  // D:2218 (no auto-disable outside IDA, plan §1.1)
    // D:2220 log_refresh("Finding with heuristic 'Small names difference'"): progress line only.
    S.Point("before:search_small_differences");
    {
      ContextScope Scope(S, "search_small_differences");
      StageSearchSmallDifferences(S);  // D:2221
    }
    S.Point("after:search_small_differences");
  }
}

// ---------------------------------------------------------------------------------------------
// Data touched (TiersDetail.h). A small lexer and clause splitter for the SQLite subset Diaphora's
// queries use. It only describes; the queries themselves always run verbatim (Path A).

namespace Tiers {

namespace {

enum class TokKind : uint8_t { Ident, Keyword, String, Number, Op, Postfix };

struct Token {
  TokKind Kind = TokKind::Op;
  std::string Text;   // identifiers unquoted; keywords lower-cased; operators as written
  bool Quoted = false;
};

std::string Lower(std::string_view Text) {
  std::string Out(Text);
  for (char& Ch : Out) {
    Ch = static_cast<char>(std::tolower(static_cast<unsigned char>(Ch)));
  }
  return Out;
}

bool IsKeyword(const std::string& Lowered) {
  static const std::set<std::string> Keywords = {
      "select", "distinct", "all",    "from",    "where",   "group",  "by",       "having",  "order",
      "asc",    "desc",     "union",  "intersect", "except", "with",  "recursive", "as",     "and",
      "or",     "not",      "like",   "glob",    "regexp",  "match",  "is",       "null",    "in",
      "between", "exists",  "case",   "when",    "then",    "else",   "end",      "cast",    "join",
      "on",     "inner",    "left",   "right",   "full",    "outer",  "cross",    "natural", "using",
      "limit",  "offset",   "collate", "escape", "materialized", "nulls", "first", "last"};
  return Keywords.count(Lowered) != 0;
}

bool IsIdentStart(unsigned char Ch) { return std::isalpha(Ch) || Ch == '_' || Ch >= 0x80; }
bool IsIdentChar(unsigned char Ch) { return std::isalnum(Ch) || Ch == '_' || Ch == '$' || Ch >= 0x80; }

std::vector<Token> Tokenize(std::string_view Sql) {
  std::vector<Token> Out;
  size_t I = 0;
  const size_t N = Sql.size();
  while (I < N) {
    const unsigned char Ch = static_cast<unsigned char>(Sql[I]);
    if (std::isspace(Ch)) {
      ++I;
      continue;
    }
    if (Ch == '-' && I + 1 < N && Sql[I + 1] == '-') {  // -- comment
      while (I < N && Sql[I] != '\n') {
        ++I;
      }
      continue;
    }
    if (Ch == '/' && I + 1 < N && Sql[I + 1] == '*') {  // /* comment */
      const size_t End = Sql.find("*/", I + 2);
      I = End == std::string_view::npos ? N : End + 2;
      continue;
    }
    if (Ch == '\'') {  // string literal, '' escapes a quote
      std::string Text;
      ++I;
      while (I < N) {
        if (Sql[I] == '\'') {
          if (I + 1 < N && Sql[I + 1] == '\'') {
            Text += '\'';
            I += 2;
            continue;
          }
          ++I;
          break;
        }
        Text += Sql[I++];
      }
      Out.push_back(Token{TokKind::String, Text, false});
      continue;
    }
    if (Ch == '"' || Ch == '`' || Ch == '[') {  // quoted identifier
      const char Close = Ch == '[' ? ']' : static_cast<char>(Ch);
      std::string Text;
      ++I;
      while (I < N) {
        if (Sql[I] == Close) {
          if (Close != ']' && I + 1 < N && Sql[I + 1] == Close) {
            Text += Close;
            I += 2;
            continue;
          }
          ++I;
          break;
        }
        Text += Sql[I++];
      }
      Out.push_back(Token{TokKind::Ident, Text, true});
      continue;
    }
    if (std::isdigit(Ch) || (Ch == '.' && I + 1 < N && std::isdigit(static_cast<unsigned char>(Sql[I + 1])))) {
      const size_t Start = I;
      while (I < N && (std::isalnum(static_cast<unsigned char>(Sql[I])) || Sql[I] == '.' ||
                       ((Sql[I] == '+' || Sql[I] == '-') && (Sql[I - 1] == 'e' || Sql[I - 1] == 'E')))) {
        ++I;
      }
      Out.push_back(Token{TokKind::Number, std::string(Sql.substr(Start, I - Start)), false});
      continue;
    }
    if (IsIdentStart(Ch)) {
      const size_t Start = I;
      while (I < N && IsIdentChar(static_cast<unsigned char>(Sql[I]))) {
        ++I;
      }
      const std::string Text(Sql.substr(Start, I - Start));
      const std::string Lowered = Lower(Text);
      if (IsKeyword(Lowered)) {
        Out.push_back(Token{TokKind::Keyword, Lowered, false});
      } else {
        Out.push_back(Token{TokKind::Ident, Text, false});
      }
      continue;
    }
    if (Ch == '%' && Sql.substr(I, 9) == "%POSTFIX%") {
      Out.push_back(Token{TokKind::Postfix, "%POSTFIX%", false});
      I += 9;
      continue;
    }
    static const char* const TwoChar[] = {"==", "!=", "<>", "<=", ">=", "||", "<<", ">>"};
    bool Matched = false;
    for (const char* Op : TwoChar) {
      if (Sql.substr(I, 2) == Op) {
        Out.push_back(Token{TokKind::Op, Op, false});
        I += 2;
        Matched = true;
        break;
      }
    }
    if (!Matched) {
      Out.push_back(Token{TokKind::Op, std::string(1, static_cast<char>(Ch)), false});
      ++I;
    }
  }
  return Out;
}

bool IsKw(const Token& T, std::string_view Word) { return T.Kind == TokKind::Keyword && T.Text == Word; }
bool IsOp(const Token& T, std::string_view Op) { return T.Kind == TokKind::Op && T.Text == Op; }

using Range = std::pair<size_t, size_t>;  // [first, last) token indices

// The index of the ')' matching the '(' at Open (or End when unbalanced).
size_t MatchParen(const std::vector<Token>& T, size_t Open, size_t End) {
  int Depth = 0;
  for (size_t I = Open; I < End; ++I) {
    if (IsOp(T[I], "(")) {
      ++Depth;
    } else if (IsOp(T[I], ")")) {
      if (--Depth == 0) {
        return I;
      }
    }
  }
  return End;
}

// Splits [B, E) at depth-0 tokens for which Pred holds (the separators are dropped).
template <class Pred>
std::vector<Range> SplitTop(const std::vector<Token>& T, size_t B, size_t E, Pred IsSep) {
  std::vector<Range> Parts;
  int Depth = 0;
  size_t Start = B;
  for (size_t I = B; I < E; ++I) {
    if (IsOp(T[I], "(")) {
      ++Depth;
    } else if (IsOp(T[I], ")")) {
      --Depth;
    } else if (Depth == 0 && IsSep(I)) {
      Parts.emplace_back(Start, I);
      Start = I + 1;
    }
  }
  Parts.emplace_back(Start, E);
  return Parts;
}

std::string JoinText(const std::vector<Token>& T, size_t B, size_t E) {
  std::string Out;
  for (size_t I = B; I < E; ++I) {
    const bool Tight = I > B && (IsOp(T[I], ".") || IsOp(T[I - 1], ".") || IsOp(T[I], ")") || IsOp(T[I], ",") ||
                                 IsOp(T[I - 1], "("));
    if (I > B && !Tight) {
      Out += ' ';
    }
    Out += T[I].Kind == TokKind::String ? "'" + T[I].Text + "'" : T[I].Text;
  }
  return Out;
}

int SourceRank(const std::string& Source) {
  if (Source.rfind("main.", 0) == 0) {
    return 0;
  }
  if (Source.rfind("diff.", 0) == 0) {
    return 1;
  }
  if (Source.rfind("cte:", 0) == 0) {
    return 2;
  }
  return 3;
}

struct Scope {
  std::string Label;
  std::map<std::string, std::string> Aliases;  // lower-cased alias (or table name) -> Source
  std::vector<std::string> Order;              // aliases in FROM order
  std::set<std::string> ResultAliases;         // lower-cased explicit result-column aliases
};

class Analyzer {
public:
  explicit Analyzer(std::string_view Sql) : T_(Tokenize(Sql)) {}

  DataTouched Run() {
    for (const Token& Tok : T_) {
      if (Tok.Kind == TokKind::Postfix) {
        ++Out_.PostfixTokens;
      }
    }
    Statement(0, T_.size(), "select", true);
    Finish();
    return std::move(Out_);
  }

private:
  const std::vector<Token> T_;
  DataTouched Out_;
  std::set<std::string> Ctes_;  // lower-cased CTE names defined so far
  std::set<ColumnRef> Columns_;
  std::set<ColumnRef> CteColumns_;
  std::set<ColumnRef> Group_;
  std::set<ColumnRef> Order_;
  std::set<std::string> Tables_;
  std::set<std::string> Unresolved_;
  std::vector<std::vector<std::pair<ColumnRef, ColumnRef>>> ArmKeys_;  // outer query arms

  // [WITH cte, ...] compound
  void Statement(size_t B, size_t E, const std::string& Label, bool Outer) {
    size_t I = B;
    if (I < E && IsKw(T_[I], "with")) {
      ++I;
      if (I < E && IsKw(T_[I], "recursive")) {
        ++I;
      }
      while (I < E && T_[I].Kind == TokKind::Ident) {
        const std::string Name = T_[I].Text;
        ++I;
        if (I < E && IsOp(T_[I], "(")) {  // name(col, ...) as (...)
          I = MatchParen(T_, I, E) + 1;
        }
        if (I < E && IsKw(T_[I], "as")) {
          ++I;
        }
        while (I < E && (IsKw(T_[I], "not") || IsKw(T_[I], "materialized"))) {
          ++I;
        }
        if (I >= E || !IsOp(T_[I], "(")) {
          break;
        }
        const size_t Close = MatchParen(T_, I, E);
        Out_.Ctes.push_back(Name);
        Statement(I + 1, Close, "cte:" + Name, false);
        Ctes_.insert(Lower(Name));
        I = Close + 1;
        if (I < E && IsOp(T_[I], ",")) {
          ++I;
          continue;
        }
        break;
      }
    }
    // compound: arms separated by depth-0 UNION [ALL] / INTERSECT / EXCEPT
    std::vector<Range> Arms = SplitTop(T_, I, E, [&](size_t K) {
      return IsKw(T_[K], "union") || IsKw(T_[K], "intersect") || IsKw(T_[K], "except");
    });
    if (Arms.size() > 1) {
      if (Outer) {
        Out_.Union = true;
      }
    }
    for (size_t A = 0; A < Arms.size(); ++A) {
      size_t ArmB = Arms[A].first;
      if (A > 0 && ArmB < Arms[A].second && IsKw(T_[ArmB], "all")) {
        ++ArmB;
      }
      const std::string ArmLabel = A == 0 ? Label : Label + "#" + std::to_string(A + 1);
      if (Outer) {
        ArmKeys_.emplace_back();
      }
      Core(ArmB, Arms[A].second, ArmLabel, Outer ? &ArmKeys_.back() : nullptr, Outer);
    }
  }

  // SELECT ... FROM ... [WHERE] [GROUP BY] [HAVING] [ORDER BY] [LIMIT]
  void Core(size_t B, size_t E, const std::string& Label, std::vector<std::pair<ColumnRef, ColumnRef>>* Keys,
            bool Outer) {
    if (B >= E || !IsKw(T_[B], "select")) {
      return;
    }
    // clause boundaries at depth 0
    size_t From = E, Where = E, Group = E, Having = E, Order = E, Limit = E;
    int Depth = 0;
    for (size_t I = B + 1; I < E; ++I) {
      if (IsOp(T_[I], "(")) {
        ++Depth;
      } else if (IsOp(T_[I], ")")) {
        --Depth;
      } else if (Depth == 0 && T_[I].Kind == TokKind::Keyword) {
        const std::string& K = T_[I].Text;
        if (K == "from" && From == E) {
          From = I;
        } else if (K == "where" && Where == E) {
          Where = I;
        } else if (K == "group" && Group == E) {
          Group = I;
        } else if (K == "having" && Having == E) {
          Having = I;
        } else if (K == "order" && Order == E) {
          Order = I;
        } else if (K == "limit" && Limit == E) {
          Limit = I;
        }
      }
    }
    const auto NextBoundary = [&](size_t After) {
      size_t Next = E;
      for (size_t Candidate : {From, Where, Group, Having, Order, Limit}) {
        if (Candidate > After && Candidate < Next) {
          Next = Candidate;
        }
      }
      return Next;
    };
    Scope S;
    S.Label = Label;
    size_t SelB = B + 1;
    if (SelB < E && (IsKw(T_[SelB], "distinct") || IsKw(T_[SelB], "all"))) {
      if (IsKw(T_[SelB], "distinct") && Outer) {
        Out_.Distinct = true;
      }
      ++SelB;
    }
    const size_t SelE = NextBoundary(B);
    if (From < E) {
      FromList(From + 1, NextBoundary(From), S, Keys);
    }
    // result columns (and their explicit aliases)
    for (const Range& Item : SplitTop(T_, SelB, SelE, [&](size_t K) { return IsOp(T_[K], ","); })) {
      size_t ItemE = Item.second;
      if (ItemE > Item.first + 1 && T_[ItemE - 1].Kind == TokKind::Ident) {
        const Token& Prev = T_[ItemE - 2];
        const bool Alias = IsKw(Prev, "as") || (!IsOp(Prev, ".") && Prev.Kind != TokKind::Op) || IsOp(Prev, ")");
        if (Alias) {
          S.ResultAliases.insert(Lower(T_[ItemE - 1].Text));
          ItemE -= IsKw(Prev, "as") ? 2 : 1;
        }
      }
      Refs(Item.first, ItemE, S, nullptr, false);
    }
    if (Where < E) {
      Boolean(Where + 1, NextBoundary(Where), S, "where", true, Keys);
    }
    if (Group < E) {
      Out_.GroupByPresent = Out_.GroupByPresent || Outer;
      size_t GB = Group + 1;
      if (GB < E && IsKw(T_[GB], "by")) {
        ++GB;
      }
      std::vector<ColumnRef> Found;
      Refs(GB, NextBoundary(Group), S, &Found, true);
      Group_.insert(Found.begin(), Found.end());
    }
    if (Having < E) {
      Boolean(Having + 1, NextBoundary(Having), S, "having", true, nullptr);
    }
    if (Order < E) {
      Out_.OrderByPresent = Out_.OrderByPresent || Outer;
      size_t OB = Order + 1;
      if (OB < E && IsKw(T_[OB], "by")) {
        ++OB;
      }
      std::vector<ColumnRef> Found;
      Refs(OB, NextBoundary(Order), S, &Found, true);
      Order_.insert(Found.begin(), Found.end());
    }
  }

  // FROM a [AS] x, b y [JOIN c z ON ...]
  void FromList(size_t B, size_t E, Scope& S, std::vector<std::pair<ColumnRef, ColumnRef>>* Keys) {
    std::vector<Range> OnClauses;
    size_t I = B;
    while (I < E) {
      // one table-or-subquery
      std::string Source;
      std::string Alias;
      if (IsOp(T_[I], "(")) {
        const size_t Close = MatchParen(T_, I, E);
        Statement(I + 1, Close, S.Label + ":subquery", false);
        I = Close + 1;
        Source = "subquery";
      } else if (T_[I].Kind == TokKind::Ident) {
        std::string Schema;
        std::string Name = T_[I].Text;
        ++I;
        if (I + 1 < E && IsOp(T_[I], ".") && T_[I + 1].Kind == TokKind::Ident) {
          Schema = Lower(Name);
          Name = T_[I + 1].Text;
          I += 2;
        }
        if (Schema.empty() && Ctes_.count(Lower(Name)) != 0) {
          Source = "cte:" + Name;
        } else {
          Source = (Schema.empty() ? std::string("main") : Schema) + "." + Lower(Name);
          Tables_.insert(Source);
        }
        Alias = Name;
      } else {
        ++I;
        continue;
      }
      if (I < E && IsKw(T_[I], "as")) {
        ++I;
      }
      if (I < E && T_[I].Kind == TokKind::Ident) {
        Alias = T_[I].Text;
        ++I;
      }
      if (Source == "subquery") {
        Source = "subquery:" + Alias;
      }
      if (!Alias.empty()) {
        S.Aliases[Lower(Alias)] = Source;
        S.Order.push_back(Lower(Alias));
      }
      // join constraint / separator
      while (I < E && !IsOp(T_[I], ",") && !IsKw(T_[I], "join")) {
        if (IsKw(T_[I], "on")) {
          size_t OnE = I + 1;
          int Depth = 0;
          while (OnE < E) {
            if (IsOp(T_[OnE], "(")) {
              ++Depth;
            } else if (IsOp(T_[OnE], ")")) {
              --Depth;
            } else if (Depth == 0 && (IsOp(T_[OnE], ",") || IsKw(T_[OnE], "join") || IsKw(T_[OnE], "left") ||
                                      IsKw(T_[OnE], "inner") || IsKw(T_[OnE], "cross") || IsKw(T_[OnE], "natural"))) {
              break;
            }
            ++OnE;
          }
          OnClauses.emplace_back(I + 1, OnE);
          I = OnE;
          continue;
        }
        if (IsKw(T_[I], "left") || IsKw(T_[I], "inner") || IsKw(T_[I], "cross") || IsKw(T_[I], "natural") ||
            IsKw(T_[I], "outer") || IsKw(T_[I], "right") || IsKw(T_[I], "full")) {
          ++I;
          continue;
        }
        ++I;
      }
      if (I < E) {
        ++I;  // ',' or 'join'
      }
    }
    // ON clauses resolve against the whole FROM list
    for (const Range& On : OnClauses) {
      Boolean(On.first, On.second, S, "on", true, Keys);
    }
  }

  // Resolves one column reference; nullopt for a result alias.
  std::optional<ColumnRef> Resolve(const Scope& S, const std::string& Qualifier, const std::string& Column,
                                   bool AliasesFirst, std::string* AliasOut) {
    if (!Qualifier.empty()) {
      const auto It = S.Aliases.find(Lower(Qualifier));
      if (It == S.Aliases.end()) {
        Unresolved_.insert(Qualifier + "." + Column);
        return ColumnRef{"?" + Qualifier, Lower(Column)};
      }
      if (AliasOut != nullptr) {
        *AliasOut = It->first;
      }
      return ColumnRef{It->second, Lower(Column)};
    }
    if (AliasesFirst && S.ResultAliases.count(Lower(Column)) != 0) {
      return std::nullopt;  // GROUP BY / ORDER BY naming a result column
    }
    if (S.Order.size() == 1) {
      if (AliasOut != nullptr) {
        *AliasOut = S.Order.front();
      }
      return ColumnRef{S.Aliases.at(S.Order.front()), Lower(Column)};
    }
    if (S.ResultAliases.count(Lower(Column)) != 0) {
      return std::nullopt;
    }
    Unresolved_.insert(Column);
    return ColumnRef{"?", Lower(Column)};
  }

  void Record(const ColumnRef& Ref) {
    if (Ref.Source.rfind("cte:", 0) == 0 || Ref.Source.rfind("subquery:", 0) == 0) {
      CteColumns_.insert(Ref);
    } else if (!Ref.Source.empty() && Ref.Source[0] != '?') {
      Columns_.insert(Ref);
    }
  }

  // Column references in [B, E). Found (optional) gets them in order; AliasOut gets the row source of
  // each (parallel). Nested SELECTs are analysed as their own scope.
  void Refs(size_t B, size_t E, const Scope& S, std::vector<ColumnRef>* Found, bool AliasesFirst,
            std::vector<std::string>* Sources = nullptr) {
    for (size_t I = B; I < E; ++I) {
      const Token& Tok = T_[I];
      if (IsOp(Tok, "(") && I + 1 < E && (IsKw(T_[I + 1], "select") || IsKw(T_[I + 1], "with"))) {
        const size_t Close = MatchParen(T_, I, E);
        Statement(I + 1, Close, S.Label + ":subquery", false);
        I = Close;
        continue;
      }
      if (Tok.Kind != TokKind::Ident) {
        continue;
      }
      if (I > B && (IsKw(T_[I - 1], "as") || IsOp(T_[I - 1], "."))) {
        continue;  // CAST(x AS type) / alias, or the column part handled below
      }
      if (I + 1 < E && IsOp(T_[I + 1], "(")) {
        continue;  // function name
      }
      std::string Alias;
      std::optional<ColumnRef> Ref;
      if (I + 2 < E && IsOp(T_[I + 1], ".") && T_[I + 2].Kind == TokKind::Ident) {
        Ref = Resolve(S, Tok.Text, T_[I + 2].Text, AliasesFirst, &Alias);
        I += 2;
      } else {
        Ref = Resolve(S, "", Tok.Text, AliasesFirst, &Alias);
      }
      if (!Ref) {
        continue;
      }
      Record(*Ref);
      if (Found != nullptr) {
        Found->push_back(*Ref);
      }
      if (Sources != nullptr) {
        Sources->push_back(Alias);
      }
    }
  }

  // A boolean clause: split at depth-0 OR (lowest precedence), then AND (skipping BETWEEN's AND),
  // unwrap NOT and parentheses around a whole group, then analyse each atom.
  void Boolean(size_t B, size_t E, const Scope& S, const std::string& Clause, bool Conjunctive,
               std::vector<std::pair<ColumnRef, ColumnRef>>* Keys) {
    while (B < E && T_[B].Kind == TokKind::Postfix) {
      ++B;
    }
    while (E > B && T_[E - 1].Kind == TokKind::Postfix) {
      --E;
    }
    if (B >= E) {
      return;
    }
    const std::vector<Range> Ors = SplitTop(T_, B, E, [&](size_t K) { return IsKw(T_[K], "or"); });
    if (Ors.size() > 1) {
      for (const Range& Part : Ors) {
        Boolean(Part.first, Part.second, S, Clause, false, Keys);
      }
      return;
    }
    bool InBetween = false;
    const std::vector<Range> Ands = SplitTop(T_, B, E, [&](size_t K) {
      if (IsKw(T_[K], "between")) {
        InBetween = true;
        return false;
      }
      if (IsKw(T_[K], "and")) {
        if (InBetween) {
          InBetween = false;
          return false;
        }
        return true;
      }
      return false;
    });
    if (Ands.size() > 1) {
      for (const Range& Part : Ands) {
        Boolean(Part.first, Part.second, S, Clause, Conjunctive, Keys);
      }
      return;
    }
    if (IsKw(T_[B], "not") && !(B + 1 < E && IsKw(T_[B + 1], "exists"))) {
      Boolean(B + 1, E, S, Clause, false, Keys);
      return;
    }
    if (IsOp(T_[B], "(") && MatchParen(T_, B, E) == E - 1 &&
        !(B + 1 < E && (IsKw(T_[B + 1], "select") || IsKw(T_[B + 1], "with")))) {
      Boolean(B + 1, E - 1, S, Clause, Conjunctive, Keys);
      return;
    }
    Atom(B, E, S, Clause, Conjunctive, Keys);
  }

  void Atom(size_t B, size_t E, const Scope& S, const std::string& Clause, bool Conjunctive,
            std::vector<std::pair<ColumnRef, ColumnRef>>* Keys) {
    Predicate P;
    P.Scope = S.Label;
    P.Clause = Clause;
    P.Text = JoinText(T_, B, E);
    P.Conjunctive = Conjunctive;
    // top-level operator
    size_t OpB = E;
    size_t OpE = E;
    int Depth = 0;
    for (size_t I = B; I < E && OpB == E; ++I) {
      const Token& Tok = T_[I];
      if (IsOp(Tok, "(")) {
        ++Depth;
        continue;
      }
      if (IsOp(Tok, ")")) {
        --Depth;
        continue;
      }
      if (Depth != 0) {
        continue;
      }
      static const char* const Ops[] = {"=", "==", "!=", "<>", "<", "<=", ">", ">="};
      for (const char* Op : Ops) {
        if (IsOp(Tok, Op)) {
          OpB = I;
          OpE = I + 1;
          P.Op = std::string(Op) == "==" ? "=" : Op;
          break;
        }
      }
      if (OpB != E) {
        break;
      }
      if (Tok.Kind == TokKind::Keyword && (Tok.Text == "like" || Tok.Text == "glob" || Tok.Text == "in" ||
                                           Tok.Text == "between" || Tok.Text == "is" || Tok.Text == "regexp" ||
                                           Tok.Text == "match")) {
        OpB = I;
        OpE = I + 1;
        P.Op = Tok.Text;
        if (Tok.Text == "is" && I + 1 < E && IsKw(T_[I + 1], "not")) {
          P.Op = "is not";
          OpE = I + 2;
        }
        if (I > B && IsKw(T_[I - 1], "not")) {
          P.Op = "not " + P.Op;
          OpB = I - 1;
        }
        break;
      }
    }
    std::vector<ColumnRef> Left;
    std::vector<ColumnRef> Right;
    std::vector<std::string> LeftSrc;
    std::vector<std::string> RightSrc;
    Refs(B, OpB, S, &Left, false, &LeftSrc);
    if (OpE < E) {
      Refs(OpE, E, S, &Right, false, &RightSrc);
    }
    P.Columns = Left;
    P.Columns.insert(P.Columns.end(), Right.begin(), Right.end());
    std::set<std::string> Instances(LeftSrc.begin(), LeftSrc.end());
    Instances.insert(RightSrc.begin(), RightSrc.end());
    Instances.erase("");
    P.Join = Instances.size() >= 2;
    const auto BareColumn = [&](size_t From, size_t To) {
      return (To - From == 3 && T_[From].Kind == TokKind::Ident && IsOp(T_[From + 1], ".") &&
              T_[From + 2].Kind == TokKind::Ident) ||
             (To - From == 1 && T_[From].Kind == TokKind::Ident);
    };
    if (P.Join && P.Op == "=" && Left.size() == 1 && Right.size() == 1 && BareColumn(B, OpB) && BareColumn(OpE, E) &&
        LeftSrc[0] != RightSrc[0]) {
      std::pair<ColumnRef, ColumnRef> Key{Left[0], Right[0]};
      if (Key.second < Key.first) {
        std::swap(Key.first, Key.second);
      }
      P.EquiKey = Key;
      if (Conjunctive && Keys != nullptr) {
        Keys->push_back(Key);
      }
    }
    Out_.Predicates.push_back(std::move(P));
  }

  void Finish() {
    Out_.Tables.assign(Tables_.begin(), Tables_.end());
    Out_.Columns.assign(Columns_.begin(), Columns_.end());
    Out_.CteColumns.assign(CteColumns_.begin(), CteColumns_.end());
    Out_.GroupBy.assign(Group_.begin(), Group_.end());
    Out_.OrderBy.assign(Order_.begin(), Order_.end());
    Out_.Unresolved.assign(Unresolved_.begin(), Unresolved_.end());
    std::set<std::pair<ColumnRef, ColumnRef>> All;
    std::string Signature;
    for (size_t A = 0; A < ArmKeys_.size(); ++A) {
      std::set<std::pair<ColumnRef, ColumnRef>> Arm(ArmKeys_[A].begin(), ArmKeys_[A].end());
      All.insert(Arm.begin(), Arm.end());
      std::string Text;
      for (const auto& [L, R] : Arm) {
        Text += (Text.empty() ? "" : " & ") + L.Text() + "=" + R.Text();
      }
      Signature += (A == 0 ? "" : " | ") + Text;
    }
    Out_.JoinKeys.assign(All.begin(), All.end());
    Out_.KeySignature = Signature;
  }
};

}  // namespace

bool ColumnRef::operator<(const ColumnRef& Other) const {
  const int A = SourceRank(Source);
  const int B = SourceRank(Other.Source);
  if (A != B) {
    return A < B;
  }
  if (Source != Other.Source) {
    return Source < Other.Source;
  }
  return Column < Other.Column;
}

DataTouched DescribeSqlDataTouched(std::string_view Sql) { return Analyzer(Sql).Run(); }

DataTouched HeuristicDataTouched(int Id, std::string_view Postfix) {
  return DescribeSqlDataTouched(ApplyPostfix(Heuristic(Id).Sql, Postfix));
}

}  // namespace Tiers

}  // namespace DSig::Diff
