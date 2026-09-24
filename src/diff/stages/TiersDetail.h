#pragma once

// Private interface (not part of the public API): helpers of src/diff/stages/HeuristicTiers.cpp
// and SmallDifferences.cpp that the diff_tiers suite and a later fusion pass use.
//
//  * RunnableHeuristics: the list run_heuristics_for_category builds (D:1479-1541), in HEURISTICS
//    order, before threads_apply runs it back to front (jkutils/threads.py:40).
//  * HeuristicTruncations: the heuristics whose worker "thread" ended with an exception (02 §5.5),
//    recorded per session. Diaphora only logs them (D:1968, D:2081) and threading.excepthook prints
//    the traceback; the record exists so tests and diagnostics can see the truncation.
//  * DataTouched: a read-only description of what one SQL string reads (tables, columns, join keys),
//    derived lexically from the verbatim SQL. No stage uses it to decide anything; it exists so a
//    post-parity fusion pass can group heuristics that share join keys (docs/fusion/INVENTORY.md).

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "dsigmatcher/diff/Registry.h"

namespace DSig::Diff {

class DiffSession;

namespace Tiers {

// D:1479-1541: the heuristic ids run_heuristics_for_category(Category) appends to
// heuristic_functions, in HEURISTICS order (the order threads_apply pops them in is the reverse).
// Empty when the build-time all_functions_matched test fires at the first entry (D:1481-1484).
// Throws DiaphoraWouldRaise("D:1495 KeyError") for a RATIO_MAX / TRUSTED entry without "min".
std::vector<int> RunnableHeuristics(DiffSession& S, HeurCategory Category);

struct HeuristicTruncation {
  int Id = -1;
  std::string Site;    // DiaphoraWouldRaise::Site
  std::string Detail;  // DiaphoraWouldRaise::Detail
};
// Every truncated heuristic of this session, in execution order.
const std::vector<HeuristicTruncation>& HeuristicTruncations(DiffSession& S);

// search_small_differences("partial") (D:2085-2150) over `Sql` instead of kSqlSmallDifferences. The
// stage is SearchSmallDifferencesWith(S, kSqlSmallDifferences); tests use another query (the same
// aliases plus a column that fails at a chosen row) to pin result_iter's fetchmany(1000) batching.
void SearchSmallDifferencesWith(DiffSession& S, std::string_view Sql);

// ---- data touched ---------------------------------------------------------------------------

// A column read by the SQL. Source is a schema-qualified table ("main.functions", "diff.constants";
// an unqualified table is "main.", SQLite's search order with no temp tables), "cte:<name>" for a
// column of a common table expression, or "?<alias>" when the alias could not be resolved.
struct ColumnRef {
  std::string Source;
  std::string Column;
  bool operator==(const ColumnRef&) const = default;
  bool operator<(const ColumnRef& Other) const;  // main.* < diff.* < cte:* < other, then text
  std::string Text() const { return Source + "." + Column; }
};

// One boolean atom of a WHERE / HAVING / ON clause, after splitting at AND / OR.
struct Predicate {
  std::string Scope;                // "select" (the outer query; "select#2" for the 2nd UNION arm) or "cte:<name>"
  std::string Clause;               // "where", "having" or "on"
  std::string Text;                 // the atom's tokens joined by single spaces (lower-case keywords kept as written)
  std::string Op;                   // top-level comparison: "=", "!=", "<", "<=", ">", ">=", "like", "not like",
                                    // "is", "is not", "in", "between", ... or "" when there is none
  std::vector<ColumnRef> Columns;   // columns the atom reads, in order of appearance
  bool Join = false;                // reads columns of two or more row sources of its scope
  bool Conjunctive = false;         // reached from the clause root through AND only (holds for every row)
  // Join && Op is "=" (or "==") && both sides are a bare column: the equi-join key, main side first.
  std::optional<std::pair<ColumnRef, ColumnRef>> EquiKey;
};

struct DataTouched {
  std::vector<std::string> Tables;      // base tables read (schema-qualified), sorted, unique
  std::vector<ColumnRef> Columns;       // base-table columns read anywhere in the SQL, sorted, unique
  std::vector<ColumnRef> CteColumns;    // columns of CTEs the SQL references, sorted, unique
  std::vector<std::string> Ctes;        // CTE names, in definition order
  std::vector<Predicate> Predicates;    // every WHERE / HAVING / ON atom, in text order
  std::vector<ColumnRef> GroupBy;       // GROUP BY columns (any scope), sorted, unique
  std::vector<ColumnRef> OrderBy;       // ORDER BY columns (any scope), sorted, unique
  // The conjunctive equi-join keys of the outer query (every UNION arm), "main = diff" normalised,
  // sorted, unique: the hash keys a fused generator could build once and share.
  std::vector<std::pair<ColumnRef, ColumnRef>> JoinKeys;
  bool Distinct = false;
  bool Union = false;
  bool GroupByPresent = false;
  bool OrderByPresent = false;
  int PostfixTokens = 0;                // `%POSTFIX%` occurrences still in the text analysed
  std::vector<std::string> Unresolved;  // names that could not be attributed (empty for all 50)
  // Canonical grouping key: the JoinKeys as "a.x=b.y" joined by " & " (UNION arms joined by " | ").
  std::string KeySignature;
};

// Lexical analysis of one SQL string (SQLite syntax subset used by Diaphora: WITH, SELECT [DISTINCT],
// comma joins and JOIN ... ON, WHERE, GROUP BY, HAVING, ORDER BY, UNION, CASE, CAST). Never throws.
DataTouched DescribeSqlDataTouched(std::string_view Sql);
// HEURISTICS[Id]["sql"] with %POSTFIX% replaced by `Postfix` (D:1518; "" is the default
// configuration, C:52 / D:1471-1473). Throws std::out_of_range for an unknown id.
DataTouched HeuristicDataTouched(int Id, std::string_view Postfix = std::string_view());

}  // namespace Tiers
}  // namespace DSig::Diff
