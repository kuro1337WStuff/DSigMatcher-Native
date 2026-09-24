#pragma once

// Every non-registry SQL string the default diff runs, rendered by tools/parity/gen_registry.py
// exactly as diaphora.py builds it (get_query_fields from diaphora_heuristics, f-strings / .format /
// .replace applied as at the cited D: lines) into src/diff/StageSql.inc. Run them only through Path A
// (Database.h / Candidates.h), never rewritten.

#include <span>
#include <string_view>

namespace DSig::Diff {

struct StageSqlSpec {
  std::string_view Name;    // the constant's name, e.g. "kSqlSameName"
  std::string_view Method;  // CBinDiff method that builds it
  int LineBegin = 0;        // D: lines
  int LineEnd = 0;
  int BindCount = 0;        // '?' parameters
  std::string_view Sha256;  // of Sql (UTF-8), from the generator
  std::string_view Sql;
};

std::span<const StageSqlSpec> StageSqls();
const StageSqlSpec& StageSql(std::string_view Name);  // throws std::out_of_range

extern const std::string_view kSqlVersion;            // D:3578 select value from diff.version
extern const std::string_view kSqlEqualDbMd5;         // D:668
extern const std::string_view kSqlEqualDbExcept;      // D:673-680
extern const std::string_view kSqlCallgraph;          // D:1294-1296 (union all of both program tables)
extern const std::string_view kSqlTotals;             // D:1411-1413
extern const std::string_view kSqlEqualMatches;       // D:1424-1430 (INTERSECT)
extern const std::string_view kSqlSameProcessor;      // D:2957-2960
extern const std::string_view kSqlStrippedCount;      // D:2551-2554
extern const std::string_view kSqlStrippedRows;       // D:2569-2577 ('Same binary with symbols stripped')
extern const std::string_view kSqlPatchCount;         // D:2599-2603
extern const std::string_view kSqlSameName;           // D:2158-2166 ('Perfect match, same name')
extern const std::string_view kSqlSmallDifferences;   // D:2093-2106 (+ f_names, df_names)
extern const std::string_view kSqlUnmatchedUnion;     // D:2647-2650
extern const std::string_view kSqlRemainingPair;      // D:2675-2685 binds: desc, ea1, ea2 (all text)
extern const std::string_view kSqlUnmatchedMain;      // D:2330
extern const std::string_view kSqlUnmatchedDiff;      // D:2343
extern const std::string_view kSqlFunctionRowMain;    // D:2453 bind: name (text)
extern const std::string_view kSqlFunctionRowDiff;    // D:2453 bind: name (text)
extern const std::string_view kSqlFunctionsExists;    // D:2976-2988 binds: name1, name2 (text)
extern const std::string_view kSqlGapMain;            // D:3236-3240 binds: ea texts
extern const std::string_view kSqlGapDiff;            // D:3236-3240 binds: ea texts
extern const std::string_view kSqlRelatedConstants;   // D:3375-3387 bind: str(constant) (text)
extern const std::string_view kSqlCuLookupMain;       // D:3419-3427 bind: name (text)
extern const std::string_view kSqlCuLookupDiff;       // D:3419-3427 bind: name (text)
extern const std::string_view kSqlCuCartesian;        // D:3429-3433 binds: 4 doubles

}
