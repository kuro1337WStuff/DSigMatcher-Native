// The heuristic registry and the stage SQL table, both generated verbatim from Diaphora by
// tools/parity/gen_registry.py.

#include "dsigmatcher/diff/Registry.h"

#include <iterator>
#include <stdexcept>
#include <string>

#include "dsigmatcher/diff/StageSql.h"

namespace DSig::Diff {

namespace {

constexpr HeuristicSpec kHeuristicTable[] = {
#include "RegistrySql.inc"
};

constexpr StageSqlSpec kStageSqlTable[] = {
#include "StageSql.inc"
};

constexpr std::string_view LookupStageSql(std::string_view Name) {
  for (const StageSqlSpec& Spec : kStageSqlTable) {
    if (Spec.Name == Name) {
      return Spec.Sql;
    }
  }
  return std::string_view();
}

static_assert(sizeof(kHeuristicTable) / sizeof(kHeuristicTable[0]) == 50, "HEURISTICS has 50 entries");

}

std::span<const HeuristicSpec> Heuristics() { return kHeuristicTable; }

const HeuristicSpec& Heuristic(int Id) {
  if (Id < 0 || static_cast<size_t>(Id) >= std::size(kHeuristicTable)) {
    throw std::out_of_range("heuristic id " + std::to_string(Id));
  }
  return kHeuristicTable[static_cast<size_t>(Id)];
}

std::string ApplyPostfix(std::string_view Sql, std::string_view Postfix) {
  // Python str.replace: every non-overlapping occurrence, scanning left to right (D:1518).
  static constexpr std::string_view Token = "%POSTFIX%";
  std::string Result;
  Result.reserve(Sql.size() + Postfix.size() * 2);
  size_t Position = 0;
  while (true) {
    const size_t Found = Sql.find(Token, Position);
    if (Found == std::string_view::npos) {
      Result.append(Sql.substr(Position));
      return Result;
    }
    Result.append(Sql.substr(Position, Found - Position));
    Result.append(Postfix);
    Position = Found + Token.size();
  }
}

std::string_view CategoryName(HeurCategory Category) {
  switch (Category) {
    case HeurCategory::Best:
      return "Best";
    case HeurCategory::Partial:
      return "Partial";
    case HeurCategory::Unreliable:
      return "Unreliable";
    case HeurCategory::Experimental:
      return "Experimental";
  }
  return "";
}

std::string_view HeurTypeName(HeurType Type) {
  switch (Type) {
    case HeurType::NoFps:
      return "NO_FPS";
    case HeurType::Ratio:
      return "RATIO";
    case HeurType::RatioMax:
      return "RATIO_MAX";
    case HeurType::RatioMaxTrusted:
      return "RATIO_MAX_TRUSTED";
  }
  return "";
}

std::span<const StageSqlSpec> StageSqls() { return kStageSqlTable; }

const StageSqlSpec& StageSql(std::string_view Name) {
  for (const StageSqlSpec& Spec : kStageSqlTable) {
    if (Spec.Name == Name) {
      return Spec;
    }
  }
  throw std::out_of_range("unknown stage SQL " + std::string(Name));
}

const std::string_view kSqlVersion = LookupStageSql("kSqlVersion");
const std::string_view kSqlEqualDbMd5 = LookupStageSql("kSqlEqualDbMd5");
const std::string_view kSqlEqualDbExcept = LookupStageSql("kSqlEqualDbExcept");
const std::string_view kSqlCallgraph = LookupStageSql("kSqlCallgraph");
const std::string_view kSqlTotals = LookupStageSql("kSqlTotals");
const std::string_view kSqlEqualMatches = LookupStageSql("kSqlEqualMatches");
const std::string_view kSqlSameProcessor = LookupStageSql("kSqlSameProcessor");
const std::string_view kSqlStrippedCount = LookupStageSql("kSqlStrippedCount");
const std::string_view kSqlStrippedRows = LookupStageSql("kSqlStrippedRows");
const std::string_view kSqlPatchCount = LookupStageSql("kSqlPatchCount");
const std::string_view kSqlSameName = LookupStageSql("kSqlSameName");
const std::string_view kSqlSmallDifferences = LookupStageSql("kSqlSmallDifferences");
const std::string_view kSqlUnmatchedUnion = LookupStageSql("kSqlUnmatchedUnion");
const std::string_view kSqlRemainingPair = LookupStageSql("kSqlRemainingPair");
const std::string_view kSqlUnmatchedMain = LookupStageSql("kSqlUnmatchedMain");
const std::string_view kSqlUnmatchedDiff = LookupStageSql("kSqlUnmatchedDiff");
const std::string_view kSqlFunctionRowMain = LookupStageSql("kSqlFunctionRowMain");
const std::string_view kSqlFunctionRowDiff = LookupStageSql("kSqlFunctionRowDiff");
const std::string_view kSqlFunctionsExists = LookupStageSql("kSqlFunctionsExists");
const std::string_view kSqlGapMain = LookupStageSql("kSqlGapMain");
const std::string_view kSqlGapDiff = LookupStageSql("kSqlGapDiff");
const std::string_view kSqlRelatedConstants = LookupStageSql("kSqlRelatedConstants");
const std::string_view kSqlCuLookupMain = LookupStageSql("kSqlCuLookupMain");
const std::string_view kSqlCuLookupDiff = LookupStageSql("kSqlCuLookupDiff");
const std::string_view kSqlCuCartesian = LookupStageSql("kSqlCuCartesian");

}
