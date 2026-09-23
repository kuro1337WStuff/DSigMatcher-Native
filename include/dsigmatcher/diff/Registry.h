#pragma once

// The 50 entries of diaphora_heuristics.HEURISTICS (H:89-1177), generated verbatim by
// tools/parity/gen_registry.py into src/diff/RegistrySql.inc. Index == position in HEURISTICS.
//
// Flags are list membership in Diaphora, not bits: HEUR_FLAG_UNRELIABLE = 1, HEUR_FLAG_SLOW = 2 and
// HEUR_FLAG_SAME_CPU = 3 (H:44-48) are tested with `in flags` (D:1498-1508), so they are stored as
// three booleans. `Min` is read only for RATIO_MAX / RATIO_MAX_TRUSTED (D:1493-1495).

#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace DSig::Diff {

// H:28-41 HEUR_TYPE_*
enum class HeurType : uint8_t { NoFps = 0, Ratio = 1, RatioMax = 2, RatioMaxTrusted = 3 };

// heur["category"]. No entry uses "Experimental" (02 Appendix B); it exists for completeness.
enum class HeurCategory : uint8_t { Best = 0, Partial = 1, Unreliable = 2, Experimental = 3 };

struct HeuristicSpec {
  int Id = 0;                        // index in HEURISTICS (0..49)
  std::string_view Name;             // verbatim NAME (also the SQL description literal, except H10)
  HeurCategory Category = HeurCategory::Best;
  HeurType RatioType = HeurType::NoFps;
  double Min = 0.0;                  // heur["min"]; 0.0 when absent
  bool HasMin = false;               // "min" in heur
  bool FlagUnreliable = false;       // HEUR_FLAG_UNRELIABLE in flags
  bool FlagSlow = false;             // HEUR_FLAG_SLOW in flags
  bool FlagSameCpu = false;          // HEUR_FLAG_SAME_CPU in flags
  std::string_view FlagsRepr;        // repr(heur["flags"]), for evidence
  int SourceLineBegin = 0;           // H: line of `NAME = ...`
  int SourceLineEnd = 0;             // H: line closing HEURISTICS.append(...)
  std::string_view SqlSha256;        // sha256 of Sql (UTF-8), from the generator
  std::string_view Sql;              // verbatim final heur["sql"], still containing %POSTFIX%
};

std::span<const HeuristicSpec> Heuristics();
const HeuristicSpec& Heuristic(int Id);  // throws std::out_of_range

// Python str.replace(sql, "%POSTFIX%", postfix): every occurrence, left to right (D:1518; H10 has two).
std::string ApplyPostfix(std::string_view Sql, std::string_view Postfix);

std::string_view CategoryName(HeurCategory Category);  // "Best", "Partial", "Unreliable", "Experimental"
std::string_view HeurTypeName(HeurType Type);          // "NO_FPS", "RATIO", "RATIO_MAX", "RATIO_MAX_TRUSTED"

}
