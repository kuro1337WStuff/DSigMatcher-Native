#pragma once

// Row consumers: check_match and the add_matches_* family. Literal ports of D:1786-2083.
// Spec: 02 §6-§12, 07 §10.5.1-10.5.2, 05 §2.2-§2.3.

#include <cstdint>
#include <optional>

#include "dsigmatcher/diff/Candidates.h"
#include "dsigmatcher/diff/MatchState.h"

namespace DSig::Diff {

class DiffSession;

// Which md_index double check_ratio uses (03a §6.4): the SQL row's `cast(md_index as real)` (check_match
// path) or Python float() of the TEXT (compare_function_rows path). Declared here because
// IRatioProvider needs it; Ratio.h re-exports it.
enum class MdSource : uint8_t { Sql = 0, Python = 1 };

class IRatioProvider {
public:
  virtual ~IRatioProvider() = default;
  virtual double CheckRatio(const HeuristicRow& Row, MdSource Src) = 0;           // check_match path (md from SQL cast)
  virtual double CompareFunctionRows(uint32_t MainRow, uint32_t DiffRow) = 0;     // D:2479-2538 (md via Python float)
};

// D:1786-1872: nullsub -> has_best_match -> check_ratio (MdSource::Sql) -> has_better_match -> hook.
// Returns the accepted ratio, or nullopt when Python returns (False, 0.0). When S.Flags().HooksLoaded,
// the hook is PatchDiffHookOnMatch (Stages.h, stages/PatchDiffHook.cpp).
std::optional<double> CheckMatch(DiffSession& S, const HeuristicRow& Row);

// D:1882-1948: routing plus the 1,000,000-row cap (D:1874-1880, counts every fetched row).
void AddMatchesInternal(DiffSession& S, RowSource& Rows, Chooser Best, std::optional<Chooser> Partial,
                        std::optional<double> Val = std::nullopt);
void AddMatchesFromQuery(DiffSession& S, RowSource& Rows, Chooser Category);                       // D:2039-2083 NO_FPS
void AddMatchesFromQueryRatio(DiffSession& S, RowSource& Rows, Chooser Best, Chooser Partial);    // D:1950-1975
void AddMatchesFromQueryRatioMax(DiffSession& S, RowSource& Rows, Chooser Best, Chooser Partial,
                                 double V);                                                       // D:1977-2000
void AddMatchesFromQueryRatioMaxTrusted(DiffSession& S, RowSource& Rows, double V);               // D:2002-2026

}
