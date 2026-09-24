#pragma once

// Configuration under test (01 §1-§2): `python diaphora.py db1 db2 -o out` with the
// shipped diaphora_config.py and no DIAPHORA_* environment variables. C: = diaphora_config.py,
// D: = diaphora.py (Diaphora 3.4.2-4-g621ec26).

#include <cstdint>
#include <string_view>

namespace DSig::Diff {

// D:100 VERSION_VALUE, written to config.version and compared with diff.version (D:3590).
inline constexpr std::string_view kVersionValue = "3.4";

// diaphora_config.py constants read by the default diff path.
inline constexpr double kDefaultPartialRatio = 0.5;                         // C:137 DEFAULT_PARTIAL_RATIO
inline constexpr double kDefaultTrustedPartialRatio = 0.3;                  // C:141 DEFAULT_TRUSTED_PARTIAL_RATIO
inline constexpr double kMatchesBonusRatio = 0.01;                          // C:116 MATCHES_BONUS_RATIO
inline constexpr double kRelatedMatchesMinRatio = 0.8;                      // C:194 RELATED_MATCHES_MIN_RATIO
inline constexpr double kIncreaseRatioPerConstantMatchSameCpu = 0.006;      // C:147
inline constexpr double kIncreaseRatioPerConstantMatch = 0.008;             // C:148
inline constexpr double kSpeedupStrippedBinariesMinPercent = 99.0;          // C:160
inline constexpr double kSpeedupPatchDiffSymbolsMinPercent = 90.0;          // C:166
inline constexpr double kSpeedupPatchDiffRenamedFunctionMinRatio = 0.6;     // C:172
inline constexpr int kMaxFunctionsPerGap = 100;                             // C:124 MAX_FUNCTIONS_PER_GAP
inline constexpr int kDiffingMatchesMaxDifferentBblocksPercent = 25;        // C:177
inline constexpr int kDiffingMatchesMinBblocks = 3;                         // C:183
inline constexpr int64_t kSqlMaxProcessedRows = 1000000;                    // C:90 SQL_MAX_PROCESSED_ROWS
inline constexpr int kSqlTimeoutLimitSeconds = 300;                         // C:92 (never emulated, 02 §5.4)
inline constexpr std::string_view kSqlDefaultPostfix =
    " and f.instructions > 5 and df.instructions > 5 ";                    // C:128 SQL_DEFAULT_POSTFIX
inline constexpr std::string_view kDecimalValues = "7f";                    // C:120 DECIMAL_VALUES
inline constexpr double kMinimumRareMdIndex = 10.0;                         // C:133 (relaxed ratio only)
inline constexpr bool kRunDefaultScripts = true;                            // C:186 RUN_DEFAULT_SCRIPTS
inline constexpr double kMlTrainedModelMatchScore = 0.15;                   // C:209 (ML is off)

// The flags CBinDiff resolves at construction (D:374-493) for a standalone run.
struct DiffConfig {
  bool Unreliable = false;            // C:46, D:400-402
  bool RelaxedRatio = false;          // C:47, D:403-405
  bool Experimental = true;           // C:48, D:406-408
  bool SlowHeuristics = true;         // C:49, D:409-411 (no auto-disable outside IDA)
  bool UseTrainedModel = false;       // C:205, D:412-414 (classifier stays None)
  bool IgnoreSubNames = true;         // C:50, D:468 (no environment override)
  bool IgnoreAllNames = false;        // C:51, forced False for standalone at D:3759-3760
  bool IgnoreSmallFunctions = false;  // C:52, D:474-476 (%POSTFIX% becomes "" when false)
  int CpuCount = 1;                   // D:489-491: `if not IS_IDA: self.cpu_count = 1`
  int64_t MaxProcessedRows = kSqlMaxProcessedRows;  // D:454-456

  // The %POSTFIX% text run_heuristics_for_category substitutes (D:1471-1473).
  std::string_view Postfix() const { return IgnoreSmallFunctions ? kSqlDefaultPostfix : std::string_view(); }

  // True for every configuration the parity engine supports: the defaults above, optionally with
  // IgnoreSmallFunctions. Unreliable, relaxed ratio, ML and threads are refused (exit 4).
  bool Supported() const {
    return !Unreliable && !RelaxedRatio && Experimental && SlowHeuristics && !UseTrainedModel &&
           IgnoreSubNames && !IgnoreAllNames && CpuCount == 1 && MaxProcessedRows == kSqlMaxProcessedRows;
  }
};

}
