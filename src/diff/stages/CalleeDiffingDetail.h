#pragma once

// Internal helpers of lane L7 (stages/CalleeDiffing.cpp). Private to src/diff; not part of the frozen
// API. The diff_callee suite includes this header to test the diff walk on its own and to read the
// per-session call counts.

#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace DSig::Diff::Detail {

// Per-session statistics of the callee-diffing stage, kept in DiffSession::Ext<CalleeDiffingStats>().
// OneMatchDiffingCalls counts find_one_match_diffing calls (D:3033) under the key
// "<field_name>:outer<k>:inner<i>", the key tools/parity/oracle_trace.py (WrapOneMatchDiffing) writes
// into run.json "stats"/"find_one_match_diffing" (06 V3: assembly 716 / pseudocode 426 on ls-old_vs_ls).
struct CalleeDiffingStats {
  std::map<std::string, int64_t> OneMatchDiffingCalls;
};

// The candidate pairs find_one_match_diffing's diff walk yields, in order and before the dones filter
// (D:3040-3066): unified_diff(main.splitlines(), diff.splitlines(), lineterm="") rows ("--- " / "+++ "
// headers included) collected into minus / plus, flushed at a context row when both are non-empty, and
// paired positionally over re.findall(CPP_NAMES_RE, "\n".join(block), re.I). Blocks still pending when
// the rows run out are discarded (03b §4.3.2, 06 §6.3).
std::vector<std::pair<std::string, std::string>> CalleeCandidatePairs(std::string_view MainText,
                                                                      std::string_view DiffText);

}
