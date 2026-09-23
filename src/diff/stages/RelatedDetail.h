#pragma once

// Lane L8 private extension point (not part of the frozen API; src/diff is a private include
// directory of dsigmatcher_diff).
//
// find_related_constants iterates `inter_consts`, a CPython set (D:3389), so the order in which its
// str elements are executed depends on PYTHONHASHSEED (plan §5 R3, 06 Open question 2, 02 §18.2).
// The engine uses the documented order: first appearance in the main function's JSON list. A caller
// that knows CPython's order for one run (for example the oracle captures, recorded under
// PYTHONHASHSEED=12345) can install it here to replay that run exactly; nothing else changes. Unset,
// it costs nothing and the documented order applies.

#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace DSig::Diff::Detail {

struct RelatedConstantOrder {
  // Called once per find_related_constants call that has at least two constants, with the main and
  // diff function names (the seed's rows) and str(constant) of every intersection element in the
  // documented order. Returns the order to execute. The result must be a permutation of `Native`
  // (the engine refuses anything else with UnsupportedInput).
  std::function<std::vector<std::string>(std::string_view MainName, std::string_view DiffName,
                                         const std::vector<std::string>& Native)>
      Reorder;
};

}
