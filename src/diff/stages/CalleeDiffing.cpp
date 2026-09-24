// Callee diffing, "Callee found diffing matches assembly / pseudo-code". Literal port of
// find_matches_diffing (D:3211-3229), find_matches_diffing_assembly / _pseudo (D:3195-3209),
// find_matches_diffing_internal (D:3150-3193) and find_one_match_diffing (D:3033-3131), with the helpers
// they call: get_row_for_items / get_function_row (D:2993-3001, D:2445-2460), functions_exists
// (D:2969-2991) and call_on_match_hook (D:3003-3031). Spec: 03b §4.3, 06 §4-§6 (including §6.7), 07
// §10.11.1, 02 §3. D: = diaphora.py, C: = diaphora_config.py (Diaphora 3.4.2-4-g621ec26).
//
// Everything runs on the main thread in Diaphora's order and writes only through MatchState::AddMatch;
// every cleanup_matches() goes through DiffSession::Cleanup so its before/after points and trace event
// exist. Rows are read through Path A: the verbatim `select *` statements of get_function_row and
// functions_exists (StageSql.h) through FetchFunctionRows, which maps each fetched row to its
// FunctionTable row by address.

#include <algorithm>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

#include "CalleeDiffingDetail.h"
#include "dsigmatcher/diff/Candidates.h"
#include "dsigmatcher/diff/Config.h"
#include "dsigmatcher/diff/Errors.h"
#include "dsigmatcher/diff/Pipeline.h"
#include "dsigmatcher/diff/StageSql.h"
#include "dsigmatcher/diff/Stages.h"
#include "dsigmatcher/diff/TextDiff.h"
#include "dsigmatcher/diff/Trace.h"

namespace DSig::Diff {

namespace Detail {

std::vector<std::pair<std::string, std::string>> CalleeCandidatePairs(std::string_view MainText,
                                                                      std::string_view DiffText) {
  // D:3040-3042: main_lines = ...splitlines(keepends=False); diff_lines likewise;
  // df = unified_diff(main_lines, diff_lines, lineterm="") (fromfile = tofile = '', n = 3).
  const std::vector<std::string_view> MainLines = PySplitLines(MainText);
  const std::vector<std::string_view> DiffLines = PySplitLines(DiffText);
  const std::vector<std::string> Rows = UnifiedDiff(MainLines, DiffLines, 3, "");

  // D:3044-3045: minus = [], plus = []. The views point into Rows, which outlives them.
  std::vector<std::string_view> Minus;
  std::vector<std::string_view> Plus;
  std::vector<std::pair<std::string, std::string>> Out;
  const auto Join = [](const std::vector<std::string_view>& Block) {  // "\n".join(block)
    std::string Text;
    for (size_t Index = 0; Index < Block.size(); ++Index) {
      if (Index != 0) {
        Text.push_back('\n');
      }
      Text.append(Block[Index]);
    }
    return Text;
  };
  for (const std::string& Row : Rows) {  // D:3047
    if (Row.empty()) {                   // D:3048-3049 (never true with lineterm="")
      continue;
    }
    // D:3051 c = row[0]. Every row starts with an ASCII character ("--- ", "+++ ", "@@ ", or the ' ',
    // '-', '+' prefix of a line), so its first byte is its first code point.
    const char C = Row[0];
    if (C == '-') {         // D:3052-3053, the "--- " header included
      Minus.push_back(Row);
    } else if (C == '+') {  // D:3054-3055, the "+++ " header included
      Plus.push_back(Row);
    } else if (C == ' ') {  // D:3056; "@@" rows fall through all three branches and never flush
      if (!Minus.empty() && !Plus.empty()) {  // D:3057
        // D:3058-3059: re.findall(CPP_NAMES_RE, "\n".join(minus / plus), re.IGNORECASE); element [i][0]
        // is group 1, the whole match. CppNamesFindAll returns views into its argument, so the joined
        // texts stay alive until the names are copied below.
        const std::string Joined1 = Join(Minus);
        const std::string Joined2 = Join(Plus);
        const std::vector<std::string_view> Matches1 = CppNamesFindAll(Joined1);
        const std::vector<std::string_view> Matches2 = CppNamesFindAll(Joined2);
        Minus.clear();  // D:3060-3061
        Plus.clear();
        const size_t Size = std::min(Matches1.size(), Matches2.size());  // D:3063
        for (size_t Index = 0; Index < Size; ++Index) {                  // D:3064-3066: positional pairing
          Out.emplace_back(std::string(Matches1[Index]), std::string(Matches2[Index]));
        }
      }
    }
  }
  // End of the rows: whatever is still in minus / plus is dropped (the loop just ends, D:3131).
  return Out;
}

}  // namespace Detail

namespace {

constexpr std::string_view kHeurAssembly = "Callee found diffing matches assembly";   // D:3199, D:3221
constexpr std::string_view kHeurPseudo = "Callee found diffing matches pseudo-code";  // D:3207, D:3226

enum class Field : uint8_t { Assembly, Pseudocode };

std::string_view FieldName(Field Which) {  // D:3200, D:3208
  return Which == Field::Assembly ? std::string_view("assembly") : std::string_view("pseudocode");
}

const TextColumn& FieldColumn(const FunctionTable& Table, Field Which) {
  return Which == Field::Assembly ? Table.Assembly : Table.Pseudocode;
}

// The `dones` set of find_matches_diffing_internal (D:3159): a Python set of str shared by the match keys
// f"{match[1]}-{match[3]}" (D:3168) and the callee keys f"{name1}-{name2}" (D:3067), 03b §4.3.2 quirk 5.
using DoneSet = std::unordered_set<std::string>;

// get_function_row(name, db_name) (D:2445-2460): `select * from {db_name}.functions where name = ?`
// bound with the name (str -> TEXT, None -> NULL), then fetchone(). The bare `except:` at D:2456-2457
// logs any error (an SQL failure, a row Python cannot decode) and returns None.
std::optional<uint32_t> GetFunctionRow(DiffSession& S, NameId Name, Side Which) {
  const std::string_view Sql = Which == Side::Main ? kSqlFunctionRowMain : kSqlFunctionRowDiff;  // D:2453
  const BindValue Bind = Name == kNoneName ? BindValue::Null() : BindValue::Str(S.Ids().NameText(Name));
  std::vector<FunctionRowRef> Rows;
  try {
    Rows = FetchFunctionRows(S, Sql, std::span<const BindValue>(&Bind, 1), Which, 1);  // D:2454-2455
  } catch (const DiaphoraWouldRaise&) {
    return std::nullopt;  // D:2456-2457
  }
  if (Rows.empty()) {
    return std::nullopt;  // fetchone() returned None
  }
  if (Rows.front().Row == kNoRow) {
    // The fetched row's address is not a TEXT address of the table (NULL or another storage class). The
    // exporter writes every address as text (`address text unique`, db_support/schema.py:72); the
    // Python value would flow into the item unchanged, which is not ported.
    throw UnsupportedInput("get_function_row: the row's address is not TEXT (input quirk not emulated)");
  }
  return Rows.front().Row;
}

// main_row["nodes"] / diff_row["nodes"] as Python sees them: an int, or None for NULL.
std::optional<int64_t> PyNodes(const FunctionTable& Table, uint32_t Row) {
  if (Table.Nodes.Null(Row)) {
    return std::nullopt;
  }
  if (Table.Nodes.NotInteger[Row] != 0) {
    throw UnsupportedInput(
        "functions.nodes holds a non-INTEGER value (Python min/max/true-division over float or str is not "
        "ported)");
  }
  return Table.Nodes.Value[Row];
}

// Magnitude below which int64 -> double is exact, so Python's int true division (correctly rounded,
// Objects/longobject.c long_true_divide) equals one IEEE division of the two converted operands.
constexpr int64_t kExactDoubleInt = int64_t{1} << 53;

// The candidate (name1, name2) after the dones and nullsub filters: D:3080-3129.
void ProcessCandidate(DiffSession& S, const std::string& Name1, const std::string& Name2, std::string_view Heur,
                      int Inner) {
  // D:3080 exists, l = self.functions_exists(name1, name2): the union of the main rows named name1 and the
  // diff rows named name2, 'main' first (order by db_name desc), fetchall (D:2976-2983); exists is
  // len(rows) == 2 (D:2984-2987). No except clause: an error propagates (D:2974-2990 try/finally).
  const BindValue Binds[2] = {BindValue::Str(Name1), BindValue::Str(Name2)};  // D:2982 (str -> TEXT)
  const std::vector<FunctionRowRef> L = FetchFunctionRows(S, kSqlFunctionsExists, Binds, Side::Main);
  if (L.size() != 2) {  // D:3081
    return;
  }
  if (L[0].Row == kNoRow || L[1].Row == kNoRow) {
    throw UnsupportedInput("functions_exists: a fetched row's address is not TEXT (input quirk not emulated)");
  }
  // D:3082-3083 main_row = l[0], diff_row = l[1]. Normally l[0] is the main row and l[1] the diff row. The
  // 06 §2.10 / 07 §10.11.1 quirk: a name present twice on one side and absent on the other also gives
  // exists == True with both rows from ONE database; the node checks below then read those two rows as
  // Python does, and the port refuses only where Python would compare them (see compare_function_rows).
  const bool SameDatabase = L[0].Which != Side::Main || L[1].Which != Side::Diff;
  const uint32_t MainRow = L[0].Row;
  const uint32_t DiffRow = L[1].Row;
  const FunctionTable& Main = S.Export(L[0].Which).Functions;
  const FunctionTable& Diff = S.Export(L[1].Which).Functions;

  // D:3084-3085 min(a, b) / max(a, b) evaluate `b < a` / `b > a`: None on either side raises TypeError.
  const std::optional<int64_t> Nodes1 = PyNodes(Main, MainRow);
  const std::optional<int64_t> Nodes2 = PyNodes(Diff, DiffRow);
  if (!Nodes1 || !Nodes2) {
    const auto TypeName = [](const std::optional<int64_t>& Value) { return Value ? "int" : "NoneType"; };
    throw DiaphoraWouldRaise("D:3084 TypeError", std::string("'<' not supported between instances of '") +
                                                     TypeName(Nodes2) + "' and '" + TypeName(Nodes1) + "'");
  }
  const int64_t MinNodes = std::min(*Nodes1, *Nodes2);  // D:3084
  const int64_t MaxNodes = std::max(*Nodes1, *Nodes2);  // D:3085

  // D:3088-3091: (min_nodes * 100) / max_nodes < DIFFING_MATCHES_MAX_DIFFERENT_BBLOCKS_PERCENT (C:177 = 25),
  // Python true division (a float, correctly rounded) compared exactly with the int 25. max_nodes == 0
  // raises ZeroDivisionError before the DIFFING_MATCHES_MIN_BBLOCKS checks, and nothing catches it up to
  // __main__ (03b §4.3.4, experiment Z).
  if (MaxNodes == 0) {
    throw DiaphoraWouldRaise("D:3089 ZeroDivisionError", "division by zero");
  }
  if (MinNodes > kExactDoubleInt / 100 || MinNodes < -(kExactDoubleInt / 100) || MaxNodes > kExactDoubleInt ||
      MaxNodes < -kExactDoubleInt) {
    throw UnsupportedInput("functions.nodes beyond 2^53 / 100: Python's exact int true division is not ported");
  }
  const double Percent = static_cast<double>(MinNodes * 100) / static_cast<double>(MaxNodes);
  if (Percent < static_cast<double>(kDiffingMatchesMaxDifferentBblocksPercent)) {
    return;
  }
  // D:3096-3099: DIFFING_MATCHES_MIN_BBLOCKS (C:183 = 3) on each side, main first.
  if (*Nodes1 < kDiffingMatchesMinBblocks) {
    return;
  }
  if (*Nodes2 < kDiffingMatchesMinBblocks) {
    return;
  }

  // D:3101 r = self.compare_function_rows(main_row, diff_row) (D:2479-2538: ratios_cache, then check_ratio
  // with md_index converted by Python float(); RatioEngine::CompareFunctionRows).
  if (SameDatabase) {
    // The same-database quirk reached the comparison: Python would score two rows of one table (and key
    // ratios_cache / deep_ratio by their addresses), which IRatioProvider cannot express. Refused
    // instead of guessed.
    throw UnsupportedInput("functions_exists('" + Name1 + "', '" + Name2 +
                           "') returned two rows of the same database (duplicate function names; 06 §2.10)");
  }
  double Ratio = S.Ratio().CompareFunctionRows(MainRow, DiffRow);
  Chooser Category = Chooser::Best;
  if (Ratio == 1.0) {  // D:3102-3103
    Category = Chooser::Best;
  } else if (Ratio > kDefaultTrustedPartialRatio) {  // D:3104-3105 (C:141 = 0.3, strict)
    Category = Chooser::Partial;
  } else {  // D:3106-3107
    return;
  }
  // D:3109-3110: the bonus is added AFTER the chooser was picked, in IEEE double (C:116 = 0.01); 0.99 +
  // 0.01 == 1.0, so a capped 0.99 gets no bonus (06 §6.5 item 7).
  if (Ratio + kMatchesBonusRatio < 1.0) {
    Ratio += kMatchesBonusRatio;
  }

  // D:3112 should_add, r = self.call_on_match_hook(heur, r, main_row, diff_row). Without hooks it returns
  // (True, r) (D:3007-3008, D:3031). With hooks (only scripts/patch_diff_vulns.py, loaded in patch-diff
  // mode, where the iteration loop never runs, 02 §3 step 4) it calls on_match(d1, d2, desc, r) with
  // desc = heur (no iteration suffix, D:3009), both names taken from MAIN (d2["name"] = main_row["name"],
  // the D:3013 Diaphora bug kept on purpose, 06 §2.11) and int() of both node counts (D:3020-3021).
  // PatchDiffHookOnMatch reproduces that script's raising conditions; its return value is
  // always (True, ratio) (scripts/patch_diff_vulns.py:204-236). md_index (D:3022-3023) is not read by it.
  if (S.Flags().HooksLoaded) {
    HeuristicRow HookRow;
    HookRow.Ea1 = Main.AddrIdOf[MainRow];  // D:3010
    HookRow.Ea2 = Diff.AddrIdOf[DiffRow];  // D:3011
    HookRow.Row1 = MainRow;
    HookRow.Row2 = DiffRow;
    HookRow.Side1 = Side::Main;
    HookRow.Side2 = Side::Diff;
    HookRow.Name1 = Main.NameIdOf[MainRow];  // D:3012
    HookRow.Name2 = Main.NameIdOf[MainRow];  // D:3013 (sic: main_row["name"])
    HookRow.Desc = S.Ids().Desc(Heur);       // D:3009
    HookRow.Nodes1 = *Nodes1;                // D:3020
    HookRow.Nodes2 = *Nodes2;                // D:3021
    PatchDiffHookOnMatch(S, HookRow, Ratio);
  }

  // D:3113-3129: heur_text = f"{heur} (iteration #{iteration})"; the item [ea1, name1, ea2, name2,
  // heur_text, r, int(nodes1), int(nodes2)] with the addresses of the two fetched rows (their TEXT) and the
  // names extracted by the regex; add_match(name1, name2, r, new_item, chooser). add_match has no
  // has_best_match check, so a same-name or already-matched pair is appended again (06 §6.7 churn) and the
  // next cleanup_matches sorts it out.
  const std::string HeurText = std::string(Heur) + " (iteration #" + std::to_string(Inner) + ")";
  const NameId Id1 = S.Ids().Name(Name1);
  const NameId Id2 = S.Ids().Name(Name2);
  const Item NewItem{Main.AddrIdOf[MainRow], Id1, Diff.AddrIdOf[DiffRow], Id2, S.Ids().Desc(HeurText), Ratio,
                     *Nodes1, *Nodes2};
  S.State().AddMatch(Id1, Id2, Ratio, NewItem, Category);
}

// find_one_match_diffing(input_main_row, input_diff_row, field_name, heur, iteration, dones)
// (D:3033-3131). `dones` is mutated in place and returned (D:3131, reassigned at D:3181).
void FindOneMatchDiffing(DiffSession& S, int Outer, uint32_t MainRow, uint32_t DiffRow, Field Which,
                         std::string_view Heur, int Inner, DoneSet& Dones) {
  ++S.Ext<Detail::CalleeDiffingStats>()
        .OneMatchDiffingCalls[std::string(FieldName(Which)) + ":outer" + std::to_string(Outer) + ":inner" +
                              std::to_string(Inner)];
  const TextColumn& MainColumn = FieldColumn(S.Main().Functions, Which);
  const TextColumn& DiffColumn = FieldColumn(S.Diff().Functions, Which);
  if (MainColumn.IsBlob[MainRow] != 0 || DiffColumn.IsBlob[DiffRow] != 0) {
    // A BLOB would reach D:3040 as Python bytes (bytes.splitlines, then str.format of bytes lines inside
    // unified_diff); the exporter only writes text, so this is refused rather than emulated.
    throw UnsupportedInput(std::string("functions.") + std::string(FieldName(Which)) +
                           " is a BLOB (Python bytes semantics of D:3040-3059 not ported)");
  }
  const std::vector<std::pair<std::string, std::string>> Pairs =
      Detail::CalleeCandidatePairs(MainColumn.View(MainRow), DiffColumn.View(DiffRow));  // D:3040-3066
  for (const auto& [Name1, Name2] : Pairs) {
    // D:3067-3070: the key is marked done BEFORE any filter, so rejected pairs are remembered too.
    if (!Dones.insert(Name1 + "-" + Name2).second) {
      continue;
    }
    // D:3072-3074: the prefix is "nullsub" (no underscore, case-sensitive).
    if (Name1.starts_with("nullsub") || Name2.starts_with("nullsub")) {
      continue;
    }
    // D:3076-3078: a progress log line every 10,000 keys (log only; `size` no longer bounds the loop).
    ProcessCandidate(S, Name1, Name2, Heur, Inner);
  }
}

// find_matches_diffing_internal(heur, field_name) (D:3150-3193).
void FindMatchesDiffingInternal(DiffSession& S, int Outer, std::string_view Heur, Field Which) {
  // D:3156 log_refresh(f"Finding with heuristic '{heur}'"): log only.
  int Inner = 1;  // D:3158
  DoneSet Dones;  // D:3159
  while (Inner <= 3) {  // D:3162
    const size_t OldTotal = S.State().TotalMatchedFunctions();  // D:3163
    for (const Chooser Key : {Chooser::Best, Chooser::Partial}) {  // D:3165
      // D:3166 get_sorted_results(key): a stable descending copy taken when this category's walk starts,
      // so the partial snapshot includes partial items added while walking best (06 §5).
      const std::vector<Item> Snapshot = S.State().SortedResults(Key);
      for (const Item& Match : Snapshot) {  // D:3167
        // D:3168-3171: f"{match[1]}-{match[3]}" (None renders "None"), marked done before the row checks.
        std::string MatchKey = std::string(S.Ids().NameKeyText(Match.Name1)) + "-" +
                               std::string(S.Ids().NameKeyText(Match.Name2));
        if (!Dones.insert(std::move(MatchKey)).second) {
          continue;
        }
        // D:3173-3174 itemize_for_chooser + get_row_for_items: CChooser.Item takes int() of the item's
        // node counts (always ints here, D:244-245), then the rows are fetched BY NAME, main first
        // (D:2998-2999).
        const std::optional<uint32_t> MainRow = GetFunctionRow(S, Match.Name1, Side::Main);
        const std::optional<uint32_t> DiffRow = GetFunctionRow(S, Match.Name2, Side::Diff);
        if (!MainRow || !DiffRow) {  // D:3175
          continue;
        }
        if (FieldColumn(S.Main().Functions, Which).Null(*MainRow)) {  // D:3176-3177 (None only; "" goes on)
          continue;
        }
        if (FieldColumn(S.Diff().Functions, Which).Null(*DiffRow)) {  // D:3178-3179
          continue;
        }
        FindOneMatchDiffing(S, Outer, *MainRow, *DiffRow, Which, Heur, Inner, Dones);  // D:3181-3183
      }
    }
    S.Cleanup(CleanupSite::L3185);  // D:3185
    LogShowSummary(S);              // D:3186 show_summary()
    const size_t NewTotal = S.State().TotalMatchedFunctions();  // D:3188
    if (NewTotal == OldTotal) {  // D:3189-3190: equality, not <=
      break;
    }
    // D:3192 log(f"New iteration with heuristic '{heur}'..."): log only.
    ++Inner;  // D:3193
  }
}

}  // namespace

void StageFindMatchesDiffing(DiffSession& S, int Iteration) {
  S.Cleanup(CleanupSite::L3217);  // D:3216-3217: "First, remove duplicates, etc... just to be sure"
  // D:3220-3224: assembly only when both program.processor values match (D:3617). call_hook
  // ("on_special_heuristic", True, ...) returns its default True: no hook is loaded outside patch-diff mode,
  // and scripts/patch_diff_vulns.py defines no on_special_heuristic (D:1450-1459).
  if (S.Flags().IsSameProcessor) {
    FindMatchesDiffingInternal(S, Iteration, kHeurAssembly, Field::Assembly);  // D:3195-3201
  }
  // D:3226-3229: pseudo-code always runs, after assembly.
  FindMatchesDiffingInternal(S, Iteration, kHeurPseudo, Field::Pseudocode);  // D:3203-3209
}

}
