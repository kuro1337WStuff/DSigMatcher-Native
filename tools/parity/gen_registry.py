#!/usr/bin/env python3
"""Generate the verbatim Diaphora SQL used by the parity engine.

Outputs (paths relative to the repository root):

  src/diff/RegistrySql.inc                  the 50 HEURISTICS entries (name, category, ratio type,
                                            min, flags, source lines, verbatim final `sql`)
  src/diff/StageSql.inc                     the non-registry stage SQL of docs/parity/00-plan.md
                                            Appendix A, rendered exactly as diaphora.py builds it
  tests/diff/generated/registry_expected.inc  counts and the sha256 of every SQL string

Sources are imported or parsed READ-ONLY from an unmodified Diaphora checkout:

  * diaphora_heuristics.py is imported (it only imports pprint and collections) with
    sys.dont_write_bytecode set, so no __pycache__ is written;
  * diaphora.py is NOT imported (it pulls in IDA/ML modules). It is parsed with `ast`, and each
    stage SQL expression is located inside the cited CBinDiff method, checked to lie inside the
    cited D: line range, and evaluated with the same inputs Python gives it (get_query_fields comes
    from the imported diaphora_heuristics).

Strings are emitted as escaped, line-split C++ literals (not raw literals) so the embedded bytes do
not depend on git's end-of-line conversion of the generated files.

Usage:
  python -B tools/parity/gen_registry.py --diaphora-dir <diaphora-ref> [--check]
The Diaphora directory can also come from the DSIG_DIAPHORA_DIR environment variable.
"""

import argparse
import ast
import hashlib
import importlib
import os
import subprocess
import sys

sys.dont_write_bytecode = True

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

CATEGORY = {"Best": "Best", "Partial": "Partial", "Unreliable": "Unreliable", "Experimental": "Experimental"}
RATIO = {0: "NoFps", 1: "Ratio", 2: "RatioMax", 3: "RatioMaxTrusted"}


def c_literal(text):
    """Escaped C++ literal pieces, one per source line, byte exact for UTF-8 `text`."""
    data = text.encode("utf-8")
    pieces = []
    current = []
    for byte in data:
        ch = chr(byte)
        if ch == "\\":
            current.append("\\\\")
        elif ch == '"':
            current.append('\\"')
        elif ch == "\n":
            current.append("\\n")
            pieces.append("".join(current))
            current = []
        elif ch == "\t":
            current.append("\\t")
        elif ch == "\r":
            current.append("\\r")
        elif ch == "?":
            # avoid trigraph-looking sequences in any compiler mode
            current.append("\\?")
        elif 0x20 <= byte < 0x7F:
            current.append(ch)
        else:
            current.append("\\%03o" % byte)
    if current or not pieces:
        pieces.append("".join(current))
    return pieces


def emit_literal(text, indent="    "):
    return "\n".join(indent + '"' + piece + '"' for piece in c_literal(text))


def sha256_hex(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def git_describe(path):
    try:
        out = subprocess.run(["git", "-C", path, "describe", "--tags", "--always", "--dirty"],
                             capture_output=True, text=True, check=True)
        return out.stdout.strip()
    except Exception:  # noqa: BLE001 - informational only
        return "unknown"


# ---------------------------------------------------------------------------------------------
# HEURISTICS (diaphora_heuristics.py)

def load_heuristics(diaphora_dir):
    sys.path.insert(0, diaphora_dir)
    try:
        module = importlib.import_module("diaphora_heuristics")
    finally:
        sys.path.pop(0)
    path = os.path.join(diaphora_dir, "diaphora_heuristics.py")
    with open(path, "r", encoding="utf-8") as handle:
        tree = ast.parse(handle.read(), filename=path)
    spans = []
    name_line = None
    for node in tree.body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == "NAME"):
            name_line = node.lineno
            continue
        if (isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Attribute)
                and node.value.func.attr == "append"
                and isinstance(node.value.func.value, ast.Name)
                and node.value.func.value.id == "HEURISTICS"):
            # cite from the `NAME = ...` line that names this entry (H:89-107 for index 0)
            first = name_line if name_line is not None else node.lineno
            spans.append((first, node.end_lineno))
            name_line = None
    if len(spans) != len(module.HEURISTICS):
        raise SystemExit(f"found {len(spans)} HEURISTICS.append calls but {len(module.HEURISTICS)} entries")
    return module, spans


# ---------------------------------------------------------------------------------------------
# Stage SQL (diaphora.py, parsed only)

class DiaphoraSource:
    def __init__(self, diaphora_dir):
        path = os.path.join(diaphora_dir, "diaphora.py")
        with open(path, "r", encoding="utf-8") as handle:
            self.text = handle.read()
        self.lines = self.text.split("\n")
        self.tree = ast.parse(self.text, filename=path)
        self.methods = {}
        for node in ast.walk(self.tree):
            if isinstance(node, ast.ClassDef) and node.name == "CBinDiff":
                for item in node.body:
                    if isinstance(item, ast.FunctionDef):
                        self.methods[item.name] = item

    @staticmethod
    def check_literals(method, node, first, last):
        """Every string literal of the expression must sit inside the cited D: lines."""
        count = 0
        for sub in ast.walk(node):
            if isinstance(sub, ast.Constant) and isinstance(sub.value, str) or isinstance(sub, ast.JoinedStr):
                count += 1
                if sub.lineno < first or sub.end_lineno > last:
                    raise SystemExit(f"{method}: literal at D:{sub.lineno}-{sub.end_lineno} is outside the cited "
                                     f"D:{first}-{last}")
        if count == 0:
            raise SystemExit(f"{method}: no string literal found in D:{first}-{last}")

    def assignment(self, method, target, first, last, aug=False):
        """The single (Aug)Assign to `target` in `method` that starts within D:first..last; its string
        literals must lie within the same lines (the statement's closing parenthesis may follow)."""
        found = []
        for node in ast.walk(self.methods[method]):
            if aug and isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name) \
                    and node.target.id == target:
                found.append(node)
            if not aug and isinstance(node, ast.Assign) and len(node.targets) == 1 \
                    and isinstance(node.targets[0], ast.Name) and node.targets[0].id == target:
                found.append(node)
        found = [n for n in found if first <= n.lineno <= last]
        if len(found) != 1:
            raise SystemExit(f"{method}: expected one assignment to '{target}' in D:{first}-{last}, got {len(found)}")
        self.check_literals(method, found[0].value, first, last)
        return found[0]

    def call_argument(self, method, first, last):
        """The first positional argument of the single cur.execute(...) call within lines first..last."""
        found = []
        for node in ast.walk(self.methods[method]):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                    and node.func.attr == "execute" and node.args:
                if node.lineno >= first and node.end_lineno <= last:
                    found.append(node)
        if len(found) != 1:
            raise SystemExit(f"{method}: expected one execute() call in D:{first}-{last}, got {len(found)}")
        self.check_literals(method, found[0].args[0], first, last)
        return found[0].args[0]

    @staticmethod
    def evaluate(node, namespace):
        expression = ast.Expression(body=node)
        ast.fix_missing_locations(expression)
        return eval(compile(expression, "<diaphora.py>", "eval"), dict(namespace))  # noqa: S307


def build_stage_sql(src, heuristics_module):
    gqf = heuristics_module.get_query_fields
    ns = {"get_query_fields": gqf}
    stages = []

    def add(name, value, method, first, last, binds, note):
        stages.append({"name": name, "sql": value, "method": method, "first": first, "last": last,
                       "binds": binds, "note": note})

    # D:3578 select value from diff.version
    node = src.call_argument("diff", 3578, 3578)
    add("kSqlVersion", src.evaluate(node, ns), "diff", 3578, 3578, 0, "diff() version check")

    # D:668 and D:673-680 equal_db
    node = src.assignment("equal_db", "sql", 668, 668)
    add("kSqlEqualDbMd5", src.evaluate(node.value, ns), "equal_db", 668, 668, 0, "equal_db md5 count")
    node = src.assignment("equal_db", "sql", 673, 680)
    add("kSqlEqualDbExcept", src.evaluate(node.value, ns), "equal_db", 673, 680, 0, "equal_db except count")

    # D:1294-1296 get_callgraph_difference
    node = src.assignment("get_callgraph_difference", "sql", 1294, 1296)
    add("kSqlCallgraph", src.evaluate(node.value, ns), "get_callgraph_difference", 1294, 1296, 0,
        "check_callgraph program rows (union all)")

    # D:1411-1413 and D:1424-1430 find_equal_matches
    node = src.assignment("find_equal_matches", "sql", 1411, 1413)
    add("kSqlTotals", src.evaluate(node.value, ns), "find_equal_matches", 1411, 1413, 0, "function totals")
    fields_node = src.assignment("find_equal_matches", "fields", 1424, 1424)
    fields = src.evaluate(fields_node.value, ns)
    node = src.assignment("find_equal_matches", "sql", 1425, 1430)
    add("kSqlEqualMatches", src.evaluate(node.value, dict(ns, fields=fields)), "find_equal_matches", 1424, 1430,
        0, "100% equal INTERSECT")

    # D:2957-2960 same_processor_both_databases
    node = src.assignment("same_processor_both_databases", "sql", 2957, 2960)
    add("kSqlSameProcessor", src.evaluate(node.value, ns), "same_processor_both_databases", 2957, 2960, 0,
        "same processor")

    # D:2551-2554, D:2569-2577 search_just_stripped_binaries
    node = src.assignment("search_just_stripped_binaries", "sql", 2551, 2554)
    add("kSqlStrippedCount", src.evaluate(node.value, ns), "search_just_stripped_binaries", 2551, 2554, 0,
        "stripped-binaries address join count")
    node = src.assignment("search_just_stripped_binaries", "sql", 2569, 2577)
    add("kSqlStrippedRows", src.evaluate(node.value, dict(ns, heur="Same binary with symbols stripped")),
        "search_just_stripped_binaries", 2568, 2577, 0, "stripped-binaries rows (heur bound at D:2568)")

    # D:2599-2603 search_patchdiff_with_symbols
    node = src.assignment("search_patchdiff_with_symbols", "sql", 2599, 2603)
    add("kSqlPatchCount", src.evaluate(node.value, ns), "search_patchdiff_with_symbols", 2599, 2603, 0,
        "patch-diff mangled-name join count")

    # D:2158-2166 find_same_name
    node = src.assignment("find_same_name", "sql", 2158, 2166)
    add("kSqlSameName", src.evaluate(node.value, dict(ns, desc="Perfect match, same name")), "find_same_name",
        2157, 2166, 0, "same name (desc bound at D:2157)")

    # D:2093-2106 search_small_differences
    node = src.assignment("search_small_differences", "sql", 2093, 2106)
    add("kSqlSmallDifferences",
        src.evaluate(node.value, dict(ns, name="Nodes, edges, complexity and mnemonics with small differences")),
        "search_small_differences", 2092, 2106, 0, "small differences (name bound at D:2092)")

    # D:2647-2650 get_unmatched_functions
    node = src.assignment("get_unmatched_functions", "sql", 2647, 2650)
    add("kSqlUnmatchedUnion", src.evaluate(node.value, ns), "get_unmatched_functions", 2647, 2650, 0,
        "unmatched UNION")

    # D:2675-2685 search_remaining_functions (values["small"] is False -> the += at 2685 applies)
    node = src.assignment("search_remaining_functions", "sql", 2675, 2683)
    base = src.evaluate(node.value, ns)
    aug = src.assignment("search_remaining_functions", "sql", 2685, 2685, aug=True)
    add("kSqlRemainingPair", base + src.evaluate(aug.value, ns), "search_remaining_functions", 2675, 2685, 3,
        "remaining pair: binds (heur text, ea1 text, ea2 text); nodes >= 3 suffix because small=False (D:2684)")

    # D:2330, D:2343 find_unmatched
    node = src.assignment("find_unmatched", "sql", 2330, 2330)
    add("kSqlUnmatchedMain", src.evaluate(node.value, ns), "find_unmatched", 2330, 2330, 0, "unmatched main")
    node = src.assignment("find_unmatched", "sql", 2343, 2343)
    add("kSqlUnmatchedDiff", src.evaluate(node.value, ns), "find_unmatched", 2343, 2343, 0, "unmatched diff")

    # D:2453 get_function_row (f-string with db_name)
    node = src.assignment("get_function_row", "sql", 2453, 2453)
    add("kSqlFunctionRowMain", src.evaluate(node.value, dict(ns, db_name="main")), "get_function_row", 2453, 2453,
        1, "function row by name (bind name text)")
    add("kSqlFunctionRowDiff", src.evaluate(node.value, dict(ns, db_name="diff")), "get_function_row", 2453, 2453,
        1, "function row by name (bind name text)")

    # D:2976-2988 functions_exists
    node = src.assignment("functions_exists", "sql", 2976, 2988)
    add("kSqlFunctionsExists", src.evaluate(node.value, ns), "functions_exists", 2976, 2988, 2,
        "functions_exists (binds name1 text, name2 text)")

    # D:3236-3240 find_functions_between (sql.format(db=...) at D:3245 / D:3252)
    node = src.assignment("find_functions_between", "sql", 3236, 3240)
    template = src.evaluate(node.value, ns)
    add("kSqlGapMain", template.format(db="main"), "find_functions_between", 3236, 3240, 2,
        "gap rows main (binds ea texts; .format(db='main'))")
    add("kSqlGapDiff", template.format(db="diff"), "find_functions_between", 3236, 3240, 2,
        "gap rows diff (binds ea texts; .format(db='diff'))")

    # D:3375-3387 find_related_constants
    node = src.assignment("find_related_constants", "sql", 3375, 3388)
    add("kSqlRelatedConstants", src.evaluate(node.value, dict(ns, heur="Same constants related matches")),
        "find_related_constants", 3367, 3388, 1, "related constants (bind str(constant) text; heur at D:3367)")

    # D:3419-3427 find_related_compilation_unit CU lookup (sql.replace("{db}", ...))
    node = src.assignment("find_related_compilation_unit", "sql", 3419, 3425)
    template = src.evaluate(node.value, ns)
    add("kSqlCuLookupMain", template.replace("{db}", "main"), "find_related_compilation_unit", 3419, 3427, 1,
        "CU lookup main (bind name text)")
    add("kSqlCuLookupDiff", template.replace("{db}", "diff"), "find_related_compilation_unit", 3419, 3427, 1,
        "CU lookup diff (bind name text)")

    # D:3429-3433 find_related_compilation_unit cartesian
    heur_node = src.assignment("find_related_compilation_unit", "heur", 3395, 3416)
    heur = src.evaluate(heur_node.value, ns)
    node = src.assignment("find_related_compilation_unit", "sql", 3429, 3433)
    add("kSqlCuCartesian", src.evaluate(node.value, dict(ns, heur=heur)), "find_related_compilation_unit",
        heur_node.lineno, 3433, 4, "related CU cartesian (binds 4 Python floats as REAL)")
    return stages


# ---------------------------------------------------------------------------------------------

def render_registry(module, spans, describe):
    out = []
    out.append("// Generated by tools/parity/gen_registry.py from diaphora_heuristics.py")
    out.append(f"// (Diaphora {describe}). Do not edit by hand; re-run the generator.")
    out.append("// Each entry: {Id, Name, Category, RatioType, Min, HasMin, FlagUnreliable, FlagSlow, FlagSameCpu,")
    out.append("//              FlagsRepr, SourceLineBegin, SourceLineEnd, SqlSha256, Sql}")
    out.append("// clang-format off")
    for index, heur in enumerate(module.HEURISTICS):
        flags = list(heur["flags"])
        has_min = "min" in heur
        min_value = float(heur["min"]) if has_min else 0.0
        first, last = spans[index]
        out.append(f"// H:{first}-{last}")
        out.append("{")
        out.append(f"    {index},")
        out.append(emit_literal(heur["name"]) + ",")
        out.append(f"    HeurCategory::{CATEGORY[heur['category']]},")
        out.append(f"    HeurType::{RATIO[heur['ratio']]},")
        out.append(f"    {repr(min_value)},")
        out.append(f"    {'true' if has_min else 'false'},")
        out.append(f"    {'true' if module.HEUR_FLAG_UNRELIABLE in flags else 'false'},")
        out.append(f"    {'true' if module.HEUR_FLAG_SLOW in flags else 'false'},")
        out.append(f"    {'true' if module.HEUR_FLAG_SAME_CPU in flags else 'false'},")
        out.append(emit_literal(repr(flags)) + ",")
        out.append(f"    {first},")
        out.append(f"    {last},")
        out.append(f'    "{sha256_hex(heur["sql"])}",')
        out.append(emit_literal(heur["sql"]))
        out.append("},")
    out.append("// clang-format on")
    return "\n".join(out) + "\n"


def render_stage_sql(stages, describe):
    out = []
    out.append("// Generated by tools/parity/gen_registry.py from diaphora.py (parsed with ast, never imported)")
    out.append(f"// and diaphora_heuristics.get_query_fields (Diaphora {describe}). Do not edit by hand.")
    out.append("// Each entry: {Name, Method, LineBegin, LineEnd, BindCount, SqlSha256, Sql}")
    out.append("// clang-format off")
    for stage in stages:
        out.append(f"// D:{stage['first']}-{stage['last']} CBinDiff.{stage['method']}: {stage['note']}")
        out.append("{")
        out.append(f'    "{stage["name"]}",')
        out.append(f'    "{stage["method"]}",')
        out.append(f"    {stage['first']},")
        out.append(f"    {stage['last']},")
        out.append(f"    {stage['binds']},")
        out.append(f'    "{sha256_hex(stage["sql"])}",')
        out.append(emit_literal(stage["sql"]))
        out.append("},")
    out.append("// clang-format on")
    return "\n".join(out) + "\n"


def render_expected(module, stages, describe):
    heuristics = module.HEURISTICS
    cats = {"Best": 0, "Partial": 0, "Unreliable": 0, "Experimental": 0}
    types = {0: 0, 1: 0, 2: 0, 3: 0}
    for heur in heuristics:
        cats[heur["category"]] += 1
        types[heur["ratio"]] += 1
    postfix_h10 = heuristics[10]["sql"].count("%POSTFIX%")
    out = []
    out.append("// Generated by tools/parity/gen_registry.py (Diaphora " + describe + "). Do not edit by hand.")
    out.append("// clang-format off")
    out.append(f"#define DSIG_EXPECTED_HEURISTIC_COUNT {len(heuristics)}")
    out.append(f"#define DSIG_EXPECTED_BEST {cats['Best']}")
    out.append(f"#define DSIG_EXPECTED_PARTIAL {cats['Partial']}")
    out.append(f"#define DSIG_EXPECTED_UNRELIABLE {cats['Unreliable']}")
    out.append(f"#define DSIG_EXPECTED_EXPERIMENTAL {cats['Experimental']}")
    out.append(f"#define DSIG_EXPECTED_NOFPS {types[0]}")
    out.append(f"#define DSIG_EXPECTED_RATIO {types[1]}")
    out.append(f"#define DSIG_EXPECTED_RATIOMAX {types[2]}")
    out.append(f"#define DSIG_EXPECTED_TRUSTED {types[3]}")
    out.append(f"#define DSIG_EXPECTED_H10_POSTFIX_TOKENS {postfix_h10}")
    out.append(f"#define DSIG_EXPECTED_STAGE_SQL_COUNT {len(stages)}")
    out.append("struct ExpectedHeuristicSql { int Id; const char* Sha256; unsigned Length; };")
    out.append("static const ExpectedHeuristicSql kExpectedHeuristicSql[] = {")
    for index, heur in enumerate(heuristics):
        out.append(f'  {{{index}, "{sha256_hex(heur["sql"])}", {len(heur["sql"].encode("utf-8"))}u}},')
    out.append("};")
    out.append("struct ExpectedStageSql { const char* Name; const char* Sha256; unsigned Length; };")
    out.append("static const ExpectedStageSql kExpectedStageSql[] = {")
    for stage in stages:
        out.append(f'  {{"{stage["name"]}", "{sha256_hex(stage["sql"])}", {len(stage["sql"].encode("utf-8"))}u}},')
    out.append("};")
    out.append("// clang-format on")
    return "\n".join(out) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--diaphora-dir", default=os.environ.get("DSIG_DIAPHORA_DIR"),
                        help="unmodified Diaphora checkout (default: $DSIG_DIAPHORA_DIR)")
    parser.add_argument("--repo", default=REPO, help="repository root (default: this script's repo)")
    parser.add_argument("--check", action="store_true", help="fail if the generated files are out of date")
    args = parser.parse_args()
    if not args.diaphora_dir:
        parser.error("--diaphora-dir (or DSIG_DIAPHORA_DIR) is required")

    module, spans = load_heuristics(args.diaphora_dir)
    src = DiaphoraSource(args.diaphora_dir)
    stages = build_stage_sql(src, module)
    describe = git_describe(args.diaphora_dir)

    longest = max(len(h["sql"].encode("utf-8")) for h in module.HEURISTICS)
    outputs = {
        os.path.join(args.repo, "src", "diff", "RegistrySql.inc"): render_registry(module, spans, describe),
        os.path.join(args.repo, "src", "diff", "StageSql.inc"): render_stage_sql(stages, describe),
        os.path.join(args.repo, "tests", "diff", "generated", "registry_expected.inc"):
            render_expected(module, stages, describe),
    }
    stale = []
    for path, content in outputs.items():
        if args.check:
            try:
                with open(path, "r", encoding="utf-8", newline="") as handle:
                    current = handle.read().replace("\r\n", "\n")
            except FileNotFoundError:
                current = None
            if current != content:
                stale.append(path)
        else:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(content)
            print(f"wrote {os.path.relpath(path, args.repo)}")
    print(f"{len(module.HEURISTICS)} heuristics (longest sql {longest} bytes), {len(stages)} stage queries, "
          f"Diaphora {describe}")
    if stale:
        for path in stale:
            print(f"STALE: {os.path.relpath(path, args.repo)}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
