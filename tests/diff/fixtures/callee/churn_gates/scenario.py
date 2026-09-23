# Scenario "churn_gates": the candidate gates of D:3067-3110 and the re-discovery churn of 06 §6.7.
# Synthetic data only. Regenerate with
#   python -B tests/diff/fixtures/callee/gen_callee_fixtures.py --diaphora-dir <diaphora-ref> --only churn_gates
#
# The seed hub_fn (same name, identical assembly) has a pseudo-code diff in which every changed line is a
# one-line replace followed by context, so each flushes on its own and yields one candidate pair:
#   same_exact(v1)  -> same_exact(v2)    same name, identical functions: already a 1.0 best match, so the
#                                         callee item (best, 1.0) is appended as churn and removed again by
#                                         the next cleanup (06 §6.7);
#   same_changed(v1)-> same_changed(v2)  same name, different bodies: add_match fakes 1.0 for equal names
#                                         and appends the partial item next to the existing same-name one;
#   gate_small_a    -> gate_small_b      nodes 2 / 2: below DIFFING_MATCHES_MIN_BBLOCKS (C:183 = 3);
#   gate_pct_a      -> gate_pct_b        nodes 3 / 13: 300 / 13 = 23.08 < 25 (C:177);
#   gate_edge_a     -> gate_edge_b       nodes 4 / 16: exactly 25.0, which passes (strict <);
#   nullsub_1a      -> nullsub_2b        the nullsub filter (D:3072);
#   nullsubx_a      -> nullsubx_b        the prefix has no underscore, so this is filtered too.
# Two more seeds: nopseudo_fn (NULL pseudocode on the diff side: skipped by the pseudo-code pass after its
# key entered dones, D:3171-3179) and emptypseudo_fn ("" pseudocode on both sides: processed, D:3176 only
# skips None, but splitlines("") is [] and the diff is empty).

import hashlib
import json

NL = chr(10)
BODY_CTX = ["  int v1;", "  int v2;", "  v1 = 1;", "  v2 = 2;"]
BODY_TAIL = ["  v1 += v2;", "  v2 -= 3;", "  v1 ^= v2;", "  return v1;"]


def Callee(Leaf):
    return NL.join(BODY_CTX + ["  %s(v1);" % Leaf] + BODY_TAIL)


def Asm(K, Extra):
    return NL.join(["mov eax, %d" % K, "add eax, %d" % (K + 1), "xor ebx, %d" % Extra, "push ebp", "mov ebp, esp",
                    "pop ebp", "retn"])


def Md5(Text):
    return hashlib.md5(Text.encode()).hexdigest()


def Mk(Id, Name, Addr, K, AsmText, PseudoText, Nodes=5, Bh=None):
    return Function(Id, Name, Addr, Nodes, AsmText, PseudoText,  # noqa: F821 (predefined)
                    edges=Nodes + K % 3, indegree=1, outdegree=1, size=40 + K,
                    instructions=len(AsmText.split(NL)), mnemonics=json.dumps(["mov"] * 3), names="[]",
                    prototype="int f()", cyclomatic_complexity=2 + K, primes_value=str(1009 + K * 2), comment=None,
                    mangled_function=Name, bytes_hash=Bh or Md5("b" + str(K)),
                    pseudocode_lines=0 if PseudoText is None else len(PseudoText.split(NL)),
                    pseudocode_hash1="h1" + str(K),
                    pseudocode_primes=str(3000 + K), function_flags=0, prototype2="int()",
                    pseudocode_hash2="h2" + str(K), pseudocode_hash3="h3" + str(K), strongly_connected=1, loops=0,
                    rva=str(Addr), tarjan_topological_sort="[]", strongly_connected_spp=str(K + 11),
                    clean_assembly=AsmText, clean_pseudo=PseudoText, mnemonics_spp=str(5000 + K), switches="[]",
                    function_hash=Md5("f" + str(K)), bytes_sum=K, md_index=str(1.5 + K / 10), constants="[]",
                    constants_count=0, segment_rva=str(Addr), assembly_addrs="[]", kgh_hash=str(7000 + K),
                    source_file=None, userdata=None, microcode=None, clean_microcode=None, microcode_spp=None,
                    export_time=0.0)


CALLS = [("same_exact", "same_exact"), ("same_changed", "same_changed"), ("gate_small_a", "gate_small_b"),
         ("gate_pct_a", "gate_pct_b"), ("gate_edge_a", "gate_edge_b"), ("nullsub_1a", "nullsub_2b"),
         ("nullsubx_a", "nullsubx_b")]


def Hub(Side):
    Lines = ["  int v1 = 0;", "  int v2 = 1;"]
    for Index, Pair in enumerate(CALLS):
        Lines.append("  %s(%s);" % (Pair[Side], "v1" if Side == 0 else "v2"))
        Lines.extend(["  c%02d = %d;" % (Index * 2, Index), "  c%02d = %d;" % (Index * 2 + 1, Index)])
    Lines.append("  return v1;")
    return NL.join(Lines)


HUB_ASM = Asm(1, 1)
SAME_EXACT_ASM = Asm(30, 30)
SAME_EXACT_PSEUDO = Callee("leaf_exact")

PROGRAM_MAIN = {"callgraph_primes": "6", "callgraph_all_primes": json.dumps({"2": 1, "3": 1}), "md5sum": "g1"}
PROGRAM_DIFF = {"callgraph_primes": "10", "callgraph_all_primes": json.dumps({"2": 1, "3": 1}), "md5sum": "g2"}

MAIN = {
    "functions": [
        Mk(1, "hub_fn", 0x1000, 1, HUB_ASM, Hub(0), Nodes=12, Bh="hub"),
        Mk(2, "same_exact", 0x2000, 30, SAME_EXACT_ASM, SAME_EXACT_PSEUDO, Nodes=5, Bh="exact"),
        Mk(3, "same_changed", 0x3000, 3, Asm(3, 3), Callee("leaf_changed_a")),
        Mk(4, "gate_small_a", 0x4000, 4, Asm(4, 4), Callee("leaf_small_a"), Nodes=2),
        Mk(5, "gate_pct_a", 0x5000, 5, Asm(5, 5), Callee("leaf_pct_a"), Nodes=3),
        Mk(6, "gate_edge_a", 0x6000, 6, Asm(6, 6), Callee("leaf_edge_a"), Nodes=4),
        Mk(7, "nullsub_1a", 0x7000, 7, Asm(7, 7), Callee("leaf_null_a")),
        Mk(8, "nullsubx_a", 0x8000, 8, Asm(8, 8), Callee("leaf_nullx_a")),
        Mk(9, "nopseudo_fn", 0x9000, 9, Asm(9, 9), Callee("leaf_nopseudo")),
        Mk(10, "emptypseudo_fn", 0xA000, 10, Asm(10, 10), ""),
    ],
    "program": PROGRAM_MAIN,
}

DIFF = {
    "functions": [
        Mk(1, "hub_fn", 0x1100, 1, HUB_ASM, Hub(1), Nodes=12, Bh="hub"),
        Mk(2, "same_exact", 0x2100, 30, SAME_EXACT_ASM, SAME_EXACT_PSEUDO, Nodes=5, Bh="exact"),
        Mk(3, "same_changed", 0x3100, 13, Asm(3, 9), Callee("leaf_changed_b"), Nodes=6),
        Mk(4, "gate_small_b", 0x4100, 14, Asm(4, 9), Callee("leaf_small_b"), Nodes=2),
        Mk(5, "gate_pct_b", 0x5100, 15, Asm(5, 9), Callee("leaf_pct_b"), Nodes=13),
        Mk(6, "gate_edge_b", 0x6100, 16, Asm(6, 9), Callee("leaf_edge_b"), Nodes=16),
        Mk(7, "nullsub_2b", 0x7100, 17, Asm(7, 9), Callee("leaf_null_b"), Nodes=6),
        Mk(8, "nullsubx_b", 0x8100, 18, Asm(8, 9), Callee("leaf_nullx_b"), Nodes=6),
        Mk(9, "nopseudo_fn", 0x9100, 19, Asm(9, 9), None),
        Mk(10, "emptypseudo_fn", 0xA100, 20, Asm(10, 10), ""),
    ],
    "program": PROGRAM_DIFF,
}
