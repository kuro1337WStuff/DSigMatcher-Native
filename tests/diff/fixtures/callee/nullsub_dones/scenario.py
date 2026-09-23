# Scenario "nullsub_dones": the order of the dones test and the nullsub filter in find_one_match_diffing
# (D:3067-3074). Synthetic data only. Regenerate with
#   python -B tests/diff/fixtures/callee/gen_callee_fixtures.py --diaphora-dir <diaphora-ref> --only nullsub_dones --no-walk
#
# Diaphora adds a candidate's key "<name1>-<name2>" to `dones` BEFORE it drops a nullsub pair, and the walk
# over the matches (D:3167-3171) uses the same set for the key "<match name1>-<match name2>". So:
#   hub_fn -> hub_fn        "100% equal" (find_equal_matches: same id, address, name, nodes, edges, size and
#                           bytes hash; pseudo-code is not compared), id 1, so it is walked first. One changed
#                           pseudo-code line calls nullsub_7 on both sides: the candidate (nullsub_7,
#                           nullsub_7) puts "nullsub_7-nullsub_7" into dones and is then dropped by the
#                           nullsub filter;
#   nullsub_7 -> nullsub_7  "100% equal" too (find_equal_matches has no nullsub filter; find_same_name has
#                           one, D:2166), id 2, walked second: its key is already in dones, so its own
#                           pseudo-code diff (leaf_old_fn -> leaf_new_fn) is never walked, and that similar
#                           pair stays unmatched. Were the nullsub filter applied first, nullsub_7 would be
#                           walked (one more find_one_match_diffing call) and the leaf pair found.
# The assembly pass has its own dones and walks both seeds; their assembly is identical, so it finds nothing.

import hashlib
import json

NL = chr(10)
CTX = ["  int v1;", "  int v2;", "  v1 = 1;", "  v2 = 2;"]
TAIL = ["  v1 += v2;", "  v2 -= 3;", "  v1 ^= v2;", "  return v1;"]


def Pseudo(Call, Arg="v1"):
    return NL.join(CTX + ["  %s(%s);" % (Call, Arg)] + TAIL)


def Asm(K, Extra):
    # Only the "xor ebx" line differs between sides; no token on it matches CPP_NAMES_RE (4+ characters).
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
                    pseudocode_lines=len(PseudoText.split(NL)), pseudocode_hash1="h1" + str(K),
                    pseudocode_primes=str(3000 + K), function_flags=0, prototype2="int()",
                    pseudocode_hash2="h2" + str(K), pseudocode_hash3="h3" + str(K), strongly_connected=1, loops=0,
                    rva=str(Addr), tarjan_topological_sort="[]", strongly_connected_spp=str(K + 11),
                    clean_assembly=AsmText, clean_pseudo=PseudoText, mnemonics_spp=str(5000 + K), switches="[]",
                    function_hash=Md5("f" + str(K)), bytes_sum=K, md_index=str(1.5 + K / 10), constants="[]",
                    constants_count=0, segment_rva=str(Addr), assembly_addrs="[]", kgh_hash=str(7000 + K),
                    source_file=None, userdata=None, microcode=None, clean_microcode=None, microcode_spp=None,
                    export_time=0.0)


HUB_ASM = Asm(1, 1)
NULLSUB_ASM = Asm(2, 2)

PROGRAM_MAIN = {"callgraph_primes": "6", "callgraph_all_primes": json.dumps({"2": 1, "3": 1}), "md5sum": "n1"}
PROGRAM_DIFF = {"callgraph_primes": "10", "callgraph_all_primes": json.dumps({"2": 1, "3": 1}), "md5sum": "n2"}

MAIN = {
    "functions": [
        Mk(1, "hub_fn", 0x1000, 1, HUB_ASM, Pseudo("nullsub_7", "v1"), Nodes=12, Bh="hub"),
        Mk(2, "nullsub_7", 0x2000, 2, NULLSUB_ASM, Pseudo("leaf_old_fn"), Bh="nullsub"),
        Mk(3, "leaf_old_fn", 0x3000, 3, Asm(3, 3), Pseudo("inner_a")),
    ],
    "program": PROGRAM_MAIN,
}

DIFF = {
    "functions": [
        Mk(1, "hub_fn", 0x1000, 1, HUB_ASM, Pseudo("nullsub_7", "v2"), Nodes=12, Bh="hub"),
        Mk(2, "nullsub_7", 0x2000, 2, NULLSUB_ASM, Pseudo("leaf_new_fn"), Bh="nullsub"),
        Mk(3, "leaf_new_fn", 0x3100, 13, Asm(3, 9), Pseudo("inner_b"), Nodes=6),
    ],
    "program": PROGRAM_DIFF,
}
