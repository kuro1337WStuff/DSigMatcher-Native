# Scenario "exp_z": 03b §4.3.4 experiment Z (spec scratch v03b/expZ.py + build.py), rebuilt in the
# tools/parity/make_fixture.py format. Synthetic data only. Regenerate with
#   python -B tests/diff/fixtures/callee/gen_callee_fixtures.py --diaphora-dir <diaphora-ref> --only exp_z
#
# The data of exp_a, except that alpha_old_callee and beta_new_callee both have nodes = 0. When the
# pseudo-code pass pairs them, (min_nodes * 100) / max_nodes (D:3088-3089) divides by zero before the
# DIFFING_MATCHES_MIN_BBLOCKS checks; nothing catches the ZeroDivisionError up to __main__ (D:3772), so
# Diaphora writes no .diaphora file (the native engine: DiaphoraWouldRaise, exit 3).

import hashlib
import json

NL = chr(10)
CTX = ["  int v1;", "  int v2;", "  v1 = 1;", "  v2 = 2;"]
TAIL = ["  v1 += v2;", "  v2 -= 3;", "  v1 ^= v2;", "  return v1;"]


def Pseudo(Call):
    return NL.join(CTX + ["  %s(v1);" % Call] + TAIL)


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
                    pseudocode_lines=len(PseudoText.split(NL)), pseudocode_hash1="h1" + str(K),
                    pseudocode_primes=str(3000 + K), function_flags=0, prototype2="int()",
                    pseudocode_hash2="h2" + str(K), pseudocode_hash3="h3" + str(K), strongly_connected=1, loops=0,
                    rva=str(Addr), tarjan_topological_sort="[]", strongly_connected_spp=str(K + 11),
                    clean_assembly=AsmText, clean_pseudo=PseudoText, mnemonics_spp=str(5000 + K), switches="[]",
                    function_hash=Md5("f" + str(K)), bytes_sum=K, md_index=str(1.5 + K / 10), constants="[]",
                    constants_count=0, segment_rva=str(Addr), assembly_addrs="[]", kgh_hash=str(7000 + K),
                    source_file=None, userdata=None, microcode=None, clean_microcode=None, microcode_spp=None,
                    export_time=0.0)


PROGRAM_MAIN = {"callgraph_primes": "6", "callgraph_all_primes": json.dumps({"2": 1, "3": 1}), "md5sum": "x1"}
PROGRAM_DIFF = {"callgraph_primes": "10", "callgraph_all_primes": json.dumps({"2": 1, "3": 1}), "md5sum": "x2"}

MAIN = {
    "functions": [
        Mk(1, "caller_fn", 0x1000, 1, Asm(1, 1), Pseudo("alpha_old_callee"), Bh="same"),
        Mk(2, "alpha_old_callee", 0x2000, 2, Asm(2, 2), Pseudo("gamma_old_leaf"), Nodes=0),
        Mk(3, "gamma_old_leaf", 0x3000, 3, Asm(3, 3), NL.join(CTX + ["  v9 = 7;"] + TAIL)),
    ],
    "program": PROGRAM_MAIN,
}

DIFF = {
    "functions": [
        Mk(1, "caller_fn", 0x1100, 1, Asm(1, 1), Pseudo("beta_new_callee"), Bh="same"),
        Mk(2, "beta_new_callee", 0x2100, 12, Asm(2, 9), Pseudo("delta_new_leaf"), Nodes=0),
        Mk(3, "delta_new_leaf", 0x3100, 13, Asm(3, 9), NL.join(CTX + ["  v9 = 8;"] + TAIL), Nodes=6),
    ],
    "program": PROGRAM_DIFF,
}
