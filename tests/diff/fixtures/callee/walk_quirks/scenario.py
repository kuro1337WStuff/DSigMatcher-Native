# Scenario "walk_quirks": the diff-walk quirks 1-4 of 03b §4.3.2 (06 §6.3, V2) through the whole stage.
# Synthetic data only. Regenerate with
#   python -B tests/diff/fixtures/callee/gen_callee_fixtures.py --diaphora-dir <diaphora-ref> --only walk_quirks
#
# The seed caller_q (same name, identical assembly) has a pseudo-code diff with five changes, each far
# enough from the next (8 context lines, more than 2 * n = 6) to sit in its own hunk. The context lines
# carry no identifier of 4+ characters, so every candidate token comes from the changed lines:
#   1. line 0 "lead_old_fn(v1)" is deleted: a leading delete-only block, flushed together with the
#      "+++ " header at the first context row, so it yields no pair (quirk 2);
#   2. "mid_old_fn(v1)" is deleted in a middle hunk and "mid_new_fn(v1)" inserted in the next hunk: the
#      one-sided block is carried across the "@@" boundary and pairs positionally with the insertion
#      (quirk 3) -> the candidate (mid_old_fn, mid_new_fn);
#   3. "pos_old_fn(v1)" becomes "extra_tok_fn(pos_new_fn(v1))": positional pairing over every token, so
#      the extra token shifts the pair to (pos_old_fn, extra_tok_fn), which does not exist (quirk 4);
#   4. the last line "tail_old_fn(v1)" becomes "tail_new_fn(v1)" with no context row after it: that
#      block is never flushed (quirk 1).
# Every callee pair (lead, mid, pos, tail) is built like exp_a's alpha_old_callee / beta_new_callee, so it
# would pass every gate of D:3080-3107 if the walk produced it.

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
                    pseudocode_lines=len(PseudoText.split(NL)), pseudocode_hash1="h1" + str(K),
                    pseudocode_primes=str(3000 + K), function_flags=0, prototype2="int()",
                    pseudocode_hash2="h2" + str(K), pseudocode_hash3="h3" + str(K), strongly_connected=1, loops=0,
                    rva=str(Addr), tarjan_topological_sort="[]", strongly_connected_spp=str(K + 11),
                    clean_assembly=AsmText, clean_pseudo=PseudoText, mnemonics_spp=str(5000 + K), switches="[]",
                    function_hash=Md5("f" + str(K)), bytes_sum=K, md_index=str(1.5 + K / 10), constants="[]",
                    constants_count=0, segment_rva=str(Addr), assembly_addrs="[]", kgh_hash=str(7000 + K),
                    source_file=None, userdata=None, microcode=None, clean_microcode=None, microcode_spp=None,
                    export_time=0.0)


def Ctx(First, Last):
    return ["  c%02d = %d;" % (I, I) for I in range(First, Last + 1)]


CALLER_MAIN = NL.join(["  lead_old_fn(v1);"] + Ctx(1, 8) + ["  mid_old_fn(v1);"] + Ctx(9, 16) + Ctx(17, 24) +
                      ["  pos_old_fn(v1);"] + Ctx(25, 32) + ["  tail_old_fn(v1);"])
CALLER_DIFF = NL.join(Ctx(1, 8) + Ctx(9, 16) + ["  mid_new_fn(v1);"] + Ctx(17, 24) +
                      ["  extra_tok_fn(pos_new_fn(v1));"] + Ctx(25, 32) + ["  tail_new_fn(v1);"])
CALLER_ASM = Asm(1, 1)

PROGRAM_MAIN = {"callgraph_primes": "6", "callgraph_all_primes": json.dumps({"2": 1, "3": 1}), "md5sum": "q1"}
PROGRAM_DIFF = {"callgraph_primes": "10", "callgraph_all_primes": json.dumps({"2": 1, "3": 1}), "md5sum": "q2"}

MAIN = {
    "functions": [
        Mk(1, "caller_q", 0x1000, 1, CALLER_ASM, CALLER_MAIN, Nodes=9, Bh="same"),
        Mk(2, "lead_old_fn", 0x2000, 2, Asm(2, 2), Callee("leaf_lead_a")),
        Mk(3, "mid_old_fn", 0x3000, 3, Asm(3, 3), Callee("leaf_mid_a")),
        Mk(4, "pos_old_fn", 0x4000, 4, Asm(4, 4), Callee("leaf_pos_a")),
        Mk(5, "tail_old_fn", 0x5000, 5, Asm(5, 5), Callee("leaf_tail_a")),
    ],
    "program": PROGRAM_MAIN,
}

DIFF = {
    "functions": [
        Mk(1, "caller_q", 0x1100, 1, CALLER_ASM, CALLER_DIFF, Nodes=9, Bh="same"),
        Mk(2, "lead_new_fn", 0x2100, 12, Asm(2, 9), Callee("leaf_lead_b"), Nodes=6),
        Mk(3, "mid_new_fn", 0x3100, 13, Asm(3, 9), Callee("leaf_mid_b"), Nodes=6),
        Mk(4, "pos_new_fn", 0x4100, 14, Asm(4, 9), Callee("leaf_pos_b"), Nodes=6),
        Mk(5, "tail_new_fn", 0x5100, 15, Asm(5, 9), Callee("leaf_tail_b"), Nodes=6),
    ],
    "program": PROGRAM_DIFF,
}
