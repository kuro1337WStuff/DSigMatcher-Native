# Lane L6 fixture: 02 Appendix A probe 5, the UNION tie (tools/parity/make_fixture.py scenario;
# synthetic data only).
#
# The diff database holds two copies of func_1: sub_9700 (id 1, address 0x9700 = 38656) and sub_9100
# (id 2, address 0x9100 = 37120). "Equal assembly or pseudo-code" (HEURISTICS[10], NO_FPS) is a
# UNION, planned as `UNION USING TEMP B-TREE`, so its rows come out sorted by the whole row and the
# address TEXT '37120' sorts before '38656' although sub_9700 comes first in the raw join. The first
# accepted 1.0 row wins (has_best_match blocks the second), so func_1 -> sub_9100 (`Equal assembly`)
# and sub_9700 stays unmatched, even though "Same order and hash" (same id) would have picked
# sub_9700 had it run first. func_2 has no counterpart, so the Partial category runs too.
#
# Regenerate: python -B tests/diff/fixtures/tiers/gen_tiers_fixtures.py --only probe5 --diaphora-dir <diaphora-ref>

ASM = "\n".join(["push rbp", "mov rbp, rsp", "mov eax, [rcx+10h]", "imul eax, 3", "add eax, 5", "xor edx, edx",
                 "pop rbp", "retn"])
OTHER = "\n".join(["push rbx", "mov ebx, ecx", "shl ebx, 4", "lea eax, [rbx+rbx*2]", "sub eax, 7", "pop rbx",
                   "retn"])

MAIN = {"functions": [Function(1, "func_1", 0x1000, 4, ASM), Function(2, "func_2", 0x2000, 3, OTHER)]}
DIFF = {"functions": [Function(1, "sub_9700", 0x9700, 4, ASM), Function(2, "sub_9100", 0x9100, 4, ASM)]}
