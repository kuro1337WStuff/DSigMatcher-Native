# Lane L6 fixture: heuristic flag filtering with different processors (tools/parity/make_fixture.py
# scenario; synthetic data only).
#
# same_processor_both_databases (D:2950-2967) is False (metapc against ARM), so every heuristic
# flagged HEUR_FLAG_SAME_CPU (H:44-48) is left out of the lists (D:1506-1508): Best runs 5
# (HEURISTICS 11, 10, 8, 7, 4, in that order) and Partial 26 (41, 40, 35, ..., 12: 39 drops out;
# 36-38 are UNRELIABLE and never run by default). Some functions stay unmatched after the Best
# category, so the Partial list is built (D:1481-1484 would otherwise stop it).
#
# Regenerate: python -B tests/diff/fixtures/tiers/gen_tiers_fixtures.py --only diffcpu --diaphora-dir <diaphora-ref>


def Asm(*Lines):
    return "\n".join(Lines)


SAME = Asm("push rbp", "mov rbp, rsp", "mov eax, [rcx+8]", "add eax, 3", "imul eax, eax", "pop rbp", "retn")
LOOP_MAIN = Asm("xor eax, eax", "loc_a:", "add eax, ecx", "dec ecx", "jnz short loc_a", "mov edx, eax", "retn")
LOOP_DIFF = Asm("xor eax, eax", "loc_a:", "add eax, ecx", "add eax, 1", "dec ecx", "jnz short loc_a", "retn")
ALONE_MAIN = Asm("mov eax, 1", "cpuid", "mov [rcx], eax", "mov [rcx+4], ebx", "retn")
ALONE_DIFF = Asm("rdtsc", "shl rdx, 20h", "or rax, rdx", "mov [rcx], rax", "xor eax, eax", "retn")

MAIN = {
    "functions": [
        Function(1, "func_same", 0x401000, 4, SAME),
        Function(2, "func_loop", 0x401100, 3, LOOP_MAIN, loops=2),
        Function(3, "func_alone", 0x401200, 2, ALONE_MAIN),
    ],
}
DIFF = {
    "functions": [
        Function(1, "sub_501000", 0x501000, 4, SAME),
        Function(2, "sub_501100", 0x501100, 3, LOOP_DIFF, loops=2),
        Function(3, "sub_501200", 0x501200, 2, ALONE_DIFF),
    ],
    "program": {"processor": "ARM"},
}
