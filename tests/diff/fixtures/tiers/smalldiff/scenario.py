# Lane L6 fixture: search_small_differences (D:2085-2150; tools/parity/make_fixture.py scenario;
# synthetic data only).
#
# Pairs with equal nodes, edges, mnemonics and cyclomatic complexity, a non-empty `names` list and
# different code and mnemonics_spp (so no SQL heuristic claims them first):
#   * low_a / low_b share 2 of 3 names: the names ratio 0.667 passes the 0.5 gate, and the recorded
#     ratio is check_ratio's, with no lower bound (05 §11, scenario E): a partial far below 0.5;
#   * weak_a / weak_b share 1 of 3 names: 0.333 fails the gate, no match;
#   * half_a / half_b share 1 of 2 names: exactly 0.5 passes (`ratio >= 0.5`).
#
# Regenerate: python -B tests/diff/fixtures/tiers/gen_tiers_fixtures.py --only smalldiff --diaphora-dir <diaphora-ref>
import json


def Asm(*Lines):
    return "\n".join(Lines)


def Pair(Id, NameMain, NameDiff, Base, NamesMain, NamesDiff, Regs):
    # the same mnemonics, different operands on every line: equal `mnemonics` JSON, no common assembly line
    Main = Asm("push rbp", "mov %s, 1" % Regs[0], "add %s, 2" % Regs[0], "imul %s, 3" % Regs[0], "pop rbp", "retn")
    Diff = Asm("push rbx", "mov %s, 7" % Regs[1], "add %s, 9" % Regs[1], "imul %s, 11" % Regs[1], "pop rbx",
               "retn 8")
    return (Function(Id, NameMain, 0x401000 + Base, 3, Main, names=json.dumps(NamesMain), kgh_hash="k%d" % Id,
                     md_index="%d.25" % Id, mnemonics_spp="3%d1" % Id),
            Function(Id, NameDiff, 0x601000 + Base, 3, Diff, names=json.dumps(NamesDiff), kgh_hash="q%d" % Id,
                     md_index="%d.75" % Id, mnemonics_spp="3%d7" % Id))


P1 = Pair(1, "low_a", "sub_low_b", 0x000, ["CreateFileW", "ReadFile", "CloseHandle"],
          ["CreateFileW", "ReadFile", "WriteFile"], ("eax", "ebx"))
P2 = Pair(2, "weak_a", "sub_weak_b", 0x100, ["HeapAlloc", "HeapFree", "GetProcessHeap"],
          ["HeapAlloc", "VirtualAlloc", "VirtualFree"], ("ecx", "edx"))
P3 = Pair(3, "half_a", "sub_half_b", 0x200, ["lstrlenW", "lstrcpyW"], ["lstrlenW", "wcscpy_s"], ("esi", "edi"))

MAIN = {"functions": [P1[0], P2[0], P3[0]]}
DIFF = {"functions": [P1[1], P2[1], P3[1]]}
