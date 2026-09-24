# Scenario `patch` of the `early` fixtures (05 §19 scenario C, rebuilt): two versions of one binary
# with symbols. Synthetic data only.
#
# Regenerate:
#   python -B tools/parity/make_fixture.py tests/diff/fixtures/early/patch/scenario.py \
#       tests/diff/fixtures/early/patch --diaphora-dir <diaphora-ref>
# then tests/diff/fixtures/early/gen_early.py.
#
# What it exercises (mode P, D:2587-2627, D:2639-2716, scripts/patch_diff_vulns.py):
# - 19 of 21 main mangled names have a partner (90.48% > 90.0, C:166, strict): patch-diff mode, the
#   default hook script is loaded;
# - find_same_name: identical functions at shifted addresses are best; two modified ones are partial
#   (check_ratio + 0.01). The patch-diff hook analyses both (ratio < 1.0): `func_2` changes `jle` into
#   `jbe` (the signed/unsigned walk finds it and breaks), `func_3` adds a size check to its pseudo-code
#   (found by find_vulns_using_pseudocode); in both cases CChooser.Item and add_item run and must not
#   raise;
# - find_remaining_functions: the main `sub_` leftovers against every diff leftover, named or not, in
#   (name, address) order, with `nodes >= 3` on both sides and val 0.6: `sub_180004000` meets
#   `renamed_fn` (similar) and `unnamed_extra`; `sub_180005000` has 2 nodes and meets no row.

BASE = 0x180001000
SHIFT = 0x1000


def Asm(*Lines):
    return "\n".join(Lines)


def Body(Seed, Blocks=3, Jump="jle"):
    Lines = ["push rbx", "sub rsp, 20h", "mov ebx, ecx"]
    for Block in range(Blocks):
        Lines += ["loc_%X:" % (0x180010000 + Seed * 0x100 + Block * 0x10),
                  "lea eax, [rbx+%d]" % (Seed * 3 + Block), "imul eax, %d" % (Seed + Block + 2),
                  "cmp eax, %Xh" % (0x40 + Seed), "%s short loc_%X" % (Jump, 0x180010000 + Seed * 0x100)]
    Lines += ["mov eax, ebx", "add rsp, 20h", "pop rbx", "retn"]
    return Asm(*Lines)


def Pseudo(Name, Seed, Extra=""):
    return "int __fastcall %s(int a1)\n{\n  int v1 = a1 * %d;\n%s  if ( v1 > %d )\n    return v1 - a1;\n  return v1;\n}" % (
        Name, Seed + 2, Extra, 0x40 + Seed)


def Named(Id, Name, Address, Seed, Nodes=4, Asm_=None, Pseudo_=None, **Extra):
    return Function(Id, Name, Address, Nodes, Asm_ if Asm_ is not None else Body(Seed, Nodes - 1),
                    Pseudo_ if Pseudo_ is not None else Pseudo(Name, Seed), md_index="%d.%d" % (Seed, Nodes), **Extra)


MAIN_FUNCTIONS = []
DIFF_FUNCTIONS = []
for Index in range(1, 20):
    Name = "func_%d" % Index
    MAIN_FUNCTIONS.append(Named(Index, Name, BASE + Index * 0x100, Index))
    if Index == 2:
        # signed -> unsigned compare (jle -> jbe): the hook's assembly walk finds the pair and stops; the
        # pseudo-code changes too, or check_ratio would say 1.0 and the hook would not look at it
        DIFF_FUNCTIONS.append(Named(Index, Name, BASE + SHIFT + Index * 0x100, Index, Asm_=Body(Index, 3, "jbe"),
                                    Pseudo_=Pseudo(Name, Index, "  v1 = (unsigned int)v1;\n")))
    elif Index == 3:
        # a new size check in the pseudo-code only
        DIFF_FUNCTIONS.append(Named(Index, Name, BASE + SHIFT + Index * 0x100, Index,
                                    Asm_=Body(Index, 3) + "\nnop",
                                    Pseudo_=Pseudo(Name, Index, "  if ( a1 > 256 )\n    return 0;\n")))
    else:
        DIFF_FUNCTIONS.append(Named(Index, Name, BASE + SHIFT + Index * 0x100, Index))

# Renamed / anonymous leftovers.
RENAMED_BODY = Body(40, 4)
MAIN_FUNCTIONS.append(Named(20, "sub_180004000", 0x180004000, 40, Nodes=5, Asm_=RENAMED_BODY,
                            Pseudo_=Pseudo("sub_180004000", 40)))
MAIN_FUNCTIONS.append(Function(21, "sub_180005000", 0x180005000, 2, Asm("mov eax, [rcx]", "add eax, 1", "retn"),
                               None, md_index="0"))
DIFF_FUNCTIONS.append(Named(20, "renamed_fn", 0x180006000, 40, Nodes=5, Asm_=RENAMED_BODY + "\nnop",
                            Pseudo_=Pseudo("renamed_fn", 40)))
DIFF_FUNCTIONS.append(Function(21, "renamed_small", 0x180007000, 2, Asm("mov eax, [rcx]", "add eax, 2", "retn"),
                               None, md_index="0"))
DIFF_FUNCTIONS.append(Named(22, "unnamed_extra", 0x180008000, 41, Nodes=5))

MAIN = {"functions": MAIN_FUNCTIONS}
DIFF = {"functions": DIFF_FUNCTIONS}
