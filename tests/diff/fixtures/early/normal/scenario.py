# Scenario `normal` of lane L5 (05 §19 scenario A, rebuilt): two versions of one binary with half of
# the names and shifted addresses. Synthetic data only.
#
# Regenerate:
#   python -B tools/parity/make_fixture.py tests/diff/fixtures/early/normal/scenario.py \
#       tests/diff/fixtures/early/normal --diaphora-dir <diaphora-ref>
# then tests/diff/fixtures/early/gen_early.py.
#
# What it exercises (mode N):
# - no address is shared (0% < 99%) and 11 of 22 mangled names have a partner (50% <= 90%): neither
#   speed-up fires, so the SQL heuristic tiers and the convergence loop run (lanes L6-L8);
# - find_same_name: 8 identical named functions are best, 2 modified ones partial (check_ratio +
#   0.01), and `tiny`, whose body changed completely, is a partial with a low ratio (no floor, 05 H5);
#   the 10 `sub_` functions are skipped (ignore_sub_names tests mangled1, D:2179) and are left to the
#   heuristics ("Equal assembly" and friends);
# - one pair with different names but the same shape and most `names` in common, for
#   search_small_differences (lane L6).
# The full expected output needs every lane; lane L5 checks the early points (gen_early.py capture).

BASE = 0x180001000
SHIFT = 0x8000


def Asm(*Lines):
    return "\n".join(Lines)


def Body(Seed, Blocks=3, Tail=()):
    Lines = ["push rbx", "sub rsp, 20h", "mov ebx, ecx"]
    for Block in range(Blocks):
        Lines += ["loc_%X:" % (0x180010000 + Seed * 0x100 + Block * 0x10),
                  "lea eax, [rbx+%d]" % (Seed * 3 + Block), "imul eax, %d" % (Seed + Block + 2),
                  "cmp eax, %Xh" % (0x40 + Seed), "jle short loc_%X" % (0x180010000 + Seed * 0x100)]
    Lines += list(Tail) + ["mov eax, ebx", "add rsp, 20h", "pop rbx", "retn"]
    return Asm(*Lines)


def Pseudo(Name, Seed, Extra=""):
    return "int __fastcall %s(int a1)\n{\n  int v1 = a1 * %d;%s\n  return v1 + %d;\n}" % (Name, Seed + 2, Extra, Seed)


def Fn(Id, Name, Address, Seed, Nodes=4, Tail=(), Extra="", **Columns):
    return Function(Id, Name, Address, Nodes, Body(Seed, Nodes - 1, Tail), Pseudo(Name, Seed, Extra),
                    md_index="%d.%d" % (Seed, Nodes), **Columns)


NAMED = ["alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta", "iota", "kappa"]
MAIN_FUNCTIONS = []
DIFF_FUNCTIONS = []
Id = 1
for Index, Name in enumerate(NAMED):
    Seed = Index + 1
    MAIN_FUNCTIONS.append(Fn(Id, Name, BASE + Id * 0x100, Seed))
    if Name in ("gamma", "theta"):
        DIFF_FUNCTIONS.append(Fn(Id, Name, BASE + SHIFT + Id * 0x100, Seed, Tail=("add ebx, 1",), Extra="\n  ++v1;"))
    else:
        DIFF_FUNCTIONS.append(Fn(Id, Name, BASE + SHIFT + Id * 0x100, Seed))
    Id += 1
for Index in range(10):
    Seed = 20 + Index
    Main = BASE + Id * 0x100
    Diff = BASE + SHIFT + Id * 0x100
    MAIN_FUNCTIONS.append(Fn(Id, "sub_%X" % Main, Main, Seed))
    DIFF_FUNCTIONS.append(Fn(Id, "sub_%X" % Diff, Diff, Seed))
    Id += 1
# tiny: same name, unrelated bodies
MAIN_FUNCTIONS.append(Function(Id, "tiny", BASE + Id * 0x100, 3,
                               Asm("xor eax, eax", "loc_1:", "add eax, ecx", "dec ecx", "jnz short loc_1", "retn"),
                               "int tiny(int a1)\n{\n  return a1 * (a1 + 1) / 2;\n}", md_index="7.25"))
DIFF_FUNCTIONS.append(Function(Id, "tiny", BASE + SHIFT + Id * 0x100, 3,
                               Asm("mov rax, gs:30h", "mov rax, [rax+60h]", "test rax, rax", "jz short loc_2",
                                   "mov eax, [rax+0BCh]", "loc_2:", "retn"),
                               "int tiny()\n{\n  return NtCurrentPeb()->NtGlobalFlag;\n}", md_index="9.5"))
Id += 1
# the small-differences pair: same nodes, edges, mnemonics and complexity; most names shared
SMALL_ASM_MAIN = Asm("push rbp", "mov rbp, rsp", "call sub_180001500", "call alpha", "call beta", "pop rbp", "retn")
SMALL_ASM_DIFF = Asm("push rbp", "mov rbp, rsp", "call sub_180009500", "call alpha", "call gamma", "pop rbp", "retn")
MAIN_FUNCTIONS.append(Function(Id, "alpha_x", BASE + Id * 0x100, 1, SMALL_ASM_MAIN, None, md_index="0",
                               names='["alpha", "beta", "sub_180001500", "g_count"]'))
DIFF_FUNCTIONS.append(Function(Id, "beta_y", BASE + SHIFT + Id * 0x100, 1, SMALL_ASM_DIFF, None, md_index="0",
                               names='["alpha", "beta", "sub_180009500", "g_count"]'))

MAIN = {"functions": MAIN_FUNCTIONS}
DIFF = {"functions": DIFF_FUNCTIONS}
