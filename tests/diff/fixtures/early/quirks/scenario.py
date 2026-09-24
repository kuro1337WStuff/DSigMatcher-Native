# Scenario `quirks` of the `early` fixtures (05 §19 scenario E, rebuilt and extended): the corner cases of
# find_same_name (D:2152-2210). Synthetic data only.
#
# Regenerate:
#   python -B tools/parity/make_fixture.py tests/diff/fixtures/early/quirks/scenario.py \
#       tests/diff/fixtures/early/quirks --diaphora-dir <diaphora-ref>
# then tests/diff/fixtures/early/gen_early.py.
#
# What it exercises (mode N: 9 mangled pairs for 20 main functions, 45%):
# - `f.name not like 'nullsub_%'` is SQLite LIKE: ASCII case-insensitive and '_' matches one character,
#   so `nullsubX`, `NULLSUB_2` and `nullsub_1` are excluded, `nullsub` (7 characters) and
#   `j_nullsub_1` are kept (05 §9);
# - check_match's own nullsub filter tests both names case-sensitively (D:1846): `wrapper_a` joins
#   `nullsub_9` through an equal mangled name and is rejected there;
# - `prettyname` has the mangled name `sub_40C000` in the main database: ignore_sub_names tests
#   mangled1, so the pass skips it although name1 == name2 (05 §9);
# - `dupname` has two diff candidates with the same name; the modified one comes first (lower id), is
#   stored with the fake 1.0 of a same-name match (D:1350-1351), and blocks the identical one through
#   has_best_match (05 H2);
# - `lowA` / `lowB`: same shape, names and mnemonics, unrelated code: a low-ratio partial left to the
#   heuristic tiers. Real Diaphora gives "Mnemonics and names" 0.5030000 here; 05 §19
#   scenario E reported 0.003 for its own data, whose scripts were not kept.
# The full expected output needs every pass; diff_early checks the early points (gen_early.py capture).

BASE = 0x40A000
SHIFT = 0x4000


def Asm(*Lines):
    return "\n".join(Lines)


def Body(Seed, Blocks=3, Tail=()):
    Lines = ["push ebx", "sub esp, 20h", "mov ebx, ecx"]
    for Block in range(Blocks):
        Lines += ["loc_%X:" % (0x480000 + Seed * 0x100 + Block * 0x10),
                  "lea eax, [ebx+%d]" % (Seed * 3 + Block), "imul eax, %d" % (Seed + Block + 2),
                  "cmp eax, %Xh" % (0x40 + Seed), "jle short loc_%X" % (0x480000 + Seed * 0x100)]
    Lines += list(Tail) + ["mov eax, ebx", "add esp, 20h", "pop ebx", "retn"]
    return Asm(*Lines)


def Pseudo(Name, Seed, Extra=""):
    return "int __fastcall %s(int a1)\n{\n  int v1 = a1 * %d;%s\n  return v1 + %d;\n}" % (Name, Seed + 2, Extra, Seed)


def Fn(Id, Name, Address, Seed, Nodes=4, Tail=(), Extra="", **Columns):
    return Function(Id, Name, Address, Nodes, Body(Seed, Nodes - 1, Tail), Pseudo(Name, Seed, Extra),
                    md_index="%d.%d" % (Seed, Nodes), **Columns)


MAIN_FUNCTIONS = []
DIFF_FUNCTIONS = []
Id = 1


def Pair(Name, Seed, DiffName=None, MainColumns=None, DiffColumns=None, DiffTail=()):
    global Id
    MAIN_FUNCTIONS.append(Fn(Id, Name, BASE + Id * 0x100, Seed, **(MainColumns or {})))
    DIFF_FUNCTIONS.append(Fn(Id, DiffName or Name, BASE + SHIFT + Id * 0x100, Seed, Tail=DiffTail,
                             **(DiffColumns or {})))
    Id += 1


Pair("nullsubX", 1)
Pair("NULLSUB_2", 2)
Pair("nullsub_1", 3)
Pair("nullsub", 4)
Pair("j_nullsub_1", 5)
Pair("wrapper_a", 6, DiffName="nullsub_9", MainColumns={"mangled_function": "?a@@YAXXZ"},
     DiffColumns={"mangled_function": "?a@@YAXXZ"})
Pair("prettyname", 7, MainColumns={"mangled_function": "sub_40C000"})
Pair("tiny", 8, DiffTail=("xor eax, eax", "cpuid", "rdtsc", "shl edx, 10h", "or eax, edx", "bswap eax", "not eax"))
# dupname: two diff functions with the same name; the modified one has the lower id
MAIN_FUNCTIONS.append(Fn(Id, "dupname", BASE + Id * 0x100, 9))
DIFF_FUNCTIONS.append(Fn(Id, "dupname", BASE + SHIFT + Id * 0x100, 9, Tail=("add ebx, 1",), Extra="\n  ++v1;"))
Id += 1
DIFF_FUNCTIONS.append(Fn(Id, "dupname", BASE + SHIFT + Id * 0x100, 9))
Id += 1
# lowA / lowB: same shape and names, unrelated code
MAIN_FUNCTIONS.append(Function(Id, "lowA", BASE + Id * 0x100, 1,
                               Asm("push ebp", "mov ebp, esp", "call alpha", "call beta", "pop ebp", "retn"),
                               "int lowA()\n{\n  alpha();\n  return beta();\n}", md_index="0",
                               names='["alpha", "beta"]'))
DIFF_FUNCTIONS.append(Function(Id, "lowB", BASE + SHIFT + Id * 0x100, 1,
                               Asm("push esi", "mov esi, ecx", "call beta", "call alpha", "pop esi", "retn"),
                               "void lowB()\n{\n  unsigned int i;\n  for ( i = 0; i < 100; ++i )\n    beta(alpha(i));\n}",
                               md_index="0", names='["alpha", "beta"]'))
Id += 1
# anonymous functions (keep the mangled-name pair count at or below 90%)
for Index in range(10):
    Seed = 30 + Index
    Main = BASE + Id * 0x100
    Diff = BASE + SHIFT + Id * 0x100
    MAIN_FUNCTIONS.append(Fn(Id, "sub_%X" % Main, Main, Seed))
    DIFF_FUNCTIONS.append(Fn(Id, "sub_%X" % Diff, Diff, Seed))
    Id += 1

MAIN = {"functions": MAIN_FUNCTIONS}
DIFF = {"functions": DIFF_FUNCTIONS}
