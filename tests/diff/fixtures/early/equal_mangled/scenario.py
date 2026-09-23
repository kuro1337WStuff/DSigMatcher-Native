# Scenario `equal_mangled` of lane L5 (05 §19 scenario D, rebuilt): C++ functions whose `name` (the
# demangled text) differs from `mangled_function`, most of them unchanged at the same id and address.
# Synthetic data only.
#
# Regenerate:
#   python -B tools/parity/make_fixture.py tests/diff/fixtures/early/equal_mangled/scenario.py \
#       tests/diff/fixtures/early/equal_mangled --diaphora-dir <diaphora-ref>
# then tests/diff/fixtures/early/gen_early.py.
#
# What it exercises (05 §5 "Keying quirk", 01 §5.5, 01 E4):
# - find_equal_matches keys its "100% equal" items by mangled_function (D:1435-1440): 17 of the 20
#   functions (same id, address, nodes, edges, size and bytes_hash) intersect;
# - 18 of 20 addresses are shared (90% < 99%: not stripped) and 20 of 20 mangled names (100% > 90%):
#   patch-diff mode;
# - find_same_name keys by the demangled name, so has_best_match does not see the equal items and the
#   same address pairs get a second best item "Perfect match, same name"; `matched_primary` ends with
#   both key spellings (37 keys for 20 functions); the modified function is a partial;
# - at write time `insert or ignore` on uq_results(address, address2) drops the duplicates and leaves
#   gaps in `line` (D:2399, D:2406).

BASE = 0x180001000


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
    return "void __fastcall %s(int a1)\n{\n  g_state = a1 * %d;%s\n}" % (Name, Seed + 2, Extra)


def Cxx(Id, Index, Address, Modified=False):
    Name = "ns::f%d(void)" % Index
    Mangled = "?f%d@ns@@YAXXZ" % Index
    Tail = ("xor ecx, ecx", "call ?g@ns@@YAXH@Z") if Modified else ()
    Extra = "\n  ns::g(0);" if Modified else ""
    return Function(Id, Name, Address, 4, Body(Index, 3, Tail), Pseudo(Name, Index, Extra),
                    mangled_function=Mangled, md_index="%d.4" % Index)


MAIN_FUNCTIONS = [Cxx(Index + 1, Index, BASE + Index * 0x100) for Index in range(20)]
DIFF_FUNCTIONS = []
for Index in range(20):
    Address = BASE + Index * 0x100
    if Index in (18, 19):
        Address += 0x10000  # moved
    DIFF_FUNCTIONS.append(Cxx(Index + 1, Index, Address, Modified=(Index == 12)))

MAIN = {"functions": MAIN_FUNCTIONS}
DIFF = {"functions": DIFF_FUNCTIONS}
