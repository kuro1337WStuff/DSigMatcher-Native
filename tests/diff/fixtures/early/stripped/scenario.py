# Scenario `stripped` of the `early` fixtures (05 §19 scenario B, rebuilt): the same binary, the diff
# side without symbols. Synthetic data only.
#
# Regenerate (writes main.sql, diff.sql, expected_*.tsv, after_*.json and oracle.json here):
#   python -B tools/parity/make_fixture.py tests/diff/fixtures/early/stripped/scenario.py \
#       tests/diff/fixtures/early/stripped --diaphora-dir <diaphora-ref>
# then tests/diff/fixtures/early/gen_early.py (the early-point capture and the mutation vectors).
#
# What it exercises (mode S, D:2540-2585):
# - every main address exists in the diff (20 of 20 = 100.0% >= 99.0, C:160), so the stripped pass
#   fires and matches by address through add_matches_from_query_ratio (best 1.0, partial >= 0.5);
# - one identical function with the same id, address and name on both sides: a "100% equal" item
#   first (D:1404-1442), so its stripped row is rejected by has_best_match;
# - one modified body: a stripped partial (0.9009592 here; 05 §19 scenario B had 0.878 on its own data);
# - `helper_20`: its address holds an unrelated function in the diff (stripped ratio below 0.5, the row
#   is dropped), and the diff has `helper_20` itself at a diff-only address: find_same_name matches it
#   in mode S;
# - a diff-only function and the unrelated one stay unmatched (unmatched `primary` rows, labels
#   swapped, D:2334-2354); find_remaining_functions only runs get_unmatched_functions (D:2707-2708).

BASE = 0x180001000


def Asm(*Lines):
    return "\n".join(Lines)


def Body(Seed, Blocks=3):
    Lines = ["push rbx", "sub rsp, 20h", "mov ebx, ecx"]
    for Block in range(Blocks):
        Lines += ["loc_%X:" % (0x180010000 + Seed * 0x100 + Block * 0x10),
                  "lea eax, [rbx+%d]" % (Seed * 3 + Block), "imul eax, %d" % (Seed + Block + 2),
                  "cmp eax, %Xh" % (0x40 + Seed), "jle short loc_%X" % (0x180010000 + Seed * 0x100)]
    Lines += ["mov eax, ebx", "add rsp, 20h", "pop rbx", "retn"]
    return Asm(*Lines)


def Pseudo(Name, Seed):
    return "int __fastcall %s(int a1)\n{\n  int v1 = a1 * %d;\n  if ( v1 > %d )\n    return v1 - a1;\n  return v1;\n}" % (
        Name, Seed + 2, 0x40 + Seed)


def Named(Id, Name, Address, Seed, Nodes=4, Asm_=None, Pseudo_=None, **Extra):
    return Function(Id, Name, Address, Nodes, Asm_ if Asm_ is not None else Body(Seed, Nodes - 1),
                    Pseudo_ if Pseudo_ is not None else Pseudo(Name, Seed), md_index="%d.%d" % (Seed, Nodes), **Extra)


def SubName(Address):
    return "sub_%X" % Address


MAIN_FUNCTIONS = [Named(1, "DllMain", BASE, 1)]
DIFF_FUNCTIONS = [Named(1, "DllMain", BASE, 1)]
for Index in range(2, 20):
    Address = BASE + Index * 0x100
    MAIN_FUNCTIONS.append(Named(Index, "Worker_%d" % Index, Address, Index))
    if Index == 7:
        # modified body: one extra block, the pseudo-code changes too
        DIFF_FUNCTIONS.append(Named(Index, SubName(Address), Address, Index, Nodes=5,
                                    Pseudo_=Pseudo(SubName(Address), Index) + "\n// v2"))
    else:
        # the stripped copy: same body, pseudo-code names the function by address
        DIFF_FUNCTIONS.append(Named(Index, SubName(Address), Address, Index,
                                    Pseudo_=Pseudo("Worker_%d" % Index, Index)))
# helper_20: an unrelated function sits at its address in the diff; helper_20 itself moved.
MAIN_FUNCTIONS.append(Named(20, "helper_20", BASE + 0x1400, 20, Nodes=3))
DIFF_FUNCTIONS.append(Function(20, SubName(BASE + 0x1400), BASE + 0x1400, 2,
                               Asm("xor eax, eax", "cpuid", "rdtsc", "shl rdx, 20h", "or rax, rdx", "retn"), None,
                               md_index="0"))
DIFF_FUNCTIONS.append(Named(21, "helper_20", BASE + 0x2400, 20, Nodes=3))
DIFF_FUNCTIONS.append(Function(22, SubName(BASE + 0x3000), BASE + 0x3000, 2,
                               Asm("mov eax, 0BEEFh", "nop", "retn"), None, md_index="0"))

MAIN = {"functions": MAIN_FUNCTIONS}
DIFF = {"functions": DIFF_FUNCTIONS}
