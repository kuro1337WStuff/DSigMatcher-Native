# Scenario of the `common` fixture pair (tools/parity/make_fixture.py). Synthetic data only.
#
# Regenerate (writes main.sql, diff.sql, expected_*.tsv, after_*.json and oracle.json here):
#   python -B tools/parity/make_fixture.py tests/diff/fixtures/common/scenario.py tests/diff/fixtures/common \
#       --diaphora-dir <diaphora-ref>
#
# What it exercises in the results writer and the parity harness (plan §4 L4, 01 §10.2-§11):
# - 02 probe 9 case A: a C++ function (name != mangled_function) identical on both sides, with the same
#   id and address, is matched twice for one address pair: "100% equal" under the mangled key
#   (D:1424-1440) and "Perfect match, same name" under the demangled one (D:2152-2210). Both reach
#   the best chooser; `insert or ignore` keeps only the first, leaving a gap in `line` (01 E4).
# - addresses above 2^32, so "%08x" prints more than eight digits (01 §10.2);
# - a same-name partial match with a ratio below 1 ("%.7f" formatting);
# - unmatched functions on both sides (the swapped primary/secondary labels, D:2334-2354), one of
#   them with a non-ASCII (UTF-8) name and one with a NULL name (Python None, written as NULL; it sits
#   above every match, so no gap query or heuristic row reaches it).
#
# Function(id, name, address, nodes, assembly, pseudocode, **column overrides) is predefined by
# make_fixture.py.

BASE = 0x180001000


def Asm(*Lines):
    return "\n".join(Lines)


CXX_NAME = "Foo::Bar(int)"
CXX_MANGLED = "?Bar@Foo@@QEAAXH@Z"
CXX_ASM = Asm("push rbx", "sub rsp, 20h", "mov ebx, ecx", "call sub_180001400", "test eax, eax",
              "jz short loc_180001030", "mov eax, ebx", "add rsp, 20h", "pop rbx", "retn")
CXX_PSEUDO = "void __fastcall Foo::Bar(Foo *this, int a2)\n{\n  if ( sub_180001400() )\n    return;\n}"

NAMED_ASM_MAIN = Asm("mov eax, [rcx+8]", "cmp eax, 10h", "jbe short loc_1", "mov eax, 10h", "loc_1:",
                     "lea rdx, [rcx+10h]", "mov [rdx], eax", "retn")
NAMED_ASM_DIFF = Asm("mov eax, [rcx+8]", "cmp eax, 20h", "jbe short loc_1", "mov eax, 20h", "loc_1:",
                     "lea rdx, [rcx+10h]", "mov [rdx], eax", "xor eax, eax", "retn")

WORKER_ASM = Asm("push rbp", "mov rbp, rsp", "mov ecx, 3", "call sub_180001500", "imul eax, 7",
                 "add eax, 11", "pop rbp", "retn")
HELPER_ASM = Asm("xor eax, eax", "cmp ecx, 1", "setz al", "shl eax, 2", "or eax, 1", "retn")
LOOPER_ASM = Asm("xor eax, eax", "loc_a:", "add eax, ecx", "dec ecx", "jnz short loc_a", "retn")
LOOPER_ASM_DIFF = Asm("xor eax, eax", "loc_a:", "add eax, ecx", "add eax, 1", "dec ecx", "jnz short loc_a", "retn")

MAIN = {
    "functions": [
        Function(1, CXX_NAME, BASE, 5, CXX_ASM, CXX_PSEUDO, mangled_function=CXX_MANGLED, md_index="1.5"),
        Function(2, "named_fn", BASE + 0x100, 3, NAMED_ASM_MAIN, "int named_fn(int *a1)\n{\n  return a1[2];\n}",
                 md_index="2.25"),
        Function(3, "sub_180001200", BASE + 0x200, 4, WORKER_ASM, "int sub_180001200()\n{\n  return 7 * x + 11;\n}",
                 md_index="3.125"),
        Function(4, "sub_180001300", BASE + 0x300, 2, HELPER_ASM, None, md_index="4.0625"),
        Function(5, "sub_180001400", BASE + 0x400, 3, LOOPER_ASM, "int sub_180001400(int a1)\n{\n  return a1;\n}",
                 md_index="5.5"),
        Function(6, "only_in_main_ü", BASE + 0x500, 2, Asm("mov eax, 0DEADh", "retn"), None, md_index="0"),
    ],
}

DIFF = {
    "functions": [
        Function(1, CXX_NAME, BASE, 5, CXX_ASM, CXX_PSEUDO, mangled_function=CXX_MANGLED, md_index="1.5"),
        Function(2, "named_fn", BASE + 0x1100, 3, NAMED_ASM_DIFF, "int named_fn(int *a1)\n{\n  return a1[4];\n}",
                 md_index="2.25"),
        Function(3, "sub_180002200", BASE + 0x1200, 4, WORKER_ASM,
                 "int sub_180002200()\n{\n  return 7 * x + 11;\n}", md_index="3.125"),
        Function(4, "sub_180002300", BASE + 0x1300, 2, HELPER_ASM, None, md_index="4.0625"),
        Function(5, "sub_180002400", BASE + 0x1400, 3, LOOPER_ASM_DIFF,
                 "int sub_180002400(int a1)\n{\n  return a1 + 1;\n}", md_index="5.5"),
        Function(6, "only_in_diff", BASE + 0x1500, 2, Asm("mov eax, 0BEEFh", "nop", "retn"), None, md_index="0"),
        Function(7, None, BASE + 0x9000, 2, Asm("mov eax, 0CAFEh", "int3", "int3", "retn"), None, md_index="0",
                 mangled_function=None),
    ],
    "program": {"md5sum": "%032x" % 0xD1FF},
}
