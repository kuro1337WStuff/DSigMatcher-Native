#!/usr/bin/env python3

"""Emit known-good KGH decimal strings for the C++ test suite.

Python integers are arbitrary precision, so str(product of primes ** exponents) is
exactly what Diaphora writes into functions.kgh_hash. These are oracle values, not
values produced by the implementation under test.
"""

import hashlib
import sys

sys.set_int_max_str_digits(1000000)

PRIMES = [2, 3, 5, 7, 11, 19, 23, 29, 31, 37, 41, 43, 47]

NAMES = [
    "NODE_ENTRY", "NODE_EXIT", "NODE_NORMAL", "EDGE_IN_CONDITIONAL",
    "EDGE_OUT_CONDITIONAL", "FEATURE_LOOP", "FEATURE_CALL", "FEATURE_DATA_REFS",
    "FEATURE_CALL_REF", "FEATURE_STRONGLY_CONNECTED", "FEATURE_FUNC_NO_RET",
    "FEATURE_FUNC_LIB", "FEATURE_FUNC_THUNK",
]

CASES = [
    ("all zero", [0] * 13),
    ("single entry block", [1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]),
    ("typical five block function", [1, 1, 5, 6, 6, 1, 3, 2, 3, 4, 0, 0, 0]),
    ("library thunk noret", [1, 1, 2, 2, 2, 0, 1, 0, 1, 2, 1, 1, 1]),
    ("hundred blocks", [1, 1, 100, 120, 120, 5, 40, 30, 40, 60, 0, 0, 0]),
    ("thousand blocks", [1, 1, 1000, 1200, 1200, 50, 400, 300, 400, 600, 0, 0, 0]),
    ("large exponent on 47", [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100000]),
    ("large exponent on 2", [100000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
    ("all primes moderate", [7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7]),
]


def main():
    print("// label, 13 exponents, decimal digit count, md5 of decimal string")
    print("const KghVector Vectors[] = {")
    for Label, Exponents in CASES:
        Product = 1
        for Prime, Exponent in zip(PRIMES, Exponents):
            Product *= Prime ** Exponent
        Text = str(Product)
        Digest = hashlib.md5(Text.encode("ascii")).hexdigest()
        print('  { "%s", { %s }, %d, "%s" },' % (
            Label,
            ", ".join(str(E) for E in Exponents),
            len(Text),
            Digest,
        ))
    print("};")
    print("")
    print("// one full literal, for debugging and for eyeballing the small cases")
    for Label, Exponents in CASES[:4]:
        Product = 1
        for Prime, Exponent in zip(PRIMES, Exponents):
            Product *= Prime ** Exponent
        print("// %-28s %s" % (Label, str(Product)))


if __name__ == "__main__":
    for Name, Prime in zip(NAMES, PRIMES):
        print("//   %-30s %d" % (Name, Prime))
    print("")
    main()
