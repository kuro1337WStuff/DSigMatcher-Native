#!/usr/bin/env python3

"""Emit prime-table test vectors from Diaphora's own primesbelow implementation.

Diaphora indexes signature fields into two distinct prime tables. This runs the real
function out of the reference checkout so the C++ sieve is checked against the
oracle rather than against a reimplementation of the same idea.
"""

import os
import sys

DIAPHORA_REF = r"<diaphora-ref>"

TABLES = [
    ("Pseudocode", 4096),
    ("Main", 2048 * 2048),
]

PROBE_INDICES = [0, 1, 2, 3, 4, 5, 6, 7, 10, 47, 100, 1000, 10000, 100000]


def main():
    if not os.path.isdir(DIAPHORA_REF):
        print("diaphora reference checkout not found at %s" % DIAPHORA_REF)
        return 1

    sys.path.insert(0, DIAPHORA_REF)
    from jkutils.factor import primesbelow

    for Label, Limit in TABLES:
        Primes = primesbelow(Limit)
        Count = len(Primes)

        print("// primesbelow(%d)  ->  %s table" % (Limit, Label))
        print("//   count = %d" % Count)
        print("//   first = %s" % Primes[:8])
        print("//   last  = %s" % Primes[-3:])
        print("//   strictly_less_than_limit = %s" % (Primes[-1] < Limit))
        print("")
        print("const PrimeVector %sVectors[] = {" % Label)
        print('  { "count", %d, %d },' % (Count, Count))
        for Index in PROBE_INDICES:
            if Index < Count:
                print('  { "at(%d)", %d, %d },' % (Index, Index, Primes[Index]))
        for Offset in (1, 2, 3):
            print('  { "last(-%d)", %d, %d },' % (Offset, Count - Offset, Primes[Count - Offset]))
        print("};")
        print("")

        print("// small-prime index checks used by mnemonics_spp and kgh")
        for Prime in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47):
            Position = Primes.index(Prime) if Prime in Primes[:Count] else -1
            print("//   primes.index(%2d) = %d" % (Prime, Position))
        print("")

    return 0


if __name__ == "__main__":
    sys.exit(main())
