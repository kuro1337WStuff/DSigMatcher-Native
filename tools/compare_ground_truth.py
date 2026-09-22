#!/usr/bin/env python3

"""Compare two extracted ground-truth symbol sets to characterise a benchmark corpus.

Reports address collisions, symbol churn between the two versions, and how much of
the overlap is actually usable as matchable ground truth.
"""

import collections
import os
import sys


def LoadTsv(Path):
    Rows = []
    with open(Path, "r", encoding="utf-8") as Handle:
        Header = Handle.readline()
        if not Header.startswith("rva"):
            raise ValueError("%s: unexpected header %r" % (Path, Header))
        for Line in Handle:
            Parts = Line.rstrip("\n").split("\t")
            if len(Parts) < 4:
                continue
            Rows.append((int(Parts[0], 16), Parts[1], int(Parts[2]), int(Parts[3])))
    return Rows


def Describe(Label, Rows):
    Rvas = [Row[0] for Row in Rows]
    Collisions = collections.Counter(Rvas)
    Duplicated = {Rva: Count for Rva, Count in Collisions.items() if Count > 1}
    WithSize = sum(1 for Row in Rows if Row[2] > 0)

    print("%s" % Label)
    print("  symbols            : %d" % len(Rows))
    print("  distinct addresses : %d" % len(set(Rvas)))
    print("  addresses shared   : %d (covering %d symbols)"
          % (len(Duplicated), sum(Duplicated.values())))
    print("  address range      : %x .. %x" % (min(Rvas), max(Rvas)) if Rvas else "  address range      : <empty>")
    print("  with nonzero size  : %d" % WithSize)

    if Duplicated:
        Worst = sorted(Duplicated.items(), key=lambda Item: -Item[1])[:3]
        for Rva, Count in Worst:
            Names = sorted(Row[1] for Row in Rows if Row[0] == Rva)[:5]
            print("    %08x shared by %d: %s" % (Rva, Count, ", ".join(Names)))

    return {Row[1]: Row[0] for Row in Rows}


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    if len(sys.argv) != 3:
        print("usage: compare_ground_truth.py <version-dir-a> <version-dir-b>")
        return 1

    DirA, DirB = sys.argv[1], sys.argv[2]
    PathA = os.path.join(DirA, "ground_truth.tsv")
    PathB = os.path.join(DirB, "ground_truth.tsv")

    for Path in (PathA, PathB):
        if not os.path.isfile(Path):
            print("missing %s - run extract_pdb_symbols.py first" % Path)
            return 1

    RowsA = LoadTsv(PathA)
    RowsB = LoadTsv(PathB)

    NamesA = Describe(os.path.basename(os.path.normpath(DirA)), RowsA)
    print("")
    NamesB = Describe(os.path.basename(os.path.normpath(DirB)), RowsB)

    Common = set(NamesA) & set(NamesB)
    OnlyA = set(NamesA) - set(NamesB)
    OnlyB = set(NamesB) - set(NamesA)
    Moved = {Name for Name in Common if NamesA[Name] != NamesB[Name]}
    Stable = Common - Moved

    print("")
    print("corpus delta")
    print("  shared names       : %d" % len(Common))
    print("    same address     : %d" % len(Stable))
    print("    moved            : %d" % len(Moved))
    print("  removed in B       : %d" % len(OnlyA))
    print("  added in B         : %d" % len(OnlyB))

    if Common:
        print("  matchable ceiling  : %.2f%% of A" % (100.0 * len(Common) / len(NamesA)))

    for Name in sorted(OnlyB)[:10]:
        print("    + %s @ %x" % (Name, NamesB[Name]))
    for Name in sorted(OnlyA)[:10]:
        print("    - %s @ %x" % (Name, NamesA[Name]))

    return 0


if __name__ == "__main__":
    sys.exit(main())
