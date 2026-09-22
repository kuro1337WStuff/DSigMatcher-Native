#!/usr/bin/env python3

import os
import sys

from make_fixture import BuildRow, WriteDatabase


def MakeGroups():
    Stable = []
    for Index in range(8):
        Stable.append({
            "nodes": 4, "edges": 5, "instructions": 20,
            "mnemonics": "push mov call ret",
            "body": "stable-body-%d" % Index,
            "pseudo_lines": 8,
            "clean_asm": "asm-stable-%d" % Index,
            "clean_pseudo": "pseudo-stable-%d" % Index,
            "clean_micro": "micro-stable-%d" % Index,
            "kind": "stable",
            "label": "Real_Stable_%d" % Index,
        })

    Drifting = []
    for Index in range(4):
        Drifting.append({
            "nodes": 5, "edges": 6, "instructions": 30,
            "mnemonics": "push sub mov call add pop ret",
            "body": "drift-body-%d" % Index,
            "pseudo_lines": 3,
            "clean_asm": "asm-drift-%d" % Index,
            "clean_pseudo": "pseudo-drift-%d" % Index,
            "clean_micro": "micro-drift-%d" % Index,
            "kind": "drifting",
            "label": "Real_Drift_%d" % Index,
        })

    Ambiguous = []
    for Index in range(2):
        Ambiguous.append({
            "nodes": 6, "edges": 7, "instructions": 40,
            "mnemonics": "push mov lea call jmp ret",
            "body": "ambig-body-%d" % Index,
            "pseudo_lines": 3,
            "clean_asm": "asm-shared-ambiguous",
            "clean_pseudo": "pseudo-ambig-%d" % Index,
            "clean_micro": "micro-shared-ambiguous",
            "kind": "ambiguous",
            "label": "Real_Ambig_%d" % Index,
        })

    Orphan = {
        "nodes": 3, "edges": 3, "instructions": 15,
        "mnemonics": "xor test jz ret",
        "body": "orphan-body",
        "pseudo_lines": 6,
        "clean_asm": "asm-orphan",
        "clean_pseudo": "pseudo-orphan",
        "clean_micro": "micro-orphan",
        "kind": "orphan",
        "label": "Real_Orphan",
    }

    return Stable, Drifting, Ambiguous, Orphan


def BuildVersion(Version, PreLabelledIndex):
    Stable, Drifting, Ambiguous, Orphan = MakeGroups()

    Rows = []
    AddressOffset = Version * 0x100000
    Slot = 0

    for Group in (Stable, Drifting, Ambiguous):
        for Index, Base in enumerate(Group):
            Body = dict(Base)
            if Version > 0 and Base["kind"] in ("drifting", "ambiguous"):
                Body["body"] = "%s-v%d" % (Base["body"], Version)

            if Version == 0:
                Name = Base["label"]
            elif Version == 1 and Base["kind"] == "stable" and Index == PreLabelledIndex:
                Name = "AlreadyNamed_ByHand"
            else:
                Name = "sub_%X" % (0x1000 + Slot * 0x10 + Version)

            Rows.append(BuildRow(Slot, Name, Body, AddressOffset))
            Slot += 1

    OrphanBody = dict(Orphan)
    OrphanBody["body"] = "%s-v%d" % (Orphan["body"], Version)
    OrphanBody["clean_asm"] = "asm-orphan-v%d" % Version
    OrphanBody["clean_pseudo"] = "pseudo-orphan-v%d" % Version
    OrphanBody["clean_micro"] = "micro-orphan-v%d" % Version
    OrphanBody["mnemonics"] = "xor test jz ret v%d" % Version
    OrphanName = Orphan["label"] if Version == 0 else "sub_DEAD"
    Rows.append(BuildRow(Slot, OrphanName, OrphanBody, AddressOffset))

    return Rows


def main():
    OutDir = sys.argv[1] if len(sys.argv) > 1 else "."
    Versions = int(sys.argv[2]) if len(sys.argv) > 2 else 3
    PreLabelledIndex = 2

    os.makedirs(OutDir, exist_ok=True)

    Paths = []
    for Version in range(Versions):
        Path = os.path.join(OutDir, "v%d.sqlite" % Version)
        WriteDatabase(Path, BuildVersion(Version, PreLabelledIndex), "metapc")
        Paths.append(Path)
        print("v%d : %s" % (Version, Path))

    print("")
    print("hand labelled version  : v0 (all names Real_*)")
    print("pre-labelled in v1     : stable index %d is AlreadyNamed_ByHand" % PreLabelledIndex)
    print("functions per version  : 15 (8 stable, 4 drifting, 2 ambiguous, 1 orphan)")
    print("")
    print("expected v0 -> v1:")
    print("  matches              : 14  (8 stable + 4 drifting + 2 ambiguous at 0.5)")
    print("  names applied        : 13  (the pre-labelled one is preserved, not clobbered)")
    print("  skipped existing     : 1")
    print("  orphan               : unmatched on both sides")
    print("")
    print("expected v1 -> v2:")
    print("  ambiguous cumulative : 0.25 after two hops at 0.5 each")
    print("  stable/drift cumul.  : 1.0")
    print("  hops recorded        : 2")
    print("paths=%s" % " ".join(Paths))


if __name__ == "__main__":
    main()
