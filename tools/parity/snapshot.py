#!/usr/bin/env python3

"""Read, write and diff the parity trace and snapshot formats.

This is the Python side of `docs/parity/00-plan.md` Appendix B. The native
engine (`src/diff/Snapshot.cpp`, `src/diff/Trace.cpp`) writes the same field
names, so every tool here parses JSON and compares values; it never compares
bytes.

Snapshot file (`snapshots/NNNNN_<sanitised point>.json`, one per point):

    {"schema": "dsig-parity-snapshot/1", "producer": ..., "pair": ..., "seq": N,
     "point": "before:find_matches_diffing:0", "iteration": 0 | null,
     "flags": {"is_same_processor", "is_patch_diff", "is_symbols_stripped",
               "hooks_loaded", "total_functions1", "total_functions2"},
     "all_matches": {"best": [item...], "partial": [...], "unreliable": [...]},
     "matched_primary": [[key, other, ratio_bits]...],
     "matched_secondary": [[key, other, ratio_bits]...],
     "ratios_cache": [["ea1-ea2", ratio_bits]...],             (optional)
     "choosers": {"best"|"partial"|"unreliable"|"multimatch": [item...]},
                                                               (after:final_pass only)
     "unmatched": {"primary": [[ea, name]...] | null,
                   "secondary": [[ea, name]...] | null}}      (after:find_unmatched only)

    item = [ea1, name1, ea2, name2, desc, ratio_bits, nodes1, nodes2]

Trace (`trace.jsonl`, one JSON object per line), event types `add_match`,
`cleanup`, `point` and `row`; see `tools/parity/README.md`.

`index.json` lists every point in order as `[seq, point, file]`; `file` is the
snapshot path relative to the capture directory, or null when `--points`
filtered the snapshot out.
"""

import fnmatch
import json
import os
import pathlib
import re
import sqlite3
import struct

SCHEMA = "dsig-parity-snapshot/1"

LISTS = ("best", "partial", "unreliable")
CHOOSERS = ("best", "partial", "unreliable", "multimatch")
UNMATCHED = ("primary", "secondary")

# Every point name Appendix B defines. Used to reject typos in --stop-at and to
# label points in reports.
POINT_PATTERNS = [
    r"after:find_equal_matches",
    r"after:apply_dirty_heuristics",
    r"(before|after):find_same_name",
    r"(before|after):find_remaining_functions",
    r"(before|after):heuristic:\d+",
    r"after:run_heuristics_for_category:[A-Za-z]+",
    r"(before|after):search_small_differences",
    r"(before|after):cleanup:\d+:\d+",
    r"(before|after):(find_matches_diffing|find_related_matches|find_related_compilation_unit"
    r"|find_locally_affine_functions):\d+",
    r"(before|after):final_pass",
    r"after:find_unmatched",
]
_POINT_RE = re.compile(r"^(?:%s)$" % "|".join(POINT_PATTERNS))

# Fields that never take part in a comparison by default: they number events or
# name the producer, they are not match state.
DEFAULT_IGNORE = ("seq", "producer")


def IsPointName(Point):
    return _POINT_RE.match(Point) is not None


# ----------------------------------------------------------------------------- values

def RatioBits(Value):
    """IEEE-754 bits of float(Value) as 16 lowercase hex digits (Appendix B).

    Python's int 1 and 0 become 1.0 and 0.0, which is exact because Diaphora
    only ever compares them with == / < / > and formats them with "%.7f"."""
    return struct.pack(">d", float(Value)).hex()


def BitsToFloat(Bits):
    return struct.unpack(">d", bytes.fromhex(Bits))[0]


def SanitisePoint(Point):
    return re.sub(r"[^A-Za-z0-9._-]", "_", Point)


def SnapshotFileName(Seq, Point):
    return "%05d_%s.json" % (Seq, SanitisePoint(Point))


def MatchesAny(Point, Globs):
    """True when Point matches one of the fnmatch globs (case-sensitive)."""
    return any(fnmatch.fnmatchcase(Point, Glob) for Glob in Globs or ())


# ----------------------------------------------------------------------------- I/O

def DumpJson(Obj):
    """Compact UTF-8 JSON text, keys in insertion order (the Appendix B order)."""
    return json.dumps(Obj, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def WriteJsonAtomic(Path, Obj, Indent=None):
    Tmp = Path + ".tmp"
    with open(Tmp, "w", encoding="utf-8", newline="\n") as Handle:
        if Indent is None:
            Handle.write(DumpJson(Obj))
        else:
            json.dump(Obj, Handle, ensure_ascii=False, indent=Indent)
        Handle.write("\n")
    os.replace(Tmp, Path)


def ReadJson(Path):
    with open(Path, "r", encoding="utf-8") as Handle:
        return json.load(Handle)


def ReadTrace(Path):
    """Yield (line_number, event) for every non-empty line of a trace file."""
    with open(Path, "r", encoding="utf-8") as Handle:
        for Number, Line in enumerate(Handle, 1):
            Line = Line.strip()
            if Line:
                yield Number, json.loads(Line)


def ReadIndex(CaptureDir):
    """The [seq, point, file] list of a capture directory, or of a bare snapshot
    directory without index.json (points are then read from the files)."""
    IndexPath = os.path.join(CaptureDir, "index.json")
    if os.path.isfile(IndexPath):
        return [tuple(Entry) for Entry in ReadJson(IndexPath)]
    SnapDir = os.path.join(CaptureDir, "snapshots")
    if not os.path.isdir(SnapDir):
        SnapDir = CaptureDir
    Entries = []
    for Name in sorted(os.listdir(SnapDir)):
        if Name.endswith(".json") and re.match(r"^\d{5}_", Name):
            Obj = ReadJson(os.path.join(SnapDir, Name))
            Entries.append((Obj.get("seq"), Obj.get("point"),
                            os.path.relpath(os.path.join(SnapDir, Name), CaptureDir)))
    return Entries


def LoadSnapshot(CaptureDir, Entry):
    if Entry[2] is None:
        return None
    return ReadJson(os.path.join(CaptureDir, Entry[2]))


# ----------------------------------------------------------------------------- comparison

def _Key(Value):
    return DumpJson(Value)


def _CompareList(Field, A, B, Limit):
    """First differing index of two ordered lists, plus a short opcode summary."""
    if A == B:
        return None
    First = None
    for Index in range(min(len(A), len(B))):
        if A[Index] != B[Index]:
            First = Index
            break
    if First is None:
        First = min(len(A), len(B))
    Diff = {"field": Field, "kind": "list", "len_a": len(A), "len_b": len(B), "first_index": First,
            "a": A[First] if First < len(A) else None, "b": B[First] if First < len(B) else None}
    import difflib
    KeysA, KeysB = [_Key(X) for X in A], [_Key(X) for X in B]
    Ops = []
    for Tag, I1, I2, J1, J2 in difflib.SequenceMatcher(None, KeysA, KeysB, autojunk=False).get_opcodes():
        if Tag == "equal":
            continue
        Ops.append({"op": Tag, "a_range": [I1, I2], "b_range": [J1, J2],
                    "a_items": A[I1:min(I2, I1 + Limit)], "b_items": B[J1:min(J2, J1 + Limit)]})
        if len(Ops) >= Limit:
            break
    Diff["opcodes"] = Ops
    SetA, SetB = {}, {}
    for Key in KeysA:
        SetA[Key] = SetA.get(Key, 0) + 1
    for Key in KeysB:
        SetB[Key] = SetB.get(Key, 0) + 1
    Diff["same_multiset"] = SetA == SetB
    return Diff


def _ToMap(Triples):
    Map, Duplicates = {}, []
    for Triple in Triples:
        Key = _Key(Triple[0])
        if Key in Map:
            Duplicates.append(Triple[0])
        Map[Key] = (Triple[0], list(Triple[1:]))
    return Map, Duplicates


def _CompareMap(Field, A, B, Limit):
    MapA, DupA = _ToMap(A)
    MapB, DupB = _ToMap(B)
    OnlyA = [MapA[K][0] for K in MapA if K not in MapB]
    OnlyB = [MapB[K][0] for K in MapB if K not in MapA]
    Changed = [{"key": MapA[K][0], "a": MapA[K][1], "b": MapB[K][1]}
               for K in MapA if K in MapB and MapA[K][1] != MapB[K][1]]
    if not OnlyA and not OnlyB and not Changed and not DupA and not DupB:
        return None
    return {"field": Field, "kind": "map", "size_a": len(MapA), "size_b": len(MapB),
            "only_in_a": OnlyA[:Limit], "only_in_b": OnlyB[:Limit], "changed": Changed[:Limit],
            "counts": {"only_in_a": len(OnlyA), "only_in_b": len(OnlyB), "changed": len(Changed)},
            "duplicate_keys_a": DupA[:Limit], "duplicate_keys_b": DupB[:Limit]}


def CompareSnapshots(A, B, Ignore=DEFAULT_IGNORE, Limit=10):
    """S-L2 comparison of two snapshot objects (plan §1.3).

    `all_matches`, `choosers` and `unmatched` are ordered lists compared item by
    item; `matched_primary`, `matched_secondary` and `ratios_cache` are maps.
    `ratios_cache` is compared only when both sides carry it. Returns a list of
    difference records (empty when equal)."""
    Diffs = []
    Ignore = set(Ignore or ())
    for Field in ("schema", "pair", "point", "iteration"):
        if Field in Ignore:
            continue
        if A.get(Field) != B.get(Field):
            Diffs.append({"field": Field, "kind": "value", "a": A.get(Field), "b": B.get(Field)})
    if "flags" not in Ignore:
        FlagsA, FlagsB = A.get("flags") or {}, B.get("flags") or {}
        for Name in sorted(set(FlagsA) | set(FlagsB)):
            if FlagsA.get(Name) != FlagsB.get(Name):
                Diffs.append({"field": "flags." + Name, "kind": "value",
                              "a": FlagsA.get(Name), "b": FlagsB.get(Name)})
    if "all_matches" not in Ignore:
        MatchesA, MatchesB = A.get("all_matches") or {}, B.get("all_matches") or {}
        for Name in list(LISTS) + sorted((set(MatchesA) | set(MatchesB)) - set(LISTS)):
            Diff = _CompareList("all_matches." + Name, MatchesA.get(Name, []), MatchesB.get(Name, []), Limit)
            if Diff:
                Diffs.append(Diff)
    for Field in ("matched_primary", "matched_secondary"):
        if Field in Ignore:
            continue
        Diff = _CompareMap(Field, A.get(Field) or [], B.get(Field) or [], Limit)
        if Diff:
            Diffs.append(Diff)
    if "ratios_cache" not in Ignore and "ratios_cache" in A and "ratios_cache" in B:
        Diff = _CompareMap("ratios_cache", A["ratios_cache"], B["ratios_cache"], Limit)
        if Diff:
            Diffs.append(Diff)
    if "choosers" not in Ignore and ("choosers" in A or "choosers" in B):
        ChA, ChB = A.get("choosers"), B.get("choosers")
        if ChA is None or ChB is None:
            Diffs.append({"field": "choosers", "kind": "presence", "a": ChA is not None, "b": ChB is not None})
        else:
            for Name in list(CHOOSERS) + sorted((set(ChA) | set(ChB)) - set(CHOOSERS)):
                Diff = _CompareList("choosers." + Name, ChA.get(Name, []), ChB.get(Name, []), Limit)
                if Diff:
                    Diffs.append(Diff)
    if "unmatched" not in Ignore and ("unmatched" in A or "unmatched" in B):
        UnA, UnB = A.get("unmatched"), B.get("unmatched")
        if UnA is None or UnB is None:
            Diffs.append({"field": "unmatched", "kind": "presence", "a": UnA is not None, "b": UnB is not None})
        else:
            for Name in UNMATCHED:
                ListA, ListB = UnA.get(Name), UnB.get(Name)
                if (ListA is None) != (ListB is None):
                    Diffs.append({"field": "unmatched." + Name, "kind": "null", "a": ListA, "b": ListB})
                elif ListA is not None:
                    Diff = _CompareList("unmatched." + Name, ListA, ListB, Limit)
                    if Diff:
                        Diffs.append(Diff)
    return Diffs


def FormatDifferences(Diffs, Limit=10):
    Lines = []
    for Diff in Diffs:
        if Diff["kind"] == "list":
            Lines.append("  %s: lengths %d vs %d, first difference at index %d%s" % (
                Diff["field"], Diff["len_a"], Diff["len_b"], Diff["first_index"],
                " (same multiset: order only)" if Diff.get("same_multiset") else ""))
            Lines.append("    a[%d] = %s" % (Diff["first_index"], DumpJson(Diff["a"])))
            Lines.append("    b[%d] = %s" % (Diff["first_index"], DumpJson(Diff["b"])))
            for Op in Diff.get("opcodes", [])[:Limit]:
                Lines.append("    %-7s a[%d:%d] b[%d:%d]" % (Op["op"], Op["a_range"][0], Op["a_range"][1],
                                                        Op["b_range"][0], Op["b_range"][1]))
                for Item in Op["a_items"][:3]:
                    Lines.append("      - %s" % DumpJson(Item))
                for Item in Op["b_items"][:3]:
                    Lines.append("      + %s" % DumpJson(Item))
        elif Diff["kind"] == "map":
            Lines.append("  %s: sizes %d vs %d; only in a %d, only in b %d, changed %d" % (
                Diff["field"], Diff["size_a"], Diff["size_b"], Diff["counts"]["only_in_a"],
                Diff["counts"]["only_in_b"], Diff["counts"]["changed"]))
            for Key in Diff["only_in_a"][:Limit]:
                Lines.append("    - %s" % DumpJson(Key))
            for Key in Diff["only_in_b"][:Limit]:
                Lines.append("    + %s" % DumpJson(Key))
            for Change in Diff["changed"][:Limit]:
                Lines.append("    ~ %s: %s -> %s" % (DumpJson(Change["key"]), DumpJson(Change["a"]),
                                                    DumpJson(Change["b"])))
            if Diff["duplicate_keys_a"] or Diff["duplicate_keys_b"]:
                Lines.append("    duplicate keys: a %s b %s" % (Diff["duplicate_keys_a"], Diff["duplicate_keys_b"]))
        else:
            Lines.append("  %s: %s vs %s" % (Diff["field"], DumpJson(Diff.get("a")), DumpJson(Diff.get("b"))))
    return "\n".join(Lines)


# ----------------------------------------------------------------------------- .diaphora files

# save_results (diaphora.py:2383-2424), verbatim DDL and statements.
_DDL = (
    "create table config (main_db text, diff_db text, version text, date text)",
    """create table results (type, line, address, name, address2, name2,
                   ratio, nodes1, nodes2, description)""",
    "create unique index uq_results on results(address, address2)",
    "create table unmatched (type, line, address, name)",
)
_RESULTS_SQL = "insert or ignore into results values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
_UNMATCHED_SQL = "insert into unmatched values (?, ?, ?, ?)"


def ChooserRow(Index, Item):
    """One results-chooser item formatted exactly as CChooser.add_item does
    (diaphora.py:275-296): "%05lu" line, "%08x" addresses, "%.7f" ratio
    (DECIMAL_VALUES = "7f", diaphora_config.py:120), "%d" nodes."""
    Ea, Name, Ea2, Name2, Desc, Bits, Nodes1, Nodes2 = Item
    return ["%05lu" % Index, "%08x" % int(Ea), Name, "%08x" % int(Ea2), Name2,
            "%.7f" % BitsToFloat(Bits), "%d" % Nodes1, "%d" % Nodes2, Desc]


def UnmatchedRow(Index, Item):
    """One "Unmatched in ..." chooser item, as CChooser.add_item formats it."""
    Ea, Name = Item
    return ["%05lu" % Index, "%08x" % int(Ea), Name]


def RowsFromDumps(Choosers, Unmatched):
    """Rebuild the results and unmatched tables from the raw chooser dumps of
    after:final_pass and after:find_unmatched, through the same DDL and the same
    `insert or ignore` as save_results, so rows dropped by uq_results are
    dropped here too. Returns (results rows, unmatched rows) in rowid order."""
    Handle = sqlite3.connect(":memory:")
    try:
        for Sql in _DDL:
            Handle.execute(Sql)
        for Category in CHOOSERS:
            for Index, Item in enumerate(Choosers.get(Category) or []):
                Handle.execute(_RESULTS_SQL, [Category] + ChooserRow(Index, Item))
        for Category in UNMATCHED:
            Items = (Unmatched or {}).get(Category)
            if Items is None:
                continue
            for Index, Item in enumerate(Items):
                Handle.execute(_UNMATCHED_SQL, [Category] + UnmatchedRow(Index, Item))
        return ReadTables(Handle)
    finally:
        Handle.close()


def ReadTables(Handle):
    Results = Handle.execute("select type, line, address, name, address2, name2, ratio, nodes1, nodes2, "
                             "description from results order by rowid").fetchall()
    Unmatched = Handle.execute("select type, line, address, name from unmatched order by rowid").fetchall()
    return Results, Unmatched


def ReadDiaphora(Path):
    """(results, unmatched, config) of a .diaphora file, rows in stored order."""
    Handle = sqlite3.connect(pathlib.Path(os.path.abspath(Path)).as_uri() + "?mode=ro", uri=True)
    try:
        Results, Unmatched = ReadTables(Handle)
        Config = Handle.execute("select main_db, diff_db, version, date from config").fetchall()
        return Results, Unmatched, Config
    finally:
        Handle.close()


def CompareRowLists(A, B, Limit=5):
    """Stored-order comparison of two row lists."""
    Report = {"identical_in_order": A == B, "rows_a": len(A), "rows_b": len(B)}
    if A != B:
        First = next((I for I in range(min(len(A), len(B))) if A[I] != B[I]), min(len(A), len(B)))
        Report["first_difference"] = {"index": First,
                                      "a": list(A[First]) if First < len(A) else None,
                                      "b": list(B[First]) if First < len(B) else None}
        Report["identical_as_multiset"] = sorted(map(repr, A)) == sorted(map(repr, B))
    return Report
