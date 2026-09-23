#!/usr/bin/env python3
"""Generate the lane L3 text-diff vectors (docs/parity/00-plan.md §4 L3).

Two modes:

  --synthetic [--out <dir>]   committed, synthetic vectors (default <repo>/tests/diff/vectors/textdiff):
      udiff_fuzz.txt          >= 10,000 random unified_diff cases (lengths 0-1000, the 199/200/201 and
                              299/300/301 boundaries, planted popular counts at exactly ntest / ntest+1,
                              small alphabets, popular tails, n in {0,1,2,3,5}, lineterm "" or "\\n").
                              Inputs are NOT stored: both sides regenerate them from SplitMix64 (see
                              PRNG / UDIFF CASE below); the file stores per case the matching-block count,
                              the unified_diff row count and the CASE hash. `--dump-case K` prints case K
                              in full for debugging.
      udiff_examples.jsonl    small cases stored in full (inputs, rows, blocks, opcodes, grouped opcodes and
                              the opcode cache as get_grouped_opcodes leaves it,
                              find_longest_match on the full range, ratio / quick_ratio / real_quick_ratio
                              IEEE bits).
      splitlines_fuzz.txt     SplitMix64 strings over a fragment table (all 10 line breaks, "\\r\\n",
                              near-miss code points); per block of 1000 strings the hash of every
                              str.splitlines() and str.split("\\n") result.
      splitlines_examples.jsonl  explicit strings with both results.
      names_fuzz.txt          120,000 SplitMix64 strings (fragments include U+0130 U+0131 U+017F U+212A,
                              their UTF-8 near neighbours and other scripts); per block of 1000 strings the
                              hash of every re.findall(CPP_NAMES_RE, s, re.IGNORECASE)[i][0] list.
      names_examples.jsonl    explicit strings with their findall lists.
    The fragment tables live in the header line of each *_fuzz.txt, so the C++ test reads them from the
    file instead of keeping a second copy.

  --corpus <root>             corpus acceptance vectors under <root>/oracle/vectors/textdiff/ (never
                              committed). For every finished oracle pair (run1/<pair>.diaphora present):
                              every `results` row (all types), for field assembly and pseudocode when both
                              are non-NULL TEXT, the row count and sha256 of
                              difflib.unified_diff(a.splitlines(), b.splitlines(), lineterm="") exactly as
                              diaphora.py:3040-3042 computes it; plus a deterministic sample of unmatched
                              cross pairs (kind "sample") for extra coverage. Only addresses, counts and
                              hashes are written.

HASHES (shared with tests/diff/textdiff_tests.cpp):
  frame(x)       = ascii(len(x_utf8)) + ":" + x_utf8 + "\\n"
  frame_list(xs) = ascii(len(xs)) + "#" + concat(frame(x) for x in xs)
  ROWS           = sha256(concat(frame(row) for row in rows))       (full 64 hex in the corpus files)
  BLOCKS         = sha256(concat("%d,%d,%d\\n" % (i, j, k) for each block))
  AUX            = sha256("%d,%d,%d;%s;%s;%s" % (flm.a, flm.b, flm.size,
                          bits(ratio), bits(quick_ratio), bits(real_quick_ratio)))
  CASE           = sha256(hex(BLOCKS) + hex(ROWS) + hex(AUX))        (first 16 hex in udiff_fuzz.txt)
  flm            = find_longest_match(0, len(a), 0, len(b)) of a fresh SequenceMatcher(None, a, b)
  bits(x)        = struct.pack(">d", x).hex()
  string block   = sha256(concat(frame_list(result) for each string in the block))

PRNG: SplitMix64 (state += 0x9E3779B97F4A7C15; z = (z ^ z>>30) * 0xBF58476D1CE4E5B9;
  z = (z ^ z>>27) * 0x94D049BB133111EB; return z ^ z>>31, all mod 2^64); below(n) = next() % n;
  pick(seq) = seq[below(len(seq))]. Per-case / per-string seed = (BASE ^ (index * 0xD1B54A32D192ED03)) mod 2^64.
  Every PRNG call below is made in exactly this order on the C++ side; do not reorder expressions.

The script refuses to run unless difflib.py has md5 60d095550edf66222f142d8bbb9feff5 (03b §1).

Usage:
  python -B tools/parity/gen_textdiff_vectors.py --synthetic
  python -B tools/parity/gen_textdiff_vectors.py --corpus <corpus-root>   (or DSIG_CORPUS_ROOT)
"""

import argparse
import difflib
import hashlib
import json
import os
import random
import re
import sqlite3
import struct
import sys
import time

sys.dont_write_bytecode = True

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
DIFFLIB_MD5 = "60d095550edf66222f142d8bbb9feff5"
CPP_NAMES_RE = "([a-zA-Z_][a-zA-Z0-9_]{3,}((::){0,1}[a-zA-Z0-9_]+)*)"  # diaphora.py:114

MASK64 = (1 << 64) - 1
SEED_MIX = 0xD1B54A32D192ED03

UDIFF_SEED = 0x5EED0003D1FF0001
UDIFF_CASES = 12000
UDIFF_EXAMPLE_SEED = 0x5EED0003D1FF0002
UDIFF_EXAMPLES = 200
UDIFF_LARGE_EXAMPLES = 8

SPLIT_SEED = 0x5EED0003511E0001
SPLIT_STRINGS = 40000
SPLIT_EXAMPLE_SEED = 0x5EED0003511E0002
SPLIT_EXAMPLES = 600

NAMES_SEED = 0x5EED00034A3E0001
NAMES_STRINGS = 120000
NAMES_EXAMPLE_SEED = 0x5EED00034A3E0002
NAMES_EXAMPLES = 1000

BLOCK = 1000

SPLIT_FRAGMENTS = [
    "a", "bc", "x", " ", "\t", "\x00", "\n", "\r", "\r\n", "\n\r", "\v", "\f", "\x1c", "\x1d", "\x1e",
    "\x1f", "\x1b", "\x85", "\x84", "\x86", "\u2028", "\u2029", "\u2027", "\u202a", "\u00e9", "\u4e2d",
    "\U0001f600", "\u0130", "\u00c2", "\u00e2", "\u2080", "\u20a8", "call sub_401000", "",
]

NAMES_FRAGMENTS = (
    list("abcdefhxvAFHXVKksSiI0123456789_:;#.+- \t\r\n,[]()*&<>")
    + ["sub_", "loc_", "nullsub_", "j_", "::", ":::", "std::", "call ", "push ", "qword", "0x401000",
       "12abcd", "Foo::Barbaz::x", "abc::defg",
       "\u0130", "\u0131", "\u017f", "\u212a",                     # the four re.I extras
       "\u012f", "\u0132", "\u0100", "\u013f", "\u017e", "\u0180", "\u0149", "\u2129", "\u212b", "\u2126",
       "\u00e9", "\u00df", "\u1e9e", "\u0345", "\u03a3", "\u03c2", "\u4e2d", "\U0001f600", "\u0085",
       "\u2028", "\uff21", "\u0661", "\u00b2", "\u00aa", "\u00ba"]
)


# ------------------------------------------------------------------------------------------------ PRNG
class SplitMix64:
    def __init__(self, seed):
        self.state = seed & MASK64

    def next(self):
        self.state = (self.state + 0x9E3779B97F4A7C15) & MASK64
        z = self.state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK64
        return z ^ (z >> 31)

    def below(self, n):
        return self.next() % n

    def pick(self, seq):
        return seq[self.below(len(seq))]


def case_rng(base, index):
    return SplitMix64(base ^ ((index * SEED_MIX) & MASK64))


# ------------------------------------------------------------------------------------------------ hashes
def frame(text):
    data = text.encode("utf-8")
    return str(len(data)).encode("ascii") + b":" + data + b"\n"


def frame_list(items):
    return str(len(items)).encode("ascii") + b"#" + b"".join(frame(x) for x in items)


def rows_hash(rows):
    h = hashlib.sha256()
    for row in rows:
        h.update(frame(row))
    return h.hexdigest()


def blocks_hash(blocks):
    h = hashlib.sha256()
    for i, j, k in blocks:
        h.update(("%d,%d,%d\n" % (i, j, k)).encode("ascii"))
    return h.hexdigest()


def bits(x):
    return struct.pack(">d", float(x)).hex()


def aux_hash(flm, r, q, rq):
    text = "%d,%d,%d;%s;%s;%s" % (flm[0], flm[1], flm[2], bits(r), bits(q), bits(rq))
    return hashlib.sha256(text.encode("ascii")).hexdigest()


def case_hash(blocks, rows, flm, r, q, rq):
    text = blocks_hash(blocks) + rows_hash(rows) + aux_hash(flm, r, q, rq)
    return hashlib.sha256(text.encode("ascii")).hexdigest()


# ------------------------------------------------------------------------------------------------ udiff
def token_text(k):
    # injective: "" only for 0, a non-ASCII prefix for k % 11 == 5, "L<k>" otherwise
    if k == 0:
        return ""
    if k % 11 == 5:
        return "\u00e9" + str(k)
    return "L" + str(k)


def gen_length(rng, cap):
    r = rng.below(100)
    if r < 30:
        n = rng.below(21)
    elif r < 50:
        n = 190 + rng.below(21)
    elif r < 60:
        n = rng.pick([199, 200, 201])
    elif r < 85:
        n = rng.below(301)
    else:
        n = rng.below(1001)
    return min(n, cap)


def gen_udiff_case(rng, cap=1000):
    """UDIFF CASE. Returns (a_tokens, b_tokens, n, lineterm). Mirrored in textdiff_tests.cpp."""
    alpha = rng.pick([1, 2, 3, 5, 10, 40, 400])
    pool = []
    for _ in range(alpha + 1):
        pool.append(rng.below(alpha + 1))

    def elem():
        if rng.below(10) < 7:
            return rng.pick(pool)
        return pool[0]

    def edit(seq):
        count = rng.below(31)
        for _ in range(count):
            op = rng.below(3)
            if op == 0:
                if seq:
                    del seq[rng.below(len(seq))]
            elif op == 1:
                pos = rng.below(len(seq) + 1)
                e = elem()
                seq.insert(pos, e)
            else:
                if seq:
                    pos = rng.below(len(seq))
                    e = elem()
                    seq[pos] = e

    mode = rng.below(4)
    la = gen_length(rng, cap)
    a = []
    for _ in range(la):
        a.append(elem())
    if mode == 0 or mode == 3:
        b = list(a)
        edit(b)
        if rng.below(10) < 3:
            tail = rng.below(301)
            b.extend([pool[0]] * tail)
    elif mode == 1:
        lb = gen_length(rng, cap)
        b = []
        for _ in range(lb):
            b.append(elem())
    else:
        target = rng.pick([199, 200, 201, 299, 300, 301])
        b = list(a)
        edit(b)
        while len(b) < target:
            pos = rng.below(len(b) + 1)
            e = elem()
            b.insert(pos, e)
        del b[target:]
        ntest = target // 100 + 1
        want = ntest + rng.below(2)
        planted = alpha + 1
        for _ in range(want):
            idx = rng.below(len(b))
            while b[idx] == planted:
                idx = (idx + 1) % len(b)
            b[idx] = planted
        for _ in range(rng.below(4)):
            if a:
                a[rng.below(len(a))] = planted
    if len(b) > cap:
        del b[cap:]
    if mode == 3:
        a, b = b, a
    n = 3 if rng.below(10) < 8 else rng.pick([0, 1, 2, 5])
    lineterm = "" if rng.below(10) < 9 else "\n"
    return a, b, n, lineterm


def udiff_eval(a_tok, b_tok, n, lineterm):
    a = [token_text(k) for k in a_tok]
    b = [token_text(k) for k in b_tok]
    rows = list(difflib.unified_diff(a, b, n=n, lineterm=lineterm))
    sm = difflib.SequenceMatcher(None, a, b)
    blocks = [tuple(x) for x in sm.get_matching_blocks()]
    flm = tuple(sm.find_longest_match(0, len(a), 0, len(b)))
    sm2 = difflib.SequenceMatcher(None, a, b)
    opcodes = [list(x) for x in sm2.get_opcodes()]
    sm3 = difflib.SequenceMatcher(None, a, b)
    grouped = [[list(op) for op in g] for g in sm3.get_grouped_opcodes(n)]
    opcodes_after = [list(x) for x in sm3.get_opcodes()]   # get_grouped_opcodes trims the cached list
    r = difflib.SequenceMatcher(None, a, b).ratio()
    q = difflib.SequenceMatcher(None, a, b).quick_ratio()
    rq = difflib.SequenceMatcher(None, a, b).real_quick_ratio()
    return a, b, rows, blocks, flm, opcodes, grouped, r, q, rq, opcodes_after


def write_udiff(out_dir):
    t0 = time.time()
    path = os.path.join(out_dir, "udiff_fuzz.txt")
    lengths = 0
    with open(path, "w", encoding="ascii", newline="\n") as f:
        f.write("# gen_textdiff_vectors.py udiff_fuzz v1: one line per case (case k = k-th line after 'seed'):\n")
        f.write("# <nblocks> <nrows> <first 16 hex of CASE = sha256(BLOCKS_hex + ROWS_hex + AUX_hex)>\n")
        f.write("# difflib.py md5 %s, python %s\n" % (DIFFLIB_MD5, sys.version.split()[0]))
        f.write("seed %d cases %d\n" % (UDIFF_SEED, UDIFF_CASES))
        for k in range(UDIFF_CASES):
            a_tok, b_tok, n, lt = gen_udiff_case(case_rng(UDIFF_SEED, k))
            lengths += len(a_tok) + len(b_tok)
            a, b, rows, blocks, flm, _, _, r, q, rq, _ = udiff_eval(a_tok, b_tok, n, lt)
            f.write("%d %d %s\n" % (len(blocks), len(rows), case_hash(blocks, rows, flm, r, q, rq)[:16]))
    print("udiff_fuzz: %d cases, %d elements, %.1fs" % (UDIFF_CASES, lengths, time.time() - t0))

    path = os.path.join(out_dir, "udiff_examples.jsonl")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        for k in range(UDIFF_EXAMPLES):
            rng = case_rng(UDIFF_EXAMPLE_SEED, k)
            cap = 20 if k < UDIFF_EXAMPLES - UDIFF_LARGE_EXAMPLES else 210
            a_tok, b_tok, n, lt = gen_udiff_case(rng, cap)
            a, b, rows, blocks, flm, opcodes, grouped, r, q, rq, after = udiff_eval(a_tok, b_tok, n, lt)
            rec = {"case": k, "a": a, "b": b, "n": n, "lineterm": lt, "rows": rows,
                   "blocks": [list(x) for x in blocks], "opcodes": opcodes, "grouped": grouped,
                   "opcodes_after_grouped": after,
                   "flm": list(flm), "ratio": bits(r), "quick_ratio": bits(q), "real_quick_ratio": bits(rq)}
            f.write(json.dumps(rec, ensure_ascii=True) + "\n")
    print("udiff_examples: %d cases" % UDIFF_EXAMPLES)


# ------------------------------------------------------------------------------------------------ strings
def gen_string(rng, fragments, max_frags):
    count = rng.below(max_frags + 1)
    parts = []
    for _ in range(count):
        parts.append(rng.pick(fragments))
    return "".join(parts)


def names_of(s):
    return [m[0] for m in re.findall(CPP_NAMES_RE, s, re.IGNORECASE)]


def write_strings(out_dir):
    # splitlines / split("\n")
    t0 = time.time()
    header = {"seed": SPLIT_SEED, "strings": SPLIT_STRINGS, "block": BLOCK, "max_fragments": 24,
              "fragments": SPLIT_FRAGMENTS}
    with open(os.path.join(out_dir, "splitlines_fuzz.txt"), "w", encoding="ascii", newline="\n") as f:
        f.write("# gen_textdiff_vectors.py splitlines_fuzz v1: <block> <strings> <pieces> <splitlines16> <splitnl16>\n")
        f.write(json.dumps(header, ensure_ascii=True) + "\n")
        for blk in range(SPLIT_STRINGS // BLOCK):
            h1 = hashlib.sha256()
            h2 = hashlib.sha256()
            pieces = 0
            for i in range(blk * BLOCK, (blk + 1) * BLOCK):
                s = gen_string(case_rng(SPLIT_SEED, i), SPLIT_FRAGMENTS, 24)
                sl = s.splitlines()
                sn = s.split("\n")
                pieces += len(sl)
                h1.update(frame_list(sl))
                h2.update(frame_list(sn))
            f.write("%d %d %d %s %s\n" % (blk, BLOCK, pieces, h1.hexdigest()[:16], h2.hexdigest()[:16]))
    with open(os.path.join(out_dir, "splitlines_examples.jsonl"), "w", encoding="utf-8", newline="\n") as f:
        handmade = ["", "\n", "a", "a\n", "a\n\n", "a\n\r", "a\r\r\n", "a\r\nb", "\r\n", "\n\r", "\r\r",
                    "a\x0bb\x1cc\u2028d\r\ne", "xyz\x0bq\x1cr\u2028s", "a\x85b", "a\u2029", "a\u2027b",
                    "a\x1fb", "a\x84b\x86c", "\n\n\n", "x\ry\nz\r\n", "\u2028\u2029\x85", "a\n\u00e9\r\n\u4e2d"]
        for sep in ["\n", "\x0b", "\x0c", "\r", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029", "\r\n"]:
            handmade += [sep, "a" + sep, sep + "a", "a" + sep + "b", "a" + sep + sep + "b", sep * 3]
        strings = handmade + [gen_string(case_rng(SPLIT_EXAMPLE_SEED, i), SPLIT_FRAGMENTS, 12)
                              for i in range(SPLIT_EXAMPLES)]
        for s in strings:
            f.write(json.dumps({"s": s, "splitlines": s.splitlines(), "split_nl": s.split("\n")},
                               ensure_ascii=True) + "\n")
    print("splitlines: %d fuzz strings, %d examples, %.1fs" % (SPLIT_STRINGS, len(strings), time.time() - t0))

    # CPP_NAMES_RE
    t0 = time.time()
    header = {"seed": NAMES_SEED, "strings": NAMES_STRINGS, "block": BLOCK, "max_fragments": 40,
              "fragments": NAMES_FRAGMENTS}
    specials = 0
    with open(os.path.join(out_dir, "names_fuzz.txt"), "w", encoding="ascii", newline="\n") as f:
        f.write("# gen_textdiff_vectors.py names_fuzz v1: <block> <strings> <matches> <names16>\n")
        f.write(json.dumps(header, ensure_ascii=True) + "\n")
        for blk in range(NAMES_STRINGS // BLOCK):
            h = hashlib.sha256()
            matches = 0
            for i in range(blk * BLOCK, (blk + 1) * BLOCK):
                s = gen_string(case_rng(NAMES_SEED, i), NAMES_FRAGMENTS, 40)
                names = names_of(s)
                matches += len(names)
                specials += sum(1 for m in names if any(c in m for c in "\u0130\u0131\u017f\u212a"))
                h.update(frame_list(names))
            f.write("%d %d %d %s\n" % (blk, BLOCK, matches, h.hexdigest()[:16]))
    with open(os.path.join(out_dir, "names_examples.jsonl"), "w", encoding="utf-8", newline="\n") as f:
        handmade = ["call Foo::Barbaz::x", "call abc::defg", "push qword ptr [rax]", "mov eax, 0x401000",
                    "12abcd", "jmp mov call push lea test", "std::vector::push_back",
                    "0x401000 call sub_401000 ab_c", "\u017fub_1234", "\u212aernel", "\u0130\u0131\u017f\u212a",
                    "\u0130\u0131\u017f", "abc", "abcd", "abcd::", "abcd::e", "abcd:::e", "abcd::::e", "a::bcde",
                    "abcd::\u0130x", "\u00e9abcd", "ab\u00e9cdef", "abcd\n::efg", "nullsub_12", "__imp_Foo",
                    "", "::", "____", "_1234", "1234", "call    j_sub_1800\u212a0", "\u4e2dabcd\u4e2d"]
        strings = handmade + [gen_string(case_rng(NAMES_EXAMPLE_SEED, i), NAMES_FRAGMENTS, 30)
                              for i in range(NAMES_EXAMPLES)]
        for s in strings:
            f.write(json.dumps({"s": s, "names": names_of(s)}, ensure_ascii=True) + "\n")
    print("names: %d fuzz strings (%d matches with a special letter), %d examples, %.1fs"
          % (NAMES_STRINGS, specials, len(strings), time.time() - t0))


# ------------------------------------------------------------------------------------------------ corpus
def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def ro(path):
    # immutable=1: no -shm/-wal is created or touched next to the oracle files (their -wal files are
    # empty, tools/parity/README.md), so the reader sees exactly the main database file.
    return sqlite3.connect("file:" + path.replace("\\", "/") + "?mode=ro&immutable=1", uri=True)


def load_functions(path):
    con = ro(path)
    try:
        rows = con.execute("select id, address, typeof(assembly), assembly, typeof(pseudocode), pseudocode "
                           "from functions order by id").fetchall()
    finally:
        con.close()
    by_int = {}
    for rid, address, ta, asm, tp, pseudo in rows:
        by_int.setdefault(int(address), []).append((address, ta, asm, tp, pseudo))
    return rows, by_int


def diff_record(kind, field, addr1, addr2, v1, v2):
    lines1 = v1.splitlines()          # diaphora.py:3040
    lines2 = v2.splitlines()          # diaphora.py:3041
    rows = list(difflib.unified_diff(lines1, lines2, lineterm=""))   # diaphora.py:3042
    return "%s\t%s\t%s\t%s\t%d\t%d\t%d\t%s\n" % (kind, field, addr1, addr2, len(lines1), len(lines2), len(rows),
                                                   rows_hash(rows))


def write_corpus(corpus, sample_per_pair, max_sample_lines):
    oracle = os.path.join(corpus, "oracle")
    manifest = json.load(open(os.path.join(oracle, "manifest.json"), encoding="utf-8"))
    out_dir = os.path.join(oracle, "vectors", "textdiff")
    os.makedirs(out_dir, exist_ok=True)
    summary = {"generator": "gen_textdiff_vectors.py --corpus v1", "difflib_md5": DIFFLIB_MD5,
               "python": sys.version, "sqlite": sqlite3.sqlite_version, "pairs": {}}
    for pair, info in manifest["diffs"].items():
        results = os.path.join(oracle, "diffs", pair, "run1", pair + ".diaphora")
        if not os.path.isfile(results):
            summary["pairs"][pair] = {"status": "no run1 results (pending)"}
            print("%s: skipped, no run1 results" % pair)
            continue
        t0 = time.time()
        ref, target = info["ref"], info["target"]
        p1 = os.path.join(oracle, "exports", ref, ref + ".sqlite")
        p2 = os.path.join(oracle, "exports", target, target + ".sqlite")
        s1, s2 = sha256_file(p1), sha256_file(p2)
        for exp, sha in ((ref, s1), (target, s2)):
            want = manifest["exports"][exp].get("sqlite_sha256")
            if want and want != sha:
                raise SystemExit("export %s sha256 %s differs from the manifest %s" % (exp, sha, want))
        rows1, map1 = load_functions(p1)
        rows2, map2 = load_functions(p2)
        con = ro(results)
        try:
            res = con.execute("select type, address, address2 from results order by rowid").fetchall()
        finally:
            con.close()
        counts = {"results_rows": len(res), "matched": 0, "null_field": 0, "not_text": 0, "unresolved": 0,
                  "sample": 0}
        out_path = os.path.join(out_dir, "udiff_corpus_%s.txt" % pair)
        with open(out_path, "w", encoding="utf-8", newline="\n") as f:
            f.write("# gen_textdiff_vectors.py --corpus v1: kind field address1 address2 lines1 lines2 nrows rows_sha256\n")
            f.write("pair\t%s\nmain\t%s\t%s\ndiff\t%s\t%s\n" % (pair, ref, s1, target, s2))
            matched_keys = set()
            for typ, a1hex, a2hex in res:
                c1 = map1.get(int(a1hex, 16), [])
                c2 = map2.get(int(a2hex, 16), [])
                if len(c1) != 1 or len(c2) != 1:
                    counts["unresolved"] += 1
                    continue
                (addr1, ta1, asm1, tp1, ps1), (addr2, ta2, asm2, tp2, ps2) = c1[0], c2[0]
                matched_keys.add((addr1, addr2))
                for field, t1, v1, t2, v2 in (("assembly", ta1, asm1, ta2, asm2), ("pseudocode", tp1, ps1, tp2, ps2)):
                    if v1 is None or v2 is None:
                        counts["null_field"] += 1
                        continue
                    if t1 != "text" or t2 != "text":
                        counts["not_text"] += 1   # bytes.splitlines differs; none expected in the corpus
                        continue
                    f.write(diff_record("matched", field, addr1, addr2, v1, v2))
                    counts["matched"] += 1
            # deterministic sample of cross pairs (not results rows) for extra coverage
            rnd = random.Random("textdiff-sample-" + pair)
            cand1 = [r for r in rows1 if r[3] is not None and r[2] == "text"]
            cand2 = [r for r in rows2 if r[3] is not None and r[2] == "text"]
            tries = 0
            while counts["sample"] < sample_per_pair and cand1 and cand2 and tries < sample_per_pair * 20:
                tries += 1
                r1, r2 = rnd.choice(cand1), rnd.choice(cand2)
                if (r1[1], r2[1]) in matched_keys:
                    continue
                for field, i1, i2 in (("assembly", 3, 3), ("pseudocode", 5, 5)):
                    v1, v2 = r1[i1], r2[i2]
                    if v1 is None or v2 is None or r1[i1 - 1] != "text" or r2[i2 - 1] != "text":
                        continue
                    if v1.count("\n") > max_sample_lines or v2.count("\n") > max_sample_lines:
                        continue
                    f.write(diff_record("sample", field, r1[1], r2[1], v1, v2))
                    counts["sample"] += 1
        counts["seconds"] = round(time.time() - t0, 1)
        summary["pairs"][pair] = counts
        print("%s: %s" % (pair, counts))
    with open(os.path.join(out_dir, "summary.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(summary, f, indent=1)


# ------------------------------------------------------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--synthetic", action="store_true", help="write the committed synthetic vectors")
    ap.add_argument("--out", default=os.path.join(REPO, "tests", "diff", "vectors", "textdiff"))
    ap.add_argument("--corpus", nargs="?", const=os.environ.get("DSIG_CORPUS_ROOT", ""),
                    help="corpus root (default DSIG_CORPUS_ROOT); writes <corpus>/oracle/vectors/textdiff")
    ap.add_argument("--sample", type=int, default=400, help="sampled cross pairs per oracle pair (corpus)")
    ap.add_argument("--max-sample-lines", type=int, default=4000)
    ap.add_argument("--dump-case", type=int, metavar="K", help="print udiff_fuzz case K in full and exit")
    args = ap.parse_args()

    if args.dump_case is not None:
        a_tok, b_tok, n, lt = gen_udiff_case(case_rng(UDIFF_SEED, args.dump_case))
        a, b, rows, blocks, flm, opcodes, grouped, r, q, rq, _ = udiff_eval(a_tok, b_tok, n, lt)
        line = "%d %d %s" % (len(blocks), len(rows), case_hash(blocks, rows, flm, r, q, rq)[:16])
        print(json.dumps({"case": args.dump_case, "line": line, "a": a, "b": b, "n": n, "lineterm": lt,
                          "blocks": blocks, "flm": flm, "opcodes": opcodes, "rows": rows, "ratio": bits(r),
                          "quick_ratio": bits(q), "real_quick_ratio": bits(rq)}, ensure_ascii=True))
        return

    md5 = hashlib.md5(open(difflib.__file__, "rb").read()).hexdigest()
    if md5 != DIFFLIB_MD5:
        raise SystemExit("difflib.py md5 %s != %s (03b §1); wrong Python" % (md5, DIFFLIB_MD5))
    if not args.synthetic and args.corpus is None:
        ap.error("give --synthetic and/or --corpus")
    if args.synthetic:
        os.makedirs(args.out, exist_ok=True)
        write_udiff(args.out)
        write_strings(args.out)
    if args.corpus is not None:
        if not args.corpus:
            ap.error("--corpus needs a path or DSIG_CORPUS_ROOT")
        write_corpus(args.corpus, args.sample, args.max_sample_lines)


if __name__ == "__main__":
    main()
