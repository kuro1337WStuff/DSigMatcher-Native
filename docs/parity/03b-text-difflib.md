# 03b: Text normalisation, difflib and graph comparison (porting spec)

> **Historical spec.** Written on 2026-09-23 against an earlier revision (`34ed418`), before the port existed; its status remarks ("not implemented", test counts, runs "still running", open questions) are historical. See [README.md](README.md) in this directory for how to read it; quoted Diaphora code is (c) Joxean Koret, AGPL-3.0-or-later, and quoted CPython `difflib` code is under the PSF License Version 2.

**Summary**

1. **The diff never normalises text.** `get_cmp_asm`, `get_cmp_asm_lines` and `get_cmp_pseudo_lines` run only at export time, from `diaphora_ida.py`. Their output is stored in `functions.clean_assembly`, `clean_pseudo` and `clean_microcode`. The native `diff` must read those columns byte for byte. Section 3 matters only when DSigMatcher writes its own exports.
2. **The only difflib call on the default ratio path is `SequenceMatcher.quick_ratio()`** on `text.split("\n")`, inside `check_ratio`. It is an order-free multiset overlap: `2*Σ_x min(count_a(x), count_b(x)) / (len_a+len_b)`. Autojunk and tie-breaking do not affect it. The result is rounded with `"{0:.7f}".format` and parsed back to a float.
3. **The full SequenceMatcher algorithm runs at diff time only inside `difflib.unified_diff`.** That covers autojunk, `find_longest_match` tie-breaking, matching blocks, opcodes and grouped opcodes. `unified_diff` is called by the "Callee found diffing matches pseudo-code/assembly" heuristics, which run by default on every outer iteration of the diff loop. These heuristics need exact difflib parity, including the autojunk rule for sequences of 200 lines or more.
4. **`ratio()` and `real_quick_ratio()` do not run under the default config.** ML and relaxed ratio are both off.
5. **`compare_graphs_pass`, `compare_graphs`, `get_graph` and `prettify_asm` are IDA UI only.** They never change a match.
6. **jkutils:** `factor.difference()` runs by default whenever the two `program.callgraph_primes` values differ (it is skipped when they are equal, diaphora.py:1305-1310). It only produces a log line, so its sole parity impact is the exceptions it can raise. `factor.difference_ratio()` runs only in relaxed mode. `kfuzzy` never runs at diff time.
7. **Verification on this PC:**
   - A clean-room port of the difflib pieces, written the way the C++ should be, was fuzzed against stdlib difflib 3.13.12: 6,000 cases, 0 mismatches.
   - Hand-written, regex-free matchers for every normaliser regex and for `CPP_NAMES_RE` were checked against Diaphora's own functions: 120,000 strings, 0 mismatches.
   - Python float formatting and MSVC `std::to_chars` agree on exact 7-decimal ties.
8. **Adversarial review (2026-09-23)** corrected 11 errors and added the missing material; see the "Verification log" at the end. The ones that matter most for the port:
   - The shared, string-keyed `dones` makes the diffing heuristic's description always `(iteration #1)`, and blocks chained callee discovery whenever the discoverer sorts first (§4.3.2 quirk 5).
   - A delete-only hunk after line 1 is carried into later hunks (§4.3.2 quirk 2).
   - The `ZeroDivisionError` and patch-diff `IndexError` aborts are proven to kill the whole run with no output file (§4.3.4, §4.4).

---

## 1. Environment and provenance (verified on this PC, 2026-09-23)

| Item | Value | Evidence |
|---|---|---|
| Diaphora checkout | `621ec2699255fa709b2ee422cd919b38f088f16b`, `git describe` = `3.4.2-4-g621ec26`, which is 4 commits after tag 3.4.2 | `git -C <diaphora-ref> describe --tags` |
| Python | `3.13.12 \| packaged by Anaconda, Inc. \| (main, Feb 24 2026, 16:05:56) [MSC v.1942 64 bit (AMD64)]` | `sys.version` |
| difflib | `<conda>\Lib\difflib.py`, 2056 lines, md5 `60d095550edf66222f142d8bbb9feff5` | `difflib.__file__`, `md5sum` |
| cdifflib | **not installed**: `ModuleNotFoundError: No module named 'cdifflib'` | `python -c "import cdifflib"` |
| sklearn / joblib / pandas | importable, sklearn 1.8.0, so `ML_AVAILABLE = True`, but see §4.5 | `python -c "import sklearn, joblib, pandas"` |

The import fallback in diaphora.py:41-51 is verbatim:

```python
try:
  from cdifflib import CSequenceMatcher as SequenceMatcher
  HAS_CDIFFLIB = True
except ImportError:
  HAS_CDIFFLIB = False
  if config.SHOW_IMPORT_WARNINGS:
    print("WARNING: Python library 'cdifflib' not found. Installing it will significantly improve text diffing performance.")
    print("INFO: Alternatively, you can silence this warning by changing the value of SHOW_IMPORT_WARNINGS in diaphora_config.py.")
  from difflib import SequenceMatcher

from difflib import unified_diff
```

`unified_diff` always comes from the stdlib and always builds a stdlib `SequenceMatcher` (difflib.py:1138). It would do so even if cdifflib were installed.

Relevant defaults, verbatim from diaphora_config.py:

```python
DIFFING_ENABLE_UNRELIABLE = False          # :46
DIFFING_ENABLE_RELAXED_RATIO = False       # :47
DIFFING_ENABLE_EXPERIMENTAL = True         # :48
DIFFING_ENABLE_SLOW_HEURISTICS = True      # :49
FUZZY_HASHING_BLOCK_SIZE = 512             # :80
DECIMAL_VALUES = "7f"                      # :120
MINIMUM_RARE_MD_INDEX = 10.0               # :133
ML_USE_TRAINED_MODEL = False               # :205
```

**Environment-variable pitfall (diaphora.py:560-569).** `get_value_for` reads `DIAPHORA_<NAME>`:

```python
    value = os.getenv(f"DIAPHORA_{value_name.upper()}")
    if value is not None:
      if isinstance(value, type(default)):
        value = type(default)(value)
      return value
    return default
```

For a bool default, `isinstance(str, bool)` is False, so the raw string is returned. Any non-empty value is truthy, including `"0"` and `"False"`. **Oracle runs must have `DIAPHORA_RELAXED_RATIO`, `DIAPHORA_UNRELIABLE`, `DIAPHORA_EXPERIMENTAL`, `DIAPHORA_SLOW_HEURISTICS` and `DIAPHORA_USE_TRAINED_MODEL` unset.** Setting any of them to `"0"` turns the feature ON.

The same rule applies to every other `get_value_for` call in `CBinDiff.__init__` (diaphora.py:400-487), so these must be unset as well:

- `DIAPHORA_IGNORE_SMALL_FUNCTIONS` (bool, :474-476).
- `DIAPHORA_PROJECT_SCRIPT` (default `None`, :421). Any value loads a hook script, and a hook can change results.
- `DIAPHORA_SQL_TIMEOUT_LIMIT` and `DIAPHORA_SQL_MAX_PROCESSED_ROWS` (int defaults, :451-456). `isinstance(str, int)` is False, so the raw **string** is stored. The first comparison against an int in `add_matches_internal` (diaphora.py:1878, 1894) then raises `TypeError`.

`DIAPHORA_IGNORE_ALL_NAMES` does not matter in standalone mode, because diaphora.py:3759-3760 overwrites it with `False`. `DIAPHORA_AUTO_DIFF` switches the entry point to `DIAPHORA_DB1`/`DB2`/`DIFF_OUT` (diaphora.py:3719-3730).

---

## 2. Call map: what actually executes in `python diaphora.py db1 db2 -o out`

| Function | Call sites | Phase | Runs in default standalone diff? |
|---|---|---|---|
| `CBinDiff.prettify_asm` (diaphora.py:1015) | diaphora_ida.py:1466-1467, 1565, 1730-1731 (asm views and HTML diffs) | IDA UI | **No** |
| `CBinDiff.re_sub` (1027) | only from `get_cmp_pseudo_lines` and `get_cmp_asm` | export / UI | **No** |
| `CBinDiff.get_cmp_asm_lines` (1037) | diaphora_ida.py:2687 (`clean_micro`), 2960 (`clean_assembly`) | export | **No** |
| `CBinDiff.get_cmp_pseudo_lines` (1049) | diaphora_ida.py:2995 | export | **No** |
| `CBinDiff.get_cmp_asm` (1068) | `get_cmp_asm_lines` (1046), `compare_graphs_pass` (1137-1138) | export / UI | **No** |
| `compare_graphs_pass`, `compare_graphs`, `get_graph` (1105-1267) | only diaphora_ida.py:1768-1784 `graph_diff_internal`, reached from chooser commands at diaphora_ida.py:539-554 | IDA UI | **No** |
| module `quick_ratio` (158) | `check_ratio` diaphora.py:1675 (`fratio` default), 1716, 1727 | diff | **Yes** |
| module `real_quick_ratio` (169) | `check_ratio` when `relaxed_ratio` (1677-1678) | diff | **No** (relaxed off) |
| `difflib.unified_diff` | `find_one_match_diffing` diaphora.py:3042 | diff | **Yes**, whenever the dirty heuristics did not fire (§4.3) |
| `difflib.unified_diff` | scripts/patch_diff_vulns.py:137, 186 (`on_match` hook) | diff | Only after patch-diff detection. It can never change a match, but it **can abort the whole run** (verified, §4.4) |
| `SequenceMatcher.ratio()` | ml/basic_engine.py:88-89 | diff | **No** (§4.5) |
| `jkutils.factor.difference` | `get_callgraph_difference` diaphora.py:1314 | diff | **Yes** when the two `callgraph_primes` differ; log only (§7.1) |
| `jkutils.factor.difference_ratio` | `ast_ratio` diaphora.py:190 via 1637-1643 | diff | **No** (relaxed only) |
| `jkutils.factor.primesbelow` | `CBinDiff.__init__` diaphora.py:376 | init | Yes; the result `self.primes` is used only by export code |
| `jkutils.kfuzzy.CKoretFuzzyHashing` | `CBinDiff.__init__` diaphora.py:390-392 (object only) | init | Object created; no hashing at diff |
| `CKoretFuzzyHashing.hash_bytes` | diaphora_ida.py:2550 | export | **No** |

---

## 3. Export-time text normalisation (produces `clean_*` columns)

> **Runs by default at diff time? No.** The only callers are in `diaphora_ida.py` (export), per §2. The diff reads the stored columns (§4). Implement this section only for a native exporter that must emit Diaphora-compatible `clean_assembly`, `clean_pseudo` and `clean_microcode`.
>
> **Current DSigMatcher code (checked in this worktree).** Nothing in `src/` writes these columns:
>
> - `src/ExportDatabase.cpp` opens the export with `SQLITE_OPEN_READONLY` and only lists `clean_assembly`/`clean_pseudo`/`clean_microcode` as read fields (lines 64-66).
> - The SQL inserts in `src/` go only to the tool's own tables: `matches` and `symbols_to_port` (`src/main.cpp:207-209`), and `dsig_provenance` and `dsig_name_origin` (`src/Provenance.cpp:127-128, 396`).
> - `src/Synth.cpp:70-131` fills `CleanAssembly`/`CleanPseudo`/`CleanMicrocode` with synthetic benchmark text in memory. It does not apply Diaphora's normalisers.
>
> So this section is dormant today. Whether a future native exporter will emit these columns is a product decision (Open question 1).
>
> `CLEANING_CMP_REPS` is also read by `is_auto_generated` (diaphora.py:1279-1286), but that function is called only from `diaphora_ida.py:1889, 1908` (IDA import), never at diff time.

### 3.1 Replacement lists (diaphora_config.py:152-155, verbatim)

```python
CLEANING_CMP_REPS = ["loc_", "j_nullsub_", "nullsub_", "j_sub_", "sub_",
  "qword_", "dword_", "byte_", "word_", "off_", "def_", "unk_", "asc_",
  "stru_", "dbl_", "locret_", "flt_", "jpt_"]
CLEANING_CMP_REMS = ["dword ptr ", "byte ptr ", "word ptr ", "qword ptr ", "short ptr"]
```

List order is load-bearing, because each entry is a separate full pass over the text. `"short ptr"` has **no** trailing space.

### 3.2 `re_sub` (diaphora.py:1027-1035)

```python
  def re_sub(self, text, repl, string):
    """
    Internal re.sub wrapper to replace things in pseudocodes and assembly
    """
    if text not in self.re_cache:
      self.re_cache[text] = re.compile(text, flags=re.IGNORECASE)

    re_obj = self.re_cache[text]
    return re_obj.sub(repl, string)
```

Semantics a port must reproduce:

- **Python `re` with `re.IGNORECASE` and a `str` pattern means Unicode case-insensitive matching.** No `re.ASCII` is set. I enumerated all 0x110000 code points on Python 3.13.12:
  - `[A-Z]`, `[a-z0-9]` and `[A-Z0-9]` under `re.I` also match four non-ASCII code points:
    - **U+0130** İ, UTF-8 `C4 B0`
    - **U+0131** ı, UTF-8 `C4 B1`
    - **U+017F** ſ, UTF-8 `C5 BF`
    - **U+212A** K (Kelvin sign), UTF-8 `E2 84 AA`
  - `[a-f0-9A-F]` and `[0-9]` match nothing outside ASCII.
  - Among the literal letters in these patterns, only `s` (also matches U+017F) and `k` (also matches U+212A) have extra matches. Affected literals: `sub_`, `j_sub_`, `nullsub_`, `j_nullsub_`, `asc_`, `stru_`, `short ptr` (s) and `unk_` (k). The enumeration was done with a scratch script.
- `re.sub` replaces all leftmost, non-overlapping matches. After a match, scanning resumes at the match end. After a failed position, it resumes one code point later. **None of the patterns used here can match the empty string.**
- The replacement strings contain no backreferences or escapes; they are literal.

### 3.3 `get_cmp_asm` (diaphora.py:1068-1102), per line

```python
  def get_cmp_asm(self, asm):
    """
    Return a better string to diff assembly text for the given input @asm text
    """
    if asm is None:
      return asm

    # Ignore the comments in the assembly dump
    tmp = asm.split(";")[0]
    tmp = tmp.split(" # ")[0]
    # Now, replace sub_, byte_, word_, dword_, loc_, etc...
    for rep in config.CLEANING_CMP_REPS:
      tmp = self.re_sub(rep + "[a-f0-9A-F]+", "XXXX", tmp)

    # Remove dword ptr, byte ptr, etc...
    for rep in config.CLEANING_CMP_REMS:
      tmp = self.re_sub(rep + "[a-f0-9A-F]+", "", tmp)

    reps = [r"\+[a-f0-9A-F]+h\+"]
    for rep in reps:
      tmp = self.re_sub(rep, "+XXXX+", tmp)
    tmp = self.re_sub(r"\.\.[a-f0-9A-F]{8}", "XXX", tmp)

    # Strip any possible remaining white-space character at the end of
    # the cleaned-up instruction
    tmp = self.re_sub("[ \t\n]+$", "", tmp)

    # Replace aName_XXX with aXXX, useful to ignore small changes in
    # offsets created to strings
    tmp = self.re_sub("a[A-Z]+[a-z0-9]+_[0-9]+", "aXXX", tmp)

    # Replace the common microcode format for "mov #0xaddress.size, whatever"
    tmp = self.re_sub(r"\#0x[A-Z0-9]+", "0xXXX", tmp)

    return tmp
```

**Porting spec.** Definitions:

- `HEX(c)` means `c ∈ [0-9a-fA-F]`.
- `LETTER(c)` means ASCII letter or one of U+0130, U+0131, U+017F, U+212A.
- `DIGIT(c)` means `c ∈ [0-9]`.
- `ALNUM(c)` means `LETTER(c) || DIGIT(c)`.
- `CI(p, c)` is case-insensitive equality of an ASCII pattern char `p` with text char `c`: `c == p` or `c == swapcase(p)`, plus `p∈{s,S}` matching U+017F and `p∈{k,K}` matching U+212A.

Steps, in this exact order, each a full left-to-right pass producing a new string:

1. `t = asm[: first ';']`, or all of `asm` if it has no `;`. This is a plain split. It also cuts `;` inside string literals, as in vector A30.
2. `t = t[: first occurrence of the 3-char substring " # "]`, if any. `"a #b"` is unchanged.
3. For each `rep` in `CLEANING_CMP_REPS`, in list order, replace every match of **`CI(rep)` followed by a maximal run of ≥1 `HEX` chars** with `"XXXX"`. The prefix is dropped.
4. For each `rep` in `CLEANING_CMP_REMS`, in list order, apply the same matcher with an empty replacement. The rep text **and the hex run after it** are both deleted. It fires **only if at least one hex char follows**. Consequences, all verified:
   - `dword ptr [ebp+8]` is untouched, because `[` is not hex.
   - `dword ptr ds:X` becomes `s:X`, because `d` of `ds` is hex.
   - `qword ptr cs:...` becomes `qs:...`, because the `"word ptr "` pass runs before the `"qword ptr "` pass and matches inside `qword ptr c`.
5. `\+[hex]+h\+` (the `h` is case-insensitive) becomes `"+XXXX+"`. The match consumes the trailing `+`, so `+1Ch+2Ch+3Ch+` gives `+XXXX+2Ch+XXXX+` (vector A25).
6. `..` followed by **exactly 8** hex chars (the `{8}` is not maximal; later hex chars stay) becomes `"XXX"`.
7. Remove trailing characters from the set `{' ', '\t', '\n'}`. This equals `rstrip(" \t\n")`. `\r` is **not** removed (vector A36).
8. `'a'|'A'` followed by an alnum run R (maximal `ALNUM` run starting right after the `a`) becomes `"aXXX"` when **len(R) ≥ 2**, **R[0] is LETTER**, the char after R is `'_'`, and that is followed by ≥1 `DIGIT`. The replaced span runs from the `a` through the maximal digit run.
   - The match can start mid-identifier: `data_1` becomes `daXXX` (vector A23).
   - If the conditions fail, advance one char and retry. Only a single `_` segment is consumed, so `aBc_1d_22` becomes `aXXXd_22`.
9. `#0` followed by `x|X` and a maximal run of ≥1 `ALNUM` becomes `"0xXXX"`.

`None` in gives `None` out; `""` in gives `""` out. The hand matcher above was fuzzed against the real function on 120,000 random strings over a hostile alphabet (all prefixes, `ptr` forms, `h+`, `..`, `#0x`, `;`, ` # `, `\t\r\n`, the 4 special code points) with 0 mismatches. The script is scratchpad `spec03b/hand.py`.

### 3.4 `get_cmp_asm_lines` (diaphora.py:1037-1047)

```python
  def get_cmp_asm_lines(self, asm):
    """
    Convert the input assembly @asm to an easier format to text diff using lists
    """
    sio = StringIO(asm)
    lines = []
    get_cmp_asm = self.get_cmp_asm
    for line in sio.readlines():
      line = line.strip("\n")
      lines.append(get_cmp_asm(line))
    return "\n".join(lines)
```

`io.StringIO` defaults to `newline="\n"`, so `readlines()` splits **only on `\n`**. `\r` stays in the line; verified that `StringIO('a\r\nb\rc\x85d\n').readlines()` gives `['a\r\n', 'b\rc\x85d\n']`. A trailing `\n` does not create an extra empty line.

```
get_cmp_asm_lines(text):
  if text is empty: return ""              // StringIO("").readlines() == []
  pieces = split(text, '\n')               // keep empty pieces
  if text ends with '\n': drop the last (empty) piece
  return join([get_cmp_asm(p) for p in pieces], "\n")
```

Verified: `"\n"` gives `""`, and `"mov eax, 1  \n\n"` gives `"mov eax, 1\n"` (two pieces, the second empty). `StringIO(None)` behaves like `""`.

### 3.5 `get_cmp_pseudo_lines` (diaphora.py:1049-1066)

```python
  def get_cmp_pseudo_lines(self, pseudo):
    """
    Convert the input pseudocode @pseudo to an easier format to text diff using lists
    """
    if pseudo is None:
      return pseudo

    # Remove all the comments
    tmp = self.re_sub(" // .*", "", pseudo)

    # Now, replace sub_, byte_, word_, dword_, loc_, etc...
    for rep in config.CLEANING_CMP_REPS:
      tmp = self.re_sub(rep + "[a-f0-9A-F]+", rep + "XXXX", tmp)
    tmp = self.re_sub("v[0-9]+", "vXXX", tmp)
    tmp = self.re_sub("a[0-9]+", "aXXX", tmp)
    tmp = self.re_sub("arg_[0-9]+", "aXXX", tmp)

    return tmp
```

This runs on the **whole** multi-line text, with no per-line split and no `re.MULTILINE`.

1. For each line (split on `\n`), truncate at the first occurrence of `" // "`. `.` matches everything except `\n`, so a `\r` before `\n` on a commented line is removed too (vector P9). `"x// c"` has no leading space and is kept.
2. For each `rep` in `CLEANING_CMP_REPS`, in order, `CI(rep) + maximal HEX+` becomes **`rep + "XXXX"`**, where `rep` is the lowercase literal from the config, whatever the source case (`SUB_abc` gives `sub_XXXX`).
3. `CI("v") + maximal DIGIT+` becomes `"vXXX"`, with no word boundaries: `dev2` gives `devXXX`, `V5` gives `vXXX`.
4. `CI("a") + maximal DIGIT+` becomes `"aXXX"`, with no boundaries: `0x1a0` gives `0x1aXXX`, `data1` gives `dataXXX`.
5. `CI("arg_") + maximal DIGIT+` becomes `"aXXX"`. Decimal only, so `arg_C` is kept. This runs after step 4, which cannot touch `arg_N` because `a` is followed by `r`.

`None` gives `None`. Fuzzed with 0 mismatches, as in §3.3.

### 3.6 Export call sites (what ends up in the DB)

- `clean_assembly` (diaphora_ida.py:2958-2963) falls back to `""` on any exception:

  ```python
    try:
      clean_assembly = self.get_cmp_asm_lines(asm)
    except:
      clean_assembly = ""
      print("Error getting assembly for 0x%x" % f)
  ```

  `asm` is `"\n".join(disasm lines)`. Every basic block except the *first one processed* starts with a synthetic `"loc_%x:"` line. The check is `if nodes == 1` on the running per-block counter `accum['nodes'] += 1` (diaphora_ida.py:2818, 2720-2726). The blocks are then re-ordered by address with the entry block first (diaphora_ida.py:2569-2594).
- `clean_microcode` (diaphora_ida.py:2657-2688): `None` unless microcode was exported. Otherwise it is `self.get_cmp_asm_lines("\n".join(ret))`, where each `ret` line is the microcode line cut to start at its mnemonic.
- `clean_pseudo` (diaphora_ida.py:2995) is `self.get_cmp_pseudo_lines(pseudo)`. It is `None` when the function has no pseudocode (`pseudo = None`, diaphora_ida.py:2541-2547).

### 3.7 Test vectors (generated by running Diaphora's own methods; JSON-escaped)

| # | input line | get_cmp_asm output |
|---|---|---|
| A1 | `"mov     eax, dword ptr [ebp+8]"` | `"mov     eax, dword ptr [ebp+8]"` |
| A2 | `"mov     eax, dword ptr ds:dword_401000"` | `"mov     eax, s:XXXX"` |
| A3 | `"mov     rax, qword ptr cs:qword_180001000"` | `"mov     rax, qs:XXXX"` |
| A4 | `"mov     rax, qword ptr fs:28h"` | `"mov     rax, qs:28h"` |
| A5 | `"mov     ax, word ptr es:[edi]"` | `"mov     ax, s:[edi]"` |
| A6 | `"mov eax, byte ptr 0"` | `"mov eax,"` |
| A7 | `"mov eax, short ptr1"` | `"mov eax,"` |
| A8 | `"mov eax, short ptr 1"` | `"mov eax, short ptr 1"` |
| A9 | `"jmp     short loc_401010"` | `"jmp     short XXXX"` |
| A10 | `"call    j_sub_401000"` | `"call    XXXX"` |
| A11 | `"call    j_nullsub_1"` | `"call    XXXX"` |
| A12 | `"call    SUB_ABCDEF ; comment"` | `"call    XXXX"` |
| A13 | `"call    loc_ABCDEFGH"` | `"call    XXXXGH"` |
| A14 | `"call    sub_401000+1Ch"` | `"call    XXXX+1Ch"` |
| A15 | `"call    \u017fub_1234"` | `"call    XXXX"` |
| A16 | `"loc_401000:"` | `"XXXX:"` |
| A17 | `"cmp     undef_12, 0"` | `"cmp     unXXXX, 0"` |
| A18 | `"lea     rcx, aHelloWorld_12 ; \"Hello\""` | `"lea     rcx, aXXX"` |
| A19 | `"lea     rcx, aHello ; \"Hello\""` | `"lea     rcx, aHello"` |
| A20 | `"lea rax, aBc_1d_22"` | `"lea rax, aXXXd_22"` |
| A21 | `"lea rax, aA_1"` | `"lea rax, aA_1"` |
| A22 | `"lea rax, a\u0131b_1"` | `"lea rax, aXXX"` |
| A23 | `"mov     eax, [rbp+data_1]"` | `"mov     eax, [rbp+daXXX]"` |
| A24 | `"mov     eax, [ebp+var_4+0Ch+arg_0]"` | `"mov     eax, [ebp+var_4+XXXX+aXXX]"` |
| A25 | `"mov eax, [esi+1Ch+2Ch+3Ch+eax]"` | `"mov eax, [esi+XXXX+2Ch+XXXX+eax]"` |
| A26 | `"x+0FFH+y"` | `"x+XXXX+y"` |
| A27 | `"x ..DEADBEEF1 y"` | `"x XXX1 y"` |
| A28 | `"mov #0xDEADBEEF.8, rax"` | `"mov 0xXXX.8, rax"` |
| A29 | `"mov #0x1a.4, rax"` | `"mov 0xXXX.4, rax"` |
| A30 | `"db 'a;b',0"` | `"db 'a"` |
| A31 | `"call    ds:__imp_foo # something"` | `"call    ds:__imp_foo"` |
| A32 | `"a #b"` | `"a #b"` |
| A33 | `";all comment"` | `""` |
| A34 | `"mov     edx, offset unk_1800A0000  "` | `"mov     edx, offset XXXX"` |
| A35 | `"\tmov eax, 1 \t"` | `"\tmov eax, 1"` |
| A36 | `"mov eax, 1\r"` | `"mov eax, 1\r"` |

| # | get_cmp_asm_lines input | output |
|---|---|---|
| L1 | `"a ; x\nb\n\nloc_1:\nc\n"` | `"a\nb\n\nXXXX:\nc"` |
| L2 | `""` | `""` |
| L3 | `"\n"` | `""` |
| L4 | `"a\r\nb\rc"` | `"a\r\nb\rc"` |
| L5 | `"mov eax, 1  \n\n"` | `"mov eax, 1\n"` |

| # | get_cmp_pseudo_lines input | output |
|---|---|---|
| P1 | `"__int64 __fastcall sub_180001000(__int64 a1, int a2)"` | `"__int64 __fastcall sub_XXXX(__int64 aXXX, int aXXX)"` |
| P2 | `"  int v3; // eax"` | `"  int vXXX;"` |
| P3 | `"  v3 = LODWORD(qword_18000A0A0) + 0x1a0; // c"` | `"  vXXX = LODWORD(qword_XXXX) + 0x1aXXX;"` |
| P4 | `"data1 = dev2 + V5 + arg_8 + arg_C + A1;"` | `"dataXXX = devXXX + vXXX + aXXX + arg_C + aXXX;"` |
| P5 | `"j_sub_1234(a1) + dword_1234 + word_12 + unk_ABC"` | `"j_sub_XXXX(aXXX) + dword_XXXX + word_XXXX + unk_XXXX"` |
| P6 | `"SUB_abc Sub_12 nullsub_1 j_nullsub_1"` | `"sub_XXXX sub_XXXX nullsub_XXXX j_nullsub_XXXX"` |
| P7 | `"x// c"` | `"x// c"` |
| P8 | `"a // b // c"` | `"a"` |
| P9 | `"loc_12 // x\r\nnext"` | `"loc_XXXX\nnext"` |
| P10 | `"undef_1 a0x arg_ v"` | `"undef_XXXX aXXXx arg_ v"` |
| P11 | `"flt_1 dbl_2 asc_3 stru_4 off_5 def_6 locret_7 jpt_8 byte_9"` | `"flt_XXXX dbl_XXXX asc_XXXX stru_XXXX off_XXXX def_XXXX locret_XXXX jpt_XXXX byte_XXXX"` |

### 3.8 `prettify_asm` (diaphora.py:1015-1025), UI only

```python
  def prettify_asm(self, asm_source):
    """
    Get a prettified form of the given assembly source
    """
    asm = []
    for line in asm_source.split("\n"):
      if not line.startswith("loc_"):
        asm.append("\t" + line)
      else:
        asm.append(line)
    return "\n".join(asm)
```

This prefixes a tab to every line that does not start with `loc_` (case-sensitive). **Runs by default? No.** It is called only by the IDA viewers (diaphora_ida.py:1466-1467, 1565, 1730-1731). No parity impact.

---

## 4. How the diff consumes difflib

### 4.1 `check_bufs`, `quick_ratio`, `real_quick_ratio` (diaphora.py:150-176)

```python
def check_bufs(buf1, buf2):
  if buf1 is None or buf2 is None:
    return False
  if buf1 == "" or buf2 == "":
    return False
  return True

#-------------------------------------------------------------------------------
def quick_ratio(buf1, buf2):
  """
  Call SequenceMatcher.quick_ratio() to get a comparison ratio.
  """
  if not check_bufs(buf1, buf2):
    return 0
  seq = SequenceMatcher(None, buf1.split("\n"), buf2.split("\n"))
  return seq.quick_ratio()


#-------------------------------------------------------------------------------
def real_quick_ratio(buf1, buf2):
  """
  Call SequenceMatcher.real_quick_ratio() to get a comparison ratio.
  """
  if not check_bufs(buf1, buf2):
    return 0
  seq = SequenceMatcher(None, buf1.split("\n"), buf2.split("\n"))
  return seq.real_quick_ratio()
```

**Porting spec (exact).**

```
double py_quick_ratio(opt<string_view> s1, opt<string_view> s2):
  if (!s1 || !s2 || s1->empty() || s2->empty()) return 0.0   // Python returns int 0; formats identically (§4.2)
  A = split_keep_empty(*s1, '\n')    // str.split("\n"): "a\nb\n" -> ["a","b",""]; never splits on \r
  B = split_keep_empty(*s2, '\n')
  cnt = multiset counts of B          // key = exact byte string (UTF-8 from SQLite)
  m = 0
  for x in A: if cnt[x] > 0 { cnt[x]--; m++ }
  return 2.0 * double(m) / double(|A| + |B|)       // |A|+|B| >= 2 here, never 0

double py_real_quick_ratio(s1, s2):
  same guard; la=|A|, lb=|B|; return 2.0 * min(la,lb) / double(la+lb)
```

- The **SequenceMatcher construction runs `__chain_b` (autojunk), but `quick_ratio` never reads `b2j`**. It counts from `self.b` directly (difflib.py:632-649, §5.7), so autojunk has **no effect** on this value.
- The result is **independent of line order** and **symmetric** in (A, B).
- Element equality is Python `str` equality. For valid UTF-8 from SQLite, byte equality is equivalent. Read with `sqlite3_column_text` plus `sqlite3_column_bytes`, not `strlen`: a Python `str` can hold `\0`.
- `2.0 * m / L` in Python is an IEEE double multiply followed by a true division of float by int. The int converts exactly while it is below 2^53. The C++ above gives identical bits.
- Performance: the result depends only on the per-function line multiset, so the C++ may precompute and cache per-function `{line → count}` maps (or sorted hashed vectors) and reuse them across many `check_ratio` calls. The output is bit-identical.

**Inputs at diff time:** the `functions.clean_pseudo`, `clean_assembly` and `clean_microcode` TEXT columns (UTF-8). The heuristic SQL selects them as `clean_pseudo1/2`, `clean_assembly1/2` and `clean_micro1/2` (diaphora_heuristics.py `SELECT_FIELDS`, lines 51-75). `compare_function_rows` reads `clean_microcode` into `clean_micro` (diaphora.py:2479-2537).

**Runs by default?** `quick_ratio`: yes, via `check_ratio`, `fratio = quick_ratio` (diaphora.py:1675). `real_quick_ratio`: no, only when `self.relaxed_ratio` is truthy (1677-1678). The default is `False` (diaphora_config.py:47; diaphora.py:403-405).

### 4.2 Call sites inside `check_ratio` (diaphora.py:1672-1753) and the 7-decimal rounding

`check_ratio` as a whole (bytes-hash short-circuit, MD-index term, `deep_ratio`, the `r == 1.0 and md1 != md2` rule) belongs to `03a-ratio.md` (§6). The difflib-dependent lines, verbatim:

```python
    fratio = quick_ratio
    decimal_values = "{0:.%s}" % config.DECIMAL_VALUES
    if self.relaxed_ratio:
      fratio = real_quick_ratio
      decimal_values = "{0:.1f}"
    ...
    v1 = 0
    if (
      pseudo1 is not None
      and pseudo2 is not None
      and pseudo1 != ""
      and pseudo2 != ""
    ):
      if clean_pseudo1 == "" or clean_pseudo2 == "":
        log("Error cleaning pseudo-code!")
      else:
        v1 = fratio(clean_pseudo1, clean_pseudo2)
        v1 = float(decimal_values.format(v1))
        if v1 == 1.0:
          # If real_quick_ratio returns 1 try again with quick_ratio
          # because it can result in false positives. If real_quick_ratio
          # says 'different', there is no point in continuing.
          if fratio == real_quick_ratio:
            v1 = quick_ratio(clean_pseudo1, clean_pseudo2)
            if v1 == 1.0:
              self.ratios_cache[key] = 1.0
              return 1.0

    v2 = fratio(clean_assembly1, clean_assembly2)
    v2 = float(decimal_values.format(v2))
    if v2 == 1:
      # Actually, same as the quick_ratio/real_quick_ratio check done
      # with the pseudo-code
      if fratio == real_quick_ratio:
        v2 = quick_ratio(clean_assembly1, clean_assembly2)
        if v2 == 1.0:
          self.ratios_cache[key] = 1.0
          return 1.0

    if self.relaxed_ratio and not ast_done:
      v3 = fratio(ast1, ast2)
      v3 = float(decimal_values.format(v3))
      if v3 == 1:
        self.ratios_cache[key] = 1.0
        return 1.0
    ...
    v5 = 0.0
    if clean_micro1 is not None and clean_micro2 is not None:
      v5 = fratio(clean_micro1, clean_micro2)
      v5 = float(decimal_values.format(v5))
      if v5 == 1:
        self.ratios_cache[key] = 1.0
        return 1.0
```

Default-config facts, where `fratio` is `quick_ratio`:

- **v1 (pseudocode)** is computed only if the **raw** `pseudocode` columns (`pseudo1/2`) are both non-NULL and non-empty. Then:
  - If either `clean_pseudo` is `""`, v1 stays `0` (with a log line).
  - If either `clean_pseudo` is NULL (raw pseudo non-empty), `check_bufs` gives 0.
  - With default config, reaching `v1 == 1.0` does **not** return early: that branch is gated on `fratio == real_quick_ratio`. v1 = 1.0 is simply kept.
- **v2 (assembly)** is always computed. NULL or `""` on either side gives 0. As with v1, 1.0 is kept with no early return.
- **v5 (microcode)** is computed only if both `clean_microcode` are non-NULL, and it **returns 1.0 immediately** when the rounded value equals 1. This is the only difflib-driven early return in the default config.

**Rounding step (exact).** `DECIMAL_VALUES = "7f"` makes `decimal_values = "{0:.7f}"`, and each value becomes `float("{0:.7f}".format(v))`. Python formats the **exact binary value**, correctly rounded, with exact ties going to even. The C++ equivalent:

```cpp
double round7(double v) {                 // Python: float("{0:.7f}".format(v))
  char buf[64];
  auto r = std::to_chars(buf, buf + sizeof buf, v, std::chars_format::fixed, 7);
  double out; std::from_chars(buf, r.ptr, out);   // correctly rounded parse == Python float()
  return out;
}
```

I verified on this PC with MSVC 14.51 (`cl /std:c++20`) that `to_chars` and `printf("%.7f")` match Python on **exact ties**, which do occur: `2m/L = 1/256` for `m=1, L=512`. In the table below, the rows 0.00390625, 0.01171875 and 0.99609375 are exact ties at the 8th decimal. The rows 0.005859375, 0.0048828125 and 2/3 are ordinary roundings, included as controls.

| v (exact) | Python `"{0:.7f}"` | MSVC `to_chars` |
|---|---|---|
| 0.00390625 | `0.0039062` | `0.0039062` |
| 0.01171875 | `0.0117188` | `0.0117188` |
| 0.005859375 | `0.0058594` | `0.0058594` |
| 0.0048828125 | `0.0048828` | `0.0048828` |
| 0.99609375 | `0.9960938` | `0.9960938` |
| 2/3 | `0.6666667` | `0.6666667` |

Re-verified during the adversarial review with `cl` 19.51.36246 (VS 18.6.2, `/std:c++20`). Both `to_chars` + `from_chars` and Python's `float("{0:.7f}".format(v))` give identical doubles for:

- all rows above
- `0.99999995`, whose double is just below the tie, so both give `0.9999999`
- the next double up, `0.9999999500000001`, so both give `1.0000000` → `1.0`
- `0.12345675`, which gives `0.1234568`
- `5e-08`, which gives `0.0000000`

`round7(int 0)` is `0.0`. A value can round **up to 1.0** only if `2m/L ≥ 0.99999995`, which needs `L ≥ 2·10^7` lines. That is not reachable in practice, but `round7` must still be applied before every `== 1` test.

**Relaxed-mode notes (not default; recorded so nobody "fixes" parity the wrong way).**

- `v3 = real_quick_ratio(ast1, ast2)` runs on `pseudocode_primes` decimal strings, which contain no `\n`. Each becomes a 1-element list, so `real_quick_ratio = 2·1/2 = 1.0` for **any** two non-empty values. In relaxed mode, therefore, any pair with both `pseudocode_primes` non-empty and `max(len) ≥ 16` returns ratio 1.0 at diaphora.py:1732-1737, unless an earlier return fired first.
- `decimal_values = "{0:.1f}"` in relaxed mode.

### 4.3 `unified_diff` in "Callee found diffing matches …" (runs by default)

**Where and when.** The diff main loop (diaphora.py:3653-3675) sits inside the `else:` of `if skip_others:` (3626-3629). It runs when neither dirty heuristic fired (`search_just_stripped_binaries`, `search_patchdiff_with_symbols`, `apply_dirty_heuristics` at diaphora.py:2629-2637, gated by `if self.experimental:` at 3618-3621):

```python
          iteration = 0
          while 1:
            self.cleanup_matches()
            old_total = self.get_total_matched_functions()

            # Find new matches by diffing assembly and pseudo-code of previously
            # found matches
            self.find_matches_diffing(iteration)
```

`find_matches_diffing` (diaphora.py:3211-3229):

```python
    # First, remove duplicates, etc... just to be sure
    self.cleanup_matches()

    # Only if the processor is the same for both databases we diff assembly
    if self.is_same_processor:
      heur = "Callee found diffing matches assembly"
      enabled = self.call_hook("on_special_heuristic", True, [heur, iteration])
      if enabled:
        self.find_matches_diffing_assembly()

    heur = "Callee found diffing matches pseudo-code"
    enabled = self.call_hook("on_special_heuristic", True, [heur, iteration])
    if enabled:
      self.find_matches_diffing_pseudo()
```

- `is_same_processor` is set by `same_processor_both_databases()` (diaphora.py:2950-2966): true iff `main.program.processor = diff.program.processor` yields a row. The assembly variant uses field `"assembly"` (3195-3201) and the pseudo variant uses `"pseudocode"` (3203-3209). Both are **raw** columns, not `clean_*`.
- With no hooks loaded, `call_hook` returns the default `True` (diaphora.py:1450-1459).

`find_matches_diffing_internal` (diaphora.py:3150-3193), verbatim:

```python
    iteration = 1
    dones = set()
    # Should I let it run for some more iterations? There is a small chance of
    # hitting an infinite loop, so I'm hardcoding an upper limit.
    while iteration <= 3:
      old_total = self.get_total_matched_functions()

      for key in ["best", "partial"]:
        l = self.get_sorted_results(key)
        for match in l:
          match_key = f"{match[1]}-{match[3]}"
          if match_key in dones:
            continue
          dones.add(match_key)

          item = self.itemize_for_chooser(match)
          main_row, diff_row = self.get_row_for_items(item)
          if main_row is not None and diff_row is not None:
            if main_row[field_name] is None:
              continue
            if diff_row[field_name] is None:
              continue

            dones = self.find_one_match_diffing(
              main_row, diff_row, field_name, heur, iteration, dones
            )

      self.cleanup_matches()
      self.show_summary()

      new_total = self.get_total_matched_functions()
      if new_total == old_total:
        break

      log(f"New iteration with heuristic '{heur}'...")
      iteration += 1
```

`find_one_match_diffing` (diaphora.py:3033-3131), the difflib part (lines 3040-3074), verbatim. The excerpt stops before lines 3076-3078, which are omitted from both quotes: `size = len(dones)` followed by a log every 10,000 keys. That line rebinds `size`, but `range(size)` was already evaluated at 3064, so the loop bound does not change and the effect is log-only.

```python
    main_lines = input_main_row[field_name].splitlines(keepends=False)
    diff_lines = input_diff_row[field_name].splitlines(keepends=False)
    df = unified_diff(main_lines, diff_lines, lineterm="")

    minus = []
    plus = []

    for row in df:
      if len(row) == 0:
        continue

      c = row[0]
      if c == "-":
        minus.append(row)
      elif c == "+":
        plus.append(row)
      elif c == " ":
        if len(minus) > 0 and len(plus) > 0:
          matches1 = re.findall(CPP_NAMES_RE, "\n".join(minus), re.IGNORECASE)
          matches2 = re.findall(CPP_NAMES_RE, "\n".join(plus), re.IGNORECASE)
          minus = []
          plus = []

          size = min(len(matches1), len(matches2))
          for i in range(size):
            name1 = matches1[i][0]
            name2 = matches2[i][0]
            key = f"{name1}-{name2}"
            if key in dones:
              continue
            dones.add(key)

            if name1.startswith("nullsub") or name2.startswith("nullsub"):
              # Ignore such functions
              continue
```

The rest of the candidate handling is quoted in §4.3.4.

#### 4.3.1 Porting spec: line splitting

`str.splitlines(keepends=False)`, **not** `split("\n")`. On Python 3.13.12 the separators are exactly these (enumerated over all code points):

| Code point | UTF-8 bytes in the DB |
|---|---|
| `\n` U+000A | `0A` |
| `\v` U+000B | `0B` |
| `\f` U+000C | `0C` |
| `\r` U+000D | `0D` (`\r\n` counts as **one** separator) |
| U+001C, U+001D, U+001E | `1C`, `1D`, `1E` |
| U+0085 NEL | `C2 85` (a raw `0x85` byte in UTF-8 is a continuation byte, **not** a separator) |
| U+2028, U+2029 | `E2 80 A8`, `E2 80 A9` |

A trailing separator does not produce a trailing empty element. Examples:

- `"a\n".splitlines()` gives `['a']`
- `"a\n\n"` gives `['a','']`
- `"\n"` gives `['']`
- `""` gives `[]`
- `"a\n\r"` gives `['a','']`
- `"a\r\r\n"` gives `['a','']`

#### 4.3.2 Porting spec: the diff-output walk

This is the exact semantics, including its quirks.

```
dones: set<string>  (shared, see below)
rows = unified_diff(main_lines, diff_lines, fromfile="", tofile="", n=3, lineterm="")   // §5.6
minus = []; plus = []
for row in rows:                      // rows are never empty
   c = row[0]
   if c == '-': minus.push(row)       // includes the header row "--- "
   elif c == '+': plus.push(row)      // includes the header row "+++ "
   elif c == ' ':
      if minus non-empty and plus non-empty:
         m1 = CPP_NAMES(join(minus, "\n"))
         m2 = CPP_NAMES(join(plus,  "\n"))
         minus.clear(); plus.clear()
         for i in 0 .. min(|m1|,|m2|)-1:          // POSITIONAL pairing
            key = m1[i] + "-" + m2[i]
            if key in dones: continue
            dones.add(key)
            if m1[i].startswith("nullsub") or m2[i].startswith("nullsub"): continue
            -> candidate (m1[i], m2[i]) processed as in §4.3.4
   // rows starting with '@' ("@@ -a,b +c,d @@") are ignored
// minus/plus still pending when rows run out are DISCARDED
```

Quirks, verified with scratch script `spec03b/t6.py`:

1. **A hunk that ends the file with changes, with no trailing context line, is never processed.** With `"a\nb\nc\ncall foo_old"` vs `"...call foo_new"`, the rows are `['--- ', '+++ ', '@@ -1,4 +1,4 @@', ' a', ' b', ' c', '-call foo_old', '+call foo_new']` and the pairs list is `[]`.
2. **The header rows `"--- "` and `"+++ "` land in `minus` and `plus`.** Neither contains an identifier token, so they contribute nothing to `m1`/`m2`. They are flushed, with zero pairs, at the **first context row of the whole diff**, and what happens next depends on where that row is:
   - **The first hunk starts with context.** This is the normal case: any change after line 1 gets up to `n=3` lines of leading context. The headers are flushed at that leading context row with no pairs. A later delete-only first hunk is **not** consumed; it accumulates as in quirk 3.
   - **The first hunk starts with a change.** This happens only when the change begins at line 1. The change rows share the buffers with the headers. A delete-only change is then flushed together with `"+++ "` at the first context row and yields no pairs, because `m2` is empty.

   Both cases were verified with `re.findall`/`unified_diff` (scratch `v03b/walk.py`):
   - `["call alpha_one","x1".."x4"]` vs `["x1".."x4"]` gives pairs `[[]]`.
   - In a 14-line case, a middle delete-only hunk `-call alpha_one` is carried into the next hunk. There it pairs positionally with `+call gamma_new`, and the flush yields `[('call','call'), ('alpha_one','gamma_new')]`.
3. **Flushing requires both lists to be non-empty.** A hunk that only deletes (or only inserts) keeps accumulating into the next hunk, across `@@` boundaries, until a context row arrives with both lists non-empty.
4. **Pairing is purely positional over all identifier-like tokens**, including mnemonics of 4 or more chars (`call`, `push`, `qword`) and hex constants with letters (`0x401000` yields `x401000`). One extra token on one side shifts every later pair.
5. `dones` is **one set shared** by two kinds of key:
   - `f"{name1}-{name2}"` of already processed existing matches, from `find_matches_diffing_internal`
   - candidate keys from `find_one_match_diffing`

   A candidate whose key equals a processed match key is skipped, and the reverse also holds. The set is re-created at every call of `find_matches_diffing_internal`, that is, per heuristic per outer iteration. It persists across that call's inner iterations 1..3.

   The key is a plain **string**, `name1 + "-" + name2`, not a pair. Names that contain `-` can therefore collide (`"a-b"+"c"` vs `"a"+"b-c"`). A bug-for-bug port must key the set on the concatenated string.

   Consequences, derived from source (3067-3070, 3168-3171) and confirmed by experiment A (scratch `v03b/expA.py` + `drvA.py`, real `diaphora.py`):
   - **Inner iterations ≥ 2 never process a seed in the default config.** Every match that `find_one_match_diffing` adds has its key added to `dones` first (3070). Every match that existed when a category loop started is added at 3171. At the start of inner iteration 2, every match key is therefore already in `dones`. Iteration 2 runs whenever the best + partial total changed, which covers both a match added in iteration 1 and a match removed by the `cleanup_matches` at 3185 (3188-3193). It processes no seed, so it adds nothing. **The description suffix is therefore always `(iteration #1)` unless a hook adds matches.** Experiment A logged `New iteration with heuristic ...` once, and the trace showed no seed processed with `inner-it 2`.
   - **Chained discovery through the same field is blocked whenever the discoverer is processed first, even across outer iterations.**
     - Take seed `caller`, which is in "best", and suppose its pseudocode diff yields the new match `alpha→beta` in "partial".
     - On the next outer iteration, `caller` is processed first again, because "best" is processed before "partial".
     - Its diff is unchanged, so it re-emits the candidate key `alpha_old_callee-beta_new_callee`. That puts the key into the fresh `dones` **before** the `alpha→beta` match is reached as a seed.
     - The match is then skipped at 3169-3170, so its own callees (`gamma→delta` in the experiment) are never found by this pseudocode heuristic.

     This holds whenever the discoverer sorts before the discovered match in the next call:
     - The discoverer is in "best" and the discovered match is in "partial".
     - Both are in the same category, and the discoverer has a higher ratio, or an equal ratio and was inserted earlier.

     If the discovered match sorts first, it *is* used as a seed. An example is a discovered "best" match (r = 1.0) found from a "partial" discoverer.

     The assembly and pseudocode variants have separate `dones` sets. In the experiment, `alpha→beta` *was* used as an **assembly** seed in the next outer iteration.

     Experiment A result: only `caller_fn` (Perfect match, same name) and `alpha_old_callee→beta_new_callee` (`Callee found diffing matches pseudo-code (iteration #1)`, 0.9008889) were matched. `gamma_old_leaf→delta_new_leaf` stayed unmatched, although its `compare_function_rows` ratio is 0.8908889 with nodes 5/6, which passes every gate in §4.3.4.
6. `get_sorted_results` (diaphora.py:3133-3140) is `sorted(self.all_matches[category], key=lambda x: float(x[5]), reverse=True)`. **Python `sorted` is stable, including with `reverse=True`**: equal ratios keep insertion order. The C++ must use `std::stable_sort` with `>` on `double(ratio)`. Each category list is snapshotted when its `for key` loop starts (3166). The "partial" snapshot is therefore taken **after** the "best" loop has run, and includes partial matches added during it (their keys are already in `dones`).
7. Seeds are re-read **by name** through `get_row_for_items` → `get_function_row(name)` (diaphora.py:2993-3001, 2445-2460), not by address. For duplicate names this is the first row SQLite returns (§8.4). The seed's key is added to `dones` (3171) **before** the NULL-field checks at 3176-3179.

#### 4.3.3 `CPP_NAMES_RE` (diaphora.py:114), porting spec

```python
CPP_NAMES_RE = "([a-zA-Z_][a-zA-Z0-9_]{3,}((::){0,1}[a-zA-Z0-9_]+)*)"
```

It is used with `re.findall(..., re.IGNORECASE)`. `matches[i][0]` is group 1, which is the **whole match**. The regex-free equivalent below was fuzzed against `re.findall` on 120,000 strings with 0 mismatches.

```
WORD(c)  = LETTER(c) || DIGIT(c) || c == '_'       // LETTER includes U+0130/0131/017F/212A (re.I, Unicode)
names(s):
  out = []; i = 0
  while i < len(s):                                 // len in CODE POINTS: "{3,}" counts characters, not bytes
    if LETTER(s[i]) or s[i] == '_':
      j = i+1; while j < len(s) and WORD(s[j]): j++
      if j - i >= 4:
        while s[j:j+2] == "::" and j+2 < len(s) and WORD(s[j+2]):
          j += 2; while j < len(s) and WORD(s[j]): j++
        out.push(s[i:j]); i = j; continue
    i++
  return out
```

A token can start mid-word after leading digits: `12abcd` gives `abcd`. A word shorter than 4 chars never yields a suffix. A leading namespace component shorter than 4 chars is dropped. These examples were verified with `re.findall`:

- `call Foo::Barbaz::x` gives `['call', 'Barbaz::x']`
- `call abc::defg` gives `['call', 'defg']`
- `push qword ptr [rax]` gives `['push', 'qword']`
- `mov eax, 0x401000` gives `['x401000']`

#### 4.3.4 What a candidate becomes (verbatim diaphora.py:3080-3129, for cross-reference)

```python
            exists, l = self.functions_exists(name1, name2)
            if exists:
              main_row = l[0]
              diff_row = l[1]
              min_nodes = min(main_row["nodes"], diff_row["nodes"])
              max_nodes = max(main_row["nodes"], diff_row["nodes"])

              # If the number of basic blocks differ in more than 75% ignore...
              if (
                (min_nodes * 100) / max_nodes
              ) < config.DIFFING_MATCHES_MAX_DIFFERENT_BBLOCKS_PERCENT:
                continue

              # There is a high risk of false positives with small functions,
              # therefore, it's preferred to miss functions than having false
              # positives
              if main_row["nodes"] < config.DIFFING_MATCHES_MIN_BBLOCKS:
                continue
              if diff_row["nodes"] < config.DIFFING_MATCHES_MIN_BBLOCKS:
                continue

              r = self.compare_function_rows(main_row, diff_row)
              if r == 1.0:
                chooser = "best"
              elif r > config.DEFAULT_TRUSTED_PARTIAL_RATIO:
                chooser = "partial"
              else:
                continue

              if r + config.MATCHES_BONUS_RATIO < 1.0:
                r += config.MATCHES_BONUS_RATIO

              should_add, r = self.call_on_match_hook(heur, r, main_row, diff_row)
              if should_add:
                heur_text = f"{heur} (iteration #{iteration})"
                ...
                self.add_match(name1, name2, r, new_item, chooser)
```

**Outputs.**

- Category: `"best"` if `r == 1.0`, `"partial"` if `r > 0.3` (`DEFAULT_TRUSTED_PARTIAL_RATIO`, diaphora_config.py:141), otherwise dropped.
- Ratio: `r`, plus `0.01` (`MATCHES_BONUS_RATIO`, diaphora_config.py:116) when `r + 0.01 < 1.0`, in IEEE double arithmetic.
- Description: `"Callee found diffing matches assembly (iteration #N)"` or `"Callee found diffing matches pseudo-code (iteration #N)"`. **N is the inner `find_matches_diffing_internal` counter, 1..3**, not the outer loop's `iteration`, which only goes to the hook (diaphora.py:3150-3158, 3033-3035, 3114). In the default config (no hooks), **N is always 1** (§4.3.2 quirk 5). Port the loop literally anyway; it is cheap.

`functions_exists` is in diaphora.py:2969-2991. `compare_function_rows` is specified in `03a-ratio.md` (§10), and `add_match` and `cleanup_matches` in `05-passes.md` (§2.4-2.5). The details below belong to those specs and are listed only to make this spec's boundary explicit:

- `functions_exists` uses a `UNION`, not `UNION ALL`, plus `order by db_name desc`, so main comes first. It requires exactly 2 rows.
- `(min_nodes*100)/max_nodes` raises `ZeroDivisionError` if both node counts are 0. This division runs **before** the `DIFFING_MATCHES_MIN_BBLOCKS` checks (3088-3099). No handler catches it: `find_one_match_diffing` → `find_matches_diffing_internal` → `find_matches_diffing` → `diff()` (`try/finally` only, 3593-3700) → `__main__` (3772). The process exits 1 before `save_results` (3773) runs, so **no output file is written**, and a stale file from an earlier run is not removed either (the `os.remove` is inside `save_results`, 2379-2381). Verified by experiment Z: scratch `v03b/expZ.py`, both callees with `nodes=0`, traceback ending at diaphora.py:3089, exit 1, no `.diaphora` file. A NULL `nodes` gives `TypeError` from `min(None, x)` on the same path.
- `DIFFING_MATCHES_MAX_DIFFERENT_BBLOCKS_PERCENT = 25` (diaphora_config.py:177) and `DIFFING_MATCHES_MIN_BBLOCKS = 3` (:183).

**Runs by default?** Yes, for the pseudo variant. The assembly variant also runs when the processors are equal. Neither runs when `skip_others` is True, i.e. when a dirty heuristic fired (diaphora.py:3626-3629).

### 4.4 Default patch-diff script (`scripts/patch_diff_vulns.py`), conditional, cannot change results

It is loaded only when all of these hold (diaphora.py:2609-2619, 3618-3621, 2633-2636):

- `self.experimental` is truthy.
- `search_just_stripped_binaries` did not fire.
- `search_patchdiff_with_symbols` sees more than `SPEEDUP_PATCH_DIFF_SYMBOLS_MIN_PERCENT = 90.0`% (computed as `count(f.mangled_function = df.mangled_function join rows) * 100 / total_functions1`).
- `self.project_script` is `None` or `""`.
- `RUN_DEFAULT_SCRIPTS` is set. Its `on_match` calls `unified_diff(asm1.split("\n"), asm2.split("\n"))` and `unified_diff(pseudo1.split("\n"), pseudo2.split("\n"))` with the **default** `lineterm="\n"` (lines 137, 186). It **always** returns `True, ratio` (line 236). Its only output is an "Interesting matches" chooser that `save_results` does not write (diaphora.py:2374-2430 writes only best/partial/unreliable/multimatch/unmatched).

The one parity-relevant risk is a crash. In `find_vulns_using_assembly` (lines 143-168), once both `added` and `removed` are set (the header rows set them immediately), an added asm line that is empty or starts with a space gives `mnem1 == ""`. `mnem1[0]` at line 162 then raises `IndexError`. The same happens to `mnem2[0]` when the current `added` mnemonic starts with `b` and the removed line is empty or starts with a space. `call_hook` (diaphora.py:1450-1459) does not catch it.

**It escapes `diff()` (resolved from source and verified).** A detected patch diff sets `skip_others = True`, so `on_match` is reached only from the main thread, never from a heuristic worker thread:

- `find_same_name("partial")` at diaphora.py:3624 (standalone forces `ignore_all_names = False`, 3760) → `check_match` (2183) → `call_hook("on_match")` (1871).
- `find_remaining_functions` (3627) → `search_remaining_functions` → `add_matches_internal` (2696) → `check_match` (1906) → 1871.

None of these frames has an `except`; `diff()` has only `try/finally` (3593-3700). Experiment B (scratch `v03b/expB.py`) used 10 functions with equal `mangled_function`, one changed with a different address, and its diff-side assembly ending in `" nop"` or an empty line. Both variants reproduced the crash:

- traceback `diaphora.py:3624 → 2183 → 1871 → 1458 → patch_diff_vulns.py:216 → 162`
- `IndexError: string index out of range`
- exit code 1
- **no output file**

The same data without the leading space finished normally: Best 9, Partial 1, file saved. The hook fires only for pairs where `check_match` reaches 1871 with `r < 1.0` (`on_match` line 206).

### 4.5 ML engine (not default)

ml/basic_engine.py:76-89 defines a function named `quick_ratio`, verbatim core:

```python
  if buf1 is None or buf2 is None or buf1 == "" or buf2 == "":
    return 0

  if buf1 == buf2:
    return 1.0

  s1 = buf1.lower().split('\n')
  s2 = buf2.lower().split('\n')
  seq = SequenceMatcher(None, s1, s2)
  return seq.ratio()
```

Despite its name it returns `ratio()`, after a None/empty guard and an exact-equality shortcut. The full `ratio()` path, §5.2-§5.7, would apply there. It has its own cdifflib import fallback (basic_engine.py:9-12). Its only caller is `compare_row` (basic_engine.py:131), for str fields that do not start with `[`.

It is reached only through `get_model_ratio`, which needs `self.classifier`, which is set only in `apply_machine_learning` when `ML_AVAILABLE and self.use_trained_model` (diaphora.py:3551-3555). `use_trained_model` defaults to `ML_USE_TRAINED_MODEL = False`. **Runs by default? No.**

---

## 5. Python 3.13.12 `difflib.SequenceMatcher`: porting spec

All call sites use `SequenceMatcher(None, a, b)` with `isjunk=None` and `autojunk=True` (the default). `a` and `b` are lists of Python `str` lines. `unified_diff` builds `SequenceMatcher(None,a,b)` (difflib.py:1138).

### 5.1 Construction, `set_seq2` and `__chain_b` (the autojunk rule)

difflib.py:179-182, 243-248, 277-303, verbatim:

```python
        self.isjunk = isjunk
        self.a = self.b = None
        self.autojunk = autojunk
        self.set_seqs(a, b)
...
        if b is self.b:
            return
        self.b = b
        self.matching_blocks = self.opcodes = None
        self.fullbcount = None
        self.__chain_b()
...
        b = self.b
        self.b2j = b2j = {}

        for i, elt in enumerate(b):
            indices = b2j.setdefault(elt, [])
            indices.append(i)

        # Purge junk elements
        self.bjunk = junk = set()
        isjunk = self.isjunk
        if isjunk:
            for elt in b2j.keys():
                if isjunk(elt):
                    junk.add(elt)
            for elt in junk: # separate loop avoids separate list of keys
                del b2j[elt]

        # Purge popular elements that are not junk
        self.bpopular = popular = set()
        n = len(b)
        if self.autojunk and n >= 200:
            ntest = n // 100 + 1
            for elt, idxs in b2j.items():
                if len(idxs) > ntest:
                    popular.add(elt)
            for elt in popular: # ditto; as fast for 1% deletion
                del b2j[elt]
```

**Spec.**

- `b2j` maps each distinct element of `b` to its **ascending** index list.
- `bjunk` is **always empty**, because `isjunk` is `None`.
- If `len(b) >= 200`: let `ntest = len(b) / 100 + 1` (integer division). Every element with **count > ntest** (strictly greater) is removed from `b2j`.
  - Examples: n=200..299 gives ntest=3, so 4 or more occurrences are popular. n=300 gives 4. Verified: 3 copies in n=200 are not popular; 4 copies are.
  - Popular elements are **not** added to `bjunk`.
  - **Only `b` (the second sequence) is ever purged.** The algorithm is asymmetric.
- If `len(b) < 200`, nothing is purged.

### 5.2 `find_longest_match(alo, ahi, blo, bhi)` (difflib.py:363-419)

```python
        a, b, b2j, isbjunk = self.a, self.b, self.b2j, self.bjunk.__contains__
        if ahi is None:
            ahi = len(a)
        if bhi is None:
            bhi = len(b)
        besti, bestj, bestsize = alo, blo, 0
        # find longest junk-free match
        # during an iteration of the loop, j2len[j] = length of longest
        # junk-free match ending with a[i-1] and b[j]
        j2len = {}
        nothing = []
        for i in range(alo, ahi):
            # look at all instances of a[i] in b; note that because
            # b2j has no junk keys, the loop is skipped if a[i] is junk
            j2lenget = j2len.get
            newj2len = {}
            for j in b2j.get(a[i], nothing):
                # a[i] matches b[j]
                if j < blo:
                    continue
                if j >= bhi:
                    break
                k = newj2len[j] = j2lenget(j-1, 0) + 1
                if k > bestsize:
                    besti, bestj, bestsize = i-k+1, j-k+1, k
            j2len = newj2len

        # Extend the best by non-junk elements on each end.  In particular,
        # "popular" non-junk elements aren't in b2j, which greatly speeds
        # the inner loop above, but also means "the best" match so far
        # doesn't contain any junk *or* popular non-junk elements.
        while besti > alo and bestj > blo and \
              not isbjunk(b[bestj-1]) and \
              a[besti-1] == b[bestj-1]:
            besti, bestj, bestsize = besti-1, bestj-1, bestsize+1
        while besti+bestsize < ahi and bestj+bestsize < bhi and \
              not isbjunk(b[bestj+bestsize]) and \
              a[besti+bestsize] == b[bestj+bestsize]:
            bestsize += 1

        # Now that we have a wholly interesting match (albeit possibly
        # empty!), we may as well suck up the matching junk on each
        # side of it too.  ...
        while besti > alo and bestj > blo and \
              isbjunk(b[bestj-1]) and \
              a[besti-1] == b[bestj-1]:
            besti, bestj, bestsize = besti-1, bestj-1, bestsize+1
        while besti+bestsize < ahi and bestj+bestsize < bhi and \
              isbjunk(b[bestj+bestsize]) and \
              a[besti+bestsize] == b[bestj+bestsize]:
            bestsize = bestsize + 1

        return Match(besti, bestj, bestsize)
```

**Spec (`isjunk=None`, so `bjunk` is empty; the last two loops never run and `not isbjunk(...)` is always true).**

```
find_longest_match(alo, ahi, blo, bhi):
  besti = alo; bestj = blo; bestsize = 0
  prev = {}                                   // j -> run length ending at (i-1, j)
  for i in [alo, ahi):
    cur = {}
    for j in b2j[a[i]] ascending (skip entirely if a[i] not in b2j, i.e. absent or POPULAR):
      if j < blo: continue                    // NOT recorded in cur
      if j >= bhi: break
      k = prev.get(j-1, 0) + 1
      cur[j] = k
      if k > bestsize:                        // STRICT: first-found wins ties
        besti = i-k+1; bestj = j-k+1; bestsize = k
    prev = cur
  // extend over ANY equal elements (popular ones included), backwards then forwards
  while besti > alo && bestj > blo && a[besti-1] == b[bestj-1]: besti--, bestj--, bestsize++
  while besti+bestsize < ahi && bestj+bestsize < bhi && a[besti+bestsize] == b[bestj+bestsize]: bestsize++
  return (besti, bestj, bestsize)
```

**Tie-breaking and consequences.** All of these were verified on stdlib 3.13.12:

- **Among the longest non-popular runs, the earliest in `a` wins, then the earliest in `b`.** Iteration is by the run's end `i` ascending, then `j` ascending, and only `>` replaces. Example: `list("abXab")` vs `list("ab_ab")` gives `(0,0,2)`, and `list("ab")` vs `list("abab")` gives `(0,0,2)`.
- **Extension happens after the choice, so the result is not necessarily the longest match.**
  - Setup: `b = [P×5, q, P×5, u0..u188]` (len 200, P popular) and `a = [q,P,P,z,P,P,P,q,P,P]`.
  - The DP sees only `q`, finds a length-1 run at a[0]↔b[5] first, and keeps it. Forward extension gives **`(0,5,3)`**, even though `a[4:10] == b[2:8]` is a 6-long match.
- **When the DP finds nothing** (every shared element is popular or absent), the block starts at `(alo, blo, 0)` and is extended forward from there:
  - With `b = [P,P,P,P,u0..u195]`: `a=[P,x]` gives `(0,0,1)`.
  - `a=[x,P]` gives `(0,0,0)`. Then `get_matching_blocks = [(2,200,0)]` and `ratio = 0.0`, while `quick_ratio = 0.009901`.
- **Autojunk effect.** With `b = [u0..u195, P,P,P,P]` and `a = [P,P,P,P]`, the default gives blocks `[(4,200,0)]` and `ratio 0.0`. `autojunk=False` would give `[(0,196,4),(4,200,0)]`. In a 2,000-case fuzz of realistic repetitive line lists (length 200-400, 10 inserts), autojunk changed the opcodes in **2000/2000** cases. **Porting without autojunk will not match.**

**C++ implementation note.** Each row's map holds keys `j` from a single `b2j` list, the one for that row's `a[i]`, in ascending order and filtered to `[blo, bhi)`. Store each row as a vector of `(j, k)` in ascending `j`. Resolve `prev.get(j-1)` with a monotone pointer, because both lists ascend. Do **not** use a dense `len_b` array unless you reset exactly the touched entries: a stale `k` from row `i-2` must read as 0.

### 5.3 `get_matching_blocks()` (difflib.py:440-490)

This is verbatim except that comment lines 444-449, 455-457, 466-468 and 474-481 are left out.

```python
        if self.matching_blocks is not None:
            return self.matching_blocks
        la, lb = len(self.a), len(self.b)
        queue = [(0, la, 0, lb)]
        matching_blocks = []
        while queue:
            alo, ahi, blo, bhi = queue.pop()
            i, j, k = x = self.find_longest_match(alo, ahi, blo, bhi)
            if k:   # if k is 0, there was no matching block
                matching_blocks.append(x)
                if alo < i and blo < j:
                    queue.append((alo, i, blo, j))
                if i+k < ahi and j+k < bhi:
                    queue.append((i+k, ahi, j+k, bhi))
        matching_blocks.sort()

        i1 = j1 = k1 = 0
        non_adjacent = []
        for i2, j2, k2 in matching_blocks:
            # Is this block adjacent to i1, j1, k1?
            if i1 + k1 == i2 and j1 + k1 == j2:
                k1 += k2
            else:
                if k1:
                    non_adjacent.append((i1, j1, k1))
                i1, j1, k1 = i2, j2, k2
        if k1:
            non_adjacent.append((i1, j1, k1))

        non_adjacent.append( (la, lb, 0) )
        self.matching_blocks = list(map(Match._make, non_adjacent))
        return self.matching_blocks
```

**Spec.**

- Recursively split into left `(alo,i,blo,j)` and right `(i+k,ahi,j+k,bhi)` sub-ranges. Recurse only when both sides of a range are non-empty, and only if `k > 0`.
- Processing order does not matter: sub-ranges are disjoint. An in-order recursion produces the sorted list directly, and the fuzz confirmed it is identical.
- Sort by `(i, j, k)`. The `i` values are distinct, so sorting by `i` alone is enough.
- Merge adjacent blocks. The first comparison is against the `(0,0,0)` seed, so a block at `(0,0,k)` merges into it harmlessly.
- Append the sentinel `(la, lb, 0)`.

### 5.4 `get_opcodes()` (difflib.py:521-545)

The quote starts at line 523. Lines 521-522 are `if self.opcodes is not None: return self.opcodes`, the cache that `get_grouped_opcodes` then mutates (§5.5). Comment lines 526-530 are left out.

```python
        i = j = 0
        self.opcodes = answer = []
        for ai, bj, size in self.get_matching_blocks():
            tag = ''
            if i < ai and j < bj:
                tag = 'replace'
            elif i < ai:
                tag = 'delete'
            elif j < bj:
                tag = 'insert'
            if tag:
                answer.append( (tag, i, ai, j, bj) )
            i, j = ai+size, bj+size
            # the list of matching blocks is terminated by a
            # sentinel with size 0
            if size:
                answer.append( ('equal', ai, i, bj, j) )
        return answer
```

### 5.5 `get_grouped_opcodes(n=3)` (difflib.py:572-595)

```python
        codes = self.get_opcodes()
        if not codes:
            codes = [("equal", 0, 1, 0, 1)]
        # Fixup leading and trailing groups if they show no changes.
        if codes[0][0] == 'equal':
            tag, i1, i2, j1, j2 = codes[0]
            codes[0] = tag, max(i1, i2-n), i2, max(j1, j2-n), j2
        if codes[-1][0] == 'equal':
            tag, i1, i2, j1, j2 = codes[-1]
            codes[-1] = tag, i1, min(i2, i1+n), j1, min(j2, j1+n)

        nn = n + n
        group = []
        for tag, i1, i2, j1, j2 in codes:
            # End the current group and start a new one whenever
            # there is a large range with no changes.
            if tag == 'equal' and i2-i1 > nn:
                group.append((tag, i1, min(i2, i1+n), j1, min(j2, j1+n)))
                yield group
                group = []
                i1, j1 = max(i1, i2-n), max(j1, j2-n)
            group.append((tag, i1, i2, j1 ,j2))
        if group and not (len(group)==1 and group[0][0] == 'equal'):
            yield group
```

- This is a generator in Python. Implement it as a function returning `vector<vector<Opcode>>`, applied to a **copy** of the opcodes; Python mutates its cached list, but the effect is invisible here.
- If both inputs are empty, the output is nothing.
- If the inputs are identical and non-empty, the output is nothing: the single `equal` group is suppressed.
- If `a` is empty and `b` is not, the output is one group with `('insert',0,0,0,lb)`.

### 5.6 `unified_diff(a, b, fromfile='', tofile='', fromfiledate='', tofiledate='', n=3, lineterm=...)` (difflib.py:1084-1161)

```python
def _format_range_unified(start, stop):
    'Convert range to the "ed" format'
    # Per the diff spec at http://www.unix.org/single_unix_specification/
    beginning = start + 1     # lines start numbering with one
    length = stop - start
    if length == 1:
        return '{}'.format(beginning)
    if not length:
        beginning -= 1        # empty ranges begin at line just before the range
    return '{},{}'.format(beginning, length)
...
    _check_types(a, b, fromfile, tofile, fromfiledate, tofiledate, lineterm)
    started = False
    for group in SequenceMatcher(None,a,b).get_grouped_opcodes(n):
        if not started:
            started = True
            fromdate = '\t{}'.format(fromfiledate) if fromfiledate else ''
            todate = '\t{}'.format(tofiledate) if tofiledate else ''
            yield '--- {}{}{}'.format(fromfile, fromdate, lineterm)
            yield '+++ {}{}{}'.format(tofile, todate, lineterm)

        first, last = group[0], group[-1]
        file1_range = _format_range_unified(first[1], last[2])
        file2_range = _format_range_unified(first[3], last[4])
        yield '@@ -{} +{} @@{}'.format(file1_range, file2_range, lineterm)

        for tag, i1, i2, j1, j2 in group:
            if tag == 'equal':
                for line in a[i1:i2]:
                    yield ' ' + line
                continue
            if tag in {'replace', 'delete'}:
                for line in a[i1:i2]:
                    yield '-' + line
            if tag in {'replace', 'insert'}:
                for line in b[j1:j2]:
                    yield '+' + line
```

With Diaphora's `lineterm=""` the output rows are:

1. If there is at least one group: exactly `"--- "` and `"+++ "`, each with a trailing space and no newline.
2. Per group, `"@@ -R1 +R2 @@"`, where `R(start,stop)` is:
   - `start+1` if `stop-start == 1`
   - `"start,0"` if the length is 0
   - otherwise `"start+1,len"`
3. Then per opcode: `' '+line` for equal; for replace, all `'-'+a-line` rows first, then all `'+'+b-line` rows; delete emits only `-`; insert emits only `+`.

For the patch-diff script (§4.4) the default `lineterm="\n"` gives `"--- \n"`, `"+++ \n"` and `"@@ … @@\n"`. Content lines never get a terminator.

### 5.7 `ratio`, `quick_ratio`, `real_quick_ratio`, `_calculate_ratio`

difflib.py:39-42, 619-620, 632-649, 658-661:

```python
def _calculate_ratio(matches, length):
    if length:
        return 2.0 * matches / length
    return 1.0
...
        matches = sum(triple[-1] for triple in self.get_matching_blocks())
        return _calculate_ratio(matches, len(self.a) + len(self.b))
...
        if self.fullbcount is None:
            self.fullbcount = fullbcount = {}
            for elt in self.b:
                fullbcount[elt] = fullbcount.get(elt, 0) + 1
        fullbcount = self.fullbcount
        # avail[x] is the number of times x appears in 'b' less the
        # number of times we've seen it in 'a' so far ... kinda
        avail = {}
        availhas, matches = avail.__contains__, 0
        for elt in self.a:
            if availhas(elt):
                numb = avail[elt]
            else:
                numb = fullbcount.get(elt, 0)
            avail[elt] = numb - 1
            if numb > 0:
                matches = matches + 1
        return _calculate_ratio(matches, len(self.a) + len(self.b))
...
        la, lb = len(self.a), len(self.b)
        # can't have more matches than the number of elements in the
        # shorter sequence
        return _calculate_ratio(min(la, lb), la + lb)
```

- `quick_ratio`: `matches = Σ_x min(count_a(x), count_b(x))`. It uses the full `b`, with no popular purge.
- `ratio`: `matches` is the sum of the matching-block sizes, which **depends on autojunk and tie-breaking**. It is not used in the default diff.
- `real_quick_ratio`: `2·min(la,lb)/(la+lb)`.
- When `length == 0`, the result is `1.0`. This cannot happen through Diaphora's guarded wrappers.

### 5.8 Line-splitting cheat sheet (the three different splitters in play)

| Where | Python call | Splits on | Trailing separator |
|---|---|---|---|
| `quick_ratio` / `real_quick_ratio` (diff) | `s.split("\n")` | `\n` only | produces a trailing `""` element |
| `find_one_match_diffing` (diff) | `s.splitlines(keepends=False)` | 10 separators (§4.3.1), `\r\n` as one | no trailing element |
| `get_cmp_asm_lines` (export) | `StringIO(s).readlines()` + `strip("\n")` | `\n` only | no trailing element |
| patch-diff script | `s.split("\n")` | `\n` only | trailing `""` |

### 5.9 Verification record

- `spec03b/port.py` is a clean-room reimplementation of `__chain_b`, `find_longest_match`, recursive `get_matching_blocks`, `get_opcodes`, `get_grouped_opcodes`, `unified_diff(lineterm="")`, `ratio`, `quick_ratio` and `real_quick_ratio`, written as the C++ should be. It was compared with stdlib outputs for equality of matching blocks, full unified-diff row lists and all three ratios. **6,000 random cases over 2 seeds, 0 mismatches.** The cases covered lengths from 0 to about 1,000, the 199/200/201 boundaries, small alphabets and deliberately popular elements.
- `spec03b/hand.py` holds the regex-free matchers for `get_cmp_asm`, `get_cmp_asm_lines`, `get_cmp_pseudo_lines` and `CPP_NAMES_RE`, checked against Diaphora's own methods: **120,000 random strings over 3 seeds, 0 mismatches.**
- The scratch scripts are in `<scratch>\spec03b\` (`port.py`, `hand.py`, `t1.py`-`t6.py`, `vec.py`, `tc.cpp`). They are session scratch, not part of the repo, and may be deleted. Each one can be rebuilt from this document.

---

## 6. Graph comparison (`compare_graphs_pass`, `compare_graphs`, `get_graph`): UI only

**Used in matching? No.** The only caller is `graph_diff_internal` (diaphora_ida.py:1768-1784), which builds `CDiffGraphViewer` windows. It is reached from the chooser popup commands `cmd_diff_graph` and `cmd_diff_graph_microcode` (diaphora_ida.py:539-554). No `diaphora.py` diff-path function calls any of the three (grep over the repo, excluding `pygments/`). The results are colours (`GRAPH_BBLOCK_MATCH_*`, diaphora_config.py:39-41), never ratios or matches. **Runs by default? No.** A C++ port needs none of this for parity. The spec below is for completeness, if the native tool ever wants the same block colouring.

`get_graph(ea1, primary, asm_type="native")` (diaphora.py:1188-1267) returns:

- `bb_blocks`: `{str(int(bb.address)) -> [[str(int(ins.address)), mnemonic, disasm], ...]}`, in the SQL order `order by bb.address asc`. `basic_blocks.address` is declared `text` (db_support/schema.py:147-151). SQLite's TEXT affinity stores inserted integers as text, so this order is **lexicographic**. An instruction address seen before is skipped (the `dones` set).
- `bb_relations`: `{str(parent bb address) -> set(str(child bb address))}` from `bb_relations`.

`compare_graphs(g1, g2)` (1165-1186) sets every block to `GRAPH_BBLOCK_MATCH_NONE`, then runs `compare_graphs_pass(..., is_second=False)` followed by `(..., is_second=True)`.

`compare_graphs_pass` (1105-1163), core (lines 1112-1163). The code is verbatim, but the comment lines 1146-1147 and 1154-1159 are left out:

```python
    for key1 in bblocks1:
      if key1 in dones1:
        continue

      for key2 in bblocks2:
        if key2 in dones2:
          continue

        # Same number of instructions?
        if len(bblocks1[key1]) == len(bblocks2[key2]):
          mod = False
          partial = True
          i = 0
          for ins1 in bblocks1[key1]:
            ins2 = bblocks2[key2][i]
            # Same mnemonic? The change can be only partial
            if ins1[1] != ins2[1]:
              partial = False

            # Try to compare the assembly after doing some cleaning
            cmp_asm1 = self.get_cmp_asm(ins1[2])
            cmp_asm2 = self.get_cmp_asm(ins2[2])
            if cmp_asm1 != cmp_asm2:
              mod = True
              if not partial:
                continue
            i += 1

          if not mod:
            colours1[key1] = config.GRAPH_BBLOCK_MATCH_PERFECT
            colours2[key2] = config.GRAPH_BBLOCK_MATCH_PERFECT
            dones1.add(key1)
            dones2.add(key2)
            break
          elif not is_second and partial:
            colours1[key1] = config.GRAPH_BBLOCK_MATCH_PARTIAL
            colours2[key2] = config.GRAPH_BBLOCK_MATCH_PARTIAL
            break
    return colours1, colours2
```

Quirks:

- Once `partial` is False and a cleaned line differs, `i` is **not** incremented (`continue` at 1142). Later `ins1` values are compared with the same `ins2` until one whose cleaned text equals it arrives; then `i` advances again. A mnemonic mismatch with equal cleaned text still advances `i`. `bblocks2[key2][i]` cannot go out of range, because `i` never exceeds the number of iterations.
- Instruction order inside a block is the SQL row order. The `get_graph` query has only `order by bb.address asc` (1219), with no tiebreak on instruction address, so the order within a block depends on the query plan. This is UI only.
- A partial match does not enter `dones`, so a later perfect match can overwrite its colour.
- The `dones1`/`dones2` sets are local to each pass.
- `get_cmp_asm` here runs on the raw `instructions.disasm` column, and the `re_cache` is shared.

---

## 7. `jkutils` at diff time

### 7.1 `factor.difference` via `get_callgraph_difference` (runs by default, log-only)

diaphora.py:1288-1338. It is called from `check_callgraph` (1326-1338), which `diff()` calls at diaphora.py:3605. That call sits inside `if self.do_continue:`. `do_continue` is set to True at 3599, and in standalone mode nothing clears it: the only `do_continue = False` is in the IDA subclass's `equal_db` override, diaphora_ida.py:3621-3631. So the call is effectively unconditional:

```python
      sql = """select callgraph_primes, callgraph_all_primes from program
        union all
        select callgraph_primes, callgraph_all_primes from diff.program"""
      cur.execute(sql)
      rows = cur.fetchall()
      if len(rows) == 2:
        cg1 = decimal.Decimal(rows[0]["callgraph_primes"])
        cg_factors1 = json.loads(rows[0]["callgraph_all_primes"])
        cg2 = decimal.Decimal(rows[1]["callgraph_primes"])
        cg_factors2 = json.loads(rows[1]["callgraph_all_primes"])

        if cg1 == cg2:
          self.equal_callgraph = True
          ...
          return 0
        else:
          FACTORS_CACHE[cg1] = cg_factors1
          FACTORS_CACHE[cg2] = cg_factors2
          diff = difference(cg1, cg2)
          total = sum(cg_factors1.values())
          if total == 0 or diff == 0:
            return 0

          percent = diff * 100.0 / total
          return percent
      else:
        raise Exception(f"Not enough rows in databases! Size is {len(rows)}")
```

The factor.py:202-242 functions involved:

```python
FACTORS_CACHE = {}
def _difference(num1, num2):
  nums = [num1,
          num2]
  s = []
  for num in nums:
    if num in FACTORS_CACHE:
      x = FACTORS_CACHE[num]
    else:
      x = factorization(int(num))
      FACTORS_CACHE[num] = x
    s.append(x)

  diffs = {}
  for x in list(s[0].keys()):
    if x in list(s[1].keys()):
      if s[0][x] != s[1][x]:
        diffs[x] = max(s[0][x], s[1][x]) - min(s[0][x], s[1][x])
    else:
      diffs[x] = s[0][x]
  
  for x in list(s[1].keys()):
    if x in list(s[0].keys()):
      if s[1][x] != s[0][x]:
        diffs[x] = max(s[0][x], s[1][x]) - min(s[0][x], s[1][x])
    else:
      diffs[x] = s[1][x]

  return diffs, s

def difference(num1, num2):
  diffs, _ = _difference(num1, num2)
  return sum(diffs.values())
```

The factor.py excerpt above is verbatim except that the docstrings at 204-206 and 237-240 are left out.

**Spec.** `difference` is reached only when `cg1 != cg2` (Decimal comparison, 1305); equal values return 0 at 1310. The cache is pre-seeded at 1312-1313 with the Decimal objects as keys, so no factorisation runs. `difference = Σ over keys k in (keys1 ∪ keys2) of |c1(k) − c2(k)|`, with a missing count taken as 0. The keys are the JSON object's **string** keys, the `primes_value` strings written at export (diaphora_ida.py:1160-1176, 1240-1270, `json.dumps` of a `{primes_value_str: count}` dict). `percent = diff*100.0/sum(cg_factors1.values())`.

**Consumers:** `check_callgraph` stores it in `self.percent` and logs it. **Neither `self.percent` nor `self.equal_callgraph` is read anywhere else** (grep of all `.py` files outside `pygments/`). **Parity impact: none on matches.** The only effect is failure behaviour. `diff()` wraps the whole run in `try/finally` with no `except` (diaphora.py:3593-3700), so any of these aborts the run before `save_results`:

- If `main.program` and `diff.program` together hold a row count other than exactly 2, it raises `Exception("Not enough rows ...")`. With 2 rows split unevenly, say 2+0, it silently compares the wrong rows.
- `callgraph_primes` NULL or not a valid decimal raises `TypeError` or `decimal.InvalidOperation`.
- `callgraph_all_primes` NULL or not JSON raises `TypeError` or `JSONDecodeError` at 1301/1303. This happens always, even when `cg1 == cg2`, because both `json.loads` calls run before the comparison.
- `callgraph_all_primes` is valid JSON but not an object (for example a list). This raises `AttributeError` **only when `cg1 != cg2`**, from `.keys()`/`.values()` in `_difference`/`sum(...)`. JSON object values that are not numbers raise `TypeError` in the same branch.

All of these escape `diff()` the same way as §4.3.4: there is no `except` on the path `get_callgraph_difference` → `check_callgraph` → `diff()` → `__main__`, so no output file is written. This is derived from source, not run. The native diff should at least detect these conditions. Whether to mirror the abort is a product decision (Open question 3).

### 7.2 `factor.difference_ratio` via `ast_ratio`: relaxed mode only

diaphora.py:180-190 and 1637-1643:

```python
def ast_ratio(ast1, ast2):
  if ast1 is None or ast2 is None:
    return 0
  if ast1 == ast2:
    return 1.0
  return difference_ratio(decimal.Decimal(ast1), decimal.Decimal(ast2))
...
  def ast_ratio(self, ast1, ast2):
    if not self.relaxed_ratio:
      return 0
    return ast_ratio(ast1, ast2)
```

Called only from `check_ratio` when `self.relaxed_ratio`, `ast1 is not None`, `ast2 is not None` and `max(len(ast1), len(ast2)) < 16` all hold (diaphora.py:1687-1697). **Runs by default? No.** If ever ported, note these properties:

- `difference_ratio = 1 − Σdiffs / max(Σexp1, Σexp2)` (factor.py:245-249).
- It raises `ZeroDivisionError` when both values factor to `{}`, i.e. are 0 or 1.
- Factorisation uses `random` in Miller-Rabin (`isprime`, 7 random bases) and Pollard-Brent. The factor multiset is unique in theory; `isprime` misclassification is probabilistic. NOT DETERMINED FROM SOURCE whether results are reproducible across runs; Python's `random` is not seeded here.

### 7.3 `primesbelow` at init

`self.primes = primes(2048 * 2048)` (diaphora.py:376). At diff time `self.primes` is read only by export code (diaphora_ida.py:2620, 2682, 2714, 2970). It costs time and memory with no effect on the output.

### 7.4 `kfuzzy`

`self.kfh = CKoretFuzzyHashing(); self.kfh.bsize = config.FUZZY_HASHING_BLOCK_SIZE` (diaphora.py:390-392). The class has no `__init__`, so this just creates the object. `hash_bytes` is called only at export (diaphora_ida.py:2550) to fill `pseudocode_hash1/2/3`. The diff compares those columns only by SQL equality or `substr(...,1,16)` equality (diaphora_heuristics.py:649-654, 785, 801, 816, 848, 864, 880, 1025-1028). **No kfuzzy code runs at diff time; nothing to port for the diff.**

---

## 8. Side findings for sibling specs (verified while tracing call sites)

1. **Experimental heuristics do not run by default.** `find_experimental_matches()` sits **inside** `if self.unreliable:` (diaphora.py:3638-3651, all spaces, 12-column indent), and `DIFFING_ENABLE_UNRELIABLE = False`. So `run_heuristics_for_category("Experimental")` (diaphora.py:2307-2311) is **skipped** in a default standalone diff, whatever `DIFFING_ENABLE_EXPERIMENTAL = True` says. That flag only gates `apply_dirty_heuristics` (diaphora.py:3618-3621).
2. **The description of the diffing-matches heuristic carries the inner iteration number 1..3** (§4.3.4), not the outer loop counter. In the default config it is always `#1` (§4.3.2 quirk 5).
3. **(Corrected in review.)** `itemize_for_chooser` (diaphora.py:2718-2730) has misleading **local variable names**: `ratio = item[4]`, `nodes1 = item[5]`, `nodes2 = item[6]`, `desc = item[7]`. It passes them **positionally** to `CChooser.Item(ea, name, ea2, name2, desc, ratio, nodes1, nodes2)` (diaphora.py:237). Because the call is positional, the resulting fields are **correct**:
   - `description = item[4]`
   - `ratio = item[5]`
   - `nodes1 = int(item[6])`
   - `nodes2 = int(item[7])`

   Verified by calling it on `[0x401000,"foo",0x402000,"bar","Some heuristic",0.8765,7,9]`, which gave `description='Some heuristic', ratio=0.8765, nodes1=7, nodes2=9` (scratch `v03b/item.py`). `find_matches_diffing_internal` uses only `vfname`/`vfname2` anyway. The only way this path can raise is `int(item[6])`/`int(item[7])` on a non-integer node value.
4. `get_function_row(name)` (diaphora.py:2445-2460) is `select * ... where name = ?` + `fetchone()`, with no `ORDER BY`. For duplicate names, which row wins is decided by SQLite's plan. NOT DETERMINED FROM SOURCE beyond "first row returned".
5. **`MIN_FUNCTIONS_TO_DISABLE_SLOW = 4001` has no effect in standalone mode.** Its only reader is the IDA options dialog default, `"slow", total_functions <= config.MIN_FUNCTIONS_TO_DISABLE_SLOW` (diaphora_ida.py:3798-3800), which is copied into `bd.slow_heuristics` at diaphora_ida.py:3714. `python diaphora.py db1 db2` uses `self.slow_heuristics = get_value_for("slow_heuristics", DIFFING_ENABLE_SLOW_HEURISTICS)` (diaphora.py:409-411), which is **True whatever the function count**. Sibling specs and the oracle harness must not auto-disable slow heuristics at 4,001 functions.

---

## Hard parts

1. **Exact difflib parity in `unified_diff`.** You need all of:
   - the autojunk purge (n ≥ 200, count > n/100+1, on `b` only)
   - strict `>` first-found tie-breaking
   - extension over popular elements *after* the DP choice, including the empty-DP case extending forward from `(alo, blo)`
   - the `j < blo` skip that does not record
   - group splitting at `> 2n` equal lines

   Any "better" LCS or Myers diff produces different hunks and therefore different candidate pairs. Port it literally and keep `spec03b/port.py`-style differential tests.
2. **`splitlines()` versus `split("\n")`.** The two diff-time consumers split differently (§5.8). `splitlines` needs UTF-8-aware detection of `C2 85`, `E2 80 A8` and `E2 80 A9`, and `\r\n` must count as one separator.
3. **The positional name pairing and pending-buffer quirks in `find_one_match_diffing`** (§4.3.2): headers inside the buffers, unflushed trailing hunks, accumulation across hunks, a shared `dones` set. These must be reproduced bug for bug. That includes the string-keyed `dones` and its consequences: no seed is processed in inner iteration ≥2, and a match found by this heuristic is shadowed as a seed for the same field whenever its discoverer sorts first.
4. **The 7-decimal rounding** must be done with a correctly rounded formatter (`std::to_chars`), never `std::round(v*1e7)/1e7`, which disagrees on exact ties and on the binary expansion.
5. **Unicode case folding** in the normalisers and `CPP_NAMES_RE`: the four extra code points (U+0130, U+0131, U+017F, U+212A), and code-point-based length counting in `{3,}`.
6. **Stable sort** for `get_sorted_results` (the order of matches processed) and the order-dependent `dones` set.
7. **`REMS` removal also eats hex chars** (`dword ptr ds:` becomes `s:`), and the pass order produces `qs:` from `qword ptr cs:`. These only matter if the native tool writes its own `clean_assembly`.

## Open questions

1. **Does DSigMatcher's exporter write `clean_assembly`, `clean_pseudo` and `clean_microcode` itself, or only read Diaphora exports?**
   - **Partly resolved (review).** The current code only reads them. `src/ExportDatabase.cpp` opens the database read-only and lists them as read fields at lines 64-66. No `src/` code writes them; see the §3 box.
   - **Still open, as a product decision:** will a future native exporter write them? If it does, §3 applies, and Zydis disassembly text will not match IDA's `GetDisasm` text anyway. Parity of `v2` then depends on the *disassembly text*, not only on this normaliser.
2. **cdifflib.** It is not installed here, and its source is not on this PC: no copy was found in miniconda `pkgs` or site-packages. If a future oracle machine has it, the class behind `quick_ratio`/`real_quick_ratio` changes. **NOT DETERMINED FROM SOURCE** whether `CSequenceMatcher` is bit-identical.
   - `unified_diff` always uses the stdlib class (difflib.py:1138), so only `quick_ratio` would be affected (plus `real_quick_ratio` and the ML `ratio`, which are not default).
   - `quick_ratio` is algorithmically trivial (a multiset count). The expected risk is low but unverified.
   - Mitigation: oracle runs must keep cdifflib uninstalled. Record `HAS_CDIFFLIB` or the import warning line in the oracle log.
3. **Crash parity.** Several diff-time paths abort the whole Python run. **The propagation question is now resolved:** every path below escapes `diff()`, the process exits 1 with a traceback, `save_results` never runs, and no output file is written. A stale file from an earlier run is not deleted.
   - §7.1 program-table and callgraph-column problems (derived from source).
   - §4.3.4 `ZeroDivisionError` when both functions have `nodes == 0`. Verified by experiment Z.
   - §4.4 patch-diff `IndexError` on an empty or space-led added asm line, or on an empty or space-led removed line when the added mnemonic starts with `b`. Verified by experiment B. The call runs on the main thread from `find_same_name` or `find_remaining_functions`, never from a heuristic thread.

   **Still open, as a product decision:** should the native diff replicate the abort (no output), or skip and continue? Oracle harnesses must delete the old output file before each run, and must treat a non-zero exit as "Diaphora produced nothing", not as an empty result.
4. **Invalid UTF-8 in TEXT columns.** Python's `sqlite3` with `text_factory=str` (diaphora.py:346) raises `sqlite3.OperationalError: Could not decode to UTF-8 column '<col>' with text '...'` on fetch. This was verified on Python 3.13.12 with `cast(x'61ff62' as text)`. C++ `sqlite3_column_text` returns the raw bytes instead. NOT DETERMINED whether any real export contains such bytes. Decide on a policy, and consider asserting in debug builds.
5. **Whether any existing export stores `basic_blocks.address` values that are not canonical decimal text** (§6, which only affects the UI colouring order). Not relevant to parity.

---

## Verification log (adversarial review, 2026-09-23)

This is an independent re-check of every behavioural claim, quoted excerpt and line number in this file. It was checked against Diaphora `621ec26` (`3.4.2-4-g621ec26`, working tree clean) and against `<conda>\Lib\difflib.py` (md5 `60d095550edf66222f142d8bbb9feff5`, 2056 lines) on Python 3.13.12.

The experiments ran on a `git archive HEAD` copy of Diaphora under scratch `v03b/dref/`, with `python -B`, so `<diaphora-ref>` was not modified by this review. Note that `diaphora-ref` already contains git-ignored `__pycache__/` directories, with timestamps 00:04 and 00:07 from earlier agents' imports. They were left untouched.

Scratch directory: `<scratch>\v03b\`.

### Re-verified as correct (no change needed)

- **§1:**
  - Python version, difflib path and md5, cdifflib absent, sklearn 1.8.0.
  - diaphora.py:41-51 import fallback, verbatim.
  - All eight `diaphora_config.py` values and line numbers.
  - `get_value_for` (560-569) semantics.
- **§2 call map:** every call-site line (grep over all non-`pygments` `.py` files).
  - `re_sub` has no callers outside the two normalisers.
  - No `diaphora.py` diff-path function calls `compare_graphs*`/`get_graph`/`prettify_asm`.
  - `graph_diff_internal` is reached only via `graph_diff`/`graph_diff_microcode` (diaphora_ida.py:1786-1791) from the chooser (546, 554).
- **§3:**
  - The code quotes of `prettify_asm`, `re_sub`, `get_cmp_asm_lines`, `get_cmp_pseudo_lines` and `get_cmp_asm` (1015-1102) are verbatim.
  - `CLEANING_CMP_REPS`/`REMS` (config 152-155) are verbatim.
  - All test vectors A1-A36, L1-L5 and P1-P11 were re-run against Diaphora's own methods: **0 mismatches** (`v03b/vec.py`).
  - The Unicode case-fold claims were re-enumerated over all 0x110000 code points (`v03b/uni.py`). The results are exactly as stated, and no pattern contains a literal `i`, the only other letter with extra folds (U+0130/U+0131).
  - The export call sites (diaphora_ida.py:2540-2594, 2657-2688, 2703-2726, 2815-2839, 2959-2963, 2995) and the `loc_%x:` rule are correct.
- **§4.1-4.2:**
  - `check_bufs`/`quick_ratio`/`real_quick_ratio` (150-176) are verbatim.
  - The `check_ratio` excerpt (1675-1753) is verbatim with the elisions marked.
  - All default-config facts hold: v1 is gated on the raw `pseudo`, v2 is ungated, v5 is the only early return, and the relaxed `real_quick_ratio`-on-primes = 1.0 quirk is real.
  - `SELECT_FIELDS` 51-75 and `compare_function_rows` 2479-2538 are correct.
- **§4.3:**
  - `diff()` control flow 3593-3700 and `find_matches_diffing*` (3150-3229) are correct.
  - `functions_exists` (2969-2991), `get_sorted_results` (3133-3140), the `find_one_match_diffing` logic and `CPP_NAMES_RE` (114) are correct.
  - The splitlines separator set was re-enumerated: exactly `0a 0b 0c 0d 1c 1d 1e 85 2028 2029`.
  - Quirks 1, 3, 4 and 6 are correct.
- **§5:**
  - All difflib quotes and line numbers are correct: 39-42, 179-182, 243-248, 277-303, 363-419, 440-490, 521-545, 572-595, 619-661, 1084-1161, 1138.
  - All worked examples were re-run (`v03b/dl.py`), including the tie-break and popular-extension examples and the n = 200/299/300 `ntest` boundaries.
- **§6:** `get_graph`/`compare_graphs`/`compare_graphs_pass` code, and `basic_blocks.address text` at schema.py:150.
- **§7:**
  - factor.py 202-249 logic.
  - `primesbelow` at 376, where `self.primes` is read only in diaphora_ida.py (2620, 2682, 2714, 2970).
  - `CKoretFuzzyHashing` has no `__init__` (kfuzzy.py:57-65), `hash_bytes` is called only at diaphora_ida.py:2550, and the pseudocode_hash SQL lines are as cited.
  - `self.percent`/`self.equal_callgraph` are never read.
- **Rounding:** MSVC `to_chars` agrees with Python, re-verified with `cl` 19.51.36246 (`v03b/tc2.cpp`), plus extra edge values (§4.2).
- **Independent difflib/walk re-derivation.**
  - `v03b/myport.py` was written **only from this document's text** (§4.1, §4.3.1-4.3.3, §5.1-5.6). It was fuzzed against stdlib `unified_diff`, `get_matching_blocks`, `quick_ratio`, `str.splitlines` and `re.findall(CPP_NAMES_RE, re.I)` in 10,000 cases over 3 seeds: **0 mismatches**.
  - `v03b/walkfuzz.py` compared the §4.3.2 walk pseudo-code with the real `CBinDiff.find_one_match_diffing` (with `functions_exists` stubbed to record candidates) in 4,000 cases, 1,900 of them with candidates. It checked candidate order and the final `dones`: **0 mismatches**.
  - The earlier `spec03b/hand.py` (seed 991, 40,000 strings) and `spec03b/port.py` (seed 992, 3,000 cases) were re-run with new seeds: 0 mismatches.

### Corrections made in place

1. **§8.3 was wrong.** It claimed `itemize_for_chooser` puts the description into `ratio` and the ratio into `nodes1`. Only the *local variable names* are shuffled; the positional call into `CChooser.Item(ea, name, ea2, name2, desc, ratio, nodes1, nodes2)` (237) yields correct fields. Verified by calling the real function (`v03b/item.py`). The note is rewritten.
2. **§4.3.2 quirk 2 was wrong in the general case.** It said a delete-only first hunk is always consumed with the headers. In fact the headers are flushed at the first context row of the diff, which is normally the leading context of the first hunk. A delete-only change after line 1 is therefore **not** consumed; it is carried forward and can pair positionally with a later hunk's `+` rows. Verified (`v03b/walk.py`: `('alpha_one','gamma_new')` cross-hunk pair). The note is rewritten.
3. **§4.4 / Open question 3: whether the patch-diff `IndexError` escapes `diff()` was left as NOT DETERMINED.** It is resolved: it escapes, on the main thread via `find_same_name` (3624 → 2183 → 1871) or `find_remaining_functions` (→ 2696 → 1906 → 1871).
   - Reproduced with experiment B (`v03b/expB.py`): exit 1, no output file, for both a space-led and an empty added line.
   - The `ZeroDivisionError` (§4.3.4) also escapes, reproduced with experiment Z (`v03b/expZ.py`).
   - §4.3.4, §4.4, §7.1 and Open question 3 are updated, and the oracle-harness consequence was added: delete stale output, and treat a non-zero exit as "no result".
4. **§4.4 loading condition was incomplete.** Four conditions were missing: the requirements that `self.experimental` is truthy, that `search_just_stripped_binaries` did not fire, and that `project_script` is None or empty, plus the exact percent formula.
5. **Summary 6, §2, §7.1: `factor.difference` does not run "unconditionally".** It is skipped when `cg1 == cg2` (1305-1310).
   - Error behaviour is split accordingly: `json.loads` errors always fire, while `AttributeError` on non-object JSON fires only when `cg1 != cg2`.
   - "Called unconditionally" is qualified with the `do_continue` guard, which cannot be False in standalone mode (only diaphora_ida.py:3631 clears it).
6. **§4.5: the ML `quick_ratio` was misdescribed.** It had been described as a bare `ratio()` call. It first returns `0` for a None or empty argument and `1.0` for exact equality (basic_engine.py:80-84). The verbatim core is now quoted.
7. **§4.2 rounding table.** It was presented as "exact ties", but 0.005859375, 0.0048828125 and 2/3 are not ties at 7 decimals. They are relabelled as controls.
8. **§6 quirk overstated.** "Every later `ins1` is compared with the same `ins2`" is true only until a cleaned-equal instruction arrives, after which `i` advances again. Reworded.
9. **Paraphrase presented as verbatim.** Several quotes silently dropped comment or docstring lines:
   - §5.3 and §5.4 (difflib comments, and the §5.4 cache lines 521-522)
   - the §6 "verbatim core" (1146-1147, 1154-1159)
   - the §7.1 factor.py excerpt (docstrings 204-206, 237-240)
   - the `find_one_match_diffing` quote, which skipped 3076-3078

   Each is now labelled with the exact elided lines. No code statement was altered in any quote.
10. **§7.2** omitted the `ast1 is not None and ast2 is not None` conditions (1689-1690) from the relaxed `ast_ratio` gate.
11. **§1 environment pitfall list was incomplete.** Added: `DIAPHORA_IGNORE_SMALL_FUNCTIONS`; `DIAPHORA_PROJECT_SCRIPT`; `DIAPHORA_SQL_TIMEOUT_LIMIT` and `DIAPHORA_SQL_MAX_PROCESSED_ROWS`, which become strings and raise `TypeError` at 1878/1894; `DIAPHORA_AUTO_DIFF`.

### Material added (omissions)

- **§4.3.2 quirk 5, the consequences of the shared, string-keyed `dones`.** Derived from source and confirmed with experiment A (`v03b/expA.py`, `drvA.py`, `ratioA.py`):
  - (a) Inner iterations ≥ 2 never process a seed in the default config, so the description suffix is always `(iteration #1)`.
  - (b) A match found by this heuristic is shadowed as a seed for the same field on later outer iterations whenever its discoverer sorts first, because the discoverer re-emits the key. In the experiment, `gamma_old_leaf→delta_new_leaf` (ratio 0.8908889, nodes 5/6) was never found.
  - (c) Names containing `-` can collide.
- **§4.3.2 quirks 6-7.** The "partial" snapshot is taken after the "best" loop. Seeds are re-read by name. The seed key is added before the NULL-field checks.
- **§4.3.4 and §7.1.** Exact propagation path and "no output file / stale file survives" behaviour.
- **§3 box.** Current DSigMatcher `src/` never writes `clean_*`; this resolves the factual part of Open question 1. Added a note that `CLEANING_CMP_REPS`'s other reader, `is_auto_generated`, is IDA-import only.
- **§6.** Instruction order within a block depends on the query plan (UI only).
- **§8.5 (for sibling specs and the orchestrator).** `MIN_FUNCTIONS_TO_DISABLE_SLOW = 4001` is read only by the IDA options dialog (diaphora_ida.py:3798-3800). In standalone mode, slow heuristics stay **on** at any function count. This contradicts the task brief's "auto-disabled at 4001".
- **Open question 4.** Exact exception text and type, verified.

### Still not determined

- Whether cdifflib's `CSequenceMatcher` is bit-identical. Its source is unavailable on this PC. Mitigation: keep it uninstalled on oracle machines.
- Whether real IDA exports ever contain:
  - invalid UTF-8
  - an empty or space-led `assembly` line (the patch-diff crash trigger)
  - `nodes = 0` functions that could meet as diffing candidates
- Row choice for duplicate names in `get_function_row` (plan-dependent, no `ORDER BY`).
- Reproducibility of `factor` factorisation (random Miller-Rabin and Pollard-Brent). This matters only for relaxed mode.
