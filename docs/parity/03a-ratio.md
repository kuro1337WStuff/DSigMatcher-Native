# 03a: Similarity ratio computation (Diaphora 3.4.2 porting spec)

**Summary.** Every *computed* similarity ratio comes from `CBinDiff.check_ratio` (`diaphora.py:1645-1775`). Not every *printed* ratio is a `check_ratio` value. Some items store a literal `1`: `find_equal_matches` (`diaphora.py:1439`), `add_matches_from_query`, the NO_FPS path (`diaphora.py:2074`), and the best branch of `find_same_name` (`diaphora.py:2200`). Two callers also add +0.01 after the call (§11). `check_ratio` is a memoised function of one `(main address, diff address)` pair. Here is what it does under the default standalone config (relaxed ratio off, ML off):

1. It returns `1.0` at once when the two `bytes_hash` values are equal. `NULL == NULL` counts as equal.
2. Otherwise it computes up to five sub-scores: v1 (cleaned pseudocode), v2 (cleaned assembly), v3 (always 0 by default), v4 (the MD-Index bonus) and v5 (cleaned microcode).
   - v1, v2 and v5 are `difflib.SequenceMatcher.quick_ratio()` over `"\n"`-split lines, a pure multiset-intersection formula, rounded to **7 decimals, half-even, on the exact binary value**.
   - `v5 == 1.0` short-circuits to `1.0`.
3. It takes the max. A `1.0` is refused when the MD-Indices differ.
4. If the result is below `1.0`, it adds `deep_ratio`, a small bonus built from `source_file`, `pseudocode_primes`, in/out-degree, `switches`, complexity and shared `constants` (0.006 or 0.008 per distinct shared constant).
5. It clamps to `0.99` when the sum reaches `1.0`.

Two callers feed it: SQL heuristics through `check_match`, and row-based heuristics through `compare_function_rows`. The two differ only in how `md_index` text becomes a double. `MATCHES_BONUS_RATIO` (+0.01) is **not** added inside `check_ratio`. Two callers add it afterwards: `find_same_name` and `find_one_match_diffing`.

I checked every claim below against the real `CBinDiff.check_ratio` and `compare_function_rows`, using a differential harness: 0 mismatches over 99,600 pair evaluations, bit-exact on the IEEE-754 double. Each quirk was also confirmed by a mutation that breaks it (see §13).

Environment of record:
- Diaphora `<diaphora-ref>`, commit `621ec26` (`git describe`: `3.4.2-4-g621ec26`).
- Python 3.13.12 (`<conda>/python.exe`), using stdlib `difflib` (cdifflib is **not** installed; `import cdifflib` raises `ModuleNotFoundError`).
- SQLite 3.51.1, from `sqlite3.sqlite_version`. This is the same version as `miniconda3/Library/include/sqlite3.h`, which the C++ build links.

---

## 0. Default configuration that governs the ratio (verified)

| Setting | Value | Source | Effect on ratio |
|---|---|---|---|
| `DIFFING_ENABLE_RELAXED_RATIO` | `False` | `diaphora_config.py:47` | `self.relaxed_ratio` is False, so `fratio = quick_ratio` with 7 decimals. v3 and `ast_ratio` are dead. |
| `DECIMAL_VALUES` | `"7f"` | `diaphora_config.py:120` | Rounding format `"{0:.7f}"`. |
| `MATCHES_BONUS_RATIO` | `0.01` | `diaphora_config.py:116` | Added by callers only (§10). |
| `MINIMUM_RARE_MD_INDEX` | `10.0` | `diaphora_config.py:133` | Only used when relaxed. |
| `INCREASE_RATIO_PER_CONSTANT_MATCH_SAME_CPU` | `0.006` | `diaphora_config.py:147` | Per distinct shared constant when the processors match. |
| `INCREASE_RATIO_PER_CONSTANT_MATCH` | `0.008` | `diaphora_config.py:148` | Per distinct shared constant otherwise. |
| `ML_USE_TRAINED_MODEL` | `False` | `diaphora_config.py:205` | `self.classifier` stays `None`, so `get_model_ratio` is unreachable. |
| `ML_TRAINED_MODEL_MATCH_SCORE` | `0.15` | `diaphora_config.py:209` | Only with ML. |
| `DEFAULT_PARTIAL_RATIO` / `DEFAULT_TRUSTED_PARTIAL_RATIO` | `0.5` / `0.3` | `diaphora_config.py:137,141` | Consumers (§11). |

The flags are read through `get_value_for` (`diaphora.py:560-569`):

```python
  def get_value_for(self, value_name, default):
    value = os.getenv(f"DIAPHORA_{value_name.upper()}")
    if value is not None:
      if isinstance(value, type(default)):
        value = type(default)(value)
      return value
    return default
```

Quirk: for a bool default, `isinstance(<str>, bool)` is False. So when `DIAPHORA_RELAXED_RATIO` (or `DIAPHORA_USE_TRAINED_MODEL`) is set to any **non-empty** string, even `"0"` or `"False"`, the flag returns that truthy string. An empty string gives a falsy value. With no environment variable set, the defaults above apply. `diaphora.py:403-405`: `self.relaxed_ratio = self.get_value_for("relaxed_ratio", config.DIFFING_ENABLE_RELAXED_RATIO)`.

`self.is_same_processor` starts as `False` (`diaphora.py:436`). It is set at `diaphora.py:3617`, `self.is_same_processor = self.same_processor_both_databases()`. That happens **after** `check_callgraph()`, `find_equal_matches()` and `equal_db()`. I checked all three (`diaphora.py:661-687, 1288-1338, 1404-1442`), and none of them calls `check_ratio`. So every `check_ratio` call sees the final value. `same_processor_both_databases` (`diaphora.py:2950-2967`) returns True iff `select 1 from main.program mp, diff.program dp where mp.processor = dp.processor` returns a row. That is SQL `=`, so a `NULL` processor never matches.

Correction to the orchestrator brief: `MIN_FUNCTIONS_TO_DISABLE_SLOW` (`diaphora_config.py:71`) is referenced **only** in `diaphora_ida.py:3799` (`"slow", total_functions <= config.MIN_FUNCTIONS_TO_DISABLE_SLOW`), the IDA GUI options. Standalone `diaphora.py` never reads it. `self.slow_heuristics` is plainly `config.DIFFING_ENABLE_SLOW_HEURISTICS` (True, `diaphora.py:409-411`), whatever the function count. In standalone mode, slow heuristics are **not** auto-disabled at 4001 functions.

Standalone mode also has `IS_IDA = False` (`diaphora.py:82-87`), which forces `self.cpu_count = 1` (`diaphora.py:489-491`), and sets `bd.ignore_all_names = False` (`diaphora.py:3759-3760`).

Which `check_ratio` callers run by default (verified in `diff()`, `diaphora.py:3616-3675`):
- `DIFFING_ENABLE_EXPERIMENTAL=True` gates **only** `apply_dirty_heuristics()` (`diaphora.py:3618-3621`).
- `find_experimental_matches()` is nested inside `if self.unreliable:` (`diaphora.py:3638-3651`), so it does not run by default. It would do nothing anyway: none of the 50 `HEURISTICS` entries has category `"Experimental"`. A count from importing `diaphora_heuristics` gives Best 12, Partial 30, Unreliable 8.
- The Unreliable category and `find_brute_force` (reached through `find_unreliable_matches`, `diaphora.py:2313-2321`) need `self.unreliable`, which is False by default.
- By default, SQL-heuristic ratios therefore come only from Best/Partial heuristics that pass the flag filters in `run_heuristics_for_category` (`diaphora.py:1497-1508`).

---

## 1. `check_bufs` (`diaphora.py:150-155`)

```python
def check_bufs(buf1, buf2):
  if buf1 is None or buf2 is None:
    return False
  if buf1 == "" or buf2 == "":
    return False
  return True
```

**Port.** `bool check_bufs(optional<string_view> a, b) { return a && b && !a->empty() && !b->empty(); }`

**Inputs.** Two nullable TEXT values.

**Runs by default?** Yes. `quick_ratio` calls it for every v1, v2 and v5 computation.

---

## 2. `quick_ratio` (`diaphora.py:158-165`) and the stdlib algorithm it calls

```python
def quick_ratio(buf1, buf2):
  # docstring (diaphora.py:159-161) omitted
  if not check_bufs(buf1, buf2):
    return 0
  seq = SequenceMatcher(None, buf1.split("\n"), buf2.split("\n"))
  return seq.quick_ratio()
```

`SequenceMatcher` is `difflib.SequenceMatcher`, because cdifflib is absent (`diaphora.py:41-49`). Here is the stdlib code that runs, from `<conda>\Lib\difflib.py` (Python 3.13.12):

```python
# difflib.py:39-42
def _calculate_ratio(matches, length):
    if length:
        return 2.0 * matches / length
    return 1.0

# difflib.py:622-649 (docstring and comments trimmed)
    def quick_ratio(self):
        if self.fullbcount is None:
            self.fullbcount = fullbcount = {}
            for elt in self.b:
                fullbcount[elt] = fullbcount.get(elt, 0) + 1
        fullbcount = self.fullbcount
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
```

`quick_ratio` never reads `b2j` or the junk/autojunk data, so the `isjunk=None`/`autojunk=True` defaults have **no effect** on it. It is order-independent: `matches = Σ_x min(count_a(x), count_b(x))`, the size of the multiset intersection.

**Porting spec (exact).**

```
double quick_ratio(optional<string_view> a, optional<string_view> b):
    if (!check_bufs(a, b)) return 0.0            // Python returns int 0; numerically identical
    A = split_keep_empty(*a, '\n')               // Python str.split("\n")
    B = split_keep_empty(*b, '\n')
    m = Σ over distinct line x of min(countA[x], countB[x])   // exact line equality
    L = |A| + |B|                                // always >= 2 here, so the "return 1.0" branch is unreachable
    return (2.0 * (double)m) / (double)L         // left to right: multiply, then divide
```

- `str.split("\n")` splits **only** on `'\n'`. It keeps empty fields, so `|A| = count('\n') + 1`. `"a\nb\n"` gives `["a","b",""]`, and `"\r"` stays in the line. Do **not** use a splitlines-style splitter. Verified: `quick_ratio('a\nb\n','a\nb') == 0.8`, where splitlines semantics would give 1.0. `quick_ratio('\n','\n\n') == 0.8`.
- Line equality is Python `str` equality on decoded text. For valid UTF-8, byte equality is equivalent. Read with `sqlite3_column_text` plus `sqlite3_column_bytes`, never `strlen`, because embedded NULs are legal in Python. Diaphora opens the DB with `db.text_factory = str` (`diaphora.py:346`), so invalid UTF-8 would raise at fetch time in Python. NOT DETERMINED FROM SOURCE what a real export contains. Assume valid UTF-8.
- `2.0 * m` is exact for `m < 2^53`. The division is one correctly rounded IEEE op, so a C++ `double` gives the same bits on SSE2/NEON.
- Implementation hint for speed without losing exactness: intern every distinct line of every text across both DBs to a `uint32` id at load time. Store each text as a sorted `(id, count)` vector plus `L`. The intersection is then a merge. Do not use hash-only comparison without a collision check.

**Runs by default?** Yes. `check_ratio` sets `fratio = quick_ratio` (`diaphora.py:1675`) whenever `relaxed_ratio` is falsy.

---

## 3. `real_quick_ratio` (`diaphora.py:169-176`). Relaxed mode only.

```python
def real_quick_ratio(buf1, buf2):
  if not check_bufs(buf1, buf2):
    return 0
  seq = SequenceMatcher(None, buf1.split("\n"), buf2.split("\n"))
  return seq.real_quick_ratio()
```

stdlib `difflib.py:651-661`:

```python
    def real_quick_ratio(self):
        la, lb = len(self.a), len(self.b)
        return _calculate_ratio(min(la, lb), la + lb)
```

**Port.** `check_bufs ? (2.0 * min(la, lb)) / (la + lb) : 0.0`, where `la` and `lb` are the `'\n'`-split field counts. The result depends only on line counts. For example, `real_quick_ratio('x','y\nz') == 0.6666666666666666`.

**Runs by default?** No. It is assigned only under `if self.relaxed_ratio:` (`diaphora.py:1677-1679`).

---

## 4. `ast_ratio` (`diaphora.py:180-190`), `CBinDiff.ast_ratio` (`diaphora.py:1637-1643`) and `jkutils.factor.difference_ratio`. Relaxed mode only.

```python
def ast_ratio(ast1, ast2):
  if ast1 is None or ast2 is None:
    return 0
  if ast1 == ast2:
    return 1.0
  return difference_ratio(decimal.Decimal(ast1), decimal.Decimal(ast2))
```

```python
  def ast_ratio(self, ast1, ast2):
    if not self.relaxed_ratio:
      return 0
    return ast_ratio(ast1, ast2)
```

`jkutils/factor.py:203-249` (abridged, logic verbatim):

```python
def _difference(num1, num2):
  nums = [num1, num2]
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

def difference_ratio(num1, num2):
  diffs, s = _difference(num1, num2)
  total = max(sum(s[0].values()), sum(s[1].values()))
  return 1 - (sum(diffs.values()) *1. / total)
```

**Port (relaxed only).** Let `ast1` and `ast2` be the `pseudocode_primes` TEXT, a decimal integer string.
- NULL on either side gives 0.
- Equal strings give `1.0`.
- Otherwise factor both integers into `{p: e}`, with `D = Σ_p |e1(p) - e2(p)|` and `T = max(Ω(n1), Ω(n2))`, where Ω counts prime factors with multiplicity. Return `1.0 - (double(D) * 1.0) / double(T)`, evaluated as `1 - ((D*1.)/T)`.

Quirks:
- `T == 0` (both values in {0, 1} but different strings, for example `"0"` and `"1"`) raises `ZeroDivisionError`.
- The result can be negative. `2` vs `3` gives `1 - 2/1 = -1.0`.
- `isprime` uses random Miller-Rabin (`jkutils/factor.py:57-58`), so Python's factorization is probabilistic for cofactors ≥ 100000. It is correct with probability ≥ 1-4^-7 per composite.
- In `check_ratio` it is only reached for strings shorter than 16 characters.

**Runs by default?** No. `check_ratio` calls `self.ast_ratio` only inside `if (self.relaxed_ratio and ...)` (`diaphora.py:1687-1694`). The wrapper itself returns 0 when `relaxed_ratio` is falsy.

---

## 5. The 7-decimal rounding step (`decimal_values`)

`diaphora.py:1676`: `decimal_values = "{0:.%s}" % config.DECIMAL_VALUES`, which gives `"{0:.7f}"`. It is applied as `v = float(decimal_values.format(v))` to v1, v2, (v3) and v5 (`diaphora.py:1710, 1722, 1734, 1750`). In relaxed mode it is `"{0:.1f}"` (`diaphora.py:1679`).

Python's `format(float, ".7f")` is **correctly rounded from the exact binary value, with ties to even**. `float(str)` is correctly rounded. Ties really occur: any quick-ratio whose reduced fraction has denominator 256, for example total line count 512 with an odd match count, lands exactly on a 7-decimal half. Verified:

| m, L | exact 2m/L | Python result | half-up (WRONG) |
|---|---|---|---|
| 1, 512 | 0.00390625 | 0.0039062 | 0.0039063 |
| 253, 512 | 0.98828125 | 0.9882812 | 0.9882813 |
| 255, 512 | 0.99609375 | 0.9960938 | 0.9960938 |
| 5, 512 | 0.01953125 | 0.0195312 | 0.0195313 |
| 3, 1536 | 0.00390625 | 0.0039062 | 0.0039063 |

The mutation test that swaps in half-up changed 81 of 6,400 pair ratios.

**Porting spec (exact, portable, no `from_chars` dependency).** For `0 <= v <= 1` (always true for these inputs):

```
double round_dec(double v, int digits /*7, or 1 in relaxed*/):
    if (v == 0.0) return 0.0;
    uint64 bits = bit_cast<uint64>(v);
    int    e    = (bits >> 52) & 0x7FF;
    uint64 mant = bits & ((1ull << 52) - 1);
    int    exp2;
    if (e == 0) { exp2 = -1074; } else { mant |= 1ull << 52; exp2 = e - 1075; }   // v = mant * 2^exp2
    u128   num  = (u128)mant * POW10[digits];       // < 2^53 * 2^24; fits in 128 bits
    int    s    = -exp2;                            // > 0 for v <= 1 (v == 1.0 gives s = 52)
    if (s >= 128) return 0.0;                       // v < 2^-75, far below 0.5e-7, so the result is 0. The guard is REQUIRED:
                                                    // without it, `q << s` and `1 << (s-1)` below shift a u128 by >= 128 (UB).
                                                    // Unreachable from quick_ratio (v >= 2/L), but keep it.
    u128   q    = num >> s;
    u128   rem  = num - (q << s);
    u128   half = (u128)1 << (s - 1);
    if (rem > half || (rem == half && (q & 1))) ++q;   // ROUND_HALF_EVEN on the exact value
    return (double)(uint64)q / (double)POW10[digits];  // one IEEE division gives the correctly rounded k/10^d,
                                                       // which equals float("0.kkkkkkk")
```

MSVC has no `unsigned __int128`, so use `_umul128`/`__shiftright128`, or a two-limb struct. `std::to_chars(fixed, 7)` followed by `std::from_chars` is also exact on MSVC STL and libstdc++. Apple libc++ support for floating `from_chars` is NOT DETERMINED here, so prefer the integer method above. Do **not** use `round(v*1e7)/1e7` or `printf` with a legacy (pre-Win10-2004) CRT.

Test vectors: the table above, plus `round_dec(2.0/3.0,7) == 0.6666667`, `round_dec(0.0,7) == 0.0` and `round_dec(1.0,7) == 1.0`.

**Runs by default?** Yes, with 7 digits.

---

## 6. `check_ratio` (`diaphora.py:1645-1775`), the core

### 6.1 Source (verbatim, except that the docstring at 1646-1649 and the comment at 1724-1725 are omitted; `# NNNN` annotations added)

```python
  def check_ratio(self, main_d, diff_d):
    ea1 = main_d["ea"]                                                # 1651
    ea2 = diff_d["ea"]
    key = f"{ea1}-{ea2}"
    if key in self.ratios_cache:                                      # 1654
      return self.ratios_cache[key]

    ast1 = main_d["pseudocode_primes"]                                # 1657
    ast2 = diff_d["pseudocode_primes"]
    pseudo1 = main_d["pseudo"]
    pseudo2 = diff_d["pseudo"]
    md1 = main_d["md_index"]
    md2 = diff_d["md_index"]
    clean_assembly1 = main_d["clean_assembly"]
    clean_assembly2 = diff_d["clean_assembly"]
    clean_pseudo1 = main_d["clean_pseudo"]
    clean_pseudo2 = diff_d["clean_pseudo"]
    clean_micro1 = main_d["clean_micro"]
    clean_micro2 = diff_d["clean_micro"]
    bytes_hash1 = main_d["bytes_hash"]
    bytes_hash2 = diff_d["bytes_hash"]

    md1 = float(md1)                                                  # 1672
    md2 = float(md2)

    fratio = quick_ratio                                              # 1675
    decimal_values = "{0:.%s}" % config.DECIMAL_VALUES
    if self.relaxed_ratio:
      fratio = real_quick_ratio
      decimal_values = "{0:.1f}"

    if bytes_hash1 == bytes_hash2:                                    # 1681
      self.ratios_cache[key] = 1.0
      return 1.0

    v3 = 0                                                            # 1685
    ast_done = False
    if (
      self.relaxed_ratio
      and ast1 is not None
      and ast2 is not None
      and max(len(ast1), len(ast2)) < 16
    ):
      ast_done = True
      v3 = self.ast_ratio(ast1, ast2)
      if v3 == 1.0:
        self.ratios_cache[key] = 1.0
        return v3

    v1 = 0                                                            # 1699
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

    v2 = fratio(clean_assembly1, clean_assembly2)                     # 1721
    v2 = float(decimal_values.format(v2))
    if v2 == 1:
      if fratio == real_quick_ratio:
        v2 = quick_ratio(clean_assembly1, clean_assembly2)
        if v2 == 1.0:
          self.ratios_cache[key] = 1.0
          return 1.0

    if self.relaxed_ratio and not ast_done:                           # 1732
      v3 = fratio(ast1, ast2)
      v3 = float(decimal_values.format(v3))
      if v3 == 1:
        self.ratios_cache[key] = 1.0
        return 1.0

    v4 = 0.0                                                          # 1739
    if md1 == md2 and md1 > 0.0:
      # A MD-Index >= 10.0 is somehow rare
      if self.relaxed_ratio and md1 > config.MINIMUM_RARE_MD_INDEX:
        self.ratios_cache[key] = 1.0
        return 1.0
      v4 = min((v1 + v2 + v3 + 3.0) / 5, 1.0)

    v5 = 0.0                                                          # 1747
    if clean_micro1 is not None and clean_micro2 is not None:
      v5 = fratio(clean_micro1, clean_micro2)
      v5 = float(decimal_values.format(v5))
      if v5 == 1:
        self.ratios_cache[key] = 1.0
        return 1.0

    values_set = set([v1, v2, v3, v4, v5])                            # 1755

    r = max(values_set)
    if r == 1.0 and md1 != md2:
      # We cannot assign a 1.0 ratio if both MD indices are different, that's an
      # error
      r = 0
      for v in values_set:
        if v != 1.0 and v > r:
          r = v

    if r < 1.0:                                                       # 1766
      score = self.deep_ratio(main_d, diff_d, r)
      if r + score < 1.0:
        r += score
      else:
        r = 0.99

    debug_refresh(f"self.ratios_cache[{main_d['name']}-{diff_d['name']}] = {r}")
    self.ratios_cache[key] = r                                        # 1774
    return r
```

### 6.2 Inputs (the `main_d`/`diff_d` dict fields read)

| dict key | DB column (table `functions`, main or diff) | Declared type (`db_support/schema.py:69-118`) | Decoding used |
|---|---|---|---|
| `ea` | `address` | `text unique` | Python `str` (TEXT affinity turns the exporter's int into canonical decimal text). Used for the cache key and, in `deep_ratio`, `int(...)`. |
| `pseudocode_primes` | `pseudocode_primes` | text | `str` or `None`. Only used when relaxed. |
| `pseudo` | `pseudocode` | text | `str` or `None`. Only the NULL/empty test. |
| `md_index` | `md_index` | text | `float(...)`. **Path-dependent source, see §6.4.** |
| `clean_assembly` | `clean_assembly` | text | `str` or `None`, split on `\n`. |
| `clean_pseudo` | `clean_pseudo` | text | `str` or `None`, split on `\n`. |
| `clean_micro` | **`clean_microcode`** (the key name differs) | text | `str` or `None`, split on `\n`. |
| `bytes_hash` | `bytes_hash` | text | `str` or `None`, compared with `==`. |
| `name` | `name` | varchar | Debug log only. |

Exporter encodings, for reference. `diaphora_ida.py`:
- `md_index`: either int `0` or `str(Decimal)` (`diaphora_ida.py:2514-2538`, `md_index = 0 ... md_index = str(md_index)`), stored in a TEXT column as `"0"` or a 28-significant-digit decimal.
- `pseudocode_primes = str(self.pseudo_hash[f])` or `None` (`diaphora_ida.py:2546-2559`).
- `clean_assembly = ""` on error (`diaphora_ida.py:2959-2962`).
- `clean_microcode` is `None` unless microcode was exported (`diaphora_ida.py:2657-2688`).
- `bytes_hash = md5(...).hexdigest()` (`diaphora_ida.py:2977`).

Addresses pass through `get_valid_prop` (`diaphora.py:719-728`): ints above `0xFFFFFFFF` become `str(prop)`, and a TEXT column holds both forms as decimal text.

### 6.3 Porting spec, default mode (relaxed = false)

```
double check_ratio(const Fn& M, const Fn& D, MdSource path):
    key = (M.address_text, D.address_text)          // any key that is 1:1 with (main row, diff row) works
    if (auto c = cache.find(key)) return *c;

    md1 = md_double(M, path); md2 = md_double(D, path);          // §6.4

    // 1681: Python ==, so None == None is TRUE and None == "x" is FALSE
    if (py_eq(M.bytes_hash, D.bytes_hash)) { cache[key] = 1.0; return 1.0; }

    double v1 = 0.0;
    if (nonempty(M.pseudocode) && nonempty(D.pseudocode)) {        // not None and != ""
        if (is_empty_str(M.clean_pseudo) || is_empty_str(D.clean_pseudo)) {
            /* log "Error cleaning pseudo-code!"; v1 stays 0 */    // NULL is NOT == "", so NULL falls to else
        } else {
            v1 = round_dec(quick_ratio(M.clean_pseudo, D.clean_pseudo), 7);   // NULL gives 0.0
            // v1 == 1.0 has NO effect in default mode (the recheck is relaxed-only)
        }
    }
    double v2 = round_dec(quick_ratio(M.clean_assembly, D.clean_assembly), 7);
    // v2 == 1.0 has NO effect in default mode
    double v3 = 0.0;                                   // Python int 0; never changes when not relaxed
    double v4 = 0.0;
    if (md1 == md2 && md1 > 0.0) {
        double x = (((v1 + v2) + v3) + 3.0) / 5.0;     // exact Python evaluation order
        v4 = (1.0 < x) ? 1.0 : x;                      // min(x, 1.0); x <= 1.0 always, but keep it
    }
    double v5 = 0.0;
    if (M.clean_microcode.has_value() && D.clean_microcode.has_value()) {    // "" passes this test; quick_ratio then gives 0
        v5 = round_dec(quick_ratio(M.clean_microcode, D.clean_microcode), 7);
        if (v5 == 1.0) { cache[key] = 1.0; return 1.0; }  // short-circuits EVEN IF md1 != md2
    }
    double r = max({v1, v2, v3, v4, v5});
    if (r == 1.0 && md1 != md2) {
        r = 0.0;
        for (double v : {v1, v2, v3, v4, v5}) if (v != 1.0 && v > r) r = v;
    }
    if (r < 1.0) {
        double score = deep_ratio(M, D);               // §7
        r = (r + score < 1.0) ? (r + score) : 0.99;    // the clamp can LOWER r (0.995 + 0.006 gives 0.99)
    }
    cache[key] = r;
    return r;
```

Behavioural consequences to test for explicitly:

- **Equal `bytes_hash` gives 1.0 unconditionally**, before md and text checks. Both NULL also gives 1.0. The mutation that ignores NULL==NULL changed 118 of 6,400 ratios.
- **v5 == 1.0 gives 1.0 unconditionally**, even when the MD-Indices differ. This happens with identical cleaned microcode, or with any non-1 quick_ratio that rounds to `"1.0000000"`. The smallest total line count `L = |A|+|B|` where that can happen is **L = 20,000,001**, with m = 10,000,000 giving 0.9999999500000025 and so 1.0. For even L the smallest is 40,000,002. L = 40,000,000 with m = 19,999,999 gives exactly the double nearest 0.99999995, which is *below* the half-way point, so 0.9999999. All three were verified with Python `"{0:.7f}"`.
- **Order of failure.** `float(md1)`/`float(md2)` (1672-1673) runs **before** the bytes_hash shortcut (1681) and after the cache lookup (1654). A NULL `md_index` therefore raises even for a pair with equal `bytes_hash`, while a cached pair never raises. The C++ must keep this order if it mirrors the error path (§12).
- **v1 or v2 == 1.0 does not short-circuit.** It gives 1.0 only when `md1 == md2`, and in that case `deep_ratio` is **not** called. When the MDs differ, the 1.0 values are dropped and r becomes the largest remaining value (v4 is 0.0 here because the MDs differ), plus `deep_ratio`.
- **An equal, positive MD-Index gives a floor of 0.6.** `v4 = (v1+v2+3)/5`, which is at least 0.6.
- `md1 > 0.0`: an md of `"0"` (functions with no topology) never earns v4.
- `set([...])` deduplication and Python int/float mixing (`v1`/`v3` may be the int `0`) do not change the numeric max. r can be the Python int `0` (seen 10-89 times per 6,400 pairs in the harness), but every consumer treats it numerically, and `"%.7f" % 0 == "0.0000000"`. No observable difference.
- The `values_set` iteration order in the `md1 != md2` loop is hash order, but only the numeric max survives, so it does not matter.

### 6.4 `md_index` to double: two decoding paths

| Caller path | Where `main_d["md_index"]` comes from | Conversion |
|---|---|---|
| **SQL-heuristic path**: `check_match` (`diaphora.py:1805,1828`) with rows from `get_query_fields` | `cast(f.md_index as real) md1, cast(df.md_index as real) md2` (`diaphora_heuristics.py:57`) | **SQLite** text-to-REAL (`sqlite3AtoF`), then Python `float(<float>)` (identity). NULL gives `None`, and `float(None)` raises `TypeError`. |
| **Row path**: `compare_function_rows` (`diaphora.py:2498,2521`) with `select *` rows | Raw TEXT `md_index` | **Python `float(str)`**, correctly rounded, like `strtod`/`from_chars`. NULL raises `TypeError`. |

Measured on this PC, SQLite 3.51.1 `CAST(x AS REAL)` differs from Python `float(x)` by 1 ulp for **158 of 200,000** random 28-digit md_index strings. Example: `"0.4008152925841381442166209413"` gives Python `0.40081529258413817` and SQLite `0.4008152925841381`.

Every `check_match` caller builds its rows with `get_query_fields`, so all of them use the SQLite path. That covers all 50 `HEURISTICS` entries (checked by importing `diaphora_heuristics` and testing each `sql` for `cast(f.md_index as real) md1`) and the internal queries at `diaphora.py:2095, 2160, 2263, 2285, 2572, 2677, 3377, 3429`.

The value is used only in `md1 == md2` (1740), its negation `md1 != md2` (the guard at 1758), `md1 > 0.0` (1740) and, when relaxed, `md1 > 10.0` (1742). `find_same_name` also reads `row["md1"]`/`row["md2"]` (SQLite path) for its relaxed-only test (2194-2197). For exporter-produced strings, a path difference therefore changes a result only when two *different* strings map to the same double under one converter but not the other. That is practically unreachable, but it is not formally impossible.

**Non-numeric or non-canonical text diverges between the two paths.** The exporter never writes such text, but foreign databases might. Probed with Python 3.13.12 / SQLite 3.51.1:

| md_index text | SQLite `CAST(.. AS REAL)` | Python `float()` |
|---|---|---|
| `''` | 0.0 | `ValueError` |
| `'abc'` | 0.0 | `ValueError` |
| `'1.5abc'` | 1.5 (longest numeric prefix) | `ValueError` |
| `'0x10'` | 0.0 | `ValueError` |
| `'nan'` / `'inf'` | 0.0 / 0.0 | nan / inf |
| `' 2.5 '`, `'+3'`, `'1e5'`, `'-0'` | 2.5, 3.0, 100000.0, -0.0 | the same |

Python `float()` also accepts `_` digit separators and `"infinity"`. `std::from_chars` accepts none of whitespace, a leading `+`, or `_`. `md_py` must therefore be computed with Python-`float` semantics, or the database rejected, for any text that is not a plain decimal/exponent literal. `str(Decimal)` and `"0"` are always plain literals.

**Compare as doubles, never as strings.** In a sample of 3,000 random edge-order permutations, `str(Decimal sum)` differed in 712 cases while the doubles were identical in all of them. The mutation "compare md strings" changed 361-545 of 6,400 ratios.

**Port.** At load time store both `md_sqlite` (read with `sqlite3_column_double`) and `md_py` (`std::from_chars` of the TEXT) per function. `sqlite3_column_double` and `CAST(... AS REAL)` share one converter: in the SQLite 3.53.0 amalgamation, `sqlite3VdbeMemRealify` does `pMem->u.r = sqlite3VdbeRealValue(pMem)`, and `sqlite3_value_double` returns `sqlite3VdbeRealValue((Mem*)pVal)`. Both reach `sqlite3AtoF`. I read this in the 3.53.0 amalgamation (`<home>/<other-project>/node_modules/better-sqlite3/deps/sqlite3/sqlite3.c`: `sqlite3VdbeMemCast` case `SQLITE_AFF_REAL` gives `sqlite3VdbeMemRealify` at 86361-86385, `sqlite3VdbeMemRealify` at 86284-86292, `sqlite3VdbeRealValue` at 86205-86219, `sqlite3_column_double` gives `sqlite3_value_double` at 94904 and 93704-93706). **Verified empirically on 3.51.1 as well.** Through ctypes against `miniconda3/Library/bin/sqlite3.dll` (3.51.1, the same library Python's `_sqlite3` reports), I read 200,001 md strings stored in a TEXT column. `sqlite3_column_double(md_index)` and `CAST(md_index AS REAL)` were bit-identical for all of them; the 3.53.0 amalgamation, built here with MSVC, gave the same result. Use `md_sqlite` for SQL-heuristic callers and `md_py` for `compare_function_rows` callers. Because of the cache (§8), the first call for a pair wins.

**SQLite version dependence (measured).** I ran `CAST(? AS REAL)` over the same 200,000 synthetic 28-digit `str(Decimal)` strings with every 64-bit SQLite DLL on this PC (script `scratchpad/v03a/onedll.py`):

| SQLite build (all Windows DLLs) | result vs 3.51.1 | differs from Python `float()` |
|---|---|---|
| 3.46.0, 3.46.1, 3.51.0, 3.51.1 (conda, and System32 `winsqlite3.dll`), 3.51.2, 3.53.0 (amalgamation, MSVC `/O2 /fp:precise`) | bit-identical | 120 / 200,000 |
| 3.37.2, 3.42.0 | **different** | **52,633 / 200,000** |

So `sqlite3AtoF` rounding changed between 3.42 and 3.46, and stayed stable from 3.46 to 3.53 on Windows builds. The 3.53.0 source has no long-double path (`sqlite3AtoF` ends in `sqlite3Fp10Convert2`, sqlite3.c:37201ff; a grep for `bUseLongDouble` finds nothing). **NOT DETERMINED** for Linux GCC x86-64 builds of 3.43-3.52, where the source of those versions is not on this PC: whether an 80-bit long-double path changes the result is unknown. The md example above (`0.4008152925841381442166209413`) gives `0.4008152925841381` in 3.51.1 and 3.53.0, and `0.40081529258413817` in Python. On this generator, 120/200,000 conversions differ from Python. The earlier 158/200,000 figure came from a different random generator.

### 6.5 Porting spec, relaxed mode (non-default, for completeness)

This mode is reachable only with the `DIAPHORA_RELAXED_RATIO` environment variable set to a non-empty string.

```
fr  = real_quick_ratio;  R(x) = round_dec(x, 1)
if bytes_hash equal: return 1.0
v3 = 0; ast_done = false
if ast1 != NULL && ast2 != NULL && max(len(ast1), len(ast2)) < 16:     // len = number of characters of the TEXT
    ast_done = true; v3 = ast_ratio(ast1, ast2)      // §4; NOT rounded; may be negative or throw
    if v3 == 1.0: return 1.0
v1 = 0
if pseudo non-empty both:
    if clean_pseudo1 == "" || clean_pseudo2 == "": log
    else: v1 = R(fr(cp1,cp2)); if v1 == 1.0 { v1 = quick_ratio(cp1,cp2) /*UNROUNDED*/; if v1 == 1.0 return 1.0 }
v2 = R(fr(ca1,ca2)); if v2 == 1 { v2 = quick_ratio(ca1,ca2) /*UNROUNDED*/; if v2 == 1.0 return 1.0 }
if !ast_done: v3 = R(fr(ast1, ast2)); if v3 == 1 return 1.0
    // pseudocode_primes has no '\n', so each side is ONE line and real_quick_ratio = 1.0 whenever both are non-empty:
    // ANY pair with both primes non-empty and one of them >= 16 chars returns 1.0 here (verified).
v4 = 0; if md1 == md2 && md1 > 0: { if md1 > 10.0 return 1.0; v4 = min((v1+v2+v3+3.0)/5, 1.0) }
v5 = 0; if micro both non-NULL: v5 = R(fr(cm1,cm2)); if v5 == 1 return 1.0
    // no quick_ratio recheck for v5: line counts within about 5% (real_quick >= 0.95 rounds to "1.0") give 1.0
then the same max / md guard / deep_ratio / 0.99 clamp as default
```

Verified against Diaphora with `bd.relaxed_ratio = True`. The functions rows at the probed address are **deep_ratio-neutral**: indegree, outdegree and cc are 0, switches and constants are `"[]"`, and source_file and primes are NULL, so `deep_ratio` returns 0. Script: `scratchpad/v03a/relaxed2.py`.
- primes `"1234567890123456789"` vs `"9876543210987654321"` give `1.0`;
- primes `"30"` vs `"210"`, with 3-line vs 4-line assembly, give `0.9`;
- md `"12.5"` on both sides gives `1.0`;
- md `"3.5"` on both sides with assembly `a\nb\nc` vs `a\nb\nd` gives `0.7333333333333333`, where v2 is the unrounded quick_ratio `2/3`.

These are the ratios **before** any deep_ratio bonus. The older `scratchpad/relaxed.py` points `ea` at arbitrary harness rows, so it prints `0.901` and `0.7343333333333333`: deep_ratio adds +0.001 there.

**Runs by default?** `check_ratio`: **yes**. Its default-reachable callers are:
- (via `check_match`) rows of the Best/Partial SQL heuristics that pass the flag filters (§0);
- `find_same_name` (whenever `ignore_all_names` is False, which is always in standalone mode, and also on the `skip_others` path, `diaphora.py:3623-3624`);
- `search_small_differences` (only when `slow_heuristics`, `diaphora.py:2218-2221`);
- `search_just_stripped_binaries` (only when `experimental` is on and at least 99% of addresses are shared, `diaphora.py:2562-2580`);
- `search_remaining_functions` (only in patch-diff mode, `diaphora.py:2708-2716`);
- `find_related_constants` (only when `slow_heuristics`, via `find_related_matches`, `diaphora.py:3662-3664`);
- `find_related_compilation_unit`;
- (via `compare_function_rows`) `find_one_match_diffing` and `find_functions_between`.

`find_brute_force`, through `add_matches_from_cursor_ratio_max`, also reaches it, but only with `unreliable` on, which is not default. The relaxed branches do **not** run by default.

---

## 7. `deep_ratio` (`diaphora.py:2749-2837`)

```python
  def deep_ratio(self, main_d, diff_d, ratio):
    ea1 = int(main_d["ea"])                                           # 2763
    ea2 = int(diff_d["ea"])
    score = 0
    cur = self.db_cursor()
    sql = "select * from {db}.functions where address = ?"            # 2772
    try:
      cur.execute(sql.format(db="main"), (str(ea1),))
      main_row = cur.fetchone()
      cur.execute(sql.format(db="diff"), (str(ea2),))
      diff_row = cur.fetchone()

      source1 = main_row["source_file"]                               # 2780
      source2 = diff_row["source_file"]
      if source1 is not None and source2 is not None:
        if source1 == source2 and source1 != "":
          score += 0.001

      pseudocode_primes1 = main_row["pseudocode_primes"]              # 2786
      pseudocode_primes2 = diff_row["pseudocode_primes"]
      if pseudocode_primes1 is not None and pseudocode_primes2 is not None:
        if pseudocode_primes1 == pseudocode_primes2 and pseudocode_primes1 != "":
          score += 0.001

      in1 = main_row["indegree"]                                      # 2792
      in2 = diff_row["indegree"]
      if in1 == in2 and in1 != 0:
        score += 0.001

      out1 = main_row["outdegree"]                                    # 2797
      out2 = diff_row["outdegree"]
      if out1 == out2 and out1 != 0:
        score += 0.001

      switches1 = main_row["switches"]                                # 2802
      switches2 = diff_row["switches"]
      if switches1 == switches2 and switches1 != "[]":
        score += 0.003

      cc1 = main_row["cyclomatic_complexity"]                         # 2807
      cc2 = diff_row["cyclomatic_complexity"]
      if cc1 == cc2 and cc1 != 0:
        score += 0.001

      if main_row["constants"] != "[]":                               # 2812
        set1 = set(json.loads(main_row["constants"]))
        set2 = set(json.loads(diff_row["constants"]))
        set_result = set1.intersection(set2)
        if len(set_result) > 0:
          if self.is_same_processor:
            tmp = config.INCREASE_RATIO_PER_CONSTANT_MATCH_SAME_CPU
          else:
            tmp = config.INCREASE_RATIO_PER_CONSTANT_MATCH
          score += len(set_result) * tmp

      if self.classifier is not None:                                 # 2823  (not default)
        if self.get_model_ratio(main_d, diff_d) == 1:
          score += config.ML_TRAINED_MODEL_MATCH_SCORE
          ...
          self.ml_chooser.add_item(tmp_item)
    finally:
      cur.close()
    return score
```

### 7.1 Inputs

`deep_ratio` re-reads **full rows** by address. It does not use the `main_d` contents apart from `ea` (and `name`/`nodes` for ML). The lookup is `address = str(int(ea))`. TEXT equals TEXT, and `address` is UNIQUE, so it finds at most one row.

| Column | Declared type | Decoding / comparison (Python semantics) | Bonus |
|---|---|---|---|
| `source_file` | text | Both non-NULL, equal, and `!= ""` | +0.001 |
| `pseudocode_primes` | text | Both non-NULL, equal (raw decimal text), and `!= ""` | +0.001 |
| `indegree` | integer | `in1 == in2 and in1 != 0`. **NULL==NULL is True and NULL != 0 is True, so two NULLs earn the bonus.** | +0.001 |
| `outdegree` | integer | Same rule as `indegree` | +0.001 |
| `switches` | text (JSON produced by `json.dumps`) | **Raw string** equality, and `!= "[]"`. Not parsed. Two NULLs earn the bonus. | +0.003 |
| `cyclomatic_complexity` | integer | Same rule as `indegree` | +0.001 |
| `constants` | text (JSON list) | If the main side is exactly the string `"[]"`, skip. Otherwise `json.loads` both sides into Python **sets** and count the distinct common elements. | + n × (0.006 if `is_same_processor` else 0.008) |

Exporter context:
- `indegree`, `outdegree` and `cyclomatic_complexity` are Python ints. Their slots are `diaphora_ida.py:3145, 3146, 3152`. They are initialised as `'outdegree': 0` and `'indegree': len(list(CodeRefsTo(f, 1)))` (`diaphora_ida.py:3071-3072`), with integer increments at 2851, 2898 and 2917, and `cc = data['edges'] - data['nodes'] + 2` (`diaphora_ida.py:2966`). INTEGER affinity keeps them as integers even if they arrive as text or as integral reals.
- `source_file` is inserted as `None` (`diaphora_ida.py:3184`, the slot after `kgh_hash` in `props_list`) and later filled by `update functions set source_file = ? where id = ?` (`diaphora_ida.py:3356`).
- `switches` is `json.dumps(list, ensure_ascii=False)` of `[[switch_cases, list(case_values)], ...]` (`diaphora.py:936-939`, `diaphora_ida.py:2486-2509`), so an empty list is the text `"[]"`.
- `constants` is a JSON list of IDA immediates (unsigned, 0x1000 to 2^64-1, after `constant_filter`, `diaphora_ida.py:2412-2434`) and decoded string literals (`diaphora_ida.py:2467-2484`).

`constants` set semantics the C++ must reproduce:
- JSON integers are **arbitrary-precision exact**. `18446744073709551615` and `18446744073709551614` are different. Parsing them to `double` changed 283-333 of 6,400 ratios in the mutation test. Use `uint64`/`int64` with a bigint fallback, or a canonical digit string.
- JSON numbers with `.`/`e` are Python floats. `1 == 1.0` in a Python set, and int and float compare by exact value. The exporter never writes floats.
- Strings compare after JSON unescaping. `"é"` and `"\u00e9"` are equal, and a string never equals a number (`set(json.loads('[1, 1.0, "1"]')) == {1, '1'}`).
- Duplicates collapse, so n counts **distinct** shared values.
- The exporter never writes these, but they are verified for foreign DBs:
  - JSON `true`/`false` equal `1`/`0` in a Python set: `set([1]) & set([True]) == {True}`.
  - `null` is `None`.
  - A nested array or object element raises `TypeError: unhashable type` in `set(...)`.
  - A JSON `NaN` literal decodes to the **same** module-level float object on both sides, so `NaN` *does* intersect with `NaN` by identity: `set(json.loads('[NaN]')) & set(json.loads('[NaN]')) == {nan}`.
- If `main.constants` is not the literal `"[]"` (for example `"[ ]"`), it is parsed, which is harmless. If it is NULL or invalid JSON, the call raises (§12). If `diff.constants` is NULL or invalid while main is non-`"[]"`, it also raises.

### 7.2 Porting spec (exact order, which matters for floating point)

```
double deep_ratio(const Row& M, const Row& D, bool same_cpu):
    double score = 0.0;                                   // Python int 0; 0 + 0.001 == 0.001 exactly
    if (M.source_file && D.source_file && *M.source_file == *D.source_file && *M.source_file != "") score = score + 0.001;
    if (M.pseudocode_primes && D.pseudocode_primes && *M.pseudocode_primes == *D.pseudocode_primes && *M.pseudocode_primes != "") score = score + 0.001;
    if (py_eq(M.indegree, D.indegree) && py_ne(M.indegree, 0)) score = score + 0.001;
    if (py_eq(M.outdegree, D.outdegree) && py_ne(M.outdegree, 0)) score = score + 0.001;
    if (py_eq(M.switches, D.switches) && py_ne(M.switches, "[]")) score = score + 0.003;
    if (py_eq(M.cyclomatic_complexity, D.cyclomatic_complexity) && py_ne(M.cyclomatic_complexity, 0)) score = score + 0.001;
    if (py_ne(M.constants, "[]")) {
        auto S1 = json_set(M.constants), S2 = json_set(D.constants);    // throws on NULL or bad JSON, like Python
        size_t n = |S1 ∩ S2|;
        if (n > 0) { double prod = (double)n * (same_cpu ? 0.006 : 0.008); score = score + prod; }
    }
    return score;                                         // ML term omitted (not default)
```

- `py_eq`/`py_ne` implement Python `==`/`!=` on `(NULL | int64 | text)`: NULL equals only NULL, and int never equals text.
- The additions must happen **in this order** and one at a time. `check_ratio` then does `r + score` **once**. Do not fold the per-feature increments into `r`.
- `deep_ratio` is only called when `r < 1.0` (`diaphora.py:1766-1767`). Its `ratio` argument is used only for the ML chooser item.

**Outputs.** A non-negative `double` added to r by `check_ratio`, subject to the 0.99 clamp.

**Runs by default?** Yes. Every `check_ratio` evaluation that reaches `r < 1.0` calls it. The ML block does not run, because `self.classifier` is `None` (§9).

---

## 8. `ratios_cache` (memoisation)

- It is created in `__init__` (`diaphora.py:431`, `self.ratios_cache = {}`) and **reset at the start of `diff()`** (`diaphora.py:3572`).
- The key is `f"{ea1}-{ea2}"` (`diaphora.py:1653`), the decimal address texts of the main and diff rows. It is written on every non-exception return path:
  - The cache writes are at 1682, 1696, 1718, 1729, 1736, 1743, 1752 and 1774.
  - Each is immediately followed by its return, at 1683, 1697, 1719, 1730, 1737, 1744, 1753 and 1775.
  - Every early write stores `1.0`. Line 1697 `return v3` is preceded by `self.ratios_cache[key] = 1.0` at 1696, and there `v3 == 1.0`.
  - The cache-hit return at 1655 writes nothing.
  - An exception, such as `float(None)` or bad JSON in `deep_ratio`, writes nothing, so a later call for the same pair raises again.
- Under the default configuration the cached value is a **pure function of the two rows plus `is_same_processor`**, and `is_same_processor` is fixed before the first call (§0). The cache is therefore semantically transparent, with one exception: the md-conversion path (§6.4). The first path to compute a pair decides whether `md_sqlite` or `md_py` was used.
- Not default: with ML enabled, `apply_machine_learning()` sets `self.classifier` only after the Best and Partial passes (`diaphora.py:3630-3636`). Pairs cached earlier never receive the ML +0.15.
- `check_match` gates on `nullsub_` and `has_best_match` *before* calling `check_ratio` (`diaphora.py:1844-1857`), so those rows are neither computed nor cached.

**Port.** A hash map keyed on `(main row index, diff row index)`. The address is UNIQUE per table, so this is equivalent. To be exact in the pathological md case, record which path computed the entry, or simply honour first-wins.

---

## 9. `get_model_ratio` (`diaphora.py:3496-3549`): not reachable by default

It is only called from `deep_ratio` under `if self.classifier is not None:` (`diaphora.py:2823-2824`). `self.classifier` starts as `None` (`diaphora.py:445`) and is assigned only in `apply_machine_learning`:

```python
  def apply_machine_learning(self):                        # diaphora.py:3551-3555
    if ML_AVAILABLE and self.use_trained_model:
      import joblib
      self.classifier = joblib.load(config.ML_TRAINED_MODEL)
      # (3555: log(f"Using ML classifier {self.classifier}") omitted)
```

Because of the `get_value_for` quirk (§0), `DIAPHORA_USE_TRAINED_MODEL=0` (any non-empty value) turns ML **on** when `ML_AVAILABLE`. `ML_AVAILABLE` is set at `ml/basic_engine.py:21/29` from the sklearn import, and sklearn is installed on this PC. The parity oracle must run with that variable unset.

`self.use_trained_model` is `get_value_for("use_trained_model", config.ML_USE_TRAINED_MODEL)`, which is `False` (`diaphora.py:412-414`, `diaphora_config.py:205`).

What it does when enabled, for the record. It selects `name, nodes, edges, indegree, outdegree, cyclomatic_complexity, primes_value, clean_pseudo, pseudocode_primes, strongly_connected, strongly_connected_spp, loops, constants, source_file` for both sides by address. It builds features with `ml.basic_engine.get_model_comparison_data(dict(row), self.is_same_processor)` and returns `self.classifier.predict(cmp_data)[0]`. A `1` adds `ML_TRAINED_MODEL_MATCH_SCORE = 0.15` and an `ml_chooser` item. `ml_chooser` is not written by `save_results` (`diaphora.py:2409-2416`).

**Port.** Not required for default parity. If ported later, note the late classifier load and cache interaction in §8.

---

## 10. `compare_function_rows` (`diaphora.py:2479-2538`) and the `check_match` dict builder (`diaphora.py:1786-1842`)

```python
  def compare_function_rows(self, main_row, diff_row):
    fields = [ ... ]                       # 2483-2489: built but NEVER used (dead code)
    main_d = {}
    main_d["ea"] = main_row["address"]
    main_d["name"] = main_row["name"]
    main_d["pseudo"] = main_row["pseudocode"]
    main_d["asm"] = main_row["assembly"]
    main_d["pseudocode_primes"] = main_row["pseudocode_primes"]
    main_d["nodes"] = main_row["nodes"]
    main_d["md_index"] = main_row["md_index"]
    main_d["clean_assembly"] = main_row["clean_assembly"]
    main_d["clean_pseudo"] = main_row["clean_pseudo"]
    main_d["clean_micro"] = main_row["clean_microcode"]
    main_d["bytes_hash"] = main_row["bytes_hash"]
    ...  (edges, indegree, outdegree, instructions, cyclomatic_complexity, strongly_connected,
          loops, constants_count, size, kgh_hash: copied but NOT read by check_ratio)
    diff_d = { same for diff_row }
    ratio = self.check_ratio(main_d, diff_d)
    return ratio
```

`check_match` (`diaphora.py:1798-1842`) builds the same keys from the heuristic SQL aliases (`diaphora_heuristics.py:51-75`):
- `ea` from `f.address ea`;
- `pseudo` from `f.pseudocode pseudo1`;
- `pseudocode_primes` from `f.pseudocode_primes pseudo_primes1`;
- `md_index` from `cast(f.md_index as real) md1`;
- `clean_assembly` from `f.clean_assembly clean_assembly1`;
- `clean_pseudo` from `f.clean_pseudo clean_pseudo1`;
- `clean_micro` from `f.clean_microcode clean_micro1`;
- `bytes_hash` from `f.bytes_hash bytes_hash1`;
- the diff side from `df.*` with suffix `2`.

**Port.** One function `ratio(main_idx, diff_idx, MdSource)`. `compare_function_rows` is `ratio(i, j, MdSource::Python)`, and the `check_match` path is `ratio(i, j, MdSource::Sqlite)`. The rows handed to `compare_function_rows` come from `select * from {db}.functions ...` (`find_functions_between`, `diaphora.py:3236-3253`) or `functions_exists` (`diaphora.py:2976-2988`, `select 'main' db_name, * ... union ...`). Both contain the full column set.

**Runs by default?** Yes, unless a dirty heuristic triggers `skip_others`. Its callers are `find_one_match_diffing` (`diaphora.py:3101`, via `find_matches_diffing` inside the `while 1` loop at `diaphora.py:3654-3675`) and `find_functions_between` (`diaphora.py:3280`, via `find_locally_affine_functions`). That loop is skipped when `apply_dirty_heuristics()` returns True (stripped-binary or patch-diff speed-up, `diaphora.py:3618-3627`). In that case these `check_ratio` users still run, all through `check_match`, never through `compare_function_rows`:
- `find_same_name("partial")`, because it sits *before* the `if skip_others` branch (`diaphora.py:3623-3624`);
- `find_remaining_functions()` (`diaphora.py:3627`). It does work only when `self.is_patch_diff` (`diaphora.py:2708`), so it is a no-op in the stripped-binary case;
- in the stripped-binary case, the `"Same binary with symbols stripped"` query has already run inside `apply_dirty_heuristics` through `add_matches_from_query_ratio` (`diaphora.py:2568-2580`).

`diaphora_ida.py:607` also calls `compare_function_rows`, but that is IDA UI only.

---

## 11. Where the ratio goes (consumers) and every use of `MATCHES_BONUS_RATIO`

The category rules themselves belong to the chooser spec. What follows is only how the ratio is transformed and gated.

1. **`check_match`** (`diaphora.py:1855-1872`). It computes `r = self.check_ratio(main_d, diff_d)` (`ratio` is always `None`, because every caller passes one argument). It rejects the row if `self.has_better_match(name1, name2, r)` and then passes `r` through the `on_match` hook. With no hooks this is `[should_add, r]` unchanged. The default patch-diff script `scripts/patch_diff_vulns.py:204-236` is auto-loaded when patch diffing is detected (`diaphora.py:2614-2619`). Whenever it returns, it returns `True, ratio` unchanged, so hooks are ratio-neutral by default. It **can raise**, though:
- In `find_vulns_using_assembly` (`scripts/patch_diff_vulns.py:143-168`), `mnem1[0]`/`mnem2[0]` at line 162 raises `IndexError` when an added or removed asm line's first space-separated token is empty, for example an empty line or a line starting with a space, and `added`/`removed` are both set.
- The exception propagates out of `check_match` like the errors in §12.
- This matters only in patch-diff mode and belongs to the driver/chooser spec.

   Consequence: **even `HEUR_TYPE_NO_FPS` heuristics depend on the computed ratio.** `add_matches_from_query` (`diaphora.py:2063-2075`) calls `check_match(row)`, so `has_better_match` sees `r`, but then it adds the item with ratio `1`/`1.0` regardless.

   Dead path: the `ratio == 1.0` branch of `check_match` would raise `UnboundLocalError` at line 1870 (`r` unset), but no caller passes `ratio`.
2. **`add_matches_internal`** (`diaphora.py:1922-1946`) uses `r` raw: `r == 1.0` goes to best, `r >= val` to partial, otherwise the unreliable window `DEFAULT_PARTIAL_RATIO > r > val`. The item stores `r` unmodified.
3. **`find_same_name`** (`diaphora.py:2194-2208`), bonus #1:

   ```python
          if float(ratio) == 1.0 or (
            self.relaxed_ratio and md1 != 0 and md1 == md2
          ):
            the_chooser = "best"
            item = [ea, name1, ea2, name2, desc, 1, nodes1, nodes2]
          else:
            the_chooser = choose
            if ratio + config.MATCHES_BONUS_RATIO < 1.0:
              ratio += config.MATCHES_BONUS_RATIO
            item = [ea, name1, ea2, name2, desc, ratio, nodes1, nodes2]
          self.add_match(name1, name2, ratio, item, the_chooser)
   ```

   Port: `if (r + 0.01 < 1.0) r = r + 0.01;` (double add; `0.99 + 0.01 == 1.0`, so a clamped 0.99 gets no bonus).
4. **`find_one_match_diffing`** (`diaphora.py:3101-3110`), bonus #2. The chooser is picked **before** the bonus:

   ```python
              r = self.compare_function_rows(main_row, diff_row)
              if r == 1.0:
                chooser = "best"
              elif r > config.DEFAULT_TRUSTED_PARTIAL_RATIO:
                chooser = "partial"
              else:
                continue
              if r + config.MATCHES_BONUS_RATIO < 1.0:
                r += config.MATCHES_BONUS_RATIO
   ```
5. **`find_functions_between`** (`diaphora.py:3280-3286`). There is **no** bonus. `r == 1.0` goes to best, `r >= DEFAULT_PARTIAL_RATIO` to partial, otherwise skip.
6. **`search_small_differences`** (`diaphora.py:2119-2148`). It computes its own gate ratio `commons/total` over the `names` JSON sets, then **replaces** it with the `check_match` ratio (`ratio = ratio2`).
7. **`add_match`** (`diaphora.py:1350-1351`) records `ratio = 1.0` in `matched_primary`/`matched_secondary` when `name1 == name2`. The **item** keeps the (possibly bonused) ratio. `has_better_match`/`has_best_match` read the recorded value, not the item.
8. **Output formatting.** `CChooser.add_item` stores `dec_vals % item.ratio` with `dec_vals = "%." + config.DECIMAL_VALUES`, so `"%.7f"` (`diaphora.py:282, 290`). `save_results` writes that **string** into `results.ratio` (`diaphora.py:2395-2424`). Parity comparison of `.diaphora` files should compare these strings, which use the same half-even exact rounding as §5. Internal ordering (`sorted(... key=lambda x: float(x[5]))`, `diaphora.py:2846, 2926, 3137-3139`) and the multimatch maxima use the unrounded doubles.

`MATCHES_BONUS_RATIO` is used exactly twice (`grep -n MATCHES_BONUS_RATIO diaphora.py` gives lines 2203-2204 and 3109-3110). `INCREASE_RATIO_PER_CONSTANT_MATCH*` is used only in `deep_ratio` (2817-2820).

---

## 12. Error behaviour (for fidelity on malformed exports)

`check_ratio` and `deep_ratio` have no `except`. Exceptions propagate to the caller:

- `float(None)` for a NULL `md_index`, and `json.loads(None)` or invalid JSON for `constants`, raise.
- `json.loads` is `strict=True`, so a raw control character inside a JSON string raises. The exporter escapes them.
- In relaxed mode `ast_ratio` can raise `ZeroDivisionError`.

Where each exception lands:
- `add_matches_from_query_ratio*`: `except: log(...); traceback.print_exc(); raise` (`diaphora.py:1967-1973`, `1992-1998`, `2018-2024`).
  - When the function is launched through `run_heuristics_for_category`, it runs in its own worker thread. The exception kills that thread. `threads_apply` (`jkutils/threads.py:27-71`) just sees the thread end, and the diff continues **without the remaining rows of that heuristic**.
  - When it is called directly from main-thread code (`search_just_stripped_binaries`, `diaphora.py:2580`), the re-raise aborts `diff()`.
- `add_matches_from_query` (NO_FPS): `except: log(...)` with no re-raise (`diaphora.py:2080-2081`). The heuristic silently stops at the failing row.
- Main-thread callers with `try/finally` only, or no handler at all, let the exception propagate out of `diff()`. The uncaught error aborts the script before `save_results`. These callers are `find_same_name`, `search_small_differences`, `search_remaining_functions`, `find_related_constants`, `find_related_compilation_unit`, `find_one_match_diffing` and `find_functions_between`.

Related abort path, a timeout rather than a ratio error:
- `add_matches_internal` does `raise SystemExit()` once one call has run longer than `self.timeout`, 300 s (`diaphora.py:1893-1896`).
- The `add_matches_from_query_ratio*` wrappers catch it (`except SystemExit: pass`, `diaphora.py:1965-1966, 1990-1991, 2016-2017`).
- Main-thread callers that call `add_matches_internal` directly do not catch it: `search_remaining_functions` (2696), `find_related_constants` (3391) and `find_related_compilation_unit` (3458). There the `SystemExit` leaves `diff()`, so the script exits with status 0 and **no `.diaphora` file** (`save_results` at 3773 is never reached).

**Port.** Our native exporter must never write NULL `md_index`, NULL/invalid `constants`, or a REAL-typed `md_index`. A double bound into a TEXT column is stored as SQLite's shorter text, which loses the 28-digit string. For reading foreign exports, mirror the "drop the rest of this heuristic" behaviour only if we ever need bug-for-bug parity on broken inputs. NOT DETERMINED FROM SOURCE whether real IDA exports contain such rows.

---

## 13. Verification performed (reproducible)

The scratch files are in `<scratch>\`. Python bytecode writing was disabled, and `git status` in diaphora-ref stayed clean.

- `harness.py` builds two synthetic DBs with the real `db_support.schema.TABLES`. Main is random; diff has 60% near-copies with one-line perturbations. The data mixes NULL and empty texts, 255/256/257-line texts to hit rounding ties, trailing newlines, near-equal 28-digit md strings, large u64 and string constants, duplicate constants, NULL switches and indegree, and same versus different processors.
- It runs the real `diaphora.CBinDiff.check_ratio` over the cross product through the `get_query_fields` SQL path, and compares it with an independent implementation of §2, §5, §6.3 and §7. Results: seeds 1, 2, 3, 7, 11, 12 (the same-processor processor setting) and 5, 6, 21 (a different processor) gave 0 mismatches in 54,800 pairs before the near-copy change. Seed 7 used 60 functions per side and the rest used 80. Seeds 3, 4, 8, 13 (same) and 9 (other) gave 0 mismatches in 32,000 pairs afterwards. Seeds 3 and 4 ran again after a mutation-script fix.
- `pathb.py` runs the real `compare_function_rows` on the same data against the spec with `md_py`: 0 mismatches in 12,800 pairs.
- Mutations of the spec implementation, each of which must break parity. Every one did:

  | Mutation | Ratios that changed |
  |---|---|
  | round half-up | 81/6,400 |
  | no rounding | 4,023 |
  | no 0.99 clamp | 7 |
  | constants as doubles | 333 |
  | no v5 short-circuit | 1 |
  | no md guard | 12 |
  | NULL bytes_hash not equal | 118 |
  | `splitlines` instead of `split("\n")` | 1,420 |
  | always 0.008 per constant | 1,871 |
  | md compared as strings (row path) | 361 and 545 |

- `relaxed.py` covers the relaxed-mode probes listed in §6.5.

A C++ unit suite should embed these as fixtures: the tie table in §5, the §6.5 values, and a small DB pair checked against the Python oracle.

---

## Hard parts

1. **Rounding exactness.** Real ties occur (denominator-256 ratios). Use exact half-even rounding on the binary value (§5). Anything based on `v*1e7` or legacy `printf` diverges in a few percent of real pairs.
2. **FP evaluation order and contraction.**
   - `v4 = (((v1+v2)+v3)+3.0)/5.0`; `score` is accumulated term by term in the listed order; `r + score` happens once; the clamp is `r + score < 1.0`.
   - Build the ratio translation unit with **`-ffp-contract=off`** on GCC/Clang. GCC in `gnu++20` mode defaults to `fast`, and Clang fuses `score + n*tmp` into an FMA on FMA-capable targets such as Apple arm64 CI (`macos-latest`).
     - This project sets `CMAKE_CXX_EXTENSIONS OFF` (`CMakeLists.txt:10`), so it compiles with `-std=c++20`, not `gnu++20`.
     - Do **not** rely on the `-std` mode to disable contraction. Whether GCC's ISO-mode default of `off` applies to C++ is NOT DETERMINED FROM SOURCE here: it is toolchain behaviour, not Diaphora.
     - Set the flag explicitly. The current `CMakeLists.txt` has no `-ffp-contract`, `/fp:` or `-march` flag, per a grep.
   - On MSVC use `/fp:precise` (not `/fp:fast` or `/fp:contract`).
   - Keep `prod = n*tmp` as a separate statement.
   - Never use `-ffast-math` or reassociation here.
3. **Two md conversion paths plus first-wins caching** (§6.4, §8). This is practically never observable, but needs `md_sqlite` and `md_py` per function to be exact. Always compare as doubles.
4. **Python `None` semantics.** `NULL == NULL` is True for `bytes_hash` (giving 1.0), `indegree`, `outdegree`, `cyclomatic_complexity` and `switches` (each earning its bonus). `NULL != ""` means a NULL `clean_pseudo` does **not** trigger the "Error cleaning" branch. It goes through `quick_ratio`, which returns 0 anyway.
5. **Python set semantics for `constants`.** Exact bigints, int/float cross-equality, JSON string unescaping, and distinct counting.
6. **`quick_ratio` performance at scale.** It is O(lines) per pair with exact line equality. Use line interning (§2). Python's per-heuristic `SQL_TIMEOUT_LIMIT` (300 s, `diaphora_config.py:92`, enforced in `add_matches_internal`, `diaphora.py:1894-1896`) and `SQL_MAX_PROCESSED_ROWS` (1,000,000, `diaphora.py:1878`) can **truncate** heuristics in Python on big inputs. Our faster port would then process rows Python never reached. This is a parity hazard that cannot be solved inside the ratio code; document it wherever outputs diverge on large binaries.
7. **The clamp can lower a ratio.** For example 0.995 with a 0.006 bonus becomes 0.99, and a later `+0.01` bonus is then refused because `0.99 + 0.01 == 1.0` is not `< 1.0`.

## Open questions

1. **SQLite version drift for `md_sqlite`. PARTLY RESOLVED.**
   - CI pins **no** SQLite version (`.github/workflows/ci.yml`):
     - Linux: `apt-get install -y libsqlite3-dev` on `ubuntu-latest`.
     - macOS: `brew install sqlite3`.
     - Windows: classic-mode `vcpkg install sqlite3:x64-windows` from the runner image's vcpkg checkout, with no baseline or manifest.
   - So the three platforms link whatever those channels ship on the day. The exact versions are NOT DETERMINED FROM SOURCE.
   - Measured on this PC (§6.4), Windows builds 3.46.0 through 3.53.0 are bit-identical on 200k md strings, while 3.37.2 and 3.42.0 differ on 26% of them. Linux GCC builds of 3.43-3.52 are not verified.
   - It only matters when two different md strings would map to the same double under one converter but not the other.
   - Decision still needed:
     - (a) accept the risk;
     - (b) vendor and pin the SQLite amalgamation, at 3.46+ to match the 3.51.1 oracle;
     - (c) compute `md_sqlite` with an in-tree port of 3.53.0 `sqlite3AtoF`/`sqlite3Fp10Convert2`, which matches 3.46-3.53 on this sample, independent of the linked library.
2. **cdifflib. RESOLVED FROM SOURCE for cdifflib 1.2.9, the current PyPI release.** I downloaded the sdist to `scratchpad/v03a/cdl/`; it is not installed.
   - `CSequenceMatcher` subclasses `difflib.SequenceMatcher`. It overrides only `__init__`, `find_longest_match`, `set_seq1`, `set_seq2` (which resets `self.fullbcount = None`) and `get_matching_blocks` (`cdifflib.py:21-79`).
   - It does **not** override `quick_ratio` or `real_quick_ratio`, so both are the inherited stdlib code in §2/§3, run on the same lists. The result is identical.
   - Older cdifflib versions: NOT DETERMINED.
3. **Real-export column contents. PARTLY RESOLVED FROM SOURCE.** For rows written by `diaphora_ida.py`'s `read_function` → `build_props_list` → `save_function` path:
   - `bytes_hash` is always an md5 hexdigest (`diaphora_ida.py:2977`).
   - `md_index` is always `0` or `str(Decimal)` (2514-2538).
   - `constants` is always a JSON list: it starts as `[]` at 3081 and is `json.dumps`'d at `diaphora.py:936-939`.
   - `indegree` is always an int (3072).
   - `address` is `int(ea)` (3207), so it is canonical decimal text.
   - None of these is ever NULL, **unless** an `after_export_function` hook rewrites the row (`diaphora_ida.py:3099-3107`) or a non-IDA exporter produced the DB. Whether real exports use such hooks: NOT DETERMINED (HANDOFF blocker 1).
4. **Heuristic execution order** (outside this spec). VERIFIED: `threads_apply` takes work with `targets.pop()` (`jkutils/threads.py:40`), so heuristics of one category run in **reverse** list order; `cpu_count` is 1 standalone, so there is one thread at a time. Ratios are cache-pure, so this does not affect `check_ratio` values. It does affect `add_match`/`has_better_match` outcomes, so the chooser/ordering spec must account for it.
5. **Bug-for-bug error handling** (§12). This is a product decision; source cannot settle it. The facts are in §12: the worker-thread heuristic is truncated, NO_FPS heuristics stop silently, main-thread callers abort with no output file, and a timeout in main-thread callers exits with no output file. "Reject the DB at load" diverges from all of these on malformed input.

---

## Verification log

An adversarial verification pass checked this spec against `<diaphora-ref>` (`3.4.2-4-g621ec26`, `git status` clean), the stdlib `difflib.py` of Python 3.13.12, the SQLite amalgamation/DLLs and the exporter `diaphora_ida.py`. The probe scripts are in `<scratch>\v03a\`: `probes1.py`, `relaxed2.py`, `misc.py`, `mdprobe.py`, `dllprobe.py`, `onedll.py`, `mdperm.py`, plus copies of the extractor's `harness.py`/`pathb.py`/`relaxed.py`, re-run in isolation.

**Confirmed unchanged:**
- every config value and line in §0;
- `get_value_for` and its bool quirk (probed: `"0"` gives `'0'`, `""` gives `''`);
- `check_bufs`, `quick_ratio`, `real_quick_ratio` and `ast_ratio` lines and logic, and the difflib source lines;
- the `check_ratio` body (1645-1775) and every `# NNNN` annotation;
- the `compare_function_rows` and `check_match` dict builders;
- the `deep_ratio` body and order (2749-2837);
- the `ratios_cache` init and reset lines, `same_processor_both_databases`, the set-point of `is_same_processor` (3617), and the fact that `equal_db`, `check_callgraph` and `find_equal_matches` never call `check_ratio`;
- the `MATCHES_BONUS_RATIO` uses (2203-2204 and 3109-3110 only) and the `INCREASE_RATIO_PER_CONSTANT_MATCH*` uses (2818 and 2820 only);
- `MIN_FUNCTIONS_TO_DISABLE_SLOW`, used only at `diaphora_ida.py:3799`;
- the `CChooser.add_item` `"%.7f"` formatting (282, 290) and `save_results` (2374-2429);
- the `itemize_for_chooser` positional shuffle (2722-2730), which maps back to the correct Item fields;
- the §5 tie table and test vectors, the §2 examples, and the relaxed `ast_ratio` quirks (`2` vs `3` gives -1.0; `"0"` vs `"1"` raises `ZeroDivisionError`);
- the md example string;
- invalid UTF-8 raising `sqlite3.OperationalError` at fetch time, and embedded NUL surviving;
- the extractor harness (seeds 3/same and 9/other, 0 mismatches over 6,400 pairs each) and `pathb.py` (0 mismatches over 3,600 pairs);
- the §5 `round_dec` integer algorithm, including the new `s >= 128` guard, simulated in Python (`rounddec.py`): 0 mismatches against `"{0:.7f}"` and `"{0:.1f}"` over 5,103,010 cases. These cover every `2m/L` with L < 3000, 300k random doubles, subnormals and values around 5e-8.

**Corrections made:**
1. **Summary:** "Every ratio Diaphora prints comes from `check_ratio`" was overstated. Literal-`1` items exist (1439, 2074, 2200), and callers add +0.01 bonuses. Reworded.
2. **§0:** Added that `DIFFING_ENABLE_EXPERIMENTAL` only gates `apply_dirty_heuristics`. `find_experimental_matches` is nested under `if self.unreliable` (3638-3651), and no heuristic has category `"Experimental"`. `find_brute_force` needs `unreliable`. The default ratio sources are only the Best/Partial heuristics.
3. **§2 / §6.1:** Code labelled "verbatim" silently dropped docstrings (159-161, 1646-1649) and the comment at 1724-1725. It is now labelled as such.
4. **§5 `round_dec`:** The pseudocode shifted a u128 by ≥ 128 (`q << s`, `1 << (s-1)`) when `s >= 128`, which is undefined behaviour in C/C++. Added `if (s >= 128) return 0.0;`. This is unreachable from quick_ratio values but required for the stated domain `0 <= v <= 1`.
5. **§6.3:** "any quick_ratio of at least 0.99999995 (about 4·10^7 lines)" was wrong. The minimum is total L = 20,000,001, odd L, with m = 10^7 (verified); even L needs 40,000,002.
6. **§6.3:** Added the order of failure: `float(md)` (1672) runs before the bytes_hash shortcut (1681) and after the cache lookup (1654).
7. **§6.4:**
   - Added that the md value is also used by the `md1 != md2` guard (1758) and by `find_same_name`'s relaxed test.
   - Verified that every `check_match` caller uses `get_query_fields` (50 heuristics plus 8 internal queries).
   - Added the SQLite-vs-Python divergence table for non-numeric text (`''`, `'nan'`, `'1.5abc'` and others) and the Python `float()` versus `std::from_chars` acceptance differences.
   - The claim that `sqlite3_column_double` equals `CAST AS REAL`, previously read only in 3.53.0, is now **verified on 3.51.1** by ctypes (0 differences over 200,001 strings).
   - Added a cross-version measurement: 3.46.0-3.53.0 are identical, while 3.37.2 and 3.42.0 differ on 26%.
   - Fixed the vague `<other-project>/...` citation to an absolute path with function line numbers.
8. **§6.5:** The relaxed "verified" values (0.9 and 0.7333…) are correct only when deep_ratio is 0. The cited `relaxed.py` actually prints 0.901 and 0.7343333333333333, because deep_ratio adds +0.001 on harness rows. They were re-verified with deep-neutral rows (`relaxed2.py`), and this is stated.
9. **§6.5 "Runs by default?":** The caller list had no qualifiers. Added the gating condition and line for each caller (slow_heuristics, experimental and ≥99% shared addresses, patch-diff mode, `ignore_all_names`), plus `find_brute_force` as non-default.
10. **§7.1:** The degree/cc "Python ints" citation (3145-3152) pointed at tuple slots, not at where the types come from. Added 3071-3072, 2851, 2898, 2917 and 2966. Added the verified set-semantics edge cases: `true`/`false` equal `1`/`0`, `null`, unhashable nested values raise, and the JSON `NaN` singleton intersects.
11. **§8:** "Look at the returns at 1682, 1696, …" listed the **cache-write** lines. The returns are at 1683, 1697, 1719, 1730, 1737, 1744, 1753 and 1775. Also added that the cache-hit return at 1655 writes nothing and that exceptions cache nothing.
12. **§9:** The `apply_machine_learning` quote omitted the log line (3555); it is now marked. Added that the `get_value_for` quirk turns ML on with `DIAPHORA_USE_TRAINED_MODEL=0` (sklearn is installed here, so `ML_AVAILABLE` is True).
13. **§10:** "In that case only `find_remaining_functions` runs" was wrong. `find_same_name` runs before the `skip_others` branch (3623-3624). `find_remaining_functions` is a no-op unless `is_patch_diff` (2708). The stripped-binary query already ran inside `apply_dirty_heuristics` (2568-2580).
14. **§11.1:** "hooks are ratio-neutral" is true for the returned value, but the default patch-diff hook can raise `IndexError` (`scripts/patch_diff_vulns.py:162`) and propagate out of `check_match`. Caveat added.
15. **§12:** Added the timeout abort path. `SystemExit` from `add_matches_internal` (1896) is uncaught in the main-thread callers at 2696, 3391 and 3458, so the script exits with status 0 and writes no `.diaphora`.
16. **Hard parts #2:** Added that this repo builds with `CMAKE_CXX_EXTENSIONS OFF` (`-std=c++20`, `CMakeLists.txt:10`) and has no FP flags yet. The GCC default for C++ is toolchain behaviour, marked NOT DETERMINED FROM SOURCE; the recommendation to set `-ffp-contract=off` explicitly stands.
17. **Open questions:**
    - #1 partly resolved: CI pins no SQLite (apt, brew, vcpkg classic); cross-version data added; options listed.
    - #2 resolved from the cdifflib 1.2.9 sdist: `quick_ratio` and `real_quick_ratio` are not overridden, so they are identical.
    - #3 partly resolved: the IDA exporter never writes NULL for those columns, except through hooks or foreign exporters.
    - #4 verified.
    - #5 is a product decision, with the facts summarised.

**Re-measured side claims:**
- md string vs double permutation sensitivity: my generator gave 1,733 of 3,000 strings differing and 0 of 3,000 doubles differing. That supports the claim qualitatively; the exact count depends on the generator.
- Python-vs-SQLite 1-ulp md conversions: 120/200,000 on my generator, against 158/200,000 reported earlier.

**Still not determined:** Linux GCC and macOS SQLite `sqlite3AtoF` behaviour for the exact CI versions; cdifflib versions before 1.2.9; the contents of real IDA exports (hooks); and whether bug-for-bug error parity is required.
