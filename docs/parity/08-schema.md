# 08: Export schema and data encoding (ingestion spec for the native loader)

> **Historical spec.** Written on 2026-09-23 against an earlier revision (`34ed418`), before the port existed; its status remarks ("not implemented", test counts, runs "still running", open questions) are historical. See [README.md](README.md) in this directory for how to read it; quoted Diaphora code is (c) Joxean Koret, AGPL-3.0-or-later, and quoted CPython `difflib` code is under the PSF License Version 2.

## Summary

- **Storage class comes from column affinity, not from the Python type.** Every `text`/`varchar` column stores TEXT, even when the exporter bound a Python `int`. `integer` columns turn numeric strings back into INTEGER, or into REAL when the value exceeds int64. That makes the `get_valid_prop` ">0xFFFFFFFF → str" rule a no-op for TEXT columns. It matters only for INTEGER columns that receive a value above 2^63, which then become a lossy REAL [EMP]. **No INTEGER column receives such a value in practice.** The one theoretical case, `function_flags = BADADDR`, cannot happen: `read_function` returns early when `get_func(f)` is None (`diaphora_ida.py:3208-3211`), and `idc.get_func_attr` returns BADADDR only when `get_func` is None ([IDA] 9.4 `idc.py:3114-3127`). In all 7 real exports every INTEGER column holds only INTEGER [REAL]. The loader should still check the type tag.
- **What is stored as TEXT.** Addresses, RVAs, hashes, prime products (`primes_value`, `mnemonics_spp`, `pseudocode_primes`, `kgh_hash`, `strongly_connected_spp`, `microcode_spp`), `md_index` and every JSON list are TEXT. The prime products are plain decimal digits of unbounded length. `md_index` is a 28-significant-digit `Decimal` string. `program.callgraph_primes` is a `Decimal` in scientific notation (for example `2.613…E+399`). `program.md5sum` is a 16-byte **BLOB** (IDA 9.x), even though its declared type is `text` (`schema.py:124`); TEXT affinity does not convert a BLOB. `program.processor` is `'pc64'` for x86/x64 inputs under IDA 9.x, 32-bit inputs included. [EMP][REAL][BIN]
- **TEXT columns are compared as text.** `kgh_hash != 0` is `kgh_hash != '0'`, `md_index > 0` is `md_index > '0'`, and `microcode_spp != 1` is `!= '1'`. `find_functions_between` compares addresses **lexicographically** (`'999999' < '1000000'` is false). The native loader must keep the raw TEXT bytes, and it must keep **NULL distinct from `''`**. [EMP]
- **`md_index` needs two doubles.** Loading it as one double is not enough. The SQL heuristic path uses SQLite `CAST(md_index AS REAL)`, which equals `sqlite3_column_double` on the TEXT value. The `compare_function_rows` path uses Python `float()`, which is correctly rounded. The two differ on **139 of 200,000** realistic values under SQLite 3.51.1 [EMP]. The verification pass re-ran this with a different random md_index-shaped distribution and got 150 of 200,000.
- **What the diff reads.** On the default path it reads **39 of the 49** `functions` columns. The side tables it reads are `constants`, `compilation_units`, `compilation_unit_functions`, `instructions`, `bb_instructions`, `program` and `version`. It never reads `basic_blocks`, `bb_relations`, `function_bblocks`, `callgraph` or `program_data`.
- **Row multiplicity is part of the contract.** `constants` keeps duplicate integers. H16 and H22 emit one row per duplicate pair; H21 is `select distinct` and does not. A basic block shared by two functions is one `basic_blocks` row whose `bb_instructions` rows gather instructions from **both** functions. Microcode instructions sit in the same `instructions` table and feed the same "rare" heuristics. That holds for the headless (`DIAPHORA_AUTO`) export as well, where the `microcode*` *columns* are NULL but the microcode *rows* are still written. [EMP][REAL]

Tags: **[SRC]** means a verbatim source quote. **[EMP]** means a result reproduced by driving Diaphora's *own* writer (`CBinDiff.save_function` / `create_indices`, imported read-only from the ref checkout) with props shaped exactly like `build_props_list`. The runtime was Python 3.13.12 with SQLite 3.51.1 (`miniconda3/Library/bin/sqlite3.dll`, the same DLL the native build links); the probe is in Appendix A. **[IDA]** means a quote from the installed IDA 9.2/9.4 Python stubs. **[REAL]** (added by the verification pass) means a check against real Diaphora exports, opened read-only (`?immutable=1`). These are the 7 oracle exports in `<corpus>/oracle/exports/*/*.sqlite` (IDA 9.4 idalib, `diaphora_ida._diff_or_export(use_ui=False)`, decompiler on), plus one headless export of the tester sample `ls` made during verification. That export used `idat -A -B -S diaphora.py` with `DIAPHORA_AUTO=1` and no `DIAPHORA_USE_DECOMPILER`, and ran from a scratch copy of the ref checkout. **[BIN]** means an inspection of the installed IDA binaries, or an idalib probe.

---

## 0. Provenance

- The reference is `<diaphora-ref>`, `git describe` = `3.4.2-4-g621ec26`. Apart from `README.md`, the only change after the tag is in `diaphora_ida.py`: 4 CSS lines inserted at 3864-3887 (`git diff --stat 3.4.2..HEAD`). All `diaphora_ida.py` line numbers below 3864 are identical to tag 3.4.2. `db_support/schema.py`, `diaphora.py` and `diaphora_heuristics.py` are unchanged.
- The heuristic numbers `H01…H50` follow definition order in `diaphora_heuristics.py`, as in `04a-heuristics-best.md`. The list was generated by importing `HEURISTICS` rather than typed by hand (12 Best, 30 Partial, 8 Unreliable).
- "Default" means the standalone run `python diaphora.py db1 db2 -o out` with the shipped `diaphora_config.py` and no `DIAPHORA_*` environment variables. In that configuration `unreliable=False` (`diaphora.py:400-402`, config line 46) and `slow_heuristics=True` (`diaphora.py:409-411`, config line 49). The `MIN_FUNCTIONS_TO_DISABLE_SLOW` auto-disable exists **only** in IDA's `BinDiffOptions` (`diaphora_ida.py:3798-3800`) and does not apply standalone. `ignore_all_names` is forced to `False` (`diaphora.py:3759-3760`). `relaxed_ratio=False` and `use_trained_model=False`.
- **Global default caveat.** When `apply_dirty_heuristics()` returns True (stripped-binary or patch-diff detection), the Best and Partial heuristics and the whole convergence loop are skipped (`diaphora.py:3616-3631`). In that case only `find_same_name` + `find_remaining_functions` + `final_pass` run. Every "Runs by default: yes" below carries the implicit condition "unless dirty mode fired".

---

## 1. SQLite typing rules that govern every column

### 1.1 Declared types and affinities (`db_support/schema.py:68-186`)

| Declared type in schema.py | Affinity (SQLite rule: contains INT → INTEGER; CHAR/TEXT → TEXT; REAL → REAL) |
|---|---|
| `integer`, `int`, `integer primary key` | INTEGER (`integer primary key` = rowid alias) |
| `text`, `varchar(255)` | TEXT |
| `real` (`export_time` only) | REAL |
| no type (`version.value` is `text`, so no untyped column exists in the export) | n/a |

### 1.2 What Python's `sqlite3` binds [EMP]

- `int` → INTEGER. Values ≥ 2^63 raise `OverflowError: Python int too large to convert to SQLite INTEGER` [EMP]. This is why `get_valid_prop` exists.
- `bool` → INTEGER 0/1. `str` → TEXT. `float` → REAL. `None` → NULL. `bytes` → **BLOB** [EMP].

### 1.3 Conversion on store

- **TEXT affinity:** INTEGER/REAL values are converted to text before storage, and BLOB/NULL are kept as they are. [EMP]: `main` at `0x401000` was bound as `int 4198400` and is stored as TEXT `'4198400'`. The SQLite int→text rendering is plain decimal, which is identical to Python `str(int)`.
- **INTEGER affinity:** a TEXT value that is a well-formed integer literal becomes INTEGER. When it does not fit in int64 it becomes REAL. [EMP]: `function_flags` bound as `str(0xFFFFFFFFFFFFFFFF)` is stored as REAL `1.844674407370955162e+19`.
- **REAL affinity:** numeric text becomes REAL. [EMP]: `export_time` bound as `'0.012345678901'` is stored as REAL.

### 1.4 Comparison rules the diff relies on [EMP]

These results came from SQLite 3.51.1, on real columns and CTE columns:

| Expression | Behaviour | Probe |
|---|---|---|
| TEXT-affinity column vs numeric literal | The literal gets TEXT affinity, so the comparison is **text** (memcmp/BINARY). | `x='10'`: `x > 9` → 0, `x != 10` → 0, `x = 10` → 1 |
| TEXT column from a `union` CTE vs literal | Still text | `with s as (select x … union …) select x > 9` → 0 for `'10'` |
| INTEGER column vs text parameter | Numeric (the param is numerified) | `n=10`: `n = '10'` → 1 |
| TEXT column vs int parameter | Text (the param is converted to text) | `x = 10` (param) → 1 for `'10'` |
| TEXT vs TEXT | memcmp, lexicographic | `'999999' < '1000000'` → 0 |
| `NULL = x` | NULL, which sorts **first** in `ORDER BY … ASC` | `order by v` over {NULL,1,0} → NULL, 0, 1 |
| `abs(text)` | REAL built from the longest numeric **prefix**; 0.0 when there is none | `abs('12abc')`=12.0, `abs(' 42')`=42.0, `abs('0x10')`=0.0, `abs('abc')`=0.0, `abs('1e3')`=1000.0 |
| `length(text)` / `substr(text,…)` | Counted in characters (UTF-8 code points) | `length(pseudocode_primes)`=37 on a 37-digit value |

---

## 2. Export pipeline: who writes what, in what order

`do_export` (`diaphora_ida.py:1191-1281`) [SRC]:

```python
1212:    self.commit_and_start_transaction()
...
1246:      props = self.read_function(func)
1247:      self.clear_pseudo_fields()
1248:      if props is False:
1249:        continue
1250:
1251:      ret = props[11]
1252:      callgraph_primes *= decimal.Decimal(ret)
...
1258:      self.save_function(props)
...
1266:    self.commit_and_start_transaction()
1267:    md5sum = GetInputFileMD5()
1268:    self.save_callgraph(
1269:      str(callgraph_primes), json.dumps(callgraph_all_primes), md5sum
1270:    )
1271:    self.export_structures()
1272:    try:
1273:      self.export_til()
...
1277:    if config.EXPORTING_COMPILATION_UNITS:
1278:      self.save_compilation_units()
1279:
1280:    log_refresh("Creating indices...")
1281:    self.create_indices()
```

What this order implies for the loader:

1. `functions.id` is assigned sequentially in `Functions(min_ea, max_ea)` order (ascending EA, `diaphora_ida.py:1198`). Skipped functions consume no id. H02 "Same order and hash" joins on `df.id = f.id`, so **ids must be loaded exactly as stored and never renumbered**. There is one exception: on a crash-resume export (`<db>-crash` exists, `diaphora_ida.py:1292-1295`), functions up to the last saved RVA are skipped (1236-1244) and ids continue from the rows already in the file. `_funcs_cache` is reset at 1215, so the functions saved before the crash get no CU membership and keep `source_file` NULL (§7.6).
2. `source_file` is inserted as NULL (props[42] = `None`, `diaphora_ida.py:3184`). It is only filled later by `save_compilation_units` (§7.6).
3. Indices and `analyze` come last (`diaphora.py:634-649`). `export()` runs another `analyze` (`diaphora_ida.py:1320-1324`). Exports therefore ship a `sqlite_stat1` table [EMP]. That table steers SQLite's query planner during Diaphora's diff, and so the **row order** of every heuristic.
4. `commit_and_start_transaction` sets `PRAGMA journal_mode = WAL` (`diaphora_ida.py:1185-1188`, `SQLITE_JOURNAL_MODE = "WAL"` config line 95). WAL mode persists in the file header, so IDA-produced exports are **WAL-mode databases** (see Hard part H-11).
5. `clear_pseudo_fields()` runs **before** `save_function` (1247 vs 1258). `self.pseudo_comments` is therefore always empty at save time, and `instructions.pseudocomment`/`pseudoitp` are NULL for every native row (§7.8). [REAL]: 0 native rows with a non-NULL `pseudocomment` in `ls.sqlite`.
6. The export connection runs `PRAGMA foreign_keys = ON` (`create_schema`, `diaphora.py:621`) before any transaction, so the `references` clauses in `schema.py` are enforced while exporting. `instructions.func_id` has **no** `references` clause (`schema.py:135`), so it is the one parent link that is not FK-checked.

**Export-option dependence (what can legitimately be NULL or empty):**

| Option | Where | Effect on stored data |
|---|---|---|
| `use_decompiler` (GUI/idalib `BinDiffOptions` default `EXPORTING_USE_DECOMPILER=True`, 3786-3788; **headless `DIAPHORA_AUTO` default False**, `diaphora_ida.py:4033-4035,4050`. Any non-empty value of `DIAPHORA_USE_DECOMPILER`, `"0"` included, turns it on, because the raw `os.getenv` string is assigned as is) | `guess_type` 2352-2363 | When off: `pseudocode`, `pseudocode_hash1/2/3`, `pseudocode_primes` and `clean_pseudo` are NULL, and `pseudocode_lines` is 0. `microcode`/`clean_microcode` are NULL and `microcode_spp` is `'1'`. `prototype` falls back to `idc.guess_type` (NULL more often). **`prototype2` also changes**, because decompiling `f` at 2967 sets types that `idc.get_type(f)` at 2968 then reads. [REAL] headless vs decompiler-on `ls`: `prototype2` differs on 188/318 functions (178 NULL vs 21 NULL), and `function_flags`/`assembly`/`clean_assembly` differ on 1. **Microcode side-table rows are still written** (see the next row). |
| `export_microcode` (GUI/idalib: `total_functions <= 8001`, `diaphora_ida.py:3831-3832`. **Headless: True by default, with no function-count threshold.** The value comes from `CBinDiff.__init__` `diaphora.py:479-481`, which is `get_value_for("export_microcode", config.EXPORTING_USE_MICROCODE=True)`. Env `DIAPHORA_EXPORT_MICROCODE` overrides it with the raw string, so a non-empty `"0"` still counts as true (`get_value_for`, 560-569). The headless override at `diaphora_ida.py:4061-4063` reads env `DIAPHORA_SELF.EXPORT_MICROCODE`, a typo that never matches) | `extract_microcode` 2662, `get_microcode` 2264 | When off: microcode columns are NULL / `'1'`, and there are no `asm_type='microcode'` rows in side tables. The **column** is filled only through `decompile_and_get` (2348-2349), because `extract_microcode(f)` (2992) runs *before* the second `get_microcode(func, ea)` (2993). The **side-table rows** come from that second call. Its gate `self.decompiler_available and self.export_microcode` (2264) passes in headless mode, because `decompiler_available = config.EXPORTING_USE_DECOMPILER` (1082) and is lowered only inside `decompile_and_get` (2311). [REAL] headless `ls`: 70,016 microcode instruction rows and 4,898 microcode blocks, identical to the decompiler-on export, while all 318 `microcode` columns are NULL. |
| `function_summaries_only` (GUI: `total_functions > 100000`, 3821-3822; headless: config `EXPORTING_FUNCTION_SUMMARIES_ONLY=False`, `diaphora.py:465`, env override 4057-4059) | `save_function` 1001-1002 | `instructions`, `basic_blocks`, `bb_relations`, `bb_instructions`, `function_bblocks` stay **empty** |
| `exclude_library_thunk=True` | `should_skip_function` 3127-3134 | FUNC_LIB / FUNC_THUNK / `nullsub_*` functions are not exported at all |
| `ida_subs` (default `EXPORTING_ONLY_NON_IDA_SUBS=True`. The name is inverted: True means `sub_*` **are** exported, `diaphora_ida.py:776, 799, 3809`) | `should_skip_function` 3112-3125 | When False: `sub_*`, `j_*`, `unknown*`, `nullsub_*` and FUNC_LIB functions are not exported |
| Microcode gate in `save_function_to_database` | `diaphora.py:914-918` | Microcode rows for a function are written only when `len(microcode_bblocks) > 0 and len(microcode_bbrelations) > 0`. A function whose non-stop microcode blocks have no successors at all gets **no** microcode rows |
| `EXPORTING_COMPILATION_UNITS=True` | 1277-1278 | Without it, `compilation_units*` are empty and `source_file` is NULL everywhere |

---

## 3. `get_valid_prop`: the ">0xFFFFFFFF" rule (`diaphora.py:719-728`)

[SRC]
```python
  def get_valid_prop(self, prop):
    """
    Get a valid property to insert into the SQLite database.
    This is a hack for 64 bit architectures kernels.
    """
    if isinstance(prop, int) and (prop > 0xFFFFFFFF or prop < -0xFFFFFFFF):
      prop = str(prop)
    elif isinstance(prop, bytes):
      prop = prop.encode("utf-8")
    return prop
```

**Porting spec.** This is only needed to reproduce the stored data; the loader never runs it.

```
valid(p):
  if p is int and (p > 0xFFFFFFFF or p < -0xFFFFFFFF): return decimal_string(p)   # same text Python str() gives
  if p is bytes: raise AttributeError                                             # 'bytes' object has no attribute 'encode'  [EMP]
  return p
```

**Effect by destination affinity** [EMP]:

| Destination | Value passed | Stored |
|---|---|---|
| TEXT column | int ≤ 0xFFFFFFFF (bound as INTEGER) | TEXT (affinity) |
| TEXT column | int > 0xFFFFFFFF (bound as str) | TEXT; same digits as the SQLite rendering |
| INTEGER column | str of an int ≤ 2^63-1 | INTEGER (affinity converts it back) |
| INTEGER column | str of an int ≥ 2^63 | **REAL** (lossy). No real export has one: `function_flags = BADADDR` cannot be reached (see Summary), and every INTEGER column in the 7 real exports is INTEGER [REAL] |
| any | `bytes` | **exception**. The exporter crashes, so no functions-row prop is ever `bytes` |

- **Inputs:** each of the first 48 props (`diaphora.py:933`) and the microcode addresses (`diaphora.py:840, 851`).
- **Outputs:** the value handed to `cursor.execute`.
- **Runs by default?** Export side only. The native diff never runs it.

---

## 4. `save_function`: the `functions` row, `callgraph`, `constants` (`diaphora.py:920-1004`)

[SRC] Phase 1:
```python
      # The last 6 fields are callers, callees, basic_blocks_data & bb_relations
      for prop in props[: len(props) - 6]:
        prop = self.get_valid_prop(prop)

        if isinstance(prop, (list, set)):
          new_props.append(
            json.dumps(list(prop), ensure_ascii=False, cls=CBytesEncoder)
          )
        else:
          new_props.append(prop)
```
Then the insert of 48 columns (`diaphora.py:943-958`) runs, and `func_id = cur.lastrowid` (969). Line 971 then records `self._funcs_cache[props[12]] = [func_id, props[11], props[19]]`, keyed by the absolute EA (int). That cache is the **only** input to CU membership and to the CU `primes_value`/`pseudocode_primes`/`functions` values (`diaphora_ida.py:3318-3330, 3374-3382`; §7.6).

**The props-to-column mapping** was checked mechanically. The `insert` column list zips 1:1 with `FUNCTION_FIELDS[0:48]` (`diaphora.py:358-372`), and the last 6 fields (`microcode_bblocks, microcode_bbrelations, callers, callees, basic_blocks_data, bb_relations`) are not columns [EMP]. Note two renames that are easy to miss: props index 12 (`f`) → `address`, and props index 14 (`true_name`) → `mangled_function`.

**JSON encoding rule:** `json.dumps(list(x), ensure_ascii=False, cls=CBytesEncoder)`. That gives Python's default separators `", "` / `": "`, no spaces inside brackets, non-ASCII written as raw UTF-8, and `"`, `\` and control chars escaped. `CBytesEncoder` (`diaphora.py:316-324`) decodes a nested `bytes` as UTF-8. A `tuple` is **not** re-encoded by `save_function` (it only checks `list`/`set`). The one tuple-derived column, `tarjan_topological_sort`, is JSON-dumped earlier in the IDA code. [EMP] examples: `'["push", "mov", "call"]'`, `'[[5, [0, 1, 2, 4]]]'`, `'[305419896, "Hello, world", 20015998343868, "abc", 305419896, 18446744073709490740]'`.

Phase 2, `callgraph` (`diaphora.py:974-982`) [SRC]:
```python
      callers, callees = props[len(props) - 4:len(props) - 2]
      sql = "insert into callgraph (func_id, address, type) values (?, ?, ?)"
      insert_args = []
      for caller in callers:
        insert_args.append([func_id, str(caller), "caller"])

      for callee in callees:
        insert_args.append([func_id, str(callee), "callee"])
```

Phase 3, `constants` (`diaphora.py:985-998`) [SRC]:
```python
      props_dict = self.create_function_dictionary(props)
      for constant in props_dict["constants"]:
        should_add = False
        if type(constant) in [str, bytes] and len(constant) > 4:
          should_add = True
        elif type(constant) in [int, float, decimal.Decimal]:
          should_add = True
          constant = str(constant)

        if should_add:
          insert_args.append([func_id, constant])
```

Phase 4 (`diaphora.py:1001-1002`): `if not self.function_summaries_only: self.save_function_to_database(props, cur, func_id)` (§7.8-7.12).

`save_function_to_database` (`diaphora.py:900-918`) [SRC]:
```python
    total_props = len(props)
    # The last 2 fields are basic_blocks_data & bb_relations for native assembly
    bb_data, bb_relations = props[total_props - 2:]
    cur_execute, instructions_ids = self.save_instructions_to_database(
      cur, bb_data, func_id
    )
    self.insert_basic_blocks_to_database(
      bb_data, cur_execute, cur, instructions_ids, bb_relations, func_id
    )

    microcode_bblocks, microcode_bbrelations = props[total_props - 6:total_props - 4]
    if len(microcode_bblocks) > 0 and len(microcode_bbrelations) > 0:
      self.save_microcode_instructions(
        func_id, cur, cur_execute, microcode_bblocks, microcode_bbrelations
      )
```
The native rows for one function always come before its microcode rows, so ids interleave per function: native instructions, native blocks and relations, then microcode. Microcode rows are skipped when **either** dict is empty. `get_microcode_bblocks` (`diaphora_ida.py:2249-2259`) creates a relations entry only for blocks that have a successor; a successor may be the stop block.

`create_function_dictionary` (`diaphora.py:895-898`) is `dict(zip(self.FUNCTION_FIELDS, props))`. It sees the **original** props, not `new_props`, so `constants` here is the Python list and not the JSON text. `get_function_from_dictionary` (890-893) is its inverse and is used only by the `after_export_function` hook (`diaphora_ida.py:3099-3107`), which no script sets by default.

- **Inputs:** the 54-tuple from `build_props_list` (`diaphora_ida.py:3138-3197`).
- **Outputs:** 1 `functions` row, N `callgraph` rows, M `constants` rows, plus side tables.
- **Runs by default?** Export side only.

---

## 5. `functions` table, column by column

### 5.1 Encoding table

The "Stored as" column is [EMP] (Appendix A output). The props index is the position in `build_props_list` (`diaphora_ida.py:3141-3196`).

| # | Column (decl → affinity) | Exporter value (source) | Stored as | NULL / empty when | Format |
|---|---|---|---|---|---|
| – | `id` integer PK | rowid | INTEGER | never | 1..N in export order |
| 0 | `name` varchar(255) → TEXT | `demangled or true_name` (`get_function_names` 2448-2453), where `demangled = demangle_name(true_name, INF_SHORT_DN) or None` | TEXT | never NULL | The mask is the *index constant* `INF_SHORT_DN = INF_SHORT_DEMNAMES = 36` ([IDA] 9.4 `idc.py:2119-2120`), not `get_inf_attr(INF_SHORT_DN)` as `idc.demangle_name` recommends (`idc.py:1684-1696`). With `DQT_FULL` the result is the **full demangled signature**, for example `public: static long _tlgWriteTemplate<…>::Write<>(struct _tlgProvider_t const *,…)` [REAL sechost]. Overloads therefore get **different** names (0 duplicate names across the 7 real exports), but the schema does not enforce uniqueness |
| 1 | `nodes` integer | blocks processed (`accum['nodes'] += 1`, 2818) | INTEGER | never | ≥0 |
| 2 | `edges` integer | +1 per succ (2897) **and** +1 per pred (2916) | INTEGER | never | ≈ 2× CFG edges |
| 3 | `indegree` integer | `len(list(CodeRefsTo(f, 1)))` (3072) + 1 per succ edge (2898) | INTEGER | never | as written, not the textbook meaning |
| 4 | `outdegree` integer | Σ `len(CodeRefsFrom(head,0))` (2737, 2851) + 1 per pred edge (2917) | INTEGER | never | |
| 5 | `size` integer | Σ `get_item_size(head)` (2709, 2845) | INTEGER | never | |
| 6 | `instructions` integer | count of heads whose bytes read OK (2846) | INTEGER | never | |
| 7 | `mnemonics` text | list of `print_insn_mnem` in block order (2852) → JSON | TEXT | `'[]'` | JSON list of str |
| 8 | `names` text | **sorted** list (3010-3011) of referenced non-`sub_`/`nullsub_` names (2744-2759) → JSON | TEXT | `'[]'` | JSON list of str |
| 9 | `prototype` text | `guess_type(ea)` or first decompiled line (2352-2363, 2340-2346) | TEXT / **NULL** | `idc_guess_type` fails and there is no decompilation ([IDA] `ida_typeinf.py:8709` → `Union[str, None]`; `idc.guess_type`, `idc.py:5653-5661`, wraps it). [REAL]: in the decompiler-on exports it is NULL exactly where `pseudocode` is NULL (ls 113/113). In the headless `ls` export it is NULL on 123/318 | C prototype |
| 10 | `cyclomatic_complexity` integer | `edges - nodes + 2` (2966) with the doubled `edges` | INTEGER | never | can be negative |
| 11 | `primes_value` text | `str(self.primes[cc])` or int `0` on exception (2969-2973) | TEXT | `'0'` when `cc` ≥ 295,947 (IndexError). A negative `cc` indexes **from the end** of `primesbelow(2048*2048)` (`diaphora.py:376`) | decimal |
| 12 | `address` text UNIQUE | `f = int(ea)`, **absolute** EA (3207) | TEXT | never | canonical decimal (`'5368713216'`, `'4198400'`) |
| 13 | `comment` text | `idc.get_func_cmt(f, 1)` (2976) | TEXT | **`''`, not NULL**, when there is no comment ([IDA] 9.4 `idc.py:3275-3283` returns `""`) | free text |
| 14 | `mangled_function` text | `true_name = get_func_name(int(f))` (2451) | TEXT | never NULL ([IDA] `idc.py:3258-3262` returns `""` at worst) | raw IDA name |
| 15 | `bytes_hash` text | `md5(b"".join(bytes_hash)).hexdigest()` (2977) | TEXT | never | 32 lowercase hex |
| 16 | `pseudocode` text | `"\n".join(self.pseudo[f])` (2548); excludes `//` lines and the first (prototype) line (2338-2346) | TEXT / NULL | NULL when not decompiled. **`''`** when the decompiled body has only the prototype line | lines joined by `\n` |
| 17 | `pseudocode_lines` integer | `len(self.pseudo[f])`, else `0` (2545, 2549) | INTEGER | never NULL | |
| 18 | `pseudocode_hash1` text | `kfh.hash_bytes(pseudo).split(";")[0]`, `''`→None (2550-2554) | TEXT / NULL | NULL when there is no pseudo or the hash part is empty. With `kfh.bsize = 512` (`diaphora.py:392`) it is **usually NULL**: [REAL] ls 309/318 NULL, although 205 functions have pseudocode | base64, `=` stripped (`kfuzzy.py:166`); the parts are joined and decoded at `kfuzzy.py:290` |
| 19 | `pseudocode_primes` text | `str(self.pseudo_hash[f])` = AST prime product (2559, 3955-3975) | TEXT / NULL | NULL when not decompiled | decimal bignum |
| 20 | `function_flags` integer | `get_func_attr(f, FUNCATTR_FLAGS)` (2981) | INTEGER (all 7 real exports [REAL]). REAL only in the synthetic BADADDR probe [EMP] `1.844674407370955162e+19` | [IDA] `idc.py:3121` "BADADDR - error", but that path needs `get_func(f)` to be None, which `read_function` 3208-3211 already excludes | flags bit mask |
| 21 | `assembly` text | `"\n".join(asm)`, entry block first, then sorted block keys, with `loc_%x:` label lines (2569-2594, 2717-2726) | TEXT | `''` when there are no instructions | lines joined by `\n` |
| 22 | `prototype2` text | `idc.get_type(f)` (2968), read **after** `self.guess_type(f)` (2967) may have decompiled `f` | TEXT / NULL | NULL when there is no type ([IDA] `idc.py:5586-5594`). This depends on the export path: [REAL] `ls` is 21 NULL with the decompiler on and 178 NULL headless | |
| 23 | `pseudocode_hash2` text | as #18, part 2 | TEXT / NULL | | |
| 24 | `pseudocode_hash3` text | as #18, part 3 | TEXT / NULL | | |
| 25 | `strongly_connected` integer | `len(strongly_connected)` (3167) | INTEGER | `0` on RecursionError (2624) | |
| 26 | `loops` integer | SCC count with len>1, plus self-loop singletons (2630-2636) | INTEGER | | |
| 27 | `rva` text UNIQUE | `f - get_base_address()` (3007) | TEXT | never | decimal |
| 28 | `tarjan_topological_sort` text | `json.dumps(robust_topological_sort(bb_topological))` (2614-2615) | TEXT / NULL | NULL on RecursionError (2625) | JSON list of lists of ints, e.g. `'[[0], [2, 1], [3]]'` |
| 29 | `strongly_connected_spp` text | Π `primes[len(scc)]` over SCCs with len>1 (2616-2620); init `0` (2610) | TEXT | `'1'` with no multi-node SCC; `'0'` on RecursionError | decimal bignum |
| 30 | `clean_assembly` text | `get_cmp_asm_lines(asm)`, `''` on exception (2959-2963) | TEXT | `''` | |
| 31 | `clean_pseudo` text | `get_cmp_pseudo_lines(pseudo)` (2995; None→None at `diaphora.py:1053-1054`) | TEXT / NULL | NULL when `pseudocode` is NULL | |
| 32 | `mnemonics_spp` text | Π `primes[cpu_ins_list.index(mnem)]` (2712-2714, 2847) | TEXT | `'1'` when no mnemonic is in the list | decimal bignum |
| 33 | `switches` text | list of `[jtable_size, list(set(case_ids))]` (2486-2509) → JSON | TEXT | `'[]'` | inner order = CPython `set` iteration order |
| 34 | `function_hash` text | `md5(b"".join(get_bytes(head, item_size)))` (2736, 2978) | TEXT | never | 32 hex |
| 35 | `bytes_sum` integer | Σ bytes (2735, 2849) | INTEGER | | |
| 36 | `md_index` text | `str(Decimal Σ 1/√emb)` (2511-2538). The int `0` is returned only when `bb_topological` is falsy, which in practice means the RecursionError path (None, 2625). A function with no edges gives `str(sum(()))` = the **str** `'0'` | TEXT | **`'0'`**, never NULL ([REAL] 111-192 `'0'` rows per export) | 28 sig. digits, e.g. `'0.7298566584517582854275250342'`; no exponent form in the 7 real exports |
| 37 | `constants` text | list: ints (dup **kept**) and strings (deduped) in extraction order (2467-2484) → JSON | TEXT | `'[]'` | JSON list of int\|str; ints up to 2^64-1 |
| 38 | `constants_count` integer | `len(data['constants'])`, duplicates included (3180) | INTEGER | | |
| 39 | `segment_rva` text | `current_head - get_segm_start(current_head)`, where `current_head` is the **last head of the last processed FlowChart block** (3004, 3223-3229). Blocks with `end_ea` 0/BADADDR are skipped. If that last block has no heads, `current_head` stays `BADADDR` (2826) | TEXT | | decimal |
| 40 | `assembly_addrs` text | RVA per `assembly` line, label lines included, so duplicates occur (2591) → JSON | TEXT | `'[]'` | |
| 41 | `kgh_hash` text | `CKoretKaramitasHash().calculate(f)` = `str(hash)` (180), or `"NO-FUNCTION"` (103) / `"NO-FLOW-GRAPH"` (107). **The sentinels cannot be reached from the exporter**: `get_func(f)` is non-None (`read_function` 3208-3211), and `FlowChart(func)` is a constructor call that never returns None | TEXT | never NULL, never `''`, never `'0'`. [REAL] 0 non-digit values in 7 exports; the longest is 20,699 digits (sechost) | decimal bignum |
| 42 | `source_file` text | `None` at insert (3184); later `update … set source_file = module_name` (3356, 3382) | NULL / TEXT | NULL outside any CU **and** for anonymous CUs (module name `""` → `None`, 3366-3368) | CU name |
| 43 | `userdata` text | `None` (3185) | NULL | always NULL by default | |
| 44 | `microcode` text | `"\n".join(self.microcode[f])` (2663) | TEXT / NULL | NULL when not exported, when not decompiled, or in any headless export without `DIAPHORA_USE_DECOMPILER` (§2). **`''`** when `self.microcode[f]==[]`: the decompilation succeeded (`decompile_and_get` sets `[]` at 2348) but `gen_microcode` returned None (2272-2273), or no line had more than 2 tokens (2287-2290). [REAL] no `''` in the 7 exports | |
| 45 | `clean_microcode` text | `get_cmp_asm_lines(...)` (2687) | TEXT / NULL | as #44 | |
| 46 | `microcode_spp` text | Π over microcode mnemonics, init `1` (2659, 2682) | TEXT | `'1'` | decimal bignum |
| 47 | `export_time` **real** | `str(time.monotonic() - t0)` (3014-3015) | **REAL** | | seconds |

[EMP] confirmed that every TEXT column above holds only TEXT or NULL, and every INTEGER column only INTEGER, **except** `function_flags` (INTEGER/REAL, in the synthetic BADADDR probe only). No column holds a BLOB. [REAL] `typeof()` over every column of `ls.sqlite` and `sechost-9168-pdb.sqlite` gives the same result, with `function_flags` INTEGER on every row. `comment` is `''` on all 318/1442 rows, `userdata` is NULL everywhere, `export_time` is REAL everywhere, and `tarjan_topological_sort` is never NULL. Outside `functions`, the only BLOBs are `program.md5sum` and `program_data.name` for `til` rows.

### 5.2 Column notes that matter to consumers

- **`address` / `rva` / `segment_rva`.** These are always canonical decimal TEXT. Python consumers use the string itself as the match-item `ea` (`diaphora.py:1436, 1910, 2067, 3115, 3299`). They call `int(ea)` only for sorting (3345), for re-querying (`str(int(...))`, 2763-2777) and for hex formatting (`"0x%x" % int(ea)`, 1935; chooser `"%08x"`, 280-288). SQL compares them with memcmp, which gives equality and **lexicographic ranges**. For numeric users, parse to uint64: all values are < 2^64. Negative values are impossible in practice (`rva` would be negative only when `f < imagebase`).
- **`md_index`.** Stored as TEXT. SQL compares it as text: `=` (H17, H20, H23, H24), `!= 0` (H20 CTE: excludes `'0'`), `> 0` (H23: true for every non-`'0'` value), `> 1` (brute force, not default). The SQL heuristic row carries `cast(f.md_index as real) md1` (`diaphora_heuristics.py:57`). `compare_function_rows` passes the raw TEXT (`diaphora.py:2498`), and `check_ratio` does `float(md1)` (1672-1673). Load **both** doubles (Hard part H-3).
- **`kgh_hash`.** `kgh_hash != 0` (H19 CTE) is `kgh_hash != '0'` [EMP: `'NO-FLOW-GRAPH' != 0` → 1]. It also drops NULL rows, because `NULL != '0'` is NULL. Diaphora never writes NULL, `''` or `'0'` here, so the filter removes nothing from real exports ([REAL] 0 such rows in 7 exports). If a sentinel `NO-FUNCTION` / `NO-FLOW-GRAPH` were present, it would be an ordinary equal-joinable value in H16, H17 and H19, but the exporter cannot produce one (§5.1 #41). The maintainer notes (not published) said, verbatim: "`kgh_hash != 0` does nothing in SQLite (TEXT compared with INTEGER). We implement what it was meant to do: skip `""` and `"0"`." The outcome ("does nothing" on real data) is right, but the mechanism is wrong: it is a text comparison with `'0'`. The native rule (`src/Heuristics.cpp:212`, `Key.empty() || Key == "0"`) agrees on Diaphora data but not in general, since Diaphora would keep `''`.
- **`microcode_spp != 1`** (H12) is a text compare with `'1'`, which is exact for a canonical decimal. **`strongly_connected_spp > 1`** (H44, not default) is text > `'1'`. For canonical non-negative decimals that equals numeric > 1.
- **`names`.** SQL compares the text: `=`, and `!= '[]'` (H24, H25, H27, H30, H31). `search_small_differences` does `set(json.loads(...))` (`diaphora.py:2119-2120`), which is a set of Python `str`.
- **`constants`.** SQL compares the text: `=`, `constants_count > 0/1` (H18, H23). `deep_ratio` parses **both** sides with `set(json.loads(...))` only if `main_row["constants"] != "[]"` (`diaphora.py:2812-2821`). The diff side is not checked for `'[]'` before it is parsed. In Python set semantics an int `305419896` and a str `"305419896"` are **different** elements. `find_related_constants` (3370-3390) re-binds each intersected element as `str(constant)` against `constants.constant`.
- **`switches`.** Compared as text (`=`, `!= '[]'`: H32, `deep_ratio` 2802-2805). It is never JSON-decoded at diff time.
- **`tarjan_topological_sort`, `strongly_connected_spp`.** Read only by Unreliable heuristics (H43, H44, H50) and by ML. Not read on the default path.
- **`source_file`.** Read by exactly **32** heuristics (H05-H10, H12, H14, H18, H20, H21, H23-H27, H32-H39, H42, H44-H50; 22 of them are on the default path), **only in `order by f.source_file = df.source_file`** (verified by scanning every `HEURISTICS` SQL: no WHERE use) (ascending: NULL, then 0, then 1, so same-CU pairs come **last**). It is also read by `deep_ratio` (`+0.001` when equal, non-NULL and non-`''`, 2780-2784) and by brute force (not default).
- **`name` vs `mangled_function`.** `matched_primary` / `matched_secondary` are keyed by `name` (`diaphora.py:1373-1374`), **except** `find_equal_matches`, which keys by `mangled_function` (`diaphora.py:1435-1440`). Neither column is unique, so the loader must not dedupe or index them as unique.
- **`pseudocode` / `assembly`.** Read as text by H11 (`=`, `is not null`) and H27 (`is not null`). Also read by `check_ratio` (`!= ""` checks, 1700-1705), by `find_one_match_diffing` (`.splitlines(keepends=False)`, 3040-3041; Python's Unicode line boundaries) and by the patch-diff hook (`split("\n")`, `scripts/patch_diff_vulns.py:137, 186`). `find_matches_diffing_internal` skips a pair when the field is NULL on either side (`diaphora.py:3176-3179`), but a `''` field goes through and yields no lines.
- **`clean_microcode`.** H07 compares it with `=`, so `''` = `''` pairs **match**. `check_ratio` tests `is not None` (1748), then `quick_ratio`, which returns 0 for `''` (`check_bufs`, 150-155). NULL and `''` behave differently, so the distinction must be kept.

---

## 6. Diff-time consumers of `functions` columns

### 6.1 SQL heuristics: generated map

Columns in `WHERE`/`ORDER BY`/CTEs, excluding the fixed `SELECT_FIELDS`. The `SELECT_FIELDS` list (`diaphora_heuristics.py:51-75`) reads `address, name, pseudocode, assembly, pseudocode_primes, nodes, cast(md_index as real), clean_assembly, clean_pseudo, mangled_function, clean_microcode, bytes_hash, edges, indegree, outdegree, instructions, cyclomatic_complexity, strongly_connected, loops, constants_count, size, kgh_hash` for **every** row of every heuristic.

| H | Name | Flags | Default? | Columns / side tables |
|---|---|---|---|---|
| 01 | Same RVA and hash | SAME_CPU | if same processor | rva, segment_rva, bytes_hash, instructions, name, nodes |
| 02 | Same order and hash | SAME_CPU | if same processor | **id**, bytes_hash, instructions, name, nodes |
| 03 | Function Hash | SAME_CPU | if same processor | function_hash, nodes, instructions |
| 04 | Bytes hash | SAME_CPU | if same processor | bytes_hash, instructions |
| 05 | Same address and mnemonics | – | yes | address, mnemonics, instructions, name, source_file |
| 06 | Same cleaned assembly | SAME_CPU | if same processor | clean_assembly, nodes, name, source_file |
| 07 | Same cleaned microcode | SAME_CPU | if same processor | clean_microcode, instructions, name, source_file |
| 08 | Same cleaned pseudo-code | – | yes | clean_pseudo, pseudocode_lines, name, source_file |
| 09 | Same address, nodes, edges and mnemonics | – | yes | rva, instructions, nodes, edges, mnemonics, source_file |
| 10 | Same RVA | SAME_CPU | if same processor | rva, name, nodes, source_file |
| 11 | Equal assembly or pseudo-code | – | yes | pseudocode, pseudocode_lines, assembly, instructions, name |
| 12 | Microcode mnemonics small primes product | – | yes | microcode_spp (`!= 1`), instructions, nodes, name, source_file |
| 13 | Same named compilation unit function match | – | yes | CU.name, CUF, id, primes_value, nodes |
| 14 | Same anonymous compilation unit function match | – | yes | CU.name, CUF, id, pseudocode_primes, nodes, source_file |
| 15 | Same compilation unit | SLOW | **yes** (standalone slow=True) | CU.pseudocode_primes, CUF, id, nodes, name |
| 16 | Same KOKA hash and constants | – | yes | **constants** table, id, kgh_hash, nodes |
| 17 | Same KOKA hash and MD-Index | – | yes | kgh_hash, md_index, nodes, outdegree, indegree, name |
| 18 | Same constants | – | yes | constants, constants_count, source_file |
| 19 | Same rare KOKA hash | – | yes | kgh_hash (`!= 0`), nodes, name |
| 20 | Same rare MD Index | – | yes | md_index (`!= 0`), nodes, source_file |
| 21 | Same address and rare constant | – | yes | **constants** table, id, address, source_file |
| 22 | Same rare constant | SLOW | **yes** | **constants** table, id, nodes, constants_count |
| 23 | Same MD Index and constants | – | yes | md_index (`> 0`), nodes, constants, constants_count, source_file |
| 24 | Import names hash | – | yes | names, md_index, instructions, nodes, source_file |
| 25 | Mnemonics and names | – | yes | mnemonics, instructions, names, source_file |
| 26 | Pseudo-code fuzzy hash | – | yes | pseudocode_hash1/2/3 (`is not null`), instructions, source_file |
| 27 | Similar pseudo-code and names | – | yes | pseudocode_lines, names, pseudocode (`is not null`), source_file |
| 28 | Mnemonics small-primes-product | – | yes | mnemonics_spp, instructions, nodes |
| 29 | Same nodes, edges, loops and SCC | – | yes | nodes, edges, strongly_connected, loops, name |
| 30 | Same low complexity, prototype and names | – | yes | names, cyclomatic_complexity, **prototype2** |
| 31 | Same low complexity and names | – | yes | names, cyclomatic_complexity, name |
| 32 | Switch structures | – | yes | switches, nodes, source_file |
| 33 | Pseudo-code fuzzy (normal) | – | yes | pseudocode_hash1, pseudocode_lines, source_file |
| 34 | Pseudo-code fuzzy (mixed) | – | yes | pseudocode_hash3, pseudocode_lines, source_file |
| 35 | Pseudo-code fuzzy (reverse) | – | yes | pseudocode_hash2, pseudocode_lines, source_file |
| 36 | Pseudo-code fuzzy AST hash | – | yes | pseudocode_primes (`length() >= 35`), pseudocode_lines, source_file |
| 37-39 | Partial pseudo-code fuzzy hash (normal/reverse/mixed) | SLOW, UNRELIABLE | **no** (`unreliable=False`, `diaphora.py:1498-1500`) | `substr(pseudocode_hashN,1,16)`, nodes, source_file |
| 40 | Same rare assembly instruction | SAME_CPU | if same processor | **instructions** (func_id, disasm), id, name, nodes |
| 41 | Same rare basic block mnemonics list | – | yes | **bb_instructions**, **instructions** (id, func_id, mnemonic), id, nodes |
| 42 | Loop count | SLOW | **yes** | loops, nodes, source_file |
| 43-50 | Unreliable category | various | **no** (`diaphora.py:3638-3641`) | adds tarjan_topological_sort, strongly_connected_spp, prototype2 (`!= 'int()'`), size, primes_value … |

### 6.2 Python consumers (default path)

| Reader | Source | Columns / tables and the encoding it assumes | Default? |
|---|---|---|---|
| version check | `diaphora.py:3578-3591` | `diff.version.value`; a missing table or row makes `diff()` return False. `!= "3.4"` only warns | yes |
| `equal_db` | 661-687 | `program.md5sum` (BLOB=BLOB); `functions(id,address,size,nodes,edges)` EXCEPT | yes; **log-only** (3600-3601) |
| `get_callgraph_difference` | 1288-1324 | `program.callgraph_primes` → `decimal.Decimal()`, `callgraph_all_primes` → `json.loads()`; raises unless **exactly 2 rows** (main+diff). When the two Decimals compare equal it returns 0 before using the JSON values. Otherwise both JSON values go into `FACTORS_CACHE` and are used as dicts (`.values()`, `.keys()`, `jkutils/factor.py:203-242`), so they must be JSON objects with numeric values | yes; the value is log-only (`self.percent`/`equal_callgraph` are never read again, verified by grep), but a parse error or a wrong row count **aborts the diff**, because `diff()` has `try/finally` with no `except` (3593-3700) |
| `find_equal_matches` | 1404-1442 | `count(*)` both; `INTERSECT` of `(id, address, mangled_function, nodes, edges, size, bytes_hash)` (typed equality, NULL≡NULL in set ops) | yes |
| `same_processor_both_databases` | 2950-2967 | `mp.processor = dp.processor` (TEXT, NULL never equal) | yes, and it gates SAME_CPU heuristics, assembly diffing and `deep_ratio`'s constant bonus |
| `search_just_stripped_binaries` | 2540-2585 | `f.address = df.address` | yes (`experimental=True`) |
| `search_patchdiff_with_symbols` | 2587-2627 | `f.mangled_function = df.mangled_function` | yes |
| `find_same_name` | 2152-2210 | `df.mangled_function = f.mangled_function or df.name = f.name`; `row["mangled1"].startswith("sub_")` | yes |
| `check_match` → `check_ratio` | 1786-1872, 1645-1775 | `SELECT_FIELDS`: pseudo/clean_pseudo (None vs `""`), clean_assembly, clean_micro (None check), bytes_hash (`==`), md1/md2 (SQLite REAL) | yes |
| `deep_ratio` | 2749-2837 | `select * … where address = ?` with `str(int(ea))`; source_file, pseudocode_primes, indegree, outdegree, switches, cyclomatic_complexity, constants (JSON) | yes, whenever r < 1.0 |
| `search_small_differences` | 2085-2150 | nodes, edges, mnemonics, cyclomatic_complexity, names (`!= '[]'`, JSON→set) | yes (slow) |
| `find_matches_diffing_*` | 3150-3229, 3033-3131 | `get_function_row` (`select * where name = ?`, `fetchone()` with no ORDER BY, 2445-2460); a NULL field skips the pair (3176-3179); `assembly`/`pseudocode` `.splitlines()`; `functions_exists` (`UNION` by name, `order by db_name desc`, needs exactly 2 rows, 2969-2991); `nodes` | yes (assembly only when same CPU) |
| `compare_function_rows` | 2479-2538 | address, name, pseudocode, assembly, pseudocode_primes, nodes, **md_index raw TEXT → `float()`**, clean_*, bytes_hash, edges, indegree, outdegree, instructions, cc, strongly_connected, loops, constants_count, size, kgh_hash | yes |
| `find_related_matches` / `find_related_constants` | 3462-3494, 3362-3393 | `constants_count > 0` both; constants JSON → set; `constants` table with `mc.constant = ?` **and `abs(mc.constant) == 0`** | yes (slow, 3662-3664) |
| `find_related_compilation_unit` | 3395-3460 | CU `id, name, start_ea, end_ea` via CUF + `f.name = ?`; `float(start_ea)`; `cast(f.address as real) between ? and ?` | yes (every iteration, 3666) |
| `find_locally_affine_functions` / `find_functions_between` | 3315-3360, 3231-3313 | `select * where address > ? and address < ? order by address desc` with **str params → lexicographic**; name, pseudocode_lines (`+`, `== 3`) | yes |
| `find_unmatched` | 2323-2356 | name, address | yes |
| `get_unmatched_functions` / `search_remaining_functions` | 2639-2700 | name, address; `f.address = ?`, `nodes >= 3` | `find_remaining_functions` (2702-2716) runs whenever dirty mode fired (3626-3627), so `get_unmatched_functions` also runs in stripped-binary mode, where its result is discarded. `search_remaining_functions` runs only in patch-diff mode (`is_patch_diff`, 2708) |
| patch-diff hook `on_match` | `scripts/patch_diff_vulns.py:204-236` | `asm` (= `assembly`), `pseudo`, name, ea, nodes; returns `ratio` unchanged | only when `is_patch_diff`; **no effect on results** |
| `get_model_ratio` / ML | 3496-3549, `ml/basic_engine.py:100-150` | adds primes_value, strongly_connected_spp, source_file…, and **branches on Python type** (`int` vs `str`) | no (`classifier=None`) |
| `find_brute_force` | 2223-2305 | temp table; `md_index > 1`, `kgh_hash > 7` (text) | no (unreliable) |

### 6.3 Coverage summary (computed from §6.1 and §6.2)

- **Read on the default path (39).** id, name, address, nodes, edges, indegree, outdegree, size, instructions, mnemonics, names, cyclomatic_complexity, primes_value, mangled_function, bytes_hash, pseudocode, pseudocode_lines, pseudocode_hash1, pseudocode_primes, assembly, prototype2, pseudocode_hash2, pseudocode_hash3, strongly_connected, loops, rva, clean_assembly, clean_pseudo, mnemonics_spp, switches, function_hash, md_index, constants, constants_count, segment_rva, kgh_hash, source_file, clean_microcode, microcode_spp.
- **Read only off the default path (2).** tarjan_topological_sort, strongly_connected_spp.
- **Never read at diff time (8).** prototype, comment, function_flags, bytes_sum, assembly_addrs, userdata, microcode, export_time. `select *` fetches them, but no consumer uses them. The one exception is the relaxed or ML path, which is not default.

---

## 7. Side tables

### 7.1 `program` (`schema.py:119-125`)

Writer `save_callgraph` (`diaphora_ida.py:3398-3407`) [SRC]:
```python
      sql = "insert into main.program (callgraph_primes, callgraph_all_primes, processor, md5sum) values (?, ?, ?, ?)"
      proc = idaapi.get_idp_name()
      if BADADDR == 0xFFFFFFFFFFFFFFFF:
        proc += "64"
      cur.execute(sql, (primes, all_primes, proc, md5sum))
```

| Column | Value | Stored [EMP] | Notes |
|---|---|---|---|
| `id` | rowid | INTEGER | exactly **1 row** per export |
| `callgraph_primes` | `str(1 * Decimal(p1) * Decimal(p2) …)` (1195, 1252); 28-digit Decimal context | TEXT, e.g. `'2.613476489367353310691717225E+399'`; `'1'` when no function. A `'0'` prime zeroes it, rendered `'0'` or with an exponent such as `'0E+560'` [EMP] | parse as a Python-`Decimal` literal (exponent form) |
| `callgraph_all_primes` | `json.dumps({primes_value: count})` (1253-1256); keys are str digits (an int `0` becomes key `"0"`) | TEXT, e.g. `'{"13": 2, "0": 1, "7": 1}'` | a JSON object |
| `processor` | `get_idp_name()` (+`"64"` iff BADADDR is 64-bit) | TEXT. [REAL] `'pc64'` in all 7 exports and in the headless export. `get_idp_name()` returns the processor *module* name `'pc'`, not `'metapc'` ([BIN] idalib 9.4 on 32-bit and 64-bit PEs; [IDA] docstring `ida_idp.py:2113`). The doc's earlier example `'metapc64'` was wrong | [IDA] 9.4 `get_idp_name() -> Union[str, None]` (`ida_idp.py:2112`). A None would already raise `TypeError` at `proc += "64"`, so NULL cannot be stored under IDA 9.x |
| `md5sum` (declared `text`, `schema.py:124`) | `GetInputFileMD5()` = `ida_nalt.retrieve_input_file_md5` ([IDA] `idautils.py:435`; 9.2 `ida_nalt.py:1977` `-> bytes`; 9.4 `ida_nalt.py:2008` `-> Union[bytes, None]`) | **BLOB (16 raw bytes)** [EMP bind test][REAL all 7 exports][BIN idalib 9.4: `bytes`, len 16]. NULL if 9.4 returns None | compared only by `equal_db` (log-only) |

- **Diff-time readers.** `equal_db` reads `md5sum`. `get_callgraph_difference` reads both primes columns and requires them to parse; the `Decimal` and `json` results feed only logs and `FACTORS_CACHE`. `same_processor_both_databases` reads `processor`.
- **Runs by default?** Yes, all three, on every diff (`diaphora.py:3600, 3605, 3617`).
- **Porting spec.** Load all 4 columns with their type tags. Fail the diff the same way Diaphora does in any of these cases (Diaphora raises and produces no results file):
  - `count(main.program)+count(diff.program) != 2`;
  - either `callgraph_primes` is not a valid Decimal literal, or either `callgraph_all_primes` is not valid JSON;
  - the two Decimals differ numerically and either JSON value is not an object with numeric values.

  Otherwise only `processor` affects matching. It is a TEXT equality, and NULL never matches.

### 7.2 `version` (`schema.py:132`)

Writer: `create_schema` (`diaphora.py:626-630`) inserts `VERSION_VALUE = "3.4"` (`diaphora.py:100`) when the table is empty. It runs at construction of **every** `CBinDiff` on the main thread (`open_db`, 571-581), including the standalone diff's db1.

- **Stored as:** TEXT `'3.4'` [EMP].
- **Read by:** `diff()` (`diaphora.py:3578-3591`), on `diff.version` only. A missing table or empty table makes `diff()` return False. A mismatch only logs.
- **Runs by default?** Yes.
- **Side effect to know about.** The standalone reference run **can write to db1**. `create_schema` runs `create table if not exists` for every table; a table that is missing gets created, and Python's sqlite3 autocommits DDL. It also inserts the version row when missing and then commits (`diaphora.py:626-630`; the `commit` is inside `if not row`). On a complete Diaphora export both are no-ops, so no page of db1 changes. Opening the file still creates or touches the WAL `-wal`/`-shm` sidecars. Parity harnesses should still diff copies, or hash before and after, as `tools/oracle/build_oracle.py` does.

### 7.3 `program_data` (`schema.py:126-131`)

Writers: `add_program_data(type, key, value)` (`diaphora.py:689-699`), called by `export_structures` (`diaphora_ida.py:3429-3462`: type `struct`/`enum`/`union`, value = C definition) and by `export_til` (3486-3490: type `til`, **name = `bytes`** → BLOB [EMP], value NULL).

- **Read at diff time:** never. It is read only by IDA-side `import_til`/`import_definitions` (`diaphora_ida.py:1335, 1357`).
- **Runs by default?** No (diff). The loader may skip it.

### 7.4 `constants` (`schema.py:170-173`)

Writer: `save_function` phase 3 (§4).

| Column | Stored [EMP] | Semantics |
|---|---|---|
| `id` | INTEGER | insertion order |
| `func_id` | INTEGER | `functions.id` |
| `constant` | TEXT | `str(int)` for ints (values ≥ 0x1000 that pass `constant_filter`, `diaphora_ida.py:2412-2434`, up to 2^64-1); the raw string for str constants **only when `len > 4`** (`diaphora.py:990`). **Duplicate ints are kept** (the list is not deduped for ints, `diaphora_ida.py:2469-2474`) |

- **Diff-time readers:** H16 and H21 (default), H22 (SLOW, standalone default), `find_related_constants` (slow).
- **`abs(mc.constant) == 0`** (`diaphora.py:3387`) is true only for strings whose leading numeric prefix is 0 or absent [EMP]: `'Hello, world'` → true, `'305419896'` → false. In practice `find_related_constants` produces rows **only for non-numeric string constants**.
- **Multiplicity.** The join `mc.constant = dc.constant` in **H16 and H22** (plain `select`) emits one row per duplicate pair. That counts against `SQL_MAX_PROCESSED_ROWS = 1000000` (`diaphora.py:1874-1880`) and changes the order in which `add_matches_internal` sees pairs. **H21 is `select distinct`** (`diaphora_heuristics.py`, "Same address and rare constant"). Its output columns are `SELECT_FIELDS` only, so duplicate constant pairs collapse into one row per `(f, df)`. [REAL] duplicate `(func_id, constant)` pairs exist in every export (28-341 per export).
- **Runs by default?** Yes.
- **Porting spec.** Load `(id, func_id, constant_text, abs_is_zero)` ordered by id. Compute `abs_is_zero` with SQLite itself: `select id, func_id, constant, abs(constant) = 0 from constants order by id`. That reproduces the numeric-prefix rule without re-implementing `sqlite3AtoF`. Keep duplicates.

### 7.5 `callgraph` (`schema.py:165-169`)

Writer: `save_function` phase 2 (§4). `address` is `str(ea)` of the **absolute** caller or callee function start. Callers include data references to the function (`diaphora_ida.py:2455-2465`); callees are code references to other functions' starts (2761-2767, 2857-2859). `type` is `'caller'`/`'callee'`.

- **Stored:** INTEGER / INTEGER / TEXT / TEXT [EMP].
- **Read at diff time:** never. `get_callers_callees` (`diaphora.py:3557-3566`) has **no caller** (grep). Default?: No.

### 7.6 `compilation_units` (`schema.py:174-181`) and `compilation_unit_functions` (182-185)

Writer `save_compilation_units` (`diaphora_ida.py:3339-3396`) [SRC excerpt]:
```python
        module_name = None
        if module["name"] != "":
          module_name = module["name"]

        vals = (module["name"], str(module["start"]), str(module["end"]))
        cur.execute(sql1, vals)
...
            if func_id not in dones:
              dones.add(func_id)
              cur.execute(sql2, (cu_id, func_id))
              cur.execute(sql4, (module_name, func_id))

        cur.execute(
          sql3,
          [module["primes"], module["pseudo_primes"], module["total"], cu_id],
        )
```
`module["primes"]`, `["pseudo_primes"]` and `["total"]` are `str(...)` (3332-3335). `primes` = Π `int(primes_value)`, `pseudo_primes` = Π `int(pseudocode_primes)` over member functions, skipping NULL (3322-3330). Both start at 1.

| Column | Stored [EMP] | Notes |
|---|---|---|
| `id` | INTEGER | |
| `name` | TEXT | **`''` for anonymous CUs** (never NULL) |
| `functions` (`int`) | INTEGER (bound as str; converted by INTEGER affinity) | not read at diff |
| `primes_value` | TEXT decimal | not read at diff (H13 uses `functions.primes_value`) |
| `pseudocode_primes` | TEXT decimal; **`'1'`** when no member has pseudocode | H15 joins on it (all "no pseudocode" CUs match each other). [REAL] 0-26 `'1'` CUs per decompiler-on export (sechost-9168: 26 of 67). In the headless `ls` export **all 11 CUs are `'1'`**, so H15 compares every CU pair there |
| `start_ea`, `end_ea` | TEXT decimal **absolute** EAs; `start_ea` UNIQUE | `float()` in `find_related_compilation_unit` |

`compilation_unit_functions`: `(id, cu_id, func_id)` all INTEGER. A function is attached to the **first** module (in `lfa_modules` order) whose `[start, end]` contains it, via `dones` (3374-3382).

- **Diff-time readers:** H13, H14 (default), H15 (SLOW, standalone default), `find_related_compilation_unit` (default, every iteration). In H13/H14, `main_cu.name != ''` excludes anonymous CUs.
- **Runs by default?** Yes.
- **Porting spec.** Load CUs `(id, name TEXT, pseudocode_primes TEXT, start_ea TEXT, end_ea TEXT)` and CUF `(cu_id, func_id)` ordered by id. Keep `start_ea`/`end_ea` as text plus `double` (Python `float()`; for integer strings SQLite `CAST` and Python agree: 0 mismatches over 300,000 random 32/64-bit addresses [EMP]).
- **Export fragility (context only).** `new_modules` is assigned only inside `if HAS_GET_SOURCE_STRINGS:` (`diaphora_ida.py:3253-3310`) but is used unconditionally at 3312. When `IDAMagicStrings` fails to import, `save_compilation_units` raises. `do_export` then aborts **before `create_indices`**, and `export()` swallows the error (1305-1312; it re-raises only when a hook's `on_export_crash` returns falsy). The result is a DB with empty CU tables and **no idx_N indices**. `export()` still commits and runs `analyze` (1316-1324), and the `program`/`program_data` rows are already written. A duplicate CU `start_ea` (declared `text unique`) would hit the same abort path.

### 7.7 Microcode vs native rows: `asm_type`

`instructions`, `basic_blocks` and `function_bblocks` carry `asm_type` `'native'` or `'microcode'`. **No diff-time SQL filters on it.** H40 and H41 therefore see microcode instructions and microcode blocks as well. Only the IDA graph view (`get_graph`, `diaphora.py:1188-1267`, called only from `diaphora_ida.py:1769-1770`) filters on `asm_type`.

### 7.8 `instructions` (`schema.py:133-146`)

Native writer (`diaphora.py:730-773`) [SRC]:
```python
    sql = """insert into main.instructions (address, mnemonic, disasm,
                      comment1, comment2, operand_names, name,
                      type, pseudocomment, pseudoitp, func_id,
                      asm_type)
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'native')"""
...
        for instruction_property in instruction:
          if isinstance(instruction_property, (list, set)):
            instruction_properties.append(
              json.dumps(
                list(instruction_property),
                ensure_ascii=False,
                cls=CBytesEncoder,
              )
            )
          elif isinstance(instruction_property, int):
            if instruction_property > 0x8000000000000000:
              instruction_property = str(instruction_property)
            instruction_properties.append(instruction_property)
```
(Lines 736-740 and 745-757.) Per-instruction source list: `[rva, mnem, disasm, cmt1, cmt2, operands_names, tmp_name, tmp_type]` (`diaphora_ida.py:2862-2871`).

Microcode writer (`diaphora.py:822-888`) inserts `(address, mnemonic, disasm, comment1, pseudocomment, func_id, 'microcode')` **only for lines whose `mnemonic is not None`** (850). It runs only when the function's microcode block and relation dicts are both non-empty (`diaphora.py:915`, §4). In a headless export without the decompiler these rows are **still written** (§2).

| Column | Native row | Microcode row | Stored [EMP] | Read at diff? |
|---|---|---|---|---|
| `id` | rowid | rowid | INTEGER | **yes** (H41 join) |
| `func_id` | functions.id | functions.id | INTEGER | **yes** (H40, H41) |
| `address` | **RVA** (`current_head - image_base`) | **absolute** EA or NULL (no `;` comment, `diaphora_ida.py:2230-2235`) | TEXT / NULL | no (idx_31 only helps the UI) |
| `disasm` | `GetDisasm(head)` | plain microcode line | TEXT | **yes** (H40: `is not null`, `!= ''`, `group by … having count(0)=1`) |
| `mnemonic` | `print_insn_mnem(head)` | first non-digit token | TEXT | **yes** (H41 `GROUP_CONCAT`) |
| `comment1` | `GetCommentEx(h,0)` (= `ida_bytes.get_cmt`, [IDA] 9.4 `idc.py:1871`), which returns **None, so NULL**, when there is no comment ([BIN] idalib 9.4: 2927/2978 and 2627/2666 lookups returned None and none returned `''`) | `color_line` (with IDA color tags) | TEXT/NULL ([REAL] ls: 15,199 NULL, all native) | no |
| `comment2` | `GetCommentEx(h,1)` (same; NULL when there is no comment) | – | TEXT/NULL | no |
| `operand_names` | JSON `[[idx, name], …]` | NULL | TEXT/NULL | no |
| `name`, `type` | `tmp_name`, `tmp_type` | NULL | TEXT/NULL | no |
| `pseudocomment` | **always NULL** (cleared before save, §2 item 5) | microcode `comments` | TEXT/NULL | no |
| `pseudoitp` | **always NULL** | NULL | NULL | no |
| `asm_type` | `'native'` | `'microcode'` | TEXT | no |

- **Runs by default?** Yes (H41 always; H40 when same processor).
- **Porting spec.** Load `(id, func_id, mnemonic, disasm)` ordered by id, **including microcode rows**. Keep NULL vs `''` for `disasm`.

### 7.9 `basic_blocks` (`schema.py:147-151`)

Native writer `insert_basic_blocks_to_database` (`diaphora.py:775-820`) [SRC]:
```python
    for key in bb_data:
      # Insert each basic block
      num += 1
      ins_ea = str(key)
      last_bb_id = self_get_bb_id(ins_ea)
      if last_bb_id is None:
        cur_execute(sql1, (num, str(ins_ea)))
        last_bb_id = cur.lastrowid
```
`get_bb_id` (701-717) is `select id from basic_blocks where address = ?` **with no `asm_type` and no function filter**. A native block at an RVA already present (a block shared by two functions) **reuses the existing row** [EMP: `f1` and `f2` sharing RVA `0x5000` → one `basic_blocks` row, `function_bblocks` (1,2) and (2,2)]. [REAL] sechost-9168-pdb has 11 shared block rows and userenv-9168-pdb has 1. The lookup also ignores `asm_type`, so a native block could reuse an earlier **microcode** block row whose absolute start equals the native RVA text. That needs image base 0 plus shared code. It is not observed in the corpus (PE bases are 0x180000000; the ELF base is 0x400000).

| Column | Native | Microcode | Stored |
|---|---|---|---|
| `num` | 1-based order within the function's `bb_data` (**not updated when the row is reused**) | 0-based (`diaphora.py:837, 876`) | INTEGER |
| `address` | RVA string | absolute EA (`get_valid_prop(block.start)`) | TEXT |
| `asm_type` | `'native'` | `'microcode'` | TEXT |

- **Read at diff time:** no. H41 groups by `bb_instructions.basic_block_id` and never touches this table. **Default?** No, but its **id space** defines H41's grouping key.

### 7.10 `bb_relations` (`schema.py:152-155`)

Native: one row per `(parent, child)` in the `bb_relations` dict (`diaphora.py:806-813`). The dict holds **duplicate forward edges**: each block's own succ list is reset at `diaphora_ida.py:2880`, but preds processed later append the same edge again (2903-2914) [EMP: `[rva+4, rva+4]` → 2 rows]. Microcode: parent/child from `succset`, skipping children not in `bblocks` (`diaphora.py:879-888`).

- **Read at diff time:** no (only `get_graph`, UI). **Default?** No.

### 7.11 `bb_instructions` (`schema.py:156-159`)

Native (`diaphora.py:798-803`) links `(last_bb_id, instructions_ids[ins_addr])` for each instruction of each block. Microcode (848-873) does the same. When a block row is shared, the **second function's instructions are appended to the same `basic_block_id`** [EMP: block 2 → instructions 2,3,5,6].

- **Read at diff time:** yes, by H41. The block below is the `main_bblocks` CTE body [SRC `diaphora_heuristics.py:943-947`]; `diff_bblocks` at 950-954 is the same over `diff.*`:
```sql
select inst.func_id, bb.basic_block_id bb_id, GROUP_CONCAT(inst.mnemonic) as mnemonics_list, count(0) inst_total
  from main.bb_instructions bb,
       main.instructions inst
 where bb.instruction_id = inst.id
 group by bb_id
```
- **Plan-dependent details** [EMP, SQLite 3.51.1 with exported indices + `analyze`]. The plan is `SCAN bb USING COVERING INDEX idx_33` then `SEARCH inst USING INTEGER PRIMARY KEY`. `GROUP_CONCAT` order is therefore `(basic_block_id, instruction_id)` ascending, which is instruction insertion order: for a shared block, the first function's instructions come first (`'xor,retn,xor,retn'`, `inst_total=4`). The separator is `,`, and NULL mnemonics are skipped. The bare column `inst.func_id` is SQLite's "arbitrary row" value; for a shared block it can be either function (observed: the first). [REAL] The same plan (`SCAN bb USING COVERING INDEX idx_33`, `SEARCH inst USING INTEGER PRIMARY KEY (rowid=?)`) holds for the full H41 SQL on the real pairs ls/ls-old and sechost-9168-pdb/userenv-9168-pdb. Those pairs carry real `sqlite_stat1` (48 rows each). `GROUP_CONCAT` equals the `instruction_id`-ascending concatenation in all 8,428 + 7,491 + 45,157 + 12,259 groups. The bare `func_id` is the first function's for all 12 shared blocks. This is an observed plan property, not a SQLite guarantee.
- **Runs by default?** Yes.
- **Porting spec.** Load `(id, basic_block_id, instruction_id)` ordered by id. Group by `basic_block_id` and concatenate mnemonics in ascending `instruction_id`, with `inst_total` = row count including duplicates. Record the func_id choice rule as an explicit, tested assumption (Hard part H-6).

### 7.12 `function_bblocks` (`schema.py:160-164`)

`(function_id, basic_block_id, asm_type)`, one row per `bb_ids` entry (native, `diaphora.py:815-820`) or per microcode block (846). Shared blocks appear under both functions.

- **Read at diff time:** no (UI `get_graph` only). **Default?** No.

---

## 8. Indices and planner statistics (`schema.py:23-65`, `create_indices` `diaphora.py:634-649`)

The index names are `idx_{position in INDICES}`, followed by `analyze`. [EMP] listing:

| idx | Table(columns) | idx | Table(columns) |
|---|---|---|---|
| 0 | functions(bytes_hash) | 21 | functions(clean_pseudo) |
| 1 | functions(pseudocode) | 22 | functions(switches) |
| 2 | functions(name) | 23 | functions(function_hash) |
| 3 | functions(mangled_function) | 24 | functions(md_index) |
| 4 | functions(assembly, pseudocode) | 25 | functions(kgh_hash) |
| 5 | functions(nodes, edges, mnemonics, names, cyclomatic_complexity, prototype2, indegree, outdegree) | 26 | functions(constants_count, constants) |
| 6 | functions(instructions, mnemonics, names) | 27 | functions(md_index, constants_count, constants) |
| 7 | functions(nodes, edges, cyclomatic_complexity) | 28 | functions(address) |
| 8 | functions(cyclomatic_complexity) | 29 | functions(microcode_spp) |
| 9 | functions(pseudocode_lines, pseudocode_primes) | 30 | functions(microcode) |
| 10 | functions(names, mnemonics) | 31 | instructions(address) |
| 11 | functions(pseudocode_hash2) | 32 | bb_relations(parent_id, child_id) |
| 12 | functions(pseudocode_hash3) | 33 | bb_instructions(basic_block_id, instruction_id) |
| 13 | functions(pseudocode_hash1, pseudocode_hash2, pseudocode_hash3) | 34 | function_bblocks(function_id, basic_block_id) |
| 14 | functions(strongly_connected) | 35 | constants(constant, func_id) |
| 15 | functions(strongly_connected_spp) | 36 | callgraph(func_id) |
| 16 | functions(loops) | 37 | compilation_units(pseudocode_primes) |
| 17 | functions(rva) | 38 | compilation_units(name) |
| 18 | functions(tarjan_topological_sort) | 39 | compilation_unit_functions(func_id) |
| 19 | functions(mnemonics_spp) | 40 | compilation_unit_functions(cu_id) |
| 20 | functions(clean_assembly) | | |

Autoindexes also exist: `sqlite_autoindex_functions_1` (address UNIQUE), `sqlite_autoindex_functions_2` (rva UNIQUE) and `sqlite_autoindex_compilation_units_1` (start_ea UNIQUE). These indices and `sqlite_stat1` do not change the result set of an order-independent query. They do change the **order** in which rows come back, and Diaphora's acceptance logic is order-dependent (see 04a). For H40/H41 they can also change the **values** of `GROUP_CONCAT` and of bare columns (§7.11). The loader should record whether `sqlite_stat1` and `idx_*` exist, so a replay path can reproduce the planner's choices.

---

## 9. Loader porting spec (C++)

### 9.1 Value representation

```cpp
enum class Sto : uint8_t { Null, Integer, Real, Text, Blob };   // sqlite3_column_type()
struct Cell {                     // one stored value, never coerced at load time
  Sto         Type;
  int64_t     I = 0;              // Integer
  double      R = 0;              // Real
  std::string Bytes;              // Text (raw UTF-8, sqlite3_column_text + _bytes) or Blob (sqlite3_column_blob)
};
```
Rules:
1. **Never collapse NULL into `''`.** The current `ColumnText` (`src/ExportDatabase.cpp:98-105`) returns an empty `string_view` for NULL and must change. Diaphora distinguishes the two for `pseudocode`, `clean_pseudo`, `clean_microcode`, `prototype2`, `pseudocode_hash*`, `pseudocode_primes`, `source_file`, `tarjan_topological_sort`, `instructions.disasm` and `compilation_units.name`.
2. Read the **type tag first** (`sqlite3_column_type`) and only then extract. Calling `sqlite3_column_int64` on TEXT or REAL silently converts (SQLite's numeric-prefix / truncation rules). That is harmless for Diaphora-written INTEGER columns but wrong for `function_flags` (REAL).
3. Load every table **`ORDER BY id`** (`version` has no id; load all rows). SQLite does not guarantee rowid order without it.

### 9.2 Per-table queries

```sql
-- functions: all 49 columns + the SQLite-evaluated double used by SELECT_FIELDS
select f.*, cast(f.md_index as real) as md_index_sqlreal from functions f order by f.id;
select id, func_id, constant, abs(constant) = 0 as abs_is_zero from constants order by id;
select id, name, functions, primes_value, pseudocode_primes, start_ea, end_ea from compilation_units order by id;
select id, cu_id, func_id from compilation_unit_functions order by id;
select id, func_id, mnemonic, disasm, asm_type from instructions order by id;
select id, basic_block_id, instruction_id from bb_instructions order by id;
select id, callgraph_primes, callgraph_all_primes, processor, md5sum from program order by id;
select value from version;
-- optional (diff never reads): basic_blocks, bb_relations, function_bblocks, callgraph, program_data
```

### 9.3 Derived fields the loader should precompute

| Field | Definition | Why |
|---|---|---|
| `md_index_sqlreal` | `CAST(md_index AS REAL)`, equal to `sqlite3_column_double` on the TEXT cell (200,000/200,000 identical [EMP]) | `SELECT_FIELDS` md1/md2 → `check_ratio` |
| `md_index_pyfloat` | correctly rounded `std::from_chars<double>(md_index_text)` (matches Python `float()`) | `compare_function_rows` → `check_ratio` |
| `address_u64`, `rva_i64` | parse of the canonical decimal text | `int(ea)` sorts (`diaphora.py:3345`), `"0x%x"` formatting |
| `address_sqlreal` | `CAST(address AS REAL)` | `find_related_compilation_unit` `between` |
| `names_set`, `constants_set` | tokenized JSON, each element tagged Int or Str (raw token text is fine: `json.dumps` is canonical and injective) | `search_small_differences`, `deep_ratio`, `find_related_constants` |
| `abs_is_zero` (constants) | from SQLite (above) | `find_related_constants` |

### 9.4 Comparison helpers (must mirror §1.4)

```
TextEq(a,b)         : both non-NULL and memcmp-equal              (SQL '=' on TEXT)
TextVsLit(a, op, n) : a is TEXT → compare a.Bytes with decimal(n) by memcmp  (kgh_hash != 0, md_index > 0, microcode_spp != 1)
AddrRange(lo,hi)    : rows with lo < address < hi by memcmp, then ORDER BY address DESC by memcmp   (find_functions_between)
NullEq              : SQL '=' with a NULL operand → NULL → row excluded; ORDER BY puts NULL first
```

### 9.5 Validation, matching Diaphora's failure modes

- `diff.version` is missing or empty → Diaphora `diff()` returns False; standalone then still writes an empty results DB (`diaphora.py:3772-3773`).
- `count(main.program) + count(diff.program) != 2` → exception, no results.
- `callgraph_primes` is not a Decimal literal, or `callgraph_all_primes` is not a JSON object → exception, no results.
- `name` NULL anywhere → Python `AttributeError` in `.startswith` (for example `diaphora.py:1392`). Diaphora never writes one; reject the input.

---

## 10. Hard parts

- **H-1. Affinity-driven text semantics.**
  - Every numeric-looking TEXT column is compared as bytes, both against literals and against parameters.
  - `find_functions_between` passes `str` addresses (item `ea` values are always `str`: `diaphora.py:1436, 1910, 2067, 3115, 3299`). The gap query and its `order by address desc` are therefore **lexicographic**. This matches numeric order only while all addresses share a digit count. It breaks, for example, for a 32-bit image crossing `0x989680` (`9999999` → `10000000`).
  - A native port that parses addresses to integers and compares numerically will diverge exactly there.
- **H-2. NULL vs `''` vs `'0'`/`'1'`.** `pseudocode` can be `''` (prototype-only decompilation). `microcode`/`clean_microcode` can be `''` (`self.microcode[f]==[]`). `comment` is `''`, not NULL, in IDA 9. CU `name` is `''` for anonymous CUs, while functions in those CUs get `source_file` NULL. `md_index` uses `'0'`, never NULL. Each of these reaches a different branch in Diaphora.
- **H-3. Two double conversions of `md_index`.**
  - SQLite 3.51.1's text→real is **not** correctly rounded. Over 200,000 `md_index` strings built with Diaphora's own formula, 139 gave `cast(s as real) != float(s)`. Example: `'2.015185537900030743935567273'` → SQLite `2.0151855379000305`, Python `2.015185537900031`.
  - `check_ratio` uses SQLite's value on the SQL path and Python's on the `compare_function_rows` path.
  - The effect is limited to `md1 == md2` / `md1 > 0.0` decisions between *different* strings that round to one double under one converter but not the other. That is rare, but the fix is trivial: carry both.
  - The reference run must use the same SQLite build (conda 3.51.1) for this to hold.
- **H-4. `abs()` on TEXT.** `abs(mc.constant) == 0` depends on SQLite's numeric-prefix parse (`'12abc'`→12, `' 42'`→42, `'0x10'`→0, `'1e3'`→1000). Evaluate it in SQLite at load time rather than re-implementing it.
- **H-5. Duplicates are data.** Duplicate integer constants, duplicate forward `bb_relations` and shared `basic_blocks` rows are all real. Deduping any of them changes row counts, `inst_total`, `GROUP_CONCAT` strings and which pairs H16/H21/H22 emit first. It can also change whether `SQL_MAX_PROCESSED_ROWS` truncates a heuristic.
- **H-6. Planner-dependent outputs.**
  - Bare columns (`inst.func_id` in H41, `f.id, f.name` in H40, which are safe there only because `having count(0) = 1`) and `GROUP_CONCAT` order depend on the query plan.
  - The plan depends on the idx_N set and `sqlite_stat1` shipped in each export.
  - The observed plan (§7.11) should be pinned in tests against a real export. The verification pass has confirmed it on two real pairs (§7.11 [REAL]).
- **H-7. Unbounded bignum TEXT.** `mnemonics_spp`, `pseudocode_primes`, `kgh_hash`, `microcode_spp`, `strongly_connected_spp` and `primes_value` are exact decimal integers of arbitrary length. `sys.set_int_max_str_digits(0)` (`diaphora.py:96-97`) removes Python's 4300-digit cap. The longest real `kgh_hash` in the 7 exports is 20,699 digits (sechost) [REAL]. The 167,210-digit value in the maintainer notes (not published) and `README.md:120` is a synthetic `47^100000` stress vector for the native renderer, not something taken from an export. At diff time they are only compared as text, plus `length(pseudocode_primes) >= 35` (character count). Never parse them into fixed-width integers.
- **H-8. JSON with Python semantics.** In `constants`, an int and a string with the same digits are distinct set members. Ints reach 2^64-1. Strings are `get_string_at(dref).decode("utf-8", "backslashreplace")` (`diaphora_ida.py:2479-2481`). `get_string_at` returns `get_strlit_contents(ea, -1, -1)` for mapped addresses (`diaphora_ida.py:252-258`). The strings can therefore contain literal backslash sequences. Strings of length ≤ 4 stay in the `functions.constants` JSON and in `constants_count`, but are **not** rows of the `constants` table (`diaphora.py:990`). Tokenizing on raw JSON token text reproduces Python equality exactly. Decoding is needed only to produce `str(constant)` for the `constants.constant = ?` lookup.
- **H-9. Non-unique names.**
  - `name` is `demangle_name(true_name, 36)`, IDA's full demangled signature, or the raw name when demangling fails (§5.1 #0). Overloads get distinct names, and the 7 real exports have 0 duplicate `name` values. But no constraint enforces uniqueness (`idx_2` is not UNIQUE) and demangling is not injective, so the loader must still allow duplicates.
  - `get_function_row` takes the first `where name = ?` row, and `functions_exists` requires *exactly* 2 union rows.
  - The loader must expose name → list of ids, not name → id.
  - `find_equal_matches` keys on `mangled_function`; everything else keys on `name`.
- **H-10. INTEGER columns are INTEGER in practice, but check the tag anyway.** `function_flags` becomes REAL only if BADADDR is bound [EMP], and the exporter cannot reach that path (Summary). Every INTEGER column in the 7 real exports is INTEGER [REAL]. The column is not read at diff time, so the loader should accept REAL there, not reject the file.
- **H-11. File-level quirks.**
  - IDA exports are WAL-mode (§2). Open with a mode that works for WAL files without writing, for example URI `file:...?mode=ro` with write access to the directory for `-shm`, or `immutable=1` when nobody else has the file open.
  - `program.md5sum` is a BLOB in a column declared `text`, and `program_data.name` is a BLOB for `til` rows.
  - The standalone reference run **mutates db1** (`create_schema`); compare against copies.
- **H-12. Python text semantics downstream.** `.splitlines()` (`diaphora.py:3040-3041`) splits on `\r`, `\x0b`, `\x0c`, `\x1c`-`\x1e`, U+0085, U+2028 and U+2029, not just `\n`. `re.IGNORECASE` with `[a-zA-Z]` also matches U+0130, U+0131, U+017F and U+212A (`CPP_NAMES_RE`, `diaphora.py:114`, used at 3058-3059). The loader must hand these consumers decoded code points, or the consumers must be UTF-8 aware.
- **H-13. Export-side reproductions (only if a native exporter is ever built).**
  - `edges` is doubled. `indegree`/`outdegree` are as written, not as their names say.
  - `segment_rva` is taken from the *last* head.
  - Negative `cc` indexes the prime list from the end.
  - `switches` inner order follows CPython set iteration.
  - `tarjan_topological_sort` follows dict-insertion order of `bb_topological`.
  - `callgraph_primes` is 28-digit Decimal rounding.
  - `instructions` uses a different big-int threshold (`> 0x8000000000000000`) than `get_valid_prop`. An int equal to exactly 2^63 would crash the bind.

---

## 11. Open questions (status after verification)

1. **BADADDR width in IDA 9.x: RESOLVED [BIN]. It is not determinable from Diaphora source.**
   - `BADADDR = _ida_idaapi.BADADDR` is native ([IDA] 9.4 `ida_idaapi.py:65`).
   - In both installed IDA 9.2 and 9.4, IDAPython imports only `ida.dll`: `python/lib-dynload/_ida_idaapi.pyd` and `plugins/idapython3.dll` do, and so do `ida.exe`/`idat.exe`. `ida.dll` is the `__EA64__` kernel; `ida32.dll` is imported only by `idalib32.dll`.
   - idalib 9.4 reports `BADADDR = 0xffffffffffffffff` for a 32-bit PE (`inf_is_64bit()` False) and for a 64-bit PE alike. `get_idp_name()` returns `'pc'` for both.
   - So every IDA 9.x export gets the suffix: `processor = 'pc64'` [REAL all 8 exports].
   - A pair that mixes IDA ≤ 8.x (32-bit `ida.exe`, no suffix) with 9.x would get `is_same_processor = False`.
2. **`md5sum` type for pre-9.x IDA: still NOT DETERMINED FROM SOURCE.** 9.2 stubs give `-> bytes`, 9.4 gives `-> Union[bytes, None]`. idalib 9.4 returns `bytes` of length 16, and all 7 real exports store a 16-byte BLOB. The value is log-only at diff time.
3. **`ida_bytes.get_cmt` for "no comment": RESOLVED for IDA 9.4 [BIN][REAL].** It returns `None`, so the column is NULL (§7.8). The diff never reads it.
4. **Headless microcode side tables: RESOLVED [REAL] (IDA 9.4 idat) and explained by source.**
   - `get_microcode`'s gate (2264) passes in headless mode, because `decompiler_available` (1082) and `export_microcode` (`diaphora.py:479-481`) are both True.
   - `hr.gen_microcode` then succeeds without an explicit `init_hexrays_plugin()`: the IDA log shows the Hex-Rays plugin loaded at startup.
   - A headless `ls` export has 70,016 `microcode` instruction rows and 4,898 `microcode` blocks, identical to the decompiler-on export, while every `microcode*` column is NULL / `'1'`. H40/H41 therefore see microcode rows in **both** export paths.
   - Not tested: a target architecture with no Hex-Rays decompiler.
5. **H41 plan stability: RESOLVED on real exports [REAL] (§7.11).** The plan, the `GROUP_CONCAT` order and the bare `func_id` choice match the synthetic observation on two real pairs with real `sqlite_stat1`. This remains an observed property, not a guarantee, so keep it as a pinned test.
6. **Export path of the parity corpus: RESOLVED.** `tools/oracle/diaphora_export.py` runs idalib and calls `diaphora_ida._diff_or_export(use_ui=False, file_out=…, file_in="")`, which means `BinDiffOptions` defaults: decompiler on, and microcode when there are ≤ 8,001 functions. The resolved options are recorded in `<id>.export.json` under `diaphora_options`, for example `ls`: `use_decompiler: true`, `export_microcode: true`. The `validate` stage re-exports the ELF samples through `idat -A -B -S` with `DIAPHORA_USE_DECOMPILER=1`, which is also decompiler on. Exports made headless *without* that variable differ in 15 `functions` columns ([REAL] `ls`): `prototype`, `pseudocode`, `pseudocode_lines`, `pseudocode_hash1/2/3`, `pseudocode_primes`, `prototype2`, `clean_pseudo`, `microcode`, `clean_microcode`, `microcode_spp`, and on one function `function_flags`/`assembly`/`clean_assembly`. They also differ in `compilation_units.pseudocode_primes`, which becomes all `'1'`.
7. **`kgh_hash` native rule: still a decision for the implementer, not a doc error.** Diaphora's filter is exactly `kgh_hash != '0'` as a text comparison. It also drops NULL, because `NULL != '0'` is NULL. The native `Key.empty() || Key == "0"` (`src/Heuristics.cpp:212`) is equivalent on every Diaphora-written export ([REAL] no `''`, `'0'` or NULL in 7 exports). Switching to the exact rule, IS NOT NULL and != `'0'`, removes the one theoretical divergence: Diaphora keeps `''`.

---

## Appendix A: probe (reproducible)

The scripts ran from a scratch directory; this condensed form is enough to regenerate every [EMP] fact:

```python
import sys, os, json, decimal, sqlite3
sys.dont_write_bytecode = True
sys.path.insert(0, r"<diaphora-ref>")
import diaphora
bd = diaphora.CBinDiff("probe.sqlite")          # create_schema: tables + version '3.4'
# props: 54-tuple in build_props_list order (diaphora_ida.py:3141-3196) with
#   f=0x140001000 (>0xFFFFFFFF), f=0x401000 (small), function_flags=0xFFFFFFFFFFFFFFFF,
#   md_index=0 / str(Decimal...), prime=0, kgh="NO-FLOW-GRAPH", constants with dup ints,
#   a short str, a >2^63 int; microcode_bblocks with a None-mnemonic line; bb_relations with a dup edge.
bd.save_function(props(...)); ...
# program / compilation_units rows inserted with the verbatim SQL of diaphora_ida.py:3346-3356, 3401
bd.db.commit(); bd.create_indices(); bd.db.commit()
db = sqlite3.connect("probe.sqlite")
for t in TABLES: for c in columns(t): db.execute(f'select typeof("{c}"), quote("{c}") from {t} order by id')
# semantics probes: kgh_hash != 0, md_index != 0 / > 0, microcode_spp != 1, abs(constant),
# cast(md_index as real) vs float() over 200k Diaphora-formula strings, address > ? and address < ?,
# ORDER BY NULL placement, EXPLAIN QUERY PLAN of the H40/H41 CTEs,
# and ctypes sqlite3_column_double(TEXT) vs cast(... as real) on miniconda3/Library/bin/sqlite3.dll.
```

Key outputs (SQLite 3.51.1):

```
function_flags  decl=INTEGER storage=integer/real ['20496', '1.844674407370955162e+19', '20496']
address         decl=TEXT    storage=text         ["'5368713216'", "'4198400'", "'5368717312'"]
md_index        decl=TEXT    storage=text         ["'0.7298566584517582854275250342'", "'0'", ...]
export_time     decl=REAL    storage=real
callgraph_primes '2.613476489367353310691717225E+399'   md5sum (bytes) -> blob, length 16
(id, kgh_hash, kgh!=0, md, md!=0, md>0, md>1, mspp, mspp!=1, scspp, scspp>1, kgh>7)
 (2, 'NO-FLOW-GRAPH', 1, '0', 0, 0, 0, '1', 0, '0', 0, 1)
abs('Hello, world')=0.0 -> ==0 true ; abs('305419896')=305419896.0
random md_index strings: 200000, python float != sqlite cast: 139
column_double(TEXT) == cast(as real): 200000, differs: 0
'999999' < '1000000' -> 0
H41 plan: SCAN bb USING COVERING INDEX idx_33 ; SEARCH inst USING INTEGER PRIMARY KEY (rowid=?)
shared block: basic_blocks [(1,'4096'),(2,'20480'),(3,'8192')]  bb 2 mnemonics 'xor,retn,xor,retn' count 4
get_valid_prop(bytes) raises AttributeError
```

---

## Verification log

The verification pass re-read every section of this document against `db_support/schema.py`, `diaphora.py` (the export path 689-1005 plus every diff-time reader cited), `diaphora_ida.py` (export path 1178-1330, 2188-3490, 3635-3832, 4024-4075), `diaphora_heuristics.py` (every SQL generated by importing `HEURISTICS` from a scratch copy), `jkutils/{graph_hashes,factor,kfuzzy}.py`, `scripts/patch_diff_vulns.py`, `ml/basic_engine.py` and the IDA 9.2/9.4 stubs. Nothing in `<diaphora-ref>` was modified: the headless run used a `git archive` copy in a scratch directory, and every export was opened with `?immutable=1`. Most SQL excerpts, line numbers, `SELECT_FIELDS`, the index list, the heuristic flag table, the §6.2 consumer line ranges, the §1.4 SQLite comparison results and the H-3 example (`'2.015185537900030743935567273'` → 2.0151855379000305 vs 2.015185537900031) checked out as written. These are the corrections:

1. **`function_flags = BADADDR` is not "the one real case".** The Summary, §3, §5.1 #20 and H-10 said it was. It is unreachable: `read_function` returns early when `get_func(f)` is None (`diaphora_ida.py:3208-3211`), and `idc.get_func_attr` returns BADADDR only when `get_func` is None (9.4 `idc.py:3114-3127`). All 7 real exports store `function_flags` as INTEGER. No INTEGER column receives a value of 2^63 or more in practice.
2. **`program.processor` example.** It was `'metapc64'`. It is `'pc64'`: `get_idp_name()` returns the module name `'pc'` (idalib 9.4 probe; 9.4 `ida_idp.py:2113` docstring), and all 8 real exports say `'pc64'`. A None return raises at `proc += "64"`, so NULL cannot be stored.
3. **Open question 1 (BADADDR width) resolved** by binary inspection and idalib: IDA 9.2/9.4 IDAPython links only the `__EA64__` `ida.dll`, and BADADDR is 0xffffffffffffffff even for a 32-bit PE. The suffix is always present under 9.x.
4. **`name` is not a "demangled short name" that "collides across overloads"** (§5.1 #0, H-9). `demangle_name(true_name, INF_SHORT_DN)` passes the constant 36 (`idc.py:2119-2120`) as the mask. The real sechost export shows full signatures (`public: static long …::Write<…>(…)`), and all 7 exports have 0 duplicate names. Uniqueness is still not enforced.
5. **The use_decompiler row in §2 gave a wrong reason.** It said `self.microcode[f]` is filled "only by `decompile_and_get`". In fact `get_microcode` fills it too (2280-2290), but the call at 2993 comes after `extract_microcode` at 2992, so it never reaches the column. Added: `prototype2` also changes with the export path, because decompiling at 2967 sets types that are read at 2968. [REAL] 188 of 318 `ls` functions differ.
6. **Headless microcode rows (open question 4) resolved.** The gate at 2264 passes in `DIAPHORA_AUTO` mode: `decompiler_available = config.EXPORTING_USE_DECOMPILER` (1082), and `export_microcode` is True via `diaphora.py:479-481`. The override at 4061-4063 reads the misspelled env `DIAPHORA_SELF.EXPORT_MICROCODE`. A real IDA 9.4 headless export of `ls` has 70,016 microcode instructions and 4,898 microcode blocks, identical to the decompiler-on export, while every `microcode*` column is NULL. The `export_microcode` row now also gives the headless default and the `get_value_for` raw-string behaviour.
7. **Missed branch:** `save_function_to_database` writes microcode rows only when `len(microcode_bblocks) > 0 and len(microcode_bbrelations) > 0` (`diaphora.py:915`). The function is now quoted in §4, and the gate is noted in §2 and §7.8.
8. **Missed data flow:** `self._funcs_cache[props[12]] = [func_id, props[11], props[19]]` (`diaphora.py:971`) is the only input to CU membership and to the CU prime values. Added to §4, with the crash-resume caveat in §2 item 1.
9. **Constant multiplicity.** §7.4 said H16, H21 and H22 all emit one row per duplicate pair. **H21 is `select distinct`**, so duplicates collapse there. Only H16 and H22 multiply rows.
10. **`kgh_hash` sentinels** `NO-FUNCTION`/`NO-FLOW-GRAPH` cannot be reached from the exporter. `get_func` is non-None, and `FlowChart(...)` never returns None (`graph_hashes.py:101-107`). 0 non-digit values in 7 exports. Also noted that `!= '0'` drops NULL.
11. **Maintainer-notes quote.** The doc gave "does nothing (TEXT compared with INTEGER)" as a quote, but it was a paraphrase. It is now quoted verbatim from the maintainer notes (not published).
12. **The "167,210-digit KGH value"** was attributed to the maintainer notes. It is a synthetic `47^100000` stress vector (maintainer notes, not published; `README.md:120`). The longest real `kgh_hash` is 20,699 digits (sechost).
13. **`md_index` detail (§5.1 #36).** A function with no edges gives the **str** `'0'` (`str(sum(()))`). The int `0` appears only on the RecursionError path. The stored value is the same.
14. **`segment_rva` (§5.1 #39).** Added that `current_head` stays BADADDR (2826) when the last processed block has no heads, and that blocks with `end_ea` 0/BADADDR are skipped (3225-3227).
15. **`deep_ratio` constants.** "The diff row is loaded unconditionally" was misleading. Both sides are parsed only when the main side is not `'[]'` (2812-2814); the diff side is not checked first.
16. **`source_file` heuristics.** "~30 heuristics" is now exact: 32 (22 on the default path), all ORDER BY only, verified by scanning the generated SQL.
17. **`get_unmatched_functions` (§6.2)** said "only in patch-diff mode". It runs whenever dirty mode fired (3626-3627). Only `search_remaining_functions` is restricted to patch-diff (2708).
18. **`get_callgraph_difference`.** The JSON must be an object only when the two Decimals differ; they are used via `FACTORS_CACHE` in `factor.py:203-242`. When the Decimals are equal it returns 0 first. §7.1's porting spec is updated to match.
19. **"The standalone reference run writes to db1" (§7.2)** was overstated. The commit sits inside `if not row` (`diaphora.py:628-630`), and a missing table is created and autocommitted. On a complete export neither happens.
20. **Line-number fixes.** `ColumnText` is at `src/ExportDatabase.cpp:98-105` (was 97-104). The H41 excerpt is `diaphora_heuristics.py:943-947` (main) / 950-954 (diff), not 942-955. The string-constant source is `get_string_at` (`diaphora_ida.py:252-258`), called at 2479, not a direct `get_strlit_contents` call (H-8). `ida_bytes.get_cmt` is defined at 9.4 `ida_bytes.py:2678` (the doc said 2680).
21. **Open question 3 (get_cmt) resolved** for IDA 9.4. It returns None, which is stored as NULL: idalib probe plus 15,199 NULL native `comment1` rows in `ls`.
22. **Open questions 5 and 6 resolved.** The H41 plan, `GROUP_CONCAT` order and bare `func_id` were confirmed on two real export pairs with real `sqlite_stat1`. The corpus export path (idalib, `BinDiffOptions` defaults, decompiler on) was confirmed from `tools/oracle/diaphora_export.py:264-280` and `<id>.export.json`.
23. **Added material.**
    - The `ida_subs` export option, whose name is inverted.
    - `PRAGMA foreign_keys = ON` during export; `instructions.func_id` has no FK.
    - `md5sum` is declared `text` but holds a BLOB. 9.4 `retrieve_input_file_md5` is `Union[bytes, None]`.
    - `pseudocode_hash1` is usually NULL (bsize 512).
    - Real NULL/`''` patterns for `prototype`, `comment`, `userdata` and `export_time`.
    - Headless CUs all have `pseudocode_primes = '1'`.
    - A native block can theoretically reuse a *microcode* block row at image base 0.
    - After a swallowed CU error, `export()` still commits and runs `analyze`.

Still open: the `md5sum` type for IDA before 9.x, and whether headless microcode rows appear for architectures without a Hex-Rays decompiler. Both are NOT DETERMINED FROM SOURCE. The `kgh_hash` rule (open question 7) is an implementation decision.
