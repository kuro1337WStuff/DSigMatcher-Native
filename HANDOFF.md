# HANDOFF.md — DSigMatcher Native

Hand-off for the next AI session. Last verified **2026-09-23** against commit `b9fa805` (tag `v0.2.0`).
Read `AGENTS.md` first (hard rules), then this file, then `JOURNAL.md` for the full history.

## What this is

A native C++20 port of **Diaphora** (Python/SQLite IDA binary differ). The goal is fast name and symbol porting between versions of the same binary. The user labels one build in IDA, then rolls the names forward to each new release with `port`, recording provenance at every hop.

- Repo: https://github.com/kuro1337WStuff/DSigMatcher-Native (public, owner **kuro1337WStuff**)
- Local: `<repo-main-checkout>`
- Diaphora reference checkout (read-only, tag 3.4.2 / `621ec26`): `<diaphora-ref>`
- Test corpus (never commit it): `<corpus>\win32u\` has two `win32u.dll` builds (26100.9168 / .9444), their PDBs, and `ground_truth.tsv`

## Hard rules

- **No `Co-Authored-By` or any AI attribution on commits, tags or PRs.** Commits are authored as kuro1337WStuff only.
- The user wants **native C++**, with as little Python as possible. Python is acceptable only for oracles and audit tools under `tools/`.
- Keep **Diaphora's exact hash definitions** (the user decided this). Don't invent "equivalent" hashes.
- Order of work: **ship a working version first**. Fusion, AVX-512 and threading come after.
- Prototype and test **on this PC** (Ryzen 9 9950X, Zen 5, AVX-512). Use GitHub CI only to confirm the other platforms once it's green locally.
- Make small increments, each verified and committed on its own. The user wants the public history to show steady progress.
- Keep `JOURNAL.md` updated: record what changed, what was tested, what was found, and include the failures.

## Build and test (verified 2026-09-23, clean build dir)

```bat
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release ^
      -DCMAKE_PREFIX_PATH=<conda>/Library ^
      -DDSIG_CORPUS_ROOT=<corpus>
cmake --build build && ctest --test-dir build --output-on-failure
```

- Toolchain: MSVC 14.51.36231, CMake 4.2.3 and Ninja, all bundled with VS 2026. None of them is on PATH until you run `vcvars64`.
- SQLite comes from conda (`miniconda3\Library`). Zydis v4.1.1 and Zycore come in through FetchContent.
- The project holds a **zero-warning** line (`/W4 /permissive-`).
- Chain the commands with `&&`, never `&`. Qwen once got a "100% passed" report from stale binaries after a failed build.

| Suite | Checks |
|---|---|
| unit (`dsigmatcher_tests`) | 316 |
| disassembler | 67 |
| peimage | 302 (198 without the corpus, the rest are skipped) |
| resolve | 825 |
| controlflowgraph | 152,784 |
| **Total** | **154,294, all passing** |

CI (`.github/workflows/ci.yml`) is **green** on Linux/GCC, macOS/Clang and Windows/MSVC for `main` and `v0.2.0`.

## GitHub auth

- The maintainer's machine pins this repo to the owner account (**kuro1337WStuff**) through a repo-local git credential helper, so a plain `git push` authenticates as the owner. Machine-specific auth details are kept outside the repo.
- Never switch the global `gh` account to push here, and never set a different git identity. The repo hooks reject commits that aren't authored and committed as the owner.

## Code map

| File | Role |
|---|---|
| `ExportDatabase` | Reads Diaphora `.sqlite` exports into SoA records over a string arena. Discovers columns with `pragma table_info`. |
| `Heuristics` | Native hash-join versions of Diaphora's SQL heuristics. Runs on a persistent `ThreadPool`. |
| `MatchStore` | Dedups before sorting, then resolves greedy 1:1. The **partitioned parallel Resolve is disabled** (kill switch). |
| `Provenance` / `main` | The `diff`, `port` and `info` CLI. `port` output is itself a valid export, so ports chain. It handles hop count, origin name, multiplicative confidence decay and the confirmation path. |
| `PeImage` | PE32/PE32+ parser. Audited against `pefile` with 0 mismatches. |
| `DisassemblerZydis` | Zydis backend behind a backend-agnostic `Disassembler` interface. |
| `ControlFlowGraph` | Blocks, edges, SCCs, loops and complexity, reproducing Diaphora's quirks. |
| `Md5`, `Sha256`, `KghHash` (bignum), `PrimeTable` | Hash primitives, each checked against a Python oracle. |
| `Synth` | Synthetic corpus with ground truth. Text columns are KB-scale. |

## Heuristic parity: 12 of 50

Source of truth: `<diaphora-ref>\diaphora_heuristics.py`. Diaphora has 12 Best, 30 Partial and 8 Unreliable heuristics.

**Done (12):**
- Best (8): Same RVA and hash, Same order and hash, Function Hash, Bytes hash, Same address and mnemonics, Same cleaned assembly, Same cleaned microcode, Same cleaned pseudo-code
- Partial (4): Same KOKA hash and MD-Index, Same constants, Same rare KOKA hash, Same rare MD Index

**Missing, Best (4):** Same address, nodes, edges and mnemonics; Same RVA; Equal assembly or pseudo-code; Microcode mnemonics small primes product.

**Missing, Partial (26):** the three compilation-unit heuristics; Same KOKA hash and constants; Same address and rare constant; Same rare constant; Same MD Index and constants; Import names hash; Mnemonics and names; Pseudo-code fuzzy hash; Similar pseudo-code and names; Mnemonics small-primes-product; Same nodes, edges, loops and SCCs; Same low complexity, prototype and names; Same low complexity and names; Switch structures; the four Pseudo-code fuzzy heuristics (normal, mixed, reverse, AST hash); the three Partial pseudo-code fuzzy hash heuristics (normal, reverse, mixed); Same rare assembly instruction; Same rare basic block mnemonics list; Loop count.

**Missing, Unreliable (8):** Same graph; Strongly connected components; Nodes, edges, complexity and mnemonics; Nodes, edges, complexity and prototype; Nodes, edges, complexity, in-degree and out-degree; Nodes, edges and complexity; Same high complexity; Topological sort hash.

**Other gaps besides the heuristics:**
- **Graded ratio.** Diaphora's `compare_function_rows` produces a similarity score. Ours is binary (1.0 unique, 0.5 ambiguous), so the per-heuristic `min` thresholds (0.5 / 0.45 / 0.2) currently have no effect.
- **Category demotion** in the Unreliable pass.
- **Call-graph propagation** and the matching that happens after the heuristics run.
- **Schema coverage** is 27 of 49 `functions` columns. The 12 side tables are unread apart from `program`. Some missing heuristics need the `constants`, `instructions` and `basic_blocks` tables.

## Known issues and divergences

- `kgh_hash != 0` does nothing in SQLite (TEXT compared with INTEGER). We implement what it was meant to do: skip `""` and `"0"`. This divergence is deliberate and **unverified**.
- `diff -o <input>` writes `matches` and `symbols_to_port` into the input database. It isn't destructive, but it's surprising. `port` already rejects aliased paths via `weakly_canonical`; `diff` needs the same check.
- The partitioned parallel `Resolve` is disabled. Its thread-count tests compare serial with serial, so they prove nothing. A reproducer with few workers is needed before re-enabling it.
- `resolve_tests` deliberately assert **order-dependent** results when matches differ only by Category. Don't "fix" the comparator: an earlier attempt broke 236 assertions.
- On Windows CI, the vcpkg `sqlite3.dll` is staged next to the exes. Otherwise a MinGW `sqlite3.dll` from PATH gets loaded and segfaults.

## Blockers

1. **No real Diaphora export exists yet.** Every heuristic is checked against transcribed SQL and synthetic data, never against real Diaphora output. The user needs to export both `win32u` builds from IDA with Diaphora. **Turn off `EXPORTING_EXCLUDE_LIBRARY_THUNK`**, because win32u is mostly syscall stubs.
2. **`bytes_hash` and `function_hash` byte-exactness.** Diaphora concatenates instructions in IDA `FlowChart` block order, and that order is native IDA code we can't see. Implement address order as an explicit, named assumption, then pin the real order against a real export. Also:
   - The `offb` truncation is dead code, so `bytes_hash` covers full raw bytes and changes when code is relocated.
   - `md_index` uses 28-digit `Decimal` with ROUND_HALF_EVEN, not `double`.
   - Cyclomatic complexity double-counts edges.
   - `indegree` and `outdegree` are swapped in Diaphora. Reproduce them as written.
3. **win32u is a weak corpus for CFG work.** It's all syscall stubs, with no loops and no indirect jumps. The user offered bigger, half-labelled exes. A second option is a Microsoft DLL with a PDB that has real function bodies (combase, windows.storage).

## Suggested next steps

1. Ask the user whether their IDA exports exist yet. If they do, run `diff` against them first: it's the biggest open risk.
2. Close out the Best tier (4 left), starting with Same RVA and Equal assembly or pseudo-code, since they need no new columns.
3. Build `md_index`, then `bytes_hash` / `function_hash` on top of the CFG.
4. Work through the Partial tier in batches, with a commit and journal entry for each.
5. **After** the version works end to end, add fusion for the three text-keyed joins (about 69% of heuristic time, measured roughly 3.2×), AVX-512/AVX2/scalar hash dispatch with a CPUID + XCR0 check (about 16× measured), then re-enable the parallel Resolve.

## Lessons from the previous session

- Generate any count you quote in docs; don't type it from memory. The "46 heuristics / 48 columns" error propagated into 9 places.
- Research-agent reports are leads, not facts. Check API claims against the actual headers.
- A benchmark that uses a naive hot primitive (FNV-1a) measures the primitive, not the design.
- Build fixtures that differ per side. Early precision of 1.0 was an artifact of the fixtures.
