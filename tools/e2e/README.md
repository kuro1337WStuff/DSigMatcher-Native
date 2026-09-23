# End-to-end tools: port on results, ground truth, chain (lane L11)

Plan: `docs/parity/00-plan.md` §7.1 D6 (port redesigned around results files), D8 (ground truth),
§7.2 "L11". The C++ side is `dsigmatcher port ... --results` (`src/cli/PortResults.cpp`, engine
`DSig::PortLabels` in `src/Provenance.cpp`); the Python here drives it, scores it and chains it.
`ctest` never runs these scripts; the C++ suite is `cli_port_results`.

| File | Does |
|---|---|
| `score_ground_truth.py <ported.sqlite> <truth.tsv\|truth-pdb.sqlite>` | Scores a ported DB against the PDB truth of the same build: label level and match level, per category and per heuristic description, alias-aware. |
| `pdb_aliases.py` | Lists every PDB function/public symbol per address through dbghelp (bindings from `tools/extract_pdb_symbols.py`), cached as TSV under `<corpus>/oracle/ground_truth/aliases/<build>.tsv`. Windows only. |
| `run_baseline.py` | Ports Diaphora's **own** run1 results of every finished oracle pair and scores them: Diaphora's baseline. |
| `run_chain.py --differ diaphora\|native [--chain cryptbase]` | hop i = diff(ref_i, target_i) -> port -> ref_{i+1}, every hop scored. `diaphora` runs the unmodified standalone Diaphora on copies; `native` runs `dsigmatcher diff`. |
| `selftest_e2e.py` | Planted-case self-test of the scorer (no corpus needed). |
| `e2e_common.py` | Shared paths, process and report helpers. |

## Paths

Nothing is hard-coded (plan §7.1 D9). Flags win over the environment:

| Flag | Environment | Meaning |
|---|---|---|
| `--corpus` | `DSIG_CORPUS_ROOT` | corpus root; the oracle is `<corpus>/oracle` |
| `--diaphora-dir` | `DSIG_DIAPHORA_DIR` | the unmodified Diaphora checkout; it is only ever run on copies |
| `--python` | `DSIG_PYTHON` | the Python for `diaphora.py` (default: the one running the script) |
| `--dsigmatcher` | `DSIG_EXE` | the executable (default: `<repo>/build/dsigmatcher[.exe]`) |

Reports go to `<corpus>/e2e-reports/<timestamp>-<kind>/` (or `--out`). They contain names taken
from the corpus, so they are never committed.

## `port --results`

```
dsigmatcher port <ref.sqlite> <target.sqlite> -o <out.sqlite> --results <x.diaphora>
                 [--include-multimatch] [--include-unreliable] [--overwrite-existing]
                 [--min-ratio <r>] [--max-hops <n>]
```

The results file is Diaphora's `save_results` layout (`D:2374-2429`, 01 §11, 09): `results(type,
line, address, name, address2, name2, ratio, nodes1, nodes2, description)`, addresses `"%08x"`
of `int(ea)`, ratio `"%.7f"`. It may come from Diaphora or from our `diff`. Every row is read,
checked and logged; best and partial rows are applied by default, unreliable and multimatch rows
only when asked. This README covers `port --results`; `dsigmatcher port --help` describes `port`
without it.

**Refusals (nothing is written).** An output that resolves to the reference, the target or the
results file (exit 2). A results row whose `address`/`address2` is not a function of the given
reference/target, or whose `name`/`name2` is neither that function's `name` nor its
`mangled_function` (exit 4: the results belong to another pair). A file that is not a results DB
or an export (exit 4). A missing file (exit 6).

**Decision per row**, in stored order (best, partial, unreliable, multimatch, each by descending
ratio):

1. not in an included category: `not_selected` (logged, never applied);
2. the target function was already claimed by an earlier selected row: `skipped_conflict`
   (the first row is the strongest evidence for that function);
3. the reference name is not a real symbol (`sub_*`, `nullsub*`, empty): `skipped_not_portable`;
4. the target already carries the identical real name: `confirmed` (no update, no origin row, no
   hop; the legacy "confirmation" rule);
5. hops = parent hops + 1 and confidence = ratio x parent confidence, from the reference's
   `dsig_name_origin` row for that function, used only while the reference still carries the
   recorded name; otherwise hops 1 and confidence = ratio. Then `--max-hops` (`skipped_hops`),
   `--min-ratio` (`skipped_ratio`), and a real target name is kept unless `--overwrite-existing`
   (`skipped_existing`). Otherwise `applied`.
6. After all rows: an applied name (or mangled name) that would appear on two functions of the
   output is not applied (`skipped_duplicate_name`), repeated until stable. A multimatch row that
   gives one reference function to two targets therefore labels neither.

### What a port writes

The output is a byte copy of the target (plus its `-wal` frames, if any) in which only two
`functions` columns change, so it stays a valid Diaphora export and can be the next hop's
reference:

| Column | Why it must travel (docs/parity/08-schema.md) |
|---|---|
| `name` | every name-keyed path of the next diff: `matched_primary/secondary` keys (`D:1373-1374`), the `find_same_name` join (`D:2158-2166`), `get_function_row` (`D:2445-2460`), `find_unmatched`, the `sub_` tests |
| `mangled_function` | `find_equal_matches` (INTERSECT key and item name, `D:1424-1440`), the `find_same_name` join and its `mangled1.startswith("sub_")` skip, patch-diff detection (`D:2599-2603`). A PDB export keeps the raw IDA name here and the demangled one in `name`, so both are copied from the reference row (`name` in both when the reference's `mangled_function` is not a real symbol) |

Deliberately **not** written:

- `prototype`, `comment`: never read at diff time (08 §6.3), so they carry no matching signal.
- `prototype2`: a feature, not a label. H30 compares it (08 §6.1) and it is the target's own type
  analysis (08 §5.1 #22).
- `names`, `assembly`, `pseudocode`, `clean_*`, the hashes, `instructions.*`, `callgraph`: analysis
  products of the target build. Rewriting the callee names inside them would need the exporter's
  text transforms (not reproducible without IDA), and would stop the reference's features matching
  a like-for-like no-PDB target in the next hop.
- No `ANALYZE`, `VACUUM` or index change: the target's `sqlite_stat1` and indices stay as exported.

Added tables (all `create if not exists`; Diaphora ignores them):

| Table | Rows |
|---|---|
| `dsig_provenance` | one per hop (the parent's hops, then this one); unchanged legacy schema |
| `dsig_name_origin` | one per applied name: origin address and name, hops, cumulative confidence, `heuristic` = `<category>:<description>`, first labelled at |
| `dsig_port_results` | one per hop that used `--results`: the results file (path, sha256, its `config` row), flags, counts; carried forward like `dsig_provenance` |
| `dsig_port_log` | this hop only: one per results row, with the reference and target names and the action taken |

Inputs are read through `file:...?mode=ro&immutable=1` when they are WAL-mode files with no
committed `-wal` frames, so a port never creates `-wal`/`-shm` files beside an oracle export.

## Ground truth (D8)

`score_ground_truth.py` joins on the function start address.

- **Truth.** An O1 ground-truth TSV (`<corpus>/oracle/ground_truth/<nopdb id>.tsv`), or a Diaphora
  export of the same build made with its PDB. Truth rows without a real name are not scored
  (`truth_unnamed`).
- **Function starts the analyses disagree on** are reported apart and never scored:
  `truth_only` (O1's `pdb_only` when the ported DB is a no-PDB analysis) and `ported_only`
  (O1's `nopdb_only`).
- **Aliases.** A label is correct when it names any PDB symbol at the address: the truth row's
  `name`/`mangled_function`, or a symbol of the alias TSV. dbghelp strips one leading underscore
  from public names and returns C++ names undecorated, so a label is also looked up, among the
  alias symbols only, with one leading `_` removed and, on Windows, with its mangled name
  undecorated (`UNDNAME_NAME_ONLY`). Correct-by-alias is counted separately.
- **Label level**: what the ported DB says at each scored address, by source (`ported:<category>`,
  `confirmed:<category>`, `target`, `none`) and by heuristic description; missing addresses get the
  reason the port left them unnamed.
- **Match level**: every results row, applied or not, judged by whether the reference name it
  proposes is a truth name of the target address, per category and per description. With
  Diaphora's own results this is Diaphora's baseline, independent of what the port was allowed
  to write.

## Commands (acceptance, plan §7.2 L11)

```
set DSIG_CORPUS_ROOT=<corpus>
set DSIG_DIAPHORA_DIR=<diaphora-ref>
python -B tools/e2e/pdb_aliases.py --all
python -B tools/e2e/run_baseline.py
python -B tools/e2e/run_chain.py --differ diaphora --chain cryptbase
python -B tools/e2e/run_chain.py --differ native --chain cryptbase
python -B tools/e2e/selftest_e2e.py
```
