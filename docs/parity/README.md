# Parity design specs

These documents are the porting specification DSigMatcher's diff engine was built from: a
section-by-section reading of Diaphora 3.4.2, with every behaviour the C++ port has to reproduce.

> **They are historical.** All of them were written on 2026-09-23 against an earlier revision of
> this repository (commit `34ed418`), before the port existed, and were only lightly corrected
> afterwards. Their status remarks describe that moment: heuristics marked "not implemented",
> counts of test executables and checks, oracle runs "still running", and open questions that
> have since been answered. Each file carries a one-line banner saying so. Read them for *why* the
> engine works the way it does, not for what is finished. The current state of the project is in
> the [top-level README](../../README.md) and the release notes under [`docs/release/`](../release/).

## Files

| File | Covers |
|---|---|
| [`01-driver.md`](01-driver.md) | Diaphora's diff driver: which passes run, in what order, the configuration, and the `.diaphora` results file. |
| [`02-matching.md`](02-matching.md) | Match bookkeeping (`add_match`, `cleanup_matches`, the matched-name maps) and how heuristic SQL is executed and consumed. |
| [`03a-ratio.md`](03a-ratio.md) | The similarity ratio (`check_ratio`, `deep_ratio`, 7-decimal rounding) and the SQLite and Python number conversions it depends on. |
| [`03b-text-difflib.md`](03b-text-difflib.md) | Text handling and the CPython `difflib` algorithms used at diff time. |
| [`04a-heuristics-best.md`](04a-heuristics-best.md) | The heuristic runner and heuristics H01-H28. |
| [`04b-heuristics-rest.md`](04b-heuristics-rest.md) | Heuristics H29-H50. |
| [`05-passes.md`](05-passes.md) | The passes that are not SQL heuristics: equal matches, stripped-binary and patch-diff detection, same name, remaining functions, small differences. |
| [`06-iterative-final.md`](06-iterative-final.md) | The iterative loop (callee diffing, related constants, related compilation units, local affinity) and the final multimatch pass. |
| [`07-native-codebase.md`](07-native-codebase.md) | The codebase as it was before the port, and what had to change. |
| [`08-schema.md`](08-schema.md) | The export schema and how values are stored and compared. |
| [`09-oracle.md`](09-oracle.md) | The parity oracle: real exports of real binaries and the results unmodified Diaphora produced from them. |

## How to read them

- **Citations.** `D:<line>` (or `diaphora.py:<line>`, or a bare line number where a document says
  so) is a line of `diaphora.py`; `H:<line>` or `heur:<line>` of `diaphora_heuristics.py`;
  `C:<line>` or `config:<line>` of `diaphora_config.py`; `threads.py:<line>` of
  `jkutils/threads.py`; `diaphora_ida.py:<line>` of the IDA exporter. All refer to Diaphora
  3.4.2-4-g621ec26 (commit `621ec26`). `difflib.py:<line>` is CPython 3.13.12's `Lib/difflib.py`. `§` numbers refer
  to sections of the same document unless another file number is given (for example "03a §6.4").
  The C++ sources use the same citations.
- **Comparison levels.** **L0**: the detected mode and Diaphora's "Final results"
  counts agree. **L1**: the `results` and `unmatched` rows are equal as multisets. **L2**: L1 plus
  identical `line` values and stored row order; this is the parity gate. **S-L2**: the same, for
  the internal match state at one named point of the pipeline.
- **Placeholders.** Paths are written as placeholders: `<diaphora-ref>` is an unmodified Diaphora
  checkout, `<corpus>` the private corpus root holding the oracle, `<scratch>` a private working
  directory, `<conda>` / `<miniconda3>` the Python installation the oracle ran with. The corpus is
  not published; it contains exports of third-party binaries.
- **Configuration.** Everything describes Diaphora run standalone
  (`python diaphora.py db1 db2 -o out`) with its default configuration and no `DIAPHORA_*`
  variables.
- **Maintainer notes.** A few passages cite the project's maintainer notes ("an earlier note") or
  an earlier summary. Neither is part of the published source; the citations are kept as history
  only, and nothing here depends on them.

## Attribution for quoted code

These documents quote Diaphora's source code and CPython's `difflib.py` verbatim in places.

- Quoted Diaphora code: Copyright (c) 2015-2026 Joxean Koret, licensed under the GNU Affero
  General Public License, version 3 or later. See [`NOTICE`](../../NOTICE).
- Quoted CPython code: Copyright (c) 2001-2024 Python Software Foundation; All Rights Reserved.
  Licensed under the PSF License Version 2; see
  [`THIRD_PARTY_NOTICES.md`](../../THIRD_PARTY_NOTICES.md).

The documents themselves are part of DSigMatcher Native and are licensed under the AGPL-3.0-or-later
like the rest of the repository.
