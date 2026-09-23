# Third-party notices

DSigMatcher Native is licensed under the GNU Affero General Public License, version 3 or later
(see `LICENSE`). Its diff engine is a C++ port of Diaphora; that attribution is in `NOTICE`. This
file lists the other third-party code that DSigMatcher contains, is derived from, or builds with,
together with the licence texts those licences require to be passed on.

This is a factual list of components and their licences. It is not legal advice.

| Component | Version | How it is used | Licence |
|---|---|---|---|
| CPython `difflib` and value semantics | 3.13.12 | Translated to C++ (`src/diff/TextDiff.cpp`, parts of `src/diff/Ratio.cpp`, `src/diff/PyValue.cpp`, `src/diff/Json.cpp`) | PSF License Version 2 |
| Zydis | 4.1.1 (commit `a2278f1`) | Fetched at configure time, linked statically | MIT |
| Zycore | commit `75a36c4` | Fetched at configure time, linked statically (a Zydis dependency) | MIT |
| SQLite | 3.51.1 | Amalgamation fetched at configure time (hash-pinned), linked statically | Public domain |

None of these sources are committed to this repository. Zydis, Zycore and SQLite are downloaded by
CMake when the project is configured (`CMakeLists.txt`, `cmake/VendoredSqlite.cmake`), and the
release binaries link them statically.

---

## CPython `difflib` (Python Software Foundation License Version 2)

`src/diff/TextDiff.cpp` is a C++ translation of `Lib/difflib.py` from CPython 3.13.12.

Summary of changes (PSF License clause 3):

- `SequenceMatcher` (`find_longest_match`, `get_matching_blocks`, `get_opcodes`,
  `get_grouped_opcodes`, `ratio`, `quick_ratio`, `real_quick_ratio`, including the autojunk rule
  for sequences of 200 or more elements) and `unified_diff` were translated from Python to C++20.
- Sequences are held as interned integer ids of `std::string_view` lines instead of Python `str`
  objects.
- The `isjunk` parameter and the junk-extension loops of `find_longest_match` were left out:
  every call site the diff engine needs uses `isjunk=None`, where those loops can never run.
- `str.split("\n")` and `str.splitlines()` were reimplemented for UTF-8 input.

`src/diff/Ratio.cpp` translates `SequenceMatcher.quick_ratio`. `src/diff/PyValue.cpp` and
`src/diff/Json.cpp` reimplement, in C++, the behaviour of CPython's `float(str)`, `repr(float)`,
`json.loads`, `json.dumps` and set semantics. They follow CPython's documented algorithms and cite
its sources; they are listed here so that their origin is clear.

The notice of copyright that the PSF License requires to be kept:

> Copyright (c) 2001-2024 Python Software Foundation; All Rights Reserved

```
PYTHON SOFTWARE FOUNDATION LICENSE VERSION 2
--------------------------------------------

1. This LICENSE AGREEMENT is between the Python Software Foundation
("PSF"), and the Individual or Organization ("Licensee") accessing and
otherwise using this software ("Python") in source or binary form and
its associated documentation.

2. Subject to the terms and conditions of this License Agreement, PSF hereby
grants Licensee a nonexclusive, royalty-free, world-wide license to reproduce,
analyze, test, perform and/or display publicly, prepare derivative works,
distribute, and otherwise use Python alone or in any derivative version,
provided, however, that PSF's License Agreement and PSF's notice of copyright,
i.e., "Copyright (c) 2001-2024 Python Software Foundation; All Rights Reserved"
are retained in Python alone or in any derivative version prepared by Licensee.

3. In the event Licensee prepares a derivative work that is based on
or incorporates Python or any part thereof, and wants to make
the derivative work available to others as provided herein, then
Licensee hereby agrees to include in any such work a brief summary of
the changes made to Python.

4. PSF is making Python available to Licensee on an "AS IS"
basis.  PSF MAKES NO REPRESENTATIONS OR WARRANTIES, EXPRESS OR
IMPLIED.  BY WAY OF EXAMPLE, BUT NOT LIMITATION, PSF MAKES NO AND
DISCLAIMS ANY REPRESENTATION OR WARRANTY OF MERCHANTABILITY OR FITNESS
FOR ANY PARTICULAR PURPOSE OR THAT THE USE OF PYTHON WILL NOT
INFRINGE ANY THIRD PARTY RIGHTS.

5. PSF SHALL NOT BE LIABLE TO LICENSEE OR ANY OTHER USERS OF PYTHON
FOR ANY INCIDENTAL, SPECIAL, OR CONSEQUENTIAL DAMAGES OR LOSS AS
A RESULT OF MODIFYING, DISTRIBUTING, OR OTHERWISE USING PYTHON,
OR ANY DERIVATIVE THEREOF, EVEN IF ADVISED OF THE POSSIBILITY THEREOF.

6. This License Agreement will automatically terminate upon a material
breach of its terms and conditions.

7. Nothing in this License Agreement shall be deemed to create any
relationship of agency, partnership, or joint venture between PSF and
Licensee.  This License Agreement does not grant permission to use PSF
trademarks or trade name in a trademark sense to endorse or promote
products or services of Licensee, or any third party.

8. By copying, installing or otherwise using Python, Licensee
agrees to be bound by the terms and conditions of this License
Agreement.
```

The design documents under `docs/parity/` also quote short passages of `difflib.py`; the same
notice applies to those quotes.

---

## Zydis (MIT License)

Source: <https://github.com/zyantific/zydis>, v4.1.1, commit
`a2278f1d254e492f6a6b39f6cb5d1f5d515659dc`.

```
The MIT License (MIT)

Copyright (c) 2014-2024 Florian Bernd
Copyright (c) 2014-2024 Joel Höner

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## Zycore (MIT License)

Source: <https://github.com/zyantific/zycore-c>, commit
`75a36c45ae1ad382b0f4e0ede0af84c11ee69928`.

```
The MIT License (MIT)

Copyright (c) 2018-2024 Florian Bernd
Copyright (c) 2018-2024 Joel Höner

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## SQLite (public domain)

Source: <https://www.sqlite.org/>, version 3.51.1, the official amalgamation
(`sqlite-amalgamation-3510100.zip`, pinned by SHA3-256 in `cmake/VendoredSqlite.cmake`), compiled
with the same options as the SQLite that produced the parity reference results.

SQLite is in the public domain and needs no licence. Its source carries this notice:

```
The author disclaims copyright to this source code.  In place of
a legal notice, here is a blessing:

   May you do good and not evil.
   May you find forgiveness for yourself and forgive others.
   May you share freely, never taking more than you give.
```

---

## Not bundled: Diaphora, IDA Pro and Hex-Rays

These programs are **not** included in the source tree or in any release archive, and no licence
for them comes with DSigMatcher:

- **Diaphora** (AGPL-3.0-or-later, Joxean Koret). DSigMatcher's engine is a port of Diaphora's
  diffing logic (see `NOTICE`), but Diaphora's own files are not distributed. The `extract`,
  `ingest` and `update` commands import an unmodified Diaphora checkout that you supply.
- **IDA Pro** with **idalib**, and the **Hex-Rays decompiler** (commercial products of Hex-Rays SA).
  `extract`, `ingest` and `update` need a licensed installation of your own. `diff`, `port` and
  `info` do not use them.
