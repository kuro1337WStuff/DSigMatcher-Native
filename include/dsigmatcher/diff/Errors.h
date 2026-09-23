#pragma once

// Error model of the parity engine (docs/parity/00-plan.md §3.11).
//
// The core library is exception-free; DSig::Diff uses exceptions because it is a literal port of
// Python's propagation. RunDiff (Pipeline.h) is the only exception boundary and maps:
//   UsageRefused              -> exit 2 (a command line the engine refuses before touching any file)
//   DiaphoraWouldRaise        -> exit 3, no output file (Python raises, save_results never runs)
//   UnsupportedInput          -> exit 4 (a configuration or input quirk the port refuses instead of guessing)
//   IoFailure                 -> exit 6
//   SqliteEnvironmentFailure  -> exit 6 (an IoFailure: the environment, not the data, made SQLite fail)
// Only DiaphoraWouldRaise is ever caught inside the engine (the heuristic workers truncate a heuristic on
// it, as Python's threads do); every other type always reaches RunDiff.

#include <stdexcept>
#include <string>
#include <utility>

namespace DSig::Diff {

// A point at which unmodified Diaphora would raise. `Site` names the Python site (for example
// "D:1672 float(None)"), `Detail` the value that triggered it.
class DiaphoraWouldRaise : public std::runtime_error {
public:
  DiaphoraWouldRaise(std::string SiteText, std::string DetailText)
      : std::runtime_error("DIAPHORA_WOULD_RAISE " + SiteText + ": " + DetailText),
        Site(std::move(SiteText)),
        Detail(std::move(DetailText)) {}

  std::string Site;
  std::string Detail;
};

// An input or configuration the native engine deliberately refuses (exit 4).
class UnsupportedInput : public std::runtime_error {
public:
  explicit UnsupportedInput(std::string WhatText)
      : std::runtime_error(WhatText), What(std::move(WhatText)) {}

  std::string What;
};

// A file could not be opened, read or written (exit 6). Not a Diaphora behaviour.
class IoFailure : public std::runtime_error {
public:
  explicit IoFailure(std::string WhatText)
      : std::runtime_error(WhatText), What(std::move(WhatText)) {}

  std::string What;
};

// SQLite failed because of the environment rather than the data or the SQL: a full disk, an I/O error,
// a temporary file that cannot be created (a missing TMP directory), no memory, a corrupt or foreign
// database file, a lock, a read-only file. Python would raise too, but such a failure is not a
// Diaphora-parity raise: a heuristic worker must not swallow it (the run would silently lose rows), so it
// derives from IoFailure (exit 6), never from DiaphoraWouldRaise. `Code` is the extended result code.
class SqliteEnvironmentFailure : public IoFailure {
public:
  SqliteEnvironmentFailure(std::string WhatText, int ExtendedCode)
      : IoFailure(std::move(WhatText)), Code(ExtendedCode) {}

  int Code = 0;
};

// A command line the engine refuses before it reads or writes anything (exit 2): an output path that
// aliases an input or one of its sidecar files, or a write target inside an oracle capture or a
// directory that is not a snapshot capture.
class UsageRefused : public std::runtime_error {
public:
  explicit UsageRefused(std::string WhatText)
      : std::runtime_error(WhatText), What(std::move(WhatText)) {}

  std::string What;
};

}
