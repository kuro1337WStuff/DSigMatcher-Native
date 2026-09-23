#pragma once

// Error model of the parity engine (docs/parity/00-plan.md §3.11).
//
// The core library is exception-free; DSig::Diff uses exceptions because it is a literal port of
// Python's propagation. RunDiff (Pipeline.h) is the only exception boundary and maps:
//   DiaphoraWouldRaise   -> exit 3, no output file (Python raises, save_results never runs)
//   UnsupportedInput     -> exit 4 (a configuration or input quirk the port refuses instead of guessing)
//   IoFailure            -> exit 6
// StageNotImplemented is thrown only by the L0 stubs of functions other lanes own; the pipeline
// (InvokeStage in Pipeline.h) logs "SKIPPED" and continues. It never escapes RunDiff.

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

// Thrown by an L0 stub: "stage X not implemented". Caught by InvokeStage only.
class StageNotImplemented final : public UnsupportedInput {
public:
  explicit StageNotImplemented(const std::string& Stage)
      : UnsupportedInput("stage " + Stage + " not implemented"), StageName(Stage) {}

  std::string StageName;
};

// A file could not be opened, read or written (exit 6). Not a Diaphora behaviour.
class IoFailure : public std::runtime_error {
public:
  explicit IoFailure(std::string WhatText)
      : std::runtime_error(WhatText), What(std::move(WhatText)) {}

  std::string What;
};

}
