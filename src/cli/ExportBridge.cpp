// L0 STUB of lane L10 (export bridge: `extract` and `ingest`, plan §7.1 D7 / §7.2). L10 replaces
// this file with the launcher of tools/export/dsig_export.py.

#include "dsigmatcher/cli/Commands.h"

namespace DSig::Cli {

CommandOutcome RunExtract(const ExtractArgs&) {
  CommandOutcome Outcome;
  Outcome.ExitCode = kExitUnsupported;
  Outcome.Message = "extract: not implemented (export bridge, lane L10)";
  return Outcome;
}

CommandOutcome RunIngest(const IngestArgs&) {
  CommandOutcome Outcome;
  Outcome.ExitCode = kExitUnsupported;
  Outcome.Message = "ingest: not implemented (export bridge, lane L10)";
  return Outcome;
}

}
