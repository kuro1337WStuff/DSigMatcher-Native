// L0 STUB of lane L11 (`port --results`, plan §7.1 D6 / §7.2). L11 replaces this file with the port
// that applies a .diaphora results file to the target export.

#include "dsigmatcher/cli/Commands.h"

namespace DSig::Cli {

CommandOutcome RunPortFromResults(const PortFromResultsArgs&) {
  CommandOutcome Outcome;
  Outcome.ExitCode = kExitUnsupported;
  Outcome.Message = "port --results: not implemented (lane L11)";
  return Outcome;
}

}
