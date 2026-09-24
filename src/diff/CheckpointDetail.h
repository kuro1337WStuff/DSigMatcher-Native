#pragma once

// Test hook of the checkpoint writer (include/dsigmatcher/diff/Checkpoint.h). Private to src/diff and
// the diff test suites; not part of the public API.

#include <string_view>

namespace DSig::Diff::Detail {

// Called by CheckpointStore::Write at each step: "state:write" and "state:rename" (the state file),
// "manifest:write" and "manifest:rename" (the manifest), then "committed" once the checkpoint is
// complete. A hook that throws IoFailure simulates a failure at that step (a full disk); a hook that ends
// the process simulates a kill there. nullptr (the default) disables it. Not thread-safe: tests set it
// around one run.
using CheckpointFaultHook = void (*)(std::string_view Step);
void SetCheckpointFaultHook(CheckpointFaultHook Hook);
CheckpointFaultHook GetCheckpointFaultHook();

}
