#pragma once

// The `.diaphora` results file: save_results (D:2374-2429) plus CChooser.add_item's formatting
// (D:275-296). Spec: 01 §10.2-§11, 09 "Results database schema". Every value is bound as TEXT.

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "dsigmatcher/diff/Interner.h"
#include "dsigmatcher/diff/MatchState.h"

namespace DSig::Diff {

// CChooser.Item(ea, name) of an "Unmatched in ..." chooser (D:2337-2338, D:2350-2351).
struct UnmatchedRow {
  AddrId Ea = kNoneAddr;
  NameId Name = kNoneName;
};

// The choosers save_results writes, in their add_item order.
struct FinalResults {
  std::vector<Item> Best;
  std::vector<Item> Partial;
  std::vector<Item> Unreliable;
  std::vector<Item> Multimatch;
  std::optional<std::vector<UnmatchedRow>> UnmatchedPrimary /*diff funcs, D:2343-2354*/;
  std::optional<std::vector<UnmatchedRow>> UnmatchedSecondary /*main, D:2330-2341*/;
};

struct WriteArgs {
  std::string OutPath;   // replaced if it exists (D:2379-2381); see WriteDiaphoraResults
  std::string MainDb;    // config.main_db: db1 exactly as passed on the command line
  std::string DiffDb;    // config.diff_db: db2 exactly as passed
  std::string Date;      // config.date; empty -> AscTimeNow()
};

// D:2374-2429. Throws IoFailure when the file cannot be written, DiaphoraWouldRaise where Python's
// formatting raises (for example "%08x" % int(ea) on a non-decimal ea). Every row is formatted before
// any file is touched. The database is written as "<OutPath>.tmp-<pid>" in the same directory and
// renamed over OutPath after the commit (a stale -journal / -wal / -shm of OutPath is removed first), so
// the bytes are save_results' but OutPath never holds a partial file: on any failure the temporary
// files are removed and an existing OutPath keeps its old content. ":memory:" is written directly.
void WriteDiaphoraResults(const WriteArgs& A, const FinalResults& R, const Interners& Ids);

// The scratch files WriteDiaphoraResults creates beside `Out` in this process (the temporary database
// and its sidecars), for the input-alias check of RunDiff.
std::vector<std::string> ResultsWriterScratchPaths(const std::string& Out);

std::string FormatLine05(uint64_t N);             // "%05lu" % n        (123456 -> "123456")
std::string FormatAddr08x(std::string_view Ea);   // "%08x" % int(ea)   (4294967296 -> "100000000")
std::string FormatRatio7(double Ratio);           // "%.7f" % ratio, correctly rounded half-even
std::string AscTimeNow();                         // time.asctime(): "Wed Sep  3 12:34:56 2026" (local time)

}
