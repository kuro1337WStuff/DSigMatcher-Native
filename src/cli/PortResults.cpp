// `dsigmatcher port <ref.sqlite> <target.sqlite> -o <out.sqlite> --results <x.diaphora>`
// (docs/parity/00-plan.md §7.1 D6, lane L11).
//
// Reads a Diaphora results database, written by `python diaphora.py db1 db2 -o x.diaphora` or by our
// own `diff`, turns every `results` row into a LabelProposal and hands them to DSig::PortLabels
// (src/Provenance.cpp), which writes the labelled copy of the target. Best and partial rows are
// applied by default; unreliable and multimatch rows only with --include-unreliable /
// --include-multimatch. Rows of the other categories are still read, checked and logged
// (dsig_port_log.action = 'not_selected'), so a scorer can judge them too.
//
// The results file layout is Diaphora's save_results (D:2374-2429; 01 §11; 09 "Results database
// schema"): results(type, line, address, name, address2, name2, ratio, nodes1, nodes2, description),
// every value TEXT; address/address2 are "%08x" % int(ea) (D:280-288); ratio is "%.7f" (D:282);
// rows are stored best, partial, unreliable, multimatch, each in chooser order (D:2405-2424), which is
// descending ratio (D:2926). The file's rowid order is that stored order.

#include <sqlite3.h>

#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "dsigmatcher/Provenance.h"
#include "dsigmatcher/Sha256.h"
#include "dsigmatcher/cli/Commands.h"

namespace DSig::Cli {

namespace {

struct ResultsFile {
  std::vector<LabelProposal> Rows;
  std::map<std::string, int64_t> RowsPerCategory;
  std::string MainDb;
  std::string DiffDb;
  std::string Version;
  std::string Date;
};

std::optional<std::string> ColumnOptional(sqlite3_stmt* Statement, int Index) {
  if (sqlite3_column_type(Statement, Index) == SQLITE_NULL) {
    return std::nullopt;
  }
  const unsigned char* Text = sqlite3_column_text(Statement, Index);
  const int Length = sqlite3_column_bytes(Statement, Index);
  if (Text == nullptr || Length <= 0) {
    return std::string();
  }
  return std::string(reinterpret_cast<const char*>(Text), static_cast<size_t>(Length));
}

std::string ColumnText(sqlite3_stmt* Statement, int Index) {
  return ColumnOptional(Statement, Index).value_or(std::string());
}

// "%08x" % int(ea) (D:280-288): lowercase hex digits, zero-padded to at least 8. Upper case is
// accepted too. A negative ea would print as "-0000001" (01 §10.2); it cannot name a function.
std::optional<uint64_t> ParseHexAddress(std::string_view Text) {
  if (Text.empty() || Text.size() > 16) {
    return std::nullopt;
  }
  uint64_t Value = 0;
  for (const char Character : Text) {
    unsigned Digit = 0;
    if (Character >= '0' && Character <= '9') {
      Digit = static_cast<unsigned>(Character - '0');
    } else if (Character >= 'a' && Character <= 'f') {
      Digit = static_cast<unsigned>(Character - 'a' + 10);
    } else if (Character >= 'A' && Character <= 'F') {
      Digit = static_cast<unsigned>(Character - 'A' + 10);
    } else {
      return std::nullopt;
    }
    Value = (Value << 4) | Digit;
  }
  return Value;
}

// "%.7f" % ratio (D:282): digits, one '.', digits. Only those characters are passed to strtod, so the
// result does not depend on the C locale's decimal point beyond the default "C" locale.
std::optional<double> ParseRatio(std::string_view Text) {
  if (Text.empty()) {
    return std::nullopt;
  }
  bool SeenDot = false;
  bool SeenDigit = false;
  for (const char Character : Text) {
    if (Character == '.') {
      if (SeenDot) {
        return std::nullopt;
      }
      SeenDot = true;
    } else if (Character >= '0' && Character <= '9') {
      SeenDigit = true;
    } else {
      return std::nullopt;
    }
  }
  if (!SeenDigit) {
    return std::nullopt;
  }
  const std::string Copy(Text);
  char* End = nullptr;
  const double Value = std::strtod(Copy.c_str(), &End);
  if (End == nullptr || *End != '\0') {
    return std::nullopt;
  }
  return Value;
}

bool HasTable(sqlite3* Handle, const char* Table) {
  sqlite3_stmt* Statement = nullptr;
  if (sqlite3_prepare_v2(Handle, "select 1 from sqlite_master where type = 'table' and name = ?", -1, &Statement,
                         nullptr) != SQLITE_OK) {
    return false;
  }
  sqlite3_bind_text(Statement, 1, Table, -1, SQLITE_TRANSIENT);
  const bool Found = sqlite3_step(Statement) == SQLITE_ROW;
  sqlite3_finalize(Statement);
  return Found;
}

bool ReadResultsFile(const std::string& Path, ResultsFile& Out, std::string& Error) {
  sqlite3* Handle = nullptr;
  const std::string Uri = ReadOnlyDatabaseUri(Path);
  if (sqlite3_open_v2(Uri.c_str(), &Handle, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, nullptr) != SQLITE_OK) {
    Error = Handle != nullptr ? sqlite3_errmsg(Handle) : "cannot allocate handle";
    sqlite3_close(Handle);
    return false;
  }
  bool Ok = true;
  if (!HasTable(Handle, "results")) {
    Error = "no 'results' table; not a Diaphora results file";
    Ok = false;
  }

  if (Ok && HasTable(Handle, "config")) {
    sqlite3_stmt* Config = nullptr;
    if (sqlite3_prepare_v2(Handle, "select main_db, diff_db, version, date from config", -1, &Config, nullptr) ==
        SQLITE_OK) {
      if (sqlite3_step(Config) == SQLITE_ROW) {
        Out.MainDb = ColumnText(Config, 0);
        Out.DiffDb = ColumnText(Config, 1);
        Out.Version = ColumnText(Config, 2);
        Out.Date = ColumnText(Config, 3);
      }
    }
    sqlite3_finalize(Config);
  }

  sqlite3_stmt* Rows = nullptr;
  if (Ok && sqlite3_prepare_v2(Handle,
                               "select rowid, type, line, address, name, address2, name2, ratio, description "
                               "from results order by rowid",
                               -1, &Rows, nullptr) != SQLITE_OK) {
    Error = std::string("'results' does not have Diaphora's columns: ") + sqlite3_errmsg(Handle);
    Ok = false;
  }
  int Code = SQLITE_DONE;
  while (Ok && (Code = sqlite3_step(Rows)) == SQLITE_ROW) {
    LabelProposal Row;
    Row.SourceRow = sqlite3_column_int64(Rows, 0);
    Row.Category = ColumnText(Rows, 1);
    Row.Line = ColumnText(Rows, 2);
    const std::string Address = ColumnText(Rows, 3);
    Row.ReferenceName = ColumnOptional(Rows, 4);
    const std::string Address2 = ColumnText(Rows, 5);
    Row.TargetName = ColumnOptional(Rows, 6);
    Row.RatioText = ColumnText(Rows, 7);
    Row.Description = ColumnText(Rows, 8);
    const std::string Where = "results row " + std::to_string(Row.SourceRow);
    if (Row.Category != "best" && Row.Category != "partial" && Row.Category != "unreliable" &&
        Row.Category != "multimatch") {
      Error = Where + ": unknown type '" + Row.Category + "'";
      Ok = false;
      break;
    }
    const std::optional<uint64_t> Ea = ParseHexAddress(Address);
    const std::optional<uint64_t> Ea2 = ParseHexAddress(Address2);
    if (!Ea || !Ea2) {
      Error = Where + ": address '" + Address + "' / address2 '" + Address2 + "' is not \"%08x\" hex";
      Ok = false;
      break;
    }
    const std::optional<double> Ratio = ParseRatio(Row.RatioText);
    if (!Ratio) {
      Error = Where + ": ratio '" + Row.RatioText + "' is not \"%.7f\" text";
      Ok = false;
      break;
    }
    Row.ReferenceEa = *Ea;
    Row.TargetEa = *Ea2;
    Row.Ratio = *Ratio;
    ++Out.RowsPerCategory[Row.Category];
    Out.Rows.push_back(std::move(Row));
  }
  if (Ok && Code != SQLITE_DONE) {
    Error = sqlite3_errmsg(Handle);
    Ok = false;
  }
  sqlite3_finalize(Rows);
  sqlite3_close(Handle);
  return Ok;
}

std::string Count(int64_t Value) { return std::to_string(Value); }

}

CommandOutcome RunPortFromResults(const PortFromResultsArgs& Args) {
  CommandOutcome Outcome;
  const auto Failure = [&Outcome](int Code, std::string Message) {
    Outcome.ExitCode = Code;
    Outcome.Message = std::move(Message);
    Outcome.Report.clear();
    return Outcome;
  };

  if (Args.Results.empty()) {
    return Failure(kExitUnsupported,
                   "port without --results runs the parity diff in-process (lane L9); not implemented yet");
  }
  if (Args.StrictSqlite || Args.IgnoreSmallFunctions) {
    return Failure(kExitUsage, "--strict-sqlite and --ignore-small-functions configure the in-process diff; "
                               "they do not apply to port --results");
  }
  if (Args.Reference.empty() || Args.Target.empty() || Args.Output.empty()) {
    return Failure(kExitUsage, "port --results needs <reference> <target> -o <output>");
  }
  if (!(Args.MinRatio >= 0.0 && Args.MinRatio <= 1.0)) {
    return Failure(kExitUsage, "min-ratio must be between 0.0 and 1.0");
  }
  if (Args.MaxHops < -1) {
    return Failure(kExitUsage, "max-hops must be zero or greater");
  }
  std::error_code Error;
  if (!std::filesystem::is_regular_file(Args.Results, Error)) {
    return Failure(kExitIo, "cannot open results file '" + Args.Results + "'");
  }

  ResultsFile Results;
  std::string ReadError;
  if (!ReadResultsFile(Args.Results, Results, ReadError)) {
    return Failure(kExitUnsupported, "results file '" + Args.Results + "': " + ReadError);
  }
  bool HashOk = false;
  const std::string ResultsSha256 = Sha256::FileHex(Args.Results, HashOk);

  for (LabelProposal& Row : Results.Rows) {
    Row.Selected = Row.Category == "best" || Row.Category == "partial" ||
                   (Row.Category == "unreliable" && Args.IncludeUnreliable) ||
                   (Row.Category == "multimatch" && Args.IncludeMultimatch);
  }

  LabelPortOptions Options;
  Options.ReferencePath = Args.Reference;
  Options.TargetPath = Args.Target;
  Options.OutputPath = Args.Output;
  Options.OtherInputs = {Args.Results};
  Options.OverwriteExistingNames = Args.Overwrite;
  Options.MinCumulativeRatio = Args.MinRatio;
  Options.MaxHops = Args.MaxHops;
  Options.ResultsPath = Args.Results;
  Options.ResultsSha256 = HashOk ? ResultsSha256 : std::string();
  Options.ResultsMainDb = Results.MainDb;
  Options.ResultsDiffDb = Results.DiffDb;
  Options.ResultsVersion = Results.Version;
  Options.ResultsDate = Results.Date;
  Options.IncludeMultimatch = Args.IncludeMultimatch;
  Options.IncludeUnreliable = Args.IncludeUnreliable;

  const LabelPortResult Port = PortLabels(Options, Results.Rows);
  if (!Port.Ok) {
    switch (Port.Failure) {
      case PortFailure::Usage:
        return Failure(kExitUsage, Port.Error);
      case PortFailure::Io:
        return Failure(kExitIo, Port.Error);
      case PortFailure::Input:
      case PortFailure::None:
        break;
    }
    return Failure(kExitUnsupported, Port.Error);
  }

  std::map<std::string, int64_t> AppliedPerCategory;
  for (size_t Index = 0; Index < Port.Decisions.size(); ++Index) {
    if (Port.Decisions[Index].Action == LabelAction::Applied) {
      ++AppliedPerCategory[Results.Rows[Index].Category];
    }
  }
  const auto PerCategory = [](const std::map<std::string, int64_t>& Counts) {
    std::string Text;
    for (const char* Category : {"best", "partial", "unreliable", "multimatch"}) {
      const auto Found = Counts.find(Category);
      Text += std::string(Text.empty() ? "" : ", ") + Category + " " +
              Count(Found == Counts.end() ? 0 : Found->second);
    }
    return Text;
  };
  std::string Categories = "best, partial";
  if (Args.IncludeUnreliable) {
    Categories += ", unreliable";
  }
  if (Args.IncludeMultimatch) {
    Categories += ", multimatch";
  }

  Outcome.ExitCode = kExitOk;
  Outcome.Report = {
      "reference        : " + Args.Reference,
      "target           : " + Args.Target,
      "results          : " + Args.Results,
      "results sha256   : " + Options.ResultsSha256,
      "output           : " + Args.Output,
      "output sha256    : " + Port.OutputSha256,
      "lineage          : " + Port.Lineage,
      "hop              : " + Count(Port.NewHop),
      "",
      "results rows     : " + Count(Port.Proposals) + " (" + PerCategory(Results.RowsPerCategory) + ")",
      "selected         : " + Count(Port.Selected) + " (" + Categories + ")",
      "names applied    : " + Count(Port.NamesApplied) + " (" + PerCategory(AppliedPerCategory) + ")",
      "names confirmed  : " + Count(Port.NamesConfirmed),
      "skipped existing : " + Count(Port.NamesSkippedExisting),
      "skipped hop cap  : " + Count(Port.NamesSkippedHops),
      "skipped ratio    : " + Count(Port.NamesSkippedRatio),
      "skipped no symbol: " + Count(Port.NamesSkippedNotPortable),
      "skipped conflict : " + Count(Port.NamesSkippedConflict),
      "skipped duplicate: " + Count(Port.NamesSkippedDuplicate),
      "label columns    : name, mangled_function",
  };
  return Outcome;
}

}
