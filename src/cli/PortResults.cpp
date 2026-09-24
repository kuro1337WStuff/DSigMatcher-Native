// `dsigmatcher port <ref.sqlite> <target.sqlite> -o <out.sqlite> [--results <x.diaphora>]`
//
// Without --results the parity diff runs in-process first (Diff::RunDiff, exactly what `dsigmatcher
// diff` runs) and writes its results file beside the output; the port then applies that file exactly
// as `port --results` would. With --results the rows of the given file are applied.
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
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "dsigmatcher/Provenance.h"
#include "dsigmatcher/cli/Commands.h"
#include "dsigmatcher/diff/Pipeline.h"

namespace DSig::Cli {

namespace {

using Diff::JsonValue;

std::filesystem::path PathOf(const std::string& Utf8) {
  try {
    return std::filesystem::path(std::u8string(Utf8.begin(), Utf8.end()));
  } catch (const std::exception&) {
    return std::filesystem::path(Utf8);
  }
}

std::string Utf8Of(const std::filesystem::path& Path) {
  const std::u8string Text = Path.u8string();
  return std::string(Text.begin(), Text.end());
}

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
// result does not depend on the C locale's decimal point beyond the default "C" locale. No clamp is
// applied: Diaphora never stores a ratio above 1.0 (check_ratio clamps to 0.99, 03a step 5, and both
// bonus sites test `r + MATCHES_BONUS_RATIO < 1.0` first, D:2203-2204 and D:3109-3110), so
// confidence = ratio x parent confidence stays within [0, 1] for Diaphora-produced results.
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

// Reads every results row. ExitCode on failure: kExitIo when the file is not an SQLite database at
// all, kExitUnsupported when it is one but not a Diaphora results file.
bool ReadResultsFile(const std::string& Path, ResultsFile& Out, std::string& Error, int& ExitCode) {
  sqlite3* Handle = nullptr;
  const std::string Uri = ReadOnlyDatabaseUri(Path);
  ExitCode = kExitIo;
  if (sqlite3_open_v2(Uri.c_str(), &Handle, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, nullptr) != SQLITE_OK) {
    Error = "cannot open it: " + std::string(Handle != nullptr ? sqlite3_errmsg(Handle) : "cannot allocate handle");
    sqlite3_close(Handle);
    return false;
  }
  // A read-only open succeeds on any file; the first schema read tells whether it is a database.
  char* Probe = nullptr;
  if (sqlite3_exec(Handle, "pragma schema_version", nullptr, nullptr, &Probe) != SQLITE_OK) {
    Error = "not an SQLite database (" + std::string(Probe != nullptr ? Probe : sqlite3_errmsg(Handle)) + ")";
    sqlite3_free(Probe);
    sqlite3_close(Handle);
    return false;
  }
  ExitCode = kExitUnsupported;
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

void RemoveResultsFile(const std::string& Path) {
  std::error_code Error;
  for (const char* Suffix : {"", "-wal", "-shm", "-journal"}) {
    std::filesystem::remove(PathOf(Path + Suffix), Error);
  }
}

// The diff's exit code. RunDiff reports an unexpected exception as an I/O failure whose message starts
// with "internal error: "; the CLI reports that as an internal error instead.
int DiffExitCode(const Diff::DiffOutcome& Outcome) {
  if (Outcome.Status == Diff::DiffStatus::Io && Outcome.Message.rfind("internal error: ", 0) == 0) {
    return kExitInternal;
  }
  return static_cast<int>(Outcome.Status);
}

}

std::string DefaultResultsPath(const std::string& Output) {
  const std::filesystem::path Native = PathOf(Output);
  return Utf8Of(Native.parent_path() / PathOf(Diff::PathStem(Utf8Of(Native.filename())) + ".diaphora"));
}

CommandOutcome RunPortFromResults(const PortFromResultsArgs& Args) {
  CommandOutcome Outcome;
  const bool InProcess = Args.Results.empty();
  std::string ResultsPath = Args.Results;
  bool DiffRan = false;
  const auto Failure = [&](int Code, std::string Message) {
    Outcome.ExitCode = Code;
    Outcome.Message = std::move(Message);
    Outcome.Report.clear();
    if (InProcess && DiffRan && !Args.KeepResults) {
      RemoveResultsFile(ResultsPath);
    }
    return Outcome;
  };

  if (!InProcess && (Args.StrictSqlite || Args.AllowSqliteMismatch || Args.IgnoreSmallFunctions || Args.Quiet ||
                     !Args.KeepResults || !Args.ResultsOutput.empty())) {
    return Failure(kExitUsage,
                   "--strict-sqlite, --allow-sqlite-mismatch, --ignore-small-functions, --quiet and "
                   "--no-keep-results configure the in-process diff; they do not apply to port --results");
  }
  if (Args.Reference.empty() || Args.Target.empty() || Args.Output.empty()) {
    return Failure(kExitUsage, "port needs <reference> <target> -o <output>");
  }
  if (!(Args.MinRatio >= 0.0 && Args.MinRatio <= 1.0)) {
    return Failure(kExitUsage, "min-ratio must be a number between 0.0 and 1.0");
  }
  if (Args.MaxHops < -1) {
    return Failure(kExitUsage, "max-hops must be zero or greater");
  }
  if (Args.OverwriteStripped && !Args.Overwrite) {
    return Failure(kExitUsage, "--overwrite-stripped needs --overwrite-existing");
  }

  if (InProcess) {
    ResultsPath = !Args.ResultsOutput.empty()
                      ? Args.ResultsOutput
                      : (Args.KeepResults ? DefaultResultsPath(Args.Output) : Args.Output + ".dsig-results-tmp");
  }

  // Every refusal the port itself would make is made before the diff runs, so a port that cannot
  // succeed never replaces an existing results file: the results file (written by the diff) and the
  // output files (written by the port) must not alias the inputs or each other.
  {
    std::vector<NamedPath> Inputs = DatabaseFileSet("the reference database", Args.Reference);
    for (NamedPath& File : DatabaseFileSet("the target database", Args.Target)) {
      Inputs.push_back(std::move(File));
    }
    std::vector<NamedPath> Written = DatabaseFileSet("the output", Args.Output);
    for (NamedPath& File : DatabaseFileSet("the temporary output", Args.Output + ".dsig-tmp")) {
      Written.push_back(std::move(File));
    }
    if (InProcess) {
      const std::vector<NamedPath> Results = DatabaseFileSet("the results file", ResultsPath);
      if (const std::optional<std::string> Alias = FindPathAlias(Results, Inputs)) {
        return Failure(kExitUsage, *Alias);
      }
      if (const std::optional<std::string> Alias = FindPathAlias(Written, Results)) {
        return Failure(kExitUsage, *Alias + "; choose another -o");
      }
    } else {
      for (NamedPath& File : DatabaseFileSet("the results file", ResultsPath)) {
        Inputs.push_back(std::move(File));
      }
    }
    if (const std::optional<std::string> Alias = FindPathAlias(Written, Inputs)) {
      return Failure(kExitUsage, *Alias);
    }
    const std::filesystem::path Directory = PathOf(Args.Output).parent_path();
    std::error_code Error;
    if (!Directory.empty() && !std::filesystem::is_directory(Directory, Error)) {
      return Failure(kExitIo, "output directory '" + Utf8Of(Directory) + "' does not exist");
    }
  }

  JsonValue DiffData = JsonValue::Null();
  if (InProcess) {
    // The inputs are checked the way the port checks them, so a missing or wrong reference is reported
    // by path before the diff opens anything.
    for (const auto& [Role, Path] : {std::pair<const char*, const std::string*>{"reference", &Args.Reference},
                                     std::pair<const char*, const std::string*>{"target", &Args.Target}}) {
      const DatabaseIdentity Identity = InspectDatabase(*Path);
      if (!Identity.Ok) {
        return Failure(Identity.Failure == PortFailure::Input ? kExitUnsupported : kExitIo,
                       std::string(Role) + ": " + Identity.Error);
      }
    }
    Diff::DiffArgs Diffing;
    Diffing.Db1 = Args.Reference;
    Diffing.Db2 = Args.Target;
    Diffing.Out = ResultsPath;
    Diffing.Config.IgnoreSmallFunctions = Args.IgnoreSmallFunctions;
    Diffing.StrictSqlite = Args.StrictSqlite;
    Diffing.AllowSqliteMismatch = Args.AllowSqliteMismatch;
    Diffing.Quiet = Args.Quiet;
    DiffRan = true;
    const Diff::DiffOutcome Diffed = Diff::RunDiff(Diffing);
    if (Diffed.Status != Diff::DiffStatus::Ok) {
      return Failure(DiffExitCode(Diffed), "diff: " + Diffed.Message);
    }
    DiffData = JsonValue::Object();
    DiffData.Set("mode", JsonValue::String(std::string(1, Diffed.Mode)));
    DiffData.Set("best", JsonValue::UInt(Diffed.Best));
    DiffData.Set("partial", JsonValue::UInt(Diffed.Partial));
    DiffData.Set("unreliable", JsonValue::UInt(Diffed.Unreliable));
    DiffData.Set("multimatch", JsonValue::UInt(Diffed.Multimatch));
    Outcome.Report.push_back("diff             : mode " + std::string(1, Diffed.Mode) + ", best " +
                             std::to_string(Diffed.Best) + ", partial " + std::to_string(Diffed.Partial) +
                             ", unreliable " + std::to_string(Diffed.Unreliable) + ", multimatch " +
                             std::to_string(Diffed.Multimatch));
  }

  std::error_code Error;
  if (!std::filesystem::is_regular_file(PathOf(ResultsPath), Error)) {
    return Failure(kExitIo, "cannot open results file '" + ResultsPath + "'");
  }

  ResultsFile Results;
  std::string ReadError;
  int ReadExit = kExitIo;
  if (!ReadResultsFile(ResultsPath, Results, ReadError, ReadExit)) {
    return Failure(ReadExit, "results file '" + ResultsPath + "': " + ReadError);
  }
  const std::string ResultsSha256 = FileSha256Hex(ResultsPath).value_or(std::string());

  // Rows of another pair are refused row by row (PortLabels), which an empty results file never
  // reaches. An empty file whose config names other exports is most likely the empty results of a
  // failed diff of another pair (diff exit 4), so the port warns. It does not refuse: the exports of a
  // genuine empty diff may have been renamed or moved since.
  std::vector<std::string> Warnings;
  if (!InProcess && Results.Rows.empty()) {
    const auto BaseName = [](const std::string& Path) {
      const size_t Slash = Path.find_last_of("/\\");
      std::string Name = Slash == std::string::npos ? Path : Path.substr(Slash + 1);
#ifdef _WIN32
      for (char& Character : Name) {
        if (Character >= 'A' && Character <= 'Z') {
          Character = static_cast<char>(Character - 'A' + 'a');
        }
      }
#endif
      return Name;
    };
    const bool MainDiffers = !Results.MainDb.empty() && BaseName(Results.MainDb) != BaseName(Args.Reference);
    const bool DiffDiffers = !Results.DiffDb.empty() && BaseName(Results.DiffDb) != BaseName(Args.Target);
    if (MainDiffers || DiffDiffers) {
      Warnings.push_back("results file '" + ResultsPath + "' has no rows and was made for '" + Results.MainDb +
                         "' / '" + Results.DiffDb + "', not for '" + BaseName(Args.Reference) + "' / '" +
                         BaseName(Args.Target) + "'; the port records a hop with no names");
      std::fprintf(stderr, "warning: %s\n", Warnings.back().c_str());
      std::fflush(stderr);
    }
  }

  for (LabelProposal& Row : Results.Rows) {
    Row.Selected = Row.Category == "best" || Row.Category == "partial" ||
                   (Row.Category == "unreliable" && Args.IncludeUnreliable) ||
                   (Row.Category == "multimatch" && Args.IncludeMultimatch);
  }

  LabelPortOptions Options;
  Options.ReferencePath = Args.Reference;
  Options.TargetPath = Args.Target;
  Options.OutputPath = Args.Output;
  Options.OtherInputs = {ResultsPath};
  Options.OverwriteExistingNames = Args.Overwrite;
  Options.OverwriteStripped = Args.OverwriteStripped;
  Options.MinCumulativeRatio = Args.MinRatio;
  Options.MaxHops = Args.MaxHops;
  Options.StoreFullPaths = Args.StoreFullPaths;
  Options.ResultsPath = ResultsPath;
  Options.ResultsSha256 = ResultsSha256;
  Options.ResultsMainDb = Results.MainDb;
  Options.ResultsDiffDb = Results.DiffDb;
  Options.ResultsVersion = Results.Version;
  Options.ResultsDate = Results.Date;
  Options.ResultsSource = InProcess ? "in-process diff" : "results file";
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
  if (InProcess && !Args.KeepResults) {
    RemoveResultsFile(ResultsPath);
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
  const auto PerCategoryJson = [](const std::map<std::string, int64_t>& Counts) {
    JsonValue Object = JsonValue::Object();
    for (const char* Category : {"best", "partial", "unreliable", "multimatch"}) {
      const auto Found = Counts.find(Category);
      Object.Set(Category, JsonValue::Int(Found == Counts.end() ? 0 : Found->second));
    }
    return Object;
  };
  std::string Categories = "best, partial";
  if (Args.IncludeUnreliable) {
    Categories += ", unreliable";
  }
  if (Args.IncludeMultimatch) {
    Categories += ", multimatch";
  }
  const std::string ResultsShown =
      InProcess ? ResultsPath + (Args.KeepResults ? " (in-process diff, kept)" : " (in-process diff, deleted)")
                : ResultsPath;

  Outcome.ExitCode = kExitOk;
  const std::vector<std::string> Lines = {
      "reference        : " + Args.Reference,
      "target           : " + Args.Target,
      "results          : " + ResultsShown,
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
  Outcome.Report.insert(Outcome.Report.end(), Lines.begin(), Lines.end());

  JsonValue Data = JsonValue::Object();
  Data.Set("reference", JsonValue::String(Args.Reference));
  Data.Set("target", JsonValue::String(Args.Target));
  Data.Set("output", JsonValue::String(Args.Output));
  Data.Set("output_sha256", JsonValue::String(Port.OutputSha256));
  Data.Set("results", JsonValue::String(ResultsPath));
  Data.Set("results_sha256", JsonValue::String(Options.ResultsSha256));
  Data.Set("results_source", JsonValue::String(Options.ResultsSource));
  Data.Set("results_kept", JsonValue::Bool(!InProcess || Args.KeepResults));
  Data.Set("diff", std::move(DiffData));
  Data.Set("lineage", JsonValue::String(Port.Lineage));
  Data.Set("hop", JsonValue::Int(Port.NewHop));
  Data.Set("functions_reference", JsonValue::Int(Port.FunctionsReference));
  Data.Set("functions_target", JsonValue::Int(Port.FunctionsTarget));
  Data.Set("results_rows", PerCategoryJson(Results.RowsPerCategory));
  JsonValue Selected = JsonValue::Array();
  for (const char* Category : {"best", "partial", "unreliable", "multimatch"}) {
    const std::string Name(Category);
    if (Name == "best" || Name == "partial" || (Name == "unreliable" && Args.IncludeUnreliable) ||
        (Name == "multimatch" && Args.IncludeMultimatch)) {
      Selected.Push(JsonValue::String(Name));
    }
  }
  Data.Set("selected_categories", std::move(Selected));
  Data.Set("proposals", JsonValue::Int(Port.Proposals));
  Data.Set("selected", JsonValue::Int(Port.Selected));
  Data.Set("names_applied", JsonValue::Int(Port.NamesApplied));
  Data.Set("names_applied_per_category", PerCategoryJson(AppliedPerCategory));
  Data.Set("names_confirmed", JsonValue::Int(Port.NamesConfirmed));
  Data.Set("skipped_existing", JsonValue::Int(Port.NamesSkippedExisting));
  Data.Set("skipped_hops", JsonValue::Int(Port.NamesSkippedHops));
  Data.Set("skipped_ratio", JsonValue::Int(Port.NamesSkippedRatio));
  Data.Set("skipped_not_portable", JsonValue::Int(Port.NamesSkippedNotPortable));
  Data.Set("skipped_conflict", JsonValue::Int(Port.NamesSkippedConflict));
  Data.Set("skipped_duplicate", JsonValue::Int(Port.NamesSkippedDuplicate));
  JsonValue WarningsJson = JsonValue::Array();
  for (const std::string& Warning : Warnings) {
    WarningsJson.Push(JsonValue::String(Warning));
  }
  Data.Set("warnings", std::move(WarningsJson));
  Outcome.Data = std::move(Data);
  return Outcome;
}

}
