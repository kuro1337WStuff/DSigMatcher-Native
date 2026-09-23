#include <sqlite3.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "dsigmatcher/ExportDatabase.h"
#include "dsigmatcher/Heuristics.h"
#include "dsigmatcher/Naming.h"
#include "dsigmatcher/Provenance.h"
#include "dsigmatcher/Types.h"
#include "dsigmatcher/cli/Commands.h"
#include "dsigmatcher/diff/Pipeline.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shellapi.h>
#endif

#ifndef DSIG_VERSION
#define DSIG_VERSION "0.0.0"
#endif

namespace {

using namespace DSig;

constexpr int kExitUsage = Cli::kExitUsage;

void PrintUsage() {
  std::printf("dsigmatcher %s - native Diaphora-compatible symbol porter\n\n", DSIG_VERSION);
  std::printf("usage:\n");
  std::printf("  dsigmatcher diff <db1.sqlite> <db2.sqlite> [-o <out.diaphora>] [options]\n");
  std::printf("  dsigmatcher port <reference.sqlite> <target.sqlite> -o <output.sqlite> [options]\n");
  std::printf("  dsigmatcher extract <in.i64|in.idb> -o <out.sqlite> [tool options]\n");
  std::printf("  dsigmatcher ingest <binary> -o <out.sqlite> [--pdb <file> | --no-pdb] [tool options]\n");
  std::printf("  dsigmatcher info <database.sqlite>\n");
  std::printf("\n");
  std::printf("diff (parity engine, the default): writes Diaphora's .diaphora results file. Without -o the\n");
  std::printf("name is <stem(db1)>_vs_<stem(db2)>.diaphora, as `python diaphora.py db1 db2` would choose.\n");
  std::printf("  -o, --output <path>              results file (deleted first; must not be an input)\n");
  std::printf("      --engine parity|legacy       legacy: the old hash-join engine and its tables\n");
  std::printf("      --format diaphora|legacy     output format (legacy only with --engine legacy)\n");
  std::printf("      --ignore-small-functions     %%POSTFIX%% = \" and f.instructions > 5 and df.instructions > 5 \"\n");
  std::printf("      --trace <file.jsonl>         JSONL trace of add_match / cleanup / point events\n");
  std::printf("      --trace-rows                 also one event per consumed SQL row\n");
  std::printf("      --snapshot-dir <dir>         a JSON snapshot at every point: <dir>/index.json lists\n");
  std::printf("                                   [seq, point, file], files are <dir>/snapshots/NNNNN_<point>.json\n");
  std::printf("                                   (tools/parity/oracle_trace.py layout; earlier snapshots replaced)\n");
  std::printf("      --snapshot-points <globs>    only points matching these globs (a|b, default *)\n");
  std::printf("      --snapshot-cache <globs>     include ratios_cache at these points\n");
  std::printf("      --pair <label>               pair label stored in snapshots\n");
  std::printf("      --replay <before.json> --stage <name> [--iteration k] [--heuristic id]\n");
  std::printf("               --snapshot-out <after.json>   run one stage from a snapshot\n");
  std::printf("      --related-cu-source native|sql\n");
  std::printf("      --strict-sqlite              exit 5 unless SQLite is the oracle's 3.51.1\n");
  std::printf("      --allow-sqlite-mismatch      do not warn about another SQLite version\n");
  std::printf("      --quiet                      no Diaphora summary lines on stderr (the SQLite version\n");
  std::printf("                                   warning is still printed; see --allow-sqlite-mismatch)\n");
  std::printf("  legacy engine only:\n");
  std::printf("  -t, --threads <n>                worker threads (default: hardware concurrency)\n");
  std::printf("      --assume-same-cpu            run processor specific heuristics unconditionally\n");
  std::printf("  exit codes: 0 ok, 2 usage, 3 Diaphora would raise (no output), 4 unsupported or not\n");
  std::printf("  implemented, 5 SQLite mismatch with --strict-sqlite, 6 I/O\n");
  std::printf("  environment: DIAPHORA_* variables are deliberately ignored. The parity engine is not\n");
  std::printf("  Diaphora and has no environment configuration: it always runs Diaphora's default\n");
  std::printf("  standalone configuration (docs/parity/00-plan.md 1.1), and the non-default settings\n");
  std::printf("  (--unreliable, --relaxed-ratio, --use-trained-model, --project-script) are refused.\n");
  std::printf("  paths: any UTF-8 / Unicode path, including UNC paths (\\\\server\\share\\...).\n");
  std::printf("\n");
  std::printf("port options:\n");
  std::printf("  -o, --output <path>              required; labelled copy of the target database\n");
  std::printf("      --results <x.diaphora>       apply this results file (ours or Diaphora's)\n");
  std::printf("      --include-multimatch         with --results: also apply multimatch rows\n");
  std::printf("      --include-unreliable         with --results: also apply unreliable rows\n");
  std::printf("      --min-ratio <r>              drop names whose cumulative confidence falls below r\n");
  std::printf("      --max-hops <n>               drop names that have travelled through more than n diffs\n");
  std::printf("      --overwrite-existing         replace real names already present in the target\n");
  std::printf("  without --results port uses the legacy engine (options -t, --ignore-small-functions,\n");
  std::printf("  --assume-same-cpu as for diff).\n");
  std::printf("\n");
  std::printf("extract / ingest tool options: --python <exe>, --ida-dir <dir>, --diaphora-dir <dir>\n");
  std::printf("  (else DSIG_PYTHON, DSIG_IDADIR, DSIG_DIAPHORA_DIR), --temp-dir <dir>, --keep-temp,\n");
  std::printf("  --timeout <seconds>\n");
  std::printf("\n");
  std::printf("The port output is itself a Diaphora-schema database, so it can be used as the\n");
  std::printf("reference for the next release without going back through IDA.\n");
}

// ---------------------------------------------------------------------------------------------
// Argument parsing

struct OptionSpec {
  const char* Name;   // canonical long name
  const char* Short;  // or nullptr
  bool TakesValue;
};

const std::vector<OptionSpec>& OptionsFor(const std::string& Command) {
  static const std::vector<OptionSpec> Diff = {
      {"--output", "-o", true},          {"--engine", nullptr, true},          {"--format", nullptr, true},
      {"--trace", nullptr, true},        {"--trace-rows", nullptr, false},     {"--snapshot-dir", nullptr, true},
      {"--snapshot-points", nullptr, true}, {"--snapshot-cache", nullptr, true}, {"--pair", nullptr, true},
      {"--replay", nullptr, true},       {"--stage", nullptr, true},           {"--iteration", nullptr, true},
      {"--heuristic", nullptr, true},    {"--snapshot-out", nullptr, true},    {"--related-cu-source", nullptr, true},
      {"--strict-sqlite", nullptr, false}, {"--allow-sqlite-mismatch", nullptr, false},
      {"--ignore-small-functions", nullptr, false}, {"--quiet", nullptr, false}, {"--threads", "-t", true},
      {"--assume-same-cpu", nullptr, false},
      // out of scope for the parity engine (plan §1.1): accepted so they can be refused with exit 4
      {"--unreliable", nullptr, false},  {"--relaxed-ratio", nullptr, false},  {"--use-trained-model", nullptr, false},
      {"--project-script", nullptr, true}};
  static const std::vector<OptionSpec> Port = {
      {"--output", "-o", true},           {"--results", nullptr, true},          {"--include-multimatch", nullptr, false},
      {"--include-unreliable", nullptr, false}, {"--overwrite", nullptr, false}, {"--overwrite-existing", nullptr, false},
      {"--min-ratio", nullptr, true},     {"--max-hops", nullptr, true},         {"--threads", "-t", true},
      {"--ignore-small-functions", nullptr, false}, {"--assume-same-cpu", nullptr, false},
      {"--strict-sqlite", nullptr, false}};
  static const std::vector<OptionSpec> Export = {
      {"--output", "-o", true},    {"--python", nullptr, true},   {"--ida-dir", nullptr, true},
      {"--diaphora-dir", nullptr, true}, {"--temp-dir", nullptr, true}, {"--keep-temp", nullptr, false},
      {"--timeout", nullptr, true}, {"--pdb", nullptr, true},     {"--no-pdb", nullptr, false}};
  static const std::vector<OptionSpec> None = {};
  if (Command == "diff") {
    return Diff;
  }
  if (Command == "port") {
    return Port;
  }
  if (Command == "extract" || Command == "ingest") {
    return Export;
  }
  return None;
}

struct Parsed {
  std::string Command;
  std::vector<std::string> Positional;
  std::map<std::string, std::string> Values;
  std::set<std::string> Flags;
  bool ShowHelp = false;
  bool Valid = true;
  std::string Error;

  bool Has(const std::string& Name) const { return Flags.count(Name) != 0 || Values.count(Name) != 0; }
  std::string Value(const std::string& Name) const {
    const auto Found = Values.find(Name);
    return Found == Values.end() ? std::string() : Found->second;
  }
};

Parsed ParseArguments(int Argc, char** Argv) {
  Parsed Result;
  if (Argc < 2) {
    Result.ShowHelp = true;
    Result.Valid = false;
    Result.Error = "no command given";
    return Result;
  }
  Result.Command = Argv[1];
  if (Result.Command == "-h" || Result.Command == "--help" || Result.Command == "help") {
    Result.ShowHelp = true;
    return Result;
  }
  static const std::set<std::string> Commands = {"diff", "port", "info", "extract", "ingest"};
  if (Commands.count(Result.Command) == 0) {
    Result.Valid = false;
    Result.Error = "unknown command '" + Result.Command + "'";
    return Result;
  }
  const std::vector<OptionSpec>& Specs = OptionsFor(Result.Command);
  for (int Index = 2; Index < Argc; ++Index) {
    const std::string Argument = Argv[Index];
    if (Argument == "-h" || Argument == "--help") {
      Result.ShowHelp = true;
      continue;
    }
    const OptionSpec* Spec = nullptr;
    for (const OptionSpec& Candidate : Specs) {
      if (Argument == Candidate.Name || (Candidate.Short != nullptr && Argument == Candidate.Short)) {
        Spec = &Candidate;
        break;
      }
    }
    if (Spec != nullptr) {
      if (Spec->TakesValue) {
        if (Index + 1 >= Argc) {
          Result.Valid = false;
          Result.Error = "option '" + Argument + "' requires a value";
          return Result;
        }
        Result.Values[Spec->Name] = Argv[++Index];
      } else {
        Result.Flags.insert(Spec->Name);
      }
      continue;
    }
    if (!Argument.empty() && Argument[0] == '-') {
      Result.Valid = false;
      Result.Error = "unknown option '" + Argument + "' for '" + Result.Command + "'";
      return Result;
    }
    Result.Positional.push_back(Argument);
  }
  const size_t Expected = (Result.Command == "diff" || Result.Command == "port") ? 2u : 1u;
  if (!Result.ShowHelp && Result.Positional.size() != Expected) {
    Result.Valid = false;
    Result.Error = "'" + Result.Command + "' expects " + std::to_string(Expected) + " path(s), got " +
                   std::to_string(Result.Positional.size());
    return Result;
  }
  const bool NeedsOutput = Result.Command == "port" || Result.Command == "extract" || Result.Command == "ingest";
  if (!Result.ShowHelp && NeedsOutput && !Result.Has("--output")) {
    Result.Valid = false;
    Result.Error = "'" + Result.Command + "' requires -o <output>";
    return Result;
  }
  return Result;
}

std::optional<long> ParseLong(const std::string& Text) {
  if (Text.empty()) {
    return std::nullopt;
  }
  char* End = nullptr;
  const long Value = std::strtol(Text.c_str(), &End, 10);
  if (End == nullptr || *End != '\0') {
    return std::nullopt;
  }
  return Value;
}

int UsageError(const std::string& Message) {
  std::fprintf(stderr, "error: %s\n\n", Message.c_str());
  PrintUsage();
  return kExitUsage;
}

// ---------------------------------------------------------------------------------------------
// Legacy engine (unchanged behaviour: the old hash-join heuristics and the matches /
// symbols_to_port tables)

bool WriteDiffResults(const std::string& Path, const FunctionTable& Reference, const FunctionTable& Target,
                      const std::vector<Match>& Matches, std::string& OutError, size_t& OutPorted) {
  sqlite3* Handle = nullptr;
  if (sqlite3_open_v2(Path.c_str(), &Handle, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) != SQLITE_OK) {
    OutError = Handle != nullptr ? sqlite3_errmsg(Handle) : "unable to allocate database handle";
    if (Handle != nullptr) {
      sqlite3_close(Handle);
    }
    return false;
  }

  char* ErrorMessage = nullptr;
  const int ExecCode = sqlite3_exec(
      Handle,
      "drop table if exists matches;"
      "drop table if exists symbols_to_port;"
      "create table matches (ea1 text, name1 text, ea2 text, name2 text, description text, ratio "
      "real, category text);"
      "create table symbols_to_port (ea2 text, current_name text, new_name text, ratio real, "
      "description text);"
      "begin transaction;",
      nullptr, nullptr, &ErrorMessage);
  if (ExecCode != SQLITE_OK) {
    OutError = ErrorMessage != nullptr ? ErrorMessage : "schema creation failed";
    sqlite3_free(ErrorMessage);
    sqlite3_close(Handle);
    return false;
  }

  sqlite3_stmt* MatchStatement = nullptr;
  sqlite3_stmt* PortStatement = nullptr;
  sqlite3_prepare_v2(Handle, "insert into matches values (?, ?, ?, ?, ?, ?, ?)", -1, &MatchStatement, nullptr);
  sqlite3_prepare_v2(Handle, "insert into symbols_to_port values (?, ?, ?, ?, ?)", -1, &PortStatement, nullptr);

  OutPorted = 0;
  for (const Match& Item : Matches) {
    const std::string Ea1 = std::string(Reference.Text(Reference.Address[Item.Index1]));
    const std::string_view Name1 = Reference.Text(Reference.Name[Item.Index1]);
    const std::string Ea2 = std::string(Target.Text(Target.Address[Item.Index2]));
    const std::string_view Name2 = Target.Text(Target.Name[Item.Index2]);
    const std::string Description = std::string("best#") + std::to_string(Item.HeuristicId);

    sqlite3_bind_text(MatchStatement, 1, Ea1.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(MatchStatement, 2, std::string(Name1).c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(MatchStatement, 3, Ea2.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(MatchStatement, 4, std::string(Name2).c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(MatchStatement, 5, Description.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_double(MatchStatement, 6, static_cast<double>(Item.Ratio));
    sqlite3_bind_text(MatchStatement, 7, CategoryName(Item.Category), -1, SQLITE_TRANSIENT);
    sqlite3_step(MatchStatement);
    sqlite3_reset(MatchStatement);

    if (!IsPortableSymbol(Name1) || Name1 == Name2) {
      continue;
    }

    sqlite3_bind_text(PortStatement, 1, Ea2.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(PortStatement, 2, std::string(Name2).c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(PortStatement, 3, std::string(Name1).c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_double(PortStatement, 4, static_cast<double>(Item.Ratio));
    sqlite3_bind_text(PortStatement, 5, Description.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(PortStatement);
    sqlite3_reset(PortStatement);
    ++OutPorted;
  }

  sqlite3_finalize(MatchStatement);
  sqlite3_finalize(PortStatement);
  sqlite3_exec(Handle, "commit transaction;", nullptr, nullptr, &ErrorMessage);
  sqlite3_free(ErrorMessage);
  sqlite3_close(Handle);
  return true;
}

void PrintHeuristicTable(const DiffResult& Result) {
  std::printf("%-30s %-18s %10s %10s\n", "heuristic", "state", "raw", "ms");
  std::printf("%-30s %-18s %10s %10s\n", "------------------------------", "------------------", "----------",
              "----------");
  for (const HeuristicStats& Stats : Result.Stats) {
    std::printf("%-30s %-18s %10zu %10.2f\n", Stats.Name.c_str(), Stats.Ran ? "ran" : Stats.SkipReason.c_str(),
                Stats.RawMatches, Stats.ElapsedMs);
  }
  std::printf("\n");
  std::printf("raw matches     : %zu\n", Result.RawMatches);
  std::printf("resolved (1:1)  : %zu\n", Result.Resolved.size());
  std::printf("wall time       : %.2f ms\n", Result.WallMs);
}

int RunLegacyDiff(const Parsed& Arguments, unsigned ThreadCount) {
  ExportDatabase Loader;

  FunctionTable Reference;
  ProgramInfo ReferenceProgram;
  const LoadResult ReferenceLoad = Loader.Load(Arguments.Positional[0], Reference, ReferenceProgram);
  if (!ReferenceLoad.Ok) {
    std::fprintf(stderr, "error: cannot load reference '%s': %s\n", Arguments.Positional[0].c_str(),
                 ReferenceLoad.Error.c_str());
    return 2;
  }

  FunctionTable Target;
  ProgramInfo TargetProgram;
  const LoadResult TargetLoad = Loader.Load(Arguments.Positional[1], Target, TargetProgram);
  if (!TargetLoad.Ok) {
    std::fprintf(stderr, "error: cannot load target '%s': %s\n", Arguments.Positional[1].c_str(),
                 TargetLoad.Error.c_str());
    return 2;
  }

  const bool SameProcessor = Arguments.Has("--assume-same-cpu") ||
                             (ReferenceProgram.Present && TargetProgram.Present &&
                              !ReferenceProgram.Processor.empty() &&
                              ReferenceProgram.Processor == TargetProgram.Processor);

  DiffOptions Options;
  Options.IgnoreSmallFunctions = Arguments.Has("--ignore-small-functions");
  Options.SameProcessor = SameProcessor;
  Options.ThreadCount = ThreadCount;

  std::printf("reference : %s\n", Arguments.Positional[0].c_str());
  std::printf("            %lld functions, processor '%s'\n", static_cast<long long>(ReferenceLoad.RowsRead),
              ReferenceProgram.Processor.c_str());
  std::printf("target    : %s\n", Arguments.Positional[1].c_str());
  std::printf("            %lld functions, processor '%s'\n", static_cast<long long>(TargetLoad.RowsRead),
              TargetProgram.Processor.c_str());
  std::printf("same cpu  : %s\n\n", SameProcessor ? "yes" : "no");

  const DiffResult Result = RunExactHeuristics(Reference, Target, Options);
  PrintHeuristicTable(Result);

  const size_t Smaller = Reference.Count() < Target.Count() ? Reference.Count() : Target.Count();
  if (Smaller > 0) {
    std::printf("coverage        : %.2f%% of the smaller side\n",
                100.0 * static_cast<double>(Result.Resolved.size()) / static_cast<double>(Smaller));
  }

  const std::string OutputPath = Arguments.Value("--output");
  if (!OutputPath.empty()) {
    std::string WriteError;
    size_t Ported = 0;
    if (!WriteDiffResults(OutputPath, Reference, Target, Result.Resolved, WriteError, Ported)) {
      std::fprintf(stderr, "error: cannot write results to '%s': %s\n", OutputPath.c_str(), WriteError.c_str());
      return 3;
    }
    std::printf("symbols to port : %zu\n", Ported);
    std::printf("results written : %s\n", OutputPath.c_str());
  }

  return 0;
}

// ---------------------------------------------------------------------------------------------
// diff: parity engine by default (plan §2.1, §7.1 D3)

int RunDiffCommand(const Parsed& Arguments) {
  const std::string Engine = Arguments.Has("--engine") ? Arguments.Value("--engine") : "parity";
  const std::string Format = Arguments.Value("--format");
  if (Engine != "parity" && Engine != "legacy") {
    return UsageError("--engine must be parity or legacy");
  }
  if (!Format.empty() && Format != "diaphora" && Format != "legacy") {
    return UsageError("--format must be diaphora or legacy");
  }

  unsigned ThreadCount = 0;
  if (Arguments.Has("--threads")) {
    const auto Parsed_ = ParseLong(Arguments.Value("--threads"));
    if (!Parsed_ || *Parsed_ <= 0) {
      return UsageError("thread count must be a positive integer");
    }
    ThreadCount = static_cast<unsigned>(*Parsed_);
  }

  if (Engine == "legacy") {
    if (Format == "diaphora") {
      std::fprintf(stderr, "error: the legacy engine writes only the legacy tables (--format legacy)\n");
      return Cli::kExitUnsupported;
    }
    return RunLegacyDiff(Arguments, ThreadCount);
  }

  // ---- parity engine ----
  if (Format == "legacy") {
    std::fprintf(stderr, "error: --format legacy with the parity engine is not implemented; use --engine legacy\n");
    return Cli::kExitUnsupported;
  }
  if (Arguments.Has("--threads") || Arguments.Has("--assume-same-cpu")) {
    return UsageError("--threads and --assume-same-cpu apply only to --engine legacy");
  }
  for (const char* Refused : {"--unreliable", "--relaxed-ratio", "--use-trained-model", "--project-script"}) {
    if (Arguments.Has(Refused)) {
      std::fprintf(stderr,
                   "error: %s is outside the parity configuration (docs/parity/00-plan.md §1.1) and is "
                   "not supported\n",
                   Refused);
      return Cli::kExitUnsupported;
    }
  }

  Diff::DiffArgs Args;
  Args.Db1 = Arguments.Positional[0];
  Args.Db2 = Arguments.Positional[1];
  Args.Out = Arguments.Value("--output");
  Args.Config.IgnoreSmallFunctions = Arguments.Has("--ignore-small-functions");
  Args.TracePath = Arguments.Value("--trace");
  Args.TraceRows = Arguments.Has("--trace-rows");
  Args.SnapshotDir = Arguments.Value("--snapshot-dir");
  if (Arguments.Has("--snapshot-points")) {
    Args.SnapshotPoints = Arguments.Value("--snapshot-points");
  }
  Args.SnapshotCache = Arguments.Value("--snapshot-cache");
  Args.PairLabel = Arguments.Value("--pair");
  Args.ReplayPath = Arguments.Value("--replay");
  Args.ReplayStage = Arguments.Value("--stage");
  Args.SnapshotOut = Arguments.Value("--snapshot-out");
  Args.StrictSqlite = Arguments.Has("--strict-sqlite");
  Args.AllowSqliteMismatch = Arguments.Has("--allow-sqlite-mismatch");
  Args.Quiet = Arguments.Has("--quiet");
  if (Arguments.Has("--iteration")) {
    const auto Value = ParseLong(Arguments.Value("--iteration"));
    if (!Value || *Value < 0) {
      return UsageError("--iteration must be a non-negative integer");
    }
    Args.ReplayIteration = static_cast<int>(*Value);
  }
  if (Arguments.Has("--heuristic")) {
    const auto Value = ParseLong(Arguments.Value("--heuristic"));
    if (!Value || *Value < 0 || *Value > 49) {
      return UsageError("--heuristic must be a HEURISTICS index 0..49");
    }
    Args.ReplayHeuristic = static_cast<int>(*Value);
  }
  if (Arguments.Has("--related-cu-source")) {
    const std::string Source = Arguments.Value("--related-cu-source");
    if (Source != "native" && Source != "sql") {
      return UsageError("--related-cu-source must be native or sql");
    }
    Args.CuSource = Source == "sql" ? Diff::RelatedCuSource::Sql : Diff::RelatedCuSource::Native;
  }
  const bool ReplayFlags = Arguments.Has("--stage") || Arguments.Has("--snapshot-out") ||
                           Arguments.Has("--iteration") || Arguments.Has("--heuristic");
  if (Args.ReplayPath.empty() && ReplayFlags) {
    return UsageError("--stage, --snapshot-out, --iteration and --heuristic need --replay");
  }
  if (!Args.ReplayPath.empty() && (Args.ReplayStage.empty() || Args.SnapshotOut.empty())) {
    return UsageError("--replay needs --stage and --snapshot-out");
  }

  const Diff::DiffOutcome Outcome = Diff::RunDiff(Args);
  if (Outcome.Status != Diff::DiffStatus::Ok) {
    std::fprintf(stderr, "error: %s\n", Outcome.Message.c_str());
    return static_cast<int>(Outcome.Status);
  }
  if (!Args.ReplayPath.empty()) {
    std::printf("snapshot written : %s\n", Outcome.OutputPath.c_str());
  } else {
    std::printf("mode             : %c\n", Outcome.Mode);
    std::printf("final results    : best %zu, partial %zu, unreliable %zu, multimatch %zu\n", Outcome.Best,
                Outcome.Partial, Outcome.Unreliable, Outcome.Multimatch);
    std::printf("results written  : %s\n", Outcome.OutputPath.c_str());
  }
  if (!Outcome.Skipped.empty()) {
    std::printf("stages skipped   : %zu (not implemented yet)\n", Outcome.Skipped.size());
  }
  return 0;
}

// ---------------------------------------------------------------------------------------------
// port

int RunPort(const Parsed& Arguments) {
  double MinRatio = 0.0;
  if (Arguments.Has("--min-ratio")) {
    MinRatio = std::strtod(Arguments.Value("--min-ratio").c_str(), nullptr);
    if (MinRatio < 0.0 || MinRatio > 1.0) {
      return UsageError("min-ratio must be between 0.0 and 1.0");
    }
  }
  int64_t MaxHops = -1;
  if (Arguments.Has("--max-hops")) {
    const auto Value = ParseLong(Arguments.Value("--max-hops"));
    if (!Value || *Value < 0) {
      return UsageError("max-hops must be zero or greater");
    }
    MaxHops = static_cast<int64_t>(*Value);
  }
  const bool Overwrite = Arguments.Has("--overwrite") || Arguments.Has("--overwrite-existing");

  if (Arguments.Has("--results")) {
    // plan §7.1 D6: apply a .diaphora results file (lane L11)
    if (Arguments.Has("--threads") || Arguments.Has("--assume-same-cpu")) {
      return UsageError("--threads and --assume-same-cpu do not apply to port --results");
    }
    Cli::PortFromResultsArgs Args;
    Args.Reference = Arguments.Positional[0];
    Args.Target = Arguments.Positional[1];
    Args.Output = Arguments.Value("--output");
    Args.Results = Arguments.Value("--results");
    Args.IncludeMultimatch = Arguments.Has("--include-multimatch");
    Args.IncludeUnreliable = Arguments.Has("--include-unreliable");
    Args.Overwrite = Overwrite;
    Args.MinRatio = MinRatio;
    Args.MaxHops = MaxHops;
    Args.StrictSqlite = Arguments.Has("--strict-sqlite");
    Args.IgnoreSmallFunctions = Arguments.Has("--ignore-small-functions");
    const Cli::CommandOutcome Outcome = Cli::RunPortFromResults(Args);
    if (Outcome.ExitCode != Cli::kExitOk) {
      std::fprintf(stderr, "error: %s\n", Outcome.Message.c_str());
      return Outcome.ExitCode;
    }
    for (const std::string& Line : Outcome.Report) {
      std::printf("%s\n", Line.c_str());
    }
    return Cli::kExitOk;
  }
  if (Arguments.Has("--include-multimatch") || Arguments.Has("--include-unreliable")) {
    return UsageError("--include-multimatch and --include-unreliable need --results");
  }

  unsigned ThreadCount = 0;
  if (Arguments.Has("--threads")) {
    const auto Value = ParseLong(Arguments.Value("--threads"));
    if (!Value || *Value <= 0) {
      return UsageError("thread count must be a positive integer");
    }
    ThreadCount = static_cast<unsigned>(*Value);
  }

  // Legacy port (unchanged behaviour until plan §4 L9).
  PortOptions Options;
  Options.ReferencePath = Arguments.Positional[0];
  Options.TargetPath = Arguments.Positional[1];
  Options.OutputPath = Arguments.Value("--output");
  Options.OverwriteExistingNames = Overwrite;
  Options.MinCumulativeRatio = MinRatio;
  Options.MaxHops = MaxHops;
  Options.Diff.IgnoreSmallFunctions = Arguments.Has("--ignore-small-functions");
  Options.Diff.SameProcessor = Arguments.Has("--assume-same-cpu");
  Options.Diff.ThreadCount = ThreadCount;

  const PortResult Result = PortSymbols(Options);
  if (!Result.Ok) {
    std::fprintf(stderr, "error: %s\n", Result.Error.c_str());
    return 3;
  }

  std::printf("reference        : %s\n", Options.ReferencePath.c_str());
  std::printf("target           : %s\n", Options.TargetPath.c_str());
  std::printf("output           : %s\n", Options.OutputPath.c_str());
  std::printf("output sha256    : %s\n", Result.OutputSha256.c_str());
  std::printf("lineage          : %s\n", Result.Lineage.c_str());
  std::printf("hop              : %lld\n\n", static_cast<long long>(Result.NewHop));

  std::printf("matches          : %lld\n", static_cast<long long>(Result.Matches));
  std::printf("names applied    : %lld\n", static_cast<long long>(Result.NamesApplied));
  std::printf("names confirmed  : %lld\n", static_cast<long long>(Result.NamesConfirmed));
  std::printf("skipped existing : %lld\n", static_cast<long long>(Result.NamesSkippedExisting));
  std::printf("skipped hop cap  : %lld\n", static_cast<long long>(Result.NamesSkippedHops));
  std::printf("skipped ratio    : %lld\n", static_cast<long long>(Result.NamesSkippedRatio));
  std::printf("skipped no symbol: %lld\n", static_cast<long long>(Result.NamesSkippedNotPortable));

  return 0;
}

// ---------------------------------------------------------------------------------------------
// extract / ingest (plan §7.1 D7, lane L10)

Cli::ExportToolOptions ToolOptions(const Parsed& Arguments, bool& Ok) {
  Cli::ExportToolOptions Tools;
  Tools.Python = Arguments.Value("--python");
  Tools.IdaDir = Arguments.Value("--ida-dir");
  Tools.DiaphoraDir = Arguments.Value("--diaphora-dir");
  Tools.TempDir = Arguments.Value("--temp-dir");
  Tools.KeepTemp = Arguments.Has("--keep-temp");
  Ok = true;
  if (Arguments.Has("--timeout")) {
    const auto Value = ParseLong(Arguments.Value("--timeout"));
    if (!Value || *Value < 0) {
      Ok = false;
    } else {
      Tools.TimeoutSeconds = static_cast<int>(*Value);
    }
  }
  return Tools;
}

int ReportCommand(const Cli::CommandOutcome& Outcome) {
  if (Outcome.ExitCode != Cli::kExitOk) {
    std::fprintf(stderr, "error: %s\n", Outcome.Message.c_str());
    return Outcome.ExitCode;
  }
  for (const std::string& Line : Outcome.Report) {
    std::printf("%s\n", Line.c_str());
  }
  return Cli::kExitOk;
}

int RunExtractCommand(const Parsed& Arguments) {
  if (Arguments.Has("--pdb") || Arguments.Has("--no-pdb")) {
    return UsageError("--pdb / --no-pdb apply to ingest only");
  }
  bool Ok = true;
  Cli::ExtractArgs Args;
  Args.Input = Arguments.Positional[0];
  Args.Output = Arguments.Value("--output");
  Args.Tools = ToolOptions(Arguments, Ok);
  if (!Ok) {
    return UsageError("--timeout must be a non-negative integer");
  }
  return ReportCommand(Cli::RunExtract(Args));
}

int RunIngestCommand(const Parsed& Arguments) {
  if (Arguments.Has("--pdb") && Arguments.Has("--no-pdb")) {
    return UsageError("--pdb and --no-pdb are exclusive");
  }
  bool Ok = true;
  Cli::IngestArgs Args;
  Args.Input = Arguments.Positional[0];
  Args.Output = Arguments.Value("--output");
  Args.Pdb = Arguments.Value("--pdb");
  Args.NoPdb = Arguments.Has("--no-pdb");
  Args.Tools = ToolOptions(Arguments, Ok);
  if (!Ok) {
    return UsageError("--timeout must be a non-negative integer");
  }
  return ReportCommand(Cli::RunIngest(Args));
}

// ---------------------------------------------------------------------------------------------
// info

int RunInfo(const Parsed& Arguments) {
  const DatabaseIdentity Identity = InspectDatabase(Arguments.Positional[0]);
  if (!Identity.Ok) {
    std::fprintf(stderr, "error: %s\n", Identity.Error.c_str());
    return 2;
  }

  std::printf("path             : %s\n", Identity.Path.c_str());
  std::printf("file sha256      : %s\n", Identity.FileSha256.c_str());
  std::printf("functions        : %lld\n", static_cast<long long>(Identity.FunctionCount));
  std::printf("processor        : %s\n", Identity.Processor.c_str());
  std::printf("input md5        : %s\n", Identity.InputMd5.empty() ? "<none>" : Identity.InputMd5.c_str());
  std::printf("provenance       : %s\n",
              Identity.HasProvenance ? "present" : "absent (hand labelled or raw export)");
  std::printf("hops recorded    : %lld\n", static_cast<long long>(Identity.HopCount));
  if (!Identity.Lineage.empty()) {
    std::printf("lineage          : %s\n", Identity.Lineage.c_str());
  }

  const std::unordered_map<std::string, NameOrigin> Origins = ReadNameOrigins(Identity.Path);
  if (!Origins.empty()) {
    std::map<int64_t, size_t> HopHistogram;
    size_t BelowThreshold = 0;
    for (const auto& Entry : Origins) {
      HopHistogram[Entry.second.Hops] += 1;
      if (Entry.second.CumulativeRatio < 0.8) {
        ++BelowThreshold;
      }
    }

    std::printf("\nported names     : %zu\n", Origins.size());
    std::printf("  below 0.80 conf: %zu\n", BelowThreshold);
    std::printf("  hop histogram  :\n");
    for (const auto& Entry : HopHistogram) {
      std::printf("    %2lld hop(s) : %zu\n", static_cast<long long>(Entry.first), Entry.second);
    }
  }

  if (!Identity.Hops.empty()) {
    std::printf("\nhop history:\n");
    std::printf("  %-4s %-34s %-34s %8s %8s\n", "hop", "source input md5", "target input md5", "matches", "applied");
    for (const HopRecord& Record : Identity.Hops) {
      std::printf("  %-4lld %-34s %-34s %8lld %8lld\n", static_cast<long long>(Record.Hop),
                  Record.SourceInputMd5.empty() ? "<none>" : Record.SourceInputMd5.c_str(),
                  Record.TargetInputMd5.empty() ? "<none>" : Record.TargetInputMd5.c_str(),
                  static_cast<long long>(Record.Matches), static_cast<long long>(Record.NamesApplied));
    }
  }

  return 0;
}

int RunMain(int Argc, char** Argv) {
  const Parsed Arguments = ParseArguments(Argc, Argv);

  if (Arguments.ShowHelp) {
    PrintUsage();
    return Arguments.Valid ? 0 : kExitUsage;
  }
  if (!Arguments.Valid) {
    return UsageError(Arguments.Error);
  }

  if (Arguments.Command == "info") {
    return RunInfo(Arguments);
  }
  if (Arguments.Command == "port") {
    return RunPort(Arguments);
  }
  if (Arguments.Command == "extract") {
    return RunExtractCommand(Arguments);
  }
  if (Arguments.Command == "ingest") {
    return RunIngestCommand(Arguments);
  }
  return RunDiffCommand(Arguments);
}

// ---------------------------------------------------------------------------------------------
// Entry point. Every argument string is UTF-8 from here on (lane R0 (f)): the engine hands paths to
// SQLite, which takes UTF-8 file names, and src/diff converts UTF-8 to wide paths for every file API
// (src/diff/FileIo.h). On Windows the narrow argv of main() is in the ANSI code page, which cannot hold
// arbitrary Unicode, so the wide command line is converted instead.

#ifdef _WIN32
std::string WideToUtf8(const wchar_t* Text) {
  const int Length = static_cast<int>(std::wcslen(Text));
  if (Length == 0) {
    return std::string();
  }
  const int Size = WideCharToMultiByte(CP_UTF8, 0, Text, Length, nullptr, 0, nullptr, nullptr);
  if (Size <= 0) {
    return std::string();
  }
  std::string Out(static_cast<size_t>(Size), '\0');
  WideCharToMultiByte(CP_UTF8, 0, Text, Length, Out.data(), Size, nullptr, nullptr);
  return Out;
}

int RunUtf8(std::vector<std::string> Arguments) {
  std::vector<char*> Pointers;
  Pointers.reserve(Arguments.size() + 1);
  for (std::string& Argument : Arguments) {
    Pointers.push_back(Argument.data());
  }
  Pointers.push_back(nullptr);
  return RunMain(static_cast<int>(Arguments.size()), Pointers.data());
}
#endif

}

#if defined(_WIN32) && defined(_MSC_VER)
// MSVC and clang-cl: the CRT splits the wide command line with the same rules it uses for argv.
int wmain(int Argc, wchar_t** Argv) {
  std::vector<std::string> Arguments;
  Arguments.reserve(static_cast<size_t>(Argc));
  for (int Index = 0; Index < Argc; ++Index) {
    Arguments.push_back(WideToUtf8(Argv[Index]));
  }
  return RunUtf8(std::move(Arguments));
}
#else
int main(int Argc, char** Argv) {
#ifdef _WIN32
  // Other Windows toolchains (MinGW without -municode): split GetCommandLineW() ourselves.
  int Count = 0;
  LPWSTR* Wide = CommandLineToArgvW(GetCommandLineW(), &Count);
  if (Wide != nullptr) {
    std::vector<std::string> Arguments;
    Arguments.reserve(static_cast<size_t>(Count));
    for (int Index = 0; Index < Count; ++Index) {
      Arguments.push_back(WideToUtf8(Wide[Index]));
    }
    LocalFree(Wide);
    return RunUtf8(std::move(Arguments));
  }
#endif
  return RunMain(Argc, Argv);  // POSIX: argv bytes are the file names as given (UTF-8 on any sane system)
}
#endif
