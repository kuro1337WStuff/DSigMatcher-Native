#include <sqlite3.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "dsigmatcher/ExportDatabase.h"
#include "dsigmatcher/Heuristics.h"
#include "dsigmatcher/Naming.h"
#include "dsigmatcher/Provenance.h"
#include "dsigmatcher/Types.h"

#ifndef DSIG_VERSION
#define DSIG_VERSION "0.0.0"
#endif

namespace {

using namespace DSig;

void PrintUsage() {
  std::printf("dsigmatcher %s - native Diaphora-compatible symbol porter\n\n", DSIG_VERSION);
  std::printf("usage:\n");
  std::printf("  dsigmatcher diff <reference.sqlite> <target.sqlite> [options]\n");
  std::printf("  dsigmatcher port <reference.sqlite> <target.sqlite> -o <output.sqlite> [options]\n");
  std::printf("  dsigmatcher info <database.sqlite>\n");
  std::printf("\n");
  std::printf("diff options:\n");
  std::printf("  -o, --output <path>          write match results to a SQLite database\n");
  std::printf("  -t, --threads <n>            worker threads (default: hardware concurrency)\n");
  std::printf("      --ignore-small-functions apply the instructions > 5 size gate\n");
  std::printf("      --assume-same-cpu        run processor specific heuristics unconditionally\n");
  std::printf("\n");
  std::printf("port options (in addition to the above):\n");
  std::printf("  -o, --output <path>          required; labelled copy of the target database\n");
  std::printf("      --min-ratio <r>          drop names whose cumulative confidence falls below r\n");
  std::printf("      --max-hops <n>           drop names that have travelled through more than n diffs\n");
  std::printf("      --overwrite-existing     replace real names already present in the target\n");
  std::printf("\n");
  std::printf("The port output is itself a Diaphora-schema database, so it can be used as the\n");
  std::printf("reference for the next release without going back through IDA.\n");
}

struct Parsed {
  std::string Command;
  std::vector<std::string> Positional;
  std::string OutputPath;
  unsigned ThreadCount = 0;
  bool IgnoreSmallFunctions = false;
  bool AssumeSameCpu = false;
  bool OverwriteExisting = false;
  double MinRatio = 0.0;
  int64_t MaxHops = -1;
  bool ShowHelp = false;
  bool Valid = true;
  std::string Error;
};

bool NeedsValue(const std::string& Argument) {
  return Argument == "-o" || Argument == "--output" || Argument == "-t" || Argument == "--threads" ||
         Argument == "--min-ratio" || Argument == "--max-hops";
}

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
  if (Result.Command != "diff" && Result.Command != "port" && Result.Command != "info") {
    Result.Valid = false;
    Result.Error = "unknown command '" + Result.Command + "'";
    return Result;
  }

  for (int Index = 2; Index < Argc; ++Index) {
    const std::string Argument = Argv[Index];

    if (Argument == "-h" || Argument == "--help") {
      Result.ShowHelp = true;
      continue;
    }
    if (Argument == "--ignore-small-functions") {
      Result.IgnoreSmallFunctions = true;
      continue;
    }
    if (Argument == "--assume-same-cpu") {
      Result.AssumeSameCpu = true;
      continue;
    }
    if (Argument == "--overwrite-existing") {
      Result.OverwriteExisting = true;
      continue;
    }

    if (NeedsValue(Argument)) {
      if (Index + 1 >= Argc) {
        Result.Valid = false;
        Result.Error = "option '" + Argument + "' requires a value";
        return Result;
      }
      const std::string Value = Argv[++Index];

      if (Argument == "-o" || Argument == "--output") {
        Result.OutputPath = Value;
      } else if (Argument == "-t" || Argument == "--threads") {
        const long Parsed_ = std::strtol(Value.c_str(), nullptr, 10);
        if (Parsed_ <= 0) {
          Result.Valid = false;
          Result.Error = "thread count must be a positive integer";
          return Result;
        }
        Result.ThreadCount = static_cast<unsigned>(Parsed_);
      } else if (Argument == "--min-ratio") {
        const double Parsed_ = std::strtod(Value.c_str(), nullptr);
        if (Parsed_ < 0.0 || Parsed_ > 1.0) {
          Result.Valid = false;
          Result.Error = "min-ratio must be between 0.0 and 1.0";
          return Result;
        }
        Result.MinRatio = Parsed_;
      } else {
        const long Parsed_ = std::strtol(Value.c_str(), nullptr, 10);
        if (Parsed_ < 0) {
          Result.Valid = false;
          Result.Error = "max-hops must be zero or greater";
          return Result;
        }
        Result.MaxHops = static_cast<int64_t>(Parsed_);
      }
      continue;
    }

    if (!Argument.empty() && Argument[0] == '-') {
      Result.Valid = false;
      Result.Error = "unknown option '" + Argument + "'";
      return Result;
    }

    Result.Positional.push_back(Argument);
  }

  const size_t Expected = Result.Command == "info" ? 1u : 2u;
  if (Result.Positional.size() != Expected) {
    Result.Valid = false;
    Result.Error = "'" + Result.Command + "' expects " + std::to_string(Expected) +
                   " database path(s), got " + std::to_string(Result.Positional.size());
    return Result;
  }

  if (Result.Command == "port" && Result.OutputPath.empty()) {
    Result.Valid = false;
    Result.Error = "'port' requires -o <output.sqlite>";
    return Result;
  }

  return Result;
}

bool WriteDiffResults(const std::string& Path, const FunctionTable& Reference,
                      const FunctionTable& Target, const std::vector<Match>& Matches,
                      std::string& OutError, size_t& OutPorted) {
  sqlite3* Handle = nullptr;
  if (sqlite3_open_v2(Path.c_str(), &Handle, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) !=
      SQLITE_OK) {
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
  sqlite3_prepare_v2(Handle, "insert into matches values (?, ?, ?, ?, ?, ?, ?)", -1,
                     &MatchStatement, nullptr);
  sqlite3_prepare_v2(Handle, "insert into symbols_to_port values (?, ?, ?, ?, ?)", -1,
                     &PortStatement, nullptr);

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
  std::printf("%-30s %-18s %10s %10s\n", "------------------------------", "------------------",
              "----------", "----------");
  for (const HeuristicStats& Stats : Result.Stats) {
    std::printf("%-30s %-18s %10zu %10.2f\n", Stats.Name.c_str(),
                Stats.Ran ? "ran" : Stats.SkipReason.c_str(), Stats.RawMatches, Stats.ElapsedMs);
  }
  std::printf("\n");
  std::printf("raw matches     : %zu\n", Result.RawMatches);
  std::printf("resolved (1:1)  : %zu\n", Result.Resolved.size());
  std::printf("wall time       : %.2f ms\n", Result.WallMs);
}

int RunDiff(const Parsed& Arguments) {
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

  const bool SameProcessor = Arguments.AssumeSameCpu ||
                             (ReferenceProgram.Present && TargetProgram.Present &&
                              !ReferenceProgram.Processor.empty() &&
                              ReferenceProgram.Processor == TargetProgram.Processor);

  DiffOptions Options;
  Options.IgnoreSmallFunctions = Arguments.IgnoreSmallFunctions;
  Options.SameProcessor = SameProcessor;
  Options.ThreadCount = Arguments.ThreadCount;

  std::printf("reference : %s\n", Arguments.Positional[0].c_str());
  std::printf("            %lld functions, processor '%s'\n",
              static_cast<long long>(ReferenceLoad.RowsRead), ReferenceProgram.Processor.c_str());
  std::printf("target    : %s\n", Arguments.Positional[1].c_str());
  std::printf("            %lld functions, processor '%s'\n",
              static_cast<long long>(TargetLoad.RowsRead), TargetProgram.Processor.c_str());
  std::printf("same cpu  : %s\n\n", SameProcessor ? "yes" : "no");

  const DiffResult Result = RunExactHeuristics(Reference, Target, Options);
  PrintHeuristicTable(Result);

  const size_t Smaller = Reference.Count() < Target.Count() ? Reference.Count() : Target.Count();
  if (Smaller > 0) {
    std::printf("coverage        : %.2f%% of the smaller side\n",
                100.0 * static_cast<double>(Result.Resolved.size()) /
                    static_cast<double>(Smaller));
  }

  if (!Arguments.OutputPath.empty()) {
    std::string WriteError;
    size_t Ported = 0;
    if (!WriteDiffResults(Arguments.OutputPath, Reference, Target, Result.Resolved, WriteError,
                          Ported)) {
      std::fprintf(stderr, "error: cannot write results to '%s': %s\n",
                   Arguments.OutputPath.c_str(), WriteError.c_str());
      return 3;
    }
    std::printf("symbols to port : %zu\n", Ported);
    std::printf("results written : %s\n", Arguments.OutputPath.c_str());
  }

  return 0;
}

int RunPort(const Parsed& Arguments) {
  PortOptions Options;
  Options.ReferencePath = Arguments.Positional[0];
  Options.TargetPath = Arguments.Positional[1];
  Options.OutputPath = Arguments.OutputPath;
  Options.OverwriteExistingNames = Arguments.OverwriteExisting;
  Options.MinCumulativeRatio = Arguments.MinRatio;
  Options.MaxHops = Arguments.MaxHops;
  Options.Diff.IgnoreSmallFunctions = Arguments.IgnoreSmallFunctions;
  Options.Diff.SameProcessor = Arguments.AssumeSameCpu;
  Options.Diff.ThreadCount = Arguments.ThreadCount;

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
  std::printf("skipped no symbol: %lld\n",
              static_cast<long long>(Result.NamesSkippedNotPortable));

  return 0;
}

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
  std::printf("input md5        : %s\n",
              Identity.InputMd5.empty() ? "<none>" : Identity.InputMd5.c_str());
  std::printf("provenance       : %s\n", Identity.HasProvenance ? "present" : "absent (hand labelled or raw export)");
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
    std::printf("  %-4s %-34s %-34s %8s %8s\n", "hop", "source input md5", "target input md5",
                "matches", "applied");
    for (const HopRecord& Record : Identity.Hops) {
      std::printf("  %-4lld %-34s %-34s %8lld %8lld\n", static_cast<long long>(Record.Hop),
                  Record.SourceInputMd5.empty() ? "<none>" : Record.SourceInputMd5.c_str(),
                  Record.TargetInputMd5.empty() ? "<none>" : Record.TargetInputMd5.c_str(),
                  static_cast<long long>(Record.Matches),
                  static_cast<long long>(Record.NamesApplied));
    }
  }

  return 0;
}

}

int main(int Argc, char** Argv) {
  const Parsed Arguments = ParseArguments(Argc, Argv);

  if (Arguments.ShowHelp) {
    PrintUsage();
    return Arguments.Valid ? 0 : 1;
  }
  if (!Arguments.Valid) {
    std::fprintf(stderr, "error: %s\n\n", Arguments.Error.c_str());
    PrintUsage();
    return 1;
  }

  if (Arguments.Command == "info") {
    return RunInfo(Arguments);
  }
  if (Arguments.Command == "port") {
    return RunPort(Arguments);
  }
  return RunDiff(Arguments);
}
