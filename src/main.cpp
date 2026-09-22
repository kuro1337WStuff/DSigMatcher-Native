#include <sqlite3.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include "dsigmatcher/ExportDatabase.h"
#include "dsigmatcher/Heuristics.h"
#include "dsigmatcher/Types.h"

namespace {

using namespace DSig;

void PrintUsage() {
  std::printf("usage: dsigmatcher <reference.sqlite> <target.sqlite> [options]\n");
  std::printf("\n");
  std::printf("Diffs two Diaphora export databases and ports names from reference to target.\n");
  std::printf("\n");
  std::printf("options:\n");
  std::printf("  -o, --output <path>          write results to a SQLite database\n");
  std::printf("  -t, --threads <n>            worker threads (default: hardware concurrency)\n");
  std::printf("      --ignore-small-functions apply the instructions > 5 size gate\n");
  std::printf("      --assume-same-cpu        run processor specific heuristics unconditionally\n");
  std::printf("  -h, --help                   show this message\n");
}

bool StartsWith(std::string_view Text, std::string_view Prefix) {
  return Text.size() >= Prefix.size() && Text.compare(0, Prefix.size(), Prefix) == 0;
}

bool IsPortableSymbol(std::string_view Name) {
  if (Name.empty()) {
    return false;
  }
  return !StartsWith(Name, "sub_") && !StartsWith(Name, "nullsub") && Name != "...";
}

struct Arguments {
  std::string ReferencePath;
  std::string TargetPath;
  std::string OutputPath;
  unsigned ThreadCount = 0;
  bool IgnoreSmallFunctions = false;
  bool AssumeSameCpu = false;
  bool ShowHelp = false;
  bool Valid = true;
  std::string Error;
};

Arguments ParseArguments(int Argc, char** Argv) {
  Arguments Result;
  std::vector<std::string> Positional;

  for (int Index = 1; Index < Argc; ++Index) {
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
    if (Argument == "-o" || Argument == "--output" || Argument == "-t" || Argument == "--threads") {
      if (Index + 1 >= Argc) {
        Result.Valid = false;
        Result.Error = "option '" + Argument + "' requires a value";
        return Result;
      }
      const std::string Value = Argv[++Index];
      if (Argument == "-o" || Argument == "--output") {
        Result.OutputPath = Value;
      } else {
        const long Parsed = std::strtol(Value.c_str(), nullptr, 10);
        if (Parsed <= 0) {
          Result.Valid = false;
          Result.Error = "thread count must be a positive integer";
          return Result;
        }
        Result.ThreadCount = static_cast<unsigned>(Parsed);
      }
      continue;
    }
    if (!Argument.empty() && Argument[0] == '-') {
      Result.Valid = false;
      Result.Error = "unknown option '" + Argument + "'";
      return Result;
    }

    Positional.push_back(Argument);
  }

  if (Positional.size() != 2) {
    Result.Valid = false;
    Result.Error = "expected exactly two database paths, got " + std::to_string(Positional.size());
    return Result;
  }

  Result.ReferencePath = Positional[0];
  Result.TargetPath = Positional[1];
  return Result;
}

bool WriteResults(const std::string& Path, const FunctionTable& Reference, const FunctionTable& Target,
                  const std::vector<Match>& Matches, std::string& OutError, size_t& OutPorted) {
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
  sqlite3_prepare_v2(Handle, "insert into matches values (?, ?, ?, ?, ?, ?, ?)", -1, &MatchStatement,
                     nullptr);
  sqlite3_prepare_v2(Handle, "insert into symbols_to_port values (?, ?, ?, ?, ?)", -1, &PortStatement,
                     nullptr);

  OutPorted = 0;
  for (const Match& Item : Matches) {
    const std::string_view Ea1 = Reference.Text(Reference.Address[Item.Index1]);
    const std::string_view Name1 = Reference.Text(Reference.Name[Item.Index1]);
    const std::string_view Ea2 = Target.Text(Target.Address[Item.Index2]);
    const std::string_view Name2 = Target.Text(Target.Name[Item.Index2]);
    const std::string Description = std::string("heuristic ") + std::to_string(Item.HeuristicId);

    sqlite3_bind_text(MatchStatement, 1, std::string(Ea1).c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(MatchStatement, 2, std::string(Name1).c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(MatchStatement, 3, std::string(Ea2).c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(MatchStatement, 4, std::string(Name2).c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(MatchStatement, 5, Description.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_double(MatchStatement, 6, static_cast<double>(Item.Ratio));
    sqlite3_bind_text(MatchStatement, 7, CategoryName(Item.Category), -1, SQLITE_TRANSIENT);
    sqlite3_step(MatchStatement);
    sqlite3_reset(MatchStatement);

    if (!IsPortableSymbol(Name1) || Name1 == Name2) {
      continue;
    }

    sqlite3_bind_text(PortStatement, 1, std::string(Ea2).c_str(), -1, SQLITE_TRANSIENT);
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

}

int main(int Argc, char** Argv) {
  const Arguments Arguments_ = ParseArguments(Argc, Argv);

  if (Arguments_.ShowHelp) {
    PrintUsage();
    return 0;
  }
  if (!Arguments_.Valid) {
    std::fprintf(stderr, "error: %s\n\n", Arguments_.Error.c_str());
    PrintUsage();
    return 1;
  }

  ExportDatabase Loader;

  FunctionTable Reference;
  ProgramInfo ReferenceProgram;
  const LoadResult ReferenceLoad = Loader.Load(Arguments_.ReferencePath, Reference, ReferenceProgram);
  if (!ReferenceLoad.Ok) {
    std::fprintf(stderr, "error: cannot load reference '%s': %s\n",
                 Arguments_.ReferencePath.c_str(), ReferenceLoad.Error.c_str());
    return 2;
  }

  FunctionTable Target;
  ProgramInfo TargetProgram;
  const LoadResult TargetLoad = Loader.Load(Arguments_.TargetPath, Target, TargetProgram);
  if (!TargetLoad.Ok) {
    std::fprintf(stderr, "error: cannot load target '%s': %s\n", Arguments_.TargetPath.c_str(),
                 TargetLoad.Error.c_str());
    return 2;
  }

  const bool SameProcessor =
      Arguments_.AssumeSameCpu ||
      (ReferenceProgram.Present && TargetProgram.Present &&
       !ReferenceProgram.Processor.empty() &&
       ReferenceProgram.Processor == TargetProgram.Processor);

  DiffOptions Options;
  Options.IgnoreSmallFunctions = Arguments_.IgnoreSmallFunctions;
  Options.SameProcessor = SameProcessor;
  Options.ThreadCount = Arguments_.ThreadCount;

  std::printf("reference : %s\n", Arguments_.ReferencePath.c_str());
  std::printf("            %lld functions, processor '%s'\n",
              static_cast<long long>(ReferenceLoad.RowsRead), ReferenceProgram.Processor.c_str());
  std::printf("target    : %s\n", Arguments_.TargetPath.c_str());
  std::printf("            %lld functions, processor '%s'\n",
              static_cast<long long>(TargetLoad.RowsRead), TargetProgram.Processor.c_str());
  std::printf("same cpu  : %s\n", SameProcessor ? "yes" : "no");
  std::printf("\n");

  const DiffResult Result = RunExactHeuristics(Reference, Target, Options);

  std::printf("%-30s %-10s %10s\n", "heuristic", "state", "raw");
  std::printf("%-30s %-10s %10s\n", "------------------------------", "----------", "----------");
  for (const HeuristicStats& Stats : Result.Stats) {
    std::printf("%-30s %-10s %10zu\n", Stats.Name.c_str(), Stats.Ran ? "ran" : Stats.SkipReason.c_str(),
                Stats.RawMatches);
  }
  std::printf("\n");
  std::printf("raw matches     : %zu\n", Result.RawMatches);
  std::printf("resolved (1:1)  : %zu\n", Result.Resolved.size());

  const size_t ReferenceTotal = Reference.Count();
  const size_t TargetTotal = Target.Count();
  if (ReferenceTotal > 0 && TargetTotal > 0) {
    const double Coverage =
        100.0 * static_cast<double>(Result.Resolved.size()) /
        static_cast<double>(ReferenceTotal < TargetTotal ? ReferenceTotal : TargetTotal);
    std::printf("coverage        : %.2f%% of the smaller side\n", Coverage);
  }

  if (!Arguments_.OutputPath.empty()) {
    std::string WriteError;
    size_t Ported = 0;
    if (!WriteResults(Arguments_.OutputPath, Reference, Target, Result.Resolved, WriteError, Ported)) {
      std::fprintf(stderr, "error: cannot write results to '%s': %s\n",
                   Arguments_.OutputPath.c_str(), WriteError.c_str());
      return 3;
    }
    std::printf("symbols to port : %zu\n", Ported);
    std::printf("results written : %s\n", Arguments_.OutputPath.c_str());
  }

  return 0;
}
