#include <sqlite3.h>

#include <cerrno>
#include <charconv>
#include <climits>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <exception>
#include <locale>
#include <map>
#include <new>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "dsigmatcher/Provenance.h"
#include "dsigmatcher/Version.h"
#include "dsigmatcher/cli/Commands.h"
#include "dsigmatcher/diff/Json.h"
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

namespace {

using namespace DSig;
using Diff::JsonValue;

constexpr int kExitUsage = Cli::kExitUsage;

// The confidence bucket `info` reports ported names below. A fixed value, not an option.
constexpr double kInfoConfidenceBucket = 0.80;

// Versions of the --json object layout; bumped when a field changes meaning or is removed.
constexpr int kJsonSchema = 1;

// ---------------------------------------------------------------------------------------------
// Help. `dsigmatcher --help` lists the commands; `dsigmatcher <command> --help` shows one command's
// options; --help-all adds the developer and parity-harness options.

void PrintGlobalUsage(std::FILE* Out) {
  std::fprintf(Out, "dsigmatcher %s - native Diaphora-compatible symbol porter\n\n", DSIG_VERSION);
  std::fprintf(Out, "usage:\n");
  std::fprintf(Out, "  dsigmatcher extract <in.i64|in.idb> -o <out.sqlite>       export a labelled IDA database\n");
  std::fprintf(Out, "  dsigmatcher ingest <binary> -o <out.sqlite>               analyse and export a raw binary\n");
  std::fprintf(Out, "  dsigmatcher diff <db1.sqlite> <db2.sqlite> [-o <x.diaphora>]  Diaphora's diff, natively\n");
  std::fprintf(Out, "  dsigmatcher port <reference.sqlite> <target.sqlite> -o <out.sqlite>\n");
  std::fprintf(Out, "                                                            diff, then copy the labels over\n");
  std::fprintf(Out, "  dsigmatcher update <labelled.sqlite> <new-binary> -o <new-labelled.sqlite>\n");
  std::fprintf(Out, "                                                            ingest + diff + port in one step\n");
  std::fprintf(Out, "  dsigmatcher info <database.sqlite>                        identity, hops and provenance\n");
  std::fprintf(Out, "  dsigmatcher --version | -V [--json]                       version and linked SQLite\n");
  std::fprintf(Out, "  dsigmatcher <command> --help                              the options of one command\n");
  std::fprintf(Out, "  dsigmatcher --help-all                                    every option, with developer ones\n");
  std::fprintf(Out, "\n");
  std::fprintf(Out, "The usual chain: `extract` the IDA database you labelled, then for every new release run\n");
  std::fprintf(Out, "`update <previous-labelled.sqlite> <new.dll> -o <new-labelled.sqlite>`. Each output is a\n");
  std::fprintf(Out, "Diaphora-schema export (query it with SQLite) and the reference of the next update; the\n");
  std::fprintf(Out, "dsig_* tables record where every ported name came from (see `info`).\n");
  std::fprintf(Out, "\n");
  std::fprintf(Out, "exit codes (every command):\n");
  std::fprintf(Out, "   0  ok\n");
  std::fprintf(Out, "   2  usage error, or refused (a path that would overwrite an input; nothing is changed)\n");
  std::fprintf(Out, "   3  Diaphora itself would raise on this input (no output written)\n");
  std::fprintf(Out, "   4  unsupported input or configuration, or a tool is missing or cannot be started; for\n");
  std::fprintf(Out, "      diff: db2 is not a Diaphora export (Diaphora's empty results are still written, as\n");
  std::fprintf(Out, "      Diaphora would)\n");
  std::fprintf(Out, "   5  SQLite is not the oracle's 3.51.1 and --strict-sqlite was given\n");
  std::fprintf(Out, "   6  I/O or environment failure (missing, unreadable or unwritable file, not SQLite,\n");
  std::fprintf(Out, "      a tool that fails, a timeout)\n");
  std::fprintf(Out, "  70  internal error (a bug, or out of memory)\n");
  std::fprintf(Out, "\n");
  std::fprintf(Out, "paths: any UTF-8 / Unicode path, including UNC paths (\\\\server\\share\\...).\n");
  std::fprintf(Out, "environment: DIAPHORA_* variables are deliberately ignored. The parity engine is not\n");
  std::fprintf(Out, "Diaphora and has no environment configuration: it always runs Diaphora's default\n");
  std::fprintf(Out, "standalone configuration.\n");
}

void PrintDiaphoraDiffOptions(std::FILE* Out) {
  std::fprintf(Out, "      --ignore-small-functions     %%POSTFIX%% = \" and f.instructions > 5 and df.instructions > 5 \"\n");
  std::fprintf(Out, "      --strict-sqlite              exit 5 unless SQLite is the oracle's 3.51.1\n");
  std::fprintf(Out, "      --allow-sqlite-mismatch      do not warn about another SQLite version\n");
  std::fprintf(Out, "      --quiet                      no Diaphora summary lines on stderr (the SQLite version\n");
  std::fprintf(Out, "                                   warning is still printed; see --allow-sqlite-mismatch)\n");
}

void PrintPortOptions(std::FILE* Out, bool InUpdate) {
  std::fprintf(Out, "      --include-multimatch         also apply multimatch rows (default: best and partial)\n");
  std::fprintf(Out, "      --include-unreliable         also apply unreliable rows\n");
  std::fprintf(Out, "      --overwrite-existing         replace real names already present in the target (alias\n");
  std::fprintf(Out, "                                   --overwrite); IDA placeholders (sub_*, nullsub_*, j_*,\n");
  std::fprintf(Out, "                                   unknown_libname_*, DllEntryPoint, start) are always replaced\n");
  std::fprintf(Out, "      --overwrite-stripped         with --overwrite-existing: let \"Same binary with symbols\n");
  std::fprintf(Out, "                                   stripped\" rows (paired by address) replace real names too\n");
  std::fprintf(Out, "      --min-ratio <r>              drop names whose cumulative confidence falls below r (0..1)\n");
  std::fprintf(Out, "      --max-hops <n>               drop names whose hop count after this port would exceed n\n");
  std::fprintf(Out, "                                   (1: only names the reference did not inherit; 0: none)\n");
  std::fprintf(Out, "      --store-full-paths           dsig_* tables record absolute input paths (default: file\n");
  std::fprintf(Out, "                                   names only; the sha256 columns identify the files)\n");
  if (!InUpdate) {
    std::fprintf(Out, "      --no-keep-results            in-process diff: delete the .diaphora after the port\n");
  }
  std::fprintf(Out, "  in-process diff options:\n");
  PrintDiaphoraDiffOptions(Out);
  std::fprintf(Out, "      --json                       print one JSON object with the outcome on stdout\n");
}

void PrintToolOptions(std::FILE* Out, bool InUpdate) {
  std::fprintf(Out, "      --python <exe>               Python with idalib (else DSIG_PYTHON, else PATH)\n");
  std::fprintf(Out, "      --ida-dir <dir>              IDA installation (else DSIG_IDADIR)\n");
  std::fprintf(Out, "      --diaphora-dir <dir>         Diaphora checkout (else DSIG_DIAPHORA_DIR)\n");
  std::fprintf(Out, "      --temp-dir <dir>             where the working copy is analysed (else the system temp)\n");
  std::fprintf(Out, "      --keep-temp                  keep that working directory\n");
  std::fprintf(Out, "      --timeout <seconds>          stop the export after this long (0..%d, 30 days; 0: none)\n",
               Cli::kMaxExportTimeoutSeconds);
  std::fprintf(Out, "      --allow-no-decompiler        export even when the Hex-Rays decompiler is unavailable\n");
  std::fprintf(Out, "                                   (no pseudo-code; never diff such an export against one\n");
  std::fprintf(Out, "                                   made with Hex-Rays)\n");
  std::fprintf(Out, "      --export-script <path>       dsig_export.py; else DSIG_EXPORT_SCRIPT, else beside the\n");
  std::fprintf(Out, "                                   executable, else <prefix>/share/dsigmatcher/tools/export\n");
  std::fprintf(Out, "                                   (<prefix>: the executable's directory, then its parent)\n");
  if (!InUpdate) {
    std::fprintf(Out, "      --quiet                      do not stream the export tool's progress to stderr; on\n");
    std::fprintf(Out, "                                   failure only the final error line is printed\n");
    std::fprintf(Out, "      --json                       print one JSON object with the outcome on stdout\n");
  }
}

void PrintCommandUsage(std::FILE* Out, const std::string& Command, bool All) {
  if (Command == "diff") {
    std::fprintf(Out, "usage: dsigmatcher diff <db1.sqlite> <db2.sqlite> [-o <out.diaphora>] [options]\n\n");
    std::fprintf(Out, "Runs Diaphora's diff natively (the parity engine) and writes Diaphora's .diaphora results\n");
    std::fprintf(Out, "file. Without -o the name is <stem(db1)>_vs_<stem(db2)>.diaphora, as `python diaphora.py\n");
    std::fprintf(Out, "db1 db2` would choose.\n\n");
    std::fprintf(Out, "  -o, --output <path>              results file, replaced only on success; an existing file\n");
    std::fprintf(Out, "                                   is left as it was on a non-zero exit (except exit 4 for a\n");
    std::fprintf(Out, "                                   db2 that is not a Diaphora export, which writes Diaphora's\n");
    std::fprintf(Out, "                                   empty results); must not be an input\n");
    PrintDiaphoraDiffOptions(Out);
    std::fprintf(Out, "      --checkpoint-dir <dir>       save the engine state after every stage (created if\n");
    std::fprintf(Out, "                                   missing; removed again once the results are written)\n");
    std::fprintf(Out, "      --resume <dir>               continue a run that stopped (crash, kill, full disk) from\n");
    std::fprintf(Out, "                                   its last checkpoint; same inputs and options required\n");
    std::fprintf(Out, "      --json                       print one JSON object with the outcome on stdout\n");
    if (All) {
      std::fprintf(Out, "\ndeveloper / parity-harness options:\n");
      std::fprintf(Out, "      --trace <file.jsonl>         JSONL trace of add_match / cleanup / point events\n");
      std::fprintf(Out, "      --trace-rows                 with --trace: also one event per consumed SQL row\n");
      std::fprintf(Out, "      --snapshot-dir <dir>         a JSON snapshot at every point: <dir>/index.json lists\n");
      std::fprintf(Out, "                                   [seq, point, file], files are <dir>/snapshots/NNNNN_<point>.json\n");
      std::fprintf(Out, "                                   (tools/parity/oracle_trace.py layout; earlier snapshots replaced)\n");
      std::fprintf(Out, "      --snapshot-points <globs>    with --snapshot-dir: only points matching these globs (a|b)\n");
      std::fprintf(Out, "      --snapshot-cache <globs>     with --snapshot-dir: include ratios_cache at these points\n");
      std::fprintf(Out, "      --pair <label>               pair label stored in snapshots and traces\n");
      std::fprintf(Out, "      --replay <before.json> --stage <name> [--iteration k] [--heuristic id]\n");
      std::fprintf(Out, "               --snapshot-out <after.json>   run one stage from a snapshot (no -o)\n");
      std::fprintf(Out, "      --related-cu-source native|sql   how the related-compilation-unit pass gets its rows\n");
      std::fprintf(Out, "                                   (native: the engine's replay, sql: Diaphora's query)\n");
      std::fprintf(Out, "  refused with exit 4 (outside Diaphora's default configuration): --unreliable,\n");
      std::fprintf(Out, "  --relaxed-ratio, --use-trained-model, --project-script <file>\n");
    }
    return;
  }
  if (Command == "port") {
    std::fprintf(Out, "usage: dsigmatcher port <reference.sqlite> <target.sqlite> -o <output.sqlite> [options]\n\n");
    std::fprintf(Out, "Copies the target export to the output and gives its functions the reference's names.\n");
    std::fprintf(Out, "Without --results the parity diff runs first, in-process, and its results file is kept as\n");
    std::fprintf(Out, "<output dir>/<output stem>.diaphora; with --results that file's rows are applied instead.\n");
    std::fprintf(Out, "The output is itself a Diaphora export: the reference of the next port.\n\n");
    std::fprintf(Out, "  -o, --output <path>              required; the labelled copy of the target (replaced)\n");
    std::fprintf(Out, "      --results <x.diaphora>       apply this results file (ours or Diaphora's)\n");
    PrintPortOptions(Out, false);
    return;
  }
  if (Command == "update") {
    std::fprintf(Out, "usage: dsigmatcher update <labelled.sqlite> <new-binary> -o <new-labelled.sqlite> [options]\n\n");
    std::fprintf(Out, "One release step: `ingest` the new binary, `diff` the labelled export against it and `port`\n");
    std::fprintf(Out, "the labels. Kept beside the output (<stem> = the output without its extension):\n");
    std::fprintf(Out, "<stem>.ingest.sqlite (the new binary's export), <stem>.ingest.export.json (its sidecar)\n");
    std::fprintf(Out, "and <stem>.diaphora (the diff's results). The first failing step stops the command with\n");
    std::fprintf(Out, "that step's exit code. --quiet also stops the ingest's progress stream on stderr.\n\n");
    std::fprintf(Out, "  -o, --output <path>              required; the labelled export of the new binary (replaced)\n");
    std::fprintf(Out, "      --pdb <file>                 load this PDB (default: no PDB, no symbol server)\n");
    std::fprintf(Out, "      --no-pdb                     explicitly no PDB\n");
    std::fprintf(Out, "  ingest tool options:\n");
    PrintToolOptions(Out, true);
    std::fprintf(Out, "  port options:\n");
    PrintPortOptions(Out, true);
    return;
  }
  if (Command == "extract" || Command == "ingest") {
    if (Command == "extract") {
      std::fprintf(Out, "usage: dsigmatcher extract <in.i64|in.idb> -o <out.sqlite> [tool options]\n\n");
      std::fprintf(Out, "Exports an IDA database with its labels (IDA idalib + the unmodified Diaphora exporter).\n");
      std::fprintf(Out, "The input is copied first and its sha256 checked before and after; it is never changed.\n\n");
    } else {
      std::fprintf(Out, "usage: dsigmatcher ingest <binary> -o <out.sqlite> [--pdb <file> | --no-pdb] [tool options]\n\n");
      std::fprintf(Out, "Analyses a raw binary headless and exports it. No PDB is loaded unless --pdb is given\n");
      std::fprintf(Out, "(and never from a symbol server).\n\n");
    }
    std::fprintf(Out, "  -o, --output <path>              required; the export (replaced), with <stem>.export.json\n");
    if (Command == "ingest") {
      std::fprintf(Out, "      --pdb <file>                 load this PDB\n");
      std::fprintf(Out, "      --no-pdb                     explicitly no PDB (the default)\n");
    }
    PrintToolOptions(Out, false);
    return;
  }
  if (Command == "info") {
    std::fprintf(Out, "usage: dsigmatcher info <database.sqlite> [--json]\n\n");
    std::fprintf(Out, "Shows a Diaphora export's identity (sha256, input md5, functions) and, for a port output,\n");
    std::fprintf(Out, "its lineage, the hop history with each hop's port settings and where its names came from.\n\n");
    std::fprintf(Out, "      --json                       print one JSON object on stdout\n");
    return;
  }
  PrintGlobalUsage(Out);
  if (All) {
    for (const char* Each : {"extract", "ingest", "diff", "port", "update", "info"}) {
      std::fprintf(Out, "------------------------------------------------------------------------------\n");
      PrintCommandUsage(Out, Each, true);
      std::fprintf(Out, "\n");
    }
  }
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
      {"--output", "-o", true},          {"--ignore-small-functions", nullptr, false},
      {"--strict-sqlite", nullptr, false}, {"--allow-sqlite-mismatch", nullptr, false},
      {"--quiet", nullptr, false},       {"--json", nullptr, false},
      {"--checkpoint-dir", nullptr, true}, {"--resume", nullptr, true},
      // developer / parity harness (--help-all)
      {"--trace", nullptr, true},        {"--trace-rows", nullptr, false},     {"--snapshot-dir", nullptr, true},
      {"--snapshot-points", nullptr, true}, {"--snapshot-cache", nullptr, true}, {"--pair", nullptr, true},
      {"--replay", nullptr, true},       {"--stage", nullptr, true},           {"--iteration", nullptr, true},
      {"--heuristic", nullptr, true},    {"--snapshot-out", nullptr, true},    {"--related-cu-source", nullptr, true},
      // outside the parity configuration: accepted so they can be refused with exit 4
      {"--unreliable", nullptr, false},  {"--relaxed-ratio", nullptr, false},  {"--use-trained-model", nullptr, false},
      {"--project-script", nullptr, true}};
  static const std::vector<OptionSpec> Port = {
      {"--output", "-o", true},           {"--results", nullptr, true},          {"--no-keep-results", nullptr, false},
      {"--include-multimatch", nullptr, false}, {"--include-unreliable", nullptr, false},
      {"--overwrite-existing", nullptr, false}, {"--overwrite", nullptr, false},
      {"--overwrite-stripped", nullptr, false}, {"--min-ratio", nullptr, true},  {"--max-hops", nullptr, true},
      {"--store-full-paths", nullptr, false}, {"--ignore-small-functions", nullptr, false},
      {"--strict-sqlite", nullptr, false}, {"--allow-sqlite-mismatch", nullptr, false}, {"--quiet", nullptr, false},
      {"--json", nullptr, false}};
  static const std::vector<OptionSpec> Update = {
      {"--output", "-o", true},    {"--pdb", nullptr, true},      {"--no-pdb", nullptr, false},
      {"--python", nullptr, true}, {"--ida-dir", nullptr, true},  {"--diaphora-dir", nullptr, true},
      {"--temp-dir", nullptr, true}, {"--keep-temp", nullptr, false}, {"--timeout", nullptr, true},
      {"--export-script", nullptr, true}, {"--allow-no-decompiler", nullptr, false},
      {"--include-multimatch", nullptr, false}, {"--include-unreliable", nullptr, false},
      {"--overwrite-existing", nullptr, false}, {"--overwrite", nullptr, false},
      {"--overwrite-stripped", nullptr, false}, {"--min-ratio", nullptr, true},  {"--max-hops", nullptr, true},
      {"--store-full-paths", nullptr, false}, {"--ignore-small-functions", nullptr, false},
      {"--strict-sqlite", nullptr, false}, {"--allow-sqlite-mismatch", nullptr, false}, {"--quiet", nullptr, false},
      {"--json", nullptr, false}};
  static const std::vector<OptionSpec> Extract = {
      {"--output", "-o", true},    {"--python", nullptr, true},   {"--ida-dir", nullptr, true},
      {"--diaphora-dir", nullptr, true}, {"--temp-dir", nullptr, true}, {"--keep-temp", nullptr, false},
      {"--timeout", nullptr, true}, {"--export-script", nullptr, true}, {"--allow-no-decompiler", nullptr, false},
      {"--quiet", nullptr, false},  {"--json", nullptr, false}};
  static const std::vector<OptionSpec> Ingest = {
      {"--output", "-o", true},    {"--python", nullptr, true},   {"--ida-dir", nullptr, true},
      {"--diaphora-dir", nullptr, true}, {"--temp-dir", nullptr, true}, {"--keep-temp", nullptr, false},
      {"--timeout", nullptr, true}, {"--pdb", nullptr, true},     {"--no-pdb", nullptr, false},
      {"--export-script", nullptr, true}, {"--allow-no-decompiler", nullptr, false},
      {"--quiet", nullptr, false},  {"--json", nullptr, false}};
  static const std::vector<OptionSpec> Info = {{"--json", nullptr, false}};
  static const std::vector<OptionSpec> None = {};
  if (Command == "diff") {
    return Diff;
  }
  if (Command == "port") {
    return Port;
  }
  if (Command == "update") {
    return Update;
  }
  if (Command == "extract") {
    return Extract;
  }
  if (Command == "ingest") {
    return Ingest;
  }
  if (Command == "info") {
    return Info;
  }
  return None;
}

const std::set<std::string>& CommandNames() {
  static const std::set<std::string> Names = {"diff", "port", "update", "info", "extract", "ingest"};
  return Names;
}

struct Parsed {
  std::string Command;
  std::vector<std::string> Positional;
  std::map<std::string, std::string> Values;
  std::set<std::string> Flags;
  bool ShowHelp = false;
  bool HelpAll = false;
  bool ShowVersion = false;
  bool NoCommand = false;
  bool Json = false;
  bool Valid = true;
  std::string Error;

  bool Has(const std::string& Name) const { return Flags.count(Name) != 0 || Values.count(Name) != 0; }
  std::string Value(const std::string& Name) const {
    const auto Found = Values.find(Name);
    return Found == Values.end() ? std::string() : Found->second;
  }
};

// "--help" wins over every argument error, in any position: a command's help is printed and the exit
// code is 0. Otherwise the first error is reported (exit 2).
Parsed ParseArguments(int Argc, char** Argv) {
  Parsed Result;
  if (Argc < 2) {
    Result.NoCommand = true;
    Result.Valid = false;
    Result.Error = "no command given";
    return Result;
  }
  const std::string First = Argv[1];
  if (First == "-h" || First == "--help" || First == "help" || First == "--help-all") {
    Result.ShowHelp = true;
    Result.HelpAll = First == "--help-all";
    for (int Index = 2; Index < Argc; ++Index) {
      const std::string Argument = Argv[Index];
      if (Argument == "--help-all" || Argument == "--all") {
        Result.HelpAll = true;
      } else if (CommandNames().count(Argument) != 0 && Result.Command.empty()) {
        Result.Command = Argument;  // `dsigmatcher help port`
      }
    }
    return Result;
  }
  if (First == "--version" || First == "-V" || First == "version") {
    Result.ShowVersion = true;
    for (int Index = 2; Index < Argc; ++Index) {
      const std::string Argument = Argv[Index];
      if (Argument == "--json") {
        Result.Json = true;
      } else if (Result.Valid) {
        Result.Valid = false;
        Result.Error = "unknown option '" + Argument + "' for 'version' (it takes only --json)";
      }
    }
    return Result;
  }
  Result.Command = First;
  if (CommandNames().count(Result.Command) == 0) {
    Result.Valid = false;
    Result.Error = "unknown command '" + Result.Command + "'";
    Result.Command.clear();
    for (int Index = 2; Index < Argc; ++Index) {
      const std::string Argument = Argv[Index];
      if (Argument == "-h" || Argument == "--help" || Argument == "--help-all") {
        Result.ShowHelp = true;
      }
    }
    return Result;
  }
  const std::vector<OptionSpec>& Specs = OptionsFor(Result.Command);
  std::string FirstError;
  for (int Index = 2; Index < Argc; ++Index) {
    const std::string Argument = Argv[Index];
    if (Argument == "-h" || Argument == "--help") {
      Result.ShowHelp = true;
      continue;
    }
    if (Argument == "--help-all") {
      Result.ShowHelp = true;
      Result.HelpAll = true;
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
          if (FirstError.empty()) {
            FirstError = "option '" + Argument + "' requires a value";
          }
          continue;
        }
        const std::string Value = Argv[++Index];
        if (Result.Values.count(Spec->Name) != 0) {
          if (FirstError.empty()) {
            FirstError = std::string("option '") + Spec->Name + "' given more than once";
          }
          continue;
        }
        Result.Values[Spec->Name] = Value;
      } else {
        Result.Flags.insert(Spec->Name);
      }
      continue;
    }
    if (Argument.size() > 1 && Argument[0] == '-') {
      if (FirstError.empty()) {
        FirstError = "unknown option '" + Argument + "' for '" + Result.Command + "'";
      }
      continue;
    }
    Result.Positional.push_back(Argument);
  }
  Result.Json = Result.Flags.count("--json") != 0;
  if (Result.ShowHelp) {
    return Result;
  }
  if (!FirstError.empty()) {
    Result.Valid = false;
    Result.Error = FirstError;
    return Result;
  }
  const bool TwoInputs = Result.Command == "diff" || Result.Command == "port" || Result.Command == "update";
  const size_t Expected = TwoInputs ? 2u : 1u;
  if (Result.Positional.size() != Expected) {
    Result.Valid = false;
    Result.Error = "'" + Result.Command + "' expects " + std::to_string(Expected) + " path(s), got " +
                   std::to_string(Result.Positional.size());
    return Result;
  }
  const bool NeedsOutput = Result.Command == "port" || Result.Command == "update" || Result.Command == "extract" ||
                           Result.Command == "ingest";
  if (NeedsOutput && !Result.Has("--output")) {
    Result.Valid = false;
    Result.Error = "'" + Result.Command + "' requires -o <output>";
    return Result;
  }
  return Result;
}

// A whole decimal integer within [Min, Max]: no whitespace, no '+', no trailing text, no overflow.
std::optional<long long> ParseInteger(const std::string& Text, long long Min, long long Max) {
  if (Text.empty()) {
    return std::nullopt;
  }
  long long Value = 0;
  const char* Begin = Text.data();
  const char* End = Text.data() + Text.size();
  const std::from_chars_result Parsed = std::from_chars(Begin, End, Value);
  if (Parsed.ec != std::errc() || Parsed.ptr != End || Value < Min || Value > Max) {
    return std::nullopt;
  }
  return Value;
}

// A decimal number in [0, 1]: digits, '.', an exponent; no whitespace, no trailing text, not NaN or
// infinite, no underflow. strtod in the "C" locale (main never calls setlocale), so '.' is the point.
std::optional<double> ParseUnitInterval(const std::string& Text) {
  if (Text.empty()) {
    return std::nullopt;
  }
  for (const char Character : Text) {
    const bool Allowed = (Character >= '0' && Character <= '9') || Character == '.' || Character == 'e' ||
                         Character == 'E' || Character == '+' || Character == '-';
    if (!Allowed) {
      return std::nullopt;
    }
  }
  errno = 0;
  char* End = nullptr;
  const double Value = std::strtod(Text.c_str(), &End);
  if (End != Text.c_str() + Text.size() || errno == ERANGE || !std::isfinite(Value) || Value < 0.0 ||
      Value > 1.0) {
    return std::nullopt;
  }
  return Value;
}

// ---------------------------------------------------------------------------------------------
// Output

void PrintJson(const std::string& Command, int ExitCode, const std::string& Message, const JsonValue& Data) {
  JsonValue Root = JsonValue::Object();
  Root.Set("schema", JsonValue::Int(kJsonSchema));
  Root.Set("tool_version", JsonValue::String(DSIG_VERSION));
  Root.Set("command", JsonValue::String(Command));
  Root.Set("exit_code", JsonValue::Int(ExitCode));
  Root.Set("message", JsonValue::String(Message));
  if (Data.IsObject()) {
    for (const auto& [Key, Value] : Data.Members()) {
      Root.Set(Key, Value);
    }
  }
  std::printf("%s\n", Diff::JsonWrite(Root).c_str());
  std::fflush(stdout);
}

int UsageError(const Parsed& Arguments, const std::string& Message) {
  if (Arguments.Json) {
    PrintJson(Arguments.Command, kExitUsage, Message, JsonValue::Null());
  }
  std::fprintf(stderr, "error: %s\n", Message.c_str());
  if (Arguments.Command.empty()) {
    std::fprintf(stderr, "run 'dsigmatcher --help' for usage\n");
  } else {
    std::fprintf(stderr, "run 'dsigmatcher %s --help' for usage\n", Arguments.Command.c_str());
  }
  return kExitUsage;
}

// Prints a command's outcome: the report on success, "error: ..." on failure; with --json one JSON
// object on stdout either way (the error line still goes to stderr).
int ReportCommand(const Parsed& Arguments, const Cli::CommandOutcome& Outcome) {
  if (Arguments.Json) {
    PrintJson(Arguments.Command, Outcome.ExitCode, Outcome.ExitCode == Cli::kExitOk ? std::string() : Outcome.Message,
              Outcome.Data);
  }
  if (Outcome.ExitCode != Cli::kExitOk) {
    std::fprintf(stderr, "error: %s\n", Outcome.Message.c_str());
    return Outcome.ExitCode;
  }
  if (!Arguments.Json) {
    for (const std::string& Line : Outcome.Report) {
      std::printf("%s\n", Line.c_str());
    }
  }
  return Cli::kExitOk;
}

// The exit code of a diff outcome: the DiffStatus value (an unexpected exception inside the engine is
// DiffStatus::Internal, exit 70).
int DiffExitCode(const Diff::DiffOutcome& Outcome) {
  if (Outcome.Status == Diff::DiffStatus::Internal) {
    return Cli::kExitInternal;
  }
  return static_cast<int>(Outcome.Status);
}

// ---------------------------------------------------------------------------------------------
// diff

int RunDiffCommand(const Parsed& Arguments) {
  for (const char* Refused : {"--unreliable", "--relaxed-ratio", "--use-trained-model", "--project-script"}) {
    if (Arguments.Has(Refused)) {
      const std::string Message = std::string(Refused) +
                                  " is outside Diaphora's default configuration, which the parity engine always "
                                  "runs, and is not supported";
      Cli::CommandOutcome Refusal;
      Refusal.ExitCode = Cli::kExitUnsupported;
      Refusal.Message = Message;
      return ReportCommand(Arguments, Refusal);
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
  Args.CheckpointDir = Arguments.Value("--checkpoint-dir");
  Args.ResumeDir = Arguments.Value("--resume");
  if ((Arguments.Has("--checkpoint-dir") && Args.CheckpointDir.empty()) ||
      (Arguments.Has("--resume") && Args.ResumeDir.empty())) {
    return UsageError(Arguments, "--checkpoint-dir and --resume need a directory");
  }
  if (Arguments.Has("--iteration")) {
    const auto Value = ParseInteger(Arguments.Value("--iteration"), 0, INT_MAX);
    if (!Value) {
      return UsageError(Arguments, "--iteration must be an integer from 0 to " + std::to_string(INT_MAX));
    }
    Args.ReplayIteration = static_cast<int>(*Value);
  }
  if (Arguments.Has("--heuristic")) {
    const auto Value = ParseInteger(Arguments.Value("--heuristic"), 0, 49);
    if (!Value) {
      return UsageError(Arguments, "--heuristic must be a HEURISTICS index 0..49");
    }
    Args.ReplayHeuristic = static_cast<int>(*Value);
  }
  if (Arguments.Has("--related-cu-source")) {
    const std::string Source = Arguments.Value("--related-cu-source");
    if (Source != "native" && Source != "sql") {
      return UsageError(Arguments, "--related-cu-source must be native or sql");
    }
    Args.CuSource = Source == "sql" ? Diff::RelatedCuSource::Sql : Diff::RelatedCuSource::Native;
  }
  if (Arguments.Has("--trace-rows") && !Arguments.Has("--trace")) {
    return UsageError(Arguments, "--trace-rows needs --trace");
  }
  if ((Arguments.Has("--snapshot-points") || Arguments.Has("--snapshot-cache")) && !Arguments.Has("--snapshot-dir")) {
    return UsageError(Arguments, "--snapshot-points and --snapshot-cache need --snapshot-dir");
  }
  const bool ReplayFlags = Arguments.Has("--stage") || Arguments.Has("--snapshot-out") ||
                           Arguments.Has("--iteration") || Arguments.Has("--heuristic");
  if (Args.ReplayPath.empty() && ReplayFlags) {
    return UsageError(Arguments, "--stage, --snapshot-out, --iteration and --heuristic need --replay");
  }
  if (!Args.ReplayPath.empty() && (Args.ReplayStage.empty() || Args.SnapshotOut.empty())) {
    return UsageError(Arguments, "--replay needs --stage and --snapshot-out");
  }
  if (!Args.ReplayPath.empty() && Arguments.Has("--output")) {
    return UsageError(Arguments, "--replay writes --snapshot-out; -o/--output does not apply");
  }
  if (!Args.ReplayPath.empty() && (Arguments.Has("--checkpoint-dir") || Arguments.Has("--resume"))) {
    return UsageError(Arguments, "--checkpoint-dir and --resume do not apply to --replay");
  }

  const Diff::DiffOutcome Outcome = Diff::RunDiff(Args);
  const int ExitCode = Outcome.Status == Diff::DiffStatus::Ok ? Cli::kExitOk : DiffExitCode(Outcome);

  Cli::CommandOutcome Report;
  Report.ExitCode = ExitCode;
  Report.Message = Outcome.Message;
  JsonValue Data = JsonValue::Object();
  Data.Set("db1", JsonValue::String(Args.Db1));
  Data.Set("db2", JsonValue::String(Args.Db2));
  Data.Set("output", JsonValue::String(Outcome.OutputPath));
  Data.Set("output_written", JsonValue::Bool(Outcome.OutputWritten));
  Data.Set("replay", JsonValue::Bool(!Args.ReplayPath.empty()));
  Data.Set("diff_returned", JsonValue::Bool(Outcome.DiffReturned));
  Data.Set("mode", Outcome.Mode == '\0' ? JsonValue::Null() : JsonValue::String(std::string(1, Outcome.Mode)));
  Data.Set("best", JsonValue::UInt(Outcome.Best));
  Data.Set("partial", JsonValue::UInt(Outcome.Partial));
  Data.Set("unreliable", JsonValue::UInt(Outcome.Unreliable));
  Data.Set("multimatch", JsonValue::UInt(Outcome.Multimatch));
  JsonValue Skipped = JsonValue::Array();
  for (const std::string& Stage : Outcome.Skipped) {
    Skipped.Push(JsonValue::String(Stage));
  }
  Data.Set("skipped", std::move(Skipped));
  Data.Set("sqlite_version", JsonValue::String(Outcome.SqliteVersion));
  Data.Set("checkpoint_dir", Outcome.CheckpointDir.empty() ? JsonValue::Null() : JsonValue::String(Outcome.CheckpointDir));
  Data.Set("resumed_after", Outcome.ResumedAfter.empty() ? JsonValue::Null() : JsonValue::String(Outcome.ResumedAfter));
  Data.Set("checkpoints_written", JsonValue::UInt(Outcome.CheckpointsWritten));
  JsonValue Warnings = JsonValue::Array();
  for (const std::string& Warning : Outcome.Warnings) {
    Warnings.Push(JsonValue::String(Warning));
  }
  Data.Set("warnings", std::move(Warnings));
  Report.Data = std::move(Data);
  if (!Args.ReplayPath.empty()) {
    Report.Report.push_back("snapshot written : " + Outcome.OutputPath);
  } else {
    Report.Report.push_back(std::string("mode             : ") + Outcome.Mode);
    Report.Report.push_back("final results    : best " + std::to_string(Outcome.Best) + ", partial " +
                            std::to_string(Outcome.Partial) + ", unreliable " + std::to_string(Outcome.Unreliable) +
                            ", multimatch " + std::to_string(Outcome.Multimatch));
    Report.Report.push_back("results written  : " + Outcome.OutputPath);
    if (!Outcome.ResumedAfter.empty()) {
      Report.Report.push_back("resumed after    : " + Outcome.ResumedAfter);
    }
  }
  return ReportCommand(Arguments, Report);
}

// ---------------------------------------------------------------------------------------------
// port / update

// The port options shared by `port` and `update`; false (with the message) on a bad value.
bool PortOptionsFrom(const Parsed& Arguments, Cli::PortFromResultsArgs& Args, std::string& Error) {
  if (Arguments.Has("--min-ratio")) {
    const auto Value = ParseUnitInterval(Arguments.Value("--min-ratio"));
    if (!Value) {
      Error = "min-ratio must be a number between 0.0 and 1.0";
      return false;
    }
    Args.MinRatio = *Value;
  }
  if (Arguments.Has("--max-hops")) {
    const auto Value = ParseInteger(Arguments.Value("--max-hops"), 0, INT64_MAX);
    if (!Value) {
      Error = "max-hops must be an integer from 0 to " + std::to_string(INT64_MAX);
      return false;
    }
    Args.MaxHops = static_cast<int64_t>(*Value);
  }
  Args.Overwrite = Arguments.Has("--overwrite") || Arguments.Has("--overwrite-existing");
  Args.OverwriteStripped = Arguments.Has("--overwrite-stripped");
  if (Args.OverwriteStripped && !Args.Overwrite) {
    Error = "--overwrite-stripped needs --overwrite-existing";
    return false;
  }
  Args.IncludeMultimatch = Arguments.Has("--include-multimatch");
  Args.IncludeUnreliable = Arguments.Has("--include-unreliable");
  Args.StoreFullPaths = Arguments.Has("--store-full-paths");
  Args.StrictSqlite = Arguments.Has("--strict-sqlite");
  Args.AllowSqliteMismatch = Arguments.Has("--allow-sqlite-mismatch");
  Args.IgnoreSmallFunctions = Arguments.Has("--ignore-small-functions");
  Args.Quiet = Arguments.Has("--quiet");
  return true;
}

int RunPort(const Parsed& Arguments) {
  Cli::PortFromResultsArgs Args;
  std::string Error;
  if (!PortOptionsFrom(Arguments, Args, Error)) {
    return UsageError(Arguments, Error);
  }
  Args.Reference = Arguments.Positional[0];
  Args.Target = Arguments.Positional[1];
  Args.Output = Arguments.Value("--output");
  Args.Results = Arguments.Value("--results");
  Args.KeepResults = !Arguments.Has("--no-keep-results");
  if (Arguments.Has("--results") && Args.Results.empty()) {
    return UsageError(Arguments, "--results needs a file name");
  }
  return ReportCommand(Arguments, Cli::RunPortFromResults(Args));
}

// ---------------------------------------------------------------------------------------------
// extract / ingest / update tools

bool ToolOptions(const Parsed& Arguments, Cli::ExportToolOptions& Tools) {
  Tools.Python = Arguments.Value("--python");
  Tools.IdaDir = Arguments.Value("--ida-dir");
  Tools.DiaphoraDir = Arguments.Value("--diaphora-dir");
  Tools.TempDir = Arguments.Value("--temp-dir");
  Tools.KeepTemp = Arguments.Has("--keep-temp");
  Tools.ExportScript = Arguments.Value("--export-script");
  Tools.AllowNoDecompiler = Arguments.Has("--allow-no-decompiler");
  Tools.Quiet = Arguments.Has("--quiet");
  if (Arguments.Has("--timeout")) {
    // Parsed as a 64-bit integer and range-checked BEFORE it is narrowed to int, on every platform, so a
    // value such as 4294967301 is refused instead of wrapping to 5 (audit F42).
    const auto Value = ParseInteger(Arguments.Value("--timeout"), 0, Cli::kMaxExportTimeoutSeconds);
    if (!Value) {
      return false;
    }
    Tools.TimeoutSeconds = static_cast<int>(*Value);
  }
  return true;
}

std::string TimeoutError() {
  return "--timeout must be an integer number of seconds from 0 to " + std::to_string(Cli::kMaxExportTimeoutSeconds) +
         " (30 days)";
}

int RunUpdateCommand(const Parsed& Arguments) {
  Cli::UpdateArgs Args;
  std::string Error;
  if (!PortOptionsFrom(Arguments, Args.Port, Error)) {
    return UsageError(Arguments, Error);
  }
  if (!ToolOptions(Arguments, Args.Tools)) {
    return UsageError(Arguments, TimeoutError());
  }
  if (Arguments.Has("--pdb") && Arguments.Has("--no-pdb")) {
    return UsageError(Arguments, "--pdb and --no-pdb are exclusive");
  }
  Args.Labelled = Arguments.Positional[0];
  Args.Binary = Arguments.Positional[1];
  Args.Output = Arguments.Value("--output");
  Args.Pdb = Arguments.Value("--pdb");
  Args.NoPdb = Arguments.Has("--no-pdb");
  return ReportCommand(Arguments, Cli::RunUpdate(Args));
}

int RunExtractCommand(const Parsed& Arguments) {
  Cli::ExtractArgs Args;
  Args.Input = Arguments.Positional[0];
  Args.Output = Arguments.Value("--output");
  if (!ToolOptions(Arguments, Args.Tools)) {
    return UsageError(Arguments, TimeoutError());
  }
  return ReportCommand(Arguments, Cli::RunExtract(Args));
}

int RunIngestCommand(const Parsed& Arguments) {
  if (Arguments.Has("--pdb") && Arguments.Has("--no-pdb")) {
    return UsageError(Arguments, "--pdb and --no-pdb are exclusive");
  }
  Cli::IngestArgs Args;
  Args.Input = Arguments.Positional[0];
  Args.Output = Arguments.Value("--output");
  Args.Pdb = Arguments.Value("--pdb");
  Args.NoPdb = Arguments.Has("--no-pdb");
  if (!ToolOptions(Arguments, Args.Tools)) {
    return UsageError(Arguments, TimeoutError());
  }
  return ReportCommand(Arguments, Cli::RunIngest(Args));
}

// ---------------------------------------------------------------------------------------------
// info

std::string PadRight(const std::string& Text, size_t Width) {
  return Text.size() >= Width ? Text : Text + std::string(Width - Text.size(), ' ');
}

std::string PadLeft(const std::string& Text, size_t Width) {
  return Text.size() >= Width ? Text : std::string(Width - Text.size(), ' ') + Text;
}

// A ratio the way printf's %g writes it (six significant digits, no trailing zeros).
std::string RatioText(double Value) {
  std::ostringstream Stream;
  Stream.imbue(std::locale::classic());
  Stream << Value;
  return Stream.str();
}

std::string MaxHopsText(int64_t MaxHops) { return MaxHops < 0 ? std::string("none") : std::to_string(MaxHops); }

std::string YesNo(bool Value) { return Value ? "yes" : "no"; }

int RunInfo(const Parsed& Arguments) {
  const DatabaseIdentity Identity = InspectDatabase(Arguments.Positional[0]);
  Cli::CommandOutcome Outcome;
  if (!Identity.Ok) {
    Outcome.ExitCode = Identity.Failure == PortFailure::Input ? Cli::kExitUnsupported : Cli::kExitIo;
    Outcome.Message = Identity.Error;
    return ReportCommand(Arguments, Outcome);
  }

  std::vector<std::string>& Lines = Outcome.Report;
  JsonValue Data = JsonValue::Object();
  Lines.push_back("path             : " + Identity.Path);
  Lines.push_back("file sha256      : " + Identity.FileSha256);
  Lines.push_back("functions        : " + std::to_string(Identity.FunctionCount));
  Lines.push_back("processor        : " + Identity.Processor);
  Lines.push_back("input md5        : " + (Identity.InputMd5.empty() ? std::string("<none>") : Identity.InputMd5));
  Lines.push_back(std::string("provenance       : ") +
                  (Identity.HasProvenance ? "present" : "absent (hand labelled or raw export)"));
  Lines.push_back("hops recorded    : " + std::to_string(Identity.HopCount));
  if (!Identity.Lineage.empty()) {
    Lines.push_back("lineage          : " + Identity.Lineage);
  }
  Data.Set("path", JsonValue::String(Identity.Path));
  Data.Set("file_sha256", JsonValue::String(Identity.FileSha256));
  Data.Set("functions", JsonValue::Int(Identity.FunctionCount));
  Data.Set("processor", JsonValue::String(Identity.Processor));
  Data.Set("input_md5", JsonValue::String(Identity.InputMd5));
  Data.Set("provenance", JsonValue::Bool(Identity.HasProvenance));
  Data.Set("hops_recorded", JsonValue::Int(Identity.HopCount));
  Data.Set("lineage", JsonValue::String(Identity.Lineage));

  const std::unordered_map<std::string, NameOrigin> Origins = ReadNameOrigins(Identity.Path);
  std::map<int64_t, size_t> HopHistogram;
  size_t BelowBucket = 0;
  for (const auto& Entry : Origins) {
    HopHistogram[Entry.second.Hops] += 1;
    if (Entry.second.CumulativeRatio < kInfoConfidenceBucket) {
      ++BelowBucket;
    }
  }
  if (!Origins.empty()) {
    Lines.push_back("");
    Lines.push_back("ported names     : " + std::to_string(Origins.size()));
    Lines.push_back("  below 0.80 confidence (fixed bucket): " + std::to_string(BelowBucket));
    Lines.push_back("  hop histogram  :");
    for (const auto& Entry : HopHistogram) {
      Lines.push_back("    " + PadLeft(std::to_string(Entry.first), 2) + " hop(s) : " + std::to_string(Entry.second));
    }
  }
  Data.Set("ported_names", JsonValue::UInt(Origins.size()));
  Data.Set("ported_names_below_0_80", JsonValue::UInt(BelowBucket));
  JsonValue Histogram = JsonValue::Object();
  for (const auto& Entry : HopHistogram) {
    Histogram.Set(std::to_string(Entry.first), JsonValue::UInt(Entry.second));
  }
  Data.Set("hop_histogram", std::move(Histogram));

  JsonValue Hops = JsonValue::Array();
  if (!Identity.Hops.empty()) {
    Lines.push_back("");
    Lines.push_back("hop history:");
    Lines.push_back("  " + PadRight("hop", 4) + " " + PadRight("source input md5", 34) + " " +
                    PadRight("target input md5", 34) + " " + PadLeft("matches", 8) + " " + PadLeft("applied", 8));
    for (const HopRecord& Record : Identity.Hops) {
      Lines.push_back("  " + PadRight(std::to_string(Record.Hop), 4) + " " +
                      PadRight(Record.SourceInputMd5.empty() ? "<none>" : Record.SourceInputMd5, 34) + " " +
                      PadRight(Record.TargetInputMd5.empty() ? "<none>" : Record.TargetInputMd5, 34) + " " +
                      PadLeft(std::to_string(Record.Matches), 8) + " " + PadLeft(std::to_string(Record.NamesApplied), 8));
    }
    Lines.push_back("");
    Lines.push_back("hop settings:");
    for (const HopRecord& Record : Identity.Hops) {
      const std::string MinRatio = RatioText(Record.MinRatio);
      std::string Text = "  hop " + std::to_string(Record.Hop) + ": source " + Record.SourcePath + ", tool " +
                         Record.ToolVersion + ", applied " + Record.AppliedAt + ", min-ratio " + MinRatio +
                         ", max-hops " + MaxHopsText(Record.MaxHops);
      Lines.push_back(Text);
      if (Record.HasPortSettings) {
        std::string Categories = "best, partial";
        if (Record.IncludeUnreliable) {
          Categories += ", unreliable";
        }
        if (Record.IncludeMultimatch) {
          Categories += ", multimatch";
        }
        Lines.push_back("         results " + Record.ResultsPath + " (" +
                        (Record.ResultsSource.empty() ? std::string("results file") : Record.ResultsSource) +
                        ", sha256 " + Record.ResultsSha256.substr(0, 16) + "...)");
        Lines.push_back("         categories " + Categories + "; overwrite-existing " + YesNo(Record.Overwrite) +
                        ", overwrite-stripped " +
                        (Record.OverwriteStripped ? YesNo(*Record.OverwriteStripped) : std::string("not recorded")));
      } else {
        Lines.push_back("         results: not recorded (a port before --results existed)");
      }
      JsonValue Hop = JsonValue::Object();
      Hop.Set("hop", JsonValue::Int(Record.Hop));
      Hop.Set("source_path", JsonValue::String(Record.SourcePath));
      Hop.Set("source_input_md5", JsonValue::String(Record.SourceInputMd5));
      Hop.Set("source_file_sha256", JsonValue::String(Record.SourceFileSha256));
      Hop.Set("target_input_md5", JsonValue::String(Record.TargetInputMd5));
      Hop.Set("target_file_sha256_before", JsonValue::String(Record.TargetFileSha256Before));
      Hop.Set("applied_at", JsonValue::String(Record.AppliedAt));
      Hop.Set("tool_version", JsonValue::String(Record.ToolVersion));
      Hop.Set("functions_reference", JsonValue::Int(Record.FunctionsReference));
      Hop.Set("functions_target", JsonValue::Int(Record.FunctionsTarget));
      Hop.Set("matches", JsonValue::Int(Record.Matches));
      Hop.Set("names_applied", JsonValue::Int(Record.NamesApplied));
      Hop.Set("names_skipped_existing", JsonValue::Int(Record.NamesSkippedExisting));
      Hop.Set("names_skipped_hops", JsonValue::Int(Record.NamesSkippedHops));
      Hop.Set("names_skipped_ratio", JsonValue::Int(Record.NamesSkippedRatio));
      Hop.Set("min_ratio", std::isfinite(Record.MinRatio) ? JsonValue::Number(MinRatio) : JsonValue::Null());
      Hop.Set("max_hops", Record.MaxHops < 0 ? JsonValue::Null() : JsonValue::Int(Record.MaxHops));
      Hop.Set("lineage", JsonValue::String(Record.Lineage));
      if (Record.HasPortSettings) {
        JsonValue Settings = JsonValue::Object();
        Settings.Set("results_path", JsonValue::String(Record.ResultsPath));
        Settings.Set("results_sha256", JsonValue::String(Record.ResultsSha256));
        Settings.Set("results_source", JsonValue::String(Record.ResultsSource));
        Settings.Set("include_multimatch", JsonValue::Bool(Record.IncludeMultimatch));
        Settings.Set("include_unreliable", JsonValue::Bool(Record.IncludeUnreliable));
        Settings.Set("overwrite_existing", JsonValue::Bool(Record.Overwrite));
        Settings.Set("overwrite_stripped",
                     Record.OverwriteStripped ? JsonValue::Bool(*Record.OverwriteStripped) : JsonValue::Null());
        Settings.Set("names_confirmed", JsonValue::Int(Record.NamesConfirmed));
        Settings.Set("names_skipped_not_portable", JsonValue::Int(Record.NamesSkippedNotPortable));
        Settings.Set("names_skipped_conflict", JsonValue::Int(Record.NamesSkippedConflict));
        Settings.Set("names_skipped_duplicate", JsonValue::Int(Record.NamesSkippedDuplicate));
        Hop.Set("port", std::move(Settings));
      } else {
        Hop.Set("port", JsonValue::Null());
      }
      Hops.Push(std::move(Hop));
    }
  }
  Data.Set("hops", std::move(Hops));
  Outcome.Data = std::move(Data);
  return ReportCommand(Arguments, Outcome);
}

int RunMain(int Argc, char** Argv) {
  const Parsed Arguments = ParseArguments(Argc, Argv);

  if (Arguments.ShowHelp) {
    PrintCommandUsage(stdout, Arguments.Command, Arguments.HelpAll);
    return 0;
  }
  if (Arguments.ShowVersion) {
    if (!Arguments.Valid) {
      return UsageError(Arguments, Arguments.Error);
    }
    if (Arguments.Json) {
      JsonValue Data = JsonValue::Object();
      Data.Set("sqlite_version", JsonValue::String(sqlite3_libversion()));
      PrintJson("version", Cli::kExitOk, std::string(), Data);
      return Cli::kExitOk;
    }
    // The first line is the stable, machine-readable part: "dsigmatcher <major.minor.patch>".
    std::printf("dsigmatcher %s\n", DSIG_VERSION);
    std::printf("SQLite %s\n", sqlite3_libversion());
    return 0;
  }
  if (Arguments.NoCommand) {
    PrintGlobalUsage(stderr);
    return kExitUsage;
  }
  if (!Arguments.Valid) {
    return UsageError(Arguments, Arguments.Error);
  }

  if (Arguments.Command == "info") {
    return RunInfo(Arguments);
  }
  if (Arguments.Command == "port") {
    return RunPort(Arguments);
  }
  if (Arguments.Command == "update") {
    return RunUpdateCommand(Arguments);
  }
  if (Arguments.Command == "extract") {
    return RunExtractCommand(Arguments);
  }
  if (Arguments.Command == "ingest") {
    return RunIngestCommand(Arguments);
  }
  return RunDiffCommand(Arguments);
}

int RunGuarded(int Argc, char** Argv) {
  return Cli::RunGuarded([Argc, Argv] { return RunMain(Argc, Argv); });
}

// ---------------------------------------------------------------------------------------------
// Entry point. Every argument string is UTF-8 from here on: the engine hands paths to
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
  return RunGuarded(static_cast<int>(Arguments.size()), Pointers.data());
}
#endif

}

#if defined(_WIN32) && defined(_MSC_VER)
// MSVC and clang-cl: the CRT splits the wide command line with the same rules it uses for argv.
int wmain(int Argc, wchar_t** Argv) {
  // Before anything can load a DLL or start a child: no loader, crash or missing-file dialog, here or in
  // Python and IDA, which inherit the mode.
  DSig::Cli::DisableErrorDialogs();
  try {
    std::vector<std::string> Arguments;
    Arguments.reserve(static_cast<size_t>(Argc));
    for (int Index = 0; Index < Argc; ++Index) {
      Arguments.push_back(WideToUtf8(Argv[Index]));
    }
    return RunUtf8(std::move(Arguments));
  } catch (...) {
    std::fprintf(stderr, "error: internal error: out of memory\n");
    return DSig::Cli::kExitInternal;
  }
}
#else
int main(int Argc, char** Argv) {
  DSig::Cli::DisableErrorDialogs();  // as in wmain; nothing on POSIX
#ifdef _WIN32
  // Other Windows toolchains (MinGW without -municode): split GetCommandLineW() ourselves.
  int Count = 0;
  LPWSTR* Wide = CommandLineToArgvW(GetCommandLineW(), &Count);
  if (Wide != nullptr) {
    std::vector<std::string> Arguments;
    try {
      Arguments.reserve(static_cast<size_t>(Count));
      for (int Index = 0; Index < Count; ++Index) {
        Arguments.push_back(WideToUtf8(Wide[Index]));
      }
    } catch (...) {
      LocalFree(Wide);
      std::fprintf(stderr, "error: internal error: out of memory\n");
      return DSig::Cli::kExitInternal;
    }
    LocalFree(Wide);
    return RunUtf8(std::move(Arguments));
  }
#endif
  return RunGuarded(Argc, Argv);  // POSIX: argv bytes are the file names as given (UTF-8 on any sane system)
}
#endif
