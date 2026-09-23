// `dsigmatcher update <labelled.sqlite> <new-binary> -o <new-labelled.sqlite>`: one step of the
// release chain. The labelled export of the previous build is the reference; the new build is
// analysed headless (`ingest`), diffed against it with the parity engine and the labels are ported
// (`port`, exactly as `port --results` applies the diff's results file). The output is the labelled
// export of the new build, the reference of the next `update`.
//
// Beside the output (<dir>/<stem> = the output path without its extension):
//   <stem>.ingest.sqlite        the unlabelled export of the new binary (ingest -o)
//   <stem>.ingest.export.json   the ingest's sidecar (tools, versions, hashes)
//   <stem>.diaphora             the diff's results file (what the port applied; query it with SQLite)
// Every argument, alias and directory check that can fail is made before the (slow) ingest starts;
// after that the first failing step stops the command with that step's exit code.

#include <cstdio>
#include <exception>
#include <filesystem>
#include <new>
#include <optional>
#include <string>
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

// <output dir>/<output stem><Suffix>
std::string BesideOutput(const std::string& Output, const std::string& Suffix) {
  const std::filesystem::path Native = PathOf(Output);
  return Utf8Of(Native.parent_path() / PathOf(Diff::PathStem(Utf8Of(Native.filename())) + Suffix));
}

JsonValue StepJson(const CommandOutcome& Step) {
  JsonValue Object = JsonValue::Object();
  Object.Set("exit_code", JsonValue::Int(Step.ExitCode));
  Object.Set("message", JsonValue::String(Step.Message));
  if (!Step.Data.IsNull()) {
    Object.Set("outcome", Step.Data);
  }
  return Object;
}

}

std::string UpdateExportPath(const std::string& Output) { return BesideOutput(Output, ".ingest.sqlite"); }

CommandOutcome RunUpdate(const UpdateArgs& Args, const IngestRunner& Ingest) {
  CommandOutcome Outcome;
  const std::string ExportPath = Args.Output.empty() ? std::string() : UpdateExportPath(Args.Output);
  const std::string SidecarPath = Args.Output.empty() ? std::string() : BesideOutput(Args.Output, ".ingest.export.json");
  const std::string ResultsPath = Args.Output.empty() ? std::string() : DefaultResultsPath(Args.Output);

  JsonValue Data = JsonValue::Object();
  Data.Set("labelled", JsonValue::String(Args.Labelled));
  Data.Set("binary", JsonValue::String(Args.Binary));
  Data.Set("output", JsonValue::String(Args.Output));
  Data.Set("export", JsonValue::String(ExportPath));
  Data.Set("export_sidecar", JsonValue::String(SidecarPath));
  Data.Set("results", JsonValue::String(ResultsPath));
  const auto Failure = [&](int Code, const std::string& Step, std::string Message) {
    Outcome.ExitCode = Code;
    Outcome.Message = Step.empty() ? std::move(Message) : Step + ": " + Message;
    Outcome.Report.clear();
    Data.Set("failed_step", Step.empty() ? JsonValue::Null() : JsonValue::String(Step));
    Outcome.Data = Data;
    return Outcome;
  };

  if (Args.Labelled.empty() || Args.Binary.empty() || Args.Output.empty()) {
    return Failure(kExitUsage, "", "update needs <labelled.sqlite> <new-binary> -o <new-labelled.sqlite>");
  }
  const PortFromResultsArgs& Options = Args.Port;
  if (!Options.Results.empty()) {
    return Failure(kExitUsage, "", "update always diffs the new binary itself; --results does not apply");
  }
  if (!Options.KeepResults) {
    return Failure(kExitUsage, "", "update keeps its results file; --no-keep-results does not apply");
  }
  if (!(Options.MinRatio >= 0.0 && Options.MinRatio <= 1.0)) {
    return Failure(kExitUsage, "", "min-ratio must be a number between 0.0 and 1.0");
  }
  if (Options.MaxHops < -1) {
    return Failure(kExitUsage, "", "max-hops must be zero or greater");
  }
  if (Options.OverwriteStripped && !Options.Overwrite) {
    return Failure(kExitUsage, "", "--overwrite-stripped needs --overwrite-existing");
  }
  if (!Args.Pdb.empty() && Args.NoPdb) {
    return Failure(kExitUsage, "", "--pdb and --no-pdb are exclusive");
  }

  // Nothing any step writes may be an input, and the steps' own files must not collide.
  std::vector<NamedPath> Inputs = DatabaseFileSet("the labelled database", Args.Labelled);
  Inputs.push_back({"the new binary", Args.Binary});
  if (!Args.Pdb.empty()) {
    Inputs.push_back({"the PDB", Args.Pdb});
  }
  std::vector<NamedPath> Intermediate = DatabaseFileSet("the intermediate export", ExportPath);
  Intermediate.push_back({"the ingest sidecar", SidecarPath});
  for (NamedPath& File : DatabaseFileSet("the results file", ResultsPath)) {
    Intermediate.push_back(std::move(File));
  }
  std::vector<NamedPath> Final = DatabaseFileSet("the output", Args.Output);
  for (NamedPath& File : DatabaseFileSet("the temporary output", Args.Output + ".dsig-tmp")) {
    Final.push_back(std::move(File));
  }
  std::vector<NamedPath> Written = Intermediate;
  Written.insert(Written.end(), Final.begin(), Final.end());
  if (const std::optional<std::string> Alias = FindPathAlias(Written, Inputs)) {
    return Failure(kExitUsage, "", *Alias);
  }
  if (const std::optional<std::string> Clash = FindPathAlias(Final, Intermediate)) {
    return Failure(kExitUsage, "", *Clash + "; choose another -o");
  }
  {
    const std::filesystem::path Directory = PathOf(Args.Output).parent_path();
    std::error_code Error;
    if (!Directory.empty() && !std::filesystem::is_directory(Directory, Error)) {
      return Failure(kExitIo, "", "output directory '" + Utf8Of(Directory) + "' does not exist");
    }
  }
  const DatabaseIdentity Labelled = InspectDatabase(Args.Labelled);
  if (!Labelled.Ok) {
    return Failure(Labelled.Failure == PortFailure::Input ? kExitUnsupported : kExitIo, "",
                   "labelled database: " + Labelled.Error);
  }
  {
    std::error_code Error;
    if (!std::filesystem::is_regular_file(PathOf(Args.Binary), Error)) {
      return Failure(kExitIo, "", "cannot read the new binary '" + Args.Binary + "'");
    }
  }

  // Step 1: ingest the new binary.
  IngestArgs Ingesting;
  Ingesting.Input = Args.Binary;
  Ingesting.Output = ExportPath;
  Ingesting.Pdb = Args.Pdb;
  Ingesting.NoPdb = Args.NoPdb;
  Ingesting.Tools = Args.Tools;
  const CommandOutcome Ingested = Ingest(Ingesting);
  Data.Set("ingest", StepJson(Ingested));
  if (Ingested.ExitCode != kExitOk) {
    // The bridge's messages already start with "ingest: ".
    const bool Prefixed = Ingested.Message.rfind("ingest: ", 0) == 0;
    return Failure(Ingested.ExitCode, "ingest", Prefixed ? Ingested.Message.substr(8) : Ingested.Message);
  }

  // Steps 2 and 3: the parity diff in-process, then the port of its results.
  PortFromResultsArgs Porting = Options;
  Porting.Reference = Args.Labelled;
  Porting.Target = ExportPath;
  Porting.Output = Args.Output;
  Porting.Results.clear();
  Porting.ResultsOutput = ResultsPath;
  Porting.KeepResults = true;
  const CommandOutcome Ported = RunPortFromResults(Porting);
  Data.Set("port", StepJson(Ported));
  if (Ported.ExitCode != kExitOk) {
    const bool DiffFailed = Ported.Message.rfind("diff: ", 0) == 0;
    return Failure(Ported.ExitCode, DiffFailed ? "diff" : "port",
                   DiffFailed ? Ported.Message.substr(6) : Ported.Message);
  }

  Outcome.ExitCode = kExitOk;
  Outcome.Report = Ingested.Report;
  Outcome.Report.push_back("");
  Outcome.Report.insert(Outcome.Report.end(), Ported.Report.begin(), Ported.Report.end());
  Data.Set("failed_step", JsonValue::Null());
  Outcome.Data = std::move(Data);
  return Outcome;
}

int RunGuarded(const std::function<int()>& Body) {
  const char* What = "unknown exception";
  std::string Text;
  try {
    return Body();
  } catch (const std::bad_alloc&) {
    What = "out of memory";
  } catch (const std::exception& Failure) {
    Text = Failure.what();
    What = Text.c_str();
  } catch (...) {
  }
  std::fflush(stdout);
  std::fprintf(stderr, "error: internal error: %s\n", What);
  std::fflush(stderr);
  return kExitInternal;
}

}
