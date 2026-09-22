#include "dsigmatcher/Provenance.h"

#include <sqlite3.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <vector>

#include "dsigmatcher/ExportDatabase.h"
#include "dsigmatcher/Naming.h"
#include "dsigmatcher/Sha256.h"

#ifndef DSIG_VERSION
#define DSIG_VERSION "0.0.0"
#endif

namespace DSig {

namespace {

const char* const CreateProvenanceSchema =
    "create table if not exists dsig_provenance ("
    "  hop integer primary key,"
    "  source_path text,"
    "  source_input_md5 text,"
    "  source_file_sha256 text,"
    "  target_input_md5 text,"
    "  target_file_sha256_before text,"
    "  applied_at text,"
    "  tool_version text,"
    "  functions_reference integer,"
    "  functions_target integer,"
    "  matches integer,"
    "  names_applied integer,"
    "  names_skipped_existing integer,"
    "  names_skipped_hops integer,"
    "  names_skipped_ratio integer,"
    "  min_ratio real,"
    "  max_hops integer,"
    "  lineage text"
    ");"
    "create table if not exists dsig_name_origin ("
    "  address text primary key,"
    "  name text,"
    "  origin_address text,"
    "  origin_name text,"
    "  hops integer,"
    "  cumulative_ratio real,"
    "  heuristic text,"
    "  first_labelled_at text"
    ");";

std::string ColumnString(sqlite3_stmt* Statement, int Index) {
  const unsigned char* Text = sqlite3_column_text(Statement, Index);
  if (Text == nullptr) {
    return std::string();
  }
  const int Length = sqlite3_column_bytes(Statement, Index);
  return std::string(reinterpret_cast<const char*>(Text), static_cast<size_t>(Length));
}

bool TableExists(sqlite3* Handle, const char* Table) {
  sqlite3_stmt* Statement = nullptr;
  const char* Query = "select 1 from sqlite_master where type='table' and name=?";
  if (sqlite3_prepare_v2(Handle, Query, -1, &Statement, nullptr) != SQLITE_OK) {
    return false;
  }
  sqlite3_bind_text(Statement, 1, Table, -1, SQLITE_TRANSIENT);
  const bool Found = sqlite3_step(Statement) == SQLITE_ROW;
  sqlite3_finalize(Statement);
  return Found;
}

bool CopyFileBinary(const std::string& From, const std::string& To) {
  std::ifstream Input(From, std::ios::binary);
  if (!Input.is_open()) {
    return false;
  }
  std::ofstream Output(To, std::ios::binary | std::ios::trunc);
  if (!Output.is_open()) {
    return false;
  }

  std::vector<char> Buffer(1024 * 1024);
  while (Input) {
    Input.read(Buffer.data(), static_cast<std::streamsize>(Buffer.size()));
    const std::streamsize Got = Input.gcount();
    if (Got > 0) {
      Output.write(Buffer.data(), Got);
    }
  }

  Output.flush();
  return Output.good();
}

std::string BuildLineage(const std::string& ParentLineage, const std::string& SourceMd5,
                         const std::string& TargetMd5) {
  const std::string Source = SourceMd5.empty() ? std::string("<unknown>") : SourceMd5;
  const std::string Target = TargetMd5.empty() ? std::string("<unknown>") : TargetMd5;

  if (ParentLineage.empty()) {
    return Source + " -> " + Target;
  }
  return ParentLineage + " -> " + Target;
}

const char* const InsertHopSql =
    "insert or replace into dsig_provenance (hop, source_path, source_input_md5, "
    "source_file_sha256, target_input_md5, target_file_sha256_before, "
    "applied_at, tool_version, functions_reference, functions_target, matches, names_applied, "
    "names_skipped_existing, names_skipped_hops, names_skipped_ratio, min_ratio, max_hops, "
    "lineage) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

void BindHop(sqlite3_stmt* Statement, const HopRecord& Record) {
  sqlite3_bind_int64(Statement, 1, Record.Hop);
  sqlite3_bind_text(Statement, 2, Record.SourcePath.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(Statement, 3, Record.SourceInputMd5.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(Statement, 4, Record.SourceFileSha256.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(Statement, 5, Record.TargetInputMd5.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(Statement, 6, Record.TargetFileSha256Before.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(Statement, 7, Record.AppliedAt.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(Statement, 8, Record.ToolVersion.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int64(Statement, 9, Record.FunctionsReference);
  sqlite3_bind_int64(Statement, 10, Record.FunctionsTarget);
  sqlite3_bind_int64(Statement, 11, Record.Matches);
  sqlite3_bind_int64(Statement, 12, Record.NamesApplied);
  sqlite3_bind_int64(Statement, 13, Record.NamesSkippedExisting);
  sqlite3_bind_int64(Statement, 14, Record.NamesSkippedHops);
  sqlite3_bind_int64(Statement, 15, Record.NamesSkippedRatio);
  sqlite3_bind_double(Statement, 16, Record.MinRatio);
  sqlite3_bind_int64(Statement, 17, Record.MaxHops);
  sqlite3_bind_text(Statement, 18, Record.Lineage.c_str(), -1, SQLITE_TRANSIENT);
}

}

std::string CurrentUtcTimestamp() {
  const auto Now = std::chrono::system_clock::now();
  const std::time_t Seconds = std::chrono::system_clock::to_time_t(Now);

  std::tm Parts{};
#ifdef _WIN32
  gmtime_s(&Parts, &Seconds);
#else
  gmtime_r(&Seconds, &Parts);
#endif

  char Buffer[32];
  std::snprintf(Buffer, sizeof(Buffer), "%04d-%02d-%02dT%02d:%02d:%02dZ", Parts.tm_year + 1900,
                Parts.tm_mon + 1, Parts.tm_mday, Parts.tm_hour, Parts.tm_min, Parts.tm_sec);
  return std::string(Buffer);
}

DatabaseIdentity InspectDatabase(const std::string& Path) {
  DatabaseIdentity Identity;
  Identity.Path = Path;

  bool HashOk = false;
  Identity.FileSha256 = Sha256::FileHex(Path, HashOk);
  if (!HashOk) {
    Identity.Error = "cannot read file for hashing";
    return Identity;
  }

  sqlite3* Handle = nullptr;
  if (sqlite3_open_v2(Path.c_str(), &Handle, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
    Identity.Error = Handle != nullptr ? sqlite3_errmsg(Handle) : "cannot allocate handle";
    if (Handle != nullptr) {
      sqlite3_close(Handle);
    }
    return Identity;
  }

  if (!TableExists(Handle, "functions")) {
    Identity.Error = "table 'functions' is missing; not a Diaphora export";
    sqlite3_close(Handle);
    return Identity;
  }

  sqlite3_stmt* Statement = nullptr;
  if (sqlite3_prepare_v2(Handle, "select count(*) from functions", -1, &Statement, nullptr) ==
      SQLITE_OK) {
    if (sqlite3_step(Statement) == SQLITE_ROW) {
      Identity.FunctionCount = sqlite3_column_int64(Statement, 0);
    }
    sqlite3_finalize(Statement);
  }

  if (TableExists(Handle, "program")) {
    Statement = nullptr;
    if (sqlite3_prepare_v2(Handle, "select processor, md5sum from program limit 1", -1, &Statement,
                           nullptr) == SQLITE_OK) {
      if (sqlite3_step(Statement) == SQLITE_ROW) {
        Identity.Processor = ColumnString(Statement, 0);
        Identity.InputMd5 = ColumnString(Statement, 1);
      }
      sqlite3_finalize(Statement);
    }
  }

  if (TableExists(Handle, "dsig_provenance")) {
    Identity.HasProvenance = true;
    Statement = nullptr;
    const char* Query =
        "select hop, source_path, source_input_md5, source_file_sha256, target_input_md5, "
        "target_file_sha256_before, applied_at, tool_version, "
        "functions_reference, functions_target, matches, names_applied, names_skipped_existing, "
        "names_skipped_hops, names_skipped_ratio, min_ratio, max_hops, lineage "
        "from dsig_provenance order by hop";
    if (sqlite3_prepare_v2(Handle, Query, -1, &Statement, nullptr) == SQLITE_OK) {
      while (sqlite3_step(Statement) == SQLITE_ROW) {
        HopRecord Record;
        Record.Hop = sqlite3_column_int64(Statement, 0);
        Record.SourcePath = ColumnString(Statement, 1);
        Record.SourceInputMd5 = ColumnString(Statement, 2);
        Record.SourceFileSha256 = ColumnString(Statement, 3);
        Record.TargetInputMd5 = ColumnString(Statement, 4);
        Record.TargetFileSha256Before = ColumnString(Statement, 5);
        Record.AppliedAt = ColumnString(Statement, 6);
        Record.ToolVersion = ColumnString(Statement, 7);
        Record.FunctionsReference = sqlite3_column_int64(Statement, 8);
        Record.FunctionsTarget = sqlite3_column_int64(Statement, 9);
        Record.Matches = sqlite3_column_int64(Statement, 10);
        Record.NamesApplied = sqlite3_column_int64(Statement, 11);
        Record.NamesSkippedExisting = sqlite3_column_int64(Statement, 12);
        Record.NamesSkippedHops = sqlite3_column_int64(Statement, 13);
        Record.NamesSkippedRatio = sqlite3_column_int64(Statement, 14);
        Record.MinRatio = sqlite3_column_double(Statement, 15);
        Record.MaxHops = sqlite3_column_int64(Statement, 16);
        Record.Lineage = ColumnString(Statement, 17);
        Identity.Lineage = Record.Lineage;
        Identity.Hops.push_back(Record);
      }
      sqlite3_finalize(Statement);
    }
    Identity.HopCount = static_cast<int64_t>(Identity.Hops.size());
  }

  sqlite3_close(Handle);
  Identity.Ok = true;
  return Identity;
}

std::unordered_map<std::string, NameOrigin> ReadNameOrigins(const std::string& Path) {
  std::unordered_map<std::string, NameOrigin> Origins;

  sqlite3* Handle = nullptr;
  if (sqlite3_open_v2(Path.c_str(), &Handle, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
    if (Handle != nullptr) {
      sqlite3_close(Handle);
    }
    return Origins;
  }

  if (!TableExists(Handle, "dsig_name_origin")) {
    sqlite3_close(Handle);
    return Origins;
  }

  sqlite3_stmt* Statement = nullptr;
  const char* Query =
      "select address, name, origin_address, origin_name, hops, cumulative_ratio, heuristic, "
      "first_labelled_at from dsig_name_origin";
  if (sqlite3_prepare_v2(Handle, Query, -1, &Statement, nullptr) == SQLITE_OK) {
    while (sqlite3_step(Statement) == SQLITE_ROW) {
      NameOrigin Origin;
      Origin.Address = ColumnString(Statement, 0);
      Origin.Name = ColumnString(Statement, 1);
      Origin.OriginAddress = ColumnString(Statement, 2);
      Origin.OriginName = ColumnString(Statement, 3);
      Origin.Hops = sqlite3_column_int64(Statement, 4);
      Origin.CumulativeRatio = sqlite3_column_double(Statement, 5);
      Origin.Heuristic = ColumnString(Statement, 6);
      Origin.FirstLabelledAt = ColumnString(Statement, 7);
      Origins.emplace(Origin.Address, Origin);
    }
    sqlite3_finalize(Statement);
  }

  sqlite3_close(Handle);
  return Origins;
}

PortResult PortSymbols(const PortOptions& Options) {
  PortResult Result;

  const DatabaseIdentity ReferenceIdentity = InspectDatabase(Options.ReferencePath);
  if (!ReferenceIdentity.Ok) {
    Result.Error = "reference: " + ReferenceIdentity.Error;
    return Result;
  }

  const DatabaseIdentity TargetIdentity = InspectDatabase(Options.TargetPath);
  if (!TargetIdentity.Ok) {
    Result.Error = "target: " + TargetIdentity.Error;
    return Result;
  }

  ExportDatabase Loader;

  FunctionTable Reference;
  ProgramInfo ReferenceProgram;
  const LoadResult ReferenceLoad = Loader.Load(Options.ReferencePath, Reference, ReferenceProgram);
  if (!ReferenceLoad.Ok) {
    Result.Error = "cannot load reference functions: " + ReferenceLoad.Error;
    return Result;
  }

  FunctionTable Target;
  ProgramInfo TargetProgram;
  const LoadResult TargetLoad = Loader.Load(Options.TargetPath, Target, TargetProgram);
  if (!TargetLoad.Ok) {
    Result.Error = "cannot load target functions: " + TargetLoad.Error;
    return Result;
  }

  DiffOptions Diff = Options.Diff;
  Diff.SameProcessor = Diff.SameProcessor || ReferenceIdentity.Processor == TargetIdentity.Processor;

  const DiffResult Diffed = RunExactHeuristics(Reference, Target, Diff);
  Result.Matches = static_cast<int64_t>(Diffed.Resolved.size());

  const std::unordered_map<std::string, NameOrigin> ReferenceOrigins =
      ReadNameOrigins(Options.ReferencePath);

  if (!CopyFileBinary(Options.TargetPath, Options.OutputPath)) {
    Result.Error = "cannot copy target database to output path";
    return Result;
  }

  sqlite3* Handle = nullptr;
  if (sqlite3_open_v2(Options.OutputPath.c_str(), &Handle,
                      SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) != SQLITE_OK) {
    Result.Error = Handle != nullptr ? sqlite3_errmsg(Handle) : "cannot allocate handle";
    if (Handle != nullptr) {
      sqlite3_close(Handle);
    }
    return Result;
  }

  char* ErrorMessage = nullptr;
  if (sqlite3_exec(Handle, "begin transaction;", nullptr, nullptr, &ErrorMessage) != SQLITE_OK) {
    Result.Error = ErrorMessage != nullptr ? ErrorMessage : "cannot begin transaction";
    sqlite3_free(ErrorMessage);
    sqlite3_close(Handle);
    return Result;
  }

  if (sqlite3_exec(Handle, CreateProvenanceSchema, nullptr, nullptr, &ErrorMessage) != SQLITE_OK) {
    Result.Error = ErrorMessage != nullptr ? ErrorMessage : "cannot create provenance tables";
    sqlite3_free(ErrorMessage);
    sqlite3_exec(Handle, "rollback transaction;", nullptr, nullptr, nullptr);
    sqlite3_close(Handle);
    return Result;
  }

  sqlite3_stmt* RenameStatement = nullptr;
  sqlite3_stmt* OriginStatement = nullptr;
  sqlite3_prepare_v2(Handle, "update functions set name = ?, mangled_function = ? where address = ?",
                     -1, &RenameStatement, nullptr);
  sqlite3_prepare_v2(
      Handle,
      "insert or replace into dsig_name_origin (address, name, origin_address, origin_name, hops, "
      "cumulative_ratio, heuristic, first_labelled_at) values (?, ?, ?, ?, ?, ?, ?, ?)",
      -1, &OriginStatement, nullptr);

  const std::string AppliedAt = CurrentUtcTimestamp();

  for (const Match& Item : Diffed.Resolved) {
    const std::string ReferenceAddress = std::string(Reference.Text(Reference.Address[Item.Index1]));
    const std::string_view ReferenceName = Reference.Text(Reference.Name[Item.Index1]);
    const std::string TargetAddress = std::string(Target.Text(Target.Address[Item.Index2]));
    const std::string_view TargetName = Target.Text(Target.Name[Item.Index2]);

    if (!IsPortableSymbol(ReferenceName)) {
      ++Result.NamesSkippedNotPortable;
      continue;
    }

    const auto Inherited = ReferenceOrigins.find(ReferenceAddress);
    const bool HasHistory = Inherited != ReferenceOrigins.end();

    const std::string OriginAddress = HasHistory ? Inherited->second.OriginAddress : ReferenceAddress;
    const std::string OriginName = HasHistory ? Inherited->second.OriginName : std::string(ReferenceName);
    const int64_t Hops = HasHistory ? Inherited->second.Hops + 1 : 1;
    const double PreviousRatio = HasHistory ? Inherited->second.CumulativeRatio : 1.0;
    const std::string FirstLabelledAt =
        HasHistory && !Inherited->second.FirstLabelledAt.empty() ? Inherited->second.FirstLabelledAt
                                                                 : AppliedAt;
    const double Cumulative = PreviousRatio * static_cast<double>(Item.Ratio);

    if (Options.MaxHops >= 0 && Hops > Options.MaxHops) {
      ++Result.NamesSkippedHops;
      continue;
    }
    if (Cumulative < Options.MinCumulativeRatio) {
      ++Result.NamesSkippedRatio;
      continue;
    }
    if (!Options.OverwriteExistingNames && IsPortableSymbol(TargetName) &&
        TargetName != ReferenceName) {
      ++Result.NamesSkippedExisting;
      continue;
    }

    sqlite3_bind_text(RenameStatement, 1, ReferenceName.data(),
                      static_cast<int>(ReferenceName.size()), SQLITE_TRANSIENT);
    sqlite3_bind_text(RenameStatement, 2, ReferenceName.data(),
                      static_cast<int>(ReferenceName.size()), SQLITE_TRANSIENT);
    sqlite3_bind_text(RenameStatement, 3, TargetAddress.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(RenameStatement);
    sqlite3_reset(RenameStatement);

    const std::string Heuristic = std::string("best#") + std::to_string(Item.HeuristicId);

    sqlite3_bind_text(OriginStatement, 1, TargetAddress.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(OriginStatement, 2, ReferenceName.data(),
                      static_cast<int>(ReferenceName.size()), SQLITE_TRANSIENT);
    sqlite3_bind_text(OriginStatement, 3, OriginAddress.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(OriginStatement, 4, OriginName.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(OriginStatement, 5, Hops);
    sqlite3_bind_double(OriginStatement, 6, Cumulative);
    sqlite3_bind_text(OriginStatement, 7, Heuristic.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(OriginStatement, 8, FirstLabelledAt.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(OriginStatement);
    sqlite3_reset(OriginStatement);

    ++Result.NamesApplied;
  }

  sqlite3_finalize(RenameStatement);
  sqlite3_finalize(OriginStatement);

  const std::string Lineage =
      BuildLineage(ReferenceIdentity.Lineage, ReferenceIdentity.InputMd5, TargetIdentity.InputMd5);
  Result.Lineage = Lineage;

  int64_t HighestParentHop = 0;
  for (const HopRecord& Record : ReferenceIdentity.Hops) {
    HighestParentHop = std::max(HighestParentHop, Record.Hop);
  }
  Result.NewHop = HighestParentHop + 1;

  sqlite3_exec(Handle, "delete from dsig_provenance;", nullptr, nullptr, nullptr);

  sqlite3_stmt* HopStatement = nullptr;
  sqlite3_prepare_v2(Handle, InsertHopSql, -1, &HopStatement, nullptr);

  for (const HopRecord& Record : ReferenceIdentity.Hops) {
    BindHop(HopStatement, Record);
    sqlite3_step(HopStatement);
    sqlite3_reset(HopStatement);
  }

  HopRecord NewRecord;
  NewRecord.Hop = Result.NewHop;
  NewRecord.SourcePath = Options.ReferencePath;
  NewRecord.SourceInputMd5 = ReferenceIdentity.InputMd5;
  NewRecord.SourceFileSha256 = ReferenceIdentity.FileSha256;
  NewRecord.TargetInputMd5 = TargetIdentity.InputMd5;
  NewRecord.TargetFileSha256Before = TargetIdentity.FileSha256;
  NewRecord.AppliedAt = AppliedAt;
  NewRecord.ToolVersion = DSIG_VERSION;
  NewRecord.FunctionsReference = static_cast<int64_t>(Reference.Count());
  NewRecord.FunctionsTarget = static_cast<int64_t>(Target.Count());
  NewRecord.Matches = Result.Matches;
  NewRecord.NamesApplied = Result.NamesApplied;
  NewRecord.NamesSkippedExisting = Result.NamesSkippedExisting;
  NewRecord.NamesSkippedHops = Result.NamesSkippedHops;
  NewRecord.NamesSkippedRatio = Result.NamesSkippedRatio;
  NewRecord.MinRatio = Options.MinCumulativeRatio;
  NewRecord.MaxHops = Options.MaxHops;
  NewRecord.Lineage = Lineage;

  BindHop(HopStatement, NewRecord);
  sqlite3_step(HopStatement);
  sqlite3_finalize(HopStatement);

  if (sqlite3_exec(Handle, "commit transaction;", nullptr, nullptr, &ErrorMessage) != SQLITE_OK) {
    Result.Error = ErrorMessage != nullptr ? ErrorMessage : "cannot commit transaction";
    sqlite3_free(ErrorMessage);
    sqlite3_close(Handle);
    return Result;
  }

  sqlite3_close(Handle);

  bool OutputHashOk = false;
  Result.OutputSha256 = Sha256::FileHex(Options.OutputPath, OutputHashOk);
  if (!OutputHashOk) {
    Result.OutputSha256.clear();
  }

  Result.Ok = true;
  return Result;
}

}
