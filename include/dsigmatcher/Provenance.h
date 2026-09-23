#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "dsigmatcher/Heuristics.h"
#include "dsigmatcher/Types.h"

namespace DSig {

struct NameOrigin {
  std::string Address;
  std::string Name;
  std::string OriginAddress;
  std::string OriginName;
  int64_t Hops = 0;
  double CumulativeRatio = 1.0;
  std::string Heuristic;
  std::string FirstLabelledAt;
};

struct HopRecord {
  int64_t Hop = 0;
  std::string SourcePath;
  std::string SourceInputMd5;
  std::string SourceFileSha256;
  std::string TargetInputMd5;
  std::string TargetFileSha256Before;
  std::string AppliedAt;
  std::string ToolVersion;
  int64_t FunctionsReference = 0;
  int64_t FunctionsTarget = 0;
  int64_t Matches = 0;
  int64_t NamesApplied = 0;
  int64_t NamesSkippedExisting = 0;
  int64_t NamesSkippedHops = 0;
  int64_t NamesSkippedRatio = 0;
  double MinRatio = 0.0;
  int64_t MaxHops = -1;
  std::string Lineage;
};

struct DatabaseIdentity {
  std::string Path;
  bool Ok = false;
  std::string Error;
  std::string InputMd5;
  std::string Processor;
  std::string FileSha256;
  int64_t FunctionCount = 0;
  bool HasProvenance = false;
  int64_t HopCount = 0;
  std::string Lineage;
  std::vector<HopRecord> Hops;
};

struct PortOptions {
  std::string ReferencePath;
  std::string TargetPath;
  std::string OutputPath;
  bool OverwriteExistingNames = false;
  double MinCumulativeRatio = 0.0;
  int64_t MaxHops = -1;
  DiffOptions Diff;
};

struct PortResult {
  bool Ok = false;
  std::string Error;
  int64_t Matches = 0;
  int64_t NamesApplied = 0;
  int64_t NamesConfirmed = 0;
  int64_t NamesSkippedExisting = 0;
  int64_t NamesSkippedHops = 0;
  int64_t NamesSkippedRatio = 0;
  int64_t NamesSkippedNotPortable = 0;
  int64_t NewHop = 0;
  std::string OutputSha256;
  std::string Lineage;
};

std::string CurrentUtcTimestamp();

DatabaseIdentity InspectDatabase(const std::string& Path);

std::unordered_map<std::string, NameOrigin> ReadNameOrigins(const std::string& Path);

PortResult PortSymbols(const PortOptions& Options);

}
