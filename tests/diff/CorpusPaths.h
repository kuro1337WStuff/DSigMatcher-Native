#pragma once

// Where the parity corpus lives (plan §2.6, §7.1 D9). Nothing here is a hard-coded personal path:
// the root comes from the DSIG_CORPUS_ROOT environment variable, else from the DSIG_CORPUS_ROOT
// compile definition (the CMake cache variable of the same name). Tests that need it skip when it is
// absent. Layout (09-oracle.md): <root>/oracle/exports/<id>/<id>.sqlite,
// <root>/oracle/diffs/<pair>/run<N>/<pair>.diaphora, <root>/oracle/traces/<pair>/,
// <root>/oracle/vectors/<lane>/.

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <random>
#include <string>
#include <string_view>

#include "dsigmatcher/diff/Database.h"

namespace DSig::Test {

// getenv without MSVC's C4996 deprecation warning.
inline std::optional<std::string> GetEnv(const char* Name) {
#ifdef _MSC_VER
  char* Buffer = nullptr;
  size_t Size = 0;
  if (_dupenv_s(&Buffer, &Size, Name) != 0 || Buffer == nullptr) {
    return std::nullopt;
  }
  std::string Value(Buffer);
  std::free(Buffer);
  return Value;
#else
  const char* Value = std::getenv(Name);
  if (Value == nullptr) {
    return std::nullopt;
  }
  return std::string(Value);
#endif
}

inline std::optional<std::string> CorpusRoot() {
  if (auto Env = GetEnv("DSIG_CORPUS_ROOT"); Env && !Env->empty()) {
    return Env;
  }
#ifdef DSIG_CORPUS_ROOT
  if (std::string_view(DSIG_CORPUS_ROOT).size() > 0) {
    return std::string(DSIG_CORPUS_ROOT);
  }
#endif
  return std::nullopt;
}

inline std::string OracleDir() {
  const auto Root = CorpusRoot();
  return Root ? (std::filesystem::path(*Root) / "oracle").string() : std::string();
}

// <root>/oracle/exports/<id>/<id>.sqlite
inline std::string ExportPath(std::string_view Id) {
  const std::string Name(Id);
  return (std::filesystem::path(OracleDir()) / "exports" / Name / (Name + ".sqlite")).string();
}

inline bool ExportAvailable(std::string_view Id) {
  std::error_code Error;
  return CorpusRoot().has_value() && std::filesystem::is_regular_file(ExportPath(Id), Error);
}

// <root>/oracle/diffs/<pair>/run<N>/<pair>.diaphora
inline std::string OracleResultsPath(std::string_view Pair, int Run = 1) {
  const std::string Name(Pair);
  return (std::filesystem::path(OracleDir()) / "diffs" / Name / ("run" + std::to_string(Run)) /
          (Name + ".diaphora"))
      .string();
}

inline std::string TracesDir(std::string_view Pair) {
  return (std::filesystem::path(OracleDir()) / "traces" / std::string(Pair)).string();
}

inline std::string VectorsDir(std::string_view Lane) {
  return (std::filesystem::path(OracleDir()) / "vectors" / std::string(Lane)).string();
}

// Tests that compare row order with the oracle need the oracle's SQLite (plan §2.6).
inline bool OracleSqlite() { return Diff::DiffDatabase::IsOracleSqlite(); }

// DSIG_TEST_DATA_DIR (compile definition): tests/diff in the source tree, for committed fixtures.
inline std::string TestDataDir() {
#ifdef DSIG_TEST_DATA_DIR
  return std::string(DSIG_TEST_DATA_DIR);
#else
  return std::string();
#endif
}

// A scratch directory for files a test builds, unique per process (several worktrees may run the
// same suite at once) under the system temp directory. Callers remove it when done.
inline std::string ScratchDir(std::string_view Suite) {
  static const std::string Unique = [] {
    std::random_device Device;
    return std::to_string(Device()) + "-" +
           std::to_string(static_cast<unsigned long long>(
               std::chrono::steady_clock::now().time_since_epoch().count() & 0xFFFFFFFFull));
  }();
  std::error_code Error;
  const std::filesystem::path Dir =
      std::filesystem::temp_directory_path(Error) / "dsig-tests" / (std::string(Suite) + "-" + Unique);
  std::filesystem::create_directories(Dir, Error);
  return Dir.string();
}

inline void RemoveScratchDir(const std::string& Dir) {
  std::error_code Error;
  std::filesystem::remove_all(Dir, Error);
}

}
