#pragma once

// Where the parity corpus lives (plan §2.6, §7.1 D9). Nothing here is a hard-coded personal path:
// the root comes from the DSIG_CORPUS_ROOT environment variable, else from the DSIG_CORPUS_ROOT
// compile definition (the CMake cache variable of the same name). Tests that need it skip when it is
// absent. Layout (09-oracle.md): <root>/oracle/exports/<id>/<id>.sqlite,
// <root>/oracle/diffs/<pair>/run<N>/<pair>.diaphora, <root>/oracle/traces/<pair>/,
// <root>/oracle/vectors/<lane>/.
//
// Every path string here is UTF-8, like every path the engine takes (src/diff/FileIo.h): Utf8ToPath /
// PathToUtf8 convert explicitly, because std::filesystem::path(std::string) and path::string() use the
// ANSI code page on Windows.

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <optional>
#include <random>
#include <string>
#include <string_view>

#include "dsigmatcher/diff/Database.h"

#ifdef _WIN32
#include <cwchar>
#endif

namespace DSig::Test {

inline std::filesystem::path Utf8ToPath(std::string_view Utf8) {
  std::u8string Text(Utf8.size(), u8'\0');
  if (!Utf8.empty()) {
    std::memcpy(Text.data(), Utf8.data(), Utf8.size());
  }
  return std::filesystem::path(Text);
}

inline std::string PathToUtf8(const std::filesystem::path& Path) {
  const std::u8string Text = Path.u8string();
  std::string Out(Text.size(), '\0');
  if (!Text.empty()) {
    std::memcpy(Out.data(), Text.data(), Text.size());
  }
  return Out;
}

// getenv without MSVC's C4996 deprecation warning; UTF-8 on Windows (the wide environment).
inline std::optional<std::string> GetEnv(const char* Name) {
#ifdef _MSC_VER
  std::wstring WideName;
  for (const char* Ch = Name; *Ch != '\0'; ++Ch) {
    WideName += static_cast<wchar_t>(static_cast<unsigned char>(*Ch));  // variable names are ASCII
  }
  wchar_t* Buffer = nullptr;
  size_t Size = 0;
  if (_wdupenv_s(&Buffer, &Size, WideName.c_str()) != 0 || Buffer == nullptr) {
    return std::nullopt;
  }
  const std::filesystem::path Value(std::wstring(Buffer, std::wcslen(Buffer)));
  std::free(Buffer);
  return PathToUtf8(Value);  // UTF-16 -> UTF-8
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
  return Root ? PathToUtf8(Utf8ToPath(*Root) / "oracle") : std::string();
}

// <root>/oracle/exports/<id>/<id>.sqlite
inline std::string ExportPath(std::string_view Id) {
  const std::string Name(Id);
  return PathToUtf8(Utf8ToPath(OracleDir()) / "exports" / Utf8ToPath(Name) / Utf8ToPath(Name + ".sqlite"));
}

inline bool ExportAvailable(std::string_view Id) {
  std::error_code Error;
  return CorpusRoot().has_value() && std::filesystem::is_regular_file(Utf8ToPath(ExportPath(Id)), Error);
}

// <root>/oracle/diffs/<pair>/run<N>/<pair>.diaphora
inline std::string OracleResultsPath(std::string_view Pair, int Run = 1) {
  const std::string Name(Pair);
  return PathToUtf8(Utf8ToPath(OracleDir()) / "diffs" / Utf8ToPath(Name) / ("run" + std::to_string(Run)) /
                    Utf8ToPath(Name + ".diaphora"));
}

inline std::string TracesDir(std::string_view Pair) {
  return PathToUtf8(Utf8ToPath(OracleDir()) / "traces" / Utf8ToPath(Pair));
}

inline std::string VectorsDir(std::string_view Lane) {
  return PathToUtf8(Utf8ToPath(OracleDir()) / "vectors" / Utf8ToPath(Lane));
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
      std::filesystem::temp_directory_path(Error) / "dsig-tests" / Utf8ToPath(std::string(Suite) + "-" + Unique);
  std::filesystem::create_directories(Dir, Error);
  return PathToUtf8(Dir);
}

inline void RemoveScratchDir(const std::string& Dir) {
  std::error_code Error;
  std::filesystem::remove_all(Utf8ToPath(Dir), Error);
}

}
