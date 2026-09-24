// sqlite_info: prints the SQLite the build links (version, source id, compile options) so every test log
// shows which SQLite produced it. With the bundled SQLite (DSIG_VENDORED_SQLITE, cmake/VendoredSqlite.cmake)
// it also checks that the library is the parity oracle's: SQLite 3.51.1 from the same check-in, compiled
// with the same `pragma compile_options` as conda's sqlite-3.51.1 DLL that Diaphora ran on
// (docs/parity/00-plan.md §5 R1). Only the compiler name and the platform-dependent entries (mutex
// implementation, atomic intrinsics) may differ; none of them influences query plans or row order.

#include <cstdio>
#include <cstring>
#include <iterator>
#include <set>
#include <string>
#include <vector>

#include <sqlite3.h>

#include "NoErrorDialogs.h"

namespace {

int ChecksRun = 0;
int ChecksFailed = 0;

void Check(bool Ok, const std::string& What) {
  ++ChecksRun;
  if (!Ok) {
    ++ChecksFailed;
    std::printf("  FAIL %s\n", What.c_str());
  }
}

std::vector<std::string> CompileOptions() {
  std::vector<std::string> Options;
  for (int Index = 0;; ++Index) {
    const char* Option = sqlite3_compileoption_get(Index);
    if (Option == nullptr) {
      break;
    }
    Options.emplace_back(Option);
  }
  return Options;
}

#ifdef DSIG_VENDORED_SQLITE
// `pragma compile_options` of the oracle's SQLite (conda sqlite-3.51.1-hda9a48d_0, Python's sqlite3),
// without COMPILER=, MUTEX_* and ATOMIC_INTRINSICS=, which are added per platform below.
const char* const kOracleOptions[] = {
    "DEFAULT_AUTOVACUUM",
    "DEFAULT_CACHE_SIZE=-2000",
    "DEFAULT_FILE_FORMAT=4",
    "DEFAULT_JOURNAL_SIZE_LIMIT=-1",
    "DEFAULT_MMAP_SIZE=0",
    "DEFAULT_PAGE_SIZE=4096",
    "DEFAULT_PCACHE_INITSZ=20",
    "DEFAULT_RECURSIVE_TRIGGERS",
    "DEFAULT_SECTOR_SIZE=4096",
    "DEFAULT_SYNCHRONOUS=2",
    "DEFAULT_WAL_AUTOCHECKPOINT=1000",
    "DEFAULT_WAL_SYNCHRONOUS=2",
    "DEFAULT_WORKER_THREADS=0",
    "DIRECT_OVERFLOW_READ",
    "ENABLE_COLUMN_METADATA",
    "ENABLE_FTS5",
    "ENABLE_GEOPOLY",
    "ENABLE_RTREE",
    "MALLOC_SOFT_LIMIT=1024",
    "MAX_ATTACHED=10",
    "MAX_COLUMN=2000",
    "MAX_COMPOUND_SELECT=500",
    "MAX_DEFAULT_PAGE_SIZE=8192",
    "MAX_EXPR_DEPTH=1000",
    "MAX_FUNCTION_ARG=1000",
    "MAX_LENGTH=1000000000",
    "MAX_LIKE_PATTERN_LENGTH=50000",
    "MAX_MMAP_SIZE=0x7fff0000",
    "MAX_PAGE_COUNT=0xfffffffe",
    "MAX_PAGE_SIZE=65536",
    "MAX_SQL_LENGTH=1000000000",
    "MAX_TRIGGER_DEPTH=1000",
    "MAX_VARIABLE_NUMBER=250000",
    "MAX_VDBE_OP=250000000",
    "MAX_WORKER_THREADS=8",
    "SYSTEM_MALLOC",
    "TEMP_STORE=1",
    "THREADSAFE=1",
};
constexpr const char* kOracleVersion = "3.51.1";
constexpr const char* kOracleSourceId =
    "2025-11-28 17:28:25 281fc0e9afc38674b9b0991943b9e9d1e64c6cbdb133d35f6f5c87ff6af38a88";

void CheckOracleBuild(const std::vector<std::string>& Options) {
  Check(std::strcmp(sqlite3_libversion(), kOracleVersion) == 0,
        std::string("sqlite3_libversion() is ") + sqlite3_libversion() + ", expected " + kOracleVersion);
  Check(std::strcmp(sqlite3_sourceid(), kOracleSourceId) == 0,
        std::string("sqlite3_sourceid() is ") + sqlite3_sourceid() + ", expected " + kOracleSourceId);
  Check(sqlite3_threadsafe() == 1, "sqlite3_threadsafe() != 1");

  std::set<std::string> Expected(std::begin(kOracleOptions), std::end(kOracleOptions));
#ifdef _WIN32
  Expected.insert("MUTEX_W32");
#else
  Expected.insert("MUTEX_PTHREADS");
#endif
  std::set<std::string> Actual;
  for (const std::string& Option : Options) {
    if (Option.rfind("COMPILER=", 0) == 0 || Option.rfind("ATOMIC_INTRINSICS=", 0) == 0) {
      continue;  // compiler-dependent, not a planner input
    }
    Actual.insert(Option);
  }
  for (const std::string& Option : Expected) {
    Check(Actual.count(Option) == 1, "compile option missing: " + Option);
  }
  for (const std::string& Option : Actual) {
    Check(Expected.count(Option) == 1, "compile option the oracle does not have: " + Option);
  }

  // The sorter is stable only single-threaded (plan §3.4): a fresh connection starts with threads = 0.
  sqlite3* Db = nullptr;
  Check(sqlite3_open_v2(":memory:", &Db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) == SQLITE_OK,
        "open :memory:");
  if (Db != nullptr) {
    sqlite3_stmt* Stmt = nullptr;
    int Threads = -1;
    if (sqlite3_prepare_v2(Db, "pragma threads", -1, &Stmt, nullptr) == SQLITE_OK && sqlite3_step(Stmt) == SQLITE_ROW) {
      Threads = sqlite3_column_int(Stmt, 0);
    }
    sqlite3_finalize(Stmt);
    Check(Threads == 0, "pragma threads is " + std::to_string(Threads) + ", expected 0");
    sqlite3_close(Db);
  }
}
#endif

}  // namespace

int main() {
  DSig::Test::DisableErrorDialogs();  // first: no loader, crash or missing-file dialog (Windows)
  const std::vector<std::string> Options = CompileOptions();
#ifdef DSIG_VENDORED_SQLITE
  const char* Origin = "bundled (DSIG_VENDORED_SQLITE=ON)";
#else
  const char* Origin = "system (DSIG_VENDORED_SQLITE=OFF)";
#endif
  std::printf("SQLite %s, %s\n", sqlite3_libversion(), Origin);
  std::printf("source id: %s\n", sqlite3_sourceid());
  std::printf("compile options:");
  for (const std::string& Option : Options) {
    std::printf(" %s", Option.c_str());
  }
  std::printf("\n");
#ifdef DSIG_VENDORED_SQLITE
  CheckOracleBuild(Options);
#endif
  std::printf("sqlite_info: %d checks run, %d failed\n", ChecksRun, ChecksFailed);
  return ChecksFailed == 0 ? 0 : 1;
}
