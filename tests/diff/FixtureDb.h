#pragma once

// Builds SQLite files from committed text fixtures (plan §2.6). A fixture is SQL text such as Python's
// sqlite3 iterdump() of a Diaphora-schema export built by tools/parity/make_fixture.py: schema.py
// TABLES, every INDICES entry, rows, and the sqlite_stat1 rows `analyze` produced (iterdump writes
// `ANALYZE "sqlite_master";` followed by `INSERT INTO "sqlite_stat1" ...`). The planner reads
// sqlite_stat1 when a connection opens the finished file, so row order matches a real export built
// the same way. The file is then switched to WAL mode like a real export (diaphora_ida.py:1187-1188).

#include <sqlite3.h>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>

#include "diff/CorpusPaths.h"

namespace DSig::Test {

// Returns "" on success, else the error text. The database file (and its -wal/-shm) is replaced.
// DbPath is UTF-8 (SQLite takes UTF-8 file names; the removal converts explicitly).
inline std::string BuildFixtureDbFromText(std::string_view Sql, const std::string& DbPath, bool Wal = true) {
  std::error_code Error;
  for (const char* Suffix : {"", "-wal", "-shm", "-journal"}) {
    std::filesystem::remove(Utf8ToPath(DbPath + Suffix), Error);
  }
  sqlite3* Db = nullptr;
  if (sqlite3_open_v2(DbPath.c_str(), &Db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) != SQLITE_OK) {
    const std::string Message = Db != nullptr ? sqlite3_errmsg(Db) : "out of memory";
    if (Db != nullptr) {
      sqlite3_close(Db);
    }
    return "open " + DbPath + ": " + Message;
  }
  const std::string Text(Sql);
  char* Message = nullptr;
  if (sqlite3_exec(Db, Text.c_str(), nullptr, nullptr, &Message) != SQLITE_OK) {
    const std::string Failure = Message != nullptr ? Message : sqlite3_errmsg(Db);
    sqlite3_free(Message);
    sqlite3_close(Db);
    return "exec " + DbPath + ": " + Failure;
  }
  if (Wal && sqlite3_exec(Db, "PRAGMA journal_mode=WAL", nullptr, nullptr, &Message) != SQLITE_OK) {
    const std::string Failure = Message != nullptr ? Message : sqlite3_errmsg(Db);
    sqlite3_free(Message);
    sqlite3_close(Db);
    return "wal " + DbPath + ": " + Failure;
  }
  sqlite3_close(Db);
  return std::string();
}

inline std::string BuildFixtureDb(const std::string& SqlPath, const std::string& DbPath, bool Wal = true) {
  std::ifstream In(Utf8ToPath(SqlPath), std::ios::binary);
  if (!In) {
    return "cannot read " + SqlPath;
  }
  std::ostringstream Buffer;
  Buffer << In.rdbuf();
  return BuildFixtureDbFromText(Buffer.str(), DbPath, Wal);
}

}
