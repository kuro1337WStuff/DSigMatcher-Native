#pragma once

// Path A connection (02 §18.3). One read-only connection holds both exports:
//   sqlite3_open_v2(<db1>, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI)
//   ATTACH ? AS diff  with <db2> bound                  (read-only through the connection's open flags)
// Each input is named by a "file:...?mode=ro&immutable=1" URI (DiffDatabase::UriForPath), so reading it
// creates no -wal / -shm beside it; an input with a non-empty -wal or -journal keeps its plain UTF-8 file
// name instead, so committed WAL frames are read and a hot journal is refused (Database.cpp
// InputFileName).
// exactly the schema names Diaphora uses (`main`, and `diff` from `attach "<db2>" as diff`,
// D:2441 / D:657). The engine never writes, never runs ANALYZE and never creates indexes, so the
// planner sees the exporter's indices and sqlite_stat1 unchanged. `pragma threads` stays 0 so the
// sorter is stable (04a §6.4).

#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

struct sqlite3;
struct sqlite3_stmt;

namespace DSig::Diff {

// sqlite3_column_type() storage classes.
enum class SqlType : uint8_t { Null = 0, Integer = 1, Real = 2, Text = 3, Blob = 4 };

// One stored value, never coerced (08 §9.1).
struct SqlCell {
  SqlType Type = SqlType::Null;
  int64_t Int = 0;
  double Real = 0.0;
  std::string Bytes;  // TEXT (raw UTF-8 bytes) or BLOB

  bool IsNull() const { return Type == SqlType::Null; }
  std::optional<std::string_view> TextOrNull() const {
    if (Type == SqlType::Text || Type == SqlType::Blob) {
      return std::string_view(Bytes);
    }
    return std::nullopt;
  }
};

// A bound parameter with Python's binding types (08 §1.2): str -> TEXT, float -> REAL,
// int -> INTEGER, None -> NULL.
struct BindValue {
  SqlType Type = SqlType::Null;
  int64_t Int = 0;
  double Real = 0.0;
  std::string Text;

  static BindValue Null() { return BindValue(); }
  static BindValue Integer(int64_t Value) {
    BindValue Result;
    Result.Type = SqlType::Integer;
    Result.Int = Value;
    return Result;
  }
  static BindValue Double(double Value) {
    BindValue Result;
    Result.Type = SqlType::Real;
    Result.Real = Value;
    return Result;
  }
  static BindValue Str(std::string_view Value) {
    BindValue Result;
    Result.Type = SqlType::Text;
    Result.Text = std::string(Value);
    return Result;
  }
};

// True for the SQLite result codes that report the environment rather than the data or the SQL (the
// primary code of `ExtendedCode`): SQLITE_FULL, SQLITE_IOERR (every extended code), SQLITE_CANTOPEN,
// SQLITE_NOMEM, SQLITE_CORRUPT, SQLITE_NOTADB, SQLITE_BUSY, SQLITE_LOCKED, SQLITE_READONLY, SQLITE_PERM,
// SQLITE_AUTH, SQLITE_PROTOCOL and SQLITE_INTERRUPT. Such a failure throws SqliteEnvironmentFailure
// (exit 6), never DiaphoraWouldRaise: a heuristic worker must not swallow a full disk or a missing TMP
// directory as if it were one of Diaphora's per-heuristic raises (audit F03).
bool IsEnvironmentalSqliteError(int ExtendedCode);

// sqlite3_initialize(), called before every open by DiffDatabase and the results writer (audit F31): a
// SQLite built with SQLITE_OMIT_AUTOINIT (Python 3.14's sqlite3.dll, for example) crashes on the first
// open otherwise. Idempotent and cheap once initialised. Throws IoFailure when it fails.
void EnsureSqliteInitialized();

// A prepared statement. Move-only. A failed prepare, bind or step throws SqliteEnvironmentFailure for
// an environmental result code (IsEnvironmentalSqliteError) and otherwise DiaphoraWouldRaise with the
// site "sqlite3_prepare", "sqlite3_bind" or "sqlite3_step" ("sqlite3 execute" for Python's own
// ProgrammingError checks: more than one statement, a wrong number of bindings), because the same SQL
// error raises in Python at cur.execute / fetch. The row sources add the site "fetch" for a TEXT value
// Python cannot decode.
class Statement {
public:
  Statement() = default;
  ~Statement();
  Statement(Statement&& Other) noexcept;
  Statement& operator=(Statement&& Other) noexcept;
  Statement(const Statement&) = delete;
  Statement& operator=(const Statement&) = delete;

  bool Valid() const { return Stmt_ != nullptr; }
  bool Step();   // true: a row is available; false: done
  void Reset();  // rewinds; bindings stay

  int ColumnCount() const;
  std::string_view ColumnName(int Column) const;
  int FindColumn(std::string_view Alias) const;  // ASCII case-insensitive like sqlite3.Row; -1 if absent
  SqlType Type(int Column) const;
  bool IsNull(int Column) const { return Type(Column) == SqlType::Null; }
  int64_t Int(int Column) const;
  double Real(int Column) const;
  std::string_view Text(int Column) const;  // raw bytes of TEXT or BLOB; "" for NULL
  std::optional<std::string_view> TextOrNull(int Column) const;
  SqlCell Cell(int Column) const;
  std::string_view Sql() const;
  sqlite3_stmt* Raw() const { return Stmt_; }

private:
  friend class DiffDatabase;
  Statement(sqlite3* Db, sqlite3_stmt* Stmt) : Db_(Db), Stmt_(Stmt) {}

  sqlite3* Db_ = nullptr;
  sqlite3_stmt* Stmt_ = nullptr;
};

// One EXPLAIN QUERY PLAN row.
struct PlanRow {
  int Id = 0;
  int Parent = 0;
  std::string Detail;
};

class DiffDatabase {
public:
  DiffDatabase();
  ~DiffDatabase();
  DiffDatabase(DiffDatabase&& Other) noexcept;
  DiffDatabase& operator=(DiffDatabase&& Other) noexcept;
  DiffDatabase(const DiffDatabase&) = delete;
  DiffDatabase& operator=(const DiffDatabase&) = delete;

  // Opens `MainPath` read-only and attaches `DiffPath` as `diff`. Throws IoFailure
  // (SqliteEnvironmentFailure for a corrupt or foreign file).
  void Open(const std::string& MainPath, const std::string& DiffPath);
  // Opens only a main database (tests, results files). Throws IoFailure.
  void OpenSingle(const std::string& MainPath);
  void Close();
  bool IsOpen() const { return Db_ != nullptr; }

  Statement Prepare(std::string_view Sql) const;
  Statement Prepare(std::string_view Sql, std::span<const BindValue> Binds) const;
  std::vector<PlanRow> ExplainQueryPlan(std::string_view Sql) const;
  bool TableExists(std::string_view Schema, std::string_view Table) const;  // Schema "main" or "diff"
  int PragmaThreads() const;
  sqlite3* Handle() const { return Db_; }

  static std::string LibVersion();  // sqlite3_libversion()
  static std::string SourceId();    // sqlite3_sourceid()
  static bool IsOracleSqlite();     // LibVersion() == kOracleSqliteVersion
  // "file:" URI for a filesystem path (percent-escapes % ? #, drive letters get a leading '/').
  static std::string UriForPath(const std::string& Path, bool ReadOnly = true);

  static constexpr std::string_view kOracleSqliteVersion = "3.51.1";

private:
  sqlite3* Db_ = nullptr;
};

}
