#pragma once

// Path A connection (docs/parity/00-plan.md §3.4). One read-only connection holds both exports:
//   sqlite3_open_v2("file:<db1>?mode=ro", SQLITE_OPEN_READONLY | SQLITE_OPEN_URI)
//   ATTACH 'file:<db2>?mode=ro' AS diff
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

// A prepared statement. Move-only. Errors from prepare or step throw DiaphoraWouldRaise("sqlite", ...),
// because the same SQL error raises in Python at cur.execute / fetch.
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

  // Opens `MainPath` read-only and attaches `DiffPath` as `diff`. Throws IoFailure.
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
