// Path A: the read-only connection and the row sources over Diaphora's verbatim SQL
// (02 §18.3, 04a §6.6).

#include "dsigmatcher/diff/Database.h"

#include <sqlite3.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <string>
#include <system_error>
#include <unordered_set>

#include "dsigmatcher/diff/Candidates.h"
#include "dsigmatcher/diff/Errors.h"
#include "dsigmatcher/diff/Pipeline.h"
#include "FileIo.h"

namespace DSig::Diff {

namespace {

bool EqualsIgnoreCaseAscii(std::string_view A, std::string_view B) {
  if (A.size() != B.size()) {
    return false;
  }
  for (size_t Index = 0; Index < A.size(); ++Index) {
    const unsigned char X = static_cast<unsigned char>(A[Index]);
    const unsigned char Y = static_cast<unsigned char>(B[Index]);
    if (std::tolower(X) != std::tolower(Y)) {
      return false;
    }
  }
  return true;
}

std::string ErrorText(sqlite3* Db) {
  return Db != nullptr ? std::string(sqlite3_errmsg(Db)) : std::string("out of memory");
}

// The error of a failed prepare / bind / step on `Db`: SqliteEnvironmentFailure (exit 6) when the
// environment caused it (IsEnvironmentalSqliteError), else DiaphoraWouldRaise at `Site`.
[[noreturn]] void ThrowSqlError(sqlite3* Db, const char* Site) {
  const int Code = Db != nullptr ? sqlite3_extended_errcode(Db) : SQLITE_NOMEM;
  if (IsEnvironmentalSqliteError(Code)) {
    throw SqliteEnvironmentFailure(std::string("SQLite failed (") + sqlite3_errstr(Code) + ", code " +
                                       std::to_string(Code) + ") at " + Site + ": " + ErrorText(Db) +
                                       "; this is an environment failure (disk, temporary directory, memory, "
                                       "lock or a damaged database file), not a Diaphora result",
                                   Code);
  }
  throw DiaphoraWouldRaise(Site, ErrorText(Db));
}

bool OnlyWhitespace(const char* Tail) {
  if (Tail == nullptr) {
    return true;
  }
  for (; *Tail != '\0'; ++Tail) {
    if (!std::isspace(static_cast<unsigned char>(*Tail))) {
      return false;
    }
  }
  return true;
}

}

bool IsEnvironmentalSqliteError(int ExtendedCode) {
  switch (ExtendedCode & 0xff) {
    case SQLITE_FULL:
    case SQLITE_IOERR:
    case SQLITE_CANTOPEN:
    case SQLITE_NOMEM:
    case SQLITE_CORRUPT:
    case SQLITE_NOTADB:
    case SQLITE_BUSY:
    case SQLITE_LOCKED:
    case SQLITE_READONLY:
    case SQLITE_PERM:
    case SQLITE_AUTH:
    case SQLITE_PROTOCOL:
    case SQLITE_INTERRUPT:
      return true;
    default:
      return false;
  }
}

void EnsureSqliteInitialized() {
  const int Code = sqlite3_initialize();
  if (Code != SQLITE_OK) {
    throw IoFailure("sqlite3_initialize failed (" + std::string(sqlite3_errstr(Code)) + ", code " +
                    std::to_string(Code) + ")");
  }
}

// ---------------------------------------------------------------------------------------------
// Statement

Statement::~Statement() {
  if (Stmt_ != nullptr) {
    sqlite3_finalize(Stmt_);
  }
}

Statement::Statement(Statement&& Other) noexcept : Db_(Other.Db_), Stmt_(Other.Stmt_) {
  Other.Db_ = nullptr;
  Other.Stmt_ = nullptr;
}

Statement& Statement::operator=(Statement&& Other) noexcept {
  if (this != &Other) {
    if (Stmt_ != nullptr) {
      sqlite3_finalize(Stmt_);
    }
    Db_ = Other.Db_;
    Stmt_ = Other.Stmt_;
    Other.Db_ = nullptr;
    Other.Stmt_ = nullptr;
  }
  return *this;
}

bool Statement::Step() {
  const int Code = sqlite3_step(Stmt_);
  if (Code == SQLITE_ROW) {
    return true;
  }
  if (Code == SQLITE_DONE) {
    return false;
  }
  // Python's sqlite3 raises OperationalError at cur.execute / fetch for the same failure; an
  // environmental failure is not a parity raise (ThrowSqlError).
  ThrowSqlError(Db_, "sqlite3_step");
}

void Statement::Reset() { sqlite3_reset(Stmt_); }

int Statement::ColumnCount() const { return sqlite3_column_count(Stmt_); }

std::string_view Statement::ColumnName(int Column) const {
  const char* Name = sqlite3_column_name(Stmt_, Column);
  return Name != nullptr ? std::string_view(Name) : std::string_view();
}

int Statement::FindColumn(std::string_view Alias) const {
  const int Count = ColumnCount();
  for (int Column = 0; Column < Count; ++Column) {
    if (EqualsIgnoreCaseAscii(ColumnName(Column), Alias)) {
      return Column;
    }
  }
  return -1;
}

SqlType Statement::Type(int Column) const {
  switch (sqlite3_column_type(Stmt_, Column)) {
    case SQLITE_INTEGER:
      return SqlType::Integer;
    case SQLITE_FLOAT:
      return SqlType::Real;
    case SQLITE_TEXT:
      return SqlType::Text;
    case SQLITE_BLOB:
      return SqlType::Blob;
    default:
      return SqlType::Null;
  }
}

int64_t Statement::Int(int Column) const { return sqlite3_column_int64(Stmt_, Column); }

double Statement::Real(int Column) const { return sqlite3_column_double(Stmt_, Column); }

std::string_view Statement::Text(int Column) const {
  // Read the type first so that a BLOB is not converted to text (sqlite3_column_blob returns its raw
  // bytes). TEXT is read with sqlite3_column_text: the exports are UTF-8 databases, so no conversion.
  const SqlType Kind = Type(Column);
  if (Kind == SqlType::Null) {
    return std::string_view();
  }
  if (Kind == SqlType::Blob) {
    const void* Data = sqlite3_column_blob(Stmt_, Column);
    const int Length = sqlite3_column_bytes(Stmt_, Column);
    if (Data == nullptr || Length <= 0) {
      return std::string_view();
    }
    return std::string_view(static_cast<const char*>(Data), static_cast<size_t>(Length));
  }
  const unsigned char* Data = sqlite3_column_text(Stmt_, Column);
  const int Length = sqlite3_column_bytes(Stmt_, Column);
  if (Data == nullptr || Length <= 0) {
    return std::string_view();
  }
  return std::string_view(reinterpret_cast<const char*>(Data), static_cast<size_t>(Length));
}

std::optional<std::string_view> Statement::TextOrNull(int Column) const {
  if (IsNull(Column)) {
    return std::nullopt;
  }
  return Text(Column);
}

SqlCell Statement::Cell(int Column) const {
  SqlCell Result;
  Result.Type = Type(Column);
  switch (Result.Type) {
    case SqlType::Integer:
      Result.Int = Int(Column);
      break;
    case SqlType::Real:
      Result.Real = Real(Column);
      break;
    case SqlType::Text:
    case SqlType::Blob:
      Result.Bytes = std::string(Text(Column));
      break;
    case SqlType::Null:
      break;
  }
  return Result;
}

std::string_view Statement::Sql() const {
  const char* Text = sqlite3_sql(Stmt_);
  return Text != nullptr ? std::string_view(Text) : std::string_view();
}

// ---------------------------------------------------------------------------------------------
// DiffDatabase

DiffDatabase::DiffDatabase() = default;

DiffDatabase::~DiffDatabase() { Close(); }

DiffDatabase::DiffDatabase(DiffDatabase&& Other) noexcept : Db_(Other.Db_) { Other.Db_ = nullptr; }

DiffDatabase& DiffDatabase::operator=(DiffDatabase&& Other) noexcept {
  if (this != &Other) {
    Close();
    Db_ = Other.Db_;
    Other.Db_ = nullptr;
  }
  return *this;
}

void DiffDatabase::Close() {
  if (Db_ != nullptr) {
    sqlite3_close_v2(Db_);
    Db_ = nullptr;
  }
}

std::string DiffDatabase::UriForPath(const std::string& Path, bool ReadOnly) {
  std::string Normal = Path;
#ifdef _WIN32
  std::replace(Normal.begin(), Normal.end(), '\\', '/');
#endif
  std::string Escaped;
  Escaped.reserve(Normal.size() + 8);
  for (const char Ch : Normal) {
    switch (Ch) {
      case '%':
        Escaped += "%25";
        break;
      case '?':
        Escaped += "%3f";
        break;
      case '#':
        Escaped += "%23";
        break;
      default:
        Escaped += Ch;
        break;
    }
  }
  if (Escaped.size() >= 2 && std::isalpha(static_cast<unsigned char>(Escaped[0])) && Escaped[1] == ':') {
    // A drive-letter path becomes file:/C:/... (SQLite's documented Windows URI form).
    Escaped.insert(Escaped.begin(), '/');
  } else if (Escaped.size() >= 2 && Escaped[0] == '/' && Escaped[1] == '/') {
    // A UNC path //server/share/x: "file://server/..." would make "server" the URI authority, which
    // SQLite rejects unless it is empty or "localhost". An empty authority keeps the whole UNC path:
    // file:////server/share/x, whose path part //server/share/x SQLite's Windows VFS treats as
    // verbatim (winIsVerbatimPathname).
    Escaped.insert(0, "//");
  }
  return "file:" + Escaped + (ReadOnly ? "?mode=ro" : "");
}

namespace {

// The file name handed to a non-URI sqlite3_open_v2 / ATTACH. Everything is a plain filesystem path
// (UTF-8; SQLite converts it to UTF-16 on Windows), so drive paths, UNC paths (\\server\share\x) and
// names containing '?', '#' or '%' need no escaping. Only names SQLite itself would reinterpret are
// changed: "" (a private temporary database), ":memory:", and a leading "file:" (parsed as a URI when
// SQLite is built with SQLITE_USE_URI=1) get a "./" prefix, which names the same relative file.
std::string PlainFileName(const std::string& Path, const char* What) {
  if (Path.empty()) {
    throw IoFailure(std::string("empty ") + What + " path");
  }
  if (Path == ":memory:" || Path.rfind("file:", 0) == 0) {
    return "./" + Path;
  }
  return Path;
}

// True when the file exists and holds at least one byte. Never throws: a path that cannot be
// converted or examined counts as non-empty, which selects the ordinary read-only open.
bool MayHoldData(const std::string& Utf8Path) {
  try {
    std::error_code Error;
    const std::filesystem::path Path = Detail::PathFromUtf8(Utf8Path);
    if (!std::filesystem::exists(Path, Error)) {
      return Error.value() != 0;
    }
    const uintmax_t Size = std::filesystem::file_size(Path, Error);
    return Error.value() != 0 || Size > 0;
  } catch (const std::exception&) {
    return true;
  }
}

// The name handed to sqlite3_open_v2 / ATTACH for an input. Reading an input must not
// create files beside it: an ordinary read-only open of a WAL-mode export creates "<db>-wal" and
// "<db>-shm" (SQLite opens the WAL with SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE even on a read-only
// connection, wal.c sqlite3WalOpen) and, being read-only, cannot checkpoint and delete them on close.
// The URI parameter immutable=1 (https://www.sqlite.org/uri.html, "immutable") reads the database file
// alone, with no locks and no sidecar files; the pager then treats the file like a temporary database
// and never looks for a WAL (pager.c sqlite3PagerOpen, act_like_temp_file). That is exact only when no
// committed frame waits in a "-wal" and no hot "-journal" has to be rolled back first, so an input
// with a non-empty -wal or -journal keeps the ordinary read-only open: committed WAL frames are read,
// and a hot journal is refused by SQLite (SQLITE_READONLY_ROLLBACK) instead of being ignored.
// UriForPath keeps drive, UNC and non-ASCII paths intact (file:/C:/..., file:////server/share/...,
// raw UTF-8 bytes), and the connection is opened with SQLITE_OPEN_URI so ATTACH accepts the URI too;
// a plain name never starts with "file:" (PlainFileName), so it is still a plain file name.
std::string InputFileName(const std::string& Path, const char* What) {
  const std::string Plain = PlainFileName(Path, What);
  if (MayHoldData(Plain + "-wal") || MayHoldData(Plain + "-journal")) {
    return Plain;
  }
  return DiffDatabase::UriForPath(Plain, true) + "&immutable=1";
}

}

void DiffDatabase::OpenSingle(const std::string& MainPath) {
  Close();
  EnsureSqliteInitialized();
  // Read-only: SQLITE_OPEN_READONLY is what mode=ro set, and ATTACH reuses these open
  // flags (attach.c: flags = db->openFlags), so the attached diff database is read-only too.
  // InputFileName decides between the immutable URI and the plain file name.
  const std::string Name = InputFileName(MainPath, "database");
  sqlite3* Handle = nullptr;
  const int Code = sqlite3_open_v2(Name.c_str(), &Handle, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, nullptr);
  if (Code != SQLITE_OK) {
    const std::string Message = ErrorText(Handle);
    if (Handle != nullptr) {
      sqlite3_close_v2(Handle);
    }
    throw IoFailure("cannot open '" + MainPath + "': " + Message);
  }
  Db_ = Handle;
  // Force the header read now so a non-database file fails here, not in the middle of a stage.
  char* Error = nullptr;
  if (sqlite3_exec(Db_, "select count(*) from main.sqlite_master", nullptr, nullptr, &Error) != SQLITE_OK) {
    const std::string Message = Error != nullptr ? Error : ErrorText(Db_);
    const int ReadCode = sqlite3_extended_errcode(Db_);
    sqlite3_free(Error);
    Close();
    throw SqliteEnvironmentFailure("cannot read '" + MainPath + "': " + Message, ReadCode);
  }
}

void DiffDatabase::Open(const std::string& MainPath, const std::string& DiffPath) {
  OpenSingle(MainPath);
  sqlite3_stmt* Attach = nullptr;
  if (sqlite3_prepare_v2(Db_, "ATTACH ? AS diff", -1, &Attach, nullptr) != SQLITE_OK) {
    const std::string Message = ErrorText(Db_);
    Close();
    throw IoFailure("cannot attach '" + DiffPath + "': " + Message);
  }
  // `attach "<db2>" as diff` (D:2441 / D:657), with the name bound (no quoting issues) and read-only
  // through the connection's open flags; immutable under the same rule as the main database.
  const std::string Name = InputFileName(DiffPath, "diff database");
  sqlite3_bind_text(Attach, 1, Name.c_str(), static_cast<int>(Name.size()), SQLITE_TRANSIENT);
  const int Code = sqlite3_step(Attach);
  sqlite3_finalize(Attach);
  if (Code != SQLITE_DONE) {
    const std::string Message = ErrorText(Db_);
    Close();
    throw IoFailure("cannot attach '" + DiffPath + "': " + Message);
  }
  char* Error = nullptr;
  if (sqlite3_exec(Db_, "select count(*) from diff.sqlite_master", nullptr, nullptr, &Error) != SQLITE_OK) {
    const std::string Message = Error != nullptr ? Error : ErrorText(Db_);
    const int ReadCode = sqlite3_extended_errcode(Db_);
    sqlite3_free(Error);
    Close();
    throw SqliteEnvironmentFailure("cannot read '" + DiffPath + "': " + Message, ReadCode);
  }
}

Statement DiffDatabase::Prepare(std::string_view Sql) const { return Prepare(Sql, {}); }

Statement DiffDatabase::Prepare(std::string_view Sql, std::span<const BindValue> Binds) const {
  if (Db_ == nullptr) {
    throw DiaphoraWouldRaise("sqlite3_prepare", "database is not open");
  }
  sqlite3_stmt* Stmt = nullptr;
  const char* Tail = nullptr;
  if (sqlite3_prepare_v2(Db_, Sql.data(), static_cast<int>(Sql.size()), &Stmt, &Tail) != SQLITE_OK) {
    ThrowSqlError(Db_, "sqlite3_prepare");
  }
  Statement Result(Db_, Stmt);
  if (Stmt == nullptr) {
    throw DiaphoraWouldRaise("sqlite3_prepare", "empty statement");
  }
  if (Tail != nullptr && Tail < Sql.data() + Sql.size()) {
    const std::string Rest(Tail, static_cast<size_t>(Sql.data() + Sql.size() - Tail));
    if (!OnlyWhitespace(Rest.c_str())) {
      // Python: ProgrammingError "You can only execute one statement at a time."
      throw DiaphoraWouldRaise("sqlite3 execute", "more than one statement");
    }
  }
  const int Expected = sqlite3_bind_parameter_count(Stmt);
  if (Expected != static_cast<int>(Binds.size())) {
    // Python: ProgrammingError "Incorrect number of bindings supplied."
    throw DiaphoraWouldRaise("sqlite3 execute", "incorrect number of bindings supplied: " +
                                                    std::to_string(Binds.size()) + " for " +
                                                    std::to_string(Expected));
  }
  for (size_t Index = 0; Index < Binds.size(); ++Index) {
    const int Slot = static_cast<int>(Index) + 1;
    const BindValue& Value = Binds[Index];
    int Code = SQLITE_OK;
    switch (Value.Type) {
      case SqlType::Null:
        Code = sqlite3_bind_null(Stmt, Slot);
        break;
      case SqlType::Integer:
        Code = sqlite3_bind_int64(Stmt, Slot, Value.Int);
        break;
      case SqlType::Real:
        Code = sqlite3_bind_double(Stmt, Slot, Value.Real);
        break;
      case SqlType::Text:
        Code = sqlite3_bind_text(Stmt, Slot, Value.Text.data(), static_cast<int>(Value.Text.size()),
                                 SQLITE_TRANSIENT);
        break;
      case SqlType::Blob:
        Code = sqlite3_bind_blob(Stmt, Slot, Value.Text.data(), static_cast<int>(Value.Text.size()),
                                 SQLITE_TRANSIENT);
        break;
    }
    if (Code != SQLITE_OK) {
      ThrowSqlError(Db_, "sqlite3_bind");
    }
  }
  return Result;
}

std::vector<PlanRow> DiffDatabase::ExplainQueryPlan(std::string_view Sql) const {
  std::string Text = "EXPLAIN QUERY PLAN ";
  Text += Sql;
  sqlite3_stmt* Stmt = nullptr;
  if (sqlite3_prepare_v2(Db_, Text.c_str(), static_cast<int>(Text.size()), &Stmt, nullptr) != SQLITE_OK) {
    ThrowSqlError(Db_, "sqlite3_prepare");
  }
  Statement Plan(Db_, Stmt);
  std::vector<PlanRow> Rows;
  while (Plan.Step()) {
    PlanRow Row;
    Row.Id = static_cast<int>(Plan.Int(0));
    Row.Parent = static_cast<int>(Plan.Int(1));
    Row.Detail = std::string(Plan.Text(3));
    Rows.push_back(std::move(Row));
  }
  return Rows;
}

bool DiffDatabase::TableExists(std::string_view Schema, std::string_view Table) const {
  const std::string Sql = "select 1 from " + std::string(Schema) +
                          ".sqlite_master where type = 'table' and name = ?";
  const BindValue Bind = BindValue::Str(Table);
  Statement Query = Prepare(Sql, std::span<const BindValue>(&Bind, 1));
  return Query.Step();
}

int DiffDatabase::PragmaThreads() const {
  Statement Query = Prepare("pragma threads");
  if (!Query.Step()) {
    return -1;
  }
  return static_cast<int>(Query.Int(0));
}

std::string DiffDatabase::LibVersion() { return std::string(sqlite3_libversion()); }

std::string DiffDatabase::SourceId() { return std::string(sqlite3_sourceid()); }

bool DiffDatabase::IsOracleSqlite() { return LibVersion() == kOracleSqliteVersion; }

// ---------------------------------------------------------------------------------------------
// SqlRowSource

namespace {

// Aliases of SELECT_FIELDS (H:51-75) whose source column is covered by
// FunctionTable::SelectFieldsUtf8Bad of the row's main (…1, ea) or diff (…2, ea2) function.
bool CoveredBySelectFields(std::string_view Alias) {
  static const char* const Main[] = {"ea",     "name1",   "pseudo1", "asm1",       "pseudo_primes1",
                                     "nodes1", "md1",     "clean_assembly1", "clean_pseudo1",
                                     "mangled1", "clean_micro1", "bytes_hash1", "edges1", "indegree1",
                                     "outdegree1", "instructions1", "cc1", "strongly_connected1",
                                     "loops1", "constants_count1", "size1", "kgh_hash1"};
  static const char* const Diff[] = {"ea2",    "name2",   "pseudo2", "asm2",       "pseudo_primes2",
                                     "nodes2", "md2",     "clean_assembly2", "clean_pseudo2",
                                     "mangled2", "clean_micro2", "bytes_hash2", "edges2", "indegree2",
                                     "outdegree2", "instructions2", "cc2", "strongly_connected2",
                                     "loops2", "constants_count2", "size2", "kgh_hash2"};
  for (const char* Name : Main) {
    if (EqualsIgnoreCaseAscii(Alias, Name)) {
      return true;
    }
  }
  for (const char* Name : Diff) {
    if (EqualsIgnoreCaseAscii(Alias, Name)) {
      return true;
    }
  }
  return false;
}

std::optional<int64_t> ReadNodes(const Statement& Stmt, int Column, const char* Alias) {
  if (Column < 0) {
    return std::nullopt;
  }
  switch (Stmt.Type(Column)) {
    case SqlType::Null:
      return std::nullopt;
    case SqlType::Integer:
      return Stmt.Int(Column);
    default:
      throw UnsupportedInput(std::string("row alias '") + Alias +
                             "' is not INTEGER or NULL (int() semantics not emulated)");
  }
}

std::optional<double> ReadMd(const Statement& Stmt, int Column, const char* Alias) {
  if (Column < 0) {
    return std::nullopt;
  }
  switch (Stmt.Type(Column)) {
    case SqlType::Null:
      return std::nullopt;
    case SqlType::Real:
      return Stmt.Real(Column);
    case SqlType::Integer:
      return static_cast<double>(Stmt.Int(Column));
    default:
      throw UnsupportedInput(std::string("row alias '") + Alias + "' is not REAL or NULL");
  }
}

}

struct SqlRowSource::Impl {
  DiffSession& S;
  std::string Sql;
  std::vector<BindValue> Binds;
  Statement Stmt;
  bool Started = false;
  bool Done = false;
  uint64_t Fetched = 0;
  int ColEa = -1;
  int ColName1 = -1;
  int ColEa2 = -1;
  int ColName2 = -1;
  int ColDesc = -1;
  int ColNodes1 = -1;
  int ColNodes2 = -1;
  int ColMd1 = -1;
  int ColMd2 = -1;
  std::vector<int> DirectUtf8;  // columns validated per row (not covered by SelectFieldsUtf8Bad)

  Impl(DiffSession& Session, std::string Text, std::vector<BindValue> Values)
      : S(Session), Sql(std::move(Text)), Binds(std::move(Values)) {}

  void Start() {
    Started = true;
    Stmt = S.Db().Prepare(Sql, Binds);
    ColEa = Stmt.FindColumn("ea");
    ColName1 = Stmt.FindColumn("name1");
    ColEa2 = Stmt.FindColumn("ea2");
    ColName2 = Stmt.FindColumn("name2");
    ColDesc = Stmt.FindColumn("description");
    ColNodes1 = Stmt.FindColumn("nodes1");
    ColNodes2 = Stmt.FindColumn("nodes2");
    ColMd1 = Stmt.FindColumn("md1");
    ColMd2 = Stmt.FindColumn("md2");
    if (ColEa < 0 || ColEa2 < 0 || ColName1 < 0 || ColName2 < 0 || ColDesc < 0) {
      throw UnsupportedInput("SqlRowSource: the query does not select SELECT_FIELDS (ea, name1, ea2, name2, "
                             "description)");
    }
    const int Count = Stmt.ColumnCount();
    for (int Column = 0; Column < Count; ++Column) {
      if (!CoveredBySelectFields(Stmt.ColumnName(Column))) {
        DirectUtf8.push_back(Column);
      }
    }
  }

  AddrId MapAddress(int Column, const char* Alias) {
    const SqlType Kind = Stmt.Type(Column);
    if (Kind != SqlType::Text) {
      // A NULL or non-TEXT address never comes from a Diaphora export (address is `text unique`).
      throw UnsupportedInput(std::string("row alias '") + Alias + "' is " +
                             (Kind == SqlType::Null ? "NULL" : "not TEXT") + " (input quirk not emulated)");
    }
    return S.Ids().Addr(Stmt.Text(Column));
  }

  NameId MapName(int Column, const char* Alias) {
    const SqlType Kind = Stmt.Type(Column);
    if (Kind == SqlType::Null) {
      return kNoneName;  // Python None; the consumer raises where Python calls .startswith on it
    }
    if (Kind != SqlType::Text) {
      throw UnsupportedInput(std::string("row alias '") + Alias + "' is not TEXT or NULL");
    }
    return S.Ids().Name(Stmt.Text(Column));
  }
};

SqlRowSource::SqlRowSource(DiffSession& S, std::string Sql, std::vector<BindValue> Binds)
    : Impl_(std::make_unique<Impl>(S, std::move(Sql), std::move(Binds))) {}

SqlRowSource::~SqlRowSource() = default;

bool SqlRowSource::Next(HeuristicRow& Out) {
  Impl& I = *Impl_;
  if (!I.Started) {
    I.Start();
  }
  if (I.Done) {
    return false;
  }
  if (!I.Stmt.Step()) {
    I.Done = true;
    return false;
  }
  ++I.Fetched;

  HeuristicRow Row;
  Row.Side1 = Side::Main;
  Row.Side2 = Side::Diff;
  // Map the addresses first: the per-row UTF-8 flags are indexed by row.
  if (I.Stmt.Type(I.ColEa) == SqlType::Text) {
    if (auto Id = I.S.Ids().FindAddr(I.Stmt.Text(I.ColEa))) {
      if (auto Found = I.S.Main().Functions.FindRow(*Id)) {
        Row.Row1 = *Found;
      }
    }
  }
  if (I.Stmt.Type(I.ColEa2) == SqlType::Text) {
    if (auto Id = I.S.Ids().FindAddr(I.Stmt.Text(I.ColEa2))) {
      if (auto Found = I.S.Diff().Functions.FindRow(*Id)) {
        Row.Row2 = *Found;
      }
    }
  }

  // 01 §13: Python decodes every TEXT column when the row is fetched and raises OperationalError
  // ("Could not decode to UTF-8 column ...") for invalid UTF-8, before the consumer sees the row.
  const FunctionTable& Main = I.S.Main().Functions;
  const FunctionTable& Diff = I.S.Diff().Functions;
  if ((Row.Row1 != kNoRow && Main.SelectFieldsUtf8Bad[Row.Row1] != 0) ||
      (Row.Row2 != kNoRow && Diff.SelectFieldsUtf8Bad[Row.Row2] != 0)) {
    throw DiaphoraWouldRaise("fetch", "Could not decode to UTF-8 a SELECT_FIELDS column (invalid UTF-8) of the row "
                                      "ea " + std::string(I.Stmt.Text(I.ColEa)) + ", ea2 " +
                                      std::string(I.Stmt.Text(I.ColEa2)));
  }
  for (const int Column : I.DirectUtf8) {
    if (I.Stmt.Type(Column) == SqlType::Text && !IsValidUtf8(I.Stmt.Text(Column))) {
      throw DiaphoraWouldRaise("fetch", "Could not decode to UTF-8 column '" +
                                            std::string(I.Stmt.ColumnName(Column)) + "' of the row ea " +
                                            std::string(I.Stmt.Text(I.ColEa)) + ", ea2 " +
                                            std::string(I.Stmt.Text(I.ColEa2)));
    }
  }

  Row.Ea1 = I.MapAddress(I.ColEa, "ea");
  Row.Ea2 = I.MapAddress(I.ColEa2, "ea2");
  Row.Name1 = I.MapName(I.ColName1, "name1");
  Row.Name2 = I.MapName(I.ColName2, "name2");
  if (I.Stmt.Type(I.ColDesc) != SqlType::Text) {
    throw UnsupportedInput("row alias 'description' is not TEXT");
  }
  Row.Desc = I.S.Ids().Desc(I.Stmt.Text(I.ColDesc));
  Row.Nodes1 = ReadNodes(I.Stmt, I.ColNodes1, "nodes1");
  Row.Nodes2 = ReadNodes(I.Stmt, I.ColNodes2, "nodes2");
  Row.Md1 = ReadMd(I.Stmt, I.ColMd1, "md1");
  Row.Md2 = ReadMd(I.Stmt, I.ColMd2, "md2");
  Out = Row;
  return true;
}

uint64_t SqlRowSource::Fetched() const { return Impl_->Fetched; }

const Statement& SqlRowSource::Current() const { return Impl_->Stmt; }

std::string_view SqlRowSource::Sql() const { return Impl_->Sql; }

// ---------------------------------------------------------------------------------------------
// FetchFunctionRows

std::vector<FunctionRowRef> FetchFunctionRows(DiffSession& S, std::string_view Sql, std::span<const BindValue> Binds,
                                              Side Default, size_t Limit) {
  std::vector<FunctionRowRef> Rows;
  if (Limit == 0) {
    return Rows;
  }
  Statement Stmt = S.Db().Prepare(Sql, Binds);
  const int ColAddress = Stmt.FindColumn("address");
  const int ColDbName = Stmt.FindColumn("db_name");
  if (ColAddress < 0) {
    throw UnsupportedInput("FetchFunctionRows: the query does not select `address`");
  }
  while (Rows.size() < Limit && Stmt.Step()) {
    FunctionRowRef Ref;
    Ref.Which = Default;
    if (ColDbName >= 0) {
      const std::string_view Db = Stmt.Text(ColDbName);
      Ref.Which = Db == "diff" ? Side::Diff : Side::Main;
    }
    const FunctionTable& Table = S.Export(Ref.Which).Functions;
    if (Stmt.Type(ColAddress) == SqlType::Text) {
      if (auto Id = S.Ids().FindAddr(Stmt.Text(ColAddress))) {
        if (auto Found = Table.FindRow(*Id)) {
          Ref.Row = *Found;
        }
      }
    }
    if (Ref.Row != kNoRow && Table.AnyColumnUtf8Bad[Ref.Row] != 0) {
      throw DiaphoraWouldRaise("fetch", "Could not decode to UTF-8 a functions column (invalid UTF-8) of the "
                                        "function at address " + std::string(Stmt.Text(ColAddress)));
    }
    Rows.push_back(Ref);
  }
  return Rows;
}

}
