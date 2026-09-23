#include "dsigmatcher/Provenance.h"

#include <sqlite3.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <map>
#include <set>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include "dsigmatcher/Naming.h"
#include "dsigmatcher/Sha256.h"
#include "dsigmatcher/Version.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace DSig {

namespace {

// ---------------------------------------------------------------------------------------------
// Paths. Every path is UTF-8, as every path the CLI passes on (src/diff/FileIo.h), and every file
// access goes through PathOf: std::filesystem::path(std::string) and path::string() use the ANSI code
// page on Windows, which is UTF-8 only in a process with the executable's manifest. Text that is not
// valid UTF-8 falls back to the native narrow conversion.

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

// The absolute path, then weakly_canonical: ".", "..", symbolic links and, for the part of the path
// that exists, the spelling the file system stores (made absolute first, so a relative path whose
// first component does not exist is still absolute). Falls back to the absolute, lexically normal
// path when that fails.
std::filesystem::path CanonicalOrAbsolute(const std::filesystem::path& Path) {
  std::error_code Error;
  const std::filesystem::path Absolute = std::filesystem::absolute(Path, Error);
  const std::filesystem::path& Base = Error ? Path : Absolute;
  Error.clear();
  std::filesystem::path Canonical = std::filesystem::weakly_canonical(Base, Error);
  if (!Error && !Canonical.empty()) {
    return Canonical;
  }
  return Base.lexically_normal();
}

// Equality of two canonical paths the way the platform's default file system compares names: NTFS
// and APFS/HFS+ ignore case (NTFS through its upper-case table, which CompareStringOrdinal with
// bIgnoreCase uses as well); other systems compare bytes.
bool SameSpelling(const std::filesystem::path& A, const std::filesystem::path& B) {
#if defined(_WIN32)
  const std::wstring& X = A.native();
  const std::wstring& Y = B.native();
  if (X.size() > static_cast<size_t>(INT32_MAX) || Y.size() > static_cast<size_t>(INT32_MAX)) {
    return X == Y;
  }
  return CompareStringOrdinal(X.data(), static_cast<int>(X.size()), Y.data(), static_cast<int>(Y.size()), TRUE) ==
         CSTR_EQUAL;
#elif defined(__APPLE__)
  const std::string& X = A.native();
  const std::string& Y = B.native();
  return X.size() == Y.size() && std::equal(X.begin(), X.end(), Y.begin(), [](char L, char R) {
           return std::tolower(static_cast<unsigned char>(L)) == std::tolower(static_cast<unsigned char>(R));
         });
#else
  return A.native() == B.native();
#endif
}

bool FileExists(const std::string& Path) {
  std::error_code Error;
  return std::filesystem::is_regular_file(PathOf(Path), Error);
}

bool PathExists(const std::string& Path) {
  std::error_code Error;
  return std::filesystem::exists(PathOf(Path), Error);
}

uintmax_t FileSizeOrZero(const std::string& Path) {
  std::error_code Error;
  const uintmax_t Size = std::filesystem::file_size(PathOf(Path), Error);
  return Error ? 0 : Size;
}

void RemoveFile(const std::string& Path) {
  std::error_code Error;
  std::filesystem::remove(PathOf(Path), Error);
}

void RemoveDatabaseFiles(const std::string& Path) {
  for (const char* Suffix : {"", "-wal", "-shm", "-journal"}) {
    RemoveFile(Path + Suffix);
  }
}

// Renames From over To (an existing To is replaced: MoveFileExW with MOVEFILE_REPLACE_EXISTING in the
// MSVC library, rename(2) elsewhere). On Windows a virus scanner or the indexer may hold a file that
// was just written for a moment, so a sharing violation is retried a few times.
bool RenameOver(const std::string& From, const std::string& To, std::error_code& Error) {
  const int Attempts =
#ifdef _WIN32
      5;
#else
      1;
#endif
  for (int Attempt = 0; Attempt < Attempts; ++Attempt) {
    Error.clear();
    std::filesystem::rename(PathOf(From), PathOf(To), Error);
    if (!Error) {
      return true;
    }
    if (Attempt + 1 < Attempts) {
      std::this_thread::sleep_for(std::chrono::milliseconds(50 * (Attempt + 1)));
    }
  }
  return false;
}

// Bytes 18-19 of the database header are 2/2 for a WAL-mode file (SQLite file format §1.3.3).
bool FileIsWalMode(const std::string& Path) {
  std::ifstream Input(PathOf(Path), std::ios::binary);
  char Header[20] = {};
  if (!Input.read(Header, sizeof(Header))) {
    return false;
  }
  return std::memcmp(Header, "SQLite format 3", 16) == 0 && Header[18] == 2 && Header[19] == 2;
}

// Copies From to To byte for byte. Fails when From cannot be read to its end (a read error is not a
// short copy), when To cannot be written, and when both name one file.
bool CopyFileBinary(const std::string& From, const std::string& To, std::string& Error) {
  if (SameFilePath(From, To)) {
    Error = "'" + From + "' and '" + To + "' are the same file";
    return false;
  }
  std::error_code SizeError;
  const uintmax_t Expected = std::filesystem::file_size(PathOf(From), SizeError);
  std::ifstream Input(PathOf(From), std::ios::binary);
  if (SizeError || !Input.is_open()) {
    Error = "cannot read '" + From + "'";
    return false;
  }
  std::ofstream Output(PathOf(To), std::ios::binary | std::ios::trunc);
  if (!Output.is_open()) {
    Error = "cannot create '" + To + "'";
    return false;
  }
  std::vector<char> Buffer(1024 * 1024);
  uintmax_t Copied = 0;
  for (;;) {
    Input.read(Buffer.data(), static_cast<std::streamsize>(Buffer.size()));
    const std::streamsize Got = Input.gcount();
    if (Input.bad()) {
      Error = "read error in '" + From + "'";
      return false;
    }
    if (Got > 0) {
      Output.write(Buffer.data(), Got);
      if (!Output) {
        Error = "write error in '" + To + "'";
        return false;
      }
      Copied += static_cast<uintmax_t>(Got);
    }
    if (Input.eof()) {
      break;
    }
    if (!Input) {
      Error = "read error in '" + From + "'";
      return false;
    }
  }
  Output.close();
  if (!Output) {
    Error = "write error in '" + To + "'";
    return false;
  }
  if (Copied != Expected) {
    Error = "'" + From + "' changed size while it was copied";
    return false;
  }
  return true;
}

// The last path component of a path as text, for either separator (the results file's config holds
// paths as the producer typed them, possibly on another platform).
std::string BaseNameAnySeparator(const std::string& Path) {
  const size_t Slash = Path.find_last_of("/\\");
  return Slash == std::string::npos ? Path : Path.substr(Slash + 1);
}

// ---------------------------------------------------------------------------------------------
// SQLite helpers

std::string ColumnString(sqlite3_stmt* Statement, int Index) {
  const unsigned char* Text = sqlite3_column_text(Statement, Index);
  if (Text == nullptr) {
    return std::string();
  }
  const int Length = sqlite3_column_bytes(Statement, Index);
  return std::string(reinterpret_cast<const char*>(Text), static_cast<size_t>(Length));
}

// ColumnString, except that a BLOB is rendered as lowercase hex.
std::string ColumnTextOrHex(sqlite3_stmt* Statement, int Index) {
  if (sqlite3_column_type(Statement, Index) != SQLITE_BLOB) {
    return ColumnString(Statement, Index);
  }
  const auto* Bytes = static_cast<const unsigned char*>(sqlite3_column_blob(Statement, Index));
  const int Length = sqlite3_column_bytes(Statement, Index);
  static const char Digits[] = "0123456789abcdef";
  std::string Hex;
  Hex.reserve(static_cast<size_t>(Length) * 2);
  for (int Position = 0; Position < Length; ++Position) {
    Hex += Digits[Bytes[Position] >> 4];
    Hex += Digits[Bytes[Position] & 0x0F];
  }
  return Hex;
}

std::optional<std::string> ColumnOptional(sqlite3_stmt* Statement, int Index) {
  if (sqlite3_column_type(Statement, Index) == SQLITE_NULL) {
    return std::nullopt;
  }
  return ColumnString(Statement, Index);
}

sqlite3* OpenReadOnly(const std::string& Path, std::string& Error) {
  sqlite3* Handle = nullptr;
  const std::string Uri = ReadOnlyDatabaseUri(Path);
  if (sqlite3_open_v2(Uri.c_str(), &Handle, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, nullptr) != SQLITE_OK) {
    Error = Handle != nullptr ? sqlite3_errmsg(Handle) : "cannot allocate handle";
    if (Handle != nullptr) {
      sqlite3_close(Handle);
    }
    return nullptr;
  }
  return Handle;
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

std::set<std::string> TableColumns(sqlite3* Handle, const char* Table) {
  std::set<std::string> Columns;
  sqlite3_stmt* Statement = nullptr;
  const std::string Query = std::string("select name from pragma_table_info('") + Table + "')";
  if (sqlite3_prepare_v2(Handle, Query.c_str(), -1, &Statement, nullptr) == SQLITE_OK) {
    while (sqlite3_step(Statement) == SQLITE_ROW) {
      Columns.insert(ColumnString(Statement, 0));
    }
  }
  sqlite3_finalize(Statement);
  return Columns;
}

// "select a, b, NULL, ..." over the columns the table has; a column added in a later version reads as
// NULL from an older database.
std::string SelectExisting(const std::vector<const char*>& Wanted, const std::set<std::string>& Present) {
  std::string List;
  for (const char* Column : Wanted) {
    List += std::string(List.empty() ? "" : ", ") + (Present.count(Column) != 0 ? Column : "NULL");
  }
  return List;
}

const char* const DropDsigTables =
    "drop table if exists dsig_provenance;"
    "drop table if exists dsig_name_origin;"
    "drop table if exists dsig_port_results;"
    "drop table if exists dsig_port_log;";

const char* const CreateProvenanceSchema =
    "create table dsig_provenance ("
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
    "create table dsig_name_origin ("
    "  address text primary key,"
    "  name text,"
    "  origin_address text,"
    "  origin_name text,"
    "  hops integer,"
    "  cumulative_ratio real,"
    "  heuristic text,"
    "  first_labelled_at text"
    ");";

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

// The dsig_port_results columns, in table order. The last two are new in 1.0.0; a parent written by
// an earlier version reads them as NULL (SelectExisting).
const std::vector<const char*>& PortResultsColumnList() {
  static const std::vector<const char*> Columns = {
      "hop",
      "results_path",
      "results_sha256",
      "results_main_db",
      "results_diff_db",
      "results_version",
      "results_date",
      "include_multimatch",
      "include_unreliable",
      "overwrite",
      "label_columns",
      "proposals",
      "selected",
      "names_applied",
      "names_confirmed",
      "names_skipped_not_portable",
      "names_skipped_conflict",
      "names_skipped_hops",
      "names_skipped_ratio",
      "names_skipped_existing",
      "names_skipped_duplicate",
      "overwrite_stripped",
      "results_source",
  };
  return Columns;
}

// Reads the port settings of every hop (dsig_port_results) into the matching HopRecord.
void ReadPortSettings(sqlite3* Handle, std::vector<HopRecord>& Hops) {
  if (!TableExists(Handle, "dsig_port_results")) {
    return;
  }
  const std::set<std::string> Present = TableColumns(Handle, "dsig_port_results");
  const std::string Query =
      "select " +
      SelectExisting({"hop", "results_path", "results_sha256", "results_source", "include_multimatch",
                      "include_unreliable", "overwrite", "overwrite_stripped", "names_confirmed",
                      "names_skipped_not_portable", "names_skipped_conflict", "names_skipped_duplicate"},
                     Present) +
      " from dsig_port_results order by hop";
  sqlite3_stmt* Statement = nullptr;
  if (sqlite3_prepare_v2(Handle, Query.c_str(), -1, &Statement, nullptr) != SQLITE_OK) {
    sqlite3_finalize(Statement);
    return;
  }
  while (sqlite3_step(Statement) == SQLITE_ROW) {
    const int64_t Hop = sqlite3_column_int64(Statement, 0);
    for (HopRecord& Record : Hops) {
      if (Record.Hop != Hop) {
        continue;
      }
      Record.HasPortSettings = true;
      Record.ResultsPath = ColumnString(Statement, 1);
      Record.ResultsSha256 = ColumnString(Statement, 2);
      Record.ResultsSource = ColumnString(Statement, 3);
      Record.IncludeMultimatch = sqlite3_column_int64(Statement, 4) != 0;
      Record.IncludeUnreliable = sqlite3_column_int64(Statement, 5) != 0;
      Record.Overwrite = sqlite3_column_int64(Statement, 6) != 0;
      if (sqlite3_column_type(Statement, 7) != SQLITE_NULL) {
        Record.OverwriteStripped = sqlite3_column_int64(Statement, 7) != 0;
      }
      Record.NamesConfirmed = sqlite3_column_int64(Statement, 8);
      Record.NamesSkippedNotPortable = sqlite3_column_int64(Statement, 9);
      Record.NamesSkippedConflict = sqlite3_column_int64(Statement, 10);
      Record.NamesSkippedDuplicate = sqlite3_column_int64(Statement, 11);
    }
  }
  sqlite3_finalize(Statement);
}

}

std::vector<NamedPath> DatabaseFileSet(const std::string& Role, const std::string& Path) {
  std::vector<NamedPath> Files;
  if (Path.empty()) {
    return Files;
  }
  Files.push_back({Role, Path});
  for (const char* Suffix : {"-wal", "-shm", "-journal"}) {
    Files.push_back({Role + "'s " + Suffix + " file", Path + Suffix});
  }
  return Files;
}

bool SameFilePath(const std::string& A, const std::string& B) {
  const std::filesystem::path PathA = PathOf(A);
  const std::filesystem::path PathB = PathOf(B);
  std::error_code Error;
  const bool ExistsA = std::filesystem::exists(PathA, Error);
  Error.clear();
  const bool ExistsB = std::filesystem::exists(PathB, Error);
  if (ExistsA && ExistsB) {
    // One file under two names: hard links, 8.3 short names, a UNC share of a local drive, ...
    Error.clear();
    if (std::filesystem::equivalent(PathA, PathB, Error) && !Error) {
      return true;
    }
  }
  return SameSpelling(CanonicalOrAbsolute(PathA), CanonicalOrAbsolute(PathB));
}

std::optional<std::string> FindPathAlias(const std::vector<NamedPath>& Written, const std::vector<NamedPath>& Inputs) {
  for (const NamedPath& Output : Written) {
    for (const NamedPath& Input : Inputs) {
      if (!Output.Path.empty() && !Input.Path.empty() && SameFilePath(Output.Path, Input.Path)) {
        return Output.Role + " '" + Output.Path + "' is " + Input.Role + " '" + Input.Path +
               "'; refusing to overwrite an input (nothing was changed)";
      }
    }
  }
  return std::nullopt;
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

  // %Y is at least four digits and every other field two, so the text is exactly the old
  // "%04d-%02d-%02dT%02d:%02d:%02dZ" for any real date (and GCC has no truncation to warn about).
  char Buffer[64];
  const size_t Length = std::strftime(Buffer, sizeof(Buffer), "%Y-%m-%dT%H:%M:%SZ", &Parts);
  return std::string(Buffer, Length);
}

std::optional<std::string> FileSha256Hex(const std::string& Path) {
  std::ifstream Stream(PathOf(Path), std::ios::binary);
  if (!Stream.is_open()) {
    return std::nullopt;
  }
  Sha256 Hasher;
  std::vector<char> Buffer(1024 * 1024);
  for (;;) {
    Stream.read(Buffer.data(), static_cast<std::streamsize>(Buffer.size()));
    const std::streamsize Got = Stream.gcount();
    if (Stream.bad()) {
      return std::nullopt;
    }
    if (Got > 0) {
      Hasher.Update(Buffer.data(), static_cast<size_t>(Got));
    }
    if (Stream.eof()) {
      break;
    }
    if (!Stream) {
      return std::nullopt;
    }
  }
  return Hasher.FinishHex();
}

std::string StoredPath(const std::string& Path, bool Full) {
  if (Path.empty()) {
    return std::string();
  }
  const std::filesystem::path Native = PathOf(Path);
  if (!Full) {
    const std::string Name = Utf8Of(Native.filename());
    return Name.empty() ? Path : Name;
  }
  return Utf8Of(CanonicalOrAbsolute(Native));
}

DatabaseIdentity InspectDatabase(const std::string& Path) {
  DatabaseIdentity Identity;
  Identity.Path = Path;
  const auto Fail = [&Identity](PortFailure Failure, std::string Message) {
    Identity.Ok = false;
    Identity.Failure = Failure;
    Identity.Error = std::move(Message);
    return Identity;
  };

  std::error_code Error;
  const std::filesystem::path Native = PathOf(Path);
  if (std::filesystem::is_directory(Native, Error)) {
    return Fail(PortFailure::Io, "'" + Path + "' is a directory, not a database");
  }
  Error.clear();
  if (!std::filesystem::exists(Native, Error)) {
    return Fail(PortFailure::Io, "cannot read '" + Path + "': no such file");
  }
  const std::optional<std::string> Sha = FileSha256Hex(Path);
  if (!Sha) {
    return Fail(PortFailure::Io, "cannot read '" + Path + "'");
  }
  Identity.FileSha256 = *Sha;

  std::string OpenError;
  sqlite3* Handle = OpenReadOnly(Path, OpenError);
  if (Handle == nullptr) {
    return Fail(PortFailure::Io, "cannot open '" + Path + "': " + OpenError);
  }
  // A read-only open succeeds on any file; the first read of the schema tells what it is.
  char* Message = nullptr;
  if (sqlite3_exec(Handle, "pragma schema_version", nullptr, nullptr, &Message) != SQLITE_OK) {
    const std::string Why = Message != nullptr ? Message : sqlite3_errmsg(Handle);
    sqlite3_free(Message);
    sqlite3_close(Handle);
    return Fail(PortFailure::Io, "'" + Path + "' is not an SQLite database (" + Why + ")");
  }

  if (!TableExists(Handle, "functions")) {
    Identity.IsResultsFile = TableExists(Handle, "results");
    sqlite3_close(Handle);
    return Fail(PortFailure::Input, Identity.IsResultsFile
                                        ? "'" + Path + "' is a Diaphora results file, not a Diaphora export"
                                        : "'" + Path + "' has no 'functions' table; not a Diaphora export");
  }

  sqlite3_stmt* Statement = nullptr;
  if (sqlite3_prepare_v2(Handle, "select count(*) from functions", -1, &Statement, nullptr) ==
      SQLITE_OK) {
    if (sqlite3_step(Statement) == SQLITE_ROW) {
      Identity.FunctionCount = sqlite3_column_int64(Statement, 0);
    }
  }
  sqlite3_finalize(Statement);

  if (TableExists(Handle, "program")) {
    Statement = nullptr;
    if (sqlite3_prepare_v2(Handle, "select processor, md5sum from program limit 1", -1, &Statement,
                           nullptr) == SQLITE_OK) {
      if (sqlite3_step(Statement) == SQLITE_ROW) {
        Identity.Processor = ColumnString(Statement, 0);
        // program.md5sum is a 16-byte BLOB in IDA 9.x exports (08 §7.1); report it as hex.
        Identity.InputMd5 = ColumnTextOrHex(Statement, 1);
      }
    }
    sqlite3_finalize(Statement);
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
    }
    sqlite3_finalize(Statement);
    Identity.HopCount = static_cast<int64_t>(Identity.Hops.size());
    ReadPortSettings(Handle, Identity.Hops);
  }

  sqlite3_close(Handle);
  Identity.Ok = true;
  return Identity;
}

std::unordered_map<std::string, NameOrigin> ReadNameOrigins(const std::string& Path) {
  std::unordered_map<std::string, NameOrigin> Origins;

  std::string OpenError;
  sqlite3* Handle = OpenReadOnly(Path, OpenError);
  if (Handle == nullptr) {
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
  }
  sqlite3_finalize(Statement);

  sqlite3_close(Handle);
  return Origins;
}

// =============================================================================================
// Label port from match proposals (docs/parity/00-plan.md §7.1 D6)
//
// What a port writes (decided from docs/parity/08-schema.md, recorded in tools/e2e/README.md):
//
//   functions.name              08 §5.1 #0. Every name-keyed path of the next hop's diff reads it:
//                               matched_primary / matched_secondary keys (D:1373-1374), the
//                               find_same_name join `df.name = f.name` (D:2158-2166),
//                               get_function_row `where name = ?` (D:2445-2460), find_unmatched
//                               (D:2323-2356) and the `sub_` tests (D:1392, 08 §6.2).
//   functions.mangled_function  08 §5.1 #14. Read by find_equal_matches (the INTERSECT key and the
//                               item name, D:1424-1440), the find_same_name join and its
//                               `mangled1.startswith("sub_")` skip (D:2158-2210), and patch-diff
//                               detection `f.mangled_function = df.mangled_function` (D:2599-2603).
//                               A PDB export stores the raw IDA name here and the demangled one in
//                               `name`, so the port copies both from the reference row; a reference
//                               whose mangled_function is not a real symbol gets `name` in both.
//
// Not written, on purpose:
//   prototype, comment          never read at diff time (08 §6.3); they carry no matching signal.
//   prototype2                  a feature, not a label: H30 compares it (08 §6.1) and its value is
//                               the target's own type analysis (08 §5.1 #22).
//   names, assembly, pseudocode, clean_*, *_hash, instructions.*, callgraph
//                               analysis products of the target build. Rewriting callee names in
//                               them would need the exporter's text transforms (not reproducible
//                               without IDA) and would make the reference's features stop matching a
//                               like-for-like no-PDB target in the next hop.
// No ANALYZE, VACUUM or index change: the target's sqlite_stat1 and indices stay as exported, so
// Diaphora plans the next hop on the same statistics a raw export would give it (08 §2 item 3).

namespace {

const char* const CreatePortResultsSchema =
    "create table dsig_port_results ("
    "  hop integer primary key,"
    "  results_path text,"
    "  results_sha256 text,"
    "  results_main_db text,"
    "  results_diff_db text,"
    "  results_version text,"
    "  results_date text,"
    "  include_multimatch integer,"
    "  include_unreliable integer,"
    "  overwrite integer,"
    "  label_columns text,"
    "  proposals integer,"
    "  selected integer,"
    "  names_applied integer,"
    "  names_confirmed integer,"
    "  names_skipped_not_portable integer,"
    "  names_skipped_conflict integer,"
    "  names_skipped_hops integer,"
    "  names_skipped_ratio integer,"
    "  names_skipped_existing integer,"
    "  names_skipped_duplicate integer,"
    "  overwrite_stripped integer,"
    "  results_source text"
    ");"
    "create table dsig_port_log ("
    "  hop integer,"
    "  results_rowid integer,"
    "  type text,"
    "  line text,"
    "  description text,"
    "  ratio text,"
    "  address text,"
    "  ref_address text,"
    "  ref_name text,"
    "  ref_mangled text,"
    "  name_before text,"
    "  mangled_before text,"
    "  confidence real,"
    "  hops integer,"
    "  action text"
    ");";

const char* const LabelColumns = "name,mangled_function";

struct LabelRow {
  std::string Address;  // functions.address as stored
  std::optional<std::string> Name;
  std::optional<std::string> Mangled;
};

struct LabelTable {
  std::vector<LabelRow> Rows;                  // `order by id`
  std::unordered_map<uint64_t, size_t> ByEa;   // int(address) -> row
};

// One stored row of a parent's dsig_port_results, carried forward like dsig_provenance.
struct StoredCell {
  int Type = SQLITE_NULL;
  int64_t Int = 0;
  double Real = 0.0;
  std::string Text;
};
using StoredRow = std::vector<StoredCell>;

class Stmt {
public:
  Stmt(sqlite3* Handle, const char* Sql) {
    Ok_ = sqlite3_prepare_v2(Handle, Sql, -1, &Statement_, nullptr) == SQLITE_OK;
  }
  ~Stmt() { sqlite3_finalize(Statement_); }
  Stmt(const Stmt&) = delete;
  Stmt& operator=(const Stmt&) = delete;

  bool Ok() const { return Ok_; }
  sqlite3_stmt* Get() const { return Statement_; }

  void Text(int Index, const std::string& Value) {
    sqlite3_bind_text(Statement_, Index, Value.data(), static_cast<int>(Value.size()), SQLITE_TRANSIENT);
  }
  void Text(int Index, const std::optional<std::string>& Value) {
    if (Value) {
      Text(Index, *Value);
    } else {
      sqlite3_bind_null(Statement_, Index);
    }
  }
  void Int(int Index, int64_t Value) { sqlite3_bind_int64(Statement_, Index, Value); }
  void Real(int Index, double Value) { sqlite3_bind_double(Statement_, Index, Value); }
  void Cell(int Index, const StoredCell& Value) {
    switch (Value.Type) {
      case SQLITE_INTEGER:
        Int(Index, Value.Int);
        break;
      case SQLITE_FLOAT:
        Real(Index, Value.Real);
        break;
      case SQLITE_TEXT:
        Text(Index, Value.Text);
        break;
      case SQLITE_BLOB:
        sqlite3_bind_blob(Statement_, Index, Value.Text.data(), static_cast<int>(Value.Text.size()),
                          SQLITE_TRANSIENT);
        break;
      default:
        sqlite3_bind_null(Statement_, Index);
        break;
    }
  }

  // Steps a statement that returns no row, then resets it for the next binding.
  bool Run() {
    const int Code = sqlite3_step(Statement_);
    sqlite3_reset(Statement_);
    sqlite3_clear_bindings(Statement_);
    return Code == SQLITE_DONE;
  }

private:
  sqlite3_stmt* Statement_ = nullptr;
  bool Ok_ = false;
};

bool Exec(sqlite3* Handle, const char* Sql, std::string& Error) {
  char* Message = nullptr;
  if (sqlite3_exec(Handle, Sql, nullptr, nullptr, &Message) != SQLITE_OK) {
    Error = Message != nullptr ? Message : sqlite3_errmsg(Handle);
    sqlite3_free(Message);
    return false;
  }
  return true;
}

bool LoadLabelTable(const std::string& Path, LabelTable& Out, std::string& Error) {
  sqlite3* Handle = OpenReadOnly(Path, Error);
  if (Handle == nullptr) {
    return false;
  }
  bool Ok = true;
  {
    Stmt Query(Handle, "select address, name, mangled_function from functions order by id");
    if (!Query.Ok()) {
      Error = sqlite3_errmsg(Handle);
      Ok = false;
    }
    int Code = SQLITE_DONE;
    while (Ok && (Code = sqlite3_step(Query.Get())) == SQLITE_ROW) {
      LabelRow Row;
      if (sqlite3_column_type(Query.Get(), 0) == SQLITE_NULL) {
        Error = "a functions row has a NULL address";
        Ok = false;
        break;
      }
      Row.Address = ColumnString(Query.Get(), 0);
      Row.Name = ColumnOptional(Query.Get(), 1);
      Row.Mangled = ColumnOptional(Query.Get(), 2);
      const std::optional<uint64_t> Ea = ParseDecimalAddress(Row.Address);
      if (!Ea) {
        Error = "functions.address '" + Row.Address + "' is not a decimal address";
        Ok = false;
        break;
      }
      if (!Out.ByEa.emplace(*Ea, Out.Rows.size()).second) {
        Error = "two functions rows share address " + Row.Address;
        Ok = false;
        break;
      }
      Out.Rows.push_back(std::move(Row));
    }
    if (Ok && Code != SQLITE_DONE) {
      Error = sqlite3_errmsg(Handle);
      Ok = false;
    }
  }
  sqlite3_close(Handle);
  return Ok;
}

bool ReadParentPortResults(const std::string& Path, std::vector<StoredRow>& Out, std::string& Error) {
  sqlite3* Handle = OpenReadOnly(Path, Error);
  if (Handle == nullptr) {
    return false;
  }
  bool Ok = true;
  if (TableExists(Handle, "dsig_port_results")) {
    const std::vector<const char*>& Columns = PortResultsColumnList();
    const int ColumnCount = static_cast<int>(Columns.size());
    const std::string Sql = "select " + SelectExisting(Columns, TableColumns(Handle, "dsig_port_results")) +
                            " from dsig_port_results order by hop";
    Stmt Query(Handle, Sql.c_str());
    if (!Query.Ok()) {
      Error = sqlite3_errmsg(Handle);
      Ok = false;
    }
    int Code = SQLITE_DONE;
    while (Ok && (Code = sqlite3_step(Query.Get())) == SQLITE_ROW) {
      StoredRow Row(static_cast<size_t>(ColumnCount));
      for (int Column = 0; Column < ColumnCount; ++Column) {
        StoredCell& Cell = Row[static_cast<size_t>(Column)];
        Cell.Type = sqlite3_column_type(Query.Get(), Column);
        if (Cell.Type == SQLITE_INTEGER) {
          Cell.Int = sqlite3_column_int64(Query.Get(), Column);
        } else if (Cell.Type == SQLITE_FLOAT) {
          Cell.Real = sqlite3_column_double(Query.Get(), Column);
        } else if (Cell.Type == SQLITE_TEXT || Cell.Type == SQLITE_BLOB) {
          const void* Bytes = Cell.Type == SQLITE_TEXT
                                  ? static_cast<const void*>(sqlite3_column_text(Query.Get(), Column))
                                  : sqlite3_column_blob(Query.Get(), Column);
          const int Length = sqlite3_column_bytes(Query.Get(), Column);
          if (Bytes != nullptr && Length > 0) {
            Cell.Text.assign(static_cast<const char*>(Bytes), static_cast<size_t>(Length));
          }
        }
      }
      Out.push_back(std::move(Row));
    }
    if (Ok && Code != SQLITE_DONE) {
      Error = sqlite3_errmsg(Handle);
      Ok = false;
    }
  }
  sqlite3_close(Handle);
  return Ok;
}

// Where PortLabels builds its output before the final rename.
std::string TemporaryOutputPath(const std::string& OutputPath) { return OutputPath + ".dsig-tmp"; }

// A consistent copy of a possibly WAL-mode export: the main file, plus its -wal when that holds
// committed frames (SQLite replays it into the copy on the first open).
bool CopyDatabase(const std::string& From, const std::string& To, std::string& Error) {
  RemoveDatabaseFiles(To);
  if (!CopyFileBinary(From, To, Error)) {
    return false;
  }
  if (FileSizeOrZero(From + "-wal") > 0 && !CopyFileBinary(From + "-wal", To + "-wal", Error)) {
    return false;
  }
  return true;
}

// Puts the finished temporary database in place of the output without ever losing the previous
// output: the old output's -wal/-shm/-journal (which must not be replayed into the new file) are moved
// aside first, the temporary is renamed over the output (which replaces it in one step), and only then
// are the moved sidecars deleted. When the rename fails the sidecars are moved back, so the previous
// output is exactly as it was.
bool PublishOutput(const std::string& Temporary, const std::string& Output, std::string& Error) {
  std::vector<std::pair<std::string, std::string>> MovedAside;  // (original, aside)
  const auto Restore = [&MovedAside]() {
    for (const auto& [Original, Aside] : MovedAside) {
      std::error_code Ignored;
      RenameOver(Aside, Original, Ignored);
    }
  };
  for (const char* Suffix : {"-wal", "-shm", "-journal"}) {
    const std::string Sidecar = Output + Suffix;
    if (!PathExists(Sidecar)) {
      continue;
    }
    const std::string Aside = Sidecar + ".dsig-old";
    RemoveFile(Aside);
    std::error_code MoveError;
    if (!RenameOver(Sidecar, Aside, MoveError)) {
      Restore();
      Error = "cannot move the previous output's sidecar '" + Sidecar + "' aside: " + MoveError.message() +
              "; the previous output was left as it was";
      return false;
    }
    MovedAside.emplace_back(Sidecar, Aside);
  }
  std::error_code RenameError;
  if (!RenameOver(Temporary, Output, RenameError)) {
    Restore();
    Error = "cannot move the new output into place as '" + Output + "': " + RenameError.message() +
            "; the previous output was left as it was";
    return false;
  }
  // Closing the last connection checkpoints and deletes the temporary's -wal; if one is left with
  // committed frames it belongs to the output now.
  if (FileSizeOrZero(Temporary + "-wal") > 0) {
    std::error_code WalError;
    if (!RenameOver(Temporary + "-wal", Output + "-wal", WalError)) {
      Error = "cannot move '" + Temporary + "-wal' beside the output: " + WalError.message();
      return false;
    }
  }
  for (const auto& [Original, Aside] : MovedAside) {
    RemoveFile(Aside);
  }
  return true;
}

std::string HexEa(uint64_t Ea) {
  char Buffer[32];
  std::snprintf(Buffer, sizeof(Buffer), "%08llx", static_cast<unsigned long long>(Ea));
  return std::string(Buffer);
}

std::string ShowName(const std::optional<std::string>& Name) { return Name ? "'" + *Name + "'" : "None"; }

bool NameMatchesRow(const std::optional<std::string>& Name, const LabelRow& Row) {
  return Name == Row.Name || Name == Row.Mangled;
}

}

const char* LabelActionName(LabelAction Action) {
  switch (Action) {
    case LabelAction::NotSelected:
      return "not_selected";
    case LabelAction::Applied:
      return "applied";
    case LabelAction::Confirmed:
      return "confirmed";
    case LabelAction::SkippedNotPortable:
      return "skipped_not_portable";
    case LabelAction::SkippedConflict:
      return "skipped_conflict";
    case LabelAction::SkippedHops:
      return "skipped_hops";
    case LabelAction::SkippedRatio:
      return "skipped_ratio";
    case LabelAction::SkippedExisting:
      return "skipped_existing";
    case LabelAction::SkippedDuplicateName:
      return "skipped_duplicate_name";
  }
  return "unknown";
}

std::string SqliteReadOnlyUri(const std::string& Path, bool Immutable) {
  std::string Normal = Path;
#ifdef _WIN32
  std::replace(Normal.begin(), Normal.end(), '\\', '/');
#endif
  std::string Escaped;
  Escaped.reserve(Normal.size() + 8);
  for (const char Character : Normal) {
    switch (Character) {
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
        Escaped += Character;
        break;
    }
  }
  if (Escaped.size() >= 2 && std::isalpha(static_cast<unsigned char>(Escaped[0])) && Escaped[1] == ':') {
    // A drive-letter path becomes file:/C:/... (SQLite's documented Windows URI form).
    Escaped.insert(Escaped.begin(), '/');
  } else if (Escaped.size() >= 2 && Escaped[0] == '/' && Escaped[1] == '/') {
    // A UNC path //server/share/x keeps an empty URI authority: file:////server/share/x, whose path
    // part SQLite's Windows VFS takes verbatim. The same rule as DiffDatabase::UriForPath.
    Escaped.insert(0, "//");
  }
  return "file:" + Escaped + (Immutable ? "?mode=ro&immutable=1" : "?mode=ro");
}

std::string ReadOnlyDatabaseUri(const std::string& Path) {
  // immutable=1 skips locking and the -wal/-shm files. It is only safe when no committed frame sits
  // in a -wal, so a WAL file with a non-empty -wal is read the normal way.
  const bool Immutable = FileIsWalMode(Path) && FileSizeOrZero(Path + "-wal") == 0;
  return SqliteReadOnlyUri(Path, Immutable);
}

std::optional<uint64_t> ParseDecimalAddress(std::string_view Text) {
  const auto IsSpace = [](char Character) {
    return Character == ' ' || Character == '\t' || Character == '\n' || Character == '\r' ||
           Character == '\f' || Character == '\v';
  };
  while (!Text.empty() && IsSpace(Text.front())) {
    Text.remove_prefix(1);
  }
  while (!Text.empty() && IsSpace(Text.back())) {
    Text.remove_suffix(1);
  }
  if (!Text.empty() && Text.front() == '+') {
    Text.remove_prefix(1);
  }
  if (Text.empty()) {
    return std::nullopt;
  }
  uint64_t Value = 0;
  bool PreviousDigit = false;
  for (size_t Position = 0; Position < Text.size(); ++Position) {
    const char Character = Text[Position];
    if (Character == '_') {
      // One '_' between two digits, as Python's int() accepts it.
      if (!PreviousDigit || Position + 1 == Text.size()) {
        return std::nullopt;
      }
      PreviousDigit = false;
      continue;
    }
    if (Character < '0' || Character > '9') {
      return std::nullopt;
    }
    const uint64_t Digit = static_cast<uint64_t>(Character - '0');
    if (Value > (UINT64_MAX - Digit) / 10) {
      return std::nullopt;
    }
    Value = Value * 10 + Digit;
    PreviousDigit = true;
  }
  return Value;
}

LabelPortResult PortLabels(const LabelPortOptions& Options, const std::vector<LabelProposal>& Proposals) {
  LabelPortResult Result;
  const auto Fail = [&Result](PortFailure Failure, std::string Message) {
    Result.Ok = false;
    Result.Failure = Failure;
    Result.Error = std::move(Message);
    return Result;
  };

  // Alias refusal before any I/O (JOURNAL.md "in-place port destroyed the target database"; lane F1).
  // The port deletes, creates and renames the output, the temporary "<output>.dsig-tmp" and every
  // -wal / -shm / -journal sidecar of both (CopyDatabase, RemoveDatabaseFiles and PublishOutput), and
  // SQLite itself creates, plays back and deletes the temporary's sidecars
  // (https://www.sqlite.org/tempfiles.html §2.1-2.3). None of those eight files may be an input or one
  // of the inputs' own sidecars.
  if (Options.OutputPath.empty()) {
    return Fail(PortFailure::Usage, "no output path");
  }
  std::vector<NamedPath> Written = DatabaseFileSet("the output", Options.OutputPath);
  for (NamedPath& File : DatabaseFileSet("the temporary output", TemporaryOutputPath(Options.OutputPath))) {
    Written.push_back(std::move(File));
  }
  std::vector<NamedPath> Inputs = DatabaseFileSet("the reference database", Options.ReferencePath);
  for (NamedPath& File : DatabaseFileSet("the target database", Options.TargetPath)) {
    Inputs.push_back(std::move(File));
  }
  for (const std::string& Other : Options.OtherInputs) {
    for (NamedPath& File : DatabaseFileSet("the input", Other)) {
      Inputs.push_back(std::move(File));
    }
  }
  if (const std::optional<std::string> Alias = FindPathAlias(Written, Inputs)) {
    return Fail(PortFailure::Usage, *Alias);
  }
  for (const std::string* Input : {&Options.ReferencePath, &Options.TargetPath}) {
    if (!FileExists(*Input)) {
      return Fail(PortFailure::Io, "cannot open '" + *Input + "'" + (PathExists(*Input) ? "" : ": no such file"));
    }
  }
  {
    const std::filesystem::path Directory = PathOf(Options.OutputPath).parent_path();
    std::error_code Error;
    if (!Directory.empty() && !std::filesystem::is_directory(Directory, Error)) {
      return Fail(PortFailure::Io, "output directory '" + Utf8Of(Directory) + "' does not exist");
    }
  }

  const DatabaseIdentity ReferenceIdentity = InspectDatabase(Options.ReferencePath);
  if (!ReferenceIdentity.Ok) {
    return Fail(ReferenceIdentity.Failure, "reference: " + ReferenceIdentity.Error);
  }
  const DatabaseIdentity TargetIdentity = InspectDatabase(Options.TargetPath);
  if (!TargetIdentity.Ok) {
    return Fail(TargetIdentity.Failure, "target: " + TargetIdentity.Error);
  }

  LabelTable Reference;
  LabelTable Target;
  std::string LoadError;
  if (!LoadLabelTable(Options.ReferencePath, Reference, LoadError)) {
    return Fail(PortFailure::Input, "reference: " + LoadError);
  }
  if (!LoadLabelTable(Options.TargetPath, Target, LoadError)) {
    return Fail(PortFailure::Input, "target: " + LoadError);
  }
  Result.FunctionsReference = static_cast<int64_t>(Reference.Rows.size());
  Result.FunctionsTarget = static_cast<int64_t>(Target.Rows.size());

  // Every proposal must describe these two databases: both addresses exist, and the names the
  // producer wrote are the rows' name or mangled_function (the "100% equal" items carry
  // mangled_function, D:1435-1440; every other item carries name, 01 §6).
  std::vector<const LabelRow*> ReferenceRows(Proposals.size(), nullptr);
  std::vector<const LabelRow*> TargetRows(Proposals.size(), nullptr);
  std::vector<size_t> TargetIndex(Proposals.size(), 0);
  for (size_t Index = 0; Index < Proposals.size(); ++Index) {
    const LabelProposal& Proposal = Proposals[Index];
    const std::string Where = "results row " + std::to_string(Proposal.SourceRow) + " (" + Proposal.Category +
                              " " + Proposal.Line + ")";
    const auto FoundReference = Reference.ByEa.find(Proposal.ReferenceEa);
    if (FoundReference == Reference.ByEa.end()) {
      return Fail(PortFailure::Input, Where + ": address " + HexEa(Proposal.ReferenceEa) +
                                          " is not a function of the reference database");
    }
    const auto FoundTarget = Target.ByEa.find(Proposal.TargetEa);
    if (FoundTarget == Target.ByEa.end()) {
      return Fail(PortFailure::Input, Where + ": address2 " + HexEa(Proposal.TargetEa) +
                                          " is not a function of the target database");
    }
    ReferenceRows[Index] = &Reference.Rows[FoundReference->second];
    TargetRows[Index] = &Target.Rows[FoundTarget->second];
    TargetIndex[Index] = FoundTarget->second;
    if (!NameMatchesRow(Proposal.ReferenceName, *ReferenceRows[Index])) {
      return Fail(PortFailure::Input,
                  Where + ": name " + ShowName(Proposal.ReferenceName) + " is not the reference function at " +
                      HexEa(Proposal.ReferenceEa) + " (" + ShowName(ReferenceRows[Index]->Name) + " / " +
                      ShowName(ReferenceRows[Index]->Mangled) + "); the results file belongs to another pair");
    }
    if (!NameMatchesRow(Proposal.TargetName, *TargetRows[Index])) {
      return Fail(PortFailure::Input,
                  Where + ": name2 " + ShowName(Proposal.TargetName) + " is not the target function at " +
                      HexEa(Proposal.TargetEa) + " (" + ShowName(TargetRows[Index]->Name) + " / " +
                      ShowName(TargetRows[Index]->Mangled) + "); the results file belongs to another pair");
    }
  }

  const std::unordered_map<std::string, NameOrigin> ReferenceOrigins = ReadNameOrigins(Options.ReferencePath);
  const std::string AppliedAt = CurrentUtcTimestamp();

  // Pass 1: one decision per proposal, in stored order. The order of the tests: not portable,
  // confirmation, hop cap, ratio floor, existing real name (JOURNAL.md "names that never travelled
  // were counted as ported").
  Result.Decisions.resize(Proposals.size());
  std::vector<bool> Claimed(Target.Rows.size(), false);
  std::vector<std::string> OriginAddress(Proposals.size());
  std::vector<std::string> OriginName(Proposals.size());
  std::vector<std::string> FirstLabelledAt(Proposals.size());
  for (size_t Index = 0; Index < Proposals.size(); ++Index) {
    const LabelProposal& Proposal = Proposals[Index];
    const LabelRow& ReferenceRow = *ReferenceRows[Index];
    const LabelRow& TargetRow = *TargetRows[Index];
    LabelDecision& Decision = Result.Decisions[Index];
    Decision.TargetAddress = TargetRow.Address;
    Decision.ReferenceAddress = ReferenceRow.Address;
    Decision.ReferenceName = ReferenceRow.Name;
    Decision.ReferenceMangled = ReferenceRow.Mangled;
    Decision.TargetNameBefore = TargetRow.Name;
    Decision.TargetMangledBefore = TargetRow.Mangled;
    ++Result.Proposals;

    if (!Proposal.Selected) {
      Decision.Action = LabelAction::NotSelected;
      continue;
    }
    ++Result.Selected;

    // The first selected proposal claims the target function, whatever its outcome: Diaphora writes
    // best, partial, unreliable, multimatch, each by descending ratio (D:2405-2424, D:2926), so the
    // first one is the strongest evidence for that function.
    if (Claimed[TargetIndex[Index]]) {
      Decision.Action = LabelAction::SkippedConflict;
      continue;
    }
    Claimed[TargetIndex[Index]] = true;

    if (!ReferenceRow.Name || !IsPortableSymbol(*ReferenceRow.Name)) {
      Decision.Action = LabelAction::SkippedNotPortable;
      continue;
    }
    const std::string& ReferenceName = *ReferenceRow.Name;
    // An IDA placeholder (sub_, j_, DllEntryPoint, ...) is not a real name: it is replaced.
    const bool TargetHasRealName = TargetRow.Name && IsPortableSymbol(*TargetRow.Name);
    if (TargetHasRealName && *TargetRow.Name == ReferenceName) {
      Decision.Action = LabelAction::Confirmed;
      continue;
    }

    // Inherit the reference's history only while the reference still carries the name it recorded.
    const auto Inherited = ReferenceOrigins.find(ReferenceRow.Address);
    const bool HasHistory = Inherited != ReferenceOrigins.end() && Inherited->second.Name == ReferenceName;
    OriginAddress[Index] = HasHistory ? Inherited->second.OriginAddress : ReferenceRow.Address;
    OriginName[Index] = HasHistory ? Inherited->second.OriginName : ReferenceName;
    FirstLabelledAt[Index] = HasHistory && !Inherited->second.FirstLabelledAt.empty()
                                 ? Inherited->second.FirstLabelledAt
                                 : AppliedAt;
    Decision.Hops = HasHistory ? Inherited->second.Hops + 1 : 1;
    const double PreviousRatio = HasHistory ? Inherited->second.CumulativeRatio : 1.0;
    Decision.Confidence = PreviousRatio * Proposal.Ratio;

    if (Options.MaxHops >= 0 && Decision.Hops > Options.MaxHops) {
      Decision.Action = LabelAction::SkippedHops;
      continue;
    }
    if (Decision.Confidence < Options.MinCumulativeRatio) {
      Decision.Action = LabelAction::SkippedRatio;
      continue;
    }
    if (TargetHasRealName) {
      // Diaphora's stripped-binary shortcut pairs functions by address, so on a real name it is only
      // trusted with both flags (JOURNAL.md: 1172 of 1329 such rows were wrong on win32u).
      const bool Stripped = Proposal.Description == kStrippedDescription;
      const bool MayOverwrite = Options.OverwriteExistingNames && (!Stripped || Options.OverwriteStripped);
      if (!MayOverwrite) {
        Decision.Action = LabelAction::SkippedExisting;
        continue;
      }
    }
    Decision.Action = LabelAction::Applied;
    Decision.WrittenMangled =
        ReferenceRow.Mangled && IsPortableSymbol(*ReferenceRow.Mangled) ? *ReferenceRow.Mangled : ReferenceName;
  }

  // Pass 2: never leave one real name on two functions of the output (Diaphora keys its match state
  // by name, D:1373-1374, and the corpus has no duplicate names, 02 probe 14). Removing an
  // application restores that function's old name, which can expose another duplicate, so repeat
  // until nothing changes; every round removes at least one application.
  for (;;) {
    std::vector<std::optional<std::string>> FinalName(Target.Rows.size());
    std::vector<std::optional<std::string>> FinalMangled(Target.Rows.size());
    for (size_t Row = 0; Row < Target.Rows.size(); ++Row) {
      FinalName[Row] = Target.Rows[Row].Name;
      FinalMangled[Row] = Target.Rows[Row].Mangled;
    }
    for (size_t Index = 0; Index < Proposals.size(); ++Index) {
      if (Result.Decisions[Index].Action == LabelAction::Applied) {
        FinalName[TargetIndex[Index]] = Result.Decisions[Index].ReferenceName;
        FinalMangled[TargetIndex[Index]] = Result.Decisions[Index].WrittenMangled;
      }
    }
    std::map<std::string, int> NameCount;
    std::map<std::string, int> MangledCount;
    for (size_t Row = 0; Row < Target.Rows.size(); ++Row) {
      if (FinalName[Row] && IsPortableSymbol(*FinalName[Row])) {
        ++NameCount[*FinalName[Row]];
      }
      if (FinalMangled[Row] && IsPortableSymbol(*FinalMangled[Row])) {
        ++MangledCount[*FinalMangled[Row]];
      }
    }
    bool Changed = false;
    for (size_t Index = 0; Index < Proposals.size(); ++Index) {
      LabelDecision& Decision = Result.Decisions[Index];
      if (Decision.Action != LabelAction::Applied) {
        continue;
      }
      if (NameCount[*Decision.ReferenceName] > 1 || MangledCount[Decision.WrittenMangled] > 1) {
        Decision.Action = LabelAction::SkippedDuplicateName;
        Decision.WrittenMangled.clear();
        Changed = true;
      }
    }
    if (!Changed) {
      break;
    }
  }

  for (const LabelDecision& Decision : Result.Decisions) {
    switch (Decision.Action) {
      case LabelAction::Applied:
        ++Result.NamesApplied;
        break;
      case LabelAction::Confirmed:
        ++Result.NamesConfirmed;
        break;
      case LabelAction::SkippedNotPortable:
        ++Result.NamesSkippedNotPortable;
        break;
      case LabelAction::SkippedConflict:
        ++Result.NamesSkippedConflict;
        break;
      case LabelAction::SkippedHops:
        ++Result.NamesSkippedHops;
        break;
      case LabelAction::SkippedRatio:
        ++Result.NamesSkippedRatio;
        break;
      case LabelAction::SkippedExisting:
        ++Result.NamesSkippedExisting;
        break;
      case LabelAction::SkippedDuplicateName:
        ++Result.NamesSkippedDuplicate;
        break;
      case LabelAction::NotSelected:
        break;
    }
  }

  std::vector<StoredRow> ParentPortResults;
  std::string ParentError;
  if (!ReadParentPortResults(Options.ReferencePath, ParentPortResults, ParentError)) {
    return Fail(PortFailure::Input, "reference: " + ParentError);
  }

  int64_t HighestParentHop = 0;
  for (const HopRecord& Record : ReferenceIdentity.Hops) {
    HighestParentHop = std::max(HighestParentHop, Record.Hop);
  }
  Result.NewHop = HighestParentHop + 1;
  Result.Lineage = BuildLineage(ReferenceIdentity.Lineage, ReferenceIdentity.InputMd5, TargetIdentity.InputMd5);

  // The output is built under a temporary name and renamed at the end, so a failed port leaves no
  // half-written database behind. Neither name (nor any sidecar) is an input: checked at the top.
  const std::string Temporary = TemporaryOutputPath(Options.OutputPath);
  std::string WriteError;
  if (!CopyDatabase(Options.TargetPath, Temporary, WriteError)) {
    RemoveDatabaseFiles(Temporary);
    return Fail(PortFailure::Io, "cannot write the output '" + Options.OutputPath + "': " + WriteError);
  }

  sqlite3* Handle = nullptr;
  if (sqlite3_open_v2(Temporary.c_str(), &Handle, SQLITE_OPEN_READWRITE, nullptr) != SQLITE_OK) {
    WriteError = Handle != nullptr ? sqlite3_errmsg(Handle) : "cannot allocate handle";
    sqlite3_close(Handle);
    RemoveDatabaseFiles(Temporary);
    return Fail(PortFailure::Io, "output '" + Options.OutputPath + "': " + WriteError);
  }

  const auto Write = [&]() -> bool {
    // The dsig_* tables of a target that was itself a port output are replaced, not merged: the
    // output describes one history (the reference's plus this hop).
    if (!Exec(Handle, "begin immediate transaction;", WriteError) || !Exec(Handle, DropDsigTables, WriteError) ||
        !Exec(Handle, CreateProvenanceSchema, WriteError) || !Exec(Handle, CreatePortResultsSchema, WriteError)) {
      return false;
    }

    Stmt Rename(Handle, "update functions set name = ?, mangled_function = ? where address = ?");
    Stmt Origin(Handle,
                "insert or replace into dsig_name_origin (address, name, origin_address, origin_name, "
                "hops, cumulative_ratio, heuristic, first_labelled_at) values (?, ?, ?, ?, ?, ?, ?, ?)");
    Stmt Log(Handle,
             "insert into dsig_port_log (hop, results_rowid, type, line, description, ratio, address, "
             "ref_address, ref_name, ref_mangled, name_before, mangled_before, confidence, hops, action) "
             "values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
    if (!Rename.Ok() || !Origin.Ok() || !Log.Ok()) {
      WriteError = sqlite3_errmsg(Handle);
      return false;
    }

    for (size_t Index = 0; Index < Proposals.size(); ++Index) {
      const LabelProposal& Proposal = Proposals[Index];
      const LabelDecision& Decision = Result.Decisions[Index];
      if (Decision.Action == LabelAction::Applied) {
        Rename.Text(1, *Decision.ReferenceName);
        Rename.Text(2, Decision.WrittenMangled);
        Rename.Text(3, Decision.TargetAddress);
        if (!Rename.Run() || sqlite3_changes(Handle) != 1) {
          WriteError = "cannot rename the function at " + Decision.TargetAddress + ": " + sqlite3_errmsg(Handle);
          return false;
        }
        Origin.Text(1, Decision.TargetAddress);
        Origin.Text(2, *Decision.ReferenceName);
        Origin.Text(3, OriginAddress[Index]);
        Origin.Text(4, OriginName[Index]);
        Origin.Int(5, Decision.Hops);
        Origin.Real(6, Decision.Confidence);
        Origin.Text(7, Proposal.Category + ":" + Proposal.Description);
        Origin.Text(8, FirstLabelledAt[Index]);
        if (!Origin.Run()) {
          WriteError = sqlite3_errmsg(Handle);
          return false;
        }
      }
      Log.Int(1, Result.NewHop);
      Log.Int(2, Proposal.SourceRow);
      Log.Text(3, Proposal.Category);
      Log.Text(4, Proposal.Line);
      Log.Text(5, Proposal.Description);
      Log.Text(6, Proposal.RatioText);
      Log.Text(7, Decision.TargetAddress);
      Log.Text(8, Decision.ReferenceAddress);
      Log.Text(9, Decision.ReferenceName);
      Log.Text(10, Decision.ReferenceMangled);
      Log.Text(11, Decision.TargetNameBefore);
      Log.Text(12, Decision.TargetMangledBefore);
      Log.Real(13, Decision.Confidence);
      Log.Int(14, Decision.Hops);
      Log.Text(15, std::string(LabelActionName(Decision.Action)));
      if (!Log.Run()) {
        WriteError = sqlite3_errmsg(Handle);
        return false;
      }
    }

    // dsig_provenance: the parent's hops, then this one.
    Stmt Hop(Handle, InsertHopSql);
    if (!Hop.Ok()) {
      WriteError = sqlite3_errmsg(Handle);
      return false;
    }
    for (const HopRecord& Record : ReferenceIdentity.Hops) {
      BindHop(Hop.Get(), Record);
      if (!Hop.Run()) {
        WriteError = sqlite3_errmsg(Handle);
        return false;
      }
    }
    HopRecord NewRecord;
    NewRecord.Hop = Result.NewHop;
    NewRecord.SourcePath = StoredPath(Options.ReferencePath, Options.StoreFullPaths);
    NewRecord.SourceInputMd5 = ReferenceIdentity.InputMd5;
    NewRecord.SourceFileSha256 = ReferenceIdentity.FileSha256;
    NewRecord.TargetInputMd5 = TargetIdentity.InputMd5;
    NewRecord.TargetFileSha256Before = TargetIdentity.FileSha256;
    NewRecord.AppliedAt = AppliedAt;
    NewRecord.ToolVersion = DSIG_VERSION;
    NewRecord.FunctionsReference = Result.FunctionsReference;
    NewRecord.FunctionsTarget = Result.FunctionsTarget;
    NewRecord.Matches = Result.Selected;
    NewRecord.NamesApplied = Result.NamesApplied;
    NewRecord.NamesSkippedExisting = Result.NamesSkippedExisting;
    NewRecord.NamesSkippedHops = Result.NamesSkippedHops;
    NewRecord.NamesSkippedRatio = Result.NamesSkippedRatio;
    NewRecord.MinRatio = Options.MinCumulativeRatio;
    NewRecord.MaxHops = Options.MaxHops;
    NewRecord.Lineage = Result.Lineage;
    BindHop(Hop.Get(), NewRecord);
    if (!Hop.Run()) {
      WriteError = sqlite3_errmsg(Handle);
      return false;
    }

    // dsig_port_results: the parent's rows, then this hop's.
    const std::vector<const char*>& Columns = PortResultsColumnList();
    std::string ColumnText;
    std::string Placeholders;
    for (const char* Column : Columns) {
      ColumnText += std::string(ColumnText.empty() ? "" : ", ") + Column;
      Placeholders += Placeholders.empty() ? "?" : ", ?";
    }
    const std::string InsertResultsSql =
        "insert or replace into dsig_port_results (" + ColumnText + ") values (" + Placeholders + ")";
    Stmt Results(Handle, InsertResultsSql.c_str());
    if (!Results.Ok()) {
      WriteError = sqlite3_errmsg(Handle);
      return false;
    }
    for (const StoredRow& Row : ParentPortResults) {
      for (size_t Column = 0; Column < Row.size(); ++Column) {
        Results.Cell(static_cast<int>(Column) + 1, Row[Column]);
      }
      if (!Results.Run()) {
        WriteError = sqlite3_errmsg(Handle);
        return false;
      }
    }
    // The results file's config names its databases as the producer typed them; they follow the same
    // path policy as the other path columns.
    const auto ConfigPath = [&Options](const std::string& Path) {
      return Options.StoreFullPaths ? Path : BaseNameAnySeparator(Path);
    };
    Results.Int(1, Result.NewHop);
    Results.Text(2, StoredPath(Options.ResultsPath, Options.StoreFullPaths));
    Results.Text(3, Options.ResultsSha256);
    Results.Text(4, ConfigPath(Options.ResultsMainDb));
    Results.Text(5, ConfigPath(Options.ResultsDiffDb));
    Results.Text(6, Options.ResultsVersion);
    Results.Text(7, Options.ResultsDate);
    Results.Int(8, Options.IncludeMultimatch ? 1 : 0);
    Results.Int(9, Options.IncludeUnreliable ? 1 : 0);
    Results.Int(10, Options.OverwriteExistingNames ? 1 : 0);
    Results.Text(11, std::string(LabelColumns));
    Results.Int(12, Result.Proposals);
    Results.Int(13, Result.Selected);
    Results.Int(14, Result.NamesApplied);
    Results.Int(15, Result.NamesConfirmed);
    Results.Int(16, Result.NamesSkippedNotPortable);
    Results.Int(17, Result.NamesSkippedConflict);
    Results.Int(18, Result.NamesSkippedHops);
    Results.Int(19, Result.NamesSkippedRatio);
    Results.Int(20, Result.NamesSkippedExisting);
    Results.Int(21, Result.NamesSkippedDuplicate);
    Results.Int(22, Options.OverwriteStripped ? 1 : 0);
    Results.Text(23, Options.ResultsSource);
    if (!Results.Run()) {
      WriteError = sqlite3_errmsg(Handle);
      return false;
    }
    return Exec(Handle, "commit transaction;", WriteError);
  };

  if (!Write()) {
    sqlite3_exec(Handle, "rollback transaction;", nullptr, nullptr, nullptr);
    sqlite3_close(Handle);
    RemoveDatabaseFiles(Temporary);
    return Fail(PortFailure::Io, "output '" + Options.OutputPath + "': " + WriteError);
  }
  if (sqlite3_close(Handle) != SQLITE_OK) {
    RemoveDatabaseFiles(Temporary);
    return Fail(PortFailure::Io, "output '" + Options.OutputPath + "': cannot close the database");
  }

  std::string PublishError;
  const bool Published = PublishOutput(Temporary, Options.OutputPath, PublishError);
  RemoveDatabaseFiles(Temporary);
  if (!Published) {
    return Fail(PortFailure::Io, PublishError);
  }

  Result.OutputSha256 = FileSha256Hex(Options.OutputPath).value_or(std::string());
  Result.Ok = true;
  return Result;
}

}
