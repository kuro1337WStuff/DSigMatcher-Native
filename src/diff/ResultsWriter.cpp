// L0 STUB of lane L4 (results writer). L4 replaces this file with the full port of save_results
// (D:2374-2429) and CChooser.add_item's formatting (D:275-296); spec: 01 §10.2-§11, 09.
//
// The stub already writes Diaphora's exact DDL and the config row, so a stubbed pipeline produces a
// valid, empty .diaphora (G0). Writing result rows and the format helpers are L4's.

#include "dsigmatcher/diff/ResultsWriter.h"

#include <sqlite3.h>

#include <cstdio>
#include <ctime>
#include <filesystem>

#include "dsigmatcher/diff/Config.h"
#include "dsigmatcher/diff/Errors.h"

namespace DSig::Diff {

namespace {

void Exec(sqlite3* Db, const char* Sql) {
  char* Error = nullptr;
  if (sqlite3_exec(Db, Sql, nullptr, nullptr, &Error) != SQLITE_OK) {
    const std::string Message = Error != nullptr ? Error : sqlite3_errmsg(Db);
    sqlite3_free(Error);
    throw IoFailure(std::string("results database: ") + Message);
  }
}

}

void WriteDiaphoraResults(const WriteArgs& A, const FinalResults& R, const Interners&) {
  const bool HasRows = !R.Best.empty() || !R.Partial.empty() || !R.Unreliable.empty() || !R.Multimatch.empty() ||
                       (R.UnmatchedPrimary && !R.UnmatchedPrimary->empty()) ||
                       (R.UnmatchedSecondary && !R.UnmatchedSecondary->empty());
  if (HasRows) {
    throw StageNotImplemented("WriteDiaphoraResults rows (L4)");
  }

  // D:2379-2381: remove an existing output first.
  std::error_code Error;
  std::filesystem::remove(std::filesystem::path(A.OutPath), Error);

  sqlite3* Db = nullptr;
  if (sqlite3_open_v2(A.OutPath.c_str(), &Db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) != SQLITE_OK) {
    const std::string Message = Db != nullptr ? sqlite3_errmsg(Db) : "out of memory";
    if (Db != nullptr) {
      sqlite3_close(Db);
    }
    throw IoFailure("cannot create '" + A.OutPath + "': " + Message);
  }
  try {
    // D:2387-2403, statement texts verbatim (they are stored in sqlite_master.sql).
    Exec(Db, "create table config (main_db text, diff_db text, version text, date text)");
    Exec(Db, "begin");
    sqlite3_stmt* Insert = nullptr;
    if (sqlite3_prepare_v2(Db, "insert into config values (?, ?, ?, ?)", -1, &Insert, nullptr) != SQLITE_OK) {
      throw IoFailure(std::string("results database: ") + sqlite3_errmsg(Db));
    }
    const std::string Date = A.Date.empty() ? AscTimeNow() : A.Date;
    sqlite3_bind_text(Insert, 1, A.MainDb.data(), static_cast<int>(A.MainDb.size()), SQLITE_TRANSIENT);
    sqlite3_bind_text(Insert, 2, A.DiffDb.data(), static_cast<int>(A.DiffDb.size()), SQLITE_TRANSIENT);
    sqlite3_bind_text(Insert, 3, kVersionValue.data(), static_cast<int>(kVersionValue.size()), SQLITE_TRANSIENT);
    sqlite3_bind_text(Insert, 4, Date.data(), static_cast<int>(Date.size()), SQLITE_TRANSIENT);
    const int Code = sqlite3_step(Insert);
    sqlite3_finalize(Insert);
    if (Code != SQLITE_DONE) {
      throw IoFailure(std::string("results database: ") + sqlite3_errmsg(Db));
    }
    Exec(Db,
         "create table results (type, line, address, name, address2, name2,\n"
         "                   ratio, nodes1, nodes2, description)");
    Exec(Db, "create unique index uq_results on results(address, address2)");
    Exec(Db, "create table unmatched (type, line, address, name)");
    Exec(Db, "commit");
  } catch (...) {
    sqlite3_close(Db);
    throw;
  }
  sqlite3_close(Db);
}

std::string FormatLine05(uint64_t) { throw StageNotImplemented("FormatLine05 (L4)"); }

std::string FormatAddr08x(std::string_view) { throw StageNotImplemented("FormatAddr08x (L4)"); }

std::string FormatRatio7(double) { throw StageNotImplemented("FormatRatio7 (L4)"); }

std::string AscTimeNow() {
  // time.asctime(): "%s %s%3d %.2d:%.2d:%.2d %d" over localtime (Modules/timemodule.c _asctime)
  static const char* const Days[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
  static const char* const Months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                       "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
  const std::time_t Now = std::time(nullptr);
  std::tm Local{};
#ifdef _WIN32
  localtime_s(&Local, &Now);
#else
  localtime_r(&Now, &Local);
#endif
  char Buffer[64];
  std::snprintf(Buffer, sizeof(Buffer), "%s %s%3d %.2d:%.2d:%.2d %d", Days[Local.tm_wday % 7],
                Months[Local.tm_mon % 12], Local.tm_mday, Local.tm_hour, Local.tm_min, Local.tm_sec,
                Local.tm_year + 1900);
  return Buffer;
}

}
