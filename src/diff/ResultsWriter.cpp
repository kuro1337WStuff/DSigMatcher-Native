// The `.diaphora` results file: a literal port of CBinDiff.save_results (D:2374-2429) plus
// the formatting CChooser.add_item applies to every chooser item (D:275-296). Spec: 01 §10.2-§11,
// 09 "Results database (.diaphora) schema", 02 §16, 06 §16.
//
// D: = diaphora.py, C: = diaphora_config.py (Diaphora 3.4.2-4-g621ec26).

#include "dsigmatcher/diff/ResultsWriter.h"

#include <sqlite3.h>

#include <charconv>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>
#include <version>

#include "FileIo.h"
#include "ResultsWriterDetail.h"
#include "dsigmatcher/diff/Config.h"
#include "dsigmatcher/diff/Database.h"
#include "dsigmatcher/diff/Errors.h"

#ifdef _WIN32
#include <process.h>
#else
#include <unistd.h>
#endif

// Floating-point std::to_chars (P0067R5) where the standard library has it (MSVC STL, libstdc++ 11+);
// the exact big-integer formatter otherwise (for example libc++ builds that do not define the macro).
// Never on Apple platforms: Apple's libc++ marks the floating-point overloads unavailable before
// macOS 13.3, so a build for an older deployment target must not reference them even where the
// feature macro is defined.
#if defined(__cpp_lib_to_chars) && __cpp_lib_to_chars >= 201611L && !defined(__APPLE__)
#define DSIG_WRITER_HAVE_FP_TO_CHARS 1
#else
#define DSIG_WRITER_HAVE_FP_TO_CHARS 0
#endif

namespace DSig::Diff {

namespace {

// ---------------------------------------------------------------------------------------------
// A small unsigned big integer (little-endian 32-bit limbs) for the exact formatters. Values stay
// below 2^1100: a double's significand times 10^7 shifted by at most 971 bits, or an address text.

class BigNat {
public:
  static BigNat FromU64(uint64_t Value) {
    BigNat N;
    while (Value != 0) {
      N.Limbs_.push_back(static_cast<uint32_t>(Value & 0xFFFFFFFFu));
      Value >>= 32;
    }
    return N;
  }

  bool IsZero() const { return Limbs_.empty(); }

  // *this = *this * Mul + Add
  void MulAdd(uint32_t Mul, uint32_t Add) {
    uint64_t Carry = Add;
    for (uint32_t& Limb : Limbs_) {
      const uint64_t Product = static_cast<uint64_t>(Limb) * Mul + Carry;
      Limb = static_cast<uint32_t>(Product & 0xFFFFFFFFu);
      Carry = Product >> 32;
    }
    if (Carry != 0) {
      Limbs_.push_back(static_cast<uint32_t>(Carry));
    }
    Trim();
  }

  void ShiftLeft(unsigned Bits) {
    if (IsZero() || Bits == 0) {
      return;
    }
    const size_t Words = Bits / 32;
    const unsigned Rest = Bits % 32;
    std::vector<uint32_t> Out(Words, 0u);
    uint32_t Carry = 0;
    for (const uint32_t Limb : Limbs_) {
      if (Rest == 0) {
        Out.push_back(Limb);
      } else {
        Out.push_back((Limb << Rest) | Carry);
        Carry = Limb >> (32 - Rest);
      }
    }
    if (Carry != 0) {
      Out.push_back(Carry);
    }
    Limbs_ = std::move(Out);
    Trim();
  }

  void ShiftRight(unsigned Bits) {
    const size_t Words = Bits / 32;
    const unsigned Rest = Bits % 32;
    if (Words >= Limbs_.size()) {
      Limbs_.clear();
      return;
    }
    std::vector<uint32_t> Out(Limbs_.begin() + static_cast<std::ptrdiff_t>(Words), Limbs_.end());
    if (Rest != 0) {
      for (size_t I = 0; I < Out.size(); ++I) {
        const uint32_t High = I + 1 < Out.size() ? Out[I + 1] : 0u;
        Out[I] = (Out[I] >> Rest) | (High << (32 - Rest));
      }
    }
    Limbs_ = std::move(Out);
    Trim();
  }

  bool Bit(unsigned Index) const {
    const size_t Word = Index / 32;
    return Word < Limbs_.size() && ((Limbs_[Word] >> (Index % 32)) & 1u) != 0;
  }

  // Any bit strictly below Index set.
  bool AnyBelow(unsigned Index) const {
    const size_t Word = Index / 32;
    for (size_t I = 0; I < Word && I < Limbs_.size(); ++I) {
      if (Limbs_[I] != 0) {
        return true;
      }
    }
    if (Word < Limbs_.size() && Index % 32 != 0) {
      const uint32_t Mask = (1u << (Index % 32)) - 1u;
      return (Limbs_[Word] & Mask) != 0;
    }
    return false;
  }

  // In place division by a small divisor; returns the remainder.
  uint32_t DivSmall(uint32_t Divisor) {
    uint64_t Remainder = 0;
    for (size_t I = Limbs_.size(); I-- > 0;) {
      const uint64_t Current = (Remainder << 32) | Limbs_[I];
      Limbs_[I] = static_cast<uint32_t>(Current / Divisor);
      Remainder = Current % Divisor;
    }
    Trim();
    return static_cast<uint32_t>(Remainder);
  }

  std::string ToDecimal() const {
    if (IsZero()) {
      return "0";
    }
    BigNat Work = *this;
    std::vector<uint32_t> Chunks;  // base 10^9, least significant first
    while (!Work.IsZero()) {
      Chunks.push_back(Work.DivSmall(1000000000u));
    }
    std::string Out = std::to_string(Chunks.back());
    for (size_t I = Chunks.size() - 1; I-- > 0;) {
      const std::string Part = std::to_string(Chunks[I]);
      Out.append(9 - Part.size(), '0');
      Out += Part;
    }
    return Out;
  }

  std::string ToHex() const {
    if (IsZero()) {
      return "0";
    }
    static const char Hex[] = "0123456789abcdef";
    std::string Out;
    for (size_t I = Limbs_.size(); I-- > 0;) {
      for (int Nibble = 7; Nibble >= 0; --Nibble) {
        const unsigned Value = (Limbs_[I] >> (Nibble * 4)) & 0xFu;
        if (Out.empty() && Value == 0) {
          continue;
        }
        Out.push_back(Hex[Value]);
      }
    }
    return Out;
  }

private:
  void Trim() {
    while (!Limbs_.empty() && Limbs_.back() == 0) {
      Limbs_.pop_back();
    }
  }

  std::vector<uint32_t> Limbs_;
};

// ---------------------------------------------------------------------------------------------
// Formatted rows (CChooser.add_item, D:275-296): a list of strings; the names stay raw (str or None).

struct ResultsRowText {
  const char* Type = "";
  std::string Line, Address, Address2, Ratio, Nodes1, Nodes2;
  std::optional<std::string_view> Name, Name2;
  std::string_view Description;
};

struct UnmatchedRowText {
  const char* Type = "";
  std::string Line, Address;
  std::optional<std::string_view> Name;
};

// "%08x" % int(item.ea) (D:280, D:286, D:288). Python None -> TypeError.
std::string FormatEa(const Interners& Ids, AddrId Ea, const char* Site) {
  if (Ea == kNoneAddr) {
    throw DiaphoraWouldRaise(Site, "TypeError: int() argument must be a string, a bytes-like object or a real "
                                   "number, not 'NoneType'");
  }
  try {
    return FormatAddr08x(Ids.AddrText(Ea));
  } catch (DiaphoraWouldRaise& Error) {
    throw DiaphoraWouldRaise(Site, Error.Detail);
  }
}

void FormatChooser(const Interners& Ids, const char* Type, const std::vector<Item>& Items,
                   std::vector<ResultsRowText>& Out) {
  uint64_t N = 0;  // CChooser.n starts at 0 (D:257) and counts every add_item (D:296)
  for (const Item& It : Items) {
    ResultsRowText Row;
    Row.Type = Type;  // item_list.insert(0, category) (D:2422-2423)
    Row.Line = FormatLine05(N);                                                          // D:285
    Row.Address = FormatEa(Ids, It.Ea1, "D:286 \"%08x\" % int(item.ea)");                // D:286
    Row.Name = Ids.NameOrNone(It.Name1);                                                 // D:287
    Row.Address2 = FormatEa(Ids, It.Ea2, "D:288 \"%08x\" % int(item.ea2)");              // D:288
    Row.Name2 = Ids.NameOrNone(It.Name2);                                                // D:289
    Row.Ratio = FormatRatio7(It.Ratio);  // D:282, D:290: "%." + DECIMAL_VALUES (C:120 "7f")
    Row.Nodes1 = std::to_string(It.Nodes1);                                              // D:291 "%d"
    Row.Nodes2 = std::to_string(It.Nodes2);                                              // D:292 "%d"
    Row.Description = Ids.DescText(It.Desc);                                             // D:293
    Out.push_back(std::move(Row));
    ++N;
  }
}

void FormatUnmatched(const Interners& Ids, const char* Type, const std::optional<std::vector<UnmatchedRow>>& Rows,
                     std::vector<UnmatchedRowText>& Out) {
  if (!Rows) {
    return;  // `if chooser is not None` (D:2420): a chooser find_unmatched never created writes nothing
  }
  uint64_t N = 0;
  for (const UnmatchedRow& In : *Rows) {
    UnmatchedRowText Row;
    Row.Type = Type;
    Row.Line = FormatLine05(N);                                          // D:280 "%05lu" % self.n
    Row.Address = FormatEa(Ids, In.Ea, "D:280 \"%08x\" % int(item.ea)");  // D:280
    Row.Name = Ids.NameOrNone(In.Name);                                  // D:280 item.vfname
    Out.push_back(std::move(Row));
    ++N;
  }
}

// ---------------------------------------------------------------------------------------------
// SQLite helpers

class Connection {
public:
  explicit Connection(const std::string& Path) {
    // sqlite3.connect(filename) (D:340-349, D:2383): SQLite takes the UTF-8 file name as is. A name
    // starting with "file:" is not a URI for Python (uri=False), so it is made a plain relative name,
    // as DiffDatabase does. ":memory:" is an in-memory database for Python too.
    std::string Name = Path;
    if (Name.rfind("file:", 0) == 0) {
      Name = "./" + Name;
    }
    EnsureSqliteInitialized();  // audit F31: a SQLITE_OMIT_AUTOINIT build crashes on open otherwise
    if (sqlite3_open_v2(Name.c_str(), &Db_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) != SQLITE_OK) {
      const std::string Message = Db_ != nullptr ? sqlite3_errmsg(Db_) : "out of memory";
      if (Db_ != nullptr) {
        sqlite3_close(Db_);
        Db_ = nullptr;
      }
      throw IoFailure("cannot create '" + Path + "': " + Message);
    }
  }
  ~Connection() {
    if (Db_ != nullptr) {
      sqlite3_close(Db_);
    }
  }
  Connection(const Connection&) = delete;
  Connection& operator=(const Connection&) = delete;

  void Exec(const char* Sql) {
    char* Error = nullptr;
    if (sqlite3_exec(Db_, Sql, nullptr, nullptr, &Error) != SQLITE_OK) {
      const std::string Message = Error != nullptr ? Error : sqlite3_errmsg(Db_);
      sqlite3_free(Error);
      throw IoFailure(std::string("results database: ") + Message);
    }
  }

  sqlite3_stmt* Prepare(const char* Sql) {
    sqlite3_stmt* Stmt = nullptr;
    if (sqlite3_prepare_v2(Db_, Sql, -1, &Stmt, nullptr) != SQLITE_OK) {
      throw IoFailure(std::string("results database: ") + sqlite3_errmsg(Db_));
    }
    return Stmt;
  }

  void Close() {
    if (Db_ != nullptr && sqlite3_close(Db_) != SQLITE_OK) {
      const std::string Message = sqlite3_errmsg(Db_);
      sqlite3_close_v2(Db_);
      Db_ = nullptr;
      throw IoFailure("results database: " + Message);
    }
    Db_ = nullptr;
  }

  sqlite3* Handle() const { return Db_; }

private:
  sqlite3* Db_ = nullptr;
};

class Stmt {
public:
  Stmt(Connection& C, const char* Sql) : C_(C), S_(C.Prepare(Sql)) {}
  ~Stmt() { sqlite3_finalize(S_); }
  Stmt(const Stmt&) = delete;
  Stmt& operator=(const Stmt&) = delete;

  // Python binds str as TEXT and None as NULL (08 §1.2); every chooser field is one of the two.
  void Bind(int Index, std::optional<std::string_view> Value) {
    const int Code = Value ? sqlite3_bind_text(S_, Index, Value->data(), static_cast<int>(Value->size()),
                                               SQLITE_TRANSIENT)
                           : sqlite3_bind_null(S_, Index);
    if (Code != SQLITE_OK) {
      throw IoFailure(std::string("results database: ") + sqlite3_errmsg(C_.Handle()));
    }
  }

  void Run() {
    const int Code = sqlite3_step(S_);
    if (Code != SQLITE_DONE) {
      throw IoFailure(std::string("results database: ") + sqlite3_errmsg(C_.Handle()));
    }
    sqlite3_reset(S_);
    sqlite3_clear_bindings(S_);
  }

private:
  Connection& C_;
  sqlite3_stmt* S_;
};

}  // namespace

namespace {

Detail::WriterFaultHook g_WriterFaultHook = nullptr;

void WriterStep(std::string_view Step) {
  if (g_WriterFaultHook != nullptr) {
    g_WriterFaultHook(Step);
  }
}

// "<out>.tmp-<pid>": the name the results file is written under before the rename (audit F26).
std::string TemporaryResultsPath(const std::string& Out) {
#ifdef _WIN32
  const long long Pid = _getpid();
#else
  const long long Pid = static_cast<long long>(getpid());
#endif
  return Out + ".tmp-" + std::to_string(Pid);
}

void RemoveIfPresent(const std::string& Utf8Path) {
  const std::filesystem::path Path = Detail::PathFromUtf8(Utf8Path);
  std::error_code Error;
  if (!std::filesystem::exists(Path, Error)) {
    return;
  }
  std::filesystem::remove(Path, Error);
  if (Error) {
    throw IoFailure("cannot remove '" + Utf8Path + "': " + Error.message());
  }
}

void RemoveDatabaseSidecars(const std::string& Utf8Path) {
  for (const char* Suffix : {"-journal", "-wal", "-shm"}) {
    RemoveIfPresent(Utf8Path + Suffix);
  }
}

void RemoveDatabaseFiles(const std::string& Utf8Path) {
  RemoveIfPresent(Utf8Path);
  RemoveDatabaseSidecars(Utf8Path);
}

}  // namespace

std::vector<std::string> ResultsWriterScratchPaths(const std::string& Out) {
  const std::string Temporary = TemporaryResultsPath(Out);
  return {Temporary, Temporary + "-journal", Temporary + "-wal", Temporary + "-shm"};
}

// ---------------------------------------------------------------------------------------------
// save_results (D:2374-2429)

void WriteDiaphoraResults(const WriteArgs& A, const FinalResults& R, const Interners& Ids) {
  // CChooser.add_item formats every item when final_pass / find_unmatched add it (D:275-296), inside
  // diff() and so before save_results runs. A formatting error (int() of a non-decimal ea) therefore
  // raises before D:2379 removes the old output: a pre-existing file stays untouched (01 §11.2, V9).
  // So every row is formatted before the file is touched.
  std::vector<ResultsRowText> Results;
  Results.reserve(R.Best.size() + R.Partial.size() + R.Unreliable.size() + R.Multimatch.size());
  // d = {"best", "partial", "unreliable", "multimatch", ...} in this order (D:2409-2416).
  FormatChooser(Ids, "best", R.Best, Results);
  FormatChooser(Ids, "partial", R.Partial, Results);
  FormatChooser(Ids, "unreliable", R.Unreliable, Results);
  FormatChooser(Ids, "multimatch", R.Multimatch, Results);
  std::vector<UnmatchedRowText> Unmatched;
  // "primary" is self.unmatched_primary (diff-DB functions), "secondary" self.unmatched_second (main-DB
  // functions): the labels are swapped relative to the chooser titles (D:2334-2354, D:2414-2415).
  FormatUnmatched(Ids, "primary", R.UnmatchedPrimary, Unmatched);
  FormatUnmatched(Ids, "secondary", R.UnmatchedSecondary, Unmatched);

  // D:2379-2381: `if os.path.exists(filename): os.remove(filename)`. os.remove refuses a directory.
  // The file is written under a temporary name in the same directory and renamed over <out> only after
  // the commit (audit F26): the bytes are the ones save_results writes, but a failure or a kill while
  // writing never leaves a half-written file at <out>, and an existing <out> is left untouched until the
  // new one is complete (the state Diaphora leaves when it raises before D:2379, 01 §11.2, V9).
  const bool InMemory = A.OutPath == ":memory:";
  std::string Target = A.OutPath;
  if (!InMemory) {
    const std::filesystem::path Out = Detail::PathFromUtf8(A.OutPath);
    std::error_code Error;
    const auto Status = std::filesystem::status(Out, Error);
    if (!Error && std::filesystem::is_directory(Status)) {
      throw IoFailure("cannot remove '" + A.OutPath + "': it is a directory");
    }
    Target = TemporaryResultsPath(A.OutPath);
    RemoveDatabaseFiles(Target);  // a leftover of a killed run that had the same process id
  }
  try {
    WriterStep("open");
    // D:2383 results_db = sqlite3_connect(filename): default journal mode (delete), no pragmas.
    Connection Db(Target);
    // D:2387-2388, autocommit (Python's sqlite3 opens no transaction before DDL).
    Db.Exec("create table config (main_db text, diff_db text, version text, date text)");
    // D:2390-2393: the INSERT opens the implicit transaction (legacy isolation_level ""); the three
    // DDL statements below run inside it and everything commits when the `with results_db:` block ends
    // (D:2405). 01 §11.2: the transaction boundary only matters for crash behaviour.
    Db.Exec("begin");
    {
      Stmt Insert(Db, "insert into config values (?, ?, ?, ?)");
      const std::string Date = A.Date.empty() ? AscTimeNow() : A.Date;
      // (self.db_name, self.last_diff_db, VERSION_VALUE, time.asctime()) (D:2392): db1 and db2 exactly
      // as passed on the command line, VERSION_VALUE = "3.4" (D:100).
      Insert.Bind(1, std::string_view(A.MainDb));
      Insert.Bind(2, std::string_view(A.DiffDb));
      Insert.Bind(3, kVersionValue);
      Insert.Bind(4, std::string_view(Date));
      Insert.Run();
    }
    WriterStep("config");
    // D:2395-2403, statement texts verbatim: sqlite_master.sql keeps them (the results DDL has a newline
    // and 19 spaces of indentation).
    Db.Exec("create table results (type, line, address, name, address2, name2,\n"
            "                   ratio, nodes1, nodes2, description)");
    Db.Exec("create unique index uq_results on results(address, address2)");
    Db.Exec("create table unmatched (type, line, address, name)");
    {
      // D:2406: `insert or ignore` + uq_results(address, address2) keeps the first row per formatted
      // address pair in write order; the dropped row's line number stays consumed (01 E4, 02 probe 9 A).
      Stmt Insert(Db, "insert or ignore into results values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
      for (const ResultsRowText& Row : Results) {
        Insert.Bind(1, std::string_view(Row.Type));
        Insert.Bind(2, std::string_view(Row.Line));
        Insert.Bind(3, std::string_view(Row.Address));
        Insert.Bind(4, Row.Name);
        Insert.Bind(5, std::string_view(Row.Address2));
        Insert.Bind(6, Row.Name2);
        Insert.Bind(7, std::string_view(Row.Ratio));
        Insert.Bind(8, std::string_view(Row.Nodes1));
        Insert.Bind(9, std::string_view(Row.Nodes2));
        Insert.Bind(10, Row.Description);
        Insert.Run();
      }
    }
    WriterStep("results");
    {
      Stmt Insert(Db, "insert into unmatched values (?, ?, ?, ?)");  // D:2407, no uniqueness
      for (const UnmatchedRowText& Row : Unmatched) {
        Insert.Bind(1, std::string_view(Row.Type));
        Insert.Bind(2, std::string_view(Row.Line));
        Insert.Bind(3, std::string_view(Row.Address));
        Insert.Bind(4, Row.Name);
        Insert.Run();
      }
    }
    WriterStep("unmatched");
    Db.Exec("commit");
    Db.Close();
    WriterStep("committed");
    if (!InMemory) {
      // A -journal / -wal / -shm left beside <out> by an earlier writer belongs to the file being
      // replaced; SQLite would take a hot journal for the new file's and roll it back into it.
      RemoveDatabaseSidecars(A.OutPath);
      Detail::RenameReplacing(Target, A.OutPath);
    }
  } catch (...) {
    if (!InMemory) {
      try {
        RemoveDatabaseFiles(Target);  // never leave the partial temporary file behind
      } catch (const std::exception&) {
        // the original error is the one reported
      }
    }
    throw;
  }
}

// ---------------------------------------------------------------------------------------------
// Formatting (CChooser.add_item, D:275-296)

std::string FormatLine05(uint64_t N) {
  // "%05lu" % self.n (D:280, D:285): at least five digits, zero padded; Python ignores the 'l'.
  std::string Digits = std::to_string(N);
  if (Digits.size() < 5) {
    Digits.insert(0, 5 - Digits.size(), '0');
  }
  return Digits;
}

std::string FormatAddr08x(std::string_view Ea) {
  // "%08x" % int(item.ea) (D:280, D:286, D:288). item.ea is the functions.address TEXT (a str).
  bool Negative = false;
  std::string Digits;
  if (!Detail::PyIntParse(Ea, Negative, Digits)) {
    throw DiaphoraWouldRaise("\"%08x\" % int(ea)",
                             "ValueError: invalid literal for int() with base 10: '" + std::string(Ea) + "'");
  }
  // D:96-97 sys.set_int_max_str_digits(0): no digit-count limit applies to int(str).
  BigNat Value;
  for (const char Ch : Digits) {
    Value.MulAdd(10u, static_cast<uint32_t>(Ch - '0'));
  }
  std::string Hex = Value.ToHex();
  if (Value.IsZero()) {
    Negative = false;  // int("-0") == 0
  }
  // The '0' flag pads after the sign to a total width of 8: "%08x" % -1 == "-0000001" (01 §10.2).
  const size_t Width = Negative ? 7 : 8;
  if (Hex.size() < Width) {
    Hex.insert(0, Width - Hex.size(), '0');
  }
  return Negative ? "-" + Hex : Hex;
}

std::string FormatRatio7(double Ratio) {
  // "%.7f" % item.ratio (D:282, D:290; DECIMAL_VALUES = "7f", C:120): correctly rounded, ties to
  // even on the exact binary value (01 §10.2, 03a §5). Python spells every NaN "nan", whatever its
  // sign bit, and the infinities "inf" / "-inf"; std::to_chars could print "-nan(ind)".
  if (std::isnan(Ratio)) {
    return "nan";
  }
  if (std::isinf(Ratio)) {
    return Ratio < 0 ? "-inf" : "inf";
  }
#if DSIG_WRITER_HAVE_FP_TO_CHARS
  char Buffer[400];  // DBL_MAX has 309 integer digits; plus sign, point and 7 decimals
  const std::to_chars_result Done =
      std::to_chars(Buffer, Buffer + sizeof(Buffer), Ratio, std::chars_format::fixed, 7);
  if (Done.ec == std::errc()) {
    return std::string(Buffer, Done.ptr);
  }
#endif
  return Detail::FormatRatio7Exact(Ratio);
}

std::string AscTimeNow() {
  // time.asctime() (D:2392) = _asctime(localtime()): "%s %s%3d %.2d:%.2d:%.2d %d"
  // (CPython Modules/timemodule.c), so the day of the month is space padded: "Wed Sep  3 ...".
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
  const auto Two = [](int Value) {
    std::string Text = std::to_string(Value);
    return Text.size() < 2 ? "0" + Text : Text;
  };
  std::string Day = std::to_string(Local.tm_mday);
  if (Day.size() < 3) {
    Day.insert(0, 3 - Day.size(), ' ');  // "%3d"
  }
  return std::string(Days[((Local.tm_wday % 7) + 7) % 7]) + " " + Months[((Local.tm_mon % 12) + 12) % 12] + Day +
         " " + Two(Local.tm_hour) + ":" + Two(Local.tm_min) + ":" + Two(Local.tm_sec) + " " +
         std::to_string(Local.tm_year + 1900);
}

// ---------------------------------------------------------------------------------------------
// Detail (ResultsWriterDetail.h)

namespace Detail {

void SetWriterFaultHook(WriterFaultHook Hook) { g_WriterFaultHook = Hook; }

std::string FormatRatio7Exact(double Value) { return FormatFixedExact(Value, 7); }

std::string FormatFixedExact(double Value, int Decimals) {
  if (Decimals < 1 || Decimals > 9) {
    throw std::invalid_argument("FormatFixedExact: decimals must be 1..9");
  }
  if (std::isnan(Value)) {
    return "nan";
  }
  const bool Negative = std::signbit(Value);
  if (std::isinf(Value)) {
    return Negative ? "-inf" : "inf";
  }
  const double Magnitude = Negative ? -Value : Value;
  uint64_t Bits = 0;
  std::memcpy(&Bits, &Magnitude, sizeof(Bits));
  const unsigned Biased = static_cast<unsigned>((Bits >> 52) & 0x7FFu);
  uint64_t Mantissa = Bits & ((uint64_t{1} << 52) - 1u);
  int Exp2 = -1074;  // value = Mantissa * 2^Exp2
  if (Biased != 0) {
    Mantissa |= uint64_t{1} << 52;
    Exp2 = static_cast<int>(Biased) - 1075;
  }
  uint32_t Scale = 1;
  for (int Index = 0; Index < Decimals; ++Index) {
    Scale *= 10u;
  }
  const size_t Places = static_cast<size_t>(Decimals);
  BigNat N = BigNat::FromU64(Mantissa);
  N.MulAdd(Scale, 0u);  // value * 10^Decimals = N * 2^Exp2
  if (Exp2 >= 0) {
    N.ShiftLeft(static_cast<unsigned>(Exp2));
  } else {
    // Round half to even on the exact quotient N / 2^Shift (the 03a §5 algorithm, any shift).
    const unsigned Shift = static_cast<unsigned>(-Exp2);
    const bool HalfBit = N.Bit(Shift - 1);
    const bool Below = N.AnyBelow(Shift - 1);
    N.ShiftRight(Shift);
    if (HalfBit && (Below || N.Bit(0))) {
      N.MulAdd(1u, 1u);
    }
  }
  std::string Digits = N.ToDecimal();
  if (Digits.size() < Places + 1) {
    Digits.insert(0, Places + 1 - Digits.size(), '0');
  }
  Digits.insert(Digits.size() - Places, 1, '.');
  return Negative ? "-" + Digits : Digits;  // Python keeps the sign of -0.0 and of negatives that round to 0
}

bool FormatRatio7UsesToChars() { return DSIG_WRITER_HAVE_FP_TO_CHARS != 0; }

bool PyIntParse(std::string_view Text, bool& Negative, std::string& Digits) {
  for (const char Ch : Text) {
    if (static_cast<unsigned char>(Ch) >= 0x80) {
      // _PyUnicode_TransformDecimalAndSpaceToASCII maps Unicode decimal digits and Unicode whitespace
      // before PyLong_FromString runs; that table is not ported (real exports store ASCII decimals).
      throw UnsupportedInput("int(): non-ASCII address text is not ported (Unicode digit/space mapping)");
    }
  }
  // Py_ISSPACE on ASCII: \t \n \v \f \r and space (0x1c-0x1f are not stripped by int()).
  const auto Space = [](char Ch) {
    return Ch == ' ' || Ch == '\t' || Ch == '\n' || Ch == '\v' || Ch == '\f' || Ch == '\r';
  };
  size_t Begin = 0;
  size_t End = Text.size();
  while (Begin < End && Space(Text[Begin])) {
    ++Begin;
  }
  while (End > Begin && Space(Text[End - 1])) {
    --End;
  }
  Negative = false;
  if (Begin < End && (Text[Begin] == '+' || Text[Begin] == '-')) {
    Negative = Text[Begin] == '-';
    ++Begin;
  }
  Digits.clear();
  const auto IsDigit = [](char Ch) { return Ch >= '0' && Ch <= '9'; };
  for (size_t I = Begin; I < End; ++I) {
    const char Ch = Text[I];
    if (IsDigit(Ch)) {
      Digits.push_back(Ch);
    } else if (Ch == '_' && I > Begin && IsDigit(Text[I - 1]) && I + 1 < End && IsDigit(Text[I + 1])) {
      continue;  // a single '_' between two digits
    } else {
      return false;
    }
  }
  if (Digits.empty()) {
    return false;
  }
  const size_t First = Digits.find_first_not_of('0');
  Digits = First == std::string::npos ? std::string("0") : Digits.substr(First);
  return true;
}

}  // namespace Detail

}  // namespace DSig::Diff
