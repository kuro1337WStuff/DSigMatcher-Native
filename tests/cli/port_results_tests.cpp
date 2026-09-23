// cli_port_results: `port --results` (docs/parity/00-plan.md §7.1 D6, §7.2 L11).
//
// Synthetic fixtures (built at run time, nothing committed but this file) cover the decision rules,
// the output schema, provenance across two hops, path safety, bad inputs and WAL handling. The corpus
// part ports Diaphora's own run1 results of every finished oracle pair and checks invariants only;
// it skips when DSIG_CORPUS_ROOT or an export is absent.

#include <sqlite3.h>

#include <cctype>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "diff/CorpusPaths.h"
#include "diff/TestHarness.h"
#include "dsigmatcher/Provenance.h"
#include "dsigmatcher/Sha256.h"
#include "dsigmatcher/cli/Commands.h"

namespace {

using namespace DSig;
using DSig::Test::ScratchDir;

// ---------------------------------------------------------------------------------------------
// fixture builders

struct Fn {
  Fn(uint64_t EaValue, std::optional<std::string> NameValue, std::optional<std::string> MangledValue = std::nullopt)
      : Ea(EaValue), Name(std::move(NameValue)), Mangled(std::move(MangledValue)) {}
  uint64_t Ea = 0;
  std::optional<std::string> Name;
  std::optional<std::string> Mangled;  // defaults to Name
  int64_t Nodes = 3;
};

bool Exec(sqlite3* Db, const std::string& Sql) {
  char* Message = nullptr;
  const bool Ok = sqlite3_exec(Db, Sql.c_str(), nullptr, nullptr, &Message) == SQLITE_OK;
  if (!Ok) {
    std::printf("  sqlite: %s\n", Message != nullptr ? Message : "?");
  }
  sqlite3_free(Message);
  return Ok;
}

void RemoveDb(const std::string& Path) {
  std::error_code Error;
  for (const char* Suffix : {"", "-wal", "-shm", "-journal"}) {
    std::filesystem::remove(Path + Suffix, Error);
  }
}

// A reduced Diaphora export: the functions columns the port reads plus a few it must leave alone,
// Diaphora's name / mangled_function / address indices, program with a 16-byte BLOB md5sum (IDA 9.x,
// 08 §7.1), version '3.4', sqlite_stat1 from ANALYZE, and WAL mode like a real export (08 §2 item 4).
bool CreateExport(const std::string& Path, const std::vector<Fn>& Rows, unsigned char Md5Seed, bool Wal = true) {
  RemoveDb(Path);
  sqlite3* Db = nullptr;
  if (sqlite3_open_v2(Path.c_str(), &Db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) != SQLITE_OK) {
    sqlite3_close(Db);
    return false;
  }
  bool Ok = Exec(Db,
                 "create table functions (id integer primary key, name varchar(255), nodes integer, "
                 "prototype text, address text unique, comment text, mangled_function text, bytes_hash text, "
                 "pseudocode text, prototype2 text, md_index text);"
                 "create index idx_name on functions(name);"
                 "create index idx_mangled on functions(mangled_function);"
                 "create index idx_address on functions(address);"
                 "create table program (id integer primary key, callgraph_primes text, callgraph_all_primes text, "
                 "processor text, md5sum text);"
                 "create table version (value text);"
                 "insert into version values ('3.4');");
  sqlite3_stmt* Program = nullptr;
  Ok = Ok && sqlite3_prepare_v2(Db, "insert into program values (1, '2', '{\"2\": 1}', 'pc64', ?)", -1, &Program,
                                nullptr) == SQLITE_OK;
  if (Ok) {
    unsigned char Md5[16];
    for (int Index = 0; Index < 16; ++Index) {
      Md5[Index] = static_cast<unsigned char>(Md5Seed + Index * 17);
    }
    sqlite3_bind_blob(Program, 1, Md5, sizeof(Md5), SQLITE_TRANSIENT);
    Ok = sqlite3_step(Program) == SQLITE_DONE;
  }
  sqlite3_finalize(Program);
  sqlite3_stmt* Insert = nullptr;
  Ok = Ok && sqlite3_prepare_v2(Db,
                                "insert into functions (id, name, nodes, prototype, address, comment, "
                                "mangled_function, bytes_hash, pseudocode, prototype2, md_index) "
                                "values (?, ?, ?, ?, ?, '', ?, ?, ?, ?, '0.5')",
                                -1, &Insert, nullptr) == SQLITE_OK;
  int64_t Id = 1;
  for (const Fn& Row : Rows) {
    if (!Ok) {
      break;
    }
    const std::optional<std::string> Mangled = Row.Mangled ? Row.Mangled : Row.Name;
    const std::string Address = std::to_string(Row.Ea);
    const std::string Proto = "int __fastcall f_" + Address + "()";
    const std::string Hash = "hash-" + Address;
    sqlite3_bind_int64(Insert, 1, Id++);
    if (Row.Name) {
      sqlite3_bind_text(Insert, 2, Row.Name->c_str(), -1, SQLITE_TRANSIENT);
    } else {
      sqlite3_bind_null(Insert, 2);
    }
    sqlite3_bind_int64(Insert, 3, Row.Nodes);
    sqlite3_bind_text(Insert, 4, Proto.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(Insert, 5, Address.c_str(), -1, SQLITE_TRANSIENT);
    if (Mangled) {
      sqlite3_bind_text(Insert, 6, Mangled->c_str(), -1, SQLITE_TRANSIENT);
    } else {
      sqlite3_bind_null(Insert, 6);
    }
    sqlite3_bind_text(Insert, 7, Hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(Insert, 8, "call sub_1\nreturn 0;", -1, SQLITE_TRANSIENT);
    sqlite3_bind_null(Insert, 9);
    Ok = sqlite3_step(Insert) == SQLITE_DONE;
    sqlite3_reset(Insert);
  }
  sqlite3_finalize(Insert);
  Ok = Ok && Exec(Db, "analyze;");
  if (Ok && Wal) {
    Ok = Exec(Db, "pragma journal_mode = wal;");
  }
  sqlite3_close(Db);
  return Ok;
}

struct ResultRow {
  std::string Type;
  std::string Line;
  uint64_t Ea = 0;
  std::optional<std::string> Name;
  uint64_t Ea2 = 0;
  std::optional<std::string> Name2;
  std::string Ratio;
  std::string Description;
};

std::string Hex8(uint64_t Ea) {
  char Buffer[32];
  std::snprintf(Buffer, sizeof(Buffer), "%08llx", static_cast<unsigned long long>(Ea));
  return Buffer;
}

// Diaphora's save_results DDL, verbatim (D:2385-2403; 01 §11.1), every value bound as TEXT.
bool CreateResults(const std::string& Path, const std::vector<ResultRow>& Rows) {
  RemoveDb(Path);
  sqlite3* Db = nullptr;
  if (sqlite3_open_v2(Path.c_str(), &Db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) != SQLITE_OK) {
    sqlite3_close(Db);
    return false;
  }
  bool Ok = Exec(Db,
                 "create table config (main_db text, diff_db text, version text, date text);"
                 "insert into config values ('ref.sqlite', 'target.sqlite', '3.4', 'Wed Sep 23 03:41:47 2026');"
                 "create table results (type, line, address, name, address2, name2,\n"
                 "                   ratio, nodes1, nodes2, description);"
                 "create unique index uq_results on results(address, address2);"
                 "create table unmatched (type, line, address, name);");
  sqlite3_stmt* Insert = nullptr;
  Ok = Ok && sqlite3_prepare_v2(Db, "insert or ignore into results values (?, ?, ?, ?, ?, ?, ?, '3', '3', ?)", -1,
                                &Insert, nullptr) == SQLITE_OK;
  for (const ResultRow& Row : Rows) {
    if (!Ok) {
      break;
    }
    const std::string A = Hex8(Row.Ea);
    const std::string A2 = Hex8(Row.Ea2);
    sqlite3_bind_text(Insert, 1, Row.Type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(Insert, 2, Row.Line.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(Insert, 3, A.c_str(), -1, SQLITE_TRANSIENT);
    if (Row.Name) {
      sqlite3_bind_text(Insert, 4, Row.Name->c_str(), -1, SQLITE_TRANSIENT);
    } else {
      sqlite3_bind_null(Insert, 4);
    }
    sqlite3_bind_text(Insert, 5, A2.c_str(), -1, SQLITE_TRANSIENT);
    if (Row.Name2) {
      sqlite3_bind_text(Insert, 6, Row.Name2->c_str(), -1, SQLITE_TRANSIENT);
    } else {
      sqlite3_bind_null(Insert, 6);
    }
    sqlite3_bind_text(Insert, 7, Row.Ratio.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(Insert, 8, Row.Description.c_str(), -1, SQLITE_TRANSIENT);
    Ok = sqlite3_step(Insert) == SQLITE_DONE;
    sqlite3_reset(Insert);
  }
  sqlite3_finalize(Insert);
  sqlite3_close(Db);
  return Ok;
}

// ---------------------------------------------------------------------------------------------
// readers

sqlite3* OpenRo(const std::string& Path) {
  sqlite3* Db = nullptr;
  const std::string Uri = ReadOnlyDatabaseUri(Path);
  if (sqlite3_open_v2(Uri.c_str(), &Db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, nullptr) != SQLITE_OK) {
    sqlite3_close(Db);
    return nullptr;
  }
  return Db;
}

// Every row of a query as text cells ("<NULL>" for NULL).
std::vector<std::vector<std::string>> Query(const std::string& Path, const std::string& Sql) {
  std::vector<std::vector<std::string>> Rows;
  sqlite3* Db = OpenRo(Path);
  if (Db == nullptr) {
    return Rows;
  }
  sqlite3_stmt* Statement = nullptr;
  if (sqlite3_prepare_v2(Db, Sql.c_str(), -1, &Statement, nullptr) == SQLITE_OK) {
    while (sqlite3_step(Statement) == SQLITE_ROW) {
      std::vector<std::string> Row;
      for (int Column = 0; Column < sqlite3_column_count(Statement); ++Column) {
        const unsigned char* Text = sqlite3_column_text(Statement, Column);
        Row.push_back(sqlite3_column_type(Statement, Column) == SQLITE_NULL
                          ? std::string("<NULL>")
                          : std::string(reinterpret_cast<const char*>(Text),
                                        static_cast<size_t>(sqlite3_column_bytes(Statement, Column))));
      }
      Rows.push_back(std::move(Row));
    }
  } else {
    std::printf("  query failed: %s\n", sqlite3_errmsg(Db));
  }
  sqlite3_finalize(Statement);
  sqlite3_close(Db);
  return Rows;
}

std::string One(const std::string& Path, const std::string& Sql) {
  const auto Rows = Query(Path, Sql);
  return Rows.empty() || Rows[0].empty() ? std::string("<none>") : Rows[0][0];
}

std::string NameAt(const std::string& Path, uint64_t Ea) {
  return One(Path, "select name from functions where address = '" + std::to_string(Ea) + "'");
}
std::string MangledAt(const std::string& Path, uint64_t Ea) {
  return One(Path, "select mangled_function from functions where address = '" + std::to_string(Ea) + "'");
}

std::string FileSha(const std::string& Path) {
  bool Ok = false;
  const std::string Hash = Sha256::FileHex(Path, Ok);
  return Ok ? Hash : std::string("<unreadable>");
}

bool Exists(const std::string& Path) {
  std::error_code Error;
  return std::filesystem::exists(Path, Error);
}

// Every functions column except the two label columns, row by row, in id order.
std::string NonLabelFingerprint(const std::string& Path) {
  const auto Columns = Query(Path, "select name from pragma_table_info('functions') order by cid");
  std::string Select;
  for (const auto& Column : Columns) {
    if (Column[0] != "name" && Column[0] != "mangled_function") {
      Select += (Select.empty() ? "" : ", ") + std::string("quote(") + Column[0] + ")";
    }
  }
  Sha256 Digest;
  for (const auto& Row : Query(Path, "select " + Select + " from functions order by id")) {
    for (const std::string& Cell : Row) {
      Digest.Update(Cell);
      Digest.Update("\x1f");
    }
    Digest.Update("\x1e");
  }
  return Digest.FinishHex();
}

std::string SchemaOf(const std::string& Path, const std::string& Table) {
  return One(Path, "select sql from sqlite_master where name = '" + Table + "'");
}

bool WalHeader(const std::string& Path) {
  std::ifstream In(Path, std::ios::binary);
  char Header[20] = {};
  In.read(Header, sizeof(Header));
  return In.gcount() == 20 && Header[18] == 2 && Header[19] == 2;
}

Cli::PortFromResultsArgs Args(const std::string& Ref, const std::string& Target, const std::string& Out,
                              const std::string& Results) {
  Cli::PortFromResultsArgs A;
  A.Reference = Ref;
  A.Target = Target;
  A.Output = Out;
  A.Results = Results;
  return A;
}

std::string Report(const Cli::CommandOutcome& Outcome, const std::string& Prefix) {
  for (const std::string& Line : Outcome.Report) {
    if (Line.rfind(Prefix, 0) == 0) {
      return Line;
    }
  }
  return "<no line " + Prefix + ">";
}

// ---------------------------------------------------------------------------------------------
// the main synthetic scenario

constexpr uint64_t kRef = 0x180001000ull;
constexpr uint64_t kTgt = 0x180002000ull;
uint64_t R(int Index) { return kRef + static_cast<uint64_t>(Index) * 0x100; }
uint64_t T(int Index) { return kTgt + static_cast<uint64_t>(Index) * 0x100; }

std::vector<Fn> ReferenceRows() {
  return {
      {R(1), "Alpha", "?Alpha@@YAXXZ"}, {R(2), "Beta", {}},  {R(3), "Gamma", {}}, {R(4), "sub_180001400", {}},
      {R(5), "Delta", {}},              {R(6), "Epsilon", {}}, {R(7), "Zeta", {}},  {R(8), "Eta", {}},
      {R(9), "Theta", {}},              {R(10), "Iota", {}},
  };
}

std::vector<Fn> TargetRows() {
  std::vector<Fn> Rows;
  for (int Index = 1; Index <= 11; ++Index) {
    Rows.push_back({T(Index), "sub_" + Hex8(T(Index)), {}});
  }
  Rows[1].Name = "Beta";        // T2: already carries the reference's name
  Rows[4].Name = "ExportName";  // T5: a real target name
  Rows[10].Name = "Iota";       // T11: the name partial row A10 -> T10 would duplicate
  return Rows;
}

// Stored order of a real .diaphora: best, partial, unreliable, multimatch; descending ratio inside.
std::vector<ResultRow> ScenarioResults() {
  auto Sub = [](int Index) { return std::optional<std::string>("sub_" + Hex8(T(Index))); };
  return {
      {"best", "00000", R(2), "Beta", T(2), "Beta", "1.0000000", "100% equal"},
      {"best", "00001", R(1), "?Alpha@@YAXXZ", T(1), Sub(1), "1.0000000", "Bytes hash"},
      {"best", "00002", R(8), "Eta", T(9), Sub(9), "1.0000000", "Same cleaned assembly"},
      {"partial", "00000", R(5), "Delta", T(5), "ExportName", "0.9000000", "Mnemonics and names"},
      {"partial", "00001", R(3), "Gamma", T(3), Sub(3), "0.7500000", "Pseudo-code fuzzy hash"},
      {"partial", "00002", R(10), "Iota", T(10), Sub(10), "0.6000000", "Same constants"},
      {"partial", "00003", R(4), "sub_180001400", T(4), Sub(4), "0.5000000", "Loop count"},
      {"unreliable", "00000", R(7), "Zeta", T(8), Sub(8), "0.5000000", "Bytes sum"},
      {"multimatch", "00000", R(6), "Epsilon", T(6), Sub(6), "0.6000000", "Related compilation unit"},
      {"multimatch", "00001", R(6), "Epsilon", T(7), Sub(7), "0.6000000", "Related compilation unit"},
      {"multimatch", "00002", R(9), "Theta", T(9), Sub(9), "0.4000000", "Related compilation unit"},
  };
}

struct Scenario {
  std::string Dir, Ref, Target, Results;
  bool Ok = false;
};

Scenario MakeScenario(const std::string& Dir) {
  Scenario S;
  S.Dir = Dir;
  std::error_code Error;
  std::filesystem::create_directories(Dir, Error);
  S.Ref = (std::filesystem::path(Dir) / "ref.sqlite").string();
  S.Target = (std::filesystem::path(Dir) / "target.sqlite").string();
  S.Results = (std::filesystem::path(Dir) / "ref_vs_target.diaphora").string();
  S.Ok = CreateExport(S.Ref, ReferenceRows(), 0x10) && CreateExport(S.Target, TargetRows(), 0x20) &&
         CreateResults(S.Results, ScenarioResults());
  return S;
}

void TestHelpers() {
  DSig::Test::Suite("helpers: ParseDecimalAddress (Python int()), ReadOnlyDatabaseUri");
  CHECK(ParseDecimalAddress("4096") == std::optional<uint64_t>(4096));
  CHECK(ParseDecimalAddress(" 4096 \n") == std::optional<uint64_t>(4096));
  CHECK(ParseDecimalAddress("4_096") == std::optional<uint64_t>(4096));
  CHECK(ParseDecimalAddress("+7") == std::optional<uint64_t>(7));
  CHECK(ParseDecimalAddress("6442455056") == std::optional<uint64_t>(0x180001010ull));
  CHECK(ParseDecimalAddress("18446744073709551615") == std::optional<uint64_t>(UINT64_MAX));
  CHECK(!ParseDecimalAddress("18446744073709551616"));
  CHECK(!ParseDecimalAddress("-1"));
  CHECK(!ParseDecimalAddress("4__096"));
  CHECK(!ParseDecimalAddress("_4"));
  CHECK(!ParseDecimalAddress("4_"));
  CHECK(!ParseDecimalAddress("0x10"));
  CHECK(!ParseDecimalAddress(""));
  CHECK(!ParseDecimalAddress("  "));
  CHECK_TEXT_EQ(ReadOnlyDatabaseUri("no_such_dir/x%y?z#.sqlite"), "file:no_such_dir/x%25y%3fz%23.sqlite?mode=ro");
  CHECK_TEXT_EQ(LabelActionName(LabelAction::SkippedDuplicateName), "skipped_duplicate_name");
  CHECK_TEXT_EQ(LabelActionName(LabelAction::NotSelected), "not_selected");
}

void TestDefaultPort(const std::string& Dir) {
  DSig::Test::Suite("port --results: default categories (best + partial)");
  const Scenario S = MakeScenario(Dir);
  CHECK(S.Ok);
  const std::string Out = (std::filesystem::path(Dir) / "out.sqlite").string();
  const std::string RefSha = FileSha(S.Ref), TargetSha = FileSha(S.Target), ResultsSha = FileSha(S.Results);

  const Cli::CommandOutcome Outcome = Cli::RunPortFromResults(Args(S.Ref, S.Target, Out, S.Results));
  CHECK_NUM_EQ(Outcome.ExitCode, Cli::kExitOk);
  if (Outcome.ExitCode != Cli::kExitOk) {
    std::printf("  error: %s\n", Outcome.Message.c_str());
    return;
  }
  CHECK_TEXT_EQ(Report(Outcome, "results rows"),
                "results rows     : 11 (best 3, partial 4, unreliable 1, multimatch 3)");
  CHECK_TEXT_EQ(Report(Outcome, "selected"), "selected         : 7 (best, partial)");
  CHECK_TEXT_EQ(Report(Outcome, "names applied"),
                "names applied    : 3 (best 2, partial 1, unreliable 0, multimatch 0)");
  CHECK_TEXT_EQ(Report(Outcome, "names confirmed"), "names confirmed  : 1");
  CHECK_TEXT_EQ(Report(Outcome, "skipped existing"), "skipped existing : 1");
  CHECK_TEXT_EQ(Report(Outcome, "skipped no symbol"), "skipped no symbol: 1");
  CHECK_TEXT_EQ(Report(Outcome, "skipped duplicate"), "skipped duplicate: 1");
  CHECK_TEXT_EQ(Report(Outcome, "skipped conflict"), "skipped conflict : 0");
  CHECK_TEXT_EQ(Report(Outcome, "hop "), "hop              : 1");

  // Labels: both columns come from the reference row.
  CHECK_TEXT_EQ(NameAt(Out, T(1)), "Alpha");
  CHECK_TEXT_EQ(MangledAt(Out, T(1)), "?Alpha@@YAXXZ");
  CHECK_TEXT_EQ(NameAt(Out, T(3)), "Gamma");
  CHECK_TEXT_EQ(MangledAt(Out, T(3)), "Gamma");
  CHECK_TEXT_EQ(NameAt(Out, T(9)), "Eta");
  CHECK_TEXT_EQ(NameAt(Out, T(2)), "Beta");            // confirmed, untouched
  CHECK_TEXT_EQ(NameAt(Out, T(5)), "ExportName");      // real target name kept
  CHECK_TEXT_EQ(NameAt(Out, T(4)), "sub_" + Hex8(T(4)));    // reference name not portable
  CHECK_TEXT_EQ(NameAt(Out, T(10)), "sub_" + Hex8(T(10)));  // would duplicate T11's "Iota"
  CHECK_TEXT_EQ(NameAt(Out, T(6)), "sub_" + Hex8(T(6)));    // multimatch not selected
  CHECK_TEXT_EQ(NameAt(Out, T(8)), "sub_" + Hex8(T(8)));    // unreliable not selected

  // Origins: hops 1, confidence = ratio, heuristic = category:description; none for confirmations.
  const auto Origins = ReadNameOrigins(Out);
  CHECK_NUM_EQ(Origins.size(), 3);
  const auto Alpha = Origins.find(std::to_string(T(1)));
  CHECK(Alpha != Origins.end());
  if (Alpha != Origins.end()) {
    CHECK_TEXT_EQ(Alpha->second.Name, "Alpha");
    CHECK_TEXT_EQ(Alpha->second.OriginAddress, std::to_string(R(1)));
    CHECK_TEXT_EQ(Alpha->second.OriginName, "Alpha");
    CHECK_NUM_EQ(Alpha->second.Hops, 1);
    CHECK(Alpha->second.CumulativeRatio == 1.0);
    CHECK_TEXT_EQ(Alpha->second.Heuristic, "best:Bytes hash");
  }
  const auto Gamma = Origins.find(std::to_string(T(3)));
  CHECK(Gamma != Origins.end() && Gamma->second.CumulativeRatio == 0.75);
  CHECK(Origins.find(std::to_string(T(2))) == Origins.end());

  // Provenance hop row and the per-row log.
  const DatabaseIdentity Identity = InspectDatabase(Out);
  CHECK(Identity.Ok && Identity.HasProvenance);
  CHECK_NUM_EQ(Identity.HopCount, 1);
  if (!Identity.Hops.empty()) {
    CHECK_NUM_EQ(Identity.Hops[0].Matches, 7);
    CHECK_NUM_EQ(Identity.Hops[0].NamesApplied, 3);
    CHECK_NUM_EQ(Identity.Hops[0].NamesSkippedExisting, 1);
    CHECK_NUM_EQ(Identity.Hops[0].FunctionsReference, 10);
    CHECK_NUM_EQ(Identity.Hops[0].FunctionsTarget, 11);
    CHECK_TEXT_EQ(Identity.Hops[0].SourceFileSha256, RefSha);
    CHECK_TEXT_EQ(Identity.Hops[0].TargetFileSha256Before, TargetSha);
  }
  // program.md5sum is a BLOB: identity and lineage carry it as 32 hex digits.
  const DatabaseIdentity RefIdentity = InspectDatabase(S.Ref);
  CHECK_NUM_EQ(RefIdentity.InputMd5.size(), 32);
  CHECK_TEXT_EQ(RefIdentity.InputMd5.substr(0, 6), "102132");
  CHECK_TEXT_EQ(Identity.Lineage, RefIdentity.InputMd5 + " -> " + InspectDatabase(S.Target).InputMd5);

  const auto Log = Query(Out, "select results_rowid, type, action, address, ref_name, hops, confidence "
                              "from dsig_port_log order by results_rowid");
  CHECK_NUM_EQ(Log.size(), 11);
  const std::vector<std::string> Expected = {"confirmed",   "applied",        "applied",      "skipped_existing",
                                             "applied",     "skipped_duplicate_name", "skipped_not_portable",
                                             "not_selected", "not_selected",  "not_selected", "not_selected"};
  for (size_t Index = 0; Index < Log.size() && Index < Expected.size(); ++Index) {
    CHECK_TEXT_EQ(Log[Index][2], Expected[Index]);
  }
  const auto PortResults = Query(Out, "select hop, results_sha256, results_main_db, results_version, label_columns, "
                                      "proposals, selected, names_applied, names_confirmed, "
                                      "names_skipped_duplicate from dsig_port_results");
  CHECK_NUM_EQ(PortResults.size(), 1);
  if (!PortResults.empty()) {
    CHECK_TEXT_EQ(PortResults[0][1], ResultsSha);
    CHECK_TEXT_EQ(PortResults[0][2], "ref.sqlite");
    CHECK_TEXT_EQ(PortResults[0][3], "3.4");
    CHECK_TEXT_EQ(PortResults[0][4], "name,mangled_function");
    CHECK_TEXT_EQ(PortResults[0][5] + "/" + PortResults[0][6] + "/" + PortResults[0][7] + "/" + PortResults[0][8] +
                      "/" + PortResults[0][9],
                  "11/7/3/1/1");
  }

  // Only the two label columns change; schema, indices, stats and every other column are the target's.
  CHECK_TEXT_EQ(NonLabelFingerprint(Out), NonLabelFingerprint(S.Target));
  CHECK_TEXT_EQ(SchemaOf(Out, "functions"), SchemaOf(S.Target, "functions"));
  CHECK_TEXT_EQ(One(Out, "select count(*) from sqlite_stat1"), One(S.Target, "select count(*) from sqlite_stat1"));
  CHECK_TEXT_EQ(One(Out, "select group_concat(value) from version"), "3.4");
  CHECK_TEXT_EQ(One(Out, "pragma integrity_check"), "ok");
  CHECK(WalHeader(Out));  // still a WAL-mode export
  CHECK(!Exists(Out + "-wal") && !Exists(Out + "-shm") && !Exists(Out + ".dsig-tmp"));

  // Inputs untouched, and no -wal/-shm created beside the WAL-mode inputs (immutable read).
  CHECK_TEXT_EQ(FileSha(S.Ref), RefSha);
  CHECK_TEXT_EQ(FileSha(S.Target), TargetSha);
  CHECK_TEXT_EQ(FileSha(S.Results), ResultsSha);
  CHECK(!Exists(S.Ref + "-wal") && !Exists(S.Ref + "-shm"));
  CHECK(!Exists(S.Target + "-wal") && !Exists(S.Target + "-shm"));
}

void TestOptInCategories(const std::string& Dir) {
  DSig::Test::Suite("port --results: --include-multimatch --include-unreliable --overwrite");
  const Scenario S = MakeScenario(Dir);
  CHECK(S.Ok);
  const std::string Out = (std::filesystem::path(Dir) / "out_all.sqlite").string();
  Cli::PortFromResultsArgs A = Args(S.Ref, S.Target, Out, S.Results);
  A.IncludeMultimatch = true;
  A.IncludeUnreliable = true;
  A.Overwrite = true;
  const Cli::CommandOutcome Outcome = Cli::RunPortFromResults(A);
  CHECK_NUM_EQ(Outcome.ExitCode, Cli::kExitOk);
  CHECK_TEXT_EQ(Report(Outcome, "selected"), "selected         : 11 (best, partial, unreliable, multimatch)");
  CHECK_TEXT_EQ(Report(Outcome, "names applied"),
                "names applied    : 5 (best 2, partial 2, unreliable 1, multimatch 0)");
  CHECK_TEXT_EQ(Report(Outcome, "skipped conflict"), "skipped conflict : 1");
  CHECK_TEXT_EQ(Report(Outcome, "skipped duplicate"), "skipped duplicate: 3");
  CHECK_TEXT_EQ(NameAt(Out, T(5)), "Delta");  // --overwrite replaces the real target name
  CHECK_TEXT_EQ(NameAt(Out, T(8)), "Zeta");   // unreliable row applied
  CHECK_TEXT_EQ(NameAt(Out, T(9)), "Eta");    // best row claimed T9; the multimatch row lost
  CHECK_TEXT_EQ(NameAt(Out, T(6)), "sub_" + Hex8(T(6)));  // one name on two functions: neither
  CHECK_TEXT_EQ(NameAt(Out, T(7)), "sub_" + Hex8(T(7)));
  const auto Actions = Query(Out, "select action from dsig_port_log where type = 'multimatch' order by results_rowid");
  CHECK_NUM_EQ(Actions.size(), 3);
  if (Actions.size() == 3) {
    CHECK_TEXT_EQ(Actions[0][0], "skipped_duplicate_name");
    CHECK_TEXT_EQ(Actions[1][0], "skipped_duplicate_name");
    CHECK_TEXT_EQ(Actions[2][0], "skipped_conflict");
  }
  const auto AllOrigins = ReadNameOrigins(Out);
  CHECK(AllOrigins.count(std::to_string(T(5))) == 1);
  CHECK(AllOrigins.count(std::to_string(T(6))) == 0);
}

// Hop 2 uses the hop-1 output as its reference, through a second results file.
void TestChain(const std::string& Dir) {
  DSig::Test::Suite("port --results: two-hop chain, the ported DB as the next reference");
  const Scenario S = MakeScenario(Dir);
  CHECK(S.Ok);
  const std::string Hop1 = (std::filesystem::path(Dir) / "hop1.sqlite").string();
  CHECK_NUM_EQ(Cli::RunPortFromResults(Args(S.Ref, S.Target, Hop1, S.Results)).ExitCode, Cli::kExitOk);

  constexpr uint64_t kV3 = 0x180003000ull;
  const auto U = [](int Index) { return kV3 + static_cast<uint64_t>(Index) * 0x100; };
  const std::string V3 = (std::filesystem::path(Dir) / "v3.sqlite").string();
  std::vector<Fn> V3Rows;
  for (int Index = 1; Index <= 4; ++Index) {
    V3Rows.push_back({U(Index), "sub_" + Hex8(U(Index)), {}});
  }
  CHECK(CreateExport(V3, V3Rows, 0x30));
  const auto SubU = [&](int Index) { return std::optional<std::string>("sub_" + Hex8(U(Index))); };
  const std::string Results2 = (std::filesystem::path(Dir) / "hop1_vs_v3.diaphora").string();
  CHECK(CreateResults(Results2, {
                                    {"best", "00000", T(1), "Alpha", U(1), SubU(1), "1.0000000", "Bytes hash"},
                                    {"best", "00001", T(2), "Beta", U(2), SubU(2), "1.0000000", "Same name"},
                                    {"partial", "00000", T(3), "Gamma", U(3), SubU(3), "0.8000000", "Loop count"},
                                    {"partial", "00001", T(4), "sub_" + Hex8(T(4)), U(4), SubU(4), "0.7000000",
                                     "Loop count"},
                                }));
  const std::string Hop2 = (std::filesystem::path(Dir) / "hop2.sqlite").string();
  const Cli::CommandOutcome Outcome = Cli::RunPortFromResults(Args(Hop1, V3, Hop2, Results2));
  CHECK_NUM_EQ(Outcome.ExitCode, Cli::kExitOk);
  if (Outcome.ExitCode != Cli::kExitOk) {
    std::printf("  error: %s\n", Outcome.Message.c_str());
    return;
  }
  CHECK_TEXT_EQ(Report(Outcome, "hop "), "hop              : 2");
  CHECK_TEXT_EQ(NameAt(Hop2, U(1)), "Alpha");
  CHECK_TEXT_EQ(MangledAt(Hop2, U(1)), "?Alpha@@YAXXZ");  // the mangled name travels with the label
  CHECK_TEXT_EQ(NameAt(Hop2, U(3)), "Gamma");

  const auto Origins = ReadNameOrigins(Hop2);
  const auto Alpha = Origins.find(std::to_string(U(1)));
  const auto Beta = Origins.find(std::to_string(U(2)));
  const auto Gamma = Origins.find(std::to_string(U(3)));
  CHECK(Alpha != Origins.end() && Beta != Origins.end() && Gamma != Origins.end());
  if (Alpha != Origins.end() && Beta != Origins.end() && Gamma != Origins.end()) {
    CHECK_NUM_EQ(Alpha->second.Hops, 2);
    CHECK_TEXT_EQ(Alpha->second.OriginAddress, std::to_string(R(1)));  // the first reference's address
    CHECK_TEXT_EQ(Alpha->second.OriginName, "Alpha");
    CHECK(Alpha->second.CumulativeRatio == 1.0);
    CHECK_TEXT_EQ(Alpha->second.FirstLabelledAt, ReadNameOrigins(Hop1).at(std::to_string(T(1))).FirstLabelledAt);
    CHECK_NUM_EQ(Beta->second.Hops, 1);  // Beta was the target's own name in hop 1 (a confirmation)
    CHECK_TEXT_EQ(Beta->second.OriginAddress, std::to_string(T(2)));
    CHECK_NUM_EQ(Gamma->second.Hops, 2);
    CHECK(Gamma->second.CumulativeRatio == 0.75 * 0.8);  // ratio x parent confidence
  }
  const DatabaseIdentity Identity = InspectDatabase(Hop2);
  CHECK_NUM_EQ(Identity.HopCount, 2);
  if (Identity.Hops.size() == 2) {
    CHECK_NUM_EQ(Identity.Hops[0].Hop, 1);
    CHECK_NUM_EQ(Identity.Hops[1].Hop, 2);
    CHECK_TEXT_EQ(Identity.Hops[1].SourceFileSha256, FileSha(Hop1));
  }
  const std::string Md5Ref = InspectDatabase(S.Ref).InputMd5, Md5Target = InspectDatabase(S.Target).InputMd5,
                    Md5V3 = InspectDatabase(V3).InputMd5;
  CHECK_TEXT_EQ(Identity.Lineage, Md5Ref + " -> " + Md5Target + " -> " + Md5V3);
  CHECK_TEXT_EQ(One(Hop2, "select group_concat(hop) from (select hop from dsig_port_results order by hop)"), "1,2");
  CHECK_TEXT_EQ(One(Hop2, "select count(*) from dsig_port_log"), "4");
  CHECK_TEXT_EQ(One(Hop2, "select group_concat(distinct hop) from dsig_port_log"), "2");

  // --max-hops 1 keeps only the name that travels its first hop; --min-ratio drops Gamma (0.6).
  Cli::PortFromResultsArgs Capped = Args(Hop1, V3, (std::filesystem::path(Dir) / "hop2_capped.sqlite").string(),
                                         Results2);
  Capped.MaxHops = 1;
  const Cli::CommandOutcome CappedOutcome = Cli::RunPortFromResults(Capped);
  CHECK_TEXT_EQ(Report(CappedOutcome, "skipped hop cap"), "skipped hop cap  : 2");
  CHECK_TEXT_EQ(Report(CappedOutcome, "names applied"),
                "names applied    : 1 (best 1, partial 0, unreliable 0, multimatch 0)");
  Cli::PortFromResultsArgs Floor = Args(Hop1, V3, (std::filesystem::path(Dir) / "hop2_floor.sqlite").string(),
                                        Results2);
  Floor.MinRatio = 0.7;
  const Cli::CommandOutcome FloorOutcome = Cli::RunPortFromResults(Floor);
  CHECK_TEXT_EQ(Report(FloorOutcome, "skipped ratio"), "skipped ratio    : 1");
  CHECK_TEXT_EQ(NameAt(Floor.Output, U(3)), "sub_" + Hex8(U(3)));
}

void TestPathSafety(const std::string& Dir) {
  DSig::Test::Suite("port --results: the output never aliases an input");
  const Scenario S = MakeScenario(Dir);
  CHECK(S.Ok);
  const std::string RefSha = FileSha(S.Ref), TargetSha = FileSha(S.Target), ResultsSha = FileSha(S.Results);
  const std::string Alias = (std::filesystem::path(Dir) / "." / "target.sqlite").string();
  for (const std::string& Out : {S.Target, S.Ref, S.Results, Alias}) {
    const Cli::CommandOutcome Outcome = Cli::RunPortFromResults(Args(S.Ref, S.Target, Out, S.Results));
    CHECK_NUM_EQ(Outcome.ExitCode, Cli::kExitUsage);
    CHECK(Outcome.Message.find("refusing to overwrite an input") != std::string::npos);
  }
  CHECK_TEXT_EQ(FileSha(S.Ref), RefSha);
  CHECK_TEXT_EQ(FileSha(S.Target), TargetSha);
  CHECK_TEXT_EQ(FileSha(S.Results), ResultsSha);
  const std::string Missing = (std::filesystem::path(Dir) / "no_such_dir" / "out.sqlite").string();
  CHECK_NUM_EQ(Cli::RunPortFromResults(Args(S.Ref, S.Target, Missing, S.Results)).ExitCode, Cli::kExitIo);
}

// Every regular file of a directory with its sha256: "nothing was deleted, created or changed".
std::map<std::string, std::string> DirState(const std::string& Dir) {
  std::map<std::string, std::string> State;
  std::error_code Error;
  for (const auto& Entry : std::filesystem::directory_iterator(Dir, Error)) {
    if (Entry.is_regular_file(Error)) {
      State[Entry.path().filename().string()] = FileSha(Entry.path().string());
    }
  }
  return State;
}

std::string DescribeState(const std::map<std::string, std::string>& State) {
  std::string Text;
  for (const auto& [Name, Sha] : State) {
    Text += (Text.empty() ? "" : ", ") + Name + "=" + Sha.substr(0, 8);
  }
  return Text;
}

// A target export whose last transaction still sits in its -wal (committed frames, not checkpointed).
bool AddCommittedWalFrame(const std::string& Path) {
#ifdef SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE
  sqlite3* Db = nullptr;
  if (sqlite3_open_v2(Path.c_str(), &Db, SQLITE_OPEN_READWRITE, nullptr) != SQLITE_OK) {
    sqlite3_close(Db);
    return false;
  }
  int Disabled = 0;
  sqlite3_db_config(Db, SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, 1, &Disabled);
  const bool Ok = Exec(Db, "update functions set comment = 'wal frame' where id = 1");
  sqlite3_close(Db);
  return Ok && Exists(Path + "-wal") && std::filesystem::file_size(Path + "-wal") > 0;
#else
  (void)Path;
  return false;
#endif
}

void TestAliasHelpers(const std::string& Dir) {
  DSig::Test::Suite("path aliasing: DatabaseFileSet / SameFilePath / FindPathAlias");
  std::error_code Error;
  std::filesystem::create_directories(std::filesystem::path(Dir) / "sub", Error);
  const std::string A = (std::filesystem::path(Dir) / "a.sqlite").string();
  CHECK(CreateExport(A, {{R(1), "Alpha"}}, 0x10, false));

  const std::vector<NamedPath> Set = DatabaseFileSet("the output", A);
  CHECK_NUM_EQ(Set.size(), 4);
  if (Set.size() == 4) {
    CHECK_TEXT_EQ(Set[0].Path, A);
    CHECK_TEXT_EQ(Set[1].Path, A + "-wal");
    CHECK_TEXT_EQ(Set[2].Path, A + "-shm");
    CHECK_TEXT_EQ(Set[3].Path, A + "-journal");
    CHECK_TEXT_EQ(Set[3].Role, "the output's -journal file");
  }
  CHECK(DatabaseFileSet("x", "").empty());

  const std::string Dotted = (std::filesystem::path(Dir) / "sub" / ".." / "." / "a.sqlite").string();
  CHECK(SameFilePath(A, A));
  CHECK(SameFilePath(A, Dotted));                    // exists: equivalent()
  CHECK(SameFilePath(A + "-wal", Dotted + "-wal"));  // absent: canonical spelling
  CHECK(!SameFilePath(A, A + "-wal"));
  CHECK(!SameFilePath(A, (std::filesystem::path(Dir) / "sub" / "a.sqlite").string()));
  const std::string Link = (std::filesystem::path(Dir) / "hard link.sqlite").string();
  std::filesystem::create_hard_link(A, Link, Error);
  if (!Error) {
    CHECK(SameFilePath(A, Link));  // one file, two names
  } else {
    DSig::Test::Note("hard links not supported here: " + Error.message());
  }
#if defined(_WIN32)
  std::string Upper = A;
  for (char& Ch : Upper) {
    Ch = static_cast<char>(std::toupper(static_cast<unsigned char>(Ch)));
  }
  CHECK(SameFilePath(A, Upper));                        // NTFS ignores case: exists
  CHECK(SameFilePath(A + "-journal", Upper + "-JOURNAL"));  // ... and for a name that does not exist yet
#endif
  const auto Hit = FindPathAlias(DatabaseFileSet("the output", Dotted + "-wal"), DatabaseFileSet("the target database", A));
  CHECK(Hit.has_value());
  if (Hit) {
    CHECK(Hit->find("the output '") == 0);
    CHECK(Hit->find("is the target database's -wal file '") != std::string::npos);
    CHECK(Hit->find("refusing to overwrite an input") != std::string::npos);
  }
  CHECK(!FindPathAlias(DatabaseFileSet("the output", (std::filesystem::path(Dir) / "b.sqlite").string()),
                       DatabaseFileSet("the target database", A)));
}

// The verifier's reproduction and every other derived-path alias: the output, "<output>.dsig-tmp" and
// the -wal/-shm/-journal sidecars of both against the reference, the target, the results file and
// their sidecars. Each case runs in its own directory and must leave every file of it untouched.
void TestDerivedPathAliases(const std::string& Dir) {
  DSig::Test::Suite("port --results: no written file (temporary, sidecars) aliases an input or its sidecars");
  struct Case {
    const char* Label;
    const char* Ref;
    const char* Target;
    const char* Results;
    const char* Out;
    bool TargetWal = false;  // leave committed frames in the target's -wal
  };
  const Case Cases[] = {
      {"target is <out>.dsig-tmp (verifier)", "ref.sqlite", "out.sqlite.dsig-tmp", "r.diaphora", "out.sqlite"},
      {"reference is <out>.dsig-tmp", "out.sqlite.dsig-tmp", "target.sqlite", "r.diaphora", "out.sqlite"},
      {"results is <out>.dsig-tmp", "ref.sqlite", "target.sqlite", "out.sqlite.dsig-tmp", "out.sqlite"},
      {"target is <out>-journal", "ref.sqlite", "out.sqlite-journal", "r.diaphora", "out.sqlite"},
      {"target is <out>-wal", "ref.sqlite", "out.sqlite-wal", "r.diaphora", "out.sqlite"},
      {"reference is <out>-shm", "out.sqlite-shm", "target.sqlite", "r.diaphora", "out.sqlite"},
      {"target is <out>.dsig-tmp-journal", "ref.sqlite", "out.sqlite.dsig-tmp-journal", "r.diaphora", "out.sqlite"},
      {"target is <out>.dsig-tmp-wal", "ref.sqlite", "out.sqlite.dsig-tmp-wal", "r.diaphora", "out.sqlite"},
      {"results is <out>.dsig-tmp-shm", "ref.sqlite", "target.sqlite", "out.sqlite.dsig-tmp-shm", "out.sqlite"},
      {"output is the target's committed -wal", "ref.sqlite", "target.sqlite", "r.diaphora", "target.sqlite-wal", true},
      {"output is the reference's -journal (absent)", "ref.sqlite", "target.sqlite", "r.diaphora", "ref.sqlite-journal"},
      {"output is the results' -wal (absent)", "ref.sqlite", "target.sqlite", "r.diaphora", "r.diaphora-wal"},
      {"output is the target's -shm (absent)", "ref.sqlite", "target.sqlite", "r.diaphora", "target.sqlite-shm"},
      {"<out>.dsig-tmp spelled through ..", "ref.sqlite", "out.sqlite.dsig-tmp", "r.diaphora", "sub/../out.sqlite"},
#if defined(_WIN32)
      {"<out>.dsig-tmp in another case (NTFS)", "ref.sqlite", "OUT.SQLITE.DSIG-TMP", "r.diaphora", "out.sqlite"},
#endif
  };
  int Index = 0;
  for (const Case& C : Cases) {
    const std::string CaseDir = (std::filesystem::path(Dir) / ("case" + std::to_string(Index++))).string();
    std::error_code Error;
    std::filesystem::create_directories(std::filesystem::path(CaseDir) / "sub", Error);
    const auto In = [&](const char* Name) { return (std::filesystem::path(CaseDir) / Name).string(); };
    bool Built = CreateExport(In(C.Ref), ReferenceRows(), 0x10) && CreateExport(In(C.Target), TargetRows(), 0x20) &&
                 CreateResults(In(C.Results), ScenarioResults());
    if (C.TargetWal) {
      Built = Built && AddCommittedWalFrame(In(C.Target));
    }
    CHECK(Built);
    if (!Built) {
      DSig::Test::Note(std::string(C.Label) + ": fixture not built");
      continue;
    }
    const std::map<std::string, std::string> Before = DirState(CaseDir);
    const Cli::CommandOutcome Outcome =
        Cli::RunPortFromResults(Args(In(C.Ref), In(C.Target), In(C.Out), In(C.Results)));
    const std::map<std::string, std::string> After = DirState(CaseDir);
    CHECK_NUM_EQ(Outcome.ExitCode, Cli::kExitUsage);
    CHECK(Outcome.Message.find("refusing to overwrite an input") != std::string::npos);
    CHECK_TEXT_EQ(DescribeState(After), DescribeState(Before));  // nothing deleted, created or changed
    if (Outcome.ExitCode != Cli::kExitUsage || After != Before) {
      DSig::Test::Note(std::string(C.Label) + ": exit " + std::to_string(Outcome.ExitCode) + ": " + Outcome.Message);
    }
  }

  // A hard link to the target named "<out>.dsig-tmp": one file under two names.
  {
    const std::string CaseDir = (std::filesystem::path(Dir) / "hardlink").string();
    const Scenario S = MakeScenario(CaseDir);
    CHECK(S.Ok);
    const std::string Out = (std::filesystem::path(CaseDir) / "out.sqlite").string();
    std::error_code Error;
    std::filesystem::create_hard_link(S.Target, Out + ".dsig-tmp", Error);
    if (Error) {
      DSig::Test::Note("hard links not supported here: " + Error.message());
    } else {
      const std::map<std::string, std::string> Before = DirState(CaseDir);
      const Cli::CommandOutcome Outcome = Cli::RunPortFromResults(Args(S.Ref, S.Target, Out, S.Results));
      CHECK_NUM_EQ(Outcome.ExitCode, Cli::kExitUsage);
      CHECK(Outcome.Message.find("the temporary output '") == 0);
      CHECK_TEXT_EQ(DescribeState(DirState(CaseDir)), DescribeState(Before));
    }
  }

  // Control: the same names without an alias still port.
  {
    const std::string CaseDir = (std::filesystem::path(Dir) / "control").string();
    const Scenario S = MakeScenario(CaseDir);
    CHECK(S.Ok);
    const std::string Out = (std::filesystem::path(CaseDir) / "out.sqlite").string();
    CHECK_NUM_EQ(Cli::RunPortFromResults(Args(S.Ref, S.Target, Out, S.Results)).ExitCode, Cli::kExitOk);
    CHECK(Exists(Out) && !Exists(Out + ".dsig-tmp"));
  }
}

// The legacy engine (port without --results) writes its output in place: the copy truncates it and
// SQLite opens it read-write, so a hot "<output>-journal" would be played back and deleted and a WAL
// output checkpoints and deletes "<output>-wal". The same audit applies.
void TestLegacyPortAliases(const std::string& Dir) {
  DSig::Test::Suite("legacy port: the output and its sidecars never alias an input or its sidecars");
  struct Case {
    const char* Label;
    const char* Ref;
    const char* Target;
    const char* Out;
    bool TargetWal = false;
  };
  const Case Cases[] = {
      {"target is <out>-journal", "ref.sqlite", "out.sqlite-journal", "out.sqlite"},
      {"target is <out>-wal", "ref.sqlite", "out.sqlite-wal", "out.sqlite"},
      {"reference is <out>-journal", "out.sqlite-journal", "target.sqlite", "out.sqlite"},
      {"output is the target's committed -wal", "ref.sqlite", "target.sqlite", "target.sqlite-wal", true},
      {"output is the target", "ref.sqlite", "target.sqlite", "./target.sqlite"},
  };
  int Index = 0;
  for (const Case& C : Cases) {
    const std::string CaseDir = (std::filesystem::path(Dir) / ("legacy" + std::to_string(Index++))).string();
    std::error_code Error;
    std::filesystem::create_directories(CaseDir, Error);
    const auto In = [&](const char* Name) { return (std::filesystem::path(CaseDir) / Name).string(); };
    bool Built = CreateExport(In(C.Ref), ReferenceRows(), 0x10) && CreateExport(In(C.Target), TargetRows(), 0x20);
    if (C.TargetWal) {
      Built = Built && AddCommittedWalFrame(In(C.Target));
    }
    CHECK(Built);
    if (!Built) {
      continue;
    }
    const std::map<std::string, std::string> Before = DirState(CaseDir);
    PortOptions Options;
    Options.ReferencePath = In(C.Ref);
    Options.TargetPath = In(C.Target);
    Options.OutputPath = In(C.Out);
    const PortResult Result = PortSymbols(Options);
    const std::map<std::string, std::string> After = DirState(CaseDir);
    CHECK(!Result.Ok);
    CHECK(Result.Error.find("refusing to overwrite an input") != std::string::npos);
    CHECK_TEXT_EQ(DescribeState(After), DescribeState(Before));
    if (Result.Ok || After != Before) {
      DSig::Test::Note(std::string(C.Label) + ": " + (Result.Ok ? std::string("ported") : Result.Error));
    }
  }
}

// Origin inheritance (Provenance.cpp PortLabels, "Inherit the reference's history only while the
// reference still carries the name it recorded"): a reference function the user renamed after the
// previous hop starts a new history (hop 1, confidence = this ratio, origin = the reference itself),
// while an unchanged name keeps its parent's hops, confidence, origin and first-labelled time.
void TestOriginInheritance(const std::string& Dir) {
  DSig::Test::Suite("port --results: origin history is inherited only while the reference keeps the recorded name");
  const Scenario S = MakeScenario(Dir);
  CHECK(S.Ok);
  const std::string Hop1 = (std::filesystem::path(Dir) / "hop1.sqlite").string();
  CHECK_NUM_EQ(Cli::RunPortFromResults(Args(S.Ref, S.Target, Hop1, S.Results)).ExitCode, Cli::kExitOk);
  const auto Hop1Origins = ReadNameOrigins(Hop1);
  CHECK(Hop1Origins.count(std::to_string(T(3))) == 1 && Hop1Origins.count(std::to_string(T(1))) == 1);
  if (Hop1Origins.count(std::to_string(T(3))) == 0 || Hop1Origins.count(std::to_string(T(1))) == 0) {
    return;
  }
  CHECK_TEXT_EQ(Hop1Origins.at(std::to_string(T(3))).Name, "Gamma");
  CHECK_NUM_EQ(Hop1Origins.at(std::to_string(T(3))).Hops, 1);
  CHECK(Hop1Origins.at(std::to_string(T(3))).CumulativeRatio == 0.75);

  // The user renames Gamma in the hop-1 database (IDA, then a re-export): dsig_name_origin still
  // records "Gamma" for that address.
  {
    sqlite3* Db = nullptr;
    CHECK(sqlite3_open_v2(Hop1.c_str(), &Db, SQLITE_OPEN_READWRITE, nullptr) == SQLITE_OK);
    CHECK(Exec(Db, "update functions set name = 'GammaRenamed', mangled_function = 'GammaRenamed' "
                   "where address = '" + std::to_string(T(3)) + "'"));
    sqlite3_close(Db);
  }
  CHECK_TEXT_EQ(NameAt(Hop1, T(3)), "GammaRenamed");
  CHECK_TEXT_EQ(One(Hop1, "select name from dsig_name_origin where address = '" + std::to_string(T(3)) + "'"),
                "Gamma");

  constexpr uint64_t kV3 = 0x180003000ull;
  const auto U = [](int Index) { return kV3 + static_cast<uint64_t>(Index) * 0x100; };
  const std::string V3 = (std::filesystem::path(Dir) / "v3.sqlite").string();
  CHECK(CreateExport(V3, {{U(1), "sub_" + Hex8(U(1))}, {U(3), "sub_" + Hex8(U(3))}}, 0x30));
  const std::string Results2 = (std::filesystem::path(Dir) / "hop1_vs_v3.diaphora").string();
  CHECK(CreateResults(Results2, {
                                    {"best", "00000", T(1), "Alpha", U(1), "sub_" + Hex8(U(1)), "1.0000000", "Bytes hash"},
                                    {"partial", "00000", T(3), "GammaRenamed", U(3), "sub_" + Hex8(U(3)), "0.8000000",
                                     "Loop count"},
                                }));
  const std::string Hop2 = (std::filesystem::path(Dir) / "hop2.sqlite").string();
  const Cli::CommandOutcome Outcome = Cli::RunPortFromResults(Args(Hop1, V3, Hop2, Results2));
  CHECK_NUM_EQ(Outcome.ExitCode, Cli::kExitOk);
  if (Outcome.ExitCode != Cli::kExitOk) {
    DSig::Test::Note(Outcome.Message);
    return;
  }
  CHECK_TEXT_EQ(NameAt(Hop2, U(3)), "GammaRenamed");
  const auto Origins = ReadNameOrigins(Hop2);
  const auto Renamed = Origins.find(std::to_string(U(3)));
  const auto Kept = Origins.find(std::to_string(U(1)));
  CHECK(Renamed != Origins.end() && Kept != Origins.end());
  if (Renamed == Origins.end() || Kept == Origins.end()) {
    return;
  }
  // renamed: a new history that starts at the hop-1 database
  CHECK_NUM_EQ(Renamed->second.Hops, 1);
  CHECK(Renamed->second.CumulativeRatio == 0.8);  // not 0.75 x 0.8
  CHECK_TEXT_EQ(Renamed->second.OriginAddress, std::to_string(T(3)));
  CHECK_TEXT_EQ(Renamed->second.OriginName, "GammaRenamed");
  CHECK_TEXT_EQ(Renamed->second.FirstLabelledAt, One(Hop2, "select applied_at from dsig_provenance where hop = 2"));
  CHECK_TEXT_EQ(One(Hop2, "select hops || ' ' || confidence from dsig_port_log where address = '" +
                              std::to_string(U(3)) + "'"),
                "1 0.8");
  // unchanged: the parent's history continues
  CHECK_NUM_EQ(Kept->second.Hops, 2);
  CHECK(Kept->second.CumulativeRatio == 1.0);
  CHECK_TEXT_EQ(Kept->second.OriginAddress, std::to_string(R(1)));
  CHECK_TEXT_EQ(Kept->second.FirstLabelledAt, Hop1Origins.at(std::to_string(T(1))).FirstLabelledAt);

  // --max-hops 1 admits the renamed function (a first hop) and stops the inherited one (a second).
  Cli::PortFromResultsArgs Capped = Args(Hop1, V3, (std::filesystem::path(Dir) / "hop2_capped.sqlite").string(), Results2);
  Capped.MaxHops = 1;
  const Cli::CommandOutcome CappedOutcome = Cli::RunPortFromResults(Capped);
  CHECK_NUM_EQ(CappedOutcome.ExitCode, Cli::kExitOk);
  CHECK_TEXT_EQ(Report(CappedOutcome, "skipped hop cap"), "skipped hop cap  : 1");
  CHECK_TEXT_EQ(NameAt(Capped.Output, U(3)), "GammaRenamed");
  CHECK_TEXT_EQ(NameAt(Capped.Output, U(1)), "sub_" + Hex8(U(1)));
  // --min-ratio 0.7: 0.8 passes for the new history; the inherited 0.75 x 0.8 = 0.6 would not.
  Cli::PortFromResultsArgs Floor = Args(Hop1, V3, (std::filesystem::path(Dir) / "hop2_floor.sqlite").string(), Results2);
  Floor.MinRatio = 0.7;
  const Cli::CommandOutcome FloorOutcome = Cli::RunPortFromResults(Floor);
  CHECK_TEXT_EQ(Report(FloorOutcome, "skipped ratio"), "skipped ratio    : 0");
  CHECK_TEXT_EQ(NameAt(Floor.Output, U(3)), "GammaRenamed");
}

void TestBadInputs(const std::string& Dir) {
  DSig::Test::Suite("port --results: bad inputs are refused and write nothing");
  const Scenario S = MakeScenario(Dir);
  CHECK(S.Ok);
  const std::string Out = (std::filesystem::path(Dir) / "bad_out.sqlite").string();
  const auto Run = [&](const std::string& Results) {
    RemoveDb(Out);
    const Cli::CommandOutcome Outcome = Cli::RunPortFromResults(Args(S.Ref, S.Target, Out, Results));
    CHECK(!Exists(Out));
    return Outcome;
  };
  const auto Sub = [](int Index) { return std::optional<std::string>("sub_" + Hex8(T(Index))); };
  const auto WithRows = [&](const std::string& File, const std::vector<ResultRow>& Rows) {
    const std::string Path = (std::filesystem::path(Dir) / File).string();
    CHECK(CreateResults(Path, Rows));
    return Path;
  };

  CHECK_NUM_EQ(Run((std::filesystem::path(Dir) / "missing.diaphora").string()).ExitCode, Cli::kExitIo);
  const std::string Text = (std::filesystem::path(Dir) / "text.diaphora").string();
  std::ofstream(Text) << "not a database";
  CHECK_NUM_EQ(Run(Text).ExitCode, Cli::kExitUnsupported);
  // An export instead of a results file.
  CHECK_NUM_EQ(Run(S.Target).ExitCode, Cli::kExitUnsupported);
  const std::string NoResults = (std::filesystem::path(Dir) / "noresults.diaphora").string();
  CHECK(CreateExport(NoResults, {}, 0x40, false));
  CHECK(Run(NoResults).Message.find("no 'results' table") != std::string::npos);

  const auto Unknown = Run(WithRows("addr.diaphora", {{"best", "00000", R(1), "?Alpha@@YAXXZ", T(1) + 4, {},
                                                         "1.0000000", "Bytes hash"}}));
  CHECK_NUM_EQ(Unknown.ExitCode, Cli::kExitUnsupported);
  CHECK(Unknown.Message.find("is not a function of the target database") != std::string::npos);
  const auto WrongRef = Run(WithRows("name.diaphora", {{"best", "00000", R(1), "Omega", T(1), Sub(1), "1.0000000",
                                                         "Bytes hash"}}));
  CHECK_NUM_EQ(WrongRef.ExitCode, Cli::kExitUnsupported);
  CHECK(WrongRef.Message.find("belongs to another pair") != std::string::npos);
  const auto WrongTarget = Run(WithRows("name2.diaphora", {{"best", "00000", R(1), "Alpha", T(1), "Omega",
                                                             "1.0000000", "Bytes hash"}}));
  CHECK_NUM_EQ(WrongTarget.ExitCode, Cli::kExitUnsupported);
  CHECK_NUM_EQ(Run(WithRows("ratio.diaphora", {{"best", "00000", R(1), "Alpha", T(1), Sub(1), "1,0", "x"}})).ExitCode,
               Cli::kExitUnsupported);
  CHECK_NUM_EQ(Run(WithRows("type.diaphora", {{"ml", "00000", R(1), "Alpha", T(1), Sub(1), "1.0000000", "x"}})).ExitCode,
               Cli::kExitUnsupported);

  Cli::PortFromResultsArgs NoResultsArg = Args(S.Ref, S.Target, Out, "");
  CHECK_NUM_EQ(Cli::RunPortFromResults(NoResultsArg).ExitCode, Cli::kExitUnsupported);
  Cli::PortFromResultsArgs Strict = Args(S.Ref, S.Target, Out, S.Results);
  Strict.StrictSqlite = true;
  CHECK_NUM_EQ(Cli::RunPortFromResults(Strict).ExitCode, Cli::kExitUsage);
  Cli::PortFromResultsArgs BadRatio = Args(S.Ref, S.Target, Out, S.Results);
  BadRatio.MinRatio = 1.5;
  CHECK_NUM_EQ(Cli::RunPortFromResults(BadRatio).ExitCode, Cli::kExitUsage);
  // A reference that is not a Diaphora export, and one that lacks the results' functions.
  const Cli::CommandOutcome NotExport = Cli::RunPortFromResults(Args(S.Results, S.Target, Out, S.Results));
  CHECK_NUM_EQ(NotExport.ExitCode, Cli::kExitUnsupported);
  CHECK(NotExport.Message.find("not a Diaphora export") != std::string::npos);
  CHECK_NUM_EQ(Cli::RunPortFromResults(Args(NoResults, S.Target, Out, S.Results)).ExitCode, Cli::kExitUnsupported);
}

// A target whose last transaction still sits in its -wal, and a stale -wal beside the output path.
void TestWal(const std::string& Dir) {
#ifndef SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE
  DSig::Test::Skip("port --results: WAL-mode inputs", "SQLite older than 3.28 (no SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE)");
  (void)Dir;
  return;
#else
  DSig::Test::Suite("port --results: WAL-mode inputs and stale output sidecars");
  const Scenario S = MakeScenario(Dir);
  CHECK(S.Ok);
  {
    sqlite3* Db = nullptr;
    CHECK(sqlite3_open_v2(S.Target.c_str(), &Db, SQLITE_OPEN_READWRITE, nullptr) == SQLITE_OK);
    int Disabled = 0;
    sqlite3_db_config(Db, SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, 1, &Disabled);
    // T11 ("Iota") is in no results row; renaming it in the -wal only also frees "Iota" for T10.
    CHECK(Exec(Db, "update functions set name = 'Kappa', mangled_function = 'Kappa' where address = '" +
                       std::to_string(T(11)) + "'"));
    sqlite3_close(Db);
  }
  CHECK(std::filesystem::file_size(S.Target + "-wal") > 0);
  const std::string Out = (std::filesystem::path(Dir) / "wal_out.sqlite").string();
  RemoveDb(Out);
  std::ofstream(Out + "-wal", std::ios::binary) << "stale garbage that must not be replayed";
  std::ofstream(Out + "-shm", std::ios::binary) << "stale";
  const Cli::CommandOutcome Outcome = Cli::RunPortFromResults(Args(S.Ref, S.Target, Out, S.Results));
  CHECK_NUM_EQ(Outcome.ExitCode, Cli::kExitOk);
  if (Outcome.ExitCode != Cli::kExitOk) {
    std::printf("  error: %s\n", Outcome.Message.c_str());
  }
  CHECK_TEXT_EQ(NameAt(Out, T(11)), "Kappa");  // the committed WAL frame reached the copy ...
  CHECK_TEXT_EQ(NameAt(Out, T(10)), "Iota");   // ... and the port decided on it: no duplicate any more
  CHECK_TEXT_EQ(NameAt(Out, T(1)), "Alpha");
  CHECK_TEXT_EQ(One(Out, "pragma integrity_check"), "ok");
  CHECK(!Exists(Out + "-wal"));
#endif
}

// ---------------------------------------------------------------------------------------------
// corpus: Diaphora's own run1 results of every finished oracle pair (plan §7.2 L11 acceptance)

void TestCorpus() {
  const char* Name = "corpus: port every finished oracle pair from Diaphora's run1 results";
  if (!DSig::Test::CorpusRoot()) {
    DSig::Test::Skip(Name, "DSIG_CORPUS_ROOT not set");
    return;
  }
  struct Pair {
    const char* Id;
    const char* Ref;
    const char* Target;
  };
  const Pair Pairs[] = {
      {"ls-old_vs_ls", "ls-old", "ls"},
      {"ls_vs_ls-old", "ls", "ls-old"},
      {"userenv-9168-pdb_vs_9278-pdb", "userenv-9168-pdb", "userenv-9278-pdb"},
      {"win32u-9168-useri64_vs_9444-nopdb", "win32u-9168-useri64", "win32u-9444-nopdb"},
      {"cryptbase-1-pdb_vs_8875-nopdb", "cryptbase-1-pdb", "cryptbase-8875-nopdb"},
      {"cryptbase-8875-pdb_vs_9444-nopdb", "cryptbase-8875-pdb", "cryptbase-9444-nopdb"},
  };
  DSig::Test::Suite(Name);
  const std::string Dir = ScratchDir("cli_port_results_corpus");
  int Ported = 0;
  for (const Pair& P : Pairs) {
    const std::string Results = DSig::Test::OracleResultsPath(P.Id, 1);
    if (!DSig::Test::ExportAvailable(P.Ref) || !DSig::Test::ExportAvailable(P.Target) || !Exists(Results)) {
      DSig::Test::Note(std::string(P.Id) + ": absent, skipped");
      continue;
    }
    const std::string Ref = DSig::Test::ExportPath(P.Ref), Target = DSig::Test::ExportPath(P.Target);
    const std::string RefSha = FileSha(Ref), TargetSha = FileSha(Target), ResultsSha = FileSha(Results);
    const std::string Out = (std::filesystem::path(Dir) / (std::string(P.Id) + ".sqlite")).string();
    const Cli::CommandOutcome Outcome = Cli::RunPortFromResults(Args(Ref, Target, Out, Results));
    CHECK_NUM_EQ(Outcome.ExitCode, Cli::kExitOk);
    if (Outcome.ExitCode != Cli::kExitOk) {
      std::printf("  %s: %s\n", P.Id, Outcome.Message.c_str());
      continue;
    }
    ++Ported;
    DSig::Test::Note(std::string(P.Id) + ": " + Report(Outcome, "names applied").substr(19) + "; " +
                     Report(Outcome, "names confirmed").substr(19) + " confirmed");
    const std::string Rows = One(Results, "select count(*) from results");
    const std::string BestPartial = One(Results, "select count(*) from results where type in ('best', 'partial')");
    CHECK_TEXT_EQ(One(Out, "select count(*) from dsig_port_log"), Rows);
    CHECK_TEXT_EQ(One(Out, "select count(*) from dsig_port_log where action != 'not_selected'"), BestPartial);
    CHECK_TEXT_EQ(One(Out, "select matches from dsig_provenance where hop = 1"), BestPartial);
    // Every applied row landed: the output name at the target address is the reference's name.
    CHECK_TEXT_EQ(One(Out, "select count(*) from dsig_port_log l join functions f on f.address = l.address "
                           "where l.action = 'applied' and (f.name is not l.ref_name or f.mangled_function is not "
                           "case when l.ref_mangled is null or l.ref_mangled = '' or l.ref_mangled = '...' or "
                           "substr(l.ref_mangled, 1, 4) = 'sub_' or substr(l.ref_mangled, 1, 7) = 'nullsub' "
                           "then l.ref_name else l.ref_mangled end)"),
                  "0");
    CHECK_TEXT_EQ(One(Out, "select count(*) from dsig_port_log where action = 'applied'"),
                  One(Out, "select count(*) from dsig_name_origin"));
    CHECK_TEXT_EQ(NonLabelFingerprint(Out), NonLabelFingerprint(Target));
    CHECK_TEXT_EQ(One(Out, "pragma quick_check"), "ok");
    CHECK(WalHeader(Out));
    CHECK_TEXT_EQ(FileSha(Ref), RefSha);
    CHECK_TEXT_EQ(FileSha(Target), TargetSha);
    CHECK_TEXT_EQ(FileSha(Results), ResultsSha);

    // A results file of another reference is refused by the name check: the cryptbase 8875 -> 9444
    // results were computed on 8875-pdb, not on the hop-1 output built from 8875-nopdb.
    if (std::string(P.Id) == "cryptbase-1-pdb_vs_8875-nopdb") {
      const std::string Other = DSig::Test::OracleResultsPath("cryptbase-8875-pdb_vs_9444-nopdb", 1);
      if (Exists(Other) && DSig::Test::ExportAvailable("cryptbase-9444-nopdb")) {
        const Cli::CommandOutcome Mismatch = Cli::RunPortFromResults(
            Args(Out, DSig::Test::ExportPath("cryptbase-9444-nopdb"),
                 (std::filesystem::path(Dir) / "mismatch.sqlite").string(), Other));
        CHECK_NUM_EQ(Mismatch.ExitCode, Cli::kExitUnsupported);
        CHECK(Mismatch.Message.find("belongs to another pair") != std::string::npos);
      }
    }
  }
  if (Ported == 0) {
    DSig::Test::Skip(Name, "no finished oracle pair with both exports present");
  }
  DSig::Test::RemoveScratchDir(Dir);
}

}

int main() {
  const std::string Dir = ScratchDir("cli_port_results");
  TestHelpers();
  TestDefaultPort((std::filesystem::path(Dir) / "default").string());
  TestOptInCategories((std::filesystem::path(Dir) / "optin").string());
  TestChain((std::filesystem::path(Dir) / "chain").string());
  TestPathSafety((std::filesystem::path(Dir) / "safety").string());
  TestAliasHelpers((std::filesystem::path(Dir) / "alias-helpers").string());
  TestDerivedPathAliases((std::filesystem::path(Dir) / "alias").string());
  TestLegacyPortAliases((std::filesystem::path(Dir) / "alias-legacy").string());
  TestOriginInheritance((std::filesystem::path(Dir) / "origin").string());
  TestBadInputs((std::filesystem::path(Dir) / "bad").string());
  TestWal((std::filesystem::path(Dir) / "wal").string());
  TestCorpus();
  DSig::Test::RemoveScratchDir(Dir);
  return DSig::Test::Finish();
}
