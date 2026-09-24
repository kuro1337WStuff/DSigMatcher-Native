// find_related_compilation_unit (D:3395-3460) and its native cartesian replay (spec 06 §9,
// 07 §10.11.3, 02 §18.3). D: = diaphora.py at 3.4.2-4-g621ec26, C: = diaphora_config.py.
//
// The pass, for every best-then-partial match with ratio >= 0.8, looks up the first compilation unit
// of each function by name (Path A, fetchone) and replays
//   select <SELECT_FIELDS 'Related compilation unit'> from functions f, diff.functions df
//    where cast(f.address as real) between ? and ? and cast(df.address as real) between ? and ?
// through add_matches_internal (1,000,000-row cap). On the real exports that query plans as
// `SCAN f` / `SCAN df` (02 Appendix C, 06 Open question 1): a nested loop over both tables in rowid
// (= id) order with the f range tested in the outer loop, so its rows are the pairs (f.id, df.id) in
// ascending order among the functions whose SQLite `cast(address as real)` lies in each range.
// CuReplaySource produces exactly that sequence from the ingested tables (FunctionTable is loaded
// `order by f.id`, and AddressSqlReal is SQLite's own cast of the same column), without
// materialising the ~45 SELECT_FIELDS columns per row (06 §9.2). It is used only when
// EXPLAIN QUERY PLAN still says `SCAN f` / `SCAN df`; otherwise, and with --related-cu-source sql,
// the verbatim SQL runs through SqlRowSource.

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "dsigmatcher/diff/Config.h"
#include "dsigmatcher/diff/Consumer.h"
#include "dsigmatcher/diff/Errors.h"
#include "dsigmatcher/diff/Pipeline.h"
#include "dsigmatcher/diff/PyValue.h"
#include "dsigmatcher/diff/StageSql.h"
#include "dsigmatcher/diff/Stages.h"

namespace DSig::Diff {

namespace {

// H:52 `{heur} description` with heur = repr("Related compilation unit") (D:3408, D:3429).
constexpr std::string_view kCuHeuristic = "Related compilation unit";

// Python's binding of a name (D:3444, D:3447): a str is bound as TEXT, None as NULL (which matches no
// row: `f.name = NULL` is never true).
BindValue BindName(const DiffSession& S, NameId Name) {
  if (Name == kNoneName) {
    return BindValue::Null();
  }
  return BindValue::Str(S.Ids().NameText(Name));
}

// One row of the CU lookup (D:3419-3425): only start_ea / end_ea are read afterwards (D:3453-3456).
struct CuRow {
  SqlCell StartEa;
  SqlCell EndEa;
};

// cur.execute(sql_{main,diff}, (name,)); row = cur.fetchone() (D:3444-3448). Returns nullopt when
// fetchone() is None. The fetch converts every column of the row with db.text_factory = str (D:346):
// a TEXT value that is not valid UTF-8 raises OperationalError there, on the main thread, so the diff
// aborts (01 §13). `SELECT distinct` with `USE TEMP B-TREE FOR DISTINCT` keeps the join order, so the
// first row is the function's compilation_unit_functions link with the lowest rowid among the
// functions of that name in ascending id (06 §9.2 first_cu, 07 §10.11.3); running the verbatim SQL
// reproduces that without assuming it.
std::optional<CuRow> CuLookup(DiffSession& S, std::string_view Sql, NameId Name, const char* Site) {
  const BindValue Bind = BindName(S, Name);
  Statement Stmt = S.Db().Prepare(Sql, std::span<const BindValue>(&Bind, 1));
  if (!Stmt.Step()) {
    return std::nullopt;
  }
  const int Count = Stmt.ColumnCount();
  for (int Column = 0; Column < Count; ++Column) {
    if (Stmt.Type(Column) == SqlType::Text && !IsValidUtf8(Stmt.Text(Column))) {
      throw DiaphoraWouldRaise(Site, "OperationalError: Could not decode to UTF-8 column '" +
                                         std::string(Stmt.ColumnName(Column)) + "'");
    }
  }
  const int ColStart = Stmt.FindColumn("start_ea");
  const int ColEnd = Stmt.FindColumn("end_ea");
  if (ColStart < 0 || ColEnd < 0) {
    throw UnsupportedInput("related CU lookup: the query does not select start_ea / end_ea");
  }
  return CuRow{Stmt.Cell(ColStart), Stmt.Cell(ColEnd)};
}

// float(main_row["start_ea"]) and its siblings (D:3453-3456). compilation_units.start_ea / end_ea are
// TEXT-affinity columns (db_support/schema.py:180-181), so a stored value is TEXT, BLOB or NULL:
//   * None  -> TypeError (06 Hard parts 6);
//   * str   -> Python float() (PyFloat: correctly rounded; ValueError where Python raises; non-ASCII
//              text is refused by PyFloat with UnsupportedInput);
//   * bytes -> float(bytes) parses the raw bytes without the Unicode mapping of str (PyFloat_FromString,
//              Objects/floatobject.c), so a non-ASCII byte fails with ValueError.
// INTEGER / REAL storage needs a foreign schema: float(float) is the value itself, float(int) is exact
// up to 2^53; anything else is refused instead of relying on the C++ conversion's rounding.
double PyFloatOfCell(const SqlCell& Cell, const char* Site) {
  switch (Cell.Type) {
    case SqlType::Null:
      throw DiaphoraWouldRaise(Site, "TypeError: float() argument must be a string or a real number, not 'NoneType'");
    case SqlType::Real:
      return Cell.Real;
    case SqlType::Integer: {
      constexpr int64_t kExact = int64_t{1} << 53;
      if (Cell.Int < -kExact || Cell.Int > kExact) {
        throw UnsupportedInput(std::string(Site) + ": float() of an INTEGER CU bound beyond 2^53 is not ported");
      }
      return static_cast<double>(Cell.Int);
    }
    case SqlType::Blob:
      for (const char Ch : Cell.Bytes) {
        if (static_cast<unsigned char>(Ch) >= 0x80) {
          throw DiaphoraWouldRaise(Site, "ValueError: could not convert string to float (non-ASCII bytes)");
        }
      }
      [[fallthrough]];
    case SqlType::Text: {
      const std::optional<double> Value = PyFloat(Cell.Bytes);
      if (!Value) {
        throw DiaphoraWouldRaise(Site, "ValueError: could not convert string to float: '" + Cell.Bytes + "'");
      }
      return *Value;
    }
  }
  throw UnsupportedInput(std::string(Site) + ": unknown storage class");
}

// The EXPLAIN QUERY PLAN guard, evaluated once per open connection.
struct CuPlanCache {
  const void* Handle = nullptr;
  bool Known = false;
  bool Ok = false;
};

// `between ? and ?` with the bound Python floats (D:3432-3433, D:3457): x >= lo AND x <= hi on SQLite
// REAL values. A NaN bound is stored by sqlite3_bind_double as NULL, which makes BETWEEN NULL and the
// row is not selected; the IEEE comparisons below are false for NaN as well. A NULL address gives a
// NULL cast and is never selected either (AddressSqlNull).
std::vector<uint32_t> RowsInRange(const FunctionTable& T, double Lo, double Hi) {
  std::vector<uint32_t> Rows;
  const size_t Count = T.Count();
  for (size_t Row = 0; Row < Count; ++Row) {
    if (T.AddressSqlNull[Row] != 0) {
      continue;
    }
    const double X = T.AddressSqlReal[Row];
    if (X >= Lo && X <= Hi) {
      Rows.push_back(static_cast<uint32_t>(Row));
    }
  }
  return Rows;
}

}

// ---------------------------------------------------------------------------------------------
// CuReplaySource

struct CuReplaySource::Impl {
  DiffSession& S;
  std::vector<uint32_t> Rows1;  // f rows in range, ascending id (outer loop)
  std::vector<uint32_t> Rows2;  // df rows in range, ascending id (inner loop)
  size_t Outer = 0;
  size_t Inner = 0;
  uint64_t Fetched = 0;
  DescId Desc{};

  Impl(DiffSession& Session, double Lo1, double Hi1, double Lo2, double Hi2)
      : S(Session),
        Rows1(RowsInRange(Session.Main().Functions, Lo1, Hi1)),
        Rows2(RowsInRange(Session.Diff().Functions, Lo2, Hi2)),
        Desc(Session.Ids().Desc(kCuHeuristic)) {}

  // SqlRowSource::Next's per-row conversions (Database.cpp), in the same order, on the ingested cells:
  // (1) the fetch-time UTF-8 check of the SELECT_FIELDS columns of both functions (a BLOB address maps
  // to no row there, so that side is not checked), (2) ea / ea2 must be TEXT, (3) name1 / name2 TEXT or
  // NULL, (4) nodes INTEGER or NULL, (5) md1 / md2 = SQLite's cast(md_index as real) (H:57).
  void Fill(uint32_t R1, uint32_t R2, HeuristicRow& Out) const {
    const FunctionTable& Main = S.Main().Functions;
    const FunctionTable& Diff = S.Diff().Functions;
    const bool Blob1 = Main.Address.IsBlob[R1] != 0;
    const bool Blob2 = Diff.Address.IsBlob[R2] != 0;
    if ((!Blob1 && Main.SelectFieldsUtf8Bad[R1] != 0) || (!Blob2 && Diff.SelectFieldsUtf8Bad[R2] != 0)) {
      throw DiaphoraWouldRaise("fetch", "Could not decode to UTF-8 a SELECT_FIELDS column (invalid UTF-8)");
    }
    if (Blob1) {
      throw UnsupportedInput("row alias 'ea' is not TEXT (input quirk not emulated)");
    }
    if (Blob2) {
      throw UnsupportedInput("row alias 'ea2' is not TEXT (input quirk not emulated)");
    }
    HeuristicRow Row;
    Row.Side1 = Side::Main;
    Row.Side2 = Side::Diff;
    Row.Row1 = R1;
    Row.Row2 = R2;
    Row.Ea1 = Main.AddrIdOf[R1];
    Row.Ea2 = Diff.AddrIdOf[R2];
    if (Main.Name.IsBlob[R1] != 0) {
      throw UnsupportedInput("row alias 'name1' is not TEXT or NULL");
    }
    if (Diff.Name.IsBlob[R2] != 0) {
      throw UnsupportedInput("row alias 'name2' is not TEXT or NULL");
    }
    Row.Name1 = Main.NameIdOf[R1];
    Row.Name2 = Diff.NameIdOf[R2];
    Row.Desc = Desc;
    const auto Nodes = [](const IntColumn& Column, uint32_t R, const char* Alias) -> std::optional<int64_t> {
      if (Column.Null(R)) {
        return std::nullopt;
      }
      if (Column.NotInteger[R] != 0) {
        throw UnsupportedInput(std::string("row alias '") + Alias +
                               "' is not INTEGER or NULL (int() semantics not emulated)");
      }
      return Column.Value[R];
    };
    Row.Nodes1 = Nodes(Main.Nodes, R1, "nodes1");
    Row.Nodes2 = Nodes(Diff.Nodes, R2, "nodes2");
    // md1/md2 must be the SQL cast, as SqlRowSource reads them; left unset, check_ratio would raise
    // float(None) where Python does not.
    if (Main.MdSqlNull[R1] == 0) {
      Row.Md1 = Main.MdSqlReal[R1];
    }
    if (Diff.MdSqlNull[R2] == 0) {
      Row.Md2 = Diff.MdSqlReal[R2];
    }
    Out = Row;
  }
};

CuReplaySource::CuReplaySource(DiffSession& S, double Lo1, double Hi1, double Lo2, double Hi2)
    : Impl_(std::make_unique<Impl>(S, Lo1, Hi1, Lo2, Hi2)) {}

CuReplaySource::~CuReplaySource() = default;

bool CuReplaySource::Next(HeuristicRow& Out) {
  Impl& I = *Impl_;
  if (I.Rows2.empty() || I.Outer >= I.Rows1.size()) {
    return false;
  }
  I.Fill(I.Rows1[I.Outer], I.Rows2[I.Inner], Out);
  ++I.Fetched;
  if (++I.Inner == I.Rows2.size()) {
    I.Inner = 0;
    ++I.Outer;
  }
  return true;
}

uint64_t CuReplaySource::Fetched() const { return Impl_->Fetched; }

bool CuReplayPlanOk(DiffSession& S) {
  CuPlanCache& Cache = S.Ext<CuPlanCache>();
  const void* Handle = S.Db().Handle();
  if (Cache.Known && Cache.Handle == Handle) {
    return Cache.Ok;
  }
  bool Ok = false;
  try {
    // 02 Appendix C / 06 Open question 1: the plan on every real pair is exactly these two loops, f
    // outer. Anything else (another SQLite, other statistics, an automatic index, a covering index,
    // df outer) sends the pass to the verbatim SQL.
    const std::vector<PlanRow> Plan = S.Db().ExplainQueryPlan(kSqlCuCartesian);
    Ok = Plan.size() == 2 && Plan[0].Detail == "SCAN f" && Plan[1].Detail == "SCAN df" && Plan[0].Parent == 0 &&
         Plan[1].Parent == 0;
  } catch (const DiaphoraWouldRaise&) {
    // The statement does not prepare: the SQL path raises at the same execute as Python (D:3457).
    Ok = false;
  }
  Cache.Handle = Handle;
  Cache.Known = true;
  Cache.Ok = Ok;
  return Ok;
}

// ---------------------------------------------------------------------------------------------
// find_related_compilation_unit

void StageFindRelatedCompilationUnit(DiffSession& S, int /*Iteration*/) {
  // D:3408-3411: call_hook("on_special_heuristic", True, ...) returns the default True: no hooks are
  // loaded in mode N, and scripts/patch_diff_vulns.py (the hooks of mode P) defines no
  // on_special_heuristic.
  S.Cleanup(CleanupSite::L3413);  // D:3413
  // D:3414 log_refresh only.
  // D:3416-3417: ONE list, best then partial, each stably sorted by ratio descending (a snapshot:
  // the adds below do not change it).
  std::vector<Item> Seeds = S.State().SortedResults(Chooser::Best);
  {
    const std::vector<Item> Partial = S.State().SortedResults(Chooser::Partial);
    Seeds.insert(Seeds.end(), Partial.begin(), Partial.end());
  }
  const bool Native = S.CuSource() == RelatedCuSource::Native;
  for (const Item& Match : Seeds) {  // D:3437; no dedup across seeds (06 §9.2 notes)
    // D:3438-3440: `ratio < RELATED_MATCHES_MIN_RATIO` (C:194, 0.8) ends the WHOLE loop.
    if (Match.Ratio < kRelatedMatchesMinRatio) {
      break;
    }
    // D:3442-3448: both lookups run (and fetch) before the None test.
    const std::optional<CuRow> MainCu = CuLookup(S, kSqlCuLookupMain, Match.Name1, "D:3445 fetchone (main CU)");
    const std::optional<CuRow> DiffCu = CuLookup(S, kSqlCuLookupDiff, Match.Name2, "D:3448 fetchone (diff CU)");
    if (!MainCu || !DiffCu) {  // D:3450-3451
      continue;
    }
    // D:3453-3456, in this order.
    const double Lo1 = PyFloatOfCell(MainCu->StartEa, "D:3453 float(start_ea)");
    const double Hi1 = PyFloatOfCell(MainCu->EndEa, "D:3454 float(end_ea)");
    const double Lo2 = PyFloatOfCell(DiffCu->StartEa, "D:3455 float(start_ea)");
    const double Hi2 = PyFloatOfCell(DiffCu->EndEa, "D:3456 float(end_ea)");
    // D:3457-3458: execute with the four floats bound as REAL, then add_matches_internal(cur, "best",
    // "partial") (val None -> 0.5, unreliable None, the 1,000,000-row cap).
    if (Native && CuReplayPlanOk(S)) {
      CuReplaySource Rows(S, Lo1, Hi1, Lo2, Hi2);
      AddMatchesInternal(S, Rows, Chooser::Best, Chooser::Partial);
    } else {
      SqlRowSource Rows(S, std::string(kSqlCuCartesian),
                        {BindValue::Double(Lo1), BindValue::Double(Hi1), BindValue::Double(Lo2), BindValue::Double(Hi2)});
      AddMatchesInternal(S, Rows, Chooser::Best, Chooser::Partial);
    }
  }
}

}
