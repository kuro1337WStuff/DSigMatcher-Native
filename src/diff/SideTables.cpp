// Side-table facts of one export (08 §7-§8).

#include "dsigmatcher/diff/SideTables.h"

#include <algorithm>

#include "dsigmatcher/diff/Errors.h"

namespace DSig::Diff {

const std::vector<std::string>& SideTableNames() {
  // db_support/schema.py TABLES order (functions .. compilation_unit_functions), then sqlite_stat1.
  static const std::vector<std::string> Names = {
      "functions",       "program",   "program_data",      "version",
      "instructions",    "basic_blocks", "bb_relations",   "bb_instructions",
      "function_bblocks", "callgraph", "constants",        "compilation_units",
      "compilation_unit_functions", "sqlite_stat1"};
  return Names;
}

const TableInfo* SideTables::Find(std::string_view Name) const {
  for (const TableInfo& Info : Tables) {
    if (Info.Name == Name) {
      return &Info;
    }
  }
  return nullptr;
}

bool SideTables::Has(std::string_view Name) const {
  const TableInfo* Info = Find(Name);
  return Info != nullptr && Info->Present;
}

int64_t SideTables::Rows(std::string_view Name) const {
  const TableInfo* Info = Find(Name);
  return Info != nullptr && Info->Present ? Info->Rows : 0;
}

void LoadSideTables(const DiffDatabase& Db, Side Which, SideTables& Out) {
  Out = SideTables();
  const std::string Schema(SchemaName(Which));
  for (const std::string& Name : SideTableNames()) {
    TableInfo Info;
    Info.Name = Name;
    Info.Present = Db.TableExists(Schema, Name);
    if (Info.Present) {
      Statement Count = Db.Prepare("select count(*) from " + Schema + "." + Name);
      if (Count.Step()) {
        Info.Rows = Count.Int(0);
      }
      Statement Columns = Db.Prepare("pragma " + Schema + ".table_info(" + Name + ")");
      while (Columns.Step()) {
        Info.Columns.emplace_back(Columns.Text(1));
      }
    }
    Out.Tables.push_back(std::move(Info));
  }
  Out.HasStat1 = Out.Has("sqlite_stat1");

  // create_indices (D:634-649) names them idx_<position in schema.INDICES>.
  {
    Statement Count = Db.Prepare("select count(*) from " + Schema +
                                 ".sqlite_master where type = 'index' and name like 'idx\\_%' escape '\\'");
    if (Count.Step()) {
      Out.IndexCount = static_cast<int>(Count.Int(0));
    }
  }

  if (const TableInfo* Program = Out.Find("program"); Program != nullptr && Program->Present) {
    // 08 §9.2; a column an old export lacks stays NULL.
    const char* const Wanted[] = {"id", "callgraph_primes", "callgraph_all_primes", "processor", "md5sum"};
    std::string Select;
    for (const char* Column : Wanted) {
      const bool Present =
          std::find(Program->Columns.begin(), Program->Columns.end(), std::string(Column)) != Program->Columns.end();
      Select += Select.empty() ? "" : ", ";
      Select += Present ? std::string(Column) : std::string("null");
    }
    const bool HasId =
        std::find(Program->Columns.begin(), Program->Columns.end(), std::string("id")) != Program->Columns.end();
    Statement Rows = Db.Prepare("select " + Select + " from " + Schema + ".program" +
                                (HasId ? " order by id" : ""));
    while (Rows.Step()) {
      ProgramRow Row;
      Row.Id = Rows.Cell(0);
      Row.CallgraphPrimes = Rows.Cell(1);
      Row.CallgraphAllPrimes = Rows.Cell(2);
      Row.Processor = Rows.Cell(3);
      Row.Md5sum = Rows.Cell(4);
      Out.Program.push_back(std::move(Row));
    }
  }

  if (const TableInfo* Version = Out.Find("version"); Version != nullptr && Version->Present) {
    const bool HasValue =
        std::find(Version->Columns.begin(), Version->Columns.end(), std::string("value")) != Version->Columns.end();
    if (HasValue) {
      // The shape of D:3578 `select value from diff.version` (scan order).
      Statement Rows = Db.Prepare("select value from " + Schema + ".version");
      while (Rows.Step()) {
        Out.Version.push_back(Rows.Cell(0));
      }
    }
  }
}

}
