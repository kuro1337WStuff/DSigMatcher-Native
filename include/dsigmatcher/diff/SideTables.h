#pragma once

// Side-table facts of one export (docs/parity/00-plan.md §3.3). The contents of `constants`,
// `compilation_units`, `compilation_unit_functions`, `instructions` and `bb_instructions` are only
// ever read through Path A SQL; ingest records their presence and row counts. The `program` rows and
// the `version` rows are loaded because preflight (L5) needs them.

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "dsigmatcher/diff/Database.h"

namespace DSig::Diff {

enum class Side : uint8_t { Main = 0, Diff = 1 };

inline std::string_view SchemaName(Side Which) { return Which == Side::Main ? "main" : "diff"; }

struct TableInfo {
  std::string Name;
  bool Present = false;
  int64_t Rows = 0;
  std::vector<std::string> Columns;  // pragma table_info order
};

// `select id, callgraph_primes, callgraph_all_primes, processor, md5sum from program order by id`
// (08 §9.2). md5sum is a BLOB in IDA 9.x exports (08 Summary).
struct ProgramRow {
  SqlCell Id;
  SqlCell CallgraphPrimes;
  SqlCell CallgraphAllPrimes;
  SqlCell Processor;
  SqlCell Md5sum;
};

struct SideTables {
  // The 13 db_support/schema.py tables plus sqlite_stat1, in schema order.
  std::vector<TableInfo> Tables;
  std::vector<ProgramRow> Program;  // order by id
  std::vector<SqlCell> Version;     // `select value from version`, scan order (D:3578 fetchone reads [0])
  int IndexCount = 0;               // indices named idx_* (create_indices, D:634-649)
  bool HasStat1 = false;

  const TableInfo* Find(std::string_view Name) const;
  bool Has(std::string_view Name) const;
  int64_t Rows(std::string_view Name) const;  // 0 when absent
};

// The table names SideTables records, in the order above.
const std::vector<std::string>& SideTableNames();

// Loads SideTables for `Which` through the shared connection (schema "main" or "diff").
// Missing tables are recorded, never an error. Throws DiaphoraWouldRaise only on SQL failure.
void LoadSideTables(const DiffDatabase& Db, Side Which, SideTables& Out);

}
