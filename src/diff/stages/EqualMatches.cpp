// Lane L5: find_equal_matches (D:1404-1442). Spec: 01 §5.5, 05 §5, 07 §10.7.
// D: = diaphora.py at 3.4.2-4-g621ec26.
//
// Both queries run through Path A (kSqlTotals, kSqlEqualMatches). The INTERSECT query has no ORDER BY:
// its row order is SQLite's (INTERSECT USING TEMP B-TREE, ascending by the whole tuple, which starts
// with the unique `id`: 05 §5 "Order"), so it is never re-sorted here.

#include <optional>
#include <string>
#include <vector>

#include "EarlyPasses.h"
#include "dsigmatcher/diff/Errors.h"
#include "dsigmatcher/diff/Pipeline.h"
#include "dsigmatcher/diff/StageSql.h"
#include "dsigmatcher/diff/Stages.h"
#include "dsigmatcher/diff/Table.h"

namespace DSig::Diff {

namespace {

struct EqualRow {
  AddrId Ea = kNoneAddr;     // row["ea"] (f.address)
  NameId Name = kNoneName;   // row["mangled_function"]
  SqlType NodesType = SqlType::Null;
  int64_t Nodes = 0;         // row["nodes"]
};

// A TEXT cell of the fetched row, decoded as Python's sqlite3 decodes it (01 §13): invalid UTF-8
// raises OperationalError at fetch time.
void RequireDecodable(const Statement& Q, int Column) {
  if (Q.Type(Column) == SqlType::Text && !IsValidUtf8(Q.Text(Column))) {
    throw DiaphoraWouldRaise("fetch", "OperationalError: Could not decode to UTF-8 column '" +
                                          std::string(Q.ColumnName(Column)) + "'");
  }
}

}

void StageFindEqualMatches(DiffSession& S) {
  // D:1411-1415 `select count(*) total from functions union all select count(*) total from
  // diff.functions`; rows = cur.fetchall().
  {
    Statement Totals = S.Db().Prepare(kSqlTotals);
    std::vector<int64_t> Rows;
    while (Totals.Step()) {
      if (Totals.Type(0) != SqlType::Integer) {
        throw UnsupportedInput("find_equal_matches: a function count is not an INTEGER");
      }
      Rows.push_back(Totals.Int(0));
    }
    // D:1416-1419: dead, `union all` of two count(*) always gives two rows (05 §5).
    if (Rows.size() != 2) {
      throw DiaphoraWouldRaise("D:1419 Exception", "Malformed database!");
    }
    S.State().SetTotals(Rows[0], Rows[1]);  // D:1421-1422
  }

  // D:1424-1432: the INTERSECT of (id, address, mangled_function, nodes, edges, size, bytes_hash);
  // rows = cur.fetchall(): every row is fetched (and its TEXT cells decoded) before any is used.
  Statement Q = S.Db().Prepare(kSqlEqualMatches);
  const int ColEa = Q.FindColumn("ea");
  const int ColName = Q.FindColumn("mangled_function");
  const int ColNodes = Q.FindColumn("nodes");
  std::vector<EqualRow> Rows;
  while (Q.Step()) {
    const int Count = Q.ColumnCount();
    for (int Column = 0; Column < Count; ++Column) {
      RequireDecodable(Q, Column);  // ea, mangled_function, nodes, bytes_hash
    }
    EqualRow Row;
    switch (Q.Type(ColEa)) {
      case SqlType::Null:
        Row.Ea = kNoneAddr;  // Python None (two NULL addresses intersect: INTERSECT treats NULLs as equal)
        break;
      case SqlType::Text:
        Row.Ea = S.Ids().Addr(Q.Text(ColEa));
        break;
      default:
        // address is `text unique` (schema.py:72): an INTEGER/REAL/BLOB value would be a Python int,
        // float or bytes inside the item, which no export produces.
        throw UnsupportedInput("find_equal_matches: a non-TEXT address is not ported");
    }
    switch (Q.Type(ColName)) {
      case SqlType::Null:
        Row.Name = kNoneName;  // Python None: every such item shares the key None (05 §5)
        break;
      case SqlType::Text:
        Row.Name = S.Ids().Name(Q.Text(ColName));
        break;
      default:
        throw UnsupportedInput("find_equal_matches: a non-TEXT mangled_function is not ported");
    }
    Row.NodesType = Q.Type(ColNodes);
    if (Row.NodesType == SqlType::Integer) {
      Row.Nodes = Q.Int(ColNodes);
    }
    Rows.push_back(Row);
  }
  S.Ext<Early::EarlyFacts>().EqualRows = static_cast<int64_t>(Rows.size());

  const DescId Desc = S.Ids().Desc("100% equal");
  // D:1433-1440, in fetch order.
  for (const EqualRow& Row : Rows) {
    // D:1435-1436 name = row["mangled_function"]; ea = row["ea"]
    // D:1437 nodes = int(row["nodes"]): int(None) raises TypeError (main thread: the run aborts).
    if (Row.NodesType == SqlType::Null) {
      throw DiaphoraWouldRaise("D:1437 TypeError",
                               "int() argument must be a string, a bytes-like object or a real number, not 'NoneType'");
    }
    if (Row.NodesType != SqlType::Integer) {
      throw UnsupportedInput("find_equal_matches: a non-INTEGER nodes value (int() of it is not ported)");
    }
    // D:1439 item = [ea, name, ea, name, "100% equal", 1, nodes, nodes]: the int 1 is the double 1.0
    // (1 == 1.0 in `item not in list`, and "%.7f" prints both as 1.0000000).
    const Item It{Row.Ea, Row.Name, Row.Ea, Row.Name, Desc, 1.0, Row.Nodes, Row.Nodes};
    S.State().AddMatch(Row.Name, Row.Name, 1.0, It, Chooser::Best);  // D:1440
  }
}

}
