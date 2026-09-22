#include "dsigmatcher/ExportDatabase.h"

#include <sqlite3.h>

#include <algorithm>
#include <cstring>
#include <unordered_set>
#include <vector>

namespace DSig {

namespace {

enum class Field : uint8_t {
  None,
  Id,
  Name,
  Address,
  Rva,
  SegmentRva,
  MangledFunction,
  BytesHash,
  FunctionHash,
  KghHash,
  MdIndex,
  Mnemonics,
  CleanAssembly,
  CleanPseudo,
  CleanMicrocode,
  SourceFile,
  Nodes,
  Edges,
  Instructions,
  Size,
  CyclomaticComplexity,
  Indegree,
  Outdegree,
  ConstantsCount,
  Loops,
  StronglyConnected,
  PseudocodeLines
};

struct WantedColumn {
  const char* Name;
  Field Target;
  bool IsText;
};

const WantedColumn Columns[] = {
  {"id", Field::Id, false},
  {"name", Field::Name, true},
  {"address", Field::Address, true},
  {"rva", Field::Rva, true},
  {"segment_rva", Field::SegmentRva, true},
  {"mangled_function", Field::MangledFunction, true},
  {"bytes_hash", Field::BytesHash, true},
  {"function_hash", Field::FunctionHash, true},
  {"kgh_hash", Field::KghHash, true},
  {"md_index", Field::MdIndex, true},
  {"mnemonics", Field::Mnemonics, true},
  {"clean_assembly", Field::CleanAssembly, true},
  {"clean_pseudo", Field::CleanPseudo, true},
  {"clean_microcode", Field::CleanMicrocode, true},
  {"source_file", Field::SourceFile, true},
  {"nodes", Field::Nodes, false},
  {"edges", Field::Edges, false},
  {"instructions", Field::Instructions, false},
  {"size", Field::Size, false},
  {"cyclomatic_complexity", Field::CyclomaticComplexity, false},
  {"indegree", Field::Indegree, false},
  {"outdegree", Field::Outdegree, false},
  {"constants_count", Field::ConstantsCount, false},
  {"loops", Field::Loops, false},
  {"strongly_connected", Field::StronglyConnected, false},
  {"pseudocode_lines", Field::PseudocodeLines, false},
};

std::unordered_set<std::string> ReadTableColumns(sqlite3* Handle, const char* Table) {
  std::unordered_set<std::string> Result;
  std::string Query = std::string("pragma table_info(") + Table + ")";
  sqlite3_stmt* Statement = nullptr;
  if (sqlite3_prepare_v2(Handle, Query.c_str(), -1, &Statement, nullptr) != SQLITE_OK) {
    return Result;
  }
  while (sqlite3_step(Statement) == SQLITE_ROW) {
    const unsigned char* Text = sqlite3_column_text(Statement, 1);
    if (Text != nullptr) {
      Result.insert(reinterpret_cast<const char*>(Text));
    }
  }
  sqlite3_finalize(Statement);
  return Result;
}

std::string_view ColumnText(sqlite3_stmt* Statement, int Index) {
  const unsigned char* Text = sqlite3_column_text(Statement, Index);
  if (Text == nullptr) {
    return std::string_view();
  }
  const int Length = sqlite3_column_bytes(Statement, Index);
  return std::string_view(reinterpret_cast<const char*>(Text), static_cast<size_t>(Length));
}

}

LoadResult ExportDatabase::Load(const std::string& Path, FunctionTable& OutTable, ProgramInfo& OutProgram) {
  LoadResult Result;

  sqlite3* Handle = nullptr;
  const int OpenCode = sqlite3_open_v2(Path.c_str(), &Handle, SQLITE_OPEN_READONLY, nullptr);
  if (OpenCode != SQLITE_OK) {
    Result.Error = Handle != nullptr ? sqlite3_errmsg(Handle) : "unable to allocate database handle";
    if (Handle != nullptr) {
      sqlite3_close(Handle);
    }
    return Result;
  }

  const std::unordered_set<std::string> Available = ReadTableColumns(Handle, "functions");
  if (Available.empty()) {
    Result.Error = "table 'functions' is missing or unreadable; not a Diaphora export";
    sqlite3_close(Handle);
    return Result;
  }

  std::string SelectList;
  std::vector<Field> Present;
  for (const WantedColumn& Column : Columns) {
    if (Available.find(Column.Name) == Available.end()) {
      continue;
    }
    if (!SelectList.empty()) {
      SelectList += ", ";
    }
    SelectList += Column.Name;
    Present.push_back(Column.Target);
  }

  const std::string Query = "select " + SelectList + " from functions";
  sqlite3_stmt* Statement = nullptr;
  if (sqlite3_prepare_v2(Handle, Query.c_str(), -1, &Statement, nullptr) != SQLITE_OK) {
    Result.Error = sqlite3_errmsg(Handle);
    sqlite3_close(Handle);
    return Result;
  }

  const int ResultColumns = sqlite3_column_count(Statement);
  std::vector<Field> SlotMap(static_cast<size_t>(ResultColumns), Field::None);
  for (int Index = 0; Index < ResultColumns; ++Index) {
    const char* NameText = sqlite3_column_name(Statement, Index);
    if (NameText == nullptr) {
      continue;
    }
    const auto Found = std::find_if(Present.begin(), Present.end(), [&](Field Candidate) {
      for (const WantedColumn& Column : Columns) {
        if (Column.Target == Candidate) {
          return std::strcmp(Column.Name, NameText) == 0;
        }
      }
      return false;
    });
    if (Found != Present.end()) {
      SlotMap[static_cast<size_t>(Index)] = *Found;
    }
  }

  sqlite3_stmt* CountStatement = nullptr;
  if (sqlite3_prepare_v2(Handle, "select count(*) from functions", -1, &CountStatement, nullptr) == SQLITE_OK) {
    if (sqlite3_step(CountStatement) == SQLITE_ROW) {
      OutTable.Reserve(static_cast<size_t>(sqlite3_column_int64(CountStatement, 0)));
    }
    sqlite3_finalize(CountStatement);
  }

  while (sqlite3_step(Statement) == SQLITE_ROW) {
    const size_t Row = OutTable.Id.size();
    OutTable.Resize(Row + 1);

    for (int Index = 0; Index < ResultColumns; ++Index) {
      switch (SlotMap[static_cast<size_t>(Index)]) {
      case Field::None:
        break;
      case Field::Id:
        OutTable.Id[Row] = sqlite3_column_int64(Statement, Index);
        break;
      case Field::Nodes:
        OutTable.Nodes[Row] = sqlite3_column_int64(Statement, Index);
        break;
      case Field::Edges:
        OutTable.Edges[Row] = sqlite3_column_int64(Statement, Index);
        break;
      case Field::Instructions:
        OutTable.Instructions[Row] = sqlite3_column_int64(Statement, Index);
        break;
      case Field::Size:
        OutTable.Size[Row] = sqlite3_column_int64(Statement, Index);
        break;
      case Field::CyclomaticComplexity:
        OutTable.CyclomaticComplexity[Row] = sqlite3_column_int64(Statement, Index);
        break;
      case Field::Indegree:
        OutTable.Indegree[Row] = sqlite3_column_int64(Statement, Index);
        break;
      case Field::Outdegree:
        OutTable.Outdegree[Row] = sqlite3_column_int64(Statement, Index);
        break;
      case Field::ConstantsCount:
        OutTable.ConstantsCount[Row] = sqlite3_column_int64(Statement, Index);
        break;
      case Field::Loops:
        OutTable.Loops[Row] = sqlite3_column_int64(Statement, Index);
        break;
      case Field::StronglyConnected:
        OutTable.StronglyConnected[Row] = sqlite3_column_int64(Statement, Index);
        break;
      case Field::PseudocodeLines:
        OutTable.PseudocodeLines[Row] = sqlite3_column_int64(Statement, Index);
        break;
      case Field::Name:
        OutTable.Name[Row] = OutTable.Pool.Append(ColumnText(Statement, Index));
        break;
      case Field::Address:
        OutTable.Address[Row] = OutTable.Pool.Append(ColumnText(Statement, Index));
        break;
      case Field::Rva:
        OutTable.Rva[Row] = OutTable.Pool.Append(ColumnText(Statement, Index));
        break;
      case Field::SegmentRva:
        OutTable.SegmentRva[Row] = OutTable.Pool.Append(ColumnText(Statement, Index));
        break;
      case Field::MangledFunction:
        OutTable.MangledFunction[Row] = OutTable.Pool.Append(ColumnText(Statement, Index));
        break;
      case Field::BytesHash:
        OutTable.BytesHash[Row] = OutTable.Pool.Append(ColumnText(Statement, Index));
        break;
      case Field::FunctionHash:
        OutTable.FunctionHash[Row] = OutTable.Pool.Append(ColumnText(Statement, Index));
        break;
      case Field::KghHash:
        OutTable.KghHash[Row] = OutTable.Pool.Append(ColumnText(Statement, Index));
        break;
      case Field::MdIndex:
        OutTable.MdIndex[Row] = OutTable.Pool.Append(ColumnText(Statement, Index));
        break;
      case Field::Mnemonics:
        OutTable.Mnemonics[Row] = OutTable.Pool.Append(ColumnText(Statement, Index));
        break;
      case Field::CleanAssembly:
        OutTable.CleanAssembly[Row] = OutTable.Pool.Append(ColumnText(Statement, Index));
        break;
      case Field::CleanPseudo:
        OutTable.CleanPseudo[Row] = OutTable.Pool.Append(ColumnText(Statement, Index));
        break;
      case Field::CleanMicrocode:
        OutTable.CleanMicrocode[Row] = OutTable.Pool.Append(ColumnText(Statement, Index));
        break;
      case Field::SourceFile:
        OutTable.SourceFile[Row] = OutTable.Pool.Append(ColumnText(Statement, Index));
        break;
      }
    }
  }

  sqlite3_finalize(Statement);
  Result.RowsRead = static_cast<int64_t>(OutTable.Id.size());

  const std::unordered_set<std::string> ProgramColumns = ReadTableColumns(Handle, "program");
  if (!ProgramColumns.empty()) {
    sqlite3_stmt* ProgramStatement = nullptr;
    if (sqlite3_prepare_v2(Handle, "select processor, md5sum, callgraph_primes from program limit 1", -1,
                           &ProgramStatement, nullptr) == SQLITE_OK) {
      if (sqlite3_step(ProgramStatement) == SQLITE_ROW) {
        OutProgram.Present = true;
        OutProgram.Processor = std::string(ColumnText(ProgramStatement, 0));
        OutProgram.Md5Sum = std::string(ColumnText(ProgramStatement, 1));
        OutProgram.CallgraphPrimes = std::string(ColumnText(ProgramStatement, 2));
      }
      sqlite3_finalize(ProgramStatement);
    }
  }

  sqlite3_close(Handle);
  Result.Ok = true;
  return Result;
}

}
