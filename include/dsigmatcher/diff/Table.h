#pragma once

// In-memory `functions` table of one export (docs/parity/00-plan.md §3.3; 07 §4.3; 08 §9).
//
// Loaded with `select f.*, cast(f.md_index as real), cast(f.address as real) from <schema>.functions f
// order by f.id`. Every cell's storage class is read with sqlite3_column_type before extraction:
// NULL stays NULL (never ''), TEXT keeps its exact bytes, and each text column has its own pool with
// 64-bit offsets (07 T5). Row index r is the r-th row in `order by id` order.

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "dsigmatcher/diff/Database.h"
#include "dsigmatcher/diff/Interner.h"
#include "dsigmatcher/diff/SideTables.h"

namespace DSig::Diff {

inline constexpr uint32_t kNoRow = 0xFFFFFFFFu;

// A TEXT-affinity column. IsBlob marks a BLOB cell (Python bytes); View() returns its raw bytes.
struct TextColumn {
  std::vector<char> Pool;
  std::vector<uint64_t> Offset;
  std::vector<uint32_t> Length;
  std::vector<uint8_t> IsNull;  // 1 = SQL NULL (Python None)
  std::vector<uint8_t> IsBlob;  // 1 = BLOB storage class

  size_t Size() const { return IsNull.size(); }
  bool Null(uint32_t Row) const { return IsNull[Row] != 0; }
  std::string_view View(uint32_t Row) const {
    return std::string_view(Pool.data() + Offset[Row], Length[Row]);
  }
  std::optional<std::string_view> Get(uint32_t Row) const {
    if (Null(Row)) {
      return std::nullopt;
    }
    return View(Row);
  }
  void Append(std::string_view Bytes, bool Blob = false);
  void AppendNull();
};

// An INTEGER-affinity column. NotInteger marks a cell whose storage class is REAL or TEXT; Value then
// holds sqlite3_column_int64's conversion and consumers must refuse or emulate it explicitly.
struct IntColumn {
  std::vector<int64_t> Value;
  std::vector<uint8_t> IsNull;
  std::vector<uint8_t> NotInteger;

  size_t Size() const { return IsNull.size(); }
  bool Null(uint32_t Row) const { return IsNull[Row] != 0; }
  std::optional<int64_t> Get(uint32_t Row) const {
    if (Null(Row)) {
      return std::nullopt;
    }
    return Value[Row];
  }
};

// The REAL-affinity column (export_time only; never read by the diff).
struct RealColumn {
  std::vector<double> Value;
  std::vector<uint8_t> IsNull;
  std::vector<uint8_t> NotReal;

  size_t Size() const { return IsNull.size(); }
  bool Null(uint32_t Row) const { return IsNull[Row] != 0; }
};

enum class ColumnKind : uint8_t { Integer, Text, Real };

struct FunctionTable {
  size_t Count() const { return Id.Size(); }

  // All 49 columns of db_support/schema.py:69-118, in schema order.
  IntColumn Id;
  TextColumn Name;
  TextColumn Address;
  IntColumn Nodes;
  IntColumn Edges;
  IntColumn Indegree;
  IntColumn Outdegree;
  IntColumn Size;
  IntColumn Instructions;
  TextColumn Mnemonics;
  TextColumn Names;
  TextColumn Prototype;
  IntColumn CyclomaticComplexity;
  TextColumn PrimesValue;
  TextColumn Comment;
  TextColumn MangledFunction;
  TextColumn BytesHash;
  TextColumn Pseudocode;
  IntColumn PseudocodeLines;
  TextColumn PseudocodeHash1;
  TextColumn PseudocodePrimes;
  IntColumn FunctionFlags;
  TextColumn Assembly;
  TextColumn Prototype2;
  TextColumn PseudocodeHash2;
  TextColumn PseudocodeHash3;
  IntColumn StronglyConnected;
  IntColumn Loops;
  TextColumn Rva;
  TextColumn TarjanTopologicalSort;
  TextColumn StronglyConnectedSpp;
  TextColumn CleanAssembly;
  TextColumn CleanPseudo;
  TextColumn MnemonicsSpp;
  TextColumn Switches;
  TextColumn FunctionHash;
  IntColumn BytesSum;
  TextColumn MdIndex;
  TextColumn Constants;
  IntColumn ConstantsCount;
  TextColumn SegmentRva;
  TextColumn AssemblyAddrs;
  TextColumn KghHash;
  TextColumn SourceFile;
  TextColumn Userdata;
  TextColumn Microcode;
  TextColumn CleanMicrocode;
  TextColumn MicrocodeSpp;
  RealColumn ExportTime;

  // `cast(f.md_index as real)` evaluated by SQLite itself: the md1/md2 of SELECT_FIELDS (H:57).
  // SQLite's cast is not correctly rounded (07 §5.3), so this must never be recomputed natively.
  std::vector<double> MdSqlReal;
  std::vector<uint8_t> MdSqlNull;
  // `cast(f.address as real)`, the value the related-CU cartesian compares (D:3432-3433).
  std::vector<double> AddressSqlReal;
  std::vector<uint8_t> AddressSqlNull;
  // 1 when a SELECT_FIELDS source column (H:51-75) of the row is TEXT with invalid UTF-8: Python's
  // fetch of such a row raises OperationalError (01 §13, db.text_factory = str at D:346).
  std::vector<uint8_t> SelectFieldsUtf8Bad;
  // 1 when any of the 49 columns is TEXT with invalid UTF-8 (a `select *` fetch of the row raises).
  std::vector<uint8_t> AnyColumnUtf8Bad;

  std::vector<AddrId> AddrIdOf;     // address text (kNoneAddr for NULL)
  std::vector<NameId> NameIdOf;     // name (kNoneName for NULL)
  std::vector<NameId> MangledIdOf;  // mangled_function (kNoneName for NULL)

  std::unordered_map<AddrId, uint32_t> RowByAddr;             // address is `text unique` (S:72)
  std::unordered_map<NameId, std::vector<uint32_t>> RowsByName;  // ascending id; names are not unique

  std::optional<uint32_t> FindRow(AddrId Ea) const;
  std::span<const uint32_t> RowsNamed(NameId Key) const;

  // Column access by schema name (for census tests and generic tools).
  static std::span<const std::string_view> ColumnNames();  // the 49 names in schema order
  static std::optional<ColumnKind> KindOf(std::string_view Column);
  const IntColumn* IntColumnNamed(std::string_view Column) const;
  const TextColumn* TextColumnNamed(std::string_view Column) const;
  const RealColumn* RealColumnNamed(std::string_view Column) const;
};

// Everything the engine knows about one export.
struct ExportData {
  Side Which = Side::Main;
  std::string Path;  // exactly as given on the command line
  FunctionTable Functions;
  SideTables Tables;
  // Problems found by ingest (missing `functions` table or columns). Ingest never throws for them:
  // Diaphora checks diff.version first (D:3577-3591), so they are refused with UnsupportedInput only
  // after the version check passes (DiffSession::RequireIngest).
  std::vector<std::string> Problems;
};

// Loads `Which` ("main" or "diff" schema of the shared connection) into `Out`, interning names and
// addresses into `Ids`. Throws DiaphoraWouldRaise only on an SQL failure while reading.
void IngestExport(const DiffDatabase& Db, Side Which, Interners& Ids, ExportData& Out);

// True when `Bytes` is valid UTF-8 as Python's strict decoder accepts it (no surrogates, no overlongs).
bool IsValidUtf8(std::string_view Bytes);

}
