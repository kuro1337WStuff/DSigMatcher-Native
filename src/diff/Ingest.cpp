// Ingest of the Diaphora `functions` table (docs/parity/00-plan.md §3.3; 07 §4-§5; 08 §9) and the
// string interners.

#include <array>
#include <deque>
#include <string>
#include <unordered_map>

#include "dsigmatcher/diff/Database.h"
#include "dsigmatcher/diff/Errors.h"
#include "dsigmatcher/diff/Interner.h"
#include "dsigmatcher/diff/SideTables.h"
#include "dsigmatcher/diff/Table.h"

namespace DSig::Diff {

// ---------------------------------------------------------------------------------------------
// Interner

struct Interner::Impl {
  std::deque<std::string> Storage;  // push_back never moves existing elements, so views stay valid
  std::vector<std::string_view> Views;
  std::unordered_map<std::string_view, uint32_t> Index;
};

Interner::Interner() : Impl_(std::make_unique<Impl>()) {}
Interner::~Interner() = default;
Interner::Interner(Interner&&) noexcept = default;
Interner& Interner::operator=(Interner&&) noexcept = default;

uint32_t Interner::Intern(std::string_view Text) {
  const auto Found = Impl_->Index.find(Text);
  if (Found != Impl_->Index.end()) {
    return Found->second;
  }
  Impl_->Storage.emplace_back(Text);
  const std::string_view Stored(Impl_->Storage.back());
  const uint32_t Id = static_cast<uint32_t>(Impl_->Views.size());
  Impl_->Views.push_back(Stored);
  Impl_->Index.emplace(Stored, Id);
  return Id;
}

std::optional<uint32_t> Interner::Find(std::string_view Text) const {
  const auto Found = Impl_->Index.find(Text);
  if (Found == Impl_->Index.end()) {
    return std::nullopt;
  }
  return Found->second;
}

std::string_view Interner::Text(uint32_t Id) const { return Impl_->Views.at(Id); }

size_t Interner::Size() const { return Impl_->Views.size(); }

// ---------------------------------------------------------------------------------------------
// Interners: name and address ids are the interner index + 1, so 0 stays Python None.

Interners::Interners() = default;
Interners::~Interners() = default;
Interners::Interners(Interners&&) noexcept = default;
Interners& Interners::operator=(Interners&&) noexcept = default;

NameId Interners::Name(std::string_view Text) { return NameId{Names_.Intern(Text) + 1u}; }

NameId Interners::NameOpt(std::optional<std::string_view> TextOrNone) {
  return TextOrNone ? Name(*TextOrNone) : kNoneName;
}

std::optional<NameId> Interners::FindName(std::string_view Text) const {
  if (auto Id = Names_.Find(Text)) {
    return NameId{*Id + 1u};
  }
  return std::nullopt;
}

std::optional<std::string_view> Interners::NameOrNone(NameId Id) const {
  if (Id == kNoneName) {
    return std::nullopt;
  }
  return Names_.Text(static_cast<uint32_t>(Id) - 1u);
}

std::string_view Interners::NameText(NameId Id) const {
  return Id == kNoneName ? std::string_view() : Names_.Text(static_cast<uint32_t>(Id) - 1u);
}

std::string_view Interners::NameKeyText(NameId Id) const {
  return Id == kNoneName ? std::string_view("None") : Names_.Text(static_cast<uint32_t>(Id) - 1u);
}

size_t Interners::NameCount() const { return Names_.Size(); }

DescId Interners::Desc(std::string_view Text) { return DescId{Descs_.Intern(Text)}; }

std::optional<DescId> Interners::FindDesc(std::string_view Text) const {
  if (auto Id = Descs_.Find(Text)) {
    return DescId{*Id};
  }
  return std::nullopt;
}

std::string_view Interners::DescText(DescId Id) const { return Descs_.Text(static_cast<uint32_t>(Id)); }

AddrId Interners::Addr(std::string_view Text) { return AddrId{Addrs_.Intern(Text) + 1u}; }

AddrId Interners::AddrOpt(std::optional<std::string_view> TextOrNone) {
  return TextOrNone ? Addr(*TextOrNone) : kNoneAddr;
}

std::optional<AddrId> Interners::FindAddr(std::string_view Text) const {
  if (auto Id = Addrs_.Find(Text)) {
    return AddrId{*Id + 1u};
  }
  return std::nullopt;
}

std::string_view Interners::AddrText(AddrId Id) const {
  return Id == kNoneAddr ? std::string_view() : Addrs_.Text(static_cast<uint32_t>(Id) - 1u);
}

std::string_view Interners::AddrKeyText(AddrId Id) const {
  return Id == kNoneAddr ? std::string_view("None") : Addrs_.Text(static_cast<uint32_t>(Id) - 1u);
}

// ---------------------------------------------------------------------------------------------
// UTF-8 validation with Python's strict decoder rules: no overlong forms, no surrogates
// (U+D800-U+DFFF), nothing above U+10FFFF.

bool IsValidUtf8(std::string_view Bytes) {
  const auto* Data = reinterpret_cast<const unsigned char*>(Bytes.data());
  const size_t Size = Bytes.size();
  size_t Index = 0;
  while (Index < Size) {
    // ASCII fast path, 8 bytes at a time
    while (Index + 8 <= Size) {
      uint64_t Word = 0;
      for (int Byte = 0; Byte < 8; ++Byte) {
        Word |= static_cast<uint64_t>(Data[Index + static_cast<size_t>(Byte)]) << (Byte * 8);
      }
      if ((Word & 0x8080808080808080ull) != 0) {
        break;
      }
      Index += 8;
    }
    if (Index >= Size) {
      break;
    }
    const unsigned char Lead = Data[Index];
    if (Lead < 0x80) {
      ++Index;
      continue;
    }
    size_t Need = 0;
    uint32_t Min = 0;
    uint32_t Code = 0;
    if (Lead >= 0xC2 && Lead <= 0xDF) {
      Need = 1;
      Min = 0x80;
      Code = Lead & 0x1Fu;
    } else if (Lead >= 0xE0 && Lead <= 0xEF) {
      Need = 2;
      Min = 0x800;
      Code = Lead & 0x0Fu;
    } else if (Lead >= 0xF0 && Lead <= 0xF4) {
      Need = 3;
      Min = 0x10000;
      Code = Lead & 0x07u;
    } else {
      return false;
    }
    if (Index + Need >= Size) {
      return false;  // truncated sequence
    }
    for (size_t Next = 1; Next <= Need; ++Next) {
      const unsigned char Continuation = Data[Index + Next];
      if ((Continuation & 0xC0u) != 0x80u) {
        return false;
      }
      Code = (Code << 6) | (Continuation & 0x3Fu);
    }
    if (Code < Min || Code > 0x10FFFFu || (Code >= 0xD800u && Code <= 0xDFFFu)) {
      return false;
    }
    Index += Need + 1;
  }
  return true;
}

// ---------------------------------------------------------------------------------------------
// Columns

void TextColumn::Append(std::string_view Bytes, bool Blob) {
  Offset.push_back(Pool.size());
  Length.push_back(static_cast<uint32_t>(Bytes.size()));
  Pool.insert(Pool.end(), Bytes.begin(), Bytes.end());
  IsNull.push_back(0);
  IsBlob.push_back(Blob ? 1 : 0);
}

void TextColumn::AppendNull() {
  Offset.push_back(Pool.size());
  Length.push_back(0);
  IsNull.push_back(1);
  IsBlob.push_back(0);
}

namespace {

struct ColumnDesc {
  std::string_view Name;
  ColumnKind Kind;
  IntColumn FunctionTable::*Int;
  TextColumn FunctionTable::*Text;
  RealColumn FunctionTable::*Real;
  bool SelectField;  // a SELECT_FIELDS source column (H:51-75)
};

#define DSIG_INT(Name, Member, Select) \
  ColumnDesc { Name, ColumnKind::Integer, &FunctionTable::Member, nullptr, nullptr, Select }
#define DSIG_TEXT(Name, Member, Select) \
  ColumnDesc { Name, ColumnKind::Text, nullptr, &FunctionTable::Member, nullptr, Select }
#define DSIG_REAL(Name, Member, Select) \
  ColumnDesc { Name, ColumnKind::Real, nullptr, nullptr, &FunctionTable::Member, Select }

// db_support/schema.py:69-118, in order. SelectField marks the columns SELECT_FIELDS projects
// (md_index is projected as cast(... as real), a REAL that is never decoded).
const std::array<ColumnDesc, 49> kColumns = {{
    DSIG_INT("id", Id, false),
    DSIG_TEXT("name", Name, true),
    DSIG_TEXT("address", Address, true),
    DSIG_INT("nodes", Nodes, true),
    DSIG_INT("edges", Edges, true),
    DSIG_INT("indegree", Indegree, true),
    DSIG_INT("outdegree", Outdegree, true),
    DSIG_INT("size", Size, true),
    DSIG_INT("instructions", Instructions, true),
    DSIG_TEXT("mnemonics", Mnemonics, false),
    DSIG_TEXT("names", Names, false),
    DSIG_TEXT("prototype", Prototype, false),
    DSIG_INT("cyclomatic_complexity", CyclomaticComplexity, true),
    DSIG_TEXT("primes_value", PrimesValue, false),
    DSIG_TEXT("comment", Comment, false),
    DSIG_TEXT("mangled_function", MangledFunction, true),
    DSIG_TEXT("bytes_hash", BytesHash, true),
    DSIG_TEXT("pseudocode", Pseudocode, true),
    DSIG_INT("pseudocode_lines", PseudocodeLines, false),
    DSIG_TEXT("pseudocode_hash1", PseudocodeHash1, false),
    DSIG_TEXT("pseudocode_primes", PseudocodePrimes, true),
    DSIG_INT("function_flags", FunctionFlags, false),
    DSIG_TEXT("assembly", Assembly, true),
    DSIG_TEXT("prototype2", Prototype2, false),
    DSIG_TEXT("pseudocode_hash2", PseudocodeHash2, false),
    DSIG_TEXT("pseudocode_hash3", PseudocodeHash3, false),
    DSIG_INT("strongly_connected", StronglyConnected, true),
    DSIG_INT("loops", Loops, true),
    DSIG_TEXT("rva", Rva, false),
    DSIG_TEXT("tarjan_topological_sort", TarjanTopologicalSort, false),
    DSIG_TEXT("strongly_connected_spp", StronglyConnectedSpp, false),
    DSIG_TEXT("clean_assembly", CleanAssembly, true),
    DSIG_TEXT("clean_pseudo", CleanPseudo, true),
    DSIG_TEXT("mnemonics_spp", MnemonicsSpp, false),
    DSIG_TEXT("switches", Switches, false),
    DSIG_TEXT("function_hash", FunctionHash, false),
    DSIG_INT("bytes_sum", BytesSum, false),
    DSIG_TEXT("md_index", MdIndex, false),
    DSIG_TEXT("constants", Constants, false),
    DSIG_INT("constants_count", ConstantsCount, true),
    DSIG_TEXT("segment_rva", SegmentRva, false),
    DSIG_TEXT("assembly_addrs", AssemblyAddrs, false),
    DSIG_TEXT("kgh_hash", KghHash, true),
    DSIG_TEXT("source_file", SourceFile, false),
    DSIG_TEXT("userdata", Userdata, false),
    DSIG_TEXT("microcode", Microcode, false),
    DSIG_TEXT("clean_microcode", CleanMicrocode, true),
    DSIG_TEXT("microcode_spp", MicrocodeSpp, false),
    DSIG_REAL("export_time", ExportTime, false),
}};

#undef DSIG_INT
#undef DSIG_TEXT
#undef DSIG_REAL

const ColumnDesc* FindDesc(std::string_view Name) {
  for (const ColumnDesc& Desc : kColumns) {
    if (Desc.Name == Name) {
      return &Desc;
    }
  }
  return nullptr;
}

const std::array<std::string_view, 49>& NameArray() {
  static const std::array<std::string_view, 49> Names = [] {
    std::array<std::string_view, 49> Result{};
    for (size_t Index = 0; Index < kColumns.size(); ++Index) {
      Result[Index] = kColumns[Index].Name;
    }
    return Result;
  }();
  return Names;
}

}

std::optional<uint32_t> FunctionTable::FindRow(AddrId Ea) const {
  const auto Found = RowByAddr.find(Ea);
  if (Found == RowByAddr.end()) {
    return std::nullopt;
  }
  return Found->second;
}

std::span<const uint32_t> FunctionTable::RowsNamed(NameId Key) const {
  const auto Found = RowsByName.find(Key);
  if (Found == RowsByName.end()) {
    return {};
  }
  return Found->second;
}

std::span<const std::string_view> FunctionTable::ColumnNames() { return NameArray(); }

std::optional<ColumnKind> FunctionTable::KindOf(std::string_view Column) {
  if (const ColumnDesc* Desc = FindDesc(Column)) {
    return Desc->Kind;
  }
  return std::nullopt;
}

const IntColumn* FunctionTable::IntColumnNamed(std::string_view Column) const {
  const ColumnDesc* Desc = FindDesc(Column);
  return Desc != nullptr && Desc->Int != nullptr ? &(this->*(Desc->Int)) : nullptr;
}

const TextColumn* FunctionTable::TextColumnNamed(std::string_view Column) const {
  const ColumnDesc* Desc = FindDesc(Column);
  return Desc != nullptr && Desc->Text != nullptr ? &(this->*(Desc->Text)) : nullptr;
}

const RealColumn* FunctionTable::RealColumnNamed(std::string_view Column) const {
  const ColumnDesc* Desc = FindDesc(Column);
  return Desc != nullptr && Desc->Real != nullptr ? &(this->*(Desc->Real)) : nullptr;
}

// ---------------------------------------------------------------------------------------------
// IngestExport

void IngestExport(const DiffDatabase& Db, Side Which, Interners& Ids, ExportData& Out) {
  Out.Which = Which;
  Out.Functions = FunctionTable();
  Out.Problems.clear();
  LoadSideTables(Db, Which, Out.Tables);
  const std::string Schema(SchemaName(Which));

  const TableInfo* Functions = Out.Tables.Find("functions");
  if (Functions == nullptr || !Functions->Present) {
    Out.Problems.push_back(Schema + ".functions: table is missing");
    return;
  }
  // 07 §5.3 step 1: a missing required column is a hard error in parity mode (after the version check).
  std::string Missing;
  for (const ColumnDesc& Desc : kColumns) {
    bool Found = false;
    for (const std::string& Column : Functions->Columns) {
      if (Column == Desc.Name) {
        Found = true;
        break;
      }
    }
    if (!Found) {
      Missing += Missing.empty() ? "" : ", ";
      Missing += std::string(Desc.Name);
    }
  }
  if (!Missing.empty()) {
    Out.Problems.push_back(Schema + ".functions: missing columns " + Missing);
    return;
  }

  // 00-plan §3.3: all columns, plus SQLite's own casts, in `order by id`.
  const std::string Sql = "select f.*, cast(f.md_index as real), cast(f.address as real) from " + Schema +
                          ".functions f order by f.id";
  Statement Stmt = Db.Prepare(Sql);
  const int Count = Stmt.ColumnCount();
  const int ColMd = Count - 2;
  const int ColAddressReal = Count - 1;
  std::vector<const ColumnDesc*> Map(static_cast<size_t>(Count), nullptr);
  for (int Column = 0; Column < Count - 2; ++Column) {
    Map[static_cast<size_t>(Column)] = FindDesc(Stmt.ColumnName(Column));
  }

  FunctionTable& T = Out.Functions;
  uint32_t Row = 0;
  while (Stmt.Step()) {
    bool SelectBad = false;
    bool AnyBad = false;
    for (int Column = 0; Column < Count - 2; ++Column) {
      const ColumnDesc* Desc = Map[static_cast<size_t>(Column)];
      if (Desc == nullptr) {
        continue;  // a column this schema version does not define
      }
      const SqlType Kind = Stmt.Type(Column);  // 08 §9.1 rule 2: the type tag first, then extract
      if (Desc->Kind == ColumnKind::Integer) {
        IntColumn& Target = T.*(Desc->Int);
        if (Kind == SqlType::Null) {
          Target.Value.push_back(0);
          Target.IsNull.push_back(1);
          Target.NotInteger.push_back(0);
        } else {
          if (Kind == SqlType::Text && !IsValidUtf8(Stmt.Text(Column))) {
            AnyBad = true;
            SelectBad = SelectBad || Desc->SelectField;
          }
          Target.Value.push_back(Stmt.Int(Column));
          Target.IsNull.push_back(0);
          Target.NotInteger.push_back(Kind == SqlType::Integer ? 0 : 1);
        }
      } else if (Desc->Kind == ColumnKind::Text) {
        TextColumn& Target = T.*(Desc->Text);
        switch (Kind) {
          case SqlType::Null:
            Target.AppendNull();
            break;
          case SqlType::Text: {
            const std::string_view Bytes = Stmt.Text(Column);
            if (!IsValidUtf8(Bytes)) {
              AnyBad = true;
              SelectBad = SelectBad || Desc->SelectField;
            }
            Target.Append(Bytes, false);
            break;
          }
          case SqlType::Blob:
            Target.Append(Stmt.Text(Column), true);
            break;
          case SqlType::Integer:
          case SqlType::Real: {
            // TEXT affinity converts numbers to text on store, so this needs a foreign schema.
            Out.Problems.push_back(Schema + ".functions." + std::string(Desc->Name) + " row " +
                                   std::to_string(Row) + " holds a number in a TEXT column");
            Target.Append(Stmt.Text(Column), false);
            break;
          }
        }
      } else {
        RealColumn& Target = T.*(Desc->Real);
        if (Kind == SqlType::Null) {
          Target.Value.push_back(0.0);
          Target.IsNull.push_back(1);
          Target.NotReal.push_back(0);
        } else {
          if (Kind == SqlType::Text && !IsValidUtf8(Stmt.Text(Column))) {
            AnyBad = true;
          }
          Target.Value.push_back(Stmt.Real(Column));
          Target.IsNull.push_back(0);
          Target.NotReal.push_back(Kind == SqlType::Real || Kind == SqlType::Integer ? 0 : 1);
        }
      }
    }
    // cast(md_index as real) and cast(address as real), evaluated by SQLite (07 §5.3 step 3).
    if (Stmt.Type(ColMd) == SqlType::Null) {
      T.MdSqlReal.push_back(0.0);
      T.MdSqlNull.push_back(1);
    } else {
      T.MdSqlReal.push_back(Stmt.Real(ColMd));
      T.MdSqlNull.push_back(0);
    }
    if (Stmt.Type(ColAddressReal) == SqlType::Null) {
      T.AddressSqlReal.push_back(0.0);
      T.AddressSqlNull.push_back(1);
    } else {
      T.AddressSqlReal.push_back(Stmt.Real(ColAddressReal));
      T.AddressSqlNull.push_back(0);
    }
    T.SelectFieldsUtf8Bad.push_back(SelectBad ? 1 : 0);
    T.AnyColumnUtf8Bad.push_back(AnyBad ? 1 : 0);
    ++Row;
  }

  // Interned ids and lookups. Diaphora keys state by name strings and the final pass by address text.
  const size_t Rows = T.Count();
  T.AddrIdOf.resize(Rows);
  T.NameIdOf.resize(Rows);
  T.MangledIdOf.resize(Rows);
  T.RowByAddr.reserve(Rows);
  for (uint32_t Index = 0; Index < Rows; ++Index) {
    const AddrId Ea = T.Address.Null(Index) ? kNoneAddr : Ids.Addr(T.Address.View(Index));
    T.AddrIdOf[Index] = Ea;
    T.NameIdOf[Index] = Ids.NameOpt(T.Name.Get(Index));
    T.MangledIdOf[Index] = Ids.NameOpt(T.MangledFunction.Get(Index));
    if (Ea != kNoneAddr && !T.RowByAddr.emplace(Ea, Index).second) {
      Out.Problems.push_back(Schema + ".functions: duplicate address " + std::string(T.Address.View(Index)));
    }
    if (T.NameIdOf[Index] != kNoneName) {
      T.RowsByName[T.NameIdOf[Index]].push_back(Index);  // rows are in id order, so ascending id
    }
  }
}

}
