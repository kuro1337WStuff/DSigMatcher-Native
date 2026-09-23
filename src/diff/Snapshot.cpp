// Snapshot JSON I/O (docs/parity/00-plan.md §2.2, Appendix B). The reference for every convention is
// the oracle instrumentation, tools/parity/oracle_trace.py + snapshot.py (lane L0b), because long
// oracle captures already exist in its format: keys in its order (Instrument.BuildSnapshot), compact
// json.dumps(ensure_ascii=False, separators=(",", ":")) text plus one newline (snapshot.py DumpJson /
// WriteJsonAtomic), file names "%05d_%s.json" % (seq, re.sub(r"[^A-Za-z0-9._-]", "_", point))
// (snapshot.py SnapshotFileName). ParseSnapshot + SerializeSnapshot round-trip a real oracle snapshot
// byte for byte (diff_foundation "oracle-conventions").

#include "dsigmatcher/diff/Snapshot.h"

#include <cstdio>
#include <cstring>

#include "FileIo.h"
#include "dsigmatcher/diff/Errors.h"
#include "dsigmatcher/diff/Table.h"

namespace DSig::Diff {

// ---------------------------------------------------------------------------------------------
// ratio bits

uint64_t RatioBits(double Value) {
  uint64_t Bits = 0;
  static_assert(sizeof(Bits) == sizeof(Value));
  std::memcpy(&Bits, &Value, sizeof(Bits));
  return Bits;
}

double RatioFromBits(uint64_t Bits) {
  double Value = 0.0;
  std::memcpy(&Value, &Bits, sizeof(Value));
  return Value;
}

std::string RatioBitsHex(double Value) {
  // struct.pack('>d', v).hex(): the big-endian byte order equals the uint64 printed most significant first
  char Buffer[17];
  std::snprintf(Buffer, sizeof(Buffer), "%016llx", static_cast<unsigned long long>(RatioBits(Value)));
  return std::string(Buffer, 16);
}

uint64_t ParseRatioBits(std::string_view Hex) {
  if (Hex.size() != 16) {
    throw JsonError("ratio_bits must have 16 hex digits: " + std::string(Hex), 0);
  }
  uint64_t Bits = 0;
  for (const char Ch : Hex) {
    Bits <<= 4;
    if (Ch >= '0' && Ch <= '9') {
      Bits |= static_cast<uint64_t>(Ch - '0');
    } else if (Ch >= 'a' && Ch <= 'f') {
      Bits |= static_cast<uint64_t>(Ch - 'a' + 10);
    } else if (Ch >= 'A' && Ch <= 'F') {
      Bits |= static_cast<uint64_t>(Ch - 'A' + 10);
    } else {
      throw JsonError("ratio_bits is not hex: " + std::string(Hex), 0);
    }
  }
  return Bits;
}

// ---------------------------------------------------------------------------------------------
// names and globs

std::string SanitisePointName(std::string_view Point) {
  // snapshot.py SanitisePoint: re.sub(r"[^A-Za-z0-9._-]", "_", point) over a Python str, so each CODE
  // POINT outside the class becomes one '_' (a well-formed UTF-8 sequence is one code point; any other
  // byte counts alone). Appendix B point names are ASCII, where this is byte-wise.
  std::string Result;
  Result.reserve(Point.size());
  size_t Index = 0;
  while (Index < Point.size()) {
    const char Ch = Point[Index];
    const bool Keep = (Ch >= 'a' && Ch <= 'z') || (Ch >= 'A' && Ch <= 'Z') || (Ch >= '0' && Ch <= '9') ||
                      Ch == '.' || Ch == '_' || Ch == '-';
    if (Keep) {
      Result += Ch;
      ++Index;
      continue;
    }
    const unsigned char Lead = static_cast<unsigned char>(Ch);
    size_t Length = 1;
    if (Lead >= 0xC2 && Lead <= 0xDF) {
      Length = 2;
    } else if (Lead >= 0xE0 && Lead <= 0xEF) {
      Length = 3;
    } else if (Lead >= 0xF0 && Lead <= 0xF4) {
      Length = 4;
    }
    if (Length > 1 && Index + Length <= Point.size() && IsValidUtf8(Point.substr(Index, Length))) {
      Index += Length;
    } else {
      ++Index;
    }
    Result += '_';
  }
  return Result;
}

std::string SnapshotFileName(int64_t Seq, std::string_view Point) {
  char Buffer[32];
  std::snprintf(Buffer, sizeof(Buffer), "%05lld_", static_cast<long long>(Seq));
  return std::string(Buffer) + SanitisePointName(Point) + ".json";
}

bool PointMatchesGlob(std::string_view Point, std::string_view Glob) {
  // Iterative wildcard match with backtracking over the last '*'.
  size_t P = 0;
  size_t G = 0;
  size_t StarG = std::string_view::npos;
  size_t StarP = 0;
  while (P < Point.size()) {
    if (G < Glob.size() && (Glob[G] == '?' || Glob[G] == Point[P])) {
      ++P;
      ++G;
    } else if (G < Glob.size() && Glob[G] == '*') {
      StarG = G++;
      StarP = P;
    } else if (StarG != std::string_view::npos) {
      G = StarG + 1;
      P = ++StarP;
    } else {
      return false;
    }
  }
  while (G < Glob.size() && Glob[G] == '*') {
    ++G;
  }
  return G == Glob.size();
}

bool PointMatchesAnyGlob(std::string_view Point, std::string_view Globs) {
  size_t Start = 0;
  while (Start <= Globs.size()) {
    const size_t Bar = Globs.find('|', Start);
    const std::string_view One = Globs.substr(Start, Bar == std::string_view::npos ? std::string_view::npos : Bar - Start);
    if (!One.empty() && PointMatchesGlob(Point, One)) {
      return true;
    }
    if (Bar == std::string_view::npos) {
      break;
    }
    Start = Bar + 1;
  }
  return false;
}

// ---------------------------------------------------------------------------------------------
// JSON mapping

namespace {

JsonValue OptionalString(const std::optional<std::string>& Value) {
  return Value ? JsonValue::String(*Value) : JsonValue::Null();
}

std::optional<std::string> ReadOptionalString(const JsonValue& Value) {
  if (Value.IsNull()) {
    return std::nullopt;
  }
  return Value.AsString();
}

JsonValue ItemToJson(const SnapItem& Item) {
  JsonValue Row = JsonValue::Array();
  Row.Push(JsonValue::String(Item.Ea1));
  Row.Push(OptionalString(Item.Name1));
  Row.Push(JsonValue::String(Item.Ea2));
  Row.Push(OptionalString(Item.Name2));
  Row.Push(JsonValue::String(Item.Desc));
  Row.Push(JsonValue::String(RatioBitsHex(RatioFromBits(Item.RatioBits))));
  Row.Push(JsonValue::Int(Item.Nodes1));
  Row.Push(JsonValue::Int(Item.Nodes2));
  return Row;
}

std::string ReadEa(const JsonValue& Value) {
  // Python items carry the TEXT address (str); an int would only come from a hand-made input.
  if (Value.IsString()) {
    return Value.AsString();
  }
  if (Value.IsNumber() && Value.IsIntegerText()) {
    return Value.NumberText();
  }
  throw JsonError("item address is neither a string nor an integer", 0);
}

SnapItem ItemFromJson(const JsonValue& Value) {
  const auto& Row = Value.Items();
  if (Row.size() != 8) {
    throw JsonError("an item must have 8 fields", 0);
  }
  SnapItem Item;
  Item.Ea1 = ReadEa(Row[0]);
  Item.Name1 = ReadOptionalString(Row[1]);
  Item.Ea2 = ReadEa(Row[2]);
  Item.Name2 = ReadOptionalString(Row[3]);
  Item.Desc = Row[4].AsString();
  Item.RatioBits = ParseRatioBits(Row[5].AsString());
  Item.Nodes1 = Row[6].AsInt64();
  Item.Nodes2 = Row[7].AsInt64();
  return Item;
}

JsonValue ItemsToJson(const std::vector<SnapItem>& Items) {
  JsonValue List = JsonValue::Array();
  for (const SnapItem& Item : Items) {
    List.Push(ItemToJson(Item));
  }
  return List;
}

std::vector<SnapItem> ItemsFromJson(const JsonValue& Value) {
  std::vector<SnapItem> Items;
  for (const JsonValue& Row : Value.Items()) {
    Items.push_back(ItemFromJson(Row));
  }
  return Items;
}

JsonValue MatchedToJson(const std::vector<SnapMatched>& Entries) {
  JsonValue List = JsonValue::Array();
  for (const SnapMatched& Entry : Entries) {
    JsonValue Row = JsonValue::Array();
    Row.Push(OptionalString(Entry.Key));
    Row.Push(OptionalString(Entry.Other));
    Row.Push(JsonValue::String(RatioBitsHex(RatioFromBits(Entry.RatioBits))));
    List.Push(std::move(Row));
  }
  return List;
}

std::vector<SnapMatched> MatchedFromJson(const JsonValue& Value) {
  std::vector<SnapMatched> Entries;
  for (const JsonValue& Row : Value.Items()) {
    const auto& Fields = Row.Items();
    if (Fields.size() != 3) {
      throw JsonError("a matched entry must have 3 fields", 0);
    }
    SnapMatched Entry;
    Entry.Key = ReadOptionalString(Fields[0]);
    Entry.Other = ReadOptionalString(Fields[1]);
    Entry.RatioBits = ParseRatioBits(Fields[2].AsString());
    Entries.push_back(std::move(Entry));
  }
  return Entries;
}

JsonValue UnmatchedToJson(const std::optional<std::vector<SnapUnmatched>>& Rows) {
  if (!Rows) {
    return JsonValue::Null();
  }
  JsonValue List = JsonValue::Array();
  for (const SnapUnmatched& Row : *Rows) {
    JsonValue Pair = JsonValue::Array();
    Pair.Push(JsonValue::String(Row.Ea));
    Pair.Push(OptionalString(Row.Name));
    List.Push(std::move(Pair));
  }
  return List;
}

std::optional<std::vector<SnapUnmatched>> UnmatchedFromJson(const JsonValue* Value) {
  if (Value == nullptr || Value->IsNull()) {
    return std::nullopt;
  }
  std::vector<SnapUnmatched> Rows;
  for (const JsonValue& Pair : Value->Items()) {
    const auto& Fields = Pair.Items();
    if (Fields.size() != 2) {
      throw JsonError("an unmatched row must have 2 fields", 0);
    }
    SnapUnmatched Row;
    Row.Ea = ReadEa(Fields[0]);
    Row.Name = ReadOptionalString(Fields[1]);
    Rows.push_back(std::move(Row));
  }
  return Rows;
}

bool ReadBoolFlag(const JsonValue& Flags, std::string_view Name) {
  const JsonValue* Value = Flags.Find(Name);
  return Value != nullptr && !Value->IsNull() && Value->AsBool();
}

int64_t ReadIntFlag(const JsonValue& Flags, std::string_view Name) {
  const JsonValue* Value = Flags.Find(Name);
  return Value != nullptr && !Value->IsNull() ? Value->AsInt64() : 0;
}

}

JsonValue SnapshotToJson(const StateSnapshot& Snapshot) {
  JsonValue Root = JsonValue::Object();
  Root.Set("schema", JsonValue::String(Snapshot.Schema));
  Root.Set("producer", JsonValue::String(Snapshot.Producer));
  Root.Set("pair", JsonValue::String(Snapshot.Pair));
  Root.Set("seq", JsonValue::Int(Snapshot.Seq));
  Root.Set("point", JsonValue::String(Snapshot.Point));
  Root.Set("iteration", Snapshot.Iteration ? JsonValue::Int(*Snapshot.Iteration) : JsonValue::Null());

  JsonValue Flags = JsonValue::Object();
  Flags.Set("is_same_processor", JsonValue::Bool(Snapshot.Flags.IsSameProcessor));
  Flags.Set("is_patch_diff", JsonValue::Bool(Snapshot.Flags.IsPatchDiff));
  Flags.Set("is_symbols_stripped", JsonValue::Bool(Snapshot.Flags.IsSymbolsStripped));
  Flags.Set("hooks_loaded", JsonValue::Bool(Snapshot.Flags.HooksLoaded));
  Flags.Set("total_functions1", JsonValue::Int(Snapshot.Flags.TotalFunctions1));
  Flags.Set("total_functions2", JsonValue::Int(Snapshot.Flags.TotalFunctions2));
  Root.Set("flags", std::move(Flags));

  JsonValue All = JsonValue::Object();
  All.Set("best", ItemsToJson(Snapshot.Best));
  All.Set("partial", ItemsToJson(Snapshot.Partial));
  All.Set("unreliable", ItemsToJson(Snapshot.Unreliable));
  Root.Set("all_matches", std::move(All));
  Root.Set("matched_primary", MatchedToJson(Snapshot.MatchedPrimary));
  Root.Set("matched_secondary", MatchedToJson(Snapshot.MatchedSecondary));

  if (Snapshot.RatiosCache) {
    JsonValue Cache = JsonValue::Array();
    for (const SnapCacheEntry& Entry : *Snapshot.RatiosCache) {
      JsonValue Row = JsonValue::Array();
      Row.Push(JsonValue::String(Entry.Key));
      Row.Push(JsonValue::String(RatioBitsHex(RatioFromBits(Entry.RatioBits))));
      Cache.Push(std::move(Row));
    }
    Root.Set("ratios_cache", std::move(Cache));
  }
  if (Snapshot.Choosers) {
    JsonValue Choosers = JsonValue::Object();
    Choosers.Set("best", ItemsToJson(Snapshot.Choosers->Best));
    Choosers.Set("partial", ItemsToJson(Snapshot.Choosers->Partial));
    Choosers.Set("unreliable", ItemsToJson(Snapshot.Choosers->Unreliable));
    Choosers.Set("multimatch", ItemsToJson(Snapshot.Choosers->Multimatch));
    Root.Set("choosers", std::move(Choosers));
  }
  if (Snapshot.Unmatched) {
    JsonValue Unmatched = JsonValue::Object();
    Unmatched.Set("primary", UnmatchedToJson(Snapshot.Unmatched->Primary));
    Unmatched.Set("secondary", UnmatchedToJson(Snapshot.Unmatched->Secondary));
    Root.Set("unmatched", std::move(Unmatched));
  }
  return Root;
}

StateSnapshot ParseSnapshot(std::string_view Json) {
  JsonParseOptions Options;
  Options.PythonCompat = true;  // written by Python's json module as well
  const JsonValue Root = JsonParse(Json, Options);
  StateSnapshot Snapshot;
  if (const JsonValue* Schema = Root.Find("schema")) {
    Snapshot.Schema = Schema->AsString();
  }
  if (Snapshot.Schema != kSnapshotSchema) {
    throw JsonError("unsupported snapshot schema \"" + Snapshot.Schema + "\"", 0);
  }
  if (const JsonValue* Producer = Root.Find("producer"); Producer != nullptr && !Producer->IsNull()) {
    Snapshot.Producer = Producer->AsString();
  }
  if (const JsonValue* Pair = Root.Find("pair"); Pair != nullptr && !Pair->IsNull()) {
    Snapshot.Pair = Pair->AsString();
  }
  if (const JsonValue* Seq = Root.Find("seq"); Seq != nullptr && !Seq->IsNull()) {
    Snapshot.Seq = Seq->AsInt64();
  }
  Snapshot.Point = Root.At("point").AsString();
  if (const JsonValue* Iteration = Root.Find("iteration"); Iteration != nullptr && !Iteration->IsNull()) {
    Snapshot.Iteration = Iteration->AsInt64();
  }
  if (const JsonValue* Flags = Root.Find("flags"); Flags != nullptr && !Flags->IsNull()) {
    Snapshot.Flags.IsSameProcessor = ReadBoolFlag(*Flags, "is_same_processor");
    Snapshot.Flags.IsPatchDiff = ReadBoolFlag(*Flags, "is_patch_diff");
    Snapshot.Flags.IsSymbolsStripped = ReadBoolFlag(*Flags, "is_symbols_stripped");
    Snapshot.Flags.HooksLoaded = ReadBoolFlag(*Flags, "hooks_loaded");
    Snapshot.Flags.TotalFunctions1 = ReadIntFlag(*Flags, "total_functions1");
    Snapshot.Flags.TotalFunctions2 = ReadIntFlag(*Flags, "total_functions2");
  }
  const JsonValue& All = Root.At("all_matches");
  Snapshot.Best = ItemsFromJson(All.At("best"));
  Snapshot.Partial = ItemsFromJson(All.At("partial"));
  Snapshot.Unreliable = ItemsFromJson(All.At("unreliable"));
  Snapshot.MatchedPrimary = MatchedFromJson(Root.At("matched_primary"));
  Snapshot.MatchedSecondary = MatchedFromJson(Root.At("matched_secondary"));
  if (const JsonValue* Cache = Root.Find("ratios_cache"); Cache != nullptr && !Cache->IsNull()) {
    std::vector<SnapCacheEntry> Entries;
    for (const JsonValue& Row : Cache->Items()) {
      const auto& Fields = Row.Items();
      if (Fields.size() != 2) {
        throw JsonError("a ratios_cache entry must have 2 fields", 0);
      }
      Entries.push_back(SnapCacheEntry{Fields[0].AsString(), ParseRatioBits(Fields[1].AsString())});
    }
    Snapshot.RatiosCache = std::move(Entries);
  }
  if (const JsonValue* Choosers = Root.Find("choosers"); Choosers != nullptr && !Choosers->IsNull()) {
    SnapChoosers Dump;
    Dump.Best = ItemsFromJson(Choosers->At("best"));
    Dump.Partial = ItemsFromJson(Choosers->At("partial"));
    Dump.Unreliable = ItemsFromJson(Choosers->At("unreliable"));
    Dump.Multimatch = ItemsFromJson(Choosers->At("multimatch"));
    Snapshot.Choosers = std::move(Dump);
  }
  if (const JsonValue* Unmatched = Root.Find("unmatched"); Unmatched != nullptr && !Unmatched->IsNull()) {
    SnapUnmatchedDump Dump;
    Dump.Primary = UnmatchedFromJson(Unmatched->Find("primary"));
    Dump.Secondary = UnmatchedFromJson(Unmatched->Find("secondary"));
    Snapshot.Unmatched = std::move(Dump);
  }
  return Snapshot;
}

std::string SerializeSnapshot(const StateSnapshot& Snapshot, bool Pretty) {
  JsonWriteOptions Options;
  Options.Pretty = Pretty;
  return JsonWrite(SnapshotToJson(Snapshot), Options);
}

StateSnapshot ReadSnapshot(const std::string& Path) {
  // UTF-8 path; on Windows a shared-delete read, so a concurrent os.replace is never blocked (FileIo.h).
  return ParseSnapshot(Detail::ReadFileBytes(Path));
}

void WriteSnapshot(const std::string& Path, const StateSnapshot& Snapshot, bool Pretty) {
  // The oracle's WriteJsonAtomic (tools/parity/snapshot.py): the JSON text, then one newline.
  Detail::WriteFileBytes(Path, SerializeSnapshot(Snapshot, Pretty) + "\n");
}

}
