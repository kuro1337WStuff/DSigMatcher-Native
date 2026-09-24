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
#include <filesystem>
#include <fstream>
#include <tuple>

#include "CheckpointDetail.h"
#include "FileIo.h"
#include "dsigmatcher/Sha256.h"
#include "dsigmatcher/diff/Checkpoint.h"
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
    throw JsonError("ratio_bits must have 16 hex digits: " + std::string(Hex), JsonError::kNoOffset);
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
      throw JsonError("ratio_bits is not hex: " + std::string(Hex), JsonError::kNoOffset);
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

// Runs `Read` and gives a JsonError that has no member path yet the path `Where` (audit F58), so a bad
// value reports "all_matches.best[0][6]: JSON value is not an integer" instead of a bare message. The
// innermost caller that knows a path wins; outer callers let the error pass unchanged.
template <class F>
auto InField(const std::string& Where, F&& Read) -> decltype(Read()) {
  try {
    return Read();
  } catch (const JsonError& Error) {
    if (!Error.Path.empty()) {
      throw;
    }
    throw JsonError(Error.Detail, Error.Position, Where);
  }
}

std::string Indexed(const std::string& Base, size_t Index) { return Base + "[" + std::to_string(Index) + "]"; }

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
  throw JsonError("item address is neither a string nor an integer", JsonError::kNoOffset);
}

SnapItem ItemFromJson(const JsonValue& Value, const std::string& Where) {
  const auto& Row = InField(Where, [&]() -> const std::vector<JsonValue>& { return Value.Items(); });
  if (Row.size() != 8) {
    throw JsonError("an item must have 8 fields", JsonError::kNoOffset, Where);
  }
  SnapItem Item;
  Item.Ea1 = InField(Indexed(Where, 0), [&] { return ReadEa(Row[0]); });
  Item.Name1 = InField(Indexed(Where, 1), [&] { return ReadOptionalString(Row[1]); });
  Item.Ea2 = InField(Indexed(Where, 2), [&] { return ReadEa(Row[2]); });
  Item.Name2 = InField(Indexed(Where, 3), [&] { return ReadOptionalString(Row[3]); });
  Item.Desc = InField(Indexed(Where, 4), [&] { return Row[4].AsString(); });
  Item.RatioBits = InField(Indexed(Where, 5), [&] { return ParseRatioBits(Row[5].AsString()); });
  Item.Nodes1 = InField(Indexed(Where, 6), [&] { return Row[6].AsInt64(); });
  Item.Nodes2 = InField(Indexed(Where, 7), [&] { return Row[7].AsInt64(); });
  return Item;
}

JsonValue ItemsToJson(const std::vector<SnapItem>& Items) {
  JsonValue List = JsonValue::Array();
  for (const SnapItem& Item : Items) {
    List.Push(ItemToJson(Item));
  }
  return List;
}

std::vector<SnapItem> ItemsFromJson(const JsonValue& Value, const std::string& Where) {
  std::vector<SnapItem> Items;
  const auto& Rows = InField(Where, [&]() -> const std::vector<JsonValue>& { return Value.Items(); });
  for (size_t Index = 0; Index < Rows.size(); ++Index) {
    Items.push_back(ItemFromJson(Rows[Index], Indexed(Where, Index)));
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

std::vector<SnapMatched> MatchedFromJson(const JsonValue& Value, const std::string& Where) {
  std::vector<SnapMatched> Entries;
  const auto& Rows = InField(Where, [&]() -> const std::vector<JsonValue>& { return Value.Items(); });
  for (size_t Index = 0; Index < Rows.size(); ++Index) {
    const std::string At = Indexed(Where, Index);
    const auto& Fields = InField(At, [&]() -> const std::vector<JsonValue>& { return Rows[Index].Items(); });
    if (Fields.size() != 3) {
      throw JsonError("a matched entry must have 3 fields", JsonError::kNoOffset, At);
    }
    SnapMatched Entry;
    Entry.Key = InField(Indexed(At, 0), [&] { return ReadOptionalString(Fields[0]); });
    Entry.Other = InField(Indexed(At, 1), [&] { return ReadOptionalString(Fields[1]); });
    Entry.RatioBits = InField(Indexed(At, 2), [&] { return ParseRatioBits(Fields[2].AsString()); });
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

std::optional<std::vector<SnapUnmatched>> UnmatchedFromJson(const JsonValue* Value, const std::string& Where) {
  if (Value == nullptr || Value->IsNull()) {
    return std::nullopt;
  }
  std::vector<SnapUnmatched> Rows;
  const auto& Pairs = InField(Where, [&]() -> const std::vector<JsonValue>& { return Value->Items(); });
  for (size_t Index = 0; Index < Pairs.size(); ++Index) {
    const std::string At = Indexed(Where, Index);
    const auto& Fields = InField(At, [&]() -> const std::vector<JsonValue>& { return Pairs[Index].Items(); });
    if (Fields.size() != 2) {
      throw JsonError("an unmatched row must have 2 fields", JsonError::kNoOffset, At);
    }
    SnapUnmatched Row;
    Row.Ea = InField(Indexed(At, 0), [&] { return ReadEa(Fields[0]); });
    Row.Name = InField(Indexed(At, 1), [&] { return ReadOptionalString(Fields[1]); });
    Rows.push_back(std::move(Row));
  }
  return Rows;
}

bool ReadBoolFlag(const JsonValue& Flags, std::string_view Name) {
  const JsonValue* Value = Flags.Find(Name);
  return InField("flags." + std::string(Name), [&] { return Value != nullptr && !Value->IsNull() && Value->AsBool(); });
}

int64_t ReadIntFlag(const JsonValue& Flags, std::string_view Name) {
  const JsonValue* Value = Flags.Find(Name);
  return InField("flags." + std::string(Name),
                 [&] { return Value != nullptr && !Value->IsNull() ? Value->AsInt64() : int64_t{0}; });
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
  return SnapshotFromJson(JsonParse(Json, Options));
}

StateSnapshot SnapshotFromJson(const JsonValue& Root) {
  StateSnapshot Snapshot;
  if (!Root.IsObject()) {
    throw JsonError("a snapshot must be a JSON object", JsonError::kNoOffset, "(root)");
  }
  if (const JsonValue* Schema = Root.Find("schema")) {
    Snapshot.Schema = InField("schema", [&] { return Schema->AsString(); });
  }
  if (Snapshot.Schema != kSnapshotSchema) {
    throw JsonError("unsupported snapshot schema \"" + Snapshot.Schema + "\"", JsonError::kNoOffset, "schema");
  }
  if (const JsonValue* Producer = Root.Find("producer"); Producer != nullptr && !Producer->IsNull()) {
    Snapshot.Producer = InField("producer", [&] { return Producer->AsString(); });
  }
  if (const JsonValue* Pair = Root.Find("pair"); Pair != nullptr && !Pair->IsNull()) {
    Snapshot.Pair = InField("pair", [&] { return Pair->AsString(); });
  }
  if (const JsonValue* Seq = Root.Find("seq"); Seq != nullptr && !Seq->IsNull()) {
    Snapshot.Seq = InField("seq", [&] { return Seq->AsInt64(); });
  }
  Snapshot.Point = InField("point", [&] { return Root.At("point").AsString(); });
  if (const JsonValue* Iteration = Root.Find("iteration"); Iteration != nullptr && !Iteration->IsNull()) {
    Snapshot.Iteration = InField("iteration", [&] { return Iteration->AsInt64(); });
  }
  if (const JsonValue* Flags = Root.Find("flags"); Flags != nullptr && !Flags->IsNull()) {
    if (!Flags->IsObject()) {
      throw JsonError("JSON value is not an object", JsonError::kNoOffset, "flags");
    }
    Snapshot.Flags.IsSameProcessor = ReadBoolFlag(*Flags, "is_same_processor");
    Snapshot.Flags.IsPatchDiff = ReadBoolFlag(*Flags, "is_patch_diff");
    Snapshot.Flags.IsSymbolsStripped = ReadBoolFlag(*Flags, "is_symbols_stripped");
    Snapshot.Flags.HooksLoaded = ReadBoolFlag(*Flags, "hooks_loaded");
    Snapshot.Flags.TotalFunctions1 = ReadIntFlag(*Flags, "total_functions1");
    Snapshot.Flags.TotalFunctions2 = ReadIntFlag(*Flags, "total_functions2");
  }
  const JsonValue& All = InField("all_matches", [&]() -> const JsonValue& { return Root.At("all_matches"); });
  Snapshot.Best = ItemsFromJson(InField("all_matches.best", [&]() -> const JsonValue& { return All.At("best"); }),
                                "all_matches.best");
  Snapshot.Partial = ItemsFromJson(
      InField("all_matches.partial", [&]() -> const JsonValue& { return All.At("partial"); }), "all_matches.partial");
  Snapshot.Unreliable = ItemsFromJson(
      InField("all_matches.unreliable", [&]() -> const JsonValue& { return All.At("unreliable"); }),
      "all_matches.unreliable");
  Snapshot.MatchedPrimary = MatchedFromJson(
      InField("matched_primary", [&]() -> const JsonValue& { return Root.At("matched_primary"); }), "matched_primary");
  Snapshot.MatchedSecondary =
      MatchedFromJson(InField("matched_secondary", [&]() -> const JsonValue& { return Root.At("matched_secondary"); }),
                      "matched_secondary");
  if (const JsonValue* Cache = Root.Find("ratios_cache"); Cache != nullptr && !Cache->IsNull()) {
    std::vector<SnapCacheEntry> Entries;
    const auto& Rows = InField("ratios_cache", [&]() -> const std::vector<JsonValue>& { return Cache->Items(); });
    for (size_t Index = 0; Index < Rows.size(); ++Index) {
      const std::string At = Indexed("ratios_cache", Index);
      const auto& Fields = InField(At, [&]() -> const std::vector<JsonValue>& { return Rows[Index].Items(); });
      if (Fields.size() != 2) {
        throw JsonError("a ratios_cache entry must have 2 fields", JsonError::kNoOffset, At);
      }
      Entries.push_back(SnapCacheEntry{InField(Indexed(At, 0), [&] { return Fields[0].AsString(); }),
                                       InField(Indexed(At, 1), [&] { return ParseRatioBits(Fields[1].AsString()); })});
    }
    Snapshot.RatiosCache = std::move(Entries);
  }
  if (const JsonValue* Choosers = Root.Find("choosers"); Choosers != nullptr && !Choosers->IsNull()) {
    SnapChoosers Dump;
    const auto Member = [&](const char* Name) -> const JsonValue& {
      return InField(std::string("choosers.") + Name, [&]() -> const JsonValue& { return Choosers->At(Name); });
    };
    Dump.Best = ItemsFromJson(Member("best"), "choosers.best");
    Dump.Partial = ItemsFromJson(Member("partial"), "choosers.partial");
    Dump.Unreliable = ItemsFromJson(Member("unreliable"), "choosers.unreliable");
    Dump.Multimatch = ItemsFromJson(Member("multimatch"), "choosers.multimatch");
    Snapshot.Choosers = std::move(Dump);
  }
  if (const JsonValue* Unmatched = Root.Find("unmatched"); Unmatched != nullptr && !Unmatched->IsNull()) {
    if (!Unmatched->IsObject()) {
      throw JsonError("JSON value is not an object", JsonError::kNoOffset, "unmatched");
    }
    SnapUnmatchedDump Dump;
    Dump.Primary = UnmatchedFromJson(Unmatched->Find("primary"), "unmatched.primary");
    Dump.Secondary = UnmatchedFromJson(Unmatched->Find("secondary"), "unmatched.secondary");
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
  // The oracle's WriteJsonAtomic (tools/parity/snapshot.py): the JSON text, then one newline, written to
  // "<path>.tmp" and renamed over the path, so a reader never sees a partial snapshot.
  Detail::ReplaceFileBytes(Path, SerializeSnapshot(Snapshot, Pretty) + "\n");
}

}

// ---------------------------------------------------------------------------------------------
// Checkpoints (Checkpoint.h)

namespace DSig::Diff {

namespace fs = std::filesystem;

namespace Detail {

namespace {
CheckpointFaultHook g_CheckpointFaultHook = nullptr;
}

void SetCheckpointFaultHook(CheckpointFaultHook Hook) { g_CheckpointFaultHook = Hook; }
CheckpointFaultHook GetCheckpointFaultHook() { return g_CheckpointFaultHook; }

}  // namespace Detail

namespace {

struct StepNameEntry {
  PipelineStep Step;
  std::string_view Name;
};

// The names are the stage names of the snapshot points (Appendix B); the two loop cleanups are named by
// their call site.
constexpr StepNameEntry kStepNames[] = {
    {PipelineStep::None, "none"},
    {PipelineStep::EqualMatches, "find_equal_matches"},
    {PipelineStep::DirtyHeuristics, "apply_dirty_heuristics"},
    {PipelineStep::SameName, "find_same_name"},
    {PipelineStep::RemainingFunctions, "find_remaining_functions"},
    {PipelineStep::BestCategory, "run_heuristics_for_category:Best"},
    {PipelineStep::PartialCategory, "run_heuristics_for_category:Partial"},
    {PipelineStep::SmallDifferences, "search_small_differences"},
    {PipelineStep::LoopCleanupTop, "cleanup:3655"},
    {PipelineStep::MatchesDiffing, "find_matches_diffing"},
    {PipelineStep::RelatedMatches, "find_related_matches"},
    {PipelineStep::RelatedCompilationUnit, "find_related_compilation_unit"},
    {PipelineStep::LocallyAffine, "find_locally_affine_functions"},
    {PipelineStep::LoopCleanupBottom, "cleanup:3671"},
    {PipelineStep::FinalPass, "final_pass"},
    {PipelineStep::FindUnmatched, "find_unmatched"},
};

std::string BitsHex(uint64_t Bits) {
  char Buffer[17];
  std::snprintf(Buffer, sizeof(Buffer), "%016llx", static_cast<unsigned long long>(Bits));
  return std::string(Buffer, 16);
}

JsonValue OptionalText(const std::string& Text) { return Text.empty() ? JsonValue::Null() : JsonValue::String(Text); }

std::string ReadOptionalText(const JsonValue& Value) { return Value.IsNull() ? std::string() : Value.AsString(); }

JsonValue BindingToJson(const CheckpointBinding& B) {
  JsonValue Root = JsonValue::Object();
  Root.Set("tool_version", JsonValue::String(B.ToolVersion));
  Root.Set("sqlite_version", JsonValue::String(B.SqliteVersion));
  Root.Set("db1_sha256", JsonValue::String(B.Db1Sha256));
  Root.Set("db1_size", JsonValue::Int(B.Db1Size));
  Root.Set("db1_wal_sha256", OptionalText(B.Db1WalSha256));
  Root.Set("db2_sha256", JsonValue::String(B.Db2Sha256));
  Root.Set("db2_size", JsonValue::Int(B.Db2Size));
  Root.Set("db2_wal_sha256", OptionalText(B.Db2WalSha256));
  Root.Set("ignore_small_functions", JsonValue::Bool(B.IgnoreSmallFunctions));
  Root.Set("related_cu_source", JsonValue::String(B.RelatedCuSource));
  return Root;
}

std::string MemberPath(const std::string& Where, std::string_view Key) {
  return Where.empty() ? std::string(Key) : Where + "." + std::string(Key);
}

const JsonValue& Member(const JsonValue& Object, std::string_view Key, const std::string& Where) {
  if (!Object.IsObject()) {
    throw JsonError("JSON value is not an object", JsonError::kNoOffset, Where.empty() ? "(root)" : Where);
  }
  const JsonValue* Found = Object.Find(Key);
  if (Found == nullptr) {
    throw JsonError("missing member", JsonError::kNoOffset, MemberPath(Where, Key));
  }
  return *Found;
}

CheckpointBinding BindingFromJson(const JsonValue& Value, const std::string& Where) {
  const auto Field = [&](std::string_view Key) -> const JsonValue& { return Member(Value, Key, Where); };
  const auto Path = [&](std::string_view Key) { return MemberPath(Where, Key); };
  CheckpointBinding B;
  B.ToolVersion = InField(Path("tool_version"), [&] { return Field("tool_version").AsString(); });
  B.SqliteVersion = InField(Path("sqlite_version"), [&] { return Field("sqlite_version").AsString(); });
  B.Db1Sha256 = InField(Path("db1_sha256"), [&] { return Field("db1_sha256").AsString(); });
  B.Db1Size = InField(Path("db1_size"), [&] { return Field("db1_size").AsInt64(); });
  B.Db1WalSha256 = InField(Path("db1_wal_sha256"), [&] { return ReadOptionalText(Field("db1_wal_sha256")); });
  B.Db2Sha256 = InField(Path("db2_sha256"), [&] { return Field("db2_sha256").AsString(); });
  B.Db2Size = InField(Path("db2_size"), [&] { return Field("db2_size").AsInt64(); });
  B.Db2WalSha256 = InField(Path("db2_wal_sha256"), [&] { return ReadOptionalText(Field("db2_wal_sha256")); });
  B.IgnoreSmallFunctions =
      InField(Path("ignore_small_functions"), [&] { return Field("ignore_small_functions").AsBool(); });
  B.RelatedCuSource = InField(Path("related_cu_source"), [&] { return Field("related_cu_source").AsString(); });
  return B;
}

void CursorToJson(JsonValue& Root, const PipelineCursor& C) {
  Root.Set("done", JsonValue::String(std::string(PipelineStepName(C.Done))));
  Root.Set("iteration", JsonValue::Int(C.Iteration));
  Root.Set("skip_others", JsonValue::Bool(C.SkipOthers));
  Root.Set("old_total", JsonValue::Int(C.OldTotal));
}

PipelineCursor CursorFromJson(const JsonValue& Value, const std::string& Where) {
  const auto Field = [&](std::string_view Key) -> const JsonValue& { return Member(Value, Key, Where); };
  const auto Path = [&](std::string_view Key) { return MemberPath(Where, Key); };
  PipelineCursor C;
  const std::string Done = InField(Path("done"), [&] { return Field("done").AsString(); });
  const std::optional<PipelineStep> Step = PipelineStepFromName(Done);
  if (!Step || *Step == PipelineStep::None) {
    throw JsonError("unknown stage \"" + Done + "\"", JsonError::kNoOffset, Path("done"));
  }
  C.Done = *Step;
  const int64_t Iteration = InField(Path("iteration"), [&] { return Field("iteration").AsInt64(); });
  if (Iteration < 0 || Iteration > 1000000) {
    throw JsonError("iteration out of range", JsonError::kNoOffset, Path("iteration"));
  }
  C.Iteration = static_cast<int>(Iteration);
  C.SkipOthers = InField(Path("skip_others"), [&] { return Field("skip_others").AsBool(); });
  C.OldTotal = InField(Path("old_total"), [&] { return Field("old_total").AsInt64(); });
  // Only cursors diff() can reach: skip_others is known from apply_dirty_heuristics on, and selects
  // either find_remaining_functions or the heuristic categories and the loop; the iteration is 0
  // outside the loop.
  const bool Categories = C.Done >= PipelineStep::BestCategory && C.Done <= PipelineStep::LoopCleanupBottom;
  const bool Consistent = !(C.SkipOthers && (C.Done < PipelineStep::DirtyHeuristics || Categories)) &&
                          !(!C.SkipOthers && C.Done == PipelineStep::RemainingFunctions) &&
                          (IsLoopStep(C.Done) || C.Iteration == 0) && C.OldTotal >= 0;
  if (!Consistent) {
    throw JsonError("a stage diff() never reaches (done \"" + Done + "\", iteration " + std::to_string(C.Iteration) +
                        ", skip_others " + (C.SkipOthers ? "true" : "false") + ")",
                    JsonError::kNoOffset, Where.empty() ? std::string("(root)") : Where);
  }
  return C;
}

std::string OptionalQuoted(const std::optional<std::string>& Text) { return Text ? JsonQuote(*Text) : "null"; }

}  // namespace

std::string_view PipelineStepName(PipelineStep Step) {
  for (const StepNameEntry& Entry : kStepNames) {
    if (Entry.Step == Step) {
      return Entry.Name;
    }
  }
  return "unknown";
}

std::optional<PipelineStep> PipelineStepFromName(std::string_view Name) {
  for (const StepNameEntry& Entry : kStepNames) {
    if (Entry.Name == Name) {
      return Entry.Step;
    }
  }
  return std::nullopt;
}

bool IsLoopStep(PipelineStep Step) {
  return Step >= PipelineStep::LoopCleanupTop && Step <= PipelineStep::LoopCleanupBottom;
}

std::pair<std::string, int64_t> FileSha256AndSize(const std::string& Utf8Path) {
  std::ifstream In(Detail::PathFromUtf8(Utf8Path), std::ios::binary);
  if (!In) {
    throw IoFailure("cannot read '" + Utf8Path + "'");
  }
  DSig::Sha256 Hasher;
  std::vector<char> Buffer(size_t{1} << 20);
  int64_t Size = 0;
  while (true) {
    In.read(Buffer.data(), static_cast<std::streamsize>(Buffer.size()));
    const std::streamsize Got = In.gcount();
    if (In.bad()) {
      throw IoFailure("cannot read '" + Utf8Path + "'");
    }
    if (Got > 0) {
      Hasher.Update(Buffer.data(), static_cast<size_t>(Got));
      Size += Got;
    }
    if (In.eof()) {
      break;
    }
    if (!In) {
      throw IoFailure("cannot read '" + Utf8Path + "'");
    }
  }
  return {Hasher.FinishHex(), Size};
}

void BindInput(const std::string& Utf8Path, std::string& Sha256, int64_t& Size, std::string& WalSha256) {
  std::tie(Sha256, Size) = FileSha256AndSize(Utf8Path);
  WalSha256.clear();
  const std::string Wal = Utf8Path + "-wal";
  std::error_code Error;
  const fs::path WalPath = Detail::PathFromUtf8(Wal);
  if (fs::is_regular_file(WalPath, Error)) {
    const uintmax_t WalSize = fs::file_size(WalPath, Error);
    if (!Error && WalSize > 0) {
      WalSha256 = FileSha256AndSize(Wal).first;  // committed frames are part of what SQLite reads
    }
  }
}

std::string DescribeBindingMismatch(const CheckpointBinding& Saved, const CheckpointBinding& Now) {
  const auto Text = [](const std::string& Value) { return Value.empty() ? std::string("none") : Value; };
  const auto Differs = [&](const char* Name, const std::string& A, const std::string& B) {
    return A == B ? std::string() : std::string(Name) + " (checkpoint " + Text(A) + ", now " + Text(B) + ")";
  };
  for (const std::string& Found :
       {Differs("tool version", Saved.ToolVersion, Now.ToolVersion),
        Differs("SQLite version", Saved.SqliteVersion, Now.SqliteVersion),
        Differs("db1 sha256", Saved.Db1Sha256, Now.Db1Sha256),
        Differs("db1 size", std::to_string(Saved.Db1Size), std::to_string(Now.Db1Size)),
        Differs("db1 -wal sha256", Saved.Db1WalSha256, Now.Db1WalSha256),
        Differs("db2 sha256", Saved.Db2Sha256, Now.Db2Sha256),
        Differs("db2 size", std::to_string(Saved.Db2Size), std::to_string(Now.Db2Size)),
        Differs("db2 -wal sha256", Saved.Db2WalSha256, Now.Db2WalSha256),
        Differs("--ignore-small-functions", Saved.IgnoreSmallFunctions ? "on" : "off",
                Now.IgnoreSmallFunctions ? "on" : "off"),
        Differs("--related-cu-source", Saved.RelatedCuSource, Now.RelatedCuSource)}) {
    if (!Found.empty()) {
      return Found;
    }
  }
  return std::string();
}

std::string SerializeCheckpointState(const EngineCheckpoint& C) {
  JsonValue State = SnapshotToJson(C.State);
  auto& Members = State.Members();
  for (auto It = Members.begin(); It != Members.end(); ++It) {
    if (It->first == "ratios_cache") {
      Members.erase(It);  // kept below, with exact address texts
      break;
    }
  }
  JsonValue Head = JsonValue::Object();
  Head.Set("schema", JsonValue::String(std::string(kCheckpointStateSchema)));
  Head.Set("binding", BindingToJson(C.Binding));
  JsonValue Cursor = JsonValue::Object();
  CursorToJson(Cursor, C.Cursor);
  Head.Set("cursor", std::move(Cursor));
  Head.Set("point_seq", JsonValue::Int(C.PointSeq));
  JsonValue Counters = JsonValue::Array();
  for (const auto& [Site, Count] : C.CleanupCounters) {
    JsonValue Row = JsonValue::Array();
    Row.Push(JsonValue::Int(Site));
    Row.Push(JsonValue::Int(Count));
    Counters.Push(std::move(Row));
  }
  Head.Set("cleanup_counters", std::move(Counters));
  JsonValue Dones = JsonValue::Array();
  for (const auto& [Name1, Name2] : C.HookDones) {
    JsonValue Row = JsonValue::Array();
    Row.Push(OptionalString(Name1));
    Row.Push(OptionalString(Name2));
    Dones.Push(std::move(Row));
  }
  Head.Set("hook_dones", std::move(Dones));
  Head.Set("state", std::move(State));

  // The ratios cache is by far the largest part (hundreds of thousands of entries on a real pair), so it
  // is appended as text instead of through the DOM.
  std::string Out = JsonWrite(Head);
  Out.pop_back();  // the closing '}' of Head
  Out.reserve(Out.size() + C.RatiosCache.size() * 48 + 32);
  Out += ",\"ratios_cache\":[";
  bool First = true;
  for (const CheckpointCacheEntry& Entry : C.RatiosCache) {
    if (!First) {
      Out += ',';
    }
    First = false;
    Out += '[';
    Out += OptionalQuoted(Entry.Ea1);
    Out += ',';
    Out += OptionalQuoted(Entry.Ea2);
    Out += ",\"";
    Out += BitsHex(Entry.RatioBits);
    Out += "\"]";
  }
  Out += "]}\n";
  return Out;
}

EngineCheckpoint ParseCheckpointState(std::string_view Json) {
  const JsonValue Root = JsonParse(Json);
  if (!Root.IsObject()) {
    throw JsonError("a checkpoint state must be a JSON object", JsonError::kNoOffset, "(root)");
  }
  const std::string Schema = InField("schema", [&] { return Member(Root, "schema", "").AsString(); });
  if (Schema != kCheckpointStateSchema) {
    throw JsonError("unsupported checkpoint state schema \"" + Schema + "\"", JsonError::kNoOffset, "schema");
  }
  EngineCheckpoint C;
  C.Binding = BindingFromJson(Member(Root, "binding", ""), "binding");
  C.Cursor = CursorFromJson(Member(Root, "cursor", ""), "cursor");
  C.PointSeq = InField("point_seq", [&] { return Member(Root, "point_seq", "").AsInt64(); });
  const auto& Counters = InField("cleanup_counters", [&]() -> const std::vector<JsonValue>& {
    return Member(Root, "cleanup_counters", "").Items();
  });
  for (size_t Index = 0; Index < Counters.size(); ++Index) {
    const std::string At = Indexed("cleanup_counters", Index);
    const auto& Row = InField(At, [&]() -> const std::vector<JsonValue>& { return Counters[Index].Items(); });
    if (Row.size() != 2) {
      throw JsonError("a cleanup counter must have 2 fields", JsonError::kNoOffset, At);
    }
    const int64_t Site = InField(Indexed(At, 0), [&] { return Row[0].AsInt64(); });
    if (Site < 0 || Site > 100000) {
      throw JsonError("cleanup site out of range", JsonError::kNoOffset, Indexed(At, 0));
    }
    C.CleanupCounters.emplace_back(static_cast<int>(Site), InField(Indexed(At, 1), [&] { return Row[1].AsInt64(); }));
  }
  const auto& Dones =
      InField("hook_dones", [&]() -> const std::vector<JsonValue>& { return Member(Root, "hook_dones", "").Items(); });
  for (size_t Index = 0; Index < Dones.size(); ++Index) {
    const std::string At = Indexed("hook_dones", Index);
    const auto& Row = InField(At, [&]() -> const std::vector<JsonValue>& { return Dones[Index].Items(); });
    if (Row.size() != 2) {
      throw JsonError("a hook_dones entry must have 2 fields", JsonError::kNoOffset, At);
    }
    C.HookDones.emplace_back(InField(Indexed(At, 0), [&] { return ReadOptionalString(Row[0]); }),
                             InField(Indexed(At, 1), [&] { return ReadOptionalString(Row[1]); }));
  }
  C.State = SnapshotFromJson(Member(Root, "state", ""));
  if (C.State.RatiosCache) {
    throw JsonError("the state must not carry ratios_cache", JsonError::kNoOffset, "state.ratios_cache");
  }
  const auto& Cache = InField("ratios_cache", [&]() -> const std::vector<JsonValue>& {
    return Member(Root, "ratios_cache", "").Items();
  });
  C.RatiosCache.reserve(Cache.size());
  for (size_t Index = 0; Index < Cache.size(); ++Index) {
    const std::string At = Indexed("ratios_cache", Index);
    const auto& Row = InField(At, [&]() -> const std::vector<JsonValue>& { return Cache[Index].Items(); });
    if (Row.size() != 3) {
      throw JsonError("a ratios_cache entry must have 3 fields", JsonError::kNoOffset, At);
    }
    CheckpointCacheEntry Entry;
    Entry.Ea1 = InField(Indexed(At, 0), [&] { return ReadOptionalString(Row[0]); });
    Entry.Ea2 = InField(Indexed(At, 1), [&] { return ReadOptionalString(Row[1]); });
    Entry.RatioBits = InField(Indexed(At, 2), [&] { return ParseRatioBits(Row[2].AsString()); });
    C.RatiosCache.push_back(std::move(Entry));
  }
  return C;
}

std::string SerializeCheckpointManifest(const CheckpointManifest& M) {
  JsonValue Root = JsonValue::Object();
  Root.Set("schema", JsonValue::String(std::string(kCheckpointManifestSchema)));
  Root.Set("binding", BindingToJson(M.Binding));
  CursorToJson(Root, M.Cursor);
  Root.Set("generation", JsonValue::Int(M.Generation));
  Root.Set("state_file", JsonValue::String(M.StateFile));
  Root.Set("state_sha256", JsonValue::String(M.StateSha256));
  Root.Set("state_bytes", JsonValue::Int(M.StateBytes));
  Root.Set("db1", JsonValue::String(M.Db1));
  Root.Set("db2", JsonValue::String(M.Db2));
  Root.Set("created_directory", JsonValue::Bool(M.CreatedDirectory));
  JsonWriteOptions Options;
  Options.Pretty = true;
  return JsonWrite(Root, Options) + "\n";
}

CheckpointManifest ParseCheckpointManifest(std::string_view Json) {
  const JsonValue Root = JsonParse(Json);
  if (!Root.IsObject()) {
    throw JsonError("a checkpoint manifest must be a JSON object", JsonError::kNoOffset, "(root)");
  }
  const std::string Schema = InField("schema", [&] { return Member(Root, "schema", "").AsString(); });
  if (Schema != kCheckpointManifestSchema) {
    throw JsonError("unsupported checkpoint manifest schema \"" + Schema + "\"", JsonError::kNoOffset, "schema");
  }
  CheckpointManifest M;
  M.Binding = BindingFromJson(Member(Root, "binding", ""), "binding");
  M.Cursor = CursorFromJson(Root, "");
  M.Generation = InField("generation", [&] { return Member(Root, "generation", "").AsInt64(); });
  M.StateFile = InField("state_file", [&] { return Member(Root, "state_file", "").AsString(); });
  M.StateSha256 = InField("state_sha256", [&] { return Member(Root, "state_sha256", "").AsString(); });
  M.StateBytes = InField("state_bytes", [&] { return Member(Root, "state_bytes", "").AsInt64(); });
  M.Db1 = InField("db1", [&] { return Member(Root, "db1", "").AsString(); });
  M.Db2 = InField("db2", [&] { return Member(Root, "db2", "").AsString(); });
  M.CreatedDirectory = InField("created_directory", [&] { return Member(Root, "created_directory", "").AsBool(); });
  return M;
}

// ---- CheckpointStore ---------------------------------------------------------------------------

namespace {

constexpr std::string_view kProbeName = ".dsig-checkpoint-probe";

// "state-" + at least six digits + ".json"
bool IsStateFileName(std::string_view Name) {
  constexpr std::string_view Prefix = "state-";
  constexpr std::string_view Suffix = ".json";
  if (Name.size() < Prefix.size() + 6 + Suffix.size() || Name.substr(0, Prefix.size()) != Prefix ||
      Name.substr(Name.size() - Suffix.size()) != Suffix) {
    return false;
  }
  for (const char Ch : Name.substr(Prefix.size(), Name.size() - Prefix.size() - Suffix.size())) {
    if (Ch < '0' || Ch > '9') {
      return false;
    }
  }
  return true;
}

std::string Sha256Hex(std::string_view Bytes) {
  DSig::Sha256 Hasher;
  Hasher.Update(Bytes);
  return Hasher.FinishHex();
}

std::string StateFileName(int64_t Generation) {
  char Buffer[40];
  std::snprintf(Buffer, sizeof(Buffer), "state-%06lld.json", static_cast<long long>(Generation));
  return Buffer;
}

}  // namespace

CheckpointStore::CheckpointStore(std::string Dir) : Dir_(std::move(Dir)) {}

std::string CheckpointStore::ManifestPath() const {
  return Detail::PathToUtf8(Detail::PathFromUtf8(Dir_) / Detail::PathFromUtf8(kCheckpointManifestName));
}

bool CheckpointStore::IsStoreFileName(std::string_view Name) {
  if (Name.size() > 4 && Name.substr(Name.size() - 4) == ".tmp") {
    Name.remove_suffix(4);
  }
  return Name == kCheckpointManifestName || Name == kProbeName || IsStateFileName(Name);
}

bool CheckpointStore::Prepare() {
  const fs::path Root = Detail::PathFromUtf8(Dir_);
  std::error_code Error;
  const bool Existed = fs::exists(Root, Error);
  if (!Existed) {
    Error.clear();
    fs::create_directories(Root, Error);
  }
  std::error_code IsDir;
  if (!fs::is_directory(Root, IsDir)) {
    throw IoFailure("cannot create checkpoint directory '" + Dir_ + "'" +
                    (Existed ? std::string(": it exists and is not a directory")
                             : (Error ? ": " + Error.message() : std::string())));
  }
  const std::string Probe = Detail::PathToUtf8(Root / Detail::PathFromUtf8(kProbeName));
  try {
    Detail::WriteFileBytes(Probe, "probe\n");
  } catch (const IoFailure& Failure) {
    throw IoFailure("checkpoint directory '" + Dir_ + "' is not writable: " + Failure.What);
  }
  Error.clear();
  fs::remove(Detail::PathFromUtf8(Probe), Error);
  if (Error) {
    throw IoFailure("checkpoint directory '" + Dir_ + "': cannot remove the probe file: " + Error.message());
  }
  CreatedDir_ = CreatedDir_ || !Existed;
  return !Existed;
}

bool CheckpointStore::HasManifest() const {
  std::error_code Error;
  return fs::exists(Detail::PathFromUtf8(ManifestPath()), Error);
}

EngineCheckpoint CheckpointStore::Load(CheckpointManifest* ManifestOut) {
  const std::string Restart = " (run the command again without --resume to start from the beginning)";
  const fs::path Root = Detail::PathFromUtf8(Dir_);
  std::error_code Error;
  if (!fs::is_directory(Root, Error)) {
    throw UnsupportedInput("--resume: '" + Dir_ + "' is not a directory, so there is no checkpoint to resume" +
                           Restart);
  }
  if (!HasManifest()) {
    throw UnsupportedInput("--resume: '" + Dir_ + "' holds no checkpoint (no " +
                           std::string(kCheckpointManifestName) + ")" + Restart);
  }
  const std::string Damaged = "--resume: the checkpoint in '" + Dir_ + "' is damaged: ";
  CheckpointManifest Manifest;
  try {
    Manifest = ParseCheckpointManifest(Detail::ReadFileBytes(ManifestPath()));
  } catch (const JsonError& Bad) {
    throw UnsupportedInput(Damaged + std::string(kCheckpointManifestName) + ": " + Bad.what() + Restart);
  }
  if (!IsStateFileName(Manifest.StateFile)) {
    throw UnsupportedInput(Damaged + "the manifest names the state file '" + Manifest.StateFile + "'" + Restart);
  }
  const std::string StatePath = Detail::PathToUtf8(Root / Detail::PathFromUtf8(Manifest.StateFile));
  if (!Detail::PathExists(StatePath)) {
    throw UnsupportedInput(Damaged + "its state file '" + Manifest.StateFile + "' is missing" + Restart);
  }
  const std::string Bytes = Detail::ReadFileBytes(StatePath);
  if (static_cast<int64_t>(Bytes.size()) != Manifest.StateBytes) {
    throw UnsupportedInput(Damaged + "'" + Manifest.StateFile + "' has " + std::to_string(Bytes.size()) +
                           " bytes, the manifest records " + std::to_string(Manifest.StateBytes) + Restart);
  }
  if (Sha256Hex(Bytes) != Manifest.StateSha256) {
    throw UnsupportedInput(Damaged + "the sha256 of '" + Manifest.StateFile + "' differs from the manifest's" +
                           Restart);
  }
  EngineCheckpoint Checkpoint;
  try {
    Checkpoint = ParseCheckpointState(Bytes);
  } catch (const JsonError& Bad) {
    throw UnsupportedInput(Damaged + "'" + Manifest.StateFile + "': " + Bad.what() + Restart);
  }
  if (!(Checkpoint.Binding == Manifest.Binding) || !(Checkpoint.Cursor == Manifest.Cursor)) {
    throw UnsupportedInput(Damaged + "'" + Manifest.StateFile + "' does not belong to its manifest" + Restart);
  }
  Generation_ = Manifest.Generation;
  CreatedDir_ = Manifest.CreatedDirectory;
  if (ManifestOut != nullptr) {
    *ManifestOut = Manifest;
  }
  return Checkpoint;
}

void CheckpointStore::Write(const EngineCheckpoint& Checkpoint, const std::string& Db1, const std::string& Db2) {
  const fs::path Root = Detail::PathFromUtf8(Dir_);
  const int64_t Next = Generation_ + 1;
  CheckpointManifest Manifest;
  Manifest.Binding = Checkpoint.Binding;
  Manifest.Cursor = Checkpoint.Cursor;
  Manifest.Generation = Next;
  Manifest.StateFile = StateFileName(Next);
  Manifest.Db1 = Db1;
  Manifest.Db2 = Db2;
  Manifest.CreatedDirectory = CreatedDir_;
  const std::string Bytes = SerializeCheckpointState(Checkpoint);
  Manifest.StateSha256 = Sha256Hex(Bytes);
  Manifest.StateBytes = static_cast<int64_t>(Bytes.size());
  const std::string StatePath = Detail::PathToUtf8(Root / Detail::PathFromUtf8(Manifest.StateFile));
  const Detail::CheckpointFaultHook Hook = Detail::GetCheckpointFaultHook();
  Detail::ReplaceFileBytesDurable(StatePath, Bytes, Hook, "state");
  try {
    Detail::ReplaceFileBytesDurable(ManifestPath(), SerializeCheckpointManifest(Manifest), Hook, "manifest");
  } catch (...) {
    std::error_code Ignored;
    fs::remove(Detail::PathFromUtf8(StatePath), Ignored);  // the manifest still names the previous state
    throw;
  }
  Generation_ = Next;
  if (Hook != nullptr) {
    Hook("committed");
  }
  // Older state files (and temporary files a killed run left) are no longer named by the manifest.
  std::error_code Error;
  std::vector<fs::path> Stale;
  for (const fs::directory_entry& Entry : fs::directory_iterator(Root, Error)) {
    const std::string Name = Detail::PathToUtf8(Entry.path().filename());
    if (Name != Manifest.StateFile && Name != kCheckpointManifestName && IsStoreFileName(Name)) {
      Stale.push_back(Entry.path());
    }
  }
  for (const fs::path& Path : Stale) {
    std::error_code Ignored;
    fs::remove(Path, Ignored);  // best effort: a leftover is removed by the next checkpoint
  }
}

void CheckpointStore::Remove() {
  const fs::path Root = Detail::PathFromUtf8(Dir_);
  std::error_code Error;
  fs::remove(Detail::PathFromUtf8(ManifestPath()), Error);
  if (Error) {
    throw IoFailure("cannot remove '" + ManifestPath() + "': " + Error.message());
  }
  std::vector<fs::path> Files;
  for (const fs::directory_entry& Entry : fs::directory_iterator(Root, Error)) {
    if (IsStoreFileName(Detail::PathToUtf8(Entry.path().filename()))) {
      Files.push_back(Entry.path());
    }
  }
  for (const fs::path& Path : Files) {
    Error.clear();
    fs::remove(Path, Error);
    if (Error) {
      throw IoFailure("cannot remove '" + Detail::PathToUtf8(Path) + "': " + Error.message());
    }
  }
  if (CreatedDir_) {
    Error.clear();
    if (fs::is_empty(Root, Error) && !Error) {
      fs::remove(Root, Error);  // only an empty directory this run created
    }
  }
}

}
