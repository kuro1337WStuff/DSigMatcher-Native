// diff_ratio: the ratio engine and Python value semantics (lane L2, docs/parity/00-plan.md §4 L2;
// spec 03a in full, 03b §4.1-§4.2, 07 §10.6, 08 §9.3, H-7, H-8).
//
// Every expected value comes from real Diaphora / CPython through tools/parity/gen_ratio_vectors.py:
//   * committed synthetic vectors (tests/diff/vectors/ratio): values.json (float(), "{0:.7f}",
//     repr, json.loads + set, quick_ratio), four 03a-harness databases and the hand-made
//     targeted.json, each run through BOTH md paths (check_match's SQL cast and
//     compare_function_rows' float());
//   * the mutation self-test: every mutation of the 03a §13 table must change at least one vector;
//   * corpus vectors (<corpus>/oracle/vectors/ratio, never committed, skipped when absent): the 03a
//     seed set, the big values file and, per oracle pair, the trace/cache pairs plus a 20k sample.

#include <sqlite3.h>

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "diff/CorpusPaths.h"
#include "diff/TestHarness.h"
#include "dsigmatcher/diff/Errors.h"
#include "dsigmatcher/diff/Json.h"
#include "dsigmatcher/diff/Pipeline.h"
#include "dsigmatcher/diff/PyValue.h"
#include "dsigmatcher/diff/Ratio.h"

namespace DSig::Diff::Testing {
// Defined in src/diff/Ratio.cpp (test seam, see there).
bool SetRatioMutationForTesting(std::string_view Name);
}

namespace {

using namespace DSig::Diff;
namespace fs = std::filesystem;

// ---------------------------------------------------------------------------------------------
// helpers

std::string Hex(double Value) {
  uint64_t Bits = 0;
  std::memcpy(&Bits, &Value, sizeof Bits);
  char Buffer[17];
  std::snprintf(Buffer, sizeof Buffer, "%016llx", static_cast<unsigned long long>(Bits));
  return Buffer;
}

double FromHex(std::string_view Text) {
  uint64_t Bits = 0;
  for (const char Ch : Text) {
    Bits <<= 4;
    if (Ch >= '0' && Ch <= '9') {
      Bits |= static_cast<uint64_t>(Ch - '0');
    } else {
      Bits |= static_cast<uint64_t>(Ch - 'a' + 10);
    }
  }
  double Value = 0.0;
  std::memcpy(&Value, &Bits, sizeof Value);
  return Value;
}

std::string HexBytes(std::string_view Bytes) {
  static const char* const kDigits = "0123456789abcdef";
  std::string Out;
  for (const char Ch : Bytes) {
    const unsigned char Byte = static_cast<unsigned char>(Ch);
    Out += kDigits[Byte >> 4];
    Out += kDigits[Byte & 15];
  }
  return Out;
}

std::string FromHexBytes(std::string_view Hex) {
  std::string Out;
  for (size_t Index = 0; Index + 1 < Hex.size(); Index += 2) {
    auto Nibble = [](char Ch) { return Ch <= '9' ? Ch - '0' : Ch - 'a' + 10; };
    Out += static_cast<char>((Nibble(Hex[Index]) << 4) | Nibble(Hex[Index + 1]));
  }
  return Out;
}

std::optional<std::string> ReadFile(const std::string& Path) {
  std::ifstream In(Path, std::ios::binary);
  if (!In) {
    return std::nullopt;
  }
  std::ostringstream Buffer;
  Buffer << In.rdbuf();
  return Buffer.str();
}

std::optional<JsonValue> ReadJson(const std::string& Path) {
  const auto Text = ReadFile(Path);
  if (!Text) {
    return std::nullopt;
  }
  JsonParseOptions Options;
  Options.PythonCompat = true;
  return JsonParse(*Text, Options);
}

std::string CommittedDir() { return (fs::path(DSig::Test::TestDataDir()) / "vectors" / "ratio").string(); }

// The outcome of a native evaluation in the vector notation: 16 hex digits, "raise" for
// DiaphoraWouldRaise, "unsupported" for UnsupportedInput.
template <class F>
std::string Outcome(F&& Evaluate) {
  try {
    return Hex(Evaluate());
  } catch (const DiaphoraWouldRaise&) {
    return "raise";
  } catch (const UnsupportedInput& Error) {
    return "unsupported: " + Error.What;
  }
}

bool OutcomeMatches(const std::string& Native, std::string_view Expected) {
  if (Expected.substr(0, 6) == "raise:") {
    return Native == "raise";
  }
  return Native == Expected;
}

// ---------------------------------------------------------------------------------------------
// unit tests: 03a §2 and §5

void TestRound7Unit() {
  DSig::Test::Suite("round7: 03a §5 tie table and boundaries");
  // m, L, Python's float("{0:.7f}".format(2m/L)) (half-up would give the last digit + 1)
  struct Case {
    int M;
    int L;
    double Expected;
  };
  const Case Cases[] = {{1, 512, 0.0039062}, {253, 512, 0.9882812}, {255, 512, 0.9960938},
                        {5, 512, 0.0195312}, {3, 1536, 0.0039062}};
  for (const Case& C : Cases) {
    const double V = (2.0 * C.M) / C.L;
    CHECK_TEXT_EQ(Hex(RatioEngine::Round7(V)), Hex(C.Expected));
  }
  CHECK_TEXT_EQ(Hex(RatioEngine::Round7(2.0 / 3.0)), Hex(0.6666667));
  CHECK_TEXT_EQ(Hex(RatioEngine::Round7(0.0)), Hex(0.0));
  CHECK_TEXT_EQ(Hex(RatioEngine::Round7(1.0)), Hex(1.0));
  CHECK_TEXT_EQ(Hex(RatioEngine::Round7(0.99999995)), Hex(0.9999999));  // the double is below the tie
  CHECK_TEXT_EQ(Hex(RatioEngine::Round7(std::nextafter(0.99999995, 1.0))), Hex(1.0));
  CHECK_TEXT_EQ(Hex(RatioEngine::Round7(0.12345675)), Hex(0.1234568));
  CHECK_TEXT_EQ(Hex(RatioEngine::Round7(5e-08)), Hex(0.0));
  CHECK_TEXT_EQ(Hex(RatioEngine::Round7(-0.00000001)), Hex(-0.0));
  CHECK_TEXT_EQ(Hex(RatioEngine::Round7(4.9406564584124654e-324)), Hex(0.0));
  CHECK_TEXT_EQ(Hex(RatioEngine::Round7(1e300)), Hex(1e300));
  // 03a §6.3: the smallest odd total line count whose best non-1 ratio rounds to 1.0
  CHECK_TEXT_EQ(Hex(RatioEngine::Round7((2.0 * 10000000.0) / 20000001.0)), Hex(1.0));
  CHECK_TEXT_EQ(Hex(RatioEngine::Round7((2.0 * 19999999.0) / 40000000.0)), Hex(0.9999999));
  CHECK_TEXT_EQ(Hex(RatioEngine::Round7((2.0 * 20000000.0) / 40000002.0)), Hex(1.0));
}

void TestQuickRatioUnit() {
  DSig::Test::Suite("quick_ratio: 03a §2 split(\"\\n\") examples");
  CHECK_TEXT_EQ(Hex(RatioEngine::QuickRatio("a\nb\n", "a\nb")), Hex(0.8));  // splitlines would give 1.0
  CHECK_TEXT_EQ(Hex(RatioEngine::QuickRatio("\n", "\n\n")), Hex(0.8));
  CHECK_TEXT_EQ(Hex(RatioEngine::QuickRatio(std::nullopt, "a")), Hex(0.0));
  CHECK_TEXT_EQ(Hex(RatioEngine::QuickRatio("", "a")), Hex(0.0));
  CHECK_TEXT_EQ(Hex(RatioEngine::QuickRatio("a", "a")), Hex(1.0));
  CHECK_TEXT_EQ(Hex(RatioEngine::QuickRatio("a\r\nb", "a\nb")), Hex(0.5));  // "\r" stays in the line
  CHECK_TEXT_EQ(Hex(RatioEngine::QuickRatio("x\ny\nx", "x\nx\nz")), Hex((2.0 * 2.0) / 6.0));
  const std::string WithNul("a\0b", 3);
  CHECK_TEXT_EQ(Hex(RatioEngine::QuickRatio(WithNul, "a")), Hex(0.0));  // embedded NUL is data
}

// ---------------------------------------------------------------------------------------------
// values vectors (float(), "{0:.7f}", repr, json.loads + set, quick_ratio)

std::string KindName(PyValue::Kind Kind) {
  switch (Kind) {
    case PyValue::Kind::None:
      return "NoneType";
    case PyValue::Kind::Bool:
      return "bool";
    case PyValue::Kind::Int:
      return "int";
    case PyValue::Kind::Float:
      return "float";
    case PyValue::Kind::Str:
      return "str";
    case PyValue::Kind::List:
      return "list";
    case PyValue::Kind::Dict:
      return "dict";
  }
  return "?";
}

// TaggedPy of gen_ratio_vectors.py, rebuilt from a PyValue.
JsonValue Tagged(const PyValue& Value) {
  JsonValue Out = JsonValue::Object();
  switch (Value.Type) {
    case PyValue::Kind::None:
      return JsonValue::Null();
    case PyValue::Kind::Bool:
      Out.Set("bool", JsonValue::Bool(Value.BoolValue));
      break;
    case PyValue::Kind::Int:
      Out.Set("int", JsonValue::String(Value.IntDigits));
      break;
    case PyValue::Kind::Float:
      Out.Set("float", JsonValue::String(std::isnan(Value.FloatValue) ? "nan" : Hex(Value.FloatValue)));
      break;
    case PyValue::Kind::Str:
      Out.Set("str", JsonValue::String(HexBytes(Value.StrValue)));
      break;
    case PyValue::Kind::List: {
      JsonValue Items = JsonValue::Array();
      for (const PyValue& Item : Value.Items) {
        Items.Push(Tagged(Item));
      }
      Out.Set("list", std::move(Items));
      break;
    }
    case PyValue::Kind::Dict: {
      JsonValue Items = JsonValue::Array();
      for (size_t Index = 0; Index < Value.Items.size(); ++Index) {
        JsonValue Pair = JsonValue::Array();
        Pair.Push(JsonValue::String(HexBytes(Value.Items[Index].StrValue)));
        Pair.Push(Tagged(Value.DictValues[Index]));
        Items.Push(std::move(Pair));
      }
      Out.Set("dict", std::move(Items));
      break;
    }
  }
  return Out;
}

struct ValuesCounts {
  size_t Round7 = 0, Round7Bad = 0, Float = 0, FloatBad = 0, Repr = 0, ReprBad = 0, Json = 0, JsonBad = 0,
         Sets = 0, SetsBad = 0, Quick = 0, QuickBad = 0;
};

void RunValues(const JsonValue& Doc, ValuesCounts& C, bool Verbose) {
  auto Report = [&](const std::string& Line) {
    if (Verbose) {
      DSig::Test::Note(Line);
    }
  };
  for (const JsonValue& Row : Doc.At("round7").Items()) {
    const double In = FromHex(Row.Items()[0].AsString());
    const std::string Got = Hex(RatioEngine::Round7(In));
    ++C.Round7;
    if (Got != Row.Items()[1].AsString()) {
      ++C.Round7Bad;
      Report("round7 " + Row.Items()[0].AsString() + ": native " + Got + ", python " + Row.Items()[1].AsString());
    }
  }
  for (const JsonValue& Row : Doc.At("pyfloat").Items()) {
    const std::string& Text = Row.Items()[0].AsString();
    const std::string& Expected = Row.Items()[1].AsString();
    std::string Got;
    try {
      const std::optional<double> Value = PyFloat(Text);
      if (!Value) {
        Got = "ValueError";
      } else if (std::isnan(*Value)) {
        Got = std::signbit(*Value) ? "-nan" : "nan";
      } else {
        Got = Hex(*Value);
      }
    } catch (const UnsupportedInput&) {
      Got = "unsupported";
    }
    ++C.Float;
    if (Got != Expected) {
      ++C.FloatBad;
      Report("float(" + Text.substr(0, 60) + "): native " + Got + ", python " + Expected);
    }
  }
  for (const JsonValue& Row : Doc.At("repr").Items()) {
    const std::string Got = PyReprFloat(FromHex(Row.Items()[0].AsString()));
    ++C.Repr;
    if (Got != Row.Items()[1].AsString()) {
      ++C.ReprBad;
      Report("repr " + Row.Items()[0].AsString() + ": native " + Got + ", python " + Row.Items()[1].AsString());
    }
  }
  for (const JsonValue& Row : Doc.At("json_loads").Items()) {
    const std::string& Text = Row.Items()[0].AsString();
    const JsonValue& Expected = Row.Items()[1];
    const std::string Marker = Expected.IsString() ? Expected.AsString() : "";
    // Python's own RecursionError, or a value nested deeper than the port's limit of 512: the port
    // refuses (UnsupportedInput), because Python's recursion depth is NOT DETERMINED FROM SOURCE.
    const bool Deep = Marker == "RecursionError" || (Row.Items().size() > 2 && Row.Items()[2].AsInt64() > 512);
    std::string Native = "value";
    PyValue Value;
    try {
      Value = PyJsonLoads(Text);
    } catch (const DiaphoraWouldRaise&) {
      Native = "raise";
    } catch (const UnsupportedInput&) {
      Native = "refused";
    }
    std::string Verdict;
    ++C.Json;
    if (Marker == "raise") {
      Verdict = Native == "raise" ? "" : "python raised, native " + Native;
    } else if (Deep) {
      Verdict = Native == "refused" ? "" : "expected the depth refusal, native " + Native;
    } else if (Native != "value") {
      Verdict = "python parsed, native " + Native;
    } else if (!(Tagged(Value) == Expected)) {
      Verdict = "value differs: " + JsonWrite(Tagged(Value));
    }
    if (!Verdict.empty()) {
      ++C.JsonBad;
      Report("json.loads(" + Text.substr(0, 40) + "): " + Verdict);
    }
  }
  for (const JsonValue& Row : Doc.At("json_sets").Items()) {
    ++C.Sets;
    std::string Verdict;
    std::string Raised;
    PySet A;
    PySet B;
    try {
      A = PySetFromList(PyJsonLoadsList(Row.At("a").AsString()));
    } catch (const DiaphoraWouldRaise&) {
      Raised = "a";
    }
    if (Raised.empty()) {
      try {
        B = PySetFromList(PyJsonLoadsList(Row.At("b").AsString()));
      } catch (const DiaphoraWouldRaise&) {
        Raised = "b";
      }
    }
    if (const JsonValue* Raise = Row.Find("raise")) {
      if (Raise->AsString().substr(0, 1) != Raised) {
        Verdict = "expected a raise on side " + Raise->AsString() + ", native: " + (Raised.empty() ? "none" : Raised);
      }
    } else if (!Raised.empty()) {
      Verdict = "native raised on side " + Raised;
    } else {
      std::vector<std::string> Elements;
      for (const PyValue& Item : PySetIntersection(A, B)) {
        Elements.push_back(KindName(Item.Type) + ":" + HexBytes(PyStr(Item)));
      }
      std::sort(Elements.begin(), Elements.end());
      std::vector<std::string> Expected;
      for (const JsonValue& Item : Row.At("elements").Items()) {
        Expected.push_back(Item.AsString());
      }
      if (static_cast<int64_t>(A.Size()) != Row.At("len_a").AsInt64() ||
          static_cast<int64_t>(B.Size()) != Row.At("len_b").AsInt64() ||
          static_cast<int64_t>(PySetIntersectionSize(A, B)) != Row.At("common").AsInt64() ||
          static_cast<int64_t>(PySetIntersectionSize(B, A)) != Row.At("common").AsInt64() || Elements != Expected) {
        Verdict = "sizes or elements differ";
      }
    }
    if (!Verdict.empty()) {
      ++C.SetsBad;
      Report("set(" + Row.At("a").AsString().substr(0, 30) + ") & set(" + Row.At("b").AsString().substr(0, 30) +
             "): " + Verdict);
    }
  }
  for (const JsonValue& Row : Doc.At("quick_ratio").Items()) {
    const auto Side = [](const JsonValue& V) -> std::optional<std::string> {
      if (V.IsNull()) {
        return std::nullopt;
      }
      return V.AsString();
    };
    const auto A = Side(Row.Items()[0]);
    const auto B = Side(Row.Items()[1]);
    const std::string Got = Hex(RatioEngine::QuickRatio(A ? std::optional<std::string_view>(*A) : std::nullopt,
                                                        B ? std::optional<std::string_view>(*B) : std::nullopt));
    ++C.Quick;
    if (Got != Row.Items()[2].AsString()) {
      ++C.QuickBad;
      Report("quick_ratio: native " + Got + ", python " + Row.Items()[2].AsString());
    }
  }
}

void CheckValuesFile(const std::string& Path, const char* Name) {
  const auto Doc = ReadJson(Path);
  if (!Doc) {
    DSig::Test::Skip(Name, "missing " + Path);
    return;
  }
  DSig::Test::Suite(Name);
  ValuesCounts C;
  RunValues(*Doc, C, true);
  DSig::Test::Note("round7 " + std::to_string(C.Round7) + ", float() " + std::to_string(C.Float) + ", repr " +
                   std::to_string(C.Repr) + ", json.loads " + std::to_string(C.Json) + ", set " +
                   std::to_string(C.Sets) + ", quick_ratio " + std::to_string(C.Quick) + " vectors");
  CHECK(C.Round7 > 0 && C.Float > 0 && C.Repr > 0 && C.Json > 0 && C.Sets > 0 && C.Quick > 0);
  CHECK_NUM_EQ(C.Round7Bad, 0);
  CHECK_NUM_EQ(C.FloatBad, 0);
  CHECK_NUM_EQ(C.ReprBad, 0);
  CHECK_NUM_EQ(C.JsonBad, 0);
  CHECK_NUM_EQ(C.SetsBad, 0);
  CHECK_NUM_EQ(C.QuickBad, 0);
}

void TestPyValueUnit() {
  DSig::Test::Suite("PyValue: 03a §7.1 set semantics and float() edges");
  const auto SetOf = [](std::string_view Text) { return PySetFromList(PyJsonLoadsList(Text)); };
  CHECK_NUM_EQ(SetOf("[1, 1.0, \"1\"]").Size(), 2);  // {1, '1'}
  CHECK_NUM_EQ(PySetIntersectionSize(SetOf("[1]"), SetOf("[true]")), 1);
  CHECK_NUM_EQ(PySetIntersectionSize(SetOf("[NaN]"), SetOf("[NaN]")), 1);  // the json module's NaN singleton
  CHECK_NUM_EQ(PySetIntersectionSize(SetOf("[18446744073709551615]"), SetOf("[18446744073709551614]")), 0);
  CHECK_NUM_EQ(PySetIntersectionSize(SetOf("[\"\\u00e9\"]"), SetOf("[\"\xc3\xa9\"]")), 1);
  bool Raised = false;
  try {
    SetOf("[[1, 2]]");
  } catch (const DiaphoraWouldRaise&) {
    Raised = true;
  }
  CHECK(Raised);
  // 03a §6.4 (synthetic 28-digit string): Python's float() is correctly rounded, SQLite 3.51.1's cast
  // gives the double below (0.4008152925841381); the md paths must never share a converter.
  CHECK_TEXT_EQ(Hex(*PyFloat("0.4008152925841381442166209413")), Hex(0.40081529258413817));
  CHECK(Hex(0.40081529258413817) != Hex(0.4008152925841381));
  CHECK(!PyFloat("1.5abc").has_value());
  CHECK(!PyFloat("").has_value());
  CHECK_TEXT_EQ(Hex(*PyFloat(" 1_000 ")), Hex(1000.0));
  CHECK_TEXT_EQ(PyReprFloat(1e16), "1e+16");
  CHECK_TEXT_EQ(PyReprFloat(0.0001), "0.0001");
  CHECK_TEXT_EQ(PyReprFloat(1e-05), "1e-05");
  CHECK_TEXT_EQ(PyReprFloat(-0.0), "-0.0");
  PyValue Big;
  Big.Type = PyValue::Kind::Int;
  Big.IntDigits = "18446744073709551616";
  PyValue AsFloat;
  AsFloat.Type = PyValue::Kind::Float;
  AsFloat.FloatValue = 18446744073709551616.0;
  CHECK(PyEquals(Big, AsFloat));
  CHECK(PyHash(Big) == PyHash(AsFloat));
  CHECK_TEXT_EQ(PyStr(AsFloat), "1.8446744073709552e+19");
  bool Refused = false;
  try {
    (void)PyFloat("\xd9\xa1");  // ARABIC-INDIC DIGIT ONE: Python maps it to '1' (Unicode database)
  } catch (const UnsupportedInput&) {
    Refused = true;
  }
  CHECK(Refused);
}

// ---------------------------------------------------------------------------------------------
// synthetic database vectors

std::string DecodeText(const JsonValue& Value, const std::vector<std::string>& Vocab) {
  std::string Out;
  bool First = true;
  for (const JsonValue& Run : Value.At("t").Items()) {
    const std::string& Line = Vocab[static_cast<size_t>(Run.Items()[0].AsInt64())];
    const int64_t Count = Run.Items()[1].AsInt64();
    for (int64_t Index = 0; Index < Count; ++Index) {
      if (!First) {
        Out += '\n';
      }
      Out += Line;
      First = false;
    }
  }
  return Out;
}

// Builds one side's database from the vector document with Python's bind types (str -> TEXT, int ->
// INTEGER, bytes -> BLOB, None -> NULL). Returns "" or the error text.
std::string BuildSide(const JsonValue& Doc, const char* Key, const std::string& Path) {
  std::error_code Ignored;
  for (const char* Suffix : {"", "-wal", "-shm", "-journal"}) {
    fs::remove(Path + Suffix, Ignored);
  }
  sqlite3* Db = nullptr;
  if (sqlite3_open_v2(Path.c_str(), &Db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) != SQLITE_OK) {
    sqlite3_close(Db);
    return "cannot create " + Path;
  }
  std::string Error;
  for (const JsonValue& Ddl : Doc.At("ddl").Items()) {
    if (sqlite3_exec(Db, Ddl.AsString().c_str(), nullptr, nullptr, nullptr) != SQLITE_OK) {
      Error = std::string("ddl: ") + sqlite3_errmsg(Db);
    }
  }
  std::vector<std::string> Vocab;
  if (const JsonValue* V = Doc.Find("vocab")) {
    for (const JsonValue& Line : V->Items()) {
      Vocab.push_back(Line.AsString());
    }
  }
  const auto& Columns = Doc.At("columns").Items();
  std::string Sql = "insert into functions (";
  std::string Marks;
  for (size_t Index = 0; Index < Columns.size(); ++Index) {
    Sql += (Index ? "," : "") + Columns[Index].AsString();
    Marks += Index ? ",?" : "?";
  }
  Sql += ") values (" + Marks + ")";
  sqlite3_exec(Db, "begin", nullptr, nullptr, nullptr);
  sqlite3_stmt* Stmt = nullptr;
  if (Error.empty() && sqlite3_prepare_v2(Db, Sql.c_str(), -1, &Stmt, nullptr) != SQLITE_OK) {
    Error = std::string("prepare: ") + sqlite3_errmsg(Db);
  }
  for (const JsonValue& Row : Doc.At(Key).Items()) {
    if (!Error.empty()) {
      break;
    }
    for (size_t Index = 0; Index < Row.Items().size(); ++Index) {
      const JsonValue& Value = Row.Items()[Index];
      const int Param = static_cast<int>(Index) + 1;
      if (Value.IsNull()) {
        sqlite3_bind_null(Stmt, Param);
      } else if (Value.IsNumber()) {
        sqlite3_bind_int64(Stmt, Param, static_cast<sqlite3_int64>(Value.AsInt64()));
      } else if (Value.IsString()) {
        const std::string& Text = Value.AsString();
        sqlite3_bind_text(Stmt, Param, Text.data(), static_cast<int>(Text.size()), SQLITE_TRANSIENT);
      } else if (Value.Find("b") != nullptr) {
        const std::string Bytes = FromHexBytes(Value.At("b").AsString());
        sqlite3_bind_blob(Stmt, Param, Bytes.data(), static_cast<int>(Bytes.size()), SQLITE_TRANSIENT);
      } else {
        const std::string Text = DecodeText(Value, Vocab);
        sqlite3_bind_text(Stmt, Param, Text.data(), static_cast<int>(Text.size()), SQLITE_TRANSIENT);
      }
    }
    if (sqlite3_step(Stmt) != SQLITE_DONE) {
      Error = std::string("insert: ") + sqlite3_errmsg(Db);
    }
    sqlite3_reset(Stmt);
  }
  sqlite3_finalize(Stmt);
  sqlite3_exec(Db, "commit", nullptr, nullptr, nullptr);
  sqlite3_close(Db);
  return Error;
}

struct PairCounts {
  size_t Pairs = 0;
  size_t SqlBad = 0;
  size_t PyBad = 0;
  size_t PySrcBad = 0;
  size_t MdSqlChecked = 0;
  size_t MdSqlBad = 0;
};

std::optional<double> MdFromVector(const JsonValue& Value) {
  if (Value.IsNull()) {
    return std::nullopt;
  }
  return FromHex(Value.AsString());
}

// Runs every (main, diff) pair of a synthetic vector document through the native engine: CheckRatio on
// the SQL path (md1/md2 exactly as Python's row had them), CompareFunctionRows and CheckRatio on the
// Python path; ratios_cache is emptied before each call, as the generator did.
std::optional<PairCounts> RunSyntheticDoc(const JsonValue& Doc, const std::string& Scratch, bool Verbose) {
  const std::string Name = Doc.At("name").AsString();
  const std::string MainPath = (fs::path(Scratch) / (Name + "-main.sqlite")).string();
  const std::string DiffPath = (fs::path(Scratch) / (Name + "-diff.sqlite")).string();
  for (const auto& [Key, Path] : {std::pair<const char*, std::string>{"main", MainPath}, {"diff", DiffPath}}) {
    const std::string Error = BuildSide(Doc, Key, Path);
    if (!Error.empty()) {
      DSig::Test::Note(Name + ": " + Error);
      return std::nullopt;
    }
  }
  DiffSession S;
  S.Open(MainPath, DiffPath);
  S.Flags().IsSameProcessor = Doc.At("same_processor").AsBool();
  RatioEngine& E = S.Engine();
  E.Prepare();
  const FunctionTable& M = S.Main().Functions;
  const FunctionTable& D = S.Diff().Functions;
  const auto& MainMd = Doc.At("main_md_sql").Items();
  const auto& DiffMd = Doc.At("diff_md_sql").Items();
  const auto& Outcomes = Doc.At("outcomes").Items();
  const auto& Results = Doc.At("results").Items();
  PairCounts C;
  if (M.Count() != MainMd.size() || D.Count() != DiffMd.size() || Results.size() != M.Count() * D.Count()) {
    DSig::Test::Note(Name + ": table sizes differ from the vector file");
    return std::nullopt;
  }
  if (DSig::Test::OracleSqlite()) {
    // ingest's cast(md_index as real) is SQLite's own conversion (plan §3.3): equal to Python's row md
    for (uint32_t Row = 0; Row < M.Count() + D.Count(); ++Row) {
      const bool IsMain = Row < M.Count();
      const FunctionTable& T = IsMain ? M : D;
      const uint32_t R = IsMain ? Row : Row - static_cast<uint32_t>(M.Count());
      const std::optional<double> Expected = MdFromVector(IsMain ? MainMd[R] : DiffMd[R]);
      const std::optional<double> Got = T.MdSqlNull[R] ? std::nullopt : std::optional<double>(T.MdSqlReal[R]);
      ++C.MdSqlChecked;
      if (Expected.has_value() != Got.has_value() || (Got && Hex(*Got) != Hex(*Expected))) {
        ++C.MdSqlBad;
      }
    }
  }
  const std::vector<std::string> Labels = [&] {
    std::vector<std::string> Out;
    if (const JsonValue* L = Doc.Find("labels")) {
      for (const JsonValue& Label : L->Items()) {
        Out.push_back(Label.AsString());
      }
    }
    return Out;
  }();
  size_t Shown = 0;
  for (uint32_t I = 0; I < M.Count(); ++I) {
    for (uint32_t J = 0; J < D.Count(); ++J) {
      const std::string& Expected = Outcomes[static_cast<size_t>(Results[I * D.Count() + J].AsInt64())].AsString();
      const size_t Bar = Expected.find('|');
      const std::string ExpectedSql = Expected.substr(0, Bar);
      const std::string ExpectedPy = Bar == std::string::npos ? Expected : Expected.substr(Bar + 1);
      HeuristicRow Row;
      Row.Ea1 = M.AddrIdOf[I];
      Row.Ea2 = D.AddrIdOf[J];
      Row.Row1 = I;
      Row.Row2 = J;
      Row.Md1 = MdFromVector(MainMd[I]);
      Row.Md2 = MdFromVector(DiffMd[J]);
      E.ClearCache();
      const std::string Sql = Outcome([&] { return E.CheckRatio(Row, MdSource::Sql); });
      E.ClearCache();
      const std::string Py = Outcome([&] { return E.CompareFunctionRows(I, J); });
      E.ClearCache();
      const std::string PySrc = Outcome([&] { return E.CheckRatio(Row, MdSource::Python); });
      ++C.Pairs;
      const bool SqlOk = OutcomeMatches(Sql, ExpectedSql);
      const bool PyOk = OutcomeMatches(Py, ExpectedPy);
      const bool PySrcOk = OutcomeMatches(PySrc, ExpectedPy);
      C.SqlBad += !SqlOk;
      C.PyBad += !PyOk;
      C.PySrcBad += !PySrcOk;
      if (Verbose && (!SqlOk || !PyOk || !PySrcOk) && Shown++ < 12) {
        const std::string What = I < Labels.size() && J < Labels.size() ? " [" + Labels[I] + " x " + Labels[J] + "]" : "";
        DSig::Test::Note(Name + " (" + std::to_string(I) + "," + std::to_string(J) + ")" + What + ": sql " + Sql +
                         " vs " + ExpectedSql + "; py " + Py + " / " + PySrc + " vs " + ExpectedPy);
      }
    }
  }
  return C;
}

std::vector<std::string> SyntheticFiles(const std::string& Dir) {
  std::vector<std::string> Files;
  std::error_code Error;
  if (!fs::is_directory(Dir, Error)) {
    return Files;
  }
  for (const auto& Entry : fs::directory_iterator(Dir, Error)) {
    const std::string Name = Entry.path().filename().string();
    if (Entry.path().extension() == ".json" && Name.rfind("values", 0) != 0) {
      Files.push_back(Entry.path().string());
    }
  }
  std::sort(Files.begin(), Files.end());
  return Files;
}

void CheckSyntheticDir(const std::string& Dir, const char* Name, size_t MinFiles) {
  const std::vector<std::string> Files = SyntheticFiles(Dir);
  if (Files.empty()) {
    DSig::Test::Skip(Name, "no vector files under " + Dir);
    return;
  }
  DSig::Test::Suite(Name);
  CHECK(Files.size() >= MinFiles);
  const std::string Scratch = DSig::Test::ScratchDir("diff_ratio");
  size_t Total = 0;
  for (const std::string& File : Files) {
    const auto Doc = ReadJson(File);
    CHECK(Doc.has_value());
    if (!Doc) {
      continue;
    }
    const auto C = RunSyntheticDoc(*Doc, Scratch, true);
    CHECK(C.has_value());
    if (!C) {
      continue;
    }
    Total += C->Pairs;
    DSig::Test::Note(fs::path(File).filename().string() + ": " + std::to_string(C->Pairs) + " pairs, mismatches sql " +
                     std::to_string(C->SqlBad) + ", compare_function_rows " + std::to_string(C->PyBad) +
                     ", CheckRatio(Python) " + std::to_string(C->PySrcBad) +
                     (C->MdSqlChecked ? ", ingest md cast " + std::to_string(C->MdSqlBad) + "/" +
                                            std::to_string(C->MdSqlChecked)
                                      : std::string(", ingest md cast not checked (SQLite is not 3.51.1)")));
    CHECK(C->Pairs > 0);
    CHECK_NUM_EQ(C->SqlBad, 0);
    CHECK_NUM_EQ(C->PyBad, 0);
    CHECK_NUM_EQ(C->PySrcBad, 0);
    CHECK_NUM_EQ(C->MdSqlBad, 0);
  }
  DSig::Test::Note(std::to_string(Total) + " pairs x 3 native evaluations in total");
  DSig::Test::RemoveScratchDir(Scratch);
}

// ---------------------------------------------------------------------------------------------
// mutation self-test (03a §13): each mutation must break at least one committed vector

void TestMutations() {
  DSig::Test::Suite("mutation self-test: 03a §13 table");
  std::vector<JsonValue> Docs;
  for (const std::string& File : SyntheticFiles(CommittedDir())) {
    if (auto Doc = ReadJson(File)) {
      Docs.push_back(std::move(*Doc));
    }
  }
  CHECK(!Docs.empty());
  const std::string Scratch = DSig::Test::ScratchDir("diff_ratio_mut");
  const char* const Mutations[] = {"round_half_up",     "no_rounding",  "no_clamp",
                                   "constants_as_doubles", "no_v5_short_circuit", "no_md_guard",
                                   "null_bytes_hash_not_equal", "splitlines", "always_0008",
                                   "md_as_strings",     "swap_md_source"};
  for (const char* Mutation : Mutations) {
    CHECK(Testing::SetRatioMutationForTesting(Mutation));
    size_t Changed = 0;
    for (const JsonValue& Doc : Docs) {
      if (const auto C = RunSyntheticDoc(Doc, Scratch, false)) {
        Changed += C->SqlBad + C->PyBad + C->PySrcBad;
      }
    }
    Testing::SetRatioMutationForTesting("");
    DSig::Test::Note(std::string(Mutation) + ": " + std::to_string(Changed) + " native evaluations changed");
    CHECK(Changed > 0);
  }
  CHECK(!Testing::SetRatioMutationForTesting("no_such_mutation"));
  // unmutated again: the vectors pass (the seam leaves no state behind)
  size_t Clean = 0;
  for (const JsonValue& Doc : Docs) {
    if (const auto C = RunSyntheticDoc(Doc, Scratch, false)) {
      Clean += C->SqlBad + C->PyBad + C->PySrcBad;
    }
  }
  CHECK_NUM_EQ(Clean, 0);
  DSig::Test::RemoveScratchDir(Scratch);
}

// ---------------------------------------------------------------------------------------------
// ratios_cache (03a §8) and deep_ratio order (03a §7.2) on the targeted databases

std::optional<uint32_t> LabelIndex(const JsonValue& Doc, std::string_view Label) {
  const auto& Labels = Doc.At("labels").Items();
  for (size_t Index = 0; Index < Labels.size(); ++Index) {
    if (Labels[Index].AsString() == Label) {
      return static_cast<uint32_t>(Index);
    }
  }
  return std::nullopt;
}

void TestCacheAndDeep() {
  DSig::Test::Suite("ratios_cache first writer wins, raises, keys; deep_ratio order");
  const auto Doc = ReadJson((fs::path(CommittedDir()) / "targeted.json").string());
  CHECK(Doc.has_value());
  if (!Doc) {
    return;
  }
  const std::string Scratch = DSig::Test::ScratchDir("diff_ratio_cache");
  const std::string MainPath = (fs::path(Scratch) / "t-main.sqlite").string();
  const std::string DiffPath = (fs::path(Scratch) / "t-diff.sqlite").string();
  CHECK_TEXT_EQ(BuildSide(*Doc, "main", MainPath), "");
  CHECK_TEXT_EQ(BuildSide(*Doc, "diff", DiffPath), "");
  {
    DiffSession S;
    S.Open(MainPath, DiffPath);
    S.Flags().IsSameProcessor = true;
    RatioEngine& E = S.Engine();
    const FunctionTable& M = S.Main().Functions;
    const FunctionTable& D = S.Diff().Functions;
    auto RowFor = [&](uint32_t I, uint32_t J) {
      HeuristicRow Row;
      Row.Ea1 = M.AddrIdOf[I];
      Row.Ea2 = D.AddrIdOf[J];
      Row.Row1 = I;
      Row.Row2 = J;
      Row.Md1 = MdFromVector(Doc->At("main_md_sql").Items()[I]);
      Row.Md2 = MdFromVector(Doc->At("diff_md_sql").Items()[J]);
      return Row;
    };
    // A pair whose SQL-path and Python-path ratios differ (the md converters, 03a §6.4).
    const auto K = LabelIndex(*Doc, "md SQLite-equal");
    CHECK(K.has_value());
    if (K) {
      E.ClearCache();
      const double Sql = E.CheckRatio(RowFor(*K, *K), MdSource::Sql);
      E.ClearCache();
      const double Py = E.CompareFunctionRows(*K, *K);
      CHECK(Hex(Sql) != Hex(Py));
      E.ClearCache();
      (void)E.CheckRatio(RowFor(*K, *K), MdSource::Sql);
      CHECK_TEXT_EQ(Hex(E.CompareFunctionRows(*K, *K)), Hex(Sql));  // the SQL path wrote first
      E.ClearCache();
      (void)E.CompareFunctionRows(*K, *K);
      CHECK_TEXT_EQ(Hex(E.CheckRatio(RowFor(*K, *K), MdSource::Sql)), Hex(Py));  // the row path wrote first
      CHECK_NUM_EQ(E.CacheSnapshot().size(), 1);
    }
    // An exception stores nothing and raises again; a cached pair never raises (D:1654 before D:1672).
    const auto N = LabelIndex(*Doc, "NULL md raises first");
    CHECK(N.has_value());
    if (N) {
      E.ClearCache();
      bool First = false;
      bool Second = false;
      try {
        E.CheckRatio(RowFor(*N, *N), MdSource::Sql);
      } catch (const DiaphoraWouldRaise&) {
        First = true;
      }
      CHECK(!E.Cached(M.AddrIdOf[*N], D.AddrIdOf[*N]).has_value());
      try {
        E.CompareFunctionRows(*N, *N);
      } catch (const DiaphoraWouldRaise&) {
        Second = true;
      }
      CHECK(First && Second);
      E.SeedCache(M.AddrIdOf[*N], D.AddrIdOf[*N], 0.25);
      CHECK_TEXT_EQ(Hex(E.CheckRatio(RowFor(*N, *N), MdSource::Sql)), Hex(0.25));
      E.SeedCache(M.AddrIdOf[*N], D.AddrIdOf[*N], 0.5);  // first writer wins
      CHECK_TEXT_EQ(Hex(*E.Cached(M.AddrIdOf[*N], D.AddrIdOf[*N])), Hex(0.25));
    }
    // Insertion order of the snapshot (Python dict order).
    E.ClearCache();
    E.SeedCache(M.AddrIdOf[3], D.AddrIdOf[1], 0.5);
    E.SeedCache(M.AddrIdOf[1], D.AddrIdOf[3], 0.75);
    (void)E.CheckRatio(RowFor(0, 0), MdSource::Sql);
    const auto Snapshot = E.CacheSnapshot();
    CHECK_NUM_EQ(Snapshot.size(), 3);
    if (Snapshot.size() == 3) {
      CHECK(Snapshot[0].Ea1 == M.AddrIdOf[3] && Snapshot[1].Ea1 == M.AddrIdOf[1] && Snapshot[2].Ea1 == M.AddrIdOf[0]);
    }
    // The key is the text f"{ea1}-{ea2}" (D:1653): "1-2" + "3" and "1" + "2-3" share "1-2-3", and None
    // renders as "None".
    E.ClearCache();
    Interners& Ids = S.Ids();
    E.SeedCache(Ids.Addr("1-2"), Ids.Addr("3"), 0.125);
    CHECK(E.Cached(Ids.Addr("1"), Ids.Addr("2-3")).has_value());
    CHECK(!E.Cached(Ids.Addr("1"), Ids.Addr("23")).has_value());
    E.SeedCache(kNoneAddr, Ids.Addr("5"), 0.375);
    CHECK(E.Cached(Ids.Addr("None"), Ids.Addr("5")).has_value());
    CHECK(!E.Cached(Ids.Addr("12"), Ids.Addr("3")).has_value());
    // deep_ratio adds its terms one at a time in D:2780-2821 order (03a §7.2).
    const auto Deep = LabelIndex(*Doc, "all deep features");
    CHECK(Deep.has_value());
    if (Deep) {
      double Expected = 0.0;
      Expected += 0.001;  // source_file
      Expected += 0.001;  // pseudocode_primes
      Expected += 0.001;  // indegree
      Expected += 0.001;  // outdegree
      Expected += 0.003;  // switches
      Expected += 0.001;  // cyclomatic_complexity
      const double Product = 3.0 * 0.006;  // three shared constants, same processor
      Expected += Product;
      CHECK_TEXT_EQ(Hex(E.DeepRatio(*Deep, *Deep)), Hex(Expected));
      S.Flags().IsSameProcessor = false;
      double Other = 0.0;
      Other += 0.001;
      Other += 0.001;
      Other += 0.001;
      Other += 0.001;
      Other += 0.003;
      Other += 0.001;
      const double OtherProduct = 3.0 * 0.008;
      Other += OtherProduct;
      CHECK_TEXT_EQ(Hex(E.DeepRatio(*Deep, *Deep)), Hex(Other));
      S.Flags().IsSameProcessor = true;
    }
  }
  DSig::Test::RemoveScratchDir(Scratch);
}

// ---------------------------------------------------------------------------------------------
// corpus vectors (<corpus>/oracle/vectors/ratio, generated by `gen_ratio_vectors.py corpus`)

struct TsvTable {
  std::map<std::string, std::string> Header;
  std::vector<std::vector<std::string>> Rows;
};

std::vector<std::string> SplitTabs(std::string_view Line) {
  std::vector<std::string> Out;
  size_t Start = 0;
  while (true) {
    const size_t Tab = Line.find('\t', Start);
    Out.emplace_back(Line.substr(Start, Tab == std::string_view::npos ? std::string_view::npos : Tab - Start));
    if (Tab == std::string_view::npos) {
      return Out;
    }
    Start = Tab + 1;
  }
}

std::optional<TsvTable> ReadTsv(const std::string& Path) {
  const auto Text = ReadFile(Path);
  if (!Text) {
    return std::nullopt;
  }
  TsvTable Table;
  std::istringstream In(*Text);
  std::string Line;
  bool SeenColumns = false;
  while (std::getline(In, Line)) {
    if (!Line.empty() && Line.back() == '\r') {
      Line.pop_back();
    }
    if (Line.empty()) {
      continue;
    }
    if (Line[0] == '#') {
      const auto Fields = SplitTabs(std::string_view(Line).substr(2));
      if (Fields.size() >= 2) {
        Table.Header[Fields[0]] = Fields[1];
      }
      continue;
    }
    if (!SeenColumns) {
      SeenColumns = true;  // the column-name line
      continue;
    }
    Table.Rows.push_back(SplitTabs(Line));
  }
  return Table;
}

struct MdEntry {
  std::string Sql;
  std::string Py;
};

std::unordered_map<std::string, MdEntry> ReadMdFile(const std::string& Path) {
  std::unordered_map<std::string, MdEntry> Out;
  if (const auto Table = ReadTsv(Path)) {
    for (const auto& Row : Table->Rows) {
      if (Row.size() >= 3) {
        Out[Row[0]] = MdEntry{Row[1], Row[2]};
      }
    }
  }
  return Out;
}

void CheckCorpusPair(const std::string& TsvPath, const std::string& VectorsDir) {
  const auto Table = ReadTsv(TsvPath);
  CHECK(Table.has_value());
  if (!Table) {
    return;
  }
  const std::string Pair = Table->Header.count("pair") ? Table->Header.at("pair") : TsvPath;
  const std::string Ref = Table->Header.count("ref") ? Table->Header.at("ref") : "";
  const std::string Target = Table->Header.count("target") ? Table->Header.at("target") : "";
  if (!DSig::Test::ExportAvailable(Ref) || !DSig::Test::ExportAvailable(Target)) {
    DSig::Test::Note(Pair + ": exports missing, skipped");
    return;
  }
  const auto MdRef = ReadMdFile((fs::path(VectorsDir) / ("md-" + Ref + ".tsv")).string());
  const auto MdTarget = ReadMdFile((fs::path(VectorsDir) / ("md-" + Target + ".tsv")).string());
  DiffSession S;
  S.Open(DSig::Test::ExportPath(Ref), DSig::Test::ExportPath(Target));
  S.Flags().IsSameProcessor = Table->Header.count("same_processor") && Table->Header.at("same_processor") == "1";
  RatioEngine& E = S.Engine();
  E.Prepare();
  const FunctionTable& M = S.Main().Functions;
  const FunctionTable& D = S.Diff().Functions;

  // md_index per function: PyFloat against Python float(); ingest's SQLite cast against Python's
  // sqlite3 cast when the linked SQLite is the oracle's 3.51.1.
  size_t MdChecked = 0;
  size_t MdPyBad = 0;
  size_t MdSqlBad = 0;
  for (const auto& [Table2, Md] : {std::pair<const FunctionTable*, const decltype(MdRef)*>{&M, &MdRef}, {&D, &MdTarget}}) {
    for (uint32_t Row = 0; Row < Table2->Count(); ++Row) {
      const auto Found = Md->find(std::string(Table2->Address.View(Row)));
      if (Found == Md->end()) {
        continue;
      }
      ++MdChecked;
      std::string Py = "raise:TypeError";
      if (!Table2->MdIndex.Null(Row)) {
        const std::optional<double> Value = PyFloat(Table2->MdIndex.View(Row));
        Py = !Value ? "ValueError" : std::isnan(*Value) ? "nan" : Hex(*Value);
      }
      MdPyBad += Py != Found->second.Py;
      if (DSig::Test::OracleSqlite()) {
        const std::string Sql = Table2->MdSqlNull[Row] ? "null" : Hex(Table2->MdSqlReal[Row]);
        MdSqlBad += Sql != Found->second.Sql;
      }
    }
  }

  size_t Vectors = 0;
  size_t SqlBad = 0;
  size_t PyBad = 0;
  size_t PySrcBad = 0;
  size_t InSitu = 0;
  size_t InSituBad = 0;
  size_t Unmapped = 0;
  size_t Shown = 0;
  for (const auto& Row : Table->Rows) {
    if (Row.size() < 6) {
      continue;
    }
    const auto Id1 = S.Ids().FindAddr(Row[0]);
    const auto Id2 = S.Ids().FindAddr(Row[1]);
    const auto R1 = Id1 ? M.FindRow(*Id1) : std::nullopt;
    const auto R2 = Id2 ? D.FindRow(*Id2) : std::nullopt;
    if (!R1 || !R2) {
      ++Unmapped;
      continue;
    }
    HeuristicRow H;
    H.Ea1 = *Id1;
    H.Ea2 = *Id2;
    H.Row1 = *R1;
    H.Row2 = *R2;
    // md1/md2 exactly as Python's SELECT_FIELDS row had them (cast(md_index as real) under 3.51.1)
    const auto Md1 = MdRef.find(Row[0]);
    const auto Md2 = MdTarget.find(Row[1]);
    if (Md1 != MdRef.end() && Md1->second.Sql != "null") {
      H.Md1 = FromHex(Md1->second.Sql);
    }
    if (Md2 != MdTarget.end() && Md2->second.Sql != "null") {
      H.Md2 = FromHex(Md2->second.Sql);
    }
    E.ClearCache();
    const std::string Sql = Outcome([&] { return E.CheckRatio(H, MdSource::Sql); });
    E.ClearCache();
    const std::string Py = Outcome([&] { return E.CompareFunctionRows(*R1, *R2); });
    E.ClearCache();
    const std::string PySrc = Outcome([&] { return E.CheckRatio(H, MdSource::Python); });
    ++Vectors;
    const bool SqlOk = OutcomeMatches(Sql, Row[2]);
    const bool PyOk = OutcomeMatches(Py, Row[3]);
    const bool PySrcOk = OutcomeMatches(PySrc, Row[3]);
    SqlBad += !SqlOk;
    PyBad += !PyOk;
    PySrcBad += !PySrcOk;
    if (Row[5] != "-") {
      // the value the real run cached or used: it came from one of the two paths (first writer)
      ++InSitu;
      InSituBad += Row[5] != Row[2] && Row[5] != Row[3];
    }
    if ((!SqlOk || !PyOk || !PySrcOk) && Shown++ < 10) {
      DSig::Test::Note(Pair + " " + Row[0] + "-" + Row[1] + ": sql " + Sql + " vs " + Row[2] + "; py " + Py + " / " +
                       PySrc + " vs " + Row[3]);
    }
  }
  DSig::Test::Note(Pair + ": " + std::to_string(Vectors) + " vectors (" + std::to_string(Unmapped) +
                   " unmapped), mismatches sql " + std::to_string(SqlBad) + ", compare_function_rows " +
                   std::to_string(PyBad) + ", CheckRatio(Python) " + std::to_string(PySrcBad) + "; in-situ " +
                   std::to_string(InSitu) + " (" + std::to_string(InSituBad) + " outside {sql, py}); md " +
                   std::to_string(MdChecked) + " functions, float() mismatches " + std::to_string(MdPyBad) +
                   (DSig::Test::OracleSqlite() ? ", cast mismatches " + std::to_string(MdSqlBad)
                                               : std::string(", cast not checked")));
  CHECK(Vectors > 0);
  CHECK_NUM_EQ(Unmapped, 0);
  CHECK_NUM_EQ(SqlBad, 0);
  CHECK_NUM_EQ(PyBad, 0);
  CHECK_NUM_EQ(PySrcBad, 0);
  CHECK_NUM_EQ(InSituBad, 0);
  CHECK(MdChecked == M.Count() + D.Count());
  CHECK_NUM_EQ(MdPyBad, 0);
  CHECK_NUM_EQ(MdSqlBad, 0);
}

void TestCorpusVectors() {
  if (!DSig::Test::CorpusRoot()) {
    DSig::Test::Skip("corpus ratio vectors", "DSIG_CORPUS_ROOT is not set");
    return;
  }
  const std::string Root = DSig::Test::VectorsDir("ratio");
  const std::string CorpusDir = (fs::path(Root) / "corpus").string();
  std::vector<std::string> Files;
  std::error_code Error;
  if (fs::is_directory(CorpusDir, Error)) {
    for (const auto& Entry : fs::directory_iterator(CorpusDir, Error)) {
      const std::string Name = Entry.path().filename().string();
      if (Entry.path().extension() == ".tsv" && Name.rfind("md-", 0) != 0) {
        Files.push_back(Entry.path().string());
      }
    }
  }
  std::sort(Files.begin(), Files.end());
  if (Files.empty()) {
    DSig::Test::Skip("corpus ratio vectors", "no vectors under " + CorpusDir + " (run gen_ratio_vectors.py corpus)");
  } else {
    DSig::Test::Suite("corpus ratio vectors: oracle pairs, both md paths");
    for (const std::string& File : Files) {
      CheckCorpusPair(File, CorpusDir);
    }
  }
  CheckSyntheticDir((fs::path(Root) / "synthetic-03a").string(), "03a seed set (synthetic, corpus dir)", 14);
  CheckValuesFile((fs::path(Root) / "values-big.json").string(), "values-big (corpus dir)");
}

}  // namespace

int main() {
  TestRound7Unit();
  TestQuickRatioUnit();
  TestPyValueUnit();
  CheckValuesFile((fs::path(CommittedDir()) / "values.json").string(), "values.json: CPython value semantics");
  CheckSyntheticDir(CommittedDir(), "committed synthetic ratio vectors: real check_ratio / compare_function_rows", 5);
  TestCacheAndDeep();
  TestMutations();
  TestCorpusVectors();
  return DSig::Test::Finish();
}
