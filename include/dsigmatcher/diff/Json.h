#pragma once

// Minimal JSON DOM for the snapshot/trace formats (docs/parity/00-plan.md Appendix B) and for
// Python-compatible parsing. Numbers are kept as their source text, so big integers survive exactly;
// callers convert with AsInt64 / AsDouble / AsUInt64. Objects keep member order; a duplicate key
// replaces the earlier value in place (Python dict semantics of json.loads).
//
// JsonParseOptions::PythonCompat accepts the NaN / Infinity / -Infinity literals Python's json module
// reads and writes. Strict mode (the default for both) rejects raw control characters U+0000-U+001F
// inside strings, as json.loads(strict=True) does. \u escapes are decoded to UTF-8; an unpaired
// surrogate is kept as its 3-byte generalized UTF-8 form (Python keeps it as a lone code point).

#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace DSig::Diff {

// The deepest nesting of arrays and objects any parser in DSig::Diff accepts (JsonParse here, and
// PyValue.cpp's json.loads port). A recursive descent parser needs one stack frame set per level; 512
// stays far below the measured crash depth (about 3000 levels in a release build, audit F30), so a
// hostile snapshot or export sidecar gets a clean JsonError instead of a stack overflow.
inline constexpr int kMaxJsonDepth = 512;

class JsonError : public std::runtime_error {
public:
  static constexpr size_t kNoOffset = static_cast<size_t>(-1);

  // `Offset` is the byte offset of a syntax error, or kNoOffset for an error about a parsed value (a
  // wrong kind, a missing member). `Where` is the member path of that value, such as
  // "all_matches.best[0][6]", when the caller knows it (audit F58).
  JsonError(const std::string& Message, size_t Offset, std::string Where = std::string())
      : std::runtime_error(Format(Message, Offset, Where)), Position(Offset), Detail(Message), Path(std::move(Where)) {}
  size_t Position = 0;
  std::string Detail;  // the message alone, without path and offset
  std::string Path;    // the member path, or "" when unknown

private:
  static std::string Format(const std::string& Message, size_t Offset, const std::string& Where) {
    std::string Text = Where.empty() ? Message : Where + ": " + Message;
    if (Offset != kNoOffset) {
      Text += " at offset " + std::to_string(Offset);
    }
    return Text;
  }
};

class JsonValue {
public:
  enum class Kind : uint8_t { Null, Bool, Number, String, Array, Object };

  JsonValue() = default;
  static JsonValue Null() { return JsonValue(); }
  static JsonValue Bool(bool Value);
  static JsonValue Number(std::string Text);  // Text must be a JSON number or NaN/Infinity/-Infinity
  static JsonValue Int(int64_t Value);
  static JsonValue UInt(uint64_t Value);
  static JsonValue String(std::string Utf8);
  static JsonValue Array();
  static JsonValue Object();

  Kind GetKind() const { return Kind_; }
  bool IsNull() const { return Kind_ == Kind::Null; }
  bool IsBool() const { return Kind_ == Kind::Bool; }
  bool IsNumber() const { return Kind_ == Kind::Number; }
  bool IsString() const { return Kind_ == Kind::String; }
  bool IsArray() const { return Kind_ == Kind::Array; }
  bool IsObject() const { return Kind_ == Kind::Object; }

  // Accessors throw JsonError when the kind does not match.
  bool AsBool() const;
  const std::string& NumberText() const;
  bool IsIntegerText() const;        // an integer literal (no '.', 'e' or NaN/Infinity)
  int64_t AsInt64() const;           // integer literal within int64 range
  uint64_t AsUInt64() const;         // non-negative integer literal within uint64 range
  double AsDouble() const;           // Python float(text): correctly rounded, overflow +-inf, underflow
                                     // +-0.0; NaN/Infinity allowed (no floating-point from_chars)
  const std::string& AsString() const;

  const std::vector<JsonValue>& Items() const;
  std::vector<JsonValue>& Items();
  const std::vector<std::pair<std::string, JsonValue>>& Members() const;
  std::vector<std::pair<std::string, JsonValue>>& Members();

  const JsonValue* Find(std::string_view Key) const;  // object member or nullptr
  const JsonValue& At(std::string_view Key) const;    // throws JsonError when absent
  JsonValue& Set(std::string Key, JsonValue Value);   // replaces in place or appends
  JsonValue& Push(JsonValue Value);                   // array append

  friend bool operator==(const JsonValue& A, const JsonValue& B);

private:
  Kind Kind_ = Kind::Null;
  bool Bool_ = false;
  std::string Text_;  // number text or string bytes
  std::vector<JsonValue> Items_;
  std::vector<std::pair<std::string, JsonValue>> Members_;
};

struct JsonParseOptions {
  bool PythonCompat = false;         // accept NaN, Infinity, -Infinity
  bool StrictControlChars = true;    // reject raw U+0000-U+001F in strings
};

JsonValue JsonParse(std::string_view Text, const JsonParseOptions& Options = {});

// True when Text is exactly one JSON number literal (Python's NUMBER_RE, without NaN / Infinity).
bool IsJsonNumberText(std::string_view Text);

struct JsonWriteOptions {
  bool Pretty = false;               // newline + two-space indent; compact (the default) is exactly
                                     // json.dumps(ensure_ascii=False, separators=(",", ":"))
};

std::string JsonWrite(const JsonValue& Value, const JsonWriteOptions& Options = {});
// A JSON string literal (with quotes) for UTF-8 text; non-ASCII is written as raw UTF-8,
// control characters as \uXXXX (or \n, \t, ...).
std::string JsonQuote(std::string_view Utf8);

}
