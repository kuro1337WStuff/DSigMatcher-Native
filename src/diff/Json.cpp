// Minimal JSON DOM, parser and writer (docs/parity/00-plan.md Appendix B). Grammar follows Python's
// json module: NUMBER_RE `-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][-+]?[0-9]+)?`, whitespace " \t\n\r",
// NaN / Infinity / -Infinity only in PythonCompat mode, strict control characters.
//
// The compact writer produces exactly the bytes of the oracle's
// json.dumps(obj, ensure_ascii=False, separators=(",", ":"), allow_nan=False) (tools/parity/snapshot.py
// DumpJson) for the values the parity formats hold: members in insertion order, no whitespace,
// numbers as their source text, strings with json's ESCAPE_DCT escapes (quote, backslash, newline,
// carriage return, tab, backspace, form feed; every other U+0000-U+001F as a six-character escape
// with lowercase hex digits) and all other bytes, non-ASCII included, written raw
// (Lib/json/encoder.py py_encode_basestring with ensure_ascii=False).

#include "dsigmatcher/diff/Json.h"

#include <charconv>  // integer from_chars only: no floating-point <charconv> (older Apple libc++ lacks it)
#include <cmath>
#include <cstdio>
#include <limits>
#include <system_error>

#include "dsigmatcher/diff/PyValue.h"

namespace DSig::Diff {

// ---------------------------------------------------------------------------------------------
// JsonValue

JsonValue JsonValue::Bool(bool Value) {
  JsonValue Result;
  Result.Kind_ = Kind::Bool;
  Result.Bool_ = Value;
  return Result;
}

JsonValue JsonValue::Number(std::string Text) {
  JsonValue Result;
  Result.Kind_ = Kind::Number;
  Result.Text_ = std::move(Text);
  return Result;
}

JsonValue JsonValue::Int(int64_t Value) { return Number(std::to_string(Value)); }

JsonValue JsonValue::UInt(uint64_t Value) { return Number(std::to_string(Value)); }

JsonValue JsonValue::String(std::string Utf8) {
  JsonValue Result;
  Result.Kind_ = Kind::String;
  Result.Text_ = std::move(Utf8);
  return Result;
}

JsonValue JsonValue::Array() {
  JsonValue Result;
  Result.Kind_ = Kind::Array;
  return Result;
}

JsonValue JsonValue::Object() {
  JsonValue Result;
  Result.Kind_ = Kind::Object;
  return Result;
}

bool IsJsonNumberText(std::string_view Text) {
  // NUMBER_RE -?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][-+]?[0-9]+)?
  size_t Pos = 0;
  const auto Digit = [&](size_t At) { return At < Text.size() && Text[At] >= '0' && Text[At] <= '9'; };
  if (Pos < Text.size() && Text[Pos] == '-') {
    ++Pos;
  }
  if (!Digit(Pos)) {
    return false;
  }
  if (Text[Pos] == '0') {
    ++Pos;
  } else {
    while (Digit(Pos)) {
      ++Pos;
    }
  }
  if (Pos < Text.size() && Text[Pos] == '.') {
    ++Pos;
    if (!Digit(Pos)) {
      return false;
    }
    while (Digit(Pos)) {
      ++Pos;
    }
  }
  if (Pos < Text.size() && (Text[Pos] == 'e' || Text[Pos] == 'E')) {
    ++Pos;
    if (Pos < Text.size() && (Text[Pos] == '+' || Text[Pos] == '-')) {
      ++Pos;
    }
    if (!Digit(Pos)) {
      return false;
    }
    while (Digit(Pos)) {
      ++Pos;
    }
  }
  return Pos == Text.size();
}

namespace {

[[noreturn]] void KindError(const char* Wanted) {
  throw JsonError(std::string("JSON value is not ") + Wanted, JsonError::kNoOffset);
}

}

bool JsonValue::AsBool() const {
  if (Kind_ != Kind::Bool) {
    KindError("a boolean");
  }
  return Bool_;
}

const std::string& JsonValue::NumberText() const {
  if (Kind_ != Kind::Number) {
    KindError("a number");
  }
  return Text_;
}

bool JsonValue::IsIntegerText() const {
  if (Kind_ != Kind::Number || Text_.empty()) {
    return false;
  }
  for (const char Ch : Text_) {
    if (Ch == '.' || Ch == 'e' || Ch == 'E' || Ch == 'N' || Ch == 'I') {
      return false;
    }
  }
  return true;
}

int64_t JsonValue::AsInt64() const {
  if (!IsIntegerText()) {
    KindError("an integer");
  }
  int64_t Value = 0;
  const auto Result = std::from_chars(Text_.data(), Text_.data() + Text_.size(), Value);
  if (Result.ec != std::errc() || Result.ptr != Text_.data() + Text_.size()) {
    throw JsonError("integer out of int64 range: " + Text_, JsonError::kNoOffset);
  }
  return Value;
}

uint64_t JsonValue::AsUInt64() const {
  if (!IsIntegerText() || Text_[0] == '-') {
    KindError("a non-negative integer");
  }
  uint64_t Value = 0;
  const auto Result = std::from_chars(Text_.data(), Text_.data() + Text_.size(), Value);
  if (Result.ec != std::errc() || Result.ptr != Text_.data() + Text_.size()) {
    throw JsonError("integer out of uint64 range: " + Text_, JsonError::kNoOffset);
  }
  return Value;
}

double JsonValue::AsDouble() const {
  if (Kind_ != Kind::Number) {
    KindError("a number");
  }
  if (Text_ == "NaN") {
    return std::numeric_limits<double>::quiet_NaN();
  }
  if (Text_ == "Infinity") {
    return std::numeric_limits<double>::infinity();
  }
  if (Text_ == "-Infinity") {
    return -std::numeric_limits<double>::infinity();
  }
  // Python's json module converts a number literal with float(text) (Lib/json/scanner.py), which is
  // correctly rounded (dtoa.c) and gives +-inf for an overflowing literal and +-0.0 for an underflowing
  // one. PyFloat is that conversion in exact big-integer arithmetic, so no floating-point from_chars is
  // needed (older Apple libc++ lacks it). Only the JSON number grammar is accepted here: PyFloat alone
  // would also take "inf", "1_0" or surrounding spaces.
  if (!IsJsonNumberText(Text_)) {
    throw JsonError("bad number: " + Text_, JsonError::kNoOffset);
  }
  const std::optional<double> Value = PyFloat(Text_);
  if (!Value) {
    throw JsonError("bad number: " + Text_, JsonError::kNoOffset);
  }
  return *Value;
}

const std::string& JsonValue::AsString() const {
  if (Kind_ != Kind::String) {
    KindError("a string");
  }
  return Text_;
}

const std::vector<JsonValue>& JsonValue::Items() const {
  if (Kind_ != Kind::Array) {
    KindError("an array");
  }
  return Items_;
}

std::vector<JsonValue>& JsonValue::Items() {
  if (Kind_ != Kind::Array) {
    KindError("an array");
  }
  return Items_;
}

const std::vector<std::pair<std::string, JsonValue>>& JsonValue::Members() const {
  if (Kind_ != Kind::Object) {
    KindError("an object");
  }
  return Members_;
}

std::vector<std::pair<std::string, JsonValue>>& JsonValue::Members() {
  if (Kind_ != Kind::Object) {
    KindError("an object");
  }
  return Members_;
}

const JsonValue* JsonValue::Find(std::string_view Key) const {
  if (Kind_ != Kind::Object) {
    return nullptr;
  }
  for (const auto& Member : Members_) {
    if (Member.first == Key) {
      return &Member.second;
    }
  }
  return nullptr;
}

const JsonValue& JsonValue::At(std::string_view Key) const {
  const JsonValue* Value = Find(Key);
  if (Value == nullptr) {
    throw JsonError("missing member \"" + std::string(Key) + "\"", JsonError::kNoOffset);
  }
  return *Value;
}

JsonValue& JsonValue::Set(std::string Key, JsonValue Value) {
  if (Kind_ != Kind::Object) {
    KindError("an object");
  }
  for (auto& Member : Members_) {
    if (Member.first == Key) {
      Member.second = std::move(Value);
      return Member.second;
    }
  }
  Members_.emplace_back(std::move(Key), std::move(Value));
  return Members_.back().second;
}

JsonValue& JsonValue::Push(JsonValue Value) {
  if (Kind_ != Kind::Array) {
    KindError("an array");
  }
  Items_.push_back(std::move(Value));
  return Items_.back();
}

bool operator==(const JsonValue& A, const JsonValue& B) {
  if (A.Kind_ != B.Kind_) {
    return false;
  }
  switch (A.Kind_) {
    case JsonValue::Kind::Null:
      return true;
    case JsonValue::Kind::Bool:
      return A.Bool_ == B.Bool_;
    case JsonValue::Kind::Number:
    case JsonValue::Kind::String:
      return A.Text_ == B.Text_;
    case JsonValue::Kind::Array:
      return A.Items_ == B.Items_;
    case JsonValue::Kind::Object:
      return A.Members_ == B.Members_;
  }
  return false;
}

// ---------------------------------------------------------------------------------------------
// Parser

namespace {

void AppendUtf8(std::string& Out, uint32_t Code) {
  if (Code < 0x80) {
    Out += static_cast<char>(Code);
  } else if (Code < 0x800) {
    Out += static_cast<char>(0xC0 | (Code >> 6));
    Out += static_cast<char>(0x80 | (Code & 0x3F));
  } else if (Code < 0x10000) {
    // includes lone surrogates (generalized UTF-8), which Python keeps as code points
    Out += static_cast<char>(0xE0 | (Code >> 12));
    Out += static_cast<char>(0x80 | ((Code >> 6) & 0x3F));
    Out += static_cast<char>(0x80 | (Code & 0x3F));
  } else {
    Out += static_cast<char>(0xF0 | (Code >> 18));
    Out += static_cast<char>(0x80 | ((Code >> 12) & 0x3F));
    Out += static_cast<char>(0x80 | ((Code >> 6) & 0x3F));
    Out += static_cast<char>(0x80 | (Code & 0x3F));
  }
}

class Parser {
public:
  Parser(std::string_view Text, const JsonParseOptions& Options) : Text_(Text), Options_(Options) {}

  JsonValue ParseDocument() {
    SkipWhitespace();
    JsonValue Value = ParseValue(0);
    SkipWhitespace();
    if (Pos_ != Text_.size()) {
      Fail("Extra data");
    }
    return Value;
  }

private:
  [[noreturn]] void Fail(const std::string& Message) const { throw JsonError(Message, Pos_); }

  void SkipWhitespace() {
    while (Pos_ < Text_.size()) {
      const char Ch = Text_[Pos_];
      if (Ch == ' ' || Ch == '\t' || Ch == '\n' || Ch == '\r') {
        ++Pos_;
      } else {
        break;
      }
    }
  }

  bool Consume(std::string_view Literal) {
    if (Text_.substr(Pos_, Literal.size()) == Literal) {
      Pos_ += Literal.size();
      return true;
    }
    return false;
  }

  JsonValue ParseValue(int Depth) {
    if (Pos_ >= Text_.size()) {
      Fail("Expecting value");
    }
    const char Ch = Text_[Pos_];
    if (Ch == '{') {
      return ParseObject(Depth);
    }
    if (Ch == '[') {
      return ParseArray(Depth);
    }
    if (Ch == '"') {
      return JsonValue::String(ParseString());
    }
    if (Consume("null")) {
      return JsonValue::Null();
    }
    if (Consume("true")) {
      return JsonValue::Bool(true);
    }
    if (Consume("false")) {
      return JsonValue::Bool(false);
    }
    if (Options_.PythonCompat) {
      if (Consume("NaN")) {
        return JsonValue::Number("NaN");
      }
      if (Consume("Infinity")) {
        return JsonValue::Number("Infinity");
      }
      if (Consume("-Infinity")) {
        return JsonValue::Number("-Infinity");
      }
    }
    if (Ch == '-' || (Ch >= '0' && Ch <= '9')) {
      return ParseNumber();
    }
    Fail("Expecting value");
  }

  JsonValue ParseNumber() {
    const size_t Start = Pos_;
    if (Text_[Pos_] == '-') {
      ++Pos_;
    }
    if (Pos_ >= Text_.size()) {
      Fail("Expecting value");
    }
    if (Text_[Pos_] == '0') {
      ++Pos_;
    } else if (Text_[Pos_] >= '1' && Text_[Pos_] <= '9') {
      while (Pos_ < Text_.size() && Text_[Pos_] >= '0' && Text_[Pos_] <= '9') {
        ++Pos_;
      }
    } else {
      Fail("Expecting value");
    }
    // Python's NUMBER_RE makes the fraction and exponent optional groups: "1." stops after "1".
    if (Pos_ + 1 < Text_.size() && Text_[Pos_] == '.' && Text_[Pos_ + 1] >= '0' && Text_[Pos_ + 1] <= '9') {
      ++Pos_;
      while (Pos_ < Text_.size() && Text_[Pos_] >= '0' && Text_[Pos_] <= '9') {
        ++Pos_;
      }
    }
    if (Pos_ < Text_.size() && (Text_[Pos_] == 'e' || Text_[Pos_] == 'E')) {
      size_t Probe = Pos_ + 1;
      if (Probe < Text_.size() && (Text_[Probe] == '+' || Text_[Probe] == '-')) {
        ++Probe;
      }
      if (Probe < Text_.size() && Text_[Probe] >= '0' && Text_[Probe] <= '9') {
        Pos_ = Probe;
        while (Pos_ < Text_.size() && Text_[Pos_] >= '0' && Text_[Pos_] <= '9') {
          ++Pos_;
        }
      }
    }
    return JsonValue::Number(std::string(Text_.substr(Start, Pos_ - Start)));
  }

  uint32_t ParseHex4() {
    if (Pos_ + 4 > Text_.size()) {
      Fail("Invalid \\uXXXX escape");
    }
    uint32_t Value = 0;
    for (int Index = 0; Index < 4; ++Index) {
      const char Ch = Text_[Pos_++];
      Value <<= 4;
      if (Ch >= '0' && Ch <= '9') {
        Value |= static_cast<uint32_t>(Ch - '0');
      } else if (Ch >= 'a' && Ch <= 'f') {
        Value |= static_cast<uint32_t>(Ch - 'a' + 10);
      } else if (Ch >= 'A' && Ch <= 'F') {
        Value |= static_cast<uint32_t>(Ch - 'A' + 10);
      } else {
        Fail("Invalid \\uXXXX escape");
      }
    }
    return Value;
  }

  std::string ParseString() {
    ++Pos_;  // opening quote
    std::string Out;
    while (true) {
      if (Pos_ >= Text_.size()) {
        Fail("Unterminated string");
      }
      const unsigned char Ch = static_cast<unsigned char>(Text_[Pos_]);
      if (Ch == '"') {
        ++Pos_;
        return Out;
      }
      if (Ch == '\\') {
        ++Pos_;
        if (Pos_ >= Text_.size()) {
          Fail("Unterminated string");
        }
        const char Escape = Text_[Pos_++];
        switch (Escape) {
          case '"':
            Out += '"';
            break;
          case '\\':
            Out += '\\';
            break;
          case '/':
            Out += '/';
            break;
          case 'b':
            Out += '\b';
            break;
          case 'f':
            Out += '\f';
            break;
          case 'n':
            Out += '\n';
            break;
          case 'r':
            Out += '\r';
            break;
          case 't':
            Out += '\t';
            break;
          case 'u': {
            uint32_t Code = ParseHex4();
            // json/decoder.py py_scanstring: a high surrogate followed by \u + low surrogate pairs up
            if (Code >= 0xD800 && Code <= 0xDBFF && Pos_ + 6 <= Text_.size() && Text_[Pos_] == '\\' &&
                Text_[Pos_ + 1] == 'u') {
              const size_t Save = Pos_;
              Pos_ += 2;
              const uint32_t Low = ParseHex4();
              if (Low >= 0xDC00 && Low <= 0xDFFF) {
                Code = 0x10000 + ((Code - 0xD800) << 10) + (Low - 0xDC00);
              } else {
                Pos_ = Save;
              }
            }
            AppendUtf8(Out, Code);
            break;
          }
          default:
            Fail("Invalid \\escape");
        }
        continue;
      }
      if (Ch < 0x20 && Options_.StrictControlChars) {
        Fail("Invalid control character");
      }
      Out += static_cast<char>(Ch);
      ++Pos_;
    }
  }

  JsonValue ParseArray(int Depth) {
    if (Depth >= kMaxJsonDepth) {
      Fail("nesting too deep (more than " + std::to_string(kMaxJsonDepth) + " levels)");
    }
    ++Pos_;
    JsonValue Result = JsonValue::Array();
    SkipWhitespace();
    if (Pos_ < Text_.size() && Text_[Pos_] == ']') {
      ++Pos_;
      return Result;
    }
    while (true) {
      SkipWhitespace();
      Result.Push(ParseValue(Depth + 1));
      SkipWhitespace();
      if (Pos_ >= Text_.size()) {
        Fail("Expecting ',' delimiter");
      }
      if (Text_[Pos_] == ',') {
        ++Pos_;
        continue;
      }
      if (Text_[Pos_] == ']') {
        ++Pos_;
        return Result;
      }
      Fail("Expecting ',' delimiter");
    }
  }

  JsonValue ParseObject(int Depth) {
    if (Depth >= kMaxJsonDepth) {
      Fail("nesting too deep (more than " + std::to_string(kMaxJsonDepth) + " levels)");
    }
    ++Pos_;
    JsonValue Result = JsonValue::Object();
    SkipWhitespace();
    if (Pos_ < Text_.size() && Text_[Pos_] == '}') {
      ++Pos_;
      return Result;
    }
    while (true) {
      SkipWhitespace();
      if (Pos_ >= Text_.size() || Text_[Pos_] != '"') {
        Fail("Expecting property name enclosed in double quotes");
      }
      std::string Key = ParseString();
      SkipWhitespace();
      if (Pos_ >= Text_.size() || Text_[Pos_] != ':') {
        Fail("Expecting ':' delimiter");
      }
      ++Pos_;
      SkipWhitespace();
      Result.Set(std::move(Key), ParseValue(Depth + 1));  // a duplicate key keeps its first position
      SkipWhitespace();
      if (Pos_ >= Text_.size()) {
        Fail("Expecting ',' delimiter");
      }
      if (Text_[Pos_] == ',') {
        ++Pos_;
        continue;
      }
      if (Text_[Pos_] == '}') {
        ++Pos_;
        return Result;
      }
      Fail("Expecting ',' delimiter");
    }
  }

  std::string_view Text_;
  JsonParseOptions Options_;
  size_t Pos_ = 0;
};

// ---------------------------------------------------------------------------------------------
// Writer

void Write(const JsonValue& Value, std::string& Out, const JsonWriteOptions& Options, int Indent) {
  const auto NewLine = [&](int Level) {
    if (Options.Pretty) {
      Out += '\n';
      Out.append(static_cast<size_t>(Level) * 2u, ' ');
    }
  };
  switch (Value.GetKind()) {
    case JsonValue::Kind::Null:
      Out += "null";
      break;
    case JsonValue::Kind::Bool:
      Out += Value.AsBool() ? "true" : "false";
      break;
    case JsonValue::Kind::Number:
      Out += Value.NumberText();
      break;
    case JsonValue::Kind::String:
      Out += JsonQuote(Value.AsString());
      break;
    case JsonValue::Kind::Array: {
      const auto& Items = Value.Items();
      Out += '[';
      for (size_t Index = 0; Index < Items.size(); ++Index) {
        if (Index > 0) {
          Out += ',';
        }
        NewLine(Indent + 1);
        Write(Items[Index], Out, Options, Indent + 1);
      }
      if (!Items.empty()) {
        NewLine(Indent);
      }
      Out += ']';
      break;
    }
    case JsonValue::Kind::Object: {
      const auto& Members = Value.Members();
      Out += '{';
      for (size_t Index = 0; Index < Members.size(); ++Index) {
        if (Index > 0) {
          Out += ',';
        }
        NewLine(Indent + 1);
        Out += JsonQuote(Members[Index].first);
        Out += Options.Pretty ? ": " : ":";
        Write(Members[Index].second, Out, Options, Indent + 1);
      }
      if (!Members.empty()) {
        NewLine(Indent);
      }
      Out += '}';
      break;
    }
  }
}

}

JsonValue JsonParse(std::string_view Text, const JsonParseOptions& Options) {
  return Parser(Text, Options).ParseDocument();
}

std::string JsonWrite(const JsonValue& Value, const JsonWriteOptions& Options) {
  std::string Out;
  Write(Value, Out, Options, 0);
  return Out;
}

std::string JsonQuote(std::string_view Utf8) {
  std::string Out;
  Out.reserve(Utf8.size() + 2);
  Out += '"';
  for (const char Raw : Utf8) {
    const unsigned char Ch = static_cast<unsigned char>(Raw);
    switch (Ch) {
      case '"':
        Out += "\\\"";
        break;
      case '\\':
        Out += "\\\\";
        break;
      case '\n':
        Out += "\\n";
        break;
      case '\r':
        Out += "\\r";
        break;
      case '\t':
        Out += "\\t";
        break;
      case '\b':
        Out += "\\b";
        break;
      case '\f':
        Out += "\\f";
        break;
      default:
        if (Ch < 0x20) {
          char Buffer[8];
          std::snprintf(Buffer, sizeof(Buffer), "\\u%04x", static_cast<unsigned>(Ch));
          Out += Buffer;
        } else {
          Out += static_cast<char>(Ch);
        }
        break;
    }
  }
  Out += '"';
  return Out;
}

}
