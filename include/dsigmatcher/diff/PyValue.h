#pragma once

// Python value semantics the diff depends on (L2; 03a §6.4, §7.1; 03b §4.1-§4.2):
//   * json.loads of `constants` / `names` columns, with exact big integers, NaN/Infinity literals and
//     strict control characters;
//   * set(...) membership and intersection with Python equality (1 == 1.0 == True, int/float compare
//     by exact value, str by code points after unescaping, a nested list/dict is unhashable);
//   * str(x) for binding constants as text (D:3390), float(text) for md_index (D:2498 -> D:1672),
//     repr(float) for log lines.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace DSig::Diff {

struct PyValue {
  enum class Kind : uint8_t { None, Bool, Int, Float, Str, List, Dict };

  Kind Type = Kind::None;
  bool BoolValue = false;         // Kind::Bool
  std::string IntDigits;          // Kind::Int: canonical decimal ("-" sign, no leading zeros)
  double FloatValue = 0.0;        // Kind::Float
  std::string StrValue;           // Kind::Str: UTF-8 (a lone surrogate keeps its 3-byte form)
  std::vector<PyValue> Items;     // Kind::List elements, or Kind::Dict keys in insertion order
  std::vector<PyValue> DictValues;// Kind::Dict values, parallel to Items

  bool Hashable() const { return Type != Kind::List && Type != Kind::Dict; }
};

// Python == as seen by set membership. A JSON NaN is one shared float object in the json module, so
// NaN from json.loads equals NaN here (03a §7.1).
bool PyEquals(const PyValue& A, const PyValue& B);
// A hash consistent with PyEquals (equal values hash equal, including 1, 1.0 and True).
size_t PyHash(const PyValue& Value);

// json.loads(Text). Throws DiaphoraWouldRaise("json.loads", ...) where Python raises (invalid JSON,
// control characters, NULL input is the caller's check).
PyValue PyJsonLoads(std::string_view Text);
// The elements set(json.loads(Text)) iterates: list elements, dict keys or the characters of a str.
// Throws DiaphoraWouldRaise where Python raises (invalid JSON, a non-iterable such as a number).
std::vector<PyValue> PyJsonLoadsList(std::string_view Text);

// A Python set of hashable values that also remembers first-insertion order.
class PySet {
public:
  // set.add(value); throws DiaphoraWouldRaise("set", "unhashable type") for a list/dict element.
  bool Insert(const PyValue& Value);
  bool Contains(const PyValue& Value) const;
  size_t Size() const { return Items_.size(); }
  const std::vector<PyValue>& Ordered() const { return Items_; }

private:
  std::vector<PyValue> Items_;
  std::unordered_multimap<size_t, uint32_t> Index_;
};

PySet PySetFromList(const std::vector<PyValue>& Items);  // set(list)
// Main ∩ Diff in first-appearance order of Main. CPython iterates the smaller set in hash order; the
// native order is a documented deviation (plan §5 R3).
std::vector<PyValue> PySetIntersection(const PySet& Main, const PySet& Diff);
size_t PySetIntersectionSize(const PySet& A, const PySet& B);

std::string PyStr(const PyValue& Value);                // str(x)
std::optional<double> PyFloat(std::string_view Text);   // float(str); nullopt where Python raises ValueError
std::string PyReprFloat(double Value);                  // repr(float): "0.5", "1e+16", "nan", "inf"

}
