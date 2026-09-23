// L0 STUB of lane L2 (Python value semantics). L2 replaces this file (spec: 03a §6.4, §7.1;
// 03b §4.1-§4.2; 08 §9.3).

#include "dsigmatcher/diff/PyValue.h"

#include "dsigmatcher/diff/Errors.h"

namespace DSig::Diff {

bool PyEquals(const PyValue&, const PyValue&) { throw StageNotImplemented("PyEquals (L2)"); }

size_t PyHash(const PyValue&) { throw StageNotImplemented("PyHash (L2)"); }

PyValue PyJsonLoads(std::string_view) { throw StageNotImplemented("PyJsonLoads (L2)"); }

std::vector<PyValue> PyJsonLoadsList(std::string_view) { throw StageNotImplemented("PyJsonLoadsList (L2)"); }

bool PySet::Insert(const PyValue&) { throw StageNotImplemented("PySet::Insert (L2)"); }

bool PySet::Contains(const PyValue&) const { throw StageNotImplemented("PySet::Contains (L2)"); }

PySet PySetFromList(const std::vector<PyValue>&) { throw StageNotImplemented("PySetFromList (L2)"); }

std::vector<PyValue> PySetIntersection(const PySet&, const PySet&) {
  throw StageNotImplemented("PySetIntersection (L2)");
}

size_t PySetIntersectionSize(const PySet&, const PySet&) { throw StageNotImplemented("PySetIntersectionSize (L2)"); }

std::string PyStr(const PyValue&) { throw StageNotImplemented("PyStr (L2)"); }

std::optional<double> PyFloat(std::string_view) { throw StageNotImplemented("PyFloat (L2)"); }

std::string PyReprFloat(double) { throw StageNotImplemented("PyReprFloat (L2)"); }

}
