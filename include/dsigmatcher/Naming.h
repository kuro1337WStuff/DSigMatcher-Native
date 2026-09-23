#pragma once

// Which function names are labels worth porting, and which are placeholders IDA made up.
//
// A placeholder never travels to the target (the reference proposal is "skipped_not_portable") and
// never protects a target function from being labelled (a target placeholder is replaced even without
// --overwrite-existing). IDA's auto-generated names:
//   sub_<ea>              an unnamed function
//   nullsub_<n>           an empty function (any "nullsub" prefix, as before 1.0.0)
//   j_<name>              a thunk that jumps to <name>
//   unknown_libname_<n>   a FLIRT library function IDA could not name
//   DllEntryPoint, start  the entry point of a DLL / an executable without symbols
// plus the empty name and "...", which Diaphora writes for a missing name.

#include <string_view>

namespace DSig {

inline bool StartsWith(std::string_view Text, std::string_view Prefix) {
  return Text.size() >= Prefix.size() && Text.compare(0, Prefix.size(), Prefix) == 0;
}

// sub_<ea>: IDA's name for a function without one.
inline bool IsAutoNamed(std::string_view Name) {
  return StartsWith(Name, "sub_");
}

inline bool IsNullSub(std::string_view Name) {
  return StartsWith(Name, "nullsub");
}

// Every name IDA generates on its own (see the list above), and the empty / "..." name.
inline bool IsPlaceholderName(std::string_view Name) {
  return Name.empty() || Name == "..." || IsAutoNamed(Name) || IsNullSub(Name) || StartsWith(Name, "j_") ||
         StartsWith(Name, "unknown_libname_") || Name == "DllEntryPoint" || Name == "start";
}

// A real name: a label a user or a PDB gave the function.
inline bool IsPortableSymbol(std::string_view Name) {
  return !IsPlaceholderName(Name);
}

// The results-row description of Diaphora's "stripped binary" shortcut (find_equal_matches on two
// builds whose symbols were stripped pairs functions by address). Those rows never overwrite a real
// target name unless the port is given --overwrite-stripped.
inline constexpr std::string_view kStrippedDescription = "Same binary with symbols stripped";

}
