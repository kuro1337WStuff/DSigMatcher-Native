#pragma once

#include <string_view>

namespace DSig {

inline bool StartsWith(std::string_view Text, std::string_view Prefix) {
  return Text.size() >= Prefix.size() && Text.compare(0, Prefix.size(), Prefix) == 0;
}

inline bool IsAutoNamed(std::string_view Name) {
  return StartsWith(Name, "sub_");
}

inline bool IsNullSub(std::string_view Name) {
  return StartsWith(Name, "nullsub");
}

inline bool IsPortableSymbol(std::string_view Name) {
  if (Name.empty()) {
    return false;
  }
  return !IsAutoNamed(Name) && !IsNullSub(Name) && Name != "...";
}

inline bool NameCompatible(std::string_view Left, std::string_view Right) {
  const bool LeftAuto = IsAutoNamed(Left);
  const bool RightAuto = IsAutoNamed(Right);
  return (Left == Right && !LeftAuto) || LeftAuto || RightAuto;
}

}
