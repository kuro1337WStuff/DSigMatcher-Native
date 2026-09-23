#pragma once

// String interning for the parity engine. Diaphora keys its match state by *name strings*
// (matched_primary / matched_secondary, D:1340-1402) and its final pass by *address text*
// (D:2839-2885), so every such string is interned once and compared by id. Ids are only equal when
// the byte strings are equal, which for valid UTF-8 is exactly Python str equality.
//
// Python None is a distinct key from the text "None" (dict keys), but renders as "None" inside
// f-string keys such as f"{name1}-{name2}" (D:1575). NameId{0} / AddrId{0} are reserved for None.

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>

namespace DSig::Diff {

enum class NameId : uint32_t {};  // functions.name, mangled_function, callee-regex names
enum class DescId : uint32_t {};  // match descriptions ("Perfect match, same name", ...)
enum class AddrId : uint32_t {};  // exact functions.address TEXT ("4198400")

inline constexpr NameId kNoneName{0};  // Python None used as a name
inline constexpr AddrId kNoneAddr{0};  // Python None used as an address

// One append-only string table. Returned string_views stay valid for the interner's lifetime.
class Interner {
public:
  Interner();
  ~Interner();
  Interner(Interner&&) noexcept;
  Interner& operator=(Interner&&) noexcept;
  Interner(const Interner&) = delete;
  Interner& operator=(const Interner&) = delete;

  uint32_t Intern(std::string_view Text);
  std::optional<uint32_t> Find(std::string_view Text) const;
  std::string_view Text(uint32_t Id) const;
  size_t Size() const;

private:
  struct Impl;
  std::unique_ptr<Impl> Impl_;
};

// The three tables the engine uses. Name and address ids start at 1; 0 is Python None.
class Interners {
public:
  Interners();
  ~Interners();
  Interners(Interners&&) noexcept;
  Interners& operator=(Interners&&) noexcept;
  Interners(const Interners&) = delete;
  Interners& operator=(const Interners&) = delete;

  NameId Name(std::string_view Text);
  NameId NameOpt(std::optional<std::string_view> TextOrNone);  // nullopt -> kNoneName
  std::optional<NameId> FindName(std::string_view Text) const;
  bool IsNone(NameId Id) const { return Id == kNoneName; }
  std::optional<std::string_view> NameOrNone(NameId Id) const;  // nullopt for kNoneName
  std::string_view NameText(NameId Id) const;                    // "" for kNoneName
  std::string_view NameKeyText(NameId Id) const;                 // "None" for kNoneName (f-string rendering)
  size_t NameCount() const;                                      // interned names, None excluded

  DescId Desc(std::string_view Text);
  std::optional<DescId> FindDesc(std::string_view Text) const;
  std::string_view DescText(DescId Id) const;

  AddrId Addr(std::string_view Text);
  AddrId AddrOpt(std::optional<std::string_view> TextOrNone);    // nullopt -> kNoneAddr
  std::optional<AddrId> FindAddr(std::string_view Text) const;
  std::string_view AddrText(AddrId Id) const;                    // "" for kNoneAddr
  std::string_view AddrKeyText(AddrId Id) const;                 // "None" for kNoneAddr

private:
  Interner Names_;
  Interner Descs_;
  Interner Addrs_;
};

}
