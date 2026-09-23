// UTF-8 file access (lane R0, orchestrator decision (f)); see FileIo.h.

#include "FileIo.h"

#include <cstring>
#include <fstream>
#include <sstream>
#include <system_error>

#include "dsigmatcher/diff/Errors.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace DSig::Diff::Detail {

namespace fs = std::filesystem;

fs::path PathFromUtf8(std::string_view Utf8) {
  // Copy into char8_t storage (no aliasing through a reinterpret_cast): a std::u8string source is
  // UTF-8 by definition on every standard library, and is converted to UTF-16 on Windows.
  std::u8string Text(Utf8.size(), u8'\0');
  if (!Utf8.empty()) {
    std::memcpy(Text.data(), Utf8.data(), Utf8.size());
  }
  try {
    return fs::path(Text);
  } catch (const std::exception& Error) {
    throw IoFailure("path is not valid UTF-8: '" + std::string(Utf8) + "' (" + Error.what() + ")");
  }
}

std::string PathToUtf8(const fs::path& Path) {
  std::u8string Text;
  try {
    Text = Path.u8string();
  } catch (const std::exception& Error) {
    throw IoFailure(std::string("path cannot be represented as UTF-8 (") + Error.what() + ")");
  }
  std::string Out(Text.size(), '\0');
  if (!Text.empty()) {
    std::memcpy(Out.data(), Text.data(), Text.size());
  }
  return Out;
}

std::string ReadFileBytes(const std::string& Utf8Path) {
  const fs::path Path = PathFromUtf8(Utf8Path);
#ifdef _WIN32
  const HANDLE Handle =
      CreateFileW(Path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
  if (Handle == INVALID_HANDLE_VALUE) {
    throw IoFailure("cannot read '" + Utf8Path + "': " + std::system_category().message(static_cast<int>(GetLastError())));
  }
  std::string Out;
  LARGE_INTEGER Size{};
  if (GetFileSizeEx(Handle, &Size) && Size.QuadPart > 0) {
    Out.reserve(static_cast<size_t>(Size.QuadPart));
  }
  char Buffer[1 << 16];
  while (true) {
    DWORD Got = 0;
    if (!ReadFile(Handle, Buffer, static_cast<DWORD>(sizeof(Buffer)), &Got, nullptr)) {
      const DWORD Code = GetLastError();
      CloseHandle(Handle);
      throw IoFailure("cannot read '" + Utf8Path + "': " + std::system_category().message(static_cast<int>(Code)));
    }
    if (Got == 0) {
      break;
    }
    Out.append(Buffer, Got);
  }
  CloseHandle(Handle);
  return Out;
#else
  std::ifstream In(Path, std::ios::binary);
  if (!In) {
    throw IoFailure("cannot read '" + Utf8Path + "'");
  }
  std::ostringstream Buffer;
  Buffer << In.rdbuf();
  if (In.bad()) {
    throw IoFailure("cannot read '" + Utf8Path + "'");
  }
  return Buffer.str();
#endif
}

void WriteFileBytes(const std::string& Utf8Path, std::string_view Bytes) {
  std::ofstream Out(PathFromUtf8(Utf8Path), std::ios::binary | std::ios::trunc);
  if (!Out) {
    throw IoFailure("cannot write '" + Utf8Path + "'");
  }
  Out.write(Bytes.data(), static_cast<std::streamsize>(Bytes.size()));
  Out.flush();
  if (!Out) {
    throw IoFailure("cannot write '" + Utf8Path + "'");
  }
}

void ReplaceFileBytes(const std::string& Utf8Path, std::string_view Bytes) {
  const std::string Temporary = Utf8Path + ".tmp";
  WriteFileBytes(Temporary, Bytes);
  const fs::path From = PathFromUtf8(Temporary);
  const fs::path To = PathFromUtf8(Utf8Path);
  std::error_code Error;
  fs::rename(From, To, Error);  // MoveFileExW(MOVEFILE_REPLACE_EXISTING) on Windows, rename(2) on POSIX
  if (!Error) {
    return;
  }
  // Some runtimes refuse to rename over an existing file: remove it first.
  std::error_code Ignored;
  fs::remove(To, Ignored);
  fs::rename(From, To, Error);
  if (!Error) {
    return;
  }
  // A reader holds the target open without delete sharing: rewrite it in place.
  fs::remove(From, Ignored);
  WriteFileBytes(Utf8Path, Bytes);
}

bool PathExists(const std::string& Utf8Path) {
  try {
    std::error_code Error;
    return fs::exists(PathFromUtf8(Utf8Path), Error);
  } catch (const std::exception&) {
    return false;
  }
}

}
