// UTF-8 file access (lane R0, design decision (f)); see FileIo.h.

#include "FileIo.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <climits>
#include <cstdint>
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
#else
#include <fcntl.h>
#include <unistd.h>
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

void RenameReplacing(const std::string& FromUtf8, const std::string& ToUtf8) {
  const fs::path From = PathFromUtf8(FromUtf8);
  const fs::path To = PathFromUtf8(ToUtf8);
  std::error_code Error;
  for (int Attempt = 0; Attempt < 20; ++Attempt) {
    Error.clear();
    fs::rename(From, To, Error);  // MoveFileExW(MOVEFILE_REPLACE_EXISTING) on Windows, rename(2) on POSIX
    if (!Error) {
      return;
    }
#ifdef _WIN32
    // ERROR_ACCESS_DENIED / ERROR_SHARING_VIOLATION while another process holds the target briefly.
    if (Error.value() != ERROR_ACCESS_DENIED && Error.value() != ERROR_SHARING_VIOLATION &&
        Error.value() != ERROR_LOCK_VIOLATION) {
      break;
    }
    Sleep(50);
#else
    break;
#endif
  }
  throw IoFailure("cannot replace '" + ToUtf8 + "' with '" + FromUtf8 + "': " + Error.message());
}

void ReplaceFileBytes(const std::string& Utf8Path, std::string_view Bytes) {
  const std::string Temporary = Utf8Path + ".tmp";
  WriteFileBytes(Temporary, Bytes);
  try {
    RenameReplacing(Temporary, Utf8Path);
  } catch (const IoFailure&) {
    std::error_code Ignored;
    fs::remove(PathFromUtf8(Temporary), Ignored);
    throw;
  }
}

namespace {

// Writes Bytes to a new file and flushes it to the disk. Throws IoFailure.
void WriteFileBytesSynced(const std::string& Utf8Path, std::string_view Bytes) {
  const fs::path Path = PathFromUtf8(Utf8Path);
#ifdef _WIN32
  const HANDLE Handle = CreateFileW(Path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                                    nullptr);
  if (Handle == INVALID_HANDLE_VALUE) {
    throw IoFailure("cannot write '" + Utf8Path + "': " +
                    std::system_category().message(static_cast<int>(GetLastError())));
  }
  size_t Done = 0;
  while (Done < Bytes.size()) {
    const size_t Chunk = std::min<size_t>(Bytes.size() - Done, size_t{1} << 24);
    DWORD Wrote = 0;
    if (!WriteFile(Handle, Bytes.data() + Done, static_cast<DWORD>(Chunk), &Wrote, nullptr) || Wrote == 0) {
      const DWORD Code = GetLastError();
      CloseHandle(Handle);
      throw IoFailure("cannot write '" + Utf8Path + "': " + std::system_category().message(static_cast<int>(Code)));
    }
    Done += Wrote;
  }
  if (!FlushFileBuffers(Handle)) {
    const DWORD Code = GetLastError();
    CloseHandle(Handle);
    throw IoFailure("cannot flush '" + Utf8Path + "': " + std::system_category().message(static_cast<int>(Code)));
  }
  if (!CloseHandle(Handle)) {
    throw IoFailure("cannot close '" + Utf8Path + "': " +
                    std::system_category().message(static_cast<int>(GetLastError())));
  }
#else
  const int Fd = ::open(Path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
  if (Fd < 0) {
    throw IoFailure("cannot write '" + Utf8Path + "': " + std::generic_category().message(errno));
  }
  size_t Done = 0;
  while (Done < Bytes.size()) {
    const ssize_t Wrote = ::write(Fd, Bytes.data() + Done, Bytes.size() - Done);
    if (Wrote < 0 && errno == EINTR) {
      continue;
    }
    if (Wrote <= 0) {
      const int Code = Wrote < 0 ? errno : ENOSPC;
      ::close(Fd);
      throw IoFailure("cannot write '" + Utf8Path + "': " + std::generic_category().message(Code));
    }
    Done += static_cast<size_t>(Wrote);
  }
  if (::fsync(Fd) != 0) {
    const int Code = errno;
    ::close(Fd);
    throw IoFailure("cannot flush '" + Utf8Path + "': " + std::generic_category().message(Code));
  }
  if (::close(Fd) != 0) {
    throw IoFailure("cannot close '" + Utf8Path + "': " + std::generic_category().message(errno));
  }
#endif
}

// POSIX: a rename is durable only once its directory is synced. Best effort (some file systems refuse
// to open or sync a directory); Windows has no equivalent and needs none for MoveFileExW.
void SyncDirectoryOf(const std::string& Utf8Path) {
#ifndef _WIN32
  fs::path Parent = PathFromUtf8(Utf8Path).parent_path();
  if (Parent.empty()) {
    Parent = ".";
  }
  const int Fd = ::open(Parent.c_str(), O_RDONLY | O_CLOEXEC);
  if (Fd >= 0) {
    (void)::fsync(Fd);
    ::close(Fd);
  }
#else
  (void)Utf8Path;
#endif
}

}  // namespace

void ReplaceFileBytesDurable(const std::string& Utf8Path, std::string_view Bytes, void (*Fault)(std::string_view),
                             std::string_view Label) {
  const std::string Temporary = Utf8Path + ".tmp";
  const auto Remove = [&] {
    std::error_code Ignored;
    fs::remove(PathFromUtf8(Temporary), Ignored);
  };
  try {
    if (Fault != nullptr) {
      Fault(std::string(Label) + ":write");
    }
    WriteFileBytesSynced(Temporary, Bytes);
    if (Fault != nullptr) {
      Fault(std::string(Label) + ":rename");
    }
    RenameReplacing(Temporary, Utf8Path);
  } catch (...) {
    Remove();
    throw;
  }
  SyncDirectoryOf(Utf8Path);
}

bool PathExists(const std::string& Utf8Path) {
  try {
    std::error_code Error;
    return fs::exists(PathFromUtf8(Utf8Path), Error);
  } catch (const std::exception&) {
    return false;
  }
}

namespace {

fs::path CanonicalOrAbsolute(const fs::path& Path) {
  std::error_code Error;
  fs::path Canonical = fs::weakly_canonical(Path, Error);
  if (!Error && !Canonical.empty()) {
    return Canonical;
  }
  Error.clear();
  const fs::path Absolute = fs::absolute(Path, Error);
  return (Error ? Path : Absolute).lexically_normal();
}

bool SameSpelling(const fs::path& A, const fs::path& B) {
#if defined(_WIN32)
  const std::wstring& X = A.native();
  const std::wstring& Y = B.native();
  if (X.size() > static_cast<size_t>(INT32_MAX) || Y.size() > static_cast<size_t>(INT32_MAX)) {
    return X == Y;
  }
  return CompareStringOrdinal(X.data(), static_cast<int>(X.size()), Y.data(), static_cast<int>(Y.size()), TRUE) ==
         CSTR_EQUAL;
#elif defined(__APPLE__)
  const std::string& X = A.native();
  const std::string& Y = B.native();
  if (X.size() != Y.size()) {
    return false;
  }
  for (size_t Index = 0; Index < X.size(); ++Index) {
    if (std::tolower(static_cast<unsigned char>(X[Index])) != std::tolower(static_cast<unsigned char>(Y[Index]))) {
      return false;
    }
  }
  return true;
#else
  return A.native() == B.native();
#endif
}

}  // namespace

bool SameFilePath(const std::string& A, const std::string& B) {
  if (A.empty() || B.empty()) {
    return false;
  }
  try {
    const fs::path PathA = PathFromUtf8(A);
    const fs::path PathB = PathFromUtf8(B);
    std::error_code Error;
    const bool ExistsA = fs::exists(PathA, Error);
    Error.clear();
    const bool ExistsB = fs::exists(PathB, Error);
    if (ExistsA && ExistsB) {
      Error.clear();
      if (fs::equivalent(PathA, PathB, Error) && !Error) {
        return true;
      }
    }
    return SameSpelling(CanonicalOrAbsolute(PathA), CanonicalOrAbsolute(PathB));
  } catch (const std::exception&) {
    return A == B;
  }
}

bool PathIsInside(const std::string& Path, const std::string& Dir) {
  if (Path.empty() || Dir.empty()) {
    return false;
  }
  try {
    const fs::path Root = CanonicalOrAbsolute(PathFromUtf8(Dir));
    fs::path Current = CanonicalOrAbsolute(PathFromUtf8(Path));
    while (true) {
      fs::path Parent = Current.parent_path();
      if (Parent.empty() || Parent == Current) {
        return false;
      }
      if (SameSpelling(Parent, Root)) {
        return true;
      }
      Current = std::move(Parent);
    }
  } catch (const std::exception&) {
    return false;
  }
}

}
