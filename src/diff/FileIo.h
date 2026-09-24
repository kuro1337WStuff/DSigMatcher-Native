#pragma once

// UTF-8 file access for the parity engine (lane R0, design decision (f)).
//
// Every path string in DSig::Diff and in the CLI is UTF-8: main() converts the Windows wide command
// line, and SQLite takes UTF-8 file names on every platform. On Windows, std::filesystem::path built
// from a std::string, std::fstream(const char*) and fopen() interpret narrow text in the ANSI code
// page instead, which corrupts any character outside it. Code in src/diff therefore never builds a
// path from a narrow string directly: it goes through PathFromUtf8 / PathToUtf8, and reads and
// writes whole files with the helpers below. UNC paths (\\server\share\...) and drive paths need no
// special handling here; they are ordinary wide paths once converted.
//
// Internal header (src/diff is a private include directory of dsigmatcher_diff). Other lanes may use
// it from their .cpp files.

#include <filesystem>
#include <string>
#include <string_view>

namespace DSig::Diff::Detail {

// The UTF-8 bytes as a filesystem path (wide on Windows). Throws IoFailure for text that is not
// valid UTF-8 on a platform whose native paths are wide.
std::filesystem::path PathFromUtf8(std::string_view Utf8);

// The path as UTF-8 bytes. Throws IoFailure when the native path cannot be represented.
std::string PathToUtf8(const std::filesystem::path& Path);

// The whole file. On Windows the file is opened with FILE_SHARE_READ | FILE_SHARE_WRITE |
// FILE_SHARE_DELETE, so a concurrent writer that replaces the file (Python os.replace, as
// tools/parity/oracle_trace.py does for index.json and run.json) is never blocked by this reader.
// Throws IoFailure.
std::string ReadFileBytes(const std::string& Utf8Path);

// Creates or truncates the file and writes Bytes. Throws IoFailure.
void WriteFileBytes(const std::string& Utf8Path, std::string_view Bytes);

// Writes Bytes to "<path>.tmp" and renames it over the path, so a reader sees either the old or the
// new content (the oracle's WriteJsonAtomic). Never rewrites the target in place: when the rename keeps
// failing (the target is held open without delete sharing), the temporary file is removed and IoFailure
// is thrown, and the target keeps its old content (audit F01: an in-place rewrite truncated an input
// another handle held).
void ReplaceFileBytes(const std::string& Utf8Path, std::string_view Bytes);

// ReplaceFileBytes for a file that must survive a crash or a power loss (the checkpoint files): the
// temporary file's bytes are flushed to the disk (FlushFileBuffers / fsync) before the rename, and on
// POSIX the directory is synced after it. `Fault`, when not null, is called with "<Label>:write" before
// the temporary file is written and "<Label>:rename" before the rename (a test hook: a throwing hook
// simulates a failure at that step). Throws IoFailure; the target keeps its old content on failure and
// the temporary file is removed.
void ReplaceFileBytesDurable(const std::string& Utf8Path, std::string_view Bytes,
                             void (*Fault)(std::string_view Step) = nullptr, std::string_view Label = {});

// Renames `From` over `To` (MoveFileExW(MOVEFILE_REPLACE_EXISTING) on Windows, rename(2) elsewhere).
// A transient sharing violation (an indexer or a virus scanner holding the target for a moment) is
// retried for about a second. Throws IoFailure; `From` is left in place on failure.
void RenameReplacing(const std::string& FromUtf8, const std::string& ToUtf8);

// True when Utf8Path names an existing regular file or directory (never throws).
bool PathExists(const std::string& Utf8Path);

// True when the two UTF-8 paths name the same file: for two existing files through the file system's
// own identity (hard links, 8.3 short names, a UNC share of a local drive, another case), otherwise by
// comparing the weakly canonical paths the way the platform's default file system compares names
// (case-insensitively on Windows and macOS). Never throws. The same rule as Provenance.cpp
// SameFilePath, which the CLI's port command uses.
bool SameFilePath(const std::string& A, const std::string& B);

// True when `Path` lies inside the directory `Dir` (at any depth), compared like SameFilePath on the
// canonical spellings. `Path == Dir` is not inside. Never throws.
bool PathIsInside(const std::string& Path, const std::string& Dir);

}
