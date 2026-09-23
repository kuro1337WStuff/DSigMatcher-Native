#pragma once

// UTF-8 file access for the parity engine (lane R0, orchestrator decision (f)).
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
// new content (the oracle's WriteJsonAtomic). Falls back to removing the target first, then to a
// plain rewrite, when the platform refuses to rename over an open file. Throws IoFailure.
void ReplaceFileBytes(const std::string& Utf8Path, std::string_view Bytes);

// True when Utf8Path names an existing regular file or directory (never throws).
bool PathExists(const std::string& Utf8Path);

}
