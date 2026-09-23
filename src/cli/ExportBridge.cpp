// Export bridge: `dsigmatcher extract` and `dsigmatcher ingest` (docs/parity/00-plan.md §7.1 D7, §7.2 L10).
//
// Both commands launch tools/export/dsig_export.py, which runs IDA idalib and the UNMODIFIED Diaphora
// exporter (diaphora_ida._diff_or_export(use_ui=False, file_out=...)). The exporter's feature
// definitions are the parity contract, so nothing here re-implements them. This file only:
//   * validates the arguments and finds the tools (flags, else DSIG_PYTHON / DSIG_IDADIR /
//     DSIG_DIAPHORA_DIR / DSIG_EXPORT_SCRIPT, else PATH and the executable's location), refusing an
//     interpreter that is a batch file and any output whose files would alias the input or the PDB;
//   * starts the script with UTF-8-safe arguments (CreateProcessW with MSVC-CRT quoting; posix_spawn
//     into its own process group) as `python -E`, in the script's directory, with no program lookup in
//     the current directory, streams its output to stderr, and enforces a backstop timeout on the whole
//     process tree;
//   * checks, independently of the script, that the input's sha256 did not change;
//   * maps the script's exit codes to the CLI's (Commands.h, plan §2.1) with a clear message, and
//     reads the <output stem>.export.json sidecar for the summary.
// Every behavioural decision of the export itself lives in dsig_export.py, which cites the Diaphora
// lines it relies on.

#include "dsigmatcher/cli/Commands.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <exception>
#include <fstream>
#include <iterator>
#include <sstream>
#include <system_error>
#include <thread>

#include "ExportBridgeDetail.h"
#include "dsigmatcher/Sha256.h"
#include "dsigmatcher/diff/Json.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <mach-o/dyld.h>
#endif
extern char** environ;
#endif

namespace DSig::Cli::ExportBridge {

namespace {

constexpr size_t kTailBytes = 64 * 1024;

std::string ToLowerAscii(std::string Text) {
  for (char& Ch : Text) {
    Ch = static_cast<char>(std::tolower(static_cast<unsigned char>(Ch)));
  }
  return Text;
}

void AppendTail(std::string& Tail, const char* Data, size_t Size) {
  Tail.append(Data, Size);
  if (Tail.size() > 2 * kTailBytes) {
    Tail.erase(0, Tail.size() - kTailBytes);
  }
}

// A timeout in seconds that steady_clock arithmetic can hold (its nanosecond count ends near 292 years):
// negative becomes 0, anything above about 31 years is capped there, which is forever for a process.
int64_t ClampTimeout(int64_t Seconds) {
  constexpr int64_t kLongest = 1000000000;
  return Seconds <= 0 ? 0 : std::min(Seconds, kLongest);
}

bool IsDirectory(const std::filesystem::path& Path) {
  std::error_code Error;
  return std::filesystem::is_directory(Path, Error);
}

// A file that exists and is not a directory. symlink_status as well, so a Windows app-execution alias
// (the WindowsApps python.exe reparse point, which status() may not resolve) still counts.
bool IsFile(const std::filesystem::path& Path) {
  std::error_code Error;
  const auto Status = std::filesystem::status(Path, Error);
  if (!Error && std::filesystem::exists(Status)) {
    return !std::filesystem::is_directory(Status);
  }
  const auto Link = std::filesystem::symlink_status(Path, Error);
  return !Error && std::filesystem::exists(Link) && !std::filesystem::is_directory(Link);
}

bool IsExecutableFile(const std::filesystem::path& Path) {
  if (!IsFile(Path)) {
    return false;
  }
#ifdef _WIN32
  return true;
#else
  return access(Path.c_str(), X_OK) == 0;
#endif
}

std::filesystem::path Absolute(const std::filesystem::path& Path) {
  std::error_code Error;
  const std::filesystem::path Result = std::filesystem::absolute(Path, Error);
  return (Error ? Path : Result).lexically_normal();
}

std::filesystem::path IdaLibraryName() {
#if defined(_WIN32)
  return "idalib.dll";
#elif defined(__APPLE__)
  return "libidalib.dylib";
#else
  return "libidalib.so";
#endif
}

// `Name` directly in `Directory` or at most MaxDepth levels below it (IDA on macOS keeps idalib in the
// app bundle; dsig_export.py FindIdaLibrary searches the same way).
bool HasFileWithin(const std::filesystem::path& Directory, const std::filesystem::path& Name, int MaxDepth) {
  if (IsFile(Directory / Name)) {
    return true;
  }
  std::error_code Error;
  std::filesystem::recursive_directory_iterator It(
      Directory, std::filesystem::directory_options::skip_permission_denied, Error);
  const std::filesystem::recursive_directory_iterator End;
  while (!Error && It != End) {
    if (It.depth() >= MaxDepth) {
      It.disable_recursion_pending();
    }
    if (It->path().filename() == Name && !It->is_directory(Error)) {
      return true;
    }
    It.increment(Error);
  }
  return false;
}

std::vector<std::filesystem::path> PathDirectories() {
  std::vector<std::filesystem::path> Result;
  const auto Value = GetEnvUtf8("PATH");
  if (!Value) {
    return Result;
  }
#ifdef _WIN32
  constexpr char Separator = ';';
#else
  constexpr char Separator = ':';
#endif
  size_t Start = 0;
  while (Start <= Value->size()) {
    size_t End = Value->find(Separator, Start);
    if (End == std::string::npos) {
      End = Value->size();
    }
    std::string Entry = Value->substr(Start, End - Start);
#ifdef _WIN32
    Entry.erase(std::remove(Entry.begin(), Entry.end(), '"'), Entry.end());
#endif
    if (!Entry.empty()) {
      Result.push_back(PathFromUtf8(Entry));
    }
    Start = End + 1;
  }
  return Result;
}

// The first match of each name in turn over the PATH directories (names outer: python3 anywhere on
// PATH wins over a plain python).
std::optional<std::filesystem::path> SearchPath(const std::vector<std::filesystem::path>& Names) {
  const std::vector<std::filesystem::path> Directories = PathDirectories();
  for (const std::filesystem::path& Name : Names) {
    for (const std::filesystem::path& Directory : Directories) {
      const std::filesystem::path Candidate = Directory / Name;
      if (IsExecutableFile(Candidate)) {
        return Absolute(Candidate);
      }
    }
  }
  return std::nullopt;
}

struct Setting {
  std::optional<std::string> Value;
  std::string Source;
};

Setting FlagOrEnv(const std::string& Flag, const char* FlagName, const char* EnvName) {
  if (!Flag.empty()) {
    return {Flag, FlagName};
  }
  if (auto Env = GetEnvUtf8(EnvName)) {
    return {Env, EnvName};
  }
  return {std::nullopt, std::string()};
}

// Weakly canonical (symbolic links, "." and "..", and the stored spelling of the part that exists), or
// the absolute, lexically normal path when that fails.
std::filesystem::path CanonicalOrAbsolute(const std::filesystem::path& Path) {
  std::error_code Error;
  const std::filesystem::path Canonical = std::filesystem::weakly_canonical(Path, Error);
  return (Error || Canonical.empty()) ? Absolute(Path) : Canonical;
}

// Two spellings compared the way the platform's default file system compares names: NTFS through its
// upper-case table (CompareStringOrdinal with bIgnoreCase), APFS/HFS+ ignoring ASCII case, others bytes.
bool SameSpelling(const std::filesystem::path& A, const std::filesystem::path& B) {
#if defined(_WIN32)
  const std::wstring& X = A.native();
  const std::wstring& Y = B.native();
  if (X.size() > 0x7FFFFFFFu || Y.size() > 0x7FFFFFFFu) {
    return X == Y;
  }
  return CompareStringOrdinal(X.data(), static_cast<int>(X.size()), Y.data(), static_cast<int>(Y.size()), TRUE) ==
         CSTR_EQUAL;
#elif defined(__APPLE__)
  return ToLowerAscii(A.native()) == ToLowerAscii(B.native());
#else
  return A.native() == B.native();
#endif
}

// Name starts with Prefix, compared as SameSpelling compares (file names only, no separators).
bool NameStartsWith(const std::string& Name, const std::string& Prefix) {
  if (Name.size() < Prefix.size()) {
    return false;
  }
#if defined(_WIN32) || defined(__APPLE__)
  return SameSpelling(PathFromUtf8(Name.substr(0, Prefix.size())), PathFromUtf8(Prefix));
#else
  return Name.compare(0, Prefix.size(), Prefix) == 0;
#endif
}

// SQLite's -wal, -shm and -journal files and Diaphora's -crash marker: dsig_export.py OUTPUT_SIDECARS,
// which PublishOutput renames aside and deletes when it replaces an output.
constexpr const char* kOutputSidecars[] = {"-wal", "-shm", "-journal", "-crash"};

std::optional<std::string> ReadTextFile(const std::filesystem::path& Path) {
  std::ifstream Stream(Path, std::ios::binary);
  if (!Stream) {
    return std::nullopt;
  }
  std::ostringstream Text;
  Text << Stream.rdbuf();
  if (Stream.bad()) {
    return std::nullopt;
  }
  return Text.str();
}

#ifdef _WIN32

std::wstring Widen(std::string_view Text) {
  if (Text.empty()) {
    return std::wstring();
  }
  const bool Utf8 = IsValidUtf8(Text);
  const UINT CodePage = Utf8 ? CP_UTF8 : CP_ACP;
  const DWORD Flags = Utf8 ? MB_ERR_INVALID_CHARS : 0;
  const int Length = static_cast<int>(Text.size());
  const int Count = MultiByteToWideChar(CodePage, Flags, Text.data(), Length, nullptr, 0);
  if (Count <= 0) {
    return std::wstring();
  }
  std::wstring Wide(static_cast<size_t>(Count), L'\0');
  MultiByteToWideChar(CodePage, Flags, Text.data(), Length, Wide.data(), Count);
  return Wide;
}

std::string Narrow(std::wstring_view Wide) {
  if (Wide.empty()) {
    return std::string();
  }
  const int Length = static_cast<int>(Wide.size());
  const int Count = WideCharToMultiByte(CP_UTF8, 0, Wide.data(), Length, nullptr, 0, nullptr, nullptr);
  if (Count <= 0) {
    return std::string();
  }
  std::string Text(static_cast<size_t>(Count), '\0');
  WideCharToMultiByte(CP_UTF8, 0, Wide.data(), Length, Text.data(), Count, nullptr, nullptr);
  return Text;
}

std::string SystemErrorText(DWORD Code) {
  wchar_t* Buffer = nullptr;
  const DWORD Length = FormatMessageW(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, Code, 0,
      reinterpret_cast<wchar_t*>(&Buffer), 0, nullptr);
  std::string Text = (Length != 0 && Buffer != nullptr) ? Narrow(std::wstring_view(Buffer, Length)) : std::string();
  if (Buffer != nullptr) {
    LocalFree(Buffer);
  }
  while (!Text.empty() && (Text.back() == '\n' || Text.back() == '\r' || Text.back() == ' ' || Text.back() == '.')) {
    Text.pop_back();
  }
  return (Text.empty() ? std::string("system error") : Text) + " (error " + std::to_string(Code) + ")";
}

// Console Ctrl+C goes to every process on the console. While the child runs we let it handle the
// interrupt (dsig_export.py cleans up and exits 130) instead of dying first and orphaning it.
BOOL WINAPI IgnoreConsoleInterrupt(DWORD Type) {
  return (Type == CTRL_C_EVENT || Type == CTRL_BREAK_EVENT) ? TRUE : FALSE;
}

std::wstring EnvironmentName(std::wstring_view Entry) {
  // "=C:=C:\dir" (a drive's current directory) keeps its leading '=' in the name.
  const size_t Equal = Entry.find(L'=', Entry.empty() ? 0 : 1);
  return std::wstring(Entry.substr(0, Equal));
}

int CompareNames(std::wstring_view A, std::wstring_view B) {
  return CompareStringOrdinal(A.data(), static_cast<int>(A.size()), B.data(), static_cast<int>(B.size()), TRUE);
}

// This process's environment plus the overrides, sorted by name case-insensitively as CreateProcess
// expects, in the double-NUL-terminated UTF-16 form of CREATE_UNICODE_ENVIRONMENT.
std::wstring BuildEnvironmentBlock(const std::vector<std::pair<std::string, std::string>>& Overrides) {
  std::vector<std::wstring> Entries;
  if (wchar_t* Block = GetEnvironmentStringsW()) {
    for (const wchar_t* Entry = Block; *Entry != L'\0'; Entry += std::wcslen(Entry) + 1) {
      Entries.emplace_back(Entry);
    }
    FreeEnvironmentStringsW(Block);
  }
  for (const auto& [Name, Value] : Overrides) {
    const std::wstring WideName = Widen(Name);
    Entries.erase(std::remove_if(Entries.begin(), Entries.end(),
                                 [&](const std::wstring& Entry) {
                                   return CompareNames(EnvironmentName(Entry), WideName) == CSTR_EQUAL;
                                 }),
                  Entries.end());
    Entries.push_back(WideName + L"=" + Widen(Value));
  }
  std::stable_sort(Entries.begin(), Entries.end(), [](const std::wstring& A, const std::wstring& B) {
    return CompareNames(EnvironmentName(A), EnvironmentName(B)) == CSTR_LESS_THAN;
  });
  std::wstring Result;
  for (const std::wstring& Entry : Entries) {
    Result += Entry;
    Result.push_back(L'\0');
  }
  if (Entries.empty()) {
    Result.push_back(L'\0');
  }
  Result.push_back(L'\0');
  return Result;
}

#endif

}  // namespace

ToolExit MapToolExit(int ToolExitCode) {
  switch (ToolExitCode) {
    case kToolOk:
      return {kExitOk, "ok"};
    case kToolUsage:
      return {kExitUsage, "invalid arguments"};
    case kToolInput:
      return {kExitIo, "input missing or unreadable"};
    case kToolIda:
      return {kExitUnsupported, "IDA not found or not usable"};
    case kToolDiaphora:
      return {kExitUnsupported, "Diaphora not found or not importable"};
    case kToolHexRays:
      return {kExitUnsupported, "the Hex-Rays decompiler is not available"};
    case kToolPdb:
      return {kExitUsage, "the PDB cannot be applied to this binary"};
    case kToolOpen:
      return {kExitUnsupported, "IDA cannot open the input"};
    case kToolExport:
      return {kExitIo, "the export failed"};
    case kToolInputChanged:
      return {kExitIo, "THE INPUT CHANGED during the export"};
    case kToolTimeout:
      return {kExitIo, "timeout"};
    case kToolOutput:
      return {kExitIo, "the output cannot be written"};
    case kToolInternal:
      return {kExitIo, "internal error in the export tool"};
    case kToolInterrupted:
      return {kExitIo, "interrupted"};
    default:
      return {kExitIo, "the export tool failed"};
  }
}

bool IsValidUtf8(std::string_view Text) {
  size_t Index = 0;
  const size_t Size = Text.size();
  while (Index < Size) {
    const unsigned char Lead = static_cast<unsigned char>(Text[Index]);
    if (Lead < 0x80) {
      ++Index;
      continue;
    }
    size_t Extra = 0;
    uint32_t CodePoint = 0;
    if (Lead >= 0xC2 && Lead <= 0xDF) {
      Extra = 1;
      CodePoint = Lead & 0x1Fu;
    } else if (Lead >= 0xE0 && Lead <= 0xEF) {
      Extra = 2;
      CodePoint = Lead & 0x0Fu;
    } else if (Lead >= 0xF0 && Lead <= 0xF4) {
      Extra = 3;
      CodePoint = Lead & 0x07u;
    } else {
      return false;
    }
    if (Size - Index <= Extra) {
      return false;
    }
    for (size_t Offset = 1; Offset <= Extra; ++Offset) {
      const unsigned char Next = static_cast<unsigned char>(Text[Index + Offset]);
      if ((Next & 0xC0u) != 0x80u) {
        return false;
      }
      CodePoint = (CodePoint << 6) | (Next & 0x3Fu);
    }
    if (Extra == 2 && (CodePoint < 0x800 || (CodePoint >= 0xD800 && CodePoint <= 0xDFFF))) {
      return false;
    }
    if (Extra == 3 && (CodePoint < 0x10000 || CodePoint > 0x10FFFF)) {
      return false;
    }
    Index += Extra + 1;
  }
  return true;
}

std::filesystem::path PathFromUtf8(std::string_view Text) {
#ifdef _WIN32
  return std::filesystem::path(Widen(Text));
#else
  return std::filesystem::path(std::string(Text));
#endif
}

std::string PathToUtf8(const std::filesystem::path& Path) {
#ifdef _WIN32
  return Narrow(Path.native());
#else
  return Path.native();
#endif
}

std::string QuoteWindowsArgument(std::string_view Argument) {
  if (!Argument.empty() && Argument.find_first_of(" \t\n\v\"") == std::string_view::npos) {
    return std::string(Argument);
  }
  std::string Quoted = "\"";
  for (size_t Index = 0;; ++Index) {
    size_t Backslashes = 0;
    while (Index < Argument.size() && Argument[Index] == '\\') {
      ++Index;
      ++Backslashes;
    }
    if (Index == Argument.size()) {
      Quoted.append(Backslashes * 2, '\\');  // they precede the closing quote
      break;
    }
    if (Argument[Index] == '"') {
      Quoted.append(Backslashes * 2 + 1, '\\');
      Quoted.push_back('"');
    } else {
      Quoted.append(Backslashes, '\\');
      Quoted.push_back(Argument[Index]);
    }
  }
  Quoted.push_back('"');
  return Quoted;
}

std::string BuildWindowsCommandLine(const std::vector<std::string>& Arguments) {
  std::string Line;
  for (size_t Index = 0; Index < Arguments.size(); ++Index) {
    if (Index != 0) {
      Line.push_back(' ');
    }
    Line += QuoteWindowsArgument(Arguments[Index]);
  }
  return Line;
}

std::optional<std::string> GetEnvUtf8(const char* Name) {
#ifdef _WIN32
  const std::wstring WideName = Widen(Name);
  const DWORD Needed = GetEnvironmentVariableW(WideName.c_str(), nullptr, 0);
  if (Needed <= 1) {
    return std::nullopt;
  }
  std::wstring Value(Needed, L'\0');
  const DWORD Got = GetEnvironmentVariableW(WideName.c_str(), Value.data(), Needed);
  if (Got == 0 || Got >= Needed) {
    return std::nullopt;
  }
  Value.resize(Got);
  return Narrow(Value);
#else
  const char* Value = std::getenv(Name);
  if (Value == nullptr || *Value == '\0') {
    return std::nullopt;
  }
  return std::string(Value);
#endif
}

std::filesystem::path SelfExecutablePath() {
#if defined(_WIN32)
  std::wstring Buffer(32768, L'\0');
  const DWORD Length = GetModuleFileNameW(nullptr, Buffer.data(), static_cast<DWORD>(Buffer.size()));
  if (Length == 0 || Length >= Buffer.size()) {
    return std::filesystem::path();
  }
  Buffer.resize(Length);
  return std::filesystem::path(Buffer);
#elif defined(__APPLE__)
  uint32_t Size = 0;
  _NSGetExecutablePath(nullptr, &Size);
  std::string Buffer(Size + 1, '\0');
  if (_NSGetExecutablePath(Buffer.data(), &Size) != 0) {
    return std::filesystem::path();
  }
  Buffer.resize(std::strlen(Buffer.c_str()));
  std::error_code Error;
  const std::filesystem::path Canonical = std::filesystem::weakly_canonical(Buffer, Error);
  return Error ? std::filesystem::path(Buffer) : Canonical;
#else
  std::error_code Error;
  const std::filesystem::path Link = std::filesystem::read_symlink("/proc/self/exe", Error);
  return Error ? std::filesystem::path() : Link;
#endif
}

std::filesystem::path SidecarPathFor(const std::filesystem::path& Output) {
  // os.path.splitext on the file name (dsig_export.py DefaultSidecar): the last '.' starts the extension
  // unless everything before it is dots, so ".hidden" and "..x" have none.
  const std::string Name = PathToUtf8(Output.filename());
  const size_t Dot = Name.rfind('.');
  bool HasExtension = false;
  if (Dot != std::string::npos) {
    for (size_t Index = 0; Index < Dot; ++Index) {
      if (Name[Index] != '.') {
        HasExtension = true;
        break;
      }
    }
  }
  const std::string Stem = HasExtension ? Name.substr(0, Dot) : Name;
  return Output.parent_path() / PathFromUtf8(Stem + ".export.json");
}

std::optional<std::string> FileSha256(const std::filesystem::path& Path) {
  std::ifstream Stream(Path, std::ios::binary);
  if (!Stream) {
    return std::nullopt;
  }
  Sha256 Hash;
  std::vector<char> Buffer(1u << 20);
  while (Stream) {
    Stream.read(Buffer.data(), static_cast<std::streamsize>(Buffer.size()));
    const std::streamsize Got = Stream.gcount();
    if (Got > 0) {
      Hash.Update(Buffer.data(), static_cast<size_t>(Got));
    }
  }
  if (Stream.bad()) {
    return std::nullopt;
  }
  return Hash.FinishHex();
}

std::string ToolErrorLine(const std::string& Tail) {
  constexpr std::string_view Prefix = "dsig_export: error: ";
  size_t Position = Tail.rfind(Prefix);
  // Only a prefix at the start of a line counts; the guard keeps Position > 0 inside the loop.
  while (Position != std::string::npos && Position != 0 && Tail[Position - 1] != '\n') {
    Position = Tail.rfind(Prefix, Position - 1);
  }
  if (Position == std::string::npos) {
    return std::string();
  }
  const size_t Start = Position + Prefix.size();
  const size_t End = Tail.find_first_of("\r\n", Start);
  return Tail.substr(Start, End == std::string::npos ? std::string::npos : End - Start);
}

bool SameFile(const std::filesystem::path& A, const std::filesystem::path& B) {
  if (A.empty() || B.empty()) {
    return false;
  }
  std::error_code Error;
  const bool ExistsA = std::filesystem::exists(A, Error);
  Error.clear();
  const bool ExistsB = std::filesystem::exists(B, Error);
  if (ExistsA && ExistsB) {
    // One file under two names: a hard link, an 8.3 short name, a case variant, a share of a local drive.
    Error.clear();
    if (std::filesystem::equivalent(A, B, Error) && !Error) {
      return true;
    }
  }
  return SameSpelling(CanonicalOrAbsolute(A), CanonicalOrAbsolute(B));
}

std::optional<std::string> WrittenPathAlias(const std::filesystem::path& Output, const std::filesystem::path& Sidecar,
                                            const std::vector<std::pair<std::string, std::filesystem::path>>& Protected) {
  const std::string OutputText = PathToUtf8(Output);
  std::vector<std::pair<std::string, std::filesystem::path>> Written = {{"the output", Output}};
  for (const char* Suffix : kOutputSidecars) {
    Written.push_back({std::string("the output's ") + Suffix + " file", PathFromUtf8(OutputText + Suffix)});
  }
  Written.push_back({"the sidecar", Sidecar});
  const std::string Refusal = "; refusing to overwrite an input (nothing was changed)";
  for (const auto& [WrittenRole, WrittenPath] : Written) {
    for (const auto& [Role, Path] : Protected) {
      if (SameFile(WrittenPath, Path)) {
        return WrittenRole + " '" + PathToUtf8(WrittenPath) + "' is " + Role + " '" + PathToUtf8(Path) + "'" + Refusal;
      }
    }
  }
  // dsig_export.py also writes names that carry its pid, unknown here: the staging copy
  // (<output>.dsig-tmp-<pid>), a previous output's sidecars renamed aside (<output>-wal.dsig-old-<pid>, ...)
  // and the sidecar's temporary file (<sidecar>.tmp-<pid>). Any input so named could be one of them.
  const std::string OutputName = PathToUtf8(Output.filename());
  std::vector<std::pair<std::string, std::string>> Prefixes = {{"the output's staging copy", OutputName + ".dsig-tmp-"}};
  for (const char* Suffix : kOutputSidecars) {
    Prefixes.push_back({std::string("the previous output's ") + Suffix + " file moved aside",
                        OutputName + Suffix + ".dsig-old-"});
  }
  Prefixes.push_back({"the sidecar's temporary file", PathToUtf8(Sidecar.filename()) + ".tmp-"});
  for (const auto& [Role, Path] : Protected) {
    if (Path.empty() || !SameFile(Path.parent_path(), Output.parent_path())) {
      continue;
    }
    const std::string Name = PathToUtf8(Path.filename());
    for (const auto& [WrittenRole, Prefix] : Prefixes) {
      if (NameStartsWith(Name, Prefix)) {
        return Role + " '" + PathToUtf8(Path) + "' has the name of " + WrittenRole + " ('" + Prefix + "<pid>')" +
               Refusal;
      }
    }
  }
  return std::nullopt;
}

std::string InterpreterProblem(const std::filesystem::path& Path) {
#ifdef _WIN32
  // Windows ignores trailing dots and spaces in a file name, so "python.bat." is a batch file too.
  std::string Name = ToLowerAscii(PathToUtf8(Path.filename()));
  while (!Name.empty() && (Name.back() == '.' || Name.back() == ' ')) {
    Name.pop_back();
  }
  const auto EndsWith = [&Name](std::string_view Suffix) {
    return Name.size() >= Suffix.size() && Name.compare(Name.size() - Suffix.size(), Suffix.size(), Suffix) == 0;
  };
  for (const char* Script : {".bat", ".cmd", ".btm"}) {
    if (EndsWith(Script)) {
      return "is a batch file, not an executable";
    }
  }
  std::ifstream Stream(Path, std::ios::binary);
  if (!Stream) {
    // The Store's python.exe is an app-execution alias that cannot be opened for reading.
    return (EndsWith(".exe") || EndsWith(".com")) ? std::string() : std::string("cannot be read");
  }
  char Head[2] = {0, 0};
  Stream.read(Head, 2);
  if (Stream.gcount() != 2 || Head[0] != 'M' || Head[1] != 'Z') {
    return "is not a Windows executable (no MZ header; a script shim?)";
  }
  return std::string();
#else
  (void)Path;
  return std::string();
#endif
}

Located FindPython(const std::string& Flag) {
  Located Result;
  const Setting Chosen = FlagOrEnv(Flag, "--python", "DSIG_PYTHON");
  std::string Shown;
  if (Chosen.Value) {
    Result.Source = Chosen.Source;
    Shown = *Chosen.Value;
    const std::filesystem::path Candidate = PathFromUtf8(*Chosen.Value);
    if (!Candidate.has_parent_path()) {
      // A bare name such as "python3": look it up on PATH like a shell would. On Windows a name without
      // an extension means name.exe, as for CreateProcess; an extension-less file of that name (a
      // pyenv-win shell shim) is not a program Windows can start.
      std::vector<std::filesystem::path> Names = {Candidate};
#ifdef _WIN32
      if (!Candidate.has_extension()) {
        Names = {std::filesystem::path(Candidate).replace_extension(".exe")};
      }
#endif
      if (auto Found = SearchPath(Names)) {
        Result.Path = *Found;
      } else {
        Result.Error = "Python not found: " + Chosen.Source + " '" + *Chosen.Value + "' is not on PATH";
      }
    } else if (IsExecutableFile(Candidate)) {
      Result.Path = Absolute(Candidate);
    } else {
      Result.Error = "Python not found: " + Chosen.Source + " '" + *Chosen.Value + "' does not exist" +
                     (IsDirectory(Candidate) ? " as a file (it is a directory)" : "");
    }
  } else {
    Result.Source = "PATH";
#ifdef _WIN32
    const std::vector<std::filesystem::path> Names = {"python.exe", "python3.exe"};
#else
    const std::vector<std::filesystem::path> Names = {"python3", "python"};
#endif
    if (auto Found = SearchPath(Names)) {
      Result.Path = *Found;
      Shown = PathToUtf8(Result.Path);
    } else {
      Result.Error = "Python not found: no python on PATH (pass --python <python executable> or set DSIG_PYTHON)";
    }
  }
  // Never start a batch file: cmd.exe would re-parse the arguments, and '&' or '%' in a sample's file
  // name would run commands (audit F15). Escaping for cmd is not attempted; it cannot be done reliably.
  if (!Result.Path.empty()) {
    const std::string Problem = InterpreterProblem(Result.Path);
    if (!Problem.empty()) {
      Result.Error = "Python not found: " + Result.Source + " '" + Shown + "' " + Problem +
                     "; point --python at python.exe itself (pyenv-win and conda shims are batch files; use the "
                     "interpreter inside the environment)";
      Result.Path.clear();
    }
  }
  return Result;
}

Located FindExportScript(const std::string& Flag) {
  Located Result;
  const Setting Chosen = FlagOrEnv(Flag, "--export-script", "DSIG_EXPORT_SCRIPT");
  if (Chosen.Value) {
    Result.Source = Chosen.Source;
    const std::filesystem::path Candidate = PathFromUtf8(*Chosen.Value);
    if (IsFile(Candidate)) {
      Result.Path = Absolute(Candidate);
    } else {
      Result.Error = "export script not found: " + Chosen.Source + " '" + *Chosen.Value + "' does not exist";
    }
    return Result;
  }
  // Beside the executable (a build directory, where CMake copies it, or a zip), or in <prefix>/share.
  Result.Source = "beside the executable";
  const std::filesystem::path Executable = SelfExecutablePath();
  const std::vector<std::filesystem::path> Candidates = ExportScriptCandidates(Executable);
  std::string Searched;
  for (const std::filesystem::path& Candidate : Candidates) {
    if (IsFile(Candidate)) {
      Result.Path = Absolute(Candidate);
      return Result;
    }
    Searched += (Searched.empty() ? "'" : ", '") + PathToUtf8(Candidate) + "'";
  }
  Result.Error = "export script not found: no dsig_export.py at " +
                 (Searched.empty() ? std::string("the executable's location (unknown on this platform)") : Searched) +
                 " (pass --export-script <path> or set DSIG_EXPORT_SCRIPT)";
  return Result;
}

std::vector<std::filesystem::path> ExportScriptCandidates(const std::filesystem::path& Executable) {
  std::vector<std::filesystem::path> Candidates;
  if (Executable.empty()) {
    return Candidates;
  }
  const std::filesystem::path Script = std::filesystem::path("tools") / "export" / "dsig_export.py";
  const std::filesystem::path Directory = Executable.parent_path();
  Candidates.push_back(Directory / "dsig_export.py");
  Candidates.push_back(Directory / "share" / "dsigmatcher" / Script);
  Candidates.push_back(Directory.parent_path() / "share" / "dsigmatcher" / Script);
  return Candidates;
}

Located FindIdaDir(const std::string& Flag) {
  Located Result;
  const Setting Chosen = FlagOrEnv(Flag, "--ida-dir", "DSIG_IDADIR");
  if (!Chosen.Value) {
    return Result;  // not configured here: dsig_export.py tries IDADIR and idapro's ida-config.json
  }
  Result.Source = Chosen.Source;
  const std::filesystem::path Directory = PathFromUtf8(*Chosen.Value);
  if (!IsDirectory(Directory)) {
    Result.Error = "IDA not found: " + Chosen.Source + " '" + *Chosen.Value + "' is not a directory";
  } else if (!HasFileWithin(Directory, IdaLibraryName(), 3)) {
    Result.Error = "IDA not found: " + Chosen.Source + " '" + *Chosen.Value + "' has no " +
                   PathToUtf8(IdaLibraryName()) + " (IDA 9.0 or newer with idalib is required)";
  } else {
    Result.Path = Absolute(Directory);
  }
  return Result;
}

Located FindDiaphoraDir(const std::string& Flag) {
  Located Result;
  const Setting Chosen = FlagOrEnv(Flag, "--diaphora-dir", "DSIG_DIAPHORA_DIR");
  if (!Chosen.Value) {
    Result.Error = "Diaphora not found: pass --diaphora-dir <Diaphora checkout> or set DSIG_DIAPHORA_DIR "
                   "(Diaphora is AGPL and is not bundled)";
    return Result;
  }
  Result.Source = Chosen.Source;
  const std::filesystem::path Directory = PathFromUtf8(*Chosen.Value);
  if (!IsDirectory(Directory)) {
    Result.Error = "Diaphora not found: " + Chosen.Source + " '" + *Chosen.Value + "' is not a directory";
    return Result;
  }
  std::string Missing;
  for (const char* Name : {"diaphora.py", "diaphora_ida.py", "diaphora_config.py"}) {
    if (!IsFile(Directory / Name)) {
      Missing += (Missing.empty() ? "" : ", ") + std::string(Name);
    }
  }
  if (!Missing.empty()) {
    Result.Error = "Diaphora not found: " + Chosen.Source + " '" + *Chosen.Value + "' has no " + Missing;
    return Result;
  }
  Result.Path = Absolute(Directory);
  return Result;
}

#ifdef _WIN32

ProcessResult RunProcess(const std::vector<std::string>& Arguments,
                         const std::vector<std::pair<std::string, std::string>>& Overrides, int64_t TimeoutSeconds,
                         std::FILE* Forward, const std::filesystem::path& WorkingDirectory) {
  ProcessResult Result;
  if (Arguments.empty()) {
    Result.Error = "no program given";
    return Result;
  }
  if (InterpreterProblem(PathFromUtf8(Arguments[0])).rfind("is a batch file", 0) == 0) {
    // Defence in depth for later callers: CreateProcess would run a batch file through cmd.exe.
    Result.Error = "refusing to start a batch file: " + Arguments[0];
    return Result;
  }
  SECURITY_ATTRIBUTES Inheritable{};
  Inheritable.nLength = sizeof(Inheritable);
  Inheritable.bInheritHandle = TRUE;
  HANDLE ReadEnd = nullptr;
  HANDLE WriteEnd = nullptr;
  if (!CreatePipe(&ReadEnd, &WriteEnd, &Inheritable, 0)) {
    Result.Error = "CreatePipe: " + SystemErrorText(GetLastError());
    return Result;
  }
  SetHandleInformation(ReadEnd, HANDLE_FLAG_INHERIT, 0);
  HANDLE NullDevice = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &Inheritable,
                                  OPEN_EXISTING, 0, nullptr);
  if (NullDevice == INVALID_HANDLE_VALUE) {
    Result.Error = "open NUL: " + SystemErrorText(GetLastError());
    CloseHandle(ReadEnd);
    CloseHandle(WriteEnd);
    return Result;
  }

  // Only the pipe and NUL are inherited, whatever else this process has open.
  SIZE_T AttributeBytes = 0;
  InitializeProcThreadAttributeList(nullptr, 1, 0, &AttributeBytes);
  std::vector<unsigned char> AttributeStorage(AttributeBytes);
  auto* Attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(AttributeStorage.data());
  HANDLE Inherited[2] = {WriteEnd, NullDevice};
  const bool AttributesOk =
      InitializeProcThreadAttributeList(Attributes, 1, 0, &AttributeBytes) &&
      UpdateProcThreadAttribute(Attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, Inherited, sizeof(Inherited),
                                nullptr, nullptr);

  STARTUPINFOEXW Startup{};
  Startup.StartupInfo.cb = sizeof(Startup);
  Startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
  Startup.StartupInfo.hStdInput = NullDevice;
  Startup.StartupInfo.hStdOutput = WriteEnd;
  Startup.StartupInfo.hStdError = WriteEnd;
  Startup.lpAttributeList = AttributesOk ? Attributes : nullptr;

  const std::wstring Application = Widen(Arguments[0]);
  std::wstring CommandLine = Widen(BuildWindowsCommandLine(Arguments));
  std::wstring Environment = BuildEnvironmentBlock(Overrides);
  DWORD Flags = CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED;
  if (AttributesOk) {
    Flags |= EXTENDED_STARTUPINFO_PRESENT;
  }
  if (GetConsoleWindow() == nullptr) {
    Flags |= CREATE_NO_WINDOW;  // no console of our own: do not pop one up for the child
  }
  PROCESS_INFORMATION Process{};
  const std::wstring Directory = WorkingDirectory.empty() ? std::wstring() : WorkingDirectory.native();
  // The child inherits this process's error mode, and so does everything it starts. Without
  // SEM_FAILCRITICALERRORS (the default under cmd.exe, PowerShell and Explorer) a failed DLL load in the
  // worker, such as a broken or foreign idalib, raises a modal "Bad Image" hard error and the headless
  // run blocks until someone clicks it. With it the load just fails and the script reports the error.
  const UINT PreviousErrorMode = GetErrorMode();
  SetErrorMode(PreviousErrorMode | SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX);
  const BOOL Created =
      CreateProcessW(Application.c_str(), CommandLine.data(), nullptr, nullptr, TRUE, Flags, Environment.data(),
                     Directory.empty() ? nullptr : Directory.c_str(), &Startup.StartupInfo, &Process);
  const DWORD CreateError = GetLastError();
  SetErrorMode(PreviousErrorMode);
  if (AttributesOk) {
    DeleteProcThreadAttributeList(Attributes);
  }
  CloseHandle(WriteEnd);
  CloseHandle(NullDevice);
  if (!Created) {
    CloseHandle(ReadEnd);
    Result.Error = SystemErrorText(CreateError);
    return Result;
  }

  // A kill-on-close job: a timeout kills the whole tree (the script and its IDA worker), and so does
  // this process exiting early.
  HANDLE Job = CreateJobObjectW(nullptr, nullptr);
  if (Job != nullptr) {
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION Limits{};
    Limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(Job, JobObjectExtendedLimitInformation, &Limits, sizeof(Limits)) ||
        !AssignProcessToJobObject(Job, Process.hProcess)) {
      CloseHandle(Job);
      Job = nullptr;
    }
  }
  ResumeThread(Process.hThread);
  CloseHandle(Process.hThread);
  Result.Started = true;
  SetConsoleCtrlHandler(IgnoreConsoleInterrupt, TRUE);

  std::string Tail;
  std::thread Reader([&] {
    char Buffer[4096];
    DWORD Got = 0;
    while (ReadFile(ReadEnd, Buffer, static_cast<DWORD>(sizeof(Buffer)), &Got, nullptr) && Got > 0) {
      if (Forward != nullptr) {
        std::fwrite(Buffer, 1, Got, Forward);
        std::fflush(Forward);
      }
      AppendTail(Tail, Buffer, Got);
    }
  });

  // The deadline is kept on the steady clock and waited for in chunks below INFINITE: a DWORD of
  // milliseconds wraps after 49.7 days, which used to turn a long timeout into a sub-second one (audit F42).
  const auto Deadline = std::chrono::steady_clock::now() + std::chrono::seconds(ClampTimeout(TimeoutSeconds));
  for (;;) {
    DWORD Chunk = INFINITE;
    if (TimeoutSeconds > 0) {
      const auto Left = std::chrono::duration_cast<std::chrono::milliseconds>(Deadline - std::chrono::steady_clock::now());
      if (Left.count() <= 0) {
        Result.TimedOut = true;
        break;
      }
      Chunk = static_cast<DWORD>(std::min<int64_t>(Left.count(), 0x7FFFFFFF));
    }
    const DWORD Waited = WaitForSingleObject(Process.hProcess, Chunk);
    if (Waited != WAIT_TIMEOUT) {
      break;  // exited (or the wait failed; the exit code below tells)
    }
  }
  if (Result.TimedOut) {
    if (Job != nullptr) {
      TerminateJobObject(Job, 1);
    } else {
      TerminateProcess(Process.hProcess, 1);
    }
    WaitForSingleObject(Process.hProcess, INFINITE);
  }
  DWORD Code = 0;
  GetExitCodeProcess(Process.hProcess, &Code);
  Result.ExitCode = static_cast<int>(Code);
  Reader.join();
  SetConsoleCtrlHandler(IgnoreConsoleInterrupt, FALSE);
  CloseHandle(ReadEnd);
  CloseHandle(Process.hProcess);
  if (Job != nullptr) {
    CloseHandle(Job);
  }
  if (Tail.size() > kTailBytes) {
    Tail.erase(0, Tail.size() - kTailBytes);
  }
  Result.Tail = std::move(Tail);
  return Result;
}

#else

// Signals that arrive while the script runs. The script lives in its own process group (so a timeout
// can kill the whole tree), which also takes it out of the terminal's foreground group: a Ctrl-C at the
// terminal reaches only this process, so it is recorded here and forwarded to the group by the wait
// loop (dsig_export.py then stops IDA, removes its work directory and exits 130).
namespace {

volatile sig_atomic_t PendingSignal = 0;

void RecordSignal(int Signal) { PendingSignal = static_cast<sig_atomic_t>(Signal); }

}  // namespace

ProcessResult RunProcess(const std::vector<std::string>& Arguments,
                         const std::vector<std::pair<std::string, std::string>>& Overrides, int64_t TimeoutSeconds,
                         std::FILE* Forward, const std::filesystem::path& WorkingDirectory) {
  (void)WorkingDirectory;  // posix_spawn has no portable chdir; POSIX never searches the cwd for programs
  ProcessResult Result;
  if (Arguments.empty()) {
    Result.Error = "no program given";
    return Result;
  }
  int Pipe[2] = {-1, -1};
  if (pipe(Pipe) != 0) {
    Result.Error = std::string("pipe: ") + std::strerror(errno);
    return Result;
  }
  fcntl(Pipe[0], F_SETFD, FD_CLOEXEC);

  posix_spawn_file_actions_t Actions;
  posix_spawn_file_actions_init(&Actions);
  posix_spawn_file_actions_addopen(&Actions, 0, "/dev/null", O_RDONLY, 0);
  posix_spawn_file_actions_adddup2(&Actions, Pipe[1], 1);
  posix_spawn_file_actions_adddup2(&Actions, Pipe[1], 2);
  if (Pipe[1] > 2) {
    posix_spawn_file_actions_addclose(&Actions, Pipe[1]);
  }
  // A new process group led by the script: Python's subprocess keeps the IDA worker in it, so a
  // signal to -Pid reaches both (audit F44). The forwarded signals get their default action back.
  posix_spawnattr_t Attributes;
  posix_spawnattr_init(&Attributes);
  sigset_t Defaults;
  sigemptyset(&Defaults);
  for (const int Signal : {SIGINT, SIGTERM, SIGHUP}) {
    sigaddset(&Defaults, Signal);
  }
  posix_spawnattr_setsigdefault(&Attributes, &Defaults);
  posix_spawnattr_setpgroup(&Attributes, 0);
  posix_spawnattr_setflags(&Attributes, static_cast<short>(POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGDEF));

  std::vector<std::string> Environment;
  for (char** Entry = environ; Entry != nullptr && *Entry != nullptr; ++Entry) {
    const std::string_view Text(*Entry);
    const std::string_view Name = Text.substr(0, Text.find('='));
    const bool Replaced = std::any_of(Overrides.begin(), Overrides.end(),
                                      [&](const auto& Override) { return Override.first == Name; });
    if (!Replaced) {
      Environment.emplace_back(Text);
    }
  }
  for (const auto& [Name, Value] : Overrides) {
    Environment.push_back(Name + "=" + Value);
  }
  std::vector<char*> Envp;
  for (std::string& Entry : Environment) {
    Envp.push_back(Entry.data());
  }
  Envp.push_back(nullptr);
  std::vector<std::string> ArgumentCopies = Arguments;
  std::vector<char*> Argv;
  for (std::string& Argument : ArgumentCopies) {
    Argv.push_back(Argument.data());
  }
  Argv.push_back(nullptr);

  // Installed before the spawn, so no signal falls between the spawn and the wait loop.
  PendingSignal = 0;
  struct sigaction Record {};
  Record.sa_handler = RecordSignal;
  sigemptyset(&Record.sa_mask);
  // A signal this process ignores (SIGINT in a background job) stays ignored and is not forwarded.
  const int Forwarded[] = {SIGINT, SIGTERM, SIGHUP};
  struct sigaction Previous[3] {};
  bool Installed[3] = {false, false, false};
  for (size_t Index = 0; Index < 3; ++Index) {
    if (sigaction(Forwarded[Index], nullptr, &Previous[Index]) == 0 && Previous[Index].sa_handler != SIG_IGN) {
      Installed[Index] = sigaction(Forwarded[Index], &Record, nullptr) == 0;
    }
  }
  const auto RestoreSignals = [&] {
    for (size_t Index = 0; Index < 3; ++Index) {
      if (Installed[Index]) {
        sigaction(Forwarded[Index], &Previous[Index], nullptr);
      }
    }
  };

  pid_t Pid = 0;
  const int SpawnError = posix_spawn(&Pid, Arguments[0].c_str(), &Actions, &Attributes, Argv.data(), Envp.data());
  posix_spawn_file_actions_destroy(&Actions);
  posix_spawnattr_destroy(&Attributes);
  close(Pipe[1]);
  if (SpawnError != 0) {
    RestoreSignals();
    close(Pipe[0]);
    Result.Error = std::strerror(SpawnError);
    return Result;
  }
  Result.Started = true;

  std::string Tail;
  std::thread Reader([&] {
    char Buffer[4096];
    for (;;) {
      const ssize_t Got = read(Pipe[0], Buffer, sizeof(Buffer));
      if (Got > 0) {
        if (Forward != nullptr) {
          std::fwrite(Buffer, 1, static_cast<size_t>(Got), Forward);
          std::fflush(Forward);
        }
        AppendTail(Tail, Buffer, static_cast<size_t>(Got));
      } else if (Got < 0 && errno == EINTR) {
        continue;
      } else {
        break;
      }
    }
  });

  // Polls with WNOWAIT: the exited script stays a zombie, so its pid, which is also the group id,
  // cannot be reused before the stragglers in the group are killed below.
  const auto HasExited = [&] {
    siginfo_t Info{};
    const int Code = waitid(P_PID, static_cast<id_t>(Pid), &Info, WEXITED | WNOHANG | WNOWAIT);
    return (Code == 0 && Info.si_pid == Pid) || (Code < 0 && errno != EINTR);
  };
  const auto ForwardPending = [&] {
    if (const int Signal = PendingSignal) {
      PendingSignal = 0;
      kill(-Pid, Signal);
    }
  };
  const auto Deadline = std::chrono::steady_clock::now() + std::chrono::seconds(ClampTimeout(TimeoutSeconds));
  while (!HasExited()) {
    ForwardPending();
    if (TimeoutSeconds > 0 && std::chrono::steady_clock::now() >= Deadline) {
      // SIGTERM first: dsig_export.py stops its IDA worker and removes its work directory.
      Result.TimedOut = true;
      kill(-Pid, SIGTERM);
      const auto Grace = std::chrono::steady_clock::now() + std::chrono::seconds(30);
      while (!HasExited() && std::chrono::steady_clock::now() < Grace) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
      }
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  // Whatever is left of the tree (a hung script after the grace period, or an orphaned worker) dies with
  // the group, as the job object does on Windows.
  kill(-Pid, SIGKILL);
  int Status = 0;
  while (waitpid(Pid, &Status, 0) < 0 && errno == EINTR) {
  }
  RestoreSignals();
  if (WIFEXITED(Status)) {
    Result.ExitCode = WEXITSTATUS(Status);
  } else if (WIFSIGNALED(Status)) {
    Result.ExitCode = 128 + WTERMSIG(Status);
  }
  Reader.join();
  close(Pipe[0]);
  if (Tail.size() > kTailBytes) {
    Tail.erase(0, Tail.size() - kTailBytes);
  }
  Result.Tail = std::move(Tail);
  return Result;
}

#endif

}  // namespace DSig::Cli::ExportBridge

namespace DSig::Cli {

namespace {

using namespace ExportBridge;

constexpr std::string_view kSidecarSchema = "dsig-export/1";

CommandOutcome Fail(int ExitCode, std::string Message) {
  CommandOutcome Outcome;
  Outcome.ExitCode = ExitCode;
  Outcome.Message = std::move(Message);
  return Outcome;
}

// Diaphora refuses to export into an IDA file name (diaphora_ida.py:3978-3987 is_ida_file, :3664).
bool HasIdaExtension(const std::filesystem::path& Path) {
  const std::string Extension = ToLowerAscii(PathToUtf8(Path.extension()));
  for (const char* Candidate : {".idb", ".i64", ".til", ".id0", ".id1", ".nam"}) {
    if (Extension == Candidate) {
      return true;
    }
  }
  return false;
}

// A .pdb is never a valid export name, and `-o x.pdb --pdb x.pdb` used to replace the PDB (audit F02).
bool HasPdbExtension(const std::filesystem::path& Path) { return ToLowerAscii(PathToUtf8(Path.extension())) == ".pdb"; }

const Diff::JsonValue* Member(const Diff::JsonValue* Object, std::string_view Key) {
  return (Object != nullptr && Object->IsObject()) ? Object->Find(Key) : nullptr;
}

std::string ScalarText(const Diff::JsonValue* Value) {
  if (Value == nullptr || Value->IsNull()) {
    return "?";
  }
  if (Value->IsString()) {
    return Value->AsString();
  }
  if (Value->IsNumber()) {
    return Value->NumberText();
  }
  if (Value->IsBool()) {
    return Value->AsBool() ? "true" : "false";
  }
  if (Value->IsArray()) {
    std::string Text;
    for (const Diff::JsonValue& Item : Value->Items()) {
      Text += (Text.empty() ? "" : ".") + ScalarText(&Item);
    }
    return Text;
  }
  return "?";
}

CommandOutcome RunExport(std::string_view Command, std::string_view Mode, const std::string& InputText,
                         const std::string& OutputText, const ExportToolOptions& Tools, const std::string& PdbText,
                         bool NoPdb) {
  const std::string Name(Command);
  if (InputText.empty()) {
    return Fail(kExitUsage, Name + ": no input given");
  }
  if (OutputText.empty()) {
    return Fail(kExitUsage, Name + ": -o <out.sqlite> is required");
  }
  if (Tools.TimeoutSeconds < 0 || Tools.TimeoutSeconds > kMaxTimeoutSeconds) {
    return Fail(kExitUsage, Name + ": --timeout must be between 0 and " + std::to_string(kMaxTimeoutSeconds) +
                                " seconds (30 days), got " + std::to_string(Tools.TimeoutSeconds));
  }

  // ---- the input
  const std::filesystem::path Input = Absolute(PathFromUtf8(InputText));
  if (IsDirectory(Input)) {
    return Fail(kExitIo, Name + ": the input is a directory: " + PathToUtf8(Input));
  }
  if (!IsFile(Input)) {
    return Fail(kExitIo, Name + ": input not found: " + PathToUtf8(Input));
  }
  const std::string Extension = ToLowerAscii(PathToUtf8(Input.extension()));
  const bool IsDatabase = Extension == ".i64" || Extension == ".idb";
  if (Mode == "idb" && !IsDatabase) {
    return Fail(kExitUsage, Name + " expects an IDA database (.i64 or .idb), got " + PathToUtf8(Input) +
                                "; use 'dsigmatcher ingest' for a raw binary");
  }
  if (Mode == "binary" && IsDatabase) {
    return Fail(kExitUsage, Name + " expects a raw binary, got the IDA database " + PathToUtf8(Input) +
                                "; use 'dsigmatcher extract' to export it");
  }

  // ---- the output
  const std::filesystem::path Output = Absolute(PathFromUtf8(OutputText));
  if (HasIdaExtension(Output)) {
    return Fail(kExitUsage, Name + ": the output must not have an IDA extension (.idb .i64 .til .id0 .id1 .nam): " +
                                PathToUtf8(Output));
  }
  if (HasPdbExtension(Output)) {
    return Fail(kExitUsage, Name + ": the output must not have the .pdb extension: " + PathToUtf8(Output));
  }
  if (SameFile(Output, Input)) {
    return Fail(kExitUsage, Name + ": the output is the input: " + PathToUtf8(Output));
  }
  if (IsDirectory(Output)) {
    return Fail(kExitUsage, Name + ": the output is a directory: " + PathToUtf8(Output));
  }
  if (!IsDirectory(Output.parent_path())) {
    return Fail(kExitIo, Name + ": the output directory does not exist: " + PathToUtf8(Output.parent_path()));
  }
  const std::filesystem::path Sidecar = SidecarPathFor(Output);
  if (SameFile(Sidecar, Output)) {
    return Fail(kExitUsage, Name + ": the sidecar " + PathToUtf8(Sidecar) + " is the output");
  }

  // ---- the PDB (ingest only)
  if (!PdbText.empty() && NoPdb) {
    return Fail(kExitUsage, Name + ": --pdb and --no-pdb are exclusive");
  }
  std::filesystem::path Pdb;
  if (!PdbText.empty()) {
    Pdb = Absolute(PathFromUtf8(PdbText));
    if (!IsFile(Pdb) || IsDirectory(Pdb)) {
      return Fail(kExitIo, Name + ": PDB not found: " + PathToUtf8(Pdb));
    }
  }
  // Nothing the script writes, replaces or moves aside may be the input or the PDB (audit F02); checked
  // before anything runs or is read, so a refusal leaves every file as it was.
  std::vector<std::pair<std::string, std::filesystem::path>> Protected = {{"the input", Input}};
  if (!Pdb.empty()) {
    Protected.push_back({"the PDB", Pdb});
  }
  if (const std::optional<std::string> Alias = WrittenPathAlias(Output, Sidecar, Protected)) {
    return Fail(kExitUsage, Name + ": " + *Alias);
  }
  std::filesystem::path TempDir;
  if (!Tools.TempDir.empty()) {
    TempDir = Absolute(PathFromUtf8(Tools.TempDir));
    if (!IsDirectory(TempDir)) {
      return Fail(kExitIo, Name + ": --temp-dir does not exist: " + PathToUtf8(TempDir));
    }
  }

  // ---- the tools: every missing one is reported at once
  const Located Python = FindPython(Tools.Python);
  const Located Script = FindExportScript(Tools.ExportScript);
  const Located Ida = FindIdaDir(Tools.IdaDir);
  const Located Diaphora = FindDiaphoraDir(Tools.DiaphoraDir);
  std::string Missing;
  for (const Located* Tool : {&Python, &Script, &Ida, &Diaphora}) {
    if (!Tool->Ok()) {
      Missing += (Missing.empty() ? "" : "; ") + Tool->Error;
    }
  }
  if (!Missing.empty()) {
    return Fail(kExitUnsupported, Name + ": " + Missing);
  }

  const std::optional<std::string> InputSha = FileSha256(Input);
  if (!InputSha) {
    return Fail(kExitIo, Name + ": cannot read the input: " + PathToUtf8(Input));
  }

  // -E: the interpreter ignores PYTHONPATH, PYTHONHOME, PYTHONSTARTUP and the like, so a module planted
  // through the caller's environment cannot shadow the driver's (audit F66; dsig_export.py CleanEnv drops
  // them for the IDA worker too). -X utf8 replaces PYTHONUTF8/PYTHONIOENCODING, which -E ignores. -I and
  // -s are not used: the idapro wheel may live in the user's site-packages.
  std::vector<std::string> Arguments = {PathToUtf8(Python.Path), "-E", "-X", "utf8", "-B", "-u",
                                        PathToUtf8(Script.Path), std::string(Mode), PathToUtf8(Input), "-o",
                                        PathToUtf8(Output), "--sidecar", PathToUtf8(Sidecar)};
  if (!Ida.Path.empty()) {
    Arguments.insert(Arguments.end(), {"--ida-dir", PathToUtf8(Ida.Path)});
  }
  Arguments.insert(Arguments.end(), {"--diaphora-dir", PathToUtf8(Diaphora.Path)});
  if (!TempDir.empty()) {
    Arguments.insert(Arguments.end(), {"--temp-dir", PathToUtf8(TempDir)});
  }
  if (Tools.KeepTemp) {
    Arguments.push_back("--keep-temp");
  }
  if (Tools.TimeoutSeconds > 0) {
    Arguments.insert(Arguments.end(), {"--timeout", std::to_string(Tools.TimeoutSeconds)});
  }
  if (Mode == "binary") {
    if (!Pdb.empty()) {
      Arguments.insert(Arguments.end(), {"--pdb", PathToUtf8(Pdb)});
    } else {
      Arguments.push_back("--no-pdb");
    }
  }
  // NoDefaultCurrentDirectoryInExePath: no program the script or IDA starts by a bare name (git, for
  // one) is looked up in the current directory, which is often the sample's own folder (audit F16). The
  // script also starts in its own directory rather than the caller's, for the same reason (Windows
  // searches the current directory for DLLs as well). Every path passed to it is absolute.
  const std::vector<std::pair<std::string, std::string>> Overrides = {
      {"PYTHONIOENCODING", "utf-8"},       {"PYTHONUTF8", "1"},
      {"PYTHONDONTWRITEBYTECODE", "1"},    {"PYTHONUNBUFFERED", "1"},
      {"NoDefaultCurrentDirectoryInExePath", "1"}};

  // dsig_export.py enforces --timeout itself and cleans up; this is only a backstop for a hung script.
  // 64-bit, so the grace period cannot overflow (audit F42).
  const int64_t Backstop =
      Tools.TimeoutSeconds > 0 ? static_cast<int64_t>(Tools.TimeoutSeconds) + kBackstopGraceSeconds : 0;
  const ProcessResult Run = RunProcess(Arguments, Overrides, Backstop, stderr, Script.Path.parent_path());
  if (!Run.Started) {
    return Fail(kExitUnsupported, Name + ": cannot start Python '" + PathToUtf8(Python.Path) + "' (from " +
                                      Python.Source + "): " + Run.Error);
  }

  // The original must be untouched whatever happened; checked here too, not only by the script.
  const std::optional<std::string> InputShaAfter = FileSha256(Input);
  if (!InputShaAfter || *InputShaAfter != *InputSha) {
    return Fail(kExitIo, Name + ": THE INPUT CHANGED during the export: " + PathToUtf8(Input) + " (sha256 " +
                             *InputSha + " -> " + InputShaAfter.value_or("unreadable") + ")");
  }
  if (Run.TimedOut) {
    return Fail(kExitIo, Name + ": timeout: the export tool did not stop within " + std::to_string(Backstop) +
                             " s and was killed");
  }
  if (Run.ExitCode != 0) {
#ifdef _WIN32
    if (Run.ExitCode == 9009) {
      return Fail(kExitUnsupported, Name + ": Python not found: '" + PathToUtf8(Python.Path) +
                                        "' is the Microsoft Store placeholder (exit 9009); install Python or pass "
                                        "--python <python executable>");
    }
#endif
    const ToolExit Mapped = MapToolExit(Run.ExitCode);
    std::string Message = Name + " failed: " + Mapped.What + " (dsig_export.py exit " +
                          std::to_string(Run.ExitCode) + ")";
    const std::string Detail = ToolErrorLine(Run.Tail);
    if (!Detail.empty()) {
      Message += ": " + Detail;
    }
    if (Run.ExitCode == kToolHexRays) {
      // The script's own --allow-no-decompiler is not a dsigmatcher option; its variable reaches the script.
      Message += " [to export anyway, set DSIG_EXPORT_ALLOW_NO_DECOMPILER=1; such an export must not be diffed "
                 "against one made with Hex-Rays]";
    }
    return Fail(Mapped.ExitCode, Message);
  }

  // ---- success: check what the script says it did
  if (!IsFile(Output)) {
    return Fail(kExitIo, Name + ": the export tool reported success but wrote no " + PathToUtf8(Output));
  }
  const std::optional<std::string> SidecarText = ReadTextFile(Sidecar);
  if (!SidecarText) {
    return Fail(kExitIo, Name + ": the export tool wrote no sidecar " + PathToUtf8(Sidecar));
  }
  Diff::JsonValue Record;
  try {
    Record = Diff::JsonParse(*SidecarText);
  } catch (const Diff::JsonError& Exc) {
    return Fail(kExitIo, Name + ": the sidecar " + PathToUtf8(Sidecar) + " is not valid JSON: " + Exc.what());
  }
  const Diff::JsonValue* Schema = Member(&Record, "schema");
  const Diff::JsonValue* InputRecord = Member(&Record, "input");
  const Diff::JsonValue* OutputRecord = Member(&Record, "output");
  const Diff::JsonValue* Unchanged = Member(InputRecord, "unchanged");
  const std::optional<std::string> OutputSha = FileSha256(Output);
  std::string Mismatch;
  if (ScalarText(Schema) != kSidecarSchema) {
    Mismatch = "schema is " + ScalarText(Schema);
  } else if (ScalarText(Member(InputRecord, "sha256")) != *InputSha) {
    Mismatch = "input sha256 " + ScalarText(Member(InputRecord, "sha256")) + " is not " + *InputSha;
  } else if (Unchanged == nullptr || !Unchanged->IsBool() || !Unchanged->AsBool()) {
    Mismatch = "the input is not recorded as unchanged";
  } else if (!OutputSha || ScalarText(Member(OutputRecord, "sha256")) != *OutputSha) {
    Mismatch = "output sha256 " + ScalarText(Member(OutputRecord, "sha256")) + " is not the file's " +
               OutputSha.value_or("(unreadable)");
  }
  if (!Mismatch.empty()) {
    return Fail(kExitIo, Name + ": the sidecar " + PathToUtf8(Sidecar) + " does not match the run: " + Mismatch);
  }

  const Diff::JsonValue* Counts = Member(&Record, "counts");
  const Diff::JsonValue* IdaRecord = Member(&Record, "ida");
  const Diff::JsonValue* DiaphoraRecord = Member(&Record, "diaphora");
  const Diff::JsonValue* PdbRecord = Member(&Record, "pdb");
  CommandOutcome Outcome;
  Outcome.Report.push_back(Name + ": wrote " + PathToUtf8(Output));
  Outcome.Report.push_back("  functions    : " + ScalarText(Member(Counts, "functions")) + " exported (" +
                           ScalarText(Member(Counts, "functions_named")) + " named, " +
                           ScalarText(Member(Counts, "functions_sub")) + " sub_*, " +
                           ScalarText(Member(Counts, "functions_with_pseudocode")) + " with pseudo-code) of " +
                           ScalarText(Member(Counts, "ida_functions")) + " in IDA");
  Outcome.Report.push_back("  input sha256 : " + *InputSha + " (unchanged)");
  if (Mode == "binary") {
    const Diff::JsonValue* Applied = Member(PdbRecord, "applied");
    Outcome.Report.push_back(
        "  pdb          : " +
        ((Applied != nullptr && Applied->IsBool() && Applied->AsBool())
             ? PathToUtf8(Pdb) + " (" + ScalarText(Member(PdbRecord, "symbols_loaded")) + " symbols loaded)"
             : std::string("none (no PDB, no symbol server)")));
  }
  Outcome.Report.push_back("  tools        : IDA " + ScalarText(Member(IdaRecord, "kernel_version")) + " (idalib " +
                           ScalarText(Member(IdaRecord, "idalib_version")) + "), Hex-Rays " +
                           ScalarText(Member(IdaRecord, "hexrays_version")) + ", Diaphora " +
                           ScalarText(Member(DiaphoraRecord, "version_value")) + " (" +
                           ScalarText(Member(DiaphoraRecord, "git_describe")) + ")");
  Outcome.Report.push_back("  sidecar      : " + PathToUtf8(Sidecar));
  return Outcome;
}

CommandOutcome RunExportGuarded(std::string_view Command, std::string_view Mode, const std::string& Input,
                                const std::string& Output, const ExportToolOptions& Tools, const std::string& Pdb,
                                bool NoPdb) {
  try {
    return RunExport(Command, Mode, Input, Output, Tools, Pdb, NoPdb);
  } catch (const std::exception& Exc) {
    return Fail(kExitIo, std::string(Command) + ": internal error: " + Exc.what());
  }
}

}  // namespace

CommandOutcome RunExtract(const ExtractArgs& Args) {
  return RunExportGuarded("extract", "idb", Args.Input, Args.Output, Args.Tools, std::string(), false);
}

CommandOutcome RunIngest(const IngestArgs& Args) {
  return RunExportGuarded("ingest", "binary", Args.Input, Args.Output, Args.Tools, Args.Pdb, Args.NoPdb);
}

}  // namespace DSig::Cli
