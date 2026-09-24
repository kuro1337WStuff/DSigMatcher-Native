#pragma once

// Shared check harness for the diff_* and cli_* suites (no framework, like the existing suites).
// Every suite's main() calls the TestXxx() functions and returns DSig::Test::Finish().
// The last line is "<n> checks run, <f> failed, <s> suites skipped".

#include <cmath>
#include <cstdio>
#include <string>
#include <string_view>

#include "../NoErrorDialogs.h"

namespace DSig::Test {

// Every suite starts with Windows' error dialogs off, before main() (tests/NoErrorDialogs.h).
[[maybe_unused]] static const bool kErrorDialogsDisabled = DisableErrorDialogs();

inline int ChecksRun = 0;
inline int ChecksFailed = 0;
inline int SuitesSkipped = 0;

inline void Report(bool Ok, const char* Expression, const char* File, int Line) {
  ++ChecksRun;
  if (!Ok) {
    ++ChecksFailed;
    std::printf("  FAIL %s:%d  %s\n", File, Line, Expression);
    std::fflush(stdout);
  }
}

inline void ReportText(bool Ok, const char* Expression, std::string_view Actual, std::string_view Expected,
                       const char* File, int Line) {
  Report(Ok, Expression, File, Line);
  if (!Ok) {
    std::printf("       actual:   \"%.*s\"\n       expected: \"%.*s\"\n", static_cast<int>(Actual.size()),
                Actual.data(), static_cast<int>(Expected.size()), Expected.data());
  }
}

inline void ReportNum(bool Ok, const char* Expression, long long Actual, long long Expected, const char* File,
                      int Line) {
  Report(Ok, Expression, File, Line);
  if (!Ok) {
    std::printf("       actual:   %lld\n       expected: %lld\n", Actual, Expected);
  }
}

inline void Suite(const char* Name) {
  std::printf("[%s]\n", Name);
  std::fflush(stdout);
}

inline void Skip(const char* Name, const std::string& Why) {
  ++SuitesSkipped;
  std::printf("[%s] SKIPPED: %s\n", Name, Why.c_str());
  std::fflush(stdout);
}

inline void Note(const std::string& Text) {
  std::printf("  %s\n", Text.c_str());
  std::fflush(stdout);
}

inline int Finish() {
  std::printf("\n%d checks run, %d failed, %d suites skipped\n", ChecksRun, ChecksFailed, SuitesSkipped);
  std::fflush(stdout);
  return ChecksFailed == 0 ? 0 : 1;
}

}

#define CHECK(Expr) ::DSig::Test::Report(static_cast<bool>(Expr), #Expr, __FILE__, __LINE__)
#define CHECK_EQ(A, B) ::DSig::Test::Report((A) == (B), #A " == " #B, __FILE__, __LINE__)
#define CHECK_TEXT_EQ(A, B)                                                                                 \
  do {                                                                                                      \
    const std::string DsigActual_{A};                                                                       \
    const std::string DsigExpected_{B};                                                                     \
    ::DSig::Test::ReportText(DsigActual_ == DsigExpected_, #A " == " #B, DsigActual_, DsigExpected_, __FILE__, \
                             __LINE__);                                                                     \
  } while (0)
#define CHECK_NUM_EQ(A, B)                                                                                  \
  do {                                                                                                      \
    const long long DsigActual_ = static_cast<long long>(A);                                                \
    const long long DsigExpected_ = static_cast<long long>(B);                                              \
    ::DSig::Test::ReportNum(DsigActual_ == DsigExpected_, #A " == " #B, DsigActual_, DsigExpected_, __FILE__, \
                            __LINE__);                                                                      \
  } while (0)
