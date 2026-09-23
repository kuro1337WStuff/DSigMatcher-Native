#pragma once

// Every test executable turns Windows' error dialogs off as the first thing it does
// (SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX): ctest and cmd.exe leave them on,
// and a test, or a child it starts (the CLI, Python, IDA; the mode is inherited), must fail rather than
// block behind a "Bad Image", crash or missing-file dialog. Elsewhere nothing happens.
//
// Two environment variables steer it. DSIG_TEST_KEEP_ERROR_MODE keeps the inherited mode (a child that
// has to report the mode it was given). DSIG_TEST_REPORT_ERROR_MODE makes the executable print
// "ERRORMODE <n>" after setting the mode and exit 0 without running anything else, so cli_commands can
// check that each test executable really does this.

#if defined(_WIN32)
#include <cstdio>
#include <cstdlib>

// Declared here rather than through <windows.h>, whose macros would reach every test.
extern "C" {
__declspec(dllimport) unsigned int __stdcall SetErrorMode(unsigned int Mode);
__declspec(dllimport) unsigned int __stdcall GetErrorMode(void);
__declspec(dllimport) unsigned long __stdcall GetEnvironmentVariableW(const wchar_t* Name, wchar_t* Buffer,
                                                                      unsigned long Size);
}
#endif

namespace DSig::Test {

inline constexpr unsigned kNoErrorDialogsMode = 0x0001u | 0x0002u | 0x8000u;

inline bool DisableErrorDialogs() {
#if defined(_WIN32)
  if (GetEnvironmentVariableW(L"DSIG_TEST_KEEP_ERROR_MODE", nullptr, 0) != 0) {
    return false;
  }
  SetErrorMode(GetErrorMode() | kNoErrorDialogsMode);
  if (GetEnvironmentVariableW(L"DSIG_TEST_REPORT_ERROR_MODE", nullptr, 0) != 0) {
    std::printf("ERRORMODE %u\n", GetErrorMode());
    std::fflush(stdout);
    std::exit(0);
  }
  return true;
#else
  return false;
#endif
}

}  // namespace DSig::Test
