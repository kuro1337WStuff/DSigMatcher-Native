cmake_minimum_required(VERSION 3.20)

project(DSigMatcherNative
  VERSION 0.1.0
  DESCRIPTION "Native C++ binary diffing engine"
  LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

find_package(Threads REQUIRED)

include(FetchContent)

# SQLite. ON (default): the bundled SQLite 3.51.1 amalgamation, compiled with the parity oracle's options
# (cmake/VendoredSqlite.cmake), so Path A reproduces the oracle's row order on every platform and the
# order-sensitive (L2) checks run everywhere. OFF: the system SQLite via find_package(SQLite3); results
# then compare at L1 (order-insensitive) unless that SQLite happens to be the oracle's 3.51.1.
option(DSIG_VENDORED_SQLITE "Build the bundled SQLite 3.51.1 (the parity oracle's) instead of the system SQLite" ON)
if(DSIG_VENDORED_SQLITE)
  include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/VendoredSqlite.cmake)
  set(DSIG_SQLITE_TARGET dsig_sqlite3)
else()
  find_package(SQLite3 REQUIRED)
  set(DSIG_SQLITE_TARGET SQLite::SQLite3)
endif()

set(ZYCORE_BUILD_SHARED_LIB OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_SHARED_LIB OFF CACHE BOOL "" FORCE)
set(ZYDIS_FEATURE_ENCODER OFF CACHE BOOL "" FORCE)
set(ZYDIS_FEATURE_DECODER ON CACHE BOOL "" FORCE)
set(ZYDIS_FEATURE_FORMATTER ON CACHE BOOL "" FORCE)
set(ZYDIS_MINIMAL_MODE OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_TESTS OFF CACHE BOOL "" FORCE)

FetchContent_Declare(zycore
  GIT_REPOSITORY https://github.com/zyantific/zycore-c.git
  GIT_TAG 75a36c45ae1ad382b0f4e0ede0af84c11ee69928)

FetchContent_Declare(zydis
  GIT_REPOSITORY https://github.com/zyantific/zydis.git
  GIT_TAG v4.1.1)

# Zydis and Zycore bring their own install() rules (static libraries, headers, CMake packages). They
# are grouped into their own install component, so `cmake --install <build> --component dsigmatcher`
# installs only the tool (see the install rules below).
set(CMAKE_INSTALL_DEFAULT_COMPONENT_NAME dsig_third_party)
FetchContent_MakeAvailable(zycore)
set(ZYAN_ZYCORE_PATH "${zycore_SOURCE_DIR}" CACHE PATH "" FORCE)
FetchContent_MakeAvailable(zydis)
unset(CMAKE_INSTALL_DEFAULT_COMPONENT_NAME)

function(dsig_apply_warnings Target)
  if(MSVC)
    target_compile_options(${Target} PRIVATE /W4 /permissive- /utf-8 /Zc:__cplusplus)
  else()
    target_compile_options(${Target} PRIVATE -Wall -Wextra -Wpedantic)
  endif()
endfunction()

add_library(dsigmatcher_core STATIC
  src/ControlFlowGraph.cpp
  src/DisassemblerZydis.cpp
  src/ExportDatabase.cpp
  src/Heuristics.cpp
  src/KghHash.cpp
  src/MatchStore.cpp
  src/Md5.cpp
  src/PeImage.cpp
  src/PrimeTable.cpp
  src/Provenance.cpp
  src/Sha256.cpp
  src/Synth.cpp
  src/ThreadPool.cpp)

target_include_directories(dsigmatcher_core PUBLIC include)
target_link_libraries(dsigmatcher_core PUBLIC ${DSIG_SQLITE_TARGET} Threads::Threads Zydis)
target_compile_definitions(dsigmatcher_core PUBLIC DSIG_VERSION="${PROJECT_VERSION}")
dsig_apply_warnings(dsigmatcher_core)

# ---------------------------------------------------------------------------------------------
# Parity engine (docs/parity/00-plan.md §3). Every source is listed explicitly (no globs).
add_library(dsigmatcher_diff STATIC
  src/diff/Database.cpp
  src/diff/FileIo.cpp
  src/diff/Ingest.cpp
  src/diff/SideTables.cpp
  src/diff/Json.cpp
  src/diff/Registry.cpp
  src/diff/Snapshot.cpp
  src/diff/Trace.cpp
  src/diff/Pipeline.cpp
  src/diff/MatchState.cpp
  src/diff/Consumer.cpp
  src/diff/FinalPass.cpp
  src/diff/Unmatched.cpp
  src/diff/Ratio.cpp
  src/diff/PyValue.cpp
  src/diff/TextDiff.cpp
  src/diff/ResultsWriter.cpp
  src/diff/stages/Preflight.cpp
  src/diff/stages/EqualMatches.cpp
  src/diff/stages/DirtyHeuristics.cpp
  src/diff/stages/SameName.cpp
  src/diff/stages/RemainingFunctions.cpp
  src/diff/stages/PatchDiffHook.cpp
  src/diff/stages/HeuristicTiers.cpp
  src/diff/stages/SmallDifferences.cpp
  src/diff/stages/CalleeDiffing.cpp
  src/diff/stages/RelatedConstants.cpp
  src/diff/stages/RelatedCompilationUnit.cpp
  src/diff/stages/LocalAffinity.cpp)
target_include_directories(dsigmatcher_diff PUBLIC include PRIVATE src/diff)
target_link_libraries(dsigmatcher_diff PUBLIC dsigmatcher_core ${DSIG_SQLITE_TARGET})
dsig_apply_warnings(dsigmatcher_diff)

# Floating point must follow Python's evaluation exactly (plan §3.12, 03a Hard parts 2): no
# contraction into FMA, no fast-math, no /arch:AVX2 or -march=native on this library.
function(dsig_apply_fp Target)
  if(MSVC)
    target_compile_options(${Target} PRIVATE /fp:precise)
  else()
    target_compile_options(${Target} PRIVATE -ffp-contract=off -fno-fast-math)
  endif()
endfunction()
dsig_apply_fp(dsigmatcher_diff)

# Product commands around the engine (plan §7.2): extract / ingest (L10), port --results (L11).
add_library(dsigmatcher_cli STATIC
  src/cli/ExportBridge.cpp
  src/cli/PortResults.cpp)
target_link_libraries(dsigmatcher_cli PUBLIC dsigmatcher_diff dsigmatcher_core)
dsig_apply_warnings(dsigmatcher_cli)
dsig_apply_fp(dsigmatcher_cli)

add_executable(dsigmatcher src/main.cpp)
target_link_libraries(dsigmatcher PRIVATE dsigmatcher_cli dsigmatcher_diff dsigmatcher_core)
dsig_apply_warnings(dsigmatcher)
if(WIN32)
  # main.cpp reads the wide command line (wmain on MSVC, CommandLineToArgvW elsewhere) and passes UTF-8
  # on; the manifest makes the process ANSI code page UTF-8 for code that still uses narrow file APIs.
  target_link_libraries(dsigmatcher PRIVATE shell32)
  if(MSVC)
    target_sources(dsigmatcher PRIVATE src/dsigmatcher.manifest)
  endif()
endif()

# System SQLite only (DSIG_VENDORED_SQLITE=OFF; the bundled one is linked statically): stage the
# sqlite3.dll that sits next to the linked import library beside the executables, so manual runs load the
# same SQLite the tests use (plan §3.4; 07 §11.2). Windows only.
set(DSIG_SQLITE_DLL "")
if(WIN32 AND NOT DSIG_VENDORED_SQLITE)
  set(_dsig_sqlite_lib "${SQLite3_LIBRARY}")
  if(NOT _dsig_sqlite_lib)
    get_target_property(_dsig_sqlite_lib SQLite::SQLite3 IMPORTED_LOCATION)
  endif()
  if(_dsig_sqlite_lib)
    get_filename_component(_dsig_sqlite_dir "${_dsig_sqlite_lib}" DIRECTORY)
    foreach(_dsig_candidate "${_dsig_sqlite_dir}/../bin/sqlite3.dll" "${_dsig_sqlite_dir}/sqlite3.dll")
      if(NOT DSIG_SQLITE_DLL AND EXISTS "${_dsig_candidate}")
        get_filename_component(DSIG_SQLITE_DLL "${_dsig_candidate}" ABSOLUTE)
      endif()
    endforeach()
  endif()
  if(DSIG_SQLITE_DLL)
    add_custom_command(TARGET dsigmatcher POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different "${DSIG_SQLITE_DLL}" "$<TARGET_FILE_DIR:dsigmatcher>"
      VERBATIM)
  endif()
endif()

# The export bridge's script (plan §7.1 D7). src/cli/ExportBridge.cpp FindExportScript looks for it
# beside the executable, then in <prefix>/share/dsigmatcher/tools/export/, then in tools/export/ of an
# ancestor directory; the last only works for a build directory inside the source tree. So the script
# is copied next to the built executable (any build directory works), and installed with it. Editing
# the script re-runs the copy: it is a link dependency of the executable (Makefile and Ninja
# generators; other generators copy it whenever the executable is rebuilt).
set(DSIG_EXPORT_SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/tools/export/dsig_export.py")
add_custom_command(TARGET dsigmatcher POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_if_different "${DSIG_EXPORT_SCRIPT}" "$<TARGET_FILE_DIR:dsigmatcher>"
  VERBATIM)
set_property(TARGET dsigmatcher APPEND PROPERTY LINK_DEPENDS "${DSIG_EXPORT_SCRIPT}")

# `cmake --install <build> --prefix <prefix> [--component dsigmatcher]`: <prefix>/bin/dsigmatcher and
# <prefix>/share/dsigmatcher/tools/export/dsig_export.py, the two places FindExportScript pairs
# (literal paths, not GNUInstallDirs variables, because the bridge searches exactly these). On Windows
# the staged sqlite3.dll (system SQLite only) goes beside the executable as well.
install(TARGETS dsigmatcher RUNTIME DESTINATION bin COMPONENT dsigmatcher)
install(FILES "${DSIG_EXPORT_SCRIPT}" DESTINATION share/dsigmatcher/tools/export COMPONENT dsigmatcher)
if(WIN32 AND DSIG_SQLITE_DLL)
  install(FILES "${DSIG_SQLITE_DLL}" DESTINATION bin COMPONENT dsigmatcher)
endif()

enable_testing()

add_executable(dsigmatcher_tests tests/dsigmatcher_tests.cpp)
target_link_libraries(dsigmatcher_tests PRIVATE dsigmatcher_core)
dsig_apply_warnings(dsigmatcher_tests)
add_test(NAME unit COMMAND dsigmatcher_tests)

# Prints the linked SQLite's version, source id and compile options into the test log; with the bundled
# SQLite it also checks them against the parity oracle's (tests/sqlite_info.cpp).
add_executable(dsig_sqlite_info tests/sqlite_info.cpp)
target_link_libraries(dsig_sqlite_info PRIVATE ${DSIG_SQLITE_TARGET})
if(DSIG_VENDORED_SQLITE)
  target_compile_definitions(dsig_sqlite_info PRIVATE DSIG_VENDORED_SQLITE=1)
endif()
dsig_apply_warnings(dsig_sqlite_info)
add_test(NAME sqlite_info COMMAND dsig_sqlite_info)

add_executable(dsigmatcher_bench bench/dsigmatcher_bench.cpp)
target_link_libraries(dsigmatcher_bench PRIVATE dsigmatcher_core)
dsig_apply_warnings(dsigmatcher_bench)

add_executable(dsigmatcher_disasm_tests tests/disassembler_tests.cpp)
target_link_libraries(dsigmatcher_disasm_tests PRIVATE dsigmatcher_core)
dsig_apply_warnings(dsigmatcher_disasm_tests)
add_test(NAME disassembler COMMAND dsigmatcher_disasm_tests)

add_executable(dsigmatcher_pe_tests tests/peimage_tests.cpp)
target_link_libraries(dsigmatcher_pe_tests PRIVATE dsigmatcher_core)
dsig_apply_warnings(dsigmatcher_pe_tests)
add_test(NAME peimage COMMAND dsigmatcher_pe_tests)

set(DSIG_CORPUS_ROOT "" CACHE PATH
    "Directory holding the win32u test corpus; real-binary PE tests skip when it is absent")
if(DSIG_CORPUS_ROOT)
  target_compile_definitions(dsigmatcher_pe_tests PRIVATE
    DSIG_CORPUS_ROOT="${DSIG_CORPUS_ROOT}")
endif()

add_executable(dsigmatcher_resolve_tests tests/resolve_tests.cpp)
target_link_libraries(dsigmatcher_resolve_tests PRIVATE dsigmatcher_core)
dsig_apply_warnings(dsigmatcher_resolve_tests)
add_test(NAME resolve COMMAND dsigmatcher_resolve_tests)

add_executable(dsigmatcher_cfg_tests tests/cfg_tests.cpp)
target_link_libraries(dsigmatcher_cfg_tests PRIVATE dsigmatcher_core)
dsig_apply_warnings(dsigmatcher_cfg_tests)
add_test(NAME controlflowgraph COMMAND dsigmatcher_cfg_tests)
if(DSIG_CORPUS_ROOT)
  target_compile_definitions(dsigmatcher_cfg_tests PRIVATE
    DSIG_CORPUS_ROOT="${DSIG_CORPUS_ROOT}")
endif()

# ---------------------------------------------------------------------------------------------
# Parity suites (plan §2.6, §3.12). Corpus- and SQLite-3.51.1-dependent tests skip without them.
function(dsig_add_suite Name Source)
  add_executable(${Name} ${Source})
  target_link_libraries(${Name} PRIVATE dsigmatcher_cli dsigmatcher_diff dsigmatcher_core)
  target_include_directories(${Name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)
  target_compile_definitions(${Name} PRIVATE DSIG_TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/diff")
  if(DSIG_CORPUS_ROOT)
    target_compile_definitions(${Name} PRIVATE DSIG_CORPUS_ROOT="${DSIG_CORPUS_ROOT}")
  endif()
  dsig_apply_warnings(${Name})
  dsig_apply_fp(${Name})
  add_test(NAME ${Name} COMMAND ${Name})
endfunction()

dsig_add_suite(diff_foundation tests/diff/foundation_tests.cpp)
# The foundation suite also runs the CLI binary itself (Unicode command-line arguments on Windows) and
# reads oracle captures through the engine's UTF-8 file helpers (src/diff/FileIo.h).
target_compile_definitions(diff_foundation PRIVATE DSIG_CLI_PATH="$<TARGET_FILE:dsigmatcher>")
target_include_directories(diff_foundation PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/diff)
add_dependencies(diff_foundation dsigmatcher)
dsig_add_suite(diff_state tests/diff/state_tests.cpp)
dsig_add_suite(diff_ratio tests/diff/ratio_tests.cpp)
dsig_add_suite(diff_textdiff tests/diff/textdiff_tests.cpp)
dsig_add_suite(diff_writer tests/diff/writer_tests.cpp)
dsig_add_suite(diff_early tests/diff/early_passes_tests.cpp)
dsig_add_suite(diff_tiers tests/diff/tiers_tests.cpp)
dsig_add_suite(diff_callee tests/diff/callee_tests.cpp)
dsig_add_suite(diff_related tests/diff/related_tests.cpp)
dsig_add_suite(diff_parity tests/diff/parity_tests.cpp)
dsig_add_suite(cli_export_bridge tests/cli/export_bridge_tests.cpp)
dsig_add_suite(cli_port_results tests/cli/port_results_tests.cpp)

# Install layout and export-script discovery away from the source tree (lane F1): installs into a
# fresh prefix under the system temp directory and runs the installed executable. No Python and no
# IDA are needed: the run stops at tool discovery, which reports every missing tool at once.
add_test(NAME cli_install_layout
  COMMAND ${CMAKE_COMMAND}
    -DBUILD_DIR=${CMAKE_BINARY_DIR}
    -DSOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
    -DCONFIG=$<CONFIG>
    -DEXE_NAME=$<TARGET_FILE_NAME:dsigmatcher>
    -DBUILT_EXE=$<TARGET_FILE:dsigmatcher>
    -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/cli/install_layout_test.cmake)
