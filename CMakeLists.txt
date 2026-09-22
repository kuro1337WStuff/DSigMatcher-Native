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

find_package(SQLite3 REQUIRED)
find_package(Threads REQUIRED)

include(FetchContent)

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

FetchContent_MakeAvailable(zycore)
set(ZYAN_ZYCORE_PATH "${zycore_SOURCE_DIR}" CACHE PATH "" FORCE)
FetchContent_MakeAvailable(zydis)

function(dsig_apply_warnings Target)
  if(MSVC)
    target_compile_options(${Target} PRIVATE /W4 /permissive- /utf-8 /Zc:__cplusplus)
  else()
    target_compile_options(${Target} PRIVATE -Wall -Wextra -Wpedantic)
  endif()
endfunction()

add_library(dsigmatcher_core STATIC
  src/DisassemblerZydis.cpp
  src/ExportDatabase.cpp
  src/Heuristics.cpp
  src/MatchStore.cpp
  src/PeImage.cpp
  src/Provenance.cpp
  src/Sha256.cpp
  src/Synth.cpp
  src/ThreadPool.cpp)

target_include_directories(dsigmatcher_core PUBLIC include)
target_link_libraries(dsigmatcher_core PUBLIC SQLite::SQLite3 Threads::Threads Zydis)
target_compile_definitions(dsigmatcher_core PUBLIC DSIG_VERSION="${PROJECT_VERSION}")
dsig_apply_warnings(dsigmatcher_core)

add_executable(dsigmatcher src/main.cpp)
target_link_libraries(dsigmatcher PRIVATE dsigmatcher_core)
dsig_apply_warnings(dsigmatcher)

enable_testing()

add_executable(dsigmatcher_tests tests/dsigmatcher_tests.cpp)
target_link_libraries(dsigmatcher_tests PRIVATE dsigmatcher_core)
dsig_apply_warnings(dsigmatcher_tests)
add_test(NAME unit COMMAND dsigmatcher_tests)

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

add_executable(dsigmatcher_resolve_tests tests/resolve_tests.cpp)
target_link_libraries(dsigmatcher_resolve_tests PRIVATE dsigmatcher_core)
dsig_apply_warnings(dsigmatcher_resolve_tests)
add_test(NAME resolve COMMAND dsigmatcher_resolve_tests)
