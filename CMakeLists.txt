cmake_minimum_required(VERSION 3.20)

project(DSigMatcherNative
  VERSION 0.1.0
  DESCRIPTION "Native C++ binary diffing engine"
  LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

find_package(SQLite3 REQUIRED)
find_package(Threads REQUIRED)

add_library(dsigmatcher_core STATIC
  src/ExportDatabase.cpp
  src/Heuristics.cpp
  src/MatchStore.cpp
  src/Provenance.cpp
  src/Sha256.cpp)

target_include_directories(dsigmatcher_core PUBLIC include)
target_link_libraries(dsigmatcher_core PUBLIC SQLite::SQLite3 Threads::Threads)
target_compile_definitions(dsigmatcher_core PUBLIC DSIG_VERSION="${PROJECT_VERSION}")

if(MSVC)
  target_compile_options(dsigmatcher_core PRIVATE /W4 /permissive- /utf-8 /Zc:__cplusplus)
else()
  target_compile_options(dsigmatcher_core PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_executable(dsigmatcher src/main.cpp)
target_link_libraries(dsigmatcher PRIVATE dsigmatcher_core)

if(MSVC)
  target_compile_options(dsigmatcher PRIVATE /W4 /permissive- /utf-8 /Zc:__cplusplus)
else()
  target_compile_options(dsigmatcher PRIVATE -Wall -Wextra -Wpedantic)
endif()
