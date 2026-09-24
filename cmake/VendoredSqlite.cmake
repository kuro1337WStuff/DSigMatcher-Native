# Bundled SQLite (DSIG_VENDORED_SQLITE=ON, the default): the official SQLite 3.51.1 amalgamation, built
# as the static library `dsig_sqlite3` with the parity oracle's compile options.
#
# Why: Diaphora's results depend on the row order SQLite's query planner produces (docs/parity/02-matching.md
# §18.3). The oracle ran on conda's sqlite 3.51.1 (package sqlite-3.51.1-hda9a48d_0), whose recipe
# compiles the same sqlite3.c (sqlite-autoconf-3510100, byte-identical to the amalgamation below) with
# only these defines:
#   SQLITE_ENABLE_RTREE SQLITE_ENABLE_GEOPOLY SQLITE_ENABLE_COLUMN_METADATA=1
#   SQLITE_MAX_VARIABLE_NUMBER=250000 SQLITE_ENABLE_JSON1 SQLITE_ENABLE_FTS5
# (SQLITE_ENABLE_JSON1 has been a no-op since 3.38: JSON is built in.) Every other entry of the oracle's
# `pragma compile_options` is a library default (DEFAULT_WORKER_THREADS=0, TEMP_STORE=1,
# DEFAULT_CACHE_SIZE=-2000, DEFAULT_PAGE_SIZE=4096, MAX_* limits, THREADSAFE=1, SYSTEM_MALLOC, ...), so
# the same defines reproduce the oracle's options exactly; tests/sqlite_info.cpp checks the full list on
# every platform. Linking statically also means no sqlite3.dll has to be found at run time.
#
# The download is pinned by the zip's SHA3-256, and the extracted sqlite3.c is checked against the
# SHA3-256 that sqlite.org publishes in the 3.51.1 release log (https://sqlite.org/releaselog/3_51_1.html).
# The content check also covers FETCHCONTENT_SOURCE_DIR_SQLITE3 (a pre-populated offline copy: a
# directory holding sqlite3.c and sqlite3.h).

set(DSIG_SQLITE_VERSION "3.51.1")
set(DSIG_SQLITE_URL "https://www.sqlite.org/2025/sqlite-amalgamation-3510100.zip")
set(DSIG_SQLITE_ZIP_SHA3_256 "856b52ffe7383d779bb86a0ed1ddc19c41b0e5751fa14ce6312f27534e629b64")
set(DSIG_SQLITE_C_SHA3_256 "7cec3a104797bea93970408168197af37f178ab608ea55efd48d28daa87a8ce3")
set(DSIG_SQLITE_H_SHA3_256 "997d63fe12f7719480136336ff6bd2e5338127a370b3590d98c3d239f9bd1246")

# Offline configures (FETCHCONTENT_FULLY_DISCONNECTED=ON) need the sources on disk. When
# FETCHCONTENT_SOURCE_DIR_SQLITE3 is not given, a `sqlite3-src` directory beside a pre-populated Zydis
# source directory is used, so build directories configured before SQLite was bundled keep working.
if(FETCHCONTENT_FULLY_DISCONNECTED AND NOT FETCHCONTENT_SOURCE_DIR_SQLITE3
   AND NOT EXISTS "${FETCHCONTENT_BASE_DIR}/sqlite3-src/sqlite3.c")
  set(_dsig_sqlite_sibling "")
  if(FETCHCONTENT_SOURCE_DIR_ZYDIS)
    get_filename_component(_dsig_sqlite_sibling "${FETCHCONTENT_SOURCE_DIR_ZYDIS}/../sqlite3-src" ABSOLUTE)
  endif()
  if(_dsig_sqlite_sibling AND EXISTS "${_dsig_sqlite_sibling}/sqlite3.c")
    message(STATUS "Bundled SQLite: offline, using ${_dsig_sqlite_sibling}")
    set(FETCHCONTENT_SOURCE_DIR_SQLITE3 "${_dsig_sqlite_sibling}" CACHE PATH
        "Pre-populated SQLite ${DSIG_SQLITE_VERSION} amalgamation (sqlite3.c, sqlite3.h)")
  else()
    message(FATAL_ERROR
      "DSIG_VENDORED_SQLITE is ON and FETCHCONTENT_FULLY_DISCONNECTED is ON, but the SQLite "
      "${DSIG_SQLITE_VERSION} amalgamation is not on disk. Unpack ${DSIG_SQLITE_URL} into a directory and "
      "pass -DFETCHCONTENT_SOURCE_DIR_SQLITE3=<dir>, or configure with -DDSIG_VENDORED_SQLITE=OFF to use "
      "the system SQLite.")
  endif()
endif()

if(POLICY CMP0135)
  cmake_policy(SET CMP0135 NEW)  # extracted files get the extraction time: rebuild after a re-download
endif()
FetchContent_Declare(sqlite3
  URL "${DSIG_SQLITE_URL}"
  URL_HASH SHA3_256=${DSIG_SQLITE_ZIP_SHA3_256})
FetchContent_MakeAvailable(sqlite3)

foreach(_dsig_file IN ITEMS sqlite3.c sqlite3.h)
  if(_dsig_file STREQUAL "sqlite3.c")
    set(_dsig_expected "${DSIG_SQLITE_C_SHA3_256}")
  else()
    set(_dsig_expected "${DSIG_SQLITE_H_SHA3_256}")
  endif()
  if(NOT EXISTS "${sqlite3_SOURCE_DIR}/${_dsig_file}")
    message(FATAL_ERROR "Bundled SQLite: ${sqlite3_SOURCE_DIR}/${_dsig_file} is missing")
  endif()
  file(SHA3_256 "${sqlite3_SOURCE_DIR}/${_dsig_file}" _dsig_actual)
  if(NOT _dsig_actual STREQUAL _dsig_expected)
    message(FATAL_ERROR "Bundled SQLite: ${sqlite3_SOURCE_DIR}/${_dsig_file} has SHA3-256 ${_dsig_actual}, "
                        "expected ${_dsig_expected} (SQLite ${DSIG_SQLITE_VERSION})")
  endif()
endforeach()

add_library(dsig_sqlite3 STATIC "${sqlite3_SOURCE_DIR}/sqlite3.c")
# SYSTEM: warnings from sqlite3.h never count against our zero-warning policy.
target_include_directories(dsig_sqlite3 SYSTEM PUBLIC "${sqlite3_SOURCE_DIR}")
# The oracle's defines, verbatim from the conda recipe (see above). THREADSAFE=1 with the platform mutex
# (MUTEX_W32 / MUTEX_PTHREADS) is the default; it is spelled out because the engine relies on it.
target_compile_definitions(dsig_sqlite3 PRIVATE
  SQLITE_ENABLE_RTREE
  SQLITE_ENABLE_GEOPOLY
  SQLITE_ENABLE_COLUMN_METADATA=1
  SQLITE_MAX_VARIABLE_NUMBER=250000
  SQLITE_ENABLE_FTS5
  SQLITE_THREADSAFE=1)
if(MSVC)
  # /w: the amalgamation is third-party code. /fp:precise: SQLite's text-to-real conversion uses
  # Dekker double-double arithmetic, which must not be contracted into FMA (md_index casts, 03a §6.4).
  target_compile_options(dsig_sqlite3 PRIVATE /w /fp:precise)
else()
  target_compile_options(dsig_sqlite3 PRIVATE -w -ffp-contract=off -fno-fast-math)
endif()
set_target_properties(dsig_sqlite3 PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_link_libraries(dsig_sqlite3 PUBLIC Threads::Threads ${CMAKE_DL_LIBS})
if(UNIX AND NOT APPLE)
  target_link_libraries(dsig_sqlite3 PUBLIC m)
endif()
