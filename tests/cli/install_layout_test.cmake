# cli_install_layout (lane F1): the export script beside the built executable, the install layout (the
# executable, the export script, and LICENSE, NOTICE, THIRD_PARTY_NOTICES.md and README.md in
# share/doc/dsigmatcher), and export-script discovery by an installed executable that lives outside the
# source tree.
#
#   cmake -DBUILD_DIR=<build> -DSOURCE_DIR=<source> -DCONFIG=<config> -DEXE_NAME=<dsigmatcher[.exe]>
#         -DBUILT_EXE=<build>/.../dsigmatcher[.exe] [-DCONFIGURE_CMAKE_VERSION=<x.y.z>]
#         -P tests/cli/install_layout_test.cmake
#
# src/cli/ExportBridge.cpp FindExportScript searches <exe dir>/dsig_export.py, then
# <exe dir>/../share/dsigmatcher/tools/export/dsig_export.py, then tools/export/ in the executable's
# directory and its ancestors (only a build directory inside the source tree has one). The installed
# executable is run as `extract <placeholder.i64> -o <out> --python <missing> --diaphora-dir <missing>`:
# the bridge checks every tool before it starts anything and names all missing ones in one message
# (exit 4), so the message shows whether the script was found without running Python or IDA.
cmake_minimum_required(VERSION 3.20)

set(Checks 0)
function(Fail Message)
  message(FATAL_ERROR "cli_install_layout: FAIL ${Message}")
endfunction()
macro(Pass)
  math(EXPR Checks "${Checks} + 1")
endmacro()

foreach(Var BUILD_DIR SOURCE_DIR EXE_NAME BUILT_EXE)
  if(NOT DEFINED ${Var} OR "${${Var}}" STREQUAL "")
    Fail("${Var} is not set")
  endif()
endforeach()
# The discovery under test must not be short-circuited by the environment.
unset(ENV{DSIG_EXPORT_SCRIPT})

# 1. the post-build copy: dsig_export.py beside the built executable, identical to the source
set(Script "${SOURCE_DIR}/tools/export/dsig_export.py")
get_filename_component(BuiltDir "${BUILT_EXE}" DIRECTORY)
if(NOT EXISTS "${BuiltDir}/dsig_export.py")
  Fail("no dsig_export.py beside ${BUILT_EXE}")
endif()
file(SHA256 "${Script}" ScriptSha)
file(SHA256 "${BuiltDir}/dsig_export.py" CopySha)
if(NOT ScriptSha STREQUAL CopySha)
  Fail("${BuiltDir}/dsig_export.py differs from ${Script}")
endif()
Pass()

# 2. install the dsigmatcher component into a fresh prefix under the system temp directory
set(Temp "")
foreach(Name TMPDIR TEMP TMP)
  if(Temp STREQUAL "" AND DEFINED ENV{${Name}} AND IS_DIRECTORY "$ENV{${Name}}")
    set(Temp "$ENV{${Name}}")
  endif()
endforeach()
if(Temp STREQUAL "")
  set(Temp "/tmp")
endif()
file(TO_CMAKE_PATH "${Temp}" Temp)
string(RANDOM LENGTH 10 ALPHABET abcdefghijklmnopqrstuvwxyz0123456789 Tag)
set(Prefix "${Temp}/dsig-install-test-${Tag}")
cmake_path(IS_PREFIX SOURCE_DIR "${Prefix}" NORMALIZE PrefixInSource)
if(PrefixInSource)
  message(STATUS "cli_install_layout: SKIPPED: the temp directory ${Temp} is inside the source tree")
  return()
endif()
file(REMOVE_RECURSE "${Prefix}")
set(ConfigArgs "")
if(DEFINED CONFIG AND NOT CONFIG STREQUAL "")
  set(ConfigArgs --config "${CONFIG}")
endif()
execute_process(
  COMMAND "${CMAKE_COMMAND}" --install "${BUILD_DIR}" --prefix "${Prefix}" --component dsigmatcher ${ConfigArgs}
  RESULT_VARIABLE Code OUTPUT_VARIABLE Out ERROR_VARIABLE Err)
if(NOT Code EQUAL 0)
  Fail("cmake --install exited ${Code}: ${Out}${Err}")
endif()
set(InstalledExe "${Prefix}/bin/${EXE_NAME}")
set(InstalledScript "${Prefix}/share/dsigmatcher/tools/export/dsig_export.py")
foreach(File "${InstalledExe}" "${InstalledScript}")
  if(NOT EXISTS "${File}")
    Fail("the install has no ${File}")
  endif()
  Pass()
endforeach()
file(SHA256 "${InstalledScript}" InstalledSha)
if(NOT InstalledSha STREQUAL ScriptSha)
  Fail("the installed dsig_export.py differs from the source")
endif()
Pass()
foreach(Other include lib)
  if(EXISTS "${Prefix}/${Other}")
    Fail("the dsigmatcher component installed ${Prefix}/${Other} (third-party files belong to dsig_third_party)")
  endif()
endforeach()
Pass()
# 2a. the licence, the notices and the README travel with the tool: <prefix>/share/doc/dsigmatcher holds
#     byte copies of the source tree's, and nothing else
set(DocNames LICENSE NOTICE THIRD_PARTY_NOTICES.md README.md)
function(CheckDocs DocDir)
  foreach(Doc IN LISTS DocNames)
    if(NOT EXISTS "${DocDir}/${Doc}")
      Fail("the install has no ${DocDir}/${Doc}")
    endif()
    file(SHA256 "${SOURCE_DIR}/${Doc}" SourceSha)
    file(SHA256 "${DocDir}/${Doc}" InstalledDocSha)
    if(NOT SourceSha STREQUAL InstalledDocSha)
      Fail("the installed ${DocDir}/${Doc} differs from ${SOURCE_DIR}/${Doc}")
    endif()
  endforeach()
  file(GLOB Installed RELATIVE "${DocDir}" "${DocDir}/*")
  list(SORT Installed)
  set(Expected ${DocNames})
  list(SORT Expected)
  if(NOT Installed STREQUAL Expected)
    Fail("${DocDir} holds '${Installed}', want exactly '${Expected}'")
  endif()
endfunction()
CheckDocs("${Prefix}/share/doc/dsigmatcher")
Pass()
# 2b. CMake 3.28+ adds Zydis and Zycore EXCLUDE_FROM_ALL (no install rules), so a plain install without
#     --component installs the same clean layout
if(DEFINED CONFIGURE_CMAKE_VERSION AND CONFIGURE_CMAKE_VERSION VERSION_GREATER_EQUAL 3.28)
  set(PlainPrefix "${Prefix}-plain")
  file(REMOVE_RECURSE "${PlainPrefix}")
  execute_process(
    COMMAND "${CMAKE_COMMAND}" --install "${BUILD_DIR}" --prefix "${PlainPrefix}" ${ConfigArgs}
    RESULT_VARIABLE Code OUTPUT_VARIABLE Out ERROR_VARIABLE Err)
  if(NOT Code EQUAL 0)
    Fail("plain cmake --install exited ${Code}: ${Out}${Err}")
  endif()
  if(NOT EXISTS "${PlainPrefix}/bin/${EXE_NAME}")
    Fail("the plain install has no bin/${EXE_NAME}")
  endif()
  CheckDocs("${PlainPrefix}/share/doc/dsigmatcher")
  foreach(Other include lib)
    if(EXISTS "${PlainPrefix}/${Other}")
      Fail("the plain install created ${PlainPrefix}/${Other} (third-party development files)")
    endif()
  endforeach()
  file(REMOVE_RECURSE "${PlainPrefix}")
  Pass()
endif()

if(WIN32 AND NOT EXISTS "${Prefix}/bin/sqlite3.dll")
  # Without a sqlite3.dll found next to the import library at configure time (CI stages vcpkg's DLL in
  # its workflow instead), the one beside the built executable is used so the installed copy can start.
  if(EXISTS "${BuiltDir}/sqlite3.dll")
    file(COPY "${BuiltDir}/sqlite3.dll" DESTINATION "${Prefix}/bin")
    message(STATUS "cli_install_layout: sqlite3.dll staged from the build directory (not installed)")
  endif()
endif()

# 3. the installed executable finds <prefix>/share/dsigmatcher/tools/export/dsig_export.py
function(RunExtract Exe WorkDir OutVar)
  file(MAKE_DIRECTORY "${WorkDir}")
  file(WRITE "${WorkDir}/placeholder.i64" "IDA2 placeholder, never opened")
  execute_process(
    COMMAND "${Exe}" extract "${WorkDir}/placeholder.i64" -o "${WorkDir}/out.sqlite"
            --python "${WorkDir}/no-such-python" --diaphora-dir "${WorkDir}/no-such-diaphora"
    WORKING_DIRECTORY "${WorkDir}"
    RESULT_VARIABLE Code OUTPUT_VARIABLE Out ERROR_VARIABLE Err)
  if(NOT Code EQUAL 4)
    Fail("${Exe} extract exited '${Code}', want 4 (tools missing): ${Out}${Err}")
  endif()
  if(NOT Err MATCHES "Diaphora not found" OR NOT Err MATCHES "Python not found")
    Fail("${Exe} extract did not report the missing tools: ${Err}")
  endif()
  if(EXISTS "${WorkDir}/out.sqlite")
    Fail("${Exe} extract wrote an output although tools were missing")
  endif()
  set(${OutVar} "${Err}" PARENT_SCOPE)
endfunction()

RunExtract("${InstalledExe}" "${Prefix}/work" Message)
if(Message MATCHES "export script not found")
  Fail("the installed executable did not find ${InstalledScript}: ${Message}")
endif()
Pass()

# 4. control: the same executable alone (no script beside it, no share/ above it) does not find one,
#    unless some ancestor of the temp directory happens to hold tools/export/dsig_export.py
set(Alone "${Prefix}/alone/bin")
file(COPY "${InstalledExe}" DESTINATION "${Alone}")
if(EXISTS "${Prefix}/bin/sqlite3.dll")
  file(COPY "${Prefix}/bin/sqlite3.dll" DESTINATION "${Alone}")
endif()
set(Ancestor "${Alone}")
set(AncestorHasScript FALSE)
foreach(Level RANGE 8)
  if(EXISTS "${Ancestor}/tools/export/dsig_export.py")
    set(AncestorHasScript TRUE)
  endif()
  get_filename_component(Parent "${Ancestor}" DIRECTORY)
  if(Parent STREQUAL Ancestor OR Parent STREQUAL "")
    break()
  endif()
  set(Ancestor "${Parent}")
endforeach()
if(AncestorHasScript)
  message(STATUS "cli_install_layout: control skipped: an ancestor of ${Alone} holds tools/export/dsig_export.py")
else()
  RunExtract("${Alone}/${EXE_NAME}" "${Prefix}/alone/work" ControlMessage)
  if(NOT ControlMessage MATCHES "export script not found")
    Fail("the executable without a script beside it still found one: ${ControlMessage}")
  endif()
  Pass()
endif()

file(REMOVE_RECURSE "${Prefix}")
message(STATUS "cli_install_layout: ${Checks} checks passed (prefix ${Prefix}, removed)")
