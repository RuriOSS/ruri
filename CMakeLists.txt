cmake_minimum_required(VERSION 3.18)

# Must be set before project() so CMake picks up the launcher during compiler init
find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
    set(CMAKE_C_COMPILER_LAUNCHER "${CCACHE_PROGRAM}")
    message(STATUS "Using ccache: ${CCACHE_PROGRAM}")
else()
    message(STATUS "Ccache not found. Compiling without cache.")
endif()

project(ruri LANGUAGES C VERSION 3.9.3)
# Avoid Pollution Reserve Config 'CMAKE_'

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT CMAKE_SYSTEM_NAME STREQUAL "Android")
    message(FATAL_ERROR "ruri is only supported on Linux platforms.")
endif()

file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/src/*.c")
add_executable(ruri ${SOURCES})

# Generate version header from CMake project version (single source of truth).
# Update the version by changing project(VERSION ...) above.
configure_file(
    "${CMAKE_SOURCE_DIR}/src/include/version.h.in"
    "${CMAKE_BINARY_DIR}/src/include/version.h"
    @ONLY
)
target_include_directories(ruri PRIVATE "${CMAKE_BINARY_DIR}/src/include")

option(ENABLE_STATIC "Enable static linking" OFF)
option(DISABLE_LIBCAP "Disable cap library linking" OFF)
option(DISABLE_LIBSECCOMP "Disable seccomp library linking" OFF)
option(DISABLE_RURIENV "Disable env in ruri" OFF)
option(DISABLE_SYSTEMD "Disable systemd support" OFF)

get_property(_isMultiConfig GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
if(NOT _isMultiConfig)
    if(NOT CMAKE_BUILD_TYPE OR CMAKE_BUILD_TYPE STREQUAL "")
        set(CMAKE_BUILD_TYPE "Release" CACHE STRING
            "Build type: Debug, Release, RelWithDebInfo, MinSizeRel" FORCE)
        message(STATUS "CMAKE_BUILD_TYPE not set, defaulting to Release")
    endif()
endif()

# Warn as early as possible so the message is prominent in configure output.
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    message(WARNING "DEBUG mode is enabled: debug symbols will be preserved.")
endif()

include(CMakeDependentOption)
if(_isMultiConfig)
    option(STRIP_DEBUGINFO "Strip debuginfo from ruri binary" ON)
else()
    # Stripping is enabled by default only in Release/MinSizeRel
    # RelWithDebInfo includes -g, stripping would defeat its purpose
    cmake_dependent_option(
        STRIP_DEBUGINFO "Strip debuginfo from ruri binary" ON
        "CMAKE_BUILD_TYPE STREQUAL Release OR CMAKE_BUILD_TYPE STREQUAL MinSizeRel"
        OFF
    )
endif()
unset(_isMultiConfig)


# Gcc/Clang/Tcc already provide __DATE__ and __TIME__ builtins used directly in src/info.c.
# string(TIMESTAMP CURRENT_BUILD_DATE "%Y-%m-%d")
# string(TIMESTAMP CURRENT_BUILD_TIME "%H:%M:%S")

find_program(GIT_EXECUTABLE git)
if(GIT_EXECUTABLE)
    execute_process(
        COMMAND ${GIT_EXECUTABLE} rev-parse --short=8 HEAD
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_COMMIT_ID
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
        RESULT_VARIABLE GIT_RESULT
        TIMEOUT 5
    )
    if(NOT GIT_RESULT EQUAL 0 OR NOT GIT_COMMIT_ID)
        message(STATUS "not a git repo or no commits; RURI_COMMIT_ID will not be defined")
    endif()
else()
    message(STATUS "git not found; RURI_COMMIT_ID will not be defined")
    set(GIT_RESULT 1)
endif()


# TinyCC special handling
if(CMAKE_C_COMPILER_ID STREQUAL "TinyCC")
    # TCC already includes distro-specific multiarch paths (e.g. /usr/lib/x86_64-linux-gnu)
    # in its built-in search dirs (`tcc -print-search-dirs`), so no hardcoded paths are needed
    # Note: If not in the search path, use CMake standard variables to specify it.
    # -DCMAKE_INCLUDE_PATH=<dir>
    # -DCMAKE_LIBRARY_PATH=<dir>

    # TCC does not predefine __VERSION__ or __TIMESTAMP__
    # __TIMESTAMP__ (gcc/clang) expands to the last modification time of the source file, which TCC cannot provide
    # Using build time as a substitute would be misleading, so "unknown" is used instead
    target_compile_definitions(ruri PRIVATE
        __VERSION__="TinyCC"
        __TIMESTAMP__="Unknown"
    )
endif()


include(CheckIncludeFile)
# pthread.h is intentionally omitted: find_package(Threads REQUIRED) below
# already verifies pthread availability and sets up -pthread compiler/linker
# flags via the Threads::Threads target, making a redundant header check unnecessary.
set(REQUIRED_HEADERS
    time.h
    grp.h
    fcntl.h
    "sys/ioctl.h"
    "sys/mount.h"
    "sys/socket.h"
    "linux/fs.h"
    "linux/version.h"
    "linux/sched.h"
)

# check_include_file uses try_compile with CMAKE_C_FLAGS and CMAKE_REQUIRED_INCLUDES,
# but NOT the project's private compile options (added later via target_compile_options).
# For the standard Linux header files listed here,
# this approach has no practical significance in actual applications.
foreach(hdr IN LISTS REQUIRED_HEADERS)
    string(MAKE_C_IDENTIFIER "HAVE_${hdr}" CHECK_NAME)
    check_include_file("${hdr}" ${CHECK_NAME})
    if(NOT ${CHECK_NAME})
        message(FATAL_ERROR "Missing required header: ${hdr}")
    endif()
endforeach()

# sys/capability.h and seccomp.h are only required when their respective
# libraries are enabled; skip the check when the library is disabled.
# Indirectly checked via find_* commands, no need to add to REQUIRED_HEADERS.
#
# Custom-prefix / sysroot lookup — CMake official variables:
#   -DCMAKE_PREFIX_PATH=<prefix>     find_path searches <prefix>/include
#   -DCMAKE_INCLUDE_PATH=<dir>       append extra dirs for find_path / find_file only
#   -DCMAKE_FIND_ROOT_PATH=<sysroot> cross-compile sysroot; prefixes all find_* paths
# Note: CMAKE_REQUIRED_INCLUDES is for check_include_file() probes only, not find_path().
if(NOT DISABLE_LIBCAP)
    find_path(LIBCAP_INCLUDE_DIR NAMES sys/capability.h REQUIRED)
    target_include_directories(ruri PRIVATE ${LIBCAP_INCLUDE_DIR})
else()
    target_compile_definitions(ruri PRIVATE DISABLE_LIBCAP)
endif()
if(NOT DISABLE_LIBSECCOMP)
    find_path(LIBSECCOMP_INCLUDE_DIR NAMES seccomp.h REQUIRED)
    target_include_directories(ruri PRIVATE ${LIBSECCOMP_INCLUDE_DIR})
else()
    target_compile_definitions(ruri PRIVATE DISABLE_LIBSECCOMP)
endif()


set(CANDIDATE_DEBUG_CFLAGS
    "-Wall"
    "-Wextra"
    "-pedantic"
    "-Wconversion"
    "-Wextra-semi-stmt"
    "-Wstrict-prototypes"
    "-fno-stack-protector"
    "-fno-omit-frame-pointer"
    "-fsanitize=address,undefined"
    "-fno-sanitize-recover=all"
    "-Wno-gnu-zero-variadic-macro-arguments"
)
set(CANDIDATE_RELEASE_CFLAGS
    "-ftrivial-auto-var-init=pattern"
    "-fstack-protector-strong"
    "-fstack-clash-protection"
    "-fcf-protection=full"
    "-Wno-unused-result"
    "-ffunction-sections"
    "-fdata-sections"
    "-pipe"
)

# -mshstk enables Intel CET Shadow Stack and is only meaningful on x86/x86_64.
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|i[3-6]86|AMD64")
    list(APPEND CANDIDATE_RELEASE_CFLAGS "-mshstk")
endif()

if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
    list(APPEND CANDIDATE_RELEASE_CFLAGS "-mbranch-protection=standard")
endif()

# IPO/LTO
include(CheckIPOSupported)
check_ipo_supported(RESULT _ipo_supported OUTPUT _ipo_output LANGUAGES C)
if(_ipo_supported)
    set_target_properties(ruri PROPERTIES
        INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE
        INTERPROCEDURAL_OPTIMIZATION_MINSIZEREL TRUE
        INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO TRUE
        INTERPROCEDURAL_OPTIMIZATION_DEBUG FALSE
    )
else()
    message(STATUS "IPO/LTO not supported: ${_ipo_output}")
endif()

# Test and apply supported flags.
# NOTE: check_c_compiler_flag / check_linker_flag results are cached in
# CMakeCache.txt. If you switch compilers, delete the build directory or
# run cmake --fresh to avoid stale cached results being applied to the
# new compiler.
include(CheckCCompilerFlag)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    foreach(flag IN LISTS CANDIDATE_DEBUG_CFLAGS)
        string(MAKE_C_IDENTIFIER "HAS_DEBUG_FLAG_${flag}" _flag_var)
        check_c_compiler_flag("${flag}" ${_flag_var})
        if(${_flag_var})
            target_compile_options(ruri PRIVATE $<$<CONFIG:Debug>:${flag}>)
        endif()
    endforeach()
else()
    foreach(flag IN LISTS CANDIDATE_RELEASE_CFLAGS)
        string(MAKE_C_IDENTIFIER "HAS_RELEASE_FLAG_${flag}" _flag_var)
        check_c_compiler_flag("${flag}" ${_flag_var})
        if(${_flag_var})
            target_compile_options(ruri PRIVATE
                $<$<CONFIG:Release>:${flag}>
                $<$<CONFIG:RelWithDebInfo>:${flag}>
                $<$<CONFIG:MinSizeRel>:${flag}>
            )
        endif()
    endforeach()
endif()

# Position-independent executable
# CMP0083 (CMake 3.14): NEW behavior makes POSITION_INDEPENDENT_CODE actually emit
# -fPIE for executables and auto-inject -pie at link time.
cmake_policy(SET CMP0083 NEW)
set(_enable_pie OFF)
if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    include(CheckPIESupported)
    check_pie_supported(LANGUAGES C)
    if(CMAKE_C_LINK_PIE_SUPPORTED)
        set(_enable_pie ON)
    endif()
endif()
# POSITION_INDEPENDENT_CODE applies on all platforms,
# But it does not apply to all cases.
# set_target_properties(ruri PROPERTIES POSITION_INDEPENDENT_CODE ${_enable_pie})


# RURI_DEBUG/RURI_DEV built-in macro
target_compile_definitions(ruri PRIVATE $<$<CONFIG:Debug>:RURI_DEBUG>)
# Override -O3 to -O2 in Release (the compiler takes the last -O flag).
# -DNDEBUG is still injected by the default CMAKE_C_FLAGS_RELEASE.
target_compile_options(ruri PRIVATE $<$<CONFIG:Release>:-O2>)
target_link_options(ruri PRIVATE $<$<CONFIG:Release>:-O2>)

if(DISABLE_RURIENV)
target_compile_definitions(ruri PRIVATE DISABLE_RURIENV)
endif()
if(DISABLE_RURIENV AND DISABLE_LIBCAP AND DISABLE_LIBSECCOMP)
target_compile_definitions(ruri PRIVATE RURI_CORE_ONLY)
endif()
if(DISABLE_SYSTEMD)
target_compile_definitions(ruri PRIVATE DISABLE_SYSTEMD)
endif()

if(GIT_RESULT EQUAL 0 AND GIT_COMMIT_ID)
    target_compile_definitions(ruri PRIVATE RURI_COMMIT_ID="${GIT_COMMIT_ID}")
endif()
target_compile_definitions(ruri PRIVATE _FILE_OFFSET_BITS=64)


# Static linking
# Static PIE requires -static-pie; plain static uses -static.
# Android (bionic) does not support static executables with PIE.
if(ENABLE_STATIC)
    # NDK explicitly states PIE is not supported with static executables.
    # Disable PIE at the target level so the linker uses -static instead.
    message(WARNING "Forcing POSITION_INDEPENDENT_CODE=OFF for static build.")
    set_target_properties(ruri PROPERTIES POSITION_INDEPENDENT_CODE OFF)
    target_link_options(ruri PRIVATE -static)
endif()

# Non-Static linking
if(_enable_pie)
    set_target_properties(ruri PROPERTIES POSITION_INDEPENDENT_CODE ${_enable_pie})
endif()
unset(_enable_pie)

# Always link pthread
find_package(Threads REQUIRED)
target_link_libraries(ruri PRIVATE Threads::Threads)

# Optional: Linux capabilities support (libcap).
# For include path lookup variables, see # Optional Library Headers above.
# Custom-prefix / sysroot lookup — CMake official variables:
#   -DCMAKE_PREFIX_PATH=<prefix>     find_library searches <prefix>/lib[64]
#   -DCMAKE_LIBRARY_PATH=<dir>       append extra dirs for find_library only
#   -DCMAKE_FIND_ROOT_PATH=<sysroot> cross-compile sysroot; prefixes all find_* paths
# Disable with -DDISABLE_LIBCAP=ON.
if(NOT DISABLE_LIBCAP)
    find_library(LIBCAP_LIBRARY NAMES cap REQUIRED)
    target_link_libraries(ruri PRIVATE ${LIBCAP_LIBRARY})
endif()

# Disable with -DDISABLE_LIBSECCOMP=ON.
if(NOT DISABLE_LIBSECCOMP)
    find_library(LIBSECCOMP_LIBRARY NAMES seccomp REQUIRED)
    target_link_libraries(ruri PRIVATE ${LIBSECCOMP_LIBRARY})
endif()

include(CheckLinkerFlag)
set(CANDIDATE_LDFLAGS
    "-Wl,-z,noexecstack"
    "-Wl,--build-id=sha1"
)
if(NOT ENABLE_STATIC)
    list(APPEND CANDIDATE_LDFLAGS
        "-Wl,-z,relro"
        "-Wl,-z,now"
    )
endif()

foreach(flag IN LISTS CANDIDATE_LDFLAGS)
    string(MAKE_C_IDENTIFIER "HAS_LDFLAG_${flag}" _flag_var)
    check_linker_flag(C "${flag}" ${_flag_var})
    if(${_flag_var})
        target_link_options(ruri PRIVATE ${flag})
    endif()
endforeach()

# Enabled only in Release/MinSizeRel
# Avoid conflicts with -fsanitize and interference with RelWithDebInfo debug symbols.
check_linker_flag(C "-Wl,--gc-sections" HAS_LDFLAG_GC_SECTIONS)
if(HAS_LDFLAG_GC_SECTIONS)
    target_link_options(ruri PRIVATE
        $<$<CONFIG:Release>:-Wl,--gc-sections>
        $<$<CONFIG:MinSizeRel>:-Wl,--gc-sections>
    )
endif()


if(STRIP_DEBUGINFO)
    check_linker_flag(C "-Wl,--strip-all" HAS_LDFLAG_STRIP_ALL)
    if(HAS_LDFLAG_STRIP_ALL)
        target_link_options(ruri PRIVATE -Wl,--strip-all)
    else()
        # Fallback: use strip command post-build
        find_program(STRIP_TOOL strip)
        if(STRIP_TOOL)
            add_custom_command(TARGET ruri POST_BUILD
                COMMAND ${STRIP_TOOL} $<TARGET_FILE:ruri>
                COMMENT "Stripping debug symbols"
            )
        else()
            message(WARNING "strip not found; debug info may remain.")
        endif()
    endif()
endif()


include(GNUInstallDirs)
install(TARGETS ruri DESTINATION ${CMAKE_INSTALL_BINDIR})

# set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CLANG_TIDY_DISABLED_CHECKS
    "-clang-analyzer-security.insecureAPI.strcpy"
    "-clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling"
    "-clang-analyzer-security.insecureAPI.UncheckedReturn"
    "-concurrency-mt-unsafe"
    "-readability-function-cognitive-complexity"
    "-readability-identifier-length"
    "-cppcoreguidelines-avoid-magic-numbers"
    "-readability-magic-numbers"
    "-cert-err33-c"
    "-cert-err34-c"
    "-cert-msc54-cpp"
    "-cert-sig30-c"
    "-altera-unroll-loops"
    "-altera-id-dependent-backward-branch"
    "-bugprone-easily-swappable-parameters"
    "-misc-include-cleaner"
    "-bugprone-signal-handler"
    "-bugprone-suspicious-realloc-usage"
    "-hicpp-signed-bitwise"
)
# Convert list to comma-separated string
list(JOIN CLANG_TIDY_DISABLED_CHECKS "," CLANG_TIDY_DISABLED_CHECKS_STR)
set(CLANG_TIDY_CHECKS "--checks=*,${CLANG_TIDY_DISABLED_CHECKS_STR}")

find_program(CLANG_TIDY_PROGRAM clang-tidy)
if(CLANG_TIDY_PROGRAM)
    add_custom_target(
        tidy
        COMMAND ${CLANG_TIDY_PROGRAM}
            ${CLANG_TIDY_CHECKS}
            -p ${CMAKE_BINARY_DIR}
            ${SOURCES}
        COMMENT "Running clang-tidy"
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    )
else()
    message(STATUS "clang-tidy not found; 'tidy' target will not be available.")
endif()

file(GLOB FORMAT_HEADERS CONFIGURE_DEPENDS
    "${CMAKE_SOURCE_DIR}/src/include/*.h"
    "${CMAKE_SOURCE_DIR}/src/easteregg/include/*.h"
)

find_program(CLANG_FORMAT_PROGRAM clang-format)
if(CLANG_FORMAT_PROGRAM)
    add_custom_target(
        format
        COMMAND ${CLANG_FORMAT_PROGRAM} -i ${SOURCES} ${FORMAT_HEADERS}
        COMMENT "Formatting source code with clang-format"
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    )
else()
    message(STATUS "clang-format not found; 'format' target will not be available.")
endif()
