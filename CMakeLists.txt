cmake_minimum_required(VERSION 3.10)
project(ruri LANGUAGES C)

# ==============================
# Sources & Executable
# ==============================
file(GLOB SOURCES CONFIGURE_DEPENDS
    ${CMAKE_SOURCE_DIR}/src/*.c
    ${CMAKE_SOURCE_DIR}/src/easteregg/*.c
)

add_executable(ruri ${SOURCES})

# ==============================
# Options
# ==============================
option(ENABLE_DEBUG "Enable debug build" OFF)
option(ENABLE_STATIC "Enable static linking" OFF)
option(DISABLE_LIBCAP "Disable cap library linking" OFF)
option(DISABLE_LIBSECCOMP "Disable seccomp library linking" OFF)
option(DISABLE_RURIENV "Disable env in ruri" OFF)
option(STRIP_DEBUGINFO "Strip debuginfo from ruri binary" ON)

# ==============================
# Platform Check
# ==============================
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "ruri is only supported on Linux platforms.")
endif()

# ==============================
# Build Metadata
# ==============================
execute_process(COMMAND date "+%Y-%m-%d" OUTPUT_VARIABLE CMAKE_CURRENT_DATE OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(COMMAND date "+%H:%M:%S" OUTPUT_VARIABLE CMAKE_CURRENT_TIME OUTPUT_STRIP_TRAILING_WHITESPACE)

execute_process(
    COMMAND git rev-parse --short HEAD
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_COMMIT_ID
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

# ==============================
# Compiler & Toolchain Setup
# ==============================
# ccache
find_program(CCACHE_FOUND ccache)
if(CCACHE_FOUND)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache)
    message(STATUS "Using ccache: ${CCACHE_FOUND}")
else()
    message(STATUS "Ccache not found. Compiling without cache.")
endif()

# TinyCC special handling
if(CMAKE_C_COMPILER MATCHES "tcc")
    set(_arch ${CMAKE_SYSTEM_PROCESSOR})
    if(_arch MATCHES "x86_64")
        set(CMAKE_LIBRARY_PATH "/usr/lib/x86_64-linux-gnu/")
        set(CMAKE_INCLUDE_PATH "/usr/include/x86_64-linux-gnu/")
    elseif(_arch MATCHES "aarch64")
        set(CMAKE_LIBRARY_PATH "/usr/lib/aarch64-linux-gnu/")
        set(CMAKE_INCLUDE_PATH "/usr/include/aarch64-linux-gnu/")
    elseif(_arch MATCHES "armv7l")
        set(CMAKE_LIBRARY_PATH "/usr/lib/arm-linux-gnueabihf/")
        set(CMAKE_INCLUDE_PATH "/usr/include/arm-linux-gnueabihf/")
    elseif(_arch MATCHES "i386")
        set(CMAKE_LIBRARY_PATH "/usr/lib/i386-linux-gnu/")
        set(CMAKE_INCLUDE_PATH "/usr/include/i386-linux-gnu/")
    elseif(_arch MATCHES "powerpc64le")
        set(CMAKE_LIBRARY_PATH "/usr/lib/powerpc64le-linux-gnu/")
        set(CMAKE_INCLUDE_PATH "/usr/include/powerpc64le-linux-gnu/")
    endif()
    add_definitions(-D__VERSION__="TinyCC")
    add_definitions(-D__TIMESTAMP__="${CMAKE_CURRENT_DATE} ${CMAKE_CURRENT_TIME}")
endif()

# ==============================
# Required Headers
# ==============================
include(CheckIncludeFile)

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
    "sys/capability.h"
    seccomp.h
    pthread.h
)

foreach(hdr IN LISTS REQUIRED_HEADERS)
    string(REPLACE "/" "_" CHECK_NAME "HAVE_${hdr}")
    string(REPLACE "." "_" CHECK_NAME "${CHECK_NAME}")
    check_include_file("${hdr}" ${CHECK_NAME})
    if(NOT ${CHECK_NAME})
        message(FATAL_ERROR "Missing required header: ${hdr}")
    endif()
endforeach()

# ==============================
# Compiler Flags
# ==============================
set(CANDIDATE_CFLAGS
    "-flto=auto"
    "-pie"
    "-fstack-protector-all"
    "-fdata-sections"
    "-fno-omit-frame-pointer"
    "-fno-stack-protector"
    "-ftrivial-auto-var-init=pattern"
    "-fstack-clash-protection"
    "-Wno-unused-result"
    "-mshstk"
    "-ffunction-sections"
    "-Wall"
    "-Wextra"
    "-Wconversion"
    "-pedantic"
    "-pipe"
)

# Test and apply supported flags
foreach(flag IN LISTS CANDIDATE_CFLAGS)
    try_compile(HAS_FLAG ${CMAKE_BINARY_DIR} ${CMAKE_SOURCE_DIR}/test/check_flag.c COMPILE_DEFINITIONS ${flag})
    if(HAS_FLAG)
        target_compile_options(ruri PRIVATE ${flag})
        message(STATUS "Compiler supports flag: ${flag}")
    else()
        message(WARNING "Compiler does not support flag: ${flag}")
    endif()
endforeach()

# LDFLAGS (applied via target_link_options later)
set(RURI_LDFLAGS
    "-Wl,-z,relro"
    "-Wl,-z,noexecstack"
    "-Wl,-z,now"
    "-Wl,--gc-sections"
    "-Wl,--disable-new-dtags"
    "-Wl,--build-id=sha1"
    "-Wl,-z,norelro"
    "-Wl,-z,execstack"
)

# ==============================
# Build Type & Definitions
# ==============================
if(ENABLE_DEBUG)
    message(WARNING "Warning: DEBUG mode is enabled")
    target_compile_definitions(ruri PRIVATE
        DEBUG_BUILD
        RURI_DEBUG
        RURI_DEV
    )
    target_compile_options(ruri PRIVATE -g3 -O0)
else()
    target_compile_options(ruri PRIVATE -O2)
    target_compile_definitions(ruri PRIVATE NDEBUG)
endif()

if(DISABLE_RURIENV)
    target_compile_definitions(ruri PRIVATE DISABLE_RURIENV)
endif()

if(DISABLE_RURIENV AND DISABLE_LIBCAP AND DISABLE_LIBSECCOMP)
    target_compile_definitions(ruri PRIVATE RURI_CORE_ONLY)
endif()

target_compile_definitions(ruri PRIVATE
    RURI_COMMIT_ID="${GIT_COMMIT_ID}"
    _FILE_OFFSET_BITS=64
)

# Position-independent executable
set_target_properties(ruri PROPERTIES POSITION_INDEPENDENT_CODE OFF)
target_compile_options(ruri PRIVATE -fPIE)

# Apply LDFLAGS
target_link_options(ruri PRIVATE ${RURI_LDFLAGS})

# Static linking
if(ENABLE_STATIC)
    target_link_options(ruri PRIVATE -static)
endif()

# ==============================
# Library Linking (Linux only)
# ==============================
find_library(LCAP cap)
find_library(LSECCOMP seccomp)
find_library(LPTHREAD pthread)

if(NOT DISABLE_LIBCAP AND NOT LCAP)
    message(FATAL_ERROR "Library 'cap' is required but not found.")
endif()
if(NOT DISABLE_LIBSECCOMP AND NOT LSECCOMP)
    message(FATAL_ERROR "Library 'seccomp' is required but not found.")
endif()

if(DISABLE_LIBCAP AND DISABLE_LIBSECCOMP)
    target_compile_definitions(ruri PRIVATE DISABLE_LIBCAP DISABLE_LIBSECCOMP)
elseif(DISABLE_LIBCAP)
    target_compile_definitions(ruri PRIVATE DISABLE_LIBCAP)
    target_link_libraries(ruri PRIVATE ${LSECCOMP})
elseif(DISABLE_LIBSECCOMP)
    target_compile_definitions(ruri PRIVATE DISABLE_LIBSECCOMP)
    target_link_libraries(ruri PRIVATE ${LCAP})
else()
    target_link_libraries(ruri PRIVATE ${LCAP} ${LSECCOMP})
endif()

# Always link pthread
target_link_libraries(ruri PRIVATE ${LPTHREAD})

# ==============================
# Debug Info Stripping
# ==============================
if(STRIP_DEBUGINFO)
    try_compile(HAS_STRIP_ALL ${CMAKE_BINARY_DIR} ${CMAKE_SOURCE_DIR}/test/check_flag.c COMPILE_DEFINITIONS -Wl,--strip-all)
    if(HAS_STRIP_ALL)
        target_link_options(ruri PRIVATE -Wl,--strip-all)
        message(STATUS "Using linker flag: -Wl,--strip-all")
    else()
        # Fallback: use strip command post-build
        find_program(STRIP_TOOL strip)
        if(STRIP_TOOL)
            add_custom_command(TARGET ruri POST_BUILD
                COMMAND ${STRIP_TOOL} ruri
                COMMENT "Stripping debug symbols"
            )
        else()
            message(WARNING "strip not found; debug info may remain.")
        endif()
    endif()
endif()

# ==============================
# Install & Dev Tools
# ==============================
install(TARGETS ruri DESTINATION bin)

add_custom_target(
    tidy
    COMMAND clang-tidy
        --checks=*,
        -clang-analyzer-security.insecureAPI.strcpy,
        -altera-unroll-loops,
        -cert-err33-c,
        -concurrency-mt-unsafe,
        -clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling,
        -readability-function-cognitive-complexity,
        -cppcoreguidelines-avoid-magic-numbers,
        -readability-magic-numbers,
        -bugprone-easily-swappable-parameters,
        -cert-err34-c,
        -misc-include-cleaner,
        -readability-identifier-length,
        -bugprone-signal-handler,
        -cert-msc54-cpp,
        -cert-sig30-c,
        -altera-id-dependent-backward-branch,
        -bugprone-suspicious-realloc-usage,
        -hicpp-signed-bitwise,
        -clang-analyzer-security.insecureAPI.UncheckedReturn
        --list-checks
        ${SOURCES}
        -- -lpthread -lseccomp -lcap -Wall -Wextra
    COMMENT "Running clang-tidy"
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

add_custom_target(
    format
    COMMAND clang-format -i ${SOURCES} ${CMAKE_SOURCE_DIR}/include/*.h
    COMMENT "Formatting source code with clang-format"
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)
