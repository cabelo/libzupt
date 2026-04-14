cmake_minimum_required(VERSION 3.10)
project(libzupt VERSION 1.0.5 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Position independent code for shared library
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Paths
set(LIBZUPT_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(LIBZUPT_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR})
set(LIBZUPT_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)

get_filename_component(LIBZUPT_EXTRA_INCLUDE_DIR
    ${LIBZUPT_SOURCE_DIR}/../zupt/include
    ABSOLUTE
)

# Sources
set(LIBZUPT_C_SOURCES
    ${LIBZUPT_SOURCE_DIR}/src/zupt_cxx.c
    ${LIBZUPT_SOURCE_DIR}/src/zupt_sha256.c
    ${LIBZUPT_SOURCE_DIR}/src/zupt_keccak.c
    ${LIBZUPT_SOURCE_DIR}/src/zupt_mlkem.c
    ${LIBZUPT_SOURCE_DIR}/src/zupt_x25519.c
    ${LIBZUPT_SOURCE_DIR}/src/zupt_crypto.c
    ${LIBZUPT_SOURCE_DIR}/src/zupt_xxh.c
    ${LIBZUPT_SOURCE_DIR}/src/zupt_aes256.c
    ${LIBZUPT_SOURCE_DIR}/src/zupt_mlock.c
)

file(GLOB LIBZUPT_CXX_SOURCES
    ${LIBZUPT_SOURCE_DIR}/src/*.cpp
)

# ========================
# SHARED LIBRARY
# ========================
add_library(zupt_shared SHARED
    ${LIBZUPT_C_SOURCES}
    ${LIBZUPT_CXX_SOURCES}
)

target_include_directories(zupt_shared PUBLIC
    $<BUILD_INTERFACE:${LIBZUPT_INCLUDE_DIR}>
    $<BUILD_INTERFACE:${LIBZUPT_EXTRA_INCLUDE_DIR}>
    $<INSTALL_INTERFACE:include>
)

target_compile_definitions(zupt_shared PRIVATE ZUPT_EXPORTS)
target_compile_features(zupt_shared PUBLIC cxx_std_17)

if(MSVC)
    target_compile_options(zupt_shared PRIVATE /W4 /D_CRT_SECURE_NO_WARNINGS)
    target_compile_options(zupt_shared PRIVATE /wd4251)
    target_compile_definitions(zupt_shared PRIVATE
        getpid=_getpid
        unlink=_unlink
    )
else()
    target_compile_options(zupt_shared PRIVATE -Wall -Wextra -O2)
endif()

set_target_properties(zupt_shared PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
    OUTPUT_NAME zupt
    LINKER_LANGUAGE CXX
)

add_library(zupt ALIAS zupt_shared)

# ========================
# STATIC LIBRARY
# ========================
add_library(zupt_static STATIC
    ${LIBZUPT_C_SOURCES}
    ${LIBZUPT_CXX_SOURCES}
)

target_include_directories(zupt_static PUBLIC
    $<BUILD_INTERFACE:${LIBZUPT_INCLUDE_DIR}>
    $<BUILD_INTERFACE:${LIBZUPT_EXTRA_INCLUDE_DIR}>
    $<INSTALL_INTERFACE:include>
)

target_compile_definitions(zupt_static PRIVATE ZUPT_STATIC)
target_compile_features(zupt_static PUBLIC cxx_std_17)

if(MSVC)
    target_compile_options(zupt_static PRIVATE /W4 /D_CRT_SECURE_NO_WARNINGS)
    target_compile_options(zupt_static PRIVATE /wd4251)
    target_compile_definitions(zupt_static PRIVATE
        getpid=_getpid
        unlink=_unlink
    )
else()
    target_compile_options(zupt_static PRIVATE -Wall -Wextra -O2)
endif()

set_target_properties(zupt_static PROPERTIES
    OUTPUT_NAME zupt_static
    LINKER_LANGUAGE CXX
)

# ========================
# INSTALL
# ========================
include(GNUInstallDirs)

install(TARGETS zupt_shared zupt_static
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(FILES
    ${LIBZUPT_INCLUDE_DIR}/zupt.hpp
    ${LIBZUPT_INCLUDE_DIR}/zupt_cxx.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

# pkg-config
configure_file(
    ${LIBZUPT_SOURCE_DIR}/libzupt.pc.in
    ${LIBZUPT_BUILD_DIR}/libzupt.pc
    @ONLY
)

install(FILES
    ${LIBZUPT_BUILD_DIR}/libzupt.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)

# CMake config
include(CMakePackageConfigHelpers)

write_basic_package_version_file(
    ${LIBZUPT_BUILD_DIR}/libzuptConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

configure_package_config_file(
    ${LIBZUPT_SOURCE_DIR}/libzuptConfig.cmake.in
    ${LIBZUPT_BUILD_DIR}/libzuptConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/libzupt
)

install(FILES
    ${LIBZUPT_BUILD_DIR}/libzuptConfig.cmake
    ${LIBZUPT_BUILD_DIR}/libzuptConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/libzupt
)

# ========================
# BUILD OPTIONS
# ========================

# 🔥 TESTS DESABILITADOS NO WINDOWS
if(WIN32)
    option(LIBZUPT_BUILD_TESTS "Build unit tests" OFF)
else()
    option(LIBZUPT_BUILD_TESTS "Build unit tests" ON)
endif()

option(LIBZUPT_BUILD_EXAMPLES "Build examples" ON)
option(LIBZUPT_BUILD_PYTHON "Build Python bindings" ON)

# ========================
# SUBDIRECTORIES
# ========================

if(LIBZUPT_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(LIBZUPT_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

if(LIBZUPT_BUILD_PYTHON)
    add_subdirectory(examples_python)
endif()
