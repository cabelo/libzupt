cmake_minimum_required(VERSION 3.10)
project(libzupt VERSION 1.0.0 LANGUAGES C CXX)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Position independent code for shared library
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Output directories
set(LIBZUPT_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(LIBZUPT_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR})
set(LIBZUPT_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)

# Source files
set(LIBZUPT_C_SOURCES
    ${LIBZUPT_SOURCE_DIR}/src/zupt_cxx.c
    ${LIBZUPT_SOURCE_DIR}/src/zupt_sha256.c
    ${LIBZUPT_SOURCE_DIR}/src/zupt_keccak.c
    ${LIBZUPT_SOURCE_DIR}/src/zupt_mlkem.c
    ${LIBZUPT_SOURCE_DIR}/src/zupt_x25519.c
    ${LIBZUPT_SOURCE_DIR}/src/zupt_crypto.c
    ${LIBZUPT_SOURCE_DIR}/src/zupt_xxh.c
    ${LIBZUPT_SOURCE_DIR}/src/zupt_aes256.c
)

set(LIBZUPT_CXX_SOURCES
    ${LIBZUPT_SOURCE_DIR}/src/zupt_crypto.cpp
)

# Include directories
include_directories(
    ${LIBZUPT_INCLUDE_DIR}
    ${LIBZUPT_SOURCE_DIR}/../zupt/include
)

# Create shared library
add_library(zupt_shared SHARED
    ${LIBZUPT_C_SOURCES}
    ${LIBZUPT_CXX_SOURCES}
)

target_include_directories(zupt_shared PUBLIC
    $<BUILD_INTERFACE:${LIBZUPT_INCLUDE_DIR}>
    $<BUILD_INTERFACE:${LIBZUPT_SOURCE_DIR}/../zupt/include>
    $<INSTALL_INTERFACE:include>
)

target_compile_definitions(zupt_shared PRIVATE ZUPT_EXPORTS)
target_compile_features(zupt_shared PUBLIC cxx_std_17)

if(MSVC)
    target_compile_options(zupt_shared PRIVATE /W4 /D_CRT_SECURE_NO_WARNINGS)
    target_compile_options(zupt_shared PRIVATE /wd4251)  # disable DLL interface warning
else()
    target_compile_options(zupt_shared PRIVATE -Wall -Wextra -O2)
endif()

set_target_properties(zupt_shared PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
    OUTPUT_NAME zupt
)

# Create static library (optional)
add_library(zupt_static STATIC
    ${LIBZUPT_C_SOURCES}
    ${LIBZUPT_CXX_SOURCES}
)

target_include_directories(zupt_static PUBLIC
    $<BUILD_INTERFACE:${LIBZUPT_INCLUDE_DIR}>
    $<BUILD_INTERFACE:${LIBZUPT_SOURCE_DIR}/../zupt/include>
)

target_compile_definitions(zupt_static PRIVATE ZUPT_STATIC)
target_compile_features(zupt_static PUBLIC cxx_std_17)

set_target_properties(zupt_static PROPERTIES
    OUTPUT_NAME zupt
)

# Install rules
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

# pkg-config file
configure_file(
    ${LIBZUPT_SOURCE_DIR}/libzupt.pc.in
    ${LIBZUPT_BUILD_DIR}/libzupt.pc
    @ONLY
)

install(FILES
    ${LIBZUPT_BUILD_DIR}/libzupt.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)

# Export targets
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

# Unit tests
option(LIBZUPT_BUILD_TESTS "Build unit tests" ON)
option(LIBZUPT_BUILD_EXAMPLES "Build examples" ON)

if(LIBZUPT_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(LIBZUPT_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# Python bindings and examples
option(LIBZUPT_BUILD_PYTHON "Build Python bindings" ON)

if(LIBZUPT_BUILD_PYTHON)
    add_subdirectory(examples_python)
endif()
