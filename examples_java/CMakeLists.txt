# CMakeLists.txt for Java JNI bindings
cmake_minimum_required(VERSION 3.15)
project(zupt_jni VERSION 1.0.5 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(Java COMPONENTS Development REQUIRED)
find_package(JNI REQUIRED)

# Find libzupt - check several possible locations
set(LIBZUPT_ROOT
    "${CMAKE_CURRENT_SOURCE_DIR}/.."
    "${CMAKE_CURRENT_SOURCE_DIR}/../.."
    "${CMAKE_CURRENT_SOURCE_DIR}/../../.."
    CACHE PATH "Root directory of libzupt"
)

# Look for libzupt.a or libzupt.so
find_path(LIBZUPT_INCLUDE_DIR
    NAMES zupt.hpp
    PATHS ${LIBZUPT_ROOT} ${LIBZUPT_ROOT}/include ${LIBZUPT_ROOT}/zupt/include
    NO_DEFAULT_PATH
)

find_library(LIBZUPT_LIBRARY
    NAMES zupt libzupt
    PATHS ${LIBZUPT_ROOT} ${LIBZUPT_ROOT}/build
    NO_DEFAULT_PATH
)

include_directories(${JNI_INCLUDE_DIRS})
include_directories(${LIBZUPT_INCLUDE_DIR})

set(JNI_SOURCES
    zupt_jni.cpp
)

add_library(zupt_jni SHARED ${JNI_SOURCES})

target_link_libraries(zupt_jni PRIVATE
    ${LIBZUPT_LIBRARY}
    ${JNI_LIBRARIES}
)

set_target_properties(zupt_jni PROPERTIES
    OUTPUT_NAME Jzupt
    PREFIX "lib"
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

install(TARGETS zupt_jni
    LIBRARY DESTINATION lib
)
