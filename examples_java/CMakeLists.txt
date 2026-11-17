cmake_minimum_required(VERSION 3.15)
project(zupt_jni LANGUAGES CXX)
find_package(JNI REQUIRED)

# Prefer the installed SDK (including the CI installation prefix). A checkout
# can also build the native dependency directly, without installing it first.
set(LIBZUPT_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/.." CACHE PATH "libzupt source directory")
find_package(libzupt 1.0.15 CONFIG QUIET)
if(libzupt_FOUND)
    set(LIBZUPT_JNI_TARGET libzupt::zupt_shared)
    message(STATUS "Using installed libzupt ${libzupt_VERSION}")
elseif(EXISTS "${LIBZUPT_ROOT}/CMakeLists.txt" AND
       EXISTS "${LIBZUPT_ROOT}/include/libzupt_version.h")
    file(STRINGS "${LIBZUPT_ROOT}/include/libzupt_version.h" LIBZUPT_JNI_VERSION_LINE
        REGEX "^#define LIBZUPT_VERSION_STRING")
    string(REGEX MATCH "[0-9]+\\.[0-9]+\\.[0-9]+" LIBZUPT_JNI_VERSION
        "${LIBZUPT_JNI_VERSION_LINE}")
    if(NOT LIBZUPT_JNI_VERSION MATCHES "^1\\." OR
       LIBZUPT_JNI_VERSION VERSION_LESS "1.0.15")
        message(FATAL_ERROR
            "Local libzupt version '${LIBZUPT_JNI_VERSION}' is incompatible. "
            "Use libzupt 1.0.15 or a compatible 1.x release.")
    endif()

    # These normal variables apply to the embedded native project. They do not
    # force or rewrite the user's cached build options.
    set(LIBZUPT_BUILD_TESTS OFF)
    set(LIBZUPT_BUILD_EXAMPLES OFF)
    set(LIBZUPT_BUILD_PYTHON OFF)
    set(LIBZUPT_BUILD_FUZZERS OFF)
    add_subdirectory("${LIBZUPT_ROOT}" "${CMAKE_CURRENT_BINARY_DIR}/libzupt-native" EXCLUDE_FROM_ALL)
    set(LIBZUPT_JNI_TARGET zupt_shared)
    message(STATUS "Using local libzupt ${LIBZUPT_JNI_VERSION}: ${LIBZUPT_ROOT}")
else()
    message(FATAL_ERROR
        "libzupt 1.0.15 was not found. Set CMAKE_PREFIX_PATH to its installation "
        "prefix, or LIBZUPT_ROOT to the libzupt source directory.")
endif()

add_library(zupt_jni SHARED zupt_jni.cpp)
target_include_directories(zupt_jni PRIVATE ${JNI_INCLUDE_DIRS})
target_link_libraries(zupt_jni PRIVATE ${LIBZUPT_JNI_TARGET} ${JNI_LIBRARIES})
set_target_properties(zupt_jni PROPERTIES OUTPUT_NAME Jzupt PREFIX "lib")
install(TARGETS zupt_jni LIBRARY DESTINATION lib RUNTIME DESTINATION bin)
