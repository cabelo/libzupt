# Unit tests for libzupt

# Test utility functions
function(add_zupt_test name)
    add_executable(zupt_test_${name} ${name}.cpp)
    target_link_libraries(zupt_test_${name} zupt_shared)
    target_include_directories(zupt_test_${name} PRIVATE ${LIBZUPT_INCLUDE_DIR})
    # Most existing tests use assert; keep those checks active in Release builds.
    if(MSVC)
        target_compile_options(zupt_test_${name} PRIVATE /UNDEBUG)
    else()
        target_compile_options(zupt_test_${name} PRIVATE -UNDEBUG)
    endif()
    add_test(NAME zupt_test_${name} COMMAND zupt_test_${name})
    if(WIN32)
        add_custom_command(TARGET zupt_test_${name} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                $<TARGET_FILE:zupt_shared> $<TARGET_FILE_DIR:zupt_test_${name}>)
    endif()
endfunction()

# Add tests
add_zupt_test(keygen)
add_zupt_test(encrypt)
add_zupt_test(decrypt)
add_zupt_test(roundtrip)
add_zupt_test(file_ops)
add_zupt_test(authentication)
add_zupt_test(secure_buffer)
add_zupt_test(fuzz_smoke)
if(UNIX)
    add_zupt_test(key_storage)
endif()

find_package(Python3 COMPONENTS Interpreter REQUIRED)
add_library(zupt_kat SHARED
    ${LIBZUPT_SOURCE_DIR}/src/zupt_mlkem.c
    ${LIBZUPT_SOURCE_DIR}/src/zupt_keccak.c
    mlkem_support.c)
target_include_directories(zupt_kat PRIVATE ${LIBZUPT_INCLUDE_DIR})
target_compile_definitions(zupt_kat PRIVATE ZUPT_TESTING)
set_target_properties(zupt_kat PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
add_test(NAME zupt_test_acvp COMMAND ${Python3_EXECUTABLE}
    ${LIBZUPT_SOURCE_DIR}/scripts/check-acvp.py --library $<TARGET_FILE:zupt_kat>)

add_executable(zupt_test_aes_portable aes_portable.c
    ${LIBZUPT_SOURCE_DIR}/src/zupt_aes256.c mlkem_support.c)
target_include_directories(zupt_test_aes_portable PRIVATE ${LIBZUPT_INCLUDE_DIR})
target_compile_definitions(zupt_test_aes_portable PRIVATE ZUPT_FORCE_PORTABLE_AES)
add_test(NAME zupt_test_aes_portable COMMAND zupt_test_aes_portable)
add_test(NAME zupt_test_primitives COMMAND ${Python3_EXECUTABLE}
    ${LIBZUPT_SOURCE_DIR}/scripts/check-primitives.py --library $<TARGET_FILE:zupt_shared>)
add_test(NAME zupt_test_legacy COMMAND ${Python3_EXECUTABLE}
    ${LIBZUPT_SOURCE_DIR}/scripts/check-legacy.py --library $<TARGET_FILE:zupt_shared>)
set_tests_properties(zupt_test_acvp zupt_test_primitives zupt_test_legacy
    PROPERTIES LABELS "python")

# Create a simple test runner script
configure_file(
    ${LIBZUPT_SOURCE_DIR}/run_tests.sh.in
    ${LIBZUPT_BUILD_DIR}/run_tests.sh
    @ONLY
)

# Install test executables
install(TARGETS zupt_test_keygen zupt_test_encrypt zupt_test_decrypt zupt_test_roundtrip zupt_test_file_ops
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
