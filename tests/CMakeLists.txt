# Unit tests for libzupt

# Test utility functions
function(add_zupt_test name)
    add_executable(zupt_test_${name} ${name}.cpp)
    target_link_libraries(zupt_test_${name} zupt_shared)
    target_include_directories(zupt_test_${name} PRIVATE ${LIBZUPT_INCLUDE_DIR})
    add_test(NAME zupt_test_${name} COMMAND zupt_test_${name})
endfunction()

# Add tests
add_zupt_test(keygen)
add_zupt_test(encrypt)
add_zupt_test(decrypt)
add_zupt_test(roundtrip)
add_zupt_test(file_ops)

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