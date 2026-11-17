# Example programs for libzupt

if(WIN32)
    set(ZUPT_EXAMPLE_LIB zupt_static)
else()
    set(ZUPT_EXAMPLE_LIB zupt_shared)
endif()

# Basic example
add_executable(zupt_example_basic example_basic.cpp)
target_link_libraries(zupt_example_basic PRIVATE ${ZUPT_EXAMPLE_LIB})

# File encryption example
add_executable(zupt_example_file example_file.cpp)
target_link_libraries(zupt_example_file PRIVATE ${ZUPT_EXAMPLE_LIB})

# Binary data example
add_executable(zupt_example_binary example_binary.cpp)
target_link_libraries(zupt_example_binary PRIVATE ${ZUPT_EXAMPLE_LIB})

add_executable(zupt_migrate migrate_v1.cpp)
target_link_libraries(zupt_migrate PRIVATE ${ZUPT_EXAMPLE_LIB})
if(LIBZUPT_BUILD_TESTS)
    find_package(Python3 COMPONENTS Interpreter REQUIRED)
    add_test(NAME zupt_test_migration_cli COMMAND ${Python3_EXECUTABLE}
        ${LIBZUPT_SOURCE_DIR}/scripts/check-migration-cli.py
        --example $<TARGET_FILE:zupt_example_file> --migrate $<TARGET_FILE:zupt_migrate>)
    set_tests_properties(zupt_test_migration_cli PROPERTIES LABELS "python")
endif()

# Installation
install(TARGETS zupt_example_basic zupt_example_file zupt_example_binary zupt_migrate
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
