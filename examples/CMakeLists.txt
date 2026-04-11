# Example programs for libzupt

# Basic example
add_executable(zupt_example_basic example_basic.cpp)
target_link_libraries(zupt_example_basic zupt_shared)
target_include_directories(zupt_example_basic PRIVATE ${LIBZUPT_INCLUDE_DIR})

# File encryption example
add_executable(zupt_example_file example_file.cpp)
target_link_libraries(zupt_example_file zupt_shared)
target_include_directories(zupt_example_file PRIVATE ${LIBZUPT_INCLUDE_DIR})

# Binary data example
add_executable(zupt_example_binary example_binary.cpp)
target_link_libraries(zupt_example_binary zupt_shared)
target_include_directories(zupt_example_binary PRIVATE ${LIBZUPT_INCLUDE_DIR})

# Installation
install(TARGETS zupt_example_basic zupt_example_file zupt_example_binary
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)