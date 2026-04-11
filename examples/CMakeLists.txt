# Example programs for libzupt

# Basic example
add_executable(zupt_example_basic example_basic.cpp)
target_link_libraries(zupt_example_basic PRIVATE zupt_shared)

# File encryption example
add_executable(zupt_example_file example_file.cpp)
target_link_libraries(zupt_example_file PRIVATE zupt_shared)

# Binary data example
add_executable(zupt_example_binary example_binary.cpp)
target_link_libraries(zupt_example_binary PRIVATE zupt_shared)

# Installation
install(TARGETS zupt_example_basic zupt_example_file zupt_example_binary
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
