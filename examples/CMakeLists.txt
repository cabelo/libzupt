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

# Installation
install(TARGETS zupt_example_basic zupt_example_file zupt_example_binary
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
