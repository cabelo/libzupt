# Example programs for libzupt

if(WIN32)
    set(LIBZUPT_EXAMPLE_LIB zupt_static)
else()
    set(LIBZUPT_EXAMPLE_LIB zupt_shared)
endif()

# Basic example
add_executable(zupt_example_basic example_basic.cpp)
target_link_libraries(zupt_example_basic PRIVATE ${LIBZUPT_EXAMPLE_LIB})
target_include_directories(zupt_example_basic PRIVATE ${LIBZUPT_INCLUDE_DIR})

# File encryption example
add_executable(zupt_example_file example_file.cpp)
target_link_libraries(zupt_example_file PRIVATE ${LIBZUPT_EXAMPLE_LIB})
target_include_directories(zupt_example_file PRIVATE ${LIBZUPT_INCLUDE_DIR})

# Binary data example
add_executable(zupt_example_binary example_binary.cpp)
target_link_libraries(zupt_example_binary PRIVATE ${LIBZUPT_EXAMPLE_LIB})
target_include_directories(zupt_example_binary PRIVATE ${LIBZUPT_INCLUDE_DIR})

# Installation
install(TARGETS zupt_example_basic zupt_example_file zupt_example_binary
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
