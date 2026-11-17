# Actual optional pybind11 extension; no dependency download during configure.
cmake_minimum_required(VERSION 3.18)
set(PYBIND11_FINDPYTHON ON)
find_package(Python3 COMPONENTS Interpreter Development.Module REQUIRED)
find_package(pybind11 CONFIG REQUIRED)
pybind11_add_module(zupt_python_bindings zupt_pybind.cpp)
set_target_properties(zupt_python_bindings PROPERTIES OUTPUT_NAME zupt)
target_link_libraries(zupt_python_bindings PRIVATE zupt_shared)
if(LIBZUPT_BUILD_TESTS)
    add_test(NAME zupt_test_python_binding COMMAND ${Python3_EXECUTABLE}
        ${LIBZUPT_SOURCE_DIR}/tests/python_binding.py $<TARGET_FILE_DIR:zupt_python_bindings>)
    set_tests_properties(zupt_test_python_binding PROPERTIES LABELS "python")
endif()
