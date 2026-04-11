if(WIN32)
    set(LIBZUPT_TEST_LIB zupt_static)
else()
    set(LIBZUPT_TEST_LIB zupt_shared)
endif()

add_executable(zupt_test_encrypt encrypt.cpp)
target_link_libraries(zupt_test_encrypt PRIVATE ${LIBZUPT_TEST_LIB})

add_executable(zupt_test_decrypt decrypt.cpp)
target_link_libraries(zupt_test_decrypt PRIVATE ${LIBZUPT_TEST_LIB})

add_executable(zupt_test_file_ops file_ops.cpp)
target_link_libraries(zupt_test_file_ops PRIVATE ${LIBZUPT_TEST_LIB})

add_executable(zupt_test_keygen keygen.cpp)
target_link_libraries(zupt_test_keygen PRIVATE ${LIBZUPT_TEST_LIB})

add_executable(zupt_test_roundtrip roundtrip.cpp)
target_link_libraries(zupt_test_roundtrip PRIVATE ${LIBZUPT_TEST_LIB})
