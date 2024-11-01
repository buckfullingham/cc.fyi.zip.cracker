find_package(Catch2 REQUIRED)

include(CTest)
include(Catch)

add_custom_target(test_zip_files.hpp
        COMMAND mako-render ${CMAKE_CURRENT_SOURCE_DIR}/test_zip_files.hpp.mako | clang-format > ${CMAKE_CURRENT_SOURCE_DIR}/test_zip_files.hpp
        DEPENDS test_zip_files.hpp.mako
)

add_executable(tests
        tests.cpp
)

target_include_directories(tests PRIVATE
        ../main
)

add_dependencies(tests
        test_zip_files.hpp
)

target_link_libraries(tests PRIVATE
        Catch2::Catch2WithMain
        zip-cracker-objects
)

catch_discover_tests(tests)
