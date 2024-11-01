find_package(ZLIB REQUIRED)
find_package(cc.fyi.common REQUIRED)
find_package(TBB REQUIRED)

add_library(zip-cracker-objects OBJECT
        zip.cpp
)

target_link_libraries(zip-cracker-objects PUBLIC
        ZLIB::ZLIB
        TBB::tbb
        cc.fyi.common::cc.fyi.common
        Threads::Threads
)

add_executable(zip-cracker
        zip-cracker.cpp
)

target_link_libraries(zip-cracker PRIVATE
        zip-cracker-objects
)
