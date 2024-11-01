cmake_minimum_required(VERSION 3.20)
project(zip-cracker LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)

set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads REQUIRED)

set(CMAKE_CXX_FLAGS "-Wall -Wextra -Werror")
set(CMAKE_CXX_FLAGS_RELEASE "-O0 -g3")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -g3 -fno-omit-frame-pointer")
set(CMAKE_CXX_FLAGS_UBSAN "${CMAKE_CXX_FLAGS_RELEASE} -fsanitize=undefined -fno-omit-frame-pointer")
set(CMAKE_EXE_LINKER_FLAGS_UBSAN "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -fsanitize=undefined -fno-omit-frame-pointer")
set(CMAKE_CXX_FLAGS_ASAN "${CMAKE_CXX_FLAGS_RELEASE} -fsanitize=address -fno-omit-frame-pointer -fno-common")
set(CMAKE_EXE_LINKER_FLAGS_ASAN "${CMAKE_EXEC_LINKER_FLAGS_RELEASE} -fsanitize=address -fno-omit-frame-pointer")

set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)

set(CMAKE_MODULE_PATH ${CMAKE_BINARY_DIR})

enable_testing()

add_subdirectory(src)
