cmake_minimum_required(VERSION 3.14)
project(ppfim)

set(CMAKE_CXX_STANDARD 14)

add_compile_options(-O3 -Wall -pthread)

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)

set(TEST_MINER_SRC
        src/test_miner.cpp
        src/miner.h
        src/miner.cpp)
add_executable(test_miner ${TEST_MINER_SRC})
target_link_libraries(test_miner tfhe-spqlios-fma)

set(TEST_USER_SRC
        src/test_user.cpp
        src/user.h
        src/user.cpp)
add_executable(test_user ${TEST_USER_SRC})
target_link_libraries(test_user tfhe-spqlios-fma)

set(TEST_CLOUD_SRC
        src/test_cloud.cpp
        src/cloud.h
        src/cloud.cpp
        src/user.h
        src/user.cpp)
add_executable(test_cloud ${TEST_CLOUD_SRC})
target_link_libraries(test_cloud tfhe-spqlios-fma)

set(TEST_PERFORMANCE_SRC
        src/test_performance.cpp
        src/cloud.h
        src/cloud.cpp
        src/user.h
        src/user.cpp
        src/miner.h
        src/miner.cpp)
add_executable(test_performance ${TEST_PERFORMANCE_SRC})
target_link_libraries(test_performance tfhe-spqlios-fma)

set(TEST_MULTITHREAD
        src/test_multithread.cpp
        src/multithread.h
        src/multithread.cpp
        src/user.h
        src/user.cpp
        src/cloud.h
        src/cloud.cpp)
add_executable(test_multithread ${TEST_MULTITHREAD})
target_link_libraries(test_multithread tfhe-spqlios-fma pthread)

set(TEST_MULTITHREAD_PERFORMANCE
        src/test_multithread_performance.cpp
        src/multithread.h
        src/multithread.cpp
        src/user.h
        src/user.cpp
        src/miner.h
        src/miner.cpp
        src/cloud.h
        src/cloud.cpp)
add_executable(test_multithread_performance ${TEST_MULTITHREAD_PERFORMANCE})
target_link_libraries(test_multithread_performance tfhe-spqlios-fma pthread)
