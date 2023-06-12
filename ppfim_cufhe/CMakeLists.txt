cmake_minimum_required(VERSION 3.14)

project(ppfim_cufhe)

find_package(CUDA REQUIRED)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -O3")

set(CUDA_NVCC_FLAGS ${CUDA_NVCC_FLAGS};-std=c++14;)
#   -gencode=arch=compute_70,code=sm_70; \\
#   -gencode=arch=compute_70,code=compute_70; \\
#   -Wno-deprecated-gpu-targets;)

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)

include_directories(
    /usr/local/cufhe/include)

link_directories(
    /usr/local/cufhe/lib)

CUDA_ADD_EXECUTABLE(test_cloud
    src/test_cloud.cu
    src/cloud.cuh
    src/cloud.cu)
target_link_libraries(test_cloud cufhe_gpu)

CUDA_ADD_EXECUTABLE(test_user
    src/test_user.cu
    src/user.cuh
    src/user.cu
    src/cloud.cuh
    src/cloud.cu)
target_link_libraries(test_user cufhe_gpu)

CUDA_ADD_EXECUTABLE(test_miner
    src/test_miner.cu
    src/miner.cuh
    src/miner.cu)
target_link_libraries(test_miner cufhe_gpu)

CUDA_ADD_EXECUTABLE(test_performance
    src/test_performance.cu
    src/user.cuh
    src/user.cu
    src/cloud.cuh
    src/cloud.cu
    src/miner.cuh
    src/miner.cu)
target_link_libraries(test_performance cufhe_gpu)
