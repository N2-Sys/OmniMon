cmake_minimum_required(VERSION 3.12)
project(Omnimon)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_BUILD_TYPE Release)
set(DPDK_DIR "/usr/local/src/dpdk/x86_64-native-linuxapp-gcc")

set(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/build/lib)
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)

include_directories(${PROJECT_SOURCE_DIR}/src ${DPDK_DIR}/include)
link_directories(${DPDK_DIR}/lib)

add_subdirectory(src)



