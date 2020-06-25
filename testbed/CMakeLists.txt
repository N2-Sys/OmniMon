cmake_minimum_required(VERSION 3.12)
project(Omnimon)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_BUILD_TYPE Release)

set(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/build/lib)
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)

set(MTCP_DIR /home/kira/mtcp)
set(DPDK_DIR ${MTCP_DIR}/dpdk/x86_64-native-linuxapp-gcc)

file(STRINGS ${DPDK_DIR}/lib/ldflags.txt DPDK_LD_FLAGS)
set(CMAKE_C_FLAGS " ${DPDK_LD_FLAGS} ")

set(MTCP_FLD ${MTCP_DIR}/mtcp)
set(MTCP_INC ${MTCP_FLD}/include)
set(MTCP_LIB ${MTCP_FLD}/lib)
set(UTIL_FLD ${MTCP_DIR}/util)
set(UTIL_INC ${UTIL_FLD}/include)

include_directories(${PROJECT_SOURCE_DIR}/src ${DPDK_DIR}/include ${UTIL_INC} ${MTCP_INC} ${UTIL_FLD}/include)
link_directories(${DPDK_DIR}/lib ${MTCP_LIB})

if(CMAKE_COMPILER_IS_GNUCXX)
    add_compile_options(-g)
    add_compile_options(-mssse3)
    message(STATUS "optional:-g")
endif(CMAKE_COMPILER_IS_GNUCXX)


add_subdirectory(src)
