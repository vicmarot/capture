cmake_minimum_required(VERSION 3.10)
project(capture C)


if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Choose the type of build (Debug or Release)" FORCE)
endif()

set(CMAKE_C_STANDARD 11)

add_executable(capture src/main.c src/capture.c src/analysis.c src/utils.c)

target_include_directories(capture PRIVATE include)

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g -O0")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3")

find_library(PCAP_LIBRARY pcap)
target_link_libraries(capture ${PCAP_LIBRARY})


file(COPY ${CMAKE_SOURCE_DIR}/config DESTINATION ${CMAKE_BINARY_DIR})