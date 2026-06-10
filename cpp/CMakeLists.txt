cmake_minimum_required(VERSION 3.14)
project(tspu_sniffer CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()
set(CMAKE_CXX_FLAGS_RELEASE "-O2 -DNDEBUG")

find_library(PCAP_LIB pcap REQUIRED)

# spdlog из системного пакета (libspdlog-dev)
find_package(spdlog REQUIRED)

add_executable(tspu_sniffer main.cpp)

target_include_directories(tspu_sniffer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(tspu_sniffer PRIVATE ${PCAP_LIB} pthread spdlog::spdlog)
