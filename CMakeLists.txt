cmake_minimum_required(VERSION 3.5)
project(iruka)


# not required if find_package is used
link_directories(/usr/local/lib/)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -Wall -I/usr/local/include/")

set(SOURCE_FILES main.cpp config.hpp config.cpp spitter.hpp spitter.cpp spitutils.hpp spitutils.cpp crc.hpp monitor.hpp sqlite3.h sqlite3.c)

add_executable(iruka ${SOURCE_FILES})
target_link_libraries(iruka pcap)
