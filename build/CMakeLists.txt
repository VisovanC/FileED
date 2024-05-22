
cmake_minimum_required(VERSION 3.10)
project(Project)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_REQUIRED True)

find_package(OpenSSL REQUIRED)

add_executable(Project main.c)

target_link_libraries(Project OpenSSL::SSL OpenSSL::Crypto)
