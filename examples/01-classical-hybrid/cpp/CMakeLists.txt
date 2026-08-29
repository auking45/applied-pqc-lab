cmake_minimum_required(VERSION 3.20)
project(classical_hybrid_cpp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

add_executable(classical_hybrid main.cpp)
target_link_libraries(classical_hybrid PRIVATE OpenSSL::Crypto OpenSSL::SSL)
