cmake_minimum_required(VERSION 3.20)
project(pqc_x509_cpp CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_path(OPENSSL_INCLUDE_DIR openssl/x509.h PATHS /opt/openssl/include NO_DEFAULT_PATH)
find_library(OPENSSL_CRYPTO_LIB crypto PATHS /opt/openssl/lib /opt/openssl/lib64 NO_DEFAULT_PATH)
find_library(OPENSSL_SSL_LIB ssl PATHS /opt/openssl/lib /opt/openssl/lib64 NO_DEFAULT_PATH)

if(NOT OPENSSL_INCLUDE_DIR OR NOT OPENSSL_CRYPTO_LIB)
    find_package(OpenSSL REQUIRED)
    set(OPENSSL_INCLUDE_DIR ${OPENSSL_INCLUDE_DIR})
    set(OPENSSL_CRYPTO_LIB OpenSSL::Crypto)
    set(OPENSSL_SSL_LIB OpenSSL::SSL)
endif()

add_executable(pqc_x509_example main.cpp)
target_include_directories(pqc_x509_example PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(pqc_x509_example PRIVATE ${OPENSSL_CRYPTO_LIB} ${OPENSSL_SSL_LIB})
