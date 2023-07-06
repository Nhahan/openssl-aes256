cmake_minimum_required(VERSION 3.0)
project(openssl-aes256)

find_package(OpenSSL REQUIRED)

set(SOURCE_FILES native/aes256sample.c)

add_executable(openssl-aes256 ${SOURCE_FILES})

target_link_libraries(openssl-aes256 OpenSSL::SSL OpenSSL::Crypto)
