cmake_minimum_required(VERSION 3.0)
project(openssl-aes256)

find_package(OpenSSL REQUIRED)

set(SOURCE_FILES native/aes256sample.c)

add_executable(openssl-aes256 ${SOURCE_FILES})

target_link_libraries(openssl-aes256 OpenSSL::SSL OpenSSL::Crypto)

# test key
# 23721d6f7972b642596471e055f6a04e


#void print_hex(const U8 *data, size_t size) {
#    for (size_t i = 0; i < size; i++) {
#        printf("%02x ", data[i]);
#    }
#    printf("\n");
#}
#printf("Ciphertext: ");
#print_hex(ciphertext, sizeof(message));