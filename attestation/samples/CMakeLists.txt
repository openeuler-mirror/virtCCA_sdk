cmake_minimum_required(VERSION 3.20)
project(tsi-samples
    LANGUAGES C)

find_package(OpenSSL REQUIRED)

include_directories(
    include
    QCBOR/inc
    t_cose/inc
)

add_executable(server src/server.c)
target_link_libraries(server vccaattestation)

add_executable(client src/client.c src/token_parse.c src/token_validate.c src/utils.c)
target_link_libraries(client t_cose qcbor)
target_link_libraries(client OpenSSL::Crypto)
target_link_libraries(client m)

target_link_directories(client PRIVATE QCBOR t_cose/build)
