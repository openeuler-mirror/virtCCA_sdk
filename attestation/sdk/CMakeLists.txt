cmake_minimum_required(VERSION 3.16)
project(virtcca-sdk
    LANGUAGES C)

set(CMAKE_INSTALL_PREFIX /usr/local)

add_library(vccaattestation)

target_sources(vccaattestation PRIVATE src/attestation.c)

target_include_directories(vccaattestation
    PUBLIC include
    PRIVATE src
)

set_target_properties(vccaattestation PROPERTIES PUBLIC_HEADER include/attestation.h)

install(TARGETS vccaattestation
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        PUBLIC_HEADER ${CMAKE_INSTALL_INCLUDEDIR}
)
