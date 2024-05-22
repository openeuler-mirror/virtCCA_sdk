cmake_minimum_required(VERSION 3.20)
project(virtcca-sdk
    LANGUAGES C)

set(CMAKE_INSTALL_PREFIX /usr/local)
set(targetname hukderive)

add_library(${targetname} SHARED)

target_sources(${targetname} PRIVATE src/huk_derive.c)

target_include_directories(${targetname} PUBLIC inc)

set_target_properties(${targetname} PROPERTIES PUBLIC_HEADER inc/huk_derive.h)

install(TARGETS ${targetname}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        PUBLIC_HEADER ${CMAKE_INSTALL_INCLUDEDIR}
)