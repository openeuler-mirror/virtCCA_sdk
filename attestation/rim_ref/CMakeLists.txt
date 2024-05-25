# CMake version
cmake_minimum_required(VERSION 3.5.1)

# Project
project(gen_rim_ref)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(GLIB REQUIRED glib-2.0)
pkg_check_modules(GOBJECT REQUIRED gobject-2.0)

# Build mode
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

# Build options
option(BUILD_RIM_GEN "Compile rim reference generator" ON)


# Set install path
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/output)
set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})

# Set include directory
set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/inc
                 )
# Set source file
set(SOURCES src/gen_rim_ref.c
            )
#GLIB
include_directories(${GLIB_INCLUDE_DIRS} ${GOBJECT_INCLUDE_DIRS})
link_directories(${GLIB_LIBRARY_DIRS} ${GOBJECT_LIBRARY_DIRS})

# Generate excutable
add_executable(${PROJECT_NAME} ${SOURCES})
target_compile_definitions(${PROJECT_NAME} PRIVATE LOG_PRINT=0)
target_include_directories(${PROJECT_NAME} PRIVATE ${INCLUDE_DIRS})
target_link_libraries(${PROJECT_NAME} OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(${PROJECT_NAME} ${GLIB_LIBRARIES} ${GOBJECT_LIBRARIES})

if(BUILD_RIM_GEN)
    message(STATUS "Build gen_rim_ref: on")
endif()
