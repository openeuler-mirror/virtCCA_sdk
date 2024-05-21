# CMake version
cmake_minimum_required(VERSION 3.5.1)

# Project
project(gen_rim_ref)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
find_package(OpenSSL REQUIRED)

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

# Generate excutable
add_executable(${PROJECT_NAME} ${SOURCES})
target_compile_definitions(${PROJECT_NAME} PRIVATE LOG_PRINT=0)
target_include_directories(${PROJECT_NAME} PRIVATE ${INCLUDE_DIRS})
target_link_libraries(${PROJECT_NAME} OpenSSL::SSL OpenSSL::Crypto)

if(BUILD_RIM_GEN)
    message(STATUS "Build gen_rim_ref: on")
endif()
