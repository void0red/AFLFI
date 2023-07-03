cmake_minimum_required(VERSION 3.22)
project(analyzer)

set(CMAKE_CXX_STANDARD 14)

if (DEFINED ENV{LLVM_HOME})
    set(LLVM_HOME ENV{LLVM_HOME})
else ()
    set(LLVM_HOME /usr/lib/llvm14)
endif ()

find_package(LLVM 14 REQUIRED CONFIG PATHS ${LLVM_HOME})
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -fno-rtti -fPIC -Wall")
include_directories(${LLVM_INCLUDE_DIRS})
separate_arguments(LLVM_DEFINITIONS_LIST NATIVE_COMMAND ${LLVM_DEFINITIONS})
add_definitions(${LLVM_DEFINITIONS_LIST})

execute_process(COMMAND llvm-config --shared-mode
        WORKING_DIRECTORY ${LLVM_HOME}/bin
        OUTPUT_VARIABLE SHARED_MODE
        OUTPUT_STRIP_TRAILING_WHITESPACE)

if (SHARED_MODE STREQUAL "shared")
    message(STATUS "use LLVM shared link")
    set(USE_SHARED USE_SHARED)
else ()
    message(STATUS "use LLVM static link")
endif ()

add_executable(analyzer analyzer.cpp)
llvm_config(analyzer ${USE_SHARED} support core irreader passes)