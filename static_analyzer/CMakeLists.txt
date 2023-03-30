cmake_minimum_required(VERSION 3.24)
project(StaticAnalyser)

set(CMAKE_CXX_STANDARD 14)

find_package(LLVM 14 REQUIRED CONFIG)
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -fno-rtti -fPIC -Wall")
include_directories(${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})
link_directories(${LLVM_LIBRARY_DIRS})

llvm_map_components_to_libnames(llvm_libs support core irreader analysis passes)

add_executable(StaticAnalyser main.cpp DataFlowGraph.cpp)
target_link_libraries(StaticAnalyser ${llvm_libs})

add_executable(StaticAnalyser2 main2.cpp DataFlowGraph.cpp)
target_link_libraries(StaticAnalyser2 ${llvm_libs})