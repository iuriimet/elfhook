cmake_minimum_required(VERSION 2.8)
get_filename_component(ProjectId ${CMAKE_CURRENT_SOURCE_DIR} NAME)
string(REPLACE " " "_" ProjectId ${ProjectId})

project(elfhook)

if(DEFINED DEBUG)
        SET(CMAKE_BUILD_TYPE "Debug")
        SET(CFLAGS " -O0 -g ")
        SET(CXXFLAGS " -O0 -g ")
        SET(CMAKE_C_FLAGS ${CFLAGS})
        SET(CMAKE_CXX_FLAGS ${CXXFLAGS})
else()
	SET(CMAKE_BUILD_TYPE "Release")
endif()
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

include_directories(${CMAKE_SOURCE_DIR}/inc ${CMAKE_SOURCE_DIR}/lib)

FILE(GLOB SRCS src/*.c src/*.cpp)
add_executable(${PROJECT_NAME} ${SRCS})

add_library(TEST_LIB SHARED ${CMAKE_SOURCE_DIR}/lib/libtest.c)
set_property(TARGET TEST_LIB PROPERTY POSITION_INDEPENDENT_CODE ON)
target_link_libraries(${PROJECT_NAME} pthread dl TEST_LIB)

message(STATUS "Configuring: " ${ProjectId})
message(STATUS "CMAKE_C_FLAGS: " ${CMAKE_C_FLAGS})
message(STATUS "CMAKE_CXX_FLAGS: " ${CMAKE_CXX_FLAGS})
