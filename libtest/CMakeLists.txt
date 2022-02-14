cmake_minimum_required(VERSION 2.8)

project(test C CXX)

file(GLOB LIB_SRCS *.c *.cpp)

add_library (${PROJECT_NAME} SHARED ${LIB_SRCS})

include_directories(SYSTEM)

set_target_properties(${PROJECT_NAME} PROPERTIES COMPILE_FLAGS ${FORTITY_OPTIONS_COMPILER})

install(TARGETS ${PROJECT_NAME} DESTINATION ${LIB_DIR})
