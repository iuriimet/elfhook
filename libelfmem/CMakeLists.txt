cmake_minimum_required(VERSION 2.8)

project(elfmem C CXX)

file(GLOB LIB_SRCS src/*.c src/*.cpp)

add_library (${PROJECT_NAME} STATIC ${LIB_SRCS})

if (DEFINED __TIZEN__)
    pkg_check_modules(LIB_DEPS REQUIRED dlog)
endif (DEFINED __TIZEN__)

include_directories(SYSTEM ${LIB_DEPS_INCLUDE_DIRS})
include_directories(inc ../common/inc)

set_target_properties(${PROJECT_NAME} PROPERTIES COMPILE_FLAGS ${FORTITY_OPTIONS_COMPILER})
