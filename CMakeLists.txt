CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

SET (PROJECT_ROOT ${CMAKE_CURRENT_LIST_DIR})
SET(CMAKE_VERBOSE_MAKEFILE ON)

IF(NOT CMAKE_BUILD_TYPE)
    SET(CMAKE_BUILD_TYPE "RELEASE")
ENDIF(NOT CMAKE_BUILD_TYPE)

IF(${CMAKE_BUILD_TYPE} STREQUAL "RELEASE")
    SET(FORTITY_OPTIONS_COMPILER "-fstack-protector-strong -Wl,-z,relro -D_FORTIFY_SOURCE=2 -fPIE")
    SET(FORTITY_OPTIONS_LINKER "-pie")
ELSE()
    SET(FORTITY_OPTIONS_COMPILER " ")
    SET(FORTITY_OPTIONS_LINKER " ")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wp,-U_FORTIFY_SOURCE")
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wp,-U_FORTIFY_SOURCE")
ENDIF()

IF("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 4.7)
    SET(CXX_STD "c++0x")
ELSE()
    SET(CXX_STD "c++11")
ENDIF()

SET(COMPILE_BASE_FLAGS		"-Werror -Wall")

if (DEFINED __TIZEN__)
    SET(COMPILE_BASE_FLAGS "${COMPILE_BASE_FLAGS} -D__TIZEN__ ")
endif (DEFINED __TIZEN__)

SET(CMAKE_C_FLAGS_DEBUG		"${COMPILE_BASE_FLAGS} -O0 -ggdb")
SET(CMAKE_CXX_FLAGS_DEBUG	"${COMPILE_BASE_FLAGS} -O0 -ggdb -std=${CXX_STD}")
SET(CMAKE_C_FLAGS_RELEASE	"${COMPILE_BASE_FLAGS} -O2 -DNDEBUG -g0")
SET(CMAKE_CXX_FLAGS_RELEASE	"${COMPILE_BASE_FLAGS} -O2 -DNDEBUG -g0 -std=${CXX_STD}")

INCLUDE(FindPkgConfig)

if (NOT DEFINED BIN_DIR)
    SET (BIN_DIR "/usr/apps/elfhook")
endif (NOT DEFINED BIN_DIR)

if (NOT DEFINED LIB_DIR)
    SET (LIB_DIR "/usr/local/lib")
endif (NOT DEFINED LIB_DIR)

if (NOT DEFINED MANIFESTDIR)
    SET (MANIFESTDIR "/usr/share/packages")
endif (NOT DEFINED MANIFESTDIR)

# ZZZ
#macro(print_all_variables)
#    message(STATUS "print_all_variables------------------------------------------{")
#    get_cmake_property(_variableNames VARIABLES)
#    foreach (_variableName ${_variableNames})
#        message(STATUS "${_variableName}=${${_variableName}}")
#    endforeach()
#    message(STATUS "print_all_variables------------------------------------------}")
#endmacro()
#print_all_variables()

add_subdirectory(libtest)
add_subdirectory(libelfmem)
add_subdirectory(elfhook)
