cmake_minimum_required(VERSION 3.15)

set(namespace "elffuzz")
project("elffuzz"
    VERSION 0.0.1
    DESCRIPTION "ElfFuzz Library"
)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(${PROJECT_NAME} STATIC)

target_sources(${PROJECT_NAME}
    PRIVATE
        src/elffuzz.cpp
        src/libelffuzz.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../elfmem/src/elfmem.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../elfmem/src/elfutils.cpp
)

include(FindPkgConfig)
if (DEFINED __TIZEN__)
    pkg_check_modules(LIB_DEPS REQUIRED dlog)
endif (DEFINED __TIZEN__)

target_include_directories(${PROJECT_NAME}
    PRIVATE
        # where the library itself will look for its internal headers
	${LIB_DEPS_INCLUDE_DIRS}
        ${CMAKE_CURRENT_SOURCE_DIR}/inc
        ${CMAKE_CURRENT_SOURCE_DIR}/../elfmem/inc
	${CMAKE_CURRENT_SOURCE_DIR}/../../common/inc
    PUBLIC
        # where top-level project will look for the library's public headers
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/inc>
        # where external projects will look for the library's public headers
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

# without it public headers won't get installed
set(public_headers
    inc/elffuzz_def.h
    inc/libelffuzz.h
)

# not for MSVC
if(CMAKE_COMPILER_IS_GNUCXX)
    # compile options for this target only
    # treat warnings as errors
    target_compile_options(${PROJECT_NAME} PRIVATE -Werror)
endif()

# where to find our CMake modules
# set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
# message(STATUS "CMake module path: ${CMAKE_MODULE_PATH}")
# include(Installing)

# for CMAKE_INSTALL_LIBDIR, CMAKE_INSTALL_BINDIR, CMAKE_INSTALL_INCLUDEDIR and others
include(GNUInstallDirs)

# note that ${public_headers} should be in quotes
set_target_properties(${PROJECT_NAME} PROPERTIES PUBLIC_HEADER "${public_headers}")

install(TARGETS ${PROJECT_NAME}
    EXPORT "${PROJECT_NAME}Targets"
    # these get default values from GNUInstallDirs, no need to set them
    #RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} # bin
    #LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} # lib
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} # lib
    # except for public headers, as we want them to be inside a library folder
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME} # include/SomeProject
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR} # include
)
