cmake_minimum_required(VERSION 3.15)

set(namespace "test")
project("test"
    VERSION 0.0.1
    DESCRIPTION "Test Library"
)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(${PROJECT_NAME} SHARED)

if (DEFINED __TIZEN__)
    set(CMAKE_C_FLAGS_DEBUG	"${CMAKE_C_FLAGS_DEBUG} -D__TIZEN__ ")
    set(CMAKE_CXX_FLAGS_DEBUG	"${CMAKE_CXX_FLAGS_DEBUG} -D__TIZEN__ ")
    set(CMAKE_C_FLAGS_RELEASE	"${CMAKE_C_FLAGS_RELEASE} -D__TIZEN__ ")
    set(CMAKE_CXX_FLAGS_RELEASE	"${CMAKE_CXX_FLAGS_RELEASE} -D__TIZEN__ ")
endif()

target_sources(${PROJECT_NAME}
    PRIVATE
        libtest.cpp
)

target_include_directories(${PROJECT_NAME}
    PRIVATE
        # where the library itself will look for its internal headers
        ${CMAKE_CURRENT_SOURCE_DIR}
    PUBLIC
        # where top-level project will look for the library's public headers
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        # where external projects will look for the library's public headers
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

# without it public headers won't get installed
set(public_headers
    libtest.h
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

if(DEFINED INSTALLDIR)
    set(CMAKE_INSTALL_PREFIX ${INSTALLDIR})
endif()

# note that ${public_headers} should be in quotes
set_target_properties(${PROJECT_NAME} PROPERTIES PUBLIC_HEADER "${public_headers}")

install(TARGETS ${PROJECT_NAME}
    EXPORT "${PROJECT_NAME}Targets"
    # these get default values from GNUInstallDirs, no need to set them
    #RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} # bin
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} # lib
    #ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} # lib
    # except for public headers, as we want them to be inside a library folder
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME} # include/SomeProject
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR} # include
)

