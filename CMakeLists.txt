cmake_minimum_required(VERSION 3.15)

project("elfhook"
    VERSION 0.0.1
    DESCRIPTION "ElfHook Project"
)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (DEFINED __TIZEN__)
    set(CMAKE_C_FLAGS_DEBUG	"${CMAKE_C_FLAGS_DEBUG} -D__TIZEN__ ")
    set(CMAKE_CXX_FLAGS_DEBUG	"${CMAKE_CXX_FLAGS_DEBUG} -D__TIZEN__ ")
    set(CMAKE_C_FLAGS_RELEASE	"${CMAKE_C_FLAGS_RELEASE} -D__TIZEN__ ")
    set(CMAKE_CXX_FLAGS_RELEASE	"${CMAKE_CXX_FLAGS_RELEASE} -D__TIZEN__ ")
endif()

add_subdirectory(libraries)

add_executable(${PROJECT_NAME})

target_sources(${PROJECT_NAME}
    PRIVATE
        elfhook.cpp
)

include(FindPkgConfig)
if(DEFINED __TIZEN__)
    pkg_check_modules(APP_DEPS REQUIRED dlog)
endif()

target_include_directories(${PROJECT_NAME}
    PRIVATE
        # where the library itself will look for its internal headers
	${APP_DEPS_INCLUDE_DIRS}
	${CMAKE_CURRENT_SOURCE_DIR}/common/inc
)

target_link_libraries(${PROJECT_NAME} PRIVATE ${APP_DEPS_LIBRARIES} elfmem test)

if (NOT DEFINED BIN_DIR)
    SET (BIN_DIR "/usr/apps/elfhook")
endif()

if (NOT DEFINED MANIFESTDIR)
    SET (MANIFESTDIR "/usr/share/packages")
endif()

install(TARGETS ${PROJECT_NAME} DESTINATION ${BIN_DIR})
install(FILES ${PROJECT_NAME}.manifest DESTINATION ${MANIFESTDIR})
