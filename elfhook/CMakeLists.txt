cmake_minimum_required (VERSION 2.8)

project(elfhook C CXX)

file(GLOB APP_SRCS *.c *.cpp)

add_executable(${PROJECT_NAME} ${APP_SRCS})
add_dependencies(${PROJECT_NAME} elfmem)
add_dependencies(${PROJECT_NAME} test)

if (DEFINED __TIZEN__)
    pkg_check_modules(APP_DEPS REQUIRED dlog)
endif (DEFINED __TIZEN__)

include_directories(SYSTEM ${APP_DEPS_INCLUDE_DIRS})
include_directories(. ../common/inc ../libtest ../libelfmem/inc)

target_link_libraries(${PROJECT_NAME} elfmem test ${APP_DEPS_LIBRARIES} pthread dl)

set_target_properties(${PROJECT_NAME} PROPERTIES COMPILE_FLAGS ${FORTITY_OPTIONS_COMPILER})
set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS ${FORTITY_OPTIONS_LINKER})

install(TARGETS ${PROJECT_NAME} DESTINATION ${BIN_DIR})
install(FILES ${PROJECT_NAME}.manifest DESTINATION ${MANIFESTDIR})
