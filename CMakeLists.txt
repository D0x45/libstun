cmake_minimum_required(VERSION 3.10)
project(libstun)

set(CMAKE_C_STANDARD "99")
set(CMAKE_C_FLAGS "-Wall -Wpedantic -Wextra -Wconversion")

if (NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  message("WARNING: not using clang! adding -fshort-enums to cflags!")
  set(CMAKE_C_FLAGS "-fshort-enums ${CMAKE_C_FLAGS}")
endif()

set(CMAKE_C_FLAGS_DEBUG "-g ${CMAKE_C_FLAGS}")
set(CMAKE_C_FLAGS_RELEASE "-O2 ${CMAKE_C_FLAGS}")

file(GLOB SOURCES "src/*.c")

include_directories("include")

if(WIN32)
    target_link_libraries(stun ws2_32)
endif()

add_library(stun STATIC ${SOURCES})
