cmake_minimum_required(VERSION 3.10)

project(ifaddrs VERSION 1.0.0)

set(SOURCES 
  src/ifaddrs.c
)
set(HEADERS 
  include/ifaddrs.h
  src/include/ifaddrs_internal.h
  src/include/macros.h
)
set(PRIVATE_HEADER_DIRS
  src/include
)
set(HEADER_DIRS
  include
)

include_directories(
  ${PRIVATE_HEADER_DIRS}
)

add_library(ifaddrs_static STATIC
    ${SOURCES}
    ${HEADERS}
)
target_include_directories(ifaddrs_static PUBLIC
  ${HEADER_DIRS}
)
set_target_properties(ifaddrs_static PROPERTIES OUTPUT_NAME ifaddrs)



add_library(ifaddrs_shared SHARED
    ${SOURCES}
    ${HEADERS}
)
target_include_directories(ifaddrs_shared PUBLIC
  ${HEADER_DIRS}
)
set_target_properties(ifaddrs_shared PROPERTIES OUTPUT_NAME ifaddrs)
