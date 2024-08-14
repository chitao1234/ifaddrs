cmake_minimum_required(VERSION 3.10)

project(ifaddrs VERSION 1.0.0)

set(sources src/ifaddrs.c)
set(private_includes src/include)
set(includes include)

include_directories(
    ${private_includes}
)

add_library(ifaddrs_static STATIC
    ${sources}
)
target_include_directories(ifaddrs_static PUBLIC
    ${includes}
)
set_target_properties(ifaddrs_static PROPERTIES OUTPUT_NAME ifaddrs)



add_library(ifaddrs_shared SHARED
    ${sources}
)
target_include_directories(ifaddrs_shared PUBLIC
    ${includes}
)
set_target_properties(ifaddrs_shared PROPERTIES OUTPUT_NAME ifaddrs)
