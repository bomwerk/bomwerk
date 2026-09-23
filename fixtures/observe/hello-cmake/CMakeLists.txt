# Smallest project that still produces a real compile and a real link, which
# is all the end-to-end observe check needs. C rather than C++ keeps the build fast
# and exercises the `cc` shim, the one every toolchain has.
cmake_minimum_required(VERSION 3.22)
project(bomwerk_observe_fixture LANGUAGES C)

add_library(greeting STATIC greeting.c)
add_executable(hello hello.c)
target_link_libraries(hello PRIVATE greeting)
