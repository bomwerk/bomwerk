cmake_minimum_required(VERSION 3.14)
project(bomwerk_golden_mixed)

include(FetchContent)

# The same fmt that .gitmodules vendors at third_party/fmt, at the same commit.
# Two producers therefore observe the same identity (pkg:github/fmtlib/fmt@<sha>)
# from two different files, and core::merge_all must fold them into ONE
# component carrying both observations. If the merge ever regresses, this
# document grows a second fmt entry and the snapshot diff says so -- which no
# per-producer unit test can see, because neither producer is wrong on its own.
FetchContent_Declare(
  fmt
  GIT_REPOSITORY https://github.com/fmtlib/fmt.git
  GIT_TAG 2d1e2f3a4b5c6d7e8f90a1b2c3d4e5f607182930
)
FetchContent_MakeAvailable(fmt)
