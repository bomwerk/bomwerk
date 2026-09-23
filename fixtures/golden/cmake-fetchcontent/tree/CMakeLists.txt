cmake_minimum_required(VERSION 3.14)
project(bomwerk_golden_cmake)

include(FetchContent)

# Pinned to a commit: immutable, so the producer rates this High.
FetchContent_Declare(
  fmt
  GIT_REPOSITORY https://github.com/fmtlib/fmt.git
  GIT_TAG 0f1e2d3c4b5a69788796a5b4c3d2e1f009182736
)

# Pinned to a tag: a tag can be moved, so the producer rates this Medium.
FetchContent_Declare(
  spdlog
  GIT_REPOSITORY https://github.com/gabime/spdlog.git
  GIT_TAG v1.14.1
)

# Both are made available: a declaration that never reaches MakeAvailable is
# reported at reduced confidence WITH a warning, which would degrade this case
# to exit 1. Keeping it clean is the point -- the degraded path is covered by
# the gitmodules-pinned case.
FetchContent_MakeAvailable(fmt spdlog)

include(cmake/deps.cmake)
