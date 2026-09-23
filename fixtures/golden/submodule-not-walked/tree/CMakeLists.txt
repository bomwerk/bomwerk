cmake_minimum_required(VERSION 3.14)
project(bomwerk_golden_submodule_scope)

include(FetchContent)

# The superproject's own dependency. It exists so this case proves the walk is
# SCOPED, not switched off: this declaration must appear in the snapshot while
# the identical-looking one inside third_party/libfoo (the submodule) must not.
FetchContent_Declare(
  spdlog
  GIT_REPOSITORY https://github.com/gabime/spdlog.git
  GIT_TAG 4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e
)
FetchContent_MakeAvailable(spdlog)
