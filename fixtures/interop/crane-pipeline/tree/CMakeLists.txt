cmake_minimum_required(VERSION 3.14)
project(bomwerk_interop_demo)

include(FetchContent)

# A second, distinct git-based dependency (the submodule above already covers
# fmt) so this fixture exercises cmake_deps' own owner-attribution path, not
# just submodules'.
FetchContent_Declare(
  spdlog
  GIT_REPOSITORY https://github.com/gabime/spdlog.git
  GIT_TAG 1a2b3c4d5e6f7089badc0ffee1234567890abcde
)
FetchContent_MakeAvailable(spdlog)
