cmake_minimum_required(VERSION 3.14)
project(libfoo)

include(FetchContent)

# libfoo's OWN dependency, not this project's. Reporting it would be the vcpkg
# bug this case exists for: a foreign project's dependency catalogue is not our
# SBOM. MakeAvailable is called so that, under --include-submodule-contents,
# the deep walk still exits 0 rather than warning about an unused declaration.
FetchContent_Declare(
  catch2
  GIT_REPOSITORY https://github.com/catchorg/Catch2.git
  GIT_TAG 7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d
)
FetchContent_MakeAvailable(catch2)
