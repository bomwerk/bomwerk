cmake_minimum_required(VERSION 3.14)
project(bomwerk_golden_cmake_variables)

include(FetchContent)
include(ExternalProject)

# The version lives in cmake/dependencies.cmake, not in this file.
FetchContent_Declare(
  abseil
  GIT_REPOSITORY https://github.com/abseil/abseil-cpp
  GIT_TAG "${abseil-cpp-version}"
)
FetchContent_MakeAvailable(abseil)

# A name that is only a variable identifies nothing: dropped, with a warning.
ExternalProject_Add(${DEP_NAME} URL ${DEP_URL})

# A literal name with a variable URL: kept by name, without the URL.
ExternalProject_Add(curl_external URL ${FROM_ARCHIVE})
