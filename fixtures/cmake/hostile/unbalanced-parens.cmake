# The call never closes — scanner must warn and not read past EOF.
FetchContent_Declare(dep
  GIT_REPOSITORY https://github.com/acme/dep.git
  GIT_TAG v1.0
