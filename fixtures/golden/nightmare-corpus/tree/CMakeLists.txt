cmake_minimum_required(VERSION 3.22)
project(nightmare LANGUAGES C)

# Miniature of bomwerk/nightmare's root CMakeLists.txt: only the FetchContent
# declaration matters to a static scan. The commit is synthetic, per this suite's rule.
include(FetchContent)
FetchContent_Declare(
  tinyxml2
  GIT_REPOSITORY https://github.com/leethomason/tinyxml2.git
  GIT_TAG        7e6d5c4b3a291807f6e5d4c3b2a1908f7e6d5c4b # 9.0.0
)
