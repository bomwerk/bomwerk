cmake_minimum_required(VERSION 3.14)
project(bomwerk_known_vulnerable_fixture)

# known-vulnerable fixture: a commit-pinned FetchContent dependency whose
# purl (pkg:github/harfbuzz/harfbuzz@<sha>) OSV's global commit index
# actually resolves — verified directly against the live API. This specific
# commit predates HarfBuzz's fix for CVE-2023-25193 (and two others), and is
# OSV's own documented example commit for demonstrating commit-based
# querying, so it is not expected to ever stop matching.
include(FetchContent)
FetchContent_Declare(
  harfbuzz
  GIT_REPOSITORY https://github.com/harfbuzz/harfbuzz.git
  GIT_TAG 6879efc2c1596d11a6a6ad296f80063b558d5e0f
)
FetchContent_MakeAvailable(harfbuzz)
