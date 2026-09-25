cmake_minimum_required(VERSION 3.22)

# Dependencies come only from vcpkg.json (docs/CONTRIBUTING.md hard rule 4). The vcpkg
# submodule pins the ports tree so CI and local builds resolve identical
# versions; override with -DCMAKE_TOOLCHAIN_FILE=... to use a system vcpkg.
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  set(bomwerk_vendored_toolchain
      "${CMAKE_CURRENT_SOURCE_DIR}/vcpkg/scripts/buildsystems/vcpkg.cmake")
  # `git clone` without --recurse-submodules leaves vcpkg/ empty, and CMake's
  # own message for a missing toolchain file does not say why. Say it here.
  if(NOT EXISTS "${bomwerk_vendored_toolchain}")
    message(FATAL_ERROR
            "The vendored vcpkg submodule is not checked out, so dependencies "
            "cannot be resolved.\n"
            "  Run:  git submodule update --init --recursive\n"
            "Or build against a vcpkg you already have:\n"
            "  cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake")
  endif()
  set(CMAKE_TOOLCHAIN_FILE "${bomwerk_vendored_toolchain}"
      CACHE STRING "Vcpkg toolchain file")
endif()

# Version source of truth. vcpkg.json's "version-string" is a SEPARATE copy
# (vcpkg has no way to read this file): bump both together.
project(bomwerk VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# KNOWN HAZARD (not fixed, deliberately): macOS Command Line Tools clang
# hardcodes /usr/local/include (Homebrew) as the first include search path,
# ahead of any -isystem flag CMake emits for vcpkg packages. If a vcpkg
# dependency is ALSO installed via Homebrew (e.g. spdlog was here), Homebrew's
# copy silently wins: a rule-4 reproducibility risk. Forcing plain -I via
# CMAKE_NO_SYSTEM_FROM_IMPORTED fixes the resolution but loses -isystem's
# warning suppression for third-party headers, which surfaced an unrelated
# spdlog/fmt upstream -Wdeprecated-declarations break; reverted for now.
# If this bites again: `brew uninstall spdlog fmt` (or unlink) removes the
# collision without touching build flags.

option(BOMWERK_WERROR   "Treat warnings as errors" ON)
option(BOMWERK_SANITIZE "Enable ASan+UBSan"        OFF)
option(BOMWERK_PRO "Build proprietary registry, monitor, triage, report, and licensing features" OFF)
set(BOMWERK_PRO_SOURCE_DIR "" CACHE PATH
    "Private extension source root; required only when BOMWERK_PRO=ON")

if(BOMWERK_PRO)
  if(BOMWERK_PRO_SOURCE_DIR STREQUAL "")
    message(FATAL_ERROR
            "BOMWERK_PRO=ON requires -DBOMWERK_PRO_SOURCE_DIR=<path to the private extension checkout>")
  endif()
  cmake_path(ABSOLUTE_PATH BOMWERK_PRO_SOURCE_DIR
             BASE_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
             NORMALIZE OUTPUT_VARIABLE BOMWERK_PRO_SOURCE_DIR)
  cmake_path(IS_PREFIX CMAKE_CURRENT_SOURCE_DIR "${BOMWERK_PRO_SOURCE_DIR}"
             NORMALIZE bomwerk_pro_source_inside_core)
  if(bomwerk_pro_source_inside_core)
    message(FATAL_ERROR
            "BOMWERK_PRO_SOURCE_DIR must be outside the public bomwerk source tree")
  endif()
  if(NOT EXISTS "${BOMWERK_PRO_SOURCE_DIR}/CMakeLists.txt")
    message(FATAL_ERROR
            "BOMWERK_PRO_SOURCE_DIR does not contain the private extension CMakeLists.txt: ${BOMWERK_PRO_SOURCE_DIR}")
  endif()
endif()

add_compile_options(-Wall -Wextra -Wpedantic)
if(BOMWERK_WERROR)
  add_compile_options(-Werror)
endif()
if(BOMWERK_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address,undefined)
endif()

find_package(CLI11 CONFIG REQUIRED)
find_package(spdlog CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
if(BOMWERK_PRO)
  # OpenSSL is a direct dependency only of the private Ed25519 verifier.
  find_package(OpenSSL 3.0 CONFIG REQUIRED)
endif()
find_package(CURL CONFIG REQUIRED)
find_package(unofficial-sqlite3 CONFIG REQUIRED)
find_package(tomlplusplus CONFIG REQUIRED)

add_library(bomwerk_core
  src/core/base64.cpp
  src/core/cvss.cpp
  src/core/exclusions.cpp
  src/core/file_index.cpp
  src/core/file_io.cpp
  src/core/git_config.cpp
  src/core/git_dir.cpp
  src/core/git_url.cpp
  src/core/json_utils.cpp
  src/core/logging.cpp
  src/core/manifest_names.cpp
  src/core/manifest_walk.cpp
  src/core/match_coverage.cpp
  src/core/model.cpp
  src/core/name_list.cpp
  src/core/percent.cpp
  src/core/purl.cpp
  src/core/scan_config.cpp
  src/core/submodule_paths.cpp
  src/core/text.cpp
  src/core/timestamp.cpp
  src/core/uuid.cpp
  src/core/warning_code.cpp
  src/core/yaml_subset.cpp)
target_include_directories(bomwerk_core PUBLIC src)
# Logging is cross-cutting; spdlog is part of core's public surface. toml++ is
# PRIVATE (only scan_config.cpp parses TOML in core); the exceptions caveat on
# the bomwerk_parsers target below applies here identically.
target_link_libraries(bomwerk_core PUBLIC spdlog::spdlog
                                   PRIVATE tomlplusplus::tomlplusplus)

# Producers (parsers|heuristics|observe|binscan). Linking only bomwerk_core
# enforces the dependency direction in the build, not just in review: a parser
# that tried to include vuln|output|cli would fail to link.
add_library(bomwerk_parsers
  src/parsers/ci/github_actions.cpp
  src/parsers/cpp/cmake_deps.cpp
  src/parsers/cpp/cmake_scanner.cpp
  src/parsers/cpp/conan.cpp
  src/parsers/cpp/conan_ref.cpp
  src/parsers/cpp/submodules.cpp
  src/parsers/cpp/vcpkg.cpp
  src/parsers/lockfiles/cargo.cpp
  src/parsers/lockfiles/composer.cpp
  src/parsers/lockfiles/go.cpp
  src/parsers/lockfiles/maven.cpp
  src/parsers/lockfiles/npm.cpp
  src/parsers/lockfiles/nuget.cpp
  src/parsers/lockfiles/pnpm.cpp
  src/parsers/lockfiles/pub.cpp
  src/parsers/lockfiles/python.cpp
  src/parsers/lockfiles/rubygems.cpp
  src/parsers/lockfiles/yarn.cpp)
target_link_libraries(bomwerk_parsers
  PUBLIC bomwerk_core
  PRIVATE nlohmann_json::nlohmann_json tomlplusplus::tomlplusplus)
# vcpkg's tomlplusplus port bakes -DTOML_HEADER_ONLY=0 into the imported
# target's interface and ships libtomlplusplus.a precompiled with the
# library's default (exceptions-enabled) configuration: only the throwing
# toml::v3::parse entry points exist in that archive, not the noex
# non-throwing ones. Overriding TOML_EXCEPTIONS on our own target cannot
# change the ABI of a binary vcpkg already compiled, so the TOML parsers use
# the throwing API and confine the catch to one function each (see
# python.cpp and cargo.cpp).

# Heuristics (parsers|heuristics|observe|binscan): evidence with no manifest
# behind it (vendored third_party/vendor C/C++ source). Linking only
# bomwerk_core keeps the same one-way dependency direction as bomwerk_parsers
#: a heuristic that tried to include parsers|vuln|output|cli would
# fail to link, which is also why the vendored-code heuristic reuses the
# git-dir/git-config/git-url primitives from core rather than
# parsers/cpp/submodules.cpp.
add_library(bomwerk_heuristics
  src/heuristics/vendored_cpp.cpp)
target_link_libraries(bomwerk_heuristics PUBLIC bomwerk_core)

# Producers (parsers|heuristics|observe|binscan): the build observer.
# Deliberately split in two, and the split is the design:
#
#   bomwerk_observe_trace is what the SHIM links. The shim impersonates the
#   compiler, so it is exec'd once per compile: thousands of times in a real
#   build. It therefore links NOTHING: no bomwerk_core, no spdlog, no JSON
#   library. Its whole startup is getcwd + one locked write + execv. Keep it
#   that way; anything added here is paid for on every compile in the build.
#
#   bomwerk_observe is the parent-side half (shim setup, spawning the build,
#   validating the trace) and links bomwerk_core like every other producer, so
#   the one-way dependency direction still holds in the build, not just review.
add_library(bomwerk_observe_trace
  src/observe/shim_names.cpp
  src/observe/trace_line.cpp
  src/observe/trace_writer.cpp)
target_include_directories(bomwerk_observe_trace PUBLIC src)

add_executable(bomwerk-shim src/observe/shim_main.cpp)
target_link_libraries(bomwerk-shim PRIVATE bomwerk_observe_trace)

add_library(bomwerk_observe
  src/observe/compile_map.cpp
  src/observe/link_map.cpp
  src/observe/run_build.cpp
  src/observe/shim_dir.cpp
  src/observe/trace_check.cpp
  src/observe/trace_read.cpp)
target_link_libraries(bomwerk_observe
  PUBLIC bomwerk_core bomwerk_observe_trace
  PRIVATE nlohmann_json::nlohmann_json)

# Producers (parsers|heuristics|observe|binscan): the binary pass. Reads
# the artifacts a build WROTE -- ELF dynamic dependencies, `ar` member names,
# an exported-symbol sample -- where observe reads the command lines that wrote
# them. Linking only bomwerk_core keeps the same one-way dependency direction
# as every other producer, and it is load-bearing here: binscan is handed
# PATHS, never trace records, so it cannot include bomwerk_observe even by
# accident, and it stays testable without a trace or a repository.
#
# There is deliberately NO third-party ELF library in this target. bomwerk
# scans itself (rule 4's own justification), so every dependency is also a
# component in our SBOM and a standing CVE surface; what this pass needs is a
# read-only slice of a fixed-width format, which byte_cursor.hpp bounds-checks
# in one reviewable place. That is also the stronger answer to rule 1 -- no
# third-party allocation on attacker-controlled sizes, and no try/catch
# anywhere in the module.
add_library(bomwerk_binscan
  src/binscan/archive_read.cpp
  src/binscan/binary_map.cpp
  src/binscan/elf_read.cpp
  src/binscan/sidecar.cpp)
target_link_libraries(bomwerk_binscan
  PUBLIC bomwerk_core
  PRIVATE nlohmann_json::nlohmann_json)

# Output writers (cyclonedx.cpp, spdx.cpp, html.cpp arrive over time). Linking
# only bomwerk_core enforces the same one-way dependency direction as
# parsers: a writer that tried to include parsers|vuln|cli would fail
# to link.
add_library(bomwerk_output
  src/output/coverage.cpp
  src/output/cra_sidecar.cpp
  src/output/cyclonedx.cpp
  src/output/html.cpp
  src/output/spdx.cpp
  src/output/spdx_license_ids.cpp
  src/output/warnings_report.cpp)
target_include_directories(bomwerk_output PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated")
target_link_libraries(bomwerk_output PUBLIC bomwerk_core PRIVATE nlohmann_json::nlohmann_json)

# SBOM readers: the inverse of bomwerk_output's writers, for anything that
# needs to load an already-generated SBOM back off disk (`trim` and `binscan`
# both do). Linking only bomwerk_core keeps the
# same one-way dependency direction as parsers/output/vuln: a producer that
# tried to include sbom would fail to
# link, and this stays its own module rather than living inside bomwerk_output
# so "output" keeps meaning "writers" for anyone reading the build.
add_library(bomwerk_sbom
  src/sbom/format.cpp
  src/sbom/read.cpp)
target_link_libraries(bomwerk_sbom PUBLIC bomwerk_core PRIVATE nlohmann_json::nlohmann_json)

# Vulnerability matching (OSV client + SQLite cache; NVD CPE
# fallback). Linking only bomwerk_core enforces the same one-way dependency
# direction as parsers and output; curl/sqlite3 stay PRIVATE so no other module
# can reach the network or the cache except through this module's interface.
# sqlite_support.cpp is the shared sqlite3 open/migrate/prepared-statement
# plumbing `vuln::cache.cpp` builds on; it lives here rather than in
# bomwerk_core because its public surface still names `sqlite3`/`sqlite3_stmt`.
# vuln is the only module that reaches sqlite3 (module dependency law,
# docs/CONTRIBUTING.md).
add_library(bomwerk_vuln
  src/vuln/cache.cpp
  src/vuln/cpe.cpp
  src/vuln/delta.cpp
  src/vuln/endpoints.cpp
  src/vuln/finding.cpp
  src/vuln/http_curl.cpp
  src/vuln/license_enrichment.cpp
  src/vuln/nvd.cpp
  src/vuln/osv.cpp
  src/vuln/sqlite_support.cpp)
target_link_libraries(bomwerk_vuln
  PUBLIC bomwerk_core
  PRIVATE nlohmann_json::nlohmann_json CURL::libcurl unofficial::sqlite3::sqlite3)

set(bomwerk_cli_common_sources
  src/cli/app.cpp
  src/cli/binscan_command.cpp
  src/cli/observe_command.cpp
  src/cli/observe_trim.cpp
  src/cli/scan_command.cpp
  src/cli/trim_command.cpp)

set(bomwerk_cli_libraries
  bomwerk_core bomwerk_parsers bomwerk_heuristics bomwerk_observe bomwerk_binscan
  bomwerk_output bomwerk_vuln bomwerk_sbom CLI11::CLI11)

add_executable(bomwerk ${bomwerk_cli_common_sources})
target_link_libraries(bomwerk PRIVATE ${bomwerk_cli_libraries})
if(NOT BOMWERK_PRO)
  target_sources(bomwerk PRIVATE src/cli/community_main.cpp)
endif()
# `bomwerk observe` looks for bomwerk-shim beside its own executable, so the
# shim must exist whenever bomwerk does: a missing shim is a runtime failure,
# not a link error, and this is what keeps it from ever happening.
add_dependencies(bomwerk bomwerk-shim)
# Single source of truth for the version is project() above.
target_compile_definitions(bomwerk PRIVATE BOMWERK_VERSION="${PROJECT_VERSION}")

enable_testing()

# One ctest per tests/unit/test_<name>.cpp. Extra arguments are additional
# libraries to link (e.g. bomwerk_parsers for producer tests). Every test can
# reach the vendored fixtures via the BOMWERK_FIXTURES_DIR compile definition
# and shared helpers under tests/support via the tests/ include path.
function(bomwerk_add_test test_name)
  add_executable(test_${test_name} tests/unit/test_${test_name}.cpp)
  target_link_libraries(test_${test_name} PRIVATE bomwerk_core ${ARGN})
  target_include_directories(test_${test_name} PRIVATE tests)
  target_compile_definitions(test_${test_name}
    PRIVATE BOMWERK_FIXTURES_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures")
  add_test(NAME ${test_name} COMMAND test_${test_name})
endfunction()

if(BOMWERK_PRO)
  set(BOMWERK_CORE_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
  add_subdirectory("${BOMWERK_PRO_SOURCE_DIR}" "${CMAKE_CURRENT_BINARY_DIR}/private-extension")
endif()

# Core-only tests link just bomwerk_core (the default).
foreach(bomwerk_test_name IN ITEMS model manifest_names sbom_format exclusions name_list percent
                                  purl match_coverage text file_io file_index manifest_walk timestamp
                                  uuid base64
                                  cvss git_config git_dir git_url scan_config unparsed_manifests
                                  yaml_subset warning_code warning_console_format)
  bomwerk_add_test(${bomwerk_test_name})
endforeach()

# warning_recorder.hpp lives under src/cli/, not src/core/, so it is registered
# here rather than folded into the core-only loop above; it needs nothing
# beyond bomwerk_core (spdlog is already part of core's public link surface).
bomwerk_add_test(warning_recorder)

# Vuln tests additionally link bomwerk_vuln. They are hermetic: the OSV and NVD
# tests inject a fake HTTP transport (never the network) and a fake sleep (never
# the clock); the cache test uses a throwaway SQLite file under the system temp
# dir. The cpe and endpoints tests are pure functions with no I/O at all.
# osv additionally links nlohmann_json (its concurrency tests build
# querybatch/hydration fixture JSON directly) and Threads (its FakeTransport
# observes std::thread overlap from match_components' concurrent fetch
# fan-out).
find_package(Threads REQUIRED)
# progress_ticker is a core:: type but its own concurrency-guarantee test spawns real
# std::thread workers (core-only tests otherwise never need Threads::Threads), so it's registered
# here rather than in the core-only foreach above.
bomwerk_add_test(progress_ticker Threads::Threads)
bomwerk_add_test(osv bomwerk_vuln nlohmann_json::nlohmann_json Threads::Threads)
# osv_delta tests diff_advisory_revisions (delta.cpp) alone: a pure function
# over delta.hpp's types, no cache/HTTP/clock involved.
bomwerk_add_test(osv_delta bomwerk_vuln)
# finding tests is_cve_shaped_id and merge_outcomes (finding.cpp) directly : 
# both pure functions, no cache/HTTP/clock involved.
bomwerk_add_test(finding bomwerk_vuln)
# vuln_cache additionally links sqlite3 directly (PRIVATE inside bomwerk_vuln
# itself, per the module dependency law) to fabricate a v1-schema
# fixture file and to read sqlite_master as an independent check on the
# migration: testing infrastructure reaching past the module boundary to
# build/verify a fixture, not a production module doing so.
bomwerk_add_test(vuln_cache bomwerk_vuln unofficial::sqlite3::sqlite3)
bomwerk_add_test(cpe bomwerk_vuln)
bomwerk_add_test(endpoints bomwerk_vuln)
bomwerk_add_test(license_enrichment bomwerk_vuln nlohmann_json::nlohmann_json Threads::Threads)
bomwerk_add_test(nvd bomwerk_vuln)
# sqlite_support tests the shared open/migrate plumbing itself : 
# create_parent_directories_if_needed and open_and_migrate, the full "open a
# sqlite-backed store" sequence every real store delegates to rather than
# repeating its own copy of it. Additionally links sqlite3 directly (PRIVATE inside
# bomwerk_vuln itself, per the module dependency law) to build tiny fixture
# files and read sqlite_master/PRAGMA user_version back independently: the
# same testing-infrastructure exception vuln_cache already takes.
bomwerk_add_test(sqlite_support bomwerk_vuln unofficial::sqlite3::sqlite3)

# Producer tests additionally link bomwerk_parsers.
bomwerk_add_test(cmake_deps bomwerk_parsers)
bomwerk_add_test(cmake_scanner bomwerk_parsers)
bomwerk_add_test(conan_ref bomwerk_parsers)
bomwerk_add_test(conan bomwerk_parsers)
bomwerk_add_test(submodules bomwerk_parsers)
# core-only rule, but links bomwerk_parsers for its drift guard: it asserts the
# skip set and the submodules producer agree on which subtrees are submodules.
bomwerk_add_test(submodule_paths bomwerk_parsers)
bomwerk_add_test(vcpkg bomwerk_parsers)
bomwerk_add_test(github_actions bomwerk_parsers)
bomwerk_add_test(go bomwerk_parsers)
bomwerk_add_test(npm bomwerk_parsers)
bomwerk_add_test(python bomwerk_parsers)
bomwerk_add_test(cargo bomwerk_parsers)
bomwerk_add_test(maven bomwerk_parsers)
bomwerk_add_test(nuget bomwerk_parsers)
bomwerk_add_test(composer bomwerk_parsers)
bomwerk_add_test(rubygems bomwerk_parsers)
bomwerk_add_test(yarn bomwerk_parsers)
bomwerk_add_test(pnpm bomwerk_parsers)
bomwerk_add_test(pub bomwerk_parsers)

# Observer tests. shim_names/trace_line/trace_writer exercise the shim
# half, so they link only bomwerk_observe_trace: the same nothing-extra the
# shim itself links. trace_line and trace_check re-parse the emitted JSON with
# nlohmann rather than trusting a substring match: the trace's whole value is
# that the trace reader can parse it.
bomwerk_add_test(shim_names bomwerk_observe_trace)
bomwerk_add_test(trace_line bomwerk_observe_trace nlohmann_json::nlohmann_json)
bomwerk_add_test(trace_writer bomwerk_observe_trace nlohmann_json::nlohmann_json)
bomwerk_add_test(trace_check bomwerk_observe nlohmann_json::nlohmann_json)
# The parent-side consumers of that trace. trace_read links nlohmann to
# build hostile input as JSON rather than hand-writing broken strings, the same
# reason trace_line does. compile_map needs no JSON at all: it works on
# already-parsed records, which is the point of the trace_read/compile_map
# split: the argv rules and the path arithmetic are testable without a parser,
# and the parser is testable without a repository.
bomwerk_add_test(trace_read bomwerk_observe nlohmann_json::nlohmann_json)
bomwerk_add_test(compile_map bomwerk_observe)
# Link_map follows the identical split: it also works on already-parsed
# records and needs no JSON, which is why it links exactly what compile_map
# does.
bomwerk_add_test(link_map bomwerk_observe)

# The binary pass. byte_cursor is tested on its own because it is the one
# type the other three trust to be bounds-safe: testing it only through them
# would leave its edges checked by accident rather than on purpose. elf_read
# and archive_read need no repository at all (each takes a file, and every
# hostile case is written byte by byte into a TempTree), and binary_map needs
# one only for the soname-existence check: the same split compile_map and
# link_map already follow. None of them parses a real build product: CI runs
# macOS too, where a build emits Mach-O, so a test that compiled something
# would assert different things on the two runners.
bomwerk_add_test(byte_cursor bomwerk_binscan)
bomwerk_add_test(elf_read bomwerk_binscan)
bomwerk_add_test(archive_read bomwerk_binscan)
bomwerk_add_test(binary_map bomwerk_binscan)

# The concurrency test spawns real threads, each with its own descriptor, to
# stand in for the parallel shim processes of a `make -j8` build.
find_package(Threads REQUIRED)
target_link_libraries(test_trace_writer PRIVATE Threads::Threads)

# The cross-producer purl invariant: every component any C/C++ producer
# emits carries a parseable, correctly-typed purl. It spans parsers AND the
# vendored heuristic, so it links both; that breadth is the point, since no
# single-producer test can assert a property that must hold across all of them.
bomwerk_add_test(purl_emission bomwerk_parsers bomwerk_heuristics)

# Heuristic tests additionally link bomwerk_heuristics. vendored_cpp also
# links bomwerk_output: it cross-checks its own license table against
# output::canonical_spdx_license_id (the two are intentionally separate : 
# module dependency law forbids the heuristic itself from including output : 
# but the test is allowed to see both).
bomwerk_add_test(vendored_cpp bomwerk_heuristics bomwerk_output)

# Output-writer tests additionally link bomwerk_output + nlohmann_json (the
# test itself re-parses the writer's JSON string to assert on structure).
bomwerk_add_test(coverage_report bomwerk_output nlohmann_json::nlohmann_json)
# the warnings-manifest writer's own test, same shape as coverage_report above.
bomwerk_add_test(warnings_report bomwerk_output nlohmann_json::nlohmann_json)
# The CRA sidecar writer's own test: pure string/path logic, hermetic.
bomwerk_add_test(cra_sidecar bomwerk_output nlohmann_json::nlohmann_json)
bomwerk_add_test(cyclonedx bomwerk_output nlohmann_json::nlohmann_json)
target_compile_definitions(test_cyclonedx PRIVATE
  BOMWERK_SCHEMA_FIXTURE_PATH="${CMAKE_BINARY_DIR}/schema-fixtures/sample.cdx.json")

# The SPDX writer emits both serializations, so it writes one schema
# fixture per version for the two validation ctests below to check.
bomwerk_add_test(spdx bomwerk_output nlohmann_json::nlohmann_json)
target_compile_definitions(test_spdx PRIVATE
  BOMWERK_SPDX_2_3_FIXTURE_PATH="${CMAKE_BINARY_DIR}/schema-fixtures/sample.spdx-2.3.json"
  BOMWERK_SPDX_3_0_FIXTURE_PATH="${CMAKE_BINARY_DIR}/schema-fixtures/sample.spdx-3.0.json")

# The HTML-report test needs only bomwerk_output: its assertions are plain
# substring checks over the returned document string.
bomwerk_add_test(html_report bomwerk_output)
# The SBOM reader's round trip through the writer it inverts, plus its
# own hostile-input handling. Links bomwerk_output in addition to bomwerk_sbom
# for exactly that round trip (components -> write_cyclonedx -> read_cyclonedx
# -> the same components), the same "test is allowed to see both sides"
# precedent as vendored_cpp/output::canonical_spdx_license_id above.
bomwerk_add_test(sbom_read bomwerk_sbom bomwerk_output)

# --all-cpes: scan/trim/binscan CLI wiring (flag parsing, scan's SPDX
# rejection, trim/binscan's --output requirement). Same precedent as
# direct command-source CLI tests: links the three command sources directly,
# since CLI command implementations are intentionally not a production
# library. app.cpp supplies version() and observe_trim.cpp supplies the trace
# application scan/trim both call, exactly the same peer sources bomwerk_cli_
# sources lists them alongside for the real binary.
add_executable(test_all_cpes_cli
  tests/unit/test_all_cpes_cli.cpp
  src/cli/app.cpp
  src/cli/observe_trim.cpp
  src/cli/scan_command.cpp
  src/cli/trim_command.cpp
  src/cli/binscan_command.cpp)
target_link_libraries(test_all_cpes_cli PRIVATE ${bomwerk_cli_libraries})
target_include_directories(test_all_cpes_cli PRIVATE tests)
add_test(NAME all_cpes_cli COMMAND test_all_cpes_cli)

# --fail-on: scan's exit-code remap. Same precedent as test_all_cpes_cli above, minus
# trim/binscan: this flag is scan-only, so only app.cpp (version()) and observe_trim.cpp (the
# trace application scan calls) are needed alongside scan_command.cpp itself.
add_executable(test_fail_on_cli
  tests/unit/test_fail_on_cli.cpp
  src/cli/app.cpp
  src/cli/observe_trim.cpp
  src/cli/scan_command.cpp)
target_link_libraries(test_fail_on_cli PRIVATE ${bomwerk_cli_libraries})
target_include_directories(test_fail_on_cli PRIVATE tests)
add_test(NAME fail_on_cli COMMAND test_fail_on_cli)

# --license-fallback-timeout/--license-cache-max-age CLI wiring, plus the exit-code
# regression guard for a timed-out (but complete) enrichment pass. Same precedent as
# test_fail_on_cli above. The zero-budget scan case never reaches the network (the deadline
# expires before enrich_component_licenses issues its first request), so this stays hermetic
# without injecting a fake transport.
add_executable(test_license_fallback_timeout_cli
  tests/unit/test_license_fallback_timeout_cli.cpp
  src/cli/app.cpp
  src/cli/observe_trim.cpp
  src/cli/scan_command.cpp)
target_link_libraries(test_license_fallback_timeout_cli PRIVATE ${bomwerk_cli_libraries})
target_include_directories(test_license_fallback_timeout_cli PRIVATE tests)
add_test(NAME license_fallback_timeout_cli COMMAND test_license_fallback_timeout_cli)

# CI validates the writer's output against the official CycloneDX 1.6 JSON
# schema. This is CI/dev tooling, not a bomwerk
# build dependency: same category as clang-format/Doxygen above, so it is
# not a vcpkg.json entry, and its absence degrades gracefully rather than
# failing configure (CI always has python3; a bare dev machine might not).
find_package(Python3 COMPONENTS Interpreter)
if(Python3_Interpreter_FOUND)
  if(NOT BOMWERK_PRO)
    add_test(NAME pro_boundary
      COMMAND ${Python3_EXECUTABLE}
              ${CMAKE_CURRENT_SOURCE_DIR}/scripts/validate_pro_boundary.py
              ${CMAKE_CURRENT_SOURCE_DIR}
              ${CMAKE_CURRENT_BINARY_DIR}
              $<TARGET_FILE:bomwerk>)
    add_test(NAME pro_boundary_validator
      COMMAND ${Python3_EXECUTABLE}
              ${CMAKE_CURRENT_SOURCE_DIR}/tests/python/test_validate_pro_boundary.py)

    # The capability ledger, the pinned --help texts and every documented
    # `bomwerk ...` example must agree with the binary (docs/capabilities.md).
    add_test(NAME docs_contract
      COMMAND ${Python3_EXECUTABLE}
              ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check_docs.py
              --bomwerk $<TARGET_FILE:bomwerk>
              --docs-root ${CMAKE_CURRENT_SOURCE_DIR}
              --ctest ${CMAKE_CTEST_COMMAND}
              --build-dir ${CMAKE_CURRENT_BINARY_DIR})
    add_test(NAME docs_contract_checker
      COMMAND ${Python3_EXECUTABLE}
              ${CMAKE_CURRENT_SOURCE_DIR}/tests/python/test_check_docs.py)

    # The history auditor is checked on throwaway repositories, never on
    # this one, so it stays honest about what it would reject.
    add_test(NAME public_history_audit_tests
      COMMAND ${Python3_EXECUTABLE}
              ${CMAKE_CURRENT_SOURCE_DIR}/tests/python/test_audit_public_history.py)
  endif()

  # docs/warning-codes.md is a rendering of core::WarningCode, not a second source of
  # truth for it; this keeps the two from drifting apart the same way
  # docs/vuln-cache-schema.md is checked against the cache's real schema. Registered
  # unconditionally: the enum it checks exists the same way in both build configurations.
  add_test(NAME warning_codes_reference
    COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/python/test_warning_codes_reference.py)

  add_test(NAME cyclonedx_schema_validation
    COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/scripts/validate_cyclonedx_schema.py
            ${CMAKE_BINARY_DIR}/schema-fixtures/sample.cdx.json
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/schemas/cyclonedx-1.6)
  set_tests_properties(cyclonedx_schema_validation PROPERTIES DEPENDS cyclonedx)

  # The same two-stage check for each SPDX serialization: the spdx test
  # emits a fixture per version, validate_spdx_schema.py checks it against the
  # vendored official schema (draft picked from the schema's own $schema).
  add_test(NAME spdx_2_3_schema_validation
    COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/scripts/validate_spdx_schema.py
            ${CMAKE_BINARY_DIR}/schema-fixtures/sample.spdx-2.3.json
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/schemas/spdx-2.3/spdx-schema.json)
  set_tests_properties(spdx_2_3_schema_validation PROPERTIES DEPENDS spdx)
  add_test(NAME spdx_3_0_schema_validation
    COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/scripts/validate_spdx_schema.py
            ${CMAKE_BINARY_DIR}/schema-fixtures/sample.spdx-3.0.json
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/schemas/spdx-3.0.1/spdx-schema.json)
  set_tests_properties(spdx_3_0_schema_validation PROPERTIES DEPENDS spdx)

  # The golden harness. One ctest per fixtures/golden/<case>/ directory,
  # each scanning that case's tree/ with the real binary and diffing the SBOM
  # byte-for-byte against the case's checked-in snapshot. This is the only test
  # that exercises the COMPOSITION in cli/scan_command.cpp: five producers, the
  # shared walk, the purl-keyed merge and the writer meeting: plus the first
  # one to assert the exit-code contract (rule 2), since it runs the binary.
  # CONFIGURE_DEPENDS so a newly added case directory re-globs on the next build
  # rather than silently never running. The IS_DIRECTORY guard skips SOURCES.md.
  file(GLOB bomwerk_golden_case_dirs CONFIGURE_DEPENDS
       "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/golden/*")
  foreach(bomwerk_golden_case_dir IN LISTS bomwerk_golden_case_dirs)
    if(IS_DIRECTORY "${bomwerk_golden_case_dir}")
      get_filename_component(bomwerk_golden_case_name "${bomwerk_golden_case_dir}" NAME)
      add_test(NAME golden_${bomwerk_golden_case_name}
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_golden_case.py
                $<TARGET_FILE:bomwerk>
                ${bomwerk_golden_case_dir})

      # The same snapshot, checked against the REFERENCE purl parser rather
      # than against itself. The golden diff proves the output did not change;
      # this proves the output is spec-legal in the first place: a snapshot can
      # be byte-stable and wrong. It reads the checked-in expected.* directly, so
      # it needs no build artifacts and does not depend on the golden test.
      # core::Purl deliberately stays lenient (it is the identity canonicalizer
      # feeding merge_all and the bom-ref UUIDs), so being strict lives out here.
      file(GLOB bomwerk_golden_expected
           "${bomwerk_golden_case_dir}/expected.*.json")
      # Expected.coverage.json is not an SBOM: validate_purls.py only
      # reads CycloneDX/SPDX shapes (see its docstring). It is also, by
      # design, the one document where a component can legitimately have no
      # `purl` at all (the no-identifier class): exactly the case this
      # validator exists to flag as an error, were it ever pointed at one; no
      # current fixture reaches that class (see match_coverage.hpp's doc
      # comment), but the exclusion should not depend on that staying true.
      # Excluded here rather than teaching the script about a third document
      # shape it was never meant to understand.
      list(REMOVE_ITEM bomwerk_golden_expected "${bomwerk_golden_case_dir}/expected.coverage.json")
      if(bomwerk_golden_expected)
        add_test(NAME purl_spec_${bomwerk_golden_case_name}
          COMMAND ${Python3_EXECUTABLE}
                  ${CMAKE_CURRENT_SOURCE_DIR}/scripts/validate_purls.py
                  ${bomwerk_golden_expected})
        # Exit 77 means packageurl-python is absent: a bare dev machine reports
        # SKIP instead of a spurious failure. CI installs the module, so it can
        # never skip there (see the pip step in .github/workflows/ci.yml).
        set_tests_properties(purl_spec_${bomwerk_golden_case_name}
          PROPERTIES SKIP_RETURN_CODE 77)
      endif()
    endif()
  endforeach()

  # The observer's acceptance check: a full cmake build traced to JSONL. This is the only
  # test that exercises the real mechanism end to end: PATH interception, a
  # genuine compiler running behind a shim, and the trace that comes out: so
  # it drives the actual binaries rather than calling the library. It observes
  # BOTH cmake phases because configuring under observe is what puts the shim
  # path into CMakeCache.txt; observing only the build phase is exactly the
  # empty-trace failure the command warns about.
  add_test(NAME observe_cmake_build
    COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_observe_case.py
            $<TARGET_FILE:bomwerk>
            $<TARGET_FILE:bomwerk-shim>
            ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/observe/hello-cmake
            ${CMAKE_COMMAND})

  # The trim acceptance check: the used-set is correct on a fixture and the same
  # answer reaches trim's and scan's HTML reports. The unit tests cover the
  # argv rules, path arithmetic and renderer; only this drives the REAL binary
  # end to end -- CLI parsing, the SBOM reader restoring component roots from
  # evidence.occurrences, trace discovery/reading, mapping, report generation,
  # SBOM retention and the exit-code contract -- so only this can catch a
  # wiring mistake between them.
  add_test(NAME trim_used_set
    COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_trim_case.py
            $<TARGET_FILE:bomwerk>
            ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/trim)
  # the public bomwerk/nightmare corpus's central claim - one source tree, two
  # build configurations, two different used-sets. The trees are identical; only
  # the (real, minimized) traces differ.
  foreach(nightmare_configuration a b)
    add_test(NAME trim_nightmare_config_${nightmare_configuration}
      COMMAND ${Python3_EXECUTABLE}
              ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_trim_case.py
              $<TARGET_FILE:bomwerk>
              ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/trim/nightmare-config-${nightmare_configuration})
  endforeach()

  # The binary pass acceptance check: dynamic dependencies appear as Binary evidence. The unit
  # tests cover the byte-level readers and the attribution separately; only
  # this drives the REAL binary end to end -- CLI parsing, the SBOM reader
  # restoring each component's root, the trace reader, artifact collection,
  # attribution, the sidecar and the exit-code contract -- so only this can
  # catch a wiring mistake between them. The ELF and ar images are generated by
  # the harness rather than committed (fixtures/binscan/SOURCES.md): CI runs
  # macOS too, where a real build emits Mach-O, and a committed blob could not
  # be reviewed.
  add_test(NAME binscan_dynamic_deps
    COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_binscan_case.py
            $<TARGET_FILE:bomwerk>
            ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/binscan)


  # The CycloneDX-out -> CRANE-in interop smoke test. Scans
  # fixtures/interop/crane-pipeline/tree/ with the real binary, then validates
  # the resulting SBOM against the real upstream `sbom-tools` binary CRANE
  # itself shells out to for --standard ntia/cra scoring. Exit 77 (SKIP) means
  # sbom-tools is not installed at .cache/sbom-tools/sbom-tools -- run
  # scripts/fetch-sbom-tools.sh first; CI always runs that first (see
  # ci.yml), so it can never skip there.
  add_test(NAME interop_sbom_tools
    COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_interop_case.py
            $<TARGET_FILE:bomwerk>
            ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/interop/crane-pipeline)
  set_tests_properties(interop_sbom_tools PROPERTIES SKIP_RETURN_CODE 77)
else()
  # WARNING, not STATUS: this guard now also gates the entire golden suite
  # (fixtures/golden/*), the only test exercising producer composition and the
  # exit-code contract (rule 2): a silently-skipped STATUS line was an
  # acceptable risk when this guard covered just the schema-validation nicety,
  # but a local build ("100% tests passed") should not go quiet about skipping
  # that much coverage. CI itself is unaffected: GitHub-hosted ubuntu-24.04/
  # macos-14 runners always have python3, so this only surfaces for a bare dev
  # machine.
  message(WARNING "python3 not found: skipping "
                  "cyclonedx_schema_validation, golden_*, purl_spec_*, observe_cmake_build, "
                  "trim_used_set, trim_nightmare_config_a/b, binscan_dynamic_deps and "
                  "interop_sbom_tools ctests "
                  "(CI always has it)")
endif()

# --- API reference (Doxygen + optional doxygen-awesome-css) ------------------
# Opt-in: configure with -DBOMWERK_DOCS=ON, then build the `docs` target.
# Output: <build>/docs/html/index.html. Doxygen is a doc TOOL, not a code
# dependency, so installing it via brew/apt does not violate the vcpkg rule.
option(BOMWERK_DOCS "Generate API reference with Doxygen (target: docs)" OFF)
if(BOMWERK_DOCS)
  find_package(Doxygen REQUIRED)
  set(BOMWERK_DOXYGEN_AWESOME_CSS "")
  if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/docs/doxygen-awesome.css")
    set(BOMWERK_DOXYGEN_AWESOME_CSS "${CMAKE_CURRENT_SOURCE_DIR}/docs/doxygen-awesome.css")
  endif()
  configure_file(docs/Doxyfile.in "${CMAKE_BINARY_DIR}/Doxyfile" @ONLY)
  add_custom_target(docs
    COMMAND Doxygen::doxygen "${CMAKE_BINARY_DIR}/Doxyfile"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    COMMENT "Generating API reference in ${CMAKE_BINARY_DIR}/docs/html")
endif()
