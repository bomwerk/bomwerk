#pragma once
#include <CLI/CLI.hpp>

namespace bomwerk::cli
{

/// Program version "MAJOR.MINOR.PATCH". Single source of truth is the CMake
/// `project()` version, injected as the BOMWERK_VERSION compile definition.
const char* version();

/// Apply the root-app polish: name, description, `-V/--version`, the footer
/// with examples and the exit-code contract, and the help formatter.
/// Subcommands register themselves separately (see scan_command.hpp).
void configure_root_app(CLI::App& application);

}  // namespace bomwerk::cli
