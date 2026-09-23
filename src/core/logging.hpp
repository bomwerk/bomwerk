#pragma once

namespace bomwerk::core
{

/// Configure the global logger once at startup: logs go to stderr (scan
/// RESULTS go to stdout: never mix, docs/CONTRIBUTING.md Logging). Level defaults to
/// `info` and can be raised/lowered with the SPDLOG_LEVEL env var
/// (e.g. `SPDLOG_LEVEL=debug`). Safe to call once from main().
void init_logging();

}  // namespace bomwerk::core
