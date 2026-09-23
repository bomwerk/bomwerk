#include "core/logging.hpp"

#include <spdlog/cfg/env.h>
#include <spdlog/sinks/stdout_color_sinks.h>  // provides stderr_color_mt too
#include <spdlog/spdlog.h>

#include <memory>

namespace bomwerk::core
{

void init_logging()
{
  // stderr only: stdout is reserved for product output (SBOM listings/files).
  auto stderr_logger = spdlog::stderr_color_mt("bomwerk");
  stderr_logger->set_pattern("%^%l%$: %v");  // e.g. "warning: partial SBOM"
  spdlog::set_default_logger(stderr_logger);
  spdlog::set_level(spdlog::level::info);

  // Honor SPDLOG_LEVEL (e.g. SPDLOG_LEVEL=debug) for development without a rebuild.
  spdlog::cfg::load_env_levels();
}

}  // namespace bomwerk::core
