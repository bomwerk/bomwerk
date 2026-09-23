// Community entry point. Paid commands are not registered, linked, or named
// by this translation unit; CMake selects the Pro entry point instead when
// BOMWERK_PRO is enabled with a private extension tree.
#include <CLI/CLI.hpp>

#include "cli/app.hpp"
#include "cli/binscan_command.hpp"
#include "cli/observe_command.hpp"
#include "cli/scan_command.hpp"
#include "cli/trim_command.hpp"
#include "core/exit_codes.hpp"
#include "core/logging.hpp"

int main(int argc, char** argv)
{
  bomwerk::core::init_logging();

  CLI::App application;
  bomwerk::cli::configure_root_app(application);

  bomwerk::cli::ScanOptions scan_options;
  CLI::App* scan_command = bomwerk::cli::register_scan_command(application, scan_options);

  bomwerk::cli::ObserveOptions observe_options;
  CLI::App* observe_command = bomwerk::cli::register_observe_command(application, observe_options);

  bomwerk::cli::TrimOptions trim_options;
  CLI::App* trim_command = bomwerk::cli::register_trim_command(application, trim_options);

  bomwerk::cli::BinscanOptions binscan_options;
  CLI::App* binscan_command = bomwerk::cli::register_binscan_command(application, binscan_options);

  try
  {
    application.parse(argc, argv);
  }
  catch (const CLI::ParseError& parse_error)
  {
    return application.exit(parse_error) == 0 ? bomwerk::core::kExitClean
                                              : bomwerk::core::kExitIncomplete;
  }

  if (scan_command->parsed())
  {
    return bomwerk::cli::run_scan(scan_options);
  }
  if (observe_command->parsed())
  {
    return bomwerk::cli::run_observe(observe_options);
  }
  if (trim_command->parsed())
  {
    return bomwerk::cli::run_trim(trim_options);
  }
  if (binscan_command->parsed())
  {
    return bomwerk::cli::run_binscan(binscan_options);
  }
  return bomwerk::core::kExitIncomplete;
}
