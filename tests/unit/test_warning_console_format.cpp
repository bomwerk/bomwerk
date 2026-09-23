#include <spdlog/sinks/ostream_sink.h>

#include <cstdio>
#include <memory>
#include <sstream>
#include <string>

#include "cli/warning_recorder.hpp"
#include "core/warning.hpp"
#include "core/warning_code.hpp"
#include "support/check.hpp"

using bomwerk::core::format_for_console;
using bomwerk::core::Warning;
using bomwerk::core::warning_code_info;
using bomwerk::core::WarningCode;

int main()
{
  // Given a core::Warning, when formatted for the console (the console was the
  // only human-facing surface still dropping the code, breaking the suppression workflow),
  // then the payload carries `[BW-XXX]: <message>`, the same code id the HTML report and
  // `--warnings` manifest already use, not just the bare message text.
  {
    const Warning warning{WarningCode::kUnreadableFile, "vcpkg: unreadable file: vcpkg.json",
                          "vcpkg", "third_party/pkg/vcpkg.json"};
    const std::string formatted = format_for_console(warning);

    const std::string expected_code_id(warning_code_info(WarningCode::kUnreadableFile).id);
    BOMWERK_TEST_CHECK(formatted ==
                       "[" + expected_code_id + "]: vcpkg: unreadable file: vcpkg.json");
  }

  // Given a bare (code, message) pair: the shape a store's own warnings and
  // startup-authorization diagnostics arrive in, with no core::Warning to carry alongside :
  // when formatted for the console, then it produces the identical shape.
  {
    const std::string formatted =
        format_for_console(WarningCode::kVulnCacheOpenFailed, "sqlite busy, retrying");

    const std::string expected_code_id(warning_code_info(WarningCode::kVulnCacheOpenFailed).id);
    BOMWERK_TEST_CHECK(formatted == "[" + expected_code_id + "]: sqlite busy, retrying");
  }

  // Given the production stderr logger's pattern, when WarningRecorder emits a warning, then
  // the actual console bytes contain one level prefix and one coded payload.
  {
    std::ostringstream captured_output;
    auto sink = std::make_shared<spdlog::sinks::ostream_sink_mt>(captured_output);
    auto logger = std::make_shared<spdlog::logger>("warning-console-test", sink);
    logger->set_pattern("%^%l%$: %v");
    logger->set_level(spdlog::level::warn);
    const std::shared_ptr<spdlog::logger> previous_logger = spdlog::default_logger();
    spdlog::set_default_logger(logger);

    bomwerk::cli::WarningRecorder recorder;
    recorder.record(Warning{WarningCode::kUnreadableFile, "vcpkg: unreadable file: vcpkg.json",
                            "vcpkg", "vcpkg.json"});
    logger->flush();
    spdlog::set_default_logger(previous_logger);

    const std::string expected_code_id(warning_code_info(WarningCode::kUnreadableFile).id);
    BOMWERK_TEST_CHECK(captured_output.str() ==
                       "warning: [" + expected_code_id + "]: vcpkg: unreadable file: vcpkg.json\n");
  }

  // Given an ecosystem-specific suppression, when warnings are recorded, then only that
  // ecosystem is exempted from degrading the scan.
  {
    bomwerk::cli::WarningRecorder recorder({"BW-CORE-004:npm"});
    recorder.record(Warning{WarningCode::kManifestNoLockfileAlongside, "npm gap", "npm", {}});
    BOMWERK_TEST_CHECK(!recorder.degraded());
    recorder.record(Warning{WarningCode::kManifestNoLockfileAlongside, "python gap", "python", {}});
    BOMWERK_TEST_CHECK(recorder.degraded());
  }

  std::puts("test_warning_console_format: OK");
  return 0;
}
