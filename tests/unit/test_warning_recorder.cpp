#include <filesystem>
#include <string>
#include <vector>

#include "cli/warning_recorder.hpp"
#include "core/warning.hpp"
#include "core/warning_code.hpp"
#include "support/check.hpp"

namespace cli = bomwerk::cli;
namespace core = bomwerk::core;

namespace
{

// A composed module's own code table, the same shape `bomwerk-pro/src/pro/warning_codes.hpp`
// uses: a `constexpr` (static-storage) `WarningCodeInfo`, never owned by the closed
// `core::WarningCode` enum this repository defines.
constexpr core::WarningCodeInfo kExternalTestCode{"BW-EXT-TEST-001", "External test cause"};

}  // namespace

int main()
{
  // Given a WarningCodeInfo owned by a composed module, when recorded the same way a local
  // WarningCode is (record(code, message, ...)), then it is collected as an externally
  // defined warning carrying that exact code, mirroring core::Result::warn's own overload
  // (core/result.hpp) so a recorder and a Result behave identically for a Pro-owned cause.
  {
    cli::WarningRecorder recorder;
    recorder.record(kExternalTestCode, "something a Pro module noticed", "npm",
                    std::filesystem::path("src/thing.json"));

    BOMWERK_TEST_CHECK(recorder.collected().size() == 1);
    const core::Warning& recorded = recorder.collected().front();
    BOMWERK_TEST_CHECK(recorded.code == core::WarningCode::kExternallyDefined);
    BOMWERK_TEST_CHECK(recorded.message == "something a Pro module noticed");
    BOMWERK_TEST_CHECK(recorded.ecosystem == "npm");
    BOMWERK_TEST_CHECK(recorded.affected_path == std::filesystem::path("src/thing.json"));
    BOMWERK_TEST_CHECK(recorded.external_code.id == kExternalTestCode.id);
    BOMWERK_TEST_CHECK(recorded.external_code.title == kExternalTestCode.title);
  }

  // Given the same WarningCodeInfo overload, when the optional ecosystem/affected_path
  // arguments are omitted, then they default the same way the WarningCode overload does.
  {
    cli::WarningRecorder recorder;
    recorder.record(kExternalTestCode, "no ecosystem or path given");

    const core::Warning& recorded = recorder.collected().front();
    BOMWERK_TEST_CHECK(recorded.ecosystem.empty());
    BOMWERK_TEST_CHECK(recorded.affected_path.empty());
  }

  // Given a recorder with no suppression entries, when an externally defined warning is
  // recorded through the WarningCodeInfo overload, then the run degrades exactly as it
  // would for a local WarningCode, since is_warning_suppressed resolves the id through
  // code_info_of regardless of which overload built the Warning.
  {
    cli::WarningRecorder recorder;
    recorder.record(kExternalTestCode, "degrades the run");
    BOMWERK_TEST_CHECK(recorder.degraded());
  }

  // Given a suppression entry naming the external code's own id, when that exact
  // WarningCodeInfo is recorded, then the run does not degrade, the same suppression
  // contract core::is_warning_suppressed documents for any warning's resolved id.
  {
    cli::WarningRecorder recorder({std::string(kExternalTestCode.id)});
    recorder.record(kExternalTestCode, "suppressed by id");
    BOMWERK_TEST_CHECK(!recorder.degraded());
    BOMWERK_TEST_CHECK(recorder.collected().size() ==
                       1);  // suppression hides degrade, not the record
  }

  return 0;
}
