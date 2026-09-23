#include <cstdio>
#include <set>
#include <string>

#include "core/warning_code.hpp"
#include "support/check.hpp"

using bomwerk::core::warning_code_info;
using bomwerk::core::WarningCode;

namespace
{

// Every WarningCode enum value, listed once here so this test can assert the registry has an
// entry for each one and that every id is unique and permanent-looking ("codes
// are a permanent commitment"). Keep this list in sync with warning_code.hpp: a value
// missing here is a gap in test coverage, not a build break (the switch in warning_code.cpp
// is what the compiler enforces via -Wswitch -Werror). kExternallyDefined is included
// because it resolves to a real placeholder entry; a composed module's own ids are its
// own test's business.
constexpr WarningCode kAllCodes[] = {
    WarningCode::kJsonNestingDepthExceeded,
    WarningCode::kInvalidJson,
    WarningCode::kInvalidToml,
    WarningCode::kEntryLimitReached,
    WarningCode::kFileLimitReached,
    WarningCode::kFileSizeLimitExceeded,
    WarningCode::kUnreadableFile,
    WarningCode::kPurlValidationFailed,
    WarningCode::kEntriesSkippedUnresolved,
    WarningCode::kMalformedEntrySkipped,
    WarningCode::kLockfileFormatUnsupported,
    WarningCode::kSelfIdentityUnresolvable,
    WarningCode::kUnresolvedVariableOrInterpolation,
    WarningCode::kDependencyMissingSource,
    WarningCode::kUnpinnedOrUnresolvedRef,
    WarningCode::kManifestNoLockfileAlongside,
    WarningCode::kManifestUnsupportedLockfile,
    WarningCode::kDirectoryWalkError,
    WarningCode::kBuildOutputDirectoryHoldsManifest,
    WarningCode::kPurlMalformed,
    WarningCode::kNameListUnreadable,
    WarningCode::kNameListEmpty,
    WarningCode::kConfigNotValidToml,
    WarningCode::kConfigFileUnreadable,
    WarningCode::kConfigFileTooLarge,
    WarningCode::kConfigKeyWrongType,
    WarningCode::kConfigArrayEntryInvalid,
    WarningCode::kConfigUnknownKey,
    WarningCode::kConfigUnknownTable,
    WarningCode::kConfigTopLevelKeyNotTable,
    WarningCode::kConfigValueInvalidFormat,
    WarningCode::kConfigDeprecatedKeyRemoved,
    WarningCode::kConfigSecretRejected,
    WarningCode::kConfigSectionIncomplete,
    WarningCode::kConfigFileNotWritten,
    WarningCode::kGitConfigStructureInvalid,
    WarningCode::kSubmoduleMissingPath,
    WarningCode::kSubmoduleUnsafePath,
    WarningCode::kSubmoduleNotInitialized,
    WarningCode::kSubmoduleNoUrl,
    WarningCode::kObserveTraceNotWritten,
    WarningCode::kObserveTraceMalformedLines,
    WarningCode::kObserveTraceExceedsLimit,
    WarningCode::kObserveTraceRewriteFailed,
    WarningCode::kObserveShimBinaryMissing,
    WarningCode::kObserveShimDirectoryUnwritable,
    WarningCode::kObserveShimCreationFailed,
    WarningCode::kObserveNoToolchainFound,
    WarningCode::kObserveNoCompilerInvocations,
    WarningCode::kObserveEvidenceOutsideRoot,
    WarningCode::kObserveResponseFilesUnexpanded,
    WarningCode::kObserveUnresolvedLinkArgument,
    WarningCode::kObserveAutoDetectedTraceUnusable,
    WarningCode::kObserveNoRootedComponents,
    WarningCode::kBinaryUnreadable,
    WarningCode::kBinaryTooLarge,
    WarningCode::kBinaryMalformedHeader,
    WarningCode::kBinaryEvidenceLimited,
    WarningCode::kSbomDocumentInvalid,
    WarningCode::kSbomWrongFormat,
    WarningCode::kSbomComponentEntrySkipped,
    WarningCode::kReportConfigFieldInvalid,
    WarningCode::kVulnCacheOpenFailed,
    WarningCode::kVulnHttpEndpointNotAllowlisted,
    WarningCode::kVulnHttpRequestFailed,
    WarningCode::kVulnHttpUnexpectedStatus,
    WarningCode::kVulnResponseMalformed,
    WarningCode::kVulnCoverageIncomplete,
    WarningCode::kLicenseFallbackIncomplete,
    WarningCode::kExternallyDefined,
};

}  // namespace

int main()
{
  // Given every WarningCode this test knows about, when looked up, then each has a
  // non-empty, unique, "BW-" prefixed id and a non-empty title.
  std::set<std::string> seen_ids;
  for (const WarningCode code : kAllCodes)
  {
    const bomwerk::core::WarningCodeInfo& info = warning_code_info(code);
    BOMWERK_TEST_CHECK(!info.id.empty());
    BOMWERK_TEST_CHECK(!info.title.empty());
    BOMWERK_TEST_CHECK(info.id.substr(0, 3) == "BW-");
    BOMWERK_TEST_CHECK(seen_ids.insert(std::string(info.id)).second);
  }

  std::puts("test_warning_code: OK");
  return 0;
}
