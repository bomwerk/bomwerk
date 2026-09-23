#include "core/warning_code.hpp"

namespace bomwerk::core
{

const WarningCodeInfo& warning_code_info(WarningCode code)
{
  // A switch (not a map) so a new WarningCode enum value with no entry here fails the build
  // under -Wswitch -Werror instead of failing at runtime. Ids are the permanent contract
  // (see warning_code.hpp): never renumbered, never reused, retired in place if unused.
  switch (code)
  {
    case WarningCode::kJsonNestingDepthExceeded:
    {
      static constexpr WarningCodeInfo kInfo{"BW-CORE-001", "nesting exceeds the JSON depth limit"};
      return kInfo;
    }
    case WarningCode::kInvalidJson:
    {
      static constexpr WarningCodeInfo kInfo{"BW-CORE-002", "file is not valid JSON"};
      return kInfo;
    }
    case WarningCode::kInvalidToml:
    {
      static constexpr WarningCodeInfo kInfo{"BW-CORE-003", "file is not valid TOML"};
      return kInfo;
    }
    case WarningCode::kManifestNoLockfileAlongside:
    {
      static constexpr WarningCodeInfo kInfo{
          "BW-CORE-004", "manifest declares ranges only, no lockfile alongside it"};
      return kInfo;
    }
    case WarningCode::kManifestUnsupportedLockfile:
    {
      static constexpr WarningCodeInfo kInfo{"BW-CORE-005",
                                             "a real lockfile was found with no parser for it yet"};
      return kInfo;
    }
    case WarningCode::kEntryLimitReached:
    {
      static constexpr WarningCodeInfo kInfo{"BW-CORE-006",
                                             "package/dependency count budget reached"};
      return kInfo;
    }
    case WarningCode::kFileLimitReached:
    {
      static constexpr WarningCodeInfo kInfo{"BW-CORE-007",
                                             "manifest/lockfile file count budget reached"};
      return kInfo;
    }
    case WarningCode::kFileSizeLimitExceeded:
    {
      static constexpr WarningCodeInfo kInfo{"BW-CORE-008", "file exceeds its byte budget"};
      return kInfo;
    }
    case WarningCode::kUnreadableFile:
    {
      static constexpr WarningCodeInfo kInfo{"BW-CORE-009", "file could not be read"};
      return kInfo;
    }
    case WarningCode::kPurlValidationFailed:
    {
      static constexpr WarningCodeInfo kInfo{"BW-CORE-010",
                                             "an assembled component purl failed validation"};
      return kInfo;
    }
    case WarningCode::kEntriesSkippedUnresolved:
    {
      static constexpr WarningCodeInfo kInfo{
          "BW-CORE-011", "entries without a resolvable name/version were skipped"};
      return kInfo;
    }
    case WarningCode::kMalformedEntrySkipped:
    {
      static constexpr WarningCodeInfo kInfo{"BW-CORE-012",
                                             "an entry had an unreadable shape and was skipped"};
      return kInfo;
    }
    case WarningCode::kLockfileFormatUnsupported:
    {
      static constexpr WarningCodeInfo kInfo{
          "BW-CORE-013", "a recognized lockfile's format/version is not supported"};
      return kInfo;
    }
    case WarningCode::kSelfIdentityUnresolvable:
    {
      static constexpr WarningCodeInfo kInfo{
          "BW-CORE-014", "the manifest's own component lacks enough identity to emit"};
      return kInfo;
    }
    case WarningCode::kUnresolvedVariableOrInterpolation:
    {
      static constexpr WarningCodeInfo kInfo{"BW-CORE-015",
                                             "a name or version depends on an unresolved variable"};
      return kInfo;
    }
    case WarningCode::kDependencyMissingSource:
    {
      static constexpr WarningCodeInfo kInfo{
          "BW-CORE-016", "a dependency declaration has no name, repository or URL"};
      return kInfo;
    }
    case WarningCode::kUnpinnedOrUnresolvedRef:
    {
      static constexpr WarningCodeInfo kInfo{"BW-CORE-017",
                                             "a dependency is not pinned to a resolved reference"};
      return kInfo;
    }
    case WarningCode::kDirectoryWalkError:
    {
      static constexpr WarningCodeInfo kInfo{"BW-CORE-018", "the directory walk stopped early"};
      return kInfo;
    }
    case WarningCode::kBuildOutputDirectoryHoldsManifest:
    {
      static constexpr WarningCodeInfo kInfo{
          "BW-CORE-019", "a skipped build-output directory holds a recognized manifest"};
      return kInfo;
    }
    case WarningCode::kPurlMalformed:
    {
      static constexpr WarningCodeInfo kInfo{"BW-CORE-020", "a supplied purl is malformed"};
      return kInfo;
    }
    case WarningCode::kNameListUnreadable:
    {
      static constexpr WarningCodeInfo kInfo{"BW-CORE-021",
                                             "a --manifest-list/--exclude-list file is unreadable"};
      return kInfo;
    }
    case WarningCode::kNameListEmpty:
    {
      static constexpr WarningCodeInfo kInfo{"BW-CORE-022",
                                             "a --manifest-list/--exclude-list file is empty"};
      return kInfo;
    }
    case WarningCode::kConfigNotValidToml:
    {
      static constexpr WarningCodeInfo kInfo{"BW-CONFIG-001", "config file is not valid TOML"};
      return kInfo;
    }
    case WarningCode::kConfigFileUnreadable:
    {
      static constexpr WarningCodeInfo kInfo{"BW-CONFIG-002", "config file could not be read"};
      return kInfo;
    }
    case WarningCode::kConfigFileTooLarge:
    {
      static constexpr WarningCodeInfo kInfo{"BW-CONFIG-003", "config file exceeds its size cap"};
      return kInfo;
    }
    case WarningCode::kConfigKeyWrongType:
    {
      static constexpr WarningCodeInfo kInfo{"BW-CONFIG-004",
                                             "a config key has the wrong value type"};
      return kInfo;
    }
    case WarningCode::kConfigArrayEntryInvalid:
    {
      static constexpr WarningCodeInfo kInfo{"BW-CONFIG-005",
                                             "a config array entry is invalid or unsafe"};
      return kInfo;
    }
    case WarningCode::kConfigUnknownKey:
    {
      static constexpr WarningCodeInfo kInfo{"BW-CONFIG-006", "config names an unknown key"};
      return kInfo;
    }
    case WarningCode::kConfigUnknownTable:
    {
      static constexpr WarningCodeInfo kInfo{"BW-CONFIG-007", "config names an unknown table"};
      return kInfo;
    }
    case WarningCode::kConfigTopLevelKeyNotTable:
    {
      static constexpr WarningCodeInfo kInfo{"BW-CONFIG-008",
                                             "a top-level config key is not a table"};
      return kInfo;
    }
    case WarningCode::kConfigValueInvalidFormat:
    {
      static constexpr WarningCodeInfo kInfo{"BW-CONFIG-009",
                                             "a config value does not match its expected format"};
      return kInfo;
    }
    case WarningCode::kConfigDeprecatedKeyRemoved:
    {
      static constexpr WarningCodeInfo kInfo{"BW-CONFIG-010",
                                             "config uses a key that has been removed"};
      return kInfo;
    }
    case WarningCode::kConfigSecretRejected:
    {
      static constexpr WarningCodeInfo kInfo{
          "BW-CONFIG-011", "config carries a secret directly instead of by reference"};
      return kInfo;
    }
    case WarningCode::kConfigSectionIncomplete:
    {
      static constexpr WarningCodeInfo kInfo{
          "BW-CONFIG-012", "a config section is missing required keys and stays unconfigured"};
      return kInfo;
    }
    case WarningCode::kConfigFileNotWritten:
    {
      static constexpr WarningCodeInfo kInfo{"BW-CONFIG-013",
                                             "a config/metadata file could not be written"};
      return kInfo;
    }
    case WarningCode::kGitConfigStructureInvalid:
    {
      static constexpr WarningCodeInfo kInfo{"BW-GIT-001",
                                             "a .git config file has an invalid structure"};
      return kInfo;
    }
    case WarningCode::kSubmoduleMissingPath:
    {
      static constexpr WarningCodeInfo kInfo{"BW-GIT-002", "a submodule entry has no path"};
      return kInfo;
    }
    case WarningCode::kSubmoduleUnsafePath:
    {
      static constexpr WarningCodeInfo kInfo{"BW-GIT-003", "a submodule entry has an unsafe path"};
      return kInfo;
    }
    case WarningCode::kSubmoduleNotInitialized:
    {
      static constexpr WarningCodeInfo kInfo{"BW-GIT-004", "a submodule is not initialized"};
      return kInfo;
    }
    case WarningCode::kSubmoduleNoUrl:
    {
      static constexpr WarningCodeInfo kInfo{"BW-GIT-005",
                                             "a submodule's url is missing or cannot be resolved"};
      return kInfo;
    }
    case WarningCode::kObserveTraceNotWritten:
    {
      static constexpr WarningCodeInfo kInfo{"BW-OBSERVE-001", "no build trace file was written"};
      return kInfo;
    }
    case WarningCode::kObserveTraceMalformedLines:
    {
      static constexpr WarningCodeInfo kInfo{"BW-OBSERVE-002",
                                             "trace lines were unreadable and were dropped"};
      return kInfo;
    }
    case WarningCode::kObserveTraceExceedsLimit:
    {
      static constexpr WarningCodeInfo kInfo{"BW-OBSERVE-003", "the trace exceeds its line limit"};
      return kInfo;
    }
    case WarningCode::kObserveTraceRewriteFailed:
    {
      static constexpr WarningCodeInfo kInfo{"BW-OBSERVE-004",
                                             "the trace could not be rewritten in canonical order"};
      return kInfo;
    }
    case WarningCode::kObserveShimBinaryMissing:
    {
      static constexpr WarningCodeInfo kInfo{"BW-OBSERVE-005",
                                             "the shim binary was not found or not executable"};
      return kInfo;
    }
    case WarningCode::kObserveShimDirectoryUnwritable:
    {
      static constexpr WarningCodeInfo kInfo{"BW-OBSERVE-006",
                                             "the shim directory could not be created"};
      return kInfo;
    }
    case WarningCode::kObserveShimCreationFailed:
    {
      static constexpr WarningCodeInfo kInfo{"BW-OBSERVE-007",
                                             "a tool shim could not be created or recorded"};
      return kInfo;
    }
    case WarningCode::kObserveNoToolchainFound:
    {
      static constexpr WarningCodeInfo kInfo{"BW-OBSERVE-008",
                                             "no compiler, linker or archiver was found on PATH"};
      return kInfo;
    }
    case WarningCode::kObserveNoCompilerInvocations:
    {
      static constexpr WarningCodeInfo kInfo{
          "BW-OBSERVE-009", "the trace holds no compiler invocations naming a source file"};
      return kInfo;
    }
    case WarningCode::kObserveEvidenceOutsideRoot:
    {
      static constexpr WarningCodeInfo kInfo{
          "BW-OBSERVE-010", "observed compile/link evidence lies outside the scan root"};
      return kInfo;
    }
    case WarningCode::kObserveResponseFilesUnexpanded:
    {
      static constexpr WarningCodeInfo kInfo{
          "BW-OBSERVE-011", "a compile/link argument was a response file bomwerk does not open"};
      return kInfo;
    }
    case WarningCode::kObserveUnresolvedLinkArgument:
    {
      static constexpr WarningCodeInfo kInfo{
          "BW-OBSERVE-012", "a link argument did not resolve to a file bomwerk observed"};
      return kInfo;
    }
    case WarningCode::kObserveAutoDetectedTraceUnusable:
    {
      static constexpr WarningCodeInfo kInfo{"BW-OBSERVE-013",
                                             "an auto-detected build trace could not be applied"};
      return kInfo;
    }
    case WarningCode::kObserveNoRootedComponents:
    {
      static constexpr WarningCodeInfo kInfo{"BW-OBSERVE-014",
                                             "a build trace judged zero components as used"};
      return kInfo;
    }
    case WarningCode::kBinaryUnreadable:
    {
      static constexpr WarningCodeInfo kInfo{"BW-BINSCAN-001",
                                             "a binary artifact could not be read"};
      return kInfo;
    }
    case WarningCode::kBinaryTooLarge:
    {
      static constexpr WarningCodeInfo kInfo{"BW-BINSCAN-002",
                                             "a binary artifact exceeds its size cap"};
      return kInfo;
    }
    case WarningCode::kBinaryMalformedHeader:
    {
      static constexpr WarningCodeInfo kInfo{"BW-BINSCAN-003",
                                             "a binary artifact has a malformed ELF/ar header"};
      return kInfo;
    }
    case WarningCode::kBinaryEvidenceLimited:
    {
      static constexpr WarningCodeInfo kInfo{
          "BW-BINSCAN-004", "binary-level dependency evidence is partial for this run"};
      return kInfo;
    }
    case WarningCode::kSbomDocumentInvalid:
    {
      static constexpr WarningCodeInfo kInfo{"BW-SBOM-001", "an SBOM document could not be read"};
      return kInfo;
    }
    case WarningCode::kSbomWrongFormat:
    {
      static constexpr WarningCodeInfo kInfo{
          "BW-SBOM-002", "an SBOM document is not in the expected/recognized format"};
      return kInfo;
    }
    case WarningCode::kSbomComponentEntrySkipped:
    {
      static constexpr WarningCodeInfo kInfo{"BW-SBOM-003", "an SBOM component entry was skipped"};
      return kInfo;
    }
    case WarningCode::kReportConfigFieldInvalid:
    {
      static constexpr WarningCodeInfo kInfo{"BW-OUTPUT-001", "a --report-config field is invalid"};
      return kInfo;
    }
    case WarningCode::kVulnCacheOpenFailed:
    {
      static constexpr WarningCodeInfo kInfo{"BW-VULN-001",
                                             "the vulnerability cache could not be opened"};
      return kInfo;
    }
    case WarningCode::kVulnHttpEndpointNotAllowlisted:
    {
      static constexpr WarningCodeInfo kInfo{
          "BW-VULN-002", "a request targeted a non-allowlisted endpoint and was refused"};
      return kInfo;
    }
    case WarningCode::kVulnHttpRequestFailed:
    {
      static constexpr WarningCodeInfo kInfo{"BW-VULN-003", "an HTTP request failed"};
      return kInfo;
    }
    case WarningCode::kVulnHttpUnexpectedStatus:
    {
      static constexpr WarningCodeInfo kInfo{"BW-VULN-004",
                                             "an HTTP request returned an unexpected status"};
      return kInfo;
    }
    case WarningCode::kVulnResponseMalformed:
    {
      static constexpr WarningCodeInfo kInfo{"BW-VULN-005", "a feed response was malformed"};
      return kInfo;
    }
    case WarningCode::kVulnCoverageIncomplete:
    {
      static constexpr WarningCodeInfo kInfo{
          "BW-VULN-006", "vulnerability match coverage is incomplete for this run"};
      return kInfo;
    }
    case WarningCode::kExternallyDefined:
    {
      // Only reachable if a caller resolves this code directly instead of going through
      // `core::code_info_of`, which returns the registering component's own id and title.
      static constexpr WarningCodeInfo kInfo{"BW-EXT-000", "code defined outside this library"};
      return kInfo;
    }
    case WarningCode::kLicenseFallbackIncomplete:
    {
      static constexpr WarningCodeInfo kInfo{
          "BW-VULN-008", "license-fallback enrichment is incomplete for this run"};
      return kInfo;
    }
  }
  static constexpr WarningCodeInfo kUnreachable{"BW-UNKNOWN", "unregistered warning code"};
  return kUnreachable;
}

}  // namespace bomwerk::core
