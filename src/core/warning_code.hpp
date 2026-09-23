#pragma once
#include <string_view>

namespace bomwerk::core
{

/// A stable identity for the CAUSE behind a `core::Warning`, independent of
/// which call site raised it, which producer's message text happens to describe it, or
/// which ecosystem it fired for (that is carried separately, in `Warning::ecosystem`).
/// Rewording a message, or moving it between producers, must never change its code.
///
/// Registered permanently in `warning_code_info()` (warning_code.cpp): an id there is never
/// renumbered and never reused for a different meaning once shipped, even if the cause it
/// names later becomes unreachable: retire it in place rather than deleting the entry.
/// Enum-value ordering/insertion position carries no meaning; only the string id looked up
/// through `warning_code_info()` is the permanent contract, so new values may be inserted
/// anywhere in this list.
enum class WarningCode
{
  // --- Shared manifest/lockfile parsing guards -----------------------------------------
  // One code per CAUSE, reused across every ecosystem parser that can hit it (npm, pnpm,
  // yarn, composer, cargo, go, maven, nuget, python, rubygems, conan, vcpkg, cmake,
  // github-actions, ...); the specific ecosystem is recorded in `Warning::ecosystem`, not
  // baked into the code, so "JSON nesting exceeds depth limit" stays ONE cause everywhere
  // it fires rather than one per ecosystem.
  kJsonNestingDepthExceeded,
  kInvalidJson,
  kInvalidToml,
  kEntryLimitReached,      ///< package/dependency/requirement/reference count budget hit
  kFileLimitReached,       ///< too many manifest/lockfile files for one ecosystem, budget hit
  kFileSizeLimitExceeded,  ///< a single manifest/lockfile file exceeded its byte budget
  kUnreadableFile,
  kPurlValidationFailed,       ///< a component's assembled purl failed validation
  kEntriesSkippedUnresolved,   ///< N entries lacked a name/version/resolution and were skipped
  kMalformedEntrySkipped,      ///< one entry had an unreadable/unexpected shape and was skipped
  kLockfileFormatUnsupported,  ///< a recognized lockfile's format/version this producer can't read
  kSelfIdentityUnresolvable,   ///< the manifest's own component lacks enough identity to emit
  kUnresolvedVariableOrInterpolation,  ///< a name/version depends on an unresolved variable
  kDependencyMissingSource,            ///< a dependency declaration has no name, repository or URL
  kUnpinnedOrUnresolvedRef,            ///< a dependency is not pinned to a resolved reference

  // --- Cross-ecosystem coverage gaps (core::find_unparsed_manifests) -------------------
  kManifestNoLockfileAlongside,  ///< loose manifest found, no lockfile beside it (BW-CORE-004)
  kManifestUnsupportedLockfile,  ///< a real lockfile found, no parser for it yet

  // --- core: file walking, purl parsing, name lists -------------------------------------
  kDirectoryWalkError,
  kBuildOutputDirectoryHoldsManifest,
  kPurlMalformed,  ///< core::parse_purl rejected a purl the caller supplied
  kNameListUnreadable,
  kNameListEmpty,

  // --- Repo-level config validation (every TOML config a build reads shares this shape) -
  kConfigNotValidToml,
  kConfigFileUnreadable,
  kConfigFileTooLarge,
  kConfigKeyWrongType,
  kConfigArrayEntryInvalid,
  kConfigUnknownKey,
  kConfigUnknownTable,
  kConfigTopLevelKeyNotTable,
  kConfigValueInvalidFormat,
  kConfigDeprecatedKeyRemoved,
  kConfigSecretRejected,
  kConfigSectionIncomplete,
  kConfigFileNotWritten,

  // --- git metadata (submodules, .git/config) -------------------------------------------
  kGitConfigStructureInvalid,
  kSubmoduleMissingPath,
  kSubmoduleUnsafePath,
  kSubmoduleNotInitialized,
  kSubmoduleNoUrl,

  // --- observe (build-trace capture; Hard Rule 6 sign-off given for this migration) --
  kObserveTraceNotWritten,
  kObserveTraceMalformedLines,
  kObserveTraceExceedsLimit,
  kObserveTraceRewriteFailed,
  kObserveShimBinaryMissing,
  kObserveShimDirectoryUnwritable,
  kObserveShimCreationFailed,
  kObserveNoToolchainFound,
  kObserveNoCompilerInvocations,
  kObserveEvidenceOutsideRoot,
  kObserveResponseFilesUnexpanded,
  kObserveUnresolvedLinkArgument,
  kObserveAutoDetectedTraceUnusable,  ///< an auto-detected (not operator-selected) trace could
                                      ///< not be applied; the scan proceeds without it
  kObserveNoRootedComponents,         ///< a trace applied cleanly but judged zero components used

  // --- binscan (ELF/ar reader) -------------------------------------------------------
  kBinaryUnreadable,
  kBinaryTooLarge,
  kBinaryMalformedHeader,
  kBinaryEvidenceLimited,  ///< summary diagnostics about why dynamic-dependency evidence is
                           ///< partial for this run (static/relocatable artifacts, artifacts
                           ///< outside the scan root, unrecognized formats, ...)

  // --- sbom readers (the inverse of output's writers) ------------------------------------
  kSbomDocumentInvalid,  ///< not JSON, no components array, unreadable, oversized
  kSbomWrongFormat,      ///< SPDX where CycloneDX was expected, or unrecognized entirely
  kSbomComponentEntrySkipped,

  // --- output writers -------------------------------------------------------------------
  kReportConfigFieldInvalid,

  // --- vuln (OSV/NVD clients, license-fallback enrichment, shared HTTP transport) -------
  kVulnCacheOpenFailed,
  kVulnHttpEndpointNotAllowlisted,
  kVulnHttpRequestFailed,
  kVulnHttpUnexpectedStatus,
  kVulnResponseMalformed,
  kVulnCoverageIncomplete,  ///< stale/rate-limited/unresolved/paginated-incomplete counts
  kLicenseFallbackIncomplete,

  // --- codes owned by a component outside this library ----------------------------------
  // A build that composes extra modules registers their ids through `Warning::external_code`
  // rather than adding values here, so this enum stays the list of causes this library can
  // itself raise. `warning_code_info` never resolves one of those: `core::code_info_of`
  // (warning.hpp) is what every consumer calls.
  kExternallyDefined,
};

/// One `WarningCode`'s permanent identity: the id shown to operators and written into
/// `--warnings` manifests (e.g. "BW-CORE-004"), and a short title for documentation. Never
/// throws; every `WarningCode` value has an entry (enforced by a unit test, not just this
/// comment).
struct WarningCodeInfo
{
  std::string_view id;
  std::string_view title;
};

[[nodiscard]] const WarningCodeInfo& warning_code_info(WarningCode code);

}  // namespace bomwerk::core
