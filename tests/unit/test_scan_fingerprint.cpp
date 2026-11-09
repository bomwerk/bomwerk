// ctest unit test for the CLI-level fingerprint reconciler: what a corpus
// match is allowed to change about a component's identity, and what it is not.
#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <filesystem>
#include <string>
#include <vector>

#include "cli/scan_fingerprint.hpp"
#include "core/model.hpp"
#include "core/result.hpp"
#include "heuristics/fingerprint.hpp"
#include "support/check.hpp"

namespace fs = std::filesystem;
namespace fingerprint = bomwerk::heuristics::fingerprint;

using bomwerk::cli::apply_fingerprint_matches;
using bomwerk::cli::FingerprintApplication;
using bomwerk::core::Component;
using bomwerk::core::Confidence;
using bomwerk::core::merge_all;
using bomwerk::core::Result;
using bomwerk::core::Source;
using bomwerk::core::WarningCode;

namespace
{

/// Exactly what `heuristics::vendored_cpp` emits for a vendor root it could
/// only name after its folder: no version, and a `pkg:generic/<folder>` purl.
/// The reconciler's whole identity-rewrite rule is keyed on this shape, so the
/// test has to reproduce it faithfully rather than approximately.
Component folder_derived_component(const std::string& folder, const fs::path& root)
{
  Component component;
  component.name = folder;
  component.purl = "pkg:generic/" + folder;
  component.root = root;
  component.evidence.push_back({Source::Heuristic,
                                root.string() + " -> found under a vendored-code trigger directory",
                                Confidence::Low});
  return component;
}

Component header_versioned_component(const std::string& name, const std::string& version,
                                     const fs::path& root)
{
  Component component;
  component.name = name;
  component.version = version;
  component.purl = "pkg:generic/" + name + "@" + version;
  component.root = root;
  component.evidence.push_back(
      {Source::Heuristic, root.string() + " -> #define VERSION", Confidence::Medium});
  return component;
}

fingerprint::RootMatch make_match(const fs::path& vendor_root, const std::string& library,
                                  const std::string& version, std::size_t matched,
                                  std::size_t considered)
{
  fingerprint::RootMatch match;
  match.vendor_root = vendor_root;
  match.library_name = library;
  match.purl_type = "generic";
  match.license = "MIT";
  match.version = version;
  match.matched_files = matched;
  match.files_considered = considered;
  match.release_file_count = considered;
  match.corpus_revision = "2026-11-02";
  match.confidence = Confidence::Medium;
  return match;
}

bool has_warning(const std::vector<bomwerk::core::Warning>& warnings, WarningCode code)
{
  return std::any_of(warnings.begin(), warnings.end(), [code](const bomwerk::core::Warning& warning)
                     { return warning.code == code; });
}

std::size_t fingerprint_evidence_count(const Component& component)
{
  return static_cast<std::size_t>(
      std::count_if(component.evidence.begin(), component.evidence.end(),
                    [](const bomwerk::core::Evidence& evidence)
                    { return evidence.source == Source::Fingerprint; }));
}

/// The headline win: a prebuilt directory bomwerk could only name after its
/// folder becomes the real library at its real version, because the bytes said
/// so. This is nightmare's cJSON case.
void a_folder_derived_identity_is_corrected()
{
  std::vector<Component> components{
      folder_derived_component("cjson-prebuilt", "third_party/cjson-prebuilt")};
  const std::vector<fingerprint::RootMatch> matches{
      make_match("third_party/cjson-prebuilt", "cjson", "1.7.15", 2, 2)};

  const Result<FingerprintApplication> applied = apply_fingerprint_matches(matches, components);

  BOMWERK_TEST_CHECK(applied.complete);
  BOMWERK_TEST_CHECK(applied.value.roots_matched == 1);
  BOMWERK_TEST_CHECK(applied.value.identities_rewritten == 1);
  BOMWERK_TEST_CHECK(applied.value.versions_filled == 1);
  BOMWERK_TEST_CHECK(components.size() == 1);
  BOMWERK_TEST_CHECK(components[0].name == "cjson");
  BOMWERK_TEST_CHECK(components[0].version == "1.7.15");
  BOMWERK_TEST_CHECK(components[0].purl == "pkg:generic/cjson@1.7.15");
  // The location survives the rewrite: it is the join key, and `trim` needs it.
  BOMWERK_TEST_CHECK(components[0].root == fs::path("third_party/cjson-prebuilt"));
  BOMWERK_TEST_CHECK(components[0].license == "MIT");
  BOMWERK_TEST_CHECK(fingerprint_evidence_count(components[0]) == 1);
  // The heuristic's own evidence is kept: this pass adds, it does not replace.
  BOMWERK_TEST_CHECK(components[0].evidence.size() == 2);
}

/// A corpus that identified the library but could not decide between releases
/// still improves the name, and must NOT invent a version.
void an_undecided_version_still_corrects_the_name()
{
  std::vector<Component> components{folder_derived_component("uthash", "third_party/uthash")};
  fingerprint::RootMatch match = make_match("third_party/uthash", "uthash", std::string(), 1, 1);
  match.candidate_versions = {"2.3.0", "2.4.0"};
  match.confidence = Confidence::Low;

  const Result<FingerprintApplication> applied = apply_fingerprint_matches({match}, components);

  BOMWERK_TEST_CHECK(applied.value.identities_rewritten == 1);
  BOMWERK_TEST_CHECK(applied.value.versions_filled == 0);
  BOMWERK_TEST_CHECK(components[0].version.empty());
  BOMWERK_TEST_CHECK(components[0].purl == "pkg:generic/uthash");
  BOMWERK_TEST_CHECK(fingerprint_evidence_count(components[0]) == 1);
}

/// nightmare's FreeRTOS case. The header says V11.1.0 and the corpus agrees on
/// the version, so there is no disagreement to report: the value of the
/// evidence is the COUNT, which says one file is not upstream.
void an_agreeing_version_is_left_alone_and_gains_evidence()
{
  std::vector<Component> components{
      header_versioned_component("freertos", "V11.1.0", "third_party/freertos")};
  const std::vector<fingerprint::RootMatch> matches{
      make_match("third_party/freertos", "freertos", "V11.1.0", 9, 14)};

  const Result<FingerprintApplication> applied = apply_fingerprint_matches(matches, components);

  BOMWERK_TEST_CHECK(applied.value.roots_matched == 1);
  BOMWERK_TEST_CHECK(applied.value.identities_rewritten == 0);
  BOMWERK_TEST_CHECK(applied.value.version_disagreements == 0);
  BOMWERK_TEST_CHECK(components[0].purl == "pkg:generic/freertos@V11.1.0");
  BOMWERK_TEST_CHECK(fingerprint_evidence_count(components[0]) == 1);
  const auto fingerprint_evidence =
      std::find_if(components[0].evidence.begin(), components[0].evidence.end(),
                   [](const bomwerk::core::Evidence& evidence)
                   { return evidence.source == Source::Fingerprint; });
  BOMWERK_TEST_CHECK(fingerprint_evidence->detail ==
                     "9 of 14 hashed files match freertos V11.1.0 (corpus 2026-11-02)");
}

/// The rule that protects every other producer: a version somebody else
/// resolved is never overwritten, and the conflict is reported instead. This is
/// what makes a vendor fork that re-points its version header visible.
void a_disagreeing_version_is_reported_and_never_overwritten()
{
  std::vector<Component> components{
      header_versioned_component("zlib", "1.3.1", "third_party/zlib")};
  const std::vector<fingerprint::RootMatch> matches{
      make_match("third_party/zlib", "zlib", "1.2.11", 22, 24)};

  const Result<FingerprintApplication> applied = apply_fingerprint_matches(matches, components);

  BOMWERK_TEST_CHECK(applied.value.version_disagreements == 1);
  BOMWERK_TEST_CHECK(applied.value.identities_rewritten == 0);
  BOMWERK_TEST_CHECK(components[0].version == "1.3.1");
  BOMWERK_TEST_CHECK(components[0].purl == "pkg:generic/zlib@1.3.1");
  BOMWERK_TEST_CHECK(has_warning(applied.warnings, WarningCode::kFingerprintVersionDisagreement));
  // The corpus's finding is still on the record, in the evidence.
  BOMWERK_TEST_CHECK(fingerprint_evidence_count(components[0]) == 1);
  // A disagreement is a finding, not a broken scan.
  BOMWERK_TEST_CHECK(applied.complete);
}

/// An identity another producer authored is never rewritten, however strong the
/// match. A `pkg:conan/...` purl is not this pass's to re-type.
void a_non_folder_derived_identity_is_never_rewritten()
{
  Component from_manifest;
  from_manifest.name = "zlib";
  from_manifest.purl = "pkg:conan/zlib";  // unversioned, but NOT folder-derived
  from_manifest.root = "third_party/zlib";
  from_manifest.evidence.push_back({Source::Manifest, "conanfile.txt", Confidence::High});
  std::vector<Component> components{from_manifest};

  fingerprint::RootMatch match = make_match("third_party/zlib", "zlib", "1.2.11", 22, 24);
  match.confidence = Confidence::High;
  const Result<FingerprintApplication> applied = apply_fingerprint_matches({match}, components);

  BOMWERK_TEST_CHECK(applied.value.identities_rewritten == 0);
  BOMWERK_TEST_CHECK(applied.value.versions_filled == 0);
  BOMWERK_TEST_CHECK(components[0].purl == "pkg:conan/zlib");
  BOMWERK_TEST_CHECK(components[0].version.empty());
  // Evidence-only is the point: the finding is recorded without touching
  // identity.
  BOMWERK_TEST_CHECK(fingerprint_evidence_count(components[0]) == 1);
}

/// A folder-derived purl for a DIFFERENT directory than the one matched must
/// not be touched, which is really a test that the join key is the root path
/// and nothing looser.
void only_the_matched_root_is_enriched()
{
  std::vector<Component> components{folder_derived_component("zlib", "third_party/zlib"),
                                    folder_derived_component("zlib", "vendor/zlib")};
  const std::vector<fingerprint::RootMatch> matches{
      make_match("third_party/zlib", "zlib", "1.2.11", 3, 3)};

  const Result<FingerprintApplication> applied = apply_fingerprint_matches(matches, components);

  BOMWERK_TEST_CHECK(applied.value.roots_matched == 1);
  BOMWERK_TEST_CHECK(components[0].purl == "pkg:generic/zlib@1.2.11");
  BOMWERK_TEST_CHECK(components[1].purl == "pkg:generic/zlib");
  BOMWERK_TEST_CHECK(fingerprint_evidence_count(components[1]) == 0);
}

/// A match with no component to attach to is reported, not turned into a new
/// component: v1 refuses to become a second producer of identity.
void a_match_with_no_component_is_reported_not_invented()
{
  std::vector<Component> components;
  const std::vector<fingerprint::RootMatch> matches{
      make_match("third_party/lwip", "lwip", "2.1.3", 5, 5)};

  const Result<FingerprintApplication> applied = apply_fingerprint_matches(matches, components);

  BOMWERK_TEST_CHECK(components.empty());
  BOMWERK_TEST_CHECK(applied.value.matches_without_component == 1);
  BOMWERK_TEST_CHECK(applied.value.roots_matched == 0);
  BOMWERK_TEST_CHECK(has_warning(applied.warnings, WarningCode::kFingerprintMatchWithoutComponent));
  BOMWERK_TEST_CHECK(applied.complete);
}

/// Why this pass runs BEFORE core::merge_all: the rewritten purl has to be the
/// merge key. A lockfile that already declared the same identity must end up as
/// ONE component, not two sharing a bom-ref.
void a_rewritten_identity_merges_with_a_matching_declaration()
{
  Component declared;
  declared.name = "cjson";
  declared.version = "1.7.15";
  declared.purl = "pkg:generic/cjson@1.7.15";
  declared.evidence.push_back({Source::Manifest, "conanfile.txt", Confidence::High});

  std::vector<Component> components{
      folder_derived_component("cjson-prebuilt", "third_party/cjson-prebuilt"), declared};
  const std::vector<fingerprint::RootMatch> matches{
      make_match("third_party/cjson-prebuilt", "cjson", "1.7.15", 2, 2)};

  const Result<FingerprintApplication> applied = apply_fingerprint_matches(matches, components);
  BOMWERK_TEST_CHECK(applied.value.identities_rewritten == 1);

  const std::vector<Component> merged = merge_all(components);
  BOMWERK_TEST_CHECK(merged.size() == 1);
  BOMWERK_TEST_CHECK(merged[0].purl == "pkg:generic/cjson@1.7.15");
  // The union of both producers' evidence, fingerprint included.
  BOMWERK_TEST_CHECK(fingerprint_evidence_count(merged[0]) == 1);
  BOMWERK_TEST_CHECK(merged[0].root == fs::path("third_party/cjson-prebuilt"));
}

/// No matches means nothing changes at all, which is the regression guard for
/// "off unless an operator names an index".
void no_matches_changes_nothing()
{
  const Component original = folder_derived_component("stb", "third_party/stb");
  std::vector<Component> components{original};

  const Result<FingerprintApplication> applied = apply_fingerprint_matches({}, components);

  BOMWERK_TEST_CHECK(applied.warnings.empty());
  BOMWERK_TEST_CHECK(applied.value.roots_matched == 0);
  BOMWERK_TEST_CHECK(components.size() == 1);
  BOMWERK_TEST_CHECK(components[0].purl == original.purl);
  BOMWERK_TEST_CHECK(components[0].name == original.name);
  BOMWERK_TEST_CHECK(components[0].evidence.size() == original.evidence.size());
}

}  // namespace

int main()
{
  a_folder_derived_identity_is_corrected();
  an_undecided_version_still_corrects_the_name();
  an_agreeing_version_is_left_alone_and_gains_evidence();
  a_disagreeing_version_is_reported_and_never_overwritten();
  a_non_folder_derived_identity_is_never_rewritten();
  only_the_matched_root_is_enriched();
  a_match_with_no_component_is_reported_not_invented();
  a_rewritten_identity_merges_with_a_matching_declaration();
  no_matches_changes_nothing();
  std::puts("test_scan_fingerprint: OK");
  return 0;
}
