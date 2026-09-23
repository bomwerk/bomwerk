// ctest unit test for core model (framework-free on purpose; Catch2 optional later)
#include <cassert>
#include <cstdio>
#include <string_view>

#include "core/model.hpp"

using bomwerk::core::Component;
using bomwerk::core::component_identity;
using bomwerk::core::Confidence;
using bomwerk::core::highest_confidence;
using bomwerk::core::merge_all;
using bomwerk::core::ReleaseMeta;
using bomwerk::core::Scope;
using bomwerk::core::Source;

int main()
{
  // Given two findings with the same purl, when they are merged, then they
  // become one component with unioned evidence and filled metadata.
  Component zlib_from_manifest;
  zlib_from_manifest.name = "zlib";
  zlib_from_manifest.version = "1.2.11";
  zlib_from_manifest.purl = "pkg:generic/zlib@1.2.11";
  zlib_from_manifest.evidence.push_back({Source::Manifest, "vcpkg.json", Confidence::High});

  Component zlib_from_heuristic;
  zlib_from_heuristic.purl = "pkg:generic/zlib@1.2.11";
  zlib_from_heuristic.cpe = "cpe:2.3:a:*:zlib:1.2.11:*:*:*:*:*:*:*";
  zlib_from_heuristic.license = "Zlib";
  zlib_from_heuristic.evidence.push_back(
      {Source::Heuristic, "third_party/zlib/LICENSE", Confidence::Medium});
  zlib_from_heuristic.used_in_build = false;

  auto merged_components = merge_all({zlib_from_manifest, zlib_from_heuristic});
  assert(merged_components.size() == 1);
  assert(merged_components[0].name == "zlib");
  assert(merged_components[0].cpe == "cpe:2.3:a:*:zlib:1.2.11:*:*:*:*:*:*:*");
  assert(merged_components[0].license == "Zlib");      // field filled from the heuristic finding
  assert(merged_components[0].evidence.size() == 2);   // evidence unioned
  assert(merged_components[0].used_in_build == true);  // any-true wins
  assert(highest_confidence(merged_components[0]) == Confidence::High);

  // Given duplicate evidence for one component, when it is merged, then the
  // duplicate collapses to the highest confidence observation.
  Component openssl_from_manifest;
  openssl_from_manifest.purl = "pkg:conan/openssl@3.2.0";
  openssl_from_manifest.evidence.push_back({Source::Manifest, "conan.lock", Confidence::Low});

  Component openssl_from_lock_refresh;
  openssl_from_lock_refresh.purl = "pkg:conan/openssl@3.2.0";
  openssl_from_lock_refresh.evidence.push_back({Source::Manifest, "conan.lock", Confidence::High});

  auto merged_openssl_components = merge_all({openssl_from_manifest, openssl_from_lock_refresh});
  assert(merged_openssl_components.size() == 1);
  assert(merged_openssl_components[0].evidence.size() == 1);
  assert(merged_openssl_components[0].evidence[0].confidence == Confidence::High);

  // Given the same purl marked dev-only by one lockfile and runtime by
  // another, when merged in either order, then the least restrictive scope
  // wins (Required > Optional > Excluded): runtime use anywhere trumps a
  // dev-only marking, and merge order cannot change the outcome (rule 3).
  {
    Component dev_only_finding;
    dev_only_finding.purl = "pkg:npm/typescript@5.4.5";
    dev_only_finding.scope = Scope::Excluded;
    Component runtime_finding;
    runtime_finding.purl = "pkg:npm/typescript@5.4.5";

    auto runtime_wins_forward = merge_all({dev_only_finding, runtime_finding});
    assert(runtime_wins_forward.size() == 1);
    assert(runtime_wins_forward[0].scope == Scope::Required);

    auto runtime_wins_reversed = merge_all({runtime_finding, dev_only_finding});
    assert(runtime_wins_reversed.size() == 1);
    assert(runtime_wins_reversed[0].scope == Scope::Required);
  }

  // Given the same purl marked Excluded by one finding and Optional by
  // another, when merged in either order, then Optional (the less restrictive
  // of the two) wins.
  {
    Component excluded_finding;
    excluded_finding.purl = "pkg:npm/eslint@9.0.0";
    excluded_finding.scope = Scope::Excluded;
    Component optional_finding;
    optional_finding.purl = "pkg:npm/eslint@9.0.0";
    optional_finding.scope = Scope::Optional;

    auto optional_wins_forward = merge_all({excluded_finding, optional_finding});
    assert(optional_wins_forward.size() == 1);
    assert(optional_wins_forward[0].scope == Scope::Optional);

    auto optional_wins_reversed = merge_all({optional_finding, excluded_finding});
    assert(optional_wins_reversed.size() == 1);
    assert(optional_wins_reversed[0].scope == Scope::Optional);
  }

  // Given two findings that agree the purl is dev-only, when merged, then the
  // Excluded marking survives: nothing claimed runtime use.
  {
    Component first_dev_finding;
    first_dev_finding.purl = "pkg:pypi/pytest@8.0.0";
    first_dev_finding.scope = Scope::Excluded;
    Component second_dev_finding;
    second_dev_finding.purl = "pkg:pypi/pytest@8.0.0";
    second_dev_finding.scope = Scope::Excluded;

    auto still_excluded = merge_all({first_dev_finding, second_dev_finding});
    assert(still_excluded.size() == 1);
    assert(still_excluded[0].scope == Scope::Excluded);
  }

  // Given equivalent PURLs with different scheme/type case, when they are
  // merged, then the canonical PURL identity is used.
  Component uppercase_purl_component;
  uppercase_purl_component.purl = "PKG:CONAN/openssl@3.2.0";
  Component lowercase_purl_component;
  lowercase_purl_component.purl = "pkg:conan/openssl@3.2.0";
  auto canonical_purl_components = merge_all({uppercase_purl_component, lowercase_purl_component});
  assert(canonical_purl_components.size() == 1);

  // Given similar but different versions, when they are merged, then core does
  // not guess ecosystem-specific version equivalence.
  Component short_version_component;
  short_version_component.purl = "pkg:conan/openssl@1.2";
  Component patch_version_component;
  patch_version_component.purl = "pkg:conan/openssl@1.2.0";
  auto distinct_version_components = merge_all({short_version_component, patch_version_component});
  assert(distinct_version_components.size() == 2);

  // Given multiple components, when they are merged, then output is purl-sorted
  // for deterministic SBOM generation.
  Component npm_component;
  npm_component.purl = "pkg:npm/a@1";
  Component conan_component;
  conan_component.purl = "pkg:conan/b@2";
  auto sorted_components = merge_all({npm_component, conan_component});
  assert(sorted_components[0].purl == "pkg:conan/b@2");
  assert(sorted_components[1].purl == "pkg:npm/a@1");

  // Given a component with a well-formed, already-canonical purl, when its
  // identity is computed, then the identity equals that purl.
  Component canonical_purl_component;
  canonical_purl_component.name = "openssl";
  canonical_purl_component.version = "3.2.0";
  canonical_purl_component.purl = "pkg:conan/openssl@3.2.0";
  assert(component_identity(canonical_purl_component) == "pkg:conan/openssl@3.2.0");

  // Given a component whose purl uses non-canonical scheme/type casing, when
  // its identity is computed, then the identity is the canonicalized
  // (lowercased) form, not the raw input: the exact behavior a duplicated,
  // never-canonicalizing identity helper would get wrong.
  Component uppercase_scheme_component;
  uppercase_scheme_component.name = "openssl";
  uppercase_scheme_component.version = "3.2.0";
  uppercase_scheme_component.purl = "PKG:CONAN/openssl@3.2.0";
  assert(component_identity(uppercase_scheme_component) == "pkg:conan/openssl@3.2.0");

  // Given a component with no purl, when its identity is computed, then it
  // falls back to `name@version`.
  Component purl_less_component;
  purl_less_component.name = "vendored-thing";
  purl_less_component.version = "2.0";
  assert(component_identity(purl_less_component) == "vendored-thing@2.0");

  // Given a default-constructed ReleaseMeta, when inspected, then every field
  // starts empty: "not supplied" is the documented meaning callers rely on
  // (cli/scan_command.cpp omits metadata.component on an empty product_id).
  {
    ReleaseMeta empty_release_meta;
    assert(empty_release_meta.product_id.empty());
    assert(empty_release_meta.version.empty());
    assert(empty_release_meta.support_until.empty());
  }

  // Given a ReleaseMeta with values assigned, when read back, then each field
  // holds exactly what was assigned to it.
  {
    ReleaseMeta populated_release_meta;
    populated_release_meta.product_id = "widget-firmware";
    populated_release_meta.version = "2.4.1";
    populated_release_meta.support_until = "2028-01-01";
    assert(populated_release_meta.product_id == "widget-firmware");
    assert(populated_release_meta.version == "2.4.1");
    assert(populated_release_meta.support_until == "2028-01-01");
  }

  // Given each confidence level, when rendered as its display label, then the
  // lower-case string table shared by the CLI listing and the HTML report
  // is returned.
  {
    assert(std::string_view(to_string(Confidence::High)) == "high");
    assert(std::string_view(to_string(Confidence::Medium)) == "medium");
    assert(std::string_view(to_string(Confidence::Low)) == "low");
  }

  // Given each scope, when rendered as its CycloneDX token, then the exact
  // schema enum spelling is returned (protocol strings, never localized).
  {
    assert(std::string_view(to_string(Scope::Required)) == "required");
    assert(std::string_view(to_string(Scope::Optional)) == "optional");
    assert(std::string_view(to_string(Scope::Excluded)) == "excluded");
  }

  std::puts("test_model: OK");
  return 0;
}
