#include "cli/scan_fingerprint.hpp"

#include <spdlog/spdlog.h>

#include <string>

#include "core/percent.hpp"
#include "core/purl.hpp"
#include "core/warning_code.hpp"
#include "heuristics/vendored_cpp.hpp"

namespace fingerprint = bomwerk::heuristics::fingerprint;

namespace bomwerk::cli
{
namespace
{

constexpr const char* kEcosystem = "fingerprint";

/// True when nothing better than the directory's own name is known about this
/// component: unversioned, and carrying precisely the purl the folder name
/// would produce. A versioned component, or one whose name came from a
/// manifest, a version header or a leftover `.git`, fails this and is never
/// renamed.
bool identity_is_folder_derived(const core::Component& component)
{
  return component.version.empty() && !component.root.empty() &&
         component.purl == heuristics::vendored_cpp::folder_derived_purl(component.root);
}

std::string assemble_purl(const std::string& purl_type, const std::string& purl_namespace,
                          const std::string& name, const std::string& version)
{
  std::string purl = "pkg:" + purl_type + "/";
  if (!purl_namespace.empty())
  {
    purl += core::percent_encode(purl_namespace) + "/";
  }
  purl += core::percent_encode(name);
  if (!version.empty())
  {
    purl += "@" + core::percent_encode(version);
  }
  return purl;
}

}  // namespace

core::Result<FingerprintApplication> apply_fingerprint_matches(
    const std::vector<fingerprint::RootMatch>& matches, std::vector<core::Component>& components)
{
  core::Result<FingerprintApplication> result;

  for (const fingerprint::RootMatch& match : matches)
  {
    bool joined = false;
    for (core::Component& component : components)
    {
      if (component.root != match.vendor_root)
      {
        continue;
      }
      joined = true;

      component.evidence.push_back(core::Evidence{
          core::Source::Fingerprint, fingerprint::describe_match(match), match.confidence});

      if (!match.license.empty() && component.license.empty())
      {
        component.license = match.license;
      }

      if (identity_is_folder_derived(component))
      {
        // The ONE shape this pass rewrites. The corpus knows the library by its
        // bytes, which beats a directory name by any measure, and because the
        // predicate above pins the folder-derived branch exactly, an identity
        // some other producer resolved cannot reach this code.
        component.name = match.library_name;
        if (!match.version.empty())
        {
          component.version = match.version;
          ++result.value.versions_filled;
        }
        component.purl =
            assemble_purl(match.purl_type, match.purl_namespace, component.name, component.version);
        ++result.value.identities_rewritten;

        // Dogfood core::Purl, the discipline the vendored heuristic and the
        // submodules producer already apply: a purl this pass cannot parse back
        // is a bug here, not merely degraded input.
        const core::Result<core::Purl> validated = core::Purl::parse(component.purl);
        if (!validated.complete)
        {
          result.warn(core::WarningCode::kPurlValidationFailed,
                      "fingerprint: " + match.vendor_root.string() +
                          " produced an unparsable purl '" + component.purl + "'",
                      kEcosystem, match.vendor_root);
        }
      }
      else if (!component.version.empty() && !match.version.empty() &&
               component.version != match.version)
      {
        // The most valuable thing this pass can report, and the reason it never
        // overwrites: the bytes on disk belong to one release while the project
        // declares another. Both survive, and T93 turns this into a verdict.
        result.warn(core::WarningCode::kFingerprintVersionDisagreement,
                    "fingerprint: " + match.vendor_root.string() + " declares version '" +
                        component.version + "' but its file hashes match " + match.library_name +
                        " " + match.version + ", keeping the declared version",
                    kEcosystem, match.vendor_root);
        ++result.value.version_disagreements;
      }
      // Remaining shape, deliberately evidence-only: an unversioned component
      // whose identity came from somewhere other than its folder name. Adding
      // a version would mean rebuilding a purl this pass did not author, and
      // its type is not ours to change. The evidence above still records what
      // the bytes say.
    }

    if (!joined)
    {
      result.warn(core::WarningCode::kFingerprintMatchWithoutComponent,
                  "fingerprint: " + match.vendor_root.string() + " matches " + match.library_name +
                      " but no component records that location, so there was nothing to enrich",
                  kEcosystem, match.vendor_root);
      ++result.value.matches_without_component;
      continue;
    }
    ++result.value.roots_matched;
  }

  spdlog::debug(
      "fingerprint: {} root(s) enriched, {} version(s) filled, {} identity rewrite(s), "
      "{} disagreement(s), {} match(es) with no component",
      result.value.roots_matched, result.value.versions_filled, result.value.identities_rewritten,
      result.value.version_disagreements, result.value.matches_without_component);
  return result;
}

}  // namespace bomwerk::cli
