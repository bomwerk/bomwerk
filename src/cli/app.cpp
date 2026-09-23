#include "cli/app.hpp"

#include <cstdio>
#include <memory>
#include <string>

#include "vuln/endpoints.hpp"

#ifndef BOMWERK_VERSION
#define BOMWERK_VERSION "0.0.0-dev"
#endif

namespace bomwerk::cli
{
namespace
{

// User-facing strings kept together (future --lang de|es, docs/CONTRIBUTING.md style).

// One-line tagline shown at the top of --help; keep it short (like git/cmake).
constexpr const char* kDescription = "Build-accurate SBOMs & EU Cyber Resilience Act evidence.";

// The full pitch lives behind --about so --help stays scannable.
constexpr const char* kAbout =
    "bomwerk builds a Software Bill of Materials from what your project actually declares\n"
    "and, eventually, what it actually links: matched against known vulnerabilities and\n"
    "EU Cyber Resilience Act evidence. On-prem: your code never leaves your machines.\n";

constexpr const char* kFooter =
    "Examples:\n"
    "  bomwerk scan .                              scan the current directory\n"
    "  bomwerk scan src/ -o sbom.spdx.json --format spdx\n"
    "  bomwerk observe -- cmake --build build      record what the build really compiled\n"
    "  bomwerk trim sbom.cdx.json                  report which components the build used\n"
    "  bomwerk binscan sbom.cdx.json               read the binaries the build produced\n"
    "\n"
    "Exit codes: 0 clean, 1 completed with warnings, 2 incomplete";

// Header and footer of `--endpoints`. This output exists so a customer's
// security team can open a firewall without reading our source, so it states
// the guarantee as plainly as the list itself.
constexpr const char* kEndpointsHeader =
    "bomwerk makes outbound HTTPS requests to these hosts, and to no others.\n"
    "Your source code never leaves the machine: the only data sent is a package\n"
    "coordinate: a purl, a resolved commit id, or a CPE match string.\n"
    "\n"
    "There are no inbound ports and no telemetry.\n"
    "\n";

constexpr const char* kEndpointsFooter =
    "\n"
    "`bomwerk scan --offline` contacts none of them and answers from the local\n"
    "cache alone. Requests honor the standard https_proxy / no_proxy variables.\n";

/// Print the one registry of outbound endpoints (vuln/endpoints.hpp). Reading
/// the same array the transport enforces is the point: what the security team
/// is told and what the binary can reach cannot drift apart.
void print_network_endpoints()
{
  const auto print_endpoint = [](const vuln::FeedEndpoint& endpoint)
  {
    // "%.*s" because these are string_views: never assume null termination.
    std::printf("  %.*s\n", static_cast<int>(endpoint.name.size()), endpoint.name.data());
    std::printf("    %.*s\n", static_cast<int>(endpoint.url.size()), endpoint.url.data());
    std::printf("    %.*s\n\n", static_cast<int>(endpoint.purpose.size()), endpoint.purpose.data());
  };

  std::fputs(kEndpointsHeader, stdout);
  for (const vuln::FeedEndpoint& endpoint : vuln::kFeedEndpoints)
  {
    print_endpoint(endpoint);
  }
  // A composed build registers its own endpoints; this build prints whatever it can reach,
  // which is what makes the list usable for a firewall rule.
  for (const vuln::FeedEndpoint& endpoint : vuln::registered_feed_endpoints())
  {
    print_endpoint(endpoint);
  }
  std::fputs(kEndpointsFooter, stdout);
}

}  // namespace

const char* version()
{
  return BOMWERK_VERSION;
}

void configure_root_app(CLI::App& application)
{
  application.name("bomwerk");
  application.description(kDescription);
  application.set_version_flag("-V,--version", std::string("bomwerk ") + version());
  application.require_subcommand(1);
  application.footer(kFooter);

  // --about prints the full product pitch and exits cleanly. trigger_on_parse
  // runs the callback during parsing (before require_subcommand is enforced),
  // so it behaves like --help/--version; CLI::Success => zero exit via exit().
  application
      .add_flag_callback(
          "--about",
          []()
          {
            std::fputs(kAbout, stdout);
            throw CLI::Success();
          },
          "Show what bomwerk is and exit")
      ->trigger_on_parse();

  // --endpoints lists every host bomwerk can contact, for a security team to
  // allowlist. Same trigger_on_parse/CLI::Success shape as --about above.
  application
      .add_flag_callback(
          "--endpoints",
          []()
          {
            print_network_endpoints();
            throw CLI::Success();
          },
          "List every outbound network endpoint bomwerk uses and exit")
      ->trigger_on_parse();

  // CLI11 reflows the footer as a paragraph by default, which destroys the
  // column alignment of the examples: keep it verbatim.
  auto help_formatter = std::make_shared<CLI::Formatter>();
  help_formatter->enable_footer_formatting(false);
  application.formatter(help_formatter);
}

}  // namespace bomwerk::cli
