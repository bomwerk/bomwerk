#pragma once
#include <string>

#include "vuln/http.hpp"

namespace bomwerk::vuln
{

/// Build the production `HttpPostFunction` backed by libcurl. `user_agent`
/// is sent verbatim (the CLI passes "bomwerk/<version>"); it is supplied by
/// the caller so this module never depends on cli/ (module dependency law).
///
/// Behavior: HTTPS POST with `Content-Type: application/json`; bounded
/// connect/total timeouts (10 s / 60 s) so a dead feed host can never hang a
/// scan; redirects are not followed (the OSV API answers directly: a
/// redirect is suspicious, rule-1 posture); libcurl's standard proxy
/// environment variables (`https_proxy`/`no_proxy`) keep working for on-prem
/// networks; oversized responses abort the transfer (hostile-server
/// defense). Never throws: every failure comes back as `status_code == 0`
/// plus a warning.
///
/// A URL outside `vuln/endpoints.hpp`'s registry is REFUSED before any socket
/// opens: the enforcement point for the pinned-host allowlist that is the
/// control against feed spoofing.
[[nodiscard]] HttpPostFunction make_curl_http_post(std::string user_agent);

/// Build the production `HttpGetFunction` backed by libcurl (NVD's CVE
/// API 2.0 is a GET whose parameters live in the query string). Identical
/// posture to `make_curl_http_post`: same timeouts, same no-redirect rule,
/// same response cap, same endpoint allowlist, same never-throws contract.
///
/// `HttpGetRequest::headers` are passed to libcurl verbatim and never logged:
/// this is the channel an NVD `apiKey` travels on.
[[nodiscard]] HttpGetFunction make_curl_http_get(std::string user_agent);

}  // namespace bomwerk::vuln
