#pragma once
#include <functional>
#include <string>
#include <vector>

#include "core/result.hpp"

namespace bomwerk::vuln
{

/// One HTTPS POST carrying a JSON body. The transport adds the
/// `Content-Type: application/json` header itself; `url` must be one of the
/// pinned feed endpoints in `vuln/endpoints.hpp` (allowlisted hosts only), which
/// the transport enforces rather than trusts.
struct HttpRequest
{
  std::string url;
  std::string body;
};

/// One HTTPS GET, the shape NVD's CVE API 2.0 and the bulk feeds
/// need: parameters live in `url`'s query string and authentication (or a
/// conditional-GET validator) is a request header. Same allowlist rule as
/// `HttpRequest`.
struct HttpGetRequest
{
  std::string url;

  /// Extra request headers as `"Name: value"`, appended verbatim. This is how
  /// an `apiKey` reaches NVD, so header VALUES ARE SECRETS: no implementation
  /// may log them or copy them into a warning. The one exception is a
  /// conditional-GET validator (`If-None-Match`/`If-Modified-Since`):
  /// those values originated in a PRIOR response from the same public feed
  /// (see `HttpResponse::etag`/`last_modified` below), so echoing one back is
  /// not a disclosure.
  std::vector<std::string> headers;
};

/// Transport-level outcome. `status_code == 0` means the request never
/// completed (DNS/TCP/TLS/timeout failure): the reason is in the surrounding
/// `Result`'s warnings. `status_code == 304` is a normal, successful outcome
/// (conditional GET): `body` is then empty by construction, never an
/// error to fall back from.
struct HttpResponse
{
  long status_code = 0;
  std::string body;

  /// Response validators for conditional GET, empty when the server sent
  /// none. Deliberately THREE NAMED FIELDS and not a general header map: a
  /// map filled from a hostile server is an unbounded key space and unbounded
  /// memory, while these three are bounded by construction (see
  /// `kMaxHeaderValueBytes` in http_curl.cpp). Only conditional GET and
  /// registry rate-limit backoff need headers today, and a general map would
  /// invite callers to depend on other server-controlled strings this module
  /// has no bounding policy for (rule 1).
  std::string etag;           ///< response `ETag`, verbatim including any weak (`W/`) prefix
  std::string last_modified;  ///< response `Last-Modified`, verbatim: an opaque token to us

  /// response `Retry-After`, verbatim (delay-seconds form only; an HTTP-date
  /// form is left for the caller to treat as unparseable). Unlike `etag`/
  /// `last_modified`, this is read-only backoff guidance for the caller: it
  /// is never echoed back as a request header.
  std::string retry_after;
};

/// Injectable transport: production passes `make_curl_http_post()` (see
/// http_curl.hpp); unit tests pass a lambda returning canned responses so no
/// test ever touches the network. Implementations never throw (rule 1) :
/// failure is `status_code == 0` plus a warning, never an exception.
using HttpPostFunction = std::function<core::Result<HttpResponse>(const HttpRequest&)>;

/// The GET counterpart, injected the same way (`make_curl_http_get()` in
/// production, a canned lambda in tests) with the same never-throws contract.
using HttpGetFunction = std::function<core::Result<HttpResponse>(const HttpGetRequest&)>;

}  // namespace bomwerk::vuln
