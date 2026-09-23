#include "vuln/http_curl.hpp"

#include <curl/curl.h>

#include <chrono>
#include <cstddef>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>

#include "core/text.hpp"
#include "core/warning_code.hpp"
#include "vuln/endpoints.hpp"

namespace bomwerk::vuln
{
namespace
{

/// Bounded network patience: a vulnerability lookup is best-effort
/// enrichment, never worth hanging a scan for (rule 1: partial output beats
/// none).
constexpr std::chrono::seconds kConnectTimeout(10);
constexpr std::chrono::seconds kTotalTimeout(60);

/// Hostile-server defense: abort a transfer that exceeds this many response
/// bytes. Real OSV querybatch and NVD CVE responses are at most a few MiB;
/// 32 MiB is generous headroom without letting a malicious proxy exhaust memory.
constexpr std::size_t kMaxResponseBytes = 32u * 1024u * 1024u;

/// Cap on one captured response-header VALUE (conditional GET). A
/// validator is an opaque token of a few dozen bytes: a bulk feed's ETag
/// measured 22 bytes on 2026-08-23: so 256 comfortably accommodates any sane
/// server while making a misbehaving one unable to grow the response object;
/// an over-long value is dropped rather than truncated-and-kept, since a
/// truncated validator would never again compare equal to itself.
constexpr std::size_t kMaxHeaderValueBytes = 256;

/// libcurl's global state must be initialized exactly once per process,
/// before the first easy handle, and is deliberately never cleaned up
/// (process lifetime, per libcurl's guidance for multi-threaded programs).
/// `std::call_once` also makes this safe when the CLI runs the OSV and NVD
/// clients on separate threads.
void ensure_curl_global_initialization()
{
  static std::once_flag initialization_flag;
  std::call_once(initialization_flag, [] { curl_global_init(CURL_GLOBAL_DEFAULT); });
}

/// CURLOPT_WRITEFUNCTION target: append the received bytes to a std::string,
/// aborting the transfer (by consuming zero bytes) past kMaxResponseBytes.
std::size_t append_response_bytes(char* received_data, std::size_t member_size,
                                  std::size_t member_count, void* destination)
{
  auto* response_body = static_cast<std::string*>(destination);
  const std::size_t received_byte_count = member_size * member_count;
  if (response_body->size() + received_byte_count > kMaxResponseBytes)
  {
    return 0;  // libcurl turns this into CURLE_WRITE_ERROR
  }
  response_body->append(received_data, received_byte_count);
  return received_byte_count;
}

/// The two response validators a conditional GET refresh needs. A plain
/// struct rather than reusing `HttpResponse` directly: the callback fires
/// before we know the request even succeeded, so it writes into a local that
/// `perform_and_collect` only adopts into the result on success, the same
/// pattern the write callback already uses for `response_body`.
struct CapturedResponseHeaders
{
  std::string etag;
  std::string last_modified;
  std::string retry_after;
};

/// CURLOPT_HEADERFUNCTION target: libcurl calls this once per response header
/// LINE (plus once for the status line and once for the blank terminator),
/// never assembling them for us. Every line is consumed (the return value
/// tells libcurl how many bytes we accepted; returning anything else aborts
/// the transfer), and only the two names we care about are retained: this is
/// what keeps a hostile server's headers from growing the response object
/// (rule 1: bounded by construction, mirrors kMaxHeaderValueBytes above).
std::size_t capture_response_header(char* header_line, std::size_t member_size,
                                    std::size_t member_count, void* destination)
{
  auto* captured = static_cast<CapturedResponseHeaders*>(destination);
  const std::size_t header_length = member_size * member_count;
  std::string_view line(header_line, header_length);
  while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
  {
    line.remove_suffix(1);
  }

  const std::size_t colon_position = line.find(':');
  if (colon_position == std::string_view::npos)
  {
    return header_length;  // the status line, or a malformed line: not a header we track
  }

  const std::string_view name = core::trimmed_view(line.substr(0, colon_position));
  std::string_view value = core::trimmed_view(line.substr(colon_position + 1));
  if (value.size() > kMaxHeaderValueBytes)
  {
    return header_length;  // a validator this long is a server misbehaving, not a real one
  }

  if (core::equals_ascii_ignore_case(name, "etag"))
  {
    captured->etag.assign(value);
  }
  else if (core::equals_ascii_ignore_case(name, "last-modified"))
  {
    captured->last_modified.assign(value);
  }
  else if (core::equals_ascii_ignore_case(name, "retry-after"))
  {
    captured->retry_after.assign(value);
  }
  return header_length;
}

struct CurlEasyHandleDeleter
{
  void operator()(CURL* easy_handle) const { curl_easy_cleanup(easy_handle); }
};

struct CurlStringListDeleter
{
  void operator()(curl_slist* string_list) const { curl_slist_free_all(string_list); }
};

using CurlEasyHandle = std::unique_ptr<CURL, CurlEasyHandleDeleter>;
using CurlStringList = std::unique_ptr<curl_slist, CurlStringListDeleter>;

/// The shared posture of every request this module makes, applied identically
/// to GET and POST: no signals (thread-safety), no redirects (a feed endpoint
/// that redirects is suspicious: rule-1 posture), bounded connect/total
/// timeouts so a dead feed host can never hang a scan, compressed transfer
/// encodings welcome, a bounded response writer, and response-validator
/// capture for conditional GET.
void apply_shared_request_options(CURL* easy_handle, const std::string& url,
                                  const std::string& user_agent, curl_slist* request_headers,
                                  std::string& response_body,
                                  CapturedResponseHeaders& captured_headers)
{
  curl_easy_setopt(easy_handle, CURLOPT_URL, url.c_str());
  curl_easy_setopt(easy_handle, CURLOPT_HTTPHEADER, request_headers);
  curl_easy_setopt(easy_handle, CURLOPT_USERAGENT, user_agent.c_str());
  curl_easy_setopt(easy_handle, CURLOPT_ACCEPT_ENCODING, "");
  curl_easy_setopt(easy_handle, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(easy_handle, CURLOPT_FOLLOWLOCATION, 0L);
  curl_easy_setopt(
      easy_handle, CURLOPT_CONNECTTIMEOUT_MS,
      static_cast<long>(
          std::chrono::duration_cast<std::chrono::milliseconds>(kConnectTimeout).count()));
  curl_easy_setopt(
      easy_handle, CURLOPT_TIMEOUT_MS,
      static_cast<long>(
          std::chrono::duration_cast<std::chrono::milliseconds>(kTotalTimeout).count()));
  curl_easy_setopt(easy_handle, CURLOPT_WRITEFUNCTION, append_response_bytes);
  curl_easy_setopt(easy_handle, CURLOPT_WRITEDATA, &response_body);
  curl_easy_setopt(easy_handle, CURLOPT_HEADERFUNCTION, capture_response_header);
  curl_easy_setopt(easy_handle, CURLOPT_HEADERDATA, &captured_headers);
}

/// Refuse a URL that is not in `vuln/endpoints.hpp`'s registry BEFORE any
/// socket opens. The pinned-host allowlist is the control against feed
/// spoofing; enforcing it here rather than trusting each call
/// site is what makes the control real. Reported like any transport failure
/// (`status_code == 0` plus a warning) so callers need no new error path.
bool reject_unless_allowlisted(const std::string& url, const char* method,
                               core::Result<HttpResponse>& result)
{
  if (is_allowlisted_feed_url(url))
  {
    return false;
  }
  // The URL is echoed because it is bomwerk's own construction, never a
  // secret; request HEADERS are never echoed anywhere in this file.
  result.warn(core::WarningCode::kVulnHttpEndpointNotAllowlisted,
              std::string("HTTP ") + method + " refused: " + url +
                  " is not an allowlisted bomwerk feed endpoint (see --endpoints)");
  return true;
}

/// Run a configured handle and fold the outcome into `result`. `status_code`
/// and `body` are collected on ANY completed request, including a `304 Not
/// Modified` (an empty body there is correct, not a partial failure) :
/// only a transport-level failure (DNS/TCP/TLS/timeout) skips this and leaves
/// `result.value` at its default.
void perform_and_collect(CURL* easy_handle, const std::string& url, const char* method,
                         std::string& response_body, CapturedResponseHeaders& captured_headers,
                         core::Result<HttpResponse>& result)
{
  const CURLcode perform_status = curl_easy_perform(easy_handle);
  if (perform_status != CURLE_OK)
  {
    result.warn(core::WarningCode::kVulnHttpRequestFailed,
                std::string("HTTP ") + method + " to " + url +
                    " failed: " + curl_easy_strerror(perform_status));
    return;
  }

  long http_status_code = 0;
  curl_easy_getinfo(easy_handle, CURLINFO_RESPONSE_CODE, &http_status_code);
  result.value.status_code = http_status_code;
  result.value.body = std::move(response_body);
  result.value.etag = std::move(captured_headers.etag);
  result.value.last_modified = std::move(captured_headers.last_modified);
  result.value.retry_after = std::move(captured_headers.retry_after);
}

}  // namespace

HttpPostFunction make_curl_http_post(std::string user_agent)
{
  return
      [user_agent = std::move(user_agent)](const HttpRequest& request) -> core::Result<HttpResponse>
  {
    core::Result<HttpResponse> result;
    if (reject_unless_allowlisted(request.url, "POST", result))
    {
      return result;
    }
    ensure_curl_global_initialization();

    const CurlEasyHandle easy_handle(curl_easy_init());
    if (easy_handle == nullptr)
    {
      result.warn(core::WarningCode::kVulnHttpRequestFailed,
                  "HTTP POST to " + request.url + " failed: libcurl initialization failed");
      return result;
    }

    const CurlStringList request_headers(
        curl_slist_append(nullptr, "Content-Type: application/json"));

    std::string response_body;
    CapturedResponseHeaders captured_headers;
    apply_shared_request_options(easy_handle.get(), request.url, user_agent, request_headers.get(),
                                 response_body, captured_headers);
    curl_easy_setopt(easy_handle.get(), CURLOPT_POSTFIELDSIZE,
                     static_cast<long>(request.body.size()));
    curl_easy_setopt(easy_handle.get(), CURLOPT_COPYPOSTFIELDS, request.body.c_str());

    perform_and_collect(easy_handle.get(), request.url, "POST", response_body, captured_headers,
                        result);
    return result;
  };
}

HttpGetFunction make_curl_http_get(std::string user_agent)
{
  return [user_agent =
              std::move(user_agent)](const HttpGetRequest& request) -> core::Result<HttpResponse>
  {
    core::Result<HttpResponse> result;
    if (reject_unless_allowlisted(request.url, "GET", result))
    {
      return result;
    }
    ensure_curl_global_initialization();

    const CurlEasyHandle easy_handle(curl_easy_init());
    if (easy_handle == nullptr)
    {
      result.warn(core::WarningCode::kVulnHttpRequestFailed,
                  "HTTP GET to " + request.url + " failed: libcurl initialization failed");
      return result;
    }

    // Caller-supplied headers may carry an API key. They are handed straight
    // to libcurl and are never logged, warned about, or otherwise copied.
    CurlStringList request_headers;
    for (const std::string& header : request.headers)
    {
      curl_slist* extended = curl_slist_append(request_headers.get(), header.c_str());
      if (extended == nullptr)
      {
        result.warn(core::WarningCode::kVulnHttpRequestFailed,
                    "HTTP GET to " + request.url + " failed: cannot build request headers");
        return result;
      }
      // curl_slist_append owns the list from here; release before re-adopting
      // so the extended head is freed exactly once.
      static_cast<void>(request_headers.release());
      request_headers.reset(extended);
    }

    std::string response_body;
    CapturedResponseHeaders captured_headers;
    apply_shared_request_options(easy_handle.get(), request.url, user_agent, request_headers.get(),
                                 response_body, captured_headers);
    curl_easy_setopt(easy_handle.get(), CURLOPT_HTTPGET, 1L);

    perform_and_collect(easy_handle.get(), request.url, "GET", response_body, captured_headers,
                        result);
    return result;
  };
}

}  // namespace bomwerk::vuln
