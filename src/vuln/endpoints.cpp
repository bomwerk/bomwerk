#include "vuln/endpoints.hpp"

#include <span>
#include <string_view>
#include <vector>

namespace bomwerk::vuln
{
namespace
{

bool is_safe_registry_subpath(std::string_view subpath)
{
  if (subpath.empty())
  {
    return false;
  }
  while (!subpath.empty())
  {
    const std::size_t separator = subpath.find('/');
    const std::string_view segment = subpath.substr(0, separator);
    if (segment.empty() || segment == "." || segment == "..")
    {
      return false;
    }
    for (const char character : segment)
    {
      const bool is_allowed = (character >= 'a' && character <= 'z') ||
                              (character >= '0' && character <= '9') || character == '.' ||
                              character == '_' || character == '+' || character == '-';
      if (!is_allowed)
      {
        return false;
      }
    }
    if (separator == std::string_view::npos)
    {
      return true;
    }
    subpath.remove_prefix(separator + 1);
  }
  return false;
}

}  // namespace

namespace
{

/// Registered once at startup and never mutated afterwards, so the read side needs no lock.
std::vector<FeedEndpoint>& registered_endpoints_storage()
{
  static std::vector<FeedEndpoint> storage;
  return storage;
}

}  // namespace

void register_feed_endpoints(std::span<const FeedEndpoint> endpoints)
{
  std::vector<FeedEndpoint>& storage = registered_endpoints_storage();
  storage.insert(storage.end(), endpoints.begin(), endpoints.end());
}

std::span<const FeedEndpoint> registered_feed_endpoints()
{
  return registered_endpoints_storage();
}

bool is_allowlisted_feed_url(std::string_view url)
{
  const auto matches = [&url](const FeedEndpoint& endpoint)
  {
    if (url == endpoint.url)
    {
      return true;
    }
    if (endpoint.allows_subpaths)
    {
      return url.starts_with(endpoint.url) &&
             is_safe_registry_subpath(url.substr(endpoint.url.size()));
    }
    // The only permitted extension of a registered URL is a query string, so
    // the character right after the endpoint must be '?' and nothing else :
    // a further path segment or a look-alike host suffix never matches.
    return url.size() > endpoint.url.size() && url.starts_with(endpoint.url) &&
           url[endpoint.url.size()] == '?';
  };

  for (const FeedEndpoint& endpoint : kFeedEndpoints)
  {
    if (matches(endpoint))
    {
      return true;
    }
  }
  for (const FeedEndpoint& endpoint : registered_feed_endpoints())
  {
    if (matches(endpoint))
    {
      return true;
    }
  }
  return false;
}

}  // namespace bomwerk::vuln
