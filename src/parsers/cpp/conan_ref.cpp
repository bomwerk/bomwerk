#include "parsers/cpp/conan_ref.hpp"

#include <cstddef>
#include <string>
#include <string_view>

#include "core/percent.hpp"
#include "core/text.hpp"

namespace bomwerk::parsers::cpp
{
namespace
{

constexpr std::string_view kUnknownComponentName = "unknown";

/// Everything before the first `separator`, or all of `text` when absent.
/// The remainder (after the separator) is written to `rest`.
std::string_view split_once(std::string_view text, char separator, std::string_view& rest)
{
  const std::size_t separator_position = text.find(separator);
  if (separator_position == std::string_view::npos)
  {
    rest = {};
    return text;
  }
  rest = text.substr(separator_position + 1);
  return text.substr(0, separator_position);
}

}  // namespace

ConanReference parse_conan_reference(std::string_view reference_text)
{
  ConanReference reference;
  std::string_view remaining = core::trimmed_view(reference_text);

  std::string_view after_hash;
  const std::string_view before_hash = split_once(remaining, '#', after_hash);

  // conan-2 lockfiles append "%<timestamp>" after the revision; drop it. The
  // strip runs only on the post-'#' segment (never on the whole reference),
  // so a stray '%' in the name/version/user/channel portion can never eat
  // a legitimate revision that follows it.
  std::string_view revision_text = after_hash;
  const std::size_t timestamp_position = revision_text.find('%');
  if (timestamp_position != std::string_view::npos)
  {
    revision_text = revision_text.substr(0, timestamp_position);
  }
  reference.revision = core::trimmed(revision_text);

  std::string_view user_channel;
  const std::string_view name_version = split_once(before_hash, '@', user_channel);
  if (!user_channel.empty())
  {
    std::string_view channel;
    reference.user = core::trimmed(split_once(user_channel, '/', channel));
    reference.channel = core::trimmed(channel);
  }

  std::string_view version;
  reference.name = core::trimmed(split_once(name_version, '/', version));
  reference.version = core::trimmed(version);
  return reference;
}

bool is_conan_version_range(std::string_view version)
{
  return !version.empty() && version.front() == '[';
}

std::string build_conan_purl(const ConanReference& reference, bool include_recipe_revision)
{
  std::string purl = "pkg:conan/";
  purl += core::percent_encode(reference.name.empty() ? kUnknownComponentName
                                                      : std::string_view{reference.name});
  if (!reference.version.empty())
  {
    purl += "@" + core::percent_encode(reference.version);
  }
  // Qualifier keys in sorted order (channel < rrev < user), so two runs are
  // byte-identical (rule 3).
  std::string qualifiers;
  if (!reference.channel.empty())
  {
    qualifiers += "channel=" + core::percent_encode(reference.channel) + "&";
  }
  if (include_recipe_revision && !reference.revision.empty())
  {
    qualifiers += "rrev=" + core::percent_encode(reference.revision) + "&";
  }
  if (!reference.user.empty())
  {
    qualifiers += "user=" + core::percent_encode(reference.user) + "&";
  }
  if (!qualifiers.empty())
  {
    qualifiers.pop_back();
    purl += "?" + qualifiers;
  }
  return purl;
}

}  // namespace bomwerk::parsers::cpp
