#pragma once
#include <string>
#include <string_view>

namespace bomwerk::parsers::cpp
{

/// A conan package reference `name/version@user/channel#revision`, every part
/// after `name` optional. Fields hold verbatim text (a `version` may be a
/// range like `[>=1.2 <2.0]`); nothing is resolved or validated here.
struct ConanReference
{
  std::string name;
  std::string version;
  std::string user;
  std::string channel;
  std::string revision;  ///< recipe revision (the part after '#'), when pinned
};

/// Split a conan reference string into its parts. Accepts every shape conan
/// itself writes: `zlib/1.2.13`, `pkg/1.0@user/channel`, `pkg/1.0#rrev`, the
/// conan-1 lock form `pkg/1.0@#rrev` and the conan-2 lock form with a
/// `%<timestamp>` suffix (dropped). Never throws; unrecognizable input yields
/// fields left empty. Example: `parse_conan_reference("fmt/10.2.1#ab%17.5")`
/// -> `{name: "fmt", version: "10.2.1", revision: "ab"}`.
[[nodiscard]] ConanReference parse_conan_reference(std::string_view reference_text);

/// True when `version` is a conan version-range expression (`[...]`), i.e. a
/// constraint rather than a pinned version: callers downgrade confidence.
[[nodiscard]] bool is_conan_version_range(std::string_view version);

/// Build a `pkg:conan` Package URL: `pkg:conan/<name>[@<version>]` plus
/// `channel`/`user` qualifiers when present and, only when
/// `include_recipe_revision` is set, an `rrev` qualifier. Qualifier keys are
/// emitted in sorted order (`channel` < `rrev` < `user`) and every value is
/// percent-encoded, so the result is byte-stable (rule 3). An empty name
/// degrades to "unknown". Meant to be validated by `core::Purl::parse`.
[[nodiscard]] std::string build_conan_purl(const ConanReference& reference,
                                           bool include_recipe_revision);

}  // namespace bomwerk::parsers::cpp
