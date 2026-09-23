#include <cassert>
#include <cstdio>
#include <string>

#include "parsers/cpp/conan_ref.hpp"
#include "support/check.hpp"

using bomwerk::parsers::cpp::build_conan_purl;
using bomwerk::parsers::cpp::ConanReference;
using bomwerk::parsers::cpp::is_conan_version_range;
using bomwerk::parsers::cpp::parse_conan_reference;

int main()
{
  // Given a bare name/version reference, when parsed, then only name and
  // version are set.
  {
    const ConanReference reference = parse_conan_reference("zlib/1.2.13");
    assert(reference.name == "zlib");
    assert(reference.version == "1.2.13");
    assert(reference.user.empty());
    assert(reference.channel.empty());
    assert(reference.revision.empty());
  }

  // Given the full name/version@user/channel#revision form, when parsed, then
  // every field lands where it belongs.
  {
    const ConanReference reference =
        parse_conan_reference("openssl/3.2.0@bincrafters/stable#4f23a5d");
    assert(reference.name == "openssl");
    assert(reference.version == "3.2.0");
    assert(reference.user == "bincrafters");
    assert(reference.channel == "stable");
    assert(reference.revision == "4f23a5d");
  }

  // Given a conan-2 lockfile entry with a %timestamp suffix, when parsed, then
  // the timestamp is dropped and the revision survives.
  {
    const ConanReference reference =
        parse_conan_reference("fmt/10.2.1#f52e03ae3d251dec704634230cd806a2%1708593606.497");
    assert(reference.name == "fmt");
    assert(reference.version == "10.2.1");
    assert(reference.revision == "f52e03ae3d251dec704634230cd806a2");
  }

  // Given a conan-1 lockfile ref with a dangling '@' (empty user/channel),
  // when parsed, then user and channel stay empty.
  {
    const ConanReference reference = parse_conan_reference("zlib/1.2.13@#abc123");
    assert(reference.name == "zlib");
    assert(reference.version == "1.2.13");
    assert(reference.user.empty());
    assert(reference.channel.empty());
    assert(reference.revision == "abc123");
  }

  // Given a hostile reference where a stray '%' precedes the revision (not
  // conan's own format, which always puts '%timestamp' after '#revision'),
  // when parsed, then the '%' strip stays scoped to the post-'#' segment, so
  // the revision is not truncated away by an earlier, unrelated '%'.
  {
    const ConanReference reference = parse_conan_reference("pkg/1.0%oops#deadbeef");
    assert(reference.name == "pkg");
    assert(reference.version == "1.0%oops");
    assert(reference.revision == "deadbeef");
  }

  // Given a version range, when parsed, then the range is kept verbatim as the
  // version and recognized as a range.
  {
    const ConanReference reference = parse_conan_reference("zlib/[>=1.2 <2.0]");
    assert(reference.version == "[>=1.2 <2.0]");
    BOMWERK_TEST_CHECK(is_conan_version_range(reference.version));
    BOMWERK_TEST_CHECK(!is_conan_version_range("1.2.13"));
  }

  // Given surrounding whitespace and a name-only string, when parsed, then the
  // name is trimmed and nothing else is invented. Empty input yields all-empty.
  {
    assert(parse_conan_reference("  cmake  ").name == "cmake");
    assert(parse_conan_reference("  cmake  ").version.empty());
    assert(parse_conan_reference("").name.empty());
  }

  // Given a plain reference, when a purl is built, then it is the canonical
  // pkg:conan form without qualifiers.
  {
    const ConanReference reference = parse_conan_reference("zlib/1.2.13");
    assert(build_conan_purl(reference, false) == "pkg:conan/zlib@1.2.13");
  }

  // Given user/channel and a revision, when purls are built with and without
  // the revision, then qualifiers appear in sorted key order
  // (channel < rrev < user) and rrev is present only on request.
  {
    const ConanReference reference =
        parse_conan_reference("openssl/3.2.0@bincrafters/stable#4f23a5d");
    assert(build_conan_purl(reference, false) ==
           "pkg:conan/openssl@3.2.0?channel=stable&user=bincrafters");
    assert(build_conan_purl(reference, true) ==
           "pkg:conan/openssl@3.2.0?channel=stable&rrev=4f23a5d&user=bincrafters");
  }

  // Given structural bytes leaked from a hostile manifest, when a purl is
  // built, then they are percent-encoded so the purl stays well-formed.
  {
    ConanReference reference;
    reference.name = "bad name";
    reference.version = "[>=1.2 <2.0]";
    assert(build_conan_purl(reference, false) == "pkg:conan/bad%20name@%5B%3E%3D1.2%20%3C2.0%5D");
  }

  // Given a reference with an empty name, when a purl is built, then the name
  // degrades to "unknown" rather than an invalid purl.
  {
    ConanReference reference;
    reference.version = "1.0";
    assert(build_conan_purl(reference, false) == "pkg:conan/unknown@1.0");
  }

  std::puts("test_conan_ref: OK");
  return 0;
}
