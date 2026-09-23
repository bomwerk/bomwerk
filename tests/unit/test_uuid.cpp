#include <cstdio>
#include <string>

#include "core/uuid.hpp"
#include "support/check.hpp"

using bomwerk::core::purl_namespace;
using bomwerk::core::uuidv5;

int main()
{
  // Given the fixed bomwerk purl-namespace UUID, when printed, then it
  // matches uuid.uuid5(uuid.NAMESPACE_DNS, "bomwerk.dev") computed with
  // Python's stdlib `uuid` module (RFC 4122 reference implementation): the
  // documented derivation for this constant (see the header doc comment).
  BOMWERK_TEST_CHECK(purl_namespace().to_string() == "a9ed27b8-aeaa-5158-8f3a-400932505998");

  // Given the same namespace and name, when hashed twice, then the same
  // UUID results (rule 3: deterministic identity): and it matches Python's
  // `uuid.uuid5(NAMESPACE, name)` for three example purls, cross-checking
  // the hand-rolled SHA-1 against a trusted reference implementation.
  {
    const auto first = uuidv5(purl_namespace(), "pkg:vcpkg/zlib@1.3.1");
    const auto second = uuidv5(purl_namespace(), "pkg:vcpkg/zlib@1.3.1");
    BOMWERK_TEST_CHECK(first.to_string() == second.to_string());
    BOMWERK_TEST_CHECK(first.to_string() == "4a33ce74-17ee-58ce-b2e0-4524c65bf3bf");
  }
  BOMWERK_TEST_CHECK(uuidv5(purl_namespace(), "pkg:vcpkg/fmt").to_string() ==
                     "5c9dbb9e-de34-538d-884c-93494aeffb9f");
  BOMWERK_TEST_CHECK(uuidv5(purl_namespace(), "pkg:conan/openssl@3.2.0").to_string() ==
                     "d379cb1f-684b-575b-85d3-55696333bcbf");

  // Given two different names, when hashed, then the UUIDs differ.
  BOMWERK_TEST_CHECK(uuidv5(purl_namespace(), "pkg:vcpkg/fmt").to_string() !=
                     uuidv5(purl_namespace(), "pkg:vcpkg/zlib@1.3.1").to_string());

  // Given any UUIDv5 output, when inspected, then the version nibble is 5
  // and the variant nibble is in the RFC 9562 §4.1 range (8, 9, a, or b) :
  // the two bit-twiddles the algorithm must apply after hashing. Position 14
  // is the first hex digit of the third group, position 19 the first of the
  // fourth (canonical "8-4-4-4-12" layout).
  {
    const std::string uuid_text = uuidv5(purl_namespace(), "pkg:generic/anything").to_string();
    BOMWERK_TEST_CHECK(uuid_text[14] == '5');
    BOMWERK_TEST_CHECK(uuid_text[19] == '8' || uuid_text[19] == '9' || uuid_text[19] == 'a' ||
                       uuid_text[19] == 'b');
  }

  // Given an empty name, when hashed, then a well-formed (not degenerate)
  // UUID still results: never a crash on an empty purl.
  BOMWERK_TEST_CHECK(uuidv5(purl_namespace(), "").to_string().size() == 36);

  std::puts("test_uuid: OK");
  return 0;
}
