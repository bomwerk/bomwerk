// ctest unit test for the go.sum producer (framework-free on purpose).
#include <cstdio>
#include <string>
#include <vector>

#include "core/model.hpp"
#include "parsers/lockfiles/go.hpp"
#include "support/check.hpp"
#include "support/temp_tree.hpp"

using bomwerk::core::Component;
using bomwerk::core::Confidence;
using bomwerk::core::highest_confidence;
using bomwerk::core::Result;
using bomwerk::test::TempTree;

namespace go_parser = bomwerk::parsers::lockfiles::go;

int main()
{
  // Given a go.sum with two modules (zip + /go.mod line each), when parsed,
  // then each module becomes ONE High-confidence component with the exact
  // resolver version, purl-sorted, and the /go.mod lines add nothing.
  {
    TempTree tree;
    tree.write(
        "go.sum",
        "github.com/gorilla/mux v1.8.0 h1:i40aqfkR1h2SlN9hojwV5ZA91wcXFOvkdNIeFDP5koI=\n"
        "github.com/gorilla/mux v1.8.0/go.mod h1:DVbg23sWSpFRCP0SfiEN6jmj59UnW/n46BH5rLB71So=\n"
        "golang.org/x/text v0.14.0 h1:ScX5w1eTa3QqT8oi6+ziP7dTV1S2+ALU0bI+0zXKWiQ=\n"
        "golang.org/x/text v0.14.0/go.mod h1:18ZOQIKpY8NJVqYksKHtTdi31H5itFRjB5/qKTNYzSU=\n");

    const Result<std::vector<Component>> result = go_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 2);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:golang/github.com/gorilla/mux@v1.8.0");
    BOMWERK_TEST_CHECK(result.value[1].purl == "pkg:golang/golang.org/x/text@v0.14.0");
    BOMWERK_TEST_CHECK(result.value[0].name == "github.com/gorilla/mux");
    BOMWERK_TEST_CHECK(result.value[0].version == "v1.8.0");
    BOMWERK_TEST_CHECK(highest_confidence(result.value[0]) == Confidence::High);
    // A known-forge module path's owner segment doubles as NTIA/CRA
    // supplier evidence; golang.org's "x/" vanity path states no publisher
    // this parser can trust, so it stays empty rather than guessing "x".
    BOMWERK_TEST_CHECK(result.value[0].supplier == "gorilla");
    BOMWERK_TEST_CHECK(result.value[1].supplier.empty());
  }

  // Given a module path with upper-case segments, when parsed, then the purl
  // is lower-cased per the purl-spec golang type while Component::name keeps
  // the module path exactly as declared.
  {
    TempTree tree;
    tree.write(
        "go.sum",
        "github.com/Masterminds/semver v1.5.0 h1:H65muMkzWKEuNDnfl9d70GUjFniHKHRbFPGBuZ3QEww=\n");

    const Result<std::vector<Component>> result = go_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:golang/github.com/masterminds/semver@v1.5.0");
    BOMWERK_TEST_CHECK(result.value[0].name == "github.com/Masterminds/semver");
  }

  // Given a pseudo-version (untagged commit), when parsed, then it passes
  // through untouched: it IS Go's exact resolved version.
  {
    TempTree tree;
    tree.write("go.sum",
               "golang.org/x/sys v0.0.0-20220908164124-27713097b956 "
               "h1:XeJjHH1KiLpKGb6lvMiksZ9l0fVUh+AmGcm0nOMEBOY=\n");

    const Result<std::vector<Component>> result = go_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].version == "v0.0.0-20220908164124-27713097b956");
  }

  // Given a module that appears ONLY as a /go.mod line (graph-only, pruned
  // from the build), when parsed, then it is deliberately not reported.
  {
    TempTree tree;
    tree.write("go.sum",
               "github.com/graph-only/dep v1.0.0/go.mod "
               "h1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=\n");

    const Result<std::vector<Component>> result = go_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.empty());
  }

  // Given malformed lines mixed with a good one (hostile input), when parsed,
  // then the good line survives, the run degrades with ONE counted warning,
  // and nothing crashes (rule 1).
  {
    TempTree tree;
    tree.write("go.sum",
               "only-two fields\n"
               "way too many fields on one line here\n"
               "github.com/good/mod v1.0.0 h1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=\n");

    const Result<std::vector<Component>> result = go_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.warnings.size() == 1);
    BOMWERK_TEST_CHECK(result.warnings[0].message.find("2 malformed line(s)") != std::string::npos);
  }

  // Given an empty go.sum and a tree with no go.sum at all, when parsed, then
  // both yield a clean empty result: absence is not an error.
  {
    TempTree tree;
    tree.write("go.sum", "");
    const Result<std::vector<Component>> empty_file_result = go_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(empty_file_result.complete);
    BOMWERK_TEST_CHECK(empty_file_result.value.empty());
    BOMWERK_TEST_CHECK(empty_file_result.warnings.empty());

    TempTree bare_tree;
    bare_tree.write("README.md", "no go here\n");
    const Result<std::vector<Component>> no_file_result = go_parser::parse(bare_tree.root());
    BOMWERK_TEST_CHECK(no_file_result.complete);
    BOMWERK_TEST_CHECK(no_file_result.value.empty());
  }

  // Given a go.sum larger than the byte cap, when parsed, then the readable
  // prefix still yields components, the cut-off tail line is dropped rather
  // than counted malformed, and the run warns about the partial parse.
  {
    TempTree tree;
    const std::string first_line =
        "github.com/first/mod v1.0.0 h1:ccccccccccccccccccccccccccccccccccccccccccc=\n";
    const std::string second_line =
        "github.com/second/mod v2.0.0 h1:ddddddddddddddddddddddddddddddddddddddddddd=\n";
    tree.write("go.sum", first_line + second_line);

    go_parser::ParseOptions options;
    options.max_file_bytes = first_line.size() + 10;  // cuts the second line mid-way
    const Result<std::vector<Component>> result = go_parser::parse(tree.root(), options);
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:golang/github.com/first/mod@v1.0.0");
    BOMWERK_TEST_CHECK(result.warnings.size() == 1);
    BOMWERK_TEST_CHECK(result.warnings[0].message.find("parsing first part only") !=
                       std::string::npos);
  }

  // Given more module lines than max_total_packages, when parsed, then the
  // budget stops the parse early with a warning instead of unbounded output.
  {
    TempTree tree;
    tree.write("go.sum",
               "github.com/a/one v1.0.0 h1:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee=\n"
               "github.com/b/two v1.0.0 h1:fffffffffffffffffffffffffffffffffffffffffff=\n"
               "github.com/c/three v1.0.0 h1:ggggggggggggggggggggggggggggggggggggggggggg=\n");

    go_parser::ParseOptions options;
    options.max_total_packages = 2;
    const Result<std::vector<Component>> result = go_parser::parse(tree.root(), options);
    BOMWERK_TEST_CHECK(!result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 2);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:golang/github.com/a/one@v1.0.0");
    BOMWERK_TEST_CHECK(result.value[1].purl == "pkg:golang/github.com/b/two@v1.0.0");
    BOMWERK_TEST_CHECK(result.warnings.size() == 1);
    BOMWERK_TEST_CHECK(result.warnings[0].message.find("go: package limit 2 reached") !=
                       std::string::npos);

    options.max_total_packages = 3;
    const Result<std::vector<Component>> exact_limit_result =
        go_parser::parse(tree.root(), options);
    BOMWERK_TEST_CHECK(exact_limit_result.complete);
    BOMWERK_TEST_CHECK(exact_limit_result.value.size() == 3);
    BOMWERK_TEST_CHECK(exact_limit_result.warnings.empty());
  }

  // Given one go.sum exactly filling the budget plus a second with another
  // valid entry, when parsed, then that later entry proves exhaustion: the
  // deterministic prefix survives, the result is incomplete, exactly one
  // warning is emitted, and the over-budget module does not leak into the
  // result.
  {
    TempTree tree;
    tree.write("go.sum",
               "github.com/a/one v1.0.0 h1:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee=\n"
               "github.com/b/two v1.0.0 h1:fffffffffffffffffffffffffffffffffffffffffff=\n");
    tree.write("vendor/other/go.sum",
               "github.com/d/four v1.0.0 h1:iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii=\n");

    go_parser::ParseOptions options;
    options.max_total_packages = 2;
    const Result<std::vector<Component>> result = go_parser::parse(tree.root(), options);
    BOMWERK_TEST_CHECK(!result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 2);
    BOMWERK_TEST_CHECK(result.warnings.size() == 1);
    for (const Component& component : result.value)
    {
      BOMWERK_TEST_CHECK(component.name != "github.com/d/four");
    }
  }

  // Given a single-segment module path (no slash), when parsed, then the purl
  // carries no namespace and still validates.
  {
    TempTree tree;
    tree.write("go.sum", "modfoo v0.1.0 h1:hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh=\n");

    const Result<std::vector<Component>> result = go_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:golang/modfoo@v0.1.0");
    // No host segment at all: no supplier to attribute.
    BOMWERK_TEST_CHECK(result.value[0].supplier.empty());
  }

  // Given a final line without a trailing newline, when parsed, then that
  // line is still read: files written by other tools do end this way.
  {
    TempTree tree;
    tree.write("go.sum",
               "github.com/no/newline v3.0.0 h1:iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii=");

    const Result<std::vector<Component>> result = go_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:golang/github.com/no/newline@v3.0.0");
  }

  // Given more go.sum files than a caller-tightened max_scanned_files allows,
  // when parsed, then a warning reports the cap, the run stays complete, and
  // the scanned subset is the path-sorted (deterministic) one.
  {
    TempTree tree;
    tree.write("a/go.sum", "github.com/example/aaa v1.0.0 h1:AAAA=\n");
    tree.write("z/go.sum", "github.com/example/zzz v1.0.0 h1:ZZZZ=\n");
    go_parser::ParseOptions options;
    options.max_scanned_files = 1;
    const auto result = go_parser::parse(tree.root(), options);
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(!result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:golang/github.com/example/aaa@v1.0.0");
  }

  std::puts("test_go: OK");
  return 0;
}
