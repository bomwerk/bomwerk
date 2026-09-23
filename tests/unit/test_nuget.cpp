// ctest unit test for the packages.lock.json producer (framework-free).
#include <cstdio>
#include <string>
#include <vector>

#include "core/model.hpp"
#include "core/warning.hpp"
#include "parsers/lockfiles/nuget.hpp"
#include "support/check.hpp"
#include "support/temp_tree.hpp"

using bomwerk::core::Component;
using bomwerk::core::Confidence;
using bomwerk::core::highest_confidence;
using bomwerk::core::Result;
using bomwerk::core::Scope;
using bomwerk::test::TempTree;

namespace nuget_parser = bomwerk::parsers::lockfiles::nuget;

int main()
{
  // Given a v1 lockfile with a Direct, a Transitive and a Project entry, when
  // parsed, then the Project reference is skipped (first-party), both packages
  // are High confidence with preserved casing, and the contentHash lands in
  // the evidence detail: never in Component::sha256. (The `requested` range
  // a real lockfile carries is omitted here: its literal text `[x, )` ends in
  // the raw-string terminator sequence, and the parser never reads it.)
  {
    TempTree tree;
    tree.write("packages.lock.json", R"({
      "version": 1,
      "dependencies": {
        "net8.0": {
          "Newtonsoft.Json": {
            "type": "Direct",
            "resolved": "13.0.3",
            "contentHash": "HrC5BXdl00IP9zeV+0Z848QWPAoCr9P3bDEZguI+gkLcBKAOxix/tLEAAHC+UvDNPv4a2d18lOReHMOagPa+zQ=="
          },
          "Serilog": {
            "type": "Transitive",
            "resolved": "3.1.1"
          },
          "My.Own.Library": {
            "type": "Project"
          }
        }
      }
    })");

    const Result<std::vector<Component>> result = nuget_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 2);
    // Purl-sorted: Newtonsoft.Json < Serilog.
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:nuget/Newtonsoft.Json@13.0.3");
    BOMWERK_TEST_CHECK(result.value[1].purl == "pkg:nuget/Serilog@3.1.1");
    BOMWERK_TEST_CHECK(result.value[0].scope == Scope::Required);
    BOMWERK_TEST_CHECK(result.value[0].sha256.empty());
    BOMWERK_TEST_CHECK(result.value[0].evidence.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].evidence[0].detail.find("net8.0, Direct") !=
                       std::string::npos);
    BOMWERK_TEST_CHECK(result.value[0].evidence[0].detail.find("contentHash HrC5") !=
                       std::string::npos);
    BOMWERK_TEST_CHECK(highest_confidence(result.value[0]) == Confidence::High);
  }

  // Given the same package resolved under two target frameworks, when parsed,
  // then merge_all folds it into ONE component with one evidence entry per
  // framework.
  {
    TempTree tree;
    tree.write("packages.lock.json", R"({
      "version": 2,
      "dependencies": {
        "net6.0": {
          "Serilog": { "type": "Transitive", "resolved": "3.1.1" }
        },
        "net8.0": {
          "Serilog": { "type": "Transitive", "resolved": "3.1.1" }
        }
      }
    })");

    const Result<std::vector<Component>> result = nuget_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:nuget/Serilog@3.1.1");
    BOMWERK_TEST_CHECK(result.value[0].evidence.size() == 2);
  }

  // Given hostile input: not JSON at all, and JSON nested past the depth
  // limit: when parsed, then each degrades to exactly one warning and never
  // crashes (rule 1).
  {
    TempTree tree;
    tree.write("packages.lock.json", "this is not json {{{{");

    const Result<std::vector<Component>> result = nuget_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.empty());
    BOMWERK_TEST_CHECK(result.warnings.size() == 1);
    BOMWERK_TEST_CHECK(result.warnings[0].message.find("not valid JSON") != std::string::npos);
  }
  {
    TempTree tree;
    std::string deeply_nested;
    for (int depth = 0; depth < 200; ++depth)
    {
      deeply_nested += "[";
    }
    tree.write("packages.lock.json", deeply_nested);

    const Result<std::vector<Component>> result = nuget_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.empty());
    BOMWERK_TEST_CHECK(result.warnings.size() == 1);
    BOMWERK_TEST_CHECK(result.warnings[0].message.find("nesting exceeds depth limit") !=
                       std::string::npos);
  }

  // Given entries without a resolved version and a lockfile without a
  // dependencies map, when parsed, then each file reports one warning and the
  // well-formed entry survives.
  {
    TempTree tree;
    tree.write("packages.lock.json", R"({
      "version": 1,
      "dependencies": {
        "net8.0": {
          "NoResolved": { "type": "Direct" },
          "Kept": { "type": "Direct", "resolved": "1.0.0" }
        }
      }
    })");
    tree.write("other/packages.lock.json", R"({ "version": 1 })");

    const Result<std::vector<Component>> result = nuget_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:nuget/Kept@1.0.0");
    BOMWERK_TEST_CHECK(result.warnings.size() == 2);
  }

  // Given three NuGet packages and a budget of two, when parsed, then the
  // deterministic two-entry prefix is retained and the result is incomplete.
  // Given a budget equal to the entry count, then the result remains complete.
  {
    TempTree tree;
    tree.write("packages.lock.json", R"({
      "version": 1,
      "dependencies": {
        "net8.0": {
          "Alpha": { "type": "Direct", "resolved": "1.0.0" },
          "Beta": { "type": "Direct", "resolved": "2.0.0" },
          "Gamma": { "type": "Direct", "resolved": "3.0.0" }
        }
      }
    })");

    nuget_parser::ParseOptions options;
    options.max_total_packages = 2;
    const Result<std::vector<Component>> result = nuget_parser::parse(tree.root(), options);
    BOMWERK_TEST_CHECK(!result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 2);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:nuget/Alpha@1.0.0");
    BOMWERK_TEST_CHECK(result.value[1].purl == "pkg:nuget/Beta@2.0.0");
    BOMWERK_TEST_CHECK(result.warnings.size() == 1);
    BOMWERK_TEST_CHECK(result.warnings[0].message.find("nuget: package limit 2 reached") !=
                       std::string::npos);

    options.max_total_packages = 3;
    const Result<std::vector<Component>> exact_limit_result =
        nuget_parser::parse(tree.root(), options);
    BOMWERK_TEST_CHECK(exact_limit_result.complete);
    BOMWERK_TEST_CHECK(exact_limit_result.value.size() == 3);
    BOMWERK_TEST_CHECK(exact_limit_result.warnings.empty());
  }

  // Given more packages.lock.json files than a caller-tightened
  // max_scanned_files allows, when parsed, then a warning reports the cap,
  // the run stays complete, and the scanned subset is the path-sorted
  // (deterministic) one.
  {
    TempTree tree;
    tree.write("a/packages.lock.json", R"({
      "version": 1,
      "dependencies": {
        "net8.0": {
          "Aaa": { "type": "Direct", "resolved": "1.0.0" }
        }
      }
    })");
    tree.write("z/packages.lock.json", R"({
      "version": 1,
      "dependencies": {
        "net8.0": {
          "Zzz": { "type": "Direct", "resolved": "1.0.0" }
        }
      }
    })");
    nuget_parser::ParseOptions options;
    options.max_scanned_files = 1;
    const auto result = nuget_parser::parse(tree.root(), options);
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(!result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:nuget/Aaa@1.0.0");
  }

  // Given a .csproj with PackageReference entries in both self-closing and
  // explicit-close form, and one entry missing Version, when parsed, then the
  // two well-formed entries emit at Medium confidence and the malformed one
  // is skipped with a warning.
  {
    TempTree tree;
    tree.write("MyApp.csproj", R"(<Project Sdk="Microsoft.NET.Sdk">
      <ItemGroup>
        <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
        <PackageReference Include="Serilog" Version="3.1.1"></PackageReference>
        <PackageReference Include="NoVersion" />
      </ItemGroup>
    </Project>)");

    const Result<std::vector<Component>> result = nuget_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 2);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:nuget/Newtonsoft.Json@13.0.3");
    BOMWERK_TEST_CHECK(result.value[1].purl == "pkg:nuget/Serilog@3.1.1");
    BOMWERK_TEST_CHECK(highest_confidence(result.value[0]) == Confidence::Medium);
    BOMWERK_TEST_CHECK(highest_confidence(result.value[1]) == Confidence::Medium);
    BOMWERK_TEST_CHECK(result.warnings.size() == 1);
    BOMWERK_TEST_CHECK(result.warnings[0].message.find(
                           "1 entrie(s) without a resolvable version") != std::string::npos);
  }

  // Given a packages.config with `package` entries, when parsed, then each
  // emits at Medium confidence and `targetFramework` is not part of the purl.
  {
    TempTree tree;
    tree.write("packages.config", R"(<?xml version="1.0" encoding="utf-8"?>
    <packages>
      <package id="nanoFramework.Json" version="2.1.0" targetFramework="net472" />
      <package id="EntityFramework" version="6.2.0" targetFramework="net472" />
    </packages>)");

    const Result<std::vector<Component>> result = nuget_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 2);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:nuget/EntityFramework@6.2.0");
    BOMWERK_TEST_CHECK(result.value[1].purl == "pkg:nuget/nanoFramework.Json@2.1.0");
    BOMWERK_TEST_CHECK(highest_confidence(result.value[0]) == Confidence::Medium);
  }

  // Given the same package declared in both a High-confidence
  // packages.lock.json and a Medium-confidence .csproj, when parsed, then
  // merge_all folds them into ONE component whose highest confidence is High
  //: Medium/High coexistence needs no special-casing beyond existing merge.
  {
    TempTree tree;
    tree.write("packages.lock.json", R"({
      "version": 1,
      "dependencies": {
        "net8.0": {
          "Serilog": { "type": "Direct", "resolved": "3.1.1" }
        }
      }
    })");
    tree.write("MyApp.csproj", R"(<Project>
      <ItemGroup>
        <PackageReference Include="Serilog" Version="3.1.1" />
      </ItemGroup>
    </Project>)");

    const Result<std::vector<Component>> result = nuget_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:nuget/Serilog@3.1.1");
    BOMWERK_TEST_CHECK(result.value[0].evidence.size() == 2);
    BOMWERK_TEST_CHECK(highest_confidence(result.value[0]) == Confidence::High);
  }

  // Given a .csproj with an unterminated PackageReference tag (hostile
  // input), when parsed, then the scan degrades to zero components with no
  // crash (rule 1): the scanner cannot pair the tag, so nothing is emitted
  // and nothing is falsely reported as skipped either.
  {
    TempTree tree;
    tree.write("Broken.csproj",
               R"(<Project><ItemGroup><PackageReference Include="X" Version="1.0.0")");

    const Result<std::vector<Component>> result = nuget_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.empty());
    BOMWERK_TEST_CHECK(result.warnings.empty());
  }

  // Given a root Directory.Packages.props and a .csproj PackageReference with
  // no Version attribute (Central Package Management's shape), when parsed,
  // then the version resolves from the props file at Medium confidence and
  // the evidence detail names both files.
  {
    TempTree tree;
    tree.write("Directory.Packages.props", R"(<Project>
      <ItemGroup>
        <PackageVersion Include="Newtonsoft.Json" Version="13.0.2" />
      </ItemGroup>
    </Project>)");
    tree.write("src/App/App.csproj", R"(<Project Sdk="Microsoft.NET.Sdk">
      <ItemGroup>
        <PackageReference Include="Newtonsoft.Json" />
      </ItemGroup>
    </Project>)");

    const Result<std::vector<Component>> result = nuget_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:nuget/Newtonsoft.Json@13.0.2");
    BOMWERK_TEST_CHECK(highest_confidence(result.value[0]) == Confidence::Medium);
    BOMWERK_TEST_CHECK(result.value[0].evidence[0].detail.find("src/App/App.csproj") !=
                       std::string::npos);
    BOMWERK_TEST_CHECK(result.value[0].evidence[0].detail.find("Directory.Packages.props") !=
                       std::string::npos);
  }

  // Given a Directory.Packages.props entry and a .csproj PackageReference that
  // spell the same package's name with different casing, when parsed, then
  // CPM resolution still matches (NuGet names are case-insensitive) and the
  // .csproj's own casing is kept as the component identity.
  {
    TempTree tree;
    tree.write("Directory.Packages.props", R"(<Project>
      <ItemGroup>
        <PackageVersion Include="newtonsoft.json" Version="13.0.2" />
      </ItemGroup>
    </Project>)");
    tree.write("App.csproj", R"(<Project>
      <ItemGroup>
        <PackageReference Include="Newtonsoft.Json" />
      </ItemGroup>
    </Project>)");

    const Result<std::vector<Component>> result = nuget_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:nuget/Newtonsoft.Json@13.0.2");
  }

  // Given a Directory.Packages.props at the root and a second, overriding one
  // in a subdirectory, when a .csproj inside that subdirectory is parsed,
  // then it resolves against the NEAREST props file, not the root one: the
  // same directory-scoped lookup MSBuild itself performs. A sibling .csproj
  // outside the subdirectory still resolves against the root file.
  {
    TempTree tree;
    tree.write("Directory.Packages.props", R"(<Project>
      <ItemGroup>
        <PackageVersion Include="Shared.Lib" Version="1.0.0" />
      </ItemGroup>
    </Project>)");
    tree.write("nested/Directory.Packages.props", R"(<Project>
      <ItemGroup>
        <PackageVersion Include="Shared.Lib" Version="2.0.0" />
      </ItemGroup>
    </Project>)");
    tree.write("nested/Inner.csproj", R"(<Project>
      <ItemGroup>
        <PackageReference Include="Shared.Lib" />
      </ItemGroup>
    </Project>)");
    tree.write("Outer.csproj", R"(<Project>
      <ItemGroup>
        <PackageReference Include="Shared.Lib" />
      </ItemGroup>
    </Project>)");

    const Result<std::vector<Component>> result = nuget_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.size() == 2);
    // Purl-sorted, and both share the name, so version orders them.
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:nuget/Shared.Lib@1.0.0");
    BOMWERK_TEST_CHECK(result.value[1].purl == "pkg:nuget/Shared.Lib@2.0.0");
  }

  // Given a .csproj PackageReference with no Version and no
  // Directory.Packages.props anywhere above it, when parsed, then it degrades
  // to the pre-existing missing-Version skip, not a crash.
  {
    TempTree tree;
    tree.write("App.csproj", R"(<Project>
      <ItemGroup>
        <PackageReference Include="Unresolvable" />
      </ItemGroup>
    </Project>)");

    const Result<std::vector<Component>> result = nuget_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.empty());
    BOMWERK_TEST_CHECK(result.warnings.size() == 1);
    BOMWERK_TEST_CHECK(result.warnings[0].message.find(
                           "1 entrie(s) without a resolvable version") != std::string::npos);
  }

  // Given a Directory.Packages.props with one well-formed and one
  // Version-less PackageVersion entry, when parsed, then the malformed entry
  // is skipped with a warning and the well-formed one still resolves its
  // .csproj reference.
  {
    TempTree tree;
    tree.write("Directory.Packages.props", R"(<Project>
      <ItemGroup>
        <PackageVersion Include="Good.Package" Version="1.0.0" />
        <PackageVersion Include="Bad.Package" />
      </ItemGroup>
    </Project>)");
    tree.write("App.csproj", R"(<Project>
      <ItemGroup>
        <PackageReference Include="Good.Package" />
        <PackageReference Include="Bad.Package" />
      </ItemGroup>
    </Project>)");

    const Result<std::vector<Component>> result = nuget_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:nuget/Good.Package@1.0.0");
    bool found_props_warning = false;
    bool found_csproj_warning = false;
    for (const bomwerk::core::Warning& warning : result.warnings)
    {
      if (warning.message.find("PackageVersion entrie(s)") != std::string::npos)
      {
        found_props_warning = true;
      }
      if (warning.message.find("entrie(s) without a resolvable version") != std::string::npos)
      {
        found_csproj_warning = true;
      }
    }
    BOMWERK_TEST_CHECK(found_props_warning);
    BOMWERK_TEST_CHECK(found_csproj_warning);
  }

  std::puts("test_nuget: OK");
  return 0;
}
