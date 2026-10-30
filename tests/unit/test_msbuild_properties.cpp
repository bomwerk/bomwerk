// ctest unit test for the MSBuild property reader behind the NuGet producer
// (framework-free).
#include <cstdio>
#include <filesystem>
#include <set>
#include <string>

#include "core/build_variables.hpp"
#include "core/file_index.hpp"
#include "parsers/lockfiles/msbuild_properties.hpp"
#include "support/check.hpp"
#include "support/temp_tree.hpp"

namespace fs = std::filesystem;
namespace msbuild = bomwerk::parsers::lockfiles::msbuild;

using bomwerk::core::expand_variables;
using bomwerk::core::kMsbuildVariableDialect;
using bomwerk::core::VariableTable;
using bomwerk::test::TempTree;

namespace
{

std::string expanded(const VariableTable& table, const std::string& text)
{
  return expand_variables(text, table, kMsbuildVariableDialect);
}

bomwerk::core::FileIndex index_of(const TempTree& tree)
{
  return bomwerk::core::build_file_index(tree.root(), std::set<std::string>{}, std::set<fs::path>{})
      .value;
}

}  // namespace

int main()
{
  // Given property groups with a plain value, a conditional one, a duplicate
  // with a different value, an empty one, nested markup and a commented-out
  // definition, when parsed, then only the plain and the conditional single
  // definitions expand; the rest are ambiguous or absent.
  {
    const VariableTable table = msbuild::parse_property_groups(R"(<Project>
  <PropertyGroup>
    <Plain>1.0</Plain>
    <Dup>a</Dup>
    <Empty></Empty>
    <Nested><Inner>x</Inner></Nested>
    <!-- <Hidden>nope</Hidden> -->
  </PropertyGroup>
  <PropertyGroup Condition="'$(Config)' == 'Release'">
    <Conditional>2.0</Conditional>
    <Dup>b</Dup>
  </PropertyGroup>
</Project>)");
    BOMWERK_TEST_CHECK(expanded(table, "$(Plain)") == "1.0");
    BOMWERK_TEST_CHECK(expanded(table, "$(plain)") == "1.0");
    BOMWERK_TEST_CHECK(expanded(table, "$(Conditional)") == "2.0");
    BOMWERK_TEST_CHECK(expanded(table, "$(Dup)") == "$(Dup)");
    BOMWERK_TEST_CHECK(expanded(table, "$(Empty)") == "$(Empty)");
    BOMWERK_TEST_CHECK(expanded(table, "$(Nested)") == "$(Nested)");
    BOMWERK_TEST_CHECK(expanded(table, "$(Hidden)") == "$(Hidden)");
  }

  // Given imports of a file, an SDK, and one with no Project, when listed,
  // then only the file imports come back.
  {
    const auto imports = msbuild::parse_import_projects(R"(<Project>
  <Import Project="..\eng\Versions.props" />
  <Import Project="Sdk.props" Sdk="Microsoft.NET.Sdk" />
  <Import Condition="true" />
  <ImportGroup><Import Project="inner.props" /></ImportGroup>
</Project>)");
    BOMWERK_TEST_CHECK(imports.size() == 2);
    BOMWERK_TEST_CHECK(imports[0] == "..\\eng\\Versions.props");
    BOMWERK_TEST_CHECK(imports[1] == "inner.props");
  }

  // Given import values of every shape, when resolved from `src/app`, then the
  // static ones name a root-relative path and the rest are refused.
  {
    const fs::path directory = "src/app";
    BOMWERK_TEST_CHECK(msbuild::resolve_import_path(directory, "..\\..\\eng\\x.props") ==
                       fs::path("eng/x.props"));
    BOMWERK_TEST_CHECK(
        msbuild::resolve_import_path(directory, "$(MSBuildThisFileDirectory)../y.props") ==
        fs::path("src/y.props"));
    BOMWERK_TEST_CHECK(msbuild::resolve_import_path(directory, "$(RepoRoot)eng/z.props") ==
                       fs::path("eng/z.props"));
    BOMWERK_TEST_CHECK(
        msbuild::resolve_import_path(directory, "$(RepositoryEngineeringDir)Versions.props") ==
        fs::path("eng/Versions.props"));
    BOMWERK_TEST_CHECK(msbuild::resolve_import_path(directory, "local.props") ==
                       fs::path("src/app/local.props"));
    BOMWERK_TEST_CHECK(
        !msbuild::resolve_import_path(directory, "../../../outside.props").has_value());
    BOMWERK_TEST_CHECK(!msbuild::resolve_import_path(directory, "/etc/passwd").has_value());
    BOMWERK_TEST_CHECK(!msbuild::resolve_import_path(directory, "$(Unknown)/a.props").has_value());
    BOMWERK_TEST_CHECK(!msbuild::resolve_import_path(directory, "*.props").has_value());
    BOMWERK_TEST_CHECK(!msbuild::resolve_import_path(directory, "").has_value());
    BOMWERK_TEST_CHECK(
        !msbuild::resolve_import_path(directory,
                                      "$([MSBuild]::GetPathOfFileAbove('Directory.Build.props', "
                                      "'$(MSBuildThisFileDirectory)../'))")
             .has_value());
  }

  // Given the .NET Arcade layout (eng/Versions.props importing
  // Version.Details.props, no Import from the project itself), a root
  // Directory.Packages.props and a nested Directory.Build.props, when a
  // project's table is built, then it holds every one of them, plus the
  // project's own property group and its own import.
  {
    TempTree tree;
    tree.write("eng/Versions.props",
               "<Project><Import Project=\"Version.Details.props\" />"
               "<PropertyGroup><AzureIdentityVersion>1.21.0</AzureIdentityVersion></PropertyGroup>"
               "</Project>");
    tree.write("eng/Version.Details.props",
               "<Project><PropertyGroup><MicrosoftBuildVersion>18.4.0</MicrosoftBuildVersion>"
               "</PropertyGroup></Project>");
    tree.write("Directory.Packages.props",
               "<Project><PropertyGroup><RootOnly>root</RootOnly></PropertyGroup></Project>");
    tree.write("src/Directory.Build.props",
               "<Project><PropertyGroup><SrcOnly>src</SrcOnly></PropertyGroup></Project>");
    tree.write(
        "src/app/extra.props",
        "<Project><PropertyGroup><FromImport>imported</FromImport></PropertyGroup></Project>");
    const bomwerk::core::FileIndex index = index_of(tree);

    msbuild::PropertyScopes scopes(index, tree.root(), 1u << 20, [] { return true; });
    const VariableTable table =
        scopes.table_for_project("src/app",
                                 "<Project><Import Project=\"extra.props\" />"
                                 "<PropertyGroup><OwnProp>own</OwnProp></PropertyGroup></Project>");
    BOMWERK_TEST_CHECK(expanded(table, "$(AzureIdentityVersion)") == "1.21.0");
    BOMWERK_TEST_CHECK(expanded(table, "$(MicrosoftBuildVersion)") == "18.4.0");
    BOMWERK_TEST_CHECK(expanded(table, "$(RootOnly)") == "root");
    BOMWERK_TEST_CHECK(expanded(table, "$(SrcOnly)") == "src");
    BOMWERK_TEST_CHECK(expanded(table, "$(OwnProp)") == "own");
    BOMWERK_TEST_CHECK(expanded(table, "$(FromImport)") == "imported");
    BOMWERK_TEST_CHECK(scopes.warnings().empty());

    // A directory with no Directory.* file of its own shares its ancestor's
    // table, and a sibling tree does not see src/'s properties.
    BOMWERK_TEST_CHECK(&scopes.table_for_directory("src/app") ==
                       &scopes.table_for_directory("src"));
    BOMWERK_TEST_CHECK(expanded(scopes.table_for_directory("tools"), "$(SrcOnly)") == "$(SrcOnly)");
  }

  // Given two files that define the same property differently, when a table is
  // built, then the property is ambiguous and never expands.
  {
    TempTree tree;
    tree.write("Directory.Build.props",
               "<Project><PropertyGroup><Version>1</Version></PropertyGroup></Project>");
    tree.write("Directory.Packages.props",
               "<Project><PropertyGroup><Version>2</Version></PropertyGroup></Project>");
    const bomwerk::core::FileIndex index = index_of(tree);
    msbuild::PropertyScopes scopes(index, tree.root(), 1u << 20, [] { return true; });
    BOMWERK_TEST_CHECK(expanded(scopes.table_for_directory(""), "$(Version)") == "$(Version)");
  }

  // Given imports that cycle, that climb out of the scan root, and that name a
  // file outside the index, when a table is built, then it terminates, reads
  // nothing outside the root and keeps what it could read.
  {
    TempTree tree;
    tree.write("Directory.Build.props",
               "<Project><Import Project=\"a.props\" /><Import Project=\"..\\..\\outside.props\" />"
               "<Import Project=\"missing.props\" />"
               "<PropertyGroup><Kept>yes</Kept></PropertyGroup></Project>");
    tree.write("a.props", "<Project><Import Project=\"Directory.Build.props\" /></Project>");
    const bomwerk::core::FileIndex index = index_of(tree);
    msbuild::PropertyScopes scopes(index, tree.root(), 1u << 20, [] { return true; });
    BOMWERK_TEST_CHECK(expanded(scopes.table_for_directory(""), "$(Kept)") == "yes");
    BOMWERK_TEST_CHECK(scopes.warnings().empty());
  }

  // Given a file budget that is already spent, when a table is built, then no
  // file is read and the table is empty.
  {
    TempTree tree;
    tree.write("Directory.Build.props",
               "<Project><PropertyGroup><Kept>yes</Kept></PropertyGroup></Project>");
    const bomwerk::core::FileIndex index = index_of(tree);
    msbuild::PropertyScopes scopes(index, tree.root(), 1u << 20, [] { return false; });
    BOMWERK_TEST_CHECK(expanded(scopes.table_for_directory(""), "$(Kept)") == "$(Kept)");
  }

  // Given a props file larger than the byte cap, when a table is built, then it
  // is skipped with one size-limit warning.
  {
    TempTree tree;
    tree.write("Directory.Build.props",
               "<Project><PropertyGroup><Kept>yes</Kept></PropertyGroup></Project>");
    const bomwerk::core::FileIndex index = index_of(tree);
    msbuild::PropertyScopes scopes(index, tree.root(), 10, [] { return true; });
    BOMWERK_TEST_CHECK(expanded(scopes.table_for_directory(""), "$(Kept)") == "$(Kept)");
    BOMWERK_TEST_CHECK(scopes.warnings().size() == 1);
    BOMWERK_TEST_CHECK(scopes.warnings()[0].code ==
                       bomwerk::core::WarningCode::kFileSizeLimitExceeded);
  }

  std::puts("test_msbuild_properties: OK");
  return 0;
}
