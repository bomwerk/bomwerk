// ctest unit test for the pom.xml + gradle.lockfile producer
// (framework-free).
#include <cstdio>
#include <string>
#include <vector>

#include "core/model.hpp"
#include "parsers/lockfiles/maven.hpp"
#include "support/check.hpp"
#include "support/temp_tree.hpp"

using bomwerk::core::Component;
using bomwerk::core::Confidence;
using bomwerk::core::highest_confidence;
using bomwerk::core::Result;
using bomwerk::core::Scope;
using bomwerk::test::TempTree;

namespace maven_parser = bomwerk::parsers::lockfiles::maven;

namespace
{

const Component* find_by_purl(const std::vector<Component>& components, const std::string& purl)
{
  for (const Component& component : components)
  {
    if (component.purl == purl)
    {
      return &component;
    }
  }
  return nullptr;
}

}  // namespace

int main()
{
  // Given a pom with a literal-version dep, a ${property}-resolved dep, a
  // test-scoped dep, an optional dep and a dependencyManagement pin, when
  // parsed, then the pin is NOT emitted, every emitted dep is Medium
  // confidence, the test dep is Excluded and the optional dep is Optional.
  {
    TempTree tree;
    tree.write("pom.xml", R"(<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>demo-app</artifactId>
  <version>2.4.6</version>
  <properties>
    <guava.version>33.2.1-jre</guava.version>
  </properties>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.pinned</groupId>
        <artifactId>never-emitted</artifactId>
        <version>9.9.9</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>3.14.0</version>
    </dependency>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>${guava.version}</version>
    </dependency>
    <dependency>
      <groupId>org.junit.jupiter</groupId>
      <artifactId>junit-jupiter</artifactId>
      <version>5.10.2</version>
      <scope>test</scope>
    </dependency>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-api</artifactId>
      <version>2.0.13</version>
      <optional>true</optional>
    </dependency>
  </dependencies>
</project>
)");

    const Result<std::vector<Component>> result = maven_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.warnings.empty());
    // 4 dependencies + 1 self-identity.
    BOMWERK_TEST_CHECK(result.value.size() == 5);

    const Component* self_identity =
        find_by_purl(result.value, "pkg:maven/com.example/demo-app@2.4.6");
    BOMWERK_TEST_CHECK(self_identity != nullptr);
    BOMWERK_TEST_CHECK(self_identity->scope == Scope::Required);
    BOMWERK_TEST_CHECK(highest_confidence(*self_identity) == Confidence::High);
    BOMWERK_TEST_CHECK(self_identity->evidence[0].detail.find("own-identity") != std::string::npos);

    const Component* guava =
        find_by_purl(result.value, "pkg:maven/com.google.guava/guava@33.2.1-jre");
    BOMWERK_TEST_CHECK(guava != nullptr);
    BOMWERK_TEST_CHECK(guava->name == "com.google.guava:guava");
    // The groupId is maven's own publisher namespace: NTIA/CRA supplier
    // evidence with no extra parsing.
    BOMWERK_TEST_CHECK(guava->supplier == "com.google.guava");
    BOMWERK_TEST_CHECK(guava->scope == Scope::Required);
    BOMWERK_TEST_CHECK(highest_confidence(*guava) == Confidence::Medium);
    BOMWERK_TEST_CHECK(guava->evidence[0].detail.find("version-from-property guava.version") !=
                       std::string::npos);

    BOMWERK_TEST_CHECK(
        find_by_purl(result.value, "pkg:maven/org.apache.commons/commons-lang3@3.14.0") != nullptr);
    const Component* junit_jupiter =
        find_by_purl(result.value, "pkg:maven/org.junit.jupiter/junit-jupiter@5.10.2");
    BOMWERK_TEST_CHECK(junit_jupiter != nullptr);
    BOMWERK_TEST_CHECK(junit_jupiter->scope == Scope::Excluded);
    const Component* slf4j_api = find_by_purl(result.value, "pkg:maven/org.slf4j/slf4j-api@2.0.13");
    BOMWERK_TEST_CHECK(slf4j_api != nullptr);
    BOMWERK_TEST_CHECK(slf4j_api->scope == Scope::Optional);
  }

  // Given a pom whose dep versions come from the project.version pseudo-
  // property and from the parent's version, when parsed, then both resolve :
  // and the parent's own <version> tag is never mistaken for the pom's.
  {
    TempTree tree;
    tree.write("pom.xml", R"(<project>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>parent-pom</artifactId>
    <version>7.7.7</version>
  </parent>
  <artifactId>child-module</artifactId>
  <version>1.2.3</version>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>sibling</artifactId>
      <version>${project.version}</version>
    </dependency>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>from-parent</artifactId>
      <version>${project.parent.version}</version>
    </dependency>
  </dependencies>
</project>
)");

    const Result<std::vector<Component>> result = maven_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.warnings.empty());
    // 2 dependencies + 1 self-identity, groupId inherited from
    // <parent> like the dependencies' own project.version references.
    BOMWERK_TEST_CHECK(result.value.size() == 3);
    BOMWERK_TEST_CHECK(find_by_purl(result.value, "pkg:maven/com.example/from-parent@7.7.7") !=
                       nullptr);
    BOMWERK_TEST_CHECK(find_by_purl(result.value, "pkg:maven/com.example/sibling@1.2.3") !=
                       nullptr);
    const Component* self_identity =
        find_by_purl(result.value, "pkg:maven/com.example/child-module@1.2.3");
    BOMWERK_TEST_CHECK(self_identity != nullptr);
    BOMWERK_TEST_CHECK(highest_confidence(*self_identity) == Confidence::High);
  }

  // Given deps whose versions are missing or reference an undefined property,
  // when parsed, then they are skipped and counted into ONE per-file warning :
  // never emitted with a guessed version.
  {
    TempTree tree;
    tree.write("pom.xml", R"(<project>
  <groupId>com.example</groupId>
  <artifactId>version-resolution-demo</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.managed</groupId>
      <artifactId>version-inherited</artifactId>
    </dependency>
    <dependency>
      <groupId>org.broken</groupId>
      <artifactId>bad-property</artifactId>
      <version>${undefined.property}</version>
    </dependency>
    <dependency>
      <groupId>org.kept</groupId>
      <artifactId>survivor</artifactId>
      <version>1.0.0</version>
    </dependency>
  </dependencies>
</project>
)");

    const Result<std::vector<Component>> result = maven_parser::parse(tree.root());
    // 1 surviving dependency + 1 self-identity.
    BOMWERK_TEST_CHECK(result.value.size() == 2);
    BOMWERK_TEST_CHECK(find_by_purl(result.value, "pkg:maven/org.kept/survivor@1.0.0") != nullptr);
    BOMWERK_TEST_CHECK(
        find_by_purl(result.value, "pkg:maven/com.example/version-resolution-demo@1.0.0") !=
        nullptr);
    BOMWERK_TEST_CHECK(result.warnings.size() == 1);
    BOMWERK_TEST_CHECK(result.warnings[0].message.find("without a resolvable version") !=
                       std::string::npos);
    BOMWERK_TEST_CHECK(result.warnings[0].message.find("2 ") != std::string::npos);
  }

  // Given a commented-out dependency, a CDATA-wrapped version and an
  // <exclusions> block naming another groupId, when parsed, then the comment
  // is invisible, the CDATA text is unwrapped and the exclusion's groupId
  // never leaks into any component.
  {
    TempTree tree;
    tree.write("pom.xml", R"(<project>
  <groupId>com.example</groupId>
  <artifactId>comment-cdata-demo</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <!--
    <dependency>
      <groupId>org.commented</groupId>
      <artifactId>ghost</artifactId>
      <version>0.0.1</version>
    </dependency>
    -->
    <dependency>
      <groupId>org.real</groupId>
      <artifactId>with-exclusions</artifactId>
      <version><![CDATA[4.5.6]]></version>
      <exclusions>
        <exclusion>
          <groupId>org.excluded</groupId>
          <artifactId>transitive-dep</artifactId>
        </exclusion>
      </exclusions>
    </dependency>
  </dependencies>
</project>
)");

    const Result<std::vector<Component>> result = maven_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.warnings.empty());
    // 1 surviving dependency + 1 self-identity.
    BOMWERK_TEST_CHECK(result.value.size() == 2);
    BOMWERK_TEST_CHECK(find_by_purl(result.value, "pkg:maven/org.real/with-exclusions@4.5.6") !=
                       nullptr);
    BOMWERK_TEST_CHECK(
        find_by_purl(result.value, "pkg:maven/com.example/comment-cdata-demo@1.0.0") != nullptr);
  }

  // Given a pom with no <parent> and no own <groupId> (so project.groupId is
  // never populated), and one dependency whose <groupId> references that
  // undefined property, when parsed, then the dependency is KEPT: never
  // dropped: with the raw, unresolved text as its identity, downgraded to
  // Low confidence and counted into one warning.
  {
    TempTree tree;
    tree.write("pom.xml", R"(<project>
  <artifactId>reactor-module</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>${project.groupId}</groupId>
      <artifactId>inherited-identity</artifactId>
      <version>1.0.0</version>
    </dependency>
  </dependencies>
</project>
)");

    const Result<std::vector<Component>> result = maven_parser::parse(tree.root());
    // No self-identity component: this pom has no own
    // <groupId>, by design: that's the whole point of this fixture.
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].name == "${project.groupId}:inherited-identity");
    BOMWERK_TEST_CHECK(result.value[0].purl ==
                       "pkg:maven/%24%7Bproject.groupId%7D/inherited-identity@1.0.0");
    BOMWERK_TEST_CHECK(result.value[0].supplier == "${project.groupId}");
    BOMWERK_TEST_CHECK(highest_confidence(result.value[0]) == Confidence::Low);
    // 2 warnings: the pre-existing unresolved-identity one, plus the new
    // self-identity-skipped one (this pom's own groupId is unresolvable too).
    BOMWERK_TEST_CHECK(result.warnings.size() == 2);
    const bool has_unresolved_identity_warning =
        result.warnings[0].message.find("unresolved groupId/artifactId") != std::string::npos ||
        result.warnings[1].message.find("unresolved groupId/artifactId") != std::string::npos;
    BOMWERK_TEST_CHECK(has_unresolved_identity_warning);
    const bool has_self_identity_skipped_warning =
        result.warnings[0].message.find("self-identity skipped") != std::string::npos ||
        result.warnings[1].message.find("self-identity skipped") != std::string::npos;
    BOMWERK_TEST_CHECK(has_self_identity_skipped_warning);
    BOMWERK_TEST_CHECK(result.warnings[0].message.find("1 ") != std::string::npos ||
                       result.warnings[1].message.find("1 ") != std::string::npos);
  }

  // Given four dependencies in one pom: groupId-only unresolved, artifactId-
  // only unresolved, both unresolved, and a clean literal survivor: when
  // parsed, then none are dropped, the three broken ones are Low confidence,
  // the survivor stays Medium, and both-unresolved counts ONCE, not twice,
  // toward the single aggregate warning.
  {
    TempTree tree;
    tree.write("pom.xml", R"(<project>
  <groupId>com.example</groupId>
  <artifactId>identity-matrix</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>${undefined.vendor}</groupId>
      <artifactId>mystery-lib</artifactId>
      <version>1.0.0</version>
    </dependency>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>${undefined.artifact}</artifactId>
      <version>2.0.0</version>
    </dependency>
    <dependency>
      <groupId>${undefined.both.group}</groupId>
      <artifactId>${undefined.both.artifact}</artifactId>
      <version>3.0.0</version>
    </dependency>
    <dependency>
      <groupId>org.kept</groupId>
      <artifactId>clean-survivor</artifactId>
      <version>4.0.0</version>
    </dependency>
  </dependencies>
</project>
)");

    const Result<std::vector<Component>> result = maven_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    // 4 dependencies + 1 self-identity.
    BOMWERK_TEST_CHECK(result.value.size() == 5);
    const Component* both_unresolved = find_by_purl(
        result.value,
        "pkg:maven/%24%7Bundefined.both.group%7D/%24%7Bundefined.both.artifact%7D@3.0.0");
    const Component* group_unresolved =
        find_by_purl(result.value, "pkg:maven/%24%7Bundefined.vendor%7D/mystery-lib@1.0.0");
    const Component* artifact_unresolved =
        find_by_purl(result.value, "pkg:maven/org.example/%24%7Bundefined.artifact%7D@2.0.0");
    const Component* clean_survivor =
        find_by_purl(result.value, "pkg:maven/org.kept/clean-survivor@4.0.0");
    const Component* self_identity =
        find_by_purl(result.value, "pkg:maven/com.example/identity-matrix@1.0.0");
    BOMWERK_TEST_CHECK(both_unresolved != nullptr);
    BOMWERK_TEST_CHECK(group_unresolved != nullptr);
    BOMWERK_TEST_CHECK(artifact_unresolved != nullptr);
    BOMWERK_TEST_CHECK(clean_survivor != nullptr);
    BOMWERK_TEST_CHECK(self_identity != nullptr);
    BOMWERK_TEST_CHECK(highest_confidence(*both_unresolved) == Confidence::Low);
    BOMWERK_TEST_CHECK(highest_confidence(*group_unresolved) == Confidence::Low);
    BOMWERK_TEST_CHECK(highest_confidence(*artifact_unresolved) == Confidence::Low);
    BOMWERK_TEST_CHECK(highest_confidence(*clean_survivor) == Confidence::Medium);
    BOMWERK_TEST_CHECK(highest_confidence(*self_identity) == Confidence::High);
    BOMWERK_TEST_CHECK(result.warnings.size() == 1);
    BOMWERK_TEST_CHECK(result.warnings[0].message.find("unresolved groupId/artifactId") !=
                       std::string::npos);
    BOMWERK_TEST_CHECK(result.warnings[0].message.find("3 ") != std::string::npos);
  }

  // Given <properties> defining both a group and an artifact name, and one
  // dependency referencing both via ${...}, when parsed, then both resolve,
  // confidence stays Medium (unchanged), and the evidence records where each
  // came from.
  {
    TempTree tree;
    tree.write("pom.xml", R"(<project>
  <groupId>com.example</groupId>
  <artifactId>identity-resolved</artifactId>
  <version>1.0.0</version>
  <properties>
    <lib.group>org.resolved</lib.group>
    <lib.artifact>resolved-lib</lib.artifact>
  </properties>
  <dependencies>
    <dependency>
      <groupId>${lib.group}</groupId>
      <artifactId>${lib.artifact}</artifactId>
      <version>9.9.9</version>
    </dependency>
  </dependencies>
</project>
)");

    const Result<std::vector<Component>> result = maven_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.warnings.empty());
    // 1 dependency + 1 self-identity.
    BOMWERK_TEST_CHECK(result.value.size() == 2);
    const Component* resolved_lib =
        find_by_purl(result.value, "pkg:maven/org.resolved/resolved-lib@9.9.9");
    BOMWERK_TEST_CHECK(resolved_lib != nullptr);
    BOMWERK_TEST_CHECK(resolved_lib->name == "org.resolved:resolved-lib");
    BOMWERK_TEST_CHECK(highest_confidence(*resolved_lib) == Confidence::Medium);
    BOMWERK_TEST_CHECK(resolved_lib->evidence[0].detail.find("groupId-from-property lib.group") !=
                       std::string::npos);
    BOMWERK_TEST_CHECK(resolved_lib->evidence[0].detail.find(
                           "artifactId-from-property lib.artifact") != std::string::npos);
    const Component* self_identity =
        find_by_purl(result.value, "pkg:maven/com.example/identity-resolved@1.0.0");
    BOMWERK_TEST_CHECK(self_identity != nullptr);
    BOMWERK_TEST_CHECK(highest_confidence(*self_identity) == Confidence::High);
  }

  // Given a pom with a <licenses><license><name> block plus one dependency,
  // when parsed, then the self-identity component carries that license text
  // verbatim.
  {
    TempTree tree;
    tree.write("pom.xml", R"(<project>
  <groupId>com.example</groupId>
  <artifactId>licensed-app</artifactId>
  <version>1.0.0</version>
  <licenses>
    <license>
      <name>Apache-2.0</name>
    </license>
  </licenses>
  <dependencies>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>some-lib</artifactId>
      <version>2.0.0</version>
    </dependency>
  </dependencies>
</project>
)");

    const Result<std::vector<Component>> result = maven_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 2);
    const Component* self_identity =
        find_by_purl(result.value, "pkg:maven/com.example/licensed-app@1.0.0");
    BOMWERK_TEST_CHECK(self_identity != nullptr);
    BOMWERK_TEST_CHECK(self_identity->license == "Apache-2.0");
    BOMWERK_TEST_CHECK(self_identity->scope == Scope::Required);
    BOMWERK_TEST_CHECK(highest_confidence(*self_identity) == Confidence::High);
  }

  // Given a pom whose <licenses> block declares two <license> entries, when
  // parsed, then only the FIRST entry's <name> is captured (mirrors
  // composer.cpp's `.front()` of a composer.json `license` array).
  {
    TempTree tree;
    tree.write("pom.xml", R"(<project>
  <groupId>com.example</groupId>
  <artifactId>dual-licensed-app</artifactId>
  <version>1.0.0</version>
  <licenses>
    <license>
      <name>Apache-2.0</name>
    </license>
    <license>
      <name>MIT</name>
    </license>
  </licenses>
</project>
)");

    const Result<std::vector<Component>> result = maven_parser::parse(tree.root());
    const Component* self_identity =
        find_by_purl(result.value, "pkg:maven/com.example/dual-licensed-app@1.0.0");
    BOMWERK_TEST_CHECK(self_identity != nullptr);
    BOMWERK_TEST_CHECK(self_identity->license == "Apache-2.0");
  }

  // Given a pom with full coordinates but no <licenses> block, when parsed,
  // then the self-identity component is still emitted, with an empty
  // license: own-identity emission and license capture are independent
  // (self-identity component).
  {
    TempTree tree;
    tree.write("pom.xml", R"(<project>
  <groupId>com.example</groupId>
  <artifactId>unlicensed-app</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>some-lib</artifactId>
      <version>2.0.0</version>
    </dependency>
  </dependencies>
</project>
)");

    const Result<std::vector<Component>> result = maven_parser::parse(tree.root());
    const Component* self_identity =
        find_by_purl(result.value, "pkg:maven/com.example/unlicensed-app@1.0.0");
    BOMWERK_TEST_CHECK(self_identity != nullptr);
    BOMWERK_TEST_CHECK(self_identity->license.empty());
  }

  // Given a pom with no top-level groupId/artifactId/version at all, when
  // parsed, then no self-identity component is emitted and one warning
  // reports it: mirroring vcpkg's component_from_port_identity, which warns
  // rather than silently dropping an unresolvable own-identity.
  {
    TempTree tree;
    tree.write("pom.xml", R"(<project>
  <dependencies>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>some-lib</artifactId>
      <version>2.0.0</version>
    </dependency>
  </dependencies>
</project>
)");

    const Result<std::vector<Component>> result = maven_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:maven/org.example/some-lib@2.0.0");
    BOMWERK_TEST_CHECK(result.warnings.size() == 1);
    BOMWERK_TEST_CHECK(result.warnings[0].message.find("self-identity skipped") !=
                       std::string::npos);
  }

  // Given hostile input: an unterminated comment swallowing the whole file :
  // when parsed, then the producer stays complete and never crashes (rule 1).
  {
    TempTree tree;
    tree.write("pom.xml", "<project><!-- never closed <dependency><groupId>x</groupId>");

    const Result<std::vector<Component>> result = maven_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.empty());
  }

  // Given a gradle.lockfile with runtime and test-only entries, comments and
  // the empty= line, when parsed, then entries are High confidence, ONLY the
  // all-test-configurations entry is Excluded and empty=/comments are skipped.
  {
    TempTree tree;
    tree.write("gradle.lockfile", R"(# This is a Gradle generated file for dependency locking.
# Manual edits can break the build and are not advised.
org.apache.commons:commons-lang3:3.14.0=compileClasspath,runtimeClasspath,testCompileClasspath
org.junit.jupiter:junit-jupiter:5.10.2=testCompileClasspath,testRuntimeClasspath
empty=annotationProcessor
)");

    const Result<std::vector<Component>> result = maven_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 2);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:maven/org.apache.commons/commons-lang3@3.14.0");
    BOMWERK_TEST_CHECK(result.value[1].purl == "pkg:maven/org.junit.jupiter/junit-jupiter@5.10.2");
    BOMWERK_TEST_CHECK(result.value[0].scope == Scope::Required);
    BOMWERK_TEST_CHECK(result.value[1].scope == Scope::Excluded);
    BOMWERK_TEST_CHECK(highest_confidence(result.value[0]) == Confidence::High);
    BOMWERK_TEST_CHECK(result.value[0].evidence[0].detail.find("configurations") !=
                       std::string::npos);
  }

  // Given malformed gradle.lockfile lines (no '=', wrong colon count), when
  // parsed, then they are counted into one warning and the good line survives.
  {
    TempTree tree;
    tree.write("gradle.lockfile", R"(this line has no equals sign
only:two=compileClasspath
a:b:c:d=compileClasspath
org.good:artifact:1.0.0=compileClasspath
)");

    const Result<std::vector<Component>> result = maven_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:maven/org.good/artifact@1.0.0");
    BOMWERK_TEST_CHECK(result.warnings.size() == 1);
    BOMWERK_TEST_CHECK(result.warnings[0].message.find("3 malformed line(s)") != std::string::npos);
  }

  // Given the same artifact declared in a pom (Medium) and locked by Gradle
  // (High), when parsed, then merge_all folds them into ONE component whose
  // highest confidence is the lockfile's High.
  {
    TempTree tree;
    tree.write("pom.xml", R"(<project>
  <dependencies>
    <dependency>
      <groupId>org.shared</groupId>
      <artifactId>both-sources</artifactId>
      <version>2.2.2</version>
    </dependency>
  </dependencies>
</project>
)");
    tree.write("gradle.lockfile", "org.shared:both-sources:2.2.2=runtimeClasspath\n");

    const Result<std::vector<Component>> result = maven_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:maven/org.shared/both-sources@2.2.2");
    BOMWERK_TEST_CHECK(result.value[0].evidence.size() == 2);
    BOMWERK_TEST_CHECK(highest_confidence(result.value[0]) == Confidence::High);
  }

  // Given three Gradle packages and a budget of two, when parsed, then the
  // deterministic two-entry prefix is retained and the result is incomplete.
  // Given a budget equal to the entry count, then the result remains complete.
  {
    TempTree tree;
    tree.write("gradle.lockfile",
               "com.example:alpha:1.0.0=runtimeClasspath\n"
               "com.example:beta:2.0.0=runtimeClasspath\n"
               "com.example:gamma:3.0.0=runtimeClasspath\n");

    maven_parser::ParseOptions options;
    options.max_total_packages = 2;
    const Result<std::vector<Component>> result = maven_parser::parse(tree.root(), options);
    BOMWERK_TEST_CHECK(!result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 2);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:maven/com.example/alpha@1.0.0");
    BOMWERK_TEST_CHECK(result.value[1].purl == "pkg:maven/com.example/beta@2.0.0");
    BOMWERK_TEST_CHECK(result.warnings.size() == 1);
    BOMWERK_TEST_CHECK(result.warnings[0].message.find("maven: package limit 2 reached") !=
                       std::string::npos);

    options.max_total_packages = 3;
    const Result<std::vector<Component>> exact_limit_result =
        maven_parser::parse(tree.root(), options);
    BOMWERK_TEST_CHECK(exact_limit_result.complete);
    BOMWERK_TEST_CHECK(exact_limit_result.value.size() == 3);
    BOMWERK_TEST_CHECK(exact_limit_result.warnings.empty());
  }

  // Given more gradle.lockfile files than a caller-tightened
  // max_scanned_files allows, when parsed, then a warning reports the cap,
  // the run stays complete, and the scanned subset is the path-sorted
  // (deterministic) one.
  {
    TempTree tree;
    tree.write("a/gradle.lockfile", "org.example:aaa:1.0.0=compileClasspath\n");
    tree.write("z/gradle.lockfile", "org.example:zzz:1.0.0=compileClasspath\n");
    maven_parser::ParseOptions options;
    options.max_scanned_files = 1;
    const auto result = maven_parser::parse(tree.root(), options);
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(!result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:maven/org.example/aaa@1.0.0");
  }

  std::puts("test_maven: OK");
  return 0;
}
