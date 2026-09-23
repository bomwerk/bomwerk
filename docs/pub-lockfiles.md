# Dart and Flutter lockfiles

Bomwerk reads Dart and Flutter `pubspec.lock` files directly and emits
resolved hosted, git, and SDK packages as `pkg:pub` components. Local `path`
dependencies are workspace-local and are intentionally omitted because they
have no registry identity. The parser never invokes `dart` or `flutter pub`;
it applies the normal bounded file and package budgets and preserves partial
line-based output when a lockfile exceeds its read limit.
