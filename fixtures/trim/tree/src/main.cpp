// First-party source: compiled, in the tree, and under no component root, so
// it must count toward the source total and toward no component's usage.
#include "json.hpp"

int main() { return json_version() == 3 ? 0 : 1; }
