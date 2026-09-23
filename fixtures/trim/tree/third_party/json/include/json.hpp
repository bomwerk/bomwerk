// Header-only vendored library. Nothing here is ever COMPILED, so this
// component can only ever be proven used by the include path a compile line
// carries -- the case that would otherwise mark most C++ vendored libraries
// unused.
#pragma once
inline int json_version() { return 3; }
