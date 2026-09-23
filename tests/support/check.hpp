#pragma once

#include <cstdio>
#include <cstdlib>

// A minimal, never-compiled-out assertion for unit tests. Plain assert() is
// stripped by -DNDEBUG in release builds, which both trips -Wunused-variable
// on values whose only use was inside assert(...) and silently turns the
// check itself into a no-op. BOMWERK_TEST_CHECK always evaluates its
// condition and aborts on failure, in debug and release alike.
#define BOMWERK_TEST_CHECK(condition)                                                     \
  do                                                                                      \
  {                                                                                       \
    if (!(condition))                                                                     \
    {                                                                                     \
      std::fprintf(stderr, "CHECK failed: %s (%s:%d)\n", #condition, __FILE__, __LINE__); \
      std::abort();                                                                       \
    }                                                                                     \
  } while (false)
