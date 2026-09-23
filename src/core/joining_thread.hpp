#pragma once
#include <thread>
#include <utility>

namespace bomwerk::core
{

/// Join-on-destruction thread wrapper: what `std::jthread` would give us.
///
/// TOOLCHAIN: the local AppleClang 14 ships libc++ 13, which has no
/// `<stop_token>` and no `std::jthread` at all (the same incomplete-C++20
/// caveat docs/CONTRIBUTING.md records for `std::ranges`/`std::views`). Replace this with
/// `std::jthread` once the toolchain moves to AppleClang 15+/Xcode 15.
///
/// Worth ten lines rather than a bare `std::thread`: a `std::thread`
/// destructor that runs un-joined calls `std::terminate`, and "never crash"
/// (rule 1) must not depend on nobody ever adding an early return between the
/// start and the join.
class JoiningThread
{
 public:
  template <typename Callable>
  explicit JoiningThread(Callable&& callable) : worker_(std::forward<Callable>(callable))
  {
  }

  ~JoiningThread() { join(); }

  JoiningThread(const JoiningThread&) = delete;
  JoiningThread& operator=(const JoiningThread&) = delete;
  JoiningThread(JoiningThread&&) = delete;
  JoiningThread& operator=(JoiningThread&&) = delete;

  /// Wait for the worker to finish. Idempotent, so the caller can join at the
  /// point where it needs the result and the destructor stays a safety net.
  void join()
  {
    if (worker_.joinable())
    {
      worker_.join();
    }
  }

 private:
  std::thread worker_;
};

}  // namespace bomwerk::core
