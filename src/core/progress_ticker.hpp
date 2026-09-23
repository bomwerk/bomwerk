#pragma once
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <utility>

namespace bomwerk::core
{

/// Wall-clock-gated "has it been long enough since the last log line" gate
/// NOT a scheduler and does not own logging or a thread: a caller
/// still decides what to log and calls `should_tick()` itself after
/// finishing a unit of work. Exists because a request-COUNTED heartbeat
/// freezes during one slow unit of work (e.g. an HTTP 429 backoff): exactly
/// when a long-running pass looks most like a hang: exactly what
/// `--license-fallback`'s old crates.io-only, request-counted heartbeat did.
///
/// Thread-safe: `should_tick()` may be called concurrently by multiple
/// workers sharing one instance (e.g. license-fallback's crates.io thread
/// AND its PyPI/RubyGems worker pool reporting into the same heartbeat) :
/// the first caller to observe the interval elapsed claims that tick via
/// compare-exchange, so exactly one heartbeat line prints per interval
/// regardless of how many threads are racing to check.
///
/// Deliberately minimal: one instance answers one "should I log
/// now" question for one pass. Reuse elsewhere is by instantiating another
/// one, not by extending this type.
class ProgressTicker
{
 public:
  ProgressTicker(std::function<std::int64_t()> now_epoch_seconds, std::chrono::seconds interval)
      : now_epoch_seconds_(std::move(now_epoch_seconds)),
        interval_seconds_(interval.count()),
        last_tick_epoch_seconds_(now_epoch_seconds_())
  {
  }

  [[nodiscard]] bool should_tick()
  {
    const std::int64_t now = now_epoch_seconds_();
    std::int64_t previous_tick = last_tick_epoch_seconds_.load();
    while (now - previous_tick >= interval_seconds_)
    {
      if (last_tick_epoch_seconds_.compare_exchange_weak(previous_tick, now))
      {
        return true;
      }
    }
    return false;
  }

 private:
  std::function<std::int64_t()> now_epoch_seconds_;
  std::int64_t interval_seconds_;
  std::atomic<std::int64_t> last_tick_epoch_seconds_;
};

}  // namespace bomwerk::core
