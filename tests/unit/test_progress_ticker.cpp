#include <atomic>
#include <chrono>
#include <cstdint>
#include <thread>
#include <vector>

#include "core/progress_ticker.hpp"
#include "support/check.hpp"

namespace core = bomwerk::core;

int main()
{
  // Given a ticker with a 30s interval and a clock advancing in 10s steps,
  // when should_tick() is called after each step, then it returns true only
  // once at least 30s have elapsed since the last tick (construction counts
  // as the first "tick"), and resets its baseline to that moment.
  {
    std::int64_t now = 0;
    core::ProgressTicker ticker([&now] { return now; }, std::chrono::seconds(30));

    now = 10;
    BOMWERK_TEST_CHECK(!ticker.should_tick());
    now = 20;
    BOMWERK_TEST_CHECK(!ticker.should_tick());
    now = 30;
    BOMWERK_TEST_CHECK(ticker.should_tick());
    now = 40;
    BOMWERK_TEST_CHECK(!ticker.should_tick());
    now = 60;
    BOMWERK_TEST_CHECK(ticker.should_tick());
  }

  // Given a ticker shared across multiple threads calling should_tick()
  // concurrently after the clock has advanced once past the interval, when
  // the concurrent calls race, then exactly one observes true: the
  // compare-exchange claim is exclusive regardless of how many threads race
  // it (needed because license-fallback's crates.io thread and its
  // PyPI/RubyGems worker pool share one instance).
  {
    constexpr int kWorkerCount = 8;
    std::atomic<std::int64_t> shared_now{0};
    core::ProgressTicker ticker([&shared_now] { return shared_now.load(); },
                                std::chrono::seconds(1));
    shared_now.store(5);

    std::atomic<int> true_count{0};
    std::vector<std::thread> workers;
    for (int worker_index = 0; worker_index < kWorkerCount; ++worker_index)
    {
      workers.emplace_back(
          [&ticker, &true_count]
          {
            if (ticker.should_tick())
            {
              ++true_count;
            }
          });
    }
    for (std::thread& worker : workers)
    {
      worker.join();
    }

    BOMWERK_TEST_CHECK(true_count.load() == 1);
  }

  return 0;
}
