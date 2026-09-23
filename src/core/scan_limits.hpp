#pragma once
#include <cstddef>

namespace bomwerk::core
{

/// Default number of package entries each lockfile ecosystem may parse during one scan.
inline constexpr std::size_t kDefaultMaxPackagesPerEcosystem = 10000;

/// Largest per-ecosystem package budget an automatically loaded repository config may request.
inline constexpr std::size_t kMaxConfiguredPackagesPerEcosystem = 100000;

/// Default number of files each producer may scan for its own manifest/lockfile type during
/// one scan.
inline constexpr std::size_t kDefaultMaxScannedFilesPerEcosystem = 10000;

}  // namespace bomwerk::core
