cmake_minimum_required(VERSION 3.14)
project(bomwerk_golden_cmake_archive)

include(FetchContent)

# Source archive pinned by hash: the hash makes the artifact immutable, so the
# producer rates this High and the digest lands both in the purl's checksum
# qualifier and in the component's hashes entry. The digest is synthetic --
# never a real zlib release hash -- so this fixture can never be mistaken for
# one of bomwerk's own dependencies (see the CI self-scan absence checks).
FetchContent_Declare(
  zlib
  URL https://zlib.net/zlib-1.3.1.tar.gz
  URL_HASH SHA256=3a1b5c7d9e2f40618293a4b5c6d7e8f901a2b3c4d5e6f708192a3b4c5d6e7f80
)

# The same shape with no hash at all: still a deliberate identity, because the
# download URL pins which artifact was fetched, but Medium rather than High --
# an unhashed URL can serve different bytes tomorrow.
FetchContent_Declare(
  libfoo
  URL https://example.com/libfoo-2.4.0.tar.bz2
)

FetchContent_MakeAvailable(zlib libfoo)
