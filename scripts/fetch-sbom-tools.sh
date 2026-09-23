#!/usr/bin/env bash
# Fetch the pinned `sbom-tools` release binary (sbom-tool/sbom-tools,
# MIT, https://sbom.tools) that CRANE itself uses to validate an uploaded SBOM
# against --standard ntia/cra. This is CI/dev tooling, not a bomwerk build
# dependency (same category as clang-format/Doxygen in CMakeLists.txt), so it
# is deliberately not a vcpkg.json entry (hard rule 4 is about what bomwerk
# links, not what validates bomwerk's output).
#
# Unlike CRANE's own Dockerfile (library/22 analysis section 4: it `curl`s
# this exact tool with no checksum or signature check), every asset here is
# verified against a checksum pinned below BEFORE it is ever executed. Those
# checksums were cross-checked against two independent sources at pin time:
# the release's own `checksums.sha256` asset and GitHub's own per-asset
# `digest` field (computed by GitHub at upload time): both agreed.
#
# Usage: fetch-sbom-tools.sh [install-dir]
#   install-dir defaults to <repo-root>/.cache/sbom-tools (gitignored).
# Writes <install-dir>/sbom-tools. Exits non-zero (with a message on stderr)
# on any unsupported platform, download failure or checksum mismatch: never
# silently installs an unverified binary.
set -euo pipefail

readonly kSbomToolsVersion="v0.2.0"
readonly kReleaseBaseUrl="https://github.com/sbom-tool/sbom-tools/releases/download/${kSbomToolsVersion}"

# asset-name:sha256 pairs, pinned from ${kReleaseBaseUrl}/checksums.sha256
# (cross-checked against the GitHub Releases API's per-asset "digest" field).
readonly kKnownAssets="
sbom-tools-linux-x86_64.tar.gz:0f93406da9643a8ea3afe4fb56c7418fb74d29ecaa0af49b260dc4b2ff597956
sbom-tools-linux-aarch64.tar.gz:fd3ed73f4d259704fa1eb7065e3fcbf45213751b3a7cbe3f0ae3429d88ad24bb
sbom-tools-macos-x86_64.tar.gz:78dda81723e83c8ba8eaff4299f003a10064991cd338c05f0acfb64c39fc7ab5
sbom-tools-macos-aarch64.tar.gz:b95ca562aa24ec733c08b3916d25e52ede8e70b1c96a3d39d01cdd77b7d3fe5f
"

script_directory="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_directory}/.." && pwd)"
install_directory="${1:-${repo_root}/.cache/sbom-tools}"

case "$(uname -s)" in
  Linux) host_os="linux" ;;
  Darwin) host_os="macos" ;;
  *)
    echo "fetch-sbom-tools: unsupported OS $(uname -s); no pinned asset for it" >&2
    exit 1
    ;;
esac
case "$(uname -m)" in
  x86_64|amd64) host_arch="x86_64" ;;
  arm64|aarch64) host_arch="aarch64" ;;
  *)
    echo "fetch-sbom-tools: unsupported architecture $(uname -m); no pinned asset for it" >&2
    exit 1
    ;;
esac

asset_name="sbom-tools-${host_os}-${host_arch}.tar.gz"
expected_checksum="$(echo "${kKnownAssets}" | awk -F: -v asset="${asset_name}" '$1 == asset { print $2 }')"
if [[ -z "${expected_checksum}" ]]; then
  echo "fetch-sbom-tools: no pinned checksum for ${asset_name}" >&2
  exit 1
fi

if [[ -x "${install_directory}/sbom-tools" &&
      -f "${install_directory}/.version" &&
      "$(cat "${install_directory}/.version")" == "${kSbomToolsVersion}" ]]; then
  echo "fetch-sbom-tools: ${install_directory}/sbom-tools already at ${kSbomToolsVersion}"
  exit 0
fi

download_directory="$(mktemp -d)"
trap 'rm -rf "${download_directory}"' EXIT

archive_path="${download_directory}/${asset_name}"
echo "fetch-sbom-tools: downloading ${asset_name} (${kSbomToolsVersion})"
curl -fsSL -o "${archive_path}" "${kReleaseBaseUrl}/${asset_name}"

if command -v sha256sum >/dev/null 2>&1; then
  actual_checksum="$(sha256sum "${archive_path}" | awk '{print $1}')"
else
  # macOS has no sha256sum by default; shasum -a 256 is its equivalent.
  actual_checksum="$(shasum -a 256 "${archive_path}" | awk '{print $1}')"
fi
if [[ "${actual_checksum}" != "${expected_checksum}" ]]; then
  echo "fetch-sbom-tools: checksum mismatch for ${asset_name}" >&2
  echo "  expected: ${expected_checksum}" >&2
  echo "  actual:   ${actual_checksum}" >&2
  exit 1
fi

mkdir -p "${install_directory}"
tar -xzf "${archive_path}" -C "${download_directory}"
extracted_binary="$(find "${download_directory}" -type f -name 'sbom-tools' -print -quit)"
if [[ -z "${extracted_binary}" ]]; then
  echo "fetch-sbom-tools: archive ${asset_name} contained no 'sbom-tools' binary" >&2
  exit 1
fi
install -m 0755 "${extracted_binary}" "${install_directory}/sbom-tools"
echo "${kSbomToolsVersion}" > "${install_directory}/.version"
echo "fetch-sbom-tools: installed ${install_directory}/sbom-tools (${kSbomToolsVersion})"
