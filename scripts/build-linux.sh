#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
cd "${repo_root}"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "This script must run on Linux. From Windows, use scripts/build-windows.ps1." >&2
  exit 2
fi

case "$(uname -m)" in
  x86_64) package_arch="x86_64" ;;
  aarch64|arm64) package_arch="aarch64" ;;
  *) echo "Unsupported Linux architecture: $(uname -m)" >&2; exit 2 ;;
esac

command -v cargo >/dev/null || { echo "cargo is required" >&2; exit 2; }
command -v sha256sum >/dev/null || { echo "sha256sum is required" >&2; exit 2; }

cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
cargo build --locked --release

version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n 1)"
package="c2probe-${version}-linux-${package_arch}"
stage="${repo_root}/dist/${package}"
archive="${repo_root}/dist/${package}.tar.gz"

rm -rf -- "${stage}"
mkdir -p "${stage}"
install -m 0755 target/release/c2probe "${stage}/c2probe"
install -m 0755 target/release/nse2yaml "${stage}/nse2yaml"
cp -R probes "${stage}/probes"
mkdir -p "${stage}/docs"
cp docs/NSE_CONVERSION.md docs/NSE_COVERAGE.md docs/PERFORMANCE.md docs/REVIEW.md "${stage}/docs/"
cp README.md spec.md "${stage}/"
"${stage}/nse2yaml" --help >/dev/null
tar --sort=name --mtime='UTC 2020-01-01' --owner=0 --group=0 --numeric-owner \
  -czf "${archive}" -C "${repo_root}/dist" "${package}"

(cd "${repo_root}/dist" && sha256sum "${package}.tar.gz" > "${package}.sha256")
echo "Created ${archive}"
echo "Checksum: ${repo_root}/dist/${package}.sha256"
