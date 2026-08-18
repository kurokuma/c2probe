#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"

block_list="${1:-${repo_root}/ctg-server-block-list.json}"
output_dir="${2:-${repo_root}/results/ctg-server-block-list}"
c2probe_bin="${C2PROBE_BIN:-${repo_root}/c2probe}"

command -v jq >/dev/null 2>&1 || {
  echo "jq is required" >&2
  exit 2
}

[[ -f "${block_list}" ]] || {
  echo "Block list not found: ${block_list}" >&2
  exit 2
}

[[ -x "${c2probe_bin}" ]] || {
  echo "c2probe is not executable: ${c2probe_bin}" >&2
  echo "Set C2PROBE_BIN=/path/to/c2probe if it is elsewhere." >&2
  exit 2
}

# Restrict both fields before placing them in shell variables or file names.
jq -e '
  type == "array" and
  all(.[ ];
    (.name | type == "string" and test("^[A-Za-z0-9._-]+$")) and
    (.cidr | type == "string" and test("^[0-9]{1,3}(\\.[0-9]{1,3}){3}/([0-9]|[12][0-9]|3[0-2])$"))
  )
' "${block_list}" >/dev/null || {
  echo "Invalid block list: every row needs a safe name and an IPv4 CIDR" >&2
  exit 2
}

duplicate_names="$(jq -r 'group_by(.name)[] | select(length > 1) | .[0].name' "${block_list}")"
if [[ -n "${duplicate_names}" ]]; then
  echo "Duplicate names would overwrite output files:" >&2
  echo "${duplicate_names}" >&2
  exit 2
fi

mkdir -p -- "${output_dir}"

while IFS=$'\t' read -r name cidr; do
  output_file="${output_dir}/${name}.jsonl"
  echo "Scanning ${name}: ${cidr} -> ${output_file}" >&2

  sudo -- "${c2probe_bin}" \
    -t "${cidr}" \
    -p 1-10000 \
    --probe-dir "${repo_root}/probes/valleyrat" \
    --scan-mode full \
    --output-mode matched \
    --format jsonl \
    --output "${output_file}"

  echo "Waiting 60 seconds after ${name}..." >&2
  sleep 60
done < <(jq -r '.[] | [.name, .cidr] | @tsv' "${block_list}")
