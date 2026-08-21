#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"

usage() {
  echo "Usage: $0 BLOCK_LIST PROBE_DIR PORTS S3_BUCKET [LOCAL_OUTPUT_DIR]" >&2
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if (($# < 4 || $# > 5)); then
  usage
  exit 2
fi

block_list="$1"
probe_dir="$2"
ports="$3"
s3_bucket="${4#s3://}"
s3_bucket="${s3_bucket%/}"
c2probe_bin="${C2PROBE_BIN:-${repo_root}/c2probe}"
scan_date="${SCAN_DATE:-$(date +%Y%m%d)}"

command -v jq >/dev/null 2>&1 || {
  echo "jq is required" >&2
  exit 2
}

command -v aws >/dev/null 2>&1 || {
  echo "AWS CLI v2 is required" >&2
  exit 2
}

[[ -f "${block_list}" ]] || {
  echo "Block list not found: ${block_list}" >&2
  exit 2
}

[[ -d "${probe_dir}" ]] || {
  echo "Probe directory not found: ${probe_dir}" >&2
  exit 2
}

[[ -x "${c2probe_bin}" ]] || {
  echo "c2probe is not executable: ${c2probe_bin}" >&2
  echo "Set C2PROBE_BIN=/path/to/c2probe if it is elsewhere." >&2
  exit 2
}

if [[ ! "${s3_bucket}" =~ ^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$ || "${s3_bucket}" == *..* ]]; then
  echo "Invalid S3 bucket name: ${s3_bucket}" >&2
  exit 2
fi

if [[ ! "${scan_date}" =~ ^[0-9]{8}$ ]] ||
  [[ "$(date -d "${scan_date}" +%Y%m%d 2>/dev/null || true)" != "${scan_date}" ]]; then
  echo "SCAN_DATE must be a valid date in yyyyMMdd form: ${scan_date}" >&2
  exit 2
fi

probe_folder="$(basename -- "$(cd -- "${probe_dir}" && pwd)")"
if [[ ! "${probe_folder}" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "Probe folder name is not safe for an S3 prefix: ${probe_folder}" >&2
  exit 2
fi

block_list_base="$(basename -- "${block_list}")"
output_name="${block_list_base%.*}"
output_dir="${5:-${repo_root}/results/${output_name:-block-list}/${probe_folder}/${scan_date}}"
s3_prefix="s3://${s3_bucket}/active_scan/${probe_folder}/${scan_date}"

# Confirm credentials and connectivity before starting a potentially long scan.
aws sts get-caller-identity >/dev/null

# Restrict both fields before placing them in shell variables or file names.
jq -e '
  type == "array" and length > 0 and
  all(.[ ];
    (.name | type == "string" and test("^[A-Za-z0-9._-]+$")) and
    (.cidr | type == "string" and test("^[0-9]{1,3}(\\.[0-9]{1,3}){3}/([0-9]|[12][0-9]|3[0-2])$"))
  )
' "${block_list}" >/dev/null || {
  echo "Invalid block list: at least one row with a safe name and IPv4 CIDR is required" >&2
  exit 2
}

duplicate_names="$(jq -r 'group_by(.name)[] | select(length > 1) | .[0].name' "${block_list}")"
if [[ -n "${duplicate_names}" ]]; then
  echo "Duplicate names would overwrite output files:" >&2
  echo "${duplicate_names}" >&2
  exit 2
fi

mkdir -p -- "${output_dir}"
output_files=()

while IFS=$'\t' read -r name cidr; do
  output_file="${output_dir}/${name}.jsonl"
  echo "Scanning ${name}: ${cidr} -> ${output_file}" >&2

  sudo -- "${c2probe_bin}" \
    -t "${cidr}" \
    -p "${ports}" \
    --probe-dir "${probe_dir}" \
    --scan-mode full \
    --output-mode matched \
    --format jsonl \
    --output "${output_file}"

  [[ -f "${output_file}" ]] || {
    echo "Expected output was not created: ${output_file}" >&2
    exit 1
  }
  output_files+=("${output_file}")

  echo "Waiting 60 seconds after ${name}..." >&2
  sleep 60
done < <(jq -r '.[] | [.name, .cidr] | @tsv' "${block_list}")

echo "All scans completed; uploading ${#output_files[@]} files to ${s3_prefix}/" >&2
for output_file in "${output_files[@]}"; do
  aws s3 cp \
    "${output_file}" \
    "${s3_prefix}/$(basename -- "${output_file}")" \
    --content-type application/x-ndjson \
    --only-show-errors
done

echo "Upload completed: ${s3_prefix}/" >&2
