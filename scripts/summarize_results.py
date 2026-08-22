#!/usr/bin/env python3
"""Summarise c2probe JSONL output for one scan date.

The result tree is organised by date and then by probe family::

    result/
      20260822/
        valleyrat/
          ctg_jp_137_220_144_0_20.jsonl
          ...
        cobaltstrike/
          ...

Each date directory is summarised on its own; every probe family directory
becomes a section, and a combined section is added when more than one exists.

Only the standard library is used, so this runs anywhere the scanner does.

Examples::

    python scripts/summarize_results.py                     # newest date, to stdout
    python scripts/summarize_results.py --date 20260822
    python scripts/summarize_results.py --all --write       # SUMMARY.md per date
    python scripts/summarize_results.py --format json
    python scripts/summarize_results.py --compare-previous
    python scripts/summarize_results.py --strict            # non-zero exit on defects
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import math
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional, Sequence

# Trailing "_A_B_C_D_P" in a file name is read as the CIDR the file covers, so
# records can be checked against the range they were supposed to come from.
FILENAME_CIDR = re.compile(r"(\d{1,3})_(\d{1,3})_(\d{1,3})_(\d{1,3})_(\d{1,2})$")
DATE_DIRECTORY = re.compile(r"^\d{8}$")
IPV4_GROUP_PREFIX = 24
IPV6_GROUP_PREFIX = 64
NO_PROBE = "(discovery only)"


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


@dataclass
class Record:
    """One JSONL line from the scanner."""

    ip: Any
    port: int
    transport: str
    port_state: str
    syn_rtt_ms: Optional[int]
    probe: Optional[str]
    family: Optional[str]
    protocol: Optional[str]
    confirmed: bool
    confidence: Optional[float]
    status: Optional[str]
    duration_ms: Optional[int]
    timestamp: Optional[datetime]
    fields: dict
    source: str

    @property
    def endpoint(self) -> str:
        return format_endpoint(self.ip, self.port)


@dataclass
class FileReport:
    """Integrity of a single JSONL file."""

    path: Path
    declared: Optional[Any]
    records: int = 0
    hosts: int = 0
    malformed: list = field(default_factory=list)
    missing_trailing_newline: bool = False
    out_of_range: list = field(default_factory=list)

    @property
    def defects(self) -> int:
        return len(self.malformed) + len(self.out_of_range) + int(self.missing_trailing_newline)


@dataclass
class ProbeSection:
    """Everything summarised for one probe family directory."""

    name: str
    records: list
    files: list

    @property
    def hosts(self) -> set:
        return {r.ip for r in self.records}

    @property
    def endpoints(self) -> set:
        return {r.endpoint for r in self.records}


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def parse_timestamp(value: Any) -> Optional[datetime]:
    """Accept RFC 3339 with nanosecond precision, which fromisoformat rejects."""
    if not isinstance(value, str):
        return None
    text = value.strip().replace("Z", "+00:00")
    text = re.sub(r"\.(\d{6})\d+", r".\1", text)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def declared_network(path: Path) -> Optional[Any]:
    match = FILENAME_CIDR.search(path.stem)
    if not match:
        return None
    octets = ".".join(match.group(i) for i in range(1, 5))
    try:
        return ipaddress.ip_network(f"{octets}/{match.group(5)}", strict=False)
    except ValueError:
        return None


def build_record(payload: dict, source: str) -> Optional[Record]:
    target = payload.get("target") or {}
    address = target.get("ip")
    if address is None:
        return None
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return None
    probe = payload.get("probe") or {}
    discovery = payload.get("discovery") or {}
    return Record(
        ip=ip,
        port=int(target.get("port", 0)),
        transport=target.get("transport", ""),
        port_state=discovery.get("port_state", ""),
        syn_rtt_ms=discovery.get("syn_rtt_ms"),
        probe=probe.get("name"),
        family=probe.get("family"),
        protocol=probe.get("protocol"),
        confirmed=bool(probe.get("confirmed", False)),
        confidence=probe.get("confidence"),
        status=probe.get("status"),
        duration_ms=probe.get("duration_ms"),
        timestamp=parse_timestamp(payload.get("timestamp")),
        fields=payload.get("fields") or {},
        source=source,
    )


def load_file(path: Path) -> tuple:
    """Return the records in one JSONL file plus its integrity report."""
    report = FileReport(path=path, declared=declared_network(path))
    raw = path.read_bytes()
    # A file that does not end in a newline was cut off mid-write.
    if raw and not raw.endswith(b"\n"):
        report.missing_trailing_newline = True
    records = []
    hosts = set()
    for number, line in enumerate(raw.decode("utf-8", errors="replace").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as error:
            report.malformed.append((number, str(error)))
            continue
        record = build_record(payload, path.name)
        if record is None:
            report.malformed.append((number, "record has no usable target.ip"))
            continue
        records.append(record)
        hosts.add(record.ip)
        if report.declared is not None and record.ip not in report.declared:
            report.out_of_range.append((str(record.ip), str(report.declared)))
    report.records = len(records)
    report.hosts = len(hosts)
    return records, report


def load_probe_sections(date_directory: Path) -> list:
    sections = []
    for child in sorted(p for p in date_directory.iterdir() if p.is_dir()):
        records = []
        reports = []
        for path in sorted(child.glob("*.jsonl")):
            file_records, report = load_file(path)
            records.extend(file_records)
            reports.append(report)
        if reports:
            sections.append(ProbeSection(name=child.name, records=records, files=reports))
    # Tolerate JSONL written directly under the date directory.
    loose = sorted(date_directory.glob("*.jsonl"))
    if loose:
        records = []
        reports = []
        for path in loose:
            file_records, report = load_file(path)
            records.extend(file_records)
            reports.append(report)
        sections.append(ProbeSection(name="(uncategorised)", records=records, files=reports))
    return sections


def available_dates(root: Path) -> list:
    if not root.is_dir():
        raise SystemExit(f"result root not found: {root}")
    dates = sorted(p for p in root.iterdir() if p.is_dir() and DATE_DIRECTORY.match(p.name))
    if not dates:
        raise SystemExit(f"no YYYYMMDD directories under {root}")
    return dates


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------


def format_endpoint(ip: Any, port: int) -> str:
    return f"[{ip}]:{port}" if ip.version == 6 else f"{ip}:{port}"


def group_network(ip: Any) -> Any:
    prefix = IPV4_GROUP_PREFIX if ip.version == 4 else IPV6_GROUP_PREFIX
    return ipaddress.ip_network(f"{ip}/{prefix}", strict=False)


def numeric_summary(values: Sequence) -> Optional[dict]:
    numbers = [v for v in values if isinstance(v, (int, float))]
    if not numbers:
        return None
    return {
        "count": len(numbers),
        "min": min(numbers),
        "max": max(numbers),
        "mean": sum(numbers) / len(numbers),
    }


def resolution_of(values: Iterable) -> Optional[int]:
    """Greatest common divisor of the samples: the effective measurement tick."""
    tick = 0
    seen = False
    for value in values:
        if isinstance(value, int):
            tick = math.gcd(tick, value)
            seen = True
    return tick if seen and tick else None


def port_set_clusters(records: Sequence, minimum: int) -> list:
    """Hosts sharing an identical set of open ports, likely one deployment template."""
    ports_by_host = defaultdict(set)
    for record in records:
        ports_by_host[record.ip].add(record.port)
    clusters = defaultdict(list)
    for ip, ports in ports_by_host.items():
        clusters[tuple(sorted(ports))].append(ip)
    grouped = [
        {"ports": list(ports), "hosts": sorted(hosts, key=lambda a: (a.version, a))}
        for ports, hosts in clusters.items()
        if len(hosts) >= minimum
    ]
    grouped.sort(key=lambda item: (-len(item["hosts"]), -len(item["ports"]), item["ports"]))
    return grouped


def constant_fields(records: Sequence, limit: int = 5) -> list:
    """Probe fields whose value barely varies, and the range of the ones that do."""
    values = defaultdict(list)
    for record in records:
        for key, value in record.fields.items():
            values[key].append(value)
    rows = []
    for key in sorted(values):
        observed = values[key]
        distinct = {json.dumps(v, sort_keys=True, ensure_ascii=False) for v in observed}
        if len(distinct) <= limit:
            rendered = ", ".join(sorted(distinct))
        else:
            stats = numeric_summary(observed)
            rendered = (
                f"{len(distinct)} distinct ({stats['min']}..{stats['max']})"
                if stats
                else f"{len(distinct)} distinct"
            )
        rows.append({"field": key, "observations": len(observed), "values": rendered})
    return rows


def summarise_section(section: ProbeSection, minimum_cluster: int) -> dict:
    records = section.records
    endpoints = Counter(
        (record.endpoint, record.probe or NO_PROBE) for record in records
    )
    timestamps = [r.timestamp for r in records if r.timestamp]
    rtt = [r.syn_rtt_ms for r in records]
    return {
        "probe_directory": section.name,
        "files": len(section.files),
        "files_with_hits": sum(1 for f in section.files if f.records),
        "records": len(records),
        "hosts": len(section.hosts),
        "endpoints": len({e for e, _ in endpoints}),
        "confirmed": sum(1 for r in records if r.confirmed),
        "unconfirmed": sum(1 for r in records if not r.confirmed),
        "by_probe": Counter(r.probe or NO_PROBE for r in records).most_common(),
        "by_family": Counter(r.family for r in records if r.family).most_common(),
        "by_protocol": Counter(r.protocol for r in records if r.protocol).most_common(),
        "by_status": Counter(r.status for r in records if r.status).most_common(),
        "by_transport": Counter(r.transport for r in records if r.transport).most_common(),
        "by_port_state": Counter(r.port_state for r in records if r.port_state).most_common(),
        "confidence": sorted({r.confidence for r in records if r.confidence is not None}),
        "ports": Counter(r.port for r in records).most_common(),
        "networks": Counter(str(group_network(r.ip)) for r in records).most_common(),
        "hosts_per_network": Counter(
            str(group_network(ip)) for ip in section.hosts
        ),
        "duration_ms": numeric_summary([r.duration_ms for r in records]),
        "syn_rtt_ms": numeric_summary(rtt),
        "syn_rtt_resolution_ms": resolution_of(rtt),
        "records_with_rtt": sum(1 for value in rtt if isinstance(value, int)),
        "first_seen": min(timestamps).isoformat() if timestamps else None,
        "last_seen": max(timestamps).isoformat() if timestamps else None,
        "clusters": port_set_clusters(records, minimum_cluster),
        "fields": constant_fields(records),
        "duplicate_endpoints": [
            {"endpoint": endpoint, "probe": probe, "count": count}
            for (endpoint, probe), count in endpoints.items()
            if count > 1
        ],
        "integrity": {
            "malformed_lines": sum(len(f.malformed) for f in section.files),
            "truncated_files": [f.path.name for f in section.files if f.missing_trailing_newline],
            "out_of_range": sum(len(f.out_of_range) for f in section.files),
            "unchecked_ranges": [f.path.name for f in section.files if f.declared is None],
        },
        "per_file": [
            {
                "file": f.path.name,
                "declared_cidr": str(f.declared) if f.declared else None,
                "records": f.records,
                "hosts": f.hosts,
                "defects": f.defects,
            }
            for f in section.files
        ],
    }


def compare_sections(current: Sequence, previous: Sequence) -> dict:
    """New and disappeared hosts/endpoints per probe directory, for daily runs."""
    previous_by_name = {section.name: section for section in previous}
    deltas = []
    for section in current:
        earlier = previous_by_name.get(section.name)
        if earlier is None:
            deltas.append(
                {
                    "probe_directory": section.name,
                    "baseline": False,
                    "new_hosts": sorted(str(ip) for ip in section.hosts),
                    "gone_hosts": [],
                    "new_endpoints": sorted(section.endpoints),
                    "gone_endpoints": [],
                }
            )
            continue
        deltas.append(
            {
                "probe_directory": section.name,
                "baseline": True,
                "new_hosts": sorted(str(ip) for ip in section.hosts - earlier.hosts),
                "gone_hosts": sorted(str(ip) for ip in earlier.hosts - section.hosts),
                "new_endpoints": sorted(section.endpoints - earlier.endpoints),
                "gone_endpoints": sorted(earlier.endpoints - section.endpoints),
            }
        )
    return {"deltas": deltas}


def summarise_date(date_directory: Path, minimum_cluster: int) -> dict:
    sections = load_probe_sections(date_directory)
    summaries = [summarise_section(section, minimum_cluster) for section in sections]
    every_record = [record for section in sections for record in section.records]
    combined_hosts = {record.ip for record in every_record}
    hosts_by_probe = defaultdict(set)
    for record in every_record:
        hosts_by_probe[record.probe or NO_PROBE].add(record.ip)
    overlap = [
        {
            "host": str(ip),
            "probes": sorted(name for name, hosts in hosts_by_probe.items() if ip in hosts),
        }
        for ip in sorted(combined_hosts, key=lambda a: (a.version, a))
        if sum(1 for hosts in hosts_by_probe.values() if ip in hosts) > 1
    ]
    return {
        "date": date_directory.name,
        "source": date_directory.as_posix(),
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "totals": {
            "probe_directories": len(sections),
            "records": len(every_record),
            "hosts": len(combined_hosts),
            "endpoints": len({record.endpoint for record in every_record}),
            "confirmed": sum(1 for record in every_record if record.confirmed),
            "defects": sum(
                summary["integrity"]["malformed_lines"]
                + summary["integrity"]["out_of_range"]
                + len(summary["integrity"]["truncated_files"])
                for summary in summaries
            ),
        },
        "multi_probe_hosts": overlap,
        "probes": summaries,
    }


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------


def table(headers: Sequence, rows: Sequence) -> list:
    if not rows:
        return ["（該当なし）", ""]
    lines = [
        "| " + " | ".join(str(h) for h in headers) + " |",
        "|" + "|".join("---" for _ in headers) + "|",
    ]
    lines.extend("| " + " | ".join(str(cell) for cell in row) + " |" for row in rows)
    lines.append("")
    return lines


def counter_table(headers: Sequence, pairs: Sequence, limit: Optional[int] = None) -> list:
    rows = list(pairs)[:limit] if limit else list(pairs)
    return table(headers, [[name, count] for name, count in rows])


def render_section(summary: dict, top: int) -> list:
    lines = [f"## probe: `{summary['probe_directory']}`", ""]
    overview = [
        ["検出レコード", summary["records"]],
        ["ユニークホスト", summary["hosts"]],
        ["ユニーク`IP:PORT`", summary["endpoints"]],
        ["confirmed / unconfirmed", f"{summary['confirmed']} / {summary['unconfirmed']}"],
        ["ファイル（検出あり）", f"{summary['files']} ({summary['files_with_hits']})"],
    ]
    if summary["confidence"]:
        overview.append(
            ["confidence", ", ".join(f"{value:g}" for value in summary["confidence"])]
        )
    if summary["duration_ms"]:
        stats = summary["duration_ms"]
        overview.append(
            ["probe所要時間", f"最小{stats['min']} / 平均{stats['mean']:.0f} / 最大{stats['max']} ms"]
        )
    if summary["syn_rtt_ms"]:
        stats = summary["syn_rtt_ms"]
        overview.append(["SYN RTT", f"最小{stats['min']} / 最大{stats['max']} ms"])
        overview.append(
            ["RTT記録率", f"{summary['records_with_rtt']} / {summary['records']}"]
        )
        if summary["syn_rtt_resolution_ms"]:
            overview.append(["RTT量子化", f"{summary['syn_rtt_resolution_ms']} ms刻み"])
    if summary["first_seen"]:
        overview.append(["走査時間帯", f"{summary['first_seen']} - {summary['last_seen']}"])
    lines += table(["項目", "値"], overview)

    lines += ["### probe内訳", ""]
    lines += counter_table(["probe", "件数"], summary["by_probe"])
    if summary["by_status"]:
        lines += ["### status内訳", ""]
        lines += counter_table(["status", "件数"], summary["by_status"])
    if len(summary["by_transport"]) > 1:
        lines += counter_table(["transport", "件数"], summary["by_transport"])
    if len(summary["by_port_state"]) > 1:
        lines += counter_table(["port_state", "件数"], summary["by_port_state"])

    lines += ["### レンジ別", ""]
    with_hits = sorted(
        (row for row in summary["per_file"] if row["records"]),
        key=lambda row: -row["records"],
    )
    lines += table(
        ["ファイル", "宣言CIDR", "検出", "ホスト"],
        [
            [row["file"], row["declared_cidr"] or "-", row["records"], row["hosts"]]
            for row in with_hits
        ],
    )
    empty = [row["file"] for row in summary["per_file"] if not row["records"]]
    if empty:
        lines += [f"検出0件: {len(empty)}ファイル（{', '.join(empty)}）", ""]

    lines += ["### ネットワーク集中度", ""]
    hosts_per_network = summary["hosts_per_network"]
    lines += table(
        ["ネットワーク", "検出", "ホスト"],
        [
            [network, count, hosts_per_network.get(network, 0)]
            for network, count in summary["networks"][:top]
        ],
    )

    lines += ["### ポート", ""]
    lines += counter_table(["ポート", "件数"], summary["ports"], limit=top)

    lines += ["### ポート構成が一致するホスト群", ""]
    lines += [
        "同一のポート集合を持つホストは、同じ構成テンプレートで展開された可能性がある。",
        "",
    ]
    lines += table(
        ["ホスト数", "ポート集合", "ホスト"],
        [
            [
                len(cluster["hosts"]),
                ", ".join(str(port) for port in cluster["ports"]),
                ", ".join(str(host) for host in cluster["hosts"]),
            ]
            for cluster in summary["clusters"]
        ],
    )

    if summary["fields"]:
        lines += ["### probe固有フィールド", ""]
        lines += table(
            ["フィールド", "観測数", "値"],
            [[row["field"], row["observations"], row["values"]] for row in summary["fields"]],
        )

    integrity = summary["integrity"]
    lines += ["### 品質チェック", ""]
    checks = [
        [
            "JSON parse",
            "全行成功" if not integrity["malformed_lines"] else f"{integrity['malformed_lines']}行が破損",
        ],
        [
            "ファイル末尾",
            "全ファイルが改行終端"
            if not integrity["truncated_files"]
            else f"切断の疑い: {', '.join(integrity['truncated_files'])}",
        ],
        [
            "CIDR整合",
            "全レコードが宣言レンジ内"
            if not integrity["out_of_range"]
            else f"{integrity['out_of_range']}件が範囲外",
        ],
        [
            "`IP:PORT`重複",
            "なし"
            if not summary["duplicate_endpoints"]
            else f"{len(summary['duplicate_endpoints'])}件",
        ],
    ]
    if integrity["unchecked_ranges"]:
        checks.append(
            ["CIDR未検査", f"{len(integrity['unchecked_ranges'])}ファイル（ファイル名から範囲を判定できず）"]
        )
    lines += table(["検査", "結果"], checks)
    return lines


def preview(items: Sequence, limit: int = 15) -> str:
    if not items:
        return "-"
    shown = ", ".join(str(item) for item in items[:limit])
    return shown if len(items) <= limit else f"{shown}, ... (他{len(items) - limit}件)"


def render_delta(delta: dict) -> list:
    lines = [f"### `{delta['probe_directory']}`", ""]
    if not delta["baseline"]:
        lines += ["前回の同名probeディレクトリがないため、全件を新規として扱う。", ""]
    lines += table(
        ["区分", "件数", "内容"],
        [
            ["新規ホスト", len(delta["new_hosts"]), preview(delta["new_hosts"])],
            ["消失ホスト", len(delta["gone_hosts"]), preview(delta["gone_hosts"])],
            ["新規`IP:PORT`", len(delta["new_endpoints"]), preview(delta["new_endpoints"])],
            ["消失`IP:PORT`", len(delta["gone_endpoints"]), preview(delta["gone_endpoints"])],
        ],
    )
    return lines


def render_markdown(summary: dict, comparison: Optional[dict], top: int) -> str:
    totals = summary["totals"]
    lines = [
        f"# スキャン結果サマリ {summary['date']}",
        "",
        f"対象: `{summary['source']}`",
        f"生成: {summary['generated_at']}",
        "",
        "fingerprintの一致はプロトコル応答の一致であり、特定の攻撃者・キャンペーンへの",
        "帰属を意味しない。以下はすべて観測事実の集計である。",
        "",
        "## 全体",
        "",
    ]
    lines += table(
        ["項目", "値"],
        [
            ["probeディレクトリ", totals["probe_directories"]],
            ["検出レコード", totals["records"]],
            ["ユニークホスト", totals["hosts"]],
            ["ユニーク`IP:PORT`", totals["endpoints"]],
            ["confirmed", totals["confirmed"]],
            ["整合性の問題", totals["defects"]],
        ],
    )
    if summary["multi_probe_hosts"]:
        lines += ["複数probeで検出されたホスト:", ""]
        lines += table(
            ["ホスト", "probe"],
            [
                [row["host"], ", ".join(row["probes"])]
                for row in summary["multi_probe_hosts"][:top]
            ],
        )
    for section in summary["probes"]:
        lines += render_section(section, top)
    if comparison:
        lines += ["## 前回スキャンとの差分", ""]
        for delta in comparison["deltas"]:
            lines += render_delta(delta)
    lines += [
        "## 注意",
        "",
        "- `--output-mode matched` で取得した結果には母数（open port数、応答はあったが",
        "  一致しなかった件数）が含まれない。分母が必要な場合はworkerのsummary",
        "  （`scheduled` / `open` / `closed` / `skipped` / `probes`）を併せて保存する。",
        "- 検出0件のレンジについて、スキャンが完走したのか中断したのかは出力からは",
        "  判別できない。同じくsummaryの保存で区別できる。",
        "",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def json_ready(value: Any) -> Any:
    if isinstance(value, Counter):
        return dict(value)
    if isinstance(value, dict):
        return {key: json_ready(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_ready(item) for item in value]
    if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return str(value)
    return value


def use_utf8_console() -> None:
    """Japanese output must survive a cp932 console, so force UTF-8 on stdout."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass


def emit(text: str, destination: Optional[Path]) -> None:
    if destination is None:
        sys.stdout.write(text if text.endswith("\n") else text + "\n")
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")
    print(f"wrote {destination}", file=sys.stderr)


def parse_arguments(argv: Optional[Sequence] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Summarise c2probe JSONL output for one scan date.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "date",
        nargs="?",
        help="scan date directory, for example 20260822. Defaults to the newest one.",
    )
    parser.add_argument(
        "--date",
        dest="date_option",
        help="same as the positional date argument",
    )
    parser.add_argument("--root", type=Path, default=Path("result"), help="result tree root")
    parser.add_argument("--all", action="store_true", help="summarise every date directory")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("-o", "--output", type=Path, help="write to this path instead of stdout")
    parser.add_argument(
        "--write",
        action="store_true",
        help="write SUMMARY.md (or SUMMARY.json) into each date directory",
    )
    parser.add_argument(
        "--compare-previous",
        action="store_true",
        help="add new/disappeared hosts against the preceding date directory",
    )
    parser.add_argument("--top", type=int, default=20, help="rows per ranked table")
    parser.add_argument(
        "--min-cluster",
        type=int,
        default=2,
        help="smallest number of hosts sharing a port set to report",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="exit non-zero when an integrity problem is found",
    )
    arguments = parser.parse_args(argv)
    if arguments.date_option:
        if arguments.date and arguments.date != arguments.date_option:
            parser.error("date given twice with different values")
        arguments.date = arguments.date_option
    if arguments.all and arguments.date:
        parser.error("--all covers every date; drop the date argument")
    if arguments.all and arguments.output:
        parser.error("--all writes one file per date; use --write instead of --output")
    if arguments.top < 1:
        parser.error("--top must be positive")
    return arguments


def target_dates(arguments: argparse.Namespace) -> list:
    dates = available_dates(arguments.root)
    if arguments.all:
        return dates
    if arguments.date:
        chosen = arguments.root / arguments.date
        if not chosen.is_dir():
            raise SystemExit(
                f"{chosen} not found; available: {', '.join(p.name for p in dates)}"
            )
        return [chosen]
    return [dates[-1]]


def previous_date(root: Path, current: Path) -> Optional[Path]:
    dates = [p for p in available_dates(root) if p.name < current.name]
    return dates[-1] if dates else None


def run(arguments: argparse.Namespace) -> int:
    defects = 0
    for date_directory in target_dates(arguments):
        summary = summarise_date(date_directory, arguments.min_cluster)
        defects += summary["totals"]["defects"]
        comparison = None
        if arguments.compare_previous:
            earlier = previous_date(arguments.root, date_directory)
            if earlier is not None:
                comparison = compare_sections(
                    load_probe_sections(date_directory), load_probe_sections(earlier)
                )
                comparison["previous_date"] = earlier.name
            else:
                print(f"no earlier date to compare {date_directory.name} with", file=sys.stderr)
        if arguments.format == "json":
            payload = json_ready({"summary": summary, "comparison": comparison})
            text = json.dumps(payload, indent=2, ensure_ascii=False)
            default_name = "SUMMARY.json"
        else:
            text = render_markdown(summary, comparison, arguments.top)
            default_name = "SUMMARY.md"
        destination = arguments.output
        if arguments.write:
            destination = date_directory / default_name
        emit(text, destination)
    if arguments.strict and defects:
        print(f"{defects} integrity problem(s) found", file=sys.stderr)
        return 1
    return 0


def main(argv: Optional[Sequence] = None) -> int:
    use_utf8_console()
    return run(parse_arguments(argv))


if __name__ == "__main__":
    sys.exit(main())
