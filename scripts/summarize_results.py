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

The tree is committed and pushed daily, and served by GitHub Pages, so
``--site`` renders it as a browsable static site: one page per scan date plus an
index that carries the day-over-day trend.

Only the standard library is used, so this runs anywhere the scanner does.

Examples::

    python scripts/summarize_results.py                     # newest date, to stdout
    python scripts/summarize_results.py --date 20260822
    python scripts/summarize_results.py --all --write       # SUMMARY.md per date
    python scripts/summarize_results.py --format json
    python scripts/summarize_results.py --compare-previous
    python scripts/summarize_results.py --strict            # non-zero exit on defects
    python scripts/summarize_results.py --site              # GitHub Pages site
"""

from __future__ import annotations

import argparse
import csv
import html
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


_SECTION_CACHE: dict = {}


def load_probe_sections(date_directory: Path) -> list:
    """Load every probe directory under one scan date.

    Site builds ask for the same date twice (once for its own page, once as the
    baseline of the next day), so results are memoised.
    """
    key = str(date_directory)
    if key in _SECTION_CACHE:
        return _SECTION_CACHE[key]
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
    _SECTION_CACHE[key] = sections
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


def host_details(records: Sequence) -> list:
    """Per-host rollup for one probe directory on one date."""
    grouped: dict = {}
    for record in records:
        entry = grouped.setdefault(
            record.ip,
            {"ports": set(), "probes": set(), "statuses": set(), "rtt": [], "records": 0},
        )
        entry["ports"].add(record.port)
        if record.probe:
            entry["probes"].add(record.probe)
        if record.status:
            entry["statuses"].add(record.status)
        if isinstance(record.syn_rtt_ms, int):
            entry["rtt"].append(record.syn_rtt_ms)
        entry["records"] += 1
    rows = []
    for ip in sorted(grouped, key=lambda a: (a.version, a)):
        entry = grouped[ip]
        rows.append(
            {
                "host": str(ip),
                "ports": sorted(entry["ports"]),
                "probes": sorted(entry["probes"]),
                "statuses": sorted(entry["statuses"]),
                "records": entry["records"],
                "syn_rtt_ms": min(entry["rtt"]) if entry["rtt"] else None,
                "endpoints": [format_endpoint(ip, port) for port in sorted(entry["ports"])],
            }
        )
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
        "hosts_detail": host_details(records),
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
# Cross-date overview
# ---------------------------------------------------------------------------


def build_overview(dates: Sequence) -> dict:
    """Index every host across every scan date.

    The per-date pages answer "what did we see that day". This answers the
    questions that only the whole series can: when a host first appeared, whether
    it is still up, and how the population moves day to day.
    """
    order = [d.name for d in dates]
    position = {name: index for index, name in enumerate(order)}
    hosts: dict = {}
    per_date = []
    probe_names: set = set()

    for date_directory in dates:
        name = date_directory.name
        sections = load_probe_sections(date_directory)
        seen_today: set = set()
        records = 0
        probe_hosts: dict = {}
        for section in sections:
            probe_names.add(section.name)
            probe_hosts[section.name] = {str(ip) for ip in section.hosts}
            records += len(section.records)
            for record in section.records:
                key = str(record.ip)
                seen_today.add(key)
                entry = hosts.setdefault(
                    key,
                    {
                        "host": key,
                        "version": record.ip.version,
                        "sort_key": (record.ip.version, int(record.ip)),
                        "network": str(group_network(record.ip)),
                        "first_seen": name,
                        "last_seen": name,
                        "dates": [],
                        "probes": set(),
                        "ports": set(),
                        "statuses": set(),
                    },
                )
                entry["last_seen"] = max(entry["last_seen"], name)
                entry["first_seen"] = min(entry["first_seen"], name)
                entry["ports"].add(record.port)
                entry["probes"].add(record.probe or section.name)
                if record.status:
                    entry["statuses"].add(record.status)
        for key in seen_today:
            hosts[key]["dates"].append(name)
        per_date.append(
            {
                "date": name,
                "records": records,
                "hosts": len(seen_today),
                "host_set": seen_today,
                "probe_hosts": probe_hosts,
            }
        )

    # New and gone are derived from the index, so they stay consistent with the
    # first/last seen columns rather than being recomputed per page.
    for index, day in enumerate(per_date):
        previous = per_date[index - 1]["host_set"] if index else set()
        appeared = day["host_set"] - previous
        day["new_hosts"] = sorted(appeared, key=lambda h: hosts[h]["sort_key"])
        day["first_seen_hosts"] = sorted(
            (h for h in appeared if hosts[h]["first_seen"] == day["date"]),
            key=lambda h: hosts[h]["sort_key"],
        )
        # Seen before, missing yesterday, back today: infrastructure returning.
        day["returning_hosts"] = sorted(
            (h for h in appeared if hosts[h]["first_seen"] != day["date"]),
            key=lambda h: hosts[h]["sort_key"],
        )
        day["gone_hosts"] = sorted(previous - day["host_set"], key=lambda h: hosts[h]["sort_key"])
        day["baseline"] = index == 0

    latest = order[-1] if order else None
    total_days = len(order)
    for entry in hosts.values():
        entry["days_observed"] = len(entry["dates"])
        entry["active"] = entry["last_seen"] == latest
        first_index = position[entry["first_seen"]]
        possible = total_days - first_index
        entry["coverage"] = entry["days_observed"] / possible if possible else 0.0
        # Intermittent means gaps *inside* the observed span. A host that simply
        # stopped appearing is gone, not flapping, so measure first..last only.
        span = position[entry["last_seen"]] - first_index + 1
        entry["span"] = span
        entry["intermittent"] = entry["days_observed"] < span

    return {
        "dates": order,
        "per_date": per_date,
        "hosts": hosts,
        "latest": latest,
        "probe_names": sorted(probe_names),
    }


def overview_tables(overview: dict, top: int) -> dict:
    """Derive the ranked views the overall page shows."""
    hosts = list(overview["hosts"].values())
    latest = overview["latest"]
    by_first_seen = sorted(
        hosts, key=lambda h: (h["first_seen"], h["sort_key"]), reverse=True
    )
    networks = Counter()
    network_hosts = defaultdict(set)
    ports = Counter()
    for entry in hosts:
        networks[entry["network"]] += 1
        network_hosts[entry["network"]].add(entry["host"])
        for port in entry["ports"]:
            ports[port] += 1
    return {
        "new_today": [h for h in hosts if h["first_seen"] == latest],
        "gone": sorted(
            (h for h in hosts if not h["active"]),
            key=lambda h: (h["last_seen"], h["sort_key"]),
            reverse=True,
        ),
        "by_first_seen": by_first_seen,
        "persistent": sorted(
            hosts, key=lambda h: (-h["days_observed"], h["sort_key"])
        )[:top],
        "intermittent": sorted(
            (h for h in hosts if h["intermittent"]),
            key=lambda h: (h["days_observed"] / h["span"], h["sort_key"]),
        )[:top],
        "networks": networks.most_common(top),
        "network_hosts": network_hosts,
        "ports": ports.most_common(top),
    }


def host_rows(entries: Sequence) -> list:
    return [
        [
            entry["host"],
            entry["first_seen"],
            entry["last_seen"],
            entry["days_observed"],
            "継続" if entry["active"] else "消失",
            ", ".join(sorted(entry["probes"])),
            ", ".join(str(port) for port in sorted(entry["ports"])),
        ]
        for entry in entries
    ]


HOST_HEADERS = ["ホスト", "初回", "最終", "観測日数", "状態", "probe", "ポート"]


def write_exports(root: Path, overview: dict) -> None:
    """Flat files for spreadsheets, pandas and OpenSearch."""
    hosts = sorted(overview["hosts"].values(), key=lambda h: h["sort_key"])
    csv_path = root / "hosts.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "host",
                "network",
                "first_seen",
                "last_seen",
                "days_observed",
                "coverage",
                "active",
                "intermittent",
                "probes",
                "ports",
                "statuses",
            ]
        )
        for entry in hosts:
            writer.writerow(
                [
                    entry["host"],
                    entry["network"],
                    entry["first_seen"],
                    entry["last_seen"],
                    entry["days_observed"],
                    f"{entry['coverage']:.3f}",
                    int(entry["active"]),
                    int(entry["intermittent"]),
                    " ".join(sorted(entry["probes"])),
                    " ".join(str(port) for port in sorted(entry["ports"])),
                    " ".join(sorted(entry["statuses"])),
                ]
            )
    print(f"wrote {csv_path}", file=sys.stderr)

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "dates": overview["dates"],
        "probe_directories": overview["probe_names"],
        "daily": [
            {
                "date": day["date"],
                "records": day["records"],
                "hosts": day["hosts"],
                "new_hosts": day["new_hosts"],
                "first_seen_hosts": day["first_seen_hosts"],
                "returning_hosts": day["returning_hosts"],
                "gone_hosts": day["gone_hosts"],
                "baseline": day["baseline"],
                "hosts_by_probe": {
                    name: len(values) for name, values in day["probe_hosts"].items()
                },
            }
            for day in overview["per_date"]
        ],
        "hosts": [
            {
                "host": entry["host"],
                "network": entry["network"],
                "first_seen": entry["first_seen"],
                "last_seen": entry["last_seen"],
                "days_observed": entry["days_observed"],
                "coverage": round(entry["coverage"], 3),
                "active": entry["active"],
                "intermittent": entry["intermittent"],
                "probes": sorted(entry["probes"]),
                "ports": sorted(entry["ports"]),
                "statuses": sorted(entry["statuses"]),
            }
            for entry in hosts
        ],
    }
    emit(json.dumps(payload, indent=2, ensure_ascii=False), root / "overview.json")


# ---------------------------------------------------------------------------
# Charts
# ---------------------------------------------------------------------------


def line_chart(labels: Sequence, series: Sequence, unit: str = "") -> str:
    """Multi-series line chart as inline SVG. No script, no dependencies."""
    if len(labels) < 2 or not series:
        return ""
    width, height = 1000, 240
    left, right, top_pad, bottom = 52, 16, 20, 34
    peak = max((max(s["values"]) for s in series if s["values"]), default=0) or 1
    plot_width = width - left - right
    plot_height = height - top_pad - bottom
    step = plot_width / (len(labels) - 1)

    def point(index: int, value: float) -> tuple:
        return left + index * step, top_pad + plot_height * (1 - value / peak)

    parts = [
        f'<svg class="chart" viewBox="0 0 {width} {height}" role="img" '
        f'aria-label="{esc(series[0]["label"])}ほかの推移">'
    ]
    for fraction in (0, 0.5, 1):
        y = top_pad + plot_height * (1 - fraction)
        value = peak * fraction
        parts.append(
            f'<line class="grid" x1="{left}" y1="{y:.1f}" x2="{width - right}" y2="{y:.1f}"/>'
        )
        parts.append(
            f'<text x="{left - 8}" y="{y + 4:.1f}" text-anchor="end">{value:.0f}{esc(unit)}</text>'
        )
    for index, label in enumerate(labels):
        # Only a few x labels fit; show the ends and a middle marker.
        if index in (0, len(labels) - 1) or (len(labels) >= 3 and index == len(labels) // 2):
            x = left + index * step
            anchor = "start" if index == 0 else "end" if index == len(labels) - 1 else "middle"
            parts.append(
                f'<text x="{x:.1f}" y="{height - 12}" text-anchor="{anchor}">{esc(label)}</text>'
            )
    for order, entry in enumerate(series):
        values = entry["values"]
        coordinates = " ".join(f"{x:.1f},{y:.1f}" for x, y in (point(i, v) for i, v in enumerate(values)))
        parts.append(f'<g class="s{order % 4}">')
        parts.append(f'<polyline points="{coordinates}"/>')
        if len(labels) <= 120:
            for index, value in enumerate(values):
                x, y = point(index, value)
                title = f'{labels[index]} {entry["label"]}: {value}{unit}'
                parts.append(
                    f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3"><title>{esc(title)}</title></circle>'
                )
        parts.append("</g>")
    parts.append("</svg>")
    return "".join(parts)


def chart_legend(series: Sequence) -> str:
    items = "".join(
        f'<span class="legend-item s{order % 4}"><span class="swatch"></span>'
        f"{esc(entry['label'])}</span>"
        for order, entry in enumerate(series)
    )
    return f'<div class="legend">{items}</div>'


def chart_block(title: str, labels: Sequence, series: Sequence, unit: str = "") -> str:
    chart = line_chart(labels, series, unit)
    if not chart:
        return ""
    return f"<h3>{esc(title)}</h3>{chart_legend(series)}{chart}"


# ---------------------------------------------------------------------------
# Static site rendering
# ---------------------------------------------------------------------------

# The result tree is pushed to GitHub daily and served by Pages, so the site has
# to be self-contained: no CDN, no build step, readable in light and dark.
SITE_CSS = """
:root {
  color-scheme: light dark;
  --bg: #ffffff; --fg: #1a1c20; --muted: #5c6370; --line: #d8dce3;
  --card: #f6f7f9; --accent: #1f6feb; --warn: #b3541e; --ok: #1a7f37;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0d1117; --fg: #e6edf3; --muted: #9198a1; --line: #30363d;
    --card: #161b22; --accent: #58a6ff; --warn: #d29922; --ok: #3fb950;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 2rem 1.25rem 4rem; background: var(--bg); color: var(--fg);
  font: 15px/1.65 -apple-system, BlinkMacSystemFont, "Segoe UI", "Hiragino Sans",
    "Noto Sans JP", Meiryo, sans-serif;
}
main { max-width: 1100px; margin: 0 auto; }
h1 { font-size: 1.6rem; margin: 0 0 .25rem; }
h2 { font-size: 1.25rem; margin: 2.5rem 0 .75rem; padding-bottom: .35rem;
     border-bottom: 1px solid var(--line); }
h3 { font-size: 1rem; margin: 1.75rem 0 .5rem; color: var(--muted); }
a { color: var(--accent); }
code, .mono { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: .92em; }
.sub { color: var(--muted); margin: 0 0 1.5rem; font-size: .9rem; }
nav { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 1.5rem; font-size: .9rem; }
.cards { display: grid; gap: .75rem; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
         margin: 1rem 0 .5rem; }
.card { background: var(--card); border: 1px solid var(--line); border-radius: 8px; padding: .8rem .9rem; }
.card .label { color: var(--muted); font-size: .78rem; letter-spacing: .04em; }
.card .value { font-size: 1.5rem; font-weight: 600; margin-top: .15rem; }
.scroll { overflow-x: auto; -webkit-overflow-scrolling: touch; }
table { border-collapse: collapse; width: 100%; font-size: .9rem; }
th, td { text-align: left; padding: .45rem .6rem; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--muted); font-weight: 600; white-space: nowrap; }
tbody tr:hover { background: var(--card); }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
.warn { color: var(--warn); font-weight: 600; }
.empty { color: var(--muted); font-style: italic; }
.note { background: var(--card); border-left: 3px solid var(--accent); padding: .75rem 1rem;
        border-radius: 0 6px 6px 0; margin: 1rem 0; font-size: .88rem; }
.trend { width: 100%; height: 160px; }
.trend rect { fill: var(--accent); }
.trend text { fill: var(--muted); font-size: 10px; }
.chart { width: 100%; height: auto; margin: .25rem 0 1rem; }
.chart text { fill: var(--muted); font-size: 11px; }
.chart .grid { stroke: var(--line); stroke-width: 1; }
.chart polyline { fill: none; stroke: currentColor; stroke-width: 2;
                  stroke-linejoin: round; stroke-linecap: round; }
.chart circle { fill: currentColor; }
.s0 { color: var(--accent); }
.s1 { color: var(--ok); }
.s2 { color: var(--warn); }
.s3 { color: #a371f7; }
.legend { display: flex; gap: 1rem; flex-wrap: wrap; font-size: .82rem; color: var(--muted); }
.legend-item { display: inline-flex; align-items: center; gap: .35rem; }
.legend .swatch { width: .8rem; height: .2rem; border-radius: 2px; background: currentColor; }
.filter { width: 100%; padding: .5rem .7rem; margin: .5rem 0 .75rem; border-radius: 6px;
          border: 1px solid var(--line); background: var(--bg); color: var(--fg); font: inherit; }
footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--line);
         color: var(--muted); font-size: .82rem; }
"""

HOST_TABLE_LIMIT = 500

# Copy boxes and table filters are the two things that make the pages usable for
# analysis, and both work without any external library.
SITE_SCRIPT = """<script>
(function () {
  function activate(box) {
    var holder = box.querySelector(".copydata");
    var area = box.querySelector("textarea");
    var count = box.querySelector(".count");
    var tabs = box.querySelectorAll(".tab");
    var data = {};
    try { data = JSON.parse(holder.textContent); } catch (error) { return; }
    function show(variant) {
      var lines = data[variant] || [];
      area.value = lines.join("\\n");
      count.textContent = lines.length.toLocaleString() + " 件";
      Array.prototype.forEach.call(tabs, function (tab) {
        tab.classList.toggle("is-active", tab.dataset.variant === variant);
      });
    }
    Array.prototype.forEach.call(tabs, function (tab) {
      tab.addEventListener("click", function () { show(tab.dataset.variant); });
    });
    area.addEventListener("focus", function () { area.select(); });
    var button = box.querySelector(".copy");
    button.addEventListener("click", function () {
      area.select();
      var done = function () {
        var original = button.textContent;
        button.textContent = "コピーしました";
        button.classList.add("is-done");
        setTimeout(function () {
          button.textContent = original;
          button.classList.remove("is-done");
        }, 1500);
      };
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(area.value).then(done, function () {
          document.execCommand("copy");
          done();
        });
      } else {
        document.execCommand("copy");
        done();
      }
    });
    show(tabs.length ? tabs[0].dataset.variant : Object.keys(data)[0]);
  }
  Array.prototype.forEach.call(document.querySelectorAll("[data-copybox]"), activate);

  Array.prototype.forEach.call(document.querySelectorAll("[data-filter]"), function (input) {
    var table = document.getElementById(input.dataset.filter);
    if (!table) { return; }
    var rows = Array.prototype.slice.call(table.tBodies[0].rows);
    var status = document.getElementById(input.dataset.filter + "-count");
    function apply() {
      var needle = input.value.trim().toLowerCase();
      var shown = 0;
      rows.forEach(function (row) {
        var hit = !needle || row.textContent.toLowerCase().indexOf(needle) !== -1;
        row.style.display = hit ? "" : "none";
        if (hit) { shown += 1; }
      });
      if (status) {
        status.textContent = shown === rows.length
          ? rows.length.toLocaleString() + " 件"
          : shown.toLocaleString() + " / " + rows.length.toLocaleString() + " 件";
      }
    }
    input.addEventListener("input", apply);
    apply();
  });
})();
</script>"""

EXTRA_CSS = """
.copybox { border: 1px solid var(--line); border-radius: 8px; background: var(--card);
           margin: 1rem 0 1.5rem; overflow: hidden; }
.copybar { display: flex; align-items: center; gap: .75rem; flex-wrap: wrap;
           padding: .5rem .65rem; border-bottom: 1px solid var(--line); }
.tabs { display: flex; gap: .25rem; }
.tab { font: inherit; font-size: .82rem; padding: .25rem .6rem; border-radius: 5px;
       border: 1px solid transparent; background: transparent; color: var(--muted); cursor: pointer; }
.tab:hover { color: var(--fg); }
.tab.is-active { background: var(--bg); border-color: var(--line); color: var(--fg); font-weight: 600; }
.copybar .count { color: var(--muted); font-size: .8rem; margin-left: auto; }
.copy { font: inherit; font-size: .82rem; padding: .3rem .8rem; border-radius: 5px;
        border: 1px solid var(--line); background: var(--bg); color: var(--fg); cursor: pointer; }
.copy:hover { border-color: var(--accent); color: var(--accent); }
.copy.is-done { border-color: var(--ok); color: var(--ok); }
.copybox textarea { display: block; width: 100%; border: 0; resize: vertical; padding: .65rem;
                    background: transparent; color: var(--fg); font-family: ui-monospace,
                    SFMono-Regular, Consolas, monospace; font-size: .82rem; line-height: 1.5; }
.copybox textarea:focus { outline: none; }
.toc { display: flex; gap: .4rem; flex-wrap: wrap; margin: 0 0 1.5rem; }
.toc a { font-size: .82rem; padding: .25rem .65rem; border: 1px solid var(--line);
         border-radius: 999px; text-decoration: none; color: var(--muted); }
.toc a:hover { border-color: var(--accent); color: var(--accent); }
.filterbar { display: flex; align-items: center; gap: .75rem; margin: .5rem 0 .75rem; }
.filterbar .count { color: var(--muted); font-size: .8rem; white-space: nowrap; }
.downloads { font-size: .85rem; color: var(--muted); }
.downloads a { margin-right: .75rem; }
"""


def copy_box(variants: Sequence, rows: int = 10) -> str:
    """A selectable, copyable list. `variants` is [(key, label, lines), ...]."""
    variants = [v for v in variants if v[2]]
    if not variants:
        return '<p class="empty">該当なし</p>'
    payload = json.dumps(
        {key: list(lines) for key, _, lines in variants}, ensure_ascii=False
    ).replace("<", "\\u003c")
    tabs = "".join(
        f'<button type="button" class="tab" data-variant="{esc(key)}">{esc(label)}</button>'
        for key, label, _ in variants
    )
    return (
        '<div class="copybox" data-copybox>'
        f'<div class="copybar"><div class="tabs">{tabs}</div>'
        '<span class="count"></span>'
        '<button type="button" class="copy">コピー</button></div>'
        f'<textarea readonly rows="{rows}" spellcheck="false"></textarea>'
        f'<script type="application/json" class="copydata">{payload}</script>'
        "</div>"
    )


def filter_bar(table_id: str, placeholder: str) -> str:
    return (
        f'<div class="filterbar"><input class="filter" type="search" '
        f'data-filter="{esc(table_id)}" placeholder="{esc(placeholder)}" '
        f'aria-label="{esc(placeholder)}">'
        f'<span class="count" id="{esc(table_id)}-count"></span></div>'
    )


def table_with_id(markup: str, table_id: str) -> str:
    return markup.replace("<table>", f'<table id="{esc(table_id)}">', 1)


def toc(items: Sequence) -> str:
    links = "".join(html_link(f"#{anchor}", label) for anchor, label in items)
    return f'<div class="toc">{links}</div>'


def section_heading(level: str, anchor: str, label: str) -> str:
    return f'<{level} id="{esc(anchor)}">{esc(label)}</{level}>'


DISCLAIMER = (
    "fingerprintの一致はプロトコル応答の一致であり、特定の攻撃者・キャンペーンへの"
    "帰属を意味しません。掲載内容はすべて観測事実の集計です。"
)


def esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def html_page(title: str, body: str, generated: str) -> str:
    return (
        "<!doctype html>\n"
        '<html lang="ja">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        '<meta name="robots" content="noindex">\n'
        f"<title>{esc(title)}</title>\n"
        f"<style>{SITE_CSS}{EXTRA_CSS}</style>\n</head>\n<body>\n<main>\n"
        f"{body}\n"
        f'<footer>\n<p>{esc(DISCLAIMER)}</p>\n'
        f"<p>生成: {esc(generated)} / c2probe summarize_results.py</p>\n</footer>\n"
        "</main>\n</body>\n</html>\n"
    )


def html_table(headers: Sequence, rows: Sequence, numeric: Sequence = ()) -> str:
    """Render a table. Cells are escaped, so callers pass text and never markup."""
    if not rows:
        return '<p class="empty">該当なし</p>'
    head = "".join(
        f'<th class="num">{esc(h)}</th>' if index in numeric else f"<th>{esc(h)}</th>"
        for index, h in enumerate(headers)
    )
    body = []
    for row in rows:
        cells = "".join(
            f'<td class="num">{esc(cell)}</td>' if index in numeric else f"<td>{esc(cell)}</td>"
            for index, cell in enumerate(row)
        )
        body.append(f"<tr>{cells}</tr>")
    return (
        '<div class="scroll"><table><thead><tr>'
        + head
        + "</tr></thead><tbody>"
        + "".join(body)
        + "</tbody></table></div>"
    )


def html_link(href: str, text: str) -> str:
    return f'<a href="{esc(href)}">{esc(text)}</a>'


def html_table_with_links(
    headers: Sequence, rows: Sequence, link_column: int, numeric: Sequence = ()
) -> str:
    """Same as html_table, but one column holds (href, text) pairs."""
    if not rows:
        return '<p class="empty">該当なし</p>'
    head = "".join(
        f'<th class="num">{esc(h)}</th>' if index in numeric else f"<th>{esc(h)}</th>"
        for index, h in enumerate(headers)
    )
    body = []
    for row in rows:
        cells = []
        for index, cell in enumerate(row):
            if index == link_column:
                href, label = cell
                cells.append(f"<td>{html_link(href, label)}</td>")
            elif index in numeric:
                cells.append(f'<td class="num">{esc(cell)}</td>')
            else:
                cells.append(f"<td>{esc(cell)}</td>")
        body.append("<tr>" + "".join(cells) + "</tr>")
    return (
        '<div class="scroll"><table><thead><tr>'
        + head
        + "</tr></thead><tbody>"
        + "".join(body)
        + "</tbody></table></div>"
    )


def html_cards(pairs: Sequence) -> str:
    cards = "".join(
        f'<div class="card"><div class="label">{esc(label)}</div>'
        f'<div class="value">{esc(value)}</div></div>'
        for label, value in pairs
    )
    return f'<div class="cards">{cards}</div>'


def html_probe_section(summary: dict, top: int) -> str:
    parts = [f'<h2>probe: <code>{esc(summary["probe_directory"])}</code></h2>']
    parts.append(
        html_cards(
            [
                ("検出", f"{summary['records']:,}"),
                ("ホスト", f"{summary['hosts']:,}"),
                ("IP:PORT", f"{summary['endpoints']:,}"),
                ("confirmed", f"{summary['confirmed']:,}"),
            ]
        )
    )
    overview = [
        ["confirmed / unconfirmed", f"{summary['confirmed']} / {summary['unconfirmed']}"],
        ["ファイル（検出あり）", f"{summary['files']} ({summary['files_with_hits']})"],
    ]
    if summary["confidence"]:
        overview.append(["confidence", ", ".join(f"{v:g}" for v in summary["confidence"])])
    if summary["duration_ms"]:
        stats = summary["duration_ms"]
        overview.append(
            ["probe所要時間", f"最小{stats['min']} / 平均{stats['mean']:.0f} / 最大{stats['max']} ms"]
        )
    if summary["syn_rtt_ms"]:
        stats = summary["syn_rtt_ms"]
        overview.append(["SYN RTT", f"最小{stats['min']} / 最大{stats['max']} ms"])
        overview.append(["RTT記録率", f"{summary['records_with_rtt']} / {summary['records']}"])
        if summary["syn_rtt_resolution_ms"]:
            overview.append(["RTT量子化", f"{summary['syn_rtt_resolution_ms']} ms刻み"])
    if summary["first_seen"]:
        overview.append(["走査時間帯", f"{summary['first_seen']} - {summary['last_seen']}"])
    parts.append(html_table(["項目", "値"], overview))

    parts.append("<h3>probe / status内訳</h3>")
    parts.append(html_table(["probe", "件数"], summary["by_probe"], numeric=(1,)))
    if summary["by_status"]:
        parts.append(html_table(["status", "件数"], summary["by_status"], numeric=(1,)))

    parts.append("<h3>レンジ別</h3>")
    with_hits = sorted(
        (row for row in summary["per_file"] if row["records"]), key=lambda r: -r["records"]
    )
    parts.append(
        html_table_with_links(
            ["ファイル", "宣言CIDR", "検出", "ホスト"],
            [
                [
                    (f"{summary['probe_directory']}/{row['file']}", row["file"]),
                    row["declared_cidr"] or "-",
                    row["records"],
                    row["hosts"],
                ]
                for row in with_hits
            ],
            link_column=0,
            numeric=(2, 3),
        )
    )
    empty = [row["file"] for row in summary["per_file"] if not row["records"]]
    if empty:
        parts.append(f'<p class="empty">検出0件: {len(empty)}ファイル</p>')

    parts.append("<h3>ネットワーク集中度</h3>")
    hosts_per_network = summary["hosts_per_network"]
    parts.append(
        html_table(
            ["ネットワーク", "検出", "ホスト"],
            [
                [network, count, hosts_per_network.get(network, 0)]
                for network, count in summary["networks"][:top]
            ],
            numeric=(1, 2),
        )
    )

    parts.append("<h3>ポート</h3>")
    parts.append(html_table(["ポート", "件数"], summary["ports"][:top], numeric=(0, 1)))

    parts.append("<h3>ポート構成が一致するホスト群</h3>")
    parts.append(
        '<p class="sub">同一のポート集合を持つホストは、同じ構成テンプレートで'
        "展開された可能性がある。</p>"
    )
    parts.append(
        html_table(
            ["ホスト数", "ポート集合", "ホスト"],
            [
                [
                    len(cluster["hosts"]),
                    ", ".join(str(port) for port in cluster["ports"]),
                    ", ".join(str(host) for host in cluster["hosts"]),
                ]
                for cluster in summary["clusters"]
            ],
            numeric=(0,),
        )
    )

    if summary["fields"]:
        parts.append("<h3>probe固有フィールド</h3>")
        parts.append(
            html_table(
                ["フィールド", "観測数", "値"],
                [[r["field"], r["observations"], r["values"]] for r in summary["fields"]],
                numeric=(1,),
            )
        )

    integrity = summary["integrity"]
    parts.append("<h3>品質チェック</h3>")
    checks = [
        [
            "JSON parse",
            "全行成功" if not integrity["malformed_lines"] else f"{integrity['malformed_lines']}行が破損",
        ],
        [
            "ファイル末尾",
            "全ファイルが改行終端"
            if not integrity["truncated_files"]
            else "切断の疑い: " + ", ".join(integrity["truncated_files"]),
        ],
        [
            "CIDR整合",
            "全レコードが宣言レンジ内"
            if not integrity["out_of_range"]
            else f"{integrity['out_of_range']}件が範囲外",
        ],
        [
            "IP:PORT重複",
            "なし"
            if not summary["duplicate_endpoints"]
            else f"{len(summary['duplicate_endpoints'])}件",
        ],
    ]
    parts.append(html_table(["検査", "結果"], checks))
    return "\n".join(parts)


def date_host_rows(summary: dict) -> list:
    """Merge every probe directory's per-host rollup for the date page table."""
    merged: dict = {}
    for section in summary["probes"]:
        for entry in section["hosts_detail"]:
            row = merged.setdefault(
                entry["host"],
                {
                    "host": entry["host"],
                    "ports": set(),
                    "probes": set(),
                    "statuses": set(),
                    "records": 0,
                    "rtt": [],
                },
            )
            row["ports"].update(entry["ports"])
            row["probes"].update(entry["probes"] or [section["probe_directory"]])
            row["statuses"].update(entry["statuses"])
            row["records"] += entry["records"]
            if entry["syn_rtt_ms"] is not None:
                row["rtt"].append(entry["syn_rtt_ms"])
    ordered = sorted(merged.values(), key=lambda r: ipaddress.ip_address(r["host"]))
    return [
        {
            "host": row["host"],
            "ports": sorted(row["ports"]),
            "probes": sorted(row["probes"]),
            "statuses": sorted(row["statuses"]),
            "records": row["records"],
            "syn_rtt_ms": min(row["rtt"]) if row["rtt"] else None,
        }
        for row in ordered
    ]


def date_lists(rows: Sequence) -> list:
    """Copy-ready variants of the day's addresses."""
    ips = [row["host"] for row in rows]
    endpoints = [
        format_endpoint(ipaddress.ip_address(row["host"]), port)
        for row in rows
        for port in row["ports"]
    ]
    networks = sorted({str(group_network(ipaddress.ip_address(ip))) for ip in ips})
    return [
        ("ip", "IPのみ", ips),
        ("endpoint", "IP:PORT", endpoints),
        ("network", "ネットワーク", networks),
        ("csv", "CSV", ["host,ports,probes"]
            + [
                f'{row["host"]},{" ".join(str(p) for p in row["ports"])},'
                f'{" ".join(row["probes"])}'
                for row in rows
            ]),
    ]


def render_html_date(
    summary: dict,
    comparison: Optional[dict],
    top: int,
    previous: Optional[str],
    following: Optional[str],
) -> str:
    totals = summary["totals"]
    rows = date_host_rows(summary)
    nav = [html_link("../index.html", "← 全体")]
    if previous:
        nav.append(html_link(f"../{previous}/index.html", f"前日 {previous}"))
    if following:
        nav.append(html_link(f"../{following}/index.html", f"翌日 {following}"))
    parts = [
        "<nav>" + "".join(nav) + "</nav>",
        f'<h1>スキャン結果 {esc(summary["date"])}</h1>',
        f'<p class="sub">{esc(summary["source"])}</p>',
        html_cards(
            [
                ("probe", totals["probe_directories"]),
                ("検出", f"{totals['records']:,}"),
                ("ホスト", f"{totals['hosts']:,}"),
                ("confirmed", f"{totals['confirmed']:,}"),
                ("整合性の問題", totals["defects"]),
            ]
        ),
    ]
    anchors = [("addresses", "アドレス一覧"), ("hosts", "ホスト")]
    if comparison:
        anchors.append(("delta", "前日差分"))
    anchors += [
        (f'probe-{index}', section["probe_directory"])
        for index, section in enumerate(summary["probes"])
    ]
    parts.append(toc(anchors))
    if totals["defects"]:
        parts.append(
            '<p class="note"><span class="warn">整合性の問題が検出されています。</span>'
            "各probeの品質チェックを確認してください。</p>"
        )

    parts.append(section_heading("h2", "addresses", "アドレス一覧"))
    parts.append(
        '<p class="sub">ブロックリストや別ツールへ渡すための一覧。形式を選んでコピーできます。</p>'
    )
    parts.append(copy_box(date_lists(rows), rows=12))
    parts.append(
        '<p class="downloads">ファイル: '
        + html_link("hosts.txt", "hosts.txt")
        + html_link("endpoints.txt", "endpoints.txt")
        + html_link("hosts.csv", "hosts.csv")
        + "</p>"
    )

    parts.append(section_heading("h2", "hosts", "ホスト"))
    parts.append(filter_bar("date-hosts", "IP、ポート、probe、statusで絞り込み"))
    parts.append(
        table_with_id(
            html_table(
                ["ホスト", "ポート", "probe", "status", "検出", "RTT"],
                [
                    [
                        row["host"],
                        ", ".join(str(port) for port in row["ports"]),
                        ", ".join(row["probes"]),
                        ", ".join(row["statuses"]),
                        row["records"],
                        f'{row["syn_rtt_ms"]} ms' if row["syn_rtt_ms"] is not None else "-",
                    ]
                    for row in rows
                ],
                numeric=(4,),
            ),
            "date-hosts",
        )
    )

    if summary["multi_probe_hosts"]:
        parts.append("<h3>複数probeで検出されたホスト</h3>")
        parts.append(
            html_table(
                ["ホスト", "probe"],
                [
                    [row["host"], ", ".join(row["probes"])]
                    for row in summary["multi_probe_hosts"][:top]
                ],
            )
        )

    if comparison:
        parts.append(
            section_heading(
                "h2", "delta", f'前日 {comparison.get("previous_date", "")} との差分'
            )
        )
        parts.append(
            html_table(
                ["probe", "新規ホスト", "消失ホスト", "新規IP:PORT", "消失IP:PORT"],
                [
                    [
                        delta["probe_directory"],
                        len(delta["new_hosts"]),
                        len(delta["gone_hosts"]),
                        len(delta["new_endpoints"]),
                        len(delta["gone_endpoints"]),
                    ]
                    for delta in comparison["deltas"]
                ],
                numeric=(1, 2, 3, 4),
            )
        )
        new_hosts = sorted(
            {host for delta in comparison["deltas"] for host in delta["new_hosts"]},
            key=ipaddress.ip_address,
        )
        gone_hosts = sorted(
            {host for delta in comparison["deltas"] for host in delta["gone_hosts"]},
            key=ipaddress.ip_address,
        )
        if new_hosts or gone_hosts:
            parts.append("<h3>新規・消失ホスト</h3>")
            parts.append(
                copy_box(
                    [("new", f"新規 ({len(new_hosts)})", new_hosts),
                     ("gone", f"消失 ({len(gone_hosts)})", gone_hosts)],
                    rows=8,
                )
            )

    for index, section in enumerate(summary["probes"]):
        parts.append(f'<div id="probe-{index}"></div>')
        parts.append(html_probe_section(section, top))

    parts.append(
        '<p class="note">この日のJSONL原本は同じディレクトリに置かれています。'
        "<code>--output-mode matched</code>の出力には母数（open port数、応答したが"
        "一致しなかった件数）が含まれません。</p>"
    )
    parts.append(SITE_SCRIPT)
    return html_page(
        f"スキャン結果 {summary['date']}", "\n".join(parts), summary["generated_at"]
    )


def render_html_index(
    overview: dict, entries: Sequence, generated: str, top: int
) -> str:
    """The overall page: cross-date trends and the host index."""
    tables = overview_tables(overview, top)
    hosts = overview["hosts"]
    latest = overview["latest"]
    days = overview["per_date"]
    active = [h for h in hosts.values() if h["active"]]
    parts = [
        "<h1>c2probe スキャン結果</h1>",
        '<p class="sub">日次スキャンの全期間集計。個々の日付の詳細は日別ページを参照。</p>',
    ]
    if not days:
        return html_page("c2probe スキャン結果", "\n".join(parts), generated)

    today = days[-1]
    parts.append(
        html_cards(
            [
                ("最新スキャン", latest),
                ("継続中ホスト", f"{len(active):,}"),
                ("累計ホスト", f"{len(hosts):,}"),
                ("最新日の初回検出", f"{len(today['first_seen_hosts']):,}"),
                ("最新日の再出現", f"{len(today['returning_hosts']):,}"),
                ("最新日の消失", f"{len(today['gone_hosts']):,}"),
                ("記録日数", len(days)),
            ]
        )
    )

    labels = [day["date"] for day in days]
    parts.append("<h2>推移</h2>")
    parts.append(
        chart_block(
            "ホスト数（検出 / 初回 / 再出現 / 消失）",
            labels,
            [
                {"label": "検出ホスト", "values": [day["hosts"] for day in days]},
                {"label": "初回検出", "values": [len(day["first_seen_hosts"]) for day in days]},
                {"label": "再出現", "values": [len(day["returning_hosts"]) for day in days]},
                {"label": "消失", "values": [len(day["gone_hosts"]) for day in days]},
            ],
        )
    )
    parts.append(
        chart_block(
            "検出レコード数",
            labels,
            [{"label": "検出レコード", "values": [day["records"] for day in days]}],
        )
    )
    if len(overview["probe_names"]) > 1:
        parts.append(
            chart_block(
                "probe別ホスト数",
                labels,
                [
                    {
                        "label": name,
                        "values": [len(day["probe_hosts"].get(name, ())) for day in days],
                    }
                    for name in overview["probe_names"]
                ],
            )
        )
    if len(days) < 2:
        parts.append(
            '<p class="empty">推移グラフは2日分以上のスキャンが揃うと表示されます。</p>'
        )
    elif days[0]["first_seen_hosts"]:
        parts.append(
            '<p class="sub">初回スキャン日は全ホストが初回検出になるため、'
            "グラフの左端だけ値が突出します。</p>"
        )

    parts.append(f"<h2>最新日({esc(latest)})の新規ホスト</h2>")
    if today["baseline"]:
        parts.append(
            '<p class="note">これが最初のスキャン日のため、全ホストを新規として扱っています。</p>'
        )
    parts.append(html_table(HOST_HEADERS, host_rows(tables["new_today"])))
    parts.append(
        copy_box(
            [
                ("new", f"新規 ({len(tables['new_today'])})",
                 [h["host"] for h in tables["new_today"]]),
                ("active", f"継続中の全ホスト ({len(active)})",
                 [h["host"] for h in sorted(active, key=lambda x: x["sort_key"])]),
                ("all", f"累計の全ホスト ({len(hosts)})",
                 [h["host"] for h in sorted(hosts.values(), key=lambda x: x["sort_key"])]),
            ],
            rows=8,
        )
    )

    if today["returning_hosts"]:
        parts.append(f"<h2>最新日({esc(latest)})の再出現ホスト</h2>")
        parts.append(
            '<p class="sub">過去に観測され、前日は検出されず、再び現れたホスト。'
            "停止と再開、または断続的な稼働を示す。</p>"
        )
        parts.append(
            html_table(
                HOST_HEADERS,
                host_rows([hosts[h] for h in today["returning_hosts"]]),
            )
        )
        parts.append(
            copy_box(
                [("returning", f"再出現 ({len(today['returning_hosts'])})",
                  today["returning_hosts"])],
                rows=6,
            )
        )

    parts.append("<h2>消失したホスト</h2>")
    parts.append(
        '<p class="sub">最終検出日が最新スキャン日より前のホスト。停止、移設、'
        "または検出条件から外れたことを示す。</p>"
    )
    parts.append(html_table(HOST_HEADERS, host_rows(tables["gone"][:top])))
    if len(tables["gone"]) > top:
        parts.append(f'<p class="empty">ほか{len(tables["gone"]) - top}件（hosts.csvに全件）</p>')

    if len(days) > 1:
        parts.append("<h2>継続と間欠</h2>")
        parts.append('<p class="sub">観測日数が多いホストほど安定した基盤。</p>')
        parts.append(html_table(HOST_HEADERS, host_rows(tables["persistent"])))
        if tables["intermittent"]:
            parts.append("<h3>間欠的に現れるホスト</h3>")
            parts.append(
                '<p class="sub">初回検出以降、観測できない日があるホスト。'
                "稼働時間帯が限られる、または不安定な基盤。</p>"
            )
            parts.append(
                html_table(
                    HOST_HEADERS + ["観測日 / 期間"],
                    [
                        row + [f"{entry['days_observed']} / {entry['span']}日"]
                        for row, entry in zip(
                            host_rows(tables["intermittent"]), tables["intermittent"]
                        )
                    ],
                )
            )

    parts.append("<h2>全期間の集中度</h2>")
    network_hosts = tables["network_hosts"]
    parts.append(
        html_table(
            ["ネットワーク", "累計ホスト", "継続中", "ホスト"],
            [
                [
                    network,
                    count,
                    sum(1 for h in network_hosts[network] if hosts[h]["active"]),
                    preview(sorted(network_hosts[network], key=lambda h: hosts[h]["sort_key"]), 12),
                ]
                for network, count in tables["networks"]
            ],
            numeric=(1, 2),
        )
    )

    parts.append("<h3>ポート</h3>")
    parts.append(
        html_table(
            ["ポート", "累計ホスト"], tables["ports"], numeric=(0, 1)
        )
    )

    parts.append("<h2>日別</h2>")
    meta = {entry["date"]: entry for entry in entries}
    parts.append(
        html_table_with_links(
            ["日付", "probe", "検出", "ホスト", "初回", "再出現", "消失", "問題"],
            [
                [
                    (f"{day['date']}/index.html", day["date"]),
                    ", ".join(meta.get(day["date"], {}).get("probe_directories", [])) or "-",
                    day["records"],
                    day["hosts"],
                    len(day["first_seen_hosts"]),
                    len(day["returning_hosts"]),
                    len(day["gone_hosts"]),
                    meta.get(day["date"], {}).get("defects") or "",
                ]
                for day in reversed(days)
            ],
            link_column=0,
            numeric=(2, 3, 4, 5, 6, 7),
        )
    )

    parts.append("<h2>ホスト一覧</h2>")
    parts.append(
        '<p class="sub">初回検出が新しい順。表の上の入力欄でIP、ポート、probe、'
        "状態を絞り込めます。</p>"
    )
    parts.append(filter_bar("host-table", "例: 143.92 / 8888 / valleyrat / 消失"))
    listed = tables["by_first_seen"][:HOST_TABLE_LIMIT]
    parts.append(table_with_id(html_table(HOST_HEADERS, host_rows(listed)), "host-table"))
    if len(tables["by_first_seen"]) > HOST_TABLE_LIMIT:
        parts.append(
            f'<p class="empty">{len(tables["by_first_seen"]):,}件中'
            f"{HOST_TABLE_LIMIT:,}件を表示。全件は hosts.csv を参照。</p>"
        )
    parts.append(
        '<p class="note">分析用の書き出し: '
        + html_link("hosts.csv", "hosts.csv")
        + "（ホスト単位の初回・最終・観測日数・ポート） / "
        + html_link("overview.json", "overview.json")
        + "（日別の新規・消失を含む全期間データ）</p>"
    )
    parts.append(SITE_SCRIPT)
    return html_page("c2probe スキャン結果", "\n".join(parts), generated)


def write_lines(path: Path, lines: Sequence) -> None:
    """Write one item per line, always with a trailing newline."""
    body = chr(10).join(str(line) for line in lines)
    path.write_text(body + chr(10) if body else body, encoding='utf-8')


def write_date_exports(date_directory: Path, summary: dict) -> None:
    """Plain lists next to the JSONL, for blocklists and other tooling."""
    rows = date_host_rows(summary)
    write_lines(date_directory / "hosts.txt", [row["host"] for row in rows])
    write_lines(
        date_directory / "endpoints.txt",
        [
            format_endpoint(ipaddress.ip_address(row["host"]), port)
            for row in rows
            for port in row["ports"]
        ],
    )
    with (date_directory / "hosts.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["host", "ports", "probes", "statuses", "records", "syn_rtt_ms"])
        for row in rows:
            writer.writerow(
                [
                    row["host"],
                    " ".join(str(port) for port in row["ports"]),
                    " ".join(row["probes"]),
                    " ".join(row["statuses"]),
                    row["records"],
                    "" if row["syn_rtt_ms"] is None else row["syn_rtt_ms"],
                ]
            )


def build_site(root: Path, dates: Sequence, top: int, minimum_cluster: int) -> int:
    """Render one page per date plus the index. Returns the total defect count."""
    generated = datetime.now(timezone.utc).isoformat(timespec="seconds")
    entries = []
    summaries = []
    defects = 0
    for index, date_directory in enumerate(dates):
        summary = summarise_date(date_directory, minimum_cluster)
        defects += summary["totals"]["defects"]
        comparison = None
        if index:
            comparison = compare_sections(
                load_probe_sections(date_directory), load_probe_sections(dates[index - 1])
            )
            comparison["previous_date"] = dates[index - 1].name
        summaries.append((date_directory, summary, comparison))
        entries.append(
            {
                "date": date_directory.name,
                "records": summary["totals"]["records"],
                "hosts": summary["totals"]["hosts"],
                "defects": summary["totals"]["defects"],
                "probe_directories": [s["probe_directory"] for s in summary["probes"]],
                "new_hosts": sum(len(d["new_hosts"]) for d in comparison["deltas"])
                if comparison
                else 0,
                "gone_hosts": sum(len(d["gone_hosts"]) for d in comparison["deltas"])
                if comparison
                else 0,
            }
        )
    for index, (date_directory, summary, comparison) in enumerate(summaries):
        previous = dates[index - 1].name if index else None
        following = dates[index + 1].name if index + 1 < len(dates) else None
        emit(
            render_html_date(summary, comparison, top, previous, following),
            date_directory / "index.html",
        )
        emit(render_markdown(summary, comparison, top), date_directory / "SUMMARY.md")
        write_date_exports(date_directory, summary)
        emit(
            json.dumps(
                json_ready({"summary": summary, "comparison": comparison}),
                indent=2,
                ensure_ascii=False,
            ),
            date_directory / "SUMMARY.json",
        )
    overview = build_overview(dates)
    emit(render_html_index(overview, entries, generated, top), root / "index.html")
    write_exports(root, overview)
    # Without this, Pages hands the tree to Jekyll before publishing it.
    (root / ".nojekyll").write_text("", encoding="utf-8")
    return defects


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
    parser.add_argument("--format", choices=("markdown", "json", "html"), default="markdown")
    parser.add_argument(
        "--site",
        action="store_true",
        help="build the GitHub Pages site: index.html plus a page, SUMMARY.md and "
        "SUMMARY.json per date. Covers every date unless one is named.",
    )
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
    if arguments.site and arguments.output:
        parser.error("--site writes into the result tree; --output does not apply")
    if arguments.site and arguments.format != "markdown":
        parser.error("--site always writes html, markdown and json together")
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
    if arguments.site:
        # A named date still rebuilds the index, because the index lists every day
        # and its trend would otherwise go stale.
        dates = available_dates(arguments.root)
        if arguments.date:
            wanted = arguments.root / arguments.date
            if not wanted.is_dir():
                raise SystemExit(f"{wanted} not found")
            dates = [d for d in dates if d.name <= wanted.name]
        defects = build_site(arguments.root, dates, arguments.top, arguments.min_cluster)
        if arguments.strict and defects:
            print(f"{defects} integrity problem(s) found", file=sys.stderr)
            return 1
        return 0
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
        elif arguments.format == "html":
            text = render_html_date(summary, comparison, arguments.top, None, None)
            default_name = "index.html"
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
