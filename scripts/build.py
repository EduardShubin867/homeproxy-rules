#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.request
from collections import defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DOMAIN_FIELDS = (
    "domain",
    "domain_suffix",
    "domain_keyword",
    "domain_regex",
)
ADDRESS_FIELDS = DOMAIN_FIELDS + ("ip_cidr",)
ALLOWED_DEFAULT_KEYS = set(ADDRESS_FIELDS) | {"type", "invert"}


class BuildError(RuntimeError):
    pass


def run(command: list[str]) -> None:
    print("+", " ".join(command), flush=True)
    subprocess.run(command, check=True)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(url: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "homeproxy-rules-builder/2.0"},
    )

    print(f"Downloading {url}")
    with urllib.request.urlopen(request, timeout=120) as response:
        content = response.read()

    if len(content) < 4 or not content.startswith(b"SRS"):
        raise BuildError(
            f"{url} did not return a valid SRS file "
            f"(size={len(content)}, prefix={content[:16]!r})"
        )

    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_bytes(content)
    temporary.replace(destination)


def values_as_list(value: Any, field: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    raise BuildError(f"Unsupported value in {field}: {value!r}")


def collect_rule(
    rule: dict[str, Any],
    values: dict[str, set[str]],
    source: str,
) -> None:
    rule_type = rule.get("type", "default")

    if rule_type == "logical":
        mode = rule.get("mode")
        invert = bool(rule.get("invert", False))
        nested = rule.get("rules")

        # Geo rule sets are expected to be unions of address conditions.
        # Reject anything more complex instead of changing its semantics.
        if mode != "or" or invert or not isinstance(nested, list):
            raise BuildError(
                f"{source}: unsupported logical rule "
                f"(mode={mode!r}, invert={invert!r})"
            )

        for child in nested:
            if not isinstance(child, dict):
                raise BuildError(f"{source}: logical child is not an object")
            collect_rule(child, values, source)
        return

    if rule_type not in ("default", ""):
        raise BuildError(f"{source}: unsupported rule type {rule_type!r}")

    unknown_keys = set(rule) - ALLOWED_DEFAULT_KEYS
    if unknown_keys:
        raise BuildError(
            f"{source}: unexpected rule fields: {sorted(unknown_keys)}"
        )

    if bool(rule.get("invert", False)):
        raise BuildError(f"{source}: inverted upstream rule is unsupported")

    for field in ADDRESS_FIELDS:
        for value in values_as_list(rule.get(field), field):
            values[field].add(value)


def collect_ruleset(
    path: Path,
    values: dict[str, set[str]],
    source: str,
) -> int:
    payload = json.loads(path.read_text(encoding="utf-8"))
    rules = payload.get("rules")

    if not isinstance(rules, list):
        raise BuildError(f"{source}: rules is not an array")

    before = sum(len(items) for items in values.values())
    for rule in rules:
        if not isinstance(rule, dict):
            raise BuildError(f"{source}: rule is not an object")
        collect_rule(rule, values, source)
    after = sum(len(items) for items in values.values())
    return after - before


def strip_comment(raw_line: str) -> str:
    return raw_line.split("#", 1)[0].strip()


def normalize_hostname(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    if value.startswith("*."):
        value = value[2:]
    if value.startswith("."):
        value = value[1:]

    if not value:
        raise BuildError("Empty domain")
    if "://" in value or "/" in value or ":" in value:
        raise BuildError(
            f"Use a hostname without protocol, port or path: {value!r}"
        )

    try:
        return value.encode("idna").decode("ascii")
    except UnicodeError as error:
        raise BuildError(f"Invalid domain {value!r}") from error


def read_domain_file(path: Path) -> dict[str, set[str]]:
    result: dict[str, set[str]] = defaultdict(set)
    if not path.exists():
        return result

    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        line = strip_comment(raw_line)
        if not line:
            continue

        try:
            if line.startswith("full:"):
                result["domain"].add(normalize_hostname(line[5:]))
            elif line.startswith("domain:"):
                result["domain"].add(normalize_hostname(line[7:]))
            elif line.startswith("suffix:"):
                result["domain_suffix"].add(normalize_hostname(line[7:]))
            elif line.startswith("keyword:"):
                value = line[8:].strip()
                if not value:
                    raise BuildError("Empty keyword")
                result["domain_keyword"].add(value)
            elif line.startswith("regexp:"):
                value = line[7:].strip()
                if not value:
                    raise BuildError("Empty regular expression")
                re.compile(value)
                result["domain_regex"].add(value)
            else:
                result["domain_suffix"].add(normalize_hostname(line))
        except (BuildError, re.error) as error:
            raise BuildError(f"{path}:{line_number}: {error}") from error

    return result


def read_ip_file(path: Path) -> set[str]:
    result: set[str] = set()
    if not path.exists():
        return result

    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        line = strip_comment(raw_line)
        if not line:
            continue

        try:
            network = ipaddress.ip_network(line, strict=False)
        except ValueError as error:
            raise BuildError(
                f"{path}:{line_number}: invalid IP/CIDR {line!r}"
            ) from error

        result.add(str(network))

    return result


def merge_values(
    target: dict[str, set[str]],
    source: dict[str, set[str]],
) -> None:
    for field, items in source.items():
        target[field].update(items)


def make_domain_rule(values: dict[str, set[str]]) -> dict[str, Any]:
    rule: dict[str, Any] = {}
    for field in DOMAIN_FIELDS:
        items = sorted(values.get(field, set()))
        if items:
            rule[field] = items
    return rule


def make_ip_rule(values: dict[str, set[str]]) -> dict[str, Any]:
    items = sorted(values.get("ip_cidr", set()))
    return {"ip_cidr": items} if items else {}


def make_address_branches(
    values: dict[str, set[str]],
) -> list[dict[str, Any]]:
    branches: list[dict[str, Any]] = []
    domain_rule = make_domain_rule(values)
    ip_rule = make_ip_rule(values)

    if domain_rule:
        branches.append(domain_rule)
    if ip_rule:
        branches.append(ip_rule)
    return branches


def as_or_rule(branches: list[dict[str, Any]]) -> dict[str, Any]:
    if not branches:
        raise BuildError("Cannot create an empty match rule")
    if len(branches) == 1:
        return branches[0]
    return {
        "type": "logical",
        "mode": "or",
        "rules": branches,
    }


def invert_rule(rule: dict[str, Any]) -> dict[str, Any]:
    return {**rule, "invert": True}


def build_source(
    include_values: dict[str, set[str]],
    exclude_values: dict[str, set[str]],
) -> dict[str, Any]:
    include_branches = make_address_branches(include_values)
    if not include_branches:
        raise BuildError("The resulting include list is empty")

    exclude_branches = make_address_branches(exclude_values)

    if not exclude_branches:
        # Top-level rule-set entries have OR semantics. Keeping domains and
        # IPs as separate branches avoids forcing an IP lookup on a domain hit.
        rules = include_branches
    else:
        include_match = as_or_rule(include_branches)
        exclude_match = as_or_rule(exclude_branches)
        rules = [
            {
                "type": "logical",
                "mode": "and",
                "rules": [
                    include_match,
                    invert_rule(exclude_match),
                ],
            }
        ]

    return {
        "version": 3,
        "rules": rules,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--sing-box",
        default=os.environ.get("SING_BOX", "sing-box"),
        help="Path to a sing-box 1.12.x binary",
    )
    parser.add_argument(
        "--work-dir",
        type=Path,
        default=ROOT / ".work",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "dist" / "homeproxy.srs",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    sources_path = ROOT / "sources.json"
    sources = json.loads(sources_path.read_text(encoding="utf-8"))

    if not isinstance(sources, list) or not sources:
        raise BuildError("sources.json must contain a non-empty array")

    work_dir: Path = args.work_dir
    downloads_dir = work_dir / "downloads"
    json_dir = work_dir / "json"
    downloads_dir.mkdir(parents=True, exist_ok=True)
    json_dir.mkdir(parents=True, exist_ok=True)

    include_values: dict[str, set[str]] = defaultdict(set)
    source_stats: list[dict[str, Any]] = []

    for source in sources:
        if not isinstance(source, dict):
            raise BuildError("Each source must be an object")

        name = source.get("name")
        url = source.get("url")
        if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9-]+", name):
            raise BuildError(f"Invalid source name: {name!r}")
        if not isinstance(url, str) or not url.startswith("https://"):
            raise BuildError(f"Invalid source URL for {name}")

        srs_path = downloads_dir / f"{name}.srs"
        json_path = json_dir / f"{name}.json"

        download(url, srs_path)
        run([
            args.sing_box,
            "rule-set",
            "decompile",
            "--output",
            str(json_path),
            str(srs_path),
        ])

        added = collect_ruleset(json_path, include_values, name)
        source_stats.append({
            "name": name,
            "sha256": sha256_file(srs_path),
            "unique_items_added": added,
        })

    custom_domains = read_domain_file(ROOT / "custom" / "include-domains.txt")
    custom_ips = read_ip_file(ROOT / "custom" / "include-ips.txt")
    merge_values(include_values, custom_domains)
    include_values["ip_cidr"].update(custom_ips)

    exclude_values: dict[str, set[str]] = defaultdict(set)
    merge_values(
        exclude_values,
        read_domain_file(ROOT / "custom" / "exclude-domains.txt"),
    )
    exclude_values["ip_cidr"].update(
        read_ip_file(ROOT / "custom" / "exclude-ips.txt")
    )

    source_payload = build_source(include_values, exclude_values)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    source_output = work_dir / "homeproxy.json"
    source_output.write_text(
        json.dumps(source_payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    with tempfile.TemporaryDirectory(dir=args.output.parent) as temporary_dir:
        temporary_srs = Path(temporary_dir) / "homeproxy.srs"
        run([
            args.sing_box,
            "rule-set",
            "compile",
            "--output",
            str(temporary_srs),
            str(source_output),
        ])

        verify_json = Path(temporary_dir) / "verify.json"
        run([
            args.sing_box,
            "rule-set",
            "decompile",
            "--output",
            str(verify_json),
            str(temporary_srs),
        ])
        verified_payload = json.loads(verify_json.read_text(encoding="utf-8"))
        if not verified_payload.get("rules"):
            raise BuildError("Generated SRS decompiled to an empty rule set")
        temporary_srs.replace(args.output)

    stats = {
        "sing_box_compatibility": "1.12.x",
        "source_format_version": 3,
        "match_structure": "domain OR ip_cidr",
        "sources": source_stats,
        "include_counts": {
            field: len(include_values.get(field, set()))
            for field in ADDRESS_FIELDS
        },
        "exclude_counts": {
            field: len(exclude_values.get(field, set()))
            for field in ADDRESS_FIELDS
        },
        "output_sha256": sha256_file(args.output),
        "output_size_bytes": args.output.stat().st_size,
    }

    stats_path = args.output.parent / "stats.json"
    stats_path.write_text(
        json.dumps(stats, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    print(json.dumps(stats, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        BuildError,
        subprocess.CalledProcessError,
        OSError,
        json.JSONDecodeError,
    ) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)
