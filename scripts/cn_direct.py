#!/usr/bin/env python3
"""Typed parser and renderer for the independent cn-direct rule bundle.

This module intentionally has no dependency on the AI rule categories in
``build.py``.  It accepts six archived byte streams, validates their syntax,
and emits deterministic client files.  Network fetching and converter calls
are explicit so offline replay never needs to access the network or download a
tool.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import json
import os
import platform
import re
import subprocess
import tempfile
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Mapping


SCHEMA = 1
HEX_256 = re.compile(r"^[0-9a-f]{64}$")
DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
DOMAIN_TYPES = {"DOMAIN", "DOMAIN-SUFFIX"}
ACL_EXCLUDED_TYPES = {"DOMAIN-KEYWORD", "IP-CIDR", "IP-CIDR6"}
SUKKA_TYPES = DOMAIN_TYPES | {"DOMAIN-KEYWORD", "DOMAIN-WILDCARD", "PROCESS-NAME", "USER-AGENT"}
SOURCE_ORDER = (
    "china_max",
    "acl_china_domain",
    "sukka_direct_clash",
    "sukka_domestic_clash",
    "sukka_direct_surge",
    "sukka_domestic_surge",
)
PSL_PATH = Path(__file__).with_name("public_suffix_list.dat")
PSL_SHA256 = "e0fe072d26b0536525badea237953ff451c9f8e64c9d02c6daa81a4491d2fc66"
PSL_VERSION = "2026-10-01"
PSL_URL = "https://publicsuffix.org/list/public_suffix_list.dat"


def _source_spec(
    archive_path: str,
    *,
    max_bytes: int,
    max_rules: int,
    repository: str | None = None,
    branch: str | None = None,
    source_path: str | None = None,
    url: str | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "archive_path": archive_path,
        "max_bytes": max_bytes,
        "max_rules": max_rules,
    }
    if repository is not None:
        result.update(
            {
                "repository": repository,
                "branch": branch,
                "source_path": source_path,
                "sha_endpoint": f"https://api.github.com/repos/{repository}/git/ref/heads/{branch}",
                "url_template": f"https://raw.githubusercontent.com/{repository}/{{sha}}/{source_path}",
            }
        )
    else:
        result["url"] = url
    return result


SOURCE_SPECS: dict[str, dict[str, Any]] = {
    "china_max": _source_spec(
        "upstream/cn-direct/china-max-domain.txt",
        max_bytes=16 * 1024 * 1024,
        max_rules=300_000,
        repository="blackmatrix7/ios_rule_script",
        branch="master",
        source_path="rule/Clash/ChinaMax/ChinaMax_Domain.txt",
    ),
    "acl_china_domain": _source_spec(
        "upstream/cn-direct/acl-china-domain.list",
        max_bytes=1024 * 1024,
        max_rules=10_000,
        repository="ACL4SSR/ACL4SSR",
        branch="master",
        source_path="Clash/ChinaDomain.list",
    ),
    "sukka_direct_clash": _source_spec(
        "upstream/cn-direct/sukka-direct.txt",
        max_bytes=512 * 1024,
        max_rules=10_000,
        url="https://ruleset-mirror.skk.moe/Clash/non_ip/direct.txt",
    ),
    "sukka_domestic_clash": _source_spec(
        "upstream/cn-direct/sukka-domestic.txt",
        max_bytes=512 * 1024,
        max_rules=10_000,
        url="https://ruleset-mirror.skk.moe/Clash/non_ip/domestic.txt",
    ),
    "sukka_direct_surge": _source_spec(
        "upstream/cn-direct/sukka-direct.conf",
        max_bytes=512 * 1024,
        max_rules=10_000,
        url="https://ruleset-mirror.skk.moe/List/non_ip/direct.conf",
    ),
    "sukka_domestic_surge": _source_spec(
        "upstream/cn-direct/sukka-domestic.conf",
        max_bytes=512 * 1024,
        max_rules=10_000,
        url="https://ruleset-mirror.skk.moe/List/non_ip/domestic.conf",
    ),
}

OUTPUT_PATHS = {
    "mihomo_domain_text": "rules/mihomo/cn-direct-domain.txt",
    "mihomo_domain_mrs": "rules/mihomo/cn-direct-domain.mrs",
    "surge_domain_set": "rules/surge/cn-direct.set",
    "mihomo_special": "rules/mihomo/cn-direct-special.list",
    "surge_special": "rules/surge/cn-direct-special.list",
    "mihomo_process": "rules/mihomo/cn-direct-process.list",
    "surge_platform": "rules/surge/cn-direct-platform.list",
}
ALLOWED_OUTPUTS = frozenset(OUTPUT_PATHS.values())


class CnDirectError(Exception):
    """Expected source, policy, review, converter, or replay validation error."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def canonical_domain(value: Any, label: str = "domain") -> str:
    if not isinstance(value, str) or not value or not value.isascii():
        raise CnDirectError(f"{label} must be a non-empty ASCII/punycode domain")
    normalized = value.lower()
    if normalized.endswith("."):
        normalized = normalized[:-1]
    if not normalized or len(normalized) > 253 or normalized.endswith("."):
        raise CnDirectError(f"{label} is not a valid DNS name: {value!r}")
    try:
        ipaddress.ip_address(normalized)
    except ValueError:
        pass
    else:
        raise CnDirectError(f"{label} must be a domain, not an IP address: {value!r}")
    labels = normalized.split(".")
    if any(not DOMAIN_LABEL.fullmatch(item) for item in labels):
        raise CnDirectError(f"{label} is not a valid DNS name: {value!r}")
    for item in labels:
        if item.startswith("xn--"):
            try:
                decoded = item.encode("ascii").decode("idna")
                encoded = decoded.encode("idna").decode("ascii").lower()
            except UnicodeError as exc:
                raise CnDirectError(f"{label} has invalid IDN punycode label: {item!r}") from exc
            if encoded != item:
                raise CnDirectError(f"{label} has non-canonical IDN punycode label: {item!r}")
    return normalized


def canonical_policy_domain(value: Any, label: str = "policy domain") -> str:
    normalized = canonical_domain(value, label)
    if normalized != value:
        raise CnDirectError(f"{label} must be lowercase and omit a trailing root dot")
    return normalized


def _idna_ascii_domain(value: str, label: str) -> str:
    """Convert a Unicode PSL name to the same canonical ASCII form as input rules."""
    try:
        ascii_labels = [label_part.encode("idna").decode("ascii").lower() for label_part in value.rstrip(".").split(".")]
    except UnicodeError as exc:
        raise CnDirectError(f"{label} contains an invalid IDN label: {value!r}") from exc
    return canonical_domain(".".join(ascii_labels), label)


@dataclass(frozen=True)
class PublicSuffixList:
    exact: frozenset[str]
    wildcard: frozenset[str]
    exception: frozenset[str]
    sha256: str

    def suffix_for(self, domain: str) -> str:
        """Return the PSL public suffix for an ASCII or Unicode DNS name."""
        normalized = _idna_ascii_domain(domain, "PSL lookup domain")
        labels = normalized.split(".")
        exception_start: int | None = None
        matched_lengths: list[int] = []
        for start in range(len(labels)):
            candidate = ".".join(labels[start:])
            if candidate in self.exception and (exception_start is None or start < exception_start):
                exception_start = start
            if candidate in self.exact:
                matched_lengths.append(len(labels) - start)
            if start > 0 and candidate in self.wildcard:
                matched_lengths.append(len(labels) - start + 1)
        if exception_start is not None:
            # An exception rule removes its first label from the public suffix.
            return ".".join(labels[exception_start + 1:])
        # PSL's implicit prevailing rule is '*'.
        suffix_label_count = max(matched_lengths, default=1)
        return ".".join(labels[-suffix_label_count:])


@lru_cache(maxsize=1)
def _read_pinned_public_suffix_list() -> bytes:
    try:
        return PSL_PATH.read_bytes()
    except OSError as exc:
        raise CnDirectError(f"cannot read pinned Public Suffix List {PSL_PATH.name}: {exc}") from exc


def load_public_suffix_list(data: bytes | None = None) -> PublicSuffixList:
    """Read and verify the repository-pinned PSL; no network fallback is allowed."""
    if data is None:
        data = _read_pinned_public_suffix_list()
    digest = sha256(data)
    if digest != PSL_SHA256:
        raise CnDirectError("pinned Public Suffix List SHA-256 does not match the reviewed registry")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CnDirectError("pinned Public Suffix List is not UTF-8") from exc
    exact: set[str] = set()
    wildcard: set[str] = set()
    exception: set[str] = set()
    version = None
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if line.startswith("// VERSION:"):
            version = line.partition(":")[2].strip().split("_", 1)[0]
            continue
        if not line or line.startswith("//"):
            continue
        target = exact
        if line.startswith("!"):
            target, line = exception, line[1:]
        elif line.startswith("*."):
            target, line = wildcard, line[2:]
        if not line or "*" in line or "!" in line:
            raise CnDirectError(f"pinned PSL line {line_number} has unsupported rule syntax")
        target.add(_idna_ascii_domain(line, f"pinned PSL line {line_number}"))
    if version != PSL_VERSION or not exact or not wildcard or not exception:
        raise CnDirectError("pinned PSL version or rule sections do not match the reviewed registry")
    return PublicSuffixList(frozenset(exact), frozenset(wildcard), frozenset(exception), digest)


def china_max_initial_wide_suffixes(rules: list["Rule"], psl: PublicSuffixList) -> list[str]:
    """Return all initial ChinaMax one-label or effective PSL-suffix scopes."""
    return sorted({
        rule.value for rule in rules
        if rule.type == "DOMAIN-SUFFIX"
        and ("." not in rule.value or psl.suffix_for(rule.value) == rule.value)
    })


def _nonempty_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip() or "\n" in value or "\r" in value:
        raise CnDirectError(f"{label} must be one non-empty trimmed line")
    return value


def validate_policy(cn_policy: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the independent policy object and return a plain dictionary."""
    if not isinstance(cn_policy, Mapping):
        raise CnDirectError("policy.cn_direct must be an object")
    policy = dict(cn_policy)
    required = {"schema", "sources", "limits", "acl_review", "china_max_initial_wide_suffixes", "china_max_wide_scope_review", "adds", "removes", "first_match_assertions", "converter"}
    unknown = set(policy) - required
    missing = required - set(policy)
    if unknown or missing:
        raise CnDirectError(f"policy.cn_direct keys mismatch; missing={sorted(missing)}, unknown={sorted(unknown)}")
    if policy["schema"] != SCHEMA:
        raise CnDirectError(f"unsupported cn_direct schema: {policy['schema']!r}")
    sources = policy["sources"]
    if not isinstance(sources, Mapping) or set(sources) != set(SOURCE_ORDER):
        raise CnDirectError("policy.cn_direct.sources must describe exactly the six registered sources")
    for source_name in SOURCE_ORDER:
        source = sources[source_name]
        if not isinstance(source, Mapping):
            raise CnDirectError(f"policy.cn_direct.sources.{source_name} must be an object")
        expected = SOURCE_SPECS[source_name]
        if source.get("archive_path") != expected["archive_path"]:
            raise CnDirectError(f"policy.cn_direct.sources.{source_name}.archive_path is fixed")
        for key in ("max_bytes", "max_rules"):
            value = source.get(key)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0 or value > expected[key]:
                raise CnDirectError(f"policy.cn_direct.sources.{source_name}.{key} must be in 1..{expected[key]}")
        snapshot_sha = source.get("snapshot_sha256")
        if snapshot_sha is not None and (not isinstance(snapshot_sha, str) or not HEX_256.fullmatch(snapshot_sha)):
            raise CnDirectError(f"policy.cn_direct.sources.{source_name}.snapshot_sha256 must be SHA-256 or null")
    limits = policy["limits"]
    if not isinstance(limits, Mapping):
        raise CnDirectError("policy.cn_direct.limits must be an object")
    limit_keys = {"maximum_added_minimum", "maximum_added_ratio", "maximum_removed_minimum", "maximum_removed_ratio", "minimum_output_rules", "maximum_output_rules"}
    if set(limits) != limit_keys:
        raise CnDirectError("policy.cn_direct.limits has missing or unknown keys")
    for key in ("maximum_added_minimum", "maximum_removed_minimum", "minimum_output_rules", "maximum_output_rules"):
        value = limits[key]
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise CnDirectError(f"policy.cn_direct.limits.{key} must be a non-negative integer")
    if limits["minimum_output_rules"] < 1 or limits["maximum_output_rules"] < limits["minimum_output_rules"]:
        raise CnDirectError("cn_direct output rule limits are inconsistent")
    for key in ("maximum_added_ratio", "maximum_removed_ratio"):
        value = limits[key]
        if not isinstance(value, (int, float)) or isinstance(value, bool) or not 0 <= value <= 1:
            raise CnDirectError(f"policy.cn_direct.limits.{key} must be between 0 and 1")
    acl_review = policy["acl_review"]
    if not isinstance(acl_review, Mapping):
        raise CnDirectError("policy.cn_direct.acl_review must be an object")
    for key in ("source_sha256", "bootstrap_candidate_id", "review_date", "decisions"):
        if key not in acl_review:
            raise CnDirectError(f"policy.cn_direct.acl_review is missing {key}")
    for key in ("source_sha256", "bootstrap_candidate_id"):
        value = acl_review[key]
        if value and (not isinstance(value, str) or not HEX_256.fullmatch(value)):
            raise CnDirectError(f"policy.cn_direct.acl_review.{key} must be SHA-256 or empty")
    if not isinstance(acl_review["decisions"], list):
        raise CnDirectError("policy.cn_direct.acl_review.decisions must be an array")
    seen: set[tuple[str, str]] = set()
    for index, item in enumerate(acl_review["decisions"]):
        if not isinstance(item, Mapping) or set(item) != {"type", "value", "action", "reason", "evidence", "review_date"}:
            raise CnDirectError(f"acl_review.decisions[{index}] has missing or unknown fields")
        if item["type"] not in DOMAIN_TYPES:
            raise CnDirectError(f"acl_review.decisions[{index}].type must be DOMAIN or DOMAIN-SUFFIX")
        canonical_policy_domain(item["value"], f"acl_review.decisions[{index}].value")
        if item["action"] not in {"accept", "reject", "candidate"}:
            raise CnDirectError(f"acl_review.decisions[{index}].action is invalid")
        _nonempty_text(item["reason"], f"acl_review.decisions[{index}].reason")
        _nonempty_text(item["evidence"], f"acl_review.decisions[{index}].evidence")
        _nonempty_text(item["review_date"], f"acl_review.decisions[{index}].review_date")
        key = (item["type"], item["value"])
        if key in seen:
            raise CnDirectError(f"duplicate ACL review decision: {key}")
        seen.add(key)
    wide = policy["china_max_initial_wide_suffixes"]
    if not isinstance(wide, list) or len(wide) != len(set(wide)):
        raise CnDirectError("china_max_initial_wide_suffixes must be a unique array")
    for index, value in enumerate(wide):
        canonical_policy_domain(value, f"china_max_initial_wide_suffixes[{index}]")
    wide_review = policy["china_max_wide_scope_review"]
    wide_review_keys = {"approval", "review_date", "source_sha256", "psl_sha256", "psl_version", "reason"}
    if not isinstance(wide_review, Mapping) or set(wide_review) != wide_review_keys:
        raise CnDirectError("china_max_wide_scope_review has missing or unknown fields")
    if wide_review["approval"] != "faithful_initial_source_snapshot":
        raise CnDirectError("china_max_wide_scope_review must record faithful initial snapshot approval")
    _nonempty_text(wide_review["review_date"], "china_max_wide_scope_review.review_date")
    _nonempty_text(wide_review["reason"], "china_max_wide_scope_review.reason")
    if wide_review["source_sha256"] != sources["china_max"].get("snapshot_sha256"):
        raise CnDirectError("ChinaMax wide-scope review must bind the fixed initial source SHA")
    if wide_review["psl_sha256"] != PSL_SHA256 or wide_review["psl_version"] != PSL_VERSION:
        raise CnDirectError("ChinaMax wide-scope review must bind the pinned Public Suffix List")
    adds = policy["adds"]
    if not isinstance(adds, list):
        raise CnDirectError("policy.cn_direct.adds must be an array")
    for index, item in enumerate(adds):
        if not isinstance(item, Mapping) or set(item) != {"type", "value", "reason", "evidence", "review_date"}:
            raise CnDirectError(f"cn_direct.adds[{index}] has missing or unknown fields")
        if item["type"] not in DOMAIN_TYPES:
            raise CnDirectError(f"cn_direct.adds[{index}].type must be DOMAIN or DOMAIN-SUFFIX")
        canonical_policy_domain(item["value"], f"cn_direct.adds[{index}].value")
        for key in ("reason", "evidence", "review_date"):
            _nonempty_text(item[key], f"cn_direct.adds[{index}].{key}")
    removes = policy["removes"]
    if not isinstance(removes, list):
        raise CnDirectError("policy.cn_direct.removes must be an array")
    for index, item in enumerate(removes):
        if not isinstance(item, Mapping) or set(item) != {"type", "value", "reason", "evidence", "review_date"}:
            raise CnDirectError(f"cn_direct.removes[{index}] has missing or unknown fields")
        if item["type"] not in DOMAIN_TYPES:
            raise CnDirectError(f"cn_direct.removes[{index}].type must be DOMAIN or DOMAIN-SUFFIX")
        canonical_policy_domain(item["value"], f"cn_direct.removes[{index}].value")
        for key in ("reason", "evidence", "review_date"):
            _nonempty_text(item[key], f"cn_direct.removes[{index}].{key}")
    if not isinstance(policy["first_match_assertions"], list):
        raise CnDirectError("first_match_assertions must be an array")
    converter = policy["converter"]
    if not isinstance(converter, Mapping) or set(converter) != {"version", "command", "binaries"}:
        raise CnDirectError("converter must contain version, command, and binaries")
    _nonempty_text(converter["version"], "converter.version")
    if converter["command"] != ["convert-ruleset", "domain", "text"]:
        raise CnDirectError("converter.command must be the registered Mihomo domain/text conversion")
    binaries = converter["binaries"]
    if not isinstance(binaries, Mapping) or not binaries:
        raise CnDirectError("converter.binaries must contain approved platform SHA-256 values")
    for target, digest in binaries.items():
        if not isinstance(target, str) or not re.fullmatch(r"(darwin|linux|windows)-[a-z0-9_]+", target):
            raise CnDirectError(f"converter binary platform key is invalid: {target!r}")
        if not isinstance(digest, str) or not HEX_256.fullmatch(digest):
            raise CnDirectError(f"converter.binaries.{target} must be a SHA-256 digest")
    return policy


@dataclass(frozen=True)
class Rule:
    type: str
    value: str
    source: str
    line: int
    raw: str

    @property
    def key(self) -> tuple[str, str]:
        return (self.type, self.value)

    def json_key(self) -> dict[str, str]:
        return {"type": self.type, "value": self.value}

    def origin(self) -> dict[str, Any]:
        return {"source": self.source, "line": self.line, "raw": self.raw}


@dataclass
class CnDirectCandidate:
    raw_sources: dict[str, bytes]
    source_rules: dict[str, list[dict[str, str]]]
    domain_rules: list[dict[str, Any]]
    special_rules: list[dict[str, str]]
    surge_special_rules: list[dict[str, str]]
    mihomo_process_rules: list[dict[str, str]]
    surge_platform_rules: list[dict[str, str]]
    outputs: dict[str, bytes]
    manifest: dict[str, Any]
    provenance: dict[str, Any]
    source_hashes: dict[str, str]
    candidate_id: str
    unreviewed_candidates: list[dict[str, str]] = field(default_factory=list)
    accepted_domain_rules: list[dict[str, Any]] = field(default_factory=list)


def _is_suffix_or_equal(host: str, suffix: str) -> bool:
    return host == suffix or host.endswith("." + suffix)


def rule_matches_host(rule_type: str, value: str, host: str) -> bool:
    host = canonical_domain(host, "host")
    if rule_type == "DOMAIN":
        return host == value
    if rule_type == "DOMAIN-SUFFIX":
        return _is_suffix_or_equal(host, value)
    if rule_type == "DOMAIN-KEYWORD":
        return value.lower() in host
    if rule_type == "DOMAIN-WILDCARD":
        pattern = "^" + re.escape(value).replace(r"\?", ".").replace(r"\*", ".*") + "$"
        return re.fullmatch(pattern, host) is not None
    return False


def _domain_rule_covers(cover: tuple[str, str], candidate: tuple[str, str]) -> bool:
    cover_type, cover_value = cover
    candidate_type, candidate_value = candidate
    if cover_type == "DOMAIN":
        return candidate_type == "DOMAIN" and cover_value == candidate_value
    if cover_type != "DOMAIN-SUFFIX":
        return False
    return _is_suffix_or_equal(candidate_value, cover_value)


def _scope_covered_by_index(scope: tuple[str, str], suffixes: set[str], exacts: set[str] | None = None) -> bool:
    """Test rule containment by walking DNS labels instead of cross-comparing sets."""
    typ, value = scope
    if typ == "DOMAIN":
        return (exacts is not None and value in exacts) or _has_suffix_ancestor(value, suffixes) is not None
    if typ == "DOMAIN-SUFFIX":
        labels = value.split(".")
        return any(".".join(labels[index:]) in suffixes for index in range(len(labels)))
    return False


def _has_suffix_ancestor(value: str, suffixes: set[str]) -> str | None:
    labels = value.split(".")
    for index in range(0, len(labels)):
        candidate = ".".join(labels[index:])
        if candidate in suffixes:
            return candidate
    return None


def compress_domain_rules(rules: list[Rule]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Deduplicate and compress suffix-covered rules in O(n * labels)."""
    by_key: dict[tuple[str, str], list[Rule]] = {}
    suffixes: set[str] = set()
    exacts: set[str] = set()
    for rule in rules:
        if rule.type not in DOMAIN_TYPES:
            raise CnDirectError(f"compress_domain_rules received non-domain type {rule.type!r}")
        by_key.setdefault(rule.key, []).append(rule)
        (exacts if rule.type == "DOMAIN" else suffixes).add(rule.value)
    roots: set[str] = set()
    for suffix in sorted(suffixes, key=lambda item: (item.count("."), item)):
        labels = suffix.split(".")
        if any(".".join(labels[index:]) in roots for index in range(1, len(labels))):
            continue
        roots.add(suffix)
    aggregate: dict[tuple[str, str], dict[str, Any]] = {}
    for value in roots:
        aggregate[("DOMAIN-SUFFIX", value)] = {"covered_input_rule_count": 0, "source_rule_counts": {}}
    for exact in exacts:
        owner = _has_suffix_ancestor(exact, roots)
        if owner is None:
            aggregate[("DOMAIN", exact)] = {"covered_input_rule_count": 0, "source_rule_counts": {}}
    for (input_type, input_value), records in by_key.items():
        owner = _has_suffix_ancestor(input_value, roots)
        if owner is None:
            # A DOMAIN-SUFFIX input is always one of roots or covered by a root.
            output_key = ("DOMAIN", input_value)
        else:
            output_key = ("DOMAIN-SUFFIX", owner)
        data = aggregate[output_key]
        data["covered_input_rule_count"] += len(records)
        for record in records:
            counts = data["source_rule_counts"]
            counts[record.source] = counts.get(record.source, 0) + 1
    output_keys = sorted(aggregate, key=lambda item: (item[0], item[1]))
    output = [{"type": typ, "value": value} for typ, value in output_keys]
    origins = [
        {
            "type": typ,
            "value": value,
            "covered_input_rule_count": aggregate[(typ, value)]["covered_input_rule_count"],
            "source_rule_counts": dict(sorted(aggregate[(typ, value)]["source_rule_counts"].items())),
        }
        for typ, value in output_keys
    ]
    return output, origins


def _validate_text_response(data: bytes, source: str, maximum: int) -> str:
    if not data:
        raise CnDirectError(f"{source} source is empty")
    if len(data) > maximum:
        raise CnDirectError(f"{source} source exceeds {maximum} bytes")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CnDirectError(f"{source} source is not UTF-8: {exc}") from exc
    if "\x00" in text:
        raise CnDirectError(f"{source} source contains NUL")
    stripped = text.lstrip().lower()
    if stripped.startswith(("<!doctype html", "<html", "<?xml", "{")):
        raise CnDirectError(f"{source} source looks like an error page")
    return text


def _parse_domain_rule(rule_type: str, value: str, source: str, line: int, raw: str) -> Rule:
    if rule_type not in DOMAIN_TYPES:
        raise CnDirectError(f"{source} line {line}: unsupported domain type {rule_type!r}")
    return Rule(rule_type, canonical_domain(value, f"{source} line {line}"), source, line, raw)


def _parse_china_max(data: bytes, source: str, maximum: int) -> list[Rule]:
    text = _validate_text_response(data, source, maximum)
    result: list[Rule] = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line or line.startswith("#"):
            continue
        if line != line.strip() or "," in line or any(ch.isspace() for ch in line):
            raise CnDirectError(f"{source} line {number}: expected one bare domain")
        if line.startswith("."):
            result.append(_parse_domain_rule("DOMAIN-SUFFIX", line[1:], source, number, line))
        else:
            result.append(_parse_domain_rule("DOMAIN", line, source, number, line))
    return result


def _parse_classical(data: bytes, source: str, maximum: int, *, acl: bool = False) -> list[Rule]:
    text = _validate_text_response(data, source, maximum)
    result: list[Rule] = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line or line.startswith("#"):
            continue
        if line != line.strip():
            raise CnDirectError(f"{source} line {number}: padded line")
        parts = line.split(",")
        if len(parts) < 2 or not parts[0] or not parts[1] or any(not part for part in parts):
            raise CnDirectError(f"{source} line {number}: malformed comma-separated rule")
        rule_type, value = parts[0], parts[1]
        if rule_type in DOMAIN_TYPES:
            if len(parts) != 2:
                raise CnDirectError(f"{source} line {number}: domain rules must have exactly two fields")
            result.append(_parse_domain_rule(rule_type, value, source, number, line))
        elif acl and rule_type == "DOMAIN-KEYWORD":
            if len(parts) != 2 or not value.isascii() or any(ch.isspace() for ch in value):
                raise CnDirectError(f"{source} line {number}: invalid excluded DOMAIN-KEYWORD")
            result.append(Rule(rule_type, value.lower(), source, number, line))
        elif acl and rule_type in {"IP-CIDR", "IP-CIDR6"}:
            if len(parts) != 3 or parts[2] != "no-resolve":
                raise CnDirectError(f"{source} line {number}: invalid excluded IP rule")
            try:
                network = ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise CnDirectError(f"{source} line {number}: invalid IP network") from exc
            if (rule_type == "IP-CIDR" and network.version != 4) or (rule_type == "IP-CIDR6" and network.version != 6):
                raise CnDirectError(f"{source} line {number}: IP rule type and address family disagree")
            result.append(Rule(rule_type, f"{network},no-resolve", source, number, line))
        elif acl:
            raise CnDirectError(f"{source} line {number}: unknown ACL source type {rule_type!r}")
        else:
            raise CnDirectError(f"{source} line {number}: unsupported rule type {rule_type!r}")
    return result


def _parse_sukka(data: bytes, source: str, maximum: int) -> list[Rule]:
    text = _validate_text_response(data, source, maximum)
    result: list[Rule] = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line or line.startswith("#"):
            continue
        if line != line.strip():
            raise CnDirectError(f"{source} line {number}: padded line")
        parts = line.split(",")
        if len(parts) != 2 or not parts[0] or not parts[1]:
            raise CnDirectError(f"{source} line {number}: expected exactly one type and value")
        rule_type, value = parts
        if rule_type in DOMAIN_TYPES:
            result.append(_parse_domain_rule(rule_type, value, source, number, line))
        elif rule_type == "DOMAIN-KEYWORD":
            if not value.isascii() or any(ch.isspace() for ch in value):
                raise CnDirectError(f"{source} line {number}: invalid DOMAIN-KEYWORD")
            result.append(Rule(rule_type, value.lower(), source, number, line))
        elif rule_type == "DOMAIN-WILDCARD":
            if not value.isascii() or not re.fullmatch(r"[a-zA-Z0-9.*?_-]+(?:\.[a-zA-Z0-9.*?_-]+)*", value):
                raise CnDirectError(f"{source} line {number}: invalid DOMAIN-WILDCARD")
            if "?" not in value and "*" not in value:
                raise CnDirectError(f"{source} line {number}: DOMAIN-WILDCARD has no wildcard")
            result.append(Rule(rule_type, value.lower(), source, number, line))
        elif rule_type in {"PROCESS-NAME", "USER-AGENT"}:
            if any(ord(ch) < 32 for ch in value):
                raise CnDirectError(f"{source} line {number}: control character in {rule_type}")
            result.append(Rule(rule_type, value, source, number, line))
        else:
            raise CnDirectError(f"{source} line {number}: unknown Sukka source type {rule_type!r}")
    return result


def parse_sources(raw_sources: Mapping[str, bytes], policy: Mapping[str, Any]) -> dict[str, list[Rule]]:
    """Parse six snapshots into typed rule records, rejecting unknown syntax."""
    validate_policy(policy)
    if set(raw_sources) != set(SOURCE_ORDER):
        raise CnDirectError("cn-direct requires exactly the six registered source snapshots")
    parsed: dict[str, list[Rule]] = {}
    for source in SOURCE_ORDER:
        data = raw_sources[source]
        if not isinstance(data, bytes):
            raise CnDirectError(f"{source} source must be bytes")
        source_policy = policy["sources"][source]
        if len(data) > source_policy["max_bytes"]:
            raise CnDirectError(f"{source} exceeds its policy byte limit")
        if source == "china_max":
            records = _parse_china_max(data, source, source_policy["max_bytes"])
        elif source == "acl_china_domain":
            records = _parse_classical(data, source, source_policy["max_bytes"], acl=True)
        else:
            records = _parse_sukka(data, source, source_policy["max_bytes"])
            if source.endswith("_clash") and any(rule.type == "USER-AGENT" for rule in records):
                raise CnDirectError(f"{source} must not contain USER-AGENT rules")
        if len(records) > source_policy["max_rules"]:
            raise CnDirectError(f"{source} exceeds its policy rule-count limit")
        parsed[source] = records
    return parsed


def _source_url(source: str, sha: str | None = None) -> str:
    spec = SOURCE_SPECS[source]
    if "url" in spec:
        return spec["url"]
    if not sha:
        raise CnDirectError(f"a commit SHA is required to form the {source} raw URL")
    return spec["url_template"].format(sha=sha)


def _http_bytes(url: str, maximum: int) -> bytes:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in {"api.github.com", "raw.githubusercontent.com", "ruleset-mirror.skk.moe"}:
        raise CnDirectError(f"refusing unapproved source URL: {url}")
    request = urllib.request.Request(url, headers={"User-Agent": "zesming-ruleset-builder/1", "Accept": "application/vnd.github+json"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            final = urllib.parse.urlparse(response.geturl())
            if response.status != 200 or final.scheme != "https" or final.hostname != parsed.hostname:
                raise CnDirectError(f"upstream HTTP/redirect validation failed for {url}")
            data = response.read(maximum + 1)
    except CnDirectError:
        raise
    except Exception as exc:
        raise CnDirectError(f"could not fetch {url}: {exc}") from exc
    if len(data) > maximum:
        raise CnDirectError(f"upstream response exceeds {maximum} bytes: {url}")
    return data


def fetch_sources(
    *,
    on_meta_sha: Any | None = None,
    on_source: Any | None = None,
) -> tuple[dict[str, bytes], dict[str, Any]]:
    """Fetch each Git source at one resolved commit and all Sukka artifacts once."""
    raw_sources: dict[str, bytes] = {}
    metadata: dict[str, Any] = {"schema": SCHEMA, "sources": {}}
    fetched_at = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    commits: dict[str, str] = {}
    for source in ("china_max", "acl_china_domain"):
        spec = SOURCE_SPECS[source]
        ref_bytes = _http_bytes(spec["sha_endpoint"], 1024 * 1024)
        try:
            ref = json.loads(ref_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CnDirectError(f"{source} branch response is invalid JSON: {exc}") from exc
        target = ref.get("object", {}) if isinstance(ref, dict) else {}
        sha = target.get("sha") if isinstance(target, dict) else None
        if ref.get("ref") != f"refs/heads/{spec['branch']}" or target.get("type") != "commit" or not isinstance(sha, str) or not re.fullmatch(r"[0-9a-fA-F]{40}", sha):
            raise CnDirectError(f"{source} branch endpoint did not return one full commit SHA")
        commits[source] = sha.lower()
        if on_meta_sha is not None:
            on_meta_sha(source, sha.lower())
    for source in SOURCE_ORDER:
        spec = SOURCE_SPECS[source]
        sha = commits.get(source)
        url = _source_url(source, sha)
        content = _http_bytes(url, spec["max_bytes"])
        raw_sources[source] = content
        record: dict[str, Any] = {"url": url, "sha256": sha256(content), "fetched_at": fetched_at}
        if sha:
            record.update({"repository": spec["repository"], "branch": spec["branch"], "commit": sha, "path": spec["source_path"]})
        else:
            record["artifact"] = source
        if source.startswith("sukka_"):
            record.update(_sukka_header_metadata(content, source))
        metadata["sources"][source] = record
        if on_source is not None:
            on_source(source, content)
    return raw_sources, metadata


def _sukka_header_metadata(data: bytes, source: str) -> dict[str, Any]:
    text = data.decode("utf-8")
    lines = text.splitlines()[:20]
    result: dict[str, Any] = {"header": {}}
    for line in lines:
        if line.startswith("# Last Updated:"):
            result["header"]["last_updated"] = line.split(":", 1)[1].strip()
        elif line.startswith("# $content-hash-v1$:"):
            result["header"]["content_hash"] = line.split(":", 1)[1].strip().strip("$")
        elif line.startswith("# Size:"):
            result["header"]["declared_size"] = line.split(":", 1)[1].strip()
        elif line.startswith("# License:"):
            result["header"]["license"] = line.split(":", 1)[1].strip()
    if not result["header"].get("content_hash") or not result["header"].get("last_updated"):
        raise CnDirectError(f"{source} is missing expected Sukka content-hash/update headers")
    return result


def _unique_source_rules(records: list[Rule]) -> list[dict[str, str]]:
    return [{"type": typ, "value": value} for typ, value in sorted({record.key for record in records})]


def _dedupe_rule_records(records: list[Rule]) -> list[Rule]:
    # Preserve line-level provenance until the output's aggregate origin map is built.
    return records


def _minimal_acl_candidates(acl_domains: list[Rule], base_domains: list[Rule]) -> list[tuple[str, str]]:
    acl_scopes = {rule.key for rule in acl_domains}
    base_suffixes = {rule.value for rule in base_domains if rule.type == "DOMAIN-SUFFIX"}
    base_exacts = {rule.value for rule in base_domains if rule.type == "DOMAIN"}
    acl_suffixes = {value for typ, value in acl_scopes if typ == "DOMAIN-SUFFIX"}
    candidates = [
        scope
        for scope in acl_scopes
        if not _scope_covered_by_index(scope, base_suffixes, base_exacts)
    ]
    # A parent suffix within ACL itself makes its exacts and narrower suffixes
    # redundant as review candidates. This still visits only each scope's labels.
    minimal = [
        scope
        for scope in candidates
        if not _scope_covered_by_index(scope, acl_suffixes - ({scope[1]} if scope[0] == "DOMAIN-SUFFIX" else set()))
    ]
    return sorted(minimal)


def acl_candidate_id(scopes: list[tuple[str, str]]) -> str:
    """Stable semantic review hash; source comments and timestamps do not affect it."""
    canonical = [{"type": typ, "value": value} for typ, value in sorted(set(scopes))]
    return sha256(canonical_bytes({"schema": SCHEMA, "acl_candidate_scopes": canonical}))


def _wide_scope_candidates(
    current_domains: list[dict[str, Any]],
    previous_domains: Any,
    psl: PublicSuffixList,
) -> list[dict[str, str]]:
    """Flag newly introduced broad merged scopes against the last accepted output."""
    if not isinstance(previous_domains, list):
        return []
    previous_keys = {
        (item.get("type"), item.get("value"))
        for item in previous_domains
        if isinstance(item, Mapping)
        and item.get("type") in DOMAIN_TYPES
        and isinstance(item.get("value"), str)
    }
    previous_suffixes = {value for typ, value in previous_keys if typ == "DOMAIN-SUFFIX"}
    previous_exacts = {value for typ, value in previous_keys if typ == "DOMAIN"}
    previous_ancestors: set[str] = set()
    for _, value in previous_keys:
        labels = value.split(".")
        previous_ancestors.update(".".join(labels[index:]) for index in range(1, len(labels)))
    candidates: list[dict[str, str]] = []
    for item in current_domains:
        typ, value = item["type"], item["value"]
        if typ != "DOMAIN-SUFFIX" or (typ, value) in previous_keys:
            continue
        scope = (typ, value)
        if _scope_covered_by_index(scope, previous_suffixes, previous_exacts):
            continue
        is_tld_or_psl = "." not in value or psl.suffix_for(value) == value
        widens_old_scope = value in previous_ancestors or value in previous_exacts
        if is_tld_or_psl or widens_old_scope:
            candidates.append({"type": typ, "value": value})
    return candidates


def _decision_for(scope: tuple[str, str], decisions: list[Mapping[str, Any]]) -> Mapping[str, Any] | None:
    matched = [item for item in decisions if _domain_rule_covers((item["type"], item["value"]), scope)]
    if not matched:
        return None
    matched.sort(key=lambda item: (item["value"].count("."), item["type"] == "DOMAIN"), reverse=True)
    return matched[0]


def _acl_scope_has_qualified_accept(
    scope: tuple[str, str], decisions: list[Mapping[str, Any]], psl: PublicSuffixList
) -> bool:
    decision = _decision_for(scope, decisions)
    if decision is None or decision["action"] != "accept":
        return False
    decision_value = decision["value"]
    return decision_value.count(".") >= 1 and psl.suffix_for(decision_value) != decision_value


def _remove_rules(rules: list[Rule], removes: list[Mapping[str, Any]]) -> tuple[list[Rule], list[dict[str, str]]]:
    if not removes:
        return rules, []
    keep: list[Rule] = []
    removed: list[dict[str, str]] = []
    for rule in rules:
        selector_matches = []
        for selector in removes:
            selector_key = (selector["type"], selector["value"])
            if _domain_rule_covers(selector_key, rule.key):
                selector_matches.append(selector)
            elif _domain_rule_covers(rule.key, selector_key):
                raise CnDirectError(
                    f"cn_direct.remove {selector['type']},{selector['value']} would cut a hole in "
                    f"{rule.type},{rule.value}; this scope cannot be represented safely"
                )
        if selector_matches:
            removed.append(rule.json_key())
        else:
            keep.append(rule)
    return keep, removed


def _check_client_source_semantics(parsed: Mapping[str, list[Rule]]) -> dict[str, Any]:
    platform_diff: dict[str, Any] = {}
    for stem in ("sukka_direct", "sukka_domestic"):
        clash = parsed[stem + "_clash"]
        surge = parsed[stem + "_surge"]
        clash_special = {rule.key for rule in clash if rule.type in {"DOMAIN-KEYWORD", "DOMAIN-WILDCARD"}}
        surge_special = {rule.key for rule in surge if rule.type in {"DOMAIN-KEYWORD", "DOMAIN-WILDCARD"}}
        clash_process = {rule.key for rule in clash if rule.type == "PROCESS-NAME"}
        surge_process = {rule.key for rule in surge if rule.type == "PROCESS-NAME"}
        clash_domains = {rule.key for rule in clash if rule.type in DOMAIN_TYPES}
        surge_domains = {rule.key for rule in surge if rule.type in DOMAIN_TYPES}
        surge_ua = sorted({rule.value for rule in surge if rule.type == "USER-AGENT"})
        platform_diff[stem] = {
            "clash_only_domain_rules": [list(item) for item in sorted(clash_domains - surge_domains)],
            "surge_only_domain_rules": [list(item) for item in sorted(surge_domains - clash_domains)],
            "clash_only_special_rules": [list(item) for item in sorted(clash_special - surge_special)],
            "surge_only_special_rules": [list(item) for item in sorted(surge_special - clash_special)],
            "clash_only_process_rules": [list(item) for item in sorted(clash_process - surge_process)],
            "surge_only_process_rules": [list(item) for item in sorted(surge_process - clash_process)],
            "surge_only_types": ["USER-AGENT"] if surge_ua else [],
            "surge_user_agents": surge_ua,
        }
    return platform_diff


def _domain_text(rules: list[dict[str, Any]]) -> bytes:
    lines = []
    for rule in rules:
        if rule["type"] == "DOMAIN":
            lines.append(rule["value"])
        elif rule["type"] == "DOMAIN-SUFFIX":
            lines.append("+." + rule["value"])
        else:
            raise CnDirectError(f"Mihomo domain text cannot encode {rule['type']!r}")
    return ("\n".join(lines) + "\n").encode("utf-8")


def _surge_domain_set(rules: list[dict[str, Any]]) -> bytes:
    lines = []
    for rule in rules:
        if rule["type"] == "DOMAIN":
            lines.append(rule["value"])
        elif rule["type"] == "DOMAIN-SUFFIX":
            lines.append("." + rule["value"])
        else:
            raise CnDirectError(f"Surge domain-set cannot encode {rule['type']!r}")
    return ("\n".join(lines) + "\n").encode("utf-8")


def _classical_bytes(rules: list[dict[str, str]], header: str) -> bytes:
    lines = [header]
    lines.extend(f"{rule['type']},{rule['value']}" for rule in rules)
    return ("\n".join(lines) + "\n").encode("utf-8")


def _platform_key() -> str:
    system = platform.system().lower()
    system_name = {"darwin": "darwin", "linux": "linux", "windows": "windows"}.get(system)
    machine = platform.machine().lower()
    machine_name = {"aarch64": "arm64", "arm64": "arm64", "x86_64": "amd64", "amd64": "amd64"}.get(machine)
    if system_name is None or machine_name is None:
        raise CnDirectError(f"unsupported converter execution platform: {system}-{machine}")
    return f"{system_name}-{machine_name}"


def _convert_mrs(
    domain_text: bytes, converter_path: str | Path, converter_policy: Mapping[str, Any]
) -> tuple[bytes, dict[str, Any], dict[str, Any]]:
    converter = Path(converter_path)
    try:
        binary = converter.read_bytes()
    except OSError as exc:
        raise CnDirectError(f"cannot read configured Mihomo converter: {exc}") from exc
    digest = sha256(binary)
    target = _platform_key()
    allowed = converter_policy["binaries"].get(target)
    if allowed is None or digest != allowed:
        raise CnDirectError(f"Mihomo converter SHA does not match the approved {target} registry entry")
    try:
        with tempfile.TemporaryDirectory(prefix="cn-direct-mrs-") as directory:
            work = Path(directory)
            source = work / "cn-direct-domain.txt"
            output = work / "cn-direct-domain.mrs"
            source.write_bytes(domain_text)
            command = [str(converter), *converter_policy["command"], str(source), str(output)]
            completed = subprocess.run(command, check=False, capture_output=True, timeout=120)
            if completed.returncode != 0:
                stderr = completed.stderr.decode("utf-8", "replace")[-2000:]
                raise CnDirectError(f"Mihomo MRS conversion failed ({completed.returncode}): {stderr}")
            mrs = output.read_bytes()
    except CnDirectError:
        raise
    except Exception as exc:
        raise CnDirectError(f"Mihomo MRS converter failed: {exc}") from exc
    if not mrs:
        raise CnDirectError("Mihomo MRS converter produced an empty file")
    registry = {
        "version": converter_policy["version"],
        "command": converter_policy["command"],
        "binaries": dict(sorted(converter_policy["binaries"].items())),
    }
    stable = {
        "repository": "MetaCubeX/mihomo",
        **registry,
        "registry_sha256": sha256(canonical_bytes(registry)),
    }
    execution = {
        "platform": target,
        "binary_sha256": digest,
    }
    return mrs, stable, execution


def _rule_counts(records: list[Rule]) -> dict[str, int]:
    result: dict[str, int] = {}
    for record in records:
        result[record.type] = result.get(record.type, 0) + 1
    return dict(sorted(result.items()))


def _set_delta(current: set[tuple[str, str]], previous_raw: Any) -> dict[str, Any]:
    previous: set[tuple[str, str]] = set()
    if isinstance(previous_raw, list):
        for item in previous_raw:
            if isinstance(item, Mapping) and isinstance(item.get("type"), str) and isinstance(item.get("value"), str):
                previous.add((item["type"], item["value"]))
            elif isinstance(item, (list, tuple)) and len(item) == 2:
                previous.add((str(item[0]), str(item[1])))
    added = sorted(current - previous)
    removed = sorted(previous - current)
    return {"before": len(previous), "after": len(current), "added": len(added), "removed": len(removed), "added_rules": added, "removed_rules": removed}


def _validate_first_match_evidence_refs(assertions: list[Any], domain_rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    checked: list[dict[str, Any]] = []
    for index, item in enumerate(assertions):
        if not isinstance(item, Mapping):
            raise CnDirectError(f"first_match_assertions[{index}] must be an object")
        required = {"client", "host", "expected_route_target", "expected_dns_target", "route_template_sha256", "dns_template_sha256", "preceding_route_sets", "preceding_dns_sets", "evidence_id"}
        if set(item) != required:
            raise CnDirectError(f"first_match_assertions[{index}] must use fields {sorted(required)}")
        if item["client"] not in {"mihomo", "surge"}:
            raise CnDirectError(f"first_match_assertions[{index}].client is invalid")
        host = canonical_policy_domain(item["host"], f"first_match_assertions[{index}].host")
        if not any(rule_matches_host(rule["type"], rule["value"], host) for rule in domain_rules):
            raise CnDirectError(f"first_match_assertions[{index}] host {host} is not in cn-direct")
        for field_name in ("expected_route_target", "expected_dns_target", "evidence_id"):
            _nonempty_text(item[field_name], f"first_match_assertions[{index}].{field_name}")
        for field_name in ("route_template_sha256", "dns_template_sha256"):
            if not isinstance(item[field_name], str) or not HEX_256.fullmatch(item[field_name]):
                raise CnDirectError(f"first_match_assertions[{index}].{field_name} must be SHA-256")
        for field_name in ("preceding_route_sets", "preceding_dns_sets"):
            values = item[field_name]
            if not isinstance(values, list):
                raise CnDirectError(f"first_match_assertions[{index}].{field_name} must be an array")
            for position, ref in enumerate(values):
                if not isinstance(ref, Mapping) or set(ref) != {"id", "sha256"}:
                    raise CnDirectError(f"first_match_assertions[{index}].{field_name}[{position}] must contain id and sha256")
                _nonempty_text(ref["id"], f"first_match_assertions[{index}].{field_name}[{position}].id")
                if not isinstance(ref["sha256"], str) or not HEX_256.fullmatch(ref["sha256"]):
                    raise CnDirectError(f"first_match_assertions[{index}].{field_name}[{position}].sha256 must be SHA-256")
        checked.append({**dict(item), "validation_status": "references_only"})
    return checked


def build_candidate(
    raw_sources: Mapping[str, bytes],
    policy: Mapping[str, Any],
    *,
    baseline: Mapping[str, Any] | None = None,
    converter_path: str | Path | None = None,
    source_provenance: Mapping[str, Any] | None = None,
) -> CnDirectCandidate:
    """Build all cn-direct client outputs from one six-source snapshot.

    Known ACL ``candidate`` decisions remain visible but are excluded from
    output.  Newly discovered incremental ACL scopes are returned in
    ``unreviewed_candidates`` so the publishing caller can hold the entire
    bundle pending review.
    """
    policy = validate_policy(policy)
    if converter_path is None:
        raise CnDirectError("an approved --mrs-converter PATH is required for a complete cn-direct candidate")
    psl = load_public_suffix_list()
    parsed = parse_sources(raw_sources, policy)
    platform_diff = _check_client_source_semantics(parsed)
    source_rules = {name: _unique_source_rules(parsed[name]) for name in SOURCE_ORDER}
    source_hashes = {name: sha256(raw_sources[name]) for name in SOURCE_ORDER}
    if baseline is None:
        for name in SOURCE_ORDER:
            expected = policy["sources"][name].get("snapshot_sha256")
            if not expected or source_hashes[name] != expected:
                raise CnDirectError(f"initial {name} bytes do not match the reviewed source snapshot SHA")
        current_wide = china_max_initial_wide_suffixes(parsed["china_max"], psl)
        if current_wide != sorted(policy["china_max_initial_wide_suffixes"]):
            raise CnDirectError("initial ChinaMax one-label/PSL scopes differ from the reviewed allowlist")
    acl_domains = [rule for rule in parsed["acl_china_domain"] if rule.type in DOMAIN_TYPES]
    base_domains = [rule for name in ("china_max", "sukka_direct_clash", "sukka_domestic_clash", "sukka_direct_surge", "sukka_domestic_surge") for rule in parsed[name] if rule.type in DOMAIN_TYPES]
    acl_candidates = _minimal_acl_candidates(acl_domains, base_domains)
    review_id = acl_candidate_id(acl_candidates)
    review_config = policy["acl_review"]
    raw_acl_sha = sha256(raw_sources["acl_china_domain"])
    if review_config.get("source_sha256") and baseline is None and raw_acl_sha != review_config["source_sha256"]:
        raise CnDirectError("initial ACL snapshot SHA does not match the reviewed policy snapshot")
    if review_config.get("bootstrap_candidate_id") and baseline is None and review_id != review_config["bootstrap_candidate_id"]:
        raise CnDirectError("initial ACL candidate hash does not match its reviewed bootstrap candidate")
    decisions = review_config["decisions"]
    accepted_acl: set[tuple[str, str]] = set()
    held_acl: set[tuple[str, str]] = set()
    rejected_acl: set[tuple[str, str]] = set()
    unreviewed: list[dict[str, str]] = []
    for scope in acl_candidates:
        decision = _decision_for(scope, decisions)
        if decision is None:
            unreviewed.append({"type": scope[0], "value": scope[1]})
        elif decision["action"] == "accept":
            accepted_acl.add(scope)
        elif decision["action"] == "candidate":
            held_acl.add(scope)
        elif decision["action"] == "reject":
            rejected_acl.add(scope)
    merge_records: list[Rule] = []
    merge_records.extend(rule for rule in parsed["china_max"] if rule.type in DOMAIN_TYPES)
    # Clash rules are emitted once; their Surge copies were compared above.
    merge_records.extend(rule for name in ("sukka_direct_clash", "sukka_domestic_clash", "sukka_direct_surge", "sukka_domestic_surge") for rule in parsed[name] if rule.type in DOMAIN_TYPES)
    base_suffixes = {rule.value for rule in base_domains if rule.type == "DOMAIN-SUFFIX"}
    base_exacts = {rule.value for rule in base_domains if rule.type == "DOMAIN"}
    for rule in acl_domains:
        if _scope_covered_by_index(rule.key, base_suffixes, base_exacts):
            merge_records.append(rule)
            continue
        decision = _decision_for(rule.key, decisions)
        if decision is not None and decision["action"] == "accept":
            merge_records.append(rule)
    for item in policy["adds"]:
        merge_records.append(Rule(item["type"], item["value"], "policy.adds", 0, f"{item['type']},{item['value']}"))
    merge_records, removed_rules = _remove_rules(merge_records, policy["removes"])
    accepted_domain_rules = [
        {
            "type": rule.type,
            "value": rule.value,
            "source": rule.source,
            "line": rule.line,
            "raw": rule.raw,
        }
        for rule in sorted(
            merge_records,
            key=lambda item: (item.type, item.value, item.source, item.line, item.raw),
        )
        # Redundant ACL records remain in the public cn-direct merge and its
        # provenance, but are not trustworthy routing evidence until explicitly
        # accepted.  Otherwise a broad base suffix such as `cn` can make an
        # unreviewed narrow ACL entry look like precise, reviewed coverage.
        if rule.source != "acl_china_domain"
        or _acl_scope_has_qualified_accept(rule.key, decisions, psl)
    ]
    domain_rules, rule_origins = compress_domain_rules(merge_records)
    if not policy["limits"]["minimum_output_rules"] <= len(domain_rules) <= policy["limits"]["maximum_output_rules"]:
        raise CnDirectError("compressed cn-direct domain count is outside its hard policy limit")
    assertions = _validate_first_match_evidence_refs(policy["first_match_assertions"], domain_rules)
    mihomo_special = sorted(
        {rule.key for name in ("sukka_direct_clash", "sukka_domestic_clash") for rule in parsed[name] if rule.type in {"DOMAIN-KEYWORD", "DOMAIN-WILDCARD"}},
    )
    surge_special = sorted(
        {rule.key for name in ("sukka_direct_surge", "sukka_domestic_surge") for rule in parsed[name] if rule.type in {"DOMAIN-KEYWORD", "DOMAIN-WILDCARD"}},
    )
    mihomo_process = sorted(
        {rule.key for name in ("sukka_direct_clash", "sukka_domestic_clash") for rule in parsed[name] if rule.type == "PROCESS-NAME"},
    )
    surge_platform = sorted(
        {rule.key for name in ("sukka_direct_surge", "sukka_domestic_surge") for rule in parsed[name] if rule.type in {"PROCESS-NAME", "USER-AGENT"}},
    )
    mihomo_special_json = [{"type": typ, "value": value} for typ, value in mihomo_special]
    surge_special_json = [{"type": typ, "value": value} for typ, value in surge_special]
    mihomo_process_json = [{"type": typ, "value": value} for typ, value in mihomo_process]
    surge_platform_json = [{"type": typ, "value": value} for typ, value in surge_platform]
    domain_bytes = _domain_text(domain_rules)
    surge_domain_bytes = _surge_domain_set(domain_rules)
    special_header = "# Generated by scripts/cn_direct.py; domain keyword/wildcard only."
    process_header = "# Generated by scripts/cn_direct.py; Mihomo PROCESS-NAME rules."
    platform_header = "# Generated by scripts/cn_direct.py; Surge PROCESS-NAME and USER-AGENT only."
    outputs = {
        OUTPUT_PATHS["mihomo_domain_text"]: domain_bytes,
        OUTPUT_PATHS["surge_domain_set"]: surge_domain_bytes,
        OUTPUT_PATHS["mihomo_special"]: _classical_bytes(mihomo_special_json, special_header),
        OUTPUT_PATHS["surge_special"]: _classical_bytes(surge_special_json, special_header),
        OUTPUT_PATHS["mihomo_process"]: _classical_bytes(mihomo_process_json, process_header),
        OUTPUT_PATHS["surge_platform"]: _classical_bytes(surge_platform_json, platform_header),
    }
    mrs_bytes, converter, converter_execution = _convert_mrs(domain_bytes, converter_path, policy["converter"])
    outputs[OUTPUT_PATHS["mihomo_domain_mrs"]] = mrs_bytes
    output_info = {
        path: {"sha256": sha256(content), "bytes": len(content)}
        for path, content in sorted(outputs.items())
    }
    if set(output_info) != ALLOWED_OUTPUTS:
        raise CnDirectError("generated output path set does not equal the registered cn-direct bundle")
    source_metadata: dict[str, Any]
    if source_provenance is None:
        source_metadata = {
            "schema": SCHEMA,
            "sources": {name: {"sha256": source_hashes[name]} for name in SOURCE_ORDER},
        }
    else:
        source_metadata = json.loads(json.dumps(source_provenance))
        declared = source_metadata.get("sources") if isinstance(source_metadata, dict) else None
        if not isinstance(declared, dict) or set(declared) != set(SOURCE_ORDER):
            raise CnDirectError("source_provenance must describe exactly the six source keys")
        for name in SOURCE_ORDER:
            if declared[name].get("sha256") != source_hashes[name]:
                raise CnDirectError(f"source_provenance SHA does not match {name} snapshot")
    source_diffs: dict[str, Any] = {}
    quantity_errors: list[str] = []
    baseline_sources = baseline.get("source_rules", {}) if isinstance(baseline, Mapping) else {}
    for name in SOURCE_ORDER:
        previous = baseline_sources.get(name) if isinstance(baseline_sources, Mapping) else None
        delta = _set_delta({(item["type"], item["value"]) for item in source_rules[name]}, previous)
        source_diffs[name] = delta
        if delta["before"]:
            limits = policy["limits"]
            allowed_add = max(limits["maximum_added_minimum"], int(delta["before"] * limits["maximum_added_ratio"]))
            allowed_remove = max(limits["maximum_removed_minimum"], int(delta["before"] * limits["maximum_removed_ratio"]))
            if delta["added"] > allowed_add:
                quantity_errors.append(f"{name} added {delta['added']} rules; maximum is {allowed_add}")
            if delta["removed"] > allowed_remove:
                quantity_errors.append(f"{name} removed {delta['removed']} rules; maximum is {allowed_remove}")
    normalized_domain = [{"type": item["type"], "value": item["value"]} for item in domain_rules]
    wide_candidates = _wide_scope_candidates(
        normalized_domain,
        baseline.get("domain_rules") if isinstance(baseline, Mapping) else None,
        psl,
    )
    if wide_candidates:
        quantity_errors.extend(
            f"new broad cn-direct merged suffix requires review: {item['value']}"
            for item in wide_candidates
        )
    domain_delta = _set_delta({(item["type"], item["value"]) for item in normalized_domain}, baseline.get("domain_rules") if isinstance(baseline, Mapping) else None)
    if domain_delta["before"]:
        limits = policy["limits"]
        if domain_delta["added"] > max(limits["maximum_added_minimum"], int(domain_delta["before"] * limits["maximum_added_ratio"])):
            quantity_errors.append(f"merged cn-direct domain output added {domain_delta['added']} rules above its limit")
        if domain_delta["removed"] > max(limits["maximum_removed_minimum"], int(domain_delta["before"] * limits["maximum_removed_ratio"])):
            quantity_errors.append(f"merged cn-direct domain output removed {domain_delta['removed']} rules above its limit")
    acl_excluded_counts = _rule_counts([rule for rule in parsed["acl_china_domain"] if rule.type in ACL_EXCLUDED_TYPES])
    acl_counts = _rule_counts(parsed["acl_china_domain"])
    source_counts = {name: len(source_rules[name]) for name in SOURCE_ORDER}
    stable_converter = converter
    manifest = {
        "schema": SCHEMA,
        "sources": {
            name: {"path": SOURCE_SPECS[name]["archive_path"], "sha256": source_hashes[name], "rules": source_counts[name]}
            for name in SOURCE_ORDER
        },
        "source_rules": source_rules,
        "domain_rules": normalized_domain,
        "outputs": output_info,
        "converter": stable_converter,
        "candidate_id": review_id,
        "acl_review": {
            "source_sha256": raw_acl_sha,
            "candidate_id": review_id,
            "candidate_count": len(acl_candidates),
            "accepted": [{"type": typ, "value": value} for typ, value in sorted(accepted_acl)],
            "rejected": [{"type": typ, "value": value} for typ, value in sorted(rejected_acl)],
            "held": [{"type": typ, "value": value} for typ, value in sorted(held_acl)],
            "unreviewed": unreviewed,
            "excluded_type_counts": acl_excluded_counts,
            "typed_rule_counts": acl_counts,
        },
        "counts": {
            "source_rules": source_counts,
            "domain_output_rules": len(domain_rules),
            "mihomo_special_rules": len(mihomo_special_json),
            "surge_special_rules": len(surge_special_json),
            "mihomo_process_rules": len(mihomo_process_json),
            "surge_platform_rules": len(surge_platform_json),
            "compressed_input_rules": len(merge_records),
            "acl_excluded_rules": sum(acl_excluded_counts.values()),
        },
        "rule_origins": rule_origins,
        "platform_differences": platform_diff,
        "removed_rules": removed_rules,
        "first_match_assertions": assertions,
        "first_match_evidence_validation": "references_only",
        "wide_scope_baseline": {
            **dict(policy["china_max_wide_scope_review"]),
            "initial_suffixes": policy["china_max_initial_wide_suffixes"],
            "public_suffix_list": {
                "path": "scripts/public_suffix_list.dat",
                "url": PSL_URL,
                "version": PSL_VERSION,
                "sha256": psl.sha256,
                "exact_rule_count": len(psl.exact),
                "wildcard_rule_count": len(psl.wildcard),
                "exception_rule_count": len(psl.exception),
            },
        },
        "diffs": {"sources": source_diffs, "domain_output": domain_delta},
        "quantity_errors": quantity_errors,
        "wide_scope_review_candidates": wide_candidates,
    }
    source_metadata["converter_execution"] = converter_execution
    provenance = source_metadata
    return CnDirectCandidate(
        raw_sources=dict(raw_sources),
        source_rules=source_rules,
        domain_rules=domain_rules,
        special_rules=mihomo_special_json,
        surge_special_rules=surge_special_json,
        mihomo_process_rules=mihomo_process_json,
        surge_platform_rules=surge_platform_json,
        outputs=outputs,
        manifest=manifest,
        provenance=provenance,
        source_hashes=source_hashes,
        candidate_id=review_id,
        unreviewed_candidates=unreviewed,
        accepted_domain_rules=accepted_domain_rules,
    )
