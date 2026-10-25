#!/usr/bin/env python3
"""Compile the private, ordered personal-routing profile from pinned inputs.

The compiler is deliberately separate from the public legacy builders.  Source
snapshots stay individually archived; only adjacent stages with identical
routing, DNS, rejection, matching and rule-format semantics share a resource.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import fnmatch
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence


SCHEMA = 1
ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = "profiles/us-primary.json"
MANIFEST_PATH = "upstream/personal/manifest.json"
INTERFACE_DIFF_REPORT = ".build-report/personal-interface-diff.json"
MIHOMO_CONVERTER_ENV = "MIHOMO_CONVERTER"
MAX_RESPONSE_BYTES = 12 * 1024 * 1024
HTTP_TIMEOUT_SECONDS = 25
SOURCE_FETCH_RETRY_DELAYS = (0.5, 1.0)
HEX_256 = re.compile(r"^[0-9a-f]{64}$")
DOMAIN_LABEL = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")
DOMAIN_TYPES = {"DOMAIN", "DOMAIN-SUFFIX"}
DOMAIN_MATCH_TYPES = DOMAIN_TYPES | {"DOMAIN-KEYWORD", "DOMAIN-WILDCARD"}
RULE_TYPES = DOMAIN_MATCH_TYPES | {
    "IP-CIDR", "IP-CIDR6", "IP-ASN", "PROCESS-NAME", "PROCESS-NAME-WILDCARD",
    "USER-AGENT", "URL-REGEX", "AND", "GEOIP", "MATCH"
}
SOURCE_TYPES = RULE_TYPES - {"GEOIP", "MATCH"}
SUKKA_IP_CANARY = ("DOMAIN", "7h15.ru1353t.1s.m4d3.by.5ukk4w.skk.moe")
DNS_INTENTS = {"system", "domestic", "foreign", "jp", "none"}
COMPACT_DNS_INTENTS = DNS_INTENTS | {"test"}
ROUTE_ACTIONS = {"US", "DIRECT", "JP", "REJECT", "TEST"}
REJECT_MODES = {None, "plain", "drop", "no-drop"}


class ProfileError(Exception):
    """Expected profile, source, conversion, or safe-write validation failure."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def pretty_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _source_specs() -> dict[str, dict[str, Any]]:
    """The exact Sukka resources referenced by the two private baselines."""
    non_ip = [
        ("lan", "non_ip", "lan"),
        ("apple_intelligence", "non_ip", "apple_intelligence"),
        ("reject_drop", "non_ip", "reject-drop"),
        ("reject_domains", "domainset", "reject"),
        ("reject_extra", "domainset", "reject_extra"),
        ("reject", "non_ip", "reject"),
        ("reject_no_drop", "non_ip", "reject-no-drop"),
        ("sogouinput", "non_ip", "sogouinput"),
        ("apple_cn", "non_ip", "apple_cn"),
        ("apple_cdn", "domainset", "apple_cdn"),
        ("apple_services", "non_ip", "apple_services"),
        ("game_download", "domainset", "game-download"),
        ("download_domains", "domainset", "download"),
        ("download", "non_ip", "download"),
        ("cdn_domains", "domainset", "cdn"),
        ("cdn", "non_ip", "cdn"),
        ("microsoft_cdn", "non_ip", "microsoft_cdn"),
        ("microsoft", "non_ip", "microsoft"),
        ("neteasemusic", "non_ip", "neteasemusic"),
        ("telegram", "non_ip", "telegram"),
    ]
    ip_sources = [
        ("lan_ip", "lan"), ("reject_ip", "reject"), ("ai_ip", "ai"),
        ("telegram_ip", "telegram"), ("telegram_asn", "telegram_asn"),
        ("apple_ip", "apple_services"), ("download_ip", "download"),
        ("cdn_ip", "cdn"), ("domestic_ip", "domestic"),
    ]
    result: dict[str, dict[str, Any]] = {}
    for platform, tree, extension in (("mihomo", "Clash", "txt"), ("surge", "List", "conf")):
        for rule_id, kind, upstream_name in non_ip:
            source_id = f"{platform}.{rule_id}"
            url = f"https://ruleset-mirror.skk.moe/{tree}/{kind}/{upstream_name}.{extension}"
            archive = f"upstream/personal/{platform}/{rule_id}.{extension}"
            max_bytes = 8 * 1024 * 1024 if kind == "domainset" else 4 * 1024 * 1024
            result[source_id] = {
                "id": source_id, "platform": platform, "kind": kind, "url": url,
                "archive_path": archive, "max_bytes": max_bytes,
            }
        for rule_id, upstream_name in ip_sources:
            source_id = f"{platform}.{rule_id}"
            url = f"https://ruleset-mirror.skk.moe/{tree}/ip/{upstream_name}.{extension}"
            archive = f"upstream/personal/{platform}/{rule_id}.{extension}"
            result[source_id] = {
                "id": source_id, "platform": platform, "kind": "ip", "url": url,
                "archive_path": archive, "max_bytes": 4 * 1024 * 1024,
            }
    return result


SOURCE_SPECS = _source_specs()
LEGACY_INPUT_PATHS = (
    "rules/ai-cn.list", "rules/ai-global.list", "rules/network-test.list", "rules/us.list",
    "rules/surge/ai-cn.set", "rules/surge/network-test.set", "rules/surge/us.set",
    "rules/surge/ai-process.list", "rules/mihomo/cn-direct-domain.mrs",
    "rules/mihomo/cn-direct-domain.txt", "rules/surge/cn-direct.set",
    "rules/mihomo/cn-direct-special.list", "rules/surge/cn-direct-special.list",
    "rules/mihomo/cn-direct-process.list", "rules/surge/cn-direct-platform.list",
)
LEGACY_SOURCE_PLATFORMS = {
    "legacy:ai-cn": {"mihomo", "surge"},
    "legacy:ai-global": {"mihomo", "surge"},
    "legacy:network-test": {"mihomo", "surge"},
    "legacy:us": {"mihomo", "surge"},
    "legacy:ai-process": {"surge"},
    "legacy:cn-direct-domain": {"mihomo", "surge"},
    "legacy:cn-direct-special": {"mihomo", "surge"},
    "legacy:cn-direct-process": {"mihomo", "surge"},
}


def _nonempty_bytes(data: bytes, label: str, maximum: int) -> str:
    if not isinstance(data, bytes):
        raise ProfileError(f"{label} must be bytes")
    if not data:
        raise ProfileError(f"{label} source is empty")
    if len(data) > maximum:
        raise ProfileError(f"{label} exceeds {maximum} bytes")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ProfileError(f"{label} is not UTF-8: {exc}") from exc
    if "\x00" in text:
        raise ProfileError(f"{label} contains NUL")
    lowered = text.lstrip().lower()
    if lowered.startswith(("<!doctype html", "<html", "<?xml", "{")):
        raise ProfileError(f"{label} looks like an HTTP error page")
    return text


def canonical_domain(value: Any, label: str = "domain") -> str:
    if not isinstance(value, str) or not value or not value.isascii():
        raise ProfileError(f"{label} must be a non-empty ASCII/punycode domain")
    normalized = value.lower()
    if normalized.endswith("."):
        normalized = normalized[:-1]
        if normalized.endswith("."):
            raise ProfileError(f"{label} has more than one terminal dot")
    if not normalized or len(normalized) > 253:
        raise ProfileError(f"{label} is not a valid DNS name: {value!r}")
    try:
        ipaddress.ip_address(normalized)
    except ValueError:
        pass
    else:
        raise ProfileError(f"{label} must be a domain, not an IP address")
    if any(not DOMAIN_LABEL.fullmatch(label_part) for label_part in normalized.split(".")):
        raise ProfileError(f"{label} is not a valid DNS name: {value!r}")
    return normalized


def _wildcard_domain(value: str, label: str) -> str:
    if not value or not value.isascii() or value != value.lower() or value.endswith("."):
        raise ProfileError(f"{label} must be lowercase ASCII without a trailing dot")
    if not re.fullmatch(r"[a-z0-9.*?_-]+(?:\.[a-z0-9.*?_-]+)*", value):
        raise ProfileError(f"{label} has unsupported wildcard syntax: {value!r}")
    if any(not part or not re.fullmatch(r"[a-z0-9*?_-]+", part) for part in value.split(".")):
        raise ProfileError(f"{label} is not a valid wildcard domain: {value!r}")
    return value


def _split_top_level(value: str, delimiter: str = ",") -> list[str]:
    """Split a small Surge expression at delimiters outside parentheses/quotes."""
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    quoted = False
    escaped = False
    for char in value:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\" and quoted:
            current.append(char)
            escaped = True
            continue
        if char == '"':
            quoted = not quoted
        elif not quoted and char == "(":
            depth += 1
        elif not quoted and char == ")":
            depth -= 1
            if depth < 0:
                raise ProfileError("unbalanced parentheses")
        if char == delimiter and not quoted and depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    if quoted or depth != 0:
        raise ProfileError("unterminated quote or unbalanced parentheses")
    parts.append("".join(current).strip())
    return parts


def _and_components(value: str, label: str = "AND rule") -> tuple[tuple[str, str], ...]:
    """Validate the bounded compound grammar used by the archived Surge source."""
    try:
        expression = value.strip()
        if not (expression.startswith("(") and expression.endswith(")")):
            raise ProfileError(f"{label} must wrap its conditions in parentheses")
        conditions = _split_top_level(expression[1:-1])
        if len(conditions) != 2:
            raise ProfileError(f"{label} must contain exactly two conditions")
        result: list[tuple[str, str]] = []
        for condition in conditions:
            if not (condition.startswith("(") and condition.endswith(")")):
                raise ProfileError(f"{label} contains a malformed condition")
            fields = _split_top_level(condition[1:-1])
            if len(fields) != 2 or not all(fields):
                raise ProfileError(f"{label} contains a malformed condition")
            kind, operand = fields[0].upper(), fields[1]
            if kind not in {"PROTOCOL", "DOMAIN", "DOMAIN-SUFFIX"}:
                raise ProfileError(f"{label} contains unsupported condition {kind!r}")
            if kind == "PROTOCOL" and not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", operand):
                raise ProfileError(f"{label} has an invalid protocol")
            if kind == "DOMAIN":
                operand = canonical_domain(operand, label)
            elif kind == "DOMAIN-SUFFIX":
                operand = canonical_domain(operand, label)
            result.append((kind, operand))
        if sum(kind == "PROTOCOL" for kind, _ in result) != 1 or sum(
            kind in {"DOMAIN", "DOMAIN-SUFFIX"} for kind, _ in result
        ) != 1:
            raise ProfileError(f"{label} requires one PROTOCOL and one domain condition")
        return tuple(result)
    except ProfileError as exc:
        if str(exc).startswith(label):
            raise
        raise ProfileError(f"{label} is malformed: {exc}") from exc


def _normalize_rule(
    rule_type: str, value: str, flags: Iterable[str], label: str, platform: str | None = None,
) -> tuple[str, str, tuple[str, ...]]:
    if not isinstance(rule_type, str) or rule_type not in SOURCE_TYPES:
        raise ProfileError(f"{label} has unknown or unsupported rule type {rule_type!r}")
    if not isinstance(value, str) or not value or any(ord(ch) < 32 for ch in value):
        raise ProfileError(f"{label} has an empty or control-containing value")
    if isinstance(flags, (str, bytes)):
        raise ProfileError(f"{label} flags must be an array of strings")
    raw_flags = tuple(flags)
    if any(not isinstance(flag, str) for flag in raw_flags):
        raise ProfileError(f"{label} flags must be an array of strings")
    if len(raw_flags) != len(set(raw_flags)):
        raise ProfileError(f"{label} repeats a rule flag")
    flag_list = tuple(sorted(set(raw_flags)))
    allowed_flags = {"no-resolve"} if rule_type in {"IP-CIDR", "IP-CIDR6", "IP-ASN"} else set()
    if rule_type in {"DOMAIN-KEYWORD", "DOMAIN-WILDCARD", "USER-AGENT", "URL-REGEX"}:
        allowed_flags.add("extended-matching")
    if set(flag_list) - allowed_flags:
        raise ProfileError(f"{label} has unsupported flags: {sorted(set(flag_list) - allowed_flags)}")
    if "extended-matching" in flag_list and platform not in {None, "surge"}:
        raise ProfileError(f"{label} extended-matching is only supported on Surge")
    if rule_type in {"USER-AGENT", "URL-REGEX", "AND"} and platform not in {None, "surge"}:
        raise ProfileError(f"{label} {rule_type} is only supported on Surge")
    if rule_type == "PROCESS-NAME-WILDCARD" and platform not in {None, "mihomo"}:
        raise ProfileError(f"{label} PROCESS-NAME-WILDCARD is only supported on Mihomo")
    if rule_type in DOMAIN_TYPES:
        value = canonical_domain(value, label)
    elif rule_type == "DOMAIN-KEYWORD":
        if not value or not value.isascii() or any(ch.isspace() for ch in value):
            raise ProfileError(f"{label} has an invalid DOMAIN-KEYWORD")
        value = value.lower()
    elif rule_type == "DOMAIN-WILDCARD":
        value = _wildcard_domain(value.lower(), label)
    elif rule_type in {"IP-CIDR", "IP-CIDR6"}:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ProfileError(f"{label} has an invalid IP network: {value!r}") from exc
        expected = 4 if rule_type == "IP-CIDR" else 6
        if network.version != expected:
            raise ProfileError(f"{label} type and address family disagree")
        value = str(network)
    elif rule_type == "IP-ASN":
        value = value.upper()
        if value.startswith("AS"):
            value = value[2:]
        if not value.isdecimal() or not 1 <= int(value) <= 4_294_967_295:
            raise ProfileError(f"{label} has an invalid IP-ASN: {value!r}")
        value = str(int(value))
    elif rule_type in {"PROCESS-NAME", "PROCESS-NAME-WILDCARD"}:
        if not value.strip() or value != value.strip():
            raise ProfileError(f"{label} has an invalid {rule_type} value")
    elif rule_type == "USER-AGENT":
        if not value.strip() or value != value.strip():
            raise ProfileError(f"{label} has an invalid USER-AGENT value")
    elif rule_type == "URL-REGEX":
        if not value.strip() or value != value.strip():
            raise ProfileError(f"{label} has an invalid URL-REGEX value")
        try:
            re.compile(value)
        except re.error as exc:
            raise ProfileError(f"{label} has an invalid URL-REGEX expression: {exc}") from exc
    elif rule_type == "AND":
        _and_components(value, label)
    return rule_type, value, flag_list


@dataclass(frozen=True)
class Rule:
    type: str
    value: str
    flags: tuple[str, ...] = ()
    source: str = ""
    line: int = 0
    platform: str = ""

    def as_dict(self, *, include_line: bool = True) -> dict[str, Any]:
        result: dict[str, Any] = {
            "platform": self.platform, "type": self.type, "value": self.value,
            "flags": list(self.flags), "source": self.source,
        }
        if include_line:
            result["line"] = self.line
        return result

    @property
    def is_domain(self) -> bool:
        return self.type in DOMAIN_MATCH_TYPES

    def render(self) -> str:
        if self.type == "AND":
            return f"{self.type},{self.value}"
        if self.type == "URL-REGEX":
            suffix = ("," + ",".join(self.flags)) if self.flags else ""
            return f"{self.type},{self.value}{suffix}"
        fields = [self.type, self.value, *self.flags]
        return ",".join(_csv_field(field) for field in fields)


def _csv_field(value: str) -> str:
    if any(char in value for char in ',"'):
        return '"' + value.replace('"', '""') + '"'
    return value


def _rule_from_parts(rule_type: str, value: str, flags: Iterable[str], source: str, line: int, platform: str) -> Rule:
    rule_type, value, flags_tuple = _normalize_rule(rule_type, value, flags, f"{source} line {line}", platform)
    return Rule(rule_type, value, flags_tuple, source, line, platform)


def _parse_classical(data: bytes, source: str, platform: str, maximum: int) -> list[Rule]:
    text = _nonempty_bytes(data, source, maximum)
    result: list[Rule] = []
    for line_no, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("#", "//")):
            continue
        if line != raw:
            raise ProfileError(f"{source} line {line_no}: padded rule")
        rule_type, separator, rest = line.partition(",")
        if not separator or not rule_type or not rest:
            raise ProfileError(f"{source} line {line_no}: expected type,value")
        if rule_type in {"IP-CIDR", "IP-CIDR6", "IP-ASN"}:
            fields = rest.split(",")
            value, flags = fields[0], fields[1:]
            if any(not flag for flag in flags):
                raise ProfileError(f"{source} line {line_no}: malformed rule fields")
        elif rule_type == "URL-REGEX":
            # A URL expression may contain commas. Only the recognized trailing
            # rule option is separated; all preceding bytes remain the regex.
            if rest.startswith('"'):
                try:
                    fields = next(csv.reader([rest], strict=True, skipinitialspace=True))
                except (csv.Error, StopIteration) as exc:
                    raise ProfileError(f"{source} line {line_no}: malformed URL-REGEX fields") from exc
                flags = []
                if len(fields) > 1 and fields[-1] == "extended-matching":
                    flags = [fields.pop()]
                if len(fields) != 1:
                    raise ProfileError(f"{source} line {line_no}: unexpected URL-REGEX fields")
                value = fields[0]
            else:
                value, separator, tail = rest.rpartition(",")
                flags = [tail] if separator and tail == "extended-matching" else []
                if not flags:
                    value = rest
        elif rule_type == "AND":
            # AND's commas delimit nested conditions, not top-level rule fields.
            value, flags = rest, []
        else:
            try:
                fields = next(csv.reader([rest], strict=True, skipinitialspace=True))
            except (csv.Error, StopIteration) as exc:
                raise ProfileError(f"{source} line {line_no}: malformed CSV rule fields") from exc
            allowed = {"extended-matching"} if rule_type in {
                "DOMAIN-KEYWORD", "DOMAIN-WILDCARD", "USER-AGENT"
            } else set()
            flags = []
            while len(fields) > 1 and fields[-1] in allowed:
                flags.insert(0, fields.pop())
            if len(fields) != 1:
                raise ProfileError(f"{source} line {line_no}: unexpected extra field for {rule_type}")
            value = fields[0]
        if not value:
            raise ProfileError(f"{source} line {line_no}: malformed rule fields")
        result.append(_rule_from_parts(rule_type, value, flags, source, line_no, platform))
    if not result:
        raise ProfileError(f"{source} contains no rules")
    return result


def _parse_domainset(data: bytes, spec: Mapping[str, Any]) -> list[Rule]:
    source = str(spec["id"])
    platform = str(spec["platform"])
    text = _nonempty_bytes(data, source, int(spec["max_bytes"]))
    result: list[Rule] = []
    for line_no, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("#", "//")):
            continue
        if line != raw:
            raise ProfileError(f"{source} line {line_no}: padded domain-set entry")
        if platform == "mihomo":
            if line.startswith("+."):
                rule_type, value = "DOMAIN-SUFFIX", line[2:]
            elif line.startswith("."):
                raise ProfileError(f"{source} line {line_no}: Mihomo domain syntax requires '+.' for suffixes")
            else:
                rule_type, value = "DOMAIN", line
        else:
            if line.startswith("."):
                rule_type, value = "DOMAIN-SUFFIX", line[1:]
            else:
                rule_type, value = "DOMAIN", line
        result.append(_rule_from_parts(rule_type, value, (), source, line_no, platform))
    if not result:
        raise ProfileError(f"{source} contains no rules")
    return result


def parse_source(data: bytes, source_id: str) -> list[Rule]:
    """Parse one registered Sukka source and reject unknown source syntax."""
    try:
        spec = SOURCE_SPECS[source_id]
    except KeyError as exc:
        raise ProfileError(f"unregistered Sukka source {source_id!r}") from exc
    if spec["kind"] == "domainset":
        rules = _parse_domainset(data, spec)
    else:
        rules = _parse_classical(data, source_id, spec["platform"], spec["max_bytes"])
        ip_types = {rule.type for rule in rules} & {"IP-CIDR", "IP-CIDR6", "IP-ASN"}
        if spec["kind"] == "ip":
            unexpected = [
                rule for rule in rules
                if rule.type not in {"IP-CIDR", "IP-CIDR6", "IP-ASN"}
                and (rule.type, rule.value) != SUKKA_IP_CANARY
            ]
            if not ip_types or unexpected:
                raise ProfileError(f"{source_id} contains a non-IP rule outside the fixed Sukka canary")
    return rules


def _parse_domain_text(data: bytes, source: str, platform: str) -> list[Rule]:
    text = _nonempty_bytes(data, source, MAX_RESPONSE_BYTES)
    result: list[Rule] = []
    for line_no, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("#", "//")):
            continue
        if line != raw:
            raise ProfileError(f"{source} line {line_no}: padded domain entry")
        if platform == "mihomo":
            if line.startswith("+."):
                rule_type, value = "DOMAIN-SUFFIX", line[2:]
            else:
                rule_type, value = "DOMAIN", line
        else:
            if line.startswith("."):
                rule_type, value = "DOMAIN-SUFFIX", line[1:]
            else:
                rule_type, value = "DOMAIN", line
        result.append(_rule_from_parts(rule_type, value, (), source, line_no, platform))
    if not result:
        raise ProfileError(f"{source} contains no domains")
    return result


def _same_semantics(left: Iterable[Rule], right: Iterable[Rule], label: str) -> None:
    left_set = {(r.type, r.value, r.flags) for r in left}
    right_set = {(r.type, r.value, r.flags) for r in right}
    if left_set != right_set:
        raise ProfileError(f"legacy platform inputs do not describe the same {label} rules")


def parse_legacy_inputs(inputs: Mapping[str, bytes]) -> dict[str, dict[str, list[Rule]]]:
    """Parse public legacy outputs without rerunning their builders."""
    if set(inputs) != set(LEGACY_INPUT_PATHS):
        missing, unexpected = set(LEGACY_INPUT_PATHS) - set(inputs), set(inputs) - set(LEGACY_INPUT_PATHS)
        raise ProfileError(f"legacy input paths mismatch; missing={sorted(missing)}, unexpected={sorted(unexpected)}")
    for path, data in inputs.items():
        if not isinstance(data, bytes):
            raise ProfileError(f"legacy input {path} must be bytes")
        if not data:
            raise ProfileError(f"legacy input {path} is empty")
        if len(data) > MAX_RESPONSE_BYTES:
            raise ProfileError(f"legacy input {path} exceeds {MAX_RESPONSE_BYTES} bytes")

    result: dict[str, dict[str, list[Rule]]] = {}

    def add(key: str, platform: str, path: str, *, domain_text: bool = False) -> list[Rule]:
        rules = _parse_domain_text(inputs[path], path, platform) if domain_text else _parse_classical(
            inputs[path], path, platform, MAX_RESPONSE_BYTES
        )
        result.setdefault(key, {})[platform] = rules
        return rules

    for key, mihomo_list, surge_set in (
        ("legacy:ai-cn", "rules/ai-cn.list", "rules/surge/ai-cn.set"),
        ("legacy:network-test", "rules/network-test.list", "rules/surge/network-test.set"),
        ("legacy:us", "rules/us.list", "rules/surge/us.set"),
    ):
        m_rules = add(key, "mihomo", mihomo_list)
        s_rules = _parse_domain_text(inputs[surge_set], surge_set, "surge")
        result[key]["surge"] = s_rules
        _same_semantics(m_rules, s_rules, key)

    ai_global = add("legacy:ai-global", "mihomo", "rules/ai-global.list")
    result["legacy:ai-global"]["surge"] = [Rule(r.type, r.value, r.flags, r.source, r.line, "surge") for r in ai_global]
    add("legacy:ai-process", "surge", "rules/surge/ai-process.list")

    mihomo_domain = add("legacy:cn-direct-domain", "mihomo", "rules/mihomo/cn-direct-domain.txt", domain_text=True)
    surge_domain = _parse_domain_text(inputs["rules/surge/cn-direct.set"], "rules/surge/cn-direct.set", "surge")
    result["legacy:cn-direct-domain"]["surge"] = surge_domain
    _same_semantics(mihomo_domain, surge_domain, "cn-direct domain")
    if not inputs["rules/mihomo/cn-direct-domain.mrs"]:
        raise ProfileError("legacy cn-direct MRS input is empty")
    add("legacy:cn-direct-special", "mihomo", "rules/mihomo/cn-direct-special.list")
    add("legacy:cn-direct-special", "surge", "rules/surge/cn-direct-special.list")
    add("legacy:cn-direct-process", "mihomo", "rules/mihomo/cn-direct-process.list")
    add("legacy:cn-direct-process", "surge", "rules/surge/cn-direct-platform.list")
    return result


def validate_profile(profile: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(profile, Mapping):
        raise ProfileError("profile must be an object")
    value = dict(profile)
    required = {"schema", "id", "routes", "jp_members", "stages", "compact"}
    if set(value) != required:
        raise ProfileError(f"profile keys mismatch; missing={sorted(required - set(value))}, unknown={sorted(set(value) - required)}")
    if value["schema"] != SCHEMA or value["id"] != "us-primary":
        raise ProfileError("unsupported personal profile schema or id")
    routes = value["routes"]
    if not isinstance(routes, Mapping) or set(routes) != ROUTE_ACTIONS:
        raise ProfileError(f"profile.routes must map exactly {sorted(ROUTE_ACTIONS)}")
    for key, target in routes.items():
        if target != key:
            raise ProfileError(f"profile.routes.{key} must keep the credential-free group name {key}")

    jp_members = value["jp_members"]
    if not isinstance(jp_members, list):
        raise ProfileError("profile.jp_members must be an array")
    seen_jp: set[tuple[str, str, tuple[str, ...]]] = set()
    for index, member in enumerate(jp_members):
        label = f"profile.jp_members[{index}]"
        if not isinstance(member, Mapping) or set(member) != {"type", "value", "source", "reason"}:
            raise ProfileError(f"{label} must contain type, value, source, and reason")
        if not isinstance(member.get("value"), str) or any(
            char in member["value"] for char in (",", "\n", "\r")
        ):
            raise ProfileError(f"{label}.value must be a single rule field without commas or newlines")
        portable_types = {
            "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD",
            "IP-CIDR", "IP-CIDR6", "IP-ASN",
        }
        if not isinstance(member.get("type"), str) or member["type"] not in portable_types:
            raise ProfileError(f"{label}.type must be a portable domain or IP rule")
        flags: tuple[str, ...] = ()
        typ, val, flags = _normalize_rule(member["type"], member["value"], flags, label)
        for key in ("source", "reason"):
            item = member[key]
            if not isinstance(item, str) or not item.strip() or item != item.strip() or "\n" in item or "\r" in item:
                raise ProfileError(f"{label}.{key} must be one non-empty line")
        dedupe_key = typ, val, flags
        if dedupe_key in seen_jp:
            raise ProfileError(f"{label} duplicates a JP member")
        seen_jp.add(dedupe_key)

    stages = value["stages"]
    if not isinstance(stages, list) or not stages:
        raise ProfileError("profile.stages must be a non-empty ordered array")
    seen_ids: set[str] = set()
    for index, stage in enumerate(stages):
        label = f"profile.stages[{index}]"
        required_stage = {"id", "action", "dns", "sources"}
        optional_stage = {"reject_mode", "extended_matching", "no_resolve", "members", "rule"}
        if not isinstance(stage, Mapping) or not required_stage <= set(stage) or set(stage) - required_stage - optional_stage:
            raise ProfileError(f"{label} has missing or unknown fields")
        stage_id = stage["id"]
        if not isinstance(stage_id, str) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", stage_id) or stage_id in seen_ids:
            raise ProfileError(f"{label}.id must be a unique lowercase slug")
        seen_ids.add(stage_id)
        if not isinstance(stage["action"], str) or stage["action"] not in ROUTE_ACTIONS:
            raise ProfileError(f"{label}.action is unsupported")
        if not isinstance(stage["dns"], str) or stage["dns"] not in DNS_INTENTS:
            raise ProfileError(f"{label}.dns must be one of {sorted(DNS_INTENTS)}")
        if not isinstance(stage["sources"], list) or any(not isinstance(item, str) for item in stage["sources"]):
            raise ProfileError(f"{label}.sources must be an array of strings")
        if len(stage["sources"]) != len(set(stage["sources"])):
            raise ProfileError(f"{label}.sources must be a unique array")
        for source_id in stage["sources"]:
            if source_id not in SOURCE_SPECS and not source_id.startswith("legacy:") and source_id not in {
                "manual:jp_members", "manual:geoip-cn", "manual:default"
            }:
                raise ProfileError(f"{label} refers to unknown source {source_id!r}")
        reject_mode = stage.get("reject_mode")
        if (reject_mode is not None and not isinstance(reject_mode, str)) or reject_mode not in REJECT_MODES or (
            reject_mode is not None and stage["action"] != "REJECT"
        ):
            raise ProfileError(f"{label}.reject_mode is invalid for its route action")
        for flag in ("extended_matching", "no_resolve"):
            if flag in stage and not isinstance(stage[flag], bool):
                raise ProfileError(f"{label}.{flag} must be boolean")
        if stage.get("members") not in (None, "jp_members"):
            raise ProfileError(f"{label}.members only supports jp_members")
        if "rule" in stage:
            rule = stage["rule"]
            if not isinstance(rule, Mapping) or set(rule) != {"type", "value", "flags"}:
                raise ProfileError(f"{label}.rule must contain type, value, and flags")
            if not isinstance(rule["flags"], list) or any(not isinstance(flag, str) for flag in rule["flags"]):
                raise ProfileError(f"{label}.rule.flags must be an array of strings")
            if not isinstance(rule["type"], str) or rule["type"] not in {"GEOIP", "MATCH"}:
                raise ProfileError(f"{label}.rule only supports terminal GEOIP or MATCH")
            if rule["type"] == "GEOIP" and (rule["value"] != "CN" or rule["flags"] != ["no-resolve"]):
                raise ProfileError("profile may only define GEOIP,CN,no-resolve")
            if rule["type"] == "MATCH" and (rule["value"] != "*" or rule["flags"]):
                raise ProfileError("terminal MATCH must use '*' without flags")
        terminal_sources = set(stage["sources"]) & {"manual:geoip-cn", "manual:default"}
        if terminal_sources:
            if set(stage["sources"]) != terminal_sources or len(terminal_sources) != 1:
                raise ProfileError(f"{label} terminal rule source must be the sole stage source")
            terminal_source = next(iter(terminal_sources))
            if "rule" not in stage:
                raise ProfileError(f"{label} terminal source requires its matching terminal rule")
            rule = stage["rule"]
            expected = {
                "manual:geoip-cn": ("GEOIP", "CN", ["no-resolve"], "DIRECT", True),
                "manual:default": ("MATCH", "*", [], "US", False),
            }[terminal_source]
            if (
                rule["type"], rule["value"], rule["flags"], stage["action"], stage.get("no_resolve", False)
            ) != expected:
                raise ProfileError(f"{label} terminal source, rule, and action do not match")
            if stage["dns"] != "none" or stage.get("extended_matching", False):
                raise ProfileError(f"{label} terminal stage cannot add group-level DNS or matching flags")
        elif "rule" in stage:
            raise ProfileError(f"{label} only manual:geoip-cn and manual:default may define terminal rules")
    if stages[-1].get("rule", {}).get("type") != "MATCH" or stages[-1]["action"] != "US":
        raise ProfileError("the final profile stage must be the default US MATCH")
    source_refs = [source_id for stage in stages for source_id in stage["sources"] if source_id in SOURCE_SPECS]
    if len(source_refs) != len(set(source_refs)) or set(source_refs) != set(SOURCE_SPECS):
        raise ProfileError("every registered Sukka snapshot must appear exactly once in the ordered stages")
    legacy_required = {
        "legacy:ai-cn", "legacy:ai-global", "legacy:network-test", "legacy:us", "legacy:ai-process",
        "legacy:cn-direct-domain", "legacy:cn-direct-special", "legacy:cn-direct-process",
    }
    legacy_refs = [source_id for stage in stages for source_id in stage["sources"] if source_id.startswith("legacy:")]
    if set(legacy_refs) != legacy_required or len(legacy_refs) != len(legacy_required):
        raise ProfileError("the profile must preserve each registered legacy rule interface exactly once")
    manual_refs = [source_id for stage in stages for source_id in stage["sources"] if source_id.startswith("manual:")]
    manual_required = {"manual:jp_members", "manual:geoip-cn", "manual:default"}
    if set(manual_refs) != manual_required or len(manual_refs) != len(manual_required):
        raise ProfileError("the profile must define JP members, the China GEOIP rule, and the default rule once")
    jp_stage = next(stage for stage in stages if "manual:jp_members" in stage["sources"])
    if jp_stage["action"] != "JP" or jp_stage.get("members") != "jp_members" or jp_stage["dns"] != "jp":
        raise ProfileError("the manual JP stage must route jp_members to JP and use the JP DNS intent")

    compact = value["compact"]
    if not isinstance(compact, Mapping) or set(compact) != {"slots"}:
        raise ProfileError("profile.compact must contain only an ordered slots array")
    slots = compact["slots"]
    if not isinstance(slots, list) or not slots:
        raise ProfileError("profile.compact.slots must be a non-empty ordered array")
    slot_ids: set[str] = set()
    compact_stage_refs: list[str] = []
    slot_tiers: list[str] = []
    slot_by_id: dict[str, Mapping[str, Any]] = {}
    for index, slot in enumerate(slots):
        label = f"profile.compact.slots[{index}]"
        required_slot = {"id", "stages"}
        optional_slot = {"action", "dns", "tier", "ip_slot", "reserve", "format"}
        if not isinstance(slot, Mapping) or not required_slot <= set(slot) or set(slot) - required_slot - optional_slot:
            raise ProfileError(f"{label} has missing or unknown fields")
        slot_id = slot["id"]
        if not isinstance(slot_id, str) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", slot_id) or slot_id in slot_ids:
            raise ProfileError(f"{label}.id must be a unique lowercase slug")
        slot_ids.add(slot_id)
        slot_by_id[slot_id] = slot
        stage_ids = slot["stages"]
        if not isinstance(stage_ids, list) or any(not isinstance(item, str) for item in stage_ids):
            raise ProfileError(f"{label}.stages must be an array of fine stage IDs")
        if len(stage_ids) != len(set(stage_ids)):
            raise ProfileError(f"{label}.stages must be unique")
        compact_stage_refs.extend(stage_ids)
        tier = slot.get("tier", "domain")
        if tier not in {"domain", "ip"}:
            raise ProfileError(f"{label}.tier must be domain or ip")
        slot_tiers.append(tier)
        if "reserve" in slot and not isinstance(slot["reserve"], bool):
            raise ProfileError(f"{label}.reserve must be boolean")
        if slot.get("format") not in (None, "domain", "domain-special", "classical"):
            raise ProfileError(f"{label}.format is unsupported")
        if not stage_ids:
            if not {"action", "dns"} <= set(slot):
                raise ProfileError(f"{label} needs action and dns for a reserved empty slot")
            if slot["action"] not in ROUTE_ACTIONS:
                raise ProfileError(f"{label}.action is unsupported")
        elif "action" in slot:
            raise ProfileError(f"{label}.action may be defined only for an empty reserved slot")
        if "dns" in slot and slot["dns"] not in COMPACT_DNS_INTENTS:
            raise ProfileError(f"{label}.dns is unsupported")
        if "ip_slot" in slot and (not isinstance(slot["ip_slot"], str) or not slot["ip_slot"]):
            raise ProfileError(f"{label}.ip_slot must name a later IP-tier slot")
    expected_compact_stages = {
        stage["id"] for stage in stages if stage.get("rule", {}).get("type") not in {"GEOIP", "MATCH"}
    }
    if set(compact_stage_refs) != expected_compact_stages or len(compact_stage_refs) != len(expected_compact_stages):
        raise ProfileError("compact slots must classify each non-terminal fine stage exactly once")
    fine_actions = {stage["id"]: stage["action"] for stage in stages}
    for slot in slots:
        if slot.get("dns") == "test":
            assigned_actions = {fine_actions[stage_id] for stage_id in slot["stages"]}
            if "action" in slot:
                assigned_actions.add(slot["action"])
            if assigned_actions != {"TEST"}:
                raise ProfileError(f"compact slot {slot['id']} dns=test is only valid for TEST stages")
    first_ip_tier = next((index for index, tier in enumerate(slot_tiers) if tier == "ip"), len(slot_tiers))
    if any(tier == "domain" for tier in slot_tiers[first_ip_tier:]):
        raise ProfileError("all domain-tier slots must precede the post-IP tier")
    for index, slot in enumerate(slots):
        target = slot.get("ip_slot")
        if target is None:
            continue
        if target not in slot_by_id:
            raise ProfileError(f"profile compact slot {slot['id']} refers to an unknown IP slot {target!r}")
        target_index = next(i for i, candidate in enumerate(slots) if candidate["id"] == target)
        if target_index <= index or slot_by_id[target].get("tier", "domain") != "ip":
            raise ProfileError(f"profile compact slot {slot['id']} ip_slot must be a later IP-tier slot")
    return value


def _legacy_source_rules(
    key: str, platform: str, legacy_rules: Mapping[str, Mapping[str, list[Rule]]]
) -> list[Rule]:
    if key not in LEGACY_SOURCE_PLATFORMS:
        raise ProfileError(f"unregistered legacy source {key!r}")
    if platform not in LEGACY_SOURCE_PLATFORMS[key]:
        return []
    rules = legacy_rules.get(key, {}).get(platform)
    if rules is None:
        raise ProfileError(f"legacy source {key!r} has no {platform} rule interface")
    return rules


def _stage_rules(
    stage: Mapping[str, Any], platform: str, parsed_sources: Mapping[str, list[Rule]],
    legacy_rules: Mapping[str, Mapping[str, list[Rule]]], profile: Mapping[str, Any],
) -> list[Rule]:
    rules: list[Rule] = []
    for source_id in stage["sources"]:
        if source_id in SOURCE_SPECS:
            if SOURCE_SPECS[source_id]["platform"] == platform:
                rules.extend(parsed_sources[source_id])
        elif source_id.startswith("legacy:"):
            rules.extend(_legacy_source_rules(source_id, platform, legacy_rules))
        elif source_id == "manual:jp_members":
            if stage["action"] != "JP" or stage.get("members") != "jp_members":
                raise ProfileError("manual:jp_members is only valid on the JP manual stage")
            for index, member in enumerate(profile["jp_members"], 1):
                rules.append(_rule_from_parts(member["type"], member["value"], (), "manual:jp_members", index, platform))
        elif source_id in {"manual:geoip-cn", "manual:default"}:
            continue
    stage_rule = stage.get("rule")
    if stage_rule:
        rules.append(Rule(stage_rule["type"], stage_rule["value"], tuple(stage_rule["flags"]), f"manual:{stage['id']}", 1, platform))
    return rules


def _domain_text(rules: Iterable[Rule]) -> bytes:
    lines = []
    for rule in rules:
        if rule.type == "DOMAIN":
            lines.append(rule.value)
        elif rule.type == "DOMAIN-SUFFIX":
            lines.append("+." + rule.value)
        else:
            raise ProfileError("domain converter received a non DOMAIN/DOMAIN-SUFFIX rule")
    return ("\n".join(lines) + "\n").encode("utf-8")


def _surge_domain_set(rules: Iterable[Rule]) -> bytes:
    lines = []
    for rule in rules:
        if rule.type == "DOMAIN":
            lines.append(rule.value)
        elif rule.type == "DOMAIN-SUFFIX":
            lines.append("." + rule.value)
        else:
            raise ProfileError("Surge domain-set received a non DOMAIN/DOMAIN-SUFFIX rule")
    return ("\n".join(lines) + "\n").encode("utf-8")


def _load_converter_policy(root: Path) -> Mapping[str, Any]:
    try:
        policy = json.loads((root / "policy.json").read_text(encoding="utf-8"))
        converter = policy["cn_direct"]["converter"]
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ProfileError(f"cannot read the approved Mihomo converter registry: {exc}") from exc
    return converter


def _convert_mrs(domain_data: bytes, root: Path, converter_path: str | Path | None = None) -> bytes:
    converter_value = converter_path or os.environ.get(MIHOMO_CONVERTER_ENV)
    if not converter_value:
        raise ProfileError(f"pure Mihomo domain outputs require {MIHOMO_CONVERTER_ENV} or converter_path")
    path = Path(converter_value)
    converter = path.expanduser()
    registry = _load_converter_policy(root)
    try:
        binary = converter.read_bytes()
    except OSError as exc:
        raise ProfileError(f"cannot read Mihomo converter at {converter}: {exc}") from exc
    target = _platform_key()
    expected = registry.get("binaries", {}).get(target)
    if not expected or sha256(binary) != expected:
        raise ProfileError(f"Mihomo converter SHA does not match the approved {target} registry")
    with tempfile.TemporaryDirectory(prefix="personal-profile-mrs-") as directory:
        source = Path(directory) / "domain.txt"
        output = Path(directory) / "domain.mrs"
        source.write_bytes(domain_data)
        command = [str(converter), *registry["command"], str(source), str(output)]
        try:
            completed = subprocess.run(command, check=False, capture_output=True, timeout=120)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ProfileError(f"Mihomo MRS conversion failed: {exc}") from exc
        if completed.returncode != 0:
            detail = completed.stderr.decode("utf-8", "replace")[-1200:]
            raise ProfileError(f"Mihomo MRS conversion failed ({completed.returncode}): {detail}")
        try:
            result = output.read_bytes()
        except OSError as exc:
            raise ProfileError("Mihomo MRS converter did not produce an output file") from exc
    if not result:
        raise ProfileError("Mihomo MRS converter produced an empty output")
    return result


def _platform_key() -> str:
    import platform as _platform

    os_name = {"darwin": "darwin", "linux": "linux", "windows": "windows"}.get(_platform.system().lower())
    machine = {"aarch64": "arm64", "arm64": "arm64", "x86_64": "amd64", "amd64": "amd64"}.get(_platform.machine().lower())
    if not os_name or not machine:
        raise ProfileError("unsupported platform for approved Mihomo converter")
    return f"{os_name}-{machine}"


def _capability(rules: Iterable[Rule]) -> str:
    rule_types = {rule.type for rule in rules}
    if rule_types and rule_types <= DOMAIN_TYPES:
        return "domain"
    if rule_types and rule_types <= DOMAIN_MATCH_TYPES:
        return "domain-special"
    return "classical"


def _source_metadata(source_id: str, data: bytes, rules: list[Rule]) -> dict[str, Any]:
    spec = SOURCE_SPECS[source_id]
    return {
        "platform": spec["platform"], "kind": spec["kind"], "url": spec["url"],
        "archive_path": spec["archive_path"], "sha256": sha256(data),
        "bytes": len(data), "rules": len(rules),
    }


CLIENT_INTERFACE_FIELDS = (
    "id", "stages", "path", "action", "dns", "reject_mode", "extended_matching", "no_resolve",
    "kind", "behavior", "format", "dns_path", "dns_kind", "dns_behavior", "dns_format",
)

# Stable canonical compact names, indexed by their former generated IDs so the
# migration can identify old manifest entries without emitting their URLs.
LEGACY_COMPACT_GROUP_IDS = {
    "priority-lan-domain": "lan-direct",
    "priority-test-domain": "test",
    "priority-reject-classical": "reject-drop",
    "priority-reject-domain": "reject",
    "priority-reject-classical-2": "reject-rules",
    "priority-reject-domain-2": "reject-extra",
    "priority-reject-classical-3": "reject-no-drop",
    "priority-reject-classical-4": "reject-extra-rules",
    "priority-jp-classical": "jp-proxy",
    "priority-us-classical": "us-proxy",
    "priority-us-classical-2": "us-proxy-ext",
    "priority-cn-direct-domain": "cn-direct",
    "priority-cn-direct-classical": "cn-direct-extra",
    "priority-lan-ip-classical": "lan-direct-ip",
    "priority-reject-ip-classical": "reject-ip",
    "priority-jp-ip-classical": "jp-proxy-ip",
    "priority-us-ip-classical": "us-proxy-ip",
    "priority-direct-ip-classical": "direct-ip",
    "priority-us-ip-late-classical": "us-proxy-ip-late",
    "priority-cn-ip-classical": "cn-direct-ip",
}
COMPACT_CAPABILITIES = {"domain", "domain-special", "classical"}
COMPACT_ACTION_NAMES = {
    "DIRECT": "direct", "TEST": "test", "REJECT": "reject", "JP": "proxy", "US": "proxy",
}


def _compact_group_name(slot: str, action: str, capability: str, ordinal: int) -> tuple[str, bool]:
    """Return a canonical ID and whether it maps a previously published ID."""
    if capability not in COMPACT_CAPABILITIES:
        raise ProfileError(f"unsupported compact group capability {capability!r}")
    if action not in COMPACT_ACTION_NAMES:
        raise ProfileError(f"unsupported compact group action {action!r}")
    legacy_id = f"priority-{slot}-{capability}" + (f"-{ordinal}" if ordinal > 1 else "")
    canonical_id = LEGACY_COMPACT_GROUP_IDS.get(legacy_id)
    if canonical_id is not None:
        return canonical_id, True
    behavior = COMPACT_ACTION_NAMES[action]
    base_id = slot if slot == behavior or slot.endswith(f"-{behavior}") else f"{slot}-{behavior}"
    return base_id, False


def _client_interface(manifest: Mapping[str, Any]) -> dict[str, list[dict[str, Any]]]:
    groups = manifest.get("groups")
    if not isinstance(groups, Mapping):
        raise ProfileError("previous manifest has no client group interface")
    stages = manifest.get("stages")
    if not isinstance(stages, list):
        raise ProfileError("manifest has no ordered stage interface")
    result: dict[str, list[dict[str, Any]]] = {}
    for platform in ("mihomo", "surge"):
        raw_groups = groups.get(platform)
        if not isinstance(raw_groups, list):
            raise ProfileError(f"manifest has no ordered {platform} groups")
        by_id: dict[str, Mapping[str, Any]] = {}
        for index, group in enumerate(raw_groups):
            if not isinstance(group, Mapping) or any(key not in group for key in CLIENT_INTERFACE_FIELDS):
                raise ProfileError(f"manifest {platform} group {index} lacks its client interface fields")
            group_id = group.get("id")
            if not isinstance(group_id, str) or group_id in by_id:
                raise ProfileError(f"manifest {platform} groups have an invalid or duplicate id")
            by_id[group_id] = group
        normalized: list[dict[str, Any]] = []
        emitted_groups: set[str] = set()
        for stage_index, stage in enumerate(stages):
            if not isinstance(stage, Mapping) or not isinstance(stage.get("id"), str):
                raise ProfileError(f"manifest stage {stage_index} is malformed")
            stage_id = stage["id"]
            group_ids = stage.get("group_by_platform")
            if not isinstance(group_ids, Mapping):
                raise ProfileError(f"manifest stage {stage_id} has no platform group mapping")
            group_id = group_ids.get(platform)
            if group_id is not None and group_id not in emitted_groups:
                try:
                    group = by_id[group_id]
                except KeyError as exc:
                    raise ProfileError(f"manifest stage {stage_id} references an unknown {platform} group") from exc
                normalized.append({"entry": "group", **{key: group[key] for key in CLIENT_INTERFACE_FIELDS}})
                emitted_groups.add(group_id)
            terminal = stage.get("terminal_rule")
            if terminal is not None:
                if not isinstance(terminal, Mapping) or not {"type", "value", "flags"} <= set(terminal):
                    raise ProfileError(f"manifest terminal rule for {stage_id} is malformed")
                normalized.append({
                    "entry": "terminal", "position": stage_index, "stage_id": stage_id,
                    "action": stage.get("action"), "dns": stage.get("dns"),
                    "reject_mode": stage.get("reject_mode"),
                    "extended_matching": stage.get("extended_matching"),
                    "extended_matching_by_platform": stage.get("extended_matching_by_platform"),
                    "no_resolve": stage.get("no_resolve"),
                    "rule": {key: terminal[key] for key in ("type", "value", "flags")},
                })
        if emitted_groups != set(by_id):
            raise ProfileError(f"manifest {platform} has an unreferenced client group")
        result[platform] = normalized
    return result


# Compact group source-stage IDs are provenance only; they may grow when an
# intentionally empty reserved selector such as JP receives its first rules.
COMPACT_CLIENT_INTERFACE_FIELDS = tuple(
    field for field in CLIENT_INTERFACE_FIELDS if field != "stages"
) + ("slot", "capability")


def _compact_client_interface(manifest: Mapping[str, Any]) -> dict[str, list[dict[str, Any]]] | None:
    compact = manifest.get("compact")
    if compact is None:
        return None
    if not isinstance(compact, Mapping) or compact.get("schema") != 1:
        raise ProfileError("previous compact manifest has an unsupported schema")
    groups = compact.get("groups")
    stages = compact.get("stages")
    if not isinstance(groups, Mapping) or not isinstance(stages, Mapping):
        raise ProfileError("compact manifest has no platform groups or ordered stages")
    result: dict[str, list[dict[str, Any]]] = {}
    for platform in ("mihomo", "surge"):
        raw_groups = groups.get(platform)
        raw_stages = stages.get(platform)
        if not isinstance(raw_groups, list) or not isinstance(raw_stages, list):
            raise ProfileError(f"compact manifest has no ordered {platform} groups and stages")
        by_id: dict[str, Mapping[str, Any]] = {}
        for index, group in enumerate(raw_groups):
            if not isinstance(group, Mapping) or any(key not in group for key in COMPACT_CLIENT_INTERFACE_FIELDS):
                raise ProfileError(f"compact manifest {platform} group {index} lacks its client interface fields")
            group_id = group.get("id")
            if not isinstance(group_id, str) or group_id in by_id:
                raise ProfileError(f"compact manifest {platform} has an invalid or duplicate group id")
            by_id[group_id] = group
        normalized: list[dict[str, Any]] = []
        emitted: set[str] = set()
        for stage_index, stage in enumerate(raw_stages):
            if not isinstance(stage, Mapping) or not isinstance(stage.get("id"), str):
                raise ProfileError(f"compact manifest {platform} stage {stage_index} is malformed")
            mappings = stage.get("group_by_platform")
            if not isinstance(mappings, Mapping):
                raise ProfileError(f"compact manifest stage {stage['id']} has no platform group mapping")
            group_id = mappings.get(platform)
            if group_id is not None:
                if group_id in emitted or group_id not in by_id:
                    raise ProfileError(f"compact manifest stage {stage['id']} has an invalid {platform} group reference")
                group = by_id[group_id]
                normalized.append({
                    "entry": "group",
                    **{key: group[key] for key in COMPACT_CLIENT_INTERFACE_FIELDS},
                })
                emitted.add(group_id)
            terminal = stage.get("terminal_rule")
            if terminal is not None:
                if not isinstance(terminal, Mapping) or not {"type", "value", "flags"} <= set(terminal):
                    raise ProfileError(f"compact terminal rule for {stage['id']} is malformed")
                normalized.append({
                    "entry": "terminal", "position": stage_index, "stage_id": stage["id"],
                    "action": stage.get("action"), "dns": stage.get("dns"),
                    "reject_mode": stage.get("reject_mode"),
                    "extended_matching": stage.get("extended_matching"),
                    "extended_matching_by_platform": stage.get("extended_matching_by_platform"),
                    "no_resolve": stage.get("no_resolve"),
                    "rule": {key: terminal[key] for key in ("type", "value", "flags")},
                })
        if emitted != set(by_id):
            raise ProfileError(f"compact manifest {platform} has an unreferenced client group")
        result[platform] = normalized
    return result


def _interface_entry_key(entry: Mapping[str, Any]) -> str:
    return f"group:{entry['id']}" if entry.get("entry") == "group" else f"terminal:{entry.get('stage_id')}"


def _interface_differences(
    before: Sequence[Mapping[str, Any]], after: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Summarize an interface change by entry so reviewers see which resource moved."""
    old = {_interface_entry_key(entry): entry for entry in before}
    new = {_interface_entry_key(entry): entry for entry in after}
    changed = []
    for key in sorted(old.keys() & new.keys()):
        fields = {
            field: {"before": old[key].get(field), "after": new[key].get(field)}
            for field in sorted(old[key].keys() | new[key].keys())
            if old[key].get(field) != new[key].get(field)
        }
        if fields:
            changed.append({"entry": key, "fields": fields})
    shared_order = [key for key in old if key in new]
    return {
        "removed": [{"entry": key, "path": old[key].get("path")} for key in old if key not in new],
        "added": [{"entry": key, "path": new[key].get("path")} for key in new if key not in old],
        "changed": changed,
        "reordered": shared_order != [key for key in new if key in old],
    }


def _require_stable_client_interface(
    previous: Mapping[str, Any] | None, current: Mapping[str, Any], *, accept_change: bool = False,
    report_root: Path | None = None,
) -> None:
    if previous is None:
        return
    before = _client_interface(previous)
    after = _client_interface(current)
    before_compact = _compact_client_interface(previous)
    after_compact = _compact_client_interface(current)
    differences: dict[str, Any] = {
        platform: _interface_differences(before[platform], after[platform])
        for platform in before if before[platform] != after[platform]
    }
    for platform in ("mihomo", "surge"):
        if before_compact is None or after_compact is None:
            differences[f"{platform} compact"] = {"compact_manifest_present": {
                "before": before_compact is not None, "after": after_compact is not None,
            }}
        elif before_compact[platform] != after_compact[platform]:
            differences[f"{platform} compact"] = _interface_differences(before_compact[platform], after_compact[platform])
    if differences and not accept_change:
        detail = ""
        if report_root is not None:
            report = report_root / INTERFACE_DIFF_REPORT
            report.parent.mkdir(parents=True, exist_ok=True)
            report.write_text(json.dumps(differences, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            detail = f"; details are in {INTERFACE_DIFF_REPORT}"
        raise ProfileError(
            "client resource interface changed for " + ", ".join(differences)
            + detail + "; review and migrate clients, then rerun once with --accept-interface-change"
        )


def _compatible(group: Mapping[str, Any], stage: Mapping[str, Any], capability: str) -> bool:
    return all(group[key] == stage[key] for key in ("action", "dns", "reject_mode", "extended_matching", "no_resolve")) and group["capability"] == capability


def _requires_rule_dns(rules: Iterable[Rule], no_resolve: bool) -> bool:
    return not no_resolve and any(
        rule.type in {"IP-CIDR", "IP-CIDR6", "IP-ASN"} and "no-resolve" not in rule.flags
        for rule in rules
    )


def _stable_physical_rules(rules: Iterable[Rule]) -> list[Rule]:
    """Drop exact duplicates within one emitted group, keeping the first source."""
    result: list[Rule] = []
    seen: set[tuple[str, str, str, tuple[str, ...]]] = set()
    for rule in rules:
        key = (rule.platform, rule.type, rule.value, rule.flags)
        if key in seen:
            continue
        seen.add(key)
        result.append(rule)
    return result


def _render_compact_group_file(
    platform: str, group: Mapping[str, Any], rules: list[Rule], root: Path,
    converter_path: str | Path | None, mrs_converter: Callable[[bytes], bytes] | None,
) -> bytes:
    if not rules:
        return f"# Compact {group['slot']} selector is intentionally empty.\n".encode("utf-8")
    if group["capability"] == "domain":
        domain_data = _domain_text(rules)
        if platform == "surge":
            return _surge_domain_set(rules)
        return _convert_mrs(domain_data, root, converter_path) if mrs_converter is None else mrs_converter(domain_data)
    return ("\n".join(rule.render() for rule in rules) + "\n").encode("utf-8")


def _compile_compact(
    profile: Mapping[str, Any], all_stages: list[dict[str, Any]], *, root: Path,
    converter_path: str | Path | None, mrs_converter: Callable[[bytes], bytes] | None,
) -> tuple[
    dict[str, bytes], dict[str, list[dict[str, Any]]],
    dict[str, list[dict[str, Any]]], dict[str, list[dict[str, Any]]],
]:
    """Build the priority interface while leaving fine stages and resources intact."""
    output_files: dict[str, bytes] = {}
    groups_by_platform: dict[str, list[dict[str, Any]]] = {"mihomo": [], "surge": []}
    stages_by_platform: dict[str, list[dict[str, Any]]] = {"mihomo": [], "surge": []}
    manifest_stages: dict[str, list[dict[str, Any]]] = {"mihomo": [], "surge": []}
    fine_by_id = {stage["id"]: stage for stage in all_stages}
    ip_types = {"IP-CIDR", "IP-CIDR6", "IP-ASN"}

    def split_ip_rules(
        rules: list[Rule], slot: Mapping[str, Any], *, stage_no_resolve: bool,
    ) -> tuple[list[Rule], list[Rule]]:
        if slot.get("tier", "domain") == "ip":
            return rules, []
        if slot["id"] == "jp":
            deferred = [rule for rule in rules if rule.type in ip_types]
        else:
            deferred = [
                rule for rule in rules
                if rule.type in ip_types and not stage_no_resolve and "no-resolve" not in rule.flags
            ]
        deferred_ids = {id(rule) for rule in deferred}
        return [rule for rule in rules if id(rule) not in deferred_ids], deferred

    for platform in ("mihomo", "surge"):
        groups = groups_by_platform[platform]
        group_rule_map: dict[str, list[Rule]] = {}
        pending_ip: dict[str, list[tuple[str, list[Rule]]]] = {}
        id_counts: dict[tuple[str, str], int] = {}
        used_group_ids: set[str] = set()
        fallback_name_counts: dict[str, int] = {}

        def unique_group_id(base_id: str) -> str:
            if base_id not in used_group_ids:
                return base_id
            candidate = f"{base_id}-extra"
            extra_ordinal = 2
            while candidate in used_group_ids:
                candidate = f"{base_id}-extra-{extra_ordinal}"
                extra_ordinal += 1
            return candidate

        for slot in profile["compact"]["slots"]:
            slot_id = slot["id"]
            entries: list[dict[str, Any]] = []
            for fine_id in slot["stages"]:
                fine = fine_by_id[fine_id]
                rules = [
                    rule for rule in fine["rules"]
                    if rule.platform == platform and (rule.type, rule.value) != SUKKA_IP_CANARY
                ]
                kept_rules, ip_rules = split_ip_rules(
                    rules, slot, stage_no_resolve=fine["no_resolve"],
                )
                if ip_rules:
                    target = slot.get("ip_slot")
                    if target is None:
                        raise ProfileError(f"compact slot {slot_id} contains resolving IP rules without an ip_slot")
                    pending_ip.setdefault(target, []).append((fine_id, ip_rules))
                rules = kept_rules
                if rules:
                    entries.append({
                        "source": fine_id, "rules": rules, "action": fine["action"], "dns": slot.get("dns", fine["dns"]),
                        # Mihomo's physical REJECT provider uses the ordinary
                        # REJECT action for both plain and no-drop source modes.
                        # Keep the original mode on the fine stage manifest.
                        "reject_mode": (
                            "plain" if platform == "mihomo" and fine["reject_mode"] == "no-drop"
                            else fine["reject_mode"]
                        ),
                        "extended_matching": fine["extended_matching_by_platform"][platform] if platform == "surge" else False,
                        "no_resolve": fine["no_resolve"],
                    })

            deferred = pending_ip.pop(slot_id, [])
            for source_id, rules in reversed(deferred):
                entries.insert(0, {
                    "source": source_id, "rules": rules, "action": slot["action"], "dns": slot["dns"],
                    "reject_mode": None, "extended_matching": False, "no_resolve": False,
                })

            if not entries and (slot.get("reserve", False) or not slot["stages"]):
                reserved_stage = fine_by_id[slot["stages"][0]] if slot["stages"] else {}
                entries.append({
                    "source": None, "rules": [], "action": slot.get("action", reserved_stage.get("action")),
                    "dns": slot.get("dns", reserved_stage.get("dns")),
                    "reject_mode": None, "extended_matching": False, "no_resolve": False,
                })

            # First preserve contiguous action/DNS/reject/extended/no-resolve
            # runs. A change only in Surge extended-matching can be bucketed
            # within the same action/DNS/reject/no-resolve and DNS-resolution
            # run; this collects US ordinary rules on both sides of the Apple
            # Intelligence extended-matching source without crossing a route
            # or resolver boundary.
            ordered_entries: list[dict[str, Any]] = []
            cursor = 0
            while cursor < len(entries):
                first_entry = entries[cursor]
                resolve_boundary = _requires_rule_dns(first_entry["rules"], first_entry["no_resolve"]) if platform == "surge" else None
                base_key = (
                    first_entry["action"], first_entry["dns"], first_entry["reject_mode"],
                    first_entry["no_resolve"], resolve_boundary,
                )
                end = cursor + 1
                while end < len(entries):
                    entry = entries[end]
                    entry_resolve_boundary = _requires_rule_dns(entry["rules"], entry["no_resolve"]) if platform == "surge" else None
                    entry_base_key = (
                        entry["action"], entry["dns"], entry["reject_mode"],
                        entry["no_resolve"], entry_resolve_boundary,
                    )
                    if entry_base_key != base_key:
                        break
                    end += 1
                semantic_run = entries[cursor:end]
                extended_values = list(dict.fromkeys(entry["extended_matching"] for entry in semantic_run))
                for extended in extended_values:
                    ordered_entries.extend(
                        entry for entry in semantic_run if entry["extended_matching"] == extended
                    )
                cursor = end
            entries = ordered_entries

            # Within each compatible run, aggregate by output format so large
            # pure domain data keeps MRS/Surge-set while complex rules share a
            # classical resource.
            semantic_runs: list[dict[str, Any]] = []
            for entry in entries:
                resolve_boundary = _requires_rule_dns(entry["rules"], entry["no_resolve"]) if platform == "surge" else None
                semantic_key = (
                    entry["action"], entry["dns"], entry["reject_mode"], entry["extended_matching"],
                    entry["no_resolve"], resolve_boundary,
                )
                if not semantic_runs or semantic_runs[-1]["key"] != semantic_key:
                    semantic_runs.append({"key": semantic_key, "entries": []})
                semantic_runs[-1]["entries"].append(entry)

            for run in semantic_runs:
                run_entries = run["entries"]
                first = run_entries[0]
                if slot.get("format"):
                    format_buckets = [(slot["format"], run_entries)]
                else:
                    domain_entries = [
                        (entry, [rule for rule in entry["rules"] if rule.type in DOMAIN_TYPES])
                        for entry in run_entries
                    ]
                    complex_entries = [
                        (entry, [rule for rule in entry["rules"] if rule.type not in DOMAIN_TYPES])
                        for entry in run_entries
                    ]
                    domain_count = sum(len(rules) for _, rules in domain_entries)
                    complex_count = sum(len(rules) for _, rules in complex_entries)
                    if complex_count and (platform == "surge" or domain_count <= 1000):
                        # Surge can index domain rules inside RULE-SET, so any
                        # compatible mixed run fits one classical resource.
                        # Mihomo keeps large domain payloads in MRS and emits
                        # their complex rules separately.
                        format_buckets = [("classical", [
                            (entry, list(entry["rules"])) for entry in run_entries
                        ])]
                    else:
                        format_buckets = [
                            ("domain", [(entry, rules) for entry, rules in domain_entries if rules]),
                            ("classical", [(entry, rules) for entry, rules in complex_entries if rules]),
                        ]
                    if not any(entry["rules"] for entry in run_entries):
                        format_buckets = [("classical", [(run_entries[0], [])])]

                for capability, bucket in format_buckets:
                    if not bucket:
                        continue
                    if slot.get("format"):
                        rules_with_sources = [
                            (entry, list(entry["rules"])) for entry in bucket
                        ]
                    else:
                        rules_with_sources = bucket
                    all_bucket_rules = [rule for _, rules in rules_with_sources for rule in rules]
                    if capability == "domain" and any(rule.type not in DOMAIN_TYPES for rule in all_bucket_rules):
                        raise ProfileError(f"compact slot {slot_id} forces domain format for non-domain rules")
                    if capability == "domain-special" and any(rule.type not in DOMAIN_MATCH_TYPES for rule in all_bucket_rules):
                        raise ProfileError(f"compact slot {slot_id} forces domain-special format for non-domain rules")
                    ordinal_key = slot_id, capability
                    id_counts[ordinal_key] = id_counts.get(ordinal_key, 0) + 1
                    ordinal = id_counts[ordinal_key]
                    group_id, has_legacy_mapping = _compact_group_name(
                        slot_id, first["action"], capability, ordinal,
                    )
                    source_stage_ids = {
                        entry["source"] for entry, _ in rules_with_sources if entry["source"] is not None
                    }
                    if (
                        platform == "mihomo" and slot_id == "reject"
                        and first["reject_mode"] in {"drop", "plain"}
                    ):
                        # Mihomo normalizes no-drop to plain before grouping.
                        # Name physical resources by that effective mode and
                        # output format instead of inferring behavior from the
                        # historical per-format ordinal.
                        if first["reject_mode"] == "drop":
                            group_id = "reject-drop"
                            if group_id in used_group_ids:
                                format_name = "rules" if capability == "classical" else capability
                                group_id = unique_group_id(f"reject-drop-{format_name}")
                        else:
                            plain_names = {
                                "domain": "reject",
                                "classical": "reject-rules",
                                "domain-special": "reject-special",
                            }
                            group_id = unique_group_id(plain_names[capability])
                        has_legacy_mapping = True
                    elif platform == "surge" and slot_id == "reject" and source_stage_ids == {"reject-drop"}:
                        group_id = "reject-drop" if "reject-drop" not in used_group_ids else unique_group_id(
                            f"reject-drop-{'rules' if capability == 'classical' else capability}"
                        )
                        has_legacy_mapping = True
                    elif platform == "surge" and slot_id == "reject":
                        if {"reject-domains", "reject-rules"} <= source_stage_ids:
                            # This mixed extended-matching run is now one
                            # canonical RULE-SET, regardless of its input
                            # DOMAIN-SET/complex source split.
                            group_id, has_legacy_mapping = "reject", True
                        elif "reject-extra" in source_stage_ids and "reject-domains" not in source_stage_ids:
                            # Keep the ordinary, non-extended extra set's
                            # meaningful ID when it is emitted before the
                            # extended reject group.
                            group_id, has_legacy_mapping = "reject-extra", True
                    elif (
                        platform == "surge" and slot_id == "cn-direct"
                        and capability == "classical" and "cn-direct-domain" in source_stage_ids
                    ):
                        group_id, has_legacy_mapping = "cn-direct", True
                    if not has_legacy_mapping:
                        base_id = group_id
                        name_ordinal = fallback_name_counts.get(base_id, 0) + 1
                        candidate_id = base_id if name_ordinal == 1 else (
                            f"{base_id}-extra" if name_ordinal == 2 else f"{base_id}-extra-{name_ordinal}"
                        )
                        while candidate_id in used_group_ids:
                            name_ordinal += 1
                            candidate_id = (
                                f"{base_id}-extra" if name_ordinal == 2 else f"{base_id}-extra-{name_ordinal}"
                            )
                        fallback_name_counts[base_id] = name_ordinal
                        group_id = candidate_id
                    elif group_id in used_group_ids:
                        raise ProfileError(f"compact groups produce duplicate canonical id {group_id!r} on {platform}")
                    used_group_ids.add(group_id)
                    group = {
                        "id": group_id, "slot": slot_id, "stages": [], "action": first["action"],
                        "dns": first["dns"], "reject_mode": first["reject_mode"],
                        "extended_matching": first["extended_matching"], "no_resolve": first["no_resolve"],
                        "capability": capability, "rule_count": 0, "path": "", "dns_path": None,
                        "dns_kind": None, "dns_behavior": None, "dns_format": None,
                    }
                    groups.append(group)
                    group_rule_map[group_id] = []
                    for source_entry, source_rules in rules_with_sources:
                        if source_entry["source"] is not None and source_entry["source"] not in group["stages"]:
                            group["stages"].append(source_entry["source"])
                        group["rule_count"] += len(source_rules)
                        group_rule_map[group_id].extend(source_rules)

            if slot_id == "jp" and not any(group["slot"] == slot_id for group in groups):
                raise ProfileError("compact JP slot must reserve its stable route resource")

        if pending_ip:
            raise ProfileError(f"compact IP rules refer to unavailable later slots: {sorted(pending_ip)}")

        for group in groups:
            extension = "mrs" if platform == "mihomo" and group["capability"] == "domain" else (
                "set" if platform == "surge" and group["capability"] == "domain" else "list"
            )
            path = f"rules/personal/{platform}/route/{group['id']}.{extension}"
            group["path"] = path
            if path in output_files:
                raise ProfileError(f"compact groups produce duplicate output path {path}")
            rules = _stable_physical_rules(group_rule_map[group["id"]])
            group_rule_map[group["id"]] = rules
            group["rule_count"] = len(rules)
            content = _render_compact_group_file(platform, group, rules, root, converter_path, mrs_converter)
            if not content:
                raise ProfileError(f"generated compact resource {path} is empty")
            output_files[path] = content
            digest = sha256(content)
            group["sha256"] = digest
            group["bytes"] = len(content)
            group["kind"] = "route"
            group["behavior"] = "domain-set" if extension in {"mrs", "set"} else "classical"
            group["format"] = extension if extension in {"mrs", "set"} else "text"
            group["dns_path"] = path
            group["dns_kind"] = "route"
            group["dns_behavior"] = group["behavior"]
            group["dns_format"] = group["format"]

            platform_map = {"mihomo": None, "surge": None}
            platform_map[platform] = group["id"]
            stage = {
                "id": group["id"], "slot": group["slot"], "action": group["action"], "dns": group["dns"],
                "reject_mode": group["reject_mode"], "extended_matching": group["extended_matching"],
                "extended_matching_by_platform": {
                    "mihomo": False, "surge": group["extended_matching"] if platform == "surge" else False,
                },
                "no_resolve": group["no_resolve"], "sources": list(group["stages"]),
                "rules": list(group_rule_map[group["id"]]), "group_by_platform": platform_map,
            }
            stages_by_platform[platform].append(stage)
            manifest_stages[platform].append({
                "id": stage["id"], "slot": stage["slot"], "action": stage["action"], "dns": stage["dns"],
                "reject_mode": stage["reject_mode"], "extended_matching": stage["extended_matching"],
                "extended_matching_by_platform": dict(stage["extended_matching_by_platform"]),
                "no_resolve": stage["no_resolve"], "stages": list(stage["sources"]),
                "rule_count": len(stage["rules"]), "group_by_platform": dict(platform_map),
                "terminal_rule": None,
            })

        for fine in all_stages:
            terminal = next((rule for rule in fine["rules"] if rule.type in {"GEOIP", "MATCH"}), None)
            if terminal is None:
                continue
            platform_rules = [rule for rule in fine["rules"] if rule.platform == platform]
            stage = {
                "id": fine["id"], "action": fine["action"], "dns": fine["dns"],
                "reject_mode": fine["reject_mode"], "extended_matching": False,
                "extended_matching_by_platform": {"mihomo": False, "surge": False},
                "no_resolve": fine["no_resolve"], "sources": list(fine["sources"]),
                "rules": platform_rules, "group_by_platform": dict(fine["group_by_platform"]),
            }
            stages_by_platform[platform].append(stage)
            manifest_stages[platform].append({
                "id": stage["id"], "action": stage["action"], "dns": stage["dns"],
                "reject_mode": stage["reject_mode"], "extended_matching": False,
                "extended_matching_by_platform": {"mihomo": False, "surge": False},
                "no_resolve": stage["no_resolve"], "stages": [stage["id"]],
                "rule_count": len(platform_rules), "group_by_platform": dict(stage["group_by_platform"]),
                "terminal_rule": terminal.as_dict(include_line=False),
            })

    return output_files, groups_by_platform, stages_by_platform, manifest_stages


def _render_group_file(platform: str, group: Mapping[str, Any], rules: list[Rule], legacy_inputs: Mapping[str, bytes], root: Path, converter_path: str | Path | None) -> bytes:
    capability = group["capability"]
    if not rules:
        return b"# JP profile is intentionally empty.\n" if group["id"] == "jp-manual" else b""
    if capability == "domain":
        if platform == "surge":
            return _surge_domain_set(rules)
        stages = group["stages"]
        if stages == ["cn-direct-domain"]:
            return legacy_inputs["rules/mihomo/cn-direct-domain.mrs"]
        return _convert_mrs(_domain_text(rules), root, converter_path)
    return ("\n".join(rule.render() for rule in rules) + "\n").encode("utf-8")


@dataclass
class PersonalCandidate:
    files: dict[str, bytes]
    manifest: dict[str, Any]
    stages: list[dict[str, Any]]
    source_rules: dict[str, list[Rule]] = field(default_factory=dict)
    compact_stages: dict[str, list[dict[str, Any]]] = field(default_factory=dict)


def compile(
    snapshot: Mapping[str, bytes],
    legacy_inputs: Mapping[str, bytes],
    profile: Mapping[str, Any],
    *,
    root: str | Path = ROOT,
    converter_path: str | Path | None = None,
    mrs_converter: Callable[[bytes], bytes] | None = None,
) -> PersonalCandidate:
    """Purely compile snapshots, legacy outputs and an ordered profile.

    `files` includes the source archive and manifest, making the online update
    one transactional write. Supply ``mrs_converter`` in isolated parser tests;
    production runs validate and invoke the approved binary via `MIHOMO_CONVERTER`.
    """
    root_path = Path(root)
    normalized_profile = validate_profile(profile)
    if set(snapshot) != set(SOURCE_SPECS):
        missing, unexpected = set(SOURCE_SPECS) - set(snapshot), set(snapshot) - set(SOURCE_SPECS)
        raise ProfileError(f"Sukka snapshot IDs mismatch; missing={sorted(missing)}, unexpected={sorted(unexpected)}")
    parsed_sources: dict[str, list[Rule]] = {}
    source_metadata: dict[str, dict[str, Any]] = {}
    for source_id in sorted(SOURCE_SPECS):
        data = snapshot[source_id]
        rules = parse_source(data, source_id)
        parsed_sources[source_id] = rules
        source_metadata[source_id] = _source_metadata(source_id, data, rules)
    legacy_rules = parse_legacy_inputs(legacy_inputs)
    all_stages: list[dict[str, Any]] = []
    source_rules: dict[str, list[Rule]] = parsed_sources.copy()
    for raw_stage in normalized_profile["stages"]:
        stage = {
            "id": raw_stage["id"], "action": raw_stage["action"], "dns": raw_stage["dns"],
            "reject_mode": raw_stage.get("reject_mode"),
            "extended_matching": raw_stage.get("extended_matching", False),
            "extended_matching_by_platform": {},
            "no_resolve": raw_stage.get("no_resolve", False),
            "sources": list(raw_stage["sources"]), "rules": [],
            "group_by_platform": {"mihomo": None, "surge": None},
        }
        for platform in ("mihomo", "surge"):
            platform_rules = _stage_rules(raw_stage, platform, parsed_sources, legacy_rules, normalized_profile)
            extended_rules = [rule for rule in platform_rules if "extended-matching" in rule.flags]
            effective_extended = stage["extended_matching"]
            if extended_rules:
                if platform != "surge":
                    raise ProfileError(f"{stage['id']} uses extended-matching on unsupported {platform} rules")
                if len(extended_rules) != len(platform_rules):
                    raise ProfileError(
                        f"{stage['id']} mixes per-rule extended-matching with ordinary rules; split the source stage"
                    )
                effective_extended = True
                platform_rules = [
                    Rule(rule.type, rule.value, tuple(flag for flag in rule.flags if flag != "extended-matching"),
                         rule.source, rule.line, rule.platform)
                    for rule in platform_rules
                ]
            stage["extended_matching_by_platform"][platform] = effective_extended
            stage["rules"].extend(platform_rules)
        all_stages.append(stage)

    files: dict[str, bytes] = {}
    for source_id, data in snapshot.items():
        files[SOURCE_SPECS[source_id]["archive_path"]] = data

    groups_by_platform: dict[str, list[dict[str, Any]]] = {"mihomo": [], "surge": []}
    group_rule_map: dict[tuple[str, str], list[Rule]] = {}
    for platform in ("mihomo", "surge"):
        last_mergeable_group: dict[str, Any] | None = None
        for stage_index, (raw_stage, stage) in enumerate(zip(normalized_profile["stages"], all_stages)):
            rules = [rule for rule in stage["rules"] if rule.platform == platform]
            platform_stage = {
                **stage,
                "extended_matching": stage["extended_matching_by_platform"][platform],
            }
            # GEOIP and MATCH are direct client terminal rules, never rule-set files.
            if raw_stage.get("rule", {}).get("type") in {"GEOIP", "MATCH"}:
                # A terminal rule is an ordering barrier. Equal-action groups
                # on either side must remain separate so clients can emit the
                # terminal rule between their stable resource references.
                last_mergeable_group = None
                continue
            if not rules and raw_stage.get("members") != "jp_members":
                continue
            capability = _capability(rules)
            if stage["id"] == "jp-manual":
                # JP is a stable, always-classical route resource. It starts as
                # a genuine empty file and accepts future members without URL changes.
                capability = "classical"
            group = last_mergeable_group
            compatible = group is not None and _compatible(group, platform_stage, capability)
            if compatible and platform == "surge":
                # Surge exposes a set-level DNS requirement. Preserve this
                # boundary instead of adding resolving IP rules to a process-
                # or domain-only set and potentially resolving earlier.
                compatible = _requires_rule_dns(
                    group_rule_map[(platform, group["id"])], group["no_resolve"]
                ) == _requires_rule_dns(rules, platform_stage["no_resolve"])
            if not compatible:
                group = {
                    "id": stage["id"], "stages": [], "action": stage["action"], "dns": stage["dns"],
                    "reject_mode": stage["reject_mode"], "extended_matching": platform_stage["extended_matching"],
                    "no_resolve": stage["no_resolve"], "capability": capability, "path": "",
                    "rule_count": 0, "dns_path": None, "dns_kind": None,
                    "dns_behavior": None, "dns_format": None,
                }
                groups_by_platform[platform].append(group)
                group_rule_map[(platform, group["id"])] = []
            group["stages"].append(stage["id"])
            group["rule_count"] += len(rules)
            group_rule_map[(platform, group["id"])].extend(rules)
            stage["group_by_platform"][platform] = group["id"]
            last_mergeable_group = group

    group_hashes: dict[str, dict[str, str]] = {"mihomo": {}, "surge": {}}
    for platform, groups in groups_by_platform.items():
        for group in groups:
            extension = "mrs" if platform == "mihomo" and group["capability"] == "domain" else (
                "set" if platform == "surge" and group["capability"] == "domain" else "list"
            )
            path = f"rules/personal/{platform}/{group['id']}.{extension}"
            group["path"] = path
            rules = group_rule_map[(platform, group["id"]) ]
            content = _render_group_file(platform, group, rules, legacy_inputs, root_path, converter_path) if mrs_converter is None else (
                mrs_converter(_domain_text(rules)) if platform == "mihomo" and group["capability"] == "domain" and group["stages"] != ["cn-direct-domain"]
                else _render_group_file(platform, group, rules, legacy_inputs, root_path, converter_path)
            )
            if not content and group["id"] != "jp-manual":
                raise ProfileError(f"generated resource {path} is empty")
            files[path] = content
            group["sha256"] = sha256(content)
            group["bytes"] = len(content)
            group["kind"] = "route"
            group["behavior"] = "domain-set" if extension in {"mrs", "set"} else "classical"
            group["format"] = extension if extension in {"mrs", "set"} else "text"
            domain_rules = [rule for rule in rules if rule.is_domain]
            group["dns_path"] = None
            if group["dns"] == "jp":
                # A separate domain-only JP DNS selector remains present while
                # empty and keeps a stable path even if JP later adds IP rules.
                dns_path = f"rules/personal/{platform}/dns-jp-manual.list"
                dns_bytes = (
                    ("\n".join(rule.render() for rule in domain_rules) + "\n").encode("utf-8")
                    if domain_rules else b"# JP DNS selector is intentionally empty.\n"
                )
                files[dns_path] = dns_bytes
                group["dns_path"] = dns_path
                group["dns_kind"] = "dns-selector"
                group["dns_behavior"] = "classical"
                group["dns_format"] = "text"
                group["dns_sha256"] = sha256(dns_bytes)
                group["dns_bytes"] = len(dns_bytes)
            elif group["dns"] != "none" and domain_rules:
                if len(domain_rules) == len(rules):
                    group["dns_path"] = path
                    group["dns_kind"] = "route"
                    group["dns_behavior"] = group["behavior"]
                    group["dns_format"] = group["format"]
                else:
                    dns_capability = _capability(domain_rules)
                    dns_extension = "mrs" if platform == "mihomo" and dns_capability == "domain" else (
                        "set" if platform == "surge" and dns_capability == "domain" else "list"
                    )
                    dns_path = f"rules/personal/{platform}/dns-{group['id']}.{dns_extension}"
                    if dns_capability == "domain" and platform == "mihomo":
                        dns_bytes = _convert_mrs(_domain_text(domain_rules), root_path, converter_path) if mrs_converter is None else mrs_converter(_domain_text(domain_rules))
                    elif dns_capability == "domain" and platform == "surge":
                        dns_bytes = _surge_domain_set(domain_rules)
                    else:
                        dns_bytes = ("\n".join(rule.render() for rule in domain_rules) + "\n").encode("utf-8")
                    files[dns_path] = dns_bytes
                    group["dns_path"] = dns_path
                    group["dns_kind"] = "dns-selector"
                    group["dns_behavior"] = "domain-set" if dns_extension in {"mrs", "set"} else "classical"
                    group["dns_format"] = dns_extension if dns_extension in {"mrs", "set"} else "text"
                    group["dns_sha256"] = sha256(dns_bytes)
                    group["dns_bytes"] = len(dns_bytes)
            group_hashes[platform][path] = sha256(content)
            if group.get("dns_path") and group["dns_path"] != path:
                group_hashes[platform][group["dns_path"]] = group["dns_sha256"]

    compact_files, compact_groups, compact_stages, compact_manifest_stages = _compile_compact(
        normalized_profile, all_stages, root=root_path,
        converter_path=converter_path, mrs_converter=mrs_converter,
    )
    collisions = set(files) & set(compact_files)
    if collisions:
        raise ProfileError(f"compact resources collide with existing personal outputs: {sorted(collisions)}")
    files.update(compact_files)

    source_hashes = {path: sha256(data) for path, data in sorted(legacy_inputs.items())}
    output_hashes = {path: digest for platform_hashes in group_hashes.values() for path, digest in platform_hashes.items()}
    output_hashes.update({path: sha256(data) for path, data in compact_files.items()})
    profile_hash = sha256(canonical_bytes(normalized_profile))
    manifest = {
        "schema": SCHEMA,
        "profile": {"id": normalized_profile["id"], "path": PROFILE_PATH, "sha256": profile_hash},
        "sources": source_metadata,
        "legacy_inputs": {path: {"sha256": digest, "bytes": len(legacy_inputs[path])} for path, digest in sorted(source_hashes.items())},
        "stages": [
            {
                "id": stage["id"], "action": stage["action"], "dns": stage["dns"],
                "reject_mode": stage["reject_mode"], "extended_matching": stage["extended_matching"],
                "extended_matching_by_platform": dict(stage["extended_matching_by_platform"]),
                "no_resolve": stage["no_resolve"], "sources": stage["sources"],
                "rule_count": sum(1 for rule in stage["rules"]),
                "rule_count_by_platform": {
                    platform: sum(1 for rule in stage["rules"] if rule.platform == platform)
                    for platform in ("mihomo", "surge")
                },
                "group_by_platform": dict(stage["group_by_platform"]),
                "terminal_rule": next((r.as_dict(include_line=False) for r in stage["rules"] if r.type in {"GEOIP", "MATCH"}), None),
            }
            for stage in all_stages
        ],
        "groups": groups_by_platform,
        "compact": {"schema": 1, "groups": compact_groups, "stages": compact_manifest_stages},
        "outputs": {path: {"sha256": digest, "bytes": len(files[path])} for path, digest in sorted(output_hashes.items())},
    }
    files[MANIFEST_PATH] = pretty_json_bytes(manifest)
    return PersonalCandidate(files, manifest, all_stages, source_rules, compact_stages)


def replay(snapshot: Mapping[str, bytes], legacy_inputs: Mapping[str, bytes], profile: Mapping[str, Any], **kwargs: Any) -> PersonalCandidate:
    """API alias emphasizing deterministic replay from archived bytes."""
    return compile(snapshot, legacy_inputs, profile, **kwargs)


def _read_bytes(root: Path, relative: str, label: str) -> bytes:
    path = root / relative
    try:
        return path.read_bytes()
    except OSError as exc:
        raise ProfileError(f"cannot read {label} {relative}: {exc}") from exc


def load_profile(root: str | Path = ROOT) -> dict[str, Any]:
    path = Path(root) / PROFILE_PATH
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProfileError(f"cannot read profile {PROFILE_PATH}: {exc}") from exc


def replay_offline(root: str | Path = ROOT, *, converter_path: str | Path | None = None) -> PersonalCandidate:
    root_path = Path(root)
    profile = load_profile(root_path)
    snapshot = {source_id: _read_bytes(root_path, spec["archive_path"], "source snapshot") for source_id, spec in SOURCE_SPECS.items()}
    legacy = {path: _read_bytes(root_path, path, "legacy input") for path in LEGACY_INPUT_PATHS}
    return replay(snapshot, legacy, profile, root=root_path, converter_path=converter_path)


def validate_bundle(root: str | Path = ROOT, *, converter_path: str | Path | None = None) -> PersonalCandidate:
    root_path = Path(root)
    candidate = replay_offline(root_path, converter_path=converter_path)
    expected = set(candidate.files)
    personal_roots = (root_path / "rules/personal", root_path / "upstream/personal")
    actual: set[str] = set()
    for base in personal_roots:
        if base.exists():
            actual.update(path.relative_to(root_path).as_posix() for path in base.rglob("*") if path.is_file())
    expected_personal = {path for path in expected if path.startswith("rules/personal/") or path.startswith("upstream/personal/")}
    if actual != expected_personal:
        raise ProfileError(f"personal bundle paths mismatch; missing={sorted(expected_personal - actual)}, unexpected={sorted(actual - expected_personal)}")
    mismatches: list[str] = []
    for relative, expected_bytes in candidate.files.items():
        try:
            current = (root_path / relative).read_bytes()
        except OSError:
            mismatches.append(relative)
            continue
        if current != expected_bytes:
            mismatches.append(relative)
    if mismatches:
        raise ProfileError("offline personal replay differs from current bundle: " + ", ".join(sorted(mismatches)))
    return candidate


def _fetch_one(source_id: str) -> tuple[str, bytes]:
    spec = SOURCE_SPECS[source_id]
    url = urllib.parse.urlparse(spec["url"])
    if url.scheme != "https" or url.hostname != "ruleset-mirror.skk.moe":
        raise ProfileError(f"refusing unapproved source URL for {source_id}")
    request = urllib.request.Request(spec["url"], headers={"User-Agent": "zesming-personal-profile/1", "Accept": "text/plain"})
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            final = urllib.parse.urlparse(response.geturl())
            if response.status != 200 or final.scheme != "https" or final.hostname != url.hostname:
                raise ProfileError(f"HTTP/redirect validation failed for {source_id}")
            maximum = int(spec["max_bytes"])
            raw_length = response.headers.get("Content-Length")
            declared_length: int | None = None
            if raw_length is not None:
                if not isinstance(raw_length, str) or not re.fullmatch(r"[0-9]+", raw_length):
                    raise ProfileError(f"{source_id} has an invalid Content-Length")
                declared_length = int(raw_length)
                if declared_length > maximum:
                    raise ProfileError(f"{source_id} exceeds its byte limit")

            chunks: list[bytes] = []
            received = 0
            while True:
                read_size = min(64 * 1024, maximum + 1 - received)
                chunk = response.read(read_size)
                if not chunk:
                    break
                chunks.append(chunk)
                received += len(chunk)
                if received > maximum:
                    raise ProfileError(f"{source_id} exceeds its byte limit")
            if declared_length is not None and received != declared_length:
                raise ProfileError(
                    f"{source_id} Content-Length mismatch: declared {declared_length} bytes, received {received}"
                )
            data = b"".join(chunks)
    except ProfileError:
        raise
    except Exception as exc:
        raise ProfileError(f"could not fetch {source_id}: {exc}") from exc
    return source_id, data


def fetch_sources() -> dict[str, bytes]:
    """Fetch all registered Sukka sources, retrying only incomplete fetches."""
    result: dict[str, bytes] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        pending = sorted(SOURCE_SPECS)
        errors: dict[str, Exception] = {}
        for attempt in range(len(SOURCE_FETCH_RETRY_DELAYS) + 1):
            futures = {pool.submit(_fetch_one, source_id): source_id for source_id in pending}
            errors = {}
            for future in concurrent.futures.as_completed(futures):
                source_id = futures[future]
                try:
                    key, data = future.result()
                    result[key] = data
                except Exception as exc:
                    errors[source_id] = exc
            if not errors:
                return result
            pending = sorted(errors)
            if attempt < len(SOURCE_FETCH_RETRY_DELAYS):
                time.sleep(SOURCE_FETCH_RETRY_DELAYS[attempt])
    if errors:
        details = "; ".join(f"{source_id}: {errors[source_id]}" for source_id in sorted(errors))
        raise ProfileError(
            f"Sukka source fetch failed after {len(SOURCE_FETCH_RETRY_DELAYS) + 1} attempts: {details}"
        )
    return result


def _snapshot_parse_errors(snapshot: Mapping[str, bytes]) -> list[str]:
    errors: list[str] = []
    for source_id in sorted(SOURCE_SPECS):
        try:
            parse_source(snapshot[source_id], source_id)
        except ProfileError as exc:
            errors.append(f"{source_id}: {exc}")
    return errors


def _save_failed_snapshot(root: Path, snapshot: Mapping[str, bytes], errors: Iterable[str]) -> None:
    """Keep fetched public inputs only on parse failure, under ignored diagnostics."""
    directory = root / ".build-report/personal-inputs"
    directory.mkdir(parents=True, exist_ok=True)
    for source_id, spec in SOURCE_SPECS.items():
        data = snapshot.get(source_id)
        if data is None:
            continue
        relative = Path(spec["archive_path"]).relative_to("upstream/personal")
        _atomic_write(directory, relative.as_posix(), data)
    report = ("\n".join(errors) + "\n").encode("utf-8")
    _atomic_write(directory, "parse-errors.txt", report)


def _assert_personal_update_allowed(root: Path) -> None:
    """Honor the repository-wide release hold for direct personal updates."""
    policy_path = root / "policy.json"
    try:
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProfileError(f"cannot read policy.json publish hold: {exc}") from exc
    hold = policy.get("publish_hold") if isinstance(policy, Mapping) else None
    if not isinstance(hold, Mapping) or not isinstance(hold.get("enabled"), bool):
        raise ProfileError("policy.json has no valid publish_hold.enabled; refusing personal update")
    if hold["enabled"]:
        reason = hold.get("reason", "")
        detail = f": {reason}" if isinstance(reason, str) and reason.strip() else ""
        raise ProfileError("personal update is blocked by policy.publish_hold" + detail)


def _valid_personal_relative_path(path: Any, prefix: str) -> bool:
    if (
        not isinstance(path, str) or not path or "\\" in path or "\x00" in path
        or path.startswith("/") or re.match(r"^[A-Za-z]:", path) is not None
        or not path.startswith(prefix)
    ):
        return False
    return all(part not in {"", ".", ".."} for part in path.split("/"))


def _manifest_digest_size(metadata: Any) -> tuple[str, int] | None:
    if not isinstance(metadata, Mapping):
        return None
    digest = metadata.get("sha256")
    size = metadata.get("bytes")
    if (
        not isinstance(digest, str) or HEX_256.fullmatch(digest) is None
        or not isinstance(size, int) or isinstance(size, bool) or size <= 0
    ):
        return None
    return digest, size


def _stale_legacy_compact_paths(
    previous: Mapping[str, Any] | None, current_files: Mapping[str, bytes],
) -> list[str]:
    """Find absent, manifest-owned personal outputs and source archives safely."""
    if previous is None:
        return []

    # Each generated output must be present in both `outputs` and an owning
    # fine/compact group with the same digest and size. This prevents an
    # unrelated or malformed output entry from authorizing a deletion.
    owners: dict[str, set[tuple[str, int]]] = {}

    def add_owner(path: Any, prefix: str, digest: Any, size: Any) -> None:
        metadata = _manifest_digest_size({"sha256": digest, "bytes": size})
        if metadata is not None and _valid_personal_relative_path(path, prefix):
            owners.setdefault(path, set()).add(metadata)

    raw_groups = previous.get("groups")
    for platform in ("mihomo", "surge"):
        prefix = f"rules/personal/{platform}/"
        platform_groups = raw_groups.get(platform) if isinstance(raw_groups, Mapping) else None
        if isinstance(platform_groups, list):
            for group in platform_groups:
                if not isinstance(group, Mapping):
                    continue
                add_owner(group.get("path"), prefix, group.get("sha256"), group.get("bytes"))
                dns_path = group.get("dns_path")
                if dns_path and dns_path != group.get("path"):
                    add_owner(dns_path, prefix, group.get("dns_sha256"), group.get("dns_bytes"))

    raw_compact = previous.get("compact")
    compact_groups = raw_compact.get("groups") if isinstance(raw_compact, Mapping) else None
    for platform in ("mihomo", "surge"):
        prefix = f"rules/personal/{platform}/"
        platform_groups = compact_groups.get(platform) if isinstance(compact_groups, Mapping) else None
        if not isinstance(platform_groups, list):
            continue
        ordinals: dict[tuple[str, str], int] = {}
        for group in platform_groups:
            if not isinstance(group, Mapping):
                continue
            slot, capability = group.get("slot"), group.get("capability")
            expected_legacy_id = None
            if isinstance(slot, str) and isinstance(capability, str):
                key = (slot, capability)
                ordinals[key] = ordinals.get(key, 0) + 1
                expected_legacy_id = f"priority-{slot}-{capability}"
                if ordinals[key] > 1:
                    expected_legacy_id += f"-{ordinals[key]}"

            path = group.get("path")
            if not _valid_personal_relative_path(path, prefix):
                continue
            parts = path.split("/")
            is_route_path = (
                len(parts) == 5 and parts[:4] == ["rules", "personal", platform, "route"]
                and re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*\.(?:list|mrs|set)", parts[4]) is not None
            )
            is_old_root_path = (
                len(parts) == 4 and expected_legacy_id is not None
                and group.get("id") == expected_legacy_id
                and re.fullmatch(re.escape(expected_legacy_id) + r"\.(?:list|mrs|set)", parts[3]) is not None
            )
            if is_route_path or is_old_root_path:
                add_owner(path, prefix, group.get("sha256"), group.get("bytes"))

    stale: set[str] = set()
    outputs = previous.get("outputs")
    if isinstance(outputs, Mapping):
        for path, tracked in outputs.items():
            if not isinstance(path, str) or path in current_files:
                continue
            platform_prefix = next((
                f"rules/personal/{platform}/" for platform in ("mihomo", "surge")
                if _valid_personal_relative_path(path, f"rules/personal/{platform}/")
            ), None)
            if platform_prefix is None or not _valid_personal_relative_path(path, platform_prefix):
                continue
            metadata = _manifest_digest_size(tracked)
            if metadata is not None and metadata in owners.get(path, set()):
                stale.add(path)

    sources = previous.get("sources")
    if isinstance(sources, Mapping):
        for source in sources.values():
            if not isinstance(source, Mapping):
                continue
            platform = source.get("platform")
            if not isinstance(platform, str) or platform not in {"mihomo", "surge"}:
                continue
            path = source.get("archive_path")
            prefix = f"upstream/personal/{platform}/"
            if (
                isinstance(path, str) and path not in current_files
                and _valid_personal_relative_path(path, prefix)
                and _manifest_digest_size(source) is not None
            ):
                stale.add(path)
    return sorted(stale)


def _atomic_write(root: Path, relative: str, content: bytes) -> Path:
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=target.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()
    return target


def write_bundle_transactionally(root: str | Path, files: Mapping[str, bytes], *, delete_paths: Iterable[str] = ()) -> None:
    root_path = Path(root)
    writes = dict(files)
    deletes = set(delete_paths) - set(writes)
    allowed_prefixes = ("rules/personal/", "upstream/personal/")
    for relative in set(writes) | deletes:
        path = Path(relative)
        if path.is_absolute() or ".." in path.parts or not relative.startswith(allowed_prefixes):
            raise ProfileError(f"refusing to write outside the personal bundle: {relative}")
        if relative in writes and not isinstance(writes[relative], bytes):
            raise ProfileError(f"transaction content for {relative} must be bytes")
    originals: dict[str, bytes | None] = {}
    replaced: list[str] = []
    try:
        for relative in sorted(set(writes) | deletes):
            target = root_path / relative
            originals[relative] = target.read_bytes() if target.is_file() else None
        for relative in sorted(writes):
            _atomic_write(root_path, relative, writes[relative])
            replaced.append(relative)
        for relative in sorted(deletes):
            target = root_path / relative
            if target.exists():
                target.unlink()
                replaced.append(relative)
    except Exception as exc:
        restore_errors: list[str] = []
        for relative in reversed(replaced):
            try:
                old = originals.get(relative)
                target = root_path / relative
                if old is None:
                    if target.exists():
                        target.unlink()
                else:
                    _atomic_write(root_path, relative, old)
            except Exception as restore_exc:
                restore_errors.append(f"{relative}: {restore_exc}")
        suffix = "; rollback errors: " + "; ".join(restore_errors) if restore_errors else ""
        raise ProfileError(f"personal bundle write failed and prior files were restored: {exc}{suffix}") from exc


def update(
    root: str | Path = ROOT, *, offline: bool = False, converter_path: str | Path | None = None,
    accept_interface_change: bool = False,
) -> PersonalCandidate:
    root_path = Path(root)
    _assert_personal_update_allowed(root_path)
    profile = load_profile(root_path)
    snapshot = (
        {source_id: _read_bytes(root_path, spec["archive_path"], "source snapshot") for source_id, spec in SOURCE_SPECS.items()}
        if offline else fetch_sources()
    )
    parse_errors = _snapshot_parse_errors(snapshot)
    if parse_errors:
        _save_failed_snapshot(root_path, snapshot, parse_errors)
        raise ProfileError(
            f"{len(parse_errors)} Sukka source(s) failed parsing; details and fetched public inputs are in "
            ".build-report/personal-inputs/"
        )
    legacy = {path: _read_bytes(root_path, path, "legacy input") for path in LEGACY_INPUT_PATHS}
    previous: Mapping[str, Any] | None = None
    manifest_path = root_path / MANIFEST_PATH
    if manifest_path.exists():
        try:
            previous_obj = json.loads(manifest_path.read_text(encoding="utf-8"))
            if not isinstance(previous_obj, Mapping):
                raise ProfileError("previous personal manifest must be a JSON object; refusing first-publish fallback")
            previous = previous_obj
        except ProfileError:
            raise
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProfileError(f"cannot read prior personal manifest: {exc}") from exc
    candidate = compile(snapshot, legacy, profile, root=root_path, converter_path=converter_path)
    _require_stable_client_interface(
        previous, candidate.manifest, accept_change=accept_interface_change, report_root=root_path,
    )
    stale = _stale_legacy_compact_paths(previous, candidate.files)
    write_bundle_transactionally(root_path, candidate.files, delete_paths=stale)
    return candidate


# --- Ordered matching API for behavior comparison ---------------------------------

def _as_rule(value: Rule | Mapping[str, Any]) -> Rule:
    if isinstance(value, Rule):
        return value
    flags = value.get("flags", ())
    if not isinstance(flags, (list, tuple)):
        flags = ()
    return Rule(
        str(value["type"]), str(value["value"]), tuple(str(flag) for flag in flags),
        str(value.get("source", "")), int(value.get("line", 0)), str(value.get("platform", "")),
    )


def _wildcard_match(value: str, pattern: str) -> bool:
    """Match only the * and ? wildcards documented by the client rule type."""
    expression = re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".")
    return re.fullmatch(expression, value, flags=re.DOTALL) is not None


def _surge_process_match(pattern: str, process: str) -> bool:
    if pattern.startswith("/") and pattern.endswith("/"):
        # Surge's /Applications/Foo.app/ form matches executable paths in that
        # bundle, including Contents/MacOS descendants.
        return process.startswith(pattern)
    if pattern.startswith("/"):
        return _wildcard_match(process, pattern)
    filename = process.rsplit("/", 1)[-1]
    return _wildcard_match(filename, pattern)


def rule_matches(
    rule: Rule | Mapping[str, Any], *, domain: str | None = None, ip: str | None = None,
    process: str | None = None, user_agent: str | None = None, asn: int | str | None = None,
    geoip: str | None = None, country: str | None = None, url: str | None = None,
    protocol: str | None = None,
) -> bool:
    item = _as_rule(rule)
    if item.type == "DOMAIN":
        return domain is not None and canonical_domain(domain, "host") == item.value
    if item.type == "DOMAIN-SUFFIX":
        host = canonical_domain(domain, "host") if domain is not None else ""
        return bool(host) and (host == item.value or host.endswith("." + item.value))
    if item.type == "DOMAIN-KEYWORD":
        host = canonical_domain(domain, "host") if domain is not None else ""
        return bool(host) and item.value in host
    if item.type == "DOMAIN-WILDCARD":
        host = canonical_domain(domain, "host") if domain is not None else ""
        return bool(host) and _wildcard_match(host, item.value)
    if item.type in {"IP-CIDR", "IP-CIDR6"}:
        try:
            address = ipaddress.ip_address(ip) if ip is not None else None
            network = ipaddress.ip_network(item.value)
        except ValueError:
            return False
        return address is not None and address.version == network.version and address in network
    if item.type == "IP-ASN":
        if asn is None:
            return False
        value = str(asn).upper().removeprefix("AS")
        return value.isdecimal() and int(value) == int(item.value)
    if item.type == "PROCESS-NAME":
        if process is None:
            return False
        if item.platform == "mihomo":
            return process.casefold() == item.value.casefold()
        return _surge_process_match(item.value, process)
    if item.type == "PROCESS-NAME-WILDCARD":
        return process is not None and _wildcard_match(process.casefold(), item.value.casefold())
    if item.type == "USER-AGENT":
        return user_agent is not None and _wildcard_match(user_agent, item.value)
    if item.type == "URL-REGEX":
        return url is not None and re.search(item.value, url) is not None
    if item.type == "AND":
        components = _and_components(item.value)
        expected_protocol = next(value for kind, value in components if kind == "PROTOCOL")
        kind, expected_domain = next((kind, value) for kind, value in components if kind != "PROTOCOL")
        domain_rule = Rule(kind, expected_domain, platform=item.platform)
        return (
            protocol is not None and protocol.upper() == expected_protocol.upper()
            and rule_matches(domain_rule, domain=domain)
        )
    if item.type == "GEOIP":
        observed = geoip if geoip is not None else country
        return observed is not None and observed.upper() == item.value.upper()
    if item.type == "MATCH":
        return True
    raise ProfileError(f"matcher does not support rule type {item.type!r}")


@dataclass(frozen=True)
class MatchResult:
    stage: Mapping[str, Any]
    rule: Rule
    stage_index: int
    rule_index: int

    @property
    def action(self) -> str:
        return str(self.stage["action"])

    @property
    def dns(self) -> str:
        return str(self.stage.get("dns", "none"))

    @property
    def reject_mode(self) -> str | None:
        value = self.stage.get("reject_mode")
        return str(value) if value is not None else None


@dataclass
class _Trie:
    children: dict[Any, "_Trie"] = field(default_factory=dict)
    entries: list[tuple[int, int, Mapping[str, Any], Rule]] = field(default_factory=list)


class _KeywordAutomaton:
    def __init__(self, patterns: list[tuple[str, tuple[int, int, Mapping[str, Any], Rule]]]):
        self.goto: list[dict[str, int]] = [{}]
        self.fail: list[int] = [0]
        self.output: list[list[tuple[int, int, Mapping[str, Any], Rule]]] = [[]]
        for pattern, entry in patterns:
            state = 0
            for char in pattern:
                next_state = self.goto[state].get(char)
                if next_state is None:
                    next_state = len(self.goto)
                    self.goto[state][char] = next_state
                    self.goto.append({})
                    self.fail.append(0)
                    self.output.append([])
                state = next_state
            self.output[state].append(entry)
        queue = list(self.goto[0].values())
        cursor = 0
        while cursor < len(queue):
            state = queue[cursor]
            cursor += 1
            for char, child in self.goto[state].items():
                queue.append(child)
                failure = self.fail[state]
                while failure and char not in self.goto[failure]:
                    failure = self.fail[failure]
                self.fail[child] = self.goto[failure].get(char, 0)
                self.output[child].extend(self.output[self.fail[child]])

    def find(self, text: str) -> list[tuple[int, int, Mapping[str, Any], Rule]]:
        state = 0
        found: list[tuple[int, int, Mapping[str, Any], Rule]] = []
        for char in text:
            while state and char not in self.goto[state]:
                state = self.fail[state]
            state = self.goto[state].get(char, 0)
            found.extend(self.output[state])
        return found


class RuleIndex:
    """Build once, then answer first-match queries without scanning every rule."""

    def __init__(self, stages: Iterable[Mapping[str, Any]], platform: str):
        if platform not in {"mihomo", "surge"}:
            raise ProfileError("RuleIndex platform must be mihomo or surge")
        self.platform = platform
        self.exact: dict[str, list[tuple[int, int, Mapping[str, Any], Rule]]] = {}
        self.suffix = _Trie()
        self.ipv4 = _Trie()
        self.ipv6 = _Trie()
        self.asn: dict[str, list[tuple[int, int, Mapping[str, Any], Rule]]] = {}
        self.process: dict[str, list[tuple[int, int, Mapping[str, Any], Rule]]] = {}
        self.process_patterns: list[tuple[int, int, Mapping[str, Any], Rule]] = []
        keyword_patterns: list[tuple[str, tuple[int, int, Mapping[str, Any], Rule]]] = []
        self.wildcard_root = _Trie()
        self.wildcard_any: list[tuple[int, int, Mapping[str, Any], Rule]] = []
        self.user_agent: list[tuple[str, tuple[int, int, Mapping[str, Any], Rule]]] = []
        self.url_regex: list[tuple[re.Pattern[str], tuple[int, int, Mapping[str, Any], Rule]]] = []
        self.compound: list[tuple[int, int, Mapping[str, Any], Rule]] = []
        self.geoip: dict[str, list[tuple[int, int, Mapping[str, Any], Rule]]] = {}
        self.terminals: list[tuple[int, int, Mapping[str, Any], Rule]] = []
        self.comparison_limitations: list[dict[str, str]] = []
        self.limitations = self.comparison_limitations
        limitation_keys: set[tuple[str, str]] = set()

        def add_limitation(stage_id: Any, kind: str, reason: str) -> None:
            key = str(stage_id), kind
            if key not in limitation_keys:
                limitation_keys.add(key)
                self.comparison_limitations.append({"stage": key[0], "type": kind, "reason": reason})

        for stage_index, stage in enumerate(stages):
            raw_rules = stage.get("rules", [])
            if not isinstance(raw_rules, list):
                raise ProfileError(f"stage {stage.get('id')} rules must be an array")
            stage_extended = stage.get("extended_matching_by_platform", {}).get(platform, stage.get("extended_matching", False))
            if stage_extended:
                add_limitation(
                    stage.get("id", ""), "extended-matching",
                    "requires client SNI/HTTP Host inspection, which RuleIndex does not model",
                )
            if stage.get("no_resolve"):
                add_limitation(
                    stage.get("id", ""), "no-resolve",
                    "requires client DNS-resolution state, which RuleIndex does not model",
                )
            for rule_index, raw_rule in enumerate(raw_rules):
                item = _as_rule(raw_rule)
                if item.platform != platform:
                    continue
                if item.type in {"USER-AGENT", "URL-REGEX", "AND"} and platform != "surge":
                    raise ProfileError(f"RuleIndex cannot use {item.type} on {platform}")
                if item.type == "PROCESS-NAME-WILDCARD" and platform != "mihomo":
                    raise ProfileError(f"RuleIndex cannot use PROCESS-NAME-WILDCARD on {platform}")
                entry = (stage_index, rule_index, stage, item)
                if "no-resolve" in item.flags and not stage.get("no_resolve"):
                    add_limitation(
                        stage.get("id", ""), "no-resolve",
                        "requires client DNS-resolution state, which RuleIndex does not model",
                    )
                if item.type == "URL-REGEX":
                    add_limitation(
                        stage.get("id", ""), "URL-REGEX",
                        "requires a full request URL; HTTPS path visibility depends on MITM",
                    )
                if item.type == "DOMAIN":
                    self.exact.setdefault(item.value, []).append(entry)
                elif item.type == "DOMAIN-SUFFIX":
                    node = self.suffix
                    for label in reversed(item.value.split(".")):
                        node = node.children.setdefault(label, _Trie())
                    node.entries.append(entry)
                elif item.type == "DOMAIN-KEYWORD":
                    keyword_patterns.append((item.value, entry))
                elif item.type == "DOMAIN-WILDCARD":
                    tail = item.value.rsplit("*", 1)[-1].rsplit("?", 1)[-1]
                    if not tail:
                        self.wildcard_any.append(entry)
                    else:
                        node = self.wildcard_root
                        for char in reversed(tail):
                            node = node.children.setdefault(char, _Trie())
                        node.entries.append(entry)
                elif item.type in {"IP-CIDR", "IP-CIDR6"}:
                    network = ipaddress.ip_network(item.value)
                    node = self.ipv4 if network.version == 4 else self.ipv6
                    number = int(network.network_address)
                    for prefix_index in range(network.prefixlen):
                        bit = network.max_prefixlen - 1 - prefix_index
                        branch = (number >> bit) & 1
                        node = node.children.setdefault(branch, _Trie())
                    node.entries.append(entry)
                elif item.type == "IP-ASN":
                    self.asn.setdefault(item.value, []).append(entry)
                elif item.type == "PROCESS-NAME":
                    if platform == "mihomo":
                        self.process.setdefault(item.value.casefold(), []).append(entry)
                    elif (item.value.startswith("/") and item.value.endswith("/")) or any(
                        mark in item.value for mark in "*?"
                    ):
                        self.process_patterns.append(entry)
                    else:
                        key = item.value if item.value.startswith("/") else item.value.rsplit("/", 1)[-1]
                        self.process.setdefault(key, []).append(entry)
                elif item.type == "PROCESS-NAME-WILDCARD":
                    self.process_patterns.append(entry)
                elif item.type == "USER-AGENT":
                    self.user_agent.append((item.value, entry))
                elif item.type == "URL-REGEX":
                    self.url_regex.append((re.compile(item.value), entry))
                elif item.type == "AND":
                    self.compound.append(entry)
                elif item.type == "GEOIP":
                    self.geoip.setdefault(item.value.upper(), []).append(entry)
                elif item.type == "MATCH":
                    self.terminals.append(entry)
                else:
                    raise ProfileError(f"RuleIndex does not support {item.type!r}")
        self.keyword_automaton = _KeywordAutomaton(keyword_patterns) if keyword_patterns else None

    @staticmethod
    def _suffix_entries(root: _Trie, labels: Iterable[str]) -> list[tuple[int, int, Mapping[str, Any], Rule]]:
        node = root
        found = list(node.entries)
        for label in labels:
            child = node.children.get(label)
            if child is None:
                break
            node = child
            found.extend(node.entries)
        return found

    def matching_rules(
        self, *, domain: str | None = None, ip: str | None = None, process: str | None = None,
        user_agent: str | None = None, asn: int | str | None = None, geoip: str | None = None,
        country: str | None = None, url: str | None = None, protocol: str | None = None,
    ) -> list[MatchResult]:
        found: list[tuple[int, int, Mapping[str, Any], Rule]] = []
        if domain is not None:
            host = canonical_domain(domain, "host")
            found.extend(self.exact.get(host, ()))
            found.extend(self._suffix_entries(self.suffix, reversed(host.split("."))))
            if self.keyword_automaton is not None:
                found.extend(self.keyword_automaton.find(host))
            node = self.wildcard_root
            for char in reversed(host):
                child = node.children.get(char)
                if child is None:
                    break
                node = child
                for entry in node.entries:
                    if rule_matches(entry[3], domain=host):
                        found.append(entry)
            found.extend(entry for entry in self.wildcard_any if rule_matches(entry[3], domain=host))
        if ip is not None:
            try:
                address = ipaddress.ip_address(ip)
            except ValueError:
                address = None
            if address is not None:
                node = self.ipv4 if address.version == 4 else self.ipv6
                found.extend(node.entries)
                number = int(address)
                for bit in range(address.max_prefixlen - 1, -1, -1):
                    node = node.children.get((number >> bit) & 1)
                    if node is None:
                        break
                    found.extend(node.entries)
        if asn is not None:
            asn_text = str(asn).upper().removeprefix("AS")
            found.extend(self.asn.get(asn_text, ()))
        if process is not None:
            if self.platform == "mihomo":
                found.extend(self.process.get(process.casefold(), ()))
            else:
                exact_keys = {process, process.rsplit("/", 1)[-1]}
                for exact_key in exact_keys:
                    found.extend(self.process.get(exact_key, ()))
            found.extend(
                entry for entry in self.process_patterns
                if (entry[3].type == "PROCESS-NAME-WILDCARD"
                    and _wildcard_match(process.casefold(), entry[3].value.casefold()))
                or (entry[3].type == "PROCESS-NAME" and self.platform == "surge"
                    and _surge_process_match(entry[3].value, process))
            )
        if user_agent is not None:
            found.extend(entry for pattern, entry in self.user_agent if _wildcard_match(user_agent, pattern))
        if url is not None:
            found.extend(entry for pattern, entry in self.url_regex if pattern.search(url))
        if protocol is not None or domain is not None:
            found.extend(
                entry for entry in self.compound
                if rule_matches(entry[3], domain=domain, protocol=protocol)
            )
        observed_country = geoip if geoip is not None else country
        if observed_country is not None:
            found.extend(self.geoip.get(observed_country.upper(), ()))
        found.extend(self.terminals)
        unique: dict[tuple[int, int], tuple[int, int, Mapping[str, Any], Rule]] = {}
        for entry in found:
            unique[(entry[0], entry[1])] = entry
        ordered = sorted(unique.values(), key=lambda entry: (entry[0], entry[1]))
        return [MatchResult(entry[2], entry[3], entry[0], entry[1]) for entry in ordered]

    def first_match(self, **subject: Any) -> MatchResult | None:
        matches = self.matching_rules(**subject)
        return matches[0] if matches else None


def first_match(stages: Iterable[Mapping[str, Any]], platform: str, **subject: Any) -> MatchResult | None:
    """Convenience wrapper; callers with many queries should reuse RuleIndex."""
    return RuleIndex(stages, platform).first_match(**subject)


def _load_inputs(root: Path) -> tuple[dict[str, bytes], dict[str, bytes]]:
    snapshot = {source_id: _read_bytes(root, spec["archive_path"], "source snapshot") for source_id, spec in SOURCE_SPECS.items()}
    legacy = {path: _read_bytes(root, path, "legacy input") for path in LEGACY_INPUT_PATHS}
    return snapshot, legacy


def _print_candidate(candidate: PersonalCandidate, *, action: str) -> None:
    total_output = sum(info["bytes"] for info in candidate.manifest["outputs"].values())
    print(f"{action}: {len(candidate.manifest['sources'])} sources, {len(candidate.manifest['stages'])} stages, "
          f"{sum(len(groups) for groups in candidate.manifest['groups'].values())} route groups, "
          f"{len(candidate.manifest['outputs'])} outputs, {total_output} output bytes")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("update", "validate", "replay"):
        sub = subparsers.add_parser(name)
        sub.add_argument("--root", type=Path, default=ROOT)
        sub.add_argument("--offline", action="store_true", help="use archived sources only")
        sub.add_argument("--converter", type=Path, help=f"approved Mihomo converter (or {MIHOMO_CONVERTER_ENV})")
        if name == "update":
            sub.add_argument(
                "--accept-interface-change", action="store_true",
                help="explicitly accept a reviewed client resource contract migration",
            )
    args = parser.parse_args(argv)
    try:
        if args.command == "update":
            candidate = update(
                args.root, offline=args.offline, converter_path=args.converter,
                accept_interface_change=args.accept_interface_change,
            )
        elif args.command == "validate":
            if not args.offline:
                parser.error("validate requires --offline")
            candidate = validate_bundle(args.root, converter_path=args.converter)
        else:
            if not args.offline:
                parser.error("replay requires --offline")
            candidate = replay_offline(args.root, converter_path=args.converter)
        _print_candidate(candidate, action=args.command)
    except ProfileError as exc:
        print(f"personal profile: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
