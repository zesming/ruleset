#!/usr/bin/env python3
"""Render and privately migrate the ordered personal-routing profile.

Public snippets are generated only from the personal manifest and are free of
node definitions.  The private migration reads the ignored baseline, preserves
its node credentials in memory, and writes candidates only to an ignored
private directory.  The comparison evaluates ordered rules through the
profile compiler's indexed matcher and labels its sampling coverage.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import io
import json
import os
import re
import shlex
import subprocess
import sys
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BASE_URL = "https://raw.githubusercontent.com/zesming/ruleset/main"
PRIVATE_BASELINE = Path(".devflow/personal-routing")
CLASH_BASELINE = "clash.before.yaml"
SURGE_BASELINE = "surge.before.conf"
V1_CLASH_BASELINE = "clash.v1.yaml"
V1_SURGE_BASELINE = "surge.v1.conf"
BASELINE_FILE_PAIRS = ((CLASH_BASELINE, SURGE_BASELINE), (V1_CLASH_BASELINE, V1_SURGE_BASELINE))
CASE_PATH = "tests/fixtures/personal-route-cases.json"

MIHOMO_REGION_GROUPS = {"US": "🇺🇸 US", "JP": "🇯🇵 JP"}
MIHOMO_POLICY_ALIASES = {
    "TEST": "⚒️ Test", "DIRECT": "🚀 Direct", "REJECT": "⛔️ Reject",
    "REJECT-DROP": "⛔️ Reject-Drop",
}
SURGE_POLICY_ALIASES = {
    "TEST": "⚒️ Test", "DIRECT": "🚀 Direct", "REJECT": "⛔️ Reject",
    "REJECT-DROP": "⛔️ Reject-Drop", "REJECT-NO-DROP": "⛔️ Reject-No-Drop",
}
MIHOMO_US_DOH = ("https://8.8.8.8/dns-query#🇺🇸 US", "https://1.1.1.1/dns-query#🇺🇸 US")
MIHOMO_JP_DOH = ("https://1.0.0.1/dns-query#🇯🇵 JP",)
MIHOMO_TEST_DOH = ("https://8.8.4.4/dns-query#⚒️ Test",)
MIHOMO_DOMESTIC_DOH = ("https://223.5.5.5/dns-query#🚀 Direct", "https://1.12.12.12/dns-query#🚀 Direct")
MIHOMO_DNS_SERVER_FIELDS = (
    "fallback", "proxy-server-nameserver", "direct-nameserver", "default-nameserver",
)
MIHOMO_DNS_POLICY_FIELDS = ("proxy-server-nameserver-policy",)
MIHOMO_INTERFACE_FRAGMENT = re.compile(
    r"^(?:lo\d*|(?:br|pppoe)-[a-z0-9_.-]+|(?:en|eth|wlan|wlp|enp|ens|eno|utun|tun|tap|ppp|bridge|br|wg|tailscale|docker|veth)\d+[a-z0-9_.-]*)$",
    re.IGNORECASE,
)
SURGE_US_DOH = ("https://8.8.8.8/dns-query", "https://1.1.1.1/dns-query")
SURGE_JP_DOH = ("https://1.0.0.1/dns-query",)
SURGE_TEST_DOH = ("https://8.8.4.4/dns-query",)
SURGE_DOMESTIC_DOH = ("https://223.5.5.5/dns-query", "https://1.12.12.12/dns-query")
SURGE_REGION_GROUPS = {"US": "🇺🇸 US", "JP": "🇯🇵 JP"}
SURGE_REGION_LEAVES = {
    ("US", "snell"): "🇺🇸 Snell", ("US", "tuic"): "🇺🇸 TUIC",
    ("JP", "snell"): "🇯🇵 Snell", ("JP", "tuic"): "🇯🇵 TUIC",
}
ATT_REAL_IP = ("epdg.epc.att.net", "epdg.epc.att-idns.net")
NINTENDO_REAL_IP = ("+.srv.nintendo.net", "*.n.n.srv.nintendo.net")
SURGE_NINTENDO_REAL_IP = ("*.srv.nintendo.net", "*.n.n.srv.nintendo.net")
DOH_ENDPOINT_ACTIONS = {
    "8.8.8.8": {"US"}, "1.1.1.1": {"US"},
    "1.0.0.1": {"JP"}, "8.8.4.4": {"JP", "TEST"},
    "223.5.5.5": {"DIRECT"}, "1.12.12.12": {"DIRECT"},
}

VALID_ACTIONS = {"US", "DIRECT", "JP", "REJECT", "TEST"}
VALID_DNS = {"system", "domestic", "foreign", "jp", "test", "none"}
VALID_PLATFORMS = {"mihomo", "surge"}
DOMAIN_RULE_TYPES = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD"}
IP_RULE_TYPES = {"IP-CIDR", "IP-CIDR6", "IP-ASN", "GEOIP"}
# Special-use DNS namespaces should continue to use their local resolution path,
# even if a broad managed Test selector happens to include them.
LOCAL_DNS_SUFFIXES = frozenset({
    "localhost", "local", "home.arpa", "internal", "lan", "test", "invalid", "example", "onion",
})


class ProfileClientsError(Exception):
    """Expected renderer, migration, or comparison error."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load_api(root: Path):
    scripts = str(root / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    try:
        import personal_profile  # type: ignore[import-not-found]
    except Exception as exc:  # pragma: no cover - import failure is environment-specific
        raise ProfileClientsError("cannot import scripts/personal_profile.py") from exc
    return personal_profile


def _replay(root: Path, converter_path: str | None = None):
    api = _load_api(root)
    try:
        return api.replay_offline(root, converter_path=converter_path)
    except Exception as exc:
        if isinstance(exc, getattr(api, "ProfileError", ())):
            raise ProfileClientsError(str(exc)) from exc
        raise ProfileClientsError(f"personal profile replay failed: {type(exc).__name__}") from exc


def _validate_base_url(base_url: str) -> str:
    parsed = urllib.parse.urlsplit(base_url)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise ProfileClientsError("--base-url must be an https URL without credentials")
    if parsed.query or parsed.fragment:
        raise ProfileClientsError("--base-url cannot include a query or fragment")
    return base_url.rstrip("/")


def _safe_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]*", value):
        raise ProfileClientsError(f"invalid {label}: {value!r}")
    return value


def _groups(candidate: Any, platform: str) -> list[dict[str, Any]]:
    if platform not in VALID_PLATFORMS:
        raise ProfileClientsError(f"unsupported client platform {platform!r}")
    compact_manifest = candidate.manifest.get("compact")
    compact = isinstance(compact_manifest, Mapping)
    if compact:
        compact_groups = compact_manifest.get("groups")
        groups = compact_groups.get(platform) if isinstance(compact_groups, Mapping) else None
        stage_map = getattr(candidate, "compact_stages", None)
        if not isinstance(stage_map, Mapping):
            stage_map = compact_manifest.get("stages")
        stages = stage_map.get(platform) if isinstance(stage_map, Mapping) else None
    else:
        groups = candidate.manifest.get("groups", {}).get(platform)
        stages = candidate.stages
    if not isinstance(groups, list):
        raise ProfileClientsError(f"manifest.groups.{platform} must be an ordered array")
    if not isinstance(stages, list):
        raise ProfileClientsError(f"manifest stages for {platform} must be an ordered array")
    result: list[dict[str, Any]] = []
    previous_stage_order = -1
    source_stage_ids = {stage.get("id") for stage in candidate.stages if isinstance(stage, Mapping)}
    stage_order: dict[str, int] = {}
    physical_group_order: list[str] = []
    for stage_index, stage in enumerate(stages):
        if not isinstance(stage, Mapping) or not isinstance(stage.get("id"), str):
            raise ProfileClientsError(f"manifest stage {stage_index} for {platform} must have a string id")
        stage_id = stage["id"]
        if stage_id in stage_order:
            raise ProfileClientsError(f"manifest stages for {platform} have duplicate ids")
        stage_order[stage_id] = stage_index
        if compact:
            group_map = stage.get("group_by_platform")
            if not isinstance(group_map, Mapping):
                raise ProfileClientsError(f"compact stage {stage_id} has no platform group mapping")
            group_id = group_map.get(platform)
            if group_id is not None:
                if group_id != stage_id:
                    raise ProfileClientsError(f"compact stage {stage_id} does not match its {platform} group id")
                physical_group_order.append(group_id)
            stage_rules = stage.get("rules", [])
            if not isinstance(stage_rules, list):
                raise ProfileClientsError(f"compact stage {stage_id} has an invalid rules array")
            for rule in stage_rules:
                rule_platform = getattr(rule, "platform", None)
                if rule_platform is None and isinstance(rule, Mapping):
                    rule_platform = rule.get("platform")
                if rule_platform != platform:
                    raise ProfileClientsError(f"compact stage {stage_id} contains a rule for another platform")
            if len(stages) >= 2 and stage_index >= len(stages) - 2 and group_map.get(platform) is not None:
                raise ProfileClientsError("compact route groups must precede the two terminal stages")
    compact_group_ids: list[str] = []
    for index, raw in enumerate(groups):
        if not isinstance(raw, Mapping):
            raise ProfileClientsError(f"manifest.groups.{platform}[{index}] must be an object")
        group = dict(raw)
        group_id = _safe_id(group.get("id"), f"{platform} group id")
        if compact:
            if group_id not in stage_order:
                raise ProfileClientsError(f"compact group {group_id} has no physical stage")
            slot = group.get("slot")
            if not isinstance(slot, str):
                raise ProfileClientsError(f"compact group {group_id} has no logical slot")
            _safe_id(slot, f"{platform} group slot")
            physical = stages[stage_order[group_id]]
            if physical.get("group_by_platform", {}).get(platform) != group_id:
                raise ProfileClientsError(f"compact group {group_id} has no matching physical stage")
            if physical.get("slot") != slot:
                raise ProfileClientsError(f"compact group {group_id} has a mismatched physical slot")
            if any(physical.get(key) != group.get(key) for key in ("action", "dns", "reject_mode", "extended_matching", "no_resolve")):
                raise ProfileClientsError(f"compact group {group_id} metadata does not match its physical stage")
            compact_group_ids.append(group_id)
        action = group.get("action")
        dns = group.get("dns")
        if action not in VALID_ACTIONS or dns not in VALID_DNS:
            raise ProfileClientsError(f"group {group_id} has unsupported action/DNS intent")
        stage_ids = group.get("stages")
        if not isinstance(stage_ids, list) or any(not isinstance(stage_id, str) for stage_id in stage_ids):
            raise ProfileClientsError(f"group {group_id} has an invalid source-stage list")
        if compact:
            if len(stage_ids) != len(set(stage_ids)):
                raise ProfileClientsError(f"compact group {group_id} has duplicate source references")
            allowed_sources = source_stage_ids
            if any(stage_id not in allowed_sources for stage_id in stage_ids):
                raise ProfileClientsError(f"compact group {group_id} references an unknown source stage")
            count = group.get("rule_count")
            if not isinstance(count, int) or isinstance(count, bool) or count < 0:
                raise ProfileClientsError(f"compact group {group_id} has an invalid rule count")
            physical_rules = stages[stage_order[group_id]].get("rules", [])
            if not isinstance(physical_rules, list) or len(physical_rules) != count:
                raise ProfileClientsError(f"compact group {group_id} rule count does not match its physical stage")
            if not stage_ids and (count != 0 or group.get("slot") not in {"jp", "jp-ip"}):
                raise ProfileClientsError(f"compact group {group_id} may be empty only for a reserved JP slot")
        else:
            if not stage_ids:
                raise ProfileClientsError(f"group {group_id} has no ordered stage list")
            try:
                first_stage_order = stage_order[stage_ids[0]]
            except (KeyError, TypeError) as exc:
                raise ProfileClientsError(f"group {group_id} references an unknown stage") from exc
            if first_stage_order <= previous_stage_order:
                raise ProfileClientsError(f"groups for {platform} are not in profile order")
            previous_stage_order = first_stage_order
        if group.get("kind") != "route":
            raise ProfileClientsError(f"group {group_id} is not a route resource")
        behavior = group.get("behavior")
        file_format = group.get("format")
        allowed_formats = {"mrs", "text"} if platform == "mihomo" else {"set", "text"}
        if behavior not in {"domain-set", "classical"} or file_format not in allowed_formats:
            raise ProfileClientsError(f"group {group_id} has unsupported {platform} behavior/format")
        if behavior == "domain-set" and file_format != ("mrs" if platform == "mihomo" else "set"):
            raise ProfileClientsError(f"group {group_id} has incompatible domain-set format")
        if behavior == "classical" and file_format != "text":
            raise ProfileClientsError(f"group {group_id} has incompatible classical format")
        path = group.get("path")
        if not isinstance(path, str) or not path.startswith(f"rules/personal/{platform}/") or ".." in Path(path).parts:
            raise ProfileClientsError(f"group {group_id} has an unsafe resource path")
        content = candidate.files.get(path)
        if not isinstance(content, bytes):
            raise ProfileClientsError(f"candidate is missing {path}")
        expected_hash = group.get("sha256")
        if expected_hash and expected_hash != sha256(content):
            raise ProfileClientsError(f"candidate resource hash mismatch for {path}")
        dns_path = group.get("dns_path")
        if dns_path is not None:
            if not isinstance(dns_path, str) or not dns_path.startswith(f"rules/personal/{platform}/") or ".." in Path(dns_path).parts:
                raise ProfileClientsError(f"group {group_id} has an unsafe DNS selector path")
            dns_content = candidate.files.get(dns_path)
            if not isinstance(dns_content, bytes):
                raise ProfileClientsError(f"candidate is missing DNS selector {dns_path}")
            dns_kind = group.get("dns_kind")
            dns_behavior = group.get("dns_behavior")
            dns_format = group.get("dns_format")
            if dns_kind not in {"route", "dns-selector"} or dns_behavior not in {"domain-set", "classical"}:
                raise ProfileClientsError(f"group {group_id} has unsupported DNS selector metadata")
            if dns_format not in allowed_formats:
                raise ProfileClientsError(f"group {group_id} has unsupported DNS selector format")
            if group.get("dns_sha256") and group["dns_sha256"] != sha256(dns_content):
                raise ProfileClientsError(f"candidate DNS selector hash mismatch for {dns_path}")
        result.append(group)
    if compact and physical_group_order != compact_group_ids:
        raise ProfileClientsError(f"compact {platform} groups do not match physical stage order")
    if compact:
        if len(stages) < 2:
            raise ProfileClientsError(f"compact {platform} profile is missing its terminal stages")
        terminal_types: list[str] = []
        for stage in stages[-2:]:
            if stage.get("group_by_platform", {}).get(platform) is not None:
                raise ProfileClientsError(f"compact {platform} terminal stages cannot map to route groups")
            for rule in stage.get("rules", []):
                rule_type = getattr(rule, "type", None)
                if rule_type is None and isinstance(rule, Mapping):
                    rule_type = rule.get("type")
                if rule_type in {"GEOIP", "MATCH"}:
                    terminal_types.append(rule_type)
        if terminal_types != ["GEOIP", "MATCH"]:
            raise ProfileClientsError(f"compact {platform} terminal stages must end with GEOIP then MATCH")
    return result


def _candidate_stages(candidate: Any, platform: str) -> list[dict[str, Any]] | list[Mapping[str, Any]]:
    """Return the physical compact stages when the replay exposes that interface."""
    compact_manifest = candidate.manifest.get("compact")
    if isinstance(compact_manifest, Mapping):
        stage_map = getattr(candidate, "compact_stages", None)
        if not isinstance(stage_map, Mapping):
            stage_map = compact_manifest.get("stages")
        stages = stage_map.get(platform) if isinstance(stage_map, Mapping) else None
        if not isinstance(stages, list):
            raise ProfileClientsError(f"compact profile has no ordered {platform} stages")
        return stages
    return candidate.stages


def _resource_url(base_url: str, path: str) -> str:
    normalized = path.lstrip("/")
    if ".." in Path(normalized).parts:
        raise ProfileClientsError("resource path escapes the profile base URL")
    return f"{base_url}/{normalized}"


def _dns_endpoints(group: Mapping[str, Any], platform: str) -> tuple[str, ...]:
    intent = group.get("dns")
    action = group.get("action")
    if intent == "none":
        return ()
    if intent == "system":
        return ("system",) if platform == "mihomo" else ("system",)
    if intent == "domestic":
        return MIHOMO_DOMESTIC_DOH if platform == "mihomo" else SURGE_DOMESTIC_DOH
    if intent == "test":
        return MIHOMO_TEST_DOH if platform == "mihomo" else SURGE_TEST_DOH
    if intent in {"foreign", "jp"}:
        is_jp = intent == "jp" or (intent == "foreign" and action == "JP")
        if platform == "mihomo":
            return MIHOMO_JP_DOH if is_jp else MIHOMO_US_DOH
        return SURGE_JP_DOH if is_jp else SURGE_US_DOH
    raise ProfileClientsError(f"unsupported DNS intent {intent!r}")


def _dns_selector_path(group: Mapping[str, Any]) -> str | None:
    value = group.get("dns_path")
    if value is None:
        return None
    if not isinstance(value, str) or ".." in Path(value).parts:
        raise ProfileClientsError(f"group {group.get('id')} has an unsafe DNS selector path")
    return value


def _mihomo_provider(group: Mapping[str, Any], base_url: str) -> list[str]:
    group_id = _safe_id(group.get("id"), "Mihomo provider name")
    path = group["path"]
    provider_kind = group.get("kind")
    behavior = group.get("behavior")
    file_format = group.get("format")
    behavior = "domain" if behavior == "domain-set" else behavior
    if provider_kind != "route" or behavior not in {"domain", "classical"} or file_format not in {"mrs", "text"}:
        raise ProfileClientsError(f"group {group_id} has unsupported Mihomo behavior/format")
    if behavior == "domain" and file_format != "mrs":
        raise ProfileClientsError(f"domain provider {group_id} must declare its compiled MRS format")
    lines = [
        f"  {group_id}:",
        "    type: http",
        f"    behavior: {behavior}",
        f"    format: {file_format}",
        f"    url: {_yaml_quote(_resource_url(base_url, path))}",
        f"    path: ./ruleset/personal-{platform_cache_slug(group_id)}.{file_format}",
        "    interval: 43200",
        f"    proxy: {MIHOMO_REGION_GROUPS['US']}",
    ]
    return lines


def platform_cache_slug(group_id: str) -> str:
    return re.sub(r"[^a-z0-9-]", "-", group_id.lower())


def _yaml_quote(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _surge_rule_kind(group: Mapping[str, Any]) -> str:
    file_format = group.get("format")
    if group.get("kind") in {"route", "dns-selector"} and file_format == "set" and group.get("behavior") == "domain-set":
        return "DOMAIN-SET"
    if group.get("kind") in {"route", "dns-selector"} and file_format == "text" and group.get("behavior") == "classical":
        return "RULE-SET"
    raise ProfileClientsError(f"group {group.get('id')} has unsupported Surge kind/format")


def _surge_dns_selector(group: Mapping[str, Any], base_url: str) -> str | None:
    path = _dns_selector_path(group)
    if path is None or group.get("dns") == "none":
        return None
    dns_kind = group.get("dns_kind")
    dns_behavior = group.get("dns_behavior")
    dns_format = group.get("dns_format")
    if dns_kind not in {"route", "dns-selector"} or dns_behavior not in {"domain-set", "classical"}:
        raise ProfileClientsError(f"group {group.get('id')} has invalid DNS selector metadata")
    kind = _surge_rule_kind({"kind": dns_kind, "behavior": dns_behavior, "format": dns_format})
    prefix = kind + ":"
    return prefix + _resource_url(base_url, path)


def _mihomo_dns_provider(group: Mapping[str, Any], base_url: str) -> list[str] | None:
    path = _dns_selector_path(group)
    if path is None or group.get("dns") == "none":
        return None
    group_id = _safe_id(group.get("id"), "DNS provider name")
    provider_id = group_id if path == group.get("path") else group_id + "-dns"
    behavior = group.get("dns_behavior")
    file_format = group.get("dns_format")
    behavior = "domain" if behavior == "domain-set" else behavior
    if group.get("dns_kind") not in {"route", "dns-selector"} or behavior not in {"domain", "classical"} or file_format not in {"mrs", "text"}:
        raise ProfileClientsError(f"group {group_id} has unsupported DNS provider behavior/format")
    return [
        f"  {provider_id}:", "    type: http", f"    behavior: {behavior}",
        f"    format: {file_format}", f"    url: {_yaml_quote(_resource_url(base_url, path))}",
        f"    path: ./ruleset/personal-{platform_cache_slug(provider_id)}.{file_format}",
        "    interval: 43200", f"    proxy: {MIHOMO_REGION_GROUPS['US']}",
    ]


def _mihomo_target(group: Mapping[str, Any]) -> str:
    action = group["action"]
    mode = group.get("reject_mode")
    if action == "REJECT":
        if mode not in {None, "plain", "drop", "no-drop"}:
            raise ProfileClientsError(f"unsupported reject mode {mode!r}")
        action = {"drop": "REJECT-DROP", "no-drop": "REJECT", "plain": "REJECT", None: "REJECT"}[mode]
    return MIHOMO_REGION_GROUPS.get(action, MIHOMO_POLICY_ALIASES.get(action, action))


def _surge_target(group: Mapping[str, Any]) -> str:
    action = group["action"]
    mode = group.get("reject_mode")
    if action == "REJECT":
        if mode not in {None, "plain", "drop", "no-drop"}:
            raise ProfileClientsError(f"unsupported reject mode {mode!r}")
        action = {"drop": "REJECT-DROP", "no-drop": "REJECT-NO-DROP", "plain": "REJECT", None: "REJECT"}[mode]
    return SURGE_REGION_GROUPS.get(action, SURGE_POLICY_ALIASES.get(action, action))


def _mihomo_proxy_groups() -> list[dict[str, Any]]:
    """Return display groups whose only job is to expose canonical action names."""
    return [
        {"name": MIHOMO_POLICY_ALIASES["TEST"], "type": "select", "proxies": [
            MIHOMO_REGION_GROUPS["US"], MIHOMO_REGION_GROUPS["JP"], MIHOMO_POLICY_ALIASES["DIRECT"],
        ]},
        *[
            {"name": MIHOMO_POLICY_ALIASES[action], "type": "select", "proxies": [builtin]}
            for action, builtin in (("DIRECT", "DIRECT"), ("REJECT", "REJECT"), ("REJECT-DROP", "REJECT-DROP"))
        ],
    ]


def _mihomo_proxy_groups_yaml() -> list[str]:
    lines = ["proxy-groups:"]
    for group in _mihomo_proxy_groups():
        lines.extend((f"  - name: {_yaml_quote(group['name'])}", f"    type: {group['type']}", "    proxies:"))
        lines.extend(f"      - {_yaml_quote(member)}" for member in group["proxies"])
    return lines


def render_mihomo_snippet(candidate: Any, base_url: str) -> str:
    """Render credential-free rule-provider, route, and DNS fragments."""
    base_url = _validate_base_url(base_url)
    groups = _groups(candidate, "mihomo")
    provider_blocks: dict[str, list[str]] = {}
    policy_members: dict[tuple[str, tuple[str, ...]], list[str]] = {}
    for group in groups:
        group_id = _safe_id(group["id"], "Mihomo group id")
        provider_blocks[group_id] = _mihomo_provider(group, base_url)
        selector_path = _dns_selector_path(group)
        dns_values = _dns_endpoints(group, "mihomo")
        if selector_path and dns_values:
            dns_provider = _mihomo_dns_provider(group, base_url)
            if dns_provider:
                dns_provider_id = group_id if selector_path == group.get("path") else group_id + "-dns"
                if dns_provider_id not in provider_blocks:
                    provider_blocks[dns_provider_id] = dns_provider
                slot = str(group.get("slot") or group_id)
                policy_members.setdefault((slot, dns_values), []).append(dns_provider_id)
    if not provider_blocks:
        raise ProfileClientsError("profile produced no Mihomo rule providers")
    ordered_rules = ["  - " + line for line in _mihomo_route_lines(candidate, base_url)]
    policies = {
        "rule-set:" + ",".join(provider_ids): endpoints
        for (_slot, endpoints), provider_ids in policy_members.items()
    }
    policy_lines: list[str] = []
    for selector, values in policies.items():
        policy_lines.append(f"    {_yaml_quote(selector)}:")
        policy_lines.extend(f"      - {_yaml_quote(value)}" for value in values)
    all_providers = [line for block in provider_blocks.values() for line in block]
    lines = [
        "rule-providers:", *all_providers,
        "rules:", *ordered_rules,
        *_mihomo_proxy_groups_yaml(),
        "dns:", "  enable: true", "  enhanced-mode: fake-ip",
        "  nameserver:", *[f"    - {value}" for value in MIHOMO_US_DOH],
        "  nameserver-policy:", *(policy_lines or ["    {}"]),
        "  fake-ip-filter-mode: blacklist", "  fake-ip-filter:",
        *[f"    - {_yaml_quote(item)}" for item in (*ATT_REAL_IP, *NINTENDO_REAL_IP)],
    ]
    return "\n".join(lines) + "\n"


def render_surge_snippet(candidate: Any, base_url: str) -> str:
    """Render ordered credential-free Surge route and Host sections."""
    base_url = _validate_base_url(base_url)
    groups = _groups(candidate, "surge")
    host_lines: list[str] = []
    for group in groups:
        dns_selector = _surge_dns_selector(group, base_url)
        dns_endpoints = _dns_endpoints(group, "surge")
        if dns_selector and dns_endpoints:
            if dns_endpoints == ("system",):
                host_lines.append(f"{dns_selector} = server:system")
            else:
                host_lines.append(f"{dns_selector} = server:{', '.join(dns_endpoints)}")
    ordered_route_lines = _surge_route_lines(candidate, base_url)
    proxy_alias_lines = [f"{alias} = {policy.lower()}" for policy, alias in SURGE_POLICY_ALIASES.items() if policy != "TEST"]
    lines = [
        "[General]",
        "encrypted-dns-server = " + ", ".join(SURGE_US_DOH),
        "encrypted-dns-follow-outbound-mode = true",
        "always-real-ip = " + ", ".join((*ATT_REAL_IP, *SURGE_NINTENDO_REAL_IP)),
        "",
        "[Proxy]",
        *proxy_alias_lines,
        "",
        "[Proxy Group]",
        f"{SURGE_POLICY_ALIASES['TEST']} = select, {SURGE_REGION_GROUPS['US']}, {SURGE_REGION_GROUPS['JP']}, {SURGE_POLICY_ALIASES['DIRECT']}",
        "",
        "[Rule]",
        *ordered_route_lines,
        "",
        "[Host]",
        *host_lines,
        "",
    ]
    return "\n".join(lines)


def _surge_endpoint_rules() -> list[str]:
    return [
        f"AND,((PROTOCOL,DOH),(DOMAIN,1.0.0.1)),{SURGE_REGION_GROUPS['JP']}",
        f"AND,((PROTOCOL,DOH),(DOMAIN,8.8.4.4)),{SURGE_POLICY_ALIASES['TEST']}",
    ]


def _is_surge_direct_inline_rule(line: str) -> bool:
    fields = _split_csv(line)
    return len(fields) >= 3 and fields[2].strip() in {"DIRECT", SURGE_POLICY_ALIASES["DIRECT"]}


def _surge_route_lines(candidate: Any, base_url: str, node_rules: Sequence[str] = (), local_stages: Sequence[Mapping[str, Any]] = ()) -> list[str]:
    """Render the single ordered Surge route program used by snippets and migration."""
    groups = _groups(candidate, "surge")
    compact = isinstance(candidate.manifest.get("compact"), Mapping)
    by_stage: dict[str, dict[str, Any]] = {}
    for group in groups:
        if compact:
            by_stage[group["id"]] = group
        else:
            for stage_id in group["stages"]:
                if stage_id in by_stage:
                    raise ProfileClientsError(f"Surge stage {stage_id} maps to multiple route groups")
                by_stage[stage_id] = group
    lines = [*node_rules]
    seen_direct_inline = {line for line in lines if _is_surge_direct_inline_rule(line)}
    for stage in local_stages:
        for rule in stage.get("rules", []):
            if rule.platform != "surge":
                continue
            if rule.type in {"GEOIP", "MATCH"}:
                raise ProfileClientsError("private inline stages may not replace profile terminal rules")
            rendered = _render_inline_rule(rule, stage, "surge")
            if _is_surge_direct_inline_rule(rendered):
                if rendered in seen_direct_inline:
                    continue
                seen_direct_inline.add(rendered)
            lines.append(rendered)
    lines.extend(_surge_endpoint_rules())
    emitted: set[str] = set()
    terminal_seen = False
    for stage in _candidate_stages(candidate, "surge"):
        group_id = stage.get("group_by_platform", {}).get("surge") if compact else stage["id"]
        group = by_stage.get(group_id)
        if group is not None:
            if terminal_seen:
                raise ProfileClientsError("Surge route group appears after the terminal stage")
            if group["id"] not in emitted:
                url = _resource_url(base_url, group["path"])
                flags = []
                if group.get("no_resolve"):
                    flags.append("no-resolve")
                if group.get("extended_matching"):
                    flags.append("extended-matching")
                fields = [_surge_rule_kind(group), url, _surge_target(group), *flags, "update-interval=43200"]
                lines.append(",".join(fields))
                emitted.add(group["id"])
            continue
        for rule in stage.get("rules", []):
            if rule.platform != "surge":
                continue
            if rule.type == "GEOIP":
                if terminal_seen:
                    raise ProfileClientsError("Surge GEOIP rule appears after the terminal stage")
                suffix = ",no-resolve" if "no-resolve" in rule.flags else ""
                lines.append(f"GEOIP,{rule.value},{_surge_target(stage)}{suffix}")
            elif rule.type == "MATCH":
                if terminal_seen:
                    raise ProfileClientsError("Surge profile contains multiple terminal rules")
                lines.append(f"FINAL,{_surge_target(stage)},dns-failed")
                terminal_seen = True
            elif stage.get("group_by_platform", {}).get("surge") is not None:
                continue
            else:
                raise ProfileClientsError(f"profile stage {stage['id']} has non-terminal Surge rules without a route resource")
    if not terminal_seen or not lines[-1].startswith("FINAL,"):
        raise ProfileClientsError("Surge profile is missing its final terminal rule")
    return lines


@dataclass
class SurgeSection:
    name: str
    header: str
    lines: list[str]


def _surge_sections(text: str) -> tuple[list[str], list[SurgeSection]]:
    preamble: list[str] = []
    sections: list[SurgeSection] = []
    current: SurgeSection | None = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            current = SurgeSection(stripped[1:-1], line, [])
            sections.append(current)
        elif current is None:
            preamble.append(line)
        else:
            current.lines.append(line)
    return preamble, sections


def _render_surge_sections(preamble: Sequence[str], sections: Sequence[SurgeSection]) -> str:
    def clean_lines(lines: Sequence[str]) -> list[str]:
        kept: list[str] = []
        for line in lines:
            stripped = line.strip()
            if stripped.startswith(("#", ";")):
                if not _keep_surge_comment(stripped):
                    continue
            if not stripped:
                continue
            kept.append(line)
        return kept

    parts = clean_lines(preamble)
    for section in sections:
        body = clean_lines(section.lines)
        while body and not body[-1].strip():
            body.pop()
        if not body:
            continue
        if parts and parts[-1].strip():
            parts.append("")
        parts.append(section.header)
        parts.extend(body)
    return "\n".join(parts).rstrip() + "\n"


def _keep_surge_comment(line: str) -> bool:
    lowered = line.casefold()
    return line.startswith("#!") or "epdg" in lowered or (
        "jp" in lowered
        and any(token in lowered for token in ("empty", "reserved", "reserve", "空", "预留"))
    )


def _section(sections: list[SurgeSection], name: str, *, create: bool = False) -> SurgeSection:
    found = [item for item in sections if item.name.lower() == name.lower()]
    if len(found) > 1:
        raise ProfileClientsError(f"baseline has duplicate [{name}] sections")
    if found:
        return found[0]
    if not create:
        raise ProfileClientsError(f"baseline is missing [{name}] section")
    item = SurgeSection(name, f"[{name}]", [])
    sections.append(item)
    return item


def _set_general_value(general: SurgeSection, key: str, value: str) -> None:
    needle = key.lower() + " ="
    positions = [index for index, line in enumerate(general.lines) if line.strip().lower().startswith(needle)]
    if len(positions) > 1:
        raise ProfileClientsError(f"baseline [General] has duplicate {key} values")
    line = f"{key} = {value}"
    if positions:
        general.lines[positions[0]] = line
    else:
        general.lines.append(line)


def _surge_rule_lines(section: SurgeSection) -> list[str]:
    return [line for line in section.lines if line.strip() and not line.lstrip().startswith(("#", ";"))]


def _replace_section_rules(section: SurgeSection, rules: Iterable[str]) -> None:
    section.lines = list(rules)


def _load_yaml_private(data: bytes) -> dict[str, Any]:
    script = "require 'json'; require 'yaml'; value=YAML.safe_load(STDIN.read, aliases: true); STDOUT.write(JSON.generate(value))"
    try:
        result = subprocess.run(["ruby", "-e", script], input=data, capture_output=True, check=True)
        parsed = json.loads(result.stdout)
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError):
        raise ProfileClientsError("cannot parse private Mihomo baseline with the system Ruby YAML parser") from None
    if not isinstance(parsed, dict):
        raise ProfileClientsError("private Mihomo baseline root must be a YAML mapping")
    return parsed


def _dump_yaml_private(value: Mapping[str, Any]) -> bytes:
    payload = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    script = """require 'json'; require 'yaml'
RESOLVER_LIST_KEYS = %w[
  nameserver fallback proxy-server-nameserver direct-nameserver
  default-nameserver
].freeze
RESOLVER_POLICY_KEYS = %w[nameserver-policy proxy-server-nameserver-policy].freeze
def intern_resolver_list(value, seen)
  return value unless value.is_a?(Array) && value.all? { |item| item.is_a?(String) }
  seen[JSON.generate(value)] ||= value
end
def share_dns_resolver_arrays(value, seen, dns_scope = false)
  case value
  when Hash
    value.each do |key, item|
      key_name = key.to_s
      if key_name == 'dns' && item.is_a?(Hash)
        value[key] = share_dns_resolver_arrays(item, seen, true)
      elsif dns_scope && RESOLVER_LIST_KEYS.include?(key_name)
        value[key] = intern_resolver_list(item, seen)
      elsif dns_scope && RESOLVER_POLICY_KEYS.include?(key_name) && item.is_a?(Hash)
        item.each { |selector, servers| item[selector] = intern_resolver_list(servers, seen) }
      elsif item.is_a?(Hash)
        value[key] = share_dns_resolver_arrays(item, seen, dns_scope)
      end
    end
    value
  else
    value
  end
end
value = share_dns_resolver_arrays(JSON.parse(STDIN.read), {})
STDOUT.write(YAML.dump(value))"""
    try:
        result = subprocess.run(["ruby", "-e", script], input=payload, capture_output=True, check=True)
    except (OSError, subprocess.CalledProcessError):
        raise ProfileClientsError("cannot serialize private Mihomo candidate with the system Ruby YAML emitter") from None
    try:
        emitted = result.stdout.decode("utf-8")
    except UnicodeDecodeError:
        return result.stdout

    def readable_unicode(match: re.Match[str]) -> str:
        codepoint = int(match.group(1), 16)
        if codepoint <= 0xFFFF or codepoint > 0x10FFFF or 0xD800 <= codepoint <= 0xDFFF:
            return match.group(0)
        return chr(codepoint)

    # Ruby quotes non-BMP characters as YAML \U escapes. Decode only valid
    # scalar escapes that are not themselves protected by a YAML backslash
    # escape, then retain the emitter's form unless Ruby parses back the exact
    # object supplied by the migration.
    readable = re.sub(r"(?<!\\)\\U([0-9A-Fa-f]{8})", readable_unicode, emitted)
    if readable != emitted:
        try:
            if _load_yaml_private(readable.encode("utf-8")) == dict(value):
                emitted = readable
        except ProfileClientsError:
            pass
    return emitted.encode("utf-8")


def _parse_surge_proxy_line(line: str) -> tuple[str, str, list[str]] | None:
    if "=" not in line or line.strip().startswith(("#", ";")):
        return None
    name, rhs = line.split("=", 1)
    if "," not in rhs:
        return None
    try:
        fields = next(csv.reader([rhs.strip()], skipinitialspace=True))
    except csv.Error as exc:
        raise ProfileClientsError("private Surge [Proxy] line has invalid CSV syntax") from exc
    if not fields:
        return None
    return name.strip(), fields[0].strip().lower(), fields


def _surge_proxy_entries(sections: Sequence[SurgeSection]) -> list[tuple[str, str, list[str]]]:
    proxy = _section(list(sections), "Proxy")
    result: list[tuple[str, str, list[str]]] = []
    for line in proxy.lines:
        parsed = _parse_surge_proxy_line(line)
        if parsed is not None:
            result.append(parsed)
    return result


_SURGE_UPSTREAM_PROTOCOLS = {
    "ss", "shadowsocks", "snell", "snell-v5", "snell-v6", "tuic", "tuic-v5",
    "vmess", "vless", "trojan", "http", "https", "socks5", "socks5-tls",
    "hysteria", "hysteria2", "wireguard", "ssh", "anytls", "naive", "naiveproxy",
}


def _surge_node_mappings(sections: Sequence[SurgeSection]) -> list[dict[str, str]]:
    nodes: list[dict[str, str]] = []
    for name, protocol, fields in _surge_proxy_entries(sections):
        if protocol in {"direct", "reject", "reject-drop", "reject-no-drop", "reject-tinygif"}:
            continue
        if protocol not in _SURGE_UPSTREAM_PROTOCOLS:
            raise ProfileClientsError(f"private Surge proxy type {protocol!r} has no safe endpoint parser")
        if len(fields) < 2 or not fields[1].strip():
            raise ProfileClientsError("private Surge proxy is missing its upstream endpoint")
        nodes.append({"name": name, "server": fields[1].strip().strip('"')})
    return nodes


def _surge_options(fields: Sequence[str], start: int = 3) -> tuple[list[str], dict[str, str]]:
    positional: list[str] = []
    options: dict[str, str] = {}
    for field in fields[start:]:
        if "=" in field:
            key, value = field.split("=", 1)
            key = key.strip().lower()
            if not key or key in options:
                raise ProfileClientsError("private Surge TUIC node has duplicate or empty option keys")
            options[key] = value.strip().strip('"')
        elif field.strip():
            positional.append(field.strip())
    return positional, options


def _remove_inactive_surge_dashboard_flag(general: SurgeSection) -> None:
    http_api_active = False
    for line in general.lines:
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")) or "=" not in stripped:
            continue
        key, value = (part.strip() for part in stripped.split("=", 1))
        if key.casefold() == "http-api" and value.casefold() not in {"", "false", "no", "off", "0", "disabled"}:
            http_api_active = True
            break
    if http_api_active:
        return
    general.lines = [
        line for line in general.lines
        if not re.match(r"^\s*http-api-web-dashboard\s*=\s*true\s*(?:[#;].*)?$", line, flags=re.IGNORECASE)
    ]


def _node_region(name: str) -> str | None:
    lowered = name.casefold()
    us = any(word in lowered for word in ("us", "usa", "united states", "美国", "🇺🇸"))
    jp = any(word in lowered for word in ("jp", "japan", "日本", "🇯🇵"))
    if us == jp:
        return None
    return "US" if us else "JP"


def _extract_jp_tuic(surge_sections: Sequence[SurgeSection], mihomo_proxies: list[dict[str, Any]]) -> dict[str, Any]:
    templates = [item for item in mihomo_proxies if isinstance(item, dict) and item.get("type") == "tuic"]
    existing_jp_nodes = [item for item in templates if _node_region(str(item.get("name", ""))) == "JP"]
    if len(existing_jp_nodes) > 1:
        raise ProfileClientsError("private Mihomo baseline has more than one JP TUIC node")
    if existing_jp_nodes:
        # A deployed v1 baseline already contains the JP leaf. Keep its complete
        # Mihomo definition byte-for-value and only canonicalize its name later.
        return existing_jp_nodes[0]
    nodes = [entry for entry in _surge_proxy_entries(surge_sections) if entry[1] in {"tuic-v5", "tuic"}]
    jp_nodes = [entry for entry in nodes if _node_region(entry[0]) == "JP"]
    if len(jp_nodes) != 1:
        raise ProfileClientsError("private Surge baseline must contain exactly one identifiable JP TUIC node")
    if not templates:
        raise ProfileClientsError("private Mihomo baseline has no TUIC template node")
    if len(templates) != 1:
        raise ProfileClientsError("private Mihomo baseline must contain exactly one TUIC template node")
    name, protocol, fields = jp_nodes[0]
    if len(fields) < 3:
        raise ProfileClientsError("private JP TUIC node is missing server or port")
    positional, options = _surge_options(fields)
    if not {"uuid", "password"}.issubset(options):
        raise ProfileClientsError("private JP TUIC node is missing required credentials")
    allowed = {"uuid", "password", "sni", "alpn", "server-cert-verify-name", "tfo"}
    unknown = set(options) - allowed
    if unknown:
        raise ProfileClientsError("private JP TUIC node has unsupported TLS/options; refusing partial migration")
    try:
        port = int(fields[2].strip())
    except (ValueError, IndexError):
        raise ProfileClientsError("private JP TUIC node has an invalid port") from None
    # US endpoint pins and transport tuning are not JP settings. In particular,
    # Surge TCP tfo is not Mihomo TUIC fast-open; use TUIC defaults for JP.
    node = {
        "name": "JP TUIC", "type": "tuic", "server": fields[1].strip(),
        "port": port, "uuid": options["uuid"], "password": options["password"],
    }
    if "sni" in options:
        node["sni"] = options["sni"]
    elif "server-cert-verify-name" in options:
        node["sni"] = options["server-cert-verify-name"]
    if "alpn" in options:
        node["alpn"] = [item.strip() for item in options["alpn"].split("|")]
        if any(not item for item in node["alpn"]):
            raise ProfileClientsError("private JP TUIC node has an empty ALPN value")
    return node


def _canonical_mihomo_groups(config: dict[str, Any], jp_node: dict[str, Any]) -> None:
    proxies = config.get("proxies")
    groups = config.get("proxy-groups")
    if not isinstance(proxies, list) or not isinstance(groups, list):
        raise ProfileClientsError("private Mihomo baseline has invalid proxy arrays")
    tuic_nodes = [item for item in proxies if isinstance(item, dict) and item.get("type") == "tuic"]
    us_nodes = [item for item in tuic_nodes if _node_region(str(item.get("name", ""))) == "US"]
    jp_nodes = [item for item in tuic_nodes if _node_region(str(item.get("name", ""))) == "JP"]
    if len(us_nodes) != 1:
        raise ProfileClientsError("private Mihomo baseline must contain exactly one US TUIC node")
    if len(jp_nodes) > 1:
        raise ProfileClientsError("private Mihomo baseline must contain at most one JP TUIC node")
    if not jp_nodes:
        if any(isinstance(item, Mapping) and item.get("name") == jp_node.get("name") for item in proxies):
            raise ProfileClientsError("private Mihomo baseline already has a conflicting JP TUIC node")
        proxies.append(jp_node)
        jp_nodes = [jp_node]
    elif jp_nodes[0] is not jp_node and jp_nodes[0] != jp_node:
        raise ProfileClientsError("private Mihomo baseline already has a conflicting JP TUIC node")

    if len(proxies) != 2:
        raise ProfileClientsError("private Mihomo profile must contain exactly the US and JP TUIC leaves")

    selected_nodes = {id(us_nodes[0]), id(jp_nodes[0])}
    proxy_names: set[str] = set()
    for proxy in proxies:
        if not isinstance(proxy, Mapping) or not isinstance(proxy.get("name"), str):
            raise ProfileClientsError("private Mihomo proxies contain an unsupported entry")
        if proxy["name"] in proxy_names:
            raise ProfileClientsError("private Mihomo proxy names are not unique")
        proxy_names.add(proxy["name"])
    for proxy in proxies:
        if id(proxy) not in selected_nodes and proxy.get("name") in set(MIHOMO_REGION_GROUPS.values()):
            raise ProfileClientsError("private Mihomo proxy name conflicts with a canonical TUIC leaf")
    # Rename the country TUIC definitions while preserving node identity fields.
    # Apply only the reviewed Mihomo TUIC compatibility settings below.
    us_nodes[0]["name"] = MIHOMO_REGION_GROUPS["US"]
    jp_nodes[0]["name"] = MIHOMO_REGION_GROUPS["JP"]
    if us_nodes[0].get("fast-open") is True:
        us_nodes[0].pop("fast-open")
    jp_nodes[0].update({
        "congestion-controller": "bbr",
        "heartbeat-interval": 8000,
        "disable-sni": False,
        "udp-relay-mode": "native",
    })

    group_names: set[str] = set()
    for group in groups:
        if not isinstance(group, Mapping) or not isinstance(group.get("name"), str):
            raise ProfileClientsError("private Mihomo proxy-groups contain an unsupported entry")
        if group["name"] in group_names:
            raise ProfileClientsError("private Mihomo proxy-group names are not unique")
        group_names.add(group["name"])
    test_groups = [
        item for item in groups if isinstance(item, Mapping)
        and (str(item.get("name", "")).upper() == "TEST" or any(marker in str(item.get("name", "")).casefold() for marker in ("test", "测速", "网络测试")))
    ]
    if len(test_groups) != 1 or not isinstance(test_groups[0].get("proxies"), list):
        raise ProfileClientsError("private Mihomo baseline must contain exactly one reusable TEST selector")
    groups[:] = _mihomo_proxy_groups()


def _node_endpoint_rules(nodes: Iterable[Mapping[str, Any]], *, platform: str, root: Path = ROOT) -> list[str]:
    rules: list[str] = []
    seen: set[tuple[str, str]] = set()
    direct_target = MIHOMO_POLICY_ALIASES["DIRECT"] if platform == "mihomo" else SURGE_POLICY_ALIASES["DIRECT"]
    for node in nodes:
        values = [node.get("server"), node.get("ip")]
        for raw in values:
            if not isinstance(raw, str) or not raw.strip():
                continue
            value = raw.strip().strip("[]")
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                try:
                    # Validate the host with the same strict domain parser used by
                    # the profile compiler; malformed endpoints stop migration.
                    api = _load_api(root)
                    value = api.canonical_domain(value, "proxy node host")
                except Exception as exc:
                    raise ProfileClientsError("private proxy node has an unsupported server address") from exc
                key = ("DOMAIN", value.casefold())
                if key in seen:
                    continue
                seen.add(key)
                rules.append(f"DOMAIN,{value},{direct_target}")
            else:
                kind = "IP-CIDR" if address.version == 4 else "IP-CIDR6"
                network = f"{address}/{address.max_prefixlen}"
                key = (kind, network)
                if key in seen:
                    continue
                seen.add(key)
                rule_kind = "IP-CIDR" if platform == "mihomo" and address.version == 4 else kind
                rules.append(f"{rule_kind},{network},{direct_target},no-resolve")
    return rules


def _mihomo_route_lines(candidate: Any, base_url: str, node_rules: Sequence[str] = (), local_stages: Sequence[Mapping[str, Any]] = ()) -> list[str]:
    groups = _groups(candidate, "mihomo")
    _ = base_url
    compact = isinstance(candidate.manifest.get("compact"), Mapping)
    route_by_stage: dict[str, dict[str, Any]] = {}
    for group in groups:
        if compact:
            route_by_stage[group["id"]] = group
        else:
            for stage_id in group["stages"]:
                route_by_stage[stage_id] = group
    rules: list[str] = []
    direct_inline_seen: set[str] = set()

    def append_rule(line: str, *, dedupe_direct: bool = True) -> None:
        if dedupe_direct:
            fields = _split_rule_fields(line)
            if (
                len(fields) >= 3 and fields[0].upper() in DOMAIN_RULE_TYPES | IP_RULE_TYPES | {"PROCESS-NAME", "USER-AGENT"}
                and (fields[2].upper() == "DIRECT" or fields[2] == MIHOMO_POLICY_ALIASES["DIRECT"])
            ):
                key = ",".join(fields)
                if key in direct_inline_seen:
                    return
                direct_inline_seen.add(key)
        rules.append(line)

    for line in node_rules:
        append_rule(line)
    for stage in local_stages:
        for rule in stage.get("rules", []):
            if rule.platform != "mihomo":
                continue
            if rule.type in {"GEOIP", "MATCH"}:
                raise ProfileClientsError("private inline stages may not replace profile terminal rules")
            append_rule(_render_inline_rule(rule, stage, "mihomo"))
    emitted: set[str] = set()
    for stage in _candidate_stages(candidate, "mihomo"):
        group_id = stage.get("group_by_platform", {}).get("mihomo") if compact else stage["id"]
        group = route_by_stage.get(group_id)
        if group is not None:
            if group["id"] not in emitted:
                append_rule(f"RULE-SET,{group['id']},{_mihomo_target(group)}" + (",no-resolve" if group.get("no_resolve") else ""), dedupe_direct=False)
                emitted.add(group["id"])
            continue
        for rule in stage.get("rules", []):
            if rule.platform != "mihomo":
                continue
            if rule.type == "GEOIP":
                append_rule(f"GEOIP,{rule.value},{_mihomo_target(stage)}" + (",no-resolve" if "no-resolve" in rule.flags else ""), dedupe_direct=False)
            elif rule.type == "MATCH":
                append_rule(f"MATCH,{_mihomo_target(stage)}", dedupe_direct=False)
            elif rule.type not in DOMAIN_RULE_TYPES | IP_RULE_TYPES | {"PROCESS-NAME", "USER-AGENT"}:
                raise ProfileClientsError(f"unsupported Mihomo inline route rule {rule.type}")
            elif stage.get("group_by_platform", {}).get("mihomo") is None:
                raise ProfileClientsError(f"profile stage {stage['id']} has non-terminal rules without a resource group")
    if not rules or not rules[-1].startswith("MATCH,"):
        raise ProfileClientsError("Mihomo profile route does not end with MATCH")
    return rules


def _mihomo_provider_data(group: Mapping[str, Any], base_url: str, provider_id: str, path: str, behavior: str, file_format: str) -> dict[str, Any]:
    return {
        "type": "http", "behavior": behavior, "format": file_format,
        "url": _resource_url(base_url, path),
        "path": f"./ruleset/personal-{platform_cache_slug(provider_id)}.{file_format}",
        "interval": 43200, "proxy": MIHOMO_REGION_GROUPS["US"],
    }


def _mihomo_display_policy(value: str, known_targets: set[str]) -> str:
    action, reject_mode = _old_policy(value, known_targets)
    if action == "REJECT":
        if reject_mode == "drop":
            action = "REJECT-DROP"
        elif reject_mode not in {None, "plain", "no-drop"}:
            raise ProfileClientsError("Mihomo provider proxy references an unsupported reject policy")
    return MIHOMO_REGION_GROUPS.get(action, MIHOMO_POLICY_ALIASES.get(action, action))


def _set_mihomo_providers(
    config: dict[str, Any], candidate: Any, base_url: str, root: Path = ROOT,
    local_stages: Sequence[Mapping[str, Any]] = (), known_targets: set[str] | None = None,
    baseline_manifest: Mapping[str, Any] | None = None,
) -> None:
    groups = _groups(candidate, "mihomo")
    old_providers = config.get("rule-providers", {})
    if not isinstance(old_providers, Mapping):
        raise ProfileClientsError("private Mihomo baseline rule-providers must be a mapping")
    dns = config.get("dns")
    if not isinstance(dns, dict):
        dns = {}
        config["dns"] = dns
    old_dns_policy = dns.get("nameserver-policy", {})
    if not isinstance(old_dns_policy, Mapping):
        raise ProfileClientsError("private Mihomo nameserver-policy must be a mapping")
    old_dns_policy = dict(old_dns_policy)
    api = _load_api(root)
    aliases = _source_aliases(candidate, api, baseline_manifest)
    profile_dns_sources = {
        rule.source
        for stage in _candidate_stages(candidate, "mihomo") if stage.get("dns") != "none"
        for rule in stage.get("rules", [])
        if rule.platform == "mihomo" and rule.type in DOMAIN_RULE_TYPES
    }
    retained_providers: dict[str, Any] = {}
    retained_policy: dict[str, Any] = {}
    known_targets = known_targets if known_targets is not None else _known_policy_targets("mihomo", config)

    def preserve_provider(name: str, provider: Mapping[str, Any]) -> None:
        preserved = dict(provider)
        if "proxy" in preserved and preserved["proxy"] is not None:
            if not isinstance(preserved["proxy"], str):
                raise ProfileClientsError("preserved Mihomo provider proxy must be a policy name")
            preserved["proxy"] = _mihomo_display_policy(preserved["proxy"], known_targets)
        retained_providers[name] = preserved

    for field in MIHOMO_DNS_SERVER_FIELDS:
        if field in dns:
            dns[field] = _normalize_resolver_target(dns[field], known_targets)
    for field in MIHOMO_DNS_POLICY_FIELDS:
        value = dns.get(field)
        if value is None:
            continue
        if not isinstance(value, Mapping):
            raise ProfileClientsError(f"private Mihomo {field} must be a mapping")
        dns[field] = {
            selector: _normalize_resolver_target(target, known_targets)
            for selector, target in value.items()
        }

    for selector, target in old_dns_policy.items():
        selector_text = str(selector)
        normalized_target = _normalize_resolver_target(target, known_targets)
        if _retire_known_legacy_dns_selector("mihomo", selector_text, normalized_target):
            continue
        provider_names = _mihomo_rule_set_names(selector_text)
        if provider_names is not None:
            retained_names: list[str] = []
            for name in provider_names:
                provider = old_providers.get(name) if isinstance(old_providers, Mapping) else None
                if not isinstance(provider, Mapping):
                    raise ProfileClientsError("private Mihomo DNS selector references an undefined provider")
                reference = _provider_reference(provider)
                try:
                    source_id = _resolve_source_reference(reference, aliases, platform="mihomo")
                except ProfileClientsError:
                    # Preserve explicit local/external DNS exceptions in their original order.
                    retained_names.append(name)
                    preserve_provider(name, provider)
                    continue
                migrated_sources = {source_id}
                group = aliases.group_sources.get(source_id)
                if isinstance(group, Mapping):
                    migrated_sources.update(_group_rule_sources(candidate, group, "mihomo"))
                reserved_empty_jp = (
                    isinstance(group, Mapping) and group.get("rule_count") == 0
                    and group.get("action") == "JP" and group.get("dns") == "jp"
                    and any(item.get("action") == "JP" and item.get("dns") == "jp" for item in groups)
                )
                if not migrated_sources & profile_dns_sources and not reserved_empty_jp:
                    retained_names.append(name)
                    preserve_provider(name, provider)
            if retained_names:
                retained_policy["rule-set:" + ",".join(retained_names)] = normalized_target
        else:
            if _dns_inline_selector_superseded_by_test(
                selector_text, normalized_target, candidate, "mihomo", api, aliases,
            ):
                continue
            # Keep inline local domain selectors such as company LAN/system mappings.
            retained_policy[selector_text] = normalized_target

    providers: dict[str, Any] = {}
    policy_members: dict[tuple[str, tuple[str, ...]], list[str]] = {}
    for group in groups:
        group_id = _safe_id(group["id"], "Mihomo provider name")
        behavior = "domain" if group["behavior"] == "domain-set" else "classical"
        providers[group_id] = _mihomo_provider_data(group, base_url, group_id, group["path"], behavior, group["format"])
        selector = _dns_selector_path(group)
        endpoints = _dns_endpoints(group, "mihomo")
        if selector and endpoints:
            selector_id = group_id if selector == group["path"] else group_id + "-dns"
            if selector_id not in providers:
                dns_behavior = "domain" if group.get("dns_behavior") == "domain-set" else group.get("dns_behavior")
                providers[selector_id] = _mihomo_provider_data(
                    group, base_url, selector_id, selector, dns_behavior, str(group.get("dns_format"))
                )
            slot = str(group.get("slot") or group_id)
            policy_members.setdefault((slot, endpoints), []).append(selector_id)
    collision = set(providers) & set(retained_providers)
    if collision:
        raise ProfileClientsError("new Mihomo providers collide with a preserved local DNS provider")
    providers.update(retained_providers)
    policies = {**retained_policy}
    policies.update({
        "rule-set:" + ",".join(provider_ids): list(endpoints)
        for (_slot, endpoints), provider_ids in policy_members.items()
    })
    config["rule-providers"] = providers
    proxies = config.get("proxies", [])
    if not isinstance(proxies, list):
        raise ProfileClientsError("private Mihomo proxies must be an array")
    node_rules = _node_endpoint_rules((item for item in proxies if isinstance(item, Mapping)), platform="mihomo", root=root)
    config["rules"] = _mihomo_route_lines(candidate, base_url, node_rules, local_stages)
    dns["enable"] = True
    dns["enhanced-mode"] = "fake-ip"
    dns["nameserver"] = list(MIHOMO_US_DOH)
    dns["nameserver-policy"] = policies
    filters = dns.get("fake-ip-filter", [])
    if not isinstance(filters, list):
        raise ProfileClientsError("private Mihomo fake-ip-filter is not a list")
    filters = list(filters)
    for host in (*ATT_REAL_IP, *NINTENDO_REAL_IP):
        if host not in filters:
            filters.append(host)
    dns["fake-ip-filter"] = filters
    fake_ip_mode = dns.get("fake-ip-filter-mode", "blacklist")
    if fake_ip_mode != "blacklist":
        raise ProfileClientsError("private Mihomo baseline must use blacklist fake-ip-filter-mode")
    dns["fake-ip-filter-mode"] = fake_ip_mode


_SURGE_GROUP_TYPES = {"select", "smart", "fallback", "url-test", "load-balance"}
_SURGE_BUILTIN_POLICIES = {"DIRECT", "REJECT", "REJECT-DROP", "REJECT-NO-DROP", "REJECT-TINYGIF"}
_SURGE_GROUP_OPTIONS = {
    "include-all", "include-all-proxies", "include-other-group", "no-alert", "hidden",
    "no-filter", "disable-udp", "evaluate-before-use",
}


def _surge_group_index(section: SurgeSection) -> dict[str, tuple[str, list[str]]]:
    result: dict[str, tuple[str, list[str]]] = {}
    for line in section.lines:
        parsed = _parse_surge_proxy_line(line)
        if parsed is None:
            if line.strip() and not line.strip().startswith(("#", ";")) and "=" in line:
                raise ProfileClientsError("private Surge Proxy Group contains an unsupported definition")
            continue
        name, kind, fields = parsed
        if kind not in _SURGE_GROUP_TYPES:
            continue
        if name in result:
            raise ProfileClientsError("private Surge proxy-group names are not unique")
        result[name] = (kind, fields)
    return result


def _surge_group_references(fields: Sequence[str], known_names: set[str]) -> tuple[list[str], list[str]]:
    members: list[str] = []
    options: list[str] = []
    for raw in fields[1:]:
        value = raw.strip().strip('"')
        if not value:
            continue
        if "=" in value:
            options.append(raw.strip())
        elif value.upper() == "DIRECT":
            members.append("DIRECT")
        elif value.casefold() in {item.casefold() for item in known_names} or value.upper() in _SURGE_BUILTIN_POLICIES:
            members.append(value)
        elif value.casefold() in _SURGE_GROUP_OPTIONS:
            options.append(raw.strip())
        else:
            raise ProfileClientsError("private Surge proxy-group has an unknown member or option")
    return members, options


def _is_surge_snell_v6(protocol: str, fields: Sequence[str]) -> bool:
    if protocol == "snell-v6":
        return True
    if protocol != "snell":
        return False
    _positional, options = _surge_options(fields)
    return options.get("version") == "6"


def _canonical_surge_proxy_names(sections: Sequence[SurgeSection]) -> list[tuple[str, str, list[str]]]:
    """Rename the four country leaves while preserving their parsed RHS values."""
    proxy = _section(list(sections), "Proxy")
    entries = _surge_proxy_entries(sections)
    by_region: dict[str, dict[str, list[str]]] = {
        region: {"tuic": [], "snell": []} for region in ("US", "JP")
    }
    for name, protocol, fields in entries:
        region = _node_region(name)
        if region not in by_region:
            continue
        if protocol in {"tuic", "tuic-v5"}:
            by_region[region]["tuic"].append(name)
        elif protocol in {"snell", "snell-v6"}:
            if not _is_surge_snell_v6(protocol, fields):
                raise ProfileClientsError(f"private Surge {region} Snell node must use protocol version 6")
            by_region[region]["snell"].append(name)
    selected: dict[str, str] = {}
    for region in ("US", "JP"):
        for kind in ("tuic", "snell"):
            if len(by_region[region][kind]) != 1:
                expected = "TUIC" if kind == "tuic" else "Snell version 6"
                raise ProfileClientsError(f"private Surge baseline must contain exactly one {region} {expected} node")
        selected[by_region[region]["snell"][0]] = SURGE_REGION_LEAVES[(region, "snell")]
        selected[by_region[region]["tuic"][0]] = SURGE_REGION_LEAVES[(region, "tuic")]
    if len(entries) != 4:
        raise ProfileClientsError("private Surge profile must contain exactly four proxy leaves")
    canonical = set(SURGE_REGION_LEAVES.values())
    for name, _protocol, _fields in entries:
        if name in canonical and name not in selected:
            raise ProfileClientsError("private Surge proxy name conflicts with a canonical leaf")
    for index, line in enumerate(proxy.lines):
        parsed = _parse_surge_proxy_line(line)
        if parsed is None or parsed[0] not in selected:
            continue
        name, protocol, fields = parsed
        target_name = selected[name]
        rhs = line.split("=", 1)[1].strip()
        changed = target_name != name
        if protocol in {"tuic", "tuic-v5"}:
            _positional, options = _surge_options(fields)
            if options.get("tfo", "").casefold() == "true":
                rhs = re.sub(
                    r",\s*tfo\s*=\s*(?:true|\"true\")(?=\s*(?:,|$))", "", rhs,
                    count=1, flags=re.IGNORECASE,
                )
                changed = True
        if changed:
            # Keep every endpoint, credential, remaining option, and field
            # value; normalize only assignment spacing and the reviewed TUIC
            # TCP Fast Open setting.
            proxy.lines[index] = f"{target_name} = {rhs}"
    return _surge_proxy_entries(sections)


def _surge_group_aliases(section: SurgeSection, proxy_entries: Sequence[tuple[str, str, list[str]]]) -> list[str]:
    """Rebuild country Smart groups and the small, user-facing TEST selector."""
    groups = _surge_group_index(section)
    expected = {
        SURGE_REGION_LEAVES[("US", "snell")].casefold(): {"snell", "snell-v6"},
        SURGE_REGION_LEAVES[("US", "tuic")].casefold(): {"tuic", "tuic-v5"},
        SURGE_REGION_LEAVES[("JP", "snell")].casefold(): {"snell", "snell-v6"},
        SURGE_REGION_LEAVES[("JP", "tuic")].casefold(): {"tuic", "tuic-v5"},
    }
    observed = {name.casefold(): protocol for name, protocol, _fields in proxy_entries}
    if len(observed) != 4 or set(observed) != set(expected):
        raise ProfileClientsError("private Surge profile must retain exactly US/JP Snell and TUIC leaves")
    if any(observed[name] not in protocols for name, protocols in expected.items()):
        raise ProfileClientsError("private Surge country leaves must be Snell v6 and TUIC")
    for name, protocol, fields in proxy_entries:
        if name.casefold() in {
            SURGE_REGION_LEAVES[("US", "snell")].casefold(),
            SURGE_REGION_LEAVES[("JP", "snell")].casefold(),
        } and not _is_surge_snell_v6(protocol, fields):
            raise ProfileClientsError("private Surge country leaves must use Snell protocol version 6")
    test_candidates = [
        name for name in groups
        if name.upper() == "TEST" or any(marker in name.casefold() for marker in ("test", "测速", "网络测试"))
    ]
    if len(test_candidates) != 1:
        raise ProfileClientsError("private Surge baseline must have exactly one reusable TEST group")
    us, jp = SURGE_REGION_GROUPS["US"], SURGE_REGION_GROUPS["JP"]
    us_snell, us_tuic = SURGE_REGION_LEAVES[("US", "snell")], SURGE_REGION_LEAVES[("US", "tuic")]
    jp_snell, jp_tuic = SURGE_REGION_LEAVES[("JP", "snell")], SURGE_REGION_LEAVES[("JP", "tuic")]
    return [
        f"{us} = smart, {us_snell}, {us_tuic}",
        f"{jp} = smart, {jp_snell}, {jp_tuic}",
        f"{SURGE_POLICY_ALIASES['TEST']} = select, {us}, {jp}, {SURGE_POLICY_ALIASES['DIRECT']}",
    ]


def _set_surge_policy_aliases(section: SurgeSection) -> None:
    """Declare named aliases for Surge's native built-in policies."""
    expected = {alias.casefold(): policy.lower() for policy, alias in SURGE_POLICY_ALIASES.items() if policy != "TEST"}
    generated_group_and_leaf_names = {
        *(name.casefold() for name in SURGE_REGION_GROUPS.values()),
        SURGE_POLICY_ALIASES["TEST"].casefold(),
        *(name.casefold() for name in SURGE_REGION_LEAVES.values()),
    }
    kept: list[str] = []
    present: set[str] = set()
    for line in section.lines:
        if "=" not in line or line.strip().startswith(("#", ";")):
            kept.append(line)
            continue
        name, raw_value = (part.strip() for part in line.split("=", 1))
        value = raw_value.strip().strip('"')
        key = name.casefold()
        if key in generated_group_and_leaf_names and "," not in raw_value:
            raise ProfileClientsError("Surge proxy alias conflicts with a generated group or leaf")
        if key not in expected:
            kept.append(line)
            continue
        if value.casefold() != expected[key]:
            raise ProfileClientsError("Surge policy alias conflicts with a proxy definition")
        if key in present:
            raise ProfileClientsError("Surge policy alias is defined more than once")
        present.add(key)
        kept.append(line)
    section.lines = kept + [
        f"{SURGE_POLICY_ALIASES[policy]} = {policy.lower()}"
        for policy, alias in SURGE_POLICY_ALIASES.items()
        if policy != "TEST" and alias.casefold() not in present
    ]


def _rewrite_surge_host_comments(host_section: SurgeSection) -> None:
    """Remove retired commentary while retaining active Host selectors/mappings."""
    host_section.lines = [
        line for line in host_section.lines
        if not line.strip().startswith(("#", ";")) or _keep_surge_comment(line.strip())
    ]


def _surge_dns(
    host_section: SurgeSection, candidate: Any, base_url: str, root: Path = ROOT,
    baseline_manifest: Mapping[str, Any] | None = None,
) -> list[str]:
    lines = []
    profile_groups = _groups(candidate, "surge")
    for group in profile_groups:
        selector = _surge_dns_selector(group, base_url)
        endpoints = _dns_endpoints(group, "surge")
        if selector and endpoints:
            if endpoints == ("system",):
                server_value = "server:system"
            else:
                server_value = "server:" + ", ".join(endpoints)
            lines.append(f"{selector} = {server_value}")
    # Preserve inline mappings and unrelated selectors; replace only selectors
    # whose archived source now has a profile DNS policy.
    api = _load_api(root)
    aliases = _source_aliases(candidate, api, baseline_manifest)
    profile_dns_sources = {
        rule.source
        for stage in _candidate_stages(candidate, "surge") if stage.get("dns") != "none"
        for rule in stage.get("rules", [])
        if rule.platform == "surge" and rule.type in DOMAIN_RULE_TYPES
    }
    explicit = []
    for line in host_section.lines:
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")) or "=" not in stripped:
            explicit.append(line)
            continue
        selector, target = (part.strip() for part in stripped.split("=", 1))
        resolver_target = _surge_server_values(target) if target.startswith("server:") else target
        if _retire_known_legacy_dns_selector("surge", selector, resolver_target):
            continue
        if selector.startswith(("RULE-SET:", "DOMAIN-SET:")):
            reference = selector.split(":", 1)[1]
            try:
                source_id = _resolve_source_reference(reference, aliases, platform="surge")
            except ProfileClientsError:
                explicit.append(line)
                continue
            migrated_sources = {source_id}
            group = aliases.group_sources.get(source_id)
            if isinstance(group, Mapping):
                migrated_sources.update(_group_rule_sources(candidate, group, "surge"))
            reserved_empty_jp = (
                isinstance(group, Mapping) and group.get("rule_count") == 0
                and group.get("action") == "JP" and group.get("dns") == "jp"
                and any(item.get("action") == "JP" and item.get("dns") == "jp" for item in profile_groups)
            )
            if migrated_sources & profile_dns_sources or reserved_empty_jp:
                continue
        elif target.startswith("server:") and _dns_inline_selector_superseded_by_test(
            selector, _surge_server_values(target), candidate, "surge", api, aliases,
        ):
            continue
        explicit.append(line)
    host_section.lines = [*explicit, *lines]
    return lines


def _migrate_surge(
    candidate: Any, surge_text: str, base_url: str, *, root: Path = ROOT,
    local_stages: Sequence[Mapping[str, Any]] = (), baseline_manifest: Mapping[str, Any] | None = None,
) -> bytes:
    preamble, sections = _surge_sections(surge_text)
    general = _section(sections, "General")
    proxy_group = _section(sections, "Proxy Group")
    route = _section(sections, "Rule")
    host = _section(sections, "Host", create=True)
    _remove_inactive_surge_dashboard_flag(general)
    _set_general_value(general, "encrypted-dns-server", ", ".join(SURGE_US_DOH))
    _set_general_value(general, "encrypted-dns-follow-outbound-mode", "true")
    current_real_ip: list[str] = []
    for line in general.lines:
        if line.strip().lower().startswith("always-real-ip ="):
            current_real_ip = [item.strip() for item in line.split("=", 1)[1].split(",") if item.strip()]
            break
    for host_value in (*ATT_REAL_IP, *SURGE_NINTENDO_REAL_IP):
        if host_value not in current_real_ip:
            current_real_ip.append(host_value)
    _set_general_value(general, "always-real-ip", ", ".join(current_real_ip))
    proxy_nodes = _surge_node_mappings(sections)
    protocol_by_region: dict[str, set[str]] = {"US": set(), "JP": set()}
    for node in proxy_nodes:
        region = _node_region(node["name"])
        if region in protocol_by_region:
            entry = next((item for item in _surge_proxy_entries(sections) if item[0] == node["name"]), None)
            if entry:
                protocol_by_region[region].add(entry[1])
    for region in ("US", "JP"):
        protocols = protocol_by_region[region]
        if not any(item.startswith("tuic") for item in protocols) or not any(item.startswith("snell") for item in protocols):
            raise ProfileClientsError(f"private Surge baseline must preserve {region} TUIC and Snell nodes")
    proxy_entries = _canonical_surge_proxy_names(sections)
    _set_surge_policy_aliases(_section(sections, "Proxy"))
    generated_groups = _surge_group_aliases(proxy_group, proxy_entries)
    proxy_group.lines = generated_groups
    node_rules = _node_endpoint_rules(proxy_nodes, platform="surge", root=root)
    _replace_section_rules(route, _surge_route_lines(candidate, base_url, node_rules, local_stages))
    _rewrite_surge_host_comments(host)
    _surge_dns(host, candidate, base_url, root, baseline_manifest)
    return _render_surge_sections(preamble, sections).encode("utf-8")


def _migrate_mihomo(
    candidate: Any, clash: Mapping[str, Any], surge_sections: Sequence[SurgeSection], base_url: str, *,
    root: Path = ROOT, local_stages: Sequence[Mapping[str, Any]] = (),
    baseline_manifest: Mapping[str, Any] | None = None,
) -> bytes:
    config = json.loads(json.dumps(clash))
    jp_node = _extract_jp_tuic(surge_sections, config.get("proxies", []))
    old_policy_targets = _known_policy_targets("mihomo", config)
    _canonical_mihomo_groups(config, jp_node)
    _set_mihomo_providers(config, candidate, base_url, root, local_stages, old_policy_targets, baseline_manifest)
    return _dump_yaml_private(config)


def _resolve_baseline_dir(root: Path, value: str | Path | None = None) -> Path:
    path = Path(value) if value is not None else root / PRIVATE_BASELINE
    if not path.is_absolute():
        path = root / path
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        raise ProfileClientsError("private baseline directory is unavailable") from None
    if not resolved.is_dir():
        raise ProfileClientsError("private baseline path is not a directory")
    return resolved


def _baseline_paths(baseline_dir: Path) -> tuple[Path, Path]:
    matches = []
    for clash_name, surge_name in BASELINE_FILE_PAIRS:
        clash_path, surge_path = baseline_dir / clash_name, baseline_dir / surge_name
        if clash_path.is_file() and surge_path.is_file():
            matches.append((clash_path, surge_path))
    if len(matches) > 1:
        raise ProfileClientsError("private baseline directory contains multiple supported input pairs")
    if matches:
        return matches[0]
    raise ProfileClientsError("private baseline inputs are unavailable")


def _load_baseline_manifest(baseline_dir: Path) -> Mapping[str, Any] | None:
    for name in ("manifest.v1.json", "manifest.json"):
        path = baseline_dir / name
        if not path.is_file():
            continue
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raise ProfileClientsError("private baseline manifest cannot be read") from None
        if not isinstance(value, Mapping):
            raise ProfileClientsError("private baseline manifest has an invalid root")
        return value
    return None


def _ensure_private_dir(root: Path, value: str | Path) -> Path:
    target = Path(value)
    if not target.is_absolute():
        target = root / target
    parent = target.resolve()
    allowed = (root / PRIVATE_BASELINE).resolve()
    try:
        parent.relative_to(allowed)
    except ValueError as exc:
        raise ProfileClientsError("--private-dir must stay under .devflow/personal-routing") from exc
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(parent, 0o700)
    return parent


def _write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    os.chmod(path, 0o600)


def private_migrate(
    root: str | Path, private_dir: str | Path, base_url: str, *,
    converter_path: str | None = None, baseline_dir: str | Path | None = None,
) -> dict[str, Path]:
    root = Path(root).resolve()
    base_url = _validate_base_url(base_url)
    target_dir = _ensure_private_dir(root, private_dir)
    candidate = _replay(root, converter_path)
    baseline_dir = _resolve_baseline_dir(root, baseline_dir)
    clash_path, surge_path = _baseline_paths(baseline_dir)
    baseline_manifest = _load_baseline_manifest(baseline_dir)
    if clash_path.name == V1_CLASH_BASELINE and baseline_manifest is None:
        raise ProfileClientsError("deployed v1 baseline needs its manifest for safe provider source replay")
    try:
        clash_raw = clash_path.read_bytes()
        surge_raw = surge_path.read_bytes()
    except OSError:
        raise ProfileClientsError("private baseline inputs are unavailable") from None
    clash = _load_yaml_private(clash_raw)
    surge_text = surge_raw.decode("utf-8")
    api = _load_api(root)
    aliases = _source_aliases(candidate, api, baseline_manifest)
    migration_unsupported: list[dict[str, Any]] = []
    local_stages = {
        "mihomo": _private_inline_stages(api, "mihomo", clash, candidate, aliases, migration_unsupported),
        "surge": _private_inline_stages(api, "surge", surge_text, candidate, aliases, migration_unsupported),
    }
    clash_candidate = _migrate_mihomo(
        candidate, clash, _surge_sections(surge_text)[1], base_url, root=root,
        local_stages=local_stages["mihomo"], baseline_manifest=baseline_manifest,
    )
    surge_candidate = _migrate_surge(
        candidate, surge_text, base_url, root=root, local_stages=local_stages["surge"],
        baseline_manifest=baseline_manifest,
    )
    report = compare_private(root, candidate, baseline_dir, _load_cases(root / CASE_PATH), local_stages=local_stages)
    report["unsupported_cases"].extend(migration_unsupported)
    outputs = {
        "clash": target_dir / "clash.candidate.yaml",
        "surge": target_dir / "surge.candidate.conf",
        "json": target_dir / "route-dns-comparison.json",
        "markdown": target_dir / "route-dns-comparison.md",
    }
    _write_private(outputs["clash"], clash_candidate)
    _write_private(outputs["surge"], surge_candidate)
    _write_private(outputs["json"], (json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8"))
    _write_private(outputs["markdown"], render_report_markdown(report).encode("utf-8"))
    return outputs


def _split_csv(line: str) -> list[str]:
    try:
        return next(csv.reader([line], skipinitialspace=True))
    except csv.Error as exc:
        raise ProfileClientsError("baseline contains malformed rule CSV") from exc


class _PolicyTargets(set):
    def __init__(self, values: Iterable[str], aliases: Mapping[str, str] | None = None):
        super().__init__(values)
        self.aliases = dict(aliases or {})


def _known_policy_targets(platform: str, baseline: Any) -> set[str]:
    choices: dict[str, list[str]] = {}
    leaf_actions: dict[str, str] = {}
    if platform == "mihomo":
        result: set[str] = set()
        for key in ("proxies", "proxy-groups"):
            entries = baseline.get(key, [])
            if not isinstance(entries, list):
                raise ProfileClientsError(f"Mihomo baseline {key} must be an array")
            for entry in entries:
                if not isinstance(entry, Mapping) or not isinstance(entry.get("name"), str):
                    raise ProfileClientsError(f"Mihomo baseline {key} contains an invalid entry")
                result.add(entry["name"])
                if key == "proxies":
                    region = _node_region(entry["name"])
                    if region or not _looks_like_reject_policy_name(entry["name"]):
                        leaf_actions[entry["name"]] = region or "US"
                else:
                    members = entry.get("proxies")
                    if not isinstance(members, list) or not members or not all(isinstance(item, str) for item in members):
                        raise ProfileClientsError("Mihomo comparison needs explicit nonempty group members")
                    choices[entry["name"]] = members
    else:
        _, sections = _surge_sections(str(baseline))
        groups = _surge_group_index(_section(sections, "Proxy Group"))
        nodes = _surge_proxy_entries(sections)
        result = {name for name, _kind, _fields in nodes} | set(groups)
        leaf_actions = {
            name: region or "US" for name, _kind, _fields in nodes
            if (region := _node_region(name)) or not _looks_like_reject_policy_name(name)
        }
        for raw in _section(sections, "Proxy").lines:
            if raw.lstrip().startswith(("#", ";")) or "=" not in raw:
                continue
            name, value = (part.strip().strip('"') for part in raw.split("=", 1))
            if value.upper() in _SURGE_BUILTIN_POLICIES:
                leaf_actions[name] = value.upper()
                result.add(name)
        for name, (_kind, fields) in groups.items():
            choices[name] = _surge_group_references(fields, result)[0]

    def resolve(name: str, visiting: set[str]) -> str:
        upper = name.upper()
        if upper in _SURGE_BUILTIN_POLICIES:
            return upper
        if name in visiting:
            raise ProfileClientsError("baseline policy groups contain a cycle")
        if name in leaf_actions:
            return leaf_actions[name]
        if name not in choices and upper in {"US", "JP", "TEST"}:
            return upper
        if any(token in name.casefold() for token in ("test", "测速", "网络测试")):
            return "TEST"
        if name not in choices and _node_region(name):
            return _node_region(name) or "US"
        if name not in choices or not choices[name]:
            raise ProfileClientsError("baseline policy group references an unknown or empty target")
        # A static comparison uses the configured first choice, not remembered
        # UI selections or the time-varying Smart result.
        return resolve(choices[name][0], visiting | {name})

    return _PolicyTargets(result, {name: resolve(name, set()) for name in result})


def _is_direct_policy_alias(value: str) -> bool:
    clean = "".join(character for character in value.casefold() if character.isalnum())
    return clean == "direct" or "直连" in value


def _is_builtin_direct_route_target(platform: str, baseline: Any, target: str) -> bool:
    """Return true only for DIRECT itself or an alias defined as DIRECT alone."""
    if target.strip().strip('"').casefold() == "direct":
        return True
    target_key = target.strip().strip('"').casefold()
    if platform == "mihomo":
        groups = baseline.get("proxy-groups", [])
        if not isinstance(groups, list):
            return False
        return any(
            isinstance(group, Mapping)
            and isinstance(group.get("name"), str)
            and group["name"].casefold() == target_key
            and isinstance(group.get("proxies"), list)
            and len(group["proxies"]) == 1
            and isinstance(group["proxies"][0], str)
            and group["proxies"][0].strip().strip('"').casefold() == "direct"
            and not group.get("use")
            and not any(group.get(key) for key in ("include-all", "include-all-proxies", "include-all-providers"))
            for group in groups
        )
    if platform == "surge":
        _, sections = _surge_sections(str(baseline))
        for line in _section(sections, "Proxy").lines:
            if line.lstrip().startswith(("#", ";")) or "=" not in line:
                continue
            name, value = line.split("=", 1)
            if name.strip().strip('"').casefold() == target_key and value.strip().strip('"').casefold() == "direct":
                return True
    return False


def _looks_like_reject_policy_name(value: str) -> bool:
    normalized = value.casefold()
    return value.startswith("🚫") or "reject" in normalized or "拒绝" in normalized


def _old_policy(action: str, known_targets: set[str] | None = None) -> tuple[str, str | None]:
    value = action.strip().strip('"')
    alias = getattr(known_targets, "aliases", {}).get(value)
    if alias is not None:
        return _old_policy(alias)
    upper = value.upper()
    normalized = value.casefold()
    if upper == "DIRECT" or (
        known_targets is not None and value in known_targets and _is_direct_policy_alias(value)
    ):
        return "DIRECT", None
    reject = {"REJECT": "plain", "REJECT-DROP": "drop", "REJECT-NO-DROP": "no-drop", "REJECT-TINYGIF": "tinygif"}
    if upper in reject:
        return "REJECT", reject[upper]
    if not value:
        raise ProfileClientsError("baseline rule has an empty policy target")
    if upper == "TEST" or any(token in normalized for token in ("test", "测速", "网络测试")):
        return "TEST", None
    region = _node_region(value)
    if region:
        return region, None
    if known_targets is not None and value in known_targets:
        if _looks_like_reject_policy_name(value):
            raise ProfileClientsError("baseline route references an unknown policy target")
        # The old route target is a configured proxy/group, not an action token.
        # Compare its observed baseline selection as US and report this as an
        # explicit AUTO/Smart -> fixed-US normalization.
        return "US", None
    raise ProfileClientsError("baseline route references an unknown policy target")


def _normalize_resolver_target(target: Any, known_targets: set[str]) -> Any:
    """Normalize old Mihomo resolver fragments to groups emitted by migration.

    Mihomo nameserver-policy values may be a single endpoint or an ordered list.
    Endpoint fragments that referenced retired baseline groups must be rewritten
    to the corresponding canonical action; configured DNS options and interface
    fragments remain intact, while unknown policy references fail closed.
    """
    if isinstance(target, str):
        values = [target]
        shape = "string"
    elif isinstance(target, list) and all(isinstance(item, str) for item in target):
        values = list(target)
        shape = "list"
    else:
        raise ProfileClientsError("Mihomo resolver target has an unsupported shape")

    normalized: list[str] = []
    for raw in values:
        value = raw.strip()
        if value.casefold() in {"system", "system://"}:
            normalized.append(value)
            continue
        if "#" not in value:
            normalized.append(value)
            continue
        parsed = urllib.parse.urlsplit(value)
        if not parsed.fragment:
            raise ProfileClientsError("Mihomo resolver endpoint has an empty policy fragment")
        fragment_parts = urllib.parse.unquote(parsed.fragment).split("&")
        bare_indices = [index for index, part in enumerate(fragment_parts) if "=" not in part]
        effective_index = bare_indices[-1] if bare_indices else None
        normalized_parts: list[str] = []
        for index, fragment in enumerate(fragment_parts):
            if index != effective_index or fragment.casefold() == "rules":
                normalized_parts.append(fragment)
                continue
            if fragment not in known_targets and fragment.upper() not in {"US", "JP", "TEST", "DIRECT", "REJECT", "REJECT-DROP", "REJECT-NO-DROP"}:
                if MIHOMO_INTERFACE_FRAGMENT.fullmatch(fragment):
                    normalized_parts.append(fragment)
                    continue
                raise ProfileClientsError("Mihomo resolver endpoint references an unknown policy target or interface")
            action, reject_mode = _old_policy(fragment, known_targets)
            if action not in {"US", "JP", "DIRECT", "TEST"} or reject_mode is not None:
                raise ProfileClientsError("Mihomo resolver endpoint references a non-egress policy")
            display_target = MIHOMO_REGION_GROUPS.get(action, MIHOMO_POLICY_ALIASES.get(action, action))
            normalized_parts.append(display_target)
        normalized_fragment = "&".join(normalized_parts)
        normalized_fragment = "".join(
            urllib.parse.quote(character, safe="") if character == "%" or ord(character) < 32 or ord(character) == 127 else character
            for character in normalized_fragment
        )
        normalized.append(urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, normalized_fragment)))

    if shape == "string":
        if not normalized:
            raise ProfileClientsError("Mihomo resolver target is empty")
        return normalized[0]
    return normalized


def _load_cases(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raise ProfileClientsError(f"cannot read route comparison cases: {path}") from None
    if not isinstance(value, dict) or value.get("schema") != 1:
        raise ProfileClientsError("route comparison cases have an unsupported schema")
    if not isinstance(value.get("independent_cases"), list):
        raise ProfileClientsError("route comparison cases must contain independent_cases")
    return value


def _rule_key(rule: Any, stage_id: str) -> tuple[str, str, str, str, int, str]:
    return (stage_id, str(rule.source), str(rule.type), str(rule.value), int(rule.line), str(rule.platform))


class _SourceAliases(dict[str, set[str]]):
    def __init__(self) -> None:
        super().__init__()
        self.group_sources: dict[str, dict[str, Any]] = {}


def _source_aliases(candidate: Any, api: Any, baseline_manifest: Mapping[str, Any] | None = None) -> _SourceAliases:
    aliases = _SourceAliases()

    def add(alias: str, source: str) -> None:
        normalized = urllib.parse.unquote(alias).replace("\\", "/").lstrip("/")
        if normalized:
            aliases.setdefault(normalized.casefold(), set()).add(source)
            aliases.setdefault(Path(normalized).name.casefold(), set()).add(source)

    source_ids = {rule.source for stage in candidate.stages for rule in stage.get("rules", [])}
    for source_id in source_ids:
        add(source_id, source_id)
        if source_id in api.SOURCE_SPECS:
            spec = api.SOURCE_SPECS[source_id]
            add(spec["archive_path"], source_id)
            add(urllib.parse.urlsplit(spec["url"]).path, source_id)
    # Legacy client configurations refer to published files, while profile rules
    # use canonical legacy:* source IDs. Map every supported legacy input shape
    # to the same identity before deciding whether a provider is profile-owned.
    legacy_paths = {
        "legacy:ai-cn": ("rules/ai-cn.list", "rules/surge/ai-cn.set"),
        "legacy:ai-global": ("rules/ai-global.list",),
        "legacy:network-test": ("rules/network-test.list", "rules/surge/network-test.set"),
        "legacy:us": ("rules/us.list", "rules/surge/us.set"),
        "legacy:ai-process": ("rules/surge/ai-process.list",),
        "legacy:cn-direct-domain": (
            "rules/mihomo/cn-direct-domain.txt",
            "rules/mihomo/cn-direct-domain.mrs",
            "rules/surge/cn-direct.set",
        ),
        "legacy:cn-direct-special": (
            "rules/mihomo/cn-direct-special.list",
            "rules/surge/cn-direct-special.list",
        ),
        "legacy:cn-direct-process": (
            "rules/mihomo/cn-direct-process.list",
            "rules/surge/cn-direct-platform.list",
        ),
    }
    for source_id, paths in legacy_paths.items():
        if source_id in source_ids:
            for path in paths:
                add(path, source_id)
        else:
            # Where the profile keeps platform-specific legacy source paths,
            # retain those exact identities. Basename-only references are
            # disambiguated by the client platform in _resolve_source_reference.
            for path in paths:
                if path in source_ids:
                    add(path, path)
    domain_text_source = "rules/mihomo/cn-direct-domain.txt"
    if domain_text_source in source_ids:
        add("rules/mihomo/cn-direct-domain.mrs", domain_text_source)
    elif "legacy:cn-direct-domain" in source_ids:
        add("rules/mihomo/cn-direct-domain.mrs", "legacy:cn-direct-domain")
    if baseline_manifest is not None:
        source_stage_metadata: dict[str, Mapping[str, Any]] = {}
        raw_stages = baseline_manifest.get("stages", [])
        if isinstance(raw_stages, list):
            source_stage_metadata = {
                stage["id"]: stage for stage in raw_stages
                if isinstance(stage, Mapping) and isinstance(stage.get("id"), str)
            }
        for manifest_key, source_prefix in (
            ("groups", "baseline-group"), ("compact", "baseline-compact-group"),
        ):
            group_root = baseline_manifest.get(manifest_key, {})
            if manifest_key == "compact" and isinstance(group_root, Mapping):
                group_root = group_root.get("groups", {})
            if not isinstance(group_root, Mapping):
                continue
            for platform in VALID_PLATFORMS:
                groups = group_root.get(platform, [])
                if not isinstance(groups, list):
                    continue
                domain_stages_by_identity: dict[tuple[Any, ...], set[str]] = {}
                if manifest_key == "compact":
                    for domain_group in groups:
                        if not isinstance(domain_group, Mapping) or domain_group.get("behavior") != "domain-set":
                            continue
                        stages = domain_group.get("stages")
                        if not isinstance(stages, list):
                            continue
                        identity = tuple(domain_group.get(key) for key in (
                            "slot", "action", "dns", "reject_mode", "extended_matching", "no_resolve",
                        ))
                        domain_stages_by_identity.setdefault(identity, set()).update(
                            stage_id for stage_id in stages if isinstance(stage_id, str)
                        )
                for raw_group in groups:
                    if not isinstance(raw_group, Mapping):
                        continue
                    group_id = raw_group.get("id")
                    path = raw_group.get("path")
                    stage_ids = raw_group.get("stages")
                    if not isinstance(group_id, str) or not isinstance(path, str) or not isinstance(stage_ids, list):
                        continue
                    source_id = f"{source_prefix}:{platform}:{group_id}"
                    aliases.group_sources[source_id] = {
                        "id": group_id,
                        "platform": platform,
                        "compact": manifest_key == "compact",
                        "stages": [stage_id for stage_id in stage_ids if isinstance(stage_id, str)],
                        **{
                            key: raw_group[key]
                            for key in (
                                "rule_count", "action", "dns", "slot", "reject_mode",
                                "extended_matching", "no_resolve", "kind", "behavior", "format",
                            )
                            if key in raw_group
                        },
                    }
                    if manifest_key == "compact":
                        identity = tuple(raw_group.get(key) for key in (
                            "slot", "action", "dns", "reject_mode", "extended_matching", "no_resolve",
                        ))
                        domain_sibling_stages = domain_stages_by_identity.get(identity, set())
                        aliases.group_sources[source_id]["sibling_domain_stages"] = [
                            stage_id for stage_id in aliases.group_sources[source_id]["stages"]
                            if stage_id in domain_sibling_stages
                        ] if raw_group.get("behavior") == "classical" else []
                        aliases.group_sources[source_id]["source_stage_identity"] = {
                            stage_id: {
                                key: source_stage_metadata[stage_id][key]
                                for key in (
                                    "action", "dns", "reject_mode", "extended_matching",
                                    "no_resolve", "sources",
                                )
                                if key in source_stage_metadata[stage_id]
                            }
                            for stage_id in aliases.group_sources[source_id]["stages"]
                            if stage_id in source_stage_metadata
                        }
                    add(path, source_id)
                    dns_path = raw_group.get("dns_path")
                    if isinstance(dns_path, str):
                        add(dns_path, source_id)
    return aliases


def _normalized_repository_reference(reference: str) -> tuple[str | None, bool]:
    """Resolve only recognized repository URL shapes to a repo-relative path."""
    raw = reference.strip().strip('"')
    parsed = urllib.parse.urlsplit(raw)
    path = urllib.parse.unquote(parsed.path if parsed.scheme else raw).replace("\\", "/").lstrip("/")
    parts = [part for part in path.split("/") if part]
    host = (parsed.hostname or "").casefold() if parsed.scheme else ""
    repo_ref = False

    def valid_ref(value: str) -> bool:
        return value == "main" or bool(re.fullmatch(r"[0-9a-fA-F]{7,40}", value))

    rest: list[str] = []
    if host == "raw.githubusercontent.com":
        if parsed.port is not None or parsed.username or parsed.password or parsed.query or parsed.fragment:
            return None, True
        repo_ref = True
        if [part.casefold() for part in parts[:2]] != ["zesming", "ruleset"]:
            return None, True
        parts = parts[2:]
        if parts and valid_ref(parts[0]):
            rest = parts[1:]
    elif host == "github.com" or (not parsed.scheme and parts[:2] == ["zesming", "ruleset"]):
        if parsed.scheme and (parsed.port is not None or parsed.username or parsed.password or parsed.query or parsed.fragment):
            return None, True
        repo_ref = True
        if [part.casefold() for part in parts[:2]] != ["zesming", "ruleset"]:
            return None, True
        parts = parts[2:]
        if parts and parts[0] == "raw":
            parts = parts[1:]
            if parts[:2] == ["refs", "heads"]:
                parts = parts[2:]
            elif parts[:2] == ["refs", "tags"]:
                return None, True
        if parts and valid_ref(parts[0]):
            rest = parts[1:]
    else:
        return None, False

    if not rest or any(part in {".", ".."} for part in rest):
        return None, repo_ref
    return "/".join(rest), repo_ref


def _resolve_source_reference(reference: str, aliases: Mapping[str, set[str]], *, platform: str | None = None) -> str:
    path, is_repository_reference = _normalized_repository_reference(reference)
    if path is None:
        if is_repository_reference:
            raise ProfileClientsError("baseline repository URL is outside the archived source map")
        parsed = urllib.parse.urlsplit(reference.strip().strip('"'))
        path = urllib.parse.unquote(parsed.path if parsed.scheme else reference.strip().strip('"')).replace("\\", "/").lstrip("/")
    while path.startswith("./"):
        path = path[2:]
    exact = aliases.get(path.casefold())
    if exact is None and path and not is_repository_reference:
        exact = aliases.get(Path(path).name.casefold())
    if not exact:
        raise ProfileClientsError("baseline references a rule source outside the archived source map")
    if len(exact) > 1 and platform in VALID_PLATFORMS:
        preferred = {
            source for source in exact
            if source.startswith(f"rules/{platform}/") or source.startswith(f"{platform}.")
            or source.startswith(f"baseline-group:{platform}:")
            or source.startswith(f"baseline-compact-group:{platform}:")
        }
        if len(preferred) == 1:
            exact = preferred
    if len(exact) != 1:
        raise ProfileClientsError("baseline rule source reference is ambiguous in the archived source map")
    return next(iter(exact))


def _source_rules(candidate: Any, source_id: str, platform: str, aliases: Mapping[str, set[str]] | None = None) -> list[Any]:
    group_sources = getattr(aliases, "group_sources", {}) if aliases is not None else {}
    group = group_sources.get(source_id) if isinstance(group_sources, Mapping) else None
    if isinstance(group, Mapping):
        if group.get("platform") != platform:
            raise ProfileClientsError("baseline group source belongs to another platform")
        if group.get("compact") is True:
            physical = _compact_source_stage(candidate, platform, group)
            if physical is None:
                raise ProfileClientsError("baseline compact group does not map to one semantically matching current archived group")
            return [rule for rule in physical.get("rules", []) if rule.platform == platform]
        stages_by_id = {stage.get("id"): stage for stage in candidate.stages if isinstance(stage, Mapping)}
        result = []
        for stage_id in dict.fromkeys(group.get("stages", [])):
            stage = stages_by_id.get(stage_id)
            if stage is None:
                raise ProfileClientsError("baseline group references an unknown fine stage")
            result.extend(rule for rule in stage.get("rules", []) if rule.platform == platform)
        if result or group.get("rule_count") == 0:
            return result
        raise ProfileClientsError("baseline group maps to no archived rules for this platform")
    result: list[Any] = []
    for stage in candidate.stages:
        for rule in stage.get("rules", []):
            if rule.source == source_id and rule.platform == platform:
                result.append(rule)
    if not result:
        raise ProfileClientsError("baseline source maps to no archived rules for this platform")
    return result


def _group_rule_sources(candidate: Any, group: Mapping[str, Any], platform: str) -> set[str]:
    """Return exact source IDs represented by one manifest resource."""
    if group.get("compact") is True:
        physical = _compact_source_stage(candidate, platform, group)
        if physical is None:
            raise ProfileClientsError("baseline compact group does not map to one identity-checked current group")
        return {
            rule.source for rule in physical.get("rules", [])
            if rule.platform == platform and isinstance(getattr(rule, "source", None), str)
        }
    stages_by_id = {stage.get("id"): stage for stage in candidate.stages if isinstance(stage, Mapping)}
    sources: set[str] = set()
    for stage_id in group.get("stages", []):
        stage = stages_by_id.get(stage_id)
        if stage is not None:
            sources.update(rule.source for rule in stage.get("rules", []) if rule.platform == platform)
    return sources


def _physical_group_value(platform: str, key: str, value: Any) -> Any:
    # Mihomo emits both plain and no-drop rejects as its same physical REJECT
    # action. Keep source-stage metadata untouched; this is only for group
    # interface matching after compaction.
    if platform == "mihomo" and key == "reject_mode" and value == "no-drop":
        return "plain"
    return value


def _same_physical_group_fields(
    platform: str, left: Mapping[str, Any], right: Mapping[str, Any], keys: Sequence[str],
) -> bool:
    return all(
        _physical_group_value(platform, key, left.get(key))
        == _physical_group_value(platform, key, right.get(key))
        for key in keys if key in right
    )


def _compact_source_stage(candidate: Any, platform: str, group: Mapping[str, Any]) -> Mapping[str, Any] | None:
    """Find a compact group by its current physical ID, then its stable slot."""
    stages = _candidate_stages(candidate, platform)
    identity_keys = ("action", "dns", "reject_mode", "extended_matching", "no_resolve")
    compact = candidate.manifest.get("compact")
    compact_groups = compact.get("groups") if isinstance(compact, Mapping) else None
    groups = compact_groups.get(platform) if isinstance(compact_groups, Mapping) else None
    if not isinstance(groups, list):
        return None

    def same_interface(item: Mapping[str, Any], *, require_sources: bool) -> bool:
        if not _same_physical_group_fields(platform, item, group, identity_keys):
            return False
        if any(item.get(key) != group[key] for key in ("slot", "kind", "behavior", "format") if key in group):
            return False
        if require_sources and item.get("stages") != group.get("stages"):
            return False
        return True

    def physical_for(item: Mapping[str, Any]) -> Mapping[str, Any] | None:
        group_id = item.get("id")
        result = [stage for stage in stages if stage.get("id") == group_id]
        if len(result) != 1:
            return None
        stage = result[0]
        if (
            stage.get("slot") != item.get("slot")
            or not _same_physical_group_fields(platform, stage, item, identity_keys)
            or stage.get("sources") != item.get("stages")
            or stage.get("group_by_platform", {}).get(platform) != group_id
        ):
            return None
        return stage

    current_id_groups = [item for item in groups if isinstance(item, Mapping) and item.get("id") == group.get("id")]
    if len(current_id_groups) > 1:
        return None
    if current_id_groups:
        current_group = current_id_groups[0]
        current_physical = physical_for(current_group)
        if current_physical is not None and same_interface(current_group, require_sources=True):
            return current_physical
        return _reclassified_compact_source_stage(candidate, platform, group)

    if not isinstance(group.get("slot"), str):
        return None
    matching = [
        item for item in groups
        if isinstance(item, Mapping)
        and same_interface(item, require_sources=True)
    ]
    if len(matching) == 1:
        return physical_for(matching[0])
    if matching:
        return None
    return _reclassified_compact_source_stage(candidate, platform, group)


def _reclassified_compact_source_stage(
    candidate: Any, platform: str, group: Mapping[str, Any],
) -> Mapping[str, Any] | None:
    """Replay a reclassified old group from its identity-checked current physical rules.

    Only rules emitted in the old slot and semantic run are considered, so a
    source stage's canary or IP rules deferred to another slot cannot be pulled
    into the old group. Old same-run domain-set siblings identify domain rules
    that the old classical resource excluded. Rule counts are intentionally not
    used as historical gates: the replay maps current archived source bytes.
    """
    stage_ids = group.get("stages")
    identities = group.get("source_stage_identity")
    behavior = group.get("behavior")
    slot = group.get("slot")
    sibling_domain_stages = group.get("sibling_domain_stages", [])
    if (
        not isinstance(stage_ids, list) or not stage_ids
        or len(stage_ids) != len(set(stage_ids))
        or not isinstance(identities, Mapping) or set(identities) != set(stage_ids)
        or behavior not in {"domain-set", "classical"}
        or group.get("kind") != "route"
        or not isinstance(slot, str)
        or not isinstance(sibling_domain_stages, list)
        or any(stage_id not in stage_ids for stage_id in sibling_domain_stages)
    ):
        return None
    current_stages = {
        stage.get("id"): stage for stage in getattr(candidate, "stages", [])
        if isinstance(stage, Mapping) and isinstance(stage.get("id"), str)
    }
    fine_rules: dict[str, list[Any]] = {}
    for stage_id in stage_ids:
        expected = identities.get(stage_id)
        source_stage = current_stages.get(stage_id)
        if not isinstance(expected, Mapping) or not isinstance(source_stage, Mapping):
            return None
        if any(source_stage.get(key) != value for key, value in expected.items()):
            return None
        stage_rules = source_stage.get("rules", [])
        if not isinstance(stage_rules, list):
            return None
        fine_rules[stage_id] = [rule for rule in stage_rules if getattr(rule, "platform", None) == platform]

    compact = candidate.manifest.get("compact")
    compact_groups = compact.get("groups") if isinstance(compact, Mapping) else None
    current_groups = compact_groups.get(platform) if isinstance(compact_groups, Mapping) else None
    if not isinstance(current_groups, list):
        return None
    physical_stages = _candidate_stages(candidate, platform)
    physical_by_id = {
        stage.get("id"): stage for stage in physical_stages
        if isinstance(stage, Mapping) and isinstance(stage.get("id"), str)
    }
    identity_keys = ("action", "dns", "reject_mode", "extended_matching", "no_resolve")
    fine_stage_by_rule: dict[int, str] = {}
    for stage_id, stage_rules in fine_rules.items():
        for rule in stage_rules:
            if id(rule) in fine_stage_by_rule:
                return None
            fine_stage_by_rule[id(rule)] = stage_id
    selected_rule_ids: set[int] = set()
    found_matching_group = False
    for current_group in current_groups:
        if not isinstance(current_group, Mapping):
            return None
        current_stage_ids = current_group.get("stages")
        if not isinstance(current_stage_ids, list):
            return None
        if (
            current_group.get("slot") != slot
            or current_group.get("kind") != "route"
            or not _same_physical_group_fields(platform, current_group, group, identity_keys)
            or not (set(current_stage_ids) & set(stage_ids))
        ):
            continue
        current_behavior = current_group.get("behavior")
        current_format = current_group.get("format")
        if (
            current_behavior not in {"domain-set", "classical"}
            or current_format not in ({"mrs", "text"} if platform == "mihomo" else {"set", "text"})
            or (current_behavior == "domain-set" and current_format != ("mrs" if platform == "mihomo" else "set"))
            or (current_behavior == "classical" and current_format != "text")
        ):
            return None
        group_id = current_group.get("id")
        physical = physical_by_id.get(group_id)
        if (
            not isinstance(group_id, str) or physical is None
            or physical.get("slot") != slot
            or physical.get("sources") != current_stage_ids
            or physical.get("group_by_platform", {}).get(platform) != group_id
            or not _same_physical_group_fields(platform, physical, current_group, identity_keys)
        ):
            return None
        found_matching_group = True
        for rule in physical.get("rules", []):
            stage_id = fine_stage_by_rule.get(id(rule))
            if stage_id in stage_ids:
                selected_rule_ids.add(id(rule))
    if not found_matching_group:
        return None

    rules: list[Any] = []
    seen: set[tuple[str, str, str, tuple[str, ...]]] = set()
    sibling_domain_stages = set(sibling_domain_stages)
    for stage_id in stage_ids:
        for rule in fine_rules[stage_id]:
            if id(rule) not in selected_rule_ids:
                continue
            if behavior == "domain-set" and rule.type not in DOMAIN_RULE_TYPES:
                continue
            if behavior == "classical" and stage_id in sibling_domain_stages and rule.type in DOMAIN_RULE_TYPES:
                continue
            key = (str(rule.platform), str(rule.type), str(rule.value), tuple(rule.flags))
            if key not in seen:
                seen.add(key)
                rules.append(rule)
    return {"id": group.get("id"), "rules": rules}


def _split_rule_fields(line: str) -> list[str]:
    fields: list[str] = []
    current: list[str] = []
    depth = 0
    quoted = False
    escaped = False
    for char in line:
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
            current.append(char)
            continue
        if not quoted:
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth < 0:
                    raise ProfileClientsError("baseline rule has unbalanced parentheses")
            elif char == "," and depth == 0:
                fields.append("".join(current).strip().strip('"'))
                current = []
                continue
        current.append(char)
    if quoted or depth != 0:
        raise ProfileClientsError("baseline rule has an unterminated quote or parenthesis")
    fields.append("".join(current).strip().strip('"'))
    return fields


def _doh_and_components(value: str) -> tuple[str, str] | None:
    match = re.fullmatch(
        r"\(\(\s*PROTOCOL\s*,\s*([^(),]+?)\s*\)\s*,\s*\(\s*DOMAIN\s*,\s*([^()]+?)\s*\)\s*\)",
        value.strip(), flags=re.IGNORECASE,
    )
    if not match or match.group(1).strip().upper() != "DOH":
        return None
    return "DOH", match.group(2).strip()


def _as_profile_rule(api: Any, platform: str, rule_type: str, value: str, flags: Sequence[str], source: str, line: int):
    if rule_type == "GEOIP":
        if not re.fullmatch(r"[A-Z]{2}|LAN", value) or set(flags) - {"no-resolve"} or len(flags) != len(set(flags)):
            raise ProfileClientsError("baseline contains an invalid GEOIP rule")
        return api.Rule("GEOIP", value, tuple(flags), source, line, platform)
    if rule_type == "MATCH":
        if value not in {"", "*"}:
            raise ProfileClientsError("MATCH rule has an unexpected value")
        return api.Rule("MATCH", "*", tuple(flags), source, line, platform)
    try:
        return api._rule_from_parts(rule_type, value, flags, source, line, platform)
    except Exception as exc:
        raise ProfileClientsError(f"baseline contains an invalid {rule_type} rule") from exc


def _stage(action: str, reject_mode: str | None, rules: Sequence[Any], *, stage_id: str, extended: bool = False, dns: str = "none") -> dict[str, Any]:
    return {
        "id": stage_id, "action": action, "reject_mode": reject_mode,
        "extended_matching": extended, "no_resolve": False, "dns": dns,
        "rules": list(rules),
    }


def _private_inline_stages(
    api: Any, platform: str, baseline: Any, candidate: Any,
    aliases: Mapping[str, set[str]], unsupported: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Retain baseline inline route exceptions ahead of the profile stages."""
    if platform == "mihomo":
        raw_rules = baseline.get("rules", [])
        if not isinstance(raw_rules, list):
            raise ProfileClientsError("Mihomo baseline rules must be an array")
    else:
        _, sections = _surge_sections(str(baseline))
        raw_rules = _surge_rule_lines(_section(sections, "Rule"))
    known_targets = _known_policy_targets(platform, baseline)
    result: list[dict[str, Any]] = []
    for line_no, raw in enumerate(raw_rules, 1):
        if not isinstance(raw, str):
            raise ProfileClientsError(f"{platform} baseline contains a non-string route rule")
        fields = _split_rule_fields(raw.strip())
        if not fields:
            continue
        kind = fields[0].upper()
        if kind in {"RULE-SET", "DOMAIN-SET", "GEOIP", "MATCH", "FINAL"}:
            continue
        if kind == "AND":
            compound = _doh_and_components(fields[1]) if len(fields) == 3 else None
            if compound:
                actual_action, actual_reject = _old_policy(fields[2], known_targets)
                if (
                    platform == "surge" and compound[1].casefold().rstrip(".") == "doh.pub"
                    and actual_action == "DIRECT" and actual_reject is None
                    and _is_builtin_direct_route_target(platform, baseline, fields[2])
                ):
                    # The old explicit doh.pub bypass is retired with the
                    # other locally pinned resolver endpoints. Keep it in the
                    # old side of the comparison so its route change remains
                    # visible there.
                    continue
                try:
                    endpoint_ip = str(ipaddress.ip_address(compound[1]))
                except ValueError:
                    endpoint_ip = ""
                expected_actions = DOH_ENDPOINT_ACTIONS.get(endpoint_ip, set())
                if actual_action in expected_actions and actual_reject is None:
                    continue
            if platform != "surge" or len(fields) < 3:
                raise ProfileClientsError("baseline has an unsupported inline AND route rule")
            action, reject_mode = _old_policy(fields[2], known_targets)
            rule = _as_profile_rule(api, platform, "AND", fields[1], (), f"baseline:{platform}:line-{line_no}", line_no)
            result.append(_stage(action, reject_mode, [rule], stage_id=f"local-inline-{platform}-{line_no}"))
            continue
        if kind in {"URL-REGEX", "URL-REGEXP"}:
            if platform != "surge" or len(fields) < 3:
                raise ProfileClientsError("baseline has an unsupported inline URL-REGEX rule")
            action, reject_mode = _old_policy(fields[2], known_targets)
            rule = _as_profile_rule(api, platform, "URL-REGEX", fields[1], (), f"baseline:{platform}:line-{line_no}", line_no)
            result.append(_stage(action, reject_mode, [rule], stage_id=f"local-inline-{platform}-{line_no}"))
            continue
        stage, endpoint = _baseline_route_rule(
            api, platform, fields, line_no, None, {}, aliases, unsupported, known_targets,
            baseline_config=baseline,
        )
        if endpoint:
            continue
        if stage is None:
            raise ProfileClientsError(f"baseline inline route rule {line_no} cannot be retained safely")
        rule = stage["rules"][0]
        if rule.type in {"GEOIP", "MATCH"}:
            continue
        if _retire_known_legacy_route(platform, fields, stage, baseline):
            continue
        if (
            platform == "surge" and rule.type == "DOMAIN"
            and rule.value in {"ruleset.skk.moe", "ruleset-mirror.skk.moe"}
            and stage.get("action") == "JP" and stage.get("reject_mode") is None
        ):
            # Keep the exact rule and its source identity, but make the two
            # clients use the same approved US route for this legacy host.
            stage["action"] = "US"
        if (
            platform == "mihomo" and rule.type == "DOMAIN"
            and _is_builtin_direct_route_target(platform, baseline, fields[2])
            and _mihomo_exact_domain_has_later_direct_suffix(
                raw_rules, line_no, rule.value, known_targets, baseline,
            )
        ):
            continue
        if (
            len(fields) >= 3 and _is_builtin_direct_route_target(platform, baseline, fields[2])
            and stage.get("action") == "DIRECT" and stage.get("reject_mode") is None
            and _inline_domain_rule_covered_by_test(api, rule, candidate, platform)
        ):
            continue
        stage["id"] = f"local-inline-{platform}-{line_no}"
        result.append(stage)
    return result


def _retire_known_legacy_route(
    platform: str, fields: Sequence[str], stage: Mapping[str, Any], baseline: Any,
) -> bool:
    """Remove only reviewed local route exceptions with their original action."""
    if len(fields) < 3 or stage.get("action") != "DIRECT" or stage.get("reject_mode") is not None:
        return False
    if not _is_builtin_direct_route_target(platform, baseline, fields[2]):
        return False
    kind = fields[0].upper()
    value = fields[1].casefold().rstrip(".")
    if kind == "DOMAIN-SUFFIX" and value == "istatmenus.app":
        return True
    return (
        kind == "DOMAIN" and platform == "mihomo"
        and value in {"clash.razord.top", "yacd.haishan.me"}
    )


def _mihomo_exact_domain_has_later_direct_suffix(
    raw_rules: Sequence[Any], line_no: int, domain: str, known_targets: set[str], baseline: Any,
) -> bool:
    """Prove an exact Direct selector redundant across only non-domain rules."""
    safe_intervening = {"IP-CIDR", "IP-CIDR6", "IP-ASN", "GEOIP"}
    canonical_domain = domain.casefold().rstrip(".")
    for raw in raw_rules[line_no:]:
        if not isinstance(raw, str):
            return False
        text = raw.strip()
        if not text or text.startswith(("#", ";")):
            continue
        fields = _split_rule_fields(text)
        if not fields:
            continue
        kind = fields[0].upper()
        if kind == "DOMAIN-SUFFIX" and len(fields) >= 3:
            if fields[1].casefold().rstrip(".") != canonical_domain:
                # Even a different suffix can cover the exact host.
                return False
            return (
                _old_policy(fields[2], known_targets) == ("DIRECT", None)
                and _is_builtin_direct_route_target("mihomo", baseline, fields[2])
            )
        if kind in safe_intervening and len(fields) >= 3:
            if not any(flag.strip().casefold() == "no-resolve" for flag in fields[3:]):
                return False
            try:
                action, reject_mode = _old_policy(fields[2], known_targets)
            except ProfileClientsError:
                return False
            if (
                action == "DIRECT" and reject_mode is None
                and _is_builtin_direct_route_target("mihomo", baseline, fields[2])
            ):
                continue
        # Unknown rules may match this exact domain or run before its suffix.
        return False
    return False


def _retire_known_legacy_dns_selector(platform: str, selector: str, target: Any) -> bool:
    """Retire only the audited Direct resolver selectors from private baselines."""
    normalized = selector.strip().casefold()
    if platform == "mihomo":
        known = {
            "+.istatmenus.app", ".istatmenus.app",
            "clash.razord.top", "yacd.haishan.me",
        }
    else:
        known = {"istatmenus.app", "*.istatmenus.app"}
    if normalized not in known or _has_private_dns_endpoint(target):
        return False
    unsupported: list[dict[str, Any]] = []
    intent, _ = _resolver_policy(target, unsupported, selector, platform=platform)
    return intent == "DIRECT"


def _render_inline_rule(rule: Any, stage: Mapping[str, Any], platform: str) -> str:
    target = _mihomo_target(stage) if platform == "mihomo" else _surge_target(stage)
    fields = [rule.type, rule.value, target]
    fields.extend(flag for flag in rule.flags if flag in {"no-resolve"})
    if platform == "surge" and stage.get("extended_matching"):
        fields.append("extended-matching")
    if rule.type == "AND":
        return ",".join(fields)
    buffer = io.StringIO()
    csv.writer(buffer, lineterminator="").writerow(fields)
    return buffer.getvalue()


def _provider_reference(provider: Mapping[str, Any]) -> str:
    value = provider.get("url") or provider.get("path")
    if not isinstance(value, str) or not value:
        raise ProfileClientsError("baseline rule provider has no URL or local path")
    return value


def _baseline_route_rule(
    api: Any, platform: str, fields: Sequence[str], line_no: int, candidate: Any,
    providers: Mapping[str, Any], aliases: Mapping[str, set[str]], unsupported: list[dict[str, Any]],
    known_targets: set[str], *, baseline_config: Any = None,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    if not fields or not fields[0]:
        raise ProfileClientsError("baseline contains an empty route rule")
    kind = fields[0].upper()
    source_label = f"baseline:{platform}:line-{line_no}"
    if kind in {"RULE-SET", "DOMAIN-SET"}:
        if platform == "mihomo":
            if kind != "RULE-SET" or len(fields) < 3:
                raise ProfileClientsError("Mihomo rule-set has an unsupported shape")
            try:
                provider = providers[fields[1]]
            except KeyError as exc:
                raise ProfileClientsError("Mihomo route references an undefined rule provider") from exc
            if not isinstance(provider, Mapping):
                raise ProfileClientsError("Mihomo rule provider metadata must be a mapping")
            reference = _provider_reference(provider)
            target_at = 2
        else:
            if len(fields) < 3:
                raise ProfileClientsError("Surge rule-set has an unsupported shape")
            reference = fields[1]
            target_at = 2
        action, reject_mode = _old_policy(fields[target_at], known_targets)
        flags = fields[target_at + 1:]
        extended = "extended-matching" in flags
        if any(flag and flag != "no-resolve" and flag != "extended-matching" and not flag.startswith("update-interval=") for flag in flags):
            unsupported.append({"id": source_label, "reason": "unrecognized rule-set option", "rule_type": kind})
        source_id = _resolve_source_reference(reference, aliases, platform=platform)
        rules = _source_rules(candidate, source_id, platform, aliases)
        rule_stage = _stage(action, reject_mode, rules, stage_id=source_label, extended=extended)
        return rule_stage, {"line": line_no, "source": source_id, "action": action, "reject_mode": reject_mode, "extended_matching": extended}

    if kind in {"URL-REGEX", "URL-REGEXP"} and platform == "surge":
        unsupported.append({"id": source_label, "reason": "Surge URL-REGEX is not modeled by domain-only route matching", "rule_type": kind})
        return None, None

    if kind == "AND":
        if len(fields) != 3:
            unsupported.append({"id": source_label, "reason": "unsupported compound route condition", "rule_type": kind})
            return None, None
        match = _doh_and_components(fields[1])
        if match:
            action, reject_mode = _old_policy(fields[2], known_targets)
            try:
                endpoint = str(ipaddress.ip_address(match[1]))
            except ValueError:
                if (
                    platform == "surge" and match[1].casefold().rstrip(".") == "doh.pub"
                    and action == "DIRECT" and reject_mode is None
                    and baseline_config is not None
                    and _is_builtin_direct_route_target(platform, baseline_config, fields[2])
                ):
                    rule = _as_profile_rule(api, platform, "AND", fields[1], (), source_label, line_no)
                    return _stage(action, reject_mode, [rule], stage_id=source_label), None
                unsupported.append({"id": source_label, "reason": "DoH route endpoint is not a literal IP", "rule_type": kind})
                return None, None
            expected_actions = DOH_ENDPOINT_ACTIONS.get(endpoint, set())
            if action in expected_actions and reject_mode is None:
                return None, {"endpoint_ip": endpoint, "action": action, "reject_mode": reject_mode, "protocol": "DOH"}
        if platform == "surge" and len(fields) >= 3:
            action, reject_mode = _old_policy(fields[2], known_targets)
            rule = _as_profile_rule(api, platform, "AND", fields[1], (), source_label, line_no)
            return _stage(action, reject_mode, [rule], stage_id=source_label), None
        unsupported.append({"id": source_label, "reason": "unsupported compound route condition", "rule_type": kind})
        return None, None

    if kind == "FINAL":
        if len(fields) < 2:
            raise ProfileClientsError("Surge FINAL rule has no policy")
        action, reject_mode = _old_policy(fields[1], known_targets)
        flags = fields[2:]
        unsupported_flags = [flag for flag in flags if flag and flag != "dns-failed"]
        if unsupported_flags:
            unsupported.append({"id": source_label, "reason": "unrecognized FINAL option", "options": unsupported_flags})
        rule = _as_profile_rule(api, platform, "MATCH", "*", (), source_label, line_no)
        return _stage(action, reject_mode, [rule], stage_id=source_label), None

    if platform == "mihomo":
        if kind == "MATCH":
            if len(fields) < 2:
                raise ProfileClientsError("Mihomo MATCH rule has no policy")
            value, target_at = "*", 1
        else:
            if len(fields) < 3:
                raise ProfileClientsError(f"Mihomo {kind} rule has an unsupported shape")
            value, target_at = fields[1], 2
        action, reject_mode = _old_policy(fields[target_at], known_targets)
        flags = fields[target_at + 1:]
    else:
        if len(fields) < 2:
            raise ProfileClientsError(f"Surge {kind} rule has an unsupported shape")
        if kind == "FINAL":
            raise ProfileClientsError("Surge FINAL parser dispatch failed")
        if len(fields) < 3:
            raise ProfileClientsError(f"Surge {kind} rule has an unsupported shape")
        value, target_at = fields[1], 2
        action, reject_mode = _old_policy(fields[target_at], known_targets)
        flags = fields[target_at + 1:]
    allowed_flags = {"no-resolve", "extended-matching"}
    unexpected = [flag for flag in flags if flag and flag not in allowed_flags and not flag.startswith("update-interval=") and flag != "dns-failed"]
    if unexpected:
        unsupported.append({"id": source_label, "reason": "unrecognized route options", "options": unexpected})
    extended = "extended-matching" in flags
    if kind == "FINAL":
        kind, value = "MATCH", "*"
    rule = _as_profile_rule(api, platform, kind, value, [flag for flag in flags if flag == "no-resolve"], source_label, line_no)
    return _stage(action, reject_mode, [rule], stage_id=source_label, extended=extended), None


def _parse_old_routes(api: Any, platform: str, candidate: Any, baseline: Any, aliases: Mapping[str, set[str]], unsupported: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    stages: list[dict[str, Any]] = []
    endpoint_routes: list[dict[str, Any]] = []
    known_targets = _known_policy_targets(platform, baseline)
    if platform == "mihomo":
        providers = baseline.get("rule-providers", {})
        rules = baseline.get("rules", [])
        if not isinstance(providers, Mapping) or not isinstance(rules, list):
            raise ProfileClientsError("Mihomo baseline rule-providers/rules have invalid types")
        for line_no, raw in enumerate(rules, 1):
            if not isinstance(raw, str):
                raise ProfileClientsError("Mihomo baseline contains a non-string route rule")
            fields = _split_rule_fields(raw)
            stage, endpoint = _baseline_route_rule(
                api, platform, fields, line_no, candidate, providers, aliases, unsupported,
                known_targets, baseline_config=baseline,
            )
            if stage:
                stages.append(stage)
            if endpoint:
                endpoint_routes.append(endpoint)
    else:
        _, sections = _surge_sections(str(baseline))
        route = _section(sections, "Rule")
        for line_no, raw in enumerate(route.lines, 1):
            text = raw.strip()
            if not text or text.startswith(("#", ";")):
                continue
            fields = _split_rule_fields(text)
            stage, endpoint = _baseline_route_rule(
                api, platform, fields, line_no, candidate, {}, aliases, unsupported,
                known_targets, baseline_config=baseline,
            )
            if stage:
                stages.append(stage)
            if endpoint:
                endpoint_routes.append(endpoint)
    if not stages or not any(rule.type == "MATCH" for stage in stages for rule in stage["rules"]):
        raise ProfileClientsError(f"{platform} baseline has no supported terminal route rule")
    return stages, endpoint_routes


def _explicit_surge_test_selector(selector: str) -> bool:
    value = selector.strip().strip('"')
    if ":" in value:
        kind, reference = value.split(":", 1)
        if kind.upper() not in {"RULE-SET", "DOMAIN-SET"}:
            return False
    else:
        reference = value
    parsed = urllib.parse.urlsplit(reference)
    label = Path(parsed.path or reference).name.casefold()
    stem = Path(label).stem
    return stem in {"test", "network-test", "priority-test-domain"}


def _resolver_class(value: str, selector: str = "", *, platform: str | None = None) -> str | None:
    raw = value.strip().strip('"')
    if raw.startswith("server:"):
        raw = raw[len("server:"):]
    lowered = raw.casefold()
    if lowered in {"system", "system://"}:
        return "system"
    parsed = urllib.parse.urlsplit(raw)
    fragment_parts = urllib.parse.unquote(parsed.fragment).split("&")
    policy_fragments = [
        part.strip() for part in fragment_parts
        if part.strip() and "=" not in part and part.strip().casefold() != "rules"
    ]
    if policy_fragments:
        fragment = policy_fragments[-1].casefold()
        policy_actions = {
            **{name.casefold(): action for action, name in MIHOMO_POLICY_ALIASES.items()},
            **{name.casefold(): action for action, name in SURGE_POLICY_ALIASES.items()},
            **{name.casefold(): action for action, name in MIHOMO_REGION_GROUPS.items()},
            **{name.casefold(): action for action, name in SURGE_REGION_GROUPS.items()},
            "test": "TEST", "direct": "DIRECT", "jp": "JP", "us": "US",
        }
        fragment_action = policy_actions.get(fragment)
        if fragment_action in {"TEST", "DIRECT", "JP", "US"}:
            return fragment_action
    host = (parsed.hostname or raw.split("#", 1)[0]).casefold()
    if platform == "surge" and host == "8.8.4.4" and _explicit_surge_test_selector(selector):
        return "TEST"
    if host == "8.8.4.4" and any(token in selector.casefold() for token in ("test", "测速", "网络测试")):
        return "TEST"
    if host in {"1.0.0.1", "8.8.4.4"}:
        return "JP"
    if host in {"8.8.8.8", "1.1.1.1", "dns.google", "cloudflare-dns.com"}:
        return "US"
    if host in {"223.5.5.5", "1.12.12.12", "doh.pub", "dns.alidns.com", "alidns.com"}:
        return "DIRECT"
    return None


def _resolver_policy(
    values: Any, unsupported: list[dict[str, Any]], selector: str, *, platform: str | None = None,
) -> tuple[str, list[str]]:
    if isinstance(values, str):
        raw_values = [values]
    elif isinstance(values, list) and all(isinstance(value, str) for value in values):
        raw_values = values
    else:
        unsupported.append({"id": selector, "reason": "resolver selector has an unsupported target shape"})
        return "unsupported", []
    if not raw_values:
        unsupported.append({"id": selector, "reason": "resolver selector has no endpoints"})
        return "unsupported", []
    classes = [_resolver_class(value, selector, platform=platform) for value in raw_values]
    if any(value is None for value in classes):
        unsupported.append({"id": selector, "reason": "resolver endpoint is outside the known US/JP/DIRECT/system map"})
        return "unsupported", raw_values
    unique = sorted(set(str(value) for value in classes))
    if len(unique) != 1:
        unsupported.append({"id": selector, "reason": "resolver selector combines different resolver ownership classes"})
        return "unsupported", raw_values
    intent = unique[0]
    return intent, raw_values


def _surge_server_values(target: str) -> list[str]:
    value = target.strip()
    if not value.startswith("server:"):
        return [value]
    endpoint_list = value[len("server:"):].strip()
    if endpoint_list.casefold() == "system":
        return ["system"]
    try:
        return [item.strip().strip('"') for item in _split_csv(endpoint_list) if item.strip()]
    except ProfileClientsError:
        raise ProfileClientsError("Surge Host selector has malformed resolver endpoint list") from None


def _mihomo_rule_set_names(selector: str) -> list[str] | None:
    prefix = "rule-set:"
    if not selector.casefold().startswith(prefix):
        return None
    names: list[str] = []
    for item in selector[len(prefix):].split(","):
        name = item.strip()
        if name.casefold().startswith(prefix):
            name = name[len(prefix):].strip()
        if not name or "," in name:
            raise ProfileClientsError("private Mihomo rule-set selector has an empty or malformed provider name")
        names.append(name)
    if not names:
        raise ProfileClientsError("private Mihomo rule-set selector contains no providers")
    return names


def _selector_rules(api: Any, platform: str, selector: str, candidate: Any, aliases: Mapping[str, set[str]], unsupported: list[dict[str, Any]]) -> tuple[list[Any], bool]:
    value = selector.strip().strip('"')
    if value.startswith(("RULE-SET:", "DOMAIN-SET:")):
        reference = value.split(":", 1)[1]
        source_id = _resolve_source_reference(reference, aliases, platform=platform)
        rules = _source_rules(candidate, source_id, platform, aliases)
        return [rule for rule in rules if rule.type in DOMAIN_RULE_TYPES], False
    rule_type = "DOMAIN"
    if value.startswith("domain:"):
        value = value.split(":", 1)[1]
    elif value.startswith("domain-suffix:"):
        rule_type, value = "DOMAIN-SUFFIX", value.split(":", 1)[1]
    elif value.startswith("keyword:"):
        rule_type, value = "DOMAIN-KEYWORD", value.split(":", 1)[1]
    elif value.startswith("domain-wildcard:"):
        rule_type, value = "DOMAIN-WILDCARD", value.split(":", 1)[1]
    elif value.startswith("+."):
        rule_type, value = "DOMAIN-SUFFIX", value[2:]
    elif value.startswith("."):
        rule_type, value = "DOMAIN-SUFFIX", value[1:]
    elif value.startswith(("geosite:", "regexp:", "ip:", "geoip:", "process:")):
        unsupported.append({"id": value, "reason": "DNS selector syntax is not represented by domain-only RuleIndex"})
        return [], False
    if rule_type == "DOMAIN" and ("*" in value or "?" in value):
        rule_type = "DOMAIN-WILDCARD"
    try:
        rule = api._rule_from_parts(rule_type, value, (), f"dns-selector:{selector}", 1, platform)
    except Exception:
        unsupported.append({"id": selector, "reason": "DNS selector has an unsupported or invalid domain shape"})
        return [], False
    return [rule], False


def _is_local_dns_scope(rule: Any) -> bool:
    if rule.type in {"DOMAIN", "DOMAIN-SUFFIX"}:
        domain = rule.value
    elif rule.type == "DOMAIN-WILDCARD" and rule.value.startswith("*.") and rule.value.count("*") == 1 and "?" not in rule.value:
        domain = rule.value[2:]
    else:
        return False
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        return True
    return any(domain == suffix or domain.endswith("." + suffix) for suffix in LOCAL_DNS_SUFFIXES)


def _has_private_dns_endpoint(values: Any) -> bool:
    endpoints = [values] if isinstance(values, str) else values if isinstance(values, (list, tuple)) else []
    for value in endpoints:
        if not isinstance(value, str):
            continue
        raw = value.strip().removeprefix("server:")
        try:
            parsed = urllib.parse.urlsplit(raw)
            host = parsed.hostname
            if host is None and "://" not in raw:
                # Bare address:port and bracketed IPv6 address:port endpoints
                # have no URL scheme, so parse them as an authority.
                host = urllib.parse.urlsplit("//" + raw.split("#", 1)[0]).hostname
        except ValueError:
            # Keep malformed endpoint forms conservatively; they are not a
            # reason to discard an existing private resolver override.
            return True
        host = (host or raw.split("#", 1)[0]).casefold().rstrip(".")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            if not host or "." not in host or any(
                host == suffix or host.endswith("." + suffix) for suffix in LOCAL_DNS_SUFFIXES
            ):
                return True
        else:
            if not address.is_global:
                return True
    return False


def _domain_rule_scope_covered(api: Any, selection: Any, cover: Any) -> bool:
    """Return true only when one managed selector covers the complete old scope."""
    if selection.type == "DOMAIN":
        if not isinstance(cover, api.Rule):
            cover = api.Rule(
                cover.type, cover.value, tuple(getattr(cover, "flags", ())),
                getattr(cover, "source", ""), getattr(cover, "line", 0), getattr(cover, "platform", ""),
            )
        return api.rule_matches(cover, domain=selection.value)
    if selection.type == "DOMAIN-SUFFIX":
        return (
            cover.type == "DOMAIN-SUFFIX"
            and (selection.value == cover.value or selection.value.endswith("." + cover.value))
        )
    if selection.type == "DOMAIN-WILDCARD":
        if cover.type == "DOMAIN-WILDCARD" and selection.value == cover.value:
            return True
        # A simple *.tail wildcard has no matches outside tail, so a managed
        # suffix selector for tail (or one of its parents) covers its full scope.
        if (
            cover.type == "DOMAIN-SUFFIX"
            and selection.value.startswith("*.")
            and selection.value.count("*") == 1
            and "?" not in selection.value
        ):
            tail = selection.value[2:]
            return tail == cover.value or tail.endswith("." + cover.value)
    return False


def _managed_test_domain_rules(candidate: Any, platform: str) -> list[Any]:
    return [
        rule
        for stage in _make_dns_stages(candidate, platform)
        if stage.get("action") == "TEST"
        for rule in stage.get("rules", [])
        if rule.platform == platform and rule.type in DOMAIN_RULE_TYPES
    ]


def _inline_domain_rule_covered_by_test(api: Any, rule: Any, candidate: Any, platform: str) -> bool:
    if rule.type not in {"DOMAIN", "DOMAIN-SUFFIX"} or _is_local_dns_scope(rule):
        return False
    return any(
        _domain_rule_scope_covered(api, rule, test_rule)
        for test_rule in _managed_test_domain_rules(candidate, platform)
    )


def _dns_inline_selector_superseded_by_test(
    selector: str, target: Any, candidate: Any, platform: str, api: Any,
    aliases: Mapping[str, set[str]],
) -> bool:
    """Drop a known public inline DNS override only when Test owns all its scope."""
    if platform == "mihomo" and _mihomo_rule_set_names(selector) is not None:
        return False
    if platform == "surge" and selector.startswith(("RULE-SET:", "DOMAIN-SET:")):
        return False

    if platform == "surge" and isinstance(target, str) and target.startswith("server:"):
        try:
            target = _surge_server_values(target)
        except ProfileClientsError:
            return False

    unsupported: list[dict[str, Any]] = []
    intent, _ = _resolver_policy(target, unsupported, selector, platform=platform)
    if intent not in {"US", "JP", "DIRECT", "TEST"}:
        return False
    if _has_private_dns_endpoint(target):
        return False

    selector_rules, extended = _selector_rules(api, platform, selector, candidate, aliases, unsupported)
    if extended or not selector_rules:
        return False
    if any(rule.type not in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-WILDCARD"} for rule in selector_rules):
        return False
    if any(_is_local_dns_scope(rule) for rule in selector_rules):
        return False

    test_rules = _managed_test_domain_rules(candidate, platform)
    return bool(test_rules) and all(
        any(_domain_rule_scope_covered(api, selection, cover) for cover in test_rules)
        for selection in selector_rules
    )


def _parse_old_dns(api: Any, platform: str, candidate: Any, baseline: Any, aliases: Mapping[str, set[str]], unsupported: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], str, list[dict[str, Any]]]:
    selectors: list[dict[str, Any]] = []
    if platform == "mihomo":
        dns = baseline.get("dns", {})
        if not isinstance(dns, Mapping):
            raise ProfileClientsError("Mihomo baseline dns section must be a mapping")
        providers = baseline.get("rule-providers", {})
        policy = dns.get("nameserver-policy", {})
        if not isinstance(policy, Mapping):
            raise ProfileClientsError("Mihomo nameserver-policy must be a mapping")
        known_targets = _known_policy_targets("mihomo", baseline)
        for position, (raw_selector, target) in enumerate(policy.items()):
            selector = str(raw_selector)
            normalized_target = _normalize_resolver_target(target, known_targets)
            provider_names = _mihomo_rule_set_names(selector)
            if provider_names is None:
                rules, extended = _selector_rules(api, platform, selector, candidate, aliases, unsupported)
            else:
                # One Mihomo rule-set selector may name a comma-separated union.
                # Expand known archived members in the original order; custom
                # members remain preserved by migration and explicitly unsupported.
                rules = []
                for name in provider_names:
                    provider = providers.get(name) if isinstance(providers, Mapping) else None
                    if not isinstance(provider, Mapping):
                        raise ProfileClientsError("Mihomo DNS selector references an undefined provider")
                    try:
                        source_id = _resolve_source_reference(_provider_reference(provider), aliases, platform=platform)
                        source_rules = _source_rules(candidate, source_id, platform, aliases)
                    except ProfileClientsError:
                        unsupported.append({
                            "id": f"{selector}:{name}",
                            "reason": "custom Mihomo DNS provider is preserved but its rule contents are not present in the archived profile source map",
                        })
                        continue
                    rules.extend(rule for rule in source_rules if rule.type in DOMAIN_RULE_TYPES)
                extended = False
            intent, raw_servers = _resolver_policy(normalized_target, unsupported, selector, platform="mihomo")
            if rules:
                selectors.append(_stage(intent, None, rules, stage_id=f"old-dns-{platform}-{position}", extended=extended, dns=intent))
                selectors[-1]["selector"] = selector
                selectors[-1]["servers"] = raw_servers
        default_values = dns.get("nameserver", [])
        default, _ = _resolver_policy(default_values, unsupported, "mihomo-default-dns", platform="mihomo")
    else:
        _, sections = _surge_sections(str(baseline))
        general = _section(sections, "General")
        host = _section(sections, "Host", create=True)
        for position, raw in enumerate(host.lines, 1):
            text = raw.strip()
            if not text or text.startswith(("#", ";")) or "=" not in text:
                continue
            selector, target = (part.strip() for part in text.split("=", 1))
            if not target.startswith("server:"):
                # IPv4/IPv6 Host mappings are local exceptions, not DNS resolver rules.
                continue
            rules, extended = _selector_rules(api, platform, selector, candidate, aliases, unsupported)
            intent, raw_servers = _resolver_policy(_surge_server_values(target), unsupported, selector, platform="surge")
            selectors.append(_stage(intent, None, rules, stage_id=f"old-dns-{platform}-{position}", extended=extended, dns=intent))
            selectors[-1]["selector"] = selector
            selectors[-1]["servers"] = raw_servers
        general_by_key: dict[str, list[str]] = {}
        for raw in general.lines:
            stripped = raw.strip()
            if stripped.startswith(("#", ";")) or "=" not in stripped:
                continue
            key, value = (part.strip() for part in stripped.split("=", 1))
            if key.casefold() in {"encrypted-dns-server", "dns-server"}:
                general_by_key.setdefault(key.casefold(), []).extend(item.strip() for item in value.split(",") if item.strip())
        general_values = general_by_key.get("encrypted-dns-server") or general_by_key.get("dns-server", [])
        default, _ = _resolver_policy(
            general_values, unsupported, "surge-default-dns", platform="surge",
        ) if general_values else ("system", [])
    return selectors, default, []


def _match_results(index: Any, subject: Mapping[str, Any], platform: str, *, extended_cname: bool = True) -> list[Any]:
    clean = {key: value for key, value in subject.items() if key != "cname"}
    results = list(index.matching_rules(**clean))
    cnames = subject.get("cname", ())
    if isinstance(cnames, str):
        cnames = [cnames]
    if platform == "surge" and extended_cname and isinstance(cnames, (list, tuple)):
        for cname in cnames:
            for result in index.matching_rules(domain=str(cname)):
                if result.stage.get("extended_matching"):
                    results.append(result)
    unique = {(item.stage_index, item.rule_index): item for item in results}
    return sorted(unique.values(), key=lambda item: (item.stage_index, item.rule_index))


def _first_route(index: Any, stages: Sequence[Mapping[str, Any]], subject: Mapping[str, Any], platform: str, api: Any):
    matches = _match_results(index, subject, platform)
    if matches:
        return matches[0]
    # Some indexed API implementations omit MATCH from the search index. Keep
    # the explicit manifest/baseline terminal as the final fallback.
    for stage_index, stage in enumerate(stages):
        for rule_index, rule in enumerate(stage.get("rules", [])):
            if rule.platform == platform and rule.type == "MATCH":
                return api.MatchResult(stage, rule, stage_index, rule_index)
    return None


def _result_route(result: Any) -> dict[str, Any] | None:
    if result is None:
        return None
    reject_mode = result.reject_mode
    if result.rule.platform == "mihomo" and reject_mode == "no-drop":
        # This Surge-only variant renders as ordinary REJECT on Mihomo.
        reject_mode = "plain"
    return {
        "stage": result.stage.get("id"), "action": result.action,
        "slot": result.stage.get("slot"), "stage_index": result.stage_index,
        "reject_mode": reject_mode,
    }


def _dns_default_dns(intent: str) -> str:
    return intent if intent in {"US", "JP", "TEST", "DIRECT", "system"} else "unsupported"


def _dns_match(index: Any, stages: Sequence[Mapping[str, Any]], subject: Mapping[str, Any], platform: str, default: str):
    matches = _match_results(index, subject, platform)
    if matches:
        stage = matches[0].stage
        intent = str(stage.get("dns", "unsupported"))
        action = stage.get("action")
        if intent == "foreign":
            intent = "JP" if action == "JP" else "US"
        elif intent == "domestic":
            intent = "DIRECT"
        elif intent == "jp":
            intent = "JP"
        elif intent in {"us", "jp", "test", "direct", "system"}:
            intent = intent.upper() if intent != "system" else "system"
        return intent, stage.get("selector"), matches[0]
    return _dns_default_dns(default), None, None


def _domain_only_stages(stages: Sequence[Mapping[str, Any]], platform: str) -> list[dict[str, Any]]:
    result = []
    for stage in stages:
        rules = [rule for rule in stage.get("rules", []) if rule.platform == platform and rule.type in DOMAIN_RULE_TYPES]
        if rules:
            result.append({**stage, "rules": rules})
    return result


def _subject_examples(rule: Any, api: Any) -> list[tuple[dict[str, Any], str]]:
    rule_type, value = rule.type, rule.value
    if rule_type == "DOMAIN":
        return [({"domain": value}, "source-rule")]
    if rule_type == "DOMAIN-SUFFIX":
        return [({"domain": value}, "source-rule-root"), ({"domain": "probe." + value}, "derived-subdomain")]
    if rule_type == "DOMAIN-KEYWORD":
        host = value.strip(".-") + ".example"
        return [({"domain": host}, "synthetic-keyword-probe")]
    if rule_type == "DOMAIN-WILDCARD":
        host = value.replace("*", "probe").replace("?", "x")
        return [({"domain": host}, "synthetic-wildcard-probe")]
    if rule_type == "AND":
        try:
            components = api._and_components(value)
        except Exception:
            return []
        protocol = next((item for kind, item in components if kind == "PROTOCOL"), None)
        domain = next(((kind, item) for kind, item in components if kind != "PROTOCOL"), None)
        if protocol is None or domain is None:
            return []
        kind, host = domain
        if kind == "DOMAIN":
            return [({"domain": host, "protocol": protocol}, "source-rule")]
        return [
            ({"domain": host, "protocol": protocol}, "source-rule-root"),
            ({"domain": "probe." + host, "protocol": protocol}, "derived-subdomain"),
        ]
    if rule_type in {"IP-CIDR", "IP-CIDR6"}:
        network = ipaddress.ip_network(value)
        address = network.network_address
        if network.num_addresses > 2:
            address = address + 1
        return [({"ip": str(address)}, "source-cidr-representative")]
    if rule_type == "IP-ASN":
        return [({"asn": rule.value}, "explicit-asn-metadata")]
    if rule_type == "PROCESS-NAME":
        return [({"process": value}, "source-process-rule")]
    if rule_type == "USER-AGENT":
        return [({"user_agent": value}, "source-user-agent-rule")]
    if rule_type == "GEOIP":
        return [({"geoip": value}, "explicit-geoip-metadata")]
    return []


def _matching_representatives(rule: Any, api: Any) -> list[tuple[dict[str, Any], str]]:
    if (rule.type, rule.value) == getattr(api, "SUKKA_IP_CANARY", None):
        return []
    result = []
    for subject, evidence in _subject_examples(rule, api):
        try:
            if api.rule_matches(rule, **subject):
                result.append((subject, evidence))
        except Exception:
            continue
    return result


def _route_signature(route: Mapping[str, Any] | None) -> tuple[str, str | None] | None:
    if route is None:
        return None
    action = str(route.get("action"))
    if action == "REJECT":
        return action, route.get("reject_mode")
    # TEST remains a user-selectable policy. A baseline's remembered choice is
    # not evidence of the selection that will be active after deployment.
    return action, None


def _diff_bucket(buckets: dict[str, dict[str, Any]], old_value: Any, new_value: Any, subject: Mapping[str, Any], evidence: str) -> None:
    if old_value == new_value:
        return
    key = f"{old_value!s} -> {new_value!s}"
    bucket = buckets.setdefault(key, {"old": old_value, "new": new_value, "count": 0, "examples": []})
    bucket["count"] += 1
    if len(bucket["examples"]) < 5:
        bucket["examples"].append({"subject": _public_subject(subject), "evidence": evidence})


def _public_subject(subject: Mapping[str, Any]) -> dict[str, Any]:
    allowed = {"domain", "ip", "process", "user_agent", "asn", "geoip", "country", "cname"}
    return {key: value for key, value in subject.items() if key in allowed}


def _make_dns_stages(candidate: Any, platform: str) -> list[dict[str, Any]]:
    result = []
    for stage in _domain_only_stages(_candidate_stages(candidate, platform), platform):
        if stage.get("dns") == "none":
            continue
        result.append(stage)
    return result


def _retained_dns_stages(old_stages: Sequence[Mapping[str, Any]], candidate: Any, platform: str) -> list[dict[str, Any]]:
    """Keep baseline local/unrelated DNS selectors while replacing migrated sources."""
    api = _load_api(ROOT)
    profile_sources = {
        rule.source
        for stage in _candidate_stages(candidate, platform) if stage.get("dns") != "none"
        for rule in stage.get("rules", [])
        if rule.platform == platform and rule.type in DOMAIN_RULE_TYPES
    }
    retained: list[dict[str, Any]] = []
    for stage in old_stages:
        selector = stage.get("selector")
        if isinstance(selector, str) and _retire_known_legacy_dns_selector(
            platform, selector, stage.get("servers", []),
        ):
            continue
        if isinstance(selector, str) and _dns_inline_selector_superseded_by_test(
            selector, stage.get("servers", []), candidate, platform, api, {},
        ):
            continue
        retained_rules = [rule for rule in stage.get("rules", []) if rule.source not in profile_sources]
        if retained_rules:
            retained.append({**stage, "rules": retained_rules})
    return retained


def _intersection_subjects(stage_ids: Sequence[str], stages: Sequence[Mapping[str, Any]], platform: str, api: Any) -> list[tuple[dict[str, Any], str]]:
    selected = [stage for stage in stages if stage.get("id") in stage_ids]
    if len(selected) != len(stage_ids):
        return []
    try:
        index = api.RuleIndex(selected, platform)
    except Exception as exc:
        raise ProfileClientsError(f"cannot index intersection for {platform}: {type(exc).__name__}") from exc
    found: dict[tuple[tuple[str, Any], ...], tuple[dict[str, Any], str]] = {}
    for stage in selected:
        for rule in stage.get("rules", []):
            if rule.platform != platform or rule.type not in DOMAIN_RULE_TYPES:
                continue
            for subject, evidence in _matching_representatives(rule, api):
                hits = index.matching_rules(**subject)
                if set(stage_ids).issubset({hit.stage.get("id") for hit in hits}):
                    found[tuple(sorted(subject.items()))] = (subject, evidence)
    return list(found.values())


def _stage_witness(stage: Mapping[str, Any], platform: str, *, family: int | None, api: Any) -> tuple[dict[str, Any], str] | None:
    for rule in stage.get("rules", []):
        if rule.platform != platform:
            continue
        if family is not None:
            if rule.type not in {"IP-CIDR", "IP-CIDR6"} or ipaddress.ip_network(rule.value).version != family:
                continue
        for subject, evidence in _matching_representatives(rule, api):
            return subject, evidence
    return None


def _compare_independent_cases(report: dict[str, Any], platform: str, api: Any, candidate: Any, new_route_index: Any, new_route_stages: Sequence[Mapping[str, Any]], old_route_index: Any, new_dns_index: Any, old_dns_index: Any, new_dns_stages: Sequence[Mapping[str, Any]], old_dns_stages: Sequence[Mapping[str, Any]], new_default_dns: str, old_default_dns: str, cases: Mapping[str, Any]) -> None:
    stages = candidate.stages
    physical_stages = _candidate_stages(candidate, platform)
    try:
        source_index = api.RuleIndex(stages, platform)
    except Exception as exc:
        raise ProfileClientsError(f"cannot index source membership rules for {platform}: {type(exc).__name__}") from exc
    results = report["independent_cases"]
    for case in cases["independent_cases"]:
        if platform not in case.get("platforms", []):
            continue
        case_id = case.get("id")
        if not isinstance(case_id, str):
            raise ProfileClientsError("independent case is missing an id")
        kind = case.get("kind")
        samples: list[tuple[dict[str, Any], str]] = []
        if kind in {"literal-domain", "literal-process", "literal-ip", "cname-domain"}:
            raw_subject = case.get("subject")
            if not isinstance(raw_subject, Mapping):
                raise ProfileClientsError(f"case {case_id} needs a subject mapping")
            samples = [(dict(raw_subject), str(case.get("evidence", "synthetic")))]
        elif kind == "stage-member":
            stage = next((item for item in stages if item.get("id") == case.get("stage")), None)
            if stage is None:
                raise ProfileClientsError(f"case {case_id} references an unknown profile stage")
            family = case.get("family")
            if family not in {None, 4, 6}:
                raise ProfileClientsError(f"case {case_id} has invalid IP family")
            sample = _stage_witness(stage, platform, family=family, api=api)
            if sample is None:
                results.append({"id": case_id, "platform": platform, "evidence": "archive", "status": "not-covered", "reason": "no matching archived rule of the requested platform/family"})
                _count_independent_evidence(report, platform, "archive", status="not-covered")
                continue
            samples = [sample]
        elif kind == "stage-intersection":
            stage_ids = case.get("stages")
            if not isinstance(stage_ids, list) or len(stage_ids) < 2:
                raise ProfileClientsError(f"case {case_id} needs at least two stage ids")
            samples = _intersection_subjects(stage_ids, stages, platform, api)
            if not samples:
                results.append({"id": case_id, "platform": platform, "evidence": "archive", "status": "not-covered", "reason": "the archived rule selectors have no representative intersection"})
                _count_independent_evidence(report, platform, "archive", status="not-covered")
                continue
        elif kind == "matcher-rule":
            stage = next((item for item in stages if item.get("id") == case.get("stage")), None)
            if stage is None:
                raise ProfileClientsError(f"case {case_id} references an unknown matcher stage")
            rule = next((rule for rule in stage.get("rules", []) if rule.platform == platform and rule.type == case.get("rule_type") and rule.value == case.get("rule_value")), None)
            if rule is None:
                results.append({"id": case_id, "platform": platform, "evidence": "synthetic", "status": "not-covered", "reason": "matcher rule is absent on this platform"})
                _count_independent_evidence(report, platform, "synthetic", status="not-covered")
                continue
            subject = dict(case.get("subject", {}))
            actual = bool(api.rule_matches(rule, **subject))
            expected = case.get("expected_match") is True
            matcher_status = "passed" if actual == expected else "failed"
            results.append({"id": case_id, "platform": platform, "evidence": "synthetic", "subject": _public_subject(subject), "matcher_result": actual, "status": matcher_status})
            _count_independent_evidence(report, platform, "synthetic", status=matcher_status)
            continue
        else:
            raise ProfileClientsError(f"case {case_id} has unsupported kind {kind!r}")

        for subject, evidence in samples:
            new_result = _first_route(new_route_index, physical_stages, subject, platform, api)
            old_result = _first_route(old_route_index, report["_old_stages"][platform], subject, platform, api)
            new_route = _result_route(new_result)
            old_route = _result_route(old_result)
            new_dns, new_selector, _ = _dns_match(new_dns_index, new_dns_stages, subject, platform, new_default_dns)
            old_dns, old_selector, _ = _dns_match(old_dns_index, old_dns_stages, subject, platform, old_default_dns)
            expected_stage = case.get("expected_new_stage")
            expected_slot = case.get("expected_new_slot")
            expected_stage_last = case.get("expected_new_stage_last")
            expected_action = case.get("expected_new_action")
            expected_old_action = case.get("expected_old_action")
            expected_dns = case.get("expected_new_dns")
            expected_stage_match = case.get("expected_stage_match")
            expected_membership = case.get("expected_membership", [])
            if expected_slot is not None and not isinstance(expected_slot, str):
                raise ProfileClientsError(f"case {case_id} has invalid expected_new_slot")
            if expected_stage_last is not None and not isinstance(expected_stage_last, bool):
                raise ProfileClientsError(f"case {case_id} has invalid expected_new_stage_last")
            if not isinstance(expected_membership, list) or not all(isinstance(item, str) for item in expected_membership):
                raise ProfileClientsError(f"case {case_id} has invalid expected_membership")
            matching_stage_ids = {match.stage.get("id") for match in _match_results(source_index, subject, platform)}
            failed = (
                (isinstance(expected_stage, str) and (new_route or {}).get("stage") != expected_stage)
                or (isinstance(expected_slot, str) and (new_route or {}).get("slot") != expected_slot)
                or (expected_stage_last is True and (
                    new_result is None or not new_route_stages or new_result.stage is not new_route_stages[-1]
                ))
                or (isinstance(expected_action, str) and (new_route or {}).get("action") != expected_action)
                or (isinstance(expected_old_action, str) and (old_route or {}).get("action") != expected_old_action)
                or (isinstance(expected_dns, str) and new_dns != expected_dns)
                or (expected_stage_match is True and case.get("stage") not in matching_stage_ids)
                or any(stage_id not in matching_stage_ids for stage_id in expected_membership)
            )
            results.append({
                "id": case_id, "platform": platform, "evidence": evidence,
                "subject": _public_subject(subject), "old_first": old_route,
                "new_first": new_route, "old_dns": old_dns, "new_dns": new_dns,
                "old_dns_selector": old_selector, "new_dns_selector": new_selector,
                "expected_new_stage": expected_stage, "expected_new_slot": expected_slot,
                "expected_new_stage_last": expected_stage_last, "expected_new_action": expected_action,
                "expected_old_action": expected_old_action, "expected_new_dns": expected_dns,
                "expected_stage_match": expected_stage_match,
                "expected_membership": expected_membership,
                "actual_membership": sorted(matching_stage_ids) if expected_membership else None,
                "expected_stage": case.get("stage") if expected_stage_match is True else None,
                "status": "failed" if failed else "passed",
            })
            _count_independent_evidence(report, platform, evidence, status="failed" if failed else "passed")
    failures = [item for item in results if item.get("platform") == platform and item.get("status") == "failed"]
    if failures:
        raise ProfileClientsError(f"independent behavior cases failed for {platform}: {[item['id'] for item in failures]}")


def _count_independent_evidence(report: dict[str, Any], platform: str, evidence: str, *, status: str = "passed") -> None:
    platform_report = report["platforms"][platform]
    counts = platform_report["independent_case_evidence_counts"]
    bucket = "not-covered" if status == "not-covered" else evidence
    counts[bucket] = counts.get(bucket, 0) + 1
    status_counts = platform_report["independent_case_evidence_status_counts"].setdefault(evidence, {})
    status_counts[status] = status_counts.get(status, 0) + 1


def _representative_evidence_class(evidence: str) -> str:
    if evidence in {"source-rule", "source-rule-root", "source-cidr-representative", "source-process-rule", "source-user-agent-rule", "archive"}:
        return "archive_rule"
    if evidence == "derived-subdomain":
        return "derived_subdomain"
    if evidence in {"synthetic-keyword-probe", "synthetic-wildcard-probe"}:
        return "derived_keyword_wildcard"
    if evidence.startswith("explicit-") or evidence == "metadata":
        return "metadata"
    return "synthetic_fixture"


def compare_private(root: Path, candidate: Any, baseline_dir: Path, cases: Mapping[str, Any], *, local_stages: Mapping[str, Sequence[Mapping[str, Any]]] | None = None) -> dict[str, Any]:
    """Compare full ordered route and DNS selectors using indexed first matches."""
    api = _load_api(root)
    baseline_dir = _resolve_baseline_dir(root, baseline_dir)
    clash_path, surge_path = _baseline_paths(baseline_dir)
    baseline_manifest = _load_baseline_manifest(baseline_dir)
    if clash_path.name == V1_CLASH_BASELINE and baseline_manifest is None:
        raise ProfileClientsError("deployed v1 baseline needs its manifest for safe provider source replay")
    try:
        clash = _load_yaml_private(clash_path.read_bytes())
        surge = surge_path.read_text(encoding="utf-8")
    except OSError:
        raise ProfileClientsError("private baseline inputs are unavailable") from None
    aliases = _source_aliases(candidate, api, baseline_manifest)
    unsupported: list[dict[str, Any]] = list(cases.get("unsupported_cases", []))
    if local_stages is None:
        local_unsupported: list[dict[str, Any]] = []
        local_stages = {
            "mihomo": _private_inline_stages(api, "mihomo", clash, candidate, aliases, local_unsupported),
            "surge": _private_inline_stages(api, "surge", surge, candidate, aliases, local_unsupported),
        }
        unsupported.extend(local_unsupported)
    old_stages: dict[str, list[dict[str, Any]]] = {}
    old_dns: dict[str, tuple[list[dict[str, Any]], str]] = {}
    endpoint_routes: dict[str, list[dict[str, Any]]] = {}
    for platform, baseline in (("mihomo", clash), ("surge", surge)):
        old_stages[platform], endpoint_routes[platform] = _parse_old_routes(api, platform, candidate, baseline, aliases, unsupported)
        dns_stages, default_dns, _ = _parse_old_dns(api, platform, candidate, baseline, aliases, unsupported)
        old_dns[platform] = (dns_stages, default_dns)

    report: dict[str, Any] = {
        "schema": 1,
        "profile": candidate.manifest.get("profile", {}),
        "sampling": {
            "method": "one or two rule-derived representatives per archived rule, queried against ordered indexes",
            "traffic_coverage_claim": False,
            "domain_intersections": "indexed suffix, exact, keyword and wildcard queries; no all-hosts pairwise scan",
            "source_evidence": "per-platform raw evidence strings and archive/derived/metadata/unsupported classes are counted separately",
        },
        "source_membership": {
            "basis": "current_archived_inputs",
            "historic_baseline_membership_reconstructed": False,
        },
        "platforms": {},
        "expected_changes": list(cases.get("expected_changes", [])),
        "unsupported_cases": unsupported,
        "independent_cases": [],
        "dns_endpoint_routes": endpoint_routes,
        "limitations": [
            "Route and DNS results use archived rule bytes and explicit matcher metadata; no live DNS, GeoIP or ASN database is queried.",
            "Source membership basis is current_archived_inputs: baseline source references resolve to current archived inputs for both old and new configuration order; historical baseline source bytes and membership are not reconstructed.",
            "Representative rule coverage describes source entries with generated probes, not all possible user traffic.",
            "Resolver ownership comparisons do not establish fake-IP allocation or packet handling; those require actual-client runtime checks.",
            "DNS comparison is an ordered selector/resolver ownership model only; it does not verify live Mihomo policy priority or Surge remote proxy-side DNS resolution.",
            "Static route diffs exclude migration-generated node endpoint bypass and DoH endpoint route rules; these require separate syntax and client-engine verification.",
        ],
    }
    # Private stage objects are used only to evaluate declared independent cases;
    # strip them before serializing the report.
    report["_old_stages"] = old_stages
    for platform in ("mihomo", "surge"):
        # Compare the actual private migration route program: retained baseline
        # inline exceptions run before the generated profile stages.
        profile_stages = _candidate_stages(candidate, platform)
        new_stages = [*local_stages.get(platform, ()), *profile_stages]
        old_platform_stages = old_stages[platform]
        old_dns_stages, old_default_dns = old_dns[platform]
        new_dns_stages = [*_retained_dns_stages(old_dns_stages, candidate, platform), *_make_dns_stages(candidate, platform)]
        try:
            new_route_index = api.RuleIndex(new_stages, platform)
            old_route_index = api.RuleIndex(old_platform_stages, platform)
            new_dns_index = api.RuleIndex(new_dns_stages, platform)
            old_dns_index = api.RuleIndex(old_dns_stages, platform)
        except Exception as exc:
            raise ProfileClientsError(f"cannot index route/DNS rules for {platform}: {type(exc).__name__}") from exc
        # Fail independent acceptance cases before the much larger source-probe
        # expansion. Diagnostic canaries are not business routing witnesses.
        report["platforms"][platform] = {
            "case_count": sum(1 for case in cases["independent_cases"] if platform in case.get("platforms", [])),
            "independent_case_evidence_counts": {},
            "independent_case_evidence_status_counts": {},
        }
        _compare_independent_cases(
            report, platform, api, candidate, new_route_index, new_stages, old_route_index,
            new_dns_index, old_dns_index, new_dns_stages, old_dns_stages,
            "US", old_default_dns, cases,
        )
        canary = getattr(api, "SUKKA_IP_CANARY", None)
        old_rules = [(stage, rule) for stage in old_platform_stages for rule in stage.get("rules", []) if rule.platform == platform and (rule.type, rule.value) != canary]
        new_rules = [(stage, rule) for stage in new_stages for rule in stage.get("rules", []) if rule.platform == platform and (rule.type, rule.value) != canary]
        route_diff: dict[str, dict[str, Any]] = {}
        dns_diff: dict[str, dict[str, Any]] = {}
        covered_old: set[tuple[str, str, str, str, int, str]] = set()
        covered_new: set[tuple[str, str, str, str, int, str]] = set()
        route_sample_count = 0
        dns_sample_count = 0
        source_sample_count = 0
        representative_evidence_counts: dict[str, int] = {}
        representative_evidence_classes = {
            "archive_rule": 0, "derived_subdomain": 0,
            "derived_keyword_wildcard": 0, "metadata": 0,
            "synthetic_fixture": 0, "unsupported": 0,
        }
        unsupported_rules = 0
        for is_old, entries in ((True, old_rules), (False, new_rules)):
            coverage = covered_old if is_old else covered_new
            for stage, rule in entries:
                # MATCH is a fallback, not a finite source member. GEOIP and
                # ASN probes use explicit metadata, never a fabricated lookup.
                if rule.type == "MATCH":
                    continue
                representatives = _matching_representatives(rule, api)
                if not representatives:
                    unsupported_rules += 1
                    representative_evidence_classes["unsupported"] += 1
                    continue
                for subject, evidence in representatives:
                    representative_evidence_counts[evidence] = representative_evidence_counts.get(evidence, 0) + 1
                    representative_evidence_classes[_representative_evidence_class(evidence)] += 1
                    if subject.get("domain"):
                        source_sample_count += 1
                    coverage.add(_rule_key(rule, str(stage.get("id"))))
                    old_result = _first_route(old_route_index, old_platform_stages, subject, platform, api)
                    new_result = _first_route(new_route_index, new_stages, subject, platform, api)
                    old_route = _result_route(old_result)
                    new_route = _result_route(new_result)
                    _diff_bucket(route_diff, _route_signature(old_route), _route_signature(new_route), subject, evidence)
                    route_sample_count += 1
                    if subject.get("domain"):
                        old_dns_intent, _, _ = _dns_match(old_dns_index, old_dns_stages, subject, platform, old_default_dns)
                        new_dns_intent, _, _ = _dns_match(new_dns_index, new_dns_stages, subject, platform, "US")
                        _diff_bucket(dns_diff, old_dns_intent, new_dns_intent, subject, evidence)
                        dns_sample_count += 1
        for matcher_label, matcher_index in (
            ("old-route", old_route_index), ("new-migrated-route", new_route_index),
            ("old-dns", old_dns_index), ("new-dns", new_dns_index),
        ):
            for limitation in getattr(matcher_index, "comparison_limitations", ()):
                item = {"id": f"{platform}:{matcher_label}:{limitation.get('stage')}:{limitation.get('type')}", "reason": limitation.get("reason")}
                if item not in unsupported:
                    unsupported.append(item)
        old_count, new_count = len(old_rules), len(new_rules)
        platform_result = {
            "old_rule_count": old_count,
            "new_rule_count": new_count,
            "new_profile_rule_count": sum(1 for stage in profile_stages for rule in stage.get("rules", []) if rule.platform == platform),
            "new_retained_local_rule_count": sum(1 for stage in local_stages.get(platform, ()) for rule in stage.get("rules", []) if rule.platform == platform),
            "old_rules_with_representative": len(covered_old),
            "new_rules_with_representative": len(covered_new),
            "old_rule_coverage_ratio": round(len(covered_old) / max(1, old_count - sum(1 for _, rule in old_rules if rule.type == "MATCH")), 6),
            "new_rule_coverage_ratio": round(len(covered_new) / max(1, new_count - sum(1 for _, rule in new_rules if rule.type == "MATCH")), 6),
            "route_sample_count": route_sample_count,
            "domain_dns_sample_count": dns_sample_count,
            "domain_representative_count": source_sample_count,
            "rule_representatives_by_evidence": representative_evidence_counts,
            "rule_representatives_by_class": representative_evidence_classes,
            "unsupported_rule_count": unsupported_rules,
            "independent_case_evidence_counts": report["platforms"][platform]["independent_case_evidence_counts"],
            "independent_case_evidence_status_counts": report["platforms"][platform]["independent_case_evidence_status_counts"],
            "route_differences": list(route_diff.values()),
            "dns_differences": list(dns_diff.values()),
            "case_count": report["platforms"].get(platform, {}).get("case_count", 0),
            "coverage_note": "Every representable old/new rule gets a bounded source-derived probe; rule-level coverage is not all-flow equivalence.",
            "diagnostic_canaries_excluded": True,
        }
        report["platforms"][platform] = platform_result
    report.pop("_old_stages", None)
    return report


def render_report_markdown(report: Mapping[str, Any]) -> str:
    lines = [
        "# Personal route and DNS comparison",
        "",
        "This private report compares ordered first route and DNS-selector matches. Archive-backed representatives and synthetic matcher fixtures are labeled separately; sample coverage does not claim all-traffic equivalence.",
        "",
        "## Coverage",
        "",
    ]
    for platform, data in report.get("platforms", {}).items():
        lines.append(
            f"- **{platform}**: old {data.get('old_rules_with_representative', 0)}/{data.get('old_rule_count', 0)} and "
            f"new {data.get('new_rules_with_representative', 0)}/{data.get('new_rule_count', 0)} rules had a representative; "
            f"{data.get('route_sample_count', 0)} route probes, {data.get('domain_dns_sample_count', 0)} DNS probes, "
            f"{data.get('case_count', 0)} declared cases. This is rule-entry coverage, not traffic coverage."
        )
        classes = data.get("rule_representatives_by_class", {})
        case_evidence = data.get("independent_case_evidence_counts", {})
        lines.append(
            f"  Representative evidence classes: archive rules {classes.get('archive_rule', 0)}, "
            f"derived subdomains {classes.get('derived_subdomain', 0)}, "
            f"keyword/wildcard probes {classes.get('derived_keyword_wildcard', 0)}, "
            f"metadata {classes.get('metadata', 0)}, unsupported rules {data.get('unsupported_rule_count', 0)}; "
            f"rule evidence: `{json.dumps(data.get('rule_representatives_by_evidence', {}), ensure_ascii=False, sort_keys=True)}`; "
            f"independent case evidence: `{json.dumps(case_evidence, ensure_ascii=False, sort_keys=True)}`."
        )
    lines.extend(["", "## Route differences", "", "| Platform | Old outcome | New outcome | Probe count | Examples |", "|---|---|---|---:|---|"])
    for platform, data in report.get("platforms", {}).items():
        for item in data.get("route_differences", []):
            examples = ", ".join(str(ex.get("subject", {}).get("domain") or ex.get("subject", {}).get("ip") or ex.get("subject", {}).get("process") or "metadata") for ex in item.get("examples", []))
            lines.append(f"| {platform} | `{item.get('old')}` | `{item.get('new')}` | {item.get('count')} | {examples} |")
    if not any(data.get("route_differences") for data in report.get("platforms", {}).values()):
        lines.append("| all | no differences among sampled rule representatives | — | 0 | — |")
    lines.extend(["", "## DNS differences", "", "| Platform | Old resolver owner | New resolver owner | Probe count | Examples |", "|---|---|---|---:|---|"])
    for platform, data in report.get("platforms", {}).items():
        for item in data.get("dns_differences", []):
            examples = ", ".join(str(ex.get("subject", {}).get("domain") or "metadata") for ex in item.get("examples", []))
            lines.append(f"| {platform} | `{item.get('old')}` | `{item.get('new')}` | {item.get('count')} | {examples} |")
    if not any(data.get("dns_differences") for data in report.get("platforms", {}).values()):
        lines.append("| all | no differences among sampled domain representatives | — | 0 | — |")
    lines.extend(["", "## Intended changes", ""])
    for item in report.get("expected_changes", []):
        if isinstance(item, Mapping):
            lines.append(f"- **{item.get('id')}**: {item.get('description')}")
        else:
            lines.append(f"- {item}")
    lines.extend(["", "## Independent cases", "", "| Case | Platform | Evidence | Old route | New route | Old DNS | New DNS | Status |", "|---|---|---|---|---|---|---|---|"])
    for item in report.get("independent_cases", []):
        old = item.get("old_first") or {}
        new = item.get("new_first") or {}
        lines.append(f"| {item.get('id')} | {item.get('platform')} | {item.get('evidence', '')} | {old.get('stage', old.get('action', ''))} / {old.get('action', '')} | {new.get('stage', new.get('action', ''))} / {new.get('action', '')} | {item.get('old_dns', '')} | {item.get('new_dns', '')} | {item.get('status')} |")
    lines.extend(["", "## DoH endpoint route rules", ""])
    for platform, items in report.get("dns_endpoint_routes", {}).items():
        for item in items:
            lines.append(f"- {platform}: {item.get('protocol')} {item.get('endpoint_ip')} -> {item.get('action')}")
    lines.extend(["", "## Unsupported or limited evidence", ""])
    for item in report.get("unsupported_cases", []):
        if isinstance(item, Mapping):
            lines.append(f"- {item.get('id')}: {item.get('reason')}")
        else:
            lines.append(f"- {item}")
    for item in report.get("limitations", []):
        lines.append(f"- {item}")
    lines.append("")
    return "\n".join(lines)


def render_examples(root: str | Path, base_url: str, *, converter_path: str | None = None) -> tuple[Path, Path]:
    root = Path(root).resolve()
    candidate = _replay(root, converter_path)
    base_url = _validate_base_url(base_url)
    mihomo = render_mihomo_snippet(candidate, base_url).encode("utf-8")
    surge = render_surge_snippet(candidate, base_url).encode("utf-8")
    paths = (root / "examples/personal-mihomo.yaml", root / "examples/personal-surge.conf")
    for path, data in zip(paths, (mihomo, surge)):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return paths


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="HTTPS root for published personal rule resources")
    parser.add_argument("--converter", help="optional approved Mihomo MRS converter")
    subparsers = parser.add_subparsers(dest="command", required=True)
    render = subparsers.add_parser("render", help="write credential-free client snippets")
    render.add_argument("--root", type=Path, default=argparse.SUPPRESS)
    render.add_argument("--base-url", default=argparse.SUPPRESS, help="override the published personal resource root")
    render.add_argument("--converter", default=argparse.SUPPRESS)
    render.add_argument("--out-dir", type=Path, default=Path("examples"))
    migrate = subparsers.add_parser("migrate", help="write private candidates and route/DNS comparison")
    migrate.add_argument("--root", type=Path, default=argparse.SUPPRESS)
    migrate.add_argument("--base-url", default=argparse.SUPPRESS, help="resource root for private candidate configs")
    migrate.add_argument("--converter", default=argparse.SUPPRESS)
    migrate.add_argument("--private-dir", type=Path, required=True)
    migrate.add_argument("--baseline-dir", type=Path, default=argparse.SUPPRESS,
                         help="directory containing either the original baseline pair or deployed v1 pair")
    compare = subparsers.add_parser("compare", help="write the private route/DNS comparison report")
    compare.add_argument("--root", type=Path, default=argparse.SUPPRESS)
    compare.add_argument("--base-url", default=argparse.SUPPRESS)
    compare.add_argument("--converter", default=argparse.SUPPRESS)
    compare.add_argument("--private-dir", type=Path, required=True)
    compare.add_argument("--cases", type=Path, default=Path(CASE_PATH))
    compare.add_argument("--baseline-dir", type=Path, default=argparse.SUPPRESS,
                         help="directory containing either the original baseline pair or deployed v1 pair")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = args.root.resolve()
    try:
        if args.command == "render":
            candidate = _replay(root, args.converter)
            base_url = _validate_base_url(args.base_url)
            target = args.out_dir if args.out_dir.is_absolute() else root / args.out_dir
            target.mkdir(parents=True, exist_ok=True)
            (target / "personal-mihomo.yaml").write_text(render_mihomo_snippet(candidate, base_url), encoding="utf-8")
            (target / "personal-surge.conf").write_text(render_surge_snippet(candidate, base_url), encoding="utf-8")
            print(f"wrote credential-free snippets under {target}")
            return 0
        if args.command == "migrate":
            outputs = private_migrate(
                root, args.private_dir, args.base_url, converter_path=args.converter,
                baseline_dir=getattr(args, "baseline_dir", None),
            )
            for label, path in outputs.items():
                print(f"{label}: {path}")
            return 0
        if args.command == "compare":
            cases_path = args.cases if args.cases.is_absolute() else root / args.cases
            baseline_dir = _resolve_baseline_dir(root, getattr(args, "baseline_dir", None))
            report = compare_private(root, _replay(root, args.converter), baseline_dir, _load_cases(cases_path))
            target = _ensure_private_dir(root, args.private_dir)
            json_path = target / "route-dns-comparison.json"
            markdown_path = target / "route-dns-comparison.md"
            _write_private(json_path, (json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8"))
            _write_private(markdown_path, render_report_markdown(report).encode("utf-8"))
            print(f"json: {json_path}")
            print(f"markdown: {markdown_path}")
            return 0
    except ProfileClientsError as exc:
        print(f"profile_clients: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
