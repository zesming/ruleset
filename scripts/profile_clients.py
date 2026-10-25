#!/usr/bin/env python3
"""Render credential-free client snippets for the ordered personal-routing profile.

Snippets are generated only from the replayed personal manifest and contain no
node definitions.  The DNS stage helpers model each client's resolver choice
for tests that check DNS ownership alongside first-match routing.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import re
import sys
import urllib.parse
from pathlib import Path
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BASE_URL = "https://raw.githubusercontent.com/zesming/ruleset/main"

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
SURGE_US_DOH = ("https://8.8.8.8/dns-query", "https://1.1.1.1/dns-query")
SURGE_JP_DOH = ("https://1.0.0.1/dns-query",)
SURGE_TEST_DOH = ("https://8.8.4.4/dns-query",)
SURGE_DOMESTIC_DOH = ("https://223.5.5.5/dns-query", "https://1.12.12.12/dns-query")
SURGE_REGION_GROUPS = {"US": "🇺🇸 US", "JP": "🇯🇵 JP"}
ATT_REAL_IP = ("epdg.epc.att.net", "epdg.epc.att-idns.net")
NINTENDO_REAL_IP = ("+.srv.nintendo.net", "*.n.n.srv.nintendo.net")
SURGE_NINTENDO_REAL_IP = ("*.srv.nintendo.net", "*.n.n.srv.nintendo.net")

VALID_ACTIONS = {"US", "DIRECT", "JP", "REJECT", "TEST"}
VALID_DNS = {"system", "domestic", "foreign", "jp", "test", "none"}
VALID_PLATFORMS = {"mihomo", "surge"}
DOMAIN_RULE_TYPES = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD"}
IP_RULE_TYPES = {"IP-CIDR", "IP-CIDR6", "IP-ASN", "GEOIP"}


class ProfileClientsError(Exception):
    """Expected renderer error."""


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


def _split_csv(line: str) -> list[str]:
    try:
        return next(csv.reader([line], skipinitialspace=True))
    except csv.Error as exc:
        raise ProfileClientsError("baseline contains malformed rule CSV") from exc


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


def _make_dns_stages(candidate: Any, platform: str) -> list[dict[str, Any]]:
    result = []
    for stage in _domain_only_stages(_candidate_stages(candidate, platform), platform):
        if stage.get("dns") == "none":
            continue
        result.append(stage)
    return result


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
    except ProfileClientsError as exc:
        print(f"profile_clients: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
