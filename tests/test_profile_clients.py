from __future__ import annotations

import hashlib
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import profile_clients as clients  # noqa: E402
import personal_profile as profile  # noqa: E402


def _rule(platform: str, rule_type: str, value: str, flags: tuple[str, ...] = ()):
    return SimpleNamespace(platform=platform, type=rule_type, value=value, flags=flags, source="fixture", line=1)


def _group(platform: str, group_id: str, stage_id: str, action: str) -> tuple[dict, str, bytes]:
    ext = "mrs" if platform == "mihomo" else "set"
    path = f"rules/personal/{platform}/{group_id}.{ext}"
    content = b"fixture-domain.example\n"
    group = {
        "id": group_id, "stages": [stage_id], "action": action, "dns": "none",
        "reject_mode": None, "extended_matching": False, "no_resolve": True,
        "kind": "route", "behavior": "domain-set", "format": ext,
        "path": path, "sha256": hashlib.sha256(content).hexdigest(),
    }
    return group, path, content


def _candidate():
    stages = []
    files = {}
    groups = {"mihomo": [], "surge": []}
    for platform in ("mihomo", "surge"):
        first, first_path, first_bytes = _group(platform, "att-us", "att-us", "US")
        after, after_path, after_bytes = _group(platform, "domestic-ip", "domestic-ip", "DIRECT")
        groups[platform].extend((first, after))
        files[first_path] = first_bytes
        files[after_path] = after_bytes
    stages = [
        {
            "id": "att-us", "action": "US", "dns": "none", "reject_mode": None,
            "extended_matching": False, "no_resolve": True,
            "group_by_platform": {"mihomo": "att-us", "surge": "att-us"},
            "rules": [_rule("mihomo", "DOMAIN-SUFFIX", "att.example"), _rule("surge", "DOMAIN-SUFFIX", "att.example")],
        },
        {
            "id": "geoip-cn", "action": "DIRECT", "dns": "none", "reject_mode": None,
            "extended_matching": False, "no_resolve": True,
            "group_by_platform": {"mihomo": None, "surge": None},
            "rules": [_rule("mihomo", "GEOIP", "CN", ("no-resolve",)), _rule("surge", "GEOIP", "CN", ("no-resolve",))],
        },
        {
            "id": "domestic-ip", "action": "DIRECT", "dns": "none", "reject_mode": None,
            "extended_matching": False, "no_resolve": True,
            "group_by_platform": {"mihomo": "domestic-ip", "surge": "domestic-ip"},
            "rules": [_rule("mihomo", "IP-CIDR", "203.0.113.0/24", ("no-resolve",)), _rule("surge", "IP-CIDR", "203.0.113.0/24", ("no-resolve",))],
        },
        {
            "id": "default-us", "action": "US", "dns": "none", "reject_mode": None,
            "extended_matching": False, "no_resolve": False,
            "group_by_platform": {"mihomo": None, "surge": None},
            "rules": [_rule("mihomo", "MATCH", "*"), _rule("surge", "MATCH", "*")],
        },
    ]
    for stage in stages:
        for platform in ("mihomo", "surge"):
            group_id = stage["group_by_platform"][platform]
            if group_id:
                next(item for item in groups[platform] if item["id"] == group_id)["stages"] = [stage["id"]]
    return SimpleNamespace(stages=stages, files=files, manifest={"groups": groups, "profile": {"id": "fixture"}})


def _compact_candidate():
    candidate = _candidate()
    compact_groups = {"mihomo": [], "surge": []}
    compact_stages = {"mihomo": [], "surge": []}
    for platform in ("mihomo", "surge"):
        for raw_group in candidate.manifest["groups"][platform]:
            group = {**raw_group, "slot": raw_group["id"]}
            fine = next(stage for stage in candidate.stages if stage["id"] == group["stages"][0])
            rules = [rule for rule in fine["rules"] if rule.platform == platform]
            group["rule_count"] = len(rules)
            compact_groups[platform].append(group)
            compact_stages[platform].append({
                **fine, "id": group["id"], "slot": group["slot"], "rules": rules,
                "sources": list(group["stages"]),
                "group_by_platform": {platform: group["id"]},
            })
        for fine in candidate.stages:
            if not any(rule.type in {"GEOIP", "MATCH"} for rule in fine["rules"]):
                continue
            rules = [rule for rule in fine["rules"] if rule.platform == platform]
            compact_stages[platform].append({
                **fine, "rules": rules, "group_by_platform": {platform: None},
            })
    candidate.manifest["compact"] = {
        "schema": 1, "groups": compact_groups, "stages": compact_stages,
    }
    candidate.compact_stages = compact_stages
    return candidate


def _candidate_with_test_dns_domains():
    candidate = _candidate()
    test_stage = {
        "id": "network-test", "action": "TEST", "dns": "test", "reject_mode": None,
        "extended_matching": False, "no_resolve": True,
        "group_by_platform": {},
        "rules": [
            profile.Rule(rule_type, domain, (), "fixture", 1, platform)
            for platform in ("mihomo", "surge")
            for rule_type, domain in (
                ("DOMAIN-SUFFIX", "speedtest.cn"),
                ("DOMAIN-SUFFIX", "internal"),
                ("DOMAIN", "api.istatmenus.app"),
                ("DOMAIN", "api.us.zesming.fun"),
            )
        ],
    }
    content = b".speedtest.cn\n.internal\napi.istatmenus.app\napi.us.zesming.fun\n"
    for platform in ("mihomo", "surge"):
        extension = "mrs" if platform == "mihomo" else "set"
        group, path, _ = _group(platform, "network-test", "network-test", "TEST")
        group.update({
            "dns": "test", "dns_path": path, "dns_kind": "route",
            "dns_behavior": "domain-set", "dns_format": extension,
            "sha256": hashlib.sha256(content).hexdigest(),
        })
        candidate.manifest["groups"][platform].insert(1, group)
        candidate.files[path] = content
        test_stage["group_by_platform"][platform] = group["id"]
    candidate.stages.insert(1, test_stage)
    return candidate


class RendererOrderTests(unittest.TestCase):
    def test_jp_tuic_uses_its_own_endpoint_and_an_alpn_array(self):
        _, sections = clients._surge_sections("[Proxy]\nJP node = tuic-v5, jp.example, 443, uuid=fixture, password=fixture, alpn=h3\n")
        node = clients._extract_jp_tuic(sections, [{"name": "US node", "type": "tuic", "ip": "192.0.2.1", "sni": "us.example", "fast-open": True, "reduce-rtt": True}])
        self.assertEqual(node["server"], "jp.example")
        self.assertEqual(node["alpn"], ["h3"])
        self.assertNotIn("ip", node)
        self.assertNotIn("sni", node)
        self.assertNotIn("fast-open", node)
        self.assertNotIn("reduce-rtt", node)

    def test_public_surge_snippet_uses_country_groups_without_private_nodes(self):
        rendered = clients.render_surge_snippet(_candidate(), "https://example.invalid/ref")
        self.assertNotIn("AND,((PROTOCOL,DOH),(DOMAIN,8.8.8.8)),🇺🇸 US", rendered)
        self.assertNotIn("AND,((PROTOCOL,DOH),(DOMAIN,223.5.5.5)),🚀 Direct", rendered)
        self.assertIn("AND,((PROTOCOL,DOH),(DOMAIN,1.0.0.1)),🇯🇵 JP", rendered)
        self.assertIn("AND,((PROTOCOL,DOH),(DOMAIN,8.8.4.4)),⚒️ Test", rendered)
        self.assertIn("🚀 Direct = direct", rendered)
        self.assertIn("⛔️ Reject = reject", rendered)
        self.assertIn("⛔️ Reject-Drop = reject-drop", rendered)
        self.assertIn("⛔️ Reject-No-Drop = reject-no-drop", rendered)
        self.assertIn("⚒️ Test = select, 🇺🇸 US, 🇯🇵 JP, 🚀 Direct", rendered)
        self.assertIn("FINAL,🇺🇸 US,dns-failed", rendered)
        self.assertIn("[Proxy]", rendered)
        self.assertIn("[Proxy Group]", rendered)
        self.assertNotIn("uuid=", rendered)
        self.assertNotIn("password=", rendered)

    @unittest.skipUnless(shutil.which("ruby"), "system Ruby YAML parser is unavailable")
    def test_private_yaml_shares_only_resolver_lists_and_keeps_unicode_readable(self):
        resolver_list = ["https://8.8.8.8/dns-query#🇺🇸 US", "https://1.1.1.1/dns-query#🇺🇸 US"]
        value = {
            "dns": {
                "nameserver": list(resolver_list),
                "default-nameserver": list(resolver_list),
                "proxy-server-nameserver": list(resolver_list),
                "direct-nameserver": list(resolver_list),
            },
            "proxies": [
                {"name": "🇺🇸 TUIC", "alpn": ["h3"]},
                {"name": "🇯🇵 TUIC", "alpn": ["h3"]},
            ],
        }

        rendered = clients._dump_yaml_private(value).decode("utf-8")

        self.assertIn("🇺🇸 TUIC", rendered)
        self.assertNotIn("\\U0001F1FA", rendered)
        self.assertIn("&1", rendered)
        self.assertIn("*1", rendered)
        self.assertEqual(rendered.count("alpn:"), 2)
        self.assertEqual(clients._load_yaml_private(rendered.encode("utf-8")), value)


class CompactGroupValidationTests(unittest.TestCase):
    def test_compact_allows_fine_source_lan_and_empty_reserved_jp_ip(self):
        candidate = _compact_candidate()
        for platform in ("mihomo", "surge"):
            groups = candidate.manifest["compact"]["groups"][platform]
            stages = candidate.compact_stages[platform]
            lan_group, empty_jp_group = groups
            lan_stage, empty_jp_stage = stages[:2]

            lan_group.update({"stages": ["att-us"], "slot": "lan", "action": "DIRECT", "dns": "system"})
            lan_stage.update({"slot": "lan", "action": "DIRECT", "dns": "system"})
            empty_jp_group.update({"stages": [], "slot": "jp-ip", "action": "JP", "dns": "jp", "rule_count": 0})
            empty_jp_stage.update({"slot": "jp-ip", "action": "JP", "dns": "jp", "rules": []})

            resolved = clients._groups(candidate, platform)
            self.assertEqual([group["slot"] for group in resolved], ["lan", "jp-ip"])
            self.assertEqual(resolved[0]["stages"], ["att-us"])
            self.assertEqual(resolved[1]["stages"], [])

    def test_reclassified_compact_replay_uses_old_slot_partition_and_source_identity(self):
        api = clients._load_api(ROOT)
        domain = profile.Rule("DOMAIN-SUFFIX", "blocked.example", (), "fixture", 1, "mihomo")
        process = profile.Rule("PROCESS-NAME", "blocked-app", (), "fixture", 2, "mihomo")
        deferred_ip = profile.Rule("IP-CIDR", "198.51.100.0/24", (), "fixture", 3, "mihomo")
        new_domain = profile.Rule("DOMAIN-SUFFIX", "new.example", (), "fixture", 4, "mihomo")
        new_process = profile.Rule("PROCESS-NAME", "new-app", (), "fixture", 5, "mihomo")
        fine_stages = [
            {
                "id": "reject-rules", "action": "REJECT", "dns": "none", "reject_mode": "plain",
                "extended_matching": False, "no_resolve": False, "sources": ["legacy:reject"],
                "rules": [domain, process, deferred_ip],
            },
            {
                "id": "reject-extra", "action": "REJECT", "dns": "none", "reject_mode": "plain",
                "extended_matching": False, "no_resolve": False, "sources": ["legacy:reject-extra"],
                "rules": [new_domain, new_process],
            },
        ]
        semantic = {
            "action": "REJECT", "dns": "none", "reject_mode": "plain",
            "extended_matching": False, "no_resolve": False,
        }
        current_groups = [
            {
                **semantic, "id": "reject-domain", "slot": "reject", "stages": ["reject-rules", "reject-extra"],
                "kind": "route", "behavior": "domain-set", "format": "mrs", "rule_count": 2,
            },
            {
                **semantic, "id": "reject-rules", "slot": "reject", "stages": ["reject-rules", "reject-extra"],
                "kind": "route", "behavior": "classical", "format": "text", "rule_count": 2,
            },
            {
                **semantic, "id": "reject-ip", "slot": "reject-ip", "stages": ["reject-rules"],
                "kind": "route", "behavior": "classical", "format": "text", "rule_count": 1,
            },
        ]

        def physical(group, rules):
            return {
                **semantic, "id": group["id"], "slot": group["slot"], "sources": list(group["stages"]),
                "rules": rules, "group_by_platform": {"mihomo": group["id"]},
            }

        candidate = SimpleNamespace(
            stages=fine_stages,
            compact_stages={"mihomo": [
                physical(current_groups[0], [domain, new_domain]),
                physical(current_groups[1], [process, new_process]),
                physical(current_groups[2], [deferred_ip]),
            ]},
            manifest={"compact": {"groups": {"mihomo": current_groups}}},
        )
        old_groups = [
            {
                **semantic, "id": "reject", "slot": "reject", "stages": ["reject-rules"],
                "kind": "route", "behavior": "domain-set", "format": "mrs", "rule_count": 99,
                "path": "rules/personal/mihomo/reject.mrs",
            },
            {
                **semantic, "id": "reject-rules-old", "slot": "reject", "stages": ["reject-rules"],
                "kind": "route", "behavior": "classical", "format": "text", "rule_count": 99,
                "path": "rules/personal/mihomo/reject-rules.list",
            },
        ]
        manifest = {
            "stages": [
                {key: stage[key] for key in (
                    "id", "action", "dns", "reject_mode", "extended_matching", "no_resolve", "sources",
                )}
                for stage in fine_stages
            ],
            "compact": {"groups": {"mihomo": old_groups, "surge": []}},
        }
        aliases = clients._source_aliases(candidate, api, manifest)

        old_domain_id = clients._resolve_source_reference(old_groups[0]["path"], aliases, platform="mihomo")
        old_classical_id = clients._resolve_source_reference(old_groups[1]["path"], aliases, platform="mihomo")
        self.assertEqual(
            [rule.value for rule in clients._source_rules(candidate, old_domain_id, "mihomo", aliases)],
            ["blocked.example"],
        )
        self.assertEqual(
            [rule.value for rule in clients._source_rules(candidate, old_classical_id, "mihomo", aliases)],
            ["blocked-app"],
        )

    def test_old_mihomo_no_drop_compact_group_maps_to_plain_physical_group(self):
        api = clients._load_api(ROOT)
        rule = profile.Rule(
            "PROCESS-NAME", "blocked-app", (), "legacy:reject-no-drop", 1, "mihomo",
        )
        merged_rule = profile.Rule(
            "PROCESS-NAME", "other-blocked-app", (), "legacy:reject-rules", 2, "mihomo",
        )
        source_stage = {
            "id": "reject-no-drop", "action": "REJECT", "dns": "none", "reject_mode": "no-drop",
            "extended_matching": False, "no_resolve": False,
            "sources": ["legacy:reject-no-drop"], "rules": [rule],
        }
        merged_source_stage = {
            "id": "reject-rules", "action": "REJECT", "dns": "none", "reject_mode": "plain",
            "extended_matching": False, "no_resolve": False,
            "sources": ["legacy:reject-rules"], "rules": [merged_rule],
        }
        current_group = {
            "id": "reject-rules", "slot": "reject", "action": "REJECT", "dns": "none",
            "reject_mode": "plain", "extended_matching": False, "no_resolve": False,
            "stages": ["reject-rules", "reject-no-drop"], "kind": "route", "behavior": "classical",
            "format": "text", "rule_count": 2,
        }
        physical = {
            **{key: current_group[key] for key in (
                "action", "dns", "reject_mode", "extended_matching", "no_resolve", "slot",
            )},
            "id": current_group["id"], "sources": list(current_group["stages"]),
            "rules": [merged_rule, rule], "group_by_platform": {"mihomo": current_group["id"]},
        }
        candidate = SimpleNamespace(
            stages=[source_stage, merged_source_stage], compact_stages={"mihomo": [physical]},
            manifest={"compact": {"groups": {"mihomo": [current_group]}}},
        )
        old_group = {
            "id": "reject-no-drop", "slot": "reject", "action": "REJECT", "dns": "none",
            "reject_mode": "no-drop", "extended_matching": False, "no_resolve": False,
            "stages": ["reject-no-drop"], "kind": "route", "behavior": "classical",
            "format": "text", "rule_count": 1,
            "path": "rules/personal/mihomo/reject-no-drop.list",
        }
        old_manifest = {
            "stages": [{key: source_stage[key] for key in (
                "id", "action", "dns", "reject_mode", "extended_matching", "no_resolve", "sources",
            )}],
            "compact": {"groups": {"mihomo": [old_group], "surge": []}},
        }
        aliases = clients._source_aliases(candidate, api, old_manifest)
        source_id = clients._resolve_source_reference(old_group["path"], aliases, platform="mihomo")

        self.assertEqual(aliases.group_sources[source_id]["source_stage_identity"]["reject-no-drop"]["reject_mode"], "no-drop")
        self.assertEqual(
            clients._group_rule_sources(candidate, aliases.group_sources[source_id], "mihomo"),
            {"legacy:reject-no-drop"},
        )
        self.assertFalse(clients._same_physical_group_fields(
            "surge", {"reject_mode": "no-drop"}, {"reject_mode": "plain"}, ("reject_mode",),
        ))


class IndependentCaseOracleTests(unittest.TestCase):
    @staticmethod
    def _mapping_rule(platform, rule_type, value, flags=()):
        return {
            "platform": platform, "type": rule_type, "value": value,
            "flags": list(flags), "source": "fixture", "line": 1,
        }

    def _compare(self, candidate, full_new_stages, cases):
        api = clients._load_api(ROOT)
        old_stages = [{
            "id": "old-default", "action": "US", "rules": [self._mapping_rule("mihomo", "MATCH", "*")],
        }]
        report = {
            "independent_cases": [],
            "platforms": {"mihomo": {
                "independent_case_evidence_counts": {},
                "independent_case_evidence_status_counts": {},
            }},
            "_old_stages": {"mihomo": old_stages},
        }
        clients._compare_independent_cases(
            report, "mihomo", api, candidate,
            api.RuleIndex(full_new_stages, "mihomo"), full_new_stages,
            api.RuleIndex(old_stages, "mihomo"), api.RuleIndex([], "mihomo"),
            api.RuleIndex([], "mihomo"), [], [], "US", "US", cases,
        )
        return report

    def test_same_action_overlap_fails_when_first_match_uses_wrong_slot(self):
        subject = {"domain": "overlap.example"}
        fine_stages = [
            {"id": "fine-us", "rules": [self._mapping_rule("mihomo", "DOMAIN-SUFFIX", "overlap.example")]},
            {"id": "fine-cn", "rules": [self._mapping_rule("mihomo", "DOMAIN-SUFFIX", "overlap.example")]},
        ]
        wrong_first = {
            "id": "priority-cn-direct", "slot": "cn-direct", "action": "DIRECT", "dns": "domestic",
            "rules": [self._mapping_rule("mihomo", "DOMAIN-SUFFIX", "overlap.example")],
        }
        expected_first = {
            "id": "priority-us", "slot": "us", "action": "DIRECT", "dns": "foreign",
            "rules": [self._mapping_rule("mihomo", "DOMAIN-SUFFIX", "overlap.example")],
        }
        terminals = [
            {"id": "geoip-cn", "action": "DIRECT", "rules": [self._mapping_rule("mihomo", "GEOIP", "CN")]},
            {"id": "default-us", "action": "US", "rules": [self._mapping_rule("mihomo", "MATCH", "*")]},
        ]
        physical = [wrong_first, expected_first, *terminals]
        candidate = SimpleNamespace(
            stages=fine_stages, compact_stages={"mihomo": physical}, manifest={"compact": {}},
        )
        local_prefix = {
            "id": "retained-company", "action": "DIRECT",
            "rules": [self._mapping_rule("mihomo", "DOMAIN-SUFFIX", "company.internal")],
        }
        cases = {"independent_cases": [{
            "id": "same-action-overlap", "kind": "literal-domain", "platforms": ["mihomo"],
            "evidence": "synthetic", "subject": subject,
            "expected_new_slot": "us", "expected_new_action": "DIRECT",
            "expected_membership": ["fine-us", "fine-cn"],
        }]}
        with self.assertRaisesRegex(clients.ProfileClientsError, "same-action-overlap"):
            self._compare(candidate, [local_prefix, *physical], cases)

    def test_terminal_last_assertion_uses_full_program_after_local_prefix(self):
        fine = {"id": "fine-us", "rules": [self._mapping_rule("mihomo", "DOMAIN-SUFFIX", "listed.example")]}
        profile_stages = [
            {"id": "priority-us", "slot": "us", "action": "US", "rules": [self._mapping_rule("mihomo", "DOMAIN-SUFFIX", "listed.example")]},
            {"id": "geoip-cn", "action": "DIRECT", "rules": [self._mapping_rule("mihomo", "GEOIP", "CN")]},
            {"id": "default-us", "action": "US", "rules": [self._mapping_rule("mihomo", "MATCH", "*")]},
        ]
        candidate = SimpleNamespace(
            stages=[fine], compact_stages={"mihomo": profile_stages}, manifest={"compact": {}},
        )
        local_prefix = {
            "id": "retained-company", "action": "DIRECT",
            "rules": [self._mapping_rule("mihomo", "DOMAIN-SUFFIX", "company.internal")],
        }
        cases = {"independent_cases": [{
            "id": "fallback-is-final", "kind": "literal-domain", "platforms": ["mihomo"],
            "evidence": "synthetic", "subject": {"domain": "unknown.invalid"},
            "expected_new_stage": "default-us", "expected_new_stage_last": True,
            "expected_new_action": "US",
        }]}
        report = self._compare(candidate, [local_prefix, *profile_stages], cases)
        self.assertEqual(report["independent_cases"][0]["status"], "passed")

        early_match = {"id": "retained-broad-match", "action": "US", "rules": [self._mapping_rule("mihomo", "MATCH", "*")]}
        with self.assertRaisesRegex(clients.ProfileClientsError, "fallback-is-final"):
            self._compare(candidate, [local_prefix, early_match, *profile_stages], cases)

    def test_comparison_projects_surge_only_reject_variant_to_actual_mihomo_policy(self):
        result = SimpleNamespace(stage={"id": "reject-no-drop"}, stage_index=0, action="REJECT", reject_mode="no-drop", rule=_rule("mihomo", "DOMAIN", "blocked.example"))
        self.assertEqual(clients._result_route(result)["reject_mode"], "plain")
        result.rule.platform = "surge"
        self.assertEqual(clients._result_route(result)["reject_mode"], "no-drop")

    def test_bare_surge_policy_aliases_keep_their_declared_actions(self):
        baseline = "[Proxy]\nblocked = reject-no-drop\nlocal = direct\n[Proxy Group]\n"
        targets = clients._known_policy_targets("surge", baseline)
        self.assertEqual(clients._old_policy("blocked", targets), ("REJECT", "no-drop"))
        self.assertEqual(clients._old_policy("local", targets), ("DIRECT", None))

    def test_surge_group_keeps_a_declared_direct_named_alias_for_resolution(self):
        baseline = "[Proxy]\n🚀 Direct = reject\n[Proxy Group]\napple = select, 🚀 Direct\n"
        targets = clients._known_policy_targets("surge", baseline)
        self.assertEqual(clients._old_policy("apple", targets), ("REJECT", "plain"))

    def test_group_defaults_resolve_through_nested_direct_and_reject_choices(self):
        baseline = {
            "proxies": [{"name": "US node"}],
            "proxy-groups": [
                {"name": "local", "proxies": ["DIRECT"]},
                {"name": "apple", "proxies": ["local", "US node"]},
                {"name": "block", "proxies": ["REJECT"]},
                {"name": "US", "proxies": ["DIRECT"]},
            ],
        }
        targets = clients._known_policy_targets("mihomo", baseline)
        self.assertEqual(clients._old_policy("apple", targets), ("DIRECT", None))
        self.assertEqual(clients._old_policy("block", targets), ("REJECT", "plain"))
        self.assertEqual(clients._old_policy("US", targets), ("DIRECT", None))
        surge = "[Proxy]\nlocal = direct\n[Proxy Group]\napple = select, local, DIRECT\n"
        self.assertEqual(clients._old_policy("apple", clients._known_policy_targets("surge", surge)), ("DIRECT", None))
        self.assertEqual(clients._old_policy("JP", clients._known_policy_targets("surge", "[Proxy]\nJP = direct\n[Proxy Group]\n")), ("DIRECT", None))

    def test_display_aliases_use_declared_builtin_semantics_and_unknown_reject_names_fail(self):
        mihomo = {
            "proxies": [{"name": "🇺🇸 US"}, {"name": "🇯🇵 JP"}],
            "proxy-groups": [
                {"name": "⚒️ Test", "proxies": ["🇺🇸 US", "🇯🇵 JP", "🚀 Direct"]},
                {"name": "🚀 Direct", "proxies": ["DIRECT"]},
                {"name": "⛔️ Reject", "proxies": ["REJECT"]},
                {"name": "⛔️ Reject-Drop", "proxies": ["REJECT-DROP"]},
            ],
        }
        mihomo_targets = clients._known_policy_targets("mihomo", mihomo)
        self.assertEqual(clients._old_policy("🇺🇸 US", mihomo_targets), ("US", None))
        self.assertEqual(clients._old_policy("🇯🇵 JP", mihomo_targets), ("JP", None))
        self.assertEqual(clients._old_policy("⚒️ Test", mihomo_targets), ("TEST", None))
        self.assertEqual(clients._old_policy("🚀 Direct", mihomo_targets), ("DIRECT", None))
        self.assertEqual(clients._old_policy("⛔️ Reject", mihomo_targets), ("REJECT", "plain"))
        self.assertEqual(clients._old_policy("⛔️ Reject-Drop", mihomo_targets), ("REJECT", "drop"))
        with self.assertRaisesRegex(clients.ProfileClientsError, "unknown policy target"):
            clients._old_policy("⛔️ Reject", {"US"})

        surge = """[Proxy]
🚀 Direct = direct
⛔️ Reject = reject
⛔️ Reject-Drop = reject-drop
⛔️ Reject-No-Drop = reject-no-drop
🇺🇸 Snell = snell, us-snell.example, 443, psk=x
🇺🇸 TUIC = tuic-v5, us.example, 443, uuid=u, password=p
🇯🇵 Snell = snell, jp-snell.example, 443, psk=y
🇯🇵 TUIC = tuic-v5, jp.example, 443, uuid=j, password=q

[Proxy Group]
⚒️ Test = select, 🇺🇸 US, 🇯🇵 JP, 🚀 Direct
🇺🇸 US = smart, 🇺🇸 Snell, 🇺🇸 TUIC
🇯🇵 JP = smart, 🇯🇵 Snell, 🇯🇵 TUIC
"""
        surge_targets = clients._known_policy_targets("surge", surge)
        self.assertEqual(clients._old_policy("🚀 Direct", surge_targets), ("DIRECT", None))
        self.assertEqual(clients._old_policy("⛔️ Reject", surge_targets), ("REJECT", "plain"))
        self.assertEqual(clients._old_policy("⛔️ Reject-Drop", surge_targets), ("REJECT", "drop"))
        self.assertEqual(clients._old_policy("⛔️ Reject-No-Drop", surge_targets), ("REJECT", "no-drop"))
        self.assertEqual(clients._old_policy("⚒️ Test", surge_targets), ("TEST", None))
        with self.assertRaisesRegex(clients.ProfileClientsError, "unknown policy target"):
            clients._old_policy("⛔️ Reject-No-Drop", {"US"})

    def test_baseline_geoip_terminal_is_preserved_outside_source_rule_parser(self):
        for platform in ("mihomo", "surge"):
            stage, endpoint = clients._baseline_route_rule(
                profile, platform, ["GEOIP", "CN", "DIRECT", "no-resolve"],
                1, None, {}, {}, [], {"DIRECT"},
            )
            self.assertIsNone(endpoint)
            self.assertEqual(stage["rules"][0].type, "GEOIP")
            self.assertEqual(stage["rules"][0].value, "CN")
            self.assertEqual(stage["rules"][0].flags, ("no-resolve",))
            self.assertEqual(stage["action"], "DIRECT")

    def test_mihomo_emits_profile_stages_around_inline_geoip_and_terminal(self):
        rendered = clients.render_mihomo_snippet(_candidate(), "https://example.invalid/ref")
        route_section = rendered.split("rules:\n", 1)[1].split("\ndns:\n", 1)[0]
        expected = [
            "RULE-SET,att-us,🇺🇸 US,no-resolve",
            "GEOIP,CN,🚀 Direct,no-resolve",
            "RULE-SET,domestic-ip,🚀 Direct,no-resolve",
            "MATCH,🇺🇸 US",
        ]
        positions = [route_section.index(value) for value in expected]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(route_section.count("MATCH,🇺🇸 US"), 1)
        self.assertIn('"⛔️ Reject-Drop"', rendered)
        self.assertIn("proxy: 🇺🇸 US", rendered)
        self.assertIn('"🚀 Direct"', rendered)
        self.assertEqual(clients._mihomo_target({"action": "REJECT", "reject_mode": "drop"}), "⛔️ Reject-Drop")
        self.assertEqual(clients._mihomo_target({"action": "REJECT", "reject_mode": "no-drop"}), "⛔️ Reject")
        self.assertIn("enhanced-mode: fake-ip", rendered)

    def test_surge_emits_doh_node_policy_then_geoip_then_final(self):
        rendered = clients.render_surge_snippet(_candidate(), "https://example.invalid/ref")
        rules = rendered.split("[Rule]\n", 1)[1].split("\n[Host]", 1)[0].splitlines()
        expected = [
            "AND,((PROTOCOL,DOH),(DOMAIN,1.0.0.1)),🇯🇵 JP",
            "DOMAIN-SET,https://example.invalid/ref/rules/personal/surge/att-us.set,🇺🇸 US,no-resolve,update-interval=43200",
            "GEOIP,CN,🚀 Direct,no-resolve",
            "DOMAIN-SET,https://example.invalid/ref/rules/personal/surge/domestic-ip.set,🚀 Direct,no-resolve,update-interval=43200",
            "FINAL,🇺🇸 US,dns-failed",
        ]
        positions = [rules.index(value) for value in expected]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(sum(line.startswith("FINAL,") for line in rules), 1)
        self.assertTrue(all("AND,((PROTOCOL,DOH)" in line for line in rules if line.startswith("AND,")))
        self.assertIn("🚀 Direct = direct", rendered)
        self.assertIn("⛔️ Reject-Drop = reject-drop", rendered)
        self.assertIn("⛔️ Reject-No-Drop = reject-no-drop", rendered)
        self.assertEqual(clients._surge_target({"action": "REJECT", "reject_mode": "no-drop"}), "⛔️ Reject-No-Drop")

    def test_compact_physical_stages_drive_rendering_and_slot_scoped_dns_unions(self):
        candidate = _compact_candidate()
        surge_groups = candidate.manifest["compact"]["groups"]["surge"]
        surge_stages = candidate.compact_stages["surge"]
        surge_groups.reverse()
        by_id = {stage["id"]: stage for stage in surge_stages}
        candidate.compact_stages["surge"] = [by_id[group["id"]] for group in surge_groups] + surge_stages[-2:]
        candidate.manifest["compact"]["stages"]["surge"] = candidate.compact_stages["surge"]
        for group, stage in zip(candidate.manifest["compact"]["groups"]["mihomo"], candidate.compact_stages["mihomo"]):
            group.update({
                "slot": "priority-one" if group["id"] == "att-us" else "priority-two",
                "action": "DIRECT", "dns": "domestic", "dns_path": group["path"],
                "dns_kind": "route", "dns_behavior": group["behavior"], "dns_format": group["format"],
            })
            stage.update({"slot": group["slot"], "action": "DIRECT", "dns": "domestic"})

        mihomo = clients.render_mihomo_snippet(candidate, "https://example.invalid/ref")
        self.assertIn('"rule-set:att-us":', mihomo)
        self.assertIn('"rule-set:domestic-ip":', mihomo)
        self.assertIn("https://223.5.5.5/dns-query#🚀 Direct", mihomo)
        surge = clients.render_surge_snippet(candidate, "https://example.invalid/ref")
        routes = surge.split("[Rule]\n", 1)[1].split("\n[Host]", 1)[0]
        self.assertLess(routes.index("/rules/personal/surge/domestic-ip.set"), routes.index("/rules/personal/surge/att-us.set"))

    def test_test_doh_endpoint_has_a_distinct_test_policy(self):
        test_group = {"id": "network-test", "action": "TEST", "dns": "test"}
        jp_group = {"id": "jp", "action": "JP", "dns": "jp"}
        self.assertEqual(clients._dns_endpoints(test_group, "mihomo"), ("https://8.8.4.4/dns-query#⚒️ Test",))
        self.assertEqual(clients._dns_endpoints(jp_group, "surge"), ("https://1.0.0.1/dns-query",))
        self.assertTrue(clients._surge_endpoint_rules()[-1].endswith(")),⚒️ Test"))

    def test_mihomo_resolver_fragment_action_beats_conflicting_test_selector(self):
        selector = "rule-set:network-test"
        test_endpoint = "https://8.8.4.4/dns-query#⚒️ Test"
        legacy_jp_endpoint = "https://8.8.4.4/dns-query#🇯🇵 JP"
        unsupported = []

        self.assertEqual(clients._resolver_class(test_endpoint, selector), "TEST")
        self.assertEqual(clients._resolver_class(legacy_jp_endpoint, selector), "JP")
        self.assertEqual(clients._resolver_class("https://8.8.4.4/dns-query", selector), "TEST")
        self.assertEqual(clients._resolver_class("https://8.8.4.4/dns-query", "rule-set:jp-proxy"), "JP")
        self.assertEqual(clients._resolver_class("https://8.8.4.4/dns-query", "DOMAIN-SET:https://example.invalid/route/test.set"), "TEST")
        self.assertEqual(clients._resolver_policy([test_endpoint], unsupported, selector)[0], "TEST")
        self.assertEqual(clients._resolver_policy([legacy_jp_endpoint], unsupported, selector)[0], "JP")
        self.assertEqual(unsupported, [])

    def test_surge_host_comment_cleanup_keeps_private_mapping_lines(self):
        section = clients.SurgeSection("Host", "[Host]", [
            "# DNS-Fallback and Apple group route selectors",
            "# CNBanned group resolver note",
            "service.internal.example = 10.0.0.7",
        ])
        clients._rewrite_surge_host_comments(section)
        self.assertEqual(section.lines, ["service.internal.example = 10.0.0.7"])

    def test_surge_section_render_keeps_only_essential_comments_and_normalizes_spacing(self):
        sections = [
            clients.SurgeSection("General", "[General]", [
                "# old multi-paragraph explanation",
                "# ePDG real IP exception",
                'script-path = "https://example.invalid/run#token"',
                "",
                "",
                "always-real-ip = epdg.epc.att.net",
            ]),
            clients.SurgeSection("Proxy Group", "[Proxy Group]", [
                "# JP reserved empty selector",
                "TEST = select, DIRECT",
            ]),
        ]
        rendered = clients._render_surge_sections([], sections)
        self.assertNotIn("old multi-paragraph", rendered)
        self.assertIn("# ePDG real IP exception", rendered)
        self.assertIn("# JP reserved empty selector", rendered)
        self.assertIn('script-path = "https://example.invalid/run#token"', rendered)
        self.assertEqual(rendered.count("\n\n"), 1)

    @unittest.skipUnless(shutil.which("ruby"), "system Ruby YAML parser is unavailable")
    def test_public_mihomo_snippet_parses_as_yaml(self):
        rendered = clients.render_mihomo_snippet(_candidate(), "https://example.invalid/ref")
        check = "require 'yaml'; YAML.safe_load(STDIN.read, aliases: true); puts 'ok'"
        result = subprocess.run(["ruby", "-e", check], input=rendered, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "ok")

    def test_private_node_endpoint_rules_are_direct(self):
        rules = clients._node_endpoint_rules(
            [{"server": "proxy.example.net"}, {"server": "203.0.113.8"}],
            platform="surge", root=ROOT,
        )
        self.assertEqual(rules, [
            "DOMAIN,proxy.example.net,🚀 Direct",
            "IP-CIDR,203.0.113.8/32,🚀 Direct,no-resolve",
        ])


class CanonicalGroupTests(unittest.TestCase):
    def test_surge_dashboard_flag_is_removed_only_when_http_api_is_inactive(self):
        inactive = clients.SurgeSection("General", "[General]", [
            "http-api-web-dashboard = true",
            "http-api-web-dashboard = false",
            "# http-api = 127.0.0.1:6171",
        ])
        clients._remove_inactive_surge_dashboard_flag(inactive)
        self.assertEqual(inactive.lines, ["http-api-web-dashboard = false", "# http-api = 127.0.0.1:6171"])

        active = clients.SurgeSection("General", "[General]", [
            "http-api = 127.0.0.1:6171",
            "http-api-web-dashboard = true",
        ])
        clients._remove_inactive_surge_dashboard_flag(active)
        self.assertEqual(active.lines[-1], "http-api-web-dashboard = true")

    def test_mihomo_renames_tuic_leaves_and_keeps_only_flat_test_selector(self):
        jp = {
            "name": "JP TUIC", "type": "tuic", "server": "jp.example", "port": 443,
            "uuid": "jp-uuid", "password": "jp-password", "sni": "jp.sni.example",
            "ip": "192.0.2.9", "alpn": ["h3"], "udp-relay-mode": "native",
        }
        us = {
            "name": "US TUIC", "type": "tuic", "server": "us.example", "port": 443,
            "uuid": "us-uuid", "password": "us-password", "fast-open": True,
            "reduce-rtt": True, "sni": "us.sni.example", "ip": "192.0.2.8",
        }
        config = {
            "proxies": [
                us,
            ],
            "proxy-groups": [
                {"name": "US Smart", "type": "url-test", "proxies": ["US TUIC", "US Snell"]},
                {"name": "JP Smart", "type": "url-test", "proxies": ["JP TUIC"]},
                {"name": "Mixed Smart", "type": "url-test", "proxies": ["US Smart", "JP Smart"]},
                {"name": "TEST pool", "type": "select", "proxies": ["Mixed Smart", "DIRECT"]},
            ],
        }
        expected_us = {**us, "name": "🇺🇸 US"}
        expected_us.pop("fast-open")
        clients._canonical_mihomo_groups(config, jp)
        self.assertEqual([item["name"] for item in config["proxy-groups"]], ["⚒️ Test", "🚀 Direct", "⛔️ Reject", "⛔️ Reject-Drop"])
        self.assertEqual(config["proxy-groups"][0], {
            "name": "⚒️ Test", "type": "select", "proxies": ["🇺🇸 US", "🇯🇵 JP", "🚀 Direct"],
        })
        self.assertEqual(config["proxy-groups"][1:], [
            {"name": "🚀 Direct", "type": "select", "proxies": ["DIRECT"]},
            {"name": "⛔️ Reject", "type": "select", "proxies": ["REJECT"]},
            {"name": "⛔️ Reject-Drop", "type": "select", "proxies": ["REJECT-DROP"]},
        ])
        self.assertEqual(len(config["proxies"]), 2)
        self.assertEqual(config["proxies"][0], expected_us)
        self.assertEqual(config["proxies"][1], {
            **jp, "name": "🇯🇵 JP", "congestion-controller": "bbr",
            "heartbeat-interval": 8000, "disable-sni": False, "udp-relay-mode": "native",
        })
        self.assertEqual(config["proxies"][0]["sni"], "us.sni.example")
        self.assertEqual(config["proxies"][1]["sni"], "jp.sni.example")
        clients._canonical_mihomo_groups(config, jp)
        self.assertEqual([item["name"] for item in config["proxy-groups"]], ["⚒️ Test", "🚀 Direct", "⛔️ Reject", "⛔️ Reject-Drop"])

    def test_old_surge_country_display_names_compare_as_logical_actions(self):
        baseline = """[Proxy]
🇺🇸 Snell = snell, us-snell.example, 443, psk=fixture, version=6
🇺🇸 TUIC = tuic-v5, us.example, 443, uuid=u, password=p
🇯🇵 Snell = snell, jp-snell.example, 443, psk=fixture, version=6
🇯🇵 TUIC = tuic-v5, jp.example, 443, uuid=j, password=q

[Proxy Group]
US Smart = smart, 🇺🇸 TUIC, 🇺🇸 Snell, include-other-group=JP Smart
JP Smart = smart, 🇯🇵 TUIC, 🇯🇵 Snell
🇺🇸 US = smart, 🇺🇸 Snell, 🇺🇸 TUIC
🇯🇵 JP = smart, 🇯🇵 Snell, 🇯🇵 TUIC
TEST pool = select, US Smart, JP Smart, DIRECT
"""
        targets = clients._known_policy_targets("surge", baseline)
        self.assertEqual(clients._old_policy("🇺🇸 US", targets), ("US", None))
        self.assertEqual(clients._old_policy("🇯🇵 JP", targets), ("JP", None))
        self.assertEqual(clients._old_policy("US Smart", targets), ("US", None))
        self.assertEqual(clients._old_policy("JP Smart", targets), ("JP", None))
        self.assertEqual(clients._old_policy("TEST pool", targets), ("TEST", None))

    def test_surge_exposes_country_smart_groups_and_a_flat_test_selector(self):
        section = clients.SurgeSection("Proxy Group", "[Proxy Group]", [
            "US Smart = smart, US TUIC, US Snell, interval=300",
            "JP Smart = smart, JP TUIC, JP Snell, interval=300",
            "Mixed Smart = smart, US Smart, JP Smart",
            "Test pool = select, Mixed Smart, JP TUIC, 🚀 Direct",
        ])
        proxy_entries = [
            ("🇺🇸 TUIC", "tuic-v5", ["tuic-v5", "us.example", "443"]),
            ("🇯🇵 TUIC", "tuic-v5", ["tuic-v5", "jp.example", "443"]),
            ("🇺🇸 Snell", "snell", ["snell", "us-snell.example", "443", "psk=fixture", "version=6"]),
            ("🇯🇵 Snell", "snell", ["snell", "jp-snell.example", "443", "psk=fixture", "version=6"]),
        ]
        lines = clients._surge_group_aliases(section, proxy_entries)
        self.assertEqual(lines, [
            "🇺🇸 US = smart, 🇺🇸 Snell, 🇺🇸 TUIC",
            "🇯🇵 JP = smart, 🇯🇵 Snell, 🇯🇵 TUIC",
            "⚒️ Test = select, 🇺🇸 US, 🇯🇵 JP, 🚀 Direct",
        ])
        self.assertNotIn("include-other-group", "\n".join(lines))

    def test_surge_tuic_rename_removes_tcp_fast_open_but_keeps_other_options(self):
        _, sections = clients._surge_sections(
            "[Proxy]\nUS node = tuic-v5, us.example, 443, uuid=u, password=p, alpn=h3, tfo=true\n"
            "JP node = tuic-v5, jp.example, 443, uuid=j, password=q, alpn=h3, tfo=false\n"
            "US Snell = snell, us-snell.example, 443, psk=s, version=6, tfo=true\n"
            "JP Snell = snell, jp-snell.example, 443, psk=t, version=6, tfo=true\n"
            "[Proxy Group]\nTEST pool = select, US node, JP node, DIRECT\n"
        )
        entries = clients._canonical_surge_proxy_names(sections)
        self.assertEqual([item[0] for item in entries], ["🇺🇸 TUIC", "🇯🇵 TUIC", "🇺🇸 Snell", "🇯🇵 Snell"])
        rendered = "\n".join(sections[0].lines)
        self.assertNotIn("tfo=true", rendered.split("🇺🇸 TUIC =", 1)[1].splitlines()[0])
        self.assertIn("tfo=false", rendered.split("🇯🇵 TUIC =", 1)[1].splitlines()[0])
        self.assertIn("tfo=true", rendered.split("🇺🇸 Snell =", 1)[1].splitlines()[0])
        self.assertIn("tfo=true", rendered.split("🇯🇵 Snell =", 1)[1].splitlines()[0])
        self.assertIn("alpn=h3", rendered)
        self.assertIn("password=q", rendered)

    def test_surge_discards_dynamic_country_wrappers_when_building_canonical_groups(self):
        section = clients.SurgeSection("Proxy Group", "[Proxy Group]", [
            "US Smart = smart, US TUIC, include-other-group=JP Smart",
            "JP Smart = smart, JP TUIC",
            "Test pool = select, US Smart, DIRECT",
        ])
        proxy_entries = [
            ("🇺🇸 TUIC", "tuic-v5", ["tuic-v5", "us.example", "443"]),
            ("🇯🇵 TUIC", "tuic-v5", ["tuic-v5", "jp.example", "443"]),
            ("🇺🇸 Snell", "snell", ["snell", "us-snell.example", "443", "psk=fixture", "version=6"]),
            ("🇯🇵 Snell", "snell", ["snell", "jp-snell.example", "443", "psk=fixture", "version=6"]),
        ]
        lines = clients._surge_group_aliases(section, proxy_entries)
        self.assertEqual(lines, [
            "🇺🇸 US = smart, 🇺🇸 Snell, 🇺🇸 TUIC",
            "🇯🇵 JP = smart, 🇯🇵 Snell, 🇯🇵 TUIC",
            "⚒️ Test = select, 🇺🇸 US, 🇯🇵 JP, 🚀 Direct",
        ])

    def test_surge_migration_is_idempotent_and_preserves_private_host_mapping(self):
        baseline = f"""[General]
encrypted-dns-server = https://8.8.8.8/dns-query

[Proxy]
US node = tuic-v5, us.example.net, 443, uuid=u, password=p, alpn=h3, tfo=true
JP node = tuic-v5, jp.example.net, 443, uuid=j, password=q, alpn=h3, tfo=false
US Snell = snell, us-snell.example.net, 443, psk=us-secret, version=6
JP Snell = snell, jp-snell.example.net, 443, psk=jp-secret, version=6

[Proxy Group]
US Smart = smart, US node, US Snell, interval=300
JP Smart = smart, JP node, JP Snell, interval=300
Mixed Smart = smart, US Smart, JP Smart
TEST pool = select, Mixed Smart, JP node, DIRECT

[Rule]
FINAL,US,dns-failed

[Host]
# DNS-Fallback and Apple group choices
company.internal = 192.0.2.10
# CNBanned group owns a resolver selector
"""
        first = clients._migrate_surge(_candidate(), baseline, "https://example.invalid/ref")
        second = clients._migrate_surge(_candidate(), first.decode("utf-8"), "https://example.invalid/ref")
        self.assertEqual(second, first)
        rendered = first.decode("utf-8")
        self.assertEqual(rendered.count("company.internal = 192.0.2.10"), 1)
        self.assertIn("🇺🇸 US = smart, 🇺🇸 Snell, 🇺🇸 TUIC", rendered)
        self.assertIn("🇯🇵 JP = smart, 🇯🇵 Snell, 🇯🇵 TUIC", rendered)
        self.assertIn("⚒️ Test = select, 🇺🇸 US, 🇯🇵 JP, 🚀 Direct", rendered)
        self.assertEqual(rendered.count("🚀 Direct = direct"), 1)
        self.assertEqual(rendered.count("⛔️ Reject = reject"), 1)
        self.assertEqual(rendered.count("⛔️ Reject-Drop = reject-drop"), 1)
        self.assertEqual(rendered.count("⛔️ Reject-No-Drop = reject-no-drop"), 1)
        self.assertIn("DOMAIN,us.example.net,🚀 Direct", rendered)
        self.assertNotIn("Mixed Smart", rendered)
        self.assertNotIn("DNS-Fallback", rendered)
        self.assertNotIn("CNBanned", rendered)
        self.assertEqual(rendered.count("\n\n"), rendered.count("[General]") + rendered.count("[Proxy]") + rendered.count("[Proxy Group]") + rendered.count("[Rule]") + rendered.count("[Host]") - 1)
        _, rendered_sections = clients._surge_sections(rendered)
        rendered_nodes = clients._surge_proxy_entries(rendered_sections)
        self.assertEqual(
            [(name, protocol) for name, protocol, _fields in rendered_nodes],
            [("🇺🇸 TUIC", "tuic-v5"), ("🇯🇵 TUIC", "tuic-v5"), ("🇺🇸 Snell", "snell"), ("🇯🇵 Snell", "snell")],
        )
        self.assertEqual(
            sum(field == "version=6" for _name, protocol, fields in rendered_nodes if protocol == "snell" for field in fields),
            2,
        )

    def test_surge_migration_rejects_native_aliases_that_conflict_with_generated_names(self):
        baseline = """[General]

[Proxy]
US node = tuic-v5, us.example.net, 443, uuid=u, password=p
JP node = tuic-v5, jp.example.net, 443, uuid=j, password=q
US Snell = snell, us-snell.example.net, 443, psk=us, version=6
JP Snell = snell, jp-snell.example.net, 443, psk=jp, version=6
⚒️ Test = direct

[Proxy Group]
US Smart = smart, US node, US Snell
JP Smart = smart, JP node, JP Snell
TEST pool = select, US Smart, JP Smart, DIRECT

[Rule]
FINAL,US,dns-failed

[Host]
"""
        with self.assertRaisesRegex(clients.ProfileClientsError, "conflicts with a generated group or leaf"):
            clients._migrate_surge(_candidate(), baseline, "https://example.invalid/ref")

    def test_surge_native_aliases_keep_original_positions_and_duplicate_definitions_fail(self):
        original = [
            "US node = tuic-v5, us.example.net, 443, uuid=u, password=p",
            "🚀 Direct = direct",
            "JP node = tuic-v5, jp.example.net, 443, uuid=j, password=q",
            "⛔️ Reject = reject",
        ]
        section = clients.SurgeSection("Proxy", "[Proxy]", list(original))

        clients._set_surge_policy_aliases(section)

        self.assertEqual(section.lines[:len(original)], original)
        self.assertEqual(section.lines[len(original):], [
            "⛔️ Reject-Drop = reject-drop",
            "⛔️ Reject-No-Drop = reject-no-drop",
        ])
        with self.assertRaisesRegex(clients.ProfileClientsError, "defined more than once"):
            clients._set_surge_policy_aliases(clients.SurgeSection(
                "Proxy", "[Proxy]", ["🚀 Direct = direct", "🚀 Direct = direct"],
            ))

    def test_surge_repeated_literal_node_endpoint_rule_is_deduplicated_idempotently(self):
        baseline = """[General]

[Proxy]
US node = tuic-v5, 192.0.2.21, 443, uuid=u, password=p
JP node = tuic-v5, jp.example.net, 443, uuid=j, password=q
US Snell = snell, us-snell.example.net, 443, psk=us, version=6
JP Snell = snell, jp-snell.example.net, 443, psk=jp, version=6

[Proxy Group]
US Smart = smart, US node, US Snell
JP Smart = smart, JP node, JP Snell
TEST pool = select, US Smart, JP Smart, DIRECT

[Rule]
FINAL,US,dns-failed

[Host]
"""
        inline = [clients._stage(
            "DIRECT", None, [_rule("surge", "IP-CIDR", "192.0.2.21/32", ("no-resolve",))],
            stage_id="local-inline-surge-ip",
        )]
        first = clients._migrate_surge(
            _candidate(), baseline, "https://example.invalid/ref", local_stages=inline,
        )
        second = clients._migrate_surge(
            _candidate(), first.decode("utf-8"), "https://example.invalid/ref", local_stages=inline,
        )
        self.assertEqual(first, second)
        self.assertEqual(first.decode("utf-8").count("IP-CIDR,192.0.2.21/32,🚀 Direct,no-resolve"), 1)

    def test_v2_surge_baseline_without_country_groups_migrates_to_smart_groups(self):
        baseline = """[General]
always-real-ip = epdg.epc.att.net

[Proxy]
US = snell, us-snell.example.net, 443, psk=us-secret, version=6
JP = snell, jp-snell.example.net, 443, psk=jp-secret, version=6
US-TUIC = tuic-v5, us.example.net, 443, uuid=u, password=p, alpn=h3, tfo=true
JP-TUIC = tuic-v5, jp.example.net, 443, uuid=j, password=q, alpn=h3

[Proxy Group]
TEST = select, US, JP, DIRECT

[Rule]
FINAL,US,dns-failed

[Host]
office.internal = 10.0.0.5
"""
        rendered = clients._migrate_surge(_candidate(), baseline, "https://example.invalid/ref").decode()
        self.assertIn("🇺🇸 Snell = snell, us-snell.example.net, 443, psk=us-secret, version=6", rendered)
        self.assertIn("🇯🇵 Snell = snell, jp-snell.example.net, 443, psk=jp-secret, version=6", rendered)
        self.assertIn("office.internal = 10.0.0.5", rendered)
        self.assertIn("🇺🇸 US = smart, 🇺🇸 Snell, 🇺🇸 TUIC", rendered)
        self.assertIn("🇯🇵 JP = smart, 🇯🇵 Snell, 🇯🇵 TUIC", rendered)
        self.assertIn("FINAL,🇺🇸 US,dns-failed", rendered)
        self.assertIn("DOMAIN,us.example.net,🚀 Direct", rendered)


class PrivateMigrationCleanupTests(unittest.TestCase):
    def test_exact_direct_removal_requires_no_resolve_on_intervening_ip_rules(self):
        candidate = _candidate()
        api = clients._load_api(ROOT)
        aliases = clients._source_aliases(candidate, api)
        baseline = {
            "proxies": [{"name": "node"}],
            "proxy-groups": [{"name": "🚀 Direct", "proxies": ["DIRECT"]}],
            "rules": [
                "DOMAIN,service.example,DIRECT",
                "IP-CIDR,203.0.113.0/24,DIRECT",
                "DOMAIN-SUFFIX,service.example,DIRECT",
            ],
        }

        retained = clients._private_inline_stages(api, "mihomo", baseline, candidate, aliases, [])
        retained_domains = [
            (rule.type, rule.value, rule.line)
            for stage in retained for rule in stage["rules"]
        ]
        self.assertIn(("DOMAIN", "service.example", 1), retained_domains)

        baseline["rules"][1] = "IP-CIDR,203.0.113.0/24,DIRECT,no-resolve"
        retained = clients._private_inline_stages(api, "mihomo", baseline, candidate, aliases, [])
        retained_domains = [
            (rule.type, rule.value, rule.line)
            for stage in retained for rule in stage["rules"]
        ]
        self.assertNotIn(("DOMAIN", "service.example", 1), retained_domains)
        self.assertIn(("DOMAIN-SUFFIX", "service.example", 3), retained_domains)

    def test_migration_retires_only_reviewed_builtin_direct_selectors(self):
        candidate = _candidate()
        api = clients._load_api(ROOT)
        aliases = clients._source_aliases(candidate, api)
        mihomo = {
            "proxies": [{"name": "node"}],
            "proxy-groups": [
                {"name": "🚀 Direct", "proxies": ["DIRECT"]},
                {"name": "custom-direct", "proxies": ["DIRECT", "node"]},
            ],
            "rules": [
                "DOMAIN-SUFFIX,istatmenus.app,DIRECT",
                "DOMAIN,istatmenus.app,DIRECT",
                "DOMAIN,clash.razord.top,DIRECT",
                "DOMAIN-SUFFIX,clash.razord.top,DIRECT",
                "DOMAIN-SUFFIX,istatmenus.app,custom-direct",
                "DOMAIN,clash.razord.top,custom-direct",
            ],
        }
        retained = clients._private_inline_stages(api, "mihomo", mihomo, candidate, aliases, [])
        retained_rules = {
            (stage["rules"][0].type, stage["rules"][0].value, stage["action"], stage["rules"][0].line)
            for stage in retained
        }
        self.assertNotIn(("DOMAIN-SUFFIX", "istatmenus.app", "DIRECT", 1), retained_rules)
        self.assertNotIn(("DOMAIN", "clash.razord.top", "DIRECT", 3), retained_rules)
        self.assertIn(("DOMAIN", "istatmenus.app", "DIRECT", 2), retained_rules)
        self.assertIn(("DOMAIN-SUFFIX", "clash.razord.top", "DIRECT", 4), retained_rules)
        self.assertIn(("DOMAIN-SUFFIX", "istatmenus.app", "DIRECT", 5), retained_rules)
        self.assertIn(("DOMAIN", "clash.razord.top", "DIRECT", 6), retained_rules)

        surge = """[Proxy]
Direct = direct
node = ss, node.example, 443, encrypt-method=aes-128-gcm, password=x

[Proxy Group]
custom-direct = select, DIRECT, node

[Rule]
AND,((PROTOCOL,DOH),(DOMAIN,doh.pub)),Direct
AND,((PROTOCOL,DOH),(DOMAIN,doh.pub)),custom-direct
DOMAIN-SUFFIX,istatmenus.app,DIRECT
DOMAIN,istatmenus.app,DIRECT
DOMAIN,ruleset.skk.moe,JP
DOMAIN,ruleset-mirror.skk.moe,JP

[Host]
"""
        aliases = clients._source_aliases(candidate, api)
        unsupported = []
        local = clients._private_inline_stages(api, "surge", surge, candidate, aliases, unsupported)
        retained_surge = [
            (stage["rules"][0].type, stage["rules"][0].value, stage["action"], stage["rules"][0].line)
            for stage in local
        ]
        doh_pub = ("AND", "((PROTOCOL,DOH),(DOMAIN,doh.pub))", "DIRECT")
        self.assertEqual(sum(item[:3] == doh_pub for item in retained_surge), 1)
        self.assertNotIn(("DOMAIN-SUFFIX", "istatmenus.app", "DIRECT", 3), retained_surge)
        self.assertIn(("DOMAIN", "istatmenus.app", "DIRECT", 4), retained_surge)
        self.assertEqual(
            [action for rule_type, value, action, _line in retained_surge if rule_type == "DOMAIN" and value.startswith("ruleset")],
            ["US", "US"],
        )
        self.assertEqual(unsupported, [])

    def test_legacy_dns_cleanup_matches_only_exact_direct_selectors(self):
        direct = ["https://dns.alidns.com/dns-query#DIRECT"]
        us = ["https://dns.google/dns-query#US"]
        self.assertTrue(clients._retire_known_legacy_dns_selector("mihomo", "+.istatmenus.app", direct))
        self.assertTrue(clients._retire_known_legacy_dns_selector("mihomo", "clash.razord.top", direct))
        self.assertTrue(clients._retire_known_legacy_dns_selector("surge", "*.istatmenus.app", direct))
        self.assertFalse(clients._retire_known_legacy_dns_selector("mihomo", "+.istatmenus.app", us))
        self.assertFalse(clients._retire_known_legacy_dns_selector("mihomo", "+.custom.istatmenus.app", direct))
        self.assertFalse(clients._retire_known_legacy_dns_selector("surge", "custom.istatmenus.app", direct))


class LegacyDnsSelectorTests(unittest.TestCase):
    def test_raw_repository_url_does_not_accept_a_different_repository(self):
        path, recognized = clients._normalized_repository_reference(
            "https://raw.githubusercontent.com/main/rules/personal/mihomo/cn-direct-domain.mrs"
        )
        self.assertIsNone(path)
        self.assertTrue(recognized)

    def test_source_witness_ignores_diagnostic_canary(self):
        canary = profile.Rule(*profile.SUKKA_IP_CANARY, platform="mihomo")
        lan = profile.Rule("DOMAIN-SUFFIX", "lan", platform="mihomo")
        self.assertEqual(clients._matching_representatives(canary, profile), [])
        subject, _ = clients._stage_witness(
            {"rules": [canary, lan]}, "mihomo", family=None, api=profile
        )
        self.assertTrue(profile.rule_matches(lan, **subject))
        self.assertNotEqual(subject.get("domain"), canary.value)

    def test_and_route_rule_generates_a_protocol_domain_witness(self):
        rule = profile.Rule(
            "AND", "((PROTOCOL,DOH),(DOMAIN,doh.pub))", (), "fixture", 1, "surge",
        )
        self.assertEqual(
            clients._matching_representatives(rule, profile),
            [({"domain": "doh.pub", "protocol": "DOH"}, "source-rule")],
        )

    def test_mihomo_comma_provider_union_expands_and_retains_custom_order(self):
        candidate = _candidate()
        candidate.stages[0]["dns"] = "foreign"
        api = clients._load_api(ROOT)
        aliases = clients._source_aliases(candidate, api)
        selector = "rule-set:ai-global,apple_intelligence,reject_drop,reject_domains,reject_extra,reject,reject_no_drop,sogouinput"
        custom_names = ["apple_intelligence", "reject_drop", "reject_domains", "reject_extra", "reject", "reject_no_drop", "sogouinput"]
        providers = {"ai-global": {"path": "fixture"}}
        providers.update({name: {"path": f"vendor/{name}.list"} for name in custom_names})
        baseline = {
            "rule-providers": providers,
            "dns": {
                "nameserver-policy": {
                    selector: ["https://dns.google/dns-query#US"],
                },
                "nameserver": ["https://dns.google/dns-query#US"],
            },
        }
        unsupported = []
        stages, default, _ = clients._parse_old_dns(api, "mihomo", candidate, baseline, aliases, unsupported)
        self.assertEqual(default, "US")
        self.assertEqual(len(stages), 1)
        self.assertEqual({rule.source for rule in stages[0]["rules"]}, {"fixture"})
        self.assertEqual(len(unsupported), len(custom_names))

        config = {
            "rule-providers": baseline["rule-providers"],
            "dns": {"nameserver-policy": baseline["dns"]["nameserver-policy"], "fake-ip-filter": []},
            "proxies": [],
        }
        clients._set_mihomo_providers(config, candidate, "https://example.invalid/ref", ROOT)
        self.assertEqual(list(config["dns"]["nameserver-policy"]), ["rule-set:" + ",".join(custom_names)])
        self.assertEqual([key for key in custom_names if key in config["rule-providers"]], custom_names)

    def test_company_dns_wildcard_selector_uses_domain_wildcard_rule(self):
        api = clients._load_api(ROOT)
        rules, extended = clients._selector_rules(api, "mihomo", "*.byted.org", _candidate(), {}, [])
        self.assertFalse(extended)
        self.assertEqual([(rule.type, rule.value) for rule in rules], [("DOMAIN-WILDCARD", "*.byted.org")])

    def test_mihomo_retires_fully_test_covered_public_dns_overrides(self):
        candidate = _candidate_with_test_dns_domains()
        policies = {
            "+.speedtest.cn": ["https://dns.alidns.com/dns-query#DIRECT"],
            "api.speedtest.cn": ["https://dns.google/dns-query#US"],
            "*.speedtest.cn": ["https://dns.alidns.com/dns-query#DIRECT"],
            "+.cn": ["https://dns.alidns.com/dns-query#DIRECT"],
            "health.speedtest.cn": ["system"],
            "+.internal": ["https://dns.alidns.com/dns-query#DIRECT"],
            "custom.speedtest.cn": ["https://10.0.0.53/dns-query"],
            "private.speedtest.cn": ["https://192.168.0.53/dns-query#DIRECT"],
            "private-port.speedtest.cn": ["192.168.0.53:53#DIRECT"],
            "private-v6.speedtest.cn": ["[fd00::53]:53#DIRECT"],
        }
        config = {
            "rule-providers": {},
            "dns": {"nameserver-policy": policies, "fake-ip-filter": []},
            "proxies": [],
        }

        clients._set_mihomo_providers(config, candidate, "https://example.invalid/ref", ROOT)

        migrated = config["dns"]["nameserver-policy"]
        self.assertNotIn("+.speedtest.cn", migrated)
        self.assertNotIn("api.speedtest.cn", migrated)
        self.assertNotIn("*.speedtest.cn", migrated)
        self.assertIn("+.cn", migrated)
        self.assertIn("health.speedtest.cn", migrated)
        self.assertIn("+.internal", migrated)
        self.assertIn("custom.speedtest.cn", migrated)
        self.assertIn("private.speedtest.cn", migrated)
        self.assertIn("private-port.speedtest.cn", migrated)
        self.assertIn("private-v6.speedtest.cn", migrated)

    def test_retained_dns_comparison_uses_the_same_test_scope_retirement(self):
        candidate = _candidate_with_test_dns_domains()
        api = clients._load_api(ROOT)
        aliases = clients._source_aliases(candidate, api)
        baseline = {
            "rule-providers": {},
            "dns": {"nameserver-policy": {
                "+.speedtest.cn": ["https://dns.alidns.com/dns-query#DIRECT"],
                "api.speedtest.cn": ["https://dns.google/dns-query#US"],
                "+.cn": ["https://dns.alidns.com/dns-query#DIRECT"],
                "health.speedtest.cn": ["system"],
                "+.internal": ["https://dns.alidns.com/dns-query#DIRECT"],
                "custom.speedtest.cn": ["https://10.0.0.53/dns-query"],
                "private.speedtest.cn": ["https://192.168.0.53/dns-query#DIRECT"],
                "private-port.speedtest.cn": ["192.168.0.53:53#DIRECT"],
                "private-v6.speedtest.cn": ["[fd00::53]:53#DIRECT"],
            }},
        }
        unsupported = []
        old_stages, _, _ = clients._parse_old_dns(api, "mihomo", candidate, baseline, aliases, unsupported)

        retained = clients._retained_dns_stages(old_stages, candidate, "mihomo")

        selectors = {stage["selector"] for stage in retained}
        self.assertNotIn("+.speedtest.cn", selectors)
        self.assertNotIn("api.speedtest.cn", selectors)
        self.assertIn("+.cn", selectors)
        self.assertIn("health.speedtest.cn", selectors)
        self.assertIn("+.internal", selectors)
        self.assertIn("custom.speedtest.cn", selectors)
        self.assertIn("private.speedtest.cn", selectors)
        self.assertIn("private-port.speedtest.cn", selectors)
        self.assertIn("private-v6.speedtest.cn", selectors)

    def test_surge_retires_only_fully_test_covered_public_dns_host_selectors(self):
        candidate = _candidate_with_test_dns_domains()
        lines = [
            "*.speedtest.cn = server:https://223.5.5.5/dns-query",
            "api.speedtest.cn = server:https://8.8.8.8/dns-query",
            "*.cn = server:https://223.5.5.5/dns-query",
            "health.speedtest.cn = server:system",
            "*.internal = server:https://223.5.5.5/dns-query",
            "custom.speedtest.cn = server:https://10.0.0.53/dns-query",
            "private.speedtest.cn = server:https://192.168.0.53/dns-query#DIRECT",
            "private-port.speedtest.cn = server:192.168.0.53:53#DIRECT",
            "private-v6.speedtest.cn = server:[fd00::53]:53#DIRECT",
            "mapped.speedtest.cn = 192.0.2.1",
        ]
        host = clients.SurgeSection("Host", "[Host]", list(lines))

        clients._surge_dns(host, candidate, "https://example.invalid/ref", ROOT)

        retained = set(host.lines)
        self.assertNotIn(lines[0], retained)
        self.assertNotIn(lines[1], retained)
        for line in lines[2:]:
            self.assertIn(line, retained)

    def test_private_inline_direct_aliases_are_retired_only_when_they_are_builtin(self):
        candidate = _candidate_with_test_dns_domains()
        api = clients._load_api(ROOT)
        aliases = clients._source_aliases(candidate, api)
        route_lines = [
            "DOMAIN-SUFFIX,speedtest.cn,🚀 Direct",
            "DOMAIN-SUFFIX,speedtest.cn,direct-plus-proxy",
            "DOMAIN-SUFFIX,speedtest.cn,dynamic-direct-alias",
        ]

        mihomo = {
            "proxies": [{"name": "node"}],
            "proxy-groups": [
                {"name": "🚀 Direct", "proxies": ["DIRECT"]},
                {"name": "direct-plus-proxy", "proxies": ["DIRECT", "node"]},
                {
                    "name": "dynamic-direct-alias", "proxies": ["DIRECT"],
                    "use": ["provider"], "include-all": True,
                },
            ],
            "rules": route_lines,
        }
        surge = (
            "[Proxy]\n🚀 Direct = direct\nnode = ss, node.example, 443, "
            "encrypt-method=aes-128-gcm, password=x\n"
            "[Proxy Group]\ndirect-plus-proxy = select, DIRECT, node\n"
            "dynamic-direct-alias = select, DIRECT, node\n"
            "[Rule]\n" + "\n".join(route_lines) + "\n"
        )

        for platform, baseline in (("mihomo", mihomo), ("surge", surge)):
            with self.subTest(platform=platform):
                local = clients._private_inline_stages(
                    api, platform, baseline, candidate, aliases, [],
                )
                retained_ids = {stage["id"] for stage in local}
                self.assertNotIn(f"local-inline-{platform}-1", retained_ids)
                self.assertIn(f"local-inline-{platform}-2", retained_ids)
                self.assertIn(f"local-inline-{platform}-3", retained_ids)

    def test_private_inline_direct_rules_yield_fully_covered_test_domains(self):
        candidate = _candidate_with_test_dns_domains()
        route_lines = [
            "DOMAIN-SUFFIX,speedtest.cn,DIRECT",
            "DOMAIN,probe.speedtest.cn,DIRECT",
            "DOMAIN-SUFFIX,istatmenus.app,DIRECT",
            "DOMAIN-SUFFIX,us.zesming.fun,DIRECT",
            "DOMAIN,bootstrap.us.zesming.fun,DIRECT",
            "DOMAIN-SUFFIX,company.internal,DIRECT",
            "DOMAIN,portal.speedtest.cn,REJECT",
        ]

        for platform in ("mihomo", "surge"):
            with self.subTest(platform=platform):
                api = clients._load_api(ROOT)
                aliases = clients._source_aliases(candidate, api)
                baseline = (
                    {"rules": route_lines, "rule-providers": {}}
                    if platform == "mihomo"
                    else "[Proxy]\n\n[Proxy Group]\n\n[Rule]\n" + "\n".join(route_lines) + "\n"
                )
                local = clients._private_inline_stages(api, platform, baseline, candidate, aliases, [])
                retained = {(stage["action"], stage["rules"][0].type, stage["rules"][0].value) for stage in local}

                self.assertNotIn(("DIRECT", "DOMAIN-SUFFIX", "speedtest.cn"), retained)
                self.assertNotIn(("DIRECT", "DOMAIN", "probe.speedtest.cn"), retained)
                self.assertNotIn(("DIRECT", "DOMAIN-SUFFIX", "istatmenus.app"), retained)
                self.assertIn(("DIRECT", "DOMAIN-SUFFIX", "us.zesming.fun"), retained)
                self.assertIn(("DIRECT", "DOMAIN", "bootstrap.us.zesming.fun"), retained)
                self.assertIn(("DIRECT", "DOMAIN-SUFFIX", "company.internal"), retained)
                self.assertIn(("REJECT", "DOMAIN", "portal.speedtest.cn"), retained)

                if platform == "mihomo":
                    test_stage = next(stage for stage in clients._make_dns_stages(candidate, platform) if stage["action"] == "TEST")
                    subject = {"domain": "speedtest.cn"}
                    route_index = api.RuleIndex([*local, test_stage], platform)
                    route = clients._first_route(route_index, [*local, test_stage], subject, platform, api)
                    dns_index = api.RuleIndex([test_stage], platform)
                    dns, _, _ = clients._dns_match(dns_index, [test_stage], subject, platform, "US")
                    self.assertEqual(route.action, "TEST")
                    self.assertEqual(dns, "TEST")

    def test_legacy_provider_paths_resolve_to_canonical_source_identity(self):
        candidate = SimpleNamespace(stages=[{
            "rules": [
                SimpleNamespace(source="legacy:ai-global"),
                SimpleNamespace(source="rules/mihomo/cn-direct-special.list"),
                SimpleNamespace(source="rules/surge/cn-direct-special.list"),
                SimpleNamespace(source="rules/mihomo/cn-direct-domain.txt"),
            ],
        }])
        aliases = clients._source_aliases(candidate, clients._load_api(ROOT))
        self.assertEqual(
            clients._resolve_source_reference("https://rules.example/rules/ai-global.list", aliases),
            "legacy:ai-global",
        )
        self.assertEqual(
            clients._resolve_source_reference("cn-direct-special.list", aliases, platform="mihomo"),
            "rules/mihomo/cn-direct-special.list",
        )
        self.assertEqual(
            clients._resolve_source_reference("cn-direct-special.list", aliases, platform="surge"),
            "rules/surge/cn-direct-special.list",
        )
        self.assertEqual(
            clients._resolve_source_reference("cn-direct-domain.mrs", aliases, platform="mihomo"),
            "rules/mihomo/cn-direct-domain.txt",
        )

    def test_baseline_group_alias_replays_fine_sources_and_allows_empty_jp_resource(self):
        candidate = _candidate()
        manifest = {
            "groups": {
                "mihomo": [
                    {
                        "id": "priority-lan-classical",
                        "path": "rules/personal/mihomo/priority-lan-classical.list",
                        "stages": ["att-us"], "rule_count": 1,
                    },
                    {
                        "id": "priority-jp-ip-classical",
                        "path": "rules/personal/mihomo/priority-jp-ip-classical.list",
                        "stages": [], "rule_count": 0,
                    },
                ],
                "surge": [],
            },
        }
        aliases = clients._source_aliases(candidate, clients._load_api(ROOT), manifest)
        group_id = clients._resolve_source_reference(
            "rules/personal/mihomo/priority-lan-classical.list", aliases, platform="mihomo",
        )
        replayed = clients._source_rules(candidate, group_id, "mihomo", aliases)
        self.assertEqual([rule.source for rule in replayed], ["fixture"])
        empty_id = clients._resolve_source_reference(
            "rules/personal/mihomo/priority-jp-ip-classical.list", aliases, platform="mihomo",
        )
        self.assertEqual(clients._source_rules(candidate, empty_id, "mihomo", aliases), [])

    def test_old_compact_group_basename_replays_current_group_by_manifest_slot(self):
        candidate = _compact_candidate()
        current = candidate.manifest["compact"]["groups"]["mihomo"][0]
        legacy_group = {
            **current,
            "id": "priority-att-us-classical",
            "slot": current["slot"],
            "path": "rules/personal/mihomo/priority-att-us-classical.mrs",
            "stages": list(current["stages"]),
            "rule_count": 1,
        }
        manifest = {"compact": {"groups": {"mihomo": [legacy_group], "surge": []}}}
        aliases = clients._source_aliases(candidate, clients._load_api(ROOT), manifest)
        source_id = clients._resolve_source_reference(legacy_group["path"], aliases, platform="mihomo")
        replayed = clients._source_rules(candidate, source_id, "mihomo", aliases)
        self.assertEqual([rule.value for rule in replayed], ["att.example"])
        source_ids = clients._group_rule_sources(candidate, aliases.group_sources[source_id], "mihomo")
        self.assertEqual(source_ids, {"fixture"})

    def test_old_compact_membership_count_does_not_limit_current_archived_rules(self):
        candidate = _compact_candidate()
        current = candidate.manifest["compact"]["groups"]["mihomo"][0]
        old_group = {
            **current,
            "path": "rules/personal/mihomo/old-att-us-classical.mrs",
            "rule_count": 316,
        }
        manifest = {"compact": {"groups": {"mihomo": [old_group], "surge": []}}}
        aliases = clients._source_aliases(candidate, clients._load_api(ROOT), manifest)
        source_id = clients._resolve_source_reference(old_group["path"], aliases, platform="mihomo")

        replayed = clients._source_rules(candidate, source_id, "mihomo", aliases)

        self.assertEqual([rule.value for rule in replayed], ["att.example"])

    def test_old_compact_slot_mapping_rejects_semantically_ambiguous_current_groups(self):
        candidate = _compact_candidate()
        current = candidate.manifest["compact"]["groups"]["mihomo"][0]
        physical = next(
            stage for stage in candidate.compact_stages["mihomo"]
            if stage["id"] == current["id"]
        )
        duplicate_id = "att-us-copy"
        duplicate_group = {**current, "id": duplicate_id, "path": "rules/personal/mihomo/att-us-copy.mrs"}
        duplicate_stage = {
            **physical,
            "id": duplicate_id,
            "group_by_platform": {"mihomo": duplicate_id},
        }
        candidate.manifest["compact"]["groups"]["mihomo"].append(duplicate_group)
        candidate.compact_stages["mihomo"].insert(len(candidate.manifest["compact"]["groups"]["mihomo"]) - 1, duplicate_stage)

        old_group = {
            **current,
            "id": "old-att-us",
            "path": "rules/personal/mihomo/old-att-us.mrs",
            "rule_count": 316,
        }
        manifest = {"compact": {"groups": {"mihomo": [old_group], "surge": []}}}
        aliases = clients._source_aliases(candidate, clients._load_api(ROOT), manifest)
        source_id = clients._resolve_source_reference(old_group["path"], aliases, platform="mihomo")

        with self.assertRaisesRegex(clients.ProfileClientsError, "semantically matching current archived group"):
            clients._source_rules(candidate, source_id, "mihomo", aliases)

    def test_report_markdown_discloses_current_archived_source_membership(self):
        rendered = clients.render_report_markdown({
            "source_membership": {
                "basis": "current_archived_inputs",
                "historic_baseline_membership_reconstructed": False,
            },
            "platforms": {},
            "limitations": [
                "Source membership basis is current_archived_inputs: baseline source references resolve to current archived inputs for both old and new configuration order; historical baseline source bytes and membership are not reconstructed.",
            ],
        })
        self.assertIn("current_archived_inputs", rendered)
        self.assertIn("historical baseline source bytes and membership are not reconstructed", rendered)

    def test_v1_manifest_full_github_urls_resolve_exact_platform_group(self):
        candidate = _candidate()
        manifest = {
            "groups": {
                "mihomo": [{
                    "id": "cn-direct-domain",
                    "path": "rules/personal/mihomo/cn-direct-domain.mrs",
                    "stages": ["att-us"], "rule_count": 1,
                }],
                "surge": [{
                    "id": "cn-direct-domain",
                    "path": "rules/personal/surge/cn-direct-domain.set",
                    "stages": ["att-us"], "rule_count": 1,
                }],
            },
        }
        aliases = clients._source_aliases(candidate, clients._load_api(ROOT), manifest)
        expected = "baseline-group:mihomo:cn-direct-domain"
        for url in (
            "https://raw.githubusercontent.com/zesming/ruleset/main/rules/personal/mihomo/cn-direct-domain.mrs",
            "https://github.com/zesming/ruleset/main/rules/personal/mihomo/cn-direct-domain.mrs",
            "https://github.com/zesming/ruleset/raw/refs/heads/main/rules/personal/mihomo/cn-direct-domain.mrs",
        ):
            source_id = clients._resolve_source_reference(url, aliases, platform="mihomo")
            self.assertEqual(source_id, expected)
            replayed = clients._source_rules(candidate, source_id, "mihomo", aliases)
            self.assertEqual([(rule.platform, rule.value) for rule in replayed], [("mihomo", "att.example")])

    def test_mihomo_resolver_fragments_normalize_retired_groups_and_reject_dangling_tags(self):
        targets = {"🌐 基础出口", "US Smart", "JP Smart", "TEST pool", "⏩️ 直连访问"}
        for interface in ("br-lan", "pppoe-wan"):
            endpoint = "https://dns.example/query#" + interface
            self.assertEqual(clients._normalize_resolver_target(endpoint, targets), endpoint)
        for unknown in ("unknown-us-policy", "unknown-jp-policy", "unknown-test-policy"):
            with self.assertRaises(clients.ProfileClientsError):
                clients._normalize_resolver_target("https://dns.example/query#" + unknown, targets)
        for fragment, expected in (
            ("REJECT&JP", "REJECT&🇯🇵 JP"),
            ("unknown-us-policy&br-lan", "unknown-us-policy&br-lan"),
            ("unknown%26JP%20Smart", "unknown&🇯🇵 JP"),
            ("h3%3Dtrue&US", "h3=true&🇺🇸 US"),
            ("ecs=value%2526&US", "ecs=value%2526&🇺🇸 US"),
        ):
            self.assertEqual(
                clients._normalize_resolver_target("https://dns.example/query#" + fragment, targets),
                "https://dns.example/query#" + expected,
            )
        with self.assertRaises(clients.ProfileClientsError):
            clients._normalize_resolver_target("https://dns.example/query#h3", targets)
        normalized = clients._normalize_resolver_target(
            ["https://8.8.8.8/dns-query#🌐 基础出口", "https://1.1.1.1/dns-query#US Smart"],
            targets,
        )
        self.assertEqual(normalized, [
            "https://8.8.8.8/dns-query#🇺🇸 US",
            "https://1.1.1.1/dns-query#🇺🇸 US",
        ])
        self.assertEqual(
            clients._normalize_resolver_target("https://dns.example/query#⏩️ 直连访问", targets),
            "https://dns.example/query#🚀 Direct",
        )
        self.assertEqual(
            clients._normalize_resolver_target(
                [
                    "https://dns.example/query#US Smart&h3=true",
                    "https://dns.example/query#h3=true&JP Smart",
                    "https://dns.example/query#eth0",
                    "https://dns.example/query#RULES&h3=true",
                    "https://dns.example/query#h3=true",
                ],
                targets,
            ),
            [
                "https://dns.example/query#🇺🇸 US&h3=true",
                "https://dns.example/query#h3=true&🇯🇵 JP",
                "https://dns.example/query#eth0",
                "https://dns.example/query#RULES&h3=true",
                "https://dns.example/query#h3=true",
            ],
        )
        with self.assertRaisesRegex(clients.ProfileClientsError, "unknown policy target"):
            clients._normalize_resolver_target("https://8.8.8.8/dns-query#deleted-group", targets)
        with self.assertRaisesRegex(clients.ProfileClientsError, "non-egress policy"):
            reject_targets = clients._known_policy_targets("mihomo", {
                "proxy-groups": [{"name": "⛔️ Reject", "proxies": ["REJECT"]}],
            })
            clients._normalize_resolver_target(
                "https://8.8.8.8/dns-query#⛔️ Reject",
                reject_targets,
            )

    def test_mihomo_external_provider_and_retained_dns_fields_use_display_targets(self):
        config = {
            "proxies": [
                {"name": "US node", "type": "tuic", "server": "us.example.net"},
                {"name": "JP node", "type": "tuic", "server": "jp.example.net"},
            ],
            "proxy-groups": [],
            "rule-providers": {
                "external-dns": {
                    "type": "http", "behavior": "domain", "format": "text",
                    "url": "https://external.example/rules.list", "path": "./external.list",
                    "interval": 43200, "proxy": "JP",
                },
            },
            "dns": {
                "nameserver-policy": {
                    "rule-set:external-dns": ["https://dns.example/policy#JP"],
                },
                "fallback": [
                    "https://dns.example/fallback#US&h3=true",
                    "https://dns.example/fallback#h3=true&JP",
                    "https://dns.example/interface#eth0",
                    "https://dns.example/rules#RULES&h3=true",
                ],
                "proxy-server-nameserver": ["https://dns.example/proxy#JP"],
                "direct-nameserver": ["https://dns.example/direct#DIRECT"],
                "default-nameserver": ["https://dns.example/bootstrap#US"],
                "proxy-server-nameserver-policy": {
                    "node.example": ["https://dns.example/node-policy#JP"],
                },
                "fake-ip-filter": [],
            },
        }
        clients._set_mihomo_providers(config, _candidate(), "https://example.invalid/ref", ROOT)
        self.assertEqual(config["rule-providers"]["external-dns"]["proxy"], "🇯🇵 JP")
        self.assertEqual(config["dns"]["nameserver-policy"]["rule-set:external-dns"], [
            "https://dns.example/policy#🇯🇵 JP",
        ])
        self.assertEqual(config["dns"]["fallback"], [
            "https://dns.example/fallback#🇺🇸 US&h3=true",
            "https://dns.example/fallback#h3=true&🇯🇵 JP",
            "https://dns.example/interface#eth0",
            "https://dns.example/rules#RULES&h3=true",
        ])
        self.assertEqual(config["dns"]["proxy-server-nameserver"], ["https://dns.example/proxy#🇯🇵 JP"])
        self.assertEqual(config["dns"]["direct-nameserver"], ["https://dns.example/direct#🚀 Direct"])
        self.assertEqual(config["dns"]["default-nameserver"], ["https://dns.example/bootstrap#🇺🇸 US"])
        self.assertEqual(config["dns"]["proxy-server-nameserver-policy"], {
            "node.example": ["https://dns.example/node-policy#🇯🇵 JP"],
        })

    def test_not_covered_case_is_counted_separately_from_archive_evidence(self):
        report = {"platforms": {"mihomo": {
            "independent_case_evidence_counts": {},
            "independent_case_evidence_status_counts": {},
        }}}
        clients._count_independent_evidence(report, "mihomo", "archive", status="not-covered")
        self.assertEqual(report["platforms"]["mihomo"]["independent_case_evidence_counts"], {"not-covered": 1})
        self.assertEqual(report["platforms"]["mihomo"]["independent_case_evidence_status_counts"], {"archive": {"not-covered": 1}})


if __name__ == "__main__":
    unittest.main()
