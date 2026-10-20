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
        self.assertIn("AND,((PROTOCOL,DOH),(DOMAIN,8.8.8.8)),🇺🇸 US", rendered)
        self.assertIn("AND,((PROTOCOL,DOH),(DOMAIN,1.0.0.1)),🇯🇵 JP", rendered)
        self.assertIn("FINAL,🇺🇸 US,dns-failed", rendered)
        self.assertNotIn("[Proxy]", rendered)
        self.assertNotIn("[Proxy Group]", rendered)
        self.assertNotIn("uuid=", rendered)
        self.assertNotIn("password=", rendered)


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
            "RULE-SET,att-us,US,no-resolve",
            "GEOIP,CN,DIRECT,no-resolve",
            "RULE-SET,domestic-ip,DIRECT,no-resolve",
            "MATCH,US",
        ]
        positions = [route_section.index(value) for value in expected]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(route_section.count("MATCH,US"), 1)
        self.assertIn("enhanced-mode: fake-ip", rendered)

    def test_surge_emits_doh_node_policy_then_geoip_then_final(self):
        rendered = clients.render_surge_snippet(_candidate(), "https://example.invalid/ref")
        rules = rendered.split("[Rule]\n", 1)[1].split("\n[Host]", 1)[0].splitlines()
        expected = [
            "AND,((PROTOCOL,DOH),(DOMAIN,8.8.8.8)),🇺🇸 US",
            "DOMAIN-SET,https://example.invalid/ref/rules/personal/surge/att-us.set,🇺🇸 US,no-resolve,update-interval=43200",
            "GEOIP,CN,DIRECT,no-resolve",
            "DOMAIN-SET,https://example.invalid/ref/rules/personal/surge/domestic-ip.set,DIRECT,no-resolve,update-interval=43200",
            "FINAL,🇺🇸 US,dns-failed",
        ]
        positions = [rules.index(value) for value in expected]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(sum(line.startswith("FINAL,") for line in rules), 1)
        self.assertTrue(all("AND,((PROTOCOL,DOH)" in line for line in rules if line.startswith("AND,")))

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
        self.assertIn("https://223.5.5.5/dns-query#DIRECT", mihomo)
        surge = clients.render_surge_snippet(candidate, "https://example.invalid/ref")
        routes = surge.split("[Rule]\n", 1)[1].split("\n[Host]", 1)[0]
        self.assertLess(routes.index("/rules/personal/surge/domestic-ip.set"), routes.index("/rules/personal/surge/att-us.set"))

    def test_test_doh_endpoint_has_a_distinct_test_policy(self):
        test_group = {"id": "network-test", "action": "TEST", "dns": "test"}
        jp_group = {"id": "jp", "action": "JP", "dns": "jp"}
        self.assertEqual(clients._dns_endpoints(test_group, "mihomo"), ("https://8.8.4.4/dns-query#TEST",))
        self.assertEqual(clients._dns_endpoints(jp_group, "surge"), ("https://1.0.0.1/dns-query",))
        self.assertTrue(clients._surge_endpoint_rules()[-1].endswith(")),TEST"))
        self.assertEqual(clients._resolver_class("https://8.8.4.4/dns-query", "RULE-SET:test"), "TEST")

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
            "DOMAIN,proxy.example.net,DIRECT",
            "IP-CIDR,203.0.113.8/32,DIRECT,no-resolve",
        ])


class CanonicalGroupTests(unittest.TestCase):
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
        expected_us = {**us, "name": "US"}
        expected_us.pop("fast-open")
        clients._canonical_mihomo_groups(config, jp)
        self.assertEqual([item["name"] for item in config["proxy-groups"]], ["TEST"])
        self.assertEqual(config["proxy-groups"][0], {
            "name": "TEST", "type": "select", "proxies": ["US", "JP", "DIRECT"],
        })
        self.assertEqual(len(config["proxies"]), 2)
        self.assertEqual(config["proxies"][0], expected_us)
        self.assertEqual(config["proxies"][1], {
            **jp, "name": "JP", "congestion-controller": "bbr",
            "heartbeat-interval": 8000, "disable-sni": False, "udp-relay-mode": "native",
        })
        self.assertEqual(config["proxies"][0]["sni"], "us.sni.example")
        self.assertEqual(config["proxies"][1]["sni"], "jp.sni.example")
        clients._canonical_mihomo_groups(config, jp)
        self.assertEqual([item["name"] for item in config["proxy-groups"]], ["TEST"])

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
            "TEST = select, 🇺🇸 US, 🇯🇵 JP, DIRECT",
        ])
        self.assertNotIn("include-other-group", "\n".join(lines))

    def test_surge_tuic_rename_preserves_entire_proxy_rhs(self):
        _, sections = clients._surge_sections(
            "[Proxy]\nUS node = tuic-v5, us.example, 443, uuid=u, password=p, alpn=h3, tfo=true\n"
            "JP node = tuic-v5, jp.example, 443, uuid=j, password=q, alpn=h3, tfo=false\n"
            "US Snell = snell, us-snell.example, 443, psk=s, version=6\n"
            "JP Snell = snell, jp-snell.example, 443, psk=t, version=6\n"
            "[Proxy Group]\nTEST pool = select, US node, JP node, DIRECT\n"
        )
        before = [line.split("=", 1)[1] for line in sections[0].lines]
        entries = clients._canonical_surge_proxy_names(sections)
        after = [line.split("=", 1)[1] for line in sections[0].lines]
        self.assertEqual([item[0] for item in entries], ["🇺🇸 TUIC", "🇯🇵 TUIC", "🇺🇸 Snell", "🇯🇵 Snell"])
        self.assertEqual(after, before)

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
            "TEST = select, 🇺🇸 US, 🇯🇵 JP, DIRECT",
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
        self.assertIn("TEST = select, 🇺🇸 US, 🇯🇵 JP, DIRECT", rendered)
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
        self.assertIn("DOMAIN,us.example.net,DIRECT", rendered)


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
            "stages": [],
            "rule_count": 1,
        }
        manifest = {"compact": {"groups": {"mihomo": [legacy_group], "surge": []}}}
        aliases = clients._source_aliases(candidate, clients._load_api(ROOT), manifest)
        source_id = clients._resolve_source_reference(legacy_group["path"], aliases, platform="mihomo")
        replayed = clients._source_rules(candidate, source_id, "mihomo", aliases)
        self.assertEqual([rule.value for rule in replayed], ["att.example"])
        source_ids = clients._group_rule_sources(candidate, aliases.group_sources[source_id], "mihomo")
        self.assertEqual(source_ids, {"fixture"})

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
        targets = {"🌐 基础出口", "US Smart", "TEST pool", "⏩️ 直连访问"}
        normalized = clients._normalize_resolver_target(
            ["https://8.8.8.8/dns-query#🌐 基础出口", "https://1.1.1.1/dns-query#US Smart"],
            targets,
        )
        self.assertEqual(normalized, [
            "https://8.8.8.8/dns-query#US",
            "https://1.1.1.1/dns-query#US",
        ])
        self.assertEqual(
            clients._normalize_resolver_target("https://dns.example/query#⏩️ 直连访问", targets),
            "https://dns.example/query#DIRECT",
        )
        with self.assertRaisesRegex(clients.ProfileClientsError, "unknown policy target"):
            clients._normalize_resolver_target("https://8.8.8.8/dns-query#deleted-group", targets)

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
