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

    def test_comparison_projects_surge_only_reject_variant_to_actual_mihomo_policy(self):
        result = SimpleNamespace(stage={"id": "reject-no-drop"}, action="REJECT", reject_mode="no-drop", rule=_rule("mihomo", "DOMAIN", "blocked.example"))
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
            "AND,((PROTOCOL,DOH),(DOMAIN,8.8.8.8)),US",
            "DOMAIN-SET,https://example.invalid/ref/rules/personal/surge/att-us.set,US,no-resolve,update-interval=43200",
            "GEOIP,CN,DIRECT,no-resolve",
            "DOMAIN-SET,https://example.invalid/ref/rules/personal/surge/domestic-ip.set,DIRECT,no-resolve,update-interval=43200",
            "FINAL,US,dns-failed",
        ]
        positions = [rules.index(value) for value in expected]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(sum(line.startswith("FINAL,") for line in rules), 1)
        self.assertTrue(all("AND,((PROTOCOL,DOH)" in line for line in rules if line.startswith("AND,")))

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
    def test_mihomo_keeps_only_fixed_country_groups_and_flat_test_selector(self):
        jp = {"name": "JP TUIC", "type": "tuic", "server": "jp.example", "port": 443}
        config = {
            "proxies": [
                {"name": "US TUIC", "type": "tuic", "server": "us.example", "port": 443},
                {"name": "US Snell", "type": "snell", "server": "us-snell.example", "port": 443},
            ],
            "proxy-groups": [
                {"name": "US Smart", "type": "url-test", "proxies": ["US TUIC", "US Snell"]},
                {"name": "JP Smart", "type": "url-test", "proxies": ["JP TUIC"]},
                {"name": "Mixed Smart", "type": "url-test", "proxies": ["US Smart", "JP Smart"]},
                {"name": "TEST pool", "type": "select", "proxies": ["Mixed Smart", "DIRECT"]},
            ],
        }
        clients._canonical_mihomo_groups(config, jp)
        groups = {item["name"]: item for item in config["proxy-groups"]}
        self.assertEqual(set(groups), {"US", "JP", "TEST"})
        self.assertEqual(groups["US"]["proxies"], ["US TUIC"])
        self.assertEqual(groups["JP"]["proxies"], ["JP TUIC"])
        self.assertEqual(groups["TEST"]["proxies"][0], "US")
        self.assertTrue(set(groups["TEST"]["proxies"]).issubset({"US", "US TUIC", "US Snell", "JP TUIC", "DIRECT"}))

    def test_surge_groups_have_same_country_smart_and_no_cross_country_aliases(self):
        section = clients.SurgeSection("Proxy Group", "[Proxy Group]", [
            "US Smart = smart, US TUIC, US Snell, interval=300",
            "JP Smart = smart, JP TUIC, JP Snell, interval=300",
            "Mixed Smart = smart, US Smart, JP Smart",
            "Test pool = select, Mixed Smart, JP TUIC, 🚀 Direct",
        ])
        proxy_entries = [
            ("US TUIC", "tuic-v5", ["tuic-v5", "us.example", "443"]),
            ("US Snell", "snell", ["snell", "us-snell.example", "443"]),
            ("JP TUIC", "tuic-v5", ["tuic-v5", "jp.example", "443"]),
            ("JP Snell", "snell", ["snell", "jp-snell.example", "443"]),
        ]
        lines = clients._surge_group_aliases(section, proxy_entries)
        self.assertEqual(len(lines), 5)
        self.assertTrue(lines[0].startswith("US Smart = smart,"))
        self.assertTrue(lines[1].startswith("JP Smart = smart,"))
        self.assertIn("US = select, US Smart", lines)
        self.assertIn("JP = select, JP Smart", lines)
        test_line = next(line for line in lines if line.startswith("TEST ="))
        self.assertIn("US,", test_line)
        self.assertIn("DIRECT", test_line)
        self.assertNotIn("Mixed Smart", test_line)
        self.assertNotIn("US Smart, JP Smart", "\n".join(lines))

    def test_surge_dynamic_group_membership_options_fail_closed(self):
        section = clients.SurgeSection("Proxy Group", "[Proxy Group]", [
            "US Smart = smart, US TUIC, include-other-group=JP Smart",
            "JP Smart = smart, JP TUIC",
            "Test pool = select, US Smart, DIRECT",
        ])
        proxy_entries = [
            ("US TUIC", "tuic-v5", ["tuic-v5", "us.example", "443"]),
            ("JP TUIC", "tuic-v5", ["tuic-v5", "jp.example", "443"]),
        ]
        with self.assertRaisesRegex(clients.ProfileClientsError, "dynamic membership"):
            clients._surge_group_aliases(section, proxy_entries)


class LegacyDnsSelectorTests(unittest.TestCase):
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
