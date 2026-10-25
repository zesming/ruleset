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


class RendererOrderTests(unittest.TestCase):

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


class RendererOutputTests(unittest.TestCase):


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


    @unittest.skipUnless(shutil.which("ruby"), "system Ruby YAML parser is unavailable")
    def test_public_mihomo_snippet_parses_as_yaml(self):
        rendered = clients.render_mihomo_snippet(_candidate(), "https://example.invalid/ref")
        check = "require 'yaml'; YAML.safe_load(STDIN.read, aliases: true); puts 'ok'"
        result = subprocess.run(["ruby", "-e", check], input=rendered, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "ok")


if __name__ == "__main__":
    unittest.main()
