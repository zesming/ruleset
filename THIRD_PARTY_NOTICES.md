# Third-party sources

The repository's own scripts, tests and documentation are licensed under AGPL-3.0 (see `LICENSE`). Third-party rule data and license texts retain their original notices and terms; they are not presented as original work or relicensed merely by being included here.

| Material | Upstream | Original license copy |
|---|---|---|
| Expanded AI domain lists, including upstream attribution | [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat) | [GPL-3.0](licenses/MetaCubeX-GPL-3.0.txt) |
| Underlying domain classification data in Meta's source chain | [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community) | [MIT](licenses/v2fly-MIT.txt) |
| Fixed Public Suffix List validation snapshot (not a routing provider) | [publicsuffix/list](https://publicsuffix.org/list/) | [MPL-2.0](licenses/PublicSuffix-MPL-2.0.txt) |
| ChinaMax Domain input and aggregated domestic domains | [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script) | [GPL-2.0](licenses/ChinaMax-GPL-2.0.txt) |
| Sukka direct/domestic rule inputs and the four explicitly retained routing expressions for `ai.com`, `g.ai`, `api.github.com`, `cloudcode-pa.googleapis.com` | [SukkaW/Surge](https://github.com/SukkaW/Surge) | [AGPL-3.0](licenses/Sukka-AGPL-3.0.txt) |
| ACL4SSR ChinaDomain input, reviewed incremental domains, and historical compatibility entries `ai.azure.com`, `sydney.bing.com`, `api.together.xyz` | [ACL4SSR/ACL4SSR](https://github.com/ACL4SSR/ACL4SSR) | [CC-BY-SA-4.0](licenses/ACL4SSR-CC-BY-SA-4.0.txt) |

Changes made here: normalization and stable ordering; an explicitly registered Azure regex-to-wildcard adaptation; local additions, exclusions and classification overrides from `policy.json`; cross-client text output. The wildcard is deliberately broader than the upstream regex and is not represented as an equivalent conversion. Provenance and exact unmodified input bytes are retained under `upstream/`, with content checksums in `manifest.json`.

Source rule files remain data, never executable instructions. A new input format fails the update instead of silently dropping lines. Existing attribution in downloaded input snapshots is retained. The six domestic rule input snapshots are copied without modification. Domestic aggregation preserves platform expressions in separate outputs, normalizes and removes redundant domain scopes, and excludes unreviewed ACL increments. Original source licenses remain attached to their data.
