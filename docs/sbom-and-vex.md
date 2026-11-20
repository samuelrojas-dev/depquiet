# SBOM and OpenVEX

Writing CycloneDX, SPDX and OpenVEX, and triaging third-party SBOMs.

## SBOM generation (CycloneDX + SPDX)

depquiet generates both major SBOM standards required by US Executive Order 14028:

```bash
# CycloneDX 1.5 (OWASP standard)
depquiet --sbom sbom.json              # CycloneDX JSON
depquiet --sbom sbom.xml               # CycloneDX XML (auto-detected)
depquiet --sbom out.cdx --sbom-format xml

# SPDX 2.3 (ISO/IEC 5962:2021)
depquiet --sbom sbom.spdx.json         # SPDX JSON (auto-detected)
depquiet --sbom out.spdx --sbom-format spdx
```

Both formats include full component inventory with Package URLs (purl), vulnerability references for known CVEs, depquiet triage verdicts, and tool creator metadata. CycloneDX additionally maps verdicts to analysis states; SPDX uses SECURITY external references with NVD links.

SBOM output works alongside all other flags — combine `--sbom` with `--sarif` to generate both in one pass.

## SBOM import — triage from third-party SBOMs

depquiet can consume CycloneDX and SPDX SBOMs as input, enabling triage on third-party SBOMs from vendors, container registries, or build systems — without needing the original lockfile:

```bash
# Explicit file input
depquiet --from-sbom vendor-sbom.cdx.json    # CycloneDX 1.4/1.5 JSON
depquiet --from-sbom vendor-sbom.spdx.json   # SPDX 2.3 JSON

# Piped via stdin (auto-detected)
cat container-sbom.json | depquiet --stdin
```

Two-mode operation:
- **Vulnerability mode** — if the SBOM contains vulnerability data (CycloneDX `vulnerabilities` array or SPDX SECURITY external refs), those are extracted and triaged directly
- **Package mode** — if no vulnerability data is present, the package inventory is extracted and queried against OSV.dev for known advisories

An inventory-only SBOM cannot be scanned with `--offline`. Missing packages or a failed
OSV.dev lookup produce "nothing scanned" and exit code `2`, rather than a clean report.

All standard depquiet flags work with SBOM input: `--epss-threshold`, `--kev`, `--sbom` (re-export), `--sarif`, `--html`, etc.

## OpenVEX documents (`--vex`)

Generate [OpenVEX](https://openvex.dev) documents that communicate the exploitability status of every vulnerability in your project. VEX (Vulnerability Exploitability eXchange) is the CISA-recommended format for telling downstream consumers which CVEs actually affect your software — and which don't.

```bash
# Generate an OpenVEX document
depquiet --vex vex.json
```

Priority and product impact are separate. The current engine observes dependency
relationships and imports; it does not prove vulnerable-function execution or
product-specific mitigations. Automatic exports preserve this uncertainty:

| Output | Automatic impact state | Priority and context |
|---|---|---|
| OpenVEX | `under_investigation` | `status_notes` contains priority, observations and limits |
| CycloneDX JSON/XML | `in_triage` | `analysis.detail` and per-component `depquiet:triage` properties |
| Scan JSON | `assessment.status: under_investigation` | Existing `verdict`, plus `evidence` and `decision_trace` |

A low EPSS, dev-only metadata, baseline, ignore or policy match never becomes an
automatic `not_affected` claim. The existing remediation priorities and exit-code
policy remain available. See the [assessment contract](https://github.com/samuelrojas-dev/depquiet/blob/main/docs/assessment-contract.md).

The output is consumable by policy engines like Sigstore's policy-controller and OPA/Gatekeeper to gate container deployments.

```yaml
# In the GitHub Action
- uses: samuelrojas-dev/depquiet@v1
  with:
    vex: depquiet-vex.json
```
