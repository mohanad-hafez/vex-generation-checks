---
on:
  push:
    branches: [matched-vex-agent-01]

description: >
  Auto-generates an OpenVEX statement for a dismissed Dependabot alert.
  Provide the alert details as inputs — the agent generates a standards-compliant
  OpenVEX document and opens a PR.

permissions:
  copilot-requests: write
  contents: read
  issues: read
  pull-requests: read
  security-events: read

env:
  ALERT_NUMBER: "5"
  ALERT_GHSA_ID: "GHSA-9wv6-86v2-598j"
  ALERT_CVE_ID: "CVE-2024-45296"
  ALERT_PACKAGE: "path-to-regexp"
  ALERT_ECOSYSTEM: "npm"
  ALERT_SEVERITY: "high"
  ALERT_SUMMARY: "path-to-regexp outputs backtracking regular expressions"
  ALERT_DISMISSED_REASON: "not_used"

tools:
  bash: true
  edit:

safe-outputs:
  create-pull-request:
    base-branch: matched-vex-base-01
    allowed-files: [".vex/*.json", ".vex/README.md"]
    title-prefix: "[VEX] "
    labels: [vex, automated]
    draft: false

timeout-minutes: 10
max-ai-credits: 20
engine:
  id: copilot
---

# Auto-Generate OpenVEX Statement on Dependabot Alert Dismissal

You are a security automation agent. When a Dependabot alert is dismissed, you generate a standards-compliant OpenVEX statement documenting why the vulnerability does not affect this project.

## Context

VEX (Vulnerability Exploitability eXchange) is a standard for communicating that a software product is NOT affected by a known vulnerability. When maintainers dismiss Dependabot alerts, they're making exactly this kind of assessment — but today that knowledge is lost. This workflow captures it in a machine-readable format.

The OpenVEX specification: https://openvex.dev/

## Your Task

### Step 1: Get the Dismissed Alert Details

All alert details are available as environment variables. Read them with bash:

```bash
echo "Alert #: $ALERT_NUMBER"
echo "GHSA ID: $ALERT_GHSA_ID"
echo "CVE ID: $ALERT_CVE_ID"
echo "Package: $ALERT_PACKAGE"
echo "Ecosystem: $ALERT_ECOSYSTEM"
echo "Severity: $ALERT_SEVERITY"
echo "Summary: $ALERT_SUMMARY"
echo "Dismissed reason: $ALERT_DISMISSED_REASON"
```

The repository is `${{ github.repository }}`.

Verify all required fields are present before proceeding. Also read the package.json (or equivalent manifest) to get this project's version number.

### Step 2: Map Dismissal Reason to VEX Status

Map the Dependabot dismissal reason to an OpenVEX status and justification:

| Dependabot Dismissal | VEX Status | VEX Justification |
|---|---|---|
| `not_used` | `not_affected` | `vulnerable_code_not_present` |
| `inaccurate` | `not_affected` | `vulnerable_code_not_in_execute_path` |
| `tolerable_risk` | `not_affected` | `inline_mitigations_already_exist` |
| `no_bandwidth` | `under_investigation` | *(none - this is not a VEX-worthy dismissal)* |

**Important**: If the dismissal reason is `no_bandwidth`, do NOT generate a VEX statement. Instead, skip and post a comment explaining that "no_bandwidth" dismissals don't represent a security assessment and therefore shouldn't generate VEX statements.

### Step 3: Determine Package URL (purl)

Construct a valid Package URL (purl) for the affected product. The purl format depends on the ecosystem:

- npm: `pkg:npm/<package>@<version>`
- PyPI: `pkg:pypi/<package>@<version>`
- Maven: `pkg:maven/<group>/<artifact>@<version>`
- RubyGems: `pkg:gem/<package>@<version>`
- Go: `pkg:golang/<module>@<version>`
- NuGet: `pkg:nuget/<package>@<version>`

Use the repository's own package version from its manifest file (package.json, setup.py, go.mod, etc.) as the product version.

### Step 4: Generate the OpenVEX Document

Create a valid OpenVEX JSON document following the v0.2.0 specification:

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://github.com/<owner>/<repo>/vex/<ghsa-id>",
  "author": "GitHub Agentic Workflow <vex-generator@github.com>",
  "role": "automated-tool",
  "timestamp": "<current ISO 8601 timestamp>",
  "version": 1,
  "tooling": "GitHub Agentic Workflows (gh-aw) VEX Generator",
  "statements": [
    {
      "vulnerability": {
        "@id": "<GHSA or CVE ID>",
        "name": "<CVE ID if available>",
        "description": "<brief vulnerability description>"
      },
      "products": [
        {
          "@id": "<purl of this package>"
        }
      ],
      "status": "<mapped VEX status>",
      "justification": "<mapped VEX justification>",
      "impact_statement": "<human-readable explanation combining the dismissal reason and any maintainer comment>"
    }
  ]
}
```

### Step 5: Write the VEX File

Save the OpenVEX document to `.vex/<ghsa-id>.json` in the repository.

If the `.vex/` directory doesn't exist yet, create it. Also create or update a `.vex/README.md` explaining the VEX directory:

```markdown
# VEX Statements

This directory contains [OpenVEX](https://openvex.dev/) statements documenting
vulnerabilities that have been assessed and determined to not affect this project.

These statements are auto-generated when Dependabot alerts are dismissed by
maintainers, capturing their security assessment in a machine-readable format.

## Format

Each file is a valid OpenVEX v0.2.0 JSON document that can be consumed by
vulnerability scanners and SBOM tools to reduce false positive alerts for
downstream consumers of this package.
```

### Step 6: Create a Pull Request

Create a pull request with:
- Title: `Add VEX statement for <CVE-ID> (<package name>)`
- Body explaining:
  - Which vulnerability was assessed
  - The maintainer's dismissal reason
  - What VEX status was assigned and why
  - A note that this is auto-generated and should be reviewed
  - Link to the original Dependabot alert

Use the `create-pull-request` safe output to create the PR.

## Important Notes

- Always validate that the generated JSON is valid before creating the PR
- Use clear, descriptive impact statements — these will be consumed by downstream users
- If multiple alerts are dismissed at once, handle each one individually
- The VEX document should be self-contained and not require external context to understand
