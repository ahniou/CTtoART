# CTtoART

**From threat intelligence to executable adversary emulation in one command.**

`CTtoART` is a Python utility that connects to a self-hosted
[OpenCTI](https://www.filigran.io/en/products/opencti/) platform, extracts the
MITRE ATT&CK techniques associated with a chosen Threat Actor, Intrusion Set,
Malware family, or Campaign, and emits ready-to-run
[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) execution
scripts. The output is intentionally easy to ingest by Red Team operators or
purple-team automation pipelines, making it a foundational building block for
a Continuous Threat Exposure Management (CTEM) workflow.

```
+-----------+       +---------------+       +---------------------+
|  OpenCTI  |  -->  |   CTtoART     |  -->  |  Atomic Red Team    |
| (STIX 2.1)|       | (this repo)   |       |  Invoke-AtomicTest  |
+-----------+       +---------------+       +---------------------+
       Threat Intelligence       Mapping +              Validated
                                 Generation             Telemetry
```

## Features

- Targets Threat Actors, Intrusion Sets, Malware, and Campaigns in OpenCTI by name.
- Walks `uses` relationships to enumerate every linked Attack Pattern and reads `x_mitre_id`.
- Maps ATT&CK technique IDs against the official Atomic Red Team CSV index.
- Emits per-technique `.ps1` scripts (and `.sh` wrappers when applicable) plus
  consolidated batch scripts.
- Produces a `manifest.json` per target for traceability and downstream automation.
- Logs and gracefully skips techniques without an ART mapping.
- Robust error handling: network timeouts, expired tokens, malformed STIX,
  missing local atomics, OpenCTI API filter incompatibilities.

## Repository Layout

```
.
|-- cti_to_art.py          # Main script (entry point)
|-- requirements.txt       # Python dependencies
|-- .env.example           # Environment variable template
|-- targets.example.json   # Optional batch target file
|-- validation_plan.md     # OpenCTI -> ART validation playbook
|-- README.md              # This file
`-- output/                # Generated artefacts (git-ignored)
    `-- <target_slug>/
        |-- manifest.json
        |-- by_technique/
        |   |-- T1059.001.ps1
        |   `-- T1059.004.sh
        `-- consolidated/
            `-- <target_slug>_all.ps1
```

## Prerequisites

| Component | Minimum version | Purpose |
|-----------|-----------------|---------|
| Python | 3.9+ | Runs the generator |
| OpenCTI | 5.12+ | Source of intelligence (older releases use the relationship-traversal fallback) |
| `pycti` | 6.2+ | Python client for OpenCTI |
| Atomic Red Team | latest | Source of test definitions (cloned locally or fetched on demand) |
| PowerShell | 5.1 (Windows) / 7+ (cross-platform) | Required on the target host to run `Invoke-AtomicTest` |
| `Invoke-AtomicRedTeam` module | latest | Test runner installed on the target host |

> **Note on scope.** This tool is intended for authorised security testing,
> CTEM/Purple Team programs, and lab-based detection engineering. Do not run
> generated artefacts against systems you do not own or have explicit written
> permission to test.

## Installation

```bash
git clone https://github.com/ahniou/CTtoART.git
cd CTtoART

python -m venv .venv
source .venv/bin/activate           # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env
chmod 600 .env                      # restrict the secrets file
```

Edit `.env` with the URL of your OpenCTI deployment and a service-account
token. Optionally set `ATOMICS_PATH` to an existing Atomic Red Team checkout:

```bash
git clone https://github.com/redcanaryco/atomic-red-team.git /opt/atomic-red-team
echo "ATOMICS_PATH=/opt/atomic-red-team" >> .env
```

If you cannot stage the atomics locally, set `ART_ALLOW_REMOTE=true` to fetch
the index CSV from GitHub on each run.

## Configuration

All configuration is driven by environment variables (loaded automatically
from `.env`). CLI flags override environment defaults.

| Variable | Required | Description |
|----------|----------|-------------|
| `OPENCTI_URL` | yes | Base URL of the OpenCTI platform (no trailing slash). |
| `OPENCTI_TOKEN` | yes | API token; the service account only needs the `KNOWLEDGE` capability. |
| `ATOMICS_PATH` | recommended | Path to the local atomic-red-team checkout, or directly to `index.csv`. |
| `ART_ALLOW_REMOTE` | optional | `true` to fetch the ART index from GitHub when no local copy exists. |

## Usage

### Single target

```bash
python cti_to_art.py --intrusion-set "APT29" --output ./output
```

### Multiple targets in one run

```bash
python cti_to_art.py \
  --threat-actor "FIN7" \
  --malware "Emotet" \
  --campaign "Operation Dream Job" \
  --output ./output
```

### Batch via JSON file

```bash
cp targets.example.json targets.json
# edit targets.json
python cti_to_art.py --targets-file targets.json --output ./output
```

### Air-gapped environments

```bash
python cti_to_art.py \
  --intrusion-set "APT29" \
  --atomics-path /opt/atomic-red-team \
  --output ./output
```

### Useful flags

```
--threat-actor NAME      Repeatable; resolves a Threat-Actor SDO by name.
--intrusion-set NAME     Repeatable; resolves an Intrusion-Set SDO by name.
--malware NAME           Repeatable; resolves a Malware SDO by name.
--campaign NAME          Repeatable; resolves a Campaign SDO by name.
--targets-file PATH      JSON file with grouped targets (see targets.example.json).
--output DIR             Output root directory (default: ./output).
--atomics-path PATH      Local atomic-red-team checkout or index.csv.
--allow-remote-art       Fetch the ART index from GitHub on demand.
--remote-art-url URL     Override the upstream URL (use a private mirror in restricted networks).
--insecure               Disable TLS verification when contacting OpenCTI (lab use only).
--log-level LEVEL        DEBUG / INFO / WARNING / ERROR (default: INFO).
```

## Output Format

For each processed target the script creates a directory named after a
slugified version of the input name, for example `output/APT29/`:

- `manifest.json` - structured summary of every technique, the ART tests
  attached to it, and any skip reasons. Suitable for downstream automation.
- `by_technique/T<technique>.ps1` - PowerShell script that runs every
  matching atomic test using `Invoke-AtomicTest`, including a prereq stage
  and a commented cleanup line.
- `by_technique/T<technique>.sh` - generated when at least one matching
  executor is `sh` or `bash`. Wraps `pwsh -Command "Invoke-AtomicTest ..."`.
- `consolidated/<target>_all.ps1` (and `.sh` if applicable) - single file
  combining every technique for the target.

Each generated script includes a header comment with the OpenCTI target
metadata, generation timestamp, and a reminder to run only in authorised
environments.

## CTEM Workflow Integration

1. **Discover** - Curate intelligence for an actor/campaign in OpenCTI.
2. **Generate** - Run `cti_to_art.py` to materialise ART artefacts.
3. **Validate** - Follow `validation_plan.md` (Phases 1 - 3) to test mapping
   accuracy, then execute the artefacts on lab endpoints.
4. **Mobilise** - Feed detection gaps back into the Detection-as-Code
   repository and re-prioritise CTI collection accordingly.
5. **Repeat** - Re-run the pipeline whenever OpenCTI intelligence or the
   Atomic Red Team index changes materially.

## Validation

A complete validation playbook lives in [`validation_plan.md`](./validation_plan.md).
It covers:

- Phase 1 - API connection and privilege validation, including STIX shape
  checks and least-privilege RBAC verification.
- Phase 2 - Mapping accuracy review, with a four-tier sampling strategy that
  protects against silent ART or OpenCTI drift.
- Phase 3 - Endpoint execution and defensive visibility validation, with a
  reusable purple-team coverage matrix.

## Troubleshooting

| Symptom | Resolution |
|---------|------------|
| `pycti is not installed` | Activate the venv and `pip install -r requirements.txt`. |
| `OPENCTI_URL and OPENCTI_TOKEN must be set` | Populate `.env` (or export them) and rerun. |
| `Failed to download ART index` | Provide a local `ATOMICS_PATH` or whitelist `raw.githubusercontent.com`. |
| `No OpenCTI entity matched name=...` | Use the canonical OpenCTI alias; check Threat-Actor vs Intrusion-Set typing. |
| `Attack pattern query via regardingOf failed` | OpenCTI < 5.12; the script automatically falls back to relationship traversal. |

## Security Notes

- `.env` should be `chmod 600` and **must not** be committed (already in `.gitignore`).
- Tokens should be rotated on the same cadence as other privileged secrets.
- Generated scripts execute real adversary techniques and must only be run on
  endpoints you control and have authorisation to test.
- Take a snapshot before running any persistence- or defence-evasion test.

## License

Distributed under the MIT License unless otherwise noted at the repository root.
Copyright AUO Corporation(auo.com)
