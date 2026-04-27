# OpenCTI Intelligence Integration and ART Trigger Validation Plan

## 1. Purpose and Scope

This validation plan ensures that the `CTtoART` toolchain reliably converts
threat intelligence held in OpenCTI into Atomic Red Team (ART) execution
artefacts, and that the resulting attacks generate the expected detection
telemetry inside our defensive stack. The plan is structured around three
phases that mirror the Continuous Threat Exposure Management (CTEM) loop:
*Discover* (Phase 1), *Prioritise* (Phase 2), and *Validate* (Phase 3).

| Phase | Goal | Owner | Cadence |
|-------|------|-------|---------|
| 1. API Connection & Privilege Validation | Prove that `pycti` can authenticate and retrieve correctly shaped STIX 2.1 objects. | CTI Engineering | Every release / quarterly token rotation |
| 2. Intelligence Mapping Accuracy | Prove that the OpenCTI -> ART mapping is faithful and free of false positives. | Threat Modelling Lead + Red Team | Per intelligence package |
| 3. Endpoint Execution & Defensive Visibility | Prove that EDR/SIEM detect, log, or block the synthesised attack techniques. | Purple Team | Per validation campaign |

### 1.1 Pre-conditions

- A reachable, self-hosted OpenCTI instance (>= 5.12) with curated intelligence.
- A non-interactive service account in OpenCTI scoped to the minimum required roles.
- An Atomic Red Team checkout (`/opt/atomic-red-team`) or `ART_ALLOW_REMOTE=true`.
- Hardened lab endpoints with a representative EDR + log shipping to the SIEM.
- Documented change-control approval for executing offensive payloads.

---

## 2. Phase 1 - API Connection & Privilege Validation

### 2.1 Goals

- Confirm that the script can authenticate to OpenCTI without credential leakage.
- Confirm that the service account has read access to Threat Actors, Intrusion
  Sets, Malware, Campaigns, Attack Patterns and the relationships between them.
- Confirm that returned objects conform to STIX 2.1 (`type`, `id`,
  `spec_version`, etc.) and that ATT&CK identifiers are populated in
  `x_mitre_id`.

### 2.2 Privilege Checklist

| Capability | Required | Why |
|------------|----------|-----|
| `KNOWLEDGE` (read) | Yes | List Threat Actors / Intrusion Sets / Malware / Campaigns / Attack Patterns |
| `KNOWLEDGE_KNUPDATE` | No | Script never mutates intelligence |
| `KNOWLEDGE_KNUPLOAD` | No | No bundle ingestion |
| `BYPASS` / Admin | No | Hard rejection - principle of least privilege |
| Token rotation policy | <= 90 days | Aligns with secret hygiene baseline |

### 2.3 Steps

1. **Network reachability and TLS check**

   ```bash
   curl -sSI --connect-timeout 5 "$OPENCTI_URL/graphql" \
     | tee /tmp/opencti-headers.txt
   ```

   Pass criteria: HTTP `200` or `401`/`403` (auth challenge), valid TLS chain
   (no `--insecure` required), expected `Server` and security headers.

2. **GraphQL `me` query** (verifies token + RBAC scope without depending on
   `pycti`):

   ```bash
   curl -sS -X POST "$OPENCTI_URL/graphql" \
     -H "Authorization: Bearer $OPENCTI_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"query":"{ me { user_email name capabilities { name } } }"}' \
     | jq '.data.me.capabilities[].name'
   ```

   Pass criteria: `KNOWLEDGE` is present; `BYPASS` is absent.

3. **`pycti` smoke test** (run from a clean Python venv with this repo's
   `requirements.txt` installed):

   ```bash
   python - <<'PY'
   import os
   from pycti import OpenCTIApiClient

   client = OpenCTIApiClient(
       url=os.environ["OPENCTI_URL"],
       token=os.environ["OPENCTI_TOKEN"],
       ssl_verify=True,
       log_level="warning",
   )
   sample = client.attack_pattern.list(first=1)
   print(sample)
   PY
   ```

   Pass criteria: command exits `0`; output contains a JSON object with
   `id`, `entity_type == "Attack-Pattern"`, and `x_mitre_id` matching `T\d{4}`.

4. **STIX shape verification** (sample query, then assert STIX-required fields):

   ```bash
   python - <<'PY'
   import os, sys
   from pycti import OpenCTIApiClient

   c = OpenCTIApiClient(os.environ["OPENCTI_URL"], os.environ["OPENCTI_TOKEN"])
   ap = c.attack_pattern.list(first=5)
   required = {"id", "standard_id", "entity_type", "x_mitre_id"}
   missing = [a.get("name") for a in ap if not required.issubset(a.keys())]
   sys.exit(1 if missing else 0)
   PY
   ```

   Pass criteria: exit code `0`. Failure indicates an OpenCTI version drift
   that the script must be patched against.

5. **Secrets handling audit**

   - `.env` file mode is `600`.
   - No token appears in logs (`grep -i token logs/*` returns nothing).
   - CI logs redact `OPENCTI_TOKEN` via masking.

### 2.4 Pass / Fail Criteria

- **Pass**: every step succeeds and the service account has only `KNOWLEDGE`.
- **Fail**: any step errors, or the service account holds `BYPASS` /
  `SETTINGS`. Remediate by re-issuing a scoped token.

### 2.5 Failure Handling

| Symptom | Likely cause | Action |
|---------|--------------|--------|
| `401` from GraphQL | Expired/revoked token | Rotate token, update `.env` |
| `requests.exceptions.SSLError` | Self-signed cert | Add CA bundle to truststore; **never** use `--insecure` outside a lab |
| `pycti` `Filter operation not supported` | OpenCTI < 5.12 | Script will auto-fall back to relationship traversal; consider upgrading |
| Empty `attack_pattern.list` | Connectors disabled | Confirm `mitre` connector is installed and synchronised |

---

## 3. Phase 2 - Intelligence Mapping Accuracy

### 3.1 Goals

- Verify that every Attack Pattern returned for a target translates into the
  intended ART test - or is correctly skipped with a logged reason.
- Catch silent regressions when OpenCTI revokes / deprecates techniques or
  when the ART index drops a test.

### 3.2 Sampling Strategy

Use a two-tier sample on every generated `manifest.json`:

1. **Statistical sample**: 10% of techniques (minimum 5, maximum 25), drawn
   randomly with `python -c "import random,json,sys;..."`.
2. **Targeted sample** (mandatory):
   - All sub-techniques (`T####.###`).
   - All techniques flagged `skipped_reason: no_art_mapping`.
   - All techniques with executor `manual` (cannot run unattended).

### 3.3 Spot-Check Workflow

#### Tier 1 - Identifier sanity

- Every key in `manifest.techniques` matches `^T\d{4}(\.\d{3})?$`.
- No duplicate technique entries.
- `target.opencti_id` is a valid STIX standard id (UUIDv4).

```bash
jq -r '.techniques | keys[]' output/<target>/manifest.json \
  | grep -vE '^T[0-9]{4}(\.[0-9]{3})?$' \
  && echo "FAIL: malformed technique ids" || echo "OK"
```

#### Tier 2 - Cross-reference with MITRE ATT&CK Navigator

- Export the technique list and overlay it against the actor's ATT&CK
  Navigator layer (or `mitre-cti` STIX bundle). The two sets should match
  within an acceptable delta (most often: OpenCTI is a strict subset).
- For any technique present in OpenCTI but missing from the public ATT&CK
  group page, capture provenance: which OpenCTI connector / analyst added it?

#### Tier 3 - ART test integrity

For each sampled technique:

1. Confirm `atomic_tests[].test_number` exists in
   `atomics/<technique_id>/<technique_id>.yaml`.
2. Confirm `executor` matches the YAML and is one of
   `powershell`, `command_prompt`, `sh`, `bash`, `manual`.
3. Open the generated `.ps1` and confirm the `Invoke-AtomicTest` call uses the
   exact `-TestNumbers` value.
4. For `sh` / `bash` tests, verify the `.sh` wrapper is present and the
   `pwsh` invocation is shell-escaped correctly.

```bash
python - <<'PY'
import json, pathlib, yaml
manifest = json.loads(pathlib.Path("output/<target>/manifest.json").read_text())
atomics = pathlib.Path("/opt/atomic-red-team/atomics")
errors = []
for tid, entry in manifest["techniques"].items():
    yaml_path = atomics / tid / f"{tid}.yaml"
    if not entry.get("atomic_tests"):
        continue
    if not yaml_path.is_file():
        errors.append(f"{tid}: yaml missing")
        continue
    data = yaml.safe_load(yaml_path.read_text())
    declared = {i+1 for i, _ in enumerate(data.get("atomic_tests", []))}
    for t in entry["atomic_tests"]:
        if t["test_number"] not in declared:
            errors.append(f"{tid}: test {t['test_number']} not in YAML")
print("OK" if not errors else "\n".join(errors))
PY
```

#### Tier 4 - False-positive review

- Reject any technique whose ATT&CK page is marked **Deprecated** or
  **Revoked**.
- Flag tests whose prerequisites (`Get-Prereq`) require domain admin or
  internet egress that does not exist in the lab; mark them `manual`.
- Reject tests that target operating systems not in scope for this campaign
  (e.g. macOS-only ART tests against a Windows-only environment).

### 3.4 Pass / Fail Criteria

- **Pass**: 100% of Tier 3 samples reconcile with the ART YAML; Tier 4 review
  produces zero false positives in the sampled set.
- **Fail**: any test number does not exist in the source YAML, or any
  deprecated / revoked technique is emitted as runnable. Re-pin the
  `atomic-red-team` checkout, re-run the script, then revalidate.

---

## 4. Phase 3 - Endpoint Execution & Defensive Visibility (Purple Team)

### 4.1 Goals

- Run the generated artefacts on representative endpoints.
- Verify that EDR, SIEM, and the Detection-as-Code pipeline observe the
  expected telemetry and (where applicable) raise the expected alerts or
  block the action.
- Produce a coverage matrix that feeds back into both the detection backlog
  and the CTI prioritisation queue.

### 4.2 Lab Topology

- **Network segmentation**: dedicated VLAN with no path to production.
- **Endpoint baseline**: golden-image Windows 11 (Build current), Windows
  Server 2022, and Ubuntu 22.04. Each endpoint snapshotted before every run.
- **Telemetry stack**:
  - EDR agent (e.g. CrowdStrike / SentinelOne / Defender for Endpoint).
  - Sysmon with the SwiftOnSecurity baseline configuration (Windows).
  - `auditd` with a known ruleset (Linux).
  - Forwarders (Splunk UF / Elastic Agent / Cribl) shipping to the SIEM.

### 4.3 Pre-Execution Checklist

- [ ] Snapshot every target VM.
- [ ] Confirm EDR is in `monitoring` (not `prevent`) for the first dry run; flip to `prevent` on the second pass to test blocking efficacy.
- [ ] Capture a 5 minute baseline with `Get-WinEvent` / `journalctl` to identify ambient noise.
- [ ] Stage the manifest and generated scripts via the agreed delivery method
      (GPO Software Distribution, MDM, or direct copy).
- [ ] Open a change ticket referencing the OpenCTI target and the manifest
      hash (`sha256sum manifest.json`).

### 4.4 Execution Procedure

For each technique in the manifest:

1. Note start time (`date -u +%FT%TZ`) - this is the SIEM correlation anchor.
2. Run the per-technique script:

   ```powershell
   pwsh -NoProfile -File .\output\<target>\by_technique\T1059.001.ps1
   ```

3. Wait for ART to print `Done executing test:`.
4. Note end time.
5. Run the corresponding cleanup (`-Cleanup`) before moving on.
6. Restore from snapshot when a technique creates persistence or modifies
   security tooling configuration.

### 4.5 Defensive Visibility Matrix

For each technique build a row of:

| Field | Source |
|-------|--------|
| Technique ID | `manifest.json` |
| Test name | `manifest.json` |
| Expected data sources | ATT&CK Data Components (e.g. `Process Creation`, `Command Execution`, `File: File Creation`) |
| Expected EDR detection | EDR rule mapping (vendor catalogue) |
| Expected SIEM alert | Detection-as-code rule id (e.g. `WIN-PS-EncodedCommand`) |
| Observed telemetry | Hits in raw logs |
| Observed alert | EDR / SIEM alert id |
| Outcome | `Detected` / `Logged-only` / `Blocked` / `Missed` |
| Mean time to alert | `alert_time - start_time` |

**Sample SIEM query (Splunk):**

```
index=edr OR index=sysmon
| eval window_start=relative_time(now(), "-30m@m")
| where _time >= strptime("$START_TIME$", "%Y-%m-%dT%H:%M:%SZ")
| where _time <= strptime("$END_TIME$", "%Y-%m-%dT%H:%M:%SZ")
| search host="$LAB_HOST$"
| stats count by signature, signature_id, process_name
```

### 4.6 Pass / Fail Criteria

- **Pass (per technique)**: at least one expected data component is logged,
  AND either an alert fires or the action is blocked when EDR is in
  `prevent` mode.
- **Pass (campaign)**: >= 80% of techniques meet the per-technique pass
  criteria; every `Missed` technique is added to the detection backlog with
  an owner and target date.
- **Fail**: telemetry never reaches the SIEM, or EDR misconfiguration
  silently swallows events. Halt the campaign and remediate the pipeline
  before continuing.

### 4.7 Reporting & CTEM Feedback Loop

- Produce a post-run report containing: manifest hash, lab inventory,
  matrix outcomes, snapshot evidence, and remediation tickets.
- Push detection gaps to the Detection-as-Code repository as issues tagged
  `cttoart` and the OpenCTI target name.
- File enrichment requests back to the CTI team for techniques that lacked a
  good ART analogue (`skipped_reason: no_art_mapping`) or that produced
  ambiguous detections.
- Schedule re-validation when either OpenCTI intelligence or the
  Atomic Red Team index changes materially (typically monthly).

---

## 5. Appendix

### 5.1 Sample manifest excerpt

```json
{
  "generated_at": "2026-04-27T09:00:00Z",
  "target": {
    "type": "Intrusion-Set",
    "name": "APT29",
    "opencti_id": "intrusion-set--2e01c80a-...-b1c4"
  },
  "techniques": {
    "T1059.001": {
      "name": "PowerShell",
      "tactics": ["execution"],
      "atomic_tests": [
        {"test_number": 1, "test_name": "Mimikatz", "executor": "powershell", "test_guid": "..."}
      ],
      "files": ["by_technique/T1059.001.ps1"]
    },
    "T1027": {
      "name": "Obfuscated Files or Information",
      "tactics": ["defense-evasion"],
      "atomic_tests": [],
      "files": [],
      "skipped_reason": "no_art_mapping"
    }
  }
}
```

### 5.2 Troubleshooting quick reference

| Symptom | Probable cause | Fix |
|---------|----------------|-----|
| `Import-Module Invoke-AtomicRedTeam` fails | Module not installed | `Install-Module -Name invoke-atomicredteam -Scope CurrentUser` |
| `Atomic test does not exist` at runtime | ART checkout drifted from index | Re-pin the checkout commit and rerun the generator |
| `pwsh: command not found` on Linux | PowerShell Core missing | `apt install -y powershell` (or vendor equivalent) |
| Empty `manifest.techniques` | Target name mismatch in OpenCTI | Use the canonical alias (e.g. `Cozy Bear` vs `APT29`) |
