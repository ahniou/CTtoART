#!/usr/bin/env python3
"""CTtoART - Convert OpenCTI threat intelligence into Atomic Red Team execution scripts.

This module connects to a self-hosted OpenCTI instance, extracts MITRE ATT&CK
Attack Patterns linked to specified Threat Actors, Intrusion Sets, Malware,
or Campaigns, then maps the T-codes to Atomic Red Team tests and emits
ready-to-run PowerShell (Invoke-AtomicTest) and shell scripts plus a
machine-readable manifest for downstream automation.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

import requests
from dotenv import load_dotenv

try:
    from pycti import OpenCTIApiClient
except ImportError:  # pragma: no cover - import guarded for clearer runtime error
    OpenCTIApiClient = None  # type: ignore


LOG = logging.getLogger("cttoart")

# Canonical Red Canary index that lists every atomic test (technique, test #, executor).
DEFAULT_ART_INDEX_URL = (
    "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/"
    "master/atomics/Indexes/Indexes-CSV/index.csv"
)
LOCAL_ART_INDEX_RELATIVE = Path("atomics/Indexes/Indexes-CSV/index.csv")

# Accepts T1059 and T1059.001 forms; the same regex is used for input filtering.
T_CODE_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$")

SUPPORTED_ENTITY_TYPES: Tuple[str, ...] = (
    "Threat-Actor",
    "Threat-Actor-Group",
    "Threat-Actor-Individual",
    "Intrusion-Set",
    "Malware",
    "Campaign",
)

# Executors that genuinely run on Linux/macOS hosts; used to decide whether
# to also emit a .sh wrapper alongside the .ps1.
SHELL_EXECUTORS = {"sh", "bash"}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class AtomicTest:
    """A single atomic test row from the Atomic Red Team index."""

    technique_id: str
    technique_name: str
    tactic: str
    test_number: int
    test_name: str
    test_guid: str
    executor: str


@dataclass
class TechniqueRecord:
    """An ATT&CK technique extracted from OpenCTI plus any matching ART tests."""

    technique_id: str
    technique_name: Optional[str]
    tactics: List[str] = field(default_factory=list)
    description: Optional[str] = None
    atomic_tests: List[AtomicTest] = field(default_factory=list)
    skipped_reason: Optional[str] = None


# ---------------------------------------------------------------------------
# OpenCTI client wrapper
# ---------------------------------------------------------------------------
class OpenCTIIntelClient:
    """Thin facade around pycti for the queries this project needs."""

    def __init__(self, url: str, token: str, ssl_verify: bool = True) -> None:
        if OpenCTIApiClient is None:
            raise RuntimeError(
                "pycti is not installed. Run `pip install -r requirements.txt`."
            )
        LOG.info("Connecting to OpenCTI at %s", url)
        self.client = OpenCTIApiClient(
            url=url,
            token=token,
            ssl_verify=ssl_verify,
            log_level="warning",
        )

    def find_entity(self, name: str, entity_type: Optional[str] = None) -> Optional[dict]:
        """Resolve a named SDO; if `entity_type` is provided it scopes the search."""
        types = [entity_type] if entity_type else list(SUPPORTED_ENTITY_TYPES)
        try:
            results = self.client.stix_domain_object.list(
                types=types,
                filters={
                    "mode": "and",
                    "filters": [
                        {
                            "key": "name",
                            "values": [name],
                            "operator": "eq",
                            "mode": "or",
                        }
                    ],
                    "filterGroups": [],
                },
                first=10,
            )
        except Exception as exc:  # broad catch: pycti raises various exception types
            LOG.error("OpenCTI lookup failed for %s (%s): %s", name, entity_type, exc)
            return None

        if not results:
            LOG.warning("No OpenCTI entity matched name=%s types=%s", name, types)
            return None

        # Prefer an exact case-insensitive match before falling back to the first hit.
        lowered = name.lower()
        for record in results:
            if (record.get("name") or "").lower() == lowered:
                return record
        return results[0]

    def list_attack_patterns_for(self, entity_id: str) -> List[dict]:
        """Return Attack-Pattern SDOs that the given entity `uses`."""
        try:
            attack_patterns = self.client.attack_pattern.list(
                filters={
                    "mode": "and",
                    "filters": [
                        {
                            "key": "regardingOf",
                            "values": [
                                {"key": "id", "values": [entity_id]},
                                {"key": "relationship_type", "values": ["uses"]},
                            ],
                        }
                    ],
                    "filterGroups": [],
                },
                getAll=True,
            )
        except Exception as exc:
            LOG.warning(
                "Attack pattern query via regardingOf failed (%s); "
                "falling back to relationship traversal.",
                exc,
            )
            attack_patterns = self._fallback_relationship_traversal(entity_id)

        LOG.info(
            "Retrieved %d attack patterns for entity %s",
            len(attack_patterns),
            entity_id,
        )
        return attack_patterns

    def _fallback_relationship_traversal(self, entity_id: str) -> List[dict]:
        """Older OpenCTI deployments may not support `regardingOf`. Walk relationships instead."""
        try:
            relationships = self.client.stix_core_relationship.list(
                fromId=entity_id,
                relationship_type="uses",
                getAll=True,
            )
        except Exception as exc:
            LOG.error("Relationship traversal failed: %s", exc)
            return []

        targets: List[dict] = []
        for rel in relationships or []:
            target = rel.get("to") or {}
            if target.get("entity_type") == "Attack-Pattern":
                targets.append(target)
        return targets


# ---------------------------------------------------------------------------
# Atomic Red Team mapping
# ---------------------------------------------------------------------------
class AtomicRedTeamIndex:
    """In-memory lookup from MITRE ATT&CK technique id -> list of AtomicTest."""

    def __init__(self) -> None:
        self.tests_by_technique: Dict[str, List[AtomicTest]] = {}

    @classmethod
    def from_csv_text(cls, csv_text: str) -> "AtomicRedTeamIndex":
        index = cls()
        reader = csv.DictReader(csv_text.splitlines())
        for row in reader:
            technique_id = (row.get("Technique #") or row.get("Technique#") or "").strip()
            if not T_CODE_PATTERN.match(technique_id):
                continue
            try:
                test_number = int((row.get("Test #") or "0").strip())
            except ValueError:
                continue
            test = AtomicTest(
                technique_id=technique_id,
                technique_name=(row.get("Technique Name") or "").strip(),
                tactic=(row.get("Tactic") or "").strip(),
                test_number=test_number,
                test_name=(row.get("Test Name") or "").strip(),
                test_guid=(row.get("Test GUID") or "").strip(),
                executor=(row.get("Executor Name") or "").strip().lower(),
            )
            index.tests_by_technique.setdefault(technique_id, []).append(test)
        LOG.info(
            "Loaded ART index: %d techniques / %d tests",
            len(index.tests_by_technique),
            sum(len(v) for v in index.tests_by_technique.values()),
        )
        return index

    @classmethod
    def load(
        cls,
        local_path: Optional[Path],
        allow_remote: bool,
        remote_url: str,
    ) -> "AtomicRedTeamIndex":
        if local_path:
            csv_path = (
                local_path
                if local_path.suffix.lower() == ".csv"
                else local_path / LOCAL_ART_INDEX_RELATIVE
            )
            if csv_path.is_file():
                LOG.info("Loading Atomic Red Team index from %s", csv_path)
                return cls.from_csv_text(csv_path.read_text(encoding="utf-8"))
            LOG.warning("ART index not found at %s", csv_path)

        if allow_remote:
            LOG.info("Fetching Atomic Red Team index from %s", remote_url)
            try:
                resp = requests.get(remote_url, timeout=30)
                resp.raise_for_status()
            except requests.RequestException as exc:
                raise RuntimeError(f"Failed to download ART index: {exc}") from exc
            return cls.from_csv_text(resp.text)

        raise RuntimeError(
            "No Atomic Red Team index available. "
            "Set ATOMICS_PATH (or --atomics-path), or enable ART_ALLOW_REMOTE."
        )

    def lookup(self, technique_id: str) -> List[AtomicTest]:
        return list(self.tests_by_technique.get(technique_id, []))


# ---------------------------------------------------------------------------
# Script generator
# ---------------------------------------------------------------------------
def _slugify(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("_")
    return slug or "target"


class ScriptGenerator:
    """Writes per-technique and consolidated ART scripts plus a JSON manifest."""

    def __init__(self, output_root: Path) -> None:
        self.output_root = output_root

    def generate(
        self,
        target_label: str,
        target_meta: dict,
        techniques: Sequence[TechniqueRecord],
    ) -> Path:
        target_dir = self.output_root / _slugify(target_label)
        by_tech_dir = target_dir / "by_technique"
        consolidated_dir = target_dir / "consolidated"
        by_tech_dir.mkdir(parents=True, exist_ok=True)
        consolidated_dir.mkdir(parents=True, exist_ok=True)

        manifest_techniques: Dict[str, dict] = {}
        consolidated_ps1_lines: List[str] = [
            self._ps1_header(target_label, target_meta, consolidated=True)
        ]
        consolidated_sh_lines: List[str] = [
            self._sh_header(target_label, target_meta, consolidated=True)
        ]
        any_sh = False

        for record in sorted(techniques, key=lambda r: r.technique_id):
            entry: dict = {
                "name": record.technique_name,
                "tactics": record.tactics,
                "atomic_tests": [],
                "files": [],
            }
            if record.skipped_reason:
                entry["skipped_reason"] = record.skipped_reason
                manifest_techniques[record.technique_id] = entry
                continue

            ps1_path = by_tech_dir / f"{record.technique_id}.ps1"
            ps1_lines = [self._ps1_header(target_label, target_meta, technique=record)]
            sh_lines = [self._sh_header(target_label, target_meta, technique=record)]
            sh_needed = False

            for test in record.atomic_tests:
                ps1_block = self._render_ps1_block(test)
                ps1_lines.append(ps1_block)
                consolidated_ps1_lines.append(ps1_block)
                entry["atomic_tests"].append(
                    {
                        "test_number": test.test_number,
                        "test_name": test.test_name,
                        "executor": test.executor,
                        "test_guid": test.test_guid,
                    }
                )
                if test.executor in SHELL_EXECUTORS:
                    sh_block = self._render_sh_block(test)
                    sh_lines.append(sh_block)
                    consolidated_sh_lines.append(sh_block)
                    sh_needed = True
                    any_sh = True

            ps1_path.write_text("\n".join(ps1_lines) + "\n", encoding="utf-8")
            entry["files"].append(str(ps1_path.relative_to(target_dir)))

            if sh_needed:
                sh_path = by_tech_dir / f"{record.technique_id}.sh"
                sh_path.write_text("\n".join(sh_lines) + "\n", encoding="utf-8")
                try:
                    sh_path.chmod(0o755)
                except OSError:
                    pass
                entry["files"].append(str(sh_path.relative_to(target_dir)))

            manifest_techniques[record.technique_id] = entry

        consolidated_ps1 = consolidated_dir / f"{_slugify(target_label)}_all.ps1"
        consolidated_ps1.write_text(
            "\n".join(consolidated_ps1_lines) + "\n", encoding="utf-8"
        )

        if any_sh:
            consolidated_sh = consolidated_dir / f"{_slugify(target_label)}_all.sh"
            consolidated_sh.write_text(
                "\n".join(consolidated_sh_lines) + "\n", encoding="utf-8"
            )
            try:
                consolidated_sh.chmod(0o755)
            except OSError:
                pass

        manifest = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "target": target_meta,
            "techniques": manifest_techniques,
            "summary": {
                "total_techniques": len(manifest_techniques),
                "techniques_with_tests": sum(
                    1 for t in manifest_techniques.values() if t.get("atomic_tests")
                ),
                "techniques_skipped": sum(
                    1 for t in manifest_techniques.values() if t.get("skipped_reason")
                ),
            },
        }
        manifest_path = target_dir / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        LOG.info("Wrote manifest to %s", manifest_path)
        return target_dir

    @staticmethod
    def _ps1_header(
        target_label: str,
        target_meta: dict,
        *,
        technique: Optional[TechniqueRecord] = None,
        consolidated: bool = False,
    ) -> str:
        lines = [
            "<#",
            f"  CTtoART generated PowerShell - {datetime.now(timezone.utc).isoformat()}",
            f"  Target: {target_label} ({target_meta.get('type', '?')})",
            f"  OpenCTI ID: {target_meta.get('opencti_id', 'n/a')}",
        ]
        if technique:
            lines.append(
                f"  Technique: {technique.technique_id} - {technique.technique_name}"
            )
        if consolidated:
            lines.append("  Mode: consolidated (all techniques)")
        lines.extend(
            [
                "  Requirements:",
                "    - PowerShell 5.1+ or PowerShell Core 7+",
                "    - Invoke-AtomicRedTeam module installed and imported",
                "    - Atomics folder synchronised locally",
                "  Run inside an authorised lab environment only.",
                "#>",
                "$ErrorActionPreference = 'Continue'",
                "Import-Module Invoke-AtomicRedTeam -ErrorAction Stop",
                "",
            ]
        )
        return "\n".join(lines)

    @staticmethod
    def _sh_header(
        target_label: str,
        target_meta: dict,
        *,
        technique: Optional[TechniqueRecord] = None,
        consolidated: bool = False,
    ) -> str:
        lines = [
            "#!/usr/bin/env bash",
            f"# CTtoART generated shell wrapper - {datetime.now(timezone.utc).isoformat()}",
            f"# Target: {target_label} ({target_meta.get('type', '?')})",
            f"# OpenCTI ID: {target_meta.get('opencti_id', 'n/a')}",
        ]
        if technique:
            lines.append(
                f"# Technique: {technique.technique_id} - {technique.technique_name}"
            )
        if consolidated:
            lines.append("# Mode: consolidated (all techniques)")
        lines.extend(
            [
                "# Requires PowerShell (pwsh) with Invoke-AtomicRedTeam installed.",
                "# Run inside an authorised lab environment only.",
                "set -u",
                "command -v pwsh >/dev/null 2>&1 || { echo 'pwsh not found in PATH' >&2; exit 1; }",
                "",
            ]
        )
        return "\n".join(lines)

    @staticmethod
    def _render_ps1_block(test: AtomicTest) -> str:
        return "\n".join(
            [
                f"# --- {test.technique_id} test {test.test_number}: {test.test_name} ---",
                f"# Executor: {test.executor} | GUID: {test.test_guid}",
                f"Invoke-AtomicTest {test.technique_id} -TestNumbers {test.test_number} -GetPrereqs",
                f"Invoke-AtomicTest {test.technique_id} -TestNumbers {test.test_number}",
                f"# Cleanup (uncomment to revert): Invoke-AtomicTest {test.technique_id} -TestNumbers {test.test_number} -Cleanup",
                "",
            ]
        )

    @staticmethod
    def _render_sh_block(test: AtomicTest) -> str:
        base = (
            f'pwsh -NoProfile -NonInteractive -Command '
            f'"Invoke-AtomicTest {test.technique_id} -TestNumbers {test.test_number}'
        )
        return "\n".join(
            [
                f"# --- {test.technique_id} test {test.test_number}: {test.test_name} ---",
                f"# Executor: {test.executor} | GUID: {test.test_guid}",
                base + ' -GetPrereqs"',
                base + '"',
                f"# Cleanup (uncomment): {base} -Cleanup\"",
                "",
            ]
        )


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def collect_techniques(
    cti: OpenCTIIntelClient,
    art_index: AtomicRedTeamIndex,
    name: str,
    entity_type: Optional[str],
) -> Tuple[Optional[dict], List[TechniqueRecord]]:
    """Resolve an OpenCTI entity, pull its Attack Patterns, and join with ART tests."""
    entity = cti.find_entity(name, entity_type)
    if not entity:
        return None, []

    LOG.info(
        "Resolved %s %s -> id=%s",
        entity.get("entity_type"),
        entity.get("name"),
        entity.get("id"),
    )

    attack_patterns = cti.list_attack_patterns_for(entity["id"])
    records: Dict[str, TechniqueRecord] = {}
    for ap in attack_patterns:
        t_code = (ap.get("x_mitre_id") or "").strip()
        if not t_code:
            LOG.debug("Skipping attack pattern without x_mitre_id: %s", ap.get("name"))
            continue
        if not T_CODE_PATTERN.match(t_code):
            LOG.warning("Ignoring unexpected MITRE id format: %s", t_code)
            continue
        if t_code in records:
            continue

        tactics: List[str] = []
        for kc in ap.get("killChainPhases", []) or []:
            phase = kc.get("phase_name") or kc.get("kill_chain_name")
            if phase:
                tactics.append(phase)

        record = TechniqueRecord(
            technique_id=t_code,
            technique_name=ap.get("name"),
            tactics=tactics,
            description=(ap.get("description") or "")[:500] or None,
        )
        tests = art_index.lookup(t_code)
        if not tests:
            record.skipped_reason = "no_art_mapping"
            LOG.info("No ART tests for %s (%s)", t_code, ap.get("name"))
        else:
            record.atomic_tests = tests
        records[t_code] = record

    return entity, list(records.values())


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="cti_to_art",
        description="Convert OpenCTI threat intelligence into Atomic Red Team scripts.",
    )
    parser.add_argument(
        "--threat-actor",
        action="append",
        default=[],
        help="Threat actor name (repeatable).",
    )
    parser.add_argument(
        "--intrusion-set",
        action="append",
        default=[],
        help="Intrusion set name (repeatable).",
    )
    parser.add_argument(
        "--malware",
        action="append",
        default=[],
        help="Malware family name (repeatable).",
    )
    parser.add_argument(
        "--campaign",
        action="append",
        default=[],
        help="Campaign name (repeatable).",
    )
    parser.add_argument(
        "--targets-file",
        type=Path,
        help='JSON file with the shape {"threat_actors": [...], "intrusion_sets": [...], '
        '"malware": [...], "campaigns": [...]}.',
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("output"),
        help="Output root directory (default: ./output).",
    )
    parser.add_argument(
        "--atomics-path",
        type=Path,
        help="Path to a local atomic-red-team checkout, or directly to index.csv.",
    )
    parser.add_argument(
        "--allow-remote-art",
        action="store_true",
        help="Fetch ART index from GitHub if the local copy is missing.",
    )
    parser.add_argument(
        "--remote-art-url",
        default=DEFAULT_ART_INDEX_URL,
        help="Override the ART index URL.",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS verification when calling OpenCTI (lab use only).",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    return parser.parse_args(argv)


def collect_targets(args: argparse.Namespace) -> List[Tuple[str, str]]:
    targets: List[Tuple[str, str]] = []
    for name in args.threat_actor:
        targets.append(("Threat-Actor", name))
    for name in args.intrusion_set:
        targets.append(("Intrusion-Set", name))
    for name in args.malware:
        targets.append(("Malware", name))
    for name in args.campaign:
        targets.append(("Campaign", name))

    if args.targets_file:
        try:
            data = json.loads(args.targets_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SystemExit(f"Could not read targets file {args.targets_file}: {exc}")
        for type_name, key in (
            ("Threat-Actor", "threat_actors"),
            ("Intrusion-Set", "intrusion_sets"),
            ("Malware", "malware"),
            ("Campaign", "campaigns"),
        ):
            for name in data.get(key, []) or []:
                targets.append((type_name, name))
    return targets


def _env_path(key: str) -> Optional[Path]:
    value = os.getenv(key)
    return Path(value) if value else None


def main(argv: Optional[Sequence[str]] = None) -> int:
    load_dotenv()
    args = parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    opencti_url = os.getenv("OPENCTI_URL")
    opencti_token = os.getenv("OPENCTI_TOKEN")
    if not opencti_url or not opencti_token:
        LOG.error("OPENCTI_URL and OPENCTI_TOKEN must be set (.env or environment).")
        return 2

    targets = collect_targets(args)
    if not targets:
        LOG.error(
            "No targets provided. Use --threat-actor / --intrusion-set / "
            "--malware / --campaign / --targets-file."
        )
        return 2

    atomics_path = args.atomics_path or _env_path("ATOMICS_PATH")
    allow_remote = args.allow_remote_art or os.getenv(
        "ART_ALLOW_REMOTE", ""
    ).lower() in {"1", "true", "yes"}

    try:
        art_index = AtomicRedTeamIndex.load(
            atomics_path, allow_remote, args.remote_art_url
        )
    except RuntimeError as exc:
        LOG.error("%s", exc)
        return 3

    try:
        cti = OpenCTIIntelClient(
            opencti_url,
            opencti_token,
            ssl_verify=not args.insecure,
        )
    except Exception as exc:
        LOG.error("Could not initialise OpenCTI client: %s", exc)
        return 4

    args.output.mkdir(parents=True, exist_ok=True)
    generator = ScriptGenerator(args.output)

    exit_code = 0
    for entity_type, name in targets:
        LOG.info("Processing %s '%s'", entity_type, name)
        try:
            entity, techniques = collect_techniques(cti, art_index, name, entity_type)
        except Exception as exc:
            LOG.error("Unhandled error while processing %s '%s': %s", entity_type, name, exc)
            exit_code = max(exit_code, 5)
            continue
        if not entity:
            LOG.warning("Skipping %s '%s' - no entity match in OpenCTI", entity_type, name)
            exit_code = max(exit_code, 1)
            continue
        if not techniques:
            LOG.warning("No attack patterns linked to %s '%s'", entity_type, name)
            continue
        target_meta = {
            "type": entity.get("entity_type"),
            "name": entity.get("name"),
            "opencti_id": entity.get("id"),
            "standard_id": entity.get("standard_id"),
        }
        target_dir = generator.generate(name, target_meta, techniques)
        LOG.info("Generated artefacts at %s", target_dir)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
