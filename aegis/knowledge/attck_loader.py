"""ATT&CK STIX data loader for Neo4j knowledge graph.

Downloads MITRE ATT&CK STIX bundles and imports them into the Neo4j graph.
Supports Enterprise ATT&CK v15+.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
# ATT&CK STIX Loader
# ──────────────────────────────────────────────


class ATTACKLoader:
    """Downloads and parses MITRE ATT&CK STIX data for import into Neo4j."""

    STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

    def __init__(self, graph: Any = None) -> None:
        self._graph = graph

    def fetch_stix_bundle(self, url: str = "") -> dict[str, Any]:
        """Fetch the ATT&CK STIX bundle from GitHub or a local file.

        Args:
            url: URL or local file path. Defaults to MITRE CTI GitHub.

        Returns:
            Parsed STIX bundle dict.
        """
        target = url or self.STIX_URL
        if target.startswith("http"):
            import urllib.request
            logger.info("Fetching ATT&CK STIX bundle from %s ...", target)
            with urllib.request.urlopen(target) as resp:
                return json.loads(resp.read().decode())
        else:
            logger.info("Loading ATT&CK STIX bundle from %s ...", target)
            with open(target, "r", encoding="utf-8") as f:
                return json.load(f)

    def extract_techniques(self, bundle: dict[str, Any]) -> list[dict[str, Any]]:
        """Extract technique objects from a STIX bundle.

        Returns list of dicts with keys: technique_id, name, description,
        tactic, is_subtechnique, parent_id, platforms, data_sources.
        """
        objects = bundle.get("objects", [])
        techniques: list[dict[str, Any]] = []

        # Build a lookup from technique ID → list of tactic names
        # (tactics are referenced via relationship objects)
        tech_to_tactics: dict[str, list[str]] = {}

        for obj in objects:
            if obj.get("type") == "relationship" and obj.get("relationship_type") == "subtechnique-of":
                tech_to_tactics.setdefault(obj["source_ref"], [])
            elif obj.get("type") == "relationship":
                # Other relationships might point to tactics
                pass

        # Extract techniques and sub-techniques
        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue

            ext_refs = obj.get("external_references", [])
            technique_id = ""
            for ref in ext_refs:
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id", "")
                    break

            if not technique_id:
                continue

            kill_chains = obj.get("kill_chain_phases", [])
            tactics = [kc["phase_name"] for kc in kill_chains]

            is_sub = bool(technique_id.count(".") > 0)
            parent_id = technique_id.split(".")[0] if is_sub else ""

            techniques.append({
                "technique_id": technique_id,
                "name": obj.get("name", ""),
                "description": obj.get("description", ""),
                "tactic": tactics[0] if tactics else "",
                "tactics": tactics,
                "is_subtechnique": is_sub,
                "parent_id": parent_id,
                "platforms": obj.get("x_mitre_platforms", []),
                "data_sources": obj.get("x_mitre_data_sources", []),
                "detection": obj.get("x_mitre_detection", ""),
            })

        logger.info("Extracted %d techniques from STIX bundle", len(techniques))
        return techniques

    def extract_relationships(self, bundle: dict[str, Any]) -> list[dict[str, Any]]:
        """Extract relationship objects from STIX bundle.

        Returns list of dicts with keys: source_ref, target_ref, relationship_type.
        """
        rels = []
        for obj in bundle.get("objects", []):
            if obj.get("type") == "relationship":
                rels.append({
                    "source_ref": obj.get("source_ref", ""),
                    "target_ref": obj.get("target_ref", ""),
                    "relationship_type": obj.get("relationship_type", ""),
                    "description": obj.get("description", ""),
                })
        logger.info("Extracted %d relationships", len(rels))
        return rels

    def generate_cypher(self, techniques: list[dict[str, Any]]) -> str:
        """Generate Cypher statements to import techniques into Neo4j.

        Returns a string of Cypher commands that can be executed via cypher-shell.
        """
        lines: list[str] = []
        lines.append("// Auto-generated ATT&CK import — %d techniques" % len(techniques))
        lines.append("")

        for t in techniques:
            lines.append(
                "MERGE (t:Technique {technique_id: '%s'})\n"
                "SET t.name = '%s',\n"
                "    t.description = '%s',\n"
                "    t.tactic = '%s',\n"
                "    t.is_subtechnique = %s,\n"
                "    t.parent_id = '%s',\n"
                "    t.platforms = %s,\n"
                "    t.version = 'v15';"
                % (
                    t["technique_id"],
                    t["name"].replace("'", "\\'"),
                    t["description"].replace("'", "\\'").replace("\n", " ")[:500],
                    t["tactic"],
                    "true" if t["is_subtechnique"] else "false",
                    t["parent_id"],
                    json.dumps(t["platforms"]),
                )
            )
            lines.append("")

        return "\n".join(lines)

    def import_to_neo4j(self, bundle: Optional[dict[str, Any]] = None) -> int:
        """Fetch, parse, and import ATT&CK data into Neo4j.

        Args:
            bundle: Optional pre-fetched STIX bundle.

        Returns:
            Number of techniques imported.
        """
        if bundle is None:
            bundle = self.fetch_stix_bundle()

        techniques = self.extract_techniques(bundle)
        cypher = self.generate_cypher(techniques)

        if self._graph:
            # TODO: Execute via Neo4j driver
            logger.info("ATT&CK import to Neo4j not yet wired")
        else:
            # Write to file for manual import
            path = "tools/attck_import.cypher"
            with open(path, "w", encoding="utf-8") as f:
                f.write(cypher)
            logger.info("Cypher import script written to %s", path)

        return len(techniques)


# ──────────────────────────────────────────────
# CLI Entrypoint
# ──────────────────────────────────────────────


def main() -> None:
    """CLI to fetch and export ATT&CK data."""
    import argparse
    parser = argparse.ArgumentParser(description="Import MITRE ATT&CK to Neo4j")
    parser.add_argument("--url", default="", help="STIX bundle URL or file path")
    parser.add_argument("--output", default="tools/attck_import.cypher", help="Output Cypher file")
    args = parser.parse_args()

    loader = ATTACKLoader()
    bundle = loader.fetch_stix_bundle(args.url) if args.url else loader.fetch_stix_bundle()
    techniques = loader.extract_techniques(bundle)
    cypher = loader.generate_cypher(techniques)

    with open(args.output, "w", encoding="utf-8") as f:
        f.write(cypher)
    logger.info("Wrote %d techniques to %s", len(techniques), args.output)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
