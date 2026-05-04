#!/usr/bin/env python3
"""Standalone CLI tool for importing MITRE ATT&CK STIX data into Neo4j.

Usage:
    # Download and export to Cypher file
    python tools/attck_importer.py --output attck_import.cypher

    # Import directly to Neo4j (requires neo4j Python driver)
    python tools/attck_importer.py --neo4j-uri bolt://localhost:7687 --neo4j-user neo4j --neo4j-password password

    # Download from a local file
    python tools/attck_importer.py --input enterprise-attack.json --output import.cypher
"""

import argparse
import json
import logging
import sys
from typing import Any, Optional

logger = logging.getLogger(__name__)


def fetch_bundle(url: str) -> dict[str, Any]:
    """Fetch the ATT&CK STIX bundle from URL or local file."""
    if url.startswith("http"):
        import urllib.request
        logger.info("Downloading ATT&CK STIX from %s ...", url)
        with urllib.request.urlopen(url) as resp:
            return json.loads(resp.read().decode())
    else:
        logger.info("Loading ATT&CK STIX from %s ...", url)
        with open(url, "r", encoding="utf-8") as f:
            return json.load(f)


def extract_techniques(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract technique objects from a STIX bundle."""
    techniques = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue

        ext_refs = obj.get("external_references", [])
        tech_id = ""
        for ref in ext_refs:
            if ref.get("source_name") == "mitre-attack":
                tech_id = ref.get("external_id", "")
                break
        if not tech_id:
            continue

        kill_chains = obj.get("kill_chain_phases", [])
        tactics = [kc["phase_name"] for kc in kill_chains]

        techniques.append({
            "technique_id": tech_id,
            "name": obj.get("name", ""),
            "description": obj.get("description", "")[:500],
            "tactic": tactics[0] if tactics else "",
            "tactics": tactics,
            "is_subtechnique": "." in tech_id,
            "parent_id": tech_id.split(".")[0] if "." in tech_id else "",
            "platforms": obj.get("x_mitre_platforms", []),
            "data_sources": obj.get("x_mitre_data_sources", []),
        })

    logger.info("Extracted %d techniques", len(techniques))
    return techniques


def extract_relationships(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract relationship objects from STIX bundle."""
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


def build_technique_id_map(techniques: list[dict[str, Any]], bundle: dict[str, Any]) -> dict[str, str]:
    """Build a mapping from STIX IDs to technique IDs."""
    id_map: dict[str, str] = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") == "attack-pattern":
            ext_refs = obj.get("external_references", [])
            for ref in ext_refs:
                if ref.get("source_name") == "mitre-attack":
                    id_map[obj["id"]] = ref.get("external_id", "")
                    break
    return id_map


def generate_cypher_import(techniques: list[dict[str, Any]], relationships: list[dict[str, Any]], id_map: dict[str, str]) -> str:
    """Generate Cypher statements for Neo4j import."""
    lines = [
        "// Auto-generated ATT&CK import script",
        f"// Generated: {__import__('datetime').datetime.now().isoformat()}",
        f"// Techniques: {len(techniques)}",
        f"// Relationships: {len(relationships)}",
        "",
        "// === Techniques ===",
        "",
    ]

    for t in techniques:
        name = t["name"].replace("'", "\\'").replace('"', '\\"')
        desc = (t.get("description", "") or "")[:400].replace("'", "\\'").replace("\n", " ")
        platforms = json.dumps(t.get("platforms", []))
        data_sources = json.dumps(t.get("data_sources", []))
        tactics = json.dumps(t.get("tactics", []))

        lines.append(
            f"MERGE (t:Technique {{technique_id: '{t['technique_id']}'}})\n"
            f"SET t.name = '{name}',\n"
            f"    t.description = '{desc}',\n"
            f"    t.tactic = '{t.get('tactic', '')}',\n"
            f"    t.is_subtechnique = {'true' if t.get('is_subtechnique') else 'false'},\n"
            f"    t.parent_id = '{t.get('parent_id', '')}',\n"
            f"    t.platforms = {platforms},\n"
            f"    t.data_sources = {data_sources},\n"
            f"    t.tactics = {tactics},\n"
            f"    t.version = 'v15';"
        )
        lines.append("")

    # Add tactic nodes
    lines.append("// === Tactics ===")
    lines.append("")
    tactics_list = [
        ("TA0001", "Initial Access", "initial-access", 1),
        ("TA0002", "Execution", "execution", 2),
        ("TA0003", "Persistence", "persistence", 3),
        ("TA0004", "Privilege Escalation", "privilege-escalation", 4),
        ("TA0005", "Defense Evasion", "defense-evasion", 5),
        ("TA0006", "Credential Access", "credential-access", 6),
        ("TA0007", "Discovery", "discovery", 7),
        ("TA0008", "Lateral Movement", "lateral-movement", 8),
        ("TA0009", "Collection", "collection", 9),
        ("TA0010", "Exfiltration", "exfiltration", 10),
        ("TA0011", "Command and Control", "command-and-control", 11),
        ("TA0040", "Impact", "impact", 12),
    ]
    for tid, name, short, order in tactics_list:
        lines.append(f"MERGE (:Tactic {{tactic_id: '{tid}', name: '{name}', short_name: '{short}', order: {order}}});")
    lines.append("")

    # Add relationships: subtechnique-of
    lines.append("// === Relationships: subtechnique-of ===")
    lines.append("")
    for rel in relationships:
        if rel["relationship_type"] == "subtechnique-of":
            source = id_map.get(rel["source_ref"], "")
            target = id_map.get(rel["target_ref"], "")
            if source and target:
                lines.append(
                    f"MATCH (a:Technique {{technique_id: '{source}'}}), "
                    f"(b:Technique {{technique_id: '{target}'}})\n"
                    f"MERGE (a)-[:SUB_TECHNIQUE_OF]->(b);"
                )
                lines.append("")

    return "\n".join(lines)


def import_to_neo4j(cypher: str, uri: str, user: str, password: str) -> int:
    """Import Cypher statements directly into Neo4j."""
    try:
        from neo4j import GraphDatabase
    except ImportError:
        logger.error("neo4j package not installed. Run: pip install neo4j")
        return 0

    driver = GraphDatabase.driver(uri, auth=(user, password))
    statements = [s.strip() for s in cypher.split(";") if s.strip() and not s.strip().startswith("//")]

    count = 0
    with driver.session() as session:
        for stmt in statements:
            try:
                session.run(stmt)
                count += 1
            except Exception as e:
                logger.warning("Failed statement: %s", str(e)[:100])

    driver.close()
    logger.info("Executed %d/%d Cypher statements", count, len(statements))
    return count


def main() -> None:
    parser = argparse.ArgumentParser(description="Import MITRE ATT&CK to Neo4j")
    parser.add_argument("--input", "-i", default="", help="Local STIX JSON file (default: download from GitHub)")
    parser.add_argument("--output", "-o", default="attck_import.cypher", help="Output Cypher file path")
    parser.add_argument("--neo4j-uri", default="", help="Neo4j bolt URI for direct import")
    parser.add_argument("--neo4j-user", default="neo4j", help="Neo4j username")
    parser.add_argument("--neo4j-password", default="password", help="Neo4j password")
    parser.add_argument("--stats-only", action="store_true", help="Only print statistics, don't generate Cypher")

    args = parser.parse_args()

    url = args.input or "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

    bundle = fetch_bundle(url)
    techniques = extract_techniques(bundle)
    relationships = extract_relationships(bundle)
    id_map = build_technique_id_map(techniques, bundle)

    print(f"Techniques: {len(techniques)}")
    print(f"  Sub-techniques: {sum(1 for t in techniques if t['is_subtechnique'])}")
    print(f"  Platforms: {set(p for t in techniques for p in t.get('platforms', []))}")
    print(f"Relationships: {len(relationships)}")
    print(f"  Subtechnique-of: {sum(1 for r in relationships if r['relationship_type'] == 'subtechnique-of')}")

    if args.stats_only:
        return

    cypher = generate_cypher_import(techniques, relationships, id_map)

    if args.neo4j_uri:
        count = import_to_neo4j(cypher, args.neo4j_uri, args.neo4j_user, args.neo4j_password)
        print(f"Imported {count} statements to Neo4j at {args.neo4j_uri}")

    with open(args.output, "w", encoding="utf-8") as f:
        f.write(cypher)
    print(f"Cypher script written to {args.output} ({len(cypher)} bytes)")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    main()
