"""Neo4j knowledge graph interface for AegisThreat.

Provides methods for querying the ATT&CK graph, importing data,
and performing BFS path expansion.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)


class KnowledgeGraph:
    """Neo4j-backed ATT&CK knowledge graph interface.

    Wrap all Cypher queries here so agents don't need to know graph internals.
    Falls back to in-memory adjacency maps when Neo4j is unavailable (MVP mode).
    """

    def __init__(self, uri: str = "", user: str = "", password: str = "", use_mock: bool = True) -> None:
        self._uri = uri
        self._user = user
        self._password = password
        self._driver: Any = None
        self._use_mock = use_mock

        if not use_mock and uri:
            self._connect()

    def _connect(self) -> None:
        """Establish connection to Neo4j."""
        try:
            from neo4j import GraphDatabase  # type: ignore[import-untyped]
            self._driver = GraphDatabase.driver(self._uri, auth=(self._user, self._password))
            self._driver.verify_connectivity()
            logger.info("Connected to Neo4j at %s", self._uri)
        except ImportError:
            logger.warning("neo4j package not installed; using mock graph")
            self._use_mock = True
        except Exception as e:
            logger.warning("Failed to connect to Neo4j: %s; using mock graph", e)
            self._use_mock = True

    def close(self) -> None:
        if self._driver:
            self._driver.close()

    # ── Queries ──────────────────────────────

    def expand_path(
        self,
        technique_ids: list[str],
        max_depth: int = 8,
        max_paths: int = 10,
    ) -> list[list[str]]:
        """Expand a set of technique IDs into possible attack paths via BFS.

        Args:
            technique_ids: Starting TTPs observed in the fragment.
            max_depth: Maximum path length (steps).
            max_paths: Maximum number of paths to return.

        Returns:
            List of paths, each a list of technique IDs.
        """
        if self._use_mock or not self._driver:
            return self._mock_bfs(technique_ids, max_depth)

        # Real Neo4j BFS query
        query = """
        MATCH path = (start:Technique)-[:FOLLOWED_BY*1..%d]->(end:Technique)
        WHERE start.technique_id IN $start_ids
        WITH path, [n IN nodes(path) | n.technique_id] AS steps
        RETURN steps, length(path) AS depth
        ORDER BY depth DESC, size(steps) DESC
        LIMIT $max_paths
        """ % max_depth

        with self._driver.session() as session:  # type: ignore[union-attr]
            result = session.run(query, start_ids=technique_ids, max_paths=max_paths)
            return [record["steps"] for record in result]

    def get_technique_neighbors(self, technique_id: str) -> list[str]:
        """Get TTPs that commonly follow or are followed by the given TTP."""
        if self._use_mock or not self._driver:
            return []
        query = """
        MATCH (t:Technique {technique_id: $tid})-[:FOLLOWED_BY]-(neighbor:Technique)
        RETURN DISTINCT neighbor.technique_id AS tid
        """
        with self._driver.session() as session:  # type: ignore[union-attr]
            return [r["tid"] for r in session.run(query, tid=technique_id)]

    def get_threat_actor_techniques(self, actor_id: str) -> list[dict[str, Any]]:
        """Get techniques used by a specific threat actor."""
        if self._use_mock or not self._driver:
            return []
        query = """
        MATCH (ta:ThreatActor {actor_id: $aid})-[:USES]->(t:Technique)
        RETURN t.technique_id AS tid, t.name AS name, t.tactic AS tactic
        """
        with self._driver.session() as session:  # type: ignore[union-attr]
            return [dict(r) for r in session.run(query, aid=actor_id)]

    def get_detection_coverage(self, technique_ids: list[str]) -> dict[str, list[str]]:
        """Check which techniques have detection rules and which are blind spots.

        Returns:
            Dict with 'covered' and 'blind_spot' keys, each a list of TTP IDs.
        """
        if self._use_mock or not self._driver:
            return {"covered": [], "blind_spot": technique_ids}

        query = """
        MATCH (t:Technique)<-[:DETECTS]-(d:DetectionRule)
        WHERE t.technique_id IN $tids
        RETURN DISTINCT t.technique_id AS tid
        """
        with self._driver.session() as session:  # type: ignore[union-attr]
            covered = [r["tid"] for r in session.run(query, tids=technique_ids)]
            blind = [t for t in technique_ids if t not in covered]
            return {"covered": covered, "blind_spot": blind}

    def search_similar_cases(
        self, technique_ids: list[str], limit: int = 5
    ) -> list[dict[str, Any]]:
        """Find historical attack cases with similar TTP patterns."""
        if self._use_mock or not self._driver:
            return []

        query = """
        MATCH (c:AttackCase)-[:INCLUDES]->(t:Technique)
        WHERE t.technique_id IN $tids
        WITH c, count(DISTINCT t) AS overlap
        ORDER BY overlap DESC
        LIMIT $limit
        MATCH (c)-[:INCLUDES]->(all_t:Technique)
        RETURN c.case_id AS case_id, c.name AS name, c.severity AS severity,
               collect(DISTINCT all_t.technique_id) AS techniques, overlap
        ORDER BY overlap DESC
        """
        with self._driver.session() as session:  # type: ignore[union-attr]
            return [dict(r) for r in session.run(query, tids=technique_ids, limit=limit)]

    def get_asset_criticality(self, hostname: str, ip_address: str = "") -> Optional[int]:
        """Get the criticality score (1-5) of an asset."""
        if self._use_mock or not self._driver:
            return None
        query = """
        MATCH (a:Asset)
        WHERE a.hostname = $hostname OR a.ip_address = $ip
        RETURN a.criticality AS criticality
        LIMIT 1
        """
        with self._driver.session() as session:  # type: ignore[union-attr]
            rec = session.run(query, hostname=hostname, ip=ip_address).single()
            return rec["criticality"] if rec else None

    # ── Mock BFS (MVP without Neo4j) ─────────

    def _mock_bfs(self, technique_ids: list[str], max_depth: int) -> list[list[str]]:
        """In-memory BFS using the hardcoded adjacency map from TracingAgent."""
        # Re-use the adjacency map from the tracing agent to avoid duplication
        from aegis.agents.tracing import TracingAgent
        adj = TracingAgent._get_attck_adjacency(TracingAgent)

        paths: list[list[str]] = []
        for tid in technique_ids:
            if tid not in adj:
                paths.append([tid])
                continue
            queue: list[tuple[str, list[str], int]] = [(tid, [tid], 0)]
            while queue:
                current, path, depth = queue.pop(0)
                if depth >= max_depth:
                    paths.append(path)
                    continue
                neighbors = adj.get(current, [])
                if not neighbors:
                    paths.append(path)
                    continue
                extended = False
                for nid in neighbors:
                    if nid not in path:
                        queue.append((nid, path + [nid], depth + 1))
                        extended = True
                if not extended:
                    paths.append(path)

        # Deduplicate
        seen: set[str] = set()
        unique: list[list[str]] = []
        for p in paths:
            k = "→".join(p)
            if k not in seen:
                seen.add(k)
                unique.append(p)
        return sorted(unique, key=len, reverse=True)[:10]
