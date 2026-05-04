"""DBSCAN-based real-time alert clustering (Phase 2).

This module replaces the MVP's rule-based clustering with density-based
spatial clustering. Each alert is vectorized (FastText / SecureBERT) and
DBSCAN groups them into AttackFragments based on semantic proximity.

Dependencies (Phase 2): scikit-learn, sentence-transformers
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import numpy as np

logger = logging.getLogger(__name__)


class AlertClusterer:
    """DBSCAN-based alert clustering for AttackFragment generation.

    Phase 1: Not used (rule-based clustering is the MVP default).
    Phase 2: Replaces the rule-based approach with ML clustering.
    """

    def __init__(
        self,
        eps: float = 0.5,
        min_samples: int = 3,
        vectorizer_model: str = "sentence-transformers/all-MiniLM-L6-v2",
    ) -> None:
        self._eps = eps
        self._min_samples = min_samples
        self._vectorizer_model = vectorizer_model
        self._embedder: Any = None

    def _ensure_embedder(self) -> None:
        """Lazy-load the sentence transformer model."""
        if self._embedder is not None:
            return
        try:
            from sentence_transformers import SentenceTransformer
            self._embedder = SentenceTransformer(self._vectorizer_model)
            logger.info("Loaded vectorizer: %s", self._vectorizer_model)
        except ImportError:
            logger.warning("sentence-transformers not installed; using random vectors")

    def _vectorize(self, alerts: list[dict[str, Any]]) -> np.ndarray:
        """Convert alerts to dense vectors.

        Each alert is serialized as: rule_name | action | hostname | source_ip
        """
        self._ensure_embedder()
        texts = []
        for a in alerts:
            text = f"{a.get('rule_name', '')} | {a.get('action', '')} | {a.get('hostname', '')} | {a.get('source_ip', '')}"
            texts.append(text)

        if self._embedder:
            return self._embedder.encode(texts)
        # Fallback: random vectors for testing
        return np.random.randn(len(texts), 384)

    def cluster(self, alerts: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
        """Cluster alerts using DBSCAN.

        Args:
            alerts: List of normalized alert dicts.

        Returns:
            List of clusters, each cluster is a list of alert dicts.
            Unclustered alerts (noise) are discarded.
        """
        if len(alerts) < self._min_samples:
            logger.debug("Too few alerts (%d) for clustering", len(alerts))
            return [alerts] if alerts else []

        vectors = self._vectorize(alerts)

        try:
            from sklearn.cluster import DBSCAN
            clusterer = DBSCAN(eps=self._eps, min_samples=self._min_samples, metric="cosine")
            labels = clusterer.fit_predict(vectors)
        except ImportError:
            logger.warning("scikit-learn not installed; returning single cluster")
            return [alerts]

        clusters: dict[int, list[dict[str, Any]]] = {}
        for i, label in enumerate(labels):
            if label == -1:  # Noise
                continue
            clusters.setdefault(int(label), []).append(alerts[i])

        logger.info("DBSCAN: %d alerts → %d clusters (%d noise)",
                     len(alerts), len(clusters),
                     sum(1 for l in labels if l == -1))

        return list(clusters.values())


class SecureBERTVectorizer:
    """Security-domain BERT vectorizer for alert text (Phase 2+).

    Uses SecureBERT or CyBERT for domain-specific embeddings.
    Falls back to sentence-transformers if not installed.
    """

    def __init__(self, model_name: str = "ehsanaghaei/SecureBERT") -> None:
        self._model_name = model_name
        self._model: Any = None

    def encode(self, texts: list[str]) -> np.ndarray:
        """Encode texts to security-domain vectors."""
        logger.warning("SecureBERT vectorizer not yet implemented (Phase 2+)")
        return np.random.randn(len(texts), 768)
