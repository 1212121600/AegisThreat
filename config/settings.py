"""Configuration management for AegisThreat.

Loads settings from YAML config files and environment variables.
Supports per-environment overrides (dev, staging, prod).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional

import yaml

# ──────────────────────────────────────────────
# Default Configuration
# ──────────────────────────────────────────────

DEFAULT_CONFIG: dict[str, Any] = {
    "environment": "dev",
    "bus": {
        "backend": "memory",  # "memory" | "kafka"
        "kafka": {
            "bootstrap_servers": "localhost:9092",
            "client_id": "aegis-threat",
        },
    },
    "agents": {
        "detection": {
            "window_minutes": 30,
            "min_alerts_per_fragment": 3,
        },
        "tracing": {
            "max_chain_depth": 8,
            "top_k_paths": 3,
            "enable_llm_verification": False,
        },
        "defense": {
            "max_debate_rounds": 3,
            "enable_mcts": False,
            "enable_debate": False,
        },
    },
    "knowledge_graph": {
        "neo4j_uri": "bolt://localhost:7687",
        "neo4j_user": "neo4j",
        "neo4j_password": "password",
        "use_mock": True,
    },
    "llm": {
        "provider": "openai",  # "openai" | "vllm" | "ollama"
        "api_key": "",
        "api_base": "https://api.openai.com/v1",
        "model": "gpt-4o",
        "temperature": 0.1,
        "max_tokens": 2048,
    },
    "vector_store": {
        "backend": "memory",  # "memory" | "milvus" | "pgvector"
        "milvus_host": "localhost",
        "milvus_port": 19530,
    },
    "server": {
        "host": "0.0.0.0",
        "port": 8000,
        "cors_origins": ["*"],
    },
    "logging": {
        "level": "INFO",
        "format": "json",  # "json" | "console"
    },
    "security": {
        "message_signing_enabled": False,
        "human_approval_required": True,
        "max_auto_actions": 0,  # 0 = no automatic execution
        "audit_log_path": "logs/audit.log",
    },
}


class Config:
    """Singleton configuration loaded from YAML + env vars."""

    _instance: Optional[Config] = None
    _data: dict[str, Any] = {}

    def __init__(self, config_path: str = "") -> None:
        self._data = dict(DEFAULT_CONFIG)  # shallow copy defaults

        if config_path:
            self._load_yaml(config_path)
        else:
            self._load_default_paths()

        self._apply_env_overrides()

    @classmethod
    def load(cls, config_path: str = "") -> Config:
        if cls._instance is None:
            cls._instance = Config(config_path)
        return cls._instance

    @classmethod
    def get(cls, key: str, default: Any = None) -> Any:
        """Convenience: Config.get('bus.backend', 'memory')"""
        if cls._instance is None:
            cls._instance = Config()
        return cls._instance._get_nested(key, default)

    def _load_yaml(self, path: str) -> None:
        p = Path(path)
        if not p.exists():
            return
        with open(p, "r", encoding="utf-8") as f:
            overrides = yaml.safe_load(f) or {}
        self._deep_merge(self._data, overrides)

    def _load_default_paths(self) -> None:
        search_paths = [
            Path("config/agent_config.yaml"),
            Path("config/agent_config.yml"),
            Path("../config/agent_config.yaml"),
        ]
        for p in search_paths:
            if p.exists():
                self._load_yaml(str(p))
                return

    def _apply_env_overrides(self) -> None:
        """Override config from environment variables (AEGIS_ prefix)."""
        env_map = {
            "AEGIS_ENV": "environment",
            "AEGIS_BUS_BACKEND": "bus.backend",
            "AEGIS_KAFKA_SERVERS": "bus.kafka.bootstrap_servers",
            "AEGIS_NEO4J_URI": "knowledge_graph.neo4j_uri",
            "AEGIS_NEO4J_USER": "knowledge_graph.neo4j_user",
            "AEGIS_NEO4J_PASSWORD": "knowledge_graph.neo4j_password",
            "AEGIS_LLM_API_KEY": "llm.api_key",
            "AEGIS_LLM_MODEL": "llm.model",
            "AEGIS_SERVER_PORT": "server.port",
            "AEGIS_LOG_LEVEL": "logging.level",
        }
        for env_key, config_path in env_map.items():
            val = os.environ.get(env_key)
            if val:
                self._set_nested(config_path, self._coerce(val))

    @staticmethod
    def _coerce(val: str) -> Any:
        if val.lower() in ("true", "yes", "1"):
            return True
        if val.lower() in ("false", "no", "0"):
            return False
        try:
            return int(val)
        except ValueError:
            pass
        return val

    def _get_nested(self, key: str, default: Any = None) -> Any:
        parts = key.split(".")
        node = self._data
        for p in parts:
            if isinstance(node, dict):
                node = node.get(p)
                if node is None:
                    return default
            else:
                return default
        return node

    def _set_nested(self, key: str, value: Any) -> None:
        parts = key.split(".")
        node = self._data
        for p in parts[:-1]:
            if p not in node:
                node[p] = {}
            node = node[p]
        node[parts[-1]] = value

    @staticmethod
    def _deep_merge(base: dict, overrides: dict) -> None:
        for key, value in overrides.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                Config._deep_merge(base[key], value)
            else:
                base[key] = value
