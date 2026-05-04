<p align="center">
  <h1 align="center">AegisThreat</h1>
  <p align="center">Multi-Agent APT Attack Chain Tracing & Adaptive Defense System</p>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-0.2.0-blue" alt="Version">
  <img src="https://img.shields.io/badge/python-3.10+-green" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-brightgreen" alt="License">
  <img src="https://img.shields.io/badge/status-Phase%200%20MVP-orange" alt="Status">
</p>

---

## What is AegisThreat?

AegisThreat is an **AI-native security operations platform** where three collaborative agents work together to automate the hardest parts of threat hunting: turning thousands of noisy alerts into coherent attack stories, predicting the attacker's next move, and recommending precise defensive actions.

**The problem it solves**: Enterprises generate tens of thousands of security alerts daily. APT attacks unfold across 6-12 distinct steps over 48 hours. Human analysts spend 4-8 hours manually piecing together a single attack chain. By the time they finish, the attacker has already moved on.

**What AegisThreat does**: Three specialized AI agents communicate over a shared ThreatBus, each handling one part of the pipeline:

```
Raw Alerts ──→ [Detection Agent] ──→ AttackFragment
                                       │
                                  [Tracing Agent] ──→ AttackChain (6-12 steps)
                                                       │
                                                  [Defense Agent] ──→ DecisionScript
```

| Agent | Role | Input | Output |
|-------|------|-------|--------|
| **Detection** | Alert Fusion | SIEM/EDR alerts | `AttackFragment` — clustered alerts with suspected ATT&CK TTPs |
| **Tracing** | Chain Reasoning | AttackFragment | `AttackChain` — full kill chain from initial access to impact, plus predicted next steps |
| **Defense** | Adaptive Response | AttackChain | `DecisionScript` — prioritized SOAR actions with business impact assessment |

All agents communicate through a shared **ThreatBus** (Kafka or in-memory), publishing standardized **Threat Event Protocol** (TEP) messages.

---

## Quick Start

### Prerequisites

- Python 3.10+
- Windows / Linux / macOS

### Install & Run Demo

```bash
# Clone
git clone https://github.com/YOUR_USER/AegisThreat.git
cd AegisThreat

# Install dependencies
pip install pydantic fastapi uvicorn numpy pyyaml websockets

# Run the end-to-end demo
python -m aegis.cli demo --scenario phishing-to-exfil
```

**Expected output** — the full pipeline runs on synthetic attack data:

```
Attack Fragments Generated: 9
  [frag-xxx] confidence=0.85 TTPs: [T1566, T1059, T1071, T1003, T1048]

Attack Chains Generated: 9
  Path: T1566 → T1059 → T1003 → T1021 → T1083 → T1048
  Predicted next: T1485 (Data Destruction)

Defense Decisions Generated: 9
  1. ISOLATE_HOST → ws-finance-07 (Credential dump)
  2. BLOCK_IP → 185.220.101.34 (C2 communication)
  3. RESET_CREDENTIAL → jwilson (Compromised account)
  Human approval required: Yes
```

### Launch the API Server

```bash
python -m aegis.cli server
# Open http://localhost:8000/docs for Swagger UI
```

### Open the Dashboard

```bash
start dashboard.html
# Or open it directly in your browser
```

The dashboard connects to the API server via WebSocket for real-time updates and provides:
- Manual alert submission form
- One-click scenario execution (4 preset APT attack patterns)
- D3.js attack chain visualization
- Decision approval/rejection workflow

---

## Features

### Implemented 

| Feature | Description |
|---------|-------------|
| **Dual-window alert clustering** | 5-minute fast-track for critical alerts + 30-minute full window |
| **Alert deduplication** | Entity-hash-based dedup across SIEM/EDR/NGFW sensors |
| **Schema normalization** | Maps Splunk, SentinelOne, Suricata, Zeek fields to canonical format |
| **Rule-based TTP mapping** | 30+ alert pattern → ATT&CK technique ID mappings |
| **Anchor-based BFS path reasoning** | Expands observed TTPs into 6-step attack chains through the ATT&CK graph |
| **Path pruning** | Platform consistency + tactic ordering + data source sharing filters |
| **Adversary simulation** | 3-tier red team strategies (Naive / Moderate / APT) with probabilistic 0-day fallback |
| **Defense arbitration** | Quantitative evaluation of defense proposals by coverage, residual risk, and business impact |
| **SQLite persistence** | Attack fragments, chains, and decisions survive server restarts |
| **WebSocket real-time push** | Live event streaming to connected dashboards |
| **API authentication** | API key / Bearer token with constant-time comparison |
| **SOAR playbook export** | Human-readable action plans with executable commands |
| **Synthetic data generator** | 4 realistic APT attack scenarios for testing and demonstration |
| **Single-file dashboard** | React + D3.js HTML file, no build step required |


---

## Architecture

```
                         ┌──────────────────────────┐
                         │   Command Center (API)     │
                         │   FastAPI + WebSocket       │
                         │   + SQLite Persistence      │
                         └────┬──────┬──────┬─────────┘
                              │      │      │
              ┌───────────────┼──────┼──────┼───────────────┐
              │               │      │      │               │
              ▼               ▼      ▼      ▼               ▼
    ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────┐
    │  Detection   │  │   Tracing   │  │   Defense   │  │ Command │
    │  Agent       │─►│   Agent     │─►│   Agent     │─►│ Center  │
    │  (fragment)  │  │   (chain)   │  │  (decision) │  │         │
    └─────────────┘  └─────────────┘  └─────────────┘  └─────────┘
         │                 │   ▲             │    ▲
         │                 │   │             │    │
         └─────────────────┴───┴─────────────┴────┘
                     ThreatBus (threat.debate)
```

### Threat Event Protocol (TEP)

All agent-to-agent communication uses a standardized JSON envelope:

```json
{
  "event_id": "evt-a1b2c3d4",
  "event_type": "fragment",
  "producer": "detection",
  "correlation_id": "frag-xxx",
  "timestamp": "2026-05-04T10:00:00Z",
  "payload": { ... }
}
```

### Attack Scenarios (Built-in Demo Data)

| Scenario | TTP Chain | Steps | Pattern |
|----------|-----------|-------|---------|
| **Phishing → Exfiltration** | T1566→T1204→T1059→T1071→T1003→T1021→T1083→T1048 | 9 | APT29-style spear-phishing campaign |
| **Brute Force → Destruction** | T1110→T1078→T1021→T1003→T1485 | 8 | VPN brute force leading to ransomware |
| **Web Exploit → Data Theft** | T1190→T1059→T1071→T1003→T1048 | 5 | CVE exploit with reverse shell |
| **Supply Chain → Exfiltration** | T1195→T1071→T1547→T1083→T1560→T1048 | 6 | Compromised update with long dwell time |

---

## Project Structure

```
AegisThreat/
├── aegis/
│   ├── agents/           # Three AI agents
│   │   ├── base.py       # Abstract agent with lifecycle + bus integration
│   │   ├── detection.py  # Alert fusion → AttackFragment
│   │   ├── tracing.py    # BFS path reasoning → AttackChain
│   │   └── defense.py    # TTP→mitigation mapping → DecisionScript
│   ├── core/
│   │   ├── models.py     # Canonical data models (TEP protocol)
│   │   ├── bus.py        # InMemoryBus + KafkaBus with DLQ
│   │   ├── alert_dedup.py # Dedup + normalization + severity filter
│   │   ├── persistence.py # SQLite storage layer
│   │   └── security.py   # HMAC signing + replay protection
│   ├── inference/
│   │   ├── path_pruner.py # Anchor-based BFS + pruning rules
│   │   ├── alert_cluster.py # DBSCAN clustering (Phase 2 stub)
│   │   ├── path_scorer.py  # GraphSAGE scoring (Phase 2 stub)
│   │   └── bayesian.py     # Bayesian network (Phase 2 stub)
│   ├── sandbox/
│   │   ├── red_team.py   # Independent attacker simulation
│   │   ├── arbitrator.py # Quantitative defense evaluation
│   │   ├── mcts.py       # Monte Carlo tree search (Phase 2 stub)
│   │   └── debate.py     # Multi-round debate engine (Phase 2 stub)
│   ├── knowledge/
│   │   ├── graph.py      # Neo4j interface with mock fallback
│   │   ├── schema.cypher # Full ATT&CK knowledge graph schema
│   │   └── attck_loader.py # MITRE ATT&CK STIX importer
│   ├── connectors/
│   │   ├── siem.py       # Splunk/Elastic/SentinelOne/Suricata/Zeek adapters
│   │   └── soar.py       # SOAR playbook builder + command generator
│   ├── llm/
│   │   └── client.py     # Unified LLM client (OpenAI/vLLM/Ollama) + template fallback
│   ├── api/
│   │   ├── server.py     # FastAPI server v2 with WebSocket + persistence
│   │   ├── auth.py       # API key / Bearer token authentication
│   │   ├── websocket.py  # Real-time event broadcasting
│   │   └── routes/       # Modular REST endpoints
│   └── cli.py            # CLI: demo, server, data-gen
├── tools/
│   ├── data_generator.py # Synthetic APT attack data (4 scenarios)
│   └── attck_importer.py # ATT&CK STIX → Neo4j import CLI
├── tests/                # 4 test files, 60+ test cases
├── config/               # YAML configuration + audit logging
├── docker/               # Docker Compose for Kafka + Neo4j
├── docs/                 # Architecture, API reference, readiness assessment
├── dashboard.html        # Single-file React + D3.js dashboard
├── pyproject.toml        # Python package configuration
└── requirements.txt      # Dependency list
```

---

## Usage Examples

### Generate Synthetic Attack Data

```bash
# List available scenarios
python tools/data_generator.py --list

# Generate a scenario as API-ready JSON
python tools/data_generator.py --scenario phishing-to-exfil --format api --output alerts.json
```

### Use Individual Modules as Libraries

```python
# Attack path reasoning (no external deps)
from aegis.inference.path_pruner import anchor_based_bfs

adjacency = {"T1566": ["T1059", "T1204"], "T1059": ["T1003"], ...}
paths = anchor_based_bfs(adjacency, observed_ttps=["T1566"], max_depth=6)
for path in paths:
    print(" → ".join(path))

# Adversary simulation
from aegis.sandbox.red_team import RedTeamSimulator, APT_ATTACKER
sim = RedTeamSimulator()
next_move = sim.simulate_response("T1059", APT_ATTACKER)

# Defense evaluation
from aegis.sandbox.arbitrator import Arbitrator
arb = Arbitrator()
verdict = arb.evaluate(1, ["T1566","T1059","T1003"], defense_actions, impact=30)
print(f"Coverage: {verdict.coverage_score:.0%}, Accepted: {verdict.defense_accepted}")
```

### Import ATT&CK Data into Neo4j

```bash
# Start Neo4j
docker-compose -f docker/docker-compose.yml up -d neo4j

# Import ATT&CK STIX data
python tools/attck_importer.py --neo4j-uri bolt://localhost:7687 --neo4j-user neo4j --neo4j-password password
```

---


