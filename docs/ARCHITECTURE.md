# AegisThreat Architecture

## System Overview

```
                        +-------------------------+
                        |  Command Center (API)    |
                        |  FastAPI + WebSocket     |
                        +----+--------+--------+---+
                             |        |        |
              +--------------+--+  +--+-----+  +--+-----------+
              |  threat.fragment|  |threat.  |  |threat.       |
              |                 |  |chain    |  |decision      |
        +-----v------+   +------v--+  +------v--+  +----------v--+
        | Detection  |   | Tracing  |  | Defense  |  | Command    |
        | Agent      |-->| Agent    |->| Agent    |->| Center     |
        +------------+   +---------+   +----------+  +-------------+
                             |    ^          |    ^
                             |    |          |    |
                             +----+----------+----+
                             |  threat.debate   |
                             +------------------+
```

## Data Flow

1. **Raw Alerts** → SIEM/EDR → Detection Agent (`ingest_alert`)
2. **AttackFragment** → `threat.fragment` → Tracing Agent → AttackChain
3. **AttackChain** → `threat.chain` → Defense Agent → DecisionScript
4. **DecisionScript** → `threat.decision` → Command Center → Human Approval

## Agent Design

| Agent | Input | Output | Key Algorithm |
|-------|-------|--------|---------------|
| Detection | Raw alerts | AttackFragment | Dual-window clustering + rule-based TTP mapping |
| Tracing | AttackFragment | AttackChain | Anchor-based BFS + path pruning + heuristic scoring |
| Defense | AttackChain | DecisionScript | TTP→mitigation mapping + quantified business impact |

## Knowledge Graph (Neo4j)

Node types: Technique, Tactic, Asset, Service, Application, User, ThreatActor, IOC, DetectionRule, Mitigation, AttackCase

Key relationships: FOLLOWED_BY, REQUIRES, DETECTS, USES, COUNTERS, AFFECTED

## ThreatBus (Kafka)

Topics: threat.fragment, threat.chain, threat.decision, threat.debate, threat.heartbeat, threat.command, threat.dlq

Message format: ThreatEvent envelope (event_id, event_type, producer, correlation_id, timestamp, payload)

## Phase Status

- **Phase 0** (Complete): Project scaffold, core models, agent framework, synthetic data, demo
- **Phase 1** (Current): Dual-window clustering, anchor-BFS, quantified impact, security hardening
- **Phase 2** (Planned): DBSCAN, GraphSAGE, Bayesian, LLM verification, MCTS, multi-round debate
- **Phase 3** (Planned): Real SIEM integration, SOAR execution, production deployment

See `ARCHITECTURE_AUDIT.md` for the detailed audit and fix log.
