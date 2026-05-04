# AegisThreat API Reference

Base URL: `http://localhost:8000`

## Endpoints

### Alerts

| Method | Path | Description |
|--------|------|-------------|
| POST | `/alerts` | Submit a single raw alert |
| POST | `/alerts/batch` | Submit multiple alerts at once |

**POST /alerts**
```json
{
  "timestamp": "2026-05-04T10:00:00Z",
  "rule_name": "brute_force",
  "source_ip": "1.2.3.4",
  "destination_ip": "10.0.0.5",
  "hostname": "server01",
  "username": "admin",
  "action": "500 failed login attempts",
  "severity": "high"
}
```

### Fragments

| Method | Path | Description |
|--------|------|-------------|
| GET | `/fragments` | List fragments (default 50, max 500) |
| GET | `/fragments/{id}` | Get specific fragment |

### Chains

| Method | Path | Description |
|--------|------|-------------|
| GET | `/chains` | List chains (default 50, max 500) |
| GET | `/chains/{id}` | Get specific chain |

### Decisions

| Method | Path | Description |
|--------|------|-------------|
| GET | `/decisions` | List decisions |
| GET | `/decisions/{id}` | Get specific decision |
| POST | `/decisions/{id}/approve` | Approve or reject a decision |

**POST /decisions/{id}/approve**
```json
{
  "approved": true,
  "approved_by": "analyst-jdoe",
  "comment": "All actions verified against runbook"
}
```

### System

| Method | Path | Description |
|--------|------|-------------|
| GET | `/stats` | System statistics |
| GET | `/health` | Health check |

### WebSocket

| Path | Description |
|------|-------------|
| `/ws` | Real-time event stream |
| `/ws?topics=fragment,decision` | Filter by event types |

WebSocket messages:
```json
{"type": "fragment", "payload": {...}}
{"type": "chain", "payload": {...}}
{"type": "decision", "payload": {...}}
{"type": "connected", "conn_id": "ws-1", "message": "Connected"}
{"type": "pong"}
```
