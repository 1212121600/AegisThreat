"""AegisThreat CLI — demo runner and management commands.

Usage:
    python -m aegis.cli demo                    # Run end-to-end demo
    python -m aegis.cli demo --scenario brute-force-lateral  # Specific scenario
    python -m aegis.cli server                  # Start API server
    python -m aegis.cli data-gen --list         # List available scenarios
    python -m aegis.cli data-gen --scenario phishing-to-exfil --output alerts.json
"""

from __future__ import annotations

import json
import logging
import sys
import time
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)


def cmd_demo(scenario: str = "phishing-to-exfil") -> None:
    """Run the full AegisThreat pipeline in demo mode.

    Generates synthetic attack data, feeds it to the Detection Agent,
    and prints the resulting AttackFragments, AttackChains, and DecisionScripts.
    """
    from aegis.core.bus import InMemoryBus, Topics
    from aegis.core.models import AttackChain, AttackFragment, DecisionScript
    from aegis.agents.detection import DetectionAgent
    from aegis.agents.tracing import TracingAgent
    from aegis.agents.defense import DefenseAgent
    from tools.data_generator import DataGenerator

    print("=" * 70)
    print("  AegisThreat — Multi-Agent APT Attack Chain Demo")
    print("=" * 70)
    print()

    # Setup
    bus = InMemoryBus()
    fragments: list[AttackFragment] = []
    chains: list[AttackChain] = []
    decisions: list[DecisionScript] = []

    bus.subscribe(Topics.FRAGMENT, lambda e: fragments.append(
        AttackFragment(**e.payload) if isinstance(e.payload, dict) else e.payload))
    bus.subscribe(Topics.CHAIN, lambda e: chains.append(
        AttackChain(**e.payload) if isinstance(e.payload, dict) else e.payload))
    bus.subscribe(Topics.DECISION, lambda e: decisions.append(
        DecisionScript(**e.payload) if isinstance(e.payload, dict) else e.payload))

    detection = DetectionAgent(bus=bus)
    tracing = TracingAgent(bus=bus)
    defense = DefenseAgent(bus=bus)

    detection.start()
    tracing.start()
    defense.start()

    # Generate synthetic alerts with current timestamps
    from datetime import datetime, timedelta, timezone
    gen = DataGenerator(base_time=datetime.now(timezone.utc) - timedelta(minutes=5))
    alerts = gen.generate_from_scenario(scenario)
    api_alerts = gen.to_api_batch(alerts)

    print(f"Scenario: {scenario}")
    print(f"Generated {len(api_alerts)} alerts simulating an APT attack chain")
    print(f"Time span: {alerts[0]['timestamp']} → {alerts[-1]['timestamp']}")
    print()

    # Feed alerts one by one to simulate real-time ingestion
    print("Feeding alerts to Detection Agent...")
    for i, alert in enumerate(api_alerts):
        detection.ingest_and_publish(alert)
        time.sleep(0.1)  # Small delay for message propagation
        if (i + 1) % 5 == 0:
            print(f"  [{i+1}/{len(api_alerts)}] alerts processed...")

    # Force flush: submit one more alert to trigger final fragment
    detection.ingest_and_publish({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "rule_name": "demo_complete",
        "source_ip": "0.0.0.0",
        "action": "end_of_demo",
        "severity": "low",
    })

    time.sleep(1)  # Allow async processing

    # ── Results ──────────────────────────────
    print()
    print("─" * 70)
    print("RESULTS")
    print("─" * 70)
    print()

    print(f"Attack Fragments Generated: {len(fragments)}")
    for frag in fragments:
        print(f"  [{frag.fragment_id}] confidence={frag.confidence:.2f}")
        print(f"    Summary: {frag.summary[:120]}")
        print(f"    TTPs: {[t.technique_id for t in frag.suspected_ttps]}")
        print(f"    Entities: {[(e.entity_type, e.value) for e in frag.entities]}")
        print()

    print(f"Attack Chains Generated: {len(chains)}")
    for chain in chains:
        print(f"  [{chain.chain_id}] confidence={chain.overall_confidence:.2f} steps={chain.step_count}")
        path = " → ".join(n.technique_id for n in sorted(chain.nodes, key=lambda n: n.step))
        print(f"    Path: {path}")
        print(f"    Tactics: {' → '.join(n.tactic for n in sorted(chain.nodes, key=lambda n: n.step) if n.tactic)}")
        pred = " → ".join(p.technique_id for p in chain.predicted_next_steps)
        print(f"    Predicted next: {pred}")
        print()

    print(f"Defense Decisions Generated: {len(decisions)}")
    for dec in decisions:
        print(f"  [{dec.decision_id}] steps={dec.step_count} impact={dec.business_impact.score}/100")
        for step in dec.steps:
            print(f"    {step.order}. {step.action.value}: {step.reason[:80]}")
        print(f"    Human approval required: {dec.requires_human_approval}")
        print()

    # Cleanup
    defense.stop()
    tracing.stop()
    detection.stop()

    print("─" * 70)
    print("Demo complete. All agents shut down.")
    print("─" * 70)


def cmd_server() -> None:
    """Start the AegisThreat API server."""
    from aegis.api.server import main
    main()


def cmd_data_gen(args: list[str]) -> None:
    """Run the synthetic data generator."""
    from tools.data_generator import main as dg_main
    import sys as _sys
    _sys.argv = ["data_generator.py"] + args
    dg_main()


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="AegisThreat CLI")
    sub = parser.add_subparsers(dest="command", help="Command")

    # Demo
    demo_parser = sub.add_parser("demo", help="Run end-to-end demo")
    demo_parser.add_argument("--scenario", "-s", default="phishing-to-exfil",
                             choices=["phishing-to-exfil", "brute-force-lateral",
                                      "webapp-exploit", "supply-chain", "all"])

    # Server
    sub.add_parser("server", help="Start API server")

    # Data generator (pass-through)
    sub.add_parser("data-gen", help="Synthetic data generator")

    args, remaining = parser.parse_known_args()

    if args.command == "demo":
        cmd_demo(scenario=args.scenario)
    elif args.command == "server":
        cmd_server()
    elif args.command == "data-gen":
        cmd_data_gen(remaining)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

