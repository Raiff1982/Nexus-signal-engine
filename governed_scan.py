#!/usr/bin/env python3
"""
governed_scan.py

Unified CLI for NexisSignalEngine + HoaxFilter + Immortal Aegis Failsafe

Usage:
    python governed_scan.py --db signals.db "text to analyze"
    python governed_scan.py --db signals.db --news --source "https://example.com/article"

Modes:
    • Default:  general input scan
    • --news:   enables hoax/news pipeline
    • --audit:  shows memory health & feedback stats
"""

import argparse
import json
import sys
import logging

from Immortal_nexus import GovernedNexisEngine
from immortal_aegis import AegisImmortalCouncil

logger = logging.getLogger("GovernedScan")
if not logger.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
    )


def run_scan(db_path: str, text: str, is_news: bool = False, source_url: str = None) -> None:
    """Run a Nexis+Aegis scan on input text."""
    engine = GovernedNexisEngine(memory_path=db_path)
    if is_news:
        result = engine.process_news(text, source_url=source_url)
    else:
        result = engine.process(text)

    print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))


def run_audit(db_path: str) -> None:
    """Show Aegis memory and feedback audit summary."""
    council = AegisImmortalCouncil()
    health = council.memory.compute_health()
    audit = council.memory.audit(limit=25)
    logger.info("===== IMMORTAL AEGIS AUDIT =====")
    logger.info(f"Health: {health}")
    logger.info(f"Entries: {len(council.memory._store)} | Snapshots: {len(council.memory.snapshots)}")
    for key, meta in audit.items():
        logger.info(f"{key}: {meta}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Nexis + HoaxFilter + Immortal Aegis CLI")
    parser.add_argument("text", nargs="*", help="Text to analyze (or stdin if empty)")
    parser.add_argument("--db", default="signals.db", help="SQLite memory DB path")
    parser.add_argument("--news", action="store_true", help="Use hoax/news processing pipeline")
    parser.add_argument("--source", default=None, help="Optional source URL for news mode")
    parser.add_argument("--audit", action="store_true", help="Show Aegis audit instead of running a scan")
    args = parser.parse_args()

    if args.audit:
        run_audit(args.db)
        return

    if args.text:
        text = " ".join(args.text)
    else:
        text = sys.stdin.read().strip()

    if not text:
        logger.error("No input text provided.")
        sys.exit(1)

    run_scan(args.db, text, args.news, args.source)


if __name__ == "__main__":
    main()
