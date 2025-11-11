#!/usr/bin/env python3
"""
nexis_aegis_bridge.py

Bridge between NexisSignalEngine and the Immortal Jellyfish Aegis Core.

- Wraps NexisSignalEngine with a regenerative, virtue-aware failsafe.
- Softens or hardens verdicts based on volatility and virtue, instead of
  always forcing "blocked".
- Feeds Aegis decisions back into Nexis memory as feedback entries.
"""

import logging
from datetime import datetime, UTC
from typing import Any, Dict, Optional

from nexis_signal_engine import NexisSignalEngine
from immortal_aegis import AegisImmortalCouncil, AgentResult, AegisConfig

logger = logging.getLogger("NexisAegisBridge")
if not logger.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
    )


class GovernedNexisEngine:
    """
    Governed wrapper around NexisSignalEngine:

    - Uses NexisSignalEngine for primary reasoning, risk, and misinformation logic.
    - Summarizes each record into a compact "governance sentence".
    - Feeds that into AegisImmortalCouncil for virtue/health assessment.
    - Uses Aegis decisions to:
      * annotate each record with aegis_decision and aegis_summary_text
      * optionally soften/harden verdict (allowed → review → flagged → blocked)
      * write Aegis feedback into Nexis memory (closed ethical loop).
    """

    def __init__(
        self,
        memory_path: str,
        entropy_threshold: float = 0.08,
        config_path: str = "config.json",
        max_memory_entries: int = 10000,
        memory_ttl_days: int = 30,
        fuzzy_threshold: int = 80,
        aegis_config: Optional[AegisConfig] = None,
    ):
        self.engine = NexisSignalEngine(
            memory_path=memory_path,
            entropy_threshold=entropy_threshold,
            config_path=config_path,
            max_memory_entries=max_memory_entries,
            memory_ttl_days=memory_ttl_days,
            fuzzy_threshold=fuzzy_threshold,
        )
        # Use provided AegisConfig if given; otherwise use defaults
        if aegis_config is not None:
            self.aegis = AegisImmortalCouncil(config=aegis_config)
        else:
            self.aegis = AegisImmortalCouncil()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _summarize_for_aegis(self, record: Dict[str, Any]) -> str:
        """
        Convert Nexis/Hoax state into a compact text string that Aegis can read.

        This is intentionally simple, deterministic, and explanation-friendly.
        """
        intent = record.get("intent_signature") or record.get("intent_warning") or {}
        misinfo = record.get("misinfo_heuristics", {}) or {}
        verdict = record.get("verdict", "unknown")
        src_note = misinfo.get("notes", {}).get("source", "none")

        suspicion = intent.get("suspicion_score", 0.0)
        entropy = intent.get("entropy_index", 0.0)
        volatility = intent.get("harmonic_volatility", 0.0)
        ethics = intent.get("ethical_alignment", "unknown")
        misinfo_score = misinfo.get("combined", 0.0)

        text = (
            f"Verdict {verdict}. "
            f"Suspicion score {suspicion:.3f}, entropy index {entropy:.3f}, "
            f"harmonic volatility {volatility:.3f}, ethics {ethics}. "
            f"Misinformation risk {misinfo_score:.3f}, source {src_note}."
        )
        return text

    def _apply_verdict_softening(
        self,
        record: Dict[str, Any],
        decision: Dict[str, Any],
    ) -> None:
        """
        Use Aegis decision to optionally upgrade/downgrade verdict severity.

        Severity ladder:
            allowed < review < flagged < blocked

        Logic:
        - Only reacts when Aegis action == "regenerated" (system stress).
        - Uses volatility + avg_virtue to choose a new verdict:
            severe → blocked
            moderate → flagged
            mild → review
        - Only overrides if new verdict is more severe than existing one.
        """
        action = decision.get("action")
        if action != "regenerated":
            return

        volatility = float(decision.get("volatility", 0.0))
        avg_virtue = float(decision.get("avg_virtue", 0.0))
        # Optional: require minimum density (enough internal history) before acting
        density = float(decision.get("density", 0.0))
        if density < 0.05:
            # Aegis memory is effectively empty; ignore this regeneration signal
            return

        # Determine target verdict based on instability profile (less twitchy)
        if volatility > 0.85 and avg_virtue < 0.3:
            target = "blocked"
            reason = "Immortal Aegis: severe instability → blocked"
        elif volatility > 0.65:
            target = "flagged"
            reason = "Immortal Aegis: moderate instability → flagged for review"
        elif volatility > 0.4:
            target = "review"
            reason = "Immortal Aegis: mild instability → human review requested"
        else:
            # Volatility too low to override a safe verdict
            return

        # Current verdict severity ordering
        severity = {
            "allowed": 1,
            "review": 2,
            "flagged": 3,
            "adaptive intervention": 4,
            "blocked": 4,
        }

        current = record.get("verdict", "allowed")
        current_level = severity.get(current, 1)
        target_level = severity.get(target, 1)

        # Only upgrade severity; never silently downgrade the engine's decision
        if target_level > current_level:
            record["verdict"] = target
            msg = record.get("message", "")
            suffix = f" [{reason}]"
            record["message"] = (msg + suffix).strip()

    def _feedback_to_nexis(
        self,
        record: Dict[str, Any],
        decision: Dict[str, Any],
    ) -> None:
        """
        Feed Aegis decision back into Nexis memory as a feedback record.

        This creates a closed ethical-learning loop:
        - Nexis sees where Aegis had to step in.
        - Future models or analysis can use this as a labeled correction stream.
        """
        feedback = {
            "aegis_action": decision.get("action"),
            "aegis_volatility": decision.get("volatility"),
            "aegis_avg_virtue": decision.get("avg_virtue"),
            "aegis_density": decision.get("density"),
            "timestamp": datetime.now(UTC).isoformat(),
            "original_hash": record.get("hash"),
            "original_verdict": record.get("verdict"),
        }

        key = f"aegis_feedback::{feedback['original_hash']}::{feedback['timestamp']}"
        try:
            # NexisSignalEngine.memory is a dict; _save_memory persists to SQLite
            self.engine.memory[key] = feedback
            self.engine._save_memory()
        except Exception as exc:
            logger.warning("Failed to persist Aegis feedback into Nexis memory: %s", exc)

    def _run_aegis(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """
        Full Aegis supervision path for a single record.
        """
        # 1) Build a governance summary
        summary_text = self._summarize_for_aegis(record)

        # 2) Run through Aegis council
        results = self.aegis.process(summary_text)
        meta: AgentResult = results["MetaCouncil"]
        decision = meta.data.get("decision", {})

        # 3) Attach to record
        record["aegis_summary_text"] = summary_text
        record["aegis_decision"] = decision

        # 4) Verdict softening/hardening
        self._apply_verdict_softening(record, decision)

        # 5) Feedback loop into Nexis memory
        self._feedback_to_nexis(record, decision)

        logger.info(
            "Aegis decision for hash=%s: %s",
            record.get("hash"),
            decision,
        )
        return record

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def process(self, input_signal: str) -> Dict[str, Any]:
        """
        Standard path (non-news) with Aegis supervision.
        """
        base = self.engine.process(input_signal)
        return self._run_aegis(base)

    def process_news(self, input_signal: str, source_url: Optional[str] = None) -> Dict[str, Any]:
        """
        News/claim path (HoaxFilter route) with Aegis supervision.
        """
        base = self.engine.process_news(input_signal, source_url=source_url)
        return self._run_aegis(base)
