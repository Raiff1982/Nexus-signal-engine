 # Immortal Aegis — Behavior and Tuning (README)

This short document explains how the Immortal Aegis interacts with the Nexis Signal Engine and how to tune its behavior.

Overview
--------
- Aegis (the "Immortal Jellyfish" council) monitors long-term memory health: volatility, density, and average virtue.
- The bridge (`Immortal_nexus.GovernedNexisEngine`) only intervenes when Aegis has executed a regenerative lifecycle event (action == "regenerated").
- This design makes Aegis a systemic safety layer — it does not override Nexis on single samples unless the system's overall health requires a correction.

Why this matters
-----------------
- Prevents per-sample noise: single messages that are unusual or ethically "unaligned" do not cause the system to escalate to human review.
- Keeps interventions meaningful: only when memory volatility crosses configured thresholds will Aegis revert or flag records.

Where to tune
-------------
- The configuration struct `AegisConfig` lives in `immortal_aegis.py` and contains the tuning fields:
  - `volatility_threshold`: when to trigger regeneration
  - `stability_threshold`: when to allow snapshot creation
  - `snapshot_ttl_days`: how long snapshots remain viable (days)
  - `density_threshold`: minimum memory density required for Aegis to act
  - `min_entries_for_snapshot`, `max_snapshots`

Examples
--------
Create a custom `AegisConfig` and pass it to `AegisImmortalCouncil` directly:

```python
from immortal_aegis import AegisConfig, AegisImmortalCouncil

cfg = AegisConfig(
    volatility_threshold=0.8,
    stability_threshold=0.1,
    snapshot_ttl_days=14,
    density_threshold=0.05,
    min_entries_for_snapshot=10,
    max_snapshots=20,
)

council = AegisImmortalCouncil(config=cfg)
```

Or construct the bridge and pass the same config so the bridge-backed CLI uses the tuned policy:

```python
from Immortal_nexus import GovernedNexisEngine
from immortal_aegis import AegisConfig

cfg = AegisConfig(volatility_threshold=0.8, density_threshold=0.05)
engine = GovernedNexisEngine(memory_path="signals.db", aegis_config=cfg)
```

How the bridge uses Aegis decisions
-----------------------------------
- The bridge obtains the Aegis decision via `AegisImmortalCouncil.process(...)` and reads the returned `MetaCouncil` decision.
- If that decision's `action` equals "regenerated", the bridge may soften or harden Nexis's per-sample verdict depending on volatility, avg_virtue, and density.
- If `action` is anything else ("none", "snapshot_created", etc.), the bridge does not change Nexis's verdict.

Quick example (control case)
----------------------------
Given an innocuous message like "hello world":

- Nexis might set `ethical_alignment: unaligned` or `virtue: misaligned` while still returning `verdict: approved`.
- Aegis will report `action: none` when memory volatility is low. The bridge will not override Nexis. This is intentional.

Next steps
----------
- If you want per-sample overrides (not recommended), adjust the bridge logic in `Immortal_nexus.py` — but be cautious: this re-introduces per-signal twitchiness.
- Prefer tuning `AegisConfig` parameters to control when Aegis steps in.

For implementation details and a quick how-to on running the bridge test, see `docs/testing.md`.
