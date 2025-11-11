"""Compatibility shim: expose the bridge as `nexis_aegis_bridge.GovernedNexisEngine`.

Historically some code imports `nexis_aegis_bridge`. The real implementation
lives in `Immortal_nexus.py` in this repository; forward the symbol here so
CLI tools like `governed_scan.py` can import the bridge by the old name.
"""
from Immortal_nexus import GovernedNexisEngine

__all__ = ["GovernedNexisEngine"]
