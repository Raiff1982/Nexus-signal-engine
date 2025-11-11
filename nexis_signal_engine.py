# Compatibility shim: some files import `nexis_signal_engine.NexisSignalEngine`.
# Prefer the more feature-complete engine defined in `Nexus.py` when present.
import importlib.util
import pathlib
import sys

# Prefer the standalone `Nexus.py` implementation if present in the same directory
# as this shim (typically the project root). The previous implementation used
# parents[1] which often missed the correct location, causing the fallback to
# import the package implementation with a different constructor signature.
shim_dir = pathlib.Path(__file__).resolve().parent
nexus_path = shim_dir / "Nexus.py"
if nexus_path.exists():
	spec = importlib.util.spec_from_file_location("Nexus", str(nexus_path))
	nexus_mod = importlib.util.module_from_spec(spec)
	spec.loader.exec_module(nexus_mod)
	NexisSignalEngine = getattr(nexus_mod, "NexisSignalEngine")
else:
	# Fallback to the installed/package implementation. Import by name to
	# allow normal package resolution (this will load the package's
	# `nexus_signal_engine` module, not this shim which is named
	# `nexis_signal_engine.py`).
	from nexus_signal_engine import NexisSignalEngine

__all__ = ["NexisSignalEngine"]
