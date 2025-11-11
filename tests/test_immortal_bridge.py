import sys
import types
import unittest

# Create a dummy `immortal_aegis` module to satisfy the bridge import
immortal_mod = types.ModuleType("immortal_aegis")

class AgentResult:
    def __init__(self, data):
        self.data = data

class AegisImmortalCouncil:
    def process(self, text):
        # Return a deterministic decision that triggers the "regenerated" action
        decision = {"action": "regenerated", "volatility": 0.5, "avg_virtue": 0.5, "density": 0.1}
        return {"MetaCouncil": AgentResult({"decision": decision})}

immortal_mod.AgentResult = AgentResult
immortal_mod.AegisImmortalCouncil = AegisImmortalCouncil
# Provide a placeholder AegisConfig so importers that expect it won't fail
immortal_mod.AegisConfig = None
sys.modules["immortal_aegis"] = immortal_mod
# Ensure project root is on sys.path so local packages can be imported
import os
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

# Now import the bridge (real NexisSignalEngine will be used)
import inspect
import nexis_signal_engine
print(f"Using nexis_signal_engine module from: {getattr(nexis_signal_engine, '__file__', 'unknown')}")
print(f"NexisSignalEngine init signature: {inspect.signature(nexis_signal_engine.NexisSignalEngine.__init__)}")

from Immortal_nexus import GovernedNexisEngine

class TestImmortalBridge(unittest.TestCase):
    def test_basic_integration(self):
        # Create a temporary .db file for the engine (Nexus requires .db extension)
        import tempfile
        import os

        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        tmp.close()
        try:
            engine = GovernedNexisEngine(memory_path=tmp.name)

            # Process a simple message
            result = engine.process("hello world")

            # Ensure Aegis metadata was attached
            self.assertIn("aegis_decision", result)
            self.assertIn("aegis_summary_text", result)

            # Ensure feedback was written into Nexis memory (keys prefixed)
            found = any(k.startswith("aegis_feedback::") for k in engine.engine.memory.keys())
            self.assertTrue(found, "Aegis feedback not found in Nexus memory")
        finally:
            try:
                os.unlink(tmp.name)
            except Exception:
                pass

if __name__ == '__main__':
    unittest.main()
