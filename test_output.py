import pytest
from nexus_signal_engine.core.engine import NexisSignalEngine


@pytest.mark.parametrize("message", [
    "hi",
    "potential exploit detected in system",
    "hope you have a good day",
    "@#$% weird ch@r@cters!!",
])
def test_message(message):
    engine = NexisSignalEngine()
    result = engine.process(message)
    assert "verdict" in result