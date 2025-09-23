from nexus_signal_engine.core.engine import NexisSignalEngine

def test_message(message):
    engine = NexisSignalEngine()
    result = engine.process(message)
    
    print(f"\nTesting: {message}")
    print(f"Verdict: {result['verdict']}")
    if "reasoning" in result:
        print(f"Explanation: {result['reasoning'].get('explanation', 'N/A')}")
        print(f"Risk Score: {result['reasoning'].get('risk_score', 'N/A')}")
        print(f"Risk Factors: {', '.join(result['reasoning'].get('risk_factors', ['None']))}")

# Test with different types of messages
messages = [
    "hi",
    "potential exploit detected in system",
    "hope you have a good day",
    "@#$% weird ch@r@cters!!"
]

for msg in messages:
    test_message(msg)