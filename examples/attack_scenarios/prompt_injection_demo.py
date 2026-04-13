"""Demo: prompt injection detection with AgentShield."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../sdk"))

from agentshield.ml.nlp_classifier import NLPClassifier
from agentshield.testing.simulator import AttackSimulator, PROMPT_INJECTION_PAYLOADS

print("AgentShield — Prompt Injection Detection Demo")
print("=" * 60)

clf = NLPClassifier()

test_inputs = [
    # Benign
    "What's the capital of France?",
    "Help me write a Python function to sort a list.",
    "Explain how transformers work in NLP.",
    # Malicious
    *PROMPT_INJECTION_PAYLOADS[:5],
]

print("\nClassifying inputs:")
for text in test_inputs:
    result = clf.classify(text)
    label = "🔴 BLOCKED" if result.is_malicious else "🟢 ALLOWED"
    print(f"\n{label} [{result.confidence:.0%}] {text[:60]}...")
    if result.patterns_matched:
        print(f"   Patterns: {result.patterns_matched[:2]}")

# Run full simulation
print("\n" + "=" * 60)
print("Running attack simulation...")
simulator = AttackSimulator(seed=42)
results = simulator.simulate_prompt_injection()
report = simulator.generate_detection_report(results)
print(f"Detection rate: {report['overall_detection_rate']:.0%} ({sum(1 for r in results if r.detected)}/{len(results)} detected)")
