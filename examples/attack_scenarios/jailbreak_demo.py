"""Demo: jailbreak detection with AgentShield."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../sdk"))

from agentshield.ml.nlp_classifier import NLPClassifier
from agentshield.testing.simulator import JAILBREAK_PAYLOADS

print("AgentShield — Jailbreak Detection Demo")
print("=" * 60)

clf = NLPClassifier()

print("\nTesting jailbreak prompts:")
detected = 0
for payload in JAILBREAK_PAYLOADS:
    result = clf.classify(payload)
    label = "🔴 JAILBREAK DETECTED" if result.is_malicious else "⚠️  Not detected (rule-miss)"
    print(f"\n{label}")
    print(f"  Prompt: {payload[:80]}...")
    print(f"  Confidence: {result.confidence:.0%}")
    if result.patterns_matched:
        print(f"  Matched: {result.patterns_matched}")
    if result.is_malicious:
        detected += 1

print(f"\nDetection rate: {detected}/{len(JAILBREAK_PAYLOADS)} ({detected/len(JAILBREAK_PAYLOADS):.0%})")
print("\nNote: Some jailbreaks use novel techniques not in pattern library.")
print("AgentShield's ML model improves with labeled training data.")
