# MITRE ATT&CK for AI Mapping

AgentShield maps detections to the MITRE ATT&CK for AI framework.

## Key Techniques

| Technique | Name | AgentShield Detection |
|-----------|------|-----------------------|
| AML.T0054 | Prompt Injection | `prompt_injection` alert |
| AML.T0056 | Indirect Prompt Injection | `indirect_injection` alert |
| AML.T0043 | Hardcoded Credentials | `credential_access` alert |
| AML.T0040 | Establish Persistence | `persistence` alert |
| AML.T0048 | Exfiltrate via Inference | `data_exfiltration` alert |

## Usage

```python
from threat_intel.mitre.mapper import map_alert_to_techniques
techniques = map_alert_to_techniques("prompt_injection")
```
