# Model Comparison Notes

Use this file to document tests between the main and secondary Groq models.

Current configured models:

- Main: `qwen/qwen3-32b`
- Secondary: `llama-3.1-8b-instant`

Verify exact model IDs in Groq Console before final evaluation. If the IDs are different, update `.env`.

## Test 1

Question:

```text
Give me a full kill chain for a Ryuk attack on a hospital.
```

| Criteria | Qwen3 32B | Llama 3.1 8B |
| --- | --- | --- |
| Answer quality |  |  |
| Response time |  |  |
| Technique IDs accurate? |  |  |
| Healthcare focus |  |  |
| Hallucinations |  |  |
| Cybersecurity detail |  |  |
| Notes |  |  |

## Test 2

Question:

```text
What SIEM rules detect MFA fatigue attacks against hospital portals?
```

| Criteria | Qwen3 32B | Llama 3.1 8B |
| --- | --- | --- |
| Answer quality |  |  |
| Response time |  |  |
| Technique IDs accurate? |  |  |
| Healthcare focus |  |  |
| Hallucinations |  |  |
| Cybersecurity detail |  |  |
| Notes |  |  |

## Test 3

Question:

```text
What is T9999?
```

| Criteria | Qwen3 32B | Llama 3.1 8B |
| --- | --- | --- |
| Correctly says unsupported/unknown |  |  |
| Avoids hallucination |  |  |
| Response time |  |  |
| Notes |  |  |
