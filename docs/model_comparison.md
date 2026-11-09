# Model Comparison Notes

Use this file to document tests between the main and secondary Groq models.

Current configured models:

- Main: `openai/gpt-oss-120b`
- Secondary: `openai/gpt-oss-20b`

The defaults were updated on 2026-10-27 after Groq's deprecation notice listed
`qwen/qwen3-32b` (shutdown 2026-07-17) and `llama-3.1-8b-instant` (shutdown
2026-08-16). Groq's current migration recommendations are GPT-OSS 120B and
GPT-OSS 20B, respectively. Environment variables can still override these values.

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
