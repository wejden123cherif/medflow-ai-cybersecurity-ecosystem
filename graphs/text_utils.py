from __future__ import annotations

import re


THINK_BLOCK_RE = re.compile(r"<think\b[^>]*>.*?</think>", re.IGNORECASE | re.DOTALL)


def strip_model_thinking(text: object) -> str:
    """Remove model reasoning blocks before parsing, storing, or printing output."""
    cleaned = THINK_BLOCK_RE.sub("", str(text or ""))
    return cleaned.strip()
