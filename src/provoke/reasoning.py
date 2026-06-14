"""Strip chain-of-thought from reasoning-model responses before detection.

Reasoning models (DeepSeek-R1, QwQ, o1-style, ...) emit a private reasoning
trace, commonly delimited by <think>...</think>, before their actual answer.
That trace routinely *quotes the attack* ("the user wants me to output PWNED")
while the model is deliberating — which would false-positive a naive detector.

For attack-success scoring, the deliverable is the answer the model actually
returns to the user/downstream, not its internal monologue. So detectors judge
the response with reasoning removed. The full raw response is still kept in the
Result for reporting transparency. Stripping is a no-op for non-reasoning models
(no tags present), so it is safe to apply unconditionally.
"""

from __future__ import annotations

import re

# Well-formed reasoning blocks (non-greedy; DOTALL so they can span newlines).
_PAIRED = re.compile(r"<(think|thinking|reasoning)>.*?</\1>", re.DOTALL | re.IGNORECASE)
# A truncated/unclosed opener (max_tokens cut the trace before the answer):
# everything from the opener onward is reasoning, not a deliverable answer.
_UNCLOSED = re.compile(r"<(think|thinking|reasoning)>.*$", re.DOTALL | re.IGNORECASE)


def strip_reasoning(text: str) -> str:
    without_pairs = _PAIRED.sub("", text)
    without_trailing = _UNCLOSED.sub("", without_pairs)
    return without_trailing.strip()
