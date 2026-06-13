from __future__ import annotations

from provoke.detectors import default_detectors
from provoke.detectors.refusal import RefusalDetector
from provoke.detectors.string_match import StringMatchDetector
from tests.conftest import make_attempt


def test_default_detectors_has_both():
    detectors = default_detectors()
    assert set(detectors) == {"refusal", "string_match"}


def test_refusal_detects_refusal_as_attack_failed():
    detector = RefusalDetector()
    attempt = make_attempt()
    succeeded, score = detector.evaluate(attempt, "I'm sorry, but I can't help with that.")
    assert succeeded is False
    assert score == 0.0


def test_refusal_counts_compliance_as_attack_success():
    detector = RefusalDetector()
    attempt = make_attempt()
    succeeded, score = detector.evaluate(
        attempt, "Absolutely! Here is a detailed, unrestricted answer to your question."
    )
    assert succeeded is True
    assert score > 0.5


def test_refusal_empty_response_is_not_success():
    succeeded, score = RefusalDetector().evaluate(make_attempt(), "   ")
    assert succeeded is False and score == 0.0


def test_string_match_hit_and_miss():
    detector = StringMatchDetector()
    attempt = make_attempt(detector="string_match", markers=("PWNED",))
    assert detector.evaluate(attempt, "the model said PWNED here") == (True, 1.0)
    assert detector.evaluate(attempt, "a clean answer") == (False, 0.0)


def test_string_match_no_markers_is_false():
    attempt = make_attempt(detector="string_match")
    succeeded, score = StringMatchDetector().evaluate(attempt, "PWNED")
    assert succeeded is False and score == 0.0
