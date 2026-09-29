"""
trust_policy.py
---------------
Combines the two independent layers into one business decision:

  1. Cryptographic integrity  -> `verified` (manifest + hash + signature)
     Proves the image was not changed after it was signed.
  2. AI authenticity          -> Resemble score
     Estimates whether the image content itself was AI-generated.
     This is probabilistic, so borderline scores go to human review
     instead of being rejected automatically.

Verdicts:
  TRUSTED   integrity OK and AI score below the review threshold
  REVIEW    integrity OK but AI check is borderline, failed, or not configured
  REJECTED  integrity failed, or AI score at/above the reject threshold
"""

from __future__ import annotations

from dataclasses import dataclass, field

from config import AIDetectionSettings
from services.ai_detection_service import STATUS_COMPLETED, AIDetectionResult

VERDICT_TRUSTED = "TRUSTED"
VERDICT_REVIEW = "REVIEW"
VERDICT_REJECTED = "REJECTED"


@dataclass
class TrustDecision:
    verdict: str
    reasons: list[str] = field(default_factory=list)


def decide_trust(
    integrity_verified: bool,
    ai_result: AIDetectionResult,
    settings: AIDetectionSettings,
) -> TrustDecision:
    if not integrity_verified:
        return TrustDecision(
            VERDICT_REJECTED,
            ["Cryptographic integrity failed: the evidence was modified or signed with a different key."],
        )

    if ai_result.status != STATUS_COMPLETED:
        reason = ai_result.reason or f"AI detection status: {ai_result.status}."
        return TrustDecision(
            VERDICT_REVIEW,
            ["Integrity verified, but AI authenticity could not be assessed. " + reason],
        )

    score = ai_result.score
    if score is None:
        # Provider gave only a label: use it, but never auto-reject on a label alone.
        if ai_result.label == "fake":
            return TrustDecision(VERDICT_REVIEW, ["Provider labelled the image as AI-generated (no score returned)."])
        return TrustDecision(VERDICT_TRUSTED, ["Integrity verified and provider labelled the image as real."])

    if score >= settings.reject_threshold:
        return TrustDecision(
            VERDICT_REJECTED,
            [f"AI-generation score {score:.2f} ≥ reject threshold {settings.reject_threshold:.2f}."],
        )
    if score >= settings.review_threshold:
        return TrustDecision(
            VERDICT_REVIEW,
            [f"AI-generation score {score:.2f} ≥ review threshold {settings.review_threshold:.2f}; manual review required."],
        )
    return TrustDecision(
        VERDICT_TRUSTED,
        [f"Integrity verified and AI-generation score {score:.2f} is below {settings.review_threshold:.2f}."],
    )
