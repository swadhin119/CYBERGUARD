"""
CyberGuard Unified Risk Engine
Provides consistent risk scoring across all analysis modules.
"""

from __future__ import annotations

from app.utils.helpers import score_to_risk, RISK_THRESHOLDS


# ------------------------------------------------------------------ #
# Scoring helpers
# ------------------------------------------------------------------ #

def calculate_risk(score: int) -> str:
    """
    Return the risk label for a given score.

    Scale:
        0 – 39  →  LOW
        40 – 69 →  SUSPICIOUS
        70 – 100 → HIGH
    """
    return score_to_risk(score)


def build_analysis_result(
    score: int,
    indicators: list[str],
    engine_name: str,
    confidence: int = 70,
) -> dict[str, Any]:
    """
    Build a standardised analysis result dictionary.

    Every analyzer should return its result through this function
    so the response structure is always consistent.
    """
    risk = calculate_risk(score)

    if risk == "HIGH":
        recommendation = (
            "Multiple suspicious indicators were detected. "
            "Avoid interacting with this content. "
            "Verify through a trusted, independent source."
        )
    elif risk == "SUSPICIOUS":
        recommendation = (
            "Some suspicious indicators were detected. "
            "Proceed with caution and verify independently "
            "before taking any action."
        )
    else:
        recommendation = (
            "No major suspicious indicators were detected by the "
            "current security engine. This does not guarantee safety — "
            "always remain cautious with unknown content."
        )

    return {
        "score": min(max(score, 0), 100),
        "risk": risk,
        "confidence": min(max(confidence, 0), 100),
        "indicators": indicators or [],
        "recommendation": recommendation,
        "analysis_engine": engine_name,
    }


def merge_indicators(
    existing: list[str],
    new: list[str],
    max_indicators: int = 20,
) -> list[str]:
    """
    Merge two indicator lists without duplicates, capped at max_indicators.
    """
    seen = set(existing)
    merged = list(existing)
    for item in new:
        if item not in seen:
            merged.append(item)
            seen.add(item)
            if len(merged) >= max_indicators:
                break
    return merged
