"""Explainable weighted scoring that distinguishes absent evidence from clean evidence."""

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from .enrichment.base import EnrichmentResult, Status, Verdict

DEFAULT_WEIGHTS = {
    "virustotal": 5.0,
    "abuseipdb": 3.0,
    "otx": 2.0,
    "urlhaus": 5.0,
    "malwarebazaar": 5.0,
    "greynoise": 2.0,
    "internetdb": 1.0,
    "rdap": 1.0,
}
POINTS: dict[Verdict, int] = {"malicious": 100, "suspicious": 50, "clean": 0}


@dataclass(frozen=True)
class SourceContribution:
    """One source's weight, evidence points and reason for inclusion or exclusion."""

    source: str
    status: Status
    verdict: Verdict
    weight: float
    points: int | None
    explanation: str


@dataclass(frozen=True)
class ScoreResult:
    """Final score with human-readable reasons and auditable source contributions."""

    score: int | None
    verdict: Verdict
    reasons: tuple[str, ...]
    contributions: tuple[SourceContribution, ...]
    known_sources: int
    supported_sources: int


def score_results(
    results: Sequence[EnrichmentResult],
    weights: Mapping[str, float] | None = None,
) -> ScoreResult:
    """Average known verdicts only; scores >=75 are malicious, other risk is suspicious."""
    configured = DEFAULT_WEIGHTS | dict(weights or {})
    if any(not math.isfinite(weight) or weight < 0 for weight in configured.values()):
        raise ValueError("Source weights must be nonnegative and finite")
    if len({result.source for result in results}) != len(results):
        raise ValueError("Each source must appear at most once")
    contributions = []
    reasons = []
    known = []
    for result in results:
        weight = configured.get(result.source, 1.0)
        points = POINTS.get(result.verdict) if result.status == "ok" and weight > 0 else None
        if points is None:
            explanation = (
                "Excluded: source weight is zero."
                if weight == 0
                else f"Excluded: {result.status}, verdict {result.verdict}; no known verdict."
            )
        else:
            known.append((weight, points))
            explanation = f"Included: {result.verdict} = {points} points, weight {weight:g}."
        contributions.append(
            SourceContribution(
                result.source, result.status, result.verdict, weight, points, explanation
            )
        )
        reasons.append(f"{result.source}: {explanation}")
        reasons.extend(f"{result.source}: {reason}" for reason in result.reasons)
    supported = sum(result.status != "unsupported" for result in results)
    if not known:
        reasons.append("No source supplied a known weighted verdict; the score is unknown.")
        return ScoreResult(None, "unknown", tuple(reasons), tuple(contributions), 0, supported)
    # Scale before summing to avoid overflow for otherwise finite custom weights.
    largest = max(weight for weight, _ in known)
    denominator = sum(weight / largest for weight, _ in known)
    score = round(sum(weight / largest * points for weight, points in known) / denominator)
    verdict = (
        "malicious"
        if score >= 75
        else ("suspicious" if any(points > 0 for _, points in known) else "clean")
    )
    reasons.append(f"Weighted mean of {len(known)} known source verdicts: {score}/100.")
    reasons.append("Malicious threshold: 75. Any remaining positive risk stays suspicious.")
    return ScoreResult(score, verdict, tuple(reasons), tuple(contributions), len(known), supported)
