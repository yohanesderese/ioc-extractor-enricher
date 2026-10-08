"""Regression tests for weighted evidence, unknown verdicts and explainability."""

import pytest

from ioc_extractor_enricher.enrichment.base import EnrichmentResult, Status, Verdict
from ioc_extractor_enricher.scorer import score_results


@pytest.mark.parametrize(
    "verdict,score", [("malicious", 100), ("suspicious", 50), ("clean", 0), ("unknown", None)]
)
def test_single_source(verdict: Verdict, score: int | None) -> None:
    """One known source maps to its points; unknown evidence has no numeric score."""
    result = score_results([EnrichmentResult("virustotal", "ok", verdict, ("Synthetic reason",))])
    assert result.score == score and result.verdict == verdict
    assert any("Synthetic reason" in reason for reason in result.reasons)
    assert result.contributions[0].points == score


@pytest.mark.parametrize(
    "status", ["timeout", "disabled", "error", "rate_limited", "not_found", "unsupported"]
)
def test_unavailable_evidence_is_not_clean(status: Status) -> None:
    """Unavailable sources cannot dilute a positive source or create a clean verdict."""
    unavailable = EnrichmentResult("abuseipdb", status)
    assert score_results([unavailable]).score is None
    result = score_results([EnrichmentResult("virustotal", "ok", "malicious"), unavailable])
    assert result.score == 100 and result.verdict == "malicious"
    assert result.known_sources == 1
    assert result.contributions[1].points is None


def test_weighted_conflicting_evidence() -> None:
    """The mean uses documented weights, excluding unknown verdicts from its denominator."""
    result = score_results(
        [
            EnrichmentResult("virustotal", "ok", "malicious"),
            EnrichmentResult("abuseipdb", "ok", "clean"),
            EnrichmentResult("otx", "ok", "suspicious"),
        ]
    )
    assert result.score == 60 and result.verdict == "suspicious"
    assert result.known_sources == result.supported_sources == 3
    assert [c.weight for c in result.contributions] == [5, 3, 2]


def test_positive_risk_never_becomes_clean() -> None:
    """Even a low weighted risk retains suspicion, including when rounding yields zero."""
    result = score_results(
        [
            EnrichmentResult("virustotal", "ok", "clean"),
            EnrichmentResult("otx", "ok", "suspicious"),
        ],
        {"virustotal": 1000, "otx": 1},
    )
    assert result.score == 0 and result.verdict == "suspicious"


def test_empty_evidence_and_zero_weight() -> None:
    """No eligible weighted verdicts means unknown, with a reason."""
    assert score_results([]).verdict == "unknown"
    result = score_results([EnrichmentResult("virustotal", "ok", "clean")], {"virustotal": 0})
    assert result.score is None and result.known_sources == 0
    assert "zero" in result.reasons[0]


def test_custom_weights_and_large_finite_weights() -> None:
    """Custom sources get a usable default, and large weights do not overflow."""
    result = score_results([EnrichmentResult("custom", "ok", "malicious")])
    assert result.score == 100 and result.contributions[0].weight == 1
    result = score_results(
        [
            EnrichmentResult("one", "ok", "malicious"),
            EnrichmentResult("two", "ok", "clean"),
        ],
        {"one": 1e308, "two": 1e308},
    )
    assert result.score == 50


@pytest.mark.parametrize("weight", [-1, float("inf"), float("nan")])
def test_invalid_weights(weight: float) -> None:
    """Invalid weights fail explicitly rather than producing an arbitrary score."""
    with pytest.raises(ValueError):
        score_results([], {"virustotal": weight})


def test_duplicate_sources_rejected() -> None:
    """One source cannot gain influence by appearing twice."""
    source = EnrichmentResult("one", "ok", "malicious")
    with pytest.raises(ValueError):
        score_results([source, source])
