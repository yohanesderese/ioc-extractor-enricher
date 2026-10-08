"""Synthetic end-to-end and component regression cases for M1."""

import json
from pathlib import Path

import pytest

from ioc_extractor_enricher import ExtractionOptions, extract
from ioc_extractor_enricher.cli import main
from ioc_extractor_enricher.noise_filter import load_whitelist
from ioc_extractor_enricher.normalization import normalize
from ioc_extractor_enricher.refang import refang
from ioc_extractor_enricher.validation import valid_domain


def values(text: str, **kwargs: object) -> set[tuple[str, str]]:
    """Project results to comparable type/value pairs."""
    return {(ioc.type, ioc.value) for ioc in extract(text, **kwargs)}


@pytest.mark.parametrize(
    "text,expected",
    [
        ("hxxp[:]//Example[.]com", "http://Example.com"),
        ("HXXPS://example(.)org", "https://example.org"),
        (r"user [at] example\.com", "user@example.com"),
        ("example{.}com", "example.com"),
    ],
)
def test_refang(text: str, expected: str) -> None:
    """Common defanged separators are restored."""
    assert refang(text) == expected


def test_all_types_and_derived_domains() -> None:
    """All nine types and URL/email host derivation work together."""
    text = (
        "hxxps://Example[.]com/Case User[at]example.org 8.8.8.8 "
        "2606:4700:4700::1111 " + "a" * 32 + " " + "b" * 40 + " " + "c" * 64 + " cve-2024-12345"
    )
    result = values(text)
    assert {kind for kind, _ in result} == {
        "url",
        "domain",
        "email",
        "ipv4",
        "ipv6",
        "md5",
        "sha1",
        "sha256",
        "cve",
    }
    assert ("domain", "example.org") in result
    assert ("url", "https://example.com/Case") in result


def test_context_and_deduplication() -> None:
    """Keep the first original sentence after case normalization."""
    result = extract("Seen Example[.]com here. Later EXAMPLE.com again.")
    assert len(result) == 1
    assert result[0].context == "Seen Example[.]com here."


def test_reserved_and_zero_options() -> None:
    """Reserved addresses and all-zero hashes require explicit opt-in."""
    text = "10.0.0.1 127.0.0.1 192.0.2.1 ::1 " + "0" * 32
    assert extract(text) == []
    assert len(extract(text, ExtractionOptions(True, True))) == 5


@pytest.mark.parametrize(
    "domain", ["payload.exe", "module.dll", "bad.invalid", "-bad.com", "a..com", "a" * 64 + ".com"]
)
def test_invalid_domains(domain: str) -> None:
    """Reject filenames, unknown suffixes and malformed DNS labels."""
    assert not valid_domain(domain)


def test_validation_rejects_malformed_candidates() -> None:
    """Bad addresses and URL ports do not raise or produce results."""
    assert extract("999.1.2.3 https://example.com:99999/") == []


def test_normalization() -> None:
    """Canonical hosts preserve meaningful case in paths and local parts."""
    assert normalize("ipv6", "2606:4700:4700:0:0:0:0:1111") == "2606:4700:4700::1111"
    assert normalize("email", "User@EXAMPLE.COM") == "User@example.com"
    assert normalize("url", "HTTPS://EXAMPLE.COM:443/Case?q=A") == ("https://example.com/Case?q=A")


def test_noise_filter(tmp_path: Path) -> None:
    """Whitelist domains include subdomains and URL/email hosts, with a toggle."""
    path = tmp_path / "whitelist.txt"
    path.write_text("# benign\nexample.com # synthetic\n8.8.8.8\n", encoding="utf-8")
    whitelist = load_whitelist(path)
    text = "https://sub.example.com/a user@example.com 8.8.8.8 otherexample.com"
    assert values(text, whitelist=whitelist) == {("domain", "otherexample.com")}
    assert len(extract(text, ExtractionOptions(filter_noise=False), whitelist)) == 6


def test_cli_text(capsys: pytest.CaptureFixture[str]) -> None:
    """CLI emits structured JSON."""
    assert main(["--text", "Example[.]com"]) == 0
    assert json.loads(capsys.readouterr().out)[0]["value"] == "example.com"


def test_cli_file_and_stdin(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both UTF-8 files and piped text work."""
    from io import StringIO

    path = tmp_path / "report.txt"
    path.write_text("example.org", encoding="utf-8")
    assert main(["--file", str(path)]) == 0
    assert json.loads(capsys.readouterr().out)[0]["value"] == "example.org"
    monkeypatch.setattr("sys.stdin", StringIO("example.com"))
    assert main([]) == 0
    assert json.loads(capsys.readouterr().out)[0]["value"] == "example.com"


def test_cli_missing_file() -> None:
    """Unreadable input exits cleanly with a nonzero status."""
    with pytest.raises(SystemExit) as error:
        main(["--file", "/nonexistent/synthetic-report.txt"])
    assert error.value.code == 2


def test_prose_punctuation_and_url_hosts() -> None:
    """Sentence punctuation and bracketed IPv6 hosts preserve whole indicators."""
    assert ("ipv4", "8.8.8.8") in values("Observed 8.8.8.8.")
    assert values("(https://example.com/Case).") == {
        ("url", "https://example.com/Case"),
        ("domain", "example.com"),
    }
    assert ("ipv6", "2606:4700:4700::1111") in values("https://[2606:4700:4700::1111]/")


def test_offline_extraction(monkeypatch: pytest.MonkeyPatch) -> None:
    """Domain validation never uses live HTTP."""

    def reject_network(*args: object, **kwargs: object) -> None:
        raise AssertionError("Extraction attempted an HTTP request")

    monkeypatch.setattr("requests.sessions.Session.request", reject_network)
    assert ("domain", "example.com") in values("example[.]com")
