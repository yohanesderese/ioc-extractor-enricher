"""Explicit, environment-configured creation of private unpublished MISP events."""

import asyncio
import os
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlsplit

import httpx

from .exports import ExportItem


@dataclass(frozen=True)
class MISPResult:
    """Safe outcome text; remote response bodies and credentials are never retained."""

    status: str
    message: str
    event_id: str | None = None
    link: str | None = None


def build_event(items: Sequence[ExportItem], report_id: str) -> dict:
    """Exclude flagged IOCs and omit original report sentences from the remote event."""
    types = {
        "ipv4": "ip-dst",
        "ipv6": "ip-dst",
        "domain": "domain",
        "url": "url",
        "md5": "md5",
        "sha1": "sha1",
        "sha256": "sha256",
        "email": "email-dst",
        "cve": "vulnerability",
    }
    attributes = [
        {
            "type": types[item.ioc.type],
            "value": item.ioc.value,
            "to_ids": item.assessment.verdict == "malicious" and item.ioc.type != "cve",
            "comment": f"IOCDesk assessment: {item.assessment.verdict}; "
            f"score: {item.assessment.score if item.assessment.score is not None else 'unknown'}",
        }
        for item in items
        if not item.false_positive
    ]
    if not attributes:
        raise ValueError("No unflagged indicators to send")
    return {
        "Event": {
            "uuid": str(uuid.uuid5(uuid.NAMESPACE_URL, f"iocdesk:report:{report_id}")),
            "info": f"IOCDesk investigation {report_id[:12]}",
            "date": datetime.now(UTC).date().isoformat(),
            "distribution": 0,
            "published": False,
            "analysis": 0,
            "threat_level_id": 4,
            "Attribute": attributes,
        }
    }


class MISPClient:
    """Use verified HTTPS, no redirects and no retries for event creation."""

    def __init__(self, client: httpx.AsyncClient, *, timeout: float = 10.0) -> None:
        """Read configuration at startup, never from browser-supplied destinations."""
        self.client = client
        self.timeout = timeout
        self._key = os.environ.get("MISP_API_KEY", "").strip()
        self._url = os.environ.get("MISP_URL", "").strip().rstrip("/")

    @property
    def configured(self) -> bool:
        """Only accept HTTPS configuration without credentials, query or fragment."""
        try:
            parsed = urlsplit(self._url)
            return bool(
                self._key
                and self._key != "..."
                and parsed.scheme == "https"
                and parsed.hostname
                and not parsed.username
                and not parsed.password
                and not parsed.query
                and not parsed.fragment
                and parsed.port != 0
            )
        except ValueError:
            return False

    async def push(self, items: Sequence[ExportItem], report_id: str) -> MISPResult:
        """Create one event; uncertain results require checking MISP before another report."""
        if not self.configured:
            return MISPResult("disabled", "Configure an HTTPS MISP URL and API key to enable push.")
        try:
            payload = build_event(items, report_id)
        except ValueError:
            return MISPResult("error", "No unflagged indicators to send.")
        uncertain = "MISP creation could not be confirmed. Check MISP before sending a new report."
        try:
            async with asyncio.timeout(self.timeout):
                response = await self.client.post(
                    f"{self._url}/events/add",
                    json=payload,
                    headers={"Authorization": self._key, "Accept": "application/json"},
                    timeout=self.timeout,
                    follow_redirects=False,
                )
            if response.status_code not in {200, 201}:
                return MISPResult("error", uncertain)
            event_id = response.json()["Event"]["id"]
            if isinstance(event_id, bool) or not str(event_id).isdigit() or int(event_id) < 1:
                raise ValueError("Invalid event identifier")
            return MISPResult(
                "success",
                "Created an unpublished organization-only MISP event.",
                str(event_id),
                f"{self._url}/events/view/{event_id}",
            )
        except (httpx.TimeoutException, TimeoutError):
            return MISPResult("timeout", uncertain)
        except (httpx.HTTPError, ValueError, KeyError, TypeError):
            return MISPResult("error", uncertain)
