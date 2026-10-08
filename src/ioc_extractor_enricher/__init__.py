"""Extract normalized indicators of compromise without network access."""

from .extractor import extract
from .models import IOC, ExtractionOptions

__all__ = ["IOC", "ExtractionOptions", "extract"]
