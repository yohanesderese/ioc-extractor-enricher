"""Restore common analyst defanging conventions."""

import re


def refang(text: str) -> str:
    """Restore schemes, dots, colons and email separators."""
    text = re.sub(r"\bhxxps(?=\s*[:\[])", "https", text, flags=re.I)
    text = re.sub(r"\bhxxp(?=\s*[:\[])", "http", text, flags=re.I)
    for pattern, replacement in (
        (r"\[\.\]|\(\.\)|\{\.\}|\\\.", "."),
        (r"\[:\]|\(:\)", ":"),
        (r"\s*\[at\]\s*|\s*\(at\)\s*", "@"),
    ):
        text = re.sub(pattern, replacement, text, flags=re.I)
    return text
