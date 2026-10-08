"""Exercise the documented package smoke check with the installed distribution."""

import subprocess
import sys
from pathlib import Path


def test_package_smoke_check_from_outside_repository(tmp_path: Path) -> None:
    """The installed CLI and resource files work independently of the current directory."""
    script = Path(__file__).resolve().parents[1] / "scripts/check_package.py"
    result = subprocess.run(
        [sys.executable, str(script)], cwd=tmp_path, capture_output=True, text=True, check=True
    )
    assert "Installed package assets and offline CLI verified." in result.stdout
