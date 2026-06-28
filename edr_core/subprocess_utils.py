from __future__ import annotations

import os
import subprocess
from collections.abc import Sequence


CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def run_hidden(command: Sequence[str], timeout: int = 8) -> str:
    """Run a system collector without creating a console window."""
    startupinfo = None
    if os.name == "nt":
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = 0
    try:
        completed = subprocess.run(
            list(command),
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
            creationflags=CREATE_NO_WINDOW if os.name == "nt" else 0,
            startupinfo=startupinfo,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return completed.stdout
