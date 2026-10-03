"""Keep the test suite out of the real audit log.

`~/.local/state/icloud-mcp/audit.log` is production detection data. A summary
of it appears in the morning brief, so a run of pytest must not be able to write
"3 sends yesterday" into the thing the owner reads to spot a compromise. Every test
gets a throwaway path instead.
"""
from __future__ import annotations

import pytest

from icloud_mcp import server


@pytest.fixture(autouse=True)
def _isolate_audit_log(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "_AUDIT", str(tmp_path / "audit.log"))
