"""Native providers: harness-authored adapters that the runtime fully controls.

Native tools are preferred where the harness must own the raw evidence bytes, because the adapter is
the only code that touches the target and it is also the only code that builds the argv array.
"""

from __future__ import annotations

from harness.providers.native.logfile import LogFileProvider
from harness.providers.native.nmap import NmapProvider
from harness.providers.native.synthetic import SyntheticProvider

__all__ = ["LogFileProvider", "NmapProvider", "SyntheticProvider"]
