"""`python -m mcp_trust_monitor`: the generic library CLI, same as `mcp-trust-monitor`.

Every mutation goes through the owning `TrustMonitor` SDK; status, events and export
read snapshots. The historical hackathon walkthroughs are separate:
`python -m mcp_trust_monitor.historical_demo`.
"""

from __future__ import annotations

import sys

from .library_cli import main

if __name__ == "__main__":
    sys.argv[0] = "python -m mcp_trust_monitor"  # usage line names the invocation, not __main__.py
    sys.exit(main())
