from __future__ import annotations

from datetime import time


# These values are part of the sealed research/live contract.  Keep one source of
# truth so configuration, scheduling, execution, and plan construction cannot drift.
GOVERNED_MINIMUM_ASSETS = 20
GOVERNED_EXECUTION_START = time(9, 30)
GOVERNED_EXECUTION_END = time(9, 35)
GOVERNED_EXECUTION_WINDOW_MINUTES = 5
GOVERNED_TIMEZONE = "America/New_York"
