"""Always-on automation layer for the quantitative research engine."""

from .config import BotConfig
from .engine import AutomationEngine

__all__ = ["AutomationEngine", "BotConfig"]
