"""Closed-Loop Browser/GUI, PC Automation, Set-of-Mark Grounding, OSINT & Document Organ."""

from am_ua.execution.pc_automation import (
    DesktopProcessWindowOrgan,
    GroundedUIElement,
    PCAutomationEngine,
    RobocorpLocatorParser,
    SetOfMarkGrounder,
    TransactionalClipboard,
)
from .cdp_browser import (
    CDPIndexedBrowser,
    IndexedDOMElement,
)
from .verified_browser_adapter import (
    DocumentMultimodalOrgan,
    OlhoDeDeusOSINT,
    VerifiedBrowserAdapter,
)

__all__ = [
    "VerifiedBrowserAdapter",
    "CDPIndexedBrowser",
    "IndexedDOMElement",
    "OlhoDeDeusOSINT",
    "DocumentMultimodalOrgan",
    "PCAutomationEngine",
    "SetOfMarkGrounder",
    "RobocorpLocatorParser",
    "TransactionalClipboard",
    "DesktopProcessWindowOrgan",
    "GroundedUIElement",
]
