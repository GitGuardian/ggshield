"""PyGitGuardian API Client"""
from .client import GGClient
from .models import Detail, Match, PolicyBreak, ScanResult
from .schemas import DetailSchema, DocumentSchema, ScanResultSchema


__version__ = "1.0.1"
GGClient._version = __version__

__all__ = [
    "Detail",
    "DetailSchema",
    "DocumentSchema",
    "GGClient",
    "Match",
    "PolicyBreak",
    "ScanResult",
    "ScanResultSchema",
]
