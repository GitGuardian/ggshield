"""PyGitGuardian API Client"""
from .client import GGClient
from .models import Detail, ScanResult
from .schemas import DetailSchema, DocumentSchema, ScanResultSchema


__version__ = "1.0.0"

__all__ = [
    "Detail",
    "DetailSchema",
    "DocumentSchema",
    "GGClient",
    "ScanResult",
    "ScanResultSchema",
]
