"""Custom exception types for DirectorSync V3."""

from __future__ import annotations


class SyncError(Exception):
    """Base exception for synchronization errors."""


class ProfileError(SyncError):
    """Raised when a resource profile is invalid."""


class DataSourceError(SyncError):
    """Raised when a data source is misconfigured or unavailable."""


class DirectorApiError(SyncError):
    """Raised when the Director API responds with an error."""
