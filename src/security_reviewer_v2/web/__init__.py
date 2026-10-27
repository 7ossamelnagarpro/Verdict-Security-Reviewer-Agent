"""Local-only web control plane for the security review pipeline."""

from .app import create_app

__all__ = ["create_app"]
