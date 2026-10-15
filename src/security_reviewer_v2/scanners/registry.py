"""Runtime registry for concrete scanner adapters."""

from __future__ import annotations

from .base import ScannerAdapter


class AdapterRegistry:
    def __init__(self, adapters: tuple[ScannerAdapter, ...] = ()) -> None:
        self._adapters: dict[str, ScannerAdapter] = {}
        for adapter in adapters:
            self.register(adapter)

    def register(self, adapter: ScannerAdapter) -> None:
        scanner_id = getattr(adapter, "scanner_id", "")
        if not scanner_id:
            raise ValueError("Adapter scanner_id is required")
        if scanner_id in self._adapters:
            raise ValueError(f"Adapter already registered for {scanner_id}")
        self._adapters[scanner_id] = adapter

    def get(self, scanner_id: str) -> ScannerAdapter | None:
        return self._adapters.get(scanner_id)

    def scanner_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._adapters))

