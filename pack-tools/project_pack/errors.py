"""Stable project-pack errors shared by the portable producer."""

from __future__ import annotations


class PackError(Exception):
    """A safe-to-render project-pack validation or operation failure."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


def fail(code: str, message: str) -> PackError:
    """Construct a stable error without including untrusted document content."""

    return PackError(code, message)
