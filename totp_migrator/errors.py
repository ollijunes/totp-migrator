"""Error types. Messages never contain secrets, URIs, or one-time codes."""


class MigratorError(Exception):
    """An expected failure that is safe to show to the user."""


class UnsupportedAccount(MigratorError):
    """A well-formed account that this tool deliberately does not migrate."""

    def __init__(self, label: str, reason: str) -> None:
        self.label = label
        self.reason = reason
        super().__init__(f"{label}: {reason}")
