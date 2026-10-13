"""Error types.

Messages are fixed descriptions plus positions (line and account numbers).
They never contain input text: no labels, secrets, URIs or parameter names.
"""


class MigratorError(Exception):
    """An expected failure that is safe to show to the user."""


class UnsupportedValue(MigratorError):
    """A well-formed value this tool deliberately does not migrate.

    Parsers turn it into a SkippedAccount so that ``--skip-unsupported`` can
    leave the account out instead of stopping the whole run.
    """
