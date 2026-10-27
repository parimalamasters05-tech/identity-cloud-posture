"""Client-data file names: built from checked parts, kept inside their folder.

Tenant labels and snapshot IDs end up in file names. A snapshot ID is read
back from the snapshot file itself, so a crafted or corrupted snapshot could
otherwise name a path like `../../outside` and have its findings, call trail
or report written outside the engagement's folders.
"""

from __future__ import annotations

import re
from pathlib import Path

#: Letters, digits, dot, hyphen, underscore; not starting with a dot. Covers
#: every snapshot ID (20261027T061703806Z-c165c41a) and tenant label in use.
_COMPONENT = re.compile(r"^[A-Za-z0-9_-][A-Za-z0-9._-]{0,199}$")


class UnsafePathError(ValueError):
    """A file name part, or a resulting path, that could leave its folder."""


def component(value: str, what: str) -> str:
    """`value` if it is safe as part of a file name; otherwise refused, not rewritten.

    Rewriting (`../x` to `-x`) could make two snapshots share one file name.
    """
    if not isinstance(value, str) or not _COMPONENT.match(value) or ".." in value:
        raise UnsafePathError(
            f"{what} {value!r} cannot be used in a file name: only letters, digits, '.', '-' "
            "and '_' are allowed, not starting with '.'."
        )
    return value


def file_in(folder: Path, name: str) -> Path:
    """`folder / name`, checked to resolve to a file directly inside `folder`."""
    folder = Path(folder)
    path = folder / name
    if Path(name).name != name or path.resolve().parent != folder.resolve():
        raise UnsafePathError(f"{name!r} would be written outside {folder}.")
    return path
