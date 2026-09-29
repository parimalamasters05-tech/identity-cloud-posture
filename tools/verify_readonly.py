"""Static read-only verifier -- control #3 of three.

Runtime controls can only fail at runtime, which on this project means failing
in front of a client. This scans the source tree with the AST and fails the
build if any write-capable API call or forbidden scope literal exists anywhere
in `src/`.

Run standalone or via `pytest tests/security/test_no_write_calls.py`:

    python tools/verify_readonly.py            # scans src/
    python tools/verify_readonly.py --path src/icp/collectors

Exit code 0 means clean; 1 means a violation, printed with file and line.
"""

from __future__ import annotations

import argparse
import ast
import sys
from dataclasses import dataclass
from pathlib import Path

#: Google API resource methods that change state. Any call to one of these on
#: any object is a violation -- we do not try to prove the receiver is a Google
#: service, because a false positive costs a rename and a false negative costs
#: a client's trust.
FORBIDDEN_METHODS: frozenset[str] = frozenset(
    {
        "insert",
        "update",
        "patch",
        "delete",
        "create",
        "batchUpdate",
        "batchDelete",
        "undelete",
        "makeAdmin",
        "signOut",
        "turnOffMobileDevice",
        "wipe",
        "wipeAccount",
        "approve",
        "reject",
        "trash",
        "untrash",
        "emptyTrash",
        "copy",
        "move",
        "setIamPolicy",
        "revoke",
    }
)

#: Method names that are legitimate Python but collide with the list above.
#: Each entry is (method, receiver) and is allowed only on that receiver.
ALLOWED_RECEIVERS: dict[str, frozenset[str]] = {
    "update": frozenset(
        {
            "dict",
            "params",
            "out",
            "row",
            "record",
            "results",
            "index",
            "state",
            "counts",
            "artifacts",
            "document",
            "item",
            "context",
            "self",
        }
    ),
    "copy": frozenset({"copy", "shutil"}),
    "create": frozenset({"Path", "path", "logging"}),
    "insert": frozenset({"list", "items", "parts", "ordered"}),
    "delete": frozenset({"dict", "cache"}),
}

#: Scope substrings that must never appear as a literal anywhere in src/.
FORBIDDEN_SCOPE_LITERALS: tuple[str, ...] = (
    "https://www.googleapis.com/auth/admin.directory.user\x00",  # exact-match guard, see below
)

#: Exact write scopes. Compared against whole string literals so that the
#: read-only variants (which are prefixes plus ".readonly") do not trip.
FORBIDDEN_SCOPES: frozenset[str] = frozenset(
    {
        "https://www.googleapis.com/auth/admin.directory.user",
        "https://www.googleapis.com/auth/admin.directory.group",
        "https://www.googleapis.com/auth/admin.directory.rolemanagement",
        "https://www.googleapis.com/auth/admin.directory.domain",
        "https://www.googleapis.com/auth/admin.datatransfer",
        "https://www.googleapis.com/auth/drive",
        "https://www.googleapis.com/auth/drive.file",
        "https://www.googleapis.com/auth/cloud-platform",
        "https://www.googleapis.com/auth/cloud-identity.policies",
        "https://www.googleapis.com/auth/admin.directory.customer",
        "https://mail.google.com/",
        "https://www.googleapis.com/auth/gmail.modify",
        "https://www.googleapis.com/auth/gmail.send",
    }
)

#: Files that legitimately name forbidden scopes: the allowlist that blocks them
#: and the taxonomy that classifies them. Both are data about scopes, not uses
#: of them. Narrow and explicit so the exemption cannot quietly widen.
SCOPE_LITERAL_EXEMPT: frozenset[str] = frozenset(
    {
        "src/icp/security/scopes.py",
        "tools/verify_readonly.py",
    }
)

#: HTTP verbs that must never be passed to a request call.
FORBIDDEN_HTTP_VERBS: frozenset[str] = frozenset({"POST", "PUT", "PATCH", "DELETE"})

VERB_EXEMPT: frozenset[str] = frozenset(
    {
        "src/icp/security/readonly.py",  # defines the block list itself
        "tools/verify_readonly.py",
    }
)


@dataclass(frozen=True)
class Violation:
    path: str
    line: int
    kind: str
    detail: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: [{self.kind}] {self.detail}"


class ReadOnlyVisitor(ast.NodeVisitor):
    def __init__(self, relative_path: str) -> None:
        self.path = relative_path
        self.violations: list[Violation] = []

    # -- method calls ----------------------------------------------------------

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr in FORBIDDEN_METHODS
            and not self._is_allowed(func)
        ):
            self.violations.append(
                Violation(
                    self.path,
                    func.lineno,
                    "write-call",
                    f".{func.attr}() is a state-changing API method. This tool must never call it.",
                )
            )
        self.generic_visit(node)

    def _is_allowed(self, func: ast.Attribute) -> bool:
        allowed = ALLOWED_RECEIVERS.get(func.attr)
        if not allowed:
            return False
        receiver = _receiver_name(func.value)
        return receiver in allowed

    # -- string literals -------------------------------------------------------

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str):
            value = node.value
            if value in FORBIDDEN_SCOPES and self.path not in SCOPE_LITERAL_EXEMPT:
                self.violations.append(
                    Violation(
                        self.path,
                        node.lineno,
                        "write-scope",
                        f"{value!r} is a write-capable OAuth scope.",
                    )
                )
            if value in FORBIDDEN_HTTP_VERBS and self.path not in VERB_EXEMPT:
                self.violations.append(
                    Violation(
                        self.path,
                        node.lineno,
                        "unsafe-verb",
                        f"HTTP verb {value!r} appears as a literal. Collection is GET-only.",
                    )
                )
        self.generic_visit(node)


def _receiver_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return _receiver_name(node.func)
    return ""


def scan_file(path: Path, root: Path) -> list[Violation]:
    relative = path.relative_to(root).as_posix()
    try:
        tree = ast.parse(path.read_text("utf-8"), filename=str(path))
    except SyntaxError as exc:
        return [Violation(relative, exc.lineno or 0, "parse-error", str(exc))]

    visitor = ReadOnlyVisitor(relative)
    visitor.visit(tree)
    return visitor.violations


def scan(target: Path, root: Path | None = None) -> list[Violation]:
    root = root or Path.cwd()
    violations: list[Violation] = []
    for path in sorted(target.rglob("*.py")):
        violations.extend(scan_file(path, root))
    return violations


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", default="src", help="Directory to scan (default: src)")
    args = parser.parse_args()

    root = Path.cwd()
    target = root / args.path
    if not target.exists():
        print(f"No such path: {target}", file=sys.stderr)
        return 2

    violations = scan(target, root)
    file_count = len(list(target.rglob("*.py")))

    if violations:
        print(f"READ-ONLY VERIFICATION FAILED: {len(violations)} violation(s)\n", file=sys.stderr)
        for violation in violations:
            print(f"  {violation}", file=sys.stderr)
        print(
            "\nIf one of these is a false positive, add the receiver to "
            "ALLOWED_RECEIVERS in tools/verify_readonly.py with a comment "
            "explaining why it cannot mutate a tenant.",
            file=sys.stderr,
        )
        return 1

    print(f"Read-only verification passed: {file_count} file(s) scanned, no write-capable calls.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
