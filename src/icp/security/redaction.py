"""Log redaction.

Assessment runs happen on a consultant's laptop and in CI. Logs get pasted into
tickets, screen-shared on walkthrough calls, and captured by CI artifact
storage. Anything sensitive that reaches a log has effectively left the
engagement's control, so it is scrubbed at the logging boundary rather than
relying on every call site to remember.
"""

from __future__ import annotations

import logging
import re

# `*` is in the local-part class so that an already-masked address re-masks to
# itself. Redaction runs at every handler and log records get reformatted, so
# a non-idempotent masker would erode addresses a little more on each pass.
_EMAIL = re.compile(r"\b[\w.%+*-]+@([\w-]+\.)+[A-Za-z]{2,}\b")
# The optional inner `bearer` matters: "Authorization: Bearer ya29..." would
# otherwise match only up to the word "Bearer" and leave the token in the log.
_BEARER = re.compile(r"(?i)\b(bearer|authorization|api[_-]?key|token)\b\s*[:=]?\s*(?:bearer\s+)?\S+")
_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)
_GOOGLE_KEY = re.compile(r"\b[A-Za-z0-9_-]{24}\.apps\.googleusercontent\.com\b")
_LONG_SECRET = re.compile(r"\b(?=[A-Za-z0-9_\-]*[0-9])(?=[A-Za-z0-9_\-]*[A-Za-z])[A-Za-z0-9_\-]{40,}\b")


def mask_email(value: str) -> str:
    """`alice.smith@example.org` -> `a***h@example.org`.

    The domain is kept because it is operationally useful and not personal; the
    local part is reduced to first and last character so two different users
    remain visibly different in a log without being identifiable.
    """

    def _mask(match: re.Match[str]) -> str:
        local, _, domain = match.group(0).partition("@")
        if len(local) <= 2:
            return f"{local[0]}***@{domain}"
        return f"{local[0]}***{local[-1]}@{domain}"

    return _EMAIL.sub(_mask, value)


def redact(value: str) -> str:
    """Apply every redaction rule. Order matters: keys before generic secrets."""
    value = _PRIVATE_KEY.sub("[REDACTED PRIVATE KEY]", value)
    value = _BEARER.sub(r"\1=[REDACTED]", value)
    value = _GOOGLE_KEY.sub("[REDACTED CLIENT ID]", value)
    value = _LONG_SECRET.sub("[REDACTED]", value)
    value = mask_email(value)
    return value


class RedactingFilter(logging.Filter):
    """Attach to every handler. Rewrites the formatted message in place."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: _redact_arg(v) for k, v in record.args.items()}
            else:
                record.args = tuple(_redact_arg(a) for a in record.args)
        return True


def _redact_arg(value: object) -> object:
    """Redact strings, leave everything else alone.

    Coercing every argument to `str` would break `%d` and `%f` format
    specifiers, turning a routine log line into a traceback on the operator's
    screen mid-collection. Only strings can carry the things we redact anyway.
    """
    return redact(value) if isinstance(value, str) else value


def configure_logging(level: int = logging.INFO, *, json_output: bool = False) -> None:
    """Install redaction globally. Call once, at process start."""
    handler = logging.StreamHandler()
    handler.addFilter(RedactingFilter())
    fmt = (
        '{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}'
        if json_output
        else "%(asctime)s %(levelname)-7s %(name)s :: %(message)s"
    )
    handler.setFormatter(logging.Formatter(fmt))

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)

    # Third-party libraries log request URLs containing user emails at INFO.
    for noisy in (
        "googleapiclient",
        "google_auth_httplib2",
        "urllib3",
        "google.auth",
        # WeasyPrint's font subsetter logs dozens of lines per report at INFO.
        "weasyprint",
        "fontTools",
        "fontTools.subset",
        "fontTools.ttLib",
    ):
        logging.getLogger(noisy).setLevel(logging.WARNING)
