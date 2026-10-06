"""Read-only Microsoft Graph access: the Google transport guard's counterpart.

Three rules, enforced on every request before it leaves the tool:

1. Graph is GET only. Any other verb to graph.microsoft.com is refused.
2. The single exception is authentication: one POST, to exactly this tenant's
   token endpoint on login.microsoftonline.com, to exchange the certificate
   for an access token. It changes nothing in the tenant. It is counted
   separately and never mixed into the read-only call trail.
3. No file content. `Sites.Read.All` could read documents; Microsoft has no
   metadata-only file permission. Any URL whose path asks for content
   (`/content`, `$value`) is refused, so the tool can list who can open a
   file but never open it.

Any host other than those two is refused too, including an `@odata.nextLink`
that points somewhere unexpected.

Authentication is a certificate (client assertion, RFC 7523), not a secret.
The private key is read from a file mounted read-only at runtime; it never
enters the image or the repository.
"""

from __future__ import annotations

import base64
import json
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from icp.models.snapshot import ApiCallRecord
from icp.security.readonly import WriteAttemptBlocked

GRAPH_HOST = "graph.microsoft.com"
LOGIN_HOST = "login.microsoftonline.com"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"

#: Path segments that return a file's bytes rather than its metadata.
_CONTENT_SEGMENTS = frozenset({"content", "$value", "contentstream"})

_AUTH_VERB = "POST"  # the one non-GET request; see rule 2 above


class GraphError(RuntimeError):
    """A Graph or login error, with Microsoft's own code and message."""

    def __init__(self, status: int | None, code: str, message: str) -> None:
        super().__init__(f"HTTP {status} {code}: {message}")
        self.status, self.code, self.message = status, code, message


@dataclass(frozen=True)
class GraphCredentials:
    tenant_id: str
    client_id: str
    thumbprint: str  # SHA-1, hex, as shown in the Entra portal
    private_key_pem: bytes

    @classmethod
    def from_files(
        cls, *, tenant_id: str, client_id: str, thumbprint: str, key_file: Path
    ) -> GraphCredentials:
        if not key_file.is_file():
            raise FileNotFoundError(f"Microsoft 365 private key not found at {key_file}")
        return cls(
            tenant_id=tenant_id.strip(),
            client_id=client_id.strip(),
            thumbprint=thumbprint.replace(":", "").strip(),
            private_key_pem=key_file.read_bytes(),
        )

    @property
    def token_url(self) -> str:
        return f"https://{LOGIN_HOST}/{self.tenant_id}/oauth2/v2.0/token"


def check_request(method: str, url: str, *, token_url: str) -> None:
    """Refuse anything but a Graph metadata GET or this tenant's token POST."""
    verb = method.upper()
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https":
        raise WriteAttemptBlocked(f"Blocked non-HTTPS request to {parts.netloc}{parts.path}")

    if verb == _AUTH_VERB:
        if url == token_url:
            return
        raise WriteAttemptBlocked(
            f"Blocked {verb} to {parts.netloc}{parts.path}. This tool is read-only; "
            "the only permitted POST is this tenant's token request."
        )
    if verb not in ("GET", "HEAD"):
        raise WriteAttemptBlocked(f"Blocked {verb} to {parts.netloc}{parts.path}. This tool is read-only.")
    if parts.netloc != GRAPH_HOST:
        raise WriteAttemptBlocked(f"Blocked request to unexpected host {parts.netloc}")
    segments = {s.lower() for s in parts.path.split("/") if s}
    if segments & _CONTENT_SEGMENTS:
        raise WriteAttemptBlocked(
            f"Blocked request for file content at {parts.path}. The tool reads sharing metadata, never file contents."
        )


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def client_assertion(creds: GraphCredentials, *, now: float | None = None) -> str:
    """A short-lived signed JWT proving possession of the certificate."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    issued = int(now if now is not None else time.time())
    header = {"alg": "RS256", "typ": "JWT", "x5t": _b64url(bytes.fromhex(creds.thumbprint))}
    claims = {
        "aud": creds.token_url,
        "iss": creds.client_id,
        "sub": creds.client_id,
        "jti": str(uuid.uuid4()),
        "nbf": issued,
        "iat": issued,
        "exp": issued + 600,
    }
    signing_input = f"{_b64url(json.dumps(header).encode())}.{_b64url(json.dumps(claims).encode())}"
    key = serialization.load_pem_private_key(creds.private_key_pem, password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("The Microsoft 365 key must be an RSA private key")
    signature = key.sign(signing_input.encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    return f"{signing_input}.{_b64url(signature)}"


Opener = Callable[..., Any]


class GraphReadOnly:
    """Microsoft Graph client that can only read.

    Every Graph request is recorded in `calls` (method, URL without query,
    status) for the run's read-only evidence. The token request is counted in
    `auth_requests` instead: it is authentication, not tenant access.
    """

    BASE = f"https://{GRAPH_HOST}/v1.0"

    def __init__(
        self,
        creds: GraphCredentials,
        *,
        recorder: list[ApiCallRecord] | None = None,
        opener: Opener | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.creds = creds
        self.calls: list[ApiCallRecord] = recorder if recorder is not None else []
        self.auth_requests = 0
        self._open = opener or urllib.request.urlopen
        self._timeout = timeout
        self._token: str | None = None
        self._token_expires = 0.0

    # -- authentication ---------------------------------------------------------

    def _access_token(self) -> str:
        if self._token and time.time() < self._token_expires - 60:
            return self._token
        form = urllib.parse.urlencode(
            {
                "client_id": self.creds.client_id,
                "scope": GRAPH_SCOPE,
                "grant_type": "client_credentials",
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": client_assertion(self.creds),
            }
        ).encode()
        url = self.creds.token_url
        check_request(_AUTH_VERB, url, token_url=url)
        request = urllib.request.Request(url, data=form, method=_AUTH_VERB)  # noqa: S310 - https enforced by check_request above
        request.add_header("Content-Type", "application/x-www-form-urlencoded")
        self.auth_requests += 1
        payload = self._send(request)
        self._token = str(payload["access_token"])
        self._token_expires = time.time() + float(payload.get("expires_in", 3600))
        return self._token

    # -- reads ------------------------------------------------------------------

    def get(self, path_or_url: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        url = (
            path_or_url if path_or_url.startswith("https://") else f"{self.BASE}/{path_or_url.lstrip('/')}"
        )
        if params:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params, safe="$,")
        check_request("GET", url, token_url=self.creds.token_url)

        request = urllib.request.Request(url, method="GET")  # noqa: S310 - https enforced by check_request above
        request.add_header("Authorization", f"Bearer {self._access_token()}")
        request.add_header("Accept", "application/json")
        record_url = urllib.parse.urlsplit(url)._replace(query="").geturl()
        try:
            payload = self._send(request)
        except GraphError as exc:
            self.calls.append(ApiCallRecord(method="GET", url=record_url, status=exc.status))
            raise
        self.calls.append(ApiCallRecord(method="GET", url=record_url, status=200))
        return payload

    def paginate(
        self, path: str, params: dict[str, Any] | None = None, *, max_pages: int | None = None
    ) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        page = self.get(path, params)
        pages = 1
        while True:
            items.extend(page.get("value", []))
            next_link = page.get("@odata.nextLink")
            if not next_link or (max_pages is not None and pages >= max_pages):
                return items
            page = self.get(str(next_link))  # checked like any other URL
            pages += 1

    # -- transport --------------------------------------------------------------

    def _send(self, request: urllib.request.Request) -> dict[str, Any]:
        try:
            with self._open(request, timeout=self._timeout) as response:
                body = response.read()
        except urllib.error.HTTPError as exc:
            raw = exc.read() if hasattr(exc, "read") else b""
            code, message = "error", raw.decode("utf-8", "replace")[:300]
            try:
                error = json.loads(raw or b"{}")
                if isinstance(error.get("error"), dict):  # Graph
                    code, message = error["error"].get("code", code), error["error"].get("message", message)
                elif "error" in error:  # login service
                    code, message = str(error["error"]), str(error.get("error_description", ""))[:300]
            except ValueError:
                pass
            raise GraphError(exc.code, code, message) from None
        return json.loads(body or b"{}")
