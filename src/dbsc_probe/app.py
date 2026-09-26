"""A flasgo demo site, like dbsc.dev, that runs dbsc-python end to end.

Browsers drive DBSC entirely via headers: the server advertises registration with
``Secure-Session-Registration`` on the probe page, the browser POSTs a signed registration JWT
to ``/dbsc/register``, and thereafter flushes an expired bound cookie through ``/dbsc/refresh``.
There is no JS DBSC API, so the page is a plain HTML/CSS/JS client that polls ``/status`` and
renders whatever DBSC is doing.

CSRF is disabled: DBSC POSTs are driven by the browser's own fetch, which sends no CSRF token.
Security headers (CSP ``default-src 'self'``, no-store caching, frame denial) stay on.

Run with::

    uv run uvicorn dbsc_probe.app:create_app --factory --host 127.0.0.1 --port 8000
"""

from __future__ import annotations

import base64
import contextvars
import json
import logging
import os
import secrets
import time
from collections import defaultdict
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from dbsc import (
    AuditEvent,
    AuditLogger,
    Binding,
    Config,
    Cookie,
    CorruptStateError,
    DbscError,
    DbscResponse,
    DbscServer,
    InMemoryStore,
    RequestContext,
    RetryableRefreshError,
    ScopeRule,
    Store,
)
from flasgo import Flasgo, Response, Settings
from flasgo.globals import request, session

logger = logging.getLogger(__name__)

PACKAGE_ROOT = Path(__file__).parent

COOKIE_NAME = "__Host-dbsc"
COOKIE_MAX_AGE_SECONDS = 180
CHALLENGE_TTL_SECONDS = 900

_current_probe: contextvars.ContextVar[str] = contextvars.ContextVar("dbsc_probe", default="")


class ProbeAudit(AuditLogger):
    """Append every DBSC state transition to the probe timeline of the request in flight."""

    def __init__(self, timelines: dict[str, list[dict[str, Any]]]) -> None:
        self._timelines = timelines

    async def log(self, event: AuditEvent, message: str, user_id: str | None) -> None:  # noqa: ARG002
        probe = _current_probe.get()
        if probe:
            self._timelines[probe].append(
                {"event": str(event), "time": int(time.time()), "message": message}
            )


def _set_cookie_header(cookie: Cookie) -> str:
    parts = [f"{cookie.name}={'' if cookie.delete else cookie.value}", f"Path={cookie.path}"]
    if cookie.delete:
        parts.extend(("Expires=Thu, 01 Jan 1970 00:00:01 GMT", "Max-Age=0"))
    else:
        parts.append(f"Max-Age={max(cookie.expires_at - int(time.time()), 0)}")
    if cookie.secure:
        parts.append("Secure")
    if cookie.http_only:
        parts.append("HttpOnly")
    parts.append(f"SameSite={cookie.same_site}")
    return "; ".join(parts)


def _endpoint_response(dbsc_response: DbscResponse) -> Response:
    """Turn a DBSC endpoint response into a flasgo Response (status, body, headers, cookies)."""

    return Response(
        body=(dbsc_response.body or "").encode("utf-8"),
        status_code=dbsc_response.status or 200,
        headers={name.lower(): value for name, value in dbsc_response.headers.items()},
        cookies=[_set_cookie_header(cookie) for cookie in dbsc_response.cookies],
        content_type=dbsc_response.content_type or "application/json",
    )


def _decorate(response: Response, dbsc_response: DbscResponse) -> Response:
    """Merge a decoration-only DBSC response into an existing one (offer header, seed challenge)."""

    for name, value in dbsc_response.headers.items():
        response.headers.setdefault(name.lower(), value)
    response.cookies.extend(_set_cookie_header(cookie) for cookie in dbsc_response.cookies)
    return response


def _response_jwt(ctx: RequestContext) -> str:
    header = ctx.header("sec-session-response") or ctx.header("secure-session-response") or ""
    return header.strip('"')


def _decode_segment(segment: str) -> dict[str, Any] | None:
    padded = segment + "=" * (-len(segment) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    except ValueError, UnicodeEncodeError:
        return None
    try:
        value = json.loads(raw)
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def _parse_jwt_parts(jwt: str) -> dict[str, Any]:
    parts = jwt.split(".")
    if len(parts) != 3:
        return {"raw": jwt}
    return {
        "raw": jwt,
        "header": _decode_segment(parts[0]) or {},
        "payload": _decode_segment(parts[1]) or {},
    }


class ProbeApp:
    """The probe site: one ``DbscServer`` plus the state the page renders.

    The probe id lives in the signed flasgo session cookie, so a page reload resumes the same
    probe. All DBSC state is keyed by that id in the dedicated ``InMemoryStore`` -- deliberately
    NOT in the session blob, the exact race the library's README warns about.
    """

    def __init__(self, *, store: Store | None = None) -> None:
        settings = Settings(
            CSRF_ENABLED=False,
            SECRET_KEY=os.environ.get("DBSC_PROBE_SECRET") or secrets.token_urlsafe(48),
        )
        self.app = Flasgo(settings=settings)
        self.app.configure_templates(PACKAGE_ROOT / "templates")
        self.app.configure_static(PACKAGE_ROOT / "static", cache_max_age=0)

        self.config = Config(
            cookie_name=COOKIE_NAME,
            cookie_max_age_seconds=COOKIE_MAX_AGE_SECONDS,
            challenge_ttl_seconds=CHALLENGE_TTL_SECONDS,
            scope_specification=[ScopeRule.exclude(path="/favicon.ico")],
        )
        self.timelines: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.reg_headers: dict[str, str] = {}
        self.jwts: dict[str, dict[str, Any]] = {}
        self.service = DbscServer(
            self.config, store or InMemoryStore(), audit=ProbeAudit(self.timelines)
        )

        self.app.get("/", public=True)(self.index)
        self.app.get("/status", public=True)(self.status)
        self.app.get("/check", public=True)(self.check)
        self.app.get("/favicon.ico", public=True)(self.favicon)
        self.app.post("/dbsc/register", public=True)(self.register)
        self.app.post("/dbsc/refresh", public=True)(self.refresh)
        self.app.post("/restart", public=True)(self.restart)

    # --- Request/response plumbing ---------------------------------------------------------

    def _origin(self) -> str:
        # flasgo already rejected any Host outside ALLOWED_HOSTS before this handler ran.
        return f"{request.scheme}://{request.headers.get('host')}"

    def _probe_id(self) -> str:
        probe = session.get("probe")
        if not probe:
            probe = secrets.token_urlsafe(32)
            session["probe"] = probe
            self.timelines[probe].append(
                {"event": "PROBE_STARTED", "time": int(time.time()), "message": "Probe created."}
            )
        return probe

    def _context(self, probe: str) -> RequestContext:
        return RequestContext(
            session_id=probe,
            user_id="",
            origin_host_url=self._origin(),
            headers=dict(request.headers),
            cookies=dict(request.cookies),
        )

    async def _binding(self, ctx: RequestContext) -> tuple[Binding | None, bool]:
        try:
            return await self.service.get_binding(ctx), False
        except CorruptStateError:
            return None, True

    # --- Routes ----------------------------------------------------------------------------

    async def index(self) -> Response:
        probe = self._probe_id()
        _current_probe.set(probe)
        ctx = self._context(probe)

        offered = await self.service.build_registration_header_response(ctx)
        merged = dict(offered.headers)
        if value := offered.headers.get("Secure-Session-Registration"):
            self.reg_headers[probe] = value

        binding, _ = await self._binding(ctx)
        if binding is not None and self.service.is_document_request(ctx):
            advertised = await self.service.advertise_refresh_challenge(binding, ctx)
            merged.update(advertised.headers)

        response = Response.template("index.html", templates=self.app.templates, context={})
        return _decorate(response, DbscResponse(headers=merged))

    async def status(self) -> Response:
        probe = self._probe_id()
        ctx = self._context(probe)
        binding, corrupt = await self._binding(ctx)

        instructions: Mapping[str, Any] | None = None
        if binding is not None:
            raw = await self.service.session_instructions_json(ctx)
            if raw:
                try:
                    instructions = json.loads(raw)
                except ValueError:
                    instructions = None

        return Response.json(
            {
                "probe": probe,
                "origin": ctx.origin_host_url,
                "cookie": {
                    "name": self.config.cookie_name,
                    "max_age": self.config.cookie_max_age_seconds,
                    "present": ctx.cookie(self.config.cookie_name) is not None,
                },
                "registered": binding is not None and not corrupt,
                "corrupt": corrupt,
                "binding": None if binding is None else self._binding_dict(binding),
                "bound_cookie_matches": (
                    None if binding is None else self.service.bound_cookie_matches(binding, ctx)
                ),
                "registration_header": self.reg_headers.get(probe),
                "registration_jwt": self.jwts.get(probe),
                "instructions": instructions,
                "timeline": self.timelines.get(probe, []),
                "now": int(time.time()),
            }
        )

    async def check(self) -> Response:
        probe = self._probe_id()
        ctx = self._context(probe)
        binding, corrupt = await self._binding(ctx)
        if corrupt:
            return Response.json({"registered": False, "corrupt": True, "decision": "fail_closed"})
        if binding is None:
            return Response.json({"registered": False, "decision": "degraded"})

        is_document = self.service.is_document_request(ctx)
        in_grace = self.service.is_within_registration_grace(binding)
        must_check = is_document or not in_grace
        cookie_present = ctx.cookie(self.config.cookie_name) is not None
        matches = self.service.bound_cookie_matches(binding, ctx)
        return Response.json(
            {
                "registered": True,
                "is_document": is_document,
                "in_grace": in_grace,
                "must_check": must_check,
                "cookie_present": cookie_present,
                "bound_cookie_matches": matches,
                "decision": "terminate" if must_check and not matches else "pass",
            }
        )

    async def favicon(self) -> Response:
        return Response(body=b"", status_code=204)

    async def register(self) -> Response:
        probe = self._probe_id()
        _current_probe.set(probe)
        ctx = self._context(probe)
        jwt = _response_jwt(ctx)
        if not jwt:
            return Response.json(
                {"ok": False, "error": "Missing Sec-Session-Response header."}, status_code=400
            )
        try:
            dbsc_response = await self.service.register(jwt, ctx)
        except DbscError as exc:
            logger.info("Registration refused: %s: %s", type(exc).__name__, exc)
            return Response.json({"ok": False}, status_code=401)
        self.jwts[probe] = _parse_jwt_parts(jwt)
        return _endpoint_response(dbsc_response)

    async def refresh(self) -> Response:
        probe = self._probe_id()
        _current_probe.set(probe)
        ctx = self._context(probe)
        jwt = _response_jwt(ctx)
        if not jwt:
            return _endpoint_response(await self.service.issue_refresh_challenge(ctx))
        try:
            dbsc_response = await self.service.refresh(jwt, ctx)
        except RetryableRefreshError:
            return _endpoint_response(await self.service.issue_refresh_challenge(ctx))
        except DbscError as exc:
            logger.info("Refresh failed terminally: %s: %s", type(exc).__name__, exc)
            revoked = await self.service.revoke(ctx, enforcement_terminated=True)
            return _decorate(Response.json({"ok": False}, status_code=401), revoked)
        self.jwts[probe] = _parse_jwt_parts(jwt)
        return _endpoint_response(dbsc_response)

    async def restart(self) -> Response:
        response = Response.json({"ok": True})
        probe = session.get("probe")
        if probe:
            _current_probe.set(probe)
            ctx = RequestContext(probe, "", self._origin(), {}, {})
            revoked = await self.service.revoke(ctx)
            response = _decorate(response, revoked)
            session.pop("probe")
        session["probe"] = secrets.token_urlsafe(32)
        return response

    # --- Helpers ---------------------------------------------------------------------------

    def _binding_dict(self, binding: Binding) -> dict[str, Any]:
        return {
            "session_identifier": binding.session_identifier,
            "algorithm": binding.algorithm,
            "public_key_pem": binding.public_key_pem,
            "created_at": binding.created_at,
            "cookie_issued_at": binding.cookie_issued_at,
            "cookie_expires_at": binding.cookie_issued_at + self.config.cookie_max_age_seconds,
            "has_refreshed": binding.has_refreshed,
            "challenge_advertised": binding.challenge_advertised,
        }


def create_app() -> Flasgo:
    """Application factory for uvicorn's ``--factory`` flag."""
    return ProbeApp().app
