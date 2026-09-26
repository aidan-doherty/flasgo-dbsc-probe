# dbsc-probe

A small **flasgo** demo site, in the spirit of https://dbsc.dev/, that runs
[dbsc-python](https://github.com/L1ghtn1ng/dbsc-python) end to end so you can watch Device Bound
Session Credentials work in a real browser.

It is the visual proof-of-integration for wiring `dbsc` into flasgo: every DBSC operation flows
through flasgo (signed session cookies, route dispatch, security headers) while all DBSC state
lives in a dedicated `InMemoryStore`, keyed by the probe id.

## What you see

- `Secure-Session-Registration` advertised on the probe page; a DBSC-capable browser registers
  automatically and the page reflects it.
- The signed registration JWT (raw, header, payload), the bound **device public key** (PEM), and
  the session-instructions JSON.
- The bound-cookie **refresh watch**: the `__Host-dbsc` cookie lives for 180s and the browser
  flushes it through `/dbsc/refresh` before it expires.
- The **enforcement gate** decision (`/check`): degraded / pass / terminate, exactly as a host
  application would compute it.
- A server-side **timeline** of DBSC audit events for the probe, which survives page reloads.
- **Run the test again** revokes the probe and starts fresh; **Copy diagnostic** dumps the full
  state.

## Requirements

- Python 3.14 (`uv` recommended)
- A DBSC-capable browser (see the note below — this is the fiddly part).

### Why stable Chrome won't show registration on localhost

DBSC standard registration is origin-gated. `http://localhost:8000` is a secure context, so the
*server* side is fine — but current Chrome (Stable 152+/Edge, and even Dev/Canary) will only offer
to register origins that are approved or carry an origin-trial token. That's why a site like
dbsc.dev registers in your everyday browser while the probe page sits at "Registration offered":
dbsc.dev is an approved origin, localhost is not. Chrome 146/147 accepted a
`chrome://flags/#device-bound-session-credentials` "Enabled - For developers" override for
arbitrary origins; newer builds silently ignore it (verified up through Stable 153/154 on
2026-09-24 — they ignore it over http and https, headed and headless).

The one configuration that reliably registers an arbitrary loopback origin is a **Chrome for
Testing 149** build started with the developer feature string. These are the switch combinations
the dbsc-python e2e suite runs against (see `tests/e2e/conftest.py` in that repo); Chrome 149 and
150 honour them, current channels do not.

### Launching Chrome for Testing 149 (local loopback, Linux or Windows)

Linux — download Chrome for Testing **149.0.7827.55** (`linux64`) from Google's Chrome for Testing
downloads page and unpack `chrome-linux64` somewhere; or reuse the pinned copy the dbsc-python
repo fetches (`uv run python scripts/fetch_e2e_browser.py`). Then:

```bash
CHROME=/path/to/chrome-linux64/chrome
"$CHROME" --user-data-dir=/tmp/dbsc-chrome \
  --enable-features="DeviceBoundSessions:RequireOriginTrialTokens/false/RefreshQuota/false/CheckSubdomainRegistration/false/OriginTrialFeedback/true/SchemaVersion/2,EnableBoundSessionCredentialsSoftwareKeysForManualTesting" \
  http://localhost:8000/
```

Windows — download Chrome for Testing **149.0.7827.55** (`win64`) from the same Chrome for Testing
downloads page, unzip it (the `chrome.exe` sits in the unpacked `chrome-win64` folder), and launch
through cmd (PowerShell backtick line continuations are easy to botch):

```bat
"%USERPROFILE%\dbsc-chrome149\chrome-win64\chrome.exe" --user-data-dir="%USERPROFILE%\dbsc-chrome149-profile" --enable-features="DeviceBoundSessions:RequireOriginTrialTokens/false/RefreshQuota/false/CheckSubdomainRegistration/false/OriginTrialFeedback/true/SchemaVersion/2,EnableBoundSessionCredentialsSoftwareKeysForManualTesting" http://localhost:8000/
```

Sanity check before trusting the window: `chrome://version` must read **Chrome for Testing
149.0.7827.55** and its **Command Line** field must contain `DeviceBoundSessions:...`. If it shows
your normal Chrome or a missing command line, the flags never applied and registration won't fire.

## Run

The repo depends on sibling checkouts of its own project root, via
[uv path sources](https://docs.astral.sh/uv/reference/settings/#path-dependencies):

```
../flasgo
../dbsc-python
```

```bash
uv sync
uv run uvicorn dbsc_probe.app:create_app --factory --host 127.0.0.1 --port 8000
```

Then open http://localhost:8000/ in the DBSC-capable browser. Plain `http` on loopback is a
secure context, so the `Secure` cookies and the flasgo signed session work without TLS. A
reverse proxy over `https://` works too; DBSC itself always requires `https` (or loopback http).

Set `DBSC_PROBE_SECRET` to pin the flasgo session/CSRF signing key, e.g. for stable sessions
across restarts:

```bash
DBSC_PROBE_SECRET="$(openssl rand -base64 48)" uv run uvicorn ...
```

## Endpoints

| Method | Path               | Purpose                                                |
| ------ | ------------------ | ------------------------------------------------------ |
| GET    | `/`                | Probe page; advertises `Secure-Session-Registration`   |
| GET    | `/status`          | JSON state the page renders (polled by the client)     |
| GET    | `/check`           | Enforcement-gate decision for the current request      |
| GET    | `/favicon.ico`     | 204; excluded from the DBSC scope                      |
| POST   | `/dbsc/register`   | Browser posts its signed registration JWT              |
| POST   | `/dbsc/refresh`    | Browser refreshes the bound cookie                     |
| POST   | `/restart`         | Revoke the current probe and start fresh               |

## Integration notes

- CSRF is disabled (`CSRF_ENABLED=False`): DBSC POSTs are browser fetches with no CSRF token, so
  a real deployment either disables CSRF for `.well-known/dbsc` paths or exempts them with a
  secure origin check. Security headers (CSP `default-src 'self'`, no-store, frame denial) remain
  on and are merged with DBSC's own no-store via header `setdefault`.
- The probe id is stored in flasgo's signed session cookie. DBSC state is keyed by that id in
  `InMemoryStore`, deliberately *not* inside the session blob (the race the dbsc-python README
  warns about).
- For a real app, replace `InMemoryStore` with a durable store and put the enforcement gate in
  your own route policy in front of protected resources.

## Development

```bash
uv run ruff check .
uv run ruff format --check .
uv run ty check
uv run pytest
```

End-to-end visual testing with a pinned Chrome 149 that actually performs DBSC registration is
described in the dbsc-python e2e suite (`DBSC_E2E_BROWSER`).

The pytest suite drives the full flow over the flasgo `TestClient` without a browser: offer →
register (crafted ES256 JWT) → two-phase refresh → enforcement gate → restart, plus the failure
paths and an unreadable-record fail-closed case.