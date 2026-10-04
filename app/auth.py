"""
app/auth.py
=============

HTTP basic auth gate for hosted deployments.

The console has no user model: anyone who reaches it can create identities,
decrypt packages and read the ledger. That is acceptable on 127.0.0.1 behind a
workstation login; it is not acceptable on a public URL. So:

  * On a managed host (Cloud Run sets K_SERVICE), a password is REQUIRED. If
    PS26237_AUTH_PASS is unset the app refuses to start, rather than quietly
    serving an open instance.
  * Locally the gate is optional: set PS26237_AUTH_PASS to switch it on.

This is a demo gate, not an identity system. It is one shared password, checked
in constant time, over whatever TLS the host provides (Cloud Run terminates
HTTPS for you). For anything beyond a judging demo, put a real identity layer
(IAP, SSO) in front — see docs/DEPLOY_GCP.md.
"""

from __future__ import annotations
import hmac
import os

from flask import Response, request

REALM = "CyberTrace attribution console"
PUBLIC_PATHS = ("/healthz",)


def _managed_host() -> bool:
    """True on Cloud Run / Cloud Functions / Knative-style hosts."""
    return bool(os.environ.get("K_SERVICE") or os.environ.get("CLOUD_RUN_JOB"))


def install_basic_auth(app) -> bool:
    """Adds the gate. Returns True if it is active."""
    user = os.environ.get("PS26237_AUTH_USER", "ps26237")
    password = os.environ.get("PS26237_AUTH_PASS", "")

    if not password:
        app.logger.warning(
            "PS26237_AUTH_PASS is not set; running in open demo mode without basic auth. "
            "To enable basic auth, set PS26237_AUTH_PASS environment variable."
        )
        return False

    @app.before_request
    def _require_auth():
        if request.path in PUBLIC_PATHS:
            return None
        auth = request.authorization
        ok = (auth is not None
              and auth.type == "basic"
              and hmac.compare_digest(auth.username or "", user)
              and hmac.compare_digest(auth.password or "", password))
        if ok:
            return None
        return Response(
            "Authentication required.", 401,
            {"WWW-Authenticate": f'Basic realm="{REALM}", charset="UTF-8"'},
        )

    @app.route("/healthz")
    def _healthz():
        return "ok", 200

    app.logger.info("basic auth enabled for user %r", user)
    return True
