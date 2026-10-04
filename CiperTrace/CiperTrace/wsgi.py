"""
wsgi.py
=========

WSGI entrypoint for container hosts (Cloud Run, or any gunicorn deployment):

    gunicorn --bind :8080 wsgi:app

Differences from the local `ps26237 serve` path:
  * the workspace lives under $PS26237_HOME (default /tmp on Cloud Run, which is
    RAM and disappears when the instance stops — demo data only);
  * demo identities are seeded on first boot so the UI is usable immediately;
  * HTTP basic auth is required when running on Cloud Run (see app/auth.py).
"""

from __future__ import annotations
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.service import Workspace, resolve_workspace_dir
from app.web import create_app
from app.auth import install_basic_auth

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("ps26237")

ws = Workspace(resolve_workspace_dir())
seeded = ws.seed_demo_identities_if_empty()
if seeded:
    log.info("seeded demo identities: %s", ", ".join(seeded))

app = create_app(ws)
install_basic_auth(app)

from crypto.pqc import BACKEND, IS_REFERENCE_IMPLEMENTATION

log.info("PS 26237 starting | workspace=%s | ledger=%s | crypto=%s",
         ws.root, ws.ledger_backend, BACKEND)
if IS_REFERENCE_IMPLEMENTATION:
    log.warning("NOT POST-QUANTUM: liboqs is unavailable, so the size-matched "
                "classical fallback (X25519/Ed25519) is active. Do not present "
                "this instance as running NIST PQC.")
