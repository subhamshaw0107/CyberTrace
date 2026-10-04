"""
api/index.py
============

Vercel Serverless Function entrypoint for PS 26237.
Vercel automatically detects the Flask WSGI instance named `app`.
"""

import os
import sys

# 1. Ensure project root is in sys.path
_current_dir = os.path.dirname(os.path.abspath(__file__))
_root_dir = os.path.dirname(_current_dir)
if _root_dir not in sys.path:
    sys.path.insert(0, _root_dir)

# 2. Configure Vercel serverless environment
os.environ["VERCEL"] = "1"
if not os.environ.get("PS26237_HOME"):
    os.environ["PS26237_HOME"] = "/tmp/ps26237_workspace"

# 3. Initialize Workspace and create Flask app instance
from app.service import Workspace, resolve_workspace_dir
from app.web import create_app

ws = Workspace(resolve_workspace_dir())
ws.seed_demo_identities_if_empty()

# Vercel's Python runtime requires the WSGI application instance to be named `app`
app = create_app(ws)
