"""
index.py
========

Root WSGI entrypoint for Vercel, Gunicorn, and other serverless/container hosts.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.service import Workspace, resolve_workspace_dir
from app.web import create_app

workspace_dir = resolve_workspace_dir()
ws = Workspace(workspace_dir)
ws.seed_demo_identities_if_empty()

# WSGI application instance
app = create_app(ws)
