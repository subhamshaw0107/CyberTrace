"""
netlify/functions/api.py
=========================

Serverless entrypoint for Netlify Functions (AWS Lambda).
Hosts the PS 26237 Flask web console over a self-contained WSGI adapter.

Features:
  - Ephemeral workspace in /tmp/ps26237_workspace.
  - Automatic demo identity seeding (alice, bob, carol).
  - Path normalization (strips Netlify function rewrite prefixes).
  - Full binary payload support (Base64 encoding/decoding for PDFs, PNGs, and packages).
"""

from __future__ import annotations
import base64
import io
import os
import sys
import urllib.parse

# 1. Ensure project root is in sys.path
_current_dir = os.path.dirname(os.path.abspath(__file__))
_root_dir = os.path.dirname(os.path.dirname(_current_dir))
if _root_dir not in sys.path:
    sys.path.insert(0, _root_dir)

# 2. Configure serverless environment variables
os.environ["NETLIFY"] = "true"
if not os.environ.get("PS26237_HOME"):
    os.environ["PS26237_HOME"] = "/tmp/ps26237_workspace"

# 3. Initialize Workspace and Flask Application
from app.service import Workspace, resolve_workspace_dir
from app.web import create_app

_workspace = Workspace(resolve_workspace_dir())
_workspace.seed_demo_identities_if_empty()
_flask_app = create_app(_workspace)


def _normalize_path(event: dict) -> str:
    path = event.get("path") or "/"
    for prefix in ("/.netlify/functions/api", "/.netlify/functions/api/"):
        if path.startswith(prefix):
            path = path[len(prefix):]
            if not path.startswith("/"):
                path = "/" + path
            break
    return path or "/"


def handler(event: dict, context: any) -> dict:
    """AWS Lambda / Netlify Function WSGI entrypoint."""
    path = _normalize_path(event)
    method = (event.get("httpMethod") or "GET").upper()
    headers = event.get("headers") or {}
    query_params = event.get("queryStringParameters") or {}

    # Decode body if present
    body = event.get("body")
    body_bytes = b""
    if body:
        if event.get("isBase64Encoded"):
            try:
                body_bytes = base64.b64decode(body)
            except Exception:
                body_bytes = body.encode("utf-8") if isinstance(body, str) else body
        else:
            body_bytes = body.encode("utf-8") if isinstance(body, str) else body

    # Build WSGI environment
    environ = {
        "REQUEST_METHOD": method,
        "SCRIPT_NAME": "",
        "PATH_INFO": path,
        "QUERY_STRING": urllib.parse.urlencode(query_params),
        "SERVER_NAME": headers.get("host", "localhost").split(":")[0],
        "SERVER_PORT": headers.get("x-forwarded-port", "443"),
        "SERVER_PROTOCOL": "HTTP/1.1",
        "wsgi.version": (1, 0),
        "wsgi.url_scheme": headers.get("x-forwarded-proto", "https"),
        "wsgi.input": io.BytesIO(body_bytes),
        "wsgi.errors": sys.stderr,
        "wsgi.multithread": False,
        "wsgi.multiprocess": False,
        "wsgi.run_once": False,
    }

    content_type = headers.get("content-type") or headers.get("Content-Type")
    if content_type:
        environ["CONTENT_TYPE"] = content_type
    environ["CONTENT_LENGTH"] = str(len(body_bytes))

    for k, v in headers.items():
        k_upper = k.upper().replace("-", "_")
        if k_upper not in ("CONTENT_TYPE", "CONTENT_LENGTH"):
            environ[f"HTTP_{k_upper}"] = v

    response_status = [200]
    response_headers = []

    def start_response(status, resp_headers, exc_info=None):
        try:
            code = int(status.split(" ")[0])
            response_status[0] = code
        except Exception:
            response_status[0] = 200
        response_headers.extend(resp_headers)

    response_iter = _flask_app(environ, start_response)
    try:
        response_data = b"".join(response_iter)
    finally:
        if hasattr(response_iter, "close"):
            response_iter.close()

    header_dict = {}
    resp_content_type = ""
    for k, v in response_headers:
        header_dict[k] = v
        if k.lower() == "content-type":
            resp_content_type = v.lower()

    # Determine binary vs text response
    is_binary = any(t in resp_content_type for t in [
        "application/octet-stream",
        "application/pdf",
        "image/",
        "application/zip",
        "application/x-download",
    ])

    if is_binary:
        return {
            "statusCode": response_status[0],
            "headers": header_dict,
            "body": base64.b64encode(response_data).decode("ascii"),
            "isBase64Encoded": True,
        }
    else:
        try:
            return {
                "statusCode": response_status[0],
                "headers": header_dict,
                "body": response_data.decode("utf-8"),
                "isBase64Encoded": False,
            }
        except UnicodeDecodeError:
            return {
                "statusCode": response_status[0],
                "headers": header_dict,
                "body": base64.b64encode(response_data).decode("ascii"),
                "isBase64Encoded": True,
            }
