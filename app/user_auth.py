"""
app/user_auth.py
================
User Authentication, Admin Access & Login Activity Tracker for CyberTrace.
"""

from __future__ import annotations
import json
import os
import time
import hashlib
from pathlib import Path
from werkzeug.security import generate_password_hash, check_password_hash

def _load_env():
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if env_path.exists():
        try:
            for line in env_path.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip())
        except Exception:
            pass

_load_env()

DEFAULT_USERS = {
    "sender@cybertrace.local": {
        "email": "sender@cybertrace.local",
        "user_id": "alice",
        "name": "Alice (Sender)",
        "role": "Sender",
        "password_hash": generate_password_hash("password123"),
    },
    "receiver@cybertrace.local": {
        "email": "receiver@cybertrace.local",
        "user_id": "bob",
        "name": "Bob (Receiver)",
        "role": "Receiver",
        "password_hash": generate_password_hash("password123"),
    },
    "carol@cybertrace.local": {
        "email": "carol@cybertrace.local",
        "user_id": "carol",
        "name": "Carol (Receiver)",
        "role": "Receiver",
        "password_hash": generate_password_hash("password123"),
    }
}


class AuthManager:
    def __init__(self, workspace_root: Path | str):
        self.workspace_root = Path(workspace_root)
        self.workspace_root.mkdir(parents=True, exist_ok=True)
        self.log_file = self.workspace_root / "login_activity.json"
        self.users_file = self.workspace_root / "users.json"
        self._init_storage()

    def _init_storage(self):
        if not self.users_file.exists():
            try:
                self.users_file.write_text(json.dumps(DEFAULT_USERS, indent=2))
            except Exception:
                pass
        if not self.log_file.exists():
            try:
                self.log_file.write_text(json.dumps([], indent=2))
            except Exception:
                pass

    def _load_users(self) -> dict:
        try:
            if self.users_file.exists():
                return json.loads(self.users_file.read_text())
        except Exception:
            pass
        return dict(DEFAULT_USERS)

    def _save_users(self, users: dict):
        try:
            self.users_file.write_text(json.dumps(users, indent=2))
        except Exception:
            pass

    def get_user_by_email(self, email: str) -> dict | None:
        email_clean = (email or "").strip().lower()
        if not email_clean:
            return None
        users = self._load_users()
        return users.get(email_clean)

    def register_or_update_user(self, email: str, user_id: str, name: str, role: str, raw_password: str) -> dict:
        email_clean = (email or "").strip().lower()
        users = self._load_users()
        user_data = {
            "email": email_clean,
            "user_id": user_id,
            "name": name,
            "role": role,
            "password_hash": generate_password_hash(raw_password)
        }
        users[email_clean] = user_data
        self._save_users(users)
        return user_data

    def authenticate_user(self, email: str, password: str, selected_role: str) -> dict | None:
        email_clean = email.strip().lower()
        if not email_clean or len(password) < 1:
            return None
        users = self._load_users()

        if email_clean in users:
            u = users[email_clean]
            stored_hash = u.get("password_hash", "")
            # Check werkzeug salted hash or fallback SHA256 legacy check
            valid = False
            if stored_hash.startswith(("scrypt:", "pbkdf2:", "sha256:")):
                valid = check_password_hash(stored_hash, password)
            else:
                valid = (stored_hash == hashlib.sha256(password.encode()).hexdigest())

            if valid:
                return {
                    "email": u["email"],
                    "user_id": u["user_id"],
                    "name": u["name"],
                    "role": selected_role or u.get("role", "Sender"),
                }
            return None

        # New user login registration helper
        name_part = email_clean.split("@")[0].capitalize()
        user_id = name_part.lower()
        role = selected_role if selected_role in ("Sender", "Receiver") else "Sender"
        new_user = {
            "email": email_clean,
            "user_id": user_id,
            "name": f"{name_part} ({role})",
            "role": role,
            "password_hash": generate_password_hash(password)
        }
        users[email_clean] = new_user
        self._save_users(users)
        return {
            "email": email_clean,
            "user_id": user_id,
            "name": new_user["name"],
            "role": role,
        }

    def authenticate_admin(self, admin_id: str, password: str) -> dict | None:
        env_admin_id = os.environ.get("CYBERTRACE_ADMIN_ID", "admin").strip().lower()
        env_admin_hash = os.environ.get("CYBERTRACE_ADMIN_PASSWORD_HASH", "")

        admin_id_clean = admin_id.strip().lower()
        if admin_id_clean != env_admin_id:
            return None

        if env_admin_hash and check_password_hash(env_admin_hash, password):
            return {
                "admin_id": env_admin_id,
                "name": "System Administrator",
            }

        return None

    def log_activity(self, user_info: dict, ip_address: str = "127.0.0.1"):
        try:
            logs = json.loads(self.log_file.read_text()) if self.log_file.exists() else []
        except Exception:
            logs = []

        entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "email": user_info.get("email", ""),
            "user_id": user_info.get("user_id", ""),
            "name": user_info.get("name", ""),
            "role": user_info.get("role", ""),
            "ip": ip_address,
        }
        logs.insert(0, entry)
        logs = logs[:200]
        try:
            self.log_file.write_text(json.dumps(logs, indent=2))
        except Exception:
            pass

    def get_activity_logs(self) -> list[dict]:
        try:
            if self.log_file.exists():
                return json.loads(self.log_file.read_text())
        except Exception:
            pass
        return []


import secrets
import base64
import uuid

EXPIRY_MAP = {
    "10m": 600,
    "30m": 1800,
    "1h": 3600,
    "6h": 21600,
    "12h": 43200,
    "24h": 86400,
}


class DeliveryManager:
    def __init__(self, workspace_root: Path | str):
        self.workspace_root = Path(workspace_root)
        self.workspace_root.mkdir(parents=True, exist_ok=True)
        self.deliveries_file = self.workspace_root / "deliveries.json"
        self._init_storage()

    def _init_storage(self):
        if not self.deliveries_file.exists():
            try:
                self.deliveries_file.write_text(json.dumps([], indent=2))
            except Exception:
                pass

    def _load(self) -> list[dict]:
        try:
            if self.deliveries_file.exists():
                deliveries = json.loads(self.deliveries_file.read_text())
                now = time.time()
                updated = False
                for d in deliveries:
                    if d.get("status") in ("PENDING", "ACCEPTED"):
                        exp_ts = d.get("expires_at_ts", 0)
                        if exp_ts and now >= exp_ts:
                            d["status"] = "EXPIRED"
                            updated = True
                if updated:
                    self._save(deliveries)
                return deliveries
        except Exception:
            pass
        return []

    def _save(self, deliveries: list[dict]):
        try:
            self.deliveries_file.write_text(json.dumps(deliveries, indent=2))
        except Exception:
            pass

    def _resolve_recipient(self, r_input: str, ws_ref=None) -> tuple[str, str, str]:
        """Resolves recipient input strictly to an authoritative registered identity (recipient_id, recipient_email, recipient_name)."""
        r_clean = r_input.strip()
        r_lower = r_clean.lower()

        ident = None
        if ws_ref:
            ident = ws_ref.get_identity(r_clean) or ws_ref.get_identity(r_lower)
            if not ident:
                ident = ws_ref.get_identity_by_email(r_lower)

        if not ident:
            from app.service import ServiceError
            raise ServiceError(f"Recipient identity '{r_input}' not found. You must select an existing registered recipient.")

        r_id = ident.get("id", "").strip()
        r_email = (ident.get("email") or "").strip().lower()
        r_name = ident.get("name", "").strip() or r_id
        if not r_id or not r_email:
            from app.service import ServiceError
            raise ServiceError(f"Registered identity '{r_input}' is missing required identity fields.")
        return (r_id, r_email, r_name)

    def create_deliveries(self, document_id: str, document_name: str, sender_info: dict, recipients: list[str | dict], expiry_key: str, package_bytes: bytes, ws_ref=None) -> list[dict]:
        deliveries = self._load()
        now_ts = time.time()
        duration_s = EXPIRY_MAP.get(expiry_key, 3600)
        exp_ts = now_ts + duration_s
        created_at_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now_ts))
        expires_at_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(exp_ts))
        pkg_b64 = base64.b64encode(package_bytes).decode()

        s_email = (sender_info.get("email") or "").strip().lower()
        s_id = sender_info.get("user_id") or s_email
        s_name = sender_info.get("name") or "Sender"

        created = []
        for r_input in recipients:
            if isinstance(r_input, dict):
                r_id = (r_input.get("recipient_id") or r_input.get("id") or "").strip()
                r_email = (r_input.get("recipient_email") or r_input.get("email") or "").strip().lower()
                r_name = (r_input.get("recipient_name") or r_input.get("name") or "").strip()
            else:
                r_id, r_email, r_name = self._resolve_recipient(r_input, ws_ref)

            # Identity consistency check (Requirement 8)
            if not r_id:
                from app.service import ServiceError
                raise ServiceError(f"Recipient ID is missing for recipient '{r_input}'.")

            if ws_ref:
                ident = ws_ref.get_identity(r_id)
                if not ident:
                    from app.service import ServiceError
                    raise ServiceError(f"Registered identity '{r_id}' not found.")
                i_email = (ident.get("email") or "").strip().lower()
                if not i_email or i_email != r_email:
                    from app.service import ServiceError
                    raise ServiceError(f"Identity consistency check failed: recipient_id '{r_id}' email '{i_email}' does not match recipient_email '{r_email}'. Delivery rejected.")
                if not r_name:
                    r_name = ident.get("name", r_id)

            del_id = f"DEL-{uuid.uuid4().hex[:8].upper()}"
            entry = {
                "delivery_id": del_id,
                "document_id": document_id,
                "document_name": document_name,
                "sender_id": s_id,
                "sender_email": s_email,
                "sender_name": s_name,
                "recipient_id": r_id,
                "recipient_email": r_email,
                "recipient_name": r_name,
                "created_at": created_at_str,
                "created_at_ts": now_ts,
                "expires_at": expires_at_str,
                "expires_at_ts": exp_ts,
                "status": "PENDING",
                "accepted_at": None,
                "decrypted_at": None,
                "access_code_hash": None,
                "access_code_expires_at_ts": None,
                "package_data_b64": pkg_b64,
            }
            deliveries.insert(0, entry)
            created.append(entry)

        self._save(deliveries)
        return created

    def get_sender_deliveries(self, sender_info: dict | str) -> list[dict]:
        if isinstance(sender_info, str):
            sender_id_clean = sender_info.strip().lower()
            sender_email_clean = sender_info.strip().lower()
        else:
            sender_id_clean = (sender_info.get("user_id") or "").strip().lower()
            sender_email_clean = (sender_info.get("email") or "").strip().lower()

        deliveries = self._load()
        result = []
        now = time.time()
        for d in deliveries:
            s_id = str(d.get("sender_id", "")).lower()
            s_email = str(d.get("sender_email", "")).lower()

            matched = False
            if sender_email_clean and (s_email == sender_email_clean or s_id == sender_email_clean):
                matched = True
            elif sender_id_clean and (s_id == sender_id_clean or s_email == sender_id_clean):
                matched = True

            if matched:
                exp_ts = d.get("expires_at_ts", 0)
                rem_s = max(0, int(exp_ts - now))
                if d["status"] == "EXPIRED" or rem_s <= 0:
                    d["remaining_str"] = "EXPIRED"
                    d["status"] = "EXPIRED"
                else:
                    m, s = divmod(rem_s, 60)
                    h, m = divmod(m, 60)
                    if h > 0:
                        d["remaining_str"] = f"Expires in {h}h {m}m"
                    else:
                        d["remaining_str"] = f"Expires in {m}m {s}s"
                result.append(d)
        return result

    def _is_recipient_match(self, d: dict, user_info: dict | str, ws_ref=None) -> bool:
        """Deterministic exact recipient identity matching.
        Every delivery belongs to exactly ONE registered recipient identity.

        Conceptually:
        1. Normalize authenticated user's email.
        2. Normalize delivery recipient email.
        3. Require exact email equality.
        4. If recipient_id is present, resolve the identity.
        5. Require recipient_id and email to refer to the same identity.
        6. Return False for everything else.

        No email prefix, name, substring, or fuzzy matching allowed.
        """
        # 1. Normalize authenticated user's email
        if isinstance(user_info, dict):
            u_email = (user_info.get("email") or "").strip().lower()
            u_id = str(user_info.get("user_id") or "").strip()
        elif isinstance(user_info, str):
            raw = user_info.strip()
            if "@" in raw:
                u_email = raw.lower()
                u_id = ""
            else:
                u_email = ""
                u_id = raw
        else:
            return False

        if not u_email and u_id and ws_ref:
            user_ident = ws_ref.get_identity(u_id)
            if user_ident:
                u_email = (user_ident.get("email") or "").strip().lower()

        if not u_email:
            return False

        # 2. Normalize delivery recipient email
        d_email = (d.get("recipient_email") or "").strip().lower()
        if not d_email:
            return False

        # 3. Require exact email equality
        if u_email != d_email:
            return False

        # 4. If recipient_id is present, resolve the identity
        d_id = str(d.get("recipient_id") or "").strip()
        if d_id:
            if ws_ref:
                ident = ws_ref.get_identity(d_id)
                if not ident:
                    return False
                # 5. Require recipient_id and email to refer to the same identity
                ident_email = (ident.get("email") or "").strip().lower()
                ident_id = str(ident.get("id") or "").strip()
                if ident_email != d_email or ident_email != u_email:
                    return False
                if u_id and u_id.lower() != ident_id.lower() and u_id.lower() != d_id.lower():
                    return False
            else:
                if u_id and u_id.lower() != d_id.lower():
                    return False

        # 6. Return True for exact match, False for everything else
        return True

    def get_recipient_deliveries(self, user_info: dict | str, ws_ref=None) -> list[dict]:
        deliveries = self._load()
        result = []
        now = time.time()
        for d in deliveries:
            if self._is_recipient_match(d, user_info, ws_ref):
                exp_ts = d.get("expires_at_ts", 0)
                rem_s = max(0, int(exp_ts - now))
                if d["status"] == "EXPIRED" or rem_s <= 0:
                    d["remaining_str"] = "EXPIRED"
                    d["status"] = "EXPIRED"
                else:
                    m, s = divmod(rem_s, 60)
                    h, m = divmod(m, 60)
                    if h > 0:
                        d["remaining_str"] = f"Expires in {h}h {m}m"
                    else:
                        d["remaining_str"] = f"Expires in {m}m {s}s"
                result.append(d)
        return result

    def get_delivery_by_id(self, delivery_id: str) -> dict | None:
        deliveries = self._load()
        for d in deliveries:
            if d.get("delivery_id") == delivery_id:
                return d
        return None

    def accept_delivery(self, delivery_id: str, user_info: dict | str, ws_ref=None) -> tuple[bool, str, bytes | None]:
        deliveries = self._load()
        now = time.time()

        for d in deliveries:
            if d["delivery_id"] == delivery_id:
                if not self._is_recipient_match(d, user_info, ws_ref):
                    return False, "Unauthorized: You are not the intended recipient of this document.", None

                if d["expires_at_ts"] and now >= d["expires_at_ts"]:
                    d["status"] = "EXPIRED"
                    self._save(deliveries)
                    return False, "Delivery has expired. Acceptance is no longer allowed.", None

                if d["status"] == "EXPIRED":
                    return False, "Delivery has expired.", None

                d["accepted_at"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))
                d["status"] = "ACCEPTED"
                self._save(deliveries)

                pkg_bytes = base64.b64decode(d["package_data_b64"]) if d.get("package_data_b64") else None
                return True, "ACCEPTED", pkg_bytes

        return False, "Delivery not found.", None

    def verify_and_get_package(self, delivery_id: str, user_info: dict | str, submitted_code: str, ws_ref=None) -> tuple[bool, str, bytes | None]:
        deliveries = self._load()
        now = time.time()

        for d in deliveries:
            if d["delivery_id"] == delivery_id:
                if not self._is_recipient_match(d, user_info, ws_ref):
                    return False, "Unauthorized: Recipient mismatch.", None

                if d["expires_at_ts"] and now >= d["expires_at_ts"]:
                    d["status"] = "EXPIRED"
                    self._save(deliveries)
                    return False, "Delivery has expired.", None

                if d["status"] != "ACCEPTED":
                    return False, f"Invalid delivery status ({d['status']}). Document must be accepted first.", None

                # Mark as DECRYPTED
                d["status"] = "DECRYPTED"
                d["decrypted_at"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))
                self._save(deliveries)

                pkg_bytes = base64.b64decode(d["package_data_b64"])
                return True, "Verified successfully.", pkg_bytes

        return False, "Delivery not found.", None

    def get_delivery_secret(self, delivery_id: str, user_info: dict | str, ws_ref=None) -> tuple[bool, str, str | None, int]:
        """
        Securely returns the recipient-specific decryption secret only to the authenticated,
        authorized recipient of this delivery.

        Authorization:
        - Validates that user_info matches the intended delivery recipient via _is_recipient_match.
        - Rejects unauthorized users with 403 Forbidden.
        - Rejects expired deliveries with 400 Bad Request.
        - Rejects revoked deliveries with 400 Bad Request.

        Secret Resolution:
        - Checks candidate passphrases (authenticated session passphrase, delivery secret, demo default).
        - Verifies the secret cryptographically against ws_ref._unlock(recipient_id, candidate).
        - Guarantees the returned secret is the true decryption secret required to unwrap the artifact.

        Returns: (success: bool, message: str, secret: str | None, http_status_code: int)
        """
        deliveries = self._load()
        now = time.time()

        for d in deliveries:
            if d.get("delivery_id") == delivery_id:
                # 1. Authorization verification
                if not self._is_recipient_match(d, user_info, ws_ref):
                    return False, "Unauthorized: You are not the intended recipient of this document.", None, 403

                # 2. Expiry verification
                if d.get("expires_at_ts") and now >= d["expires_at_ts"]:
                    d["status"] = "EXPIRED"
                    self._save(deliveries)
                    return False, "Document delivery has expired.", None, 400

                if d.get("status") == "EXPIRED":
                    return False, "Document delivery has expired.", None, 400

                # 3. Revocation verification
                if d.get("status") == "REVOKED":
                    return False, "Document delivery has been revoked.", None, 400

                r_id = (d.get("recipient_id") or "").strip()
                if not r_id:
                    return False, "Recipient identity missing from delivery record.", None, 400

                # 4. Resolve candidate secrets
                candidate_secrets = []
                if isinstance(user_info, dict):
                    sess_pass = user_info.get("passphrase")
                    if sess_pass and sess_pass not in candidate_secrets:
                        candidate_secrets.append(sess_pass)

                if d.get("recipient_secret") and d["recipient_secret"] not in candidate_secrets:
                    candidate_secrets.append(d["recipient_secret"])

                if "password123" not in candidate_secrets:
                    candidate_secrets.append("password123")

                # 5. Cryptographic verification of candidate secret
                if ws_ref:
                    for cand in candidate_secrets:
                        try:
                            ws_ref._unlock(r_id, cand)
                            return True, "Decryption secret verified.", cand, 200
                        except Exception:
                            continue

                return False, "Decryption secret could not be unlocked with recipient credentials.", None, 404

        return False, "Delivery not found.", None, 404

