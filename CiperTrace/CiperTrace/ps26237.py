#!/usr/bin/env python3
"""
ps26237 -- command-line tool for encrypted distribution with per-recipient
forensic watermarking and ledger-backed attribution.

  python ps26237.py init    [--ledger sim|fabric]
  python ps26237.py keygen  --id alice
  python ps26237.py encrypt --doc report.pdf --recipients alice,bob,carol [--out report.ps26237]
  python ps26237.py decrypt --as alice --package report.ps26237 [--out-dir .]
  python ps26237.py trace   --leaked photo.jpg [--json]
  python ps26237.py ledger-status
  python ps26237.py serve   [--port 8237]

Workspace: --workspace DIR, or $PS26237_HOME, default ./ps26237_workspace.
Passphrases: prompted interactively, or read from $PS26237_PASSPHRASE for scripts.
Exit codes: 0 ok, 1 error, 2 trace ran but did not confirm a recipient.
"""
import argparse
import getpass
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _passphrase(prompt: str, confirm: bool = False) -> str:
    env = os.environ.get("PS26237_PASSPHRASE")
    if env:
        return env
    p = getpass.getpass(prompt)
    if confirm and p != getpass.getpass("Repeat passphrase: "):
        raise SystemExit("passphrases do not match")
    return p


def main(argv=None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        print("No command specified. Defaulting to 'serve' (starting web console)...")
        print("Run 'python ps26237.py --help' to see all available CLI commands.\n")
        argv = ["serve"]

    ap = argparse.ArgumentParser(prog="ps26237", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", default=os.environ.get("PS26237_HOME", "ps26237_workspace"))
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init", help="create/configure a workspace")
    p.add_argument("--ledger", choices=["sim", "fabric"], default="sim")

    p = sub.add_parser("keygen", help="create an identity (ML-KEM-768 + ML-DSA-65 key pairs)")
    p.add_argument("--id", required=True)

    p = sub.add_parser("encrypt", help="encrypt a document once for several recipients")
    p.add_argument("--doc", required=True)
    p.add_argument("--recipients", required=True, help="comma-separated identity ids")
    p.add_argument("--doc-id")
    p.add_argument("--out")

    p = sub.add_parser("decrypt", help="decrypt as a recipient: watermark, sign, commit to ledger")
    p.add_argument("--as", dest="rid", required=True)
    p.add_argument("--package", required=True)
    p.add_argument("--out-dir", default=".")

    p = sub.add_parser("trace", help="attribute a leaked copy (image or PDF)")
    p.add_argument("--leaked", required=True)
    p.add_argument("--json", action="store_true")

    sub.add_parser("ledger-status", help="ledger nodes, record count, cross-node integrity")
    sub.add_parser("identities", help="list identities")

    p = sub.add_parser("serve", help="start the local web UI")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8237)

    args = ap.parse_args(argv)

    from app.service import Workspace, ServiceError
    from watermark.document_formats import UnsupportedFormat

    try:
        if args.cmd == "init":
            ws = Workspace(args.workspace, ledger=args.ledger)
            print(f"workspace {os.path.abspath(args.workspace)} (ledger: {ws.ledger_backend})")
            return 0

        ws = Workspace(args.workspace)

        if args.cmd == "keygen":
            info = ws.create_identity(args.id, _passphrase(f"New passphrase for {args.id}: ", confirm=True))
            print(f"created identity '{info['id']}': {info['algorithms']['kem']} public key {info['kem_public_key_bytes']} B, "
                  f"{info['algorithms']['signature']} public key {info['dsa_public_key_bytes']} B ({info['algorithms']['backend']})")
            if ws.ledger_backend == "fabric":
                print("signing key registered on the Fabric ledger (write-once)")

        elif args.cmd == "identities":
            for rid in ws.list_identities():
                print(rid)

        elif args.cmd == "encrypt":
            data = open(args.doc, "rb").read()
            recipients = [r.strip() for r in args.recipients.split(",") if r.strip()]
            pkg = ws.encrypt(data, args.doc, recipients, args.doc_id)
            out = args.out or os.path.splitext(args.doc)[0] + ".ps26237"
            open(out, "wb").write(pkg)
            info = ws.package_info(pkg)
            print(f"encrypted {args.doc} once as {info['document_id']} for {', '.join(info['recipients'])} -> {out}")

        elif args.cmd == "decrypt":
            pkg = open(args.package, "rb").read()
            t = time.perf_counter()
            res = ws.decrypt(pkg, args.rid, _passphrase(f"Passphrase for {args.rid}: "))
            os.makedirs(args.out_dir, exist_ok=True)
            out = os.path.join(args.out_dir, res.filename)
            open(out, "wb").write(res.data)
            r = res.record
            print(f"decrypted {r['document_id']} as {args.rid} -> {out}")
            print(f"  watermark {r['watermark_id']}  session {r['session_id']}  {r['human_timestamp']}")
            print(f"  signed with {args.rid}'s ML-DSA-65 key; committed on {len(res.committed_on)} ledger nodes "
                  f"({ws.ledger_backend}) ref {res.ledger_ref[:16]}  [{time.perf_counter() - t:.1f}s]")

        elif args.cmd == "trace":
            t = time.perf_counter()
            out = ws.trace(open(args.leaked, "rb").read())
            if args.json:
                print(json.dumps(out.to_dict(), indent=1))
            else:
                print(out.report.pretty_print())
                if len(out.candidates_tried) > 1:
                    print("candidates tried: " + "; ".join(f"{c['source']} conf {c['confidence']} -> {c['verdict']}" for c in out.candidates_tried))
                print(f"[{time.perf_counter() - t:.1f}s]")
            return 0 if out.confirmed else 2

        elif args.cmd == "ledger-status":
            print(json.dumps(ws.ledger_status(), indent=1))

        elif args.cmd == "serve":
            from app.web import create_app
            print(f"PS26237 web UI on http://{args.host}:{args.port}  (workspace {os.path.abspath(args.workspace)}, ledger {ws.ledger_backend})")
            create_app(ws).run(host=args.host, port=args.port, threaded=True)
        return 0
    except (ServiceError, UnsupportedFormat, FileNotFoundError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
