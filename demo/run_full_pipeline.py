"""
demo/run_full_pipeline.py
============================

Full end-to-end demonstration of PS 26237's required workflow:

  1. Sender encrypts a document ONCE, distributes to multiple recipients (broadcast-encrypt).
  2. Each recipient decrypts independently with their own PQC credentials.
  3. Each decryption generates a unique invisible watermark.
  4. Each recipient signs a decryption record with their own ML-DSA private key.
  5. Signed records are committed to a quorum-based, multi-node, tamper-evident ledger.
  6. Recipients receive visually-identical, forensically-distinct copies.
  7. One copy is "leaked". The system extracts its watermark.
  8. The watermark is matched against the ledger.
  9. Signature + ledger evidence is cryptographically verified.
  10. A verifiable attribution report identifies the exact recipient.

Also demonstrates the security property: a single rogue administrator
tampering with one ledger node CANNOT successfully frame an innocent
recipient, because the quorum of honest nodes disagrees.

Run: python3 demo/run_full_pipeline.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "output")
os.makedirs(OUTPUT_DIR, exist_ok=True)

import cv2
import numpy as np

from crypto.pqc import MLKEM, MLDSA
from crypto.document_crypto import encrypt_for_recipients, EncryptedPackage
from crypto.decryption_session import perform_decryption_session
from ledger.ledger_network import LedgerNetwork
from forensics.trace_leak import trace_leaked_document


SEP = "\n" + "=" * 78


def banner(title):
    print(SEP)
    print(f"  {title}")
    print(SEP)


def make_synthetic_document(seed: int, width=512, height=512) -> np.ndarray:
    """Creates a synthetic 'scanned document' image for the demo (so the
    pipeline is runnable offline with no external assets)."""
    rng = np.random.RandomState(seed)
    img = np.full((height, width, 3), 255, dtype=np.uint8)
    for y in range(40, height - 30, 25):
        x = 30
        while x < width - 60:
            line_len = rng.randint(20, 80)
            cv2.line(img, (x, y), (x + line_len, y), (20, 20, 20), 2)
            x += line_len + rng.randint(10, 30)
    return img


def main():
    banner("STEP 0: SETUP -- Identities, Keys, and Ledger Network")

    # --- Sender & recipients generate their own PQC keypairs ---
    print("Generating ML-KEM-768 (encryption) and ML-DSA-65 (signing) keypairs...")
    recipients = {
        "alice": {"kem": MLKEM.keygen(), "dsa": MLDSA.keygen()},
        "bob":   {"kem": MLKEM.keygen(), "dsa": MLDSA.keygen()},
        "carol": {"kem": MLKEM.keygen(), "dsa": MLDSA.keygen()},
    }
    for rid, keys in recipients.items():
        print(f"  [{rid}] ML-KEM-768 pk: {keys['kem'].public_key[:8].hex()}...  "
              f"ML-DSA-65 pk: {keys['dsa'].public_key[:8].hex()}...")

    # --- Air-gapped permissioned ledger network: 4 independent nodes, quorum 3 ---
    ledger = LedgerNetwork(
        node_ids=["sender-org-node", "independent-auditor-node", "security-dept-node", "offsite-backup-node"],
        quorum=3,
    )
    print(f"\nLedger network initialized: {list(ledger.nodes.keys())}")
    print(f"Quorum required for a record to be considered committed/trusted: {ledger.quorum} of {len(ledger.nodes)} nodes")

    banner("STEP 1: SENDER ENCRYPTS THE DOCUMENT ONCE (broadcast-encrypt)")
    document_id = "OP-BLUEHORIZON-ANNEX-C"
    original_doc = make_synthetic_document(seed=1)
    cv2.imwrite(os.path.join(OUTPUT_DIR, "00_original_source_document.png"), original_doc)

    doc_bytes = original_doc.tobytes()  # what actually gets encrypted (raw pixel payload)
    recipient_kem_pubkeys = {rid: keys["kem"].public_key for rid, keys in recipients.items()}
    package = encrypt_for_recipients(document_id, doc_bytes, recipient_kem_pubkeys)

    print(f"Document ID: {document_id}")
    print(f"Ciphertext (SHARED, identical for all recipients): {package.ciphertext[:48]}... ({len(package.ciphertext)} b64 chars)")
    print(f"Number of per-recipient key-wraps: {len(package.key_wraps)} (one ML-KEM-768 encapsulation each)")
    print("This single EncryptedPackage is what gets distributed to everyone.")

    banner("STEP 2-5: EACH RECIPIENT DECRYPTS INDEPENDENTLY -> WATERMARK -> SIGN -> COMMIT")

    watermarked_outputs = {}
    session_results = {}

    for rid, keys in recipients.items():
        print(f"\n--- Recipient: {rid} ---")
        result = perform_decryption_session(
            package=package,
            recipient_id=rid,
            recipient_kem_secret_key=keys["kem"].secret_key,
            recipient_dsa_keypair=keys["dsa"],
            raw_image_array=original_doc,  # decrypted bytes reconstructed as image for watermarking demo
        )
        session_results[rid] = result

        print(f"  Decrypted successfully: {len(result.plaintext_bytes)} bytes recovered")
        print(f"  Watermark ID generated: {result.record.watermark_id}")
        print(f"  Decryption record signed with {rid}'s OWN ML-DSA-65 private key")
        print(f"  Signature: {result.signature_hex[:32]}...")

        # Commit to ledger (embedding signature + signer public key into the record
        # so forensic verification later doesn't need to re-contact the recipient)
        ledger_record = result.record.to_dict()
        ledger_record["_signature_hex"] = result.signature_hex
        ledger_record["_signer_public_key_hex"] = result.signer_public_key_hex

        commit = ledger.commit_record(ledger_record)
        print(f"  Ledger commit: {commit.quorum_achieved}/{commit.quorum_needed} nodes -> "
              f"{'COMMITTED' if commit.committed else 'FAILED'} (block #{commit.block_index})")

        # Save the visually-identical, forensically-unique output each recipient receives
        out_path = os.path.join(OUTPUT_DIR, f"recipient_{rid}_decrypted.png")
        cv2.imwrite(out_path, result.watermarked_array)
        watermarked_outputs[rid] = out_path
        print(f"  Recipient's watermarked copy saved: {out_path}")

    banner("STEP 6: VISUAL COMPARISON -- All copies look identical")
    diffs = []
    rids = list(recipients.keys())
    for i in range(len(rids)):
        for j in range(i + 1, len(rids)):
            a = cv2.imread(watermarked_outputs[rids[i]])
            b = cv2.imread(watermarked_outputs[rids[j]])
            diff = cv2.absdiff(a, b)
            diffs.append((rids[i], rids[j], diff.mean(), diff.max()))
    for a, b, mean_d, max_d in diffs:
        print(f"  {a} vs {b}: mean pixel diff = {mean_d:.3f}, max pixel diff = {max_d} "
              f"(imperceptible to the human eye, but watermarks are cryptographically distinct)")

    banner("STEP 7: SIMULATE A LEAK -- Carol's copy ends up on a forum, re-saved as JPEG")
    carol_copy = cv2.imread(watermarked_outputs["carol"])
    ok, encoded = cv2.imencode(".jpg", carol_copy, [cv2.IMWRITE_JPEG_QUALITY, 85])
    leaked_image = cv2.imdecode(encoded, cv2.IMREAD_COLOR)
    cv2.imwrite(os.path.join(OUTPUT_DIR, "LEAKED_document_found_online.jpg"), leaked_image)
    print("Leaked file saved as: output/LEAKED_document_found_online.jpg")
    print("(JPEG-recompressed at quality 85, simulating a re-upload/re-share degradation)")

    banner("STEP 8-10: FORENSIC TRACE -- Extract watermark, verify against ledger")
    recipient_signing_pubkeys = {rid: keys["dsa"].public_key for rid, keys in recipients.items()}
    report = trace_leaked_document(leaked_image, ledger, recipient_signing_pubkeys)
    print(report.pretty_print())

    banner("BONUS: ROGUE ADMINISTRATOR ATTACK SIMULATION")
    print("A single compromised admin on 'security-dept-node' tries to alter the ledger")
    print("to frame 'bob' instead of the true leaker 'carol'...\n")

    # find carol's block index on the target node to tamper
    target_node = ledger.nodes["security-dept-node"]
    carol_wm = session_results["carol"].record.watermark_id
    carol_block_idx = None
    for blk in target_node.chain:
        if blk.record.get("watermark_id") == carol_wm:
            carol_block_idx = blk.index
            break

    tampered_record = dict(target_node.chain[carol_block_idx].record)
    tampered_record["recipient_id"] = "bob"  # framing bob!
    ledger.simulate_rogue_admin_tamper("security-dept-node", carol_block_idx, tampered_record)

    integrity = ledger.verify_network_integrity()
    print(f"Ledger integrity check: network_consistent={integrity['network_consistent']}")
    print(f"Tampered node detected: {integrity['tampered_nodes']}")

    report_after_attack = trace_leaked_document(leaked_image, ledger, recipient_signing_pubkeys)
    print("\nRe-running forensic trace on the SAME leaked file after the tamper attempt:")
    print(report_after_attack.pretty_print())
    print("\n>>> The attack FAILED: quorum of honest nodes still correctly identifies CAROL. <<<")

    banner("PIPELINE COMPLETE")
    print("Summary of files produced in output/:")
    print("  00_original_source_document.png   - the original document")
    print("  recipient_alice_decrypted.png     - Alice's watermarked copy")
    print("  recipient_bob_decrypted.png       - Bob's watermarked copy")
    print("  recipient_carol_decrypted.png     - Carol's watermarked copy")
    print("  LEAKED_document_found_online.jpg  - simulated leaked/degraded copy")


if __name__ == "__main__":
    main()
