# Problem Statement 26237 (verbatim)

**Title:** Cryptographic Attribution and Immutable Decryption Provenance for Multi-Recipient Encrypted Document Distribution
**Organization:** Ministry of Defence — **Department:** Indian Navy (WESEE)
**Category:** Software — **Theme:** Blockchain & Cybersecurity

## Description

Sensitive documents are often distributed under a broadcast-encrypt, individually-decrypt model, where a sender encrypts a file once and each recipient decrypts it independently using their own credentials.

When such a file is shared with a single recipient, a leak is trivially attributable. However, when the same file is distributed to a group of recipients, every recipient who was capable of decrypting it becomes an equally plausible suspect if the file leaks, since the decrypted content is identical for all of them and carries no trace of which specific decryption produced the leaked copy.

Existing safeguards such as server-side access logs and static watermarks applied before distribution do not solve this. Access logs can be altered by a privileged administrator, and a watermark that is identical across all recipients reproduces the same attribution problem it is meant to solve.

## Expected Outcome

Teams are expected to build a system that generates a unique, invisible forensic watermark at the moment of decryption, specific to each recipient's session, so that every decrypted copy is visually identical but forensically distinct.

Each decryption event must be cryptographically bound to the recipient's identity using a digital signature generated with the recipient's own private key, so that the recipient cannot later deny having decrypted the file.

This signed decryption record must be committed to an immutable, tamper-evident ledger, so that no single administrator or compromised account can retroactively alter or erase the record of who decrypted what and when.

Given a leaked copy of a distributed document, the solution should be able to extract the embedded watermark, look it up against the ledger, and return a cryptographically verifiable record identifying the exact recipient responsible.

## Key Requirements

1. Generate a unique, invisible forensic watermark at the moment of decryption.
2. Make the watermark specific to each recipient and decryption session.
3. Ensure every decrypted copy is visually identical while remaining forensically distinct.
4. Cryptographically bind each decryption event to the recipient's identity.
5. Use the recipient's own private key to generate a digital signature for the decryption record.
6. Use NIST-standardized post-quantum cryptographic algorithms instead of classical cryptographic algorithms for Key Exchange and Digital Signatures.
7. Implement the immutable audit layer using blockchain or Distributed Ledger Technology (DLT).
8. Ensure that no single administrator or compromised account can retroactively modify or delete audit records.
9. Extract the forensic watermark from a leaked document.
10. Look up the extracted watermark against the immutable ledger.
11. Return a cryptographically verifiable record identifying the recipient associated with the decryption event.
12. Support complete operation within an offline and air-gapped environment.
13. Have no dependency on external cloud KMS services.
14. Have no dependency on public blockchain networks.

## End-to-End Workflow

1. The sender encrypts the document and distributes it to authorized recipients.
2. An authorized recipient decrypts the document using their credentials.
3. The system generates a unique invisible forensic watermark tied to the recipient's decryption session.
4. The recipient signs the decryption record using their post-quantum private signing key.
5. The signed decryption record is committed to an offline, tamper-evident blockchain/DLT ledger.
6. The recipient receives a visually identical but uniquely fingerprinted decrypted document.
7. If the document is leaked, the forensic watermark is extracted from the leaked copy.
8. The extracted watermark is matched against the immutable ledger.
9. The associated post-quantum digital signature and ledger evidence are cryptographically verified.
10. The system produces a verifiable record identifying the recipient and corresponding decryption event.

## Deployment Constraint

The complete system must run fully within an offline and air-gapped environment. All cryptographic operations, identity management, watermark generation, ledger operations, and forensic verification must function without external cloud services, cloud KMS infrastructure, or public blockchain networks.
