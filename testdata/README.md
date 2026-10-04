# Third-party test data

`scans/` contains 6 scanned business forms from the **FUNSD** dataset
(Form Understanding in Noisy Scanned Documents), downloaded from
https://guillaumejaume.github.io/FUNSD/.

FUNSD is a subset of the RVL-CDIP dataset and is distributed **for
non-commercial, research purposes only**. It is included here only as
realistic input for watermark robustness measurement
(`demo/test_watermark_robustness.py`). It is not part of the system and
should be removed before any commercial or operational deployment.

`third_party/fabric-samples/` (repository root) is a shallow clone of
https://github.com/hyperledger/fabric-samples (Apache-2.0), kept as a
reference for the Fabric network layout. The network in `ledger/fabric/`
is written for this project and does not import it at run time.
