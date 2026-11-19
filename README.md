# KuantumCryptography_VDR_PQC_Protocol

Post-quantum cryptography (PQC) session, signing, and integrity verification prototype using synthetic **VDR (Vitamin D Receptor)** research profiles within a zero-trust architectural framing.

## Scope & Disclaimer
- **Purpose:** Research, data privacy, and cyber-architecture verification prototype.
- **Non-Clinical Notice:** This project does **not** provide clinical evaluation, diagnosis, prognosis, or treatment recommendations, and is not intended for clinical decision-making.

## Repository Structure
- `profiles.py` — Synthetic `VDR` (`12q13.11`) research profiles and sender/receiver role definitions (`authority` and `compute_node`).
- `pqc_channel.py` — Conceptual PQC session key derivation (`ML-KEM` style), envelope signing (`ML-DSA` style), receiver validation, and tampering detection.
- `demo.py` — Runnable scenario demonstrating both a valid verified envelope and rejection of a modified payload.

## Running the Prototype
```bash
python demo.py
