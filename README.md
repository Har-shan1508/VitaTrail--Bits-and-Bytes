# VitaTrail - Universal Health Record & Safety Vault

VitaTrail is an integrated medical record management and patient safety platform. It enables seamless record collection across hospitals, cryptographic proof of authenticity, proactive drug-interaction detection, and time-limited access links for medical professionals.

## Core Capabilities

* **Patient Safety & Redundancy Detection:** Automatically scans cross-provider health records for duplicate lab tests (within 30 days), drug-drug interactions (e.g., NSAIDs + Blood Thinners), and allergy conflicts.
* **Cryptographic Authenticity & Privacy:**
  * **AES-256-GCM Envelope Encryption:** Medical records are encrypted at rest using per-patient data keys.
  * **Ed25519 Digital Signatures:** Every record issued by a medical provider is signed to guarantee origin and prevent database tampering.
* **Granular Privacy Tiers:**
  * **Tier 1 (Routine):** Prescriptions, vitals, routine lab tests.
  * **Tier 2 (Specialist):** Imaging, surgical notes.
  * **Tier 3 (Restricted):** Mental health, reproductive health (requires a 6-digit PIN to unlock).
* **Scoped Link Sharing:** Patients can issue time-limited access links to doctors with customizable expiration times and specialty filters.
* **Adherence & Medicine Reminders:** Daily dose tracking grid with automated adherence percentage and streak tracking.

---

## Setup & Running Instructions

### 1. Prerequisites
Ensure Python 3.8+ is installed on your system.

### 2. Environment Setup
Clone or navigate to the project directory and install the required dependencies:

```bash
pip install flask werkzeug cryptography PyJWT