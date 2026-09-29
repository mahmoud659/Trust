# TrustCap Prototype

Evidence capture and verification prototype using ECDSA digital signatures and SHA-256 image hashing.

---

## Architecture

```
┌─────────────────────────┐         POST /verify         ┌──────────────────────────┐
│      Streamlit          │ ────────────────────────────► │      FastAPI             │
│  app.py (port 8501)     │                               │  api.py  (port 8000)     │
│                         │ ◄──── JSON verification ───── │                          │
│  • Camera capture       │        result                 │  • Manifest validation   │
│  • SHA-256 hash         │                               │  • SHA-256 recalculation │
│  • Manifest creation    │                               │  • Hash comparison       │
│  • Demo signing         │                               │  • Signature verification│
│  • Evidence Inspector   │                               │  • Final VERIFIED flag   │
│  • Tampering Lab        │                               │                          │
└─────────────────────────┘                               └──────────────────────────┘
```

> **Prototype note:**
> Signing is simulated by the Streamlit application.
> In production, the Private Key must be protected on the client device
> and must never be sent to the verification service.

---

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Start the FastAPI backend (Terminal 1)

```bash
cd C:\Users\A store\Desktop\trustcap_lab
uvicorn api:app --reload --port 8000
```

API docs available at: http://localhost:8000/docs

### 3. Start the Streamlit app (Terminal 2)

```bash
cd C:\Users\A store\Desktop\trustcap_lab
streamlit run app.py
```

App available at: http://localhost:8501

---

## Modes

### Mode 1 — Capture Evidence

Simulates the customer claim flow:
1. Enter Claim ID and Capture ID
2. Take a photo with the camera
3. SHA-256 is generated from the exact image bytes
4. Manifest is created and canonicalized
5. Manifest is signed with the demo private key
6. Download the Evidence Package (ZIP)

**Evidence Package contains:**
```
image.jpg
manifest.json
signature.txt
public_key.pem
```
> The private key is NOT included in the package.

---

### Mode 2 — Evidence Inspector + Tampering Lab

Upload evidence components and send to FastAPI for independent verification.

**Verification result shows:**
- Manifest Validation ✅/❌
- Image Hash ✅/❌
- Digital Signature ✅/❌
- Final VERIFIED / FAILED

#### Tampering Lab Scenarios

| Tab | What changes | Expected result |
|-----|-------------|----------------|
| Tamper Image | Modified image uploaded, manifest unchanged | `hash_valid=false`, `verified=false` |
| Tamper Manifest | Manifest field edited (e.g. claim_id), signature unchanged | `signature_valid=false`, `verified=false` |
| Advanced Tampering Test | Modified image + new hash injected into manifest, original signature kept | `hash_valid=true`, `signature_valid=false`, `verified=false` |

The Advanced Tampering Test demonstrates why **SHA-256 alone is not sufficient** — the digital signature is the true tamper-proof seal.

---

## File Structure

```
trustcap_lab/
├── api.py              ← FastAPI verification backend
├── app.py              ← Streamlit two-mode UI
├── demo_keys.py        ← Demo key pair management
├── hash.py             ← Original CLI test script
├── requirements.txt
├── README.md
├── keys/               ← Auto-generated on first run (gitignore!)
│   ├── private_key.pem
│   └── public_key.pem
└── services/
    ├── hash_service.py
    ├── manifest_service.py
    └── signature_service.py
```

> **Security note:** Add `keys/private_key.pem` to `.gitignore` before committing.
