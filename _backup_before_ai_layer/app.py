"""
app.py
------
TrustCap Streamlit Prototype — Evidence Capture & Inspection / Tampering Lab.

Streamlit responsibilities (UI only):
  - Camera capture
  - SHA-256 generation from raw image bytes
  - Manifest creation and canonicalization
  - Demo signing (simulates client-side signing in prototype)
  - Evidence package download
  - Evidence upload and inspection UI
  - Calling FastAPI for all verification decisions

Streamlit does NOT make its own final verification decision.
All results displayed come from the FastAPI response.

PROTOTYPE NOTE:
  Signing is simulated by the Streamlit application.
  In production, the Private Key must be protected on the client device
  and must never be sent to the verification service.
"""

import base64
import hashlib
import io
import json
import uuid
import zipfile
from datetime import datetime, timezone

import requests
import streamlit as st
from cryptography.hazmat.primitives.asymmetric import ec

from demo_keys import KEY_ID, get_or_create_keys
from services.manifest_service import ManifestService
from services.signature_service import SignatureService

# ── Config ───────────────────────────────────────────────────────────────────
FASTAPI_URL = "http://localhost:8000/verify"
PAGE_CAPTURE = "Capture Evidence"
PAGE_INSPECTOR = "Evidence Inspector"


# ── Page setup ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="TrustCap Prototype",
    page_icon="🔒",
    layout="wide",
)


# ── Load demo keys (cached across reruns) ────────────────────────────────────
@st.cache_resource
def load_demo_keys():
    return get_or_create_keys()


private_key, public_key_obj, public_key_pem = load_demo_keys()


# ── Sidebar navigation ───────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🔒 TRUSTCAP Prototype")
    st.markdown("---")
    page = st.radio(
        "Navigation",
        [PAGE_CAPTURE, PAGE_INSPECTOR],
        label_visibility="collapsed",
    )
    st.markdown("---")
    st.caption(
        "**Prototype note:**  \n"
        "Signing is simulated by the Streamlit application.  \n"
        "In production, the Private Key must be protected on the client device "
        "and must never be sent to the verification service."
    )


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_manifest(claim_id: str, capture_id: str, image_hash: str) -> dict:
    return {
        "claim_id": claim_id,
        "capture_id": capture_id,
        "image_hash": image_hash,
        "key_id": KEY_ID,
        "captured_at": datetime.now(timezone.utc).isoformat(),
    }


def sign_manifest(manifest: dict) -> str:
    canonical = ManifestService.canonicalize(manifest)
    return SignatureService.sign(canonical, private_key)


def build_evidence_zip(
    image_bytes: bytes,
    manifest: dict,
    signature: str,
    pub_key_pem: str,
) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("image.jpg", image_bytes)
        zf.writestr("manifest.json", json.dumps(manifest, indent=2))
        zf.writestr("signature.txt", signature)
        zf.writestr("public_key.pem", pub_key_pem)
        # Private key intentionally NOT included
    return buf.getvalue()


def call_verify_api(
    image_bytes: bytes,
    manifest_str: str,
    signature: str,
    pub_key_pem: str,
) -> dict | None:
    try:
        resp = requests.post(
            FASTAPI_URL,
            files={"image": ("image.jpg", image_bytes, "image/jpeg")},
            data={
                "manifest": manifest_str,
                "signature": signature,
                "public_key": pub_key_pem,
            },
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.ConnectionError:
        st.error(
            "❌ Cannot connect to FastAPI backend at `http://localhost:8000`.  \n"
            "Please start it with: `uvicorn api:app --reload --port 8000`"
        )
        return None
    except Exception as e:
        st.error(f"❌ API error: {e}")
        return None


def display_verification_results(result: dict):
    """Render the verification result cards + detail expanders."""
    m_ok = result.get("manifest_valid", False)
    h_ok = result.get("hash_valid", False)
    s_ok = result.get("signature_valid", False)
    verified = result.get("verified", False)

    st.markdown("### Verification Results")

    col1, col2, col3 = st.columns(3)
    with col1:
        icon = "✅" if m_ok else "❌"
        label = "VALID" if m_ok else "INVALID"
        st.metric("Manifest Validation", f"{icon} {label}")
    with col2:
        icon = "✅" if h_ok else "❌"
        label = "MATCH" if h_ok else "MISMATCH"
        st.metric("Image Hash", f"{icon} {label}")
    with col3:
        icon = "✅" if s_ok else "❌"
        label = "VALID" if s_ok else "INVALID"
        st.metric("Digital Signature", f"{icon} {label}")

    st.markdown("---")

    if verified:
        st.success("## ✅ FINAL — VERIFIED")
    else:
        st.error("## ❌ FINAL — VERIFICATION FAILED")

    # Detail expanders
    with st.expander("🔍 Hash Details"):
        col_a, col_b = st.columns(2)
        with col_a:
            st.markdown("**Server Calculated Hash**")
            st.code(result.get("server_calculated_hash", "—"), language=None)
        with col_b:
            st.markdown("**Manifest `image_hash`**")
            st.code(result.get("manifest_image_hash", "—"), language=None)

    with st.expander("📋 Manifest Fields"):
        col_a, col_b, col_c = st.columns(3)
        with col_a:
            st.markdown("**Claim ID**")
            st.code(result.get("claim_id", "—"), language=None)
        with col_b:
            st.markdown("**Capture ID**")
            st.code(result.get("capture_id", "—"), language=None)
        with col_c:
            st.markdown("**Key ID**")
            st.code(result.get("key_id", "—"), language=None)

    errors = result.get("errors", [])
    if errors:
        with st.expander("⚠️ Verification Errors", expanded=True):
            for err in errors:
                st.warning(err)


# ─────────────────────────────────────────────────────────────────────────────
# MODE 1 — Capture Evidence
# ─────────────────────────────────────────────────────────────────────────────

if page == PAGE_CAPTURE:
    st.title("📸 Capture Evidence")
    st.markdown(
        "Simulate the customer claim flow. "
        "Capture a photo, generate a cryptographic evidence package, and verify it."
    )
    st.markdown("---")

    col_left, col_right = st.columns([1, 1])

    with col_left:
        st.markdown("### Evidence Metadata")
        claim_id = st.text_input(
            "Claim ID",
            value="CLM-001",
            placeholder="e.g. CLM-001",
        )
        capture_id = st.text_input(
            "Capture ID",
            value=f"CAP-{uuid.uuid4().hex[:8].upper()}",
            placeholder="Auto-generated",
        )

    st.markdown("---")
    st.markdown("### 📷 Camera Capture")
    camera_img = st.camera_input("Take a photo of the evidence")

    if camera_img is not None:
        image_bytes = camera_img.getvalue()

        st.markdown("---")
        st.markdown("### Generated Evidence")

        col_img, col_details = st.columns([1, 1])

        with col_img:
            st.markdown("**Captured Image**")
            st.image(image_bytes, use_container_width=True)

        with col_details:
            # SHA-256
            img_hash = sha256_bytes(image_bytes)
            st.markdown("**Image SHA-256**")
            st.code(img_hash, language=None)

            # Build manifest
            manifest = build_manifest(claim_id, capture_id, img_hash)
            st.markdown("**Manifest JSON**")
            st.json(manifest)

            # Sign
            signature = sign_manifest(manifest)
            st.markdown("**ECDSA Signature** (Base64)")
            st.code(signature, language=None)

            st.markdown("**Key ID**")
            st.code(KEY_ID, language=None)

        st.markdown("---")
        col_btn1, col_btn2 = st.columns(2)

        with col_btn1:
            if st.button("🔍 Verify Evidence", use_container_width=True):
                with st.spinner("Sending to FastAPI for verification…"):
                    result = call_verify_api(
                        image_bytes=image_bytes,
                        manifest_str=json.dumps(manifest),
                        signature=signature,
                        pub_key_pem=public_key_pem,
                    )
                if result:
                    display_verification_results(result)

        with col_btn2:
            zip_bytes = build_evidence_zip(
                image_bytes=image_bytes,
                manifest=manifest,
                signature=signature,
                pub_key_pem=public_key_pem,
            )
            st.download_button(
                label="📦 Download Evidence Package",
                data=zip_bytes,
                file_name=f"evidence_{claim_id}_{capture_id}.zip",
                mime="application/zip",
                use_container_width=True,
            )
            st.caption("Package contains: image.jpg, manifest.json, signature.txt, public_key.pem")

    else:
        st.info("👆 Use the camera above to capture evidence.")


# ─────────────────────────────────────────────────────────────────────────────
# MODE 2 — Evidence Inspector + Tampering Lab
# ─────────────────────────────────────────────────────────────────────────────

elif page == PAGE_INSPECTOR:
    st.title("🔬 Evidence Inspector")
    st.markdown(
        "Upload evidence components and send them to the FastAPI backend for independent verification.  \n"
        "Use the **Tampering Lab** below to test what happens when evidence is modified."
    )
    st.markdown("---")

    # ── Upload section ────────────────────────────────────────────────────────
    st.markdown("### Upload Evidence Components")

    col_up1, col_up2 = st.columns(2)

    with col_up1:
        uploaded_image = st.file_uploader(
            "📁 Upload Image",
            type=["jpg", "jpeg", "png", "webp"],
            key="inspector_image",
        )
        if uploaded_image:
            st.image(uploaded_image.getvalue(), caption="Uploaded Image", use_container_width=True)

        uploaded_pub_key = st.file_uploader(
            "🔑 Upload Public Key (PEM)",
            type=["pem", "txt"],
            key="inspector_pubkey",
        )
        inspector_pub_key_text = ""
        if uploaded_pub_key:
            inspector_pub_key_text = uploaded_pub_key.read().decode("utf-8")
            st.text_area("Public Key Preview", inspector_pub_key_text, height=120, disabled=True)
        else:
            inspector_pub_key_text = st.text_area(
                "Or paste Public Key (PEM)",
                placeholder="-----BEGIN PUBLIC KEY-----\n...",
                height=120,
                key="inspector_pubkey_paste",
            )

    with col_up2:
        uploaded_manifest = st.file_uploader(
            "📄 Upload Manifest JSON",
            type=["json", "txt"],
            key="inspector_manifest",
        )
        inspector_manifest_text = ""
        if uploaded_manifest:
            inspector_manifest_text = uploaded_manifest.read().decode("utf-8")

        inspector_manifest_text = st.text_area(
            "Manifest JSON (editable)",
            value=inspector_manifest_text,
            height=200,
            key="inspector_manifest_area",
            placeholder='{"claim_id": "CLM-001", "capture_id": "CAP-...", "image_hash": "..."}',
        )

        inspector_signature = st.text_area(
            "Signature (Base64)",
            height=100,
            key="inspector_signature",
            placeholder="Base64-encoded ECDSA signature…",
        )

    st.markdown("---")

    # ── Inspect button ────────────────────────────────────────────────────────
    if st.button("🔍 Inspect Evidence", type="primary", use_container_width=True):
        # Validation
        missing = []
        if not uploaded_image:
            missing.append("Image")
        if not inspector_manifest_text.strip():
            missing.append("Manifest JSON")
        if not inspector_signature.strip():
            missing.append("Signature")
        if not inspector_pub_key_text.strip():
            missing.append("Public Key")

        if missing:
            st.error(f"Please provide: {', '.join(missing)}")
        else:
            img_bytes = uploaded_image.getvalue()
            with st.spinner("Sending to FastAPI for verification…"):
                result = call_verify_api(
                    image_bytes=img_bytes,
                    manifest_str=inspector_manifest_text,
                    signature=inspector_signature.strip(),
                    pub_key_pem=inspector_pub_key_text.strip(),
                )
            if result:
                display_verification_results(result)

    # ─────────────────────────────────────────────────────────────────────────
    # TAMPERING LAB
    # ─────────────────────────────────────────────────────────────────────────
    st.markdown("---")
    st.markdown("## 🧪 Tampering Lab")
    st.markdown(
        "_Developer tool for prototype demonstration and education. "
        "Test what cryptographic verification catches._"
    )

    tab_img, tab_manifest, tab_advanced = st.tabs([
        "🖼️ Tamper Image",
        "📝 Tamper Manifest",
        "⚡ Advanced Tampering Test",
    ])

    # ── Tab 1: Tamper Image ───────────────────────────────────────────────────
    with tab_img:
        st.markdown("### 🖼️ Tamper Image")
        st.markdown(
            "Upload a **modified version** of the original image.  \n"
            "The Manifest and Signature are **not updated** — only the image changes."
        )
        st.info(
            "**Expected result:**  \n"
            "`hash_valid = false` — the server will recalculate a different SHA-256  \n"
            "`verified = false` — final verification fails"
        )

        tampered_image = st.file_uploader(
            "Upload modified image",
            type=["jpg", "jpeg", "png", "webp"],
            key="tamper_image_file",
        )
        if tampered_image:
            st.image(tampered_image.getvalue(), caption="Modified Image", use_container_width=True)

        if st.button("🔍 Inspect with Tampered Image", key="btn_tamper_image"):
            missing = []
            if not tampered_image:
                missing.append("Tampered Image")
            if not inspector_manifest_text.strip():
                missing.append("Manifest JSON (upload above in Evidence Components)")
            if not inspector_signature.strip():
                missing.append("Signature (enter above in Evidence Components)")
            if not inspector_pub_key_text.strip():
                missing.append("Public Key (upload above in Evidence Components)")

            if missing:
                st.error(f"Please provide: {', '.join(missing)}")
            else:
                with st.spinner("Sending tampered evidence to FastAPI…"):
                    result = call_verify_api(
                        image_bytes=tampered_image.getvalue(),
                        manifest_str=inspector_manifest_text,
                        signature=inspector_signature.strip(),
                        pub_key_pem=inspector_pub_key_text.strip(),
                    )
                if result:
                    display_verification_results(result)

    # ── Tab 2: Tamper Manifest ────────────────────────────────────────────────
    with tab_manifest:
        st.markdown("### 📝 Tamper Manifest")
        st.markdown(
            "Edit the Manifest JSON below.  \n"
            "The original Signature and Image remain unchanged."
        )
        st.info(
            "**Expected result:**  \n"
            "`signature_valid = false` — the signed canonical manifest no longer matches  \n"
            "`verified = false` — final verification fails"
        )

        # Pre-populate from the uploaded manifest above
        tampered_manifest_text = st.text_area(
            "Edit Manifest JSON",
            value=inspector_manifest_text,
            height=250,
            key="tamper_manifest_area",
            help='Try changing "claim_id": "CLM-001" to "claim_id": "CLM-999"',
        )

        st.caption('💡 Example: change `"claim_id": "CLM-001"` → `"claim_id": "CLM-999"`')

        if st.button("🔍 Inspect with Tampered Manifest", key="btn_tamper_manifest"):
            missing = []
            if not uploaded_image:
                missing.append("Image (upload above in Evidence Components)")
            if not tampered_manifest_text.strip():
                missing.append("Tampered Manifest JSON")
            if not inspector_signature.strip():
                missing.append("Signature (enter above in Evidence Components)")
            if not inspector_pub_key_text.strip():
                missing.append("Public Key (upload above in Evidence Components)")

            if missing:
                st.error(f"Please provide: {', '.join(missing)}")
            else:
                with st.spinner("Sending tampered manifest to FastAPI…"):
                    result = call_verify_api(
                        image_bytes=uploaded_image.getvalue(),
                        manifest_str=tampered_manifest_text,
                        signature=inspector_signature.strip(),
                        pub_key_pem=inspector_pub_key_text.strip(),
                    )
                if result:
                    display_verification_results(result)

    # ── Tab 3: Advanced Tampering Test ────────────────────────────────────────
    with tab_advanced:
        st.markdown("### ⚡ Advanced Tampering Test")
        st.markdown(
            "This test demonstrates **why SHA-256 alone is not sufficient** for evidence integrity."
        )

        st.warning(
            "**Scenario:**  \n"
            "1. Upload a modified image  \n"
            "2. The new SHA-256 is automatically recalculated and injected into the Manifest  \n"
            "3. The **original Signature** is kept unchanged  \n\n"
            "The image and manifest will match each other (hash_valid = true),  \n"
            "but the digital signature will FAIL because the signed manifest was modified."
        )

        adv_image = st.file_uploader(
            "Upload modified image (for advanced test)",
            type=["jpg", "jpeg", "png", "webp"],
            key="adv_tamper_image",
        )

        adv_manifest_preview = ""
        adv_new_hash = ""

        if adv_image:
            # Auto-recalculate hash
            adv_new_hash = sha256_bytes(adv_image.getvalue())
            st.markdown("**Auto-calculated new SHA-256:**")
            st.code(adv_new_hash, language=None)

            if inspector_manifest_text.strip():
                try:
                    adv_manifest_dict = json.loads(inspector_manifest_text)
                    old_hash = adv_manifest_dict.get("image_hash", "")
                    adv_manifest_dict["image_hash"] = adv_new_hash
                    adv_manifest_preview = json.dumps(adv_manifest_dict, indent=2)

                    st.markdown("**Modified Manifest** _(image_hash replaced)_:")
                    st.json(adv_manifest_dict)

                    col_a, col_b = st.columns(2)
                    with col_a:
                        st.markdown("**Old `image_hash`:**")
                        st.code(old_hash[:32] + "…" if old_hash else "—", language=None)
                    with col_b:
                        st.markdown("**New `image_hash`:**")
                        st.code(adv_new_hash[:32] + "…", language=None)

                except json.JSONDecodeError:
                    st.error("Original manifest JSON is invalid — upload a valid manifest above first.")
            else:
                st.info("Upload the original Manifest JSON in the Evidence Components section above.")

        if st.button("🔍 Inspect with Advanced Tampering", key="btn_adv_tamper"):
            missing = []
            if not adv_image:
                missing.append("Modified Image (in this tab)")
            if not adv_manifest_preview:
                missing.append("Original Manifest (upload in Evidence Components above)")
            if not inspector_signature.strip():
                missing.append("Original Signature (enter in Evidence Components above)")
            if not inspector_pub_key_text.strip():
                missing.append("Public Key (upload in Evidence Components above)")

            if missing:
                st.error(f"Please provide: {', '.join(missing)}")
            else:
                with st.spinner("Sending advanced tampered evidence to FastAPI…"):
                    result = call_verify_api(
                        image_bytes=adv_image.getvalue(),
                        manifest_str=adv_manifest_preview,
                        signature=inspector_signature.strip(),
                        pub_key_pem=inspector_pub_key_text.strip(),
                    )
                if result:
                    display_verification_results(result)

                    # Educational callout
                    h_ok = result.get("hash_valid", False)
                    s_ok = result.get("signature_valid", False)

                    if h_ok and not s_ok:
                        st.markdown("---")
                        st.info(
                            "### 💡 Key Insight\n\n"
                            "The **image and manifest now match** (hash_valid = ✅).  \n"
                            "An attacker successfully updated the manifest to reflect the new image.  \n\n"
                            "But the **digital signature proves** that the manifest was modified after signing.  \n"
                            "The original signed manifest is gone — you cannot forge a valid signature without the private key.  \n\n"
                            "**This is why SHA-256 alone is not sufficient.  \n"
                            "The digital signature is the true tamper-proof seal.**"
                        )
                    elif not h_ok and not s_ok:
                        st.markdown("---")
                        st.warning(
                            "Both hash and signature failed. "
                            "Make sure you uploaded the modified image and the original manifest above."
                        )
