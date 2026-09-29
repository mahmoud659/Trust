"""
app.py
------
TrustCap Streamlit Prototype — Evidence Capture, Inspection, Tampering Lab
and AI-generation detection.

Runs standalone — no FastAPI server needed:
    streamlit run app.py

Responsibilities:
  - Login gate (email + password from .env)
  - Camera capture, SHA-256, manifest creation, demo signing
  - Evidence package download / upload
  - Verification via services/verification_service.py — the same code the
    optional api.py exposes over HTTP. This file only renders its results.

PROTOTYPE NOTE:
  Signing is simulated by the Streamlit application.
  In production, the Private Key must be protected on the client device
  and must never be sent to the verification service.
"""

import hashlib
import io
import json
import uuid
import zipfile
from datetime import datetime, timezone

import streamlit as st

from config import AIDetectionSettings, load_ai_detection_settings
from demo_keys import KEY_ID, get_or_create_keys
from services.ai_detection_service import AIDetectionService
from services.manifest_service import ManifestService
from services.signature_service import SignatureService
from services.verification_service import EvidenceInputError, detect_ai_standalone, verify_evidence
from ui import auth
from ui import components as ui
from ui.theme import inject_global_css

PAGE_CAPTURE = "Capture evidence"
PAGE_INSPECTOR = "Evidence inspector"
PAGE_AI = "AI detection"
IMAGE_TYPES = ["jpg", "jpeg", "png", "webp"]
MAX_ZIP_BYTES = 30 * 1024 * 1024


# ── Page setup ───────────────────────────────────────────────────────────────
st.set_page_config(page_title="TrustCap · Evidence Integrity Lab", page_icon="🛡️", layout="wide")
inject_global_css()

# Nothing below this line renders until the user has signed in.
signed_in_email = auth.require_login()


@st.cache_resource
def load_demo_keys():
    return get_or_create_keys()


@st.cache_resource
def load_ai_engine() -> tuple[AIDetectionSettings, AIDetectionService]:
    # One detector for the whole app, so its result cache is shared across sessions.
    settings = load_ai_detection_settings()
    return settings, AIDetectionService(settings)


private_key, public_key_obj, public_key_pem = load_demo_keys()
ai_settings, ai_detector = load_ai_engine()
thresholds = {"review_threshold": ai_settings.review_threshold, "reject_threshold": ai_settings.reject_threshold}


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


def build_evidence_zip(image_bytes: bytes, manifest: dict, signature: str, pub_key_pem: str) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
        zip_file.writestr("image.jpg", image_bytes)
        zip_file.writestr("manifest.json", json.dumps(manifest, indent=2))
        zip_file.writestr("signature.txt", signature)
        zip_file.writestr("public_key.pem", pub_key_pem)
        # Private key intentionally NOT included
    return buffer.getvalue()


def run_verification(result_key: str, image_bytes: bytes, manifest_json: str, signature: str,
                     public_key: str, run_ai_check: bool = True) -> None:
    """Run the verification service and store the result in session state (so it survives reruns)."""
    with st.spinner("Verifying evidence — integrity checks and AI analysis…"):
        try:
            st.session_state[result_key] = verify_evidence(
                image_bytes=image_bytes,
                manifest_json=manifest_json,
                signature_b64=signature,
                public_key_pem=public_key,
                detector=ai_detector,
                settings=ai_settings,
                run_ai_check=run_ai_check,
            )
            st.session_state.pop(f"{result_key}_error", None)
        except EvidenceInputError as error:
            st.session_state.pop(result_key, None)
            st.session_state[f"{result_key}_error"] = str(error)


def show_stored_result(result_key: str, thresholds: dict) -> None:
    error_message = st.session_state.get(f"{result_key}_error")
    if error_message:
        st.error(error_message)
    result = st.session_state.get(result_key)
    if result:
        ui.verification_result(result, thresholds)


def report_missing(missing: list[str]) -> bool:
    if missing:
        st.error("Please provide: " + ", ".join(missing))
        return True
    return False


# ── Sidebar ──────────────────────────────────────────────────────────────────
with st.sidebar:
    ui.sidebar_brand()
    ui.render_html('<div class="tc-side-label">Workspace</div>')
    page = st.radio(
        "Navigation",
        [PAGE_CAPTURE, PAGE_INSPECTOR, PAGE_AI],
        label_visibility="collapsed",
        key="nav_page",
    )
    st.markdown("---")
    ui.sidebar_status(ai_settings)
    st.markdown("---")
    ui.sidebar_user(signed_in_email)
    if st.button("Sign out", key="btn_logout", width="stretch"):
        auth.logout("You have been signed out.")
        st.rerun()
    st.markdown("---")
    ui.render_html(
        '<div class="tc-side-note"><b>Prototype note</b><br>Signing is simulated by the Streamlit application. '
        "In production, the private key must be protected on the client device and never sent to the "
        "verification service.</div>"
    )


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 1 — Capture Evidence
# ─────────────────────────────────────────────────────────────────────────────

def new_capture_id() -> None:
    st.session_state["capture_capture_id"] = f"CAP-{uuid.uuid4().hex[:8].upper()}"


def get_capture_evidence(image_bytes: bytes, claim_id: str, capture_id: str) -> dict:
    """
    Build + sign the manifest once per (image, claim, capture) combination.
    Without this, every Streamlit rerun would create a new timestamp and a new
    signature, so the downloaded package would differ from the verified one.
    """
    image_hash = sha256_bytes(image_bytes)
    cache_key = (image_hash, claim_id, capture_id)
    cached = st.session_state.get("capture_evidence")
    if cached and cached["cache_key"] == cache_key:
        return cached

    manifest = build_manifest(claim_id, capture_id, image_hash)
    evidence = {
        "cache_key": cache_key,
        "image_hash": image_hash,
        "manifest": manifest,
        "signature": sign_manifest(manifest),
    }
    st.session_state["capture_evidence"] = evidence
    st.session_state.pop("capture_result", None)
    st.session_state.pop("capture_result_error", None)
    return evidence


def render_capture_page() -> None:
    ui.page_header(
        "Customer claim flow",
        "Capture evidence",
        "Take a photo, seal it with a SHA-256 hash and an ECDSA signature, then send it for "
        "verification — including an AI-generation check.",
    )

    st.session_state.setdefault("capture_claim_id", "CLM-001")
    if "capture_capture_id" not in st.session_state:
        new_capture_id()

    column_meta, column_camera = st.columns([2, 3], gap="large")

    with column_meta:
        ui.section_title("1", "Evidence metadata")
        with st.container(border=True):
            claim_id = st.text_input("Claim ID", key="capture_claim_id", placeholder="e.g. CLM-001")
            id_column, button_column = st.columns([3, 1], vertical_alignment="bottom")
            with id_column:
                capture_id = st.text_input("Capture ID", key="capture_capture_id")
            with button_column:
                st.button("New", key="btn_new_capture_id", on_click=new_capture_id, width="stretch",
                          help="Generate a new capture ID")
        ui.section_title("", "How it works")
        ui.how_it_works([
            ("Capture", "the photo is taken inside the app."),
            ("Hash", "SHA-256 is computed from the exact image bytes."),
            ("Sign", "the canonical manifest is signed with ECDSA P-256."),
            ("Verify", "the hash and signature are re-checked, then Resemble AI detection runs."),
        ])

    with column_camera:
        ui.section_title("2", "Camera capture")
        with st.container(border=True):
            camera_image = st.camera_input("Take a photo of the evidence", label_visibility="collapsed")

    if camera_image is None:
        ui.empty_state("Use the camera above to capture evidence. The sealed package will appear here.")
        return

    if not claim_id.strip() or not capture_id.strip():
        st.error("Claim ID and Capture ID are required.")
        return

    image_bytes = camera_image.getvalue()
    evidence = get_capture_evidence(image_bytes, claim_id.strip(), capture_id.strip())
    manifest = evidence["manifest"]
    signature = evidence["signature"]

    ui.section_title("3", "Sealed evidence package", "Private key is never included")
    column_image, column_details = st.columns([2, 3], gap="large")

    with column_image:
        with st.container(border=True):
            st.image(image_bytes, caption="Captured image", width="stretch")

    with column_details:
        with st.container(border=True):
            ui.hash_block("Image SHA-256", evidence["image_hash"])
            tab_manifest, tab_signature, tab_key = st.tabs(["Manifest", "Signature", "Public key"])
            with tab_manifest:
                st.json(manifest)
            with tab_signature:
                ui.hash_block("ECDSA signature (Base64)", signature)
                ui.key_value_list([("Key ID", KEY_ID), ("Algorithm", "ECDSA P-256 / SHA-256")])
            with tab_key:
                st.code(public_key_pem, language=None)

    ui.section_title("4", "Verify or export")
    with st.container(border=True):
        run_ai_check = st.toggle("Run AI-generation check (Resemble AI)", value=True, key="capture_run_ai")
        column_verify, column_download = st.columns(2)
        with column_verify:
            if st.button("Verify evidence", type="primary", width="stretch", key="btn_capture_verify"):
                run_verification("capture_result", image_bytes, json.dumps(manifest), signature,
                                 public_key_pem, run_ai_check)
        with column_download:
            st.download_button(
                label="Download evidence package (.zip)",
                data=build_evidence_zip(image_bytes, manifest, signature, public_key_pem),
                file_name=f"evidence_{claim_id.strip()}_{capture_id.strip()}.zip",
                mime="application/zip",
                width="stretch",
            )
        st.caption("Package contains: image.jpg, manifest.json, signature.txt, public_key.pem")

    if "capture_result" in st.session_state or "capture_result_error" in st.session_state:
        ui.section_title("5", "Verification result")
        show_stored_result("capture_result", thresholds)


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 2 — Evidence Inspector + Tampering Lab
# ─────────────────────────────────────────────────────────────────────────────

def _decode_upload(state_key: str) -> str | None:
    uploaded = st.session_state.get(state_key)
    if uploaded is None:
        return None
    try:
        return uploaded.getvalue().decode("utf-8")
    except UnicodeDecodeError:
        st.session_state["inspector_load_error"] = f"{uploaded.name} is not a UTF-8 text file."
        return None


def on_manifest_file_change() -> None:
    text = _decode_upload("insp_manifest_file")
    if text is not None:
        st.session_state["insp_manifest_text"] = text
        st.session_state["tamper_manifest_text"] = text


def on_public_key_file_change() -> None:
    text = _decode_upload("insp_pubkey_file")
    if text is not None:
        st.session_state["insp_pubkey_text"] = text


def on_evidence_zip_change() -> None:
    """Fill all four evidence components from a package produced by the Capture page."""
    st.session_state.pop("inspector_load_error", None)
    uploaded = st.session_state.get("insp_zip")
    if uploaded is None:
        st.session_state.pop("insp_zip_image", None)
        return
    try:
        zip_bytes = uploaded.getvalue()
        if len(zip_bytes) > MAX_ZIP_BYTES:
            raise ValueError("Package is larger than 30 MB.")
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zip_file:
            names = set(zip_file.namelist())
            required = {"image.jpg", "manifest.json", "signature.txt", "public_key.pem"}
            missing = required - names
            if missing:
                raise ValueError(f"Package is missing: {', '.join(sorted(missing))}")
            manifest_text = zip_file.read("manifest.json").decode("utf-8")
            st.session_state["insp_zip_image"] = zip_file.read("image.jpg")
            st.session_state["insp_manifest_text"] = manifest_text
            st.session_state["tamper_manifest_text"] = manifest_text
            st.session_state["insp_signature_text"] = zip_file.read("signature.txt").decode("utf-8").strip()
            st.session_state["insp_pubkey_text"] = zip_file.read("public_key.pem").decode("utf-8")
    except (zipfile.BadZipFile, ValueError, UnicodeDecodeError) as error:
        st.session_state.pop("insp_zip_image", None)
        st.session_state["inspector_load_error"] = f"Could not load evidence package: {error}"


def reset_tampered_manifest() -> None:
    st.session_state["tamper_manifest_text"] = st.session_state.get("insp_manifest_text", "")


def render_inspector_page() -> None:
    for state_key in ("insp_manifest_text", "insp_signature_text", "insp_pubkey_text", "tamper_manifest_text"):
        st.session_state.setdefault(state_key, "")

    ui.page_header(
        "Independent verification",
        "Evidence inspector",
        "Load an evidence package and verify it. "
        "Then use the <b>Tampering Lab</b> to see exactly what each protection layer catches.",
    )

    ui.section_title("1", "Load evidence", "Quick load a .zip, or upload each part")
    with st.container(border=True):
        st.file_uploader("Evidence package (.zip from the Capture page)", type=["zip"], key="insp_zip",
                         on_change=on_evidence_zip_change)
        if st.session_state.get("inspector_load_error"):
            st.error(st.session_state["inspector_load_error"])

    column_left, column_right = st.columns(2, gap="large")
    with column_left:
        with st.container(border=True):
            uploaded_image = st.file_uploader("Image", type=IMAGE_TYPES, key="insp_image_file")
            zip_image = st.session_state.get("insp_zip_image")
            image_bytes = uploaded_image.getvalue() if uploaded_image else zip_image
            if image_bytes:
                source = "Uploaded image" if uploaded_image else "Image from evidence package"
                st.image(image_bytes, caption=source, width="stretch")

            st.file_uploader("Public key (PEM)", type=["pem", "txt"], key="insp_pubkey_file",
                             on_change=on_public_key_file_change)
            public_key_text = st.text_area("Public key (editable)", key="insp_pubkey_text", height=130,
                                           placeholder="-----BEGIN PUBLIC KEY-----\n...")

    with column_right:
        with st.container(border=True):
            st.file_uploader("Manifest JSON", type=["json", "txt"], key="insp_manifest_file",
                             on_change=on_manifest_file_change)
            manifest_text = st.text_area("Manifest JSON (editable)", key="insp_manifest_text", height=220,
                                         placeholder='{"claim_id": "CLM-001", "capture_id": "CAP-...", "image_hash": "..."}')
            signature_text = st.text_area("Signature (Base64)", key="insp_signature_text", height=110,
                                          placeholder="Base64-encoded ECDSA signature…")

    ui.section_title("2", "Verify")
    with st.container(border=True):
        run_ai_check = st.toggle("Run AI-generation check (Resemble AI)", value=True, key="insp_run_ai")
        if st.button("Inspect evidence", type="primary", width="stretch", key="btn_inspect"):
            missing = [name for name, value in (
                ("Image", image_bytes), ("Manifest JSON", manifest_text.strip()),
                ("Signature", signature_text.strip()), ("Public key", public_key_text.strip()),
            ) if not value]
            if not report_missing(missing):
                run_verification("insp_result", image_bytes, manifest_text, signature_text, public_key_text, run_ai_check)
    show_stored_result("insp_result", thresholds)

    render_tampering_lab(image_bytes, manifest_text, signature_text, public_key_text)


def render_tampering_lab(original_image: bytes | None, manifest_text: str, signature_text: str,
                         public_key_text: str) -> None:
    ui.section_title("3", "Tampering Lab", "Developer tool for demonstration and education")
    ui.callout(
        "info", "Uses the evidence loaded above",
        "<div>Each scenario changes one part of the evidence and keeps the rest from step 1. "
        "Integrity failures skip the AI check automatically — the package is rejected anyway.</div>",
    )
    st.write("")

    tab_image, tab_manifest, tab_advanced = st.tabs(["Tamper image", "Tamper manifest", "Advanced tampering"])

    # ── Tab 1: Tamper Image ───────────────────────────────────────────────────
    with tab_image:
        column_info, column_action = st.columns([2, 3], gap="large")
        with column_info:
            ui.callout(
                "warn", "Scenario",
                "<div>Upload a <b>modified version</b> of the original image. The manifest and signature are "
                "<b>not updated</b>.</div><div style='margin-top:.5rem'>Expected: <code>hash_valid = false</code>, "
                "<code>verified = false</code>, verdict <b>REJECTED</b>.</div>",
            )
        with column_action:
            tampered_image = st.file_uploader("Modified image", type=IMAGE_TYPES, key="tamper_image_file")
            if tampered_image:
                st.image(tampered_image.getvalue(), caption="Modified image", width=320)
            if st.button("Inspect with tampered image", key="btn_tamper_image", width="stretch"):
                missing = [name for name, value in (
                    ("Modified image", tampered_image), ("Manifest JSON (step 1)", manifest_text.strip()),
                    ("Signature (step 1)", signature_text.strip()), ("Public key (step 1)", public_key_text.strip()),
                ) if not value]
                if not report_missing(missing):
                    run_verification("tamper_image_result", tampered_image.getvalue(), manifest_text,
                                     signature_text, public_key_text)
        show_stored_result("tamper_image_result", thresholds)

    # ── Tab 2: Tamper Manifest ────────────────────────────────────────────────
    with tab_manifest:
        column_info, column_action = st.columns([2, 3], gap="large")
        with column_info:
            ui.callout(
                "warn", "Scenario",
                "<div>Edit any manifest field. The original image and signature stay unchanged.</div>"
                "<div style='margin-top:.5rem'>Try <code>\"claim_id\": \"CLM-001\"</code> → "
                "<code>\"claim_id\": \"CLM-999\"</code>.</div><div style='margin-top:.5rem'>Expected: "
                "<code>signature_valid = false</code>, <code>verified = false</code>, verdict <b>REJECTED</b>.</div>",
            )
        with column_action:
            tampered_manifest_text = st.text_area("Edit manifest JSON", key="tamper_manifest_text", height=230)
            column_reset, column_run = st.columns([1, 2])
            with column_reset:
                st.button("Reset to original", key="btn_reset_manifest", on_click=reset_tampered_manifest,
                          width="stretch")
            with column_run:
                run_clicked = st.button("Inspect with tampered manifest", key="btn_tamper_manifest", width="stretch")
            if run_clicked:
                missing = [name for name, value in (
                    ("Image (step 1)", original_image), ("Tampered manifest JSON", tampered_manifest_text.strip()),
                    ("Signature (step 1)", signature_text.strip()), ("Public key (step 1)", public_key_text.strip()),
                ) if not value]
                if not report_missing(missing):
                    run_verification("tamper_manifest_result", original_image, tampered_manifest_text,
                                     signature_text, public_key_text)
        show_stored_result("tamper_manifest_result", thresholds)

    # ── Tab 3: Advanced Tampering Test ────────────────────────────────────────
    with tab_advanced:
        column_info, column_action = st.columns([2, 3], gap="large")
        with column_info:
            ui.callout(
                "fail", "Why SHA-256 alone is not enough",
                "<ol style='margin:.25rem 0 0 1rem;padding:0'><li>Upload a modified image</li>"
                "<li>Its new SHA-256 is injected into the manifest automatically</li>"
                "<li>The <b>original signature</b> is kept</li></ol>"
                "<div style='margin-top:.5rem'>Image and manifest now match (<code>hash_valid = true</code>), "
                "but the signature fails because the signed manifest changed.</div>",
            )
        adv_manifest_json = ""
        with column_action:
            adv_image = st.file_uploader("Modified image (advanced test)", type=IMAGE_TYPES, key="adv_image_file")
            if adv_image:
                adv_new_hash = sha256_bytes(adv_image.getvalue())
                if manifest_text.strip():
                    try:
                        adv_manifest = json.loads(manifest_text)
                        old_hash = str(adv_manifest.get("image_hash", ""))
                        adv_manifest["image_hash"] = adv_new_hash
                        adv_manifest_json = json.dumps(adv_manifest, indent=2)
                        ui.hash_block("Old image_hash", old_hash)
                        ui.hash_block("New image_hash (injected)", adv_new_hash)
                        with st.expander("Modified manifest"):
                            st.json(adv_manifest)
                    except (json.JSONDecodeError, AttributeError):
                        st.error("Original manifest JSON is invalid — load a valid manifest in step 1 first.")
                else:
                    ui.hash_block("New SHA-256", adv_new_hash)
                    st.info("Load the original manifest in step 1 to build the modified manifest.")

            if st.button("Inspect with advanced tampering", key="btn_adv_tamper", width="stretch"):
                missing = [name for name, value in (
                    ("Modified image", adv_image), ("Original manifest (step 1)", adv_manifest_json),
                    ("Original signature (step 1)", signature_text.strip()),
                    ("Public key (step 1)", public_key_text.strip()),
                ) if not value]
                if not report_missing(missing):
                    run_verification("adv_result", adv_image.getvalue(), adv_manifest_json,
                                     signature_text, public_key_text)

        show_stored_result("adv_result", thresholds)
        adv_result = st.session_state.get("adv_result")
        if adv_result:
            hash_ok = adv_result.get("hash_valid", False)
            signature_ok = adv_result.get("signature_valid", False)
            if hash_ok and not signature_ok:
                ui.callout(
                    "info", "Key insight",
                    "<div>The attacker made the image and manifest match (<b>hash_valid ✓</b>), but cannot "
                    "produce a valid signature without the private key.</div><div style='margin-top:.4rem'>"
                    "<b>The digital signature is the true tamper-proof seal — SHA-256 alone is not sufficient.</b></div>",
                )
            elif not hash_ok and not signature_ok:
                ui.callout("warn", "Unexpected result",
                           "<div>Both hash and signature failed. Make sure you uploaded the modified image and "
                           "loaded the original manifest in step 1.</div>")


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 3 — Standalone AI detection
# ─────────────────────────────────────────────────────────────────────────────

def render_ai_page() -> None:
    ui.page_header(
        "Content authenticity",
        "AI-generation detection",
        "Check whether any image was created by a generative AI model, using Resemble AI Detect. "
        "This check is independent of the cryptographic seal: a signature proves the file was not "
        "changed, this estimates whether its content is synthetic.",
    )

    column_input, column_result = st.columns([2, 3], gap="large")

    with column_input:
        ui.section_title("1", "Image")
        with st.container(border=True):
            source = st.segmented_control("Source", ["Upload", "Camera"], default="Upload", key="ai_source",
                                          label_visibility="collapsed")
            if source == "Camera":
                image_input = st.camera_input("Take a photo", key="ai_camera", label_visibility="collapsed")
            else:
                image_input = st.file_uploader("Image to analyze", type=IMAGE_TYPES, key="ai_upload")
            image_bytes = image_input.getvalue() if image_input else None
            if image_bytes and source != "Camera":
                st.image(image_bytes, width="stretch")

            if st.button("Analyze image", type="primary", width="stretch", key="btn_ai_analyze",
                         disabled=image_bytes is None):
                with st.spinner("Analyzing with Resemble AI…"):
                    try:
                        st.session_state["ai_page_result"] = detect_ai_standalone(image_bytes, ai_detector)
                        st.session_state.pop("ai_page_error", None)
                    except EvidenceInputError as error:
                        st.session_state.pop("ai_page_result", None)
                        st.session_state["ai_page_error"] = str(error)

        ui.section_title("", "How to read the score")
        ui.how_it_works([
            (f"Below {thresholds['review_threshold']:.0%}", "likely authentic → TRUSTED (if integrity passes)."),
            (f"{thresholds['review_threshold']:.0%} – {thresholds['reject_threshold']:.0%}", "borderline → manual REVIEW."),
            (f"Above {thresholds['reject_threshold']:.0%}", "likely AI-generated → REJECTED."),
        ])

    with column_result:
        ui.section_title("2", "Result")
        if st.session_state.get("ai_page_error"):
            st.error(st.session_state["ai_page_error"])
        result = st.session_state.get("ai_page_result")
        if not result:
            ui.empty_state("Upload or capture an image, then click Analyze.")
            return
        with st.container(border=True):
            ui.ai_score_panel(result.get("ai_detection", {}), thresholds)
            st.write("")
            ui.hash_block("Analyzed image SHA-256", result.get("image_sha256", ""))
        ui.callout(
            "info", "Detection is probabilistic",
            "<div>No detector is 100% accurate. Treat the score as a risk signal, and keep borderline cases "
            "for a human reviewer. Thresholds are configured in <code>.env</code>.</div>",
        )


# ── Router ───────────────────────────────────────────────────────────────────
if page == PAGE_CAPTURE:
    render_capture_page()
elif page == PAGE_INSPECTOR:
    render_inspector_page()
else:
    render_ai_page()
