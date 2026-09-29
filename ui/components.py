"""
ui/components.py
----------------
Reusable presentation components. They only render data returned by the
FastAPI backend; they never decide whether evidence is valid.

Every dynamic value is HTML-escaped before rendering, because manifest fields
and error messages can contain user-controlled text.
"""

from __future__ import annotations

from html import escape

import streamlit as st

from ui.theme import COLORS

# State -> (colour, soft background, badge symbol)
_STATE_STYLE = {
    "pass": (COLORS["pass"], COLORS["pass_soft"], "✓"),
    "fail": (COLORS["fail"], COLORS["fail_soft"], "✕"),
    "warn": (COLORS["warn"], COLORS["warn_soft"], "!"),
    "skip": (COLORS["skip"], COLORS["skip_soft"], "–"),
}

_VERDICT_STYLE = {
    "TRUSTED": ("pass", "Evidence trusted", "✓"),
    "REVIEW": ("warn", "Manual review required", "!"),
    "REJECTED": ("fail", "Evidence rejected", "✕"),
}

DEFAULT_THRESHOLDS = {"review_threshold": 0.50, "reject_threshold": 0.85}


def render_html(markup: str) -> None:
    """Render HTML; lines are stripped so Markdown never treats indentation as a code block."""
    compact_markup = "".join(line.strip() for line in markup.splitlines())
    st.markdown(compact_markup, unsafe_allow_html=True)


# ── Layout pieces ───────────────────────────────────────────────────────────
def sidebar_brand() -> None:
    render_html(
        """
        <div class="tc-brand">
          <div class="tc-brand-mark">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.2"
                 stroke-linecap="round" stroke-linejoin="round">
              <path d="M12 2l8 4v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6l8-4z"/><path d="M8.5 12l2.5 2.5 4.5-5"/>
            </svg>
          </div>
          <div><div class="tc-brand-name">TRUSTCAP</div><div class="tc-brand-sub">Evidence Integrity Lab</div></div>
        </div>
        """
    )


def sidebar_status(ai_settings) -> None:
    """ai_settings: config.AIDetectionSettings."""
    render_html('<div class="tc-side-label">System status</div>')
    if not ai_settings.enabled:
        ai_color, ai_text = "#64748B", "Disabled"
    elif ai_settings.is_configured:
        ai_color, ai_text = "#22C55E", "Resemble ready"
    else:
        ai_color, ai_text = "#F59E0B", "No API key"

    render_html(
        f"""
        <div class="tc-status-row"><span>Verification engine</span>
          <span><span class="tc-dot" style="background:#22C55E"></span>Local</span></div>
        <div class="tc-status-row"><span>AI detection</span>
          <span><span class="tc-dot" style="background:{ai_color}"></span>{ai_text}</span></div>
        """
    )


def sidebar_user(email: str) -> None:
    initial = escape(email[:1].upper() or "?")
    render_html(
        f"""
        <div class="tc-side-label">Signed in</div>
        <div class="tc-user"><div class="tc-avatar">{initial}</div>
        <div class="tc-user-email">{escape(email)}</div></div>
        """
    )


def page_header(eyebrow: str, title: str, subtitle: str) -> None:
    render_html(
        f"""
        <div class="tc-eyebrow">{escape(eyebrow)}</div>
        <div class="tc-title">{escape(title)}</div>
        <div class="tc-subtitle">{subtitle}</div>
        """
    )


def section_title(number: str, title: str, hint: str = "") -> None:
    hint_html = f'<span class="tc-section-hint">{escape(hint)}</span>' if hint else ""
    number_html = f'<div class="tc-section-num">{escape(number)}</div>' if number else ""
    render_html(
        f"""
        <div class="tc-section">{number_html}
        <div class="tc-section-title">{escape(title)}</div>{hint_html}</div>
        """
    )


def callout(kind: str, title: str, body_html: str) -> None:
    """kind: pass | warn | fail | skip | info. body_html must already be safe HTML."""
    if kind == "info":
        color, background = COLORS["brand"], COLORS["brand_soft"]
    else:
        color, background, _ = _STATE_STYLE[kind]
    render_html(
        f"""
        <div class="tc-callout" style="background:{background};border-color:{color}33;color:{COLORS['ink']}">
          <div class="tc-callout-title" style="color:{color}">{escape(title)}</div>{body_html}
        </div>
        """
    )


def how_it_works(steps: list[tuple[str, str]]) -> None:
    items = "".join(f"<li><b>{escape(name)}</b> — {escape(text)}</li>" for name, text in steps)
    render_html(f'<ol class="tc-howto">{items}</ol>')


def empty_state(message: str) -> None:
    render_html(f'<div class="tc-empty">{escape(message)}</div>')


def hash_block(label: str, value: str) -> None:
    render_html(
        f'<div class="tc-hash-label">{escape(label)}</div><div class="tc-hash">{escape(value or "—")}</div>'
    )


def key_value_list(pairs: list[tuple[str, str]]) -> None:
    rows = "".join(f"<dt>{escape(key)}</dt><dd>{escape(str(value) or '—')}</dd>" for key, value in pairs)
    render_html(f'<dl class="tc-kv">{rows}</dl>')


# ── Verification result ─────────────────────────────────────────────────────
def _ai_step_state(ai_detection: dict, thresholds: dict) -> tuple[str, str]:
    status = ai_detection.get("status")
    score = ai_detection.get("score")
    if status == "completed":
        if score is None:
            return ("warn", "Label: fake") if ai_detection.get("label") == "fake" else ("pass", "Label: real")
        if score >= thresholds["reject_threshold"]:
            return "fail", f"AI likely · {score:.0%}"
        if score >= thresholds["review_threshold"]:
            return "warn", f"Borderline · {score:.0%}"
        return "pass", f"Likely real · {score:.0%}"
    if status in ("error", "not_configured"):
        return "warn", "Unavailable"
    return "skip", "Skipped"


def _step_card(index: int, name: str, state: str, state_text: str) -> str:
    color, background, symbol = _STATE_STYLE[state]
    return (
        f'<div class="tc-step" style="background:{background};border-color:{color}33">'
        f'<div class="tc-step-top"><span class="tc-step-idx">STEP {index:02d}</span>'
        f'<span class="tc-badge" style="background:{color}">{symbol}</span></div>'
        f'<div class="tc-step-name">{escape(name)}</div>'
        f'<div class="tc-step-state" style="color:{color}">{escape(state_text)}</div></div>'
    )


def verification_pipeline(result: dict, thresholds: dict) -> None:
    manifest_ok = result.get("manifest_valid", False)
    hash_ok = result.get("hash_valid", False)
    signature_ok = result.get("signature_valid", False)
    ai_state, ai_text = _ai_step_state(result.get("ai_detection") or {}, thresholds)
    verdict = result.get("trust_verdict", "TRUSTED" if result.get("verified") else "REJECTED")
    verdict_state = _VERDICT_STYLE.get(verdict, ("skip", verdict, "–"))[0]

    cards = [
        _step_card(1, "Manifest", "pass" if manifest_ok else "fail", "Valid" if manifest_ok else "Invalid"),
        _step_card(2, "Image hash", "pass" if hash_ok else "fail", "Match" if hash_ok else "Mismatch"),
        _step_card(3, "Signature", "pass" if signature_ok else "fail", "Valid" if signature_ok else "Invalid"),
        _step_card(4, "AI authenticity", ai_state, ai_text),
        _step_card(5, "Final verdict", verdict_state, verdict),
    ]
    render_html(f'<div class="tc-pipeline">{"".join(cards)}</div>')


def verdict_banner(result: dict) -> None:
    verdict = result.get("trust_verdict", "TRUSTED" if result.get("verified") else "REJECTED")
    state, headline, symbol = _VERDICT_STYLE.get(verdict, ("skip", verdict, "–"))
    color, background, _ = _STATE_STYLE[state]
    reasons = result.get("trust_reasons") or []
    reason_html = "<br>".join(escape(reason) for reason in reasons) or "&nbsp;"
    integrity_text = "Cryptographic integrity: VERIFIED" if result.get("verified") else "Cryptographic integrity: FAILED"

    render_html(
        f"""
        <div class="tc-verdict" style="background:{background};border-color:{color}40;color:{COLORS['ink']}">
          <div class="tc-verdict-icon" style="background:{color}">{symbol}</div>
          <div>
            <div class="tc-verdict-kicker" style="color:{color}">Final verdict · {escape(verdict)}</div>
            <div class="tc-verdict-title" style="color:{color}">{escape(headline)}</div>
            <div class="tc-verdict-reason">{reason_html}</div>
            <div class="tc-verdict-sub">{integrity_text}</div>
          </div>
        </div>
        """
    )


def ai_score_panel(ai_detection: dict, thresholds: dict) -> None:
    status = ai_detection.get("status", "skipped")
    score = ai_detection.get("score")
    review = thresholds["review_threshold"]
    reject = thresholds["reject_threshold"]

    if status != "completed" or score is None:
        kind = "skip" if status in ("skipped", "disabled") else "warn"
        title = {
            "skipped": "AI check skipped",
            "disabled": "AI detection disabled",
            "not_configured": "AI detection not configured",
            "error": "AI detection failed",
        }.get(status, "AI result unavailable")
        if status == "completed":  # label only, no score
            title = f"Provider label: {ai_detection.get('label', 'unknown')}"
        callout(kind, title, f"<div>{escape(ai_detection.get('reason') or 'No score returned.')}</div>")
        return

    if score >= reject:
        state, label_text = "fail", "Likely AI-generated"
    elif score >= review:
        state, label_text = "warn", "Borderline — review"
    else:
        state, label_text = "pass", "Likely authentic"
    color, background, _ = _STATE_STYLE[state]
    provider_label = (ai_detection.get("label") or "—").upper()

    render_html(
        f"""
        <div class="tc-ai">
          <div class="tc-ai-head">
            <div>
              <div class="tc-hash-label">AI-generation probability</div>
              <div class="tc-ai-score" style="color:{color}">{score:.0%}</div>
            </div>
            <span class="tc-ai-label" style="background:{background};color:{color};border:1px solid {color}40">{label_text}</span>
          </div>
          <div class="tc-gauge">
            <div class="tc-gauge-marker" style="left:{score * 100:.1f}%"></div>
            <div class="tc-gauge-tick" style="left:{review * 100:.1f}%">Review {review:.0%}</div>
            <div class="tc-gauge-tick" style="left:{reject * 100:.1f}%">Reject {reject:.0%}</div>
          </div>
          <div class="tc-gauge-scale"><span>0% · Real</span><span>100% · AI</span></div>
          <div class="tc-ai-meta">
            <span>Provider <b>Resemble AI</b></span>
            <span>Label <b>{escape(provider_label)}</b></span>
            <span>Detection ID <b>{escape(ai_detection.get('detection_id') or '—')}</b></span>
            <span>{'Cached result' if ai_detection.get('cached') else 'Live result'}</span>
          </div>
        </div>
        """
    )


def verification_result(result: dict, thresholds: dict | None = None) -> None:
    """Full result view: pipeline, verdict, AI panel, integrity details, errors."""
    thresholds = thresholds or DEFAULT_THRESHOLDS

    verification_pipeline(result, thresholds)
    verdict_banner(result)

    column_ai, column_integrity = st.columns([1, 1], gap="medium")
    with column_ai:
        with st.container(border=True):
            render_html('<div class="tc-section-title" style="margin-bottom:.75rem">AI authenticity</div>')
            ai_score_panel(result.get("ai_detection") or {"status": "skipped", "reason": "Backend returned no AI result."}, thresholds)

    with column_integrity:
        with st.container(border=True):
            render_html('<div class="tc-section-title" style="margin-bottom:.75rem">Integrity details</div>')
            hash_block("Calculated SHA-256", result.get("server_calculated_hash", ""))
            hash_block("Manifest image_hash", str(result.get("manifest_image_hash", "")))
            st.write("")
            key_value_list([
                ("Claim ID", result.get("claim_id", "")),
                ("Capture ID", result.get("capture_id", "")),
                ("Key ID", result.get("key_id", "")),
            ])

    errors = result.get("errors") or []
    if errors:
        with st.expander(f"Verification errors ({len(errors)})", expanded=True):
            for error_message in errors:
                st.warning(error_message)

    with st.expander("Raw API response"):
        st.json(result)
