"""
ui/auth.py
----------
Login gate for the Streamlit app. `require_login()` must be called before any
page content is rendered: it shows the login screen and stops the script
(st.stop) until the user signs in.
"""

from __future__ import annotations

import time

import streamlit as st

from services.auth_service import Authenticator, load_auth_settings
from ui.components import render_html

SESSION_USER_KEY = "auth_user"
SESSION_EXPIRES_KEY = "auth_expires_at"

_LOGIN_CSS = """
<style>
section[data-testid="stSidebar"], [data-testid="collapsedControl"], [data-testid="stSidebarCollapsedControl"] { display:none; }
.block-container { max-width: 440px !important; padding-top: 9vh !important; }
.tc-login-head { text-align:center; margin-bottom:1.5rem; }
.tc-login-mark { width:54px; height:54px; border-radius:14px; margin:0 auto .9rem; display:flex; align-items:center;
  justify-content:center; background:linear-gradient(135deg,#6366F1,#1E3A8A); box-shadow:0 10px 26px rgba(79,70,229,.35); }
.tc-login-title { font-size:1.5rem; font-weight:700; color:#0F172A; letter-spacing:-.01em; }
.tc-login-sub { font-size:.92rem; color:#64748B; margin-top:.3rem; }
div[data-testid="stForm"] { background:#FFFFFF; border:1px solid #E2E8F0; border-radius:16px; padding:1.5rem 1.5rem 1.1rem;
  box-shadow:0 12px 32px rgba(15,23,42,.06); }
.tc-login-foot { text-align:center; font-size:.78rem; color:#94A3B8; margin-top:1.1rem; }
</style>
"""


@st.cache_resource
def get_authenticator() -> Authenticator:
    # Shared across all sessions, so the failed-attempt counter cannot be reset by opening a new tab.
    return Authenticator(load_auth_settings())


def current_user() -> str | None:
    return st.session_state.get(SESSION_USER_KEY)


def logout(message: str | None = None) -> None:
    st.session_state.pop(SESSION_USER_KEY, None)
    st.session_state.pop(SESSION_EXPIRES_KEY, None)
    if message:
        st.session_state["auth_notice"] = message


def _session_is_valid() -> bool:
    if not current_user():
        return False
    if time.time() > st.session_state.get(SESSION_EXPIRES_KEY, 0):
        logout("Your session expired. Please sign in again.")
        return False
    return True


def _render_login_screen(authenticator: Authenticator) -> None:
    st.markdown(_LOGIN_CSS, unsafe_allow_html=True)
    render_html(
        """
        <div class="tc-login-head">
          <div class="tc-login-mark">
            <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.2"
                 stroke-linecap="round" stroke-linejoin="round">
              <path d="M12 2l8 4v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6l8-4z"/><path d="M8.5 12l2.5 2.5 4.5-5"/>
            </svg>
          </div>
          <div class="tc-login-title">Sign in to TrustCap</div>
          <div class="tc-login-sub">Evidence Integrity Lab · authorized access only</div>
        </div>
        """
    )

    notice = st.session_state.pop("auth_notice", None)
    if notice:
        st.info(notice)

    if not authenticator.settings.is_configured:
        st.error(
            "Login is not configured. Add AUTH_EMAIL and AUTH_PASSWORD_HASH to the .env file, "
            "then restart the app."
        )
        return

    with st.form("login_form", clear_on_submit=False):
        email = st.text_input("Email", placeholder="name@company.com", autocomplete="username")
        password = st.text_input("Password", type="password", autocomplete="current-password")
        submitted = st.form_submit_button("Sign in", type="primary", width="stretch")

    if submitted:
        result = authenticator.login(email, password)
        if result.success:
            st.session_state[SESSION_USER_KEY] = email.strip().lower()
            st.session_state[SESSION_EXPIRES_KEY] = time.time() + authenticator.settings.session_minutes * 60
            st.rerun()
        else:
            st.error(result.message)

    render_html('<div class="tc-login-foot">Protected prototype · activity is limited to signed-in users</div>')


def require_login() -> str:
    """Returns the signed-in email, or renders the login screen and stops the script."""
    if _session_is_valid():
        return current_user()
    _render_login_screen(get_authenticator())
    st.stop()
