"""Cloud Sentry — Cloud Storage Access Control & Security Misconfiguration Simulator.

Academic cybersecurity Streamlit dashboard built strictly on top of the tested
local backend modules:
  - models.py         (Users, Roles, StorageObjects, JSON persistence)
  - access_control.py (Deterministic RBAC & policy decision engine)
  - risk_analyzer.py  (Misconfiguration detection & educational 0-100 risk score)
  - test_cases.py     (Independent Expected READ Matrix & verification logic)
  - utils/logger.py   (Local JSON audit trail & request metrics)
"""

from __future__ import annotations

import uuid

import pandas as pd
import streamlit as st

from access_control import check_access
from models import (
    AccessPolicy,
    Action,
    Classification,
    Role,
    StorageObject,
    User,
    load_objects,
    load_users,
    save_objects,
    save_users,
)
from risk_analyzer import (
    EDUCATIONAL_RISK_DISCLAIMER,
    Severity,
    analyze_all_objects,
    calculate_overall_risk,
)
from test_cases import (
    EXPECTED_READ_MATRIX,
    compare_expected_vs_actual,
    get_expected_read_matrix_df,
    verify_matrix_dataframe,
)
from utils.logger import AuditLogger


# ---------------------------------------------------------------------------
# Page Setup
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="Cloud Sentry — Cloud Storage Security Simulator",
    page_icon="☁️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ---------------------------------------------------------------------------
# Minimalist Monochrome SVG Logo (Simple Shield + Cloud Mark)
# ---------------------------------------------------------------------------
def get_logo_svg(size: int = 48, theme: str = "Dark") -> str:
    """Return a clean, minimal grey/black/white SVG logo for Cloud Sentry."""
    is_dark = theme == "Dark"
    box_fill = "#171717" if is_dark else "#111111"
    box_stroke = "#404040" if is_dark else "#262626"
    fg_stroke = "#FAFAFA"
    accent_fill = "#A3A3A3"
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" '
        f'viewBox="0 0 64 64" fill="none" aria-label="Cloud Sentry Logo">'
        f'<rect x="3" y="3" width="58" height="58" rx="14" '
        f'fill="{box_fill}" stroke="{box_stroke}" stroke-width="2"/>'
        # Simple minimalist shield outline
        f'<path d="M32 13L48 19.5V32C48 41.8 41.2 49.4 32 52.5C22.8 49.4 16 41.8 16 32V19.5L32 13Z" '
        f'stroke="{fg_stroke}" stroke-width="2.6" stroke-linejoin="round"/>'
        # Minimal inner cloud-arch & lock dot
        f'<path d="M24 35H40C42.2 35 44 33.2 44 31C44 29 42.5 27.3 40.5 27.1'
        f'C39.8 23.6 36.7 21 33 21C29.8 21 27.1 22.9 25.9 25.6'
        f'C23.2 26 21 28.3 21 31C21 33.2 22.3 35 24 35Z" '
        f'stroke="{fg_stroke}" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>'
        f'<circle cx="32" cy="41.5" r="2.3" fill="{accent_fill}"/>'
        f"</svg>"
    )


# ---------------------------------------------------------------------------
# Monochrome Theme CSS (Grey, Black & White — Dark & Light Modes) + Intro
# ---------------------------------------------------------------------------
def build_theme_css(theme: str) -> str:
    """Generate complete grey/black/white CSS for Dark or Light mode + intro."""
    if theme == "Dark":
        bg_main = "#0a0a0a"
        bg_sidebar = "#111111"
        bg_card = "#171717"
        bg_elevated = "#1f1f1f"
        bg_banner = "linear-gradient(135deg, #171717 0%, #0d0d0d 100%)"
        text_primary = "#fafafa"
        text_secondary = "#a3a3a3"
        border_color = "#262626"
        btn_primary_bg = "#fafafa"
        btn_primary_fg = "#0a0a0a"
        btn_primary_hover = "#e5e5e5"
        btn_sec_bg = "#1c1c1c"
        btn_sec_fg = "#f5f5f5"
        allow_bg = "#171717"
        allow_border = "#fafafa"
        allow_fg = "#fafafa"
        deny_bg = "#171717"
        deny_border = "#737373"
        deny_fg = "#d4d4d4"
        splash_bg = "radial-gradient(circle at 50% 45%, #1c1c1c 0%, #0a0a0a 65%, #000000 100%)"
        splash_title_grad = "linear-gradient(90deg, #ffffff 0%, #d4d4d4 55%, #a3a3a3 100%)"
        splash_sub = "#a3a3a3"
        progress_fill = "#e5e5e5"
        progress_track = "#262626"
        input_bg = "#141414"
        brand_color = "#ffffff"
    else:
        bg_main = "#ffffff"
        bg_sidebar = "#f5f5f5"
        bg_card = "#fafafa"
        bg_elevated = "#f0f0f0"
        bg_banner = "linear-gradient(135deg, #171717 0%, #262626 100%)"
        text_primary = "#0a0a0a"
        text_secondary = "#525252"
        border_color = "#e5e5e5"
        btn_primary_bg = "#111111"
        btn_primary_fg = "#ffffff"
        btn_primary_hover = "#262626"
        btn_sec_bg = "#ffffff"
        btn_sec_fg = "#171717"
        allow_bg = "#f5f5f5"
        allow_border = "#111111"
        allow_fg = "#0a0a0a"
        deny_bg = "#f5f5f5"
        deny_border = "#737373"
        deny_fg = "#262626"
        splash_bg = "radial-gradient(circle at 50% 45%, #ffffff 0%, #f5f5f5 60%, #e5e5e5 100%)"
        splash_title_grad = "linear-gradient(90deg, #0a0a0a 0%, #262626 55%, #525252 100%)"
        splash_sub = "#525252"
        progress_fill = "#171717"
        progress_track = "#e5e5e5"
        input_bg = "#ffffff"
        brand_color = "#0a0a0a"

    return f"""
<style>
    :root {{
        --cs-bg-main: {bg_main};
        --cs-bg-sidebar: {bg_sidebar};
        --cs-bg-card: {bg_card};
        --cs-text-primary: {text_primary};
        --cs-text-secondary: {text_secondary};
        --cs-border: {border_color};
    }}

    /* Core App & Sidebar Surface Theming */
    [data-testid="stAppViewContainer"] {{
        background-color: {bg_main} !important;
        color: {text_primary} !important;
        transition: background-color 0.2s ease, color 0.2s ease;
    }}
    [data-testid="stHeader"] {{
        background-color: transparent !important;
    }}
    [data-testid="stSidebar"] {{
        background-color: {bg_sidebar} !important;
        border-right: 1px solid {border_color};
    }}
    [data-testid="stSidebar"] * {{
        color: {text_primary};
    }}

    /* Typography & Labels */
    [data-testid="stAppViewContainer"] h1,
    [data-testid="stAppViewContainer"] h2,
    [data-testid="stAppViewContainer"] h3,
    [data-testid="stAppViewContainer"] h4,
    [data-testid="stAppViewContainer"] p,
    [data-testid="stAppViewContainer"] label,
    [data-testid="stAppViewContainer"] li {{
        color: {text_primary};
    }}
    [data-testid="stCaptionContainer"] p {{
        color: {text_secondary} !important;
    }}
    hr {{
        border-color: {border_color} !important;
    }}

    /* Metric Cards */
    [data-testid="stMetric"] {{
        background-color: {bg_card};
        border: 1px solid {border_color};
        border-radius: 10px;
        padding: 0.9rem 1.05rem;
    }}
    [data-testid="stMetricLabel"] p {{
        color: {text_secondary} !important;
        font-weight: 600 !important;
    }}
    [data-testid="stMetricValue"] {{
        color: {text_primary} !important;
    }}
    [data-testid="stMetricDelta"] > div {{
        color: {text_secondary} !important;
        background-color: {bg_elevated} !important;
        border-radius: 6px;
        padding: 0.1rem 0.45rem;
    }}
    [data-testid="stMetricDelta"] svg {{
        fill: {text_secondary} !important;
    }}

    /* Buttons — Strict Grey / Black / White */
    button[kind="primary"],
    [data-testid="stFormSubmitButton"] button {{
        background-color: {btn_primary_bg} !important;
        color: {btn_primary_fg} !important;
        border: 1px solid {btn_primary_bg} !important;
        font-weight: 600 !important;
        border-radius: 8px !important;
    }}
    button[kind="primary"]:hover,
    [data-testid="stFormSubmitButton"] button:hover {{
        background-color: {btn_primary_hover} !important;
        border-color: {btn_primary_hover} !important;
    }}
    button[kind="primary"] *,
    [data-testid="stFormSubmitButton"] button * {{
        color: {btn_primary_fg} !important;
    }}
    button[kind="secondary"] {{
        background-color: {btn_sec_bg} !important;
        color: {btn_sec_fg} !important;
        border: 1px solid {border_color} !important;
        border-radius: 8px !important;
    }}
    button[kind="secondary"]:hover {{
        background-color: {bg_elevated} !important;
        border-color: {text_secondary} !important;
    }}

    /* Progress Bar, Alerts, Tabs, Inputs & Expanders */
    [data-testid="stProgress"] > div > div > div {{
        background-color: {progress_track} !important;
    }}
    [data-testid="stProgress"] > div > div > div > div {{
        background-color: {progress_fill} !important;
    }}
    [data-testid="stAlert"] {{
        background-color: {bg_card} !important;
        color: {text_primary} !important;
        border: 1px solid {border_color} !important;
        border-left: 4px solid {text_primary} !important;
        border-radius: 8px !important;
    }}
    [data-testid="stAlert"] * {{
        color: {text_primary} !important;
    }}
    [data-testid="stForm"],
    [data-testid="stExpander"] {{
        background-color: {bg_card};
        border: 1px solid {border_color} !important;
        border-radius: 10px;
    }}
    div[data-baseweb="select"] > div,
    div[data-baseweb="input"] > div {{
        background-color: {input_bg} !important;
        color: {text_primary} !important;
        border-color: {border_color} !important;
    }}
    [data-baseweb="tab-highlight"] {{
        background-color: {text_primary} !important;
    }}
    [data-testid="stSidebar"] input[type="radio"]:checked + div,
    [data-baseweb="checkbox"] [aria-checked="true"] {{
        accent-color: {text_primary};
    }}

    /* Sidebar Brand Lockup */
    .cs-sidebar-brand {{
        display: flex;
        align-items: center;
        gap: 0.7rem;
        padding: 0.2rem 0 0.5rem 0;
    }}
    .cs-sidebar-brand-title {{
        font-size: 1.28rem;
        font-weight: 800;
        letter-spacing: -0.02em;
        color: {brand_color} !important;
        line-height: 1.1;
    }}
    .cs-sidebar-brand-sub {{
        font-size: 0.74rem;
        color: {text_secondary} !important;
        margin-top: 0.15rem;
    }}

    /* Main Header Banner */
    .cs-header {{
        background: {bg_banner};
        padding: 1.2rem 1.45rem;
        border-radius: 12px;
        color: #fafafa !important;
        margin-bottom: 1.25rem;
        border: 1px solid #2e2e2e;
        display: flex;
        align-items: center;
        gap: 1rem;
    }}
    .cs-header h1 {{
        margin: 0;
        font-size: 1.5rem;
        font-weight: 800;
        color: #fafafa !important;
        letter-spacing: -0.015em;
    }}
    .cs-header p {{
        margin: 0.25rem 0 0 0;
        color: #a3a3a3 !important;
        font-size: 0.88rem;
    }}

    /* Access Simulator Result Banners (Monochrome) */
    .cs-result-allow {{
        background-color: {allow_bg};
        border: 1px solid {border_color};
        border-left: 6px solid {allow_border};
        color: {allow_fg} !important;
        padding: 1rem 1.25rem;
        border-radius: 10px;
        margin: 0.75rem 0;
    }}
    .cs-result-allow h3, .cs-result-allow p, .cs-result-allow strong {{
        color: {allow_fg} !important;
    }}
    .cs-result-deny {{
        background-color: {deny_bg};
        border: 1px solid {border_color};
        border-left: 6px solid {deny_border};
        color: {deny_fg} !important;
        padding: 1rem 1.25rem;
        border-radius: 10px;
        margin: 0.75rem 0;
    }}
    .cs-result-deny h3, .cs-result-deny p, .cs-result-deny strong {{
        color: {deny_fg} !important;
    }}

    /* =====================================================================
       Monochrome Zoom-In Startup Splash Animation
       ===================================================================== */
    @keyframes csSplashBackdrop {{
        0%   {{ opacity: 1; visibility: visible; }}
        72%  {{ opacity: 1; visibility: visible; }}
        100% {{ opacity: 0; visibility: hidden; pointer-events: none; }}
    }}
    @keyframes csZoomTitle {{
        0% {{
            opacity: 0;
            transform: scale(0.32);
            filter: blur(14px);
            letter-spacing: 0.28em;
        }}
        30% {{
            opacity: 1;
            transform: scale(1.0);
            filter: blur(0px);
            letter-spacing: 0.08em;
        }}
        72% {{
            opacity: 1;
            transform: scale(1.07);
            filter: blur(0px);
            letter-spacing: 0.1em;
        }}
        100% {{
            opacity: 0;
            transform: scale(1.55);
            filter: blur(6px);
            letter-spacing: 0.18em;
        }}
    }}
    @keyframes csLogoPulse {{
        0%   {{ transform: scale(0.35); opacity: 0; }}
        32%  {{ transform: scale(1.03); opacity: 1; }}
        72%  {{ transform: scale(1.0); opacity: 1; }}
        100% {{ transform: scale(1.45); opacity: 0; }}
    }}
    @keyframes csSubFade {{
        0%, 22% {{ opacity: 0; transform: translateY(14px); }}
        42%, 72% {{ opacity: 1; transform: translateY(0); }}
        100% {{ opacity: 0; transform: translateY(-10px); }}
    }}
    @keyframes csDashboardReveal {{
        0%, 62% {{ opacity: 0.08; transform: scale(0.985); }}
        100%    {{ opacity: 1; transform: scale(1); }}
    }}

    .cs-splash-overlay {{
        position: fixed;
        inset: 0;
        z-index: 999999;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        background: {splash_bg};
        pointer-events: none;
        animation: csSplashBackdrop 2.9s cubic-bezier(0.22, 1, 0.36, 1) forwards;
    }}
    .cs-splash-logo {{
        filter: drop-shadow(0 8px 24px rgba(0, 0, 0, 0.35));
        animation: csLogoPulse 2.9s cubic-bezier(0.22, 1, 0.36, 1) forwards;
        margin-bottom: 1.1rem;
    }}
    .cs-splash-title {{
        font-size: clamp(2.8rem, 7vw, 5.4rem);
        font-weight: 900;
        text-transform: uppercase;
        background: {splash_title_grad};
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        text-align: center;
        line-height: 1.05;
        animation: csZoomTitle 2.9s cubic-bezier(0.22, 1, 0.36, 1) forwards;
    }}
    .cs-splash-sub {{
        margin-top: 0.85rem;
        font-size: clamp(0.85rem, 1.5vw, 1.05rem);
        font-weight: 600;
        letter-spacing: 0.22em;
        text-transform: uppercase;
        color: {splash_sub};
        text-align: center;
        animation: csSubFade 2.9s ease forwards;
    }}
    .cs-dashboard-reveal {{
        animation: csDashboardReveal 2.9s ease forwards;
    }}
</style>
"""


def render_startup_splash(theme: str = "Dark") -> None:
    """Render the full-screen Cloud Sentry monochrome zoom-in intro overlay."""
    splash_logo = get_logo_svg(size=92, theme=theme)
    st.markdown(
        f"""
        <div class="cs-splash-overlay">
            <div class="cs-splash-logo">{splash_logo}</div>
            <div class="cs-splash-title">Cloud Sentry</div>
            <div class="cs-splash-sub">Cloud Storage Access Control &amp; Security Simulator</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Constants & Seed Data
# ---------------------------------------------------------------------------
DEFAULT_USERS_SEED: list[dict[str, str]] = [
    {"id": "U001", "name": "Alice", "role": "Admin"},
    {"id": "U002", "name": "Bob", "role": "Manager"},
    {"id": "U003", "name": "Charlie", "role": "Employee"},
    {"id": "U004", "name": "David", "role": "Guest"},
]

DEFAULT_OBJECTS_SEED: list[dict[str, object]] = [
    {
        "id": "OBJ001",
        "name": "public_notice.pdf",
        "owner": "Alice",
        "classification": "Public",
        "policy": "public-read",
        "allowed_roles": [],
    },
    {
        "id": "OBJ002",
        "name": "company_policy.pdf",
        "owner": "Alice",
        "classification": "Internal",
        "policy": "role-restricted",
        "allowed_roles": ["Admin", "Manager", "Employee"],
    },
    {
        "id": "OBJ003",
        "name": "employee_records.csv",
        "owner": "Alice",
        "classification": "Confidential",
        "policy": "role-restricted",
        "allowed_roles": ["Admin", "Manager"],
    },
    {
        "id": "OBJ004",
        "name": "salary_data.xlsx",
        "owner": "Alice",
        "classification": "Confidential",
        "policy": "role-restricted",
        "allowed_roles": ["Admin", "Manager"],
    },
    {
        "id": "OBJ005",
        "name": "database_backup.zip",
        "owner": "Alice",
        "classification": "Restricted",
        "policy": "private",
        "allowed_roles": [],
    },
]

ALL_ROLES: list[Role] = [Role.ADMIN, Role.MANAGER, Role.EMPLOYEE, Role.GUEST]
ALL_ACTIONS: list[Action] = [Action.READ, Action.WRITE, Action.DELETE]
ALL_POLICIES: list[AccessPolicy] = [
    AccessPolicy.PUBLIC_READ,
    AccessPolicy.PRIVATE,
    AccessPolicy.ROLE_RESTRICTED,
]
ALL_CLASSIFICATIONS: list[Classification] = [
    Classification.PUBLIC,
    Classification.INTERNAL,
    Classification.CONFIDENTIAL,
    Classification.RESTRICTED,
]


# ---------------------------------------------------------------------------
# Theme-Aware Table Styling Helper
# ---------------------------------------------------------------------------
def make_cell_styler(theme: str):
    """Return a monochrome grey/black/white Pandas cell styler."""
    is_dark = theme == "Dark"

    def style_cell(val: object) -> str:
        text = str(val).upper()
        if text in ("ALLOW", "YES", "PASS", "LOW"):
            return (
                "background-color: #262626; color: #fafafa; font-weight: 600;"
                if is_dark
                else "background-color: #f5f5f5; color: #111111; font-weight: 600;"
            )
        if text in ("DENY", "NO"):
            return (
                "background-color: #141414; color: #a3a3a3; font-weight: 500;"
                if is_dark
                else "background-color: #ffffff; color: #737373; font-weight: 500;"
            )
        if text in ("FAIL", "CRITICAL"):
            return (
                "background-color: #fafafa; color: #0a0a0a; font-weight: 800;"
                if is_dark
                else "background-color: #0a0a0a; color: #fafafa; font-weight: 800;"
            )
        if text == "HIGH":
            return (
                "background-color: #404040; color: #ffffff; font-weight: 700;"
                if is_dark
                else "background-color: #262626; color: #ffffff; font-weight: 700;"
            )
        if text == "MEDIUM":
            return (
                "background-color: #2e2e2e; color: #d4d4d4; font-weight: 600;"
                if is_dark
                else "background-color: #e5e5e5; color: #262626; font-weight: 600;"
            )
        return ""

    return style_cell


def restore_default_data() -> None:
    """Restore the default simulated users and objects to local JSON files."""
    restored_users = [User.from_dict(item) for item in DEFAULT_USERS_SEED]
    restored_objects = [StorageObject.from_dict(item) for item in DEFAULT_OBJECTS_SEED]
    save_users(restored_users)
    save_objects(restored_objects)


def generate_next_user_id(users: list[User]) -> str:
    """Generate the next clean sequential user ID (e.g., U005, U006)."""
    max_num = 0
    for u in users:
        if u.id.startswith("U") and u.id[1:].isdigit():
            max_num = max(max_num, int(u.id[1:]))
    return f"U{max_num + 1:03d}"


# ---------------------------------------------------------------------------
# 1. Dashboard Page
# ---------------------------------------------------------------------------
def render_dashboard(
    users: list[User],
    objects: list[StorageObject],
    logger: AuditLogger,
    theme: str,
) -> None:
    st.subheader("Security Posture Dashboard")

    assessments = analyze_all_objects(objects)
    risk_summary = calculate_overall_risk(assessments)
    audit_metrics = logger.get_metrics()
    style_cell = make_cell_styler(theme)

    overall_risk_score: int = risk_summary["overall_score"]
    overall_security_score: int = max(0, min(100, 100 - overall_risk_score))
    critical_count: int = risk_summary["counts"][Severity.CRITICAL.value]

    row1 = st.columns(3)
    row1[0].metric("Number of Users", len(users))
    row1[1].metric("Number of Cloud Objects", len(objects))
    row1[2].metric(
        "Overall Security Score",
        f"{overall_security_score} / 100",
        delta=f"Risk Score: {overall_risk_score}/100 ({risk_summary['overall_severity']})",
        delta_color="inverse" if overall_risk_score >= 35 else "normal",
    )

    row2 = st.columns(3)
    row2[0].metric("Total Access Requests", audit_metrics["total_requests"])
    row2[1].metric(
        "Denied Requests",
        audit_metrics["denied_requests"],
        delta=f"{audit_metrics['unauthorized_attempts']} unauthorized attempts",
        delta_color="inverse" if audit_metrics["unauthorized_attempts"] > 0 else "off",
    )
    row2[2].metric(
        "Critical Misconfigurations",
        critical_count,
        delta="Action Required" if critical_count > 0 else "No Critical Issues",
        delta_color="inverse" if critical_count > 0 else "normal",
    )

    st.progress(
        overall_security_score / 100,
        text=f"Overall Security Score: {overall_security_score}/100 (Educational Heuristic Risk: {overall_risk_score}/100)",
    )
    st.caption(EDUCATIONAL_RISK_DISCLAIMER)

    chart_color = "#d4d4d4" if theme == "Dark" else "#262626"
    left, right = st.columns(2)
    with left:
        st.markdown("#### Misconfiguration Severity Distribution")
        sev_df = pd.DataFrame(
            {
                "Severity": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                "Objects": [
                    risk_summary["counts"]["CRITICAL"],
                    risk_summary["counts"]["HIGH"],
                    risk_summary["counts"]["MEDIUM"],
                    risk_summary["counts"]["LOW"],
                ],
            }
        ).set_index("Severity")
        st.bar_chart(sev_df, height=240, color=chart_color)

    with right:
        st.markdown("#### Per-Object Educational Risk Score (0–100)")
        obj_risk_df = pd.DataFrame(
            [{"Object": a.object_name, "Risk Score": a.risk_score} for a in assessments]
        ).set_index("Object")
        st.bar_chart(obj_risk_df, height=240, color=chart_color)

    st.markdown("#### Recent Access Activity")
    logs_df = logger.get_logs_dataframe()
    if logs_df.empty:
        st.info(
            "No access requests logged yet. Use **Access Simulator** in the sidebar to simulate requests."
        )
    else:
        styled_logs = logs_df.head(5).style.map(style_cell, subset=["Decision"])
        st.dataframe(styled_logs, width="stretch", hide_index=True)


# ---------------------------------------------------------------------------
# 2. Cloud Objects Page
# ---------------------------------------------------------------------------
def render_cloud_objects(users: list[User], objects: list[StorageObject]) -> None:
    st.subheader("Simulated Cloud Storage Objects")
    st.caption(
        "Inspect local cloud storage objects stored in `data/objects.json`. Modify an "
        "object's policy or allowed roles to demonstrate live misconfiguration detection "
        "and policy drift."
    )

    table_df = pd.DataFrame(
        [
            {
                "ID": o.id,
                "Object Name": o.name,
                "Owner": o.owner,
                "Classification": o.classification.value,
                "Policy": o.policy.value,
                "Allowed Roles": ", ".join(r.value for r in o.allowed_roles) or "None",
            }
            for o in objects
        ]
    )
    st.dataframe(table_df, width="stretch", hide_index=True)

    st.divider()
    tab_edit, tab_add = st.tabs(["Modify Object Policy / Roles", "Add New Simulated Object"])
    owner_names = [u.name for u in users]

    with tab_edit:
        if not objects:
            st.warning("No cloud objects available. Click 'Restore Default Objects' in the sidebar.")
        else:
            selected_label = st.selectbox(
                "Select Cloud Object to Edit",
                [f"{o.id} — {o.name}" for o in objects],
            )
            selected_id = selected_label.split(" — ")[0]
            target = next(o for o in objects if o.id == selected_id)

            with st.form("edit_cloud_object_form"):
                c1, c2 = st.columns(2)
                with c1:
                    new_classification = st.selectbox(
                        "Classification",
                        [c.value for c in ALL_CLASSIFICATIONS],
                        index=[c.value for c in ALL_CLASSIFICATIONS].index(
                            target.classification.value
                        ),
                    )
                    new_policy = st.selectbox(
                        "Access Policy",
                        [p.value for p in ALL_POLICIES],
                        index=[p.value for p in ALL_POLICIES].index(target.policy.value),
                    )
                with c2:
                    owner_idx = (
                        owner_names.index(target.owner)
                        if target.owner in owner_names
                        else 0
                    )
                    new_owner = st.selectbox("Owner", owner_names, index=owner_idx)
                    new_allowed = st.multiselect(
                        "Allowed Roles (used for role-restricted policy)",
                        [r.value for r in ALL_ROLES],
                        default=[r.value for r in target.allowed_roles],
                    )

                if st.form_submit_button("Save Changes", type="primary"):
                    target.classification = Classification(new_classification)
                    target.policy = AccessPolicy(new_policy)
                    target.owner = new_owner
                    target.allowed_roles = [Role(r) for r in new_allowed]
                    save_objects(objects)
                    st.success(f"Updated '{target.name}' in data/objects.json.")
                    st.rerun()

            if len(objects) > 1:
                if st.button(f"Delete '{target.name}'", key=f"del_obj_{target.id}"):
                    remaining = [o for o in objects if o.id != target.id]
                    save_objects(remaining)
                    st.success(f"Deleted cloud object '{target.name}'.")
                    st.rerun()

    with tab_add:
        with st.form("add_cloud_object_form"):
            c1, c2 = st.columns(2)
            with c1:
                add_name = st.text_input("Object Name", placeholder="e.g., audit_report.pdf")
                add_classification = st.selectbox(
                    "Classification", [c.value for c in ALL_CLASSIFICATIONS], index=2
                )
            with c2:
                add_policy = st.selectbox(
                    "Access Policy", [p.value for p in ALL_POLICIES], index=1
                )
                add_owner = st.selectbox("Owner", owner_names)
            add_allowed = st.multiselect(
                "Allowed Roles (used for role-restricted policy)",
                [r.value for r in ALL_ROLES],
                default=["Admin", "Manager"],
            )

            if st.form_submit_button("Add Cloud Object", type="primary"):
                if not add_name.strip():
                    st.error("Object name cannot be empty.")
                elif any(o.name == add_name.strip() for o in objects):
                    st.error(f"An object named '{add_name.strip()}' already exists.")
                else:
                    new_obj = StorageObject(
                        id=f"OBJ{uuid.uuid4().hex[:4].upper()}",
                        name=add_name.strip(),
                        owner=add_owner,
                        classification=Classification(add_classification),
                        policy=AccessPolicy(add_policy),
                        allowed_roles=[Role(r) for r in add_allowed],
                    )
                    objects.append(new_obj)
                    save_objects(objects)
                    st.success(f"Added simulated object '{new_obj.name}'.")
                    st.rerun()


# ---------------------------------------------------------------------------
# 3. Users & Roles Page (Dynamic User Management)
# ---------------------------------------------------------------------------
def render_users_and_roles(users: list[User], objects: list[StorageObject]) -> None:
    st.subheader("Simulated Users & RBAC Roles")
    st.caption(
        "Create, update, or remove simulated users stored in `data/users.json`. "
        "Any user you add or modify is immediately available in the Access Simulator, "
        "Cloud Objects owner list, Access Matrix, and Security Tests."
    )

    users_df = pd.DataFrame(
        [{"User ID": u.id, "Name": u.name, "Role": u.role.value} for u in users]
    )
    st.dataframe(users_df, width="stretch", hide_index=True)

    st.divider()
    tab_add, tab_edit, tab_delete = st.tabs(
        ["Add New User", "Edit User / Role", "Delete User"]
    )

    with tab_add:
        with st.form("add_user_form"):
            c1, c2 = st.columns(2)
            with c1:
                new_name = st.text_input("User Name", placeholder="e.g., Ruhani, Priya, Sam")
            with c2:
                new_role_str = st.selectbox("Assign Role", [r.value for r in ALL_ROLES])

            if st.form_submit_button("Add User", type="primary"):
                cleaned_name = new_name.strip()
                if not cleaned_name:
                    st.error("User name cannot be empty.")
                elif any(u.name.lower() == cleaned_name.lower() for u in users):
                    st.error(f"A user named '{cleaned_name}' already exists.")
                else:
                    created = User(
                        id=generate_next_user_id(users),
                        name=cleaned_name,
                        role=Role(new_role_str),
                    )
                    updated_users = [*users, created]
                    save_users(updated_users)
                    st.success(
                        f"Added user '{created.name}' ({created.id}) with role '{created.role.value}'! "
                        f"You can now test them in Access Simulator or Security Tests."
                    )
                    st.rerun()

    with tab_edit:
        if not users:
            st.warning("No users available.")
        else:
            selected_u_label = st.selectbox(
                "Select User to Edit",
                [f"{u.id} — {u.name} ({u.role.value})" for u in users],
                key="edit_user_select",
            )
            selected_uid = selected_u_label.split(" — ")[0]
            target_user = next(u for u in users if u.id == selected_uid)

            with st.form("edit_user_form"):
                c1, c2 = st.columns(2)
                with c1:
                    edited_name = st.text_input("User Name", value=target_user.name)
                with c2:
                    edited_role_str = st.selectbox(
                        "Role",
                        [r.value for r in ALL_ROLES],
                        index=[r.value for r in ALL_ROLES].index(target_user.role.value),
                    )

                if st.form_submit_button("Save User Changes", type="primary"):
                    cleaned = edited_name.strip()
                    if not cleaned:
                        st.error("User name cannot be empty.")
                    elif any(
                        u.id != target_user.id and u.name.lower() == cleaned.lower()
                        for u in users
                    ):
                        st.error(f"Another user is already named '{cleaned}'.")
                    else:
                        replacement = User(
                            id=target_user.id,
                            name=cleaned,
                            role=Role(edited_role_str),
                        )
                        updated_users = [
                            replacement if u.id == target_user.id else u for u in users
                        ]
                        save_users(updated_users)

                        # Keep object ownership in sync if user was renamed
                        if cleaned != target_user.name:
                            owner_changed = False
                            for obj in objects:
                                if obj.owner == target_user.name:
                                    obj.owner = cleaned
                                    owner_changed = True
                            if owner_changed:
                                save_objects(objects)

                        st.success(
                            f"Updated '{replacement.name}' ({replacement.id}) -> Role: {replacement.role.value}."
                        )
                        st.rerun()

    with tab_delete:
        if len(users) <= 1:
            st.info("At least one user must remain in the simulator.")
        else:
            del_label = st.selectbox(
                "Select User to Delete",
                [f"{u.id} — {u.name} ({u.role.value})" for u in users],
                key="delete_user_select",
            )
            del_uid = del_label.split(" — ")[0]
            del_user = next(u for u in users if u.id == del_uid)
            owned_objs = [o.name for o in objects if o.owner == del_user.name]
            if owned_objs:
                st.warning(
                    f"'{del_user.name}' currently owns: {', '.join(owned_objs)}. "
                    "Deleting them will reassign those objects to an Admin or remaining user."
                )

            if st.button(f"Delete User '{del_user.name}'", type="secondary"):
                remaining_users = [u for u in users if u.id != del_user.id]
                save_users(remaining_users)

                if owned_objs:
                    fallback_owner = next(
                        (u.name for u in remaining_users if u.role == Role.ADMIN),
                        remaining_users[0].name,
                    )
                    for obj in objects:
                        if obj.owner == del_user.name:
                            obj.owner = fallback_owner
                    save_objects(objects)

                st.success(f"Deleted user '{del_user.name}'.")
                st.rerun()

    st.divider()
    st.markdown("#### Role & Policy Reference")
    ref_df = pd.DataFrame(
        [
            {
                "Policy": "public-read",
                "READ": "All roles (Admin, Manager, Employee, Guest)",
                "WRITE": "Admin only",
                "DELETE": "Admin only",
            },
            {
                "Policy": "private",
                "READ": "Owner and Admin only",
                "WRITE": "Owner and Admin only",
                "DELETE": "Owner and Admin only",
            },
            {
                "Policy": "role-restricted",
                "READ": "Only roles listed in allowed_roles",
                "WRITE": "Admin and Manager (if in allowed_roles)",
                "DELETE": "Admin only",
            },
        ]
    )
    st.dataframe(ref_df, width="stretch", hide_index=True)


# ---------------------------------------------------------------------------
# 4. Access Simulator Page
# ---------------------------------------------------------------------------
def render_access_simulator(
    users: list[User],
    objects: list[StorageObject],
    logger: AuditLogger,
) -> None:
    st.subheader("Access Control Request Simulator")
    st.caption(
        "Select a user, cloud storage object, and action to evaluate the deterministic "
        "access-control engine. Every simulated request is logged to the local audit trail."
    )

    user_options = {f"{u.name} ({u.role.value})": u for u in users}
    object_options = {
        f"{o.name} [{o.classification.value} | {o.policy.value}]": o for o in objects
    }

    c1, c2, c3 = st.columns([2, 2, 1])
    with c1:
        selected_user_label = st.selectbox("User", list(user_options.keys()))
    with c2:
        selected_obj_label = st.selectbox("Cloud Object", list(object_options.keys()))
    with c3:
        selected_action_str = st.selectbox("Action", [a.value for a in ALL_ACTIONS])

    selected_user = user_options[selected_user_label]
    selected_obj = object_options[selected_obj_label]
    selected_action = Action(selected_action_str)

    st.info(
        f"**Selected Object Details:** `{selected_obj.name}` | "
        f"**Owner:** `{selected_obj.owner}` | "
        f"**Classification:** `{selected_obj.classification.value}` | "
        f"**Policy:** `{selected_obj.policy.value}` | "
        f"**Allowed Roles:** `{', '.join(r.value for r in selected_obj.allowed_roles) or 'None'}`"
    )

    if st.button("Simulate Access Request", type="primary", width="stretch"):
        decision = check_access(selected_user, selected_obj, selected_action)

        expected_allowed: bool | None = None
        matrix_comparison = None
        if selected_action == Action.READ and selected_obj.name in EXPECTED_READ_MATRIX:
            matrix_comparison = compare_expected_vs_actual(selected_user, selected_obj)
            expected_allowed = matrix_comparison.expected_allowed

        logger.log_access(decision, expected_allowed=expected_allowed)

        if decision.allowed:
            st.markdown(
                f"""
                <div class="cs-result-allow">
                    <h3 style="margin:0;">✓ ALLOWED</h3>
                    <p style="margin:0.4rem 0 0 0;"><strong>Explanation:</strong> {decision.reason}</p>
                </div>
                """,
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                f"""
                <div class="cs-result-deny">
                    <h3 style="margin:0;">✕ DENIED</h3>
                    <p style="margin:0.4rem 0 0 0;"><strong>Explanation:</strong> {decision.reason}</p>
                </div>
                """,
                unsafe_allow_html=True,
            )

        d1, d2, d3, d4 = st.columns(4)
        d1.metric("User", f"{decision.user} ({decision.role})")
        d2.metric("Cloud Object", decision.object)
        d3.metric("Action", decision.action)
        d4.metric("Decision", "ALLOWED" if decision.allowed else "DENIED")

        if matrix_comparison is not None:
            exp_txt = "ALLOW" if matrix_comparison.expected_allowed else "DENY"
            if matrix_comparison.status == "PASS":
                st.success(
                    f"Expected Access Matrix Verification: **PASS** (Expected READ = `{exp_txt}`, Actual = `{decision.decision}`)."
                )
            else:
                st.error(
                    f"Expected Access Matrix Verification: **FAIL** — Policy drift detected! "
                    f"Expected READ = `{exp_txt}`, but Actual = `{decision.decision}`."
                )


# ---------------------------------------------------------------------------
# 5. Access Matrix Page
# ---------------------------------------------------------------------------
def render_access_matrix(
    users: list[User],
    objects: list[StorageObject],
    theme: str,
) -> None:
    st.subheader("Predefined Expected READ Access Matrix")
    st.caption(
        "Stored independently from `access_control.py` so actual policy configurations "
        "can be audited against expected least-privilege READ permissions."
    )

    style_cell = make_cell_styler(theme)
    matrix_df = get_expected_read_matrix_df()
    styled_matrix = matrix_df.style.map(
        style_cell, subset=["Admin", "Manager", "Employee", "Guest"]
    )
    st.dataframe(styled_matrix, width="stretch", hide_index=True)

    st.divider()
    st.markdown("#### Live Comparison: Expected Matrix vs. Actual Access-Control Engine")
    comparison_df = verify_matrix_dataframe(users, objects)
    total_checks = len(comparison_df)
    passed_checks = int((comparison_df["Status"] == "PASS").sum()) if total_checks else 0
    failed_checks = total_checks - passed_checks

    m1, m2, m3 = st.columns(3)
    m1.metric("Matrix Checks", total_checks)
    m2.metric("PASS", passed_checks)
    m3.metric("FAIL (Drift)", failed_checks)

    styled_comp = comparison_df.style.map(
        style_cell, subset=["Expected READ", "Actual READ", "Status"]
    )
    st.dataframe(styled_comp, width="stretch", hide_index=True)


# ---------------------------------------------------------------------------
# 6. Risk Analyzer Page
# ---------------------------------------------------------------------------
def render_risk_analyzer(objects: list[StorageObject], theme: str) -> None:
    st.subheader("Security Misconfiguration & Risk Analyzer")
    st.info(EDUCATIONAL_RISK_DISCLAIMER)

    style_cell = make_cell_styler(theme)
    assessments = analyze_all_objects(objects)
    summary = calculate_overall_risk(assessments)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Overall Risk Score", f"{summary['overall_score']} / 100")
    c2.metric("Overall Severity", summary["overall_severity"])
    c3.metric("CRITICAL / HIGH", f"{summary['counts']['CRITICAL']} / {summary['counts']['HIGH']}")
    c4.metric("MEDIUM / LOW", f"{summary['counts']['MEDIUM']} / {summary['counts']['LOW']}")

    risk_df = pd.DataFrame(
        [
            {
                "Object": a.object_name,
                "Classification": a.classification,
                "Policy": a.policy,
                "Risk Score": a.risk_score,
                "Severity": a.severity.value,
                "Detected Issue": a.detected_issue,
                "Remediation": a.remediation,
            }
            for a in assessments
        ]
    )
    styled_risk = risk_df.style.map(style_cell, subset=["Severity"])
    st.dataframe(styled_risk, width="stretch", hide_index=True)

    st.markdown("#### Detailed Findings & Explanations")
    for assessment in assessments:
        with st.expander(
            f"[{assessment.severity.value}] {assessment.object_name} — "
            f"Risk Score: {assessment.risk_score}/100 ({assessment.detected_issue})"
        ):
            st.markdown(f"- **Classification:** `{assessment.classification}`")
            st.markdown(f"- **Policy:** `{assessment.policy}`")
            st.markdown(
                f"- **Allowed Roles:** `{', '.join(assessment.allowed_roles) or 'None'}`"
            )
            st.markdown(f"- **Explanation:** {assessment.explanation}")
            st.markdown(f"- **Remediation Recommendation:** {assessment.remediation}")


# ---------------------------------------------------------------------------
# 7. Audit Logs Page
# ---------------------------------------------------------------------------
def render_audit_logs(logger: AuditLogger, theme: str) -> None:
    st.subheader("Access Attempt Audit Logs")
    st.caption(
        "Local audit trail stored in `data/audit_logs.json` recording all simulated requests."
    )

    style_cell = make_cell_styler(theme)
    metrics = logger.get_metrics()
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Requests", metrics["total_requests"])
    c2.metric("Allowed Requests", metrics["allowed_requests"])
    c3.metric("Denied Requests", metrics["denied_requests"])
    c4.metric("Unauthorized Attempts", metrics["unauthorized_attempts"])

    f1, f2, f3 = st.columns(3)
    with f1:
        role_filter = st.selectbox("Filter by Role", ["All"] + [r.value for r in ALL_ROLES])
    with f2:
        action_filter = st.selectbox(
            "Filter by Action", ["All"] + [a.value for a in ALL_ACTIONS]
        )
    with f3:
        decision_filter = st.selectbox("Filter by Decision", ["All", "ALLOW", "DENY"])

    filtered_df = logger.filter_logs(
        role=role_filter,
        action=action_filter,
        decision=decision_filter,
    )

    if filtered_df.empty:
        st.info("No audit log records match the current filter.")
    else:
        styled_logs = filtered_df.style.map(style_cell, subset=["Decision"])
        st.dataframe(styled_logs, width="stretch", hide_index=True)

        b1, b2 = st.columns(2)
        with b1:
            st.download_button(
                "Download Audit Logs (CSV)",
                data=filtered_df.to_csv(index=False).encode("utf-8"),
                file_name="cloud_sentry_audit_logs.csv",
                mime="text/csv",
                width="stretch",
            )
        with b2:
            if st.button("Clear Audit Logs", width="stretch"):
                logger.clear_logs()
                st.success("Audit logs cleared.")
                st.rerun()


# ---------------------------------------------------------------------------
# 8. Security Tests Page (Dynamic Role Mapping + Custom Test Runner)
# ---------------------------------------------------------------------------
def render_security_tests(
    users: list[User],
    objects: list[StorageObject],
    theme: str,
) -> None:
    st.subheader("Automated & Custom Security Verification Tests")
    st.caption(
        "Compares expected access decisions against actual `check_access()` results "
        "using your live users (`data/users.json`) and objects (`data/objects.json`)."
    )

    style_cell = make_cell_styler(theme)
    objs_by_name = {o.name: o for o in objects}

    # Dynamically pick an active user for each role (works with custom users!)
    user_for_role: dict[Role, User] = {}
    for role in ALL_ROLES:
        matching = [u for u in users if u.role == role]
        if matching:
            user_for_role[role] = matching[0]

    # --- Section 1: Custom Interactive Test Builder ---
    st.markdown("#### 1. Custom Security Test Builder (Test Any User & Object)")
    if "custom_test_results" not in st.session_state:
        st.session_state["custom_test_results"] = []

    if users and objects:
        u_map = {f"{u.name} ({u.role.value})": u for u in users}
        o_map = {f"{o.name} [{o.policy.value}]": o for o in objects}
        tc1, tc2, tc3, tc4 = st.columns([2, 2, 1, 1])
        with tc1:
            t_user_lbl = st.selectbox("Test User", list(u_map.keys()), key="ct_user")
        with tc2:
            t_obj_lbl = st.selectbox("Test Object", list(o_map.keys()), key="ct_obj")
        with tc3:
            t_action_str = st.selectbox(
                "Action", [a.value for a in ALL_ACTIONS], key="ct_action"
            )
        with tc4:
            t_expected_str = st.selectbox(
                "Expected", ["ALLOW", "DENY"], key="ct_expected"
            )

        b_run, b_clear = st.columns([3, 1])
        with b_run:
            if st.button("Run Custom Test Case", type="primary", width="stretch"):
                t_user = u_map[t_user_lbl]
                t_obj = o_map[t_obj_lbl]
                t_action = Action(t_action_str)
                expected_bool = t_expected_str == "ALLOW"
                actual = check_access(t_user, t_obj, t_action)
                status = "PASS" if actual.allowed == expected_bool else "FAIL"
                st.session_state["custom_test_results"].insert(
                    0,
                    {
                        "Test ID": f"CT-{len(st.session_state['custom_test_results']) + 1:02d}",
                        "User": actual.user,
                        "Role": actual.role,
                        "Cloud Object": actual.object,
                        "Action": actual.action,
                        "Expected": t_expected_str,
                        "Actual": actual.decision,
                        "Status": status,
                        "Reason": actual.reason,
                    },
                )
        with b_clear:
            if st.button("Clear Custom Tests", width="stretch"):
                st.session_state["custom_test_results"] = []
                st.rerun()

        if st.session_state["custom_test_results"]:
            custom_df = pd.DataFrame(st.session_state["custom_test_results"])
            styled_custom = custom_df.style.map(
                style_cell, subset=["Expected", "Actual", "Status"]
            )
            st.dataframe(styled_custom, width="stretch", hide_index=True)

    st.divider()

    # --- Section 2: Automated Role-Based Core Verification ---
    st.markdown("#### 2. Automated Core Role Verification (Expected vs. Actual)")
    core_specs = [
        ("TC-01", Role.ADMIN, "database_backup.zip", Action.READ, True),
        ("TC-02", Role.GUEST, "database_backup.zip", Action.READ, False),
        ("TC-03", Role.GUEST, "public_notice.pdf", Action.READ, True),
        ("TC-04", Role.EMPLOYEE, "salary_data.xlsx", Action.READ, False),
        ("TC-05", Role.MANAGER, "salary_data.xlsx", Action.READ, True),
        ("TC-06", Role.EMPLOYEE, "company_policy.pdf", Action.READ, True),
        ("TC-07", Role.GUEST, "public_notice.pdf", Action.DELETE, False),
        ("TC-08", Role.ADMIN, "public_notice.pdf", Action.DELETE, True),
        ("TC-09", Role.EMPLOYEE, "public_notice.pdf", Action.WRITE, False),
        ("TC-10", Role.MANAGER, "salary_data.xlsx", Action.WRITE, True),
        ("TC-11", Role.MANAGER, "salary_data.xlsx", Action.DELETE, False),
        ("TC-12", Role.EMPLOYEE, "employee_records.csv", Action.READ, False),
    ]

    core_rows: list[dict[str, str]] = []
    for test_id, role, oname, action, expected_allowed in core_specs:
        if role not in user_for_role or oname not in objs_by_name:
            continue
        actual = check_access(user_for_role[role], objs_by_name[oname], action)
        expected_str = "ALLOW" if expected_allowed else "DENY"
        status = "PASS" if actual.allowed == expected_allowed else "FAIL"
        core_rows.append(
            {
                "Test ID": test_id,
                "User": actual.user,
                "Role": actual.role,
                "Cloud Object": actual.object,
                "Action": actual.action,
                "Expected": expected_str,
                "Actual": actual.decision,
                "Status": status,
                "Reason": actual.reason,
            }
        )

    core_df = pd.DataFrame(core_rows)
    core_pass = int((core_df["Status"] == "PASS").sum()) if not core_df.empty else 0
    core_fail = len(core_df) - core_pass

    matrix_df = verify_matrix_dataframe(users, objects)
    mat_pass = int((matrix_df["Status"] == "PASS").sum()) if not matrix_df.empty else 0
    mat_fail = len(matrix_df) - mat_pass

    total_tests = len(core_df) + len(matrix_df)
    total_pass = core_pass + mat_pass
    total_fail = core_fail + mat_fail

    k1, k2, k3 = st.columns(3)
    k1.metric("Automated Checks", total_tests)
    k2.metric("Passed", total_pass)
    k3.metric("Failed", total_fail)

    if total_tests == 0:
        st.info("Add users/objects or restore default data to run baseline checks.")
    elif total_fail == 0:
        st.success(f"All {total_pass}/{total_tests} automated security checks PASSED.")
    else:
        st.error(
            f"{total_fail} check(s) FAILED — one or more cloud objects currently deviate "
            f"from the expected access-control baseline!"
        )

    if not core_df.empty:
        styled_core = core_df.style.map(
            style_cell, subset=["Expected", "Actual", "Status"]
        )
        st.dataframe(styled_core, width="stretch", hide_index=True)

    st.markdown("#### 3. Expected READ Matrix Verification (All Matrix Objects × All Current Users)")
    if not matrix_df.empty:
        styled_mat = matrix_df.style.map(
            style_cell, subset=["Expected READ", "Actual READ", "Status"]
        )
        st.dataframe(styled_mat, width="stretch", hide_index=True)


# ---------------------------------------------------------------------------
# Main Application Shell
# ---------------------------------------------------------------------------
def main() -> None:
    # Initialize theme & intro animation state
    if "theme_mode" not in st.session_state:
        st.session_state["theme_mode"] = "Dark"

    play_intro = False
    if not st.session_state.get("intro_played", False):
        play_intro = True
        st.session_state["intro_played"] = True

    users = load_users()
    objects = load_objects()
    logger = AuditLogger()

    assessments = analyze_all_objects(objects)
    risk_summary = calculate_overall_risk(assessments)
    security_score = max(0, min(100, 100 - risk_summary["overall_score"]))

    with st.sidebar:
        sidebar_logo = get_logo_svg(size=40, theme=st.session_state["theme_mode"])
        st.markdown(
            f"""
            <div class="cs-sidebar-brand">
                {sidebar_logo}
                <div>
                    <div class="cs-sidebar-brand-title">Cloud Sentry</div>
                    <div class="cs-sidebar-brand-sub">Access &amp; Misconfiguration Lab</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Light / Dark Mode Switch
        is_dark = st.toggle(
            "Dark Mode",
            value=(st.session_state["theme_mode"] == "Dark"),
            key="dark_mode_toggle",
        )
        st.session_state["theme_mode"] = "Dark" if is_dark else "Light"

        st.divider()

        page = st.radio(
            "Navigation",
            [
                "Dashboard",
                "Cloud Objects",
                "Users & Roles",
                "Access Simulator",
                "Access Matrix",
                "Risk Analyzer",
                "Audit Logs",
                "Security Tests",
            ],
        )

        st.divider()
        st.metric("Security Score", f"{security_score} / 100")
        st.caption(
            f"Educational Risk: {risk_summary['overall_score']}/100 ({risk_summary['overall_severity']})"
        )

        if st.button("Restore Default Data", width="stretch"):
            restore_default_data()
            st.success("Restored default users and cloud objects.")
            st.rerun()

    theme = st.session_state["theme_mode"]
    st.markdown(build_theme_css(theme), unsafe_allow_html=True)

    # Trigger cinematic zoom-in intro on first load or Replay click
    if play_intro:
        render_startup_splash(theme)

    header_logo = get_logo_svg(size=48, theme="Dark")
    reveal_cls = "cs-dashboard-reveal" if play_intro else ""
    st.markdown(
        f"""
        <div class="cs-header {reveal_cls}">
            {header_logo}
            <div>
                <h1>Cloud Sentry — Cloud Storage Access Control &amp; Security Simulator</h1>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if page == "Dashboard":
        render_dashboard(users, objects, logger, theme)
    elif page == "Cloud Objects":
        render_cloud_objects(users, objects)
    elif page == "Users & Roles":
        render_users_and_roles(users, objects)
    elif page == "Access Simulator":
        render_access_simulator(users, objects, logger)
    elif page == "Access Matrix":
        render_access_matrix(users, objects, theme)
    elif page == "Risk Analyzer":
        render_risk_analyzer(objects, theme)
    elif page == "Audit Logs":
        render_audit_logs(logger, theme)
    elif page == "Security Tests":
        render_security_tests(users, objects, theme)


if __name__ == "__main__":
    main()
