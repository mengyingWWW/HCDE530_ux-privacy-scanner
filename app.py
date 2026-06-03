"""
UX Privacy Scanner — two-state Zotero-style research library + transcript view.
"""

from __future__ import annotations

import html
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote_plus, unquote

import importlib

import streamlit as st
import streamlit.components.v1 as components

import scanner as _scanner

importlib.reload(_scanner)

if not hasattr(_scanner, "scan_transcript_pii"):
    raise ImportError(
        "scanner.py is missing scan_transcript_pii. Save all files, stop Streamlit (Ctrl+C), "
        "then run: streamlit run app.py"
    )

from scanner import (
    PIIFlag,
    compute_risk_level,
    detect_pii,
    extract_participant,
    extract_session_date,
    redact_text,
    render_highlighted_html,
    render_redacted_html,
    scan_transcript_pii,
    wrap_transcript_iframe_html,
)

SAMPLES_DIR = Path(__file__).parent / "samples"
SAMPLE_FOLDER = "Canvas LMS Usability Study"
SAMPLE_CLUSTER_DIR = SAMPLES_DIR / SAMPLE_FOLDER
SAMPLE_SYNC_VERSION = 7
ROOT_LABEL = "My Research Library"
CHEVRON_EXPANDED = "\u25be"  # ▾
CHEVRON_COLLAPSED = "\u25b8"  # ▸

VIEW_LIBRARY = "library"
VIEW_TRANSCRIPT = "transcript"

HTML_FONT_STYLE = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap');
* { font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important; }
</style>
"""

TRANSCRIPT_HTML_HEIGHT = 600


def _anthropic_api_key() -> str | None:
    key = os.environ.get("ANTHROPIC_API_KEY")
    if key:
        return key
    try:
        return st.secrets["ANTHROPIC_API_KEY"]
    except Exception:
        return None


NAV_SCRIPT = """
<script>
function ppsOpenFile(topic, file) {
  const w = window.top || window.parent;
  const url = new URL(w.location.href);
  url.searchParams.set("open_topic", topic);
  url.searchParams.set("open_file", file);
  w.location.assign(url.toString());
}
function ppsToggleFolder(expandedValue) {
  const w = window.top || window.parent;
  const url = new URL(w.location.href);
  url.searchParams.set("expanded", expandedValue);
  w.location.assign(url.toString());
}
function ppsNav(payload) {
  const w = window.top || window.parent;
  const url = new URL(w.location.href);
  url.searchParams.set("pps_nav", JSON.stringify(payload));
  w.location.assign(url.toString());
}
</script>
"""

CUSTOM_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap');

* {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important;
}

:root {
    --bg-white: #ffffff;
    --bg-sidebar: #f7f7f9;
    --text-body: #1a1a2e;
    --text-body-alt: #374151;
    --text-muted: #6b7280;
    --text-heading: #111827;
    --border: #e2e8f0;
    --gradient-start: #7c3aed;
    --gradient-end: #2563eb;
    --btn-text: #7c3aed;
    --lavender: #ede9fe;
    --search-bg: #f3f4f6;
}

html, body, [class*="css"],
h1, h2, h3, h4, h5, h6, p, span, label, input, button, th, td, div {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important;
    color: var(--text-body);
}

.stApp,
[data-testid="stAppViewContainer"],
.main .block-container {
    background: var(--bg-white) !important;
    color: var(--text-body) !important;
}

.block-container {
    padding-top: 1rem !important;
    padding-bottom: 0rem !important;
    padding-left: 1.25rem !important;
    padding-right: 1.25rem !important;
    max-width: 100% !important;
}

.main .block-container {
    overflow-y: auto !important;
    height: 100vh;
}

.element-container {
    margin-bottom: 0 !important;
}

div[data-testid="stVerticalBlock"] > div {
    gap: 0 !important;
}

[data-testid="stHorizontalBlock"]:has(.layout-row-marker) .element-container {
    margin-bottom: 0 !important;
}

[data-testid="stHorizontalBlock"]:has(.layout-row-marker) > [data-testid="column"]:last-child [data-testid="stVerticalBlock"] {
    gap: 0 !important;
}

#MainMenu, footer, header { visibility: hidden; }

/* ---- Global button system ---- */
.stApp .stButton > button,
.stApp [data-testid="stBaseButton-secondary"] {
    background: var(--bg-white) !important;
    border: 1px solid var(--border) !important;
    box-shadow: none !important;
    color: var(--text-body-alt) !important;
    border-radius: 8px !important;
}

.stApp .stButton > button p,
.stApp .stButton > button span,
.stApp .stButton > button [data-testid="stMarkdownContainer"] p {
    color: var(--text-body-alt) !important;
    -webkit-text-fill-color: var(--text-body-alt) !important;
}

.stApp .stButton > button[kind="primary"],
.stApp .stDownloadButton > button,
.stApp [data-testid="stBaseButton-primary"] {
    background: linear-gradient(135deg, var(--gradient-start), var(--gradient-end)) !important;
    border: none !important;
    color: #ffffff !important;
    font-weight: 600 !important;
}

.stApp .stButton > button[kind="primary"] p,
.stApp .stButton > button[kind="primary"] span,
.stApp .stDownloadButton > button p,
.stApp .stDownloadButton > button span {
    color: #ffffff !important;
    -webkit-text-fill-color: #ffffff !important;
}

.stApp .stButton > button[kind="secondary"],
.stApp [data-testid="stBaseButton-secondary"] {
    background: var(--bg-white) !important;
    border: 1px solid var(--border) !important;
    color: var(--text-body-alt) !important;
}

.btn-text-only .stButton > button,
.btn-text-only .stButton > button p,
.btn-text-only .stButton > button span {
    background: transparent !important;
    border: none !important;
    box-shadow: none !important;
    color: var(--btn-text) !important;
    -webkit-text-fill-color: var(--btn-text) !important;
}

.btn-text-only .stButton > button:hover,
.btn-text-only .stButton > button:hover p {
    background: var(--search-bg) !important;
    color: #6d28d9 !important;
    -webkit-text-fill-color: #6d28d9 !important;
}

/* Upload — primary gradient browse button, light chrome */
.upload-primary [data-testid="stFileUploader"] section,
.upload-primary [data-testid="stFileUploaderDropzone"] {
    background: var(--bg-white) !important;
    border: 1px solid var(--border) !important;
    color: var(--text-body-alt) !important;
}

.upload-primary [data-testid="stFileUploader"] label {
    color: var(--text-muted) !important;
    font-weight: 500 !important;
}

.upload-primary [data-testid="stFileUploader"] small,
.upload-primary [data-testid="stFileUploaderDropzoneInstructions"] {
    color: var(--text-muted) !important;
}

.upload-primary [data-testid="stFileUploader"] button {
    background: linear-gradient(135deg, var(--gradient-start), var(--gradient-end)) !important;
    border: none !important;
    color: #ffffff !important;
    font-weight: 600 !important;
    border-radius: 8px !important;
}

.upload-primary [data-testid="stFileUploader"] button p,
.upload-primary [data-testid="stFileUploader"] button span {
    color: #ffffff !important;
    -webkit-text-fill-color: #ffffff !important;
}

/* Search inputs */
.toolbar-search input,
[data-testid="stHorizontalBlock"]:has(.layout-row-marker)
> [data-testid="column"]:last-child
.element-container:has(.toolbar-row-marker) ~ .element-container
[data-testid="stTextInput"] input,
.sidebar-new-folder-input input,
.folder-rename-row input {
    background: var(--search-bg) !important;
    color: var(--text-body-alt) !important;
    border: 1px solid var(--border) !important;
    border-radius: 8px !important;
}

.toolbar-search input::placeholder,
[data-testid="stHorizontalBlock"]:has(.layout-row-marker)
> [data-testid="column"]:last-child
.element-container:has(.toolbar-row-marker) ~ .element-container
[data-testid="stTextInput"] input::placeholder,
.sidebar-new-folder-input input::placeholder,
.folder-rename-row input::placeholder {
    color: var(--text-muted) !important;
}

/* Fixed 220px left panel */
[data-testid="stHorizontalBlock"]:has(.layout-row-marker) > [data-testid="column"]:first-child {
    width: 220px !important;
    min-width: 220px !important;
    max-width: 220px !important;
    flex: 0 0 220px !important;
    background: var(--bg-sidebar) !important;
    border-radius: 0 !important;
    padding: 0.65rem 0.55rem 0.5rem !important;
    border-right: 1px solid var(--border) !important;
}

[data-testid="stHorizontalBlock"]:has(.layout-row-marker) > [data-testid="column"]:first-child [data-testid="stVerticalBlock"] {
    gap: 0 !important;
    min-height: calc(100vh - 2rem);
}

[data-testid="stHorizontalBlock"]:has(.layout-row-marker) > [data-testid="column"]:last-child {
    background: var(--bg-white) !important;
    padding-left: 1.25rem !important;
}

.left-title {
    font-size: 0.78rem;
    font-weight: 700;
    color: #7c3aed;
    margin: 0 0 6px 0.15rem;
    letter-spacing: -0.01em;
}

.sidebar-actions {
    margin-bottom: 6px !important;
}

.sidebar-actions .stButton > button {
    font-size: 0.72rem !important;
    font-weight: 500 !important;
    min-height: 1.65rem !important;
    padding: 0.28rem 0.45rem !important;
    justify-content: flex-start !important;
    width: 100% !important;
    background: var(--bg-white) !important;
    border: 1px solid var(--border) !important;
    color: var(--text-body-alt) !important;
}

.sidebar-actions .stButton > button p,
.sidebar-actions .stButton > button span {
    color: var(--text-body-alt) !important;
    -webkit-text-fill-color: var(--text-body-alt) !important;
}

.sidebar-actions .stButton > button:hover {
    background: var(--search-bg) !important;
    border-color: var(--border) !important;
}

.upload-primary--toolbar [data-testid="stFileUploader"] {
    margin: 0 !important;
}

.upload-primary--toolbar [data-testid="stFileUploader"] section {
    padding: 0.2rem 0.45rem !important;
    min-height: 2rem !important;
}

.upload-primary--toolbar label {
    display: none !important;
}

.upload-primary--toolbar [data-testid="stFileUploaderDropzoneInstructions"] {
    display: none !important;
}

.upload-primary--toolbar [data-testid="stFileUploader"] button {
    font-size: 0.78rem !important;
    padding: 0.35rem 0.85rem !important;
    min-height: 2rem !important;
    width: 100% !important;
}

.html-file-table-wrap {
    margin: 0;
    padding: 0;
}

.sidebar-tree-html {
    margin: 6px 0 0 0 !important;
}

.sidebar-tree-html .element-container {
    margin: 0 !important;
    padding: 0 !important;
}

[data-testid="stHtml"] {
    margin: 0 !important;
    padding: 0 !important;
}

[data-testid="stHtml"] iframe {
    border: none !important;
    display: block;
}

.library-table-html {
    margin: 0 !important;
    padding: 0 !important;
}

.sidebar-new-folder-input {
    margin: 6px 0 6px 0.15rem !important;
}

.sidebar-new-folder-input input {
    font-size: 0.72rem !important;
    padding: 0.3rem 0.45rem !important;
    min-height: 1.65rem !important;
}

.toolbar-folder-add .stButton > button,
.toolbar-folder-add .stButton > button p,
.toolbar-folder-add .stButton > button span {
    background: linear-gradient(135deg, var(--gradient-start), var(--gradient-end)) !important;
    border: none !important;
    color: #ffffff !important;
    -webkit-text-fill-color: #ffffff !important;
    font-weight: 600 !important;
    font-size: 0.78rem !important;
    min-height: 32px !important;
    height: 32px !important;
    padding: 0 0.75rem !important;
    box-shadow: none !important;
}

.toolbar-folder-add .stButton > button:hover,
.toolbar-folder-add .stButton > button:hover p {
    filter: brightness(1.05);
    color: #ffffff !important;
    -webkit-text-fill-color: #ffffff !important;
}

.add-topic-btn button, .add-topic-btn button p {
    display: none !important;
}

.upload-bottom { display: none !important; }

/* Main library panel */
.main-library-panel {
    display: block;
}

.main-library-panel .element-container {
    margin-bottom: 0 !important;
}

.element-container:has(.folder-title-wrap),
.element-container:has(.folder-heading),
.element-container:has(.folder-rename-row),
.element-container:has(h1.folder-heading),
.element-container:has([data-testid="stMarkdownContainer"] h1.folder-heading) {
    margin-bottom: 0 !important;
    padding-bottom: 0 !important;
}

.element-container:has([data-testid="stHorizontalBlock"] .folder-heading) {
    margin-bottom: 0 !important;
}

.folder-title-wrap {
    margin: 0 !important;
    padding: 0 !important;
}

.folder-title-wrap .folder-heading {
    display: inline;
    margin: 0;
}

.folder-title-row {
    display: flex;
    align-items: center;
    margin: 0;
    padding: 0;
}

.folder-title-row .folder-heading {
    margin: 0;
    padding: 0;
}

.element-container:has(.folder-title-row) {
    margin: 0 !important;
    padding: 0 !important;
}

.inline-edit-pencil {
    margin: 0 !important;
    padding: 0 !important;
}

.inline-edit-pencil .stButton,
[data-testid="stHorizontalBlock"]:has(h1.folder-heading) > [data-testid="column"]:last-child .stButton {
    margin: 0 !important;
    padding: 0 !important;
}

[data-testid="stHorizontalBlock"]:has(h1.folder-heading) > [data-testid="column"]:last-child .stButton > button,
.inline-edit-pencil .stButton > button {
    background: transparent !important;
    border: none !important;
    box-shadow: none !important;
    color: #9ca3af !important;
    -webkit-text-fill-color: #9ca3af !important;
    font-size: 14px !important;
    font-weight: 400 !important;
    padding: 0 0 0 2px !important;
    margin: 0 !important;
    min-height: 0 !important;
    height: auto !important;
    line-height: 1.2 !important;
    width: auto !important;
    min-width: 0 !important;
}

[data-testid="stHorizontalBlock"]:has(h1.folder-heading) > [data-testid="column"]:last-child .stButton > button:hover,
.inline-edit-pencil .stButton > button:hover {
    background: transparent !important;
    color: #7c3aed !important;
    -webkit-text-fill-color: #7c3aed !important;
}

[data-testid="stHorizontalBlock"]:has(h1.folder-heading) > [data-testid="column"]:last-child .stButton > button p,
.inline-edit-pencil .stButton > button p {
    color: inherit !important;
    -webkit-text-fill-color: inherit !important;
    font-size: 14px !important;
}

.folder-rename-row input {
    font-size: 1.15rem !important;
    font-weight: 700 !important;
    padding: 0.25rem 0.5rem !important;
    margin: 0 !important;
}

.element-container:has(.toolbar-row-marker),
.element-container:has(.toolbar-row) {
    margin-top: 0 !important;
    margin-bottom: 0 !important;
    padding: 0 !important;
}

.toolbar-row {
    margin: 0 !important;
    padding: 0 !important;
    min-height: 0 !important;
    max-height: none !important;
    height: auto !important;
}

.element-container:has(.library-table-html) {
    margin-top: 8px !important;
    margin-bottom: 0 !important;
    padding: 0 !important;
}

.toolbar-row [data-testid="stHorizontalBlock"] {
    align-items: center !important;
    margin: 0 !important;
    padding: 0 !important;
    gap: 0.5rem !important;
    min-height: 0 !important;
    height: auto !important;
}

/* Tight stack: folder title → toolbar → table in main panel */
[data-testid="stHorizontalBlock"]:has(.layout-row-marker)
> [data-testid="column"]:last-child [data-testid="stVerticalBlock"] {
    gap: 0 !important;
}

[data-testid="stHorizontalBlock"]:has(.layout-row-marker)
> [data-testid="column"]:last-child
[data-testid="stVerticalBlock"] > [data-testid="stVerticalBlockBorderWrapper"] {
    padding: 0 !important;
    margin: 0 !important;
    background: transparent !important;
    border: none !important;
    box-shadow: none !important;
}

[data-testid="stHorizontalBlock"]:has(.layout-row-marker)
> [data-testid="column"]:last-child .element-container {
    margin-top: 0 !important;
    margin-bottom: 0 !important;
    padding-top: 0 !important;
    padding-bottom: 0 !important;
}

[data-testid="stHorizontalBlock"]:has(.layout-row-marker)
> [data-testid="column"]:last-child
[data-testid="stHorizontalBlock"]:has(h1.folder-heading) {
    margin: 0 !important;
    padding: 0 !important;
    min-height: 0 !important;
    align-items: center !important;
}

[data-testid="stHorizontalBlock"]:has(.layout-row-marker)
> [data-testid="column"]:last-child
.element-container:has(h1.folder-heading) {
    margin-bottom: 0 !important;
}

[data-testid="stHorizontalBlock"]:has(.layout-row-marker)
> [data-testid="column"]:last-child
.element-container:has(.inline-edit-pencil) {
    margin-bottom: 0 !important;
}

.toolbar-row-marker {
    display: block;
    height: 0;
    margin: 0;
    padding: 0;
    line-height: 0;
    overflow: hidden;
}

[data-testid="stHorizontalBlock"]:has(.layout-row-marker)
> [data-testid="column"]:last-child
.element-container:has([data-testid="stHorizontalBlock"] h1.folder-heading) {
    margin-bottom: 0 !important;
    padding-bottom: 0 !important;
}

[data-testid="stHorizontalBlock"]:has(.layout-row-marker)
> [data-testid="column"]:last-child
.element-container:has(.toolbar-row-marker) {
    margin-top: 6px !important;
    margin-bottom: 0 !important;
    min-height: 0 !important;
    height: 0 !important;
    line-height: 0 !important;
}

[data-testid="stHorizontalBlock"]:has(.layout-row-marker)
> [data-testid="column"]:last-child
.element-container:has(.toolbar-row-marker) + .element-container {
    margin-top: 0 !important;
    padding-top: 0 !important;
}

[data-testid="stHorizontalBlock"]:has(.layout-row-marker)
> [data-testid="column"]:last-child
.element-container:has(.toolbar-row-marker) + .element-container
[data-testid="stHorizontalBlock"] {
    margin-top: 0 !important;
    margin-bottom: 0 !important;
    padding: 0 !important;
    min-height: 0 !important;
}

[data-testid="stMarkdownContainer"]:has(h1.folder-heading) {
    margin: 0 !important;
    padding: 0 !important;
}

.toolbar-row .element-container,
.toolbar-row [data-testid="stVerticalBlock"] {
    margin: 0 !important;
    padding: 0 !important;
    gap: 0 !important;
}

.toolbar-search input,
[data-testid="stHorizontalBlock"]:has(.layout-row-marker)
> [data-testid="column"]:last-child
.element-container:has(.toolbar-row-marker) ~ .element-container
[data-testid="stTextInput"] input {
    font-size: 0.8rem !important;
    min-height: 32px !important;
    height: 32px !important;
    padding: 0 0.65rem !important;
    margin: 0 !important;
}

.toolbar-search .stTextInput,
.toolbar-search [data-testid="stTextInputRootElement"],
[data-testid="stHorizontalBlock"]:has(.layout-row-marker)
> [data-testid="column"]:last-child
.element-container:has(.toolbar-row-marker) ~ .element-container
.stTextInput,
[data-testid="stHorizontalBlock"]:has(.layout-row-marker)
> [data-testid="column"]:last-child
.element-container:has(.toolbar-row-marker) ~ .element-container
[data-testid="stTextInputRootElement"] {
    margin: 0 !important;
}

.folder-heading,
.folder-title-wrap h1.folder-heading,
[data-testid="stMarkdownContainer"] h1.folder-heading {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important;
    font-size: 1.35rem;
    font-weight: 600;
    color: var(--text-heading) !important;
    -webkit-text-fill-color: var(--text-heading) !important;
    opacity: 1 !important;
    margin: 0;
    padding: 0;
    letter-spacing: -0.02em;
    line-height: 1.2;
}

.file-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.84rem;
}

.file-table thead th {
    text-align: left;
    font-size: 0.68rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-muted);
    padding: 0.55rem 0.75rem;
    border-bottom: 1px solid var(--border);
    background: var(--search-bg);
}

.file-table tbody tr {
    border-bottom: 1px solid #f0f0f2;
    transition: background 0.12s ease;
}

.file-table tbody tr:hover {
    background: #f9fafb;
}

.file-table td {
    padding: 0.65rem 0.75rem;
    color: var(--text-body);
    vertical-align: middle;
}

.file-name-cell { font-weight: 500; }

.risk-badge {
    display: inline-block;
    font-size: 0.68rem;
    font-weight: 600;
    padding: 0.15rem 0.5rem;
    border-radius: 999px;
}

.risk-high { background: #fee2e2; color: #dc2626; }
.risk-medium { background: #fef3c7; color: #d97706; }
.risk-low { background: #d1fae5; color: #059669; }

/* Transcript view */
.transcript-top {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    margin-bottom: 0.85rem;
    padding-bottom: 0.65rem;
    border-bottom: 1px solid var(--border);
}

.breadcrumb {
    font-size: 0.82rem;
    color: var(--text-muted);
}

.breadcrumb strong {
    color: var(--text-body);
    font-weight: 600;
}

.breadcrumb-sep { color: #d1d5db; margin: 0 0.35rem; }

.col-title {
    font-size: 0.92rem;
    font-weight: 700;
    color: var(--text-heading) !important;
    margin: 0;
}

.transcript-compare {
    margin-top: 0.35rem;
}

.transcript-compare [data-testid="column"] {
    min-width: 0 !important;
}

.transcript-col-toolbar {
    margin-bottom: 0.5rem !important;
    padding-bottom: 0.5rem !important;
    border-bottom: 1px solid var(--border) !important;
}

.transcript-compare,
.transcript-compare [data-testid="stMarkdownContainer"],
.transcript-compare [data-testid="stMarkdownContainer"] p,
.transcript-compare [data-testid="stMarkdownContainer"] div,
.transcript-compare [data-testid="stMarkdownContainer"] span,
.transcript-scroll,
.transcript-scroll * {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif !important;
}

.transcript-scroll mark,
.transcript-scroll .pii-wrapper {
    background: #ede9fe !important;
    background-color: #ede9fe !important;
    background-image: none !important;
    color: #1a1a2e !important;
    border-bottom: 2px solid #7c3aed !important;
}

.transcript-scroll {
    overflow-y: auto !important;
    max-height: calc(100vh - 160px) !important;
    padding: 1rem 1.15rem !important;
    font-size: 0.86rem !important;
    line-height: 1.72 !important;
    color: #1a1a2e !important;
    border: 1px solid var(--border) !important;
    border-radius: 8px !important;
    background: #ffffff !important;
}

.transcript-scroll.redacted-scroll {
    background: #fafafa !important;
}

.transcript-scroll .redacted-token {
    color: #7c3aed !important;
    font-weight: 700;
}

.back-btn .stButton > button {
    font-weight: 600 !important;
    padding: 0.2rem 0.4rem !important;
    min-height: 1.5rem !important;
}

.empty-library {
    padding: 3rem 2rem;
    text-align: center;
    color: var(--text-muted);
    background: var(--search-bg);
    border-radius: 12px;
    border: 1px dashed var(--border);
}

.empty-library h3 {
    color: var(--text-heading) !important;
    margin-bottom: 0.5rem;
}

.empty-library p {
    color: var(--text-muted) !important;
}

/* Streamlit widgets — no dark fills */
.stApp [data-testid="stFileUploaderDropzone"],
.stApp [data-testid="stFileUploader"] > div {
    background: var(--bg-white) !important;
    color: var(--text-body-alt) !important;
}

.toolbar-search [data-testid="stTextInputRootElement"],
.toolbar-search [data-baseweb="input"],
[data-testid="stHorizontalBlock"]:has(.layout-row-marker)
> [data-testid="column"]:last-child
.element-container:has(.toolbar-row-marker) ~ .element-container
[data-testid="stTextInputRootElement"],
[data-testid="stHorizontalBlock"]:has(.layout-row-marker)
> [data-testid="column"]:last-child
.element-container:has(.toolbar-row-marker) ~ .element-container
[data-baseweb="input"] {
    background: var(--search-bg) !important;
    border: 1px solid var(--border) !important;
}

/* Streamlit alerts — light only */
.stAlert,
[data-testid="stNotification"] {
    background: var(--search-bg) !important;
    color: var(--text-body-alt) !important;
}
</style>
"""

@dataclass
class SessionRecord:
    text: str
    flags: list[PIIFlag]
    risk: str
    participant: str
    session_date: str
    scan_mode: str = ""


def _init_state() -> None:
    defaults = {
        "view": VIEW_LIBRARY,
        "library": {},
        "selected_topic": SAMPLE_FOLDER,
        "selected_file": None,
        "upload_topic": SAMPLE_FOLDER,
        "search_query": "",
        "root_expanded": True,
        "expanded_folder": SAMPLE_FOLDER,
        "show_new_folder_input": False,
        "editing_folder": False,
        "rename_folder_value": "",
    }
    for key, val in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = val

    if not st.session_state.get("library_bootstrapped"):
        _load_sample_sessions()
        st.session_state.library_bootstrapped = True
    _sync_library_from_expanded_folder()
    if st.session_state.library and not st.session_state.get("metadata_refreshed_v4"):
        _rebuild_all_records()
        st.session_state.metadata_refreshed_v4 = True
    if st.session_state.get("samples_sync_version", 0) < SAMPLE_SYNC_VERSION:
        if st.session_state.library:
            _sync_sample_sessions()
        st.session_state.samples_sync_version = SAMPLE_SYNC_VERSION


def _ensure_topic(name: str) -> None:
    if name not in st.session_state.library:
        st.session_state.library[name] = {"expanded": False, "files": {}}


def _display_participant(name: str) -> str:
    """Single-line participant label for the library table."""
    clean = " ".join(name.split()).strip()
    if clean.lower().endswith("interviewer"):
        clean = clean[: -len("interviewer")].strip()
    return clean or "—"


def _build_record(text: str) -> SessionRecord:
    flags, scan_mode = scan_transcript_pii(text, api_key=_anthropic_api_key())
    return SessionRecord(
        text=text,
        flags=flags,
        risk=compute_risk_level(len(flags)),
        participant=_display_participant(extract_participant(text, flags)),
        session_date=extract_session_date(text),
        scan_mode=scan_mode,
    )


def _rescan_selected_record() -> None:
    """Re-run PII detection on the open transcript file."""
    topic = st.session_state.selected_topic
    fname = st.session_state.selected_file
    if not topic or not fname:
        return
    files = st.session_state.library.get(topic, {}).get("files", {})
    record = files.get(fname)
    if not record:
        return
    files[fname] = _build_record(record.text)


def _rebuild_all_records() -> None:
    """Refresh parsed metadata (participant, date, flags) from stored text."""
    for data in st.session_state.library.values():
        files = data.get("files", {})
        for fname, rec in list(files.items()):
            files[fname] = _build_record(rec.text)


def _add_file(topic: str, filename: str, text: str) -> None:
    _ensure_topic(topic)
    st.session_state.library[topic]["files"][filename] = _build_record(text)
    st.session_state.expanded_folder = topic
    _sync_library_from_expanded_folder()
    st.session_state.selected_topic = topic
    st.session_state.upload_topic = topic


def _open_transcript(topic: str, filename: str) -> None:
    st.session_state.view = VIEW_TRANSCRIPT
    st.session_state.selected_topic = topic
    st.session_state.selected_file = filename
    st.session_state.upload_topic = topic
    st.session_state.expanded_folder = topic
    _sync_library_from_expanded_folder()


def _back_to_library() -> None:
    st.session_state.view = VIEW_LIBRARY


def _selected_record() -> SessionRecord | None:
    topic = st.session_state.selected_topic
    fname = st.session_state.selected_file
    if not topic or not fname:
        return None
    return st.session_state.library.get(topic, {}).get("files", {}).get(fname)


def _rename_topic(old_name: str, new_name: str) -> bool:
    new_name = new_name.strip()
    if not new_name or new_name == old_name:
        return False
    if new_name in st.session_state.library:
        st.toast("A folder with that name already exists.", icon="⚠️")
        return False
    st.session_state.library[new_name] = st.session_state.library.pop(old_name)
    if st.session_state.selected_topic == old_name:
        st.session_state.selected_topic = new_name
    if st.session_state.upload_topic == old_name:
        st.session_state.upload_topic = new_name
    return True


def _upload_files_to_topic(topic: str, uploaded) -> None:
    if not topic or topic not in st.session_state.library:
        st.toast("Select a topic folder first.", icon="📁")
        return
    for file in uploaded:
        _add_file(topic, file.name, file.read().decode("utf-8"))
    st.rerun()


def _tree_slug(name: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "_", name.strip())
    return (slug[:72] or "item").strip("_")


def _expanded_session_key(folder_name: str) -> str:
    return f"expanded_{_tree_slug(folder_name)}"


def _expanded_folder_name() -> str | None:
    """Currently expanded tree folder (from session state / ?expanded= query param)."""
    ef = st.session_state.get("expanded_folder")
    return ef if ef else None


def _is_folder_expanded(folder_name: str) -> bool:
    ef = _expanded_folder_name()
    if folder_name == ROOT_LABEL:
        return ef is not None
    return ef == folder_name


def _set_folder_expanded(folder_name: str, value: bool) -> None:
    """Sync legacy library flags when expanded_folder is updated elsewhere."""
    st.session_state[_expanded_session_key(folder_name)] = value
    if folder_name == ROOT_LABEL:
        st.session_state.root_expanded = value
    elif folder_name in st.session_state.library:
        st.session_state.library[folder_name]["expanded"] = value


def _sync_library_from_expanded_folder() -> None:
    """Mirror expanded_folder into root_expanded and per-topic library flags."""
    ef = _expanded_folder_name()
    st.session_state.root_expanded = ef is not None
    for topic in st.session_state.library:
        st.session_state.library[topic]["expanded"] = ef == topic
        st.session_state[_expanded_session_key(topic)] = ef == topic
    st.session_state[_expanded_session_key(ROOT_LABEL)] = ef is not None


def _process_expanded_query_param() -> bool:
    """Apply ?expanded= folder toggle from HTML sidebar clicks."""
    params = st.query_params
    if "expanded" not in params:
        return False
    raw = params.get("expanded")
    if isinstance(raw, list):
        raw = raw[0]
    if raw == "" or raw is None:
        st.session_state.expanded_folder = None
    else:
        folder = unquote(str(raw).replace("+", " "))
        st.session_state.expanded_folder = folder
        if folder in st.session_state.library:
            st.session_state.selected_topic = folder
            st.session_state.upload_topic = folder
            st.session_state.view = VIEW_LIBRARY
            st.session_state.editing_folder = False
        elif folder == ROOT_LABEL:
            st.session_state.selected_topic = None
            st.session_state.view = VIEW_LIBRARY
            st.session_state.editing_folder = False
    _sync_library_from_expanded_folder()
    del st.query_params["expanded"]
    return True


def _file_open_href(topic: str, fname: str) -> str:
    """Query-string link for opening a transcript (main-page HTML table)."""
    return f"?open_topic={quote_plus(topic)}&open_file={quote_plus(fname)}"


def _file_open_onclick(topic: str, fname: str) -> str:
    """Open transcript via query params (iframe sidebar tree)."""
    topic_js = json.dumps(topic)
    file_js = json.dumps(fname)
    return f"onclick='ppsOpenFile({topic_js},{file_js})'"


def _process_open_file_query_param() -> bool:
    """Open a session file when sidebar/table sets open_topic & open_file."""
    params = st.query_params
    if "open_topic" not in params or "open_file" not in params:
        return False
    raw_topic = params.get("open_topic")
    raw_file = params.get("open_file")
    if isinstance(raw_topic, list):
        raw_topic = raw_topic[0]
    if isinstance(raw_file, list):
        raw_file = raw_file[0]
    topic = unquote(str(raw_topic).replace("+", " "))
    fname = unquote(str(raw_file).replace("+", " "))
    files = st.session_state.library.get(topic, {}).get("files", {})
    if fname in files:
        _open_transcript(topic, fname)
    else:
        st.toast(f"Could not open “{fname}”. Try refreshing the app.", icon="⚠️")
    if "open_topic" in st.query_params:
        del st.query_params["open_topic"]
    if "open_file" in st.query_params:
        del st.query_params["open_file"]
    return True


def _tree_folder_onclick(folder_name: str, is_open: bool) -> str:
    """Navigate parent frame: expand folder or collapse with empty expanded."""
    expanded_val = "" if is_open else folder_name
    return f"onclick='ppsToggleFolder({json.dumps(expanded_val)})'"


def _folder_chevron(expanded: bool) -> str:
    return CHEVRON_EXPANDED if expanded else CHEVRON_COLLAPSED


def _tree_row_hover_attrs(default_bg: str) -> str:
    return (
        f"onmouseover=\"this.style.background='#f5f3ff'\" "
        f"onmouseout=\"this.style.background='{default_bg}'\""
    )


def _build_sidebar_tree_html() -> str:
    """Single HTML block for the sidebar tree (Unicode chevrons, query-param nav)."""
    library: dict = st.session_state.library
    root_expanded = _is_folder_expanded(ROOT_LABEL)
    selected_topic = st.session_state.selected_topic
    selected_file = st.session_state.selected_file
    in_library = st.session_state.view == VIEW_LIBRARY
    in_transcript = st.session_state.view == VIEW_TRANSCRIPT

    root_hover = _tree_row_hover_attrs("transparent")
    parts = [
        HTML_FONT_STYLE,
        NAV_SCRIPT,
        '<div class="sidebar-tree-html" style="font-family: Inter, sans-serif; font-size: 13px;">',
        f'<div {_tree_folder_onclick(ROOT_LABEL, root_expanded)} '
        'style="padding: 4px 8px; color: #6b7280; cursor: pointer; border-radius: 6px;" '
        f"{root_hover}>"
        f"{_folder_chevron(root_expanded)} {html.escape(ROOT_LABEL)}</div>",
    ]

    if root_expanded:
        for topic in sorted(library.keys()):
            topic_expanded = _is_folder_expanded(topic)
            folder_active = selected_topic == topic and in_library
            topic_bg = "#ede9fe" if folder_active else "transparent"
            topic_hover = _tree_row_hover_attrs(topic_bg)
            parts.append(
                f'<div {_tree_folder_onclick(topic, topic_expanded)} '
                "style=\"padding: 4px 8px 4px 20px; border-radius: 6px; cursor: pointer; "
                f"color: #374151; background: {topic_bg};\" {topic_hover}>"
                f"{_folder_chevron(topic_expanded)} {html.escape(topic)}</div>"
            )
            if topic_expanded:
                for fname in sorted(library[topic].get("files", {}).keys()):
                    file_active = (
                        selected_topic == topic
                        and selected_file == fname
                        and in_transcript
                    )
                    display = fname if len(fname) <= 34 else fname[:31] + "…"
                    file_bg = "#ede9fe" if file_active else "transparent"
                    file_hover = _tree_row_hover_attrs(file_bg)
                    parts.append(
                        f'<div {_file_open_onclick(topic, fname)} '
                        "style=\"padding: 3px 8px 3px 32px; cursor: pointer; color: #374151; "
                        f"border-radius: 6px; background: {file_bg};\" {file_hover}>"
                        f"{html.escape(display)}</div>"
                    )

    parts.append("</div>")
    return "".join(parts)


def _js_nav_attr(payload: dict) -> str:
    """onclick handler that navigates via query param (read on next Streamlit run)."""
    payload_json = json.dumps(payload, separators=(",", ":"))
    payload_json = payload_json.replace("'", "&#39;")
    return f"onclick='ppsNav({payload_json})'"


def _process_nav_query_params() -> bool:
    """Apply navigation from HTML onclick (pps_nav query param). Returns True if handled."""
    raw = st.query_params.get("pps_nav")
    if not raw:
        return False
    if isinstance(raw, list):
        raw = raw[0]
    try:
        payload = json.loads(unquote(raw))
    except (json.JSONDecodeError, TypeError):
        del st.query_params["pps_nav"]
        return False

    action = payload.get("a")
    topic = payload.get("topic")
    file = payload.get("file")

    if action == "open_file" and topic and file:
        _open_transcript(topic, file)
    elif action == "edit_folder" and topic:
        st.session_state.editing_folder = True
        st.session_state.rename_folder_value = topic
        st.session_state.selected_topic = topic
        st.session_state.upload_topic = topic
        st.session_state.view = VIEW_LIBRARY
    elif action == "back_library":
        _back_to_library()

    del st.query_params["pps_nav"]
    return True


def _sidebar_tree_height() -> int:
    """Iframe height for the HTML sidebar tree."""
    library = st.session_state.library
    height = 36
    if _is_folder_expanded(ROOT_LABEL):
        height += 32 * max(1, len(library))
        for topic, data in library.items():
            if _is_folder_expanded(topic):
                height += 28 * max(1, len(data.get("files", {})))
    return min(520, max(72, height + 12))


def _render_sidebar_tree() -> None:
    """Sidebar tree as HTML in an iframe so NAV_SCRIPT and onclick handlers run."""
    tree_html = _build_sidebar_tree_html()
    tree_h = _sidebar_tree_height()
    components.html(tree_html, height=tree_h, scrolling=False)


def _build_file_table_html(
    topic: str, filtered: list[tuple[str, SessionRecord]]
) -> str:
    row_hover = (
        "onmouseover=\"this.style.background='#f5f3ff'\" "
        "onmouseout=\"this.style.background='transparent'\""
    )
    cell = (
        'style="padding:0 0.65rem;border:none;border-bottom:1px solid #f0f0f2;'
        'font-size:0.84rem;font-weight:400;color:#1a1a2e;vertical-align:middle;'
        'line-height:1.2;"'
    )
    cell_meta = cell.replace("color:#1a1a2e", "color:#6b7280")

    rows: list[str] = []
    for fname, record in filtered:
        href = _file_open_href(topic, fname)
        rows.append(
            f"<tr style=\"height:44px;cursor:pointer;\" {row_hover} "
            f"onclick=\"location.href='{href}'\">"
            f'<td width="40%" {cell}>'
            f'<a href="{href}" style="color:inherit;text-decoration:none;display:block;">'
            f"{html.escape(fname)}</a></td>"
            f"<td {cell}>{html.escape(record.participant)}</td>"
            f'<td width="14%" {cell_meta}>{html.escape(record.session_date)}</td>'
            f'<td width="14%" {cell}>{_risk_badge_html(record.risk)}</td>'
            f'<td width="8%" {cell_meta} style="text-align:right;padding-right:0.65rem;">'
            f"{len(record.flags)}</td>"
            "</tr>"
        )

    th = (
        'style="padding:0 0.65rem;height:44px;border:none;'
        'border-bottom:1px solid #e2e8f0;background:#f3f4f6;'
        'font-size:0.67rem;font-weight:600;text-transform:uppercase;'
        'letter-spacing:0.05em;color:#6b7280;text-align:left;vertical-align:middle;"'
    )
    return (
        HTML_FONT_STYLE
        + '<div class="html-file-table-wrap">'
        + '<table style="width:100%;border-collapse:collapse;margin:0;padding:0;">'
        + "<thead><tr>"
        f'<th width="40%" {th}>File Name</th>'
        f"<th {th}>Participant</th>"
        f'<th width="14%" {th}>Date</th>'
        f'<th width="14%" {th}>Risk Level</th>'
        f'<th width="8%" {th} style="text-align:right;">Flags</th>'
        + "</tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></div>"
    )


def _create_folder_from_input(name: str) -> None:
    topic_name = name.strip()
    if not topic_name:
        return
    _ensure_topic(topic_name)
    st.session_state.selected_topic = topic_name
    st.session_state.upload_topic = topic_name
    st.session_state.expanded_folder = topic_name
    _sync_library_from_expanded_folder()
    st.session_state.show_new_folder_input = False
    st.session_state.rename_folder_value = ""
    st.rerun()


def _sync_sample_sessions() -> None:
    """Sync sample .txt files from disk (add, update, remove stale session_* names)."""
    if not SAMPLE_CLUSTER_DIR.is_dir():
        return
    _ensure_topic(SAMPLE_FOLDER)
    files = st.session_state.library[SAMPLE_FOLDER]["files"]
    on_disk = {p.name: p for p in SAMPLE_CLUSTER_DIR.glob("*.txt")}
    for fname in list(files.keys()):
        if fname.startswith("session_") and fname not in on_disk:
            del files[fname]
            if st.session_state.selected_file == fname:
                st.session_state.selected_file = None
    for path in sorted(on_disk.values()):
        files[path.name] = _build_record(path.read_text(encoding="utf-8"))


def _load_sample_sessions() -> None:
    if not SAMPLE_CLUSTER_DIR.is_dir():
        return
    for path in sorted(SAMPLE_CLUSTER_DIR.glob("*.txt")):
        _add_file(SAMPLE_FOLDER, path.name, path.read_text(encoding="utf-8"))
    st.session_state.selected_topic = SAMPLE_FOLDER
    st.session_state.upload_topic = SAMPLE_FOLDER
    st.session_state.expanded_folder = SAMPLE_FOLDER
    _sync_library_from_expanded_folder()


def _risk_badge_html(risk: str) -> str:
    css = risk.lower()
    return f'<span class="risk-badge risk-{css}">{risk}</span>'


def _pick_files_for_topic(topic: str | None, uploader_key: str) -> None:
    """Shared file picker body for sidebar and folder upload dialogs."""
    if not topic or topic not in st.session_state.library:
        st.warning("Select a folder in the sidebar tree first.")
        return
    uploaded = st.file_uploader(
        "Choose .txt files",
        type=["txt"],
        accept_multiple_files=True,
        label_visibility="collapsed",
        key=uploader_key,
    )
    if uploaded:
        _upload_files_to_topic(topic, uploaded)


@st.dialog("New File")
def _sidebar_new_file_dialog() -> None:
    """Sidebar: add a file to whichever folder is selected in the tree."""
    topic = st.session_state.selected_topic
    st.caption(
        "Uploads into the folder currently selected in the sidebar tree."
    )
    _pick_files_for_topic(topic, "dialog_sidebar_new_file")


@st.dialog("Add File to this folder")
def _folder_new_file_dialog() -> None:
    """Main panel: add a file to the folder open in the library view."""
    topic = st.session_state.selected_topic
    if topic:
        st.caption(f"Uploads into **{topic}**.")
    _pick_files_for_topic(topic, "dialog_folder_new_file")


def _render_left_panel() -> None:
    st.markdown('<p class="left-title">UX Privacy Scanner</p>', unsafe_allow_html=True)

    st.markdown('<div class="sidebar-actions">', unsafe_allow_html=True)
    if st.button(
        "New Folder",
        key="sb_new_folder",
        use_container_width=True,
        type="secondary",
    ):
        st.session_state.show_new_folder_input = True
        st.rerun()

    if st.button(
        "New File",
        key="sb_new_file",
        use_container_width=True,
        type="secondary",
    ):
        if not st.session_state.selected_topic:
            st.toast("Select a folder in the tree first.", icon="📁")
        else:
            _sidebar_new_file_dialog()

    st.markdown("</div>", unsafe_allow_html=True)

    if st.session_state.show_new_folder_input:
        st.markdown('<div class="sidebar-new-folder-input">', unsafe_allow_html=True)
        folder_name = st.text_input(
            "New folder name",
            placeholder="Folder name…",
            label_visibility="collapsed",
            key="sidebar_new_folder_name",
        )
        if st.button("Create", key="sidebar_create_folder", type="secondary"):
            _create_folder_from_input(folder_name)
        st.markdown("</div>", unsafe_allow_html=True)

    _render_sidebar_tree()


def _filter_files(files: dict[str, SessionRecord]) -> list[tuple[str, SessionRecord]]:
    q = st.session_state.search_query.strip().lower()
    items = sorted(files.items())
    if not q:
        return items
    return [
        (fname, rec)
        for fname, rec in items
        if q in fname.lower()
        or q in rec.participant.lower()
        or q in rec.session_date.lower()
    ]


def _render_folder_heading(topic: str) -> None:
    """Folder title with inline pencil; inline rename when editing."""
    editing = st.session_state.editing_folder and st.session_state.selected_topic == topic

    if editing:
        st.markdown('<div class="folder-title-wrap folder-rename-row">', unsafe_allow_html=True)
        r1, r2, r3 = st.columns([8, 1, 1], gap="small")
        with r1:
            new_name = st.text_input(
                "Folder name",
                value=topic,
                label_visibility="collapsed",
                key="rename_folder_input",
            )
        with r2:
            if st.button("Save", key="confirm_rename", type="secondary"):
                if _rename_topic(topic, new_name):
                    st.session_state.editing_folder = False
                    st.session_state.rename_folder_value = ""
                    st.rerun()
        with r3:
            if st.button("Cancel", key="cancel_rename", type="secondary"):
                st.session_state.editing_folder = False
                st.session_state.rename_folder_value = ""
                st.rerun()
        st.markdown("</div>", unsafe_allow_html=True)
        return

    title_col, pencil_col = st.columns([1, 0.045], gap="small", vertical_alignment="center")
    with title_col:
        st.markdown(
            f'<h1 class="folder-heading folder-title-row">{html.escape(topic)}</h1>',
            unsafe_allow_html=True,
        )
    with pencil_col:
        if st.button("✎", key="edit_folder_pencil", help="Rename folder"):
            st.session_state.editing_folder = True
            st.session_state.rename_folder_value = topic
            st.rerun()


def _render_file_table(topic: str, files: dict[str, SessionRecord]) -> None:
    filtered = _filter_files(files)
    if not filtered:
        st.markdown(
            '<div class="empty-library"><p>No files in this folder yet. '
            "Use <strong>Add File to this folder</strong> above or "
            "<strong>New File</strong> in the sidebar.</p></div>",
            unsafe_allow_html=True,
        )
        return

    table_html = _build_file_table_html(topic, filtered)
    st.markdown('<div class="library-table-html">', unsafe_allow_html=True)
    st.markdown(table_html, unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)


def _render_library_view() -> None:
    topic = st.session_state.selected_topic
    if not topic or topic not in st.session_state.library:
        st.markdown(
            '<div class="empty-library"><h3>My Research Library</h3>'
            "<p>Select a topic folder on the left, or create a new folder.</p></div>",
            unsafe_allow_html=True,
        )
        return

    st.markdown('<div class="main-library-panel library-header-stack">', unsafe_allow_html=True)
    _render_folder_heading(topic)

    st.markdown('<span class="toolbar-row-marker"></span>', unsafe_allow_html=True)
    t_add, t_spacer, t_search = st.columns([2.2, 3.6, 2.2], gap="small")
    with t_add:
        if st.button(
            "Add File to this folder",
            key="tb_add_file_folder",
            use_container_width=True,
            type="primary",
        ):
            _folder_new_file_dialog()
    with t_search:
        st.text_input(
            "Search files",
            placeholder="Search…",
            label_visibility="collapsed",
            key="search_query",
        )

    files = st.session_state.library[topic]["files"]
    _render_file_table(topic, files)
    st.markdown("</div>", unsafe_allow_html=True)


def _render_transcript_view() -> None:
    topic = st.session_state.selected_topic or ""
    fname = st.session_state.selected_file or ""
    record = _selected_record()

    if not record:
        st.warning("Session file not found.")
        st.markdown('<div class="btn-text-only">', unsafe_allow_html=True)
        if st.button("← Back to library"):
            _back_to_library()
            st.rerun()
        st.markdown("</div>", unsafe_allow_html=True)
        return

    st.markdown('<div class="transcript-top">', unsafe_allow_html=True)
    bc1, bc2 = st.columns([0.12, 0.88], gap="small")
    with bc1:
        st.markdown('<div class="back-btn btn-text-only">', unsafe_allow_html=True)
        if st.button("←", key="back_library", help="Back to library"):
            _back_to_library()
            st.rerun()
        st.markdown("</div>", unsafe_allow_html=True)
    with bc2:
        st.markdown(
            f'<p class="breadcrumb">'
            f"<strong>{html.escape(ROOT_LABEL)}</strong>"
            f'<span class="breadcrumb-sep">/</span>'
            f"<strong>{html.escape(topic)}</strong>"
            f'<span class="breadcrumb-sep">/</span>'
            f"{html.escape(fname)}"
            f"</p>",
            unsafe_allow_html=True,
        )
    st.markdown("</div>", unsafe_allow_html=True)

    if not record.flags:
        _rescan_selected_record()
        record = _selected_record() or record

    redacted_plain = redact_text(record.text, record.flags)
    audit_html = wrap_transcript_iframe_html(
        render_highlighted_html(record.text, record.flags),
        title="Audit View",
    )
    redacted_html = wrap_transcript_iframe_html(
        render_redacted_html(record.text, record.flags),
        title="Redacted View",
    )

    scan_labels = {
        "ai": "AI-powered detection",
        "contextual": "Contextual heuristic detection",
        "contextual_fallback": "Contextual fallback (AI unavailable or no matches)",
        "regex": "Regex detection",
        "regex_fallback": "Regex fallback",
    }
    scan_note = scan_labels.get(record.scan_mode, record.scan_mode or "unknown")
    api_key = _anthropic_api_key()
    status_col, rescan_col = st.columns([4, 1], gap="small")
    with status_col:
        if api_key:
            st.caption(
                f"{len(record.flags)} PII span(s) detected · {scan_note}. "
                "Hover purple text in Audit View for GDPR cards."
            )
        else:
            st.caption(
                f"{len(record.flags)} PII span(s) detected · {scan_note}. "
                "Set `ANTHROPIC_API_KEY` for AI explanations. Hover purple highlights for details."
            )
    with rescan_col:
        if st.button("Rescan PII", key="rescan_pii", use_container_width=True):
            _rescan_selected_record()
            st.rerun()

    st.markdown('<div class="transcript-compare">', unsafe_allow_html=True)
    col_audit, col_redacted = st.columns(2, gap="medium")

    with col_audit:
        audit_hdr, audit_dl = st.columns([2, 1], gap="small")
        with audit_hdr:
            st.markdown(
                '<p class="col-title">Audit View</p>',
                unsafe_allow_html=True,
            )
        with audit_dl:
            st.download_button(
                "Download",
                data=record.text,
                file_name=f"audit_{fname}",
                mime="text/plain",
                type="secondary",
                key="dl_audit",
                use_container_width=True,
            )
        components.html(audit_html, height=TRANSCRIPT_HTML_HEIGHT, scrolling=True)

    with col_redacted:
        red_hdr, red_dl = st.columns([2, 1], gap="small")
        with red_hdr:
            st.markdown(
                '<p class="col-title">Redacted View</p>',
                unsafe_allow_html=True,
            )
        with red_dl:
            st.download_button(
                "Download",
                data=redacted_plain,
                file_name=f"redacted_{fname}",
                mime="text/plain",
                type="secondary",
                key="dl_redacted",
                use_container_width=True,
            )
        components.html(redacted_html, height=TRANSCRIPT_HTML_HEIGHT, scrolling=True)

    st.markdown("</div>", unsafe_allow_html=True)


def main() -> None:
    st.set_page_config(
        page_title="UX Privacy Scanner",
        page_icon="🔒",
        layout="wide",
        initial_sidebar_state="collapsed",
    )
    st.markdown(CUSTOM_CSS, unsafe_allow_html=True)
    _init_state()
    if _process_expanded_query_param():
        st.rerun()
    if _process_open_file_query_param():
        st.rerun()
    if _process_nav_query_params():
        st.rerun()

    left, right = st.columns([1, 5], gap="small")

    with left:
        st.markdown('<span class="layout-row-marker"></span>', unsafe_allow_html=True)
        _render_left_panel()

    with right:
        if st.session_state.view == VIEW_TRANSCRIPT:
            _render_transcript_view()
        else:
            _render_library_view()


if __name__ == "__main__":
    main()
