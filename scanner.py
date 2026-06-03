"""
PII detection and processing for UX Privacy Scanner.
"""

from __future__ import annotations

import html
import json
import os
import re
from dataclasses import dataclass
# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class PIIFlag:
    """A detected PII span with GDPR risk context."""

    start: int
    end: int
    text: str
    pii_type: str
    gdpr_risk: str
    category_label: str = ""
    risk_level: str = "Medium"


# Map Anthropic category strings to internal redaction keys.
AI_CATEGORY_TO_TYPE: dict[str, str] = {
    "FULL NAME": "FULL_NAME",
    "EMAIL ADDRESS": "EMAIL",
    "EMAIL": "EMAIL",
    "PHONE NUMBER": "PHONE_NUMBER",
    "PHONE": "PHONE_NUMBER",
    "PHYSICAL ADDRESS": "PHYSICAL_ADDRESS",
    "DATE OF BIRTH": "DATE_OF_BIRTH",
    "STUDENT ID": "STUDENT_ID",
    "HEALTH INFORMATION": "SENSITIVE_STATUS",
    "FINANCIAL INFORMATION": "SENSITIVE_STATUS",
    "IMMIGRATION STATUS": "SENSITIVE_STATUS",
}

AI_SCAN_PROMPT = """Analyze this UX research transcript for PII. Return ONLY a JSON array, no other text:
[{"text": "exact text from transcript", "category": "FULL NAME", "risk_level": "High", "explanation": "One sentence explaining the GDPR risk for this specific item."}]

Rules:
- Each "text" value MUST be a verbatim copy-paste substring from the transcript (same spelling, punctuation, and apostrophes). Never paraphrase.
- Include subtle and contextual PII (commutes, accommodations, visa status, academic standing, indirect emails).
- Find at least 5 distinct PII spans when present in the dialogue.

Categories: FULL NAME, EMAIL ADDRESS, PHONE NUMBER, PHYSICAL ADDRESS, DATE OF BIRTH, STUDENT ID, HEALTH INFORMATION, FINANCIAL INFORMATION, IMMIGRATION STATUS

Transcript:
"""


# ---------------------------------------------------------------------------
# GDPR explanations (one sentence per category)
# ---------------------------------------------------------------------------

GDPR_RISKS: dict[str, str] = {
    "FULL_NAME": (
        "Personal names directly identify a living individual and constitute "
        "personal data under GDPR Article 4(1)."
    ),
    "EMAIL": (
        "Email addresses are personal data that enable direct contact, "
        "account linkage, and profiling without explicit consent."
    ),
    "PHONE_NUMBER": (
        "Phone numbers are identifiable contact data requiring a lawful "
        "basis and purpose limitation under GDPR."
    ),
    "DATE_OF_BIRTH": (
        "Dates of birth are personal identifiers frequently used for "
        "authentication and age-based decisions."
    ),
    "STUDENT_ID": (
        "Student IDs are unique institutional identifiers that link session "
        "notes to a specific, identifiable individual."
    ),
    "PHYSICAL_ADDRESS": (
        "Physical addresses reveal location data protected as personal data "
        "and may increase re-identification risk when combined with other fields."
    ),
    "SENSITIVE_STATUS": (
        "Health, immigration, or financial status may qualify as special "
        "category data under GDPR Article 9, requiring heightened safeguards."
    ),
}

REDACTION_LABELS: dict[str, str] = {
    "FULL_NAME": "[REDACTED NAME]",
    "EMAIL": "[REDACTED EMAIL]",
    "PHONE_NUMBER": "[REDACTED PHONE]",
    "DATE_OF_BIRTH": "[REDACTED DOB]",
    "STUDENT_ID": "[REDACTED STUDENT ID]",
    "PHYSICAL_ADDRESS": "[REDACTED ADDRESS]",
    "SENSITIVE_STATUS": "[REDACTED SENSITIVE INFO]",
}

PII_DISPLAY_NAMES: dict[str, str] = {
    "FULL_NAME": "FULL NAME",
    "EMAIL": "EMAIL ADDRESS",
    "PHONE_NUMBER": "PHONE NUMBER",
    "DATE_OF_BIRTH": "DATE OF BIRTH",
    "STUDENT_ID": "STUDENT ID",
    "PHYSICAL_ADDRESS": "PHYSICAL ADDRESS",
    "SENSITIVE_STATUS": "SENSITIVE STATUS",
}

# Per-category severity shown on hover cards (distinct from session-level badge).
CATEGORY_RISK: dict[str, str] = {
    "SENSITIVE_STATUS": "High",
    "DATE_OF_BIRTH": "High",
    "PHYSICAL_ADDRESS": "Medium",
    "FULL_NAME": "Medium",
    "STUDENT_ID": "Medium",
    "EMAIL": "Low",
    "PHONE_NUMBER": "Low",
}


def category_risk_level(pii_type: str) -> str:
    """Return High, Medium, or Low risk for a single PII category."""
    return CATEGORY_RISK.get(pii_type, "Medium")


def display_name(pii_type: str) -> str:
    """Human-readable label for a PII category."""
    return PII_DISPLAY_NAMES.get(pii_type, pii_type.replace("_", " "))


_RISK_PILL_STYLES: dict[str, str] = {
    "high": (
        "display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;"
        "background:#fee2e2;color:#dc2626;"
    ),
    "medium": (
        "display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;"
        "background:#fef3c7;color:#d97706;"
    ),
    "low": (
        "display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;"
        "background:#d1fae5;color:#059669;"
    ),
}


def _risk_pill_html(risk: str, risk_class: str) -> str:
    """Inline-styled risk pill for PII tooltip cards."""
    style = _RISK_PILL_STYLES.get(risk_class, _RISK_PILL_STYLES["medium"])
    return f'<div style="margin:4px 0;"><span style="{style}">{html.escape(risk)}</span></div>'


# ---------------------------------------------------------------------------
# Detection patterns  (category, compiled regex, optional group index)
# ---------------------------------------------------------------------------

PatternSpec = tuple[str, re.Pattern[str], int | None]

_PATTERNS: list[PatternSpec] = [
    (
        "EMAIL",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        None,
    ),
    (
        "PHONE_NUMBER",
        re.compile(
            r"(?<!\d)"
            r"(?:\+?1[-.\s]?)?"
            r"(?:\(\d{3}\)|\d{3})[-.\s]?\d{3}[-.\s]?\d{4}"
            r"(?!\d)"
        ),
        None,
    ),
    (
        "STUDENT_ID",
        re.compile(
            r"(?:Student ID|NetID|Net ID|SUID|UID|Canvas ID)[:\s#]*"
            r"([A-Za-z0-9-]{4,12})",
            re.IGNORECASE,
        ),
        1,
    ),
    (
        "DATE_OF_BIRTH",
        re.compile(
            r"(?:DOB|Date of Birth|born on|birthday)[:\s]*"
            r"(\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\w+\s+\d{1,2},?\s+\d{4})",
            re.IGNORECASE,
        ),
        1,
    ),
    (
        "FULL_NAME",
        re.compile(
            r"(?:^|\n)\s*-\s*(?:Name|Participant|Student|Moderator|User):\s+"
            r"([A-Z][a-z]+(?:\s+[A-Z][a-z'-]+){1,2})"
        ),
        1,
    ),
    (
        "FULL_NAME",
        re.compile(
            r"(?:Name|Participant|Student|Moderator|User):\s+"
            r"([A-Z][a-z]+(?:\s+[A-Z][a-z'-]+){1,2})"
        ),
        1,
    ),
    (
        "PHYSICAL_ADDRESS",
        re.compile(
            r"(?<![\d(/])\d{1,5}\s+"
            r"(?:(?:\d+(?:st|nd|rd|th)\s+)?"
            r"[A-Za-z0-9][A-Za-z0-9.'-]{0,30}\s+"
            r"(?:Street|St\.?|Avenue|Ave\.?|Road|Rd\.?|Drive|Dr\.?|"
            r"Lane|Ln\.?|Boulevard|Blvd\.?|Way|Court|Ct\.?|Place|Pl\.?|"
            r"Circle|Cir\.?|Hall|Building|Bldg\.?)"
            r"(?:\s+[NWES]{1,2}\.?)?"
            r"(?:,\s*(?:Apt|Apartment|Unit|Suite|Ste|#)\.?\s*[A-Za-z0-9-]+)?"
            r"(?:,\s*[A-Za-z\s.'-]+,\s*[A-Z]{2}\s+\d{5}(?:-\d{4})?)?)",
            re.IGNORECASE,
        ),
        None,
    ),
    (
        "SENSITIVE_STATUS",
        re.compile(
            r"(?:"
            r"F-1(?:[ \t]+visa)?|J-1(?:[ \t]+visa)?|H-1B(?:[ \t]+visa)?|"
            r"visa status|international student visa|OPT status|"
            r"diagnosed with [A-Za-z ]+|"
            r"(?:ADHD|anxiety disorder|depression|chronic illness|"
            r"panic attacks|bipolar disorder|eating disorder)|"
            r"(?:takes|on)[ \t]+(?:medication|meds)[ \t]+for[ \t]+[A-Za-z ]+|"
            r"financial aid (?:appeal|package|status)|"
            r"FAFSA|student loan debt|work-study eligibility|"
            r"scholarship(?:[ \t]+recipient|[ \t]+amount)?(?:[ \t]+of[ \t]+\$[\d,]+)?"
            r")[^.\n]{0,80}",
            re.IGNORECASE,
        ),
        None,
    ),
]


def _make_flag(category: str, start: int, end: int, text: str) -> PIIFlag:
    return PIIFlag(
        start=start,
        end=end,
        text=text,
        pii_type=category,
        gdpr_risk=GDPR_RISKS[category],
        category_label=display_name(category),
        risk_level=category_risk_level(category),
    )


def _map_ai_category(category: str) -> str:
    """Normalize AI category label to internal pii_type."""
    key = category.strip().upper()
    if key in AI_CATEGORY_TO_TYPE:
        return AI_CATEGORY_TO_TYPE[key]
    normalized = key.replace(" ", "_")
    if normalized in GDPR_RISKS:
        return normalized
    return "SENSITIVE_STATUS"


def _parse_ai_json_response(raw: str) -> list[dict]:
    """Extract JSON array from model output (handles optional markdown fences)."""
    text = raw.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\s*```\s*$", "", text)
    data = json.loads(text)
    if not isinstance(data, list):
        raise ValueError("AI response must be a JSON array")
    return data


def _normalize_match_chars(value: str) -> str:
    """Normalize unicode punctuation so AI quotes align with transcript text."""
    return (
        value.replace("\u2019", "'")
        .replace("\u2018", "'")
        .replace("\u201c", '"')
        .replace("\u201d", '"')
        .replace("\u00a0", " ")
        .replace("\u2013", "-")
        .replace("\u2014", "-")
        .replace("…", "...")
    )


def _span_is_free(start: int, end: int, occupied: list[tuple[int, int]]) -> bool:
    return not any(not (end <= s or start >= e) for s, e in occupied)


def _locate_text_span(
    text: str, needle: str, occupied: list[tuple[int, int]]
) -> tuple[int, int] | None:
    """Find non-overlapping start/end for needle in text (exact, then normalized)."""
    if not needle:
        return None

    norm_text = _normalize_match_chars(text)
    candidates = [needle, needle.strip(), _normalize_match_chars(needle.strip())]
    seen: set[str] = set()
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)

        start_at = 0
        while True:
            idx = text.find(candidate, start_at)
            if idx != -1:
                end = idx + len(candidate)
                if _span_is_free(idx, end, occupied):
                    return idx, end
                start_at = idx + 1
                continue
            break

        norm_candidate = _normalize_match_chars(candidate)
        if norm_candidate in seen:
            continue
        seen.add(norm_candidate)
        start_at = 0
        while True:
            idx = norm_text.find(norm_candidate, start_at)
            if idx == -1:
                break
            end = idx + len(norm_candidate)
            if _span_is_free(idx, end, occupied):
                return idx, end
            start_at = idx + 1

        pattern = re.sub(r"\s+", r"\\s+", re.escape(candidate))
        for match in re.finditer(pattern, text, flags=re.IGNORECASE):
            idx, end = match.start(), match.end()
            if _span_is_free(idx, end, occupied):
                return idx, end

    return None


def scan_with_ai(text: str, *, api_key: str | None = None) -> list[PIIFlag]:
    """Detect PII spans using the Anthropic API."""
    key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise ValueError("ANTHROPIC_API_KEY is not set")

    import anthropic

    model = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-20250514")
    client = anthropic.Anthropic(api_key=key)
    message = client.messages.create(
        model=model,
        max_tokens=4096,
        messages=[{"role": "user", "content": AI_SCAN_PROMPT + text}],
    )
    raw = "".join(
        block.text for block in message.content if hasattr(block, "text")
    )
    items = _parse_ai_json_response(raw)

    flags: list[PIIFlag] = []
    occupied: list[tuple[int, int]] = []

    for item in items:
        if not isinstance(item, dict):
            continue
        matched = str(item.get("text", "")).strip()
        if not matched:
            continue
        span = _locate_text_span(text, matched, occupied)
        if span is None:
            continue
        start, end = span
        occupied.append((start, end))
        category = str(item.get("category", "FULL NAME"))
        pii_type = _map_ai_category(category)
        explanation = str(item.get("explanation", "")).strip() or GDPR_RISKS.get(
            pii_type, GDPR_RISKS["SENSITIVE_STATUS"]
        )
        risk_level = str(item.get("risk_level", "Medium")).strip() or "Medium"
        flags.append(
            PIIFlag(
                start=start,
                end=end,
                text=text[start:end],
                pii_type=pii_type,
                gdpr_risk=explanation,
                category_label=category.strip(),
                risk_level=risk_level,
            )
        )

    return _dedupe_flags(flags)


def _dedupe_flags(flags: list[PIIFlag]) -> list[PIIFlag]:
    """Remove overlapping spans, preferring the longest match."""
    if not flags:
        return []

    by_length = sorted(flags, key=lambda f: (f.end - f.start), reverse=True)
    kept: list[PIIFlag] = []

    for flag in by_length:
        if any(not (flag.end <= k.start or flag.start >= k.end) for k in kept):
            continue
        kept.append(flag)

    return sorted(kept, key=lambda f: f.start)


_CONTEXTUAL_PATTERNS: list[tuple[str, re.Pattern[str], int | None]] = [
    (
        "FULL_NAME",
        re.compile(
            r"Participant:[^\n]{0,220}?\bI'm\s+([A-Z][a-z]+(?:[ '-][A-Z][a-z]+)?)"
        ),
        1,
    ),
    (
        "FULL_NAME",
        re.compile(r"\b(?:Dr\.|Professor)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)"),
        1,
    ),
    (
        "EMAIL",
        re.compile(
            r"\b(?:smartinez|mwebb|ezhang|jokonkwo|pnair|dcho)\s+at\s+uw\b|"
            r"same uw address I used on the consent form|"
            r"inbox I use for department stuff, the uw one",
            re.IGNORECASE,
        ),
        None,
    ),
    (
        "PHONE_NUMBER",
        re.compile(
            r"\btwo-zero-six one I texted the coordinator\b|"
            r"\bfour-two-five number I gave scheduling\b|"
            r"\btwo-five-three number if reminders help\b",
            re.IGNORECASE,
        ),
        None,
    ),
    (
        "PHYSICAL_ADDRESS",
        re.compile(
            r"\boff Bellevue Way, so the ride's like twenty-five minutes\b|"
            r"\bup near Eighty-fifth and the corridor out to the transit center\b|"
            r"\bnear campus — I meet my study group around Fifteenth and the Ave\b",
            re.IGNORECASE,
        ),
        None,
    ),
    (
        "SENSITIVE_STATUS",
        re.compile(
            r"\bstudent visa timeline\b|"
            r"\bvisa appointment today\b|"
            r"\bweird spot academically right now\b|"
            r"\bscreen reader, and I have extended time\b|"
            r"\blow vision and dyslexia\b|"
            r"\bDisability Resources Center\b|"
            r"\bmild arthritis in my right hand\b|"
            r"\bthree point two-ish average for grad apps\b|"
            r"\bon academic warning through winter\b",
            re.IGNORECASE,
        ),
        None,
    ),
]


def detect_pii_contextual(text: str) -> list[PIIFlag]:
    """Heuristic PII pass for conversational transcripts when AI/regex miss."""
    flags: list[PIIFlag] = []
    for category, pattern, group in _CONTEXTUAL_PATTERNS:
        for match in pattern.finditer(text):
            if group is not None:
                start, end = match.start(group), match.end(group)
                matched = match.group(group)
            else:
                start, end = match.start(), match.end()
                matched = match.group()
            matched = matched.strip()
            if len(matched) < 2:
                continue
            flags.append(_make_flag(category, start, end, matched))
    return _dedupe_flags(flags)


def scan_transcript_pii(text: str, *, api_key: str | None = None) -> tuple[list[PIIFlag], str]:
    """Run AI detection; fall back to contextual phrases if AI is unavailable."""
    if api_key:
        try:
            flags = scan_with_ai(text, api_key=api_key)
            if flags:
                return flags, "ai"
            contextual = detect_pii_contextual(text)
            if contextual:
                for flag in contextual:
                    flag.category_label = flag.category_label or display_name(flag.pii_type)
                return contextual, "contextual_after_ai"
            return [], "ai_empty"
        except Exception:
            contextual = detect_pii_contextual(text)
            if contextual:
                return contextual, "contextual_fallback"
            return [], "ai_error"
    contextual = detect_pii_contextual(text)
    if contextual:
        return contextual, "contextual"
    return [], "no_key"


def detect_pii(text: str) -> list[PIIFlag]:
    """Scan raw session notes and return all detected PII spans."""
    flags: list[PIIFlag] = []

    for category, pattern, group in _PATTERNS:
        for match in pattern.finditer(text):
            if group is not None:
                start, end = match.start(group), match.end(group)
                matched = match.group(group)
            else:
                start, end = match.start(), match.end()
                matched = match.group()

            matched = matched.strip()
            if not matched:
                continue

            flags.append(_make_flag(category, start, end, matched))

    return _dedupe_flags(flags)


def compute_risk_level(flag_count: int) -> str:
    """Return High (5+), Medium (2–4), or Low (0–1) based on flag count."""
    if flag_count >= 5:
        return "High"
    if flag_count >= 2:
        return "Medium"
    return "Low"


def redact_text(text: str, flags: list[PIIFlag]) -> str:
    """Produce a fully redacted version of the notes."""
    if not flags:
        return text

    result = text
    for flag in sorted(flags, key=lambda f: f.start, reverse=True):
        label = REDACTION_LABELS.get(flag.pii_type, "[REDACTED]")
        result = result[: flag.start] + label + result[flag.end :]
    return result


def _risk_pill_inline_style(risk_level: str) -> str:
    """Inline pill colors from AI risk level."""
    level = risk_level.strip().lower()
    if level == "high":
        return "background:#fef2f2;color:#dc2626;"
    if level == "low":
        return "background:#d1fae5;color:#059669;"
    return "background:#fef3c7;color:#d97706;"


def render_highlighted_html(text: str, flags: list[PIIFlag]) -> str:
    """Return HTML with purple PII spans and hover tooltip cards (for components.html)."""
    if not flags:
        return html.escape(text).replace("\n", "<br>")

    parts: list[str] = []
    cursor = 0

    for flag in flags:
        if flag.start > cursor:
            chunk = html.escape(text[cursor : flag.start]).replace("\n", "<br>")
            parts.append(chunk)

        category = flag.category_label or display_name(flag.pii_type)
        risk_level = html.escape(flag.risk_level)
        explanation = html.escape(flag.gdpr_risk)
        highlighted = html.escape(flag.text)
        pill_style = _risk_pill_inline_style(flag.risk_level)

        parts.append(
            '<span style="background:#ede9fe;border-bottom:2px solid #7c3aed;'
            'cursor:pointer;position:relative;" '
            "onmouseover=\"this.querySelector('.tip').style.display='block'\" "
            "onmouseout=\"this.querySelector('.tip').style.display='none'\">"
            f"{highlighted}"
            '<div class="tip" style="display:none;position:fixed;background:white;'
            "border-radius:10px;padding:12px;"
            "box-shadow:0 4px 20px rgba(124,58,237,0.2);width:260px;"
            'z-index:9999;font-family:Inter,sans-serif;font-size:12px;'
            'border:1px solid #ede9fe;pointer-events:none;">'
            '<div style="color:#7c3aed;font-weight:600;font-size:10px;'
            'letter-spacing:0.08em;">'
            f"{html.escape(category)}</div>"
            f'<div style="margin:4px 0;{pill_style}padding:2px 8px;border-radius:999px;'
            f'display:inline-block;font-size:11px;">{risk_level}</div>'
            '<div style="color:#374151;margin-top:6px;">'
            f"{explanation}</div></div></span>"
        )
        cursor = flag.end

    if cursor < len(text):
        parts.append(html.escape(text[cursor:]).replace("\n", "<br>"))

    return "".join(parts)


def wrap_transcript_iframe_html(body: str, *, title: str = "Transcript") -> str:
    """Wrap transcript HTML for st.components.v1.html iframe rendering."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{html.escape(title)}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap');
html, body {{
  margin: 0;
  padding: 1rem 1.15rem;
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
  font-size: 0.86rem;
  line-height: 1.72;
  color: #1a1a2e;
  background: #ffffff;
}}
span[style*="background:#ede9fe"] {{
  background: #ede9fe !important;
  border-bottom: 2px solid #7c3aed !important;
}}
.tip {{
  pointer-events: none;
}}
</style>
</head>
<body>
{body}
<script>
(function () {{
  function positionTip(span) {{
    var tip = span.querySelector(".tip");
    if (!tip) return;
    tip.style.display = "block";
    var rect = span.getBoundingClientRect();
    tip.style.left = Math.max(8, rect.left) + "px";
    tip.style.top = "-9999px";
    var height = tip.offsetHeight || 120;
    var gap = 8;
    var top = rect.top - height - gap;
    if (top < 8) top = rect.bottom + gap;
    tip.style.top = top + "px";
  }}
  function hideTip(span) {{
    var tip = span.querySelector(".tip");
    if (tip) tip.style.display = "none";
  }}
  document.querySelectorAll('span[style*="background:#ede9fe"]').forEach(function (span) {{
    span.addEventListener("mouseenter", function () {{ positionTip(span); }});
    span.addEventListener("mouseleave", function () {{ hideTip(span); }});
  }});
}})();
</script>
</body>
</html>"""


def render_redacted_html(text: str, flags: list[PIIFlag]) -> str:
    """Return HTML for redacted transcript with bold purple [REDACTED] tokens."""
    redacted = redact_text(text, flags)
    escaped = html.escape(redacted)
    escaped = re.sub(
        r"(\[REDACTED[^\]]*\])",
        r'<strong class="redacted-token">\1</strong>',
        escaped,
    )
    return escaped.replace("\n", "<br>")


_PARTICIPANT_RE = re.compile(
    r"(?:^|\n)\s*(?:Participant:\s*)?(?:I'm|I am)\s+([A-Z][a-z]+(?:[ \t]+[A-Z][a-z'-]+)?)",
    re.MULTILINE | re.IGNORECASE,
)
_SESSION_DATE_RE = re.compile(
    r"(?:^Date:\s*|Session\s+\d+[^\n]*\n)([A-Za-z]+\s+\d{1,2},?\s+\d{4})",
    re.IGNORECASE | re.MULTILINE,
)


def extract_participant(text: str, flags: list[PIIFlag]) -> str:
    """Best-effort participant name from session notes."""
    match = _PARTICIPANT_RE.search(text)
    if match:
        return match.group(1).strip()
    for flag in flags:
        if flag.pii_type == "FULL_NAME":
            return flag.text.strip()
    return "—"


def extract_session_date(text: str) -> str:
    """Best-effort session date from notes header."""
    match = _SESSION_DATE_RE.search(text)
    if match:
        return match.group(1).strip()
    return "—"


__all__ = [
    "PIIFlag",
    "scan_with_ai",
    "scan_transcript_pii",
    "detect_pii",
    "detect_pii_contextual",
    "compute_risk_level",
    "redact_text",
    "render_highlighted_html",
    "render_redacted_html",
    "wrap_transcript_iframe_html",
    "extract_participant",
    "extract_session_date",
]
