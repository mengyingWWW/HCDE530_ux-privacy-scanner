# MP2 Reflection — UX Privacy Scanner

## What did you build?

I built **UX Privacy Scanner**, a browser-based tool for qualitative UX researchers who need to review participant privacy before sharing session notes. Think of it as a small research library plus a privacy review desk: transcripts live in folders, you open a file, and the system flags passages that may contain personally identifiable information (PII). Hovering a purple highlight can show category (e.g., full name, immigration status), risk level, and a short GDPR-oriented rationale.

The **library view** lists sessions with participant label, date, and an overall risk badge. The **transcript view** shows **Audit View** (original dialogue, highlighted) and **Redacted View** (`[REDACTED NAME]`-style tokens) side by side, with downloads for each. Detection uses the **Anthropic API** on realistic **Canvas LMS usability** interview scripts where PII appears in natural speech—commutes, accommodations, visa pressure—not in `Name:` / `Email:` headers. The goal is contextual review, not a regex demo.

---

## What decisions did you make?

My **MP2a declaration** centered on a transcript PII detector. During implementation I expanded into **file organization**, because researchers manage studies and many sessions, not one upload at a time. I added a Zotero-style sidebar, a searchable file table, and a dedicated transcript screen—closer to how UX labs actually work.

I chose **Python and Streamlit** (in Cursor) over a notebook-only deliverable or a no-code builder. Streamlit supported library state, two-column layouts, and `components.html` iframes so explanation cards could use working hover behavior—hard to get from sanitized markdown alone. A notebook would show analysis; it would not feel like a product.

For **data**, I authored six fictional transcripts as interviewer–participant dialogue with **embedded PII**, forcing contextual detection. I split **`scanner.py`** (API, spans, HTML) from **`app.py`** (UI) to keep responsibilities clear.

---

## What would you do differently?

I would **enrich file organization**: study-level metadata (IRB, consent version), tags/filters, bulk import, and version notes when a file is rescanned after edits. Today the library fits a bundled demo, not a multi-quarter lab archive.

I would also **deepen PII explanations** so cards respond to *this* line in *this* session—not generic “email is personal data” language. The prompt and UI should highlight ambiguous, dialogue-based risk (e.g., neighborhood + enrollment status) and explain combined re-identification, not only obvious identifiers. I would add click-to-pin cards and more reliable positioning for long transcripts.

---

## What does this work demonstrate?

**User-centered design** shows in the catalog → open → compare → export flow, side-by-side audit/redacted panes, and samples that mirror real usability interviews (`app.py` navigation, table risk badges).

**Technical skill** shows in Anthropic integration (`scan_with_ai`), JSON-to-`PIIFlag` parsing, highlight HTML in iframes, and Streamlit session state for folders and file selection (`scanner.py` vs `app.py`).

**Privacy and ethics** show in GDPR-framed copy, category-based redaction, and intentional subtle PII in dialogue (health, visa, academic standing)—not only emails.

**Professional communication** shows in the public GitHub repo, README for outside readers, and this reflection linking product choices to reviewable tradeoffs.
