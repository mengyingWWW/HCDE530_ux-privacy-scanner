# UX Privacy Scanner

**Public project URL:** [https://github.com/mengyingWWW/HCDE530_ux-privacy-scanner](https://github.com/mengyingWWW/HCDE530_ux-privacy-scanner)

When you run this project locally, it starts a web app in your browser where you can browse UX research transcripts, automatically detect personally identifiable information (PII), review purple-highlighted findings with GDPR risk explanations, and compare an audit view with a redacted view side by side.

---

## What it does

UX Privacy Scanner is a research-library tool for teams who collect qualitative data (such as usability interview transcripts) and need to review privacy risk before sharing or archiving notes.

The app lets you:

- Organize session transcripts in a folder-based **Research Library** (similar to a simple reference manager)
- **Scan transcripts for PII** using the Anthropic API, with contextual understanding of names, contact details, locations, health or immigration references, and other sensitive details that appear in natural dialogue—not only obvious patterns like email addresses
- Open any session in an **Audit View** (original text with purple highlights and hover cards explaining category, risk level, and GDPR-related rationale) and a **Redacted View** (a version with sensitive spans replaced by labeled tokens such as `[REDACTED NAME]`)
- **Download** audit and redacted plain-text exports
- See a **risk summary** per file in the library table (High / Medium / Low based on how much PII was found)

Sample Canvas LMS usability interview transcripts are included so you can try the workflow immediately without uploading your own files.

---

## Who it is for

This tool is written for **UX researchers, HCI students, and privacy-conscious design teams** who work with session notes and need a practical way to:

- Flag PII before sharing transcripts with advisors, clients, or classmates
- Document *why* a phrase might be sensitive (not just that it matches a regex)
- Produce a redacted copy for reports or portfolios while keeping an auditable original

You do not need to have taken HCDE 530 to use or evaluate the project; it assumes familiarity with web apps and basic Python setup, not course-specific jargon.

---

## How to run it locally

### Prerequisites

- Python 3.10 or newer
- [Anthropic API key](https://console.anthropic.com/) (recommended for AI-powered detection and explanations). Without a key, the app still runs using built-in fallback detection, but explanations will be less tailored.

### Setup

```bash
git clone https://github.com/mengyingWWW/HCDE530_ux-privacy-scanner.git
cd HCDE530_ux-privacy-scanner
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### API key (recommended)

Either export an environment variable:

```bash
export ANTHROPIC_API_KEY="your-api-key-here"
```

Or create `.streamlit/secrets.toml` (this file is gitignored and will not be committed):

```toml
ANTHROPIC_API_KEY = "your-api-key-here"
```

Optional: set a different model:

```bash
export ANTHROPIC_MODEL="claude-sonnet-4-20250514"
```

### Start the app

```bash
streamlit run app.py
```

Streamlit will print a local URL (usually **http://localhost:8501**). Open that address in your browser.

### Basic workflow

1. In the sidebar, expand **My Research Library** → **Canvas LMS Usability Study** and click a session file (e.g. `session_P1.txt`).
2. In **Audit View**, hover purple highlights to read PII category, risk level, and a short GDPR-oriented explanation.
3. Use **Redacted View** to see the de-identified version.
4. Click **Rescan PII** if you change the transcript or want to refresh AI detection.
5. Use **Download** buttons to save audit or redacted text files.

You can add your own `.txt` transcripts to a folder under `samples/` or upload through the library UI when that flow is enabled in the app.

---

## Project structure

| Path | Purpose |
|------|---------|
| `app.py` | Streamlit UI: library, transcript comparison, downloads |
| `scanner.py` | PII detection (Anthropic API + fallbacks), HTML rendering for highlights |
| `samples/` | Example UX interview transcripts |
| `requirements.txt` | Python dependencies |
| `.streamlit/config.toml` | App theme (colors, layout) |

---

## Privacy note

This tool is intended for **educational and research workflow support**. It does not replace legal review. Do not commit API keys or real participant data to a public repository; keep secrets in environment variables or local `secrets.toml` only.

---

## License

See repository defaults; sample transcripts are fictional usability research dialogue for demonstration.
