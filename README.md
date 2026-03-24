# Repo Shield

Repo Shield scans repositories for risky patterns, generates a markdown report, and opens a Streamlit dashboard that visualizes report data.

## What It Detects

- High-entropy secret-like strings
- Hardcoded credential patterns
- JWT and AWS key patterns
- Risky dependency version usage in package manifests
- Optional AI audit summaries using Gemini

## Requirements

- Python 3.10+
- Git installed and available on PATH

## Installation

From the project root:

    python -m pip install -e .

If using virtual environment on Windows:

    . ./.venv/Scripts/Activate.ps1
    python -m pip install -e .

Verify CLI:

    repo-shield --help

If command is not found, use the venv executable directly:

    .venv/Scripts/repo-shield.exe --help

## Configure AI (Optional)

Create a .env file in project root:

    GOOGLE_API_KEY=your_key_here

If key is missing or quota is exhausted, run with --no-ai.

## Core Commands

Scan a GitHub repository:

    repo-shield scan https://github.com/user/repo

Scan current directory explicitly:

    repo-shield scan thisdir

Scan current directory by default (no repo argument):

    repo-shield scan

Scan a local folder path:

    repo-shield scan C:/path/to/project

## Useful Flags

- --no-ai: skip Gemini audit (recommended when quota is limited)
- --md: print markdown report to terminal
- --max-files N: limit number of files sent to AI audit

Examples:

    repo-shield scan thisdir --md --no-ai
    repo-shield scan https://github.com/user/repo --max-files 5

## Report And Dashboard Flow

1. Scan runs and writes report.md in current directory.
2. CLI auto-launches Streamlit in report mode.
3. CLI prints the dashboard URL.

Note: if port 8501 is busy, Repo Shield auto-picks another available port and prints that URL.

## Launch Dashboard Manually

Use the built-in UI command:

    repo-shield ui

Or run Streamlit directly with a specific report:

    python -m streamlit run streamlit_app.py --server.port 8502 -- --report-file report.md

## Typical Workflow

1. Activate environment.
2. Run scan with thisdir or repo URL.
3. Open printed Streamlit URL.
4. Review findings and recommendations in report.md.

## Troubleshooting

- repo-shield not recognized:
  activate your virtual environment or call .venv/Scripts/repo-shield.exe directly.
- AI quota errors (429):
  rerun with --no-ai.
- Streamlit not opening:
  use the exact Dashboard URL printed by the scan command.
