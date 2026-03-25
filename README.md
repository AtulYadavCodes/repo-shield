# Repo Shield

Repo Shield is an AI-powered security scanner for code repositories. It detects risky patterns, generates an AI-ready markdown report, and opens a Streamlit dashboard so you can review findings and AI insights in one place.

## Screenshots

![Repo Shield dashboard 5](./Screenshot%202026-03-25%20134858.png)
![Repo Shield dashboard 6](./Screenshot%202026-03-25%20134935.png)
![Repo Shield dashboard 2](./Screenshot%202026-03-25%20134805.png)
![Repo Shield dashboard 3](./Screenshot%202026-03-25%20134826.png)
![Repo Shield dashboard 4](./Screenshot%202026-03-25%20134843.png)



## Features

- Detects high-entropy, secret-like strings
- Flags hardcoded credential patterns (tokens, passwords, API keys)
- Identifies JWTs and AWS-style access keys
- Inspects dependency manifests for risky / outdated versions
- Runs optional AI audit summaries using Google Gemini on high‑risk files

## Requirements

- Python 3.10+
- Git installed and available on PATH

## Installation

From the project root:

    python -m pip install -e .

If using a virtual environment on Windows:

    . ./.venv/Scripts/Activate.ps1
    python -m pip install -e .

Verify the CLI is installed:

    repo-shield --help

If the command is not found, use the venv executable directly:

    .venv/Scripts/repo-shield.exe --help

## Usage

Basic scans:

- Scan a GitHub repository:

      repo-shield scan https://github.com/user/repo

- Scan the current directory explicitly:

      repo-shield scan thisdir

- Scan the current directory by default (no repo argument):

      repo-shield scan

- Scan a local folder path:

      repo-shield scan C:/path/to/project

### Useful Flags

- `--no-ai` – skip Gemini audit (recommended when quota is limited)
- `--md` – print the markdown report to the terminal
- `--max-files N` – limit the number of files sent to the AI audit

Examples:

    repo-shield scan thisdir --md --no-ai
    repo-shield scan https://github.com/user/repo --max-files 5

## Optional AI Configuration

To enable AI audit summaries, create a `.env` file in the project root:

    GOOGLE_API_KEY=your_key_here

If the key is missing or quota is exhausted, run with `--no-ai` to skip AI analysis:

    repo-shield scan thisdir --no-ai

## Report And Dashboard Flow

1. A scan runs and writes `report.md` in the current directory.
2. The CLI auto-launches Streamlit in report mode.
3. The CLI prints the dashboard URL to the terminal.

If port 8501 is busy, Repo Shield automatically picks another available port and prints that URL instead.

## Launch Dashboard Manually

Use the built-in UI command:

    repo-shield ui

Or run Streamlit directly with a specific report file:

    python -m streamlit run streamlit_app.py --server.port 8502 -- --report-file report.md

## Typical Workflow

1. Activate your Python environment.
2. Run a scan with `thisdir` or a repo URL.
3. Open the printed Streamlit URL in your browser.
4. Review findings and remediation tips in `report.md` and the dashboard.

## Troubleshooting

- `repo-shield` not recognized:
  - Activate your virtual environment, or call `.venv/Scripts/repo-shield.exe` directly.
- AI quota errors (HTTP 429):
  - Rerun with `--no-ai`.
- Streamlit dashboard not opening automatically:
  - Copy and paste the exact dashboard URL printed by the scan command into your browser, or start it manually as shown above.
