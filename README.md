# Repo Shield

Repo Shield is a terminal-first security scanner for code repositories.
It uses static checks (AST, regex, entropy) and an optional Gemini AI audit.

## Features

- Detects high-entropy secret-like strings
- Flags hardcoded credentials (tokens, passwords, API keys)
- Identifies JWT and AWS-style key patterns
- Scans dependency manifests for risky/unpinned versions
- Optionally runs AI audit summaries with Gemini
- Prints a full scan report directly in the terminal

## Requirements

- Python 3.10+
- Git available in PATH

## Installation

```bash
python -m pip install -e .
```

Windows (venv):

```powershell
. ./.venv/Scripts/Activate.ps1
python -m pip install -e .
```

## Usage

Scan current directory:

```bash
repo-shield scan
```

Scan explicit source:

```bash
repo-shield scan thisdir
repo-shield scan C:/path/to/project
repo-shield scan https://github.com/user/repo
```

Useful flags:

- `--no-ai` skip AI audit
- `--max-files N` limit files sent to AI audit

Examples:

```bash
repo-shield scan thisdir --no-ai
repo-shield scan https://github.com/user/repo --max-files 5
```

## AI Setup (Optional)

Create `.env` in the project root:

```env
GEMINI_API_KEY=your_key_here
```

If the key is missing or quota is exhausted, run scanner-only mode:

```bash
repo-shield scan thisdir --no-ai
```

## Output

Repo Shield prints:

- Static finding counts by severity
- Detailed findings list
- AI audit summary per file
- Regex + AI confirmed "real issues"

All output is shown in the terminal. No dashboard or report file is generated.

## Troubleshooting

`repo-shield` not recognized:

- Activate your virtual environment
- Or use `.venv/Scripts/repo-shield.exe --help`

AI quota errors (HTTP 429):

- Rerun with `--no-ai`
