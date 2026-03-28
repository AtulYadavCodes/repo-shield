# Repo Shield

Repo Shield is a terminal-first repository security scanner.
It combines static checks (regex, entropy, and Python AST rules) with an optional Gemini-based AI review step.

## What It Detects

- Hardcoded credential patterns (passwords, API keys, secrets)
- JWT token patterns
- AWS Access Key ID and AWS Secret Key patterns
- High-entropy secret-like strings
- Dangerous Python logic patterns (for example, eval and exec)
- Risky dependency declarations in:
  - requirements.txt
  - package.json

## Current CLI Structure

Repo Shield exposes one command group:

```bash
repo-shield scan [repo_url_or_path] [--max-files N] [--no-ai]
```

Arguments:

- repo_url_or_path (optional)
  - Default: thisdir
  - Accepts:
    - thisdir (scan current working directory)
    - local path (for example C:/work/my-repo)
    - remote Git URL (for example https://github.com/org/repo)

Options:

- --no-ai
  - Run only static scanning (skip Gemini audit)
- --max-files N
  - Limit how many eligible findings are sent to AI
  - 0 means no limit

## Requirements

- Python 3.10+
- Git available in PATH

## Installation

Editable install:

```bash
python -m pip install -e .
```

Windows (venv example):

```powershell
. ./.venv/Scripts/Activate.ps1
python -m pip install -e .
```

## Optional AI Setup

Create a .env file in project root:

```env
GEMINI_API_KEY=your_api_key_here
```

If key is missing, Repo Shield will fail AI initialization and you can run scanner-only mode:

```bash
repo-shield scan thisdir --no-ai
```

## Usage Examples

Scan current directory:

```bash
repo-shield scan
```

Scan local path:

```bash
repo-shield scan C:/path/to/repo
```

Scan remote repository without AI:

```bash
repo-shield scan https://github.com/user/repo --no-ai
```

Scan with AI but only first 5 eligible files:

```bash
repo-shield scan thisdir --max-files 5
```

## Output Format

Terminal report includes:

- Final Result
- Repository source
- Total static findings and severity breakdown
- Detailed static findings list
- AI audit summary:
  - files audited
  - success/failed count
  - per-file AI response

Important:

- Static findings are preliminary and not a final security verdict.
- If AI is skipped or unavailable, the report still prints static findings.

## Sample Report

Example output from a scan run:

Command used:

```bash
repo-shield scan https://github.com/Mateusz-Nejman/Pixed --max-files 1
```

```text
========================================================================
REPO SHIELD TERMINAL REPORT
========================================================================
Final Result: REVIEW REQUIRED (potential issues detected; manual review needed)
Repository: https://github.com/Mateusz-Nejman/Pixed
Total findings (static): 4
Static findings are preliminary and not a final security verdict.
Severity breakdown: critical=4 high=0 medium=0

Detailed findings:

     severity       method         file name                reason

  1. [critical]      [REGEX]      FlyingButton.axaml-       hardcoded credential pattern
  2. [critical]      [REGEX]      ToolButton.axaml-       hardcoded credential pattern
  3. [critical]      [REGEX]      ToolRadio.axaml-       hardcoded credential pattern
  4. [critical]      [REGEX]      ToolRadioCustom.axaml-       hardcoded credential pattern

AI audit summary:
  files audited=1 success=1 failed=0
  1. FlyingButton.axaml
  status: False Positive
       reason: The attribute 'RecognizesAccessKey' is a UI property used for keyboard mnemonics (e.g., Alt+Key shortcuts), and 'x:Key' is a standard identifier for resources in Avalonia/XAML. Neither contains sensitive credentials.
       recommendation: Ignore this finding as it is a false positive triggered by keywords related to UI functionality.
------------------------------------------------------------------------------------------------------------------------------------------------

Scan complete (scanner + AI).
```

## Project Modules

- cli.py: command parsing, orchestration, terminal report rendering
- scanner.py: repository preparation (clone/copy) and scan kickoff
- analyzer.py: static analysis rules and finding generation
- ai_audit.py: Gemini prompt construction and AI call
- models.py: shared data model types

## Troubleshooting

Command not found (repo-shield):

- Activate your environment first
- Or run module install again: python -m pip install -e .

AI quota/rate limit errors:

- Re-run with --no-ai
- Or reduce load with --max-files

No findings when expected:

- Confirm you are scanning the intended path/repository
- Verify target files are not inside skipped directories (.git, .venv, node_modules, **pycache**)
