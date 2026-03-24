# repo_shield

repo_shield scans Git repositories for risky patterns and supports both terminal and Streamlit dashboard workflows.

## Current Project Layout

```
newsecuri/
|-- __init__.py
|-- cli.py
|-- scanner.py
|-- analyzer.py
|-- ai_audit.py
|-- models.py
|-- streamlit_app.py
|-- pyproject.toml
|-- README.md
|-- .env
```

## Features

- Entropy-based secret detection
- Hardcoded credential pattern detection
- JWT token detection
- AWS key pattern detection
- Dependency checks in requirements.txt and package.json
- AI audit with Gemini and auto-retry for quota limits
- Dashboard charts (language distribution, reasons, finding table)

## Setup

```bash
pip install -e .
```

Add your API key in `.env`:

```env
GOOGLE_API_KEY=your_key_here
```

## Start

Default behavior (CLI starts Streamlit dashboard automatically):

```bash
repo-shield https://github.com/user/repo
```

Headless dashboard mode:

```bash
repo-shield https://github.com/user/repo --headless
```

Terminal-only mode (no Streamlit UI):

```bash
repo-shield https://github.com/user/repo --no-ui
```

Terminal-only scan without AI calls:

```bash
repo-shield https://github.com/user/repo --no-ui --no-ai
```

Run Streamlit directly:

```bash
streamlit run streamlit_app.py
```
