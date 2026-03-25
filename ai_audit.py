import os
import re
import time

from google import genai

from models import AuditTask


class GeminiAuditor:
    def __init__(self, api_key: str | None = None, model: str = "gemini-3-flash-preview"):
        self.api_key = api_key or os.getenv("GOOGLE_API_KEY")
        if not self.api_key:
            raise ValueError("GOOGLE_API_KEY is not set.")
        self.client = genai.Client(api_key=self.api_key)
        self.model = model

    def audit_code(self, task: AuditTask, code: str, max_retries: int = 1) -> str:
        attempt = 0
        while attempt <= max_retries:
            try:
                response = self.client.models.generate_content(
                    model=self.model,
                    contents=(
                        "You are a security code auditor. "
                        f"Audit this {task.language} file. "
                        f"Reason it was flagged: {task.reason}.\n\n"
                        "Return a short, practical markdown report with:\n"
                        "1. A one-sentence summary of the main risk.\n"
                        "2. A bullet list of specific issues, each with an approximate line number or small code snippet.\n"
                        "3. Concrete fix suggestions for each issue.\n\n"
                        "Only describe issues that are truly present in the provided code.\n\n"
                        f"Code to audit (truncated if very long):\n\n{code[:5000]}"
                    ),
                )
                return response.text or "No response text returned by model."
            except Exception as exc:
                msg = str(exc)
                if "429" in msg or "RESOURCE_EXHAUSTED" in msg:
                    attempt += 1
                    if attempt > max_retries:
                        raise RuntimeError(
                            "Google Gemini API quota or rate limit exceeded. "
                            "Reduce --max-files, wait, or configure billing/quota for GOOGLE_API_KEY."
                        ) from exc

                    delay = 10
                    match = re.search(r"retry\s+in\s+([0-9]+(?:\.[0-9]+)?)s", msg, re.IGNORECASE)
                    if match:
                        delay = max(1, int(float(match.group(1))) + 1)
                    time.sleep(delay)
                    continue
                raise

        raise RuntimeError("Audit failed after retries.")
