import os

from google import genai

from models import AuditTask


class GeminiAuditor:
    def __init__(self, api_key: str | None = None, model: str = "gemini-3-flash-preview"):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY is not set.")
        self.client = genai.Client(api_key=self.api_key)
        self.model = model

    def audit_code(self, task: AuditTask, code: str, max_retries: int = 0) -> str:
        prompt = (
            "You are a security code auditor. "
            "Analyze the provided code and decide if the finding is a 'Real Vulnerability' or a 'False Positive'.\n"
            "Respond ONLY as plain text (NO JSON and NO curly braces) and keep it short and direct.\n"
            "\n"
            "status: Real Vulnerability | False Positive\n"
            
            "reason: string\n"
            "recommendation: string\n"
            "\n\n"
            f"Language: {task.language}\n"
            f"Reason: {task.reason}\n\n"
            f"Code:\n{code[:5000]}"
        )

        response = self.client.models.generate_content(model=self.model, contents=prompt)
        text = (response.text or "").strip()
        if text.startswith("{") and text.endswith("}"):
            text = text[1:-1].strip()
        return text or "No response"
