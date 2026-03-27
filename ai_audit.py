import os
import re
import time
import json
from typing import Any

from google import genai

from models import AuditTask


class GeminiAuditor:
    def __init__(self, api_key: str | None = None, model: str = "gemini-3-flash-preview"):
        self.api_key = api_key or os.getenv("GOOGLE_API_KEY")
        if not self.api_key:
            raise ValueError("GOOGLE_API_KEY is not set.")
        self.client = genai.Client(api_key=self.api_key)
        self.model = model

    def _extract_json_block(self, text: str) -> dict[str, Any]:
        raw = (text or "").strip()
        if not raw:
            raise ValueError("Empty model response")

        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                return data
        except Exception:
            pass

        fenced = re.search(r"```(?:json)?\s*(\{[\s\S]*\})\s*```", raw, re.IGNORECASE)
        if fenced:
            data = json.loads(fenced.group(1))
            if isinstance(data, dict):
                return data

        first = raw.find("{")
        last = raw.rfind("}")
        if first != -1 and last != -1 and last > first:
            data = json.loads(raw[first : last + 1])
            if isinstance(data, dict):
                return data

        raise ValueError("Could not parse JSON object from model response")

    def _normalize_structured_result(self, data: dict[str, Any]) -> dict[str, Any]:
        steps = data.get("reasoning_steps")
        if not isinstance(steps, dict):
            steps = {}

        step_1 = str(
            steps.get("step_1_classify_issue")
            or data.get("step_1_classify_issue")
            or ""
        ).strip()
        step_2 = str(
            steps.get("step_2_verify_context")
            or data.get("step_2_verify_context")
            or ""
        ).strip()
        step_3 = str(
            steps.get("step_3_suggest_fix")
            or data.get("step_3_suggest_fix")
            or ""
        ).strip()

        confidence_raw = data.get("confidence", 0)
        try:
            confidence = float(confidence_raw)
        except Exception:
            confidence = 0.0
        confidence = max(0.0, min(1.0, confidence))

        is_vulnerability = data.get("is_vulnerability")
        if isinstance(is_vulnerability, str):
            is_vulnerability = is_vulnerability.strip().lower() in {"true", "1", "yes"}
        else:
            is_vulnerability = bool(is_vulnerability)

        vuln_type = str(data.get("type") or "unknown").strip() or "unknown"
        fix = str(data.get("fix") or "No fix provided").strip() or "No fix provided"

        return {
            "is_vulnerability": is_vulnerability,
            "confidence": confidence,
            "type": vuln_type,
            "fix": fix,
            "reasoning_steps": {
                "step_1_classify_issue": step_1,
                "step_2_verify_context": step_2,
                "step_3_suggest_fix": step_3,
            },
        }

    def audit_code(self, task: AuditTask, code: str, max_retries: int = 1) -> dict[str, Any]:
        attempt = 0
        while attempt <= max_retries:
            try:
                response = self.client.models.generate_content(
                    model=self.model,
                    contents=(
                        "You are a strict security code auditor. "
                        "Audit ONLY the code provided. Do not guess.\n\n"
                        f"Language: {task.language}\n"
                        f"Flag Reason: {task.reason}\n\n"
                        "Perform this exact reasoning flow:\n"
                        "Step 1: classify issue\n"
                        "Step 2: verify context\n"
                        "Step 3: suggest fix\n\n"
                        "Return ONLY valid JSON with this exact shape:\n"
                        "{\n"
                        '  "is_vulnerability": true,\n'
                        '  "confidence": 0.87,\n'
                        '  "type": "hardcoded_secret",\n'
                        '  "fix": "use env variable",\n'
                        '  "reasoning_steps": {\n'
                        '    "step_1_classify_issue": "...",\n'
                        '    "step_2_verify_context": "...",\n'
                        '    "step_3_suggest_fix": "..."\n'
                        "  }\n"
                        "}\n\n"
                        "Rules:\n"
                        "- confidence must be a number in [0,1].\n"
                        "- If not a real vulnerability, set is_vulnerability=false and explain why in step_2_verify_context.\n"
                        "- Keep each reasoning step concise and evidence-based.\n"
                        "- Do not include code fences, formatted sections, or extra keys.\n\n"
                        f"Code to audit (truncated if very long):\n\n{code[:5000]}"
                    ),
                )
                parsed = self._extract_json_block(response.text or "")
                return self._normalize_structured_result(parsed)
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
                if attempt <= max_retries:
                    attempt += 1
                    continue
                raise

        raise RuntimeError("Audit failed after retries.")
