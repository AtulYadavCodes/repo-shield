from dataclasses import dataclass


@dataclass
class AuditTask:
    file_path: str
    reason: str
    language: str
