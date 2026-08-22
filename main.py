import re
from typing import List
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field

app = FastAPI(
    title="Linux Log Analyzer & Telemetry Engine",
    description="Asynchronous engine for parsing raw Linux system logs, extracting severity levels, and computing error rates.",
    version="1.0.0",
)

class LogPayload(BaseModel):
    raw_logs: List[str] = Field(
        example=[
            "Aug 22 14:10:01 ubuntu-server systemd[1]: Started System Logging Service.",
            "Aug 22 14:10:05 ubuntu-server kernel: [ERROR] Out of memory: Kill process 8912 (python3).",
            "Aug 22 14:10:10 ubuntu-server sshd[2041]: [WARNING] Failed password for invalid user admin."
        ]
    )

class LogAnalysisResponse(BaseModel):
    total_lines_parsed: int
    error_count: int
    warning_count: int
    info_count: int
    flagged_entries: List[str]

# Simple syslog pattern extractor
LOG_PATTERN = re.compile(r"\[(ERROR|WARNING|INFO)\]|ERROR|WARNING")

@app.post("/parse-logs", response_model=LogAnalysisResponse, status_code=status.HTTP_200_OK)
async def parse_syslog(payload: LogPayload):
    """
    Ingests raw Linux syslog lines, categorizes entry severity, and isolates high-priority system alerts.
    """
    if not payload.raw_logs:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Log payload cannot be empty."
        )

    errors = 0
    warnings = 0
    info = 0
    flagged = []

    for line in payload.raw_logs:
        upper_line = line.upper()
        if "ERROR" in upper_line:
            errors += 1
            flagged.append(line)
        elif "WARNING" in upper_line or "WARN" in upper_line:
            warnings += 1
            flagged.append(line)
        else:
            info += 1

    return LogAnalysisResponse(
        total_lines_parsed=len(payload.raw_logs),
        error_count=errors,
        warning_count=warnings,
        info_count=info,
        flagged_entries=flagged
    )
