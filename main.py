import re
from typing import List
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field

app = FastAPI(
    title="Linux Log Analyzer & Telemetry Engine",
    description="Asynchronous engine for parsing raw Linux system logs using robust regex patterns, extracting severity levels, and computing metrics.",
    version="1.1.0",
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

# Robust regex pattern to catch explicitly bracketed or standalone severity tags
LOG_PATTERN = re.compile(r"\[(ERROR|WARNING|INFO)\]|\b(ERROR|WARNING|INFO|WARN)\b", re.IGNORECASE)

@app.post("/parse-logs", response_model=LogAnalysisResponse, status_code=status.HTTP_200_OK)
async def parse_syslog(payload: LogPayload):
    """
    Ingests raw Linux syslog lines, categorizes entry severity using regex search, and isolates alerts.
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
        match = LOG_PATTERN.search(line)
        if match:
            # Extract matched group from either group 1 or group 2
            severity = next((g for g in match.groups() if g), "").upper()
            if "ERROR" in severity:
                errors += 1
                flagged.append(line)
            elif "WARN" in severity:
                warnings += 1
                flagged.append(line)
            else:
                info += 1
        else:
            info += 1

    return LogAnalysisResponse(
        total_lines_parsed=len(payload.raw_logs),
        error_count=errors,
        warning_count=warnings,
        info_count=info,
        flagged_entries=flagged
    )
