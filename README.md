# Asynchronous Linux Log & Event Analyzer

An asynchronous Python service built with FastAPI and Pydantic v2 to ingest, validate, and compute error metrics from raw Linux syslog streams.

## Features
* **Pattern Recognition:** Regex-based log ingestion separating system warnings, kernel errors, and standard process telemetry.
* **Schema Validation:** Strict type-checking and validation for incoming payload lists using Pydantic v2.
* **Real-time Metrics:** High-throughput JSON response detailing error frequencies and isolating critical failures.

## Quickstart

```bash
git clone [https://github.com/christianfever31-commits/log-analyzer-async.git](https://github.com/christianfever31-commits/log-analyzer-async.git)
cd log-analyzer-async
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload
