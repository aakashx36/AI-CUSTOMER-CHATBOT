import logging
import json
import os

LOG_DIR = "backend"
LOG_FILE = os.path.join(LOG_DIR, "app.log")

# Ensure Directory Exists
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR, exist_ok=True)

logger = logging.getLogger("genai_telemetry")
logger.setLevel(logging.INFO)

if not logger.handlers:
    # Console Handler (Live Output)
    console_handler = logging.StreamHandler()
    logger.addHandler(console_handler)

    # File Handler (Physical Record Persistence)
    file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
    logger.addHandler(file_handler)

def _log_event(level: str, event_data: dict):
    log_entry = json.dumps(event_data)
    if level == "warning":
        logger.warning(log_entry)
    else:
        logger.info(log_entry)
        
    # Force instant flush to app.log
    for handler in logger.handlers:
        handler.flush()

def log_safety_event(user_id: str, event_type: str, details: str):
    _log_event("warning", {
        "event_category": "SAFETY_EVENT",
        "user_id": user_id,
        "event_type": event_type,
        "details": details
    })