import re
from typing import Tuple, Dict, Any
from backend.telemetry import log_safety_event

# 1. Advanced Blocked Patterns (Jailbreak, Ethics Bypass, Instruction Injection)
_BLOCKED_PATTERNS_LIST = [
    r"ignore\s+(all\s+)?(previous\s+)?instructions",
    r"ignore\s+(system\s+)?prompt",
    r"bypass\s+safety",
    r"disable\s+ethics",
    r"forget\s+ethics",
    r"act\s+as\s+an\s+unfiltered",
    r"do\s+anything\s+now",
    r"dan\s+mode",
    r"jailbreak",
    r"delete\s+from",
    r"drop\s+table",
    r"reveal\s+api\s+key",
]

# Pre-compiled Master Combined Regex for Max Performance
_COMBINED_BLOCKED_REGEX = re.compile(
    "|".join(f"({p})" for p in _BLOCKED_PATTERNS_LIST),
    flags=re.IGNORECASE
)

# 2. PII Patterns (Credit Card, SSN, Phone Numbers)
_PII_PATTERNS = {
    "credit_card": re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "phone": re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")
}

# 3. Off-Topic / Out of Domain Keywords (Random Context Detection)
_OUT_OF_DOMAIN_PATTERNS = re.compile(
    r"\b(tell\s+me\s+a\s+joke|who\s+won\s+the\s+match|write\s+a\s+poem|recipe\s+for|capital\t+of)\b",
    flags=re.IGNORECASE
)

def evaluate_input_safety(user_id: str, user_text: str) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Evaluates input text for:
    1. Empty/Overlength bounds
    2. Prompt Injection & Ethics Bypass
    3. Sensitive PII Leaks
    4. Out-of-Domain/Random Context Fallback
    """
    clean_text = user_text.strip()
    
    # Check 1: Empty or Bounds
    if not clean_text:
        return False, "Input message cannot be empty.", {"status": "REJECTED_EMPTY"}
        
    if len(clean_text) > 2000:
        return False, "Input exceeds maximum allowed length of 2000 characters.", {"status": "REJECTED_OVERLENGTH"}

    # Check 2: Prompt Injection / Safety Violation
    match = _COMBINED_BLOCKED_REGEX.search(clean_text)
    if match:
        violation = match.group(0)
        # Log to telemetry.py instantly
        log_safety_event(
            user_id=user_id,
            event_type="PROMPT_INJECTION_ATTEMPT",
            details=f"Matched policy rule: '{violation}'"
        )
        return False, "Security Policy Violation: I cannot process commands that attempt to bypass safety instructions or ethical guardrails.", {"status": "BLOCKED_SECURITY"}

    # Check 3: PII Detection & Sanitization
    for pii_type, compiled_regex in _PII_PATTERNS.items():
        if compiled_regex.search(clean_text):
            log_safety_event(
                user_id=user_id,
                event_type="PII_EXPOSURE_PREVENTED",
                details=f"Detected unencrypted PII ({pii_type})"
            )
            return False, f"Sensitive Information Detected: Please remove {pii_type} details before sending.", {"status": "BLOCKED_PII"}

    # Check 4: Out-of-Domain / Random Context Handler
    if _OUT_OF_DOMAIN_PATTERNS.search(clean_text):
        return False, "I am a Customer Service Virtual Assistant. I can only assist with account support, orders, and service inquiries. How can I help you with your account today?", {"status": "OUT_OF_SCOPE"}

    # Passed All Safety Checks
    return True, "Passed safety checks.", {"status": "PASSED"}