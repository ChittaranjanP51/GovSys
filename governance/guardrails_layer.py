"""Runtime guardrails (input + output) built on Guardrails AI.

Validators are implemented locally (no Guardrails Hub token needed, fully offline) and
registered with Guardrails AI so they compose into `Guard` objects. If the guardrails
package cannot be imported, the same validators run natively, so protection never
silently disappears.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# ------------------------------------------------------------------ detectors
INJECTION_PATTERNS = [
    r"ignore (all |any )?(the )?(previous|prior|above) (instructions|rules)",
    r"disregard (your|the|all) (rules|instructions|guidelines|policy|policies)",
    r"you are now (in )?(dan|developer mode|unrestricted|jailbroken)",
    r"(reveal|print|show|repeat) (me )?(your|the) (system prompt|hidden instructions)",
    r"act as (an? )?(admin|administrator|root|superuser)",
    r"(bypass|disable|turn off) (the )?(guardrails?|policy|policies|security|filters?)",
    r"pretend (that )?you (have|are) no (rules|restrictions)",
]
CODE_INJECTION_PATTERNS = [
    r";\s*(drop|delete|truncate|alter|grant|revoke)\s+",
    r"\bunion\s+select\b",
    r"\bor\s+1\s*=\s*1\b",
    r"--\s*$",
    r"\bselect\b.+\bfrom\b\s+(iam|gov|pg_)",
    r"<script\b",
]
TOXIC_TERMS = ["kill yourself", "idiot", "stupid bot", "i will hurt"]

PII_PATTERNS = {
    "email": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
    "phone": r"\+?\d{1,3}[-\s]?\d{2,5}[-\s]?\d{3,5}[-\s]?\d{3,6}",
    "card_number": r"\b(?:\d[ -]?){13,19}\b",
    "national_id": r"\bNID-\d{4}-\d{4}\b",
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
}
SECRET_PATTERNS = {
    "password_hash": r"pbkdf2_sha256\$",
    "private_key": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    "api_key": r"\b(sk|pk|lf)-[A-Za-z0-9_-]{16,}\b",
    "jwt": r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
}
MAX_INPUT_CHARS = 2000


def _luhn(num: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", num)][::-1]
    if not 13 <= len(digits) <= 19:
        return False
    total = sum(d if i % 2 == 0 else (d * 2 - 9 if d * 2 > 9 else d * 2) for i, d in enumerate(digits))
    return total % 10 == 0


def find_pii(text: str, kinds=None) -> dict[str, list[str]]:
    hits = {}
    for kind, pat in PII_PATTERNS.items():
        if kinds and kind not in kinds:
            continue
        found = re.findall(pat, text)
        if kind == "card_number":
            found = [f for f in found if _luhn(f)]
        if found:
            hits[kind] = found
    return hits


def redact(text: str, hits: dict[str, list[str]]) -> str:
    for kind, values in hits.items():
        for v in sorted(set(values), key=len, reverse=True):
            text = text.replace(v, f"[REDACTED_{kind.upper()}]")
    return text


@dataclass
class GuardOutcome:
    passed: bool
    text: str                         # possibly redacted text to continue with
    violations: list[str] = field(default_factory=list)
    redactions: dict = field(default_factory=dict)
    engine: str = "native"

    @property
    def detail(self) -> str:
        if not self.passed:
            return "; ".join(self.violations)
        if self.redactions:
            return "passed with redaction of " + ", ".join(f"{k}x{len(v)}" for k, v in self.redactions.items())
        return "no violations"


# ------------------------------------------------------- native validators
def v_prompt_injection(text: str) -> str | None:
    low = text.lower()
    for p in INJECTION_PATTERNS:
        if re.search(p, low):
            return f"prompt-injection pattern detected ({p.split(' ')[0]}...)"
    return None


def v_code_injection(text: str) -> str | None:
    low = text.lower()
    for p in CODE_INJECTION_PATTERNS:
        if re.search(p, low, re.MULTILINE):
            return "SQL/code-injection pattern detected"
    return None


def v_toxicity(text: str) -> str | None:
    low = text.lower()
    return "abusive language detected" if any(t in low for t in TOXIC_TERMS) else None


def v_length(text: str) -> str | None:
    return f"input exceeds {MAX_INPUT_CHARS} characters" if len(text) > MAX_INPUT_CHARS else None


def v_restricted_data(text: str) -> str | None:
    return "restricted data (national ID) present in output" if re.search(PII_PATTERNS["national_id"], text) else None


def v_secrets(text: str) -> str | None:
    for kind, pat in SECRET_PATTERNS.items():
        if re.search(pat, text):
            return f"secret material ({kind}) present in output"
    return None


INPUT_BLOCKERS = [v_length, v_prompt_injection, v_code_injection, v_toxicity]
OUTPUT_BLOCKERS = [v_restricted_data, v_secrets]

# ----------------------------------------------------- Guardrails AI binding
try:
    from guardrails import Guard
    from guardrails.classes.rc import RC
    from guardrails.settings import settings as _gr_settings
    from guardrails.utils.hub_telemetry_utils import HubTelemetry
    from guardrails.validator_base import (FailResult, PassResult, Validator,
                                           register_validator)

    # Data sovereignty: Guardrails AI ships hub telemetry to a remote endpoint by
    # default, and every Guard() re-reads ~/.guardrailsrc (default: metrics ON).
    # Pin the config in-process so nothing ever leaves the machine.
    _LOCAL_RC = RC(enable_metrics=False, use_remote_inferencing=False)
    RC.load = classmethod(lambda cls, logger=None: _LOCAL_RC)
    _gr_settings.rc = _LOCAL_RC
    _gr_settings.disable_tracing = True
    HubTelemetry(enabled=False)._enabled = False

    def _wrap(name: str, fn):
        @register_validator(name=f"govsys/{name}", data_type="string")
        class _V(Validator):
            def _validate(self, value, metadata):  # noqa: D401
                msg = fn(value)
                return FailResult(error_message=msg) if msg else PassResult()
        _V.__name__ = name
        return _V

    _INPUT_GUARD = Guard(name="govsys-input").use(*[_wrap(f.__name__, f)(on_fail="noop") for f in INPUT_BLOCKERS])
    _OUTPUT_GUARD = Guard(name="govsys-output").use(*[_wrap(f.__name__, f)(on_fail="noop") for f in OUTPUT_BLOCKERS])
    ENGINE = "guardrails-ai"
except Exception:  # noqa: BLE001 - fall back to the identical native validators
    _INPUT_GUARD = _OUTPUT_GUARD = None
    ENGINE = "native"


def _run(guard, blockers, text: str) -> list[str]:
    if guard is not None:
        try:
            res = guard.validate(text)
            fails = [s.failure_reason or s.validator_name for s in (res.validation_summaries or [])
                     if s.validator_status == "fail"]
            if res.validation_passed is False and not fails:
                fails = ["guardrails validation failed"]
            return fails
        except Exception:  # noqa: BLE001
            pass
    return [m for m in (b(text) for b in blockers) if m]


def check_input(text: str) -> GuardOutcome:
    violations = _run(_INPUT_GUARD, INPUT_BLOCKERS, text)
    if violations:
        return GuardOutcome(False, text, violations, engine=ENGINE)
    # Sensitive identifiers typed by the user are redacted before reaching any LLM.
    hits = find_pii(text, kinds={"card_number", "national_id", "ssn"})
    return GuardOutcome(True, redact(text, hits), redactions=hits, engine=ENGINE)


def check_output(text: str, pii_allowed: bool) -> GuardOutcome:
    violations = _run(_OUTPUT_GUARD, OUTPUT_BLOCKERS, text)
    if violations:
        return GuardOutcome(False, "", violations, engine=ENGINE)
    kinds = {"card_number", "ssn"} | (set() if pii_allowed else {"email", "phone"})
    hits = find_pii(text, kinds=kinds)
    return GuardOutcome(True, redact(text, hits), redactions=hits, engine=ENGINE)
