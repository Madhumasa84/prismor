"""Transport-neutral research plumbing; NO concrete model adapter is verified.

Future verified adapters must dispatch every underlying inference through Budget,
including each retry/question, and normalize only against their documented API.
Nothing here defines a provider request/response schema or reads credentials.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import math
import time

from .judge import JudgeError, Judgment, reply_record

INTERFACE_FIELDS = ("adapter", "endpoint_or_checkpoint", "request_schema", "response_schema",
                    "policy_conditioning", "model_version", "generation_parameters",
                    "authentication", "interface_evidence")
# Deliberately empty until a supplied protocol is verified and implemented.
VERIFIED_ADAPTERS = frozenset()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def sha(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def missing_prerequisites(config):
    missing = [field for field in INTERFACE_FIELDS if config.get(field) is None
               or (field == "interface_evidence" and not config.get(field))]
    if config.get("adapter") not in VERIFIED_ADAPTERS:
        missing.append("implemented verified adapter")
    if config.get("available") is not True:
        missing.append("available configuration")
    return missing


class Budget:
    """One reservation immediately before EACH inference request; no retries here."""
    def __init__(self, settings, cap, *, decision_timeout_seconds=None):
        enabled, maximum = settings.get("LIVE_MODEL_RUN"), settings.get("MAX_REAL_REQUESTS")
        if type(enabled) is not bool or type(maximum) is not int or maximum < 0:
            raise ValueError("invalid live settings")
        if type(cap) is not int or cap < 0:
            raise ValueError("invalid request cap")
        self.enabled = enabled
        self.limit = min(maximum, cap)
        self.requests = 0
        if decision_timeout_seconds is not None and (
                not math.isfinite(decision_timeout_seconds) or decision_timeout_seconds <= 0):
            raise ValueError("positive decision deadline required")
        self.deadline = (time.monotonic() + decision_timeout_seconds
                         if decision_timeout_seconds is not None else None)

    def remaining(self):
        if self.deadline is None:
            return None
        return max(0, self.deadline - time.monotonic())

    def reserve(self):
        if not self.enabled or self.requests >= self.limit:
            raise PermissionError("real inference disabled or request budget exhausted")
        if self.remaining() == 0:
            raise TimeoutError("overall decision deadline exhausted before request")
        self.requests += 1


def request_identity(request, *, model_version, inference_configuration, conditioning,
                     adapter=None, parser_version=None, aggregation_version=None):
    if not model_version:
        raise ValueError("exact model/version is required")
    # Full input includes trusted policy/task, authorization and source/context.
    return {"adapter": adapter, "parser_version": parser_version,
            "aggregation_version": aggregation_version, "judge_input": json.loads(request.serialized_input),
            "model_version": model_version,
            "inference_configuration": deepcopy(inference_configuration),
            "conditioning": deepcopy(conditioning)}


def redact(value, secrets):
    """Synthetic responses may be retained; credential VALUES never are."""
    if isinstance(value, str):
        for secret in secrets:
            if secret:
                value = value.replace(secret, "[credential redacted]")
        return value
    if isinstance(value, dict):
        return {redact(k, secrets): redact(v, secrets) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v, secrets) for v in value]
    return value


def dispatch(budget, identity, send, parse, *, timeout_seconds, output_limit,
             provenance="test_fixture", credential_values=(), boundary=None,
             retained_response_bytes=65536):
    """Common attempt recorder for future adapters and explicit offline tests.

    send returns a provider envelope: raw_response, actual_model_version, optional
    usage/monetary_cost. These are INTERNAL fields, not an invented provider API.
    parse is a verified adapter's normalizer. Callers must redact credential
    values and enforce the limits in their transport. No automatic fallback.
    """
    if (not isinstance(timeout_seconds, (int, float)) or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0 or type(output_limit) is not int or output_limit <= 0):
        raise ValueError("positive finite timeout and output limit required")
    if (identity["inference_configuration"].get("output_limit") != output_limit
            or identity["inference_configuration"].get("timeout_seconds") != timeout_seconds):
        raise ValueError("attempt limits must match hashed inference configuration")
    if provenance != "test_fixture":
        if (boundary is None or boundary.kind != "genuine_live"
                or identity.get("adapter") not in VERIFIED_ADAPTERS):
            raise ValueError("genuine execution requires a verified live recording adapter")
    if type(retained_response_bytes) is not int or retained_response_bytes <= 0:
        raise ValueError("positive retained response byte cap required")
    if boundary is not None and boundary.parsers.get(
            (identity.get("adapter"), identity.get("parser_version"))) is not parse:
        raise ValueError("parser not registered at recording boundary")
    budget.reserve()  # Before send OR credential resolution in a future adapter.
    started = time.perf_counter()
    record = {"provenance": provenance, "request_identity": deepcopy(identity),
              "request_input_sha256": sha(identity["judge_input"]),
              "request_identity_sha256": sha(identity), "raw_response": None,
              "actual_model_version": None, "normalized": None, "usage": None,
              "monetary_cost": None, "timeout_seconds": timeout_seconds,
              "output_limit": output_limit, "provider_generation_token_cap": output_limit,
              "retained_response_byte_cap": retained_response_bytes,
              "overall_deadline_configured": budget.deadline is not None,
              "underlying_attempt_accounting": "one_callback; hidden retries unverified",
              "status": None, "error": None}
    try:
        remaining = budget.remaining()
        effective_timeout = min(timeout_seconds, remaining) if remaining is not None else timeout_seconds
        envelope = send(timeout_seconds=effective_timeout, output_limit=output_limit)
        raw = envelope["raw_response"]
        raw_bytes = canonical(raw).encode("utf-8")
        record["response_bytes"] = len(raw_bytes)
        if len(raw_bytes) > retained_response_bytes:
            record["discarded_response_sha256"] = hashlib.sha256(raw_bytes).hexdigest()
            raise ValueError("retained response byte cap exceeded")
        record["raw_response"] = deepcopy(raw)
        record["actual_model_version"] = envelope.get("actual_model_version")
        record["usage"] = deepcopy(envelope.get("usage"))
        record["monetary_cost"] = deepcopy(envelope.get("monetary_cost"))
        if time.perf_counter() - started > effective_timeout or budget.remaining() == 0:
            raise TimeoutError("callback returned after deadline; cancellation not established")
        result = parse(deepcopy(record["raw_response"]))
        if budget.remaining() == 0:
            raise TimeoutError("overall decision deadline exhausted during normalization")
        if not isinstance(result, (Judgment, JudgeError)):
            result = JudgeError("invalid_output", "normalizer returned an invalid type")
        if record["actual_model_version"] != identity["model_version"]:
            result = JudgeError("invalid_output", "requested/actual model version mismatch")
        record["normalized"] = reply_record(result)
        record["status"] = "valid" if isinstance(result, Judgment) else result.kind
    except TimeoutError:
        record.update(status="timeout", error="inference request timed out")
    except (ValueError, KeyError, TypeError):
        record.update(status="invalid_output", error="response or normalizer contract invalid")
    except Exception as exc:
        # Exception messages may contain credentials, URLs or request bodies.
        record.update(status="unavailable", error=type(exc).__name__)
    record["measured_attempt_ms"] = (time.perf_counter() - started) * 1000
    record["parsing_status"] = "valid" if record["status"] == "valid" else "invalid" if record["status"] == "invalid_output" else "not_completed"
    record["live_latency_ms"] = record["measured_attempt_ms"] if provenance == "genuine_live" else None
    record = redact(record, credential_values)
    return boundary.capture(record, parse) if boundary is not None else record


def replay(record, identity, *, boundary=None):
    """Replay only through the independently retained trusted recording boundary.

    Digests establish consistency, not remote inference or provider provenance.
    Fixture replay remains labelled a fixture and supplies no live latency.
    """
    started = time.perf_counter()
    if boundary is None:
        raise ValueError("replay requires an authoritative recording boundary")
    try:
        boundary.validate_attempt(record, identity)
    except (KeyError, TypeError) as exc:
        raise ValueError("invalid replay evidence") from exc
    result = deepcopy(record)
    result.update(provenance="offline_replay", recording_kind=boundary.kind, live_latency_ms=None,
                  original_live_latency_ms=record.get("live_latency_ms"),
                  replay_processing_ms=(time.perf_counter() - started) * 1000)
    return result
