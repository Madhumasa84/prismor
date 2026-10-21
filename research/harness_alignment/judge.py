"""Research-only judgment contract. No Niti API or inference implementation."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass, field
import hashlib
import json
from typing import Protocol, Union

from .casebook import ROOT, serialize_judge_request

DECISIONS = {"allow", "deny", "missing_authorization", "unresolved_semantics"}
ERRORS = {"invalid_output", "timeout", "unavailable"}
EXPERIMENTS = ("native-rules", "scripted-fast", "scripted-stronger", "scripted-selective")


def action_hash(action):
    return hashlib.sha256(json.dumps(action, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True)
class JudgeRequest:
    serialized_input: str
    action_sha256: str

    @classmethod
    def from_input(cls, visible_input):
        serialized = serialize_judge_request({"input": visible_input})
        return cls(serialized, action_hash(json.loads(serialized)["proposed_action"]))


@dataclass(frozen=True)
class Judgment:
    decision: str
    reason: str
    # Preserve the complete original payload. No synthesized confidence field.
    native_fields: dict = field(default_factory=dict)

    def __post_init__(self):
        if (not isinstance(self.decision, str) or self.decision not in DECISIONS
                or not isinstance(self.reason, str) or not self.reason.strip()
                or not isinstance(self.native_fields, dict)):
            raise ValueError("invalid research judgment")
        json.dumps(self.native_fields)


@dataclass(frozen=True)
class JudgeError:
    kind: str
    message: str
    native_fields: object = None

    def __post_init__(self):
        if self.kind not in ERRORS:
            raise ValueError("unknown research judge error")


Reply = Union[Judgment, JudgeError]


class Judge(Protocol):
    name: str
    provenance: dict

    def judge(self, request: JudgeRequest) -> Reply:
        ...


class ScriptedJudge:
    """Consume explicit fixture outcomes in order; never read casebook labels.

    A fresh instance is created for each case. Exhaustion is an error, not an
    implicit allow, retry, or cached answer. Timeout errors are simulations.
    """
    def __init__(self, name, outcomes):
        self.name = name
        self.provenance = {"kind": "scripted", "judge": name}
        self._outcomes = iter(deepcopy(outcomes))
        self.requests = []

    def judge(self, request):
        self.requests.append(request)
        raw = next(self._outcomes, {"error": "unavailable", "message": "script exhausted"})
        if isinstance(raw, dict):
            if isinstance(raw.get("error"), str) and raw["error"] in ERRORS:
                return JudgeError(raw["error"], str(raw.get("message", "scripted error")), deepcopy(raw))
            if (isinstance(raw.get("decision"), str) and raw["decision"] in DECISIONS
                    and isinstance(raw.get("reason"), str) and raw["reason"].strip()):
                return Judgment(raw["decision"], raw["reason"], deepcopy(raw))
        return JudgeError("invalid_output", "script did not produce a valid judgment", deepcopy(raw))


def reply_record(reply):
    return {"status": "judgment" if isinstance(reply, Judgment) else "error", **deepcopy(asdict(reply))}


def configuration(experiment):
    if experiment not in EXPERIMENTS:
        raise ValueError(f"unknown experimental mode: {experiment}")
    controls = json.loads((ROOT / "scripted_controls.json").read_text())
    return {"experiment": experiment, **deepcopy(controls[experiment])}
