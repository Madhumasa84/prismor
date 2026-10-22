"""Consistency boundary for research recordings, not provider attestation.

The evaluator must retain this boundary/its exported manifest independently of
editable result rows. A process owner who rewrites both is outside this model.
Offline parsers are registered only on explicitly fixture-scoped boundaries.
"""
from copy import deepcopy

from .judge import reply_record
from .model_io import VERIFIED_ADAPTERS, sha

AGGREGATIONS = frozenset({'single-v1', 'all-required-v1', 'selective-v1'})


def aggregate(decisions, version):
    if version not in AGGREGATIONS or not decisions:
        raise ValueError('unknown or empty aggregation')
    if version == 'single-v1':
        if len(decisions) != 1:
            raise ValueError('single requires exactly one attempt')
        return decisions[0]
    if version == 'selective-v1':
        required = 2 if decisions[0] == 'unresolved_semantics' else 1
        if len(decisions) != required:
            raise ValueError('selective route requires all and only declared stages')
        return decisions[-1]
    for decision in ('deny', 'missing_authorization', 'unresolved_semantics', 'allow'):
        if decision in decisions:
            return decision
    raise ValueError('invalid decisions')


class RecordingBoundary:
    def __init__(self, *, kind='genuine_live', parsers=None):
        if kind not in ('genuine_live', 'test_fixture'):
            raise ValueError('invalid recording kind')
        self.kind = kind
        self.parsers = dict(parsers or {})
        if kind == 'genuine_live' and any(a not in VERIFIED_ADAPTERS for a, _ in self.parsers):
            raise ValueError('no verified live adapter')
        self._records, self._plans = {}, {}

    @classmethod
    def from_trusted_manifest(cls, manifest, *, parsers):
        """Caller must authenticate/protect this manifest independently of rows."""
        if manifest.get('version') != 1:
            raise ValueError('unsupported recording manifest')
        result = cls(kind=manifest['kind'], parsers=parsers)
        result._records = deepcopy(manifest['records'])
        for plan in manifest['plans']:
            result.declare(*plan['key'], plan['identities'], aggregation=plan['aggregation'])
        return result

    def declare(self, case_id, configuration_id, evaluation, identities, *, aggregation='single-v1'):
        """Call before executing; identities include conditioning/config/version."""
        if aggregation not in AGGREGATIONS or not identities:
            raise ValueError('explicit aggregation and required attempts needed')
        for identity in identities:
            if (identity.get('adapter'), identity.get('parser_version')) not in self.parsers:
                raise ValueError('unregistered parser')
            if identity.get('aggregation_version') != aggregation:
                raise ValueError('aggregation binding mismatch')
        key = (case_id, configuration_id, evaluation)
        if key in self._plans:
            raise ValueError('duplicate decision declaration')
        self._plans[key] = deepcopy({'identities': identities, 'aggregation': aggregation})

    def capture(self, record, parser):
        identity = record['request_identity']
        if self.parsers.get((identity.get('adapter'), identity.get('parser_version'))) is not parser:
            raise ValueError('parser not registered at recording boundary')
        if record['provenance'] != self.kind:
            raise ValueError('recording provenance mismatch')
        result = deepcopy(record)
        rid = str(len(self._records))
        result['recording_id'] = rid
        self._records[rid] = sha(result)
        return result

    def validate_attempt(self, record, identity):
        if self._records.get(record.get('recording_id')) != sha(record):
            raise ValueError('record differs from authoritative recording')
        if (record['request_identity'] != identity or record['request_identity_sha256'] != sha(identity)
                or record['request_input_sha256'] != sha(identity['judge_input'])
                or record['actual_model_version'] != identity['model_version']
                or record['provenance'] != self.kind or record['status'] != 'valid'):
            raise ValueError('invalid request/version/provenance binding')
        parser = self.parsers[(identity['adapter'], identity['parser_version'])]
        normalized = reply_record(parser(deepcopy(record['raw_response'])))
        if normalized != record['normalized'] or normalized['status'] != 'judgment':
            raise ValueError('normalization mismatch')
        return normalized['decision']

    def decision(self, row, expected_input):
        plan = self._plans[(row['case_id'], row['configuration_id'], row['evaluation'])]
        attempts = row.get('model_attempts', [])
        identities = plan['identities']
        if len({a.get('recording_id') for a in attempts}) != len(attempts):
            raise ValueError('a required attempt cannot reuse another recording')
        required = len(identities)
        if plan['aggregation'] == 'selective-v1':
            if len(identities) != 2 or not attempts:
                raise ValueError('selective plan requires two possible stages')
            first = self.validate_attempt(attempts[0], identities[0])
            required = 2 if first == 'unresolved_semantics' else 1
        identities = identities[:required]
        if (len(attempts) != required or row.get('model_call_count') != len(attempts)
                or row.get('judges_actually_run') != [i['adapter'] for i in identities]
                or row.get('response_provenance') != self.kind):
            raise ValueError('incomplete or mismatched required attempts')
        if any(i['judge_input'] != expected_input for i in identities):
            raise ValueError('case input mismatch')
        decisions = [self.validate_attempt(a, i) for a, i in zip(attempts, identities)]
        result = aggregate(decisions, plan['aggregation'])
        if (row.get('aggregation_version') != plan['aggregation']
                or (row.get('judge_decision') or {}).get('decision') != result):
            raise ValueError('summary/aggregation mismatch')
        return result

    def manifest(self):
        return {'version': 1, 'kind': self.kind, 'records': deepcopy(self._records),
                'plans': [{'key': list(k), **deepcopy(v)} for k, v in self._plans.items()]}
