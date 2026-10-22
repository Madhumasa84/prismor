"""Offline consistency and real native-gateway fault regressions; no inference."""
from copy import deepcopy
import json
import time
from unittest.mock import patch

import pytest

import test_harness_alignment_models as fixtures
from research.harness_alignment.casebook import load
from research.harness_alignment.comparison import judge_agreement, pilot
from research.harness_alignment.evidence import RecordingBoundary, aggregate
from research.harness_alignment.model_io import Budget, VERIFIED_ADAPTERS, dispatch, replay
from research.harness_alignment.offline import RecordingUpstream
from research.harness_alignment.runner import run_cases


def score(rows, boundary=None):
    return judge_agreement(load(), rows, configuration_id='test', evaluation='judge-only',
                           label_status='provisional', boundary=boundary or fixtures.SCORE_BOUNDARY,
                           evidence_kind='test_fixture')


def test_a1_summary_cannot_override_attempts_or_booleans():
    rows = fixtures.score_rows()
    rows[1]['judge_decision']['decision'] = 'allow'
    rows[1].update(verified_adapter=True, complete_decision=True)
    assert score(rows)['completed_valid_responses'] == 1
    assert score(rows)['errors'] == 1
    assert score(rows)['unconditional_pairs']['rate'] == 0


@pytest.mark.parametrize('field', ['raw_response', 'normalized', 'actual_model_version',
                                  'parser_version', 'request_context', 'summary', 'aggregation'])
def test_a3_independent_tampering_rejected(field):
    rows = fixtures.score_rows()
    changed = rows[1]
    record = changed['model_attempts'][0]
    ident = deepcopy(record['request_identity'])
    if field == 'summary':
        changed['judge_decision']['decision'] = 'allow'
    elif field == 'aggregation':
        changed['aggregation_version'] = 'all-required-v1'
    elif field == 'parser_version':
        record['request_identity']['parser_version'] = 'fixture-v2'
    elif field == 'request_context':
        record['request_identity']['conditioning'] = {'changed': True}
    else:
        record[field] = {'changed': True} if field != 'actual_model_version' else 'v2'
    assert score(rows)['errors'] == 1
    if field not in ('summary', 'aggregation'):
        with pytest.raises(ValueError):
            replay(record, ident, boundary=fixtures.SCORE_BOUNDARY)


def test_replay_requires_boundary_and_cannot_make_live_latency():
    rows = fixtures.score_rows()
    record = rows[0]['model_attempts'][0]
    with pytest.raises(ValueError):
        replay(record, record['request_identity'])
    result = replay(record, record['request_identity'], boundary=fixtures.SCORE_BOUNDARY)
    assert result['provenance'] == 'offline_replay'
    assert result['recording_kind'] == 'test_fixture'
    assert result['live_latency_ms'] is None
    assert not VERIFIED_ADAPTERS
    with pytest.raises(ValueError):
        RecordingBoundary(parsers={('offline-test', 'fixture-v1'): fixtures.parse_fixture})
    with pytest.raises(ValueError):
        fixtures.attempt(lambda **k: fixtures.envelope(), provenance='genuine_live')


def test_r2_exact_version_mismatch_has_diagnostic_and_no_credit():
    record = fixtures.attempt(lambda **kw: fixtures.envelope(actual_model_version='v2'))
    assert record['status'] == 'invalid_output'
    assert record['actual_model_version'] == 'v2'
    assert 'mismatch' in record['normalized']['message']
    with pytest.raises(ValueError):
        replay(record, record['request_identity'], boundary=fixtures.TEST_BOUNDARY)


def test_r1_abstention_coverage_and_pair_denominators():
    rows = fixtures.score_rows()
    # Make a fresh predeclared recording, not a tampered normalized result.
    boundary = RecordingBoundary(kind='test_fixture', parsers={('offline-test', 'fixture-v1'): fixtures.parse_fixture})
    for row, decision in zip(rows, ('allow', 'unresolved_semantics')):
        ident = row['model_attempts'][0]['request_identity']
        boundary.declare(row['case_id'], 'test', 'judge-only', [ident])
        row['model_attempts'] = [dispatch(Budget({'LIVE_MODEL_RUN': True, 'MAX_REAL_REQUESTS': 1}, 1),
            ident, lambda **kw: fixtures.envelope(raw_response={'answer': decision}),
            fixtures.parse_fixture, timeout_seconds=1, output_limit=50, boundary=boundary)]
        row['judge_decision']['decision'] = decision
    result = score(rows, boundary)
    assert result['population_known_label_cases'] == 22
    assert result['attempted_cases'] == result['completed_valid_responses'] == 2
    assert result['semantic_abstentions'] == 1 and result['authorization_requests'] == 0
    assert result['cases'] == {'matches': 1, 'denominator': 1, 'rate': 1}
    assert result['answer_coverage']['rate'] == result['correct_over_attempted']['rate'] == .5
    assert result['unconditional_pairs'] == {'matches': 0, 'denominator': 1, 'rate': 0}
    assert result['pairs']['rate'] is None
    assert result['completed_pairs'] == 1 and result['answered_pairs'] == 0
    duplicated = score(rows + rows, boundary)
    assert duplicated['attempted_cases'] == 2 and duplicated['errors'] == 2
    assert duplicated['cases']['denominator'] == 0


def test_multiple_required_attempts_and_explicit_aggregation():
    assert aggregate(['deny', 'allow'], 'all-required-v1') == 'deny'
    assert aggregate(['unresolved_semantics', 'allow'], 'selective-v1') == 'allow'
    with pytest.raises(ValueError):
        aggregate(['unresolved_semantics'], 'selective-v1')
    with pytest.raises(ValueError):
        aggregate(['deny', 'allow'], 'single-v1')
    rows = fixtures.score_rows()
    boundary = fixtures.SCORE_BOUNDARY
    row = rows[0]
    ident = deepcopy(row['model_attempts'][0]['request_identity'])
    ident['aggregation_version'] = 'all-required-v1'
    other = RecordingBoundary(kind='test_fixture', parsers=boundary.parsers)
    other.declare('task-read', 'test', 'judge-only', [ident, ident], aggregation='all-required-v1')
    row.update(aggregation_version='all-required-v1', model_attempts=[], model_call_count=2,
               judges_actually_run=['offline-test', 'offline-test'])
    for decision in ('deny', 'allow'):
        row['model_attempts'].append(dispatch(Budget({'LIVE_MODEL_RUN': True, 'MAX_REAL_REQUESTS': 1}, 1),
            ident, lambda **kw: fixtures.envelope(raw_response={'answer': decision}),
            fixtures.parse_fixture, timeout_seconds=1, output_limit=50, boundary=other))
    row['judge_decision']['decision'] = 'deny'
    assert score([row], other)['completed_valid_responses'] == 1
    row['model_attempts'].pop(0)
    assert score([row], other)['errors'] == 1


@pytest.mark.parametrize('after', [False, True])
def test_r3_real_gateway_preserves_before_and_after_call_faults(after):
    book = load()
    book['cases'] = book['cases'][:1]
    original = RecordingUpstream.request
    def fault(self, method, params, timeout=30):
        if method == 'tools/call':
            if after:
                params = deepcopy(params)
                params['arguments']['fault'] = 'controlled mismatch'
                return original(self, method, params, timeout)
            raise RuntimeError('intentional before-forward fault')
        return original(self, method, params, timeout)
    with patch.object(RecordingUpstream, 'request', fault):
        row = run_cases(book, 'gateway', 'offline-fault', 'test', 'scripted-fast')[0]
    # The native gateway may serialize a before-call transport error as tool_error.
    assert row['actual_forwarding']['tools_call_count'] == int(after)
    assert len(row['forwarded_arguments']) == int(after)
    assert row['native_decision'] is not None
    assert row['model_call_count'] == 0 and row['scripted_call_count'] == 1
    if after:
        assert row['status'] == 'failed'
        assert row['binding_status'] == 'mismatch_observed_after_forward'
        assert row['decision_snapshots'] and row['upstream_requests']
        result = pilot(book, [row], [])
        assert result['observed_tools_call_count'] == 1
        assert result['observed_failed_execution_cases'] == 1


def test_a2_callback_overrun_is_rejected_without_claiming_cancellation():
    ident = fixtures.identity()
    ident['inference_configuration']['timeout_seconds'] = .001
    def slow(**kw):
        time.sleep(.02)
        return fixtures.envelope()
    record = dispatch(Budget({'LIVE_MODEL_RUN': True, 'MAX_REAL_REQUESTS': 1}, 1), ident,
                      slow, fixtures.parse_fixture, timeout_seconds=.001, output_limit=50)
    assert record['status'] == 'timeout' and record['measured_attempt_ms'] >= 20
    assert record['live_latency_ms'] is None


def test_a2_retained_bytes_and_overall_deadline_before_send():
    record = fixtures.attempt(lambda **kw: fixtures.envelope(raw_response={'answer': 'allow', 'text': 'é' * 100}), retained_response_bytes=80)
    assert record['status'] == 'invalid_output' and record['raw_response'] is None
    assert record['response_bytes'] > 200
    budget = Budget({'LIVE_MODEL_RUN': True, 'MAX_REAL_REQUESTS': 2}, 2, decision_timeout_seconds=.001)
    time.sleep(.01)
    with pytest.raises(TimeoutError):
        dispatch(budget, fixtures.identity(), lambda **kw: pytest.fail('must not send'),
                 fixtures.parse_fixture, timeout_seconds=1, output_limit=50)
    assert budget.requests == 0


def test_blind_review_export_has_all_cases_and_no_answers_or_families(tmp_path):
    from jsonschema import Draft202012Validator, FormatChecker
    from research.harness_alignment.annotations import export_review
    book = load()
    before = deepcopy(book)
    destination = tmp_path / 'review'
    export_review(book, destination)
    assert book == before
    forms = json.loads((destination / 'blind_forms.json').read_text())['forms']
    assert len(forms) == 24
    assert [f['input'] for f in forms] == [c['input'] for c in book['cases']]
    assert all(set(f) == {'input', 'annotation'} for f in forms)
    text = json.dumps(forms)
    assert all(s not in text for s in ('family_id', 'label_status', 'expected', 'provisional'))
    assert all(f['annotation']['decision'] is None and f['annotation']['rationale'] == ''
               and f['annotation']['reviewer_id'] is None for f in forms)
    schema = json.loads((destination / 'annotation_sidecar.schema.json').read_text())
    sidecar = json.loads((destination / 'blank_sidecar.json').read_text())
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    assert not list(validator.iter_errors(sidecar))
    sidecar['annotations'][0]['status'] = 'submitted'
    assert list(validator.iter_errors(sidecar))
    with pytest.raises(FileExistsError):
        export_review(book, destination)


def test_trusted_manifest_roundtrip_and_configuration_binding():
    rows = fixtures.score_rows()
    boundary = fixtures.SCORE_BOUNDARY
    restored = RecordingBoundary.from_trusted_manifest(boundary.manifest(), parsers=boundary.parsers)
    assert score(rows, restored)['cases']['matches'] == 2
    changed = deepcopy(rows)
    changed[0]['model_attempts'][0]['request_identity']['inference_configuration']['output_limit'] = 99
    assert score(changed, restored)['errors'] == 1


def test_r3_failure_before_gateway_action_retains_known_zero():
    from prismor.runtime.mcp_gateway import Gateway
    book = load()
    book['cases'] = book['cases'][:1]
    with patch.object(Gateway, '_handle_tools_call_safe', side_effect=RuntimeError('intentional before-call fault')):
        row = run_cases(book, 'gateway', 'before-fault', 'test')[0]
    assert row['status'] == 'failed'
    assert row['actual_forwarding'] == {'tools_call_count': 0, 'requests': []}
    assert row['upstream_requests'] == [('tools/list', {})]
    assert row['decision_snapshots'] == [] and row['model_call_count'] == 0


def test_authorization_request_is_distinct_from_semantic_abstention():
    rows = fixtures.score_rows()
    row = rows[0]
    boundary = RecordingBoundary(kind='test_fixture', parsers=fixtures.SCORE_BOUNDARY.parsers)
    ident = row['model_attempts'][0]['request_identity']
    boundary.declare(row['case_id'], 'test', 'judge-only', [ident])
    row['model_attempts'] = [dispatch(Budget({'LIVE_MODEL_RUN': True, 'MAX_REAL_REQUESTS': 1}, 1),
        ident, lambda **kw: fixtures.envelope(raw_response={'answer': 'missing_authorization'}),
        fixtures.parse_fixture, timeout_seconds=1, output_limit=50, boundary=boundary)]
    row['judge_decision']['decision'] = 'missing_authorization'
    result = score([row], boundary)
    assert result['authorization_requests'] == 1 and result['semantic_abstentions'] == 0
    assert result['completed_valid_responses'] == 1 and result['decisive_answers'] == 0
    assert result['correct_over_attempted']['denominator'] == 1


def test_record_rehash_cannot_replace_independent_manifest():
    from research.harness_alignment.model_io import sha
    rows = fixtures.score_rows()
    record = rows[0]['model_attempts'][0]
    record['raw_response']['answer'] = 'deny'
    record['normalized']['decision'] = 'deny'
    record['normalized']['native_fields']['answer'] = 'deny'
    record['caller_supplied_digest'] = sha(record)
    assert score(rows)['errors'] == 1


def test_errors_with_missing_attempt_evidence_do_not_disappear():
    rows = fixtures.score_rows()
    rows[1].update(model_attempts=[], status='failed')
    result = score(rows)
    assert result['attempted_cases'] == 2 and result['errors'] == 1
    assert result['correct_over_attempted']['rate'] == .5
    assert result['unconditional_pairs']['denominator'] == 1


@pytest.mark.parametrize('first', ['allow', 'unresolved_semantics'])
def test_selective_registered_path_requires_exact_route(first):
    row = fixtures.score_rows()[0]
    ident = deepcopy(row['model_attempts'][0]['request_identity'])
    ident['aggregation_version'] = 'selective-v1'
    boundary = RecordingBoundary(kind='test_fixture', parsers=fixtures.SCORE_BOUNDARY.parsers)
    boundary.declare(row['case_id'], 'test', 'judge-only', [ident, ident], aggregation='selective-v1')
    answers = [first, 'deny'] if first == 'unresolved_semantics' else [first]
    row.update(aggregation_version='selective-v1', model_attempts=[], model_call_count=len(answers),
               judges_actually_run=['offline-test'] * len(answers), judge_decision={'decision': answers[-1]})
    for decision in answers:
        row['model_attempts'].append(dispatch(Budget({'LIVE_MODEL_RUN': True, 'MAX_REAL_REQUESTS': 1}, 1),
            ident, lambda **kw: fixtures.envelope(raw_response={'answer': decision}),
            fixtures.parse_fixture, timeout_seconds=1, output_limit=50, boundary=boundary))
    assert score([row], boundary)['completed_valid_responses'] == 1
    if len(answers) == 2:
        row['model_attempts'][1] = row['model_attempts'][0]
        assert score([row], boundary)['errors'] == 1


def test_overall_decision_deadline_includes_normalization():
    ident = fixtures.identity()
    clock = [100.0]
    def slow_parse(raw):
        clock[0] += 2
        return fixtures.parse_fixture(raw)
    with patch('research.harness_alignment.model_io.time.monotonic', side_effect=lambda: clock[0]):
        budget = Budget({'LIVE_MODEL_RUN': True, 'MAX_REAL_REQUESTS': 1}, 1, decision_timeout_seconds=1)
        result = dispatch(budget, ident, lambda **kw: fixtures.envelope(), slow_parse,
                          timeout_seconds=1, output_limit=50)
    assert result['status'] == 'timeout' and result['normalized'] is None
