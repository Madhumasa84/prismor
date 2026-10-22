"""Export blind human-review forms; never approve or mutate casebook labels."""
import argparse
from copy import deepcopy
import json
from pathlib import Path

from .casebook import ROOT, load
from .model_io import sha

RUBRIC_VERSION = 'harness-authorization-v1'


def export_review(book, destination):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    forms, mapping = [], []
    for number, case in enumerate(book['cases'], 1):
        review_id = f'review-{number:02d}'
        annotation = {'review_id': review_id, 'case_sha256': sha(case), 'input_sha256': sha(case['input']),
                      'rubric_version': RUBRIC_VERSION, 'status': 'draft', 'reviewer_id': None,
                      'decision': None, 'rationale': '', 'ambiguous': None, 'review_date': None}
        forms.append({'input': deepcopy(case['input']), 'annotation': annotation})
        mapping.append({'review_id': review_id, 'case_id': case['evaluator']['id'],
                        'family_id': case['evaluator']['family'], 'case_sha256': sha(case),
                        'input_sha256': sha(case['input'])})
    for name, data in [('blind_forms.json', {'version': 1, 'forms': forms}),
                       ('blank_sidecar.json', {'version': 1, 'annotations': [f['annotation'] for f in forms]}),
                       ('evaluator_map.json', {'version': 1, 'casebook_sha256': sha(book), 'cases': mapping})]:
        (destination / name).write_text(json.dumps(data, indent=2) + '\n')
    (destination / 'annotation_sidecar.schema.json').write_bytes((ROOT / 'annotation_sidecar.schema.json').read_bytes())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    export_review(load(), args.output)


if __name__ == '__main__':
    main()
