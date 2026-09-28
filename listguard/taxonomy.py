'''Validation and immutable access for ListGuard's closed-set taxonomy.'''

from __future__ import annotations

import json
from enum import Enum
from pathlib import Path
from typing import Final, TypeGuard


CANONICAL_POLICY_BUCKETS: Final[tuple[str, ...]] = (
    'ok',
    'weapon',
    'animal',
    'counterfeit',
    'pii',
    'other_illegal',
    'unknown',
)

DEFAULT_POLICY_BUCKETS_PATH: Final[Path] = (
    Path(__file__).resolve().parent.parent / 'policy' / 'buckets.json'
)


class PolicyTaxonomyError(ValueError):
    '''Raised when the configured taxonomy violates its closed-set contract.'''


def load_policy_buckets(
    path: str | Path = DEFAULT_POLICY_BUCKETS_PATH,
) -> tuple[str, ...]:
    '''Load, validate, and return the canonical policy buckets as a tuple.'''
    taxonomy_path = Path(path)

    try:
        raw_document = taxonomy_path.read_text(encoding='utf-8')
    except (OSError, UnicodeError) as exc:
        raise PolicyTaxonomyError(
            f'Unable to read policy taxonomy at {taxonomy_path}'
        ) from exc

    try:
        document = json.loads(raw_document)
    except json.JSONDecodeError as exc:
        raise PolicyTaxonomyError(
            f'Policy taxonomy at {taxonomy_path} must contain valid JSON'
        ) from exc

    if not isinstance(document, list):
        raise PolicyTaxonomyError(
            f'Policy taxonomy at {taxonomy_path} must be a JSON array'
        )

    ordered_buckets: list[str] = []
    seen_buckets: set[str] = set()
    duplicate_buckets: set[str] = set()

    for index, bucket in enumerate(document):
        if not isinstance(bucket, str):
            raise PolicyTaxonomyError(
                'Policy taxonomy entry at index '
                f'{index} must be a string'
            )
        if bucket in seen_buckets:
            duplicate_buckets.add(bucket)
            continue
        seen_buckets.add(bucket)
        ordered_buckets.append(bucket)

    if duplicate_buckets:
        duplicates = ', '.join(sorted(duplicate_buckets))
        raise PolicyTaxonomyError(
            f'Policy taxonomy contains duplicate bucket values: {duplicates}'
        )

    actual = set(ordered_buckets)
    expected = set(CANONICAL_POLICY_BUCKETS)

    if actual != expected:
        missing = tuple(
            bucket for bucket in CANONICAL_POLICY_BUCKETS if bucket not in actual
        )
        unexpected = tuple(bucket for bucket in ordered_buckets if bucket not in expected)
        details: list[str] = []
        if missing:
            details.append(f'missing buckets: {", ".join(missing)}')
        if unexpected:
            details.append(f'unexpected buckets: {", ".join(unexpected)}')
        raise PolicyTaxonomyError(
            f'Policy taxonomy is not the canonical closed set ({"; ".join(details)})'
        )

    return tuple(ordered_buckets)


POLICY_BUCKETS: Final[tuple[str, ...]] = load_policy_buckets()


def is_policy_bucket(candidate: object) -> TypeGuard[str]:
    '''Return whether a value belongs to the configured closed taxonomy.'''
    return isinstance(candidate, str) and candidate in POLICY_BUCKETS


def validate_policy_bucket_alignment(bucket_enum: type[Enum]) -> None:
    '''Require a policy enum to contain exactly the configured bucket values.'''
    if not isinstance(bucket_enum, type) or not issubclass(bucket_enum, Enum):
        raise PolicyTaxonomyError('Policy bucket taxonomy must be an Enum class')

    values = tuple(member.value for member in bucket_enum)
    if any(not isinstance(value, str) for value in values):
        raise PolicyTaxonomyError(
            f'Policy bucket enum {bucket_enum.__name__} must contain only string values'
        )

    actual = set(values)
    expected = set(POLICY_BUCKETS)
    if len(values) != len(POLICY_BUCKETS) or actual != expected:
        missing = tuple(bucket for bucket in POLICY_BUCKETS if bucket not in actual)
        unexpected = tuple(sorted(value for value in actual if value not in expected))
        details: list[str] = []
        if missing:
            details.append(f'missing buckets: {", ".join(missing)}')
        if unexpected:
            details.append(f'unexpected buckets: {", ".join(unexpected)}')
        raise PolicyTaxonomyError(
            f'Policy bucket enum {bucket_enum.__name__} does not match '
            f'policy/buckets.json ({"; ".join(details)})'
        )


__all__ = [
    'CANONICAL_POLICY_BUCKETS',
    'DEFAULT_POLICY_BUCKETS_PATH',
    'POLICY_BUCKETS',
    'PolicyTaxonomyError',
    'is_policy_bucket',
    'load_policy_buckets',
    'validate_policy_bucket_alignment',
]
