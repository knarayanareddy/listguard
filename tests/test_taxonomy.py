from __future__ import annotations

import json
from enum import Enum
from pathlib import Path

import pytest

from listguard import POLICY_BUCKETS
from listguard.models import PolicyBucket
from listguard.taxonomy import (
    CANONICAL_POLICY_BUCKETS,
    PolicyTaxonomyError,
    is_policy_bucket,
    load_policy_buckets,
    validate_policy_bucket_alignment,
)


EXPECTED_BUCKETS = (
    'ok',
    'weapon',
    'animal',
    'counterfeit',
    'pii',
    'other_illegal',
    'unknown',
)


class _MissingBucket(str, Enum):
    OK = 'ok'


class _NumericBucket(Enum):
    OK = 1


class _ExtendedBucket(str, Enum):
    OK = 'ok'
    WEAPON = 'weapon'
    ANIMAL = 'animal'
    COUNTERFEIT = 'counterfeit'
    PII = 'pii'
    OTHER_ILLEGAL = 'other_illegal'
    UNKNOWN = 'unknown'
    HUMAN_BAN = 'human_ban'


def test_default_taxonomy_contains_exact_canonical_values() -> None:
    assert CANONICAL_POLICY_BUCKETS == EXPECTED_BUCKETS
    assert POLICY_BUCKETS == EXPECTED_BUCKETS
    assert load_policy_buckets() == EXPECTED_BUCKETS


@pytest.mark.parametrize('candidate', [*EXPECTED_BUCKETS, PolicyBucket.OK])
def test_closed_set_predicate_accepts_only_configured_values(
    candidate: object,
) -> None:
    assert is_policy_bucket(candidate) is True


@pytest.mark.parametrize(
    'candidate',
    [None, 1, True, ['ok'], '', 'OK', 'weapons', 'human_ban'],
)
def test_closed_set_predicate_rejects_untrusted_values(candidate: object) -> None:
    assert is_policy_bucket(candidate) is False


def test_loader_accepts_any_order_for_the_same_closed_set(tmp_path: Path) -> None:
    reordered = tuple(reversed(EXPECTED_BUCKETS))
    taxonomy_path = tmp_path / 'buckets.json'
    taxonomy_path.write_text(json.dumps(reordered), encoding='utf-8')

    assert load_policy_buckets(taxonomy_path) == reordered


@pytest.mark.parametrize(
    ('document', 'expected_message'),
    [
        ({}, 'must be a JSON array'),
        ([1, 2, 3], 'must be a string'),
        (list(EXPECTED_BUCKETS[:-1]), 'missing buckets'),
        ([*EXPECTED_BUCKETS, 'human_ban'], 'unexpected buckets'),
    ],
)
def test_loader_rejects_noncanonical_taxonomy_documents(
    tmp_path: Path,
    document: object,
    expected_message: str,
) -> None:
    taxonomy_path = tmp_path / 'buckets.json'
    taxonomy_path.write_text(json.dumps(document), encoding='utf-8')

    with pytest.raises(PolicyTaxonomyError, match=expected_message):
        load_policy_buckets(taxonomy_path)


def test_loader_rejects_duplicate_bucket_values(tmp_path: Path) -> None:
    duplicated = list(EXPECTED_BUCKETS)
    duplicated[-1] = duplicated[0]
    taxonomy_path = tmp_path / 'buckets.json'
    taxonomy_path.write_text(json.dumps(duplicated), encoding='utf-8')

    with pytest.raises(PolicyTaxonomyError, match='duplicate bucket values: ok'):
        load_policy_buckets(taxonomy_path)


def test_loader_rejects_invalid_json(tmp_path: Path) -> None:
    taxonomy_path = tmp_path / 'buckets.json'
    taxonomy_path.write_text('["ok",', encoding='utf-8')

    with pytest.raises(PolicyTaxonomyError, match='must contain valid JSON'):
        load_policy_buckets(taxonomy_path)


def test_loader_rejects_a_missing_file(tmp_path: Path) -> None:
    taxonomy_path = tmp_path / 'missing.json'

    with pytest.raises(PolicyTaxonomyError, match='Unable to read policy taxonomy'):
        load_policy_buckets(taxonomy_path)


def test_loader_rejects_invalid_utf8(tmp_path: Path) -> None:
    taxonomy_path = tmp_path / 'buckets.json'
    taxonomy_path.write_bytes(bytes([255]))

    with pytest.raises(PolicyTaxonomyError, match='Unable to read policy taxonomy'):
        load_policy_buckets(taxonomy_path)


def test_model_enum_matches_the_configured_taxonomy() -> None:
    assert validate_policy_bucket_alignment(PolicyBucket) is None


@pytest.mark.parametrize(
    ('bucket_enum', 'expected_message'),
    [
        (_MissingBucket, 'missing buckets'),
        (_ExtendedBucket, 'unexpected buckets: human_ban'),
        (_NumericBucket, 'must contain only string values'),
        (dict, 'must be an Enum class'),
    ],
)
def test_enum_alignment_rejects_taxonomy_drift(
    bucket_enum: type[Enum],
    expected_message: str,
) -> None:
    with pytest.raises(PolicyTaxonomyError, match=expected_message):
        validate_policy_bucket_alignment(bucket_enum)
