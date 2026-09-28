import json
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from uuid import UUID

import pytest
from pydantic import ValidationError

from listguard.models import (
    Action,
    AuditReceipt,
    ListingInput,
    PolicyBucket,
    PolicyResult,
)


BUCKET_FILE = json.loads(
    (Path(__file__).resolve().parents[1] / 'policy' / 'buckets.json')
    .read_text(encoding='utf-8')
)


def test_action_and_policy_bucket_enums_match_closed_sets() -> None:
    assert {member.value for member in Action} == {
        'allow',
        'queue',
        'block',
    }
    assert {member.value for member in PolicyBucket} == set(BUCKET_FILE)
    assert len(BUCKET_FILE) == len(set(BUCKET_FILE)) == 7

    with pytest.raises(ValueError):
        Action('ban_human')
    with pytest.raises(ValueError):
        PolicyBucket('invented_category')


def test_listing_input_accepts_aliases_json_metadata_and_price() -> None:
    listing = ListingInput.model_validate(
        {
            'id': ' lg-safe-phone-01 ',
            'title': '  Working smartphone  ',
            'text': '  Fully tested device with charger.  ',
            'image_metadata': [
                {
                    'filename': 'front.jpg',
                    'width': 1200,
                    'height': 1600,
                    'labels': ['phone', 'used'],
                    'seller_supplied_caption': None,
                }
            ],
            'price': '249.99',
            'currency': 'EUR',
            'metadata': {
                'marketplace': 'example',
                'seller_id': 'seller-42',
            },
        }
    )

    assert listing.listing_id == 'lg-safe-phone-01'
    assert listing.title == 'Working smartphone'
    assert listing.description == 'Fully tested device with charger.'
    assert listing.price == Decimal('249.99')
    assert listing.image_metadata[0]['width'] == 1200
    assert listing.metadata['seller_id'] == 'seller-42'
    assert listing.model_dump(mode='json')['listing_id'] == 'lg-safe-phone-01'

    other = ListingInput(listing_id='lg-other', title='Book')
    assert other.description == ''
    assert other.image_metadata == []
    assert other.metadata == {}
    assert other.image_metadata is not listing.image_metadata
    assert other.metadata is not listing.metadata

    with pytest.raises(ValidationError):
        listing.title = 'Mutated title'


@pytest.mark.parametrize(
    'payload',
    [
        {'listing_id': '   ', 'title': 'Phone'},
        {'listing_id': 'lg-1', 'title': '   '},
        {'listing_id': 'lg-1'},
        {
            'listing_id': 'lg-1',
            'title': 'Phone',
            'currency': 'eur',
        },
        {
            'listing_id': 'lg-1',
            'title': 'Phone',
            'price': -1,
        },
        {
            'listing_id': 'lg-1',
            'title': 'Phone',
            'image_metadata': ['not-an-object'],
        },
        {
            'listing_id': 'lg-1',
            'title': 'Phone',
            'hallucinated_bucket': 'weapon',
        },
    ],
)
def test_listing_input_rejects_invalid_or_untrusted_shapes(
    payload: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        ListingInput.model_validate(payload)


def test_policy_result_serializes_closed_values_and_reason_alias() -> None:
    result = PolicyResult.model_validate(
        {
            'bucket': 'ok',
            'action': 'allow',
            'confidence': 0.99,
            'reasons': ['no_policy_violation'],
            'rationale': 'No deterministic violation was found.',
        }
    )

    assert result.bucket is PolicyBucket.OK
    assert result.action is Action.ALLOW
    assert result.reason_codes == ('no_policy_violation',)

    serialized = result.model_dump(mode='json')
    assert serialized['bucket'] == 'ok'
    assert serialized['action'] == 'allow'
    assert serialized['reason_codes'] == ['no_policy_violation']


@pytest.mark.parametrize(
    ('bucket', 'action', 'reason_codes'),
    [
        (PolicyBucket.WEAPON, Action.BLOCK, ['weapon']),
        (PolicyBucket.COUNTERFEIT, Action.QUEUE, ['counterfeit']),
        (
            PolicyBucket.UNKNOWN,
            Action.QUEUE,
            ['injection_or_jailbreak'],
        ),
        (
            PolicyBucket.UNKNOWN,
            Action.BLOCK,
            ['injection_or_jailbreak'],
        ),
        (PolicyBucket.OK, Action.ALLOW, ['no_policy_violation']),
    ],
)
def test_policy_result_accepts_valid_routes(
    bucket: PolicyBucket,
    action: Action,
    reason_codes: list[str],
) -> None:
    result = PolicyResult(
        bucket=bucket,
        action=action,
        confidence=0.97,
        reason_codes=reason_codes,
    )
    assert result.bucket == bucket
    assert result.action == action


@pytest.mark.parametrize(
    ('bucket', 'action', 'reason_codes'),
    [
        (PolicyBucket.WEAPON, Action.ALLOW, ['weapon']),
        (PolicyBucket.WEAPON, Action.QUEUE, ['weapon']),
        (PolicyBucket.COUNTERFEIT, Action.ALLOW, ['counterfeit']),
        (PolicyBucket.COUNTERFEIT, Action.BLOCK, ['counterfeit']),
        (
            PolicyBucket.UNKNOWN,
            Action.ALLOW,
            ['injection_or_jailbreak'],
        ),
    ],
)
def test_policy_result_prevents_action_downgrades(
    bucket: PolicyBucket,
    action: Action,
    reason_codes: list[str],
) -> None:
    with pytest.raises(ValidationError):
        PolicyResult(
            bucket=bucket,
            action=action,
            confidence=0.99,
            reason_codes=reason_codes,
        )


@pytest.mark.parametrize(
    'confidence',
    [-0.01, 1.01, float('nan'), float('inf'), '0.99'],
)
def test_policy_result_rejects_invalid_confidence(confidence: object) -> None:
    with pytest.raises(ValidationError):
        PolicyResult(
            bucket=PolicyBucket.OK,
            action=Action.ALLOW,
            confidence=confidence,
        )


def test_policy_result_rejects_invalid_bucket_and_reason_codes() -> None:
    with pytest.raises(ValidationError):
        PolicyResult(
            bucket='hallucinated_policy',
            action=Action.BLOCK,
            confidence=0.9,
        )

    with pytest.raises(ValidationError):
        PolicyResult(
            bucket=PolicyBucket.COUNTERFEIT,
            action=Action.QUEUE,
            confidence=0.9,
            reason_codes=['counterfeit', 'counterfeit'],
        )

    with pytest.raises(ValidationError):
        PolicyResult(
            bucket=PolicyBucket.OK,
            action=Action.ALLOW,
            confidence=0.9,
            reason_codes=['Not A Code'],
        )


def test_audit_receipt_validates_signature_and_serializes_json() -> None:
    result = PolicyResult(
        bucket=PolicyBucket.WEAPON,
        action=Action.BLOCK,
        confidence=0.995,
        reason_codes=['weapon'],
    )
    created_at = datetime(2025, 1, 2, 3, 4, 5, tzinfo=timezone.utc)

    receipt = AuditReceipt(
        listing_id='lg-weapon-01',
        listing_hash='a' * 64,
        result=result,
        policy_version='policy-2025.01',
        signature='ed25519:system-signature',
        created_at=created_at,
        previous_receipt_hash='b' * 64,
    )

    assert isinstance(receipt.receipt_id, UUID)
    assert receipt.actor == 'system'
    assert receipt.result.action is Action.BLOCK

    serialized = receipt.model_dump(mode='json')
    assert isinstance(serialized['receipt_id'], str)
    assert serialized['result']['action'] == 'block'
    assert serialized['actor'] == 'system'
    assert serialized['created_at'].endswith('Z')


def test_audit_receipt_supports_decision_and_timestamp_aliases() -> None:
    result = PolicyResult(
        bucket=PolicyBucket.COUNTERFEIT,
        action=Action.QUEUE,
        confidence=0.98,
        reason_codes=['counterfeit'],
    )

    receipt = AuditReceipt.model_validate(
        {
            'listing_id': 'lg-fake-rolex-01',
            'listing_hash': 'c' * 64,
            'decision': result.model_dump(mode='json'),
            'policy_version': 'policy-2025.01',
            'signature': 'ed25519:system-signature',
            'timestamp': '2025-01-02T03:04:05Z',
        }
    )

    assert receipt.result.bucket is PolicyBucket.COUNTERFEIT
    assert receipt.created_at == datetime(
        2025,
        1,
        2,
        3,
        4,
        5,
        tzinfo=timezone.utc,
    )


def test_audit_receipt_requires_human_actor_and_operator_for_override() -> None:
    result = PolicyResult(
        bucket=PolicyBucket.WEAPON,
        action=Action.BLOCK,
        confidence=0.995,
        reason_codes=['weapon'],
    )
    complete_override = {
        'listing_id': 'lg-weapon-01',
        'listing_hash': 'd' * 64,
        'result': result.model_dump(mode='json'),
        'policy_version': 'policy-2025.01',
        'signature': 'ed25519:human-signature',
        'actor': 'human',
        'operator_id': 'reviewer-17',
        'override_action': 'allow',
        'override_reason': 'Verified as a non-functional museum prop.',
        'overridden_at': '2025-01-02T04:00:00Z',
    }

    receipt = AuditReceipt.model_validate(complete_override)
    assert receipt.actor == 'human'
    assert receipt.operator_id == 'reviewer-17'
    assert receipt.override_action is Action.ALLOW

    for field in (
        'operator_id',
        'override_action',
        'override_reason',
        'overridden_at',
    ):
        incomplete = dict(complete_override)
        incomplete.pop(field)
        with pytest.raises(ValidationError):
            AuditReceipt.model_validate(incomplete)

    misattributed = dict(complete_override)
    misattributed['actor'] = 'system'
    with pytest.raises(ValidationError):
        AuditReceipt.model_validate(misattributed)


def test_audit_receipt_rejects_invalid_integrity_fields() -> None:
    result = PolicyResult(
        bucket=PolicyBucket.WEAPON,
        action=Action.BLOCK,
        confidence=0.995,
        reason_codes=['weapon'],
    )
    base = {
        'listing_id': 'lg-weapon-01',
        'listing_hash': 'e' * 64,
        'result': result.model_dump(mode='json'),
        'policy_version': 'policy-2025.01',
        'signature': 'ed25519:system-signature',
    }

    invalid_changes = (
        {'listing_hash': 'E' * 64},
        {'listing_hash': 'abc'},
        {'created_at': datetime(2025, 1, 2, 3, 4, 5)},
        {'actor': 'robot'},
        {'receipt_version': '2.0'},
        {'signature': '   '},
        {'unexpected_integrity_field': True},
    )

    for changes in invalid_changes:
        with pytest.raises(ValidationError):
            AuditReceipt.model_validate({**base, **changes})
