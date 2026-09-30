from __future__ import annotations

import inspect
import json
import logging
import os
import types
from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Union, get_args, get_origin
from uuid import UUID, uuid4

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    model_validator,
)

from listguard.models import (
    Action,
    AuditReceipt,
    HumanOverride,
    ListingInput,
    OperatorId,
    OverrideReason,
    PolicyBucket,
    PolicyResult,
)
from listguard.policy import DETERMINISTIC_POLICY_VERSION, evaluate_listing
from listguard.storage import (
    DEFAULT_DATABASE_PATH,
    ReceiptConflictError,
    ReceiptNotFoundError,
    ReceiptSignatureError,
    ReceiptStoreError,
    SQLiteReceiptStore,
    SigningKeyConflictError,
    compute_listing_hash,
    compute_receipt_hash,
)

LOGGER = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TEMPLATE_DIRECTORY = PROJECT_ROOT / 'web' / 'templates'

PolicyEvaluator = Callable[[ListingInput], PolicyResult]
VerificationMode = Literal['permissive', 'local', 'external']

_POLICY_RESULT_FIELDS: tuple[str, ...] = (
    'policy_result',
    'result',
    'decision',
    'classification',
    'moderation_result',
    'policy_decision',
)
_OVERRIDE_FIELDS: tuple[str, ...] = (
    'human_override',
    'override',
    'review',
    'review_command',
    'override_command',
)
_RECEIPT_ID_FIELDS: frozenset[str] = frozenset(
    {
        'receipt',
        'audit_receipt',
        'new_receipt',
        'human_receipt',
    }
)
_OVERRIDE_PARAMETER_NAMES: frozenset[str] = frozenset(
    {
        'override',
        'human_override',
        'review',
        'review_command',
        'override_command',
    }
)


class _IncompatibleMethodCall(Exception):
    """Internal signal used to select a compatible storage operation."""


class OverrideRequest(BaseModel):
    """A human review command submitted by the moderation desk."""

    model_config = ConfigDict(
        extra='forbid',
        frozen=True,
        populate_by_name=True,
        str_strip_whitespace=True,
        validate_assignment=True,
        validate_default=True,
    )

    operator_id: OperatorId = Field(
        validation_alias=AliasChoices(
            'operator_id',
            'reviewer_id',
            'operator_identifier',
        ),
    )
    action: Action | None = Field(
        default=None,
        validation_alias=AliasChoices(
            'action',
            'new_action',
            'override_action',
            'reviewed_action',
        ),
    )
    decision: Literal['accept', 'override'] | None = None
    reason: OverrideReason = Field(
        validation_alias=AliasChoices(
            'reason',
            'override_reason',
            'note',
        ),
    )

    @model_validator(mode='before')
    @classmethod
    def normalize_command(cls, value: object) -> object:
        """Normalize the supported action-valued decision shorthand."""
        if not isinstance(value, Mapping):
            return value

        payload = dict(value)
        raw_decision = payload.get('decision')
        raw_action = next(
            (
                payload.get(key)
                for key in (
                    'action',
                    'new_action',
                    'override_action',
                    'reviewed_action',
                )
                if key in payload
            ),
            None,
        )

        if isinstance(raw_decision, str):
            normalized_decision = raw_decision.casefold()

            if normalized_decision in {member.value for member in Action}:
                if raw_action is not None and raw_action != normalized_decision:
                    raise ValueError(
                        'decision and action must not specify different actions'
                    )
                payload['action'] = normalized_decision
                payload['decision'] = 'override'
            elif normalized_decision not in {'accept', 'override'}:
                raise ValueError(
                    'decision must be accept, override, allow, queue, or block'
                )
        elif raw_decision is not None:
            raise ValueError('decision must be a string')

        if payload.get('decision') is None:
            if raw_action is None and 'action' not in payload:
                raise ValueError(
                    'decision or an explicit override action is required'
                )
            payload['decision'] = 'override'

        if payload.get('decision') == 'override' and raw_action is None:
            raise ValueError('an override decision requires an action')

        return payload


def _build_sqlite_store(
    database_path: Path,
    signing_key: str | bytes | None,
    verification_mode: VerificationMode,
) -> SQLiteReceiptStore:
    """Construct the repository while tolerating optional constructor settings."""
    try:
        signature = inspect.signature(SQLiteReceiptStore)
    except (TypeError, ValueError):
        return SQLiteReceiptStore(database_path)

    parameters = signature.parameters
    kwargs: dict[str, object] = {}

    if 'database_path' in parameters:
        kwargs['database_path'] = database_path
    elif 'path' in parameters:
        kwargs['path'] = database_path
    else:
        return SQLiteReceiptStore(
            database_path,
            signing_key=signing_key,
            verification_mode=verification_mode,
        )

    if 'signing_key' in parameters:
        kwargs['signing_key'] = signing_key
    if 'verification_mode' in parameters:
        kwargs['verification_mode'] = verification_mode

    return SQLiteReceiptStore(**kwargs)


def _find_method(
    store: object,
    method_names: tuple[str, ...],
) -> tuple[str, Any] | None:
    for method_name in method_names:
        method = getattr(store, method_name, None)
        if callable(method):
            return method_name, method
    return None


def _invoke_compatible(
    method: Callable[..., object],
    candidates: tuple[tuple[tuple[object, ...], dict[str, object]], ...],
) -> object:
    try:
        signature = inspect.signature(method)
    except (TypeError, ValueError):
        arguments, keyword_arguments = candidates[0]
        result = method(*arguments, **keyword_arguments)
    else:
        result = None
        matched = False

        for arguments, keyword_arguments in candidates:
            try:
                signature.bind(*arguments, **keyword_arguments)
            except TypeError:
                continue

            result = method(*arguments, **keyword_arguments)
            matched = True
            break

        if not matched:
            raise _IncompatibleMethodCall(
                'The receipt store method has an incompatible signature'
            )

    if inspect.isawaitable(result):
        if inspect.iscoroutine(result):
            result.close()
        raise ReceiptStoreError(
            'The synchronous receipt store returned an awaitable'
        )

    return result


def _mapping_value(value: object, *names: str) -> object | None:
    for name in names:
        if isinstance(value, Mapping) and name in value:
            return value[name]
        if hasattr(value, name):
            return getattr(value, name)
    return None


def _coerce_backend_receipt(value: object) -> AuditReceipt:
    """Accept model, JSON, envelope, mapping, or SQLite-row store responses."""
    if isinstance(value, AuditReceipt):
        return value

    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ReceiptStoreError(
                'Receipt backend returned malformed receipt JSON'
            ) from exc
        return _coerce_backend_receipt(decoded)

    if isinstance(value, (tuple, list)):
        if not value:
            raise ReceiptStoreError(
                'Receipt backend returned an empty receipt record'
            )
        return _coerce_backend_receipt(value[0])

    if isinstance(value, Mapping):
        for envelope_key in _RECEIPT_ID_FIELDS:
            if envelope_key in value:
                return _coerce_backend_receipt(value[envelope_key])

        for payload_key in (
            'payload',
            'receipt_json',
            'payload_json',
            'record',
            'data',
        ):
            if payload_key in value:
                return _coerce_backend_receipt(value[payload_key])

    for attribute_name in _RECEIPT_ID_FIELDS:
        nested_value = getattr(value, attribute_name, None)
        if nested_value is not None:
            return _coerce_backend_receipt(nested_value)

    if isinstance(value, Mapping):
        candidate: object = dict(value)
        if 'receipt_id' not in candidate and 'id' in candidate:
            candidate = dict(candidate)
            candidate['receipt_id'] = candidate['id']

        model_values = {
            field_name: candidate[field_name]
            for field_name in AuditReceipt.model_fields
            if isinstance(candidate, Mapping) and field_name in candidate
        }
        if model_values:
            candidate = model_values

        try:
            return AuditReceipt.model_validate(candidate)
        except ValidationError as exc:
            raise ReceiptStoreError(
                'Receipt backend returned an invalid receipt payload'
            ) from exc

    if hasattr(value, 'model_dump'):
        try:
            return AuditReceipt.model_validate(value.model_dump(mode='python'))
        except (AttributeError, TypeError, ValidationError) as exc:
            raise ReceiptStoreError(
                'Receipt backend returned an invalid receipt object'
            ) from exc

    raise ReceiptStoreError(
        'Receipt backend did not return a valid AuditReceipt'
    )


def _get_receipt(
    store: object,
    receipt_id: UUID,
    verification_mode: VerificationMode,
) -> AuditReceipt:
    found = _find_method(
        store,
        (
            'get_receipt',
            'read_receipt',
            'fetch_receipt',
            'get',
            'read',
        ),
    )
    if found is None:
        raise ReceiptStoreError('Receipt store does not expose receipt retrieval')

    _, method = found
    result = _invoke_compatible(
        method,
        (
            ((receipt_id,), {}),
            ((str(receipt_id),), {}),
            ((), {'receipt_id': receipt_id}),
            ((), {'id': receipt_id}),
            (
                (),
                {
                    'receipt_id': receipt_id,
                    'verification_mode': verification_mode,
                },
            ),
            ((receipt_id, verification_mode), {}),
        ),
    )

    if result is None:
        raise ReceiptNotFoundError('Receipt not found')

    return _coerce_backend_receipt(result)


def _annotation_contains(annotation: object, expected: type[BaseModel]) -> bool:
    if isinstance(annotation, type):
        try:
            if issubclass(annotation, expected):
                return True
        except TypeError:
            pass

    origin = get_origin(annotation)
    if origin in {Union, types.UnionType}:
        return any(
            _annotation_contains(argument, expected)
            for argument in get_args(annotation)
        )

    return False


def _put_field(
    fields: Mapping[str, Any],
    values: dict[str, object],
    names: tuple[str, ...],
    value: object,
) -> str | None:
    for name in names:
        if name in fields:
            values[name] = value
            return name
    return None


def _required_field_default(
    name: str,
    annotation: object,
) -> object | None:
    normalized_name = name.casefold()

    if name == 'actor' or normalized_name in {
        'created_by',
        'review_actor',
        'receipt_actor',
    }:
        return None
    if name == 'action' or normalized_name in {
        'effective_action',
        'final_action',
        'reviewed_action',
        'content_action',
    }:
        return None
    if name == 'bucket' or normalized_name in {
        'policy_bucket',
        'category',
    }:
        return None
    if name == 'confidence' or normalized_name in {
        'policy_confidence',
        'classifier_confidence',
    }:
        return None
    if name == 'rationale':
        return None
    if name == 'reason_codes' or normalized_name in {
        'policy_reason_codes',
        'decision_reason_codes',
    }:
        return ()
    if name in {'created_at', 'decided_at', 'issued_at', 'submitted_at'}:
        return datetime.now(timezone.utc)
    if 'signature' in normalized_name:
        return 'pending-store-signature'
    if normalized_name in {'revision', 'sequence', 'receipt_number'}:
        return 1
    if _annotation_contains(annotation, PolicyResult):
        return None
    if _annotation_contains(annotation, HumanOverride):
        return None
    if _annotation_contains(annotation, ListingInput):
        return None

    return None


def _build_human_override(
    receipt_id: UUID,
    command: OverrideRequest,
    action: Action,
) -> HumanOverride:
    now = datetime.now(timezone.utc)
    fields = HumanOverride.model_fields
    values: dict[str, object] = {
        'receipt_id': receipt_id,
        'original_receipt_id': receipt_id,
        'operator_id': command.operator_id,
        'reviewer_id': command.operator_id,
        'action': action,
        'reason': command.reason,
        'override_reason': command.reason,
        'created_at': now,
        'decided_at': now,
        'submitted_at': now,
    }

    validated_values = {
        name: value for name, value in values.items() if name in fields
    }

    for name, field in fields.items():
        if name not in validated_values and field.is_required():
            if name in {'created_at', 'decided_at', 'submitted_at'}:
                validated_values[name] = now

    try:
        return HumanOverride.model_validate(validated_values)
    except ValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail='The human override does not match the audit schema',
        ) from exc


def _build_audit_receipt(
    listing: ListingInput,
    policy_result: PolicyResult,
    actor: Literal['system', 'human'],
    original_receipt: AuditReceipt | None = None,
    human_override: HumanOverride | None = None,
) -> AuditReceipt:
    """Build a schema-version-tolerant receipt for the Phase 2 store."""
    now = datetime.now(timezone.utc)
    receipt_id = uuid4()
    fields = AuditReceipt.model_fields
    values: dict[str, object] = {}

    _put_field(fields, values, ('receipt_id', 'id'), receipt_id)
    _put_field(fields, values, ('listing_id',), listing.listing_id)
    _put_field(fields, values, ('listing_hash',), compute_listing_hash(listing))
    _put_field(fields, values, ('listing',), listing)
    _put_field(fields, values, ('actor',), actor)
    _put_field(
        fields,
        values,
        ('policy_version', 'engine_version', 'model_version'),
        DETERMINISTIC_POLICY_VERSION,
    )
    _put_field(
        fields,
        values,
        ('action', 'effective_action', 'final_action', 'reviewed_action'),
        (
            human_override.action
            if human_override is not None
            else policy_result.action
        ),
    )
    _put_field(fields, values, ('bucket', 'policy_bucket'), policy_result.bucket)
    _put_field(
        fields,
        values,
        ('confidence', 'policy_confidence', 'classifier_confidence'),
        policy_result.confidence,
    )
    _put_field(
        fields,
        values,
        ('reason_codes', 'policy_reason_codes', 'decision_reason_codes'),
        policy_result.reason_codes,
    )
    _put_field(fields, values, ('rationale',), policy_result.rationale)

    policy_field_name: str | None = None
    for field_name, field in fields.items():
        if _annotation_contains(field.annotation, PolicyResult):
            policy_field_name = field_name
            values[field_name] = policy_result
            break

    if policy_field_name is None:
        policy_field_name = _put_field(
            fields,
            values,
            _POLICY_RESULT_FIELDS,
            policy_result,
        )

    override_field_name: str | None = None
    for field_name, field in fields.items():
        if _annotation_contains(field.annotation, HumanOverride):
            override_field_name = field_name
            if human_override is not None:
                values[field_name] = human_override
            break

    if override_field_name is None and human_override is not None:
        override_field_name = _put_field(
            fields,
            values,
            _OVERRIDE_FIELDS,
            human_override,
        )

    if original_receipt is not None:
        _put_field(
            fields,
            values,
            ('original_receipt_id', 'parent_receipt_id', 'source_receipt_id'),
            original_receipt.receipt_id,
        )
        _put_field(
            fields,
            values,
            (
                'parent_receipt_hash',
                'previous_receipt_hash',
                'original_receipt_hash',
            ),
            compute_receipt_hash(original_receipt),
        )
        _put_field(
            fields,
            values,
            ('original_receipt', 'parent_receipt', 'source_receipt'),
            original_receipt,
        )

        try:
            previous_revision = int(getattr(original_receipt, 'revision', 0))
        except (TypeError, ValueError):
            previous_revision = 0
        _put_field(
            fields,
            values,
            ('revision', 'sequence', 'receipt_number'),
            previous_revision + 1,
        )

    if human_override is not None:
        _put_field(
            fields,
            values,
            ('operator_id', 'reviewer_id', 'operator_identifier'),
            human_override.operator_id,
        )
        _put_field(
            fields,
            values,
            ('override_reason', 'review_reason', 'note'),
            human_override.reason,
        )

    for timestamp_name in (
        'created_at',
        'decided_at',
        'issued_at',
        'submitted_at',
    ):
        _put_field(fields, values, (timestamp_name,), now)

    for field_name, field in fields.items():
        if field_name in values or not field.is_required():
            continue

        if 'signature' in field_name.casefold():
            values[field_name] = 'pending-store-signature'
            continue

        default_value = _required_field_default(field_name, field.annotation)
        if default_value is not None:
            values[field_name] = default_value
            continue

        raise ReceiptStoreError(
            f'Unsupported required AuditReceipt field: {field_name}'
        )

    try:
        return AuditReceipt.model_validate(values)
    except ValidationError as exc:
        raise ReceiptStoreError(
            'The configured AuditReceipt schema cannot represent the moderation result'
        ) from exc


def _append_with_override(
    store: object,
    receipt: AuditReceipt,
    human_override: HumanOverride | None,
    original_receipt: AuditReceipt | None,
) -> AuditReceipt:
    found = _find_method(
        store,
        (
            'append_receipt',
            'add_receipt',
            'record_receipt',
            'store_receipt',
            'append',
            'record',
        ),
    )
    if found is None:
        raise ReceiptStoreError('Receipt store does not expose receipt persistence')

    method_name, method = found
    kwargs: dict[str, object] = {}
    parent_hash: str | None = None

    try:
        parameters = inspect.signature(method).parameters
    except (TypeError, ValueError):
        parameters = {}

    for parameter_name in parameters:
        if parameter_name in _RECEIPT_ID_FIELDS:
            kwargs[parameter_name] = receipt
        elif parameter_name in _OVERRIDE_PARAMETER_NAMES:
            kwargs[parameter_name] = human_override
        elif 'parent_receipt_hash' in parameter_name or (
            'previous_receipt_hash' in parameter_name
        ):
            if original_receipt is not None:
                parent_hash = compute_receipt_hash(original_receipt)
                kwargs[parameter_name] = parent_hash
        elif parameter_name in {
            'original_receipt_id',
            'parent_receipt_id',
            'source_receipt_id',
        }:
            if original_receipt is not None:
                kwargs[parameter_name] = original_receipt.receipt_id

    if kwargs:
        kwargs.setdefault('receipt', receipt)
        candidates: tuple[
            tuple[tuple[object, ...], dict[str, object]],
            ...,
        ] = (((), kwargs),)
    else:
        candidates = (
            ((receipt,), {}),
            ((receipt, human_override), {}),
            ((), {'receipt': receipt}),
            (
                (),
                {
                    'receipt': receipt,
                    'human_override': human_override,
                },
            ),
        )

    result = _invoke_compatible(method, candidates)

    if result is None or result is True:
        return receipt
    if isinstance(result, (UUID, str)):
        return _coerce_backend_receipt(result)

    return _coerce_backend_receipt(result)


def _store_system_receipt(
    store: object,
    listing: ListingInput,
    policy_result: PolicyResult,
) -> AuditReceipt:
    receipt = _build_audit_receipt(
        listing=listing,
        policy_result=policy_result,
        actor='system',
    )

    dedicated = _find_method(
        store,
        (
            'record_system_receipt',
            'record_system_decision',
            'create_system_receipt',
        ),
    )
    if dedicated is not None:
        _, method = dedicated
        try:
            result = _invoke_compatible(
                method,
                (
                    ((receipt,), {}),
                    ((), {'receipt': receipt}),
                    (
                        (listing, policy_result, DETERMINISTIC_POLICY_VERSION),
                        {},
                    ),
                    (
                        (),
                        {
                            'listing': listing,
                            'policy_result': policy_result,
                            'policy_version': DETERMINISTIC_POLICY_VERSION,
                        },
                    ),
                    ((listing, policy_result), {}),
                ),
            )
        except _IncompatibleMethodCall:
            pass
        else:
            if isinstance(result, (UUID, str)):
                raise ReceiptStoreError(
                    f'Receipt backend returned an invalid record: {method_name}'
                )
            if result is None:
                return receipt
            return _coerce_backend_receipt(result)

    return _append_with_override(
        store=store,
        receipt=receipt,
        human_override=None,
        original_receipt=None,
    )


def _store_human_receipt(
    store: object,
    original_receipt: AuditReceipt,
    human_override: HumanOverride,
    system_policy_result: PolicyResult,
) -> AuditReceipt:
    human_receipt = _build_audit_receipt(
        listing=ListingInput.model_validate(
            {
                'listing_id': original_receipt.listing_id,
                'title': 'Human-reviewed listing receipt',
            }
        ),
        policy_result=system_policy_result,
        actor='human',
        original_receipt=original_receipt,
        human_override=human_override,
    )

    dedicated = _find_method(
        store,
        (
            'append_human_override',
            'record_human_override',
            'append_override',
            'record_override',
            'apply_override',
            'apply_human_override',
        ),
    )
    if dedicated is not None:
        _, method = dedicated
        try:
            result = _invoke_compatible(
                method,
                (
                    (
                        (original_receipt, human_override, human_receipt),
                        {},
                    ),
                    ((), {
                        'original_receipt': original_receipt,
                        'override': human_override,
                        'receipt': human_receipt,
                    }),
                    ((human_receipt, human_override), {}),
                    ((human_override, human_receipt), {}),
                    ((original_receipt, human_override), {}),
                    (
                        (original_receipt.receipt_id, human_override),
                        {},
                    ),
                    ((human_override, original_receipt.receipt_id), {}),
                    (
                        (
                            original_receipt,
                            human_override,
                            system_policy_result,
                            DETERMINISTIC_POLICY_VERSION,
                        ),
                        {},
                    ),
                    ((human_receipt,), {}),
                    ((human_override,), {}),
                ),
            )
        except _IncompatibleMethodCall:
            pass
        else:
            if result is None:
                return human_receipt
            return _coerce_backend_receipt(result)

    return _append_with_override(
        store=store,
        receipt=human_receipt,
        human_override=human_override,
        original_receipt=original_receipt,
    )


def _extract_policy_result(receipt: object) -> PolicyResult | None:
    if isinstance(receipt, PolicyResult):
        return receipt

    seen: set[int] = set()
    queue: list[object] = [receipt]

    while queue:
        current = queue.pop(0)
        identity = id(current)
        if identity in seen:
            continue
        seen.add(identity)

        if isinstance(current, PolicyResult):
            return current

        for field_name in _POLICY_RESULT_FIELDS:
            nested = _mapping_value(current, field_name)
            if nested is not None:
                queue.append(nested)

        mapping: Mapping[str, object] | None = None
        if isinstance(current, Mapping):
            mapping = current
        elif hasattr(current, 'model_dump'):
            try:
                dumped = current.model_dump(mode='python')
            except (AttributeError, TypeError):
                dumped = None
            if isinstance(dumped, Mapping):
                mapping = dumped

        if mapping is not None:
            action = mapping.get('action')
            bucket = mapping.get('bucket')
            confidence = mapping.get('confidence')
            if action is not None and bucket is not None and confidence is not None:
                try:
                    return PolicyResult.model_validate(
                        {
                            'action': action,
                            'bucket': bucket,
                            'confidence': float(confidence),
                            'reason_codes': mapping.get(
                                'reason_codes',
                                mapping.get('reasons', ()),
                            ),
                            'rationale': mapping.get('rationale', ''),
                        }
                    )
                except (TypeError, ValueError, ValidationError):
                    pass

    return None


def _extract_human_override(receipt: object) -> HumanOverride | None:
    for field_name in _OVERRIDE_FIELDS:
        value = _mapping_value(receipt, field_name)
        if isinstance(value, HumanOverride):
            return value
        if isinstance(value, Mapping):
            try:
                return HumanOverride.model_validate(value)
            except ValidationError:
                continue
    return None


def _receipt_effective_action(receipt: object) -> Action | None:
    for field_name in (
        'effective_action',
        'final_action',
        'reviewed_action',
        'content_action',
        'action',
    ):
        value = _mapping_value(receipt, field_name)
        if isinstance(value, Action):
            return value
        if isinstance(value, str):
            try:
                return Action(value)
            except ValueError:
                pass

    override = _extract_human_override(receipt)
    if override is not None:
        return override.action

    policy_result = _extract_policy_result(receipt)
    if policy_result is not None:
        return policy_result.action

    return None


def _receipt_response(receipt: AuditReceipt) -> dict[str, object]:
    policy_result = _extract_policy_result(receipt)
    if policy_result is None:
        raise ReceiptStoreError(
            'AuditReceipt does not contain a valid nested PolicyResult'
        )

    effective_action = _receipt_effective_action(receipt)
    if effective_action is None:
        raise ReceiptStoreError(
            'AuditReceipt does not contain a valid content action'
        )

    payload = receipt.model_dump(mode='json')
    policy_payload = policy_result.model_dump(mode='json')

    payload['policy_result'] = policy_payload
    payload['action'] = effective_action.value
    payload['effective_action'] = effective_action.value
    payload['bucket'] = policy_result.bucket.value
    payload['confidence'] = policy_result.confidence
    payload['reason_codes'] = list(policy_result.reason_codes)
    payload['rationale'] = policy_result.rationale

    return payload


def _assert_receipt_actor(
    receipt: AuditReceipt,
    expected_actor: Literal['system', 'human'],
) -> None:
    if receipt.actor != expected_actor:
        raise ReceiptStoreError(
            f'Receipt store changed the immutable {expected_actor!r} actor'
        )


def _raise_storage_http_error(exc: ReceiptStoreError) -> HTTPException:
    if isinstance(exc, ReceiptNotFoundError):
        return HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail='Receipt not found',
        )
    if isinstance(exc, ReceiptConflictError):
        return HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail='Receipt conflict',
        )
    if isinstance(exc, (ReceiptSignatureError, SigningKeyConflictError)):
        return HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail='Receipt integrity service is unavailable',
        )

    LOGGER.exception('Receipt backend failure', exc_info=exc)
    return HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail='Receipt backend failure',
    )


async def _close_store(store: object) -> None:
    close = getattr(store, 'close', None)
    if not callable(close):
        return

    result = close()
    if inspect.isawaitable(result):
        await result


def create_app(
    database_path: str | Path | None = None,
    *,
    receipt_store: object | None = None,
    store: object | None = None,
    evaluator: PolicyEvaluator = evaluate_listing,
    template_directory: str | Path = DEFAULT_TEMPLATE_DIRECTORY,
    signing_key: str | bytes | None = None,
    verification_mode: VerificationMode = 'permissive',
) -> FastAPI:
    """Create a configured ListGuard API and moderation desk application."""
    if verification_mode not in {'permissive', 'local', 'external'}:
        raise ValueError(
            'verification_mode must be permissive, local, or external'
        )

    supplied_store = receipt_store if receipt_store is not None else store
    owns_store = supplied_store is None

    if supplied_store is None:
        if database_path is None:
            database_path = os.getenv(
                'LISTGUARD_DATABASE_PATH',
                str(DEFAULT_DATABASE_PATH),
            )

        configured_store: object = _build_sqlite_store(
            database_path=Path(database_path),
            signing_key=(
                signing_key
                if signing_key is not None
                else os.getenv('LISTGUARD_SIGNING_KEY')
            ),
            verification_mode=verification_mode,
        )
    else:
        configured_store = supplied_store

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        if owns_store:
            yield
            await _close_store(application.state.receipt_store)
        else:
            yield

    application = FastAPI(
        title='ListGuard',
        version='0.1.0',
        description=(
            'Content-only marketplace trust and safety ingestion control plane'
        ),
        lifespan=lifespan,
    )
    application.state.receipt_store = configured_store
    application.state.policy_evaluator = evaluator
    application.state.verification_mode = verification_mode

    templates = Jinja2Templates(directory=str(template_directory))

    @application.get('/health', tags=['operations'])
    def health() -> dict[str, str]:
        return {'status': 'ok'}

    @application.get(
        '/',
        response_class=HTMLResponse,
        include_in_schema=False,
    )
    def moderation_desk(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(
            request=request,
            name='index.html',
            context={
                'policy_version': DETERMINISTIC_POLICY_VERSION,
            },
        )

    @application.post('/api/v1/moderate', tags=['moderation'])
    def moderate_listing(listing: ListingInput) -> dict[str, object]:
        try:
            evaluated = application.state.policy_evaluator(listing)
            policy_result = PolicyResult.model_validate(evaluated)
        except ValidationError as exc:
            LOGGER.error('Policy evaluator returned an invalid result: %s', exc)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail='Policy evaluator contract failure',
            ) from exc
        except Exception as exc:
            LOGGER.exception('Policy evaluation failed')
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail='Policy evaluation failed',
            ) from exc

        try:
            receipt = _store_system_receipt(
                application.state.receipt_store,
                listing,
                policy_result,
            )
            _assert_receipt_actor(receipt, 'system')
            return _receipt_response(receipt)
        except ReceiptStoreError as exc:
            raise _raise_storage_http_error(exc) from exc

    @application.get('/api/v1/receipts/{receipt_id}', tags=['receipts'])
    def get_receipt(receipt_id: UUID) -> dict[str, object]:
        try:
            receipt = _get_receipt(
                application.state.receipt_store,
                receipt_id,
                application.state.verification_mode,
            )
            return _receipt_response(receipt)
        except ReceiptStoreError as exc:
            raise _raise_storage_http_error(exc) from exc

    @application.post(
        '/api/v1/receipts/{receipt_id}/override',
        tags=['receipts'],
    )
    def override_receipt(
        receipt_id: UUID,
        command: OverrideRequest,
    ) -> dict[str, object]:
        try:
            original_receipt = _get_receipt(
                application.state.receipt_store,
                receipt_id,
                application.state.verification_mode,
            )
        except ReceiptStoreError as exc:
            raise _raise_storage_http_error(exc) from exc

        system_policy_result = _extract_policy_result(original_receipt)
        if system_policy_result is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail='Stored receipt has no valid policy result',
            )

        current_action = _receipt_effective_action(original_receipt)
        if current_action is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail='Stored receipt has no valid content action',
            )

        if command.decision == 'accept':
            if command.action is not None and command.action != current_action:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail='Accept cannot change the system content action',
                )
            effective_action = current_action
        else:
            if command.action is None:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail='An override action is required',
                )
            effective_action = command.action

        human_override = _build_human_override(
            receipt_id=original_receipt.receipt_id,
            command=command,
            action=effective_action,
        )

        try:
            human_receipt = _store_human_receipt(
                store=application.state.receipt_store,
                original_receipt=original_receipt,
                human_override=human_override,
                system_policy_result=system_policy_result,
            )
            _assert_receipt_actor(human_receipt, 'human')
            if human_receipt.receipt_id == original_receipt.receipt_id:
                raise ReceiptStoreError(
                    'Human override reused the immutable system receipt identifier'
                )
            return _receipt_response(human_receipt)
        except ReceiptStoreError as exc:
            raise _raise_storage_http_error(exc) from exc

    return application


app = create_app()

__all__ = ['OverrideRequest', 'app', 'create_app']