from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import secrets
import sqlite3
import threading
from collections.abc import Iterator, Mapping
from datetime import datetime, timezone
from pathlib import Path
from types import TracebackType
from typing import Literal
from uuid import UUID

from pydantic import ValidationError

from listguard.models import (
    Action,
    AuditReceipt,
    HumanOverride,
    ListingInput,
    PolicyBucket,
    PolicyResult,
    ReceiptActor,
)
from listguard.taxonomy import POLICY_BUCKETS

DEFAULT_DATABASE_PATH = Path('receipts.db')

_SIGNATURE_ALGORITHM = 'hmac-sha256'
_SIGNATURE_PREFIX = f'{_SIGNATURE_ALGORITHM}:'
_SIGNING_KEY_METADATA_KEY = 'audit-integrity-key-v1'

VerificationMode = Literal['permissive', 'local', 'external']


class ReceiptStoreError(RuntimeError):
    '''Base exception for persistence, configuration, or signing failures.'''


class ReceiptNotFoundError(ReceiptStoreError):
    '''Raised when a requested receipt or override does not exist.'''


class ReceiptConflictError(ReceiptStoreError):
    '''Raised when an immutable identifier is reused with different content.'''


class ReceiptSignatureError(ReceiptStoreError):
    '''Raised when a required local receipt signature is invalid.'''


class SigningKeyConflictError(ReceiptStoreError):
    '''Raised when an explicit key conflicts with an existing database key.'''


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(',', ':'),
        ).encode('utf-8')
    except (TypeError, ValueError) as exc:
        raise ReceiptStoreError(
            'Value cannot be represented as canonical JSON'
        ) from exc


def compute_listing_hash(
    listing: ListingInput | Mapping[str, object],
) -> str:
    '''Compute a stable SHA-256 hash over a validated listing payload.'''
    validated_listing = ListingInput.model_validate(listing)
    canonical_payload = validated_listing.model_dump(mode='json')
    return hashlib.sha256(_canonical_json_bytes(canonical_payload)).hexdigest()


def hash_listing(
    listing: ListingInput | Mapping[str, object],
) -> str:
    '''Compatibility alias for :func:`compute_listing_hash`.'''
    return compute_listing_hash(listing)


def compute_receipt_hash(receipt: AuditReceipt) -> str:
    '''Compute the canonical hash used to link an audit receipt revision.'''
    validated_receipt = _coerce_receipt(receipt)
    canonical_payload = validated_receipt.model_dump(mode='json')
    return hashlib.sha256(_canonical_json_bytes(canonical_payload)).hexdigest()


def hash_receipt(receipt: AuditReceipt) -> str:
    '''Compatibility alias for :func:`compute_receipt_hash`.'''
    return compute_receipt_hash(receipt)


def _normalize_signing_key(signing_key: str | bytes | None) -> bytes | None:
    if signing_key is None:
        return None
    if isinstance(signing_key, str):
        if not signing_key:
            raise ValueError('signing_key cannot be empty')
        return signing_key.encode('utf-8')
    if isinstance(signing_key, bytes):
        if not signing_key:
            raise ValueError('signing_key cannot be empty')
        return bytes(signing_key)
    raise TypeError('signing_key must be a string, bytes, or None')


def _coerce_uuid(value: UUID | str, field_name: str) -> str:
    try:
        if isinstance(value, UUID):
            return str(value)
        return str(UUID(str(value)))
    except (TypeError, ValueError, AttributeError) as exc:
        raise ValueError(f'{field_name} must be a valid UUID') from exc


def _coerce_receipt(receipt: AuditReceipt | Mapping[str, object]) -> AuditReceipt:
    if isinstance(receipt, AuditReceipt):
        return receipt
    return AuditReceipt.model_validate(receipt)


def _parse_receipt(payload: str) -> AuditReceipt:
    try:
        return AuditReceipt.model_validate_json(payload)
    except ValidationError as exc:
        raise ReceiptStoreError(
            'Stored receipt payload is invalid or does not match the schema'
        ) from exc


def _parse_human_override(payload: str) -> HumanOverride:
    try:
        return HumanOverride.model_validate_json(payload)
    except ValidationError as exc:
        raise ReceiptStoreError(
            'Stored human override payload is invalid'
        ) from exc


def _utc_iso(value: datetime, field_name: str) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f'{field_name} must be timezone-aware')
    return (
        value.astimezone(timezone.utc)
        .isoformat(timespec='microseconds')
        .replace('+00:00', 'Z')
    )


def _coerce_filter_actor(actor: ReceiptActor | str | None) -> str | None:
    if actor is None:
        return None
    normalized = str(actor)
    if normalized not in {'system', 'human'}:
        raise ValueError("actor must be 'system', 'human', or None")
    return normalized


def _coerce_filter_action(action: Action | str | None) -> str | None:
    if action is None:
        return None
    return Action(action).value


def _coerce_filter_bucket(bucket: PolicyBucket | str | None) -> str | None:
    if bucket is None:
        return None
    normalized = PolicyBucket(bucket).value
    if normalized not in POLICY_BUCKETS:
        raise ValueError('bucket is outside the configured policy taxonomy')
    return normalized


def _validate_page_limit(limit: int | None, field_name: str) -> int | None:
    if limit is None:
        return None
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise TypeError(f'{field_name} must be an integer or None')
    if limit < 0:
        raise ValueError(f'{field_name} must be at least 0')
    return limit


class ReceiptStore:
    '''Thread-safe SQLite store for immutable, signed moderation receipts.'''

    def __init__(
        self,
        database_path: str | Path = DEFAULT_DATABASE_PATH,
        signing_key: str | bytes | None = None,
        *,
        verification_mode: VerificationMode = 'permissive',
        allow_external_signatures: bool | None = None,
        require_valid_signature: bool | None = None,
    ) -> None:
        if verification_mode not in {'permissive', 'local', 'external'}:
            raise ValueError(
                "verification_mode must be 'permissive', 'local', or 'external'"
            )
        if allow_external_signatures is not None and not isinstance(
            allow_external_signatures, bool
        ):
            raise TypeError('allow_external_signatures must be a boolean or None')
        if require_valid_signature is not None and not isinstance(
            require_valid_signature, bool
        ):
            raise TypeError('require_valid_signature must be a boolean or None')

        self.database_path = Path(database_path)
        self.verification_mode = verification_mode
        self.allow_external_signatures = (
            verification_mode != 'local'
            if allow_external_signatures is None
            else allow_external_signatures
        )
        self.require_valid_signature = (
            verification_mode == 'local'
            if require_valid_signature is None
            else require_valid_signature
        )
        self._provided_signing_key = _normalize_signing_key(signing_key)
        self._signing_key: bytes | None = None
        self._lock = threading.RLock()
        self._connection: sqlite3.Connection | None = None
        self._open()

    @property
    def signing_key(self) -> bytes:
        '''Return a copy of the active local audit-signing key.'''
        if self._signing_key is None:
            raise ReceiptStoreError('Local audit signing is not initialized')
        return bytes(self._signing_key)

    def _open(self) -> None:
        if self._connection is not None:
            return

        connection: sqlite3.Connection | None = None
        try:
            self.database_path.parent.mkdir(parents=True, exist_ok=True)
            connection = sqlite3.connect(
                str(self.database_path),
                timeout=30.0,
                check_same_thread=False,
            )
            connection.row_factory = sqlite3.Row
            connection.execute('PRAGMA foreign_keys = ON')
            connection.execute('PRAGMA busy_timeout = 30000')
            connection.execute('PRAGMA synchronous = NORMAL')
            connection.execute('PRAGMA journal_mode = WAL')

            bucket_values = ', '.join(
                f"'{bucket}'" for bucket in POLICY_BUCKETS
            )
            connection.executescript(
                f'''
                CREATE TABLE IF NOT EXISTS audit_metadata (
                    metadata_key TEXT PRIMARY KEY,
                    metadata_value BLOB NOT NULL
                ) WITHOUT ROWID;

                CREATE TABLE IF NOT EXISTS receipts (
                    receipt_id TEXT PRIMARY KEY,
                    listing_id TEXT NOT NULL,
                    listing_hash TEXT NOT NULL,
                    actor TEXT NOT NULL
                        CHECK (actor IN ('system', 'human')),
                    operator_id TEXT,
                    bucket TEXT NOT NULL
                        CHECK (bucket IN ({bucket_values})),
                    action TEXT NOT NULL
                        CHECK (action IN ('allow', 'queue', 'block')),
                    reason_codes_json TEXT NOT NULL,
                    policy_version TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    previous_receipt_hash TEXT,
                    original_receipt_id TEXT,
                    override_action TEXT
                        CHECK (
                            override_action IS NULL OR
                            override_action IN ('allow', 'queue', 'block')
                        ),
                    override_reason TEXT,
                    overridden_at TEXT,
                    payload_json TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS receipts_listing_created_idx
                    ON receipts (listing_id, created_at, receipt_id);

                CREATE INDEX IF NOT EXISTS receipts_listing_hash_idx
                    ON receipts (listing_hash);

                CREATE INDEX IF NOT EXISTS receipts_actor_idx
                    ON receipts (actor, created_at);

                CREATE INDEX IF NOT EXISTS receipts_operator_idx
                    ON receipts (operator_id, created_at);

                CREATE INDEX IF NOT EXISTS receipts_previous_hash_idx
                    ON receipts (previous_receipt_hash);

                CREATE TABLE IF NOT EXISTS human_overrides (
                    override_receipt_id TEXT PRIMARY KEY,
                    original_receipt_id TEXT NOT NULL,
                    actor TEXT NOT NULL CHECK (actor = 'human'),
                    operator_id TEXT NOT NULL,
                    action TEXT NOT NULL
                        CHECK (action IN ('allow', 'queue', 'block')),
                    reason TEXT NOT NULL,
                    overridden_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    FOREIGN KEY (override_receipt_id)
                        REFERENCES receipts (receipt_id),
                    FOREIGN KEY (original_receipt_id)
                        REFERENCES receipts (receipt_id)
                );

                CREATE INDEX IF NOT EXISTS human_overrides_original_idx
                    ON human_overrides (
                        original_receipt_id,
                        overridden_at,
                        override_receipt_id
                    );

                CREATE INDEX IF NOT EXISTS human_overrides_operator_idx
                    ON human_overrides (operator_id, overridden_at);
                '''
            )
            self._initialize_signing_key(connection)
            self._connection = connection
        except ReceiptStoreError:
            if connection is not None:
                connection.close()
            raise
        except (OSError, sqlite3.Error) as exc:
            if connection is not None:
                connection.close()
            raise ReceiptStoreError(
                f'Unable to initialize receipt database at {self.database_path}'
            ) from exc

    def _initialize_signing_key(self, connection: sqlite3.Connection) -> None:
        try:
            connection.execute('BEGIN IMMEDIATE')
            row = connection.execute(
                '''
                SELECT metadata_value
                FROM audit_metadata
                WHERE metadata_key = ?
                ''',
                (_SIGNING_KEY_METADATA_KEY,),
            ).fetchone()

            if row is None:
                key = self._provided_signing_key or secrets.token_bytes(32)
                encoded_key = base64.b64encode(key).decode('ascii')
                connection.execute(
                    '''
                    INSERT INTO audit_metadata (
                        metadata_key,
                        metadata_value
                    )
                    VALUES (?, ?)
                    ''',
                    (
                        _SIGNING_KEY_METADATA_KEY,
                        f'{_SIGNATURE_ALGORITHM}:{encoded_key}',
                    ),
                )
                self._signing_key = key
            else:
                stored_key = self._decode_stored_key(row['metadata_value'])
                if (
                    self._provided_signing_key is not None
                    and not hmac.compare_digest(
                        stored_key,
                        self._provided_signing_key,
                    )
                ):
                    raise SigningKeyConflictError(
                        'Stored audit signing key does not match signing_key'
                    )
                self._signing_key = stored_key

            connection.commit()
        except ReceiptStoreError:
            connection.rollback()
            raise
        except sqlite3.Error as exc:
            connection.rollback()
            raise ReceiptStoreError(
                'Unable to initialize the stored audit signing key'
            ) from exc

    @staticmethod
    def _decode_stored_key(raw_value: object) -> bytes:
        try:
            if isinstance(raw_value, memoryview):
                raw_value = raw_value.tobytes()
            if isinstance(raw_value, bytes):
                serialized = raw_value.decode('ascii')
            elif isinstance(raw_value, str):
                serialized = raw_value
            else:
                raise ValueError('metadata value is not text')

            algorithm, separator, encoded_key = serialized.partition(':')
            if (
                separator != ':'
                or algorithm != _SIGNATURE_ALGORITHM
                or not encoded_key
            ):
                raise ValueError('metadata envelope is invalid')

            padding = '=' * ((4 - len(encoded_key) % 4) % 4)
            decoded = base64.b64decode(
                encoded_key + padding,
                validate=True,
            )
            if not decoded:
                raise ValueError('decoded key is empty')
            return decoded
        except (
            UnicodeError,
            ValueError,
            binascii.Error,
        ) as exc:
            raise ReceiptStoreError(
                'Stored audit signing key is corrupt'
            ) from exc

    def _require_connection(self) -> sqlite3.Connection:
        if self._connection is None:
            raise ReceiptStoreError('Receipt store is not open')
        return self._connection

    def close(self) -> None:
        '''Close the SQLite connection. The store may be reopened as a context.'''
        with self._lock:
            if self._connection is not None:
                self._connection.close()
                self._connection = None

    def __enter__(self) -> ReceiptStore:
        with self._lock:
            if self._connection is None:
                self._open()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def __del__(self) -> None:
        connection = getattr(self, '_connection', None)
        if connection is not None:
            try:
                connection.close()
            except sqlite3.Error:
                return

    def _signing_payload(self, receipt: AuditReceipt) -> bytes:
        return _canonical_json_bytes(
            receipt.model_dump(mode='json', exclude={'signature'})
        )

    def sign_receipt(self, receipt: AuditReceipt) -> str:
        '''Return a local HMAC signature for a validated receipt.'''
        validated_receipt = _coerce_receipt(receipt)
        digest = hmac.new(
            self.signing_key,
            self._signing_payload(validated_receipt),
            hashlib.sha256,
        ).hexdigest()
        return f'{_SIGNATURE_PREFIX}{digest}'

    def verify_receipt(self, receipt: AuditReceipt) -> bool:
        '''Return whether a receipt has a valid local HMAC signature.'''
        try:
            validated_receipt = _coerce_receipt(receipt)
            supplied_signature = validated_receipt.signature
            if not supplied_signature.startswith(_SIGNATURE_PREFIX):
                return False
            supplied_digest = supplied_signature[len(_SIGNATURE_PREFIX):]
            if len(supplied_digest) != hashlib.sha256().digest_size * 2:
                return False

            expected_digest = hmac.new(
                self.signing_key,
                self._signing_payload(validated_receipt),
                hashlib.sha256,
            ).hexdigest()
            return hmac.compare_digest(supplied_digest, expected_digest)
        except (ReceiptStoreError, ValidationError, TypeError, ValueError):
            return False

    def create_receipt(
        self,
        listing: ListingInput | Mapping[str, object],
        result: PolicyResult | Mapping[str, object],
        policy_version: str,
        *,
        listing_hash: str | None = None,
        previous_receipt_hash: str | None = None,
        receipt_id: UUID | str | None = None,
        created_at: datetime | None = None,
        actor: ReceiptActor = 'system',
        operator_id: str | None = None,
        original_receipt_id: UUID | str | None = None,
        override_action: Action | str | None = None,
        override_reason: str | None = None,
        overridden_at: datetime | None = None,
    ) -> AuditReceipt:
        '''Create and locally sign a receipt without persisting it.'''
        self._require_connection()
        validated_listing = ListingInput.model_validate(listing)
        validated_result = PolicyResult.model_validate(result)
        resolved_listing_hash = (
            listing_hash or compute_listing_hash(validated_listing)
        )

        fields: dict[str, object] = {
            'listing_id': validated_listing.listing_id,
            'listing_hash': resolved_listing_hash,
            'result': validated_result,
            'policy_version': policy_version,
            'signature': 'pending:local-signature',
            'previous_receipt_hash': previous_receipt_hash,
            'original_receipt_id': original_receipt_id,
            'actor': actor,
            'operator_id': operator_id,
            'override_action': override_action,
            'override_reason': override_reason,
            'overridden_at': overridden_at,
        }
        if receipt_id is not None:
            fields['receipt_id'] = receipt_id
        if created_at is not None:
            fields['created_at'] = created_at

        unsigned_receipt = AuditReceipt.model_validate(fields)
        signed_fields = unsigned_receipt.model_dump(mode='python')
        signed_fields['signature'] = self.sign_receipt(unsigned_receipt)
        return AuditReceipt.model_validate(signed_fields)

    def record_decision(
        self,
        listing: ListingInput | Mapping[str, object],
        result: PolicyResult | Mapping[str, object],
        policy_version: str,
        *,
        previous_receipt_hash: str | None = None,
        receipt_id: UUID | str | None = None,
        created_at: datetime | None = None,
    ) -> AuditReceipt:
        '''Create, sign, and atomically persist a system decision receipt.'''
        receipt = self.create_receipt(
            listing,
            result,
            policy_version,
            previous_receipt_hash=previous_receipt_hash,
            receipt_id=receipt_id,
            created_at=created_at,
        )
        self.append_receipt(receipt)
        return receipt

    def _prepare_human_override(
        self,
        connection: sqlite3.Connection,
        receipt: AuditReceipt,
    ) -> tuple[UUID, HumanOverride]:
        if receipt.override_action is None:
            raise ReceiptStoreError(
                'Human override receipt requires an override_action'
            )

        original: AuditReceipt | None = None
        if receipt.original_receipt_id is not None:
            row = connection.execute(
                '''
                SELECT payload_json
                FROM receipts
                WHERE receipt_id = ?
                ''',
                (str(receipt.original_receipt_id),),
            ).fetchone()
            if row is not None:
                original = _parse_receipt(str(row['payload_json']))
        elif receipt.previous_receipt_hash is not None:
            rows = connection.execute(
                '''
                SELECT payload_json
                FROM receipts
                WHERE listing_id = ?
                ORDER BY created_at, receipt_id
                ''',
                (receipt.listing_id,),
            ).fetchall()
            for candidate_row in rows:
                candidate = _parse_receipt(str(candidate_row['payload_json']))
                if compute_receipt_hash(candidate) == receipt.previous_receipt_hash:
                    original = candidate
                    break

        if original is None:
            raise ReceiptStoreError(
                'Human override receipt must reference an existing receipt'
            )
        if original.receipt_id == receipt.receipt_id:
            raise ReceiptStoreError(
                'A human override cannot reference itself'
            )
        if original.listing_id != receipt.listing_id:
            raise ReceiptStoreError(
                'Human override and original receipt must reference the same listing'
            )
        if receipt.override_reason is None or receipt.overridden_at is None:
            raise ReceiptStoreError(
                'Human override receipt is missing its reason or timestamp'
            )
        if receipt.operator_id is None:
            raise ReceiptStoreError(
                'Human override receipt is missing its operator identifier'
            )

        override = HumanOverride(
            receipt_id=original.receipt_id,
            action=receipt.override_action,
            reason=receipt.override_reason,
            operator_id=receipt.operator_id,
            actor='human',
            created_at=receipt.overridden_at,
        )
        return original.receipt_id, override

    def append_receipt(
        self,
        receipt: AuditReceipt | Mapping[str, object],
    ) -> bool:
        '''Persist a receipt idempotently.

        Returns ``True`` for a newly inserted receipt and ``False`` when the
        exact immutable receipt already exists. Reusing an identifier for
        different content raises :class:`ReceiptConflictError`.
        '''
        validated_receipt = _coerce_receipt(receipt)

        with self._lock:
            connection = self._require_connection()
            try:
                with connection:
                    existing_row = connection.execute(
                        '''
                        SELECT payload_json
                        FROM receipts
                        WHERE receipt_id = ?
                        ''',
                        (str(validated_receipt.receipt_id),),
                    ).fetchone()

                    if existing_row is not None:
                        existing = _parse_receipt(
                            str(existing_row['payload_json'])
                        )
                        if existing == validated_receipt:
                            return False
                        raise ReceiptConflictError(
                            'receipt_id already exists with different content'
                        )

                    if (
                        self.require_valid_signature
                        and not self.verify_receipt(validated_receipt)
                    ):
                        raise ReceiptSignatureError(
                            'Receipt does not have a valid local signature'
                        )

                    prepared_override: tuple[UUID, HumanOverride] | None = None
                    if (
                        validated_receipt.actor == 'human'
                        and validated_receipt.override_action is not None
                    ):
                        prepared_override = self._prepare_human_override(
                            connection,
                            validated_receipt,
                        )

                    effective_action = validated_receipt.effective_action.value
                    connection.execute(
                        '''
                        INSERT INTO receipts (
                            receipt_id,
                            listing_id,
                            listing_hash,
                            actor,
                            operator_id,
                            bucket,
                            action,
                            reason_codes_json,
                            policy_version,
                            created_at,
                            previous_receipt_hash,
                            original_receipt_id,
                            override_action,
                            override_reason,
                            overridden_at,
                            payload_json
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''',
                        (
                            str(validated_receipt.receipt_id),
                            validated_receipt.listing_id,
                            validated_receipt.listing_hash,
                            validated_receipt.actor,
                            validated_receipt.operator_id,
                            validated_receipt.result.bucket.value,
                            effective_action,
                            _canonical_json_bytes(
                                validated_receipt.reason_codes
                            ).decode('utf-8'),
                            validated_receipt.policy_version,
                            _utc_iso(
                                validated_receipt.created_at,
                                'created_at',
                            ),
                            validated_receipt.previous_receipt_hash,
                            (
                                str(validated_receipt.original_receipt_id)
                                if validated_receipt.original_receipt_id
                                is not None
                                else None
                            ),
                            (
                                validated_receipt.override_action.value
                                if validated_receipt.override_action is not None
                                else None
                            ),
                            validated_receipt.override_reason,
                            (
                                _utc_iso(
                                    validated_receipt.overridden_at,
                                    'overridden_at',
                                )
                                if validated_receipt.overridden_at is not None
                                else None
                            ),
                            validated_receipt.model_dump_json(),
                        ),
                    )

                    if prepared_override is not None:
                        original_id, override = prepared_override
                        connection.execute(
                            '''
                            INSERT INTO human_overrides (
                                override_receipt_id,
                                original_receipt_id,
                                actor,
                                operator_id,
                                action,
                                reason,
                                overridden_at,
                                payload_json
                            )
                            VALUES (?, ?, 'human', ?, ?, ?, ?, ?)
                            ''',
                            (
                                str(validated_receipt.receipt_id),
                                str(original_id),
                                override.operator_id,
                                override.action.value,
                                override.reason,
                                _utc_iso(override.created_at, 'overridden_at'),
                                override.model_dump_json(),
                            ),
                        )
                return True
            except ReceiptStoreError:
                raise
            except sqlite3.IntegrityError as exc:
                raise ReceiptConflictError(
                    'Receipt conflicts with an existing audit record'
                ) from exc
            except sqlite3.Error as exc:
                raise ReceiptStoreError(
                    'Unable to append moderation receipt'
                ) from exc

    add_receipt = append_receipt
    save_receipt = append_receipt

    def get_receipt(
        self,
        receipt_id: UUID | str,
    ) -> AuditReceipt | None:
        '''Return a receipt by identifier, or ``None`` when it is absent.'''
        normalized_id = _coerce_uuid(receipt_id, 'receipt_id')
        with self._lock:
            connection = self._require_connection()
            row = connection.execute(
                '''
                SELECT payload_json
                FROM receipts
                WHERE receipt_id = ?
                ''',
                (normalized_id,),
            ).fetchone()

        if row is None:
            return None
        return _parse_receipt(str(row['payload_json']))

    def require_receipt(self, receipt_id: UUID | str) -> AuditReceipt:
        '''Return a receipt or raise :class:`ReceiptNotFoundError`.'''
        receipt = self.get_receipt(receipt_id)
        if receipt is None:
            raise ReceiptNotFoundError(
                f'Receipt {receipt_id!s} does not exist'
            )
        return receipt

    def list_receipts(
        self,
        listing_id: str | None = None,
        *,
        listing_hash: str | None = None,
        actor: ReceiptActor | str | None = None,
        operator_id: str | None = None,
        bucket: PolicyBucket | str | None = None,
        action: Action | str | None = None,
        policy_version: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int | None = 100,
        offset: int = 0,
        newest_first: bool = False,
    ) -> list[AuditReceipt]:
        '''Return receipts matching deterministic audit filters.'''
        actor_value = _coerce_filter_actor(actor)
        action_value = _coerce_filter_action(action)
        bucket_value = _coerce_filter_bucket(bucket)
        validated_limit = _validate_page_limit(limit, 'limit')

        if isinstance(offset, bool) or not isinstance(offset, int):
            raise TypeError('offset must be an integer')
        if offset < 0:
            raise ValueError('offset must be at least 0')

        conditions: list[str] = []
        parameters: list[object] = []

        if listing_id is not None:
            conditions.append('listing_id = ?')
            parameters.append(listing_id)
        if listing_hash is not None:
            conditions.append('listing_hash = ?')
            parameters.append(listing_hash)
        if actor_value is not None:
            conditions.append('actor = ?')
            parameters.append(actor_value)
        if operator_id is not None:
            conditions.append('operator_id = ?')
            parameters.append(operator_id)
        if bucket_value is not None:
            conditions.append('bucket = ?')
            parameters.append(bucket_value)
        if action_value is not None:
            conditions.append('action = ?')
            parameters.append(action_value)
        if policy_version is not None:
            conditions.append('policy_version = ?')
            parameters.append(policy_version)
        if since is not None:
            conditions.append('created_at >= ?')
            parameters.append(_utc_iso(since, 'since'))
        if until is not None:
            conditions.append('created_at <= ?')
            parameters.append(_utc_iso(until, 'until'))

        where_clause = ''
        if conditions:
            where_clause = ' WHERE ' + ' AND '.join(conditions)

        direction = 'DESC' if newest_first else 'ASC'
        query = f'''
            SELECT payload_json
            FROM receipts
            {where_clause}
            ORDER BY created_at {direction}, receipt_id {direction}
        '''
        if validated_limit is not None:
            query += ' LIMIT ? OFFSET ?'
            parameters.extend((validated_limit, offset))
        elif offset:
            query += ' LIMIT -1 OFFSET ?'
            parameters.append(offset)

        with self._lock:
            connection = self._require_connection()
            rows = connection.execute(query, tuple(parameters)).fetchall()

        return [_parse_receipt(str(row['payload_json'])) for row in rows]

    get_receipts = list_receipts

    def iter_receipts(
        self,
        listing_id: str | None = None,
    ) -> Iterator[AuditReceipt]:
        '''Iterate over all receipts, optionally restricted to one listing.'''
        yield from self.list_receipts(listing_id, limit=None)

    def get_receipts_for_listing(
        self,
        listing_id: str,
    ) -> list[AuditReceipt]:
        '''Return the complete chronological audit history for a listing.'''
        return self.list_receipts(listing_id, limit=None)

    def latest_receipt(
        self,
        listing_id: str,
    ) -> AuditReceipt | None:
        '''Return the most recently created receipt for a listing.'''
        receipts = self.list_receipts(
            listing_id,
            limit=1,
            newest_first=True,
        )
        return receipts[0] if receipts else None

    get_latest_receipt = latest_receipt

    def count_receipts(
        self,
        listing_id: str | None = None,
        *,
        actor: ReceiptActor | str | None = None,
    ) -> int:
        '''Return a filtered receipt count without deserializing payloads.'''
        actor_value = _coerce_filter_actor(actor)
        conditions: list[str] = []
        parameters: list[object] = []

        if listing_id is not None:
            conditions.append('listing_id = ?')
            parameters.append(listing_id)
        if actor_value is not None:
            conditions.append('actor = ?')
            parameters.append(actor_value)

        where_clause = ''
        if conditions:
            where_clause = ' WHERE ' + ' AND '.join(conditions)

        with self._lock:
            connection = self._require_connection()
            row = connection.execute(
                f'''
                SELECT COUNT(*) AS receipt_count
                FROM receipts
                {where_clause}
                ''',
                tuple(parameters),
            ).fetchone()
        return int(row['receipt_count'])

    def verify_chain(self, listing_id: str) -> bool:
        '''Verify that each stored receipt links to an earlier receipt.'''
        receipts = self.get_receipts_for_listing(listing_id)
        seen_hashes: set[str] = set()

        for receipt in receipts:
            if receipt.previous_receipt_hash is None:
                if seen_hashes:
                    return False
            elif receipt.previous_receipt_hash not in seen_hashes:
                return False
            seen_hashes.add(compute_receipt_hash(receipt))

        return True

    def verify_receipt_chain(self, receipt: AuditReceipt) -> bool:
        '''Verify one receipt's local link to the stored listing history.'''
        validated_receipt = _coerce_receipt(receipt)
        if self.get_receipt(validated_receipt.receipt_id) != validated_receipt:
            return False
        if validated_receipt.previous_receipt_hash is None:
            return True
        return any(
            compute_receipt_hash(candidate)
            == validated_receipt.previous_receipt_hash
            for candidate in self.get_receipts_for_listing(
                validated_receipt.listing_id
            )
        )

    def _resolve_receipt_reference(
        self,
        receipt: AuditReceipt | UUID | str,
    ) -> AuditReceipt:
        if isinstance(receipt, AuditReceipt):
            return receipt
        return self.require_receipt(receipt)

    def create_override(
        self,
        original_receipt: (
            AuditReceipt
            | HumanOverride
            | UUID
            | str
            | None
        ) = None,
        action: Action | str | HumanOverride | None = None,
        reason: str | None = None,
        operator_id: str | None = None,
        *,
        original_receipt_id: UUID | str | None = None,
        receipt_id: UUID | str | None = None,
        receipt: AuditReceipt | UUID | str | None = None,
        override: HumanOverride | None = None,
        override_action: Action | str | None = None,
        override_reason: str | None = None,
        reviewer_id: str | None = None,
        policy_version: str | None = None,
        previous_receipt_hash: str | None = None,
        created_at: datetime | None = None,
        overridden_at: datetime | None = None,
        new_receipt_id: UUID | str | None = None,
    ) -> AuditReceipt:
        '''Create a signed human override receipt without persisting it.'''
        command = override

        if isinstance(original_receipt, HumanOverride):
            if command is not None:
                raise ValueError('Human override command was provided twice')
            command = original_receipt
            original_receipt = None

        if isinstance(action, HumanOverride):
            if command is not None:
                raise ValueError('Human override command was provided twice')
            command = action
            action = None

        references = [
            candidate
            for candidate in (
                original_receipt,
                original_receipt_id,
                receipt_id,
                receipt,
            )
            if candidate is not None
        ]
        if len(references) > 1:
            raise ValueError('Original receipt was provided more than once')
        base_reference = references[0] if references else None

        if command is not None:
            target_receipt_id = command.receipt_id
        elif base_reference is not None and not isinstance(
            base_reference,
            (UUID, str),
        ):
            target_receipt_id = base_reference.receipt_id
        else:
            target_receipt_id = (
                base_reference
                if base_reference is not None
                else None
            )

        if target_receipt_id is None:
            raise ValueError('An original receipt identifier is required')

        if isinstance(base_reference, AuditReceipt):
            original = base_reference
        elif isinstance(base_reference, (UUID, str)):
            original = self.require_receipt(base_reference)
        else:
            original = self.require_receipt(target_receipt_id)

        if original.receipt_id != target_receipt_id:
            raise ValueError(
                'Human override target does not match the original receipt'
            )

        if action is not None and override_action is not None:
            if Action(action) != Action(override_action):
                raise ValueError('Conflicting human override actions were supplied')
        resolved_action = (
            action
            if action is not None
            else override_action
            if override_action is not None
            else command.action
            if command is not None
            else None
        )
        if resolved_action is None:
            raise ValueError('A human override action is required')

        if reason is not None and override_reason is not None and reason != override_reason:
            raise ValueError('Conflicting human override reasons were supplied')
        resolved_reason = (
            reason
            if reason is not None
            else override_reason
            if override_reason is not None
            else command.reason
            if command is not None
            else None
        )
        if resolved_reason is None:
            raise ValueError('A human override reason is required')

        if operator_id is not None and reviewer_id is not None and operator_id != reviewer_id:
            raise ValueError('Conflicting human operator identifiers were supplied')
        resolved_operator = (
            operator_id
            if operator_id is not None
            else reviewer_id
            if reviewer_id is not None
            else command.operator_id
            if command is not None
            else None
        )
        if resolved_operator is None:
            raise ValueError('A human operator identifier is required')

        resolved_overridden_at = (
            overridden_at
            if overridden_at is not None
            else command.created_at
            if command is not None
            else datetime.now(timezone.utc)
        )

        return self.create_receipt(
            ListingInput(
                listing_id=original.listing_id,
                title=original.listing_id,
            ),
            original.result,
            policy_version or original.policy_version,
            listing_hash=original.listing_hash,
            previous_receipt_hash=(
                previous_receipt_hash
                or compute_receipt_hash(original)
            ),
            receipt_id=new_receipt_id,
            created_at=created_at,
            actor='human',
            operator_id=resolved_operator,
            original_receipt_id=original.receipt_id,
            override_action=Action(resolved_action),
            override_reason=resolved_reason,
            overridden_at=resolved_overridden_at,
        )

    create_human_override = create_override
    build_human_override = create_override

    def record_override(
        self,
        *args: object,
        **kwargs: object,
    ) -> AuditReceipt:
        '''Create, persist, and return a signed human override receipt.'''
        receipt = self.create_override(*args, **kwargs)
        self.append_receipt(receipt)
        return receipt

    record_human_override = record_override

    def append_override(
        self,
        override: HumanOverride,
        *,
        original_receipt: AuditReceipt | UUID | str | None = None,
        policy_version: str | None = None,
        created_at: datetime | None = None,
        overridden_at: datetime | None = None,
    ) -> AuditReceipt:
        '''Create and persist a human override from a validated command.'''
        if not isinstance(override, HumanOverride):
            raise TypeError('override must be a HumanOverride')
        receipt = self.create_override(
            original_receipt=original_receipt,
            override=override,
            policy_version=policy_version,
            created_at=created_at,
            overridden_at=overridden_at,
        )
        self.append_receipt(receipt)
        return receipt

    def create_signoff(
        self,
        original_receipt: AuditReceipt | UUID | str,
        operator_id: str,
        *,
        policy_version: str | None = None,
        receipt_id: UUID | str | None = None,
        created_at: datetime | None = None,
    ) -> AuditReceipt:
        '''Create a signed human acceptance without changing policy output.'''
        original = self._resolve_receipt_reference(original_receipt)
        return self.create_receipt(
            ListingInput(
                listing_id=original.listing_id,
                title=original.listing_id,
            ),
            original.result,
            policy_version or original.policy_version,
            listing_hash=original.listing_hash,
            previous_receipt_hash=compute_receipt_hash(original),
            receipt_id=receipt_id,
            created_at=created_at,
            actor='human',
            operator_id=operator_id,
            original_receipt_id=original.receipt_id,
        )

    def record_signoff(
        self,
        original_receipt: AuditReceipt | UUID | str,
        operator_id: str,
        *,
        policy_version: str | None = None,
        receipt_id: UUID | str | None = None,
        created_at: datetime | None = None,
    ) -> AuditReceipt:
        '''Create and persist a signed human acceptance receipt.'''
        receipt = self.create_signoff(
            original_receipt,
            operator_id,
            policy_version=policy_version,
            receipt_id=receipt_id,
            created_at=created_at,
        )
        self.append_receipt(receipt)
        return receipt

    def get_override(
        self,
        original_receipt_id: UUID | str,
    ) -> HumanOverride | None:
        '''Return the latest human override for an original receipt.'''
        normalized_id = _coerce_uuid(
            original_receipt_id,
            'original_receipt_id',
        )
        with self._lock:
            connection = self._require_connection()
            row = connection.execute(
                '''
                SELECT payload_json
                FROM human_overrides
                WHERE original_receipt_id = ?
                   OR override_receipt_id = ?
                ORDER BY overridden_at DESC, override_receipt_id DESC
                LIMIT 1
                ''',
                (normalized_id, normalized_id),
            ).fetchone()

        if row is None:
            return None
        return _parse_human_override(str(row['payload_json']))

    get_human_override = get_override

    def require_override(
        self,
        original_receipt_id: UUID | str,
    ) -> HumanOverride:
        '''Return a human override or raise :class:`ReceiptNotFoundError`.'''
        override = self.get_override(original_receipt_id)
        if override is None:
            raise ReceiptNotFoundError(
                f'Human override for receipt {original_receipt_id!s} '
                'does not exist'
            )
        return override

    def get_override_receipt(
        self,
        original_receipt_id: UUID | str,
    ) -> AuditReceipt | None:
        '''Return the latest signed receipt implementing a human override.'''
        normalized_id = _coerce_uuid(
            original_receipt_id,
            'original_receipt_id',
        )
        with self._lock:
            connection = self._require_connection()
            row = connection.execute(
                '''
                SELECT payload_json
                FROM receipts
                WHERE original_receipt_id = ?
                  AND actor = 'human'
                  AND override_action IS NOT NULL
                ORDER BY created_at DESC, receipt_id DESC
                LIMIT 1
                ''',
                (normalized_id,),
            ).fetchone()

        if row is None:
            return None
        return _parse_receipt(str(row['payload_json']))

    def list_overrides(
        self,
        original_receipt_id: UUID | str | None = None,
    ) -> list[HumanOverride]:
        '''Return human overrides in chronological audit order.'''
        normalized_id = (
            _coerce_uuid(original_receipt_id, 'original_receipt_id')
            if original_receipt_id is not None
            else None
        )
        with self._lock:
            connection = self._require_connection()
            if normalized_id is None:
                rows = connection.execute(
                    '''
                    SELECT payload_json
                    FROM human_overrides
                    ORDER BY overridden_at, override_receipt_id
                    '''
                ).fetchall()
            else:
                rows = connection.execute(
                    '''
                    SELECT payload_json
                    FROM human_overrides
                    WHERE original_receipt_id = ?
                    ORDER BY overridden_at, override_receipt_id
                    ''',
                    (normalized_id,),
                ).fetchall()

        return [
            _parse_human_override(str(row['payload_json']))
            for row in rows
        ]


SQLiteReceiptStore = ReceiptStore


__all__ = [
    'DEFAULT_DATABASE_PATH',
    'ReceiptConflictError',
    'ReceiptNotFoundError',
    'ReceiptSignatureError',
    'ReceiptStore',
    'ReceiptStoreError',
    'SQLiteReceiptStore',
    'SigningKeyConflictError',
    'VerificationMode',
    'compute_listing_hash',
    'compute_receipt_hash',
    'hash_listing',
    'hash_receipt',
]