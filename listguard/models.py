from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from typing import Annotated, Literal
from uuid import UUID, uuid4

from pydantic import (
    AliasChoices,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    StringConstraints,
    field_validator,
    model_validator,
)


class Action(str, Enum):
    '''The only permitted moderation actions for listing content.'''

    ALLOW = 'allow'
    QUEUE = 'queue'
    BLOCK = 'block'


class PolicyBucket(str, Enum):
    '''Closed set of policy categories permitted by policy/buckets.json.'''

    OK = 'ok'
    WEAPON = 'weapon'
    ANIMAL = 'animal'
    COUNTERFEIT = 'counterfeit'
    PII = 'pii'
    OTHER_ILLEGAL = 'other_illegal'
    UNKNOWN = 'unknown'


ListingId = Annotated[
    str,
    StringConstraints(min_length=1, max_length=128),
]
Title = Annotated[
    str,
    StringConstraints(min_length=1, max_length=500),
]
Description = Annotated[
    str,
    StringConstraints(max_length=100_000),
]
CurrencyCode = Annotated[
    str,
    StringConstraints(min_length=3, max_length=3, pattern=r'^[A-Z]{3}$'),
]
ReasonCode = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=64,
        pattern=r'^[a-z][a-z0-9_]*$',
    ),
]
Sha256Hex = Annotated[
    str,
    StringConstraints(pattern=r'^[0-9a-f]{64}$'),
]
PolicyVersion = Annotated[
    str,
    StringConstraints(min_length=1, max_length=64),
]
Signature = Annotated[
    str,
    StringConstraints(min_length=1, max_length=4096),
]
OperatorId = Annotated[
    str,
    StringConstraints(min_length=1, max_length=128),
]
OverrideReason = Annotated[
    str,
    StringConstraints(min_length=1, max_length=2000),
]
ImageMetadata = dict[str, JsonValue]


class ListingInput(BaseModel):
    '''Untrusted marketplace content submitted for moderation.'''

    model_config = ConfigDict(
        extra='forbid',
        frozen=True,
        populate_by_name=True,
        str_strip_whitespace=True,
        validate_assignment=True,
        validate_default=True,
    )

    listing_id: ListingId = Field(
        validation_alias=AliasChoices('listing_id', 'id'),
    )
    title: Title
    description: Description = Field(
        default='',
        validation_alias=AliasChoices('description', 'text'),
    )
    image_metadata: list[ImageMetadata] = Field(
        default_factory=list,
        max_length=50,
    )
    price: Decimal | None = Field(
        default=None,
        ge=0,
        max_digits=20,
        decimal_places=6,
    )
    currency: CurrencyCode | None = None
    metadata: dict[str, JsonValue] = Field(
        default_factory=dict,
        max_length=100,
    )


class PolicyResult(BaseModel):
    '''Validated output of classification and deterministic policy routing.'''

    model_config = ConfigDict(
        extra='forbid',
        frozen=True,
        str_strip_whitespace=True,
        validate_assignment=True,
        validate_default=True,
    )

    bucket: PolicyBucket
    action: Action
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        allow_inf_nan=False,
        strict=True,
    )
    reason_codes: tuple[ReasonCode, ...] = Field(
        default_factory=tuple,
        max_length=32,
        validation_alias=AliasChoices('reason_codes', 'reasons'),
    )
    rationale: str = Field(default='', max_length=4000)

    @field_validator('reason_codes')
    @classmethod
    def reject_duplicate_reason_codes(
        cls,
        value: tuple[ReasonCode, ...],
    ) -> tuple[ReasonCode, ...]:
        if len(value) != len(set(value)):
            raise ValueError('reason_codes must not contain duplicates')
        return value

    @model_validator(mode='after')
    def enforce_non_bypassable_routing(self) -> PolicyResult:
        if self.bucket == PolicyBucket.WEAPON and self.action != Action.BLOCK:
            raise ValueError('weapon listings must use the block action')
        if (
            self.bucket == PolicyBucket.COUNTERFEIT
            and self.action != Action.QUEUE
        ):
            raise ValueError('counterfeit listings must use the queue action')
        if (
            'injection_or_jailbreak' in self.reason_codes
            and self.action == Action.ALLOW
        ):
            raise ValueError('prompt injection detections cannot be allowed')
        return self


class AuditReceipt(BaseModel):
    '''Immutable signed receipt for a listing decision or human override.'''

    model_config = ConfigDict(
        extra='forbid',
        frozen=True,
        populate_by_name=True,
        str_strip_whitespace=True,
        validate_assignment=True,
        validate_default=True,
    )

    listing_id: ListingId
    listing_hash: Sha256Hex
    result: PolicyResult = Field(
        validation_alias=AliasChoices('result', 'policy_result', 'decision'),
    )
    policy_version: PolicyVersion
    signature: Signature
    receipt_id: UUID = Field(default_factory=uuid4)
    receipt_version: Literal['1.0'] = '1.0'
    created_at: AwareDatetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        validation_alias=AliasChoices('created_at', 'timestamp'),
    )
    previous_receipt_hash: Sha256Hex | None = None
    actor: Literal['system', 'human'] = 'system'
    operator_id: OperatorId | None = None
    override_action: Action | None = None
    override_reason: OverrideReason | None = None
    overridden_at: AwareDatetime | None = None

    @model_validator(mode='after')
    def enforce_human_override_attribution(self) -> AuditReceipt:
        override_fields = (
            'operator_id',
            'override_action',
            'override_reason',
            'overridden_at',
        )
        override_values = (
            self.operator_id,
            self.override_action,
            self.override_reason,
            self.overridden_at,
        )

        if self.actor == 'human':
            if self.operator_id is None:
                raise ValueError('human sign-off requires operator_id')
            if self.override_action is not None or self.override_reason is not None:
                missing = [
                    name
                    for name, value in zip(override_fields, override_values)
                    if value is None
                ]
                if missing:
                    raise ValueError(
                        'human override requires operator_id, override_action, '
                        'override_reason, and overridden_at'
                    )
        elif any(value is not None for value in override_values):
            raise ValueError(
                'override fields require actor=human'
            )

        return self
