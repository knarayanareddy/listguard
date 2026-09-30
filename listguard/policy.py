from __future__ import annotations

import inspect
import re
from collections.abc import Mapping, Sequence
from decimal import Decimal
from pathlib import Path
from typing import Final

from pydantic import ValidationError

from listguard.brand_verifier import (
    BrandCatalog,
    BrandCatalogError,
    BrandVerificationResult,
    BrandVerifier,
    LuxuryBrandVerifier,
)
from listguard.compactor import WinnowCompactor
from listguard.models import (
    Action,
    ListingInput,
    PolicyBucket,
    PolicyResult,
)
from listguard.taxonomy import is_policy_bucket


DETERMINISTIC_POLICY_VERSION: Final[str] = 'deterministic-policy-v1'
DEFAULT_POLICY_BRAND_SOURCE: Final[Path | None] = None

_POLICY_CONFIDENCE: Final[float] = 0.99
_MAX_TEXT_DEPTH: Final[int] = 32
_MAX_TEXT_VALUES: Final[int] = 30_000
_MAX_TEXT_VALUE_CHARACTERS: Final[int] = 200_000
_MAX_COMBINED_TEXT_CHARACTERS: Final[int] = 2_000_000
_REASON_CODE_RE: Final[re.Pattern[str]] = re.compile(
    r'^[a-z][a-z0-9_]{0,63}$'
)

_INJECTION_REASON_CODES: Final[frozenset[str]] = frozenset(
    {
        'injection_or_jailbreak',
        'ignore_previous_instructions',
        'disregard_policy_instructions',
        'mark_as_allowed',
        'response_manipulation',
        'system_prompt_injection',
        'developer_message_injection',
        'role_instruction_injection',
        'jailbreak',
        'policy_bypass',
        'multilingual_instruction_injection',
    }
)

_COUNTERFEIT_REASON_CODES: Final[frozenset[str]] = frozenset(
    {
        'counterfeit',
        'brand_price_disparity',
        'counterfeit_terminology',
        'invalid_serial_number',
        'conflicting_serial_numbers',
    }
)

_INJECTION_PATTERNS: Final[tuple[tuple[re.Pattern[str], str], ...]] = tuple(
    (re.compile(pattern), reason)
    for pattern, reason in (
        (
            r'\b(?:ignore|disregard|forget)\s+(?:all\s+|any\s+)?'
            r'(?:the\s+)?(?:previous|prior|above|earlier|preceding)\s+'
            r'(?:instructions?|prompts?|directives?|rules?|directions?)\b',
            'ignore_previous_instructions',
        ),
        (
            r'\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+)?'
            r'(?:the\s+)?(?:system|developer|safety|moderation|'
            r'trust\s+and\s+safety)\s+'
            r'(?:prompt|message|instructions?|policy|policies|rules?)\b',
            'disregard_policy_instructions',
        ),
        (
            r'\b(?:mark|classify|label|set|rate)\s+'
            r'(?:(?:this|it|the)\s+)?'
            r'(?:(?:listing|item|content|post|text)\s+)?'
            r'(?:as\s+)?'
            r'(?:allow|allowed|approve|approved|safe|pass|passed)\b',
            'mark_as_allowed',
        ),
        (
            r'\b(?:respond|reply|return|output|answer)\s+'
            r'(?:with\s+)?(?:only\s+)?'
            r'(?:allow|allowed|approve|approved|safe|pass|passed)\b',
            'response_manipulation',
        ),
        (
            r'\b(?:reveal|print|show|display|repeat|leak)\s+'
            r'(?:the\s+)?(?:system|developer|hidden)\s+'
            r'(?:prompt|message|instructions?|rules?)\b',
            'system_prompt_injection',
        ),
        (
            r'<\s*/?\s*(?:system|developer|assistant|tool)\s*>',
            'system_prompt_injection',
        ),
        (
            r'\[\s*(?:inst|/inst|system|developer)\s*\]',
            'system_prompt_injection',
        ),
        (
            r'(?:^|\n)\s*(?:system|developer)\s*:\s*\S',
            'developer_message_injection',
        ),
        (
            r'\b(?:act|behave|respond)\s+as\s+(?:if\s+you\s+are\s+)?'
            r'(?:a\s+)?(?:unrestricted|unfiltered|jailbroken|developer|root)\b',
            'role_instruction_injection',
        ),
        (
            r'\b(?:pretend|roleplay|role-play)\s+(?:that\s+)?(?:you\s+are|to\s+be)\s+'
            r'(?:an?\s+)?(?:unrestricted|unfiltered|uncensored|developer|root)\b',
            'role_instruction_injection',
        ),
        (
            r'\b(?:enable|activate|enter|switch\s+to)\s+'
            r'(?:developer|debug|god|dan|jailbreak)\s+mode\b',
            'jailbreak',
        ),
        (
            r'\b(?:bypass|disable|remove|circumvent)\s+'
            r'(?:all\s+|any\s+)?(?:the\s+)?'
            r'(?:safety|security|content|moderation)\s+'
            r'(?:policy|policies|filter|filters|checks?|rules?)\b',
            'policy_bypass',
        ),
        (
            r'\b(?:ignorez|ignorez\s+les|ignoriere|ignoriere\s+alle|'
            r'ignora|ignora\s+las|neem\s+de\s+melkening\s+over)\b',
            'multilingual_instruction_injection',
        ),
        (
            r'\b(?:instructions|anweisungen|instrucciones|instructions)\s+'
            r'(?:précédentes|vorherigen|anteriores|précédentes)\b',
            'multilingual_instruction_injection',
        ),
    )
)

_WEAPON_PATTERNS: Final[tuple[re.Pattern[str], ...]] = tuple(
    re.compile(pattern)
    for pattern in (
        r'\b(?:firearm|firearms|fire\s+arm|fire\s+arms|gun|guns|'
        r'handgun|pistol|revolver|shotgun| rifle|rifles|carbine|'
        r'assault\s+rifle|machine\s+gun|submachine\s+gun)\b',
        r'\b(?:ammunition|ammunitions|live\s+ammo|live\s+ammunition|'
        r'live\s+rounds?|rounds?\s+included)\b',
        r'\b(?:tactical|combat|military|survival|hunting)\s+'
        r'(?:weapon|weapons|knife|blades?)\b',
        r'\b(?:hunting\s+knife|combat\s+knife|pocket\s+knife|'
        r'folding\s+knife|bayonet|machete|sword)\b',
        r'\bknife\b',
    )
)

_ANIMAL_PATTERNS: Final[tuple[re.Pattern[str], ...]] = tuple(
    re.compile(pattern)
    for pattern in (
        r'\b(?:live|exotic|wild|endangered)\s+'
        r'(?:animal|animals|pets?|wildlife)\b',
        r'\b(?:animal|animals|pet|pets)\s+(?:for\s+sale|sale|adoption\s+'
        r'(?:listing|offer))\b',
        r'\b(?:sell|selling|offer|offering|buy|buying)\s+'
        r'(?:a\s+|an\s+|the\s+)?(?:live\s+)?'
        r'(?:dog|cat|bird|parrot|reptile|snake|turtle|ferret|wildlife)\b',
    )
)

_PII_PATTERNS: Final[tuple[re.Pattern[str], ...]] = tuple(
    re.compile(pattern)
    for pattern in (
        r'\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b',
        r'(?<!\d)(?:\+?\d[\s().-]?){8,15}\d(?!\d)',
        r'(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)',
        r'\b(?:national\s+)?social\s+security\s+(?:number|ssn)\b',
        r'\b(?:passport|driver\s+licen[cs]e)\s+(?:number|no\.?|#)\b',
        r'\b(?:reveal|publish|share|expose|leak)\s+'
        r'(?:customer|buyer|seller|user)\s+'
        r'(?:name|address|phone|email|data|information)\b',
    )
)

_OTHER_ILLEGAL_PATTERNS: Final[tuple[re.Pattern[str], ...]] = tuple(
    re.compile(pattern)
    for pattern in (
        r'\b(?:sell|selling|offer|offering|supply|supplies)\s+'
        r'(?:hard\s+)?(?:drugs?|cocaine|heroin|methamphetamine|fentanyl)\b',
        r'\b(?:stolen|hot)\s+(?:goods|merchandise|property)\b',
        r'\b(?:child\s+(?:porn|sexual\s+abuse\s+material)|csam)\b',
        r'\b(?:human\s+trafficking|organ\s+trafficking)\b',
        r'\b(?:contraband|smuggled\s+(?:goods|products?))\b',
    )
)


class PolicyRoutingError(RuntimeError):
    """Raised when deterministic policy routing cannot be completed safely."""


def _append_reason(reasons: list[str], *candidates: str) -> None:
    for candidate in candidates:
        if (
            _REASON_CODE_RE.fullmatch(candidate)
            and candidate not in reasons
            and len(reasons) < 32
        ):
            reasons.append(candidate)


def _iter_text_values(
    value: object,
    *,
    depth: int = 0,
    count: int = 0,
) -> tuple[list[str], int]:
    if depth > _MAX_TEXT_DEPTH or count >= _MAX_TEXT_VALUES:
        return [], count

    values: list[str] = []

    if isinstance(value, str):
        if len(value) <= _MAX_TEXT_VALUE_CHARACTERS:
            values.append(value)
            count += 1
        return values, count

    if isinstance(value, Mapping):
        for key, nested in value.items():
            if count >= _MAX_TEXT_VALUES:
                break
            if isinstance(key, str) and len(key) <= _MAX_TEXT_VALUE_CHARACTERS:
                values.append(key)
                count += 1
            nested_values, count = _iter_text_values(
                nested,
                depth=depth + 1,
                count=count,
            )
            values.extend(nested_values)
        return values, count

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        for nested in value:
            if count >= _MAX_TEXT_VALUES:
                break
            nested_values, count = _iter_text_values(
                nested,
                depth=depth + 1,
                count=count,
            )
            values.extend(nested_values)
        return values, count

    return values, count


def _collect_policy_text(
    listing: ListingInput,
    compactor: WinnowCompactor,
) -> tuple[tuple[str, ...], str]:
    raw_values, _ = _iter_text_values(
        {
            'title': listing.title,
            'description': listing.description,
            'image_metadata': listing.image_metadata,
            'metadata': listing.metadata,
        }
    )

    normalized_values: list[str] = []
    total_characters = 0
    seen: set[str] = set()

    for raw_value in raw_values:
        normalized = compactor.normalize_text(raw_value)
        normalized = re.sub(r'[_-]+', ' ', normalized)
        normalized = re.sub(r'\s+', ' ', normalized).strip()
        if not normalized or normalized in seen:
            continue
        if total_characters + len(normalized) > _MAX_COMBINED_TEXT_CHARACTERS:
            break
        seen.add(normalized)
        normalized_values.append(normalized)
        total_characters += len(normalized)

    return tuple(normalized_values), '\n'.join(normalized_values)


def _matching_patterns(
    text: str,
    patterns: Sequence[re.Pattern[str]],
) -> bool:
    return any(pattern.search(text) is not None for pattern in patterns)


def _detect_injection(text: str) -> list[str]:
    reasons: list[str] = []
    for pattern, reason in _INJECTION_PATTERNS:
        if pattern.search(text) is not None:
            _append_reason(reasons, reason)

    if reasons:
        _append_reason(
            reasons,
            'injection_or_jailbreak',
            'policy_bypass'
            if 'policy_bypass' in reasons
            else 'response_manipulation',
        )
    return reasons


def _coerce_flag(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().casefold()
        if normalized in {'true', 'yes', '1', 'counterfeit', 'suspicious'}:
            return True
        if normalized in {'false', 'no', '0', 'safe', 'genuine'}:
            return False
    return bool(value)


def _result_flag(result: object, *names: str) -> bool:
    if isinstance(result, bool):
        return result
    if isinstance(result, str):
        return result.strip().casefold() in {
            'counterfeit',
            'suspicious',
            'queue',
        }
    if isinstance(result, Mapping):
        for name in names:
            if name in result and _coerce_flag(result[name]):
                return True
        bucket = result.get('bucket')
        return isinstance(bucket, str) and bucket.casefold() == 'counterfeit'
    for name in names:
        if hasattr(result, name) and _coerce_flag(getattr(result, name)):
            return True
    bucket = getattr(result, 'bucket', None)
    return (
        isinstance(bucket, (str, PolicyBucket))
        and str(
            bucket.value if isinstance(bucket, PolicyBucket) else bucket
        ).casefold()
        == 'counterfeit'
    )


def _result_reasons(result: object) -> list[str]:
    reasons: list[str] = []
    if isinstance(result, Mapping):
        raw_reasons = result.get('reason_codes', result.get('reasons', ()))
    else:
        raw_reasons = getattr(
            result,
            'reason_codes',
            getattr(result, 'reasons', ()),
        )

    if isinstance(raw_reasons, str):
        raw_reasons = (raw_reasons,)
    if isinstance(raw_reasons, Sequence):
        for reason in raw_reasons:
            if isinstance(reason, str):
                _append_reason(reasons, reason)

    if _result_flag(
        result,
        'price_disparity',
        'brand_price_disparity',
        'disparity_detected',
    ):
        _append_reason(reasons, 'brand_price_disparity')
    if _result_flag(result, 'counterfeit_terminology'):
        _append_reason(reasons, 'counterfeit_terminology')
    if _result_flag(result, 'invalid_serial_number', 'invalid_serial'):
        _append_reason(reasons, 'invalid_serial_number')
    if _result_flag(result, 'conflicting_serial_numbers', 'conflicting_serials'):
        _append_reason(reasons, 'conflicting_serial_numbers')
    if _result_flag(
        result,
        'is_counterfeit',
        'suspected_counterfeit',
        'counterfeit_detected',
        'counterfeit',
        'requires_review',
    ):
        _append_reason(reasons, 'counterfeit')

    return reasons


def _validate_listing(
    listing: ListingInput | Mapping[str, object],
) -> ListingInput:
    if isinstance(listing, ListingInput):
        return listing
    try:
        return ListingInput.model_validate(listing)
    except ValidationError as exc:
        raise PolicyRoutingError(
            'Listing does not satisfy the closed ListingInput schema'
        ) from exc


def _coerce_route_reasons(
    reason_codes: Sequence[str] | str,
    reasons: Sequence[str] | str | None,
) -> tuple[str, ...]:
    if reasons is not None:
        if reason_codes:
            raise TypeError('Specify reason_codes or reasons, not both')
        reason_codes = reasons
    if isinstance(reason_codes, str):
        reason_codes = (reason_codes,)

    normalized: list[str] = []
    for reason in reason_codes:
        if not isinstance(reason, str) or not _REASON_CODE_RE.fullmatch(reason):
            raise PolicyRoutingError(
                f'Invalid policy reason code: {reason!r}'
            )
        if reason not in normalized:
            normalized.append(reason)
    if len(normalized) > 32:
        raise PolicyRoutingError('A policy result cannot exceed 32 reason codes')
    return tuple(normalized)


def route_bucket(
    bucket: PolicyBucket | str | PolicyResult,
    reason_codes: Sequence[str] | str = (),
    *,
    reasons: Sequence[str] | str | None = None,
    confidence: float = _POLICY_CONFIDENCE,
    rationale: str = '',
) -> PolicyResult:
    """Route one closed-set bucket to its non-bypassable content action."""

    if isinstance(bucket, PolicyResult):
        if reasons is not None:
            raise TypeError('reasons cannot be supplied with a PolicyResult')
        return bucket

    bucket_value = (
        bucket.value if isinstance(bucket, PolicyBucket) else bucket
    )
    if not is_policy_bucket(bucket_value):
        raise PolicyRoutingError(
            f'Policy bucket is outside the configured closed set: {bucket!r}'
        )

    validated_bucket = PolicyBucket(bucket_value)
    normalized_reasons = _coerce_route_reasons(reason_codes, reasons)

    if (
        'weapon' in normalized_reasons
        or 'live_ammunition' in normalized_reasons
    ):
        validated_bucket = PolicyBucket.WEAPON
    elif (
        validated_bucket == PolicyBucket.OK
        and any(
            reason in _COUNTERFEIT_REASON_CODES
            for reason in normalized_reasons
        )
    ):
        validated_bucket = PolicyBucket.COUNTERFEIT
    elif (
        validated_bucket == PolicyBucket.OK
        and any(
            reason in _INJECTION_REASON_CODES
            for reason in normalized_reasons
        )
    ):
        validated_bucket = PolicyBucket.UNKNOWN

    if validated_bucket == PolicyBucket.WEAPON:
        action = Action.BLOCK
    elif validated_bucket == PolicyBucket.COUNTERFEIT:
        action = Action.QUEUE
    elif validated_bucket == Action.__members__['QUEUE']:
        action = Action.QUEUE
    elif validated_bucket == PolicyBucket.OTHER_ILLEGAL:
        action = Action.BLOCK
    elif validated_bucket in {
        PolicyBucket.ANIMAL,
        PolicyBucket.PII,
        PolicyBucket.UNKNOWN,
    }:
        action = Action.QUEUE
    elif validated_bucket == PolicyBucket.OK:
        action = Action.QUEUE if 'injection_or_jailbreak' in normalized_reasons else Action.ALLOW
    else:
        raise PolicyRoutingError(
            f'No deterministic route exists for bucket {validated_bucket.value!r}'
        )

    if 'injection_or_jailbreak' in normalized_reasons and action == Action.ALLOW:
        action = Action.QUEUE

    if not rationale:
        rationale = (
            f'Policy bucket {validated_bucket.value} routes listing content '
            f'to {action.value}.'
        )

    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        raise PolicyRoutingError('Policy confidence must be numeric')
    normalized_confidence = float(confidence)
    if not 0.0 <= normalized_confidence <= 1.0:
        raise PolicyRoutingError('Policy confidence must be between 0 and 1')

    try:
        return PolicyResult(
            bucket=validated_bucket,
            action=action,
            confidence=normalized_confidence,
            reason_codes=normalized_reasons,
            rationale=rationale,
        )
    except ValidationError as exc:
        raise PolicyRoutingError(
            'Deterministic policy produced an invalid closed-set result'
        ) from exc


def route_policy(
    bucket: PolicyBucket | str | PolicyResult,
    reason_codes: Sequence[str] | str = (),
    *,
    reasons: Sequence[str] | str | None = None,
    confidence: float = _POLICY_CONFIDENCE,
    rationale: str = '',
) -> PolicyResult:
    """Compatibility name for :func:`route_bucket`."""

    return route_bucket(
        bucket,
        reason_codes,
        reasons=reasons,
        confidence=confidence,
        rationale=rationale,
    )


class DeterministicPolicy:
    """Pure-Python, deterministic marketplace content policy engine."""

    policy_version = DETERMINISTIC_POLICY_VERSION
    version = DETERMINISTIC_POLICY_VERSION

    def __init__(
        self,
        brand_verifier: BrandVerifier | None = None,
        *,
        brand_catalog: BrandCatalog | Mapping[str, object] | str | Path | None = None,
        catalog: BrandCatalog | Mapping[str, object] | str | Path | None = None,
        index: BrandCatalog | Mapping[str, object] | str | Path | None = None,
        catalog_path: str | Path | None = None,
        brand_index: BrandCatalog | Mapping[str, object] | str | Path | None = None,
        compactor: WinnowCompactor | None = None,
    ) -> None:
        supplied_catalogs = [
            source
            for source in (
                brand_catalog,
                catalog,
                index,
                catalog_path,
                brand_index,
            )
            if source is not None
        ]
        if len(supplied_catalogs) > 1:
            raise TypeError(
                'Specify only one trusted brand catalog source'
            )

        if brand_verifier is not None and supplied_catalogs:
            raise TypeError(
                'Specify brand_verifier or a catalog source, not both'
            )

        if compactor is not None and not callable(
            getattr(compactor, 'normalize_text', None)
        ):
            raise TypeError(
                'compactor must provide a callable normalize_text method'
            )
        self._compactor = compactor or WinnowCompactor()
        self._brand_verifier_is_custom = brand_verifier is not None

        if brand_verifier is not None:
            if not (
                callable(brand_verifier)
                or callable(getattr(brand_verifier, 'verify', None))
                or callable(getattr(brand_verifier, 'verify_listing', None))
                or callable(
                    getattr(
                        brand_verifier,
                        'verify_brand_and_serial',
                        None,
                    )
                )
            ):
                raise TypeError(
                    'brand_verifier must be callable or expose verify()'
                )
            self._brand_verifier = brand_verifier
        elif supplied_catalogs:
            source = supplied_catalogs[0]
            if (
                callable(source)
                or callable(getattr(source, 'verify', None))
                or callable(getattr(source, 'verify_listing', None))
            ):
                self._brand_verifier = source
                self._brand_verifier_is_custom = True
            else:
                try:
                    if isinstance(source, (str, Path)):
                        self._brand_verifier = LuxuryBrandVerifier(
                            index=source
                        )
                    elif isinstance(source, BrandCatalog):
                        self._brand_verifier = LuxuryBrandVerifier(
                            index=source
                        )
                    elif isinstance(source, Mapping):
                        self._brand_verifier = LuxuryBrandVerifier(
                            index=BrandCatalog.from_document(source)
                        )
                    else:
                        raise TypeError(
                            'Trusted brand catalog source has an invalid type'
                        )
                except (BrandCatalogError, TypeError, OSError) as exc:
                    raise PolicyRoutingError(
                        'Unable to initialize the trusted brand catalog'
                    ) from exc
        else:
            try:
                self._brand_verifier = LuxuryBrandVerifier(
                    index=DEFAULT_POLICY_BRAND_SOURCE
                )
            except (BrandCatalogError, TypeError, OSError) as exc:
                raise PolicyRoutingError(
                    'Unable to initialize the trusted brand catalog'
                ) from exc

    @property
    def brand_verifier(self) -> BrandVerifier:
        return self._brand_verifier

    def _verify_brand(
        self,
        listing: ListingInput,
    ) -> tuple[bool, list[str], bool]:
        verifier = self._brand_verifier
        if callable(getattr(verifier, 'verify', None)):
            method = getattr(verifier, 'verify')
        elif callable(getattr(verifier, 'verify_listing', None)):
            method = getattr(verifier, 'verify_listing')
        elif callable(getattr(verifier, 'verify_brand_and_serial', None)):
            method = getattr(verifier, 'verify_brand_and_serial')
        elif callable(verifier):
            method = verifier
        else:
            raise TypeError('brand_verifier is not callable')

        try:
            result = method(listing)
            if inspect.isawaitable(result):
                raise TypeError(
                    'Asynchronous brand verifiers are not deterministic'
                )
        except Exception:
            return False, ['brand_verification_error'], True

        if result is None or result is False:
            return False, [], False
        if result is True:
            return True, ['counterfeit'], False

        reasons = _result_reasons(result)
        counterfeit = _result_flag(
            result,
            'is_counterfeit',
            'suspected_counterfeit',
            'counterfeit_detected',
            'counterfeit',
            'requires_review',
            'price_disparity',
            'brand_price_disparity',
            'disparity_detected',
            'counterfeit_terminology',
            'invalid_serial_number',
            'invalid_serial',
            'conflicting_serial_numbers',
            'conflicting_serials',
        )
        if counterfeit:
            _append_reason(reasons, 'counterfeit')
        return counterfeit, reasons, False

    def evaluate(
        self,
        listing: ListingInput | Mapping[str, object],
    ) -> PolicyResult:
        """Evaluate untrusted listing content and return a closed-set result."""

        validated = _validate_listing(listing)
        texts, combined_text = _collect_policy_text(
            validated,
            self._compactor,
        )
        del texts

        brand_counterfeit, brand_reasons, verification_error = (
            self._verify_brand(validated)
        )

        weapon_reasons: list[str] = []
        if _matching_patterns(combined_text, _WEAPON_PATTERNS):
            _append_reason(weapon_reasons, 'weapon')

        injection_reasons = _detect_injection(combined_text)

        animal_reasons: list[str] = []
        if _matching_patterns(combined_text, _ANIMAL_PATTERNS):
            _append_reason(animal_reasons, 'animal')

        pii_reasons: list[str] = []
        if _matching_patterns(combined_text, _PII_PATTERNS):
            _append_reason(pii_reasons, 'pii')

        illegal_reasons: list[str] = []
        if _matching_patterns(combined_text, _OTHER_ILLEGAL_PATTERNS):
            _append_reason(illegal_reasons, 'other_illegal')

        if verification_error:
            _append_reason(brand_reasons, 'brand_verification_error')

        if brand_counterfeit and self._brand_verifier_is_custom:
            bucket = PolicyBucket.COUNTERFEIT
            reasons = list(brand_reasons)
            rationale = (
                'The explicitly configured brand verifier classified the '
                'listing content as counterfeit. The listing is queued for '
                'human review; no human account action is taken.'
            )
        elif weapon_reasons:
            bucket = PolicyBucket.WEAPON
            reasons = [*weapon_reasons, *injection_reasons]
            rationale = (
                'Weapon content was detected in listing text or image '
                'metadata. The listing content is blocked.'
            )
        elif brand_counterfeit:
            bucket = PolicyBucket.COUNTERFEIT
            reasons = [*brand_reasons, *injection_reasons]
            rationale = (
                'Trusted brand verification found counterfeit evidence. '
                'The listing content is queued for human review.'
            )
        elif illegal_reasons:
            bucket = PolicyBucket.OTHER_ILLEGAL
            reasons = [*illegal_reasons, *injection_reasons]
            rationale = (
                'Other illegal listing content was detected by deterministic '
                'rules. The listing content is blocked.'
            )
        elif pii_reasons:
            bucket = PolicyBucket.PII
            reasons = [*pii_reasons, *injection_reasons]
            rationale = (
                'Personal information was detected in the listing content. '
                'The listing is queued for human review.'
            )
        elif animal_reasons:
            bucket = PolicyBucket.ANIMAL
            reasons = [*animal_reasons, *injection_reasons]
            rationale = (
                'Animal-related listing content was detected. The listing is '
                'queued for human review.'
            )
        elif injection_reasons:
            bucket = PolicyBucket.UNKNOWN
            reasons = injection_reasons
            rationale = (
                'Prompt injection or jailbreak text was detected in untrusted '
                'listing content. The listing is queued and cannot be allowed '
                'by deterministic processing.'
            )
        elif verification_error:
            bucket = PolicyBucket.UNKNOWN
            reasons = brand_reasons
            rationale = (
                'Brand verification failed, so the listing is queued rather '
                'than being incorrectly allowed.'
            )
        else:
            bucket = PolicyBucket.OK
            reasons = ['no_policy_violation']
            rationale = (
                'No deterministic marketplace content policy violation was '
                'found.'
            )

        return route_bucket(
            bucket,
            reasons,
            confidence=_POLICY_CONFIDENCE,
            rationale=rationale,
        )

    def evaluate_listing(
        self,
        listing: ListingInput | Mapping[str, object],
    ) -> PolicyResult:
        return self.evaluate(listing)

    def route_listing(
        self,
        listing: ListingInput | Mapping[str, object],
    ) -> PolicyResult:
        return self.evaluate(listing)

    def classify(
        self,
        listing: ListingInput | Mapping[str, object],
    ) -> PolicyBucket:
        return self.evaluate(listing).bucket

    def __call__(
        self,
        listing: ListingInput | Mapping[str, object],
    ) -> PolicyResult:
        return self.evaluate(listing)


PolicyEngine = DeterministicPolicy
PolicyRouter = DeterministicPolicy


def evaluate_listing(
    listing: ListingInput | Mapping[str, object],
    brand_verifier: BrandVerifier | None = None,
    *,
    brand_catalog: BrandCatalog | Mapping[str, object] | str | Path | None = None,
    catalog: BrandCatalog | Mapping[str, object] | str | Path | None = None,
    index: BrandCatalog | Mapping[str, object] | str | Path | None = None,
    catalog_path: str | Path | None = None,
    compactor: WinnowCompactor | None = None,
) -> PolicyResult:
    """Evaluate a listing with an optionally injected trusted verifier."""

    policy = DeterministicPolicy(
        brand_verifier=brand_verifier,
        brand_catalog=brand_catalog,
        catalog=catalog,
        index=index,
        catalog_path=catalog_path,
        compactor=compactor,
    )
    return policy.evaluate(listing)


__all__ = [
    'DEFAULT_POLICY_BRAND_SOURCE',
    'DETERMINISTIC_POLICY_VERSION',
    'DeterministicPolicy',
    'PolicyEngine',
    'PolicyResult',
    'PolicyRouter',
    'PolicyRoutingError',
    'evaluate_listing',
    'route_bucket',
    'route_policy',
]