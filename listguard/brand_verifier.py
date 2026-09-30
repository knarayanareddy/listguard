from __future__ import annotations

import json
import re
import threading
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType
from typing import Final, Protocol, runtime_checkable

from listguard.compactor import WinnowCompactor
from listguard.models import ListingInput


DEFAULT_LUXURY_INDEX_PATH: Final[Path] = (
    Path(__file__).resolve().parent.parent
    / 'fixtures'
    / 'brands'
    / 'luxury_index.json'
)
DEFAULT_BRAND_INDEX_PATH: Final[Path] = DEFAULT_LUXURY_INDEX_PATH

_MAX_CATALOG_BYTES: Final[int] = 2 * 1024 * 1024
_MAX_BRANDS: Final[int] = 1_000
_MAX_ALIASES_PER_BRAND: Final[int] = 100
_MAX_SERIAL_PATTERNS: Final[int] = 32
_MAX_SERIAL_PATTERN_LENGTH: Final[int] = 512
_MAX_SERIAL_LENGTH: Final[int] = 64
_MAX_TEXT_DEPTH: Final[int] = 32
_MAX_TEXT_VALUES: Final[int] = 20_000
_MAX_TEXT_VALUE_CHARACTERS: Final[int] = 200_000
_MAX_COLLECTED_TEXT_CHARACTERS: Final[int] = 2_000_000

_SERIAL_KEYS: Final[frozenset[str]] = frozenset(
    {
        'serial',
        'serialno',
        'serialnumber',
        'serialnumbers',
        'watchserial',
    }
)

_SERIAL_PLACEHOLDERS: Final[frozenset[str]] = frozenset(
    {
        'AVAILABLE',
        'N/A',
        'NA',
        'NONE',
        'NOTAVAILABLE',
        'NOTKNOWN',
        'ONREQUEST',
        'PENDING',
        'UNKNOWN',
    }
)

_SERIAL_CONTEXT_RE: Final[re.Pattern[str]] = re.compile(
    r'\b(?:serial(?:[\s_]*(?:number|no\.?|#))?|watch[\s_]+serial)'
    r'\s*(?:is|[:=#-])?\s*'
    r'([a-z0-9](?:[a-z0-9-]{2,62}[a-z0-9]))\b'
)

_COUNTERFEIT_PATTERNS: Final[tuple[re.Pattern[str], ...]] = tuple(
    re.compile(pattern)
    for pattern in (
        r'\b(?:replica|replicas|counterfeit|counterfeits|fake|knockoff|'
        r'bootleg|bootlegs|clone|cloned|dupe|imitation)\b',
        r'\baaa\s+(?:quality|replica|grade|reproduction)\b',
        r'\b(?:not|isn\s*t|non)\s+(?:genuine|authentic|real)\b',
        r'\b(?:authorized|authorised)\s+replica\b',
        r'\b(?:same|exact)\s+(?:copy|replica)\b',
    )
)

_NON_COUNTERFEIT_CONTEXT_RE: Final[tuple[re.Pattern[str], ...]] = tuple(
    re.compile(pattern)
    for pattern in (
        r'\banti[\s-]*counterfeit\b',
        r'\bnot\s+(?:a\s+|an\s+|any\s+)?'
        r'(?:replica|counterfeit|fake|knockoff|bootleg|clone|imitation)\b',
        r'\bno\s+(?:replica|counterfeit|fake|knockoff|bootleg|clone)\b',
        r'\bcounterfeit\s+(?:check|checking|report|verification|'
        r'authentication|warning|guide|education)\b',
        r'\b(?:check|checking|detect|detecting|verify|identifying)\s+'
        r'(?:for\s+)?counterfeits?\b',
        r'\bhow\s+to\s+(?:spot|identify|detect)\s+(?:a\s+)?'
        r'(?:fake|counterfeit|replica)\b',
    )
)


class BrandCatalogError(ValueError):
    """Raised when a trusted brand catalog is malformed or ambiguous."""


def _reject_json_constant(value: str) -> None:
    raise BrandCatalogError(
        f'Non-finite JSON number is not allowed in brand catalog: {value}'
    )


def _object_without_duplicate_keys(
    pairs: Sequence[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise BrandCatalogError(
                f'Duplicate JSON object key in brand catalog: {key!r}'
            )
        result[key] = value
    return result


def _read_catalog_document(path: Path) -> object:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise BrandCatalogError(
            f'Unable to access brand catalog at {path}'
        ) from exc

    if size > _MAX_CATALOG_BYTES:
        raise BrandCatalogError(
            f'Brand catalog exceeds {_MAX_CATALOG_BYTES} bytes'
        )

    try:
        raw = path.read_text(encoding='utf-8')
    except (OSError, UnicodeError) as exc:
        raise BrandCatalogError(
            f'Unable to read brand catalog at {path}'
        ) from exc

    try:
        return json.loads(
            raw,
            parse_constant=_reject_json_constant,
            object_pairs_hook=_object_without_duplicate_keys,
        )
    except BrandCatalogError:
        raise
    except json.JSONDecodeError as exc:
        raise BrandCatalogError(
            f'Brand catalog at {path} is not valid JSON'
        ) from exc


def _normalize_lookup_text(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError('brand lookup text must be a string')
    normalized = WinnowCompactor.normalize_text(value)
    if not normalized:
        raise BrandCatalogError(
            'Brand identifiers and aliases cannot normalize to empty text'
        )
    return normalized


def _normalize_serial(value: str) -> str:
    normalized = unicodedata.normalize('NFKC', value).upper()
    normalized = re.sub(r'\s+', '', normalized, flags=re.UNICODE)
    return normalized.strip('-_')


def _normalized_key(value: str) -> str:
    return ''.join(
        character
        for character in WinnowCompactor.normalize_text(value)
        if character.isascii() and character.isalnum()
    )


def _parse_positive_decimal(value: object, context: str) -> Decimal:
    if isinstance(value, bool) or not isinstance(
        value, (str, int, float, Decimal)
    ):
        raise BrandCatalogError(f'{context} must be a decimal number')

    try:
        parsed = (
            value
            if isinstance(value, Decimal)
            else Decimal(str(value).strip())
        )
    except (InvalidOperation, ValueError) as exc:
        raise BrandCatalogError(
            f'{context} must be a decimal number'
        ) from exc

    if not parsed.is_finite() or parsed <= 0:
        raise BrandCatalogError(f'{context} must be finite and greater than zero')

    exponent = parsed.as_tuple().exponent
    if not isinstance(exponent, int) or exponent < -12:
        raise BrandCatalogError(
            f'{context} cannot have more than 12 fractional digits'
        )
    if parsed.adjusted() > 12:
        raise BrandCatalogError(f'{context} is unreasonably large')

    return parsed


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

    if isinstance(value, Sequence):
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


def _collect_listing_text(listing: ListingInput) -> tuple[tuple[str, ...], str]:
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
        normalized = WinnowCompactor.normalize_text(raw_value)
        if not normalized or normalized in seen:
            continue
        if total_characters + len(normalized) > _MAX_COLLECTED_TEXT_CHARACTERS:
            break
        seen.add(normalized)
        normalized_values.append(normalized)
        total_characters += len(normalized)

    return tuple(normalized_values), '\n'.join(normalized_values)


def _extract_serial_scalars(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, bool):
        return []
    if isinstance(value, int):
        return [str(value)]
    return []


def _collect_serial_numbers(
    value: object,
    *,
    depth: int = 0,
) -> tuple[str, ...]:
    if depth > _MAX_TEXT_DEPTH:
        return ()

    candidates: list[str] = []

    if isinstance(value, Mapping):
        for raw_key, nested in value.items():
            if not isinstance(raw_key, str):
                continue
            key = _normalized_key(raw_key)
            if key in _SERIAL_KEYS:
                candidates.extend(_extract_serial_scalars(nested))
                if isinstance(nested, Mapping):
                    for serial_key in ('value', 'number', 'serial'):
                        if serial_key in nested:
                            candidates.extend(
                                _extract_serial_scalars(nested[serial_key])
                            )
            candidates.extend(
                _collect_serial_numbers(nested, depth=depth + 1)
            )
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        for nested in value:
            candidates.extend(
                _collect_serial_numbers(nested, depth=depth + 1)
            )

    normalized_candidates: list[str] = []
    for candidate in candidates:
        normalized = _normalize_serial(candidate)
        if (
            not normalized
            or len(normalized) > _MAX_SERIAL_LENGTH
            or normalized in _SERIAL_PLACEHOLDERS
        ):
            continue
        if normalized not in normalized_candidates:
            normalized_candidates.append(normalized)

    return tuple(normalized_candidates)


def _contains_counterfeit_terminology(texts: Sequence[str]) -> bool:
    for text in texts:
        for pattern in _COUNTERFEIT_PATTERNS:
            for match in pattern.finditer(text):
                start = max(0, match.start() - 80)
                end = min(len(text), match.end() + 80)
                context = text[start:end]
                if any(
                    exclusion.search(context)
                    for exclusion in _NON_COUNTERFEIT_CONTEXT_RE
                ):
                    continue
                return True
    return False


def _parse_symbol_price(text: str) -> tuple[Decimal, str] | None:
    patterns: tuple[tuple[re.Pattern[str], str], ...] = (
        (re.compile(r'€\s*(\d{1,12}(?:[.,]\d{1,6})?)'), 'EUR'),
        (re.compile(r'\$\s*(\d{1,12}(?:[.,]\d{1,6})?)'), 'USD'),
        (re.compile(r'£\s*(\d{1,12}(?:[.,]\d{1,6})?)'), 'GBP'),
    )

    for pattern, currency in patterns:
        match = pattern.search(text)
        if match is None:
            continue
        normalized_number = match.group(1).replace(',', '.')
        try:
            return Decimal(normalized_number), currency
        except InvalidOperation:
            continue
    return None


@dataclass(frozen=True, slots=True)
class BrandRule:
    """Immutable verification rules for one trusted brand."""

    identifier: str
    name: str
    aliases: tuple[str, ...]
    minimum_prices: Mapping[str, Decimal]
    serial_patterns: tuple[re.Pattern[str], ...]
    valid_serials: frozenset[str]
    serial_prefixes: tuple[str, ...]

    @property
    def search_terms(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys((self.identifier, self.name, *self.aliases)))

    @property
    def canonical_name(self) -> str:
        return self.name

    def minimum_price_for(self, currency: str) -> Decimal | None:
        return self.minimum_prices.get(currency.upper())

    def validate_serial(self, serial: str) -> bool | None:
        normalized = _normalize_serial(serial)
        if (
            not normalized
            or normalized in _SERIAL_PLACEHOLDERS
            or len(normalized) > _MAX_SERIAL_LENGTH
        ):
            return False

        if normalized in self.valid_serials:
            return True
        if any(
            normalized.startswith(prefix)
            for prefix in self.serial_prefixes
        ):
            return True
        if any(
            pattern.fullmatch(normalized) is not None
            for pattern in self.serial_patterns
        ):
            return True
        if not (
            self.serial_patterns
            or self.valid_serials
            or self.serial_prefixes
        ):
            return None
        return False


@dataclass(frozen=True, slots=True)
class BrandCatalog:
    """Validated, immutable collection of trusted brand rules."""

    schema_version: int
    default_currency: str
    rules: tuple[BrandRule, ...]
    _lookup: Mapping[str, BrandRule]

    @classmethod
    def from_document(cls, document: object) -> BrandCatalog:
        if isinstance(document, cls):
            return document
        if not isinstance(document, Mapping):
            raise BrandCatalogError(
                'Brand catalog root must be a JSON object'
            )

        allowed_root_keys = {
            'schema_version',
            'default_currency',
            'brands',
        }
        unknown_root_keys = set(document) - allowed_root_keys
        if unknown_root_keys:
            keys = ', '.join(sorted(str(key) for key in unknown_root_keys))
            raise BrandCatalogError(
                f'Unknown brand catalog root keys: {keys}'
            )

        schema_version = document.get('schema_version')
        if (
            isinstance(schema_version, bool)
            or not isinstance(schema_version, int)
            or schema_version != 1
        ):
            raise BrandCatalogError(
                'Brand catalog schema_version must be integer 1'
            )

        default_currency = document.get('default_currency', 'EUR')
        if (
            not isinstance(default_currency, str)
            or re.fullmatch(r'[A-Z]{3}', default_currency) is None
        ):
            raise BrandCatalogError(
                'Brand catalog default_currency must be a three-letter '
                'uppercase currency code'
            )

        raw_brands = document.get('brands')
        if not isinstance(raw_brands, Mapping):
            raise BrandCatalogError(
                'Brand catalog brands must be a JSON object keyed by '
                'brand identifier'
            )
        if not raw_brands:
            raise BrandCatalogError(
                'Brand catalog must define at least one brand'
            )
        if len(raw_brands) > _MAX_BRANDS:
            raise BrandCatalogError(
                f'Brand catalog cannot define more than {_MAX_BRANDS} brands'
            )

        rules: list[BrandRule] = []
        lookup: dict[str, BrandRule] = {}
        normalized_identifiers: dict[str, str] = {}

        # The identifier is intentionally the first argument to this parser.
        # It must not be confused with the brand definition mapping.
        for raw_identifier, raw_definition in raw_brands.items():
            if not isinstance(raw_identifier, str):
                raise BrandCatalogError(
                    'Every brand definition brand identifier must be a string'
                )

            normalized_identifier = _normalize_lookup_text(raw_identifier)
            if (
                re.fullmatch(
                    r'[a-z0-9]+(?:[_-][a-z0-9]+)*',
                    normalized_identifier,
                )
                is None
                or len(normalized_identifier) > 64
            ):
                raise BrandCatalogError(
                    f'Invalid brand identifier: {raw_identifier!r}'
                )

            previous_identifier = normalized_identifiers.get(
                normalized_identifier
            )
            if previous_identifier is not None:
                raise BrandCatalogError(
                    'Brand identifiers collide after normalization: '
                    f'{previous_identifier!r} and {raw_identifier!r}'
                )
            normalized_identifiers[normalized_identifier] = raw_identifier

            rule = _parse_brand_definition(
                raw_identifier,
                raw_definition,
                normalized_identifier,
            )
            rules.append(rule)

            for search_term in rule.search_terms:
                normalized_term = _normalize_lookup_text(search_term)
                previous_rule = lookup.get(normalized_term)
                if previous_rule is not None and (
                    previous_rule.identifier != rule.identifier
                ):
                    raise BrandCatalogError(
                        f'Alias {search_term!r} is assigned to both brands '
                        f'{previous_rule.identifier!r} and '
                        f'{rule.identifier!r}'
                    )
                lookup[normalized_term] = rule

        ordered_rules = tuple(sorted(rules, key=lambda rule: rule.identifier))
        return cls(
            schema_version=schema_version,
            default_currency=default_currency,
            rules=ordered_rules,
            _lookup=MappingProxyType(lookup),
        )

    def rule_for(self, candidate: str) -> BrandRule | None:
        return self._lookup.get(_normalize_lookup_text(candidate))

    get_brand = rule_for

    @property
    def brands(self) -> Mapping[str, BrandRule]:
        return MappingProxyType(
            {rule.identifier: rule for rule in self.rules}
        )

    def __len__(self) -> int:
        return len(self.rules)

    def __iter__(self):
        return iter(self.rules)


def _parse_brand_definition(
    raw_identifier: str,
    raw_definition: object,
    normalized_identifier: str,
) -> BrandRule:
    if not isinstance(raw_definition, Mapping):
        raise BrandCatalogError(
            f'Brand definition {raw_identifier!r} must be a JSON object'
        )

    allowed_keys = {
        'name',
        'aliases',
        'minimum_prices',
        'serial_patterns',
        'valid_serials',
        'serial_prefixes',
    }
    unknown_keys = set(raw_definition) - allowed_keys
    if unknown_keys:
        keys = ', '.join(sorted(str(key) for key in unknown_keys))
        raise BrandCatalogError(
            f'Unknown keys in brand definition {raw_identifier!r}: {keys}'
        )

    name = raw_definition.get('name')
    if not isinstance(name, str) or not name.strip():
        raise BrandCatalogError(
            f'Brand definition {raw_identifier!r} name must be a string'
        )
    if len(name) > 128:
        raise BrandCatalogError(
            f'Brand name is too long in definition {raw_identifier!r}'
        )
    normalized_name = _normalize_lookup_text(name)
    if len(normalized_name) > 128:
        raise BrandCatalogError(
            f'Normalized brand name is too long for {raw_identifier!r}'
        )

    raw_aliases = raw_definition.get('aliases', [name])
    if (
        not isinstance(raw_aliases, Sequence)
        or isinstance(raw_aliases, (str, bytes))
    ):
        raise BrandCatalogError(
            f'Aliases for brand {raw_identifier!r} must be an array'
        )
    if len(raw_aliases) > _MAX_ALIASES_PER_BRAND:
        raise BrandCatalogError(
            f'Brand {raw_identifier!r} has too many aliases'
        )

    aliases: list[str] = []
    for raw_alias in raw_aliases:
        if not isinstance(raw_alias, str) or not raw_alias.strip():
            raise BrandCatalogError(
                f'Aliases for brand {raw_identifier!r} must be non-empty strings'
            )
        if len(raw_alias) > 128:
            raise BrandCatalogError(
                f'Alias is too long for brand {raw_identifier!r}'
            )
        normalized_alias = _normalize_lookup_text(raw_alias)
        if len(normalized_alias) > 128:
            raise BrandCatalogError(
                f'Normalized alias is too long for brand {raw_identifier!r}'
            )
        if normalized_alias not in {
            _normalize_lookup_text(alias) for alias in aliases
        }:
            aliases.append(raw_alias.strip())

    if not aliases:
        aliases.append(name.strip())

    raw_prices = raw_definition.get('minimum_prices')
    if not isinstance(raw_prices, Mapping) or not raw_prices:
        raise BrandCatalogError(
            f'Brand {raw_identifier!r} minimum_prices must be a non-empty object'
        )
    if len(raw_prices) > 100:
        raise BrandCatalogError(
            f'Brand {raw_identifier!r} defines too many currencies'
        )

    minimum_prices: dict[str, Decimal] = {}
    for raw_currency, raw_threshold in raw_prices.items():
        if (
            not isinstance(raw_currency, str)
            or re.fullmatch(r'[A-Z]{3}', raw_currency) is None
        ):
            raise BrandCatalogError(
                f'Invalid currency code for brand {raw_identifier!r}: '
                f'{raw_currency!r}'
            )
        minimum_prices[raw_currency] = _parse_positive_decimal(
            raw_threshold,
            f'Minimum price for {raw_identifier} in {raw_currency}',
        )

    raw_patterns = raw_definition.get('serial_patterns', [])
    if (
        not isinstance(raw_patterns, Sequence)
        or isinstance(raw_patterns, (str, bytes))
    ):
        raise BrandCatalogError(
            f'serial_patterns for brand {raw_identifier!r} must be an array'
        )
    if len(raw_patterns) > _MAX_SERIAL_PATTERNS:
        raise BrandCatalogError(
            f'Brand {raw_identifier!r} has too many serial patterns'
        )

    serial_patterns: list[re.Pattern[str]] = []
    for raw_pattern in raw_patterns:
        if not isinstance(raw_pattern, str) or not raw_pattern:
            raise BrandCatalogError(
                f'Serial patterns for brand {raw_identifier!r} must be '
                'non-empty strings'
            )
        if len(raw_pattern) > _MAX_SERIAL_PATTERN_LENGTH:
            raise BrandCatalogError(
                f'Serial regex is too long for brand {raw_identifier!r}'
            )
        try:
            serial_patterns.append(re.compile(raw_pattern))
        except re.error as exc:
            raise BrandCatalogError(
                f'Invalid serial regex for brand {raw_identifier!r}: {exc}'
            ) from exc

    raw_valid_serials = raw_definition.get('valid_serials', [])
    if (
        not isinstance(raw_valid_serials, Sequence)
        or isinstance(raw_valid_serials, (str, bytes))
    ):
        raise BrandCatalogError(
            f'valid_serials for brand {raw_identifier!r} must be an array'
        )
    valid_serials: set[str] = set()
    for raw_serial in raw_valid_serials:
        if not isinstance(raw_serial, str) or not raw_serial.strip():
            raise BrandCatalogError(
                f'valid_serials for brand {raw_identifier!r} must contain '
                'non-empty strings'
            )
        normalized_serial = _normalize_serial(raw_serial)
        if len(normalized_serial) > _MAX_SERIAL_LENGTH:
            raise BrandCatalogError(
                f'Valid serial is too long for brand {raw_identifier!r}'
            )
        valid_serials.add(normalized_serial)

    raw_prefixes = raw_definition.get('serial_prefixes', [])
    if (
        not isinstance(raw_prefixes, Sequence)
        or isinstance(raw_prefixes, (str, bytes))
    ):
        raise BrandCatalogError(
            f'serial_prefixes for brand {raw_identifier!r} must be an array'
        )
    prefixes: list[str] = []
    for raw_prefix in raw_prefixes:
        if not isinstance(raw_prefix, str) or not raw_prefix.strip():
            raise BrandCatalogError(
                f'serial_prefixes for brand {raw_identifier!r} must contain '
                'non-empty strings'
            )
        normalized_prefix = _normalize_serial(raw_prefix)
        if not normalized_prefix or len(normalized_prefix) > _MAX_SERIAL_LENGTH:
            raise BrandCatalogError(
                f'Invalid serial prefix for brand {raw_identifier!r}'
            )
        if normalized_prefix not in prefixes:
            prefixes.append(normalized_prefix)

    return BrandRule(
        identifier=normalized_identifier,
        name=name.strip(),
        aliases=tuple(aliases),
        minimum_prices=MappingProxyType(minimum_prices),
        serial_patterns=tuple(serial_patterns),
        valid_serials=frozenset(valid_serials),
        serial_prefixes=tuple(prefixes),
    )


@dataclass(frozen=True, slots=True, init=False)
class BrandVerificationResult:
    """Immutable output of trusted brand and serial verification."""

    brand_identifier: str | None
    brand_name: str | None
    price: Decimal | None
    currency: str | None
    minimum_price: Decimal | None
    price_disparity: bool
    counterfeit_terminology: bool
    serial_numbers: tuple[str, ...]
    serial_valid: bool | None
    invalid_serial_number: bool
    conflicting_serial_numbers: bool
    is_counterfeit: bool
    reason_codes: tuple[str, ...]
    confidence: float
    rationale: str

    def __init__(
        self,
        brand_identifier: str | None = None,
        brand_name: str | None = None,
        *,
        brand: str | None = None,
        brand_id: str | None = None,
        matched_brand: str | None = None,
        detected_brand: str | None = None,
        price: Decimal | None = None,
        detected_price: Decimal | None = None,
        currency: str | None = None,
        minimum_price: Decimal | None = None,
        threshold: Decimal | None = None,
        price_disparity: bool | None = None,
        brand_price_disparity: bool | None = None,
        disparity_detected: bool | None = None,
        counterfeit_terminology: bool = False,
        is_counterfeit: bool | None = None,
        suspected_counterfeit: bool | None = None,
        counterfeit: bool | None = None,
        serial_numbers: Sequence[str] = (),
        serial_number: str | Sequence[str] | None = None,
        serial_valid: bool | None = None,
        valid_serial: bool | None = None,
        invalid_serial_number: bool | None = None,
        invalid_serial: bool | None = None,
        conflicting_serial_numbers: bool = False,
        reason_codes: Sequence[str] = (),
        reasons: Sequence[str] = (),
        confidence: float | None = None,
        rationale: str = '',
    ) -> None:
        resolved_identifier = brand_identifier or brand_id
        resolved_name = brand_name or brand or matched_brand or detected_brand
        if resolved_identifier is None and brand_id is not None:
            resolved_identifier = brand_id
        if resolved_name is None and resolved_identifier is not None:
            resolved_name = resolved_identifier

        resolved_price = price if price is not None else detected_price
        resolved_threshold = (
            minimum_price if minimum_price is not None else threshold
        )

        disparity_flags = (
            price_disparity,
            brand_price_disparity,
            disparity_detected,
        )
        resolved_disparity = any(
            bool(flag) for flag in disparity_flags if flag is not None
        )

        serial_candidates: list[str] = []
        if isinstance(serial_number, str):
            serial_candidates.append(serial_number)
        elif serial_number is not None:
            serial_candidates.extend(serial_number)
        for candidate in serial_numbers:
            if candidate not in serial_candidates:
                serial_candidates.append(candidate)
        normalized_serials = tuple(
            dict.fromkeys(
                normalized
                for candidate in serial_candidates
                if (normalized := _normalize_serial(candidate))
            )
        )

        invalid_flags = (invalid_serial_number, invalid_serial)
        resolved_invalid = any(
            bool(flag) for flag in invalid_flags if flag is not None
        )
        if resolved_invalid:
            resolved_serial_valid: bool | None = False
        elif serial_valid is not None:
            resolved_serial_valid = serial_valid
        elif valid_serial is not None:
            resolved_serial_valid = valid_serial
        else:
            resolved_serial_valid = None

        supplied_reasons = tuple(reason_codes) or tuple(reasons)
        normalized_reasons: list[str] = []
        for reason in supplied_reasons:
            if (
                isinstance(reason, str)
                and re.fullmatch(r'[a-z][a-z0-9_]{0,63}', reason)
                and reason not in normalized_reasons
            ):
                normalized_reasons.append(reason)

        explicit_counterfeit_flags = (
            is_counterfeit,
            suspected_counterfeit,
            counterfeit,
        )
        explicit_counterfeit = any(
            bool(flag)
            for flag in explicit_counterfeit_flags
            if flag is not None
        )
        derived_counterfeit = any(
            (
                explicit_counterfeit,
                resolved_disparity,
                counterfeit_terminology,
                resolved_invalid,
                conflicting_serial_numbers,
                'counterfeit' in normalized_reasons,
                'brand_price_disparity' in normalized_reasons,
                'counterfeit_terminology' in normalized_reasons,
                'invalid_serial_number' in normalized_reasons,
            )
        )
        if derived_counterfeit and 'counterfeit' not in normalized_reasons:
            normalized_reasons.insert(0, 'counterfeit')

        if confidence is None:
            if resolved_disparity and counterfeit_terminology:
                resolved_confidence = 0.99
            elif resolved_disparity or counterfeit_terminology:
                resolved_confidence = 0.98
            elif resolved_invalid or conflicting_serial_numbers:
                resolved_confidence = 0.97
            elif derived_counterfeit:
                resolved_confidence = 0.95
            else:
                resolved_confidence = 0.0
        else:
            if isinstance(confidence, bool) or not isinstance(
                confidence, (int, float)
            ):
                raise TypeError('confidence must be numeric')
            resolved_confidence = float(confidence)

        if not rationale:
            if derived_counterfeit:
                rationale = (
                    'Trusted brand verification found evidence that the '
                    'listing content may be counterfeit.'
                )
            elif resolved_name is not None:
                rationale = (
                    f'{resolved_name} was identified, but no deterministic '
                    'counterfeit evidence was found.'
                )
            else:
                rationale = (
                    'No trusted brand or counterfeit evidence was detected.'
                )

        object.__setattr__(self, 'brand_identifier', resolved_identifier)
        object.__setattr__(self, 'brand_name', resolved_name)
        object.__setattr__(self, 'price', resolved_price)
        object.__setattr__(self, 'currency', currency)
        object.__setattr__(self, 'minimum_price', resolved_threshold)
        object.__setattr__(self, 'price_disparity', resolved_disparity)
        object.__setattr__(
            self,
            'counterfeit_terminology',
            bool(counterfeit_terminology),
        )
        object.__setattr__(self, 'serial_numbers', normalized_serials)
        object.__setattr__(self, 'serial_valid', resolved_serial_valid)
        object.__setattr__(
            self,
            'invalid_serial_number',
            resolved_invalid,
        )
        object.__setattr__(
            self,
            'conflicting_serial_numbers',
            bool(conflicting_serial_numbers),
        )
        object.__setattr__(self, 'is_counterfeit', derived_counterfeit)
        object.__setattr__(self, 'reason_codes', tuple(normalized_reasons))
        object.__setattr__(self, 'confidence', resolved_confidence)
        object.__setattr__(self, 'rationale', rationale)

    @property
    def brand(self) -> str | None:
        return self.brand_name

    @property
    def brand_id(self) -> str | None:
        return self.brand_identifier

    @property
    def matched_brand(self) -> str | None:
        return self.brand_name

    @property
    def detected_brand(self) -> str | None:
        return self.brand_name

    @property
    def listing_price(self) -> Decimal | None:
        return self.price

    @property
    def detected_price(self) -> Decimal | None:
        return self.price

    @property
    def threshold(self) -> Decimal | None:
        return self.minimum_price

    @property
    def price_threshold(self) -> Decimal | None:
        return self.minimum_price

    @property
    def brand_price_disparity(self) -> bool:
        return self.price_disparity

    @property
    def disparity_detected(self) -> bool:
        return self.price_disparity

    @property
    def suspected_counterfeit(self) -> bool:
        return self.is_counterfeit

    @property
    def counterfeit_detected(self) -> bool:
        return self.is_counterfeit

    @property
    def requires_review(self) -> bool:
        return self.is_counterfeit

    @property
    def serial_number(self) -> str | None:
        if len(self.serial_numbers) == 1:
            return self.serial_numbers[0]
        return None

    @property
    def valid_serial(self) -> bool | None:
        return self.serial_valid

    @property
    def serial_verified(self) -> bool | None:
        return self.serial_valid

    @property
    def invalid_serial(self) -> bool:
        return self.invalid_serial_number

    @property
    def conflicting_serials(self) -> bool:
        return self.conflicting_serial_numbers

    @property
    def reasons(self) -> tuple[str, ...]:
        return self.reason_codes


BrandVerification = BrandVerificationResult
LuxuryBrandIndex = BrandCatalog


@runtime_checkable
class BrandVerifier(Protocol):
    """Structural interface accepted by the deterministic policy engine."""

    def verify(self, listing: ListingInput) -> BrandVerificationResult:
        """Verify one validated marketplace listing."""
        ...


def _load_catalog_path(path: Path) -> BrandCatalog:
    return BrandCatalog.from_document(_read_catalog_document(path))


@lru_cache(maxsize=1)
def _default_catalog() -> BrandCatalog:
    return _load_catalog_path(DEFAULT_LUXURY_INDEX_PATH)


def load_luxury_catalog(
    path: str | Path = DEFAULT_LUXURY_INDEX_PATH,
) -> BrandCatalog:
    """Load and validate a trusted luxury-brand catalog."""

    catalog_path = Path(path)
    try:
        if catalog_path.resolve() == DEFAULT_LUXURY_INDEX_PATH.resolve():
            return _default_catalog()
    except OSError:
        return _load_catalog_path(catalog_path)
    return _load_catalog_path(catalog_path)


def load_brand_catalog(
    path: str | Path = DEFAULT_BRAND_INDEX_PATH,
) -> BrandCatalog:
    """Compatibility alias for :func:`load_luxury_catalog`."""

    return load_luxury_catalog(path)


def load_luxury_index(
    path: str | Path = DEFAULT_LUXURY_INDEX_PATH,
) -> BrandCatalog:
    """Compatibility alias for :func:`load_luxury_catalog`."""

    return load_luxury_catalog(path)


class LuxuryBrandVerifier:
    """Deterministic brand, price, and serial-number verifier."""

    def __init__(
        self,
        index: BrandCatalog | str | Path | None = None,
        *,
        path: str | Path | None = None,
        catalog: BrandCatalog | str | Path | None = None,
        catalog_path: str | Path | None = None,
    ) -> None:
        sources = [
            source
            for source in (index, path, catalog, catalog_path)
            if source is not None
        ]
        if len(sources) > 1:
            raise TypeError(
                'Specify only one of index, path, catalog, or catalog_path'
            )

        source = sources[0] if sources else None
        if isinstance(source, BrandCatalog):
            self._index = source
        elif source is not None:
            self._index = load_luxury_catalog(source)
        else:
            self._index = _default_catalog()

    @property
    def index(self) -> BrandCatalog:
        return self._index

    @property
    def catalog(self) -> BrandCatalog:
        return self._index

    def _match_rule(self, texts: Sequence[str]) -> BrandRule | None:
        best_rule: BrandRule | None = None
        best_score = -1

        for rule in self._index.rules:
            for term in rule.search_terms:
                normalized_term = _normalize_lookup_text(term)
                pattern = re.compile(
                    rf'(?<!\w){re.escape(normalized_term)}(?!\w)'
                )
                for text in texts:
                    match = pattern.search(text)
                    if match is None:
                        continue
                    score = len(normalized_term)
                    if (
                        score > best_score
                        or (
                            score == best_score
                            and best_rule is not None
                            and rule.identifier < best_rule.identifier
                        )
                    ):
                        best_rule = rule
                        best_score = score
        return best_rule

    def verify(
        self,
        listing: ListingInput | Mapping[str, object],
    ) -> BrandVerificationResult:
        """Verify a listing without obeying any text embedded in it."""

        try:
            validated = ListingInput.model_validate(listing)
        except Exception as exc:
            raise BrandCatalogError(
                'Listing does not satisfy the ListingInput schema'
            ) from exc

        texts, combined_text = _collect_listing_text(validated)
        rule = self._match_rule(texts)
        counterfeit_terminology = _contains_counterfeit_terminology(texts)

        price = validated.price
        currency = validated.currency
        threshold: Decimal | None = None

        if price is None:
            parsed_symbol_price = _parse_symbol_price(combined_text)
            if parsed_symbol_price is not None:
                price, currency = parsed_symbol_price

        if rule is not None:
            effective_currency = currency or self._index.default_currency
            if (
                price is not None
                and effective_currency is not None
            ):
                threshold = rule.minimum_price_for(effective_currency)
                currency = effective_currency

        price_disparity = bool(
            price is not None
            and threshold is not None
            and price < threshold
        )

        serial_candidates = list(
            _collect_serial_numbers(validated.metadata)
        )
        serial_candidates.extend(
            _collect_serial_numbers(validated.image_metadata)
        )
        for text in texts:
            for match in _SERIAL_CONTEXT_RE.finditer(text):
                serial_candidates.append(match.group(1))

        serial_numbers: list[str] = []
        for candidate in serial_candidates:
            normalized = _normalize_serial(candidate)
            if (
                not normalized
                or len(normalized) > _MAX_SERIAL_LENGTH
                or normalized in _SERIAL_PLACEHOLDERS
                or normalized in serial_numbers
            ):
                continue
            serial_numbers.append(normalized)

        serial_valid: bool | None = None
        invalid_serial = False
        if rule is not None and serial_numbers:
            serial_valid = True
            for serial in serial_numbers:
                outcome = rule.validate_serial(serial)
                if outcome is False:
                    invalid_serial = True
                    serial_valid = False
                    break
                if outcome is None:
                    serial_valid = None

        conflicting_serials = len(serial_numbers) > 1
        reason_codes: list[str] = []
        if any(
            (
                price_disparity,
                counterfeit_terminology,
                invalid_serial,
                conflicting_serials,
            )
        ):
            reason_codes.append('counterfeit')
        if price_disparity:
            reason_codes.append('brand_price_disparity')
        if counterfeit_terminology:
            reason_codes.append('counterfeit_terminology')
        if invalid_serial:
            reason_codes.append('invalid_serial_number')
        if conflicting_serials:
            reason_codes.append('conflicting_serial_numbers')

        if price_disparity and threshold is not None and price is not None:
            rationale = (
                f'{rule.name if rule is not None else "A trusted brand"} was '
                f'identified at {price} {currency}; the configured minimum '
                f'price is {threshold} {currency}. '
            )
        elif counterfeit_terminology:
            rationale = (
                'Explicit counterfeit or replica terminology was found in '
                'the listing content. '
            )
        elif invalid_serial:
            rationale = (
                'A supplied serial number does not match the trusted brand '
                'verification rule. '
            )
        else:
            rationale = (
                f'{rule.name} was identified, but no deterministic '
                'counterfeit evidence was found.'
                if rule is not None
                else 'No trusted brand or counterfeit evidence was detected.'
            )

        if reason_codes and rationale.endswith(' '):
            rationale += 'The listing content requires human review.'
        elif rule is not None and not reason_codes:
            rationale = (
                f'{rule.name} was identified, but no deterministic '
                'counterfeit evidence was found.'
            )

        confidence = 0.0
        if price_disparity or counterfeit_terminology:
            confidence = 0.99 if price_disparity else 0.98
        elif invalid_serial or conflicting_serials:
            confidence = 0.97

        return BrandVerificationResult(
            brand_identifier=rule.identifier if rule is not None else None,
            brand_name=rule.name if rule is not None else None,
            price=price,
            currency=currency,
            minimum_price=threshold,
            price_disparity=price_disparity,
            counterfeit_terminology=counterfeit_terminology,
            serial_numbers=tuple(serial_numbers),
            serial_valid=serial_valid,
            invalid_serial_number=invalid_serial,
            conflicting_serial_numbers=conflicting_serials,
            reason_codes=tuple(reason_codes),
            confidence=confidence,
            rationale=rationale,
        )

    def verify_listing(
        self,
        listing: ListingInput | Mapping[str, object],
    ) -> BrandVerificationResult:
        return self.verify(listing)

    def verify_brand_and_serial(
        self,
        listing: ListingInput | Mapping[str, object],
    ) -> BrandVerificationResult:
        return self.verify(listing)

    def __call__(
        self,
        listing: ListingInput | Mapping[str, object],
    ) -> BrandVerificationResult:
        return self.verify(listing)


_DEFAULT_BRAND_VERIFIER_LOCK: Final[threading.Lock] = threading.Lock()


def _coerce_verifier(
    source: object | None,
) -> BrandVerifier:
    if source is None:
        return LuxuryBrandVerifier()
    if isinstance(source, BrandCatalog):
        return LuxuryBrandVerifier(index=source)
    if isinstance(source, (str, Path, Mapping)):
        return LuxuryBrandVerifier(index=source)
    if (
        callable(source)
        or callable(getattr(source, 'verify', None))
        or callable(getattr(source, 'verify_listing', None))
        or callable(getattr(source, 'verify_brand_and_serial', None))
    ):
        return source  # type: ignore[return-value]
    raise TypeError(
        'verifier must be a BrandVerifier, BrandCatalog, path, or mapping'
    )


def verify_listing(
    listing: ListingInput | Mapping[str, object],
    verifier: object | None = None,
    *,
    index: BrandCatalog | str | Path | None = None,
    catalog: BrandCatalog | str | Path | Mapping[str, object] | None = None,
) -> BrandVerificationResult:
    """Verify a listing using an explicit or default trusted verifier."""

    sources = [source for source in (index, catalog) if source is not None]
    if len(sources) > 1:
        raise TypeError('Specify only one of index or catalog')

    source = verifier
    if sources:
        if verifier is not None:
            raise TypeError('Specify verifier or catalog source, not both')
        source = sources[0]

    with _DEFAULT_BRAND_VERIFIER_LOCK:
        resolved = _coerce_verifier(source)

    if callable(getattr(resolved, 'verify', None)):
        method = getattr(resolved, 'verify')
    elif callable(getattr(resolved, 'verify_listing', None)):
        method = getattr(resolved, 'verify_listing')
    elif callable(getattr(resolved, 'verify_brand_and_serial', None)):
        method = getattr(resolved, 'verify_brand_and_serial')
    else:
        method = resolved

    result = method(listing)
    if not isinstance(result, BrandVerificationResult):
        raise BrandCatalogError(
            'Brand verifier returned an unsupported result type'
        )
    return result


def verify_brand_and_serial(
    listing: ListingInput | Mapping[str, object],
    verifier: object | None = None,
    *,
    index: BrandCatalog | str | Path | None = None,
    catalog: BrandCatalog | str | Path | Mapping[str, object] | None = None,
) -> BrandVerificationResult:
    """Compatibility name for :func:`verify_listing`."""

    return verify_listing(
        listing,
        verifier,
        index=index,
        catalog=catalog,
    )


__all__ = [
    'BrandCatalog',
    'BrandCatalogError',
    'BrandRule',
    'BrandVerification',
    'BrandVerificationResult',
    'BrandVerifier',
    'DEFAULT_BRAND_INDEX_PATH',
    'DEFAULT_LUXURY_INDEX_PATH',
    'LuxuryBrandIndex',
    'LuxuryBrandVerifier',
    'load_brand_catalog',
    'load_luxury_catalog',
    'load_luxury_index',
    'verify_brand_and_serial',
    'verify_listing',
]