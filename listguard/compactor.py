from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass
from typing import Final

DEFAULT_TOKEN_BUDGET: Final[int] = 512
DEFAULT_MAX_CHARACTERS: Final[int] = 16_000

_TOKEN_RE: Final[re.Pattern[str]] = re.compile(
    r"\w+(?:['’]\w+)*|[^\w\s]",
    flags=re.UNICODE,
)

_CONFUSABLES: Final[dict[str, str]] = {
    # Cyrillic characters commonly used in mixed-script attacks.
    'а': 'a',
    'в': 'b',
    'е': 'e',
    'к': 'k',
    'м': 'm',
    'н': 'h',
    'о': 'o',
    'р': 'p',
    'с': 'c',
    'т': 't',
    'у': 'y',
    'х': 'x',
    'і': 'i',
    'ј': 'j',
    'ѕ': 's',
    'һ': 'h',
    'ё': 'e',
    'є': 'e',
    'ї': 'i',
    'ґ': 'r',
    # Greek characters commonly confused with Latin letters.
    'α': 'a',
    'β': 'b',
    'ε': 'e',
    'η': 'n',
    'ι': 'i',
    'κ': 'k',
    'ν': 'v',
    'ο': 'o',
    'ρ': 'p',
    'σ': 's',
    'τ': 't',
    'υ': 'u',
    'χ': 'x',
    'ϲ': 'c',
    # Armenian and Georgian forms used in simple homoglyph attacks.
    'օ': 'o',
    'ց': 'g',
    'ա': 'a',
    'հ': 'h',
    'ո': 'n',
    'ռ': 'n',
    'ր': 'r',
    'ց': 'g',
    # Latin characters commonly substituted for ASCII letters.
    'ı': 'i',
    'ɡ': 'g',
    'ɩ': 'i',
    'ɪ': 'i',
    'ʟ': 'l',
    'ⅼ': 'l',
    'ο': 'o',
}

_TRANSLATION_TABLE: Final[dict[int, str | int]] = str.maketrans(
    _CONFUSABLES
)


class _Unset:
    __slots__ = ()


_UNSET: Final[_Unset] = _Unset()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(
        value.encode('utf-8', errors='surrogatepass')
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class CompactionResult:
    '''Deterministic metadata describing one compactor invocation.'''

    normalized_text: str
    original_token_count: int
    output_token_count: int
    truncated: bool
    original_sha256: str
    output_sha256: str


class WinnowCompactor:
    '''Normalize adversarial text and compact it to a deterministic budget.

    Submitted text is always treated as untrusted data. The compactor does
    not execute, obey, or semantically interpret instructions found in a
    marketplace listing.
    '''

    def __init__(
        self,
        max_tokens: int | None = DEFAULT_TOKEN_BUDGET,
        max_characters: int | None = DEFAULT_MAX_CHARACTERS,
    ) -> None:
        self._validate_limit(max_tokens, 'max_tokens')
        self._validate_limit(max_characters, 'max_characters')
        self.max_tokens = max_tokens
        self.max_characters = max_characters

    @staticmethod
    def _validate_limit(value: int | None, field_name: str) -> None:
        if value is None:
            return
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f'{field_name} must be an integer or None')
        if value < 1:
            raise ValueError(f'{field_name} must be at least 1')

    def _resolve_limit(
        self,
        per_call_value: int | None | _Unset,
        configured_value: int | None,
        field_name: str,
    ) -> int | None:
        resolved = (
            configured_value
            if isinstance(per_call_value, _Unset)
            else per_call_value
        )
        if resolved is not None and not isinstance(resolved, int):
            raise TypeError(f'{field_name} must be an integer or None')
        self._validate_limit(resolved, field_name)
        return resolved

    @staticmethod
    def normalize_text(text: str) -> str:
        '''Return stable, case-folded text suitable for policy matching.

        Compatibility normalization is applied first. Combining marks and
        invisible formatting characters are removed, controls become spaces,
        common confusables are folded, and all whitespace is collapsed.
        '''
        if not isinstance(text, str):
            raise TypeError('text must be a string')

        normalized = unicodedata.normalize('NFKC', text)
        normalized = normalized.casefold()
        normalized = unicodedata.normalize('NFKD', normalized)

        characters: list[str] = []
        for character in normalized:
            category = unicodedata.category(character)
            if category == 'Cc':
                characters.append(' ')
            elif category in {'Cf', 'Mn', 'Me'}:
                continue
            elif category == 'Cs':
                characters.append('\ufffd')
            else:
                characters.append(character)

        normalized = ''.join(characters)
        normalized = normalized.translate(_TRANSLATION_TABLE)
        return re.sub(r'\s+', ' ', normalized, flags=re.UNICODE).strip()

    @classmethod
    def normalize(cls, text: str) -> str:
        '''Compatibility alias for :meth:`normalize_text`.'''
        return cls.normalize_text(text)

    @staticmethod
    def tokenize(text: str) -> tuple[str, ...]:
        '''Split text into deterministic lexical and punctuation tokens.'''
        if not isinstance(text, str):
            raise TypeError('text must be a string')
        return tuple(_TOKEN_RE.findall(text))

    @classmethod
    def count_tokens(cls, text: str) -> int:
        '''Return the deterministic lexical token count for text.'''
        return len(cls.tokenize(text))

    def compaction_result(
        self,
        text: str,
        *,
        max_tokens: int | None | _Unset = _UNSET,
        max_characters: int | None | _Unset = _UNSET,
    ) -> CompactionResult:
        '''Normalize, budget, and describe a compactor invocation.'''
        if not isinstance(text, str):
            raise TypeError('text must be a string')

        selected_token_limit = self._resolve_limit(
            max_tokens,
            self.max_tokens,
            'max_tokens',
        )
        selected_character_limit = self._resolve_limit(
            max_characters,
            self.max_characters,
            'max_characters',
        )

        normalized = self.normalize_text(text)
        original_token_count = self.count_tokens(text)

        if selected_token_limit is None:
            compacted = normalized
        else:
            tokens = self.tokenize(normalized)
            compacted = ' '.join(tokens[:selected_token_limit])

        if (
            selected_character_limit is not None
            and len(compacted) > selected_character_limit
        ):
            compacted = compacted[:selected_character_limit].rstrip()

        return CompactionResult(
            normalized_text=compacted,
            original_token_count=original_token_count,
            output_token_count=self.count_tokens(compacted),
            truncated=compacted != normalized,
            original_sha256=_sha256_text(text),
            output_sha256=_sha256_text(compacted),
        )

    def compact(
        self,
        text: str,
        *,
        max_tokens: int | None | _Unset = _UNSET,
        max_characters: int | None | _Unset = _UNSET,
    ) -> str:
        '''Return normalized text constrained by the configured budgets.'''
        return self.compaction_result(
            text,
            max_tokens=max_tokens,
            max_characters=max_characters,
        ).normalized_text

    def compact_with_metadata(
        self,
        text: str,
        *,
        max_tokens: int | None | _Unset = _UNSET,
        max_characters: int | None | _Unset = _UNSET,
    ) -> CompactionResult:
        '''Compatibility alias for :meth:`compaction_result`.'''
        return self.compaction_result(
            text,
            max_tokens=max_tokens,
            max_characters=max_characters,
        )

    def compact_text(
        self,
        text: str,
        *,
        max_tokens: int | None | _Unset = _UNSET,
        max_characters: int | None | _Unset = _UNSET,
    ) -> str:
        '''Compatibility alias for :meth:`compact`.'''
        return self.compact(
            text,
            max_tokens=max_tokens,
            max_characters=max_characters,
        )

    def __call__(
        self,
        text: str,
        *,
        max_tokens: int | None | _Unset = _UNSET,
        max_characters: int | None | _Unset = _UNSET,
    ) -> str:
        return self.compact(
            text,
            max_tokens=max_tokens,
            max_characters=max_characters,
        )


__all__ = [
    'CompactionResult',
    'DEFAULT_MAX_CHARACTERS',
    'DEFAULT_TOKEN_BUDGET',
    'WinnowCompactor',
]