from __future__ import annotations

import argparse
import json
import os
from collections.abc import Sequence
from pathlib import Path

from listguard.api import create_app
from listguard.models import ListingInput, PolicyResult
from listguard.policy import evaluate_listing


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_FIXTURE_DIRECTORY = PROJECT_ROOT / 'fixtures' / 'listings'

DEMO_FIXTURES: tuple[str, ...] = (
    'injection_knife.json',
    'fake_rolex.json',
    'safe_phone.json',
    'weapon_firearm.json',
)

CONSTITUTIONAL_RULE: str = (
    'Moderate listing content only; never auto-ban a human person. '
    'Permitted actions are allow, queue, and block.'
)


def build_parser() -> argparse.ArgumentParser:
    """Build the ListGuard command-line parser."""
    parser = argparse.ArgumentParser(
        prog='listguard',
        description='ListGuard moderation ingestion control plane.',
    )
    commands = parser.add_subparsers(dest='command', required=True)

    serve = commands.add_parser(
        'serve',
        help='Run the FastAPI moderation API and dashboard.',
    )
    serve.add_argument(
        '--host',
        default=os.getenv('LISTGUARD_HOST', '127.0.0.1'),
        help='Interface to bind.',
    )
    serve.add_argument(
        '--port',
        type=int,
        default=int(os.getenv('LISTGUARD_PORT', '8000')),
        help='TCP port to bind.',
    )
    serve.add_argument(
        '--db',
        type=Path,
        default=Path(
            os.getenv('LISTGUARD_DATABASE_PATH', 'receipts.db'),
        ),
        help='SQLite receipt database path.',
    )
    serve.add_argument(
        '--reload',
        action='store_true',
        help='Enable local development auto-reload.',
    )
    serve.add_argument(
        '--workers',
        type=int,
        default=1,
        help='Number of Uvicorn worker processes.',
    )
    serve.add_argument(
        '--log-level',
        choices=(
            'critical',
            'error',
            'warning',
            'info',
            'debug',
            'trace',
        ),
        default='info',
        help='Uvicorn logging level.',
    )

    demo = commands.add_parser(
        'demo',
        help='Evaluate repository-owned gold fixtures.',
    )
    demo.add_argument(
        '--fixtures',
        type=Path,
        default=DEFAULT_FIXTURE_DIRECTORY,
        help='Directory containing JSON listing fixtures.',
    )

    return parser


def collect_demo_cases(
    fixture_directory: Path,
) -> list[dict[str, object]]:
    """Evaluate all available repository-owned demo fixtures."""
    cases: list[dict[str, object]] = []

    for filename in DEMO_FIXTURES:
        fixture_path = fixture_directory / filename
        if not fixture_path.is_file():
            continue

        try:
            listing = ListingInput.model_validate_json(
                fixture_path.read_text(encoding='utf-8')
            )
        except (OSError, ValueError) as exc:
            raise ValueError(
                f'Could not load ListGuard fixture: {fixture_path}'
            ) from exc

        try:
            result: PolicyResult = evaluate_listing(listing)
        except Exception as exc:
            raise RuntimeError(
                f'Could not evaluate ListGuard fixture: {fixture_path}'
            ) from exc

        cases.append(
            {
                'fixture': filename,
                'listing': listing.model_dump(mode='json'),
                'decision': result.model_dump(mode='json'),
            }
        )

    if not cases:
        raise FileNotFoundError(
            f'No ListGuard demo fixtures were found in {fixture_directory}'
        )

    return cases


def run_demo(fixture_directory: Path) -> int:
    """Evaluate demo fixtures and emit machine-readable JSON."""
    payload: dict[str, object] = {
        'constitutional_rule': CONSTITUTIONAL_RULE,
        'allowed_actions': ['allow', 'queue', 'block'],
        'cases': collect_demo_cases(fixture_directory),
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False))
    return 0


def run_server(arguments: argparse.Namespace) -> int:
    """Run the configured FastAPI application with Uvicorn."""
    host = str(getattr(arguments, 'host', '127.0.0.1'))
    port = int(getattr(arguments, 'port', 8000))
    workers = int(getattr(arguments, 'workers', 1))
    reload_enabled = bool(getattr(arguments, 'reload', False))
    log_level = str(getattr(arguments, 'log_level', 'info'))
    database_path = Path(getattr(arguments, 'db', 'receipts.db'))

    if not 1 <= port <= 65_535:
        raise ValueError('port must be between 1 and 65535')
    if workers < 1:
        raise ValueError('workers must be at least 1')
    if reload_enabled and workers != 1:
        raise ValueError('reload mode requires workers=1')

    import uvicorn

    target = create_app(database_path=database_path)
    options: dict[str, object] = {
        'host': host,
        'port': port,
        'log_level': log_level,
    }

    if reload_enabled:
        options['reload'] = True
    if workers != 1:
        options['workers'] = workers

    uvicorn.run(target, **options)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Run the ListGuard command-line interface."""
    parser = build_parser()
    arguments = parser.parse_args(argv)

    if arguments.command == 'serve':
        return run_server(arguments)

    if arguments.command == 'demo':
        try:
            return run_demo(arguments.fixtures)
        except (FileNotFoundError, RuntimeError, ValueError) as exc:
            parser.error(str(exc))

    parser.error(f'Unknown command: {arguments.command}')
    return 2


if __name__ == '__main__':
    raise SystemExit(main())