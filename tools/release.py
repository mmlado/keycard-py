"""
Release helpers shared by `invoke release` and the release workflow.

Usage:
    python tools/release.py bump 0.5.0       # version and changelog
    python tools/release.py check v0.5.0     # prints GitHub Actions outputs
    python tools/release.py notes 0.5.0      # changelog section
"""
import argparse
import datetime
import re
import sys
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parent.parent
INIT = ROOT / 'keycard' / '__init__.py'
CHANGELOG = ROOT / 'CHANGELOG.md'

VERSION_LINE = re.compile(r'^__version__ = "([^"]+)"$', re.M)
UNRELEASED_LINK = re.compile(
    r'^\[unreleased\]: (?P<repo>\S+)/compare/v(?P<version>\S+)\.\.\.HEAD$',
    re.M | re.I)
PRERELEASE = re.compile(r'(a|b|rc)\d+$')


def read_version(init_text: str) -> str:
    match = VERSION_LINE.search(init_text)
    if match is None:
        raise ValueError('No __version__ line in keycard/__init__.py')
    return match.group(1)


def is_prerelease(version: str) -> bool:
    return PRERELEASE.search(version) is not None


def changelog_section(changelog: str, version: str) -> Optional[str]:
    match = re.search(
        rf'^## \[{re.escape(version)}\][^\n]*\n(.*?)(?=^## \[|^\[|\Z)',
        changelog, re.M | re.S)
    return match.group(1).strip() if match else None


def bump(
    init_text: str,
    changelog: str,
    version: str,
    date: datetime.date
) -> tuple[str, str]:
    unreleased = changelog_section(changelog, 'Unreleased')
    if not unreleased:
        raise ValueError('Nothing under [Unreleased] in CHANGELOG.md')
    if changelog_section(changelog, version) is not None:
        raise ValueError(f'CHANGELOG.md already has a [{version}] section')

    link = UNRELEASED_LINK.search(changelog)
    if link is None:
        raise ValueError('No [unreleased] comparison link in CHANGELOG.md')
    repo, previous = link.group('repo'), link.group('version')

    init_text = VERSION_LINE.sub(f'__version__ = "{version}"', init_text)
    changelog = changelog.replace(
        '## [Unreleased]\n',
        f'## [Unreleased]\n\n## [{version}] - {date.isoformat()}\n',
        1)
    changelog = UNRELEASED_LINK.sub(
        f'[unreleased]: {repo}/compare/v{version}...HEAD\n'
        f'[{version}]: {repo}/compare/v{previous}...v{version}',
        changelog)
    return init_text, changelog


def check(tag: str, init_text: str, changelog: str) -> list[str]:
    errors = []
    version = tag.removeprefix('v')
    package_version = read_version(init_text)
    if version != package_version:
        errors.append(
            f'Tag {tag} does not match __version__ {package_version}')
    if not is_prerelease(version) and not changelog_section(
            changelog, version):
        errors.append(f'CHANGELOG.md has no [{version}] section')
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('bump').add_argument('version')
    commands.add_parser('check').add_argument('tag')
    commands.add_parser('notes').add_argument('version')
    args = parser.parse_args()

    init_text = INIT.read_text()
    changelog = CHANGELOG.read_text()

    if args.command == 'bump':
        init_text, changelog = bump(
            init_text, changelog, args.version, datetime.date.today())
        INIT.write_text(init_text)
        CHANGELOG.write_text(changelog)
    elif args.command == 'check':
        errors = check(args.tag, init_text, changelog)
        for error in errors:
            print(error, file=sys.stderr)
        if errors:
            return 1
        version = args.tag.removeprefix('v')
        print(f'version={version}')
        print(f'prerelease={str(is_prerelease(version)).lower()}')
    else:
        notes = changelog_section(changelog, args.version)
        if notes is None:
            print(f'CHANGELOG.md has no [{args.version}] section',
                  file=sys.stderr)
            return 1
        print(notes)
    return 0


if __name__ == '__main__':
    sys.exit(main())
