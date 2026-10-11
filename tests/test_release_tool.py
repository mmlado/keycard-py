import datetime

import pytest

from tools import release

INIT = '"""Docs."""\n\n__version__ = "0.4.0"\n'
CHANGELOG = """# Changelog

## [Unreleased]

### Added

- Something new

## [0.4.0] - 2026-10-11

### Added

- Applet 4.0 support

[unreleased]: https://github.com/mmlado/keycard-py/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/mmlado/keycard-py/compare/v0.3.0...v0.4.0
"""


def test_read_version():
    assert release.read_version(INIT) == '0.4.0'


def test_read_version_missing():
    with pytest.raises(ValueError, match='__version__'):
        release.read_version('"""Docs."""\n')


@pytest.mark.parametrize('version, expected', [
    ('0.5.0', False),
    ('0.5.0rc1', True),
    ('1.0.0b2', True),
    ('1.0.0a1', True),
])
def test_is_prerelease(version, expected):
    assert release.is_prerelease(version) is expected


def test_changelog_section():
    assert release.changelog_section(CHANGELOG, '0.4.0') == (
        '### Added\n\n- Applet 4.0 support')
    assert release.changelog_section(CHANGELOG, 'Unreleased') == (
        '### Added\n\n- Something new')
    assert release.changelog_section(CHANGELOG, '0.5.0') is None


def test_bump():
    init_text, changelog = release.bump(
        INIT, CHANGELOG, '0.5.0', datetime.date(2026, 11, 1))

    assert release.read_version(init_text) == '0.5.0'
    assert '## [Unreleased]\n\n## [0.5.0] - 2026-11-01\n' in changelog
    assert release.changelog_section(changelog, 'Unreleased') == ''
    assert release.changelog_section(changelog, '0.5.0') == (
        '### Added\n\n- Something new')
    assert changelog.endswith(
        '[unreleased]: https://github.com/mmlado/keycard-py/compare/'
        'v0.5.0...HEAD\n'
        '[0.5.0]: https://github.com/mmlado/keycard-py/compare/'
        'v0.4.0...v0.5.0\n'
        '[0.4.0]: https://github.com/mmlado/keycard-py/compare/'
        'v0.3.0...v0.4.0\n')


def test_bump_needs_unreleased_changes():
    _, changelog = release.bump(
        INIT, CHANGELOG, '0.5.0', datetime.date(2026, 11, 1))

    with pytest.raises(ValueError, match='Nothing under'):
        release.bump(INIT, changelog, '0.6.0', datetime.date(2026, 12, 1))


def test_bump_rejects_existing_version():
    with pytest.raises(ValueError, match='already has'):
        release.bump(INIT, CHANGELOG, '0.4.0', datetime.date(2026, 11, 1))


def test_check_passes():
    assert release.check('v0.4.0', INIT, CHANGELOG) == []


def test_check_tag_mismatch():
    assert release.check('v0.4.1', INIT, CHANGELOG) == [
        'Tag v0.4.1 does not match __version__ 0.4.0',
        'CHANGELOG.md has no [0.4.1] section',
    ]


def test_check_prerelease_needs_no_changelog_section():
    init_text = INIT.replace('0.4.0', '0.5.0rc1')
    assert release.check('v0.5.0rc1', init_text, CHANGELOG) == []
