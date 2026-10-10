# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Support Pairing Mode for Keycard version 3.2
- Store NDEF data up to 512 bytes in chunks (applet 3.2+) and read it in segments (applet 4.0+)
- `KeyCard.secure_channel_version`, chosen from the applet version
- Applet 4.x support: Secure Channel V2 with Identity Certificate verification against trusted Keycard CAs (`KeyCard(ca_public_keys=..., trusted_identity_keys=...)`, official CA by default)
- 4.x SELECT fields in `ApplicationInfo`: status, PIN retries, LEE mode and Identity Certificate
- `init` accepts PIN/PUK retry limits and an Alternate PIN
- Opt-in hardware tests (`KEYCARD_READER`, `KEYCARD_DESTRUCTIVE`) and `tools/load_test_identity.py`

### Changed

- TLV parsing and encoding use the `ber-tlv` package
- AES, secp256k1 ECDH and ECDSA verification use the `cryptography` package; `pyaes` is no longer a dependency
- The secure channel is behind an interface in `keycard.secure_channel`; `SecureChannel` is now `SecureChannelV1`
- `pair`, `unpair` and `mutually_authenticate` raise `InvalidStateError` on cards that don't use Secure Channel V1
- `open_secure_channel()` takes no arguments: 3.x cards use the stored `pairing` and always run MUTUALLY AUTHENTICATE; 4.x cards check the trusted Keycard CAs
- `pair()` stores and returns a `Pairing(slot, key)` named tuple; `unpair()` clears it
- `init()` takes the pairing secret as optional: required on 3.x, rejected on 4.x
- `commands.open_secure_channel` and `commands.init` handle both secure channel versions
- `ident()` returns the CA public key in compressed form
- `select()` and `factory_reset()` reset the secure channel and PIN state

### Fixed

- `ident()` recovered the CA key from the wrong digest
- Older versions not supported. Python 3.10+ now supported

## [0.3.0] - 2025-08-24

### Changed

- Open Secure Channel also mutually authenticates unless specified otherwise.
- SignatureResult object returned by sign methods
- Identity returns public key.

## [0.2.0] - 2025-08-06

### Added

- LOAD KEY command
- SET PINLESS PATH command
- GENERATE MNEMONIC command
- DERIVE KEY command

## [0.1.0] - 2025-08-05

### Added

- INIT command
- IDENT command
- OPEN SECURE CHANNEL command
- MUTUALLY AUTHENTICATE command
- PAIR command
- UNPAIR command
- GET STATUS command
- VERIFY PIN command
- CHANGE PIN command
- UNBLOCK PIN command
- REMOVE KEY command
- GENERATE KEY command
- SIGN command
- EXPORT KEY command
- GET_DATA command
- STORE DATA command
- FACTORY RESET command


[unreleased]: https://github.com/olivierlacan/keep-a-changelog/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/olivierlacan/keep-a-changelog/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/olivierlacan/keep-a-changelog/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/mmlado/keycard-py/releases/tag/v0.1.0