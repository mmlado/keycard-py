# KeyCard Python SDK

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) [![Python](https://img.shields.io/badge/python-3.13.3-blue.svg)](https://www.python.org/downloads/) [![codecov](https://codecov.io/gh/mmlado/keycard-py/branch/main/graph/badge.svg)](https://codecov.io/gh/mmlado/keycard-py) ![stars](https://img.shields.io/github/stars/mmlado/keycard-py.svg?style=social) ![lastcommit](https://img.shields.io/github/last-commit/mmlado/keycard-py.svg) ![numcontributors](https://img.shields.io/github/contributors-anon/mmlado/keycard-py.svg) 
A minimal, clean, fully native Python SDK for communicating with [Keycard](https://keycard.tech) smart cards.

This SDK is under active development.  
APDU commands are being implemented one by one.

## Supported Commands

- [x] SELECT
- [x] INIT
- [x] IDENT
- [x] OPEN SECURE CHANNEL
- [x] MUTUALLY AUTHENTICATE
- [x] PAIR
- [x] UNPAIR
- [x] GET STATUS
- [x] VERIFY PIN
- [ ] CHANGE PIN
- [ ] UNBLOCK PIN
- [ ] LOAD KEY
- [ ] DERIVE KEY
- [ ] GENERATE MNEMONIC
- [ ] REMOVE KEY
- [ ] GENERATE KEY
- [ ] SIGN
- [ ] SET PINLESS PATH
- [ ] EXPORT KEY
- [ ] STORE DATA
- [ ] KEY DATA

## Goals

- Fully native Python implementation
- Clean API surface
- Easy to integrate
- Clear separation between transport, protocol, parsing, and crypto
- Fully tested, deterministic behavior
- Focused on correctness, clarity, and maintainability

## Installation

```bash
git clone https://github.com/mmlado/keycard-py.git
cd keycard-py
python -m venv venv
source venv/bin/activate
pip install -e .
pytest
```

## License

MIT

## Contributions

Contributions are welcome as this SDK grows.