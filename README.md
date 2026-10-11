[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) [![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/) [![codecov](https://codecov.io/gh/mmlado/keycard-py/branch/main/graph/badge.svg)](https://codecov.io/gh/mmlado/keycard-py) [![PyPI version](https://img.shields.io/pypi/v/keycard.svg)](https://pypi.org/project/keycard/) [![PyPI Downloads](https://static.pepy.tech/personalized-badge/keycard?period=total&units=INTERNATIONAL_SYSTEM&left_color=BLACK&right_color=GREEN&left_text=downloads)](https://pepy.tech/projects/keycard) [![Build status](https://github.com/mmlado/keycard-py/actions/workflows/test.yml/badge.svg)](https://github.com/mmlado/keycard-py/actions/workflows/test.yml) [![Documentation](https://img.shields.io/badge/docs-gh--pages-blue.svg)](https://mmlado.github.io/keycard-py/) ![stars](https://img.shields.io/github/stars/mmlado/keycard-py.svg?style=social) ![lastcommit](https://img.shields.io/github/last-commit/mmlado/keycard-py.svg) ![numcontributors](https://img.shields.io/github/contributors-anon/mmlado/keycard-py.svg)

A minimal, clean, fully native Python SDK for communicating with [Keycard](https://keycard.tech) smart cards. One `KeyCard` object works with applet 3.x and 4.x; it picks the matching secure channel when the card is selected.

[Documentation](https://deepwiki.com/mmlado/keycard-py) · [API reference](https://mmlado.github.io/keycard-py/)

## Requirements

- Python 3.10 or higher; tested on 3.10 to 3.14
- A PC/SC smart card reader. On Linux, run the `pcscd` service; building `pyscard` from source also needs `libpcsclite-dev`.

## Installation

```bash
pip install keycard
```

The package is published on PyPI as `keycard` (repo name is keycard-py).

### From source

```bash
git clone https://github.com/mmlado/keycard-py.git
cd keycard-py
python -m venv venv
source venv/bin/activate
pip install -e .
pytest
```

## Usage

### Connect and select

```python
from keycard import KeyCard

with KeyCard() as card:
    card.select()
    print(card.version)         # e.g. (4, 0)
    print(card.is_initialized)
```

`KeyCard()` uses the first PC/SC reader. For another reader, connect a `Transport` yourself:

```python
from keycard import KeyCard
from keycard.transport import Transport

transport = Transport()
transport.connect(1)
card = KeyCard(transport)
```

The examples below continue with a selected `card`.

### Open a secure channel: applet 4.x

When the secure channel opens, the card proves it is genuine with its Identity Certificate, which must be signed by a trusted Keycard CA. The official CA is trusted by default; any other card raises `UntrustedCardError`.

```python
PIN = '123456'
PUK = '987654321098'

if not card.is_initialized:
    card.init(PIN, PUK)  # opens the secure channel itself
else:
    card.open_secure_channel()

card.verify_pin(PIN)     # False on a wrong PIN
```

`init` also takes `pin_retries`, `puk_retries` and an `alt_pin`. Without `alt_pin`, the card uses the first 6 digits of the PUK as the Alternate PIN. PIN verification tries the Alternate PIN first, so if the PUK starts with the PIN, `verify_pin(PIN)` unlocks the alternate keys instead of the main ones.

Development cards carry a certificate from the Test CA (see `tools/load_test_identity.py`). Trust it only during development, since anyone can sign with it:

```python
from keycard import KeyCard, constants

card = KeyCard(ca_public_keys=[
    constants.OFFICIAL_CA_PUBLIC_KEY,
    constants.TEST_CA_PUBLIC_KEY,
])
```

### Open a secure channel: applet 3.x

3.x cards need a pairing, a shared key stored in one of the card's pairing slots. Pair once with the pairing secret set at `init`, and keep the result for later sessions:

```python
PAIRING_SECRET = 'my pairing secret'

if not card.is_initialized:
    card.init(PIN, PUK, PAIRING_SECRET)
    card.select()

pairing = card.pair(PAIRING_SECRET)  # Pairing(slot, key): store it
card.open_secure_channel()
card.verify_pin(PIN)
```

In a later session, reuse the stored pairing instead of pairing again:

```python
from keycard.pairing import Pairing

card.pairing = Pairing(slot, key)
card.open_secure_channel()
```

The card has a limited number of pairing slots; `card.unpair(slot)` frees one.

### Keys

Generate a key on the card, or load one from a BIP-39 mnemonic. The passphrase goes into the seed, so the card never sees it:

```python
from mnemonic import Mnemonic  # pip install mnemonic
from keycard.constants import LoadKeyType

card.generate_key()

seed = Mnemonic.to_seed('<your twelve or twenty-four words>', passphrase='')
card.load_key(LoadKeyType.BIP39_SEED, bip39_seed=seed)
```

The card can also generate the mnemonic, returning word indexes:

```python
indexes = card.generate_mnemonic()
words = ' '.join(Mnemonic('english').wordlist[i] for i in indexes)
```

Export a public key:

```python
from keycard.constants import DerivationOption

exported = card.export_key(
    DerivationOption.DERIVE, public_only=True, keypath="m/44'/60'/0'/0/0")
exported.public_key  # 65-byte uncompressed point
```

### Sign

```python
from hashlib import sha256

digest = sha256(b'message').digest()

result = card.sign(digest)  # the current key on 3.x, the master key on 4.x
result = card.sign_with_path(digest, "m/44'/60'/0'/0/0")

result.signature     # r || s, 64 bytes
result.signature_der
result.recovery_id
result.public_key
```

BIP-340 Schnorr signatures (applet 4.x) take an optional 32-byte tweak that the card adds to the private key, such as a BIP-341 Taproot tweak. `result.public_key` is the untweaked key:

```python
from keycard.constants import SigningAlgorithm

result = card.sign_with_path(
    digest,
    "m/86'/0'/0'/0/0",
    algorithm=SigningAlgorithm.SCHNORR_BIP340,
    tweak=tweak,
)
```

### Applet 4.x features

```python
card.get_challenge(32)  # random bytes from the card

# BIP-85 entropy, here for a 12-word English mnemonic
card.export_bip85("m/83696968'/39'/0'/12'/0'", 16)

# Raw ECDH secret; run it through your protocol's KDF
card.ecdh(peer_public_key, "m/44'/1237'/0'/0/0")
```

ECDH works only under the NIP-44 (`m/44'/1237'`) and EIP-1581 (`m/43'/60'/1581'`) paths, at least 5 levels deep.

Loading a seed in LEE mode also derives the [LEE](https://github.com/logos-blockchain/logos-execution-zone) keys:

```python
card.load_key(LoadKeyType.LEE_SEED, bip39_seed=seed)
keys = card.export_lee("m/0'")  # ask, nsk, vsk_d, vsk_z
```

### Differences between 3.x and 4.x

| | 3.x | 4.x |
| --- | --- | --- |
| Secure channel | Pairing, Secure Channel V1 | Secure Channel V2; the card is checked against trusted Keycard CAs |
| Current key, `derive_key`, PIN-less signing | Yes | No |
| Schnorr, LEE, BIP-85, ECDH, GET CHALLENGE | No | Yes |

Using a 4.x feature on a 3.x card raises `APDUError` with the card's status word. The pairing calls raise `InvalidStateError` on 4.x.

### Errors

All errors derive from `keycard.exceptions.KeyCardError`:

- `APDUError`: the card returned a failure; the status word is in `.sw`
- `InvalidStateError`: a precondition isn't met, such as no secure channel or PIN not verified
- `UntrustedCardError`: the card's Identity Certificate isn't signed by a trusted CA
- `InvalidResponseError`: the card's response is malformed
- `TransportError`: no reader found

### Example script

[`example/example.py`](example/example.py) walks through the commands on a 3.x or 4.x card. It factory-resets the card first, so use a test card. It needs the `mnemonic` package.

## Development

```bash
pip install -e '.[dev]'
pytest
flake8 keycard tests
mypy keycard
```

Hardware tests run against a real card only when asked. `KEYCARD_READER` is the reader index; tests that factory-reset the card also need `KEYCARD_DESTRUCTIVE=1`:

```bash
KEYCARD_READER=0 pytest tests/hardware
KEYCARD_READER=0 KEYCARD_DESTRUCTIVE=1 pytest tests/hardware
```

4.x development cards need a Test CA certificate, provisioned with `python tools/load_test_identity.py`.

## License

MIT

## Contributions

Contributions are welcome as this SDK grows.
