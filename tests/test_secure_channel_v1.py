import pytest

from keycard.apdu import APDUResponse
from keycard.crypto.aes import aes_cbc_decrypt, aes_cbc_encrypt
from keycard.exceptions import APDUError
from keycard.secure_channel import (
    SecureChannelV1,
    SecureChannelVersion,
    channel_version,
)


@pytest.fixture
def session_params():
    return {
        "shared_secret": bytes(32),
        "pairing_key": bytes(32),
        "salt": bytes(16),
        "seed_iv": bytes(16),
    }


def test_open_sets_authenticated_and_keys(session_params):
    session = SecureChannelV1.from_handshake(**session_params)
    assert session.authenticated is True
    assert isinstance(session.enc_key, bytes) and len(session.enc_key) == 32
    assert isinstance(session.mac_key, bytes) and len(session.mac_key) == 32
    assert session.iv == session_params['seed_iv']


def test_wrap_apdu_authenticated(session_params):
    session = SecureChannelV1.from_handshake(**session_params)
    wrapped = session.wrap_apdu(
        0x80,
        0xCA,
        0x00,
        0x00,
        b'testdata'
    )
    assert isinstance(wrapped, bytes)
    assert len(wrapped) > 16  # IV + encrypted data


@pytest.mark.parametrize("ins,should_raise", [
    (0x11, False),
    (0xCA, True),
])
def test_wrap_apdu_auth_check(ins, should_raise):
    session = SecureChannelV1(
        b'\x01' * 32,
        b'\x02' * 32,
        bytes(16),
        authenticated=False
    )
    if should_raise:
        with pytest.raises(ValueError, match="not authenticated"):
            session.wrap_apdu(0x80, ins, 0x00, 0x00, b'test')
    else:
        session.wrap_apdu(0x80, ins, 0x00, 0x00, b'test')


def test_unwrap_response_authenticated_and_mac(monkeypatch, session_params):
    # Patch aes_cbc_encrypt and aes_cbc_decrypt to simulate expected behavior
    session = SecureChannelV1.from_handshake(**session_params)
    plaintext = b"hello world" + b'\x90\x00'  # status word 0x9000

    # Simulate encryption and MAC

    def fake_decrypt(key, iv, data):
        return plaintext

    def fake_encrypt(key, iv, data, padding=True):
        # Return 16 bytes MAC for mac_key, else just return dummy
        if key == session.mac_key:
            return b'Y' * 16
        return b'Z' * (len(data) // 16 * 16)

    monkeypatch.setattr(
        'keycard.secure_channel.v1.aes_cbc_decrypt', fake_decrypt)
    monkeypatch.setattr(
        'keycard.secure_channel.v1.aes_cbc_encrypt', fake_encrypt)

    # Compose response: 16 bytes MAC + encrypted data
    response = APDUResponse(b'Y' * 16 + b'Z' * 16, 0x900)
    out, sw = session.unwrap_response(response)
    assert out == plaintext[:-2]
    assert sw == 0x9000


def test_unwrap_response_256_bytes(session_params):
    session = SecureChannelV1.from_handshake(**session_params)
    payload = bytes(range(223))
    encrypted = aes_cbc_encrypt(
        session.enc_key, session.iv, payload + b'\x90\x00')
    mac = aes_cbc_encrypt(
        session.mac_key, bytes(16), bytes(16) + encrypted, padding=False
    )[-16:]
    response = APDUResponse(mac + encrypted, 0x9000)
    assert len(response.data) == 256

    out, sw = session.unwrap_response(response)

    assert out == payload
    assert sw == 0x9000


def test_unwrap_response_not_authenticated_raises(session_params):
    session = SecureChannelV1.from_handshake(**session_params)
    session.authenticated = False
    response = APDUResponse(bytes(32), 0x900)
    with pytest.raises(ValueError, match="not authenticated"):
        session.unwrap_response(response)


def test_unwrap_response_invalid_length_raises(session_params):
    session = SecureChannelV1.from_handshake(**session_params)
    session.authenticated = True
    response = APDUResponse(bytes(10), 0x900)
    with pytest.raises(ValueError, match="Invalid secure response length"):
        session.unwrap_response(response)


def test_unwrap_response_invalid_mac_raises(monkeypatch, session_params):
    session = SecureChannelV1.from_handshake(**session_params)
    # Patch aes_cbc_encrypt to return a different MAC

    def fake_encrypt(key, iv, data, padding=True):
        return b'X' * 16

    monkeypatch.setattr(
        'keycard.secure_channel.v1.aes_cbc_encrypt',
        fake_encrypt
    )

    response = APDUResponse(b'Y' * 16 + b'Z' * 16, 0x900)

    with pytest.raises(ValueError, match="Invalid MAC"):
        session.unwrap_response(response)


def test_unwrap_response_missing_status_word(monkeypatch, session_params):
    session = SecureChannelV1.from_handshake(**session_params)

    def fake_decrypt(key, iv, data):
        return b'\x01'

    monkeypatch.setattr(
        'keycard.secure_channel.v1.aes_cbc_decrypt',
        fake_decrypt)
    monkeypatch.setattr(
        'keycard.secure_channel.v1.aes_cbc_encrypt',
        lambda *a, **k: b'Y' * 16)

    response = APDUResponse(b'Y' * 16 + b'Z' * 16, 0x9000)

    with pytest.raises(ValueError, match="Missing status word"):
        session.unwrap_response(response)


def _card_response(session, payload, sw):
    encrypted = aes_cbc_encrypt(
        session.enc_key, session.iv, payload + sw.to_bytes(2, 'big'))
    lr = (16 + len(encrypted)) & 0xFF
    mac = aes_cbc_encrypt(
        session.mac_key, bytes(16), bytes([lr]) + bytes(15) + encrypted,
        padding=False
    )[-16:]
    return APDUResponse(mac + encrypted, 0x9000)


def test_version_and_is_open(session_params):
    session = SecureChannelV1.from_handshake(**session_params)
    assert session.version == SecureChannelVersion.V1
    assert session.is_open is True


def test_wrap_builds_full_apdu_the_card_can_verify(session_params):
    session = SecureChannelV1.from_handshake(**session_params)
    iv = session.iv

    apdu = session.wrap(0xCA, 0x01, 0x02, b'payload')

    header, lc, body = apdu[:4], apdu[4], apdu[5:]
    assert header == bytes([0x80, 0xCA, 0x01, 0x02])
    assert lc == len(body)
    mac, encrypted = body[:16], body[16:]
    assert aes_cbc_decrypt(session.enc_key, iv, encrypted) == b'payload'
    expected_mac = aes_cbc_encrypt(
        session.mac_key, bytes(16), apdu[:5] + bytes(11) + encrypted,
        padding=False
    )[-16:]
    assert mac == expected_mac


def test_unwrap_returns_data(session_params):
    session = SecureChannelV1.from_handshake(**session_params)
    response = _card_response(session, b'result', 0x9000)

    assert session.unwrap(response) == b'result'


def test_unwrap_raises_on_inner_status_word(session_params):
    session = SecureChannelV1.from_handshake(**session_params)
    response = _card_response(session, b'', 0x6A84)

    with pytest.raises(APDUError) as excinfo:
        session.unwrap(response)
    assert excinfo.value.sw == 0x6A84


def test_unwrap_raises_on_outer_status_word(session_params):
    session = SecureChannelV1.from_handshake(**session_params)

    with pytest.raises(APDUError) as excinfo:
        session.unwrap(APDUResponse(b'', 0x6982))
    assert excinfo.value.sw == 0x6982


@pytest.mark.parametrize('app_version,expected', [
    ((0, 0), SecureChannelVersion.V1),
    ((3, 2), SecureChannelVersion.V1),
    ((3, 99), SecureChannelVersion.V1),
    ((4, 0), SecureChannelVersion.V2),
    ((5, 1), SecureChannelVersion.V2),
])
def test_channel_version(app_version, expected):
    assert channel_version(app_version) == expected
