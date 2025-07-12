from .. import constants
from ..exceptions import APDUError


def verify_pin(transport, session, pin: str) -> bool:
    if session is None:
        raise ValueError(
            "Secure session must be established before verifying PIN.")

    cla, ins, p1, p2, data = session.wrap_apdu(
        cla=constants.CLA_PROPRIETARY,
        ins=constants.INS_VERIFY_PIN,
        p1=0x00,
        p2=0x00,
        data=pin
    )

    response = transport.send_apdu(bytes([cla, ins, p1, p2, len(data)]) + data)

    if response.status_word == 0x9000:
        return True

    if (response.status_word & 0xFFF0) == 0x63C0:
        attempts = response.status_word & 0x000F
        if attempts == 0:
            raise RuntimeError("PIN is blocked")
        return False

    raise APDUError(response.status_word)
