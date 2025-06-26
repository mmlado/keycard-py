# Applet AID
KEYCARD_AID: bytes = bytes.fromhex('A000000804000101')

CLAISO7816: int = 0x00
CLA_PROPRIETARY: int = 0x80

# APDU instructions
INS_SELECT: int = 0xA4
INS_INIT: int = 0xFE

# Status words
SW_SUCCESS: int = 0x9000
