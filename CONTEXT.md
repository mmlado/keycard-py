# keycard-py

Python client library for the Keycard smart card applet, covering applet versions 3.x and 4.x through a single card object.

## Language

### Card identity

**Identity Certificate**:
The 98-byte certificate, issued at provisioning, that binds a card's Identity Key to a Keycard CA.
_Avoid_: factory certificate, ident cert, card cert

**Identity Key**:
The card's own key pair, certified by its Identity Certificate, which proves the card is genuine when a secure channel is opened.
_Avoid_: ident key, authentikey

**Keycard CA**:
The key that signs Identity Certificates; cards in the field carry certificates from the official one.
_Avoid_: root key, issuer

**Test CA**:
The publicly known Keycard CA used by upstream tests and tools to provision development cards; it proves nothing about genuineness.
_Avoid_: dev CA, fake CA

**Trusted Identity Key**:
A specific card's Identity Key that the client accepts even when its certificate is not signed by a trusted Keycard CA.
_Avoid_: whitelisted card key

### Secure channel

**Secure Channel V1**:
The encrypted session used by applet 3.x, which requires a prior Pairing.
_Avoid_: old channel, SC1

**Secure Channel V2**:
The encrypted session used by applet 4.x; pairing-less, and the card proves its identity with its Identity Key.
_Avoid_: new channel, CCM channel

**Pairing**:
A long-lived shared secret between one client and one 3.x card, stored in one of the card's pairing slots. Does not exist on 4.x.

### Credentials

**Alternate PIN**:
An optional second PIN set at initialization; verifying it instead of the main PIN unlocks a different key hierarchy derived from the same seed.
_Avoid_: duress PIN, alt PIN, decoy PIN

### Keys

**Current Key**:
On 3.x, the derived key the card keeps selected between commands for signing and export. Does not exist on 4.x, where every operation names its derivation path.
_Avoid_: active key
