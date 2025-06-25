class KeyCardError(Exception):
    """Base exception for Keycard SDK"""
    pass

class TLVParseError(Exception):
    """Exception raised for errors in TLV parsing."""
    pass