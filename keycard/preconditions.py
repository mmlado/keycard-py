from functools import wraps
from .exceptions import InvalidStateError


def make_precondition(attribute_name, display_name=None):
    def decorator(func):
        @wraps(func)
        def wrapper(card, *args, **kwargs):
            if not getattr(card, attribute_name, False):
                readable = (
                    display_name or
                    attribute_name.replace('_', ' ').title()
                )
                raise InvalidStateError(f'{readable} must be satisfied.')
            return func(card, *args, **kwargs)
        return wrapper
    return decorator


require_selected = make_precondition(
    'is_selected',
    'Card Selection'
)
require_initialized = make_precondition(
    'is_initialized',
    'Card Initialization'
)
require_secure_channel = make_precondition(
    'is_secure_channel_open',
    'Secure Channel'
)
require_pin_verified = make_precondition(
    'is_pin_verified',
    'PIN verification'
)
