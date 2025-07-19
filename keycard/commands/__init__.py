# flake8: noqa: F401

if __debug__:
    # Development mode: dynamically import all public symbols
    import importlib
    import pkgutil

    __all__ = []

    for _, module_name, _ in pkgutil.iter_modules(__path__):
        if module_name == '__init__':
            continue

        module = importlib.import_module(f'.{module_name}', package=__name__)
        for attr in dir(module):
            if not attr.startswith('_'):
                globals()[attr] = getattr(module, attr)
                __all__.append(attr)

else:
    # Production mode: static imports for safety and stability
    from .change_secret import change_secret
    from .factory_reset import factory_reset
    from .generate_key import generate_key
    from .ident import ident
    from .init import init
    from .get_status import get_status
    from .mutually_authenticate import mutually_authenticate
    from .open_secure_channel import open_secure_channel
    from .pair import pair
    from .remove_key import remove_key
    from .select import select
    from .unblock_pin import unblock_pin
    from .unpair import unpair
    from .verify_pin import verify_pin

    __all__ = [
        'change_secret',
        'factory_reset',
        'generate_key',
        'ident',
        'init',
        'get_status',
        'mutually_authenticate',
        'open_secure_channel',
        'pair',
        'remove_key',
        'select',
        'unblock_pin',
        'unpair',
        'verify_pin',
    ]
