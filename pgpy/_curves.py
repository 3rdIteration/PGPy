""" _curves.py
define elliptic curve descriptors for use in PGPy
"""

from Crypto.PublicKey import ECC

__all__ = tuple()

# pycryptodome curve name mapping
_pcd_curve_names = {name for name in ('P-256', 'P-384', 'P-521', 'Ed25519', 'Curve25519')}


def _get_supported_curves():
    """Return the set of curve names supported by pycryptodome."""
    if hasattr(_get_supported_curves, '_curves'):
        return _get_supported_curves._curves

    supported = set()
    # Test each curve pycryptodome might support
    test_curves = [
        'P-256', 'P-384', 'P-521', 'Ed25519', 'Curve25519',
        'brainpoolP256r1', 'brainpoolP384r1', 'brainpoolP512r1',
        'secp256k1',
    ]
    for curve_name in test_curves:
        try:
            ECC.generate(curve=curve_name)
            supported.add(curve_name)
        except (ValueError, Exception):
            pass

    # Add aliases used by PGPy curve descriptors
    if 'P-256' in supported:
        supported.add('SECP256R1')
    if 'P-384' in supported:
        supported.add('SECP384R1')
    if 'P-521' in supported:
        supported.add('SECP521R1')
    if 'Curve25519' in supported:
        supported.add('X25519')
    if 'Ed25519' in supported:
        supported.add('ed25519')

    _get_supported_curves._curves = supported
    return supported


class CurveDescriptor:
    """Base class for elliptic curve descriptors."""
    name = None
    key_size = None

    def __init__(self):
        pass

    def __call__(self):
        return self


class SECP256R1(CurveDescriptor):
    name = 'SECP256R1'
    key_size = 256
    pcd_name = 'P-256'


class SECP384R1(CurveDescriptor):
    name = 'SECP384R1'
    key_size = 384
    pcd_name = 'P-384'


class SECP521R1(CurveDescriptor):
    name = 'SECP521R1'
    key_size = 521
    pcd_name = 'P-521'


class SECP256K1(CurveDescriptor):
    name = 'secp256k1'
    key_size = 256
    pcd_name = 'secp256k1'


class BrainpoolP256R1(CurveDescriptor):
    name = 'brainpoolP256r1'
    key_size = 256
    pcd_name = 'brainpoolP256r1'


class BrainpoolP384R1(CurveDescriptor):
    name = 'brainpoolP384r1'
    key_size = 384
    pcd_name = 'brainpoolP384r1'


class BrainpoolP512R1(CurveDescriptor):
    name = 'brainpoolP512r1'
    key_size = 512
    pcd_name = 'brainpoolP512r1'


class X25519(CurveDescriptor):
    name = 'X25519'
    key_size = 256
    pcd_name = 'Curve25519'


class Ed25519(CurveDescriptor):
    name = 'ed25519'
    key_size = 256
    pcd_name = 'Ed25519'


# Mapping from curve name to curve descriptor (analogous to ec._CURVE_TYPES)
_CURVE_TYPES = {}
for _curve_cls in [SECP256R1, SECP384R1, SECP521R1, SECP256K1,
                   BrainpoolP256R1, BrainpoolP384R1, BrainpoolP512R1,
                   X25519, Ed25519]:
    _CURVE_TYPES[_curve_cls.name] = _curve_cls
