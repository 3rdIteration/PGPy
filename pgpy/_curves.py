""" _curves.py
define elliptic curve descriptors for use in PGPy
"""

from ._backend import BACKEND, _has_cryptography, _has_pycryptodomex

__all__ = tuple()


def _get_supported_curves():
    """Return the set of curve names supported by the active backend."""
    if hasattr(_get_supported_curves, '_curves'):
        return _get_supported_curves._curves

    supported = set()

    if BACKEND == 'cryptography':
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519, x25519

        # python-cryptography supports all standard curves
        crypto_curves = {
            'P-256': ec.SECP256R1,
            'P-384': ec.SECP384R1,
            'P-521': ec.SECP521R1,
            'secp256k1': ec.SECP256K1,
            'brainpoolP256r1': ec.BrainpoolP256R1,
            'brainpoolP384r1': ec.BrainpoolP384R1,
            'brainpoolP512r1': ec.BrainpoolP512R1,
        }
        for curve_name, curve_cls in crypto_curves.items():
            try:
                ec.generate_private_key(curve_cls())
                supported.add(curve_name)
            except Exception:
                pass

        # Ed25519 and X25519
        try:
            ed25519.Ed25519PrivateKey.generate()
            supported.add('Ed25519')
        except Exception:
            pass

        try:
            x25519.X25519PrivateKey.generate()
            supported.add('Curve25519')
        except Exception:
            pass

    elif _has_pycryptodomex:
        from Cryptodome.PublicKey import ECC

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

    # Also add curves supported by the ecdsa library as fallback
    try:
        from ecdsa import SECP256k1 as _s256k1, BRAINPOOLP256r1, BRAINPOOLP384r1, BRAINPOOLP512r1  # noqa: F811,F401
        supported.add('secp256k1')
        supported.add('brainpoolP256r1')
        supported.add('brainpoolP384r1')
        supported.add('brainpoolP512r1')
    except ImportError:
        pass

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
