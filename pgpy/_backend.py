""" _backend.py
Crypto backend detection and unified wrapper functions.

PGPy supports two crypto backends:
  1. python-cryptography (preferred)
  2. pycryptodomex (fallback)

Additional fallbacks:
  - ecdsa library (for curves not supported by the primary backend)
  - embit library (optional, for secp256k1 optimization)
"""
import hashlib

__all__ = tuple()

# --- Backend detection ---

_has_cryptography = False
_has_pycryptodomex = False

try:
    import cryptography  # noqa: F401
    _has_cryptography = True
except ImportError:
    pass

try:
    import Cryptodome  # noqa: F401
    _has_pycryptodomex = True
except ImportError:
    pass

if not _has_cryptography and not _has_pycryptodomex:
    raise ImportError(
        "PGPy requires either 'cryptography' or 'pycryptodomex' package. "
        "Install one with: pip install cryptography  OR  pip install pycryptodomex"
    )

# python-cryptography is preferred when available
BACKEND = 'cryptography' if _has_cryptography else 'pycryptodomex'


# --- Hash module wrapper ---

# Map hash names to hashlib names
_HASHLIB_NAMES = {
    'MD5': 'md5',
    'SHA1': 'sha1',
    'SHA224': 'sha224',
    'SHA256': 'sha256',
    'SHA384': 'sha384',
    'SHA512': 'sha512',
    'RIPEMD160': 'ripemd160',
}


class _HashModule(object):
    """Wrapper providing a unified interface for hash algorithm modules.

    For pycryptodomex backend, .new() returns Cryptodome hash objects.
    For python-cryptography backend, .new() returns hashlib hash objects.
    """
    def __init__(self, name, digest_size, pcd_module=None):
        self.name = name
        self.digest_size = digest_size
        self._pcd_module = pcd_module

    def new(self, data=None):
        if BACKEND == 'pycryptodomex' and self._pcd_module is not None:
            if data is not None:
                return self._pcd_module.new(data)
            return self._pcd_module.new()
        else:
            hname = _HASHLIB_NAMES.get(self.name, self.name.lower())
            h = hashlib.new(hname)
            if data is not None:
                h.update(data)
            return h


def _build_hash_modules():
    """Build the hash module registry."""
    modules = {}
    if _has_pycryptodomex:
        from Cryptodome.Hash import MD5, SHA1, SHA224, SHA256, SHA384, SHA512, RIPEMD160
        pcd = {
            'MD5': MD5, 'SHA1': SHA1, 'SHA224': SHA224, 'SHA256': SHA256,
            'SHA384': SHA384, 'SHA512': SHA512, 'RIPEMD160': RIPEMD160,
        }
    else:
        pcd = {}

    for name, hlib_name in _HASHLIB_NAMES.items():
        try:
            ds = hashlib.new(hlib_name).digest_size
        except ValueError:
            continue
        modules[name] = _HashModule(name, ds, pcd.get(name))

    return modules


_HASH_MODULES = _build_hash_modules()


def get_hash_algo(name):
    """Get a hash module wrapper by name.

    Returns a _HashModule with .new(data), .digest_size, .name.
    """
    if name in _HASH_MODULES:
        return _HASH_MODULES[name]
    raise ValueError("Unsupported hash algorithm: {}".format(name))


def get_hash_obj(name, data=None):
    """Create a new hash object by algorithm name."""
    mod = get_hash_algo(name)
    return mod.new(data)


# --- python-cryptography hash helper ---

def _get_crypto_hash(name):
    """Get a cryptography hashes instance from algorithm name."""
    from cryptography.hazmat.primitives import hashes
    _map = {
        'MD5': hashes.MD5(),
        'SHA1': hashes.SHA1(),
        'SHA224': hashes.SHA224(),
        'SHA256': hashes.SHA256(),
        'SHA384': hashes.SHA384(),
        'SHA512': hashes.SHA512(),
    }
    if name in _map:
        return _map[name]
    raise ValueError("Unsupported hash for cryptography backend: {}".format(name))


# --- python-cryptography curve helper ---

def _get_crypto_curve(curve_pcd_name):
    """Get a cryptography ec curve instance from curve name."""
    from cryptography.hazmat.primitives.asymmetric import ec
    _map = {
        'P-256': ec.SECP256R1(),
        'P-384': ec.SECP384R1(),
        'P-521': ec.SECP521R1(),
        'secp256k1': ec.SECP256K1(),
        'brainpoolP256r1': ec.BrainpoolP256R1(),
        'brainpoolP384r1': ec.BrainpoolP384R1(),
        'brainpoolP512r1': ec.BrainpoolP512R1(),
    }
    if curve_pcd_name in _map:
        return _map[curve_pcd_name]
    raise ValueError("Unsupported curve: {}".format(curve_pcd_name))


# --- Symmetric cipher wrappers ---

class _CryptographyCFBCipher(object):
    """Wraps python-cryptography CFB cipher to match pycryptodomex API."""
    def __init__(self, algorithm, iv):
        from cryptography.hazmat.primitives.ciphers import Cipher, modes
        self._cipher = Cipher(algorithm, modes.CFB(iv))

    def encrypt(self, data):
        enc = self._cipher.encryptor()
        return enc.update(data) + enc.finalize()

    def decrypt(self, data):
        dec = self._cipher.decryptor()
        return dec.update(data) + dec.finalize()


class _CryptographyAESKW(object):
    """Wraps python-cryptography AES Key Wrap to match pycryptodomex AES.MODE_KW API."""
    def __init__(self, key):
        self._key = key

    def seal(self, data):
        from cryptography.hazmat.primitives.keywrap import aes_key_wrap
        return aes_key_wrap(self._key, data)

    def unseal(self, data):
        from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
        return aes_key_unwrap(self._key, data)


class _CipherModuleWrapper(object):
    """Wraps a python-cryptography cipher algorithm to match pycryptodomex cipher module API.

    Provides .new(key, mode, iv=, segment_size=) and MODE_CFB constant.
    """
    MODE_CFB = 'cfb'

    def __init__(self, algo_class, block_size_bytes):
        self._algo_class = algo_class
        self.block_size = block_size_bytes

    def new(self, key, mode, iv=None, segment_size=None):
        if mode == self.MODE_CFB:
            return _CryptographyCFBCipher(self._algo_class(key), iv)
        raise ValueError("Unsupported mode: {}".format(mode))


class _AESModuleWrapper(_CipherModuleWrapper):
    """AES with additional KEY_WRAP support."""
    MODE_KW = 'kw'

    def __init__(self):
        from cryptography.hazmat.primitives.ciphers import algorithms
        super().__init__(algorithms.AES, 16)

    def new(self, key, mode, iv=None, segment_size=None):
        if mode == self.MODE_KW:
            return _CryptographyAESKW(key)
        return super().new(key, mode, iv=iv, segment_size=segment_size)


def _build_cipher_modules():
    """Build cipher module wrappers for the active backend."""
    if BACKEND == 'cryptography':
        import warnings
        from cryptography.hazmat.primitives.ciphers import algorithms
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            return {
                'AES': _AESModuleWrapper(),
                'DES3': _CipherModuleWrapper(algorithms.TripleDES, 8),
                'CAST5': _CipherModuleWrapper(algorithms.CAST5, 8),
                'Blowfish': _CipherModuleWrapper(algorithms.Blowfish, 8),
            }
    else:
        from Cryptodome.Cipher import AES, DES3, CAST, Blowfish
        return {
            'AES': AES,
            'DES3': DES3,
            'CAST5': CAST,
            'Blowfish': Blowfish,
        }


_CIPHER_MODULES = _build_cipher_modules()


def get_cipher_module(name):
    """Get a cipher module by name."""
    if name in _CIPHER_MODULES:
        return _CIPHER_MODULES[name]
    raise ValueError("Unsupported cipher: {}".format(name))


# --- PKCS7 padding ---

def pkcs7_pad(data, block_size, style='pkcs7'):
    """PKCS7 pad data to block_size (in bytes)."""
    if BACKEND == 'cryptography':
        from cryptography.hazmat.primitives.padding import PKCS7
        padder = PKCS7(block_size * 8).padder()
        return padder.update(data) + padder.finalize()
    else:
        from Cryptodome.Util.Padding import pad
        return pad(data, block_size, style=style)


def pkcs7_unpad(data, block_size, style='pkcs7'):
    """PKCS7 unpad data."""
    if BACKEND == 'cryptography':
        from cryptography.hazmat.primitives.padding import PKCS7
        unpadder = PKCS7(block_size * 8).unpadder()
        return unpadder.update(data) + unpadder.finalize()
    else:
        from Cryptodome.Util.Padding import unpad
        return unpad(data, block_size, style=style)


# --- RSA PKCS1v1.5 cipher (for key transport in packets.py) ---

class _PKCS1v15CipherWrapper(object):
    """Unified wrapper for RSA PKCS1v1.5 encrypt/decrypt."""
    def __init__(self, key):
        self._key = key

    def encrypt(self, data):
        if BACKEND == 'cryptography':
            from cryptography.hazmat.primitives.asymmetric import padding
            return self._key.encrypt(data, padding.PKCS1v15())
        else:
            from Cryptodome.Cipher import PKCS1_v1_5
            return PKCS1_v1_5.new(self._key).encrypt(data)

    def decrypt(self, data, sentinel):
        if BACKEND == 'cryptography':
            from cryptography.hazmat.primitives.asymmetric import padding
            try:
                return self._key.decrypt(data, padding.PKCS1v15())
            except Exception:
                return sentinel
        else:
            from Cryptodome.Cipher import PKCS1_v1_5
            return PKCS1_v1_5.new(self._key).decrypt(data, sentinel)


def pkcs1v15_cipher(key):
    """Create a PKCS1v1.5 cipher for RSA key transport."""
    return _PKCS1v15CipherWrapper(key)


# --- Concat KDF ---

def concat_kdf(hash_name, shared_secret, key_length, other_info):
    """Implementation of Concat KDF (NIST SP 800-56A section 5.8.1).

    Uses python-cryptography's ConcatKDFHash when available, falls back to hashlib.
    """
    if BACKEND == 'cryptography':
        from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
        ckdf = ConcatKDFHash(
            algorithm=_get_crypto_hash(hash_name.upper()),
            length=key_length,
            otherinfo=other_info,
        )
        return ckdf.derive(shared_secret)
    else:
        import struct
        hasher = hashlib.new(hash_name)
        hash_len = hasher.digest_size
        reps = (key_length + hash_len - 1) // hash_len

        derived = b''
        for counter in range(1, reps + 1):
            h = hashlib.new(hash_name)
            h.update(struct.pack('>I', counter))
            h.update(shared_secret)
            h.update(other_info)
            derived += h.digest()

        return derived[:key_length]


# --- DER helpers for Ed25519/X25519 ---

# DER AlgorithmIdentifier for Ed25519 (OID 1.3.101.112)
ED25519_ALG_ID = bytes([0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70])
# DER AlgorithmIdentifier for X25519 (OID 1.3.101.110)
X25519_ALG_ID = bytes([0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e])


def raw_pub_to_der(raw_pub, alg_id):
    """Wrap raw public key bytes into SubjectPublicKeyInfo DER format."""
    bit_string = bytes([0x03, len(raw_pub) + 1, 0x00]) + raw_pub
    return bytes([0x30, len(alg_id) + len(bit_string)]) + alg_id + bit_string
