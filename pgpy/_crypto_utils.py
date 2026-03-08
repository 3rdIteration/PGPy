""" _crypto_utils.py
Utility functions for pycryptodome crypto operations
"""
import hashlib
import struct

from Crypto.Hash import MD5, SHA1, SHA224, SHA256, SHA384, SHA512, RIPEMD160

__all__ = ['get_hash_algo', 'get_hash_obj', 'concat_kdf',
           'ED25519_ALG_ID', 'X25519_ALG_ID', 'raw_pub_to_der']

# Map hash algorithm names (as used in PGPy) to pycryptodome hash modules
_HASH_MODULES = {
    'MD5': MD5,
    'SHA1': SHA1,
    'SHA224': SHA224,
    'SHA256': SHA256,
    'SHA384': SHA384,
    'SHA512': SHA512,
    'RIPEMD160': RIPEMD160,
}


def get_hash_algo(name):
    """Get the pycryptodome hash module by name.

    Returns the module (e.g., Crypto.Hash.SHA256) which can be used as:
        hash_obj = get_hash_algo('SHA256').new(data)
    """
    if name in _HASH_MODULES:
        return _HASH_MODULES[name]
    raise ValueError("Unsupported hash algorithm: {}".format(name))


def get_hash_obj(name, data=None):
    """Create a new pycryptodome hash object by algorithm name.

    Returns a hash object (e.g., SHA256.new(data)).
    """
    mod = get_hash_algo(name)
    if data is not None:
        return mod.new(data)
    return mod.new()


def concat_kdf(hash_name, shared_secret, key_length, other_info):
    """Implementation of Concat KDF (NIST SP 800-56A section 5.8.1).

    This replaces cryptography.hazmat.primitives.kdf.concatkdf.ConcatKDFHash.
    """
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


# DER AlgorithmIdentifier for Ed25519 (OID 1.3.101.112)
ED25519_ALG_ID = bytes([0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70])
# DER AlgorithmIdentifier for X25519 (OID 1.3.101.110)
X25519_ALG_ID = bytes([0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e])


def raw_pub_to_der(raw_pub, alg_id):
    """Wrap raw public key bytes into SubjectPublicKeyInfo DER format."""
    bit_string = bytes([0x03, len(raw_pub) + 1, 0x00]) + raw_pub
    return bytes([0x30, len(alg_id) + len(bit_string)]) + alg_id + bit_string
