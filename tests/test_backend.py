"""Tests for crypto backend abstraction layer.

Tests that crypto operations work correctly regardless of which backend is active.
"""
import pytest
import warnings

import pgpy
from pgpy._backend import BACKEND, _has_cryptography, _has_pycryptodomex
from pgpy.constants import (
    PubKeyAlgorithm, EllipticCurveOID, HashAlgorithm, KeyFlags,
    SymmetricKeyAlgorithm,
)

# Suppress self-sigs / revocation warnings
pytestmark = pytest.mark.filterwarnings("ignore::UserWarning")


class TestBackendDetection:
    """Test that backend detection works correctly."""

    def test_backend_is_valid(self):
        assert BACKEND in ('cryptography', 'pycryptodomex')

    def test_at_least_one_backend(self):
        assert _has_cryptography or _has_pycryptodomex

    def test_cryptography_preferred(self):
        """When both backends are installed, cryptography should be preferred."""
        if _has_cryptography:
            assert BACKEND == 'cryptography'


class TestHashOperations:
    """Test hash operations work with both backends."""

    @pytest.mark.parametrize("hash_name,expected_size", [
        ("MD5", 16),
        ("SHA1", 20),
        ("SHA224", 28),
        ("SHA256", 32),
        ("SHA384", 48),
        ("SHA512", 64),
    ])
    def test_hash_algo(self, hash_name, expected_size):
        from pgpy._backend import get_hash_algo
        h = get_hash_algo(hash_name)
        assert h.name == hash_name
        assert h.digest_size == expected_size
        obj = h.new(b"test data")
        assert len(obj.digest()) == expected_size

    def test_hash_algo_unsupported(self):
        from pgpy._backend import get_hash_algo
        with pytest.raises(ValueError):
            get_hash_algo("NOSUCHHASH")


class TestConcatKDF:
    """Test Concat KDF implementation."""

    def test_concat_kdf_basic(self):
        from pgpy._backend import concat_kdf
        result = concat_kdf('SHA256', b'shared_secret', 32, b'other_info')
        assert len(result) == 32
        assert isinstance(result, bytes)

    def test_concat_kdf_deterministic(self):
        from pgpy._backend import concat_kdf
        r1 = concat_kdf('SHA256', b'secret', 16, b'info')
        r2 = concat_kdf('SHA256', b'secret', 16, b'info')
        assert r1 == r2

    def test_concat_kdf_different_inputs(self):
        from pgpy._backend import concat_kdf
        r1 = concat_kdf('SHA256', b'secret1', 16, b'info')
        r2 = concat_kdf('SHA256', b'secret2', 16, b'info')
        assert r1 != r2


class TestSymmetricCiphers:
    """Test symmetric cipher wrappers."""

    def test_aes_cfb_encrypt_decrypt(self):
        from pgpy._backend import get_cipher_module
        aes = get_cipher_module('AES')
        key = b'\x00' * 16
        iv = b'\x00' * 16
        cipher_enc = aes.new(key, aes.MODE_CFB, iv=iv, segment_size=128)
        ct = cipher_enc.encrypt(b'Hello, World!!! ')
        cipher_dec = aes.new(key, aes.MODE_CFB, iv=iv, segment_size=128)
        pt = cipher_dec.decrypt(ct)
        assert pt == b'Hello, World!!! '

    def test_aes_key_wrap(self):
        from pgpy._backend import get_cipher_module
        aes = get_cipher_module('AES')
        key = b'\x00' * 16
        data = b'\x01' * 16
        kw = aes.new(key, aes.MODE_KW)
        wrapped = kw.seal(data)
        kw2 = aes.new(key, aes.MODE_KW)
        unwrapped = kw2.unseal(wrapped)
        assert unwrapped == data

    def test_des3_cfb(self):
        from pgpy._backend import get_cipher_module
        des3 = get_cipher_module('DES3')
        key = b'\x00' * 24
        iv = b'\x00' * 8
        cipher_enc = des3.new(key, des3.MODE_CFB, iv=iv, segment_size=64)
        ct = cipher_enc.encrypt(b'TestData')
        cipher_dec = des3.new(key, des3.MODE_CFB, iv=iv, segment_size=64)
        pt = cipher_dec.decrypt(ct)
        assert pt == b'TestData'


class TestPKCS7Padding:
    """Test PKCS7 padding operations."""

    def test_pad_unpad(self):
        from pgpy._backend import pkcs7_pad, pkcs7_unpad
        data = b'Hello'
        padded = pkcs7_pad(data, 8)
        assert len(padded) % 8 == 0
        unpadded = pkcs7_unpad(padded, 8)
        assert unpadded == data


class TestRSAOperations:
    """Test RSA key generation, signing, verification, encryption, and decryption."""

    def test_rsa_generate_sign_verify(self):
        key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
        uid = pgpy.PGPUID.new('Test RSA', 'rsa@test.com')
        key.add_uid(uid, hashes=[HashAlgorithm.SHA256],
                    usage={KeyFlags.Sign, KeyFlags.Certify})

        msg = "Hello, RSA on {} backend!".format(BACKEND)
        sig = key.sign(msg)
        assert sig is not None
        assert key.pubkey.verify(msg, sig)

    def test_rsa_encrypt_decrypt(self):
        key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
        uid = pgpy.PGPUID.new('Test RSA Enc', 'rsa-enc@test.com')
        key.add_uid(uid, hashes=[HashAlgorithm.SHA256],
                    usage={KeyFlags.Sign, KeyFlags.Certify,
                           KeyFlags.EncryptCommunications})

        plaintext = "Secret RSA message on {} backend".format(BACKEND)
        msg = pgpy.PGPMessage.new(plaintext)
        encrypted = key.pubkey.encrypt(msg)
        assert encrypted is not None

        decrypted = key.decrypt(encrypted)
        assert decrypted.message == plaintext

    def test_rsa_wrong_message_fails(self):
        key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
        uid = pgpy.PGPUID.new('Test RSA Wrong', 'rsa-wrong@test.com')
        key.add_uid(uid, hashes=[HashAlgorithm.SHA256],
                    usage={KeyFlags.Sign, KeyFlags.Certify})

        sig = key.sign("message A")
        assert not key.pubkey.verify("message B", sig)


class TestDSAOperations:
    """Test DSA key generation, signing, and verification."""

    def test_dsa_generate_sign_verify(self):
        key = pgpy.PGPKey.new(PubKeyAlgorithm.DSA, 2048)
        uid = pgpy.PGPUID.new('Test DSA', 'dsa@test.com')
        key.add_uid(uid, hashes=[HashAlgorithm.SHA256],
                    usage={KeyFlags.Sign, KeyFlags.Certify})

        msg = "Hello, DSA on {} backend!".format(BACKEND)
        sig = key.sign(msg)
        assert sig is not None
        assert key.pubkey.verify(msg, sig)


class TestECDSAOperations:
    """Test ECDSA operations with various curves."""

    NIST_CURVES = [
        pytest.param(EllipticCurveOID.NIST_P256, HashAlgorithm.SHA256, id="P-256"),
        pytest.param(EllipticCurveOID.NIST_P384, HashAlgorithm.SHA384, id="P-384"),
        pytest.param(EllipticCurveOID.NIST_P521, HashAlgorithm.SHA512, id="P-521"),
    ]

    EXTRA_CURVES = [
        pytest.param(EllipticCurveOID.SECP256K1, HashAlgorithm.SHA256, id="secp256k1"),
        pytest.param(EllipticCurveOID.Brainpool_P256, HashAlgorithm.SHA256, id="brainpoolP256r1"),
        pytest.param(EllipticCurveOID.Brainpool_P384, HashAlgorithm.SHA384, id="brainpoolP384r1"),
        pytest.param(EllipticCurveOID.Brainpool_P512, HashAlgorithm.SHA512, id="brainpoolP512r1"),
    ]

    @pytest.mark.parametrize("curve_oid,halg", NIST_CURVES + EXTRA_CURVES)
    def test_ecdsa_sign_verify(self, curve_oid, halg):
        key = pgpy.PGPKey.new(PubKeyAlgorithm.ECDSA, curve_oid)
        uid = pgpy.PGPUID.new('Test ECDSA', 'ecdsa@test.com')
        key.add_uid(uid, hashes=[halg], usage={KeyFlags.Sign, KeyFlags.Certify})

        msg = "Hello, ECDSA {} on {} backend!".format(curve_oid.name, BACKEND)
        sig = key.sign(msg)
        assert sig is not None
        assert key.pubkey.verify(msg, sig)

    @pytest.mark.parametrize("curve_oid,halg", NIST_CURVES + EXTRA_CURVES)
    def test_ecdsa_wrong_message_fails(self, curve_oid, halg):
        key = pgpy.PGPKey.new(PubKeyAlgorithm.ECDSA, curve_oid)
        uid = pgpy.PGPUID.new('Test ECDSA', 'ecdsa@test.com')
        key.add_uid(uid, hashes=[halg], usage={KeyFlags.Sign, KeyFlags.Certify})

        sig = key.sign("message A")
        assert not key.pubkey.verify("message B", sig)


class TestEdDSAOperations:
    """Test EdDSA (Ed25519) operations."""

    def test_eddsa_sign_verify(self):
        key = pgpy.PGPKey.new(PubKeyAlgorithm.EdDSA, EllipticCurveOID.Ed25519)
        uid = pgpy.PGPUID.new('Test EdDSA', 'eddsa@test.com')
        key.add_uid(uid, hashes=[HashAlgorithm.SHA256],
                    usage={KeyFlags.Sign, KeyFlags.Certify})

        msg = "Hello, EdDSA on {} backend!".format(BACKEND)
        sig = key.sign(msg)
        assert sig is not None
        assert key.pubkey.verify(msg, sig)

    def test_eddsa_wrong_message_fails(self):
        key = pgpy.PGPKey.new(PubKeyAlgorithm.EdDSA, EllipticCurveOID.Ed25519)
        uid = pgpy.PGPUID.new('Test EdDSA', 'eddsa@test.com')
        key.add_uid(uid, hashes=[HashAlgorithm.SHA256],
                    usage={KeyFlags.Sign, KeyFlags.Certify})

        sig = key.sign("message A")
        assert not key.pubkey.verify("message B", sig)


class TestECDHOperations:
    """Test ECDH encryption/decryption with various curves."""

    ECDH_CURVES = [
        pytest.param(EllipticCurveOID.Curve25519, HashAlgorithm.SHA256, id="Curve25519"),
        pytest.param(EllipticCurveOID.NIST_P256, HashAlgorithm.SHA256, id="P-256"),
        pytest.param(EllipticCurveOID.NIST_P384, HashAlgorithm.SHA384, id="P-384"),
        pytest.param(EllipticCurveOID.NIST_P521, HashAlgorithm.SHA512, id="P-521"),
        pytest.param(EllipticCurveOID.SECP256K1, HashAlgorithm.SHA256, id="secp256k1"),
        pytest.param(EllipticCurveOID.Brainpool_P256, HashAlgorithm.SHA256, id="brainpoolP256r1"),
        pytest.param(EllipticCurveOID.Brainpool_P384, HashAlgorithm.SHA384, id="brainpoolP384r1"),
        pytest.param(EllipticCurveOID.Brainpool_P512, HashAlgorithm.SHA512, id="brainpoolP512r1"),
    ]

    @pytest.mark.parametrize("curve_oid,halg", ECDH_CURVES)
    def test_ecdh_encrypt_decrypt(self, curve_oid, halg):
        # Create primary signing key
        if curve_oid == EllipticCurveOID.Curve25519:
            pkey = pgpy.PGPKey.new(PubKeyAlgorithm.EdDSA, EllipticCurveOID.Ed25519)
        else:
            pkey = pgpy.PGPKey.new(PubKeyAlgorithm.ECDSA, EllipticCurveOID.NIST_P256)

        uid = pgpy.PGPUID.new('Test ECDH', 'ecdh@test.com')
        pkey.add_uid(uid, hashes=[halg], usage={KeyFlags.Sign, KeyFlags.Certify})

        # Create ECDH subkey
        subkey = pgpy.PGPKey.new(PubKeyAlgorithm.ECDH, curve_oid)
        pkey.add_subkey(subkey, usage={KeyFlags.EncryptCommunications})

        plaintext = "Hello, ECDH {} on {} backend!".format(curve_oid.name, BACKEND)
        msg = pgpy.PGPMessage.new(plaintext)
        encrypted = pkey.pubkey.encrypt(msg)
        assert encrypted is not None

        decrypted = pkey.decrypt(encrypted)
        assert decrypted.message == plaintext


class TestSymmetricEncryption:
    """Test symmetric message encryption/decryption."""

    @pytest.mark.parametrize("cipher", [
        SymmetricKeyAlgorithm.AES128,
        SymmetricKeyAlgorithm.AES192,
        SymmetricKeyAlgorithm.AES256,
        SymmetricKeyAlgorithm.TripleDES,
        SymmetricKeyAlgorithm.CAST5,
        SymmetricKeyAlgorithm.Blowfish,
    ])
    def test_symmetric_encrypt_decrypt(self, cipher):
        plaintext = "Symmetric cipher {} on {} backend".format(cipher.name, BACKEND)
        msg = pgpy.PGPMessage.new(plaintext)
        encrypted = msg.encrypt("test passphrase", cipher=cipher)
        decrypted = encrypted.decrypt("test passphrase")
        assert decrypted.message == plaintext


class TestBackendConsistency:
    """Test that operations produce consistent results regardless of backend."""

    def test_key_export_import_roundtrip(self):
        """Test that keys generated with one backend can be serialized and re-loaded."""
        key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
        uid = pgpy.PGPUID.new('Roundtrip Test', 'roundtrip@test.com')
        key.add_uid(uid, hashes=[HashAlgorithm.SHA256],
                    usage={KeyFlags.Sign, KeyFlags.Certify})

        # Export and re-import
        key_str = str(key)
        key2, _ = pgpy.PGPKey.from_blob(key_str)

        # Sign with original, verify with re-imported
        sig = key.sign("test message")
        assert key2.pubkey.verify("test message", sig)

    def test_ecdsa_key_export_import_roundtrip(self):
        key = pgpy.PGPKey.new(PubKeyAlgorithm.ECDSA, EllipticCurveOID.NIST_P256)
        uid = pgpy.PGPUID.new('ECDSA Roundtrip', 'ecdsa-rt@test.com')
        key.add_uid(uid, hashes=[HashAlgorithm.SHA256],
                    usage={KeyFlags.Sign, KeyFlags.Certify})

        key_str = str(key)
        key2, _ = pgpy.PGPKey.from_blob(key_str)

        sig = key.sign("test message")
        assert key2.pubkey.verify("test message", sig)

    def test_eddsa_key_export_import_roundtrip(self):
        key = pgpy.PGPKey.new(PubKeyAlgorithm.EdDSA, EllipticCurveOID.Ed25519)
        uid = pgpy.PGPUID.new('EdDSA Roundtrip', 'eddsa-rt@test.com')
        key.add_uid(uid, hashes=[HashAlgorithm.SHA256],
                    usage={KeyFlags.Sign, KeyFlags.Certify})

        key_str = str(key)
        key2, _ = pgpy.PGPKey.from_blob(key_str)

        sig = key.sign("test message")
        assert key2.pubkey.verify("test message", sig)

    def test_existing_rsa_keys_still_work(self):
        """Load existing test RSA keys and verify they still work."""
        import glob
        import os

        rsa_keys = sorted(glob.glob('tests/testdata/keys/rsa.*.sec.asc'))
        if not rsa_keys:
            pytest.skip("No test RSA keys found")

        for kf in rsa_keys:
            key, _ = pgpy.PGPKey.from_file(kf)
            assert key is not None
            assert key.fingerprint is not None

    def test_existing_ecdsa_keys_still_work(self):
        """Load existing test ECDSA keys if any."""
        import glob

        ecdsa_keys = sorted(glob.glob('tests/testdata/keys/ecc.*.sec.asc'))
        for kf in ecdsa_keys:
            key, _ = pgpy.PGPKey.from_file(kf)
            assert key is not None
