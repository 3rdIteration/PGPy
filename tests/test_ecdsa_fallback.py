"""Tests for ecdsa/embit library fallback for secp256k1 and Brainpool curves."""
import pytest
import warnings

import pgpy
from pgpy.constants import (
    PubKeyAlgorithm, EllipticCurveOID, HashAlgorithm, KeyFlags,
)
from pgpy.packet.fields import _ECDSA_CURVES, _has_embit


# Suppress self-sigs / revocation warnings
pytestmark = pytest.mark.filterwarnings("ignore::UserWarning")

# Curves that use the ecdsa/embit fallback
FALLBACK_CURVES = [
    pytest.param(EllipticCurveOID.SECP256K1, HashAlgorithm.SHA256, id="secp256k1"),
    pytest.param(EllipticCurveOID.Brainpool_P256, HashAlgorithm.SHA256, id="brainpoolP256r1"),
    pytest.param(EllipticCurveOID.Brainpool_P384, HashAlgorithm.SHA384, id="brainpoolP384r1"),
    pytest.param(EllipticCurveOID.Brainpool_P512, HashAlgorithm.SHA512, id="brainpoolP512r1"),
]


class TestECDSAFallbackKeygen:
    """Test ECDSA key generation for fallback curves."""

    @pytest.mark.parametrize("curve_oid,halg", FALLBACK_CURVES)
    def test_generate_ecdsa_key(self, curve_oid, halg):
        key = pgpy.PGPKey.new(PubKeyAlgorithm.ECDSA, curve_oid)
        assert key is not None
        assert key.fingerprint is not None
        uid = pgpy.PGPUID.new('Test', 'test@example.com')
        key.add_uid(uid, hashes=[halg], usage={KeyFlags.Sign, KeyFlags.Certify})
        assert len(key.userids) == 1

    @pytest.mark.parametrize("curve_oid,halg", FALLBACK_CURVES)
    def test_generate_ecdh_subkey(self, curve_oid, halg):
        # Use NIST P-256 as the primary signing key
        pkey = pgpy.PGPKey.new(PubKeyAlgorithm.ECDSA, EllipticCurveOID.NIST_P256)
        uid = pgpy.PGPUID.new('Test', 'test@example.com')
        pkey.add_uid(uid, hashes=[halg], usage={KeyFlags.Sign, KeyFlags.Certify})

        subkey = pgpy.PGPKey.new(PubKeyAlgorithm.ECDH, curve_oid)
        pkey.add_subkey(subkey, usage={KeyFlags.EncryptCommunications})
        assert len(list(pkey.subkeys.values())) == 1


class TestECDSAFallbackSignVerify:
    """Test ECDSA signing and verification for fallback curves."""

    @pytest.mark.parametrize("curve_oid,halg", FALLBACK_CURVES)
    def test_sign_and_verify_string(self, curve_oid, halg):
        key = pgpy.PGPKey.new(PubKeyAlgorithm.ECDSA, curve_oid)
        uid = pgpy.PGPUID.new('Test', 'test@example.com')
        key.add_uid(uid, hashes=[halg], usage={KeyFlags.Sign, KeyFlags.Certify})

        string = "Hello, {}!".format(curve_oid.name)
        sig = key.sign(string)
        assert sig is not None

        sv = key.pubkey.verify(string, sig)
        assert sv

    @pytest.mark.parametrize("curve_oid,halg", FALLBACK_CURVES)
    def test_verify_wrong_message_fails(self, curve_oid, halg):
        key = pgpy.PGPKey.new(PubKeyAlgorithm.ECDSA, curve_oid)
        uid = pgpy.PGPUID.new('Test', 'test@example.com')
        key.add_uid(uid, hashes=[halg], usage={KeyFlags.Sign, KeyFlags.Certify})

        sig = key.sign("message A")
        sv = key.pubkey.verify("message B", sig)
        assert not sv

    @pytest.mark.parametrize("curve_oid,halg", FALLBACK_CURVES)
    def test_cross_key_verify_fails(self, curve_oid, halg):
        key1 = pgpy.PGPKey.new(PubKeyAlgorithm.ECDSA, curve_oid)
        uid1 = pgpy.PGPUID.new('Test1', 'test1@example.com')
        key1.add_uid(uid1, hashes=[halg], usage={KeyFlags.Sign, KeyFlags.Certify})

        key2 = pgpy.PGPKey.new(PubKeyAlgorithm.ECDSA, curve_oid)
        uid2 = pgpy.PGPUID.new('Test2', 'test2@example.com')
        key2.add_uid(uid2, hashes=[halg], usage={KeyFlags.Sign, KeyFlags.Certify})

        sig = key1.sign("test message")
        # PGPy raises PGPError when the signer keyid doesn't match
        with pytest.raises(pgpy.errors.PGPError):
            key2.pubkey.verify("test message", sig)


class TestECDHFallbackEncryptDecrypt:
    """Test ECDH encrypt/decrypt for fallback curves."""

    @pytest.mark.parametrize("curve_oid,halg", FALLBACK_CURVES)
    def test_encrypt_decrypt_message(self, curve_oid, halg):
        pkey = pgpy.PGPKey.new(PubKeyAlgorithm.ECDSA, EllipticCurveOID.NIST_P256)
        uid = pgpy.PGPUID.new('Test', 'test@example.com')
        pkey.add_uid(uid, hashes=[halg], usage={KeyFlags.Sign, KeyFlags.Certify})

        subkey = pgpy.PGPKey.new(PubKeyAlgorithm.ECDH, curve_oid)
        pkey.add_subkey(subkey, usage={KeyFlags.EncryptCommunications})

        plaintext = "Hello, ECDH {}!".format(curve_oid.name)
        msg = pgpy.PGPMessage.new(plaintext)
        encrypted = pkey.pubkey.encrypt(msg)
        assert encrypted is not None

        decrypted = pkey.decrypt(encrypted)
        assert decrypted.message == plaintext


class TestEmbitFallback:
    """Test that embit is used for secp256k1 when available."""

    @pytest.mark.skipif(not _has_embit, reason="embit not installed")
    def test_embit_used_for_secp256k1(self):
        """Verify that embit is detected and used for secp256k1 operations."""
        assert _has_embit is True
        key = pgpy.PGPKey.new(PubKeyAlgorithm.ECDSA, EllipticCurveOID.SECP256K1)
        uid = pgpy.PGPUID.new('Test embit', 'embit@example.com')
        key.add_uid(uid, hashes=[HashAlgorithm.SHA256],
                    usage={KeyFlags.Sign, KeyFlags.Certify})

        sig = key.sign("embit test")
        sv = key.pubkey.verify("embit test", sig)
        assert sv

    def test_ecdsa_curves_mapping(self):
        """Verify that the curve mapping contains exactly the expected curves."""
        assert EllipticCurveOID.SECP256K1 in _ECDSA_CURVES
        assert EllipticCurveOID.Brainpool_P256 in _ECDSA_CURVES
        assert EllipticCurveOID.Brainpool_P384 in _ECDSA_CURVES
        assert EllipticCurveOID.Brainpool_P512 in _ECDSA_CURVES
        # NIST curves should NOT be in the fallback mapping
        assert EllipticCurveOID.NIST_P256 not in _ECDSA_CURVES
        assert EllipticCurveOID.NIST_P384 not in _ECDSA_CURVES
        assert EllipticCurveOID.NIST_P521 not in _ECDSA_CURVES


class TestSupportedCurves:
    """Test that _get_supported_curves includes the new curves."""

    def test_secp256k1_supported(self):
        from pgpy._curves import _get_supported_curves
        supported = _get_supported_curves()
        assert 'secp256k1' in supported

    def test_brainpool_curves_supported(self):
        from pgpy._curves import _get_supported_curves
        supported = _get_supported_curves()
        assert 'brainpoolP256r1' in supported
        assert 'brainpoolP384r1' in supported
        assert 'brainpoolP512r1' in supported
