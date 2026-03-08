""" fields.py
"""
from __future__ import absolute_import, division

import abc
import binascii
import collections
import copy
import hashlib
import itertools
import math
import os

try:
    import collections.abc as collections_abc
except ImportError:
    collections_abc = collections

from pyasn1.codec.der import decoder
from pyasn1.codec.der import encoder
from pyasn1.type.univ import Integer
from pyasn1.type.univ import Sequence
from pyasn1.type.namedtype import NamedTypes, NamedType

from Crypto.PublicKey import RSA as _RSA
from Crypto.PublicKey import DSA as _DSA
from Crypto.PublicKey import ECC as _ECC
from Crypto.Signature import pkcs1_15 as _pkcs1_15
from Crypto.Signature import DSS as _DSS
from Crypto.Signature import eddsa as _eddsa
from Crypto.Cipher import PKCS1_v1_5 as _PKCS1_v1_5
from Crypto.Cipher import AES as _AES
from Crypto.Util.Padding import pad as _pkcs7_pad
from Crypto.Util.Padding import unpad as _pkcs7_unpad

from .._crypto_utils import get_hash_algo, concat_kdf

from .subpackets import Signature as SignatureSP
from .subpackets import UserAttribute
from .subpackets import signature
from .subpackets import userattribute

from .types import MPI
from .types import MPIs

from ..constants import EllipticCurveOID
from ..constants import ECPointFormat
from ..constants import HashAlgorithm
from ..constants import PubKeyAlgorithm
from ..constants import String2KeyType
from ..constants import S2KGNUExtension
from ..constants import SymmetricKeyAlgorithm

from ..decorators import sdproperty

from ..errors import PGPDecryptionError
from ..errors import PGPError
from ..errors import PGPIncompatibleECPointFormatError

from ..symenc import _decrypt
from ..symenc import _encrypt

from ..types import Field

__all__ = ['SubPackets',
           'UserAttributeSubPackets',
           'Signature',
           'OpaqueSignature',
           'RSASignature',
           'DSASignature',
           'ECDSASignature',
           'EdDSASignature',
           'PubKey',
           'OpaquePubKey',
           'RSAPub',
           'DSAPub',
           'ElGPub',
           'ECPoint',
           'ECDSAPub',
           'EdDSAPub',
           'ECDHPub',
           'String2Key',
           'ECKDF',
           'PrivKey',
           'OpaquePrivKey',
           'RSAPriv',
           'DSAPriv',
           'ElGPriv',
           'ECDSAPriv',
           'EdDSAPriv',
           'ECDHPriv',
           'CipherText',
           'RSACipherText',
           'ElGCipherText',
           'ECDHCipherText', ]


class SubPackets(collections_abc.MutableMapping, Field):
    _spmodule = signature

    def __init__(self):
        super(SubPackets, self).__init__()
        self._hashed_sp = collections.OrderedDict()
        self._unhashed_sp = collections.OrderedDict()

    def __bytearray__(self):
        _bytes = bytearray()
        _bytes += self.__hashbytearray__()
        _bytes += self.__unhashbytearray__()
        return _bytes

    def __hashbytearray__(self):
        _bytes = bytearray()
        _bytes += self.int_to_bytes(sum(len(sp) for sp in self._hashed_sp.values()), 2)
        for hsp in self._hashed_sp.values():
            _bytes += hsp.__bytearray__()
        return _bytes

    def __unhashbytearray__(self):
        _bytes = bytearray()
        _bytes += self.int_to_bytes(sum(len(sp) for sp in self._unhashed_sp.values()), 2)
        for uhsp in self._unhashed_sp.values():
            _bytes += uhsp.__bytearray__()
        return _bytes

    def __len__(self):  # pragma: no cover
        return sum(sp.header.length for sp in itertools.chain(self._hashed_sp.values(), self._unhashed_sp.values())) + 4

    def __iter__(self):
        for sp in itertools.chain(self._hashed_sp.values(), self._unhashed_sp.values()):
            yield sp

    def __setitem__(self, key, val):
        # the key provided should always be the classname for the subpacket
        # but, there can be multiple subpackets of the same type
        # so, it should be stored in the format: [h_]<key>_<seqid>
        # where:
        #  - <key> is the classname of val
        #  - <seqid> is a sequence id, starting at 0, for a given classname

        i = 0
        if isinstance(key, tuple):  # pragma: no cover
            key, i = key

        d = self._unhashed_sp
        if key.startswith('h_'):
            d, key = self._hashed_sp, key[2:]

        while (key, i) in d:
            i += 1

        d[(key, i)] = val

    def __getitem__(self, key):
        if isinstance(key, tuple):  # pragma: no cover
            return self._hashed_sp.get(key, self._unhashed_sp.get(key))

        if key.startswith('h_'):
            return [v for k, v in self._hashed_sp.items() if key[2:] == k[0]]

        else:
            return [v for k, v in itertools.chain(self._hashed_sp.items(), self._unhashed_sp.items()) if key == k[0]]

    def __delitem__(self, key):
        ##TODO: this
        raise NotImplementedError

    def __contains__(self, key):
        return key in set(k for k, _ in itertools.chain(self._hashed_sp, self._unhashed_sp))

    def __copy__(self):
        sp = SubPackets()
        sp._hashed_sp = self._hashed_sp.copy()
        sp._unhashed_sp = self._unhashed_sp.copy()

        return sp

    def addnew(self, spname, hashed=False, **kwargs):
        nsp = getattr(self._spmodule, spname)()
        for p, v in kwargs.items():
            if hasattr(nsp, p):
                setattr(nsp, p, v)
        nsp.update_hlen()
        if hashed:
            self['h_' + spname] = nsp

        else:
            self[spname] = nsp

    def update_hlen(self):
        for sp in self:
            sp.update_hlen()

    def parse(self, packet):
        hl = self.bytes_to_int(packet[:2])
        del packet[:2]

        # we do it this way because we can't ensure that subpacket headers are sized appropriately
        # for their contents, but we can at least output that correctly
        # so instead of tracking how many bytes we can now output, we track how many bytes have we parsed so far
        plen = len(packet)
        while plen - len(packet) < hl:
            sp = SignatureSP(packet)
            self['h_' + sp.__class__.__name__] = sp

        uhl = self.bytes_to_int(packet[:2])
        del packet[:2]

        plen = len(packet)
        while plen - len(packet) < uhl:
            sp = SignatureSP(packet)
            self[sp.__class__.__name__] = sp


class UserAttributeSubPackets(SubPackets):
    """
    This is nearly the same as just the unhashed subpackets from above,
    except that there isn't a length specifier. So, parse will only parse one packet,
    appending that one packet to self.__unhashed_sp.
    """
    _spmodule = userattribute

    def __bytearray__(self):
        _bytes = bytearray()
        for uhsp in self._unhashed_sp.values():
            _bytes += uhsp.__bytearray__()
        return _bytes

    def __len__(self):  # pragma: no cover
        return sum(len(sp) for sp in self._unhashed_sp.values())

    def parse(self, packet):
        # parse just one packet and add it to the unhashed subpacket ordereddict
        # I actually have yet to come across a User Attribute packet with more than one subpacket
        # which makes sense, given that there is only one defined subpacket
        sp = UserAttribute(packet)
        self[sp.__class__.__name__] = sp


class Signature(MPIs):
    def __init__(self):
        for i in self.__mpis__:
            setattr(self, i, MPI(0))

    def __bytearray__(self):
        _bytes = bytearray()
        for i in self:
            _bytes += i.to_mpibytes()
        return _bytes

    @abc.abstractproperty
    def __sig__(self):
        """return the signature bytes in a format that can be understood by the signature verifier"""

    @abc.abstractmethod
    def from_signer(self, sig):
        """create and parse a concrete Signature class instance"""


class OpaqueSignature(Signature):
    def __init__(self):
        super(OpaqueSignature, self).__init__()
        self.data = bytearray()

    def __bytearray__(self):
        return self.data

    def __sig__(self):
        return self.data

    def parse(self, packet):
        self.data = packet

    def from_signer(self, sig):
        self.data = bytearray(sig)


class RSASignature(Signature):
    __mpis__ = ('md_mod_n', )

    def __sig__(self):
        return self.md_mod_n.to_mpibytes()[2:]

    def parse(self, packet):
        self.md_mod_n = MPI(packet)

    def from_signer(self, sig):
        self.md_mod_n = MPI(self.bytes_to_int(sig))


class DSASignature(Signature):
    __mpis__ = ('r', 's')

    def __sig__(self):
        # return the signature data into an ASN.1 sequence of integers in DER format
        seq = Sequence(componentType=NamedTypes(*[NamedType(n, Integer()) for n in self.__mpis__]))
        for n in self.__mpis__:
            seq.setComponentByName(n, getattr(self, n))

        return encoder.encode(seq)

    def from_signer(self, sig):
        ##TODO: just use pyasn1 for this
        def _der_intf(_asn):
            if _asn[0] != 0x02:  # pragma: no cover
                raise ValueError("Expected: Integer (0x02). Got: 0x{:02X}".format(_asn[0]))
            del _asn[0]

            if _asn[0] & 0x80:  # pragma: no cover
                llen = _asn[0] & 0x7F
                del _asn[0]

                flen = self.bytes_to_int(_asn[:llen])
                del _asn[:llen]

            else:
                flen = _asn[0] & 0x7F
                del _asn[0]

            i = self.bytes_to_int(_asn[:flen])
            del _asn[:flen]
            return i

        if isinstance(sig, bytes):
            sig = bytearray(sig)

        # this is a very limited asn1 decoder - it is only intended to decode a DER encoded sequence of integers
        if not sig[0] == 0x30:
            raise NotImplementedError("Expected: Sequence (0x30). Got: 0x{:02X}".format(sig[0]))
        del sig[0]

        # skip the sequence length field
        if sig[0] & 0x80:  # pragma: no cover
            llen = sig[0] & 0x7F
            del sig[:llen + 1]

        else:
            del sig[0]

        self.r = MPI(_der_intf(sig))
        self.s = MPI(_der_intf(sig))

    def parse(self, packet):
        self.r = MPI(packet)
        self.s = MPI(packet)


class ECDSASignature(DSASignature):
    def from_signer(self, sig):
        seq, _ = decoder.decode(sig)
        self.r = MPI(seq[0])
        self.s = MPI(seq[1])


class EdDSASignature(DSASignature):
    def from_signer(self, sig):
        lsig = len(sig)
        if lsig % 2 != 0:
            raise PGPError("malformed EdDSA signature")
        split = lsig // 2
        self.r = MPI(self.bytes_to_int(sig[:split]))
        self.s = MPI(self.bytes_to_int(sig[split:]))

    def __sig__(self):
        # TODO: change this length when EdDSA can be used with another curve (Ed448)
        siglen = (EllipticCurveOID.Ed25519.key_size + 7) // 8
        return self.int_to_bytes(self.r, siglen) + self.int_to_bytes(self.s, siglen)


class PubKey(MPIs):
    __pubfields__ = ()

    @property
    def __mpis__(self):
        for i in self.__pubfields__:
            yield i

    def __init__(self):
        super(PubKey, self).__init__()
        for field in self.__pubfields__:
            if isinstance(field, tuple):  # pragma: no cover
                field, val = field
            else:
                val = MPI(0)
            setattr(self, field, val)

    @abc.abstractmethod
    def __pubkey__(self):
        """return the requisite *PublicKey class from the pycryptodome library"""

    def __len__(self):
        return sum(len(getattr(self, i)) for i in self.__pubfields__)

    def __bytearray__(self):
        _bytes = bytearray()
        for field in self.__pubfields__:
            _bytes += getattr(self, field).to_mpibytes()

        return _bytes

    def publen(self):
        return len(self)

    def verify(self, subj, sigbytes, hash_alg):
        return NotImplemented  # pragma: no cover


class OpaquePubKey(PubKey):  # pragma: no cover
    def __init__(self):
        super(OpaquePubKey, self).__init__()
        self.data = bytearray()

    def __iter__(self):
        yield self.data

    def __pubkey__(self):
        return NotImplemented

    def __bytearray__(self):
        return self.data

    def parse(self, packet):
        ##TODO: this needs to be length-bounded to the end of the packet
        self.data = packet


class RSAPub(PubKey):
    __pubfields__ = ('n', 'e')

    def __pubkey__(self):
        return _RSA.construct((int(self.n), int(self.e)))

    def verify(self, subj, sigbytes, hash_alg):
        # zero-pad sigbytes if necessary
        sigbytes = (b'\x00' * (self.n.byte_length() - len(sigbytes))) + sigbytes
        try:
            h = hash_alg.new(subj)
            _pkcs1_15.new(self.__pubkey__()).verify(h, sigbytes)
        except (ValueError, TypeError):
            return False
        return True

    def parse(self, packet):
        self.n = MPI(packet)
        self.e = MPI(packet)


class DSAPub(PubKey):
    __pubfields__ = ('p', 'q', 'g', 'y')

    def __pubkey__(self):
        return _DSA.construct((int(self.y), int(self.g), int(self.p), int(self.q)))

    def verify(self, subj, sigbytes, hash_alg):
        try:
            h = hash_alg.new(subj)
            _DSS.new(self.__pubkey__(), 'fips-186-3', encoding='der').verify(h, sigbytes)
        except (ValueError, TypeError):
            return False
        return True

    def parse(self, packet):
        self.p = MPI(packet)
        self.q = MPI(packet)
        self.g = MPI(packet)
        self.y = MPI(packet)


class ElGPub(PubKey):
    __pubfields__ = ('p', 'g', 'y')

    def __pubkey__(self):
        raise NotImplementedError()

    def parse(self, packet):
        self.p = MPI(packet)
        self.g = MPI(packet)
        self.y = MPI(packet)


class ECPoint:
    def __init__(self, packet=None):
        if packet is None:
            return
        xy = bytearray(MPI(packet).to_mpibytes()[2:])
        self.format = ECPointFormat(xy[0])
        del xy[0]
        if self.format == ECPointFormat.Standard:
            xylen = len(xy)
            if xylen % 2 != 0:
                raise PGPError("malformed EC point")
            self.bytelen = xylen // 2
            self.x = MPI(MPIs.bytes_to_int(xy[:self.bytelen]))
            self.y = MPI(MPIs.bytes_to_int(xy[self.bytelen:]))
        elif self.format == ECPointFormat.Native:
            self.bytelen = 0  # dummy value for copy
            self.x = bytes(xy)
            self.y = None
        else:
            raise NotImplementedError("No curve is supposed to use only X or Y coordinates")

    @classmethod
    def from_values(cls, bitlen, pform, x, y=None):
        ct = cls()
        ct.bytelen = (bitlen + 7) // 8
        ct.format = pform
        ct.x = x
        ct.y = y
        return ct

    def __len__(self):
        """ Returns length of MPI encoded point """
        if self.format == ECPointFormat.Standard:
            return 2 * self.bytelen + 3
        elif self.format == ECPointFormat.Native:
            return len(self.x) + 3
        else:
            raise NotImplementedError("No curve is supposed to use only X or Y coordinates")

    def to_mpibytes(self):
        """ Returns MPI encoded point as it should be written in packet """
        b = bytearray()
        b.append(self.format)
        if self.format == ECPointFormat.Standard:
            b += MPIs.int_to_bytes(self.x, self.bytelen)
            b += MPIs.int_to_bytes(self.y, self.bytelen)
        elif self.format == ECPointFormat.Native:
            b += self.x
        else:
            raise NotImplementedError("No curve is supposed to use only X or Y coordinates")
        return MPI(MPIs.bytes_to_int(b)).to_mpibytes()

    def __bytearray__(self):
        return self.to_mpibytes()

    def __copy__(self):
        pk = self.__class__()
        pk.bytelen = self.bytelen
        pk.format = self.format
        pk.x = copy.copy(self.x)
        pk.y = copy.copy(self.y)
        return pk


class ECDSAPub(PubKey):
    __pubfields__ = ('p',)

    def __init__(self):
        super(ECDSAPub, self).__init__()
        self.oid = None

    def __len__(self):
        return len(self.p) + len(encoder.encode(self.oid.value)) - 1

    def __pubkey__(self):
        return _ECC.construct(curve=self.oid.curve().pcd_name,
                              point_x=int(self.p.x), point_y=int(self.p.y))

    def __bytearray__(self):
        _b = bytearray()
        _b += encoder.encode(self.oid.value)[1:]
        _b += self.p.to_mpibytes()
        return _b

    def __copy__(self):
        pkt = super(ECDSAPub, self).__copy__()
        pkt.oid = self.oid
        return pkt

    def verify(self, subj, sigbytes, hash_alg):
        try:
            h = hash_alg.new(subj)
            _DSS.new(self.__pubkey__(), 'fips-186-3', encoding='der').verify(h, sigbytes)
        except (ValueError, TypeError):
            return False
        return True

    def parse(self, packet):
        oidlen = packet[0]
        del packet[0]
        _oid = bytearray(b'\x06')
        _oid.append(oidlen)
        _oid += bytearray(packet[:oidlen])
        oid, _  = decoder.decode(bytes(_oid))
        self.oid = EllipticCurveOID(oid)
        del packet[:oidlen]

        self.p = ECPoint(packet)
        if self.p.format != ECPointFormat.Standard:
            raise PGPIncompatibleECPointFormatError("Only Standard format is valid for ECDSA")


class EdDSAPub(PubKey):
    __pubfields__ = ('p', )

    def __init__(self):
        super(EdDSAPub, self).__init__()
        self.oid = None

    def __len__(self):
        return len(self.p) + len(encoder.encode(self.oid.value)) - 1

    def __bytearray__(self):
        _b = bytearray()
        _b += encoder.encode(self.oid.value)[1:]
        _b += self.p.to_mpibytes()
        return _b

    def __pubkey__(self):
        # Build SubjectPublicKeyInfo DER for Ed25519 from raw public key bytes
        raw_pub = bytes(self.p.x)
        alg_id = bytes([0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70])  # Ed25519 OID: 1.3.101.112
        bit_string = bytes([0x03, len(raw_pub) + 1, 0x00]) + raw_pub
        der = bytes([0x30, len(alg_id) + len(bit_string)]) + alg_id + bit_string
        return _ECC.import_key(der)

    def __copy__(self):
        pkt = super(EdDSAPub, self).__copy__()
        pkt.oid = self.oid
        return pkt

    def verify(self, subj, sigbytes, hash_alg):
        # GnuPG requires a pre-hashing with EdDSA
        # https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-06#section-14.8
        h = hash_alg.new(subj)
        subj = h.digest()
        try:
            _eddsa.new(self.__pubkey__(), 'rfc8032').verify(subj, sigbytes)
        except (ValueError, TypeError):
            return False
        return True

    def parse(self, packet):
        oidlen = packet[0]
        del packet[0]
        _oid = bytearray(b'\x06')
        _oid.append(oidlen)
        _oid += bytearray(packet[:oidlen])
        oid, _  = decoder.decode(bytes(_oid))
        self.oid = EllipticCurveOID(oid)
        del packet[:oidlen]

        self.p = ECPoint(packet)
        if self.p.format != ECPointFormat.Native:
            raise PGPIncompatibleECPointFormatError("Only Native format is valid for EdDSA")


class ECDHPub(PubKey):
    __pubfields__ = ('p',)

    def __init__(self):
        super(ECDHPub, self).__init__()
        self.oid = None
        self.kdf = ECKDF()

    def __len__(self):
        return len(self.p) + len(self.kdf) + len(encoder.encode(self.oid.value)) - 1

    def __pubkey__(self):
        if self.oid == EllipticCurveOID.Curve25519:
            # Build SubjectPublicKeyInfo DER for X25519 from raw public key bytes
            raw_pub = bytes(self.p.x)
            alg_id = bytes([0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e])  # X25519 OID: 1.3.101.110
            bit_string = bytes([0x03, len(raw_pub) + 1, 0x00]) + raw_pub
            der = bytes([0x30, len(alg_id) + len(bit_string)]) + alg_id + bit_string
            return _ECC.import_key(der)
        else:
            return _ECC.construct(curve=self.oid.curve().pcd_name,
                                  point_x=int(self.p.x), point_y=int(self.p.y))

    def __bytearray__(self):
        _b = bytearray()
        _b += encoder.encode(self.oid.value)[1:]
        _b += self.p.to_mpibytes()
        _b += self.kdf.__bytearray__()
        return _b

    def __copy__(self):
        pkt = super(ECDHPub, self).__copy__()
        pkt.oid = self.oid
        pkt.kdf = copy.copy(self.kdf)
        return pkt

    def parse(self, packet):
        """
        Algorithm-Specific Fields for ECDH keys:

          o  a variable-length field containing a curve OID, formatted
             as follows:

             -  a one-octet size of the following field; values 0 and
                0xFF are reserved for future extensions

             -  the octets representing a curve OID, defined in
                Section 11

             -  MPI of an EC point representing a public key

          o  a variable-length field containing KDF parameters,
             formatted as follows:

             -  a one-octet size of the following fields; values 0 and
                0xff are reserved for future extensions

             -  a one-octet value 01, reserved for future extensions

             -  a one-octet hash function ID used with a KDF

             -  a one-octet algorithm ID for the symmetric algorithm
                used to wrap the symmetric key used for the message
                encryption; see Section 8 for details
        """
        oidlen = packet[0]
        del packet[0]
        _oid = bytearray(b'\x06')
        _oid.append(oidlen)
        _oid += bytearray(packet[:oidlen])
        oid, _  = decoder.decode(bytes(_oid))

        self.oid = EllipticCurveOID(oid)
        del packet[:oidlen]

        self.p = ECPoint(packet)
        if self.oid == EllipticCurveOID.Curve25519:
            if self.p.format != ECPointFormat.Native:
                raise PGPIncompatibleECPointFormatError("Only Native format is valid for Curve25519")
        elif self.p.format != ECPointFormat.Standard:
            raise PGPIncompatibleECPointFormatError("Only Standard format is valid for this curve")
        self.kdf.parse(packet)


class String2Key(Field):
    """
    3.7.  String-to-Key (S2K) Specifiers

    String-to-key (S2K) specifiers are used to convert passphrase strings
    into symmetric-key encryption/decryption keys.  They are used in two
    places, currently: to encrypt the secret part of private keys in the
    private keyring, and to convert passphrases to encryption keys for
    symmetrically encrypted messages.

    3.7.1.  String-to-Key (S2K) Specifier Types

    There are three types of S2K specifiers currently supported, and
    some reserved values:

       ID          S2K Type
       --          --------
       0           Simple S2K
       1           Salted S2K
       2           Reserved value
       3           Iterated and Salted S2K
       100 to 110  Private/Experimental S2K

    These are described in Sections 3.7.1.1 - 3.7.1.3.

    3.7.1.1.  Simple S2K

    This directly hashes the string to produce the key data.  See below
    for how this hashing is done.

       Octet 0:        0x00
       Octet 1:        hash algorithm

    Simple S2K hashes the passphrase to produce the session key.  The
    manner in which this is done depends on the size of the session key
    (which will depend on the cipher used) and the size of the hash
    algorithm's output.  If the hash size is greater than the session key
    size, the high-order (leftmost) octets of the hash are used as the
    key.

    If the hash size is less than the key size, multiple instances of the
    hash context are created -- enough to produce the required key data.
    These instances are preloaded with 0, 1, 2, ... octets of zeros (that
    is to say, the first instance has no preloading, the second gets
    preloaded with 1 octet of zero, the third is preloaded with two
    octets of zeros, and so forth).

    As the data is hashed, it is given independently to each hash
    context.  Since the contexts have been initialized differently, they
    will each produce different hash output.  Once the passphrase is
    hashed, the output data from the multiple hashes is concatenated,
    first hash leftmost, to produce the key data, with any excess octets
    on the right discarded.

    3.7.1.2.  Salted S2K

    This includes a "salt" value in the S2K specifier -- some arbitrary
    data -- that gets hashed along with the passphrase string, to help
    prevent dictionary attacks.

       Octet 0:        0x01
       Octet 1:        hash algorithm
       Octets 2-9:     8-octet salt value

    Salted S2K is exactly like Simple S2K, except that the input to the
    hash function(s) consists of the 8 octets of salt from the S2K
    specifier, followed by the passphrase.

    3.7.1.3.  Iterated and Salted S2K

    This includes both a salt and an octet count.  The salt is combined
    with the passphrase and the resulting value is hashed repeatedly.
    This further increases the amount of work an attacker must do to try
    dictionary attacks.

       Octet  0:        0x03
       Octet  1:        hash algorithm
       Octets 2-9:      8-octet salt value
       Octet  10:       count, a one-octet, coded value

    The count is coded into a one-octet number using the following
    formula:

       #define EXPBIAS 6
           count = ((Int32)16 + (c & 15)) << ((c >> 4) + EXPBIAS);

    The above formula is in C, where "Int32" is a type for a 32-bit
    integer, and the variable "c" is the coded count, Octet 10.

    Iterated-Salted S2K hashes the passphrase and salt data multiple
    times.  The total number of octets to be hashed is specified in the
    encoded count in the S2K specifier.  Note that the resulting count
    value is an octet count of how many octets will be hashed, not an
    iteration count.

    Initially, one or more hash contexts are set up as with the other S2K
    algorithms, depending on how many octets of key data are needed.
    Then the salt, followed by the passphrase data, is repeatedly hashed
    until the number of octets specified by the octet count has been
    hashed.  The one exception is that if the octet count is less than
    the size of the salt plus passphrase, the full salt plus passphrase
    will be hashed even though that is greater than the octet count.
    After the hashing is done, the data is unloaded from the hash
    context(s) as with the other S2K algorithms.
    """
    @sdproperty
    def encalg(self):
        return self._encalg

    @encalg.register(int)
    @encalg.register(SymmetricKeyAlgorithm)
    def encalg_int(self, val):
        self._encalg = SymmetricKeyAlgorithm(val)

    @sdproperty
    def specifier(self):
        return self._specifier

    @specifier.register(int)
    @specifier.register(String2KeyType)
    def specifier_int(self, val):
        self._specifier = String2KeyType(val)

    @sdproperty
    def gnuext(self):
        return self._gnuext

    @gnuext.register(int)
    @gnuext.register(S2KGNUExtension)
    def gnuext_int(self, val):
        self._gnuext = S2KGNUExtension(val)

    @sdproperty
    def halg(self):
        return self._halg

    @halg.register(int)
    @halg.register(HashAlgorithm)
    def halg_int(self, val):
        self._halg = HashAlgorithm(val)

    @sdproperty
    def count(self):
        return (16 + (self._count & 15)) << ((self._count >> 4) + 6)

    @count.register(int)
    def count_int(self, val):
        if val < 0 or val > 255:  # pragma: no cover
            raise ValueError("count must be between 0 and 256")
        self._count = val

    def __init__(self):
        super(String2Key, self).__init__()
        self.usage = 0
        self.encalg = 0
        self.specifier = 0
        self.iv = None

        # specifier-specific fields
        # simple, salted, iterated
        self.halg = 0

        # salted, iterated
        self.salt = bytearray()

        # iterated
        self.count = 0

        # GNU extension default type: ignored if specifier != GNUExtension
        self.gnuext = 1

        # GNU extension smartcard
        self.scserial = None

    def __bytearray__(self):
        _bytes = bytearray()
        _bytes.append(self.usage)
        if bool(self):
            _bytes.append(self.encalg)
            _bytes.append(self.specifier)
            if self.specifier == String2KeyType.GNUExtension:
                return self._experimental_bytearray(_bytes)
            if self.specifier >= String2KeyType.Simple:
                _bytes.append(self.halg)
            if self.specifier >= String2KeyType.Salted:
                _bytes += self.salt
            if self.specifier == String2KeyType.Iterated:
                _bytes.append(self._count)
            if self.iv is not None:
                _bytes += self.iv
        return _bytes

    def _experimental_bytearray(self, _bytes):
        if self.specifier == String2KeyType.GNUExtension:
            _bytes += b'\x00GNU'
            _bytes.append(self.gnuext)
            if self.scserial:
                _bytes.append(len(self.scserial))
                _bytes += self.scserial
        return _bytes

    def __len__(self):
        return len(self.__bytearray__())

    def __bool__(self):
        return self.usage in [254, 255]

    def __nonzero__(self):
        return self.__bool__()

    def __copy__(self):
        s2k = String2Key()
        s2k.usage = self.usage
        s2k.encalg = self.encalg
        s2k.specifier = self.specifier
        s2k.gnuext = self.gnuext
        s2k.iv = self.iv
        s2k.halg = self.halg
        s2k.salt = copy.copy(self.salt)
        s2k.count = self._count
        s2k.scserial = self.scserial
        return s2k

    def parse(self, packet, iv=True):
        self.usage = packet[0]
        del packet[0]

        if bool(self):
            self.encalg = packet[0]
            del packet[0]

            self.specifier = packet[0]
            del packet[0]

            if self.specifier == String2KeyType.GNUExtension:
                return self._experimental_parse(packet, iv)

            if self.specifier >= String2KeyType.Simple:
                # this will always be true
                self.halg = packet[0]
                del packet[0]

            if self.specifier >= String2KeyType.Salted:
                self.salt = packet[:8]
                del packet[:8]

            if self.specifier == String2KeyType.Iterated:
                self.count = packet[0]
                del packet[0]

            if iv:
                self.iv = packet[:(self.encalg.block_size // 8)]
                del packet[:(self.encalg.block_size // 8)]

    def _experimental_parse(self, packet, iv=True):
        """
        https://git.gnupg.org/cgi-bin/gitweb.cgi?p=gnupg.git;a=blob;f=doc/DETAILS;h=3046523da62c576cf6a765a8b0829876cfdc6b3b;hb=b0f0791e4ade845b2a0e2a94dbda4f3bf1ceb039#l1346

        GNU extensions to the S2K algorithm

        1 octet  - S2K Usage: either 254 or 255.
        1 octet  - S2K Cipher Algo: 0
        1 octet  - S2K Specifier: 101
        4 octets - "\x00GNU"
        1 octet  - GNU S2K Extension Number.

        If such a GNU extension is used neither an IV nor any kind of
        checksum is used.  The defined GNU S2K Extension Numbers are:

        - 1 :: Do not store the secret part at all.  No specific data
               follows.

        - 2 :: A stub to access smartcards.  This data follows:
               - One octet with the length of the following serial number.
               - The serial number. Regardless of what the length octet
                 indicates no more than 16 octets are stored.
        """
        if self.specifier == String2KeyType.GNUExtension:
            if packet[:4] != b'\x00GNU':
                raise PGPError("Invalid S2K GNU extension magic value")
            del packet[:4]
            self.gnuext = packet[0]
            del packet[0]

            if self.gnuext == S2KGNUExtension.Smartcard:
                slen = min(packet[0], 16)
                del packet[0]
                self.scserial = packet[:slen]
                del packet[:slen]

    def derive_key(self, passphrase):
        ##TODO: raise an exception if self.usage is not 254 or 255
        keylen = self.encalg.key_size
        hashlen = self.halg.digest_size * 8

        ctx = int(math.ceil((keylen / hashlen)))

        # Simple S2K - always done
        hsalt = b''
        if isinstance(passphrase, bytes):
            hpass = passphrase
        else:
            hpass = passphrase.encode('utf-8')

        # salted, iterated S2K
        if self.specifier >= String2KeyType.Salted:
            hsalt = bytes(self.salt)

        count = len(hsalt + hpass)
        if self.specifier == String2KeyType.Iterated and self.count > len(hsalt + hpass):
            count = self.count

        hcount = (count // len(hsalt + hpass))
        hleft = count - (hcount * len(hsalt + hpass))

        hashdata = ((hsalt + hpass) * hcount) + (hsalt + hpass)[:hleft]

        h = []
        for i in range(0, ctx):
            _h = self.halg.hasher
            _h.update(b'\x00' * i)
            _h.update(hashdata)
            h.append(_h)

        # GC some stuff
        del hsalt
        del hpass
        del hashdata

        # and return the key!
        return b''.join(hc.digest() for hc in h)[:(keylen // 8)]


class ECKDF(Field):
    """
    o  a variable-length field containing KDF parameters,
       formatted as follows:

       -  a one-octet size of the following fields; values 0 and
          0xff are reserved for future extensions

       -  a one-octet value 01, reserved for future extensions

       -  a one-octet hash function ID used with a KDF

       -  a one-octet algorithm ID for the symmetric algorithm
          used to wrap the symmetric key used for the message
          encryption; see Section 8 for details
    """
    @sdproperty
    def halg(self):
        return self._halg

    @halg.register(int)
    @halg.register(HashAlgorithm)
    def halg_int(self, val):
        self._halg = HashAlgorithm(val)

    @sdproperty
    def encalg(self):
        return self._encalg

    @encalg.register(int)
    @encalg.register(SymmetricKeyAlgorithm)
    def encalg_int(self, val):
        self._encalg = SymmetricKeyAlgorithm(val)

    def __init__(self):
        super(ECKDF, self).__init__()
        self.halg = 0
        self.encalg = 0

    def __bytearray__(self):
        _bytes = bytearray()
        _bytes.append(len(self) - 1)
        _bytes.append(0x01)
        _bytes.append(self.halg)
        _bytes.append(self.encalg)
        return _bytes

    def __len__(self):
        return 4

    def parse(self, packet):
        # packet[0] should always be 3
        # packet[1] should always be 1
        # TODO: this assert is likely not necessary, but we should raise some kind of exception
        #       if parsing fails due to these fields being incorrect
        assert packet[:2] == b'\x03\x01'
        del packet[:2]

        self.halg = packet[0]
        del packet[0]

        self.encalg = packet[0]
        del packet[0]

    def derive_key(self, s, curve, pkalg, fingerprint):
        # wrapper around the Concatenation KDF
        # assemble the additional data as defined in RFC 6637:
        #  Param = curve_OID_len || curve_OID || public_key_alg_ID || 03 || 01 || KDF_hash_ID || KEK_alg_ID for AESKeyWrap || "Anonymous
        data = bytearray()
        data += encoder.encode(curve.value)[1:]
        data.append(pkalg)
        data += b'\x03\x01'
        data.append(self.halg)
        data.append(self.encalg)
        data += b'Anonymous Sender    '
        data += binascii.unhexlify(fingerprint.replace(' ', ''))

        return concat_kdf(self.halg.name, s, self.encalg.key_size // 8, bytes(data))


class PrivKey(PubKey):
    __privfields__ = ()

    @property
    def __mpis__(self):
        for i in super(PrivKey, self).__mpis__:
            yield i

        for i in self.__privfields__:
            yield i

    def __init__(self):
        super(PrivKey, self).__init__()

        self.s2k = String2Key()
        self.encbytes = bytearray()
        self.chksum = bytearray()

        for field in self.__privfields__:
            setattr(self, field, MPI(0))

    def __bytearray__(self):
        _bytes = bytearray()
        _bytes += super(PrivKey, self).__bytearray__()

        _bytes += self.s2k.__bytearray__()
        if self.s2k:
            _bytes += self.encbytes

        else:
            for field in self.__privfields__:
                _bytes += getattr(self, field).to_mpibytes()

        if self.s2k.usage == 0:
            _bytes += self.chksum

        return _bytes

    def __len__(self):
        nbytes = super(PrivKey, self).__len__() + len(self.s2k) + len(self.chksum)
        if self.s2k:
            nbytes += len(self.encbytes)

        else:
            nbytes += sum(len(getattr(self, i)) for i in self.__privfields__)

        return nbytes

    def __copy__(self):
        pk = super(PrivKey, self).__copy__()
        pk.s2k = copy.copy(self.s2k)
        pk.encbytes = copy.copy(self.encbytes)
        pk.chksum = copy.copy(self.chksum)
        return pk

    @abc.abstractmethod
    def __privkey__(self):
        """return the requisite *PrivateKey class from the pycryptodome library"""

    @abc.abstractmethod
    def _generate(self, key_size):
        """Generate a new PrivKey"""

    def _compute_chksum(self):
        "Calculate the key checksum"

    def publen(self):
        return super(PrivKey, self).__len__()

    def encrypt_keyblob(self, passphrase, enc_alg, hash_alg):
        # PGPy will only ever use iterated and salted S2k mode
        self.s2k.usage = 254
        self.s2k.encalg = enc_alg
        self.s2k.specifier = String2KeyType.Iterated
        self.s2k.iv = enc_alg.gen_iv()
        self.s2k.halg = hash_alg
        self.s2k.salt = bytearray(os.urandom(8))
        self.s2k.count = hash_alg.tuned_count

        # now that String-to-Key is ready to go, derive sessionkey from passphrase
        # and then unreference passphrase
        sessionkey = self.s2k.derive_key(passphrase)
        del passphrase

        pt = bytearray()
        for pf in self.__privfields__:
            pt += getattr(self, pf).to_mpibytes()

        # append a SHA-1 hash of the plaintext so far to the plaintext
        pt += hashlib.new('sha1', pt).digest()

        # encrypt
        self.encbytes = bytearray(_encrypt(bytes(pt), bytes(sessionkey), enc_alg, bytes(self.s2k.iv)))

        # delete pt and clear self
        del pt
        self.clear()

    @abc.abstractmethod
    def decrypt_keyblob(self, passphrase):
        if not self.s2k:  # pragma: no cover
            # not encrypted
            return

        # Encryption/decryption of the secret data is done in CFB mode using
        # the key created from the passphrase and the Initial Vector from the
        # packet.  A different mode is used with V3 keys (which are only RSA)
        # than with other key formats.  (...)
        #
        # With V4 keys, a simpler method is used.  All secret MPI values are
        # encrypted in CFB mode, including the MPI bitcount prefix.

        # derive the session key from our passphrase, and then unreference passphrase
        sessionkey = self.s2k.derive_key(passphrase)
        del passphrase

        # attempt to decrypt this key
        pt = _decrypt(bytes(self.encbytes), bytes(sessionkey), self.s2k.encalg, bytes(self.s2k.iv))

        # check the hash to see if we decrypted successfully or not
        if self.s2k.usage == 254 and not pt[-20:] == hashlib.new('sha1', pt[:-20]).digest():
            # if the usage byte is 254, key material is followed by a 20-octet sha-1 hash of the rest
            # of the key material block
            raise PGPDecryptionError("Passphrase was incorrect!")

        if self.s2k.usage == 255 and not self.bytes_to_int(pt[-2:]) == (sum(bytearray(pt[:-2])) % 65536):  # pragma: no cover
            # if the usage byte is 255, key material is followed by a 2-octet checksum of the rest
            # of the key material block
            raise PGPDecryptionError("Passphrase was incorrect!")

        return bytearray(pt)

    def sign(self, sigdata, hash_alg):
        return NotImplemented  # pragma: no cover

    def clear(self):
        """delete and re-initialize all private components to zero"""
        for field in self.__privfields__:
            delattr(self, field)
            setattr(self, field, MPI(0))


class OpaquePrivKey(PrivKey, OpaquePubKey):  # pragma: no cover
    def __privkey__(self):
        return NotImplemented

    def _generate(self, key_size):
        # return NotImplemented
        raise NotImplementedError()

    def decrypt_keyblob(self, passphrase):
        return NotImplemented


class RSAPriv(PrivKey, RSAPub):
    __privfields__ = ('d', 'p', 'q', 'u')

    def __privkey__(self):
        return _RSA.construct((int(self.n), int(self.e), int(self.d), int(self.p), int(self.q)))

    def _compute_chksum(self):
        chs = sum(sum(bytearray(c.to_mpibytes())) for c in (self.d, self.p, self.q, self.u)) % 65536
        self.chksum = bytearray(self.int_to_bytes(chs, 2))

    def _generate(self, key_size):
        if any(c != 0 for c in self):  # pragma: no cover
            raise PGPError("key is already populated")

        # generate some big numbers!
        pk = _RSA.generate(key_size)

        self.n = MPI(pk.n)
        self.e = MPI(pk.e)
        self.d = MPI(pk.d)
        self.p = MPI(pk.p)
        self.q = MPI(pk.q)
        # from the RFC:
        # "- MPI of u, the multiplicative inverse of p, mod q."
        # pycryptodome: pk.u = p^-1 mod q, which matches the PGP RFC
        self.u = MPI(pk.u)

        del pk

        self._compute_chksum()

    def parse(self, packet):
        super(RSAPriv, self).parse(packet)
        self.s2k.parse(packet)

        if not self.s2k:
            self.d = MPI(packet)
            self.p = MPI(packet)
            self.q = MPI(packet)
            self.u = MPI(packet)

            if self.s2k.usage == 0:
                self.chksum = packet[:2]
                del packet[:2]

        else:
            ##TODO: this needs to be bounded to the length of the encrypted key material
            self.encbytes = packet

    def decrypt_keyblob(self, passphrase):
        kb = super(RSAPriv, self).decrypt_keyblob(passphrase)
        del passphrase

        self.d = MPI(kb)
        self.p = MPI(kb)
        self.q = MPI(kb)
        self.u = MPI(kb)

        if self.s2k.usage in [254, 255]:
            self.chksum = kb
            del kb

    def sign(self, sigdata, hash_alg):
        h = hash_alg.new(sigdata)
        return _pkcs1_15.new(self.__privkey__()).sign(h)


class DSAPriv(PrivKey, DSAPub):
    __privfields__ = ('x',)

    def __privkey__(self):
        return _DSA.construct((int(self.y), int(self.g), int(self.p), int(self.q), int(self.x)))

    def _compute_chksum(self):
        chs = sum(bytearray(self.x.to_mpibytes())) % 65536
        self.chksum = bytearray(self.int_to_bytes(chs, 2))

    def _generate(self, key_size):
        if any(c != 0 for c in self):  # pragma: no cover
            raise PGPError("key is already populated")

        # generate some big numbers!
        pk = _DSA.generate(key_size)

        self.p = MPI(pk.p)
        self.q = MPI(pk.q)
        self.g = MPI(pk.g)
        self.y = MPI(pk.y)
        self.x = MPI(pk.x)

        del pk

        self._compute_chksum()

    def parse(self, packet):
        super(DSAPriv, self).parse(packet)
        self.s2k.parse(packet)

        if not self.s2k:
            self.x = MPI(packet)

        else:
            self.encbytes = packet

        if self.s2k.usage in [0, 255]:
            self.chksum = packet[:2]
            del packet[:2]

    def decrypt_keyblob(self, passphrase):
        kb = super(DSAPriv, self).decrypt_keyblob(passphrase)
        del passphrase

        self.x = MPI(kb)

        if self.s2k.usage in [254, 255]:
            self.chksum = kb
            del kb

    def sign(self, sigdata, hash_alg):
        h = hash_alg.new(sigdata)
        return _DSS.new(self.__privkey__(), 'fips-186-3', encoding='der').sign(h)


class ElGPriv(PrivKey, ElGPub):
    __privfields__ = ('x', )

    def __privkey__(self):
        raise NotImplementedError()

    def _compute_chksum(self):
        chs = sum(bytearray(self.x.to_mpibytes())) % 65536
        self.chksum = bytearray(self.int_to_bytes(chs, 2))

    def _generate(self, key_size):
        raise NotImplementedError(PubKeyAlgorithm.ElGamal)

    def parse(self, packet):
        super(ElGPriv, self).parse(packet)
        self.s2k.parse(packet)

        if not self.s2k:
            self.x = MPI(packet)

        else:
            self.encbytes = packet

        if self.s2k.usage in [0, 255]:
            self.chksum = packet[:2]
            del packet[:2]

    def decrypt_keyblob(self, passphrase):
        kb = super(ElGPriv, self).decrypt_keyblob(passphrase)
        del passphrase

        self.x = MPI(kb)

        if self.s2k.usage in [254, 255]:
            self.chksum = kb
            del kb


class ECDSAPriv(PrivKey, ECDSAPub):
    __privfields__ = ('s', )

    def __privkey__(self):
        return _ECC.construct(curve=self.oid.curve().pcd_name,
                              d=int(self.s),
                              point_x=int(self.p.x), point_y=int(self.p.y))

    def _compute_chksum(self):
        chs = sum(bytearray(self.s.to_mpibytes())) % 65536
        self.chksum = bytearray(self.int_to_bytes(chs, 2))

    def _generate(self, oid):
        if any(c != 0 for c in self):  # pragma: no cover
            raise PGPError("Key is already populated!")

        self.oid = EllipticCurveOID(oid)

        if not self.oid.can_gen:
            raise ValueError("Curve not currently supported: {}".format(oid.name))

        pk = _ECC.generate(curve=self.oid.curve().pcd_name)
        self.p = ECPoint.from_values(self.oid.key_size, ECPointFormat.Standard,
                                     MPI(int(pk.pointQ.x)), MPI(int(pk.pointQ.y)))
        self.s = MPI(int(pk.d))
        self._compute_chksum()

    def parse(self, packet):
        super(ECDSAPriv, self).parse(packet)
        self.s2k.parse(packet)

        if not self.s2k:
            self.s = MPI(packet)

            if self.s2k.usage == 0:
                self.chksum = packet[:2]
                del packet[:2]
        else:
            ##TODO: this needs to be bounded to the length of the encrypted key material
            self.encbytes = packet

    def decrypt_keyblob(self, passphrase):
        kb = super(ECDSAPriv, self).decrypt_keyblob(passphrase)
        del passphrase
        self.s = MPI(kb)

    def sign(self, sigdata, hash_alg):
        h = hash_alg.new(sigdata)
        return _DSS.new(self.__privkey__(), 'fips-186-3', encoding='der').sign(h)


class EdDSAPriv(PrivKey, EdDSAPub):
    __privfields__ = ('s', )

    def __privkey__(self):
        s = self.int_to_bytes(self.s, (self.oid.key_size + 7) // 8)
        return _ECC.construct(curve='Ed25519', seed=s)

    def _compute_chksum(self):
        chs = sum(bytearray(self.s.to_mpibytes())) % 65536
        self.chksum = bytearray(self.int_to_bytes(chs, 2))

    def _generate(self, oid):
        if any(c != 0 for c in self):  # pragma: no cover
            raise PGPError("Key is already populated!")

        self.oid = EllipticCurveOID(oid)

        if self.oid != EllipticCurveOID.Ed25519:
            raise ValueError("EdDSA only supported with {}".format(EllipticCurveOID.Ed25519))

        pk = _ECC.generate(curve='Ed25519')
        x = pk.public_key().export_key(format='raw')
        self.p = ECPoint.from_values(self.oid.key_size, ECPointFormat.Native, x)
        self.s = MPI(self.bytes_to_int(pk.seed))
        self._compute_chksum()

    def parse(self, packet):
        super(EdDSAPriv, self).parse(packet)
        self.s2k.parse(packet)

        if not self.s2k:
            self.s = MPI(packet)
            if self.s2k.usage == 0:
                self.chksum = packet[:2]
                del packet[:2]
        else:
            ##TODO: this needs to be bounded to the length of the encrypted key material
            self.encbytes = packet

    def decrypt_keyblob(self, passphrase):
        kb = super(EdDSAPriv, self).decrypt_keyblob(passphrase)
        del passphrase
        self.s = MPI(kb)

    def sign(self, sigdata, hash_alg):
        # GnuPG requires a pre-hashing with EdDSA
        # https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-06#section-14.8
        h = hash_alg.new(sigdata)
        sigdata = h.digest()
        return _eddsa.new(self.__privkey__(), 'rfc8032').sign(sigdata)


class ECDHPriv(ECDSAPriv, ECDHPub):
    def __bytearray__(self):
        _b = ECDHPub.__bytearray__(self)
        _b += self.s2k.__bytearray__()
        if not self.s2k:
            _b += self.s.to_mpibytes()
            if self.s2k.usage == 0:
                _b += self.chksum
        else:
            _b += self.encbytes
        return _b

    def __len__(self):
        nbytes = ECDHPub.__len__(self) + len(self.s2k) + len(self.chksum)
        if self.s2k:
            nbytes += len(self.encbytes)
        else:
            nbytes += sum(len(getattr(self, i)) for i in self.__privfields__)
        return nbytes

    def __privkey__(self):
        if self.oid == EllipticCurveOID.Curve25519:
            # NOTE: GPG stores Curve25519 secret in little-endian
            s = self.int_to_bytes(self.s, (self.oid.key_size + 7) // 8, 'little')
            return _ECC.construct(curve='Curve25519', seed=s)
        else:
            return ECDSAPriv.__privkey__(self)

    def _generate(self, oid):
        _oid = EllipticCurveOID(oid)
        if _oid == EllipticCurveOID.Curve25519:
            if any(c != 0 for c in self):  # pragma: no cover
                raise PGPError("Key is already populated!")
            self.oid = _oid
            pk = _ECC.generate(curve='Curve25519')
            x = pk.public_key().export_key(format='raw')
            self.p = ECPoint.from_values(self.oid.key_size, ECPointFormat.Native, x)
            # NOTE: GPG stores Curve25519 secret in little-endian
            self.s = MPI(self.bytes_to_int(pk.seed, 'little'))
            self._compute_chksum()
        else:
            ECDSAPriv._generate(self, oid)
        self.kdf.halg = self.oid.kdf_halg
        self.kdf.encalg = self.oid.kek_alg

    def publen(self):
        return ECDHPub.__len__(self)

    def parse(self, packet):
        ECDHPub.parse(self, packet)
        self.s2k.parse(packet)

        if not self.s2k:
            self.s = MPI(packet)
            if self.s2k.usage == 0:
                self.chksum = packet[:2]
                del packet[:2]
        else:
            ##TODO: this needs to be bounded to the length of the encrypted key material
            self.encbytes = packet

    def sign(self, sigdata, hash_alg):
        raise PGPError("Cannot sign with an ECDH key")


class CipherText(MPIs):
    def __init__(self):
        super(CipherText, self).__init__()
        for i in self.__mpis__:
            setattr(self, i, MPI(0))

    @classmethod
    @abc.abstractmethod
    def encrypt(cls, encfn, *args):
        """create and populate a concrete CipherText class instance"""

    @abc.abstractmethod
    def decrypt(self, decfn, *args):
        """decrypt the ciphertext contained in this CipherText instance"""

    def __bytearray__(self):
        _bytes = bytearray()
        for i in self:
            _bytes += i.to_mpibytes()
        return _bytes


class RSACipherText(CipherText):
    __mpis__ = ('me_mod_n', )

    @classmethod
    def encrypt(cls, encfn, *args):
        ct = cls()
        ct.me_mod_n = MPI(cls.bytes_to_int(encfn(*args)))
        return ct

    def decrypt(self, decfn, *args):
        return decfn(*args)

    def parse(self, packet):
        self.me_mod_n = MPI(packet)


class ElGCipherText(CipherText):
    __mpis__ = ('gk_mod_p', 'myk_mod_p')

    @classmethod
    def encrypt(cls, encfn, *args):
        raise NotImplementedError()

    def decrypt(self, decfn, *args):
        raise NotImplementedError()

    def parse(self, packet):
        self.gk_mod_p = MPI(packet)
        self.myk_mod_p = MPI(packet)


class ECDHCipherText(CipherText):
    __mpis__ = ('p',)

    @classmethod
    def encrypt(cls, pk, *args):
        """
        For convenience, the synopsis of the encoding method is given below;
        however, this section, [NIST-SP800-56A], and [RFC3394] are the
        normative sources of the definition.

            Obtain the authenticated recipient public key R
            Generate an ephemeral key pair {v, V=vG}
            Compute the shared point S = vR;
            m = symm_alg_ID || session key || checksum || pkcs5_padding;
            curve_OID_len = (byte)len(curve_OID);
            Param = curve_OID_len || curve_OID || public_key_alg_ID || 03
            || 01 || KDF_hash_ID || KEK_alg_ID for AESKeyWrap || "Anonymous
            Sender    " || recipient_fingerprint;
            Z_len = the key size for the KEK_alg_ID used with AESKeyWrap
            Compute Z = KDF( S, Z_len, Param );
            Compute C = AESKeyWrap( Z, m ) as per [RFC3394]
            VB = convert point V to the octet string
            Output (MPI(VB) || len(C) || C).

        The decryption is the inverse of the method given.  Note that the
        recipient obtains the shared secret by calculating
        """
        # *args should be:
        # - m
        #
        _m, = args

        # m may need to be PKCS5-padded
        m = _pkcs7_pad(_m, 8, style='pkcs7')

        km = pk.keymaterial
        ct = cls()

        # generate ephemeral key pair and keep public key in ct
        # use private key to compute the shared point "s"
        if km.oid == EllipticCurveOID.Curve25519:
            v = _ECC.generate(curve='Curve25519')
            x = v.public_key().export_key(format='raw')
            ct.p = ECPoint.from_values(km.oid.key_size, ECPointFormat.Native, x)
            # X25519 key exchange: shared = other_pub * my_priv
            shared_point = km.__pubkey__().pointQ * v.d
            s = int(shared_point.x).to_bytes(32, 'big')
        else:
            v = _ECC.generate(curve=km.oid.curve().pcd_name)
            x = MPI(int(v.pointQ.x))
            y = MPI(int(v.pointQ.y))
            ct.p = ECPoint.from_values(km.oid.key_size, ECPointFormat.Standard, x, y)
            # ECDH: shared = other_pub * my_priv
            shared_point = km.__pubkey__().pointQ * v.d
            byte_size = (km.oid.key_size + 7) // 8
            s = int(shared_point.x).to_bytes(byte_size, 'big')

        # derive the wrapping key
        z = km.kdf.derive_key(s, km.oid, PubKeyAlgorithm.ECDH, pk.fingerprint)

        # compute C using AES Key Wrap (RFC 3394)
        ct.c = _AES.new(z, _AES.MODE_KW).seal(m)

        return ct

    def decrypt(self, pk, *args):
        km = pk.keymaterial
        if km.oid == EllipticCurveOID.Curve25519:
            # Build SubjectPublicKeyInfo DER for X25519 from raw ephemeral public key bytes
            raw_pub = bytes(self.p.x)
            alg_id = bytes([0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e])
            bit_string = bytes([0x03, len(raw_pub) + 1, 0x00]) + raw_pub
            der = bytes([0x30, len(alg_id) + len(bit_string)]) + alg_id + bit_string
            v = _ECC.import_key(der)
            # X25519 key exchange: shared = ephemeral_pub * my_priv
            shared_point = v.pointQ * km.__privkey__().d
            s = int(shared_point.x).to_bytes(32, 'big')
        else:
            # assemble the public component of ephemeral key v
            v = _ECC.construct(curve=km.oid.curve().pcd_name,
                               point_x=int(self.p.x), point_y=int(self.p.y))
            # compute s using the inverse of how it was derived during encryption
            shared_point = v.pointQ * km.__privkey__().d
            byte_size = (km.oid.key_size + 7) // 8
            s = int(shared_point.x).to_bytes(byte_size, 'big')

        # derive the wrapping key
        z = km.kdf.derive_key(s, km.oid, PubKeyAlgorithm.ECDH, pk.fingerprint)

        # unwrap and unpad m
        _m = _AES.new(z, _AES.MODE_KW).unseal(bytes(self.c))

        return _pkcs7_unpad(_m, 8, style='pkcs7')

    def __init__(self):
        super(ECDHCipherText, self).__init__()
        self.c = bytearray(0)

    def __bytearray__(self):
        _bytes = bytearray()
        _bytes += self.p.to_mpibytes()
        _bytes.append(len(self.c))
        _bytes += self.c
        return _bytes

    def parse(self, packet):
        # read ephemeral public key
        self.p = ECPoint(packet)
        # read signature value
        clen = packet[0]
        del packet[0]
        self.c += packet[:clen]
        del packet[:clen]
