# from https://github.com/bitcoin-core/HWI

#!/usr/bin/env python3
# Copyright (c) 2020 The HWI developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Key Classes and Utilities
*************************

Classes and utilities for working with extended public keys, key origins, and other key related things.
"""

import random
from . import _base58 as base58
from .common import (
    AddressType,
    Chain,
    hash256,
    hash160,
)
from .errors import BadArgumentError

import binascii
import hmac
import hashlib
import struct
from typing import (
    Dict,
    List,
    Optional,
    Sequence,
    Tuple,
)


HARDENED_FLAG = 1 << 31

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def TaggedHash(tag: str, data: bytes):
    ss = hashlib.sha256(tag.encode('utf-8')).digest()
    ss += ss
    ss += data
    return hashlib.sha256(ss).digest()

Point = Optional[Tuple[int, int]]

def H_(x: int) -> int:
    """
    Shortcut function that "hardens" a number in a BIP44 path.
    """
    return x | HARDENED_FLAG

def is_hardened(i: int) -> bool:
    """
    Returns whether an index is hardened
    """
    return i & HARDENED_FLAG != 0


def point_add(p1: Point, p2: Point) -> Point:
    if (p1 is None):
        return p2
    if (p2 is None):
        return p1
    if (p1[0] == p2[0] and p1[1] != p2[1]):
        return None
    if (p1 == p2):
        lam = (3 * p1[0] * p1[0] * pow(2 * p1[1], p - 2, p)) % p
    else:
        lam = ((p2[1] - p1[1]) * pow(p2[0] - p1[0], p - 2, p)) % p
    x3 = (lam * lam - p1[0] - p2[0]) % p
    return (x3, (lam * (p1[0] - x3) - p1[1]) % p)


def point_mul(p: Point, n: int) -> Point:
    r = None
    for i in range(256):
        if ((n >> i) & 1):
            r = point_add(r, p)
        p = point_add(p, p)
    return r


def deserialize_point(b: bytes) -> Point:
    x = int.from_bytes(b[1:], byteorder="big")
    y = pow((x * x * x + 7) % p, (p + 1) // 4, p)
    if (y & 1 != b[0] & 1):
        y = p - y
    return (x, y)


def bytes_to_point(point_bytes: bytes) -> Point:
    header = point_bytes[0]
    if header == 4:
        x = point_bytes = point_bytes[1:33]
        y = point_bytes = point_bytes[33:65]
        return (int(binascii.hexlify(x), 16), int(binascii.hexlify(y), 16))
    return deserialize_point(point_bytes)

def point_to_bytes(p: Point) -> bytes:
    if p is None:
        raise ValueError("Cannot convert None to bytes")
    return (b'\x03' if p[1] & 1 else b'\x02') + p[0].to_bytes(32, byteorder="big")


# An extended public key (xpub) or private key (xprv). Just a data container for now.
# Only handles deserialization of extended keys into component data to be handled by something else
class ExtendedKey(object):
    """
    A BIP 32 extended public key.
    """

    MAINNET_PUBLIC = b'\x04\x88\xB2\x1E'
    MAINNET_PRIVATE = b'\x04\x88\xAD\xE4'
    TESTNET_PUBLIC = b'\x04\x35\x87\xCF'
    TESTNET_PRIVATE = b'\x04\x35\x83\x94'

    def __init__(self, version: bytes, depth: int, parent_fingerprint: bytes, child_num: int, chaincode: bytes, privkey: Optional[bytes], pubkey: bytes) -> None:
        """
        :param version: The version bytes for this xpub
        :param depth: The depth of this xpub as defined in BIP 32
        :param parent_fingerprint: The 4 byte fingerprint of the parent xpub as defined in BIP 32
        :param child_num: The number of this xpub as defined in BIP 32
        :param chaincode: The chaincode of this xpub as defined in BIP 32
        :param privkey: The private key for this xpub if available
        :param pubkey: The public key for this xpub
        """
        self.version: bytes = version
        self.is_testnet: bool = version == ExtendedKey.TESTNET_PUBLIC or version == ExtendedKey.TESTNET_PRIVATE
        self.is_private: bool = version == ExtendedKey.MAINNET_PRIVATE or version == ExtendedKey.TESTNET_PRIVATE
        self.depth: int = depth
        self.parent_fingerprint: bytes = parent_fingerprint
        self.child_num: int = child_num
        self.chaincode: bytes = chaincode
        self.pubkey: bytes = pubkey
        self.privkey: Optional[bytes] = privkey

    @classmethod
    def deserialize(cls, xpub: str) -> 'ExtendedKey':
        """
        Create an :class:`~ExtendedKey` from a Base58 check encoded xpub

        :param xpub: The Base58 check encoded xpub
        """
        data = base58.decode(xpub)[:-4] # Decoded xpub without checksum
        return cls.from_bytes(data)

    @classmethod
    def from_bytes(cls, data: bytes) -> 'ExtendedKey':
        """
        Create an :class:`~ExtendedKey` from a serialized xpub

        :param xpub: The serialized xpub
        """

        version = data[0:4]
        if version not in [ExtendedKey.MAINNET_PRIVATE, ExtendedKey.MAINNET_PUBLIC, ExtendedKey.TESTNET_PRIVATE, ExtendedKey.TESTNET_PUBLIC]:
            raise BadArgumentError(f"Extended key magic of {version.hex()} is invalid")
        is_private = version == ExtendedKey.MAINNET_PRIVATE or version == ExtendedKey.TESTNET_PRIVATE
        depth = data[4]
        parent_fingerprint = data[5:9]
        child_num = struct.unpack('>I', data[9:13])[0]
        chaincode = data[13:45]

        if is_private:
            privkey = data[46:]
            pubkey = point_to_bytes(point_mul(G, int.from_bytes(privkey, byteorder="big")))
            return cls(version, depth, parent_fingerprint, child_num, chaincode, privkey, pubkey)
        else:
            pubkey = data[45:78]
            return cls(version, depth, parent_fingerprint, child_num, chaincode, None, pubkey)

    def serialize(self) -> bytes:
        """
        Serialize the ExtendedKey with the serialization format described in BIP 32.
        Does not create an xpub string, but the bytes serialized here can be Base58 check encoded into one.

        :return: BIP 32 serialized extended key
        """
        r = self.version + struct.pack('B', self.depth) + self.parent_fingerprint + struct.pack('>I', self.child_num) + self.chaincode
        if self.is_private:
            if self.privkey is None:
                raise ValueError("Somehow we are private but don't have a privkey")
            r += b"\x00" + self.privkey
        else:
            r += self.pubkey
        return r

    def to_string(self) -> str:
        """
        Serialize the ExtendedKey as a Base58 check encoded xpub string

        :return: Base58 check encoded xpub
        """
        data = self.serialize()
        checksum = hash256(data)[0:4]
        return base58.encode(data + checksum)

    def get_printable_dict(self) -> Dict[str, object]:
        """
        Get the attributes of this ExtendedKey as a dictionary that can be printed

        :return: Dictionary containing ExtendedKey information that can be printed
        """
        d: Dict[str, object] = {}
        d['testnet'] = self.is_testnet
        d['private'] = self.is_private
        d['depth'] = self.depth
        d['parent_fingerprint'] = binascii.hexlify(self.parent_fingerprint).decode()
        d['child_num'] = self.child_num
        d['chaincode'] = binascii.hexlify(self.chaincode).decode()
        if self.is_private and isinstance(self.privkey, bytes):
            d['privkey'] = binascii.hexlify(self.privkey).decode()
        d['pubkey'] = binascii.hexlify(self.pubkey).decode()
        return d

    def derive_pub(self, i: int) -> 'ExtendedKey':
        """
        Derive the public key at the given child index.

        :param i: The child index of the pubkey to derive
        """
        if is_hardened(i):
            raise ValueError("Index cannot be larger than 2^31")

        # Data to HMAC.  Same as CKDpriv() for public child key.
        data = self.pubkey + struct.pack(">L", i)

        # Get HMAC of data
        Ihmac = hmac.new(self.chaincode, data, hashlib.sha512).digest()
        Il = Ihmac[:32]
        Ir = Ihmac[32:]

        # Construct curve point Il*G+K
        Il_int = int(binascii.hexlify(Il), 16)
        child_pubkey = point_add(point_mul(G, Il_int), bytes_to_point(self.pubkey))

        # Construct and return a new BIP32Key
        pubkey = point_to_bytes(child_pubkey)
        chaincode = Ir
        fingerprint = hash160(self.pubkey)[0:4]
        return ExtendedKey(ExtendedKey.TESTNET_PUBLIC if self.is_testnet else ExtendedKey.MAINNET_PUBLIC, self.depth + 1, fingerprint, i, chaincode, None, pubkey)

    def derive_pub_path(self, path: Sequence[int]) -> 'ExtendedKey':
        """
        Derive the public key at the given path

        :param path: Sequence of integers for the path of the pubkey to derive
        """
        key = self
        for i in path:
            key = key.derive_pub(i)
        return key


class KeyOriginInfo(object):
    """
    Object representing the origin of a key.
    """
    def __init__(self, fingerprint: bytes, path: Sequence[int]) -> None:
        """
        :param fingerprint: The 4 byte BIP 32 fingerprint of a parent key from which this key is derived from
        :param path: The derivation path to reach this key from the key at ``fingerprint``
        """
        self.fingerprint: bytes = fingerprint
        self.path: Sequence[int] = path

    @classmethod
    def deserialize(cls, s: bytes) -> 'KeyOriginInfo':
        """
        Deserialize a serialized KeyOriginInfo.
        They will be serialized in the same way that PSBTs serialize derivation paths
        """
        fingerprint = s[0:4]
        s = s[4:]
        path = list(struct.unpack("<" + "I" * (len(s) // 4), s))
        return cls(fingerprint, path)

    def serialize(self) -> bytes:
        """
        Serializes the KeyOriginInfo in the same way that derivation paths are stored in PSBTs
        """
        r = self.fingerprint
        r += struct.pack("<" + "I" * len(self.path), *self.path)
        return r

    def _path_string(self, hardened_char: str = "h") -> str:
        s = ""
        for i in self.path:
            hardened = is_hardened(i)
            i &= ~HARDENED_FLAG
            s += "/" + str(i)
            if hardened:
                s += hardened_char
        return s

    def to_string(self, hardened_char: str = "h") -> str:
        """
        Return the KeyOriginInfo as a string in the form <fingerprint>/<index>/<index>/...
        This is the same way that KeyOriginInfo is shown in descriptors
        """
        s = binascii.hexlify(self.fingerprint).decode()
        s += self._path_string(hardened_char)
        return s

    @classmethod
    def from_string(cls, s: str) -> 'KeyOriginInfo':
        """
        Create a KeyOriginInfo from the string

        :param s: The string to parse
        """
        s = s.lower()
        entries = s.split("/")
        fingerprint = binascii.unhexlify(s[0:8])
        path: Sequence[int] = []
        if len(entries) > 1:
            path = parse_path(s[9:])
        return cls(fingerprint, path)

    def get_derivation_path(self) -> str:
        """
        Return the string for just the path
        """
        return "m" + self._path_string()

    def get_full_int_list(self) -> List[int]:
        """
        Return a list of ints representing this KeyOriginInfo.
        The first int is the fingerprint, followed by the path
        """
        xfp = [struct.unpack("<I", self.fingerprint)[0]]
        xfp.extend(self.path)
        return xfp


def parse_path(nstr: str) -> List[int]:
    """
    Convert BIP32 path string to list of uint32 integers with hardened flags.
    Several conventions are supported to set the hardened flag: -1, 1', 1h

    e.g.: "0/1h/1" -> [0, 0x80000001, 1]

    :param nstr: path string
    :return: list of integers
    """
    if not nstr:
        return []

    n = nstr.split("/")

    # m/a/b/c => a/b/c
    if n[0] == "m":
        n = n[1:]

    def str_to_harden(x: str) -> int:
        if x.startswith("-"):
            return H_(abs(int(x)))
        elif x.endswith(("h", "'")):
            return H_(int(x[:-1]))
        else:
            return int(x)

    try:
        return [str_to_harden(x) for x in n]
    except Exception:
        raise ValueError("Invalid BIP32 path", nstr)


def get_bip44_purpose(addrtype: AddressType) -> int:
    """
    Determine the BIP 44 purpose based on the given :class:`~hwilib.common.AddressType`.

    :param addrtype: The address type
    """
    if addrtype == AddressType.LEGACY:
        return 44
    elif addrtype == AddressType.SH_WIT:
        return 49
    elif addrtype == AddressType.WIT:
        return 84
    elif addrtype == AddressType.TAP:
        return 86
    else:
        raise ValueError("Unknown address type")


def get_bip44_chain(chain: Chain) -> int:
    """
    Determine the BIP 44 coin type based on the Bitcoin chain type.

    For the Bitcoin mainnet chain, this returns 0. For the other chains, this returns 1.

    :param chain: The chain
    """
    if chain == Chain.MAIN:
        return 0
    else:
        return 1

def get_addrtype_from_bip44_purpose(index: int) -> Optional[AddressType]:
    purpose = index & ~HARDENED_FLAG

    if purpose == 44:
        return AddressType.LEGACY
    elif purpose == 49:
        return AddressType.SH_WIT
    elif purpose == 84:
        return AddressType.WIT
    elif purpose == 86:
        return AddressType.TAP
    else:
        return None

def is_standard_path(
    path: Sequence[int],
    addrtype: AddressType,
    chain: Chain,
) -> bool:
    if len(path) != 5:
        return False
    if not is_hardened(path[0]) or not is_hardened(path[1]) or not is_hardened(path[2]):
        return False
    if is_hardened(path[3]) or is_hardened(path[4]):
        return False
    computed_addrtype = get_addrtype_from_bip44_purpose(path[0])
    if computed_addrtype is None:
        return False
    if computed_addrtype != addrtype:
        return False
    if path[1] != H_(get_bip44_chain(chain)):
        return False
    if path[3] not in [0, 1]:
        return False
    return True


def modinv(a, n):
    """Compute the modular inverse of a modulo n using the extended Euclidean
    Algorithm. See https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Modular_integers.
    """
    # TODO: Change to pow(a, -1, n) available in Python 3.8
    t1, t2 = 0, 1
    r1, r2 = n, a
    while r2 != 0:
        q = r1 // r2
        t1, t2 = t2, t1 - q * t2
        r1, r2 = r2, r1 - q * r2
    if r1 > 1:
        return None
    if t1 < 0:
        t1 += n
    return t1


def jacobi_symbol(n, k):
    """Compute the Jacobi symbol of n modulo k

    See https://en.wikipedia.org/wiki/Jacobi_symbol

    For our application k is always prime, so this is the same as the Legendre symbol."""
    assert k > 0 and k & 1, "jacobi symbol is only defined for positive odd k"
    n %= k
    t = 0
    while n != 0:
        while n & 1 == 0:
            n >>= 1
            r = k & 7
            t ^= (r == 3 or r == 5)
        n, k = k, n
        t ^= (n & k & 3 == 3)
        n = n % k
    if k == 1:
        return -1 if t else 1
    return 0

def modsqrt(a, p):
    """Compute the square root of a modulo p when p % 4 = 3.

    The Tonelli-Shanks algorithm can be used. See https://en.wikipedia.org/wiki/Tonelli-Shanks_algorithm

    Limiting this function to only work for p % 4 = 3 means we don't need to
    iterate through the loop. The highest n such that p - 1 = 2^n Q with Q odd
    is n = 1. Therefore Q = (p-1)/2 and sqrt = a^((Q+1)/2) = a^((p+1)/4)

    secp256k1's is defined over field of size 2**256 - 2**32 - 977, which is 3 mod 4.
    """
    if p % 4 != 3:
        raise NotImplementedError("modsqrt only implemented for p % 4 = 3")
    sqrt = pow(a, (p + 1)//4, p)
    if pow(sqrt, 2, p) == a % p:
        return sqrt
    return None

class EllipticCurve:
    def __init__(self, p, a, b):
        """Initialize elliptic curve y^2 = x^3 + a*x + b over GF(p)."""
        self.p = p
        self.a = a % p
        self.b = b % p

    def affine(self, p1):
        """Convert a Jacobian point tuple p1 to affine form, or None if at infinity.

        An affine point is represented as the Jacobian (x, y, 1)"""
        x1, y1, z1 = p1
        if z1 == 0:
            return None
        inv = modinv(z1, self.p)
        inv_2 = (inv**2) % self.p
        inv_3 = (inv_2 * inv) % self.p
        return ((inv_2 * x1) % self.p, (inv_3 * y1) % self.p, 1)

    def has_even_y(self, p1):
        """Whether the point p1 has an even Y coordinate when expressed in affine coordinates."""
        return not (p1[2] == 0 or self.affine(p1)[1] & 1)

    def negate(self, p1):
        """Negate a Jacobian point tuple p1."""
        x1, y1, z1 = p1
        return (x1, (self.p - y1) % self.p, z1)

    def on_curve(self, p1):
        """Determine whether a Jacobian tuple p is on the curve (and not infinity)"""
        x1, y1, z1 = p1
        z2 = pow(z1, 2, self.p)
        z4 = pow(z2, 2, self.p)
        return z1 != 0 and (pow(x1, 3, self.p) + self.a * x1 * z4 + self.b * z2 * z4 - pow(y1, 2, self.p)) % self.p == 0

    def is_x_coord(self, x):
        """Test whether x is a valid X coordinate on the curve."""
        x_3 = pow(x, 3, self.p)
        return jacobi_symbol(x_3 + self.a * x + self.b, self.p) != -1

    def lift_x(self, x):
        """Given an X coordinate on the curve, return a corresponding affine point for which the Y coordinate is even."""
        x_3 = pow(x, 3, self.p)
        v = x_3 + self.a * x + self.b
        y = modsqrt(v, self.p)
        if y is None:
            return None
        return (x, self.p - y if y & 1 else y, 1)

    def double(self, p1):
        """Double a Jacobian tuple p1

        See https://en.wikibooks.org/wiki/Cryptography/Prime_Curve/Jacobian_Coordinates - Point Doubling"""
        x1, y1, z1 = p1
        if z1 == 0:
            return (0, 1, 0)
        y1_2 = (y1**2) % self.p
        y1_4 = (y1_2**2) % self.p
        x1_2 = (x1**2) % self.p
        s = (4*x1*y1_2) % self.p
        m = 3*x1_2
        if self.a:
            m += self.a * pow(z1, 4, self.p)
        m = m % self.p
        x2 = (m**2 - 2*s) % self.p
        y2 = (m*(s - x2) - 8*y1_4) % self.p
        z2 = (2*y1*z1) % self.p
        return (x2, y2, z2)

    def add_mixed(self, p1, p2):
        """Add a Jacobian tuple p1 and an affine tuple p2

        See https://en.wikibooks.org/wiki/Cryptography/Prime_Curve/Jacobian_Coordinates - Point Addition (with affine point)"""
        x1, y1, z1 = p1
        x2, y2, z2 = p2
        assert(z2 == 1)
        # Adding to the point at infinity is a no-op
        if z1 == 0:
            return p2
        z1_2 = (z1**2) % self.p
        z1_3 = (z1_2 * z1) % self.p
        u2 = (x2 * z1_2) % self.p
        s2 = (y2 * z1_3) % self.p
        if x1 == u2:
            if (y1 != s2):
                # p1 and p2 are inverses. Return the point at infinity.
                return (0, 1, 0)
            # p1 == p2. The formulas below fail when the two points are equal.
            return self.double(p1)
        h = u2 - x1
        r = s2 - y1
        h_2 = (h**2) % self.p
        h_3 = (h_2 * h) % self.p
        u1_h_2 = (x1 * h_2) % self.p
        x3 = (r**2 - h_3 - 2*u1_h_2) % self.p
        y3 = (r*(u1_h_2 - x3) - y1*h_3) % self.p
        z3 = (h*z1) % self.p
        return (x3, y3, z3)

    def add(self, p1, p2):
        """Add two Jacobian tuples p1 and p2

        See https://en.wikibooks.org/wiki/Cryptography/Prime_Curve/Jacobian_Coordinates - Point Addition"""
        x1, y1, z1 = p1
        x2, y2, z2 = p2
        # Adding the point at infinity is a no-op
        if z1 == 0:
            return p2
        if z2 == 0:
            return p1
        # Adding an Affine to a Jacobian is more efficient since we save field multiplications and squarings when z = 1
        if z1 == 1:
            return self.add_mixed(p2, p1)
        if z2 == 1:
            return self.add_mixed(p1, p2)
        z1_2 = (z1**2) % self.p
        z1_3 = (z1_2 * z1) % self.p
        z2_2 = (z2**2) % self.p
        z2_3 = (z2_2 * z2) % self.p
        u1 = (x1 * z2_2) % self.p
        u2 = (x2 * z1_2) % self.p
        s1 = (y1 * z2_3) % self.p
        s2 = (y2 * z1_3) % self.p
        if u1 == u2:
            if (s1 != s2):
                # p1 and p2 are inverses. Return the point at infinity.
                return (0, 1, 0)
            # p1 == p2. The formulas below fail when the two points are equal.
            return self.double(p1)
        h = u2 - u1
        r = s2 - s1
        h_2 = (h**2) % self.p
        h_3 = (h_2 * h) % self.p
        u1_h_2 = (u1 * h_2) % self.p
        x3 = (r**2 - h_3 - 2*u1_h_2) % self.p
        y3 = (r*(u1_h_2 - x3) - s1*h_3) % self.p
        z3 = (h*z1*z2) % self.p
        return (x3, y3, z3)

    def mul(self, ps):
        """Compute a (multi) point multiplication

        ps is a list of (Jacobian tuple, scalar) pairs.
        """
        r = (0, 1, 0)
        for i in range(255, -1, -1):
            r = self.double(r)
            for (p, n) in ps:
                if ((n >> i) & 1):
                    r = self.add(r, p)
        return r


SECP256K1_FIELD_SIZE = 2**256 - 2**32 - 977
SECP256K1 = EllipticCurve(SECP256K1_FIELD_SIZE, 0, 7)
SECP256K1_G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8, 1)
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_ORDER_HALF = SECP256K1_ORDER // 2

class ECPubKey():
    """A secp256k1 public key"""

    def __init__(self):
        """Construct an uninitialized public key"""
        self.valid = False

    def set(self, data):
        """Construct a public key from a serialization in compressed or uncompressed format"""
        if (len(data) == 65 and data[0] == 0x04):
            p = (int.from_bytes(data[1:33], 'big'), int.from_bytes(data[33:65], 'big'), 1)
            self.valid = SECP256K1.on_curve(p)
            if self.valid:
                self.p = p
                self.compressed = False
        elif (len(data) == 33 and (data[0] == 0x02 or data[0] == 0x03)):
            x = int.from_bytes(data[1:33], 'big')
            if SECP256K1.is_x_coord(x):
                p = SECP256K1.lift_x(x)
                # Make the Y coordinate odd if required (lift_x always produces
                # a point with an even Y coordinate).
                if data[0] & 1:
                    p = SECP256K1.negate(p)
                self.p = p
                self.valid = True
                self.compressed = True
            else:
                self.valid = False
        else:
            self.valid = False

    @property
    def is_compressed(self):
        return self.compressed

    @property
    def is_valid(self):
        return self.valid

    def get_bytes(self):
        assert(self.valid)
        p = SECP256K1.affine(self.p)
        if p is None:
            return None
        if self.compressed:
            return bytes([0x02 + (p[1] & 1)]) + p[0].to_bytes(32, 'big')
        else:
            return bytes([0x04]) + p[0].to_bytes(32, 'big') + p[1].to_bytes(32, 'big')

    def verify_ecdsa(self, sig, msg, low_s=True):
        """Verify a strictly DER-encoded ECDSA signature against this pubkey.

        See https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm for the
        ECDSA verifier algorithm"""
        assert(self.valid)

        # Extract r and s from the DER formatted signature. Return false for
        # any DER encoding errors.
        if (sig[1] + 2 != len(sig)):
            return False
        if (len(sig) < 4):
            return False
        if (sig[0] != 0x30):
            return False
        if (sig[2] != 0x02):
            return False
        rlen = sig[3]
        if (len(sig) < 6 + rlen):
            return False
        if rlen < 1 or rlen > 33:
            return False
        if sig[4] >= 0x80:
            return False
        if (rlen > 1 and (sig[4] == 0) and not (sig[5] & 0x80)):
            return False
        r = int.from_bytes(sig[4:4+rlen], 'big')
        if (sig[4+rlen] != 0x02):
            return False
        slen = sig[5+rlen]
        if slen < 1 or slen > 33:
            return False
        if (len(sig) != 6 + rlen + slen):
            return False
        if sig[6+rlen] >= 0x80:
            return False
        if (slen > 1 and (sig[6+rlen] == 0) and not (sig[7+rlen] & 0x80)):
            return False
        s = int.from_bytes(sig[6+rlen:6+rlen+slen], 'big')

        # Verify that r and s are within the group order
        if r < 1 or s < 1 or r >= SECP256K1_ORDER or s >= SECP256K1_ORDER:
            return False
        if low_s and s >= SECP256K1_ORDER_HALF:
            return False
        z = int.from_bytes(msg, 'big')

        # Run verifier algorithm on r, s
        w = modinv(s, SECP256K1_ORDER)
        u1 = z*w % SECP256K1_ORDER
        u2 = r*w % SECP256K1_ORDER
        R = SECP256K1.affine(SECP256K1.mul([(SECP256K1_G, u1), (self.p, u2)]))
        if R is None or (R[0] % SECP256K1_ORDER) != r:
            return False
        return True

def generate_privkey():
    """Generate a valid random 32-byte private key."""
    return random.randrange(1, SECP256K1_ORDER).to_bytes(32, 'big')

def rfc6979_nonce(key):
    """Compute signing nonce using RFC6979."""
    v = bytes([1] * 32)
    k = bytes([0] * 32)
    k = hmac.new(k, v + b"\x00" + key, 'sha256').digest()
    v = hmac.new(k, v, 'sha256').digest()
    k = hmac.new(k, v + b"\x01" + key, 'sha256').digest()
    v = hmac.new(k, v, 'sha256').digest()
    return hmac.new(k, v, 'sha256').digest()

class ECKey():
    """A secp256k1 private key"""

    def __init__(self):
        self.valid = False

    def set(self, secret, compressed):
        """Construct a private key object with given 32-byte secret and compressed flag."""
        assert(len(secret) == 32)
        secret = int.from_bytes(secret, 'big')
        self.valid = (secret > 0 and secret < SECP256K1_ORDER)
        if self.valid:
            self.secret = secret
            self.compressed = compressed

    def generate(self, compressed=True):
        """Generate a random private key (compressed or uncompressed)."""
        self.set(generate_privkey(), compressed)

    def get_bytes(self):
        """Retrieve the 32-byte representation of this key."""
        assert(self.valid)
        return self.secret.to_bytes(32, 'big')

    @property
    def is_valid(self):
        return self.valid

    @property
    def is_compressed(self):
        return self.compressed

    def get_pubkey(self):
        """Compute an ECPubKey object for this secret key."""
        assert(self.valid)
        ret = ECPubKey()
        p = SECP256K1.mul([(SECP256K1_G, self.secret)])
        ret.p = p
        ret.valid = True
        ret.compressed = self.compressed
        return ret

    def sign_ecdsa(self, msg, low_s=True, rfc6979=False):
        """Construct a DER-encoded ECDSA signature with this key.

        See https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm for the
        ECDSA signer algorithm."""
        assert(self.valid)
        z = int.from_bytes(msg, 'big')
        # Note: no RFC6979 by default, but a simple random nonce (some tests rely on distinct transactions for the same operation)
        if rfc6979:
            k = int.from_bytes(rfc6979_nonce(self.secret.to_bytes(32, 'big') + msg), 'big')
        else:
            k = random.randrange(1, SECP256K1_ORDER)
        R = SECP256K1.affine(SECP256K1.mul([(SECP256K1_G, k)]))
        r = R[0] % SECP256K1_ORDER
        s = (modinv(k, SECP256K1_ORDER) * (z + self.secret * r)) % SECP256K1_ORDER
        if low_s and s > SECP256K1_ORDER_HALF:
            s = SECP256K1_ORDER - s
        # Represent in DER format. The byte representations of r and s have
        # length rounded up (255 bits becomes 32 bytes and 256 bits becomes 33
        # bytes).
        rb = r.to_bytes((r.bit_length() + 8) // 8, 'big')
        sb = s.to_bytes((s.bit_length() + 8) // 8, 'big')
        return b'\x30' + bytes([4 + len(rb) + len(sb), 2, len(rb)]) + rb + bytes([2, len(sb)]) + sb


def tweak_add_pubkey(key: bytes, tweak: bytes) -> Optional[Tuple[bytes, bool]]:
    """Tweak a public key and return whether the result had to be negated."""

    assert len(key) == 32
    assert len(tweak) == 32

    x_coord = int.from_bytes(key, 'big')
    if x_coord >= SECP256K1_FIELD_SIZE:
        return None
    P = SECP256K1.lift_x(x_coord)
    if P is None:
        return None
    t = int.from_bytes(tweak, 'big')
    if t >= SECP256K1_ORDER:
        return None
    Q = SECP256K1.affine(SECP256K1.mul([(SECP256K1_G, t), (P, 1)]))
    if Q is None:
        return None
    return (Q[0].to_bytes(32, 'big'), not SECP256K1.has_even_y(Q))

def verify_schnorr(key, sig, msg):
    """Verify a Schnorr signature (see BIP 340).

    - key is a 32-byte xonly pubkey (computed using compute_xonly_pubkey).
    - sig is a 64-byte Schnorr signature
    - msg is a 32-byte message
    """
    assert len(key) == 32
    assert len(msg) == 32
    assert len(sig) == 64

    x_coord = int.from_bytes(key, 'big')
    if x_coord == 0 or x_coord >= SECP256K1_FIELD_SIZE:
        return False
    P = SECP256K1.lift_x(x_coord)
    if P is None:
        return False
    r = int.from_bytes(sig[0:32], 'big')
    if r >= SECP256K1_FIELD_SIZE:
        return False
    s = int.from_bytes(sig[32:64], 'big')
    if s >= SECP256K1_ORDER:
        return False
    e = int.from_bytes(TaggedHash("BIP0340/challenge", sig[0:32] + key + msg), 'big') % SECP256K1_ORDER
    R = SECP256K1.mul([(SECP256K1_G, s), (P, SECP256K1_ORDER - e)])
    if not SECP256K1.has_even_y(R):
        return False
    if ((r * R[2] * R[2]) % SECP256K1_FIELD_SIZE) != R[0]:
        return False
    return True

def sign_schnorr(key, msg, aux=None, flip_p=False, flip_r=False):
    """Create a Schnorr signature (see BIP 340)."""

    if aux is None:
        aux = bytes(32)

    assert len(key) == 32
    assert len(msg) == 32
    assert len(aux) == 32

    sec = int.from_bytes(key, 'big')
    if sec == 0 or sec >= SECP256K1_ORDER:
        return None
    P = SECP256K1.affine(SECP256K1.mul([(SECP256K1_G, sec)]))
    if SECP256K1.has_even_y(P) == flip_p:
        sec = SECP256K1_ORDER - sec
    t = (sec ^ int.from_bytes(TaggedHash("BIP0340/aux", aux), 'big')).to_bytes(32, 'big')
    kp = int.from_bytes(TaggedHash("BIP0340/nonce", t + P[0].to_bytes(32, 'big') + msg), 'big') % SECP256K1_ORDER
    assert kp != 0
    R = SECP256K1.affine(SECP256K1.mul([(SECP256K1_G, kp)]))
    k = kp if SECP256K1.has_even_y(R) != flip_r else SECP256K1_ORDER - kp
    e = int.from_bytes(TaggedHash("BIP0340/challenge", R[0].to_bytes(32, 'big') + P[0].to_bytes(32, 'big') + msg), 'big') % SECP256K1_ORDER
    return R[0].to_bytes(32, 'big') + ((k + e * sec) % SECP256K1_ORDER).to_bytes(32, 'big')
