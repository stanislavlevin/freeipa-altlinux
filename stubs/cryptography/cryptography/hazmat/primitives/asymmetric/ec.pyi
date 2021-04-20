import abc
import typing
from cryptography import utils as utils
from cryptography.hazmat._oid import ObjectIdentifier as ObjectIdentifier
from cryptography.hazmat.backends import _get_backend as _get_backend
from cryptography.hazmat.primitives import _serialization as _serialization, hashes as hashes
from cryptography.hazmat.primitives.asymmetric import AsymmetricSignatureContext as AsymmetricSignatureContext, AsymmetricVerificationContext as AsymmetricVerificationContext, utils as asym_utils
from typing import Any

class EllipticCurveOID:
    SECP192R1: Any = ...
    SECP224R1: Any = ...
    SECP256K1: Any = ...
    SECP256R1: Any = ...
    SECP384R1: Any = ...
    SECP521R1: Any = ...
    BRAINPOOLP256R1: Any = ...
    BRAINPOOLP384R1: Any = ...
    BRAINPOOLP512R1: Any = ...
    SECT163K1: Any = ...
    SECT163R2: Any = ...
    SECT233K1: Any = ...
    SECT233R1: Any = ...
    SECT283K1: Any = ...
    SECT283R1: Any = ...
    SECT409K1: Any = ...
    SECT409R1: Any = ...
    SECT571K1: Any = ...
    SECT571R1: Any = ...

class EllipticCurve(metaclass=abc.ABCMeta):
    @property
    @abc.abstractmethod
    def name(self) -> str: ...
    @property
    @abc.abstractmethod
    def key_size(self) -> int: ...

class EllipticCurveSignatureAlgorithm(metaclass=abc.ABCMeta):
    @property
    @abc.abstractmethod
    def algorithm(self) -> typing.Union[asym_utils.Prehashed, hashes.HashAlgorithm]: ...

class EllipticCurvePrivateKey(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def signer(self, signature_algorithm: EllipticCurveSignatureAlgorithm) -> AsymmetricSignatureContext: ...
    @abc.abstractmethod
    def exchange(self, algorithm: ECDH, peer_public_key: EllipticCurvePublicKey) -> bytes: ...
    @abc.abstractmethod
    def public_key(self) -> EllipticCurvePublicKey: ...
    @property
    @abc.abstractmethod
    def curve(self) -> EllipticCurve: ...
    @property
    @abc.abstractmethod
    def key_size(self) -> int: ...
    @abc.abstractmethod
    def sign(self, data: Any, signature_algorithm: EllipticCurveSignatureAlgorithm) -> bytes: ...
    @abc.abstractmethod
    def private_numbers(self) -> EllipticCurvePrivateNumbers: ...
    @abc.abstractmethod
    def private_bytes(self, encoding: _serialization.Encoding, format: _serialization.PrivateFormat, encryption_algorithm: _serialization.KeySerializationEncryption) -> bytes: ...
EllipticCurvePrivateKeyWithSerialization = EllipticCurvePrivateKey

class EllipticCurvePublicKey(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def verifier(self, signature: bytes, signature_algorithm: EllipticCurveSignatureAlgorithm) -> AsymmetricVerificationContext: ...
    @property
    @abc.abstractmethod
    def curve(self) -> EllipticCurve: ...
    @property
    @abc.abstractmethod
    def key_size(self) -> int: ...
    @abc.abstractmethod
    def public_numbers(self) -> EllipticCurvePublicNumbers: ...
    @abc.abstractmethod
    def public_bytes(self, encoding: _serialization.Encoding, format: _serialization.PublicFormat) -> bytes: ...
    @abc.abstractmethod
    def verify(self, signature: bytes, data: bytes, signature_algorithm: EllipticCurveSignatureAlgorithm) -> None: ...
    @classmethod
    def from_encoded_point(cls: Any, curve: EllipticCurve, data: bytes) -> EllipticCurvePublicKey: ...
EllipticCurvePublicKeyWithSerialization = EllipticCurvePublicKey

class SECT571R1(EllipticCurve):
    name: str = ...
    key_size: int = ...

class SECT409R1(EllipticCurve):
    name: str = ...
    key_size: int = ...

class SECT283R1(EllipticCurve):
    name: str = ...
    key_size: int = ...

class SECT233R1(EllipticCurve):
    name: str = ...
    key_size: int = ...

class SECT163R2(EllipticCurve):
    name: str = ...
    key_size: int = ...

class SECT571K1(EllipticCurve):
    name: str = ...
    key_size: int = ...

class SECT409K1(EllipticCurve):
    name: str = ...
    key_size: int = ...

class SECT283K1(EllipticCurve):
    name: str = ...
    key_size: int = ...

class SECT233K1(EllipticCurve):
    name: str = ...
    key_size: int = ...

class SECT163K1(EllipticCurve):
    name: str = ...
    key_size: int = ...

class SECP521R1(EllipticCurve):
    name: str = ...
    key_size: int = ...

class SECP384R1(EllipticCurve):
    name: str = ...
    key_size: int = ...

class SECP256R1(EllipticCurve):
    name: str = ...
    key_size: int = ...

class SECP256K1(EllipticCurve):
    name: str = ...
    key_size: int = ...

class SECP224R1(EllipticCurve):
    name: str = ...
    key_size: int = ...

class SECP192R1(EllipticCurve):
    name: str = ...
    key_size: int = ...

class BrainpoolP256R1(EllipticCurve):
    name: str = ...
    key_size: int = ...

class BrainpoolP384R1(EllipticCurve):
    name: str = ...
    key_size: int = ...

class BrainpoolP512R1(EllipticCurve):
    name: str = ...
    key_size: int = ...

_CURVE_TYPES: typing.Dict[str, typing.Type[EllipticCurve]]

class ECDSA(EllipticCurveSignatureAlgorithm):
    _algorithm: Any = ...
    def __init__(self, algorithm: Any) -> None: ...
    algorithm: Any = ...

def generate_private_key(curve: EllipticCurve, backend: Any=...) -> EllipticCurvePrivateKey: ...
def derive_private_key(private_value: int, curve: EllipticCurve, backend: Any=...) -> EllipticCurvePrivateKey: ...

class EllipticCurvePublicNumbers:
    _y: Any = ...
    _x: Any = ...
    _curve: Any = ...
    def __init__(self, x: int, y: int, curve: EllipticCurve) -> None: ...
    def public_key(self, backend: Any=...) -> EllipticCurvePublicKey: ...
    def encode_point(self) -> bytes: ...
    @classmethod
    def from_encoded_point(cls: Any, curve: EllipticCurve, data: bytes) -> EllipticCurvePublicNumbers: ...
    curve: Any = ...
    x: Any = ...
    y: Any = ...
    def __eq__(self, other: Any) -> Any: ...
    def __ne__(self, other: Any) -> Any: ...
    def __hash__(self) -> Any: ...
    def __repr__(self): ...

class EllipticCurvePrivateNumbers:
    _private_value: Any = ...
    _public_numbers: Any = ...
    def __init__(self, private_value: int, public_numbers: EllipticCurvePublicNumbers) -> None: ...
    def private_key(self, backend: Any=...) -> EllipticCurvePrivateKey: ...
    private_value: Any = ...
    public_numbers: Any = ...
    def __eq__(self, other: Any) -> Any: ...
    def __ne__(self, other: Any) -> Any: ...
    def __hash__(self) -> Any: ...

class ECDH: ...

_OID_TO_CURVE: Any

def get_curve_for_oid(oid: ObjectIdentifier) -> typing.Type[EllipticCurve]: ...
