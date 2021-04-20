import typing
from cryptography import x509 as x509
from cryptography.hazmat.backends import _get_backend as _get_backend
from cryptography.hazmat.primitives import serialization as serialization
from cryptography.hazmat.primitives.asymmetric import dsa as dsa, ec as ec, rsa as rsa
from typing import Any

_ALLOWED_PKCS12_TYPES: Any

def load_key_and_certificates(data: bytes, password: typing.Optional[bytes], backend: Any=...) -> typing.Tuple[typing.Optional[_ALLOWED_PKCS12_TYPES], typing.Optional[x509.Certificate], typing.List[x509.Certificate]]: ...
def serialize_key_and_certificates(name: typing.Optional[bytes], key: typing.Optional[_ALLOWED_PKCS12_TYPES], cert: typing.Optional[x509.Certificate], cas: typing.Optional[typing.Iterable[x509.Certificate]], encryption_algorithm: serialization.KeySerializationEncryption) -> bytes: ...
