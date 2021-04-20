import datetime
import typing
from cryptography import utils as utils, x509 as x509
from cryptography.exceptions import UnsupportedAlgorithm as UnsupportedAlgorithm
from cryptography.hazmat.backends.openssl import dsa as dsa, ec as ec, rsa as rsa
from cryptography.hazmat.backends.openssl.decode_asn1 import _asn1_integer_to_int as _asn1_integer_to_int, _asn1_string_to_bytes as _asn1_string_to_bytes, _decode_x509_name as _decode_x509_name, _obj2txt as _obj2txt, _parse_asn1_time as _parse_asn1_time
from cryptography.hazmat.backends.openssl.encode_asn1 import _encode_asn1_int_gc as _encode_asn1_int_gc, _txt2obj_gc as _txt2obj_gc
from cryptography.hazmat.primitives import hashes as hashes, serialization as serialization
from cryptography.x509.base import _PUBLIC_KEY_TYPES as _PUBLIC_KEY_TYPES
from cryptography.x509.name import _ASN1Type as _ASN1Type
from typing import Any

class _Certificate(x509.Certificate):
    _ocsp_resp_ref: typing.Any
    _backend: Any = ...
    _x509: Any = ...
    _version: Any = ...
    def __init__(self, backend: Any, x509_cert: Any) -> None: ...
    def __repr__(self): ...
    def __eq__(self, other: object) -> bool: ...
    def __ne__(self, other: object) -> bool: ...
    def __hash__(self) -> int: ...
    def __deepcopy__(self, memo: Any): ...
    def fingerprint(self, algorithm: hashes.HashAlgorithm) -> bytes: ...
    version: Any = ...
    @property
    def serial_number(self) -> int: ...
    def public_key(self) -> _PUBLIC_KEY_TYPES: ...
    @property
    def not_valid_before(self) -> datetime.datetime: ...
    @property
    def not_valid_after(self) -> datetime.datetime: ...
    @property
    def issuer(self) -> x509.Name: ...
    @property
    def subject(self) -> x509.Name: ...
    @property
    def signature_hash_algorithm(self) -> typing.Optional[hashes.HashAlgorithm]: ...
    @property
    def signature_algorithm_oid(self) -> x509.ObjectIdentifier: ...
    def extensions(self) -> x509.Extensions: ...
    @property
    def signature(self) -> bytes: ...
    @property
    def tbs_certificate_bytes(self) -> bytes: ...
    def public_bytes(self, encoding: serialization.Encoding) -> bytes: ...

class _RevokedCertificate(x509.RevokedCertificate):
    _backend: Any = ...
    _crl: Any = ...
    _x509_revoked: Any = ...
    def __init__(self, backend: Any, crl: Any, x509_revoked: Any) -> None: ...
    @property
    def serial_number(self) -> int: ...
    @property
    def revocation_date(self) -> datetime.datetime: ...
    def extensions(self) -> x509.Extensions: ...

class _CertificateRevocationList:
    _backend: Any = ...
    _x509_crl: Any = ...
    def __init__(self, backend: Any, x509_crl: Any) -> None: ...
    def __eq__(self, other: object) -> bool: ...
    def __ne__(self, other: object) -> bool: ...
    def fingerprint(self, algorithm: hashes.HashAlgorithm) -> bytes: ...
    def _sorted_crl(self): ...
    def get_revoked_certificate_by_serial_number(self, serial_number: int) -> typing.Optional[x509.RevokedCertificate]: ...
    @property
    def signature_hash_algorithm(self) -> typing.Optional[hashes.HashAlgorithm]: ...
    @property
    def signature_algorithm_oid(self) -> x509.ObjectIdentifier: ...
    @property
    def issuer(self) -> x509.Name: ...
    @property
    def next_update(self) -> datetime.datetime: ...
    @property
    def last_update(self) -> datetime.datetime: ...
    @property
    def signature(self) -> bytes: ...
    @property
    def tbs_certlist_bytes(self) -> bytes: ...
    def public_bytes(self, encoding: serialization.Encoding) -> bytes: ...
    def _revoked_cert(self, idx: Any): ...
    def __iter__(self) -> Any: ...
    def __getitem__(self, idx: Any): ...
    def __len__(self) -> int: ...
    def extensions(self) -> x509.Extensions: ...
    def is_signature_valid(self, public_key: _PUBLIC_KEY_TYPES) -> bool: ...

class _CertificateSigningRequest:
    _backend: Any = ...
    _x509_req: Any = ...
    def __init__(self, backend: Any, x509_req: Any) -> None: ...
    def __eq__(self, other: object) -> bool: ...
    def __ne__(self, other: object) -> bool: ...
    def __hash__(self) -> int: ...
    def public_key(self) -> _PUBLIC_KEY_TYPES: ...
    @property
    def subject(self) -> x509.Name: ...
    @property
    def signature_hash_algorithm(self) -> typing.Optional[hashes.HashAlgorithm]: ...
    @property
    def signature_algorithm_oid(self) -> x509.ObjectIdentifier: ...
    def extensions(self) -> x509.Extensions: ...
    def public_bytes(self, encoding: serialization.Encoding) -> bytes: ...
    @property
    def tbs_certrequest_bytes(self) -> bytes: ...
    @property
    def signature(self) -> bytes: ...
    @property
    def is_signature_valid(self) -> bool: ...
    def get_attribute_for_oid(self, oid: x509.ObjectIdentifier) -> bytes: ...

class _SignedCertificateTimestamp:
    _backend: Any = ...
    _sct_list: Any = ...
    _sct: Any = ...
    def __init__(self, backend: Any, sct_list: Any, sct: Any) -> None: ...
    @property
    def version(self) -> x509.certificate_transparency.Version: ...
    @property
    def log_id(self) -> bytes: ...
    @property
    def timestamp(self) -> datetime.datetime: ...
    @property
    def entry_type(self) -> x509.certificate_transparency.LogEntryType: ...
    @property
    def _signature(self): ...
    def __hash__(self) -> int: ...
    def __eq__(self, other: object) -> bool: ...
    def __ne__(self, other: object) -> bool: ...
