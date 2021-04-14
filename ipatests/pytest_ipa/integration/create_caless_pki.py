# Copyright (c) 2015-2017, Jan Cholasta <jcholast@redhat.com>
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
from __future__ import annotations

import datetime
import itertools
import os
import os.path
import six

from cryptography import __version__ as cryptography_version
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from pkg_resources import parse_version
from pyasn1.type import univ, char, namedtype, tag
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.codec.native import decoder as native_decoder

from typing import Iterator, NamedTuple, TYPE_CHECKING

if TYPE_CHECKING:
    from typing import (
        Any, List, Optional, Protocol, TypeVar
    )
    from cryptography.x509.general_name import GeneralName
    from cryptography.x509 import Certificate, CertificateBuilder, Name
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

    class Profile(Protocol):
        def __call__(
            self,
            builder: CertificateBuilder,
            ca_nick: str,
            ca: Optional[CertInfo],
            **kwargs: Any,
        ) -> CertificateBuilder:
            ...


if six.PY3:
    unicode = str

DAY = datetime.timedelta(days=1)
YEAR = 365 * DAY

# we get the variables from ca_less test
domain: Optional[str] = None
realm: Optional[str] = None
server1: Optional[str] = None
server2: Optional[str] = None
client: Optional[str] = None
password: Optional[str] = None
cert_dir: Optional[str] = None


class CertInfo(NamedTuple):
    nick: str
    key: RSAPrivateKey
    cert: Certificate
    counter: Iterator[int]


class PrincipalName(univ.Sequence):
    '''See RFC 4120 for details'''
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'name-type',
            univ.Integer().subtype(
                explicitTag=tag.Tag(
                    tag.tagClassContext,
                    tag.tagFormatSimple,
                    0,
                ),
            ),
        ),
        namedtype.NamedType(
            'name-string',
            univ.SequenceOf(char.GeneralString()).subtype(
                explicitTag=tag.Tag(
                    tag.tagClassContext,
                    tag.tagFormatSimple,
                    1,
                ),
            ),
        ),
    )


class KRB5PrincipalName(univ.Sequence):
    '''See RFC 4556 for details'''
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'realm',
            char.GeneralString().subtype(
                explicitTag=tag.Tag(
                    tag.tagClassContext,
                    tag.tagFormatSimple,
                    0,
                ),
            ),
        ),
        namedtype.NamedType(
            'principalName',
            PrincipalName().subtype(
                explicitTag=tag.Tag(
                    tag.tagClassContext,
                    tag.tagFormatSimple,
                    1,
                ),
            ),
        ),
    )


def profile_ca(
    builder: CertificateBuilder,
    ca_nick: str,
    ca: Optional[CertInfo],
    **kwargs: Any,
) -> CertificateBuilder:
    assert cert_dir is not None  # cast out Optional mypy#645

    now = datetime.datetime.utcnow()

    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + 10 * YEAR)

    crl_uri = u'file://{}.crl'.format(os.path.join(cert_dir, ca_nick))

    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=True,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    )
    builder = builder.add_extension(
        x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(crl_uri)],
                    relative_name=None,
                    crl_issuer=None,
                    reasons=None,
                ),
        ]),
        critical=False,
    )

    public_key = builder._public_key

    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(public_key),
        critical=False,
    )
    # here we get "ca" only for "ca1/subca" CA
    if not ca:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key),
            critical=False,
        )
    else:
        ski_ext = ca.cert.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        )
        auth_keyidentifier = (x509.AuthorityKeyIdentifier
                              .from_issuer_subject_key_identifier)
        '''
        cryptography < 2.7 accepts only Extension object.
        Remove this workaround when all supported platforms update
        python-cryptography.
        '''
        if (parse_version(cryptography_version) >= parse_version('2.7')):
            extension = auth_keyidentifier(ski_ext.value)
        else:
            extension = auth_keyidentifier(ski_ext)  # type: ignore[arg-type]

        builder = builder.add_extension(extension, critical=False)
    return builder


def profile_server(
    builder: CertificateBuilder,
    ca_nick: str,
    ca: Optional[CertInfo],
    **kwargs: Any,
) -> CertificateBuilder:
    warp: datetime.timedelta = kwargs.get("warp", datetime.timedelta(days=0))
    dns_name: Optional[str] = kwargs.get("dns_name")
    badusage: bool = kwargs.get("badusage", False)
    wildcard: bool = kwargs.get("wildcard", False)
    assert cert_dir is not None  # cast out Optional mypy#645
    assert domain is not None  # cast out Optional mypy#645
    assert server1 is not None  # cast out Optional mypy#645

    now = datetime.datetime.utcnow() + warp

    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + YEAR)

    crl_uri = u'file://{}.crl'.format(os.path.join(cert_dir, ca_nick))

    builder = builder.add_extension(
        x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(crl_uri)],
                    relative_name=None,
                    crl_issuer=None,
                    reasons=None,
                ),
        ]),
        critical=False,
    )

    if dns_name is not None:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(dns_name)]),
            critical=False,
        )

    if badusage:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=True,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=False
        )

    if wildcard:
        names = [x509.DNSName(u'*.' + domain)]
        server_split = server1.split('.', 1)
        if len(server_split) == 2 and domain != server_split[1]:
            names.append(x509.DNSName(u'*.' + server_split[1]))
        builder = builder.add_extension(
            x509.SubjectAlternativeName(names),
            critical=False,
        )

    return builder


def profile_kdc(
    builder: CertificateBuilder,
    ca_nick: str,
    ca: Optional[CertInfo],
    **kwargs: Any,
) -> CertificateBuilder:
    warp: datetime.timedelta = kwargs.get("warp", datetime.timedelta(days=0))
    dns_name: Optional[str] = kwargs.get("dns_name")
    badusage: bool = kwargs.get("badusage", False)

    assert cert_dir is not None  # cast out Optional mypy#645
    assert realm is not None  # cast out Optional mypy#645

    now = datetime.datetime.utcnow() + warp

    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + YEAR)

    crl_uri = u'file://{}.crl'.format(os.path.join(cert_dir, ca_nick))

    builder = builder.add_extension(
        x509.ExtendedKeyUsage([x509.ObjectIdentifier('1.3.6.1.5.2.3.5')]),
        critical=False,
    )

    name = {
        'realm': realm,
        'principalName': {
            'name-type': 2,
            'name-string': ['krbtgt', realm],
        },
    }
    name = native_decoder.decode(name, asn1Spec=KRB5PrincipalName())
    name_der: bytes = der_encoder.encode(name)

    names: List[GeneralName] = [
        x509.OtherName(x509.ObjectIdentifier('1.3.6.1.5.2.2'), name_der)
    ]
    if dns_name is not None:
        names += [x509.DNSName(dns_name)]

    builder = builder.add_extension(
        x509.SubjectAlternativeName(names),
        critical=False,
    )

    builder = builder.add_extension(
        x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(crl_uri)],
                    relative_name=None,
                    crl_issuer=None,
                    reasons=None,
                ),
        ]),
        critical=False,
    )

    if badusage:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=True,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=False
        )

    return builder


def gen_cert(
    profile: Profile,
    nick_base: str,
    subject: Name,
    ca: Optional[CertInfo] = None,
    **kwargs: Any,
) -> CertInfo:
    assert cert_dir is not None  # cast out Optional mypy#645
    assert password is not None  # cast out Optional mypy#645

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    public_key = key.public_key()

    counter = itertools.count(1)

    if ca is not None:
        ca_nick, ca_key, ca_cert, ca_counter = ca
        nick = os.path.join(ca_nick, nick_base)
        issuer = ca_cert.subject
    else:
        nick = ca_nick = nick_base
        ca_key = key
        ca_counter = counter
        issuer = subject

    serial = next(ca_counter)

    builder = x509.CertificateBuilder()
    builder = builder.serial_number(serial)
    builder = builder.issuer_name(issuer)
    builder = builder.subject_name(subject)
    builder = builder.public_key(public_key)
    builder = profile(builder, ca_nick, ca, **kwargs)

    cert = builder.sign(
        private_key=ca_key,
        algorithm=hashes.SHA256(),
        backend=default_backend(),
    )

    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password.encode()),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    try:
        os.makedirs(os.path.dirname(os.path.join(cert_dir, nick)))
    except OSError:
        pass
    with open(os.path.join(cert_dir, nick + '.key'), 'wb') as f:
        f.write(key_pem)
    with open(os.path.join(cert_dir, nick + '.crt'), 'wb') as f:
        f.write(cert_pem)

    return CertInfo(nick, key, cert, counter)


def revoke_cert(ca: CertInfo, serial: int) -> None:
    assert cert_dir is not None  # cast out Optional mypy#645
    now = datetime.datetime.utcnow()

    crl_builder = x509.CertificateRevocationListBuilder()
    crl_builder = crl_builder.issuer_name(ca.cert.subject)
    crl_builder = crl_builder.last_update(now)
    crl_builder = crl_builder.next_update(now + DAY)

    crl_filename = os.path.join(cert_dir, ca.nick + '.crl')

    try:
        f = open(crl_filename, 'rb')
    except IOError:
        pass
    else:
        with f:
            crl_pem = f.read()

        crl = x509.load_pem_x509_crl(crl_pem, default_backend())

        for revoked_cert in crl:
            crl_builder = crl_builder.add_revoked_certificate(revoked_cert)

    builder = x509.RevokedCertificateBuilder()
    builder = builder.serial_number(serial)
    builder = builder.revocation_date(now)

    revoked_cert = builder.build(default_backend())

    crl_builder = crl_builder.add_revoked_certificate(revoked_cert)

    crl = crl_builder.sign(
        private_key=ca.key,
        algorithm=hashes.SHA256(),
        backend=default_backend(),
    )

    crl_pem = crl.public_bytes(serialization.Encoding.PEM)

    with open(crl_filename, 'wb') as f:
        f.write(crl_pem)


def gen_server_certs(
    nick_base: str, hostname: str, org: str, ca: CertInfo
) -> None:
    gen_cert(profile_server, nick_base,
             x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
                x509.NameAttribute(NameOID.COMMON_NAME, hostname)
             ]),
             ca, dns_name=hostname
             )
    gen_cert(profile_server, nick_base + u'-badname',
             x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
                x509.NameAttribute(NameOID.COMMON_NAME, u'not-' + hostname)
             ]),
             ca, dns_name=u'not-' + hostname
             )
    gen_cert(profile_server, nick_base + u'-altname',
             x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
                x509.NameAttribute(NameOID.COMMON_NAME, u'alt-' + hostname)
             ]),
             ca, dns_name=hostname
             )
    gen_cert(profile_server, nick_base + u'-expired',
             x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,
                                   u'Expired'),
                x509.NameAttribute(NameOID.COMMON_NAME, hostname)
             ]),
             ca, dns_name=hostname, warp=-2 * YEAR
             )
    gen_cert(
        profile_server, nick_base + u'-not-yet-valid',
        x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u'Future'),
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ]),
        ca, dns_name=hostname, warp=1 * DAY,
    )
    gen_cert(profile_server, nick_base + u'-badusage',
             x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,
                                   u'Bad Usage'),
                x509.NameAttribute(NameOID.COMMON_NAME, hostname)
             ]),
             ca, dns_name=hostname, badusage=True
             )
    revoked = gen_cert(profile_server, nick_base + u'-revoked',
                       x509.Name([
                           x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
                           x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,
                                              u'Revoked'),
                           x509.NameAttribute(NameOID.COMMON_NAME, hostname)
                       ]),
                       ca, dns_name=hostname
                       )
    revoke_cert(ca, revoked.cert.serial_number)


def gen_kdc_certs(
    nick_base: str, hostname: str, org: str, ca: CertInfo
) -> None:
    gen_cert(profile_kdc, nick_base + u'-kdc',
             x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u'KDC'),
                x509.NameAttribute(NameOID.COMMON_NAME, hostname)
             ]),
             ca
             )
    gen_cert(profile_kdc, nick_base + u'-kdc-badname',
             x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u'KDC'),
                x509.NameAttribute(NameOID.COMMON_NAME, u'not-' + hostname)
             ]),
             ca
             )
    gen_cert(profile_kdc, nick_base + u'-kdc-altname',
             x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u'KDC'),
                x509.NameAttribute(NameOID.COMMON_NAME, u'alt-' + hostname)
             ]),
             ca, dns_name=hostname
             )
    gen_cert(profile_kdc, nick_base + u'-kdc-expired',
             x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,
                                   u'Expired KDC'),
                x509.NameAttribute(NameOID.COMMON_NAME, hostname)
             ]),
             ca, warp=-2 * YEAR
             )
    gen_cert(profile_kdc, nick_base + u'-kdc-badusage',
             x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,
                                   u'Bad Usage KDC'),
                x509.NameAttribute(NameOID.COMMON_NAME, hostname)
             ]),
             ca, badusage=True
             )
    revoked = gen_cert(profile_kdc, nick_base + u'-kdc-revoked',
                       x509.Name([
                           x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
                           x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,
                                              u'Revoked KDC'),
                           x509.NameAttribute(NameOID.COMMON_NAME, hostname)
                       ]),
                       ca
                       )
    revoke_cert(ca, revoked.cert.serial_number)


def gen_subtree(
    nick_base: str, org: str, ca: Optional[CertInfo] = None
) -> CertInfo:
    assert domain is not None  # cast out Optional mypy#645
    assert server1 is not None  # cast out Optional mypy#645
    assert server2 is not None  # cast out Optional mypy#645
    assert client is not None  # cast out Optional mypy#645

    subca = gen_cert(profile_ca, nick_base,
                     x509.Name([
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
                        x509.NameAttribute(NameOID.COMMON_NAME, u'CA')
                     ]),
                     ca
                     )
    gen_cert(profile_server, u'wildcard',
             x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
                x509.NameAttribute(NameOID.COMMON_NAME, u'*.' + domain)
             ]),
             subca, wildcard=True
             )
    gen_server_certs(u'server', server1, org, subca)
    gen_server_certs(u'replica', server2, org, subca)
    gen_server_certs(u'client', client, org, subca)
    gen_cert(profile_kdc, u'kdcwildcard',
             x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
                x509.NameAttribute(NameOID.COMMON_NAME, u'*.' + domain)
             ]),
             subca
             )
    gen_kdc_certs(u'server', server1, org, subca)
    gen_kdc_certs(u'replica', server2, org, subca)
    gen_kdc_certs(u'client', client, org, subca)
    return subca


def create_pki() -> None:
    assert cert_dir is not None  # cast out Optional mypy#645
    assert server1 is not None  # cast out Optional mypy#645
    assert server2 is not None  # cast out Optional mypy#645

    gen_cert(profile_server, u'server-selfsign',
             x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'Self-signed'),
                x509.NameAttribute(NameOID.COMMON_NAME, server1)
             ])
             )
    gen_cert(profile_server, u'replica-selfsign',
             x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'Self-signed'),
                x509.NameAttribute(NameOID.COMMON_NAME, server2)
             ])
             )
    gen_cert(profile_server, u'noca',
             x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'No-CA'),
                x509.NameAttribute(NameOID.COMMON_NAME, server1)
             ])
             )
    gen_cert(profile_kdc, u'server-kdc-selfsign',
             x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'Self-signed'),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u'KDC'),
                x509.NameAttribute(NameOID.COMMON_NAME, server1)
             ])
             )
    gen_cert(profile_kdc, u'replica-kdc-selfsign',
             x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'Self-signed'),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u'KDC'),
                x509.NameAttribute(NameOID.COMMON_NAME, server2)
             ])
             )
    ca1 = gen_subtree(u'ca1', u'Example Organization')
    gen_subtree(u'subca', u'Subsidiary Example Organization', ca1)
    gen_subtree(u'ca2', u'Other Example Organization')
    ca3 = gen_subtree(u'ca3', u'Unknown Organization')
    os.unlink(os.path.join(cert_dir, ca3.nick + '.key'))
    os.unlink(os.path.join(cert_dir, ca3.nick + '.crt'))
