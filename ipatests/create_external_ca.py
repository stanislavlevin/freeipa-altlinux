#
# Copyright (C) 2017  FreeIPA Contributors see COPYING for license
#
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
from __future__ import annotations

import argparse

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

import datetime

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Iterable, Optional

    from cryptography.x509 import Name, Certificate, CertificateBuilder
    from cryptography.x509.extensions import ExtensionType
    from cryptography.hazmat.primitives.asymmetric.rsa import (
        RSAPrivateKey,
        RSAPublicKey,
    )

ISSUER_CN = 'example.test'


class ExternalCA:
    """Provide external CA for testing
    """

    def __init__(
        self, days: int = 365, key_size: Optional[int] = None
    ) -> None:
        self.now = datetime.datetime.utcnow()
        self.delta = datetime.timedelta(days=days)
        self.ca_key: Optional[RSAPrivateKey] = None
        self.ca_public_key: Optional[RSAPublicKey] = None
        self.issuer: Optional[Name] = None
        self.key_size = key_size or 2048

    def create_ca_key(self) -> None:
        """Create private and public key for CA

        Note: The test still creates 2048 although IPA CA uses 3072 bit RSA
        by default. This also tests that IPA supports an external signing CA
        with weaker keys than the IPA base CA.
        """
        self.ca_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=default_backend(),
        )
        self.ca_public_key = self.ca_key.public_key()

    def sign(self, builder: CertificateBuilder) -> Certificate:
        assert self.ca_key is not None  # cast out Optional mypy#645
        return builder.sign(
            private_key=self.ca_key,
            algorithm=hashes.SHA256(),
            backend=default_backend(),
        )

    def create_ca(
        self,
        cn: str = ISSUER_CN,
        path_length: Optional[int] = None,
        extensions: Iterable[ExtensionType] = (),
    ) -> bytes:
        """Create root CA.

        :returns: bytes -- Root CA in PEM format.
        """
        if self.ca_key is None or self.ca_public_key is None:
            self.create_ca_key()

        assert self.ca_key is not None  # cast out Optional mypy#645
        assert self.ca_public_key is not None  # cast out Optional mypy#645

        subject = self.issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, str(cn)),
        ])

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(self.issuer)
        builder = builder.public_key(self.ca_public_key)
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(self.now)
        builder = builder.not_valid_after(self.now + self.delta)

        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
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
            x509.BasicConstraints(ca=True, path_length=path_length),
            critical=True,
        )

        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(self.ca_public_key),
            critical=False,
        )

        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                 self.ca_public_key
                 ),
            critical=False,
        )

        for extension in extensions:
            builder = builder.add_extension(extension, critical=False)

        cert = builder.sign(self.ca_key, hashes.SHA256(), default_backend())

        return cert.public_bytes(serialization.Encoding.PEM)

    def sign_csr(
        self, ipa_csr: bytes, path_length: Optional[int] = 1
    ) -> bytes:
        """Sign certificate CSR.

        :param ipa_csr: CSR in PEM format.
        :type ipa_csr: bytes.
        :returns: bytes -- Signed CA in PEM format.
        """
        assert self.issuer is not None  # cast out Optional mypy#645
        assert self.ca_public_key is not None  # cast out Optional mypy#645

        csr_tbs = x509.load_pem_x509_csr(ipa_csr, default_backend())

        csr_public_key = csr_tbs.public_key()
        csr_subject = csr_tbs.subject

        builder = x509.CertificateBuilder()
        builder = builder.public_key(csr_public_key)
        builder = builder.subject_name(csr_subject)
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.issuer_name(self.issuer)
        builder = builder.not_valid_before(self.now)
        builder = builder.not_valid_after(self.now + self.delta)

        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
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
            x509.SubjectKeyIdentifier.from_public_key(csr_public_key),
            critical=False,
        )

        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                 self.ca_public_key
                 ),
            critical=False,
        )

        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length),
            critical=True,
        )

        cert = self.sign(builder)

        return cert.public_bytes(serialization.Encoding.PEM)


def main() -> None:
    IPA_CSR = '/root/ipa.csr'
    ROOT_CA = '/tmp/rootca.pem'
    IPA_CA = '/tmp/ipaca.pem'
    parser = argparse.ArgumentParser("Create external CA")
    parser.add_argument(
        '--csr', type=argparse.FileType('rb'), default=IPA_CSR,
        help="Path to ipa.csr (default: {})".format(IPA_CSR)
    )
    parser.add_argument(
        '--rootca', type=argparse.FileType('wb'), default=ROOT_CA,
        help="New root CA file (default: {})".format(ROOT_CA)
    )
    parser.add_argument(
        '--ipaca', type=argparse.FileType('wb'), default=IPA_CA,
        help="New IPA CA file (default: {})".format(ROOT_CA)
    )

    args = parser.parse_args()

    with args.csr as f:
        ipa_csr = f.read()

    external_ca = ExternalCA()
    root_ca = external_ca.create_ca()
    ipa_ca = external_ca.sign_csr(ipa_csr)

    with args.rootca as f:
        f.write(root_ca)

    with args.ipaca as f:
        f.write(ipa_ca)

    o = "ipa-server-install --external-cert-file={} --external-cert-file={}"
    print(o.format(args.rootca.name, args.ipaca.name))


if __name__ == '__main__':
    main()
