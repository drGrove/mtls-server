import datetime
import logging
import os
import uuid

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import gnupg


class CertProcessorKeyNotFoundError(Exception):
    pass


class CertProcessorInvalidSignatureError(Exception):
    pass


class CertProcessor:
    def __init__(self, config):
        gnupg_path = config.get('mtls', 'gnupg_home')
        if not os.path.isabs(gnupg_path):
            gnupg_path = os.path.abspath(
                os.path.join(
                    os.path.dirname(__file__), gnupg_path
                )
            )
        self.gpg = gnupg.GPG(gnupghome=gnupg_path)
        self.gpg.encoding = 'utf-8'
        self.config = config

    def encrypt(self, data, recipients, sign=False):
        return self.gpg.encrypt(data, recipients, sign=sign)

    def decrypt(self, data):
        fingerprint = None
        try:
            data = self.gpg.decrypt(data)
            fingerprint = data.fingerprint
        except Exception as e:
            logging.error(e)
            data = None
        if data.ok is False:
            logging.error(data.status)
            data = None
        return data, fingerprint

    def verify(self, csr, signature):
        verified = self.gpg.verify_data(signature,
                                        csr)
        if not verified.valid:
            logging.error(str(verified.trust_level))
            raise CertProcessorInvalidSignatureError

    def get_csr(self, csr):
        try:
            return x509.load_pem_x509_csr(bytes(csr, 'utf-8'),
                                          default_backend())
        except Exception as e:
            logging.error(e)
            return None

    def get_ca_key(self):
        ca_key_path = self.config.get('mtls', 'ca_key')
        if not os.path.isabs(ca_key_path):
            ca_key_path = os.path.abspath(
                os.path.join(
                    os.path.dirname(__file__),
                    ca_key_path
                )
            )
        try:
            with open(ca_key_path, 'rb') as key_file:
                ca_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )
                return ca_key
        except IOError:
            logging.error('Erroring opening file: {}'.format(ca_key_path))
            raise CertProcessorKeyNotFoundError()

    def get_ca_crt(self):
        ca_crt_path = self.config.get('mtls', 'ca_cert')
        if not os.path.isabs(ca_crt_path):
            ca_cert_path = os.path.abspath(
                os.path.join(
                    os.path.dirname(__file__),
                    ca_crt_path
                )
            )
        try:
            with open(ca_crt_path, 'rb') as crt_file:
                ca_crt = x509.load_pem_x509_certificate(
                    crt_file.read(),
                    default_backend()
                )
                return ca_crt
        except IOError:
            logging.error('Erroring opening file: {}'.format(ca_key_path))
            raise CertProcessorKeyNotFoundError()

    def generate_cert(self, csr, lifetime):
        ca_pkey = self.get_ca_key()
        ca_crt = self.get_ca_crt()
        now = datetime.datetime.utcnow()
        lifetime_delta = now + datetime.timedelta(hours=int(lifetime))
        alts = []
        for alt in self.config.get('mtls', 'alternate_name').split(','):
            alts.append(x509.DNSName(u'{}'.format(alt)))
        crt = x509.CertificateBuilder().subject_name(
            csr.subject
        ).issuer_name(
            ca_crt.subject
        ).public_key(
            csr.public_key()
        ).serial_number(
            uuid.uuid4().int
        ).not_valid_before(
           now
        ).not_valid_after(
            lifetime_delta
        ).add_extension(
            extension=x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=True,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
                key_cert_sign=True,
                crl_sign=False
            ),
            critical=True
        ).add_extension(
            extension=x509.BasicConstraints(ca=True, path_length=0),
            critical=True
        ).add_extension(
            extension=x509.AuthorityKeyIdentifier.from_issuer_public_key(
                ca_pkey.public_key()
            ),
            critical=False
        )

        if len(alts) > 0:
            crt = crt.add_extension(
                x509.SubjectAlternativeName(alts), critical=False
            )

        crt = crt.sign(
            private_key=ca_pkey,
            algorithm=hashes.SHA256(),
            backend=default_backend()
        )
        # builder = x509.CertificateBuilder()
        # builder = builder.subject_name(csr.subject)
        # builder = builder.issuer_name(ca_crt.subject)
        # now = datetime.datetime.utcnow()
        # builder = builder.not_valid_before(now)
        # lifetime_delta = now + datetime.timedelta(hours=int(lifetime))
        # builder = builder.not_valid_after(lifetime_delta)
        # builder = builder.serial_number(uuid.uuid4().int)
        # builder = builder.public_key(ca_key.public_key())
        # builder = builder.add_extension(
        #     csr.extensions.get_extension_for_oid(
        #         x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        #     ).value,
        #     critical=False
        # )
        # builder = builder.add_extension(
        #     x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
        #     critical=False
        # )
        # builder = builder.add_extension(
        #     x509.AuthorityKeyIdentifier.from_issuer_public_key(
        #         ca_key.public_key()
        #     ),
        #     critical=False
        # )
        # certificate = builder.sign(
        #     private_key=ca_key, algorithm=hashes.SHA256(),
        #     backend=default_backend()
        # )
        return crt.public_bytes(serialization.Encoding.PEM)
