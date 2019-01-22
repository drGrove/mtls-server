import datetime
import datetime
import logging
import os

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import gnupg


class CertProcessorKeyNotFoundError(Exception):
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

    def get_csr(self, csr):
        try:
            return x509.load_pem_x509_csr(bytes(str(csr), 'utf-8'),
                                          default_backend())
        except Exception as e:
            logging.error(e)
            return None

    def generate_cert(self, csr, lifetime):
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
        except IOError:
            logging.error('Erroring opening file: {}'.format(ca_key_path))
            raise CertProcessorKeyNotFoundError()

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(csr.subject)
        builder = builder.issuer_name(x509.Name([
            x509.NameAttribute(
                x509.OID_COMMON_NAME,
                self.config.get('mtls', 'issuer_name')
            )
        ]))
        now = datetime.datetime.now()
        builder = builder.not_valid_before(now)
        lifetime_delta = now + datetime.timedelta(hours=int(lifetime))
        builder = builder.not_valid_after(lifetime_delta)
        return
