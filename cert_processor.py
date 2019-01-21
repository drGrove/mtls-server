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
        self.gpg = gnupg.GPG(gnupghome=config.get('mtls', 'gnupg_home'))
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
            return x509.load_pem_x509_csr(bytes(str(csr), 'utf-8'), default_backend())
        except Exception as e:
            logging.error(e)
            return None

    def generate_cert(self, csr, lifetime):
        try:
            with open(self.config.get('mtls', 'ca_key'), 'rb') as key_file:
                ca_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )
        except IOError:
            logging.error('Erroring opening file: {}'.format(self.config.get('mtls', 'ca_key')))
            raise CertProcessorKeyNotFoundError()

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(csr.subject)
        builder = builder.issuer_name(x509.Name([
            x509.NameAttribute(x509.OID_COMMON_NAME, self.config.get('mtls', 'issuer_name'))
        ]))
        now = datetime.datetime.now()
        builder = builder.not_valid_before(now)
        builder = builder.not_valid_after(now + datetime.timedelta(hours=int(lifetime)))
        return
