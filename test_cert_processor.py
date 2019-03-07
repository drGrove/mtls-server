import os
import random
import tempfile
import unittest

from configparser import ConfigParser
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends import openssl
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import gnupg
import re

from cert_processor import CertProcessor
from cert_processor import CertProcessorKeyNotFoundError
from cert_processor import CertProcessorInvalidSignatureError
import storage


def generate_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )


def generate_csr(key, common_name):
    country = 'US'
    state = 'CA'
    locality = 'San Francisco'
    organization_name = 'My Org'
    email = 'test@example.com'
    return x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email)
    ])).sign(key, hashes.SHA256(), default_backend())


def gen_pgp_key(email, password, gpg):
    input_data = gpg.gen_key_input(
        name_email=email,
        passphrase=password
    )
    return gpg.gen_key(input_data)


class User:

    def __init__(self, email, password, key, gpg=None):
        self.gpg = gpg
        self.email = email
        self.password = password
        self.key = key
        self.pgp_key = gen_pgp_key(email, password, gpg)
        self.fingerprint = self.pgp_key.fingerprint
        self.__csrs = []

    @property
    def email(self):
        return self.__email

    @email.setter
    def email(self, email):
        self.__email = email

    @property
    def password(self):
        return self.__password

    @password.setter
    def password(self, password):
        self.__password = password

    @property
    def pgp_key(self):
        return self.__pgp_key

    @pgp_key.setter
    def pgp_key(self, pgp_key):
        self.__pgp_key = pgp_key

    @property
    def csrs(self):
        return self.__csrs

    def gen_csr(self, common_name=None):
        if common_name is None:
            common_name = self.email
        csr = generate_csr(self.key, common_name)
        self.__csrs.append(csr)
        return csr


def gen_passwd():
    chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    chars += '1234567890'
    chars += '!@#$%^&*()-_+=|?><,.'
    pw = ""
    for c in range(50):
        pw += random.choice(chars)
    if re.search('[0-9]+', pw) is None:
        pw = gen_passwd()
    return pw


class TestCertProcessorBase(unittest.TestCase):
    def get_ca_cert(self):
        ca_cert = self.cert_processor.get_ca_cert()
        self.assertIsInstance(ca_cert, openssl.x509._Certificate)

    def has_ca_key(self):
        ca_key = self.cert_processor.get_ca_key()
        self.assertIsInstance(ca_key, openssl.rsa._RSAPrivateKey)

    def verify(self):
        for user in self.users:
            csr = user.gen_csr()
            signature = self.gpg.sign(
                csr.public_bytes(serialization.Encoding.PEM),
                keyid=user.fingerprint,
                detach=True,
                clearsign=True,
                passphrase=user.password
            )
            signature_str = str(signature)
            csr_str = csr.public_bytes(serialization.Encoding.PEM)\
                .decode('utf-8')
            sig_path = '{tmpdir}/{fingerprint}.asc'.format(
                tmpdir=self.GNUPGHOME.name,
                fingerprint=user.fingerprint
            )
            with open(sig_path, 'wb') as sig_file:
                sig_file.write(bytes(signature_str, 'utf-8'))
            self.cert_processor.verify(
                csr.public_bytes(serialization.Encoding.PEM),
                sig_path
            )
            os.remove(sig_path)

    def generate_cert(self):
        for user in self.users:
            csr = user.gen_csr()
            sig = self.gpg.sign(
                csr.public_bytes(serialization.Encoding.PEM),
                keyid=user.fingerprint,
                detach=True,
                clearsign=True,
                passphrase=user.password
            )
            bcert = self.cert_processor.generate_cert(csr, 60)
            cert = x509.load_pem_x509_certificate(
                bcert,
                backend=default_backend()
            )
            self.assertIsInstance(cert, openssl.x509._Certificate)

    def get_crl(self):
        rev_serial_num = None
        for i, user in enumerate(self.users):
            csr = user.gen_csr()
            sig = self.gpg.sign(
                csr.public_bytes(serialization.Encoding.PEM),
                keyid=user.fingerprint,
                detach=True,
                clearsign=True,
                passphrase=user.password
            )
            bcert = self.cert_processor.generate_cert(csr, 60)
            cert = x509.load_pem_x509_certificate(
                bcert,
                backend=default_backend()
            )
            if i == 1:
                self.cert_processor.revoke_cert(cert.serial_number)
                rev_serial_num = cert.serial_number

        crl = self.cert_processor.get_crl()
        self.assertIsInstance(crl, openssl.x509._CertificateRevocationList)
        self.assertIsInstance(
            crl.get_revoked_certificate_by_serial_number(rev_serial_num),
            openssl.x509._RevokedCertificate
        )
        self.assertIn(
            "-----BEGIN X509 CRL-----",
            crl.public_bytes(serialization.Encoding.PEM).decode('UTF-8')
        )
        self.assertIn(
            "-----END X509 CRL-----",
            crl.public_bytes(serialization.Encoding.PEM).decode('UTF-8')
        )

    def get_empty_crl(self):
        crl = self.cert_processor.get_crl()
        self.assertIsInstance(crl, openssl.x509._CertificateRevocationList)
        self.assertIn(
            "-----BEGIN X509 CRL-----",
            crl.public_bytes(serialization.Encoding.PEM).decode('UTF-8')
        )
        self.assertIn(
            "-----END X509 CRL-----",
            crl.public_bytes(serialization.Encoding.PEM).decode('UTF-8')
        )

    def revoke_cert(self):
        user = self.users[0]
        csr = user.gen_csr()
        sig = self.gpg.sign(
            csr.public_bytes(serialization.Encoding.PEM),
            keyid=user.fingerprint,
            detach=True,
            clearsign=True,
            passphrase=user.password
        )
        bcert = self.cert_processor.generate_cert(csr, 60)
        cert = x509.load_pem_x509_certificate(
            bcert,
            backend=default_backend()
        )
        self.cert_processor.revoke_cert(cert.serial_number)
        rev_cert = self.cert_processor.storage.revoked_certs()[0]
        rev_cert = x509.load_pem_x509_certificate(
            bytes(str(rev_cert), 'UTF-8'),
            backend=default_backend()
        )
        self.assertEqual(cert.serial_number, rev_cert.serial_number)


class TestCertProcessorSQLite(unittest.TestCase):
    def setUp(self):
        self.GNUPGHOME = tempfile.TemporaryDirectory()
        config = ConfigParser()
        config.read_string(
            """
            [ca]
            key = secrets/certs/authority/RootCA.key
            cert = secrets/certs/authority/RootCA.pem
            issuer = My Company Name
            alternate_name = *.myname.com

            [gnupg]
            home={gnupghome}

            [storage]
            engine=sqlite3

            [storage.sqlite3]
            db_path=:memory:
            """.format(gnupghome=self.GNUPGHOME.name)
        )
        self.common_name = 'user@host'
        self.key = generate_key()
        self.engine = storage.SQLiteStorageEngine(config)
        cur = self.engine.conn.cursor()
        cur.execute('DROP TABLE IF EXISTS certs')
        self.engine.conn.commit()
        self.engine.init_db()
        self.cert_processor = CertProcessor(config)
        self.gpg = gnupg.GPG(gnupghome=self.GNUPGHOME.name)
        self.users = [
            User('user@host', gen_passwd(), generate_key(), gpg=self.gpg),
            User('user2@host', gen_passwd(), generate_key(), gpg=self.gpg),
            User('user3@host', gen_passwd(), generate_key(), gpg=self.gpg)
        ]
        for user in self.users:
            self.gpg.import_keys(self.gpg.export_keys(user.fingerprint))

    def tearDown(self):
        self.GNUPGHOME.cleanup()

    def test_get_ca_cert(self):
        self.get_ca_cert()

    def test_has_ca_key(self):
        self.has_ca_key()

    def test_verify(self):
        self.verify()

    def test_generate_cert(self):
        self.generate_cert()

    def test_get_crl(self):
        self.get_crl()

    def test_get_empty_crl(self):
        self.get_empty_crl()

    def test_revoke_cert(self):
        self.revoke_cert()


class TestCertProcessorPostgres(TestCertProcessorBase):
    def setUp(self):
        self.GNUPGHOME = tempfile.TemporaryDirectory()
        config = ConfigParser()
        config.read_string(
            """
            [ca]
            key = secrets/certs/authority/RootCA.key
            cert = secrets/certs/authority/RootCA.pem
            issuer = My Company Name
            alternate_name = *.myname.com

            [gnupg]
            home={gnupghome}

            [storage]
            engine=postgres

            [storage.postgres]
            database = mtls
            user = postgres
            password = postgres
            host = localhost
            """.format(gnupghome=self.GNUPGHOME.name)
        )
        self.common_name = 'user@host'
        self.key = generate_key()
        self.engine = storage.PostgresqlStorageEngine(config)
        cur = self.engine.conn.cursor()
        cur.execute('DROP TABLE IF EXISTS certs')
        self.engine.conn.commit()
        self.engine.init_db()

        self.cert_processor = CertProcessor(config)
        self.gpg = gnupg.GPG(gnupghome=self.GNUPGHOME.name)
        self.users = [
            User('user@host', gen_passwd(), generate_key(), gpg=self.gpg),
            User('user2@host', gen_passwd(), generate_key(), gpg=self.gpg),
            User('user3@host', gen_passwd(), generate_key(), gpg=self.gpg)
        ]
        for user in self.users:
            self.gpg.import_keys(self.gpg.export_keys(user.fingerprint))

    def tearDown(self):
        self.GNUPGHOME.cleanup()

    def test_get_ca_cert(self):
        self.get_ca_cert()

    def test_has_ca_key(self):
        self.has_ca_key()

    def test_verify(self):
        self.verify()

    def test_generate_cert(self):
        self.generate_cert()

    def test_get_crl(self):
        self.get_crl()

    def test_get_empty_crl(self):
        self.get_empty_crl()

    def test_revoke_cert(self):
        self.revoke_cert()
