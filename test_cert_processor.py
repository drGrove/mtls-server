import logging
import os
import random
import tempfile
import time
import unittest
from unittest.mock import patch

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
from utils import User
from utils import gen_passwd
from utils import gen_pgp_key
from utils import generate_csr
from utils import generate_key


logging.disable(logging.CRITICAL)


class TestCertProcessorBase(unittest.TestCase):
    def get_ca_cert(self):
        key = self.cert_processor.get_ca_key()
        ca_cert = self.cert_processor.get_ca_cert(key)
        self.assertIsInstance(ca_cert, openssl.x509._Certificate)

    def has_ca_key(self):
        ca_key = self.cert_processor.get_ca_key()
        self.assertIsInstance(ca_key, openssl.rsa._RSAPrivateKey)

    def verify_user(self):
        for user in self.users:
            csr = user.gen_csr()
            signature = self.user_gpg.sign(
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
                tmpdir=self.USER_GNUPGHOME.name,
                fingerprint=user.fingerprint
            )
            with open(sig_path, 'wb') as sig_file:
                sig_file.write(bytes(signature_str, 'utf-8'))
            fingerprint = self.cert_processor.verify(
                csr.public_bytes(serialization.Encoding.PEM),
                sig_path
            )
            os.remove(sig_path)
            self.assertEqual(fingerprint, user.pgp_key.fingerprint)

    def verify_admin(self):
        for user in self.admin_users:
            csr = user.gen_csr()
            signature = self.admin_gpg.sign(
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
                tmpdir=self.ADMIN_GNUPGHOME.name,
                fingerprint=user.fingerprint
            )
            with open(sig_path, 'wb') as sig_file:
                sig_file.write(bytes(signature_str, 'utf-8'))
            fingerprint = self.cert_processor.admin_verify(
                csr.public_bytes(serialization.Encoding.PEM),
                sig_path
            )
            os.remove(sig_path)
            self.assertEqual(fingerprint, user.pgp_key.fingerprint)

    def verify_unauthorized_user(self):
        pass

    def generate_cert(self):
        for user in self.users:
            csr = user.gen_csr()
            sig = self.user_gpg.sign(
                csr.public_bytes(serialization.Encoding.PEM),
                keyid=user.fingerprint,
                detach=True,
                clearsign=True,
                passphrase=user.password
            )
            bcert = self.cert_processor.generate_cert(
                csr,
                60,
                user.fingerprint
            )
            cert = x509.load_pem_x509_certificate(
                bcert,
                backend=default_backend()
            )
            self.assertIsInstance(cert, openssl.x509._Certificate)

    def get_crl(self):
        rev_serial_num = None
        for i, user in enumerate(self.users):
            csr = user.gen_csr()
            sig = self.user_gpg.sign(
                csr.public_bytes(serialization.Encoding.PEM),
                keyid=user.fingerprint,
                detach=True,
                clearsign=True,
                passphrase=user.password
            )
            bcert = self.cert_processor.generate_cert(
                csr,
                60,
                user.fingerprint
            )
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
        sig = self.user_gpg.sign(
            csr.public_bytes(serialization.Encoding.PEM),
            keyid=user.fingerprint,
            detach=True,
            clearsign=True,
            passphrase=user.password
        )
        bcert = self.cert_processor.generate_cert(csr, 60, user.fingerprint)
        cert = x509.load_pem_x509_certificate(
            bcert,
            backend=default_backend()
        )
        self.cert_processor.revoke_cert(cert.serial_number)
        rev_cert = self.cert_processor.storage.get_revoked_certs()[0]
        rev_cert = x509.load_pem_x509_certificate(
            bytes(str(rev_cert), 'UTF-8'),
            backend=default_backend()
        )
        self.assertEqual(cert.serial_number, rev_cert.serial_number)

    def update_cert(self):
        user = self.users[0]
        csr = user.gen_csr()
        sig = self.user_gpg.sign(
            csr.public_bytes(serialization.Encoding.PEM),
            keyid=user.fingerprint,
            detach=True,
            clearsign=True,
            passphrase=user.password
        )
        bcert = self.cert_processor.generate_cert(
            csr,
            60,
            user.fingerprint
        )
        old_cert = x509.load_pem_x509_certificate(
            bcert,
            backend=default_backend()
        )
        time.sleep(65)
        new_b_cert = self.cert_processor.generate_cert(
            csr,
            60,
            user.fingerprint
        )
        new_cert = x509.load_pem_x509_certificate(
            bcert,
            backend=default_backend()
        )
        self.assertEqual(old_cert.serial_number, new_cert.serial_number)


class TestCertProcessorSQLite(TestCertProcessorBase):
    def setUp(self):
        self.USER_GNUPGHOME = tempfile.TemporaryDirectory()
        self.ADMIN_GNUPGHOME = tempfile.TemporaryDirectory()
        config = ConfigParser()
        config.read_string(
            """
            [ca]
            key = secrets/certs/authority/RootCA.key
            cert = secrets/certs/authority/RootCA.pem
            issuer = My Company Name
            alternate_name = *.myname.com

            [gnupg]
            user={user_gnupghome}
            admin={admin_gnupghome}

            [storage]
            engine=sqlite3

            [storage.sqlite3]
            db_path=:memory:
            """.format(
                user_gnupghome=self.USER_GNUPGHOME.name,
                admin_gnupghome=self.ADMIN_GNUPGHOME.name,
            )
        )
        self.common_name = 'user@host'
        self.key = generate_key()
        self.engine = storage.SQLiteStorageEngine(config)
        cur = self.engine.conn.cursor()
        cur.execute('DROP TABLE IF EXISTS certs')
        self.engine.conn.commit()
        self.engine.init_db()
        self.cert_processor = CertProcessor(config)
        self.user_gpg = gnupg.GPG(gnupghome=self.USER_GNUPGHOME.name)
        self.admin_gpg = gnupg.GPG(gnupghome=self.ADMIN_GNUPGHOME.name)
        self.users = [
            User('user@host', gen_passwd(), generate_key(), gpg=self.user_gpg),
            User(
                'user2@host',
                gen_passwd(),
                generate_key(),
                gpg=self.user_gpg
            ),
            User(
                'user3@host',
                gen_passwd(),
                generate_key(),
                gpg=self.user_gpg
            )
        ]
        self.invalid_users = [
            User(
                'user4@host',
                gen_passwd(),
                generate_key(),
                gpg=self.user_gpg
            )
        ]
        self.admin_users = [
            User(
                'admin@host',
                gen_passwd(),
                generate_key(),
                gpg=self.admin_gpg
            )
        ]
        for user in self.users:
            self.user_gpg.import_keys(
                self.user_gpg.export_keys(user.fingerprint)
            )
        for user in self.admin_users:
            self.admin_gpg.import_keys(
                self.admin_gpg.export_keys(user.fingerprint)
            )

    def tearDown(self):
        self.USER_GNUPGHOME.cleanup()
        self.ADMIN_GNUPGHOME.cleanup()

    def test_get_ca_cert(self):
        self.get_ca_cert()

    def test_has_ca_key(self):
        self.has_ca_key()

    def test_verify_user(self):
        self.verify_user()

    def test_generate_cert(self):
        self.generate_cert()

    def test_get_crl(self):
        self.get_crl()

    def test_get_empty_crl(self):
        self.get_empty_crl()

    def test_revoke_cert(self):
        self.revoke_cert()

    def test_update_cert(self):
        self.update_cert()


class TestCertProcessorPostgres(TestCertProcessorBase):
    def setUp(self):
        self.USER_GNUPGHOME = tempfile.TemporaryDirectory()
        self.ADMIN_GNUPGHOME = tempfile.TemporaryDirectory()
        config = ConfigParser()
        config.read_string(
            """
            [ca]
            key = secrets/certs/authority/RootCA.key
            cert = secrets/certs/authority/RootCA.pem
            issuer = My Company Name
            alternate_name = *.myname.com

            [gnupg]
            user={user_gnupghome}
            admin={admin_gnupghome}

            [storage]
            engine=postgres

            [storage.postgres]
            database = mtls
            user = postgres
            password = postgres
            host = localhost
            """.format(
                user_gnupghome=self.USER_GNUPGHOME.name,
                admin_gnupghome=self.ADMIN_GNUPGHOME.name
            )
        )
        self.common_name = 'user@host'
        self.key = generate_key()
        self.engine = storage.PostgresqlStorageEngine(config)
        cur = self.engine.conn.cursor()
        cur.execute('DROP TABLE IF EXISTS certs')
        self.engine.conn.commit()
        self.engine.init_db()

        self.cert_processor = CertProcessor(config)
        self.user_gpg = gnupg.GPG(gnupghome=self.USER_GNUPGHOME.name)
        self.admin_gpg = gnupg.GPG(gnupghome=self.ADMIN_GNUPGHOME.name)
        self.users = [
            User('user@host', gen_passwd(), generate_key(), gpg=self.user_gpg),
            User(
                'user2@host',
                gen_passwd(),
                generate_key(),
                gpg=self.user_gpg
            ),
            User(
                'user3@host',
                gen_passwd(),
                generate_key(),
                gpg=self.user_gpg
            )
        ]
        self.invalid_users = [
            User(
                'user4@host',
                gen_passwd(),
                generate_key(),
                gpg=self.user_gpg
            )
        ]
        self.admin_users = [
            User(
                'admin@host',
                gen_passwd(),
                generate_key(),
                gpg=self.admin_gpg
            )
        ]
        for user in self.users:
            self.user_gpg.import_keys(
                self.user_gpg.export_keys(user.fingerprint)
            )
        for user in self.admin_users:
            self.admin_gpg.import_keys(
                self.admin_gpg.export_keys(user.fingerprint)
            )

    def tearDown(self):
        self.USER_GNUPGHOME.cleanup()
        self.ADMIN_GNUPGHOME.cleanup()

    def test_get_ca_cert(self):
        self.get_ca_cert()

    def test_has_ca_key(self):
        self.has_ca_key()

    def test_verify_user(self):
        self.verify_user()

    def test_verify_admin(self):
        self.verify_admin()

    def test_verify_unauthorized_user(self):
        self.verify_unauthorized_user()

    def test_generate_cert(self):
        self.generate_cert()

    def test_get_crl(self):
        self.get_crl()

    def test_get_empty_crl(self):
        self.get_empty_crl()

    def test_revoke_cert(self):
        self.revoke_cert()

    def test_update_cert(self):
        self.update_cert()


class TestCertProcessorMissingStorage(TestCertProcessorBase):
    def setUp(self):
        self.USER_GNUPGHOME = tempfile.TemporaryDirectory()
        self.ADMIN_GNUPGHOME = tempfile.TemporaryDirectory()
        self.config = ConfigParser()
        self.config.read_string(
            """
            [ca]
            key = secrets/certs/authority/RootCA.key
            cert = secrets/certs/authority/RootCA.pem
            issuer = My Company Name
            alternate_name = *.myname.com

            [gnupg]
            user={user_gnupghome}
            admin={admin_gnupghome}
            """.format(
                user_gnupghome=self.USER_GNUPGHOME.name,
                admin_gnupghome=self.ADMIN_GNUPGHOME.name
            )
        )

    def tearDown(self):
        self.USER_GNUPGHOME.cleanup()
        self.ADMIN_GNUPGHOME.cleanup()

    def test_missing_storage(self):
        with self.assertRaises(storage.StorageEngineMissing):
            self.cert_processor = CertProcessor(self.config)


class TestCertProcessorRelativeGnupgHome(TestCertProcessorBase):
    def setUp(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        self.USER_GNUPGHOME = tempfile.TemporaryDirectory(
            prefix=dir_path + '/secrets/'
        )
        self.ADMIN_GNUPGHOME = tempfile.TemporaryDirectory(
            prefix=dir_path + '/secrets/'
        )
        relative_user = '.' + self.USER_GNUPGHOME.name.split(dir_path)[1]
        relative_admin = '.' + self.ADMIN_GNUPGHOME.name.split(dir_path)[1]
        config = ConfigParser()
        config.read_string(
            """
            [ca]
            key = secrets/certs/authority/RootCA.key
            cert = secrets/certs/authority/RootCA.pem
            issuer = My Company Name
            alternate_name = *.myname.com

            [gnupg]
            user={user_gnupghome}
            admin={admin_gnupghome}

            [storage]
            engine=sqlite3

            [storage.sqlite3]
            db_path=:memory:
            """.format(
                user_gnupghome=relative_user,
                admin_gnupghome=relative_admin,
            )
        )
        self.common_name = 'user@host'
        self.key = generate_key()
        self.engine = storage.SQLiteStorageEngine(config)
        cur = self.engine.conn.cursor()
        cur.execute('DROP TABLE IF EXISTS certs')
        self.engine.conn.commit()
        self.engine.init_db()
        self.cert_processor = CertProcessor(config)
        self.user_gpg = gnupg.GPG(gnupghome=self.USER_GNUPGHOME.name)
        self.admin_gpg = gnupg.GPG(gnupghome=self.ADMIN_GNUPGHOME.name)
        self.users = [
            User('user@host', gen_passwd(), generate_key(), gpg=self.user_gpg),
            User(
                'user2@host',
                gen_passwd(),
                generate_key(),
                gpg=self.user_gpg
            ),
            User(
                'user3@host',
                gen_passwd(),
                generate_key(),
                gpg=self.user_gpg
            )
        ]
        self.invalid_users = [
            User(
                'user4@host',
                gen_passwd(),
                generate_key(),
                gpg=self.user_gpg
            )
        ]
        self.admin_users = [
            User(
                'admin@host',
                gen_passwd(),
                generate_key(),
                gpg=self.admin_gpg
            )
        ]
        for user in self.users:
            self.user_gpg.import_keys(
                self.user_gpg.export_keys(user.fingerprint)
            )
        for user in self.admin_users:
            self.admin_gpg.import_keys(
                self.admin_gpg.export_keys(user.fingerprint)
            )

    def tearDown(self):
        self.USER_GNUPGHOME.cleanup()
        self.ADMIN_GNUPGHOME.cleanup()

    def test_get_ca_cert(self):
        self.get_ca_cert()

    def test_has_ca_key(self):
        self.has_ca_key()

    def test_verify_user(self):
        self.verify_user()

    def test_generate_cert(self):
        self.generate_cert()

    def test_get_crl(self):
        self.get_crl()

    def test_get_empty_crl(self):
        self.get_empty_crl()

    def test_revoke_cert(self):
        self.revoke_cert()

    def test_update_cert(self):
        self.update_cert()


class TestCertProcessorPasswordCAKey(TestCertProcessorBase):
    def setUp(self):
        self.USER_GNUPGHOME = tempfile.TemporaryDirectory()
        self.ADMIN_GNUPGHOME = tempfile.TemporaryDirectory()
        self.AUTHORITY_FOLDER = tempfile.TemporaryDirectory()
        config = ConfigParser()
        config.read_string(
            """
            [ca]
            key = {authority_folder}/RootCA.key
            cert = {authority_folder}/RootCA.pem
            issuer = My Company Name
            alternate_name = *.myname.com

            [gnupg]
            user={user_gnupghome}
            admin={admin_gnupghome}

            [storage]
            engine=sqlite3

            [storage.sqlite3]
            db_path=:memory:
            """.format(
                user_gnupghome=self.USER_GNUPGHOME.name,
                admin_gnupghome=self.ADMIN_GNUPGHOME.name,
                authority_folder=self.AUTHORITY_FOLDER.name
            )
        )
        self.common_name = 'user@host'
        self.key = generate_key()
        self.engine = storage.SQLiteStorageEngine(config)
        cur = self.engine.conn.cursor()
        cur.execute('DROP TABLE IF EXISTS certs')
        self.engine.conn.commit()
        self.engine.init_db()
        self.cert_processor = CertProcessor(config)
        self.user_gpg = gnupg.GPG(gnupghome=self.USER_GNUPGHOME.name)
        self.admin_gpg = gnupg.GPG(gnupghome=self.ADMIN_GNUPGHOME.name)
        self.users = [
            User('user@host', gen_passwd(), generate_key(), gpg=self.user_gpg),
            User(
                'user2@host',
                gen_passwd(),
                generate_key(),
                gpg=self.user_gpg
            ),
            User(
                'user3@host',
                gen_passwd(),
                generate_key(),
                gpg=self.user_gpg
            )
        ]
        self.invalid_users = [
            User(
                'user4@host',
                gen_passwd(),
                generate_key(),
                gpg=self.user_gpg
            )
        ]
        self.admin_users = [
            User(
                'admin@host',
                gen_passwd(),
                generate_key(),
                gpg=self.admin_gpg
            )
        ]
        for user in self.users:
            self.user_gpg.import_keys(
                self.user_gpg.export_keys(user.fingerprint)
            )
        for user in self.admin_users:
            self.admin_gpg.import_keys(
                self.admin_gpg.export_keys(user.fingerprint)
            )

    def tearDown(self):
        self.USER_GNUPGHOME.cleanup()
        self.ADMIN_GNUPGHOME.cleanup()
        self.AUTHORITY_FOLDER.cleanup()

    def test_get_ca_cert(self):
        os.environ['CA_KEY_PASSWORD'] = gen_passwd()
        self.get_ca_cert()
        del os.environ['CA_KEY_PASSWORD']

    def test_has_ca_key(self):
        os.environ['CA_KEY_PASSWORD'] = gen_passwd()
        self.has_ca_key()
        del os.environ['CA_KEY_PASSWORD']

    def test_generate_cert_with_password(self):
        os.environ['CA_KEY_PASSWORD'] = gen_passwd()
        self.generate_cert()
        del os.environ['CA_KEY_PASSWORD']

    def test_generate_cert_without_password(self):
        self.generate_cert()


class TestCertProcessorCRLDistributionPath(TestCertProcessorBase):
    def setUp(self):
        self.USER_GNUPGHOME = tempfile.TemporaryDirectory()
        self.ADMIN_GNUPGHOME = tempfile.TemporaryDirectory()
        self.AUTHORITY_FOLDER = tempfile.TemporaryDirectory()
        self.FQDN = 'my.test.server'
        self.fqdn_patch = patch.dict('os.environ', {'FQDN': self.FQDN})
        self.fqdn_patch.start()
        config = ConfigParser()
        config.read_string(
            """
            [ca]
            key = {authority_folder}/RootCA.key
            cert = {authority_folder}/RootCA.pem
            issuer = My Company Name
            alternate_name = *.myname.com

            [gnupg]
            user={user_gnupghome}
            admin={admin_gnupghome}

            [storage]
            engine=sqlite3

            [storage.sqlite3]
            db_path=:memory:
            """.format(
                user_gnupghome=self.USER_GNUPGHOME.name,
                admin_gnupghome=self.ADMIN_GNUPGHOME.name,
                authority_folder=self.AUTHORITY_FOLDER.name
            )
        )
        self.common_name = 'user@host'
        self.key = generate_key()
        self.engine = storage.SQLiteStorageEngine(config)
        cur = self.engine.conn.cursor()
        cur.execute('DROP TABLE IF EXISTS certs')
        self.engine.conn.commit()
        self.engine.init_db()
        self.cert_processor = CertProcessor(config)
        self.user_gpg = gnupg.GPG(gnupghome=self.USER_GNUPGHOME.name)
        self.admin_gpg = gnupg.GPG(gnupghome=self.ADMIN_GNUPGHOME.name)
        self.users = [
            User('user@host', gen_passwd(), generate_key(), gpg=self.user_gpg),
        ]
        for user in self.users:
            self.user_gpg.import_keys(
                self.user_gpg.export_keys(user.fingerprint)
            )

    def tearDown(self):
        self.USER_GNUPGHOME.cleanup()
        self.ADMIN_GNUPGHOME.cleanup()
        self.AUTHORITY_FOLDER.cleanup()
        self.fqdn_patch.stop()

    def test_crl_distribution_path(self):
        user = self.users[0]
        csr = user.gen_csr()
        sig = self.user_gpg.sign(
            csr.public_bytes(serialization.Encoding.PEM),
            keyid=user.fingerprint,
            detach=True,
            clearsign=True,
            passphrase=user.password
        )
        bcert = self.cert_processor.generate_cert(
            csr,
            60,
            user.fingerprint
        )
        cert = x509.load_pem_x509_certificate(
            bcert,
            backend=default_backend()
        )
        self.assertIsInstance(cert, openssl.x509._Certificate)
        has_crl_extension = False
        for extension in cert.extensions:
            if isinstance(extension.value, x509.CRLDistributionPoints):
                has_crl_extension = True
                for distributionPoint in extension.value:
                    uris = distributionPoint.full_name
                    for uri in uris:
                        crl_path = 'http://{FQDN}/crl'.format(
                            FQDN=self.FQDN
                        )
                        self.assertEqual(
                            uri.value,
                            crl_path
                        )
        self.assertTrue(has_crl_extension)


if __name__ == "__main__":
    unittest.main()
