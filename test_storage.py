import unittest
import configparser
import datetime

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import storage


def generate_fake_cert(common_name, serial_number=None, expired=False):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        public_key = private_key.public_key()

        today = datetime.datetime.today()
        one_day = datetime.timedelta(1, 0, 0)

        builder = x509.CertificateBuilder()

        builder = builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]))

        builder = builder.issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, 'Fake Issuer'),
        ]))

        if serial_number is not None:
            builder = builder.serial_number(serial_number)
        else:
            builder = builder.serial_number(x509.random_serial_number())

        if expired:
            builder = builder.not_valid_before(today - 3 * one_day)
            builder = builder.not_valid_after(today - one_day)
        else:
            builder = builder.not_valid_before(today - one_day)
            builder = builder.not_valid_after(today + one_day)

        builder = builder.public_key(public_key)

        return builder.sign(
            private_key=private_key,
            algorithm=hashes.SHA256(),
            backend=default_backend(),
        )


class TestSQLiteStorageEngine(unittest.TestCase):
    def setUp(self):
        config = configparser.ConfigParser()
        config.read_string(
            """
            [storage.sqlite3]
            db_path=:memory:
            """)

        self.engine = storage.SQLiteStorageEngine(config)
        cur = self.engine.conn.cursor()
        cur.execute('DROP TABLE IF EXISTS certs')
        self.engine.conn.commit()
        self.engine.init_db()

    def tearDown(self):
        self.engine.close()

    def test_save_cert_persists_data(self):
        """
        Verify that certificates are actually persisted to the DB
        """

        common_name = 'user@host'
        query = 'SELECT serial_number FROM certs WHERE common_name=?'
        cur = self.engine.conn.cursor()

        cur.execute(query, [common_name])
        self.assertIsNone(cur.fetchone())

        cert = generate_fake_cert(common_name)
        self.engine.save_cert(cert)

        cur.execute(query, [common_name])
        self.assertIsNotNone(cur.fetchone())

    def test_save_cert_success_conditions(self):
        """
        Verify that a certificate can be saved if the serial number is unique
        and if the CommonName does not conflict with any existing non-expired
        and non-revoked certificates
        """

        # Saving a certificate for the first time
        cert = generate_fake_cert('user@host1')
        self.engine.save_cert(cert)

        # Superceeding an expired certificate
        cert = generate_fake_cert('user@host2', expired=True)
        self.engine.save_cert(cert)
        cert = generate_fake_cert('user@host2')
        self.engine.save_cert(cert)

        # Superceeding a revoked certificate
        cert = generate_fake_cert('user@host3')
        self.engine.save_cert(cert)
        self.engine.revoke_cert(cert.serial_number)
        cert = generate_fake_cert('user@host3')
        self.engine.save_cert(cert)

    def test_save_cert_failure_conditions(self):
        """
        Verify that an exception is raised when a caller asks to save a
        certificate with a non-unique serial number, or if the CommonName
        conflicts with any existing non-expired and non-revoked certificates
        """

        # Conflicting serial number with any previous certificate
        cert = generate_fake_cert('user@host1', serial_number=123)
        self.engine.save_cert(cert)
        cert = generate_fake_cert('user@host1', serial_number=123)
        with self.assertRaises(storage.StorageEngineCertificateConflict):
            self.engine.save_cert(cert)

        # Conflicting CommonName with still-valid certificate
        cert = generate_fake_cert('user@host2')
        self.engine.save_cert(cert)
        cert = generate_fake_cert('user@host2')
        with self.assertRaises(storage.StorageEngineCertificateConflict):
            self.engine.save_cert(cert)

    def test_revoke_cert_persists_data(self):
        """
        Verify that revocations are actually persisted to the DB
        """

        query = 'SELECT revoked FROM certs WHERE serial_number=?'
        cur = self.engine.conn.cursor()

        cert = generate_fake_cert('user@host', serial_number=123)
        self.engine.save_cert(cert)

        cur.execute(query, [str(cert.serial_number)])
        self.assertEqual(cur.fetchone()[0], 0)

        self.engine.revoke_cert(cert.serial_number)

        cur.execute(query, [str(cert.serial_number)])
        self.assertEqual(cur.fetchone()[0], 1)
