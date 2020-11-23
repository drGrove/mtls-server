import configparser
import datetime
import logging
import unittest

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from mtls_server import storage
from mtls_server.cert_processor import CertProcessorMismatchedPublicKeyError
from mtls_server.config import Config


logging.disable(logging.CRITICAL)


def generate_fake_cert(
    common_name, serial_number=None, expired=False, pkey=None, upkey=None
):
    today = datetime.datetime.today()
    one_day = datetime.timedelta(1, 0, 0)

    builder = x509.CertificateBuilder()

    builder = builder.subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    )

    builder = builder.issuer_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Fake Issuer")])
    )

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

    builder = builder.public_key(upkey.public_key())

    return builder.sign(
        private_key=pkey, algorithm=hashes.SHA256(), backend=default_backend()
    )


def update_cert(old_cert, csr, pkey, upkey):
    common_name = old_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    common_name = common_name[0].value
    old_cert_pub = (
        old_cert.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("UTF-8")
    )
    csr_pub = (
        csr.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("UTF-8")
    )
    if old_cert_pub != csr_pub:
        raise CertProcessorMismatchedPublicKeyError
    now = datetime.datetime.utcnow()
    lifetime_delta = now + datetime.timedelta(seconds=120)
    alts = [x509.DNSName(u"*.mycompany.com")]
    cert = (
        x509.CertificateBuilder()
        .subject_name(old_cert.subject)
        .issuer_name(old_cert.issuer)
        .public_key(upkey.public_key())
        .serial_number(old_cert.serial_number)
        .not_valid_before(old_cert.not_valid_before)
        .not_valid_after(lifetime_delta)
    )
    if len(alts) > 0:
        cert = cert.add_extension(x509.SubjectAlternativeName(alts), critical=False)
    cert = cert.sign(
        private_key=pkey, algorithm=hashes.SHA256(), backend=default_backend()
    )
    return cert


def generate_csr(common_name, email, key):
    country = "US"
    state = "CA"
    locality = "Mountain View"
    organization_name = "My Org"
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COUNTRY_NAME, country),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
                    x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
                    x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                    x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
                ]
            )
        )
        .sign(key, hashes.SHA256(), default_backend())
    )
    return csr


class TestSQLiteStorageEngine(unittest.TestCase):
    def setUp(self):
        config = configparser.ConfigParser()
        config.read_string(
            """
            [storage.sqlite3]
            db_path=:memory:
            """
        )
        Config.init_config(config=config)
        self.engine = storage.SQLiteStorageEngine(Config)
        cur = self.engine.conn.cursor()
        cur.execute("DROP TABLE IF EXISTS certs")
        self.engine.conn.commit()
        self.engine.init_db()
        self.pkey = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        self.upkey = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )

    def tearDown(self):
        self.engine.close()

    def test_save_cert_persists_data(self):
        """
        Verify that certificates are actually persisted to the DB
        """

        common_name = "user@host"
        query = "SELECT serial_number FROM certs WHERE common_name=?"
        cur = self.engine.conn.cursor()

        cur.execute(query, [common_name])
        self.assertIsNone(cur.fetchone())
        cert = generate_fake_cert(common_name, pkey=self.pkey, upkey=self.upkey)
        self.engine.save_cert(cert, "ABCDEFGH")

        cur.execute(query, [common_name])
        self.assertIsNotNone(cur.fetchone())

    def test_save_cert_success_conditions(self):
        """
        Verify that a certificate can be saved if the serial number is unique
        and if the CommonName does not conflict with any existing non-expired
        and non-revoked certificates
        """

        # Saving a certificate for the first time
        cert = generate_fake_cert("user@host1", pkey=self.pkey, upkey=self.upkey)
        self.engine.save_cert(cert, "ABCDEFGH")

        # Superceeding a revoked certificate
        cert = generate_fake_cert("user@host3", pkey=self.pkey, upkey=self.upkey)
        self.engine.save_cert(cert, "ABCDEFGH")
        self.engine.revoke_cert(cert.serial_number)
        cert = generate_fake_cert("user@host3", pkey=self.pkey, upkey=self.upkey)
        self.engine.save_cert(cert, "ABCDEFGH")

    def test_save_cert_failure_conditions(self):
        """
        Verify that an exception is raised when a caller asks to save a
        certificate with a non-unique serial number, or if the CommonName
        conflicts with any existing non-expired and non-revoked certificates
        """

        # Conflicting serial number with any previous certificate
        cert = generate_fake_cert(
            "user@host1", serial_number=123, pkey=self.pkey, upkey=self.upkey
        )
        self.engine.save_cert(cert, "ABCDEFGH")
        cert = generate_fake_cert(
            "user@host1", serial_number=123, pkey=self.pkey, upkey=self.upkey
        )
        with self.assertRaises(storage.StorageEngineCertificateConflict):
            self.engine.save_cert(cert, "ABCDEFGH")

        # Conflicting CommonName with still-valid certificate
        cert = generate_fake_cert("user@host2", pkey=self.pkey, upkey=self.upkey)
        self.engine.save_cert(cert, "ABCDEFGH")
        cert = generate_fake_cert("user@host2", pkey=self.pkey, upkey=self.upkey)
        with self.assertRaises(storage.StorageEngineCertificateConflict):
            self.engine.save_cert(cert, "ABCDEFGH")

    def test_revoke_cert_persists_data(self):
        """
        Verify that revocations are actually persisted to the DB
        """

        query = "SELECT revoked FROM certs WHERE serial_number=?"
        cur = self.engine.conn.cursor()

        cert = generate_fake_cert(
            "user@host", serial_number=123, pkey=self.pkey, upkey=self.upkey
        )
        self.engine.save_cert(cert, "ABCDEFGH")

        cur.execute(query, [str(cert.serial_number)])
        self.assertEqual(cur.fetchone()[0], 0)

        self.engine.revoke_cert(cert.serial_number)

        cur.execute(query, [str(cert.serial_number)])
        self.assertEqual(cur.fetchone()[0], 1)

    def test_update_cert(self):
        """
        Verify that a certificate can be updated.
        """
        old_cert = generate_fake_cert(
            "user@host", serial_number=123, pkey=self.pkey, upkey=self.upkey
        )
        self.engine.save_cert(old_cert, "ABCDEFGH")
        csr = generate_csr("user@host", "test@example.com", self.upkey)
        cert = update_cert(old_cert, csr, self.pkey, self.upkey)
        self.engine.update_cert(serial_number=cert.serial_number, cert=cert)
        self.assertEqual(old_cert.serial_number, cert.serial_number)
        self.assertEqual(old_cert.not_valid_before, cert.not_valid_before)


class TestPostgresqlStorageEngine(unittest.TestCase):
    def setUp(self):
        config = configparser.ConfigParser()
        config.read_string(
            """
            [storage]
            engine=postgres

            [storage.postgres]
            database = mtls
            user = postgres
            password = postgres
            host = localhost
            """
        )
        Config.init_config(config=config)
        self.engine = storage.PostgresqlStorageEngine(Config)
        cur = self.engine.conn.cursor()
        cur.execute("DROP TABLE IF EXISTS certs")
        self.engine.conn.commit()
        self.engine.init_db()
        self.pkey = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        self.upkey = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )

    def tearDown(self):
        self.engine.close()

    def test_save_cert_persists_data(self):
        """
        Verify that certificates are actually persisted to the DB
        """

        common_name = "user@host"
        query = "SELECT serial_number FROM certs WHERE common_name=%s"
        cur = self.engine.conn.cursor()

        cur.execute(query, [common_name])
        self.assertIsNone(cur.fetchone())

        cert = generate_fake_cert(common_name, pkey=self.pkey, upkey=self.upkey)
        self.engine.save_cert(cert, "ABCDEFGH")

        cur.execute(query, [common_name])
        self.assertIsNotNone(cur.fetchone())

    def test_save_cert_success_conditions(self):
        """
        Verify that a certificate can be saved if the serial number is unique
        and if the CommonName does not conflict with any existing non-expired
        and non-revoked certificates
        """

        # Saving a certificate for the first time
        cert = generate_fake_cert("user@host1", pkey=self.pkey, upkey=self.upkey)
        self.engine.save_cert(cert, "ABCDEFGH")

        # Superceeding an expired certificate
        cert = generate_fake_cert(
            "user@host2", expired=True, pkey=self.pkey, upkey=self.upkey
        )
        self.engine.save_cert(cert, "ABCDEFGH")
        cert = generate_fake_cert("user@host2", pkey=self.pkey, upkey=self.upkey)
        self.engine.save_cert(cert, "39DL2LSL")

        # Superceeding a revoked certificate
        cert = generate_fake_cert("user@host3", pkey=self.pkey, upkey=self.upkey)
        self.engine.save_cert(cert, "40LD0DL")
        self.engine.revoke_cert(cert.serial_number)
        cert = generate_fake_cert("user@host3", pkey=self.pkey, upkey=self.upkey)
        self.engine.save_cert(cert, "40LD0DL")

    def test_save_cert_failure_conditions(self):
        """
        Verify that an exception is raised when a caller asks to save a
        certificate with a non-unique serial number, or if the CommonName
        conflicts with any existing non-expired and non-revoked certificates
        """

        # Conflicting serial number with any previous certificate
        cert = generate_fake_cert(
            "user@host1", serial_number=123, pkey=self.pkey, upkey=self.upkey
        )
        self.engine.save_cert(cert, "ABCDEFGH")
        cert = generate_fake_cert(
            "user@host1", serial_number=123, pkey=self.pkey, upkey=self.upkey
        )
        with self.assertRaises(storage.StorageEngineCertificateConflict):
            self.engine.save_cert(cert, "ABCDEFGH")

        # Conflicting CommonName with still-valid certificate
        cert = generate_fake_cert("user@host2", pkey=self.pkey, upkey=self.upkey)
        self.engine.save_cert(cert, "39DL2LSL")
        cert = generate_fake_cert("user@host2", pkey=self.pkey, upkey=self.upkey)
        with self.assertRaises(storage.StorageEngineCertificateConflict):
            self.engine.save_cert(cert, "39DL2LSL")

    def test_revoke_cert_persists_data(self):
        """
        Verify that revocations are actually persisted to the DB
        """
        query = "SELECT revoked FROM certs WHERE serial_number = %s"
        cur = self.engine.conn.cursor()
        cert = generate_fake_cert(
            "user@host", serial_number=123, pkey=self.pkey, upkey=self.upkey
        )
        self.engine.save_cert(cert, "ABCDEFGH")
        cur.execute(query, (str(cert.serial_number),))
        self.assertEqual(cur.fetchone()[0], False)
        self.engine.revoke_cert(cert.serial_number)
        cur.execute(query, (str(cert.serial_number),))
        self.assertEqual(cur.fetchone()[0], True)

    def test_update_cert(self):
        """
        Verify that a certificate can be updated.
        """
        old_cert = generate_fake_cert(
            "user@host", serial_number=123, pkey=self.pkey, upkey=self.upkey, expired=True
        )
        self.engine.save_cert(old_cert, "ABCDEFGH")
        csr = generate_csr("user@host", "test@example.com", self.upkey)
        cert = update_cert(old_cert, csr, self.pkey, self.upkey)
        self.engine.update_cert(serial_number=cert.serial_number, cert=cert)
        self.assertEqual(old_cert.serial_number, cert.serial_number)
        self.assertEqual(old_cert.not_valid_before, cert.not_valid_before)


if __name__ == "__main__":
    unittest.main()
