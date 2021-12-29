import base64
import json
import logging
import unittest

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from mtls_server.server import create_app

from integration_test.base import BaseTests
from integration_test.base import PostgresqlBaseTestCase
from integration_test.base import SQLiteBaseTestCase


logging.disable(logging.CRITICAL)

class BaseCertificateTests(BaseTests):
    def get_ca_cert(self):
        response = self.app.get("/ca")
        self.assertEqual(response.status_code, 200)
        res = json.loads(response.data)
        self.assertEqual(res["issuer"], "My Company Name")

    def get_crl(self):
        response = self.app.get("/crl")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"-----BEGIN X509 CRL-----", response.data)
        self.assertIn(b"-----END X509 CRL-----", response.data)

    def user_generate_cert(self):
        user = self.users[0]
        csr = user.gen_csr()
        payload = {
            "csr": csr.public_bytes(serialization.Encoding.PEM).decode(
                "utf-8"
            ),
            "lifetime": 60,
        }
        sig = self.user_gpg.sign(
            json.dumps(payload),
            keyid=user.fingerprint,
            detach=True,
            passphrase=user.password,
        )
        pgpb64 = base64.b64encode(str(sig).encode('ascii'))
        response = self.app.post(
            "/certs",
            json=payload,
            content_type="application/json",
            headers={
                'Authorization': f'PGP-SIG {str(pgpb64.decode("utf-8"))}'
            }
        )
        res = json.loads(response.data)
        self.assertEqual(response.status_code, 200)
        self.assertIn("-----BEGIN CERTIFICATE-----", res["cert"])
        self.assertIn("-----END CERTIFICATE-----", res["cert"])

    def invalid_user_generate_cert(self):
        user = self.invalid_users[0]
        csr = user.gen_csr()
        payload = {
            "csr": csr.public_bytes(serialization.Encoding.PEM).decode(
                "utf-8"
            ),
            "lifetime": 60,
        }
        sig = self.invalid_gpg.sign(
            json.dumps(payload),
            keyid=user.fingerprint,
            detach=True,
            passphrase=user.password,
        )
        pgpb64 = base64.b64encode(str(sig).encode('ascii'))
        response = self.app.post(
            "/certs",
            json=payload,
            content_type="application/json",
            headers={
                'Authorization': f'PGP-SIG {str(pgpb64.decode("utf-8"))}'
            }
        )
        res = json.loads(response.data)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(res["error"], True)

    def admin_user_generate_cert(self):
        user = self.users[0]
        admin = self.admin_users[0]
        csr = user.gen_csr()
        payload = {
            "csr": csr.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
            "lifetime": 60,
        }
        sig = self.admin_gpg.sign(
            json.dumps(payload),
            keyid=admin.fingerprint,
            detach=True,
            passphrase=admin.password,
        )
        pgpb64 = base64.b64encode(str(sig).encode('ascii'))
        response = self.app.post(
            "/certs",
            json=payload,
            content_type="application/json",
            headers={
                'Authorization': f'PGP-SIG {str(pgpb64.decode("utf-8"))}'
            }
        )
        res = json.loads(response.data)
        self.assertEqual(response.status_code, 200)
        self.assertIn("-----BEGIN CERTIFICATE-----", res["cert"])
        self.assertIn("-----END CERTIFICATE-----", res["cert"])

    def user_cannot_get_other_users_cert(self):
        user1 = self.users[0]
        user2 = self.users[1]
        csr = user1.gen_csr()
        payload = {
            "csr": csr.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
            "lifetime": 60,
        }
        sig = self.user_gpg.sign(
            json.dumps(payload),
            keyid=user1.fingerprint,
            detach=True,
            passphrase=user1.password,
        )
        pgpb64 = base64.b64encode(str(sig).encode('ascii'))
        response = self.app.post(
            "/certs",
            json=payload,
            content_type="application/json",
            headers={
                'Authorization': f'PGP-SIG {str(pgpb64.decode("utf-8"))}'
            }
        )
        res = json.loads(response.data)
        self.assertEqual(response.status_code, 200)
        cert = x509.load_pem_x509_certificate(
            str(res["cert"]).encode("UTF-8"), backend=default_backend()
        )
        payload = {}
        sig = self.user_gpg.sign(
            json.dumps(payload),
            keyid=user2.fingerprint,
            detach=True,
            passphrase=user2.password
        )
        pgpb64 = base64.b64encode(str(sig).encode('ascii'))
        response = self.app.delete(
            f"/certs/{cert.serial_number}",
            json=payload,
            content_type="application/json",
            headers={
                'Authorization': f'PGP-SIG {str(pgpb64.decode("utf-8"))}'
            }
        )
        self.assertEqual(response.status_code, 404)

    def get_version(self):
        with open("VERSION", "r") as v:
            version = v.readline().strip()
        response = self.app.get("/version")
        res = json.loads(response.data)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(res["version"], version)


class TestCertificatesSQLite(SQLiteBaseTestCase, BaseCertificateTests):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()

    def setUp(self):
        super().setUp()
        app = create_app(self.Config)
        app.testing = True
        self.app = app.test_client()

    def tearDown(self):
        super().tearDown()
        del self.app

    def test_get_ca_cert(self):
        self.get_ca_cert()

    def test_get_crl(self):
        self.get_crl()

    def test_user_generate_cert(self):
        self.user_generate_cert()

    def test_invalid_user_generate_cert(self):
        self.invalid_user_generate_cert()

    def test_admin_user_generate_cert(self):
        self.admin_user_generate_cert()

    def test_user_cannot_get_other_users_cert(self):
        self.user_cannot_get_other_users_cert()

    def test_get_version(self):
        self.get_version()


class TestCertificatesPostgresql(PostgresqlBaseTestCase, BaseCertificateTests):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()

    def setUp(self):
        super().setUp()
        app = create_app(self.Config)
        app.testing = True
        self.app = app.test_client()

    def tearDown(self):
        del self.app

    def test_get_ca_cert(self):
        self.get_ca_cert()

    def test_get_crl(self):
        self.get_crl()

    def test_user_generate_cert(self):
        self.user_generate_cert()

    def test_invalid_user_generate_cert(self):
        self.invalid_user_generate_cert()

    def test_admin_user_generate_cert(self):
        self.admin_user_generate_cert()

    def test_user_cannot_get_other_users_cert(self):
        self.user_cannot_get_other_users_cert()

    def test_get_version(self):
        self.get_version()


if __name__ == "__main__":
    unittest.main()
