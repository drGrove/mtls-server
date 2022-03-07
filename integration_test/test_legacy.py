import base64
import json
import unittest

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from mtls_server.server import create_app

from integration_test.base import BaseTests
from integration_test.base import PostgresqlBaseTestCase
from integration_test.base import SQLiteBaseTestCase


class BaseLegacyCertificateTests(BaseTests):
    def user_generate_cert(self):
        user = self.users[0]
        csr = user.gen_csr()
        payload = {
            "csr": csr.public_bytes(serialization.Encoding.PEM).decode(
                "utf-8"
            ),
            "lifetime": 60,
            "type": "CERTIFICATE",
        }
        sig = self.user_gpg.sign(
            payload["csr"],
            keyid=user.fingerprint,
            detach=True,
            clearsign=True,
            passphrase=user.password,
        )
        payload["signature"] = str(sig)
        response = self.app.post(
            "/",
            json=payload,
            content_type="application/json",
        )
        res = json.loads(response.data)
        self.assertEqual(response.status_code, 200)
        self.assertIn("-----BEGIN CERTIFICATE-----", res["cert"])
        self.assertIn("-----END CERTIFICATE-----", res["cert"])

    def revoke_cert(self):
        user = self.users[0]
        csr = user.gen_csr()
        payload = {
            "csr": csr.public_bytes(serialization.Encoding.PEM).decode(
                "utf-8"
            ),
            "lifetime": 60,
            "type": "CERTIFICATE",
        }
        sig = self.user_gpg.sign(
            payload["csr"],
            keyid=user.fingerprint,
            detach=True,
            clearsign=True,
            passphrase=user.password,
        )
        payload["signature"] = str(sig)
        response = self.app.post(
            "/",
            json=payload,
            content_type="application/json",
        )

        res = json.loads(response.data)

        user_cert = x509.load_pem_x509_certificate(
           str(res["cert"]).encode("UTF-8"), backend=default_backend()
        )
        query =  {
            "serial_number": user_cert.serial_number
        }
        sig = self.user_gpg.sign(
            json.dumps(query).encode('utf-8'),
            keyid=user.fingerprint,
            detach=True,
            clearsign=True,
            passphrase=user.password,
        )
        payload = {
            "query": query,
            "signature": str(sig),
            "type": "CERTIFICATE"
        }
        response = self.app.delete(
            '/',
            json=payload,
            content_type='application/json'
        )
        res = json.loads(response.data)
        self.assertTrue(res['msg'] == "success", res)

    def user_cannot_revoke_other_users_cert(self):
        user1 = self.users[0]
        user2 = self.users[1]
        csr = user1.gen_csr()
        csr_str = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        sig = self.user_gpg.sign(
            csr_str,
            keyid=user1.fingerprint,
            detach=True,
            clearsign=True,
            passphrase=user1.password,
        )
        payload = {
            "csr": csr_str,
            "lifetime": 60,
            "type": "CERTIFICATE",
            "signature": str(sig)
        }
        response = self.app.post(
            "/",
            json=payload,
            content_type="application/json",
        )
        res = json.loads(response.data)
        self.assertEqual(response.status_code, 200)
        cert = x509.load_pem_x509_certificate(
            str(res["cert"]).encode("UTF-8"), backend=default_backend()
        )
        query = {
            "serial_number": str(cert.serial_number)
        }
        sig = self.user_gpg.sign(
            json.dumps(query),
            keyid=user2.fingerprint,
            detach=True,
            clearsign=True,
            passphrase=user2.password
        )
        payload = {
            "query": query,
            "type": "CERTIFICATE",
            "signature": str(sig),
        }
        response = self.app.delete(
            f"/",
            json=payload,
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 404, response.data)


class TestLegacyCertificatesSQLite(SQLiteBaseTestCase, BaseLegacyCertificateTests):
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

    def test_user_generate_cert(self):
        self.user_generate_cert()

    def test_revoke_cert(self):
        self.revoke_cert()

    def test_user_cannot_revoke_other_users_cert(self):
        self.user_cannot_revoke_other_users_cert()


class TestLegacyCertificatesPostgresql(PostgresqlBaseTestCase, BaseLegacyCertificateTests):
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

    def test_user_generate_cert(self):
        self.user_generate_cert()

    def test_revoke_cert(self):
        self.revoke_cert()

    def test_user_cannot_revoke_other_users_cert(self):
        self.user_cannot_revoke_other_users_cert()
