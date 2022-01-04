import json
import logging
import unittest

from mtls_server.server import create_app

from integration_test.base import BaseTests
from integration_test.base import SQLiteBaseTestCase


logging.disable(logging.CRITICAL)

class OtherTests(BaseTests, SQLiteBaseTestCase):
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
        response = self.app.get("/ca")
        self.assertEqual(response.status_code, 200)
        res = json.loads(response.data)
        self.assertEqual(res["issuer"], "My Company Name")

    def test_get_crl(self):
        response = self.app.get("/crl")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"-----BEGIN X509 CRL-----", response.data)
        self.assertIn(b"-----END X509 CRL-----", response.data)

    def test_get_version(self):
        with open("VERSION", "r") as v:
            version = v.readline().strip()
        response = self.app.get("/version")
        res = json.loads(response.data)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(res["version"], version)


if __name__ == "__main__":
    unittest.main()
