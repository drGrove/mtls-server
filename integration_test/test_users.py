import base64
import json
import os
import unittest


from mtls_server.server import create_app

from integration_test.base import BaseTests
from integration_test.base import PostgresqlBaseTestCase
from integration_test.base import SQLiteBaseTestCase


class BaseUserTests(BaseTests):
    def add_user_valid_admin(self):
        admin = self.admin_users[0]
        payload = {
            "fingerprint": "C92FE5A3FBD58DD3EC5AA26BB10116B8193F2DBD",
        }
        sig = self.admin_gpg.sign(
            json.dumps(payload, sort_keys=True),
            keyid=admin.fingerprint,
            detach=True,
            passphrase=admin.password,
        )
        pgpb64 = base64.b64encode(str(sig).encode('ascii'))
        response = self.app.post(
            "/users",
            json=payload,
            content_type="application/json",
            headers={
                'Authorization': f'PGP-SIG {str(pgpb64.decode("utf-8"))}'
            }
        )
        res = json.loads(response.data)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(res["msg"], "success")

    def add_user_invalid_admin(self):
        user = self.invalid_users[0]
        new_user = self.new_users[0]
        payload = {
            "fingerprint": new_user.fingerprint,
        }
        sig = self.user_gpg.sign(
            json.dumps(payload, sort_keys=True),
            keyid=user.fingerprint,
            detach=True,
            passphrase=user.password,
        )
        pgpb64 = base64.b64encode(str(sig).encode('ascii'))
        response = self.app.post(
            "/users",
            json=payload,
            content_type="application/json",
            headers={
                'Authorization': f'PGP-SIG {str(pgpb64.decode("utf-8"))}'
            }
        )
        res = json.loads(response.data)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(res["error"], True)

    def add_admin_valid_admin(self):
        admin = self.admin_users[0]
        fingerprint = "C92FE5A3FBD58DD3EC5AA26BB10116B8193F2DBD"
        payload = {
            "fingerprint": fingerprint,
        }
        sig = self.admin_gpg.sign(
            json.dumps(payload, sort_keys=True),
            keyid=admin.fingerprint,
            detach=True,
            passphrase=admin.password,
        )
        pgpb64 = base64.b64encode(str(sig).encode('ascii'))
        response = self.app.post(
            "/users",
            json=payload,
            content_type="application/json",
            headers={
                'Authorization': f'PGP-SIG {str(pgpb64.decode("utf-8"))}'
            }
        )
        res = json.loads(response.data)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(res["msg"], "success")

    def add_admin_twice_valid_admin(self):
        fingerprint = "C92FE5A3FBD58DD3EC5AA26BB10116B8193F2DBD"
        admin = self.admin_users[0]
        payload = {
            "fingerprint": fingerprint,
            "admin": True,
        }
        sig = self.admin_gpg.sign(
            json.dumps(payload, sort_keys=True),
            keyid=admin.fingerprint,
            detach=True,
            passphrase=admin.password,
        )
        pgpb64 = base64.b64encode(str(sig).encode('ascii'))
        response = self.app.post(
            "/users",
            json=payload,
            content_type="application/json",
            headers={
                'Authorization': f'PGP-SIG {str(pgpb64.decode("utf-8"))}'
            }
        )
        res = json.loads(response.data)
        self.assertEqual(res["msg"], "success")

        sig = self.admin_gpg.sign(
            json.dumps(payload, sort_keys=True),
            keyid=admin.fingerprint,
            detach=True,
            passphrase=admin.password,
        )
        pgpb64 = base64.b64encode(str(sig).encode('ascii'))
        response = self.app.post(
            "/users",
            json=payload,
            content_type="application/json",
            headers={
                'Authorization': f'PGP-SIG {str(pgpb64.decode("utf-8"))}'
            }
        )
        res = json.loads(response.data)
        self.assertEqual(res["msg"], "success")

    def add_admin_add_key_not_on_keyserver(self):
        admin = self.admin_users[0]
        new_user = self.invalid_users[0]
        payload = {
            "fingerprint": new_user.fingerprint,
        }
        sig = self.admin_gpg.sign(
            json.dumps(payload, sort_keys=True),
            keyid=admin.fingerprint,
            detach=True,
            passphrase=admin.password,
        )
        pgpb64 = base64.b64encode(str(sig).encode('ascii'))
        response = self.app.post(
            "/users",
            json=payload,
            content_type="application/json",
            headers={
                'Authorization': f'PGP-SIG {str(pgpb64.decode("utf-8"))}'
            }
        )
        self.assertEqual(response.status_code, 422)

    def add_admin_invalid_admin(self):
        admin = self.users[0]
        new_user = self.new_users[0]
        payload = {
            "admin": True,
            "fingerprint": new_user.fingerprint,
        }
        sig = self.admin_gpg.sign(
            json.dumps(payload, sort_keys=True),
            keyid=admin.fingerprint,
            detach=True,
            passphrase=admin.password,
        )
        pgpb64 = base64.b64encode(str(sig).encode('ascii'))
        response = self.app.post(
            "/users",
            json=payload,
            content_type="application/json",
            headers={
                'Authorization': f'PGP-SIG {str(pgpb64.decode("utf-8"))}'
            }
        )
        res = json.loads(response.data)
        self.assertEqual(res["error"], True)

    def remove_user_valid_admin(self):
        admin = self.admin_users[0]
        fingerprint = "C92FE5A3FBD58DD3EC5AA26BB10116B8193F2DBD"
        sig = self.admin_gpg.sign(
            "NOCONTENT",
            keyid=admin.fingerprint,
            detach=True,
            passphrase=admin.password,
        )
        pgpb64 = base64.b64encode(str(sig).encode('ascii'))
        response = self.app.delete(
            f"/users/{fingerprint}",
            content_type="application/json",
            headers={
                'Authorization': f'PGP-SIG {str(pgpb64.decode("utf-8"))}'
            }
        )
        res = json.loads(response.data)
        self.assertEqual(res["msg"], "success")

    def remove_user_invalid_admin(self):
        admin = self.users[0]
        new_user = self.new_users[0]
        sig = self.admin_gpg.sign(
            "NOCONTENT",
            keyid=admin.fingerprint,
            detach=True,
            passphrase=admin.password,
        )
        pgpb64 = base64.b64encode(str(sig).encode('ascii'))
        response = self.app.delete(
            f"/users/{new_user.fingerprint}",
            content_type="application/json",
            headers={
                'Authorization': f'PGP-SIG {str(pgpb64.decode("utf-8"))}'
            }
        )
        res = json.loads(response.data)
        self.assertEqual(res["error"], True)

    def remove_admin_valid_admin(self):
        admin = self.admin_users[0]
        fingerprint = "C92FE5A3FBD58DD3EC5AA26BB10116B8193F2DBD"
        payload = {
            "admin": True,
            "fingerprint": fingerprint,
        }
        sig = self.admin_gpg.sign(
            json.dumps(payload, sort_keys=True),
            keyid=admin.fingerprint,
            detach=True,
            passphrase=admin.password,
        )
        pgpb64 = base64.b64encode(str(sig).encode('ascii'))
        response = self.app.delete(
            f"/users/{fingerprint}",
            json=payload,
            content_type="application/json",
            headers={
                'Authorization': f'PGP-SIG {str(pgpb64.decode("utf-8"))}'
            }
        )
        self.assertEqual(response.status_code, 200)

    def remove_admin_invalid_admin(self):
        user = self.users[0]
        new_user = self.new_users[0]
        payload = {
            "admin": True,
            "fingerprint": new_user.fingerprint,
        }
        sig = self.user_gpg.sign(
            json.dumps(payload, sort_keys=True),
            keyid=user.fingerprint,
            detach=True,
            passphrase=user.password,
        )
        pgpb64 = base64.b64encode(str(sig).encode('ascii'))
        response = self.app.delete(
            f"/users/{new_user.fingerprint}",
            json=payload,
            content_type="application/json",
            headers={
                'Authorization': f'PGP-SIG {str(pgpb64.decode("utf-8"))}'
            }
        )
        res = json.loads(response.data)
        self.assertEqual(res["error"], True)


class TestUserSQLite(SQLiteBaseTestCase, BaseUserTests):
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

    def test_add_user_valid_admin(self):
        self.add_user_valid_admin()

    def test_add_user_invalid_admin(self):
        self.add_user_invalid_admin()

    def test_add_admin_valid_admin(self):
        self.add_admin_valid_admin()

    def test_add_admin_twice_valid_admin(self):
        self.add_admin_twice_valid_admin()

    def test_add_admin_add_key_not_on_keyserver(self):
        self.add_admin_add_key_not_on_keyserver()

    def test_add_admin_invalid_admin(self):
        self.add_admin_invalid_admin()

    def test_remove_user_valid_admin(self):
        self.remove_user_valid_admin()

    def test_remove_user_invalid_admin(self):
        self.remove_user_invalid_admin()

    def test_remove_admin_valid_admin(self):
        self.remove_admin_valid_admin()

    def test_remove_admin_invalid_admin(self):
        self.remove_admin_invalid_admin()

class TestUserPostgresql(PostgresqlBaseTestCase, BaseUserTests):
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

    def test_add_user_valid_admin(self):
        self.add_user_valid_admin()

    def test_add_user_invalid_admin(self):
        self.add_user_invalid_admin()

    def test_add_admin_valid_admin(self):
        self.add_admin_valid_admin()

    def test_add_admin_twice_valid_admin(self):
        self.add_admin_twice_valid_admin()

    def test_add_admin_add_key_not_on_keyserver(self):
        self.add_admin_add_key_not_on_keyserver()

    def test_add_admin_invalid_admin(self):
        self.add_admin_invalid_admin()

    def test_remove_user_valid_admin(self):
        self.remove_user_valid_admin()

    def test_remove_user_invalid_admin(self):
        self.remove_user_invalid_admin()

    def test_remove_admin_valid_admin(self):
        self.remove_admin_valid_admin()

    def test_remove_admin_invalid_admin(self):
        self.remove_admin_invalid_admin()


if __name__ == "__main__":
    unittest.main()
