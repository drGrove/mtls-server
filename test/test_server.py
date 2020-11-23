import json
import logging
import tempfile
import unittest

from configparser import ConfigParser
from cryptography.hazmat.primitives import serialization
import gnupg

from mtls_server import storage
from mtls_server.config import Config
from mtls_server.server import create_app
from mtls_server.utils import User
from mtls_server.utils import gen_passwd
from mtls_server.utils import generate_key


logging.disable(logging.CRITICAL)


class TestServer(unittest.TestCase):
    def setUp(self):
        self.USER_GNUPGHOME = tempfile.TemporaryDirectory()
        self.ADMIN_GNUPGHOME = tempfile.TemporaryDirectory()
        self.INVALID_GNUPGHOME = tempfile.TemporaryDirectory()
        self.NEW_USER_GNUPGHOME = tempfile.TemporaryDirectory()
        self.config = ConfigParser()
        self.config.read_string(
            """
            [mtls]
            min_lifetime=60
            max_lifetime=0

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
        Config.init_config(config=self.config)
        self.key = generate_key()
        self.engine = storage.SQLiteStorageEngine(Config)
        cur = self.engine.conn.cursor()
        cur.execute("DROP TABLE IF EXISTS certs")
        self.engine.conn.commit()
        self.engine.init_db()
        self.user_gpg = gnupg.GPG(gnupghome=self.USER_GNUPGHOME.name)
        self.admin_gpg = gnupg.GPG(gnupghome=self.ADMIN_GNUPGHOME.name)
        self.invalid_gpg = gnupg.GPG(gnupghome=self.INVALID_GNUPGHOME.name)
        self.new_user_gpg = gnupg.GPG(gnupghome=self.NEW_USER_GNUPGHOME.name)
        app = create_app(Config)
        self.app = app.test_client()
        self.users = [
            User("user@host", gen_passwd(), generate_key(), gpg=self.user_gpg),
            User("user2@host", gen_passwd(), generate_key(), gpg=self.user_gpg),
            User("user3@host", gen_passwd(), generate_key(), gpg=self.user_gpg),
        ]
        self.invalid_users = [
            User("user4@host", gen_passwd(), generate_key(), gpg=self.invalid_gpg)
        ]
        self.admin_users = [
            User("admin@host", gen_passwd(), generate_key(), gpg=self.admin_gpg)
        ]
        self.new_users = [
            User("newuser@host", gen_passwd(), generate_key(), gpg=self.new_user_gpg),
            User("newuser2@host", gen_passwd(), generate_key(), gpg=self.new_user_gpg),
        ]
        for user in self.users:
            self.user_gpg.import_keys(self.user_gpg.export_keys(user.fingerprint))
            self.user_gpg.trust_keys([user.fingerprint], "TRUST_ULTIMATE")
        for user in self.admin_users:
            # Import to admin keychain
            self.admin_gpg.import_keys(self.admin_gpg.export_keys(user.fingerprint))
            self.admin_gpg.trust_keys([user.fingerprint], "TRUST_ULTIMATE")
            # Import to user keychain
            self.user_gpg.import_keys(self.admin_gpg.export_keys(user.fingerprint))
            self.user_gpg.trust_keys([user.fingerprint], "TRUST_ULTIMATE")
        for user in self.invalid_users:
            self.invalid_gpg.import_keys(self.invalid_gpg.export_keys(user.fingerprint))
            self.invalid_gpg.trust_keys([user.fingerprint], "TRUST_ULTIMATE")
        for user in self.new_users:
            self.new_user_gpg.import_keys(self.new_user_gpg.export_keys(user.fingerprint))
            self.new_user_gpg.trust_keys([user.fingerprint], "TRUST_ULTIMATE")

    def tearDown(self):
        self.USER_GNUPGHOME.cleanup()
        self.ADMIN_GNUPGHOME.cleanup()
        self.INVALID_GNUPGHOME.cleanup()
        self.NEW_USER_GNUPGHOME.cleanup()

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

    def test_user_generate_cert(self):
        user = self.users[0]
        csr = user.gen_csr()
        sig = self.user_gpg.sign(
            csr.public_bytes(serialization.Encoding.PEM),
            keyid=user.fingerprint,
            detach=True,
            clearsign=True,
            passphrase=user.password,
        )
        payload = {
            "csr": csr.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
            "signature": str(sig),
            "lifetime": 60,
            "type": "CERTIFICATE",
        }
        response = self.app.post(
            "/", data=json.dumps(payload), content_type="application/json"
        )
        res = json.loads(response.data)
        self.assertEqual(response.status_code, 200)
        self.assertIn("-----BEGIN CERTIFICATE-----", res["cert"])
        self.assertIn("-----END CERTIFICATE-----", res["cert"])

    def test_invalid_user_generate_cert(self):
        user = self.invalid_users[0]
        csr = user.gen_csr()
        sig = self.invalid_gpg.sign(
            csr.public_bytes(serialization.Encoding.PEM),
            keyid=user.fingerprint,
            detach=True,
            clearsign=True,
            passphrase=user.password,
        )
        payload = {
            "csr": csr.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
            "signature": str(sig),
            "lifetime": 60,
            "type": "CERTIFICATE",
        }
        response = self.app.post(
            "/", data=json.dumps(payload), content_type="application/json"
        )
        res = json.loads(response.data)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(res["error"], True)

    def test_get_version(self):
        with open("VERSION", "r") as v:
            version = v.readline().strip()
        response = self.app.get("/version")
        res = json.loads(response.data)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(res["version"], version)


if __name__ == "__main__":
    unittest.main()
