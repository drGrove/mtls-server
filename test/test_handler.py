import datetime
import json
import logging
import os
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

from mtls_server.cert_processor import CertProcessor
from mtls_server.cert_processor import CertProcessorKeyNotFoundError
from mtls_server.cert_processor import CertProcessorInvalidSignatureError
from mtls_server.cert_processor import CertProcessorUntrustedSignatureError
from mtls_server.handler import Handler
from mtls_server import storage
from mtls_server.utils import User
from mtls_server.utils import gen_passwd
from mtls_server.utils import gen_pgp_key
from mtls_server.utils import generate_csr
from mtls_server.utils import generate_key


# logging.disable(logging.CRITICAL)


class TestHandler(unittest.TestCase):
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
        self.common_name = "user@host"
        self.key = generate_key()
        self.engine = storage.SQLiteStorageEngine(self.config)
        cur = self.engine.conn.cursor()
        cur.execute("DROP TABLE IF EXISTS certs")
        self.engine.conn.commit()
        self.engine.init_db()
        self.cert_processor = CertProcessor(self.config)
        self.handler = Handler(self.config)
        self.user_gpg = gnupg.GPG(gnupghome=self.USER_GNUPGHOME.name)
        self.admin_gpg = gnupg.GPG(gnupghome=self.ADMIN_GNUPGHOME.name)
        self.invalid_gpg = gnupg.GPG(gnupghome=self.INVALID_GNUPGHOME.name)
        self.new_user_gpg = gnupg.GPG(gnupghome=self.NEW_USER_GNUPGHOME.name)
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

    def test_user_revoke_cert_serial_number(self):
        user = self.users[0]
        csr = user.gen_csr()
        bcert = self.cert_processor.generate_cert(csr, 60, user.fingerprint)
        cert = x509.load_pem_x509_certificate(bcert, backend=default_backend())
        body = {"query": {"serial_number": str(cert.serial_number)}}
        data = json.dumps(body["query"]).encode("UTF-8")
        sig = self.user_gpg.sign(
            data,
            keyid=user.fingerprint,
            detach=True,
            clearsign=True,
            passphrase=user.password,
        )
        body["signature"] = str(sig)
        response = json.loads(self.handler.revoke_cert(body)[0])
        self.assertTrue(response["msg"] == "success")

    def test_admin_revoke_cert_serial_number(self):
        admin = self.admin_users[0]
        user = self.users[0]
        user_csr = user.gen_csr()
        user_bcert = self.cert_processor.generate_cert(user_csr, 60, user.fingerprint)
        user_cert = x509.load_pem_x509_certificate(user_bcert, backend=default_backend())
        body = {"query": {"serial_number": str(user_cert.serial_number)}}
        data = json.dumps(body["query"]).encode("UTF-8")
        sig = self.admin_gpg.sign(
            data,
            keyid=admin.fingerprint,
            detach=True,
            clearsign=True,
            passphrase=admin.password,
        )
        body["signature"] = str(sig)
        response = json.loads(self.handler.revoke_cert(body)[0])
        self.assertTrue(response["msg"] == "success")

    def test_invalid_revoke_cert_serial_number(self):
        valid_user = self.users[0]
        user = self.invalid_users[0]
        csr = valid_user.gen_csr()
        bcert = self.cert_processor.generate_cert(csr, 60, valid_user.fingerprint)
        cert = x509.load_pem_x509_certificate(bcert, backend=default_backend())
        body = {"query": {"serial_number": str(cert.serial_number)}}
        data = json.dumps(body["query"]).encode("UTF-8")
        sig = self.invalid_gpg.sign(
            data,
            keyid=user.fingerprint,
            detach=True,
            clearsign=True,
            passphrase=user.password,
        )
        body["signature"] = str(sig)
        response = json.loads(self.handler.revoke_cert(body)[0])
        self.assertEqual(response["error"], True, msg=response)

    def test_create_cert(self):
        for user in self.users:
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
            response = json.loads(self.handler.create_cert(payload)[0])
            self.assertIn("-----BEGIN CERTIFICATE-----", response["cert"])
            cert = x509.load_pem_x509_certificate(
                response["cert"].encode("UTF-8"), backend=default_backend()
            )
            self.assertIsInstance(cert, openssl.x509._Certificate)

    def test_create_cert_for_other_user_as_user(self):
        user = self.users[0]
        csr = user.gen_csr("Some other random user", "someotheruser@example.com")
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
        response = json.loads(self.handler.create_cert(payload)[0])
        self.assertEqual(response["error"], True, msg=response)

    def test_create_cert_for_other_user_as_admin(self):
        user = self.admin_users[0]
        csr = user.gen_csr("Some other random user", "someotheruser@example.com")
        sig = self.admin_gpg.sign(
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
        response = json.loads(self.handler.create_cert(payload)[0])
        self.assertIn(
            "-----BEGIN CERTIFICATE-----", response.get("cert", ""), msg=response
        )
        cert = x509.load_pem_x509_certificate(
            response["cert"].encode("UTF-8"), backend=default_backend()
        )
        email = cert.subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)[0]
        email = email.value
        self.assertEqual(email, "someotheruser@example.com", msg=response)

    def test_invalid_user_create_cert(self):
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
        response = json.loads(self.handler.create_cert(payload)[0])
        self.assertEqual(response["error"], True)

    def test_add_user_valid_admin(self):
        admin = self.admin_users[0]
        sig = self.admin_gpg.sign(
            "C92FE5A3FBD58DD3EC5AA26BB10116B8193F2DBD",
            keyid=admin.fingerprint,
            clearsign=True,
            detach=True,
            passphrase=admin.password,
        )
        payload = {
            "fingerprint": "C92FE5A3FBD58DD3EC5AA26BB10116B8193F2DBD",
            "signature": str(sig),
            "type": "USER",
        }
        response = json.loads(self.handler.add_user(payload)[0])
        self.assertEqual(response["msg"], "success")

    def test_add_user_invalid_admin(self):
        user = self.users[0]
        new_user = self.new_users[0]
        sig = self.user_gpg.sign(
            new_user.fingerprint.encode("UTF-8"),
            keyid=user.fingerprint,
            clearsign=True,
            detach=True,
            passphrase=user.password,
        )
        payload = {
            "fingerprint": new_user.fingerprint,
            "signature": str(sig),
            "type": "USER",
        }
        response = json.loads(self.handler.add_user(payload)[0])
        self.assertEqual(response["error"], True)

    def test_add_admin_valid_admin(self):
        admin = self.admin_users[0]
        new_user = self.new_users[0]
        sig = self.admin_gpg.sign(
            "B10116B8193F2DBD",
            keyid=admin.fingerprint,
            clearsign=True,
            detach=True,
            passphrase=admin.password,
        )
        payload = {
            "fingerprint": "B10116B8193F2DBD",
            "signature": str(sig),
            "type": "USER",
        }
        response = self.handler.add_user(payload, is_admin=True)
        response_json = json.loads(response[0])
        self.assertEqual(response_json["msg"], "success")

    def test_add_admin_twice_valid_admin(self):
        admin = self.admin_users[0]
        new_user = self.new_users[0]
        sig = self.admin_gpg.sign(
            "B10116B8193F2DBD",
            keyid=admin.fingerprint,
            clearsign=True,
            detach=True,
            passphrase=admin.password,
        )
        payload = {
            "fingerprint": "B10116B8193F2DBD",
            "signature": str(sig),
            "type": "USER",
        }
        response = self.handler.add_user(payload, is_admin=True)
        response_json = json.loads(response[0])
        self.assertEqual(response_json["msg"], "success")
        response = self.handler.add_user(payload, is_admin=True)
        response_json = json.loads(response[0])
        self.assertEqual(response_json["msg"], "success")

    def test_add_admin_add_key_not_on_keyserver(self):
        admin = self.admin_users[0]
        new_user = self.invalid_users[0]
        sig = self.admin_gpg.sign(
            new_user.fingerprint.encode("UTF-8"),
            keyid=admin.fingerprint,
            clearsign=True,
            detach=True,
            passphrase=admin.password,
        )
        payload = {
            "fingerprint": new_user.fingerprint,
            "signature": str(sig),
            "type": "USER",
        }
        response = self.handler.add_user(payload, is_admin=True)
        self.assertEqual(response[1], 422)

    def test_add_admin_invalid_admin(self):
        admin = self.users[0]
        new_user = self.new_users[0]
        sig = self.admin_gpg.sign(
            new_user.fingerprint.encode("UTF-8"),
            keyid=admin.fingerprint,
            clearsign=True,
            detach=True,
            passphrase=admin.password,
        )
        payload = {
            "fingerprint": new_user.fingerprint,
            "signature": str(sig),
            "type": "USER",
        }
        response = json.loads(self.handler.add_user(payload, is_admin=True)[0])
        self.assertEqual(response["error"], True)

    def test_remove_user_valid_admin(self):
        admin = self.admin_users[0]
        sig = self.admin_gpg.sign(
            "C92FE5A3FBD58DD3EC5AA26BB10116B8193F2DBD",
            keyid=admin.fingerprint,
            clearsign=True,
            detach=True,
            passphrase=admin.password,
        )
        payload = {
            "fingerprint": "C92FE5A3FBD58DD3EC5AA26BB10116B8193F2DBD",
            "signature": str(sig),
            "type": "USER",
        }
        response = json.loads(self.handler.add_user(payload)[0])
        self.assertEqual(response["msg"], "success")
        response = json.loads(self.handler.remove_user(payload)[0])
        self.assertEqual(response["msg"], "success")

    def test_remove_user_invalid_admin(self):
        admin = self.users[0]
        new_user = self.new_users[0]
        sig = self.admin_gpg.sign(
            new_user.fingerprint.encode("UTF-8"),
            keyid=admin.fingerprint,
            clearsign=True,
            detach=True,
            passphrase=admin.password,
        )
        payload = {
            "fingerprint": new_user.fingerprint,
            "signature": str(sig),
            "type": "USER",
        }
        response = json.loads(self.handler.add_user(payload, is_admin=True)[0])
        self.assertEqual(response["error"], True)

    def test_remove_admin_valid_admin(self):
        admin = self.admin_users[0]
        sig = self.admin_gpg.sign(
            "C92FE5A3FBD58DD3EC5AA26BB10116B8193F2DBD".encode("UTF-8"),
            keyid=admin.fingerprint,
            clearsign=True,
            detach=True,
            passphrase=admin.password,
        )
        payload = {
            "fingerprint": "C92FE5A3FBD58DD3EC5AA26BB10116B8193F2DBD",
            "signature": str(sig),
            "type": "ADMIN",
        }
        response = json.loads(self.handler.add_user(payload)[0])
        self.assertEqual(response["msg"], "success")
        response = json.loads(self.handler.remove_user(payload)[0])
        self.assertEqual(response["msg"], "success")

    def test_remove_admin_invalid_admin(self):
        user = self.users[0]
        new_user = self.new_users[0]
        sig = self.user_gpg.sign(
            new_user.fingerprint.encode("UTF-8"),
            keyid=user.fingerprint,
            clearsign=True,
            detach=True,
            passphrase=user.password,
        )
        payload = {
            "fingerprint": new_user.fingerprint,
            "signature": str(sig),
            "type": "ADMIN",
        }
        response = json.loads(self.handler.add_user(payload, is_admin=True)[0])
        self.assertEqual(response["error"], True)


class TestHandlerSeeding(unittest.TestCase):
    def setUp(self):
        self.USER_GNUPGHOME = tempfile.TemporaryDirectory()
        self.ADMIN_GNUPGHOME = tempfile.TemporaryDirectory()
        self.NEW_USER_GNUPGHOME = tempfile.TemporaryDirectory()
        self.NEW_ADMIN_GNUPGHOME = tempfile.TemporaryDirectory()
        self.SEED_DIR = tempfile.TemporaryDirectory()
        self.config = ConfigParser()
        self.config.read_string(
            """
            [mtls]
            min_lifetime=60
            max_lifetime=0
            seed_dir={seed_dir}

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
                seed_dir=self.SEED_DIR.name,
            )
        )
        self.common_name = "user@host"
        self.key = generate_key()
        self.engine = storage.SQLiteStorageEngine(self.config)
        cur = self.engine.conn.cursor()
        cur.execute("DROP TABLE IF EXISTS certs")
        self.engine.conn.commit()
        self.engine.init_db()
        self.cert_processor = CertProcessor(self.config)
        self.user_gpg = gnupg.GPG(gnupghome=self.USER_GNUPGHOME.name)
        self.admin_gpg = gnupg.GPG(gnupghome=self.ADMIN_GNUPGHOME.name)
        self.new_user_gpg = gnupg.GPG(gnupghome=self.NEW_USER_GNUPGHOME.name)
        self.new_admin_gpg = gnupg.GPG(gnupghome=self.NEW_ADMIN_GNUPGHOME.name)
        self.new_users = [
            User("user@host", gen_passwd(), generate_key(), gpg=self.new_user_gpg)
        ]
        self.new_admins = [
            User("admin@host", gen_passwd(), generate_key(), gpg=self.new_admin_gpg)
        ]

    def tearDown(self):
        self.USER_GNUPGHOME.cleanup()
        self.ADMIN_GNUPGHOME.cleanup()
        self.NEW_USER_GNUPGHOME.cleanup()
        self.NEW_ADMIN_GNUPGHOME.cleanup()
        self.SEED_DIR.cleanup()

    def test_seed_users(self):
        seed_subpath = "user"
        os.makedirs("{}/{}".format(self.SEED_DIR.name, seed_subpath))
        for user in self.new_users:
            fingerprint = user.fingerprint
            pgp_armored_key = self.new_user_gpg.export_keys(fingerprint)
            fingerprint_file = "{base}/{subpath}/{fingerprint}.asc".format(
                base=self.SEED_DIR.name, subpath=seed_subpath, fingerprint=fingerprint
            )
            with open(fingerprint_file, "w") as fpf:
                fpf.write(pgp_armored_key)
        handler = Handler(self.config)
        user_gpg = handler.cert_processor.user_gpg
        stored_fingerprints = []
        for key in user_gpg.list_keys():
            stored_fingerprints.append(key["fingerprint"])
        for user in self.new_users:
            self.assertIn(user.fingerprint, stored_fingerprints)

    def test_seed_admins(self):
        seed_subpath = "admin"
        os.makedirs("{}/{}".format(self.SEED_DIR.name, seed_subpath))
        for admin in self.new_admins:
            fingerprint = admin.fingerprint
            pgp_armored_key = self.new_admin_gpg.export_keys(fingerprint)
            fingerprint_file = "{base}/{subpath}/{fingerprint}.asc".format(
                base=self.SEED_DIR.name, subpath=seed_subpath, fingerprint=fingerprint
            )
            with open(fingerprint_file, "w") as fpf:
                fpf.write(pgp_armored_key)
        handler = Handler(self.config)
        admin_gpg = handler.cert_processor.admin_gpg
        stored_fingerprints = []
        for key in admin_gpg.list_keys():
            stored_fingerprints.append(key["fingerprint"])
        for admin in self.new_admins:
            self.assertIn(admin.fingerprint, stored_fingerprints)

    def test_seed_separate_admin_and_user(self):
        for seed_subpath in ["user", "admin"]:
            os.makedirs("{}/{}".format(self.SEED_DIR.name, seed_subpath))
        for user in self.new_users:
            fingerprint = user.fingerprint
            pgp_armored_key = self.new_user_gpg.export_keys(fingerprint)
            fingerprint_file = "{base}/{subpath}/{fingerprint}.asc".format(
                base=self.SEED_DIR.name, subpath="user", fingerprint=fingerprint
            )
            with open(fingerprint_file, "w") as fpf:
                fpf.write(pgp_armored_key)
        for admin in self.new_admins:
            fingerprint = admin.fingerprint
            pgp_armored_key = self.new_admin_gpg.export_keys(fingerprint)
            fingerprint_file = "{base}/{subpath}/{fingerprint}.asc".format(
                base=self.SEED_DIR.name, subpath="admin", fingerprint=fingerprint
            )
            with open(fingerprint_file, "w") as fpf:
                fpf.write(pgp_armored_key)
        handler = Handler(self.config)
        user_gpg = handler.cert_processor.user_gpg
        admin_gpg = handler.cert_processor.admin_gpg
        user_stored_fingerprints = []
        admin_stored_fingerprints = []
        for key in user_gpg.list_keys():
            user_stored_fingerprints.append(key["fingerprint"])
        for key in admin_gpg.list_keys():
            admin_stored_fingerprints.append(key["fingerprint"])
        for admin in self.new_admins:
            self.assertIn(admin.fingerprint, admin_stored_fingerprints)
            self.assertIn(admin.fingerprint, user_stored_fingerprints)
        for user in self.new_users:
            self.assertIn(user.fingerprint, user_stored_fingerprints)
            self.assertNotIn(user.fingerprint, admin_stored_fingerprints)


if __name__ == "__main__":
    unittest.main()
