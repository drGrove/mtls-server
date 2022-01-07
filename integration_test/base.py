import logging
import os
import tempfile
from unittest import TestCase
from unittest import mock

from configparser import ConfigParser
from flask.testing import FlaskClient
import gnupg

from mtls_server.config import Config
from mtls_server.storage import PostgresqlStorageEngine
from mtls_server.storage import SQLiteStorageEngine
from mtls_server.utils import User
from mtls_server.utils import gen_passwd
from mtls_server.utils import generate_key


class BaseTests(TestCase):
    app: FlaskClient
    users: list
    admin_users: list
    invalid_users: list
    new_users: list
    user_gpg: gnupg.GPG
    admin_gpg: gnupg.GPG
    invalid_gpg: gnupg.GPG


class PostgresqlBaseTestCase(TestCase):
    @classmethod
    def setUpClass(cls):
        logging.disable(logging.CRITICAL)
        cls.env_patcher = mock.patch.dict(os.environ, {"SEED_ON_INIT": "0"})
        cls.env_patcher.start()

    @classmethod
    def tearDownClass(cls):
        logging.disable(logging.NOTSET)
        cls.env_patcher.stop()

    def setUp(self):
        self.USER_GNUPGHOME = tempfile.TemporaryDirectory()
        self.ADMIN_GNUPGHOME = tempfile.TemporaryDirectory()
        self.INVALID_GNUPGHOME = tempfile.TemporaryDirectory()
        self.NEW_USER_GNUPGHOME = tempfile.TemporaryDirectory()
        config = ConfigParser()
        config.read_string(
            f"""
            [mtls]
            min_lifetime=60
            max_lifetime=0

            [ca]
            key = secrets/certs/authority/RootCA.key
            cert = secrets/certs/authority/RootCA.pem
            issuer = My Company Name
            alternate_name = *.myname.com

            [gnupg]
            user={self.USER_GNUPGHOME.name}
            admin={self.ADMIN_GNUPGHOME.name}

            [storage]
            engine=postgres

            [storage.postgres]
            database = mtls
            user = postgres
            password = postgres
            host = {os.environ.get('PGHOST', 'localhost')}
            """
        )
        Config.init_config(config=config)
        self.Config = Config
        self.key = generate_key(512)
        self.engine = PostgresqlStorageEngine(self.Config)
        with self.engine.conn.cursor() as cur:
            cur.execute("DROP TABLE IF EXISTS certs")
            self.engine.init_db()
        self.user_gpg = gnupg.GPG(gnupghome=self.USER_GNUPGHOME.name)
        self.admin_gpg = gnupg.GPG(gnupghome=self.ADMIN_GNUPGHOME.name)
        self.invalid_gpg = gnupg.GPG(gnupghome=self.INVALID_GNUPGHOME.name)
        self.new_user_gpg = gnupg.GPG(gnupghome=self.NEW_USER_GNUPGHOME.name)
        self.users = [
            User("user@host", gen_passwd(), generate_key(512), gpg=self.user_gpg),
            User(
                "user2@host", gen_passwd(), generate_key(512), gpg=self.user_gpg
            ),
            User(
                "user3@host", gen_passwd(), generate_key(512), gpg=self.user_gpg
            ),
        ]
        self.invalid_users = [
            User(
                "user4@host",
                gen_passwd(),
                generate_key(512),
                gpg=self.invalid_gpg,
            )
        ]
        self.admin_users = [
            User(
                "admin@host", gen_passwd(), generate_key(512), gpg=self.admin_gpg
            )
        ]
        self.new_users = [
            User(
                "newuser@host",
                gen_passwd(),
                generate_key(512),
                gpg=self.new_user_gpg,
            ),
            User(
                "newuser2@host",
                gen_passwd(),
                generate_key(512),
                gpg=self.new_user_gpg,
            ),
        ]
        for user in self.users:
            self.user_gpg.import_keys(
                self.user_gpg.export_keys(user.fingerprint)
            )
        for user in self.admin_users:
            # Import to admin keychain
            self.admin_gpg.import_keys(
                self.admin_gpg.export_keys(user.fingerprint)
            )
            # Import to user keychain
            self.user_gpg.import_keys(
                self.admin_gpg.export_keys(user.fingerprint)
            )
        for user in self.invalid_users:
            self.invalid_gpg.import_keys(
                self.invalid_gpg.export_keys(user.fingerprint)
            )
        for user in self.new_users:
            self.new_user_gpg.import_keys(
                self.new_user_gpg.export_keys(user.fingerprint)
            )

    def tearDown(self):
        super().tearDown()
        if os.environ.get('CLEANUP', '1') == '1':
            self.USER_GNUPGHOME.cleanup()
            self.ADMIN_GNUPGHOME.cleanup()
            self.INVALID_GNUPGHOME.cleanup()
            self.NEW_USER_GNUPGHOME.cleanup()

class SQLiteBaseTestCase(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env_patcher = mock.patch.dict(os.environ, {"SEED_ON_INIT": "0"})
        cls.env_patcher.start()


    @classmethod
    def tearDownClass(cls):
        cls.env_patcher.stop()

    def setUp(self):
        self.USER_GNUPGHOME = tempfile.TemporaryDirectory()
        self.ADMIN_GNUPGHOME = tempfile.TemporaryDirectory()
        self.INVALID_GNUPGHOME = tempfile.TemporaryDirectory()
        self.NEW_USER_GNUPGHOME = tempfile.TemporaryDirectory()
        config = ConfigParser()
        config.read_string(
            f"""
            [mtls]
            min_lifetime=60
            max_lifetime=0

            [ca]
            key = secrets/certs/authority/RootCA.key
            cert = secrets/certs/authority/RootCA.pem
            issuer = My Company Name
            alternate_name = *.myname.com

            [gnupg]
            user={self.USER_GNUPGHOME.name}
            admin={self.ADMIN_GNUPGHOME.name}

            [storage]
            engine=sqlite3

            [storage.sqlite3]
            db_path=:memory:
            """
        )
        Config.init_config(config=config)
        self.Config = Config
        self.user_gpg = gnupg.GPG(gnupghome=self.USER_GNUPGHOME.name)
        self.admin_gpg = gnupg.GPG(gnupghome=self.ADMIN_GNUPGHOME.name)
        self.invalid_gpg = gnupg.GPG(gnupghome=self.INVALID_GNUPGHOME.name)
        self.new_user_gpg = gnupg.GPG(gnupghome=self.NEW_USER_GNUPGHOME.name)
        self.users = [
            User("user@host", gen_passwd(), generate_key(512), gpg=self.user_gpg),
            User(
                "user2@host", gen_passwd(), generate_key(512), gpg=self.user_gpg
            ),
            User(
                "user3@host", gen_passwd(), generate_key(512), gpg=self.user_gpg
            ),
        ]
        self.invalid_users = [
            User(
                "user4@host",
                gen_passwd(),
                generate_key(512),
                gpg=self.invalid_gpg,
            )
        ]
        self.admin_users = [
            User(
                "admin@host", gen_passwd(), generate_key(512), gpg=self.admin_gpg
            )
        ]
        self.new_users = [
            User(
                "newuser@host",
                gen_passwd(),
                generate_key(512),
                gpg=self.new_user_gpg,
            ),
            User(
                "newuser2@host",
                gen_passwd(),
                generate_key(512),
                gpg=self.new_user_gpg,
            ),
        ]
        self.key = generate_key(512)
        self.engine = SQLiteStorageEngine(self.Config)
        cur = self.engine.conn.cursor()
        cur.execute("DROP TABLE IF EXISTS certs")
        self.engine.init_db()
        for user in self.users:
            self.user_gpg.import_keys(
                self.user_gpg.export_keys(user.fingerprint)
            )
        for user in self.admin_users:
            # Import to admin keychain
            self.admin_gpg.import_keys(
                self.admin_gpg.export_keys(user.fingerprint)
            )
            # Import to user keychain
            self.user_gpg.import_keys(
                self.admin_gpg.export_keys(user.fingerprint)
            )
        for user in self.invalid_users:
            self.invalid_gpg.import_keys(
                self.invalid_gpg.export_keys(user.fingerprint)
            )
        for user in self.new_users:
            self.new_user_gpg.import_keys(
                self.new_user_gpg.export_keys(user.fingerprint)
            )

    def tearDown(self):
        if os.environ.get('CLEANUP', '1') == '1':
            self.USER_GNUPGHOME.cleanup()
            self.ADMIN_GNUPGHOME.cleanup()
            self.INVALID_GNUPGHOME.cleanup()
            self.NEW_USER_GNUPGHOME.cleanup()
