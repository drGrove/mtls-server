import datetime
import os

from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import Encoding

from .logger import logger


class StorageEngineCertificateConflict(Exception):
    """
    Raise when a StorageEngine implementation is asked to persist a certificate
    with a serial number that already exists or CommonName that is already in
    use by another non-expired/revoked certificate
    """


class StorageEngineMissing(Exception):
    """
    Raise when a StorageEngine type is missing.
    """


class UpdateCertException(Exception):
    """
    Raise when attempting to update a cert and parameters are missing.
    """


class SqlStorageEngine:
    """
    A Base SQL Storage Engine implementation.
    """

    def close(self):
        return self.conn.close()


class SQLiteStorageEngine(SqlStorageEngine):
    """
    A StorageEngine implementation that persists data to a SQLite3 database
    """

    def __init__(self, config):
        import sqlite3

        db_path = config.get(
            "storage.sqlite3",
            "db_path",
            os.path.join(os.getcwd(), "mtls-server.db"),
        )
        self.conn = sqlite3.connect(db_path, check_same_thread=False)

    def init_db(self):
        cur = self.conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS certs (
                serial_number text,
                common_name text,
                not_valid_after datetime,
                cert blob,
                revoked boolean,
                fingerprint text
            )
            """
        )
        self.conn.commit()

    def save_cert(self, cert, fingerprint):
        if self.__conflicting_cert_exists(cert, fingerprint):
            raise StorageEngineCertificateConflict

        common_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        common_name = common_name[0].value

        cur = self.conn.cursor()
        cur.execute(
            """
            INSERT INTO certs (
                serial_number,
                common_name,
                not_valid_after,
                cert,
                revoked,
                fingerprint
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                str(cert.serial_number),
                common_name,
                cert.not_valid_after,
                cert.public_bytes(Encoding.PEM).decode("UTF-8"),
                False,
                fingerprint,
            ],
        )
        self.conn.commit()

    def revoke_cert(self, serial_number):
        cur = self.conn.cursor()
        logger.info(
            "Revoking certificate {serial_number}".format(
                serial_number=serial_number
            )
        )
        cur.execute(
            "UPDATE certs SET revoked=1 WHERE serial_number=?",
            [str(serial_number),],
        )
        self.conn.commit()

    def update_cert(self, serial_number=None, cert=None):
        if not serial_number or not cert:
            logger.error("A serial number and cert are required to update.")
            raise UpdateCertException
        cur = self.conn.cursor()
        logger.info(
            "Updating certificate {serial_number}".format(
                serial_number=serial_number
            )
        )
        cur.execute(
            """
            UPDATE
                certs
            SET
                cert=?,
                not_valid_after=?
            WHERE
                serial_number=?
            """,
            [
                cert.public_bytes(Encoding.PEM).decode("UTF-8"),
                cert.not_valid_after,
                str(serial_number),
            ],
        )
        self.conn.commit()

    def get_cert(
        self,
        serial_number=None,
        common_name=None,
        fingerprint=None,
        show_revoked=False,
    ):
        cur = self.conn.cursor()
        query = "SELECT cert FROM certs WHERE"
        query_options = []
        values = []
        if serial_number is not None:
            query_options.append("serial_number=?")
            values.append(str(serial_number))
        if fingerprint is not None:
            query_options.append("fingerprint=?")
            values.append(str(fingerprint))
        if common_name is not None:
            query_options.append("common_name=?")
            values.append(str(common_name))

        query_options.append("revoked=?")
        if show_revoked:
            values.append(str(1))
        else:
            values.append(str(0))

        query = f"{query} {' AND '.join(query_options)}"
        cur.execute(query, values)
        rows = cur.fetchall()
        certs = []
        for row in rows:
            certs.append(row[0])
        return certs

    def get_revoked_certs(self):
        cur = self.conn.cursor()
        now = str(datetime.datetime.utcnow())
        cur.execute(
            "SELECT cert FROM certs WHERE revoked=1 AND not_valid_after>?",
            [now],
        )
        rows = cur.fetchall()
        certs = []
        for row in rows:
            certs.append(row[0])
        return certs

    def __conflicting_cert_exists(self, cert, fingerprint):
        common_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        common_name = common_name[0].value

        cur = self.conn.cursor()
        cur.execute(
            """
            SELECT count(*) FROM certs
            WHERE serial_number=?
            OR (
                common_name=?
                AND revoked=0
            )
            """,
            [str(cert.serial_number), common_name],
        )
        conflicts = cur.fetchone()[0]
        return conflicts > 0


class PostgresqlStorageEngine(SqlStorageEngine):
    """
    A StorageEngine implementation that persists data to a Postgresql database
    """

    def __init__(self, config):
        import psycopg2

        self.conn = psycopg2.connect(
            dbname=config.get("storage.postgres", "database"),
            user=config.get("storage.postgres", "user"),
            password=config.get("storage.postgres", "password"),
            host=config.get("storage.postgres", "host", "localhost"),
            port=config.get_int("storage.postgres", "port", 5432),
        )
        self.conn.autocommit = True

    def __del__(self):
        self.conn.close()

    def init_db(self):
        with self.conn.cursor() as cur:
            logger.debug("Create Table certs")
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS certs (
                    serial_number text,
                    common_name text,
                    not_valid_after timestamp,
                    cert text,
                    revoked boolean,
                    fingerprint text
                )
                """
            )

    def save_cert(self, cert, fingerprint):
        if self.__conflicting_cert_exists(cert, fingerprint):
            raise StorageEngineCertificateConflict

        common_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        common_name = common_name[0].value

        with self.conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO certs (
                    serial_number,
                    common_name,
                    not_valid_after,
                    cert,
                    revoked,
                    fingerprint
                )
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (
                    str(cert.serial_number),
                    common_name,
                    cert.not_valid_after,
                    cert.public_bytes(Encoding.PEM).decode("UTF-8"),
                    False,
                    fingerprint,
                ),
            )

    def get_cert(
        self,
        serial_number=None,
        common_name=None,
        fingerprint=None,
        show_revoked=False,
    ):
        with self.conn.cursor() as cur:
            query = "SELECT cert FROM certs WHERE"
            query_options = []
            values = []
            if serial_number is not None:
                query_options.append("serial_number=%s")
                values.append(str(serial_number))
            if fingerprint is not None:
                query_options.append("fingerprint=%s")
                values.append(fingerprint)
            if common_name is not None:
                query_options.append("common_name=%s")
                values.append(common_name)

            query_options.append("revoked=%s")
            if show_revoked:
                values.append(True)
            else:
                values.append(False)

            cur.execute(f"{query} {' AND '.join(query_options)}", tuple(values))
            rows = cur.fetchall()
            certs = []
            for row in rows:
                certs.append(row[0])
            return certs

    def revoke_cert(self, serial_number):
        with self.conn.cursor() as cur:
            logger.info(
                "Revoking certificate {serial_number}".format(
                    serial_number=serial_number
                )
            )
            cur.execute(
                "UPDATE certs SET revoked=true WHERE serial_number = %s",
                (str(serial_number),),
            )

    def update_cert(self, serial_number=None, cert=None):
        if not serial_number or not cert:
            logger.error("A serial number and cert are required to update.")
            raise UpdateCertException
        with self.conn.cursor() as cur:
            logger.info(
                "Updating certificate {serial_number}".format(
                    serial_number=serial_number
                )
            )
            cur.execute(
                """
                UPDATE
                    certs
                SET
                    cert = %s,
                    not_valid_after = %s
                WHERE
                    serial_number = %s
                """,
                (
                    cert.public_bytes(Encoding.PEM).decode("UTF-8"),
                    cert.not_valid_after,
                    str(serial_number),
                ),
            )

    def get_revoked_certs(self):
        with self.conn.cursor() as cur:
            now = datetime.datetime.utcnow()
            not_valid_after = now.strftime("%Y-%m-%d %H:%M:%S")
            cur.execute(
                "SELECT cert FROM certs WHERE revoked = true AND "
                + "not_valid_after > %s",
                (str(not_valid_after),),
            )
            rows = cur.fetchall()
            certs = []
            for row in rows:
                certs.append(row[0])
            return certs

    def __conflicting_cert_exists(self, cert, fingerprint):
        common_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        common_name = common_name[0].value

        with self.conn.cursor() as cur:
            cur.execute(
                """
                SELECT count(*) FROM certs
                WHERE serial_number = %s
                OR (
                    common_name = %s
                    AND fingerprint = %s
                    AND revoked=false
                )
                """,
                (str(cert.serial_number), common_name, fingerprint),
            )
            conflicts = cur.fetchone()[0]
            return conflicts > 0


class StorageEngineNotSupportedError(Exception):
    """
    Raise when a StorageEngine implementation cannot be created from the
    provided configuration
    """


class StorageEngine:
    """
    StorageEngine is a factory that returns a concrete engine implementation
    depending on the configuration
    """

    def __new__(cls, config):
        engine = config.get("storage", "engine", None)
        if engine is None:
            raise StorageEngineMissing()
        if engine == "sqlite3":
            return SQLiteStorageEngine(config)
        elif engine == "postgres":
            return PostgresqlStorageEngine(config)
        else:
            raise StorageEngineNotSupportedError(engine)
