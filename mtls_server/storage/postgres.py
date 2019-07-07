import datetime

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import Encoding
import psycopg2

from .sql import SqlStorageEngine
from . import exceptions
from ..logger import logger


class PostgresqlStorageEngine(SqlStorageEngine):
    """
    A StorageEngine implementation that persists data to a Postgresql database
    """

    def __init__(self, config):

        self.conn = psycopg2.connect(
            dbname=config.get("storage.postgres", "database"),
            user=config.get("storage.postgres", "user"),
            password=config.get("storage.postgres", "password"),
            host=config.get("storage.postgres", "host", fallback="localhost"),
            port=config.get("storage.postgres", "port", fallback=5432),
        )

    def init_db(self):
        cur = self.conn.cursor()
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
        self.conn.commit()

    def save_cert(self, cert, fingerprint):
        if self.__conflicting_cert_exists(cert, fingerprint):
            raise exceptions.StorageEngineCertificateConflict

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
        self.conn.commit()

    def get_cert(
        self, serial_number=None, common_name=None, fingerprint=None, show_revoked=False
    ):
        cur = self.conn.cursor()
        value = None
        query = "SELECT cert FROM certs WHERE"
        if serial_number is not None:
            query += " serial_number = %s"
            value = str(serial_number)
        elif fingerprint is not None:
            query += " fingerprint = %s"
            value = fingerprint
        elif common_name is not None:
            query += " common_name = %s"
            value = common_name
        else:
            return None

        query += " AND revoked = %s"

        cur.execute(query, (value, show_revoked))
        rows = cur.fetchall()
        certs = []
        for row in rows:
            certs.append(row[0])
        return certs

    def revoke_cert(self, serial_number):
        cur = self.conn.cursor()
        logger.info(
            "Revoking certificate {serial_number}".format(serial_number=serial_number)
        )
        cur.execute(
            "UPDATE certs SET revoked=true WHERE serial_number = %s",
            (str(serial_number),),
        )
        self.conn.commit()

    def update_cert(self, serial_number=None, cert=None):
        if not serial_number or not cert:
            logger.error("A serial number and cert are required to update.")
            raise exceptions.UpdateCertException
        cur = self.conn.cursor()
        logger.info(
            "Updating certificate {serial_number}".format(serial_number=serial_number)
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
        self.conn.commit()

    def get_revoked_certs(self):
        cur = self.conn.cursor()
        now = datetime.datetime.utcnow()
        not_valid_after = now.strftime("%Y-%m-%d %H:%M:%S")
        cur.execute(
            "SELECT cert FROM certs WHERE revoked = true AND " + "not_valid_after > %s",
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

        cur = self.conn.cursor()
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
