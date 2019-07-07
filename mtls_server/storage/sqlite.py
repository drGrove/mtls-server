import datetime
import sqlite3

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import Encoding
import psycopg2

from ..logger import logger
from .sql import SqlStorageEngine
from . import exceptions

class SQLiteStorageEngine(SqlStorageEngine):
    """
    A StorageEngine implementation that persists data to a SQLite3 database
    """

    def __init__(self, config):
        db_path = config.get("storage.sqlite3", "db_path")
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
            "Revoking certificate {serial_number}".format(serial_number=serial_number)
        )
        cur.execute(
            "UPDATE certs SET revoked=1 WHERE serial_number=?", [str(serial_number)]
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
        self, serial_number=None, common_name=None, fingerprint=None, show_revoked=False
    ):
        cur = self.conn.cursor()
        key = None
        value = None
        query = "SELECT cert FROM certs WHERE"
        if serial_number is not None:
            query += " serial_number=?"
            value = str(serial_number)
        elif fingerprint is not None:
            query += " fingerprint=?"
            value = str(fingerprint)
        elif common_name is not None:
            query += " common_name=?"
            value = str(common_name)
        else:
            return None

        if show_revoked:
            query += " AND revoked=1"
        else:
            query += " AND revoked=0"

        cur.execute(query, [str(value)])
        rows = cur.fetchall()
        certs = []
        for row in rows:
            certs.append(row[0])
        return certs

    def get_revoked_certs(self):
        cur = self.conn.cursor()
        now = str(datetime.datetime.utcnow())
        cur.execute("SELECT cert FROM certs WHERE revoked=1 AND not_valid_after>?", [now])
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



